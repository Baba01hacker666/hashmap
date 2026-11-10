/* hashmap - brute/map engine implementation
 *
 * Design: each candidate length's keyspace is split into spans; workers pop
 * spans from per-length queues. On stop (signal or all targets found) a
 * worker records its unfinished span tail; after all workers join, remaining
 * spans + tails are written to a state file (tmp + atomic rename) when work
 * is left. A later run with the same config resumes exactly from that file.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include "engine.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "charset.h"
#include "crypto.h"
#include "hashmap.h"
#include "util.h"

/* ------------------------------------------------------------------ */
/* engine internals                                                    */
/* ------------------------------------------------------------------ */

#define HM_STATE_MAGIC "HMSTATE 2"
#define HM_MAX_SPANS_IN_STATE 1000000

typedef struct {
    int len;
    hm_span_t *v; /* malloc'd */
    int n;
    _Atomic int span_at; /* next span index to pop */
} hm_queue_t;

typedef struct {
    _Atomic uint64_t cur_lo;    /* current span lo                    */
    _Atomic uint64_t cur_hi;    /* current span hi (exclusive)        */
    _Atomic uint64_t span_pos;  /* candidates done inside cur span    */
    _Atomic int cur_len;        /* length of cur span                 */
    _Atomic int cur_valid;      /* cur_* holds unfinished span tail   */
    _Atomic int exited;         /* worker finished                    */
} hm_wslot_t;

typedef struct {
    int len;
    hm_span_t *v;
    int n;
} hm_spans_t;

/* engine-owned shared state */
static const hm_cfg_t *g_cfg;
static hm_queue_t g_q[HM_MAX_PWLEN + 1];
static bool g_q_known[HM_MAX_PWLEN + 1]; /* length had a state section */
static atomic_uint_fast64_t g_done_len[HM_MAX_PWLEN + 1];
static _Atomic int g_workers_done;
static _Atomic int g_found_cnt;
static _Atomic int g_show_len;
static hm_wslot_t *g_w;
static pthread_mutex_t g_found_mtx = PTHREAD_MUTEX_INITIALIZER;
static char *g_found_mask;
static bool g_resumed;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static uint64_t engine_pow(int base, int e, bool *ovf)
{
    uint64_t r = 1;

    *ovf = false;
    for (int i = 0; i < e; i++) {
        if (r > UINT64_MAX / (uint64_t)base) {
            *ovf = true;
            return 0;
        }
        r *= (uint64_t)base;
    }
    return r;
}

static void engine_hex_encode(const char *s, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";

    for (size_t i = 0; i < n; i++) {
        out[2 * i] = h[((uint8_t)s[i]) >> 4];
        out[2 * i + 1] = h[(uint8_t)s[i] & 0xf];
    }
    out[2 * n] = '\0';
}

int hm_parse_target(const char *hex, hm_target_t *tg)
{
    size_t l;

    if (hex == NULL || tg == NULL)
        return -1;
    l = strlen(hex);
    if (l != 32) {
        fprintf(stderr, "[-] '%s' is not a 32-char MD5 hex string\n", hex);
        return -1;
    }
    for (int i = 0; i < 16; i++) {
        char c1 = (char)tolower((unsigned char)hex[2 * i]);
        char c2 = (char)tolower((unsigned char)hex[2 * i + 1]);
        int v1;
        int v2;

        if (!isxdigit((unsigned char)c1) || !isxdigit((unsigned char)c2)) {
            fprintf(stderr, "[-] '%s' is not valid hex\n", hex);
            return -1;
        }
        v1 = (c1 >= 'a') ? c1 - 'a' + 10 : c1 - '0';
        v2 = (c2 >= 'a') ? c2 - 'a' + 10 : c2 - '0';
        tg->bytes[i] = (uint8_t)(v1 * 16 + v2);
    }
    memcpy(tg->hex, hex, l);
    tg->hex[l] = '\0';
    return 0;
}

int hm_load_targets(const char *path, hm_target_t *targets, int *nt)
{
    FILE *f;
    char line[256];

    f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "[-] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    while (*nt < HM_MAX_TARGETS && fgets(line, sizeof(line), f) != NULL) {
        char *s = line;
        char *nl;

        while (*s == ' ' || *s == '\t')
            s++;
        if (*s == '#' || *s == '\n' || *s == '\0')
            continue;
        nl = strpbrk(s, "\r\n");
        if (nl != NULL)
            *nl = '\0';
        if (strlen(s) != 32) {
            fprintf(stderr, "[-] hash file line not MD5 hex (32 chars): '%s'\n",
                    s);
            fclose(f);
            return -1;
        }
        if (hm_parse_target(s, &targets[*nt]) < 0) {
            fclose(f);
            return -1;
        }
        (*nt)++;
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* lenctx (md5 midstate fast path)                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t base[4]; /* midstate (or MD5 init when unsalted) */
    uint8_t blk[64];  /* final block template               */
    int cand_off;     /* offset of candidate chars in blk   */
    bool fast;
} lenctx_t;

/* Build the per-length md5 context.
 *
 * fast path cases (one transform per candidate):
 *   - salt is absent:      block = candidate | 0x80 | len
 *   - post-salt:           block = candidate | salt | 0x80 | len
 *   - pre-salt, aligned:   salt occupies whole 64B blocks -> midstate over
 *                          the salt blocks, block = candidate | 0x80 | len
 *   - pre-salt, unaligned: one single block = salt | candidate | 0x80 | len
 * anything longer than 55 bytes falls back to the generic hm_md5() path.
 */
static void lenctx_build(lenctx_t *ctx, int L, const char *salt, int salt_len,
                         bool pre)
{
    int pre_len = pre ? salt_len : 0;
    int post_len = pre ? 0 : salt_len;
    int total = pre_len + L + post_len;
    uint64_t bits = (uint64_t)total * 8;

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->base, HM_MD5_INIT, sizeof(ctx->base));

    if (pre && pre_len > 0 && (pre_len % 64) == 0 && (L + post_len) <= 55) {
        /* block-aligned pre-salt: precompute the midstate */
        uint8_t sblk[64];
        int nblk = pre_len / 64;

        for (int i = 0; i < nblk; i++) {
            memcpy(sblk, salt + (size_t)i * 64, 64);
            hm_md5_transform(ctx->base, sblk);
        }
        ctx->fast = true;
        ctx->cand_off = 0;
        memset(ctx->blk, 0, sizeof(ctx->blk));
        ctx->blk[L + post_len] = 0x80;
        for (int i = 0; i < 8; i++) /* md5 length field is LE */
            ctx->blk[56 + i] = (uint8_t)(bits >> (8 * i));
        if (post_len > 0)
            memcpy(ctx->blk + L, salt, (size_t)post_len);
    } else if (total <= 55) {
        /* everything fits in one block */
        ctx->fast = true;
        ctx->cand_off = pre_len;
        memset(ctx->blk, 0, sizeof(ctx->blk));
        if (pre_len > 0)
            memcpy(ctx->blk, salt, (size_t)pre_len);
        if (post_len > 0)
            memcpy(ctx->blk + pre_len + L, salt, (size_t)post_len);
        ctx->blk[total] = 0x80;
        for (int i = 0; i < 8; i++)
            ctx->blk[56 + i] = (uint8_t)(bits >> (8 * i));
    }
}

static void md5_candidate(const lenctx_t *ctx, const char *cs, int L,
                          const uint8_t *digs, uint8_t out[16],
                          const char *salt, int salt_len, bool pre)
{
    int pre_len = pre ? salt_len : 0;
    int post_len = pre ? 0 : salt_len;

    if (ctx->fast) {
        uint32_t st[4];
        uint8_t blk[64];

        memcpy(st, ctx->base, sizeof(st));
        memcpy(blk, ctx->blk, sizeof(blk));
        for (int k = 0; k < L; k++)
            blk[ctx->cand_off + k] = (uint8_t)cs[digs[k]];
        hm_md5_transform(st, blk);
        for (int i = 0; i < 4; i++) {
            out[4 * i] = (uint8_t)(st[i]);
            out[4 * i + 1] = (uint8_t)(st[i] >> 8);
            out[4 * i + 2] = (uint8_t)(st[i] >> 16);
            out[4 * i + 3] = (uint8_t)(st[i] >> 24);
        }
    } else {
        uint8_t buf[HM_MAX_SALT * 2 + HM_MAX_PWLEN];
        size_t n = 0;

        if (pre_len > 0) {
            memcpy(buf, salt, (size_t)pre_len);
            n = (size_t)pre_len;
        }
        for (int k = 0; k < L; k++)
            buf[n++] = (uint8_t)cs[digs[k]];
        if (post_len > 0) {
            memcpy(buf + n, salt, (size_t)post_len);
            n += (size_t)post_len;
        }
        hm_md5(buf, n, out);
    }
}

static void idx_to_digits(uint64_t idx, uint8_t *d, int L, int cslen)
{
    for (int i = L - 1; i >= 0; i--) {
        d[i] = (uint8_t)(idx % (uint64_t)cslen);
        idx /= (uint64_t)cslen;
    }
}

static bool odom_next(uint8_t *d, int L, int cslen)
{
    for (int i = L - 1; i >= 0; i--) {
        if (++d[i] < cslen)
            return true;
        d[i] = 0;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* span queues                                                         */
/* ------------------------------------------------------------------ */

/* fresh partition of [0, space) over thr spans (empty chunks dropped) */
static int spans_fresh(hm_queue_t *q, int len, uint64_t space, int thr)
{
    uint64_t chunk;
    int n = 0;
    hm_span_t *v;

    if (thr < 1)
        thr = 1;
    chunk = space / (uint64_t)thr;
    v = calloc((size_t)thr, sizeof(hm_span_t));
    if (v == NULL)
        return -1;
    for (int i = 0; i < thr; i++) {
        uint64_t lo = chunk * (uint64_t)i;
        uint64_t hi = (i == thr - 1) ? space : lo + chunk;

        if (lo < hi) {
            v[n].lo = lo;
            v[n].hi = hi;
            n++;
        }
    }
    q->len = len;
    q->v = v;
    q->n = n;
    atomic_store(&q->span_at, 0);
    return 0;
}

static void queues_free_all(void)
{
    for (int L = 0; L <= HM_MAX_PWLEN; L++) {
        free(g_q[L].v);
        g_q[L].v = NULL;
        g_q[L].n = 0;
        g_q[L].len = L;
        atomic_store(&g_q[L].span_at, 0);
    }
}

/* ------------------------------------------------------------------ */
/* state save (post-join only: workers are gone, no races)             */
/* ------------------------------------------------------------------ */

static void snapshot_spans(hm_spans_t *snaps)
{
    for (int L = 0; L <= HM_MAX_PWLEN; L++) {
        snaps[L].len = L;
        snaps[L].v = NULL;
        snaps[L].n = 0;
    }

    for (int L = g_cfg->minlen; L <= g_cfg->maxlen; L++) {
        hm_queue_t *q = &g_q[L];
        int span_at = atomic_load(&q->span_at);
        int rem = q->n - span_at;

        if (q->v == NULL)
            continue;
        snaps[L].v = calloc((size_t)(rem + g_cfg->nthreads + 1),
                            sizeof(hm_span_t));
        if (snaps[L].v == NULL) {
            fprintf(stderr, "[-] out of memory (state snapshot)\n");
            exit(1);
        }
        for (int i = span_at; i < q->n; i++)
            snaps[L].v[snaps[L].n++] = q->v[i];
    }

    for (int t = 0; t < g_cfg->nthreads; t++) {
        uint64_t cur_lo;
        uint64_t cur_hi;
        uint64_t pos;
        int L;

        if (atomic_load(&g_w[t].cur_valid) == 0)
            continue;
        cur_lo = atomic_load(&g_w[t].cur_lo);
        cur_hi = atomic_load(&g_w[t].cur_hi);
        pos = atomic_load(&g_w[t].span_pos);
        L = (int)atomic_load(&g_w[t].cur_len);
        if (L < g_cfg->minlen || L > g_cfg->maxlen)
            continue;
        if (cur_lo + pos >= cur_hi)
            continue; /* tail already finished */
        if (snaps[L].v == NULL)
            continue; /* queue absent - should not happen */
        snaps[L].v[snaps[L].n].lo = cur_lo + pos;
        snaps[L].v[snaps[L].n].hi = cur_hi;
        snaps[L].n++;
    }
}

static void snapshot_free(hm_spans_t *snaps)
{
    for (int L = 0; L <= HM_MAX_PWLEN; L++) {
        free(snaps[L].v);
        snaps[L].v = NULL;
        snaps[L].n = 0;
    }
}

static int state_write(void)
{
    char tmp[HM_MAX_STATE_PATH + 32];
    char cshex[2 * HM_MAX_CS + 1];
    char salthex[2 * HM_MAX_SALT + 1];
    hm_spans_t snaps[HM_MAX_PWLEN + 1];
    FILE *f;
    int failed = 0;

    if (g_cfg->state_path[0] == '\0')
        return 0;
    memset(snaps, 0, sizeof(snaps));
    snapshot_spans(snaps);

    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", g_cfg->state_path, (int)getpid());
    engine_hex_encode(g_cfg->cs, (size_t)g_cfg->cslen, cshex);
    if (g_cfg->salt_len == 0)
        strcpy(salthex, "-");
    else
        engine_hex_encode(g_cfg->salt, (size_t)g_cfg->salt_len, salthex);

    f = fopen(tmp, "w");
    if (f == NULL) {
        fprintf(stderr, "[-] cannot write state %s: %s\n", tmp,
                strerror(errno));
        snapshot_free(snaps);
        return -1;
    }
    if (fprintf(f,
                "%s\nmode %s\ncs %s\nmin %d\nmax %d\nsalt %s\npos %s\n"
                "targets %d\n",
                HM_STATE_MAGIC, (g_cfg->rec != NULL) ? "map" : "brute", cshex,
                g_cfg->minlen, g_cfg->maxlen, salthex,
                g_cfg->salt_pre ? "pre" : "post", g_cfg->ntargets) < 0)
        failed = 1;
    if (!failed) {
        for (int i = 0; i < g_cfg->ntargets && !failed; i++)
            if (fprintf(f, "%s\n", g_cfg->targets[i].hex) < 0)
                failed = 1;
        for (int L = g_cfg->minlen; L <= g_cfg->maxlen && !failed; L++) {
            if (fprintf(f, "len %d spans %d\n", L, snaps[L].n) < 0) {
                failed = 1;
                break;
            }
            for (int k = 0; k < snaps[L].n; k++) {
                if (fprintf(f, "%" PRIu64 " %" PRIu64 "\n", snaps[L].v[k].lo,
                            snaps[L].v[k].hi) < 0) {
                    failed = 1;
                    break;
                }
            }
        }
    }
    if (!failed && fflush(f) != 0)
        failed = 1;
    if (!failed)
        (void)hm_fsync(f);
    if (fclose(f) != 0)
        failed = 1;
    if (failed) {
        remove(tmp);
        fprintf(stderr, "[-] state write failed\n");
        snapshot_free(snaps);
        return -1;
    }
    snapshot_free(snaps);
    if (rename(tmp, g_cfg->state_path) != 0) {
        fprintf(stderr, "[-] state rename failed: %s\n", strerror(errno));
        remove(tmp);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* state load                                                          */
/* ------------------------------------------------------------------ */

static int state_load(void)
{
    FILE *f;
    char line[512];
    const char *want_mode = (g_cfg->rec != NULL) ? "map" : "brute";
    char cshex_mine[2 * HM_MAX_CS + 1];
    char salthex_mine[2 * HM_MAX_SALT + 1];
    bool have_magic = false;
    bool ok = true;
    int phase = 0; /* 0 = headers, 1 = target lines, 2 = span sections */
    int tcount = 0;
    int ntargets = -1;
    int cur_len = -1;
    int cur_n = -1;
    int cur_idx = 0;
    hm_span_t *cur_span = NULL;

    if (g_cfg->state_path[0] == '\0')
        return 0; /* no state requested: fresh */
    f = fopen(g_cfg->state_path, "r");
    if (f == NULL) {
        if (errno == ENOENT)
            return 0; /* absent state: fresh run */
        fprintf(stderr, "[-] cannot open state %s: %s\n", g_cfg->state_path,
                strerror(errno));
        return -1;
    }

    engine_hex_encode(g_cfg->cs, (size_t)g_cfg->cslen, cshex_mine);
    if (g_cfg->salt_len == 0)
        strcpy(salthex_mine, "-");
    else
        engine_hex_encode(g_cfg->salt, (size_t)g_cfg->salt_len, salthex_mine);

    while (fgets(line, sizeof(line), f) != NULL) {
        char *nl = strpbrk(line, "\r\n");

        if (nl != NULL)
            *nl = '\0';

        if (phase == 0) {
            if (!have_magic) {
                if (strncmp(line, HM_STATE_MAGIC,
                            strlen(HM_STATE_MAGIC)) == 0)
                    have_magic = true;
                else if (line[0] != '\0' && line[0] != '#') {
                    fprintf(stderr,
                            "[-] state file bad magic (use --fresh to "
                            "ignore)\n");
                    ok = false;
                    break;
                }
                continue;
            }
            if (strncmp(line, "mode ", 5) == 0) {
                if (strcmp(line + 5, want_mode) != 0)
                    ok = false;
            } else if (strncmp(line, "cs ", 3) == 0) {
                if (strcmp(line + 3, cshex_mine) != 0)
                    ok = false;
            } else if (strncmp(line, "min ", 4) == 0) {
                int iv;

                if (sscanf(line + 4, "%d", &iv) != 1 || iv != g_cfg->minlen)
                    ok = false;
            } else if (strncmp(line, "max ", 4) == 0) {
                int iv;

                if (sscanf(line + 4, "%d", &iv) != 1 || iv != g_cfg->maxlen)
                    ok = false;
            } else if (strncmp(line, "salt ", 5) == 0) {
                if (strcmp(line + 5, salthex_mine) != 0)
                    ok = false;
            } else if (strncmp(line, "pos ", 4) == 0) {
                if (strcmp(line + 4, g_cfg->salt_pre ? "pre" : "post") != 0)
                    ok = false;
            } else if (strncmp(line, "targets ", 8) == 0) {
                if (sscanf(line + 8, "%d", &ntargets) != 1 ||
                    ntargets != g_cfg->ntargets) {
                    ok = false;
                } else {
                    phase = 1;
                    tcount = 0;
                    if (ntargets == 0)
                        phase = 2;
                }
            } else if (line[0] != '\0') {
                ok = false; /* unexpected header token */
            }
            continue;
        }

        if (phase == 1) {
            char th[80];

            if (sscanf(line, "%32s", th) != 1 ||
                strcmp(th, g_cfg->targets[tcount].hex) != 0)
                ok = false;
            tcount++;
            if (tcount >= ntargets)
                phase = 2;
            continue;
        }

        /* phase 2: span sections */
        {
            int len_hdr;
            int n_spans;

            if (sscanf(line, "len %d spans %d", &len_hdr, &n_spans) == 2) {
                if (cur_span != NULL) { /* previous section unfinished */
                    fprintf(stderr,
                            "[-] state span section truncated (use --fresh)\n");
                    ok = false;
                    break;
                }
                if (len_hdr < g_cfg->minlen || len_hdr > g_cfg->maxlen ||
                    n_spans < 0 || n_spans > HM_MAX_SPANS_IN_STATE) {
                    ok = false;
                    break;
                }
                cur_len = len_hdr;
                cur_n = n_spans;
                cur_idx = 0;
                cur_span = (n_spans > 0)
                               ? calloc((size_t)n_spans, sizeof(hm_span_t))
                               : NULL;
                if (n_spans > 0 && cur_span == NULL) {
                    fprintf(stderr, "[-] out of memory (state load)\n");
                    ok = false;
                    break;
                }
                if (cur_n == 0) {
                    /* section for a finished/empty length */
                    g_q[cur_len].len = cur_len;
                    free(g_q[cur_len].v);
                    g_q[cur_len].v = NULL;
                    g_q[cur_len].n = 0;
                    atomic_store(&g_q[cur_len].span_at, 0);
                    g_q_known[cur_len] = true;
                    cur_len = -1;
                    cur_n = -1;
                }
                continue;
            }
            if (cur_len >= 0) {
                uint64_t lo;
                uint64_t hi;

                if (sscanf(line, "%" SCNu64 " %" SCNu64, &lo, &hi) == 2) {
                    if (hi > lo) {
                        if (cur_idx >= cur_n) {
                            ok = false; /* more lines than 'spans' declared */
                            break;
                        }
                        cur_span[cur_idx].lo = lo;
                        cur_span[cur_idx].hi = hi;
                        cur_idx++;
                        if (cur_idx == cur_n) {
                            g_q[cur_len].len = cur_len;
                            free(g_q[cur_len].v);
                            g_q[cur_len].v = cur_span;
                            g_q[cur_len].n = cur_n;
                            atomic_store(&g_q[cur_len].span_at, 0);
                            g_q_known[cur_len] = true;
                            cur_span = NULL;
                            cur_len = -1;
                            cur_n = -1;
                            cur_idx = 0;
                        }
                    }
                    continue;
                }
                if (line[0] != '\0') { /* garbage inside span section */
                    ok = false;
                    break;
                }
            }
            /* ignore blank lines / unknown trailing junk */
        }
    }
    fclose(f);

    if (cur_span != NULL) {
        /* last section ended but file hit EOF mid-section */
        fprintf(stderr,
                "[-] state span section truncated (use --fresh to ignore)\n");
        free(cur_span);
        cur_span = NULL;
        ok = false;
    }
    if (!have_magic) {
        fprintf(stderr, "[-] state file missing magic (use --fresh)\n");
        return -1;
    }
    if (!ok || tcount != (ntargets > 0 ? ntargets : 0)) {
        fprintf(stderr,
                "[-] state file incompatible/corrupt for this run (use --fresh "
                "to ignore)\n");
        return -1;
    }

    g_resumed = (ntargets >= 0);
    return 0;
}

/* fresh-span any length the state did not mention */
static int queues_complete(void)
{
    for (int L = g_cfg->minlen; L <= g_cfg->maxlen; L++) {
        bool ovf;
        uint64_t space = engine_pow(g_cfg->cslen, L, &ovf);

        if (ovf) {
            fprintf(stderr, "[-] keyspace overflow at length %d\n", L);
            return -1;
        }
        if (g_q_known[L])
            continue; /* state already decided this length (may be empty) */
        if (g_q[L].v == NULL) {
            if (spans_fresh(&g_q[L], L, space, g_cfg->nthreads) < 0) {
                fprintf(stderr, "[-] out of memory (span partition)\n");
                return -1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* worker                                                              */
/* ------------------------------------------------------------------ */

static const hm_target_t *find_hit(const uint8_t dg[16])
{
    for (int i = 0; i < g_cfg->ntargets; i++) {
        if (memcmp(dg, g_cfg->targets[i].bytes, 16) == 0)
            return &g_cfg->targets[i];
    }
    return NULL;
}

static void report_found(const hm_target_t *tg, const char *plain, int L)
{
    int idx = -1;
    bool all;

    for (int i = 0; i < g_cfg->ntargets; i++) {
        if (strcmp(g_cfg->targets[i].hex, tg->hex) == 0)
            idx = i;
    }
    pthread_mutex_lock(&g_found_mtx);
    if (idx >= 0 && g_found_mask[idx] == 0) {
        g_found_mask[idx] = 1;
        printf("[+] CRACKED  %s  ->  %s  (len %d)\n", tg->hex, plain, L);
        if (g_cfg->outf != NULL) {
            fprintf(g_cfg->outf, "%s:%s\n", tg->hex, plain);
            fflush(g_cfg->outf);
        }
        atomic_fetch_add(&g_found_cnt, 1);
    }
    all = (atomic_load(&g_found_cnt) >= g_cfg->ntargets);
    pthread_mutex_unlock(&g_found_mtx);
    if (all)
        atomic_store(&hm_stop, 1);
}

static void map_record_write(const uint8_t dg[16], const char *plain, int plen)
{
    uint8_t rec[HM_MAX_PLAIN + 17];

    memcpy(rec, dg, 16);
    rec[16] = (uint8_t)plen;
    memcpy(rec + 17, plain, (size_t)plen);
    if (fwrite(rec, 1, (size_t)(17 + plen), g_cfg->rec) !=
        (size_t)(17 + plen)) {
        fprintf(stderr, "[-] map stream write failed: %s\n", strerror(errno));
        exit(1);
    }
}

static void record_stop_tail(hm_wslot_t *me, int L, uint64_t lo, uint64_t hi,
                             uint64_t done)
{
    atomic_store(&me->cur_len, L);
    atomic_store(&me->cur_lo, lo);
    atomic_store(&me->cur_hi, hi);
    atomic_store(&me->span_pos, done);
    atomic_store(&me->cur_valid, 1);
}

static void *worker(void *arg)
{
    intptr_t tid = (intptr_t)arg;
    const int pre_len = g_cfg->salt_pre ? g_cfg->salt_len : 0;
    const int post_len = g_cfg->salt_pre ? 0 : g_cfg->salt_len;
    const char *cs = g_cfg->cs;
    const bool pre = g_cfg->salt_pre != 0;
    hm_wslot_t *me = &g_w[tid];
    uint8_t digs[HM_MAX_PWLEN];
    uint8_t dg[16];
    char plain[HM_MAX_PLAIN];

    atomic_store(&me->cur_valid, 0);
    atomic_store(&me->exited, 0);

    for (int L = g_cfg->minlen; L <= g_cfg->maxlen; L++) {
        hm_queue_t *q = &g_q[L];
        lenctx_t ctx;
        bool ovf;
        uint64_t space = engine_pow(g_cfg->cslen, L, &ovf);

        if (ovf || space == 0)
            continue;
        lenctx_build(&ctx, L, g_cfg->salt, g_cfg->salt_len, pre);
        atomic_store(&g_show_len, L);

        for (;;) {
            const int k = atomic_fetch_add(&q->span_at, 1);
            uint64_t lo;
            uint64_t hi;
            uint64_t idx;
            uint64_t done = 0;

            if (k >= q->n)
                break; /* queue exhausted -> next length */
            lo = q->v[k].lo;
            hi = q->v[k].hi;
            idx_to_digits(lo, digs, L, g_cfg->cslen);
            memset(plain, 0, (size_t)(pre_len + L + post_len + 1));
            if (pre_len > 0)
                memcpy(plain, g_cfg->salt, (size_t)pre_len);
            if (post_len > 0)
                memcpy(plain + pre_len + L, g_cfg->salt, (size_t)post_len);

            idx = lo;
            for (; idx < hi; idx++) {
                if (atomic_load(&hm_stop) != 0)
                    goto stop_span;
                md5_candidate(&ctx, cs, L, digs, dg, g_cfg->salt,
                              g_cfg->salt_len, pre);
                if (g_cfg->rec != NULL) {
                    int plen = pre_len + L + post_len;

                    for (int kk = 0; kk < L; kk++)
                        plain[pre_len + kk] = cs[digs[kk]];
                    map_record_write(dg, plain, plen);
                } else {
                    const hm_target_t *hit = find_hit(dg);

                    if (hit != NULL) {
                        char found[HM_MAX_PLAIN];

                        memcpy(found, plain, (size_t)(pre_len + L + post_len));
                        for (int kk = 0; kk < L; kk++)
                            found[pre_len + kk] = cs[digs[kk]];
                        found[pre_len + L + post_len] = '\0';
                        report_found(hit, found, L);
                        if (atomic_load(&hm_stop) != 0)
                            goto stop_span;
                    }
                }
                if (!odom_next(digs, L, g_cfg->cslen))
                    break; /* wrapped: end of this span's keyspace */
                done = idx - lo + 1;
            }
            atomic_fetch_add(&g_done_len[L], hi - lo);
            continue;

stop_span:
            done = idx - lo;
            atomic_fetch_add(&g_done_len[L], done);
            if (idx < hi)
                record_stop_tail(me, L, lo, hi, done);
            goto worker_exit;
        }
    }
worker_exit:
    atomic_store(&me->exited, 1);
    atomic_fetch_add(&g_workers_done, 1);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* progress + engine entry                                             */
/* ------------------------------------------------------------------ */

static void engine_progress_tick(uint64_t total_space, double t0)
{
    static double last_t;
    static uint64_t last_done;
    static bool first = true;
    uint64_t done = 0;
    double rate;
    double pct;
    double remain;
    char cbuf[32];
    char rbuf[32];

    if (first) {
        first = false;
        last_t = t0;
        last_done = 0;
    }
    for (int L = 0; L <= HM_MAX_PWLEN; L++)
        done += atomic_load(&g_done_len[L]);
    double now = hm_now();
    rate = (now > last_t) ? (double)(done - last_done) / (now - last_t) : 0.0;
    last_done = done;
    last_t = now;
    hm_fmt_u64(done, cbuf, sizeof(cbuf));
    hm_fmt_rate(rate, rbuf, sizeof(rbuf));
    pct = (total_space > 0) ? (double)done * 100.0 / (double)total_space : 0.0;
    if (pct > 100.0)
        pct = 100.0;
    remain = (rate > 0.0) ? (double)(total_space - done) / rate : 0.0;
    printf("\r[*] len %d  %s tried  %.1f%%  %s  eta %.0fs   ",
           atomic_load(&g_show_len), cbuf, pct, rbuf, remain);
    fflush(stdout);
}

int hm_engine_run(hm_cfg_t *cfg, int *finished)
{
    uint64_t total_space = 0;
    double t0;
    pthread_t *tids;
    int nfound;
    bool ovf;

    g_cfg = cfg;
    g_resumed = false;
    memset(g_done_len, 0, sizeof(g_done_len));
    memset(g_q_known, 0, sizeof(g_q_known));
    atomic_store(&g_workers_done, 0);
    atomic_store(&g_found_cnt, 0);
    atomic_store(&g_show_len, cfg->minlen);
    queues_free_all();

    g_found_mask = calloc((size_t)cfg->ntargets + 1, 1);
    g_w = calloc((size_t)cfg->nthreads, sizeof(hm_wslot_t));
    if (g_found_mask == NULL || g_w == NULL || cfg->nthreads < 1) {
        fprintf(stderr, "[-] out of memory / bad thread count\n");
        free(g_found_mask);
        free(g_w);
        return -1;
    }

    for (int L = cfg->minlen; L <= cfg->maxlen; L++) {
        uint64_t sp = engine_pow(cfg->cslen, L, &ovf);

        if (ovf || sp > UINT64_MAX - total_space) {
            fprintf(stderr, "[-] keyspace overflow, lower --max\n");
            free(g_found_mask);
            free(g_w);
            return -1;
        }
        total_space += sp;
    }
    if (total_space == 0) {
        fprintf(stderr, "[-] empty keyspace\n");
        free(g_found_mask);
        free(g_w);
        return -1;
    }

    if (state_load() < 0) {
        free(g_found_mask);
        free(g_w);
        return -1;
    }
    if (queues_complete() < 0) {
        queues_free_all();
        free(g_found_mask);
        free(g_w);
        return -1;
    }

    printf("[*] hashmap v%s - %s mode%s\n", HM_VERSION,
           (cfg->rec != NULL) ? "map" : "brute",
           g_resumed ? " (resumed from state)" : "");
    printf("[*] charset: (%d chars)%s%s%s\n", cfg->cslen,
           cfg->cslen <= 64 ? " [" : "", cfg->cslen <= 64 ? cfg->cs : "",
           cfg->cslen <= 64 ? "]" : "");
    char kbuf[32];
    hm_fmt_u64(total_space, kbuf, sizeof(kbuf));
    printf("[*] length: %d-%d  keyspace: %s\n", cfg->minlen, cfg->maxlen,
           kbuf);
    printf("[*] threads: %d  salt: %s (%s)\n", cfg->nthreads,
           cfg->salt_len ? cfg->salt : "(none)",
           cfg->salt_len ? (cfg->salt_pre ? "pre" : "post") : "-");
    if (cfg->rec == NULL)
        printf("[*] targets: %d\n", cfg->ntargets);

    t0 = hm_now();
    tids = calloc((size_t)cfg->nthreads, sizeof(pthread_t));
    if (tids == NULL) {
        fprintf(stderr, "[-] out of memory\n");
        queues_free_all();
        free(g_found_mask);
        free(g_w);
        return -1;
    }
    for (int i = 0; i < cfg->nthreads; i++) {
        if (pthread_create(&tids[i], NULL, worker, (void *)(intptr_t)i) != 0) {
            fprintf(stderr, "[-] pthread_create failed\n");
            atomic_store(&hm_stop, 1);
        }
    }

    while (atomic_load(&g_workers_done) < cfg->nthreads) {
        hm_sleep_ms(200);
        if (atomic_load(&hm_stop) == 0)
            engine_progress_tick(total_space, t0);
    }
    for (int i = 0; i < cfg->nthreads; i++)
        pthread_join(tids[i], NULL);

    /* count remaining work */
    uint64_t remaining = 0;
    for (int L = cfg->minlen; L <= cfg->maxlen; L++) {
        int span_at = atomic_load(&g_q[L].span_at);

        if (g_q[L].v == NULL)
            continue;
        for (int i = span_at; i < g_q[L].n; i++) {
            if (g_q[L].v[i].hi > g_q[L].v[i].lo)
                remaining++;
        }
    }
    for (int t = 0; t < cfg->nthreads; t++) {
        uint64_t cur_lo = atomic_load(&g_w[t].cur_lo);
        uint64_t cur_hi = atomic_load(&g_w[t].cur_hi);
        uint64_t pos = atomic_load(&g_w[t].span_pos);

        if (atomic_load(&g_w[t].cur_valid) != 0 && cur_lo + pos < cur_hi)
            remaining++;
    }

    nfound = atomic_load(&g_found_cnt);
    *finished = (remaining == 0 ||
                 (cfg->rec == NULL && nfound >= cfg->ntargets));

    printf("\r\033[K");
    double elapsed = hm_now() - t0;
    uint64_t done_total = 0;
    for (int L = 0; L <= HM_MAX_PWLEN; L++)
        done_total += atomic_load(&g_done_len[L]);
    char cbuf[32];
    char rbuf[32];
    hm_fmt_u64(done_total, cbuf, sizeof(cbuf));
    hm_fmt_rate(elapsed > 0 ? (double)done_total / elapsed : 0.0, rbuf,
                sizeof(rbuf));
    printf("[*] done: %s candidates in %.2fs (%s avg)\n", cbuf, elapsed, rbuf);

    if (!*finished && cfg->state_path[0] != '\0') {
        if (state_write() == 0)
            printf("[*] state saved to %s (resume with --state %s)\n",
                   cfg->state_path, cfg->state_path);
    } else if (*finished && cfg->state_path[0] != '\0') {
        if (remove(cfg->state_path) == 0)
            printf("[*] state file removed (run complete)\n");
        else if (errno != ENOENT)
            printf("[-] failed removing state: %s\n", strerror(errno));
    }

    queues_free_all();
    free(tids);
    free(g_found_mask);
    free(g_w);
    return nfound;
}

/* ------------------------------------------------------------------ */
/* shared option parser (brute/map)                                    */
/* ------------------------------------------------------------------ */

int hm_opts_common(int argc, char **argv, hm_cfg_t *cfg, bool want_targets)
{
    static const hm_longopt_t lopts[] = {
        { "hash", 1, 'H' },
        { "file", 1, 'f' },
        { "charset", 1, 'c' },
        { "min", 1, 1 },
        { "max", 1, 2 },
        { "threads", 1, 't' },
        { "salt", 1, 's' },
        { "salt-pos", 1, 'p' },
        { "out", 1, 'o' },
        { "state", 1, 3 },
        { "fresh", 0, 4 },
        { NULL, 0, 0 }
    };
    int opt;
    bool have_cs = false;
    bool have_out = false;
    char cs_buf[HM_MAX_CS + 1];
    size_t cs_buflen = 0;
    int cores = hm_cpu_count();

    cfg->minlen = 1;
    cfg->maxlen = 6;
    cfg->nthreads = (cores > 1) ? cores : 1;
    cfg->ntargets = 0;

    hm_getopt_reset();
    while ((opt = hm_getopt_long(argc, argv, "H:f:c:t:s:p:o:", lopts)) != -1) {
        switch (opt) {
        case 'H':
            if (!want_targets) {
                fprintf(stderr, "[-] -H not valid in this mode\n");
                return -1;
            }
            if (cfg->ntargets >= HM_MAX_TARGETS) {
                fprintf(stderr, "[-] too many targets\n");
                return -1;
            }
            if (hm_parse_target(hm_optarg, &cfg->targets[cfg->ntargets]) < 0)
                return -1;
            cfg->ntargets++;
            break;
        case 'f':
            if (!want_targets) {
                fprintf(stderr, "[-] -f not valid in this mode\n");
                return -1;
            }
            if (hm_load_targets(hm_optarg, cfg->targets, &cfg->ntargets) < 0)
                return -1;
            break;
        case 'c':
            have_cs = true;
            if (strlen(hm_optarg) > HM_MAX_CS) {
                fprintf(stderr, "[-] charset too long (max %d)\n", HM_MAX_CS);
                return -1;
            }
            snprintf(cs_buf, sizeof(cs_buf), "%s", hm_optarg);
            break;
        case 1: /* min */
            if (sscanf(hm_optarg, "%d", &cfg->minlen) != 1 ||
                cfg->minlen < 1 || cfg->minlen > HM_MAX_PWLEN) {
                fprintf(stderr, "[-] bad --min value\n");
                return -1;
            }
            break;
        case 2: /* max */
            if (sscanf(hm_optarg, "%d", &cfg->maxlen) != 1 ||
                cfg->maxlen < 1 || cfg->maxlen > HM_MAX_PWLEN) {
                fprintf(stderr, "[-] bad --max value\n");
                return -1;
            }
            break;
        case 't':
            if (sscanf(hm_optarg, "%d", &cfg->nthreads) != 1 ||
                cfg->nthreads < 1) {
                fprintf(stderr, "[-] bad --threads value\n");
                return -1;
            }
            break;
        case 's':
            cfg->salt_len = (int)strlen(hm_optarg);
            if (cfg->salt_len > HM_MAX_SALT) {
                fprintf(stderr, "[-] salt too long (max %d)\n", HM_MAX_SALT);
                return -1;
            }
            memcpy(cfg->salt, hm_optarg, (size_t)cfg->salt_len);
            break;
        case 'p':
            if (strcmp(hm_optarg, "pre") == 0)
                cfg->salt_pre = 1;
            else if (strcmp(hm_optarg, "post") == 0)
                cfg->salt_pre = 0;
            else {
                fprintf(stderr, "[-] salt-pos must be pre|post\n");
                return -1;
            }
            break;
        case 'o':
            have_out = true;
            snprintf(cfg->out_path, sizeof(cfg->out_path), "%s", hm_optarg);
            break;
        case 3: /* state */
            snprintf(cfg->state_path, sizeof(cfg->state_path), "%s", hm_optarg);
            break;
        case 4: /* fresh */
            if (cfg->state_path[0] != '\0')
                remove(cfg->state_path);
            cfg->state_path[0] = '\0';
            break;
        default:
            return -1;
        }
    }

    if (!have_cs)
        strcpy(cs_buf, "digits");
    if (hm_build_charset(cs_buf, cfg->cs, &cs_buflen) < 0) {
        fprintf(stderr, "[-] broken/empty charset spec '%s'\n", cs_buf);
        return -1;
    }
    cfg->cslen = (int)cs_buflen;

    if (!have_out)
        cfg->out_path[0] = '\0';
    return 0;
}

