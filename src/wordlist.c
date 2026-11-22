/* hashmap - wordlist mode: match target hashes against a wordlist
 *
 * This is the "common passwords" stage of a lookup: instead of brute forcing
 * a keyspace, every candidate of a wordlist is hashed and compared.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcrypt.h"
#include "crypto.h"
#include "engine.h"
#include "hashmap.h"
#include "iouring.h"
#include "match.h"
#include "util.h"

#define HM_WL_MAX_TARGETS 4096
#define HM_WL_CHUNK 2048 /* lines per work unit */

typedef struct {
    uint8_t bytes[32];
    char hex[65];
    char salt[48]; /* the bcrypt setting of this hash */
    _Atomic int found;
} wl_target_t;

typedef struct {
    wl_target_t *targets;
    int ntargets;
    char *salt;
    int salt_len;
    int salt_pre;
    hm_algo_t algo;
    int use_bcrypt;
    char *data;      /* the whole wordlist */
    size_t data_len;
    size_t *offs;    /* offset of every line start (+ one past the end) */
    size_t nlines;
    _Atomic size_t next;   /* next line block to take */
    _Atomic int stop;      /* stop flag */
    _Atomic int nfound;
    int dlen; /* digest bytes compared per candidate */
    FILE *outf;
    pthread_mutex_t mtx;
} wl_ctx_t;

static wl_ctx_t g_wl;

/* exact multi-target lookup (see match.h): one probe per candidate instead of
 * a memcmp per target, which is what the 4096-target runs need */
static hm_match_t g_wl_match;
static bool g_wl_match_ready;
static uint8_t g_wl_match_digests[HM_MATCH_MAX_TARGETS][32];
static const void *g_wl_match_user[HM_MATCH_MAX_TARGETS];

/* hash one candidate (with salt) */
static void wl_hash(const char *line, size_t len, uint8_t *out,
                    const char *bcrypt_setting)
{
    uint8_t buf[HM_MAX_PLAIN];
    size_t n = 0;
    size_t ol = 0;

    if (g_wl.salt_len > 0 && g_wl.salt_pre) {
        memcpy(buf, g_wl.salt, (size_t)g_wl.salt_len);
        n = (size_t)g_wl.salt_len;
    }
    /* Reserve room for a suffix salt and the terminator bcrypt requires. */
    size_t suffix_len = g_wl.salt_pre ? 0u : (size_t)g_wl.salt_len;
    if (len > sizeof(buf) - n - suffix_len - 1)
        len = sizeof(buf) - n - suffix_len - 1;
    memcpy(buf + n, line, len);
    n += len;
    if (g_wl.salt_len > 0 && !g_wl.salt_pre) {
        memcpy(buf + n, g_wl.salt, (size_t)g_wl.salt_len);
        n += (size_t)g_wl.salt_len;
    }
    buf[n] = '\0';
    if (g_wl.use_bcrypt && bcrypt_setting != NULL && bcrypt_setting[0] != '\0') {
        char h[HM_BCRYPT_MAX];

        if (hm_bcrypt((const char *)buf, bcrypt_setting, h, sizeof(h)) < 0) {
            memset(out, 0, 32);
            return;
        }
        (void)hm_bcrypt_digest(h, out);
        return;
    }
    hm_hash(g_wl.algo, buf, n, out, &ol);
}

/* digest bytes of a finished MD5 state (little endian words) */
static void md5_out(const uint32_t st[4], uint8_t out[16])
{
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (uint8_t)(st[i]);
        out[4 * i + 1] = (uint8_t)(st[i] >> 8);
        out[4 * i + 2] = (uint8_t)(st[i] >> 16);
        out[4 * i + 3] = (uint8_t)(st[i] >> 24);
    }
}

/* digest bytes of a finished SHA-256 state (big endian words) */
static void sha256_out(const uint32_t st[8], uint8_t out[32])
{
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(st[i] >> 24);
        out[4 * i + 1] = (uint8_t)(st[i] >> 16);
        out[4 * i + 2] = (uint8_t)(st[i] >> 8);
        out[4 * i + 3] = (uint8_t)(st[i]);
    }
}

/* Build the single MD5 block for a line (salt included). Returns -1 when the
 * message does not fit one block and has to use the generic path. */
static int wl_md5_block(const char *line, size_t len, uint8_t blk[64])
{
    size_t total = (size_t)g_wl.salt_len + len;
    size_t n = 0;
    uint64_t bits;

    if (total > 55)
        return -1;
    memset(blk, 0, 64);
    if (g_wl.salt_len > 0 && g_wl.salt_pre) {
        memcpy(blk, g_wl.salt, (size_t)g_wl.salt_len);
        n = (size_t)g_wl.salt_len;
    }
    memcpy(blk + n, line, len);
    n += len;
    if (g_wl.salt_len > 0 && !g_wl.salt_pre) {
        memcpy(blk + n, g_wl.salt, (size_t)g_wl.salt_len);
        n += (size_t)g_wl.salt_len;
    }
    bits = (uint64_t)total * 8;
    blk[n] = 0x80;
    for (int i = 0; i < 8; i++)
        blk[56 + i] = (uint8_t)(bits >> (8 * i));
    return 0;
}

/* Build the single SHA-256 block for a line (salt included). */
static int wl_sha256_block(const char *line, size_t len, uint8_t blk[64])
{
    size_t total = (size_t)g_wl.salt_len + len;
    size_t n = 0;
    uint64_t bits;

    if (total > 55)
        return -1;
    memset(blk, 0, 64);
    if (g_wl.salt_len > 0 && g_wl.salt_pre) {
        memcpy(blk, g_wl.salt, (size_t)g_wl.salt_len);
        n = (size_t)g_wl.salt_len;
    }
    memcpy(blk + n, line, len);
    n += len;
    if (g_wl.salt_len > 0 && !g_wl.salt_pre) {
        memcpy(blk + n, g_wl.salt, (size_t)g_wl.salt_len);
        n += (size_t)g_wl.salt_len;
    }
    bits = (uint64_t)total * 8;
    blk[n] = 0x80;
    for (int i = 0; i < 8; i++)
        blk[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    return 0;
}

static int wl_hit_one(int t, const char *plain, size_t len);

static int wl_hit(const uint8_t *dg, size_t dlen, const char *plain, size_t len)
{
    /* The index is built for the width this run hashes to (the algorithm is
     * derived from the hash length, so that width is known before the
     * workers start). It replaces the per-target memcmp scan. */
    if (g_wl_match_ready && (int)dlen == g_wl.dlen) {
        unsigned hits[HM_MATCH_MAX_TARGETS];
        unsigned n = hm_match(&g_wl_match, dg, hits);
        int any = 0;

        for (unsigned k = 0; k < n; k++) {
            int t = (int)((const wl_target_t *)g_wl_match_user[hits[k]] -
                          g_wl.targets);

            if (!g_wl.targets[t].found)
                any |= wl_hit_one(t, plain, len);
        }
        return any;
    }
    int any = 0;
    for (int t = 0; t < g_wl.ntargets; t++) {
        if (g_wl.targets[t].found || memcmp(g_wl.targets[t].bytes, dg, dlen) != 0)
            continue;
        any |= wl_hit_one(t, plain, len);
    }
    return any;
}

/* the single-target compare-and-report body of wl_hit */
static int wl_hit_one(int t, const char *plain, size_t len)
{
    if (g_wl.targets[t].found)
        return 0;
    pthread_mutex_lock(&g_wl.mtx);
    if (!g_wl.targets[t].found) {
        char out[HM_MAX_PLAIN + 1];

        memcpy(out, plain, len > HM_MAX_PLAIN ? HM_MAX_PLAIN : len);
        out[len > HM_MAX_PLAIN ? HM_MAX_PLAIN : len] = '\0';
        g_wl.targets[t].found = 1;
        printf("[+] CRACKED  %s  ->  %s\n", g_wl.targets[t].hex, out);
        if (g_wl.outf != NULL) {
            fprintf(g_wl.outf, "%s:%s\n", g_wl.targets[t].hex, out);
            fflush(g_wl.outf);
        }
        atomic_fetch_add(&g_wl.nfound, 1);
    }
    pthread_mutex_unlock(&g_wl.mtx);
    return 1;
}

static void *wl_worker(void *arg)
{
    (void)arg;
    uint8_t dg[32];

    for (;;) {
        size_t start;
        size_t end;
        size_t i;

        if (atomic_load(&g_wl.stop) != 0)
            return NULL;
        start = atomic_fetch_add(&g_wl.next, HM_WL_CHUNK);
        end = start + HM_WL_CHUNK;
        if (start >= g_wl.nlines)
            return NULL;
        if (end > g_wl.nlines)
            end = g_wl.nlines;

        i = start;
        while (i < end) {
            /* collect up to four lines so MD5 can run four chains at once */
            size_t offs[4];
            size_t lens[4];
            int n = 0;

            while (i < end && n < 4) {
                size_t off = g_wl.offs[i];
                size_t eol = g_wl.offs[i + 1];
                size_t len;

                while (eol > off && g_wl.data[eol - 1] == '\n')
                    eol--;
                while (eol > off && g_wl.data[eol - 1] == '\r')
                    eol--;
                len = eol - off;
                i++;
                if (len == 0 || len > HM_MAX_PLAIN)
                    continue;
                offs[n] = off;
                lens[n] = len;
                n++;
            }
            if (n == 0)
                break;
            if (atomic_load(&g_wl.stop) != 0)
                return NULL;

            if (!g_wl.use_bcrypt && g_wl.algo == HM_ALG_MD5) {
                uint8_t blk[4][64];
                uint32_t st[4][4];
                int b = 0;

                for (; b < n; b++) {
                    if (wl_md5_block(g_wl.data + offs[b], lens[b], blk[b]) != 0)
                        break;
                    memcpy(st[b], HM_MD5_INIT, sizeof(st[b]));
                }
                if (b == n) {
                    if (n == 4) {
                        hm_md5_transform4(st, (const uint8_t (*)[64])blk);
                    } else {
                        for (int l = 0; l < n; l++)
                            hm_md5_transform(st[l], blk[l]);
                    }
                    for (int l = 0; l < n; l++) {
                        md5_out(st[l], dg);
                        wl_hit(dg, 16, g_wl.data + offs[l], lens[l]);
                    }
                    continue;
                }
                /* a long line: hash this batch with the generic path */
                for (int l = 0; l < n; l++) {
                    wl_hash(g_wl.data + offs[l], lens[l], dg, NULL);
                    wl_hit(dg, 16, g_wl.data + offs[l], lens[l]);
                }
                continue;
            }

            if (!g_wl.use_bcrypt && g_wl.algo == HM_ALG_SHA256) {
                uint8_t blk[4][64];
                uint32_t st[4][8];
                int b = 0;

                for (; b < n; b++) {
                    if (wl_sha256_block(g_wl.data + offs[b], lens[b],
                                        blk[b]) != 0)
                        break;
                    memcpy(st[b], HM_SHA256_H0, sizeof(HM_SHA256_H0));
                }
                if (b == n && n == 4) {
                    hm_sha256_transform4(st, (const uint8_t (*)[64])blk);
                    for (int l = 0; l < n; l++) {
                        sha256_out(st[l], dg);
                        wl_hit(dg, 32, g_wl.data + offs[l], lens[l]);
                    }
                    continue;
                }
                if (b != n) {
                    /* a long line in batch: hash this batch generically */
                    size_t dlen = hm_algo_size(g_wl.algo);

                    for (int l = 0; l < n; l++) {
                        wl_hash(g_wl.data + offs[l], lens[l], dg, NULL);
                        wl_hit(dg, dlen, g_wl.data + offs[l], lens[l]);
                    }
                    continue;
                }
                /* n < 4, all short: fall through to generic path below */
            }

            if (g_wl.use_bcrypt) {
                for (int l = 0; l < n; l++) {
                    for (int t = 0; t < g_wl.ntargets; t++) {
                        if (g_wl.targets[t].found ||
                            g_wl.targets[t].salt[0] == '\0')
                            continue;
                        wl_hash(g_wl.data + offs[l], lens[l], dg,
                                g_wl.targets[t].salt);
                        if (memcmp(g_wl.targets[t].bytes, dg, 23) == 0)
                            (void)wl_hit_one(t, g_wl.data + offs[l], lens[l]);
                    }
                }
                continue;
            }

            /* sha1/sha256 (non-batched) or fallback: one digest per line */
            {
                size_t dlen = hm_algo_size(g_wl.algo);

                for (int l = 0; l < n; l++) {
                    wl_hash(g_wl.data + offs[l], lens[l], dg, NULL);
                    wl_hit(dg, dlen, g_wl.data + offs[l], lens[l]);
                }
            }
        }
    }
}


static int wl_read_file(const char *path, char **out, size_t *outlen,
                         int use_io_uring)
{
    FILE *f;
    long sz;
    char *buf;

    if (use_io_uring) {
        if (hm_io_uring_available()) {
            if (hm_iouring_read_file(path, out, outlen) == 0) {
                fprintf(stderr,
                        "[*] io_uring: loaded wordlist with async reads\n");
                return 0;
            }
            fprintf(stderr,
                    "[-] io_uring read failed, falling back to regular I/O\n");
        } else {
            fprintf(stderr,
                    "[-] io_uring requested but unavailable on this "
                    "build/kernel, using regular I/O\n");
        }
    }

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "[-] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        fprintf(stderr, "[-] cannot seek %s\n", path);
        return -1;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        fprintf(stderr, "[-] cannot size %s\n", path);
        return -1;
    }
    rewind(f);
    buf = malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        fprintf(stderr, "[-] out of memory\n");
        return -1;
    }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "[-] cannot read %s\n", path);
        free(buf);
        fclose(f);
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);
    *out = buf;
    *outlen = (size_t)sz;
    return 0;
}

int hm_mode_wordlist(int argc, char **argv)
{
    static const hm_longopt_t lopts[] = {
        { "hash", 1, 'H' },
        { "hash-file", 1, 'F' },
        { "wordlist", 1, 'w' },
        { "out", 1, 'o' },
        { "salt", 1, 's' },
        { "salt-pos", 1, 'p' },
        { "threads", 1, 't' },
        { "algo", 1, 'a' },
        { "first", 0, 'f' },
        { "io-uring", 0, 1 },
        { "help", 0, 'h' },
        { NULL, 0, 0 }
    };
    wl_target_t *targets = NULL;
    const char *wordlist = NULL;
    const char *outpath = NULL;
    char salt[HM_MAX_SALT + 1];
    int salt_len = 0;
    int salt_pre = 1;
    int stop_first = 0;
    int nthreads = (int)hm_cpu_count();
    hm_algo_t algo = HM_ALG_MD5;
    bool algo_set = false;
    bool use_bcrypt = false;
    int use_io_uring = 0;
    int ntargets = 0;
    int opt;
    int rc = 1;
    char *data = NULL;
    size_t data_len = 0;
    pthread_t *tids = NULL;

    memset(&g_wl, 0, sizeof(g_wl));
    memset(salt, 0, sizeof(salt));

    targets = malloc(sizeof(wl_target_t) * (size_t)HM_WL_MAX_TARGETS);
    if (targets == NULL) {
        fprintf(stderr, "[-] out of memory\n");
        return 1;
    }

    hm_getopt_reset();
    while ((opt = hm_getopt_long(argc, argv, "H:F:w:o:s:p:t:afh", lopts)) != -1) {
        switch (opt) {
        case 'H': {
            hm_target_t tg;

            if (ntargets >= HM_WL_MAX_TARGETS) {
                fprintf(stderr, "[-] too many hashes\n");
                goto out;
            }
            if (hm_is_bcrypt_hash(hm_optarg)) {
                char bcsalt[48];

                if (hm_parse_bcrypt_target(hm_optarg, &tg, bcsalt) < 0)
                    goto out;
                memcpy(targets[ntargets].bytes, tg.bytes, 23);
                memcpy(targets[ntargets].hex, tg.hex, strlen(tg.hex) + 1);
                snprintf(targets[ntargets].salt,
                         sizeof(targets[ntargets].salt), "%s", bcsalt);
                use_bcrypt = true;
            } else {
                if (hm_parse_target(hm_optarg, &tg) < 0)
                    goto out;
                memcpy(targets[ntargets].bytes, tg.bytes, strlen(tg.hex) / 2);
                memcpy(targets[ntargets].hex, tg.hex, strlen(tg.hex) + 1);
            }
            targets[ntargets].found = 0;
            ntargets++;
            break;
        }
        case 'F': {
            hm_target_t *tgs =
                malloc(sizeof(hm_target_t) * (size_t)HM_WL_MAX_TARGETS);
            int nt = 0;

            if (tgs == NULL) {
                fprintf(stderr, "[-] out of memory\n");
                goto out;
            }
            if (hm_load_targets(hm_optarg, tgs, &nt) < 0) {
                free(tgs);
                goto out;
            }
            if ((size_t)ntargets + (size_t)nt > (size_t)HM_WL_MAX_TARGETS) {
                fprintf(stderr, "[-] too many hashes\n");
                free(tgs);
                goto out;
            }
            for (int i = 0; i < nt; i++) {
                if (hm_is_bcrypt_hash(tgs[i].hex)) {
                    char bcsalt[48];
                    hm_target_t bt;

                    if (hm_parse_bcrypt_target(tgs[i].hex, &bt, bcsalt) < 0) {
                        free(tgs);
                        goto out;
                    }
                    memcpy(targets[ntargets].bytes, bt.bytes, 23);
                    memcpy(targets[ntargets].hex, bt.hex, strlen(bt.hex) + 1);
                    snprintf(targets[ntargets].salt,
                             sizeof(targets[ntargets].salt), "%s", bcsalt);
                    use_bcrypt = true;
                } else {
                    memcpy(targets[ntargets].bytes, tgs[i].bytes,
                           strlen(tgs[i].hex) / 2);
                    memcpy(targets[ntargets].hex, tgs[i].hex,
                           strlen(tgs[i].hex) + 1);
                }
                targets[ntargets].found = 0;
                ntargets++;
            }
            free(tgs);
            break;
        }
        case 'w':
            wordlist = hm_optarg;
            break;
        case 'o':
            outpath = hm_optarg;
            break;
        case 's':
            salt_len = (int)strlen(hm_optarg);
            if (salt_len > HM_MAX_SALT) {
                fprintf(stderr, "[-] salt too long (max %d)\n", HM_MAX_SALT);
                goto out;
            }
            memcpy(salt, hm_optarg, (size_t)salt_len);
            break;
        case 'p':
            if (strcmp(hm_optarg, "pre") == 0)
                salt_pre = 1;
            else if (strcmp(hm_optarg, "post") == 0)
                salt_pre = 0;
            else {
                fprintf(stderr, "[-] salt-pos must be pre|post\n");
                goto out;
            }
            break;
        case 't':
            if (sscanf(hm_optarg, "%d", &nthreads) != 1 || nthreads < 1) {
                fprintf(stderr, "[-] bad --threads value\n");
                goto out;
            }
            break;
        case 'a':
            if (hm_algo_parse(hm_optarg, &algo) < 0) {
                fprintf(stderr, "[-] unknown algo '%s' (md5|sha256)\n",
                        hm_optarg);
                goto out;
            }
            algo_set = true;
            break;
        case 'f':
            stop_first = 1;
            break;
        case 1: /* --io-uring */
            use_io_uring = 1;
            break;
        case 'h':
            hm_usage_wordlist();
            free(targets);
            return 0;
        default:
            fprintf(stderr, "[-] unknown option\n");
            hm_usage_wordlist();
            goto out;
        }
    }

    if (wordlist == NULL) {
        fprintf(stderr, "[-] wordlist mode needs -w <wordlist>\n");
        hm_usage_wordlist();
        goto out;
    }
    if (ntargets < 1) {
        fprintf(stderr, "[-] wordlist mode needs at least one hash (-H)\n");
        hm_usage_wordlist();
        goto out;
    }
    if (wl_read_file(wordlist, &data, &data_len, use_io_uring) < 0)
        goto out;

    /* index the lines once so the workers can jump straight to their block */
    {
        size_t nlines = 1;
        size_t *offs;
        size_t k = 0;

        for (size_t i = 0; i < data_len; i++) {
            if (data[i] == '\n')
                nlines++;
        }
        offs = malloc((nlines + 1) * sizeof(size_t));
        if (offs == NULL) {
            fprintf(stderr, "[-] out of memory\n");
            goto out;
        }
        offs[k++] = 0;
        for (size_t i = 0; i < data_len; i++) {
            if (data[i] == '\n')
                offs[k++] = i + 1;
        }
        offs[k] = data_len;
        g_wl.offs = offs;
        g_wl.nlines = nlines;
    }

    /* the algorithm: explicit, or derived from the hash length */
    if (!algo_set) {
        size_t hlen = 0;

        for (int i = 0; i < ntargets; i++) {
            size_t n = strlen(targets[i].hex);

            if (hlen == 0)
                hlen = n;
            else if (n != hlen) {
                fprintf(stderr,
                        "[-] all targets must use the same hash length\n");
                goto out;
            }
        }
        if (hlen == 64)
            algo = HM_ALG_SHA256;
    }
    g_wl.algo = algo;
    g_wl.use_bcrypt = use_bcrypt;
    g_wl.dlen = use_bcrypt ? 23 : (int)hm_algo_size(algo);

    /* index the targets for the digest width the run will produce: a handful
     * of memcmps is fine, a few hundred is not */
    g_wl_match_ready = false;
    {
        int width = 0;

        if (use_bcrypt) {
            width = 23;
        } else if (ntargets > 0) {
            width = (int)hm_algo_size(algo);
        }
        if (!use_bcrypt && ntargets >= 4 && ntargets <= HM_MATCH_MAX_TARGETS &&
            width > 0) {
            for (int i = 0; i < ntargets; i++) {
                memcpy(g_wl_match_digests[i], targets[i].bytes, 32);
                g_wl_match_user[i] = &targets[i];
            }
            if (hm_match_build(&g_wl_match, g_wl_match_digests, g_wl_match_user,
                               (unsigned)ntargets, (unsigned)width) == 0)
                g_wl_match_ready = true;
        }
    }

    g_wl.targets = targets;
    g_wl.ntargets = ntargets;
    g_wl.salt = salt;
    g_wl.salt_len = salt_len;
    g_wl.salt_pre = salt_pre;
    g_wl.data = data;
    g_wl.data_len = data_len;
    g_wl.outf = NULL;
    pthread_mutex_init(&g_wl.mtx, NULL);
    atomic_store(&g_wl.next, 0);
    atomic_store(&g_wl.stop, 0);
    atomic_store(&g_wl.nfound, 0);

    if (outpath != NULL) {
        g_wl.outf = fopen(outpath, "a");
        if (g_wl.outf == NULL) {
            fprintf(stderr, "[-] cannot open %s: %s\n", outpath,
                    strerror(errno));
            goto out;
        }
    }

    printf("[*] wordlist %s (%zu bytes, %d hash%s)\n", wordlist, data_len,
           ntargets, (ntargets == 1) ? "" : "es");

    tids = calloc((size_t)nthreads, sizeof(pthread_t));
    if (tids == NULL) {
        fprintf(stderr, "[-] out of memory\n");
        goto out;
    }
    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&tids[i], NULL, wl_worker, NULL) != 0) {
            fprintf(stderr, "[-] pthread_create failed\n");
            atomic_store(&g_wl.stop, 1);
        }
    }
    for (int i = 0; i < nthreads; i++)
        pthread_join(tids[i], NULL);

    {
        int found = atomic_load(&g_wl.nfound);
        int missing = ntargets - found;

        printf("[*] %d/%d hash%s cracked\n", found, ntargets,
               (ntargets == 1) ? "" : "es");
        rc = (stop_first ? (found > 0 ? 0 : 1) : (missing == 0 ? 0 : 1));
    }

out:
    if (tids != NULL) {
        for (int i = 0; i < nthreads; i++)
            (void)tids[i];
        free(tids);
    }
    if (g_wl_match_ready) {
        hm_match_free(&g_wl_match);
        g_wl_match_ready = false;
    }
    if (g_wl.outf != NULL)
        fclose(g_wl.outf);
    free(g_wl.offs);
    free(data);
    free(targets);
    return rc;
}
