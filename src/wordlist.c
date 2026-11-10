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

#include "crypto.h"
#include "engine.h"
#include "hashmap.h"
#include "util.h"

#define HM_WL_MAX_TARGETS 4096
#define HM_WL_CHUNK 2048 /* lines per work unit */

typedef struct {
    uint8_t bytes[16];
    char hex[33];
    int found;
} wl_target_t;

typedef struct {
    wl_target_t *targets;
    int ntargets;
    char *salt;
    int salt_len;
    int salt_pre;
    char *data;      /* the whole wordlist */
    size_t data_len;
    size_t *offs;    /* offset of every line start (+ one past the end) */
    size_t nlines;
    _Atomic size_t next;   /* next line block to take */
    _Atomic int stop;      /* stop flag */
    _Atomic int nfound;
    FILE *outf;
    pthread_mutex_t mtx;
} wl_ctx_t;

static wl_ctx_t g_wl;

/* hash one candidate (with salt) */
static void wl_hash(const char *line, size_t len, uint8_t out[16])
{
    uint8_t buf[HM_MAX_PLAIN];
    size_t n = 0;

    if (g_wl.salt_len > 0 && g_wl.salt_pre) {
        memcpy(buf, g_wl.salt, (size_t)g_wl.salt_len);
        n = (size_t)g_wl.salt_len;
    }
    if (len > sizeof(buf) - n - 1)
        len = sizeof(buf) - n - 1;
    memcpy(buf + n, line, len);
    n += len;
    if (g_wl.salt_len > 0 && !g_wl.salt_pre) {
        memcpy(buf + n, g_wl.salt, (size_t)g_wl.salt_len);
        n += (size_t)g_wl.salt_len;
    }
    hm_md5(buf, n, out);
}

static void *wl_worker(void *arg)
{
    (void)arg;
    uint8_t dg[16];

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

        for (i = start; i < end; i++) {
            size_t off = g_wl.offs[i];
            size_t eol = g_wl.offs[i + 1];
            size_t len;

            while (eol > off && g_wl.data[eol - 1] == '\n')
                eol--;
            while (eol > off && g_wl.data[eol - 1] == '\r')
                eol--;
            len = eol - off;
            if (len == 0)
                continue;
            if (len > HM_MAX_PLAIN - 1)
                continue;
            wl_hash(g_wl.data + off, len, dg);

            for (int t = 0; t < g_wl.ntargets; t++) {
                if (g_wl.targets[t].found)
                    continue;
                if (memcmp(g_wl.targets[t].bytes, dg, 16) != 0)
                    continue;
                pthread_mutex_lock(&g_wl.mtx);
                if (!g_wl.targets[t].found) {
                    char plain[HM_MAX_PLAIN + 1];

                    memcpy(plain, g_wl.data + off, len);
                    plain[len] = '\0';
                    g_wl.targets[t].found = 1;
                    printf("[+] CRACKED  %s  ->  %s\n", g_wl.targets[t].hex,
                           plain);
                    if (g_wl.outf != NULL) {
                        fprintf(g_wl.outf, "%s:%s\n", g_wl.targets[t].hex, plain);
                        fflush(g_wl.outf);
                    }
                    atomic_fetch_add(&g_wl.nfound, 1);
                }
                pthread_mutex_unlock(&g_wl.mtx);
                break;
            }
        }
    }
}

static int wl_read_file(const char *path, char **out, size_t *outlen)
{
    FILE *f = fopen(path, "rb");
    long sz;
    char *buf;

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
        { "first", 0, 'f' },
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
    while ((opt = hm_getopt_long(argc, argv, "H:F:w:o:s:p:t:fh", lopts)) != -1) {
        switch (opt) {
        case 'H': {
            hm_target_t tg;

            if (ntargets >= HM_WL_MAX_TARGETS) {
                fprintf(stderr, "[-] too many hashes\n");
                goto out;
            }
            if (hm_parse_target(hm_optarg, &tg) < 0)
                goto out;
            memcpy(targets[ntargets].bytes, tg.bytes, 16);
            memcpy(targets[ntargets].hex, tg.hex, 33);
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
                memcpy(targets[ntargets].bytes, tgs[i].bytes, 16);
                memcpy(targets[ntargets].hex, tgs[i].hex, 33);
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
        case 'f':
            stop_first = 1;
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
    if (wl_read_file(wordlist, &data, &data_len) < 0)
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
    if (g_wl.outf != NULL)
        fclose(g_wl.outf);
    free(g_wl.offs);
    free(data);
    free(targets);
    return rc;
}
