/* hashmap - search mode: look up digests in map files produced by 'map'
 *
 * Accepts several map files (shards) and/or a directory of *.hmmap files.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "crypto.h"
#include "engine.h"
#include "hashmap.h"
#include "hmar.h"
#include "util.h"

#define HM_MAP_MAGIC "HMMAP 2\n"
#define HM_MAP_MAGIC_LEN (sizeof(HM_MAP_MAGIC) - 1)
#define HM_MAP_MAGIC_V1 "HMMAP 1\n"
#define HM_MAP_MAX_HDR 64

typedef struct {
    uint8_t bytes[32];
    char hex[65];
    char salt[48]; /* the bcrypt setting of this hash */
    int width;     /* stored digest bytes for this hash */
    _Atomic int found;
} want_t;

typedef struct {
    char **v;
    int n;
    int cap;
} strlist_t;

static void sl_add(strlist_t *l, const char *s)
{
    if (l->n >= l->cap)
        return;
    l->v[l->n++] = strdup(s);
}

static void sl_free(strlist_t *l)
{
    for (int i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    memset(l, 0, sizeof(*l));
}

/* collect the *.hmmap files of a directory (sorted) */
static int sl_add_dir(strlist_t *l, const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char **names = NULL;
    int n = 0;
    int cap = 0;

    if (d == NULL) {
        fprintf(stderr, "[-] cannot open directory %s: %s\n", dir,
                strerror(errno));
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        int is_map = len >= 6 && strcmp(e->d_name + len - 6, ".hmmap") == 0;
        int is_arc = len >= 5 && strcmp(e->d_name + len - 5, ".hmar") == 0;

        if (!is_map && !is_arc)
            continue;
        if (n >= cap) {
            int ncap = (cap == 0) ? 16 : cap * 2;
            char **tmp = realloc(names, (size_t)ncap * sizeof(char *));

            if (tmp == NULL) {
                closedir(d);
                return -1;
            }
            names = tmp;
            cap = ncap;
        }
        names[n] = strdup(e->d_name);
        if (names[n] == NULL) {
            closedir(d);
            return -1;
        }
        n++;
    }
    closedir(d);

    /* simple insertion sort - the file count is small */
    for (int i = 1; i < n; i++) {
        char *key = names[i];
        int j = i - 1;

        while (j >= 0 && strcmp(names[j], key) > 0) {
            names[j + 1] = names[j];
            j--;
        }
        names[j + 1] = key;
    }
    for (int i = 0; i < n; i++) {
        char path[HM_MAX_STATE_PATH * 2];
        size_t dl = strlen(dir);
        size_t nl = strlen(names[i]);
        size_t sep = (dl > 0 && dir[dl - 1] == '/') ? 0 : 1;

        if (dl + sep + nl + 1 >= sizeof(path)) {
            free(names[i]);
            continue;
        }
        memcpy(path, dir, dl);
        if (sep)
            path[dl] = '/';
        memcpy(path + dl + sep, names[i], nl + 1);
        sl_add(l, path);
        free(names[i]);
    }
    free(names);
    return 0;
}

/* scan one plain HMMAP file for the wanted hashes */
static int scan_plain(const char *path, want_t *wants, int nwants, FILE *outf)
{
    FILE *f = fopen(path, "rb");
    char magic[HM_MAP_MAGIC_LEN];
    char salt[64];
    int dlen = 16;

    if (f == NULL) {
        fprintf(stderr, "[-] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fread(magic, 1, HM_MAP_MAGIC_LEN, f) != HM_MAP_MAGIC_LEN) {
        fprintf(stderr, "[-] %s is not a hashmap map file (missing "
                        "header)\n",
                path);
        fclose(f);
        return -1;
    }
    if (memcmp(magic, HM_MAP_MAGIC_V1, HM_MAP_MAGIC_LEN) == 0) {
        dlen = 16; /* v1 maps: md5 with a 16 byte digest */
    } else if (memcmp(magic, HM_MAP_MAGIC, HM_MAP_MAGIC_LEN) == 0) {
        char line[HM_MAP_MAX_HDR];
        bool seen = false;

        salt[0] = '\0';
        for (;;) {
            long prev = ftell(f);
            char *nl;

            if (fgets(line, sizeof(line), f) == NULL)
                break;
            nl = strpbrk(line, "\r\n");
            if (nl != NULL)
                *nl = '\0';
            if (strncmp(line, "dlen ", 5) == 0) {
                dlen = atoi(line + 5);
                seen = true;
                continue;
            }
            if (strncmp(line, "salt ", 5) == 0) {
                snprintf(salt, sizeof(salt), "%.58s", line + 5);
                continue;
            }
            if (strncmp(line, "algo ", 5) == 0)
                continue;
            /* anything else: the header is over, the records start here -
             * put the line back (the records are binary) */
            if (prev >= 0)
                (void)fseek(f, prev, SEEK_SET);
            break;
        }
        if (!seen || dlen < 1 || dlen > 32) {
            fprintf(stderr, "[-] %s has a broken header\n", path);
            fclose(f);
            return -1;
        }
    } else {
        fprintf(stderr, "[-] %s is not a hashmap map file (missing "
                        "header)\n",
                path);
        fclose(f);
        return -1;
    }

    if (salt[0] != '\0') {
        /* a bcrypt map: the hashes must use the same salt and cost */
        for (int i = 0; i < nwants; i++) {
            if (wants[i].salt[0] == '\0')
                continue;
            if (strcmp(wants[i].salt, salt) != 0) {
                fprintf(stderr,
                        "[-] the map was built with '%s' but the hash uses "
                        "'%s'\n",
                        salt, wants[i].salt);
                fclose(f);
                return -1;
            }
        }
    }

    for (;;) {
        uint8_t rec[33];
        size_t got = fread(rec, 1, (size_t)dlen + 1, f);

        if (got == 0)
            break; /* clean EOF */
        if (got != (size_t)dlen + 1) {
            fprintf(stderr, "[-] truncated map record in %s\n", path);
            fclose(f);
            return -1;
        }
        int plen = rec[dlen];
        if (plen < 1 || plen > HM_MAX_PLAIN) {
            fprintf(stderr, "[-] bad record length in %s (corrupt map?)\n",
                    path);
            fclose(f);
            return -1;
        }
        char plain[HM_MAX_PLAIN + 1];

        if (fread(plain, 1, (size_t)plen, f) != (size_t)plen) {
            fprintf(stderr, "[-] truncated map record in %s\n", path);
            fclose(f);
            return -1;
        }
        plain[plen] = '\0';

        for (int i = 0; i < nwants; i++) {
            if (wants[i].found)
                continue;
            if (wants[i].width < dlen)
                continue; /* the want is narrower than the stored digest */
            if (memcmp(wants[i].bytes, rec, (size_t)dlen) == 0) {
                printf("%s:%s\n", wants[i].hex, plain);
                if (outf != NULL) {
                    fprintf(outf, "%s:%s\n", wants[i].hex, plain);
                    fflush(outf);
                }
                wants[i].found = 1;
                break;
            }
        }
    }
    fclose(f);
    return 0;
}

/* per-file scan state shared by the archive workers */
typedef struct {
    want_t *wants;
    int nwants;
    FILE *outf;
    int dlen;
    pthread_mutex_t out_mtx;
} arc_ctx_t;

static void arc_row(void *ctx, const uint8_t *dig, const uint8_t *key,
                    size_t klen)
{
    arc_ctx_t *c = ctx;
    char plain[256];

    for (int i = 0; i < c->nwants; i++) {
        if (c->wants[i].found)
            continue;
        if (c->wants[i].width < c->dlen)
            continue;
        if (memcmp(c->wants[i].bytes, dig, (size_t)c->dlen) != 0)
            continue;
        if (klen >= sizeof(plain))
            klen = sizeof(plain) - 1;
        memcpy(plain, key, klen);
        plain[klen] = '\0';
        pthread_mutex_lock(&c->out_mtx);
        if (c->wants[i].found == 0) {
            c->wants[i].found = 1;
            printf("%s:%s\n", c->wants[i].hex, plain);
            if (c->outf != NULL) {
                fprintf(c->outf, "%s:%s\n", c->wants[i].hex, plain);
                fflush(c->outf);
            }
        }
        pthread_mutex_unlock(&c->out_mtx);
        break;
    }
}

/* single-threaded walk, also used for HMARCH1 archives that cannot be split */
static int scan_archive_serial(const char *path, arc_ctx_t *c)
{
    hm_hmar_t *ar = NULL;
    int rows;
    int rc = 0;

    if (hm_hmar_open(path, &ar) < 0)
        return -1;
    for (;;) {
        int got = hm_hmar_next(ar, &rows);

        if (got < 0) {
            rc = -1;
            break;
        }
        if (got == 0)
            break;
        for (int r = 0; r < rows; r++) {
            size_t klen = 0;
            const uint8_t *key = hm_hmar_key(ar, r, &klen);
            const uint8_t *dig = hm_hmar_digest(ar, r);

            if (dig != NULL)
                arc_row(c, dig, key, klen);
        }
    }
    hm_hmar_close(ar);
    return rc;
}

/* scan an HMARCH1/HMARCH2 archive without restoring it first */
static int scan_archive(const char *path, want_t *wants, int nwants, FILE *outf,
                        int threads, int verify)
{
    hm_hmar_t *ar = NULL;
    arc_ctx_t c;
    int rc;

    if (hm_hmar_open(path, &ar) < 0)
        return -1;
    c.dlen = hm_hmar_dlen(ar);
    if (hm_hmar_salt(ar)[0] != '\0') {
        /* a bcrypt map: the hashes must use the same salt */
        for (int i = 0; i < nwants; i++) {
            if (wants[i].salt[0] == '\0')
                continue;
            if (strcmp(wants[i].salt, hm_hmar_salt(ar)) != 0) {
                fprintf(stderr,
                        "[-] the map was built with '%s' but the hash uses "
                        "'%s'\n",
                        hm_hmar_salt(ar), wants[i].salt);
                hm_hmar_close(ar);
                return -1;
            }
        }
    }
    hm_hmar_close(ar);

    c.wants = wants;
    c.nwants = nwants;
    c.outf = outf;
    pthread_mutex_init(&c.out_mtx, NULL);
    rc = hm_hmar_scan(path, threads, verify, arc_row, &c);
    pthread_mutex_destroy(&c.out_mtx);
    if (rc == 1) /* not splittable */
        rc = scan_archive_serial(path, &c);
    return rc;
}

/* dispatch on the file magic: plain map or lossless archive */
static int scan_map(const char *path, want_t *wants, int nwants, FILE *outf,
                    int threads, int verify)
{
    FILE *f = fopen(path, "rb");
    char magic[8];
    size_t got;

    if (f == NULL) {
        fprintf(stderr, "[-] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    got = fread(magic, 1, sizeof(magic), f);
    fclose(f);
    if (got == sizeof(magic) &&
        (memcmp(magic, "HMARCH1\n", 8) == 0 ||
         memcmp(magic, "HMARCH2\n", 8) == 0))
        return scan_archive(path, wants, nwants, outf, threads, verify);
    return scan_plain(path, wants, nwants, outf);
}

int hm_mode_search(int argc, char **argv)
{
    static const hm_longopt_t lopts[] = {
        { "hash", 1, 'H' },
        { "hash-file", 1, 'F' },
        { "out", 1, 'o' },
        { "threads", 1, 't' },
        { "no-verify", 0, 1 },
        { "help", 0, 'h' },
        { NULL, 0, 0 }
    };
    want_t *wants = NULL;
    strlist_t maps = { NULL, 0, 0 };
    const char *outpath = NULL;
    FILE *outf = NULL;
    int nwants = 0;
    int threads = (int)hm_cpu_count();
    int verify = 1;
    int opt;
    int rc = 2;

    wants = malloc(sizeof(want_t) * (size_t)HM_MAX_TARGETS);
    maps.v = malloc(sizeof(char *) * (size_t)HM_MAX_TARGETS);
    maps.cap = HM_MAX_TARGETS;
    if (wants == NULL || maps.v == NULL) {
        fprintf(stderr, "[-] out of memory\n");
        free(wants);
        free(maps.v);
        return 1;
    }

    hm_getopt_reset();
    while ((opt = hm_getopt_long(argc, argv, "H:F:o:t:h", lopts)) != -1) {
        switch (opt) {
        case 'H': {
            hm_target_t tg;

            if (nwants >= HM_MAX_TARGETS) {
                fprintf(stderr, "[-] too many hashes\n");
                goto out;
            }
            if (hm_is_bcrypt_hash(hm_optarg)) {
                if (hm_parse_bcrypt_target(hm_optarg, &tg,
                                           wants[nwants].salt) < 0)
                    goto out;
                memcpy(wants[nwants].bytes, tg.bytes, 23);
                memcpy(wants[nwants].hex, tg.hex, strlen(tg.hex) + 1);
                wants[nwants].width = 23;
            } else {
                if (hm_parse_target(hm_optarg, &tg) < 0)
                    goto out;
                memcpy(wants[nwants].bytes, tg.bytes, strlen(tg.hex) / 2);
                memcpy(wants[nwants].hex, tg.hex, strlen(tg.hex) + 1);
                wants[nwants].width = (int)(strlen(tg.hex) / 2);
            }
            wants[nwants].found = 0;
            nwants++;
            break;
        }
        case 'F': {
            hm_target_t *tgs = malloc(sizeof(hm_target_t) * (size_t)HM_MAX_TARGETS);
            int nt = 0;

            if (tgs == NULL) {
                fprintf(stderr, "[-] out of memory\n");
                goto out;
            }
            if (hm_load_targets(hm_optarg, tgs, &nt) < 0) {
                free(tgs);
                goto out;
            }
            if ((size_t)nwants + (size_t)nt > (size_t)HM_MAX_TARGETS) {
                fprintf(stderr, "[-] too many hashes (max %d)\n", HM_MAX_TARGETS);
                free(tgs);
                goto out;
            }
            for (int i = 0; i < nt; i++) {
                size_t hlen = strlen(tgs[i].hex);
                int width = hm_is_bcrypt_hash(tgs[i].hex) ? 23 : (int)(hlen / 2);

                memcpy(wants[nwants].bytes, tgs[i].bytes, (size_t)width);
                memcpy(wants[nwants].hex, tgs[i].hex, hlen + 1);
                wants[nwants].width = width;
                wants[nwants].found = 0;
                nwants++;
            }
            free(tgs);
            break;
        }
        case 'o':
            outpath = hm_optarg;
            break;
        case 't': {
            char *end = NULL;
            long v = strtol(hm_optarg, &end, 10);

            if (end == NULL || *end != '\0' || v < 1 ||
                v > HM_HMAR_MAX_THREADS) {
                fprintf(stderr, "[-] bad --threads value (1-%d)\n",
                        HM_HMAR_MAX_THREADS);
                goto out;
            }
            threads = (int)v;
            break;
        }
        case 1:
            verify = 0;
            break;
        case 'h':
            hm_usage_search();
            free(wants);
            free(maps.v);
            return 0;
        default:
            fprintf(stderr, "[-] unknown option\n");
            hm_usage_search();
            goto out;
        }
    }

    /* the positional arguments are map files and/or directories */
    for (int i = hm_optind; i < argc; i++) {
        struct stat st;

        if (stat(argv[i], &st) != 0) {
            fprintf(stderr, "[-] cannot open %s: %s\n", argv[i],
                    strerror(errno));
            rc = 1;
            goto out;
        }
        if (S_ISDIR(st.st_mode)) {
            if (sl_add_dir(&maps, argv[i]) < 0) {
                rc = 1;
                goto out;
            }
        } else {
            sl_add(&maps, argv[i]);
        }
    }
    if (maps.n == 0 || nwants < 1) {
        fprintf(stderr,
                "[-] search needs at least one hash (-H) and a map file\n");
        hm_usage_search();
        goto out;
    }

    if (outpath != NULL) {
        outf = fopen(outpath, "a");
        if (outf == NULL) {
            fprintf(stderr, "[-] cannot open %s: %s\n", outpath,
                    strerror(errno));
            rc = 1;
            goto out;
        }
    }

    for (int i = 0; i < maps.n; i++) {
        if (scan_map(maps.v[i], wants, nwants, outf, threads, verify) < 0) {
            rc = 1;
            goto out;
        }
        if (nwants > 0) {
            int left = 0;

            for (int k = 0; k < nwants; k++)
                if (!wants[k].found)
                    left++;
            if (left == 0)
                break; /* everything found, no need to scan further */
        }
    }

    {
        int missing = 0;

        for (int i = 0; i < nwants; i++) {
            if (!wants[i].found) {
                missing++;
                fprintf(stderr, "[-] %s not found in map\n", wants[i].hex);
            }
        }
        rc = (missing == 0) ? 0 : 1;
    }

out:
    if (outf != NULL)
        fclose(outf);
    sl_free(&maps);
    free(wants);
    return rc;
}
