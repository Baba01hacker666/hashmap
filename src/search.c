/* hashmap - search mode: look up digests in map files produced by 'map'
 *
 * Accepts several map files (shards) and/or a directory of *.hmmap files.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "crypto.h"
#include "engine.h"
#include "hashmap.h"
#include "util.h"

#define HM_MAP_MAGIC "HMMAP 1\n"
#define HM_MAP_MAGIC_LEN (sizeof(HM_MAP_MAGIC) - 1)

typedef struct {
    uint8_t bytes[16];
    char hex[33];
    int found;
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

        if (len < 6 || strcmp(e->d_name + len - 6, ".hmmap") != 0)
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

/* scan one map file for the wanted hashes */
static int scan_map(const char *path, want_t *wants, int nwants, FILE *outf)
{
    FILE *f = fopen(path, "rb");
    char magic[HM_MAP_MAGIC_LEN];

    if (f == NULL) {
        fprintf(stderr, "[-] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fread(magic, 1, HM_MAP_MAGIC_LEN, f) != HM_MAP_MAGIC_LEN ||
        memcmp(magic, HM_MAP_MAGIC, HM_MAP_MAGIC_LEN) != 0) {
        fprintf(stderr, "[-] %s is not a hashmap map file (missing HMMAP 1 "
                        "header)\n", path);
        fclose(f);
        return -1;
    }

    for (;;) {
        uint8_t rec[17];
        size_t got = fread(rec, 1, 17, f);

        if (got == 0)
            break; /* clean EOF */
        if (got != 17) {
            fprintf(stderr, "[-] truncated map record in %s\n", path);
            fclose(f);
            return -1;
        }
        int plen = rec[16];
        if (plen < 1 || plen > HM_MAX_PWLEN + HM_MAX_SALT + 1) {
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
            if (memcmp(wants[i].bytes, rec, 16) == 0) {
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

int hm_mode_search(int argc, char **argv)
{
    static const hm_longopt_t lopts[] = {
        { "hash", 1, 'H' },
        { "hash-file", 1, 'F' },
        { "out", 1, 'o' },
        { "help", 0, 'h' },
        { NULL, 0, 0 }
    };
    want_t *wants = NULL;
    strlist_t maps = { NULL, 0, 0 };
    const char *outpath = NULL;
    FILE *outf = NULL;
    int nwants = 0;
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
    while ((opt = hm_getopt_long(argc, argv, "H:F:o:h", lopts)) != -1) {
        switch (opt) {
        case 'H': {
            hm_target_t tg;

            if (nwants >= HM_MAX_TARGETS) {
                fprintf(stderr, "[-] too many hashes\n");
                goto out;
            }
            if (hm_parse_target(hm_optarg, &tg) < 0)
                goto out;
            memcpy(wants[nwants].bytes, tg.bytes, 16);
            memcpy(wants[nwants].hex, tg.hex, 33);
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
                memcpy(wants[nwants].bytes, tgs[i].bytes, 16);
                memcpy(wants[nwants].hex, tgs[i].hex, 33);
                wants[nwants].found = 0;
                nwants++;
            }
            free(tgs);
            break;
        }
        case 'o':
            outpath = hm_optarg;
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
        if (scan_map(maps.v[i], wants, nwants, outf) < 0) {
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
