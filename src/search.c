/* hashmap - search mode: look up digests in a map file produced by 'map'
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int hm_mode_search(int argc, char **argv)
{
    static const hm_longopt_t lopts[] = {
        { "hash", 1, 'H' },
        { "hash-file", 1, 'F' },
        { "file", 1, 'F' },
        { "help", 0, 'h' },
        { NULL, 0, 0 }
    };
    const char *mapfile = NULL;
    want_t *wants = NULL;
    int nwants = 0;
    int opt;
    int rc = 2;
    FILE *f = NULL;

    wants = malloc(sizeof(want_t) * (size_t)HM_MAX_TARGETS);
    if (wants == NULL) {
        fprintf(stderr, "[-] out of memory\n");
        return 1;
    }

    hm_getopt_reset();
    while ((opt = hm_getopt_long(argc, argv, "H:F:f:h", lopts)) != -1) {
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
        case 'F':
        case 'f': {
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
        case 'h':
            hm_usage_search();
            free(wants);
            return 0;
        default:
            fprintf(stderr, "[-] unknown option\n");
            hm_usage_search();
            goto out;
        }
    }

    if (hm_optind < argc)
        mapfile = argv[hm_optind++];
    if (mapfile == NULL || nwants < 1 || hm_optind < argc) {
        fprintf(stderr,
                "[-] search needs at least one hash (-H) and a map file\n");
        hm_usage_search();
        goto out;
    }

    f = fopen(mapfile, "rb");
    if (f == NULL) {
        fprintf(stderr, "[-] cannot open %s: %s\n", mapfile, strerror(errno));
        rc = 1;
        goto out;
    }

    /* validate optional magic header */
    {
        char magic[HM_MAP_MAGIC_LEN];

        if (fread(magic, 1, HM_MAP_MAGIC_LEN, f) != HM_MAP_MAGIC_LEN ||
            memcmp(magic, HM_MAP_MAGIC, HM_MAP_MAGIC_LEN) != 0) {
            fprintf(stderr,
                    "[-] %s is not a hashmap map file (missing %s header)\n",
                    mapfile, "HMMAP 1");
            rc = 1;
            goto out;
        }
    }

    /* stream records */
    for (;;) {
        uint8_t rec[17];
        size_t got = fread(rec, 1, 17, f);

        if (got == 0)
            break; /* clean EOF */
        if (got != 17) {
            fprintf(stderr, "[-] truncated map record in %s\n", mapfile);
            rc = 1;
            goto out;
        }
        int plen = rec[16];
        if (plen > HM_MAX_PWLEN + HM_MAX_SALT + 1 || plen < 1) {
            fprintf(stderr, "[-] bad record length in %s (corrupt map?)\n",
                    mapfile);
            rc = 1;
            goto out;
        }
        char plain[HM_MAX_PLAIN + 1];
        if (plen > 0 && fread(plain, 1, (size_t)plen, f) != (size_t)plen) {
            fprintf(stderr, "[-] truncated map record in %s\n", mapfile);
            rc = 1;
            goto out;
        }
        plain[plen] = '\0';

        for (int i = 0; i < nwants; i++) {
            if (wants[i].found)
                continue;
            if (memcmp(wants[i].bytes, rec, 16) == 0) {
                printf("%s:%s\n", wants[i].hex, plain);
                wants[i].found = 1;
                break;
            }
        }
    }

    int missing = 0;
    for (int i = 0; i < nwants; i++) {
        if (!wants[i].found) {
            missing++;
            fprintf(stderr, "[-] %s not found in map\n", wants[i].hex);
        }
    }
    rc = (missing == 0) ? 0 : 1;

out:
    if (f != NULL)
        fclose(f);
    free(wants);
    return rc;
}
