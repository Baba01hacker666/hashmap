/* hashmap - map mode: write an exhaustive digest->plaintext map file
 *
 * File format (binary, little-endian records): the literal line
 *   HMMAP 1\n
 * followed by one record per candidate:
 *   [16B MD5 digest][1B plaintext length][plaintext bytes]
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "engine.h"
#include "hashmap.h"
#include "util.h"

#define HM_MAP_MAGIC "HMMAP 1\n"

/* does the file exist and start with the map magic? */
static int map_file_valid(const char *path)
{
    FILE *f = fopen(path, "rb");
    char magic[16];
    size_t want = strlen(HM_MAP_MAGIC);
    size_t n;

    if (f == NULL)
        return 0;
    n = fread(magic, 1, want, f);
    fclose(f);
    return (n == want && memcmp(magic, HM_MAP_MAGIC, want) == 0);
}

static int file_exists(const char *path)
{
    struct stat st;

    return (stat(path, &st) == 0);
}

int hm_mode_map(int argc, char **argv)
{
    hm_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    int prc = hm_opts_common(argc, argv, &cfg, false);
    if (prc == 1) { /* -h */
        hm_usage_map();
        return 0;
    }
    if (prc < 0) {
        hm_usage_map();
        return 2;
    }
    if (cfg.minlen > cfg.maxlen) {
        fprintf(stderr, "[-] invalid length range %d-%d\n", cfg.minlen,
                cfg.maxlen);
        return 2;
    }
    if (cfg.out_path[0] == '\0') {
        fprintf(stderr, "[-] map mode needs an output file: -o <out.hmmap>\n");
        hm_usage_map();
        return 2;
    }
    if (cfg.state_path[0] == '\0') {
        /* map resumes like brute; give it a default state so long jobs can
         * continue across runs */
        snprintf(cfg.state_path, sizeof(cfg.state_path), "hashmap-map.state");
    }

    /* A resumed map run must APPEND: the records of the already finished
     * spans live in the existing file. Truncating here would silently
     * produce an incomplete map. */
    {
        int resuming = (cfg.state_path[0] != '\0') &&
                       file_exists(cfg.state_path);

        if (resuming && !map_file_valid(cfg.out_path)) {
            fprintf(stderr,
                    "[-] state file exists but '%s' is missing or not a map "
                    "file\n",
                    cfg.out_path);
            fprintf(stderr,
                    "[-] the map cannot be continued - use --fresh to "
                    "rebuild it\n");
            return 2;
        }

        cfg.rec = fopen(cfg.out_path, resuming ? "ab" : "wb");
        if (cfg.rec == NULL) {
            fprintf(stderr, "[-] cannot write %s: %s\n", cfg.out_path,
                    strerror(errno));
            return 1;
        }
        if (!resuming &&
            fwrite(HM_MAP_MAGIC, 1, strlen(HM_MAP_MAGIC), cfg.rec) !=
                strlen(HM_MAP_MAGIC)) {
            fprintf(stderr, "[-] cannot write map header: %s\n",
                    strerror(errno));
            fclose(cfg.rec);
            return 1;
        }
    }
    int finished = 0;
    (void)hm_engine_run(&cfg, &finished);
    if (cfg.rec != NULL) {
        fflush(cfg.rec);
        fclose(cfg.rec);
        cfg.rec = NULL;
    }
    if (cfg.outf != NULL) {
        fclose(cfg.outf);
        cfg.outf = NULL;
    }
    if (!finished)
        return 1;
    return 0;
}
