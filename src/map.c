/* hashmap - map mode: write an exhaustive digest->plaintext map file
 *
 * File format (binary, little-endian records): the literal line
 *   HMMAP 1\n
 * followed by one record per candidate:
 *   [16B MD5 digest][1B plaintext length][plaintext bytes]
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "engine.h"
#include "hashmap.h"

#define HM_MAP_MAGIC "HMMAP 1\n"

int hm_mode_map(int argc, char **argv)
{
    hm_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (hm_opts_common(argc, argv, &cfg, false) < 0)
        return 2;
    if (cfg.minlen > cfg.maxlen) {
        fprintf(stderr, "[-] invalid length range %d-%d\n", cfg.minlen,
                cfg.maxlen);
        return 2;
    }
    if (cfg.state_path[0] == '\0') {
        /* map resumes like brute; give it a default state when writing a
         * real output file so long jobs can continue across runs */
        snprintf(cfg.state_path, sizeof(cfg.state_path), "hashmap-map.state");
    }

    cfg.rec = fopen(cfg.out_path, "wb");
    if (cfg.rec == NULL) {
        fprintf(stderr,
                "[-] map mode needs -o <out.hmmap> (writable): %s\n",
                strerror(errno));
        return 2;
    }
    if (fwrite(HM_MAP_MAGIC, 1, strlen(HM_MAP_MAGIC), cfg.rec) !=
        strlen(HM_MAP_MAGIC)) {
        fprintf(stderr, "[-] cannot write map header: %s\n", strerror(errno));
        fclose(cfg.rec);
        return 1;
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
