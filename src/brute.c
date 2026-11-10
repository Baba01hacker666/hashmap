/* hashmap - brute mode: threaded MD5 keyspace search with resume
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "engine.h"
#include "hashmap.h"
#include "util.h"

int hm_mode_brute(int argc, char **argv)
{
    hm_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.targets = malloc(sizeof(hm_target_t) * (size_t)HM_MAX_TARGETS);
    if (cfg.targets == NULL) {
        fprintf(stderr, "[-] out of memory\n");
        return 1;
    }
    if (hm_opts_common(argc, argv, &cfg, true) < 0) {
        free(cfg.targets);
        return 2;
    }
    if (hm_optind < argc) {
        /* positional hashes allowed too */
        for (int i = hm_optind; i < argc; i++) {
            if (cfg.ntargets >= HM_MAX_TARGETS) {
                fprintf(stderr, "[-] too many targets\n");
                free(cfg.targets);
                return 2;
            }
            if (hm_parse_target(argv[i], &cfg.targets[cfg.ntargets]) < 0) {
                free(cfg.targets);
                return 2;
            }
            cfg.ntargets++;
        }
    }
    if (cfg.ntargets < 1) {
        fprintf(stderr,
                "[-] brute needs at least one target: -H <md5hex> or "
                "-f <file>\n");
        free(cfg.targets);
        return 2;
    }
    if (cfg.minlen > cfg.maxlen) {
        fprintf(stderr, "[-] invalid length range %d-%d\n", cfg.minlen,
                cfg.maxlen);
        free(cfg.targets);
        return 2;
    }
    if (cfg.out_path[0] != '\0') {
        cfg.outf = fopen(cfg.out_path, "a");
        if (cfg.outf == NULL) {
            fprintf(stderr, "[-] cannot open %s: %s\n", cfg.out_path,
                    strerror(errno));
            free(cfg.targets);
            return 1;
        }
    }

    int finished = 0;
    int rc = hm_engine_run(&cfg, &finished);
    if (cfg.outf != NULL) {
        fclose(cfg.outf);
        cfg.outf = NULL;
    }
    free(cfg.targets);

    if (rc < 0)
        return 1;
    if (finished && rc >= cfg.ntargets)
        return 0;
    return 1;
}
