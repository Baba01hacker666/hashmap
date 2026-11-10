/* hashmap - brute/map engine: threaded keyspace walker with interval-based
 * state save + exact resume.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_ENGINE_H
#define HM_ENGINE_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "hashmap.h"

/* remaining-work span inside one length's keyspace */
typedef struct {
    uint64_t lo; /* inclusive candidate ordinal */
    uint64_t hi; /* exclusive */
} hm_span_t;

typedef struct {
    /* targets (MD5, 16-byte digests) - brute mode; array is caller-owned */
    hm_target_t *targets;
    int ntargets;

    int minlen, maxlen;
    char cs[HM_MAX_CS + 1];
    int cslen;
    char salt[HM_MAX_SALT + 1];
    int salt_len;
    int salt_pre; /* 1 = salt before candidate */

    int nthreads;

    /* state/resume; empty = no state file */
    char state_path[HM_MAX_STATE_PATH];

    /* results path (used to open outf in hm_opts_common) */
    char out_path[HM_MAX_STATE_PATH];

    /* map mode: stream of binary records (NULL = plain brute mode) */
    FILE *rec;

    /* results file for found lines (or NULL) */
    FILE *outf;
} hm_cfg_t;

/* run the engine; returns number of targets found (brute) or 0/errors.
 * *finished is set when the whole configured keyspace was covered. */
int hm_engine_run(hm_cfg_t *cfg, int *finished);

/* shared option parser for brute/map modes. parses -H/-F/-c/-t/-s/-p/-o,
 * --min/--max/--state/--fresh into cfg (targets appended to cfg->targets,
 * caller allocates HM_MAX_TARGETS slots). want_targets=false rejects -H/-F
 * (map mode). returns 0 on success, 1 when help was requested (-h),
 * -1 on error (message already printed). */
int hm_opts_common(int argc, char **argv, hm_cfg_t *cfg, bool want_targets);

/* parse a 32-char MD5 hex string into target (both fill bytes and hex) */
int hm_parse_target(const char *hex, hm_target_t *tg);

/* load targets from a hash file (one md5 hex per line, '#' comments) */
int hm_load_targets(const char *path, hm_target_t *targets, int *nt);

#endif /* HM_ENGINE_H */
