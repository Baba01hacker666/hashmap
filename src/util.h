/* hashmap - util helpers: timing, formatting, signals, portable getopt
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_UTIL_H
#define HM_UTIL_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* global stop flag (workers + main), set by SIGINT/SIGTERM or engine logic */
extern _Atomic int hm_stop;

void hm_sig_setup(void);

double hm_now(void);
void hm_fmt_u64(uint64_t v, char *buf, size_t n);
void hm_fmt_rate(double hps, char *buf, size_t n);

/* platform shims */
void hm_sleep_ms(unsigned ms);
int hm_fsync(FILE *f);
int hm_cpu_count(void);

/* --- portable getopt_long subset (no GNU dependency) --- */
typedef struct {
    const char *name; /* long option name without "--" */
    int has_arg;      /* 0 = no argument, 1 = required argument */
    int val;          /* short char, or a code > 255 for long-only options */
} hm_longopt_t;

extern const char *hm_optarg;
extern int hm_optind;

/* returns the option value, -1 when done, '?' on unknown/missing argument.
 * shortopts follows the getopt convention: "H:f:c:t:" (':' = needs arg).
 * longopts may be NULL. */
int hm_getopt_long(int argc, char **argv, const char *shortopts,
                   const hm_longopt_t *longopts);

/* reset the parser state (call before a second parsing round) */
void hm_getopt_reset(void);

#endif /* HM_UTIL_H */
