/* hashmap - util helpers */
#ifndef HM_UTIL_H
#define HM_UTIL_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/* global stop flag (workers + main), set by SIGINT/SIGTERM or engine logic */
extern _Atomic int hm_stop;

void hm_sig_setup(void);
void hm_sig_keepalive(void); /* handled here so workers must decide shutdown */

double hm_now(void);
void hm_fmt_u64(uint64_t v, char *buf, size_t n);
void hm_fmt_rate(double hps, char *buf, size_t n);

#endif /* HM_UTIL_H */
