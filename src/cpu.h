/* hashmap - runtime CPU capability detection and kernel autotuning
 *
 * The baseline binary dispatches optional kernels at runtime. cpu.c identifies
 * the machine (vendor, model, feature bits
 * straight from CPUID, not from /proc, so it also works in containers) and
 * picks the widest implementation that is actually present:
 *
 *   md5     avx512 (16 lanes) > avx2 (8 lanes) > x86-64 baseline
 *   sha256  avx512 > avx2 > baseline
 *           (sha-ni is detected and reported but is not implemented)
 *
 * HM_CPU=off forces the portable path, HM_CPU=avx2 limits the
 * choice by hand, and HM_CPU_VERBOSE=1 explains the decision.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_CPU_H
#define HM_CPU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Feature bits we care about. Every one is read from the CPU itself; the
 * library never assumes that a feature compiled for exists at run time. */
typedef struct {
    /* vendor / identity */
    char vendor[13];    /* "GenuineIntel", "AuthenticAMD", ...            */
    char brand[49];     /* the brand string, or "" when CPUID has none    */
    unsigned family, model, stepping;
    unsigned logical;   /* online logical processors (not affinity-limited) */

    /* baseline x86-64 (v1) */
    bool sse2, sse42, popcnt, aes, pclmul;

    /* vector extensions */
    bool avx, avx2, avx512f, avx512vl, avx512bw, avx512dq, avx512vbmi;

    /* hash / crypto extensions */
    bool sha_ni;        /* Intel SHA extensions (SHA-1 and SHA-256)        */
    bool bmi2, adx;

    /* pre-autotune maximum widths; see hm_autotune() for selected widths */
    int md5_lanes;      /* 16 (avx512), 8 (avx2), 4 (baseline multi)      */
    int sha256_lanes;
    bool use_sha_ni;    /* false: SHA-NI kernel is not implemented        */
} hm_cpu_t;

/* Detect once (thread-safe, idempotent) and return the cached result. */
const hm_cpu_t *hm_cpu(void);

/* True when the pre-autotune choice permits at least `bits` vector bits
 * (128, 256 or 512). Consult hm_autotune() for the selected widths. */
bool hm_cpu_has_vector(unsigned bits);

/* A short human-readable list of the interesting features, e.g.
 * "avx2 avx512f sha_ni bmi2". Never NULL; may be empty on non-x86. */
const char *hm_cpu_features(void);

/* Print the detection result (used by `hashmap cpu`). */
void hm_cpu_report(void);

/* ------------------------------------------------------------------ */
/* autotune: measure, do not guess                                     */
/* ------------------------------------------------------------------ */

/* The autotuner times the candidate kernels of this machine once (a few
 * milliseconds) and remembers the winner per algorithm. It is only used to
 * *confirm* the CPUID choice, so a machine whose AVX-512 is slow (downclocked
 * or emulated) automatically falls back to the AVX2 path. */
typedef struct {
    int md5_lanes;
    int sha256_lanes;
    bool md5_avx512;
    bool sha256_avx512;
    bool measured;      /* false when the run used the CPUID default only   */
} hm_tune_t;

/* Run the measurement (idempotent, thread-safe). Cheap enough to call from a
 * startup path; HM_CPU=off skips it. */
const hm_tune_t *hm_autotune(void);

/* The one-line summary printed by --cpu / the cpu mode. */
void hm_tune_report(void);

/* True when the selected algorithm should use the AVX-512 kernel. */
bool hm_cpu_wide_for(bool sha256);

#endif /* HM_CPU_H */
