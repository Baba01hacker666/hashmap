/* hashmap - runtime CPU detection and kernel autotuning
 *
 * Why this file exists: the binary must run everywhere and still use the
 * best kernel each machine offers. Compile-time -march=native would lock
 * the choice to the build machine (and crash on older CPUs), so every
 * decision here is made at run time from CPUID, then double-checked by a
 * short measurement and OS-aware checks.
 *
 *  1. detect() reads CPUID leaves 0/1/7 (and 0x80000004 for the brand
 *     string) exactly the way the compiler's __builtin_cpu_supports does,
 *     but keeps the raw bits so the report can show them.
 *  2. choose() maps the bits to the widest kernel set that is present:
 *       md5     16 lanes on avx512f, 8 on avx2, 4 scalar lanes otherwise
 *       sha256  16 lanes on avx512f, 8 on avx2, 4 scalar lanes otherwise
 *     SHA-NI is reported only; no SHA-NI kernel is implemented.
 *  3. autotune() times the candidate batches and, if the wider kernel is
 *     not at least 25% faster on this machine (heavy AVX-512 downclocking,
 *     a hypervisor that emulates it), picks the narrower one. The measured
 *     result is cached after the first run.
 *
 * Environment overrides (documented in docs/cpu.md):
 *   HM_CPU=off          baseline kernels only
 *   HM_CPU=baseline     alias of off
 *   HM_CPU=avx2         never use 512-bit kernels
 *   HM_CPU=avx512       use the widest kernel the CPU reports
 *   HM_CPU_VERBOSE=1    explain every decision on stderr
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "cpu.h"

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

#if defined(__x86_64__) || defined(__i386__)
#define HM_HAVE_CPUID 1
#include <cpuid.h>
#endif

/* the small amount of state the dispatch in crypto.c asks for */
static hm_cpu_t g_cpu;
static hm_tune_t g_tune;
static pthread_once_t g_cpu_once = PTHREAD_ONCE_INIT;
static pthread_once_t g_tune_once = PTHREAD_ONCE_INIT;
static _Thread_local bool g_tuning;
static char g_features[128];

/* HM_CPU modes */
enum {
    HM_CPU_AUTO = 0,
    HM_CPU_FORCE_OFF,
    HM_CPU_FORCE_AVX2,
    HM_CPU_FORCE_AVX512
};

static int cpu_mode(void)
{
    int mode = HM_CPU_AUTO;
    {
        const char *e = getenv("HM_CPU");

        if (e != NULL) {
            if (strcmp(e, "off") == 0 || strcmp(e, "baseline") == 0 ||
                strcmp(e, "0") == 0)
                mode = HM_CPU_FORCE_OFF;
            else if (strcmp(e, "avx2") == 0)
                mode = HM_CPU_FORCE_AVX2;
            else if (strcmp(e, "avx512") == 0)
                mode = HM_CPU_FORCE_AVX512;
        }
    }
    return mode;
}

static bool verbose(void)
{
    const char *e = getenv("HM_CPU_VERBOSE");

    return e != NULL && e[0] != '\0' && strcmp(e, "0") != 0;
}

static void note(const char *msg)
{
    if (!verbose())
        return;
    fprintf(stderr, "[cpu] %s\n", msg);
}

/* ------------------------------------------------------------------ */
/* CPUID                                                              */
/* ------------------------------------------------------------------ */

#ifdef HM_HAVE_CPUID

static void cpuid_ex(unsigned leaf, unsigned sub, unsigned *a, unsigned *b,
                     unsigned *c, unsigned *d)
{
    __cpuid_count(leaf, sub, *a, *b, *c, *d);
}

static void detect_x86(hm_cpu_t *c)
{
    unsigned a, b, cc, d;
    unsigned maxleaf;

    memset(c, 0, sizeof(*c));
    cpuid_ex(0, 0, &maxleaf, &b, &cc, &d);
    memcpy(c->vendor, &b, 4);
    memcpy(c->vendor + 4, &d, 4);
    memcpy(c->vendor + 8, &cc, 4);
    c->vendor[12] = '\0';

    cpuid_ex(1, 0, &a, &b, &cc, &d);
    c->stepping = a & 0xfu;
    c->model = (a >> 4) & 0xfu;
    c->family = (a >> 8) & 0xfu;
    if (c->family == 6u || c->family == 15u)
        c->model += ((a >> 16) & 0xfu) << 4;
    if (c->family == 15u)
        c->family += (a >> 20) & 0xffu;
    c->sse2 = (d & (1u << 26)) != 0;
    c->sse42 = (cc & (1u << 20)) != 0;
    c->popcnt = (cc & (1u << 23)) != 0;
    c->aes = (cc & (1u << 25)) != 0;
    c->pclmul = (cc & (1u << 1)) != 0;
    c->avx = (cc & (1u << 28)) != 0;

    /* leaf 7: subleaf 0 holds the feature block we use */
    if (maxleaf >= 7) {
        unsigned maxsub;

        cpuid_ex(7, 0, &maxsub, &b, &cc, &d);
        (void)maxsub;
        c->avx2 = (b & (1u << 5)) != 0;
        c->bmi2 = (b & (1u << 8)) != 0;
        c->sha_ni = (b & (1u << 29)) != 0;
        c->adx = (b & (1u << 19)) != 0;
        c->avx512f = (b & (1u << 16)) != 0;
        c->avx512dq = (b & (1u << 17)) != 0;
        c->avx512bw = (b & (1u << 30)) != 0;
        c->avx512vl = (b & (1u << 31)) != 0;
        c->avx512vbmi = (cc & (1u << 1)) != 0;
    }

    /* CPUID feature bits alone are insufficient: the OS must save vector
     * register state. GCC's runtime checks incorporate OSXSAVE/XCR0. */
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    c->avx = c->avx && __builtin_cpu_supports("avx");
    c->avx2 = c->avx2 && __builtin_cpu_supports("avx2");
    c->avx512f = c->avx512f && __builtin_cpu_supports("avx512f");
    c->avx512bw = c->avx512bw && __builtin_cpu_supports("avx512bw");
#else
    c->avx = c->avx2 = c->avx512f = c->avx512bw = false;
#endif

    /* brand string: leaves 0x80000002..0x80000004 */
    cpuid_ex(0x80000000u, 0, &a, &b, &cc, &d);
    if (a >= 0x80000004u) {
        char *p = c->brand;

        for (unsigned leaf = 0x80000002u; leaf <= 0x80000004u; leaf++) {
            cpuid_ex(leaf, 0, &a, &b, &cc, &d);
            memcpy(p, &a, 4);
            memcpy(p + 4, &b, 4);
            memcpy(p + 8, &cc, 4);
            memcpy(p + 12, &d, 4);
            p += 16;
        }
        c->brand[48] = '\0';
        /* trim the leading spaces CPUID leaves in the brand string */
        p = c->brand;
        while (*p == ' ')
            p++;
        if (p != c->brand)
            memmove(c->brand, p, strlen(p) + 1);
    }
}

#else /* !HM_HAVE_CPUID */

static void detect_x86(hm_cpu_t *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->vendor, sizeof(c->vendor), "unknown");
    /* non-x86: everything falls back to the portable kernels */
}

#endif

/* ------------------------------------------------------------------ */
/* choose: feature bits -> kernels                                    */
/* ------------------------------------------------------------------ */

static void collect_features(const hm_cpu_t *c, char *out, size_t n)
{
    static const char *names[] = {"sse2", "sse4.2", "popcnt", "aes", "avx",
                                  "avx2", "avx512f", "avx512vl", "avx512bw",
                                  "avx512dq", "avx512vbmi", "sha-ni", "bmi2",
                                  "adx"};
    const bool bits[] = {c->sse2, c->sse42, c->popcnt, c->aes, c->avx,
                         c->avx2, c->avx512f, c->avx512vl, c->avx512bw,
                         c->avx512dq, c->avx512vbmi, c->sha_ni, c->bmi2,
                         c->adx};
    size_t used = 0;

    out[0] = '\0';
    for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        if (!bits[i])
            continue;
        if (used != 0 && used + 1 < n)
            out[used++] = ' ';
        {
            size_t len = strlen(names[i]);

            if (used + len >= n)
                break;
            memcpy(out + used, names[i], len);
            used += len;
            out[used] = '\0';
        }
    }
}

static void choose(hm_cpu_t *c)
{
    const int mode = cpu_mode();
    bool wide = c->avx512f;
    bool narrow = c->avx2;

#if !defined(__x86_64__) || (!defined(__GNUC__) && !defined(__clang__)) || \
    (!defined(__linux__) && !defined(__APPLE__))
    /* SIMD implementations are only compiled on these x86-64 targets. */
    wide = false;
    narrow = false;
#endif

    if (mode == HM_CPU_FORCE_OFF) {
        wide = false;
        narrow = false;
        note("HM_CPU=off: using the portable kernels, no vector dispatch");
    } else if (mode == HM_CPU_FORCE_AVX2) {
        if (wide)
            note("HM_CPU=avx2: capping the kernels at 8 lanes");
        wide = false;
    } else if (mode == HM_CPU_FORCE_AVX512 && !wide) {
        note("HM_CPU=avx512: this CPU does not support AVX-512F, "
             "falling back");
    }

    c->md5_lanes = wide ? 16 : (narrow ? 8 : 4);
    c->sha256_lanes = c->md5_lanes;
    /* sha-ni only helps the one-shot path; the cracking loop batches */
    c->use_sha_ni = false; /* detected, but no SHA-NI implementation yet */

    if (c->md5_lanes == 16)
        note("avx512 kernels selected (16 lanes)");
    else if (c->md5_lanes == 8)
        note("avx2 kernels selected (8 lanes)");
    else
        note("scalar/SSE kernels selected (4 lanes)");
}

static void init_cpu(void)
{
    hm_cpu_t c;
    int n;

    detect_x86(&c);
    n = hm_cpu_count();
    c.logical = n > 0 ? (unsigned)n : 1u;
    choose(&c);
    collect_features(&c, g_features, sizeof(g_features));
    g_cpu = c;
}

const hm_cpu_t *hm_cpu(void)
{
    (void)pthread_once(&g_cpu_once, init_cpu);
    return &g_cpu;
}

bool hm_cpu_has_vector(unsigned bits)
{
    return (unsigned)hm_cpu()->md5_lanes * 32u >= bits;
}

const char *hm_cpu_features(void)
{
    (void)hm_cpu();
    return g_features;
}

void hm_cpu_report(void)
{
    const hm_cpu_t *c = hm_cpu();
    const hm_tune_t *t = hm_autotune();

    printf("cpu:      %s\n", c->brand[0] != '\0' ? c->brand : c->vendor);
    printf("vendor:   %s  family %u model %u stepping %u\n", c->vendor,
           c->family, c->model, c->stepping);
    printf("logical:  %u (online processors; may exceed process affinity)\n", c->logical);
    printf("features: %s\n", g_features[0] != '\0' ? g_features : "(none)");
    printf("kernels:  md5 %d-lane, sha256 %d-lane (md5 %s, sha256 %s)\n",
           t->md5_lanes, t->sha256_lanes,
           t->md5_lanes == 16 ? "avx512f" : (t->md5_lanes == 8 ? "avx2" : "baseline"),
           t->sha256_lanes == 16 ? "avx512f" : (t->sha256_lanes == 8 ? "avx2" : "baseline"));
    printf("sha-ni:   %s (not used by current kernels)\n", c->sha_ni ? "available" : "unavailable");
    if (getenv("HM_CPU") != NULL)
        printf("override: HM_CPU=%s\n", getenv("HM_CPU"));
}

/* ------------------------------------------------------------------ */
/* autotune                                                           */
/* ------------------------------------------------------------------ */

/* Time one transform shape and return nanoseconds per candidate. The lane
 * count in the loop is the only difference between the two candidates, so
 * the comparison isolates the kernel. */
static double time_md5(int lanes, int rounds)
{
    uint32_t st[16][4];
    uint8_t blk[16][64];
    double t0;
    double dt;

    for (int l = 0; l < 16; l++) {
        memset(blk[l], 0, 64);
        memcpy(blk[l], "00000000", 8);
        blk[l][8] = 0x80;
        blk[l][56] = 64;
        memcpy(st[l], HM_MD5_INIT, sizeof(HM_MD5_INIT));
    }
    t0 = hm_now();
    for (int r = 0; r < rounds; r++) {
        if (lanes == 16) {
            hm_md5_transform16x(st, (const uint8_t (*)[64])(const void *)blk);
        } else {
            hm_md5_transform8x(st, (const uint8_t (*)[64])(const void *)blk);
            hm_md5_transform8x(st + 8, (const uint8_t (*)[64])(const void *)(blk + 8));
        }
    }
    dt = hm_now() - t0;
    if (dt <= 0.0)
        return 0.0;
    return dt / ((double)rounds * 16.0) * 1e9;
}

static double time_sha256(int lanes, int rounds)
{
    uint32_t st[16][8];
    uint8_t blk[16][64];
    double t0;
    double dt;

    for (int l = 0; l < 16; l++) {
        memset(blk[l], 0, 64);
        memcpy(blk[l], "00000000", 8);
        blk[l][8] = 0x80;
        blk[l][63] = 64;
        memcpy(st[l], HM_SHA256_H0, sizeof(HM_SHA256_H0));
    }
    t0 = hm_now();
    for (int r = 0; r < rounds; r++) {
        if (lanes == 16) {
            hm_sha256_transform16x(st, (const uint8_t (*)[64])(const void *)blk);
        } else {
            hm_sha256_transform8x(st, (const uint8_t (*)[64])(const void *)blk);
            hm_sha256_transform8x(st + 8, (const uint8_t (*)[64])(const void *)(blk + 8));
        }
    }
    dt = hm_now() - t0;
    if (dt <= 0.0)
        return 0.0;
    return dt / ((double)rounds * 16.0) * 1e9;
}

static void init_tune(void)
{
    const hm_cpu_t *c = hm_cpu();
    hm_tune_t t;

    g_tuning = true;
    memset(&t, 0, sizeof(t));
    t.md5_lanes = c->md5_lanes;
    t.sha256_lanes = c->sha256_lanes;
    t.md5_avx512 = c->md5_lanes == 16;
    t.sha256_avx512 = c->sha256_lanes == 16;

    /* Only a CPU that reports 512-bit vectors can be tuned downwards, and a
     * forced mode must not be overridden. */
    if (c->avx2 && c->avx512f && t.md5_avx512 &&
        cpu_mode() == HM_CPU_AUTO) {
        const int rounds = 2000;
        const double w = time_md5(16, rounds);
        const double n = time_md5(8, rounds);
        const double ws = time_sha256(16, rounds);
        const double ns = time_sha256(8, rounds);

        /* stay on AVX-512 only when it is a real win; a 25% margin covers
         * the frequency drop a mixed workload can see */
        if (!(w * 1.25 < n)) {
            note("autotune: avx512 md5 is not a clear win, using 8 lanes");
            t.md5_lanes = 8;
            t.md5_avx512 = false;
        }
        if (!(ws * 1.25 < ns)) {
            t.sha256_lanes = 8;
            t.sha256_avx512 = false;
        }
        if (verbose()) {
            fprintf(stderr,
                    "[cpu] autotune: md5 16-lane %.2f vs 8-lane %.2f ns; "
                    "sha256 16-lane %.2f vs 8-lane %.2f ns\n",
                    w, n, ws, ns);
        }
        t.measured = true;
    }
    g_tune = t;
    g_tuning = false;
}

const hm_tune_t *hm_autotune(void)
{
    (void)pthread_once(&g_tune_once, init_tune);
    return &g_tune;
}

bool hm_cpu_wide_for(bool sha256)
{
    if (g_tuning)
        return hm_cpu_has_vector(512);
    const hm_tune_t *t = hm_autotune();
    return sha256 ? t->sha256_avx512 : t->md5_avx512;
}


void hm_tune_report(void)
{
    const hm_tune_t *t = hm_autotune();

    printf("tuned:    md5 %d lanes%s, sha256 %d lanes%s\n", t->md5_lanes,
           t->md5_avx512 ? " (avx512)" : "", t->sha256_lanes,
           t->sha256_avx512 ? " (avx512)" : "");
    printf("measure:  %s\n", t->measured ? "yes (autotuned)" : "no (CPUID)");
}
