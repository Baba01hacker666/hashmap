/*
 * hashmap - fast multi-threaded hash toolkit
 *
 *   digest  : hash a string with an algorithm (md5 / sha1 / sha256), salt optional
 *   brute   : multithreaded plaintext recovery for MD5 via pure brute force
 *             (length ranges, charset presets + combos, salted or not)
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define VERSION      "0.1.0"
#define MAX_TARGETS  4096
#define MAX_SALT     32
#define MAX_PWLEN    32
#define MAX_CS       256
#define MAX_PLAIN    (MAX_SALT * 2 + MAX_PWLEN + 1)

typedef enum { ALG_MD5, ALG_SHA1, ALG_SHA256 } algo_t;

/* ------------------------------------------------------------------ */
/* MD5                                                                 */
/* ------------------------------------------------------------------ */

static const uint32_t T[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
};

#define ROTL32(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define ROTR32(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
#define MDF(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MDG(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define MDH(x, y, z) ((x) ^ (y) ^ (z))
#define MDI(x, y, z) ((y) ^ ((x) | (~(z))))

#define STEP(f, a, b, c, d, m, s)                    \
    do {                                             \
        (a) += f((b), (c), (d)) + (m) + T[t];        \
        (a) = ROTL32((a), (s));                      \
        (a) += (b);                                  \
        t++;                                         \
    } while (0)

/* fully unrolled single-block transform, correct for messages of any
 * length as long as blk holds exactly one padded 64-byte block */
static inline void md5_transform(uint32_t st[4], const uint8_t blk[64])
{
    uint32_t x[16];
#ifdef __GNUC__
#pragma GCC unroll 16
#endif
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)blk[4 * i]     |
               ((uint32_t)blk[4 * i + 1] << 8)  |
               ((uint32_t)blk[4 * i + 2] << 16) |
               ((uint32_t)blk[4 * i + 3] << 24);

    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    int t = 0;

    /* round 1 - F */
    STEP(MDF, a, b, c, d, x[0], 7);   STEP(MDF, d, a, b, c, x[1], 12);
    STEP(MDF, c, d, a, b, x[2], 17);  STEP(MDF, b, c, d, a, x[3], 22);
    STEP(MDF, a, b, c, d, x[4], 7);   STEP(MDF, d, a, b, c, x[5], 12);
    STEP(MDF, c, d, a, b, x[6], 17);  STEP(MDF, b, c, d, a, x[7], 22);
    STEP(MDF, a, b, c, d, x[8], 7);   STEP(MDF, d, a, b, c, x[9], 12);
    STEP(MDF, c, d, a, b, x[10], 17); STEP(MDF, b, c, d, a, x[11], 22);
    STEP(MDF, a, b, c, d, x[12], 7);  STEP(MDF, d, a, b, c, x[13], 12);
    STEP(MDF, c, d, a, b, x[14], 17); STEP(MDF, b, c, d, a, x[15], 22);

    /* round 2 - G */
    STEP(MDG, a, b, c, d, x[1], 5);   STEP(MDG, d, a, b, c, x[6], 9);
    STEP(MDG, c, d, a, b, x[11], 14); STEP(MDG, b, c, d, a, x[0], 20);
    STEP(MDG, a, b, c, d, x[5], 5);   STEP(MDG, d, a, b, c, x[10], 9);
    STEP(MDG, c, d, a, b, x[15], 14); STEP(MDG, b, c, d, a, x[4], 20);
    STEP(MDG, a, b, c, d, x[9], 5);   STEP(MDG, d, a, b, c, x[14], 9);
    STEP(MDG, c, d, a, b, x[3], 14);  STEP(MDG, b, c, d, a, x[8], 20);
    STEP(MDG, a, b, c, d, x[13], 5);  STEP(MDG, d, a, b, c, x[2], 9);
    STEP(MDG, c, d, a, b, x[7], 14);  STEP(MDG, b, c, d, a, x[12], 20);

    /* round 3 - H */
    STEP(MDH, a, b, c, d, x[5], 4);   STEP(MDH, d, a, b, c, x[8], 11);
    STEP(MDH, c, d, a, b, x[11], 16); STEP(MDH, b, c, d, a, x[14], 23);
    STEP(MDH, a, b, c, d, x[1], 4);   STEP(MDH, d, a, b, c, x[4], 11);
    STEP(MDH, c, d, a, b, x[7], 16);  STEP(MDH, b, c, d, a, x[10], 23);
    STEP(MDH, a, b, c, d, x[13], 4);  STEP(MDH, d, a, b, c, x[0], 11);
    STEP(MDH, c, d, a, b, x[3], 16);  STEP(MDH, b, c, d, a, x[6], 23);
    STEP(MDH, a, b, c, d, x[9], 4);   STEP(MDH, d, a, b, c, x[12], 11);
    STEP(MDH, c, d, a, b, x[15], 16); STEP(MDH, b, c, d, a, x[2], 23);

    /* round 4 - I */
    STEP(MDI, a, b, c, d, x[0], 6);   STEP(MDI, d, a, b, c, x[7], 10);
    STEP(MDI, c, d, a, b, x[14], 15); STEP(MDI, b, c, d, a, x[5], 21);
    STEP(MDI, a, b, c, d, x[12], 6);  STEP(MDI, d, a, b, c, x[3], 10);
    STEP(MDI, c, d, a, b, x[10], 15); STEP(MDI, b, c, d, a, x[1], 21);
    STEP(MDI, a, b, c, d, x[8], 6);   STEP(MDI, d, a, b, c, x[15], 10);
    STEP(MDI, c, d, a, b, x[6], 15);  STEP(MDI, b, c, d, a, x[13], 21);
    STEP(MDI, a, b, c, d, x[4], 6);   STEP(MDI, d, a, b, c, x[11], 10);
    STEP(MDI, c, d, a, b, x[2], 15);  STEP(MDI, b, c, d, a, x[9], 21);

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

static const uint32_t MD5_INIT[4] = {
    0x67452301u, 0xefcdab89u, 0x98badcfelu, 0x10325476u
};

/* generic md5 for arbitrary-length messages (fallback path) */
static void md5_generic(const uint8_t *msg, size_t len, uint8_t out[16])
{
    uint32_t st[4] = { MD5_INIT[0], MD5_INIT[1], MD5_INIT[2], MD5_INIT[3] };
    size_t i = 0;

    while (i + 64 <= len) {
        md5_transform(st, msg + i);
        i += 64;
    }

    uint8_t tail[128];
    size_t rem = len - i;
    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    size_t body_end = (rem < 56) ? 56 : 120;
    memset(tail + rem + 1, 0, body_end - rem - 1);
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        tail[body_end + j] = (uint8_t)(bits >> (8 * j));
    md5_transform(st, tail);
    if (body_end == 120)
        md5_transform(st, tail + 64);

    for (int j = 0; j < 4; j++) {
        out[4 * j]     = (uint8_t)(st[j]);
        out[4 * j + 1] = (uint8_t)(st[j] >> 8);
        out[4 * j + 2] = (uint8_t)(st[j] >> 16);
        out[4 * j + 3] = (uint8_t)(st[j] >> 24);
    }
}

/* ------------------------------------------------------------------ */
/* SHA-1 / SHA-256 (digest mode extras)                                 */
/* ------------------------------------------------------------------ */

static void sha1_generic(const uint8_t *msg, size_t len, uint8_t out[20])
{
    uint32_t h[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfelu,
                      0x10325476u, 0xc3d2e1f0u };
    size_t total = len;
    const uint8_t *p = msg;
    size_t i = 0;

    while (i + 64 <= len) {
        uint32_t w[80];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)p[4 * j] << 24) | ((uint32_t)p[4 * j + 1] << 16) |
                   ((uint32_t)p[4 * j + 2] << 8) | (uint32_t)p[4 * j + 3];
        for (int j = 16; j < 80; j++)
            w[j] = ROTL32(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t f, k;
            if (j < 20)      { f = (b & c) | (~b & d);           k = 0x5a827999u; }
            else if (j < 40) { f = b ^ c ^ d;                    k = 0x6ed9eba1u; }
            else if (j < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8f1bbcdcu; }
            else             { f = b ^ c ^ d;                    k = 0xca62c1d6u; }
            uint32_t tmp = ROTL32(a, 5) + f + e + k + w[j];
            e = d; d = c; c = ROTL32(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        i += 64;
        p += 64;
    }
    (void)total;

    uint8_t tail[128];
    size_t rem = len - i;
    memcpy(tail, p, rem);
    tail[rem] = 0x80;
    size_t body_end = (rem < 56) ? 56 : 120;
    memset(tail + rem + 1, 0, body_end - rem - 1);
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        tail[body_end + j] = (uint8_t)(bits >> (56 - 8 * j)); /* big endian */
    /* finish last block(s) with same expansion loop */
    size_t blks = (body_end == 56) ? 64 : 128;
    for (size_t off = 0; off < blks; off += 64) {
        uint32_t w[80];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)tail[off + 4 * j] << 24) |
                   ((uint32_t)tail[off + 4 * j + 1] << 16) |
                   ((uint32_t)tail[off + 4 * j + 2] << 8) |
                   (uint32_t)tail[off + 4 * j + 3];
        for (int j = 16; j < 80; j++)
            w[j] = ROTL32(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t f, k;
            if (j < 20)      { f = (b & c) | (~b & d);           k = 0x5a827999u; }
            else if (j < 40) { f = b ^ c ^ d;                    k = 0x6ed9eba1u; }
            else if (j < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8f1bbcdcu; }
            else             { f = b ^ c ^ d;                    k = 0xca62c1d6u; }
            uint32_t tmp = ROTL32(a, 5) + f + e + k + w[j];
            e = d; d = c; c = ROTL32(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    for (int j = 0; j < 5; j++) {
        out[4 * j]     = (uint8_t)(h[j] >> 24);
        out[4 * j + 1] = (uint8_t)(h[j] >> 16);
        out[4 * j + 2] = (uint8_t)(h[j] >> 8);
        out[4 * j + 3] = (uint8_t)(h[j]);
    }
}

/* SHA-256 constants are derived at runtime from cube/square roots of the
 * first primes (FIPS 180-4 spec definition) - no typo'd tables. */
static void sha256_consts(uint32_t K[64], uint32_t H0[8])
{
    static const uint16_t primes[64] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
        257, 263, 269, 271, 277, 281, 283, 293, 307, 311
    };
    for (int i = 0; i < 64; i++) {
        double c = cbrt((double)primes[i]);
        double f = c - floor(c);
        K[i] = (uint32_t)(f * 4294967296.0);
        if (i < 8) {
            double s = sqrt((double)primes[i]);
            f = s - floor(s);
            H0[i] = (uint32_t)(f * 4294967296.0);
        }
    }
}

static void sha256_generic(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t K[64], H0[8];
    sha256_consts(K, H0);
    uint32_t h[8];
    memcpy(h, H0, sizeof(h));

    size_t i = 0;
    const uint8_t *p = msg;
    while (i + 64 <= len) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)p[4 * j] << 24) | ((uint32_t)p[4 * j + 1] << 16) |
                   ((uint32_t)p[4 * j + 2] << 8) | (uint32_t)p[4 * j + 3];
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = ROTR32(w[j - 15], 7) ^ ROTR32(w[j - 15], 18) ^ (w[j - 15] >> 3);
            uint32_t s1 = ROTR32(w[j - 2], 17) ^ ROTR32(w[j - 2], 19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[j] + w[j];
            uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c;  c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        i += 64; p += 64;
    }

    uint8_t tail[128];
    size_t rem = len - i;
    memcpy(tail, p, rem);
    tail[rem] = 0x80;
    size_t body_end = (rem < 56) ? 56 : 120;
    memset(tail + rem + 1, 0, body_end - rem - 1);
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        tail[body_end + j] = (uint8_t)(bits >> (56 - 8 * j));
    size_t blks = (body_end == 56) ? 64 : 128;
    for (size_t off = 0; off < blks; off += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)tail[off + 4 * j] << 24) |
                   ((uint32_t)tail[off + 4 * j + 1] << 16) |
                   ((uint32_t)tail[off + 4 * j + 2] << 8) |
                   (uint32_t)tail[off + 4 * j + 3];
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = ROTR32(w[j - 15], 7) ^ ROTR32(w[j - 15], 18) ^ (w[j - 15] >> 3);
            uint32_t s1 = ROTR32(w[j - 2], 17) ^ ROTR32(w[j - 2], 19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[j] + w[j];
            uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c;  c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    for (int j = 0; j < 8; j++) {
        out[4 * j]     = (uint8_t)(h[j] >> 24);
        out[4 * j + 1] = (uint8_t)(h[j] >> 16);
        out[4 * j + 2] = (uint8_t)(h[j] >> 8);
        out[4 * j + 3] = (uint8_t)(h[j]);
    }
}

static void hash_any(algo_t alg, const uint8_t *msg, size_t len, uint8_t *out, size_t *outlen)
{
    switch (alg) {
    case ALG_MD5:    *outlen = 16; md5_generic(msg, len, out);    break;
    case ALG_SHA1:   *outlen = 20; sha1_generic(msg, len, out);   break;
    case ALG_SHA256: *outlen = 32; sha256_generic(msg, len, out); break;
    }
}

static void to_hex(const uint8_t *b, size_t n, char *s)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        s[2 * i]     = h[b[i] >> 4];
        s[2 * i + 1] = h[b[i] & 0xf];
    }
    s[2 * n] = 0;
}

/* ------------------------------------------------------------------ */
/* charset handling                                                     */
/* ------------------------------------------------------------------ */

typedef struct { const char *name; const char *chars; } cs_builtin_t;

static const cs_builtin_t BUILTINS[] = {
    { "digits",    "0123456789" },
    { "lower",     "abcdefghijklmnopqrstuvwxyz" },
    { "upper",     "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
    { "alpha",     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" },
    { "alnum",     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" },
    { "hexlower",  "0123456789abcdef" },
    { "hexupper",  "0123456789ABCDEF" },
    { "special",   "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" },
    { "all",       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                   "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ " },
    { NULL, NULL }
};

/* spec: builtin names joined with '+', unknown tokens taken literally
 * e.g.  "digits", "lower+digits", "abc123" */
static int build_charset(const char *spec, char *out, size_t *outlen)
{
    size_t n = 0;
    const char *p = spec;
    if (!*p) return -1;
    while (*p) {
        const char *plus = strchr(p, '+');
        size_t tl = plus ? (size_t)(plus - p) : strlen(p);
        bool matched = false;
        for (const cs_builtin_t *b = BUILTINS; b->name; b++) {
            if (strlen(b->name) == tl && strncmp(p, b->name, tl) == 0) {
                for (const char *c = b->chars; *c && n < MAX_CS; c++)
                    out[n++] = *c;
                matched = true;
                break;
            }
        }
        if (!matched)
            for (size_t i = 0; i < tl && n < MAX_CS; i++)
                out[n++] = p[i];
        if (!plus) break;
        p = plus + 1;
    }
    if (n == 0) return -1;
    *outlen = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* brute force core                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t bytes[32];
    char    hex[65];
} target_t;

typedef struct {
    /* shared config (read-only) */
    int            nthreads;
    int            minlen, maxlen;
    const char    *cs;            /* charset chars */
    int            cslen;
    char           salt[MAX_SALT + 1];
    int            salt_len;
    int            salt_pre;      /* 1 = salt before candidate */
    int            ntargets;
    const target_t *targets;
    volatile atomic_int *stop;    /* points to g_stop */

    /* shared results */
    pthread_mutex_t *found_mtx;
    atomic_uint_fast64_t *counter; /* total candidates tried */
    atomic_int           *cur_len; /* progress display */
    atomic_int           *workers_done;
    FILE                 *out;
    volatile int         *found_total;

    /* per-thread */
    int tid;
} job_t;

static inline bool odom_next(uint8_t *d, int L, int cslen)
{
    for (int i = L - 1; i >= 0; i--) {
        if (++d[i] < cslen)
            return true;
        d[i] = 0;
    }
    return false;
}

static inline void idx_to_digits(uint64_t idx, uint8_t *d, int L, int cslen)
{
    for (int i = L - 1; i >= 0; i--) {
        d[i] = (uint8_t)(idx % (uint64_t)cslen);
        idx /= (uint64_t)cslen;
    }
}

typedef struct {
    uint32_t base[4];   /* midstate (or MD5 init)             */
    uint8_t  blk[64];   /* final block template               */
    bool     fast;      /* midstate path usable               */
    bool     has_pre;   /* salt before candidate (blk has no len) */
} lenctx_t;

static void build_lenctx(lenctx_t *ctx, int L,
                         const char *salt, int salt_len, bool pre)
{
    const int pre_len  = pre ? salt_len : 0;
    const int post_len = pre ? 0 : salt_len;
    const int total    = pre_len + L + post_len;
    const int rem      = L + post_len; /* bytes after midstate */

    memset(ctx, 0, sizeof(*ctx));
    ctx->has_pre = pre_len > 0;

    if (pre_len <= 55 && rem <= 55) {
        ctx->fast = true;
        if (pre_len > 0) {
            uint8_t b1[64];
            memset(b1, 0, 64);
            memcpy(b1, salt, pre_len);
            b1[pre_len] = 0x80;
            uint64_t bits = (uint64_t)total * 8;
            for (int i = 0; i < 8; i++)
                b1[56 + i] = (uint8_t)(bits >> (8 * i));
            memcpy(ctx->base, MD5_INIT, sizeof(ctx->base));
            md5_transform(ctx->base, b1);
        } else {
            memcpy(ctx->base, MD5_INIT, sizeof(ctx->base));
        }

        memset(ctx->blk, 0, 64);
        if (post_len)
            memcpy(ctx->blk + L, salt, (size_t)post_len);
        ctx->blk[rem] = 0x80;
        if (pre_len == 0) { /* single block: length field lives here */
            uint64_t bits = (uint64_t)total * 8;
            for (int i = 0; i < 8; i++)
                ctx->blk[56 + i] = (uint8_t)(bits >> (8 * i));
        }
    } else {
        ctx->fast = false; /* generic fallback */
    }
}

static inline void make_digest(const lenctx_t *ctx, const char *cs, int L,
                               const uint8_t *digs, uint8_t out[16],
                               const char *salt, int salt_len, bool pre)
{
    const int pre_len  = pre ? salt_len : 0;
    const int post_len = pre ? 0 : salt_len;

    if (ctx->fast) {
        uint32_t st[4];
        memcpy(st, ctx->base, sizeof(st));
        uint8_t blk[64];
        memcpy(blk, ctx->blk, 64);
        for (int k = 0; k < L; k++)
            blk[k] = (uint8_t)cs[digs[k]];
        md5_transform(st, blk);
        for (int i = 0; i < 4; i++) {
            out[4 * i]     = (uint8_t)(st[i]);
            out[4 * i + 1] = (uint8_t)(st[i] >> 8);
            out[4 * i + 2] = (uint8_t)(st[i] >> 16);
            out[4 * i + 3] = (uint8_t)(st[i] >> 24);
        }
    } else {
        uint8_t buf[MAX_SALT * 2 + MAX_PWLEN];
        size_t n = 0;
        if (pre_len) { memcpy(buf, salt, (size_t)pre_len); n = (size_t)pre_len; }
        for (int k = 0; k < L; k++)
            buf[n++] = (uint8_t)cs[digs[k]];
        if (post_len) { memcpy(buf + n, salt, (size_t)post_len); n += (size_t)post_len; }
        md5_generic(buf, n, out);
    }
}

static void report_found(job_t *job, const target_t *tg, const char *plain,
                         int L, double elapsed)
{
    pthread_mutex_lock(job->found_mtx);
    printf("\r\033[K");
    printf("[+] CRACKED  %s  ->  %s  (len %d, %.2fs)\n", tg->hex, plain, L, elapsed);
    if (job->out) {
        fprintf(job->out, "%s:%s\n", tg->hex, plain);
        fflush(job->out);
    }
    (*(volatile int *)job->found_total)++;
    bool all = (*job->found_total >= job->ntargets);
    pthread_mutex_unlock(job->found_mtx);
    if (all) /* nothing left to find - stop all workers */
        atomic_store(job->stop, 1);
}

static inline bool check_targets(const job_t *job, const uint8_t dg[16],
                                 const target_t **hit)
{
    for (int i = 0; i < job->ntargets; i++) {
        if (dg[0] == job->targets[i].bytes[0] && dg[1] == job->targets[i].bytes[1] &&
            dg[2] == job->targets[i].bytes[2] && dg[3] == job->targets[i].bytes[3] &&
            memcmp(dg, job->targets[i].bytes, 16) == 0) {
            *hit = &job->targets[i];
            return true;
        }
    }
    return false;
}

static void *worker(void *arg)
{
    job_t *job = (job_t *)arg;
    const char *cs = job->cs;
    const int cslen = job->cslen;
    const char *salt = job->salt;
    const int salt_len = job->salt_len;
    const bool pre = job->salt_pre != 0;
    const int pre_len = pre ? salt_len : 0;
    const int post_len = pre ? 0 : salt_len;
    const uint64_t flush_mask = (1u << 12) - 1; /* flush count every 4096 */

    uint8_t digs[MAX_PWLEN];
    char plain[MAX_PLAIN];
    uint8_t dg[16];
    uint64_t local = 0;

    for (int L = job->minlen; L <= job->maxlen; L++) {
        if (atomic_load_explicit(job->stop, memory_order_relaxed))
            break;
        atomic_store(job->cur_len, L);

        uint64_t space;
        bool ovf = false;
        {
            uint64_t r = 1;
            for (int i = 0; i < L; i++) {
                if (r > UINT64_MAX / (uint64_t)cslen) { ovf = true; break; }
                r *= (uint64_t)cslen;
            }
            space = r;
        }
        if (ovf)
            break;

        uint64_t chunk = space / (uint64_t)job->nthreads;
        uint64_t lo = chunk * (uint64_t)job->tid;
        uint64_t hi = (job->tid == job->nthreads - 1) ? space : lo + chunk;
        if (lo >= hi)
            continue;

        lenctx_t ctx;
        build_lenctx(&ctx, L, salt, salt_len, pre);

        idx_to_digits(lo, digs, L, cslen);

        for (uint64_t idx = lo; idx < hi; idx++) {
            if (atomic_load_explicit(job->stop, memory_order_relaxed))
                goto done;

            make_digest(&ctx, cs, L, digs, dg, salt, salt_len, pre);

            const target_t *hit;
            if (check_targets(job, dg, &hit)) {
                size_t n = 0;
                if (pre_len) { memcpy(plain, salt, (size_t)pre_len); n = (size_t)pre_len; }
                for (int k = 0; k < L; k++)
                    plain[n++] = cs[digs[k]];
                if (post_len) { memcpy(plain + n, salt, (size_t)post_len); n += (size_t)post_len; }
                plain[n] = 0;
                report_found(job, hit, plain, L, 0.0);
            }

            local++;
            if ((local & flush_mask) == 0)
                atomic_fetch_add_explicit(job->counter, flush_mask + 1,
                                          memory_order_relaxed);

            if (!odom_next(digs, L, cslen))
                break; /* wrapped - shouldn't happen mid-chunk except at end */
        }
    }
done:
    atomic_fetch_add_explicit(job->counter, local & flush_mask,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(job->workers_done, 1, memory_order_relaxed);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* helpers                                                              */
/* ------------------------------------------------------------------ */

static atomic_int g_stop = 0;

static void on_sigint(int sig)
{
    (void)sig;
    atomic_store(&g_stop, 1);
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void fmt_u64(uint64_t v, char *buf, size_t n)
{
    char tmp[32];
    int i = 0;
    if (v == 0) { snprintf(buf, n, "0"); return; }
    while (v) {
        tmp[i++] = (char)('0' + (v % 10));
        v /= 10;
        if (i % 4 == 3 && v) tmp[i++] = ',';
    }
    int o = 0;
    while (i > 0 && (size_t)o < n - 1) buf[o++] = tmp[--i];
    buf[o] = 0;
}

static void fmt_rate(double hps, char *buf, size_t n)
{
    if (hps >= 1e9)      snprintf(buf, n, "%.2f GH/s", hps / 1e9);
    else if (hps >= 1e6) snprintf(buf, n, "%.2f MH/s", hps / 1e6);
    else if (hps >= 1e3) snprintf(buf, n, "%.2f kH/s", hps / 1e3);
    else                  snprintf(buf, n, "%.2f H/s", hps);
}

static uint64_t pow_checked(uint64_t base, int e, bool *ovf)
{
    uint64_t r = 1;
    *ovf = false;
    for (int i = 0; i < e; i++) {
        if (r > UINT64_MAX / base) { *ovf = true; return 0; }
        r *= base;
    }
    return r;
}

static int parse_hex_md5(const char *hex, target_t *tg)
{
    size_t l = strlen(hex);
    if (l != 32) {
        fprintf(stderr, "[-] '%s' is not a 32-char MD5 hex string\n", hex);
        return -1;
    }
    for (int i = 0; i < 16; i++) {
        char c1 = hex[2 * i], c2 = hex[2 * i + 1];
        if (!isxdigit((unsigned char)c1) || !isxdigit((unsigned char)c2)) {
            fprintf(stderr, "[-] '%s' is not valid hex\n", hex);
            return -1;
        }
        int v1 = isdigit((unsigned char)c1) ? c1 - '0' : (tolower(c1) - 'a' + 10);
        int v2 = isdigit((unsigned char)c2) ? c2 - '0' : (tolower(c2) - 'a' + 10);
        tg->bytes[i] = (uint8_t)(v1 * 16 + v2);
    }
    to_hex(tg->bytes, 16, tg->hex);
    return 0;
}

static int load_hash_file(const char *path, target_t *targets, int *nt)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[-] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    char line[256];
    while ((nt[0] < MAX_TARGETS) && fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == 0) continue;
        char *nl = strpbrk(s, "\r\n");
        if (nl) *nl = 0;
        if (strlen(s) != 32) {
            fprintf(stderr, "[-] hash file line not MD5 hex (32 chars): '%s'\n", s);
            fclose(f);
            return -1;
        }
        if (parse_hex_md5(s, &targets[nt[0]]) < 0) { fclose(f); return -1; }
        nt[0]++;
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* usage                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    printf(
    "hashmap v" VERSION " - fast multi-threaded hash toolkit\n"
    "\n"
    "usage:\n"
    "  %s digest -a <md5|sha1|sha256> -i <string> [options]\n"
    "  %s brute  -H <md5hex> [options]\n"
    "\n"
    "digest options:\n"
    "  -a, --algo <md5|sha1|sha256>  hash algo (default md5)\n"
    "  -i, --input <string>          string to hash ('-' + stdin lines)\n"
    "  -s, --salt <string>           salt the input\n"
    "  -p, --salt-pos <pre|post>     salt placement (default pre)\n"
    "\n"
    "brute options:\n"
    "  -H, --hash <md5hex>           target hash, repeat for multiple targets\n"
    "  -f, --file <file>             file of MD5 hashes (one per line, '#' comments)\n"
    "  -c, --charset <spec>          charset: builtin names or literal chars,\n"
    "                                combinable with '+'. builtins:\n"
    "                                  digits lower upper alpha alnum hexlower\n"
    "                                  hexupper special all\n"
    "                                default: digits\n"
    "      --min <n>                 min length (default 1)\n"
    "      --max <n>                 max length (default 6)\n"
    "  -t, --threads <n>             worker threads (default: all cores)\n"
    "  -s, --salt <string>           salt applied to every candidate\n"
    "  -p, --salt-pos <pre|post>     salt placement (default pre)\n"
    "  -o, --out <file>              append crack results to file\n"
    "  -v, --version                 print version\n"
    "  -h, --help                    this help\n"
    "\n"
    "examples:\n"
    "  %s digest -i hello\n"
    "  %s digest -a md5 -i hello -s hunter2 -p post\n"
    "  %s brute -H 900150983cd24fb0d6963f7d28e17f72\n" /* abc */
    "  %s brute -H <hash> -c lower+digits --min 1 --max 6 -t 8\n"
    "  %s brute -H <hash> -c digits -s mycompany -p pre\n"
    "  %s brute -f targets.txt -c alnum --max 4\n",
    prog, prog, prog, prog, prog, prog, prog, prog);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    const char *prog = argv[0];
    const char *mode = argv[1];

    if (strcmp(mode, "-h") == 0 || strcmp(mode, "--help") == 0) {
        usage(prog);
        return 0;
    }
    if (strcmp(mode, "-v") == 0 || strcmp(mode, "--version") == 0) {
        printf("hashmap v" VERSION "\n");
        return 0;
    }

    /* ---------------- digest mode ---------------- */
    if (strcmp(mode, "digest") == 0) {
        int algo = ALG_MD5;
        const char *input = NULL, *salt = NULL, *saltpos = "pre", *file = NULL;

        static struct option lopts[] = {
            { "algo",     required_argument, 0, 'a' },
            { "input",    required_argument, 0, 'i' },
            { "salt",     required_argument, 0, 's' },
            { "salt-pos", required_argument, 0, 'p' },
            { "file",     required_argument, 0, 'f' },
            { "help",     no_argument,       0, 'h' },
            { "version",  no_argument,       0, 'v' },
            { 0, 0, 0, 0 }
        };
        int opt;
        while ((opt = getopt_long(argc - 1, argv + 1, "a:i:s:p:f:hv", lopts, NULL)) != -1) {
            switch (opt) {
            case 'a':
                if (!strcmp(optarg, "md5")) algo = ALG_MD5;
                else if (!strcmp(optarg, "sha1")) algo = ALG_SHA1;
                else if (!strcmp(optarg, "sha256")) algo = ALG_SHA256;
                else { fprintf(stderr, "[-] unknown algo '%s'\n", optarg); return 2; }
                break;
            case 'i': input = optarg; break;
            case 's': salt = optarg; break;
            case 'p':
                if (strcmp(optarg, "pre") && strcmp(optarg, "post")) {
                    fprintf(stderr, "[-] salt-pos must be pre|post\n");
                    return 2;
                }
                saltpos = optarg;
                break;
            case 'f': file = optarg; break;
            case 'h': usage(prog); return 0;
            case 'v': printf("hashmap v" VERSION "\n"); return 0;
            default: return 2;
            }
        }
        if (!input && !file) {
            fprintf(stderr, "[-] digest needs -i <string> or -f <file>\n");
            return 2;
        }

        size_t snl = salt ? strlen(salt) : 0;
        if (snl > MAX_SALT) { fprintf(stderr, "[-] salt too long (max %d)\n", MAX_SALT); return 2; }
        bool digest_pre = !strcmp(saltpos, "pre");

        /* hash one string, print hex + newline */
#define DIGEST_ONE(str_)                                                  \
        do {                                                              \
            const char *s_ = (str_);                                      \
            size_t ll = strlen(s_);                                       \
            size_t bn = 0;                                                \
            static uint8_t buf[MAX_SALT + 8192];                          \
            if (salt && digest_pre) { memcpy(buf, salt, snl); bn = snl; }  \
            memcpy(buf + bn, s_, ll); bn += ll;                           \
            if (salt && !digest_pre) { memcpy(buf + bn, salt, snl); bn += snl; } \
            uint8_t o[32];                                                \
            size_t olen;                                                  \
            hash_any((algo_t)algo, buf, bn, o, &olen);                    \
            char hex[65];                                                 \
            to_hex(o, olen, hex);                                         \
            printf("%s\n", hex);                                          \
        } while (0)

        if (input) {
            if (!strcmp(input, "-") && !isatty(0)) {
                char line[8192];
                while (fgets(line, sizeof(line), stdin)) {
                    char *nl = strpbrk(line, "\r\n");
                    if (nl) *nl = 0;
                    DIGEST_ONE(line);
                }
            } else {
                DIGEST_ONE(input);
            }
        }
        if (file) {
            FILE *fp = fopen(file, "r");
            if (!fp) { fprintf(stderr, "[-] cannot open %s: %s\n", file, strerror(errno)); return 1; }
            char line[8192];
            while (fgets(line, sizeof(line), fp)) {
                char *s = line;
                while (*s == ' ' || *s == '\t') s++;
                if (*s == '#' || *s == '\n' || !*s) continue;
                char *nl = strpbrk(s, "\r\n");
                if (nl) *nl = 0;
                DIGEST_ONE(s);
            }
            fclose(fp);
        }
        return 0;
    }

    /* ---------------- brute mode ---------------- */
    if (strcmp(mode, "brute") == 0) {
        target_t *targets = calloc(MAX_TARGETS, sizeof(target_t));
        int ntargets = 0;
        int minlen = 1, maxlen = 6, nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
        const char *csspec = "digits";
        const char *salt = NULL, *saltpos = "pre", *outfile = NULL;

        static struct option lopts[] = {
            { "hash",     required_argument, 0, 'H' },
            { "file",     required_argument, 0, 'f' },
            { "charset",  required_argument, 0, 'c' },
            { "min",      required_argument, 0, 1000 },
            { "max",      required_argument, 0, 1001 },
            { "threads",  required_argument, 0, 't' },
            { "salt",     required_argument, 0, 's' },
            { "salt-pos", required_argument, 0, 'p' },
            { "out",      required_argument, 0, 'o' },
            { "help",     no_argument,       0, 'h' },
            { "version",  no_argument,       0, 'v' },
            { 0, 0, 0, 0 }
        };
        int opt;
        optind = 1;
        while ((opt = getopt_long(argc - 1, argv + 1, "H:f:c:t:s:p:o:hv", lopts, NULL)) != -1) {
            switch (opt) {
            case 'H':
                if (ntargets >= MAX_TARGETS) { fprintf(stderr, "[-] too many targets\n"); return 2; }
                if (parse_hex_md5(optarg, &targets[ntargets]) < 0) return 2;
                ntargets++;
                break;
            case 'f':
                if (load_hash_file(optarg, targets, &ntargets) < 0) return 2;
                break;
            case 'c': csspec = optarg; break;
            case 1000: minlen = atoi(optarg); break;
            case 1001: maxlen = atoi(optarg); break;
            case 't': nthreads = atoi(optarg); break;
            case 's': salt = optarg; break;
            case 'p':
                if (strcmp(optarg, "pre") && strcmp(optarg, "post")) {
                    fprintf(stderr, "[-] salt-pos must be pre|post\n");
                    return 2;
                }
                saltpos = optarg;
                break;
            case 'o': outfile = optarg; break;
            case 'h': usage(prog); return 0;
            case 'v': printf("hashmap v" VERSION "\n"); return 0;
            default: return 2;
            }
        }

        if (ntargets == 0) {
            fprintf(stderr, "[-] brute needs at least one target: -H <md5hex> or -f <file>\n");
            return 2;
        }
        if (minlen < 1 || maxlen < 1 || minlen > MAX_PWLEN || maxlen > MAX_PWLEN || minlen > maxlen) {
            fprintf(stderr, "[-] invalid length range %d-%d (1..%d)\n", minlen, maxlen, MAX_PWLEN);
            return 2;
        }
        if (nthreads < 1) nthreads = 1;
        if (nthreads > 1024) nthreads = 1024;

        char cs[MAX_CS + 1];
        size_t cslen = 0;
        if (build_charset(csspec, cs, &cslen) < 0) {
            fprintf(stderr, "[-] empty charset\n");
            return 2;
        }
        cs[cslen] = 0;

        size_t salt_len = salt ? strlen(salt) : 0;
        if (salt_len > MAX_SALT) { fprintf(stderr, "[-] salt too long (max %d)\n", MAX_SALT); return 2; }
        bool pre = !strcmp(saltpos, "pre");

        /* dedupe targets, drop found dups */
        for (int i = 0; i < ntargets; i++)
            for (int j = i + 1; j < ntargets; j++)
                if (memcmp(targets[i].bytes, targets[j].bytes, 16) == 0) {
                    targets[j] = targets[--ntargets];
                    j--;
                }

        /* keyspace */
        uint64_t total_space = 0;
        bool ovf = false;
        for (int L = minlen; L <= maxlen; L++) {
            uint64_t s = pow_checked((uint64_t)cslen, L, &ovf);
            if (ovf || s > UINT64_MAX - total_space) {
                fprintf(stderr, "[-] keyspace too large, lower --max\n");
                return 2;
            }
            total_space += s;
        }
        if (total_space < (uint64_t)nthreads)
            nthreads = (int)total_space;

        /* banner */
        printf("[*] hashmap v" VERSION " - brute mode\n");
        printf("[*] charset: %s (%zu chars)", csspec, cslen);
        if (cslen <= 64) printf(" [%s]", cs);
        printf("\n");
        char tmp[32];
        fmt_u64(total_space, tmp, sizeof(tmp));
        printf("[*] length: %d-%d  keyspace: %s\n", minlen, maxlen, tmp);
        printf("[*] threads: %d\n", nthreads);
        printf("[*] salt: %s (%s)\n", salt ? salt : "(none)",
               salt ? (pre ? "pre" : "post") : "-");
        printf("[*] targets: %d\n", ntargets);

        FILE *outf = NULL;
        if (outfile) {
            outf = fopen(outfile, "a");
            if (!outf) { fprintf(stderr, "[-] cannot open %s: %s\n", outfile, strerror(errno)); return 1; }
        }

        /* shared state */
        static atomic_uint_fast64_t counter = 0;
        atomic_int cur_len = minlen;
        atomic_int workers_done = 0;
        pthread_mutex_t found_mtx = PTHREAD_MUTEX_INITIALIZER;
        int found_total = 0;

        job_t *jobs = calloc((size_t)nthreads, sizeof(job_t));
        pthread_t *tids = calloc((size_t)nthreads, sizeof(pthread_t));

        /* signals */
        struct sigaction sa = { 0 };
        sa.sa_handler = on_sigint;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);

        double t0 = now_s();
        for (int i = 0; i < nthreads; i++) {
            jobs[i] = (job_t){
                .nthreads = nthreads,
                .minlen = minlen, .maxlen = maxlen,
                .cs = cs, .cslen = (int)cslen,
                .salt = { 0 }, .salt_len = (int)salt_len, .salt_pre = pre ? 1 : 0,
                .ntargets = ntargets, .targets = targets,
                .stop = &g_stop,
                .found_mtx = &found_mtx,
                .counter = &counter,
                .cur_len = &cur_len,
                .workers_done = &workers_done,
                .out = outf,
                .found_total = &found_total,
                .tid = i,
            };
            if (salt) memcpy(jobs[i].salt, salt, salt_len);
            if (pthread_create(&tids[i], NULL, worker, &jobs[i]) != 0) {
                fprintf(stderr, "[-] pthread_create failed\n");
                return 1;
            }
        }

        uint64_t last_count = 0;
        double last_t = t0;
        int shown_len = minlen;

        for (;;) {
            struct timespec ts = { 0, 200 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            uint64_t cnt = atomic_load_explicit(&counter, memory_order_relaxed);
            double now = now_s();
            double rate = (double)(cnt - last_count) / (now - last_t);
            last_count = cnt;
            last_t = now;
            int fl = found_total;
            int cl = atomic_load_explicit(&cur_len, memory_order_relaxed);
            double pct = total_space ? (double)cnt * 100.0 / (double)total_space : 0;
            if (pct > 100) pct = 100;
            shown_len = (cl < minlen || cl > maxlen) ? shown_len : cl;
            double remain = rate > 0 ? (double)(total_space - cnt) / rate : 0;
            char cbuf[32], rbuf[32];
            fmt_u64(cnt, cbuf, sizeof(cbuf));
            fmt_rate(rate, rbuf, sizeof(rbuf));
            printf("\r[*] len %d/%d  %s tried  %.1f%%  %s  eta %.0fs  found %d/%d   ",
                   shown_len, maxlen, cbuf, pct, rbuf, remain, fl, ntargets);
            fflush(stdout);
            if (atomic_load_explicit(&g_stop, memory_order_relaxed) ||
                atomic_load_explicit(&workers_done, memory_order_relaxed) == nthreads)
                break;
        }

        for (int i = 0; i < nthreads; i++)
            pthread_join(tids[i], NULL);

        double elapsed = now_s() - t0;
        uint64_t cnt = atomic_load_explicit(&counter, memory_order_relaxed);
        char cbuf[32], rbuf[32];
        fmt_u64(cnt, cbuf, sizeof(cbuf));
        fmt_rate(elapsed > 0 ? (double)cnt / elapsed : 0, rbuf, sizeof(rbuf));
        printf("\r\033[K");
        printf("[*] done: %s candidates in %.2fs (%s avg)\n", cbuf, elapsed, rbuf);

        if (found_total > 0 && found_total == ntargets) {
            printf("[+] all %d target(s) cracked\n", ntargets);
            if (outf) fclose(outf);
            return 0;
        }
        if (found_total > 0)
            printf("[*] cracked %d/%d target(s)\n", found_total, ntargets);
        if (atomic_load(&g_stop))
            printf("[!] stopped (interrupt)\n");
        else
            printf("[-] exhausted keyspace, %d target(s) not found\n", ntargets - found_total);
        if (outf) fclose(outf);
        return (found_total == ntargets) ? 0 : 1;
    }

    fprintf(stderr, "[-] unknown mode '%s' (use digest|brute, see --help)\n", mode);
    return 2;
}
