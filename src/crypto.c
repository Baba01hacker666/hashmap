/* hashmap - crypto backends implementation
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "crypto.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* MD5                                                                 */
/* ------------------------------------------------------------------ */

#define HM_ROTL32(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define HM_MDF(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define HM_MDG(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define HM_MDH(x, y, z) ((x) ^ (y) ^ (z))
#define HM_MDI(x, y, z) ((y) ^ ((x) | (~(z))))

#define HM_STEP(f, a, b, c, d, m, s)         \
    do {                                     \
        (a) += f((b), (c), (d)) + (m) + T[t]; \
        (a) = HM_ROTL32((a), (s));            \
        (a) += (b);                           \
        t++;                                  \
    } while (0)

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

const uint32_t HM_MD5_INIT[4] = {
    0x67452301u, 0xefcdab89u, 0x98badcfelu, 0x10325476u
};

void hm_md5_transform(uint32_t st[4], const uint8_t blk[64])
{
    uint32_t x[16];
    int t = 0;
    uint32_t a, b, c, d;

#ifdef __GNUC__
#pragma GCC unroll 16
#endif
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)blk[4 * i] |
               ((uint32_t)blk[4 * i + 1] << 8) |
               ((uint32_t)blk[4 * i + 2] << 16) |
               ((uint32_t)blk[4 * i + 3] << 24);

    a = st[0];
    b = st[1];
    c = st[2];
    d = st[3];

    /* round 1 - F */
    HM_STEP(HM_MDF, a, b, c, d, x[0], 7);
    HM_STEP(HM_MDF, d, a, b, c, x[1], 12);
    HM_STEP(HM_MDF, c, d, a, b, x[2], 17);
    HM_STEP(HM_MDF, b, c, d, a, x[3], 22);
    HM_STEP(HM_MDF, a, b, c, d, x[4], 7);
    HM_STEP(HM_MDF, d, a, b, c, x[5], 12);
    HM_STEP(HM_MDF, c, d, a, b, x[6], 17);
    HM_STEP(HM_MDF, b, c, d, a, x[7], 22);
    HM_STEP(HM_MDF, a, b, c, d, x[8], 7);
    HM_STEP(HM_MDF, d, a, b, c, x[9], 12);
    HM_STEP(HM_MDF, c, d, a, b, x[10], 17);
    HM_STEP(HM_MDF, b, c, d, a, x[11], 22);
    HM_STEP(HM_MDF, a, b, c, d, x[12], 7);
    HM_STEP(HM_MDF, d, a, b, c, x[13], 12);
    HM_STEP(HM_MDF, c, d, a, b, x[14], 17);
    HM_STEP(HM_MDF, b, c, d, a, x[15], 22);

    /* round 2 - G */
    HM_STEP(HM_MDG, a, b, c, d, x[1], 5);
    HM_STEP(HM_MDG, d, a, b, c, x[6], 9);
    HM_STEP(HM_MDG, c, d, a, b, x[11], 14);
    HM_STEP(HM_MDG, b, c, d, a, x[0], 20);
    HM_STEP(HM_MDG, a, b, c, d, x[5], 5);
    HM_STEP(HM_MDG, d, a, b, c, x[10], 9);
    HM_STEP(HM_MDG, c, d, a, b, x[15], 14);
    HM_STEP(HM_MDG, b, c, d, a, x[4], 20);
    HM_STEP(HM_MDG, a, b, c, d, x[9], 5);
    HM_STEP(HM_MDG, d, a, b, c, x[14], 9);
    HM_STEP(HM_MDG, c, d, a, b, x[3], 14);
    HM_STEP(HM_MDG, b, c, d, a, x[8], 20);
    HM_STEP(HM_MDG, a, b, c, d, x[13], 5);
    HM_STEP(HM_MDG, d, a, b, c, x[2], 9);
    HM_STEP(HM_MDG, c, d, a, b, x[7], 14);
    HM_STEP(HM_MDG, b, c, d, a, x[12], 20);

    /* round 3 - H */
    HM_STEP(HM_MDH, a, b, c, d, x[5], 4);
    HM_STEP(HM_MDH, d, a, b, c, x[8], 11);
    HM_STEP(HM_MDH, c, d, a, b, x[11], 16);
    HM_STEP(HM_MDH, b, c, d, a, x[14], 23);
    HM_STEP(HM_MDH, a, b, c, d, x[1], 4);
    HM_STEP(HM_MDH, d, a, b, c, x[4], 11);
    HM_STEP(HM_MDH, c, d, a, b, x[7], 16);
    HM_STEP(HM_MDH, b, c, d, a, x[10], 23);
    HM_STEP(HM_MDH, a, b, c, d, x[13], 4);
    HM_STEP(HM_MDH, d, a, b, c, x[0], 11);
    HM_STEP(HM_MDH, c, d, a, b, x[3], 16);
    HM_STEP(HM_MDH, b, c, d, a, x[6], 23);
    HM_STEP(HM_MDH, a, b, c, d, x[9], 4);
    HM_STEP(HM_MDH, d, a, b, c, x[12], 11);
    HM_STEP(HM_MDH, c, d, a, b, x[15], 16);
    HM_STEP(HM_MDH, b, c, d, a, x[2], 23);

    /* round 4 - I */
    HM_STEP(HM_MDI, a, b, c, d, x[0], 6);
    HM_STEP(HM_MDI, d, a, b, c, x[7], 10);
    HM_STEP(HM_MDI, c, d, a, b, x[14], 15);
    HM_STEP(HM_MDI, b, c, d, a, x[5], 21);
    HM_STEP(HM_MDI, a, b, c, d, x[12], 6);
    HM_STEP(HM_MDI, d, a, b, c, x[3], 10);
    HM_STEP(HM_MDI, c, d, a, b, x[10], 15);
    HM_STEP(HM_MDI, b, c, d, a, x[1], 21);
    HM_STEP(HM_MDI, a, b, c, d, x[8], 6);
    HM_STEP(HM_MDI, d, a, b, c, x[15], 10);
    HM_STEP(HM_MDI, c, d, a, b, x[6], 15);
    HM_STEP(HM_MDI, b, c, d, a, x[13], 21);
    HM_STEP(HM_MDI, a, b, c, d, x[4], 6);
    HM_STEP(HM_MDI, d, a, b, c, x[11], 10);
    HM_STEP(HM_MDI, c, d, a, b, x[2], 15);
    HM_STEP(HM_MDI, b, c, d, a, x[9], 21);

    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
}

void hm_md5(const uint8_t *msg, size_t len, uint8_t out[16])
{
    uint32_t st[4] = { HM_MD5_INIT[0], HM_MD5_INIT[1], HM_MD5_INIT[2],
                       HM_MD5_INIT[3] };
    size_t i = 0;

    while (i + 64 <= len) {
        hm_md5_transform(st, msg + i);
        i += 64;
    }

    uint8_t tail[128];
    size_t rem = len - i;
    size_t body_end = (rem < 56) ? 56 : 120;
    uint64_t bits = (uint64_t)len * 8;

    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    memset(tail + rem + 1, 0, body_end - rem - 1);
    for (size_t j = 0; j < 8; j++)
        tail[body_end + j] = (uint8_t)(bits >> (8 * j));

    hm_md5_transform(st, tail);
    if (body_end == 120)
        hm_md5_transform(st, tail + 64);

    for (int j = 0; j < 4; j++) {
        out[4 * j] = (uint8_t)(st[j]);
        out[4 * j + 1] = (uint8_t)(st[j] >> 8);
        out[4 * j + 2] = (uint8_t)(st[j] >> 16);
        out[4 * j + 3] = (uint8_t)(st[j] >> 24);
    }
}

/* ------------------------------------------------------------------ */
/* SHA-1                                                               */
/* ------------------------------------------------------------------ */

static void sha1_blocks(uint32_t h[5], const uint8_t *p, size_t nblks)
{
    for (size_t off = 0; off < nblks * 64; off += 64) {
        uint32_t w[80];
        for (size_t j = 0; j < 16; j++)
            w[j] = ((uint32_t)p[off + 4 * j] << 24) |
                   ((uint32_t)p[off + 4 * j + 1] << 16) |
                   ((uint32_t)p[off + 4 * j + 2] << 8) |
                   (uint32_t)p[off + 4 * j + 3];
        for (int j = 16; j < 80; j++)
            w[j] = HM_ROTL32(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t f, k;
            if (j < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999u;
            } else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1u;
            } else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdcu;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6u;
            }
            uint32_t tmp = HM_ROTL32(a, 5) + f + e + k + w[j];
            e = d;
            d = c;
            c = HM_ROTL32(b, 30);
            b = a;
            a = tmp;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }
}

/* generic multi-block sha1: whole message must be one padded buffer tail
 * handled here (msg + worker-built padding). supports arbitrary len. */
void hm_sha1(const uint8_t *msg, size_t len, uint8_t out[20])
{
    uint32_t h[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfelu, 0x10325476u,
                      0xc3d2e1f0u };
    size_t i = 0;
    while (i + 64 <= len) {
        sha1_blocks(h, msg + i, 1);
        i += 64;
    }

    uint8_t tail[128];
    size_t rem = len - i;
    size_t body_end = (rem < 56) ? 56 : 120;
    uint64_t bits = (uint64_t)len * 8;

    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    memset(tail + rem + 1, 0, body_end - rem - 1);
    for (size_t j = 0; j < 8; j++)
        tail[body_end + j] = (uint8_t)(bits >> (56 - 8 * j)); /* BE */

    sha1_blocks(h, tail, (body_end + 63) / 64);

    for (int j = 0; j < 5; j++) {
        out[4 * j] = (uint8_t)(h[j] >> 24);
        out[4 * j + 1] = (uint8_t)(h[j] >> 16);
        out[4 * j + 2] = (uint8_t)(h[j] >> 8);
        out[4 * j + 3] = (uint8_t)(h[j]);
    }
}

/* ------------------------------------------------------------------ */
/* SHA-256 (FIPS 180-4 constants, hardcoded - no libm dependency)     */
/* ------------------------------------------------------------------ */

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint32_t SHA256_H0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static void sha256_blocks(uint32_t h[8], const uint32_t K[64],
                          const uint8_t *p, size_t nblks)
{
    for (size_t off = 0; off < nblks * 64; off += 64) {
        uint32_t w[64];
        for (size_t j = 0; j < 16; j++)
            w[j] = ((uint32_t)p[off + 4 * j] << 24) |
                   ((uint32_t)p[off + 4 * j + 1] << 16) |
                   ((uint32_t)p[off + 4 * j + 2] << 8) |
                   (uint32_t)p[off + 4 * j + 3];
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = ((w[j - 15] >> 7) | (w[j - 15] << 25)) ^
                          ((w[j - 15] >> 18) | (w[j - 15] << 14)) ^
                          (w[j - 15] >> 3);
            uint32_t s1 = ((w[j - 2] >> 17) | (w[j - 2] << 15)) ^
                          ((w[j - 2] >> 19) | (w[j - 2] << 13)) ^
                          (w[j - 2] >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                          ((e >> 25) | (e << 7));
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[j] + w[j];
            uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
                          ((a >> 22) | (a << 10));
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
}

void hm_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t h[8];

    memcpy(h, SHA256_H0, sizeof(h));

    size_t i = 0;
    while (i + 64 <= len) {
        sha256_blocks(h, SHA256_K, msg + i, 1);
        i += 64;
    }

    uint8_t tail[128];
    size_t rem = len - i;
    size_t body_end = (rem < 56) ? 56 : 120;
    uint64_t bits = (uint64_t)len * 8;

    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    memset(tail + rem + 1, 0, body_end - rem - 1);
    for (size_t j = 0; j < 8; j++)
        tail[body_end + j] = (uint8_t)(bits >> (56 - 8 * j)); /* BE */

    sha256_blocks(h, SHA256_K, tail, (body_end + 63) / 64);

    for (size_t j = 0; j < 8; j++) {
        out[4 * j] = (uint8_t)(h[j] >> 24);
        out[4 * j + 1] = (uint8_t)(h[j] >> 16);
        out[4 * j + 2] = (uint8_t)(h[j] >> 8);
        out[4 * j + 3] = (uint8_t)(h[j]);
    }
}

/* ------------------------------------------------------------------ */
/* generic dispatch                                                    */
/* ------------------------------------------------------------------ */

const char *hm_algo_name(hm_algo_t alg)
{
    switch (alg) {
    case HM_ALG_SHA1:
        return "sha1";
    case HM_ALG_SHA256:
        return "sha256";
    case HM_ALG_MD5:
    default:
        return "md5";
    }
}

int hm_algo_parse(const char *name, hm_algo_t *out)
{
    if (strcmp(name, "md5") == 0) {
        *out = HM_ALG_MD5;
        return 0;
    }
    if (strcmp(name, "sha1") == 0) {
        *out = HM_ALG_SHA1;
        return 0;
    }
    if (strcmp(name, "sha256") == 0) {
        *out = HM_ALG_SHA256;
        return 0;
    }
    return -1;
}

size_t hm_algo_size(hm_algo_t alg)
{
    switch (alg) {
    case HM_ALG_SHA1:
        return 20;
    case HM_ALG_SHA256:
        return 32;
    case HM_ALG_MD5:
    default:
        return 16;
    }
}

void hm_hash(hm_algo_t alg, const uint8_t *msg, size_t len, uint8_t *out,
             size_t *olen)
{
    *olen = hm_algo_size(alg);
    switch (alg) {
    case HM_ALG_SHA1:
        hm_sha1(msg, len, out);
        break;
    case HM_ALG_SHA256:
        hm_sha256(msg, len, out);
        break;
    case HM_ALG_MD5:
    default:
        hm_md5(msg, len, out);
        break;
    }
}

void hm_to_hex(const uint8_t *b, size_t n, char *s)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        s[2 * i] = h[b[i] >> 4];
        s[2 * i + 1] = h[b[i] & (size_t)0xf];
    }
    s[2 * n] = '\0';
}
