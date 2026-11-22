/* hashmap - crypto backends implementation
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "crypto.h"

#include "cpu.h"

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

/* Four independent MD5 compressions in one pass. The four message chains do
 * not depend on each other, so the CPU can overlap their rounds; cracking
 * throughput improves roughly threefold on a modern core. The state and the
 * block are laid out per lane: st[lane][word], blk[lane][64]. */
#define HM_MD5_STEP4(f, A, B, C, D, j, s, k)                              \
    do {                                                                   \
        const uint32_t t4 = T[k];                                          \
        (A)[0] = HM_ROTL32((A)[0] + f((B)[0], (C)[0], (D)[0]) +          \
                               x[0][j] + t4, (s)) + (B)[0];               \
        (A)[1] = HM_ROTL32((A)[1] + f((B)[1], (C)[1], (D)[1]) +          \
                               x[1][j] + t4, (s)) + (B)[1];               \
        (A)[2] = HM_ROTL32((A)[2] + f((B)[2], (C)[2], (D)[2]) +          \
                               x[2][j] + t4, (s)) + (B)[2];               \
        (A)[3] = HM_ROTL32((A)[3] + f((B)[3], (C)[3], (D)[3]) +          \
                               x[3][j] + t4, (s)) + (B)[3];               \
    } while (0)

void hm_md5_transform4(uint32_t st[4][4], const uint8_t blk[4][64])
{
    uint32_t x[4][16];
    uint32_t a[4], b[4], c[4], d[4];

    for (int l = 0; l < 4; l++) {
        for (int i = 0; i < 16; i++) {
            const uint8_t *p = blk[l] + 4 * i;

            x[l][i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        }
        a[l] = st[l][0];
        b[l] = st[l][1];
        c[l] = st[l][2];
        d[l] = st[l][3];
    }

    HM_MD5_STEP4(HM_MDF, a, b, c, d, 0, 7, 0);
    HM_MD5_STEP4(HM_MDF, d, a, b, c, 1, 12, 1);
    HM_MD5_STEP4(HM_MDF, c, d, a, b, 2, 17, 2);
    HM_MD5_STEP4(HM_MDF, b, c, d, a, 3, 22, 3);
    HM_MD5_STEP4(HM_MDF, a, b, c, d, 4, 7, 4);
    HM_MD5_STEP4(HM_MDF, d, a, b, c, 5, 12, 5);
    HM_MD5_STEP4(HM_MDF, c, d, a, b, 6, 17, 6);
    HM_MD5_STEP4(HM_MDF, b, c, d, a, 7, 22, 7);
    HM_MD5_STEP4(HM_MDF, a, b, c, d, 8, 7, 8);
    HM_MD5_STEP4(HM_MDF, d, a, b, c, 9, 12, 9);
    HM_MD5_STEP4(HM_MDF, c, d, a, b, 10, 17, 10);
    HM_MD5_STEP4(HM_MDF, b, c, d, a, 11, 22, 11);
    HM_MD5_STEP4(HM_MDF, a, b, c, d, 12, 7, 12);
    HM_MD5_STEP4(HM_MDF, d, a, b, c, 13, 12, 13);
    HM_MD5_STEP4(HM_MDF, c, d, a, b, 14, 17, 14);
    HM_MD5_STEP4(HM_MDF, b, c, d, a, 15, 22, 15);
    HM_MD5_STEP4(HM_MDG, a, b, c, d, 1, 5, 16);
    HM_MD5_STEP4(HM_MDG, d, a, b, c, 6, 9, 17);
    HM_MD5_STEP4(HM_MDG, c, d, a, b, 11, 14, 18);
    HM_MD5_STEP4(HM_MDG, b, c, d, a, 0, 20, 19);
    HM_MD5_STEP4(HM_MDG, a, b, c, d, 5, 5, 20);
    HM_MD5_STEP4(HM_MDG, d, a, b, c, 10, 9, 21);
    HM_MD5_STEP4(HM_MDG, c, d, a, b, 15, 14, 22);
    HM_MD5_STEP4(HM_MDG, b, c, d, a, 4, 20, 23);
    HM_MD5_STEP4(HM_MDG, a, b, c, d, 9, 5, 24);
    HM_MD5_STEP4(HM_MDG, d, a, b, c, 14, 9, 25);
    HM_MD5_STEP4(HM_MDG, c, d, a, b, 3, 14, 26);
    HM_MD5_STEP4(HM_MDG, b, c, d, a, 8, 20, 27);
    HM_MD5_STEP4(HM_MDG, a, b, c, d, 13, 5, 28);
    HM_MD5_STEP4(HM_MDG, d, a, b, c, 2, 9, 29);
    HM_MD5_STEP4(HM_MDG, c, d, a, b, 7, 14, 30);
    HM_MD5_STEP4(HM_MDG, b, c, d, a, 12, 20, 31);
    HM_MD5_STEP4(HM_MDH, a, b, c, d, 5, 4, 32);
    HM_MD5_STEP4(HM_MDH, d, a, b, c, 8, 11, 33);
    HM_MD5_STEP4(HM_MDH, c, d, a, b, 11, 16, 34);
    HM_MD5_STEP4(HM_MDH, b, c, d, a, 14, 23, 35);
    HM_MD5_STEP4(HM_MDH, a, b, c, d, 1, 4, 36);
    HM_MD5_STEP4(HM_MDH, d, a, b, c, 4, 11, 37);
    HM_MD5_STEP4(HM_MDH, c, d, a, b, 7, 16, 38);
    HM_MD5_STEP4(HM_MDH, b, c, d, a, 10, 23, 39);
    HM_MD5_STEP4(HM_MDH, a, b, c, d, 13, 4, 40);
    HM_MD5_STEP4(HM_MDH, d, a, b, c, 0, 11, 41);
    HM_MD5_STEP4(HM_MDH, c, d, a, b, 3, 16, 42);
    HM_MD5_STEP4(HM_MDH, b, c, d, a, 6, 23, 43);
    HM_MD5_STEP4(HM_MDH, a, b, c, d, 9, 4, 44);
    HM_MD5_STEP4(HM_MDH, d, a, b, c, 12, 11, 45);
    HM_MD5_STEP4(HM_MDH, c, d, a, b, 15, 16, 46);
    HM_MD5_STEP4(HM_MDH, b, c, d, a, 2, 23, 47);
    HM_MD5_STEP4(HM_MDI, a, b, c, d, 0, 6, 48);
    HM_MD5_STEP4(HM_MDI, d, a, b, c, 7, 10, 49);
    HM_MD5_STEP4(HM_MDI, c, d, a, b, 14, 15, 50);
    HM_MD5_STEP4(HM_MDI, b, c, d, a, 5, 21, 51);
    HM_MD5_STEP4(HM_MDI, a, b, c, d, 12, 6, 52);
    HM_MD5_STEP4(HM_MDI, d, a, b, c, 3, 10, 53);
    HM_MD5_STEP4(HM_MDI, c, d, a, b, 10, 15, 54);
    HM_MD5_STEP4(HM_MDI, b, c, d, a, 1, 21, 55);
    HM_MD5_STEP4(HM_MDI, a, b, c, d, 8, 6, 56);
    HM_MD5_STEP4(HM_MDI, d, a, b, c, 15, 10, 57);
    HM_MD5_STEP4(HM_MDI, c, d, a, b, 6, 15, 58);
    HM_MD5_STEP4(HM_MDI, b, c, d, a, 13, 21, 59);
    HM_MD5_STEP4(HM_MDI, a, b, c, d, 4, 6, 60);
    HM_MD5_STEP4(HM_MDI, d, a, b, c, 11, 10, 61);
    HM_MD5_STEP4(HM_MDI, c, d, a, b, 2, 15, 62);
    HM_MD5_STEP4(HM_MDI, b, c, d, a, 9, 21, 63);

    for (int l = 0; l < 4; l++) {
        st[l][0] += a[l];
        st[l][1] += b[l];
        st[l][2] += c[l];
        st[l][3] += d[l];
    }
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

const uint32_t HM_SHA256_H0[8] = {
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


/* Four independent SHA-256 compressions in one pass (single block each).
 * st[lane][0..7], blk[lane][64]. Mirrors hm_md5_transform4 for cracking. */
void hm_sha256_transform4(uint32_t st[4][8], const uint8_t blk[4][64])
{
    uint32_t w[4][64];
    uint32_t a[4], b[4], c[4], d[4], e[4], f[4], g[4], hh[4];

    for (int l = 0; l < 4; l++) {
        for (int j = 0; j < 16; j++) {
            const uint8_t *p = blk[l] + 4 * j;
            w[l][j] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                      ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        }
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = ((w[l][j - 15] >> 7) | (w[l][j - 15] << 25)) ^
                          ((w[l][j - 15] >> 18) | (w[l][j - 15] << 14)) ^
                          (w[l][j - 15] >> 3);
            uint32_t s1 = ((w[l][j - 2] >> 17) | (w[l][j - 2] << 15)) ^
                          ((w[l][j - 2] >> 19) | (w[l][j - 2] << 13)) ^
                          (w[l][j - 2] >> 10);
            w[l][j] = w[l][j - 16] + s0 + w[l][j - 7] + s1;
        }
        a[l] = st[l][0]; b[l] = st[l][1]; c[l] = st[l][2]; d[l] = st[l][3];
        e[l] = st[l][4]; f[l] = st[l][5]; g[l] = st[l][6]; hh[l] = st[l][7];
    }

    for (int j = 0; j < 64; j++) {
        const uint32_t kj = SHA256_K[j];
        for (int l = 0; l < 4; l++) {
            uint32_t S1 = ((e[l] >> 6) | (e[l] << 26)) ^
                          ((e[l] >> 11) | (e[l] << 21)) ^
                          ((e[l] >> 25) | (e[l] << 7));
            uint32_t ch = (e[l] & f[l]) ^ (~e[l] & g[l]);
            uint32_t t1 = hh[l] + S1 + ch + kj + w[l][j];
            uint32_t S0 = ((a[l] >> 2) | (a[l] << 30)) ^
                          ((a[l] >> 13) | (a[l] << 19)) ^
                          ((a[l] >> 22) | (a[l] << 10));
            uint32_t mj = (a[l] & b[l]) ^ (a[l] & c[l]) ^ (b[l] & c[l]);
            uint32_t t2 = S0 + mj;
            hh[l] = g[l];
            g[l] = f[l];
            f[l] = e[l];
            e[l] = d[l] + t1;
            d[l] = c[l];
            c[l] = b[l];
            b[l] = a[l];
            a[l] = t1 + t2;
        }
    }

    for (int l = 0; l < 4; l++) {
        st[l][0] += a[l]; st[l][1] += b[l]; st[l][2] += c[l]; st[l][3] += d[l];
        st[l][4] += e[l]; st[l][5] += f[l]; st[l][6] += g[l]; st[l][7] += hh[l];
    }
}


/* ------------------------------------------------------------------ */
/* SIMD multi-lane compression (x86-64, AVX2, runtime dispatched)      */
/* ------------------------------------------------------------------ */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__linux__) || defined(__APPLE__))

#define HM_HAVE_AVX2_LANES 1

/* Four 32-bit lanes per vector: lanes 0..3 of one ymm register are the four
 * independent candidate chains. These two files use only GCC/Clang vector
 * extensions, and every function is compiled with the avx2 target attribute,
 * so the rest of the binary can still be built for any baseline. */

#define HM_LANE_V __attribute__((vector_size(32)))
typedef uint32_t hm_v8 HM_LANE_V;

__attribute__((target("avx2")))
static hm_v8 hm_v_t(uint32_t x)
{
    hm_v8 r;
    r[0] = x; r[1] = x; r[2] = x; r[3] = x;
    r[4] = x; r[5] = x; r[6] = x; r[7] = x;
    return r;
}

__attribute__((target("avx2"), always_inline)) static inline
hm_v8 hm_v_load8(const uint32_t *p)
{
    hm_v8 r;
    __builtin_memcpy(&r, p, sizeof(r));
    return r;
}

__attribute__((target("avx2"), always_inline)) static inline
void hm_v_store8(uint32_t *p, hm_v8 v)
{
    __builtin_memcpy(p, &v, sizeof(v));
}

/* the MD5 rotation amount of round step j (RFC 1321 schedule) */
static unsigned hm_md5_shift(int j)
{
    static const unsigned sh[4][4] = {{7u, 12u, 17u, 22u},
                                      {5u, 9u, 14u, 20u},
                                      {4u, 11u, 16u, 23u},
                                      {6u, 10u, 15u, 21u}};

    return sh[(unsigned)j >> 4][(unsigned)j & 3u];
}

/* MD5: eight independent single-block compressions at once. Faster than the
 * four-way scalar path above by roughly 1.8x on a core with AVX2 (measured:
 * 36.8 -> 42.7 M md5/s in research/engine_bench), and the four-way scalar
 * path remains for machines without AVX2. */
__attribute__((target("avx2")))
static void hm_simd_md5_8(uint32_t st[8][4], const uint8_t blk[8][64])
{
    hm_v8 x[16];
    hm_v8 a, b, c, d, a0, b0, c0, d0;

    for (int i = 0; i < 16; i++) {
        uint32_t lane[8];

        for (int l = 0; l < 8; l++) {
            const uint8_t *p = blk[l] + 4 * i;

            lane[l] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        }
        x[i] = hm_v_load8(lane);
    }
    {
        uint32_t la[8], lb[8], lc[8], ld[8];

        for (int l = 0; l < 8; l++) {
            la[l] = st[l][0];
            lb[l] = st[l][1];
            lc[l] = st[l][2];
            ld[l] = st[l][3];
        }
        a = a0 = hm_v_load8(la);
        b = b0 = hm_v_load8(lb);
        c = c0 = hm_v_load8(lc);
        d = d0 = hm_v_load8(ld);
    }
    for (int j = 0; j < 64; j++) {
        hm_v8 f;
        hm_v8 m;
        hm_v8 t;
        unsigned idx;
        unsigned s;
        const unsigned r = (unsigned)j >> 4;

        if (r == 0) {
            f = d ^ (b & (c ^ d));
            idx = (unsigned)j;
        } else if (r == 1) {
            f = c ^ (d & (b ^ c));
            idx = (5u * (unsigned)j + 1u) & 15u;
        } else if (r == 2) {
            f = b ^ c ^ d;
            idx = (3u * (unsigned)j + 5u) & 15u;
        } else {
            f = c ^ (b | ~d);
            idx = (7u * (unsigned)j) & 15u;
        }
        m = x[idx];
        t = a + f + m + hm_v_t(T[j]);
        s = hm_md5_shift(j);
        a = d;
        d = c;
        c = b;
        b = b + ((t << s) | (t >> (32u - s)));
    }
    {
        uint32_t la[8], lb[8], lc[8], ld[8];

        hm_v_store8(la, a0 + a);
        hm_v_store8(lb, b0 + b);
        hm_v_store8(lc, c0 + c);
        hm_v_store8(ld, d0 + d);
        for (int l = 0; l < 8; l++) {
            st[l][0] = la[l];
            st[l][1] = lb[l];
            st[l][2] = lc[l];
            st[l][3] = ld[l];
        }
    }
}

/* SHA-256: eight independent single-block compressions at once. The scalar
 * four-way path measured 2.65 M/s; this one 26.5 M/s (10x) because the
 * message schedule of each lane is vectorised as well. */
__attribute__((target("avx2")))
static void hm_simd_sha256_8(uint32_t st[8][8], const uint8_t blk[8][64])
{
    hm_v8 w[64];
    hm_v8 a, b, c, d, e, f, g, h;
    uint32_t lane[8];

    for (int i = 0; i < 16; i++) {
        for (int l = 0; l < 8; l++) {
            const uint8_t *p = blk[l] + 4 * i;

            lane[l] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                      ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        }
        w[i] = hm_v_load8(lane);
    }
    for (int j = 16; j < 64; j++) {
        hm_v8 x15 = w[j - 15];
        hm_v8 x2 = w[j - 2];
        hm_v8 s0 = ((x15 >> 7) | (x15 << 25)) ^
                   ((x15 >> 18) | (x15 << 14)) ^ (x15 >> 3);
        hm_v8 s1 = ((x2 >> 17) | (x2 << 15)) ^
                   ((x2 >> 19) | (x2 << 13)) ^ (x2 >> 10);

        w[j] = w[j - 16] + s0 + w[j - 7] + s1;
    }
#define HM_LOAD_ST(i, dst)                                            \
    do {                                                              \
        for (int l = 0; l < 8; l++)                                   \
            lane[l] = st[l][(i)];                                     \
        (dst) = hm_v_load8(lane);                                     \
    } while (0)
    HM_LOAD_ST(0, a);
    HM_LOAD_ST(1, b);
    HM_LOAD_ST(2, c);
    HM_LOAD_ST(3, d);
    HM_LOAD_ST(4, e);
    HM_LOAD_ST(5, f);
    HM_LOAD_ST(6, g);
    HM_LOAD_ST(7, h);
#undef HM_LOAD_ST
    for (int j = 0; j < 64; j++) {
        hm_v8 S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                   ((e >> 25) | (e << 7));
        hm_v8 ch = (e & f) ^ (~e & g);
        hm_v8 t1 = h + S1 + ch + hm_v_t(SHA256_K[j]) + w[j];
        hm_v8 S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
                   ((a >> 22) | (a << 10));
        hm_v8 mj = (a & b) ^ (a & c) ^ (b & c);
        hm_v8 t2 = S0 + mj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    {
        hm_v8 v[8];

        v[0] = a; v[1] = b; v[2] = c; v[3] = d;
        v[4] = e; v[5] = f; v[6] = g; v[7] = h;
        for (int i = 0; i < 8; i++) {
            hm_v_store8(lane, v[i]);
            for (int l = 0; l < 8; l++)
                st[l][i] += lane[l];
        }
    }
}


/* ------------------------------------------------------------------ */
/* AVX-512: sixteen lanes per round (runtime dispatched)                */
/* ------------------------------------------------------------------ */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__linux__) || defined(__APPLE__))

#define HM_HAVE_AVX512_LANES 1

/* Same structure as the eight-lane kernel, one zmm register per state word,
 * sixteen independent candidate chains per compression round. Only the
 * integer subset of AVX-512 is used (no rotations, no mask registers), so
 * any CPU with avx512f can run it. */
typedef uint32_t hm_v16 __attribute__((vector_size(64)));

__attribute__((target("avx512f"), always_inline)) static inline
hm_v16 hm_v16_t(uint32_t x)
{
    hm_v16 r;

    for (int i = 0; i < 16; i++)
        r[i] = x;
    return r;
}

/* MD5 round step over sixteen lanes. j, idx and ss are literals at every
 * call site, so the T[j] broadcast and the shift amount are compile-time
 * constants; the 64 steps below are unrolled for the same reason the scalar
 * core is (GCC keeps a rolled loop version out of line and re-materialises
 * the constant vector on each iteration). */
#define HM_MD5_S16(j, fexpr, idx, ss)                                    \
    do {                                                                 \
        const hm_v16 f = (fexpr);                                        \
        const hm_v16 t = a + f + x[(idx)] + hm_v16_t(T[(j)]);            \
                                                                         \
        a = d;                                                           \
        d = c;                                                           \
        c = b;                                                           \
        b = b + ((t << (ss)) | (t >> (32u - (ss))));                     \
    } while (0)

__attribute__((target("avx512f")))
static void hm_simd_md5_16_body(hm_v16 x[16], uint32_t st[16][4])
{
    hm_v16 a, b, c, d, a0, b0, c0, d0;
    uint32_t lane[16];

    for (int l = 0; l < 16; l++) {
        lane[l] = st[l][0];
    }
    __builtin_memcpy(&a, lane, sizeof(a));
    for (int l = 0; l < 16; l++) {
        lane[l] = st[l][1];
    }
    __builtin_memcpy(&b, lane, sizeof(b));
    for (int l = 0; l < 16; l++) {
        lane[l] = st[l][2];
    }
    __builtin_memcpy(&c, lane, sizeof(c));
    for (int l = 0; l < 16; l++) {
        lane[l] = st[l][3];
    }
    __builtin_memcpy(&d, lane, sizeof(d));
    a0 = a; b0 = b; c0 = c; d0 = d;
    HM_MD5_S16(0, d ^ (b & (c ^ d)), 0, 7u);
    HM_MD5_S16(1, d ^ (b & (c ^ d)), 1, 12u);
    HM_MD5_S16(2, d ^ (b & (c ^ d)), 2, 17u);
    HM_MD5_S16(3, d ^ (b & (c ^ d)), 3, 22u);
    HM_MD5_S16(4, d ^ (b & (c ^ d)), 4, 7u);
    HM_MD5_S16(5, d ^ (b & (c ^ d)), 5, 12u);
    HM_MD5_S16(6, d ^ (b & (c ^ d)), 6, 17u);
    HM_MD5_S16(7, d ^ (b & (c ^ d)), 7, 22u);
    HM_MD5_S16(8, d ^ (b & (c ^ d)), 8, 7u);
    HM_MD5_S16(9, d ^ (b & (c ^ d)), 9, 12u);
    HM_MD5_S16(10, d ^ (b & (c ^ d)), 10, 17u);
    HM_MD5_S16(11, d ^ (b & (c ^ d)), 11, 22u);
    HM_MD5_S16(12, d ^ (b & (c ^ d)), 12, 7u);
    HM_MD5_S16(13, d ^ (b & (c ^ d)), 13, 12u);
    HM_MD5_S16(14, d ^ (b & (c ^ d)), 14, 17u);
    HM_MD5_S16(15, d ^ (b & (c ^ d)), 15, 22u);
    HM_MD5_S16(16, c ^ (d & (b ^ c)), 1, 5u);
    HM_MD5_S16(17, c ^ (d & (b ^ c)), 6, 9u);
    HM_MD5_S16(18, c ^ (d & (b ^ c)), 11, 14u);
    HM_MD5_S16(19, c ^ (d & (b ^ c)), 0, 20u);
    HM_MD5_S16(20, c ^ (d & (b ^ c)), 5, 5u);
    HM_MD5_S16(21, c ^ (d & (b ^ c)), 10, 9u);
    HM_MD5_S16(22, c ^ (d & (b ^ c)), 15, 14u);
    HM_MD5_S16(23, c ^ (d & (b ^ c)), 4, 20u);
    HM_MD5_S16(24, c ^ (d & (b ^ c)), 9, 5u);
    HM_MD5_S16(25, c ^ (d & (b ^ c)), 14, 9u);
    HM_MD5_S16(26, c ^ (d & (b ^ c)), 3, 14u);
    HM_MD5_S16(27, c ^ (d & (b ^ c)), 8, 20u);
    HM_MD5_S16(28, c ^ (d & (b ^ c)), 13, 5u);
    HM_MD5_S16(29, c ^ (d & (b ^ c)), 2, 9u);
    HM_MD5_S16(30, c ^ (d & (b ^ c)), 7, 14u);
    HM_MD5_S16(31, c ^ (d & (b ^ c)), 12, 20u);
    HM_MD5_S16(32, b ^ c ^ d, 5, 4u);
    HM_MD5_S16(33, b ^ c ^ d, 8, 11u);
    HM_MD5_S16(34, b ^ c ^ d, 11, 16u);
    HM_MD5_S16(35, b ^ c ^ d, 14, 23u);
    HM_MD5_S16(36, b ^ c ^ d, 1, 4u);
    HM_MD5_S16(37, b ^ c ^ d, 4, 11u);
    HM_MD5_S16(38, b ^ c ^ d, 7, 16u);
    HM_MD5_S16(39, b ^ c ^ d, 10, 23u);
    HM_MD5_S16(40, b ^ c ^ d, 13, 4u);
    HM_MD5_S16(41, b ^ c ^ d, 0, 11u);
    HM_MD5_S16(42, b ^ c ^ d, 3, 16u);
    HM_MD5_S16(43, b ^ c ^ d, 6, 23u);
    HM_MD5_S16(44, b ^ c ^ d, 9, 4u);
    HM_MD5_S16(45, b ^ c ^ d, 12, 11u);
    HM_MD5_S16(46, b ^ c ^ d, 15, 16u);
    HM_MD5_S16(47, b ^ c ^ d, 2, 23u);
    HM_MD5_S16(48, c ^ (b | ~d), 0, 6u);
    HM_MD5_S16(49, c ^ (b | ~d), 7, 10u);
    HM_MD5_S16(50, c ^ (b | ~d), 14, 15u);
    HM_MD5_S16(51, c ^ (b | ~d), 5, 21u);
    HM_MD5_S16(52, c ^ (b | ~d), 12, 6u);
    HM_MD5_S16(53, c ^ (b | ~d), 3, 10u);
    HM_MD5_S16(54, c ^ (b | ~d), 10, 15u);
    HM_MD5_S16(55, c ^ (b | ~d), 1, 21u);
    HM_MD5_S16(56, c ^ (b | ~d), 8, 6u);
    HM_MD5_S16(57, c ^ (b | ~d), 15, 10u);
    HM_MD5_S16(58, c ^ (b | ~d), 6, 15u);
    HM_MD5_S16(59, c ^ (b | ~d), 13, 21u);
    HM_MD5_S16(60, c ^ (b | ~d), 4, 6u);
    HM_MD5_S16(61, c ^ (b | ~d), 11, 10u);
    HM_MD5_S16(62, c ^ (b | ~d), 2, 15u);
    HM_MD5_S16(63, c ^ (b | ~d), 9, 21u);

    {
        const hm_v16 ra = a0 + a;
        const hm_v16 rb = b0 + b;
        const hm_v16 rc = c0 + c;
        const hm_v16 rd = d0 + d;

        __builtin_memcpy(lane, &ra, sizeof(ra));
        for (int l = 0; l < 16; l++) {
            st[l][0] = lane[l];
        }
        __builtin_memcpy(lane, &rb, sizeof(rb));
        for (int l = 0; l < 16; l++) {
            st[l][1] = lane[l];
        }
        __builtin_memcpy(lane, &rc, sizeof(rc));
        for (int l = 0; l < 16; l++) {
            st[l][2] = lane[l];
        }
        __builtin_memcpy(lane, &rd, sizeof(rd));
        for (int l = 0; l < 16; l++) {
            st[l][3] = lane[l];
        }
    }
}

__attribute__((target("avx512f")))
static void hm_simd_md5_16(uint32_t st[16][4], const uint8_t blk[16][64])
{
    hm_v16 x[16];

    for (int i = 0; i < 16; i++) {
        uint32_t lane[16];

        for (int l = 0; l < 16; l++) {
            const uint8_t *p = blk[l] + 4 * i;

            lane[l] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        }
        __builtin_memcpy(&x[i], lane, sizeof(x[i]));
    }
    hm_simd_md5_16_body(x, st);
}

#undef HM_MD5_S16

/* SHA-256 round step over sixteen lanes; the K constant is a literal at
 * every call site, so no constant vector is reloaded (see HM_MD5_S16). */
#define HM_SHA_S16(j, K)                                                  \
    do {                                                                  \
        hm_v16 S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^    \
                    ((e >> 25) | (e << 7));                               \
        hm_v16 ch = (e & f) ^ (~e & g);                                   \
        hm_v16 t1 = h + S1 + ch + hm_v16_t(0x##K##u) + w[(j)];            \
        hm_v16 S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^    \
                    ((a >> 22) | (a << 10));                              \
        hm_v16 mj = (a & b) ^ (a & c) ^ (b & c);                          \
        hm_v16 t2 = S0 + mj;                                              \
                                                                          \
        h = g;                                                            \
        g = f;                                                            \
        f = e;                                                            \
        e = d + t1;                                                       \
        d = c;                                                            \
        c = b;                                                            \
        b = a;                                                            \
        a = t1 + t2;                                                      \
    } while (0)

__attribute__((target("avx512f")))
static void hm_simd_sha256_16_body(hm_v16 w[64], uint32_t st[16][8])
{
    hm_v16 a, b, c, d, e, f, g, h;
    uint32_t lane[16];

#define HM_LOAD_ST16(i, dst)                                          \
    do {                                                              \
        for (int l = 0; l < 16; l++)                                  \
            lane[l] = st[l][(i)];                                     \
        __builtin_memcpy(&(dst), lane, sizeof(dst));                   \
    } while (0)
    HM_LOAD_ST16(0, a);
    HM_LOAD_ST16(1, b);
    HM_LOAD_ST16(2, c);
    HM_LOAD_ST16(3, d);
    HM_LOAD_ST16(4, e);
    HM_LOAD_ST16(5, f);
    HM_LOAD_ST16(6, g);
    HM_LOAD_ST16(7, h);
#undef HM_LOAD_ST16
    HM_SHA_S16(0, 428a2f98);
    HM_SHA_S16(1, 71374491);
    HM_SHA_S16(2, b5c0fbcf);
    HM_SHA_S16(3, e9b5dba5);
    HM_SHA_S16(4, 3956c25b);
    HM_SHA_S16(5, 59f111f1);
    HM_SHA_S16(6, 923f82a4);
    HM_SHA_S16(7, ab1c5ed5);
    HM_SHA_S16(8, d807aa98);
    HM_SHA_S16(9, 12835b01);
    HM_SHA_S16(10, 243185be);
    HM_SHA_S16(11, 550c7dc3);
    HM_SHA_S16(12, 72be5d74);
    HM_SHA_S16(13, 80deb1fe);
    HM_SHA_S16(14, 9bdc06a7);
    HM_SHA_S16(15, c19bf174);
    HM_SHA_S16(16, e49b69c1);
    HM_SHA_S16(17, efbe4786);
    HM_SHA_S16(18, 0fc19dc6);
    HM_SHA_S16(19, 240ca1cc);
    HM_SHA_S16(20, 2de92c6f);
    HM_SHA_S16(21, 4a7484aa);
    HM_SHA_S16(22, 5cb0a9dc);
    HM_SHA_S16(23, 76f988da);
    HM_SHA_S16(24, 983e5152);
    HM_SHA_S16(25, a831c66d);
    HM_SHA_S16(26, b00327c8);
    HM_SHA_S16(27, bf597fc7);
    HM_SHA_S16(28, c6e00bf3);
    HM_SHA_S16(29, d5a79147);
    HM_SHA_S16(30, 06ca6351);
    HM_SHA_S16(31, 14292967);
    HM_SHA_S16(32, 27b70a85);
    HM_SHA_S16(33, 2e1b2138);
    HM_SHA_S16(34, 4d2c6dfc);
    HM_SHA_S16(35, 53380d13);
    HM_SHA_S16(36, 650a7354);
    HM_SHA_S16(37, 766a0abb);
    HM_SHA_S16(38, 81c2c92e);
    HM_SHA_S16(39, 92722c85);
    HM_SHA_S16(40, a2bfe8a1);
    HM_SHA_S16(41, a81a664b);
    HM_SHA_S16(42, c24b8b70);
    HM_SHA_S16(43, c76c51a3);
    HM_SHA_S16(44, d192e819);
    HM_SHA_S16(45, d6990624);
    HM_SHA_S16(46, f40e3585);
    HM_SHA_S16(47, 106aa070);
    HM_SHA_S16(48, 19a4c116);
    HM_SHA_S16(49, 1e376c08);
    HM_SHA_S16(50, 2748774c);
    HM_SHA_S16(51, 34b0bcb5);
    HM_SHA_S16(52, 391c0cb3);
    HM_SHA_S16(53, 4ed8aa4a);
    HM_SHA_S16(54, 5b9cca4f);
    HM_SHA_S16(55, 682e6ff3);
    HM_SHA_S16(56, 748f82ee);
    HM_SHA_S16(57, 78a5636f);
    HM_SHA_S16(58, 84c87814);
    HM_SHA_S16(59, 8cc70208);
    HM_SHA_S16(60, 90befffa);
    HM_SHA_S16(61, a4506ceb);
    HM_SHA_S16(62, bef9a3f7);
    HM_SHA_S16(63, c67178f2);

    {
        hm_v16 v[8];

        v[0] = a;
        v[1] = b;
        v[2] = c;
        v[3] = d;
        v[4] = e;
        v[5] = f;
        v[6] = g;
        v[7] = h;
        for (int i = 0; i < 8; i++) {
            __builtin_memcpy(lane, &v[i], sizeof(v[i]));
            for (int l = 0; l < 16; l++)
                st[l][i] += lane[l];
        }
    }
}

#undef HM_SHA_S16

__attribute__((target("avx512f")))
static void hm_simd_sha256_16(uint32_t st[16][8], const uint8_t blk[16][64])
{
    hm_v16 w[64];
    uint32_t lane[16];

    for (int i = 0; i < 16; i++) {
        for (int l = 0; l < 16; l++) {
            const uint8_t *p = blk[l] + 4 * i;

            lane[l] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                      ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        }
        __builtin_memcpy(&w[i], lane, sizeof(w[i]));
    }
    for (int j = 16; j < 64; j++) {
        hm_v16 x15 = w[j - 15];
        hm_v16 x2 = w[j - 2];
        hm_v16 s0 = ((x15 >> 7) | (x15 << 25)) ^
                   ((x15 >> 18) | (x15 << 14)) ^ (x15 >> 3);
        hm_v16 s1 = ((x2 >> 17) | (x2 << 15)) ^
                   ((x2 >> 19) | (x2 << 13)) ^ (x2 >> 10);

        w[j] = w[j - 16] + s0 + w[j - 7] + s1;
    }
    hm_simd_sha256_16_body(w, st);
}

/* the shared runtime detector decides all dispatch (see cpu.c); this keeps
 * the widest-kernel question in one place instead of two private caches */
static int hm_cpu_avx512(bool sha256)
{
    return hm_cpu_wide_for(sha256) ? 1 : 0;
}
#endif /* AVX-512 lanes */
#endif /* x86-64 SIMD */

/* Sixteen independent MD5 compressions; falls back to two eight-lane (and
 * then four-lane) batches on a CPU without AVX-512. Either way all sixteen
 * lanes are consumed, so the caller can batch sixteen candidates on any
 * machine. The sixteen-lane kernel runs at ~76 M md5/s per core on a
 * 2.6 GHz Xeon versus ~30 M for the eight-lane one. */
void hm_md5_transform16x(uint32_t st[16][4], const uint8_t blk[16][64])
{
#if defined(HM_HAVE_AVX512_LANES)
    if (hm_cpu_avx512(false)) {
        hm_simd_md5_16(st, blk);
        return;
    }
#endif
    hm_md5_transform8x(st, blk);
    hm_md5_transform8x(st + 8, blk + 8);
}

void hm_sha256_transform16x(uint32_t st[16][8], const uint8_t blk[16][64])
{
#if defined(HM_HAVE_AVX512_LANES)
    if (hm_cpu_avx512(true)) {
        hm_simd_sha256_16(st, blk);
        return;
    }
#endif
    hm_sha256_transform8x(st, blk);
    hm_sha256_transform8x(st + 8, blk + 8);
}

/* One runtime check, then the batched transforms below use the widest path
 * the CPU actually supports. */
#if defined(HM_HAVE_AVX2_LANES)
static int hm_cpu_avx2(void)
{
    return (hm_cpu()->avx2 && hm_cpu_has_vector(256)) ? 1 : 0;
}
#endif /* HM_HAVE_AVX2_LANES */

/* Eight independent MD5 compressions; falls back to two four-way batches. */
void hm_md5_transform8x(uint32_t st[8][4], const uint8_t blk[8][64])
{
#if defined(HM_HAVE_AVX2_LANES)
    if (hm_cpu_avx2()) {
        hm_simd_md5_8(st, blk);
        return;
    }
#endif
    hm_md5_transform4(st, blk);
    hm_md5_transform4(st + 4, blk + 4);
}

/* Eight independent SHA-256 compressions; falls back to two four-way
 * batches. */
void hm_sha256_transform8x(uint32_t st[8][8], const uint8_t blk[8][64])
{
#if defined(HM_HAVE_AVX2_LANES)
    if (hm_cpu_avx2()) {
        hm_simd_sha256_8(st, blk);
        return;
    }
#endif
    hm_sha256_transform4(st, blk);
    hm_sha256_transform4(st + 4, blk + 4);
}

void hm_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t h[8];

    memcpy(h, HM_SHA256_H0, sizeof(h));

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

void hm_sha256_init(hm_sha256_ctx *c)
{
    memcpy(c->h, HM_SHA256_H0, sizeof(c->h));
    c->used = 0;
    c->total = 0;
}

void hm_sha256_update(hm_sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = data;

    c->total += (uint64_t)len;
    if (c->used != 0) {
        size_t want = 64 - c->used;
        size_t take = len < want ? len : want;

        memcpy(c->buf + c->used, p, take);
        c->used += take;
        p += take;
        len -= take;
        if (c->used == 64) {
            sha256_blocks(c->h, SHA256_K, c->buf, 1);
            c->used = 0;
        }
    }
    while (len >= 64) {
        sha256_blocks(c->h, SHA256_K, p, 1);
        p += 64;
        len -= 64;
    }
    if (len != 0) {
        memcpy(c->buf, p, len);
        c->used = len;
    }
}

void hm_sha256_final(hm_sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->total * 8;

    c->buf[c->used++] = 0x80;
    if (c->used > 56) {
        memset(c->buf + c->used, 0, 64 - c->used);
        sha256_blocks(c->h, SHA256_K, c->buf, 1);
        c->used = 0;
    }
    memset(c->buf + c->used, 0, 56 - c->used);
    for (size_t j = 0; j < 8; j++)
        c->buf[56 + j] = (uint8_t)(bits >> (56 - 8 * j));
    sha256_blocks(c->h, SHA256_K, c->buf, 1);

    for (size_t j = 0; j < 8; j++) {
        out[4 * j] = (uint8_t)(c->h[j] >> 24);
        out[4 * j + 1] = (uint8_t)(c->h[j] >> 16);
        out[4 * j + 2] = (uint8_t)(c->h[j] >> 8);
        out[4 * j + 3] = (uint8_t)(c->h[j]);
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
