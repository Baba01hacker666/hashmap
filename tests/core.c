/* Differential tests for batched compression and multi-target lookup. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "match.h"

static uint32_t seed = 0x12345678u;
static uint32_t rnd(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

static int test_kernels(void)
{
    for (int iteration = 0; iteration < 100; iteration++) {
        uint8_t block[16][64];
        uint32_t md[16][4], mdref[16][4];
        uint32_t sh[16][8], shref[16][8];
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 64; j++) block[i][j] = (uint8_t)rnd();
            for (int j = 0; j < 4; j++) md[i][j] = rnd();
            for (int j = 0; j < 8; j++) sh[i][j] = rnd();
        }
        memcpy(mdref, md, sizeof(md));
        memcpy(shref, sh, sizeof(sh));
        for (int i = 0; i < 16; i += 4) {
            hm_md5_transform4(mdref + i, (const uint8_t (*)[64])(const void *)(block + i));
            hm_sha256_transform4(shref + i, (const uint8_t (*)[64])(const void *)(block + i));
        }
        hm_md5_transform16x(md, (const uint8_t (*)[64])(const void *)block);
        hm_sha256_transform16x(sh, (const uint8_t (*)[64])(const void *)block);
        if (memcmp(md, mdref, sizeof(md)) || memcmp(sh, shref, sizeof(sh)))
            return 1;
    }
    return 0;
}

static int test_matcher(void)
{
    enum { N = 300 };
    uint8_t keys[N][32];
    const void *users[N];
    unsigned hits[N];
    for (unsigned width = 1; width <= 32; width++) {
        hm_match_t m;
        for (unsigned i = 0; i < N; i++) {
            for (unsigned j = 0; j < 32; j++) keys[i][j] = (uint8_t)rnd();
            users[i] = NULL;
        }
        memcpy(keys[7], keys[3], 32);
        if (hm_match_build(&m, keys, users, N, width) != 0) return 1;
        for (unsigned i = 0; i < N + 100; i++) {
            uint8_t query[32];
            unsigned expected = 0;
            unsigned char seen[N];
            memset(seen, 0, sizeof(seen));
            if (i < N) memcpy(query, keys[i], 32);
            else for (unsigned j = 0; j < 32; j++) query[j] = (uint8_t)rnd();
            unsigned count = hm_match(&m, query, hits);
            for (unsigned k = 0; k < count; k++) {
                if (hits[k] >= N || seen[hits[k]] || memcmp(keys[hits[k]], query, width)) {
                    hm_match_free(&m); return 1;
                }
                seen[hits[k]] = 1;
            }
            for (unsigned k = 0; k < N; k++) {
                if (!memcmp(keys[k], query, width)) {
                    expected++;
                    if (!seen[k]) { hm_match_free(&m); return 1; }
                }
            }
            if (count != expected) { hm_match_free(&m); return 1; }
        }
        hm_match_free(&m);
    }
    return 0;
}

int main(void)
{
    if (test_kernels()) { fputs("FAIL batched kernels\n", stderr); return 1; }
    if (test_matcher()) { fputs("FAIL matcher\n", stderr); return 1; }
    puts("PASS differential batched kernels and matcher");
    return 0;
}
