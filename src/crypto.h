/* hashmap - crypto backends (MD5 focus, SHA-1/SHA-256 for digest mode)
 *
 * MD5 core is a fully unrolled single-block transform - shared by digest
 * mode and the brute/map engines (midstate fast path).
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_CRYPTO_H
#define HM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    HM_ALG_MD5 = 0,
    HM_ALG_SHA1 = 1,
    HM_ALG_SHA256 = 2
} hm_algo_t;

/* --- md5 low-level --- */
extern const uint32_t HM_MD5_INIT[4];
void hm_md5_transform(uint32_t st[4], const uint8_t blk[64]);
void hm_md5(const uint8_t *msg, size_t len, uint8_t out[16]);

/* --- other algos (digest mode) --- */
void hm_sha1(const uint8_t *msg, size_t len, uint8_t out[20]);
void hm_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

/* --- generic dispatch --- */
const char *hm_algo_name(hm_algo_t alg);
int hm_algo_parse(const char *name, hm_algo_t *out);
size_t hm_algo_size(hm_algo_t alg);
void hm_hash(hm_algo_t alg, const uint8_t *msg, size_t len, uint8_t *out,
             size_t *olen);
void hm_to_hex(const uint8_t *b, size_t n, char *s);

#endif /* HM_CRYPTO_H */
