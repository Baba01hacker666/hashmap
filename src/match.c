/* hashmap - exact multi-target digest lookup (see match.h)
 *
 * The deletion-free table uses open addressing and linear probing, with
 * fingerprints followed by full digest comparisons. Duplicate digests are
 * stored separately and all matching target indices are returned.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "match.h"

struct hm_match_slots {
    uint32_t *hash; /* fingerprint, 0 = empty slot */
    uint32_t *index; /* target index + 1 */
    size_t size;     /* power of two, >= 2n */
};

/* 64-bit finalizer (MurmurHash3 mix): a bijection on 64-bit words */
static uint64_t hm_mix64(uint64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

/* the two hashes of one digest: slot start and fingerprint */
static void hm_hash_pair(const uint8_t *p, unsigned width, uint64_t *slot,
                         uint32_t *fp)
{
    uint64_t h = 0x9e3779b97f4a7c15ULL;
    uint64_t rem = 0;
    unsigned i = 0;

    /* fold the digest in 8-byte chunks; the tail is folded bytewise so any
     * width 1..32 is handled without reading past the digest */
    while (i + 8 <= width) {
        uint64_t w;

        memcpy(&w, p + i, 8);
        h = hm_mix64(h ^ w);
        i += 8;
    }
    for (unsigned j = 0; i < width; i++, j++)
        rem |= (uint64_t)p[i] << (8 * j);

    /* Mix again for a fingerprint to reduce full comparisons inside a
     * probe cluster. Exact equality never depends on the fingerprint alone. */
    h = hm_mix64(h ^ rem ^ ((uint64_t)width << 56));
    *slot = h;
    *fp = (uint32_t)(hm_mix64(h ^ 0x27d4eb2f165667c5ULL) >> 24) | 1u;
}

int hm_match_build(hm_match_t *m, uint8_t (*digests)[32], const void **user,
                   unsigned n, unsigned width)
{
    size_t size = 4;

    memset(m, 0, sizeof(*m));
    m->digests = digests;
    m->user = user;
    m->n = n;
    m->width = width;
    if (n == 0 || width == 0 || width > 32)
        return -1;

    /* load factor at most 1/2, rounded up to a power of two */
    while (size < (size_t)n * 2u)
        size <<= 1;

    m->slots = calloc(1, sizeof(*m->slots));
    if (m->slots == NULL)
        return -1;
    m->slots->size = size;
    m->slots->hash = calloc(size, sizeof(uint32_t));
    m->slots->index = calloc(size, sizeof(uint32_t));
    if (m->slots->hash == NULL || m->slots->index == NULL) {
        free(m->slots->hash);
        free(m->slots->index);
        free(m->slots);
        m->slots = NULL;
        return -1;
    }

    for (unsigned t = 0; t < n; t++) {
        uint64_t h;
        uint32_t fp;
        size_t p;

        hm_hash_pair(m->digests[t], width, &h, &fp);
        p = (size_t)h & (size - 1u);
        /* a target whose start slot is taken continues along the same probe
         * sequence as every query of that digest, so insertion and lookup
         * always meet */
        while (m->slots->hash[p] != 0)
            p = (p + 1u) & (size - 1u);
        m->slots->hash[p] = fp;
        m->slots->index[p] = t + 1u;
    }
    return 0;
}

void hm_match_free(hm_match_t *m)
{
    if (m == NULL || m->slots == NULL)
        return;
    free(m->slots->hash);
    free(m->slots->index);
    free(m->slots);
    m->slots = NULL;
}

static unsigned hm_scan(const hm_match_t *m, const uint8_t *q, unsigned *hits)
{
    unsigned found = 0;

    for (unsigned t = 0; t < m->n; t++) {
        if (hm_match_exact(m->digests[t], q, m->width))
            hits[found++] = t;
    }
    return found;
}

unsigned hm_match(const hm_match_t *m, const uint8_t *q, unsigned *hits)
{
    const struct hm_match_slots *s = m->slots;
    uint64_t h;
    uint32_t fp;
    size_t p;
    unsigned found = 0;

    if (s == NULL)
        return hm_scan(m, q, hits);

    hm_hash_pair(q, m->width, &h, &fp);
    p = (size_t)h & (s->size - 1u);
    for (;;) {
        uint32_t stored = s->hash[p];

        if (stored == 0)
            break; /* the probe sequence of this digest ends here */
        if (stored == fp) {
            unsigned t = s->index[p] - 1u;

            /* the fingerprint only narrows the candidates; equality is
             * decided on the full stored digest */
            if (t < m->n && hm_match_exact(m->digests[t], q, m->width))
                hits[found++] = t;
        }
        p = (p + 1u) & (s->size - 1u);
    }
    return found;
}

void hm_match_describe(const hm_match_t *m, char *buf, size_t len)
{
    if (m->slots == NULL) {
        snprintf(buf, len, "linear scan (%u targets)", m->n);
        return;
    }
    snprintf(buf, len, "%u slots for %u targets (load %.2f)", (unsigned)m->slots->size,
             m->n, m->slots->size != 0
                         ? (double)m->n / (double)m->slots->size
                         : 0.0);
}
