/* hashmap - exact multi-target digest lookup
 *
 * A digest query has to be compared against every -H/-F target, and a scan
 * costs one memcmp per target. hm_match replaces that with an open-addressing
 * index over the target digests: at most a couple of probes per query, with a
 * full-width byte comparison whenever a slot's hash agrees, so the answer is
 * always exact.
 *
 * The table keeps load at or below one half. Lookup probes until an empty
 * slot and compares full digests after a fingerprint match. Performance is
 * typically much better than a scan for many targets, but clustered keys can
 * require linear probing; no worst-case constant-time guarantee is made.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_MATCH_H
#define HM_MATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HM_MATCH_MAX_TARGETS 4096

/* geometry of the index (private; holds slot words, no target data) */
struct hm_match_slots;

typedef struct {
    /* the target digests, width bytes each, packed one after another */
    uint8_t (*digests)[32];
    /* caller data handed back with every hit (usually target pointers) */
    const void **user;
    unsigned n;     /* targets */
    unsigned width; /* compared bytes per digest (1..32) */
    struct hm_match_slots *slots; /* NULL => exhaustive scan */
} hm_match_t;

/* Build an index over n digests of width bytes (1..32). Returns 0 and fills
 * *m on success; on allocation failure returns -1 and leaves the matcher in
 * scan mode, which can only cost speed, never a match. */
int hm_match_build(hm_match_t *m, uint8_t (*digests)[32], const void **user,
                   unsigned n, unsigned width);

void hm_match_free(hm_match_t *m);

/* Every target index whose digest equals q. Returns the number of matches and
 * writes them to *hits (unspecified order, room for m->n entries). The
 * result is exact: never a digest that differs, never a missed target. */
unsigned hm_match(const hm_match_t *m, const uint8_t *q, unsigned *hits);

static inline bool hm_match_exact(const uint8_t *a, const uint8_t *b,
                                  unsigned width)
{
    return __builtin_memcmp(a, b, width) == 0;
}

/* one-line description of the index, for verbose output */
void hm_match_describe(const hm_match_t *m, char *buf, size_t len);

#endif /* HM_MATCH_H */
