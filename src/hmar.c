/* hashmap - streaming decoder for HMARCH1/HMARCH2 map archives
 *
 * An archive stores the original HMMAP header, groups of rows coded with the
 * map-archive codecs (predicted digests, ranked exceptions, prefix strings,
 * RSM1 field lanes) and a SHA-256 over the original file. This decoder walks
 * the groups without creating a restored file, so `search` can scan a .hmar
 * directly.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "hashmap.h"
#include "hmar.h"

#define HM_HMAR_GROUP 1024
#define HM_HMAR_BLOCK 64
#define HM_HMAR_KEY_STRIDE 256
#define HM_HMAR_MAX_TOKENS 96
#define HM_HMAR_MAX_TOKEN 24
#define HM_HMAR_MAX_SYMBOLS (256 + HM_HMAR_MAX_TOKENS)
#define HM_HMAR_HDR 192

#define HM_HMAR_MAGIC1 "HMARCH1\n"
#define HM_HMAR_MAGIC2 "HMARCH2\n"
#define HM_HMAR_MAGIC_LEN 8

/* key frame modes (HMARCH2 extended groups) */
#define KEY_DIRECT 0
#define KEY_PREFIX 1
#define KEY_ELIAS 2
#define KEY_FULL_LENGTH 3

/* digest lane modes */
#define DIG_PREDICTED 0
#define DIG_LITERAL 255
#define DIG_SUBBLOCKS 254
#define DIG_TABLE 253

#define HM_HMAR_EXTENDED 0x7f
#define HM_HMAR_FRONT 0x80

struct hm_hmar {
    FILE *f;
    char path[HM_MAX_STATE_PATH];
    int v2;
    int is_bcrypt;
    hm_algo_t algo;
    char algo_name[8];
    int dlen;
    char salt[65];

    int nrows;
    uint8_t *keys; /* HM_HMAR_GROUP slots of HM_HMAR_KEY_STRIDE bytes */
    uint16_t *klen;
    uint8_t *store;
    uint8_t *calc;
    uint8_t *table;
    const uint8_t *dig[HM_HMAR_GROUP];

    uint8_t *frame;
    size_t framecap;
    uint8_t *flat;
    size_t flatcap;

    uint8_t hdr[HM_HMAR_HDR];
    size_t hdrlen;
    hm_sha256_ctx sum;
};

/* ------------------------------------------------------------------ */
/* diagnostics                                                         */
/* ------------------------------------------------------------------ */

static int bad(const hm_hmar_t *h, const char *what)
{
    fprintf(stderr, "[-] %s: %s\n", h->path, what);
    return -1;
}

/* ------------------------------------------------------------------ */
/* small in-memory readers                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *p;
    size_t n;
    size_t at;
} mem_t;

static int mtake(mem_t *m, size_t n, const uint8_t **out)
{
    if (n > m->n - m->at)
        return -1;
    *out = m->p + m->at;
    m->at += n;
    return 0;
}

static int mu8(mem_t *m, unsigned *v)
{
    const uint8_t *p;

    if (mtake(m, 1, &p) != 0)
        return -1;
    *v = p[0];
    return 0;
}

static int muv(mem_t *m, uint64_t *v)
{
    uint64_t r = 0;

    for (unsigned shift = 0; shift <= 63; shift += 7) {
        const uint8_t *p;

        if (mtake(m, 1, &p) != 0)
            return -1;
        if (shift == 63 && (p[0] & 127u) > 1u)
            return -1;
        r |= (uint64_t)(p[0] & 127u) << shift;
        if (p[0] < 128u) {
            if (shift != 0 && p[0] == 0)
                return -1; /* non-canonical varint */
            *v = r;
            return 0;
        }
    }
    return -1;
}

typedef struct {
    const uint8_t *p;
    size_t nbits;
    size_t at;
} bitr_t;

static void bits_init(bitr_t *b, const uint8_t *p, size_t n)
{
    b->p = p;
    b->nbits = n * 8u;
    b->at = 0;
}

static size_t bits_left(const bitr_t *b)
{
    return b->nbits - b->at;
}

static int bits_get(bitr_t *b, unsigned width, uint64_t *v)
{
    uint64_t x = 0;

    if ((size_t)width > bits_left(b))
        return -1;
    for (unsigned i = 0; i < width; i++) {
        size_t pos = b->at + i;
        unsigned bit = ((unsigned)b->p[pos >> 3] >>
                        (unsigned)(7 - (pos & 7))) & 1u;

        x = (x << 1) | (uint64_t)bit;
    }
    b->at += width;
    *v = x;
    return 0;
}

static int bits_one(bitr_t *b, unsigned *v)
{
    uint64_t x;

    if (bits_get(b, 1, &x) != 0)
        return -1;
    *v = (unsigned)x;
    return 0;
}

static int bits_bytes(bitr_t *b, uint8_t *dst, size_t n)
{
    if (n > bits_left(b) / 8u)
        return -1;
    if ((b->at & 7u) == 0) {
        memcpy(dst, b->p + (b->at >> 3), n);
        b->at += n * 8u;
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        uint64_t x;

        if (bits_get(b, 8, &x) != 0)
            return -1;
        dst[i] = (uint8_t)x;
    }
    return 0;
}

static int bits_pad(bitr_t *b)
{
    size_t left = bits_left(b);
    uint64_t x = 0;

    if (left >= 8)
        return -1;
    if (left != 0 && bits_get(b, (unsigned)left, &x) != 0)
        return -1;
    return x == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* RSM1 shapes and field lanes                                         */
/* ------------------------------------------------------------------ */

static int unshape(mem_t *m, int n, uint32_t *lens)
{
    uint64_t fixed;

    if (muv(m, &fixed) != 0)
        return -1;
    if (fixed != 0) {
        if (fixed - 1 > 255)
            return -1;
        for (int i = 0; i < n; i++)
            lens[i] = (uint32_t)(fixed - 1);
        return 0;
    }
    {
        unsigned mode;

        if (mu8(m, &mode) != 0)
            return -1;
        if (mode == 0) {
            for (int i = 0; i < n; i++) {
                uint64_t v;

                if (muv(m, &v) != 0 || v > 255)
                    return -1;
                lens[i] = (uint32_t)v;
            }
            return 0;
        }
        if (mode == 1) {
            uint64_t low;
            unsigned width;
            unsigned wb;
            const uint8_t *p;
            size_t nbytes;
            bitr_t bits;

            if (muv(m, &low) != 0 || low > 255)
                return -1;
            if (mu8(m, &wb) != 0)
                return -1;
            width = wb;            if (width < 1 || width > 64)
                return -1;
            nbytes = ((size_t)width * (size_t)n + 7u) / 8u;
            if (mtake(m, nbytes, &p) != 0)
                return -1;
            bits_init(&bits, p, nbytes);
            for (int i = 0; i < n; i++) {
                uint64_t v;

                if (bits_get(&bits, width, &v) != 0)
                    return -1;
                v += low;
                if (v > 255)
                    return -1;
                lens[i] = (uint32_t)v;
            }
            return bits_pad(&bits);
        }
    }
    return -1;
}

/* canonical Huffman codebook */
typedef struct {
    int child[2];
    int sym;
} hnode_t;

static int huff_decode(hm_hmar_t *h, mem_t *m, size_t expected,
                       const uint8_t **out, size_t *outsz)
{
    uint8_t bitmap[32];
    const uint8_t *p;
    uint8_t clen[HM_HMAR_MAX_SYMBOLS];
    const uint8_t *tok[HM_HMAR_MAX_TOKENS];
    uint16_t toklen[HM_HMAR_MAX_TOKENS];
    unsigned ntok = 0;
    int nsym = 256;
    uint64_t code = 0;
    unsigned prev = 0;
    size_t nodes_max = 1;
    hnode_t *tree;
    size_t ntab = 1;
    const uint8_t *stream;
    size_t streamsz;
    bitr_t bits;
    size_t produced = 0;

    memset(clen, 0, sizeof(clen));
    if (mtake(m, 32, &p) != 0)
        return -1;
    memcpy(bitmap, p, 32);
    for (unsigned id = 0; id < 256; id++) {
        if ((((unsigned)bitmap[id >> 3] >> (id & 7u)) & 1u) != 0) {
            unsigned len;

            if (mu8(m, &len) != 0 || len == 0 || len > 63)
                return -1;
            clen[id] = (uint8_t)len;
        }
    }
    {
        uint64_t nv;

        if (muv(m, &nv) != 0 || nv > HM_HMAR_MAX_TOKENS)
            return -1;
        ntok = (unsigned)nv;
    }
    {
        const uint8_t *prev_tok = NULL;
        size_t prev_len = 0;

        for (unsigned i = 0; i < ntok; i++) {
            uint64_t wv;
            const uint8_t *word;
            unsigned len;
            size_t cmp;

            if (muv(m, &wv) != 0 || wv < 2 || wv > HM_HMAR_MAX_TOKEN)
                return -1;
            if (mtake(m, (size_t)wv, &word) != 0)
                return -1;
            cmp = prev_len < (size_t)wv ? prev_len : (size_t)wv;
            if (prev_tok != NULL) {
                int c = memcmp(word, prev_tok, cmp);

                if (c < 0 || (c == 0 && (size_t)wv <= prev_len))
                    return -1;
            }
            if (mu8(m, &len) != 0 || len == 0 || len > 63)
                return -1;
            tok[i] = word;
            toklen[i] = (uint16_t)wv;
            clen[256 + i] = (uint8_t)len;
            prev_tok = word;
            prev_len = (size_t)wv;
        }
    }
    nsym = 256 + (int)ntok;

    for (int id = 0; id < nsym; id++) {
        if (clen[id] != 0)
            nodes_max += clen[id];
    }
    if (nodes_max > 1 + (size_t)nsym * 63u)
        return -1;
    tree = malloc(nodes_max * sizeof(*tree));
    if (tree == NULL)
        return -1;
    tree[0].child[0] = tree[0].child[1] = -1;
    tree[0].sym = -1;

    for (unsigned w = 1; w <= 63; w++) {
        for (int id = 0; id < nsym; id++) {
            if (clen[id] != (uint8_t)w)
                continue;
            if (prev != 0 && w > prev) {
                if (w - prev >= 64 || code > (UINT64_MAX >> (w - prev))) {
                    free(tree);
                    return -1;
                }
            }
            code <<= (w - prev);
            if (w < 64 && code >= ((uint64_t)1 << w)) {
                free(tree);
                return -1;
            }
            {
                size_t at = 0;

                for (unsigned j = w; j != 0; j--) {
                    unsigned bit = (unsigned)((code >> (j - 1u)) & 1u);
                    int next = tree[at].child[bit];

                    if (next < 0) {
                        if (ntab >= nodes_max) {
                            free(tree);
                            return -1;
                        }
                        tree[ntab].child[0] = tree[ntab].child[1] = -1;
                        tree[ntab].sym = -1;
                        tree[at].child[bit] = (int)ntab;
                        next = (int)ntab;
                        ntab++;
                    }
                    at = (size_t)next;
                }
                if (tree[at].sym >= 0 || tree[at].child[0] >= 0 ||
                    tree[at].child[1] >= 0) {
                    free(tree);
                    return -1;
                }
                tree[at].sym = id;
            }
            code++;
            prev = w;
        }
    }
    if (ntab == 1) {
        free(tree);
        return -1;
    }

    stream = m->p + m->at;
    streamsz = m->n - m->at;
    m->at = m->n;
    bits_init(&bits, stream, streamsz);
    if (h->flatcap < expected) {
        uint8_t *np = realloc(h->flat, expected == 0 ? 1 : expected);

        if (np == NULL) {
            free(tree);
            return -1;
        }
        h->flat = np;
        h->flatcap = expected;
    }
    while (produced < expected) {
        size_t at = 0;
        size_t add;
        unsigned depth = 0;

        while (tree[at].sym < 0) {
            unsigned bit;
            int next;

            if (bits_one(&bits, &bit) != 0 || ++depth > 63) {
                free(tree);
                return -1;
            }
            next = tree[at].child[bit];
            if (next < 0) {
                free(tree);
                return -1;
            }
            at = (size_t)next;
        }
        if (tree[at].sym < 256) {
            uint8_t lit = (uint8_t)tree[at].sym;

            add = 1;
            if (add > expected - produced) {
                free(tree);
                return -1;
            }
            h->flat[produced] = lit;
        } else {
            unsigned id = (unsigned)tree[at].sym - 256u;

            if (id >= ntok) {
                free(tree);
                return -1;
            }
            add = toklen[id];
            if (add > expected - produced) {
                free(tree);
                return -1;
            }
            memcpy(h->flat + produced, tok[id], add);
        }
        produced += add;
    }
    free(tree);
    if (bits_pad(&bits) != 0)
        return -1;
    *out = h->flat;
    *outsz = produced;
    return 0;
}

static int read_lane(hm_hmar_t *h, mem_t *m, int n, uint32_t *lens,
                     const uint8_t **flat, size_t *flatsz)
{
    unsigned mode;
    size_t total = 0;
    const uint8_t *p;

    if (mu8(m, &mode) != 0)
        return -1;
    if (unshape(m, n, lens) != 0)
        return -1;
    for (int i = 0; i < n; i++) {
        if ((size_t)lens[i] > SIZE_MAX - total)
            return -1;
        total += lens[i];
    }
    if (mode == 0) {
        if (mtake(m, total, &p) != 0)
            return -1;
        *flat = p;
        *flatsz = total;
    } else if (mode == 1) {
        if (huff_decode(h, m, total, flat, flatsz) != 0)
            return -1;
    } else {
        return -1;
    }
    if (m->at != m->n)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* HMARCH2 key frames                                                  */
/* ------------------------------------------------------------------ */

static int set_key(hm_hmar_t *h, int row, const uint8_t *src, size_t len)
{
    if (len > HM_HMAR_KEY_STRIDE - 1)
        return -1;
    memcpy(h->keys + (size_t)row * HM_HMAR_KEY_STRIDE, src, len);
    h->klen[row] = (uint16_t)len;
    return 0;
}

static const uint8_t *get_key(const hm_hmar_t *h, int row, size_t *len)
{
    *len = h->klen[row];
    return h->keys + (size_t)row * HM_HMAR_KEY_STRIDE;
}

static int decode_elias(hm_hmar_t *h, mem_t *m)
{
    uint64_t wv;
    uint64_t ellv;
    unsigned w;
    unsigned ell;
    const uint8_t *p;
    bitr_t bits;
    unsigned tail;
    unsigned partial;
    uint64_t high = 0;
    int n = h->nrows;

    if (muv(m, &wv) != 0 || muv(m, &ellv) != 0)
        return -1;
    if (n < 1 || wv < 1 || wv > HM_HMAR_KEY_STRIDE - 1 || ellv > 8 * wv)
        return -1;
    w = (unsigned)wv;
    ell = (unsigned)ellv;
    {
        size_t rest = m->n - m->at;

        if (mtake(m, rest, &p) != 0)
            return -1;
        bits_init(&bits, p, rest);
    }
    if ((size_t)n * ((size_t)ell + 1) > bits_left(&bits))
        return -1;
    tail = ell / 8u;
    partial = ell % 8u;
    for (int i = 0; i < n; i++) {
        uint8_t *slot = h->keys + (size_t)i * HM_HMAR_KEY_STRIDE;

        memset(slot, 0, w);
        if (partial != 0) {
            uint64_t v;

            if (bits_get(&bits, partial, &v) != 0)
                return -1;
            slot[w - tail - 1] = (uint8_t)v;
        }
        if (bits_bytes(&bits, slot + (w - tail), tail) != 0)
            return -1;
        h->klen[i] = (uint16_t)w;
    }
    for (int i = 0; i < n; i++) {
        unsigned bit;
        uint64_t q;
        uint8_t *slot = h->keys + (size_t)i * HM_HMAR_KEY_STRIDE;
        unsigned at = w - tail;

        for (;;) {
            if (bits_one(&bits, &bit) != 0)
                return -1;
            if (bit != 0)
                break;
            if (high == UINT64_MAX)
                return -1;
            high++;
        }
        q = high;
        if (partial != 0) {
            unsigned mask = (1u << (8u - partial)) - 1u;

            at--;
            slot[at] = (uint8_t)(slot[at] |
                                 (uint8_t)((q & mask) << partial));
            q >>= 8u - partial;
        }
        while (at != 0) {
            slot[--at] = (uint8_t)(q & 255u);
            q >>= 8;
        }
        if (q != 0)
            return -1;
    }
    return bits_pad(&bits);
}

static int decode_key_frame(hm_hmar_t *h, const uint8_t *data, size_t size)
{
    mem_t m = { data, size, 0 };
    unsigned mode;
    int n = h->nrows;

    if (mu8(&m, &mode) != 0)
        return -1;
    if (mode == KEY_DIRECT) {
        uint32_t lens[HM_HMAR_GROUP];
        const uint8_t *flat;
        size_t flatsz;
        size_t off = 0;

        if (read_lane(h, &m, n, lens, &flat, &flatsz) != 0)
            return -1;
        for (int i = 0; i < n; i++) {
            if (set_key(h, i, flat + off, lens[i]) != 0)
                return -1;
            off += lens[i];
        }
        return off == flatsz ? 0 : -1;
    }
    if (mode == KEY_ELIAS)
        return decode_elias(h, &m);
    if (mode == KEY_PREFIX || mode == KEY_FULL_LENGTH) {
        uint32_t prefixes[HM_HMAR_GROUP];
        uint32_t lens[HM_HMAR_GROUP];
        const uint8_t *first;
        unsigned flen;
        const uint8_t *flat;
        size_t flatsz;
        size_t off = 0;

        if (mu8(&m, &flen) != 0 || flen > HM_HMAR_KEY_STRIDE - 1)
            return -1;
        if (mtake(&m, flen, &first) != 0)
            return -1;
        if (set_key(h, 0, first, flen) != 0)
            return -1;
        if (n == 1)
            return m.at == m.n ? 0 : -1;
        if (unshape(&m, n - 1, prefixes) != 0)
            return -1;
        if (read_lane(h, &m, n - 1, lens, &flat, &flatsz) != 0)
            return -1;
        for (int i = 1; i < n; i++) {
            size_t prevlen;
            const uint8_t *prev = get_key(h, i - 1, &prevlen);
            uint32_t plen = prefixes[i - 1];
            uint8_t slot[HM_HMAR_KEY_STRIDE];

            if (mode == KEY_FULL_LENGTH) {
                if (plen < lens[i - 1])
                    return -1;
                plen -= lens[i - 1];
            }
            if ((size_t)plen > prevlen)
                return -1;
            if ((size_t)plen + lens[i - 1] > HM_HMAR_KEY_STRIDE - 1)
                return -1;
            memcpy(slot, prev, plen);
            memcpy(slot + plen, flat + off, lens[i - 1]);
            off += lens[i - 1];
            if (set_key(h, i, slot, (size_t)plen + lens[i - 1]) != 0)
                return -1;
        }
        return off == flatsz ? 0 : -1;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* digest prediction                                                   */
/* ------------------------------------------------------------------ */

static int predict_row(hm_hmar_t *h, int row)
{
    uint8_t out[32];
    size_t olen = 0;
    size_t len;
    const uint8_t *key;
    uint8_t *slot;

    if (h->is_bcrypt)
        return -1;
    key = get_key(h, row, &len);
    hm_hash(h->algo, key, len, out, &olen);
    slot = h->calc + (size_t)row * (size_t)h->dlen;
    memcpy(slot, out, (size_t)h->dlen);
    h->dig[row] = slot;
    return 0;
}

static unsigned u32_bits(uint32_t v)
{
    unsigned n = 0;

    while (v != 0) {
        n++;
        v >>= 1;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* file helpers                                                        */
/* ------------------------------------------------------------------ */

static int read_file(hm_hmar_t *h, void *buf, size_t n)
{
    if (fread(buf, 1, n, h->f) != n)
        return bad(h, "truncated archive");
    return 0;
}

static int get_byte(hm_hmar_t *h, unsigned *v)
{
    int c = getc(h->f);

    if (c == EOF)
        return bad(h, "truncated archive");
    *v = (unsigned)c;
    return 0;
}

/* ------------------------------------------------------------------ */
/* digest lanes                                                        */
/* ------------------------------------------------------------------ */

static void index_layout(int n, int count, unsigned *bits, size_t *mask_bytes,
                         size_t *index_bytes, int *bitmap)
{
    unsigned b = 0;

    if (count > 1) {
        unsigned v = (unsigned)(count - 1);

        b = u32_bits(v);
    }
    {
        size_t dense = ((size_t)n * b + 7u) / 8u;
        size_t mask = ((size_t)n + 7u) / 8u;
        size_t refs = ((size_t)(n - count) * b + 7u) / 8u;

        *bits = b;
        *mask_bytes = mask;
        if (mask + refs < dense) {
            *bitmap = 1;
            *index_bytes = refs;
        } else {
            *bitmap = 0;
            *index_bytes = dense;
        }
    }
}

static int table_digests(hm_hmar_t *h, int n)
{
    unsigned char cb[2];
    int count;
    size_t d = (size_t)h->dlen;
    unsigned bits;
    size_t mask_bytes;
    size_t index_bytes;
    int bitmap;
    uint8_t mask[128];
    uint8_t idxbuf[1400];
    bitr_t bitsr;
    int next_new = 0;
    uint8_t seen[HM_HMAR_GROUP];

    if (read_file(h, cb, 2) != 0)
        return -1;
    count = ((int)cb[0] << 8) | (int)cb[1];
    if (count < 1 || count > n)
        return bad(h, "invalid digest table size");
    if (read_file(h, h->table, (size_t)count * d) != 0)
        return -1;
    index_layout(n, count, &bits, &mask_bytes, &index_bytes, &bitmap);
    if (mask_bytes > sizeof(mask) || index_bytes > sizeof(idxbuf))
        return bad(h, "invalid digest table layout");
    memset(seen, 0, sizeof(seen));
    if (bitmap) {
        if (mask_bytes != 0 && read_file(h, mask, mask_bytes) != 0)
            return -1;
        if (mask_bytes != 0 && n % 8 != 0 &&
            (mask[mask_bytes - 1] >> (unsigned)(n % 8)) != 0)
            return bad(h, "invalid digest bitmap padding");
        if (index_bytes != 0 && read_file(h, idxbuf, index_bytes) != 0)
            return -1;
        bits_init(&bitsr, idxbuf, index_bytes);
    } else {
        if (index_bytes != 0 && read_file(h, idxbuf, index_bytes) != 0)
            return -1;
        bits_init(&bitsr, idxbuf, index_bytes);
    }
    for (int i = 0; i < n; i++) {
        unsigned index;

        if (bitmap && (mask[i >> 3] & (uint8_t)(1u << (unsigned)(i & 7))) == 0) {
            index = (unsigned)next_new++;
            if ((int)index >= count)
                return bad(h, "dangling digest table index");
        } else {
            uint64_t v;

            if (bits_get(&bitsr, bits, &v) != 0)
                return bad(h, "truncated digest table indices");
            index = (unsigned)v;
            if ((int)index >= count)
                return bad(h, "digest table index out of range");
            if (bitmap) {
                if ((int)index >= next_new)
                    return bad(h, "forward digest table reference");
            } else if (seen[index] == 0) {
                if ((int)index != next_new)
                    return bad(h, "digest table out of first-occurrence order");
                seen[index] = 1;
                next_new++;
            }
        }
        h->dig[i] = h->table + (size_t)index * d;
    }
    if (next_new != count)
        return bad(h, "incorrect number of digest table indices");
    if (bits_pad(&bitsr) != 0)
        return bad(h, "invalid digest index padding");
    return 0;
}

static int group_digests(hm_hmar_t *h)
{
    unsigned mode;
    int n = h->nrows;
    size_t d = (size_t)h->dlen;

    if (get_byte(h, &mode) != 0)
        return -1;
    if (mode == DIG_PREDICTED) {
        if (h->is_bcrypt)
            return bad(h, "a bcrypt map cannot predict digests");
        for (int i = 0; i < n; i++) {
            if (predict_row(h, i) != 0)
                return bad(h, "cannot predict a digest");
        }
        return 0;
    }
    if (mode == DIG_LITERAL) {
        if (read_file(h, h->store, (size_t)n * d) != 0)
            return -1;
        for (int i = 0; i < n; i++)
            h->dig[i] = h->store + (size_t)i * d;
        return 0;
    }
    if (mode == DIG_TABLE)
        return table_digests(h, n);
    if (mode == DIG_SUBBLOCKS) {
        int at = 0;

        while (at < n) {
            unsigned k;
            int nb = n - at < HM_HMAR_BLOCK ? n - at : HM_HMAR_BLOCK;

            if (get_byte(h, &k) != 0)
                return -1;
            if (k == 0) {
                for (int i = 0; i < nb; i++) {
                    if (predict_row(h, at + i) != 0)
                        return bad(h, "cannot predict a digest");
                }
            } else if (k == DIG_LITERAL) {
                if (read_file(h, h->store + (size_t)at * d,
                              (size_t)nb * d) != 0)
                    return -1;
                for (int i = 0; i < nb; i++)
                    h->dig[at + i] = h->store + (size_t)(at + i) * d;
            } else {
                return bad(h, "this archive stores ranked digest exceptions; "
                              "unpack it with hashmap-archive first");
            }
            at += nb;
        }
        return 0;
    }
    return bad(h, "unknown digest lane mode");
}

/* ------------------------------------------------------------------ */
/* groups                                                              */
/* ------------------------------------------------------------------ */

static int legacy_block(hm_hmar_t *h, unsigned tag)
{
    int n = (int)(tag & (unsigned)(HM_HMAR_FRONT - 1));
    int front = (tag & HM_HMAR_FRONT) != 0;
    unsigned k;
    size_t d = (size_t)h->dlen;

    if (n < 1 || n > HM_HMAR_BLOCK)
        return bad(h, "invalid block size");
    if (get_byte(h, &k) != 0)
        return -1;
    for (int i = 0; i < n; i++) {
        unsigned prefix = 0;
        unsigned suffix;
        size_t prevlen = 0;
        const uint8_t *prev = NULL;
        uint8_t *slot = h->keys + (size_t)i * HM_HMAR_KEY_STRIDE;

        if (front) {
            if (get_byte(h, &prefix) != 0)
                return -1;
        }
        if (get_byte(h, &suffix) != 0)
            return -1;
        if (i > 0)
            prev = get_key(h, i - 1, &prevlen);
        if ((size_t)prefix > prevlen)
            return bad(h, "invalid prefix length in a block");
        if ((size_t)prefix + suffix > HM_HMAR_KEY_STRIDE - 1)
            return bad(h, "key too long in a block");
        if (prefix != 0)
            memcpy(slot, prev, prefix);
        if (read_file(h, slot + prefix, suffix) != 0)
            return -1;
        h->klen[i] = (uint16_t)(prefix + suffix);
    }
    h->nrows = n;
    if (k == 0) {
        for (int i = 0; i < n; i++) {
            if (predict_row(h, i) != 0)
                return bad(h, "cannot predict a digest");
        }
    } else if (k == DIG_LITERAL) {
        if (read_file(h, h->store, (size_t)n * d) != 0)
            return -1;
        for (int i = 0; i < n; i++)
            h->dig[i] = h->store + (size_t)i * d;
    } else {
        return bad(h, "this archive stores ranked digest exceptions; unpack "
                      "it with hashmap-archive first");
    }
    return 0;
}

static int extended_group(hm_hmar_t *h)
{
    unsigned char nb[2];
    unsigned char sb[4];
    uint32_t size;
    int n;
    size_t maxsize;

    if (read_file(h, nb, 2) != 0 || read_file(h, sb, 4) != 0)
        return -1;
    n = ((int)nb[0] << 8) | (int)nb[1];
    size = ((uint32_t)sb[0] << 24) | ((uint32_t)sb[1] << 16) |
           ((uint32_t)sb[2] << 8) | (uint32_t)sb[3];
    if (n < 1 || n > HM_HMAR_GROUP)
        return bad(h, "invalid group row count");
    maxsize = 4u + (size_t)(2 + HM_HMAR_KEY_STRIDE - 1) * (size_t)n;
    if (size < 1 || (size_t)size > maxsize)
        return bad(h, "invalid group key frame size");
    if (h->framecap < (size_t)size) {
        uint8_t *np = realloc(h->frame, (size_t)size);

        if (np == NULL)
            return bad(h, "out of memory");
        h->frame = np;
        h->framecap = (size_t)size;
    }
    if (read_file(h, h->frame, (size_t)size) != 0)
        return -1;
    h->nrows = n;
    if (decode_key_frame(h, h->frame, (size_t)size) != 0)
        return bad(h, "corrupt group key frame");
    if (group_digests(h) != 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

static int hdr_add(hm_hmar_t *h, const char *line, size_t len)
{
    if (len > sizeof(h->hdr) - h->hdrlen)
        return -1;
    memcpy(h->hdr + h->hdrlen, line, len);
    h->hdrlen += len;
    return 0;
}

static int copy_str(char *dst, size_t cap, const char *src)
{
    size_t len = strlen(src);

    if (len >= cap)
        return -1;
    memcpy(dst, src, len + 1);
    return 0;
}

/* read one header line; copy the exact bytes into the checksummed header,
 * then strip the newline for parsing */
static int hdr_line(hm_hmar_t *h, char *line, size_t cap)
{
    size_t len;

    if (fgets(line, (int)cap, h->f) == NULL)
        return bad(h, "truncated archive header");
    len = strlen(line);
    if (len < 2 || line[len - 1] != '\n')
        return bad(h, "unsupported archive map header");
    if (hdr_add(h, line, len) != 0)
        return bad(h, "archive map header too long");
    line[len - 1] = '\0';
    return 0;
}

static int parse_header(hm_hmar_t *h, const char *hmmap_magic)
{
    char line[96];

    h->hdrlen = 0;
    memcpy(h->hdr, hmmap_magic, 8);
    h->hdrlen = 8;
    if (memcmp(hmmap_magic, "HMMAP 1\n", 8) == 0) {
        h->algo = HM_ALG_MD5;
        snprintf(h->algo_name, sizeof(h->algo_name), "md5");
        h->dlen = 16;
        return 0;
    }
    if (memcmp(hmmap_magic, "HMMAP 2\n", 8) != 0)
        return bad(h, "unsupported archive map header");

    if (hdr_line(h, line, sizeof(line)) != 0)
        return -1;
    if (strncmp(line, "algo ", 5) != 0)
        return bad(h, "unsupported archive map header");
    if (strcmp(line + 5, "bcrypt") == 0) {
        h->is_bcrypt = 1;
        if (copy_str(h->algo_name, sizeof(h->algo_name), "bcrypt") != 0)
            return bad(h, "unsupported archive algorithm");
    } else if (hm_algo_parse(line + 5, &h->algo) == 0) {
        if (copy_str(h->algo_name, sizeof(h->algo_name), line + 5) != 0)
            return bad(h, "unsupported archive algorithm");
    } else {
        return bad(h, "unsupported archive algorithm");
    }

    if (hdr_line(h, line, sizeof(line)) != 0)
        return -1;
    if (strncmp(line, "dlen ", 5) != 0)
        return bad(h, "unsupported archive map header");
    {
        char *end = NULL;
        long v = strtol(line + 5, &end, 10);

        if (end == NULL || *end != '\0' || v < 1 || v > 32 ||
            line[5] < '0' || line[5] > '9')
            return bad(h, "unsupported archive digest width");
        h->dlen = (int)v;
    }

    if (h->is_bcrypt) {
        size_t body;

        if (hdr_line(h, line, sizeof(line)) != 0)
            return -1;
        if (strncmp(line, "salt ", 5) != 0)
            return bad(h, "unsupported archive salt line");
        body = strlen(line) - 5;
        if (body < 1 || body > 64)
            return bad(h, "unsupported archive salt line");
        if (copy_str(h->salt, sizeof(h->salt), line + 5) != 0)
            return bad(h, "unsupported archive salt line");
    }
    if (!h->is_bcrypt && (size_t)h->dlen > hm_algo_size(h->algo))
        return bad(h, "archive digest width exceeds the algorithm size");
    return 0;
}

int hm_hmar_open(const char *path, hm_hmar_t **out)
{
    hm_hmar_t *h;
    char magic[HM_HMAR_MAGIC_LEN];
    char hmmap[8];

    *out = NULL;
    h = calloc(1, sizeof(*h));
    if (h == NULL) {
        fprintf(stderr, "[-] out of memory\n");
        return -1;
    }
    snprintf(h->path, sizeof(h->path), "%s", path);
    h->f = fopen(path, "rb");
    if (h->f == NULL) {
        fprintf(stderr, "[-] cannot open %s: %s\n", path, strerror(errno));
        free(h);
        return -1;
    }
    if (fread(magic, 1, sizeof(magic), h->f) != sizeof(magic)) {
        bad(h, "not a hashmap archive (missing magic)");
        goto fail;
    }
    if (memcmp(magic, HM_HMAR_MAGIC2, HM_HMAR_MAGIC_LEN) == 0) {
        h->v2 = 1;
    } else if (memcmp(magic, HM_HMAR_MAGIC1, HM_HMAR_MAGIC_LEN) != 0) {
        bad(h, "not a hashmap archive (missing magic)");
        goto fail;
    }
    if (fread(hmmap, 1, sizeof(hmmap), h->f) != sizeof(hmmap)) {
        bad(h, "truncated archive header");
        goto fail;
    }
    if (parse_header(h, hmmap) != 0)
        goto fail;

    h->keys = malloc((size_t)HM_HMAR_GROUP * HM_HMAR_KEY_STRIDE);
    h->klen = malloc((size_t)HM_HMAR_GROUP * sizeof(*h->klen));
    h->store = malloc((size_t)HM_HMAR_GROUP * 32u);
    h->calc = malloc((size_t)HM_HMAR_GROUP * 32u);
    h->table = malloc((size_t)HM_HMAR_GROUP * 32u);
    h->flat = malloc(1);
    if (h->keys == NULL || h->klen == NULL || h->store == NULL ||
        h->calc == NULL || h->table == NULL || h->flat == NULL) {
        bad(h, "out of memory");
        goto fail;
    }
    h->flatcap = 1;
    hm_sha256_init(&h->sum);
    hm_sha256_update(&h->sum, h->hdr, h->hdrlen);
    *out = h;
    return 0;

fail:
    hm_hmar_close(h);
    return -1;
}

void hm_hmar_close(hm_hmar_t *h)
{
    if (h == NULL)
        return;
    if (h->f != NULL)
        fclose(h->f);
    free(h->keys);
    free(h->klen);
    free(h->store);
    free(h->calc);
    free(h->table);
    free(h->frame);
    free(h->flat);
    free(h);
}

const char *hm_hmar_algo(const hm_hmar_t *h)
{
    return h->algo_name;
}

int hm_hmar_dlen(const hm_hmar_t *h)
{
    return h->dlen;
}

const char *hm_hmar_salt(const hm_hmar_t *h)
{
    return h->salt;
}

int hm_hmar_next(hm_hmar_t *h, int *nrows)
{
    unsigned tag;
    int c = getc(h->f);

    if (c == EOF)
        return bad(h, "truncated archive (no checksum)");
    tag = (unsigned)c;
    if (tag == 0) {
        uint8_t want[32];
        uint8_t got[32];

        if (read_file(h, want, sizeof(want)) != 0)
            return -1;
        hm_sha256_final(&h->sum, got);
        if (memcmp(want, got, sizeof(want)) != 0)
            return bad(h, "checksum mismatch (the archive is damaged)");
        if (getc(h->f) != EOF)
            return bad(h, "trailing data after the archive checksum");
        return 0;
    }
    if (tag == HM_HMAR_EXTENDED) {
        if (!h->v2)
            return bad(h, "extended group in an HMARCH1 archive");
        if (extended_group(h) != 0)
            return -1;
    } else {
        if (legacy_block(h, tag) != 0)
            return -1;
    }
    for (int i = 0; i < h->nrows; i++) {
        size_t len;
        const uint8_t *key = get_key(h, i, &len);
        uint8_t lb = (uint8_t)len;

        hm_sha256_update(&h->sum, h->dig[i], (size_t)h->dlen);
        hm_sha256_update(&h->sum, &lb, 1);
        hm_sha256_update(&h->sum, key, len);
    }
    *nrows = h->nrows;
    return 1;
}

const uint8_t *hm_hmar_key(const hm_hmar_t *h, int row, size_t *len)
{
    return get_key(h, row, len);
}

const uint8_t *hm_hmar_digest(const hm_hmar_t *h, int row)
{
    return h->dig[row];
}
