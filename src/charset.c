/* hashmap - charset presets + combinator implementation
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "charset.h"

#include <stdbool.h>
#include <string.h>

#define HM_CS_CAP 256

typedef struct {
    const char *name;
    const char *chars;
} hm_cs_builtin_t;

static const hm_cs_builtin_t HM_BUILTINS[] = {
    { "digits",   "0123456789" },
    { "lower",    "abcdefghijklmnopqrstuvwxyz" },
    { "upper",    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
    { "alpha",    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" },
    { "alnum",    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" },
    { "hexlower", "0123456789abcdef" },
    { "hexupper", "0123456789ABCDEF" },
    { "special",  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" },
    { "symbols",  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" },
    { "all",      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ " },
    { "full",     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ " },
    { "default",  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" },
    { NULL, NULL }
};

typedef struct {
    char *out;
    size_t len;
    size_t cap;
    bool used[256];
} cs_buf_t;

static void cs_add(cs_buf_t *b, unsigned char c)
{
    if (b->used[c])
        return; /* never duplicate: keeps the keyspace honest */
    b->used[c] = true;
    if (b->len + 1 < b->cap)
        b->out[b->len++] = (char)c;
}

/* add the characters of a literal chunk, honouring backslash escapes */
static void cs_add_literal(cs_buf_t *b, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\\' && i + 1 < n) {
            i++;
            cs_add(b, (unsigned char)s[i]);
            continue;
        }
        cs_add(b, (unsigned char)s[i]);
    }
}

static const char *cs_builtin_chars(const char *word, size_t n)
{
    for (const hm_cs_builtin_t *b = HM_BUILTINS; b->name != NULL; b++) {
        if (strlen(b->name) == n && memcmp(b->name, word, n) == 0)
            return b->chars;
    }
    return NULL;
}

static void cs_parse_spec(cs_buf_t *b, const char *spec)
{
    const char *p = spec;

    while (*p != '\0') {
        const char *start;
        size_t n;
        const char *preset;

        if (*p == '+') { /* separator */
            p++;
            continue;
        }
        start = p;
        while (*p != '\0' && *p != '+')
            p++;
        n = (size_t)(p - start);
        if (n == 0)
            continue;

        preset = cs_builtin_chars(start, n);
        if (preset != NULL) {
            for (const char *c = preset; *c != '\0'; c++)
                cs_add(b, (unsigned char)*c);
        } else {
            cs_add_literal(b, start, n);
        }
    }
}

int hm_build_charset_multi(int nspecs, char *const *specs, char *out,
                           size_t *outlen)
{
    cs_buf_t b;

    if (out == NULL || outlen == NULL || specs == NULL || nspecs <= 0)
        return -1;

    memset(&b, 0, sizeof(b));
    b.out = out;
    b.cap = HM_CS_CAP;

    for (int i = 0; i < nspecs; i++) {
        if (specs[i] == NULL)
            continue;
        cs_parse_spec(&b, specs[i]);
    }
    if (b.len == 0)
        return -1;

    out[b.len] = '\0';
    *outlen = b.len;
    return 0;
}

int hm_build_charset(const char *spec, char *out, size_t *outlen)
{
    char *specs[1];

    if (spec == NULL)
        return -1;
    specs[0] = (char *)spec;
    return hm_build_charset_multi(1, specs, out, outlen);
}
