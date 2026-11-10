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
    { "all",      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ " },
    { NULL, NULL }
};

int hm_build_charset(const char *spec, char *out, size_t *outlen)
{
    size_t n = 0;
    const char *p = spec;
    const char *cs_builtins = NULL;

    if (spec == NULL || *spec == '\0')
        return -1;

    while (*p != '\0') {
        const char *plus = strchr(p, '+');
        size_t tl = (plus != NULL) ? (size_t)(plus - p) : strlen(p);
        bool matched = false;

        for (const hm_cs_builtin_t *b = HM_BUILTINS; b->name != NULL; b++) {
            if (strlen(b->name) == tl && strncmp(p, b->name, tl) == 0) {
                for (const char *c = b->chars; *c != '\0' && n < HM_CS_CAP; c++)
                    out[n++] = *c;
                matched = true;
                break;
            }
        }
        if (!matched) {
            for (size_t i = 0; i < tl && n < HM_CS_CAP; i++)
                out[n++] = p[i];
            if (cs_builtins == NULL && tl == 0)
                return -1;
        }
        if (plus == NULL)
            break;
        p = plus + 1;
    }

    if (n == 0)
        return -1;
    out[n] = '\0';
    *outlen = n;
    return 0;
}
