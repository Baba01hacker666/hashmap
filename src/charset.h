/* hashmap - charset presets + combinator */
#ifndef HM_CHARSET_H
#define HM_CHARSET_H

#include <stddef.h>

/* spec: builtin names joined with '+'; unknown tokens are literal chars.
 * e.g. "digits", "lower+digits", "abc123"
 * returns 0 on success and fills out/outlen; -1 on empty/broken spec. */
int hm_build_charset(const char *spec, char *out, size_t *outlen);

#endif /* HM_CHARSET_H */
