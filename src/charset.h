/* hashmap - charset presets + combinator
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_CHARSET_H
#define HM_CHARSET_H

#include <stddef.h>

/* Build a charset from one or more specs.
 *
 * spec syntax:
 *   - chunks joined with '+' (e.g. "lower+digits")
 *   - a chunk that matches a builtin name expands to that set
 *   - any other chunk is taken literally
 *   - '\' escapes the next character ('\+' is a literal plus, '\!' a literal
 *     bang, '\\' a literal backslash)
 *
 * Duplicates are removed, so the keyspace never gets inflated by a repeated
 * character.
 *
 * returns 0 on success and fills out/outlen; -1 on empty/broken spec.
 */
int hm_build_charset(const char *spec, char *out, size_t *outlen);

/* same, but unions several specs (e.g. -c lower -c digits) */
int hm_build_charset_multi(int nspecs, char *const *specs, char *out,
                           size_t *outlen);

#endif /* HM_CHARSET_H */
