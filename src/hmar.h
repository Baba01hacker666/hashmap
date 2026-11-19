/* hashmap - streaming reader for HMARCH1/HMARCH2 map archives
 *
 * The archive is a lossless backup of an HMMAP file: an archive magic, the
 * original HMMAP header, encoded groups of rows and a SHA-256 of the original
 * bytes. This reader decodes the rows on the fly so search mode can use a
 * .hmar file without unpacking it to disk first.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_HMAR_H
#define HM_HMAR_H

#include <stddef.h>
#include <stdint.h>

/* Opaque streaming reader. */
typedef struct hm_hmar hm_hmar_t;

/* Open an HMARCH1 or HMARCH2 archive. Returns 0 on success and stores the
 * reader in *out; on failure prints a diagnostic and returns -1. */
int hm_hmar_open(const char *path, hm_hmar_t **out);

void hm_hmar_close(hm_hmar_t *h);

/* Header information of the restored HMMAP file. */
const char *hm_hmar_algo(const hm_hmar_t *h); /* "md5", "sha1", "sha256", "bcrypt" */
int hm_hmar_dlen(const hm_hmar_t *h);        /* stored digest bytes */
const char *hm_hmar_salt(const hm_hmar_t *h); /* bcrypt salt line, or "" */

/* Decode the next group of rows.
 *  1  decoded, *nrows > 0 (at most 1024)
 *  0  end of archive (the checksum was checked when the file allowed it)
 * -1  malformed, truncated or unsupported archive
 */
int hm_hmar_next(hm_hmar_t *h, int *nrows);

/* Row accessors for the group returned by hm_hmar_next. The key pointer is
 * valid until the next call; the digest pointer is never NULL. */
const uint8_t *hm_hmar_key(const hm_hmar_t *h, int row, size_t *len);
const uint8_t *hm_hmar_digest(const hm_hmar_t *h, int row);

/* Visits every row of a group, from whichever worker decoded it. */
typedef void (*hm_hmar_row_fn)(void *ctx, const uint8_t *digest,
                               const uint8_t *key, size_t keylen);

#define HM_HMAR_MAX_THREADS 64

/* Scan every group with up to `threads` decoders and call `fn` for each row.
 * The rows of a group are delivered in order by one worker; groups may be
 * visited in any order. With `verify` set the archive checksum is checked
 * as well (the rows are re-hashed in original order while the workers run).
 *
 * Returns 0 on success, -1 on error and 1 when the archive cannot be split
 * (HMARCH1 legacy groups), in which case the caller should fall back to
 * hm_hmar_open/hm_hmar_next. */
int hm_hmar_scan(const char *path, int threads, int verify,
                 hm_hmar_row_fn fn, void *ctx);

#endif /* HM_HMAR_H */
