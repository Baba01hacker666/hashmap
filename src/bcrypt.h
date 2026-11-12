/* hashmap - bcrypt (Blowfish based password hashing)
 *
 * A self contained implementation of the OpenBSD bcrypt scheme ($2a$, $2b$,
 * $2y$), so the tool stays dependency free. The password is never stored:
 * a hash carries its own random salt, which is why bcrypt cannot be used
 * with a plain digest map - but it can be verified against a candidate
 * list, and with a fixed salt it can be precomputed into a map.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_BCRYPT_H
#define HM_BCRYPT_H

#include <stddef.h>

#define HM_BCRYPT_MAX 64  /* the full hash string is 60 chars */

/* Compute the bcrypt hash of `password` for the given setting.
 *
 * `setting` is either a full hash ("$2b$12$<salt><digest>") - the salt and
 * the cost are taken from it - or a prefix ("$2b$12$<22 salt chars>").
 * The result is written to `out` (at least 61 bytes) in the standard
 * $2b$12$<22 salt><31 digest> form.
 *
 * returns 0 on success, -1 on a bad setting.
 */
int hm_bcrypt(const char *password, const char *setting, char *out,
              size_t outlen);

/* the 23 raw digest bytes of a bcrypt hash (decoded from the base64) */
int hm_bcrypt_digest(const char *hash, unsigned char out[23]);

/* the salt of a bcrypt hash (22 chars, without the trailing NUL) */
int hm_bcrypt_salt(const char *hash, char out[23]);

#endif /* HM_BCRYPT_H */
