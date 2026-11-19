/* hashmap - optional io_uring helpers (experimental, Linux >= 5.1)
 *
 * Built only when HM_USE_IO_URING is defined; otherwise the functions
 * report "not available" and callers fall back to regular I/O.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_IOURING_H
#define HM_IOURING_H

#include <stddef.h>

/* 1 when the running kernel is >= major.minor (Linux), 0 otherwise. */
int hm_kernel_at_least(int major, int minor);

/* 1 when io_uring can be used by this build on this system. */
int hm_io_uring_available(void);

/* Read a whole file into a newly allocated buffer (NUL terminated, like
 * a text/binary blob). Returns 0 on success. On failure returns -1 and
 * leaves *out untouched so the caller can try a regular read path. */
int hm_iouring_read_file(const char *path, char **out, size_t *outlen);

#endif /* HM_IOURING_H */
