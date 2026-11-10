/* hashmap - platform feature-test macros
 *
 * MUST be included first in every translation unit, before any system
 * header, so the POSIX/Windows feature set is fixed before <stdio.h> and
 * friends are pulled in.
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HM_COMPAT_H
#define HM_COMPAT_H

#if defined(_WIN32)
/* mingw: no POSIX signals, but we get the CRT signal() */
#else
#if defined(__APPLE__)
/* Darwin exposes _SC_NPROCESSORS_ONLN and the BSD bits only in full mode */
#define _DARWIN_C_SOURCE 1
#else
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#endif /* HM_COMPAT_H */
