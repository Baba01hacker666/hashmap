/* hashmap - optional io_uring helpers (experimental, Linux >= 5.1)
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include "iouring.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <sys/utsname.h>
#endif

#if defined(HM_USE_IO_URING) && defined(__linux__)
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <liburing.h>
#endif

int hm_kernel_at_least(int major, int minor)
{
#if defined(__linux__)
    struct utsname u;
    int maj = 0;
    int min = 0;

    if (uname(&u) != 0)
        return 0;
    if (sscanf(u.release, "%d.%d", &maj, &min) < 2)
        return 0;
    return (maj > major) || (maj == major && min >= minor);
#else
    (void)major;
    (void)minor;
    return 0;
#endif
}

int hm_io_uring_available(void)
{
#if defined(HM_USE_IO_URING) && defined(__linux__)
    struct io_uring ring;

    if (!hm_kernel_at_least(5, 1))
        return 0;
    if (io_uring_queue_init(8, &ring, 0) != 0)
        return 0;
    io_uring_queue_exit(&ring);
    return 1;
#else
    return 0;
#endif
}

int hm_iouring_read_file(const char *path, char **out, size_t *outlen)
{
#if defined(HM_USE_IO_URING) && defined(__linux__)
    struct io_uring ring;
    struct stat st;
    char *buf = NULL;
    int fd = -1;
    int ret = -1;
    int ring_ok = 0;
    unsigned inflight = 0;
    off_t off = 0;
    const size_t chunk = 1024u * 1024u; /* 1 MiB per read */
    const unsigned depth = 8;

    if (!hm_kernel_at_least(5, 1))
        return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
        goto out;
    buf = malloc((size_t)st.st_size + 1u);
    if (buf == NULL)
        goto out;
    if (io_uring_queue_init(depth, &ring, 0) != 0)
        goto out;
    ring_ok = 1;

    while ((off_t)off < st.st_size || inflight > 0) {
        while (inflight < depth && off < st.st_size) {
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            size_t want = (size_t)(st.st_size - off);
            if (want > chunk)
                want = chunk;
            if (sqe == NULL)
                break;
            io_uring_prep_read(sqe, fd, buf + off, (unsigned)want, (__u64)off);
            io_uring_sqe_set_data(sqe, (void *)(uintptr_t)want);
            off += (off_t)want;
            inflight++;
        }
        if (inflight == 0)
            break;
        if (io_uring_submit(&ring) < 0)
            goto out;
        while (inflight > 0) {
            struct io_uring_cqe *cqe = NULL;
            size_t want;
            int r = io_uring_wait_cqe(&ring, &cqe);
            if (r < 0)
                goto out;
            want = (size_t)(uintptr_t)io_uring_cqe_get_data(cqe);
            if (cqe->res < 0 || (size_t)cqe->res != want) {
                io_uring_cqe_seen(&ring, cqe);
                goto out;
            }
            io_uring_cqe_seen(&ring, cqe);
            inflight--;
        }
    }

    buf[st.st_size] = '\0';
    *out = buf;
    *outlen = (size_t)st.st_size;
    buf = NULL;
    ret = 0;

out:
    if (ring_ok)
        io_uring_queue_exit(&ring);
    if (fd >= 0)
        close(fd);
    free(buf);
    return ret;
#else
    (void)path;
    (void)out;
    (void)outlen;
    return -1;
#endif
}
