#ifndef _SYS_UIO_H
#define _SYS_UIO_H

#include <sys/types.h>

struct iovec {
    void *iov_base;
    size_t iov_len;
};

ssize_t readv(int, const struct iovec *, int);
ssize_t writev(int, const struct iovec *, int);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
ssize_t preadv(int, const struct iovec *, int, off_t);
ssize_t pwritev(int, const struct iovec *, int, off_t);
#endif

#ifdef _GNU_SOURCE
ssize_t preadv2(int, const struct iovec *, int, off_t, int);
ssize_t pwritev2(int, const struct iovec *, int, off_t, int);
ssize_t process_vm_readv(pid_t, const struct iovec *, unsigned long,
                         const struct iovec *, unsigned long, unsigned long);
ssize_t process_vm_writev(pid_t, const struct iovec *, unsigned long,
                          const struct iovec *, unsigned long, unsigned long);

#define RWF_HIPRI 0x00000001
#define RWF_DSYNC 0x00000002
#define RWF_SYNC 0x00000004
#define RWF_NOWAIT 0x00000008
#define RWF_APPEND 0x00000010
#define RWF_NOAPPEND 0x00000020
#endif

#endif
