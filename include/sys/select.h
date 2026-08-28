#ifndef _SYS_SELECT_H
#define _SYS_SELECT_H

#include <features.h>
#include <sys/types.h>
#include <time.h>
#define __NEED_sigset_t
#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __DEFINED_struct_timeval
#define __DEFINED_struct_timeval
struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
};
#endif

#define FD_SETSIZE 1024
typedef struct { unsigned long fds_bits[FD_SETSIZE / (8 * sizeof(unsigned long))]; } fd_set;
#define FD_ZERO(set) __builtin_memset((set), 0, sizeof(*(set)))
#define FD_SET(fd, set) ((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] |= 1UL << ((fd) % (8 * sizeof(unsigned long))))
#define FD_CLR(fd, set) ((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] &= ~(1UL << ((fd) % (8 * sizeof(unsigned long)))))
#define FD_ISSET(fd, set) !!((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] & (1UL << ((fd) % (8 * sizeof(unsigned long)))))

int select(int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict, struct timeval *__restrict);
int pselect(int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict, const struct timespec *__restrict, const sigset_t *__restrict);

#ifdef __cplusplus
}
#endif

#endif
