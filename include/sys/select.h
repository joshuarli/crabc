#ifndef _SYS_SELECT_H
#define _SYS_SELECT_H

#if defined(__x86_64__)
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_size_t
#define __NEED_time_t
#define __NEED_suseconds_t
#define __NEED_struct_timeval
#define __NEED_struct_timespec
#define __NEED_sigset_t

#include <bits/alltypes.h>

#define FD_SETSIZE 1024

typedef unsigned long fd_mask;

typedef struct {
	unsigned long fds_bits[FD_SETSIZE / 8 / sizeof(long)];
} fd_set;

#define FD_ZERO(s) do { int __i; unsigned long *__b=(s)->fds_bits; for(__i=sizeof (fd_set)/sizeof (long); __i; __i--) *__b++=0; } while(0)
#define FD_SET(d, s)   ((s)->fds_bits[(d)/(8*sizeof(long))] |= (1UL<<((d)%(8*sizeof(long)))))
#define FD_CLR(d, s)   ((s)->fds_bits[(d)/(8*sizeof(long))] &= ~(1UL<<((d)%(8*sizeof(long)))))
#define FD_ISSET(d, s) !!((s)->fds_bits[(d)/(8*sizeof(long))] & (1UL<<((d)%(8*sizeof(long)))))

int select (int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict, struct timeval *__restrict);
int pselect (int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict, const struct timespec *__restrict, const sigset_t *__restrict);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define NFDBITS (8*(int)sizeof(long))
#endif

#if _REDIR_TIME64
__REDIR(select, __select_time64);
__REDIR(pselect, __pselect_time64);
#endif

#ifdef __cplusplus
}
#endif

#else

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

#endif
