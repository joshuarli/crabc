#ifndef _SYS_SELECT_H
#define _SYS_SELECT_H

#include <sys/types.h>
#include <time.h>
#include <signal.h>

#define FD_SETSIZE 1024
typedef struct { unsigned long fds_bits[FD_SETSIZE / (8 * sizeof(unsigned long))]; } fd_set;
#define FD_ZERO(set) __builtin_memset((set), 0, sizeof(*(set)))
#define FD_SET(fd, set) ((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] |= 1UL << ((fd) % (8 * sizeof(unsigned long))))
#define FD_CLR(fd, set) ((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] &= ~(1UL << ((fd) % (8 * sizeof(unsigned long)))))
#define FD_ISSET(fd, set) !!((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] & (1UL << ((fd) % (8 * sizeof(unsigned long)))))

int select(int, fd_set *restrict, fd_set *restrict, fd_set *restrict, struct timeval *restrict);
int pselect(int, fd_set *restrict, fd_set *restrict, fd_set *restrict, const struct timespec *restrict, const sigset_t *restrict);

#endif
