#ifndef _POLL_H
#define _POLL_H

#include <features.h>
#include <sys/types.h>

typedef unsigned long nfds_t;

struct pollfd {
    int fd;
    short events;
    short revents;
};

#define POLLIN 0x0001
#define POLLRDNORM 0x0040
#define POLLRDBAND 0x0080
#define POLLPRI 0x0002
#define POLLOUT 0x0004
#define POLLWRNORM 0x0100
#define POLLWRBAND 0x0200
#define POLLERR 0x0008
#define POLLHUP 0x0010
#define POLLNVAL 0x0020
#if defined(__x86_64__) && !defined(POLLMSG)
#define POLLMSG 0x0400
#define POLLRDHUP 0x2000
#endif

int poll(struct pollfd [], nfds_t, int);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#include <signal.h>
#include <time.h>
int ppoll(struct pollfd [], nfds_t, const struct timespec *__restrict,
          const sigset_t *__restrict);
#endif

#endif
