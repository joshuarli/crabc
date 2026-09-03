#ifndef _POLL_H
#define _POLL_H
#if defined(__x86_64__)

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#include <bits/poll.h>

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008
#define POLLHUP    0x010
#define POLLNVAL   0x020
#define POLLRDNORM 0x040
#define POLLRDBAND 0x080
#ifndef POLLWRNORM
#define POLLWRNORM 0x100
#define POLLWRBAND 0x200
#endif
#ifndef POLLMSG
#define POLLMSG    0x400
#define POLLRDHUP  0x2000
#endif

typedef unsigned long nfds_t;

struct pollfd {
	int fd;
	short events;
	short revents;
};

int poll (struct pollfd *, nfds_t, int);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_time_t
#define __NEED_struct_timespec
#define __NEED_sigset_t
#include <bits/alltypes.h>
int ppoll(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);
#endif

#if _REDIR_TIME64
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
__REDIR(ppoll, __ppoll_time64);
#endif
#endif

#ifdef __cplusplus
}
#endif

#else

#include <features.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif
#endif
