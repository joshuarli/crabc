#ifndef _CRABC_SYS_TIMERFD_H
#define _CRABC_SYS_TIMERFD_H

#include <features.h>
#include <time.h>
#include <fcntl.h>

/* Strict C/C++ may name timerfd's pointer parameters without selecting the
 * POSIX time-record definition from <time.h>. Match musl by forward-declaring
 * the record at this header boundary. */
struct itimerspec;

#ifdef __cplusplus
extern "C" {
#endif

#define TFD_NONBLOCK O_NONBLOCK
#define TFD_CLOEXEC O_CLOEXEC
#define TFD_TIMER_ABSTIME 1
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
int timerfd_create(int, int);
int timerfd_settime(int, int, const struct itimerspec *, struct itimerspec *);
int timerfd_gettime(int, struct itimerspec *);

#if defined(_REDIR_TIME64) && _REDIR_TIME64
__REDIR(timerfd_settime, __timerfd_settime64);
__REDIR(timerfd_gettime, __timerfd_gettime64);
#endif

#ifdef __cplusplus
}
#endif

#endif
