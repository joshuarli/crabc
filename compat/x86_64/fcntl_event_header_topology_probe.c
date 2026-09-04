/*
 * Direct Linux/x86-64 header-topology witness for the fcntl and event-family
 * cluster. Each translation unit selects exactly one public header so a
 * preceding include cannot conceal a guard, type-identity, or transitive
 * include regression.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if defined(CRABC_FCNTL_EVENT_FCNTL)

#include <fcntl.h>

#ifndef _FCNTL_H
#error "<fcntl.h> must retain musl's public guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<fcntl.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(&creat),
    int (*)(const char *, mode_t)), "creat must use mode_t");
_Static_assert(sizeof(struct flock) == 32 && _Alignof(struct flock) == 8,
    "x86 flock layout");
_Static_assert(O_DIRECTORY == 0200000 && O_NOFOLLOW == 0400000 &&
    O_TMPFILE == 020200000, "x86 fcntl constants arrive from bits/fcntl.h");

#elif defined(CRABC_FCNTL_EVENT_SYS_FCNTL)

#include <sys/fcntl.h>

#ifndef _FCNTL_H
#error "<sys/fcntl.h> must redirect to <fcntl.h>"
#endif
#ifdef _CRABC_SYS_FCNTL_H
#error "<sys/fcntl.h> must not retain a project-private redirect guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/fcntl.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(&creat),
    int (*)(const char *, mode_t)), "redirected creat must use mode_t");

#elif defined(CRABC_FCNTL_EVENT_SEMAPHORE)

#include <semaphore.h>

#ifndef _SEMAPHORE_H
#error "<semaphore.h> must retain musl's public guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<semaphore.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
_Static_assert(sizeof(sem_t) == 32 && _Alignof(sem_t) == 4,
    "x86 sem_t layout");
_Static_assert(sizeof(((sem_t *)0)->__val) == 32 &&
    __builtin_types_compatible_p(__typeof__(((sem_t *)0)->__val[0]), volatile int),
    "sem_t must retain musl's volatile word array");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_getvalue),
    int (*)(sem_t *__restrict, int *__restrict)),
    "sem_getvalue restrict contract");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sem_timedwait),
    int (*)(sem_t *__restrict, const struct timespec *__restrict)),
    "sem_timedwait declaration");

#elif defined(CRABC_FCNTL_EVENT_EPOLL)

#include <sys/epoll.h>

#ifndef _SYS_EPOLL_H
#error "<sys/epoll.h> must retain musl's public guard"
#endif
#ifdef _CRABC_SYS_EPOLL_H
#error "<sys/epoll.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/epoll.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
_Static_assert(sizeof(struct epoll_event) == 12 &&
    _Alignof(struct epoll_event) == 1 &&
    __builtin_offsetof(struct epoll_event, data) == 4,
    "x86 epoll packed record");
_Static_assert(__builtin_types_compatible_p(__typeof__(&epoll_pwait),
    int (*)(int, struct epoll_event *, int, int, const sigset_t *)),
    "epoll_pwait declaration");

#elif defined(CRABC_FCNTL_EVENT_EVENTFD)

#include <sys/eventfd.h>

#ifndef _SYS_EVENTFD_H
#error "<sys/eventfd.h> must retain musl's public guard"
#endif
#ifdef _CRABC_SYS_EVENTFD_H
#error "<sys/eventfd.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/eventfd.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
_Static_assert(sizeof(eventfd_t) == 8 && _Alignof(eventfd_t) == 8,
    "eventfd_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&eventfd),
    int (*)(unsigned int, int)), "eventfd declaration");

#elif defined(CRABC_FCNTL_EVENT_INOTIFY)

#include <sys/inotify.h>

#ifndef _SYS_INOTIFY_H
#error "<sys/inotify.h> must retain musl's public guard"
#endif
#ifdef _CRABC_SYS_INOTIFY_H
#error "<sys/inotify.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/inotify.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
_Static_assert(sizeof(struct inotify_event) == 16 &&
    _Alignof(struct inotify_event) == 4 &&
    __builtin_offsetof(struct inotify_event, name) == 16,
    "inotify event record");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inotify_add_watch),
    int (*)(int, const char *, uint32_t)), "inotify_add_watch declaration");

#elif defined(CRABC_FCNTL_EVENT_SIGNALFD)

#include <sys/signalfd.h>

#ifndef _SYS_SIGNALFD_H
#error "<sys/signalfd.h> must retain musl's public guard"
#endif
#ifdef _CRABC_SYS_SIGNALFD_H
#error "<sys/signalfd.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/signalfd.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
_Static_assert(sizeof(struct signalfd_siginfo) == 128 &&
    _Alignof(struct signalfd_siginfo) == 8,
    "signalfd siginfo record");
_Static_assert(__builtin_types_compatible_p(__typeof__(&signalfd),
    int (*)(int, const sigset_t *, int)), "signalfd declaration");

#elif defined(CRABC_FCNTL_EVENT_TIMERFD)

#include <sys/timerfd.h>

#ifndef _SYS_TIMERFD_H
#error "<sys/timerfd.h> must retain musl's public guard"
#endif
#ifdef _CRABC_SYS_TIMERFD_H
#error "<sys/timerfd.h> must not retain a project-private guard"
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_create),
    int (*)(int, int)), "timerfd_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_settime),
    int (*)(int, int, const struct itimerspec *, struct itimerspec *)),
    "timerfd_settime declaration");

#else
#error "select exactly one fcntl/event direct-header topology variant"
#endif

int crabc_x86_fcntl_event_header_topology_probe(void)
{
    return 0;
}
