// C++ companion for the direct Linux/x86-64 fcntl/event header-topology
// witness. It keeps each selected external declaration observable to nm.

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if defined(CRABC_FCNTL_EVENT_FCNTL)

#include <fcntl.h>

#ifdef _BITS_FCNTL_H
#error "<fcntl.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
using selected_signature = int (*)(const char *, mode_t);
static_assert(__is_same(decltype(&creat), selected_signature));
__attribute__((used)) static selected_signature selected_reference = creat;

#elif defined(CRABC_FCNTL_EVENT_SYS_FCNTL)

#include <sys/fcntl.h>

#ifdef _CRABC_SYS_FCNTL_H
#error "<sys/fcntl.h> must not retain a project-private redirect guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/fcntl.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
using selected_signature = int (*)(const char *, mode_t);
static_assert(__is_same(decltype(&creat), selected_signature));
__attribute__((used)) static selected_signature selected_reference = creat;

#elif defined(CRABC_FCNTL_EVENT_SEMAPHORE)

#include <semaphore.h>

#ifdef _BITS_FCNTL_H
#error "<semaphore.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
using selected_signature = int (*)(sem_t *__restrict, int *__restrict);
static_assert(sizeof(sem_t) == 32 && alignof(sem_t) == 4);
static_assert(__is_same(decltype(((sem_t *)nullptr)->__val[0]), volatile int &));
static_assert(__is_same(decltype(&sem_getvalue), selected_signature));
__attribute__((used)) static selected_signature selected_reference = sem_getvalue;

#elif defined(CRABC_FCNTL_EVENT_EPOLL)

#include <sys/epoll.h>

#ifdef _CRABC_SYS_EPOLL_H
#error "<sys/epoll.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/epoll.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
using selected_signature = int (*)(int, struct epoll_event *, int, int,
    const sigset_t *);
static_assert(sizeof(struct epoll_event) == 12 && alignof(struct epoll_event) == 1);
static_assert(__is_same(decltype(&epoll_pwait), selected_signature));
__attribute__((used)) static selected_signature selected_reference = epoll_pwait;

#elif defined(CRABC_FCNTL_EVENT_EVENTFD)

#include <sys/eventfd.h>

#ifdef _CRABC_SYS_EVENTFD_H
#error "<sys/eventfd.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/eventfd.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
using selected_signature = int (*)(unsigned int, int);
static_assert(__is_same(eventfd_t, uint64_t));
static_assert(__is_same(decltype(&eventfd), selected_signature));
__attribute__((used)) static selected_signature selected_reference = eventfd;

#elif defined(CRABC_FCNTL_EVENT_INOTIFY)

#include <sys/inotify.h>

#ifdef _CRABC_SYS_INOTIFY_H
#error "<sys/inotify.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/inotify.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
using selected_signature = int (*)(int, const char *, uint32_t);
static_assert(sizeof(struct inotify_event) == 16 && alignof(struct inotify_event) == 4);
static_assert(__is_same(decltype(&inotify_add_watch), selected_signature));
__attribute__((used)) static selected_signature selected_reference = inotify_add_watch;

#elif defined(CRABC_FCNTL_EVENT_SIGNALFD)

#include <sys/signalfd.h>

#ifdef _CRABC_SYS_SIGNALFD_H
#error "<sys/signalfd.h> must not retain a project-private guard"
#endif
#ifdef _BITS_FCNTL_H
#error "<sys/signalfd.h> must not acquire a synthetic bits/fcntl.h guard"
#endif
using selected_signature = int (*)(int, const sigset_t *, int);
static_assert(sizeof(struct signalfd_siginfo) == 128 && alignof(struct signalfd_siginfo) == 8);
static_assert(__is_same(decltype(&signalfd), selected_signature));
__attribute__((used)) static selected_signature selected_reference = signalfd;

#elif defined(CRABC_FCNTL_EVENT_TIMERFD)

#include <sys/timerfd.h>

#ifdef _CRABC_SYS_TIMERFD_H
#error "<sys/timerfd.h> must not retain a project-private guard"
#endif
using selected_signature = int (*)(int, int, const struct itimerspec *,
    struct itimerspec *);
static_assert(__is_same(decltype(&timerfd_settime), selected_signature));
__attribute__((used)) static selected_signature selected_reference = timerfd_settime;

#else
#error "select exactly one fcntl/event direct-header topology variant"
#endif

extern "C" int crabc_x86_fcntl_event_header_topology_probe_cpp()
{
    return 0;
}
