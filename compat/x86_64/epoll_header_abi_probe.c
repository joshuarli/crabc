/* Selected Linux/x86-64 <sys/epoll.h> declaration and layout ABI facts. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

_Static_assert(sizeof(epoll_data_t) == 8 && _Alignof(epoll_data_t) == 8,
               "x86 epoll data union ABI");
_Static_assert(sizeof(struct epoll_event) == 12 && _Alignof(struct epoll_event) == 1,
               "x86 packed epoll event ABI");
_Static_assert(offsetof(struct epoll_event, events) == 0 &&
                   offsetof(struct epoll_event, data) == 4,
               "x86 packed epoll event offsets");
_Static_assert(sizeof(struct epoll_params) == 8 && _Alignof(struct epoll_params) == 4,
               "x86 epoll parameter ABI");
_Static_assert(offsetof(struct epoll_params, busy_poll_usecs) == 0 &&
                   offsetof(struct epoll_params, busy_poll_budget) == 4 &&
                   offsetof(struct epoll_params, prefer_busy_poll) == 6 &&
                   offsetof(struct epoll_params, __pad) == 7,
               "x86 epoll parameter offsets");

_Static_assert(EPOLL_CLOEXEC == O_CLOEXEC && EPOLL_NONBLOCK == O_NONBLOCK,
               "epoll creation flags");
_Static_assert(EPOLLIN == 0x001 && EPOLLPRI == 0x002 && EPOLLOUT == 0x004 &&
                   EPOLLERR == 0x008 && EPOLLHUP == 0x010 && EPOLLNVAL == 0x020 &&
                   EPOLLRDNORM == 0x040 && EPOLLRDBAND == 0x080 &&
                   EPOLLWRNORM == 0x100 && EPOLLWRBAND == 0x200 && EPOLLMSG == 0x400,
               "epoll readiness constants");
_Static_assert(EPOLLRDHUP == 0x2000 && EPOLLEXCLUSIVE == (1U << 28) &&
                   EPOLLWAKEUP == (1U << 29) && EPOLLONESHOT == (1U << 30) &&
                   EPOLLET == (1U << 31),
               "epoll behavior constants");
_Static_assert(EPOLL_CTL_ADD == 1 && EPOLL_CTL_DEL == 2 && EPOLL_CTL_MOD == 3,
               "epoll control constants");
_Static_assert(_IOC_NONE == 0U && _IOC_WRITE == 1U && _IOC_READ == 2U,
               "selected generic ioctl directions");
_Static_assert(EPIOCSPARAMS == 0x40088a01U && EPIOCGPARAMS == 0x80088a02U,
               "epoll parameter ioctl encodings");
_Static_assert(EPIOCSPARAMS == _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params) &&
                   EPIOCGPARAMS == _IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params),
               "epoll parameter ioctl composition");

_Static_assert(__builtin_types_compatible_p(__typeof__(&epoll_create),
                                             int (*)(int)),
               "epoll_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&epoll_create1),
                                             int (*)(int)),
               "epoll_create1 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&epoll_ctl),
                                             int (*)(int, int, int, struct epoll_event *)),
               "epoll_ctl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&epoll_wait),
                                             int (*)(int, struct epoll_event *, int, int)),
               "epoll_wait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&epoll_pwait),
                                             int (*)(int, struct epoll_event *, int, int,
                                                     const sigset_t *)),
               "epoll_pwait declaration");
