/* C++17 companion for the Linux/x86-64 <sys/epoll.h> ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

static_assert(sizeof(epoll_data_t) == 8 && alignof(epoll_data_t) == 8,
              "x86 epoll data union ABI");
static_assert(sizeof(struct epoll_event) == 12 && alignof(struct epoll_event) == 1,
              "x86 packed epoll event ABI");
static_assert(__builtin_offsetof(struct epoll_event, events) == 0 &&
                  __builtin_offsetof(struct epoll_event, data) == 4,
              "x86 packed epoll event offsets");
static_assert(sizeof(struct epoll_params) == 8 && alignof(struct epoll_params) == 4,
              "x86 epoll parameter ABI");
static_assert(__builtin_offsetof(struct epoll_params, busy_poll_usecs) == 0 &&
                  __builtin_offsetof(struct epoll_params, busy_poll_budget) == 4 &&
                  __builtin_offsetof(struct epoll_params, prefer_busy_poll) == 6 &&
                  __builtin_offsetof(struct epoll_params, __pad) == 7,
              "x86 epoll parameter offsets");

static_assert(EPOLL_CLOEXEC == O_CLOEXEC && EPOLL_NONBLOCK == O_NONBLOCK,
              "epoll creation flags");
static_assert(EPOLLIN == 0x001 && EPOLLPRI == 0x002 && EPOLLOUT == 0x004 &&
                  EPOLLERR == 0x008 && EPOLLHUP == 0x010 && EPOLLNVAL == 0x020 &&
                  EPOLLRDNORM == 0x040 && EPOLLRDBAND == 0x080 &&
                  EPOLLWRNORM == 0x100 && EPOLLWRBAND == 0x200 && EPOLLMSG == 0x400,
              "epoll readiness constants");
static_assert(EPOLLRDHUP == 0x2000 && EPOLLEXCLUSIVE == (1U << 28) &&
                  EPOLLWAKEUP == (1U << 29) && EPOLLONESHOT == (1U << 30) &&
                  EPOLLET == (1U << 31),
              "epoll behavior constants");
static_assert(EPOLL_CTL_ADD == 1 && EPOLL_CTL_DEL == 2 && EPOLL_CTL_MOD == 3,
              "epoll control constants");
static_assert(_IOC_NONE == 0U && _IOC_WRITE == 1U && _IOC_READ == 2U,
              "selected generic ioctl directions");
static_assert(EPIOCSPARAMS == 0x40088a01U && EPIOCGPARAMS == 0x80088a02U,
              "epoll parameter ioctl encodings");
static_assert(EPIOCSPARAMS == _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params) &&
                  EPIOCGPARAMS == _IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params),
              "epoll parameter ioctl composition");

using epoll_create_signature = int (*)(int);
using epoll_ctl_signature = int (*)(int, int, int, struct epoll_event *);
using epoll_wait_signature = int (*)(int, struct epoll_event *, int, int);
using epoll_pwait_signature = int (*)(int, struct epoll_event *, int, int,
                                      const sigset_t *);

static_assert(__is_same(decltype(&epoll_create), epoll_create_signature),
              "epoll_create C++ declaration");
static_assert(__is_same(decltype(&epoll_create1), epoll_create_signature),
              "epoll_create1 C++ declaration");
static_assert(__is_same(decltype(&epoll_ctl), epoll_ctl_signature),
              "epoll_ctl C++ declaration");
static_assert(__is_same(decltype(&epoll_wait), epoll_wait_signature),
              "epoll_wait C++ declaration");
static_assert(__is_same(decltype(&epoll_pwait), epoll_pwait_signature),
              "epoll_pwait C++ declaration");

extern "C" int epoll_create(int);
extern "C" int epoll_create1(int);
extern "C" int epoll_ctl(int, int, int, struct epoll_event *);
extern "C" int epoll_wait(int, struct epoll_event *, int, int);
extern "C" int epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);
