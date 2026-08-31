/* C++17 companion for the selected Linux/x86-64 <sys/timerfd.h> ABI. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/timerfd.h>

using timerfd_create_signature = int (*)(int, int);
using timerfd_settime_signature = int (*)(
    int, int, const struct itimerspec *, struct itimerspec *);
using timerfd_gettime_signature = int (*)(int, struct itimerspec *);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define CRABC_TIMERFD_ITIMERSPEC_VISIBLE 1
#endif

static_assert(TFD_NONBLOCK == O_NONBLOCK && TFD_NONBLOCK == 0x800,
              "C++ x86 timerfd nonblocking flag");
static_assert(TFD_CLOEXEC == O_CLOEXEC && TFD_CLOEXEC == 0x80000,
              "C++ x86 timerfd close-on-exec flag");
static_assert(TFD_TIMER_ABSTIME == 1 && TFD_TIMER_CANCEL_ON_SET == 2,
              "C++ x86 timerfd settime flags");
#ifdef CRABC_TIMERFD_ITIMERSPEC_VISIBLE
static_assert(sizeof(struct timespec) == 16 && alignof(struct timespec) == 8,
              "C++ x86 timespec size/alignment");
static_assert(sizeof(struct itimerspec) == 32 &&
                  alignof(struct itimerspec) == 8 &&
                  __builtin_offsetof(struct itimerspec, it_interval) == 0 &&
                  __builtin_offsetof(struct itimerspec, it_value) == 16,
              "C++ x86 itimerspec layout");
#endif
static_assert(__is_same(decltype(&timerfd_create), timerfd_create_signature),
              "C++ timerfd_create declaration");
static_assert(__is_same(decltype(&timerfd_settime), timerfd_settime_signature),
              "C++ timerfd_settime declaration");
static_assert(__is_same(decltype(&timerfd_gettime), timerfd_gettime_signature),
              "C++ timerfd_gettime declaration");

__attribute__((used)) static timerfd_create_signature timerfd_create_cxx_reference =
    timerfd_create;
__attribute__((used)) static timerfd_settime_signature timerfd_settime_cxx_reference =
    timerfd_settime;
__attribute__((used)) static timerfd_gettime_signature timerfd_gettime_cxx_reference =
    timerfd_gettime;

int crabc_x86_64_timerfd_header_abi_probe_cpp()
{
#ifdef CRABC_TIMERFD_ITIMERSPEC_VISIBLE
    return (int)sizeof(struct itimerspec);
#else
    return 0;
#endif
}
