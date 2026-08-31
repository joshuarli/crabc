/* Pinned-musl/project Linux/x86-64 timer_gettime C++ declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <time.h>

#if defined(CRABC_TIMER_GETTIME_EXPECT_HIDDEN)
/* This branch is compiled only when strict C++17 must hide the POSIX name. */
int crabc_x86_64_timer_gettime_header_abi_hidden_probe_cpp()
{
    return timer_gettime((timer_t)nullptr, nullptr);
}
#else
using timer_gettime_signature = int (*)(timer_t, struct itimerspec *);

static_assert(sizeof(timer_t) == 8 && alignof(timer_t) == 8,
    "x86 opaque timer_t ABI");
static_assert(sizeof(struct timespec) == 16 && alignof(struct timespec) == 8,
    "x86 timespec ABI");
static_assert(sizeof(struct itimerspec) == 32 &&
    alignof(struct itimerspec) == 8, "x86 itimerspec ABI");
static_assert(__builtin_offsetof(struct itimerspec, it_interval) == 0,
    "x86 itimerspec interval offset");
static_assert(__builtin_offsetof(struct itimerspec, it_value) == 16,
    "x86 itimerspec value offset");
static_assert(__is_same(decltype(&timer_gettime), timer_gettime_signature),
    "timer_gettime declaration");

static timer_gettime_signature timer_gettime_function __attribute__((used)) =
    timer_gettime;

int crabc_x86_64_timer_gettime_header_abi_probe_cpp()
{
    return timer_gettime_function != nullptr ? 0 : 1;
}
#endif
