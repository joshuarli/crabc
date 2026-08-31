/* Pinned-musl/project Linux/x86-64 timer_gettime declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <time.h>

#if defined(CRABC_TIMER_GETTIME_EXPECT_HIDDEN)
/* This branch is compiled only when strict C11 must hide the POSIX name. */
int crabc_x86_64_timer_gettime_header_abi_hidden_probe(void)
{
    return timer_gettime((timer_t)0, (struct itimerspec *)0);
}
#else
typedef int (*timer_gettime_signature)(timer_t, struct itimerspec *);

_Static_assert(sizeof(timer_t) == 8 && _Alignof(timer_t) == 8,
    "x86 opaque timer_t ABI");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec ABI");
_Static_assert(sizeof(struct itimerspec) == 32 &&
    _Alignof(struct itimerspec) == 8, "x86 itimerspec ABI");
_Static_assert(__builtin_offsetof(struct itimerspec, it_interval) == 0,
    "x86 itimerspec interval offset");
_Static_assert(__builtin_offsetof(struct itimerspec, it_value) == 16,
    "x86 itimerspec value offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timer_gettime),
    timer_gettime_signature), "timer_gettime declaration");

static timer_gettime_signature timer_gettime_function __attribute__((used)) =
    timer_gettime;

int crabc_x86_64_timer_gettime_header_abi_probe(void)
{
    return timer_gettime_function != (timer_gettime_signature)0 ? 0 : 1;
}
#endif
