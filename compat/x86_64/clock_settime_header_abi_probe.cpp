/* Pinned-musl/project Linux/x86-64 clock_settime C++ declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <time.h>

#if defined(CRABC_CLOCK_SETTIME_EXPECT_HIDDEN)
/* This branch is compiled only when strict C++ must hide the POSIX name. */
int crabc_x86_64_clock_settime_header_abi_hidden_probe_cpp()
{
    return clock_settime(0, nullptr);
}
#else
using clock_settime_signature = int (*)(clockid_t, const struct timespec *);

static_assert(__is_same(decltype(&clock_settime), clock_settime_signature),
    "clock_settime declaration");

static clock_settime_signature clock_settime_function __attribute__((used)) =
    clock_settime;

int crabc_x86_64_clock_settime_header_abi_probe_cpp()
{
    return clock_settime_function != nullptr ? 0 : 1;
}
#endif
