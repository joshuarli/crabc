/* Pinned-musl/project Linux/x86-64 timer_getoverrun C++ declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <time.h>

#if defined(CRABC_TIMER_GETOVERRUN_EXPECT_HIDDEN)
/* This branch is compiled only when strict C++17 must hide the POSIX name. */
int crabc_x86_64_timer_getoverrun_header_abi_hidden_probe_cpp()
{
    return timer_getoverrun((timer_t)nullptr);
}
#else
using timer_getoverrun_signature = int (*)(timer_t);

static_assert(sizeof(timer_t) == 8 && alignof(timer_t) == 8,
    "x86 opaque timer_t ABI");
static_assert(__is_same(decltype(&timer_getoverrun), timer_getoverrun_signature),
    "timer_getoverrun declaration");

static timer_getoverrun_signature timer_getoverrun_function __attribute__((used)) =
    timer_getoverrun;

int crabc_x86_64_timer_getoverrun_header_abi_probe_cpp()
{
    return timer_getoverrun_function != nullptr ? 0 : 1;
}
#endif
