/* Native Linux/x86-64 C++17 <sched.h> sched_yield linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

using sched_yield_signature = int (*)(void);

static_assert(__is_same(decltype(&sched_yield), sched_yield_signature),
    "sched_yield declaration");

/* Retain one undefined reference so the runner proves unmangled C linkage. */
static volatile sched_yield_signature sched_yield_function = sched_yield;

int crabc_x86_64_sched_yield_header_abi_probe_cpp()
{
    return sched_yield_function != nullptr ? 0 : 1;
}
