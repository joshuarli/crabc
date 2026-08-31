/* Pinned-musl/project Linux/x86-64 sched_get_priority_min C++ declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

using sched_get_priority_min_signature = int (*)(int);

static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "Linux scheduler policy constants");
static_assert(__is_same(decltype(&sched_get_priority_min),
    sched_get_priority_min_signature), "sched_get_priority_min declaration");

static sched_get_priority_min_signature sched_get_priority_min_function
    __attribute__((used)) = sched_get_priority_min;

int crabc_x86_64_sched_get_priority_min_header_abi_probe_cpp()
{
    return sched_get_priority_min_function != nullptr ? 0 : 1;
}
