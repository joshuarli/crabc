/* Native Linux/x86-64 C++17 <sched.h> priority-bound linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

using sched_priority_bound_signature = int (*)(int);

static_assert(__is_same(decltype(&sched_get_priority_max),
    sched_priority_bound_signature), "sched_get_priority_max declaration");
static_assert(__is_same(decltype(&sched_get_priority_min),
    sched_priority_bound_signature), "sched_get_priority_min declaration");

/* Retain both undefined external-C references for the linkage check. */
static volatile sched_priority_bound_signature sched_priority_maximum =
    sched_get_priority_max;
static volatile sched_priority_bound_signature sched_priority_minimum =
    sched_get_priority_min;

int crabc_x86_64_sched_priority_bounds_header_abi_probe_cpp()
{
    return sched_priority_maximum == nullptr || sched_priority_minimum == nullptr;
}
