/* Native Linux/x86-64 C11 <sched.h> priority-bound declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

typedef int (*sched_priority_bound_signature)(int);

_Static_assert(__builtin_types_compatible_p(
    __typeof__(&sched_get_priority_max), sched_priority_bound_signature),
    "sched_get_priority_max declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&sched_get_priority_min), sched_priority_bound_signature),
    "sched_get_priority_min declaration");

static volatile sched_priority_bound_signature sched_priority_maximum =
    sched_get_priority_max;
static volatile sched_priority_bound_signature sched_priority_minimum =
    sched_get_priority_min;

int crabc_x86_64_sched_priority_bounds_header_abi_probe(void)
{
    return sched_priority_maximum == 0 || sched_priority_minimum == 0;
}
