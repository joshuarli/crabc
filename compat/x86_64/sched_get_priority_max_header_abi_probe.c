/* Pinned-musl/project Linux/x86-64 sched_get_priority_max C declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

typedef int (*sched_get_priority_max_signature)(int);

_Static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "Linux scheduler policy constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_get_priority_max),
    sched_get_priority_max_signature), "sched_get_priority_max declaration");

static sched_get_priority_max_signature sched_get_priority_max_function
    __attribute__((used)) = sched_get_priority_max;

int crabc_x86_64_sched_get_priority_max_header_abi_probe(void)
{
    return sched_get_priority_max_function != (sched_get_priority_max_signature)0
        ? 0 : 1;
}
