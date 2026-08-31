/* Native Linux/x86-64 C11 <sched.h> sched_yield declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

typedef int (*sched_yield_signature)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_yield),
    sched_yield_signature), "sched_yield declaration");

static sched_yield_signature sched_yield_function = sched_yield;

int crabc_x86_64_sched_yield_header_abi_probe(void)
{
    return sched_yield_function != 0 ? 0 : 1;
}
