/* Native Linux/x86-64 GNU <sched.h> sched_getcpu declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>
#include <sys/syscall.h>

typedef int (*sched_getcpu_signature)(void);

_Static_assert(SYS_getcpu == 309, "x86 getcpu syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_getcpu),
    sched_getcpu_signature), "sched_getcpu declaration");

/* Preserve an externally callable GNU C ABI reference in the object. */
static volatile sched_getcpu_signature sched_getcpu_function = sched_getcpu;

int crabc_x86_64_sched_getcpu_header_abi_probe(void)
{
    return sched_getcpu_function != 0 ? 0 : 1;
}
