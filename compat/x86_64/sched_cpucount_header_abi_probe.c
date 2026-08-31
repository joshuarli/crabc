/* Native Linux/x86-64 GNU <sched.h> CPU-count helper declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>

#ifndef CPU_COUNT_S
#error "CPU_COUNT_S must be visible under _GNU_SOURCE"
#endif
#ifndef CPU_COUNT
#error "CPU_COUNT must be visible under _GNU_SOURCE"
#endif

typedef int (*sched_cpucount_signature)(size_t, const cpu_set_t *);

_Static_assert(sizeof(cpu_set_t) == 128, "musl cpu_set_t width");
_Static_assert(_Alignof(cpu_set_t) == _Alignof(unsigned long),
    "musl cpu_set_t alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__sched_cpucount),
    sched_cpucount_signature), "__sched_cpucount declaration");

static cpu_set_t zero_set;
/* Preserve an externally callable GNU C ABI reference in the object. */
static volatile sched_cpucount_signature sched_cpucount_function =
    __sched_cpucount;

int crabc_x86_64_sched_cpucount_header_abi_probe(void)
{
    return sched_cpucount_function == 0 ||
        CPU_COUNT_S(sizeof(zero_set), &zero_set) != 0 ||
        CPU_COUNT(&zero_set) != 0;
}
