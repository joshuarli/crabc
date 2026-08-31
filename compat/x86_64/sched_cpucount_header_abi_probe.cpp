/* Native Linux/x86-64 GNU <sched.h> CPU-count helper linkage probe. */

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

using sched_cpucount_signature = int (*)(size_t, const cpu_set_t *);

static_assert(sizeof(cpu_set_t) == 128, "musl cpu_set_t width");
static_assert(alignof(cpu_set_t) == alignof(unsigned long),
    "musl cpu_set_t alignment");
static_assert(__is_same(decltype(&__sched_cpucount), sched_cpucount_signature),
    "__sched_cpucount declaration");

static cpu_set_t zero_set;
/* Retain one undefined external-C reference for the linkage check. */
static volatile sched_cpucount_signature sched_cpucount_function =
    __sched_cpucount;

int crabc_x86_64_sched_cpucount_header_abi_probe_cpp()
{
    return sched_cpucount_function == nullptr ||
        CPU_COUNT_S(sizeof(zero_set), &zero_set) != 0 ||
        CPU_COUNT(&zero_set) != 0;
}
