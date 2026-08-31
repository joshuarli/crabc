/* GNU Linux/x86-64 sched_getaffinity declaration, mask, and ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#ifndef _GNU_SOURCE
#error "this probe requires the GNU sched profile"
#endif

#include <sched.h>
#include <stddef.h>

typedef int (*sched_getaffinity_signature)(pid_t, size_t, cpu_set_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_getaffinity),
    sched_getaffinity_signature), "sched_getaffinity declaration");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8,
    "x86 size_t ABI");
_Static_assert(sizeof(cpu_set_t) == 128 && _Alignof(cpu_set_t) == 8,
    "x86 cpu_set_t ABI");
_Static_assert(offsetof(cpu_set_t, __bits) == 0 &&
    sizeof(((cpu_set_t *)0)->__bits) == 128,
    "x86 cpu_set_t layout");
static sched_getaffinity_signature sched_getaffinity_function = sched_getaffinity;

int crabc_x86_64_sched_getaffinity_header_abi_probe(void)
{
    cpu_set_t mask = { { 0 } };

    return sched_getaffinity_function(0, sizeof(mask), &mask) == -1 ? 0 : 1;
}
