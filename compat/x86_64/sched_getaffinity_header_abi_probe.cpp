/* GNU C++ companion for the Linux/x86-64 sched_getaffinity ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#ifndef _GNU_SOURCE
#error "this probe requires the GNU sched profile"
#endif

#include <sched.h>

using sched_getaffinity_signature = int (*)(pid_t, size_t, cpu_set_t *);

static_assert(__is_same(decltype(&sched_getaffinity),
    sched_getaffinity_signature), "sched_getaffinity declaration");
static_assert(sizeof(pid_t) == 4 && alignof(pid_t) == 4, "x86 pid_t ABI");
static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8, "x86 size_t ABI");
static_assert(sizeof(cpu_set_t) == 128 && alignof(cpu_set_t) == 8,
    "x86 cpu_set_t ABI");
static_assert(__builtin_offsetof(cpu_set_t, __bits) == 0 &&
    sizeof(((cpu_set_t *)0)->__bits) == 128,
    "x86 cpu_set_t layout");
extern "C" void crabc_sched_getaffinity_linkage_witness()
{
    static volatile sched_getaffinity_signature witness = &sched_getaffinity;
    (void)witness;
}
