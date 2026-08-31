/* C++ companion for the Linux/x86-64 sched_getparam ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sched.h>

using sched_getparam_signature = int (*)(pid_t, struct sched_param *);

static_assert(__is_same(decltype(&sched_getparam),
    sched_getparam_signature), "sched_getparam declaration");
static_assert(sizeof(pid_t) == 4 && alignof(pid_t) == 4, "x86 pid_t ABI");
static_assert(sizeof(sched_param) == 48 && alignof(sched_param) == 8,
    "x86 sched_param ABI");
static_assert(__builtin_offsetof(sched_param, sched_priority) == 0 &&
    __builtin_offsetof(sched_param, __reserved1) == 4 &&
    __builtin_offsetof(sched_param, __reserved2) == 8 &&
    __builtin_offsetof(sched_param, __reserved3) == 40,
    "x86 sched_param layout");
static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "POSIX scheduler policy values");

extern "C" void crabc_sched_getparam_linkage_witness()
{
    static volatile sched_getparam_signature witness = &sched_getparam;
    (void)witness;
}
