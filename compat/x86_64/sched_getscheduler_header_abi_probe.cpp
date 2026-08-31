/* C++ companion for the Linux/x86-64 sched_getscheduler ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sched.h>

using sched_getscheduler_signature = int (*)(pid_t);

static_assert(__is_same(decltype(&sched_getscheduler),
    sched_getscheduler_signature), "sched_getscheduler declaration");
static_assert(sizeof(pid_t) == 4 && alignof(pid_t) == 4, "x86 pid_t ABI");
static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "POSIX scheduler policy values");

extern "C" void crabc_sched_getscheduler_linkage_witness()
{
    static volatile sched_getscheduler_signature witness = &sched_getscheduler;
    (void)witness;
}
