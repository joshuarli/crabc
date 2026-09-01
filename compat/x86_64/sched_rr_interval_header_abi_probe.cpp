/* C++ companion for the Linux/x86-64 sched_rr_get_interval ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sched.h>

using sched_rr_get_interval_signature = int (*)(pid_t, struct timespec *);

static_assert(__is_same(decltype(&sched_rr_get_interval),
    sched_rr_get_interval_signature), "sched_rr_get_interval declaration");
static_assert(sizeof(pid_t) == 4 && alignof(pid_t) == 4, "x86 pid_t ABI");
static_assert(sizeof(struct timespec) == 16 && alignof(struct timespec) == 8,
    "x86 timespec ABI");
static_assert(__builtin_offsetof(struct timespec, tv_sec) == 0 &&
    __builtin_offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec member offsets");
static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "POSIX scheduler policy values");

extern "C" void crabc_sched_rr_interval_linkage_witness()
{
    static volatile sched_rr_get_interval_signature witness =
        &sched_rr_get_interval;
    (void)witness;
}
