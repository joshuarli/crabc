/* Linux/x86-64 sched_rr_get_interval declaration and ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sched.h>

typedef int (*sched_rr_get_interval_signature)(pid_t, struct timespec *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_rr_get_interval),
    sched_rr_get_interval_signature), "sched_rr_get_interval declaration");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec ABI");
_Static_assert(__builtin_offsetof(struct timespec, tv_sec) == 0 &&
    __builtin_offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec member offsets");
_Static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "POSIX scheduler policy values");

static sched_rr_get_interval_signature sched_rr_get_interval_function =
    sched_rr_get_interval;

int crabc_x86_64_sched_rr_interval_header_abi_probe(void)
{
    struct timespec value = {0};

    return sched_rr_get_interval_function(0, &value) == -1 ? 0 : 1;
}
