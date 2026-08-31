/* Linux/x86-64 sched_getscheduler declaration and ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sched.h>

typedef int (*sched_getscheduler_signature)(pid_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_getscheduler),
    sched_getscheduler_signature), "sched_getscheduler declaration");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "POSIX scheduler policy values");

static sched_getscheduler_signature sched_getscheduler_function =
    sched_getscheduler;

int crabc_x86_64_sched_getscheduler_header_abi_probe(void)
{
    return sched_getscheduler_function(0) == -1 ? 0 : 1;
}
