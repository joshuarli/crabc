/* Linux/x86-64 sched_getparam declaration, record, and ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sched.h>
#include <stddef.h>

typedef int (*sched_getparam_signature)(pid_t, struct sched_param *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_getparam),
    sched_getparam_signature), "sched_getparam declaration");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(struct sched_param) == 48 &&
    _Alignof(struct sched_param) == 8, "x86 sched_param ABI");
_Static_assert(offsetof(struct sched_param, sched_priority) == 0 &&
    offsetof(struct sched_param, __reserved1) == 4 &&
    offsetof(struct sched_param, __reserved2) == 8 &&
    offsetof(struct sched_param, __reserved3) == 40,
    "x86 sched_param layout");
_Static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "POSIX scheduler policy values");

static sched_getparam_signature sched_getparam_function = sched_getparam;

int crabc_x86_64_sched_getparam_header_abi_probe(void)
{
    struct sched_param parameter = { 0 };

    return sched_getparam_function(0, &parameter) == -1 ? 0 : 1;
}
