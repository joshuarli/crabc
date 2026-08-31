/* Static crabc-libc x86-64 scheduler-priority bounds fixture.
 *
 * The same project-header C body executes through pinned musl 1.2.6 and a
 * dependency-free -nostdlib -static candidate linked only with the selected
 * crabc archive. It selects only direct read-only priority minima/maxima for
 * SCHED_OTHER/FIFO/RR and invalid-policy errno translation. It is not policy
 * selection or mutation, current-policy/parameter observation, affinity,
 * scheduling progress, thread runtime, timer/clock, CRT, loader, sysroot, or
 * public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>

typedef int (*sched_priority_bound_signature)(int);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 && sizeof(int) == 4,
    "x86 LP64 scalar widths");
_Static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "selected Linux scheduler policy values");
_Static_assert(SYS_sched_get_priority_max == 146 &&
    SYS_sched_get_priority_min == 147,
    "x86 scheduler-priority syscall numbers");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&sched_get_priority_max), sched_priority_bound_signature),
    "sched_get_priority_max declaration");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&sched_get_priority_min), sched_priority_bound_signature),
    "sched_get_priority_min declaration");

static volatile sched_priority_bound_signature sched_priority_maximum =
    sched_get_priority_max;
static volatile sched_priority_bound_signature sched_priority_minimum =
    sched_get_priority_min;

static int check_bound_pair(int policy, int expected_minimum, int expected_maximum)
{
    errno = E2BIG;
    if (sched_priority_minimum(policy) != expected_minimum || errno != E2BIG)
        return 1;

    errno = EILSEQ;
    if (sched_priority_maximum(policy) != expected_maximum || errno != EILSEQ)
        return 2;
    return 0;
}

static int check_invalid_policy(void)
{
    errno = ERANGE;
    if (sched_priority_minimum(-1) != -1 || errno != EINVAL)
        return 1;

    errno = E2BIG;
    if (sched_priority_maximum(-1) != -1 || errno != EINVAL)
        return 2;
    return 0;
}

int crabc_x86_64_sched_priority_bounds_probe(void)
{
    int status = check_bound_pair(SCHED_OTHER, 0, 0);

    if (status != 0)
        return 10 + status;
    status = check_bound_pair(SCHED_FIFO, 1, 99);
    if (status != 0)
        return 20 + status;
    status = check_bound_pair(SCHED_RR, 1, 99);
    if (status != 0)
        return 30 + status;
    status = check_invalid_policy();
    return status == 0 ? 0 : 40 + status;
}

#ifndef CRABC_SCHED_PRIORITY_BOUNDS_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_priority_bounds_probe();
}
#endif
