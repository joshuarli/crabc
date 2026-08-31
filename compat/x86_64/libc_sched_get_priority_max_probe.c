/* Static crabc-libc x86-64 selected sched_get_priority_max fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a dependency-free -nostdlib -static candidate linked only with the
 * selected crabc archive. It exercises the fixed Linux SCHED_OTHER/FIFO/RR
 * query results and one rejected invalid policy. It does not select the
 * priority-minimum sibling, policy mutation/parameters, affinity, scheduling
 * guarantees, a thread runtime, process lifecycle, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>

typedef int (*sched_get_priority_max_signature)(int);

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SCHED_OTHER == 0 && SCHED_FIFO == 1 && SCHED_RR == 2,
    "Linux scheduler policy values");
_Static_assert(SYS_sched_get_priority_max == 146,
    "x86 sched_get_priority_max syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_get_priority_max),
    sched_get_priority_max_signature), "sched_get_priority_max declaration");

static volatile sched_get_priority_max_signature sched_get_priority_max_function =
    sched_get_priority_max;

static int check_success(int policy, int expected, int stale_errno)
{
    errno = stale_errno;
    if (sched_get_priority_max_function(policy) != expected)
        return 1;
    return errno == stale_errno ? 0 : 2;
}

static int check_invalid_policy(void)
{
    errno = E2BIG;
    if (sched_get_priority_max_function(-1) != -1)
        return 1;
    return errno == EINVAL ? 0 : 2;
}

int crabc_x86_64_sched_get_priority_max_probe(void)
{
    int status = check_success(SCHED_OTHER, 0, E2BIG);

    if (status != 0)
        return 10 + status;
    status = check_success(SCHED_FIFO, 99, ERANGE);
    if (status != 0)
        return 20 + status;
    status = check_success(SCHED_RR, 99, EILSEQ);
    if (status != 0)
        return 30 + status;
    status = check_invalid_policy();
    return status == 0 ? 0 : 40 + status;
}

#ifndef CRABC_SCHED_GET_PRIORITY_MAX_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_get_priority_max_probe();
}
#endif
