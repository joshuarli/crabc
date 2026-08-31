/*
 * Pinned-musl Linux/x86-64 sched_getscheduler differential body.
 *
 * Musl intentionally turns this POSIX process-facing scheduler observation
 * API into -1/ENOSYS instead of forwarding Linux's thread-scoped raw syscall
 * 145. The common body demonstrates the raw Linux distinction, then checks
 * that the C ABI preserves musl's result for current, invalid, and missing
 * pid-shaped inputs without selecting scheduler policy or lifecycle APIs.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(SYS_sched_getscheduler == 145,
    "Linux 5.10 x86 sched_getscheduler syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_getscheduler),
    int (*)(pid_t)), "sched_getscheduler declaration");

static long raw_sched_getscheduler(pid_t pid)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_sched_getscheduler), "D"((long)pid)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static int check_musl_process_api(pid_t pid, int failure)
{
    errno = ERANGE;
    if (sched_getscheduler(pid) != -1)
        return failure;
    if (errno != ENOSYS)
        return failure + 1;
    return 0;
}

int crabc_x86_64_sched_getscheduler_probe(void)
{
    int failure;

    /* Linux observes the calling thread at pid 0; this is deliberately not
     * the POSIX process API that musl exposes. The numeric policy is kernel
     * controlled, so only a nonnegative raw result and stale errno matter. */
    errno = ERANGE;
    if (raw_sched_getscheduler(0) < 0 || errno != ERANGE)
        return 1;

    errno = ERANGE;
    if (raw_sched_getscheduler((pid_t)-1) != -EINVAL || errno != ERANGE)
        return 2;

    failure = check_musl_process_api(0, 10);
    if (failure)
        return failure;
    failure = check_musl_process_api((pid_t)-1, 20);
    if (failure)
        return failure;
    return check_musl_process_api(INT_MAX, 30);
}

#ifndef CRABC_SCHED_GETSCHEDULER_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_getscheduler_probe();
}
#endif
