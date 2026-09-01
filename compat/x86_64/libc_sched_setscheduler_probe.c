/*
 * Pinned-musl Linux/x86-64 sched_setscheduler differential body.
 *
 * Musl intentionally turns this POSIX process-facing scheduler-policy
 * operation into -1/ENOSYS instead of forwarding Linux's thread-scoped raw
 * syscall 144. The common body only issues that raw syscall against an
 * impossible pid with a valid SCHED_OTHER parameter, proving its
 * non-mutating ESRCH contrast. It then proves the C ABI preserves musl's
 * result for current, invalid, and missing pid-shaped inputs, policies, and
 * pointers without modifying a record or dereferencing a null pointer.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>

typedef int (*sched_setscheduler_signature)(
    pid_t, int, const struct sched_param *);

_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(struct sched_param) == 48 &&
    _Alignof(struct sched_param) == 8, "x86 sched_param ABI");
_Static_assert(offsetof(struct sched_param, sched_priority) == 0 &&
    offsetof(struct sched_param, __reserved3) == 40,
    "x86 sched_param layout");
_Static_assert(SYS_sched_setscheduler == 144,
    "Linux 5.10 x86 sched_setscheduler syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_setscheduler),
    sched_setscheduler_signature), "sched_setscheduler declaration");

static long raw_sched_setscheduler(
    pid_t pid, int policy, const struct sched_param *parameter)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_sched_setscheduler), "D"((long)pid),
          "S"((long)policy), "d"(parameter)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static void fill_param(struct sched_param *parameter)
{
    unsigned char *bytes = (unsigned char *)parameter;
    size_t offset;

    for (offset = 0; offset < sizeof(*parameter); offset++)
        bytes[offset] = 0xa5;
}

static int param_is_unchanged(const struct sched_param *parameter)
{
    const unsigned char *bytes = (const unsigned char *)parameter;
    size_t offset;

    for (offset = 0; offset < sizeof(*parameter); offset++)
        if (bytes[offset] != 0xa5)
            return 0;
    return 1;
}

static int check_musl_process_api(
    pid_t pid, int policy, sched_setscheduler_signature function, int failure)
{
    struct sched_param parameter;

    fill_param(&parameter);
    errno = ERANGE;
    if (function(pid, policy, &parameter) != -1)
        return failure;
    if (errno != ENOSYS)
        return failure + 1;
    if (!param_is_unchanged(&parameter))
        return failure + 2;
    return 0;
}

static int check_musl_null_parameter(
    pid_t pid, int policy, sched_setscheduler_signature function, int failure)
{
    errno = ERANGE;
    if (function(pid, policy, NULL) != -1)
        return failure;
    if (errno != ENOSYS)
        return failure + 1;
    return 0;
}

int crabc_x86_64_sched_setscheduler_probe(void)
{
    const struct sched_param raw_parameter = { 0 };
    sched_setscheduler_signature function = sched_setscheduler;
    int failure;

    /* Linux pid_max is below INT_MAX. Passing that impossible task id with a
     * valid SCHED_OTHER parameter observes raw ESRCH without mutating a task
     * or choosing a scheduler policy. This is deliberately not the POSIX
     * process API that musl exposes. */
    errno = ERANGE;
    if (raw_sched_setscheduler(INT_MAX, SCHED_OTHER, &raw_parameter) != -ESRCH ||
        errno != ERANGE)
        return 1;

    failure = check_musl_process_api(0, SCHED_OTHER, function, 10);
    if (failure)
        return failure;
    failure = check_musl_process_api((pid_t)-1, SCHED_FIFO, function, 20);
    if (failure)
        return failure;
    failure = check_musl_process_api(INT_MAX, INT_MAX, function, 30);
    if (failure)
        return failure;
    failure = check_musl_null_parameter(0, SCHED_OTHER, function, 40);
    if (failure)
        return failure;
    failure = check_musl_null_parameter((pid_t)-1, SCHED_FIFO, function, 50);
    if (failure)
        return failure;
    return check_musl_null_parameter(INT_MAX, -1, function, 60);
}

#ifndef CRABC_SCHED_SETSCHEDULER_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_setscheduler_probe();
}
#endif
