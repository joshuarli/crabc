/* Pinned-musl Linux/x86-64 sched_setaffinity(2) reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(pid_t) == 4, "x86 pid_t size");
_Static_assert(sizeof(cpu_set_t) == 128, "x86 cpu_set_t size");
_Static_assert(_Alignof(cpu_set_t) == 8, "x86 cpu_set_t alignment");
_Static_assert(SYS_sched_setaffinity == 203,
               "x86 sched_setaffinity syscall number");
_Static_assert(SYS_sched_getaffinity == 204,
               "x86 sched_getaffinity syscall number");

static int has_set_bit(const cpu_set_t *mask)
{
    const unsigned char *value = (const unsigned char *)mask;
    for (size_t index = 0; index < sizeof(*mask); ++index) {
        if (value[index] != 0)
            return 1;
    }
    return 0;
}

static int no_bits_outside(const cpu_set_t *value, const cpu_set_t *allowed)
{
    const unsigned char *actual = (const unsigned char *)value;
    const unsigned char *limit = (const unsigned char *)allowed;
    for (size_t index = 0; index < sizeof(*value); ++index) {
        if ((actual[index] & (unsigned char)~limit[index]) != 0)
            return 0;
    }
    return 1;
}

static int first_set_cpu(const cpu_set_t *mask)
{
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, mask))
            return cpu;
    }
    return -1;
}

static int is_single_cpu(const cpu_set_t *mask, int expected_cpu)
{
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if ((CPU_ISSET(cpu, mask) != 0) != (cpu == expected_cpu))
            return 0;
    }
    return 1;
}

static int verify_child_singleton(const cpu_set_t *observed)
{
    int cpu = first_set_cpu(observed);
    cpu_set_t singleton;
    cpu_set_t after_raw;
    cpu_set_t after_musl;
    long raw_length;

    if (cpu < 0)
        return 1;
    CPU_ZERO(&singleton);
    CPU_SET(cpu, &singleton);

    if (syscall(SYS_sched_setaffinity, 0, sizeof(singleton), &singleton) != 0)
        return 2;
    CPU_ZERO(&after_raw);
    raw_length =
        syscall(SYS_sched_getaffinity, 0, sizeof(after_raw), &after_raw);
    if (raw_length <= 0 || (size_t)raw_length > sizeof(after_raw) ||
        !is_single_cpu(&after_raw, cpu))
        return 3;

    if (sched_setaffinity(0, sizeof(singleton), &singleton) != 0)
        return 4;
    CPU_ZERO(&after_musl);
    if (sched_getaffinity(0, sizeof(after_musl), &after_musl) != 0 ||
        !is_single_cpu(&after_musl, cpu))
        return 5;

    return 0;
}

int main(void)
{
    cpu_set_t observed;
    cpu_set_t after_musl;
    cpu_set_t after_direct;
    cpu_set_t empty;

    CPU_ZERO(&observed);
    errno = 0;
    if (sched_getaffinity(0, sizeof(observed), &observed) != 0 ||
        !has_set_bit(&observed))
        return 10;

    errno = 0;
    if (sched_setaffinity(0, sizeof(observed), &observed) != 0)
        return 11;

    CPU_ZERO(&after_musl);
    if (sched_getaffinity(0, sizeof(after_musl), &after_musl) != 0 ||
        !no_bits_outside(&after_musl, &observed) ||
        memcmp(&after_musl, &observed, sizeof(observed)) != 0)
        return 12;

    errno = 0;
    if (syscall(SYS_sched_setaffinity, 0, sizeof(observed), &observed) != 0)
        return 13;

    CPU_ZERO(&after_direct);
    long direct_after_length =
        syscall(SYS_sched_getaffinity, 0, sizeof(after_direct), &after_direct);
    if (direct_after_length <= 0 ||
        (size_t)direct_after_length > sizeof(after_direct) ||
        !no_bits_outside(&after_direct, &observed) ||
        memcmp(&after_direct, &observed, sizeof(observed)) != 0)
        return 14;

    pid_t child = fork();
    if (child < 0)
        return 15;
    if (child == 0)
        _exit(verify_child_singleton(&observed));

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 16;

    CPU_ZERO(&empty);
    errno = 0;
    if (sched_setaffinity(0, sizeof(empty), &empty) != -1 || errno != EINVAL)
        return 20;

    errno = 0;
    if (syscall(SYS_sched_setaffinity, 0, sizeof(empty), &empty) != -1 ||
        errno != EINVAL)
        return 21;

    errno = 0;
    if (sched_setaffinity((pid_t)INT_MAX, sizeof(observed), &observed) != -1 ||
        errno != ESRCH)
        return 30;

    errno = 0;
    if (syscall(SYS_sched_setaffinity, (pid_t)INT_MAX, sizeof(observed),
                &observed) != -1 || errno != ESRCH)
        return 31;

    puts("layout=cpu-set128/8 syscall=203 current=musl-success/raw-success subset=child-singleton postcondition-not-broadened empty=EINVAL missing=ESRCH");
    return 0;
}
