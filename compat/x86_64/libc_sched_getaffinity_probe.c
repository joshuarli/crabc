/*
 * Pinned-musl Linux/x86-64 sched_getaffinity differential body.
 *
 * Musl's GNU C wrapper sends the raw thread selector, byte count, and writable
 * cpu_set_t to syscall 204. Linux returns the initialized prefix length; musl
 * converts success to zero and clears only the remaining caller-owned tail.
 * The same body proves that direct raw prefix/tail contract, then runs through
 * pinned musl and the static candidate without selecting affinity mutation.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8,
    "x86 size_t ABI");
_Static_assert(sizeof(cpu_set_t) == 128 && _Alignof(cpu_set_t) == 8,
    "x86 cpu_set_t ABI");
_Static_assert(offsetof(cpu_set_t, __bits) == 0 &&
    sizeof(((cpu_set_t *)0)->__bits) == 128,
    "x86 cpu_set_t layout");
_Static_assert(SYS_sched_getaffinity == 204,
    "Linux 5.10 x86 sched_getaffinity syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_getaffinity),
    int (*)(pid_t, size_t, cpu_set_t *)), "sched_getaffinity declaration");

static long raw_sched_getaffinity(pid_t pid, size_t size, cpu_set_t *mask)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_sched_getaffinity), "D"((long)pid), "S"(size),
          "d"(mask)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static void fill_mask(cpu_set_t *mask)
{
    unsigned char *bytes = (unsigned char *)mask;
    size_t offset;

    for (offset = 0; offset < sizeof(*mask); offset++)
        bytes[offset] = 0xa5;
}

static int raw_prefix_matches(const cpu_set_t *raw, const cpu_set_t *normalized,
    size_t initialized)
{
    const unsigned char *raw_bytes = (const unsigned char *)raw;
    const unsigned char *normalized_bytes = (const unsigned char *)normalized;
    size_t offset;

    for (offset = 0; offset < initialized; offset++)
        if (raw_bytes[offset] != normalized_bytes[offset])
            return 0;
    return 1;
}

static int tail_is_zero(const cpu_set_t *mask, size_t initialized)
{
    const unsigned char *bytes = (const unsigned char *)mask;
    size_t offset;

    for (offset = initialized; offset < sizeof(*mask); offset++)
        if (bytes[offset] != 0)
            return 0;
    return 1;
}

static int tail_is_unchanged(const cpu_set_t *mask, size_t initialized)
{
    const unsigned char *bytes = (const unsigned char *)mask;
    size_t offset;

    for (offset = initialized; offset < sizeof(*mask); offset++)
        if (bytes[offset] != 0xa5)
            return 0;
    return 1;
}

static int mask_is_unchanged(const cpu_set_t *mask)
{
    return tail_is_unchanged(mask, 0);
}

static int check_current_task(int failure)
{
    cpu_set_t raw_mask;
    cpu_set_t normalized_mask;
    long initialized;

    fill_mask(&raw_mask);
    errno = ERANGE;
    initialized = raw_sched_getaffinity(0, sizeof(raw_mask), &raw_mask);
    if (initialized <= 0 || initialized > (long)sizeof(raw_mask))
        return failure;
    if (errno != ERANGE)
        return failure + 1;
    if (!tail_is_unchanged(&raw_mask, (size_t)initialized))
        return failure + 2;

    fill_mask(&normalized_mask);
    errno = ERANGE;
    if (sched_getaffinity(0, sizeof(normalized_mask), &normalized_mask) != 0)
        return failure + 3;
    if (errno != ERANGE)
        return failure + 4;
    if (!raw_prefix_matches(&raw_mask, &normalized_mask, (size_t)initialized))
        return failure + 5;
    if (!tail_is_zero(&normalized_mask, (size_t)initialized))
        return failure + 6;
    return 0;
}

static int check_invalid_capacity(int failure)
{
    cpu_set_t mask;

    fill_mask(&mask);
    errno = ERANGE;
    if (sched_getaffinity(0, 1, &mask) != -1)
        return failure;
    if (errno != EINVAL)
        return failure + 1;
    return mask_is_unchanged(&mask) ? 0 : failure + 2;
}

static int check_missing_task(int failure)
{
    cpu_set_t mask;

    fill_mask(&mask);
    errno = ERANGE;
    if (sched_getaffinity(INT_MAX, sizeof(mask), &mask) != -1)
        return failure;
    if (errno != ESRCH)
        return failure + 1;
    return mask_is_unchanged(&mask) ? 0 : failure + 2;
}

static int check_null_mask(int failure)
{
    errno = ERANGE;
    if (sched_getaffinity(0, sizeof(cpu_set_t), NULL) != -1)
        return failure;
    return errno == EFAULT ? 0 : failure + 1;
}

int crabc_x86_64_sched_getaffinity_probe(void)
{
    int failure = check_current_task(10);

    if (failure)
        return failure;
    failure = check_invalid_capacity(20);
    if (failure)
        return failure;
    failure = check_missing_task(30);
    if (failure)
        return failure;
    return check_null_mask(40);
}

#ifndef CRABC_SCHED_GETAFFINITY_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_getaffinity_probe();
}
#endif
