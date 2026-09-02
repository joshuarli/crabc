/*
 * Pinned-musl Linux/x86-64 sched_setaffinity differential body.
 *
 * Musl's GNU C wrapper forwards its signed task selector, byte count, and
 * read-only cpu_set_t to syscall 203, then translates raw Linux errors to
 * C -1/errno while leaving errno untouched on success. The candidate fixture
 * obtains its valid current mask through a fixture-local raw syscall 204 so
 * that linking it selects only sched_setaffinity from the static archive.
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
_Static_assert(SYS_sched_setaffinity == 203,
    "Linux 5.10 x86 sched_setaffinity syscall number");
_Static_assert(SYS_sched_getaffinity == 204,
    "Linux 5.10 x86 sched_getaffinity syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_setaffinity),
    int (*)(pid_t, size_t, const cpu_set_t *)),
    "sched_setaffinity declaration");

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

static void zero_mask(cpu_set_t *mask)
{
    unsigned char *bytes = (unsigned char *)mask;
    size_t offset;

    for (offset = 0; offset < sizeof(*mask); offset++)
        bytes[offset] = 0;
}

static void copy_mask(cpu_set_t *destination, const cpu_set_t *source)
{
    unsigned char *output = (unsigned char *)destination;
    const unsigned char *input = (const unsigned char *)source;
    size_t offset;

    for (offset = 0; offset < sizeof(*destination); offset++)
        output[offset] = input[offset];
}

static int mask_is_unchanged(const cpu_set_t *actual, const cpu_set_t *before)
{
    const unsigned char *actual_bytes = (const unsigned char *)actual;
    const unsigned char *before_bytes = (const unsigned char *)before;
    size_t offset;

    for (offset = 0; offset < sizeof(*actual); offset++)
        if (actual_bytes[offset] != before_bytes[offset])
            return 0;
    return 1;
}

static int has_set_bit(const cpu_set_t *mask)
{
    const unsigned char *bytes = (const unsigned char *)mask;
    size_t offset;

    for (offset = 0; offset < sizeof(*mask); offset++)
        if (bytes[offset] != 0)
            return 1;
    return 0;
}

static int no_bits_outside(const cpu_set_t *actual, const cpu_set_t *allowed)
{
    const unsigned char *actual_bytes = (const unsigned char *)actual;
    const unsigned char *allowed_bytes = (const unsigned char *)allowed;
    size_t offset;

    for (offset = 0; offset < sizeof(*actual); offset++)
        if ((actual_bytes[offset] & (unsigned char)~allowed_bytes[offset]) != 0)
            return 0;
    return 1;
}

static int read_current_nonempty_mask(cpu_set_t *mask)
{
    long initialized;

    zero_mask(mask);
    initialized = raw_sched_getaffinity(0, sizeof(*mask), mask);
    return initialized > 0 && initialized <= (long)sizeof(*mask) &&
        has_set_bit(mask);
}

static int check_current_task(int failure)
{
    cpu_set_t observed;
    cpu_set_t before;
    cpu_set_t after;

    if (!read_current_nonempty_mask(&observed))
        return failure;
    copy_mask(&before, &observed);
    errno = ERANGE;
    if (sched_setaffinity(0, sizeof(observed), &observed) != 0)
        return failure + 1;
    if (errno != ERANGE)
        return failure + 2;
    if (!mask_is_unchanged(&observed, &before))
        return failure + 3;

    if (!read_current_nonempty_mask(&after))
        return failure + 4;
    return no_bits_outside(&after, &before) ? 0 : failure + 5;
}

static int check_empty_mask(int failure)
{
    cpu_set_t empty;
    cpu_set_t before;

    zero_mask(&empty);
    copy_mask(&before, &empty);
    errno = ERANGE;
    if (sched_setaffinity(0, sizeof(empty), &empty) != -1)
        return failure;
    if (errno != EINVAL)
        return failure + 1;
    return mask_is_unchanged(&empty, &before) ? 0 : failure + 2;
}

static int check_missing_task(int failure)
{
    cpu_set_t observed;
    cpu_set_t before;

    if (!read_current_nonempty_mask(&observed))
        return failure;
    copy_mask(&before, &observed);
    errno = ERANGE;
    if (sched_setaffinity(INT_MAX, sizeof(observed), &observed) != -1)
        return failure + 1;
    if (errno != ESRCH)
        return failure + 2;
    return mask_is_unchanged(&observed, &before) ? 0 : failure + 3;
}

static int check_null_mask(int failure)
{
    errno = ERANGE;
    if (sched_setaffinity(0, sizeof(cpu_set_t), NULL) != -1)
        return failure;
    return errno == EFAULT ? 0 : failure + 1;
}

int crabc_x86_64_sched_setaffinity_probe(void)
{
    int failure = check_current_task(10);

    if (failure)
        return failure;
    failure = check_empty_mask(20);
    if (failure)
        return failure;
    failure = check_missing_task(30);
    if (failure)
        return failure;
    return check_null_mask(40);
}

#ifndef CRABC_SCHED_SETAFFINITY_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_setaffinity_probe();
}
#endif
