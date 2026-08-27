/* Pinned-musl Linux/x86-64 sched_getaffinity(2) reference. */

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
#include <unistd.h>

struct guarded_mask {
    cpu_set_t value;
    unsigned char trailing[16];
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(pid_t) == 4, "x86 pid_t size");
_Static_assert(sizeof(cpu_set_t) == 128, "x86 cpu_set_t size");
_Static_assert(_Alignof(cpu_set_t) == 8, "x86 cpu_set_t alignment");
_Static_assert(SYS_sched_getaffinity == 204,
               "x86 sched_getaffinity syscall number");

static int unwritten_is_unchanged(const struct guarded_mask *mask, size_t length)
{
    const unsigned char *value = (const unsigned char *)&mask->value;

    if (length > sizeof(mask->value))
        return 0;
    for (size_t index = length; index < sizeof(mask->value); ++index) {
        if (value[index] != 0xa5)
            return 0;
    }
    for (size_t index = 0; index < sizeof(mask->trailing); ++index) {
        if (mask->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int trailing_is_unchanged(const struct guarded_mask *mask)
{
    for (size_t index = 0; index < sizeof(mask->trailing); ++index) {
        if (mask->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int mask_matches(const cpu_set_t *value, const cpu_set_t *other,
                        size_t length)
{
    return memcmp(value, other, length) == 0;
}

static int zero_suffix(const cpu_set_t *mask, size_t length)
{
    const unsigned char *value = (const unsigned char *)mask;
    if (length > sizeof(*mask))
        return 0;
    for (size_t index = length; index < sizeof(*mask); ++index) {
        if (value[index] != 0)
            return 0;
    }
    return 1;
}

static int has_set_bit(const cpu_set_t *mask, size_t length)
{
    const unsigned char *value = (const unsigned char *)mask;
    for (size_t index = 0; index < length; ++index) {
        if (value[index] != 0)
            return 1;
    }
    return 0;
}

int main(void)
{
    struct guarded_mask musl_value;
    struct guarded_mask direct_value;
    struct guarded_mask musl_short;
    struct guarded_mask direct_short;
    struct guarded_mask musl_missing;
    struct guarded_mask direct_missing;

    memset(&musl_value, 0xa5, sizeof(musl_value));
    errno = 0;
    int musl_length = sched_getaffinity(0, sizeof(musl_value.value),
                                        &musl_value.value);
    if (musl_length != 0 || !trailing_is_unchanged(&musl_value))
        return 10;

    memset(&direct_value, 0xa5, sizeof(direct_value));
    errno = 0;
    long direct_length = syscall(SYS_sched_getaffinity, 0,
                                 sizeof(direct_value.value),
                                 &direct_value.value);
    if (direct_length <= 0 || (size_t)direct_length > sizeof(direct_value.value) ||
        !has_set_bit(&direct_value.value, (size_t)direct_length) ||
        !unwritten_is_unchanged(&direct_value, (size_t)direct_length) ||
        !zero_suffix(&musl_value.value, (size_t)direct_length) ||
        !mask_matches(&musl_value.value, &direct_value.value,
                      (size_t)direct_length))
        return 11;

    memset(&musl_short, 0xa5, sizeof(musl_short));
    errno = 0;
    if (sched_getaffinity(0, 1, &musl_short.value) != -1 ||
        errno != EINVAL || !unwritten_is_unchanged(&musl_short, 0) ||
        ((const unsigned char *)&musl_short.value)[0] != 0xa5)
        return 20;

    memset(&direct_short, 0xa5, sizeof(direct_short));
    errno = 0;
    if (syscall(SYS_sched_getaffinity, 0, 1, &direct_short.value) != -1 ||
        errno != EINVAL || !unwritten_is_unchanged(&direct_short, 0) ||
        ((const unsigned char *)&direct_short.value)[0] != 0xa5)
        return 21;

    memset(&musl_missing, 0xa5, sizeof(musl_missing));
    errno = 0;
    if (sched_getaffinity((pid_t)INT_MAX, sizeof(musl_missing.value),
                          &musl_missing.value) != -1 ||
        errno != ESRCH || !unwritten_is_unchanged(&musl_missing, 0))
        return 30;

    memset(&direct_missing, 0xa5, sizeof(direct_missing));
    errno = 0;
    if (syscall(SYS_sched_getaffinity, (pid_t)INT_MAX,
                sizeof(direct_missing.value), &direct_missing.value) != -1 ||
        errno != ESRCH || !unwritten_is_unchanged(&direct_missing, 0))
        return 31;

    puts("layout=cpu-set128 syscall=204 current=musl-success0/raw-returned-prefix-match/musl-zero-tail short=EINVAL missing=ESRCH");
    return 0;
}
