/* Native Linux/x86-64 static posix_spawnattr_setpgroup C ABI evidence.
 *
 * Musl's complete source body writes the supplied caller value into the
 * caller-owned `__pgrp` member and returns zero. This fixture observes only
 * that valid-storage assignment, not spawn execution, attribute initialization
 * or other queries, file actions, child state, signals, or scheduler policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

#ifndef CRABC_POSIX_SPAWNATTR_SETPGROUP_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_setpgroup_signature)(posix_spawnattr_t *, pid_t);

_Static_assert(
    __builtin_types_compatible_p(__typeof__(&posix_spawnattr_setpgroup),
                                 posix_spawnattr_setpgroup_signature),
    "posix_spawnattr_setpgroup declaration");
_Static_assert(sizeof(posix_spawnattr_t) == 336, "posix_spawnattr_t size");
_Static_assert(__alignof__(posix_spawnattr_t) == 8,
               "posix_spawnattr_t alignment");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __pgrp) == 4,
               "posix_spawnattr_t process-group offset");

static void fill_bytes(unsigned char *bytes, unsigned long count,
                       unsigned char value)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        bytes[index] = value;
}

static int bytes_match(const unsigned char *left, const unsigned char *right,
                       unsigned long count)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static void reset_attributes(posix_spawnattr_t *attributes,
                             posix_spawnattr_t *expected, pid_t process_group)
{
    fill_bytes((unsigned char *)attributes, sizeof(*attributes), 0xa5);
    fill_bytes((unsigned char *)expected, sizeof(*expected), 0xa5);
    expected->__pgrp = process_group;
}

int crabc_x86_64_posix_spawnattr_setpgroup_probe(void)
{
    const posix_spawnattr_setpgroup_signature function =
        posix_spawnattr_setpgroup;
    posix_spawnattr_t attributes;
    posix_spawnattr_t expected;

    reset_attributes(&attributes, &expected, (pid_t)0);
    if (posix_spawnattr_setpgroup(&attributes, (pid_t)0) != 0)
        return 1;
    if (attributes.__pgrp != (pid_t)0)
        return 2;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 3;

    reset_attributes(&attributes, &expected, (pid_t)-17);
    if (function(&attributes, (pid_t)-17) != 0)
        return 4;
    if (attributes.__pgrp != (pid_t)-17)
        return 5;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 6;

#ifndef CRABC_POSIX_SPAWNATTR_SETPGROUP_FREESTANDING
    errno = E2BIG;
    reset_attributes(&attributes, &expected, (pid_t)2718);
    if (posix_spawnattr_setpgroup(&attributes, (pid_t)2718) != 0)
        return 7;
    if (attributes.__pgrp != (pid_t)2718)
        return 8;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 9;
    if (errno != E2BIG)
        return 10;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_SETPGROUP_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_setpgroup_probe();
}
#endif
