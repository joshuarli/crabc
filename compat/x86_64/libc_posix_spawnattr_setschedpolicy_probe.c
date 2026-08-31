/* Native Linux/x86-64 static posix_spawnattr_setschedpolicy C ABI evidence.
 *
 * Musl's complete source body returns ENOSYS without reading either argument.
 * This fixture observes only that fixed compatibility status, not attribute
 * mutation, scheduler policy, spawn execution, file actions, child state,
 * signals, or process lifecycle.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_setschedpolicy_signature)(posix_spawnattr_t *,
                                                         int);

enum { CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_ENOSYS = 38 };

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_FREESTANDING
_Static_assert(CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_ENOSYS == ENOSYS,
               "Linux ENOSYS status value");
#endif

_Static_assert(
    __builtin_types_compatible_p(__typeof__(&posix_spawnattr_setschedpolicy),
                                 posix_spawnattr_setschedpolicy_signature),
    "posix_spawnattr_setschedpolicy declaration");

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

int crabc_x86_64_posix_spawnattr_setschedpolicy_probe(void)
{
    const posix_spawnattr_setschedpolicy_signature function =
        posix_spawnattr_setschedpolicy;
    posix_spawnattr_t attributes;
    posix_spawnattr_t expected;

    fill_bytes((unsigned char *)&attributes, sizeof(attributes), 0xa5);
    expected = attributes;
    if (posix_spawnattr_setschedpolicy(&attributes, 0) !=
        CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_ENOSYS)
        return 1;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 2;

    if (function((posix_spawnattr_t *)0, -17) !=
        CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_ENOSYS)
        return 3;

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_FREESTANDING
    errno = E2BIG;
    fill_bytes((unsigned char *)&attributes, sizeof(attributes), 0x5a);
    expected = attributes;
    if (posix_spawnattr_setschedpolicy(&attributes, 2718) !=
        CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_ENOSYS)
        return 4;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 5;
    if (errno != E2BIG)
        return 6;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_setschedpolicy_probe();
}
#endif
