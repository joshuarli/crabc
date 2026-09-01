/* Native Linux/x86-64 static posix_spawnattr_setschedparam C ABI regression.
 *
 * Musl's complete source body returns ENOSYS without reading either argument.
 * This fixture observes only that fixed compatibility status, not attribute or
 * scheduler-parameter mutation, scheduler behavior, spawn execution, file
 * actions, child state, signals, or process lifecycle.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>
#include <spawn.h>

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_setschedparam_signature)(
    posix_spawnattr_t *, const struct sched_param *);

enum { CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_ENOSYS = 38 };

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_FREESTANDING
_Static_assert(CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_ENOSYS == ENOSYS,
               "Linux ENOSYS status value");
#endif

_Static_assert(
    __builtin_types_compatible_p(__typeof__(&posix_spawnattr_setschedparam),
                                 posix_spawnattr_setschedparam_signature),
    "posix_spawnattr_setschedparam declaration");

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

int crabc_x86_64_posix_spawnattr_setschedparam_probe(void)
{
    const posix_spawnattr_setschedparam_signature function =
        posix_spawnattr_setschedparam;
    posix_spawnattr_t attributes;
    posix_spawnattr_t expected_attributes;
    struct sched_param parameter;
    struct sched_param expected_parameter;

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_FREESTANDING
    errno = E2BIG;
#endif

    fill_bytes((unsigned char *)&attributes, sizeof(attributes), 0xa5);
    fill_bytes((unsigned char *)&parameter, sizeof(parameter), 0x5a);
    expected_attributes = attributes;
    expected_parameter = parameter;
    if (posix_spawnattr_setschedparam(&attributes, &parameter) !=
        CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_ENOSYS)
        return 1;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected_attributes,
                     sizeof(attributes)))
        return 2;
    if (!bytes_match((const unsigned char *)&parameter,
                     (const unsigned char *)&expected_parameter,
                     sizeof(parameter)))
        return 3;

    if (function((posix_spawnattr_t *)0, &parameter) !=
        CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_ENOSYS)
        return 4;
    if (!bytes_match((const unsigned char *)&parameter,
                     (const unsigned char *)&expected_parameter,
                     sizeof(parameter)))
        return 5;

    if (function(&attributes, (const struct sched_param *)0) !=
        CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_ENOSYS)
        return 6;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected_attributes,
                     sizeof(attributes)))
        return 7;

    if (function((posix_spawnattr_t *)0, (const struct sched_param *)0) !=
        CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_ENOSYS)
        return 8;

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_FREESTANDING
    if (errno != E2BIG)
        return 9;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_SETSCHEDPARAM_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_setschedparam_probe();
}
#endif
