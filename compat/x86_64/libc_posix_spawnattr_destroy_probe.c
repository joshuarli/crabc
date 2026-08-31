/* Native Linux/x86-64 static posix_spawnattr_destroy C ABI evidence.
 *
 * Musl's complete source body returns zero without reading, writing, freeing,
 * or retaining its opaque pointer. This fixture therefore observes only that
 * private no-op, not spawn execution, file actions, child state, or signal
 * and scheduler attributes.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

#ifndef CRABC_POSIX_SPAWNATTR_DESTROY_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_destroy_signature)(posix_spawnattr_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_destroy),
                                             posix_spawnattr_destroy_signature),
               "posix_spawnattr_destroy declaration");

static void fill_bytes(unsigned char *bytes, unsigned long count,
                       unsigned char value)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        bytes[index] = value;
}

static int bytes_match(const unsigned char *bytes, unsigned long count,
                       unsigned char value)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        if (bytes[index] != value)
            return 0;
    return 1;
}

int crabc_x86_64_posix_spawnattr_destroy_probe(void)
{
    const posix_spawnattr_destroy_signature function = posix_spawnattr_destroy;
    posix_spawnattr_t attributes;

    fill_bytes((unsigned char *)&attributes, sizeof(attributes), 0xa5);
    if (posix_spawnattr_destroy(&attributes) != 0)
        return 1;
    if (!bytes_match((const unsigned char *)&attributes, sizeof(attributes), 0xa5))
        return 2;
    if (function(&attributes) != 0)
        return 3;
    if (!bytes_match((const unsigned char *)&attributes, sizeof(attributes), 0xa5))
        return 4;
    if (posix_spawnattr_destroy((posix_spawnattr_t *)0) != 0)
        return 5;
    if (function((posix_spawnattr_t *)0) != 0)
        return 6;

#ifndef CRABC_POSIX_SPAWNATTR_DESTROY_FREESTANDING
    errno = E2BIG;
    if (posix_spawnattr_destroy(&attributes) != 0)
        return 7;
    if (errno != E2BIG)
        return 8;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_DESTROY_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_destroy_probe();
}
#endif
