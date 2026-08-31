/* Native Linux/x86-64 static posix_spawnattr_init C ABI evidence.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through one extracted `-nostdlib -static` crabc archive member. It
 * observes only musl's full caller-owned attribute-record zero initialization,
 * not spawn execution, file actions, child state, or signal/scheduler policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

#ifndef CRABC_POSIX_SPAWNATTR_INIT_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_init_signature)(posix_spawnattr_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_init),
                                             posix_spawnattr_init_signature),
               "posix_spawnattr_init declaration");

struct guarded_attributes {
    unsigned char before[17];
    posix_spawnattr_t attributes;
    unsigned char after[19];
};

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

static int attributes_are_zero(const posix_spawnattr_t *attributes)
{
    return bytes_match((const unsigned char *)attributes, sizeof(*attributes), 0);
}

static int check_guarded_initialization(posix_spawnattr_init_signature function)
{
    struct guarded_attributes guarded;

    fill_bytes(guarded.before, sizeof(guarded.before), 0x5a);
    fill_bytes((unsigned char *)&guarded.attributes, sizeof(guarded.attributes), 0xa5);
    fill_bytes(guarded.after, sizeof(guarded.after), 0x3c);

    if (function(&guarded.attributes) != 0)
        return 1;
    if (!attributes_are_zero(&guarded.attributes))
        return 2;
    if (!bytes_match(guarded.before, sizeof(guarded.before), 0x5a))
        return 3;
    if (!bytes_match(guarded.after, sizeof(guarded.after), 0x3c))
        return 4;

    fill_bytes((unsigned char *)&guarded.attributes, sizeof(guarded.attributes), 0x96);
    if (posix_spawnattr_init(&guarded.attributes) != 0)
        return 5;
    if (!attributes_are_zero(&guarded.attributes))
        return 6;
    if (!bytes_match(guarded.before, sizeof(guarded.before), 0x5a))
        return 7;
    if (!bytes_match(guarded.after, sizeof(guarded.after), 0x3c))
        return 8;

    return 0;
}

int crabc_x86_64_posix_spawnattr_init_probe(void)
{
    const posix_spawnattr_init_signature function = posix_spawnattr_init;
    posix_spawnattr_t attributes;
    int result;

    result = check_guarded_initialization(function);
    if (result != 0)
        return result;

    fill_bytes((unsigned char *)&attributes, sizeof(attributes), 0x69);
#ifndef CRABC_POSIX_SPAWNATTR_INIT_FREESTANDING
    errno = E2BIG;
#endif
    if (function(&attributes) != 0)
        return 16;
    if (!attributes_are_zero(&attributes))
        return 17;
#ifndef CRABC_POSIX_SPAWNATTR_INIT_FREESTANDING
    if (errno != E2BIG)
        return 18;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_INIT_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_init_probe();
}
#endif
