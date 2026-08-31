/* Native Linux/x86-64 static posix_spawnattr_getflags C ABI evidence.
 *
 * Musl's complete source body copies the caller-owned `__flags` member into
 * the caller-owned short result and returns zero. This fixture observes only
 * that valid-storage readback, not spawn execution, attribute mutation, file
 * actions, child state, signals, or scheduling policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

#ifndef CRABC_POSIX_SPAWNATTR_GETFLAGS_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_getflags_signature)(const posix_spawnattr_t *,
                                                   short *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_getflags),
                                             posix_spawnattr_getflags_signature),
               "posix_spawnattr_getflags declaration");

struct flags_slot {
    unsigned char before;
    short flags;
    unsigned char after;
};

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

static int slot_matches(const struct flags_slot *slot, short expected)
{
    return slot->before == 0x5a && slot->flags == expected &&
           slot->after == 0xa5;
}

static void reset_slot(struct flags_slot *slot)
{
    slot->before = 0x5a;
    slot->flags = (short)-1;
    slot->after = 0xa5;
}

int crabc_x86_64_posix_spawnattr_getflags_probe(void)
{
    const posix_spawnattr_getflags_signature function = posix_spawnattr_getflags;
    const short first_flags =
        (short)(POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP);
    const short second_flags =
        (short)(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    posix_spawnattr_t attributes;
    posix_spawnattr_t expected;
    struct flags_slot slot;

    fill_bytes((unsigned char *)&attributes, sizeof(attributes), 0xa5);
    attributes.__flags = first_flags;
    expected = attributes;
    reset_slot(&slot);
    if (posix_spawnattr_getflags(&attributes, &slot.flags) != 0)
        return 1;
    if (!slot_matches(&slot, first_flags))
        return 2;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 3;

    attributes.__flags = second_flags;
    expected = attributes;
    reset_slot(&slot);
    if (function(&attributes, &slot.flags) != 0)
        return 4;
    if (!slot_matches(&slot, second_flags))
        return 5;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 6;

#ifndef CRABC_POSIX_SPAWNATTR_GETFLAGS_FREESTANDING
    errno = E2BIG;
    attributes.__flags = first_flags;
    expected = attributes;
    reset_slot(&slot);
    if (posix_spawnattr_getflags(&attributes, &slot.flags) != 0)
        return 7;
    if (!slot_matches(&slot, first_flags))
        return 8;
    if (!bytes_match((const unsigned char *)&attributes,
                     (const unsigned char *)&expected, sizeof(attributes)))
        return 9;
    if (errno != E2BIG)
        return 10;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_GETFLAGS_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_getflags_probe();
}
#endif
