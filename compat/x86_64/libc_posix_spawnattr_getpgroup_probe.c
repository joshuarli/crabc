/* Native Linux/x86-64 static posix_spawnattr_getpgroup C ABI evidence.
 *
 * Musl's complete source body copies the caller-owned `__pgrp` member into
 * caller-owned pid_t storage and returns zero. This fixture observes only
 * that valid-storage readback, not spawn execution, attribute initialization
 * or mutation, file actions, child state, signals, or scheduling policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

#ifndef CRABC_POSIX_SPAWNATTR_GETPGROUP_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_getpgroup_signature)(const posix_spawnattr_t *,
                                                    pid_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_getpgroup),
                                             posix_spawnattr_getpgroup_signature),
               "posix_spawnattr_getpgroup declaration");

struct guarded_attributes {
    unsigned char before[17];
    posix_spawnattr_t attributes;
    unsigned char after[19];
};

struct guarded_pgroup {
    unsigned char before[13];
    pid_t pgroup;
    unsigned char after[17];
};

static void fill_bytes(unsigned char *bytes, unsigned long count,
                       unsigned char value)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        bytes[index] = value;
}

static void copy_bytes(unsigned char *destination, const unsigned char *source,
                       unsigned long count)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        destination[index] = source[index];
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

static int bytes_match_value(const unsigned char *bytes, unsigned long count,
                             unsigned char value)
{
    unsigned long index;

    for (index = 0; index != count; ++index)
        if (bytes[index] != value)
            return 0;
    return 1;
}

static void reset_pgroup_slot(struct guarded_pgroup *slot)
{
    fill_bytes(slot->before, sizeof(slot->before), 0x5a);
    slot->pgroup = (pid_t)-1;
    fill_bytes(slot->after, sizeof(slot->after), 0xa5);
}

static int pgroup_slot_matches(const struct guarded_pgroup *slot, pid_t expected)
{
    return bytes_match_value(slot->before, sizeof(slot->before), 0x5a) &&
           slot->pgroup == expected &&
           bytes_match_value(slot->after, sizeof(slot->after), 0xa5);
}

static int check_readback(posix_spawnattr_getpgroup_signature function,
                          pid_t expected_pgroup, unsigned char fill)
{
    struct guarded_attributes guarded;
    struct guarded_pgroup slot;
    unsigned char expected[sizeof(guarded.attributes)];

    fill_bytes(guarded.before, sizeof(guarded.before), 0x3c);
    fill_bytes((unsigned char *)&guarded.attributes, sizeof(guarded.attributes),
               fill);
    guarded.attributes.__pgrp = expected_pgroup;
    copy_bytes(expected, (const unsigned char *)&guarded.attributes,
               sizeof(expected));
    fill_bytes(guarded.after, sizeof(guarded.after), 0x96);
    reset_pgroup_slot(&slot);

    if (function(&guarded.attributes, &slot.pgroup) != 0)
        return 1;
    if (!pgroup_slot_matches(&slot, expected_pgroup))
        return 2;
    if (!bytes_match((const unsigned char *)&guarded.attributes, expected,
                     sizeof(expected)))
        return 3;
    if (!bytes_match_value(guarded.before, sizeof(guarded.before), 0x3c))
        return 4;
    if (!bytes_match_value(guarded.after, sizeof(guarded.after), 0x96))
        return 5;

    return 0;
}

int crabc_x86_64_posix_spawnattr_getpgroup_probe(void)
{
    const posix_spawnattr_getpgroup_signature function =
        posix_spawnattr_getpgroup;
    int result;

    result = check_readback(posix_spawnattr_getpgroup, (pid_t)12345, 0xa5);
    if (result != 0)
        return result;
    result = check_readback(function, (pid_t)-321, 0x69);
    if (result != 0)
        return result + 16;

#ifndef CRABC_POSIX_SPAWNATTR_GETPGROUP_FREESTANDING
    errno = E2BIG;
    result = check_readback(function, (pid_t)91, 0x3c);
    if (result != 0)
        return result + 32;
    if (errno != E2BIG)
        return 48;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_GETPGROUP_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_getpgroup_probe();
}
#endif
