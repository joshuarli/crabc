/* Native Linux/x86-64 static posix_spawnattr_getschedpolicy C ABI evidence.
 *
 * Musl's complete source body returns ENOSYS directly without reading either
 * declared pointer or changing errno. This fixture observes only that narrow
 * compatibility result, not scheduler policy, attribute storage, spawn
 * execution, file actions, signals, or child state.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <spawn.h>

typedef int (*posix_spawnattr_getschedpolicy_signature)(
    const posix_spawnattr_t *, int *);

_Static_assert(__builtin_types_compatible_p(
                   __typeof__(&posix_spawnattr_getschedpolicy),
                   posix_spawnattr_getschedpolicy_signature),
               "posix_spawnattr_getschedpolicy declaration");

struct guarded_attributes {
    unsigned char before[17];
    posix_spawnattr_t attributes;
    unsigned char after[19];
};

struct guarded_policy {
    unsigned char before[13];
    int policy;
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

static void reset_attributes(struct guarded_attributes *guarded,
                             unsigned char fill)
{
    fill_bytes(guarded->before, sizeof(guarded->before), 0x3c);
    fill_bytes((unsigned char *)&guarded->attributes, sizeof(guarded->attributes),
               fill);
    fill_bytes(guarded->after, sizeof(guarded->after), 0x96);
}

static void reset_policy(struct guarded_policy *guarded, int value)
{
    fill_bytes(guarded->before, sizeof(guarded->before), 0x5a);
    guarded->policy = value;
    fill_bytes(guarded->after, sizeof(guarded->after), 0xa5);
}

static int attributes_match(const struct guarded_attributes *guarded,
                            const unsigned char *expected)
{
    return bytes_match_value(guarded->before, sizeof(guarded->before), 0x3c) &&
           bytes_match((const unsigned char *)&guarded->attributes, expected,
                       sizeof(guarded->attributes)) &&
           bytes_match_value(guarded->after, sizeof(guarded->after), 0x96);
}

static int policy_matches(const struct guarded_policy *guarded, int expected)
{
    return bytes_match_value(guarded->before, sizeof(guarded->before), 0x5a) &&
           guarded->policy == expected &&
           bytes_match_value(guarded->after, sizeof(guarded->after), 0xa5);
}

static int check_direct_nonnull(void)
{
    struct guarded_attributes attributes;
    struct guarded_policy policy;
    unsigned char expected_attributes[sizeof(attributes.attributes)];

    reset_attributes(&attributes, 0xa5);
    copy_bytes(expected_attributes, (const unsigned char *)&attributes.attributes,
               sizeof(expected_attributes));
    reset_policy(&policy, -321);
    if (posix_spawnattr_getschedpolicy(&attributes.attributes, &policy.policy) !=
        ENOSYS)
        return 1;
    if (!attributes_match(&attributes, expected_attributes))
        return 2;
    if (!policy_matches(&policy, -321))
        return 3;
    return 0;
}

static int check_indirect_ignored_pointers(
    posix_spawnattr_getschedpolicy_signature function)
{
    struct guarded_attributes attributes;
    struct guarded_policy policy;
    unsigned char expected_attributes[sizeof(attributes.attributes)];

    reset_attributes(&attributes, 0x69);
    copy_bytes(expected_attributes, (const unsigned char *)&attributes.attributes,
               sizeof(expected_attributes));
    reset_policy(&policy, 917);
    if (function(&attributes.attributes, &policy.policy) != ENOSYS)
        return 1;
    if (!attributes_match(&attributes, expected_attributes) ||
        !policy_matches(&policy, 917))
        return 2;
    if (function((const posix_spawnattr_t *)0, &policy.policy) != ENOSYS)
        return 3;
    if (!policy_matches(&policy, 917))
        return 4;
    if (function(&attributes.attributes, (int *)0) != ENOSYS)
        return 5;
    if (!attributes_match(&attributes, expected_attributes))
        return 6;
    if (function((const posix_spawnattr_t *)0, (int *)0) != ENOSYS)
        return 7;
    if (!attributes_match(&attributes, expected_attributes) ||
        !policy_matches(&policy, 917))
        return 8;
    return 0;
}

int crabc_x86_64_posix_spawnattr_getschedpolicy_probe(void)
{
    const posix_spawnattr_getschedpolicy_signature function =
        posix_spawnattr_getschedpolicy;
    int result;

#ifndef CRABC_POSIX_SPAWNATTR_GETSCHEDPOLICY_FREESTANDING
    errno = E2BIG;
#endif
    result = check_direct_nonnull();
    if (result != 0)
        return result;
    result = check_indirect_ignored_pointers(function);
    if (result != 0)
        return result + 16;
#ifndef CRABC_POSIX_SPAWNATTR_GETSCHEDPOLICY_FREESTANDING
    if (errno != E2BIG)
        return 48;
#endif
    return 0;
}

#ifndef CRABC_POSIX_SPAWNATTR_GETSCHEDPOLICY_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawnattr_getschedpolicy_probe();
}
#endif
