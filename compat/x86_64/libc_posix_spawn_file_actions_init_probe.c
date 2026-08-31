/* Native Linux/x86-64 static posix_spawn_file_actions_init C ABI evidence.
 *
 * Musl's complete source body writes a null caller-owned `__actions` pointer
 * and returns zero. This fixture observes only that valid-storage empty-list
 * sentinel, not file-action addition/destruction, spawn execution, child
 * lifecycle, attribute state, signals, or scheduling policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

#ifndef CRABC_POSIX_SPAWN_FILE_ACTIONS_INIT_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawn_file_actions_init_signature)(
    posix_spawn_file_actions_t *);

_Static_assert(
    __builtin_types_compatible_p(__typeof__(&posix_spawn_file_actions_init),
                                 posix_spawn_file_actions_init_signature),
    "posix_spawn_file_actions_init declaration");
_Static_assert(sizeof(posix_spawn_file_actions_t) == 80,
               "posix_spawn_file_actions_t size");
_Static_assert(__alignof__(posix_spawn_file_actions_t) == 8,
               "posix_spawn_file_actions_t alignment");
_Static_assert(__builtin_offsetof(posix_spawn_file_actions_t, __actions) == 8,
               "posix_spawn_file_actions_t actions offset");

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

static void reset_actions(posix_spawn_file_actions_t *actions,
                          posix_spawn_file_actions_t *expected)
{
    fill_bytes((unsigned char *)actions, sizeof(*actions), 0xa5);
    fill_bytes((unsigned char *)expected, sizeof(*expected), 0xa5);
    actions->__actions = actions;
    expected->__actions = 0;
}

int crabc_x86_64_posix_spawn_file_actions_init_probe(void)
{
    const posix_spawn_file_actions_init_signature function =
        posix_spawn_file_actions_init;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_t expected;

    reset_actions(&actions, &expected);
    if (posix_spawn_file_actions_init(&actions) != 0)
        return 1;
    if (actions.__actions != 0)
        return 2;
    if (!bytes_match((const unsigned char *)&actions,
                     (const unsigned char *)&expected, sizeof(actions)))
        return 3;

    reset_actions(&actions, &expected);
    if (function(&actions) != 0)
        return 4;
    if (actions.__actions != 0)
        return 5;
    if (!bytes_match((const unsigned char *)&actions,
                     (const unsigned char *)&expected, sizeof(actions)))
        return 6;

#ifndef CRABC_POSIX_SPAWN_FILE_ACTIONS_INIT_FREESTANDING
    errno = E2BIG;
    reset_actions(&actions, &expected);
    if (posix_spawn_file_actions_init(&actions) != 0)
        return 7;
    if (actions.__actions != 0)
        return 8;
    if (!bytes_match((const unsigned char *)&actions,
                     (const unsigned char *)&expected, sizeof(actions)))
        return 9;
    if (errno != E2BIG)
        return 10;
#endif

    return 0;
}

#ifndef CRABC_POSIX_SPAWN_FILE_ACTIONS_INIT_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawn_file_actions_init_probe();
}
#endif
