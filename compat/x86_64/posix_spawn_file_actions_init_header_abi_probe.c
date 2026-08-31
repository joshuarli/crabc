/* Pinned-musl/project Linux/x86-64 posix_spawn_file_actions_init declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

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

static posix_spawn_file_actions_init_signature
    posix_spawn_file_actions_init_function __attribute__((used)) =
        posix_spawn_file_actions_init;

int crabc_x86_64_posix_spawn_file_actions_init_header_abi_probe(void)
{
    return posix_spawn_file_actions_init_function !=
                   (posix_spawn_file_actions_init_signature)0
               ? 0
               : 1;
}
