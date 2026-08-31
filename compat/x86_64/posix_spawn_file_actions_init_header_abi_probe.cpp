/* C++17 companion for the Linux/x86-64 posix_spawn_file_actions_init declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

using posix_spawn_file_actions_init_signature = int (*) (
    posix_spawn_file_actions_t *);

static_assert(__is_same(decltype(&posix_spawn_file_actions_init),
                        posix_spawn_file_actions_init_signature),
              "C++ posix_spawn_file_actions_init declaration");
static_assert(sizeof(posix_spawn_file_actions_t) == 80,
              "C++ posix_spawn_file_actions_t size");
static_assert(alignof(posix_spawn_file_actions_t) == 8,
              "C++ posix_spawn_file_actions_t alignment");
static_assert(__builtin_offsetof(posix_spawn_file_actions_t, __actions) == 8,
              "C++ posix_spawn_file_actions_t actions offset");

static posix_spawn_file_actions_init_signature
    posix_spawn_file_actions_init_function __attribute__((used)) =
        posix_spawn_file_actions_init;

int crabc_x86_64_posix_spawn_file_actions_init_header_abi_probe_cpp()
{
    return posix_spawn_file_actions_init_function != nullptr ? 0 : 1;
}
