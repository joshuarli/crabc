/* Pinned-musl/project Linux/x86-64 spawn file-actions C++ declaration gate. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

using file_actions_init_signature = int (*)(posix_spawn_file_actions_t *);
using file_actions_destroy_signature = int (*)(posix_spawn_file_actions_t *);
using file_actions_addclose_signature = int (*)(posix_spawn_file_actions_t *, int);
using file_actions_adddup2_signature = int (*)(posix_spawn_file_actions_t *, int, int);
using file_actions_addopen_signature = int (*)(posix_spawn_file_actions_t *, int,
                                               const char *, int, mode_t);
using file_actions_addchdir_signature = int (*)(posix_spawn_file_actions_t *,
                                                const char *);
using file_actions_addfchdir_signature = int (*)(posix_spawn_file_actions_t *, int);

static_assert(__is_same(decltype(&posix_spawn_file_actions_init),
                        file_actions_init_signature));
static_assert(__is_same(decltype(&posix_spawn_file_actions_destroy),
                        file_actions_destroy_signature));
static_assert(__is_same(decltype(&posix_spawn_file_actions_addclose),
                        file_actions_addclose_signature));
static_assert(__is_same(decltype(&posix_spawn_file_actions_adddup2),
                        file_actions_adddup2_signature));
static_assert(__is_same(decltype(&posix_spawn_file_actions_addopen),
                        file_actions_addopen_signature));
static_assert(sizeof(posix_spawn_file_actions_t) == 80 &&
              alignof(posix_spawn_file_actions_t) == 8);
static_assert(__builtin_offsetof(posix_spawn_file_actions_t, __actions) == 8);

static file_actions_init_signature init_function __attribute__((used)) =
    posix_spawn_file_actions_init;
static file_actions_destroy_signature destroy_function __attribute__((used)) =
    posix_spawn_file_actions_destroy;
static file_actions_addclose_signature addclose_function __attribute__((used)) =
    posix_spawn_file_actions_addclose;
static file_actions_adddup2_signature adddup2_function __attribute__((used)) =
    posix_spawn_file_actions_adddup2;
static file_actions_addopen_signature addopen_function __attribute__((used)) =
    posix_spawn_file_actions_addopen;

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
static_assert(__is_same(decltype(&posix_spawn_file_actions_addchdir_np),
                        file_actions_addchdir_signature));
static_assert(__is_same(decltype(&posix_spawn_file_actions_addfchdir_np),
                        file_actions_addfchdir_signature));
static file_actions_addchdir_signature addchdir_function __attribute__((used)) =
    posix_spawn_file_actions_addchdir_np;
static file_actions_addfchdir_signature addfchdir_function __attribute__((used)) =
    posix_spawn_file_actions_addfchdir_np;
#endif

int crabc_x86_64_posix_spawn_file_actions_header_abi_probe()
{
    return init_function && destroy_function && addclose_function &&
                   adddup2_function && addopen_function
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
                   && addchdir_function && addfchdir_function
#endif
               ? 0
               : 1;
}
