/* Pinned-musl/project Linux/x86-64 spawn file-actions C declaration gate. */
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

typedef int (*file_actions_init_signature)(posix_spawn_file_actions_t *);
typedef int (*file_actions_destroy_signature)(posix_spawn_file_actions_t *);
typedef int (*file_actions_addclose_signature)(posix_spawn_file_actions_t *, int);
typedef int (*file_actions_adddup2_signature)(posix_spawn_file_actions_t *, int, int);
typedef int (*file_actions_addopen_signature)(posix_spawn_file_actions_t *, int,
                                              const char *, int, mode_t);
typedef int (*file_actions_addchdir_signature)(posix_spawn_file_actions_t *,
                                               const char *);
typedef int (*file_actions_addfchdir_signature)(posix_spawn_file_actions_t *, int);

_Static_assert(sizeof(posix_spawn_file_actions_t) == 80,
               "posix_spawn_file_actions_t size");
_Static_assert(__alignof__(posix_spawn_file_actions_t) == 8,
               "posix_spawn_file_actions_t alignment");
_Static_assert(__builtin_offsetof(posix_spawn_file_actions_t, __actions) == 8,
               "posix_spawn_file_actions_t actions offset");
_Static_assert(sizeof(mode_t) == 4, "x86 mode_t width");

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
static file_actions_addchdir_signature addchdir_function __attribute__((used)) =
    posix_spawn_file_actions_addchdir_np;
static file_actions_addfchdir_signature addfchdir_function __attribute__((used)) =
    posix_spawn_file_actions_addfchdir_np;
#endif

int crabc_x86_64_posix_spawn_file_actions_header_abi_probe(void)
{
    return init_function && destroy_function && addclose_function &&
                   adddup2_function && addopen_function
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
                   && addchdir_function && addfchdir_function
#endif
               ? 0
               : 1;
}
