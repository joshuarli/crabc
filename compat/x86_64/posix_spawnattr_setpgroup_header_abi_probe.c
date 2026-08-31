/* Pinned-musl/project Linux/x86-64 posix_spawnattr_setpgroup declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

typedef int (*posix_spawnattr_setpgroup_signature)(posix_spawnattr_t *, pid_t);

_Static_assert(
    __builtin_types_compatible_p(__typeof__(&posix_spawnattr_setpgroup),
                                 posix_spawnattr_setpgroup_signature),
    "posix_spawnattr_setpgroup declaration");
_Static_assert(sizeof(posix_spawnattr_t) == 336, "posix_spawnattr_t size");
_Static_assert(__alignof__(posix_spawnattr_t) == 8,
               "posix_spawnattr_t alignment");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __pgrp) == 4,
               "posix_spawnattr_t process-group offset");

static posix_spawnattr_setpgroup_signature posix_spawnattr_setpgroup_function
    __attribute__((used)) = posix_spawnattr_setpgroup;

int crabc_x86_64_posix_spawnattr_setpgroup_header_abi_probe(void)
{
    return posix_spawnattr_setpgroup_function !=
                   (posix_spawnattr_setpgroup_signature)0
               ? 0
               : 1;
}
