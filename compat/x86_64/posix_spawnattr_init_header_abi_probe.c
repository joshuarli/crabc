/* Pinned-musl/project Linux/x86-64 posix_spawnattr_init declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

typedef int (*posix_spawnattr_init_signature)(posix_spawnattr_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_init),
                                             posix_spawnattr_init_signature),
               "posix_spawnattr_init declaration");
_Static_assert(sizeof(posix_spawnattr_t) == 336,
               "x86-64 posix_spawnattr_t size");
_Static_assert(__alignof__(posix_spawnattr_t) == 8,
               "x86-64 posix_spawnattr_t alignment");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __flags) == 0,
               "posix_spawnattr_t flags offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __pgrp) == 4,
               "posix_spawnattr_t process-group offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __def) == 8,
               "posix_spawnattr_t default-signal offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __mask) == 136,
               "posix_spawnattr_t signal-mask offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __prio) == 264,
               "posix_spawnattr_t priority offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __pol) == 268,
               "posix_spawnattr_t policy offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __fn) == 272,
               "posix_spawnattr_t implementation-pointer offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __pad) == 280,
               "posix_spawnattr_t padding offset");

static posix_spawnattr_init_signature posix_spawnattr_init_function
    __attribute__((used)) = posix_spawnattr_init;

int crabc_x86_64_posix_spawnattr_init_header_abi_probe(void)
{
    return posix_spawnattr_init_function != (posix_spawnattr_init_signature)0
               ? 0
               : 1;
}
