/* Pinned-musl/project Linux/x86-64 posix_spawnattr_getflags declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

typedef int (*posix_spawnattr_getflags_signature)(const posix_spawnattr_t *,
                                                   short *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_getflags),
                                             posix_spawnattr_getflags_signature),
               "posix_spawnattr_getflags declaration");

static posix_spawnattr_getflags_signature posix_spawnattr_getflags_function
    __attribute__((used)) = posix_spawnattr_getflags;

int crabc_x86_64_posix_spawnattr_getflags_header_abi_probe(void)
{
    return posix_spawnattr_getflags_function !=
                   (posix_spawnattr_getflags_signature)0
               ? 0
               : 1;
}
