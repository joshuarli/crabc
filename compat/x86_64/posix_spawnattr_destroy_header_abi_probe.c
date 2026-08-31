/* Pinned-musl/project Linux/x86-64 posix_spawnattr_destroy declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

typedef int (*posix_spawnattr_destroy_signature)(posix_spawnattr_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_destroy),
                                             posix_spawnattr_destroy_signature),
               "posix_spawnattr_destroy declaration");

static posix_spawnattr_destroy_signature posix_spawnattr_destroy_function
    __attribute__((used)) = posix_spawnattr_destroy;

int crabc_x86_64_posix_spawnattr_destroy_header_abi_probe(void)
{
    return posix_spawnattr_destroy_function !=
                   (posix_spawnattr_destroy_signature)0
               ? 0
               : 1;
}
