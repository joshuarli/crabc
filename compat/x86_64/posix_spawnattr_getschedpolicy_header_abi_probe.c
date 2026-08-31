/* Pinned-musl/project Linux/x86-64 posix_spawnattr_getschedpolicy declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

typedef int (*posix_spawnattr_getschedpolicy_signature)(
    const posix_spawnattr_t *, int *);

_Static_assert(__builtin_types_compatible_p(
                   __typeof__(&posix_spawnattr_getschedpolicy),
                   posix_spawnattr_getschedpolicy_signature),
               "posix_spawnattr_getschedpolicy declaration");
_Static_assert(sizeof(posix_spawnattr_t) == 336,
               "x86-64 posix_spawnattr_t size");
_Static_assert(_Alignof(posix_spawnattr_t) == 8,
               "x86-64 posix_spawnattr_t alignment");
_Static_assert(sizeof(int) == 4, "x86-64 int size");

static posix_spawnattr_getschedpolicy_signature
    posix_spawnattr_getschedpolicy_function __attribute__((used)) =
        posix_spawnattr_getschedpolicy;

int crabc_x86_64_posix_spawnattr_getschedpolicy_header_abi_probe(void)
{
    return posix_spawnattr_getschedpolicy_function !=
                   (posix_spawnattr_getschedpolicy_signature)0
               ? 0
               : 1;
}
