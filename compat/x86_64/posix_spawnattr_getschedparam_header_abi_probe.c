/* Pinned-musl/project Linux/x86-64 posix_spawnattr_getschedparam declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>
#include <spawn.h>

typedef int (*posix_spawnattr_getschedparam_signature)(
    const posix_spawnattr_t *, struct sched_param *);

_Static_assert(
    __builtin_types_compatible_p(__typeof__(&posix_spawnattr_getschedparam),
                                 posix_spawnattr_getschedparam_signature),
    "posix_spawnattr_getschedparam declaration");
_Static_assert(sizeof(posix_spawnattr_t) == 336 &&
                   _Alignof(posix_spawnattr_t) == 8,
               "x86-64 posix_spawnattr_t ABI");
_Static_assert(sizeof(struct sched_param) == 48 &&
                   _Alignof(struct sched_param) == 8,
               "x86-64 sched_param ABI");

static posix_spawnattr_getschedparam_signature
    posix_spawnattr_getschedparam_function __attribute__((used)) =
        posix_spawnattr_getschedparam;

int crabc_x86_64_posix_spawnattr_getschedparam_header_abi_probe(void)
{
    return posix_spawnattr_getschedparam_function !=
                   (posix_spawnattr_getschedparam_signature)0
               ? 0
               : 1;
}
