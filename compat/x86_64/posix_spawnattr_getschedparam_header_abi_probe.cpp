/* C++17 companion for the Linux/x86-64 posix_spawnattr_getschedparam declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>
#include <spawn.h>

using posix_spawnattr_getschedparam_signature =
    int (*)(const posix_spawnattr_t *, struct sched_param *);

static_assert(__is_same(decltype(&posix_spawnattr_getschedparam),
                        posix_spawnattr_getschedparam_signature),
              "C++ posix_spawnattr_getschedparam declaration");
static_assert(sizeof(posix_spawnattr_t) == 336 && alignof(posix_spawnattr_t) == 8,
              "x86-64 posix_spawnattr_t ABI");
static_assert(sizeof(struct sched_param) == 48 &&
                  alignof(struct sched_param) == 8,
              "x86-64 sched_param ABI");

static posix_spawnattr_getschedparam_signature
    posix_spawnattr_getschedparam_function __attribute__((used)) =
        posix_spawnattr_getschedparam;

int crabc_x86_64_posix_spawnattr_getschedparam_header_abi_probe_cpp()
{
    return posix_spawnattr_getschedparam_function != nullptr ? 0 : 1;
}
