/* C++17 companion for the Linux/x86-64 posix_spawnattr_setschedparam declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>
#include <spawn.h>

using posix_spawnattr_setschedparam_signature =
    int (*)(posix_spawnattr_t *, const struct sched_param *);

static_assert(__is_same(decltype(&posix_spawnattr_setschedparam),
                        posix_spawnattr_setschedparam_signature),
              "C++ posix_spawnattr_setschedparam declaration");

static posix_spawnattr_setschedparam_signature
    posix_spawnattr_setschedparam_function __attribute__((used)) =
        posix_spawnattr_setschedparam;

int crabc_x86_64_posix_spawnattr_setschedparam_header_abi_probe_cpp()
{
    return posix_spawnattr_setschedparam_function != nullptr ? 0 : 1;
}
