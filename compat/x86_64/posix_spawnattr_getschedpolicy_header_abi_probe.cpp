/* C++17 companion for the Linux/x86-64 posix_spawnattr_getschedpolicy declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

using posix_spawnattr_getschedpolicy_signature = int (*)(
    const posix_spawnattr_t *, int *);

static_assert(__is_same(decltype(&posix_spawnattr_getschedpolicy),
                        posix_spawnattr_getschedpolicy_signature),
              "C++ posix_spawnattr_getschedpolicy declaration");
static_assert(sizeof(posix_spawnattr_t) == 336,
              "x86-64 posix_spawnattr_t size");
static_assert(alignof(posix_spawnattr_t) == 8,
              "x86-64 posix_spawnattr_t alignment");
static_assert(sizeof(int) == 4, "x86-64 int size");

static posix_spawnattr_getschedpolicy_signature
    posix_spawnattr_getschedpolicy_function __attribute__((used)) =
        posix_spawnattr_getschedpolicy;

int crabc_x86_64_posix_spawnattr_getschedpolicy_header_abi_probe_cpp()
{
    return posix_spawnattr_getschedpolicy_function != nullptr ? 0 : 1;
}
