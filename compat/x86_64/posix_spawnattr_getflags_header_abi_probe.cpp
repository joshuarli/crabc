/* C++17 companion for the Linux/x86-64 posix_spawnattr_getflags declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

using posix_spawnattr_getflags_signature = int (*)(const posix_spawnattr_t *,
                                                   short *);

static_assert(__is_same(decltype(&posix_spawnattr_getflags),
                        posix_spawnattr_getflags_signature),
              "C++ posix_spawnattr_getflags declaration");

static posix_spawnattr_getflags_signature posix_spawnattr_getflags_function
    __attribute__((used)) = posix_spawnattr_getflags;

int crabc_x86_64_posix_spawnattr_getflags_header_abi_probe_cpp()
{
    return posix_spawnattr_getflags_function != nullptr ? 0 : 1;
}
