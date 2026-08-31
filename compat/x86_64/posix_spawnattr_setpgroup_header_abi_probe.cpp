/* C++17 companion for the Linux/x86-64 posix_spawnattr_setpgroup declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

using posix_spawnattr_setpgroup_signature = int (*)(posix_spawnattr_t *, pid_t);

static_assert(__is_same(decltype(&posix_spawnattr_setpgroup),
                        posix_spawnattr_setpgroup_signature),
              "C++ posix_spawnattr_setpgroup declaration");
static_assert(sizeof(posix_spawnattr_t) == 336, "C++ posix_spawnattr_t size");
static_assert(alignof(posix_spawnattr_t) == 8,
              "C++ posix_spawnattr_t alignment");
static_assert(__builtin_offsetof(posix_spawnattr_t, __pgrp) == 4,
              "C++ posix_spawnattr_t process-group offset");

static posix_spawnattr_setpgroup_signature posix_spawnattr_setpgroup_function
    __attribute__((used)) = posix_spawnattr_setpgroup;

int crabc_x86_64_posix_spawnattr_setpgroup_header_abi_probe_cpp()
{
    return posix_spawnattr_setpgroup_function != nullptr ? 0 : 1;
}
