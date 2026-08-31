/* C++17 companion for the Linux/x86-64 posix_spawnattr_getpgroup declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <spawn.h>

using posix_spawnattr_getpgroup_signature = int (*)(const posix_spawnattr_t *,
                                                     pid_t *);

static_assert(__is_same(decltype(&posix_spawnattr_getpgroup),
                        posix_spawnattr_getpgroup_signature),
              "C++ posix_spawnattr_getpgroup declaration");
static_assert(sizeof(pid_t) == 4, "x86-64 pid_t size");
static_assert(__builtin_offsetof(posix_spawnattr_t, __pgrp) == 4,
              "posix_spawnattr_t process-group offset");
static_assert(__is_same(decltype(((posix_spawnattr_t *)nullptr)->__pgrp),
                        pid_t),
              "posix_spawnattr_t process-group type");

static posix_spawnattr_getpgroup_signature posix_spawnattr_getpgroup_function
    __attribute__((used)) = posix_spawnattr_getpgroup;

int crabc_x86_64_posix_spawnattr_getpgroup_header_abi_probe_cpp()
{
    return posix_spawnattr_getpgroup_function != nullptr ? 0 : 1;
}
