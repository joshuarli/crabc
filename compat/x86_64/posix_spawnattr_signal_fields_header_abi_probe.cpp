/* Pinned-musl/project Linux/x86-64 C++ spawn-attribute signal-field declaration gate. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif
#include <spawn.h>
using posix_spawnattr_setflags_signature = int (*)(posix_spawnattr_t *, short);
using posix_spawnattr_setsigset_signature = int (*)(posix_spawnattr_t *, const sigset_t *);
using posix_spawnattr_getsigset_signature = int (*)(const posix_spawnattr_t *, sigset_t *);
static_assert(__is_same(decltype(&posix_spawnattr_setflags), posix_spawnattr_setflags_signature), "setflags declaration");
static_assert(__is_same(decltype(&posix_spawnattr_setsigmask), posix_spawnattr_setsigset_signature), "setsigmask declaration");
static_assert(__is_same(decltype(&posix_spawnattr_getsigmask), posix_spawnattr_getsigset_signature), "getsigmask declaration");
static_assert(__is_same(decltype(&posix_spawnattr_setsigdefault), posix_spawnattr_setsigset_signature), "setsigdefault declaration");
static_assert(__is_same(decltype(&posix_spawnattr_getsigdefault), posix_spawnattr_getsigset_signature), "getsigdefault declaration");
static_assert(sizeof(posix_spawnattr_t) == 336 && alignof(posix_spawnattr_t) == 8, "attribute ABI");
static_assert(sizeof(sigset_t) == 128 && alignof(sigset_t) == 8, "sigset ABI");
static_assert(__builtin_offsetof(posix_spawnattr_t, __flags) == 0 && __builtin_offsetof(posix_spawnattr_t, __def) == 8 && __builtin_offsetof(posix_spawnattr_t, __mask) == 136, "field offsets");
static posix_spawnattr_setflags_signature posix_spawnattr_setflags_function __attribute__((used)) = posix_spawnattr_setflags;
static posix_spawnattr_setsigset_signature posix_spawnattr_setsigmask_function __attribute__((used)) = posix_spawnattr_setsigmask;
static posix_spawnattr_getsigset_signature posix_spawnattr_getsigmask_function __attribute__((used)) = posix_spawnattr_getsigmask;
static posix_spawnattr_setsigset_signature posix_spawnattr_setsigdefault_function __attribute__((used)) = posix_spawnattr_setsigdefault;
static posix_spawnattr_getsigset_signature posix_spawnattr_getsigdefault_function __attribute__((used)) = posix_spawnattr_getsigdefault;
