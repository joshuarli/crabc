/* Pinned-musl/project Linux/x86-64 spawn-attribute signal-field declaration gate. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif
#include <spawn.h>

typedef int (*posix_spawnattr_setflags_signature)(posix_spawnattr_t *, short);
typedef int (*posix_spawnattr_setsigset_signature)(posix_spawnattr_t *, const sigset_t *);
typedef int (*posix_spawnattr_getsigset_signature)(const posix_spawnattr_t *, sigset_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_setflags), posix_spawnattr_setflags_signature), "setflags declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_setsigmask), posix_spawnattr_setsigset_signature), "setsigmask declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_getsigmask), posix_spawnattr_getsigset_signature), "getsigmask declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_setsigdefault), posix_spawnattr_setsigset_signature), "setsigdefault declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_getsigdefault), posix_spawnattr_getsigset_signature), "getsigdefault declaration");
_Static_assert(sizeof(posix_spawnattr_t) == 336 && _Alignof(posix_spawnattr_t) == 8, "attribute ABI");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8, "sigset ABI");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __flags) == 0, "flags offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __def) == 8, "default offset");
_Static_assert(__builtin_offsetof(posix_spawnattr_t, __mask) == 136, "mask offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(((posix_spawnattr_t *)0)->__def), sigset_t), "default type");
_Static_assert(__builtin_types_compatible_p(__typeof__(((posix_spawnattr_t *)0)->__mask), sigset_t), "mask type");

static posix_spawnattr_setflags_signature posix_spawnattr_setflags_function __attribute__((used)) = posix_spawnattr_setflags;
static posix_spawnattr_setsigset_signature posix_spawnattr_setsigmask_function __attribute__((used)) = posix_spawnattr_setsigmask;
static posix_spawnattr_getsigset_signature posix_spawnattr_getsigmask_function __attribute__((used)) = posix_spawnattr_getsigmask;
static posix_spawnattr_setsigset_signature posix_spawnattr_setsigdefault_function __attribute__((used)) = posix_spawnattr_setsigdefault;
static posix_spawnattr_getsigset_signature posix_spawnattr_getsigdefault_function __attribute__((used)) = posix_spawnattr_getsigdefault;

int crabc_x86_64_posix_spawnattr_signal_fields_header_abi_probe(void) { return posix_spawnattr_setflags_function && posix_spawnattr_setsigmask_function && posix_spawnattr_getsigmask_function && posix_spawnattr_setsigdefault_function && posix_spawnattr_getsigdefault_function ? 0 : 1; }
