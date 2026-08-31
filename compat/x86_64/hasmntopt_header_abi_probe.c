/* Pinned-musl/project Linux/x86-64 <mntent.h> hasmntopt declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <mntent.h>
#include <stddef.h>

_Static_assert(sizeof(struct mntent) == 40, "mntent x86 LP64 size");
_Static_assert(_Alignof(struct mntent) == 8, "mntent x86 LP64 alignment");
_Static_assert(offsetof(struct mntent, mnt_fsname) == 0, "mntent fsname offset");
_Static_assert(offsetof(struct mntent, mnt_dir) == 8, "mntent directory offset");
_Static_assert(offsetof(struct mntent, mnt_type) == 16, "mntent type offset");
_Static_assert(offsetof(struct mntent, mnt_opts) == 24, "mntent options offset");
_Static_assert(offsetof(struct mntent, mnt_freq) == 32, "mntent frequency offset");
_Static_assert(offsetof(struct mntent, mnt_passno) == 36, "mntent pass-number offset");

#if defined(CRABC_EXPECT_HASMNTOPT)
typedef char *(*hasmntopt_signature)(const struct mntent *, const char *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&hasmntopt),
    hasmntopt_signature), "hasmntopt declaration");

static hasmntopt_signature hasmntopt_function __attribute__((used)) = hasmntopt;
#endif

int crabc_x86_64_hasmntopt_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_HASMNTOPT)
    return hasmntopt_function == (hasmntopt_signature)0;
#else
    return 0;
#endif
}
