/* Selected Linux/x86-64 hasmntopt C header ABI facts.
 *
 * Pinned musl 1.2.6 owns this declaration and `struct mntent` layout oracle.
 * This compile-only probe selects one caller-owned option-string lookup, not
 * mount-table streams, parsing, state, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <mntent.h>
#include <stddef.h>

typedef char *(*crabc_hasmntopt_signature)(const struct mntent *, const char *);

_Static_assert(sizeof(struct mntent) == 40 && _Alignof(struct mntent) == 8,
               "x86 struct mntent ABI");
_Static_assert(offsetof(struct mntent, mnt_fsname) == 0,
               "mnt_fsname offset");
_Static_assert(offsetof(struct mntent, mnt_dir) == 8, "mnt_dir offset");
_Static_assert(offsetof(struct mntent, mnt_type) == 16, "mnt_type offset");
_Static_assert(offsetof(struct mntent, mnt_opts) == 24, "mnt_opts offset");
_Static_assert(offsetof(struct mntent, mnt_freq) == 32, "mnt_freq offset");
_Static_assert(offsetof(struct mntent, mnt_passno) == 36, "mnt_passno offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&hasmntopt),
                                             crabc_hasmntopt_signature),
               "hasmntopt declaration");

int crabc_x86_64_hasmntopt_header_abi_probe(void)
{
    struct mntent entry = {0};
    return hasmntopt(&entry, "rw") != 0;
}
