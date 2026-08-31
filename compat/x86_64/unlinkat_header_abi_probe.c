/* Selected Linux/x86-64 unlinkat C header ABI facts.
 *
 * Pinned musl 1.2.6 owns this declaration, constants, and C linkage oracle.
 * This compile-only probe selects one caller-directed directory-entry removal
 * leaf, not a pathname-policy family or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef int (*crabc_unlinkat_signature)(int, const char *, int);

_Static_assert(AT_FDCWD == -100 && AT_REMOVEDIR == 0x200 &&
                   AT_SYMLINK_NOFOLLOW == 0x100,
               "x86 unlinkat constants");
_Static_assert(SYS_unlinkat == 263, "Linux x86 unlinkat syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&unlinkat),
                                             crabc_unlinkat_signature),
               "unlinkat declaration");

int crabc_x86_64_unlinkat_header_abi_probe(void)
{
    return unlinkat(AT_FDCWD, "unlinkat-header", 0);
}
