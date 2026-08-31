/* Linux/x86-64 GNU <unistd.h> syncfs declaration probe.
 *
 * Pinned musl 1.2.6 owns the GNU-only declaration boundary.  The runner
 * compiles this source through both header trees under isolated C profiles;
 * it proves no archive linkage or filesystem behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/syscall.h>
#include <unistd.h>

typedef int (*syncfs_signature)(int);

_Static_assert(SYS_syncfs == 306, "x86 syncfs syscall number");

#if defined(CRABC_SYNCFS_REQUIRE_GNU) || \
    defined(CRABC_SYNCFS_REQUIRE_GNU_HIDDEN)
_Static_assert(__builtin_types_compatible_p(__typeof__(&syncfs),
    syncfs_signature), "GNU syncfs declaration");
#endif

/* This opt-in reference must fail outside GNU feature selection. */
#if defined(CRABC_SYNCFS_REQUIRE_GNU_HIDDEN)
__attribute__((used)) static syncfs_signature crabc_syncfs_must_be_hidden =
    syncfs;
#endif

int crabc_x86_64_syncfs_header_abi_probe(void)
{
    return SYS_syncfs;
}
