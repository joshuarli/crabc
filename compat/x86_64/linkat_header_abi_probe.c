/* Selected Linux/x86-64 linkat C header ABI facts.
 *
 * Pinned musl 1.2.6 owns this POSIX declaration, LP64 scalar layout, and C
 * linkage oracle. This compile-only probe selects one descriptor-relative
 * hard-link entry; it does not select ordinary link, pathname policy,
 * allocation, CWD state, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*crabc_linkat_signature)(int, const char *, int, const char *,
                                      int);

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 linkat int ABI");
_Static_assert(sizeof(char *) == 8 && _Alignof(char *) == 8,
               "x86 linkat pointer ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&linkat),
                                             crabc_linkat_signature),
               "linkat declaration");

int crabc_x86_64_linkat_header_abi_probe(void)
{
    return linkat(-100, "existing", -100, "new", 0);
}
