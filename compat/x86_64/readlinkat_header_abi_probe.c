/* Selected Linux/x86-64 readlinkat C header ABI facts.
 *
 * Pinned musl 1.2.6 owns this POSIX declaration, LP64 byte-count layout, and
 * C linkage oracle. This compile-only probe selects one caller-buffered
 * descriptor-relative readlink entry; it does not select ordinary readlink,
 * pathname policy, allocation, CWD state, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef ssize_t (*crabc_readlinkat_signature)(int, const char *, char *, size_t);

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 readlinkat int ABI");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8,
               "x86 readlinkat size_t ABI");
_Static_assert(sizeof(ssize_t) == 8 && _Alignof(ssize_t) == 8,
               "x86 readlinkat ssize_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readlinkat),
                                             crabc_readlinkat_signature),
               "readlinkat declaration");

int crabc_x86_64_readlinkat_header_abi_probe(void)
{
    return (int)readlinkat(-100, "fixture", 0, 0);
}
