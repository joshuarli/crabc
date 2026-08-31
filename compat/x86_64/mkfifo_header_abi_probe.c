/* Selected Linux/x86-64 mkfifo C header ABI facts.
 *
 * Pinned musl 1.2.6 owns the declaration, scalar, and mode-constant oracle.
 * This compile-only probe selects only the one static archive entry, never a
 * wider special-node or pathname API surface.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/stat.h>
#include <sys/types.h>

typedef int (*crabc_mkfifo_signature)(const char *, mode_t);

_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4 &&
                   __builtin_types_compatible_p(mode_t, unsigned int),
               "x86 mode_t ABI");
_Static_assert(S_IFMT == 0170000 && S_IFIFO == 0010000 &&
                   S_IRUSR == 0400 && S_IWUSR == 0200 &&
                   S_IRWXU == 0700,
               "x86 FIFO mode constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mkfifo),
                                             crabc_mkfifo_signature),
               "mkfifo declaration");

int crabc_x86_64_mkfifo_header_abi_probe(void)
{
    return S_IFIFO;
}
