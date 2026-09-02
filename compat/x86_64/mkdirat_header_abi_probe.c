/* Selected Linux/x86-64 mkdirat C header ABI facts.
 *
 * Pinned musl 1.2.6 owns the declaration, scalar, and syscall-number oracle.
 * This compile-only probe selects only the one static archive entry, never a
 * pathname-creation policy or a wider filesystem surface.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

typedef int (*crabc_mkdirat_signature)(int, const char *, mode_t);

_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4 &&
                   __builtin_types_compatible_p(mode_t, unsigned int),
               "x86 mode_t ABI");
_Static_assert(S_IFMT == 0170000 && S_IFDIR == 0040000 && S_IRWXU == 0700 &&
                   S_IRWXG == 0070 && S_IRWXO == 0007,
               "x86 directory mode constants");
_Static_assert(SYS_mkdirat == 258, "Linux x86 mkdirat syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mkdirat),
                                             crabc_mkdirat_signature),
               "mkdirat declaration");

int crabc_x86_64_mkdirat_header_abi_probe(void)
{
    return S_IFDIR;
}
