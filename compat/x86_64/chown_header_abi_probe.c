/* Selected Linux/x86-64 chown C header ABI facts.
 *
 * Pinned musl 1.2.6 owns this declaration, uid_t/gid_t layout, and C linkage
 * oracle. This compile-only probe selects one following pathname ownership
 * entry, not the sibling ownership APIs, credential policy, or public x86
 * support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <unistd.h>

typedef int (*crabc_chown_signature)(const char *, uid_t, gid_t);

_Static_assert(sizeof(uid_t) == 4 && _Alignof(uid_t) == 4 &&
                   __builtin_types_compatible_p(uid_t, unsigned int),
               "x86 chown uid_t ABI");
_Static_assert(sizeof(gid_t) == 4 && _Alignof(gid_t) == 4 &&
                   __builtin_types_compatible_p(gid_t, unsigned int),
               "x86 chown gid_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&chown),
                                             crabc_chown_signature),
               "chown declaration");

int crabc_x86_64_chown_header_abi_probe(void)
{
    return chown("chown-header", (uid_t)-1, (gid_t)-1);
}
