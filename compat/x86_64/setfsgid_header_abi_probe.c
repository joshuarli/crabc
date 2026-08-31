/* Pinned-musl/project Linux/x86-64 setfsgid declaration and scalar ABI gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <sys/types.h>

typedef int (*setfsgid_signature)(gid_t);

_Static_assert(sizeof(gid_t) == 4 && _Alignof(gid_t) == 4,
    "x86 gid_t ABI");
_Static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");
_Static_assert(SYS_setfsgid == 123, "Linux 5.10 x86 setfsgid syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setfsgid),
    setfsgid_signature), "setfsgid declaration");

static setfsgid_signature setfsgid_function = setfsgid;

int crabc_x86_64_setfsgid_header_abi_probe(void)
{
    return setfsgid_function != (setfsgid_signature)0 ? 0 : 1;
}
