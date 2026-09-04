/* Pinned-musl/project Linux/x86-64 setfsuid declaration and scalar ABI gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>

typedef int (*setfsuid_signature)(uid_t);

_Static_assert(sizeof(uid_t) == 4 && _Alignof(uid_t) == 4,
    "x86 uid_t ABI");
_Static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
_Static_assert(SYS_setfsuid == 122, "Linux 5.10 x86 setfsuid syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setfsuid),
    setfsuid_signature), "setfsuid declaration");

static setfsuid_signature setfsuid_function = setfsuid;

int crabc_x86_64_setfsuid_header_abi_probe(void)
{
    return setfsuid_function != (setfsuid_signature)0 ? 0 : 1;
}
