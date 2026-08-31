/* Pinned-musl/project Linux/x86-64 personality declaration and scalar ABI gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <sys/personality.h>
#include <sys/syscall.h>

typedef int (*personality_signature)(unsigned long);

_Static_assert(sizeof(unsigned long) == 8 && _Alignof(unsigned long) == 8,
    "x86 unsigned long ABI");
_Static_assert(PER_LINUX == 0 && PER_MASK == 0xff,
    "Linux personality base-mask constants");
_Static_assert(SYS_personality == 135,
    "Linux 5.10 x86 personality syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&personality),
    personality_signature), "personality declaration");

static personality_signature personality_function = personality;

int crabc_x86_64_personality_header_abi_probe(void)
{
    return personality_function != (personality_signature)0 ? 0 : 1;
}
