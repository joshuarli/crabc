/* C++17 companion for the Linux/x86-64 personality declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <sys/personality.h>
#include <sys/syscall.h>

using personality_signature = int (*)(unsigned long);

static_assert(sizeof(unsigned long) == 8 && alignof(unsigned long) == 8,
    "x86 unsigned long ABI");
static_assert(PER_LINUX == 0 && PER_MASK == 0xff,
    "Linux personality base-mask constants");
static_assert(SYS_personality == 135,
    "Linux 5.10 x86 personality syscall number");
static_assert(__is_same(decltype(&personality), personality_signature),
    "C++ personality declaration");

extern "C" void crabc_personality_linkage_witness(personality_signature);

static personality_signature personality_function = personality;

int crabc_x86_64_personality_header_abi_probe_cpp()
{
    crabc_personality_linkage_witness(personality_function);
    return personality_function != nullptr ? 0 : 1;
}
