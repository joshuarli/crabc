/* C++17 companion for the Linux/x86-64 setfsgid declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>

using setfsgid_signature = int (*)(gid_t);

static_assert(sizeof(gid_t) == 4 && alignof(gid_t) == 4,
    "x86 gid_t ABI");
static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");
static_assert(SYS_setfsgid == 123, "Linux 5.10 x86 setfsgid syscall number");
static_assert(__is_same(decltype(&setfsgid), setfsgid_signature),
    "C++ setfsgid declaration");

extern "C" void crabc_setfsgid_linkage_witness(setfsgid_signature);

static setfsgid_signature setfsgid_function = setfsgid;

int crabc_x86_64_setfsgid_header_abi_probe_cpp()
{
    crabc_setfsgid_linkage_witness(setfsgid_function);
    return setfsgid_function != nullptr ? 0 : 1;
}
