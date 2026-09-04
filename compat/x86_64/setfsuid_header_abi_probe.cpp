/* C++17 companion for the Linux/x86-64 setfsuid declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>

using setfsuid_signature = int (*)(uid_t);

static_assert(sizeof(uid_t) == 4 && alignof(uid_t) == 4,
    "x86 uid_t ABI");
static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
static_assert(SYS_setfsuid == 122, "Linux 5.10 x86 setfsuid syscall number");
static_assert(__is_same(decltype(&setfsuid), setfsuid_signature),
    "C++ setfsuid declaration");

extern "C" void crabc_setfsuid_linkage_witness(setfsuid_signature);

static setfsuid_signature setfsuid_function = setfsuid;

int crabc_x86_64_setfsuid_header_abi_probe_cpp()
{
    crabc_setfsuid_linkage_witness(setfsuid_function);
    return setfsuid_function != nullptr ? 0 : 1;
}
