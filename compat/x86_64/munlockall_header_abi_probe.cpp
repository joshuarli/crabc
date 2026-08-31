/* Linux/x86-64 selected <sys/mman.h> munlockall C++17 declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

using munlockall_type = int (*)();

static_assert(__is_same(decltype(&munlockall), munlockall_type),
    "C++ munlockall declaration");

__attribute__((used)) static munlockall_type crabc_munlockall_cpp_linkage =
    munlockall;

int crabc_x86_64_munlockall_header_abi_probe_cpp()
{
    return 0;
}
