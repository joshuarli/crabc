/* Linux/x86-64 selected <sys/mman.h> mlockall C++17 declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

using mlockall_type = int (*)(int);

static_assert(__is_same(decltype(&mlockall), mlockall_type),
    "C++ mlockall declaration");
static_assert(MCL_CURRENT == 1, "C++ MCL_CURRENT ABI value");
static_assert(MCL_FUTURE == 2, "C++ MCL_FUTURE ABI value");

__attribute__((used)) static mlockall_type crabc_mlockall_cpp_linkage =
    mlockall;

int crabc_x86_64_mlockall_header_abi_probe_cpp()
{
    return 0;
}
