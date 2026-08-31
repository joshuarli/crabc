/* Pinned-musl/project Linux/x86-64 <ulimit.h> C++ linkage gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <ulimit.h>

#if defined(CRABC_EXPECT_ULIMIT)
using ulimit_signature = long (*)(int, ...);

static_assert(sizeof(long) == 8, "x86 LP64 long width");
static_assert(UL_GETFSIZE == 1 && UL_SETFSIZE == 2,
    "musl historical ulimit commands");
static_assert(__is_same(decltype(&ulimit), ulimit_signature),
    "C++ ulimit declaration");

static ulimit_signature ulimit_function __attribute__((used)) = ulimit;
#endif

int crabc_x86_64_ulimit_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_ULIMIT)
    return ulimit_function == nullptr;
#else
    return 0;
#endif
}
