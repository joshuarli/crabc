/* Pinned-musl/project Linux/x86-64 <unistd.h> fchdir C++ linkage gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_FCHDIR)
using fchdir_signature = int (*)(int);

static_assert(sizeof(int) == 4, "x86 signed int width");
static_assert(__is_same(decltype(&fchdir), fchdir_signature),
    "C++ fchdir declaration");

static fchdir_signature fchdir_function __attribute__((used)) = fchdir;
#endif

int crabc_x86_64_fchdir_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_FCHDIR)
    return fchdir_function == nullptr;
#else
    return 0;
#endif
}
