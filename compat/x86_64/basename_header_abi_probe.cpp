/* C++17 companion for the Linux/x86-64 basename declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <libgen.h>

using basename_signature = char *(*)(char *);

#if defined(CRABC_EXPECT_BASENAME)
static_assert(__is_same(decltype(&basename), basename_signature),
    "basename declaration");
static basename_signature basename_function __attribute__((used)) = basename;
#endif

int crabc_x86_64_basename_header_abi_probe()
{
#if defined(CRABC_EXPECT_BASENAME)
    return basename_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
