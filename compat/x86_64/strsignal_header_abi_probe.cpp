/* Linux/x86-64 <string.h> strsignal C++ linkage and feature-visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

using strsignal_signature = char *(*)(int);

#if defined(CRABC_EXPECT_STRSIGNAL)
static_assert(__is_same(decltype(&strsignal), strsignal_signature),
              "strsignal declaration");
static strsignal_signature strsignal_function __attribute__((used)) = strsignal;
#endif

#if defined(CRABC_REQUIRE_STRSIGNAL_HIDDEN)
static strsignal_signature required_strsignal_function = strsignal;
#endif

int crabc_x86_64_strsignal_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_STRSIGNAL)
    return strsignal_function == nullptr;
#else
    return 0;
#endif
}
