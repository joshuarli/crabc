/* C++ companion for the native x86-64 <string.h> strtok declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

using strtok_signature = char *(*)(char *, const char *);

#if defined(CRABC_EXPECT_STRTOK)
static_assert(__is_same(decltype(&strtok), strtok_signature),
              "strtok declaration");
static strtok_signature strtok_signature_value = strtok;
#endif

int crabc_x86_64_strtok_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_STRTOK)
    (void)strtok_signature_value;
#endif
    return 0;
}
