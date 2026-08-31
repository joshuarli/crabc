/* C++ companion for the native x86-64 <string.h> strsep declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

using strsep_signature = char *(*)(char **, const char *);

#if defined(CRABC_EXPECT_STRSEP)
static_assert(__is_same(decltype(&strsep), strsep_signature),
              "strsep declaration");
#endif

int crabc_x86_64_strsep_header_abi_probe_cpp()
{
    return 0;
}
