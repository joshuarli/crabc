/* Linux/x86-64 <stdlib.h> getsubopt C++ linkage/visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

using getsubopt_signature = int (*)(char **, char *const *, char **);

#if defined(CRABC_EXPECT_GETSUBOPT)
static_assert(__is_same(decltype(&getsubopt), getsubopt_signature),
              "getsubopt declaration");
static getsubopt_signature getsubopt_function __attribute__((used)) = getsubopt;
#endif

#if defined(CRABC_REQUIRE_GETSUBOPT_HIDDEN)
static getsubopt_signature required_getsubopt_function = getsubopt;
#endif

int crabc_x86_64_getsubopt_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_GETSUBOPT)
    return getsubopt_function == nullptr;
#else
    return 0;
#endif
}
