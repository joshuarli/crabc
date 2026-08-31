/* Linux/x86-64 <stdlib.h> getsubopt declaration/feature-visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)
typedef int (*getsubopt_signature)(char **, char *const *, char **);

#if defined(CRABC_EXPECT_GETSUBOPT)
_Static_assert(CRABC_TYPE_IS(__typeof__(&getsubopt), getsubopt_signature),
    "getsubopt declaration");
static getsubopt_signature getsubopt_function __attribute__((used)) = getsubopt;
#endif

/* Compiled only by the strict-profile negative checks. */
#if defined(CRABC_REQUIRE_GETSUBOPT_HIDDEN)
static getsubopt_signature required_getsubopt_function = getsubopt;
#endif

int crabc_x86_64_getsubopt_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_GETSUBOPT)
    return getsubopt_function == 0;
#else
    return 0;
#endif
}
