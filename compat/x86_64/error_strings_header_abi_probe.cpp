/* C++ companion for the native x86-64 <string.h> error-string probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

using strerror_signature = char *(*)(int);
using strerror_r_signature = int (*)(int, char *, size_t);

#if defined(CRABC_EXPECT_STRERROR_L) || defined(CRABC_REQUIRE_STRERROR_L_HIDDEN)
using strerror_l_signature = char *(*)(int, locale_t);
#endif

static_assert(__is_same(decltype(&strerror), strerror_signature),
              "strerror declaration");
static strerror_signature strerror_function = strerror;

#if defined(CRABC_EXPECT_STRERROR_R)
static_assert(__is_same(decltype(&strerror_r), strerror_r_signature),
              "strerror_r declaration");
static strerror_r_signature strerror_r_function = strerror_r;
#endif

#if defined(CRABC_EXPECT_STRERROR_L)
static_assert(__is_same(decltype(&strerror_l), strerror_l_signature),
              "strerror_l declaration");
static strerror_l_signature strerror_l_function = strerror_l;
#endif

#if defined(CRABC_REQUIRE_STRERROR_R_HIDDEN)
static strerror_r_signature required_strerror_r_function = strerror_r;
#endif

#if defined(CRABC_REQUIRE_STRERROR_L_HIDDEN)
static strerror_l_signature required_strerror_l_function = strerror_l;
#endif

int crabc_x86_64_error_strings_header_abi_probe_cpp()
{
    if (strerror_function == nullptr) return 1;
#if defined(CRABC_EXPECT_STRERROR_R)
    if (strerror_r_function == nullptr) return 2;
#endif
#if defined(CRABC_EXPECT_STRERROR_L)
    if (strerror_l_function == nullptr) return 3;
#endif
#if defined(CRABC_REQUIRE_STRERROR_R_HIDDEN)
    (void)required_strerror_r_function;
#endif
#if defined(CRABC_REQUIRE_STRERROR_L_HIDDEN)
    (void)required_strerror_l_function;
#endif
    return 0;
}
