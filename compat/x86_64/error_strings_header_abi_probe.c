/* Source-only Linux/x86-64 <string.h> error-string declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef char *(*strerror_signature)(int);
typedef int (*strerror_r_signature)(int, char *, size_t);

#if defined(CRABC_EXPECT_STRERROR_L) || defined(CRABC_REQUIRE_STRERROR_L_HIDDEN)
typedef char *(*strerror_l_signature)(int, locale_t);
#endif

static strerror_signature strerror_function = strerror;

#if defined(CRABC_EXPECT_STRERROR_R)
static strerror_r_signature strerror_r_function = strerror_r;
#endif

#if defined(CRABC_EXPECT_STRERROR_L)
static strerror_l_signature strerror_l_function = strerror_l;
#endif

/* This branch is compiled only for strict-feature negative checks. */
#if defined(CRABC_REQUIRE_STRERROR_R_HIDDEN)
static strerror_r_signature required_strerror_r_function = strerror_r;
#endif

/* This branch is compiled only for strict-feature negative checks. */
#if defined(CRABC_REQUIRE_STRERROR_L_HIDDEN)
static strerror_l_signature required_strerror_l_function = strerror_l;
#endif

int crabc_x86_64_error_strings_header_abi_probe(void)
{
    (void)strerror_function;
#if defined(CRABC_EXPECT_STRERROR_R)
    (void)strerror_r_function;
#endif
#if defined(CRABC_EXPECT_STRERROR_L)
    (void)strerror_l_function;
#endif
#if defined(CRABC_REQUIRE_STRERROR_R_HIDDEN)
    (void)required_strerror_r_function;
#endif
#if defined(CRABC_REQUIRE_STRERROR_L_HIDDEN)
    (void)required_strerror_l_function;
#endif
    return 0;
}
