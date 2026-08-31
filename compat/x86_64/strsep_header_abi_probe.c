/* Source-only Linux/x86-64 <string.h> strsep declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef char *(*strsep_signature)(char **, const char *);

#if defined(CRABC_EXPECT_STRSEP)
static strsep_signature strsep_signature_value = strsep;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_STRSEP_HIDDEN)
static strsep_signature required_strsep_signature = strsep;
#endif

int crabc_x86_64_strsep_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_STRSEP)
    (void)strsep_signature_value;
#endif
#if defined(CRABC_REQUIRE_STRSEP_HIDDEN)
    (void)required_strsep_signature;
#endif
    return 0;
}
