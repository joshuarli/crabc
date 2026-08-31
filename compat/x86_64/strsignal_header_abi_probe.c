/* Linux/x86-64 <string.h> strsignal declaration and feature-visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef char *(*strsignal_signature)(int);

#if defined(CRABC_EXPECT_STRSIGNAL)
static strsignal_signature strsignal_function __attribute__((used)) = strsignal;
#endif

/* This branch is compiled only for strict-feature negative checks. */
#if defined(CRABC_REQUIRE_STRSIGNAL_HIDDEN)
static strsignal_signature required_strsignal_function = strsignal;
#endif

int crabc_x86_64_strsignal_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_STRSIGNAL)
    return strsignal_function == 0;
#else
    return 0;
#endif
}
