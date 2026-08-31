/* Source-only Linux/x86-64 <unistd.h> getpagesize declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*getpagesize_signature)(void);

#if defined(CRABC_EXPECT_GETPAGESIZE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpagesize),
    getpagesize_signature), "getpagesize declaration");
static getpagesize_signature getpagesize_signature_value = getpagesize;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_GETPAGESIZE_HIDDEN)
static getpagesize_signature getpagesize_must_be_hidden = getpagesize;
#endif

int crabc_x86_64_getpagesize_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_GETPAGESIZE)
    return getpagesize_signature_value != (getpagesize_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
