/* Source-only Linux/x86-64 <unistd.h> getdtablesize declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*getdtablesize_signature)(void);

#if defined(CRABC_EXPECT_GETDTABLESIZE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&getdtablesize),
    getdtablesize_signature), "getdtablesize declaration");
static getdtablesize_signature getdtablesize_signature_value = getdtablesize;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_GETDTABLESIZE_HIDDEN)
static getdtablesize_signature getdtablesize_must_be_hidden = getdtablesize;
#endif

int crabc_x86_64_getdtablesize_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_GETDTABLESIZE)
    return getdtablesize_signature_value != (getdtablesize_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
