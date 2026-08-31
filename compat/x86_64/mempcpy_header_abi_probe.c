/* Source-only Linux/x86-64 <string.h> mempcpy declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef void *(*mempcpy_signature)(void *, const void *, size_t);

#if defined(CRABC_EXPECT_MEMPCPY)
static mempcpy_signature mempcpy_signature_value = mempcpy;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_MEMPCPY_HIDDEN)
static mempcpy_signature required_mempcpy_signature = mempcpy;
#endif

int crabc_x86_64_mempcpy_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_MEMPCPY)
    (void)mempcpy_signature_value;
#endif
#if defined(CRABC_REQUIRE_MEMPCPY_HIDDEN)
    (void)required_mempcpy_signature;
#endif
    return 0;
}
