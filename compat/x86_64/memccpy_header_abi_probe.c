/* Source-only Linux/x86-64 <string.h> memccpy declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef void *(*memccpy_signature)(void *, const void *, int, size_t);

#if defined(CRABC_EXPECT_MEMCCPY)
static memccpy_signature memccpy_signature_value = memccpy;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_MEMCCPY_HIDDEN)
static memccpy_signature required_memccpy_signature = memccpy;
#endif

int crabc_x86_64_memccpy_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_MEMCCPY)
    (void)memccpy_signature_value;
#endif
#if defined(CRABC_REQUIRE_MEMCCPY_HIDDEN)
    (void)required_memccpy_signature;
#endif
    return 0;
}
