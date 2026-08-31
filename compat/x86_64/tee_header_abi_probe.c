/* Source-only Linux/x86-64 GNU <fcntl.h> tee declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <fcntl.h>

typedef ssize_t (*tee_signature)(int, int, size_t, unsigned);

#if defined(CRABC_EXPECT_TEE)
static tee_signature tee_signature_value = tee;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_TEE_HIDDEN)
static tee_signature required_tee_signature = tee;
#endif

int crabc_x86_64_tee_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_TEE)
    (void)tee_signature_value;
#endif
#if defined(CRABC_REQUIRE_TEE_HIDDEN)
    (void)required_tee_signature;
#endif
    return 0;
}
