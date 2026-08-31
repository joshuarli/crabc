/* Source-only Linux/x86-64 GNU <fcntl.h> splice declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <fcntl.h>

typedef ssize_t (*splice_signature)(int, off_t *, int, off_t *, size_t,
    unsigned);

#if defined(CRABC_EXPECT_SPLICE)
_Static_assert(sizeof(off_t) == sizeof(long), "x86 LP64 off_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&splice),
    splice_signature), "splice declaration");
static splice_signature splice_function __attribute__((used)) = splice;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_SPLICE_HIDDEN)
static splice_signature splice_must_be_hidden __attribute__((used)) = splice;
#endif

int crabc_x86_64_splice_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_SPLICE)
    return splice_function != (splice_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
