/* Pinned-musl/project Linux/x86-64 l64a declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

typedef char *(*l64a_signature)(long);

#if defined(CRABC_EXPECT_L64A)
_Static_assert(__builtin_types_compatible_p(__typeof__(&l64a), l64a_signature),
    "l64a declaration");
static l64a_signature l64a_function __attribute__((used)) = l64a;
#endif

/* This opt-in reference must fail under strict and POSIX C selectors. */
#if defined(CRABC_REQUIRE_L64A_HIDDEN)
static l64a_signature l64a_must_be_hidden = l64a;
#endif

int crabc_x86_64_l64a_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_L64A)
    return l64a_function != (l64a_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
