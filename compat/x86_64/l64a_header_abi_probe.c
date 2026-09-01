/* Pinned-musl/project Linux/x86-64 a64l/l64a declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

typedef char *(*l64a_signature)(long);
typedef long (*a64l_signature)(const char *);

#if defined(CRABC_EXPECT_L64A)
_Static_assert(__builtin_types_compatible_p(__typeof__(&l64a), l64a_signature),
    "l64a declaration");
static l64a_signature l64a_function __attribute__((used)) = l64a;
#endif

#if defined(CRABC_EXPECT_A64L)
_Static_assert(__builtin_types_compatible_p(__typeof__(&a64l), a64l_signature),
    "a64l declaration");
static a64l_signature a64l_function __attribute__((used)) = a64l;
#endif

/* This opt-in reference must fail under strict and POSIX C selectors. */
#if defined(CRABC_REQUIRE_L64A_HIDDEN)
static l64a_signature l64a_must_be_hidden = l64a;
#endif

/* This opt-in reference must fail under strict and POSIX C selectors. */
#if defined(CRABC_REQUIRE_A64L_HIDDEN)
static a64l_signature a64l_must_be_hidden = a64l;
#endif

int crabc_x86_64_l64a_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_L64A)
    return l64a_function != (l64a_signature)0 ? 0 : 1;
#elif defined(CRABC_EXPECT_A64L)
    return a64l_function != (a64l_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
