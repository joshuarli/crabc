/* C++17 companion for the Linux/x86-64 l64a declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

using l64a_signature = char *(*)(long);

#if defined(CRABC_EXPECT_L64A)
static_assert(__is_same(decltype(&l64a), l64a_signature),
              "C++ l64a declaration");
static l64a_signature l64a_function __attribute__((used)) = l64a;
#endif

/* This opt-in reference must fail under strict and POSIX C++ selectors. */
#if defined(CRABC_REQUIRE_L64A_HIDDEN)
static l64a_signature l64a_must_be_hidden = l64a;
#endif

int crabc_x86_64_l64a_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_L64A)
    return l64a_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
