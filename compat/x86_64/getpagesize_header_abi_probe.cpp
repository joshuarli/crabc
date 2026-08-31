/* C++17 companion for the Linux/x86-64 getpagesize declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using getpagesize_signature = int (*)(void);

#if defined(CRABC_EXPECT_GETPAGESIZE)
static_assert(__is_same(decltype(&getpagesize), getpagesize_signature),
    "C++ getpagesize declaration");
static getpagesize_signature getpagesize_signature_value = getpagesize;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_GETPAGESIZE_HIDDEN)
static getpagesize_signature getpagesize_must_be_hidden = getpagesize;
#endif

int crabc_x86_64_getpagesize_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_GETPAGESIZE)
    return getpagesize_signature_value != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
