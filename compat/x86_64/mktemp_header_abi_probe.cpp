/* C++17 companion for the Linux/x86-64 mktemp declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#if defined(CRABC_EXPECT_MKTEMP)
using mktemp_signature = char *(*)(char *);

static_assert(__is_same(decltype(&mktemp), mktemp_signature),
    "C++ mktemp declaration");

static mktemp_signature mktemp_function = mktemp;
#endif

/* An opt-in reference that must fail when the extension is hidden. */
#if defined(CRABC_REQUIRE_MKTEMP_HIDDEN)
using hidden_mktemp_signature = char *(*)(char *);
static hidden_mktemp_signature mktemp_must_be_hidden = mktemp;
#endif

int crabc_x86_64_mktemp_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_MKTEMP)
    return mktemp_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
