/* C++17 companion for the Linux/x86-64 stdlib.h grantpt declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#if defined(CRABC_EXPECT_GRANTPT)
using grantpt_signature = int (*)(int);

static_assert(__is_same(decltype(&grantpt), grantpt_signature),
    "C++ grantpt declaration");

static grantpt_signature grantpt_function __attribute__((used)) = grantpt;
#endif

/* An opt-in reference that must fail while the extension is hidden. */
#if defined(CRABC_REQUIRE_GRANTPT_HIDDEN)
using hidden_grantpt_signature = int (*)(int);
static hidden_grantpt_signature grantpt_must_be_hidden = grantpt;
#endif

int crabc_x86_64_grantpt_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_GRANTPT)
    return grantpt_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
