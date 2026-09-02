/* C++17 companion for the Linux/x86-64 ualarm declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_UALARM)
using ualarm_signature = unsigned int (*)(unsigned int, unsigned int);

static_assert(__is_same(decltype(&ualarm), ualarm_signature),
    "C++ ualarm declaration");

static ualarm_signature ualarm_function = ualarm;
#endif

/* An opt-in reference that must fail when the extension is hidden. */
#if defined(CRABC_REQUIRE_UALARM_HIDDEN)
using hidden_ualarm_signature = unsigned int (*)(unsigned int, unsigned int);
static hidden_ualarm_signature ualarm_must_be_hidden = ualarm;
#endif

int crabc_x86_64_ualarm_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_UALARM)
    return ualarm_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
