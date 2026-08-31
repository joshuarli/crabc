/* C++17 companion for the Linux/x86-64 usleep declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_USLEEP)
using usleep_signature = int (*)(unsigned int);

static_assert(__is_same(decltype(&usleep), usleep_signature),
    "C++ usleep declaration");

static usleep_signature usleep_function = usleep;
#endif

/* An opt-in reference that must fail when the extension is hidden. */
#if defined(CRABC_REQUIRE_USLEEP_HIDDEN)
using hidden_usleep_signature = int (*)(unsigned int);
static hidden_usleep_signature usleep_must_be_hidden = usleep;
#endif

int crabc_x86_64_usleep_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_USLEEP)
    return usleep_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
