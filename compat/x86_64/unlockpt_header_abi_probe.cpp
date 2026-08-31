/* C++17 companion for the Linux/x86-64 stdlib.h unlockpt declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#if defined(CRABC_EXPECT_UNLOCKPT)
using unlockpt_signature = int (*)(int);

static_assert(__is_same(decltype(&unlockpt), unlockpt_signature),
    "C++ unlockpt declaration");

static unlockpt_signature unlockpt_function __attribute__((used)) = unlockpt;
#endif

/* An opt-in reference that must fail while the extension is hidden. */
#if defined(CRABC_REQUIRE_UNLOCKPT_HIDDEN)
using hidden_unlockpt_signature = int (*)(int);
static hidden_unlockpt_signature unlockpt_must_be_hidden = unlockpt;
#endif

int crabc_x86_64_unlockpt_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_UNLOCKPT)
    return unlockpt_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
