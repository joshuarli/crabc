/* Source-only Linux/x86-64 stdlib.h unlockpt declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#if defined(CRABC_EXPECT_UNLOCKPT)
typedef int (*unlockpt_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&unlockpt),
    unlockpt_signature), "unlockpt declaration");

static unlockpt_signature unlockpt_function __attribute__((used)) = unlockpt;
#endif

/* An opt-in reference that must fail while the extension is hidden. */
#if defined(CRABC_REQUIRE_UNLOCKPT_HIDDEN)
typedef int (*hidden_unlockpt_signature)(int);
static hidden_unlockpt_signature unlockpt_must_be_hidden = unlockpt;
#endif

int crabc_x86_64_unlockpt_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_UNLOCKPT)
    return unlockpt_function != (unlockpt_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
