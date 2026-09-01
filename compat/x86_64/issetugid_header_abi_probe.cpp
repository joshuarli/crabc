/* C++17 companion for the Linux/x86-64 GNU/BSD issetugid declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using issetugid_signature = int (*)(void);

#if defined(CRABC_EXPECT_ISSETUGID)
static_assert(__is_same(decltype(&issetugid), issetugid_signature),
    "issetugid declaration");
static issetugid_signature issetugid_function __attribute__((used)) = issetugid;
#endif

#if defined(CRABC_REQUIRE_ISSETUGID_HIDDEN)
static issetugid_signature issetugid_must_be_hidden __attribute__((used)) = issetugid;
#endif

int crabc_x86_64_issetugid_header_abi_probe()
{
#if defined(CRABC_EXPECT_ISSETUGID)
    return issetugid_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
