/* C++17 companion for the Linux/x86-64 GNU gettid declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using gettid_signature = pid_t (*)(void);

#if defined(CRABC_EXPECT_GETTID)
static_assert(__is_same(decltype(&gettid), gettid_signature),
    "gettid declaration");
static gettid_signature gettid_function __attribute__((used)) = gettid;
#endif

#if defined(CRABC_REQUIRE_GETTID_HIDDEN)
static gettid_signature gettid_must_be_hidden __attribute__((used)) = gettid;
#endif

int crabc_x86_64_gettid_header_abi_probe()
{
#if defined(CRABC_EXPECT_GETTID)
    return gettid_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
