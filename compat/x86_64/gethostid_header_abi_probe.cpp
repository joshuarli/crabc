/* C++17 companion for the Linux/x86-64 gethostid declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_GETHOSTID)
using gethostid_signature = long (*)(void);

static_assert(__is_same(decltype(&gethostid), gethostid_signature),
    "C++ gethostid declaration");

static gethostid_signature gethostid_function = gethostid;
#endif

/* An opt-in reference that must fail under strict/POSIX-only selectors. */
#if defined(CRABC_REQUIRE_GETHOSTID_HIDDEN)
using hidden_gethostid_signature = long (*)(void);
static hidden_gethostid_signature gethostid_must_be_hidden = gethostid;
#endif

int crabc_x86_64_gethostid_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_GETHOSTID)
    return gethostid_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
