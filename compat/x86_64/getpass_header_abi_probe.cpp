/* C++17 companion for the Linux/x86-64 getpass declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

#if defined(CRABC_EXPECT_GETPASS)
using getpass_signature = char *(*)(const char *);

static_assert(__is_same(decltype(&getpass), getpass_signature),
    "C++ getpass declaration");

static getpass_signature getpass_function = getpass;
#endif

/* An opt-in reference that must fail when the extension is hidden. */
#if defined(CRABC_REQUIRE_GETPASS_HIDDEN)
using hidden_getpass_signature = char *(*)(const char *);
static hidden_getpass_signature getpass_must_be_hidden = getpass;
#endif

int crabc_x86_64_getpass_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_GETPASS)
    return getpass_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
