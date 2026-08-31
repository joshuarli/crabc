/* C++17 companion for the Linux/x86-64 POSIX sigpending declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_SIGPENDING)
using sigpending_signature = int (*)(sigset_t *);

static_assert(__is_same(decltype(&sigpending), sigpending_signature),
    "C++ POSIX sigpending declaration");

/* Retain the name so the object proof observes unmangled C linkage. */
__attribute__((used)) static sigpending_signature sigpending_cxx_reference =
    sigpending;
#endif

/* Both strict POSIX and GNU C++ profiles must retain this POSIX spelling. */
#if defined(CRABC_REQUIRE_SIGPENDING)
__attribute__((used)) static auto sigpending_must_be_visible = &sigpending;
#endif

int crabc_x86_64_sigpending_header_abi_probe_cpp()
{
    return 0;
}
