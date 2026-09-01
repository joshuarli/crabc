/* C++17 companion for the Linux/x86-64 GNU bsd_signal header contract. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_BSD_SIGNAL)
using bsd_signal_handler = void (*)(int);
using bsd_signal_signature = bsd_signal_handler (*)(int, bsd_signal_handler);

static_assert(__is_same(decltype(&bsd_signal), bsd_signal_signature),
    "GNU C++ bsd_signal declaration");

/* The header declaration must already be C linkage. This exact redeclaration
 * detects a misplaced project-header declaration, and the object witness
 * below proves that it retains the unmangled bsd_signal spelling. */
extern "C" bsd_signal_handler bsd_signal(int, bsd_signal_handler);
__attribute__((used)) static bsd_signal_signature bsd_signal_cxx_reference =
    bsd_signal;
#endif

/* Strict/POSIX C++ must reject this GNU-only declaration. */
#if defined(CRABC_REQUIRE_BSD_SIGNAL_HIDDEN)
__attribute__((used)) static auto bsd_signal_must_be_hidden = &bsd_signal;
#endif

int crabc_x86_64_signal_legacy_aliases_header_abi_probe_cpp()
{
    return 0;
}
