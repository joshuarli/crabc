/* C++17 companion for the Linux/x86-64 GNU signal-set binary helper gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_GNU_SIGNAL_SET_BINARY)
using sigset_binary_signature = int (*)(
    sigset_t *, const sigset_t *, const sigset_t *);

static_assert(__is_same(decltype(&sigandset), sigset_binary_signature),
    "C++ sigandset declaration");
static_assert(__is_same(decltype(&sigorset), sigset_binary_signature),
    "C++ sigorset declaration");

/* Retain both names so the object proof observes their unmangled C linkage. */
__attribute__((used)) static sigset_binary_signature sigandset_cxx_reference =
    sigandset;
__attribute__((used)) static sigset_binary_signature sigorset_cxx_reference =
    sigorset;
#endif

/* Strict POSIX C++ must reject both GNU-only declarations. */
#if defined(CRABC_REQUIRE_GNU_SIGNAL_SET_BINARY_HIDDEN)
__attribute__((used)) static auto sigandset_must_be_hidden = &sigandset;
__attribute__((used)) static auto sigorset_must_be_hidden = &sigorset;
#endif

int crabc_x86_64_signal_set_binary_header_abi_probe_cpp()
{
    return 0;
}
