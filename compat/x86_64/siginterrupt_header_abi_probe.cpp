/* Linux/x86-64 <signal.h> siginterrupt C++ linkage and visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

using siginterrupt_signature = int (*)(int, int);

#if defined(CRABC_EXPECT_SIGINTERRUPT)
static_assert(__is_same(decltype(&siginterrupt), siginterrupt_signature),
    "siginterrupt declaration");
static_assert(SA_RESTART == 0x10000000, "Linux SA_RESTART value");
static siginterrupt_signature siginterrupt_function __attribute__((used)) =
    siginterrupt;
#endif

#if defined(CRABC_REQUIRE_SIGINTERRUPT_HIDDEN)
static siginterrupt_signature required_siginterrupt_function = siginterrupt;
#endif

extern "C" int crabc_x86_64_siginterrupt_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_SIGINTERRUPT)
    return siginterrupt_function == nullptr;
#else
    return 0;
#endif
}
