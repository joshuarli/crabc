/* Linux/x86-64 <signal.h> SysV-helper C++ linkage and visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

using sysv_signal_unary_signature = int (*)(int);
/* musl spells this function-pointer type inline rather than exposing the
 * project's `sighandler_t` typedef, so keep the oracle-facing probe literal. */
using sysv_signal_handler_signature = void (*)(int);
using sysv_sigset_signature = sysv_signal_handler_signature (*)
    (int, sysv_signal_handler_signature);

#if defined(CRABC_EXPECT_SYSV_SIGNAL_HELPERS)
static_assert(__is_same(decltype(&sighold), sysv_signal_unary_signature),
    "sighold declaration");
static_assert(__is_same(decltype(&sigignore), sysv_signal_unary_signature),
    "sigignore declaration");
static_assert(__is_same(decltype(&sigrelse), sysv_signal_unary_signature),
    "sigrelse declaration");
static_assert(__is_same(decltype(&sigset), sysv_sigset_signature),
    "sigset declaration");

/* The header declarations must retain their C ABI spellings for C++ callers. */
extern "C" int sighold(int);
extern "C" int sigignore(int);
extern "C" int sigrelse(int);
extern "C" sysv_signal_handler_signature sigset(
    int, sysv_signal_handler_signature);

__attribute__((used)) static sysv_signal_unary_signature sighold_reference =
    sighold;
__attribute__((used)) static sysv_signal_unary_signature sigignore_reference =
    sigignore;
__attribute__((used)) static sysv_signal_unary_signature sigrelse_reference =
    sigrelse;
__attribute__((used)) static sysv_sigset_signature sigset_reference = sigset;
#endif

#if defined(CRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN)
__attribute__((used)) static sysv_signal_unary_signature sighold_hidden =
    sighold;
__attribute__((used)) static sysv_signal_unary_signature sigignore_hidden =
    sigignore;
__attribute__((used)) static sysv_signal_unary_signature sigrelse_hidden =
    sigrelse;
__attribute__((used)) static sysv_sigset_signature sigset_hidden = sigset;
#endif

extern "C" int crabc_x86_64_signal_sysv_helpers_header_abi_probe_cpp()
{
    return 0;
}
