/* Linux/x86-64 <signal.h> SysV-helper declaration and visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

typedef int (*sysv_signal_unary_signature)(int);
/* XSI exposes the function declaration without GNU sighandler_t in both
 * native x86 header trees, so retain the concrete handler signature. */
typedef void (*sysv_signal_handler_signature)(int);
typedef sysv_signal_handler_signature (*sysv_sigset_signature)(
    int, sysv_signal_handler_signature);

#if defined(CRABC_EXPECT_SYSV_SIGNAL_HELPERS)
_Static_assert(__builtin_types_compatible_p(__typeof__(&sighold),
    sysv_signal_unary_signature), "sighold declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigignore),
    sysv_signal_unary_signature), "sigignore declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigrelse),
    sysv_signal_unary_signature), "sigrelse declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigset),
    sysv_sigset_signature), "sigset declaration");

__attribute__((used)) static sysv_signal_unary_signature sighold_reference =
    sighold;
__attribute__((used)) static sysv_signal_unary_signature sigignore_reference =
    sigignore;
__attribute__((used)) static sysv_signal_unary_signature sigrelse_reference =
    sigrelse;
__attribute__((used)) static sysv_sigset_signature sigset_reference = sigset;
#endif

/* This branch is compiled only where the legacy-XSI declarations must hide. */
#if defined(CRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN)
__attribute__((used)) static sysv_signal_unary_signature sighold_hidden =
    sighold;
__attribute__((used)) static sysv_signal_unary_signature sigignore_hidden =
    sigignore;
__attribute__((used)) static sysv_signal_unary_signature sigrelse_hidden =
    sigrelse;
__attribute__((used)) static sysv_sigset_signature sigset_hidden = sigset;
#endif

int crabc_x86_64_signal_sysv_helpers_header_abi_probe(void)
{
    return 0;
}
