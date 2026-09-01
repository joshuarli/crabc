/* Linux/x86-64 GNU <signal.h> bsd_signal declaration/visibility probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

typedef void (*bsd_signal_handler)(int);
typedef bsd_signal_handler (*bsd_signal_signature)(int, bsd_signal_handler);

#if defined(CRABC_EXPECT_BSD_SIGNAL)
_Static_assert(__builtin_types_compatible_p(__typeof__(&bsd_signal),
    bsd_signal_signature), "GNU bsd_signal declaration");
__attribute__((used)) static bsd_signal_signature bsd_signal_c_reference =
    bsd_signal;
#endif

/* This branch is compiled only where GNU-only bsd_signal must be hidden. */
#if defined(CRABC_REQUIRE_BSD_SIGNAL_HIDDEN)
__attribute__((used)) static bsd_signal_signature bsd_signal_must_be_hidden =
    bsd_signal;
#endif

int crabc_x86_64_signal_legacy_aliases_header_abi_probe(void)
{
    return 0;
}
