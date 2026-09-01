/* Static Linux/x86-64 musl-shaped legacy signal-alias fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a true freestanding crabc candidate. bsd_signal is taken from
 * the GNU public header; __sysv_signal is intentionally declared locally
 * because musl exports it only as an ABI compatibility alias, not a header
 * API. The fixture checks ordinary AMD64 function calls, returned old-handler
 * values, invalid-signal errno, and restoration through all three spellings.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <signal.h>

typedef sighandler_t (*legacy_signal_signature)(int, sighandler_t);

/* musl's signal.c exports this weak ABI alias without a public declaration. */
extern sighandler_t __sysv_signal(int, sighandler_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&signal),
    legacy_signal_signature), "signal calling ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bsd_signal),
    legacy_signal_signature), "bsd_signal GNU calling ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__sysv_signal),
    legacy_signal_signature), "__sysv_signal ABI declaration");

static void first_handler(int signal)
{
    (void)signal;
}

static void second_handler(int signal)
{
    (void)signal;
}

static int check_legacy_alias_behavior(void)
{
    sighandler_t initial;

    /* This candidate deliberately names aliases only. If archive extraction
     * cannot resolve their same-object musl aliases to signal, this link fails
     * before a direct signal reference can mask that closure hole. */
    initial = bsd_signal(SIGUSR1, first_handler);
    if (initial == SIG_ERR)
        return 1;
    if (bsd_signal(SIGUSR1, second_handler) != first_handler)
        return 2;
    if (__sysv_signal(SIGUSR1, SIG_DFL) != second_handler)
        return 3;
    if (bsd_signal(SIGUSR1, initial) != SIG_DFL)
        return 4;

    errno = 0;
    if (bsd_signal(0, first_handler) != SIG_ERR || errno != EINVAL)
        return 5;
    errno = 0;
    if (__sysv_signal(0, first_handler) != SIG_ERR || errno != EINVAL)
        return 6;
    return 0;
}

#if defined(CRABC_SIGNAL_LEGACY_ALIASES_FREESTANDING)
int crabc_x86_64_signal_legacy_aliases_probe(void)
{
    return check_legacy_alias_behavior();
}
#else
int main(void)
{
    return check_legacy_alias_behavior();
}
#endif
