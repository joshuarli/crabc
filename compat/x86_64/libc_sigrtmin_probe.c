/*
 * Pinned-musl Linux/x86-64 __libc_current_sigrtmin differential body.
 *
 * The source closure is only musl's fixed 35 return. The same C body runs
 * through pinned musl and through the freestanding candidate, checking the
 * direct ABI spelling, existing SIGRTMIN macro value, deterministic return,
 * and stale errno without selecting delivery, actions, masks, waits,
 * descriptors, timers, pthread policy, or a general signal runtime.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>

_Static_assert(__builtin_types_compatible_p(__typeof__(&__libc_current_sigrtmin),
    int (*)(void)), "__libc_current_sigrtmin declaration");

int crabc_x86_64_sigrtmin_probe(void)
{
    errno = ERANGE;
    if (__libc_current_sigrtmin() != 35 || errno != ERANGE)
        return 1;
    if (SIGRTMIN != 35 || errno != ERANGE)
        return 2;
    if (__libc_current_sigrtmin() != SIGRTMIN || errno != ERANGE)
        return 3;
    return 0;
}

#ifndef CRABC_SIGRTMIN_FREESTANDING
int main(void)
{
    return crabc_x86_64_sigrtmin_probe();
}
#endif
