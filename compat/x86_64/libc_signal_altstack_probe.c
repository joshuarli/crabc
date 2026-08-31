/* Static crabc-libc x86-64 alternate signal-stack fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6 and
 * then through a true dependency-free `-nostdlib -static` crabc candidate.
 * It proves the modern `sigaltstack` record/precondition boundary and one
 * real SA_ONSTACK handler entry/return through the already-selected action
 * restorer. It neither allocates a signal stack nor turns the existing signal
 * leaves into a general signal framework, pthread policy, or runtime claim.
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
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

enum { ALT_STACK_BYTES = 64 * 1024 };

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8,
    "x86 scalar ABI");
_Static_assert(sizeof(stack_t) == 24 && _Alignof(stack_t) == 8,
    "x86 alternate-stack record ABI");
_Static_assert(offsetof(stack_t, ss_sp) == 0 &&
    offsetof(stack_t, ss_flags) == 8 && offsetof(stack_t, ss_size) == 16,
    "x86 alternate-stack field ABI");
_Static_assert(SS_ONSTACK == 1 && SS_DISABLE == 2 && MINSIGSTKSZ == 2048,
    "x86 alternate-stack constants");
_Static_assert(SA_ONSTACK == 0x08000000 && SIGUSR1 == 10,
    "x86 alternate-stack delivery constants");
_Static_assert(SYS_sigaltstack == 131,
    "x86 sigaltstack syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigaltstack),
    int (*)(const stack_t *, stack_t *)), "sigaltstack declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigaction),
    int (*)(int, const struct sigaction *, struct sigaction *)),
    "sigaction declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&raise), int (*)(int)),
    "raise declaration");

static unsigned char alternate_stack[ALT_STACK_BYTES]
    __attribute__((aligned(64)));
static volatile sig_atomic_t handler_signal;
static volatile sig_atomic_t handler_on_alt_stack;
static volatile sig_atomic_t handler_disable_rejected;

static int same_stack(const stack_t *left, const stack_t *right)
{
    return left->ss_sp == right->ss_sp &&
        left->ss_flags == right->ss_flags &&
        left->ss_size == right->ss_size;
}

static void record_alt_stack_delivery(int signal)
{
    volatile unsigned char marker;
    stack_t running = {0};
    stack_t disable = {
        .ss_sp = 0,
        .ss_flags = SS_DISABLE,
        .ss_size = 0,
    };
    uintptr_t marker_address = (uintptr_t)(const void *)&marker;
    uintptr_t stack_start = (uintptr_t)(const void *)alternate_stack;
    uintptr_t stack_end = stack_start + sizeof(alternate_stack);

    handler_signal = signal;
    if (sigaltstack(0, &running) == 0 &&
        (running.ss_flags & SS_ONSTACK) != 0 &&
        running.ss_sp == (void *)alternate_stack &&
        running.ss_size == sizeof(alternate_stack) &&
        marker_address >= stack_start && marker_address < stack_end)
        handler_on_alt_stack = 1;

    /* Linux rejects replacement/disable while this frame owns the stack.
     * The wrapper deliberately leaves that EPERM policy to the kernel. */
    errno = 0;
    if (sigaltstack(&disable, 0) == -1 && errno == EPERM)
        handler_disable_rejected = 1;
}

static int test_altstack(void)
{
    stack_t original = {0};
    stack_t previous = {0};
    stack_t observed = {0};
    stack_t disabled_previous = {0};
    stack_t disable = {
        .ss_sp = 0,
        .ss_flags = SS_DISABLE,
        .ss_size = 0,
    };
    stack_t rejected_onstack = {
        .ss_sp = alternate_stack,
        .ss_flags = SS_ONSTACK,
        .ss_size = sizeof(alternate_stack),
    };
    stack_t too_small = {
        .ss_sp = alternate_stack,
        .ss_flags = 0,
        .ss_size = MINSIGSTKSZ - 1,
    };
    stack_t too_small_onstack = {
        .ss_sp = alternate_stack,
        .ss_flags = SS_ONSTACK,
        .ss_size = MINSIGSTKSZ - 1,
    };
    stack_t enabled = {
        .ss_sp = alternate_stack,
        .ss_flags = 0,
        .ss_size = sizeof(alternate_stack),
    };
    struct sigaction saved_action = {0};
    struct sigaction action = {0};
    int action_saved = 0;
    int stack_changed = 0;
    int result = 1;

    errno = ERANGE;
    if (sigaltstack(0, &original) != 0 || errno != ERANGE)
        return result;

    errno = E2BIG;
    if (sigaltstack(0, 0) != 0 || errno != E2BIG) {
        result = 2;
        goto cleanup;
    }

    errno = 0;
    if (sigaltstack(&rejected_onstack, 0) != -1 || errno != EINVAL) {
        result = 3;
        goto cleanup;
    }

    errno = 0;
    if (sigaltstack(&too_small, 0) != -1 || errno != ENOMEM) {
        result = 4;
        goto cleanup;
    }

    /* Pinned musl tests the enabled size before SS_ONSTACK, so this
     * intentionally both-invalid record reports ENOMEM, not EINVAL. */
    errno = 0;
    if (sigaltstack(&too_small_onstack, 0) != -1 || errno != ENOMEM) {
        result = 5;
        goto cleanup;
    }

    errno = ERANGE;
    if (sigaltstack(&enabled, &previous) != 0 || errno != ERANGE ||
        !same_stack(&previous, &original)) {
        result = 6;
        goto cleanup;
    }
    stack_changed = 1;

    errno = E2BIG;
    if (sigaltstack(0, &observed) != 0 || errno != E2BIG ||
        observed.ss_sp != (void *)alternate_stack || observed.ss_flags != 0 ||
        observed.ss_size != sizeof(alternate_stack)) {
        result = 7;
        goto cleanup;
    }

    if (sigaction(SIGUSR1, 0, &saved_action) != 0) {
        result = 8;
        goto cleanup;
    }
    action_saved = 1;
    if (sigemptyset(&action.sa_mask) != 0) {
        result = 9;
        goto cleanup;
    }
    action.sa_handler = record_alt_stack_delivery;
    action.sa_flags = SA_ONSTACK;
    action.sa_restorer = 0;
    if (sigaction(SIGUSR1, &action, 0) != 0) {
        result = 10;
        goto cleanup;
    }

    handler_signal = 0;
    handler_on_alt_stack = 0;
    handler_disable_rejected = 0;
    if (raise(SIGUSR1) != 0 || handler_signal != SIGUSR1 ||
        handler_on_alt_stack != 1 || handler_disable_rejected != 1) {
        result = 11;
        goto cleanup;
    }

    if (sigaltstack(0, &observed) != 0 ||
        observed.ss_sp != (void *)alternate_stack || observed.ss_flags != 0 ||
        observed.ss_size != sizeof(alternate_stack)) {
        result = 12;
        goto cleanup;
    }

    errno = ERANGE;
    if (sigaltstack(&disable, &disabled_previous) != 0 || errno != ERANGE ||
        !same_stack(&disabled_previous, &enabled)) {
        result = 13;
        goto cleanup;
    }
    /* Keep cleanup responsible for restoring the captured entry state until
     * that restoration has itself succeeded below. */
    stack_changed = 1;

    errno = E2BIG;
    if (sigaltstack(0, &observed) != 0 || errno != E2BIG ||
        observed.ss_sp != 0 || observed.ss_flags != SS_DISABLE ||
        observed.ss_size != 0) {
        result = 14;
        goto cleanup;
    }

    errno = ERANGE;
    if (sigaltstack(&original, 0) != 0 || errno != ERANGE) {
        result = 15;
        goto cleanup;
    }
    stack_changed = 0;
    result = 0;

cleanup:
    if (action_saved)
        (void)sigaction(SIGUSR1, &saved_action, 0);
    if (stack_changed)
        (void)sigaltstack(&original, 0);
    return result;
}

int crabc_x86_64_signal_altstack_probe(void)
{
    return test_altstack();
}

#ifndef CRABC_SIGNAL_ALTSTACK_FREESTANDING
int main(void)
{
    return crabc_x86_64_signal_altstack_probe();
}
#endif
