/* Static crabc-libc x86-64 alternate signal-stack fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6 and
 * then through a true dependency-free `-nostdlib -static` crabc candidate.
 * It records the sigaltstack record/precondition boundary and two bounded
 * SA_ONSTACK handler entries through the selected action restorer. Static
 * storage keeps the alternate stack alive throughout both deliveries.
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
enum {
    OUTER_SIGNAL, OUTER_ON_STACK, OUTER_FLAGS, OUTER_QUERY_ERRNO,
    OUTER_DISABLE_ERRNO, NESTED_RAISE_RESULT, NESTED_RAISE_ERRNO,
    OUTER_AFTER_FLAGS, OUTER_AFTER_ERRNO, OUTER_PHASE,
    INNER_SIGNAL, INNER_ON_STACK, INNER_FLAGS, INNER_QUERY_ERRNO,
    INNER_DISABLE_ERRNO, INNER_PHASE, HANDLER_RECORDS
};
static volatile sig_atomic_t handler_records[HANDLER_RECORDS];
enum {
    OUTER_INFO_SIGNAL, OUTER_CONTEXT_POINTER, OUTER_CONTEXT_SIZE,
    OUTER_CONTEXT_FLAGS, INNER_INFO_SIGNAL, INNER_CONTEXT_POINTER,
    INNER_CONTEXT_SIZE, INNER_CONTEXT_FLAGS, CONTEXT_RECORDS
};
static volatile sig_atomic_t context_records[CONTEXT_RECORDS];
static volatile sig_atomic_t handler_output_untouched[2];
static volatile sig_atomic_t handler_phase;
static uint32_t observations[46];

/* A fixture-only write leaves the selected libc archive independent of stdio. */
static long write_observations(void)
{
    long result;
    register long number __asm__("rax") = 1;
    register long descriptor __asm__("rdi") = 1;
    register const void *buffer __asm__("rsi") = observations;
    register long length __asm__("rdx") = sizeof(observations);

    __asm__ volatile ("syscall" : "=a"(result) : "a"(number), "D"(descriptor),
        "S"(buffer), "d"(length) : "rcx", "r11", "memory");
    return result;
}

static int same_stack(const stack_t *left, const stack_t *right)
{
    return left->ss_sp == right->ss_sp &&
        left->ss_flags == right->ss_flags &&
        left->ss_size == right->ss_size;
}

static void record_alt_stack_delivery(int signal, siginfo_t *info, void *raw_context)
{
    volatile unsigned char marker;
    stack_t running = {0};
    stack_t disable = {
        .ss_sp = 0,
        .ss_flags = SS_DISABLE,
        .ss_size = 0,
    };
    stack_t rejected_output = {
        .ss_sp = alternate_stack + 32,
        .ss_flags = 0x1357,
        .ss_size = 0x2468,
    };
    const stack_t rejected_output_copy = rejected_output;
    uintptr_t marker_address = (uintptr_t)(const void *)&marker;
    uintptr_t stack_start = (uintptr_t)(const void *)alternate_stack;
    uintptr_t stack_end = stack_start + sizeof(alternate_stack);
    int saved_errno = errno;
    int inner = signal == SIGUSR2;
    int base = inner ? INNER_SIGNAL : OUTER_SIGNAL;
    int context_base = inner ? INNER_INFO_SIGNAL : OUTER_INFO_SIGNAL;
    ucontext_t *context = raw_context;

    handler_records[base] = signal;
    context_records[context_base] = info->si_signo;
    context_records[context_base + 1] =
        context->uc_stack.ss_sp == (void *)alternate_stack;
    context_records[context_base + 2] =
        context->uc_stack.ss_size == sizeof(alternate_stack);
    context_records[context_base + 3] = context->uc_stack.ss_flags;
    handler_records[base + 1] = marker_address >= stack_start &&
        marker_address < stack_end;
    errno = ERANGE;
    if (sigaltstack(0, &running) == 0 &&
        running.ss_sp == (void *)alternate_stack &&
        running.ss_size == sizeof(alternate_stack))
        handler_records[base + 2] = running.ss_flags;
    handler_records[base + 3] = errno;

    /* Query and disable take the direct syscall path in both selected
     * runtimes. An enabled request could invoke size preflight, so handlers
     * never make one. Linux rejects disable while either frame owns the stack. */
    errno = 0;
    if (sigaltstack(&disable, &rejected_output) == -1)
        handler_records[base + 4] = errno;
    handler_output_untouched[inner] =
        same_stack(&rejected_output, &rejected_output_copy);

    if (inner) {
        handler_records[INNER_PHASE] = handler_phase;
    } else {
        handler_phase = 1;
        errno = ERANGE;
        handler_records[NESTED_RAISE_RESULT] = raise(SIGUSR2);
        handler_records[NESTED_RAISE_ERRNO] = errno;
        errno = E2BIG;
        if (sigaltstack(0, &running) == 0)
            handler_records[OUTER_AFTER_FLAGS] = running.ss_flags;
        handler_records[OUTER_AFTER_ERRNO] = errno;
        handler_phase = 2;
        handler_records[OUTER_PHASE] = handler_phase;
    }
    errno = saved_errno;
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
    stack_t invalid_flags = {
        .ss_sp = alternate_stack,
        .ss_flags = 4,
        .ss_size = sizeof(alternate_stack),
    };
    stack_t enabled = {
        .ss_sp = alternate_stack,
        .ss_flags = 0,
        .ss_size = sizeof(alternate_stack),
    };
    stack_t untouched = {
        .ss_sp = alternate_stack + 32,
        .ss_flags = 0x1357,
        .ss_size = 0x2468,
    };
    const stack_t untouched_copy = untouched;
    struct sigaction saved_action = {0};
    struct sigaction saved_nested_action = {0};
    struct sigaction action = {0};
    int action_saved = 0;
    int nested_action_saved = 0;
    int stack_changed = 0;
    int result = 1;
    int index;

    errno = ERANGE;
    if (sigaltstack(0, &original) != 0 || errno != ERANGE)
        goto cleanup;
    observations[0] = original.ss_flags;
    observations[1] = original.ss_size;

    errno = E2BIG;
    if (sigaltstack(0, 0) != 0 || errno != E2BIG) {
        result = 2;
        goto cleanup;
    }

    errno = 0;
    if (sigaltstack(&rejected_onstack, &untouched) != -1 ||
        errno != EINVAL || !same_stack(&untouched, &untouched_copy)) {
        result = 3;
        goto cleanup;
    }
    observations[40] = same_stack(&untouched, &untouched_copy);

    errno = 0;
    if (sigaltstack(&too_small, &untouched) != -1 ||
        errno != ENOMEM || !same_stack(&untouched, &untouched_copy)) {
        result = 4;
        goto cleanup;
    }
    observations[41] = same_stack(&untouched, &untouched_copy);

    /* Pinned musl tests the enabled size before SS_ONSTACK, so this
     * intentionally both-invalid record reports ENOMEM, not EINVAL. */
    errno = 0;
    if (sigaltstack(&too_small_onstack, &untouched) != -1 ||
        errno != ENOMEM || !same_stack(&untouched, &untouched_copy)) {
        result = 5;
        goto cleanup;
    }
    observations[42] = same_stack(&untouched, &untouched_copy);

    errno = 0;
    if (sigaltstack(&invalid_flags, &untouched) != -1 ||
        errno != EINVAL || !same_stack(&untouched, &untouched_copy)) {
        result = 19;
        goto cleanup;
    }
    observations[43] = same_stack(&untouched, &untouched_copy);

    errno = ERANGE;
    if (sigaltstack(&enabled, &previous) != 0 || errno != ERANGE ||
        !same_stack(&previous, &original)) {
        result = 6;
        goto cleanup;
    }
    observations[2] = previous.ss_flags;
    observations[3] = errno;
    stack_changed = 1;

    errno = E2BIG;
    if (sigaltstack(0, &observed) != 0 || errno != E2BIG ||
        observed.ss_sp != (void *)alternate_stack || observed.ss_flags != 0 ||
        observed.ss_size != sizeof(alternate_stack)) {
        result = 7;
        goto cleanup;
    }
    observations[4] = observed.ss_flags;
    observations[5] = observed.ss_size;
    observations[6] = errno;

    if (sigaction(SIGUSR1, 0, &saved_action) != 0) {
        result = 8;
        goto cleanup;
    }
    action_saved = 1;
    if (sigaction(SIGUSR2, 0, &saved_nested_action) != 0) {
        result = 16;
        goto cleanup;
    }
    nested_action_saved = 1;
    if (sigemptyset(&action.sa_mask) != 0) {
        result = 9;
        goto cleanup;
    }
    action.sa_sigaction = record_alt_stack_delivery;
    action.sa_flags = SA_ONSTACK | SA_SIGINFO;
    action.sa_restorer = 0;
    if (sigaction(SIGUSR1, &action, 0) != 0) {
        result = 10;
        goto cleanup;
    }
    if (sigaction(SIGUSR2, &action, 0) != 0) {
        result = 17;
        goto cleanup;
    }

    errno = E2BIG;
    if (raise(SIGUSR1) != 0 || errno != E2BIG ||
        handler_records[OUTER_SIGNAL] != SIGUSR1 ||
        handler_records[OUTER_ON_STACK] != 1 ||
        handler_records[OUTER_FLAGS] != SS_ONSTACK ||
        handler_records[OUTER_QUERY_ERRNO] != ERANGE ||
        handler_records[OUTER_DISABLE_ERRNO] != EPERM ||
        handler_records[NESTED_RAISE_RESULT] != 0 ||
        handler_records[NESTED_RAISE_ERRNO] != ERANGE ||
        handler_records[OUTER_AFTER_FLAGS] != SS_ONSTACK ||
        handler_records[OUTER_AFTER_ERRNO] != E2BIG ||
        handler_records[OUTER_PHASE] != 2 ||
        handler_records[INNER_SIGNAL] != SIGUSR2 ||
        handler_records[INNER_ON_STACK] != 1 ||
        handler_records[INNER_FLAGS] != SS_ONSTACK ||
        handler_records[INNER_QUERY_ERRNO] != ERANGE ||
        handler_records[INNER_DISABLE_ERRNO] != EPERM ||
        handler_records[INNER_PHASE] != 1 ||
        handler_output_untouched[0] != 1 ||
        handler_output_untouched[1] != 1) {
        result = 11;
        goto cleanup;
    }
    observations[23] = errno;

    if (sigaltstack(0, &observed) != 0 ||
        observed.ss_sp != (void *)alternate_stack || observed.ss_flags != 0 ||
        observed.ss_size != sizeof(alternate_stack)) {
        result = 12;
        goto cleanup;
    }
    observations[24] = observed.ss_flags;

    errno = ERANGE;
    if (sigaltstack(&disable, &disabled_previous) != 0 || errno != ERANGE ||
        !same_stack(&disabled_previous, &enabled)) {
        result = 13;
        goto cleanup;
    }
    observations[25] = disabled_previous.ss_flags;
    observations[26] = errno;
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
    observations[27] = observed.ss_flags;
    observations[28] = observed.ss_size;
    observations[29] = errno;

    errno = ERANGE;
    if (sigaltstack(&original, 0) != 0 || errno != ERANGE) {
        result = 15;
        goto cleanup;
    }
    observations[30] = errno;
    stack_changed = 0;
    result = 0;

cleanup:
    if (nested_action_saved)
        (void)sigaction(SIGUSR2, &saved_nested_action, 0);
    if (action_saved)
        (void)sigaction(SIGUSR1, &saved_action, 0);
    if (stack_changed)
        (void)sigaltstack(&original, 0);
    for (index = 0; index < HANDLER_RECORDS; ++index)
        observations[7 + index] = handler_records[index];
    for (index = 0; index < CONTEXT_RECORDS; ++index)
        observations[32 + index] = context_records[index];
    observations[44] = handler_output_untouched[0];
    observations[45] = handler_output_untouched[1];
    observations[31] = result;
    if (write_observations() != sizeof(observations) && result == 0)
        result = 18;
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
