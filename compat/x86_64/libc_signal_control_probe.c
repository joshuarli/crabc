/* Static crabc-libc x86-64 signal-control fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. It selects only simple application signal-set helpers,
 * disposition installation/query, the calling-thread mask, and pending-state
 * observation. Fixture-local raw tgkill delivery proves the private
 * rt_sigreturn restorer without selecting `kill`, `raise`, `tgkill`, waits,
 * pthread policy, alternate stacks, queues, or a general signal runtime.
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

enum {
    SIGNAL_WORDS = sizeof(sigset_t) / sizeof(unsigned long),
    DELIVERY_SPINS = 1 << 20,
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long width");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 public sigset_t layout");
_Static_assert(sizeof(struct sigaction) == 152 &&
    _Alignof(struct sigaction) == 8, "x86 public sigaction layout");
_Static_assert(offsetof(struct sigaction, sa_mask) == 8,
    "x86 sigaction mask offset");
_Static_assert(offsetof(struct sigaction, sa_flags) == 136,
    "x86 sigaction flags offset");
_Static_assert(offsetof(struct sigaction, sa_restorer) == 144,
    "x86 sigaction restorer offset");
_Static_assert(SYS_rt_sigaction == 13 && SYS_rt_sigprocmask == 14 &&
    SYS_rt_sigpending == 127, "x86 signal syscall numbers");
_Static_assert(SYS_getpid == 39 && SYS_gettid == 186 && SYS_tgkill == 234,
    "x86 fixture-only delivery syscall numbers");
_Static_assert(SIGUSR1 == 10 && SIGUSR2 == 12, "x86 signal constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigaction),
    int (*)(int, const struct sigaction *, struct sigaction *)),
    "sigaction declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&signal),
    sighandler_t (*)(int, sighandler_t)), "signal declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigprocmask),
    int (*)(int, const sigset_t *, sigset_t *)), "sigprocmask declaration");

static volatile sig_atomic_t delivered;

static void record_delivery(int signal)
{
    delivered = signal;
}

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

/* This is fixture-local delivery machinery, not a selected C ABI wrapper. */
static int raw_tgkill_self(int signal)
{
    long pid = raw_syscall0(SYS_getpid);
    long tid = raw_syscall0(SYS_gettid);

    if (pid < 0 || tid < 0)
        return -1;
    return raw_syscall3(SYS_tgkill, pid, tid, signal) == 0 ? 0 : -1;
}

/* The fixture uses this only to observe forwarding of a reserved raw bit. */
static int raw_current_mask(unsigned long *mask)
{
    return raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, 0, (long)mask,
        sizeof *mask) == 0 ? 0 : -1;
}

static void fill_set_words(sigset_t *set, unsigned long value)
{
    for (size_t index = 0; index < SIGNAL_WORDS; index++)
        set->__bits[index] = value;
}

static int tail_has_value(const sigset_t *set, unsigned long value)
{
    for (size_t index = 1; index < SIGNAL_WORDS; index++)
        if (set->__bits[index] != value)
            return 0;
    return 1;
}

static void fill_action_bytes(struct sigaction *action, unsigned char value)
{
    unsigned char *bytes = (unsigned char *)(void *)action;

    for (size_t index = 0; index < sizeof *action; index++)
        bytes[index] = value;
}

/* Musl changes only handler, the first mask word, and flags on old actions. */
static int action_unwritten_bytes_have_value(const struct sigaction *action,
    unsigned char value)
{
    const unsigned char *bytes = (const unsigned char *)(const void *)action;

    for (size_t index = 16; index < 136; index++)
        if (bytes[index] != value)
            return 0;
    for (size_t index = 140; index < sizeof *action; index++)
        if (bytes[index] != value)
            return 0;
    return 1;
}

static int wait_for_delivery(int signal)
{
    for (unsigned long spin = 0; spin < DELIVERY_SPINS; spin++) {
        if (delivered == signal)
            return 0;
    }
    return -1;
}

static int expect_invalid_set_operation(int (*operation)(sigset_t *, int),
    sigset_t *set, int signal)
{
    errno = 0;
    if (operation(set, signal) != -1 || errno != EINVAL)
        return -1;
    return 0;
}

static int test_set_helpers(void)
{
    const unsigned long poison = 0x9e3779b97f4a7c15UL;
    sigset_t set;

    fill_set_words(&set, poison);
    if (sigemptyset(&set) != 0 || set.__bits[0] != 0 ||
        !tail_has_value(&set, poison))
        return 1;

    fill_set_words(&set, poison);
    if (sigfillset(&set) != 0 || set.__bits[0] != 0xfffffffc7fffffffUL ||
        !tail_has_value(&set, poison))
        return 2;
    if (sigismember(&set, SIGUSR1) != 1 || sigismember(&set, SIGRTMIN) != 1 ||
        sigismember(&set, SIGRTMAX) != 1 || sigismember(&set, 32) != 0 ||
        sigismember(&set, 33) != 0 || sigismember(&set, 34) != 0)
        return 3;
    if (sigismember(&set, 0) != 0 || sigismember(&set, 65) != 0)
        return 4;

    fill_set_words(&set, poison);
    set.__bits[0] = 0;
    if (sigaddset(&set, SIGUSR1) != 0 || sigismember(&set, SIGUSR1) != 1 ||
        !tail_has_value(&set, poison))
        return 5;
    if (sigdelset(&set, SIGUSR1) != 0 || sigismember(&set, SIGUSR1) != 0 ||
        !tail_has_value(&set, poison))
        return 6;
    for (int invalid = 0; invalid <= 65; invalid++) {
        if (invalid != 0 && invalid != 32 && invalid != 33 && invalid != 34 &&
            invalid != 65)
            continue;
        if (expect_invalid_set_operation(sigaddset, &set, invalid) != 0 ||
            expect_invalid_set_operation(sigdelset, &set, invalid) != 0)
            return 7;
    }

    return 0;
}

static int test_action_mask_and_pending(void)
{
    const unsigned long set_poison = 0x9e3779b97f4a7c15UL;
    const unsigned char action_poison = 0xa5;
    struct sigaction saved_usr1 = {0};
    struct sigaction saved_usr2 = {0};
    struct sigaction action = {0};
    struct sigaction observed;
    sigset_t saved_mask = {0};
    sigset_t usr1_set = {0};
    sigset_t usr2_set = {0};
    sigset_t reserved_set = {0};
    sigset_t old_mask;
    sigset_t pending;
    unsigned long raw_mask = 0;
    int saved_usr1_ready = 0;
    int saved_usr2_ready = 0;
    int saved_mask_ready = 0;
    int result = 0;

    if (SIGRTMIN != 35 || SIGRTMAX != 64) {
        result = 1;
        goto cleanup;
    }
    if (sigaction(SIGUSR1, 0, &saved_usr1) != 0) {
        result = 2;
        goto cleanup;
    }
    saved_usr1_ready = 1;
    if (sigaction(SIGUSR2, 0, &saved_usr2) != 0) {
        result = 3;
        goto cleanup;
    }
    saved_usr2_ready = 1;
    if (sigprocmask(SIG_SETMASK, 0, &saved_mask) != 0) {
        result = 4;
        goto cleanup;
    }
    saved_mask_ready = 1;

    if (sigemptyset(&usr1_set) != 0 || sigaddset(&usr1_set, SIGUSR1) != 0) {
        result = 5;
        goto cleanup;
    }

    /* A nonzero first mask word distinguishes musl's partial old-action copy. */
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaddset(&action.sa_mask, SIGUSR2) != 0) {
        result = 6;
        goto cleanup;
    }
    action.sa_handler = record_delivery;
    action.sa_flags = SA_RESTART;
    /* The selected ABI must install its private restorer, not this address. */
    action.sa_restorer = (void (*)(void))(uintptr_t)0x1234;
    if (sigaction(SIGUSR1, &action, 0) != 0) {
        result = 7;
        goto cleanup;
    }
    fill_action_bytes(&observed, action_poison);
    if (sigaction(SIGUSR1, 0, &observed) != 0 ||
        observed.sa_handler != record_delivery ||
        observed.sa_mask.__bits[0] != action.sa_mask.__bits[0] ||
        (observed.sa_flags & (SA_RESTART | SA_RESTORER)) !=
            (SA_RESTART | SA_RESTORER) ||
        !action_unwritten_bytes_have_value(&observed, action_poison)) {
        result = 8;
        goto cleanup;
    }
    if (sigprocmask(SIG_UNBLOCK, &usr1_set, 0) != 0) {
        result = 9;
        goto cleanup;
    }
    delivered = 0;
    if (raw_tgkill_self(SIGUSR1) != 0 || wait_for_delivery(SIGUSR1) != 0) {
        result = 10;
        goto cleanup;
    }

    for (int invalid = 0; invalid <= 65; invalid++) {
        if (invalid != 0 && invalid != 32 && invalid != 33 && invalid != 34 &&
            invalid != 65)
            continue;
        errno = 0;
        if (sigaction(invalid, 0, 0) != -1 || errno != EINVAL) {
            result = 11;
            goto cleanup;
        }
    }

    if (signal(SIGUSR2, record_delivery) != saved_usr2.sa_handler) {
        result = 12;
        goto cleanup;
    }
    fill_action_bytes(&observed, action_poison);
    if (sigaction(SIGUSR2, 0, &observed) != 0 ||
        observed.sa_handler != record_delivery ||
        (observed.sa_flags & (SA_RESTART | SA_RESTORER)) !=
            (SA_RESTART | SA_RESTORER) ||
        !action_unwritten_bytes_have_value(&observed, action_poison)) {
        result = 13;
        goto cleanup;
    }
    if (sigemptyset(&usr2_set) != 0 || sigaddset(&usr2_set, SIGUSR2) != 0 ||
        sigprocmask(SIG_UNBLOCK, &usr2_set, 0) != 0) {
        result = 14;
        goto cleanup;
    }
    delivered = 0;
    if (raw_tgkill_self(SIGUSR2) != 0 || wait_for_delivery(SIGUSR2) != 0) {
        result = 15;
        goto cleanup;
    }

    reserved_set.__bits[0] = 1UL << 31;
    if (sigprocmask(SIG_BLOCK, &reserved_set, 0) != 0 ||
        raw_current_mask(&raw_mask) != 0 ||
        (raw_mask & reserved_set.__bits[0]) == 0) {
        result = 16;
        goto cleanup;
    }
    fill_set_words(&old_mask, set_poison);
    if (sigprocmask(SIG_SETMASK, 0, &old_mask) != 0 ||
        (old_mask.__bits[0] & reserved_set.__bits[0]) != 0 ||
        !tail_has_value(&old_mask, set_poison) ||
        sigprocmask(SIG_UNBLOCK, &reserved_set, 0) != 0) {
        result = 17;
        goto cleanup;
    }
    fill_set_words(&old_mask, set_poison);
    if (sigprocmask(SIG_BLOCK, &usr1_set, &old_mask) != 0 ||
        sigismember(&old_mask, SIGUSR1) != 0 ||
        !tail_has_value(&old_mask, set_poison)) {
        result = 18;
        goto cleanup;
    }
    delivered = 0;
    if (raw_tgkill_self(SIGUSR1) != 0 || delivered != 0) {
        result = 19;
        goto cleanup;
    }
    fill_set_words(&pending, set_poison);
    if (sigpending(&pending) != 0 || sigismember(&pending, SIGUSR1) != 1 ||
        !tail_has_value(&pending, set_poison)) {
        result = 20;
        goto cleanup;
    }
    errno = 0;
    if (sigpending(0) != -1 || errno != EFAULT) {
        result = 21;
        goto cleanup;
    }
    if (sigprocmask(SIG_UNBLOCK, &usr1_set, 0) != 0 ||
        wait_for_delivery(SIGUSR1) != 0) {
        result = 22;
        goto cleanup;
    }

cleanup:
    /* Do not restore a default disposition while our fixture signal is pending. */
    if (saved_mask_ready && result != 0)
        (void)sigprocmask(SIG_UNBLOCK, &usr1_set, 0);
    if (saved_usr2_ready)
        (void)sigaction(SIGUSR2, &saved_usr2, 0);
    if (saved_usr1_ready)
        (void)sigaction(SIGUSR1, &saved_usr1, 0);
    if (saved_mask_ready)
        (void)sigprocmask(SIG_SETMASK, &saved_mask, 0);
    return result;
}

int crabc_x86_64_signal_control_probe(void)
{
    int set_result = test_set_helpers();

    if (set_result != 0)
        return set_result;
    return test_action_mask_and_pending() == 0 ? 0 : 100;
}

#ifndef CRABC_SIGNAL_CONTROL_FREESTANDING
int main(void)
{
    return crabc_x86_64_signal_control_probe();
}
#endif
