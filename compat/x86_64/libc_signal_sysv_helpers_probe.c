/*
 * Pinned-musl Linux/x86-64 SysV signal-helper differential and static body.
 *
 * The same project-header XSI C body first runs against pinned musl 1.2.6 and
 * then through the opt-in true-static crabc candidate. Raw action/mask calls
 * are fixture containment: they stage and inspect disposable SIGUSR1/SIGUSR2
 * state without selecting the public signal-control surface.
 */

#define _XOPEN_SOURCE 700

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

_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 public sigset_t layout");
_Static_assert(sizeof(struct sigaction) == 152 && _Alignof(struct sigaction) == 8,
    "x86 public sigaction layout");
_Static_assert(SYS_rt_sigaction == 13 && SYS_rt_sigprocmask == 14,
    "Linux x86 signal syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sighold),
    int (*)(int)), "sighold declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigignore),
    int (*)(int)), "sigignore declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigrelse),
    int (*)(int)), "sigrelse declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigset),
    sighandler_t (*)(int, sighandler_t)), "sigset declaration");

struct linux_sigaction {
    uintptr_t handler;
    unsigned long flags;
    uintptr_t restorer;
    unsigned long mask;
};

_Static_assert(sizeof(struct linux_sigaction) == 32 &&
    _Alignof(struct linux_sigaction) == 8, "x86 kernel sigaction layout");
_Static_assert(offsetof(struct linux_sigaction, flags) == 8 &&
    offsetof(struct linux_sigaction, restorer) == 16 &&
    offsetof(struct linux_sigaction, mask) == 24,
    "x86 kernel sigaction offsets");

typedef int (*sysv_signal_unary)(int);
typedef sighandler_t (*sysv_sigset)(int, sighandler_t);

/* Volatile function pointers retain the selected C calls, not compiler builtins. */
static sysv_signal_unary volatile direct_sighold = sighold;
static sysv_signal_unary volatile direct_sigignore = sigignore;
static sysv_signal_unary volatile direct_sigrelse = sigrelse;
static sysv_sigset volatile direct_sigset = sigset;

static long raw_syscall4(long number, long first, long second, long third,
    long fourth)
{
    long result = number;
    register long argument_four __asm__("r10") = fourth;

    __asm__ volatile("syscall" : "+a"(result)
        : "D"(first), "S"(second), "d"(third), "r"(argument_four)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_sigaction(int signal, const struct linux_sigaction *action,
    struct linux_sigaction *old_action)
{
    return raw_syscall4(SYS_rt_sigaction, signal, (long)(uintptr_t)action,
        (long)(uintptr_t)old_action, (long)sizeof(unsigned long));
}

static long raw_sigprocmask(int how, const unsigned long *set,
    unsigned long *old_set)
{
    return raw_syscall4(SYS_rt_sigprocmask, how, (long)(uintptr_t)set,
        (long)(uintptr_t)old_set, (long)sizeof(unsigned long));
}

static unsigned long signal_bit(int signal)
{
    return 1UL << (signal - 1);
}

static void first_handler(int signal)
{
    (void)signal;
}

static void second_handler(int signal)
{
    (void)signal;
}

static int check_hold_and_release(void)
{
    unsigned long original_mask = 0;
    unsigned long observed_mask = 0;

    if (raw_sigprocmask(SIG_SETMASK, 0, &original_mask) != 0)
        return 1;
    errno = E2BIG;
    if (direct_sighold(SIGUSR1) != 0 || errno != E2BIG)
        return 2;
    if (raw_sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        (observed_mask & signal_bit(SIGUSR1)) == 0)
        return 3;
    errno = E2BIG;
    if (direct_sigrelse(SIGUSR1) != 0 || errno != E2BIG)
        return 4;
    if (raw_sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        (observed_mask & signal_bit(SIGUSR1)) != 0)
        return 5;
    errno = 0;
    if (direct_sighold(0) != -1 || errno != EINVAL)
        return 6;
    errno = 0;
    if (direct_sigrelse(32) != -1 || errno != EINVAL)
        return 7;
    if (raw_sigprocmask(SIG_SETMASK, &original_mask, 0) != 0)
        return 8;
    return 0;
}

static int check_ignore(void)
{
    struct linux_sigaction original = { 0, 0, 0, 0 };
    struct linux_sigaction observed = { 0, 0, 0, 0 };

    if (raw_sigaction(SIGUSR2, 0, &original) != 0)
        return 10;
    errno = E2BIG;
    if (direct_sigignore(SIGUSR2) != 0 || errno != E2BIG)
        return 11;
    if (raw_sigaction(SIGUSR2, 0, &observed) != 0 ||
        observed.handler != (uintptr_t)SIG_IGN || observed.mask != 0)
        return 12;
    errno = 0;
    if (direct_sigignore(0) != -1 || errno != EINVAL)
        return 13;
    if (raw_sigaction(SIGUSR2, &original, 0) != 0)
        return 14;
    return 0;
}

static int check_sigset(void)
{
    const unsigned long usr1 = signal_bit(SIGUSR1);
    struct linux_sigaction original_action = { 0, 0, 0, 0 };
    struct linux_sigaction staged_action = {
        (uintptr_t)first_handler, 0, 0, 0,
    };
    struct linux_sigaction observed_action = { 0, 0, 0, 0 };
    unsigned long original_mask = 0;
    unsigned long observed_mask = 0;

    if (raw_sigaction(SIGUSR1, 0, &original_action) != 0)
        return 20;
    if (raw_sigprocmask(SIG_SETMASK, 0, &original_mask) != 0)
        return 21;
    if (raw_sigaction(SIGUSR1, &staged_action, 0) != 0)
        return 22;
    if (raw_sigprocmask(SIG_UNBLOCK, &usr1, 0) != 0)
        return 23;

    errno = E2BIG;
    if (direct_sigset(SIGUSR1, second_handler) != first_handler || errno != E2BIG)
        return 24;
    if (raw_sigaction(SIGUSR1, 0, &observed_action) != 0 ||
        observed_action.handler != (uintptr_t)second_handler)
        return 25;
    if (raw_sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        (observed_mask & usr1) != 0)
        return 26;

    errno = E2BIG;
    if (direct_sigset(SIGUSR1, SIG_HOLD) != second_handler || errno != E2BIG)
        return 27;
    if (raw_sigaction(SIGUSR1, 0, &observed_action) != 0 ||
        observed_action.handler != (uintptr_t)second_handler)
        return 28;
    if (raw_sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        (observed_mask & usr1) == 0)
        return 29;

    errno = E2BIG;
    if (direct_sigset(SIGUSR1, first_handler) != SIG_HOLD || errno != E2BIG)
        return 30;
    if (raw_sigaction(SIGUSR1, 0, &observed_action) != 0 ||
        observed_action.handler != (uintptr_t)first_handler)
        return 31;
    if (raw_sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        (observed_mask & usr1) != 0)
        return 32;

    errno = E2BIG;
    if (direct_sigset(SIGUSR1, SIG_DFL) != first_handler || errno != E2BIG)
        return 33;
    errno = 0;
    if (direct_sigset(0, first_handler) != SIG_ERR || errno != EINVAL)
        return 34;

    if (raw_sigaction(SIGUSR1, &original_action, 0) != 0)
        return 35;
    if (raw_sigprocmask(SIG_SETMASK, &original_mask, 0) != 0)
        return 36;
    return 0;
}

int crabc_x86_64_signal_sysv_helpers_probe(void)
{
    int result;

    result = check_hold_and_release();
    if (result != 0)
        return result;
    result = check_ignore();
    if (result != 0)
        return result;
    return check_sigset();
}

#ifndef CRABC_SIGNAL_SYSV_HELPERS_FREESTANDING
int main(void)
{
    return crabc_x86_64_signal_sysv_helpers_probe();
}
#endif
