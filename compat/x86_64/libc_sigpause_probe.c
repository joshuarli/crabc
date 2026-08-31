/*
 * Pinned-musl Linux/x86-64 `sigpause` differential and static-candidate body.
 *
 * The runner keeps the fixture process isolated. It uses raw setup and a
 * two-FIFO handshake only to arrange one already-pending SIGUSR1 before the
 * selected public call. Those raw fixture operations are not crabc exports:
 * the candidate itself must link only `sigpause` plus its errno/TLS seam.
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

enum {
    READY_FD = 3,
    RELEASE_FD = 4,
    KERNEL_SIGSET_SIZE = sizeof(unsigned long),
    KERNEL_SA_RESTORER = 0x04000000,
};

_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 public sigset_t layout");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_rt_sigaction == 13 &&
    SYS_rt_sigprocmask == 14 && SYS_rt_sigsuspend == 130,
    "x86 selected signal and fixture syscall numbers");
_Static_assert(SIGUSR1 == 10 && SIGUSR2 == 12,
    "x86 selected application signals");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigpause),
    int (*)(int)), "GNU sigpause declaration");

struct kernel_sigaction {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};

_Static_assert(sizeof(struct kernel_sigaction) == 32,
    "x86 compact kernel signal-action record");
_Static_assert(offsetof(struct kernel_sigaction, handler) == 0 &&
    offsetof(struct kernel_sigaction, flags) == 8 &&
    offsetof(struct kernel_sigaction, restorer) == 16 &&
    offsetof(struct kernel_sigaction, mask) == 24,
    "x86 compact kernel signal-action offsets");

#ifdef CRABC_SIGPAUSE_FREESTANDING
extern void crabc_x86_64_sigpause_restorer(void);
#else
__attribute__((naked, noreturn))
void crabc_x86_64_sigpause_restorer(void)
{
    __asm__ volatile("mov $15, %rax\n\tsyscall\n\tud2");
}
#endif

static volatile sig_atomic_t delivered_signal;

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_read(int descriptor, void *bytes, unsigned long length)
{
    return raw_syscall4(SYS_read, descriptor, (long)(uintptr_t)bytes, length, 0);
}

static long raw_write(int descriptor, const void *bytes, unsigned long length)
{
    return raw_syscall4(SYS_write, descriptor, (long)(uintptr_t)bytes, length, 0);
}

static unsigned long signal_bit(int signal)
{
    return 1UL << (signal - 1);
}

static int raw_replace_mask(int how, const unsigned long *set,
    unsigned long *old_set)
{
    return raw_syscall4(SYS_rt_sigprocmask, how, (long)(uintptr_t)set,
        (long)(uintptr_t)old_set, KERNEL_SIGSET_SIZE) == 0 ? 0 : -1;
}

static void record_signal(int signal)
{
    delivered_signal = signal;
}

static int install_fixture_handler(void)
{
    const struct kernel_sigaction action = {
        .handler = record_signal,
        .flags = KERNEL_SA_RESTORER,
        .restorer = crabc_x86_64_sigpause_restorer,
        .mask = 0,
    };

    return raw_syscall4(SYS_rt_sigaction, SIGUSR1,
        (long)(uintptr_t)&action, 0, KERNEL_SIGSET_SIZE) == 0 ? 0 : -1;
}

int crabc_x86_64_sigpause_probe(void)
{
    const unsigned long selected_mask = signal_bit(SIGUSR1) | signal_bit(SIGUSR2);
    unsigned long original_mask = 0;
    unsigned long observed_mask = 0;
    char ready = 'R';
    char release = 0;
    int result = 1;

    if (install_fixture_handler() != 0)
        return 1;
    if (raw_replace_mask(SIG_BLOCK, &selected_mask, &original_mask) != 0)
        return 2;

    errno = 0;
    if (sigpause(0) != -1 || errno != EINVAL) {
        result = 3;
        goto restore_mask;
    }
    errno = 0;
    if (sigpause(32) != -1 || errno != EINVAL) {
        result = 4;
        goto restore_mask;
    }
    if (raw_replace_mask(SIG_BLOCK, 0, &observed_mask) != 0 ||
        (observed_mask & selected_mask) != selected_mask) {
        result = 5;
        goto restore_mask;
    }

    if (raw_write(READY_FD, &ready, 1) != 1 ||
        raw_read(RELEASE_FD, &release, 1) != 1 || release != 'G') {
        result = 6;
        goto restore_mask;
    }

    errno = ERANGE;
    if (sigpause(SIGUSR1) != -1 || errno != EINTR ||
        delivered_signal != SIGUSR1) {
        result = 7;
        goto restore_mask;
    }
    if (raw_replace_mask(SIG_BLOCK, 0, &observed_mask) != 0 ||
        (observed_mask & selected_mask) != selected_mask) {
        result = 8;
        goto restore_mask;
    }
    result = 0;

restore_mask:
    if (raw_replace_mask(SIG_SETMASK, &original_mask, 0) != 0 && result == 0)
        return 9;
    return result;
}

#ifndef CRABC_SIGPAUSE_FREESTANDING
int main(void)
{
    return crabc_x86_64_sigpause_probe();
}
#endif
