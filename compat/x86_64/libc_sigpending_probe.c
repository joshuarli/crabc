/*
 * Pinned-musl Linux/x86-64 sigpending differential and static-candidate body.
 *
 * This fixture uses raw rt_sigprocmask and tgkill only to arrange one blocked,
 * pending SIGUSR1 in its own short-lived process. Those setup syscalls are not
 * crabc exports: the candidate itself must link only sigpending and its
 * initial-TLS errno seam, without an action, mask, wait, or delivery wrapper.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>

enum {
    SIGSET_WORDS = 128 / sizeof(unsigned long),
    KERNEL_SIGSET_SIZE = sizeof(unsigned long),
};

_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 public sigset_t layout");
_Static_assert(SIGSET_WORDS == 16, "x86 public sigset_t word count");
_Static_assert(SYS_getpid == 39 && SYS_gettid == 186 &&
    SYS_rt_sigprocmask == 14 && SYS_rt_sigpending == 127 &&
    SYS_tgkill == 234, "x86 sigpending fixture syscall numbers");
_Static_assert(SIGUSR1 == 10, "x86 selected pending signal");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigpending),
    int (*)(sigset_t *)), "POSIX sigpending declaration");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "0"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile("syscall"
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

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static unsigned long signal_bit(int signal_number)
{
    return 1UL << (signal_number - 1);
}

/* Fixture-only state arrangement; no sigprocmask C ABI call is linked. */
static int raw_block_usr1(void)
{
    const unsigned long mask = signal_bit(SIGUSR1);

    return raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK,
        (long)(uintptr_t)&mask, 0, KERNEL_SIGSET_SIZE) == 0 ? 0 : -1;
}

/* Fixture-only delivery; no C process-signaling wrapper is linked. */
static int raw_tgkill_self(int signal_number)
{
    long process_id = raw_syscall0(SYS_getpid);
    long thread_id = raw_syscall0(SYS_gettid);

    if (process_id <= 0 || thread_id <= 0)
        return -1;
    return raw_syscall3(SYS_tgkill, process_id, thread_id, signal_number) == 0
        ? 0 : -1;
}

int crabc_x86_64_sigpending_probe(void)
{
    sigset_t pending = {0};
    unsigned long *pending_words = (unsigned long *)(void *)&pending;

    if (raw_block_usr1() != 0 || raw_tgkill_self(SIGUSR1) != 0)
        return 1;

    /* Linux replaces only word zero; these tail sentinels are caller-owned. */
    pending_words[0] = 0xfeedfacecafebeefUL;
    pending_words[1] = 0x0123456789abcdefUL;
    pending_words[SIGSET_WORDS - 1] = 0xfedcba9876543210UL;
    errno = ERANGE;
    if (sigpending(&pending) != 0 || errno != ERANGE)
        return 2;
    if ((pending_words[0] & signal_bit(SIGUSR1)) == 0 ||
        pending_words[1] != 0x0123456789abcdefUL ||
        pending_words[SIGSET_WORDS - 1] != 0xfedcba9876543210UL)
        return 3;

    errno = ERANGE;
    if (sigpending((sigset_t *)(uintptr_t)1) != -1 || errno != EFAULT)
        return 4;
    errno = ERANGE;
    if (sigpending(0) != -1 || errno != EFAULT)
        return 5;

    return 0;
}

#ifndef CRABC_SIGPENDING_FREESTANDING
int main(void)
{
    return crabc_x86_64_sigpending_probe();
}
#endif
