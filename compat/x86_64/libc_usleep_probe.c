/*
 * Pinned-musl Linux/x86-64 usleep differential and static-candidate body.
 *
 * The same one-symbol project-header C body first runs through pinned musl
 * 1.2.6 and then through the selected `-nostdlib -static` candidate. It
 * proves only musl's historical microsecond wrapper over nanosleep: zero and
 * short completion preserve errno, while a fixture-local raw SIGALRM timer
 * interrupts one-second, one-second-plus-one-microsecond, and UINT_MAX
 * durations. Raw action/mask/timer setup makes the interruption deterministic
 * without linking or selecting a public signal action, mask, timer, or sleep
 * policy API.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

enum {
    KERNEL_SIGSET_SIZE = sizeof(unsigned long),
    KERNEL_SA_RESTORER = 0x04000000,
    INTERRUPT_MICROSECONDS = 20000,
};

_Static_assert(sizeof(unsigned int) == 4 && sizeof(long) == 8,
    "x86 LP64 scalar widths");
_Static_assert(UINT_MAX == 4294967295U, "x86 unsigned maximum");
_Static_assert(SIGALRM == 14 && SIG_UNBLOCK == 1 && SIG_SETMASK == 2,
    "x86 selected signal constants");
_Static_assert(SYS_rt_sigaction == 13 && SYS_rt_sigprocmask == 14 &&
    SYS_rt_sigreturn == 15 && SYS_nanosleep == 35 && SYS_setitimer == 38,
    "x86 raw fixture syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&usleep),
    int (*)(unsigned int)), "usleep declaration");

struct kernel_sigaction {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};

struct raw_timeval {
    long tv_sec;
    long tv_usec;
};

struct raw_itimerval {
    struct raw_timeval it_interval;
    struct raw_timeval it_value;
};

_Static_assert(sizeof(struct kernel_sigaction) == 32 &&
    _Alignof(struct kernel_sigaction) == 8,
    "x86 compact kernel signal action");
_Static_assert(offsetof(struct kernel_sigaction, handler) == 0 &&
    offsetof(struct kernel_sigaction, flags) == 8 &&
    offsetof(struct kernel_sigaction, restorer) == 16 &&
    offsetof(struct kernel_sigaction, mask) == 24,
    "x86 compact kernel signal action offsets");
_Static_assert(sizeof(struct raw_timeval) == 16 &&
    sizeof(struct raw_itimerval) == 32,
    "x86 raw interval-timer records");

#ifdef CRABC_USLEEP_FREESTANDING
extern void crabc_x86_64_usleep_restorer(void);
#else
__attribute__((naked, noreturn))
void crabc_x86_64_usleep_restorer(void)
{
    __asm__ volatile("mov $15, %rax\n\tsyscall\n\tud2");
}
#endif

static volatile sig_atomic_t signal_delivered;

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

static int raw_replace_mask(int how, const unsigned long *set,
    unsigned long *old_set)
{
    return raw_syscall4(SYS_rt_sigprocmask, how, (long)(uintptr_t)set,
        (long)(uintptr_t)old_set, KERNEL_SIGSET_SIZE) == 0 ? 0 : -1;
}

static int raw_replace_action(const struct kernel_sigaction *action,
    struct kernel_sigaction *old_action)
{
    return raw_syscall4(SYS_rt_sigaction, SIGALRM, (long)(uintptr_t)action,
        (long)(uintptr_t)old_action, KERNEL_SIGSET_SIZE) == 0 ? 0 : -1;
}

static int raw_arm_alarm(unsigned long microseconds)
{
    const struct raw_itimerval timer = {
        { 0, 0 },
        { (long)(microseconds / 1000000UL),
          (long)(microseconds % 1000000UL) },
    };

    return raw_syscall3(SYS_setitimer, 0, (long)(uintptr_t)&timer, 0) == 0 ?
        0 : -1;
}

static void record_alarm(int signal_number)
{
    if (signal_number == SIGALRM)
        signal_delivered = SIGALRM;
}

static int install_fixture_handler(struct kernel_sigaction *saved_action,
    unsigned long *saved_mask)
{
    const struct kernel_sigaction action = {
        .handler = record_alarm,
        .flags = KERNEL_SA_RESTORER,
        .restorer = crabc_x86_64_usleep_restorer,
        .mask = 0,
    };
    const unsigned long alarm_mask = signal_bit(SIGALRM);

    if (raw_replace_action(&action, saved_action) != 0 ||
        raw_replace_mask(SIG_SETMASK, 0, saved_mask) != 0)
        return -1;
    return raw_replace_mask(SIG_UNBLOCK, &alarm_mask, 0);
}

static int restore_fixture_handler(const struct kernel_sigaction *saved_action,
    const unsigned long *saved_mask)
{
    int status = 0;

    if (raw_arm_alarm(0) != 0)
        status = -1;
    if (raw_replace_action(saved_action, 0) != 0)
        status = -1;
    if (raw_replace_mask(SIG_SETMASK, saved_mask, 0) != 0)
        status = -1;
    return status;
}

static int check_zero_and_short_completion(void)
{
    errno = ERANGE;
    if (usleep(0U) != 0 || errno != ERANGE)
        return 1;

    errno = ERANGE;
    if (usleep(1000U) != 0 || errno != ERANGE)
        return 2;
    return 0;
}

static int check_interrupted_request(unsigned int requested)
{
    int result;

    signal_delivered = 0;
    if (raw_arm_alarm(INTERRUPT_MICROSECONDS) != 0)
        return 1;
    errno = 0;
    result = usleep(requested);
    if (raw_arm_alarm(0) != 0)
        return 2;
    if (result != -1 || errno != EINTR || signal_delivered != SIGALRM)
        return 3;
    return 0;
}

static int check_normalized_interruption(void)
{
    struct kernel_sigaction saved_action;
    unsigned long saved_mask;
    int status;

    if (install_fixture_handler(&saved_action, &saved_mask) != 0)
        return 1;

    status = check_interrupted_request(1000000U);
    if (status == 0)
        status = check_interrupted_request(1000001U);
    if (status == 0)
        status = check_interrupted_request(UINT_MAX);

    return restore_fixture_handler(&saved_action, &saved_mask) == 0 ?
        status : 4;
}

int crabc_x86_64_usleep_probe(void)
{
    int status = check_zero_and_short_completion();

    if (status != 0)
        return 10 + status;
    status = check_normalized_interruption();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_USLEEP_FREESTANDING
int main(void)
{
    return crabc_x86_64_usleep_probe();
}
#endif
