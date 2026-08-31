/*
 * Pinned-musl Linux/x86-64 siginterrupt differential and static body.
 *
 * The public XSI C body first executes through pinned musl 1.2.6 and then
 * through exactly the selected -nostdlib -static candidate. Fixture-private
 * raw rt_sigaction calls only stage/query disposable action metadata; they do
 * not select public sigaction, signal sets, delivery, waits, or process state.
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

_Static_assert(sizeof(struct sigaction) == 152 && _Alignof(struct sigaction) == 8,
    "x86 public sigaction layout");
_Static_assert(offsetof(struct sigaction, sa_flags) == 136,
    "x86 public sigaction flags offset");
_Static_assert(SA_RESTART == 0x10000000 && SA_NODEFER == 0x40000000,
    "Linux selected signal-action flags");
_Static_assert(SYS_rt_sigaction == 13, "x86 rt_sigaction syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&siginterrupt),
    int (*)(int, int)), "siginterrupt declaration");

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

typedef int (*siginterrupt_function)(int, int);

/* Parentheses retain the selected public C ABI boundary rather than a builtin. */
static siginterrupt_function volatile direct_siginterrupt = siginterrupt;

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

/* The fixture never delivers SIGUSR1; this address makes Linux retain flags. */
static void retained_action_handler(int signal)
{
    (void)signal;
}

static int check_restart_toggle(void)
{
    struct linux_sigaction original = { 0, 0, 0, 0 };
    struct linux_sigaction staged = {
        (uintptr_t)retained_action_handler, SA_RESTART | SA_NODEFER, 0, 0,
    };
    struct linux_sigaction observed = { 0, 0, 0, 0 };

    if (raw_sigaction(SIGUSR1, 0, &original) != 0)
        return 1;
    if (raw_sigaction(SIGUSR1, &staged, 0) != 0)
        return 2;
    if (raw_sigaction(SIGUSR1, 0, &observed) != 0 ||
        observed.handler != staged.handler)
        return 21;
    if ((observed.flags & SA_NODEFER) == 0)
        return 22;
    if ((observed.flags & SA_RESTART) == 0)
        return 23;

    errno = E2BIG;
    /* Any nonzero flag clears SA_RESTART, not merely the literal value one. */
    if (direct_siginterrupt(SIGUSR1, -7) != 0 || errno != E2BIG)
        return 3;
    if (raw_sigaction(SIGUSR1, 0, &observed) != 0 ||
        observed.handler != staged.handler ||
        (observed.flags & SA_RESTART) != 0 ||
        (observed.flags & SA_NODEFER) == 0)
        return 4;

    errno = E2BIG;
    /* Zero is the source-defined request to restore SA_RESTART. */
    if (direct_siginterrupt(SIGUSR1, 0) != 0 || errno != E2BIG)
        return 5;
    if (raw_sigaction(SIGUSR1, 0, &observed) != 0 ||
        observed.handler != staged.handler)
        return 6;
    if ((observed.flags & SA_NODEFER) == 0)
        return 7;
    if ((observed.flags & SA_RESTART) == 0)
        return 8;

    if (raw_sigaction(SIGUSR1, &original, 0) != 0)
        return 7;
    return 0;
}

int crabc_x86_64_siginterrupt_probe(void)
{
    int result = check_restart_toggle();

    if (result != 0)
        return result;

    /* The query succeeds, then musl's replacement attempt is EINVAL. */
    errno = E2BIG;
    if (direct_siginterrupt(SIGKILL, 1) != -1 || errno != EINVAL)
        return 16;
    return 0;
}

#ifndef CRABC_SIGINTERRUPT_FREESTANDING
int main(void)
{
    return crabc_x86_64_siginterrupt_probe();
}
#endif
