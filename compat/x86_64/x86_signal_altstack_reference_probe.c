/* Native Linux/x86-64 pinned-musl alternate-stack/action/suspend control. */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native little-endian Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(stack_t) == 24 && offsetof(stack_t, ss_sp) == 0 &&
    offsetof(stack_t, ss_flags) == 8 && offsetof(stack_t, ss_size) == 16,
    "x86-64 kernel alternate-stack record");
_Static_assert(sizeof(siginfo_t) == 128 && _Alignof(siginfo_t) == 8,
    "x86-64 signal-information record");
_Static_assert(SYS_sigaltstack == 131 && SYS_rt_sigsuspend == 130 &&
    SYS_rt_sigaction == 13 && SYS_rt_sigreturn == 15,
    "x86-64 signal syscall numbers");

static _Alignas(16) unsigned char alternate[65536];
static volatile sig_atomic_t observed;
static volatile sig_atomic_t value;

static void info_handler(int received, siginfo_t *info, void *context)
{
    unsigned char local;
    uintptr_t address = (uintptr_t)&local;
    sig_atomic_t result = received == SIGUSR1;
    stack_t stack, disabled = { .ss_flags = SS_DISABLE };
    sigset_t mask;
    int saved_errno = errno;

    if (address >= (uintptr_t)alternate && address < (uintptr_t)alternate + sizeof alternate)
        result |= 2;
    if (info->si_signo == received && info->si_code == SI_QUEUE)
        result |= 4;
    value = info->si_value.sival_int;
    if (context)
        result |= 8;
    if (sigprocmask(SIG_SETMASK, 0, &mask) == 0 &&
        sigismember(&mask, received) == 1 && sigismember(&mask, SIGUSR2) == 1)
        result |= 16;
    if (sigaltstack(0, &stack) == 0 && (stack.ss_flags & SS_ONSTACK))
        result |= 32;
    if (sigaltstack(&disabled, 0) == -1 && errno == EPERM)
        result |= 64;
    observed = result;
    errno = saved_errno;
}

static void simple_handler(int received)
{
    unsigned char local;
    uintptr_t address = (uintptr_t)&local;
    observed = received == SIGUSR1 && address >= (uintptr_t)alternate &&
        address < (uintptr_t)alternate + sizeof alternate;
}

static int same_stack(const stack_t *left, const stack_t *right)
{
    return left->ss_sp == right->ss_sp && left->ss_size == right->ss_size &&
        left->ss_flags == right->ss_flags;
}

int main(void)
{
    stack_t original_stack, unchanged, enabled;
    stack_t stack = { .ss_sp = alternate, .ss_size = sizeof alternate };
    stack_t tiny = { .ss_sp = alternate, .ss_size = 1 };
    stack_t disabled = { .ss_flags = SS_DISABLE };
    sigset_t blocked, original_mask, suspended, restored, pending;
    struct sigaction action = {0}, original_action, queried;
    union sigval payload = { .sival_int = 7654321 };

    if (sigemptyset(&blocked) || sigaddset(&blocked, SIGUSR1) || sigaddset(&blocked, SIGUSR2) ||
        sigprocmask(SIG_BLOCK, &blocked, &original_mask) || sigaltstack(0, &original_stack))
        return 1;
    errno = 1234;
    if (sigaltstack(&tiny, 0) != -1 || errno != ENOMEM || sigaltstack(0, &unchanged) ||
        !same_stack(&original_stack, &unchanged))
        return 2;
    if (sigaltstack(&stack, 0) || sigaltstack(0, &enabled) || !same_stack(&enabled, &stack))
        return 3;
    action.sa_sigaction = info_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    if (sigemptyset(&action.sa_mask) || sigaddset(&action.sa_mask, SIGUSR2) ||
        sigaction(SIGUSR1, &action, &original_action) || sigaction(SIGUSR1, 0, &queried) ||
        queried.sa_sigaction != info_handler || !(queried.sa_flags & SA_SIGINFO) ||
        sigismember(&queried.sa_mask, SIGUSR2) != 1)
        return 4;
    if (sigprocmask(SIG_SETMASK, 0, &suspended) || sigdelset(&suspended, SIGUSR1) ||
        sigqueue(getpid(), SIGUSR1, payload) || sigpending(&pending) ||
        sigismember(&pending, SIGUSR1) != 1)
        return 5;
    if (sigsuspend(&suspended) != -1 || errno != EINTR || observed != 127 || value != 7654321 ||
        sigprocmask(SIG_SETMASK, 0, &restored) || sigismember(&restored, SIGUSR1) != 1 ||
        sigismember(&restored, SIGUSR2) != 1 || sigpending(&pending) ||
        sigismember(&pending, SIGUSR1) != 0 || sigaltstack(0, &enabled) || enabled.ss_flags != 0)
        return 6;
    action.sa_handler = simple_handler;
    action.sa_flags = SA_ONSTACK;
    if (sigaction(SIGUSR1, &action, 0) || raise(SIGUSR1) || sigsuspend(&suspended) != -1 ||
        errno != EINTR || observed != 1)
        return 7;
    if (sigaction(SIGUSR1, &original_action, 0) || sigaltstack(&disabled, 0) ||
        sigaltstack(0, &enabled) || !(enabled.ss_flags & SS_DISABLE) ||
        sigaltstack(&original_stack, 0) || sigprocmask(SIG_SETMASK, &original_mask, 0))
        return 8;
    puts("altstack=enabled,onstack,disabled handlers=siginfo,simple masks=handler,restored suspend=EINTR errors=ENOMEM,EPERM");
    return 0;
}
