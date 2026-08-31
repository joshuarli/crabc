/*
 * Pinned-musl Linux/x86-64 GNU signal-header ABI assertions.
 *
 * This probe is compiled once against the oracle headers and once with the
 * project header tree first. It checks only declaration/layout vocabulary; it
 * neither links nor claims a crabc C signal implementation.
 */

#define _GNU_SOURCE 1

#include <signal.h>
#include <stddef.h>

_Static_assert(sizeof(sigset_t) == 128, "x86 sigset_t size");
_Static_assert(_Alignof(sigset_t) == 8, "x86 sigset_t alignment");
_Static_assert(sizeof(union sigval) == 8, "x86 sigval size");
_Static_assert(_Alignof(union sigval) == 8, "x86 sigval alignment");
_Static_assert(sizeof(siginfo_t) == 128, "x86 siginfo size");
_Static_assert(_Alignof(siginfo_t) == 8, "x86 siginfo alignment");
_Static_assert(offsetof(siginfo_t, si_signo) == 0, "x86 siginfo signo");
_Static_assert(offsetof(siginfo_t, si_errno) == 4, "x86 siginfo errno");
_Static_assert(offsetof(siginfo_t, si_code) == 8, "x86 siginfo code");
_Static_assert(offsetof(siginfo_t, si_pid) == 16, "x86 siginfo pid");
_Static_assert(offsetof(siginfo_t, si_uid) == 20, "x86 siginfo uid");
_Static_assert(offsetof(siginfo_t, si_value) == 24, "x86 siginfo value");
_Static_assert(sizeof(struct sigaction) == 152, "x86 sigaction size");
_Static_assert(_Alignof(struct sigaction) == 8, "x86 sigaction alignment");
_Static_assert(offsetof(struct sigaction, sa_mask) == 8, "x86 sigaction mask");
_Static_assert(offsetof(struct sigaction, sa_flags) == 136, "x86 sigaction flags");
_Static_assert(offsetof(struct sigaction, sa_restorer) == 144, "x86 sigaction restorer");
_Static_assert(sizeof(stack_t) == 24, "x86 stack_t size");
_Static_assert(_Alignof(stack_t) == 8, "x86 stack_t alignment");
_Static_assert(offsetof(stack_t, ss_sp) == 0, "x86 stack_t pointer");
_Static_assert(offsetof(stack_t, ss_flags) == 8, "x86 stack_t flags");
_Static_assert(offsetof(stack_t, ss_size) == 16, "x86 stack_t size field");

_Static_assert(__builtin_types_compatible_p(greg_t, long long),
    "x86 greg_t is signed long long");
_Static_assert(sizeof(gregset_t) == 23 * sizeof(long long), "x86 gregset_t size");
_Static_assert(_Alignof(gregset_t) == 8, "x86 gregset_t alignment");
_Static_assert(__builtin_types_compatible_p(fpregset_t, struct _fpstate *),
    "x86 fpregset_t is an _fpstate pointer");
_Static_assert(sizeof(struct _fpstate) == 512, "x86 fpstate size");
_Static_assert(_Alignof(struct _fpstate) == 8, "x86 fpstate alignment");
_Static_assert(offsetof(struct _fpstate, rip) == 8, "x86 fpstate rip");
_Static_assert(offsetof(struct _fpstate, _st) == 32, "x86 fpstate x87 fields");
_Static_assert(offsetof(struct _fpstate, _xmm) == 160, "x86 fpstate XMM fields");
_Static_assert(sizeof(struct sigcontext) == 256, "x86 sigcontext size");
_Static_assert(_Alignof(struct sigcontext) == 8, "x86 sigcontext alignment");
_Static_assert(offsetof(struct sigcontext, rip) == 128, "x86 sigcontext rip");
_Static_assert(offsetof(struct sigcontext, fpstate) == 184, "x86 sigcontext fpstate");
_Static_assert(offsetof(struct sigcontext, __reserved1) == 192,
    "x86 sigcontext reserved tail");
_Static_assert(sizeof(mcontext_t) == 256, "x86 mcontext size");
_Static_assert(_Alignof(mcontext_t) == 8, "x86 mcontext alignment");
_Static_assert(offsetof(mcontext_t, gregs) == 0, "x86 mcontext gregs");
_Static_assert(offsetof(mcontext_t, fpregs) == 184, "x86 mcontext fpregs");
_Static_assert(offsetof(mcontext_t, __reserved1) == 192,
    "x86 mcontext reserved tail");
_Static_assert(sizeof(ucontext_t) == 936, "x86 ucontext size");
_Static_assert(_Alignof(ucontext_t) == 8, "x86 ucontext alignment");
_Static_assert(offsetof(ucontext_t, uc_link) == 8, "x86 ucontext link");
_Static_assert(offsetof(ucontext_t, uc_stack) == 16, "x86 ucontext stack");
_Static_assert(offsetof(ucontext_t, uc_mcontext) == 40, "x86 ucontext mcontext");
_Static_assert(offsetof(ucontext_t, uc_sigmask) == 296, "x86 ucontext mask");
_Static_assert(offsetof(ucontext_t, __fpregs_mem) == 424,
    "x86 ucontext fpstate storage");

_Static_assert(REG_R8 == 0 && REG_RIP == 16 && REG_EFL == 17,
    "x86 GNU general-register indices");
_Static_assert(REG_CSGSFS == 18 && REG_ERR == 19 && REG_TRAPNO == 20 &&
        REG_OLDMASK == 21 && REG_CR2 == 22,
    "x86 GNU signal-frame register tail");
_Static_assert(MINSIGSTKSZ == 2048 && SIGSTKSZ == 8192,
    "x86 alternate signal-stack constants");
_Static_assert(SA_RESTORER == 0x04000000 && SA_ONSTACK == 0x08000000,
    "x86 signal-action constants");
_Static_assert(SI_QUEUE == -1 && SI_TKILL == -6,
    "x86 queued and thread signal codes");

_Static_assert(__builtin_types_compatible_p(__typeof__(&kill),
    int (*)(int, int)), "GNU kill declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&killpg),
    int (*)(pid_t, int)), "GNU killpg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&raise),
    int (*)(int)), "GNU raise declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigqueue),
    int (*)(pid_t, int, union sigval)), "GNU sigqueue declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigtimedwait),
    int (*)(const sigset_t *, siginfo_t *, const struct timespec *)),
    "GNU sigtimedwait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigwaitinfo),
    int (*)(const sigset_t *, siginfo_t *)), "GNU sigwaitinfo declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigwait),
    int (*)(const sigset_t *, int *)), "GNU sigwait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigpause),
    int (*)(int)), "GNU sigpause declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigaddset),
    int (*)(sigset_t *, int)), "GNU/POSIX sigaddset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigdelset),
    int (*)(sigset_t *, int)), "GNU/POSIX sigdelset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigfillset),
    int (*)(sigset_t *)), "GNU/POSIX sigfillset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigisemptyset),
    int (*)(const sigset_t *)), "GNU sigisemptyset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigorset),
    int (*)(sigset_t *, const sigset_t *, const sigset_t *)),
    "GNU sigorset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigandset),
    int (*)(sigset_t *, const sigset_t *, const sigset_t *)),
    "GNU sigandset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigpending),
    int (*)(sigset_t *)), "GNU/POSIX sigpending declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__libc_current_sigrtmax),
    int (*)(void)), "GNU realtime-maximum bridge declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__libc_current_sigrtmin),
    int (*)(void)), "GNU realtime-minimum bridge declaration");
