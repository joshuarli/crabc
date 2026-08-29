/* Pinned-musl Linux/x86-64 POSIX signal-header opaque-context assertions. */

#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stddef.h>

_Static_assert(sizeof(mcontext_t) == 256, "x86 POSIX mcontext size");
_Static_assert(_Alignof(mcontext_t) == 8, "x86 POSIX mcontext alignment");
_Static_assert(sizeof(union sigval) == 8, "x86 POSIX sigval size");
_Static_assert(_Alignof(union sigval) == 8, "x86 POSIX sigval alignment");
_Static_assert(sizeof(siginfo_t) == 128, "x86 POSIX siginfo size");
_Static_assert(_Alignof(siginfo_t) == 8, "x86 POSIX siginfo alignment");
_Static_assert(offsetof(siginfo_t, si_signo) == 0 &&
    offsetof(siginfo_t, si_errno) == 4 &&
    offsetof(siginfo_t, si_code) == 8 &&
    offsetof(siginfo_t, si_pid) == 16 &&
    offsetof(siginfo_t, si_uid) == 20 &&
    offsetof(siginfo_t, si_value) == 24,
    "x86 POSIX queued siginfo fields");
_Static_assert(sizeof(ucontext_t) == 936, "x86 POSIX ucontext size");
_Static_assert(_Alignof(ucontext_t) == 8, "x86 POSIX ucontext alignment");
_Static_assert(offsetof(ucontext_t, uc_stack) == 16, "x86 POSIX ucontext stack");
_Static_assert(offsetof(ucontext_t, uc_mcontext) == 40,
    "x86 POSIX ucontext mcontext");
_Static_assert(offsetof(ucontext_t, uc_sigmask) == 296,
    "x86 POSIX ucontext mask");
_Static_assert(offsetof(ucontext_t, __fpregs_mem) == 424,
    "x86 POSIX ucontext fpstate storage");

_Static_assert(__builtin_types_compatible_p(__typeof__(&kill),
    int (*)(int, int)), "POSIX kill declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&raise),
    int (*)(int)), "POSIX raise declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigqueue),
    int (*)(pid_t, int, union sigval)), "POSIX sigqueue declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigtimedwait),
    int (*)(const sigset_t *, siginfo_t *, const struct timespec *)),
    "POSIX sigtimedwait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigwaitinfo),
    int (*)(const sigset_t *, siginfo_t *)), "POSIX sigwaitinfo declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigwait),
    int (*)(const sigset_t *, int *)), "POSIX sigwait declaration");
