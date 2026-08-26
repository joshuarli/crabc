/* Pinned-musl Linux/x86-64 POSIX signal-header opaque-context assertions. */

#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stddef.h>

_Static_assert(sizeof(mcontext_t) == 256, "x86 POSIX mcontext size");
_Static_assert(_Alignof(mcontext_t) == 8, "x86 POSIX mcontext alignment");
_Static_assert(sizeof(ucontext_t) == 936, "x86 POSIX ucontext size");
_Static_assert(_Alignof(ucontext_t) == 8, "x86 POSIX ucontext alignment");
_Static_assert(offsetof(ucontext_t, uc_stack) == 16, "x86 POSIX ucontext stack");
_Static_assert(offsetof(ucontext_t, uc_mcontext) == 40,
    "x86 POSIX ucontext mcontext");
_Static_assert(offsetof(ucontext_t, uc_sigmask) == 296,
    "x86 POSIX ucontext mask");
_Static_assert(offsetof(ucontext_t, __fpregs_mem) == 424,
    "x86 POSIX ucontext fpstate storage");
