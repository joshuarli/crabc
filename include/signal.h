#ifndef _SIGNAL_H
#define _SIGNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#define __NEED_size_t
#define __NEED_sigset_t
#include <bits/alltypes.h>
#include <sys/types.h>

#if defined(_GNU_SOURCE)
#define __ucontext ucontext
#endif

typedef void (*sighandler_t)(int);
typedef int sig_atomic_t;

#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIG_ERR ((sighandler_t)-1)
#define SIG_HOLD ((sighandler_t)2)

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define SIGTRAP   5
#endif
#define SIGABRT   6
#define SIGIOT    6
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1  10
#define SIGSEGV  11
#define SIGUSR2  12
#define SIGPIPE  13
#define SIGALRM  14
#define SIGTERM  15
#define SIGSTKFLT 16
#define SIGCHLD  17
#define SIGCONT  18
#define SIGSTOP  19
#define SIGTSTP  20
#define SIGTTIN  21
#define SIGTTOU  22
#define SIGURG   23
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define SIGXCPU  24
#define SIGXFSZ  25
#define SIGVTALRM 26
#endif
#define SIGPROF  27
#define SIGWINCH 28
#define SIGIO    29
#define SIGPOLL  29
#define SIGPWR   30
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define SIGSYS   31
#endif
#define SIGUNUSED 31

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define _NSIG    65
#define NSIG     _NSIG
#endif

#define SIG_BLOCK   0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SA_NOCLDSTOP  1
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define SA_NOCLDWAIT  2
#endif
#define SA_SIGINFO    4
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define SA_ONSTACK    0x08000000
#endif
#define SA_RESTART    0x10000000
#define SA_NODEFER    0x40000000
#define SA_RESETHAND  0x80000000
#define SA_RESTORER   0x04000000

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define SS_ONSTACK    1
#define SS_DISABLE    2
#if defined(__aarch64__)
#define MINSIGSTKSZ   6144
#define SIGSTKSZ      12288
#else
#define MINSIGSTKSZ   2048
#define SIGSTKSZ      8192
#endif
#endif

#define SI_USER   0
#define SI_TKILL  (-6)

union sigval {
    int sival_int;
    void *sival_ptr;
};

/* This is musl's public Linux siginfo layout.  In particular, the field
 * union is eight-byte aligned on AArch64, so queued-signal sender data starts
 * at offset 16 and the sigval starts at offset 24. */
typedef struct {
    int si_signo;
    int si_errno;
    int si_code;
    union {
        char __pad[128 - 2 * sizeof(int) - sizeof(long)];
        struct {
            union {
                struct {
                    pid_t si_pid;
                    uid_t si_uid;
                } __piduid;
                struct {
                    int si_timerid;
                    int si_overrun;
                } __timer;
            } __first;
            union {
                union sigval si_value;
                struct {
                    int si_status;
                    clock_t si_utime;
                    clock_t si_stime;
                } __sigchld;
            } __second;
        } __si_common;
        struct {
            void *si_addr;
            short si_addr_lsb;
            union {
                struct {
                    void *si_lower;
                    void *si_upper;
                } __addr_bnd;
                unsigned si_pkey;
            } __first;
        } __sigfault;
        struct {
            long si_band;
            int si_fd;
        } __sigpoll;
        struct {
            void *si_call_addr;
            int si_syscall;
            unsigned si_arch;
        } __sigsys;
    } __si_fields;
} siginfo_t;

#define si_pid __si_fields.__si_common.__first.__piduid.si_pid
#define si_uid __si_fields.__si_common.__first.__piduid.si_uid
#define si_status __si_fields.__si_common.__second.__sigchld.si_status
#define si_utime __si_fields.__si_common.__second.__sigchld.si_utime
#define si_stime __si_fields.__si_common.__second.__sigchld.si_stime
#define si_value __si_fields.__si_common.__second.si_value
#define si_addr __si_fields.__sigfault.si_addr
#define si_addr_lsb __si_fields.__sigfault.si_addr_lsb
#define si_lower __si_fields.__sigfault.__first.__addr_bnd.si_lower
#define si_upper __si_fields.__sigfault.__first.__addr_bnd.si_upper
#define si_pkey __si_fields.__sigfault.__first.si_pkey
#define si_band __si_fields.__sigpoll.si_band
#define si_fd __si_fields.__sigpoll.si_fd
#define si_timerid __si_fields.__si_common.__first.__timer.si_timerid
#define si_overrun __si_fields.__si_common.__first.__timer.si_overrun
#define si_ptr si_value.sival_ptr
#define si_int si_value.sival_int
#define si_call_addr __si_fields.__sigsys.si_call_addr
#define si_syscall __si_fields.__sigsys.si_syscall
#define si_arch __si_fields.__sigsys.si_arch

/* musl's public record keeps the full 128-byte mask before flags/restorer;
 * the Linux kernel syscall record has a different compact ordering. */
struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, siginfo_t *, void *);
    } __sa_handler;
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};
#define sa_handler __sa_handler.sa_handler
#define sa_sigaction __sa_handler.sa_sigaction

/* Keep the tag private: the public musl type is stack_t, and exposing a
 * sigaltstack tag collides with the function namespace in strict checks. */
struct __stack {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
};

typedef struct __stack stack_t;

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef unsigned long greg_t;
typedef unsigned long gregset_t[34];
typedef struct {
    __uint128_t vregs[32];
    unsigned int fpsr;
    unsigned int fpcr;
} fpregset_t;
typedef struct sigcontext {
    unsigned long fault_address;
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
    long double __reserved[256];
} mcontext_t;
#else
typedef struct { long double __regs[274]; } mcontext_t;
#endif
typedef struct __ucontext {
    unsigned long uc_flags;
    struct __ucontext *uc_link;
    stack_t uc_stack;
    sigset_t uc_sigmask;
    mcontext_t uc_mcontext;
} ucontext_t;

#ifndef __DEFINED_struct_timespec
#define __DEFINED_struct_timespec
struct timespec {
    long tv_sec;
    long tv_nsec;
};
#endif

struct sigevent {
    union sigval sigev_value;
    int sigev_signo;
    int sigev_notify;
    union {
        /* Linux/musl reserves this tail; sizeof(struct sigevent) is 64. */
        char __pad[64 - 2 * sizeof(int) - sizeof(union sigval)];
        int sigev_notify_thread_id;
        struct {
            void (*sigev_notify_function)(union sigval);
            pthread_attr_t *sigev_notify_attributes;
        } __sigev_thread;
    } __sigev_fields;
};

#define sigev_notify_thread_id __sigev_fields.sigev_notify_thread_id
#define sigev_notify_function __sigev_fields.__sigev_thread.sigev_notify_function
#define sigev_notify_attributes __sigev_fields.__sigev_thread.sigev_notify_attributes

#define SIGEV_NONE 1
#define SIGEV_SIGNAL 0
#define SIGEV_THREAD 2
#define SIGEV_THREAD_ID 4
#define SIGRTMIN 35
int __libc_current_sigrtmax(void);
#define SIGRTMAX (__libc_current_sigrtmax())
#define SI_QUEUE (-1)
#define SI_TIMER (-2)
#define SI_ASYNCIO (-4)
#define SI_MESGQ (-3)
#define ILL_ILLOPC 1
#define ILL_ILLOPN 2
#define ILL_ILLADR 3
#define ILL_ILLTRP 4
#define ILL_PRVOPC 5
#define ILL_PRVREG 6
#define ILL_COPROC 7
#define ILL_BADSTK 8
#define FPE_INTDIV 1
#define FPE_INTOVF 2
#define FPE_FLTDIV 3
#define FPE_FLTOVF 4
#define FPE_FLTUND 5
#define FPE_FLTRES 6
#define FPE_FLTINV 7
#define FPE_FLTSUB 8
#define SEGV_MAPERR 1
#define SEGV_ACCERR 2
#define BUS_ADRALN 1
#define BUS_ADRERR 2
#define BUS_OBJERR 3
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define TRAP_BRKPT 1
#define TRAP_TRACE 2
#endif
#define CLD_EXITED 1
#define CLD_KILLED 2
#define CLD_DUMPED 3
#define CLD_TRAPPED 4
#define CLD_STOPPED 5
#define CLD_CONTINUED 6

int sigaction(int, const struct sigaction *, struct sigaction *);
sighandler_t signal(int, sighandler_t);
int raise(int);
int kill(int, int);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int tgkill(int, int, int);
#endif
int sigemptyset(sigset_t *);
int sigfillset(sigset_t *);
int sigaddset(sigset_t *, int);
int sigdelset(sigset_t *, int);
int sigismember(const sigset_t *, int);
int sigprocmask(int, const sigset_t *, sigset_t *);
int sigpending(sigset_t *);
int sigsuspend(const sigset_t *);
int sigtimedwait(const sigset_t *, siginfo_t *, const struct timespec *);
int sigwaitinfo(const sigset_t *, siginfo_t *);
int sigwait(const sigset_t *, int *);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int sigaltstack(const stack_t *, stack_t *);
int killpg(pid_t, int);
#endif
void psiginfo(const siginfo_t *, const char *);
void psignal(int, const char *);
int pthread_kill(pthread_t, int);
int pthread_sigmask(int, const sigset_t *restrict, sigset_t *restrict);
/* These System V signal helpers are legacy XSI. POSIX.1-2024 no longer
 * reserves them in the current XSI namespace; retain them for older X/Open,
 * BSD, and GNU source contracts. */
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE) \
 || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 800)
int sighold(int);
int sigignore(int);
int siginterrupt(int, int);
int sigpause(int);
#endif
int sigqueue(pid_t, int, const union sigval);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE) \
 || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 800)
int sigrelse(int);
sighandler_t sigset(int, sighandler_t);
#endif

#ifdef __cplusplus
}
#endif

#endif
