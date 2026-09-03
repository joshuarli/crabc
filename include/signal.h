#ifndef _SIGNAL_H
#define _SIGNAL_H
#if defined(__x86_64__)

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)

#ifdef _GNU_SOURCE
#define __ucontext ucontext
#endif

#define __NEED_size_t
#define __NEED_pid_t
#define __NEED_uid_t
#define __NEED_struct_timespec
#define __NEED_pthread_t
#define __NEED_pthread_attr_t
#define __NEED_time_t
#define __NEED_clock_t
#define __NEED_sigset_t

#include <bits/alltypes.h>

#define SIG_BLOCK     0
#define SIG_UNBLOCK   1
#define SIG_SETMASK   2

#define SI_ASYNCNL (-60)
#define SI_TKILL (-6)
#define SI_SIGIO (-5)
#define SI_ASYNCIO (-4)
#define SI_MESGQ (-3)
#define SI_TIMER (-2)
#define SI_QUEUE (-1)
#define SI_USER 0
#define SI_KERNEL 128

typedef struct sigaltstack stack_t;

#endif

#include <bits/signal.h>

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)

#define SIG_HOLD ((void (*)(int)) 2)

#define FPE_INTDIV 1
#define FPE_INTOVF 2
#define FPE_FLTDIV 3
#define FPE_FLTOVF 4
#define FPE_FLTUND 5
#define FPE_FLTRES 6
#define FPE_FLTINV 7
#define FPE_FLTSUB 8

#define ILL_ILLOPC 1
#define ILL_ILLOPN 2
#define ILL_ILLADR 3
#define ILL_ILLTRP 4
#define ILL_PRVOPC 5
#define ILL_PRVREG 6
#define ILL_COPROC 7
#define ILL_BADSTK 8

#define SEGV_MAPERR 1
#define SEGV_ACCERR 2
#define SEGV_BNDERR 3
#define SEGV_PKUERR 4
#define SEGV_MTEAERR 8
#define SEGV_MTESERR 9

#define BUS_ADRALN 1
#define BUS_ADRERR 2
#define BUS_OBJERR 3
#define BUS_MCEERR_AR 4
#define BUS_MCEERR_AO 5

#define CLD_EXITED 1
#define CLD_KILLED 2
#define CLD_DUMPED 3
#define CLD_TRAPPED 4
#define CLD_STOPPED 5
#define CLD_CONTINUED 6

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef struct {
#ifdef __SI_SWAP_ERRNO_CODE
	int si_signo, si_code, si_errno;
#else
	int si_signo, si_errno, si_code;
#endif
	union {
		char __pad[128 - 2*sizeof(int) - sizeof(long)];
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
					clock_t si_utime, si_stime;
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
#define si_pid     __si_fields.__si_common.__first.__piduid.si_pid
#define si_uid     __si_fields.__si_common.__first.__piduid.si_uid
#define si_status  __si_fields.__si_common.__second.__sigchld.si_status
#define si_utime   __si_fields.__si_common.__second.__sigchld.si_utime
#define si_stime   __si_fields.__si_common.__second.__sigchld.si_stime
#define si_value   __si_fields.__si_common.__second.si_value
#define si_addr    __si_fields.__sigfault.si_addr
#define si_addr_lsb __si_fields.__sigfault.si_addr_lsb
#define si_lower   __si_fields.__sigfault.__first.__addr_bnd.si_lower
#define si_upper   __si_fields.__sigfault.__first.__addr_bnd.si_upper
#define si_pkey    __si_fields.__sigfault.__first.si_pkey
#define si_band    __si_fields.__sigpoll.si_band
#define si_fd      __si_fields.__sigpoll.si_fd
#define si_timerid __si_fields.__si_common.__first.__timer.si_timerid
#define si_overrun __si_fields.__si_common.__first.__timer.si_overrun
#define si_ptr     si_value.sival_ptr
#define si_int     si_value.sival_int
#define si_call_addr __si_fields.__sigsys.si_call_addr
#define si_syscall __si_fields.__sigsys.si_syscall
#define si_arch    __si_fields.__sigsys.si_arch

struct sigaction {
	union {
		void (*sa_handler)(int);
		void (*sa_sigaction)(int, siginfo_t *, void *);
	} __sa_handler;
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};
#define sa_handler   __sa_handler.sa_handler
#define sa_sigaction __sa_handler.sa_sigaction

#define SA_UNSUPPORTED 0x00000400
#define SA_EXPOSE_TAGBITS 0x00000800

struct sigevent {
	union sigval sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		char __pad[64 - 2*sizeof(int) - sizeof(union sigval)];
		pid_t sigev_notify_thread_id;
		struct {
			void (*sigev_notify_function)(union sigval);
			pthread_attr_t *sigev_notify_attributes;
		} __sev_thread;
	} __sev_fields;
};

#define sigev_notify_thread_id __sev_fields.sigev_notify_thread_id
#define sigev_notify_function __sev_fields.__sev_thread.sigev_notify_function
#define sigev_notify_attributes __sev_fields.__sev_thread.sigev_notify_attributes

#define SIGEV_SIGNAL 0
#define SIGEV_NONE 1
#define SIGEV_THREAD 2
#define SIGEV_THREAD_ID 4

int __libc_current_sigrtmin(void);
int __libc_current_sigrtmax(void);

#define SIGRTMIN  (__libc_current_sigrtmin())
#define SIGRTMAX  (__libc_current_sigrtmax())

int kill(pid_t, int);

int sigemptyset(sigset_t *);
int sigfillset(sigset_t *);
int sigaddset(sigset_t *, int);
int sigdelset(sigset_t *, int);
int sigismember(const sigset_t *, int);

int sigprocmask(int, const sigset_t *__restrict, sigset_t *__restrict);
int sigsuspend(const sigset_t *);
int sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict);
int sigpending(sigset_t *);
int sigwait(const sigset_t *__restrict, int *__restrict);
int sigwaitinfo(const sigset_t *__restrict, siginfo_t *__restrict);
int sigtimedwait(const sigset_t *__restrict, siginfo_t *__restrict, const struct timespec *__restrict);
int sigqueue(pid_t, int, union sigval);

int pthread_sigmask(int, const sigset_t *__restrict, sigset_t *__restrict);
int pthread_kill(pthread_t, int);

void psiginfo(const siginfo_t *, const char *);
void psignal(int, const char *);

#endif

#if defined(_XOPEN_SOURCE) || defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
int killpg(pid_t, int);
int sigaltstack(const stack_t *__restrict, stack_t *__restrict);
int sighold(int);
int sigignore(int);
int siginterrupt(int, int);
int sigpause(int);
int sigrelse(int);
void (*sigset(int, void (*)(int)))(int);
#define TRAP_BRKPT 1
#define TRAP_TRACE 2
#define TRAP_BRANCH 3
#define TRAP_HWBKPT 4
#define TRAP_UNK 5
#define POLL_IN 1
#define POLL_OUT 2
#define POLL_MSG 3
#define POLL_ERR 4
#define POLL_PRI 5
#define POLL_HUP 6
#define SS_ONSTACK    1
#define SS_DISABLE    2
#define SS_AUTODISARM (1U << 31)
#define SS_FLAG_BITS SS_AUTODISARM
#endif

#if defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
#define NSIG _NSIG
typedef void (*sig_t)(int);

#define SYS_SECCOMP 1
#define SYS_USER_DISPATCH 2
#endif

#ifdef _GNU_SOURCE
typedef void (*sighandler_t)(int);
void (*bsd_signal(int, void (*)(int)))(int);
int sigisemptyset(const sigset_t *);
int sigorset (sigset_t *, const sigset_t *, const sigset_t *);
int sigandset(sigset_t *, const sigset_t *, const sigset_t *);

#define SA_NOMASK SA_NODEFER
#define SA_ONESHOT SA_RESETHAND
#endif

#define SIG_ERR  ((void (*)(int))-1)
#define SIG_DFL  ((void (*)(int)) 0)
#define SIG_IGN  ((void (*)(int)) 1)

typedef int sig_atomic_t;

void (*signal(int, void (*)(int)))(int);
int raise(int);

#if _REDIR_TIME64
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
__REDIR(sigtimedwait, __sigtimedwait_time64);
#endif
#endif

#ifdef __cplusplus
}
#endif

#else

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

/* This is musl's public Linux siginfo layout. The field union is eight-byte
 * aligned on the staged 64-bit Linux targets, so queued-signal sender data
 * starts at offset 16 and the sigval starts at offset 24. */
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

#if defined(__x86_64__) && defined(_GNU_SOURCE)
enum { REG_R8 = 0 };
#define REG_R8 REG_R8
enum { REG_R9 = 1 };
#define REG_R9 REG_R9
enum { REG_R10 = 2 };
#define REG_R10 REG_R10
enum { REG_R11 = 3 };
#define REG_R11 REG_R11
enum { REG_R12 = 4 };
#define REG_R12 REG_R12
enum { REG_R13 = 5 };
#define REG_R13 REG_R13
enum { REG_R14 = 6 };
#define REG_R14 REG_R14
enum { REG_R15 = 7 };
#define REG_R15 REG_R15
enum { REG_RDI = 8 };
#define REG_RDI REG_RDI
enum { REG_RSI = 9 };
#define REG_RSI REG_RSI
enum { REG_RBP = 10 };
#define REG_RBP REG_RBP
enum { REG_RBX = 11 };
#define REG_RBX REG_RBX
enum { REG_RDX = 12 };
#define REG_RDX REG_RDX
enum { REG_RAX = 13 };
#define REG_RAX REG_RAX
enum { REG_RCX = 14 };
#define REG_RCX REG_RCX
enum { REG_RSP = 15 };
#define REG_RSP REG_RSP
enum { REG_RIP = 16 };
#define REG_RIP REG_RIP
enum { REG_EFL = 17 };
#define REG_EFL REG_EFL
enum { REG_CSGSFS = 18 };
#define REG_CSGSFS REG_CSGSFS
enum { REG_ERR = 19 };
#define REG_ERR REG_ERR
enum { REG_TRAPNO = 20 };
#define REG_TRAPNO REG_TRAPNO
enum { REG_OLDMASK = 21 };
#define REG_OLDMASK REG_OLDMASK
enum { REG_CR2 = 22 };
#define REG_CR2 REG_CR2
#endif

/* musl exposes x86 machine and user-context records only to a POSIX-or-later
 * feature profile. Keep that x86 visibility boundary local while preserving
 * the existing AArch64 public-header behavior. */
#if !defined(__x86_64__) || defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#if defined(__x86_64__) && (defined(_GNU_SOURCE) || defined(_BSD_SOURCE))
/* Match musl's Linux/x86-64 GNU/BSD signal-context vocabulary exactly. These
 * records describe signal-frame observations only; this source-only header
 * slice does not select a C signal runtime. */
typedef long long greg_t, gregset_t[23];
typedef struct _fpstate {
    unsigned short cwd, swd, ftw, fop;
    unsigned long long rip, rdp;
    unsigned mxcsr, mxcr_mask;
    struct {
        unsigned short significand[4], exponent, padding[3];
    } _st[8];
    struct {
        unsigned element[4];
    } _xmm[16];
    unsigned padding[24];
} *fpregset_t;
struct sigcontext {
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
    unsigned long rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags;
    unsigned short cs, gs, fs, __pad0;
    unsigned long err, trapno, oldmask, cr2;
    struct _fpstate *fpstate;
    unsigned long __reserved1[8];
};
typedef struct {
    gregset_t gregs;
    fpregset_t fpregs;
    unsigned long long __reserved1[8];
} mcontext_t;
#elif defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
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
#elif defined(__x86_64__)
typedef struct { unsigned long __space[32]; } mcontext_t;
#else
typedef struct { long double __regs[274]; } mcontext_t;
#endif

#if defined(__x86_64__)
typedef struct __ucontext {
    unsigned long uc_flags;
    struct __ucontext *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    sigset_t uc_sigmask;
    unsigned long __fpregs_mem[64];
} ucontext_t;
#else
typedef struct __ucontext {
    unsigned long uc_flags;
    struct __ucontext *uc_link;
    stack_t uc_stack;
    sigset_t uc_sigmask;
    mcontext_t uc_mcontext;
} ucontext_t;
#endif
#endif

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
int __libc_current_sigrtmin(void);
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
/* Pinned musl exposes this historical `signal` spelling only to GNU source.
 * `__sysv_signal` is an ABI-only alias in musl's signal.c and deliberately has
 * no public header declaration. */
#if defined(_GNU_SOURCE)
void (*bsd_signal(int, void (*)(int)))(int);
int sigisemptyset(const sigset_t *);
int sigorset(sigset_t *, const sigset_t *, const sigset_t *);
int sigandset(sigset_t *, const sigset_t *, const sigset_t *);
#endif
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
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void psiginfo(const siginfo_t *, const char *);
void psignal(int, const char *);
#endif
int pthread_kill(pthread_t, int);
int pthread_sigmask(int, const sigset_t *__restrict, sigset_t *__restrict);
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
#endif
