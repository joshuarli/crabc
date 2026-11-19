#if defined(__x86_64__)
#if defined(__x86_64__)
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define MINSIGSTKSZ 2048
#define SIGSTKSZ 8192
#endif

#ifdef _GNU_SOURCE
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
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
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
#else
typedef struct {
	unsigned long __space[32];
} mcontext_t;
#endif

struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
};

typedef struct __ucontext {
	unsigned long uc_flags;
	struct __ucontext *uc_link;
	stack_t uc_stack;
	mcontext_t uc_mcontext;
	sigset_t uc_sigmask;
	unsigned long __fpregs_mem[64];
} ucontext_t;

#define SA_NOCLDSTOP  1
#define SA_NOCLDWAIT  2
#define SA_SIGINFO    4
#define SA_ONSTACK    0x08000000
#define SA_RESTART    0x10000000
#define SA_NODEFER    0x40000000
#define SA_RESETHAND  0x80000000
#define SA_RESTORER   0x04000000

#endif

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED SIGSYS

#define _NSIG 65

#endif
#elif defined(__aarch64__)
/* musl 1.2.6 aarch64/bits/signal.h, MIT licensed. */
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define MINSIGSTKSZ 6144
#define SIGSTKSZ 12288
#endif

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
	unsigned long sp, pc, pstate;
	long double __reserved[256];
} mcontext_t;

#define FPSIMD_MAGIC 0x46508001
#define ESR_MAGIC 0x45535201
#define EXTRA_MAGIC 0x45585401
#define SVE_MAGIC 0x53564501
struct _aarch64_ctx {
	unsigned int magic;
	unsigned int size;
};
struct fpsimd_context {
	struct _aarch64_ctx head;
	unsigned int fpsr;
	unsigned int fpcr;
	__uint128_t vregs[32];
};
struct esr_context {
	struct _aarch64_ctx head;
	unsigned long esr;
};
struct extra_context {
	struct _aarch64_ctx head;
	unsigned long datap;
	unsigned int size;
	unsigned int __reserved[3];
};
struct sve_context {
	struct _aarch64_ctx head;
	unsigned short vl;
	unsigned short __reserved[3];
};
#define SVE_VQ_BYTES		16
#define SVE_VQ_MIN		1
#define SVE_VQ_MAX		512
#define SVE_VL_MIN		(SVE_VQ_MIN * SVE_VQ_BYTES)
#define SVE_VL_MAX		(SVE_VQ_MAX * SVE_VQ_BYTES)
#define SVE_NUM_ZREGS		32
#define SVE_NUM_PREGS		16
#define sve_vl_valid(vl) \
	((vl) % SVE_VQ_BYTES == 0 && (vl) >= SVE_VL_MIN && (vl) <= SVE_VL_MAX)
#define sve_vq_from_vl(vl)	((vl) / SVE_VQ_BYTES)
#define sve_vl_from_vq(vq)	((vq) * SVE_VQ_BYTES)
#define SVE_SIG_ZREG_SIZE(vq)	((unsigned)(vq) * SVE_VQ_BYTES)
#define SVE_SIG_PREG_SIZE(vq)	((unsigned)(vq) * (SVE_VQ_BYTES / 8))
#define SVE_SIG_FFR_SIZE(vq)	SVE_SIG_PREG_SIZE(vq)
#define SVE_SIG_REGS_OFFSET					\
	((sizeof(struct sve_context) + (SVE_VQ_BYTES - 1))	\
		/ SVE_VQ_BYTES * SVE_VQ_BYTES)
#define SVE_SIG_ZREGS_OFFSET	SVE_SIG_REGS_OFFSET
#define SVE_SIG_ZREG_OFFSET(vq, n) \
	(SVE_SIG_ZREGS_OFFSET + SVE_SIG_ZREG_SIZE(vq) * (n))
#define SVE_SIG_ZREGS_SIZE(vq) \
	(SVE_SIG_ZREG_OFFSET(vq, SVE_NUM_ZREGS) - SVE_SIG_ZREGS_OFFSET)
#define SVE_SIG_PREGS_OFFSET(vq) \
	(SVE_SIG_ZREGS_OFFSET + SVE_SIG_ZREGS_SIZE(vq))
#define SVE_SIG_PREG_OFFSET(vq, n) \
	(SVE_SIG_PREGS_OFFSET(vq) + SVE_SIG_PREG_SIZE(vq) * (n))
#define SVE_SIG_PREGS_SIZE(vq) \
	(SVE_SIG_PREG_OFFSET(vq, SVE_NUM_PREGS) - SVE_SIG_PREGS_OFFSET(vq))
#define SVE_SIG_FFR_OFFSET(vq) \
	(SVE_SIG_PREGS_OFFSET(vq) + SVE_SIG_PREGS_SIZE(vq))
#define SVE_SIG_REGS_SIZE(vq) \
	(SVE_SIG_FFR_OFFSET(vq) + SVE_SIG_FFR_SIZE(vq) - SVE_SIG_REGS_OFFSET)
#define SVE_SIG_CONTEXT_SIZE(vq) (SVE_SIG_REGS_OFFSET + SVE_SIG_REGS_SIZE(vq))
#else
typedef struct {
	long double __regs[18+256];
} mcontext_t;
#endif

struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
};

typedef struct __ucontext {
	unsigned long uc_flags;
	struct __ucontext *uc_link;
	stack_t uc_stack;
	sigset_t uc_sigmask;
	mcontext_t uc_mcontext;
} ucontext_t;

#define SA_NOCLDSTOP  1
#define SA_NOCLDWAIT  2
#define SA_SIGINFO    4
#define SA_ONSTACK    0x08000000
#define SA_RESTART    0x10000000
#define SA_NODEFER    0x40000000
#define SA_RESETHAND  0x80000000
#define SA_RESTORER   0x04000000

#endif

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED SIGSYS

#define _NSIG 65

#endif
