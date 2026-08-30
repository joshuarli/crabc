/* Linux/x86-64 machine/context public-header ABI facts.
 *
 * Pinned musl 1.2.6 owns these declaration, feature-visibility, and LP64
 * layout facts. This compile-only probe intentionally proves no ptrace,
 * aux-vector, or context-switch runtime behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/auxv.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/procfs.h>
#include <sys/ucontext.h>

#ifndef ELF_NGREG
#error "Linux/x86-64 must expose ELF_NGREG"
#endif
#ifdef ELF_NREG
#error "Linux/x86-64 must not expose AArch64 ELF_NREG"
#endif
#ifdef HWCAP_FP
#error "Linux/x86-64 must not expose AArch64 HWCAP_FP"
#endif
#ifdef HWCAP_ASIMD
#error "Linux/x86-64 must not expose AArch64 HWCAP_ASIMD"
#endif
#ifdef HWCAP2_MTE
#error "Linux/x86-64 must not expose AArch64 HWCAP2_MTE"
#endif

#ifdef CRABC_MACHINE_CONTEXT_REQUIRE_CONTEXT_HIDDEN
static mcontext_t machine_context_mcontext_must_be_hidden;
static ucontext_t machine_context_ucontext_must_be_hidden;
#endif

_Static_assert(ELF_NGREG == 27, "x86 ELF general-register count");
_Static_assert(R15 == 0 && RAX == 10 && RIP == 16 && RSP == 19 && GS == 26,
    "x86 ptrace user-register indices");
_Static_assert(sizeof(struct user_regs_struct) == 216 &&
    _Alignof(struct user_regs_struct) == 8, "x86 user register layout");
_Static_assert(offsetof(struct user_regs_struct, r15) == 0 &&
    offsetof(struct user_regs_struct, rax) == 80 &&
    offsetof(struct user_regs_struct, rip) == 128 &&
    offsetof(struct user_regs_struct, rsp) == 152 &&
    offsetof(struct user_regs_struct, gs) == 208,
    "x86 user register offsets");
_Static_assert(sizeof(struct user_fpregs_struct) == 512 &&
    _Alignof(struct user_fpregs_struct) == 8, "x86 user floating-point layout");
_Static_assert(offsetof(struct user_fpregs_struct, rip) == 8 &&
    offsetof(struct user_fpregs_struct, mxcsr) == 24 &&
    offsetof(struct user_fpregs_struct, xmm_space) == 160,
    "x86 user floating-point offsets");
_Static_assert(__builtin_types_compatible_p(elf_greg_t, unsigned long long),
    "x86 elf_greg_t type");
_Static_assert(sizeof(elf_gregset_t) == 216 && _Alignof(elf_gregset_t) == 8,
    "x86 elf general-register set layout");
_Static_assert(sizeof(elf_fpregset_t) == 512 && _Alignof(elf_fpregset_t) == 8,
    "x86 elf floating-point register set layout");
_Static_assert(sizeof(struct user) == 912 && _Alignof(struct user) == 8,
    "x86 user-area layout");
_Static_assert(offsetof(struct user, regs) == 0 &&
    offsetof(struct user, i387) == 224 &&
    offsetof(struct user, u_debugreg) == 848, "x86 user-area offsets");

_Static_assert(sizeof(struct elf_prstatus) == 336 &&
    _Alignof(struct elf_prstatus) == 8, "x86 ELF process-status layout");
_Static_assert(offsetof(struct elf_prstatus, pr_reg) == 112,
    "x86 ELF process-status register offset");
_Static_assert(sizeof(struct elf_prpsinfo) == 136 &&
    _Alignof(struct elf_prpsinfo) == 8, "x86 ELF process-info layout");

#ifdef CRABC_MACHINE_CONTEXT_EXPECT_CONTEXT
_Static_assert(sizeof(mcontext_t) == 256 && _Alignof(mcontext_t) == 8,
    "x86 machine-context layout");
_Static_assert(sizeof(ucontext_t) == 936 && _Alignof(ucontext_t) == 8,
    "x86 user-context layout");
_Static_assert(offsetof(ucontext_t, uc_mcontext) == 40,
    "x86 user-context machine-context offset");
#ifdef CRABC_MACHINE_CONTEXT_EXPECT_GNU_BSD
#ifndef NGREG
#error "GNU/BSD x86 context profile must expose NGREG"
#endif
_Static_assert(NGREG == 23, "x86 GNU/BSD general-register count");
_Static_assert(sizeof(greg_t) == 8 && sizeof(gregset_t) == 184,
    "x86 GNU/BSD general-register context layout");
_Static_assert(offsetof(mcontext_t, gregs) == 0 &&
    offsetof(mcontext_t, fpregs) == 184,
    "x86 GNU/BSD machine-context offsets");
#else
#ifdef NGREG
#error "strict/POSIX/XOPEN x86 context profile must hide NGREG"
#endif
#endif
#else
#ifdef NGREG
#error "strict x86 context profile must hide NGREG"
#endif
#endif

_Static_assert(PTRACE_GETFPREGS == 14 && PTRACE_SETFPREGS == 15 &&
    PTRACE_GETFPXREGS == 18 && PTRACE_SETFPXREGS == 19,
    "generic ptrace floating-point commands");
_Static_assert(PTRACE_PEEKSIGINFO == 0x4209 && PTRACE_GETSIGMASK == 0x420a &&
    PTRACE_SETSIGMASK == 0x420b && PTRACE_SECCOMP_GET_FILTER == 0x420c &&
    PTRACE_SECCOMP_GET_METADATA == 0x420d && PTRACE_GET_SYSCALL_INFO == 0x420e &&
    PTRACE_GET_RSEQ_CONFIGURATION == 0x420f,
    "extended generic ptrace commands");
_Static_assert(PTRACE_GET_THREAD_AREA == 25 && PTRACE_SET_THREAD_AREA == 26 &&
    PTRACE_ARCH_PRCTL == 30 && PTRACE_SYSEMU == 31 &&
    PTRACE_SYSEMU_SINGLESTEP == 32 && PTRACE_SINGLEBLOCK == 33,
    "x86 ptrace commands");
_Static_assert(PT_TRACE_ME == PTRACE_TRACEME &&
    PT_GET_THREAD_AREA == PTRACE_GET_THREAD_AREA &&
    PT_STEPBLOCK == PTRACE_SINGLEBLOCK, "ptrace compatibility aliases");
_Static_assert(PTRACE_O_SUSPEND_SECCOMP == 0x00200000 &&
    PTRACE_O_MASK == 0x003000ff && PTRACE_EVENT_STOP == 128 &&
    PTRACE_SYSCALL_INFO_SECCOMP == 3,
    "ptrace option and event constants");
_Static_assert(sizeof(struct __ptrace_peeksiginfo_args) == 16 &&
    _Alignof(struct __ptrace_peeksiginfo_args) == 8,
    "ptrace peeksiginfo argument layout");
_Static_assert(offsetof(struct __ptrace_peeksiginfo_args, flags) == 8 &&
    offsetof(struct __ptrace_peeksiginfo_args, nr) == 12,
    "ptrace peeksiginfo argument offsets");
_Static_assert(sizeof(struct __ptrace_seccomp_metadata) == 16 &&
    _Alignof(struct __ptrace_seccomp_metadata) == 8,
    "ptrace seccomp metadata layout");
_Static_assert(sizeof(struct __ptrace_syscall_info) == 88 &&
    _Alignof(struct __ptrace_syscall_info) == 8,
    "ptrace syscall-information layout");
_Static_assert(offsetof(struct __ptrace_syscall_info, instruction_pointer) == 8 &&
    offsetof(struct __ptrace_syscall_info, stack_pointer) == 16 &&
    offsetof(struct __ptrace_syscall_info, entry.args) == 32,
    "ptrace syscall-information offsets");
_Static_assert(sizeof(struct __ptrace_rseq_configuration) == 24 &&
    _Alignof(struct __ptrace_rseq_configuration) == 8,
    "ptrace rseq configuration layout");

typedef unsigned long (*getauxval_signature)(unsigned long);
typedef long (*ptrace_signature)(int, ...);
typedef int (*getcontext_signature)(struct __ucontext *);
typedef void (*makecontext_signature)(struct __ucontext *, void (*)(), int, ...);
typedef int (*setcontext_signature)(const struct __ucontext *);
typedef int (*swapcontext_signature)(struct __ucontext *, const struct __ucontext *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getauxval),
    getauxval_signature), "getauxval declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ptrace),
    ptrace_signature), "ptrace declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getcontext),
    getcontext_signature), "getcontext declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&makecontext),
    makecontext_signature), "makecontext declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setcontext),
    setcontext_signature), "setcontext declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&swapcontext),
    swapcontext_signature), "swapcontext declaration");
