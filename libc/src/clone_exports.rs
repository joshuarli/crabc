// Linux clone export.
//
// The public clone ABI is a varargs wrapper around the kernel's five clone
// arguments plus the user callback and context.
// Keep the argument decoding here, at the libc boundary: the architecture
// helper below only knows the fixed musl __clone calling convention and always
// starts the callback on the supplied stack before exiting with its result.

const CABI_CLONE_VM: c_int = 0x00000100;
const CABI_CLONE_PIDFD: c_int = 0x00001000;
const CABI_CLONE_THREAD: c_int = 0x00010000;
const CABI_CLONE_SETTLS: c_int = 0x00080000;
const CABI_CLONE_PARENT_SETTID: c_int = 0x00100000;
const CABI_CLONE_CHILD_CLEARTID: c_int = 0x00200000;
const CABI_CLONE_CHILD_SETTID: c_int = 0x01000000;

// musl's __abort_lock serializes fork-like process creation with abort and
// other libc lock transitions.  crabc has no shared libc.lock state, so keep
// the same boundary as a clone-local lock; the child releases its private
// copy in cabi_clone_post_fork(0), and the parent releases its copy on every
// return from __crabc_clone.
static CABI_CLONE_ABORT_LOCK: AtomicI32 = AtomicI32::new(0);

#[inline]
unsafe fn cabi_clone_lock_abort() {
    while CABI_CLONE_ABORT_LOCK
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
unsafe fn cabi_clone_unlock_abort() {
    CABI_CLONE_ABORT_LOCK.store(0, Ordering::Release);
}

#[repr(C)]
struct CabiCloneStartArgs {
    func: unsafe extern "C" fn(*mut c_void) -> c_int,
    arg: *mut c_void,
    sigmask: SigSetT,
}

// __post_Fork(0) equivalent for crabc's fixed thread-slot registry.  A
// non-CLONE_VM clone has only one live thread in the child, but the copied
// registry still contains the parent's TIDs and lock state. Clear those slots
// before releasing the child copy of the abort lock and restoring the caller's
// signal mask; the child registers itself lazily on its first pthread call.
unsafe fn cabi_clone_post_fork(ret: i64) {
    if ret == 0 {
        reset_thread_registry_after_fork(-1);
    }
    cabi_clone_unlock_abort();
}

unsafe fn cabi_clone_block_all_sigs(old: *mut SigSetT) {
    let mut all: SigSetT = 0;
    sigfillset(&mut all);
    let _ = sigprocmask(SIG_BLOCK, &all, old);
}

unsafe fn cabi_clone_restore_sigs(old: *const SigSetT) {
    let _ = sigprocmask(SIG_SETMASK, old, core::ptr::null_mut());
}

// This wrapper is entered only for non-CLONE_VM clones.  The child first
// performs the post-fork libc reset and restores the caller's mask, then runs
// the user's callback; the assembly helper turns this return value into the
// child exit status.
unsafe extern "C" fn cabi_clone_start(arg: *mut c_void) -> c_int {
    let csa = &*(arg as *const CabiCloneStartArgs);
    cabi_clone_post_fork(0);
    cabi_clone_restore_sigs(&csa.sigmask);
    (csa.func)(csa.arg)
}

// __crabc_clone(func, stack, flags, arg, ptid, tls, ctid)
//
// This is the fixed-argument ABI used by musl's arch/*/clone.s.  In
// particular, clone's C `flags` argument is an int, while the kernel expects
// an unsigned long in its first syscall argument; each helper widens the
// low 32 bits in the architecture's syscall register explicitly.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".text",
    ".global __crabc_clone",
    ".hidden __crabc_clone",
    ".type __crabc_clone, @function",
    "__crabc_clone:",
    "mov rax, rdi",
    "mov edi, edx",
    "mov rdx, r8",
    "mov r10, [rsp + 8]",
    "mov r8, r9",
    "mov r9, rax",
    "and rsi, -16",
    "sub rsi, 8",
    "mov [rsi], rcx",
    "mov eax, 56",
    "syscall",
    "test rax, rax",
    "jnz 1f",
    "xor ebp, ebp",
    "pop rdi",
    "call r9",
    "mov edi, eax",
    "mov eax, 60",
    "syscall",
    "hlt",
    "1:",
    "ret",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global __crabc_clone",
    ".hidden __crabc_clone",
    ".type __crabc_clone,%function",
    "__crabc_clone:",
    // Align stack and save func,arg.
    "and x1,x1,#-16",
    "stp x0,x3,[x1,#-16]!",
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid).
    "uxtw x0,w2",
    "mov x2,x4",
    "mov x3,x5",
    "mov x4,x6",
    "mov x8,#220",
    "svc #0",
    "cbz x0,1f",
    "ret",
    // Child: callback result is the exit status.
    "1:",
    "mov x29,#0",
    "ldp x1,x0,[sp],#16",
    "blr x1",
    "mov x8,#93",
    "svc #0",
);

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".global __crabc_clone",
    ".hidden __crabc_clone",
    ".type __crabc_clone, %function",
    "__crabc_clone:",
    // Align stack and save func,arg.
    "andi a1,a1,-16",
    "addi a1,a1,-16",
    "sd a0,0(a1)",
    "sd a3,8(a1)",
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid).
    "slli a0,a2,32",
    "srli a0,a0,32",
    "mv a2,a4",
    "mv a3,a5",
    "mv a4,a6",
    "li a7,220",
    "ecall",
    "beqz a0,1f",
    "ret",
    // Child: callback result is the exit status.
    "1:",
    "ld a1,0(sp)",
    "ld a0,8(sp)",
    "jalr a1",
    "li a7,93",
    "ecall",
);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
extern "C" {
    fn __crabc_clone(
        func: usize,
        stack: *mut u8,
        flags: c_int,
        arg: *mut c_void,
        ptid: *mut c_int,
        tls: *mut c_void,
        ctid: *mut c_int,
    ) -> i64;
}

#[no_mangle]
pub unsafe extern "C" fn clone(
    func: unsafe extern "C" fn(*mut c_void) -> c_int,
    stack: *mut c_void,
    flags: c_int,
    arg: *mut c_void,
    mut args: ...,
) -> c_int {
    // These flags would create a child that needs libc's thread/TLS state,
    // which this standalone process clone cannot establish consistently.
    // Match musl's public clone contract by rejecting them before touching
    // the caller's varargs or issuing a syscall.
    const BAD_FLAGS: c_int = CABI_CLONE_THREAD | CABI_CLONE_SETTLS | CABI_CLONE_CHILD_CLEARTID;
    if stack.is_null() || (flags & BAD_FLAGS) != 0 {
        ERRNO = EINVAL;
        return -1;
    }

    // Linux consumes optional arguments only for the flags that request
    // corresponding parent/child ID or pidfd storage.  Reading these in any
    // other order would shift the AArch64 syscall ABI (ptid, tls, ctid).
    let mut ptid: *mut c_int = core::ptr::null_mut();
    let mut tls: *mut c_void = core::ptr::null_mut();
    let mut ctid: *mut c_int = core::ptr::null_mut();
    if (flags & (CABI_CLONE_PIDFD | CABI_CLONE_PARENT_SETTID | CABI_CLONE_CHILD_SETTID)) != 0 {
        ptid = args.next_arg();
    }
    if (flags & CABI_CLONE_CHILD_SETTID) != 0 {
        tls = args.next_arg();
        ctid = args.next_arg();
    }

    // CLONE_VM cannot safely carry a parent-side wrapper context: the caller
    // may return and reuse that stack while the child is still starting.  As
    // in musl, use the raw callback path for it.  The process-clone path below
    // blocks signals, serializes the libc state transition, and runs through
    // cabi_clone_start in the child.
    if (flags & CABI_CLONE_VM) != 0 {
        return syscall_result(__crabc_clone(
            func as usize,
            stack as *mut u8,
            flags,
            arg,
            ptid,
            tls,
            ctid,
        )) as c_int;
    }

    let mut csa = CabiCloneStartArgs {
        func,
        arg,
        sigmask: 0,
    };
    cabi_clone_block_all_sigs(&mut csa.sigmask);
    cabi_clone_lock_abort();
    let ret = __crabc_clone(
        cabi_clone_start as *const () as usize,
        stack as *mut u8,
        flags,
        &mut csa as *mut CabiCloneStartArgs as *mut c_void,
        ptid,
        tls,
        ctid,
    );
    // __crabc_clone returns only in the parent.  On failure this also releases
    // the lock before errno conversion; the child releases its private copy
    // in cabi_clone_start before the callback runs.
    cabi_clone_post_fork(ret);
    cabi_clone_restore_sigs(&csa.sigmask);
    // syscall_result publishes kernel errno as -1 without changing a
    // successful call's pre-existing errno.
    syscall_result(ret) as c_int
}
