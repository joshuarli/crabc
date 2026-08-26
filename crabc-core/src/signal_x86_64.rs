//! Direct Linux/x86-64 signal operations.
//!
//! This module is an intentionally raw kernel ABI boundary. It owns neither
//! a process signal policy nor a signal-return trampoline. In particular,
//! Linux/x86-64 handler actions need [`SA_RESTORER`] and a non-null
//! [`KernelSigAction::restorer`] that performs the non-returning
//! `rt_sigreturn` syscall. The runtime which owns handler installation must
//! provide that trampoline and must ensure that it remains executable for as
//! long as the kernel can enter the handler. Supplying an ordinary Rust
//! function, a C function return, or an invalid address as `restorer` corrupts
//! the signal frame rather than reporting an ordinary syscall error.
//!
//! The direct core boundary deliberately does not choose or export a default
//! restorer. `crabc-libc` and `crabc-rs` have distinct runtime ownership and
//! linkage requirements; assigning either one here would make raw core use
//! depend on a particular libc instance. Callers that install only
//! `SIG_DFL`/`SIG_IGN` may keep `restorer` zero, but handler actions are
//! unsafe for the concrete x86-64 frame reason above.

use crate::Result;
use crate::syscall::{
    decode, decode_i32, syscall2, syscall3, syscall4, SYS_RT_SIGACTION, SYS_RT_SIGPENDING,
    SYS_RT_SIGPROCMASK, SYS_RT_SIGQUEUEINFO, SYS_RT_SIGSUSPEND, SYS_RT_SIGTIMEDWAIT,
    SYS_SIGALTSTACK, SYS_SIGNALFD4,
};

/// The Linux/x86-64 `SA_RESTORER` bit required for an installed handler's
/// explicit signal-return trampoline.
pub const SA_RESTORER: u64 = 0x0400_0000;

/// The Linux/x86-64 kernel signal-set width passed to every `rt_*` syscall.
///
/// Linux's kernel ABI deliberately accepts one 64-bit word here, even though
/// musl's public `sigset_t` has more storage for source ABI compatibility.
pub const KERNEL_SIGSET_SIZE: usize = core::mem::size_of::<u64>();

/// Linux/x86-64's compact `rt_sigaction` record.
///
/// The public C `struct sigaction` is a separate ABI. This is exactly the
/// 32-byte record accepted by the kernel's `rt_sigaction` syscall: handler,
/// flags, restorer, then its one 64-bit signal-mask word.
///
/// A handler action must set [`SA_RESTORER`] and put an executable,
/// non-returning `rt_sigreturn` trampoline in [`Self::restorer`]. The kernel
/// enters `handler` according to the selected signal-handler ABI and expects a
/// normal handler return to transfer to that trampoline. The caller owns that
/// asynchronous execution contract; this raw record does not add a fallback.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigAction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

/// Linux's fixed-size `siginfo_t` transport record.
///
/// The kernel fills only the fields meaningful for the triggering signal.
/// Consumers must interpret it according to `si_code`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct SigInfo {
    pub bytes: [u8; 128],
}

impl SigInfo {
    /// A zeroed record suitable for kernel output.
    #[inline]
    pub const fn zeroed() -> Self {
        Self { bytes: [0; 128] }
    }
}

/// Linux/x86-64's `stack_t` layout for `sigaltstack`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalStack {
    pub sp: *mut u8,
    pub flags: i32,
    _padding: i32,
    pub size: usize,
}

impl SignalStack {
    /// Builds a kernel signal-stack record with its x86-64 ABI padding
    /// initialized to zero.
    #[inline]
    pub const fn new(sp: *mut u8, flags: i32, size: usize) -> Self {
        Self {
            sp,
            flags,
            _padding: 0,
            size,
        }
    }
}

/// Installs or queries a signal action without libc or TLS `errno`.
///
/// # Safety
///
/// `action` and `old_action` must be null or point to valid compact
/// Linux/x86-64 records for the duration of the call. A handler action must
/// set [`SA_RESTORER`] and supply an executable `rt_sigreturn` trampoline in
/// `restorer`. The trampoline must never return through the ordinary C or Rust
/// ABI: it must issue Linux/x86-64 syscall 15 (`rt_sigreturn`), which restores
/// the kernel-built signal frame. The handler, its mask, and its restorer must
/// also remain valid for asynchronous entry until a later action replacement
/// has completed. This direct syscall does not call libc or establish libc
/// signal-reservation policy.
#[inline]
pub unsafe fn rt_sigaction_raw(
    signal: i32,
    action: *const KernelSigAction,
    old_action: *mut KernelSigAction,
) -> Result<()> {
    // SAFETY: The caller owns the compact-kernel-record pointer and
    // handler/restorer contracts; the other arguments are scalar values.
    decode(unsafe {
        syscall4(
            SYS_RT_SIGACTION,
            signal as usize,
            action as usize,
            old_action as usize,
            KERNEL_SIGSET_SIZE,
        )
    })
    .map(|_| ())
}

/// Changes or queries the calling thread's kernel signal mask.
///
/// # Safety
///
/// `set` and `old_set` must be null or point to one readable/writable
/// kernel-sized signal-set word, respectively. This direct syscall does not
/// apply any libc-reserved-signal policy.
#[inline]
pub unsafe fn rt_sigprocmask_raw(how: i32, set: *const u64, old_set: *mut u64) -> Result<()> {
    // SAFETY: The caller owns the kernel signal-set pointer contracts.
    decode(unsafe {
        syscall4(
            SYS_RT_SIGPROCMASK,
            how as usize,
            set as usize,
            old_set as usize,
            KERNEL_SIGSET_SIZE,
        )
    })
    .map(|_| ())
}

/// Queries the calling thread's pending signal set.
///
/// # Safety
///
/// `set` must point to writable storage for one kernel-sized signal-set word.
#[inline]
pub unsafe fn rt_sigpending_raw(set: *mut u64) -> Result<()> {
    // SAFETY: The caller owns the kernel signal-set output storage.
    decode(unsafe { syscall2(SYS_RT_SIGPENDING, set as usize, KERNEL_SIGSET_SIZE) }).map(|_| ())
}

/// Atomically swaps in `set` while waiting for an unblocked signal.
///
/// A successful wait never returns; Linux reports `EINTR` after a handler
/// runs. The returned error is intentionally preserved as an ordinary result
/// value rather than being translated through TLS `errno`.
///
/// # Safety
///
/// `set` must point to one readable kernel-sized signal-set word. If the
/// selected signal has a handler, its action must satisfy
/// [`rt_sigaction_raw`]'s x86-64 restorer contract.
#[inline]
pub unsafe fn rt_sigsuspend_raw(set: *const u64) -> Result<()> {
    // SAFETY: The caller owns the kernel signal-set input storage.
    decode(unsafe { syscall2(SYS_RT_SIGSUSPEND, set as usize, KERNEL_SIGSET_SIZE) }).map(|_| ())
}

/// Waits for one signal in `set` and returns its signal number.
///
/// # Safety
///
/// `set` must point to one readable kernel-sized signal-set word. `info` must
/// be null or point to writable 128-byte Linux `siginfo_t` storage. `timeout`
/// must be null or point to one Linux/x86-64 `timespec` record.
#[inline]
pub unsafe fn rt_sigtimedwait_raw(
    set: *const u64,
    info: *mut SigInfo,
    timeout: *const u8,
) -> Result<i32> {
    // SAFETY: The caller owns every pointed-to kernel ABI record.
    decode_i32(unsafe {
        syscall4(
            SYS_RT_SIGTIMEDWAIT,
            set as usize,
            info as usize,
            timeout as usize,
            KERNEL_SIGSET_SIZE,
        )
    })
}

/// Queues the supplied Linux `siginfo_t` record to a process.
///
/// # Safety
///
/// `info` must point to a fully initialized Linux signal-information record
/// whose fields satisfy `rt_sigqueueinfo`'s ABI contract.
#[inline]
pub unsafe fn rt_sigqueueinfo_raw(pid: i32, signal: i32, info: *const SigInfo) -> Result<()> {
    // SAFETY: The caller owns the signal-info input record contract.
    decode(unsafe {
        syscall3(
            SYS_RT_SIGQUEUEINFO,
            pid as usize,
            signal as usize,
            info as usize,
        )
    })
    .map(|_| ())
}

/// Installs or queries an alternate signal stack.
///
/// # Safety
///
/// `stack` and `old_stack` must be null or point to valid Linux/x86-64
/// `stack_t` records. Any enabled stack memory must remain valid while the
/// kernel may dispatch a signal on it. A handler installed with `SA_ONSTACK`
/// still must satisfy [`rt_sigaction_raw`]'s restorer contract.
#[inline]
pub unsafe fn sigaltstack_raw(
    stack: *const SignalStack,
    old_stack: *mut SignalStack,
) -> Result<()> {
    // SAFETY: The caller owns both `stack_t` pointer contracts.
    decode(unsafe { syscall2(SYS_SIGALTSTACK, stack as usize, old_stack as usize) }).map(|_| ())
}

/// Creates or updates a Linux `signalfd4` descriptor.
///
/// # Safety
///
/// `mask` must point to one readable Linux kernel-sized signal-set word. When
/// `fd` is non-negative it must designate an existing signalfd descriptor.
/// `flags` uses Linux's `SFD_*` bit representation.
#[inline]
pub unsafe fn signalfd4_raw(fd: i32, mask: *const u64, flags: u32) -> Result<i32> {
    // SAFETY: The caller owns the mask pointer and descriptor contracts.
    decode_i32(unsafe {
        syscall4(
            SYS_SIGNALFD4,
            fd as usize,
            mask as usize,
            KERNEL_SIGSET_SIZE,
            flags as usize,
        )
    })
}

#[cfg(test)]
mod tests {
    use core::arch::global_asm;
    use core::mem::{align_of, offset_of, size_of};
    use core::sync::atomic::{AtomicI32, Ordering};

    use super::{KERNEL_SIGSET_SIZE, KernelSigAction, SA_RESTORER, SigInfo, SignalStack, rt_sigaction_raw, rt_sigprocmask_raw};

    const SIGUSR1: i32 = 10;
    const SIG_UNBLOCK: i32 = 1;
    const SIG_SETMASK: i32 = 2;
    const SIGUSR1_MASK: u64 = 1 << (SIGUSR1 - 1);
    const SYS_RT_SIGRETURN: usize = 15;

    static DELIVERED_SIGNAL: AtomicI32 = AtomicI32::new(0);

    // This test-only, uniquely named trampoline is the x86-64 Linux ABI
    // sequence in musl's arch/x86_64 signal restore object: syscall 15 does
    // not return normally; it asks the kernel to restore the signal frame.
    // It is intentionally not exported by crabc-core production code, which
    // has no right to choose the libc/facade runtime owner's restorer.
    global_asm!(
        ".global crabc_core_x86_64_signal_test_restorer",
        ".type crabc_core_x86_64_signal_test_restorer, @function",
        "crabc_core_x86_64_signal_test_restorer:",
        "mov rax, 15",
        "syscall",
        ".size crabc_core_x86_64_signal_test_restorer, .-crabc_core_x86_64_signal_test_restorer",
    );

    unsafe extern "C" {
        fn crabc_core_x86_64_signal_test_restorer();
    }

    extern "C" fn record_sigusr1(signal: i32) {
        // Atomic stores are lock-free on x86-64 and do not require libc or
        // allocation. The handler does not call any Rust or C runtime API.
        DELIVERED_SIGNAL.store(signal, Ordering::Relaxed);
    }

    struct RestoreMask(u64);

    impl Drop for RestoreMask {
        fn drop(&mut self) {
            // SAFETY: The saved mask is one initialized kernel-sized word.
            let _ = unsafe { rt_sigprocmask_raw(SIG_SETMASK, &self.0, core::ptr::null_mut()) };
        }
    }

    struct RestoreAction(KernelSigAction);

    impl Drop for RestoreAction {
        fn drop(&mut self) {
            // SAFETY: This exact compact action was returned by the kernel
            // and remains valid plain data for the replacement syscall.
            let _ = unsafe {
                rt_sigaction_raw(SIGUSR1, &self.0, core::ptr::null_mut())
            };
        }
    }

    #[test]
    fn x86_64_rt_sigaction_uses_the_kernel_record_and_sa_restorer_frame() {
        assert_eq!(KERNEL_SIGSET_SIZE, 8);
        assert_eq!(size_of::<KernelSigAction>(), 32);
        assert_eq!(align_of::<KernelSigAction>(), 8);
        assert_eq!(offset_of!(KernelSigAction, handler), 0);
        assert_eq!(offset_of!(KernelSigAction, flags), 8);
        assert_eq!(offset_of!(KernelSigAction, restorer), 16);
        assert_eq!(offset_of!(KernelSigAction, mask), 24);
        assert_eq!(size_of::<SigInfo>(), 128);
        assert_eq!(align_of::<SigInfo>(), 8);
        assert_eq!(size_of::<SignalStack>(), 24);
        assert_eq!(align_of::<SignalStack>(), 8);
        assert_eq!(offset_of!(SignalStack, sp), 0);
        assert_eq!(offset_of!(SignalStack, flags), 8);
        assert_eq!(offset_of!(SignalStack, size), 16);

        let mut previous_mask = 0u64;
        // SAFETY: The selected one-bit mask and previous-mask output are live
        // kernel-sized words. Saving then unblocking SIGUSR1 makes delivery
        // independent of a harness-inherited block while `RestoreMask` puts
        // the precise former thread mask back before the test returns.
        unsafe {
            rt_sigprocmask_raw(SIG_UNBLOCK, &SIGUSR1_MASK, &mut previous_mask)
                .expect("unblock test signal through the raw kernel ABI");
        }
        let _restore_mask = RestoreMask(previous_mask);

        let mut previous_action = KernelSigAction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        // SAFETY: The null action queries SIGUSR1 into the initialized compact
        // kernel record; no libc signal API is called.
        unsafe {
            rt_sigaction_raw(SIGUSR1, core::ptr::null(), &mut previous_action)
                .expect("query SIGUSR1 through rt_sigaction");
        }

        let action = KernelSigAction {
            handler: record_sigusr1 as *const () as usize,
            flags: SA_RESTORER,
            restorer: crabc_core_x86_64_signal_test_restorer as *const () as usize,
            mask: 0,
        };
        // SAFETY: The handler is a non-allocating C-ABI atomic store, and the
        // uniquely named restorer executes only x86-64 `rt_sigreturn`. Both
        // code addresses stay live for this test; `RestoreAction` reinstalls
        // the exact prior kernel action before either address can disappear.
        unsafe {
            rt_sigaction_raw(SIGUSR1, &action, core::ptr::null_mut())
                .expect("install x86-64 handler action");
        }
        let _restore_action = RestoreAction(previous_action);

        let mut observed = KernelSigAction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        // SAFETY: The null action queries the exact kernel compact record.
        unsafe {
            rt_sigaction_raw(SIGUSR1, core::ptr::null(), &mut observed)
                .expect("query installed x86-64 handler action");
        }
        assert_eq!(observed.handler, action.handler);
        assert_eq!(observed.flags & SA_RESTORER, SA_RESTORER);
        assert_eq!(observed.restorer, action.restorer);
        assert_eq!(observed.mask, 0);

        DELIVERED_SIGNAL.store(0, Ordering::Relaxed);
        crate::process::tgkill(crate::process::getpid(), crate::thread::gettid(), SIGUSR1)
            .expect("deliver SIGUSR1 to this exact test thread");
        // `tgkill` returns to user code only after the selected current-thread
        // handler and its rt_sigreturn trampoline have completed. Observing
        // this store proves the x86 handler entry and signal-frame return, not
        // only that the kernel accepted the record shape.
        assert_eq!(DELIVERED_SIGNAL.load(Ordering::Relaxed), SIGUSR1);
        assert_eq!(SYS_RT_SIGRETURN, 15);
    }
}
