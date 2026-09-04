//! Owned-static Linux/x86-64 `abort` termination path.
//!
//! The behavioral oracle is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/exit/abort.c` first raises `SIGABRT`; if it returns because the signal
//! was blocked, ignored, or handled by a returning handler, it blocks signals,
//! installs `SIG_DFL`, sends the calling task `SIGABRT`, and unblocks that one
//! signal so the default abnormal termination occurs.
//!
//! Musl's full implementation serializes this with `__abort_lock`, backed by
//! `abort_lock.c`, `lock.c`, and private `struct pthread`/`__libc` state.  The
//! owned-static runtime intentionally has no concurrent sigaction policy or
//! that internal state owner.  This translation preserves the observable
//! default/blocked/ignored/returning-handler termination sequence with raw
//! Linux 5.10 syscalls and the existing selected `raise` boundary, without
//! importing fake lock or `__libc` baggage merely to satisfy archive linkage.
//!
//! Concurrent disposition mutation remains outside this narrow static runtime
//! contract.  The direct final `SIGKILL` and `_Exit(127)` paths are defensive
//! only: after a successful default `SIGABRT` delivery they are unreachable.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("owned static abort support requires little-endian Linux/x86-64");

use core::ffi::c_int;

use super::{immediate_termination, raw_syscall, signal_execution};

const SIG_BLOCK: i64 = 0;
const SIG_UNBLOCK: i64 = 1;
const SIGABRT: c_int = 6;
const SIGKILL: c_int = 9;
const KERNEL_SIGSET_SIZE: i64 = core::mem::size_of::<u64>() as i64;

/// Linux x86-64's compact `rt_sigaction` input record.
///
/// Its all-zero instance is exactly the `SIG_DFL` record that musl installs
/// after its private abort lock is held.  No restorer is required for a
/// default disposition.
#[repr(C)]
struct KernelSigAction {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: u64,
}

const _: [(); 32] = [(); core::mem::size_of::<KernelSigAction>()];
const _: [(); 8] = [(); core::mem::align_of::<KernelSigAction>()];

/// Terminate abnormally through `SIGABRT` and never return.
///
/// The first `raise` provides normal C signal semantics.  If it returns, the
/// caller's SIGABRT disposition cannot remain ignored, blocked, or returning:
/// the second raw delivery is made only after default disposition installation
/// and unblocking SIGABRT.  This function makes no allocation, lock, or TCB
/// ownership claim.
#[no_mangle]
pub extern "C" fn abort() -> ! {
    // The selected signal-execution owner performs musl's protected initial
    // delivery.  A default action normally makes this call non-returning.
    let _ = signal_execution::raise(SIGABRT);

    let all_signals = u64::MAX;
    // SAFETY: these are complete local one-word Linux signal-mask records;
    // Linux x86's rt_sigprocmask consumes exactly eight mask bytes.
    unsafe {
        let _ = raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            SIG_BLOCK,
            (&all_signals as *const u64) as usize as i64,
            0,
            KERNEL_SIGSET_SIZE,
        );
    }

    let default_action = KernelSigAction {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    // SAFETY: Linux reads one complete all-zero default-action record and no
    // output record.  This direct private transition intentionally does not
    // expose or depend on musl's abort-lock bookkeeping.
    unsafe {
        let _ = raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGACTION,
            i64::from(SIGABRT),
            (&default_action as *const KernelSigAction) as usize as i64,
            0,
            KERNEL_SIGSET_SIZE,
        );
    }

    // SAFETY: gettid has no arguments; tkill receives that current task ID
    // and the scalar SIGABRT value, matching the pinned abort path's target.
    let thread_id = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    unsafe {
        let _ = raw_syscall::syscall2(
            raw_syscall::SYS_TKILL,
            thread_id,
            i64::from(SIGABRT),
        );
    }

    let abort_mask = 1_u64 << (SIGABRT - 1);
    // SAFETY: unblocking this exact kernel-visible bit delivers the pending
    // default SIGABRT.  It should not return in a valid process.
    unsafe {
        let _ = raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            SIG_UNBLOCK,
            (&abort_mask as *const u64) as usize as i64,
            0,
            KERNEL_SIGSET_SIZE,
        );
    }

    // The raw default delivery above is terminal.  Retain musl's defensive
    // no-return intent if an invalid execution environment nevertheless lets
    // it return, without allocating or consulting a private runtime lock.
    let process_id = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETPID) };
    unsafe {
        let _ = raw_syscall::syscall2(
            raw_syscall::SYS_KILL,
            process_id,
            i64::from(SIGKILL),
        );
    }
    immediate_termination::_Exit(127)
}
