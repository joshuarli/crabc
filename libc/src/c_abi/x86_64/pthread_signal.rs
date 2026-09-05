//! Owned pthread signal delivery and requester-mask transaction.
//!
//! Pinned musl 1.2.6 commit 9fa28ece75d8a2191de7c5bb53bed224c5947417
//! (MIT), src/thread/pthread_kill.c: block all signals, lock the target's
//! kill lock, deliver only while its Linux TID is live, unlock, restore the
//! requester mask. This includes internal signals so asynchronous cancellation
//! cannot abandon a target mapping lease or kill lock.
//!
//! The existing lifecycle owner pins the target mapping and excludes TID
//! retirement. tgkill names both the owned process and the leased TID; for
//! these process-local handles its result and SI_TKILL delivery match musl's
//! tkill. A retired joinable target accepts valid signals without a syscall.

use core::ffi::{c_int, c_void};
use super::{pthread_create_join, raw_syscall};

const EINVAL: c_int = 22;

/// Own the calling thread's complete kernel mask until a signal transaction
/// has released every lock and mapping lease. Restoring can immediately
/// deliver pending application signals or asynchronous cancellation.
pub(super) struct AllSignals(u64);

impl AllSignals {
    pub(super) unsafe fn block() -> Result<Self, c_int> {
        let all = u64::MAX;
        let mut previous = 0;
        let result = unsafe { raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK, 0, (&all as *const u64) as i64,
            (&mut previous as *mut u64) as i64, 8,
        ) };
        if result < 0 { Err((-result) as c_int) } else { Ok(Self(previous)) }
    }
}

impl Drop for AllSignals {
    fn drop(&mut self) {
        unsafe { raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK, 2, (&self.0 as *const u64) as i64, 0, 8,
        ); }
    }
}

/// Deliver a signal to an owned pthread or C11 thread, preserving caller errno.
/// Signal zero checks the target without delivering a signal.
///
/// # Safety
/// `thread` must identify a thread in this process whose handle is still valid:
/// it has not been joined, and a detached thread has not completed. A completed
/// joinable thread remains valid until joined. The caller owns the effects of
/// delivering `signal` under the process's current signal dispositions.
#[no_mangle]
pub unsafe extern "C" fn pthread_kill(thread: *mut c_void, signal: c_int) -> c_int {
    // The lifecycle callback is skipped for a retired thread, so preserve
    // musl's invalid-signal result before entering either live/retired branch.
    if signal as u32 >= 65 { return EINVAL; }
    let mask = match unsafe { AllSignals::block() } {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    let result = unsafe {
        pthread_create_join::with_selected_pthread_signal_target(thread, |tgid, tid, _| {
            -raw_syscall::syscall3(
                raw_syscall::SYS_TGKILL, i64::from(tgid), i64::from(tid), i64::from(signal),
            ) as c_int
        })
    }.unwrap_or(EINVAL);
    drop(mask);
    result
}
