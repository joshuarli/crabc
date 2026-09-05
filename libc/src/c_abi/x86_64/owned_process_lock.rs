//! Musl 1.2.6 process-creation/SIGABRT transaction lock (MIT), revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417. Sources: process/{_Fork,
//! posix_spawn}.c, exit/abort.c, signal/sigaction.c. The lock protects transient
//! abort disposition and spawn's error-pipe lifetime against concurrent fork.
//! It reuses the owned runtime's allocation-free 0/1 private-futex mutex shape.
//! Every acquiring path blocks signals first; no user callback runs held.

use core::sync::atomic::{AtomicI32, Ordering};
use super::raw_syscall as sys;
static LOCK: AtomicI32 = AtomicI32::new(0);

pub(super) struct ProcessGuard;
impl ProcessGuard {
    /// # Safety
    /// All signals are blocked in this task. Caller holds the outer internal
    /// locks required by its process transaction and will not call user code.
    pub(super) unsafe fn acquire_blocked() -> Self {
        while LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            unsafe { sys::syscall4(202, LOCK.as_ptr() as i64, 128, 1, 0); }
        }
        Self
    }
}
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        LOCK.store(0, Ordering::Release);
        unsafe { sys::syscall3(202, LOCK.as_ptr() as i64, 129, 1); }
    }
}

/// SIGABRT sigaction's scoped block/lock/update/unlock/restore transaction.
pub(super) struct SignalGuard { guard: Option<ProcessGuard>, saved: u64 }
impl SignalGuard {
    pub(super) unsafe fn acquire() -> Result<Self, i32> {
        let mut saved = 0;
        let result = unsafe { sys::syscall4(14, 0, &u64::MAX as *const u64 as i64,
            &mut saved as *mut u64 as i64, 8) };
        // A denied mask operation cannot satisfy the lock's async-signal
        // invariant. Fail before acquiring or changing a disposition.
        if result < 0 { return Err(-result as i32); }
        Ok(Self { guard: Some(unsafe { ProcessGuard::acquire_blocked() }), saved })
    }
}
impl Drop for SignalGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        unsafe { sys::syscall4(14, 2, &self.saved as *const u64 as i64, 0, 8); }
    }
}

/// Acquire musl _Fork's inner lock after all signals are blocked.
/// # Safety
/// Caller has completed its outer fork preparation and blocks every signal.
/// Exactly one original-parent/error or sole-child completion follows raw fork.
pub(super) unsafe fn pthread_fork_prepare() {
    core::mem::forget(unsafe { ProcessGuard::acquire_blocked() });
}
/// Release the matching inner lock in the original parent, including failure.
/// # Safety
/// This completes that process's unmatched pthread_fork_prepare once.
pub(super) unsafe fn pthread_fork_parent() { drop(ProcessGuard); }
/// Reset the inherited lock in a sole-thread fork child.
/// # Safety
/// Called once after a prepared fork, before restoring signals or user child
/// callbacks. Never call from a CLONE_VM spawn child.
pub(super) unsafe fn pthread_fork_child() { LOCK.store(0, Ordering::Relaxed); }
