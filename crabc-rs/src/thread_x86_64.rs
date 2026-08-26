//! Narrow Linux/x86-64 thread observations and scheduler operations.
//!
//! This target-specific slice preserves the three record-independent thread
//! operations admitted by the AArch64 facade: the calling task ID, the
//! currently observed CPU, and a scheduler yield.  Affinity masks,
//! round-robin intervals, futex wrappers, and credential transitions remain
//! outside this module until their x86-64 contracts have independent
//! evidence.

use crate::process::Pid;

/// Returns the caller's Linux task ID.
#[inline]
#[must_use]
pub fn gettid() -> Pid {
    // SAFETY: Linux returns a positive task ID for a running task.
    unsafe { Pid::from_raw_unchecked(crabc_core::thread::gettid()) }
}

/// Returns the CPU on which the calling thread is currently running.
///
/// This follows Rustix's infallible `thread::sched_getcpu` contract.  The
/// core seam uses Linux's direct `getcpu` syscall with private writable output
/// storage; it does not call libc or inspect thread-local `errno`.
#[inline]
#[must_use]
pub fn sched_getcpu() -> usize {
    crabc_core::thread::sched_getcpu()
}

/// Yields the processor to the Linux scheduler.
///
/// Linux treats this operation as infallible.  The direct core seam retains
/// its error type so future kernel behavior does not require a public API
/// break.
#[inline]
pub fn sched_yield() {
    let _ = crabc_core::thread::sched_yield();
}
