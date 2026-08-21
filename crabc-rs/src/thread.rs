//! Thread-associated Linux kernel operations.

use crate::process::Pid;

/// Returns the caller's Linux task ID.
#[inline]
#[must_use]
pub fn gettid() -> Pid {
    // SAFETY: Linux returns a positive task ID for a running task.
    unsafe { Pid::from_raw_unchecked(crabc_core::thread::gettid()) }
}

/// Yields the processor to the Linux scheduler.
///
/// Linux treats this operation as infallible. The direct core seam retains the
/// error type so future kernel behavior does not need a public API break.
#[inline]
pub fn sched_yield() {
    let _ = crabc_core::thread::sched_yield();
}
