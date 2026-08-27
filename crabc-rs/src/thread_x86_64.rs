//! Narrow Linux/x86-64 thread observations and scheduler operations.
//!
//! This target-specific slice preserves the three record-independent thread
//! operations admitted by the AArch64 facade: the calling task ID, the
//! currently observed CPU, a scheduler yield, and a read-only round-robin
//! interval query. Affinity masks, futex wrappers, and credential transitions
//! remain outside this module until their x86-64 contracts have independent
//! evidence.

use core::mem::MaybeUninit;
use core::time::Duration;

use crate::process::Pid;
use crate::{Errno, Result};

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

/// Reads a Linux task's round-robin scheduling interval.
///
/// `None` selects the calling task; `Some(pid)` selects the Linux task ID.
/// The direct syscall writes an x86-64 16-byte `timespec`, which this facade
/// validates before converting to Rust's canonical [`Duration`]. This
/// operation only observes scheduler state: it does not select a policy or
/// mutate a task.
#[inline]
pub fn sched_rr_get_interval(pid: Option<Pid>) -> Result<Duration> {
    let mut interval = MaybeUninit::<crate::time::Timespec>::uninit();
    // SAFETY: `interval` is private writable storage with the exact
    // Linux/x86-64 timespec layout, and Linux initializes it on success.
    unsafe {
        crabc_core::thread::sched_rr_get_interval_raw(
            pid.map_or(0, Pid::as_raw_pid),
            interval.as_mut_ptr().cast(),
        )?;
    }
    // SAFETY: A successful syscall initialized the complete timespec.
    let interval = unsafe { interval.assume_init() };
    if interval.tv_sec < 0 || !(0..1_000_000_000).contains(&interval.tv_nsec) {
        return Err(Errno::RANGE);
    }
    Ok(Duration::new(
        interval.tv_sec as u64,
        interval.tv_nsec as u32,
    ))
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
