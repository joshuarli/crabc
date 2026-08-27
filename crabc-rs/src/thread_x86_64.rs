//! Narrow Linux/x86-64 thread observations and scheduler operations.
//!
//! This target-specific slice preserves record-independent thread operations
//! plus bounded CPU-affinity observation and mutation. Futex wrappers and
//! credential transitions remain outside this module until their x86-64
//! contracts have independent evidence.

use core::mem::MaybeUninit;
use core::time::Duration;

use crate::process::Pid;
use crate::{Errno, Result};

/// A bounded Linux CPU-affinity mask.
///
/// The fixed 1024-bit capacity is the native x86-64 facade boundary. Local
/// bit operations affect only this value. Applying a set to a task is a
/// separate, explicit scheduling mutation through [`sched_setaffinity`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CpuSet([u64; 16]);

impl CpuSet {
    /// The largest CPU identifier representable by this fixed mask plus one.
    pub const MAX_CPU: usize = 1024;

    /// Creates an empty CPU set.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self([0; 16])
    }

    /// Returns whether `cpu` is present in this affinity mask.
    ///
    /// # Panics
    ///
    /// Panics when `cpu` is outside [`Self::MAX_CPU`].
    #[inline]
    pub fn is_set(&self, cpu: usize) -> bool {
        (self.0[cpu / 64] & (1u64 << (cpu % 64))) != 0
    }

    /// Adds `cpu` to this local affinity mask.
    ///
    /// # Panics
    ///
    /// Panics when `cpu` is outside [`Self::MAX_CPU`].
    #[inline]
    pub fn set(&mut self, cpu: usize) {
        self.0[cpu / 64] |= 1u64 << (cpu % 64);
    }

    /// Removes `cpu` from this local affinity mask.
    ///
    /// # Panics
    ///
    /// Panics when `cpu` is outside [`Self::MAX_CPU`].
    #[inline]
    pub fn unset(&mut self, cpu: usize) {
        self.0[cpu / 64] &= !(1u64 << (cpu % 64));
    }

    /// Counts the CPUs present in this affinity mask.
    #[inline]
    pub fn count(&self) -> u32 {
        self.0.iter().map(|word| word.count_ones()).sum()
    }

    /// Returns whether the mask contains no CPUs.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    /// Clears every CPU from this local affinity mask.
    #[inline]
    pub fn clear(&mut self) {
        self.0 = [0; 16];
    }
}

impl Default for CpuSet {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

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

/// Reads a Linux task's CPU-affinity mask.
///
/// `None` selects the calling task; `Some(pid)` selects the Linux task ID.
/// Linux may write fewer bytes than this fixed 1024-bit capacity; the
/// unwritten suffix is cleared before exposure. A kernel mask larger than
/// this boundary is reported as `EINVAL`.
#[inline]
pub fn sched_getaffinity(pid: Option<Pid>) -> Result<CpuSet> {
    let mut mask = CpuSet::new();
    let size = core::mem::size_of_val(&mask.0);
    // SAFETY: `mask` is initialized writable storage for exactly `size` bytes.
    let written = unsafe {
        crabc_core::thread::sched_getaffinity_raw(
            pid.map_or(0, Pid::as_raw_pid),
            mask.0.as_mut_ptr().cast(),
            size,
        )?
    };
    if written > size {
        return Err(Errno::RANGE);
    }
    if written < size {
        // SAFETY: `written <= size`, so the tail is within `mask`.
        unsafe {
            core::ptr::write_bytes(
                mask.0.as_mut_ptr().cast::<u8>().add(written),
                0,
                size - written,
            );
        }
    }
    Ok(mask)
}

/// Sets a Linux task's CPU-affinity mask.
///
/// `None` selects the calling task; `Some(pid)` selects the Linux task ID.
/// Linux may intersect the requested mask with CPUs present in the system and
/// CPUs permitted by the task's cpuset cgroup. An empty resulting mask is
/// reported as [`crate::Errno::INVAL`]. This fixed 1024-bit boundary is passed
/// to Linux as 128 bytes, so a kernel requiring a larger affinity-mask
/// capacity also reports [`crate::Errno::INVAL`]. This operation is an explicit
/// process-scheduling mutation and does not call libc or inspect thread-local
/// `errno`.
#[inline]
pub fn sched_setaffinity(pid: Option<Pid>, cpuset: &CpuSet) -> Result<()> {
    let size = core::mem::size_of_val(&cpuset.0);
    // SAFETY: `cpuset` owns readable storage for exactly `size` bytes.
    unsafe {
        crabc_core::thread::sched_setaffinity_raw(
            pid.map_or(0, Pid::as_raw_pid),
            cpuset.0.as_ptr().cast(),
            size,
        )
    }
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
