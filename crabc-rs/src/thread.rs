//! Thread-associated Linux kernel operations.

use core::mem::MaybeUninit;
use core::time::Duration;

use bitflags::bitflags;

use crate::process::Pid;
pub use crate::process::{Gid, Uid};
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
/// This follows Rustix's infallible `thread::sched_getcpu` contract. The
/// implementation uses Linux's direct `getcpu` syscall with private writable
/// output storage; it does not call libc or inspect thread-local `errno`.
#[inline]
#[must_use]
pub fn sched_getcpu() -> usize {
    crabc_core::thread::sched_getcpu()
}

/// Sets the calling thread's real, effective, and saved user IDs.
///
/// This follows Rustix's `thread::set_thread_res_uid` shape while retaining
/// Linux's actual credential scope: the raw syscall changes only the calling
/// kernel task. It does not synchronize the change across the other threads
/// of a process, and it must not be used as a process-wide credential API.
/// `None` requests Linux's all-ones no-change word. An explicit
/// `Some(Uid::from_raw(u32::MAX))` is rejected as [`crate::Errno::INVAL`] so
/// the typed value cannot silently acquire `None`'s sentinel meaning.
///
/// # Warning
///
/// This is deliberately the Linux kernel operation, not musl's synchronized
/// POSIX process credential transition. It affects only the calling task, so
/// callers must coordinate any code whose assumptions depend on credentials.
#[inline]
pub fn set_thread_res_uid<R, E, S>(ruid: R, euid: E, suid: S) -> Result<()>
where
    R: Into<Option<Uid>>,
    E: Into<Option<Uid>>,
    S: Into<Option<Uid>>,
{
    let ruid = checked_uid_word(ruid.into())?;
    let euid = checked_uid_word(euid.into())?;
    let suid = checked_uid_word(suid.into())?;
    crabc_core::thread::setresuid_raw(ruid, euid, suid)
}

/// Sets the calling thread's real, effective, and saved group IDs.
///
/// This follows Rustix's `thread::set_thread_res_gid` shape while retaining
/// Linux's actual credential scope: the raw syscall changes only the calling
/// kernel task. It does not synchronize the change across the other threads
/// of a process, and it must not be used as a process-wide credential API.
/// `None` requests Linux's all-ones no-change word. An explicit
/// `Some(Gid::from_raw(u32::MAX))` is rejected as [`crate::Errno::INVAL`] so
/// the typed value cannot silently acquire `None`'s sentinel meaning.
///
/// # Warning
///
/// This is deliberately the Linux kernel operation, not musl's synchronized
/// POSIX process credential transition. It affects only the calling task, so
/// callers must coordinate any code whose assumptions depend on credentials.
#[inline]
pub fn set_thread_res_gid<R, E, S>(rgid: R, egid: E, sgid: S) -> Result<()>
where
    R: Into<Option<Gid>>,
    E: Into<Option<Gid>>,
    S: Into<Option<Gid>>,
{
    let rgid = checked_gid_word(rgid.into())?;
    let egid = checked_gid_word(egid.into())?;
    let sgid = checked_gid_word(sgid.into())?;
    crabc_core::thread::setresgid_raw(rgid, egid, sgid)
}

#[inline]
fn checked_uid_word(uid: Option<Uid>) -> Result<u32> {
    match uid {
        Some(uid) if uid.as_raw() == u32::MAX => Err(Errno::INVAL),
        Some(uid) => Ok(uid.as_raw()),
        None => Ok(u32::MAX),
    }
}

#[inline]
fn checked_gid_word(gid: Option<Gid>) -> Result<u32> {
    match gid {
        Some(gid) if gid.as_raw() == u32::MAX => Err(Errno::INVAL),
        Some(gid) => Ok(gid.as_raw()),
        None => Ok(u32::MAX),
    }
}

/// A bounded Linux CPU-affinity mask.
///
/// The fixed 1024-bit capacity matches the pinned AArch64 Rustix shape. Its
/// local bit operations change only this value; affinity mutation remains a
/// separate process-scheduling operation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CpuSet([u64; 16]);

impl CpuSet {
    /// The largest CPU identifier representable by this fixed mask plus one.
    pub const MAX_CPU: usize = 1024;

    /// Creates an empty CPU set.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self([0; 16])
    }

    /// Returns whether `cpu` is present in this affinity mask.
    ///
    /// # Panics
    ///
    /// Panics when `cpu` is outside [`Self::MAX_CPU`], matching Rustix's
    /// fixed-mask boundary.
    #[inline]
    pub fn is_set(&self, cpu: usize) -> bool {
        (self.0[cpu / 64] & (1u64 << (cpu % 64))) != 0
    }

    /// Adds `cpu` to this local affinity mask.
    ///
    /// # Panics
    ///
    /// Panics when `cpu` is outside [`Self::MAX_CPU`], matching Rustix's
    /// fixed-mask boundary.
    #[inline]
    pub fn set(&mut self, cpu: usize) {
        self.0[cpu / 64] |= 1u64 << (cpu % 64);
    }

    /// Removes `cpu` from this local affinity mask.
    ///
    /// # Panics
    ///
    /// Panics when `cpu` is outside [`Self::MAX_CPU`], matching Rustix's
    /// fixed-mask boundary.
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

/// Reads a Linux task's CPU-affinity mask.
///
/// `None` selects the calling task; `Some(pid)` selects the Linux task ID.
/// The kernel mask is copied into a fixed 1024-bit native value. If the
/// kernel requires a larger mask, Linux returns `EINVAL`, which is preserved
/// rather than truncated or hidden behind allocation. Successful short writes
/// have their unwritten suffix cleared before the value is exposed.
#[inline]
pub fn sched_getaffinity(pid: Option<Pid>) -> Result<CpuSet> {
    let mut mask = CpuSet::new();
    let size = core::mem::size_of_val(&mask.0);
    // SAFETY: `mask` is initialized writable storage for exactly `size` bytes.
    let written = unsafe {
        crabc_core::thread::sched_getaffinity_raw(
            Pid::as_raw(pid),
            mask.0.as_mut_ptr().cast(),
            size,
        )?
    };
    if written > size {
        return Err(Errno::RANGE);
    }
    if written < size {
        // SAFETY: `written <= size` above, and the remainder lies within the
        // initialized mask storage returned by the kernel.
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
/// reported as [`crate::Errno::INVAL`]. This operation intentionally exposes
/// that process-scheduling mutation explicitly; it does not call libc or
/// inspect thread-local `errno`.
#[inline]
pub fn sched_setaffinity(pid: Option<Pid>, cpuset: &CpuSet) -> Result<()> {
    let size = core::mem::size_of_val(&cpuset.0);
    // SAFETY: `cpuset` owns readable storage for exactly `size` bytes.
    unsafe {
        crabc_core::thread::sched_setaffinity_raw(Pid::as_raw(pid), cpuset.0.as_ptr().cast(), size)
    }
}

/// Reads a Linux task's round-robin scheduling interval.
///
/// `None` selects the calling task; `Some(pid)` selects the Linux task ID.
/// The direct syscall writes an AArch64 `timespec`, which this facade validates
/// before converting to Rust's canonical [`Duration`]. This operation only
/// observes scheduler state: it does not select a policy or mutate a task.
#[inline]
pub fn sched_rr_get_interval(pid: Option<Pid>) -> Result<Duration> {
    let mut interval = MaybeUninit::<crate::time::Timespec>::uninit();
    // SAFETY: `interval` is private writable storage with the exact
    // Linux/AArch64 timespec layout, and Linux initializes it on success.
    unsafe {
        crabc_core::thread::sched_rr_get_interval_raw(
            Pid::as_raw(pid),
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
/// Linux treats this operation as infallible. The direct core seam retains the
/// error type so future kernel behavior does not need a public API break.
#[inline]
pub fn sched_yield() {
    let _ = crabc_core::thread::sched_yield();
}

/// Direct Linux futex operations.
///
/// This is the low-level building block used by synchronization primitives.
/// The futex word is borrowed as an [`AtomicU32`], which makes its four-byte
/// alignment and atomic storage contract explicit at the Rust boundary. The
/// caller must keep the atomic word alive and at the same address until the
/// syscall returns; Linux may inspect it again while a wait is queued.
pub mod futex {
    use super::*;

    // Keep the timeout spelling at the same module boundary as Rustix.  The
    // C-layout value remains defined once in `time`, rather than creating a
    // second futex-specific timespec record.
    pub use crate::time::{Nsecs, Secs, Timespec};

    bitflags! {
        #[repr(transparent)]
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        /// Linux futex operation flags.
        ///
        /// `PRIVATE` is appropriate for a futex used only by threads in this
        /// process. Omit it for a word shared between processes.
        pub struct Flags: u32 {
            /// `FUTEX_PRIVATE_FLAG`.
            const PRIVATE = 0x80;
            /// `FUTEX_CLOCK_REALTIME`.
            const CLOCK_REALTIME = 0x100;
            /// Preserve future Linux-defined bits for kernel validation.
            const _ = !0;
        }
    }

    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAKE: u32 = 1;

    /// Waits while `uaddr` still contains `val`.
    ///
    /// The timeout is a Linux/AArch64 `timespec` interpreted as a relative
    /// duration by `FUTEX_WAIT`; `None` waits indefinitely. Linux can return
    /// [`crate::Errno::AGAIN`] when the value changed before the wait was
    /// queued and [`crate::Errno::INTR`] when a signal interrupts the wait.
    /// Both are ordinary futex wakeup races and are intentionally preserved
    /// for the caller to handle.
    #[inline]
    pub fn wait(
        uaddr: &core::sync::atomic::AtomicU32,
        flags: Flags,
        val: u32,
        timeout: Option<&Timespec>,
    ) -> crate::Result<()> {
        let timeout = timeout
            .map(|value| (value as *const Timespec).cast::<u8>())
            .unwrap_or(core::ptr::null());
        // SAFETY: `AtomicU32` guarantees a four-byte-aligned atomic word and
        // the borrowed word plus optional C-layout timespec remain alive for
        // the entire syscall. Linux only reads these locations for FUTEX_WAIT.
        unsafe {
            crabc_core::thread::futex_raw(
                (uaddr as *const core::sync::atomic::AtomicU32).cast::<u32>(),
                FUTEX_WAIT | flags.bits(),
                val,
                timeout,
                core::ptr::null(),
                0,
            )
            .map(|_| ())
        }
    }

    /// Wakes up to `val` waiters queued on `uaddr`.
    ///
    /// The return value is the number of waiters actually woken. A successful
    /// call with no queued waiters returns `Ok(0)`. The atomic word must remain
    /// four-byte aligned and alive until the syscall returns.
    #[inline]
    pub fn wake(
        uaddr: &core::sync::atomic::AtomicU32,
        flags: Flags,
        val: u32,
    ) -> crate::Result<usize> {
        // SAFETY: `AtomicU32` guarantees a four-byte-aligned word which stays
        // alive for the syscall. FUTEX_WAKE does not dereference a timeout.
        unsafe {
            crabc_core::thread::futex_raw(
                (uaddr as *const core::sync::atomic::AtomicU32).cast::<u32>(),
                FUTEX_WAKE | flags.bits(),
                val,
                core::ptr::null(),
                core::ptr::null(),
                0,
            )
        }
    }
}
