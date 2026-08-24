//! Stateless Linux/AArch64 thread operations.

use crate::Result;
use crate::syscall::{decode, syscall0, syscall2, syscall3, syscall6, SYS_FUTEX, SYS_GETCPU, SYS_GETTID, SYS_SCHED_GETAFFINITY, SYS_SCHED_RR_GET_INTERVAL, SYS_SCHED_SETAFFINITY, SYS_SCHED_YIELD, SYS_SETRESGID, SYS_SETRESUID};
use core::{arch::asm, mem::MaybeUninit};

/// `FUTEX_WAIT`, waiting while the futex word still equals `expected`.
pub const FUTEX_WAIT: u32 = 0;
/// `FUTEX_WAKE`, waking up to the requested number of waiters.
pub const FUTEX_WAKE: u32 = 1;
/// Use process-private futex hashing. Process-shared objects omit this bit.
pub const FUTEX_PRIVATE_FLAG: u32 = 128;

/// Performs a raw Linux futex operation.
///
/// This is the stateless kernel seam used by native Rust synchronization
/// objects and by the C facade. The timeout pointer, when non-null, must
/// point to a Linux/AArch64 `struct timespec`; for `FUTEX_WAIT` it is a
/// relative timeout.
///
/// # Safety
///
/// `address` must be a valid, four-byte-aligned futex word readable for
/// the duration of the syscall. `timeout` must be null or point to a
/// readable Linux/AArch64 timespec. `operation` must be a supported
/// futex operation plus any valid futex flags.
#[inline]
pub unsafe fn futex_raw(
    address: *const u32,
    operation: u32,
    expected: u32,
    timeout: *const u8,
    secondary: *const u32,
    value3: u32,
) -> Result<usize> {
    // SAFETY: The caller owns the futex word and optional timeout memory
    // contracts; all remaining arguments are immediate kernel values.
    decode(unsafe {
        syscall6(
            SYS_FUTEX,
            address as usize,
            operation as usize,
            expected as usize,
            timeout as usize,
            secondary as usize,
            value3 as usize,
        )
    })
}

/// Waits while `address` still contains `expected`.
///
/// `timeout` is a nullable pointer to a relative Linux/AArch64 timespec.
/// `private` selects `FUTEX_PRIVATE_FLAG`; set it to false for a
/// process-shared synchronization object.
///
/// # Safety
///
/// The futex word and optional timeout must satisfy the contracts of
/// [`futex_raw`].
#[inline]
pub unsafe fn futex_wait(
    address: *const u32,
    expected: u32,
    private: bool,
    timeout: *const u8,
) -> Result<()> {
    let operation = FUTEX_WAIT | if private { FUTEX_PRIVATE_FLAG } else { 0 };
    // SAFETY: The caller supplied the futex and timeout contracts.
    unsafe { futex_raw(address, operation, expected, timeout, core::ptr::null(), 0) }
        .map(|_| ())
}

/// Wakes up to `count` waiters sleeping on `address`.
///
/// Set `private` to false for a process-shared synchronization object.
/// The returned count is the number of waiters woken by the kernel.
///
/// # Safety
///
/// `address` must be a valid, four-byte-aligned futex word readable for
/// the duration of the syscall.
#[inline]
pub unsafe fn futex_wake(address: *const u32, count: u32, private: bool) -> Result<usize> {
    let operation = FUTEX_WAKE | if private { FUTEX_PRIVATE_FLAG } else { 0 };
    // SAFETY: The caller supplied the futex-word contract.
    unsafe {
        futex_raw(
            address,
            operation,
            count,
            core::ptr::null(),
            core::ptr::null(),
            0,
        )
    }
}

/// Returns the caller's Linux thread ID.
#[inline]
pub fn gettid() -> i32 {
    // Linux guarantees a positive ID for a running task.
    unsafe { syscall0(SYS_GETTID) as i32 }
}

/// Reads the calling thread's AArch64 `TPIDR_EL0` value as an opaque identity.
///
/// This is the architectural thread-pointer register installed by the Linux
/// thread runtime; it is intentionally distinct from the kernel task ID
/// returned by [`gettid`]. The value is not dereferenced or retained here.
/// Callers must treat it only as an opaque same-thread identity and must not
/// assume it is a stable process-wide identifier across thread exit or TLS
/// runtime transitions. A zero value remains representable during the earliest
/// runtime setup before a thread pointer is installed.
#[inline]
pub fn thread_pointer_identity() -> usize {
    let thread_pointer: usize;
    // SAFETY: `TPIDR_EL0` is readable at Linux/AArch64 EL0. This instruction
    // only snapshots the calling thread's register and touches no memory.
    unsafe {
        asm!(
            "mrs {thread_pointer}, tpidr_el0",
            thread_pointer = out(reg) thread_pointer,
            options(nomem, nostack, preserves_flags),
        );
    }
    thread_pointer
}

/// Sets the calling task's real, effective, and saved user IDs through
/// Linux's native `setresuid` syscall.
///
/// The Linux all-ones word (`u32::MAX`) means “leave this ID unchanged.”
/// This raw seam accepts that kernel ABI word directly; the typed native
/// facade owns the `Option<Uid>` conversion and rejects an explicit typed
/// all-ones value before reaching this syscall.
#[inline]
pub fn setresuid_raw(ruid: u32, euid: u32, suid: u32) -> Result<()> {
    // SAFETY: All arguments are immediate Linux uid_t words. Linux
    // applies the credential change to the calling kernel task only.
    decode(unsafe { syscall3(SYS_SETRESUID, ruid as usize, euid as usize, suid as usize) })
        .map(|_| ())
}

/// Sets the calling task's real, effective, and saved group IDs through
/// Linux's native `setresgid` syscall.
///
/// The Linux all-ones word (`u32::MAX`) means “leave this ID unchanged.”
/// This raw seam accepts that kernel ABI word directly; the typed native
/// facade owns the `Option<Gid>` conversion and rejects an explicit typed
/// all-ones value before reaching this syscall.
#[inline]
pub fn setresgid_raw(rgid: u32, egid: u32, sgid: u32) -> Result<()> {
    // SAFETY: All arguments are immediate Linux gid_t words. Linux
    // applies the credential change to the calling kernel task only.
    decode(unsafe { syscall3(SYS_SETRESGID, rgid as usize, egid as usize, sgid as usize) })
        .map(|_| ())
}

/// The CPU and NUMA-node observation returned by Linux `getcpu`.
///
/// These are separate kernel outputs: `cpu` identifies the CPU currently
/// executing the call and `numa_node` identifies its NUMA node. The task may
/// migrate immediately after the syscall, so this is an observation rather
/// than an affinity or placement guarantee.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CpuAndNumaNode {
    /// Linux CPU identifier at the `getcpu` observation point.
    pub cpu: u32,
    /// Linux NUMA-node identifier at the same observation point.
    pub numa_node: u32,
}

/// Observes the Linux CPU and NUMA node of the calling thread.
///
/// Linux/AArch64 `getcpu` writes both `u32` outputs into private stack
/// storage for the complete syscall. The cache argument is null because this
/// direct seam intentionally exposes only the stable CPU/node output pair;
/// it owns no NUMA topology discovery, CPU policy, or fallback. A valid pair
/// of owned outputs makes `EFAULT` unreachable, but any other kernel error is
/// preserved for callers that need that direct result.
#[inline]
pub fn getcpu() -> Result<CpuAndNumaNode> {
    let mut cpu = MaybeUninit::<u32>::uninit();
    let mut numa_node = MaybeUninit::<u32>::uninit();
    // SAFETY: Both pointers address live, writable `u32` output storage for
    // the syscall; the null cache pointer requests no cache observation.
    decode(unsafe {
        syscall3(
            SYS_GETCPU,
            cpu.as_mut_ptr() as usize,
            numa_node.as_mut_ptr() as usize,
            core::ptr::null::<u8>() as usize,
        )
    })?;
    // SAFETY: A successful Linux getcpu syscall initializes both requested
    // output words before returning.
    Ok(CpuAndNumaNode {
        cpu: unsafe { cpu.assume_init() },
        numa_node: unsafe { numa_node.assume_init() },
    })
}

/// Returns the Linux CPU on which the calling thread is currently running.
///
/// This retained CPU-only view follows Rustix's infallible `sched_getcpu`
/// contract while delegating to [`getcpu`], so the NUMA-node output is no
/// longer discarded at the kernel boundary. Linux can report `EFAULT` only
/// for invalid output pointers, which this function's private storage rules
/// out.
#[inline]
pub fn sched_getcpu() -> usize {
    match getcpu() {
        Ok(location) => location.cpu as usize,
        Err(_) => {
            // The documented failure requires an invalid output pointer;
            // this function owns valid stack storage, so do not fabricate
            // a CPU number or expose a C-style error channel here.
            panic!("Linux getcpu syscall failed")
        }
    }
}

/// Reads a Linux task's round-robin scheduling interval.
///
/// This is the raw kernel seam for `sched_rr_get_interval`; the native
/// facade owns the output storage and validates the returned timespec.
/// Linux PID zero selects the calling task.
///
/// # Safety
///
/// `interval` must point to writable Linux/AArch64 `struct timespec`
/// storage for the duration of the syscall.
#[inline]
pub unsafe fn sched_rr_get_interval_raw(pid: i32, interval: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies writable timespec storage; `pid` and
    // the pointer are immediate Linux syscall arguments.
    decode(unsafe { syscall2(SYS_SCHED_RR_GET_INTERVAL, pid as usize, interval as usize) })
        .map(|_| ())
}

/// Reads a Linux task's CPU-affinity mask.
///
/// The raw syscall returns the number of bytes written. The native facade
/// supplies the fixed target mask capacity and clears any unwritten tail.
/// Linux reports `EINVAL` when that capacity is smaller than the kernel's
/// affinity mask; this seam preserves that error unchanged.
///
/// # Safety
///
/// `mask` must point to writable storage for `size` bytes for the duration
/// of the syscall. Linux PID zero selects the calling task.
#[inline]
pub unsafe fn sched_getaffinity_raw(pid: i32, mask: *mut u8, size: usize) -> Result<usize> {
    // SAFETY: The caller supplies writable mask storage for `size` bytes;
    // all three values are immediate Linux syscall arguments.
    decode(unsafe { syscall3(SYS_SCHED_GETAFFINITY, pid as usize, size, mask as usize) })
}

/// Sets a Linux task's CPU-affinity mask.
///
/// Linux may intersect the requested mask with CPUs present in the
/// system and CPUs permitted by the task's cpuset cgroup. An empty
/// resulting mask is reported by the kernel as `EINVAL`; this seam keeps
/// that error unchanged.
///
/// # Safety
///
/// `mask` must point to readable storage for `size` bytes for the
/// duration of the syscall. Linux PID zero selects the calling task.
#[inline]
pub unsafe fn sched_setaffinity_raw(pid: i32, mask: *const u8, size: usize) -> Result<()> {
    // SAFETY: The caller supplies readable mask storage for `size` bytes;
    // all three values are immediate Linux syscall arguments.
    decode(unsafe { syscall3(SYS_SCHED_SETAFFINITY, pid as usize, size, mask as usize) })
        .map(|_| ())
}

/// Yields the processor to the Linux scheduler.
#[inline]
pub fn sched_yield() -> Result<()> {
    // SAFETY: `sched_yield` has no user-memory arguments.
    decode(unsafe { syscall0(SYS_SCHED_YIELD) }).map(|_| ())
}
