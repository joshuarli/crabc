//! Deliberately bounded Linux/x86-64 event-descriptor operations.
//!
//! This target-specific module owns the `poll(2)`, `ppoll(2)`, and epoll syscall
//! seams. The x86-64 records are kept separate from the AArch64 event module so
//! that a caller cannot accidentally pass an AArch64-owned record to an x86
//! syscall. These are native core operations only; choosing a public facade or
//! claiming x86-64 support remains outside this module.

use crate::syscall::{
    decode, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6, SYS_EPOLL_CREATE1,
    SYS_EPOLL_CTL, SYS_EPOLL_PWAIT, SYS_EVENTFD2, SYS_POLL, SYS_PPOLL, SYS_READ, SYS_WRITE,
};
use crate::{RawFd, Result};

/// The Linux/x86-64 `struct pollfd` record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct KernelPollFd {
    /// Descriptor being observed.
    pub fd: RawFd,
    /// Requested event bits.
    pub events: i16,
    /// Events reported by Linux.
    pub revents: i16,
}

const _: () = assert!(core::mem::size_of::<KernelPollFd>() == 8);
const _: () = assert!(core::mem::align_of::<KernelPollFd>() == 4);
const _: () = assert!(core::mem::offset_of!(KernelPollFd, fd) == 0);
const _: () = assert!(core::mem::offset_of!(KernelPollFd, events) == 4);
const _: () = assert!(core::mem::offset_of!(KernelPollFd, revents) == 6);

/// The packed Linux/x86-64 `struct epoll_event` kernel record.
///
/// x86-64 intentionally places the eight-byte data union at byte offset four;
/// this is not the naturally aligned 16-byte layout used by AArch64. Callers
/// reading a field from an array of these records must preserve the packed
/// record contract (for example, by copying the field value rather than
/// forming an unaligned reference).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct KernelEpollEvent {
    /// Readiness and behavior bits reported by or registered with Linux.
    pub events: u32,
    /// Caller-provided opaque event data.
    pub data: u64,
}

const _: () = assert!(core::mem::size_of::<KernelEpollEvent>() == 12);
const _: () = assert!(core::mem::align_of::<KernelEpollEvent>() == 1);
const _: () = assert!(core::mem::offset_of!(KernelEpollEvent, events) == 0);
const _: () = assert!(core::mem::offset_of!(KernelEpollEvent, data) == 4);

/// Creates a Linux eventfd counter without libc or TLS `errno`.
#[inline]
pub fn eventfd(initval: u32, flags: u32) -> Result<RawFd> {
    // SAFETY: Linux validates the scalar initial value and flag arguments.
    decode(unsafe { syscall2(SYS_EVENTFD2, initval as usize, flags as usize) })
        .map(|fd| fd as RawFd)
}

/// Reads one complete eight-byte Linux eventfd counter record.
#[inline]
pub fn eventfd_read(fd: RawFd) -> Result<u64> {
    let mut value = 0_u64;
    // SAFETY: `value` is aligned writable storage for one eventfd record.
    let count = decode(unsafe {
        syscall3(
            SYS_READ,
            fd as usize,
            (&mut value as *mut u64).cast::<u8>() as usize,
            core::mem::size_of::<u64>(),
        )
    })?;
    if count != core::mem::size_of::<u64>() {
        return Err(crate::Errno::IO);
    }
    Ok(value)
}

/// Writes one complete eight-byte Linux eventfd counter record.
#[inline]
pub fn eventfd_write(fd: RawFd, value: u64) -> Result<()> {
    // SAFETY: `value` is aligned readable storage for one eventfd record.
    let count = decode(unsafe {
        syscall3(
            SYS_WRITE,
            fd as usize,
            (&value as *const u64).cast::<u8>() as usize,
            core::mem::size_of::<u64>(),
        )
    })?;
    if count != core::mem::size_of::<u64>() {
        return Err(crate::Errno::IO);
    }
    Ok(())
}

/// Creates a Linux epoll descriptor without using libc or TLS `errno`.
#[inline]
pub fn epoll_create1(flags: u32) -> Result<RawFd> {
    // SAFETY: Linux validates the epoll flags; no user memory is accessed by
    // this operation.
    decode(unsafe { syscall1(SYS_EPOLL_CREATE1, flags as usize) }).map(|fd| fd as RawFd)
}

/// Adds, modifies, or removes a descriptor from an epoll interest list.
///
/// # Safety
///
/// For `EPOLL_CTL_ADD` and `EPOLL_CTL_MOD`, `event` must point to one
/// readable [`KernelEpollEvent`] that remains live for the syscall. For
/// `EPOLL_CTL_DEL`, `event` may be null as required by Linux. The descriptor
/// arguments are passed directly to the kernel for validation.
#[inline]
pub unsafe fn epoll_ctl_raw(
    epoll_fd: RawFd,
    operation: u32,
    source_fd: RawFd,
    event: *const KernelEpollEvent,
) -> Result<()> {
    // SAFETY: The caller owns the optional packed-event pointer contract;
    // Linux validates the operation and both descriptors.
    decode(unsafe {
        syscall4(
            SYS_EPOLL_CTL,
            epoll_fd as usize,
            operation as usize,
            source_fd as usize,
            event as usize,
        )
    })
    .map(|_| ())
}

/// Waits for epoll readiness with an optional Linux signal mask.
///
/// `timeout_ms` is Linux's signed millisecond representation: `-1` waits
/// indefinitely and zero performs a non-blocking query. `maxevents` is the
/// signed `int` width required by the x86-64 kernel ABI; typed callers should
/// validate their `usize` buffer length before converting it to `i32`.
///
/// # Safety
///
/// `events` must point to writable storage for `maxevents` consecutive
/// [`KernelEpollEvent`] records and remain live for the syscall. `sigmask`
/// must be null or point to a kernel-sized Linux signal mask of `sigsetsize`
/// bytes. The caller owns the pointed-to storage and ABI layout.
#[inline]
pub unsafe fn epoll_pwait_raw(
    epoll_fd: RawFd,
    events: *mut KernelEpollEvent,
    maxevents: i32,
    timeout_ms: i32,
    sigmask: *const u8,
    sigsetsize: usize,
) -> Result<usize> {
    // SAFETY: The caller owns the writable packed-event array and optional
    // signal-mask contract; Linux validates descriptor, count, timeout, and
    // signal-mask values.
    decode(unsafe {
        syscall6(
            SYS_EPOLL_PWAIT,
            epoll_fd as usize,
            events as usize,
            maxevents as usize,
            timeout_ms as usize,
            sigmask as usize,
            sigsetsize,
        )
    })
}

/// Waits for epoll readiness without changing a signal mask.
///
/// This is the x86-64 null-mask form of [`epoll_pwait_raw`].
///
/// # Safety
///
/// `events` must point to writable storage for `maxevents` consecutive
/// [`KernelEpollEvent`] records and remain live for the syscall.
#[inline]
pub unsafe fn epoll_wait_raw(
    epoll_fd: RawFd,
    events: *mut KernelEpollEvent,
    maxevents: i32,
    timeout_ms: i32,
) -> Result<usize> {
    // A null mask leaves the calling thread's signal mask unchanged. The
    // x86-64 kernel signal-set size is eight bytes even for this null mask.
    unsafe {
        epoll_pwait_raw(
            epoll_fd,
            events,
            maxevents,
            timeout_ms,
            core::ptr::null(),
            core::mem::size_of::<usize>(),
        )
    }
}

/// Waits for readiness in caller-owned x86-64 `pollfd` records.
///
/// `timeout_ms` is Linux's signed millisecond timeout: `-1` waits
/// indefinitely and zero performs a non-blocking query. The caller owns the
/// record pointer and must keep it writable for `nfds` records until the
/// syscall returns.
///
/// # Safety
///
/// `fds` must be null when `nfds` is zero or point to writable storage for
/// `nfds` consecutive [`KernelPollFd`] records. The records must remain live
/// for the duration of the syscall. Linux validates descriptor values,
/// requested bits, and the timeout.
#[inline]
pub unsafe fn poll_raw(
    fds: *mut KernelPollFd,
    nfds: usize,
    timeout_ms: i32,
) -> Result<usize> {
    // SAFETY: The caller owns the exact record-array contract documented
    // above; the x86-64 syscall ABI carries these three arguments in
    // rdi/rsi/rdx.
    decode(unsafe { syscall3(SYS_POLL, fds as usize, nfds, timeout_ms as usize) })
}

/// Waits for readiness through the Linux/x86-64 `ppoll` syscall.
///
/// # Safety
///
/// `fds` must be null when `nfds` is zero or point to writable x86-64
/// `pollfd` records. `timeout` must be null or point to one x86-64 Linux
/// `timespec` (`i64` seconds followed by `i64` nanoseconds). `sigmask` must
/// be null or point to `sigsetsize` bytes accepted by Linux.
#[inline]
pub unsafe fn ppoll_raw(
    fds: *mut u8,
    nfds: usize,
    timeout: *const u8,
    sigmask: *const u8,
    sigsetsize: usize,
) -> Result<usize> {
    // SAFETY: The caller owns the pointer and record contracts; x86-64
    // carries these five syscall arguments in rdi/rsi/rdx/r10/r8.
    decode(unsafe {
        syscall5(
            SYS_PPOLL,
            fds as usize,
            nfds,
            timeout as usize,
            sigmask as usize,
            sigsetsize,
        )
    })
}
