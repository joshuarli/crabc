//! Deliberately bounded Linux/x86-64 event-descriptor operations.
//!
//! This target-specific module owns the `poll(2)` and `ppoll(2)` syscall seams.
//! The x86-64 `pollfd` record is kept separate from the AArch64 event module so
//! that a caller cannot accidentally pass an AArch64-owned event record to an
//! x86 syscall. The typed facade admits bounded `poll`, `ppoll`, and signal-only
//! `pause`; pselect, epoll, signalfd, and wider event records remain deferred.

use crate::syscall::{
    decode, syscall2, syscall3, syscall5, SYS_EVENTFD2, SYS_POLL, SYS_PPOLL, SYS_READ,
    SYS_WRITE,
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
