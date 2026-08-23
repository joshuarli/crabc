//! Stateless Linux/AArch64 pipe operations.

use core::mem::MaybeUninit;

use crate::{RawFd, Result};
use crate::syscall::{decode, syscall2, syscall4, syscall6, SYS_PIPE2, SYS_SPLICE, SYS_TEE, SYS_VMSPLICE};

/// Linux `F_GETPIPE_SZ`—read a pipe's current capacity in bytes.
const F_GETPIPE_SZ: i32 = 1_032;

/// Creates a pipe in caller-provided Linux `int[2]` storage without using
/// libc or TLS `errno`.
///
/// # Safety
///
/// `fds` must either point to writable storage for two Linux `int` values
/// or be a pointer the caller intentionally passes through to the kernel.
/// The latter preserves the C ABI's `EFAULT` behavior for an invalid
/// pointer.
#[inline]
pub unsafe fn pipe2_raw(fds: *mut RawFd, flags: u32) -> Result<()> {
    // SAFETY: The caller owns the pointer contract. Linux validates both
    // the output storage and the supplied flags.
    decode(unsafe { syscall2(SYS_PIPE2, fds as usize, flags as usize) }).map(|_| ())
}

/// Creates a pipe with Linux `pipe2` without using libc or TLS `errno`.
#[inline]
pub fn pipe2(flags: u32) -> Result<(RawFd, RawFd)> {
    let mut fds = MaybeUninit::<[RawFd; 2]>::uninit();
    // SAFETY: `fds` provides writable storage for exactly two Linux C
    // ints. A successful pipe2 initializes both descriptors.
    unsafe { pipe2_raw(fds.as_mut_ptr().cast(), flags)? };
    // SAFETY: Linux pipe2 initialized both descriptors on the successful
    // return above; each is a newly owned non-negative descriptor.
    let [reader, writer] = unsafe { fds.assume_init() };
    Ok((reader, writer))
}

/// Reads a Linux pipe's current capacity through the direct `fcntl`
/// syscall, without libc or TLS `errno`.
///
/// The kernel returns a non-negative byte count for `F_GETPIPE_SZ` and
/// reports descriptor/type failures directly. A negative value outside
/// Linux's syscall-error range would not be a valid pipe capacity and is
/// rejected rather than converted to a large `usize`.
#[inline]
pub fn fcntl_getpipe_size(fd: RawFd) -> Result<usize> {
    // SAFETY: F_GETPIPE_SZ has no pointer argument; the null third
    // argument is the canonical immediate representation for this
    // direct fcntl syscall.
    let size = unsafe { crate::io::fcntl_raw(fd, F_GETPIPE_SZ, core::ptr::null_mut())? };
    if size < 0 {
        return Err(crate::Errno::RANGE);
    }
    Ok(size as usize)
}

/// Duplicates data from one Linux pipe into another without consuming it.
///
/// The kernel may return a short count when fewer than `length` bytes are
/// available or the destination pipe cannot accept the whole request.
/// Flags retain Linux's `SPLICE_F_*` representation and kernel errors are
/// returned unchanged.
#[inline]
pub fn tee_raw(fd_in: RawFd, fd_out: RawFd, length: usize, flags: u32) -> Result<usize> {
    // SAFETY: Both descriptors and the scalar length/flags are immediate
    // Linux syscall arguments; the kernel validates pipe direction and
    // capacity requirements.
    decode(unsafe {
        syscall4(
            SYS_TEE,
            fd_in as usize,
            fd_out as usize,
            length,
            flags as usize,
        )
    })
}

/// Transfers bytes between a file and a pipe through Linux `splice(2)`.
///
/// `offset_in` and `offset_out` are nullable pointers to Linux `loff_t`
/// values. A null pointer selects and advances the descriptor's current
/// offset; a non-null pointer selects an explicit offset and advances the
/// pointed-to value. At least one descriptor must refer to a pipe, as
/// required by Linux. The pointers and descriptor lifetimes are owned by
/// the caller for the duration of this call.
#[inline]
pub unsafe fn splice_raw(
    fd_in: RawFd,
    offset_in: *mut u64,
    fd_out: RawFd,
    offset_out: *mut u64,
    length: usize,
    flags: u32,
) -> Result<usize> {
    // SAFETY: The caller owns the nullable offset-pointer contracts. All
    // descriptors and scalar values are immediate Linux syscall
    // arguments; the kernel validates pipe direction and flags.
    decode(unsafe {
        syscall6(
            SYS_SPLICE,
            fd_in as usize,
            offset_in as usize,
            fd_out as usize,
            offset_out as usize,
            length,
            flags as usize,
        )
    })
}

/// Transfers caller-owned iovec memory to or from a pipe through
/// Linux `vmsplice(2)`.
///
/// # Safety
///
/// `iovecs` must point to `count` readable Linux [`crate::io::Iovec`]
/// records, and each record must satisfy the direction and lifetime
/// contract of the selected pipe descriptor. With `SPLICE_F_GIFT`, the
/// supplied pages must be page-aligned, page-sized, and never modified or
/// reused after the kernel accepts them. The caller must also ensure that
/// memory is writable when the pipe's read end is supplied.
#[inline]
pub unsafe fn vmsplice_raw(
    fd: RawFd,
    iovecs: *const crate::io::Iovec,
    count: usize,
    flags: u32,
) -> Result<usize> {
    // SAFETY: The caller owns the iovec-array and pointed-to-memory
    // contracts. Linux validates the descriptor, count, and flags.
    decode(unsafe {
        crate::syscall::syscall4(
            SYS_VMSPLICE,
            fd as usize,
            iovecs as usize,
            count,
            flags as usize,
        )
    })
}
