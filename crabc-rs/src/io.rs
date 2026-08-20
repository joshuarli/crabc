//! Direct descriptor I/O.
//!
//! These operations use the shared typed kernel seam in `crabc-core`; they do
//! not call crabc's public C ABI and never read or write TLS `errno`.

use crate::buffer::Buffer;
use crate::{AsFd, RawFd, Result};

pub use crate::Errno;

/// Reads bytes into initialized or potentially uninitialized storage.
///
/// For initialized buffers the returned value is the number of bytes read. For
/// `MaybeUninit` storage, the returned pair separates the initialized prefix
/// from the remaining uninitialized suffix. The descriptor remains borrowed
/// for the duration of the operation.
#[inline]
#[allow(private_interfaces)]
pub fn read<Fd: AsFd, Buf: Buffer<u8>>(fd: Fd, mut buffer: Buf) -> Result<Buf::Output> {
    let fd = fd.as_fd();
    let (pointer, length) = buffer.parts_mut();
    // SAFETY: `Buffer` is sealed and supplies writable storage for exactly
    // `length` bytes. A successful read initializes precisely its returned
    // prefix, which is then reflected in the buffer-specific result.
    let initialized = unsafe { crabc_core::io::read_raw(fd.as_raw_fd(), pointer.cast(), length)? };
    // SAFETY: A successful kernel `read` initializes its returned prefix and
    // never reports a length larger than the supplied buffer.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Writes the complete byte slice as far as the kernel accepts it.
///
/// A successful short write is reported as its actual byte count, matching the
/// Linux `write` contract.
#[inline]
pub fn write<Fd: AsFd>(fd: Fd, buffer: &[u8]) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `buffer` is valid immutable storage for its exact length.
    unsafe { crabc_core::io::write_raw(fd.as_raw_fd(), buffer.as_ptr(), buffer.len()) }
}

/// Closes a raw descriptor without retrying errors.
///
/// # Safety
///
/// `fd` must be open and uniquely owned by the caller. It must not be used
/// after this call, even if the kernel reports an error: retrying close can
/// release a descriptor reused by another operation.
#[inline]
pub unsafe fn close(fd: RawFd) {
    let _ = crabc_core::io::close(fd);
}

/// Repeats an operation when it fails with `EINTR`.
///
/// This is intentionally opt-in. In particular, do not use it with `close`.
#[inline]
pub fn retry_on_intr<T, F>(mut operation: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    loop {
        match operation() {
            Err(error) if error.raw() == 4 => continue,
            result => return result,
        }
    }
}

/// Sets `FD_CLOEXEC` through Linux `FIOCLEX`.
#[inline]
pub fn ioctl_fioclex<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `FIOCLEX` is the Linux no-argument descriptor request.
    unsafe { crate::ioctl::ioctl(fd, crate::ioctl::NoArg::<0x5451>::new()) }
}

/// Clears `FD_CLOEXEC` through Linux `FIONCLEX`.
#[inline]
pub fn ioctl_fionclex<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `FIONCLEX` is the Linux no-argument descriptor request.
    unsafe { crate::ioctl::ioctl(fd, crate::ioctl::NoArg::<0x5450>::new()) }
}

/// Enables or disables nonblocking I/O through Linux `FIONBIO`.
#[inline]
pub fn ioctl_fionbio<Fd: AsFd>(fd: Fd, value: bool) -> Result<()> {
    // SAFETY: `FIONBIO` reads one C `int` from its argument and does not
    // mutate it. Linux's C `int` representation is a 32-bit `i32` here.
    unsafe {
        crate::ioctl::ioctl(
            fd,
            crate::ioctl::Setter::<0x5421, i32>::new(i32::from(value)),
        )
    }
}

/// Returns the byte count currently available to read through `FIONREAD`.
#[inline]
pub fn ioctl_fionread<Fd: AsFd>(fd: Fd) -> Result<u64> {
    // SAFETY: `FIONREAD` initializes one C `int` and Linux exposes its result
    // as a nonnegative count, subject to the kernel's C-int width.
    unsafe {
        crate::ioctl::ioctl(fd, crate::ioctl::Getter::<0x541b, i32>::new())
            .map(|count| count as u64)
    }
}
