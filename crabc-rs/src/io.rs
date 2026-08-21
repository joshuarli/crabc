//! Direct descriptor I/O.
//!
//! These operations use the shared typed kernel seam in `crabc-core`; they do
//! not call crabc's public C ABI and never read or write TLS `errno`.

use crate::buffer::Buffer;
use crate::{AsFd, OwnedFd, RawFd, Result};

pub use crate::Errno;

bitflags::bitflags! {
    /// `FD_*` flags used by [`fcntl_getfd`] and [`fcntl_setfd`].
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct FdFlags: u32 {
        /// `FD_CLOEXEC`: close this descriptor during a successful exec.
        const CLOEXEC = crabc_core::io::FD_CLOEXEC;

        /// Preserve unknown Linux flag bits when round-tripping kernel values.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// `O_*` flags accepted by [`dup3`].
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct DupFlags: u32 {
        /// `O_CLOEXEC`: set close-on-exec on the new descriptor.
        const CLOEXEC = crabc_core::io::O_CLOEXEC;

        /// Preserve unknown Linux flag bits for kernel validation.
        const _ = !0;
    }
}

/// `dup(fd)`—duplicate a descriptor with a fresh owner.
#[inline]
pub fn dup<Fd: AsFd>(fd: Fd) -> Result<OwnedFd> {
    let raw = crabc_core::io::dup(fd.as_fd().as_raw_fd())?;
    // SAFETY: Linux returned a new open descriptor whose ownership is now
    // transferred to this `OwnedFd`.
    unsafe { Ok(OwnedFd::from_raw_fd(raw)) }
}

/// `dup2(fd, new)`—replace the descriptor held by `new`.
///
/// The mutable owner prevents aliasing the target through this API. Linux's
/// AArch64 implementation uses `dup3` internally while preserving `dup2`'s
/// equal-descriptor no-op semantics.
#[inline]
pub fn dup2<Fd: AsFd>(fd: Fd, new: &mut OwnedFd) -> Result<()> {
    crabc_core::io::dup2(fd.as_fd().as_raw_fd(), new.as_raw_fd())
}

/// `dup3(fd, new, flags)`—replace the descriptor held by `new` with flags.
#[inline]
pub fn dup3<Fd: AsFd>(fd: Fd, new: &mut OwnedFd, flags: DupFlags) -> Result<()> {
    crabc_core::io::dup3(fd.as_fd().as_raw_fd(), new.as_raw_fd(), flags.bits())
}

/// `fcntl(fd, F_GETFD)`—read descriptor flags.
#[inline]
pub fn fcntl_getfd<Fd: AsFd>(fd: Fd) -> Result<FdFlags> {
    crabc_core::io::fcntl_getfd(fd.as_fd().as_raw_fd()).map(FdFlags::from_bits_retain)
}

/// `fcntl(fd, F_SETFD, flags)`—replace descriptor flags.
#[inline]
pub fn fcntl_setfd<Fd: AsFd>(fd: Fd, flags: FdFlags) -> Result<()> {
    crabc_core::io::fcntl_setfd(fd.as_fd().as_raw_fd(), flags.bits())
}

/// `fcntl(fd, F_DUPFD)`—duplicate at or above `minimum`.
#[inline]
pub fn fcntl_dupfd<Fd: AsFd>(fd: Fd, minimum: RawFd) -> Result<OwnedFd> {
    let raw = crabc_core::io::fcntl_dupfd(fd.as_fd().as_raw_fd(), minimum)?;
    // SAFETY: Linux returned a new open descriptor whose ownership is now
    // transferred to this `OwnedFd`.
    unsafe { Ok(OwnedFd::from_raw_fd(raw)) }
}

/// `fcntl(fd, F_DUPFD_CLOEXEC)`—duplicate with close-on-exec set.
#[inline]
pub fn fcntl_dupfd_cloexec<Fd: AsFd>(fd: Fd, minimum: RawFd) -> Result<OwnedFd> {
    let raw = crabc_core::io::fcntl_dupfd_cloexec(fd.as_fd().as_raw_fd(), minimum)?;
    // SAFETY: Linux returned a new open descriptor whose ownership is now
    // transferred to this `OwnedFd`.
    unsafe { Ok(OwnedFd::from_raw_fd(raw)) }
}

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
