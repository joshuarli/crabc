//! Darwin descriptor I/O over libSystem.

use core::ffi::c_int;

use super::errno::{self, Errno, Result};
use super::sys;
use crate::buffer::Buffer;
use crate::io::{FdFlags, IoSlice, IoSliceMut};
use crate::{AsFd, OwnedFd, RawFd};

bitflags::bitflags! {
    /// `O_*` flags accepted by [`dup3`], with Darwin values.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct DupFlags: u32 {
        /// `O_CLOEXEC`: set close-on-exec on the new descriptor.
        const CLOEXEC = sys::O_CLOEXEC.cast_unsigned();
        /// `O_CLOFORK`: set close-on-fork on the new descriptor.
        const CLOFORK = sys::O_CLOFORK.cast_unsigned();

        /// Preserve unknown flag bits for libSystem validation.
        const _ = !0;
    }
}

/// Closes `fd` once, without retrying, and reports libSystem's result.
#[inline]
pub(crate) fn close_raw(fd: RawFd) -> Result<()> {
    // SAFETY: the caller transfers its unique ownership of `fd`; nothing uses
    // the number after this call, whatever the result.
    let result = unsafe { sys::close(fd) };
    errno::check(result).map(|_| ())
}

/// Converts a slice length to the `int` count taken by the vectored calls.
///
/// A count beyond `c_int` exceeds Darwin's `IOV_MAX` as well, which libSystem
/// reports as `EINVAL`.
#[inline]
fn iovec_count(length: usize) -> Result<c_int> {
    c_int::try_from(length).map_err(|_| Errno::INVAL)
}

/// `dup(fd)`: duplicate a descriptor with a fresh owner.
///
/// The new descriptor does not have close-on-exec set; use
/// [`fcntl_dupfd_cloexec`] for an atomically close-on-exec duplicate.
#[inline]
pub fn dup<Fd: AsFd>(fd: Fd) -> Result<OwnedFd> {
    // SAFETY: `dup` has no memory arguments; the borrow keeps `fd` open.
    let raw = unsafe { sys::dup(fd.as_fd().as_raw_fd()) };
    let raw = errno::check(raw)?;
    // SAFETY: a successful `dup` returns a new open descriptor whose
    // ownership transfers to this `OwnedFd`.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `dup2(fd, new)`: replace the descriptor held by `new`.
///
/// The mutable owner prevents aliasing the target through this API. Equal
/// descriptors are validated and otherwise left unchanged.
#[inline]
pub fn dup2<Fd: AsFd>(fd: Fd, new: &mut OwnedFd) -> Result<()> {
    // SAFETY: `dup2` has no memory arguments, and `new` is uniquely borrowed
    // so no other owner observes its descriptor number being replaced.
    let result = unsafe { sys::dup2(fd.as_fd().as_raw_fd(), new.as_raw_fd()) };
    errno::check(result).map(|_| ())
}

/// `dup3(fd, new, flags)`: replace the descriptor held by `new` with flags.
///
/// macOS 27 provides `dup3`, so close-on-exec is applied atomically. Equal
/// descriptors fail with [`Errno::INVAL`], as on Linux.
#[inline]
pub fn dup3<Fd: AsFd>(fd: Fd, new: &mut OwnedFd, flags: DupFlags) -> Result<()> {
    // SAFETY: as for `dup2`; libSystem validates the flag word.
    let result =
        unsafe { sys::dup3(fd.as_fd().as_raw_fd(), new.as_raw_fd(), flags.bits().cast_signed()) };
    errno::check(result).map(|_| ())
}

/// `fcntl(fd, F_GETFD)`: read descriptor flags.
#[inline]
pub fn fcntl_getfd<Fd: AsFd>(fd: Fd) -> Result<FdFlags> {
    // SAFETY: `F_GETFD` takes no argument and touches no caller memory.
    let flags = unsafe { sys::fcntl(fd.as_fd().as_raw_fd(), sys::F_GETFD) };
    errno::check(flags).map(|flags| FdFlags::from_bits_retain(flags.cast_unsigned()))
}

/// `fcntl(fd, F_SETFD, flags)`: replace descriptor flags.
#[inline]
pub fn fcntl_setfd<Fd: AsFd>(fd: Fd, flags: FdFlags) -> Result<()> {
    // SAFETY: `F_SETFD` takes one `int` and touches no caller memory.
    let result =
        unsafe { sys::fcntl(fd.as_fd().as_raw_fd(), sys::F_SETFD, flags.bits().cast_signed()) };
    errno::check(result).map(|_| ())
}

/// `fcntl(fd, F_DUPFD)`: duplicate at or above `minimum`.
#[inline]
pub fn fcntl_dupfd<Fd: AsFd>(fd: Fd, minimum: RawFd) -> Result<OwnedFd> {
    // SAFETY: `F_DUPFD` takes one `int` and touches no caller memory.
    let raw = unsafe { sys::fcntl(fd.as_fd().as_raw_fd(), sys::F_DUPFD, minimum) };
    let raw = errno::check(raw)?;
    // SAFETY: a successful `F_DUPFD` returns a new open descriptor whose
    // ownership transfers to this `OwnedFd`.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `fcntl(fd, F_DUPFD_CLOEXEC)`: duplicate with close-on-exec set atomically.
#[inline]
pub fn fcntl_dupfd_cloexec<Fd: AsFd>(fd: Fd, minimum: RawFd) -> Result<OwnedFd> {
    // SAFETY: `F_DUPFD_CLOEXEC` takes one `int` and touches no caller memory.
    let raw = unsafe { sys::fcntl(fd.as_fd().as_raw_fd(), sys::F_DUPFD_CLOEXEC, minimum) };
    let raw = errno::check(raw)?;
    // SAFETY: a successful `F_DUPFD_CLOEXEC` returns a new open descriptor
    // whose ownership transfers to this `OwnedFd`.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
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
    // `length` bytes, which stays live for the call.
    let read = unsafe { sys::read(fd.as_raw_fd(), pointer.cast(), length) };
    let initialized = errno::check_size(read)?;
    if initialized > length {
        return Err(Errno::IO);
    }
    // SAFETY: a successful `read` initialized exactly its returned prefix,
    // which the check above keeps within the supplied buffer.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Reads into initialized byte segments in order.
///
/// libSystem fills the segments as one logical concatenated buffer and may
/// return a short count. Segment contents beyond that count remain unchanged.
/// More segments than Darwin's `IOV_MAX` return [`Errno::INVAL`].
#[inline]
pub fn readv<Fd: AsFd>(fd: Fd, buffers: &mut [IoSliceMut<'_>]) -> Result<usize> {
    let fd = fd.as_fd();
    let count = iovec_count(buffers.len())?;
    // SAFETY: `IoSliceMut` is `repr(transparent)` over `struct iovec`; each
    // value was built from a live, disjoint mutable byte slice, and the slice
    // keeps every record readable for the call.
    let read = unsafe { sys::readv(fd.as_raw_fd(), buffers.as_ptr().cast(), count) };
    errno::check_size(read)
}

/// Reads bytes at `offset` without changing the descriptor's file position.
///
/// The buffer contract is the same as [`read`]. Offsets above `i64::MAX` are
/// negative `off_t` values, which libSystem rejects with [`Errno::INVAL`].
#[inline]
#[allow(private_interfaces)]
pub fn pread<Fd: AsFd, Buf: Buffer<u8>>(
    fd: Fd,
    mut buffer: Buf,
    offset: u64,
) -> Result<Buf::Output> {
    let fd = fd.as_fd();
    let (pointer, length) = buffer.parts_mut();
    // SAFETY: `Buffer` supplies writable storage for exactly `length` bytes,
    // and the descriptor borrow keeps the fd open for this call.
    let read = unsafe { sys::pread(fd.as_raw_fd(), pointer.cast(), length, offset.cast_signed()) };
    let initialized = errno::check_size(read)?;
    if initialized > length {
        return Err(Errno::IO);
    }
    // SAFETY: a successful `pread` initialized exactly its returned prefix,
    // which the check above keeps within the supplied buffer.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Reads initialized byte segments from `offset` without changing the
/// descriptor's file position.
///
/// The segment contract is the same as [`readv`]; the offset contract is the
/// same as [`pread`].
#[inline]
pub fn preadv<Fd: AsFd>(fd: Fd, buffers: &mut [IoSliceMut<'_>], offset: u64) -> Result<usize> {
    let fd = fd.as_fd();
    let count = iovec_count(buffers.len())?;
    // SAFETY: as for `readv`: transparent iovec records over live, disjoint
    // mutable slices that remain borrowed for the call.
    let read =
        unsafe { sys::preadv(fd.as_raw_fd(), buffers.as_ptr().cast(), count, offset.cast_signed()) };
    errno::check_size(read)
}

/// Writes the byte slice as far as libSystem accepts it.
///
/// A successful short write is reported as its actual byte count.
#[inline]
pub fn write<Fd: AsFd>(fd: Fd, buffer: &[u8]) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `buffer` is valid immutable storage for its exact length.
    let written = unsafe { sys::write(fd.as_raw_fd(), buffer.as_ptr().cast(), buffer.len()) };
    errno::check_size(written)
}

/// Writes initialized byte segments in order.
///
/// libSystem treats the segments as one logical concatenated buffer and may
/// return a short count. More segments than Darwin's `IOV_MAX` return
/// [`Errno::INVAL`].
#[inline]
pub fn writev<Fd: AsFd>(fd: Fd, buffers: &[IoSlice<'_>]) -> Result<usize> {
    let fd = fd.as_fd();
    let count = iovec_count(buffers.len())?;
    // SAFETY: `IoSlice` is `repr(transparent)` over `struct iovec`; each value
    // was built from a live immutable byte slice that stays borrowed for the
    // call.
    let written = unsafe { sys::writev(fd.as_raw_fd(), buffers.as_ptr().cast(), count) };
    errno::check_size(written)
}

/// Writes bytes at `offset` without changing the descriptor's file position.
///
/// Offsets above `i64::MAX` return [`Errno::INVAL`] from libSystem.
#[inline]
pub fn pwrite<Fd: AsFd>(fd: Fd, buffer: &[u8], offset: u64) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `buffer` is valid immutable storage for its exact length, and
    // the descriptor borrow keeps the fd open for this call.
    let written = unsafe {
        sys::pwrite(fd.as_raw_fd(), buffer.as_ptr().cast(), buffer.len(), offset.cast_signed())
    };
    errno::check_size(written)
}

/// Writes initialized byte segments at `offset` without changing the
/// descriptor's file position.
///
/// The segment contract is the same as [`writev`]; the offset contract is
/// the same as [`pwrite`].
#[inline]
pub fn pwritev<Fd: AsFd>(fd: Fd, buffers: &[IoSlice<'_>], offset: u64) -> Result<usize> {
    let fd = fd.as_fd();
    let count = iovec_count(buffers.len())?;
    // SAFETY: as for `writev`: transparent iovec records over live slices.
    let written =
        unsafe { sys::pwritev(fd.as_raw_fd(), buffers.as_ptr().cast(), count, offset.cast_signed()) };
    errno::check_size(written)
}

/// Closes a raw descriptor without retrying errors.
///
/// # Safety
///
/// `fd` must be open and uniquely owned by the caller. It must not be used
/// after this call, even if libSystem reports an error: XNU releases the
/// descriptor before any interruptible part of `close`, so retrying can
/// release a descriptor reused by another operation.
#[inline]
pub unsafe fn close(fd: RawFd) {
    let _ = close_raw(fd);
}

/// Sets `FD_CLOEXEC` through Darwin `FIOCLEX`.
#[inline]
pub fn ioctl_fioclex<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `FIOCLEX` takes no argument and touches no caller memory.
    let result = unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::FIOCLEX) };
    errno::check(result).map(|_| ())
}

/// Clears `FD_CLOEXEC` through Darwin `FIONCLEX`.
#[inline]
pub fn ioctl_fionclex<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `FIONCLEX` takes no argument and touches no caller memory.
    let result = unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::FIONCLEX) };
    errno::check(result).map(|_| ())
}

/// Enables or disables nonblocking I/O through Darwin `FIONBIO`.
#[inline]
pub fn ioctl_fionbio<Fd: AsFd>(fd: Fd, value: bool) -> Result<()> {
    let mut value = c_int::from(value);
    // SAFETY: `FIONBIO` reads one `int` through its pointer argument, which
    // points at the live local above for the duration of the call.
    let result =
        unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::FIONBIO, &raw mut value) };
    errno::check(result).map(|_| ())
}

/// Returns the byte count currently available to read through `FIONREAD`.
#[inline]
pub fn ioctl_fionread<Fd: AsFd>(fd: Fd) -> Result<u64> {
    let mut count: c_int = 0;
    // SAFETY: `FIONREAD` writes one `int` through its pointer argument, which
    // points at the live, initialized local above for the duration of the
    // call.
    let result =
        unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::FIONREAD, &raw mut count) };
    errno::check(result)?;
    u64::try_from(count).map_err(|_| Errno::IO)
}
