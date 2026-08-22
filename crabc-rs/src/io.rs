//! Direct descriptor I/O.
//!
//! These operations use the shared typed kernel seam in `crabc-core`; they do
//! not call crabc's public C ABI and never read or write TLS `errno`.

use core::marker::PhantomData;
use core::slice;

use crate::buffer::Buffer;
use crate::{AsFd, BorrowedFd, OwnedFd, RawFd, Result};

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
    /// The bounded Linux `RWF_*` flags accepted by [`preadv2`] and
    /// [`pwritev2`].
    ///
    /// This closed set follows the stable flag vocabulary exposed by the
    /// pinned Rustix raw backend: unknown bits, including newer header bits,
    /// are rejected by the safe APIs before a syscall instead of being
    /// silently forwarded. The pinned musl header also advertises
    /// `RWF_NOAPPEND` (`0x20`), but the local Rustix ground truth does not yet
    /// expose it, so this bounded slice deliberately treats it as a future bit.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct ReadWriteFlags: u32 {
        /// `RWF_HIPRI`.
        const HIPRI = 0x0000_0001;
        /// `RWF_DSYNC`.
        const DSYNC = 0x0000_0002;
        /// `RWF_SYNC`.
        const SYNC = 0x0000_0004;
        /// `RWF_NOWAIT`.
        const NOWAIT = 0x0000_0008;
        /// `RWF_APPEND`.
        const APPEND = 0x0000_0010;
    }
}

bitflags::bitflags! {
    /// The three Linux `SYNC_FILE_RANGE_*` controls accepted by
    /// [`sync_file_range`].
    ///
    /// This is a closed flag vocabulary: values built with
    /// [`from_bits_retain`](SyncFileRangeFlags::from_bits_retain) are checked
    /// by [`sync_file_range`] and unknown bits return `EINVAL` before the
    /// syscall.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct SyncFileRangeFlags: u32 {
        /// Wait for already-submitted writeback before starting this request.
        const WAIT_BEFORE = 0x01;
        /// Start writeback for dirty pages in this range.
        const WRITE = 0x02;
        /// Wait for writeback after starting this request.
        const WAIT_AFTER = 0x04;
    }
}

/// A borrowed initialized byte range for [`writev`].
///
/// The wrapper preserves the source slice's lifetime and pointer provenance
/// while presenting the Linux `struct iovec` layout required by the direct
/// syscall. It is `Copy` because it carries only an immutable borrow.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct IoSlice<'a> {
    iovec: crabc_core::io::Iovec,
    _lifetime: PhantomData<&'a [u8]>,
}

impl<'a> IoSlice<'a> {
    /// Borrows `buffer` as one immutable vectored-I/O segment.
    #[inline]
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            iovec: crabc_core::io::Iovec {
                // Linux's iovec uses a mutable C pointer even for writev;
                // the immutable Rust borrow is retained by `_lifetime`.
                iov_base: buffer.as_ptr().cast_mut(),
                iov_len: buffer.len(),
            },
            _lifetime: PhantomData,
        }
    }

    /// Returns the remaining immutable segment.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `iovec` was created from a live `'a` slice and `advance`
        // only moves its pointer within that original slice.
        unsafe { slice::from_raw_parts(self.iovec.iov_base.cast_const(), self.iovec.iov_len) }
    }

    /// Removes `amount` bytes from the front of this segment.
    ///
    /// This is useful when a caller handles a short write and retries the
    /// remaining segments. It panics if `amount` exceeds the segment length.
    #[inline]
    pub fn advance(&mut self, amount: usize) {
        if amount > self.iovec.iov_len {
            panic!("advancing IoSlice beyond its length");
        }
        if amount == 0 {
            return;
        }

        // SAFETY: `amount` is within the original slice's bounds.
        self.iovec.iov_base = unsafe { self.iovec.iov_base.add(amount) };
        self.iovec.iov_len -= amount;
    }
}

/// A borrowed initialized mutable byte range for [`readv`].
///
/// Constructing one requires an exclusive `&mut [u8]`, so safe callers cannot
/// put overlapping mutable ranges into one readv call. This initialized-byte
/// API intentionally does not accept `MaybeUninit`; use [`read`] when the
/// initialized prefix and uninitialized suffix must be represented explicitly.
#[repr(transparent)]
pub struct IoSliceMut<'a> {
    iovec: crabc_core::io::Iovec,
    _lifetime: PhantomData<&'a mut [u8]>,
}

impl<'a> IoSliceMut<'a> {
    /// Borrows `buffer` as one mutable vectored-I/O segment.
    #[inline]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            iovec: crabc_core::io::Iovec {
                iov_base: buffer.as_mut_ptr(),
                iov_len: buffer.len(),
            },
            _lifetime: PhantomData,
        }
    }

    /// Returns the remaining segment as an immutable byte slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `iovec` was created from a live `'a` mutable slice and
        // `advance` only moves its pointer within that original slice.
        unsafe { slice::from_raw_parts(self.iovec.iov_base.cast_const(), self.iovec.iov_len) }
    }

    /// Returns the remaining segment as a mutable byte slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `iovec` was created from a live `'a` mutable slice and
        // `advance` only moves its pointer within that original slice.
        unsafe { slice::from_raw_parts_mut(self.iovec.iov_base, self.iovec.iov_len) }
    }

    /// Removes `amount` bytes from the front of this segment.
    ///
    /// This is useful when a caller handles a short read and retries the
    /// remaining segments. It panics if `amount` exceeds the segment length.
    #[inline]
    pub fn advance(&mut self, amount: usize) {
        if amount > self.iovec.iov_len {
            panic!("advancing IoSliceMut beyond its length");
        }
        if amount == 0 {
            return;
        }

        // SAFETY: `amount` is within the original slice's bounds.
        self.iovec.iov_base = unsafe { self.iovec.iov_base.add(amount) };
        self.iovec.iov_len -= amount;
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

/// Synchronizes a checked byte range of an open regular file.
///
/// `offset` and `length` are unsigned at this Rust boundary and describe the
/// half-open range `[offset, offset + length)`. Before entering Linux's signed
/// `loff_t` ABI, both values and their checked sum must fit in `i64`; failure
/// returns `EINVAL` without making a syscall. `length == 0` is supported and
/// has Linux's precise meaning: synchronize from `offset` through end of file.
/// The descriptor is borrowed for the direct operation and is never closed or
/// otherwise transferred by this function.
///
/// Unknown bits in `flags` are rejected with `EINVAL` before the syscall.
#[inline]
pub fn sync_file_range(
    fd: BorrowedFd<'_>,
    offset: u64,
    length: u64,
    flags: SyncFileRangeFlags,
) -> Result<()> {
    if SyncFileRangeFlags::from_bits(flags.bits()).is_none()
        || offset > i64::MAX as u64
        || length > i64::MAX as u64
        || offset.checked_add(length).map_or(true, |end| end > i64::MAX as u64)
    {
        return Err(crate::Errno::INVAL);
    }

    // The checks above establish the exact non-negative signed `loff_t`
    // representation and preserve Linux's zero-length-to-EOF convention.
    crabc_core::io::sync_file_range(
        fd.as_raw_fd(),
        offset as i64,
        length as i64,
        flags.bits(),
    )
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

/// Reads into initialized byte segments in order.
///
/// Linux fills the segments as one logical concatenated buffer and may return
/// a short count. Segment contents beyond that count remain unchanged. The
/// descriptor is borrowed for the duration of the direct syscall, and the
/// exclusive borrows held by [`IoSliceMut`] keep the destination ranges
/// disjoint. For potentially uninitialized storage, use [`read`] instead.
#[inline]
pub fn readv<Fd: AsFd>(fd: Fd, buffers: &mut [IoSliceMut<'_>]) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `IoSliceMut` is `repr(transparent)` over the Linux iovec record;
    // each value was built from a live, disjoint mutable byte slice. The
    // slice keeps all records readable for the syscall duration.
    unsafe {
        crabc_core::io::readv_raw(
            fd.as_raw_fd(),
            buffers.as_ptr().cast::<crabc_core::io::Iovec>(),
            buffers.len(),
        )
    }
}

/// Reads bytes at `offset` without changing the descriptor's file position.
///
/// The descriptor is borrowed for the operation, and the buffer contract is
/// the same as [`read`]: initialized storage returns a byte count while
/// `MaybeUninit` storage returns its initialized prefix and remaining suffix.
/// `offset` is a non-negative Linux file offset; the kernel rejects values
/// outside its signed `off_t` range.
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
    // and the descriptor borrow keeps the fd open for this syscall.
    let initialized = unsafe {
        crabc_core::io::pread_raw(fd.as_raw_fd(), pointer.cast(), length, offset)?
    };
    // SAFETY: A successful kernel pread initializes its returned prefix and
    // never reports a length larger than the supplied buffer.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Reads initialized byte segments from `offset` without changing the
/// descriptor's file position.
///
/// Linux treats the segments as one logical concatenated buffer and may
/// return a short count; bytes beyond that count remain unchanged. This
/// initialized-byte API intentionally does not accept `MaybeUninit`; use
/// [`read`] when the initialized prefix and uninitialized suffix must be
/// represented explicitly. `offset` is a non-negative Linux file offset;
/// values above `i64::MAX` return `EINVAL`.
#[inline]
pub fn preadv<Fd: AsFd>(
    fd: Fd,
    buffers: &mut [IoSliceMut<'_>],
    offset: u64,
) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `IoSliceMut` is `repr(transparent)` over the Linux iovec record;
    // each value was built from a live, disjoint mutable byte slice. The
    // descriptor and all records remain borrowed for the direct syscall.
    unsafe {
        crabc_core::io::preadv_raw(
            fd.as_raw_fd(),
            buffers.as_ptr().cast::<crabc_core::io::Iovec>(),
            buffers.len(),
            offset,
        )
    }
}

/// Reads initialized byte segments with Linux `preadv2` flags.
///
/// `offset == u64::MAX` is the explicit Linux sentinel for the descriptor's
/// current file position; that form may advance the position. Every other
/// `u64` is passed as a positioned offset, with its low and high 32-bit words
/// preserved by the AArch64 syscall seam. Unknown `ReadWriteFlags` bits return
/// `EINVAL` before a syscall. A short read initializes only its returned byte
/// count; the remaining initialized segments are unchanged.
#[inline]
pub fn preadv2<Fd: AsFd>(
    fd: Fd,
    buffers: &mut [IoSliceMut<'_>],
    offset: u64,
    flags: ReadWriteFlags,
) -> Result<usize> {
    if ReadWriteFlags::from_bits(flags.bits()).is_none() {
        return Err(crate::Errno::INVAL);
    }
    let fd = fd.as_fd();
    // SAFETY: `IoSliceMut` is `repr(transparent)` over the Linux iovec record;
    // each value was built from a live, disjoint mutable byte slice. The
    // descriptor, records, and source ranges remain borrowed for the direct
    // six-argument syscall.
    unsafe {
        crabc_core::io::preadv2_raw(
            fd.as_raw_fd(),
            buffers.as_ptr().cast::<crabc_core::io::Iovec>(),
            buffers.len(),
            offset,
            flags.bits(),
        )
    }
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

/// Writes initialized byte segments in order.
///
/// Linux treats the segments as one logical concatenated buffer and may
/// return a short count. The descriptor and every source segment remain
/// borrowed for the duration of the direct syscall; no allocation or C ABI
/// wrapper is involved.
#[inline]
pub fn writev<Fd: AsFd>(fd: Fd, buffers: &[IoSlice<'_>]) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `IoSlice` is `repr(transparent)` over the Linux iovec record;
    // each value was built from a live immutable byte slice. The slice keeps
    // all records and source ranges readable for the syscall duration.
    unsafe {
        crabc_core::io::writev_raw(
            fd.as_raw_fd(),
            buffers.as_ptr().cast::<crabc_core::io::Iovec>(),
            buffers.len(),
        )
    }
}

/// Writes bytes at `offset` without changing the descriptor's file position.
///
/// A successful short write is returned as the number of bytes accepted by
/// Linux. The descriptor is borrowed for the duration of the operation.
#[inline]
pub fn pwrite<Fd: AsFd>(fd: Fd, buffer: &[u8], offset: u64) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `buffer` is valid immutable storage for its exact length, and
    // the descriptor borrow keeps the fd open for this syscall.
    unsafe {
        crabc_core::io::pwrite_raw(fd.as_raw_fd(), buffer.as_ptr(), buffer.len(), offset)
    }
}

/// Writes initialized byte segments at `offset` without changing the
/// descriptor's file position.
///
/// Linux treats the segments as one logical concatenated buffer and may
/// return a short count. `offset` is a non-negative Linux file offset; values
/// above `i64::MAX` return `EINVAL`.
#[inline]
pub fn pwritev<Fd: AsFd>(
    fd: Fd,
    buffers: &[IoSlice<'_>],
    offset: u64,
) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `IoSlice` is `repr(transparent)` over the Linux iovec record;
    // each value was built from a live immutable byte slice. The descriptor,
    // records, and source ranges remain borrowed for the direct syscall.
    unsafe {
        crabc_core::io::pwritev_raw(
            fd.as_raw_fd(),
            buffers.as_ptr().cast::<crabc_core::io::Iovec>(),
            buffers.len(),
            offset,
        )
    }
}

/// Writes initialized byte segments with Linux `pwritev2` flags.
///
/// `offset == u64::MAX` is the explicit Linux sentinel for the descriptor's
/// current file position; that form may advance the position. Every other
/// `u64` is passed as a positioned offset, with its low and high 32-bit words
/// preserved by the AArch64 syscall seam. Unknown `ReadWriteFlags` bits return
/// `EINVAL` before a syscall. A successful short write is returned as its
/// actual byte count.
#[inline]
pub fn pwritev2<Fd: AsFd>(
    fd: Fd,
    buffers: &[IoSlice<'_>],
    offset: u64,
    flags: ReadWriteFlags,
) -> Result<usize> {
    if ReadWriteFlags::from_bits(flags.bits()).is_none() {
        return Err(crate::Errno::INVAL);
    }
    let fd = fd.as_fd();
    // SAFETY: `IoSlice` is `repr(transparent)` over the Linux iovec record;
    // each value was built from a live immutable byte slice. The descriptor,
    // records, and source ranges remain borrowed for the direct six-argument
    // syscall.
    unsafe {
        crabc_core::io::pwritev2_raw(
            fd.as_raw_fd(),
            buffers.as_ptr().cast::<crabc_core::io::Iovec>(),
            buffers.len(),
            offset,
            flags.bits(),
        )
    }
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
