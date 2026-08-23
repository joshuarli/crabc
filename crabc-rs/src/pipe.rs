//! Direct Linux pipe operations.
//!
//! The returned descriptors own their kernel resources and all operations use
//! the shared `crabc-core` syscall seam. No public C ABI or TLS `errno` state
//! is involved.

use bitflags::bitflags;
use core::marker::PhantomData;

use crate::{AsFd, OwnedFd, Result};

/// The maximum size of an atomically written pipe record on Linux.
pub const PIPE_BUF: usize = 4096;

bitflags! {
    /// Flags accepted by Linux `pipe2` on AArch64.
    ///
    /// Unknown bits are retained so callers which forward a newer
    /// kernel-defined flag do not lose it before the kernel validates it.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct PipeFlags: u32 {
        /// `O_NONBLOCK`.
        const NONBLOCK = 0x0000_0800;
        /// `O_DIRECT`, enabling packet-mode pipe semantics.
        const DIRECT = 0x0001_0000;
        /// `O_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

bitflags! {
    /// Flags accepted by Linux `tee` and the related splice operations.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpliceFlags: u32 {
        /// `SPLICE_F_MOVE`.
        const MOVE = 0x0000_0001;
        /// `SPLICE_F_NONBLOCK`.
        const NONBLOCK = 0x0000_0002;
        /// `SPLICE_F_MORE`.
        const MORE = 0x0000_0004;
        /// `SPLICE_F_GIFT`.
        const GIFT = 0x0000_0008;
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// A raw-memory iovec accepted by [`vmsplice`].
///
/// This intentionally mirrors Rustix's `IoSliceRaw`: an immutable source
/// slice is represented by a mutable C pointer because Linux may retain or
/// write through that pointer depending on the pipe end supplied to
/// [`vmsplice`]. The lifetime prevents the pointed-to range from ending while
/// the descriptor operation is being prepared, but does not decide the
/// kernel's direction or retention policy.
#[repr(transparent)]
pub struct IoSliceRaw<'a> {
    iovec: crabc_core::io::Iovec,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> IoSliceRaw<'a> {
    /// Wraps an immutable source range for a pipe's write end.
    #[inline]
    pub fn from_slice(buffer: &'a [u8]) -> Self {
        Self {
            iovec: crabc_core::io::Iovec {
                // Linux's `iovec` ABI uses a mutable pointer even for a
                // source range. The borrow and vmsplice safety contract keep
                // the bytes live and govern any kernel retention.
                iov_base: buffer.as_ptr().cast_mut(),
                iov_len: buffer.len(),
            },
            _lifetime: PhantomData,
        }
    }

    /// Wraps a mutable destination range for a pipe's read end.
    #[inline]
    pub fn from_slice_mut(buffer: &'a mut [u8]) -> Self {
        Self {
            iovec: crabc_core::io::Iovec {
                iov_base: buffer.as_mut_ptr(),
                iov_len: buffer.len(),
            },
            _lifetime: PhantomData,
        }
    }
}

/// Creates a pipe with neither end nonblocking nor close-on-exec.
#[inline]
pub fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    pipe_with(PipeFlags::empty())
}

/// Creates a pipe with the requested Linux `pipe2` flags.
#[inline]
pub fn pipe_with(flags: PipeFlags) -> Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = crabc_core::pipe::pipe2(flags.bits())?;
    // SAFETY: a successful Linux `pipe2` returns two new, non-negative,
    // uniquely-owned descriptors.
    unsafe { Ok((OwnedFd::from_raw_fd(reader), OwnedFd::from_raw_fd(writer))) }
}

/// Returns a pipe's current Linux kernel capacity in bytes through
/// `fcntl(F_GETPIPE_SZ)`.
///
/// The descriptor remains borrowed, and Linux errors—including calling this
/// on a non-pipe descriptor—are returned unchanged. Capacity is an observation
/// of shared pipe state; callers must not treat it as stable if another actor
/// changes the pipe size.
#[inline]
#[doc(alias = "F_GETPIPE_SZ")]
pub fn fcntl_getpipe_size<Fd: AsFd>(fd: Fd) -> Result<usize> {
    crabc_core::pipe::fcntl_getpipe_size(fd.as_fd().as_raw_fd())
}

/// Copies up to `len` bytes from one pipe to another without consuming the
/// source pipe's data.
///
/// The returned count may be shorter than `len`; Linux errors, including
/// non-pipe descriptors or unsupported flags, remain ordinary [`crate::Errno`]
/// values. No fallback or retry is applied.
#[inline]
pub fn tee<FdIn: AsFd, FdOut: AsFd>(
    fd_in: FdIn,
    fd_out: FdOut,
    len: usize,
    flags: SpliceFlags,
) -> Result<usize> {
    crabc_core::pipe::tee_raw(
        fd_in.as_fd().as_raw_fd(),
        fd_out.as_fd().as_raw_fd(),
        len,
        flags.bits(),
    )
}

/// Transfers bytes between a file and a pipe through Linux `splice(2)`.
///
/// `off_in` and `off_out` must be `None` for pipe descriptors. For a regular
/// file, `None` uses and advances its current offset; `Some` selects an
/// explicit offset and advances that pointed-to value. Linux may return a
/// short count, which is preserved as the successful result. Explicit offsets
/// and their requested `[offset, offset + len)` ranges must fit Linux's
/// signed `loff_t`; invalid ranges return [`crate::Errno::INVAL`] before the
/// syscall and leave caller offsets unchanged.
#[inline]
pub fn splice<FdIn: AsFd, FdOut: AsFd>(
    fd_in: FdIn,
    off_in: Option<&mut u64>,
    fd_out: FdOut,
    off_out: Option<&mut u64>,
    len: usize,
    flags: SpliceFlags,
) -> Result<usize> {
    let max_loff_t = i64::MAX as u64;
    let len_as_u64 = len as u64;
    let in_initial = off_in.as_ref().map(|offset| **offset);
    let out_initial = off_out.as_ref().map(|offset| **offset);
    let range_fits = |offset: Option<u64>| {
        offset.map_or(true, |offset| {
            offset <= max_loff_t
                && len_as_u64 <= max_loff_t
                && offset
                    .checked_add(len_as_u64)
                    .map_or(false, |end| end <= max_loff_t)
        })
    };
    if !range_fits(in_initial) || !range_fits(out_initial) {
        return Err(crate::Errno::INVAL);
    }
    // Stage explicit offsets so an error cannot expose a kernel-side partial
    // update through the caller's mutable references.
    let mut in_offset = in_initial;
    let mut out_offset = out_initial;
    let in_fd = fd_in.as_fd();
    let out_fd = fd_out.as_fd();
    // SAFETY: The descriptor borrows and optional offset borrows remain live
    // for the direct syscall. The core seam documents the kernel's splice
    // direction and offset-pointer requirements.
    let copied = unsafe {
        crabc_core::pipe::splice_raw(
            in_fd.as_raw_fd(),
            in_offset
                .as_mut()
                .map_or(core::ptr::null_mut(), |offset| offset as *mut u64),
            out_fd.as_raw_fd(),
            out_offset
                .as_mut()
                .map_or(core::ptr::null_mut(), |offset| offset as *mut u64),
            len,
            flags.bits(),
        )
    }?;
    // Commit only after a successful full or short transfer. `None` selects
    // and advances the descriptor's shared offset in the kernel, so there is
    // no caller-owned value to commit in that form.
    if let (Some(offset), Some(updated)) = (off_in, in_offset) {
        *offset = updated;
    }
    if let (Some(offset), Some(updated)) = (off_out, out_offset) {
        *offset = updated;
    }
    Ok(copied)
}

/// Transfers raw memory to or from a pipe through Linux `vmsplice(2)`.
///
/// # Safety
///
/// The caller must supply the pipe end matching the buffers' direction. With
/// [`SpliceFlags::GIFT`], every range must be page-aligned, have a page-sized
/// length, and remain unmodified and unreused after the kernel accepts it.
/// Without `GIFT`, Linux may still retain source pages for the pipe's lifetime,
/// so the caller must follow the kernel's ordinary vmsplice lifetime rules.
#[inline]
pub unsafe fn vmsplice<PipeFd: AsFd>(
    fd: PipeFd,
    bufs: &[IoSliceRaw<'_>],
    flags: SpliceFlags,
) -> Result<usize> {
    // Rustix limits the iovec array to Linux's UIO_MAXIOV bound rather than
    // asking the kernel to reject a larger caller slice.
    let count = core::cmp::min(bufs.len(), 1024);
    let iovecs = bufs.as_ptr().cast::<crabc_core::io::Iovec>();
    // SAFETY: The caller upholds vmsplice's direction, page-retention, and
    // mutability obligations documented above. The iovec array remains live
    // for the syscall and its elements preserve their source lifetimes.
    unsafe { crabc_core::pipe::vmsplice_raw(fd.as_fd().as_raw_fd(), iovecs, count, flags.bits()) }
}
