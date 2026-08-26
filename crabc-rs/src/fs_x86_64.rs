//! Deliberately narrow Linux/x86-64 filesystem metadata operations.
//!
//! This module admits descriptor-based `fstat(2)`, file-access advice, and
//! file readahead.  The
//! x86-64 kernel record is not interchangeable with the AArch64 record:
//! `st_nlink` and the timestamp nanoseconds are 64-bit here, and the record
//! has a distinct 144-byte layout.  Path metadata, `statx`, filesystem
//! statistics, and mutating filesystem operations remain outside this staged
//! target boundary until they have their own x86-64 evidence.

use core::mem::MaybeUninit;
use core::num::NonZeroU64;

use crate::{AsFd, Result};

/// The six POSIX filesystem access-pattern policies accepted by Linux
/// `fadvise64`.
///
/// This filesystem advice type is intentionally distinct from the virtual
/// memory advice types in [`crate::mm`]. The values are the Linux/POSIX ABI
/// constants and are passed directly to the x86-64 `fadvise64` syscall.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum Advice {
    /// `POSIX_FADV_NORMAL`.
    Normal = 0,
    /// `POSIX_FADV_SEQUENTIAL`.
    Sequential = 2,
    /// `POSIX_FADV_RANDOM`.
    Random = 1,
    /// `POSIX_FADV_NOREUSE`.
    NoReuse = 5,
    /// `POSIX_FADV_WILLNEED`.
    WillNeed = 3,
    /// `POSIX_FADV_DONTNEED`.
    DontNeed = 4,
}

/// Linux/x86-64 `struct stat` returned by `fstat(2)`.
///
/// This is the private-kernel-shaped record exposed by the bounded native
/// facade. Its field types and order follow the pinned musl x86-64 ABI; the
/// trailing reserved words are retained so the buffer passed to Linux is
/// exactly 144 bytes.
#[doc(alias = "struct stat")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Stat {
    /// Device identifier.
    pub st_dev: u64,
    /// Inode number.
    pub st_ino: u64,
    /// Hard-link count.
    pub st_nlink: u64,
    /// File type and permission bits.
    pub st_mode: u32,
    /// Owning user ID.
    pub st_uid: u32,
    /// Owning group ID.
    pub st_gid: u32,
    __pad0: u32,
    /// Device identifier for special files.
    pub st_rdev: u64,
    /// File size in bytes.
    pub st_size: i64,
    /// Preferred I/O block size.
    pub st_blksize: i64,
    /// Allocated 512-byte blocks.
    pub st_blocks: i64,
    /// Last-access time in seconds.
    pub st_atime: i64,
    /// Last-access time nanoseconds.
    pub st_atime_nsec: i64,
    /// Last-modification time in seconds.
    pub st_mtime: i64,
    /// Last-modification time nanoseconds.
    pub st_mtime_nsec: i64,
    /// Last-status-change time in seconds.
    pub st_ctime: i64,
    /// Last-status-change time nanoseconds.
    pub st_ctime_nsec: i64,
    __unused: [i64; 3],
}

const _: [(); 144] = [(); core::mem::size_of::<Stat>()];
const _: [(); 8] = [(); core::mem::align_of::<Stat>()];
const _: [(); 0] = [(); core::mem::offset_of!(Stat, st_dev)];
const _: [(); 8] = [(); core::mem::offset_of!(Stat, st_ino)];
const _: [(); 16] = [(); core::mem::offset_of!(Stat, st_nlink)];
const _: [(); 24] = [(); core::mem::offset_of!(Stat, st_mode)];
const _: [(); 28] = [(); core::mem::offset_of!(Stat, st_uid)];
const _: [(); 32] = [(); core::mem::offset_of!(Stat, st_gid)];
const _: [(); 40] = [(); core::mem::offset_of!(Stat, st_rdev)];
const _: [(); 48] = [(); core::mem::offset_of!(Stat, st_size)];
const _: [(); 56] = [(); core::mem::offset_of!(Stat, st_blksize)];
const _: [(); 64] = [(); core::mem::offset_of!(Stat, st_blocks)];
const _: [(); 72] = [(); core::mem::offset_of!(Stat, st_atime)];
const _: [(); 88] = [(); core::mem::offset_of!(Stat, st_mtime)];
const _: [(); 104] = [(); core::mem::offset_of!(Stat, st_ctime)];

/// Queries metadata for an open file or directory descriptor.
///
/// The descriptor is borrowed for the duration of the direct Linux syscall;
/// no libc wrapper or thread-local `errno` is involved.  The returned record
/// contains the x86-64 kernel ABI fields, including nanosecond timestamps and
/// the signed size/block fields.
#[inline]
pub fn fstat<Fd: AsFd>(fd: Fd) -> Result<Stat> {
    let fd = fd.as_fd();
    let mut stat = MaybeUninit::<Stat>::uninit();
    // SAFETY: `Stat` is the complete 144-byte Linux/x86-64 `struct stat`
    // layout, and its writable storage remains live during the syscall.
    unsafe { crabc_core::fs::fstat_raw(fd.as_raw_fd(), stat.as_mut_ptr().cast())? };
    // SAFETY: A successful `fstat` initialized the complete output record.
    Ok(unsafe { stat.assume_init() })
}

/// Gives Linux a POSIX filesystem access-pattern advisory through the native
/// x86-64 `fadvise64` syscall.
///
/// `offset` and the optional `length` are non-negative Rust quantities. Each
/// must fit Linux's signed `loff_t` argument; values above `i64::MAX` return
/// [`crate::Errno::INVAL`] before the descriptor is borrowed or a syscall is
/// issued. `None` is the Linux zero-length-to-end-of-file convention. The
/// descriptor is borrowed and its current file position is unchanged.
#[inline]
#[doc(alias = "posix_fadvise")]
pub fn fadvise<Fd: AsFd>(
    fd: Fd,
    offset: u64,
    len: Option<NonZeroU64>,
    advice: Advice,
) -> Result<()> {
    let offset = i64::try_from(offset).map_err(|_| crate::Errno::INVAL)?;
    let length = len.map_or(Ok(0), |length| {
        i64::try_from(length.get()).map_err(|_| crate::Errno::INVAL)
    })?;
    crabc_core::fs::fadvise64(fd.as_fd().as_raw_fd(), offset, length, advice as u32)
}

/// Initiates Linux file readahead for a byte range of an open file.
///
/// `offset` and `length` are unsigned byte quantities at this safe boundary.
/// The x86-64 syscall carries the offset as signed Linux `loff_t`, so values
/// above that range—or whose checked half-open end exceeds it—return
/// [`crate::Errno::INVAL`] before the direct syscall. A zero length is
/// forwarded unchanged. Successful readahead leaves the descriptor's current
/// file position unchanged.
#[inline]
pub fn readahead<Fd: AsFd>(fd: Fd, offset: u64, length: u64) -> Result<()> {
    if offset > i64::MAX as u64
        || length > i64::MAX as u64
        || offset
            .checked_add(length)
            .map_or(true, |end| end > i64::MAX as u64)
    {
        return Err(crate::Errno::INVAL);
    }

    crabc_core::fs::readahead(fd.as_fd().as_raw_fd(), offset as i64, length as usize)
}
