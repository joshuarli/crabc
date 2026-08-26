//! Deliberately narrow Linux/x86-64 filesystem metadata operations.
//!
//! This module currently admits only descriptor-based `fstat(2)`.  The
//! x86-64 kernel record is not interchangeable with the AArch64 record:
//! `st_nlink` and the timestamp nanoseconds are 64-bit here, and the record
//! has a distinct 144-byte layout.  Path metadata, `statx`, filesystem
//! statistics, and mutating filesystem operations remain outside this staged
//! target boundary until they have their own x86-64 evidence.

use core::mem::MaybeUninit;

use crate::{AsFd, Result};

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
