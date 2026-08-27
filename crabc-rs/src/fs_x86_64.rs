//! Deliberately narrow Linux/x86-64 filesystem metadata and link observations.
//!
//! This module admits descriptor-based `fstat(2)`, a deliberately narrow
//! query-only `statat(2)` path-metadata boundary, caller-buffer-only
//! `readlinkat(2)` target reads, file-access advice, and file readahead. The
//! x86-64 kernel record is not interchangeable with the AArch64 record:
//! `st_nlink` and the timestamp nanoseconds are 64-bit here, and the record
//! has a distinct 144-byte layout. This private path slice admits only `CWD`
//! and `AT_SYMLINK_NOFOLLOW` for metadata, plus the direct caller-buffer
//! readlink target boundary; `AT_EMPTY_PATH`, a general path module, `statx`,
//! filesystem statistics, allocation-backed path helpers, and mutating
//! filesystem operations remain outside this staged target boundary until
//! they have their own x86-64 evidence.

use bitflags::bitflags;
use crate::buffer::Buffer;
use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::num::NonZeroU64;

use crate::{AsFd, BorrowedFd, Errno, Result};

/// The largest byte pathname accepted by the fixed-stack [`PathArg`] boundary.
///
/// One byte is reserved for the terminating NUL. This private x86-64 metadata
/// slice deliberately does not allocate for longer paths; callers receive
/// [`Errno::NAMETOOLONG`] before a syscall instead.
pub const SMALL_PATH_BUFFER_SIZE: usize = 256;

/// A pathname input accepted by [`statat`], [`stat`], and [`readlinkat_raw`].
///
/// Implementations borrow an existing C string or form one in a fixed stack
/// buffer. The callback is invoked while that C string remains live, so the
/// safe facade never exposes a temporary raw pathname pointer. Byte-oriented
/// inputs reject interior NULs with [`Errno::INVAL`] and need not be UTF-8.
pub trait PathArg {
    /// Runs `callback` with a NUL-terminated representation of this path.
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>;
}

#[inline]
fn with_path_bytes<T, F>(bytes: &[u8], callback: F) -> Result<T>
where
    F: FnOnce(&CStr) -> Result<T>,
{
    if bytes.iter().any(|&byte| byte == 0) {
        return Err(Errno::INVAL);
    }
    if bytes.len() >= SMALL_PATH_BUFFER_SIZE {
        return Err(Errno::NAMETOOLONG);
    }

    let mut storage = [0_u8; SMALL_PATH_BUFFER_SIZE];
    storage[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: `bytes` has no NUL and is shorter than the buffer, while the
    // zero-initialized next byte is its sole terminating NUL.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(&storage[..=bytes.len()]) };
    callback(path)
}

impl PathArg for &CStr {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        callback(self)
    }
}

impl PathArg for &[u8] {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self, callback)
    }
}

impl<const LENGTH: usize> PathArg for &[u8; LENGTH] {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self, callback)
    }
}

impl PathArg for &str {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_bytes(), callback)
    }
}

/// `AT_FDCWD`, the directory token representing the current working directory.
///
/// This is a reserved Linux token rather than an owned descriptor. It is
/// accepted only as the directory argument to [`statat`] and
/// [`readlinkat_raw`] in this private x86-64 path slice and can never become
/// an owned descriptor.
pub const CWD: BorrowedFd<'static> =
    // SAFETY: `AT_FDCWD` is a reserved, non-allocatable Linux token. The
    // narrowly documented exception in `BorrowedFd::borrow_raw` permits it.
    unsafe { BorrowedFd::borrow_raw(crabc_core::AT_FDCWD) };

bitflags! {
    /// The closed `fstatat(2)` flag vocabulary admitted by [`statat`].
    ///
    /// `SYMLINK_NOFOLLOW` observes a final symlink rather than its target.
    /// `AT_EMPTY_PATH`, `AT_NO_AUTOMOUNT`, and all unknown bits remain outside
    /// this private foundation and return [`Errno::INVAL`] before a syscall.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct AtFlags: u32 {
        /// `AT_SYMLINK_NOFOLLOW`.
        const SYMLINK_NOFOLLOW = 0x0000_0100;
    }
}

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

/// Queries x86-64 Linux metadata for `path` relative to `dirfd`.
///
/// This is a private, query-only `fstatat(2)` foundation. The returned
/// [`Stat`] is exactly the 144-byte Linux/x86-64 kernel layout. `dirfd` is
/// borrowed for the direct syscall, while [`PathArg`] keeps any temporary
/// pathname storage alive until Linux has consumed it. Only
/// [`AtFlags::SYMLINK_NOFOLLOW`] is accepted; unknown bits, `AT_EMPTY_PATH`,
/// and mutating path operations are intentionally not part of this boundary.
#[inline]
#[doc(alias = "fstatat")]
pub fn statat<P: PathArg, Fd: AsFd>(dirfd: Fd, path: P, flags: AtFlags) -> Result<Stat> {
    let flags = AtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        let mut stat = MaybeUninit::<Stat>::uninit();
        // SAFETY: `PathArg` supplies a live C string and `Stat` is the complete
        // x86-64 output layout. The kernel initializes it only on success.
        unsafe {
            crabc_core::fs::statat(
                dirfd.as_raw_fd(),
                path,
                stat.as_mut_ptr().cast(),
                flags.bits(),
            )?;
        }
        // SAFETY: successful `newfstatat` initialized the complete record.
        Ok(unsafe { stat.assume_init() })
    })
}

/// Queries x86-64 Linux metadata for `path` relative to the current directory.
///
/// This is [`statat`] with [`CWD`] and no flags. It remains a private,
/// query-only metadata operation; it does not establish a general x86-64 path
/// API or filesystem mutation boundary.
#[inline]
pub fn stat<P: PathArg>(path: P) -> Result<Stat> {
    statat(CWD, path, AtFlags::empty())
}

/// Reads a symbolic-link target relative to `dirfd` into caller-owned storage.
///
/// Linux returns the exact initialized target-byte prefix and never appends a
/// NUL byte. If the supplied buffer is shorter than the target, Linux reports
/// success with the truncated prefix. A zero-length buffer returns
/// [`crate::Errno::INVAL`] from the raw kernel boundary; unlike the C wrapper,
/// this direct facade deliberately does not translate it to an empty result.
/// This boundary allocates nothing, changes no process or descriptor state,
/// and propagates kernel errors unchanged.
#[inline]
#[allow(private_interfaces)]
pub fn readlinkat_raw<P: PathArg, Fd: AsFd, Buf: Buffer<u8>>(
    dirfd: Fd,
    path: P,
    mut buffer: Buf,
) -> Result<Buf::Output> {
    let dirfd = dirfd.as_fd();
    let (pointer, length) = buffer.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        // SAFETY: `Buffer` is sealed and supplies writable storage for
        // exactly `length` bytes. `readlinkat` initializes the returned
        // prefix and does not write a terminating NUL byte.
        unsafe {
            crabc_core::fs::readlinkat_raw(
                dirfd.as_raw_fd(),
                path,
                pointer.cast(),
                length,
            )
        }
    })?;
    // SAFETY: A successful readlinkat initialized exactly the reported
    // prefix and never returns more bytes than the supplied buffer length.
    unsafe { Ok(buffer.assume_init(initialized)) }
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
