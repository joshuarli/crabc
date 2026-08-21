//! Direct Linux/AArch64 filesystem operations.
//!
//! Filesystem operations use the shared stateless Linux/AArch64 syscall seams.
//! They exercise path, descriptor, flag, mode, ownership, and typed error
//! contracts without crossing into libc's process-global runtime state.

use bitflags::bitflags;
use core::mem::MaybeUninit;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::buffer::Buffer;
use crate::{path::Arg, AsFd, BorrowedFd, OwnedFd, Result};

pub use crate::{RawDir, RawDirEntry};

/// `AT_FDCWD`, a directory token representing the current working directory.
///
/// It is a reserved Linux token rather than an owned descriptor. It is safe to
/// borrow for `*at` APIs and can never be converted into [`OwnedFd`].
pub const CWD: BorrowedFd<'static> =
    // SAFETY: `AT_FDCWD` is a reserved, non-allocatable Linux token. See the
    // narrowly documented exception in `BorrowedFd::borrow_raw`.
    unsafe { BorrowedFd::borrow_raw(crabc_core::AT_FDCWD) };

/// A special directory token which requires an absolute path.
///
/// Linux has no `AT_ABS` constant. Rustix conventionally passes `-EBADF`, a
/// non-allocatable invalid descriptor, so an absolute path ignores `dirfd`
/// while a relative path deterministically fails with `EBADF`.
pub const ABS: BorrowedFd<'static> =
    // SAFETY: `-EBADF` is a documented Rustix convention for `*at` operations
    // and `BorrowedFd::borrow_raw` accepts this narrowly scoped token.
    unsafe { BorrowedFd::borrow_raw(-9) };

bitflags! {
    /// `O_*` flags accepted by [`openat`] on Linux/AArch64.
    ///
    /// Unknown bits are preserved so callers forwarding kernel-defined flags
    /// do not lose information as Linux grows new values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct OFlags: u32 {
        /// `O_ACCMODE`.
        const ACCMODE = 0x0000_0003;
        /// The read/write portion of [`Self::ACCMODE`].
        const RWMODE = Self::ACCMODE.bits();
        /// Read-only access. This bit pattern is zero.
        const RDONLY = 0;
        /// `O_WRONLY`.
        const WRONLY = 0x0000_0001;
        /// `O_RDWR`.
        const RDWR = 0x0000_0002;
        /// `O_CREAT`.
        const CREATE = 0x0000_0040;
        /// `O_EXCL`.
        const EXCL = 0x0000_0080;
        /// `O_NOCTTY`.
        const NOCTTY = 0x0000_0100;
        /// `O_TRUNC`.
        const TRUNC = 0x0000_0200;
        /// `O_APPEND`.
        const APPEND = 0x0000_0400;
        /// `O_NONBLOCK`.
        const NONBLOCK = 0x0000_0800;
        /// `O_DSYNC`.
        const DSYNC = 0x0000_1000;
        /// `O_ASYNC`/`FASYNC`.
        const ASYNC = 0x0000_2000;
        /// `O_DIRECTORY` in crabc's pinned Linux/AArch64 headers.
        const DIRECTORY = 0x0000_4000;
        /// `O_NOFOLLOW` in crabc's pinned Linux/AArch64 headers.
        const NOFOLLOW = 0x0000_8000;
        /// `O_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
        /// `O_SYNC`.
        const SYNC = 0x0010_1000;
        /// `O_FSYNC`, an alias of [`Self::SYNC`].
        const FSYNC = Self::SYNC.bits();
        /// `O_RSYNC`, an alias of [`Self::SYNC`].
        const RSYNC = Self::SYNC.bits();
        /// `O_DIRECT`.
        const DIRECT = 0x0001_0000;
        /// `O_LARGEFILE`.
        const LARGEFILE = 0x0002_0000;
        /// `O_NOATIME`.
        const NOATIME = 0x0004_0000;
        /// `O_PATH`.
        const PATH = 0x0020_0000;
        /// `O_TMPFILE`.
        const TMPFILE = 0x0040_4000;
        /// Preserve future kernel-defined bits.
        const _ = !0;
    }
}

bitflags! {
    /// `RESOLVE_*` flags accepted by Linux [`openat2`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct ResolveFlags: u64 {
        /// `RESOLVE_NO_XDEV`.
        const NO_XDEV = 0x01;
        /// `RESOLVE_NO_MAGICLINKS`.
        const NO_MAGICLINKS = 0x02;
        /// `RESOLVE_NO_SYMLINKS`.
        const NO_SYMLINKS = 0x04;
        /// `RESOLVE_BENEATH`.
        const BENEATH = 0x08;
        /// `RESOLVE_IN_ROOT`.
        const IN_ROOT = 0x10;
        /// `RESOLVE_CACHED`.
        const CACHED = 0x20;
        /// Preserve future Linux-defined flags.
        const _ = !0;
    }
}

bitflags! {
    /// `XATTR_*` flags accepted by Linux extended-attribute setters.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct XattrFlags: u32 {
        /// `XATTR_CREATE`: fail if the named attribute already exists.
        const CREATE = 0x1;
        /// `XATTR_REPLACE`: fail if the named attribute does not exist.
        const REPLACE = 0x2;
        /// Preserve future Linux-defined flags.
        const _ = !0;
    }
}

bitflags! {
    /// `RENAME_*` flags accepted by Linux `renameat2`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct RenameFlags: u32 {
        /// `RENAME_EXCHANGE`.
        const EXCHANGE = 0x2;
        /// `RENAME_NOREPLACE`.
        const NOREPLACE = 0x1;
        /// `RENAME_WHITEOUT`.
        const WHITEOUT = 0x4;
        /// Preserve future Linux-defined flags.
        const _ = !0;
    }
}

bitflags! {
    /// File creation-permission bits for [`openat`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct Mode: u32 {
        /// Owner read permission.
        const RUSR = 0o400;
        /// Owner write permission.
        const WUSR = 0o200;
        /// Owner execute/search permission.
        const XUSR = 0o100;
        /// Group read permission.
        const RGRP = 0o040;
        /// Group write permission.
        const WGRP = 0o020;
        /// Group execute/search permission.
        const XGRP = 0o010;
        /// Other read permission.
        const ROTH = 0o004;
        /// Other write permission.
        const WOTH = 0o002;
        /// Other execute/search permission.
        const XOTH = 0o001;
        /// Owner read/write/execute permission.
        const RWXU = Self::RUSR.bits() | Self::WUSR.bits() | Self::XUSR.bits();
        /// Group read/write/execute permission.
        const RWXG = Self::RGRP.bits() | Self::WGRP.bits() | Self::XGRP.bits();
        /// Other read/write/execute permission.
        const RWXO = Self::ROTH.bits() | Self::WOTH.bits() | Self::XOTH.bits();
        /// Set-user-ID bit.
        const SUID = 0o4000;
        /// Set-group-ID bit.
        const SGID = 0o2000;
        /// Sticky bit.
        const STICKY = 0o1000;
        /// `S_ISVTX`, the Rustix spelling for the sticky bit.
        const SVTX = Self::STICKY.bits();
        /// Preserve future Linux mode bits.
        const _ = !0;
    }
}

/// Raw Linux `st_mode` bits.
pub type RawMode = u32;

impl Mode {
    /// Extracts permission bits from a Linux `st_mode` value.
    #[inline]
    pub const fn from_raw_mode(st_mode: RawMode) -> Self {
        Self::from_bits_truncate(st_mode & !0o170000)
    }

    /// Returns this value in the Linux `st_mode` representation.
    #[inline]
    pub const fn as_raw_mode(self) -> RawMode {
        self.bits()
    }
}

impl From<RawMode> for Mode {
    #[inline]
    fn from(st_mode: RawMode) -> Self {
        Self::from_raw_mode(st_mode)
    }
}

impl From<Mode> for RawMode {
    #[inline]
    fn from(mode: Mode) -> Self {
        mode.as_raw_mode()
    }
}

bitflags! {
    /// `AT_*` flags accepted by filesystem operations on Linux/AArch64.
    ///
    /// Linux reuses some flag bits for different syscall families. Preserve
    /// them verbatim here; each operation documents the subset its kernel
    /// syscall accepts.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct AtFlags: u32 {
        /// `AT_SYMLINK_NOFOLLOW`.
        const SYMLINK_NOFOLLOW = 0x100;
        /// `AT_EACCESS` for access checks.
        const EACCESS = 0x200;
        /// `AT_REMOVEDIR` for `unlinkat`.
        const REMOVEDIR = 0x200;
        /// `AT_SYMLINK_FOLLOW` for `linkat`.
        const SYMLINK_FOLLOW = 0x400;
        /// `AT_NO_AUTOMOUNT` for metadata queries.
        const NO_AUTOMOUNT = 0x800;
        /// `AT_EMPTY_PATH` for supported Linux `*at` operations.
        const EMPTY_PATH = 0x1000;
        /// `AT_STATX_SYNC_AS_STAT` (the zero-valued default).
        const STATX_SYNC_AS_STAT = 0;
        /// `AT_STATX_FORCE_SYNC`.
        const STATX_FORCE_SYNC = 0x2000;
        /// `AT_STATX_DONT_SYNC`.
        const STATX_DONT_SYNC = 0x4000;
        /// Preserve future Linux-defined flags.
        const _ = !0;
    }
}

/// A file kind encoded in Linux `st_mode` or `getdents64` records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    /// `S_IFREG`.
    RegularFile,
    /// `S_IFDIR`.
    Directory,
    /// `S_IFLNK`.
    Symlink,
    /// `S_IFIFO`.
    Fifo,
    /// `S_IFSOCK`.
    Socket,
    /// `S_IFCHR`.
    CharacterDevice,
    /// `S_IFBLK`.
    BlockDevice,
    /// An unrecognized Linux file kind.
    Unknown,
}

impl FileType {
    /// Interprets the file-kind bits in a Linux `st_mode` value.
    #[inline]
    pub const fn from_raw_mode(st_mode: RawMode) -> Self {
        match st_mode & 0o170000 {
            0o100000 => Self::RegularFile,
            0o040000 => Self::Directory,
            0o120000 => Self::Symlink,
            0o010000 => Self::Fifo,
            0o140000 => Self::Socket,
            0o020000 => Self::CharacterDevice,
            0o060000 => Self::BlockDevice,
            _ => Self::Unknown,
        }
    }

    /// Returns this value in the Linux `st_mode` representation.
    #[inline]
    pub const fn as_raw_mode(self) -> RawMode {
        match self {
            Self::RegularFile => 0o100000,
            Self::Directory => 0o040000,
            Self::Symlink => 0o120000,
            Self::Fifo => 0o010000,
            Self::Socket => 0o140000,
            Self::CharacterDevice => 0o020000,
            Self::BlockDevice => 0o060000,
            Self::Unknown => 0o170000,
        }
    }

    #[inline]
    pub(crate) const fn from_dirent_d_type(d_type: u8) -> Self {
        match d_type {
            1 => Self::Fifo,
            2 => Self::CharacterDevice,
            4 => Self::Directory,
            6 => Self::BlockDevice,
            8 => Self::RegularFile,
            10 => Self::Symlink,
            12 => Self::Socket,
            _ => Self::Unknown,
        }
    }
}

/// Linux/AArch64 `struct stat` metadata.
///
/// This is deliberately `repr(C)` and matches the kernel ABI consumed by
/// `fstat` and `newfstatat`, not crabc's public C `struct stat` definition.
/// The fields are the Rustix Linux/AArch64 surface; padding stays private so
/// callers do not accidentally depend on it.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct Stat {
    /// Device identifier.
    pub st_dev: u64,
    /// Inode number.
    pub st_ino: u64,
    /// File type and permission bits.
    pub st_mode: u32,
    /// Hard-link count.
    pub st_nlink: u32,
    /// Owning user ID.
    pub st_uid: u32,
    /// Owning group ID.
    pub st_gid: u32,
    /// Device identifier for special files.
    pub st_rdev: u64,
    __pad1: u64,
    /// Size in bytes.
    pub st_size: i64,
    /// Preferred I/O block size.
    pub st_blksize: i32,
    __pad2: i32,
    /// Allocated 512-byte blocks.
    pub st_blocks: i64,
    /// Last-access time in seconds.
    pub st_atime: i64,
    /// Last-access nanoseconds.
    pub st_atime_nsec: u64,
    /// Last-modification time in seconds.
    pub st_mtime: i64,
    /// Last-modification nanoseconds.
    pub st_mtime_nsec: u64,
    /// Last-status-change time in seconds.
    pub st_ctime: i64,
    /// Last-status-change nanoseconds.
    pub st_ctime_nsec: u64,
    __unused4: u32,
    __unused5: u32,
}

/// Seconds in a Linux `timespec`.
pub type Secs = i64;

/// Nanoseconds in a Linux `timespec`.
pub type Nsecs = i64;

/// A Linux `timespec` value.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: Secs,
    /// Nanoseconds, or [`UTIME_NOW`]/[`UTIME_OMIT`] for timestamp updates.
    pub tv_nsec: Nsecs,
}

/// The current time sentinel accepted in [`Timespec::tv_nsec`] by Linux
/// `utimensat`.
pub const UTIME_NOW: Nsecs = 0x3fff_ffff;

/// The leave-unchanged sentinel accepted in [`Timespec::tv_nsec`] by Linux
/// `utimensat`.
pub const UTIME_OMIT: Nsecs = 0x3fff_fffe;

/// The access and modification timestamps consumed by `utimensat` and
/// `futimens`.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Timestamps {
    /// Last-access timestamp.
    pub last_access: Timespec,
    /// Last-modification timestamp.
    pub last_modification: Timespec,
}

/// Linux advisory-lock operations accepted by [`flock`] and [`fcntl_lock`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FlockOperation {
    /// Acquire a shared lock, waiting if needed.
    LockShared = 1,
    /// Acquire an exclusive lock, waiting if needed.
    LockExclusive = 2,
    /// Release a lock.
    Unlock = 8,
    /// Acquire a shared lock without waiting.
    NonBlockingLockShared = 1 | 4,
    /// Acquire an exclusive lock without waiting.
    NonBlockingLockExclusive = 2 | 4,
    /// Release a lock without waiting.
    NonBlockingUnlock = 8 | 4,
}

/// Enumeration of possible methods to seek within an open file descriptor.
///
/// This follows Rustix's Linux `SeekFrom` vocabulary. `Data` and `Hole` map to
/// Linux sparse-file seeking and are available on this target in addition to
/// the portable `Start`, `End`, and `Current` variants.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SeekFrom {
    /// Set the offset to the provided absolute byte position.
    Start(u64),
    /// Set the offset relative to the end of the file.
    End(i64),
    /// Set the offset relative to the current file position.
    Current(i64),
    /// Seek to the next data region at or after the provided offset.
    Data(u64),
    /// Seek to the next hole at or after the provided offset.
    Hole(u64),
}

/// Opens `path` relative to `dirfd`.
///
/// The call directly reaches the Linux `openat` syscall through the shared
/// `crabc-core` implementation. A successful descriptor is returned as an
/// RAII owner; a failure is returned directly as [`crate::Errno`].
#[inline]
pub fn openat<P: Arg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    oflags: OFlags,
    create_mode: Mode,
) -> Result<OwnedFd> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        crabc_core::fs::openat(
            dirfd.as_raw_fd(),
            path,
            oflags.bits() as i32,
            create_mode.bits(),
        )
        .map(|fd| {
            // SAFETY: A successful `openat` returns a newly owned non-negative
            // descriptor. This is the sole transfer into the RAII wrapper.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
    })
}

/// Opens `path` relative to the process current directory.
#[inline]
pub fn open<P: Arg>(path: P, oflags: OFlags, create_mode: Mode) -> Result<OwnedFd> {
    openat(CWD, path, oflags, create_mode)
}

/// Repositions an open file descriptor using Linux's `lseek` operation.
///
/// The returned offset is an unsigned byte position, matching Rustix. An
/// absolute offset larger than `i64::MAX` is passed through to Linux's signed
/// `off_t` representation and therefore receives the kernel's normal
/// `EINVAL` result when it becomes negative.
#[inline]
#[doc(alias = "lseek")]
pub fn seek<Fd: AsFd>(fd: Fd, position: SeekFrom) -> Result<u64> {
    let (whence, offset) = match position {
        SeekFrom::Start(offset) => (crabc_core::fs::SEEK_SET, offset as i64),
        SeekFrom::End(offset) => (crabc_core::fs::SEEK_END, offset),
        SeekFrom::Current(offset) => (crabc_core::fs::SEEK_CUR, offset),
        SeekFrom::Data(offset) => (crabc_core::fs::SEEK_DATA, offset as i64),
        SeekFrom::Hole(offset) => (crabc_core::fs::SEEK_HOLE, offset as i64),
    };
    // Linux reports successful file offsets as non-negative signed `off_t`
    // values; the cast preserves that kernel result in Rustix's `u64` API.
    crabc_core::fs::lseek(fd.as_fd().as_raw_fd(), offset, whence).map(|offset| offset as u64)
}

/// Returns the current offset of an open file descriptor without changing it.
#[inline]
#[doc(alias = "lseek")]
pub fn tell<Fd: AsFd>(fd: Fd) -> Result<u64> {
    crabc_core::fs::lseek(fd.as_fd().as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)
        .map(|offset| offset as u64)
}

/// Flushes file data and metadata for an open file descriptor.
#[inline]
pub fn fsync<Fd: AsFd>(fd: Fd) -> Result<()> {
    crabc_core::fs::fsync(fd.as_fd().as_raw_fd())
}

/// Flushes file data for an open file descriptor.
#[inline]
pub fn fdatasync<Fd: AsFd>(fd: Fd) -> Result<()> {
    crabc_core::fs::fdatasync(fd.as_fd().as_raw_fd())
}

/// Sets the length of an open file descriptor.
///
/// The length uses Rustix's unsigned byte-count API and is passed to the
/// Linux `loff_t` syscall representation without a separate libc conversion.
#[inline]
pub fn ftruncate<Fd: AsFd>(fd: Fd, length: u64) -> Result<()> {
    crabc_core::fs::ftruncate(fd.as_fd().as_raw_fd(), length as i64)
}

/// Opens `path` relative to `dirfd` with Linux `openat2` resolution controls.
///
/// `O_LARGEFILE` is not synthesized on Linux/AArch64: as in Rustix's pinned
/// 64-bit backend, the supplied flag representation is passed unchanged.
#[inline]
pub fn openat2<P: Arg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    oflags: OFlags,
    create_mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        crabc_core::fs::openat2(
            dirfd.as_raw_fd(),
            path,
            oflags.bits() as u64,
            create_mode.bits() as u64,
            resolve.bits(),
        )
        .map(|fd| {
            // SAFETY: A successful openat2 returns a newly owned
            // non-negative descriptor, transferring ownership exactly once.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
    })
}

/// Reads an extended attribute into caller-provided storage.
#[inline]
pub fn getxattr<P: Arg, Name: Arg, Buf: Buffer<u8>>(
    path: P,
    name: Name,
    mut value: Buf,
) -> Result<Buf::Output> {
    let (pointer, length) = value.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: `Buffer` supplies writable output storage and both
            // arguments supply NUL-terminated pathnames for this syscall.
            unsafe {
                crabc_core::fs::getxattr_raw(
                    path.as_ptr().cast(),
                    name.as_ptr().cast(),
                    pointer,
                    length,
                )
            }
        })
    })?;
    // SAFETY: A successful getxattr initialized exactly the returned prefix.
    unsafe { Ok(value.assume_init(initialized)) }
}

/// Reads an extended attribute without following a final symbolic link.
#[inline]
pub fn lgetxattr<P: Arg, Name: Arg, Buf: Buffer<u8>>(
    path: P,
    name: Name,
    mut value: Buf,
) -> Result<Buf::Output> {
    let (pointer, length) = value.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: `Buffer` supplies writable output storage and both
            // arguments supply NUL-terminated pathnames for this syscall.
            unsafe {
                crabc_core::fs::lgetxattr_raw(
                    path.as_ptr().cast(),
                    name.as_ptr().cast(),
                    pointer,
                    length,
                )
            }
        })
    })?;
    // SAFETY: A successful lgetxattr initialized exactly the returned prefix.
    unsafe { Ok(value.assume_init(initialized)) }
}

/// Reads a descriptor extended attribute into caller-provided storage.
#[inline]
pub fn fgetxattr<Fd: AsFd, Name: Arg, Buf: Buffer<u8>>(
    fd: Fd,
    name: Name,
    mut value: Buf,
) -> Result<Buf::Output> {
    let fd = fd.as_fd();
    let (pointer, length) = value.parts_mut();
    let initialized = name.into_with_c_str(|name| {
        // SAFETY: `Buffer` supplies writable output storage and `name` is a
        // NUL-terminated pathname for the direct syscall.
        unsafe {
            crabc_core::fs::fgetxattr_raw(
                fd.as_raw_fd(),
                name.as_ptr().cast(),
                pointer,
                length,
            )
        }
    })?;
    // SAFETY: A successful fgetxattr initialized exactly the returned prefix.
    unsafe { Ok(value.assume_init(initialized)) }
}

/// Sets an extended attribute on a path.
#[inline]
pub fn setxattr<P: Arg, Name: Arg>(
    path: P,
    name: Name,
    value: &[u8],
    flags: XattrFlags,
) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: `path` and `name` are NUL-terminated; `value` remains
            // readable for its exact slice length through the syscall.
            unsafe {
                crabc_core::fs::setxattr_raw(
                    path.as_ptr().cast(),
                    name.as_ptr().cast(),
                    value.as_ptr(),
                    value.len(),
                    flags.bits(),
                )
            }
        })
    })
}

/// Sets an extended attribute without following a final symbolic link.
#[inline]
pub fn lsetxattr<P: Arg, Name: Arg>(
    path: P,
    name: Name,
    value: &[u8],
    flags: XattrFlags,
) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: `path` and `name` are NUL-terminated; `value` remains
            // readable for its exact slice length through the syscall.
            unsafe {
                crabc_core::fs::lsetxattr_raw(
                    path.as_ptr().cast(),
                    name.as_ptr().cast(),
                    value.as_ptr(),
                    value.len(),
                    flags.bits(),
                )
            }
        })
    })
}

/// Sets an extended attribute on an open descriptor.
#[inline]
pub fn fsetxattr<Fd: AsFd, Name: Arg>(
    fd: Fd,
    name: Name,
    value: &[u8],
    flags: XattrFlags,
) -> Result<()> {
    let fd = fd.as_fd();
    name.into_with_c_str(|name| {
        // SAFETY: `name` is NUL-terminated and `value` remains readable for
        // its exact slice length through the direct syscall.
        unsafe {
            crabc_core::fs::fsetxattr_raw(
                fd.as_raw_fd(),
                name.as_ptr().cast(),
                value.as_ptr(),
                value.len(),
                flags.bits(),
            )
        }
    })
}

/// Lists extended attribute names into caller-provided storage.
#[inline]
pub fn listxattr<P: Arg, Buf: Buffer<u8>>(path: P, mut list: Buf) -> Result<Buf::Output> {
    let (pointer, length) = list.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        // SAFETY: `Buffer` supplies writable output storage and `path` is a
        // NUL-terminated pathname for this syscall.
        unsafe { crabc_core::fs::listxattr_raw(path.as_ptr().cast(), pointer, length) }
    })?;
    // SAFETY: A successful listxattr initialized exactly the returned prefix.
    unsafe { Ok(list.assume_init(initialized)) }
}

/// Lists extended attribute names without following a final symbolic link.
#[inline]
pub fn llistxattr<P: Arg, Buf: Buffer<u8>>(path: P, mut list: Buf) -> Result<Buf::Output> {
    let (pointer, length) = list.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        // SAFETY: `Buffer` supplies writable output storage and `path` is a
        // NUL-terminated pathname for this syscall.
        unsafe { crabc_core::fs::llistxattr_raw(path.as_ptr().cast(), pointer, length) }
    })?;
    // SAFETY: A successful llistxattr initialized exactly the returned prefix.
    unsafe { Ok(list.assume_init(initialized)) }
}

/// Lists descriptor extended-attribute names into caller-provided storage.
#[inline]
pub fn flistxattr<Fd: AsFd, Buf: Buffer<u8>>(fd: Fd, mut list: Buf) -> Result<Buf::Output> {
    let fd = fd.as_fd();
    let (pointer, length) = list.parts_mut();
    // SAFETY: `Buffer` supplies writable output storage for the direct
    // syscall, and the descriptor borrow remains live for it.
    let initialized = unsafe { crabc_core::fs::flistxattr_raw(fd.as_raw_fd(), pointer, length) }?;
    // SAFETY: A successful flistxattr initialized exactly the returned prefix.
    unsafe { Ok(list.assume_init(initialized)) }
}

/// Removes an extended attribute from a path.
#[inline]
pub fn removexattr<P: Arg, Name: Arg>(path: P, name: Name) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: Both arguments are NUL-terminated pathnames for the
            // duration of this direct syscall.
            unsafe { crabc_core::fs::removexattr_raw(path.as_ptr().cast(), name.as_ptr().cast()) }
        })
    })
}

/// Removes an extended attribute without following a final symbolic link.
#[inline]
pub fn lremovexattr<P: Arg, Name: Arg>(path: P, name: Name) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: Both arguments are NUL-terminated pathnames for the
            // duration of this direct syscall.
            unsafe { crabc_core::fs::lremovexattr_raw(path.as_ptr().cast(), name.as_ptr().cast()) }
        })
    })
}

/// Removes an extended attribute from an open descriptor.
#[inline]
pub fn fremovexattr<Fd: AsFd, Name: Arg>(fd: Fd, name: Name) -> Result<()> {
    let fd = fd.as_fd();
    name.into_with_c_str(|name| {
        // SAFETY: `name` is a NUL-terminated pathname for the duration of
        // this direct syscall; Linux validates the descriptor.
        unsafe { crabc_core::fs::fremovexattr_raw(fd.as_raw_fd(), name.as_ptr().cast()) }
    })
}

/// Queries metadata for an open file or directory.
#[inline]
pub fn fstat<Fd: AsFd>(fd: Fd) -> Result<Stat> {
    let fd = fd.as_fd();
    let mut stat = MaybeUninit::<Stat>::uninit();
    // SAFETY: `Stat` exactly matches the Linux/AArch64 output layout, and its
    // writable `MaybeUninit` storage remains live throughout the syscall.
    unsafe { crabc_core::fs::fstat_raw(fd.as_raw_fd(), stat.as_mut_ptr().cast())? };
    // SAFETY: A successful fstat initialized the complete `Stat` object.
    Ok(unsafe { stat.assume_init() })
}

/// Queries metadata for `path` relative to `dirfd`.
///
/// This is Rustix's `fstatat` spelling. Use [`AtFlags::SYMLINK_NOFOLLOW`] to
/// query a symbolic link itself rather than its target.
#[inline]
#[doc(alias = "fstatat")]
pub fn statat<P: Arg, Fd: AsFd>(dirfd: Fd, path: P, flags: AtFlags) -> Result<Stat> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        let mut stat = MaybeUninit::<Stat>::uninit();
        // SAFETY: `Stat` exactly matches the Linux/AArch64 output layout, and
        // `path`/the output storage remain live for the direct syscall.
        unsafe {
            crabc_core::fs::statat(
                dirfd.as_raw_fd(),
                path,
                stat.as_mut_ptr().cast(),
                flags.bits(),
            )?
        };
        // SAFETY: A successful newfstatat initialized the complete `Stat`.
        Ok(unsafe { stat.assume_init() })
    })
}

/// Queries metadata for `path` relative to the process current directory.
#[inline]
pub fn stat<P: Arg>(path: P) -> Result<Stat> {
    statat(CWD, path, AtFlags::empty())
}

/// Queries metadata for `path` without following a final symbolic link.
#[inline]
pub fn lstat<P: Arg>(path: P) -> Result<Stat> {
    statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
}

/// Removes a file or, with [`AtFlags::REMOVEDIR`], an empty directory.
#[inline]
pub fn unlinkat<P: Arg, Fd: AsFd>(dirfd: Fd, path: P, flags: AtFlags) -> Result<()> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| crabc_core::fs::unlinkat(dirfd.as_raw_fd(), path, flags.bits()))
}

/// Creates a directory relative to `dirfd`.
#[inline]
pub fn mkdirat<P: Arg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode) -> Result<()> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| crabc_core::fs::mkdirat(dirfd.as_raw_fd(), path, mode.bits()))
}

/// Creates a directory relative to the process current directory.
#[inline]
pub fn mkdir<P: Arg>(path: P, mode: Mode) -> Result<()> {
    mkdirat(CWD, path, mode)
}

/// Removes a file relative to the process current directory.
#[inline]
pub fn unlink<P: Arg>(path: P) -> Result<()> {
    unlinkat(CWD, path, AtFlags::empty())
}

/// Removes an empty directory relative to the process current directory.
#[inline]
pub fn rmdir<P: Arg>(path: P) -> Result<()> {
    unlinkat(CWD, path, AtFlags::REMOVEDIR)
}

/// Reads a symbolic-link target relative to `dirfd` into a caller-provided
/// buffer, without allocating or appending a NUL byte.
#[inline]
pub fn readlinkat_raw<P: Arg, Fd: AsFd, Buf: Buffer<u8>>(
    dirfd: Fd,
    path: P,
    mut buffer: Buf,
) -> Result<Buf::Output> {
    let dirfd = dirfd.as_fd();
    let (pointer, length) = buffer.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        // SAFETY: `Buffer` is sealed and supplies writable storage for
        // exactly `length` bytes. readlinkat initializes the returned prefix.
        unsafe { crabc_core::fs::readlinkat_raw(dirfd.as_raw_fd(), path, pointer.cast(), length) }
    })?;
    // SAFETY: A successful readlinkat initialized exactly the reported prefix
    // and never returns more bytes than the supplied buffer length.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Reads a symbolic-link target relative to `dirfd`.
///
/// The supplied vector is reused when possible. The result is a `CString`
/// because Linux link targets are byte pathnames and never contain an
/// embedded NUL.
#[cfg(feature = "alloc")]
#[inline]
pub fn readlinkat<P: Arg, Fd: AsFd, B: Into<Vec<u8>>>(
    dirfd: Fd,
    path: P,
    reuse: B,
) -> Result<CString> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        let mut buffer = reuse.into();
        buffer.clear();
        buffer.reserve(crate::path::SMALL_PATH_BUFFER_SIZE);

        loop {
            let capacity = buffer.capacity();
            let spare = buffer.spare_capacity_mut();
            // SAFETY: the vector spare capacity is writable for its exact
            // length and remains live for the duration of this syscall.
            let length = unsafe {
                crabc_core::fs::readlinkat_raw(
                    dirfd.as_raw_fd(),
                    path,
                    spare.as_mut_ptr().cast(),
                    spare.len(),
                )?
            };
            if length < capacity {
                // SAFETY: Linux readlinkat returns a pathname byte sequence,
                // which cannot contain NUL. The successful return proves this
                // exact prefix was initialized before it is committed.
                unsafe {
                    buffer.set_len(length);
                    return Ok(CString::from_vec_unchecked(buffer));
                }
            }
            buffer.reserve(capacity.saturating_add(1));
        }
    })
}

/// Reads a symbolic-link target relative to the process current directory.
#[cfg(feature = "alloc")]
#[inline]
pub fn readlink<P: Arg, B: Into<Vec<u8>>>(path: P, reuse: B) -> Result<CString> {
    readlinkat(CWD, path, reuse)
}

/// Creates a hard link between two paths relative to their directory
/// descriptors.
#[inline]
pub fn linkat<P: Arg, Q: Arg, PFd: AsFd, QFd: AsFd>(
    old_dirfd: PFd,
    old_path: P,
    new_dirfd: QFd,
    new_path: Q,
    flags: AtFlags,
) -> Result<()> {
    let old_dirfd = old_dirfd.as_fd();
    let new_dirfd = new_dirfd.as_fd();
    old_path.into_with_c_str(|old_path| {
        new_path.into_with_c_str(|new_path| {
            crabc_core::fs::linkat(
                old_dirfd.as_raw_fd(),
                old_path,
                new_dirfd.as_raw_fd(),
                new_path,
                flags.bits(),
            )
        })
    })
}

/// Creates a hard link relative to the process current directory.
#[inline]
pub fn link<P: Arg, Q: Arg>(old_path: P, new_path: Q) -> Result<()> {
    linkat(CWD, old_path, CWD, new_path, AtFlags::empty())
}

/// Creates a symbolic link relative to `new_dirfd`.
#[inline]
pub fn symlinkat<P: Arg, Q: Arg, Fd: AsFd>(
    target: P,
    new_dirfd: Fd,
    new_path: Q,
) -> Result<()> {
    let new_dirfd = new_dirfd.as_fd();
    target.into_with_c_str(|target| {
        new_path.into_with_c_str(|new_path| {
            crabc_core::fs::symlinkat(target, new_dirfd.as_raw_fd(), new_path)
        })
    })
}

/// Creates a symbolic link relative to the process current directory.
#[inline]
pub fn symlink<P: Arg, Q: Arg>(target: P, new_path: Q) -> Result<()> {
    symlinkat(target, CWD, new_path)
}

/// Renames a path or directory without special Linux rename flags.
#[inline]
pub fn renameat<P: Arg, Q: Arg, PFd: AsFd, QFd: AsFd>(
    old_dirfd: PFd,
    old_path: P,
    new_dirfd: QFd,
    new_path: Q,
) -> Result<()> {
    renameat_with(old_dirfd, old_path, new_dirfd, new_path, RenameFlags::empty())
}

/// Renames a path or directory with Linux `renameat2` flags.
#[inline]
pub fn renameat_with<P: Arg, Q: Arg, PFd: AsFd, QFd: AsFd>(
    old_dirfd: PFd,
    old_path: P,
    new_dirfd: QFd,
    new_path: Q,
    flags: RenameFlags,
) -> Result<()> {
    let old_dirfd = old_dirfd.as_fd();
    let new_dirfd = new_dirfd.as_fd();
    old_path.into_with_c_str(|old_path| {
        new_path.into_with_c_str(|new_path| {
            crabc_core::fs::renameat2(
                old_dirfd.as_raw_fd(),
                old_path,
                new_dirfd.as_raw_fd(),
                new_path,
                flags.bits(),
            )
        })
    })
}

/// Renames a path or directory relative to the process current directory.
#[inline]
pub fn rename<P: Arg, Q: Arg>(old_path: P, new_path: Q) -> Result<()> {
    renameat(CWD, old_path, CWD, new_path)
}

/// Changes permissions for an open file or directory.
#[inline]
pub fn fchmod<Fd: AsFd>(fd: Fd, mode: Mode) -> Result<()> {
    crabc_core::fs::fchmod(fd.as_fd().as_raw_fd(), mode.bits())
}

/// Changes permissions for `path` relative to `dirfd`.
///
/// Linux cannot change a symbolic link's mode. Matching Rustix, passing
/// exactly [`AtFlags::SYMLINK_NOFOLLOW`] reports `EOPNOTSUPP`; passing any
/// other nonempty flag set reports `EINVAL` rather than silently ignoring it.
#[inline]
#[doc(alias = "fchmodat")]
pub fn chmodat<P: Arg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode, flags: AtFlags) -> Result<()> {
    if flags == AtFlags::SYMLINK_NOFOLLOW {
        return Err(crate::Errno::OPNOTSUPP);
    }
    if !flags.is_empty() {
        return Err(crate::Errno::INVAL);
    }
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| crabc_core::fs::fchmodat(dirfd.as_raw_fd(), path, mode.bits(), 0))
}

/// Changes permissions relative to the process current directory.
#[inline]
pub fn chmod<P: Arg>(path: P, mode: Mode) -> Result<()> {
    chmodat(CWD, path, mode, AtFlags::empty())
}

/// Sets access and modification times relative to `dirfd`.
#[inline]
pub fn utimensat<P: Arg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    times: &Timestamps,
    flags: AtFlags,
) -> Result<()> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: `path` and `times` remain valid for the direct syscall, and
        // `Timestamps` is exactly two Linux/AArch64 `timespec` values.
        unsafe {
            crabc_core::fs::utimensat_raw(
                dirfd.as_raw_fd(),
                path.as_ptr().cast(),
                (times as *const Timestamps).cast(),
                flags.bits(),
            )
        }
    })
}

/// Sets timestamps on an open file or directory.
#[inline]
pub fn futimens<Fd: AsFd>(fd: Fd, times: &Timestamps) -> Result<()> {
    // SAFETY: `times` remains valid for the direct syscall, and its layout is
    // exactly two Linux/AArch64 `timespec` values. A null path selects the
    // kernel's futimens form.
    unsafe {
        crabc_core::fs::utimensat_raw(
            fd.as_fd().as_raw_fd(),
            core::ptr::null(),
            (times as *const Timestamps).cast(),
            0,
        )
    }
}

/// Acquires or releases a Linux `flock` advisory lock.
#[inline]
pub fn flock<Fd: AsFd>(fd: Fd, operation: FlockOperation) -> Result<()> {
    crabc_core::fs::flock(fd.as_fd().as_raw_fd(), operation as u32)
}

#[repr(C)]
struct KernelFlock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

/// Acquires or releases a whole-file, process-associated `fcntl` lock.
///
/// A zero length deliberately means from byte zero through the dynamically
/// changing end of file. As in Rustix, these locks are process-associated and
/// do not protect two threads of one process from each other.
#[inline]
pub fn fcntl_lock<Fd: AsFd>(fd: Fd, operation: FlockOperation) -> Result<()> {
    let (command, lock_type) = match operation {
        FlockOperation::LockShared => (7, 0),
        FlockOperation::LockExclusive => (7, 1),
        FlockOperation::Unlock => (7, 2),
        FlockOperation::NonBlockingLockShared => (6, 0),
        FlockOperation::NonBlockingLockExclusive => (6, 1),
        FlockOperation::NonBlockingUnlock => (6, 2),
    };
    let mut lock = KernelFlock {
        l_type: lock_type,
        l_whence: 0,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    // SAFETY: `KernelFlock` matches the Linux/AArch64 `struct flock` ABI and
    // remains live for the command. The selected command reads this complete
    // whole-file lock specification.
    unsafe {
        crabc_core::io::fcntl_raw(
            fd.as_fd().as_raw_fd(),
            command,
            core::ptr::addr_of_mut!(lock).cast(),
        )
        .map(|_| ())
    }
}
