//! Staged Linux/x86-64 filesystem operations and memory-file support.
//!
//! This module admits descriptor-based `fstat(2)`, `statat(2)` path metadata,
//! caller-buffered and allocation-backed `readlinkat(2)` target reads,
//! caller-buffered extended-attribute operations through the direct path,
//! no-follow-path, and descriptor syscall forms, direct `statx(2)` extended
//! metadata with operation-specific lookup flags, `access(2)` and `faccessat2(2)` permission
//! checks, direct `fcntl(F_GETFL/F_SETFL)` status-flag observation and
//! mutation, filesystem-capacity observation through `statfs(2)` and
//! `fstatfs(2)` plus derived `statvfs` views, a bounded pathname lifecycle
//! and namespace slice through `openat(2)`, `newfstatat(2)`, `mkdirat(2)`,
//! `mknodat(2)`, `unlinkat(2)`, `linkat(2)`, `symlinkat(2)`, `renameat2(2)`,
//! `fchmodat(2)`, `fchownat(2)`, and `truncate(2)`, file-access advice,
//! file readahead, descriptor-based file-length and timestamp mutation, and
//! closed pathname timestamp mutation through a bounded no-alloc path boundary,
//! fixed-mode descriptor-range allocation,
//! descriptor-to-descriptor transfer and descriptor-range copying,
//! file-position and synchronization operations,
//! system-wide and descriptor-associated filesystem synchronization, and direct anonymous
//! memory-file creation with bounded sealing, plus private named and anonymous
//! temporary-file ownership and caller-buffered/owned temporary-directory
//! creation.
//! The
//! x86-64 kernel record is not interchangeable with the AArch64 record:
//! `st_nlink` and the timestamp nanoseconds are 64-bit here, and the record
//! has a distinct 144-byte layout. The pathname lifecycle slice uses explicit
//! current-directory or borrowed-directory authority and operation-specific
//! `AT_*` flag types. A bounded physical canonicalization operation uses
//! explicit descriptor traversal; general `AT_EMPTY_PATH` remains separate
//! x86 work, while [`StatxAtFlags::EMPTY_PATH`] is admitted only for
//! `statx(2)`. Current-directory mutation is owned by [`crate::process`].
//! Allocation-free Linux `getdents64` streams are admitted through [`RawDir`]
//! and [`Dir`]: their caller-owned record buffer and opaque cursor semantics do
//! not select a C `DIR` ABI.

#[cfg(feature = "alloc")]
use alloc::{ffi::CString, string::String, vec::Vec};
use bitflags::bitflags;
use crate::buffer::Buffer;
use core::ffi::CStr;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::num::NonZeroU64;
use core::ptr;

#[cfg(feature = "std")]
use std::ffi::{OsStr, OsString};
#[cfg(feature = "std")]
use std::os::unix::ffi::OsStrExt;
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};

use crate::{
    process::{Gid, Uid},
    AsFd, BorrowedFd, Errno, OwnedFd, Result,
};

pub use crate::{RawDir, RawDirEntry};

bitflags! {
    /// The bounded Linux `fallocate` modes supported by this facade.
    ///
    /// This is a closed set: unknown mode bits, and Linux modes with stronger
    /// filesystem-specific range semantics, are not forwarded by the safe
    /// [`fallocate`] API. `PUNCH_HOLE` must be combined with `KEEP_SIZE`, as
    /// required by Linux; `ZERO_RANGE` may be combined with `KEEP_SIZE`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct FallocateFlags: u32 {
        /// Allocate blocks and extend the file when the range reaches beyond
        /// its current end (Linux's mode-zero operation).
        const ALLOCATE = 0;
        /// Do not change the file length while allocating or zeroing.
        const KEEP_SIZE = 0x01;
        /// Deallocate the range and make reads return zero; requires
        /// [`Self::KEEP_SIZE`].
        const PUNCH_HOLE = 0x02;
        /// Convert the range to zeros, allocating blocks as needed.
        const ZERO_RANGE = 0x10;
    }
}

bitflags! {
    /// Permission checks accepted by [`access`] and [`accessat`].
    ///
    /// This closed set mirrors Linux's `R_OK`, `W_OK`, `X_OK`, and `F_OK`
    /// vocabulary. Unknown bits are rejected before a syscall;
    /// [`Access::EXISTS`] deliberately has the zero value used by `F_OK`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct Access: u32 {
        /// Test read permission.
        const READ_OK = 0x4;
        /// Test write permission.
        const WRITE_OK = 0x2;
        /// Test execute/search permission.
        const EXEC_OK = 0x1;
        /// Test only whether the path exists.
        const EXISTS = 0;
    }
}

bitflags! {
    /// `XATTR_*` flags accepted by Linux extended-attribute setters.
    ///
    /// Unknown bits are forwarded to Linux for validation rather than being
    /// silently discarded at the native Rust boundary.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct XattrFlags: u32 {
        /// `XATTR_CREATE`: fail if the named attribute already exists.
        const CREATE = 0x1;
        /// `XATTR_REPLACE`: fail if the named attribute does not exist.
        const REPLACE = 0x2;
        /// Preserve future Linux-defined flags for direct kernel validation.
        const _ = !0;
    }
}

bitflags! {
    /// Known Linux/x86-64 `O_*` values for [`openat`], [`fcntl_getfl`], and
    /// [`fcntl_setfl`].
    ///
    /// Unknown bits are retained so callers can faithfully observe and forward
    /// future kernel-defined status bits. At the pathname boundary they are
    /// passed directly to Linux rather than interpreted as a portability or
    /// fallback policy.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct OFlags: u32 {
        /// `O_ACCMODE` on Linux/x86-64, including the `O_PATH` selection bit.
        const ACCMODE = 0x0020_0003;
        /// The read/write-only portion of [`Self::ACCMODE`].
        ///
        /// On x86-64, `O_PATH` is part of `O_ACCMODE` but is not a read/write
        /// mode bit.
        const RWMODE = 0x0000_0003;
        /// `O_RDONLY`. This bit pattern is zero.
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
        /// `O_DIRECT`.
        const DIRECT = 0x0000_4000;
        /// `O_LARGEFILE`.
        const LARGEFILE = 0x0000_8000;
        /// `O_DIRECTORY`.
        const DIRECTORY = 0x0001_0000;
        /// `O_NOFOLLOW`.
        const NOFOLLOW = 0x0002_0000;
        /// `O_NOATIME`.
        const NOATIME = 0x0004_0000;
        /// `O_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
        /// `O_SYNC`.
        const SYNC = 0x0010_1000;
        /// `O_FSYNC`, an alias of [`Self::SYNC`].
        const FSYNC = Self::SYNC.bits();
        /// `O_RSYNC`, an alias of [`Self::SYNC`].
        const RSYNC = Self::SYNC.bits();
        /// `O_PATH`.
        const PATH = 0x0020_0000;
        /// `O_TMPFILE`.
        const TMPFILE = 0x0041_0000;
        /// Preserve future kernel-defined bits.
        const _ = !0;
    }
}

/// Linux whole-file advisory-lock operations accepted by [`flock`].
///
/// These values apply to an open file description through the direct
/// `flock(2)` syscall. They are deliberately distinct from the read-only
/// [`crate::process::fcntl_getlk`] record-lock observation slice; this module
/// does not expose `fcntl` record-lock mutation. The blocking variants may
/// wait indefinitely for a conflicting advisory lock.
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

/// The largest byte pathname represented in the fixed-stack [`PathArg`]
/// boundary.
///
/// One byte is reserved for the terminating NUL. No-allocation builds reject
/// longer byte paths with [`Errno::NAMETOOLONG`]; allocation-enabled builds
/// form an owned [`CString`] and leave Linux to enforce its pathname limit.
pub const SMALL_PATH_BUFFER_SIZE: usize = 256;

/// A pathname or memory-file name input accepted by the staged path lifecycle,
/// [`access`], [`accessat`], [`statat`], [`stat`], [`statx`], [`statfs`], [`statvfs`],
/// [`readlinkat_raw`], [`canonicalize_into`], the extended-attribute family,
/// the timestamp-mutation family, the temporary-object family,
/// [`crate::process::chroot`], [`crate::mount::{mount, unmount}`], and
/// [`memfd_create`].
///
/// Implementations borrow an existing C string or form one in a fixed stack
/// buffer; allocation-enabled builds use an owned [`CString`] for longer
/// inputs. The callback is invoked while that C string remains live, so the
/// safe facade never exposes a temporary raw pathname pointer. Byte-oriented
/// inputs reject interior NULs with [`Errno::INVAL`] and need not be UTF-8.
/// [`memfd_create`] uses the same input boundary for its anonymous-file label,
/// not for pathname resolution.
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
        #[cfg(feature = "alloc")]
        {
            let path = CString::new(bytes).map_err(|_| Errno::INVAL)?;
            return callback(path.as_c_str());
        }

        #[cfg(not(feature = "alloc"))]
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

#[cfg(feature = "alloc")]
impl PathArg for CString {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        callback(self.as_c_str())
    }
}

#[cfg(feature = "alloc")]
impl PathArg for &CString {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        callback(self.as_c_str())
    }
}

#[cfg(feature = "alloc")]
impl PathArg for String {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_bytes(), callback)
    }
}

#[cfg(feature = "alloc")]
impl PathArg for &String {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_bytes(), callback)
    }
}

#[cfg(feature = "std")]
impl PathArg for &OsStr {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_bytes(), callback)
    }
}

#[cfg(feature = "std")]
impl PathArg for &OsString {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_os_str().as_bytes(), callback)
    }
}

#[cfg(feature = "std")]
impl PathArg for OsString {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_os_str().as_bytes(), callback)
    }
}

#[cfg(feature = "std")]
impl PathArg for &Path {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_os_str().as_bytes(), callback)
    }
}

#[cfg(feature = "std")]
impl PathArg for &PathBuf {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_os_str().as_bytes(), callback)
    }
}

#[cfg(feature = "std")]
impl PathArg for PathBuf {
    #[inline]
    fn into_with_c_str<T, F>(self, callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_path_bytes(self.as_os_str().as_bytes(), callback)
    }
}

/// `AT_FDCWD`, the directory token representing the current working directory.
///
/// This is a reserved Linux token rather than an owned descriptor. It is
/// accepted only as the directory argument to staged `*at` operations and can
/// never become an owned descriptor.
pub const CWD: BorrowedFd<'static> =
    // SAFETY: `AT_FDCWD` is a reserved, non-allocatable Linux token. The
    // narrowly documented exception in `BorrowedFd::borrow_raw` permits it.
    unsafe { BorrowedFd::borrow_raw(crabc_core::AT_FDCWD) };

bitflags! {
    /// The closed `fstatat(2)` flag vocabulary admitted by [`statat`].
    ///
    /// `SYMLINK_NOFOLLOW` observes a final symlink rather than its target.
    /// `AT_EMPTY_PATH`, `AT_NO_AUTOMOUNT`, and all unknown bits remain outside
    /// this staged metadata boundary and return [`Errno::INVAL`] before a syscall.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct AtFlags: u32 {
        /// `AT_SYMLINK_NOFOLLOW`.
        const SYMLINK_NOFOLLOW = 0x0000_0100;
    }
}

bitflags! {
    /// Linux `statx(2)` lookup and synchronization flags accepted by [`statx`].
    ///
    /// This vocabulary is deliberately separate from the closed [`AtFlags`]
    /// used by `newfstatat(2)`: `AT_EMPTY_PATH`, `AT_NO_AUTOMOUNT`, and the
    /// statx synchronization modifiers have operation-specific kernel
    /// meanings. Unknown bits are retained and passed to Linux so this direct
    /// syscall boundary preserves its kernel validation behavior.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct StatxAtFlags: u32 {
        /// `AT_SYMLINK_NOFOLLOW`: observe a final symbolic link itself.
        const SYMLINK_NOFOLLOW = 0x0000_0100;
        /// `AT_NO_AUTOMOUNT`: do not trigger a terminal automount.
        const NO_AUTOMOUNT = 0x0000_0800;
        /// `AT_EMPTY_PATH`: resolve an empty path as `dirfd` itself.
        const EMPTY_PATH = 0x0000_1000;
        /// `AT_STATX_FORCE_SYNC`: request metadata synchronized to storage.
        const FORCE_SYNC = 0x0000_2000;
        /// `AT_STATX_DONT_SYNC`: accept cached metadata when available.
        const DONT_SYNC = 0x0000_4000;
        /// Preserve future Linux-defined statx flags for direct validation.
        const _ = !0;
    }
}

bitflags! {
    /// Flags accepted by [`unlinkat`].
    ///
    /// This is intentionally separate from [`AtFlags`]: `AT_REMOVEDIR` is
    /// meaningful only to `unlinkat(2)`, so a metadata flag cannot become a
    /// removal request by accident.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct UnlinkAtFlags: u32 {
        /// Remove an empty directory rather than a non-directory entry.
        const REMOVEDIR = 0x0000_0200;
    }
}

bitflags! {
    /// Flags accepted by [`linkat`].
    ///
    /// The direct x86-64 lifecycle slice admits only the final-link-follow
    /// selection. `AT_EMPTY_PATH` and all other `AT_*` forms are excluded.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct LinkAtFlags: u32 {
        /// Follow a final symbolic link at the source path.
        const SYMLINK_FOLLOW = 0x0000_0400;
    }
}

bitflags! {
    /// Linux `renameat2(2)` flags admitted by [`renameat_with`].
    ///
    /// The no-replace and exchange operations are ordinary namespace
    /// transitions. Whiteout creation is filesystem- and privilege-specific,
    /// so it remains outside this staged Rust boundary.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct RenameFlags: u32 {
        /// Fail when the destination already exists.
        const NOREPLACE = 0x0000_0001;
        /// Atomically exchange two existing directory entries.
        const EXCHANGE = 0x0000_0002;
    }
}

bitflags! {
    /// Flags accepted by [`chownat`].
    ///
    /// Ownership changes have their own closed flag type because Linux reuses
    /// `AT_*` bit values across unrelated operations.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct ChownFlags: u32 {
        /// Change a final symbolic link itself rather than its target.
        const SYMLINK_NOFOLLOW = 0x0000_0100;
    }
}

bitflags! {
    /// The closed `utimensat(2)` pathname flag vocabulary.
    ///
    /// Linux reuses `AT_*` values across unrelated syscall families. Keeping
    /// this timestamp-specific type separate from [`AtFlags`] and
    /// [`AccessAtFlags`] prevents metadata or access selections from crossing
    /// into a timestamp mutation request. `AT_EMPTY_PATH`, `AT_SYMLINK_FOLLOW`,
    /// and unknown bits are rejected before a descriptor is borrowed or a
    /// pathname is converted.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct TimestampAtFlags: u32 {
        /// Update a final symbolic link itself rather than its target.
        const SYMLINK_NOFOLLOW = 0x0000_0100;
    }
}

bitflags! {
    /// Flags accepted by [`accessat`].
    ///
    /// This operation-specific type is intentionally distinct from
    /// [`AtFlags`], whose closed vocabulary belongs to the staged `statat`
    /// metadata boundary. Linux reuses these flag bits across unrelated
    /// `*at` syscalls; keeping the types separate prevents an access flag from
    /// silently becoming a valid metadata flag. Unknown bits are rejected
    /// before entering the kernel.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct AccessAtFlags: u32 {
        /// Check using effective rather than real credentials.
        const EACCESS = 0x0000_0200;
        /// Check the final symbolic link itself rather than its target.
        const SYMLINK_NOFOLLOW = 0x0000_0100;
    }
}

/// Tests a pathname using Linux's standard `access()` behavior.
///
/// The pathname is resolved relative to the process current working
/// directory and the permission check uses the real UID and GID. This direct
/// x86-64 facade reaches the shared `faccessat(AT_FDCWD, path, mode)` seam;
/// it does not consult libc or thread-local `errno`. Unknown [`Access`] bits
/// are rejected before the pathname is converted or the syscall is issued.
#[inline]
pub fn access<P: PathArg>(path: P, access: Access) -> Result<()> {
    let access = Access::from_bits(access.bits()).ok_or(Errno::INVAL)?;
    path.into_with_c_str(|path| crabc_core::fs::access(path, access.bits()))
}

/// Tests a pathname relative to `dirfd` using Linux's `faccessat` and
/// `faccessat2` contracts.
///
/// Empty [`AccessAtFlags`] uses the three-argument `faccessat` syscall.
/// Either supported nonempty flag uses direct `faccessat2`, preserving its
/// kernel availability and error result without an emulated fallback. The
/// descriptor is borrowed only for the syscall, and [`PathArg`] keeps any
/// fixed-stack pathname representation live until Linux has consumed it.
/// Unknown access modes and flags are rejected before that boundary.
#[inline]
#[doc(alias = "faccessat")]
#[doc(alias = "faccessat2")]
pub fn accessat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    access: Access,
    flags: AccessAtFlags,
) -> Result<()> {
    let access = Access::from_bits(access.bits()).ok_or(Errno::INVAL)?;
    let flags = AccessAtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        crabc_core::fs::accessat(
            dirfd.as_raw_fd(),
            path,
            access.bits(),
            flags.bits(),
        )
    })
}

/// Reads the open-file-description status flags through `fcntl(F_GETFL)`.
///
/// The returned [`OFlags`] includes the access mode and status flags reported
/// by Linux. Unknown kernel bits are retained. These flags are shared by
/// duplicate descriptors; per-descriptor close-on-exec state remains the
/// separate [`crate::io::fcntl_getfd`] contract.
#[inline]
#[doc(alias = "F_GETFL")]
pub fn fcntl_getfl<Fd: AsFd>(fd: Fd) -> Result<OFlags> {
    crabc_core::io::fcntl_getfl(fd.as_fd().as_raw_fd()).map(OFlags::from_bits_retain)
}

/// Replaces the open-file-description status flags through `fcntl(F_SETFL)`.
///
/// Linux changes only status bits supported for the open file. Access,
/// creation, and per-descriptor flags are not promised to change. The
/// descriptor is borrowed and the operation affects all descriptors referring
/// to the same open file description.
#[inline]
#[doc(alias = "F_SETFL")]
pub fn fcntl_setfl<Fd: AsFd>(fd: Fd, flags: OFlags) -> Result<()> {
    crabc_core::io::fcntl_setfl(fd.as_fd().as_raw_fd(), flags.bits())
}

/// Acquires or releases a Linux whole-file `flock(2)` advisory lock.
///
/// The descriptor is borrowed only for the direct syscall. Blocking operations
/// may wait indefinitely. This remains separate from
/// [`crate::process::fcntl_getlk`], which only observes `fcntl` record
/// locks; record-lock mutation and generic `fcntl` stay outside the x86-64
/// facade.
#[inline]
pub fn flock<Fd: AsFd>(fd: Fd, operation: FlockOperation) -> Result<()> {
    crabc_core::fs::flock(fd.as_fd().as_raw_fd(), operation as u32)
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

bitflags! {
    /// Linux file-creation permission and process-mask bits.
    ///
    /// This is shared by the staged x86-64 pathname lifecycle and the native
    /// process::umask vocabulary. The bitset intentionally retains future
    /// Linux mode bits, matching the AArch64 facade contract. Individual
    /// operations such as [`mknodat`] may deliberately validate a narrower
    /// subset before entering the kernel.
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
        /// S_ISVTX, the Rustix spelling for the sticky bit.
        const SVTX = Self::STICKY.bits();
        /// Preserve future Linux mode bits.
        const _ = !0;
    }
}

/// Raw Linux st_mode bits.
pub type RawMode = u32;

/// Linux `dev_t` used by [`mknodat`].
///
/// Linux/x86-64 carries this value in one 64-bit syscall argument. FIFO
/// creation always uses [`FIFO_DEVICE`]; character and block device creation
/// retains the kernel's ordinary privilege and device-number checks.
pub type Dev = u64;

/// The device number required when creating a FIFO.
pub const FIFO_DEVICE: Dev = 0;

/// Seconds in a Linux/x86-64 `timespec`.
pub type Secs = i64;

/// Nanoseconds in a Linux/x86-64 `timespec`.
pub type Nsecs = i64;

/// A Linux/x86-64 `timespec` used for descriptor timestamp updates.
///
/// The representation is the direct kernel record consumed by
/// [`futimens`], rather than a public C `struct timespec` compatibility
/// declaration. `tv_nsec` accepts ordinary nanoseconds and the
/// [`UTIME_NOW`]/[`UTIME_OMIT`] sentinels; Linux validates every supplied
/// value.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: Secs,
    /// Nanoseconds, or [`UTIME_NOW`]/[`UTIME_OMIT`] for timestamp updates.
    pub tv_nsec: Nsecs,
}

const _: [(); 16] = [(); core::mem::size_of::<Timespec>()];
const _: [(); 8] = [(); core::mem::align_of::<Timespec>()];

/// The current-time sentinel accepted in [`Timespec::tv_nsec`] by Linux
/// `utimensat`.
pub const UTIME_NOW: Nsecs = 0x3fff_ffff;

/// The leave-unchanged sentinel accepted in [`Timespec::tv_nsec`] by Linux
/// `utimensat`.
pub const UTIME_OMIT: Nsecs = 0x3fff_fffe;

/// The access and modification timestamps consumed by [`futimens`].
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Timestamps {
    /// Last-access timestamp.
    pub last_access: Timespec,
    /// Last-modification timestamp.
    pub last_modification: Timespec,
}

const _: [(); 32] = [(); core::mem::size_of::<Timestamps>()];
const _: [(); 8] = [(); core::mem::align_of::<Timestamps>()];

/// A legacy Linux/x86-64 `timeval` value expressed in whole seconds and
/// microseconds.
///
/// This native Rust value is converted to [`Timespec`] before the direct
/// syscall. Its microsecond field must be in `0..1_000_000`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timeval {
    /// Whole seconds.
    pub tv_sec: Secs,
    /// Microseconds within `tv_sec`.
    pub tv_usec: i64,
}

const _: [(); 16] = [(); core::mem::size_of::<Timeval>()];
const _: [(); 8] = [(); core::mem::align_of::<Timeval>()];

/// A legacy Linux timestamp pair expressed in whole seconds.
///
/// [`utime`] converts these values to two [`Timespec`] records with zero
/// nanoseconds before entering Linux.
#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Utimbuf {
    /// Last-access timestamp in whole seconds.
    pub actime: Secs,
    /// Last-modification timestamp in whole seconds.
    pub modtime: Secs,
}

impl Mode {
    /// Extracts permission bits from a Linux st_mode value.
    #[inline]
    pub const fn from_raw_mode(st_mode: RawMode) -> Self {
        Self::from_bits_truncate(st_mode & !0o170000)
    }

    /// Returns this value in the Linux st_mode representation.
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

/// A file kind encoded in Linux `st_mode` values.
///
/// [`FileType::Unknown`] is an observation-only result and cannot be used by
/// [`mknodat`] to create an arbitrary file type.
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

    /// Interprets the Linux `DT_*` byte embedded in a `getdents64` record.
    ///
    /// `DT_UNKNOWN` and values not defined by Linux are retained as an
    /// observation-only [`Self::Unknown`] result. A directory record's type is
    /// not a metadata query; callers that need an authoritative type use
    /// [`statat`] or [`fstat`].
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

/// A descriptor-owning, allocation-free Linux directory stream.
///
/// `Dir` takes ownership of the directory descriptor and borrows caller-owned
/// storage for `getdents64` records. Each entry borrows the stream, so an
/// entry cannot remain live while the next call refills or advances it. `None`
/// means end-of-directory; `Some(Err(_))` reports the first I/O or malformed
/// record error, after which the stream is exhausted. Use [`RawDir`] when an
/// undersized-buffer error must be recovered by dropping the iterator and
/// rebuilding it with a larger buffer on the same descriptor.
pub struct Dir<'buffer> {
    entries: RawDir<'buffer, OwnedFd>,
    done: bool,
}

/// One byte-preserving entry borrowed from [`Dir`].
pub type DirEntry<'entry> = RawDirEntry<'entry>;

impl<'buffer> Dir<'buffer> {
    /// Opens `path` as a close-on-exec directory stream.
    ///
    /// The stream uses read-only access, `O_DIRECTORY`, and `O_CLOEXEC`.
    /// Path arguments remain byte-oriented through [`PathArg`]; no UTF-8 or
    /// process-global C `DIR` state is involved.
    #[inline]
    pub fn open<P: PathArg>(path: P, buffer: &'buffer mut [MaybeUninit<u8>]) -> Result<Self> {
        Self::openat(CWD, path, buffer)
    }

    /// Opens `path` relative to a borrowed directory descriptor as a
    /// close-on-exec directory stream.
    #[inline]
    pub fn openat<P: PathArg, Fd: AsFd>(
        dirfd: Fd,
        path: P,
        buffer: &'buffer mut [MaybeUninit<u8>],
    ) -> Result<Self> {
        let fd = openat(
            dirfd,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self::from_owned_fd(fd, buffer))
    }

    /// Constructs a stream by transferring ownership of an existing
    /// directory descriptor.
    ///
    /// The descriptor is not re-opened or duplicated. If it does not refer to
    /// a directory, the first call to [`Self::next`] returns the kernel error.
    #[inline]
    pub fn from_owned_fd(fd: OwnedFd, buffer: &'buffer mut [MaybeUninit<u8>]) -> Self {
        Self {
            entries: RawDir::new(fd, buffer),
            done: false,
        }
    }

    /// Rewinds the directory stream to its beginning.
    ///
    /// Buffered records are discarded immediately. The direct `lseek` to
    /// offset zero is deferred until the next call to [`Self::next`], matching
    /// Rustix's Linux-raw `rewinddir` behavior. Interrupted seeks are retried;
    /// another kernel error is returned through that call and exhausts the
    /// stream.
    #[inline]
    pub fn rewind(&mut self) {
        self.entries.rewind();
        self.done = false;
    }

    /// Seeks to a Linux directory-entry cookie.
    ///
    /// `offset` is the opaque cookie returned by
    /// [`DirEntry::next_entry_cookie`], not a byte offset. Buffered records
    /// are discarded before the direct `lseek(fd, offset, SEEK_SET)` call,
    /// which retries interruption. Another failed seek is returned immediately
    /// and leaves the stream exhausted.
    #[inline]
    pub fn seek(&mut self, offset: i64) -> Result<()> {
        match self.entries.seek(offset) {
            Ok(()) => {
                self.done = false;
                Ok(())
            }
            Err(error) => {
                self.done = true;
                Err(error)
            }
        }
    }

    /// Returns the next entry, an I/O error, or end-of-directory.
    #[inline]
    pub fn next(&mut self) -> Option<Result<DirEntry<'_>>> {
        if self.done {
            return None;
        }
        match self.entries.next() {
            Some(Err(error)) => {
                self.done = true;
                Some(Err(error))
            }
            Some(Ok(entry)) => Some(Ok(entry)),
            None => {
                self.done = true;
                None
            }
        }
    }

    /// Borrows the owned directory descriptor for descriptor-relative
    /// operations without transferring ownership.
    #[inline]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.entries.as_fd()
    }
}

impl AsFd for Dir<'_> {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.entries.as_fd()
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsRawFd for Dir<'_> {
    #[inline]
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        Dir::as_fd(self).as_raw_fd()
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsFd for Dir<'_> {
    #[inline]
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // SAFETY: `Dir` owns its descriptor through its internal `OwnedFd`, so
        // it stays open for the returned standard-library borrow.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(Dir::as_fd(self).as_raw_fd()) }
    }
}

bitflags! {
    /// Stable Linux `MFD_*` creation flags for [`memfd_create`].
    ///
    /// This is deliberately a closed set: unknown or newer kernel bits are
    /// rejected by [`MemfdFlags::from_bits`] instead of being silently
    /// forwarded. [`MemfdFlags::HUGETLB`] selects only the kernel's default
    /// hugetlb page size; `MFD_HUGE_*` size selectors and any huge-page
    /// allocation policy remain outside this bounded facade slice.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MemfdFlags: u32 {
        /// Set `FD_CLOEXEC` on the returned descriptor.
        const CLOEXEC = 0x0001;
        /// Permit `F_ADD_SEALS` operations on the returned file.
        const ALLOW_SEALING = 0x0002;
        /// Use hugetlb-backed storage with the kernel's default huge-page
        /// size. Allocation remains a direct kernel result; this facade does
        /// not expose huge-page size selection or reservation policy.
        const HUGETLB = 0x0004;
    }
}

bitflags! {
    /// Linux `F_SEAL_*` flags returned by [`fcntl_get_seals`].
    ///
    /// Linux 5.10 defines the first five flags below. Unknown bits are retained
    /// so observations from a newer Linux kernel are not silently discarded at
    /// the native Rust boundary, and requested unknown bits pass unchanged to
    /// Linux for validation. In particular, [`SealFlags::EXEC`] is kept as an
    /// exact directly forwarded Linux 6.3+ bit; executable-policy behavior is
    /// not part of this Linux-5.10 evidence slice.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SealFlags: u32 {
        /// Prevent adding further seals.
        const SEAL = 0x0001;
        /// Prevent shrinking the inode.
        const SHRINK = 0x0002;
        /// Prevent growing the inode.
        const GROW = 0x0004;
        /// Prevent writes to the inode.
        const WRITE = 0x0008;
        /// Prevent future writable shared mappings (Linux 5.1+).
        ///
        /// Writable shared mappings created before this seal remain permitted,
        /// but direct descriptor writes are rejected.
        const FUTURE_WRITE = 0x0010;
        /// Directly forward the Linux 6.3+ executable-change seal.
        ///
        /// It is intentionally exposed for API fidelity but is not proved on
        /// the Linux 5.10 baseline and does not admit executable-policy scope.
        const EXEC = 0x0020;
        /// Preserve future Linux-defined seal bits.
        const _ = !0;
    }
}

/// Creates an anonymous Linux memory file and returns its unique owner.
///
/// `name` follows the bounded [`PathArg`] boundary: it is a borrowed
/// byte-oriented NUL-terminated string, rejects interior NUL bytes, and does
/// not require UTF-8. Byte and string inputs through the no-allocation arm
/// reject names of 256 bytes or more with [`Errno::NAMETOOLONG`] before the
/// syscall; a supplied [`CStr`] is borrowed directly. Linux accepts 249 label
/// bytes and rejects 250 with its direct [`Errno::INVAL`] result; that kernel
/// limit remains distinct from the facade's 256-byte conversion limit.
///
/// This creates only anonymous memory files. `memfd_secret`, huge-page size
/// selectors, and broader filesystem policy remain outside the typed x86-64
/// facade.
#[inline]
pub fn memfd_create<P: PathArg>(name: P, flags: MemfdFlags) -> Result<OwnedFd> {
    let flags = MemfdFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    name.into_with_c_str(|name| {
        crabc_core::fs::memfd_create(name, flags.bits()).map(|fd| {
            // SAFETY: successful Linux `memfd_create` returns one fresh,
            // non-negative descriptor whose ownership transfers here.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
    })
}

/// Reads the Linux `F_SEAL_*` flags associated with a descriptor's inode.
///
/// This is an observation-only operation over a borrowed descriptor. Linux
/// returns `EINVAL` for inodes that do not support sealing, and all kernel
/// errors remain direct [`crate::Errno`] results without libc or TLS `errno`.
#[inline]
#[doc(alias = "F_GET_SEALS")]
pub fn fcntl_get_seals<Fd: AsFd>(fd: Fd) -> Result<SealFlags> {
    crabc_core::io::fcntl_get_seals(fd.as_fd().as_raw_fd()).map(SealFlags::from_bits_retain)
}

/// Adds Linux `F_SEAL_*` flags to a descriptor's inode.
///
/// The descriptor must have been created with [`MemfdFlags::ALLOW_SEALING`],
/// and once [`SealFlags::SEAL`] is present no further flags may be added.
/// [`SealFlags::FUTURE_WRITE`] rejects direct descriptor writes and new shared
/// writable mappings, while retaining writable shared mappings that existed
/// before the seal was added.
/// Unknown requested bits are forwarded unchanged; Linux 5.10 rejects an
/// unrecognized bit with its direct [`crate::Errno::INVAL`] result. The
/// [`SealFlags::EXEC`] bit is likewise forwarded unchanged when requested, but
/// its Linux 6.3+ executable-policy semantics are not part of this Linux-5.10
/// slice.
/// Kernel errors such as [`crate::Errno::PERM`] remain direct results without
/// libc or TLS `errno`.
#[inline]
#[doc(alias = "F_ADD_SEALS")]
pub fn fcntl_add_seals<Fd: AsFd>(fd: Fd, seals: SealFlags) -> Result<()> {
    crabc_core::io::fcntl_add_seals(fd.as_fd().as_raw_fd(), seals.bits())
}

/// Number of kernel-random bytes used for each named temporary-file candidate.
/// The bytes are encoded as 24 hexadecimal pathname bytes (96 bits).
pub const TEMP_FILE_RANDOM_BYTES: usize = 12;

/// Maximum number of candidate names attempted after an `EEXIST` collision.
pub const TEMP_FILE_MAX_ATTEMPTS: usize = 128;

const TEMP_FILE_NAME_MAX: usize = 255;
const TEMP_FILE_SUFFIX_LENGTH: usize = TEMP_FILE_RANDOM_BYTES * 2;
const TEMP_FILE_MODE_BITS: u32 = 0o600;

/// An owned named temporary regular file with descriptor-relative cleanup.
///
/// Creation opens a stable directory descriptor, then atomically creates a
/// private `O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC` entry with a 96-bit
/// `getrandom` suffix. The value owns both descriptors and unlinks its
/// basename on drop. [`Self::into_owned_fd`] deliberately persists the
/// directory entry and transfers only the file descriptor to the caller.
///
/// The name is a basename, not a process-relative pathname. Callers that need
/// a full path retain the directory authority they supplied and join it with
/// [`Self::name`]; no ambient CWD or global temporary-file registry is used.
pub struct NamedTempFile {
    fd: OwnedFd,
    parent: OwnedFd,
    name: [u8; TEMP_FILE_NAME_MAX + 1],
    name_len: u16,
    cleanup: bool,
}

impl NamedTempFile {
    /// Borrows the generated basename without a trailing NUL.
    #[inline]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Borrows the stable directory descriptor used for creation and cleanup.
    #[inline]
    pub fn parent_fd(&self) -> BorrowedFd<'_> {
        self.parent.as_fd()
    }

    /// Borrows the created file descriptor.
    #[inline]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Unlinks the entry and closes both owned descriptors.
    ///
    /// If unlinking fails, the value remains armed for a best-effort retry in
    /// `Drop`, and the kernel error is returned to the caller.
    pub fn remove(mut self) -> Result<()> {
        let result = self.unlink();
        if result.is_ok() {
            self.cleanup = false;
        }
        result
    }

    /// Persists the directory entry and transfers ownership of its file FD.
    ///
    /// The parent directory descriptor is closed by this operation. The
    /// caller is responsible for retaining or removing the named entry after
    /// this transfer.
    pub fn into_owned_fd(self) -> OwnedFd {
        let mut this = ManuallyDrop::new(self);
        this.cleanup = false;
        // SAFETY: `this` is never dropped after `ManuallyDrop` is created;
        // explicitly release the retained parent descriptor, then move the
        // file descriptor out exactly once.
        unsafe {
            ptr::drop_in_place(&mut this.parent);
            ptr::read(&this.fd)
        }
    }

    fn unlink(&self) -> Result<()> {
        let name = unsafe {
            CStr::from_bytes_with_nul_unchecked(&self.name[..self.name_len as usize + 1])
        };
        unlinkat(&self.parent, name, UnlinkAtFlags::empty())
    }
}

impl AsFd for NamedTempFile {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.as_fd()
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsRawFd for NamedTempFile {
    #[inline]
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.as_fd().as_raw_fd()
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsFd for NamedTempFile {
    #[inline]
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // SAFETY: `NamedTempFile` owns its descriptor through `OwnedFd`, so it
        // remains open for the returned standard-library borrow.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.as_fd().as_raw_fd()) }
    }
}

impl Drop for NamedTempFile {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = self.unlink();
        }
    }
}

/// Creates a named temporary file in `parent` relative to the current
/// directory, retaining a stable parent descriptor for cleanup.
#[inline]
pub fn create_temp_file<P: PathArg, Prefix: PathArg>(
    parent: P,
    prefix: Prefix,
) -> Result<NamedTempFile> {
    parent.into_with_c_str(|parent| {
        let directory = openat(
            CWD,
            parent,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        create_temp_file_at(&directory, prefix)
    })
}

/// Creates a named temporary file relative to an already-open directory.
///
/// `parent` must be a real open directory descriptor, not the special
/// `AT_FDCWD` token: retaining a duplicate is what makes drop cleanup immune
/// to later current-directory changes. The generated basename is available
/// through [`NamedTempFile::name`].
#[inline]
pub fn create_temp_file_at<Fd: AsFd, Prefix: PathArg>(
    parent: Fd,
    prefix: Prefix,
) -> Result<NamedTempFile> {
    let parent = parent.as_fd();
    if parent.as_raw_fd() < 0 {
        return Err(Errno::BADF);
    }
    let parent = crate::io::fcntl_dupfd_cloexec(parent, 0)?;
    prefix.into_with_c_str(|prefix| {
        let (name, name_len, fd) = create_temp_file_at_bytes(&parent, prefix.to_bytes())?;
        Ok(NamedTempFile {
            fd,
            parent,
            name,
            name_len: name_len as u16,
            cleanup: true,
        })
    })
}

fn create_temp_file_at_bytes<Fd: AsFd>(
    parent: Fd,
    prefix: &[u8],
) -> Result<([u8; TEMP_FILE_NAME_MAX + 1], usize, OwnedFd)> {
    let name_len = validate_temp_file_prefix(prefix)?;
    let mut candidate = [0u8; TEMP_FILE_NAME_MAX + 1];
    let mut entropy = [0u8; TEMP_FILE_RANDOM_BYTES];
    let hex = b"0123456789abcdef";
    let mut attempt = 0;
    while attempt < TEMP_FILE_MAX_ATTEMPTS {
        crate::rand::getentropy(&mut entropy)?;
        candidate[..prefix.len()].copy_from_slice(prefix);
        for (index, byte) in entropy.iter().enumerate() {
            candidate[prefix.len() + index * 2] = hex[(byte >> 4) as usize];
            candidate[prefix.len() + index * 2 + 1] = hex[(byte & 0x0f) as usize];
        }
        candidate[name_len] = 0;
        let candidate_cstr =
            unsafe { CStr::from_bytes_with_nul_unchecked(&candidate[..name_len + 1]) };
        match openat(
            parent.as_fd(),
            candidate_cstr,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_bits_retain(TEMP_FILE_MODE_BITS),
        ) {
            Ok(fd) => return Ok((candidate, name_len, fd)),
            Err(Errno::EXIST) => attempt += 1,
            Err(error) => return Err(error),
        }
    }
    Err(Errno::EXIST)
}

#[inline]
fn validate_temp_file_prefix(prefix: &[u8]) -> Result<usize> {
    if prefix.is_empty() || prefix.iter().any(|&byte| byte == b'/') {
        return Err(Errno::INVAL);
    }
    let name_len = prefix
        .len()
        .checked_add(TEMP_FILE_SUFFIX_LENGTH)
        .ok_or(Errno::NAMETOOLONG)?;
    if name_len > TEMP_FILE_NAME_MAX {
        return Err(Errno::NAMETOOLONG);
    }
    Ok(name_len)
}

/// A descriptor-owned anonymous temporary regular file.
///
/// `TempFile` uses Linux `O_TMPFILE | O_RDWR | O_CLOEXEC` relative to the
/// requested directory. It never creates a directory entry, and dropping the
/// value closes the only Rust ownership token for the inode. The requested
/// [`Mode`] is used at creation time and remains subject to the process umask.
///
/// This API deliberately has no named-file or `mkstemp` fallback. A filesystem
/// that cannot create anonymous temporary files returns
/// [`Errno::OPNOTSUPP`] from [`Self::open`] or [`Self::open_at`]. Callers that
/// need a pathname must choose and audit a separate named-file contract.
#[repr(transparent)]
pub struct TempFile {
    fd: OwnedFd,
}

impl TempFile {
    /// Opens an anonymous temporary file in `directory` relative to CWD.
    ///
    /// `directory` must name a directory on a filesystem supporting Linux
    /// `O_TMPFILE`; the successful descriptor is opened read/write and
    /// close-on-exec. No pathname is returned or created. `EOPNOTSUPP` is
    /// returned unchanged when the filesystem lacks this operation.
    #[inline]
    pub fn open<P: PathArg>(directory: P, mode: Mode) -> Result<Self> {
        Self::open_at(CWD, directory, mode)
    }

    /// Opens an anonymous temporary file in `directory` relative to `dirfd`.
    ///
    /// The directory descriptor remains the caller's responsibility; only the
    /// newly created temporary-file descriptor is moved into `TempFile`.
    /// `directory` must name a directory on a filesystem supporting Linux
    /// `O_TMPFILE`. No named-file fallback is attempted on `EOPNOTSUPP`.
    #[inline]
    pub fn open_at<Fd: AsFd, P: PathArg>(dirfd: Fd, directory: P, mode: Mode) -> Result<Self> {
        openat(
            dirfd,
            directory,
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            mode,
        )
        .map(|fd| Self { fd })
    }

    /// Borrows the anonymous file descriptor for direct I/O and metadata
    /// operations.
    #[inline]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Consumes the temporary-file wrapper and returns its owned descriptor.
    ///
    /// The descriptor remains anonymous; transferring it does not create a
    /// directory entry or change its close-on-exec status.
    #[inline]
    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for TempFile {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.as_fd()
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsRawFd for TempFile {
    #[inline]
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.as_fd().as_raw_fd()
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsFd for TempFile {
    #[inline]
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // SAFETY: `TempFile` owns its descriptor through `OwnedFd`, so it
        // remains open for the returned standard-library borrow.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.as_fd().as_raw_fd()) }
    }
}

/// Sets the length of an open file descriptor.
///
/// The length is an unsigned byte count at this facade boundary. Values above
/// Linux's signed loff_t range return [Errno::INVAL](crate::Errno::INVAL)
/// before the descriptor is borrowed or the direct ftruncate(2) syscall is
/// issued. Successful extension creates a zero-filled byte range; all
/// descriptor and filesystem errors remain direct kernel results.
#[inline]
pub fn ftruncate<Fd: AsFd>(fd: Fd, length: u64) -> Result<()> {
    if length > i64::MAX as u64 {
        return Err(Errno::INVAL);
    }

    crabc_core::fs::ftruncate(fd.as_fd().as_raw_fd(), length as i64)
}

/// Sets the length of a pathname-selected file.
///
/// This is the direct Linux `truncate(2)` operation through the fixed-stack
/// [`PathArg`] boundary. Values above the signed `loff_t` range return
/// [`Errno::INVAL`] before pathname conversion or syscall entry. It does not
/// resolve a descriptor, allocate, or provide a C ABI wrapper.
#[inline]
pub fn truncate<P: PathArg>(path: P, length: u64) -> Result<()> {
    if length > i64::MAX as u64 {
        return Err(Errno::INVAL);
    }

    path.into_with_c_str(|path| crabc_core::fs::truncate(path, length as i64))
}

/// Sets access and modification timestamps relative to `dirfd`.
///
/// The descriptor and fixed-stack pathname are borrowed only for the direct
/// Linux `utimensat(2)` syscall. This closed operation accepts only
/// [`TimestampAtFlags::SYMLINK_NOFOLLOW`]; it does not expose `AT_EMPTY_PATH`,
/// general pathname mutation, or a public C timestamp API. Linux validates
/// ordinary nanoseconds and [`UTIME_NOW`]/[`UTIME_OMIT`] directly.
#[inline]
pub fn utimensat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    times: &Timestamps,
    flags: TimestampAtFlags,
) -> Result<()> {
    let flags = TimestampAtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: `path` and `times` remain valid for the direct syscall, and
        // `Timestamps` is exactly two Linux/x86-64 `timespec` values.
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

/// Sets access and modification timestamps on an open file or directory.
///
/// This is the descriptor-only `utimensat(2)` form: Linux receives the
/// borrowed descriptor, a null pathname, two exact x86-64 [`Timespec`]
/// records, and zero flags. The timestamp pair remains live for the direct
/// syscall, and Linux validates normal nanoseconds, [`UTIME_NOW`], and
/// [`UTIME_OMIT`] without a libc wrapper or TLS `errno`.
#[inline]
pub fn futimens<Fd: AsFd>(fd: Fd, times: &Timestamps) -> Result<()> {
    // SAFETY: `times` remains valid for the direct syscall, and its layout is
    // exactly two Linux/x86-64 `timespec` values. A null path selects the
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

/// Sets access and modification times on an open file using microseconds.
///
/// `None` sends a null timestamp pointer and asks Linux to set both values to
/// the current time. For explicit values, each `tv_usec` must be in
/// `0..1_000_000`; invalid values return [`Errno::INVAL`] before the
/// descriptor is borrowed or the direct syscall is issued.
#[inline]
pub fn futimes<Fd: AsFd>(fd: Fd, times: Option<&[Timeval; 2]>) -> Result<()> {
    let converted = match times {
        None => None,
        Some(times) => Some([
            timeval_to_timespec(times[0])?,
            timeval_to_timespec(times[1])?,
        ]),
    };
    let times_ptr = converted
        .as_ref()
        .map_or(core::ptr::null(), |times| times.as_ptr());

    // SAFETY: the borrowed descriptor and optional converted timestamp array
    // remain valid for this direct syscall. A null timestamp pointer selects
    // Linux's current-time behavior.
    unsafe {
        crabc_core::fs::utimensat_raw(
            fd.as_fd().as_raw_fd(),
            core::ptr::null(),
            times_ptr.cast(),
            0,
        )
    }
}

/// Sets timestamps for a final symbolic link rather than its target.
///
/// `None` asks Linux to set both link timestamps to the current time. Explicit
/// microsecond values are validated before the fixed-stack pathname conversion
/// and direct syscall.
#[inline]
pub fn lutimes<P: PathArg>(path: P, times: Option<&[Timeval; 2]>) -> Result<()> {
    let converted = match times {
        None => None,
        Some(times) => Some([
            timeval_to_timespec(times[0])?,
            timeval_to_timespec(times[1])?,
        ]),
    };
    let times_ptr = converted
        .as_ref()
        .map_or(core::ptr::null(), |times| times.as_ptr());
    path.into_with_c_str(|path| {
        // SAFETY: the path and optional converted timestamp array remain live
        // for the direct syscall. The no-follow flag updates the final
        // symbolic link itself rather than resolving it to its target.
        unsafe {
            crabc_core::fs::utimensat_raw(
                crabc_core::AT_FDCWD,
                path.as_ptr().cast(),
                times_ptr.cast(),
                TimestampAtFlags::SYMLINK_NOFOLLOW.bits(),
            )
        }
    })
}

/// Sets timestamps for a path relative to `dirfd`, following a final symlink.
///
/// `None` asks Linux to set both timestamps to the current time. Explicit
/// microsecond values are validated before the descriptor is borrowed or the
/// fixed-stack pathname is converted.
#[inline]
pub fn futimesat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    times: Option<&[Timeval; 2]>,
) -> Result<()> {
    let converted = match times {
        None => None,
        Some(times) => Some([
            timeval_to_timespec(times[0])?,
            timeval_to_timespec(times[1])?,
        ]),
    };
    let times_ptr = converted
        .as_ref()
        .map_or(core::ptr::null(), |times| times.as_ptr());
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: the borrowed directory descriptor, path, and optional
        // converted timestamp array remain live for the direct syscall.
        // Zero flags preserve final-symlink-following behavior.
        unsafe {
            crabc_core::fs::utimensat_raw(
                dirfd.as_raw_fd(),
                path.as_ptr().cast(),
                times_ptr.cast(),
                0,
            )
        }
    })
}

/// Sets timestamps for a current-directory-relative path, following a final
/// symbolic link.
///
/// `None` asks Linux to set both timestamps to the current time. Explicit
/// microsecond values are validated before the fixed-stack pathname conversion
/// and direct syscall.
#[inline]
pub fn utimes<P: PathArg>(path: P, times: Option<&[Timeval; 2]>) -> Result<()> {
    let converted = match times {
        None => None,
        Some(times) => Some([
            timeval_to_timespec(times[0])?,
            timeval_to_timespec(times[1])?,
        ]),
    };
    let times_ptr = converted
        .as_ref()
        .map_or(core::ptr::null(), |times| times.as_ptr());
    path.into_with_c_str(|path| {
        // SAFETY: the path and optional converted timestamp array remain live
        // for the direct syscall. Zero flags preserve final-symlink-following
        // behavior.
        unsafe {
            crabc_core::fs::utimensat_raw(
                crabc_core::AT_FDCWD,
                path.as_ptr().cast(),
                times_ptr.cast(),
                0,
            )
        }
    })
}

/// Sets timestamps for a current-directory-relative path at whole-second
/// precision, following a final symbolic link.
///
/// `None` asks Linux to set both timestamps to the current time. Explicit
/// [`Utimbuf`] values are converted to two [`Timespec`] records with zero
/// nanoseconds before entering the direct syscall.
#[inline]
pub fn utime<P: PathArg>(path: P, times: Option<&Utimbuf>) -> Result<()> {
    let converted = times.map(|times| {
        [
            Timespec {
                tv_sec: times.actime,
                tv_nsec: 0,
            },
            Timespec {
                tv_sec: times.modtime,
                tv_nsec: 0,
            },
        ]
    });
    let times_ptr = converted
        .as_ref()
        .map_or(core::ptr::null(), |times| times.as_ptr());
    path.into_with_c_str(|path| {
        // SAFETY: the path and optional converted timestamp array remain live
        // for the direct syscall. Zero flags preserve final-symlink-following
        // behavior.
        unsafe {
            crabc_core::fs::utimensat_raw(
                crabc_core::AT_FDCWD,
                path.as_ptr().cast(),
                times_ptr.cast(),
                0,
            )
        }
    })
}

#[inline]
fn timeval_to_timespec(time: Timeval) -> Result<Timespec> {
    if time.tv_usec < 0 || time.tv_usec >= 1_000_000 {
        return Err(Errno::INVAL);
    }
    Ok(Timespec {
        tv_sec: time.tv_sec,
        tv_nsec: time.tv_usec * 1_000,
    })
}

/// Allocates, zeros, or punches a range in an open file.
///
/// The syscall borrows the supplied raw descriptor for its duration: passing a
/// reference or [`BorrowedFd`] retains Rust descriptor ownership, while an
/// owning [`AsFd`] passed by value follows ordinary Rust move/drop semantics.
/// `offset` and `length` are non-negative byte counts. Both must fit Linux's
/// signed `loff_t`, and their sum must not overflow that range; these invalid
/// ranges return [`Errno::INVAL`] before a syscall.
/// `PUNCH_HOLE` requires `KEEP_SIZE`, and unknown or unsupported mode bits are
/// rejected before a syscall. The operation never changes the descriptor's
/// current file position. `ALLOCATE` extends the file when necessary;
/// `KEEP_SIZE` suppresses that extension.
#[inline]
pub fn fallocate<Fd: AsFd>(
    fd: Fd,
    flags: FallocateFlags,
    offset: u64,
    length: u64,
) -> Result<()> {
    if FallocateFlags::from_bits(flags.bits()).is_none()
        || (flags.contains(FallocateFlags::PUNCH_HOLE)
            && !flags.contains(FallocateFlags::KEEP_SIZE))
        || (flags.contains(FallocateFlags::PUNCH_HOLE)
            && flags.contains(FallocateFlags::ZERO_RANGE))
        || offset > i64::MAX as u64
        || length > i64::MAX as u64
        || offset
            .checked_add(length)
            .map_or(true, |end| end > i64::MAX as u64)
    {
        return Err(Errno::INVAL);
    }

    crabc_core::fs::fallocate(
        fd.as_fd().as_raw_fd(),
        flags.bits(),
        offset as i64,
        length as i64,
    )
}

/// Allocates a non-negative byte range using Linux `fallocate(2)` mode zero,
/// the native Rust spelling of POSIX `posix_fallocate`.
///
/// This fixes the mode to zero and otherwise has the same descriptor,
/// range-validation, position, and direct-kernel-error contract as
/// [`fallocate`]. Unlike the C `posix_fallocate` function's direct integer
/// error convention, this API returns [`Result<(), Errno>`] and does not use
/// libc or TLS `errno`.
#[inline]
pub fn posix_fallocate<Fd: AsFd>(fd: Fd, offset: u64, length: u64) -> Result<()> {
    fallocate(fd, FallocateFlags::empty(), offset, length)
}

/// Transfers up to `count` bytes from the supplied input descriptor to the
/// supplied output descriptor through Linux `sendfile(2)`.
///
/// With `offset == Some`, Linux starts at the supplied non-negative input
/// offset, leaves the input descriptor's shared position unchanged, and
/// writes the resulting position back through the same mutable reference.
/// With `offset == None`, Linux starts at and advances the input descriptor's
/// shared position. The output descriptor's shared position advances in both
/// forms. A short transfer is returned as its actual byte count. The syscall
/// does not transfer kernel descriptor ownership. Passing a reference or
/// [`BorrowedFd`] retains Rust descriptor ownership; as with any by-value
/// Rust parameter, an owning `AsFd` value is consumed by the call.
///
/// The optional offset is a Rust in/out borrow, not a nullable C `off_t *`:
/// values above Linux's signed `off_t` range are rejected with
/// [`Errno::INVAL`] before the syscall, and the reference remains valid for
/// the call. This direct descriptor-transfer boundary does not admit
/// splice-family operations, pathname opening, or a C ABI.
#[inline]
pub fn sendfile<OutFd: AsFd, InFd: AsFd>(
    out_fd: OutFd,
    in_fd: InFd,
    offset: Option<&mut u64>,
    count: usize,
) -> Result<usize> {
    if offset
        .as_ref()
        .map_or(false, |offset| **offset > i64::MAX as u64)
    {
        return Err(Errno::INVAL);
    }

    crabc_core::io::sendfile(
        out_fd.as_fd().as_raw_fd(),
        in_fd.as_fd().as_raw_fd(),
        offset,
        count,
    )
}

/// Copies up to `len` bytes between the supplied descriptors through Linux
/// `copy_file_range(2)`.
///
/// A supplied `off_in` or `off_out` is an explicit in/out byte position. Its
/// descriptor's shared position remains unchanged, while the supplied value
/// advances by the copied byte count. With `None`, Linux uses and advances
/// that descriptor's shared position. A short copy, including zero at end of
/// input, is returned as its actual byte count.
///
/// Explicit offsets and their requested ranges must fit signed Linux
/// `loff_t`. The wrapper stages both offsets in local initialized values and
/// commits them only after a successful syscall, so an error leaves caller
/// offsets unchanged. The syscall borrows raw descriptor values for the call;
/// passing a reference or [`BorrowedFd`] retains Rust descriptor ownership,
/// while an owning `AsFd` passed by value follows ordinary Rust move/drop
/// semantics. This boundary always passes zero Linux copy flags and does not
/// admit copy flags, sendfile/splice fallbacks, pathname operations, a C ABI,
/// or general file-copy policy.
#[inline]
pub fn copy_file_range<InFd: AsFd, OutFd: AsFd>(
    in_fd: InFd,
    off_in: Option<&mut u64>,
    out_fd: OutFd,
    off_out: Option<&mut u64>,
    len: usize,
) -> Result<usize> {
    let len_as_u64 = len as u64;
    let max_loff_t = i64::MAX as u64;
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
        return Err(Errno::INVAL);
    }

    let mut in_offset = in_initial;
    let mut out_offset = out_initial;
    let in_fd = in_fd.as_fd();
    let out_fd = out_fd.as_fd();
    let copied = crabc_core::fs::copy_file_range(
        in_fd.as_raw_fd(),
        in_offset.as_mut(),
        out_fd.as_raw_fd(),
        out_offset.as_mut(),
        len,
    )?;

    // Commit only after a successful syscall. In particular, this prevents a
    // partially updated kernel in/out pointer from escaping on an error.
    if let (Some(offset), Some(updated)) = (off_in, in_offset) {
        *offset = updated;
    }
    if let (Some(offset), Some(updated)) = (off_out, out_offset) {
        *offset = updated;
    }
    Ok(copied)
}

/// The Linux file-position origins accepted by [`seek`].
///
/// `Data` and `Hole` select Linux sparse-file regions in addition to the
/// ordinary absolute, end-relative, and current-position origins. Unsupported
/// sparse seeking or an invalid resulting position remains a direct kernel
/// error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SeekFrom {
    /// Set the position to an absolute byte offset.
    Start(u64),
    /// Set the position relative to the end of the file.
    End(i64),
    /// Set the position relative to the current file position.
    Current(i64),
    /// Set the position to the next data region at or after an absolute byte
    /// offset.
    Data(u64),
    /// Set the position to the next hole at or after an absolute byte offset.
    Hole(u64),
}

/// Repositions an open descriptor through Linux `lseek(2)`.
///
/// Successful Linux positions are non-negative and are returned as an
/// unsigned byte offset. Absolute `Start`, `Data`, and `Hole` values above
/// `i64::MAX` are passed through their signed Linux `off_t` representation,
/// so their direct Linux error is preserved: a negative `SEEK_SET` position
/// is `EINVAL`, while sparse `SEEK_DATA`/`SEEK_HOLE` may report `ENXIO`.
/// Relative positions retain their signed Linux representation, so an invalid
/// resulting offset remains the kernel's direct error.
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

    // Linux reports a non-negative signed off_t on every successful seek;
    // preserve that direct kernel value in the facade's unsigned byte count.
    crabc_core::fs::lseek(fd.as_fd().as_raw_fd(), offset, whence).map(|offset| offset as u64)
}

/// Returns an open descriptor's current byte position without changing it.
#[inline]
#[doc(alias = "lseek")]
pub fn tell<Fd: AsFd>(fd: Fd) -> Result<u64> {
    crabc_core::fs::lseek(fd.as_fd().as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)
        .map(|offset| offset as u64)
}

/// Flushes file data and metadata for an open descriptor through Linux
/// `fsync(2)`.
///
/// The descriptor is borrowed only for the direct syscall; filesystem and
/// descriptor errors remain unchanged [`Errno`] values.
#[inline]
pub fn fsync<Fd: AsFd>(fd: Fd) -> Result<()> {
    crabc_core::fs::fsync(fd.as_fd().as_raw_fd())
}

/// Flushes file data for an open descriptor through Linux `fdatasync(2)`.
///
/// The descriptor is borrowed only for the direct syscall; filesystem and
/// descriptor errors remain unchanged [`Errno`] values.
#[inline]
pub fn fdatasync<Fd: AsFd>(fd: Fd) -> Result<()> {
    crabc_core::fs::fdatasync(fd.as_fd().as_raw_fd())
}

/// Requests system-wide filesystem synchronization through Linux `sync(2)`.
///
/// Unlike [`syncfs`], this operation is neither descriptor- nor
/// filesystem-scoped: it includes dirty data reachable through other
/// descriptors and filesystems in the calling system. Linux waits for
/// kernel/filesystem writeback completion before returning, but that is not a
/// promise that a device's volatile cache has reached nonvolatile media.
/// Linux specifies this syscall as always successful, so the typed Rust
/// operation returns `()` without libc or TLS `errno`.
#[inline]
pub fn sync() {
    crabc_core::fs::sync();
}

/// Requests synchronization of the filesystem associated with `fd`
/// through Linux `syncfs(2)`.
///
/// The descriptor is borrowed only for the direct syscall. A successful
/// request is a Linux kernel/filesystem writeback completion point, not a
/// promise that a device's volatile cache has reached nonvolatile media.
/// Descriptor and filesystem errors remain unchanged [`Errno`] values. This
/// does not admit the separate process/system-wide `sync(2)` operation.
#[inline]
pub fn syncfs<Fd: AsFd>(fd: Fd) -> Result<()> {
    crabc_core::fs::syncfs(fd.as_fd().as_raw_fd())
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

impl Stat {
    /// Returns the file kind encoded in [`Self::st_mode`].
    #[inline]
    pub const fn file_type(self) -> FileType {
        FileType::from_raw_mode(self.st_mode)
    }

    /// Returns the permission and special bits encoded in [`Self::st_mode`].
    #[inline]
    pub const fn mode(self) -> Mode {
        Mode::from_raw_mode(self.st_mode)
    }
}

/// Linux `struct statx` metadata returned by [`statx`].
///
/// The 256-byte record is shared by the admitted Linux targets. Optional
/// observations are valid only when their corresponding bit is present in
/// [`Self::stx_mask`]; callers must not infer support merely from the
/// requested mask.
#[doc(alias = "struct statx")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Statx {
    /// Fields supplied by the kernel.
    pub stx_mask: u32,
    /// Preferred I/O block size.
    pub stx_blksize: u32,
    /// File attributes.
    pub stx_attributes: StatxAttributes,
    /// Hard-link count.
    pub stx_nlink: u32,
    /// Owning user ID.
    pub stx_uid: u32,
    /// Owning group ID.
    pub stx_gid: u32,
    /// File type and permission bits.
    pub stx_mode: u16,
    __spare0: [u16; 1],
    /// Inode number.
    pub stx_ino: u64,
    /// File size in bytes.
    pub stx_size: u64,
    /// Allocated 512-byte blocks.
    pub stx_blocks: u64,
    /// Attributes understood by the filesystem.
    pub stx_attributes_mask: StatxAttributes,
    /// Last-access timestamp.
    pub stx_atime: StatxTimestamp,
    /// Birth/creation timestamp, when supplied.
    pub stx_btime: StatxTimestamp,
    /// Last-status-change timestamp.
    pub stx_ctime: StatxTimestamp,
    /// Last-modification timestamp.
    pub stx_mtime: StatxTimestamp,
    /// Device major number for special files.
    pub stx_rdev_major: u32,
    /// Device minor number for special files.
    pub stx_rdev_minor: u32,
    /// Containing filesystem device major number.
    pub stx_dev_major: u32,
    /// Containing filesystem device minor number.
    pub stx_dev_minor: u32,
    /// Mount ID, when supplied.
    pub stx_mnt_id: u64,
    /// Minimum direct-I/O memory alignment, when supplied.
    pub stx_dio_mem_align: u32,
    /// Direct-I/O offset alignment, when supplied.
    pub stx_dio_offset_align: u32,
    /// Subvolume identifier.
    pub stx_subvol: u64,
    /// Minimum atomic-write unit.
    pub stx_atomic_write_unit_min: u32,
    /// Maximum atomic-write unit.
    pub stx_atomic_write_unit_max: u32,
    /// Maximum number of atomic-write segments.
    pub stx_atomic_write_segments_max: u32,
    /// Direct-I/O read-offset alignment.
    pub stx_dio_read_offset_align: u32,
    /// Optional maximum atomic-write unit.
    pub stx_atomic_write_unit_max_opt: u32,
    __spare2: [u32; 1],
    __spare3: [u64; 8],
}

/// One timestamp in Linux's `struct statx` output.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct StatxTimestamp {
    /// Seconds since the Unix epoch.
    pub tv_sec: i64,
    /// Nanoseconds within the second.
    pub tv_nsec: u32,
    __reserved: i32,
}

bitflags! {
    /// `STATX_*` fields accepted by [`statx`].
    ///
    /// This is deliberately closed to the fields understood by this pinned
    /// facade. [`Statx::stx_mask`] remains authoritative when a kernel omits
    /// a requested field or supplies only a subset of the request.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct StatxFlags: u32 {
        /// File type.
        const TYPE = 0x0001;
        /// Permission and file-type mode.
        const MODE = 0x0002;
        /// Hard-link count.
        const NLINK = 0x0004;
        /// Owning user ID.
        const UID = 0x0008;
        /// Owning group ID.
        const GID = 0x0010;
        /// Last-access timestamp.
        const ATIME = 0x0020;
        /// Last-modification timestamp.
        const MTIME = 0x0040;
        /// Last-status-change timestamp.
        const CTIME = 0x0080;
        /// Inode number.
        const INO = 0x0100;
        /// File size.
        const SIZE = 0x0200;
        /// Allocated 512-byte blocks.
        const BLOCKS = 0x0400;
        /// All basic metadata fields.
        const BASIC_STATS = 0x07ff;
        /// Birth/creation timestamp.
        const BTIME = 0x0800;
        /// Mount ID.
        const MNT_ID = 0x1000;
        /// Direct-I/O alignment fields.
        const DIOALIGN = 0x2000;
        /// The historical `STATX_ALL` mask.
        const ALL = 0x0fff;
    }
}

impl StatxFlags {
    /// Reserved mask bit rejected before entering the kernel.
    ///
    /// It is exposed as a raw value only so callers testing direct Linux
    /// compatibility can construct a retained bitflags value; it is not a
    /// valid member of this closed flag set.
    pub const RESERVED_MASK: u32 = 0x8000_0000;
}

bitflags! {
    /// `STATX_ATTR_*` bits reported in [`Statx::stx_attributes`].
    ///
    /// This is a closed set matching the pinned facade contract. Unknown
    /// kernel attribute bits remain raw kernel observations; this facade does
    /// not invent names for them.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct StatxAttributes: u64 {
        /// File is compressed.
        const COMPRESSED = 0x0000_0000_0000_0004;
        /// File is immutable.
        const IMMUTABLE = 0x0000_0000_0000_0010;
        /// File is append-only.
        const APPEND = 0x0000_0000_0000_0020;
        /// File is excluded from filesystem dumps.
        const NODUMP = 0x0000_0000_0000_0040;
        /// File is encrypted.
        const ENCRYPTED = 0x0000_0000_0000_0800;
        /// Automount trigger.
        const AUTOMOUNT = 0x0000_0000_0000_1000;
        /// Mount root.
        const MOUNT_ROOT = 0x0000_0000_0000_2000;
        /// Verity-protected file.
        const VERITY = 0x0000_0000_0010_0000;
        /// DAX file.
        const DAX = 0x0000_0000_0020_0000;
    }
}

const _: [(); 256] = [(); core::mem::size_of::<Statx>()];
const _: [(); 8] = [(); core::mem::align_of::<Statx>()];
const _: [(); 16] = [(); core::mem::size_of::<StatxTimestamp>()];
const _: [(); 8] = [(); core::mem::align_of::<StatxTimestamp>()];
const _: [(); 0] = [(); core::mem::offset_of!(Statx, stx_mask)];
const _: [(); 4] = [(); core::mem::offset_of!(Statx, stx_blksize)];
const _: [(); 8] = [(); core::mem::offset_of!(Statx, stx_attributes)];
const _: [(); 16] = [(); core::mem::offset_of!(Statx, stx_nlink)];
const _: [(); 20] = [(); core::mem::offset_of!(Statx, stx_uid)];
const _: [(); 24] = [(); core::mem::offset_of!(Statx, stx_gid)];
const _: [(); 28] = [(); core::mem::offset_of!(Statx, stx_mode)];
const _: [(); 32] = [(); core::mem::offset_of!(Statx, stx_ino)];
const _: [(); 40] = [(); core::mem::offset_of!(Statx, stx_size)];
const _: [(); 48] = [(); core::mem::offset_of!(Statx, stx_blocks)];
const _: [(); 56] = [(); core::mem::offset_of!(Statx, stx_attributes_mask)];
const _: [(); 64] = [(); core::mem::offset_of!(Statx, stx_atime)];
const _: [(); 80] = [(); core::mem::offset_of!(Statx, stx_btime)];
const _: [(); 96] = [(); core::mem::offset_of!(Statx, stx_ctime)];
const _: [(); 112] = [(); core::mem::offset_of!(Statx, stx_mtime)];
const _: [(); 128] = [(); core::mem::offset_of!(Statx, stx_rdev_major)];
const _: [(); 132] = [(); core::mem::offset_of!(Statx, stx_rdev_minor)];
const _: [(); 136] = [(); core::mem::offset_of!(Statx, stx_dev_major)];
const _: [(); 140] = [(); core::mem::offset_of!(Statx, stx_dev_minor)];
const _: [(); 144] = [(); core::mem::offset_of!(Statx, stx_mnt_id)];
const _: [(); 152] = [(); core::mem::offset_of!(Statx, stx_dio_mem_align)];
const _: [(); 156] = [(); core::mem::offset_of!(Statx, stx_dio_offset_align)];

bitflags! {
    /// Linux mount flags reported by [`StatFs`] and [`StatVfs`].
    ///
    /// Unknown bits are retained so observations from newer kernels are not
    /// discarded. These are filesystem observations, not mount-changing
    /// operation flags.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct StatVfsMountFlags: u64 {
        /// `ST_RDONLY`.
        const RDONLY = 0x0000_0001;
        /// `ST_NOSUID`.
        const NOSUID = 0x0000_0002;
        /// `ST_NODEV`.
        const NODEV = 0x0000_0004;
        /// `ST_NOEXEC`.
        const NOEXEC = 0x0000_0008;
        /// `ST_SYNCHRONOUS`.
        const SYNCHRONOUS = 0x0000_0010;
        /// `ST_MANDLOCK`.
        const MANDLOCK = 0x0000_0040;
        /// `ST_NOATIME`.
        const NOATIME = 0x0000_0400;
        /// `ST_NODIRATIME`.
        const NODIRATIME = 0x0000_0800;
        /// `ST_RELATIME`.
        const RELATIME = 0x0000_1000;
        /// Preserve future Linux-defined mount bits.
        const _ = !0;
    }
}

/// Linux/x86-64 `struct statfs` filesystem statistics.
///
/// This is the kernel representation returned by [`statfs`] and
/// [`fstatfs`], not a public C ABI alias. The spare words remain private so
/// the output buffer retains the complete 120-byte x86-64 layout.
#[doc(alias = "struct statfs")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct StatFs {
    /// Filesystem type magic number.
    pub f_type: i64,
    /// Fundamental block size in bytes.
    pub f_bsize: i64,
    /// Total data blocks in the filesystem.
    pub f_blocks: u64,
    /// Free blocks, including blocks reserved for the superuser.
    pub f_bfree: u64,
    /// Free blocks available to an unprivileged caller.
    pub f_bavail: u64,
    /// Total file nodes.
    pub f_files: u64,
    /// Free file nodes.
    pub f_ffree: u64,
    /// Filesystem identifier words.
    pub f_fsid: [i32; 2],
    /// Maximum filename length.
    pub f_namelen: i64,
    /// Fragment size, or zero when not reported.
    pub f_frsize: i64,
    /// Linux mount flags.
    pub f_flags: i64,
    __spare: [i64; 4],
}

const _: [(); 120] = [(); core::mem::size_of::<StatFs>()];
const _: [(); 8] = [(); core::mem::align_of::<StatFs>()];
const _: [(); 0] = [(); core::mem::offset_of!(StatFs, f_type)];
const _: [(); 8] = [(); core::mem::offset_of!(StatFs, f_bsize)];
const _: [(); 16] = [(); core::mem::offset_of!(StatFs, f_blocks)];
const _: [(); 24] = [(); core::mem::offset_of!(StatFs, f_bfree)];
const _: [(); 32] = [(); core::mem::offset_of!(StatFs, f_bavail)];
const _: [(); 40] = [(); core::mem::offset_of!(StatFs, f_files)];
const _: [(); 48] = [(); core::mem::offset_of!(StatFs, f_ffree)];
const _: [(); 56] = [(); core::mem::offset_of!(StatFs, f_fsid)];
const _: [(); 64] = [(); core::mem::offset_of!(StatFs, f_namelen)];
const _: [(); 72] = [(); core::mem::offset_of!(StatFs, f_frsize)];
const _: [(); 80] = [(); core::mem::offset_of!(StatFs, f_flags)];
const _: [(); 88] = [(); core::mem::offset_of!(StatFs, __spare)];

/// POSIX-shaped filesystem statistics derived from Linux [`StatFs`].
///
/// Linux has no separate `statvfs` syscall. The facade performs `statfs` or
/// `fstatfs` and applies musl's Linux field mapping: a zero fragment size
/// falls back to the fundamental block size, available file nodes equal the
/// reported free file nodes, and `f_fsid` is the first signed Linux
/// filesystem-id word widened to `u64`.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct StatVfs {
    /// Fundamental block size in bytes.
    pub f_bsize: u64,
    /// Fragment size in bytes, falling back to `f_bsize` when absent.
    pub f_frsize: u64,
    /// Total data blocks in the filesystem.
    pub f_blocks: u64,
    /// Free blocks, including blocks reserved for the superuser.
    pub f_bfree: u64,
    /// Free blocks available to an unprivileged caller.
    pub f_bavail: u64,
    /// Total file nodes.
    pub f_files: u64,
    /// Free file nodes.
    pub f_ffree: u64,
    /// Available file nodes; Linux supplies no distinct value.
    pub f_favail: u64,
    /// The first Linux filesystem-id word, widened with musl's signed-to-
    /// unsigned conversion.
    pub f_fsid: u64,
    /// POSIX-shaped mount flags.
    pub f_flag: StatVfsMountFlags,
    /// Maximum filename length.
    pub f_namemax: u64,
}

impl From<StatFs> for StatVfs {
    #[inline]
    fn from(statfs: StatFs) -> Self {
        let f_bsize = statfs.f_bsize as u64;
        Self {
            f_bsize,
            f_frsize: if statfs.f_frsize != 0 { statfs.f_frsize as u64 } else { f_bsize },
            f_blocks: statfs.f_blocks,
            f_bfree: statfs.f_bfree,
            f_bavail: statfs.f_bavail,
            f_files: statfs.f_files,
            f_ffree: statfs.f_ffree,
            f_favail: statfs.f_ffree,
            f_fsid: statfs.f_fsid[0] as u64,
            f_flag: StatVfsMountFlags::from_bits_retain(statfs.f_flags as u64),
            f_namemax: statfs.f_namelen as u64,
        }
    }
}

/// Queries filesystem statistics for an open file or directory.
#[inline]
pub fn fstatfs<Fd: AsFd>(fd: Fd) -> Result<StatFs> {
    let fd = fd.as_fd();
    let mut statfs = MaybeUninit::<StatFs>::uninit();
    // SAFETY: `StatFs` is the complete 120-byte Linux/x86-64 output layout.
    unsafe { crabc_core::fs::fstatfs_raw(fd.as_raw_fd(), statfs.as_mut_ptr().cast())? };
    // SAFETY: a successful syscall initialized the complete output record.
    Ok(unsafe { statfs.assume_init() })
}

/// Queries filesystem statistics for `path` using the fixed-stack path boundary.
#[inline]
pub fn statfs<P: PathArg>(path: P) -> Result<StatFs> {
    path.into_with_c_str(|path| {
        let mut statfs = MaybeUninit::<StatFs>::uninit();
        // SAFETY: `PathArg` keeps the C string live and `StatFs` is complete.
        crabc_core::fs::statfs(path, statfs.as_mut_ptr().cast())?;
        // SAFETY: a successful syscall initialized the complete output record.
        Ok(unsafe { statfs.assume_init() })
    })
}

/// Queries POSIX-shaped filesystem statistics for an open descriptor.
#[inline]
pub fn fstatvfs<Fd: AsFd>(fd: Fd) -> Result<StatVfs> {
    fstatfs(fd).map(StatVfs::from)
}

/// Queries POSIX-shaped filesystem statistics for `path`.
#[inline]
pub fn statvfs<P: PathArg>(path: P) -> Result<StatVfs> {
    statfs(path).map(StatVfs::from)
}

/// Queries extended Linux metadata for `path` relative to `dirfd`.
///
/// This direct x86-64 `statx` shape enters Linux through syscall 332, returns
/// kernel errors directly, and does not emulate musl's `ENOSYS` compatibility
/// fallback or cache process-wide availability. The returned
/// [`Statx::stx_mask`] determines which requested observations are valid; a
/// successful call does not promise every requested field. Unlike [`statat`],
/// this operation accepts the separate [`StatxAtFlags`] vocabulary, including
/// its narrowly scoped `AT_EMPTY_PATH` and synchronization forms.
#[inline]
pub fn statx<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    flags: StatxAtFlags,
    mask: StatxFlags,
) -> Result<Statx> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        let mut statx = MaybeUninit::<Statx>::uninit();
        // SAFETY: `Statx` is the complete Linux 256-byte output layout,
        // while `PathArg` keeps its C string and the writable record storage
        // live for the direct syscall. The core seam owns mask prevalidation.
        unsafe {
            crabc_core::fs::statx_raw(
                dirfd.as_raw_fd(),
                path.as_ptr().cast(),
                flags.bits(),
                mask.bits(),
                statx.as_mut_ptr().cast(),
            )?
        };
        // SAFETY: A successful statx initialized the complete output record.
        Ok(unsafe { statx.assume_init() })
    })
}

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
/// The returned [`Stat`] is exactly the 144-byte Linux/x86-64 kernel layout.
/// `dirfd` is borrowed for the direct syscall, while [`PathArg`] keeps any
/// temporary pathname storage alive until Linux has consumed it. Only
/// [`AtFlags::SYMLINK_NOFOLLOW`] is admitted; `AT_EMPTY_PATH` and
/// `AT_NO_AUTOMOUNT` remain outside this `newfstatat(2)` boundary.
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
/// This is [`statat`] with [`CWD`] and no flags.
#[inline]
pub fn stat<P: PathArg>(path: P) -> Result<Stat> {
    statat(CWD, path, AtFlags::empty())
}

/// Queries x86-64 Linux metadata for a final symbolic link itself.
#[inline]
pub fn lstat<P: PathArg>(path: P) -> Result<Stat> {
    statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
}

/// Opens `path` relative to `dirfd` through Linux `openat(2)`.
///
/// The directory descriptor is borrowed and a successful direct syscall
/// transfers its fresh descriptor into [`OwnedFd`]. `O_*` meanings remain
/// Linux/x86-64 meanings: this facade supplies no portability mapping, libc
/// wrapper, or fallback. `create_mode` is meaningful only when Linux sees a
/// creation flag, and the process umask remains a kernel/process policy.
#[inline]
pub fn openat<P: PathArg, Fd: AsFd>(
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
            // SAFETY: successful Linux `openat` transfers one fresh,
            // non-negative descriptor into this RAII owner.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
    })
}

/// Opens `path` relative to the process current directory.
#[inline]
pub fn open<P: PathArg>(path: P, oflags: OFlags, create_mode: Mode) -> Result<OwnedFd> {
    openat(CWD, path, oflags, create_mode)
}

/// Creates or truncates a current-directory-relative file with `creat(2)`
/// semantics.
///
/// The returned descriptor is write-only. Linux applies the process umask to
/// `mode` when creating the entry; no close-on-exec policy is implied.
#[inline]
#[doc(alias = "creat")]
pub fn create<P: PathArg>(path: P, mode: Mode) -> Result<OwnedFd> {
    openat(
        CWD,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
        mode,
    )
}

/// Creates a directory relative to `dirfd`.
///
/// The fixed-stack path and borrowed directory descriptor remain live only
/// through the direct `mkdirat(2)` syscall. Linux applies the process umask.
#[inline]
pub fn mkdirat<P: PathArg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode) -> Result<()> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| crabc_core::fs::mkdirat(dirfd.as_raw_fd(), path, mode.bits()))
}

/// Creates a current-directory-relative directory.
#[inline]
pub fn mkdir<P: PathArg>(path: P, mode: Mode) -> Result<()> {
    mkdirat(CWD, path, mode)
}

/// Creates a Linux filesystem node relative to `dirfd`.
///
/// The file kind and permission/special bits are separate so callers cannot
/// accidentally override the requested type through `mode`. [`FileType::Unknown`]
/// is observation-only and rejected. `dev` is Linux's 64-bit `dev_t`; use
/// [`FIFO_DEVICE`] for [`FileType::Fifo`]. Character and block device policy
/// remains the kernel's direct privilege and filesystem decision.
#[inline]
pub fn mknodat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    file_type: FileType,
    mode: Mode,
    dev: Dev,
) -> Result<()> {
    if file_type == FileType::Unknown || mode.bits() & !0o7777 != 0 {
        return Err(Errno::INVAL);
    }

    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        crabc_core::fs::mknodat(
            dirfd.as_raw_fd(),
            path,
            file_type.as_raw_mode() | mode.bits(),
            dev,
        )
    })
}

/// Creates a FIFO node relative to `dirfd`.
#[inline]
pub fn mkfifoat<P: PathArg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode) -> Result<()> {
    mknodat(dirfd, path, FileType::Fifo, mode, FIFO_DEVICE)
}

/// Creates a current-directory-relative FIFO node.
#[inline]
pub fn mkfifo<P: PathArg>(path: P, mode: Mode) -> Result<()> {
    mkfifoat(CWD, path, mode)
}

/// Removes a path relative to `dirfd`.
///
/// [`UnlinkAtFlags::REMOVEDIR`] selects removal of an empty directory. The
/// closed flag type excludes `AT_EMPTY_PATH` and unrelated `AT_*` meanings.
#[inline]
pub fn unlinkat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    flags: UnlinkAtFlags,
) -> Result<()> {
    let flags = UnlinkAtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| crabc_core::fs::unlinkat(dirfd.as_raw_fd(), path, flags.bits()))
}

/// Removes a current-directory-relative non-directory entry.
#[inline]
pub fn unlink<P: PathArg>(path: P) -> Result<()> {
    unlinkat(CWD, path, UnlinkAtFlags::empty())
}

/// Removes a current-directory-relative empty directory.
#[inline]
pub fn rmdir<P: PathArg>(path: P) -> Result<()> {
    unlinkat(CWD, path, UnlinkAtFlags::REMOVEDIR)
}

/// Number of kernel-random bytes used for each temporary-directory candidate.
///
/// The bytes are encoded as 24 hexadecimal pathname bytes, giving every
/// candidate 96 bits of entropy before the atomic `mkdirat` attempt.
pub const TEMP_DIR_RANDOM_BYTES: usize = 12;

/// Maximum number of candidate names attempted after an `EEXIST` collision.
pub const TEMP_DIR_MAX_ATTEMPTS: usize = 128;

const TEMP_DIR_NAME_MAX: usize = 255;
const TEMP_DIR_SUFFIX_LENGTH: usize = TEMP_DIR_RANDOM_BYTES * 2;
const TEMP_DIR_MODE: Mode = Mode::RWXU;

// Linux's x86-64 pathname ceiling includes its terminating NUL. This local
// limit belongs to temporary pathname construction only; canonicalization is
// a separately staged x86 capability and must not leak its API or policy here.
const TEMP_DIR_PATH_MAX: usize = 4096;

/// Creates a private temporary directory below `parent` and writes the
/// resulting pathname with the caller's `parent` spelling into caller-owned
/// storage.
///
/// `parent` is opened as a directory before creation, so the actual creation
/// is descriptor-relative and does not depend on a process-global CWD race.
/// The returned bytes are still a pathname, not a retained directory handle;
/// callers coordinating CWD changes should prefer [`create_temp_dir_at_into`].
/// `prefix` is a non-empty, NUL-free single directory-entry prefix; it may
/// contain arbitrary non-UTF-8 bytes but may not contain `/`. The generated
/// suffix contains 96 bits from Linux `getrandom`, and each candidate is
/// created atomically with `mkdirat` using mode `0700` (the process umask may
/// only remove permissions). Up to [`TEMP_DIR_MAX_ATTEMPTS`] `EEXIST`
/// collisions are retried; another kernel error is returned unchanged.
///
/// The initialized output is the pathname bytes without a trailing NUL. This
/// operation never allocates and returns [`Errno::RANGE`] when the caller's
/// output is too small, [`Errno::INVAL`] for an invalid prefix, or
/// [`Errno::NAMETOOLONG`] when the directory-entry/pathname bounds are
/// exceeded. No libc ABI, C `errno`, or process-global temporary-directory
/// state is used.
#[inline]
pub fn create_temp_dir_into<P: PathArg, Prefix: PathArg, Buf: Buffer<u8>>(
    parent: P,
    prefix: Prefix,
    mut output: Buf,
) -> Result<Buf::Output> {
    let (pointer, capacity) = output.parts_mut();
    let initialized = parent.into_with_c_str(|parent| {
        prefix.into_with_c_str(|prefix| {
            let prefix_bytes = prefix.to_bytes();
            let name_length = validate_temp_prefix(prefix_bytes)?;
            let separator = !parent.to_bytes().ends_with(b"/");
            let total = parent
                .to_bytes()
                .len()
                .checked_add(usize::from(separator))
                .and_then(|length| length.checked_add(name_length))
                .ok_or(Errno::NAMETOOLONG)?;
            if total >= TEMP_DIR_PATH_MAX {
                return Err(Errno::NAMETOOLONG);
            }
            if total > capacity {
                return Err(Errno::RANGE);
            }

            let directory = openat(
                CWD,
                parent,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let mut basename = [0u8; TEMP_DIR_NAME_MAX + 1];
            let basename_length =
                create_temp_dir_at_bytes(&directory, prefix_bytes, &mut basename)?;

            // SAFETY: `pointer` has `capacity` writable bytes from the sealed
            // `Buffer` contract, and the exact output length was checked above.
            unsafe {
                ptr::copy_nonoverlapping(parent.as_ptr().cast(), pointer, parent.to_bytes().len());
                let mut offset = parent.to_bytes().len();
                if separator {
                    pointer.add(offset).write(b'/');
                    offset += 1;
                }
                ptr::copy_nonoverlapping(basename.as_ptr(), pointer.add(offset), basename_length);
            }
            Ok(total)
        })
    })?;
    // SAFETY: the closure copied exactly `initialized` initialized pathname
    // bytes into the `Buffer` storage.
    unsafe { Ok(output.assume_init(initialized)) }
}

/// Creates an owned private temporary directory below `parent`.
///
/// This is the allocation-enabled spelling of [`create_temp_dir_into`]. The
/// returned `CString` is the created full pathname and preserves arbitrary
/// non-UTF-8 bytes. The allocation is made only after the fixed direct-kernel
/// creation contract succeeds.
#[cfg(feature = "alloc")]
#[inline]
pub fn create_temp_dir<P: PathArg, Prefix: PathArg>(parent: P, prefix: Prefix) -> Result<CString> {
    let mut output = [0u8; TEMP_DIR_PATH_MAX];
    let length = create_temp_dir_into(parent, prefix, &mut output)?;
    let mut bytes = Vec::with_capacity(length + 1);
    bytes.extend_from_slice(&output[..length]);
    bytes.push(0);
    // SAFETY: the source is composed from NUL-free `PathArg` bytes and a
    // generated hexadecimal suffix; the only NUL is the final terminator.
    Ok(unsafe { CString::from_vec_with_nul_unchecked(bytes) })
}

/// Creates a private temporary directory below an already-open directory and
/// returns its generated basename in caller-owned storage.
///
/// This descriptor-relative form is the narrow no-allocation primitive behind
/// [`create_temp_dir_into`]. It is useful when the caller already has a stable
/// directory descriptor and does not need a process-relative full pathname.
#[inline]
pub fn create_temp_dir_at_into<Fd: AsFd, Prefix: PathArg, Buf: Buffer<u8>>(
    parent: Fd,
    prefix: Prefix,
    mut output: Buf,
) -> Result<Buf::Output> {
    let (pointer, capacity) = output.parts_mut();
    let initialized = prefix.into_with_c_str(|prefix| {
        let prefix = prefix.to_bytes();
        let name_length = validate_temp_prefix(prefix)?;
        if name_length > capacity {
            return Err(Errno::RANGE);
        }
        // SAFETY: `pointer` is writable for `capacity` bytes and the helper
        // writes exactly `name_length` initialized bytes after successful
        // atomic directory creation.
        let output = unsafe { core::slice::from_raw_parts_mut(pointer, capacity) };
        create_temp_dir_at_bytes(parent, prefix, output)
    })?;
    // SAFETY: the helper initialized exactly `initialized` bytes in the
    // caller's buffer.
    unsafe { Ok(output.assume_init(initialized)) }
}

/// Creates an owned private temporary directory below an open directory and
/// returns its generated basename.
#[cfg(feature = "alloc")]
#[inline]
pub fn create_temp_dir_at<Fd: AsFd, Prefix: PathArg>(parent: Fd, prefix: Prefix) -> Result<CString> {
    let mut output = [0u8; TEMP_DIR_NAME_MAX + 1];
    let length = create_temp_dir_at_into(parent, prefix, &mut output)?;
    let mut bytes = Vec::with_capacity(length + 1);
    bytes.extend_from_slice(&output[..length]);
    bytes.push(0);
    // SAFETY: the output consists of NUL-free prefix and hexadecimal suffix
    // bytes followed by one explicit terminator.
    Ok(unsafe { CString::from_vec_with_nul_unchecked(bytes) })
}

#[inline]
fn validate_temp_prefix(prefix: &[u8]) -> Result<usize> {
    if prefix.is_empty() || prefix.iter().any(|&byte| byte == b'/') {
        return Err(Errno::INVAL);
    }
    let name_length = prefix
        .len()
        .checked_add(TEMP_DIR_SUFFIX_LENGTH)
        .ok_or(Errno::NAMETOOLONG)?;
    if name_length > TEMP_DIR_NAME_MAX {
        return Err(Errno::NAMETOOLONG);
    }
    Ok(name_length)
}

fn create_temp_dir_at_bytes<Fd: AsFd>(
    parent: Fd,
    prefix: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let name_length = validate_temp_prefix(prefix)?;
    if output.len() < name_length {
        return Err(Errno::RANGE);
    }
    let parent = parent.as_fd();
    let mut candidate = [0u8; TEMP_DIR_NAME_MAX + 1];
    let mut entropy = [0u8; TEMP_DIR_RANDOM_BYTES];
    let hex = b"0123456789abcdef";

    let mut attempt = 0;
    while attempt < TEMP_DIR_MAX_ATTEMPTS {
        crate::rand::getentropy(&mut entropy)?;
        candidate[..prefix.len()].copy_from_slice(prefix);
        for (index, byte) in entropy.iter().enumerate() {
            candidate[prefix.len() + index * 2] = hex[(byte >> 4) as usize];
            candidate[prefix.len() + index * 2 + 1] = hex[(byte & 0x0f) as usize];
        }
        let candidate_cstr =
            unsafe { CStr::from_bytes_with_nul_unchecked(&candidate[..name_length + 1]) };
        match crabc_core::fs::mkdirat(parent.as_raw_fd(), candidate_cstr, TEMP_DIR_MODE.bits()) {
            Ok(()) => {
                output[..name_length].copy_from_slice(&candidate[..name_length]);
                return Ok(name_length);
            }
            Err(Errno::EXIST) => attempt += 1,
            Err(error) => return Err(error),
        }
    }
    Err(Errno::EXIST)
}

/// Creates a hard link between paths relative to their directory descriptors.
///
/// [`LinkAtFlags::SYMLINK_FOLLOW`] selects final-source-link resolution. This
/// safe boundary deliberately excludes `AT_EMPTY_PATH` and its descriptor
/// linking semantics.
#[inline]
pub fn linkat<P: PathArg, Q: PathArg, PFd: AsFd, QFd: AsFd>(
    old_dirfd: PFd,
    old_path: P,
    new_dirfd: QFd,
    new_path: Q,
    flags: LinkAtFlags,
) -> Result<()> {
    let flags = LinkAtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
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
pub fn link<P: PathArg, Q: PathArg>(old_path: P, new_path: Q) -> Result<()> {
    linkat(CWD, old_path, CWD, new_path, LinkAtFlags::empty())
}

/// Creates a symbolic link relative to `new_dirfd`.
///
/// The link target is stored as supplied and is not resolved at creation.
#[inline]
pub fn symlinkat<P: PathArg, Q: PathArg, Fd: AsFd>(
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

/// Creates a current-directory-relative symbolic link.
#[inline]
pub fn symlink<P: PathArg, Q: PathArg>(target: P, new_path: Q) -> Result<()> {
    symlinkat(target, CWD, new_path)
}

/// Renames a path or directory without special Linux rename flags.
#[inline]
pub fn renameat<P: PathArg, Q: PathArg, PFd: AsFd, QFd: AsFd>(
    old_dirfd: PFd,
    old_path: P,
    new_dirfd: QFd,
    new_path: Q,
) -> Result<()> {
    renameat_with(
        old_dirfd,
        old_path,
        new_dirfd,
        new_path,
        RenameFlags::empty(),
    )
}

/// Renames a path or directory using the admitted Linux `renameat2(2)` flags.
///
/// [`RenameFlags::NOREPLACE`] and [`RenameFlags::EXCHANGE`] are mutually
/// exclusive; their combination and unknown flag bits return [`Errno::INVAL`]
/// before path conversion or syscall entry. Whiteout creation remains outside
/// this filesystem- and privilege-dependent staged boundary.
#[inline]
pub fn renameat_with<P: PathArg, Q: PathArg, PFd: AsFd, QFd: AsFd>(
    old_dirfd: PFd,
    old_path: P,
    new_dirfd: QFd,
    new_path: Q,
    flags: RenameFlags,
) -> Result<()> {
    let flags = RenameFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    if flags.contains(RenameFlags::NOREPLACE) && flags.contains(RenameFlags::EXCHANGE) {
        return Err(Errno::INVAL);
    }

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
pub fn rename<P: PathArg, Q: PathArg>(old_path: P, new_path: Q) -> Result<()> {
    renameat(CWD, old_path, CWD, new_path)
}

/// Changes permissions for an open file or directory.
#[inline]
pub fn fchmod<Fd: AsFd>(fd: Fd, mode: Mode) -> Result<()> {
    crabc_core::fs::fchmod(fd.as_fd().as_raw_fd(), mode.bits())
}

/// Changes permissions for `path` relative to `dirfd`.
///
/// Linux cannot change a symbolic link's mode. Passing exactly
/// [`AtFlags::SYMLINK_NOFOLLOW`] returns [`Errno::OPNOTSUPP`] without a
/// syscall; all other flags are rejected before syscall entry.
#[inline]
#[doc(alias = "fchmodat")]
pub fn chmodat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    mode: Mode,
    flags: AtFlags,
) -> Result<()> {
    let flags = AtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    if flags == AtFlags::SYMLINK_NOFOLLOW {
        return Err(Errno::OPNOTSUPP);
    }
    if !flags.is_empty() {
        return Err(Errno::INVAL);
    }

    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| crabc_core::fs::fchmodat(dirfd.as_raw_fd(), path, mode.bits(), 0))
}

/// Changes permissions for a current-directory-relative path.
#[inline]
pub fn chmod<P: PathArg>(path: P, mode: Mode) -> Result<()> {
    chmodat(CWD, path, mode, AtFlags::empty())
}

/// Converts optional typed ownership IDs to Linux's `fchown*` words.
///
/// Linux reserves all ones as the no-change sentinel. `None` is the only way
/// to request that meaning: an all-ones typed ID is rejected instead of being
/// silently treated as absence.
#[inline]
fn ownership_words(owner: Option<Uid>, group: Option<Gid>) -> Result<(u32, u32)> {
    let owner = match owner {
        Some(owner) if owner.as_raw() == u32::MAX => return Err(Errno::INVAL),
        Some(owner) => owner.as_raw(),
        None => u32::MAX,
    };
    let group = match group {
        Some(group) if group.as_raw() == u32::MAX => return Err(Errno::INVAL),
        Some(group) => group.as_raw(),
        None => u32::MAX,
    };
    Ok((owner, group))
}

/// Changes ownership for an open file or directory.
#[inline]
pub fn fchown<Fd: AsFd>(fd: Fd, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
    let (owner, group) = ownership_words(owner, group)?;
    crabc_core::fs::fchown(fd.as_fd().as_raw_fd(), owner, group)
}

/// Changes ownership for `path` relative to `dirfd`.
///
/// [`ChownFlags::SYMLINK_NOFOLLOW`] selects the final symbolic link itself.
/// `AT_EMPTY_PATH` and all other cross-syscall flag meanings are excluded.
#[inline]
#[doc(alias = "fchownat")]
pub fn chownat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    owner: Option<Uid>,
    group: Option<Gid>,
    flags: ChownFlags,
) -> Result<()> {
    let (owner, group) = ownership_words(owner, group)?;
    let flags = ChownFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        crabc_core::fs::fchownat(dirfd.as_raw_fd(), path, owner, group, flags.bits())
    })
}

/// Changes ownership for a path, following a final symbolic link.
#[inline]
pub fn chown<P: PathArg>(path: P, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
    chownat(CWD, path, owner, group, ChownFlags::empty())
}

/// Changes ownership for a final symbolic link itself.
#[inline]
pub fn lchown<P: PathArg>(path: P, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
    chownat(CWD, path, owner, group, ChownFlags::SYMLINK_NOFOLLOW)
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

/// Reads a complete symbolic-link target relative to `dirfd` into owned
/// byte-path storage.
///
/// `readlinkat(2)` does not append a NUL byte and reports a successful length
/// equal to the supplied capacity for both an exactly fitting target and a
/// truncated one. This wrapper therefore retries with a larger buffer until
/// the returned length is strictly shorter than the capacity. The supplied
/// vector is reused where its capacity permits; the resulting [`CString`]
/// preserves arbitrary non-NUL target bytes without UTF-8 conversion.
#[cfg(feature = "alloc")]
#[inline]
pub fn readlinkat<P: PathArg, Fd: AsFd, B: Into<Vec<u8>>>(
    dirfd: Fd,
    path: P,
    reuse: B,
) -> Result<CString> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        let mut buffer = reuse.into();
        buffer.clear();
        buffer.reserve(SMALL_PATH_BUFFER_SIZE);

        loop {
            let capacity = buffer.capacity();
            let spare = buffer.spare_capacity_mut();
            // SAFETY: the vector spare capacity is writable for its exact
            // length and remains live for the duration of this direct syscall.
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

/// Reads a complete symbolic-link target relative to the process current
/// directory into owned byte-path storage.
///
/// The current working directory is process-global on Linux. Relative paths
/// therefore require callers to coordinate with concurrent CWD mutation; an
/// absolute path ignores the [`CWD`] directory token as usual.
#[cfg(feature = "alloc")]
#[inline]
pub fn readlink<P: PathArg, B: Into<Vec<u8>>>(path: P, reuse: B) -> Result<CString> {
    readlinkat(CWD, path, reuse)
}

/// The Linux pathname bound used by the native canonicalization operation.
///
/// Linux pathname arguments and the musl `realpath` implementation are both
/// bounded by `PATH_MAX` bytes including the terminating NUL. The native
/// operation therefore accepts and returns at most `PATH_MAX - 1` pathname
/// bytes, while preserving arbitrary non-NUL bytes in those bytes.
pub const CANONICAL_PATH_MAX: usize = 4096;

const CANONICAL_PENDING_CAPACITY: usize = CANONICAL_PATH_MAX * 2;
const CANONICAL_MAX_SYMLINKS: usize = 40;

/// Resolves a pathname to an absolute, byte-preserving physical pathname.
///
/// This is the allocation-free caller-buffered equivalent of [`canonicalize`].
/// The input is accepted through [`PathArg`], so it may contain non-UTF-8
/// bytes but may not contain an interior NUL. `.` and `..` are interpreted
/// lexically, while every existing component is checked against the kernel and
/// symbolic links are read relative to their containing directory. Linux's
/// direct `openat`, `readlinkat`, and `getcwd` seams are used; no libc
/// function, C ABI, or TLS `errno` is involved.
///
/// The initialized result is the canonical pathname without a trailing NUL.
/// A buffer too small for the result returns [`crate::Errno::RANGE`]. A
/// pathname or symlink expansion exceeding the Linux/musl `PATH_MAX` bound
/// returns [`crate::Errno::NAMETOOLONG`]. Symlink traversal is bounded at the
/// Linux/musl limit of forty links and returns [`crate::Errno::LOOP`] when the
/// limit is reached.
#[inline]
pub fn canonicalize_into<P: PathArg, Buf: Buffer<u8>>(
    path: P,
    mut output: Buf,
) -> Result<Buf::Output> {
    let (pointer, capacity) = output.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        canonicalize_bytes(path.to_bytes(), |resolved| {
            if resolved.len() > capacity {
                return Err(crate::Errno::RANGE);
            }
            // SAFETY: `pointer` and `capacity` come from the sealed `Buffer`
            // contract; `resolved` is an initialized pathname prefix owned by
            // this call and is copied before the callback returns.
            unsafe { ptr::copy_nonoverlapping(resolved.as_ptr(), pointer, resolved.len()) };
            Ok(resolved.len())
        })
    })?;
    // SAFETY: `canonicalize_bytes` copied exactly `initialized` initialized
    // bytes into the buffer supplied by `Buffer::parts_mut`.
    unsafe { Ok(output.assume_init(initialized)) }
}

/// Resolves a pathname to an owned, NUL-terminated physical pathname.
///
/// This alloc-enabled spelling is useful when the result must outlive the
/// call. It retains the bounded `PATH_MAX` contract and the direct-kernel
/// semantics of [`canonicalize_into`]. The returned [`CString`] contains no
/// interior NUL and preserves non-UTF-8 pathname bytes exactly.
#[cfg(feature = "alloc")]
#[inline]
pub fn canonicalize<P: PathArg>(path: P) -> Result<CString> {
    let path = canonical_path_bytes(path)?;
    canonicalize_bytes(&path, |resolved| {
        let mut bytes = Vec::with_capacity(resolved.len() + 1);
        bytes.extend_from_slice(resolved);
        bytes.push(0);
        // SAFETY: The source path was NUL-free and the only NUL appended here
        // is the final terminator required by `CString`.
        Ok(unsafe { CString::from_vec_with_nul_unchecked(bytes) })
    })
}

#[cfg(feature = "alloc")]
#[inline]
fn canonical_path_bytes<P: PathArg>(path: P) -> Result<Vec<u8>> {
    path.into_with_c_str(|path| Ok(path.to_bytes().to_vec()))
}

/// Runs `f` with a canonical pathname assembled in a fixed, no-alloc
/// workspace. Keeping this workspace bounded makes the same resolution
/// algorithm available to `--no-default-features` static probes and to the
/// owned alloc facade without introducing a hidden allocator dependency.
fn canonicalize_bytes<T, F>(path: &[u8], f: F) -> Result<T>
where
    F: FnOnce(&[u8]) -> Result<T>,
{
    if path.is_empty() {
        return Err(crate::Errno::NOENT);
    }
    if path.len() >= CANONICAL_PATH_MAX {
        return Err(crate::Errno::NAMETOOLONG);
    }

    let mut workspace = CanonicalWorkspace::new(path)?;
    workspace.resolve()?;
    f(workspace.resolved())
}

struct CanonicalWorkspace {
    pending: [u8; CANONICAL_PENDING_CAPACITY],
    pending_len: usize,
    pending_pos: usize,
    target: [u8; CANONICAL_PATH_MAX],
    resolved: [u8; CANONICAL_PATH_MAX],
    cwd: [MaybeUninit<u8>; CANONICAL_PATH_MAX],
    resolved_len: usize,
    absolute: bool,
    unresolved_up: usize,
    symlink_count: usize,
}

impl CanonicalWorkspace {
    fn new(path: &[u8]) -> Result<Self> {
        let mut pending = [0; CANONICAL_PENDING_CAPACITY];
        pending[..path.len()].copy_from_slice(path);
        Ok(Self {
            pending,
            pending_len: path.len(),
            pending_pos: 0,
            target: [0; CANONICAL_PATH_MAX],
            resolved: [0; CANONICAL_PATH_MAX],
            cwd: [MaybeUninit::uninit(); CANONICAL_PATH_MAX],
            resolved_len: 0,
            absolute: path[0] == b'/',
            unresolved_up: 0,
            symlink_count: 0,
        })
    }

    fn resolved(&self) -> &[u8] {
        &self.resolved[..self.resolved_len]
    }

    fn resolve(&mut self) -> Result<()> {
        let cwd_len = if self.absolute {
            0
        } else {
            // Capture the process CWD before opening the stable directory fd.
            // As with `process::getcwd`, callers must coordinate concurrent
            // CWD changes while performing pathname work.
            let (cwd, _) = crate::process::getcwd(&mut self.cwd)?;
            if cwd.is_empty() || cwd[cwd.len() - 1] != 0 {
                return Err(crate::Errno::IO);
            }
            cwd.len() - 1
        };

        let mut current = if self.absolute {
            self.open_root()?
        } else {
            self.open_current_directory()?
        };
        if self.absolute {
            self.resolved[0] = b'/';
            self.resolved_len = 1;
        }

        while let Some((start, end, has_remaining, trailing_slash)) = self.next_component() {
            let component = &self.pending[start..end];

            if component == b"." {
                if has_remaining || trailing_slash {
                    self.ensure_directory(&current)?;
                }
                continue;
            }

            if component == b".." {
                let parent = self.open_component(&current, b"..", true)?;
                current = parent;
                self.pop_component();
                continue;
            }

            let candidate = self.open_component(&current, component, false)?;
            let mut link_target = [MaybeUninit::<u8>::uninit(); CANONICAL_PATH_MAX];
            let link_length = self.readlink_component(&current, component, &mut link_target)?;

            if let Some(link_length) = link_length {
                if self.symlink_count == CANONICAL_MAX_SYMLINKS {
                    return Err(crate::Errno::LOOP);
                }
                self.symlink_count += 1;
                if link_length == 0 {
                    return Err(crate::Errno::NOENT);
                }
                // SAFETY: `readlinkat` initialized exactly this prefix and
                // Linux symlink targets cannot contain NUL bytes.
                let target = unsafe {
                    core::slice::from_raw_parts(link_target.as_ptr().cast::<u8>(), link_length)
                };
                self.target[..link_length].copy_from_slice(target);
                self.splice_target(link_length, end)?;
                if self.target[0] == b'/' {
                    current = self.open_root()?;
                    self.absolute = true;
                    self.unresolved_up = 0;
                    self.resolved_len = 1;
                    self.resolved[0] = b'/';
                }
                continue;
            }

            if !has_remaining && trailing_slash {
                self.ensure_directory(&candidate)?;
            }
            self.append_component_range(start, end)?;
            if has_remaining {
                self.ensure_directory(&candidate)?;
                current = candidate;
            }
        }

        if self.absolute {
            return Ok(());
        }

        // A relative result is anchored to the physical initial CWD after all
        // descriptor-relative `..` operations have been applied. The bytes
        // came from Linux's getcwd and are initialized through the Buffer
        // contract above.
        // SAFETY: `cwd_len` was returned by Linux and excludes its final NUL.
        let cwd = unsafe { core::slice::from_raw_parts(self.cwd.as_ptr().cast::<u8>(), cwd_len) };
        let mut base_len = cwd.len();
        for _ in 0..self.unresolved_up {
            while base_len > 1 && cwd[base_len - 1] != b'/' {
                base_len -= 1;
            }
            if base_len > 1 {
                base_len -= 1;
            }
        }
        let separator = self.resolved_len != 0 && base_len != 0 && cwd[base_len - 1] != b'/';
        let total = base_len
            .checked_add(usize::from(separator))
            .and_then(|length| length.checked_add(self.resolved_len))
            .ok_or(crate::Errno::NAMETOOLONG)?;
        if total >= CANONICAL_PATH_MAX {
            return Err(crate::Errno::NAMETOOLONG);
        }
        if self.resolved_len != 0 {
            // Move the relative suffix into its final position before copying
            // the absolute CWD prefix. The source and destination overlap.
            unsafe {
                ptr::copy(
                    self.resolved.as_ptr(),
                    self.resolved
                        .as_mut_ptr()
                        .add(base_len + usize::from(separator)),
                    self.resolved_len,
                );
                ptr::copy_nonoverlapping(cwd.as_ptr(), self.resolved.as_mut_ptr(), base_len);
            }
        } else {
            unsafe {
                ptr::copy_nonoverlapping(cwd.as_ptr(), self.resolved.as_mut_ptr(), base_len);
            }
        }
        if separator {
            self.resolved[base_len] = b'/';
        }
        self.resolved_len = total;
        Ok(())
    }

    fn next_component(&mut self) -> Option<(usize, usize, bool, bool)> {
        let mut start = self.pending_pos;
        while start < self.pending_len && self.pending[start] == b'/' {
            start += 1;
        }
        if start == self.pending_len {
            self.pending_pos = start;
            return None;
        }
        let mut end = start;
        while end < self.pending_len && self.pending[end] != b'/' {
            end += 1;
        }
        let mut after = end;
        while after < self.pending_len && self.pending[after] == b'/' {
            after += 1;
        }
        self.pending_pos = end;
        Some((
            start,
            end,
            after < self.pending_len,
            after == self.pending_len && end < after,
        ))
    }

    fn splice_target(&mut self, target_len: usize, component_end: usize) -> Result<()> {
        let suffix_len = self.pending_len - component_end;
        let total = target_len
            .checked_add(suffix_len)
            .ok_or(crate::Errno::NAMETOOLONG)?;
        if total >= CANONICAL_PENDING_CAPACITY {
            return Err(crate::Errno::NAMETOOLONG);
        }
        unsafe {
            ptr::copy(
                self.pending.as_ptr().add(component_end),
                self.pending.as_mut_ptr().add(target_len),
                suffix_len,
            );
            ptr::copy_nonoverlapping(self.target.as_ptr(), self.pending.as_mut_ptr(), target_len);
        }
        self.pending_len = total;
        self.pending_pos = 0;
        Ok(())
    }

    fn append_component_range(&mut self, start: usize, end: usize) -> Result<()> {
        let length = end - start;
        let separator = self.resolved_len != 0 && self.resolved[self.resolved_len - 1] != b'/';
        let total = self
            .resolved_len
            .checked_add(usize::from(separator))
            .and_then(|current| current.checked_add(length))
            .ok_or(crate::Errno::NAMETOOLONG)?;
        if total >= CANONICAL_PATH_MAX {
            return Err(crate::Errno::NAMETOOLONG);
        }
        if separator {
            self.resolved[self.resolved_len] = b'/';
            self.resolved_len += 1;
        }
        unsafe {
            ptr::copy_nonoverlapping(
                self.pending.as_ptr().add(start),
                self.resolved.as_mut_ptr().add(self.resolved_len),
                length,
            );
        }
        self.resolved_len = total;
        Ok(())
    }

    fn pop_component(&mut self) {
        if self.resolved_len == 0 {
            self.unresolved_up = self.unresolved_up.saturating_add(1);
        } else if self.absolute {
            while self.resolved_len > 1 && self.resolved[self.resolved_len - 1] != b'/' {
                self.resolved_len -= 1;
            }
            if self.resolved_len > 1 {
                self.resolved_len -= 1;
            }
        } else {
            while self.resolved_len > 0 && self.resolved[self.resolved_len - 1] != b'/' {
                self.resolved_len -= 1;
            }
            if self.resolved_len > 0 {
                self.resolved_len -= 1;
            }
        }
    }

    fn open_root(&self) -> Result<OwnedFd> {
        self.open_path(b"/")
    }

    fn open_current_directory(&self) -> Result<OwnedFd> {
        self.open_path(b".")
    }

    fn open_path(&self, path: &[u8]) -> Result<OwnedFd> {
        canonical_path_cstr(path, |path| {
            openat(
                CWD,
                path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })
    }

    fn open_component<Fd: AsFd>(
        &self,
        directory: Fd,
        component: &[u8],
        directory_only: bool,
    ) -> Result<OwnedFd> {
        canonical_path_cstr(component, |component| {
            let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let flags = if directory_only {
                flags | OFlags::DIRECTORY
            } else {
                flags
            };
            openat(directory, component, flags, Mode::empty())
        })
    }

    fn ensure_directory<Fd: AsFd>(&self, descriptor: Fd) -> Result<()> {
        canonical_path_cstr(b".", |path| {
            let _ = openat(
                descriptor,
                path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(())
        })
    }

    fn readlink_component(
        &self,
        directory: &OwnedFd,
        component: &[u8],
        target: &mut [MaybeUninit<u8>; CANONICAL_PATH_MAX],
    ) -> Result<Option<usize>> {
        canonical_path_cstr(component, |component| {
            // SAFETY: `target` is writable for its full fixed length and the
            // component C string remains alive for the direct syscall.
            match unsafe {
                crabc_core::fs::readlinkat_raw(
                    directory.as_raw_fd(),
                    component,
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            } {
                Ok(length) => {
                    if length >= target.len() {
                        Err(crate::Errno::NAMETOOLONG)
                    } else {
                        Ok(Some(length))
                    }
                }
                Err(crate::Errno::INVAL) => Ok(None),
                Err(error) => Err(error),
            }
        })
    }
}

fn canonical_path_cstr<T, F>(path: &[u8], f: F) -> Result<T>
where
    F: FnOnce(&CStr) -> Result<T>,
{
    if path.len() >= CANONICAL_PATH_MAX {
        return Err(crate::Errno::NAMETOOLONG);
    }
    let mut bytes = [0u8; CANONICAL_PATH_MAX];
    bytes[..path.len()].copy_from_slice(path);
    bytes[path.len()] = 0;
    // SAFETY: `path` is NUL-free by construction: all callers pass either a
    // component from a validated `PathArg` or the fixed `.`/`/` spellings.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(&bytes[..path.len() + 1]) };
    f(path)
}

/// Reads an extended attribute into caller-provided storage.
///
/// A zero-length output buffer is the Linux size-query form. A successful
/// nonzero-buffer read returns only the initialized prefix; `ERANGE` means the
/// supplied buffer was too short and no owned allocation or retry is hidden.
#[inline]
pub fn getxattr<P: PathArg, Name: PathArg, Buf: Buffer<u8>>(
    path: P,
    name: Name,
    mut value: Buf,
) -> Result<Buf::Output> {
    let (pointer, length) = value.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: `Buffer` supplies writable output storage and both
            // arguments are NUL-terminated for the direct syscall.
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
    // SAFETY: Linux initialized exactly the reported output prefix.
    unsafe { Ok(value.assume_init(initialized)) }
}

/// Reads an extended attribute without following a final symbolic link.
#[inline]
pub fn lgetxattr<P: PathArg, Name: PathArg, Buf: Buffer<u8>>(
    path: P,
    name: Name,
    mut value: Buf,
) -> Result<Buf::Output> {
    let (pointer, length) = value.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: `Buffer` supplies writable output storage and both
            // arguments are NUL-terminated for the direct syscall.
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
    // SAFETY: Linux initialized exactly the reported output prefix.
    unsafe { Ok(value.assume_init(initialized)) }
}

/// Reads a descriptor extended attribute into caller-provided storage.
#[inline]
pub fn fgetxattr<Fd: AsFd, Name: PathArg, Buf: Buffer<u8>>(
    fd: Fd,
    name: Name,
    mut value: Buf,
) -> Result<Buf::Output> {
    let fd = fd.as_fd();
    let (pointer, length) = value.parts_mut();
    let initialized = name.into_with_c_str(|name| {
        // SAFETY: `Buffer` supplies writable output storage, `name` is
        // NUL-terminated, and the descriptor borrow remains live.
        unsafe {
            crabc_core::fs::fgetxattr_raw(fd.as_raw_fd(), name.as_ptr().cast(), pointer, length)
        }
    })?;
    // SAFETY: Linux initialized exactly the reported output prefix.
    unsafe { Ok(value.assume_init(initialized)) }
}

/// Sets an extended attribute on a path.
#[inline]
pub fn setxattr<P: PathArg, Name: PathArg>(
    path: P,
    name: Name,
    value: &[u8],
    flags: XattrFlags,
) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: Both names are NUL-terminated and `value` remains
            // readable for its exact slice length through this syscall.
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
pub fn lsetxattr<P: PathArg, Name: PathArg>(
    path: P,
    name: Name,
    value: &[u8],
    flags: XattrFlags,
) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: Both names are NUL-terminated and `value` remains
            // readable for its exact slice length through this syscall.
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
pub fn fsetxattr<Fd: AsFd, Name: PathArg>(
    fd: Fd,
    name: Name,
    value: &[u8],
    flags: XattrFlags,
) -> Result<()> {
    let fd = fd.as_fd();
    name.into_with_c_str(|name| {
        // SAFETY: `name` is NUL-terminated, `value` remains readable for its
        // exact slice length, and the descriptor borrow remains live.
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

/// Lists extended-attribute names into caller-provided storage.
///
/// Returned names are Linux's NUL-separated byte sequence, without a lossy
/// UTF-8 conversion or a hidden allocation.
#[inline]
pub fn listxattr<P: PathArg, Buf: Buffer<u8>>(path: P, mut list: Buf) -> Result<Buf::Output> {
    let (pointer, length) = list.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        // SAFETY: `Buffer` supplies writable output storage and `path` is
        // NUL-terminated for this direct syscall.
        unsafe { crabc_core::fs::listxattr_raw(path.as_ptr().cast(), pointer, length) }
    })?;
    // SAFETY: Linux initialized exactly the reported output prefix.
    unsafe { Ok(list.assume_init(initialized)) }
}

/// Lists extended-attribute names without following a final symbolic link.
#[inline]
pub fn llistxattr<P: PathArg, Buf: Buffer<u8>>(path: P, mut list: Buf) -> Result<Buf::Output> {
    let (pointer, length) = list.parts_mut();
    let initialized = path.into_with_c_str(|path| {
        // SAFETY: `Buffer` supplies writable output storage and `path` is
        // NUL-terminated for this direct syscall.
        unsafe { crabc_core::fs::llistxattr_raw(path.as_ptr().cast(), pointer, length) }
    })?;
    // SAFETY: Linux initialized exactly the reported output prefix.
    unsafe { Ok(list.assume_init(initialized)) }
}

/// Lists descriptor extended-attribute names into caller-provided storage.
#[inline]
pub fn flistxattr<Fd: AsFd, Buf: Buffer<u8>>(fd: Fd, mut list: Buf) -> Result<Buf::Output> {
    let fd = fd.as_fd();
    let (pointer, length) = list.parts_mut();
    // SAFETY: `Buffer` supplies writable output storage and the descriptor
    // borrow remains live for the direct syscall.
    let initialized = unsafe { crabc_core::fs::flistxattr_raw(fd.as_raw_fd(), pointer, length) }?;
    // SAFETY: Linux initialized exactly the reported output prefix.
    unsafe { Ok(list.assume_init(initialized)) }
}

/// Removes an extended attribute from a path.
#[inline]
pub fn removexattr<P: PathArg, Name: PathArg>(path: P, name: Name) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: Both names are NUL-terminated for the direct syscall.
            unsafe { crabc_core::fs::removexattr_raw(path.as_ptr().cast(), name.as_ptr().cast()) }
        })
    })
}

/// Removes an extended attribute without following a final symbolic link.
#[inline]
pub fn lremovexattr<P: PathArg, Name: PathArg>(path: P, name: Name) -> Result<()> {
    path.into_with_c_str(|path| {
        name.into_with_c_str(|name| {
            // SAFETY: Both names are NUL-terminated for the direct syscall.
            unsafe { crabc_core::fs::lremovexattr_raw(path.as_ptr().cast(), name.as_ptr().cast()) }
        })
    })
}

/// Removes an extended attribute from an open descriptor.
#[inline]
pub fn fremovexattr<Fd: AsFd, Name: PathArg>(fd: Fd, name: Name) -> Result<()> {
    let fd = fd.as_fd();
    name.into_with_c_str(|name| {
        // SAFETY: `name` is NUL-terminated and the descriptor borrow remains
        // live for this direct syscall.
        unsafe { crabc_core::fs::fremovexattr_raw(fd.as_raw_fd(), name.as_ptr().cast()) }
    })
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
