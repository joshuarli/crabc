//! Deliberately narrow Linux/x86-64 filesystem observations and memory-file operations.
//!
//! This module admits descriptor-based `fstat(2)`, a deliberately narrow
//! query-only `statat(2)` path-metadata boundary, caller-buffer-only
//! `readlinkat(2)` target reads, `access(2)` and `faccessat2(2)` permission
//! checks, direct `fcntl(F_GETFL/F_SETFL)` status-flag observation and
//! mutation, file-access advice, file readahead, descriptor-based file-length
//! and timestamp mutation, and closed pathname timestamp mutation through a
//! fixed-stack path boundary, fixed-mode descriptor-range allocation,
//! descriptor-to-descriptor transfer and descriptor-range copying,
//! file-position and synchronization operations,
//! system-wide and descriptor-associated filesystem synchronization, and direct anonymous
//! memory-file creation with bounded
//! sealing.
//! The
//! x86-64 kernel record is not interchangeable with the AArch64 record:
//! `st_nlink` and the timestamp nanoseconds are 64-bit here, and the record
//! has a distinct 144-byte layout. The private metadata path slice admits only
//! `CWD` and `AT_SYMLINK_NOFOLLOW`, while the direct permission-observation
//! slice has its own closed access mode and flag types. The caller-buffer
//! readlink target boundary remains private. `AT_EMPTY_PATH`, a general path
//! module, `statx`, filesystem statistics, allocation-backed path helpers,
//! and pathname mutation other than the closed timestamp family remain outside
//! this staged target boundary until they have their own x86-64 evidence.

use bitflags::bitflags;
use crate::buffer::Buffer;
use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::num::NonZeroU64;

use crate::{AsFd, BorrowedFd, Errno, OwnedFd, Result};

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
    /// Known Linux/x86-64 `O_*` values for [`fcntl_getfl`] and
    /// [`fcntl_setfl`].
    ///
    /// This type is deliberately admitted only for direct open-file-
    /// description status-flag observation and mutation. It is not an
    /// admission of x86-64 `open(2)`, `openat(2)`, pathname resolution, or a
    /// general C `fcntl` facade. Unknown bits are retained so callers can
    /// faithfully observe and forward future kernel-defined status bits.
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

/// The largest byte pathname accepted by the fixed-stack [`PathArg`] boundary.
///
/// One byte is reserved for the terminating NUL. This fixed-stack x86-64
/// facade boundary deliberately does not allocate for longer paths; callers receive
/// [`Errno::NAMETOOLONG`] before a syscall instead.
pub const SMALL_PATH_BUFFER_SIZE: usize = 256;

/// A pathname or memory-file name input accepted by [`access`], [`accessat`],
/// [`statat`], [`stat`], [`readlinkat_raw`], the timestamp-mutation family,
/// and [`memfd_create`].
///
/// Implementations borrow an existing C string or form one in a fixed stack
/// buffer. The callback is invoked while that C string remains live, so the
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
/// accepted only as the directory argument to [`accessat`], [`statat`],
/// [`readlinkat_raw`], and [`utimensat`], and can never become an owned
/// descriptor.
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
    /// [`AtFlags`], whose closed vocabulary belongs to the private `statat`
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
    /// This preserves the native process::umask vocabulary without admitting
    /// x86-64 pathname creation APIs. The bitset intentionally retains future
    /// Linux mode bits, matching the AArch64 facade contract.
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
