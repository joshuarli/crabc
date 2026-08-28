//! Direct Linux/AArch64 filesystem operations.
//!
//! Filesystem operations use the shared stateless Linux/AArch64 syscall seams.
//! They exercise path, descriptor, flag, mode, ownership, and typed error
//! contracts without crossing into libc's process-global runtime state.

use bitflags::bitflags;
use core::ffi::CStr;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::num::NonZeroU64;
use core::ptr;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::buffer::Buffer;
use crate::{
    path::Arg,
    process::{Gid, Uid},
    AsFd, BorrowedFd, OwnedFd, Result,
};

pub use crate::{RawDir, RawDirEntry};

bitflags! {
    /// Permission checks accepted by [`access`].
    ///
    /// This closed set mirrors POSIX `R_OK`, `W_OK`, `X_OK`, and `F_OK`.
    /// Unknown bits are rejected by [`Access::from_bits`] and are never
    /// forwarded to the kernel.
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
        /// its current end (Linux `FALLOC_FL_ALLOCATE_RANGE`, value zero).
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

/// The six POSIX filesystem access-pattern policies accepted by Linux
/// `fadvise64`.
///
/// This filesystem advice type is intentionally distinct from [`crate::mm::Advice`],
/// whose values describe virtual-memory page policy rather than file access.
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
    /// Stable Linux `MFD_*` creation flags for [`memfd_create`].
    ///
    /// This is deliberately a closed set: unknown or newer kernel bits are
    /// rejected by [`MemfdFlags::from_bits`] instead of being silently
    /// forwarded. Huge-page sizing bits and Linux 6.3 exec-policy flags are
    /// outside this bounded facade slice.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MemfdFlags: u32 {
        /// Set `FD_CLOEXEC` on the returned descriptor.
        const CLOEXEC = 0x0001;
        /// Permit `F_ADD_SEALS` operations on the returned file.
        const ALLOW_SEALING = 0x0002;
        /// Use hugetlb-backed storage with the kernel's default huge-page
        /// size. Allocation may fail when no suitable huge pages are reserved.
        const HUGETLB = 0x0004;
    }
}

bitflags! {
    /// Linux `F_SEAL_*` flags returned by [`fcntl_get_seals`].
    ///
    /// Unknown bits are retained so observations from a newer Linux kernel are
    /// not silently discarded at the native Rust boundary.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SealFlags: u32 {
        /// Prevent adding or removing seals.
        const SEAL = 0x0001;
        /// Prevent shrinking the inode.
        const SHRINK = 0x0002;
        /// Prevent growing the inode.
        const GROW = 0x0004;
        /// Prevent writes to the inode.
        const WRITE = 0x0008;
        /// Prevent future writable mappings (Linux 5.1+).
        const FUTURE_WRITE = 0x0010;
        /// Prevent executable changes (Linux 6.3+).
        const EXEC = 0x0020;
        /// Preserve future Linux-defined seal bits.
        const _ = !0;
    }
}

/// Creates an anonymous Linux memory file and returns its unique owner.
///
/// `name` follows the existing [`Arg`] boundary: it is a borrowed or owned
/// byte-oriented NUL-terminated string, rejects interior NUL bytes, and does
/// not require UTF-8. Linux limits the name to 249 bytes excluding the NUL;
/// the kernel reports an overlong name as `EINVAL` (or the no-alloc `Arg`
/// boundary reports its documented bounded-name error before the syscall).
#[inline]
pub fn memfd_create<P: Arg>(name: P, flags: MemfdFlags) -> Result<OwnedFd> {
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
        unlinkat(&self.parent, name, AtFlags::empty())
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
pub fn create_temp_file<P: Arg, Prefix: Arg>(parent: P, prefix: Prefix) -> Result<NamedTempFile> {
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
pub fn create_temp_file_at<Fd: AsFd, Prefix: Arg>(
    parent: Fd,
    prefix: Prefix,
) -> Result<NamedTempFile> {
    let parent = parent.as_fd();
    if parent.as_raw_fd() < 0 {
        return Err(crate::Errno::BADF);
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
        let _ = crate::rand::getentropy(&mut entropy)?;
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
            Err(crate::Errno::EXIST) => attempt += 1,
            Err(error) => return Err(error),
        }
    }
    Err(crate::Errno::EXIST)
}

#[inline]
fn validate_temp_file_prefix(prefix: &[u8]) -> Result<usize> {
    if prefix.is_empty() || prefix.iter().any(|&byte| byte == b'/') {
        return Err(crate::Errno::INVAL);
    }
    let name_len = prefix
        .len()
        .checked_add(TEMP_FILE_SUFFIX_LENGTH)
        .ok_or(crate::Errno::NAMETOOLONG)?;
    if name_len > TEMP_FILE_NAME_MAX {
        return Err(crate::Errno::NAMETOOLONG);
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
/// [`crate::Errno::OPNOTSUPP`] (Linux `EOPNOTSUPP`) from [`Self::open`] or
/// [`Self::open_at`]. Callers that need a pathname must choose and audit a
/// separate named-file contract.
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
    pub fn open<P: Arg>(directory: P, mode: Mode) -> Result<Self> {
        Self::open_at(CWD, directory, mode)
    }

    /// Opens an anonymous temporary file in `directory` relative to `dirfd`.
    ///
    /// The directory descriptor remains the caller's responsibility; only the
    /// newly created temporary-file descriptor is moved into `TempFile`.
    /// `directory` must name a directory on a filesystem supporting Linux
    /// `O_TMPFILE`. No named-file fallback is attempted on `EOPNOTSUPP`.
    #[inline]
    pub fn open_at<Fd: AsFd, P: Arg>(dirfd: Fd, directory: P, mode: Mode) -> Result<Self> {
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
    /// Path arguments remain byte-oriented through [`Arg`]; no UTF-8 or
    /// process-global C `DIR` state is involved.
    #[inline]
    pub fn open<P: Arg>(path: P, buffer: &'buffer mut [MaybeUninit<u8>]) -> Result<Self> {
        Self::openat(CWD, path, buffer)
    }

    /// Opens `path` relative to a borrowed directory descriptor as a
    /// close-on-exec directory stream.
    #[inline]
    pub fn openat<P: Arg, Fd: AsFd>(
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
        // SAFETY: `Dir` owns the descriptor through its internal `OwnedFd`,
        // so it stays open for the returned standard-library borrow.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(Dir::as_fd(self).as_raw_fd()) }
    }
}

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

/// Linux `dev_t` used by [`mknodat`].
///
/// The AArch64 kernel ABI carries this value in one 64-bit syscall register.
/// FIFO creation always uses [`FIFO_DEVICE`] because FIFOs do not carry a
/// device number; character and block nodes are subject to the kernel's
/// privilege and device-number checks.
pub type Dev = u64;

/// The device number required by Linux for a FIFO node.
pub const FIFO_DEVICE: Dev = 0;

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

bitflags! {
    /// Flags accepted by [`chownat`].
    ///
    /// This is deliberately separate from [`AtFlags`]. Linux reuses the
    /// `*at` flag word across unrelated operations, while ownership changes
    /// only accept `AT_SYMLINK_NOFOLLOW` in this bounded facade. In
    /// particular, access, unlink, link, statx, and timestamp flags cannot
    /// accidentally cross the ownership boundary. Linux's
    /// `AT_EMPTY_PATH` form is left outside this path-based slice.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct ChownFlags: u32 {
        /// Change the symbolic link itself rather than its target.
        const SYMLINK_NOFOLLOW = 0x100;
    }
}

bitflags! {
    /// Linux mount flags reported by [`StatFs`] and [`StatVfs`].
    ///
    /// Unknown bits are retained so callers can inspect flags introduced by
    /// newer kernels without losing information. These are observations, not
    /// flags accepted by a mount-changing operation.
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

/// Linux/AArch64 `struct statx` metadata returned by [`statx`].
///
/// The representation follows the pinned Rustix layout. Optional observations
/// are valid only when their corresponding bit is present in [`Self::stx_mask`];
/// callers must not infer support merely from the requested mask.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
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
    /// facade. `Statx::stx_mask` remains authoritative when a kernel omits a
    /// requested field or supplies only a subset of the request.
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
    /// Reserved mask bit rejected by Rustix before entering the kernel.
    ///
    /// It is exposed as a raw value only so callers testing kernel-compatibility
    /// behavior can construct a retained bitflags value; it is not a valid
    /// member of this closed flag set.
    pub const RESERVED_MASK: u32 = 0x8000_0000;
}

bitflags! {
    /// `STATX_ATTR_*` bits reported in [`Statx::stx_attributes`].
    ///
    /// This is a closed set matching the pinned Rustix contract. Unknown
    /// kernel attribute bits are retained in the raw statx wire value only by
    /// the kernel; this facade does not invent names for them.
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
const _: [(); 16] = [(); core::mem::size_of::<StatxTimestamp>()];

/// Linux/AArch64 `struct statfs` filesystem statistics.
///
/// This is the kernel representation returned by [`statfs`] and [`fstatfs`],
/// not a public C `struct statfs` alias. The spare words are retained privately
/// solely to keep the output buffer's ABI layout exact; callers receive the
/// named filesystem observations below.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
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
    /// Fragment size, or zero when the filesystem does not report one.
    pub f_frsize: i64,
    /// Linux mount flags as returned by the kernel.
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
/// Linux has no separate `statvfs` syscall. [`statvfs`] and [`fstatvfs`]
/// perform `statfs`/`fstatfs` and apply musl's Linux field mapping: a zero
/// fragment size falls back to the fundamental block size, available file nodes
/// equal the reported free file nodes, and `f_fsid` is the first signed Linux
/// filesystem-id word widened to `u64`.
#[derive(Debug, Copy, Clone)]
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
    /// Available file nodes. Linux supplies no distinct value; this is `f_ffree`.
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
            f_frsize: if statfs.f_frsize != 0 {
                statfs.f_frsize as u64
            } else {
                f_bsize
            },
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

/// A legacy Linux `timeval` value expressed in whole seconds and
/// microseconds.
///
/// This is a native Rust value used by [`futimes`]; it is converted to the
/// nanosecond [`Timespec`] representation before the direct syscall. The
/// microsecond field must be in `0..1_000_000`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timeval {
    /// Whole seconds.
    pub tv_sec: Secs,
    /// Microseconds within the second.
    pub tv_usec: i64,
}

/// A legacy Linux `utime` timestamp pair expressed in whole seconds.
///
/// This is a native Rust value used by [`utime`]. It is converted to the
/// nanosecond [`Timespec`] representation before the direct syscall; both
/// resulting nanosecond fields are always zero.
#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Utimbuf {
    /// Last-access timestamp in whole seconds.
    pub actime: Secs,
    /// Last-modification timestamp in whole seconds.
    pub modtime: Secs,
}

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

/// Operations on an exclusive record lock beginning at a descriptor's current
/// file offset.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CurrentLockOperation {
    /// Release the selected range without waiting.
    Unlock,
    /// Acquire an exclusive lock, waiting until it is available.
    LockExclusive,
    /// Acquire an exclusive lock without waiting.
    TryExclusive,
    /// Observe whether an exclusive lock would conflict.
    TestExclusive,
}

/// A checked signed range relative to a descriptor's current file offset.
///
/// `ToEnd` uses Linux's zero-length `struct flock` convention. The non-zero
/// forms avoid an ambiguous zero-byte lock and preserve the direction of a
/// POSIX `lockf` request without transporting C integer command constants.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CurrentLockRange {
    /// Lock from the current offset through the dynamically changing EOF.
    ToEnd,
    /// Lock `length` bytes beginning at the current offset.
    Forward(NonZeroU64),
    /// Lock `length` bytes ending at the current offset.
    Backward(NonZeroU64),
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

/// Creates or truncates `path` with C `creat` semantics.
///
/// This is the deliberately narrow equivalent of `creat(path, mode)`:
/// it opens relative to the process current directory with write-only
/// access, creates the file when absent, and truncates it when present. The
/// supplied [`Mode`] is used only for a newly created file and Linux applies
/// the process umask. No additional open policy, including `O_CLOEXEC`, is
/// implied; use [`open`] when other flags or access modes are needed.
#[inline]
#[doc(alias = "creat")]
pub fn create<P: Arg>(path: P, mode: Mode) -> Result<OwnedFd> {
    openat(
        CWD,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
        mode,
    )
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

/// Flushes pending filesystem metadata and cached file data for all
/// filesystems.
///
/// This operation is system-wide rather than descriptor- or mount-scoped: it
/// includes dirty data reachable through other descriptors and filesystems in
/// the calling system. Linux waits for writeback I/O completion, whereas POSIX
/// permits `sync()` to return after scheduling writes. Completion here means
/// kernel/filesystem writeback completion, not a guarantee that a device's
/// volatile cache has reached nonvolatile media. Linux specifies `sync()` as
/// always successful, so this Rustix-shaped operation returns `()` and does
/// not expose libc or TLS `errno`.
#[inline]
pub fn sync() {
    crabc_core::fs::sync();
}

/// Declares an expected access pattern for a file range through Linux's
/// native `fadvise64` syscall.
///
/// `len == None` is passed as a zero length, which Linux interprets as
/// extending the advice to the end of the file. `Some(length)` is guaranteed
/// non-zero by [`NonZeroU64`]. On AArch64 Linux, `offset` and `length` are
/// signed `loff_t` syscall arguments; values above `i64::MAX` return
/// [`Errno::INVAL`] before the syscall. This is a typed Rust error, not a C
/// `posix_fadvise` status conversion.
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

/// Initiates Linux readahead for a byte range of an open file.
///
/// `offset` and `length` are unsigned byte quantities at this safe boundary:
/// negative offsets cannot be expressed, while values above Linux's signed
/// `loff_t` range are rejected with [`Errno::INVAL`] instead of being cast or
/// truncated. The half-open range `[offset, offset + length)` must also end
/// within that signed range; checked arithmetic rejects a wrapping or
/// unrepresentable end before the direct syscall. A zero length is allowed
/// and is forwarded unchanged; its advisory effect is whatever Linux defines
/// for a zero count. Successful readahead leaves the descriptor's current
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

/// Transfers up to `count` bytes from a borrowed input descriptor to a
/// borrowed output descriptor through Linux `sendfile`.
///
/// With `offset == Some`, Linux starts at the supplied non-negative input
/// offset, leaves the input descriptor's shared position unchanged, and
/// writes the resulting position back through the same mutable reference.
/// With `offset == None`, Linux starts at and advances the input descriptor's
/// shared position. The output descriptor's shared position advances in both
/// forms. A short transfer is returned as its actual byte count, and no
/// descriptor ownership changes hands.
///
/// The optional offset is a Rust in/out borrow, not a nullable C `off_t *`:
/// values above Linux's signed `off_t` range are rejected with [`Errno::INVAL`]
/// before the syscall, and the reference remains valid for the call.
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
        return Err(crate::Errno::INVAL);
    }

    crabc_core::io::sendfile(
        out_fd.as_fd().as_raw_fd(),
        in_fd.as_fd().as_raw_fd(),
        offset,
        count,
    )
}

/// Copies up to `len` bytes from a borrowed input descriptor to a borrowed
/// output descriptor through Linux `copy_file_range`.
///
/// A supplied `off_in` or `off_out` is an explicit in/out byte position. The
/// corresponding descriptor position remains unchanged, and the supplied
/// value advances by the number of bytes copied. With `None`, Linux uses and
/// advances that descriptor's shared position. A short copy is returned as
/// its byte count, including zero at end of input.
///
/// Both explicit offsets and their requested ranges must fit signed Linux
/// `loff_t`; invalid values return [`Errno::INVAL`] before the syscall. The
/// offsets are staged in initialized local values: a successful full or short
/// copy commits Linux's resulting values to the caller's references, while an
/// error leaves both caller-provided offsets unchanged. No descriptor
/// ownership changes hands, and the bounded API always passes zero syscall
/// flags.
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
        return Err(crate::Errno::INVAL);
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

/// Flushes all pending filesystem data associated with the descriptor's
/// mounted filesystem.
///
/// The descriptor is borrowed only for the direct Linux/AArch64 `syncfs`
/// syscall; no libc wrapper, process-global state, or TLS `errno` is used.
#[inline]
pub fn syncfs<Fd: AsFd>(fd: Fd) -> Result<()> {
    crabc_core::fs::syncfs(fd.as_fd().as_raw_fd())
}

/// Sets the length of a pathname-selected file.
///
/// The length uses Rustix's unsigned byte-count API. Values above Linux's
/// signed `loff_t` range return [`crate::Errno::INVAL`] before the path is
/// converted or the direct syscall is issued, so an invalid request cannot
/// mutate the named file.
#[inline]
pub fn truncate<P: Arg>(path: P, length: u64) -> Result<()> {
    if length > i64::MAX as u64 {
        return Err(crate::Errno::INVAL);
    }
    path.into_with_c_str(|path| crabc_core::fs::truncate(path, length as i64))
}

/// Sets the length of an open file descriptor.
///
/// The length uses Rustix's unsigned byte-count API. Values above Linux's
/// signed `loff_t` range return [`crate::Errno::INVAL`] before the descriptor
/// is borrowed or the direct syscall is issued.
#[inline]
pub fn ftruncate<Fd: AsFd>(fd: Fd, length: u64) -> Result<()> {
    if length > i64::MAX as u64 {
        return Err(crate::Errno::INVAL);
    }
    crabc_core::fs::ftruncate(fd.as_fd().as_raw_fd(), length as i64)
}

/// Allocates, zeros, or punches a range in an open file.
///
/// The descriptor is borrowed for the direct Linux syscall and remains owned
/// by its caller. `offset` and `length` are non-negative byte counts. Both
/// must fit Linux's signed `loff_t`, and their sum must not overflow that
/// range; these invalid ranges return [`Errno::INVAL`] before a syscall.
/// `PUNCH_HOLE` requires `KEEP_SIZE`, and unknown or unsupported mode bits are
/// rejected before a syscall. The operation never changes the descriptor's
/// current file position. `ALLOCATE` extends the file when necessary;
/// `KEEP_SIZE` suppresses that extension.
#[inline]
pub fn fallocate<Fd: AsFd>(fd: Fd, flags: FallocateFlags, offset: u64, length: u64) -> Result<()> {
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
        return Err(crate::Errno::INVAL);
    }

    crabc_core::fs::fallocate(
        fd.as_fd().as_raw_fd(),
        flags.bits(),
        offset as i64,
        length as i64,
    )
}

/// Allocates a file range using the POSIX mode-zero operation.
///
/// This is the native Rust spelling of `posix_fallocate`: the descriptor is
/// borrowed, the operation never changes its current position, and the
/// non-negative byte range must fit Linux's signed `loff_t` representation.
/// Linux errors are returned as [`Errno`] values rather than through the C
/// function's direct integer error convention. The operation has no flag
/// argument; use [`fallocate`] when a Linux mode is intentional.
#[inline]
pub fn posix_fallocate<Fd: AsFd>(fd: Fd, offset: u64, length: u64) -> Result<()> {
    fallocate(fd, FallocateFlags::empty(), offset, length)
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
            crabc_core::fs::fgetxattr_raw(fd.as_raw_fd(), name.as_ptr().cast(), pointer, length)
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

/// Reads the open-file-description status flags through `fcntl(F_GETFL)`.
///
/// The returned [`OFlags`] includes the access mode and status flags reported
/// by Linux. Unknown kernel bits are retained, matching Rustix's Linux API.
/// These are shared by duplicate descriptors; per-descriptor close-on-exec
/// state remains the separate [`crate::io::fcntl_getfd`] contract.
#[inline]
#[doc(alias = "F_GETFL")]
pub fn fcntl_getfl<Fd: AsFd>(fd: Fd) -> Result<OFlags> {
    crabc_core::io::fcntl_getfl(fd.as_fd().as_raw_fd()).map(OFlags::from_bits_retain)
}

/// Replaces the open-file-description status flags through `fcntl(F_SETFL)`.
///
/// Linux applies only the status bits supported for the open file; immutable
/// creation and descriptor flags are not promised to change. The descriptor
/// is borrowed and the operation affects all descriptors referring to the
/// same open file description.
#[inline]
#[doc(alias = "F_SETFL")]
pub fn fcntl_setfl<Fd: AsFd>(fd: Fd, flags: OFlags) -> Result<()> {
    crabc_core::io::fcntl_setfl(fd.as_fd().as_raw_fd(), flags.bits())
}

/// Queries filesystem statistics for an open file or directory.
///
/// The returned value is a typed Linux/AArch64 kernel view. It does not borrow
/// libc state or expose the public C `struct statfs` ABI.
#[inline]
pub fn fstatfs<Fd: AsFd>(fd: Fd) -> Result<StatFs> {
    let fd = fd.as_fd();
    let mut statfs = MaybeUninit::<StatFs>::uninit();
    // SAFETY: `StatFs` exactly matches the Linux/AArch64 `struct statfs`
    // output layout, and its writable storage remains live throughout the
    // syscall.
    unsafe { crabc_core::fs::fstatfs_raw(fd.as_raw_fd(), statfs.as_mut_ptr().cast())? };
    // SAFETY: A successful fstatfs initialized the complete StatFs object.
    Ok(unsafe { statfs.assume_init() })
}

/// Queries filesystem statistics for `path`.
///
/// The operation is a direct Linux/AArch64 `statfs` call. The pathname is
/// borrowed only for the duration of the syscall and failures are returned as
/// an ordinary [`crate::Errno`].
#[inline]
pub fn statfs<P: Arg>(path: P) -> Result<StatFs> {
    path.into_with_c_str(|path| {
        let mut statfs = MaybeUninit::<StatFs>::uninit();
        // `StatFs` exactly matches the Linux/AArch64 `struct statfs` output
        // layout, and `path`/the output storage remain live for the direct
        // syscall. The core wrapper owns the raw-pointer boundary.
        crabc_core::fs::statfs(path, statfs.as_mut_ptr().cast())?;
        // SAFETY: A successful statfs initialized the complete StatFs object.
        Ok(unsafe { statfs.assume_init() })
    })
}

/// Queries POSIX-shaped filesystem statistics for an open file or directory.
///
/// Linux has no `fstatvfs` syscall; this is [`fstatfs`] followed by the
/// documented [`StatFs`] to [`StatVfs`] field mapping.
#[inline]
pub fn fstatvfs<Fd: AsFd>(fd: Fd) -> Result<StatVfs> {
    fstatfs(fd).map(StatVfs::from)
}

/// Queries POSIX-shaped filesystem statistics for `path`.
///
/// Linux has no `statvfs` syscall; this is [`statfs`] followed by the
/// documented [`StatFs`] to [`StatVfs`] field mapping.
#[inline]
pub fn statvfs<P: Arg>(path: P) -> Result<StatVfs> {
    statfs(path).map(StatVfs::from)
}

/// Queries extended Linux metadata for `path` relative to `dirfd`.
///
/// This is Rustix's direct `statx` shape. The operation enters Linux/AArch64
/// through syscall 291, returns kernel errors directly, and does not emulate
/// musl's `ENOSYS` compatibility fallback or cache process-wide availability.
/// The returned [`Statx::stx_mask`] determines which requested observations
/// are valid; a successful call does not promise every requested field.
#[inline]
pub fn statx<P: Arg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    flags: AtFlags,
    mask: StatxFlags,
) -> Result<Statx> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        let mut statx = MaybeUninit::<Statx>::uninit();
        // `Statx` is the exact 256-byte Linux/AArch64 output layout. The
        // private core wire type validates that layout before issuing the
        // direct syscall, and the writable storage remains live throughout.
        unsafe {
            crabc_core::fs::statx_raw(
                dirfd.as_raw_fd(),
                path.as_ptr().cast(),
                flags.bits(),
                mask.bits(),
                statx.as_mut_ptr().cast(),
            )?
        };
        // SAFETY: A successful statx initialized the complete Statx object.
        Ok(unsafe { statx.assume_init() })
    })
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

/// Tests a path using the standard POSIX `access()` contract.
///
/// The path is resolved from the process current working directory. This is
/// musl's `faccessat(AT_FDCWD, path, mode, 0)` public-wrapper contract; on
/// AArch64 the underlying Linux syscall has only `(dirfd, path, mode)` and
/// therefore no flags argument. Linux performs the check with the real UID
/// and GID, matching `access()` rather than an effective-ID check. This
/// bounded API intentionally has no directory descriptor or `faccessat2`
/// flags surface.
#[inline]
pub fn access<P: Arg>(path: P, access: Access) -> Result<()> {
    if Access::from_bits(access.bits()).is_none() {
        return Err(crate::Errno::INVAL);
    }
    path.into_with_c_str(|path| crabc_core::fs::access(path, access.bits()))
}

/// Tests a path relative to a borrowed directory descriptor.
///
/// Empty [`AtFlags`] uses AArch64's direct three-argument `faccessat`
/// syscall. Either supported nonempty flag uses direct `faccessat2`; an old
/// kernel therefore returns [`crate::Errno::NOSYS`] rather than receiving an
/// emulated or cached fallback. Unknown access modes and flags are rejected
/// before path conversion and syscall entry. [`AtFlags::REMOVEDIR`] shares
/// Linux's `0x200` bit with [`AtFlags::EACCESS`], so that spelling is
/// necessarily interpreted as the latter at this call boundary.
#[inline]
pub fn accessat<P: Arg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    access: Access,
    flags: AtFlags,
) -> Result<()> {
    const ACCESSAT_FLAG_BITS: u32 = AtFlags::EACCESS.bits() | AtFlags::SYMLINK_NOFOLLOW.bits();
    if Access::from_bits(access.bits()).is_none() || flags.bits() & !ACCESSAT_FLAG_BITS != 0 {
        return Err(crate::Errno::INVAL);
    }
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        crabc_core::fs::accessat(dirfd.as_raw_fd(), path, access.bits(), flags.bits())
    })
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
/// operation never allocates and returns [`crate::Errno::RANGE`] when the
/// caller's output is too small, [`crate::Errno::INVAL`] for an invalid prefix,
/// or [`crate::Errno::NAMETOOLONG`] when the directory-entry/pathname bounds
/// are exceeded. No libc ABI, C `errno`, or process-global temporary-directory
/// state is used.
#[inline]
pub fn create_temp_dir_into<P: Arg, Prefix: Arg, Buf: Buffer<u8>>(
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
                .ok_or(crate::Errno::NAMETOOLONG)?;
            if total >= CANONICAL_PATH_MAX {
                return Err(crate::Errno::NAMETOOLONG);
            }
            if total > capacity {
                return Err(crate::Errno::RANGE);
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
pub fn create_temp_dir<P: Arg, Prefix: Arg>(parent: P, prefix: Prefix) -> Result<CString> {
    let mut output = [0u8; CANONICAL_PATH_MAX];
    let length = create_temp_dir_into(parent, prefix, &mut output)?;
    let mut bytes = Vec::with_capacity(length + 1);
    bytes.extend_from_slice(&output[..length]);
    bytes.push(0);
    // SAFETY: the source is composed from NUL-free `Arg` bytes and a
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
pub fn create_temp_dir_at_into<Fd: AsFd, Prefix: Arg, Buf: Buffer<u8>>(
    parent: Fd,
    prefix: Prefix,
    mut output: Buf,
) -> Result<Buf::Output> {
    let (pointer, capacity) = output.parts_mut();
    let initialized = prefix.into_with_c_str(|prefix| {
        let prefix = prefix.to_bytes();
        let name_length = validate_temp_prefix(prefix)?;
        if name_length > capacity {
            return Err(crate::Errno::RANGE);
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
pub fn create_temp_dir_at<Fd: AsFd, Prefix: Arg>(parent: Fd, prefix: Prefix) -> Result<CString> {
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
        return Err(crate::Errno::INVAL);
    }
    let name_length = prefix
        .len()
        .checked_add(TEMP_DIR_SUFFIX_LENGTH)
        .ok_or(crate::Errno::NAMETOOLONG)?;
    if name_length > TEMP_DIR_NAME_MAX {
        return Err(crate::Errno::NAMETOOLONG);
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
        return Err(crate::Errno::RANGE);
    }
    let parent = parent.as_fd();
    let mut candidate = [0u8; TEMP_DIR_NAME_MAX + 1];
    let mut entropy = [0u8; TEMP_DIR_RANDOM_BYTES];
    let hex = b"0123456789abcdef";

    let mut attempt = 0;
    while attempt < TEMP_DIR_MAX_ATTEMPTS {
        let _ = crate::rand::getentropy(&mut entropy)?;
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
            Err(crate::Errno::EXIST) => {
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Err(crate::Errno::EXIST)
}

/// Creates a Linux filesystem node relative to `dirfd`.
///
/// This follows Rustix's `mknodat` vocabulary while keeping the node type and
/// creation permissions distinct. `FileType::Unknown` is metadata-only and is
/// rejected. `mode` may contain only the permission and special bits accepted
/// by `mknodat`; its file-type bits (or any other unknown bits) are rejected
/// before the direct kernel call, so callers cannot accidentally override the
/// explicit `file_type`. `dev` is the Linux AArch64 `dev_t` value; use
/// [`FIFO_DEVICE`] for [`FileType::Fifo`].
#[inline]
pub fn mknodat<P: Arg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    file_type: FileType,
    mode: Mode,
    dev: Dev,
) -> Result<()> {
    if file_type == FileType::Unknown || mode.bits() & !0o7777 != 0 {
        return Err(crate::Errno::INVAL);
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
///
/// FIFOs have no device number; this wrapper always supplies
/// [`FIFO_DEVICE`] and the explicit [`FileType::Fifo`] type to Linux.
#[inline]
pub fn mkfifoat<P: Arg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode) -> Result<()> {
    mknodat(dirfd, path, FileType::Fifo, mode, FIFO_DEVICE)
}

/// Creates a FIFO node relative to the process current directory.
#[inline]
pub fn mkfifo<P: Arg>(path: P, mode: Mode) -> Result<()> {
    mkfifoat(CWD, path, mode)
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
/// The input is accepted through [`Arg`], so it may contain non-UTF-8 bytes but
/// may not contain an interior NUL. `.` and `..` are interpreted lexically,
/// while every existing component is checked against the kernel and symbolic
/// links are read relative to their containing directory. Linux's direct
/// `openat`, `readlinkat`, and `getcwd` seams are used; no libc function, C
/// ABI, or TLS `errno` is involved.
///
/// The initialized result is the canonical pathname without a trailing NUL.
/// A buffer too small for the result returns [`crate::Errno::RANGE`]. A
/// pathname or symlink expansion exceeding the Linux/musl `PATH_MAX` bound
/// returns [`crate::Errno::NAMETOOLONG`]. Symlink traversal is bounded at the
/// Linux/musl limit of forty links and returns [`crate::Errno::LOOP`] when the
/// limit is reached.
#[inline]
pub fn canonicalize_into<P: Arg, Buf: Buffer<u8>>(path: P, mut output: Buf) -> Result<Buf::Output> {
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
pub fn canonicalize<P: Arg>(path: P) -> Result<CString> {
    let path = path_bytes(path)?;
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
fn path_bytes<P: Arg>(path: P) -> Result<Vec<u8>> {
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
        with_path_cstr(path, |path| {
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
        with_path_cstr(component, |component| {
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
        with_path_cstr(b".", |path| {
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
        with_path_cstr(component, |component| {
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

fn with_path_cstr<T, F>(path: &[u8], f: F) -> Result<T>
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
    // component from a validated `Arg` or the fixed `.`/`/` spellings.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(&bytes[..path.len() + 1]) };
    f(path)
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
pub fn symlinkat<P: Arg, Q: Arg, Fd: AsFd>(target: P, new_dirfd: Fd, new_path: Q) -> Result<()> {
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
    renameat_with(
        old_dirfd,
        old_path,
        new_dirfd,
        new_path,
        RenameFlags::empty(),
    )
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

/// Converts optional typed ownership IDs to the Linux `fchown*` words.
///
/// Linux uses all ones (`(uid_t)-1`/`(gid_t)-1`) as an explicit no-change
/// sentinel. `None` is the only way to request that sentinel here: although
/// [`Uid::from_raw`] and [`Gid::from_raw`] preserve raw words for observation,
/// an all-ones typed ID is rejected so it cannot silently become `None`.
#[inline]
fn ownership_words(owner: Option<Uid>, group: Option<Gid>) -> Result<(u32, u32)> {
    let owner = match owner {
        Some(owner) if owner.as_raw() == u32::MAX => return Err(crate::Errno::INVAL),
        Some(owner) => owner.as_raw(),
        None => u32::MAX,
    };
    let group = match group {
        Some(group) if group.as_raw() == u32::MAX => return Err(crate::Errno::INVAL),
        Some(group) => group.as_raw(),
        None => u32::MAX,
    };
    Ok((owner, group))
}

/// Validates and returns the ownership-specific `fchownat` flag word.
#[inline]
fn checked_chown_flags(flags: ChownFlags) -> Result<u32> {
    ChownFlags::from_bits(flags.bits())
        .map(|flags| flags.bits())
        .ok_or(crate::Errno::INVAL)
}

/// Changes ownership for an open file or directory.
///
/// `None` for either ID maps to Linux's all-ones no-change sentinel. A
/// `Some(Uid::from_raw(u32::MAX))` or `Some(Gid::from_raw(u32::MAX))` is
/// rejected with [`crate::Errno::INVAL`] instead of being given that meaning.
#[inline]
pub fn fchown<Fd: AsFd>(fd: Fd, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
    let (owner, group) = ownership_words(owner, group)?;
    crabc_core::fs::fchown(fd.as_fd().as_raw_fd(), owner, group)
}

/// Changes ownership for `path` relative to `dirfd`.
///
/// The bounded [`ChownFlags`] type accepts only
/// [`ChownFlags::SYMLINK_NOFOLLOW`], which changes a symbolic link itself.
/// All other `AT_*` meanings belong to other syscall families and are
/// rejected before path conversion or the kernel boundary.
#[inline]
#[doc(alias = "fchownat")]
pub fn chownat<P: Arg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    owner: Option<Uid>,
    group: Option<Gid>,
    flags: ChownFlags,
) -> Result<()> {
    let (owner, group) = ownership_words(owner, group)?;
    let flags = checked_chown_flags(flags)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        crabc_core::fs::fchownat(dirfd.as_raw_fd(), path, owner, group, flags)
    })
}

/// Changes ownership for `path`, following a final symbolic link.
#[inline]
pub fn chown<P: Arg>(path: P, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
    chownat(CWD, path, owner, group, ChownFlags::empty())
}

/// Changes ownership for `path` without following a final symbolic link.
#[inline]
pub fn lchown<P: Arg>(path: P, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
    chownat(CWD, path, owner, group, ChownFlags::SYMLINK_NOFOLLOW)
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

/// Sets access and modification times on an open file using microseconds.
///
/// This preserves the legacy `futimes` timestamp unit while using Linux's
/// direct `utimensat` syscall. `None` maps to the kernel's null-times pointer,
/// which sets both timestamps to the current time. For `Some(times)`, each
/// `tv_usec` must be in `0..1_000_000`; invalid values return
/// [`crate::Errno::INVAL`] before entering the kernel.
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

/// Sets access and modification times on a path without following its final
/// symbolic link.
///
/// This keeps the legacy `lutimes` microsecond unit while using the direct
/// Linux `utimensat` syscall with [`AtFlags::SYMLINK_NOFOLLOW`]. `None` maps
/// to the kernel's null-times pointer and sets both timestamps to the current
/// time. Invalid microsecond fields return [`crate::Errno::INVAL`] before the
/// path conversion or syscall.
#[inline]
pub fn lutimes<P: Arg>(path: P, times: Option<&[Timeval; 2]>) -> Result<()> {
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
        // for this direct syscall. The no-follow flag updates the final
        // symbolic link itself rather than resolving it to its target.
        unsafe {
            crabc_core::fs::utimensat_raw(
                crabc_core::AT_FDCWD,
                path.as_ptr().cast(),
                times_ptr.cast(),
                AtFlags::SYMLINK_NOFOLLOW.bits(),
            )
        }
    })
}

/// Sets access and modification times for a path relative to `dirfd`,
/// following its final symbolic link.
///
/// This keeps the legacy `futimesat` microsecond unit while using the direct
/// Linux `utimensat` syscall with no path flags. `None` maps to the kernel's
/// null-times pointer and sets both timestamps to the current time. Invalid
/// microsecond fields return [`crate::Errno::INVAL`] before path conversion or
/// the syscall.
#[inline]
pub fn futimesat<P: Arg, Fd: AsFd>(dirfd: Fd, path: P, times: Option<&[Timeval; 2]>) -> Result<()> {
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
        // converted timestamp array remain live for this direct syscall.
        // Zero flags preserve futimesat's final-symlink-following behavior.
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

/// Sets access and modification times for a path relative to the process
/// current directory, following its final symbolic link.
///
/// This keeps the legacy `utimes` microsecond unit while using the direct
/// Linux `utimensat` syscall with zero path flags. `None` maps to the kernel's
/// null-times pointer and sets both timestamps to the current time. Invalid
/// microsecond fields return [`crate::Errno::INVAL`] before path conversion or
/// the syscall.
#[inline]
pub fn utimes<P: Arg>(path: P, times: Option<&[Timeval; 2]>) -> Result<()> {
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
        // for this direct syscall. Zero flags preserve utimes' final-symlink-
        // following behavior.
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

/// Sets access and modification times for a path at whole-second precision,
/// following its final symbolic link.
///
/// This preserves the legacy `utime` timestamp unit while using the direct
/// Linux `utimensat` syscall with `AT_FDCWD` and zero flags. `None` maps to
/// the kernel's null-times pointer and sets both timestamps to the current
/// time. Explicit [`Utimbuf`] values are converted to two `Timespec` values
/// with zero nanoseconds; no C ABI pointer or process-global error state is
/// involved.
#[inline]
pub fn utime<P: Arg>(path: P, times: Option<&Utimbuf>) -> Result<()> {
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
        // for this direct syscall. Zero flags preserve utime's final-symlink-
        // following behavior.
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
        return Err(crate::Errno::INVAL);
    }
    Ok(Timespec {
        tv_sec: time.tv_sec,
        tv_nsec: time.tv_usec * 1_000,
    })
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

// Linux/AArch64 keeps the trailing padding after `l_pid`; the direct fcntl
// seam must therefore receive the complete 32-byte record rather than a
// Rust-optimized approximation.
const _: [(); 32] = [(); core::mem::size_of::<KernelFlock>()];
const _: [(); 8] = [(); core::mem::align_of::<KernelFlock>()];

const F_GETLK: i32 = 5;
const F_SETLK: i32 = 6;
const F_SETLKW: i32 = 7;
const F_UNLCK: i16 = 2;
const F_WRLCK: i16 = 1;

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

/// Acquires, tests, or releases an exclusive lock relative to a descriptor's
/// current file offset.
///
/// The current offset is observed through direct `lseek(SEEK_CUR)` and is not
/// changed. `CurrentLockRange` is converted to a checked Linux/AArch64
/// `struct flock`; arithmetic overflow is returned as [`crate::Errno::RANGE`]
/// before the fcntl syscall. `TestExclusive` reports a conflicting lock as
/// [`crate::Errno::ACCESS`], matching the POSIX lockf observable result, while
/// all other kernel errors remain ordinary errno values.
#[inline]
#[doc(alias = "lockf")]
pub fn lock_from_current<Fd: AsFd>(
    fd: Fd,
    operation: CurrentLockOperation,
    range: CurrentLockRange,
) -> Result<()> {
    let fd = fd.as_fd();
    let current = crabc_core::fs::lseek(fd.as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)?;
    if current < 0 {
        return Err(crate::Errno::RANGE);
    }
    let (start, length) = match range {
        CurrentLockRange::ToEnd => (current, 0_i64),
        CurrentLockRange::Forward(length) => {
            let length = i64::try_from(length.get()).map_err(|_| crate::Errno::RANGE)?;
            (current, length)
        }
        CurrentLockRange::Backward(length) => {
            let length = i64::try_from(length.get()).map_err(|_| crate::Errno::RANGE)?;
            (
                current.checked_sub(length).ok_or(crate::Errno::RANGE)?,
                length,
            )
        }
    };
    let (command, lock_type) = match operation {
        CurrentLockOperation::Unlock => (F_SETLK, F_UNLCK),
        CurrentLockOperation::LockExclusive => (F_SETLKW, F_WRLCK),
        CurrentLockOperation::TryExclusive => (F_SETLK, F_WRLCK),
        CurrentLockOperation::TestExclusive => (F_GETLK, F_WRLCK),
    };
    let mut lock = KernelFlock {
        l_type: lock_type,
        l_whence: crabc_core::fs::SEEK_SET as i16,
        l_start: start,
        l_len: length,
        l_pid: 0,
    };
    // SAFETY: `KernelFlock` is the complete Linux/AArch64 `struct flock` ABI
    // record and remains live for the selected fcntl operation.
    unsafe {
        crabc_core::io::fcntl_raw(
            fd.as_raw_fd(),
            command,
            core::ptr::addr_of_mut!(lock).cast(),
        )
        .map(|_| ())?
    };
    if operation == CurrentLockOperation::TestExclusive && lock.l_type != F_UNLCK {
        return Err(crate::Errno::ACCESS);
    }
    Ok(())
}
