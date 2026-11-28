//! Darwin filesystem operations over libSystem.
//!
//! The facade module [`crate::fs`] re-exports these items next to the
//! vocabulary both targets share.

#[cfg(feature = "alloc")]
use alloc::{ffi::CString, vec::Vec};
use core::ffi::{c_char, c_int, c_uint, CStr};
use core::marker::PhantomData;
use core::mem::{align_of, offset_of, size_of, MaybeUninit};
use core::ptr::{self, NonNull};
use core::slice;

use super::errno::{self, Errno, Result};
use super::sys;
use crate::buffer::Buffer;
use crate::fs::{
    ownership_words, timeval_to_timespec, Access, CurrentLockOperation, CurrentLockRange,
    FileType, FlockOperation, Mode, Nsecs, PathArg, SeekFrom, Timespec, Timestamps, Timeval,
    Utimbuf,
};
use crate::process::{Gid, Uid};
#[cfg(feature = "alloc")]
use crate::fs::SMALL_PATH_BUFFER_SIZE;
use crate::{AsFd, BorrowedFd, OwnedFd, RawFd};

const _: () = {
    assert!(size_of::<Timespec>() == size_of::<sys::Timespec>());
    assert!(align_of::<Timespec>() == align_of::<sys::Timespec>());
    assert!(offset_of!(Timespec, tv_sec) == offset_of!(sys::Timespec, tv_sec));
    assert!(offset_of!(Timespec, tv_nsec) == offset_of!(sys::Timespec, tv_nsec));
    assert!(size_of::<Timestamps>() == 2 * size_of::<sys::Timespec>());
    assert!(offset_of!(Timestamps, last_modification) == size_of::<sys::Timespec>());
};

/// `AT_FDCWD`, the directory token representing the current working directory.
///
/// This is Darwin's reserved token (`-2`) rather than an owned descriptor. It
/// is accepted only as the directory argument to `*at` operations.
pub const CWD: BorrowedFd<'static> =
    // SAFETY: `AT_FDCWD` is Darwin's reserved, non-allocatable token, which
    // the documented exception in `BorrowedFd::borrow_raw` permits.
    unsafe { BorrowedFd::borrow_raw(sys::AT_FDCWD) };

bitflags::bitflags! {
    /// Darwin `O_*` values for [`openat`], [`fcntl_getfl`], and
    /// [`fcntl_setfl`].
    ///
    /// The flags common to both targets keep their Linux names. Linux-only
    /// flags (`DIRECT`, `LARGEFILE`, `NOATIME`, `PATH`, `TMPFILE`, `RSYNC`)
    /// have no Darwin counterpart and are absent; Darwin-only flags are
    /// added under their Darwin names. Unknown bits are retained and passed
    /// to libSystem unchanged.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct OFlags: u32 {
        /// `O_ACCMODE`.
        const ACCMODE = sys::O_ACCMODE.cast_unsigned();
        /// The read/write-only portion of [`Self::ACCMODE`]; equal to it on
        /// Darwin.
        const RWMODE = sys::O_ACCMODE.cast_unsigned();
        /// `O_RDONLY`. This bit pattern is zero.
        const RDONLY = sys::O_RDONLY.cast_unsigned();
        /// `O_WRONLY`.
        const WRONLY = sys::O_WRONLY.cast_unsigned();
        /// `O_RDWR`.
        const RDWR = sys::O_RDWR.cast_unsigned();
        /// `O_CREAT`.
        const CREATE = sys::O_CREAT.cast_unsigned();
        /// `O_EXCL`.
        const EXCL = sys::O_EXCL.cast_unsigned();
        /// `O_NOCTTY`.
        const NOCTTY = sys::O_NOCTTY.cast_unsigned();
        /// `O_TRUNC`.
        const TRUNC = sys::O_TRUNC.cast_unsigned();
        /// `O_APPEND`.
        const APPEND = sys::O_APPEND.cast_unsigned();
        /// `O_NONBLOCK`.
        const NONBLOCK = sys::O_NONBLOCK.cast_unsigned();
        /// `O_DSYNC`.
        const DSYNC = sys::O_DSYNC.cast_unsigned();
        /// `O_ASYNC`.
        const ASYNC = sys::O_ASYNC.cast_unsigned();
        /// `O_DIRECTORY`.
        const DIRECTORY = sys::O_DIRECTORY.cast_unsigned();
        /// `O_NOFOLLOW`.
        const NOFOLLOW = sys::O_NOFOLLOW.cast_unsigned();
        /// `O_CLOEXEC`.
        const CLOEXEC = sys::O_CLOEXEC.cast_unsigned();
        /// `O_SYNC`.
        const SYNC = sys::O_SYNC.cast_unsigned();
        /// `O_FSYNC`, an alias of [`Self::SYNC`].
        const FSYNC = Self::SYNC.bits();
        /// `O_SHLOCK`: take a shared `flock` lock atomically with the open.
        const SHLOCK = sys::O_SHLOCK.cast_unsigned();
        /// `O_EXLOCK`: take an exclusive `flock` lock atomically with the open.
        const EXLOCK = sys::O_EXLOCK.cast_unsigned();
        /// `O_EVTONLY`: open only for event notification.
        const EVTONLY = sys::O_EVTONLY.cast_unsigned();
        /// `O_SYMLINK`: open a final symbolic link itself.
        const SYMLINK = sys::O_SYMLINK.cast_unsigned();
        /// `O_CLOFORK`: close the descriptor in the child of a fork.
        const CLOFORK = sys::O_CLOFORK.cast_unsigned();
        /// `O_NOFOLLOW_ANY`: reject a symbolic link in any path component.
        const NOFOLLOW_ANY = sys::O_NOFOLLOW_ANY.cast_unsigned();
        /// `O_EXEC`: open for execute only.
        const EXEC = sys::O_EXEC.cast_unsigned();
        /// `O_SEARCH`: open a directory for search only.
        const SEARCH = (sys::O_EXEC | sys::O_DIRECTORY).cast_unsigned();
        /// Preserve unknown bits.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The closed `fstatat(2)` flag vocabulary admitted by [`statat`], with
    /// Darwin values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct AtFlags: u32 {
        /// `AT_SYMLINK_NOFOLLOW`.
        const SYMLINK_NOFOLLOW = sys::AT_SYMLINK_NOFOLLOW.cast_unsigned();
    }
}

bitflags::bitflags! {
    /// Flags accepted by [`unlinkat`], with Darwin values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct UnlinkAtFlags: u32 {
        /// Remove an empty directory rather than a non-directory entry.
        const REMOVEDIR = sys::AT_REMOVEDIR.cast_unsigned();
    }
}

bitflags::bitflags! {
    /// Flags accepted by [`linkat`], with Darwin values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct LinkAtFlags: u32 {
        /// Follow a final symbolic link at the source path.
        const SYMLINK_FOLLOW = sys::AT_SYMLINK_FOLLOW.cast_unsigned();
    }
}

bitflags::bitflags! {
    /// Rename flags admitted by [`renameat_with`], with Darwin
    /// `renameatx_np` values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct RenameFlags: u32 {
        /// Fail when the destination already exists (`RENAME_EXCL`).
        const NOREPLACE = sys::RENAME_EXCL;
        /// Atomically exchange two existing directory entries
        /// (`RENAME_SWAP`).
        const EXCHANGE = sys::RENAME_SWAP;
    }
}

bitflags::bitflags! {
    /// The closed `utimensat(2)` pathname flag vocabulary, with Darwin values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct TimestampAtFlags: u32 {
        /// Update a final symbolic link itself rather than its target.
        const SYMLINK_NOFOLLOW = sys::AT_SYMLINK_NOFOLLOW.cast_unsigned();
    }
}

bitflags::bitflags! {
    /// Flags accepted by [`chownat`], with Darwin values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct ChownFlags: u32 {
        /// Change a final symbolic link itself rather than its target.
        const SYMLINK_NOFOLLOW = sys::AT_SYMLINK_NOFOLLOW.cast_unsigned();
    }
}

bitflags::bitflags! {
    /// Flags accepted by [`accessat`], with Darwin values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct AccessAtFlags: u32 {
        /// Check using effective rather than real credentials.
        const EACCESS = sys::AT_EACCESS.cast_unsigned();
        /// Check the final symbolic link itself rather than its target.
        const SYMLINK_NOFOLLOW = sys::AT_SYMLINK_NOFOLLOW.cast_unsigned();
    }
}

/// Darwin `dev_t`, used by [`mknodat`].
pub type Dev = i32;

/// The current-time sentinel accepted in [`Timespec::tv_nsec`] by Darwin
/// `utimensat`.
pub const UTIME_NOW: Nsecs = sys::UTIME_NOW;

/// The leave-unchanged sentinel accepted in [`Timespec::tv_nsec`] by Darwin
/// `utimensat`.
pub const UTIME_OMIT: Nsecs = sys::UTIME_OMIT;

/// Opens the directory that temporary-object creation works relative to.
///
/// Darwin has no `O_PATH`; `O_SEARCH` needs only search permission on the
/// directory, which creating an entry in it requires anyway.
pub(crate) const TEMP_PARENT_FLAGS: OFlags = OFlags::SEARCH.union(OFlags::CLOEXEC);

/// Darwin's `mode_t` is 16 bits. libSystem keeps only the permission and
/// special bits of a creation or change mode, so dropping higher [`Mode`]
/// bits matches Linux, which also ignores them.
#[inline]
fn mode_bits(mode: Mode) -> sys::mode_t {
    (mode.bits() & 0xffff) as sys::mode_t
}

#[inline]
fn path_ptr(path: &CStr) -> *const c_char {
    path.as_ptr()
}

/// Tests a pathname with libSystem `access`, using the real UID and GID.
///
/// Unknown [`Access`] bits are rejected with [`Errno::INVAL`] before the
/// pathname is converted.
#[inline]
pub fn access<P: PathArg>(path: P, access: Access) -> Result<()> {
    let access = Access::from_bits(access.bits()).ok_or(Errno::INVAL)?;
    path.into_with_c_str(|path| {
        // SAFETY: `PathArg` keeps `path` NUL-terminated and live for the call.
        let result = unsafe { sys::access(path_ptr(path), access.bits().cast_signed()) };
        errno::check(result).map(|_| ())
    })
}

/// Tests a pathname relative to `dirfd` with libSystem `faccessat`.
///
/// Unknown access modes and flags are rejected with [`Errno::INVAL`] before
/// the descriptor is used.
#[inline]
#[doc(alias = "faccessat")]
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
        // SAFETY: the descriptor borrow and `PathArg` keep both arguments live.
        let result = unsafe {
            sys::faccessat(
                dirfd.as_raw_fd(),
                path_ptr(path),
                access.bits().cast_signed(),
                flags.bits().cast_signed(),
            )
        };
        errno::check(result).map(|_| ())
    })
}

/// Reads the open-file-description status flags through `fcntl(F_GETFL)`.
///
/// Unknown bits are retained.
#[inline]
#[doc(alias = "F_GETFL")]
pub fn fcntl_getfl<Fd: AsFd>(fd: Fd) -> Result<OFlags> {
    // SAFETY: `F_GETFL` takes no argument and touches no caller memory.
    let flags = unsafe { sys::fcntl(fd.as_fd().as_raw_fd(), sys::F_GETFL) };
    errno::check(flags).map(|flags| OFlags::from_bits_retain(flags.cast_unsigned()))
}

/// Replaces the open-file-description status flags through `fcntl(F_SETFL)`.
///
/// Darwin changes only the status flags `F_SETFL` may set and ignores the
/// access mode and creation flags. The change affects every descriptor that
/// shares the open file description.
#[inline]
#[doc(alias = "F_SETFL")]
pub fn fcntl_setfl<Fd: AsFd>(fd: Fd, flags: OFlags) -> Result<()> {
    // SAFETY: `F_SETFL` takes one `int` and touches no caller memory.
    let result =
        unsafe { sys::fcntl(fd.as_fd().as_raw_fd(), sys::F_SETFL, flags.bits().cast_signed()) };
    errno::check(result).map(|_| ())
}

/// Acquires or releases a whole-file `flock(2)` advisory lock.
///
/// Darwin associates these locks with the open file description, as Linux
/// does. Blocking operations may wait indefinitely.
#[inline]
pub fn flock<Fd: AsFd>(fd: Fd, operation: FlockOperation) -> Result<()> {
    // SAFETY: `flock` has no memory arguments; the borrow keeps `fd` open.
    let result = unsafe { sys::flock(fd.as_fd().as_raw_fd(), operation as c_int) };
    errno::check(result).map(|_| ())
}

#[inline]
fn fcntl_record_lock(fd: BorrowedFd<'_>, command: c_int, lock: &mut sys::Flock) -> Result<()> {
    // SAFETY: the record-lock commands read, and `F_GETLK` writes, exactly
    // one `struct flock`, which `lock` keeps live and exclusive for the call.
    let result = unsafe { sys::fcntl(fd.as_raw_fd(), command, ptr::from_mut(lock)) };
    errno::check(result).map(|_| ())
}

/// Acquires or releases a whole-file, process-associated `fcntl` lock.
///
/// The range extends from byte zero through the dynamically changing EOF.
/// These locks do not exclude threads of the same process, and closing any
/// descriptor for the file releases the process's locks on it.
#[inline]
pub fn fcntl_lock<Fd: AsFd>(fd: Fd, operation: FlockOperation) -> Result<()> {
    let (command, lock_type) = match operation {
        FlockOperation::LockShared => (sys::F_SETLKW, sys::F_RDLCK),
        FlockOperation::LockExclusive => (sys::F_SETLKW, sys::F_WRLCK),
        FlockOperation::Unlock => (sys::F_SETLKW, sys::F_UNLCK),
        FlockOperation::NonBlockingLockShared => (sys::F_SETLK, sys::F_RDLCK),
        FlockOperation::NonBlockingLockExclusive => (sys::F_SETLK, sys::F_WRLCK),
        FlockOperation::NonBlockingUnlock => (sys::F_SETLK, sys::F_UNLCK),
    };
    let mut lock = sys::Flock {
        l_start: 0,
        l_len: 0,
        l_pid: 0,
        l_type: lock_type,
        l_whence: sys::FLOCK_WHENCE_SET,
    };
    fcntl_record_lock(fd.as_fd(), command, &mut lock)
}

/// Acquires, tests, or releases an exclusive process-associated record lock
/// relative to a descriptor's observed current file offset.
///
/// The contract matches the Linux facade: the offset is read with
/// `lseek(SEEK_CUR)` and never changed, lengths above `i64::MAX` return
/// [`Errno::RANGE`], and `TestExclusive` reports a conflict as
/// [`Errno::ACCESS`].
#[inline]
#[doc(alias = "lockf")]
pub fn lock_from_current<Fd: AsFd>(
    fd: Fd,
    operation: CurrentLockOperation,
    range: CurrentLockRange,
) -> Result<()> {
    let fd = fd.as_fd();
    let current = tell(fd)?;
    let current = i64::try_from(current).map_err(|_| Errno::RANGE)?;
    let (start, length) = match range {
        CurrentLockRange::ToEnd => (current, 0_i64),
        CurrentLockRange::Forward(length) => {
            let length = i64::try_from(length.get()).map_err(|_| Errno::RANGE)?;
            (current, length)
        }
        CurrentLockRange::Backward(length) => {
            let length = i64::try_from(length.get()).map_err(|_| Errno::RANGE)?;
            (current.checked_sub(length).ok_or(Errno::RANGE)?, length)
        }
    };
    let (command, lock_type) = match operation {
        CurrentLockOperation::Unlock => (sys::F_SETLK, sys::F_UNLCK),
        CurrentLockOperation::LockExclusive => (sys::F_SETLKW, sys::F_WRLCK),
        CurrentLockOperation::TryExclusive => (sys::F_SETLK, sys::F_WRLCK),
        CurrentLockOperation::TestExclusive => (sys::F_GETLK, sys::F_WRLCK),
    };
    let mut lock = sys::Flock {
        l_start: start,
        l_len: length,
        l_pid: 0,
        l_type: lock_type,
        l_whence: sys::FLOCK_WHENCE_SET,
    };
    fcntl_record_lock(fd, command, &mut lock)?;
    if operation == CurrentLockOperation::TestExclusive && lock.l_type != sys::F_UNLCK {
        return Err(Errno::ACCESS);
    }
    Ok(())
}

/// A descriptor-owning libSystem directory stream.
///
/// `Dir` owns a libSystem `DIR` created with `fdopendir`. Each entry borrows
/// the stream, so an entry cannot remain live while the next call advances
/// it. Unlike the Linux stream, libSystem allocates and owns the record
/// storage: the caller's `buffer` is borrowed for source compatibility but
/// never written. `fdopendir` also sets `FD_CLOEXEC` on the descriptor it
/// adopts, including one passed to [`Self::from_owned_fd`].
///
/// `None` means end-of-directory; `Some(Err(_))` reports the first error,
/// after which the stream is exhausted until [`Self::rewind`] or
/// [`Self::seek`].
pub struct Dir<'buffer> {
    stream: Stream,
    fd: RawFd,
    done: bool,
    _buffer: PhantomData<&'buffer mut [MaybeUninit<u8>]>,
}

enum Stream {
    Open(NonNull<sys::Dir>),
    Failed { _fd: OwnedFd, error: Errno },
}

// SAFETY: `Dir` uniquely owns its libSystem stream, and a `DIR` is not tied to
// the thread that created it. Moving the owner moves every later use of the
// stream to the receiving thread; `fd` is a plain integer and `OwnedFd` is
// `Send`.
unsafe impl Send for Dir<'_> {}

// SAFETY: every method that touches the libSystem stream takes `&mut self`.
// Through `&Dir` only `as_fd` is reachable, and it reads the stored descriptor
// number without touching the stream.
unsafe impl Sync for Dir<'_> {}

/// One byte-preserving entry borrowed from [`Dir`].
///
/// The name borrows libSystem's record, which stays valid until the stream
/// advances; the borrow of the [`Dir`] enforces that. The entry is `Send` but,
/// unlike its Linux counterpart, not `Sync`: [`Self::next_entry_cookie`]
/// queries the stream itself.
#[derive(Debug)]
pub struct DirEntry<'entry> {
    file_name: &'entry CStr,
    file_type: FileType,
    inode_number: u64,
    stream: NonNull<sys::Dir>,
}

// SAFETY: the entry exclusively borrows its `Dir` for `'entry`, so no other
// thread can use the stream while the entry lives. Moving the entry moves the
// only remaining user of the stream pointer, and a `DIR` is not tied to the
// thread that created it. The name is an immutable borrow of `Sync` data.
unsafe impl Send for DirEntry<'_> {}

impl<'buffer> Dir<'buffer> {
    /// Opens `path` as a close-on-exec directory stream.
    #[inline]
    pub fn open<P: PathArg>(path: P, buffer: &'buffer mut [MaybeUninit<u8>]) -> Result<Self> {
        Self::openat(CWD, path, buffer)
    }

    /// Opens `path` relative to a borrowed directory descriptor as a
    /// close-on-exec directory stream.
    ///
    /// A failure to create the libSystem stream is returned here rather than
    /// from the first call to [`Self::next`].
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
        let dir = Self::from_owned_fd(fd, buffer);
        match dir.stream {
            Stream::Open(_) => Ok(dir),
            Stream::Failed { error, .. } => Err(error),
        }
    }

    /// Constructs a stream by transferring ownership of an existing
    /// directory descriptor.
    ///
    /// The descriptor is not re-opened or duplicated. If libSystem cannot
    /// adopt it, for example because it is not a directory, the first call to
    /// [`Self::next`] returns that error.
    #[inline]
    pub fn from_owned_fd(fd: OwnedFd, buffer: &'buffer mut [MaybeUninit<u8>]) -> Self {
        let _ = buffer;
        let raw = fd.as_raw_fd();
        // SAFETY: `raw` is open and owned by `fd`. On success the stream takes
        // over the descriptor; on failure libSystem leaves it untouched.
        let stream = unsafe { sys::fdopendir(raw) };
        let stream = match NonNull::new(stream) {
            Some(stream) => {
                let _ = fd.into_raw_fd();
                Stream::Open(stream)
            }
            None => Stream::Failed {
                error: errno::last(),
                _fd: fd,
            },
        };
        Self {
            stream,
            fd: raw,
            done: false,
            _buffer: PhantomData,
        }
    }

    /// Rewinds the directory stream to its beginning with `rewinddir`.
    #[inline]
    pub fn rewind(&mut self) {
        if let Stream::Open(stream) = self.stream {
            // SAFETY: `stream` is the live stream this value owns, and
            // `&mut self` excludes any borrowed entry.
            unsafe { sys::rewinddir(stream.as_ptr()) };
        }
        self.done = false;
    }

    /// Seeks to a cookie returned by [`DirEntry::next_entry_cookie`] with
    /// `seekdir`.
    ///
    /// libSystem's `seekdir` reports no error: a cookie this stream did not
    /// produce leaves the position unchanged.
    #[inline]
    pub fn seek(&mut self, offset: i64) -> Result<()> {
        match self.stream {
            Stream::Open(stream) => {
                // SAFETY: `stream` is the live stream this value owns, and
                // `&mut self` excludes any borrowed entry.
                unsafe { sys::seekdir(stream.as_ptr(), offset) };
                self.done = false;
                Ok(())
            }
            Stream::Failed { error, .. } => {
                self.done = true;
                Err(error)
            }
        }
    }

    /// Returns the next entry, an error, or end-of-directory.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<DirEntry<'_>>> {
        if self.done {
            return None;
        }
        let stream = match self.stream {
            Stream::Open(stream) => stream,
            Stream::Failed { error, .. } => {
                self.done = true;
                return Some(Err(error));
            }
        };
        errno::clear();
        // SAFETY: `stream` is the live stream this value owns, and `&mut self`
        // excludes any entry still borrowing the previous record.
        let record = unsafe { sys::readdir(stream.as_ptr()) };
        let Some(record) = NonNull::new(record) else {
            let error = errno::current();
            self.done = true;
            return error.map(Err);
        };
        // SAFETY: `record` is the record `readdir` just returned for this
        // stream. The entry's lifetime is the exclusive borrow of `self`,
        // which excludes every call that advances or closes the stream.
        match unsafe { read_record(record) } {
            Ok((file_name, file_type, inode_number)) => Some(Ok(DirEntry {
                file_name,
                file_type,
                inode_number,
                stream,
            })),
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }

    /// Borrows the owned directory descriptor without transferring ownership.
    ///
    /// Changing the file position through this borrow bypasses libSystem's
    /// buffered records; use [`Self::seek`] or [`Self::rewind`] instead.
    #[inline]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the stream, or the failed owner, keeps `self.fd` open until
        // `self` is dropped, which cannot happen while the returned borrow of
        // `self` lives.
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

/// Validates one libSystem `struct dirent` and borrows its name.
///
/// The record is variable-length: only `d_reclen` bytes are guaranteed to be
/// readable, so it is read field by field instead of as a whole struct.
///
/// # Safety
///
/// `record` must be the record `readdir` just returned for a live stream, and
/// the returned name must not be used after that stream next advances or is
/// closed.
unsafe fn read_record<'entry>(
    record: NonNull<sys::Dirent>,
) -> Result<(&'entry CStr, FileType, u64)> {
    let base = record.as_ptr().cast::<u8>();
    let field = |offset: usize| base.wrapping_add(offset);
    // SAFETY: `readdir` returned a complete record, whose fixed header
    // (through `d_type`) is readable. Unaligned reads make no assumption
    // about record alignment.
    let inode_number = unsafe { field(offset_of!(sys::Dirent, d_ino)).cast::<u64>().read_unaligned() };
    // SAFETY: as above; `d_reclen` lies in the fixed header.
    let record_length =
        unsafe { field(offset_of!(sys::Dirent, d_reclen)).cast::<u16>().read_unaligned() };
    // SAFETY: as above; `d_namlen` lies in the fixed header.
    let name_length =
        unsafe { field(offset_of!(sys::Dirent, d_namlen)).cast::<u16>().read_unaligned() };
    // SAFETY: as above; `d_type` lies in the fixed header.
    let d_type = unsafe { field(offset_of!(sys::Dirent, d_type)).read() };
    let name_offset = offset_of!(sys::Dirent, d_name);
    let name_end = name_offset + usize::from(name_length) + 1;
    if name_end > usize::from(record_length) {
        return Err(Errno::IO);
    }
    // SAFETY: the name and its terminator lie within the `d_reclen` bytes
    // libSystem provides, which the caller keeps unchanged for `'entry`.
    let name = unsafe { slice::from_raw_parts(field(name_offset), name_end - name_offset) };
    let file_name = CStr::from_bytes_with_nul(name).map_err(|_| Errno::IO)?;
    Ok((file_name, FileType::from_dirent_d_type(d_type), inode_number))
}

impl Drop for Dir<'_> {
    fn drop(&mut self) {
        if let Stream::Open(stream) = self.stream {
            // SAFETY: `stream` is live and owned by `self`, and is never used
            // again. `closedir` also closes the adopted descriptor; its error
            // cannot be reported from `Drop` and retrying could close a reused
            // descriptor number.
            let _ = unsafe { sys::closedir(stream.as_ptr()) };
        }
    }
}

impl AsFd for Dir<'_> {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        Dir::as_fd(self)
    }
}

impl DirEntry<'_> {
    /// Returns the entry name as bytes without its trailing NUL.
    #[inline]
    pub fn name_bytes(&self) -> &[u8] {
        self.file_name.to_bytes()
    }

    /// Returns the byte-preserving entry name.
    #[inline]
    pub fn file_name(&self) -> &CStr {
        self.file_name
    }

    /// Returns the file type reported by the directory record.
    #[inline]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// Returns the entry inode number.
    #[inline]
    #[doc(alias = "inode_number")]
    pub fn ino(&self) -> u64 {
        self.inode_number
    }

    /// Returns the `telldir` cookie for the next entry, for [`Dir::seek`].
    ///
    /// libSystem records a position for each distinct cookie until the stream
    /// is closed. If it cannot record one, the result is `u64::MAX`, which
    /// [`Dir::seek`] ignores.
    #[inline]
    #[doc(alias = "off")]
    pub fn next_entry_cookie(&self) -> u64 {
        // SAFETY: the entry's borrow of its `Dir` keeps the stream live and
        // positioned just after this entry, and excludes every other use of
        // it while the entry exists.
        let cookie = unsafe { sys::telldir(self.stream.as_ptr()) };
        cookie.cast_unsigned()
    }
}

/// Darwin file metadata returned by [`fstat`] and [`statat`].
///
/// libSystem's `struct stat` stores several fields in narrower integers than
/// Linux/AArch64. This record widens them without loss to the Linux/AArch64
/// field types, so code reading the shared fields builds for both targets.
/// `st_dev` and `st_rdev` hold the bit pattern of Darwin's 32-bit `dev_t`,
/// zero-extended. The Darwin-only birth time, file flags and generation
/// number follow.
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
    /// Size in bytes.
    pub st_size: i64,
    /// Preferred I/O block size.
    pub st_blksize: i32,
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
    /// Creation time in seconds.
    pub st_birthtime: i64,
    /// Creation nanoseconds.
    pub st_birthtime_nsec: u64,
    /// User-settable file flags (`chflags`).
    pub st_flags: u32,
    /// File generation number.
    pub st_gen: u32,
}

impl Stat {
    #[inline]
    fn from_sys(raw: &sys::Stat) -> Self {
        Self {
            st_dev: u64::from(raw.st_dev.cast_unsigned()),
            st_ino: raw.st_ino,
            st_mode: u32::from(raw.st_mode),
            st_nlink: u32::from(raw.st_nlink),
            st_uid: raw.st_uid,
            st_gid: raw.st_gid,
            st_rdev: u64::from(raw.st_rdev.cast_unsigned()),
            st_size: raw.st_size,
            st_blksize: raw.st_blksize,
            st_blocks: raw.st_blocks,
            st_atime: raw.st_atimespec.tv_sec,
            st_atime_nsec: raw.st_atimespec.tv_nsec.cast_unsigned(),
            st_mtime: raw.st_mtimespec.tv_sec,
            st_mtime_nsec: raw.st_mtimespec.tv_nsec.cast_unsigned(),
            st_ctime: raw.st_ctimespec.tv_sec,
            st_ctime_nsec: raw.st_ctimespec.tv_nsec.cast_unsigned(),
            st_birthtime: raw.st_birthtimespec.tv_sec,
            st_birthtime_nsec: raw.st_birthtimespec.tv_nsec.cast_unsigned(),
            st_flags: raw.st_flags,
            st_gen: raw.st_gen,
        }
    }
}

/// Queries metadata for an open file or directory descriptor.
#[inline]
pub fn fstat<Fd: AsFd>(fd: Fd) -> Result<Stat> {
    let fd = fd.as_fd();
    let mut raw = MaybeUninit::<sys::Stat>::uninit();
    // SAFETY: `raw` is writable storage for one complete `struct stat`, live
    // for the call, and the borrow keeps the descriptor open.
    let result = unsafe { sys::fstat(fd.as_raw_fd(), raw.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `fstat` initialized the complete record.
    let raw = unsafe { raw.assume_init() };
    Ok(Stat::from_sys(&raw))
}

/// Queries metadata for `path` relative to `dirfd` with libSystem `fstatat`.
///
/// Only [`AtFlags::SYMLINK_NOFOLLOW`] is admitted; other bits return
/// [`Errno::INVAL`] before the pathname is converted.
#[inline]
#[doc(alias = "fstatat")]
pub fn statat<P: PathArg, Fd: AsFd>(dirfd: Fd, path: P, flags: AtFlags) -> Result<Stat> {
    let flags = AtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        let mut raw = MaybeUninit::<sys::Stat>::uninit();
        // SAFETY: `PathArg` keeps `path` live, and `raw` is writable storage
        // for one complete `struct stat` during the call.
        let result = unsafe {
            sys::fstatat(dirfd.as_raw_fd(), path_ptr(path), raw.as_mut_ptr(), flags.bits().cast_signed())
        };
        errno::check(result)?;
        // SAFETY: a successful `fstatat` initialized the complete record.
        let raw = unsafe { raw.assume_init() };
        Ok(Stat::from_sys(&raw))
    })
}

/// Opens `path` relative to `dirfd` with libSystem `openat`.
///
/// `O_*` meanings are Darwin's. `create_mode` is meaningful only with a
/// creation flag, and the process umask still applies.
#[inline]
pub fn openat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    oflags: OFlags,
    create_mode: Mode,
) -> Result<OwnedFd> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: the descriptor borrow and `PathArg` keep both arguments live.
        // The mode is passed as the promoted `unsigned int` that the variadic
        // prototype reads.
        let fd = unsafe {
            sys::openat(
                dirfd.as_raw_fd(),
                path_ptr(path),
                oflags.bits().cast_signed(),
                c_uint::from(mode_bits(create_mode)),
            )
        };
        let fd = errno::check(fd)?;
        // SAFETY: a successful `openat` returns one fresh, non-negative
        // descriptor whose ownership transfers to this owner.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    })
}

/// Creates a directory relative to `dirfd`. The process umask applies.
#[inline]
pub fn mkdirat<P: PathArg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode) -> Result<()> {
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: the descriptor borrow and `PathArg` keep both arguments live.
        let result = unsafe { sys::mkdirat(dirfd.as_raw_fd(), path_ptr(path), mode_bits(mode)) };
        errno::check(result).map(|_| ())
    })
}

/// Creates a filesystem node relative to `dirfd` with libSystem `mknodat`.
///
/// The file kind and permission bits are separate, as on Linux;
/// [`FileType::Unknown`] and mode bits outside `0o7777` return
/// [`Errno::INVAL`]. Device nodes require superuser privilege on Darwin.
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
    let raw_mode =
        sys::mode_t::try_from(file_type.as_raw_mode() | mode.bits()).map_err(|_| Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: the descriptor borrow and `PathArg` keep both arguments live.
        let result = unsafe { sys::mknodat(dirfd.as_raw_fd(), path_ptr(path), raw_mode, dev) };
        errno::check(result).map(|_| ())
    })
}

/// Removes a path relative to `dirfd`.
///
/// [`UnlinkAtFlags::REMOVEDIR`] selects removal of an empty directory.
/// Unknown flag bits return [`Errno::INVAL`].
#[inline]
pub fn unlinkat<P: PathArg, Fd: AsFd>(dirfd: Fd, path: P, flags: UnlinkAtFlags) -> Result<()> {
    let flags = UnlinkAtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: the descriptor borrow and `PathArg` keep both arguments live.
        let result =
            unsafe { sys::unlinkat(dirfd.as_raw_fd(), path_ptr(path), flags.bits().cast_signed()) };
        errno::check(result).map(|_| ())
    })
}

/// Creates a hard link between paths relative to their directory descriptors.
///
/// Unknown flag bits return [`Errno::INVAL`].
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
            // SAFETY: both descriptor borrows and both `PathArg` strings stay
            // live for the call.
            let result = unsafe {
                sys::linkat(
                    old_dirfd.as_raw_fd(),
                    path_ptr(old_path),
                    new_dirfd.as_raw_fd(),
                    path_ptr(new_path),
                    flags.bits().cast_signed(),
                )
            };
            errno::check(result).map(|_| ())
        })
    })
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
            // SAFETY: the descriptor borrow and both strings stay live.
            let result = unsafe {
                sys::symlinkat(path_ptr(target), new_dirfd.as_raw_fd(), path_ptr(new_path))
            };
            errno::check(result).map(|_| ())
        })
    })
}

/// Renames a path or directory with libSystem `renameatx_np`.
///
/// [`RenameFlags::NOREPLACE`] and [`RenameFlags::EXCHANGE`] are mutually
/// exclusive; their combination and unknown bits return [`Errno::INVAL`]
/// before path conversion. A filesystem without support for a flag returns
/// [`Errno::NOTSUP`].
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
            // SAFETY: both descriptor borrows and both strings stay live.
            let result = unsafe {
                sys::renameatx_np(
                    old_dirfd.as_raw_fd(),
                    path_ptr(old_path),
                    new_dirfd.as_raw_fd(),
                    path_ptr(new_path),
                    flags.bits(),
                )
            };
            errno::check(result).map(|_| ())
        })
    })
}

/// Changes permissions for an open file or directory.
#[inline]
pub fn fchmod<Fd: AsFd>(fd: Fd, mode: Mode) -> Result<()> {
    // SAFETY: `fchmod` has no memory arguments; the borrow keeps `fd` open.
    let result = unsafe { sys::fchmod(fd.as_fd().as_raw_fd(), mode_bits(mode)) };
    errno::check(result).map(|_| ())
}

/// Changes permissions for `path` relative to `dirfd` with `fchmodat`.
///
/// Unlike Linux, Darwin can change a symbolic link's own mode:
/// [`AtFlags::SYMLINK_NOFOLLOW`] does so. Unknown bits return
/// [`Errno::INVAL`].
#[inline]
#[doc(alias = "fchmodat")]
pub fn chmodat<P: PathArg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode, flags: AtFlags) -> Result<()> {
    let flags = AtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: the descriptor borrow and `PathArg` keep both arguments live.
        let result = unsafe {
            sys::fchmodat(dirfd.as_raw_fd(), path_ptr(path), mode_bits(mode), flags.bits().cast_signed())
        };
        errno::check(result).map(|_| ())
    })
}

/// Changes ownership for an open file or directory.
///
/// `None` leaves that ID unchanged; an all-ones typed ID is rejected with
/// [`Errno::INVAL`] because libSystem reserves it as the no-change value.
#[inline]
pub fn fchown<Fd: AsFd>(fd: Fd, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
    let (owner, group) = ownership_words(owner, group)?;
    // SAFETY: `fchown` has no memory arguments; the borrow keeps `fd` open.
    let result = unsafe { sys::fchown(fd.as_fd().as_raw_fd(), owner, group) };
    errno::check(result).map(|_| ())
}

/// Changes ownership for `path` relative to `dirfd` with `fchownat`.
///
/// [`ChownFlags::SYMLINK_NOFOLLOW`] selects the final symbolic link itself.
/// Unknown bits return [`Errno::INVAL`].
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
        // SAFETY: the descriptor borrow and `PathArg` keep both arguments live.
        let result = unsafe {
            sys::fchownat(dirfd.as_raw_fd(), path_ptr(path), owner, group, flags.bits().cast_signed())
        };
        errno::check(result).map(|_| ())
    })
}

/// Reads a symbolic-link target relative to `dirfd` into caller-owned storage.
///
/// libSystem returns the initialized target prefix without a NUL byte; a
/// buffer shorter than the target holds a truncated prefix.
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
        // SAFETY: `Buffer` supplies writable storage for exactly `length`
        // bytes; the descriptor borrow and `PathArg` keep the other arguments
        // live.
        let read =
            unsafe { sys::readlinkat(dirfd.as_raw_fd(), path_ptr(path), pointer.cast(), length) };
        errno::check_size(read)
    })?;
    if initialized > length {
        return Err(Errno::IO);
    }
    // SAFETY: a successful `readlinkat` initialized exactly the reported
    // prefix, which the check above keeps within the supplied buffer.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Reads a complete symbolic-link target relative to `dirfd` into owned
/// byte-path storage, growing the buffer until the target fits.
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
            let length = readlinkat_raw(dirfd, path, buffer.spare_capacity_mut())?.0.len();
            if length < capacity {
                // SAFETY: `readlinkat_raw` initialized exactly this prefix of
                // the spare capacity.
                unsafe { buffer.set_len(length) };
                // SAFETY: a symbolic-link target cannot contain NUL.
                return Ok(unsafe { CString::from_vec_unchecked(buffer) });
            }
            buffer.reserve(capacity.saturating_add(1));
        }
    })
}

/// Sets the length of an open file descriptor.
///
/// Values above `i64::MAX` return [`Errno::INVAL`] before the call.
#[inline]
pub fn ftruncate<Fd: AsFd>(fd: Fd, length: u64) -> Result<()> {
    let length = i64::try_from(length).map_err(|_| Errno::INVAL)?;
    // SAFETY: `ftruncate` has no memory arguments; the borrow keeps `fd` open.
    let result = unsafe { sys::ftruncate(fd.as_fd().as_raw_fd(), length) };
    errno::check(result).map(|_| ())
}

/// Sets the length of a pathname-selected file.
///
/// Values above `i64::MAX` return [`Errno::INVAL`] before path conversion.
#[inline]
pub fn truncate<P: PathArg>(path: P, length: u64) -> Result<()> {
    let length = i64::try_from(length).map_err(|_| Errno::INVAL)?;
    path.into_with_c_str(|path| {
        // SAFETY: `PathArg` keeps `path` live for the call.
        let result = unsafe { sys::truncate(path_ptr(path), length) };
        errno::check(result).map(|_| ())
    })
}

/// Calls `utimensat`, where a null `times` sets both timestamps to now.
///
/// # Safety
///
/// `path` must be null or a live NUL-terminated string, and `times` must be
/// null or point at two live [`Timespec`] values.
#[inline]
unsafe fn utimensat_raw(
    dirfd: RawFd,
    path: *const c_char,
    times: *const Timespec,
    flags: c_int,
) -> Result<()> {
    // SAFETY: the caller supplies the pointer contracts; `Timespec` has the
    // layout of `struct timespec`, asserted above.
    let result = unsafe { sys::utimensat(dirfd, path, times.cast(), flags) };
    errno::check(result).map(|_| ())
}

#[inline]
fn convert_timevals(times: Option<&[Timeval; 2]>) -> Result<Option<[Timespec; 2]>> {
    match times {
        None => Ok(None),
        Some(times) => Ok(Some([timeval_to_timespec(times[0])?, timeval_to_timespec(times[1])?])),
    }
}

#[inline]
fn times_ptr(times: &Option<[Timespec; 2]>) -> *const Timespec {
    times.as_ref().map_or(ptr::null(), |times| times.as_ptr())
}

/// Sets access and modification timestamps relative to `dirfd`.
///
/// Only [`TimestampAtFlags::SYMLINK_NOFOLLOW`] is admitted. libSystem
/// validates ordinary nanoseconds and [`UTIME_NOW`]/[`UTIME_OMIT`].
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
        // SAFETY: `path` and `times` stay live for the call, and `Timestamps`
        // is two consecutive `Timespec` values.
        unsafe {
            utimensat_raw(
                dirfd.as_raw_fd(),
                path_ptr(path),
                ptr::from_ref(times).cast(),
                flags.bits().cast_signed(),
            )
        }
    })
}

/// Sets access and modification timestamps on an open file or directory.
#[inline]
pub fn futimens<Fd: AsFd>(fd: Fd, times: &Timestamps) -> Result<()> {
    // SAFETY: `times` is two consecutive `Timespec` values with the layout of
    // `struct timespec`, live for the call.
    let result =
        unsafe { sys::futimens(fd.as_fd().as_raw_fd(), ptr::from_ref(times).cast()) };
    errno::check(result).map(|_| ())
}

/// Sets access and modification times on an open file using microseconds.
///
/// `None` sets both to the current time. Each explicit `tv_usec` must be in
/// `0..1_000_000`; other values return [`Errno::INVAL`] before the call.
#[inline]
pub fn futimes<Fd: AsFd>(fd: Fd, times: Option<&[Timeval; 2]>) -> Result<()> {
    let converted = convert_timevals(times)?;
    // SAFETY: the optional converted pair stays live for the call; null
    // selects the current time.
    let result = unsafe { sys::futimens(fd.as_fd().as_raw_fd(), times_ptr(&converted).cast()) };
    errno::check(result).map(|_| ())
}

/// Sets timestamps for a final symbolic link rather than its target.
///
/// `None` sets both to the current time; explicit values are validated
/// before path conversion.
#[inline]
pub fn lutimes<P: PathArg>(path: P, times: Option<&[Timeval; 2]>) -> Result<()> {
    let converted = convert_timevals(times)?;
    path.into_with_c_str(|path| {
        // SAFETY: the path and optional converted pair stay live for the call.
        unsafe {
            utimensat_raw(
                sys::AT_FDCWD,
                path_ptr(path),
                times_ptr(&converted),
                sys::AT_SYMLINK_NOFOLLOW,
            )
        }
    })
}

/// Sets timestamps for a path relative to `dirfd`, following a final symlink.
///
/// Darwin has no `futimesat`; this is `utimensat` with converted values, as
/// on Linux.
#[inline]
pub fn futimesat<P: PathArg, Fd: AsFd>(
    dirfd: Fd,
    path: P,
    times: Option<&[Timeval; 2]>,
) -> Result<()> {
    let converted = convert_timevals(times)?;
    let dirfd = dirfd.as_fd();
    path.into_with_c_str(|path| {
        // SAFETY: the descriptor borrow, path and optional pair stay live.
        unsafe { utimensat_raw(dirfd.as_raw_fd(), path_ptr(path), times_ptr(&converted), 0) }
    })
}

/// Sets timestamps for a current-directory-relative path, following a final
/// symbolic link.
#[inline]
pub fn utimes<P: PathArg>(path: P, times: Option<&[Timeval; 2]>) -> Result<()> {
    let converted = convert_timevals(times)?;
    path.into_with_c_str(|path| {
        // SAFETY: the path and optional converted pair stay live for the call.
        unsafe { utimensat_raw(sys::AT_FDCWD, path_ptr(path), times_ptr(&converted), 0) }
    })
}

/// Sets timestamps for a current-directory-relative path at whole-second
/// precision, following a final symbolic link.
#[inline]
pub fn utime<P: PathArg>(path: P, times: Option<&Utimbuf>) -> Result<()> {
    let converted = times.map(|times| {
        [
            Timespec { tv_sec: times.actime, tv_nsec: 0 },
            Timespec { tv_sec: times.modtime, tv_nsec: 0 },
        ]
    });
    path.into_with_c_str(|path| {
        // SAFETY: the path and optional converted pair stay live for the call.
        unsafe { utimensat_raw(sys::AT_FDCWD, path_ptr(path), times_ptr(&converted), 0) }
    })
}

/// Repositions an open descriptor with libSystem `lseek`.
///
/// Absolute positions above `i64::MAX` reach libSystem as negative `off_t`
/// values and return its error. `Data` and `Hole` use Darwin's `SEEK_DATA`
/// and `SEEK_HOLE`.
#[inline]
#[doc(alias = "lseek")]
pub fn seek<Fd: AsFd>(fd: Fd, position: SeekFrom) -> Result<u64> {
    let (whence, offset) = match position {
        SeekFrom::Start(offset) => (sys::SEEK_SET, offset.cast_signed()),
        SeekFrom::End(offset) => (sys::SEEK_END, offset),
        SeekFrom::Current(offset) => (sys::SEEK_CUR, offset),
        SeekFrom::Data(offset) => (sys::SEEK_DATA, offset.cast_signed()),
        SeekFrom::Hole(offset) => (sys::SEEK_HOLE, offset.cast_signed()),
    };
    // SAFETY: `lseek` has no memory arguments; the borrow keeps `fd` open.
    let position = unsafe { sys::lseek(fd.as_fd().as_raw_fd(), offset, whence) };
    if position == -1 {
        return Err(errno::last());
    }
    u64::try_from(position).map_err(|_| Errno::IO)
}

/// Returns an open descriptor's current byte position without changing it.
#[inline]
#[doc(alias = "lseek")]
pub fn tell<Fd: AsFd>(fd: Fd) -> Result<u64> {
    seek(fd, SeekFrom::Current(0))
}

/// Flushes file data and metadata for an open descriptor to the storage
/// device with libSystem `fsync`.
///
/// Darwin's `fsync` does not ask the device to flush its own volatile cache;
/// that needs `fcntl(F_FULLFSYNC)`, which this facade does not expose.
#[inline]
pub fn fsync<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `fsync` has no memory arguments; the borrow keeps `fd` open.
    let result = unsafe { sys::fsync(fd.as_fd().as_raw_fd()) };
    errno::check(result).map(|_| ())
}

/// Schedules system-wide filesystem writeback with libSystem `sync`.
///
/// Darwin's `sync` may return before the writes complete.
#[inline]
pub fn sync() {
    sys::sync();
}
