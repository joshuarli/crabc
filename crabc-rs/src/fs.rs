//! Direct Linux/AArch64 filesystem operations.
//!
//! The first vertical slice intentionally contains just the stateless `openat`
//! operation. It exercises path, descriptor, flag, mode, ownership, and typed
//! error contracts without crossing into libc's process-global runtime state.

use bitflags::bitflags;

use crate::{path::Arg, AsFd, BorrowedFd, OwnedFd, Result};

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
        /// `O_DIRECTORY` in crabc's pinned Linux/AArch64 headers.
        const DIRECTORY = 0x0000_4000;
        /// `O_NOFOLLOW` in crabc's pinned Linux/AArch64 headers.
        const NOFOLLOW = 0x0004_0000;
        /// `O_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
        /// `O_SYNC`/`O_FSYNC`/`O_RSYNC`.
        const SYNC = 0x0010_1000;
        /// Preserve future kernel-defined bits.
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
        /// Preserve future Linux mode bits.
        const _ = !0;
    }
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
