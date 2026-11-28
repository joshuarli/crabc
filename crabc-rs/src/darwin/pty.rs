//! Darwin pseudoterminal operations over libSystem.
//!
//! The facade module [`crate::pty`] re-exports these items next to the
//! vocabulary both targets share.

#[cfg(feature = "alloc")]
use alloc::{ffi::CString, vec::Vec};
use core::ffi::{c_int, CStr};
use core::mem::MaybeUninit;

use super::errno::{self, Result};
use super::sys;
use crate::{AsFd, BorrowedFd, OwnedFd};

bitflags::bitflags! {
    /// Darwin `O_*` flags accepted by [`openpt`] and [`crate::pty::PtyPair::open`].
    ///
    /// The pair constructor requires [`Self::RDWR`]. `NOCTTY` and `CLOEXEC`
    /// are passed to the master as requested; its internal slave open always
    /// includes `NOCTTY` so constructing a pair cannot acquire a controlling
    /// terminal as a side effect.
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct OpenptFlags: u32 {
        /// `O_RDWR`.
        const RDWR = sys::O_RDWR.cast_unsigned();
        /// `O_NOCTTY`.
        const NOCTTY = sys::O_NOCTTY.cast_unsigned();
        /// `O_CLOEXEC`.
        const CLOEXEC = sys::O_CLOEXEC.cast_unsigned();
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

/// Opens a new pseudoterminal master with libSystem `posix_openpt`.
///
/// `posix_openpt` opens the `/dev/ptmx` clone device with `flags`, so
/// [`OpenptFlags::CLOEXEC`] sets close-on-exec atomically.
#[inline]
pub fn openpt(flags: OpenptFlags) -> Result<OwnedFd> {
    let raw = errno::check(sys::posix_openpt(flags.bits().cast_signed()))?;
    // SAFETY: a successful `posix_openpt` returns a new open descriptor whose
    // ownership transfers to this owner.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Grants access to the slave side of a pseudoterminal with libSystem
/// `grantpt`.
#[inline]
pub fn grantpt<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `grantpt` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    errno::check(unsafe { sys::grantpt(fd.as_fd().as_raw_fd()) }).map(|_| ())
}

/// Unlocks the slave side of a pseudoterminal with libSystem `unlockpt`.
#[inline]
pub fn unlockpt<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `unlockpt` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    errno::check(unsafe { sys::unlockpt(fd.as_fd().as_raw_fd()) }).map(|_| ())
}

/// Returns the slave device name into caller-provided uninitialized storage.
///
/// The returned [`CStr`] borrows `buffer`, includes its trailing NUL, and is
/// the name libSystem `ptsname_r` reports for the master, such as
/// `/dev/ttys004`. A short buffer returns [`crate::Errno::RANGE`] without
/// partial-name success.
#[inline]
pub fn ptsname_into<'buffer, Fd: AsFd>(
    fd: Fd,
    buffer: &'buffer mut [MaybeUninit<u8>],
) -> Result<&'buffer CStr> {
    // SAFETY: `buffer` is writable for its whole length, which is the bound
    // passed to `ptsname_r`.
    let result = unsafe {
        sys::ptsname_r(fd.as_fd().as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len())
    };
    errno::check(result)?;
    // SAFETY: a successful `ptsname_r` copied a NUL-terminated name into
    // `buffer`, so every byte up to that NUL is initialized, and the name
    // borrows `buffer` for the returned lifetime.
    Ok(unsafe { CStr::from_ptr(buffer.as_ptr().cast()) })
}

/// `ptsname_r(fd)` with an owned result.
///
/// The supplied vector is cleared and reused when possible. Unlike the C
/// static-buffer `ptsname` ABI, the returned [`CString`] owns its bytes and
/// can outlive the descriptor borrow.
#[cfg(feature = "alloc")]
#[inline]
pub fn ptsname<Fd: AsFd, B: Into<Vec<u8>>>(fd: Fd, reuse: B) -> Result<CString> {
    let mut path = reuse.into();
    path.clear();
    path.reserve(sys::PTY_NAME_CAPACITY);
    let length = ptsname_into(fd, path.spare_capacity_mut())?.count_bytes();
    // SAFETY: `ptsname_into` initialized `length` name bytes and their NUL in
    // the vector's spare capacity.
    unsafe { path.set_len(length + 1) };
    // SAFETY: the name has exactly one final NUL and no interior NUL.
    Ok(unsafe { CString::from_vec_with_nul_unchecked(path) })
}

/// Opens the slave of `master` by its `ptsname_r` name with `flags`.
///
/// Darwin has no `TIOCGPTPEER`. The name stays bound to this slave while the
/// caller holds `master` open.
#[inline]
pub(crate) fn open_slave(master: BorrowedFd<'_>, flags: OpenptFlags) -> Result<OwnedFd> {
    let mut name = [MaybeUninit::<u8>::uninit(); sys::PTY_NAME_CAPACITY];
    let name = ptsname_into(master, &mut name)?;
    crate::fs::open(name, flags.into(), crate::fs::Mode::empty())
}

/// Makes `slave` the calling process's controlling terminal with `TIOCSCTTY`.
///
/// # Safety
///
/// The caller must be a session leader without a controlling terminal, keep
/// `slave` open for the call, and serialize the transition with every other
/// session, process-group and terminal-state operation in the process.
#[inline]
pub(crate) unsafe fn set_controlling_terminal(slave: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: `TIOCSCTTY` takes no argument and touches no caller memory; the
    // caller upholds the process-state obligations.
    let result: c_int = unsafe { sys::ioctl(slave.as_raw_fd(), sys::TIOCSCTTY) };
    errno::check(result).map(|_| ())
}
