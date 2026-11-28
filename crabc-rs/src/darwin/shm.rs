//! Darwin POSIX shared-memory objects over libSystem `shm_open`.
//!
//! The facade module [`crate::shm`] re-exports these operations next to the
//! name vocabulary both targets share.

use super::errno::{self, Result};
use super::sys;
use crate::fs::{Mode, OFlags};
use crate::shm::NameArg;
use crate::OwnedFd;

/// Opens a POSIX shared-memory object with libSystem `shm_open`.
///
/// All leading slashes are ignored and the rest of the name is passed as
/// `/<name>`; it cannot be empty, `.`, `..`, contain `/`, or exceed 30
/// bytes, as Darwin limits the whole name to `PSHMNAMLEN` (31) bytes.
///
/// XNU sets close-on-exec on every descriptor `shm_open` returns, as POSIX
/// requires, and rejects an explicit `O_CLOEXEC` with
/// [`crate::Errno::INVAL`], so [`OFlags::CLOEXEC`] is removed from `flags`
/// and the rest are passed through. `shm_open` accepts only
/// [`OFlags::RDONLY`], [`OFlags::RDWR`], [`OFlags::CREATE`] and
/// [`OFlags::EXCL`]; any other flag fails with [`crate::Errno::INVAL`].
#[inline]
pub fn open<P: NameArg>(name: P, flags: OFlags, mode: Mode) -> Result<OwnedFd> {
    let flags = flags.difference(OFlags::CLOEXEC).bits().cast_signed();
    let mode = (mode.bits() & 0xffff).cast_signed();
    name.into_with_shm_name(|name| {
        // SAFETY: `name` is a live NUL-terminated string for the call, and
        // the variadic mode is the `int` that `shm_open` reads with
        // `O_CREAT`.
        let raw = unsafe { sys::shm_open(name.as_ptr(), flags, mode) };
        let raw = errno::check(raw)?;
        // SAFETY: a successful `shm_open` returns a new open descriptor whose
        // ownership transfers to this owner.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    })
}

/// Unlinks a POSIX shared-memory object with libSystem `shm_unlink`.
///
/// Existing descriptors and mappings of the object stay usable until they
/// are closed or unmapped.
#[inline]
pub fn unlink<P: NameArg>(name: P) -> Result<()> {
    name.into_with_shm_name(|name| {
        // SAFETY: `name` is a live NUL-terminated string for the call.
        errno::check(unsafe { sys::shm_unlink(name.as_ptr()) }).map(|_| ())
    })
}
