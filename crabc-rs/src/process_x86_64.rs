//! Bounded Linux/x86-64 process-identity observations.
//!
//! This module intentionally admits only scalar identity queries, the
//! kernel's three-word real/effective/saved credential observations, and
//! pidfd creation. The larger process facade remains AArch64-only until each
//! of its target-sized records and state transitions has an independent
//! x86-64 contract.

use bitflags::bitflags;

use crate::{OwnedFd, Result};

/// A raw Linux/x86-64 `pid_t` representation.
pub type RawPid = i32;

/// A raw Linux/x86-64 `uid_t` representation.
pub type RawUid = u32;

/// A raw Linux/x86-64 `gid_t` representation.
pub type RawGid = u32;

/// A non-zero Linux process or thread identifier.
pub use crate::signal::Pid;

bitflags! {
    /// Flags accepted by Linux `pidfd_open`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct PidfdFlags: u32 {
        /// Make operations on the returned pidfd nonblocking.
        const NONBLOCK = 0x0000_0800;
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// An opaque Linux user identifier.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Uid(RawUid);

impl Uid {
    /// The Linux root user identifier.
    pub const ROOT: Self = Self(0);

    /// Wraps an exact Linux x86-64 `uid_t` value.
    #[inline]
    pub const fn from_raw(raw: RawUid) -> Self {
        Self(raw)
    }

    /// Returns the exact Linux x86-64 `uid_t` value.
    #[inline]
    pub const fn as_raw(self) -> RawUid {
        self.0
    }

    /// Returns whether this identifier is the root user.
    #[inline]
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }
}

/// An opaque Linux group identifier.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Gid(RawGid);

impl Gid {
    /// The Linux root group identifier.
    pub const ROOT: Self = Self(0);

    /// Wraps an exact Linux x86-64 `gid_t` value.
    #[inline]
    pub const fn from_raw(raw: RawGid) -> Self {
        Self(raw)
    }

    /// Returns the exact Linux x86-64 `gid_t` value.
    #[inline]
    pub const fn as_raw(self) -> RawGid {
        self.0
    }

    /// Returns whether this identifier is the root group.
    #[inline]
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }
}

/// The calling process's real, effective, and saved user IDs.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UidTriple {
    /// The real user ID.
    pub real: Uid,
    /// The effective user ID.
    pub effective: Uid,
    /// The saved-set user ID.
    pub saved: Uid,
}

/// The calling process's real, effective, and saved group IDs.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GidTriple {
    /// The real group ID.
    pub real: Gid,
    /// The effective group ID.
    pub effective: Gid,
    /// The saved-set group ID.
    pub saved: Gid,
}

/// Returns the caller's process ID.
#[inline]
#[must_use]
pub fn getpid() -> Pid {
    // SAFETY: Linux returns a positive process ID for a running task.
    unsafe { Pid::from_raw_unchecked(crabc_core::process::getpid()) }
}

/// Returns the caller's parent process ID, if one is visible in this PID
/// namespace.
#[inline]
#[must_use]
pub fn getppid() -> Option<Pid> {
    Pid::from_raw(crabc_core::process::getppid())
}

/// Opens a stable Linux process descriptor for `pid`.
///
/// The returned [`OwnedFd`] remains valid across PID reuse and closes through
/// the native descriptor owner. Linux's target-lifetime, permission, and
/// unsupported-flag errors are returned directly; this operation does not
/// call libc or inspect thread-local `errno`.
#[inline]
pub fn pidfd_open(pid: Pid, flags: PidfdFlags) -> Result<OwnedFd> {
    let fd = crabc_core::process::pidfd_open_raw(pid.as_raw_pid(), flags.bits())?;
    // SAFETY: successful Linux pidfd_open returns one fresh, non-negative
    // descriptor whose ownership transfers to this value.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Returns the caller's real Linux user ID.
#[inline]
#[must_use]
pub fn getuid() -> Uid {
    Uid::from_raw(crabc_core::process::getuid())
}

/// Returns the caller's effective Linux user ID.
#[inline]
#[must_use]
pub fn geteuid() -> Uid {
    Uid::from_raw(crabc_core::process::geteuid())
}

/// Returns the caller's real Linux group ID.
#[inline]
#[must_use]
pub fn getgid() -> Gid {
    Gid::from_raw(crabc_core::process::getgid())
}

/// Returns the caller's effective Linux group ID.
#[inline]
#[must_use]
pub fn getegid() -> Gid {
    Gid::from_raw(crabc_core::process::getegid())
}

/// Reads the calling process's real, effective, and saved user IDs.
#[inline]
pub fn getresuid() -> crate::Result<UidTriple> {
    crabc_core::process::getresuid_raw().map(|ids| UidTriple {
        real: Uid::from_raw(ids.real),
        effective: Uid::from_raw(ids.effective),
        saved: Uid::from_raw(ids.saved),
    })
}

/// Reads the calling process's real, effective, and saved group IDs.
#[inline]
pub fn getresgid() -> crate::Result<GidTriple> {
    crabc_core::process::getresgid_raw().map(|ids| GidTriple {
        real: Gid::from_raw(ids.real),
        effective: Gid::from_raw(ids.effective),
        saved: Gid::from_raw(ids.saved),
    })
}

/// Returns a process group ID. `None` selects the calling process.
#[inline]
pub fn getpgid(pid: Option<Pid>) -> crate::Result<Pid> {
    crabc_core::process::getpgid(pid.map_or(0, Pid::as_raw_pid)).map(|raw| {
        // Linux returns a positive process ID for every successful process
        // group observation.
        unsafe { Pid::from_raw_unchecked(raw) }
    })
}

/// Returns the calling process's process group ID.
#[inline]
#[must_use]
pub fn getpgrp() -> Pid {
    match crabc_core::process::getpgid(0) {
        // Linux returns a positive process ID for a live calling process.
        Ok(raw) => unsafe { Pid::from_raw_unchecked(raw) },
        Err(_) => panic!("Linux getpgid(0) syscall failed"),
    }
}

/// Returns a session ID. `None` selects the calling process.
#[inline]
pub fn getsid(pid: Option<Pid>) -> crate::Result<Pid> {
    crabc_core::process::getsid(pid.map_or(0, Pid::as_raw_pid)).map(|raw| {
        // Linux returns a positive process ID for every successful session
        // observation.
        unsafe { Pid::from_raw_unchecked(raw) }
    })
}

const _: () = assert!(core::mem::size_of::<Uid>() == 4);
const _: () = assert!(core::mem::align_of::<Uid>() == 4);
const _: () = assert!(core::mem::size_of::<Gid>() == 4);
const _: () = assert!(core::mem::align_of::<Gid>() == 4);
const _: () = assert!(core::mem::size_of::<Pid>() == 4);
const _: () = assert!(core::mem::align_of::<Pid>() == 4);
