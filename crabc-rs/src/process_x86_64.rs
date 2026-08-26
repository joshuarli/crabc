//! Bounded Linux/x86-64 process and record-lock observations.
//!
//! This module intentionally admits only scalar identity queries, the
//! kernel's three-word real/effective/saved credential observations, pidfd
//! creation, and the read-only typed `fcntl(F_GETLK)` record-lock query. The
//! larger process facade remains AArch64-only until each of its target-sized
//! records and state transitions has an independent x86-64 contract.

use bitflags::bitflags;

use crate::{AsFd, OwnedFd, Result};

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

// Linux/x86-64 `struct flock` has the same field order and 32-byte record
// shape as the AArch64 ABI. Keep this wire record private to the facade and
// validate every field before returning it to a safe caller.
type KernelFlock = crabc_core::process::KernelFlock;

/// A process-associated record-lock query in Linux's `fcntl(F_GETLK)` ABI.
///
/// `start` and `length` are non-negative byte offsets. A zero `length` asks
/// Linux to consider the range through the current end of file. `pid` is
/// meaningful in a returned conflicting lock and is ignored for the input
/// query.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Flock {
    /// Starting byte offset.
    pub start: u64,
    /// Number of bytes in the lock range.
    pub length: u64,
    /// Process holding a returned conflicting lock, if reported by Linux.
    pub pid: Option<Pid>,
    /// Requested or observed lock kind.
    pub typ: FlockType,
    /// Requested or observed offset origin.
    pub offset_type: FlockOffsetType,
}

/// Lock kind used by [`fcntl_getlk`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i16)]
pub enum FlockType {
    /// A shared/read lock.
    ReadLock = 0,
    /// An exclusive/write lock.
    WriteLock = 1,
    /// No lock would block the query; valid only in a returned record.
    Unlocked = 2,
}

/// Byte-offset origin used by [`fcntl_getlk`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i16)]
pub enum FlockOffsetType {
    /// Offset from the beginning of the file.
    Set = 0,
    /// Offset from the current file position.
    Current = 1,
    /// Offset from the end of the file.
    End = 2,
}

impl From<FlockType> for Flock {
    #[inline]
    fn from(typ: FlockType) -> Self {
        Self {
            start: 0,
            length: 0,
            pid: None,
            typ,
            offset_type: FlockOffsetType::Set,
        }
    }
}

impl Flock {
    #[inline]
    fn into_kernel(self) -> Result<KernelFlock> {
        if self.start > i64::MAX as u64 || self.length > i64::MAX as u64 {
            return Err(crate::Errno::RANGE);
        }
        let l_type = match self.typ {
            FlockType::ReadLock => FlockType::ReadLock as i16,
            FlockType::WriteLock => FlockType::WriteLock as i16,
            // Linux documents an unlocked input as undefined for F_GETLK;
            // reject it rather than sending an ambiguous wire record.
            FlockType::Unlocked => return Err(crate::Errno::INVAL),
        };
        Ok(KernelFlock {
            l_type,
            l_whence: self.offset_type as i16,
            l_start: self.start as i64,
            l_len: self.length as i64,
            l_pid: self.pid.map_or(0, Pid::as_raw_pid),
        })
    }

    #[inline]
    fn from_kernel(lock: KernelFlock) -> Result<Option<Self>> {
        let typ = match lock.l_type {
            2 => return Ok(None),
            0 => FlockType::ReadLock,
            1 => FlockType::WriteLock,
            _ => return Err(crate::Errno::RANGE),
        };
        let offset_type = match lock.l_whence {
            0 => FlockOffsetType::Set,
            1 => FlockOffsetType::Current,
            2 => FlockOffsetType::End,
            _ => return Err(crate::Errno::RANGE),
        };
        if lock.l_start < 0 || lock.l_len < 0 || lock.l_pid < 0 {
            return Err(crate::Errno::RANGE);
        }
        let pid = if lock.l_pid == 0 {
            None
        } else {
            // SAFETY: the range check above proves this raw PID is positive.
            Some(unsafe { Pid::from_raw_unchecked(lock.l_pid) })
        };
        Ok(Some(Self {
            start: lock.l_start as u64,
            length: lock.l_len as u64,
            pid,
            typ,
            offset_type,
        }))
    }
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

/// Queries the first process-associated record lock that would block `lock`.
///
/// Linux returns `None` when no lock would block, or the first conflicting
/// lock as a typed [`Flock`]. The input must be a read or write lock; an
/// [`FlockType::Unlocked`] input is rejected because Linux leaves that input
/// form undefined. Integer offsets, enum values, and returned PIDs are
/// checked before crossing this safe facade. The query is read-only and uses
/// direct Linux `fcntl(F_GETLK)` without libc or TLS `errno`.
#[inline]
pub fn fcntl_getlk<Fd: AsFd>(fd: Fd, lock: &Flock) -> Result<Option<Flock>> {
    let mut kernel_lock = (*lock).into_kernel()?;
    crabc_core::process::fcntl_getlk_raw(fd.as_fd().as_raw_fd(), &mut kernel_lock)?;
    Flock::from_kernel(kernel_lock)
}

const _: () = assert!(core::mem::size_of::<Uid>() == 4);
const _: () = assert!(core::mem::align_of::<Uid>() == 4);
const _: () = assert!(core::mem::size_of::<Gid>() == 4);
const _: () = assert!(core::mem::align_of::<Gid>() == 4);
const _: () = assert!(core::mem::size_of::<Pid>() == 4);
const _: () = assert!(core::mem::align_of::<Pid>() == 4);

#[cfg(test)]
mod tests {
    use super::{Flock, FlockOffsetType, FlockType, KernelFlock, Pid};

    #[test]
    fn x86_64_flock_conversion_preserves_a_conflicting_lock_record() {
        let raw = KernelFlock {
            l_type: FlockType::WriteLock as i16,
            l_whence: FlockOffsetType::End as i16,
            l_start: 12,
            l_len: 34,
            l_pid: 56,
        };
        let expected = Flock {
            start: 12,
            length: 34,
            // SAFETY: the synthetic raw kernel PID is positive.
            pid: Some(unsafe { Pid::from_raw_unchecked(56) }),
            typ: FlockType::WriteLock,
            offset_type: FlockOffsetType::End,
        };

        assert_eq!(Flock::from_kernel(raw), Ok(Some(expected)));
        assert_eq!(
            Flock::from_kernel(KernelFlock { l_type: FlockType::Unlocked as i16, ..raw }),
            Ok(None),
        );
    }
}
