//! Bounded Linux/x86-64 process and record-lock observations.
//!
//! This module intentionally admits only scalar identity queries, the
//! kernel's three-word real/effective/saved credential observations, pidfd
//! creation, read-only scheduling-priority observations and bounds, and the
//! read-only typed `fcntl(F_GETLK)` record-lock query. The larger process
//! facade remains AArch64-only until
//! each of its target-sized records and state transitions has an independent
//! x86-64 contract.

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

/// A Linux nice value returned by the native `getpriority` facade.
///
/// Linux's scheduler accepts values from `-20` through `19`, inclusive. The
/// wrapper keeps that range closed so an arbitrary integer cannot cross this
/// API boundary. This is the normal nice-value representation; it is not the
/// kernel's non-negative `getpriority` wire encoding.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Priority(i32);

impl Priority {
    /// The most favorable Linux nice value.
    pub const MIN: Self = Self(-20);
    /// The least favorable Linux nice value.
    pub const MAX: Self = Self(19);
    /// Linux's default nice value.
    pub const DEFAULT: Self = Self(0);

    /// Converts a Linux nice value into the bounded priority type.
    #[inline]
    pub const fn from_raw(raw: i32) -> Option<Self> {
        if raw >= Self::MIN.0 && raw <= Self::MAX.0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Returns the Linux nice value.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0
    }

    /// Converts Linux's non-negative `getpriority` syscall result.
    ///
    /// This is intentionally separate from [`from_raw`]: the syscall result
    /// is encoded as `20 - nice` to avoid a negative success return, whereas
    /// this facade exposes the ordinary nice value.
    #[inline]
    fn from_kernel_encoded(raw: i32) -> Option<Self> {
        if raw >= 1 && raw <= 40 {
            Self::from_raw(20 - raw)
        } else {
            None
        }
    }
}

/// Which Linux process set `getpriority` should observe.
///
/// `Process(None)` and `ProcessGroup(None)` select the caller's process and
/// process group respectively. `User` transmits Linux's raw user selector:
/// its zero word selects the calling process's effective user, so it does not
/// let a non-root caller name UID zero explicitly. The closed enum prevents
/// unsupported `which` values from crossing the native API boundary.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum PriorityTarget {
    /// `PRIO_PROCESS`, with `None` meaning the calling process.
    Process(Option<Pid>),
    /// `PRIO_PGRP`, with `None` meaning the calling process group.
    ProcessGroup(Option<Pid>),
    /// `PRIO_USER`, selecting all processes for this user. A zero user word
    /// has Linux's current-effective-user shorthand semantics.
    User(Uid),
}

impl PriorityTarget {
    /// `PRIO_PROCESS`.
    pub const PRIO_PROCESS: i32 = 0;
    /// `PRIO_PGRP`.
    pub const PRIO_PGRP: i32 = 1;
    /// `PRIO_USER`.
    pub const PRIO_USER: i32 = 2;

    /// Constructs a process target, where `None` denotes the caller.
    #[inline]
    pub const fn process(pid: Option<Pid>) -> Self {
        Self::Process(pid)
    }

    /// Constructs a process-group target, where `None` denotes the caller's
    /// process group.
    #[inline]
    pub const fn process_group(pgid: Option<Pid>) -> Self {
        Self::ProcessGroup(pgid)
    }

    /// Constructs a raw Linux user target.
    ///
    /// `Uid::ROOT` transmits the zero selector, which Linux interprets as the
    /// calling process's effective user rather than as an explicit root-user
    /// request.
    #[inline]
    pub const fn user(uid: Uid) -> Self {
        Self::User(uid)
    }

    /// Returns the exact `(which, who)` words passed to Linux.
    #[inline]
    pub const fn as_raw(self) -> (i32, u32) {
        match self {
            Self::Process(pid) => (
                Self::PRIO_PROCESS,
                match pid {
                    Some(pid) => pid.as_raw_pid() as u32,
                    None => 0,
                },
            ),
            Self::ProcessGroup(pgid) => (
                Self::PRIO_PGRP,
                match pgid {
                    Some(pgid) => pgid.as_raw_pid() as u32,
                    None => 0,
                },
            ),
            Self::User(uid) => (Self::PRIO_USER, uid.as_raw()),
        }
    }
}

/// A Linux scheduler policy with a stable priority-range query.
///
/// This closed vocabulary deliberately covers only policies whose Linux
/// priority bounds are stable and directly observable here. Scheduler
/// selection and mutation are outside this read-only API.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum SchedulerPolicy {
    /// The normal time-sharing scheduler policy (`SCHED_OTHER`).
    Other = 0,
    /// The first-in, first-out real-time policy (`SCHED_FIFO`).
    Fifo = 1,
    /// The round-robin real-time policy (`SCHED_RR`).
    RoundRobin = 2,
}

impl SchedulerPolicy {
    /// Returns the Linux scheduler policy token.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// The minimum and maximum priority accepted by one Linux scheduler policy.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct SchedulerPriorityBounds {
    minimum: i32,
    maximum: i32,
}

impl SchedulerPriorityBounds {
    /// Returns the lowest priority accepted by the policy.
    #[inline]
    pub const fn minimum(self) -> i32 {
        self.minimum
    }

    /// Returns the highest priority accepted by the policy.
    #[inline]
    pub const fn maximum(self) -> i32 {
        self.maximum
    }
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

/// Reads the accepted priority bounds for one Linux scheduler policy.
///
/// This is a read-only direct-kernel observation. Linux errors remain
/// ordinary [`crate::Errno`] results. The facade also rejects an inverted
/// kernel record as [`crate::Errno::RANGE`] rather than exposing an impossible
/// range.
#[inline]
pub fn scheduler_priority_bounds(policy: SchedulerPolicy) -> Result<SchedulerPriorityBounds> {
    let (minimum, maximum) = crabc_core::process::scheduler_priority_bounds_raw(policy.as_raw())?;
    if minimum > maximum {
        return Err(crate::Errno::RANGE);
    }
    Ok(SchedulerPriorityBounds { minimum, maximum })
}

/// Reads the bounded Linux nice value for a process, process group, or user.
///
/// This is a read-only direct-kernel query. Linux's raw syscall returns the
/// inverted non-negative encoding `20 - nice` (the range `[1, 40]`) so that a
/// successful result cannot be confused with a negative errno. This facade
/// performs the kernel conversion and returns the ordinary nice value in
/// [`Priority`]. No C ABI, thread-local `errno`, or C `-1` sentinel is
/// involved.
#[inline]
pub fn getpriority(target: PriorityTarget) -> Result<Priority> {
    let (which, who) = target.as_raw();
    let encoded = crabc_core::process::getpriority_raw(which, who)?;
    // Linux documents successful getpriority results as [1, 40]. Treat a
    // violation as an impossible kernel contract rather than inventing an
    // errno or silently applying libc's sentinel convention.
    Priority::from_kernel_encoded(encoded).ok_or(crate::Errno::RANGE)
}

/// Reads `PRIO_PROCESS` for an optional process identifier.
#[inline]
pub fn getpriority_process(pid: Option<Pid>) -> Result<Priority> {
    getpriority(PriorityTarget::Process(pid))
}

/// Reads `PRIO_PGRP` for an optional process-group identifier.
#[inline]
pub fn getpriority_process_group(pgid: Option<Pid>) -> Result<Priority> {
    getpriority(PriorityTarget::ProcessGroup(pgid))
}

/// Reads `PRIO_USER` for a raw Linux user selector.
///
/// Passing [`Uid::ROOT`] transmits zero and therefore observes the calling
/// process's effective user under Linux's `PRIO_USER` shorthand semantics.
#[inline]
pub fn getpriority_user(uid: Uid) -> Result<Priority> {
    getpriority(PriorityTarget::User(uid))
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
    use super::{Flock, FlockOffsetType, FlockType, KernelFlock, Pid, Priority};

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

    #[test]
    fn x86_64_priority_decodes_only_the_kernel_success_range() {
        assert_eq!(Priority::from_kernel_encoded(1).map(Priority::as_raw), Some(19));
        assert_eq!(Priority::from_kernel_encoded(20).map(Priority::as_raw), Some(0));
        assert_eq!(Priority::from_kernel_encoded(40).map(Priority::as_raw), Some(-20));
        assert_eq!(Priority::from_kernel_encoded(0), None);
        assert_eq!(Priority::from_kernel_encoded(41), None);
    }
}
