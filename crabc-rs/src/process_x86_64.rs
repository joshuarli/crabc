//! Bounded Linux/x86-64 process and record-lock observations.
//!
//! This module intentionally admits only scalar identity queries, the
//! kernel's three-word real/effective/saved credential observations, pidfd
//! creation, read-only resource-limit and resource-usage observations,
//! read-only scheduling-priority observations and bounds, and the read-only
//! typed `fcntl(F_GETLK)` record-lock query. The larger process facade remains
//! AArch64-only until each of its target-sized records and state transitions
//! has an independent x86-64 contract.

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

/// A Linux resource whose current and maximum limits can be queried.
///
/// This closed vocabulary matches the `RLIMIT_*` selectors in the pinned
/// Linux/musl x86-64 headers. There is no raw selector constructor, so an
/// unknown or future resource number cannot cross this facade boundary.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Resource {
    /// `RLIMIT_CPU`.
    Cpu = 0,
    /// `RLIMIT_FSIZE`.
    Fsize = 1,
    /// `RLIMIT_DATA`.
    Data = 2,
    /// `RLIMIT_STACK`.
    Stack = 3,
    /// `RLIMIT_CORE`.
    Core = 4,
    /// `RLIMIT_RSS`.
    Rss = 5,
    /// `RLIMIT_NPROC`.
    Nproc = 6,
    /// `RLIMIT_NOFILE`.
    Nofile = 7,
    /// `RLIMIT_MEMLOCK`.
    Memlock = 8,
    /// `RLIMIT_AS`.
    As = 9,
    /// `RLIMIT_LOCKS`.
    Locks = 10,
    /// `RLIMIT_SIGPENDING`.
    Sigpending = 11,
    /// `RLIMIT_MSGQUEUE`.
    Msgqueue = 12,
    /// `RLIMIT_NICE`.
    Nice = 13,
    /// `RLIMIT_RTPRIO`.
    Rtprio = 14,
    /// `RLIMIT_RTTIME`.
    Rttime = 15,
}

impl Resource {
    /// Returns the exact Linux resource selector used by `prlimit64`.
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

/// Current and maximum values for one Linux process resource.
///
/// Linux's `RLIM_INFINITY` is represented as `None`; every finite kernel
/// value is preserved exactly. This type is returned only by read-only
/// queries in the staged x86-64 facade.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Rlimit {
    /// Soft/current limit. `None` means unlimited.
    pub current: Option<u64>,
    /// Hard/maximum limit. `None` means unlimited.
    pub maximum: Option<u64>,
}

impl Rlimit {
    #[inline]
    fn from_kernel(limit: crabc_core::process::KernelRlimit64) -> Self {
        Self {
            current: (limit.rlim_cur != u64::MAX).then_some(limit.rlim_cur),
            maximum: (limit.rlim_max != u64::MAX).then_some(limit.rlim_max),
        }
    }
}

/// Which calling-task resource usage Linux should observe.
///
/// `SelfProcess` is the calling process, `Children` is terminated and waited
/// children of that process, and `Thread` is the calling thread. These are
/// the three selectors exposed by the pinned musl x86-64 `sys/resource.h`;
/// arbitrary future kernel selector values cannot cross this native boundary.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ResourceUsageTarget {
    /// `RUSAGE_SELF`, the calling process.
    SelfProcess = 0,
    /// `RUSAGE_CHILDREN`, terminated and waited children.
    Children = -1,
    /// `RUSAGE_THREAD`, the calling thread.
    Thread = 1,
}

impl ResourceUsageTarget {
    /// Returns the Linux `RUSAGE_*` selector.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// One CPU-time value returned by Linux `getrusage`.
///
/// The x86-64 Linux ABI is LP64, so the kernel's timeval record contains two
/// signed 64-bit words. The fields retain that signed representation rather
/// than converting through a C `timeval` or a potentially lossy `Duration`.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResourceUsageTime {
    seconds: i64,
    microseconds: i64,
}

impl ResourceUsageTime {
    #[inline]
    fn from_kernel(value: crabc_core::process::KernelRusageTimeval) -> Self {
        Self {
            seconds: value.tv_sec,
            microseconds: value.tv_usec,
        }
    }

    /// Whole seconds of CPU time.
    #[inline]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Microseconds within the CPU-time second.
    #[inline]
    pub const fn microseconds(self) -> i64 {
        self.microseconds
    }
}

/// Read-only Linux resource-usage observations.
///
/// The fourteen counters are copied exactly from Linux's signed 64-bit
/// `long` fields. `maximum_resident_set_size` is measured in KiB on Linux;
/// the historical integral-memory, swap, IPC, and signal fields are retained
/// as kernel observations even though contemporary Linux normally reports
/// zero for them. No reserved words from musl's larger public C struct are
/// exposed: the kernel leaves that compatibility tail uninitialized.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResourceUsage {
    /// User CPU time consumed by the selected target.
    pub user_time: ResourceUsageTime,
    /// System CPU time consumed by the selected target.
    pub system_time: ResourceUsageTime,
    /// Maximum resident-set size, in KiB on Linux.
    pub maximum_resident_set_size: i64,
    /// Integral shared-memory size (historical Linux field).
    pub integral_shared_memory_size: i64,
    /// Integral unshared-data size (historical Linux field).
    pub integral_unshared_data_size: i64,
    /// Integral unshared-stack size (historical Linux field).
    pub integral_unshared_stack_size: i64,
    /// Number of minor page faults.
    pub minor_page_faults: i64,
    /// Number of major page faults.
    pub major_page_faults: i64,
    /// Number of swaps (historical Linux field).
    pub swaps: i64,
    /// Block input operations.
    pub block_input_operations: i64,
    /// Block output operations.
    pub block_output_operations: i64,
    /// IPC messages sent (historical Linux field).
    pub ipc_messages_sent: i64,
    /// IPC messages received (historical Linux field).
    pub ipc_messages_received: i64,
    /// Signals received (historical Linux field).
    pub signals_received: i64,
    /// Voluntary context switches.
    pub voluntary_context_switches: i64,
    /// Involuntary context switches.
    pub involuntary_context_switches: i64,
}

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

/// Reads the calling process's current and maximum resource limits through
/// Linux `prlimit64` without using libc, a public C ABI, or TLS `errno`.
///
/// This operation is strictly read-only: it selects PID zero, passes a null
/// new-limit pointer, and preserves the complete initialized `rlimit64`
/// result. Linux's `RLIM_INFINITY` is represented as `None` in the returned
/// [`Rlimit`].
#[inline]
pub fn getrlimit(resource: Resource) -> Result<Rlimit> {
    crabc_core::process::getrlimit_raw(resource.as_raw()).map(Rlimit::from_kernel)
}

/// Reads a target process's resource limits through Linux `prlimit64` without
/// using libc, a public C ABI, or TLS `errno`.
///
/// `None` selects the calling process; `Some(pid)` selects that Linux process.
/// This query preserves target-lifetime, permission, and invalid-target
/// errors as ordinary [`crate::Errno`] values and performs no mutation.
#[inline]
pub fn getrlimit_for(pid: Option<Pid>, resource: Resource) -> Result<Rlimit> {
    let pid = pid.map_or(0, Pid::as_raw_pid);
    crabc_core::process::getrlimit_for_raw(pid, resource.as_raw()).map(Rlimit::from_kernel)
}

/// Reads a calling-task resource-usage record through Linux's native
/// `getrusage` syscall.
///
/// This is a read-only direct-kernel query. It does not call the public C ABI,
/// inspect TLS `errno`, or expose musl's caller-provided `struct rusage`
/// storage. Linux's initialized 144-byte x86-64 record is copied into the
/// typed [`ResourceUsage`] value; musl's uninitialized reserved tail is
/// omitted.
#[inline]
pub fn getrusage(target: ResourceUsageTarget) -> Result<ResourceUsage> {
    crabc_core::process::getrusage_raw(target.as_raw()).map(ResourceUsage::from)
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
const _: () = assert!(core::mem::size_of::<crabc_core::process::KernelRlimit64>() == 16);
const _: () = assert!(core::mem::align_of::<crabc_core::process::KernelRlimit64>() == 8);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRlimit64, rlim_cur) == 0);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRlimit64, rlim_max) == 8);
const _: () = assert!(core::mem::size_of::<crabc_core::process::KernelRusageTimeval>() == 16);
const _: () = assert!(core::mem::align_of::<crabc_core::process::KernelRusageTimeval>() == 8);
const _: () = assert!(core::mem::size_of::<crabc_core::process::KernelRusage>() == 144);
const _: () = assert!(core::mem::align_of::<crabc_core::process::KernelRusage>() == 8);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_utime) == 0);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_stime) == 16);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_maxrss) == 32);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_nivcsw) == 136);

impl From<crabc_core::process::KernelRusage> for ResourceUsage {
    #[inline]
    fn from(value: crabc_core::process::KernelRusage) -> Self {
        Self {
            user_time: ResourceUsageTime::from_kernel(value.ru_utime),
            system_time: ResourceUsageTime::from_kernel(value.ru_stime),
            maximum_resident_set_size: value.ru_maxrss,
            integral_shared_memory_size: value.ru_ixrss,
            integral_unshared_data_size: value.ru_idrss,
            integral_unshared_stack_size: value.ru_isrss,
            minor_page_faults: value.ru_minflt,
            major_page_faults: value.ru_majflt,
            swaps: value.ru_nswap,
            block_input_operations: value.ru_inblock,
            block_output_operations: value.ru_oublock,
            ipc_messages_sent: value.ru_msgsnd,
            ipc_messages_received: value.ru_msgrcv,
            signals_received: value.ru_nsignals,
            voluntary_context_switches: value.ru_nvcsw,
            involuntary_context_switches: value.ru_nivcsw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Flock, FlockOffsetType, FlockType, KernelFlock, Pid, Priority, Resource, ResourceUsage,
        ResourceUsageTarget, Rlimit,
    };

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

    #[test]
    fn x86_64_rlimit_maps_kernel_infinity_without_loss() {
        let finite = Rlimit::from_kernel(crabc_core::process::KernelRlimit64 {
            rlim_cur: 7,
            rlim_max: 11,
        });
        assert_eq!(finite.current, Some(7));
        assert_eq!(finite.maximum, Some(11));

        let unlimited = Rlimit::from_kernel(crabc_core::process::KernelRlimit64 {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        });
        assert_eq!(unlimited.current, None);
        assert_eq!(unlimited.maximum, None);

        assert_eq!(Resource::Nofile.as_raw(), 7);
        assert_eq!(Resource::Rttime.as_raw(), 15);
    }

    #[test]
    fn x86_64_rusage_maps_the_initialized_kernel_record() {
        let value = crabc_core::process::KernelRusage {
            ru_utime: crabc_core::process::KernelRusageTimeval { tv_sec: 1, tv_usec: 2 },
            ru_stime: crabc_core::process::KernelRusageTimeval { tv_sec: 3, tv_usec: 4 },
            ru_maxrss: 5,
            ru_ixrss: 6,
            ru_idrss: 7,
            ru_isrss: 8,
            ru_minflt: 9,
            ru_majflt: 10,
            ru_nswap: 11,
            ru_inblock: 12,
            ru_oublock: 13,
            ru_msgsnd: 14,
            ru_msgrcv: 15,
            ru_nsignals: 16,
            ru_nvcsw: 17,
            ru_nivcsw: 18,
        };
        let usage = ResourceUsage::from(value);

        assert_eq!(usage.user_time.seconds(), 1);
        assert_eq!(usage.user_time.microseconds(), 2);
        assert_eq!(usage.system_time.seconds(), 3);
        assert_eq!(usage.system_time.microseconds(), 4);
        assert_eq!(usage.maximum_resident_set_size, 5);
        assert_eq!(usage.integral_shared_memory_size, 6);
        assert_eq!(usage.integral_unshared_data_size, 7);
        assert_eq!(usage.integral_unshared_stack_size, 8);
        assert_eq!(usage.minor_page_faults, 9);
        assert_eq!(usage.major_page_faults, 10);
        assert_eq!(usage.swaps, 11);
        assert_eq!(usage.block_input_operations, 12);
        assert_eq!(usage.block_output_operations, 13);
        assert_eq!(usage.ipc_messages_sent, 14);
        assert_eq!(usage.ipc_messages_received, 15);
        assert_eq!(usage.signals_received, 16);
        assert_eq!(usage.voluntary_context_switches, 17);
        assert_eq!(usage.involuntary_context_switches, 18);
        assert_eq!(ResourceUsageTarget::SelfProcess.as_raw(), 0);
        assert_eq!(ResourceUsageTarget::Children.as_raw(), -1);
        assert_eq!(ResourceUsageTarget::Thread.as_raw(), 1);
    }
}
