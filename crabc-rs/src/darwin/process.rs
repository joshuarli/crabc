//! Darwin process identity, limits, accounting, priorities, current-directory
//! operations and `posix_spawn` children over libSystem.
//!
//! The raw functions near the top have the names and shapes of the
//! `crabc-core` process seam, so the facade module selects one of the two at
//! compile time and keeps a single body for each operation they share.

#[cfg(feature = "alloc")]
use core::ffi::c_char;
use core::ffi::{c_int, CStr};
use core::fmt;
use core::mem::MaybeUninit;
use core::ptr;

use super::errno::{self, Errno, Result};
use super::sys;
use crate::process::{Flock, FlockOffsetType, Pid, PriorityTarget, Rlimit};
#[cfg(feature = "alloc")]
use crate::process::FdAction;
use crate::{AsFd, RawFd};

pub(crate) use sys::{getegid, geteuid, getgid, getpid, getppid, getuid};

/// `kill(pid, signal)`.
#[inline]
pub(crate) fn kill(pid: i32, signal: i32) -> Result<()> {
    errno::check(sys::kill(pid, signal)).map(|_| ())
}

/// `getpgid(pid)`, where zero selects the caller.
#[inline]
pub(crate) fn getpgid(pid: i32) -> Result<i32> {
    errno::check(sys::getpgid(pid))
}

/// `getsid(pid)`, where zero selects the caller.
#[inline]
pub(crate) fn getsid(pid: i32) -> Result<i32> {
    errno::check(sys::getsid(pid))
}

/// `chdir(path)`.
#[inline]
pub(crate) fn chdir(path: &CStr) -> Result<()> {
    // SAFETY: `path` is a live NUL-terminated string for the call.
    errno::check(unsafe { sys::chdir(path.as_ptr()) }).map(|_| ())
}

/// `fchdir(fd)`.
#[inline]
pub(crate) fn fchdir(fd: RawFd) -> Result<()> {
    // SAFETY: `fchdir` has no memory arguments; the caller's borrow keeps
    // `fd` open for the call.
    errno::check(unsafe { sys::fchdir(fd) }).map(|_| ())
}

/// `chroot(path)`.
#[inline]
pub(crate) fn chroot(path: &CStr) -> Result<()> {
    // SAFETY: `path` is a live NUL-terminated string for the call.
    errno::check(unsafe { sys::chroot(path.as_ptr()) }).map(|_| ())
}

/// `umask(mask)`. Darwin's `mode_t` is 16 bits and libSystem keeps only the
/// permission bits, so dropping the high bits of `mask` loses nothing.
#[inline]
pub(crate) fn umask_raw(mask: u32) -> u32 {
    u32::from(sys::umask((mask & 0xffff) as sys::mode_t))
}

/// `getgroups(0, NULL)`: the current number of supplementary groups.
#[inline]
pub(crate) fn getgroups_count_raw() -> Result<usize> {
    // SAFETY: a zero size asks for the count only; nothing is written.
    let count = unsafe { sys::getgroups(0, ptr::null_mut()) };
    errno::check(count).map(|count| count as usize)
}

/// `getgroups(length, groups)`.
///
/// # Safety
///
/// `groups` must be writable for `length` group IDs, or null when `length`
/// is zero.
#[inline]
pub(crate) unsafe fn getgroups_raw(groups: *mut u32, length: usize) -> Result<usize> {
    let length = c_int::try_from(length).unwrap_or(c_int::MAX);
    // SAFETY: the caller supplies storage for at least `length` IDs.
    let count = unsafe { sys::getgroups(length, groups) };
    errno::check(count).map(|count| count as usize)
}

/// `getcwd(buffer, length)`, returning the initialized length including the
/// terminating NUL.
///
/// An empty buffer fails with [`Errno::RANGE`] before the call: libSystem
/// would otherwise allocate its own buffer for a null pointer.
///
/// # Safety
///
/// `buffer` must be writable for `length` bytes.
#[inline]
pub(crate) unsafe fn getcwd_raw(buffer: *mut u8, length: usize) -> Result<usize> {
    if length == 0 {
        return Err(Errno::RANGE);
    }
    // SAFETY: the caller supplies `length` writable bytes, and `length` is
    // non-zero, so libSystem writes into them rather than allocating.
    let result = unsafe { sys::getcwd(buffer.cast(), length) };
    if result.is_null() {
        return Err(errno::last());
    }
    // SAFETY: a successful `getcwd` stored a NUL-terminated path at `buffer`.
    let path = unsafe { CStr::from_ptr(result.cast_const()) };
    Ok(path.count_bytes() + 1)
}

/// `setpriority(which, who, priority)`.
#[inline]
pub(crate) fn setpriority_raw(which: i32, who: u32, priority: i32) -> Result<()> {
    errno::check(sys::setpriority(which, who, priority)).map(|_| ())
}

/// `sched_get_priority_min` and `sched_get_priority_max` for one policy.
#[inline]
pub(crate) fn scheduler_priority_bounds_raw(policy: i32) -> Result<(i32, i32)> {
    let minimum = errno::check(sys::sched_get_priority_min(policy))?;
    let maximum = errno::check(sys::sched_get_priority_max(policy))?;
    Ok((minimum, maximum))
}

/// `getrusage(who)`.
#[inline]
pub(crate) fn getrusage_raw(who: i32) -> Result<sys::Rusage> {
    let mut usage = MaybeUninit::<sys::Rusage>::uninit();
    // SAFETY: `usage` is writable storage for one `struct rusage`.
    let result = unsafe { sys::getrusage(who, usage.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `getrusage` initialized the whole record.
    Ok(unsafe { usage.assume_init() })
}

/// One libSystem `times` observation: the four accounting fields and the
/// separate elapsed-tick return value.
#[derive(Clone, Copy)]
pub(crate) struct TimesObservation {
    pub(crate) process: sys::Tms,
    pub(crate) elapsed_ticks: sys::clock_t,
}

/// `times(buffer)`.
#[inline]
pub(crate) fn times_raw() -> Result<TimesObservation> {
    let mut process = MaybeUninit::<sys::Tms>::uninit();
    errno::clear();
    // SAFETY: `process` is writable storage for one `struct tms`.
    let elapsed_ticks = unsafe { sys::times(process.as_mut_ptr()) };
    if elapsed_ticks == sys::clock_t::MAX {
        if let Some(error) = errno::current() {
            return Err(error);
        }
    }
    // SAFETY: `times` initialized the record; `(clock_t)-1` with `errno`
    // still clear is a valid elapsed count, not a failure.
    let process = unsafe { process.assume_init() };
    Ok(TimesObservation {
        process,
        elapsed_ticks,
    })
}

/// `_exit(status)`: ends the process without running `atexit` handlers,
/// Rust destructors or stdio flushes.
#[inline]
pub(crate) fn exit_immediately(status: i32) -> ! {
    sys::_exit(status)
}

bitflags::bitflags! {
    /// Options for waiting on one owned child process, with Darwin values.
    ///
    /// [`Child::wait`](crate::process::Child::wait) consumes its owner only
    /// when it reaps the child; `NOHANG`, stop and continue reports return the
    /// owner in [`WaitOutcome`](crate::process::WaitOutcome).
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct WaitOptions: u32 {
        /// Return immediately when this child has no reportable state change.
        const NOHANG = sys::WNOHANG.cast_unsigned();
        /// Report a stopped child which is not being traced.
        const UNTRACED = sys::WUNTRACED.cast_unsigned();
        /// Report a child resumed with `SIGCONT`.
        const CONTINUED = sys::WCONTINUED.cast_unsigned();
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

/// A Darwin wait-status word returned while consuming an owned child.
///
/// Darwin reports a continued child as `SIGCONT` in the stop encoding
/// (`0x137f`) rather than Linux's `0xffff`.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct WaitStatus(i32);

/// `_WSTOPPED`, the low seven bits of a stop or continue report.
const WAIT_STOPPED: i32 = 0o177;

impl WaitStatus {
    /// Returns the raw Darwin wait-status word.
    #[inline]
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self.0
    }

    /// Returns whether the child exited normally.
    #[inline]
    #[must_use]
    pub const fn exited(self) -> bool {
        self.0 & 0x7f == 0
    }

    /// Returns the child's ordinary exit code when it exited normally.
    #[inline]
    #[must_use]
    pub const fn exit_status(self) -> Option<i32> {
        if self.exited() {
            Some((self.0 >> 8) & 0xff)
        } else {
            None
        }
    }

    /// Returns whether the child was terminated by a signal.
    #[inline]
    #[must_use]
    pub const fn signaled(self) -> bool {
        let signal = self.0 & 0x7f;
        signal != 0 && signal != WAIT_STOPPED
    }

    /// Returns the terminating raw signal number when applicable.
    #[inline]
    #[must_use]
    pub const fn terminating_signal(self) -> Option<i32> {
        if self.signaled() {
            Some(self.0 & 0x7f)
        } else {
            None
        }
    }

    /// Returns whether the terminating signal produced a core dump.
    #[inline]
    #[must_use]
    pub const fn core_dumped(self) -> bool {
        self.signaled() && self.0 & 0x80 != 0
    }

    /// Returns whether the child is currently stopped.
    #[inline]
    #[must_use]
    pub const fn stopped(self) -> bool {
        self.0 & 0x7f == WAIT_STOPPED && self.0 >> 8 != sys::SIGCONT
    }

    /// Returns the raw stopping signal number when applicable.
    #[inline]
    #[must_use]
    pub const fn stopping_signal(self) -> Option<i32> {
        if self.stopped() {
            Some(self.0 >> 8)
        } else {
            None
        }
    }

    /// Returns whether the child has continued from a job-control stop.
    #[inline]
    #[must_use]
    pub const fn continued(self) -> bool {
        self.0 & 0x7f == WAIT_STOPPED && self.0 >> 8 == sys::SIGCONT
    }
}

impl fmt::Debug for WaitStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut status = formatter.debug_struct("WaitStatus");
        status
            .field("exited", &self.exited())
            .field("signaled", &self.signaled())
            .field("stopped", &self.stopped())
            .field("continued", &self.continued());
        if let Some(code) = self.exit_status() {
            status.field("exit_status", &code);
        }
        if let Some(signal) = self.terminating_signal() {
            status.field("terminating_signal", &signal);
        }
        if let Some(signal) = self.stopping_signal() {
            status.field("stopping_signal", &signal);
        }
        status.finish()
    }
}

/// Waits for `pid` with `waitpid`, retrying interruptions; `None` reports
/// `NOHANG` with no change.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn wait_child(pid: Pid, options: WaitOptions) -> Result<Option<WaitStatus>> {
    let mut status: c_int = 0;
    let waited = loop {
        // SAFETY: `status` is writable for the call and the owned PID is
        // positive; an interrupted wait consumed no state.
        let result =
            unsafe { sys::waitpid(pid.as_raw_pid(), &mut status, options.bits().cast_signed()) };
        match errno::check(result) {
            Err(Errno::INTR) => continue,
            result => break result?,
        }
    };
    if waited == 0 {
        Ok(None)
    } else {
        Ok(Some(WaitStatus(status)))
    }
}

/// A process resource whose limits can be queried and changed on Darwin.
///
/// Darwin has nine limits. `RLIMIT_RSS` is an alias of `RLIMIT_AS` there, so
/// it has no separate variant, and Linux's `LOCKS`, `SIGPENDING`,
/// `MSGQUEUE`, `NICE`, `RTPRIO` and `RTTIME` do not exist.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Resource {
    /// `RLIMIT_CPU`.
    Cpu = sys::RLIMIT_CPU as u32,
    /// `RLIMIT_FSIZE`.
    Fsize = sys::RLIMIT_FSIZE as u32,
    /// `RLIMIT_DATA`.
    Data = sys::RLIMIT_DATA as u32,
    /// `RLIMIT_STACK`.
    Stack = sys::RLIMIT_STACK as u32,
    /// `RLIMIT_CORE`.
    Core = sys::RLIMIT_CORE as u32,
    /// `RLIMIT_AS`, which Darwin also names `RLIMIT_RSS`.
    As = sys::RLIMIT_AS as u32,
    /// `RLIMIT_MEMLOCK`.
    Memlock = sys::RLIMIT_MEMLOCK as u32,
    /// `RLIMIT_NPROC`.
    Nproc = sys::RLIMIT_NPROC as u32,
    /// `RLIMIT_NOFILE`.
    Nofile = sys::RLIMIT_NOFILE as u32,
}

impl Resource {
    /// Returns the Darwin resource selector.
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

#[inline]
fn limit_from_raw(value: sys::rlim_t) -> Option<u64> {
    (value != sys::RLIM_INFINITY).then_some(value)
}

/// Encodes one limit; a finite value at or above Darwin's `RLIM_INFINITY`
/// (2⁶³ − 1) cannot be told apart from unlimited and is rejected.
#[inline]
fn limit_to_raw(value: Option<u64>) -> Result<sys::rlim_t> {
    match value {
        None => Ok(sys::RLIM_INFINITY),
        Some(value) if value < sys::RLIM_INFINITY => Ok(value),
        Some(_) => Err(Errno::INVAL),
    }
}

/// Reads the calling process's current and maximum limits for `resource`.
///
/// Darwin's `RLIM_INFINITY` is represented as `None`.
#[inline]
pub fn getrlimit(resource: Resource) -> Result<Rlimit> {
    let mut limit = MaybeUninit::<sys::Rlimit>::uninit();
    // SAFETY: `limit` is writable storage for one `struct rlimit`.
    let result = unsafe { sys::getrlimit(resource.as_raw() as c_int, limit.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `getrlimit` initialized the record.
    let limit = unsafe { limit.assume_init() };
    Ok(Rlimit {
        current: limit_from_raw(limit.rlim_cur),
        maximum: limit_from_raw(limit.rlim_max),
    })
}

/// Changes the calling process's current and maximum limits for `resource`.
///
/// `None` represents Darwin's `RLIM_INFINITY`. A current limit above the
/// maximum, and a finite value that is not below `RLIM_INFINITY`, are
/// rejected with [`Errno::INVAL`] before the call. The change is
/// process-wide and must be coordinated with other limit users.
#[inline]
pub fn setrlimit(resource: Resource, limit: Rlimit) -> Result<()> {
    let record = sys::Rlimit {
        rlim_cur: limit_to_raw(limit.current)?,
        rlim_max: limit_to_raw(limit.maximum)?,
    };
    if record.rlim_cur > record.rlim_max {
        return Err(Errno::INVAL);
    }
    // SAFETY: `record` is a live, initialized `struct rlimit` for the call.
    let result = unsafe { sys::setrlimit(resource.as_raw() as c_int, &record) };
    errno::check(result).map(|_| ())
}

/// Which resource usage Darwin `getrusage` should observe.
///
/// Darwin has no per-thread `RUSAGE_THREAD` selector.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ResourceUsageTarget {
    /// `RUSAGE_SELF`, the calling process.
    SelfProcess = sys::RUSAGE_SELF,
    /// `RUSAGE_CHILDREN`, terminated and waited children.
    Children = sys::RUSAGE_CHILDREN,
}

impl ResourceUsageTarget {
    /// Returns the Darwin `RUSAGE_*` selector.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// A Darwin nice value, from `-20` through `20` inclusive.
///
/// Darwin's range ends at `PRIO_MAX` (20), one above Linux's. The closed
/// range keeps an arbitrary integer from crossing this API boundary.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Priority(i32);

impl Priority {
    /// The most favorable Darwin nice value.
    pub const MIN: Self = Self(sys::PRIO_MIN);
    /// The least favorable Darwin nice value.
    pub const MAX: Self = Self(sys::PRIO_MAX);
    /// Darwin's default nice value.
    pub const DEFAULT: Self = Self(0);

    /// Converts a Darwin nice value into the bounded priority type.
    #[inline]
    pub const fn from_raw(raw: i32) -> Option<Self> {
        if raw >= Self::MIN.0 && raw <= Self::MAX.0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Returns the Darwin nice value.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0
    }
}

/// Reads the nice value for a process, process group, or user.
///
/// Darwin's `getpriority` returns `-1` both for a nice value of `-1` and for
/// failure, so `errno` is cleared first and inspected only after a `-1`.
#[inline]
pub fn getpriority(target: PriorityTarget) -> Result<Priority> {
    let (which, who) = target.as_raw();
    errno::clear();
    let value = sys::getpriority(which, who);
    if value == -1 {
        if let Some(error) = errno::current() {
            return Err(error);
        }
    }
    Priority::from_raw(value).ok_or(Errno::RANGE)
}

/// A Darwin scheduler policy with a priority-range query.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum SchedulerPolicy {
    /// The normal time-sharing scheduler policy (`SCHED_OTHER`).
    Other = sys::SCHED_OTHER,
    /// The first-in, first-out policy (`SCHED_FIFO`).
    Fifo = sys::SCHED_FIFO,
    /// The round-robin policy (`SCHED_RR`).
    RoundRobin = sys::SCHED_RR,
}

impl SchedulerPolicy {
    /// Returns the Darwin scheduler policy token.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// Lock kind used by [`fcntl_getlk`], with Darwin `F_*LCK` values.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i16)]
pub enum FlockType {
    /// A shared/read lock.
    ReadLock = sys::F_RDLCK,
    /// An exclusive/write lock.
    WriteLock = sys::F_WRLCK,
    /// No lock would block the query; valid only in a returned record.
    Unlocked = sys::F_UNLCK,
}

/// Queries the first process-associated record lock that would block `lock`.
///
/// Returns `None` when no lock would block, or the first conflicting lock.
/// An [`FlockType::Unlocked`] input is rejected with [`Errno::INVAL`], and
/// offsets beyond `i64::MAX` with [`Errno::RANGE`], before the call; a
/// malformed returned record is reported as [`Errno::RANGE`].
#[inline]
pub fn fcntl_getlk<Fd: AsFd>(fd: Fd, lock: &Flock) -> Result<Option<Flock>> {
    if lock.start > i64::MAX as u64 || lock.length > i64::MAX as u64 {
        return Err(Errno::RANGE);
    }
    let l_type = match lock.typ {
        FlockType::ReadLock | FlockType::WriteLock => lock.typ as i16,
        FlockType::Unlocked => return Err(Errno::INVAL),
    };
    let mut record = sys::Flock {
        l_start: lock.start as i64,
        l_len: lock.length as i64,
        l_pid: lock.pid.map_or(0, Pid::as_raw_pid),
        l_type,
        l_whence: lock.offset_type as i16,
    };
    // SAFETY: `F_GETLK` reads and rewrites the one live `struct flock`
    // passed as its variadic pointer argument.
    let result = unsafe {
        sys::fcntl(fd.as_fd().as_raw_fd(), sys::F_GETLK, &mut record as *mut sys::Flock)
    };
    errno::check(result)?;
    let typ = match record.l_type {
        sys::F_UNLCK => return Ok(None),
        sys::F_RDLCK => FlockType::ReadLock,
        sys::F_WRLCK => FlockType::WriteLock,
        _ => return Err(Errno::RANGE),
    };
    let offset_type = match c_int::from(record.l_whence) {
        sys::SEEK_SET => FlockOffsetType::Set,
        sys::SEEK_CUR => FlockOffsetType::Current,
        sys::SEEK_END => FlockOffsetType::End,
        _ => return Err(Errno::RANGE),
    };
    if record.l_start < 0 || record.l_len < 0 || record.l_pid < 0 {
        return Err(Errno::RANGE);
    }
    Ok(Some(Flock {
        start: record.l_start as u64,
        length: record.l_len as u64,
        pid: Pid::from_raw(record.l_pid),
        typ,
        offset_type,
    }))
}

/// A `posix_spawnattr_t` destroyed on drop.
#[cfg(feature = "alloc")]
struct SpawnAttributes(sys::posix_spawnattr_t);

#[cfg(feature = "alloc")]
impl SpawnAttributes {
    fn new() -> Result<Self> {
        let mut attributes = MaybeUninit::<sys::posix_spawnattr_t>::uninit();
        // SAFETY: `attributes` is writable storage for the opaque handle.
        errno::check_code(unsafe { sys::posix_spawnattr_init(attributes.as_mut_ptr()) })?;
        // SAFETY: a successful init stored a valid handle.
        Ok(Self(unsafe { attributes.assume_init() }))
    }
}

#[cfg(feature = "alloc")]
impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        // SAFETY: the handle was initialized by `new` and is destroyed once.
        // Destroying a valid handle cannot fail, so the result is ignored.
        let _ = unsafe { sys::posix_spawnattr_destroy(&mut self.0) };
    }
}

/// A `posix_spawn_file_actions_t` destroyed on drop.
#[cfg(feature = "alloc")]
struct SpawnFileActions(sys::posix_spawn_file_actions_t);

#[cfg(feature = "alloc")]
impl SpawnFileActions {
    fn new() -> Result<Self> {
        let mut actions = MaybeUninit::<sys::posix_spawn_file_actions_t>::uninit();
        // SAFETY: `actions` is writable storage for the opaque handle.
        errno::check_code(unsafe { sys::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
        // SAFETY: a successful init stored a valid handle.
        Ok(Self(unsafe { actions.assume_init() }))
    }
}

#[cfg(feature = "alloc")]
impl Drop for SpawnFileActions {
    fn drop(&mut self) {
        // SAFETY: the handle was initialized by `new` and is destroyed once.
        // Destroying a valid handle cannot fail, so the result is ignored.
        let _ = unsafe { sys::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

/// Spawns `path` with `posix_spawn` and `POSIX_SPAWN_CLOEXEC_DEFAULT`.
///
/// The child receives descriptors 0, 1 and 2 where the parent has them open,
/// then the `actions` in order; every other descriptor is closed at exec.
/// `posix_spawn` reports setup and exec failures directly and leaves no
/// child behind on failure.
///
/// # Safety
///
/// `argv` and `envp` must each be a null-terminated array of pointers to
/// NUL-terminated strings, all live for the call.
#[cfg(feature = "alloc")]
pub(crate) unsafe fn spawn(
    path: &CStr,
    argv: &[*const u8],
    envp: &[*const u8],
    actions: &[FdAction<'_>],
    process_group: Option<Option<Pid>>,
    new_session: bool,
    signal_mask: Option<&crate::signal::SignalSet>,
) -> Result<Pid> {
    let mut attributes = SpawnAttributes::new()?;
    let mut flags = sys::POSIX_SPAWN_CLOEXEC_DEFAULT;
    if new_session {
        flags |= sys::POSIX_SPAWN_SETSID;
    }
    if let Some(group) = process_group {
        flags |= sys::POSIX_SPAWN_SETPGROUP;
        let group = group.map_or(0, Pid::as_raw_pid);
        // SAFETY: `attributes` holds an initialized handle.
        errno::check_code(unsafe { sys::posix_spawnattr_setpgroup(&mut attributes.0, group) })?;
    }
    if let Some(mask) = signal_mask {
        flags |= sys::POSIX_SPAWN_SETSIGMASK;
        // SAFETY: `attributes` holds an initialized handle and `mask` is one
        // live `sigset_t`, which libSystem copies.
        errno::check_code(unsafe {
            sys::posix_spawnattr_setsigmask(&mut attributes.0, mask.kernel_bits())
        })?;
    }
    // SAFETY: `attributes` holds an initialized handle.
    errno::check_code(unsafe { sys::posix_spawnattr_setflags(&mut attributes.0, flags) })?;

    let mut file_actions = SpawnFileActions::new()?;
    for standard in 0..=2 {
        // SAFETY: `F_GETFD` takes no pointer argument; it only reports
        // whether `standard` is open in the parent.
        if unsafe { sys::fcntl(standard, sys::F_GETFD) } != -1 {
            // SAFETY: `file_actions` holds an initialized handle.
            errno::check_code(unsafe {
                sys::posix_spawn_file_actions_addinherit_np(&mut file_actions.0, standard)
            })?;
        }
    }
    for action in actions {
        let code = match *action {
            // SAFETY: `file_actions` holds an initialized handle.
            FdAction::Close(fd) => unsafe {
                sys::posix_spawn_file_actions_addclose(&mut file_actions.0, fd.as_raw_fd())
            },
            // SAFETY: `file_actions` holds an initialized handle.
            FdAction::Dup2 { from, to } => unsafe {
                sys::posix_spawn_file_actions_adddup2(&mut file_actions.0, from.as_raw_fd(), to)
            },
        };
        errno::check_code(code)?;
    }

    let mut pid: sys::pid_t = 0;
    // SAFETY: `path` is NUL-terminated, both handles are initialized, and the
    // caller guarantees the two null-terminated pointer arrays. libSystem
    // never writes through the argument or environment strings.
    let code = unsafe {
        sys::posix_spawn(
            &mut pid,
            path.as_ptr(),
            &file_actions.0,
            &attributes.0,
            argv.as_ptr().cast::<*mut c_char>(),
            envp.as_ptr().cast::<*mut c_char>(),
        )
    };
    errno::check_code(code)?;
    Pid::from_raw(pid).ok_or(Errno::IO)
}
