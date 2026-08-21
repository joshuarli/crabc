//! Process identifiers, process groups, and signal delivery.
//!
//! These operations issue Linux/AArch64 syscalls through `crabc-core`; they
//! do not use libc's process wrappers or its thread-local `errno` channel.

use core::fmt;
use core::mem::MaybeUninit;
use core::num::NonZeroI32;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bitflags::bitflags;

use crate::signal::SigInfo;
use crate::Result;
#[cfg(feature = "alloc")]
use crate::Errno;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::convert::Infallible;
#[cfg(feature = "alloc")]
use core::ffi::CStr;
#[cfg(feature = "alloc")]
use crate::{AsFd, BorrowedFd, RawFd};
#[cfg(feature = "alloc")]
use crate::path::Arg;

/// A process identifier as a raw Linux `pid_t`.
pub type RawPid = i32;

/// A non-zero Linux process or thread identifier.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pid(NonZeroI32);

impl Pid {
    /// The Linux init process.
    pub const INIT: Self = Self(unsafe { NonZeroI32::new_unchecked(1) });

    /// Converts a positive raw process identifier into a typed identifier.
    #[inline]
    pub const fn from_raw(raw: RawPid) -> Option<Self> {
        debug_assert!(raw >= 0);
        match NonZeroI32::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    /// Converts a known non-zero raw process identifier into a typed identifier.
    ///
    /// # Safety
    ///
    /// `raw` must be non-zero.
    #[inline]
    pub const unsafe fn from_raw_unchecked(raw: RawPid) -> Self {
        Self(unsafe { NonZeroI32::new_unchecked(raw) })
    }

    /// Returns the non-zero raw process identifier.
    #[inline]
    pub const fn as_raw_nonzero(self) -> NonZeroI32 {
        self.0
    }

    /// Returns the raw Linux process identifier.
    #[inline]
    pub const fn as_raw_pid(self) -> RawPid {
        self.0.get()
    }

    /// Encodes an optional process identifier for Linux APIs where zero means
    /// the calling process.
    #[inline]
    pub const fn as_raw(pid: Option<Self>) -> RawPid {
        match pid {
            Some(pid) => pid.as_raw_pid(),
            None => 0,
        }
    }

    /// Tests whether this identifies Linux init.
    #[inline]
    pub const fn is_init(self) -> bool {
        self.as_raw_pid() == 1
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A non-zero Linux signal number.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Signal(NonZeroI32);

impl Signal {
    /// `SIGHUP`.
    pub const HUP: Self = Self(unsafe { NonZeroI32::new_unchecked(1) });
    /// `SIGINT`.
    pub const INT: Self = Self(unsafe { NonZeroI32::new_unchecked(2) });
    /// `SIGQUIT`.
    pub const QUIT: Self = Self(unsafe { NonZeroI32::new_unchecked(3) });
    /// `SIGILL`.
    pub const ILL: Self = Self(unsafe { NonZeroI32::new_unchecked(4) });
    /// `SIGTRAP`.
    pub const TRAP: Self = Self(unsafe { NonZeroI32::new_unchecked(5) });
    /// `SIGABRT` / `SIGIOT`.
    pub const ABORT: Self = Self(unsafe { NonZeroI32::new_unchecked(6) });
    /// `SIGBUS`.
    pub const BUS: Self = Self(unsafe { NonZeroI32::new_unchecked(7) });
    /// `SIGFPE`.
    pub const FPE: Self = Self(unsafe { NonZeroI32::new_unchecked(8) });
    /// `SIGKILL`.
    pub const KILL: Self = Self(unsafe { NonZeroI32::new_unchecked(9) });
    /// `SIGUSR1`.
    pub const USR1: Self = Self(unsafe { NonZeroI32::new_unchecked(10) });
    /// `SIGSEGV`.
    pub const SEGV: Self = Self(unsafe { NonZeroI32::new_unchecked(11) });
    /// `SIGUSR2`.
    pub const USR2: Self = Self(unsafe { NonZeroI32::new_unchecked(12) });
    /// `SIGPIPE`.
    pub const PIPE: Self = Self(unsafe { NonZeroI32::new_unchecked(13) });
    /// `SIGALRM`.
    pub const ALARM: Self = Self(unsafe { NonZeroI32::new_unchecked(14) });
    /// `SIGTERM`.
    pub const TERM: Self = Self(unsafe { NonZeroI32::new_unchecked(15) });
    /// `SIGSTKFLT`.
    pub const STKFLT: Self = Self(unsafe { NonZeroI32::new_unchecked(16) });
    /// `SIGCHLD`.
    pub const CHILD: Self = Self(unsafe { NonZeroI32::new_unchecked(17) });
    /// `SIGCONT`.
    pub const CONT: Self = Self(unsafe { NonZeroI32::new_unchecked(18) });
    /// `SIGSTOP`.
    pub const STOP: Self = Self(unsafe { NonZeroI32::new_unchecked(19) });
    /// `SIGTSTP`.
    pub const TSTP: Self = Self(unsafe { NonZeroI32::new_unchecked(20) });
    /// `SIGTTIN`.
    pub const TTIN: Self = Self(unsafe { NonZeroI32::new_unchecked(21) });
    /// `SIGTTOU`.
    pub const TTOU: Self = Self(unsafe { NonZeroI32::new_unchecked(22) });
    /// `SIGURG`.
    pub const URG: Self = Self(unsafe { NonZeroI32::new_unchecked(23) });
    /// `SIGXCPU`.
    pub const XCPU: Self = Self(unsafe { NonZeroI32::new_unchecked(24) });
    /// `SIGXFSZ`.
    pub const XFSZ: Self = Self(unsafe { NonZeroI32::new_unchecked(25) });
    /// `SIGVTALRM`.
    pub const VTALARM: Self = Self(unsafe { NonZeroI32::new_unchecked(26) });
    /// `SIGPROF`.
    pub const PROF: Self = Self(unsafe { NonZeroI32::new_unchecked(27) });
    /// `SIGWINCH`.
    pub const WINCH: Self = Self(unsafe { NonZeroI32::new_unchecked(28) });
    /// `SIGIO` / `SIGPOLL`.
    pub const IO: Self = Self(unsafe { NonZeroI32::new_unchecked(29) });
    /// `SIGPWR`.
    pub const POWER: Self = Self(unsafe { NonZeroI32::new_unchecked(30) });
    /// `SIGSYS`.
    pub const SYS: Self = Self(unsafe { NonZeroI32::new_unchecked(31) });
    /// The first application-visible realtime signal on Linux/musl.
    pub const RTMIN: Self = Self(unsafe { NonZeroI32::new_unchecked(35) });
    /// The last Linux realtime signal on this target.
    pub const RTMAX: Self = Self(unsafe { NonZeroI32::new_unchecked(64) });

    /// Converts an application-visible Linux/musl signal number into a typed
    /// signal.
    ///
    /// In addition to the standard 1–31 signals, this accepts the full musl
    /// application realtime range 35–64. musl reserves 32, 33, and 34 for
    /// runtime use and deliberately keeps them outside this safe vocabulary.
    #[inline]
    pub const fn from_named_raw(raw: i32) -> Option<Self> {
        if (raw >= 1 && raw <= 31) || (raw >= Self::RTMIN.as_raw() && raw <= Self::RTMAX.as_raw()) {
            // SAFETY: The range check proves that `raw` is non-zero.
            Some(Self(unsafe { NonZeroI32::new_unchecked(raw) }))
        } else {
            None
        }
    }

    /// Constructs an arbitrary non-zero Linux signal number.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid non-zero signal number for the intended kernel
    /// operation and must not be one of musl's internally reserved signals
    /// (32, 33, or 34) unless the caller owns the runtime consequences.
    #[inline]
    pub const unsafe fn from_raw_unchecked(raw: i32) -> Self {
        Self(unsafe { NonZeroI32::new_unchecked(raw) })
    }

    /// Returns the raw Linux signal number.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0.get()
    }

    /// Returns whether this is an application-visible realtime signal.
    #[inline]
    #[must_use]
    pub const fn is_realtime(self) -> bool {
        self.as_raw() >= Self::RTMIN.as_raw() && self.as_raw() <= Self::RTMAX.as_raw()
    }
}

/// Returns the caller's process ID.
#[inline]
#[must_use]
pub fn getpid() -> Pid {
    // SAFETY: Linux returns a positive process ID for a running task.
    unsafe { Pid::from_raw_unchecked(crabc_core::process::getpid()) }
}

/// Returns the caller's parent process ID, if one is visible in this PID namespace.
#[inline]
#[must_use]
pub fn getppid() -> Option<Pid> {
    Pid::from_raw(crabc_core::process::getppid())
}

/// Returns the caller's real Linux user ID.
#[inline]
#[must_use]
pub fn getuid() -> u32 {
    crabc_core::process::getuid()
}

/// Returns a process group ID. `None` means the calling process.
#[inline]
pub fn getpgid(pid: Option<Pid>) -> Result<Pid> {
    crabc_core::process::getpgid(Pid::as_raw(pid)).map(|pid| {
        // A successful getpgid result is always a positive process ID.
        unsafe { Pid::from_raw_unchecked(pid) }
    })
}

/// Assigns a process group. `None` retains Linux's calling-process meaning.
#[inline]
pub fn setpgid(pid: Option<Pid>, pgid: Option<Pid>) -> Result<()> {
    crabc_core::process::setpgid(Pid::as_raw(pid), Pid::as_raw(pgid))
}

/// Returns the caller's process group ID.
#[inline]
#[must_use]
pub fn getpgrp() -> Pid {
    match crabc_core::process::getpgid(0) {
        // The current process always belongs to a positive process group.
        Ok(pid) => unsafe { Pid::from_raw_unchecked(pid) },
        Err(_) => panic!("Linux getpgid(0) syscall failed"),
    }
}

/// Returns a session ID. `None` means the calling process.
#[inline]
pub fn getsid(pid: Option<Pid>) -> Result<Pid> {
    crabc_core::process::getsid(Pid::as_raw(pid)).map(|pid| {
        // A successful getsid result is always a positive process ID.
        unsafe { Pid::from_raw_unchecked(pid) }
    })
}

/// Creates a new session and returns its ID.
#[inline]
pub fn setsid() -> Result<Pid> {
    crabc_core::process::setsid().map(|pid| {
        // A successful setsid result is always a positive process ID.
        unsafe { Pid::from_raw_unchecked(pid) }
    })
}

/// Sends a signal to one process.
#[inline]
pub fn kill_process(pid: Pid, signal: Signal) -> Result<()> {
    crabc_core::process::kill(pid.as_raw_pid(), signal.as_raw())
}

/// Tests whether a process exists and may receive a signal without sending one.
#[inline]
pub fn test_kill_process(pid: Pid) -> Result<()> {
    crabc_core::process::kill(pid.as_raw_pid(), 0)
}

/// Tests whether every member of a process group exists and may receive a
/// signal without sending one.
#[inline]
pub fn test_kill_process_group(pid: Pid) -> Result<()> {
    crabc_core::process::kill(-pid.as_raw_pid(), 0)
}

/// Sends a signal to a process group.
#[inline]
pub fn kill_process_group(pid: Pid, signal: Signal) -> Result<()> {
    crabc_core::process::kill(-pid.as_raw_pid(), signal.as_raw())
}

/// Sends a signal to the caller's process group.
#[inline]
pub fn kill_current_process_group(signal: Signal) -> Result<()> {
    crabc_core::process::kill(0, signal.as_raw())
}

/// Tests whether the caller's process group may receive a signal.
#[inline]
pub fn test_kill_current_process_group() -> Result<()> {
    crabc_core::process::kill(0, 0)
}

/// Sets the calling process group to the calling process ID.
///
/// This is a convenience spelling of `setpgid(None, None)` and remains
/// subject to Linux's process-group/session races and permission checks.
#[inline]
pub fn setpgrp() -> Result<()> {
    setpgid(None, None)
}

bitflags! {
    /// Options for `wait`, `waitpid`, and `waitpgid`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct WaitOptions: u32 {
        /// Return immediately when no matching child has changed state.
        const NOHANG = 0x0000_0001;
        /// Report stopped children which are not being traced.
        const UNTRACED = 0x0000_0002;
        /// Report a child resumed with `SIGCONT`.
        const CONTINUED = 0x0000_0008;
        /// Preserve future Linux option bits for kernel validation.
        const _ = !0;
    }
}

/// A Linux wait-status word returned by `wait4`/`waitpid`.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct WaitStatus(i32);

impl WaitStatus {
    /// Returns the raw Linux wait-status word.
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
        signal != 0 && signal != 0x7f
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
        self.0 & 0xff == 0x7f
    }

    /// Returns the raw stopping signal number when applicable.
    #[inline]
    #[must_use]
    pub const fn stopping_signal(self) -> Option<i32> {
        if self.stopped() {
            Some((self.0 >> 8) & 0xff)
        } else {
            None
        }
    }

    /// Returns whether the child has continued from a job-control stop.
    #[inline]
    #[must_use]
    pub const fn continued(self) -> bool {
        self.0 == 0xffff
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

/// Waits for any child process state change.
#[inline]
pub fn wait(options: WaitOptions) -> Result<Option<(Pid, WaitStatus)>> {
    wait_raw(-1, options)
}

/// Waits for one child. `None` uses Linux's current-process-group selection.
#[inline]
pub fn waitpid(pid: Option<Pid>, options: WaitOptions) -> Result<Option<(Pid, WaitStatus)>> {
    wait_raw(Pid::as_raw(pid), options)
}

/// Waits for a child in process group `pgid`.
#[inline]
pub fn waitpgid(pgid: Pid, options: WaitOptions) -> Result<Option<(Pid, WaitStatus)>> {
    wait_raw(-pgid.as_raw_pid(), options)
}

#[inline]
fn wait_raw(target: i32, options: WaitOptions) -> Result<Option<(Pid, WaitStatus)>> {
    let mut status = 0_i32;
    // SAFETY: `status` is writable Linux `int` storage and `target`/options
    // retain the documented wait4/waitpid scalar encodings.
    let pid = unsafe { crabc_core::process::wait4_raw(target, &mut status, options.bits())? };
    if pid == 0 {
        return Ok(None);
    }
    // Linux returns a positive child PID whenever wait4 reports a state.
    Ok(Some((unsafe { Pid::from_raw_unchecked(pid) }, WaitStatus(status))))
}

/// Target selection for Linux `waitid`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WaitId {
    /// Wait on any child process.
    All,
    /// Wait on one child process.
    Pid(Pid),
    /// Wait on a process group. `None` means the caller's group.
    Pgid(Option<Pid>),
}

bitflags! {
    /// Options for Linux `waitid`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct WaitIdOptions: u32 {
        /// Return immediately when no matching child has changed state.
        const NOHANG = 0x0000_0001;
        /// Report stopped children.
        const STOPPED = 0x0000_0002;
        /// Report exited children.
        const EXITED = 0x0000_0004;
        /// Report continued children.
        const CONTINUED = 0x0000_0008;
        /// Leave the matching child waitable after observing it.
        const NOWAIT = 0x0100_0000;
        /// Preserve future Linux option bits for kernel validation.
        const _ = !0;
    }
}

/// A typed `waitid` result backed by Linux's signal-information record.
#[derive(Clone, Copy, Debug)]
pub struct WaitIdStatus(SigInfo);

impl WaitIdStatus {
    /// Returns the process ID associated with the child-state report.
    #[inline]
    #[must_use]
    pub fn pid(self) -> Option<Pid> {
        self.0.sender_pid()
    }

    /// Returns the raw Linux child-state code.
    #[inline]
    #[must_use]
    pub fn raw_code(self) -> i32 {
        self.0.raw_code()
    }

    /// Returns whether the child exited normally.
    #[inline]
    #[must_use]
    pub fn exited(self) -> bool {
        self.raw_code() == 1
    }

    /// Returns whether a signal killed the child without a core dump.
    #[inline]
    #[must_use]
    pub fn killed(self) -> bool {
        self.raw_code() == 2
    }

    /// Returns whether a signal killed the child with a core dump.
    #[inline]
    #[must_use]
    pub fn dumped(self) -> bool {
        self.raw_code() == 3
    }

    /// Returns whether the child stopped.
    #[inline]
    #[must_use]
    pub fn stopped(self) -> bool {
        self.raw_code() == 5
    }

    /// Returns whether the child continued.
    #[inline]
    #[must_use]
    pub fn continued(self) -> bool {
        self.raw_code() == 6
    }

    /// Returns the exit status or signal number from the child report.
    #[inline]
    #[must_use]
    pub fn status(self) -> i32 {
        self.0.status()
    }
}

/// Waits through Linux `waitid`.
#[inline]
pub fn waitid(target: WaitId, options: WaitIdOptions) -> Result<Option<WaitIdStatus>> {
    let (kind, id) = match target {
        WaitId::All => (0, 0),
        WaitId::Pid(pid) => (1, pid.as_raw_pid() as u32),
        WaitId::Pgid(pid) => (2, Pid::as_raw(pid) as u32),
    };
    let mut info = MaybeUninit::<crabc_core::signal::SigInfo>::uninit();
    // SAFETY: `info` is aligned writable Linux `siginfo_t` storage and the
    // target/options values use the documented `waitid` encodings.
    unsafe {
        crabc_core::process::waitid_raw(kind, id, info.as_mut_ptr(), options.bits())?;
        let info = SigInfo::from_core(info.assume_init());
        if info.raw_signal() == 0 {
            Ok(None)
        } else {
            Ok(Some(WaitIdStatus(info)))
        }
    }
}

/// The result of a raw Linux fork-equivalent clone.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ForkResult {
    /// The original process, carrying its new child ID.
    Parent { child: Pid },
    /// The child process.
    Child,
}

/// Performs a raw Linux fork-equivalent clone without any atfork callbacks.
///
/// # Safety
///
/// In a multithreaded process, the child may only call async-signal-safe
/// operations before a successful `execve` or `exit_immediately`. It must not
/// allocate, lock ordinary Rust synchronization primitives, invoke destructors
/// or unwinding, access potentially locked runtime state, or call arbitrary
/// Rust/std/C APIs. This primitive deliberately does not run atfork handlers
/// or repair any C-runtime state.
#[inline]
pub unsafe fn fork_raw() -> Result<ForkResult> {
    match crabc_core::process::fork_raw()? {
        0 => Ok(ForkResult::Child),
        child => Ok(ForkResult::Parent {
            // A non-zero successful clone result is a positive child PID.
            child: unsafe { Pid::from_raw_unchecked(child) },
        }),
    }
}

/// Registers callbacks around `fork` and prepared `spawn` operations.
///
/// Prepare callbacks run in reverse registration order; parent and child
/// callbacks run in registration order. The registry is fixed-capacity to keep
/// the child path allocation-free, matching crabc's existing C atfork bound.
///
/// # Safety
///
/// Every callback must be valid for the process lifetime. In particular, a
/// child callback may run after a multithreaded fork and therefore must obey
/// the same async-signal-safety restrictions as [`fork`]'s child result. Do
/// not allocate, lock unrelated state, unwind, or invoke arbitrary Rust/C
/// facilities from a child callback.
#[inline]
pub unsafe fn register_atfork(
    prepare: Option<unsafe extern "C" fn()>,
    parent: Option<unsafe extern "C" fn()>,
    child: Option<unsafe extern "C" fn()>,
) -> Result<()> {
    atfork_lock();
    let count = ATFORK_COUNT.load(Ordering::Relaxed);
    if count == ATFORK_CAPACITY {
        atfork_unlock();
        return Err(crate::Errno::NOMEM);
    }
    // SAFETY: The atfork lock serializes mutation; `count` was checked to fit
    // the static array. Registered callbacks are copied function pointers.
    unsafe { core::ptr::addr_of_mut!(ATFORK_CALLBACKS).cast::<AtFork>().add(count).write(AtFork { prepare, parent, child }) };
    ATFORK_COUNT.store(count + 1, Ordering::Release);
    atfork_unlock();
    Ok(())
}

/// Forks with the native atfork registry around the raw clone boundary.
///
/// # Safety
///
/// The child restrictions are identical to [`fork_raw`]. Registered atfork
/// child callbacks additionally run in that restricted state. This does not
/// invoke C ABI `pthread_atfork` callbacks: crabc-rs owns its direct native
/// facade registry and never crosses the public C ABI to perform a syscall.
#[inline]
pub unsafe fn fork() -> Result<ForkResult> {
    let has_handlers = unsafe { atfork_prepare() };
    let all_signals = !0_u64;
    let mut old_mask = 0_u64;
    // Blocking signals across clone prevents a handler from observing the
    // native atfork registry while it is between prepare and child/parent
    // completion. Failure is retained as a non-fatal kernel condition; clone
    // itself still supplies the definitive result.
    let mask_changed = unsafe {
        crabc_core::signal::rt_sigprocmask_raw(0, &all_signals, &mut old_mask).is_ok()
    };
    let result = unsafe { fork_raw() };
    if has_handlers {
        match result {
            Ok(ForkResult::Child) => unsafe { atfork_child() },
            Ok(ForkResult::Parent { .. }) | Err(_) => unsafe { atfork_parent() },
        }
    }
    if mask_changed {
        // SAFETY: `old_mask` is the initialized word returned by the earlier
        // successful mask query, and no Rust memory survives this syscall.
        let _ = unsafe {
            crabc_core::signal::rt_sigprocmask_raw(2, &old_mask, core::ptr::null_mut())
        };
    }
    result
}

/// Immediately exits the current Linux thread group without destructors or a C ABI
/// transition. This is the only general-purpose post-fork child failure path.
#[inline]
pub fn exit_immediately(status: i32) -> ! {
    crabc_core::process::exit_immediately(status)
}

const ATFORK_CAPACITY: usize = 64;

#[derive(Clone, Copy)]
struct AtFork {
    prepare: Option<unsafe extern "C" fn()>,
    parent: Option<unsafe extern "C" fn()>,
    child: Option<unsafe extern "C" fn()>,
}

const EMPTY_ATFORK: AtFork = AtFork { prepare: None, parent: None, child: None };

// This process-global registry intentionally belongs to the native facade,
// rather than the stateless syscall crate. It uses fixed storage so callback
// execution after fork never allocates. C `pthread_atfork` retains its own C
// ABI registry; this avoids a public-C-ABI call from crabc-rs.
static mut ATFORK_CALLBACKS: [AtFork; ATFORK_CAPACITY] = [EMPTY_ATFORK; ATFORK_CAPACITY];
static ATFORK_COUNT: AtomicUsize = AtomicUsize::new(0);
static ATFORK_LOCK: AtomicBool = AtomicBool::new(false);

#[inline]
fn atfork_lock() {
    while ATFORK_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn atfork_unlock() {
    ATFORK_LOCK.store(false, Ordering::Release);
}

#[inline]
unsafe fn atfork_prepare() -> bool {
    if ATFORK_COUNT.load(Ordering::Acquire) == 0 {
        return false;
    }
    atfork_lock();
    let count = ATFORK_COUNT.load(Ordering::Acquire);
    let callbacks = core::ptr::addr_of!(ATFORK_CALLBACKS).cast::<AtFork>();
    let mut index = count;
    while index != 0 {
        index -= 1;
        // SAFETY: The lock prevents concurrent registration and `index` is
        // bounded by the atomically published array length.
        let callback = unsafe { (*callbacks.add(index)).prepare };
        if let Some(callback) = callback {
            // SAFETY: `register_atfork` documents the callback contract.
            unsafe { callback() };
        }
    }
    true
}

#[inline]
unsafe fn atfork_parent() {
    atfork_finish(false)
}

#[inline]
unsafe fn atfork_child() {
    atfork_finish(true)
}

#[inline]
unsafe fn atfork_finish(is_child: bool) {
    let count = ATFORK_COUNT.load(Ordering::Acquire);
    let callbacks = core::ptr::addr_of!(ATFORK_CALLBACKS).cast::<AtFork>();
    let mut index = 0;
    while index < count {
        // SAFETY: The prepare-side lock is still held and `index` is bounded
        // by the atomically published callback count.
        let callback = unsafe {
            if is_child {
                (*callbacks.add(index)).child
            } else {
                (*callbacks.add(index)).parent
            }
        };
        if let Some(callback) = callback {
            // SAFETY: `register_atfork` documents the callback contract.
            unsafe { callback() };
        }
        index += 1;
    }
    atfork_unlock();
}

/// A caller-owned, allocation-free `execve` specification.
///
/// This is the no-alloc counterpart to [`PreparedExec`] and is useful when a
/// program has already built stable C-string pointer arrays. It deliberately
/// has no child descriptor or process-state actions; those higher-level
/// facilities require parent-side owned preparation.
#[derive(Clone, Copy, Debug)]
pub struct BorrowedExec<'a> {
    path: &'a core::ffi::CStr,
    argv: &'a [*const u8],
    envp: &'a [*const u8],
}

impl<'a> BorrowedExec<'a> {
    /// Validates terminal null pointers for caller-owned `execve` arrays.
    ///
    /// # Safety
    ///
    /// Every non-null pointer in `argv` and `envp` must point to a readable
    /// NUL-terminated byte string for the entire lifetime of this value. The
    /// arrays must not be mutated while the value is used. `argv` must have a
    /// non-null first entry and both arrays must end in one null pointer.
    #[inline]
    pub unsafe fn new(
        path: &'a core::ffi::CStr,
        argv: &'a [*const u8],
        envp: &'a [*const u8],
    ) -> Result<Self> {
        if argv.len() < 2
            || envp.is_empty()
            || argv[0].is_null()
            || !argv.last().is_some_and(|pointer| pointer.is_null())
            || !envp.last().is_some_and(|pointer| pointer.is_null())
        {
            return Err(crate::Errno::INVAL);
        }
        Ok(Self { path, argv, envp })
    }

    /// Executes the caller-owned specification in the current process.
    #[inline]
    pub fn exec(self) -> Result<core::convert::Infallible> {
        // SAFETY: `BorrowedExec::new` documented and checked the array shape;
        // its unsafe contract supplies the pointed-to C-string validity.
        match unsafe {
            crabc_core::process::execve_raw(
                self.path.as_ptr().cast(),
                self.argv.as_ptr(),
                self.envp.as_ptr(),
            )
        } {
            Err(error) => Err(error),
            Ok(()) => panic!("Linux execve unexpectedly returned success"),
        }
    }
}

/// A descriptor action prepared in the parent for a child exec path.
///
/// The source borrow keeps the descriptor open while a [`PreparedExec`] is
/// used. Destination descriptor numbers intentionally remain raw because they
/// identify child namespace slots rather than a parent-owned resource.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub enum FdAction<'fd> {
    /// Close this descriptor in the child before exec.
    Close(BorrowedFd<'fd>),
    /// Duplicate `from` onto `to` in the child before exec.
    Dup2 { from: BorrowedFd<'fd>, to: RawFd },
}

#[cfg(feature = "alloc")]
impl<'fd> FdAction<'fd> {
    /// Prepares a child close action while retaining a borrow of `fd`.
    #[inline]
    pub fn close<Fd: AsFd + ?Sized>(fd: &'fd Fd) -> Self {
        Self::Close(fd.as_fd())
    }

    /// Prepares a child `dup2` action while retaining a borrow of `from`.
    #[inline]
    pub fn dup2<Fd: AsFd + ?Sized>(from: &'fd Fd, to: RawFd) -> Self {
        Self::Dup2 { from: from.as_fd(), to }
    }
}

/// Process-state changes applied in the child before an exec.
///
/// The builder is intentionally narrow: every child operation is a direct
/// async-signal-safe syscall and preparation performs no hidden work after
/// `fork`. More complex POSIX spawn attributes remain separate capability
/// groups rather than silently introducing child-side allocation or libc use.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SpawnOptions<'mask> {
    process_group: Option<Option<Pid>>,
    new_session: bool,
    signal_mask: Option<&'mask crate::signal::SignalSet>,
}

#[cfg(feature = "alloc")]
impl<'mask> SpawnOptions<'mask> {
    /// Creates options which inherit process group, session, and signal mask.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { process_group: None, new_session: false, signal_mask: None }
    }

    /// Assigns the child to `pgid`; `None` creates a group led by the child.
    #[inline]
    #[must_use]
    pub const fn process_group(mut self, pgid: Option<Pid>) -> Self {
        self.process_group = Some(pgid);
        self
    }

    /// Makes the child a new session leader before exec.
    #[inline]
    #[must_use]
    pub const fn new_session(mut self, enabled: bool) -> Self {
        self.new_session = enabled;
        self
    }

    /// Replaces the child's signal mask before exec.
    #[inline]
    #[must_use]
    pub const fn signal_mask(mut self, mask: &'mask crate::signal::SignalSet) -> Self {
        self.signal_mask = Some(mask);
        self
    }
}

/// A validated, allocation-complete program image ready for direct exec or a
/// safe prepared fork/exec spawn.
///
/// Paths and argument/environment storage are copied and their null-terminated
/// pointer arrays are built in the parent. [`spawn`](Self::spawn)'s child path
/// therefore performs only direct descriptor/process syscalls, `execve`, an
/// error-pipe write, and `exit_group`.
#[cfg(feature = "alloc")]
pub struct PreparedExec<'fd> {
    path: CString,
    // These owned strings keep the precomputed pointer arrays valid until an
    // exec replaces the process image or this prepared value is dropped.
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_pointers: Vec<*const u8>,
    envp_pointers: Vec<*const u8>,
    actions: Vec<FdAction<'fd>>,
    options: SpawnOptions<'fd>,
}

#[cfg(feature = "alloc")]
impl<'fd> PreparedExec<'fd> {
    /// Resolves and validates a program path plus its argument and environment
    /// strings in the parent process.
    ///
    /// `argv` must contain at least one entry. An empty `envp` deliberately
    /// means an empty environment; this facade never reads or mutates C's
    /// process-global environment behind the caller's back.
    #[inline]
    pub fn new<P: Arg>(path: P, argv: &[&CStr], envp: &[&CStr]) -> Result<Self> {
        if argv.is_empty() {
            return Err(crate::Errno::INVAL);
        }
        path.into_with_c_str(|path| {
            let path = CString::new(path.to_bytes()).map_err(|_| crate::Errno::INVAL)?;
            let argv = copy_c_strings(argv)?;
            let envp = copy_c_strings(envp)?;
            Ok(Self {
                path,
                argv_pointers: c_string_pointers(&argv),
                envp_pointers: c_string_pointers(&envp),
                _argv: argv,
                _envp: envp,
                actions: Vec::new(),
                options: SpawnOptions::new(),
            })
        })
    }

    /// Replaces the prepared child descriptor actions. The vector copy occurs
    /// now, before any fork, rather than in the child execution path.
    #[inline]
    #[must_use]
    pub fn with_actions(mut self, actions: &[FdAction<'fd>]) -> Self {
        self.actions.extend_from_slice(actions);
        self
    }

    /// Replaces the prepared child process-state options.
    #[inline]
    #[must_use]
    pub const fn with_options(mut self, options: SpawnOptions<'fd>) -> Self {
        self.options = options;
        self
    }

    /// Returns the fully encoded executable path.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &CStr {
        self.path.as_c_str()
    }

    /// Executes this prepared image in the current process.
    ///
    /// Descriptor and process-state actions run first, so a failed exec may
    /// leave those caller-visible process changes in place. Use
    /// [`Self::spawn`] when failure isolation is required.
    ///
    /// # Safety
    ///
    /// The caller must exclusively control every descriptor affected by an
    /// [`FdAction`], including its destination slot, until this call either
    /// replaces the process image or returns an error. In particular, a close
    /// action can invalidate the owner from which its source was borrowed.
    /// The caller must also own the process-wide effects of the configured
    /// session, process-group, and signal-mask options if exec fails.
    #[inline]
    pub unsafe fn exec(&self) -> Result<Infallible> {
        self.apply_child_setup()?;
        self.exec_no_setup()
    }

    /// Spawns this image with a `CLOEXEC` error pipe.
    ///
    /// The parent receives an `Errno` if child setup or `execve` fails and
    /// reaps that failed child before returning. A successful exec closes the
    /// pipe atomically via `CLOEXEC`, after which this returns a typed child.
    #[inline]
    pub fn spawn(&self) -> Result<Child> {
        let (reader, initial_writer) = crabc_core::pipe::pipe2(crabc_core::io::O_CLOEXEC)?;
        let writer = match reserve_child_error_fd(initial_writer, &self.actions) {
            Ok(writer) => writer,
            Err(error) => {
                let _ = crabc_core::io::close(reader);
                let _ = crabc_core::io::close(initial_writer);
                return Err(error);
            }
        };
        match unsafe { fork() } {
            Err(error) => {
                let _ = crabc_core::io::close(reader);
                let _ = crabc_core::io::close(writer);
                Err(error)
            }
            Ok(ForkResult::Parent { child }) => {
                let _ = crabc_core::io::close(writer);
                let result = read_child_exec_result(reader);
                if let Err(error) = result {
                    let _ = waitpid(Some(child), WaitOptions::empty());
                    Err(error)
                } else {
                    Ok(Child { pid: child })
                }
            }
            Ok(ForkResult::Child) => {
                let _ = crabc_core::io::close(reader);
                let error = match self.apply_child_setup().and_then(|()| self.exec_no_setup()) {
                    Err(error) => error,
                    Ok(never) => match never {},
                };
                write_child_exec_error_and_exit(writer, error)
            }
        }
    }

    #[inline]
    fn apply_child_setup(&self) -> Result<()> {
        if self.options.new_session {
            crabc_core::process::setsid()?;
        }
        if let Some(process_group) = self.options.process_group {
            crabc_core::process::setpgid(0, Pid::as_raw(process_group))?;
        }
        if let Some(mask) = self.options.signal_mask {
            // SAFETY: `mask` is a one-word kernel signal-set value retained by
            // this prepared object's borrow through the direct syscall.
            unsafe {
                crabc_core::signal::rt_sigprocmask_raw(2, mask.kernel_bits(), core::ptr::null_mut())?;
            }
        }
        for action in &self.actions {
            match *action {
                FdAction::Close(fd) => crabc_core::io::close(fd.as_raw_fd())?,
                FdAction::Dup2 { from, to } => crabc_core::io::dup2(from.as_raw_fd(), to)?,
            }
        }
        Ok(())
    }

    #[inline]
    fn exec_no_setup(&self) -> Result<Infallible> {
        // SAFETY: `PreparedExec` owns every NUL-terminated string and both
        // terminal-null pointer arrays for the entire syscall. Linux execve
        // does not return after success.
        match unsafe {
            crabc_core::process::execve_raw(
                self.path.as_ptr().cast(),
                self.argv_pointers.as_ptr(),
                self.envp_pointers.as_ptr(),
            )
        } {
            Err(error) => Err(error),
            Ok(()) => panic!("Linux execve unexpectedly returned success"),
        }
    }
}

/// A successfully spawned native child process.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Child {
    pid: Pid,
}

#[cfg(feature = "alloc")]
impl Child {
    /// Returns the child's process ID.
    #[inline]
    #[must_use]
    pub const fn pid(self) -> Pid {
        self.pid
    }

    /// Waits for this child. `NOHANG` may return `None` without consuming the
    /// child, while a state report returns its decoded wait status.
    #[inline]
    pub fn wait(self, options: WaitOptions) -> Result<Option<WaitStatus>> {
        waitpid(Some(self.pid), options).map(|result| result.map(|(_, status)| status))
    }
}

#[cfg(feature = "alloc")]
#[inline]
fn copy_c_strings(values: &[&CStr]) -> Result<Vec<CString>> {
    let mut copied = Vec::with_capacity(values.len());
    for value in values {
        copied.push(CString::new(value.to_bytes()).map_err(|_| crate::Errno::INVAL)?);
    }
    Ok(copied)
}

#[cfg(feature = "alloc")]
#[inline]
fn c_string_pointers(values: &[CString]) -> Vec<*const u8> {
    let mut pointers = Vec::with_capacity(values.len() + 1);
    for value in values {
        pointers.push(value.as_ptr().cast());
    }
    pointers.push(core::ptr::null());
    pointers
}

/// Reserves a close-on-exec child error descriptor outside every `dup2` target.
///
/// A prepared action may legally replace any raw child descriptor. Relocating
/// the private error writer first preserves `spawn`'s promise to report child
/// setup and exec errors rather than mistaking a clobbered error pipe for a
/// successful exec.
#[cfg(feature = "alloc")]
fn reserve_child_error_fd(writer: RawFd, actions: &[FdAction<'_>]) -> Result<RawFd> {
    let mut minimum = 3;
    loop {
        let candidate = crabc_core::io::fcntl_dupfd_cloexec(writer, minimum)?;
        let collides = actions.iter().any(|action| match action {
            FdAction::Dup2 { to, .. } => *to == candidate,
            FdAction::Close(_) => false,
        });
        if !collides {
            let _ = crabc_core::io::close(writer);
            return Ok(candidate);
        }
        let _ = crabc_core::io::close(candidate);
        if candidate == i32::MAX {
            return Err(crate::Errno::MFILE);
        }
        minimum = candidate + 1;
    }
}

#[cfg(feature = "alloc")]
#[inline]
fn read_child_exec_result(reader: RawFd) -> Result<()> {
    let mut bytes = [0_u8; core::mem::size_of::<i32>()];
    let mut filled = 0;
    while filled != bytes.len() {
        match crabc_core::io::read(reader, &mut bytes[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(Errno::INTR) => continue,
            Err(error) => {
                let _ = crabc_core::io::close(reader);
                return Err(error);
            }
        }
    }
    let _ = crabc_core::io::close(reader);
    if filled == 0 {
        return Ok(());
    }
    if filled != bytes.len() {
        return Err(Errno::IO);
    }
    let raw = i32::from_ne_bytes(bytes);
    Err(Errno::from_raw(raw).unwrap_or(Errno::IO))
}

#[cfg(feature = "alloc")]
#[inline]
fn write_child_exec_error_and_exit(writer: RawFd, error: Errno) -> ! {
    let bytes = error.raw().to_ne_bytes();
    let mut written = 0;
    while written != bytes.len() {
        match crabc_core::io::write(writer, &bytes[written..]) {
            Ok(0) => break,
            Ok(count) => written += count,
            Err(Errno::INTR) => continue,
            Err(_) => break,
        }
    }
    let _ = crabc_core::io::close(writer);
    exit_immediately(127)
}
