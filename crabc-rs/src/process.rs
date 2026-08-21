//! Process identifiers, process groups, and signal delivery.
//!
//! These operations issue Linux/AArch64 syscalls through `crabc-core`; they
//! do not use libc's process wrappers or its thread-local `errno` channel.

use core::fmt;
use core::num::NonZeroI32;

use crate::{Result};

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
    /// `SIGCHLD`.
    pub const CHILD: Self = Self(unsafe { NonZeroI32::new_unchecked(17) });
    /// `SIGCONT`.
    pub const CONT: Self = Self(unsafe { NonZeroI32::new_unchecked(18) });
    /// `SIGSTOP`.
    pub const STOP: Self = Self(unsafe { NonZeroI32::new_unchecked(19) });

    /// Returns the raw Linux signal number.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0.get()
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
