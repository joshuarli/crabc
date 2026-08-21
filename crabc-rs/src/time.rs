//! Direct Linux/AArch64 clock queries.
//!
//! Known clocks use an infallible interface matching Rustix: each enum value
//! is supported by Linux at runtime. Dynamic descriptor clocks and clock
//! mutation remain outside this first M3 vertical slice.

use core::mem::MaybeUninit;
use bitflags::bitflags;

use crate::{AsFd, Errno, OwnedFd, Result};

pub use crate::fs::{Nsecs, Secs, Timespec};

/// Linux `CLOCK_*` identifiers which are known to be supported at runtime.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum ClockId {
    /// `CLOCK_REALTIME`.
    Realtime = 0,
    /// `CLOCK_MONOTONIC`.
    Monotonic = 1,
    /// `CLOCK_PROCESS_CPUTIME_ID`.
    ProcessCPUTime = 2,
    /// `CLOCK_THREAD_CPUTIME_ID`.
    ThreadCPUTime = 3,
    /// `CLOCK_MONOTONIC_RAW`.
    MonotonicRaw = 4,
    /// `CLOCK_REALTIME_COARSE`.
    RealtimeCoarse = 5,
    /// `CLOCK_MONOTONIC_COARSE`.
    MonotonicCoarse = 6,
    /// `CLOCK_BOOTTIME`.
    Boottime = 7,
    /// `CLOCK_REALTIME_ALARM`.
    RealtimeAlarm = 8,
    /// `CLOCK_BOOTTIME_ALARM`.
    BoottimeAlarm = 9,
}

impl TryFrom<i32> for ClockId {
    type Error = Errno;

    #[inline]
    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            2 => Ok(Self::ProcessCPUTime),
            3 => Ok(Self::ThreadCPUTime),
            4 => Ok(Self::MonotonicRaw),
            5 => Ok(Self::RealtimeCoarse),
            6 => Ok(Self::MonotonicCoarse),
            7 => Ok(Self::Boottime),
            8 => Ok(Self::RealtimeAlarm),
            9 => Ok(Self::BoottimeAlarm),
            _ => Err(Errno::RANGE),
        }
    }
}

/// Returns a known Linux clock's resolution.
#[must_use]
#[inline]
pub fn clock_getres(id: ClockId) -> Timespec {
    clock_query(id, crabc_core::time::clock_getres_raw)
}

/// Returns a known Linux clock's current value.
#[must_use]
#[inline]
pub fn clock_gettime(id: ClockId) -> Timespec {
    clock_query(id, crabc_core::time::clock_gettime_raw)
}

bitflags! {
    /// Flags accepted by Linux `timerfd_create`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct TimerfdFlags: u32 {
        /// `TFD_NONBLOCK`.
        const NONBLOCK = 0x0000_0800;
        /// `TFD_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

bitflags! {
    /// Flags accepted by Linux `timerfd_settime`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct TimerfdTimerFlags: u32 {
        /// `TFD_TIMER_ABSTIME`.
        const ABSTIME = 0x1;
        /// `TFD_TIMER_CANCEL_ON_SET`.
        const CANCEL_ON_SET = 0x2;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

/// Clocks accepted by Linux `timerfd_create`.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum TimerfdClockId {
    /// `CLOCK_REALTIME`.
    Realtime = 0,
    /// `CLOCK_MONOTONIC`.
    Monotonic = 1,
    /// `CLOCK_BOOTTIME`.
    Boottime = 7,
    /// `CLOCK_REALTIME_ALARM`.
    RealtimeAlarm = 8,
    /// `CLOCK_BOOTTIME_ALARM`.
    BoottimeAlarm = 9,
}

/// Linux `struct itimerspec` used by timerfd operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct Itimerspec {
    /// Interval between expirations.
    pub it_interval: Timespec,
    /// Initial expiration or absolute expiration time.
    pub it_value: Timespec,
}

/// Creates a Linux timer descriptor.
#[inline]
pub fn timerfd_create(clock_id: TimerfdClockId, flags: TimerfdFlags) -> Result<OwnedFd> {
    let fd = crabc_core::time::timerfd_create(clock_id as i32, flags.bits())?;
    // SAFETY: a successful Linux `timerfd_create` returns one new,
    // non-negative, uniquely-owned descriptor.
    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

/// Arms or disarms a Linux timer descriptor and returns its previous setting.
#[inline]
pub fn timerfd_settime<Fd: AsFd>(
    fd: Fd,
    flags: TimerfdTimerFlags,
    new_value: &Itimerspec,
) -> Result<Itimerspec> {
    let fd = fd.as_fd();
    let mut old_value = MaybeUninit::<Itimerspec>::uninit();
    // SAFETY: `new_value` and `old_value` have the Linux/AArch64
    // `struct itimerspec` layout, and the output is initialized on success.
    unsafe {
        crabc_core::time::timerfd_settime_raw(
            fd.as_raw_fd(),
            flags.bits(),
            (new_value as *const Itimerspec).cast(),
            old_value.as_mut_ptr().cast(),
        )?;
        Ok(old_value.assume_init())
    }
}

/// Returns a Linux timer descriptor's current setting.
#[inline]
pub fn timerfd_gettime<Fd: AsFd>(fd: Fd) -> Result<Itimerspec> {
    let fd = fd.as_fd();
    let mut value = MaybeUninit::<Itimerspec>::uninit();
    // SAFETY: `value` has exactly the Linux/AArch64 `struct itimerspec`
    // layout and Linux initializes it on success.
    unsafe {
        crabc_core::time::timerfd_gettime_raw(fd.as_raw_fd(), value.as_mut_ptr().cast())?;
        Ok(value.assume_init())
    }
}

fn clock_query(
    id: ClockId,
    query: unsafe fn(i32, *mut u8) -> Result<()>,
) -> Timespec {
    let mut value = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `value` has exactly the Linux/AArch64 `timespec` layout and
    // the enum contains only statically supported Linux clock identifiers.
    match unsafe { query(id as i32, value.as_mut_ptr().cast()) } {
        Ok(()) => unsafe { value.assume_init() },
        Err(error) => panic!("known Linux clock query failed with errno {}", error.raw()),
    }
}
