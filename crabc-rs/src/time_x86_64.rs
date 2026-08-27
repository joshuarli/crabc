//! Bounded native Linux/x86-64 clock queries, relative `nanosleep`, private
//! `clock_nanosleep`, read-only interval-timer queries, and timerfds.
//!
//! This staged facade admits only validated realtime, monotonic,
//! monotonic-raw, and process-CPU observations, typed realtime milliseconds,
//! typed relative sleep and private clock-sleep outcomes. Interrupted sleeps
//! preserve the kernel's remainder instead of retrying or hiding `EINTR`. It
//! intentionally
//! does not expose AArch64 calendar, POSIX-timer, timezone, interval-timer
//! control, or clock-mutation APIs, nor a C sleep ABI, until their x86-64
//! records and behavior have independent evidence. The interval-timer query
//! and timerfd slices are direct kernel boundaries; neither selects a C time
//! API or promotes x86-64 platform support.

use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::time::Duration;
use bitflags::bitflags;
use crabc_core::time::{
    KernelItimerval, KernelItimervalTimeval, KernelItimerspec, KernelTimespec,
};
use crate::{AsFd, Errno, OwnedFd, Result};

/// Nanoseconds in one second.
///
/// This preserves the public scalar type of the corresponding AArch64
/// constant. Kernel `timespec` fields remain signed 64-bit words and are
/// checked against the widened value at this ABI boundary.
pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

const CLOCK_NANOSLEEP_TIMER_ABSTIME: u32 = 1;

/// Linux clock identifiers admitted by this x86-64 foundation slice.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ClockId {
    /// `CLOCK_REALTIME` (Unix epoch wall clock).
    Realtime = 0,
    /// `CLOCK_MONOTONIC` (boot-relative, nondecreasing clock).
    Monotonic = 1,
    /// `CLOCK_PROCESS_CPUTIME_ID` (CPU time consumed by this process).
    ProcessCPUTime = 2,
    /// `CLOCK_MONOTONIC_RAW` (hardware-derived non-adjusted clock).
    MonotonicRaw = 4,
}

impl TryFrom<i32> for ClockId {
    type Error = Errno;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            2 => Ok(Self::ProcessCPUTime),
            4 => Ok(Self::MonotonicRaw),
            _ => Err(Errno::INVAL),
        }
    }
}

/// Linux/x86-64 `struct timespec` represented as a typed native observation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Timespec {
    /// Seconds in the selected clock's epoch.
    pub tv_sec: i64,
    /// Nanoseconds within `tv_sec`, normalized by Linux on success.
    pub tv_nsec: i64,
}

const _: () = assert!(core::mem::size_of::<Timespec>() == 16);
const _: () = assert!(core::mem::align_of::<Timespec>() == 8);

/// The result of a relative native sleep request.
///
/// An interrupted sleep is not retried or converted into a hidden success:
/// the kernel-provided remaining duration is returned explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepOutcome {
    /// The requested duration elapsed without interruption.
    Completed,
    /// A signal interrupted the sleep before completion.
    Interrupted {
        /// Duration the kernel reports as still remaining.
        remaining: Duration,
    },
}

/// Errors produced while converting or issuing a native sleep request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleepError {
    /// The request exceeded Linux/x86-64's signed `timespec.tv_sec` range.
    DurationOutOfRange,
    /// A mode-specific timespec request had a non-canonical `tv_nsec` field.
    ///
    /// Relative `nanosleep` constructs its timespec from [`Duration`] and
    /// therefore cannot produce this variant; it remains part of the shared
    /// sleep error vocabulary for exact facade parity.
    InvalidRequest,
    /// The kernel returned an invalid remaining `timespec` after `EINTR`.
    InvalidRemaining,
    /// A Linux syscall failure, kept as a typed value.
    ///
    /// Relative `EINTR` is represented by [`SleepOutcome::Interrupted`].
    Kernel(Errno),
}

impl SleepError {
    /// Returns the underlying kernel error for syscall failures.
    #[must_use]
    pub const fn kernel_errno(self) -> Option<Errno> {
        match self {
            Self::Kernel(error) => Some(error),
            Self::DurationOutOfRange | Self::InvalidRequest | Self::InvalidRemaining => None,
        }
    }
}

impl Timespec {
    fn from_kernel(value: KernelTimespec) -> Result<Self> {
        if !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
            return Err(Errno::RANGE);
        }
        Ok(Self { tv_sec: value.tv_sec, tv_nsec: value.tv_nsec })
    }
}

/// Sleeps for a relative duration through Linux `nanosleep`.
///
/// `Duration` is converted explicitly to the Linux/x86-64 timespec contract:
/// seconds must fit in `i64`, and nanoseconds are already guaranteed by Rust
/// to be below one billion. `EINTR` is represented by
/// [`SleepOutcome::Interrupted`] with the kernel's remaining duration; other
/// kernel failures are returned as [`SleepError::Kernel`]. No retry, C sleep
/// ABI, TLS `errno`, or allocation is involved.
#[inline]
pub fn nanosleep(duration: Duration) -> core::result::Result<SleepOutcome, SleepError> {
    let request = duration_to_timespec(duration)?;
    let mut remaining = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `request` is an initialized Linux/x86-64 timespec and
    // `remaining` is writable storage for the kernel's interrupted result.
    match unsafe {
        crabc_core::time::nanosleep_raw(
            (&request as *const Timespec).cast(),
            remaining.as_mut_ptr().cast(),
        )
    } {
        Ok(()) => Ok(SleepOutcome::Completed),
        Err(Errno::INTR) => {
            // SAFETY: Linux initializes the remaining timespec whenever this
            // syscall returns EINTR.
            let remaining = unsafe { remaining.assume_init() };
            Ok(SleepOutcome::Interrupted {
                remaining: duration_from_timespec(remaining)?,
            })
        }
        Err(error) => Err(SleepError::Kernel(error)),
    }
}

/// Sleeps for a relative duration on a selected Linux clock.
///
/// This is the typed x86-64 form of `clock_nanosleep`: `duration` is
/// converted to an x86-64 `timespec`, and an `EINTR` result includes the
/// kernel-provided remaining duration. Other syscall failures remain typed in
/// [`SleepError::Kernel`].
#[inline]
pub fn clock_nanosleep_relative(
    id: ClockId,
    duration: Duration,
) -> core::result::Result<SleepOutcome, SleepError> {
    let request = duration_to_timespec(duration)?;
    let mut remaining = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `request` is an initialized Linux/x86-64 timespec and
    // `remaining` is writable storage for the kernel's interrupted result.
    match unsafe {
        crabc_core::time::clock_nanosleep_raw(
            id as i32,
            0,
            (&request as *const Timespec).cast(),
            remaining.as_mut_ptr().cast(),
        )
    } {
        Ok(()) => Ok(SleepOutcome::Completed),
        Err(Errno::INTR) => {
            // SAFETY: Linux initializes the remaining timespec whenever this
            // relative syscall returns EINTR.
            let remaining = unsafe { remaining.assume_init() };
            Ok(SleepOutcome::Interrupted {
                remaining: duration_from_timespec(remaining)?,
            })
        }
        Err(error) => Err(SleepError::Kernel(error)),
    }
}

/// Sleeps until an absolute time on a selected Linux clock.
///
/// `deadline` uses the Linux/x86-64 `timespec` contract: `tv_sec` is signed
/// 64-bit seconds and `tv_nsec` must be in `0..1_000_000_000`. No
/// normalization is performed, so a past or negative deadline is passed to
/// the selected clock unchanged. A malformed `tv_nsec` is rejected before
/// the syscall. Linux reports an interrupted absolute sleep as
/// [`SleepError::Kernel`] containing `EINTR`; no remaining duration is
/// returned or invented because `TIMER_ABSTIME` has no remaining output.
#[inline]
pub fn clock_nanosleep_absolute(
    id: ClockId,
    deadline: Timespec,
) -> core::result::Result<(), SleepError> {
    if !valid_timespec(deadline) {
        return Err(SleepError::InvalidRequest);
    }
    // SAFETY: `deadline` has the validated Linux/x86-64 timespec range. The
    // null remaining pointer is required for an absolute request.
    match unsafe {
        crabc_core::time::clock_nanosleep_raw(
            id as i32,
            CLOCK_NANOSLEEP_TIMER_ABSTIME,
            (&deadline as *const Timespec).cast(),
            core::ptr::null_mut(),
        )
    } {
        Ok(()) => Ok(()),
        Err(error) => Err(SleepError::Kernel(error)),
    }
}

#[inline]
fn duration_to_timespec(duration: Duration) -> core::result::Result<Timespec, SleepError> {
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| SleepError::DurationOutOfRange)?;
    Ok(Timespec {
        tv_sec: seconds,
        tv_nsec: duration.subsec_nanos() as i64,
    })
}

#[inline]
fn duration_from_timespec(timespec: Timespec) -> core::result::Result<Duration, SleepError> {
    if timespec.tv_sec < 0 || !(0..i64::from(NANOS_PER_SECOND)).contains(&timespec.tv_nsec) {
        return Err(SleepError::InvalidRemaining);
    }
    Ok(Duration::new(
        timespec.tv_sec as u64,
        timespec.tv_nsec as u32,
    ))
}

#[inline]
fn valid_timespec(timespec: Timespec) -> bool {
    timespec.tv_nsec >= 0 && timespec.tv_nsec < i64::from(NANOS_PER_SECOND)
}

/// A UTC realtime observation reduced to whole milliseconds.
///
/// The seconds field remains signed so observations before the Unix epoch are
/// representable. The millisecond field is normalized to `0..1000` by
/// truncating the kernel's validated nanosecond remainder rather than
/// rounding it. Private fields prevent callers from manufacturing a
/// non-canonical value.
#[derive(Debug, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealtimeMillis {
    seconds: i64,
    milliseconds: u16,
}

impl RealtimeMillis {
    #[inline]
    fn from_timespec(value: Timespec) -> Option<Self> {
        if !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
            return None;
        }
        Some(Self {
            seconds: value.tv_sec,
            milliseconds: (value.tv_nsec / 1_000_000) as u16,
        })
    }

    /// Returns signed whole seconds since the Unix epoch.
    #[inline]
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns the truncated millisecond remainder in `0..1000`.
    #[inline]
    #[must_use]
    pub const fn milliseconds(self) -> u16 {
        self.milliseconds
    }
}

/// Reads a validated observation from one admitted Linux clock.
pub fn clock_gettime(clock: ClockId) -> Result<Timespec> {
    Timespec::from_kernel(crabc_core::time::clock_gettime(clock as i32)?)
}

/// Reads a validated resolution for one admitted Linux clock.
pub fn clock_getres(clock: ClockId) -> Result<Timespec> {
    Timespec::from_kernel(crabc_core::time::clock_getres(clock as i32)?)
}

/// Reads the current UTC wall-clock value using the admitted realtime clock.
pub fn timespec_get() -> Result<Timespec> {
    clock_gettime(ClockId::Realtime)
}

/// Reads `CLOCK_REALTIME` and truncates its subsecond part to milliseconds.
///
/// The direct x86-64 clock query returns a normalized kernel `timespec`; no C
/// `timeb` record, timezone state, allocation, or thread-local `errno` is
/// involved. A malformed kernel result is rejected before a public value is
/// exposed.
#[inline]
pub fn realtime_millis() -> Result<RealtimeMillis> {
    RealtimeMillis::from_timespec(clock_gettime(ClockId::Realtime)?).ok_or(Errno::RANGE)
}

/// Returns CPU time consumed by the calling process as a native duration.
///
/// This observes Linux's `CLOCK_PROCESS_CPUTIME_ID`, which accumulates user
/// and system CPU time across the process rather than elapsed wall time. The
/// known-clock result is infallible by convention; malformed or failed kernel
/// data cannot be represented as a `Duration` and is treated as an impossible
/// direct-kernel contract failure.
#[inline]
#[must_use]
pub fn process_cpu_time() -> Duration {
    let value = clock_gettime(ClockId::ProcessCPUTime)
        .unwrap_or_else(|_| panic!("Linux process CPU clock query failed"));
    if value.tv_sec < 0 || !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
        panic!("Linux process CPU clock returned an invalid timespec");
    }
    Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
}

/// The three Linux process interval timers admitted by [`getitimer`].
///
/// This is a closed vocabulary: unsupported selector integers cannot cross
/// the safe Rust boundary. `Real` measures elapsed wall-clock time, `Virtual`
/// measures user CPU time, and `Profiler` measures user plus system CPU time.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum IntervalTimerKind {
    /// `ITIMER_REAL` (selector `0`).
    Real = 0,
    /// `ITIMER_VIRTUAL` (selector `1`).
    Virtual = 1,
    /// `ITIMER_PROF` (selector `2`).
    Profiler = 2,
}

impl TryFrom<i32> for IntervalTimerKind {
    type Error = Errno;

    /// Converts one Linux `ITIMER_*` selector, rejecting unsupported values.
    #[inline]
    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Real),
            1 => Ok(Self::Virtual),
            2 => Ok(Self::Profiler),
            _ => Err(Errno::INVAL),
        }
    }
}

/// A validated interval-timer observation returned by Linux `getitimer`.
///
/// Both durations are non-negative and have microsecond precision, because
/// Linux reports signed seconds plus a normalized microsecond remainder. The
/// fields are private: this query-only x86-64 slice exposes no interval-timer
/// control operation that can consume a caller-manufactured setting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IntervalTimerValue {
    interval: Duration,
    value: Duration,
}

impl IntervalTimerValue {
    /// Returns the interval between expirations, or zero for a one-shot timer.
    #[must_use]
    #[inline]
    pub const fn interval(self) -> Duration {
        self.interval
    }

    /// Returns the time remaining until the next expiration, or zero when the
    /// timer is disarmed.
    #[must_use]
    #[inline]
    pub const fn value(self) -> Duration {
        self.value
    }
}

/// Errors returned by the native `getitimer` query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetitimerError {
    /// Linux returned a malformed signed timeval or microsecond remainder.
    InvalidKernelValue,
    /// The direct Linux syscall failed.
    Kernel(Errno),
}

impl GetitimerError {
    /// Returns the underlying Linux errno for a syscall failure.
    #[must_use]
    #[inline]
    pub const fn kernel_errno(self) -> Option<Errno> {
        match self {
            Self::Kernel(error) => Some(error),
            Self::InvalidKernelValue => None,
        }
    }
}

/// Reads one process interval timer through the direct Linux syscall.
///
/// This query does not arm, disarm, or otherwise mutate process timer state.
/// Linux's signed timeval fields are validated before conversion to
/// [`IntervalTimerValue`]; malformed kernel output is never exposed as a
/// negative or non-canonical Rust duration. No libc, C ABI, vDSO, allocation,
/// or TLS `errno` is involved.
#[inline]
pub fn getitimer(
    kind: IntervalTimerKind,
) -> core::result::Result<IntervalTimerValue, GetitimerError> {
    let mut value = MaybeUninit::<KernelItimerval>::uninit();
    // SAFETY: `value` is writable storage for one exact x86-64 Linux
    // `itimerval` result and remains live for the direct syscall.
    unsafe {
        crabc_core::time::getitimer_raw(kind as i32, value.as_mut_ptr())
            .map_err(GetitimerError::Kernel)?;
    }
    // SAFETY: Linux initializes all four result words on successful return.
    let value = unsafe { value.assume_init() };
    let interval = duration_from_itimerval_timeval(value.it_interval)
        .ok_or(GetitimerError::InvalidKernelValue)?;
    let value = duration_from_itimerval_timeval(value.it_value)
        .ok_or(GetitimerError::InvalidKernelValue)?;
    Ok(IntervalTimerValue { interval, value })
}

/// Converts one signed Linux interval-timer timeval into a canonical Rust
/// duration. Linux's `getitimer` ABI reports non-negative values with
/// `tv_usec` in `0..1_000_000`; every other record is rejected.
#[inline]
fn duration_from_itimerval_timeval(value: KernelItimervalTimeval) -> Option<Duration> {
    if value.tv_sec < 0 || value.tv_usec < 0 || value.tv_usec >= 1_000_000 {
        return None;
    }
    Some(Duration::new(
        value.tv_sec as u64,
        (value.tv_usec as u32) * 1_000,
    ))
}

#[cfg(test)]
mod interval_timer_tests {
    use super::{duration_from_itimerval_timeval, Duration, KernelItimervalTimeval};

    #[test]
    fn x86_64_interval_timer_timeval_rejects_malformed_kernel_fields() {
        assert_eq!(
            duration_from_itimerval_timeval(KernelItimervalTimeval {
                tv_sec: 12,
                tv_usec: 345,
            }),
            Some(Duration::new(12, 345_000)),
        );
        assert_eq!(
            duration_from_itimerval_timeval(KernelItimervalTimeval {
                tv_sec: -1,
                tv_usec: 0,
            }),
            None,
        );
        assert_eq!(
            duration_from_itimerval_timeval(KernelItimervalTimeval {
                tv_sec: 0,
                tv_usec: -1,
            }),
            None,
        );
        assert_eq!(
            duration_from_itimerval_timeval(KernelItimervalTimeval {
                tv_sec: 0,
                tv_usec: 1_000_000,
            }),
            None,
        );
    }
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
    }
}

bitflags! {
    /// Flags accepted by Linux `timerfd_settime`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct TimerfdTimerFlags: u32 {
        /// `TFD_TIMER_ABSTIME`.
        const ABSTIME = 0x0000_0001;
        /// `TFD_TIMER_CANCEL_ON_SET`.
        const CANCEL_ON_SET = 0x0000_0002;
    }
}

/// Clocks admitted by the Linux/x86-64 timerfd descriptor slice.
///
/// `CLOCK_REALTIME` and `CLOCK_MONOTONIC` cover ordinary wall-clock and
/// monotonic descriptor timers. Wake-alarm and boot-time timer policies remain
/// deferred because they carry separate suspend and capability behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum TimerfdClockId {
    /// `CLOCK_REALTIME`.
    Realtime = 0,
    /// `CLOCK_MONOTONIC`.
    Monotonic = 1,
}

/// Linux/x86-64 `struct itimerspec` used by timerfd operations.
///
/// Both fields are direct Linux `timespec` records. Input values must have a
/// non-negative seconds field and a nanosecond field in `0..1_000_000_000`;
/// [`timerfd_settime`] rejects malformed records before the kernel boundary.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Itimerspec {
    /// Interval between expirations, or zero for a one-shot timer.
    pub it_interval: Timespec,
    /// Initial or absolute expiration, or zero to disarm the timer.
    pub it_value: Timespec,
}

const _: () = assert!(core::mem::size_of::<Itimerspec>() == 32);
const _: () = assert!(core::mem::align_of::<Itimerspec>() == 8);
const _: () = assert!(core::mem::offset_of!(Itimerspec, it_interval) == 0);
const _: () = assert!(core::mem::offset_of!(Itimerspec, it_value) == 16);

impl Default for Itimerspec {
    #[inline]
    fn default() -> Self {
        Self {
            it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: Timespec { tv_sec: 0, tv_nsec: 0 },
        }
    }
}

/// Creates a Linux/x86-64 timer descriptor.
#[inline]
pub fn timerfd_create(clock_id: TimerfdClockId, flags: TimerfdFlags) -> Result<OwnedFd> {
    let fd = crabc_core::time::timerfd_create(clock_id as i32, flags.bits())?;
    // SAFETY: successful `timerfd_create` returns one fresh, non-negative,
    // uniquely owned Linux descriptor.
    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

/// Arms or disarms a Linux/x86-64 timer descriptor and returns its previous
/// setting.
///
/// The interval and initial value have the exact kernel `itimerspec` shape.
/// A zero initial value disarms the descriptor. `ABSTIME` changes the initial
/// value from a relative duration to an absolute value in the selected clock.
/// Linux validates timerfd flag combinations directly.
#[inline]
pub fn timerfd_settime<Fd: AsFd>(
    fd: Fd,
    flags: TimerfdTimerFlags,
    new_value: &Itimerspec,
) -> Result<Itimerspec> {
    let new_value = itimerspec_to_kernel(*new_value)?;
    let fd = fd.as_fd();
    let mut old_value = MaybeUninit::<KernelItimerspec>::uninit();
    // SAFETY: `new_value` is an initialized exact x86-64 kernel record,
    // `old_value` is writable exact storage, and the descriptor borrow remains
    // open for the complete direct syscall.
    unsafe {
        crabc_core::time::timerfd_settime_raw(
            fd.as_raw_fd(),
            flags.bits(),
            &new_value,
            old_value.as_mut_ptr(),
        )?;
        itimerspec_from_kernel(old_value.assume_init())
    }
}

/// Reads a Linux/x86-64 timer descriptor's current setting.
#[inline]
pub fn timerfd_gettime<Fd: AsFd>(fd: Fd) -> Result<Itimerspec> {
    let fd = fd.as_fd();
    let mut value = MaybeUninit::<KernelItimerspec>::uninit();
    // SAFETY: `value` is exact writable x86-64 kernel storage and the
    // descriptor borrow remains open while Linux initializes the record.
    unsafe {
        crabc_core::time::timerfd_gettime_raw(fd.as_raw_fd(), value.as_mut_ptr())?;
        itimerspec_from_kernel(value.assume_init())
    }
}

#[inline]
fn itimerspec_to_kernel(value: Itimerspec) -> Result<KernelItimerspec> {
    Ok(KernelItimerspec {
        it_interval: timer_timespec_to_kernel(value.it_interval)?,
        it_value: timer_timespec_to_kernel(value.it_value)?,
    })
}

#[inline]
fn timer_timespec_to_kernel(value: Timespec) -> Result<KernelTimespec> {
    if value.tv_sec < 0 || !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
        return Err(Errno::INVAL);
    }
    Ok(KernelTimespec {
        tv_sec: value.tv_sec,
        tv_nsec: value.tv_nsec,
    })
}

#[inline]
fn itimerspec_from_kernel(value: KernelItimerspec) -> Result<Itimerspec> {
    Ok(Itimerspec {
        it_interval: timer_timespec_from_kernel(value.it_interval)?,
        it_value: timer_timespec_from_kernel(value.it_value)?,
    })
}

#[inline]
fn timer_timespec_from_kernel(value: KernelTimespec) -> Result<Timespec> {
    if value.tv_sec < 0 || !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
        return Err(Errno::RANGE);
    }
    Ok(Timespec {
        tv_sec: value.tv_sec,
        tv_nsec: value.tv_nsec,
    })
}
