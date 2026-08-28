//! Bounded native Linux/x86-64 wall-clock, civil-calendar, advanced
//! clock-query/mutation, owned POSIX timer, relative `nanosleep`, typed
//! `clock_nanosleep`, interval-timer-control, and timerfd operations.
//!
//! This staged facade admits validated Linux clock IDs, typed whole-second and
//! millisecond realtime observations, direct `gettimeofday` wall-clock
//! observations, strict UTC Gregorian conversion, alloc-gated explicit
//! immutable POSIX-TZ/TZif local projections, direct safe clock mutation, and
//! owned POSIX timers without `SIGEV_THREAD` callbacks. Interrupted sleeps
//! preserve the kernel's remainder instead of retrying or hiding `EINTR`. It
//! intentionally does not expose C time/tm APIs, libc `TZ` state, zoneinfo
//! loading, inverse ambiguous-local conversion, C `timer_t`/`sigevent` ABI,
//! or a timer/signal policy framework. The interval-timer and timerfd slices
//! are direct kernel boundaries; none selects a C time API or promotes x86-64
//! platform support.

use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::time::Duration;
use bitflags::bitflags;
use crabc_core::time::{
    KernelItimerval, KernelItimervalTimeval, KernelItimerspec, KernelTimespec,
};
use crate::process::Pid;
use crate::signal::Signal;
use crate::{AsFd, BorrowedFd, Errno, OwnedFd, Result};

pub use crate::civil_time::{
    difftime, gmtime, timegm, CalendarTime, UnixTime, NANOS_PER_SECOND,
};
#[cfg(feature = "alloc")]
pub use crate::civil_time::LocalCalendar;

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
    /// `CLOCK_THREAD_CPUTIME_ID` (CPU time consumed by this thread).
    ThreadCPUTime = 3,
    /// `CLOCK_MONOTONIC_RAW` (hardware-derived non-adjusted clock).
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
    /// `CLOCK_TAI`.
    Tai = 11,
}

impl TryFrom<i32> for ClockId {
    type Error = Errno;

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
            11 => Ok(Self::Tai),
            _ => Err(Errno::INVAL),
        }
    }
}

/// A validated Linux process CPU-clock identifier.
///
/// Linux represents this clock as `(-pid - 1) * 8 + 2`, rather than allocating
/// a timer object. Construction validates the encoded ID with direct
/// `clock_getres`, so safe callers cannot manufacture a clock for a missing or
/// unrelated process.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessClockId(i32);

impl ProcessClockId {
    /// Returns the Linux-encoded `clockid_t` value.
    #[must_use]
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0
    }
}

/// Resolves a process CPU clock without libc or TLS `errno`.
///
/// `None` selects the calling process. Linux reports `EINVAL` when the
/// encoded clock does not resolve; this typed API adopts musl's
/// `clock_getcpuclockid` mapping of that specific condition to `ESRCH` while
/// retaining every other direct kernel error.
pub fn clock_getcpuclockid(pid: Option<Pid>) -> Result<ProcessClockId> {
    // `clockid_t` is signed 32-bit. Reject values whose Linux/musl encoding
    // would wrap into an unrelated ordinary clock before validating it.
    const MAX_ENCODED_PROCESS_PID: i32 = 268_435_455;
    if let Some(pid) = pid {
        if pid.as_raw_pid() > MAX_ENCODED_PROCESS_PID {
            return Err(Errno::SRCH);
        }
    }

    let raw_pid = pid.map_or(0, Pid::as_raw_pid) as u32;
    let encoded = raw_pid.wrapping_neg().wrapping_sub(1).wrapping_shl(3)
        | ClockId::ProcessCPUTime as u32;
    let encoded = encoded as i32;
    let mut resolution = MaybeUninit::<KernelTimespec>::uninit();
    // SAFETY: `resolution` owns one exact x86-64 output record. Success proves
    // that Linux accepted the encoded scalar before it becomes a typed value.
    match unsafe { crabc_core::time::clock_getres_raw(encoded, resolution.as_mut_ptr()) } {
        Err(Errno::INVAL) => Err(Errno::SRCH),
        Err(error) => Err(error),
        Ok(()) => {
            // SAFETY: Linux initialized the full private record on success.
            let _ = unsafe { resolution.assume_init() };
            Ok(ProcessClockId(encoded))
        }
    }
}

/// Linux clock identifiers accepted by [`clock_gettime_dynamic`].
///
/// `Dynamic` borrows a descriptor that must remain open for the query; Linux
/// validates whether it is a clock device. `Process` can only contain a value
/// returned by [`clock_getcpuclockid`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum DynamicClockId<'fd> {
    /// One of the direct known Linux clocks.
    Known(ClockId),
    /// A validated process CPU clock.
    Process(ProcessClockId),
    /// A Linux `CLOCKFD` descriptor-backed clock.
    Dynamic(BorrowedFd<'fd>),
    /// `CLOCK_REALTIME_ALARM`.
    RealtimeAlarm,
    /// `CLOCK_TAI`.
    Tai,
    /// `CLOCK_BOOTTIME`.
    Boottime,
    /// `CLOCK_BOOTTIME_ALARM`.
    BoottimeAlarm,
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

/// Returns the current value of a known, validated-process, or descriptor
/// backed Linux clock.
///
/// Unlike [`clock_gettime`], this operation remains fallible because Linux may
/// reject a dynamic descriptor clock. No libc or TLS `errno` participates;
/// the shared x86 clock dispatcher reaches the validated vDSO or its direct
/// syscall fallback with caller-owned private output storage.
pub fn clock_gettime_dynamic(id: DynamicClockId<'_>) -> Result<Timespec> {
    let mut value = MaybeUninit::<KernelTimespec>::uninit();
    // SAFETY: `value` owns one exact x86-64 Linux timespec output record for
    // the dynamically encoded clock ID.
    unsafe {
        crabc_core::time::clock_gettime_raw(dynamic_clock_id(id), value.as_mut_ptr().cast())?;
        Timespec::from_kernel(value.assume_init())
    }
}

const CLOCKFD: i32 = 3;

#[inline]
fn dynamic_clock_id(id: DynamicClockId<'_>) -> i32 {
    match id {
        DynamicClockId::Known(id) => id as i32,
        DynamicClockId::Process(id) => id.as_raw(),
        DynamicClockId::Dynamic(fd) => ((!fd.as_raw_fd()) << 3) | CLOCKFD,
        DynamicClockId::RealtimeAlarm => ClockId::RealtimeAlarm as i32,
        DynamicClockId::Tai => ClockId::Tai as i32,
        DynamicClockId::Boottime => ClockId::Boottime as i32,
        DynamicClockId::BoottimeAlarm => ClockId::BoottimeAlarm as i32,
    }
}

/// Reads the current UTC wall-clock value using the admitted realtime clock.
pub fn timespec_get() -> Result<Timespec> {
    clock_gettime(ClockId::Realtime)
}

/// Sets one known Linux clock through the direct x86-64 syscall.
///
/// The public `Timespec` is validated before it becomes a private kernel
/// record. Linux remains responsible for settable-clock and privilege checks;
/// callers can use a non-settable clock such as `CLOCK_MONOTONIC` to observe
/// its direct `EINVAL` or `EPERM` result without mutating realtime.
#[inline]
pub fn clock_settime(id: ClockId, timespec: Timespec) -> Result<()> {
    if !valid_timespec(timespec) {
        return Err(Errno::INVAL);
    }
    let timespec = KernelTimespec {
        tv_sec: timespec.tv_sec,
        tv_nsec: timespec.tv_nsec,
    };
    // SAFETY: `timespec` is initialized and canonical. Linux owns the clock
    // mutability and privilege decision.
    unsafe { crabc_core::time::clock_settime_raw(id as i32, &timespec) }
}

/// Reads the current UTC wall clock through direct Linux `gettimeofday`.
///
/// Linux's signed seconds plus normalized microsecond remainder are converted
/// into a Rust-native [`UnixTime`]. A malformed kernel remainder is reported
/// as [`Errno::RANGE`]; no C `timeval`/`tm`, libc `TZ` state, vDSO dispatch,
/// allocation, or thread-local `errno` is involved.
#[inline]
pub fn wall_clock() -> Result<UnixTime> {
    let parts = crabc_core::time::gettimeofday()?;
    UnixTime::from_wall_clock_parts(parts.seconds, parts.microseconds).ok_or(Errno::RANGE)
}

/// Reads the current UTC wall-clock second through the validated realtime
/// clock query. Subsecond precision is intentionally discarded at this
/// typed boundary; no C `time_t`/`tloc` ABI or thread-local `errno` is used.
#[inline]
pub fn time() -> Result<i64> {
    Ok(clock_gettime(ClockId::Realtime)?.tv_sec)
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

/// A validated interval-timer setting accepted by and returned from Linux
/// `getitimer`/`setitimer`.
///
/// Both durations are non-negative and have microsecond precision, because
/// Linux reports signed seconds plus a normalized microsecond remainder. The
/// fields are private so callers can only submit settings made through the
/// precision- and range-checked [`Self::new`] constructor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IntervalTimerValue {
    interval: Duration,
    value: Duration,
}

impl IntervalTimerValue {
    /// Constructs an interval-timer setting with Linux `timeval` precision.
    ///
    /// `setitimer` is a legacy microsecond API. Values with sub-microsecond
    /// precision are rejected rather than silently rounded at the kernel
    /// boundary; [`alarm`] and [`ualarm`] provide the corresponding integral
    /// second and microsecond aliases. Seconds outside Linux's signed
    /// `timeval.tv_sec` range are rejected as well.
    #[inline]
    pub const fn new(interval: Duration, value: Duration) -> Option<Self> {
        if interval.subsec_nanos() % 1_000 != 0
            || value.subsec_nanos() % 1_000 != 0
            || interval.as_secs() > i64::MAX as u64
            || value.as_secs() > i64::MAX as u64
        {
            return None;
        }
        Some(Self { interval, value })
    }

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

/// Errors returned when controlling a Linux process interval timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntervalTimerError {
    /// A duration cannot be represented by Linux's signed microsecond
    /// `timeval` ABI, or has finer-than-microsecond precision.
    InvalidSpecification,
    /// Linux rejected the interval-timer operation.
    Kernel(Errno),
}

impl IntervalTimerError {
    /// Returns the underlying Linux errno, when the failure came from Linux.
    #[must_use]
    #[inline]
    pub const fn kernel_errno(self) -> Option<Errno> {
        match self {
            Self::InvalidSpecification => None,
            Self::Kernel(error) => Some(error),
        }
    }
}

/// Arms or disarms one of Linux's three process interval timers.
///
/// The setting uses the same validated microsecond vocabulary returned by
/// [`getitimer`]. The previous setting is returned after Linux's atomic
/// `setitimer` exchange. This is process-global state: callers must coordinate
/// use of the selected timer with other code in the same process.
#[inline]
pub fn setitimer(
    kind: IntervalTimerKind,
    new_value: IntervalTimerValue,
) -> core::result::Result<IntervalTimerValue, IntervalTimerError> {
    let new_value = kernel_itimerval_from_interval(new_value);
    let mut old_value = MaybeUninit::<KernelItimerval>::uninit();
    // SAFETY: `new_value` is a fully initialized Linux/x86-64 timeval pair
    // and the output storage is initialized on a successful syscall.
    unsafe {
        crabc_core::time::setitimer_raw(kind as i32, &new_value, old_value.as_mut_ptr())
            .map_err(IntervalTimerError::Kernel)?;
        let old_value = old_value.assume_init();
        interval_from_kernel_itimerval(old_value).ok_or(IntervalTimerError::InvalidSpecification)
    }
}

/// Arms the real interval timer for integral seconds and returns its previous
/// remaining value rounded up to the next second.
///
/// The ceiling is required by the `alarm` contract: a previously armed timer
/// with any positive fractional remainder reports at least one second. This
/// is a Rust facade alias only; it does not add a C ABI export.
#[inline]
pub fn alarm(seconds: u32) -> core::result::Result<u32, IntervalTimerError> {
    let setting = IntervalTimerValue::new(Duration::ZERO, Duration::from_secs(seconds as u64))
        .ok_or(IntervalTimerError::InvalidSpecification)?;
    let old = setitimer(IntervalTimerKind::Real, setting)?;
    let seconds = old.value.as_secs();
    let rounded = seconds.saturating_add(u64::from(old.value.subsec_nanos() != 0));
    Ok(rounded.min(u64::from(u32::MAX)) as u32)
}

/// Arms the real interval timer in integral microseconds and returns its
/// previous remaining value in microseconds.
///
/// This is a Rust facade alias only; it does not add a C ABI export.
#[inline]
pub fn ualarm(
    value_microseconds: u32,
    interval_microseconds: u32,
) -> core::result::Result<u32, IntervalTimerError> {
    let setting = IntervalTimerValue::new(
        Duration::from_micros(interval_microseconds as u64),
        Duration::from_micros(value_microseconds as u64),
    )
    .ok_or(IntervalTimerError::InvalidSpecification)?;
    let old = setitimer(IntervalTimerKind::Real, setting)?;
    let micros = old
        .value
        .as_secs()
        .saturating_mul(1_000_000)
        .saturating_add(u64::from(old.value.subsec_nanos() / 1_000));
    Ok(micros.min(u64::from(u32::MAX)) as u32)
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

#[inline]
fn kernel_itimerval_from_interval(value: IntervalTimerValue) -> KernelItimerval {
    fn timeval(value: Duration) -> KernelItimervalTimeval {
        KernelItimervalTimeval {
            tv_sec: value.as_secs() as i64,
            tv_usec: (value.subsec_nanos() / 1_000) as i64,
        }
    }
    KernelItimerval {
        it_interval: timeval(value.interval),
        it_value: timeval(value.value),
    }
}

#[inline]
fn interval_from_kernel_itimerval(value: KernelItimerval) -> Option<IntervalTimerValue> {
    IntervalTimerValue::new(
        duration_from_itimerval_timeval(value.it_interval)?,
        duration_from_itimerval_timeval(value.it_value)?,
    )
}

/// A validated nanosecond-resolution POSIX timer setting.
///
/// This is deliberately distinct from timerfd's public `Itimerspec`: it owns
/// only a pair of non-negative `Duration` values and never exposes a C
/// `itimerspec` record or `timer_t` representation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimerSpec {
    interval: Duration,
    value: Duration,
}

impl TimerSpec {
    /// Constructs a setting when both durations fit Linux's signed timespec
    /// seconds field.
    #[must_use]
    #[inline]
    pub const fn new(interval: Duration, value: Duration) -> Option<Self> {
        if interval.as_secs() > i64::MAX as u64 || value.as_secs() > i64::MAX as u64 {
            None
        } else {
            Some(Self { interval, value })
        }
    }

    /// Returns the repeat interval; zero means one-shot.
    #[must_use]
    #[inline]
    pub const fn interval(self) -> Duration {
        self.interval
    }

    /// Returns the initial or current expiration value.
    #[must_use]
    #[inline]
    pub const fn value(self) -> Duration {
        self.value
    }
}

bitflags! {
    /// Flags accepted by Linux `timer_settime`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct TimerSetFlags: u32 {
        /// Interpret the expiration as an absolute deadline on the selected
        /// clock instead of a relative duration.
        const ABSTIME = 0x0000_0001;
        /// Preserve non-`ABSTIME` bits unchanged. Linux 5.10 masks these
        /// bits while applying the timer rather than rejecting them.
        const _ = !0;
    }
}

/// The supported Linux POSIX timer notification modes.
///
/// `SIGEV_THREAD` is deliberately absent: its callback lifetime requires a
/// process runtime and policy boundary that this direct facade does not own.
/// Signal and thread-directed timers carry only an integer payload, never a C
/// `sigval` union or callback pointer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimerNotification {
    /// Expiration has no notification side effect.
    None,
    /// Deliver `signal` with an integer payload.
    Signal { signal: Signal, value: i32 },
    /// Deliver `signal` with an integer payload directly to `thread`.
    ThreadId {
        /// The target Linux task ID.
        thread: Pid,
        /// The signal to deliver.
        signal: Signal,
        /// The integer payload.
        value: i32,
    },
}

/// Errors returned while reading or replacing an owned POSIX timer setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerError {
    /// Linux returned a setting outside Rust's checked duration representation.
    InvalidSpecification,
    /// Linux rejected the timer ID, flags, or setting operation.
    Kernel(Errno),
}

impl TimerError {
    /// Returns the underlying direct kernel error, when present.
    #[must_use]
    #[inline]
    pub const fn kernel_errno(self) -> Option<Errno> {
        match self {
            Self::InvalidSpecification => None,
            Self::Kernel(error) => Some(error),
        }
    }
}

/// An owned Linux POSIX timer.
///
/// The private kernel identifier is retired by [`Self::delete`]. Dropping an
/// undeleted timer makes one best-effort direct `timer_delete` call; its
/// result cannot be reported from `Drop`.
pub struct PosixTimer {
    id: Option<i32>,
}

impl PosixTimer {
    /// Creates a timer on `clock` with a non-callback notification mode.
    #[inline]
    pub fn new(clock: ClockId, notification: TimerNotification) -> Result<Self> {
        let event = kernel_sigevent(notification);
        let mut id = 0i32;
        // SAFETY: `event` is the exact private x86-64 Linux sigevent record,
        // and `id` is one live writable kernel timer-ID word.
        unsafe {
            crabc_core::time::timer_create_raw(
                clock as i32,
                (&event as *const KernelSigevent).cast(),
                &mut id,
            )?;
        }
        Ok(Self { id: Some(id) })
    }

    /// Returns the private raw kernel timer identifier for diagnostics only.
    #[must_use]
    #[inline]
    pub const fn as_raw(&self) -> i32 {
        match self.id {
            Some(id) => id,
            None => -1,
        }
    }

    /// Arms or disarms the timer and returns its previous setting.
    ///
    /// [`TimerSetFlags`] reaches the direct Linux syscall unchanged. In the
    /// Linux 5.10 POSIX-timer path, only `ABSTIME` controls the arm mode; other
    /// retained bits are ignored rather than preflighted into an invented error.
    #[inline]
    pub fn settime(
        &self,
        flags: TimerSetFlags,
        new_value: TimerSpec,
    ) -> core::result::Result<TimerSpec, TimerError> {
        let new_value = timer_spec_to_kernel(new_value);
        let mut old_value = MaybeUninit::<KernelItimerspec>::uninit();
        // SAFETY: `self` retains the timer ID; `new_value` is initialized; and
        // Linux initializes the complete old setting on success.
        unsafe {
            crabc_core::time::timer_settime_raw(
                self.as_raw(),
                flags.bits() as i32,
                &new_value,
                old_value.as_mut_ptr(),
            )
            .map_err(TimerError::Kernel)?;
            timer_spec_from_kernel(old_value.assume_init()).ok_or(TimerError::InvalidSpecification)
        }
    }

    /// Reads the timer's current setting.
    ///
    /// Linux's `SIGEV_NONE` implementation can retain the last expiry as a
    /// nonzero value after a disarm while reporting a zero interval. This
    /// direct boundary preserves that kernel record instead of manufacturing
    /// a fully zero setting.
    #[inline]
    pub fn gettime(&self) -> core::result::Result<TimerSpec, TimerError> {
        let mut value = MaybeUninit::<KernelItimerspec>::uninit();
        // SAFETY: `self` retains the timer ID and `value` owns one exact
        // writable x86-64 itimerspec record.
        unsafe {
            crabc_core::time::timer_gettime_raw(self.as_raw(), value.as_mut_ptr())
                .map_err(TimerError::Kernel)?;
            timer_spec_from_kernel(value.assume_init()).ok_or(TimerError::InvalidSpecification)
        }
    }

    /// Returns the number of expirations overrun since the last notification.
    #[inline]
    pub fn getoverrun(&self) -> Result<i32> {
        crabc_core::time::timer_getoverrun_raw(self.as_raw())
    }

    /// Explicitly deletes the timer.
    ///
    /// On error its identifier is retained so `Drop` can make one best-effort
    /// retry.
    #[inline]
    pub fn delete(&mut self) -> Result<()> {
        let id = self.id.ok_or(Errno::INVAL)?;
        crabc_core::time::timer_delete_raw(id)?;
        self.id = None;
        Ok(())
    }
}

impl Drop for PosixTimer {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _ = crabc_core::time::timer_delete_raw(id);
        }
    }
}

/// Private Linux/x86-64 `sigevent` storage for POSIX timer creation.
///
/// It is intentionally not a public C ABI type. `value`, `signal`, `notify`,
/// and the `SIGEV_THREAD_ID` task word occupy the pinned offsets below.
#[repr(C)]
struct KernelSigevent {
    value: usize,
    signal: i32,
    notify: i32,
    padding: [i32; 12],
}

const _: () = assert!(core::mem::size_of::<KernelSigevent>() == 64);
const _: () = assert!(core::mem::align_of::<KernelSigevent>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelSigevent, value) == 0);
const _: () = assert!(core::mem::offset_of!(KernelSigevent, signal) == 8);
const _: () = assert!(core::mem::offset_of!(KernelSigevent, notify) == 12);
const _: () = assert!(core::mem::offset_of!(KernelSigevent, padding) == 16);

#[inline]
fn kernel_sigevent(notification: TimerNotification) -> KernelSigevent {
    let (value, signal, notify, thread) = match notification {
        TimerNotification::None => (0, 0, 1, 0),
        TimerNotification::Signal { signal, value } => {
            (value as u32 as usize, signal.as_raw(), 0, 0)
        }
        TimerNotification::ThreadId {
            thread,
            signal,
            value,
        } => (
            value as u32 as usize,
            signal.as_raw(),
            4,
            thread.as_raw_pid(),
        ),
    };
    let mut event = KernelSigevent {
        value,
        signal,
        notify,
        padding: [0; 12],
    };
    event.padding[0] = thread;
    event
}

#[inline]
fn timer_spec_to_kernel(value: TimerSpec) -> KernelItimerspec {
    fn timespec(value: Duration) -> KernelTimespec {
        KernelTimespec {
            tv_sec: value.as_secs() as i64,
            tv_nsec: value.subsec_nanos() as i64,
        }
    }
    KernelItimerspec {
        it_interval: timespec(value.interval),
        it_value: timespec(value.value),
    }
}

#[inline]
fn timer_spec_from_kernel(value: KernelItimerspec) -> Option<TimerSpec> {
    fn duration(value: KernelTimespec) -> Option<Duration> {
        if value.tv_sec < 0 || !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
            return None;
        }
        Some(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
    }
    TimerSpec::new(duration(value.it_interval)?, duration(value.it_value)?)
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
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
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
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// Clocks accepted by Linux `timerfd_create`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
