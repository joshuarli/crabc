//! Darwin clocks, sleeps, wall-clock reads and interval timers over
//! libSystem.
//!
//! `nanosleep_raw` and `gettimeofday` have the names and shapes of the
//! `crabc-core` time seam, so the facade module keeps one body for the
//! operations both targets share.

use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::time::Duration;

use super::errno::{self, Errno, Result};
use super::sys;
use crate::time::{
    GetitimerError, IntervalTimerError, IntervalTimerKind, IntervalTimerValue, Timespec,
    NANOS_PER_SECOND,
};

/// Darwin clock identifiers.
///
/// Darwin's `CLOCK_MONOTONIC` keeps counting while the system sleeps, like
/// Linux's `CLOCK_BOOTTIME`; `UptimeRaw` is the clock that pauses during
/// sleep. Linux's coarse, boot-time, alarm and TAI clocks do not exist.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ClockId {
    /// `CLOCK_REALTIME` (Unix epoch wall clock).
    Realtime = sys::CLOCK_REALTIME as i32,
    /// `CLOCK_MONOTONIC` (nondecreasing, including time asleep).
    Monotonic = sys::CLOCK_MONOTONIC as i32,
    /// `CLOCK_PROCESS_CPUTIME_ID` (CPU time consumed by this process).
    ProcessCPUTime = sys::CLOCK_PROCESS_CPUTIME_ID as i32,
    /// `CLOCK_THREAD_CPUTIME_ID` (CPU time consumed by this thread).
    ThreadCPUTime = sys::CLOCK_THREAD_CPUTIME_ID as i32,
    /// `CLOCK_MONOTONIC_RAW` (hardware-derived, not slewed, including sleep).
    MonotonicRaw = sys::CLOCK_MONOTONIC_RAW as i32,
    /// `CLOCK_MONOTONIC_RAW_APPROX`, the raw clock at scheduler resolution.
    MonotonicRawApprox = sys::CLOCK_MONOTONIC_RAW_APPROX as i32,
    /// `CLOCK_UPTIME_RAW` (raw and nondecreasing, paused while asleep).
    UptimeRaw = sys::CLOCK_UPTIME_RAW as i32,
    /// `CLOCK_UPTIME_RAW_APPROX`, the uptime clock at scheduler resolution.
    UptimeRawApprox = sys::CLOCK_UPTIME_RAW_APPROX as i32,
}

impl TryFrom<i32> for ClockId {
    type Error = Errno;

    fn try_from(value: i32) -> Result<Self> {
        const REALTIME: i32 = ClockId::Realtime as i32;
        const MONOTONIC: i32 = ClockId::Monotonic as i32;
        const PROCESS: i32 = ClockId::ProcessCPUTime as i32;
        const THREAD: i32 = ClockId::ThreadCPUTime as i32;
        const MONOTONIC_RAW: i32 = ClockId::MonotonicRaw as i32;
        const MONOTONIC_RAW_APPROX: i32 = ClockId::MonotonicRawApprox as i32;
        const UPTIME_RAW: i32 = ClockId::UptimeRaw as i32;
        const UPTIME_RAW_APPROX: i32 = ClockId::UptimeRawApprox as i32;
        match value {
            REALTIME => Ok(Self::Realtime),
            MONOTONIC => Ok(Self::Monotonic),
            PROCESS => Ok(Self::ProcessCPUTime),
            THREAD => Ok(Self::ThreadCPUTime),
            MONOTONIC_RAW => Ok(Self::MonotonicRaw),
            MONOTONIC_RAW_APPROX => Ok(Self::MonotonicRawApprox),
            UPTIME_RAW => Ok(Self::UptimeRaw),
            UPTIME_RAW_APPROX => Ok(Self::UptimeRawApprox),
            _ => Err(Errno::INVAL),
        }
    }
}

#[inline]
fn clock_raw(clock: ClockId) -> sys::clockid_t {
    clock as i32 as sys::clockid_t
}

/// Rejects a record whose nanoseconds are outside `0..1_000_000_000`.
#[inline]
fn validated(value: sys::Timespec) -> Result<Timespec> {
    if !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
        return Err(Errno::RANGE);
    }
    Ok(Timespec {
        tv_sec: value.tv_sec,
        tv_nsec: value.tv_nsec,
    })
}

/// Reads a validated observation from one Darwin clock.
pub fn clock_gettime(clock: ClockId) -> Result<Timespec> {
    let mut value = MaybeUninit::<sys::Timespec>::uninit();
    // SAFETY: `value` is writable storage for one `struct timespec`.
    let result = unsafe { sys::clock_gettime(clock_raw(clock), value.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `clock_gettime` initialized the record.
    validated(unsafe { value.assume_init() })
}

/// Reads a validated resolution for one Darwin clock.
pub fn clock_getres(clock: ClockId) -> Result<Timespec> {
    let mut value = MaybeUninit::<sys::Timespec>::uninit();
    // SAFETY: `value` is writable storage for one `struct timespec`.
    let result = unsafe { sys::clock_getres(clock_raw(clock), value.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `clock_getres` initialized the record.
    validated(unsafe { value.assume_init() })
}

/// Sets one Darwin clock.
///
/// A non-canonical `tv_nsec` is rejected with [`Errno::INVAL`] before the
/// call. libSystem sets only `CLOCK_REALTIME`, which needs root; any other
/// clock fails with `EINVAL`.
#[inline]
pub fn clock_settime(id: ClockId, timespec: Timespec) -> Result<()> {
    if !(0..i64::from(NANOS_PER_SECOND)).contains(&timespec.tv_nsec) {
        return Err(Errno::INVAL);
    }
    let value = sys::Timespec {
        tv_sec: timespec.tv_sec,
        tv_nsec: timespec.tv_nsec,
    };
    // SAFETY: `value` is a live, canonical `struct timespec` for the call.
    let result = unsafe { sys::clock_settime(clock_raw(id), &value) };
    errno::check(result).map(|_| ())
}

/// `nanosleep(request, remaining)`.
///
/// # Safety
///
/// `request` must point to a readable `struct timespec` and `remaining` to
/// writable storage for one, both live for the call.
#[inline]
pub(crate) unsafe fn nanosleep_raw(request: *const u8, remaining: *mut u8) -> Result<()> {
    // SAFETY: the caller supplies both records; `Timespec` is libSystem's
    // `struct timespec`.
    let result = unsafe { sys::nanosleep(request.cast(), remaining.cast()) };
    errno::check(result).map(|_| ())
}

/// The seconds and microseconds of one `gettimeofday` observation.
pub(crate) struct WallClockParts {
    pub(crate) seconds: i64,
    pub(crate) microseconds: i64,
}

/// `gettimeofday(tp, NULL)`.
#[inline]
pub(crate) fn gettimeofday() -> Result<WallClockParts> {
    let mut value = MaybeUninit::<sys::Timeval>::uninit();
    // SAFETY: `value` is writable storage for one `struct timeval`; the
    // obsolete timezone argument is null.
    let result = unsafe { sys::gettimeofday(value.as_mut_ptr(), core::ptr::null_mut()) };
    errno::check(result)?;
    // SAFETY: a successful `gettimeofday` initialized the record.
    let value = unsafe { value.assume_init() };
    Ok(WallClockParts {
        seconds: value.tv_sec,
        microseconds: i64::from(value.tv_usec),
    })
}

#[inline]
fn duration_from_timeval(value: sys::Timeval) -> Option<Duration> {
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let microseconds = u32::try_from(value.tv_usec).ok().filter(|value| *value < 1_000_000)?;
    Some(Duration::new(seconds, microseconds * 1_000))
}

#[inline]
fn interval_from_record(record: sys::Itimerval) -> Option<IntervalTimerValue> {
    IntervalTimerValue::new(
        duration_from_timeval(record.it_interval)?,
        duration_from_timeval(record.it_value)?,
    )
}

#[inline]
fn timeval_from_duration(value: Duration) -> sys::Timeval {
    sys::Timeval {
        tv_sec: value.as_secs() as i64,
        tv_usec: (value.subsec_nanos() / 1_000) as sys::suseconds_t,
    }
}

/// Reads one process interval timer without changing it.
///
/// A negative or non-canonical returned `timeval` is reported as
/// [`GetitimerError::InvalidKernelValue`].
#[inline]
pub fn getitimer(
    kind: IntervalTimerKind,
) -> core::result::Result<IntervalTimerValue, GetitimerError> {
    let mut record = MaybeUninit::<sys::Itimerval>::uninit();
    // SAFETY: `record` is writable storage for one `struct itimerval`.
    let result = unsafe { sys::getitimer(kind as i32, record.as_mut_ptr()) };
    errno::check(result).map_err(GetitimerError::Kernel)?;
    // SAFETY: a successful `getitimer` initialized the record.
    interval_from_record(unsafe { record.assume_init() }).ok_or(GetitimerError::InvalidKernelValue)
}

/// Arms or disarms one process interval timer and returns its previous
/// setting.
///
/// This is process-global state: callers must coordinate use of the selected
/// timer with other code in the same process.
#[inline]
pub fn setitimer(
    kind: IntervalTimerKind,
    new_value: IntervalTimerValue,
) -> core::result::Result<IntervalTimerValue, IntervalTimerError> {
    let record = sys::Itimerval {
        it_interval: timeval_from_duration(new_value.interval()),
        it_value: timeval_from_duration(new_value.value()),
    };
    let mut old = MaybeUninit::<sys::Itimerval>::uninit();
    // SAFETY: `record` is a live, initialized `struct itimerval`, and `old`
    // is writable storage for the previous one.
    let result = unsafe { sys::setitimer(kind as i32, &record, old.as_mut_ptr()) };
    errno::check(result).map_err(IntervalTimerError::Kernel)?;
    // SAFETY: a successful `setitimer` stored the previous setting.
    interval_from_record(unsafe { old.assume_init() }).ok_or(IntervalTimerError::InvalidSpecification)
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Timespec>() == size_of::<sys::Timespec>());
    assert!(align_of::<Timespec>() == align_of::<sys::Timespec>());
    assert!(offset_of!(Timespec, tv_sec) == offset_of!(sys::Timespec, tv_sec));
    assert!(offset_of!(Timespec, tv_nsec) == offset_of!(sys::Timespec, tv_nsec));

    assert!(IntervalTimerKind::Real as i32 == sys::ITIMER_REAL);
    assert!(IntervalTimerKind::Virtual as i32 == sys::ITIMER_VIRTUAL);
    assert!(IntervalTimerKind::Profiler as i32 == sys::ITIMER_PROF);
};
