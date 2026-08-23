//! Direct Linux/AArch64 clock queries.
//!
//! Known clocks use an infallible interface matching Rustix: each enum value
//! is supported by Linux at runtime. Dynamic descriptor clocks retain a
//! fallible result because the kernel can reject a descriptor-backed clock.

use bitflags::bitflags;
use core::mem::MaybeUninit;
use core::time::Duration;

use crate::{process::Pid, process::Signal, AsFd, BorrowedFd, Errno, OwnedFd, Result};

#[cfg(feature = "alloc")]
use crate::timezone::{OffsetInfo, TimeZone, UtcOffset};

pub use crate::fs::{Nsecs, Secs, Timespec};

/// Nanoseconds in one Unix-epoch second.
pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

const CLOCK_NANOSLEEP_TIMER_ABSTIME: u32 = 1;

/// A UTC wall-clock instant represented relative to the Unix epoch.
///
/// `seconds` is signed so instants before 1970 remain representable. The
/// subsecond component is always normalized to `0..NANOS_PER_SECOND`; the
/// fields stay private so callers cannot construct a non-canonical value.
/// This is a Rust-native value type, not a C `timeval`/`timespec` alias.
#[derive(Debug, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixTime {
    seconds: i64,
    nanoseconds: u32,
}

impl UnixTime {
    /// The Unix epoch, 1970-01-01 00:00:00 UTC.
    pub const UNIX_EPOCH: Self = Self {
        seconds: 0,
        nanoseconds: 0,
    };

    /// Constructs a normalized Unix time from signed seconds and nanoseconds.
    ///
    /// Returns `None` when `nanoseconds` is not a subsecond remainder. The
    /// seconds component is intentionally signed and therefore accepts times
    /// before the epoch.
    #[must_use]
    pub const fn from_parts(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if nanoseconds < NANOS_PER_SECOND {
            Some(Self {
                seconds,
                nanoseconds,
            })
        } else {
            None
        }
    }

    /// Returns signed whole seconds since 1970-01-01 00:00:00 UTC.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns the normalized nanosecond remainder within the current second.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    /// Converts Linux's canonical `gettimeofday` fields into this type.
    ///
    /// Linux supplies a signed seconds field and a microsecond remainder in
    /// `0..1_000_000`. The remainder is widened to nanoseconds without
    /// changing the epoch or carrying into the seconds field.
    #[inline]
    fn from_kernel_parts(parts: crabc_core::time::KernelWallClockParts) -> Option<Self> {
        if !(0..1_000_000).contains(&parts.microseconds) {
            return None;
        }
        Self::from_parts(parts.seconds, (parts.microseconds as u32) * 1_000)
    }
}

/// A normalized UTC civil time in the range representable by musl's
/// `struct tm` year field on Linux/AArch64.
///
/// The value is deliberately not a C `tm` layout.  Its private fields ensure
/// that a safe caller cannot construct an invalid month, day, clock field, or
/// derived weekday.  Time-zone state, DST state, leap-second state, and C
/// `errno` are not part of this UTC-only value.
#[derive(Debug, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CalendarTime {
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    weekday: u8,
    yearday: u16,
}

impl CalendarTime {
    /// Converts signed Unix-epoch seconds to a normalized UTC calendar value.
    ///
    /// This is the direct musl Gregorian conversion, including its rejection
    /// of seconds whose resulting `tm_year` would not fit in an AArch64 C
    /// `int`.  The native boundary reports that condition as `ERANGE` rather
    /// than exposing musl's null pointer and TLS-`errno` protocol.
    #[inline]
    pub fn from_unix_seconds(seconds: i64) -> Result<Self> {
        calendar_from_unix_seconds(seconds)
    }

    /// Constructs a normalized UTC calendar value from civil fields.
    ///
    /// Month and day are one-based, and clock fields use their ordinary
    /// bounded Gregorian ranges.  Unlike C `timegm`, this native constructor
    /// does not accept out-of-range fields for normalization; invalid states
    /// are rejected before they enter the typed value.
    #[inline]
    pub fn from_ymdhms(
        year: i64,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self> {
        if !(1..=12).contains(&month)
            || !(1..=days_in_month(year, month)).contains(&day)
            || hour >= 24
            || minute >= 60
            || second >= 60
        {
            return Err(Errno::INVAL);
        }

        let seconds =
            calendar_seconds(year, month, day, hour, minute, second).ok_or(Errno::RANGE)?;
        let value = Self::from_unix_seconds(seconds)?;
        // This check also documents that the constructor is strict rather
        // than silently inheriting C's field-normalization behavior.
        if value.year != year
            || value.month != month
            || value.day != day
            || value.hour != hour
            || value.minute != minute
            || value.second != second
        {
            return Err(Errno::RANGE);
        }
        Ok(value)
    }

    /// Returns the proleptic Gregorian year.
    #[must_use]
    pub const fn year(self) -> i64 {
        self.year
    }

    /// Returns the one-based Gregorian month.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// Returns the one-based day of the month.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// Returns the hour in UTC, in `0..24`.
    #[must_use]
    pub const fn hour(self) -> u8 {
        self.hour
    }

    /// Returns the minute in UTC, in `0..60`.
    #[must_use]
    pub const fn minute(self) -> u8 {
        self.minute
    }

    /// Returns the second in UTC, in `0..60`.
    #[must_use]
    pub const fn second(self) -> u8 {
        self.second
    }

    /// Returns the weekday with Sunday as zero, matching musl's `tm_wday`.
    #[must_use]
    pub const fn weekday(self) -> u8 {
        self.weekday
    }

    /// Returns the zero-based day of the year, matching musl's `tm_yday`.
    #[must_use]
    pub const fn yearday(self) -> u16 {
        self.yearday
    }

    /// Converts this normalized UTC value back to signed Unix-epoch seconds.
    #[inline]
    pub fn unix_seconds(self) -> Result<i64> {
        calendar_seconds(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
        .ok_or(Errno::RANGE)
    }
}

/// A local civil-time view of one explicitly supplied UTC instant.
///
/// `LocalCalendar` combines [`UnixTime`] with an explicitly supplied,
/// immutable [`TimeZone`]. The offset-adjusted whole seconds are converted
/// through [`CalendarTime`], while the input nanoseconds and the selected
/// offset metadata are preserved. The abbreviation is borrowed from `zone`;
/// no timezone bytes are copied into a second allocation and no process-global
/// `TZ` state is consulted.
///
/// This is a one-way UTC-instant conversion. It does not resolve an ambiguous
/// or nonexistent local civil value back to an instant, and it does not load
/// system zoneinfo, format text, parse text, or mutate a clock.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCalendar<'zone> {
    instant: UnixTime,
    calendar: CalendarTime,
    offset: OffsetInfo<'zone>,
}

#[cfg(feature = "alloc")]
impl<'zone> LocalCalendar<'zone> {
    /// Converts one UTC instant using the supplied immutable timezone rules.
    ///
    /// The selected offset is applied to whole seconds with checked
    /// arithmetic. [`Errno::RANGE`] is returned if the adjusted seconds cannot
    /// be represented by the existing native [`CalendarTime`] range; the
    /// original instant and its nanoseconds are never normalized or discarded.
    #[inline]
    pub fn from_unix_time(instant: UnixTime, zone: &'zone TimeZone) -> Result<Self> {
        let offset = zone.offset_at(instant);
        let local_seconds = instant
            .seconds()
            .checked_add(i64::from(offset.offset().seconds_east_of_utc()))
            .ok_or(Errno::RANGE)?;
        Ok(Self {
            instant,
            calendar: CalendarTime::from_unix_seconds(local_seconds)?,
            offset,
        })
    }

    /// Returns the original UTC instant, including its nanosecond remainder.
    #[must_use]
    pub const fn instant(self) -> UnixTime {
        self.instant
    }

    /// Returns the normalized local civil fields at whole-second precision.
    #[must_use]
    pub const fn calendar(self) -> CalendarTime {
        self.calendar
    }

    /// Returns the selected offset east of UTC.
    #[must_use]
    pub const fn offset(self) -> UtcOffset {
        self.offset.offset()
    }

    /// Returns the complete copied offset metadata for this instant.
    #[must_use]
    pub const fn offset_info(self) -> OffsetInfo<'zone> {
        self.offset
    }

    /// Reports whether the selected offset is marked as daylight saving.
    #[must_use]
    pub const fn is_daylight_saving(self) -> bool {
        self.offset.is_daylight_saving()
    }

    /// Returns the selected NUL-free timezone abbreviation bytes.
    #[must_use]
    pub const fn abbreviation(self) -> &'zone [u8] {
        self.offset.abbreviation()
    }

    /// Returns the preserved nanosecond remainder within the local second.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.instant.nanoseconds()
    }
}

/// Reads the current UTC wall-clock second through the direct Linux clock
/// syscall.  This is the native counterpart of musl's `time`; subsecond
/// precision is intentionally discarded at this typed boundary.
#[inline]
pub fn time() -> Result<i64> {
    Ok(clock_query_result(ClockId::Realtime as i32)?.tv_sec)
}

/// A UTC realtime observation reduced to whole milliseconds.
///
/// The seconds field remains signed so observations before the Unix epoch are
/// representable. The millisecond field is a normalized remainder in
/// `0..1000`; it is obtained by truncating Linux's nanosecond field rather
/// than rounding it. The fields are private so callers cannot construct a
/// non-canonical observation or cross this native boundary with a C
/// `timespec` value.
#[derive(Debug, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealtimeMillis {
    seconds: i64,
    milliseconds: u16,
}

impl RealtimeMillis {
    #[inline]
    fn from_timespec(value: Timespec) -> Option<Self> {
        if !(0..NANOS_PER_SECOND as i64).contains(&value.tv_nsec) {
            return None;
        }
        Some(Self {
            seconds: value.tv_sec,
            milliseconds: (value.tv_nsec / 1_000_000) as u16,
        })
    }

    /// Returns signed whole seconds since 1970-01-01 00:00:00 UTC.
    #[must_use]
    #[inline]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns the truncated millisecond remainder within the current
    /// second, in `0..1000`.
    #[must_use]
    #[inline]
    pub const fn milliseconds(self) -> u16 {
        self.milliseconds
    }
}

/// Reads `CLOCK_REALTIME` through the shared Linux vDSO clock dispatch and
/// truncates its subsecond component to milliseconds.
///
/// Kernel errors remain typed [`Errno`] values. Absent or malformed vDSO
/// metadata falls back to the direct syscall; no C ABI function, allocation,
/// timezone state, or TLS `errno` participates in the observation.
#[inline]
pub fn realtime_millis() -> Result<RealtimeMillis> {
    RealtimeMillis::from_timespec(clock_query_result(ClockId::Realtime as i32)?).ok_or(Errno::RANGE)
}

/// Computes the difference between two signed Unix-epoch seconds.
///
/// The operands are converted independently, so the full AArch64 `time_t`
/// domain does not overflow in an intermediate signed-integer subtraction.
#[inline]
#[must_use]
pub fn difftime(t1: i64, t0: i64) -> f64 {
    t1 as f64 - t0 as f64
}

/// Converts signed Unix-epoch seconds to a normalized UTC calendar value.
#[inline]
pub fn gmtime(seconds: i64) -> Result<CalendarTime> {
    CalendarTime::from_unix_seconds(seconds)
}

/// Converts a normalized UTC calendar value to signed Unix-epoch seconds.
#[inline]
pub fn timegm(calendar: &CalendarTime) -> Result<i64> {
    calendar.unix_seconds()
}

const LEAPOCH_SECONDS: i128 = 946_684_800 + 86_400 * (31 + 29);
const DAYS_PER_400_YEARS: i128 = 365 * 400 + 97;
const DAYS_PER_100_YEARS: i128 = 365 * 100 + 24;
const DAYS_PER_4_YEARS: i128 = 365 * 4 + 1;
const MARCH_BASED_DAYS: [i128; 12] = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29];
const MONTH_DAYS_BEFORE: [i128; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

#[inline]
fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[inline]
fn days_in_month(year: i64, month: u8) -> u8 {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    days
}

/// musl's `__year_to_secs`, evaluated in a wider intermediate type so the
/// native API never relies on signed-overflow behavior from a C expression.
#[inline]
fn year_to_seconds(year: i128, is_leap: &mut bool) -> i128 {
    // musl spells this fast-path guard as `year-2ULL <= 136`.  The unsigned
    // suffix is material: years 0, 1, and all negative years take the
    // Gregorian 400-year path rather than wrapping into the fast path.
    if (2..=138).contains(&year) {
        let year = year as i64;
        let mut leaps = (year - 68) >> 2;
        if (year - 68) & 3 == 0 {
            leaps -= 1;
            *is_leap = true;
        } else {
            *is_leap = false;
        }
        return 31_536_000 * (year as i128 - 70) + 86_400 * leaps as i128;
    }

    let offset = year - 100;
    let cycles = offset.div_euclid(400);
    let mut rem = offset.rem_euclid(400);
    let (centuries, leaps);
    if rem == 0 {
        *is_leap = true;
        centuries = 0;
        leaps = 0;
    } else {
        let century;
        if rem >= 200 {
            if rem >= 300 {
                century = 3;
                rem -= 300;
            } else {
                century = 2;
                rem -= 200;
            }
        } else if rem >= 100 {
            century = 1;
            rem -= 100;
        } else {
            century = 0;
        }
        centuries = century;
        if rem == 0 {
            *is_leap = false;
            leaps = 0;
        } else {
            leaps = rem / 4;
            rem %= 4;
            *is_leap = rem == 0;
        }
    }
    let total_leaps = leaps + 97 * cycles + 24 * centuries - (*is_leap as i128);
    (year - 100) * 31_536_000 + total_leaps * 86_400 + 946_684_800 + 86_400
}

#[inline]
fn calendar_seconds(
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<i64> {
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return None;
    }
    let mut leap = false;
    // musl's helper receives the C `tm_year` offset from 1900, not the
    // proleptic Gregorian year exposed by `CalendarTime`.
    let mut seconds = year_to_seconds(year as i128 - 1900, &mut leap);
    let month_index = month as usize - 1;
    seconds += (MONTH_DAYS_BEFORE[month_index] + if leap && month >= 3 { 1 } else { 0 }) * 86_400;
    seconds += (day as i128 - 1) * 86_400;
    seconds += hour as i128 * 3_600 + minute as i128 * 60 + second as i128;
    i64::try_from(seconds).ok()
}

#[inline]
fn calendar_from_unix_seconds(seconds: i64) -> Result<CalendarTime> {
    let seconds = seconds as i128;
    let min_seconds = i32::MIN as i128 * 31_622_400;
    let max_seconds = i32::MAX as i128 * 31_622_400;
    if seconds < min_seconds || seconds > max_seconds {
        return Err(Errno::RANGE);
    }

    let relative = seconds - LEAPOCH_SECONDS;
    let days = relative.div_euclid(86_400);
    let remainder = relative.rem_euclid(86_400);
    let weekday = (3 + days).rem_euclid(7) as u8;

    let cycles_400 = days.div_euclid(DAYS_PER_400_YEARS);
    let mut remaining_days = days.rem_euclid(DAYS_PER_400_YEARS);
    let mut cycles_100 = remaining_days / DAYS_PER_100_YEARS;
    if cycles_100 == 4 {
        cycles_100 -= 1;
    }
    remaining_days -= cycles_100 * DAYS_PER_100_YEARS;
    let mut cycles_4 = remaining_days / DAYS_PER_4_YEARS;
    if cycles_4 == 25 {
        cycles_4 -= 1;
    }
    remaining_days -= cycles_4 * DAYS_PER_4_YEARS;
    let mut years_in_cycle = remaining_days / 365;
    if years_in_cycle == 4 {
        years_in_cycle -= 1;
    }
    remaining_days -= years_in_cycle * 365;

    let leap = years_in_cycle == 0 && (cycles_4 != 0 || cycles_100 == 0);
    let mut yearday = remaining_days + 31 + 28 + if leap { 1 } else { 0 };
    if yearday >= 365 + if leap { 1 } else { 0 } {
        yearday -= 365 + if leap { 1 } else { 0 };
    }

    let years = years_in_cycle + 4 * cycles_4 + 100 * cycles_100 + 400 * cycles_400;
    let mut month_index = 0usize;
    while month_index < MARCH_BASED_DAYS.len() && MARCH_BASED_DAYS[month_index] <= remaining_days {
        remaining_days -= MARCH_BASED_DAYS[month_index];
        month_index += 1;
    }
    let mut year = years + 2000;
    // `month_index` is March-based and the C `tm_mon` equivalent is
    // zero-based: March is 2, January is 0, and February is 1.
    let mut month = month_index as i128 + 2;
    if month >= 12 {
        month -= 12;
        year += 1;
    }
    if year - 1900 < i32::MIN as i128 || year - 1900 > i32::MAX as i128 {
        return Err(Errno::RANGE);
    }

    Ok(CalendarTime {
        year: year as i64,
        month: month as u8 + 1,
        day: remaining_days as u8 + 1,
        hour: (remainder / 3_600) as u8,
        minute: (remainder / 60 % 60) as u8,
        second: (remainder % 60) as u8,
        weekday,
        yearday: yearday as u16,
    })
}

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
    /// The request exceeded Linux/AArch64's signed `timespec.tv_sec` range.
    DurationOutOfRange,
    /// An absolute deadline had a non-canonical `tv_nsec` field.
    InvalidRequest,
    /// The kernel returned an invalid remaining `timespec` after `EINTR`.
    InvalidRemaining,
    /// A Linux syscall failure, kept as a typed value.
    ///
    /// Relative `EINTR` is represented by [`SleepOutcome::Interrupted`].
    /// Absolute `EINTR` remains here because Linux provides no remaining
    /// duration for an absolute deadline.
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

/// Sleeps for a relative duration through Linux `nanosleep`.
///
/// `Duration` is converted explicitly to the Linux/AArch64 timespec contract:
/// seconds must fit in `i64`, and nanoseconds are already guaranteed by Rust
/// to be below one billion. `EINTR` is represented by
/// [`SleepOutcome::Interrupted`] with the kernel's remaining duration; other
/// kernel failures are returned as [`SleepError::Kernel`]. No retry, C sleep
/// ABI, TLS `errno`, or allocation is involved.
#[inline]
pub fn nanosleep(duration: Duration) -> core::result::Result<SleepOutcome, SleepError> {
    let request = duration_to_timespec(duration)?;
    let mut remaining = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `request` is an initialized Linux/AArch64 timespec and
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
/// This is the typed relative form of `clock_nanosleep`: `duration` is
/// converted to an AArch64 `timespec`, and an `EINTR` result includes the
/// kernel-provided remaining duration. Other syscall failures remain typed in
/// [`SleepError::Kernel`].
#[inline]
pub fn clock_nanosleep_relative(
    id: ClockId,
    duration: Duration,
) -> core::result::Result<SleepOutcome, SleepError> {
    let request = duration_to_timespec(duration)?;
    let mut remaining = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `request` is an initialized Linux/AArch64 timespec and
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
/// `deadline` uses the Linux/AArch64 `timespec` contract: `tv_sec` is signed
/// 64-bit seconds and `tv_nsec` must be in `0..1_000_000_000`. No
/// normalization is performed, so a past or negative deadline is passed to
/// the selected clock unchanged. A malformed `tv_nsec` is rejected before
/// the syscall. Linux reports an interrupted
/// absolute sleep as [`SleepError::Kernel`] containing `EINTR`; no remaining
/// duration is returned or invented because `TIMER_ABSTIME` has no remaining
/// time output.
#[inline]
pub fn clock_nanosleep_absolute(
    id: ClockId,
    deadline: Timespec,
) -> core::result::Result<(), SleepError> {
    if !valid_timespec(deadline) {
        return Err(SleepError::InvalidRequest);
    }
    // SAFETY: `deadline` has the validated Linux/AArch64 timespec range. The
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
    if timespec.tv_sec < 0 || !(0..1_000_000_000).contains(&timespec.tv_nsec) {
        return Err(SleepError::InvalidRemaining);
    }
    Ok(Duration::new(
        timespec.tv_sec as u64,
        timespec.tv_nsec as u32,
    ))
}

#[inline]
fn valid_timespec(timespec: Timespec) -> bool {
    timespec.tv_nsec >= 0 && timespec.tv_nsec < NANOS_PER_SECOND as i64
}

/// Reads the current UTC wall clock from Linux's `gettimeofday` syscall.
///
/// Kernel failures are returned as [`crate::Errno`] values. A malformed
/// kernel subsecond field is reported as `Errno::RANGE`; valid Linux results
/// always normalize to a [`UnixTime`] with nanoseconds below one second. No
/// C `errno`, timezone state, vDSO/libc call, or allocation is involved.
#[inline]
pub fn wall_clock() -> Result<UnixTime> {
    let parts = crabc_core::time::gettimeofday()?;
    UnixTime::from_kernel_parts(parts).ok_or(Errno::RANGE)
}

/// The three Linux process interval timers accepted by [`getitimer`] and
/// [`setitimer`].
///
/// This is deliberately a closed vocabulary: unsupported selector integers
/// cannot cross the safe Rust API boundary. `Real` measures elapsed wall-clock
/// time, `Virtual` measures user CPU time, and `Profiler` measures user plus
/// system CPU time.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
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

    /// Converts a Linux `ITIMER_*` selector, rejecting unsupported values.
    #[inline]
    fn try_from(value: i32) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Real),
            1 => Ok(Self::Virtual),
            2 => Ok(Self::Profiler),
            _ => Err(Errno::INVAL),
        }
    }
}

/// A validated interval-timer setting returned by Linux `getitimer`.
///
/// Both durations are non-negative and have nanosecond precision that is a
/// multiple of one thousand, because Linux reports signed seconds plus a
/// normalized microsecond remainder. The fields are private and there are no
/// mutation methods, so callers cannot construct or alter an invalid timer
/// setting through this type.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub struct IntervalTimerValue {
    interval: Duration,
    value: Duration,
}

impl IntervalTimerValue {
    /// Constructs an interval-timer setting with Linux `timeval` precision.
    ///
    /// `setitimer` is a legacy microsecond API. Values with sub-microsecond
    /// precision are rejected rather than silently rounded at the kernel
    /// boundary; `alarm` and `ualarm` provide the corresponding integral
    /// second and microsecond aliases.
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
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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
/// The query does not arm, disarm, or otherwise mutate process timer state.
/// Linux's signed timeval fields are validated before conversion to
/// [`IntervalTimerValue`]; malformed kernel output is never exposed as a
/// negative or non-canonical Rust duration. No libc, C ABI, vDSO, allocation,
/// or TLS `errno` is involved.
#[inline]
pub fn getitimer(
    kind: IntervalTimerKind,
) -> core::result::Result<IntervalTimerValue, GetitimerError> {
    let mut value = MaybeUninit::<crabc_core::time::KernelItimerval>::uninit();
    // SAFETY: `value` is writable storage for the exact Linux/AArch64
    // `__kernel_old_itimerval` record and remains live for the syscall.
    unsafe {
        crabc_core::time::getitimer_raw(kind as i32, value.as_mut_ptr().cast())
            .map_err(GetitimerError::Kernel)?;
    }
    // SAFETY: A successful getitimer syscall initializes all four words.
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
fn duration_from_itimerval_timeval(
    value: crabc_core::time::KernelItimervalTimeval,
) -> Option<Duration> {
    if value.tv_sec < 0 || value.tv_usec < 0 || value.tv_usec >= 1_000_000 {
        return None;
    }
    Some(Duration::new(
        value.tv_sec as u64,
        (value.tv_usec as u32) * 1_000,
    ))
}

/// Errors returned when controlling a Linux process interval timer.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IntervalTimerError {
    /// A duration cannot be represented by Linux's signed microsecond
    /// `timeval` ABI, or has finer-than-microsecond precision.
    InvalidSpecification,
    /// Linux rejected the interval-timer operation.
    Kernel(Errno),
}

impl IntervalTimerError {
    /// Returns the underlying kernel errno, when the failure came from Linux.
    #[must_use]
    #[inline]
    pub const fn kernel_errno(self) -> Option<Errno> {
        match self {
            Self::InvalidSpecification => None,
            Self::Kernel(error) => Some(error),
        }
    }
}

/// Arms, disarms, and observes one of Linux's three process interval timers.
///
/// The setting is represented by the same validated microsecond vocabulary
/// returned by [`getitimer`]. The previous setting is returned after the
/// kernel operation, matching Linux's atomic `setitimer` exchange.
#[inline]
pub fn setitimer(
    kind: IntervalTimerKind,
    new_value: IntervalTimerValue,
) -> core::result::Result<IntervalTimerValue, IntervalTimerError> {
    let new_value = kernel_itimerval_from_interval(new_value);
    let mut old_value = MaybeUninit::<crabc_core::time::KernelItimerval>::uninit();
    // SAFETY: `new_value` is a fully initialized Linux timeval pair and the
    // output storage is initialized on a successful syscall.
    unsafe {
        crabc_core::time::setitimer_raw(
            kind as i32,
            (&new_value as *const crabc_core::time::KernelItimerval).cast(),
            old_value.as_mut_ptr().cast(),
        )
        .map_err(IntervalTimerError::Kernel)?;
        let old_value = old_value.assume_init();
        interval_from_kernel_itimerval(old_value).ok_or(IntervalTimerError::InvalidSpecification)
    }
}

/// Arms the real interval timer for integral seconds and returns its previous
/// remaining value rounded up to the next second.
///
/// The ceiling is required by the C `alarm` contract: a previously armed
/// timer with any positive fractional remainder reports at least one second.
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

#[inline]
fn kernel_itimerval_from_interval(value: IntervalTimerValue) -> crabc_core::time::KernelItimerval {
    fn timeval(duration: Duration) -> crabc_core::time::KernelItimervalTimeval {
        crabc_core::time::KernelItimervalTimeval {
            tv_sec: duration.as_secs() as i64,
            tv_usec: (duration.subsec_nanos() / 1_000) as i64,
        }
    }
    crabc_core::time::KernelItimerval {
        it_interval: timeval(value.interval),
        it_value: timeval(value.value),
    }
}

#[inline]
fn interval_from_kernel_itimerval(
    value: crabc_core::time::KernelItimerval,
) -> Option<IntervalTimerValue> {
    fn duration(value: crabc_core::time::KernelItimervalTimeval) -> Option<Duration> {
        if value.tv_sec < 0 || value.tv_usec < 0 || value.tv_usec >= 1_000_000 {
            return None;
        }
        Some(Duration::new(
            value.tv_sec as u64,
            (value.tv_usec as u32) * 1_000,
        ))
    }
    IntervalTimerValue::new(duration(value.it_interval)?, duration(value.it_value)?)
}

/// A validated nanosecond-resolution POSIX timer setting.
///
/// Unlike [`IntervalTimerValue`], this uses Linux's native `timespec` ABI and
/// therefore preserves sub-microsecond precision. The fields are private so
/// malformed nanoseconds and unrepresentable seconds cannot cross the safe
/// syscall boundary.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub struct TimerSpec {
    interval: Duration,
    value: Duration,
}

impl TimerSpec {
    /// Constructs a timer setting, returning `None` if seconds exceed Linux's
    /// signed `timespec.tv_sec` range.
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
    /// POSIX `timer_settime` flags.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct TimerSetFlags: u32 {
        /// Interpret the expiration as an absolute deadline on the selected
        /// clock instead of a relative duration.
        const ABSTIME = 1;
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// The supported Linux POSIX timer notification modes.
///
/// `SIGEV_THREAD` is intentionally absent: it requires a process runtime and
/// callback ownership boundary. Signal payloads are integer values, matching
/// Linux's `sigval` representation without exposing a raw C union.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum TimerNotification {
    /// Expiration has no notification side effect.
    None,
    /// Deliver `signal` with the supplied integer payload.
    Signal { signal: Signal, value: i32 },
    /// Deliver `signal` directly to `thread` with the supplied payload.
    ThreadId {
        thread: Pid,
        signal: Signal,
        value: i32,
    },
}

/// Errors returned by POSIX timer creation and operations.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TimerError {
    /// A timer setting cannot be represented by Linux's signed timespec ABI.
    InvalidSpecification,
    /// Linux rejected the clock, notification, timer ID, flag, or operation.
    Kernel(Errno),
}

impl TimerError {
    /// Returns the underlying kernel errno, when present.
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
/// The kernel timer ID is private and can only be retired through
/// [`Self::delete`]. Dropping an undeleted timer makes one best-effort direct
/// `timer_delete` syscall; its result cannot be reported from `Drop`.
pub struct PosixTimer {
    id: Option<i32>,
}

impl PosixTimer {
    /// Creates a timer on `clock` with the selected non-thread notification.
    #[inline]
    pub fn new(clock: ClockId, notification: TimerNotification) -> Result<Self> {
        let event = kernel_sigevent(notification);
        let mut id = 0i32;
        // SAFETY: `event` is the exact private 64-byte Linux sigevent layout,
        // and `id` is writable storage for the kernel timer ID.
        unsafe {
            crabc_core::time::timer_create_raw(
                clock as i32,
                (&event as *const KernelSigevent).cast(),
                &mut id,
            )?;
        }
        Ok(Self { id: Some(id) })
    }

    /// Returns the kernel timer ID for diagnostics and raw interoperation.
    #[must_use]
    #[inline]
    pub const fn as_raw(&self) -> i32 {
        match self.id {
            Some(id) => id,
            None => -1,
        }
    }

    /// Arms or disarms the timer and returns its previous setting.
    #[inline]
    pub fn settime(
        &self,
        flags: TimerSetFlags,
        new_value: TimerSpec,
    ) -> core::result::Result<TimerSpec, TimerError> {
        let new_value = kernel_itimerspec(new_value);
        let mut old_value = MaybeUninit::<crabc_core::time::KernelItimerspec>::uninit();
        // SAFETY: The timer ID is owned by `self`; the input is initialized;
        // Linux initializes old_value on success.
        unsafe {
            crabc_core::time::timer_settime_raw(
                self.as_raw(),
                flags.bits() as i32,
                (&new_value as *const crabc_core::time::KernelItimerspec).cast(),
                old_value.as_mut_ptr().cast(),
            )
            .map_err(TimerError::Kernel)?;
            timer_spec_from_kernel(old_value.assume_init()).ok_or(TimerError::InvalidSpecification)
        }
    }

    /// Reads the current setting of the timer.
    #[inline]
    pub fn gettime(&self) -> core::result::Result<TimerSpec, TimerError> {
        let mut value = MaybeUninit::<crabc_core::time::KernelItimerspec>::uninit();
        // SAFETY: The timer ID is owned by `self`; Linux initializes the full
        // output record on success.
        unsafe {
            crabc_core::time::timer_gettime_raw(self.as_raw(), value.as_mut_ptr().cast())
                .map_err(TimerError::Kernel)?;
            timer_spec_from_kernel(value.assume_init()).ok_or(TimerError::InvalidSpecification)
        }
    }

    /// Returns the number of expirations overrun since the last notification.
    #[inline]
    pub fn getoverrun(&self) -> Result<i32> {
        crabc_core::time::timer_getoverrun_raw(self.as_raw())
    }

    /// Explicitly deletes this timer.
    ///
    /// On an error the ID is retained so `Drop` can make a best-effort retry.
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

#[repr(C)]
struct KernelSigevent {
    value: usize,
    signal: i32,
    notify: i32,
    padding: [i32; 12],
}

#[inline]
fn kernel_sigevent(notification: TimerNotification) -> KernelSigevent {
    let (value, signal, notify, tid) = match notification {
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
    event.padding[0] = tid;
    event
}

#[inline]
fn kernel_itimerspec(value: TimerSpec) -> crabc_core::time::KernelItimerspec {
    fn timespec(value: Duration) -> crabc_core::time::KernelTimerTimespec {
        crabc_core::time::KernelTimerTimespec {
            tv_sec: value.as_secs() as i64,
            tv_nsec: value.subsec_nanos() as i64,
        }
    }
    crabc_core::time::KernelItimerspec {
        it_interval: timespec(value.interval),
        it_value: timespec(value.value),
    }
}

#[inline]
fn timer_spec_from_kernel(value: crabc_core::time::KernelItimerspec) -> Option<TimerSpec> {
    fn duration(value: crabc_core::time::KernelTimerTimespec) -> Option<Duration> {
        if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
            return None;
        }
        Some(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
    }
    TimerSpec::new(duration(value.it_interval)?, duration(value.it_value)?)
}

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
    /// `CLOCK_TAI` (Linux kernels with TAI support).
    Tai = 11,
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
            11 => Ok(Self::Tai),
            9 => Ok(Self::BoottimeAlarm),
            _ => Err(Errno::RANGE),
        }
    }
}

/// A validated Linux process CPU-clock identifier.
///
/// Linux represents a process CPU clock as `(-pid - 1) * 8 + 2`, using the
/// encoded value as a `clockid_t` rather than allocating a kernel object. The
/// value is private until [`clock_getcpuclockid`] has validated it with
/// `clock_getres`; this prevents a safe caller from manufacturing an ID for a
/// process which does not exist or is not visible in the caller's PID
/// namespace.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessClockId(i32);

impl ProcessClockId {
    /// Returns the Linux-encoded clock identifier.
    #[must_use]
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0
    }
}

/// Resolves a process CPU clock for `pid` without using libc or TLS `errno`.
///
/// `None` requests the calling process, matching Linux's `pid == 0` API
/// convention. Linux reports `EINVAL` for a process clock that cannot be
/// resolved; musl's `clock_getcpuclockid` translates that particular kernel
/// result to POSIX `ESRCH`, while preserving all other kernel errors.
pub fn clock_getcpuclockid(pid: Option<Pid>) -> Result<ProcessClockId> {
    // A clockid_t is signed 32-bit. Linux bounds real PIDs far below this,
    // but Pid intentionally permits any positive pid_t word. Refuse values
    // whose musl encoding would wrap into an unrelated known clock ID (for
    // example i32::MAX would become CLOCK_PROCESS_CPUTIME_ID for self).
    const MAX_ENCODED_PROCESS_PID: i32 = 268_435_455;
    if let Some(pid) = pid {
        if pid.as_raw_pid() > MAX_ENCODED_PROCESS_PID {
            return Err(Errno::SRCH);
        }
    }
    let raw_pid = Pid::as_raw(pid) as u32;
    // This is musl's `(-pid-1)*8 + 2` encoding evaluated with the same
    // unsigned wraparound as the Linux clock-id ABI.
    let id =
        raw_pid.wrapping_neg().wrapping_sub(1).wrapping_shl(3) | ClockId::ProcessCPUTime as u32;
    let id = id as i32;
    let mut resolution = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `resolution` is writable storage for the Linux timespec, and
    // the encoded scalar is validated by the kernel before construction of
    // the typed process-clock value.
    match unsafe { crabc_core::time::clock_getres_raw(id, resolution.as_mut_ptr().cast()) } {
        Err(Errno::INVAL) => Err(Errno::SRCH),
        Err(error) => Err(error),
        Ok(()) => {
            // The kernel initializes the timespec on success. We intentionally
            // do not expose it: resolution is only the validation operation.
            let _ = unsafe { resolution.assume_init() };
            Ok(ProcessClockId(id))
        }
    }
}

/// Linux clock identifiers accepted by [`clock_gettime_dynamic`].
///
/// `Known` contains clocks which are supported by Linux at runtime. `Dynamic`
/// encodes a borrowed clock device descriptor using Linux's `CLOCKFD` scheme;
/// the descriptor owner remains responsible for keeping it open for the
/// duration of the call. The named clock variants mirror Rustix's Linux
/// dynamic-clock vocabulary and may still be rejected by a particular kernel.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum DynamicClockId<'fd> {
    /// A clock identifier which is always supported at runtime.
    Known(ClockId),
    /// A validated process CPU clock returned by [`clock_getcpuclockid`].
    Process(ProcessClockId),
    /// A Linux dynamic clock backed by an open clock device descriptor.
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

/// Reads the current UTC timespec through Linux's realtime clock.
///
/// This is the native Rust counterpart of the C11 `timespec_get` operation
/// for its only supported Linux base, `TIME_UTC`. The C base discriminator and
/// its zero-success sentinel are intentionally absent: a safe caller can only
/// request UTC, and a syscall failure is returned as a typed [`Errno`]. The
/// operation is read-only and does not expose C ABI storage, locale/timezone
/// state, or TLS `errno`.
#[inline]
pub fn timespec_get() -> Result<Timespec> {
    clock_query_result(ClockId::Realtime as i32)
}

/// Sets a known Linux clock through the direct `clock_settime` syscall.
///
/// The nanosecond field is validated before the raw syscall so a safe caller
/// cannot cross the kernel boundary with a non-canonical `timespec`. Linux
/// still owns clock mutability and privilege checks: `Errno::INVAL` is
/// preserved for clocks such as [`ClockId::Monotonic`] that cannot be set,
/// while `Errno::PERM` is preserved when the caller lacks `CAP_SYS_TIME`.
#[inline]
pub fn clock_settime(id: ClockId, timespec: Timespec) -> Result<()> {
    if !(0..NANOS_PER_SECOND as i64).contains(&timespec.tv_nsec) {
        return Err(Errno::INVAL);
    }

    // SAFETY: `Timespec` is the exact Linux/AArch64 `struct timespec` layout,
    // and its nanosecond field was validated immediately above.
    unsafe { crabc_core::time::clock_settime_raw(id as i32, (&timespec as *const Timespec).cast()) }
}

/// Returns the current value of a known or descriptor-backed Linux clock.
///
/// This is the Rustix-shaped fallible companion to [`clock_gettime`]. Linux
/// validates the encoded clock identifier and can return an error such as
/// [`Errno::INVAL`] for a descriptor that is not a clock device. The query
/// uses the shared typed clock dispatcher with caller-owned, fully initialized
/// output storage. Eligible fixed clock IDs use the kernel vDSO; descriptor
/// clocks reach the same vDSO entry, which delegates unsupported IDs through
/// its exact kernel syscall fallback. It does not dispatch through libc or TLS
/// `errno`.
pub fn clock_gettime_dynamic(id: DynamicClockId<'_>) -> Result<Timespec> {
    clock_query_result(dynamic_clock_id(id))
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

/// Returns CPU time consumed by the calling process as a native duration.
///
/// This observes Linux's `CLOCK_PROCESS_CPUTIME_ID`, which accumulates user
/// and system CPU time for all threads in the process rather than wall-clock
/// elapsed time. The known-clock query is infallible by convention; a
/// malformed kernel timespec is treated as an impossible Linux contract
/// before constructing [`Duration`].
#[must_use]
#[inline]
pub fn process_cpu_time() -> Duration {
    let value = clock_gettime(ClockId::ProcessCPUTime);
    if value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= NANOS_PER_SECOND as i64 {
        panic!("Linux process CPU clock returned an invalid timespec");
    }
    Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
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

fn clock_query(id: ClockId, query: unsafe fn(i32, *mut u8) -> Result<()>) -> Timespec {
    let mut value = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `value` has exactly the Linux/AArch64 `timespec` layout and
    // the enum contains only statically supported Linux clock identifiers.
    match unsafe { query(id as i32, value.as_mut_ptr().cast()) } {
        Ok(()) => unsafe { value.assume_init() },
        Err(error) => panic!("known Linux clock query failed with errno {}", error.raw()),
    }
}

#[inline]
fn clock_query_result(clock_id: i32) -> Result<Timespec> {
    let mut value = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `value` has exactly the Linux/AArch64 `timespec` layout and the
    // direct syscall initializes it on success. Errors are returned before
    // the uninitialized value can be observed.
    unsafe {
        crabc_core::time::clock_gettime_raw(clock_id, value.as_mut_ptr().cast())?;
        Ok(value.assume_init())
    }
}

#[cfg(test)]
mod tests {
    use super::{RealtimeMillis, Timespec, NANOS_PER_SECOND};

    #[test]
    fn realtime_millis_conversion_preserves_signed_seconds_and_truncates() {
        let value = RealtimeMillis::from_timespec(Timespec {
            tv_sec: -1,
            tv_nsec: 999_999_999,
        })
        .expect("canonical kernel timespec");

        assert_eq!(value.seconds(), -1);
        assert_eq!(value.milliseconds(), 999);
        assert!(RealtimeMillis::from_timespec(Timespec {
            tv_sec: 0,
            tv_nsec: NANOS_PER_SECOND as i64,
        })
        .is_none());
    }
}
