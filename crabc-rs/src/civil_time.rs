//! Target-independent Unix-time, Gregorian-calendar, and explicit timezone projection values.
//!
//! This private implementation keeps the pinned-musl semantic UTC conversion
//! and rule-input-only local-calendar projection shared by the admitted native
//! facades. `crabc-rs/UPSTREAM.md` records the exact musl 1.2.6 source map,
//! license notice, and intentional Rust-native differences. It owns no clock,
//! C record, libc timezone state, or zoneinfo I/O.

use crate::{Errno, Result};

#[cfg(feature = "alloc")]
use crate::timezone::{OffsetInfo, TimeZone, UtcOffset};

/// Nanoseconds in one Unix-epoch second.
pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

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
    pub(crate) fn from_wall_clock_parts(seconds: i64, microseconds: i64) -> Option<Self> {
        if !(0..1_000_000).contains(&microseconds) {
            return None;
        }
        Self::from_parts(seconds, (microseconds as u32) * 1_000)
    }
}

/// A normalized UTC civil time in the range representable by musl's
/// `struct tm` year field on supported Linux targets.
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
    /// of seconds whose resulting `tm_year` would not fit in a C
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

/// Computes the difference between two signed Unix-epoch seconds.
///
/// The operands are converted independently, so the full signed `time_t`
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
