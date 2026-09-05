//! Selected static Linux/x86-64 C `timegm` boundary.
//!
//! This leaf owns exactly the GNU/BSD UTC broken-down-time inverse: it
//! normalizes one caller-owned LP64 `struct tm`, returns signed `time_t`, and
//! writes a fixed `UTC` offset/name result. It has no kernel call and does not
//! read process environment, zone rules, or mutable process-global state. It
//! is not local civil conversion, formatting/parsing, a calendar API family,
//! libc.so, CRT, dynamic TLS, loader, sysroot, allocator, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/time/timegm.c` maps to [`timegm`].
//! - `src/time/__tm_to_secs.c` maps to [`tm_to_secs`].
//! - `src/time/__secs_to_tm.c` maps to [`secs_to_tm`].
//! - `src/time/__year_to_secs.c` maps to [`year_to_secs`].
//! - `src/time/__month_to_secs.c` maps to [`month_to_secs`].
//!
//! The source's bounded `int` input domain makes every intermediate fit in an
//! `i64`. The wrapping spellings below suppress debug-overflow machinery while
//! retaining those exact values for every representable x86 `struct tm`.

use core::ffi::{c_char, c_int, c_long};

use super::errno::set_errno;

const EOVERFLOW: c_int = 75;
const LEAPOCH: i64 = 946_684_800 + 86_400 * (31 + 29);
const DAYS_PER_400Y: i64 = 365 * 400 + 97;
const DAYS_PER_100Y: i64 = 365 * 100 + 24;
const DAYS_PER_4Y: i64 = 365 * 4 + 1;
const SECONDS_PER_DAY: i64 = 86_400;
pub(super) static UTC: [u8; 4] = *b"UTC\0";
const SECS_THROUGH_MONTH: [i64; 12] = [
    0,
    31 * SECONDS_PER_DAY,
    59 * SECONDS_PER_DAY,
    90 * SECONDS_PER_DAY,
    120 * SECONDS_PER_DAY,
    151 * SECONDS_PER_DAY,
    181 * SECONDS_PER_DAY,
    212 * SECONDS_PER_DAY,
    243 * SECONDS_PER_DAY,
    273 * SECONDS_PER_DAY,
    304 * SECONDS_PER_DAY,
    334 * SECONDS_PER_DAY,
];
const DAYS_IN_MONTH: [c_int; 12] = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29];

/// Exact Linux/x86-64 GNU `struct tm` storage.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tm {
    pub(super) seconds: c_int,
    pub(super) minutes: c_int,
    pub(super) hours: c_int,
    pub(super) month_day: c_int,
    pub(super) month: c_int,
    pub(super) year: c_int,
    pub(super) week_day: c_int,
    pub(super) year_day: c_int,
    pub(super) daylight_saving: c_int,
    pub(super) utc_offset: c_long,
    pub(super) utc_name: *const c_char,
}

const _: () = {
    assert!(core::mem::size_of::<Tm>() == 56);
    assert!(core::mem::align_of::<Tm>() == 8);
    assert!(core::mem::offset_of!(Tm, seconds) == 0);
    assert!(core::mem::offset_of!(Tm, minutes) == 4);
    assert!(core::mem::offset_of!(Tm, hours) == 8);
    assert!(core::mem::offset_of!(Tm, month_day) == 12);
    assert!(core::mem::offset_of!(Tm, month) == 16);
    assert!(core::mem::offset_of!(Tm, year) == 20);
    assert!(core::mem::offset_of!(Tm, week_day) == 24);
    assert!(core::mem::offset_of!(Tm, year_day) == 28);
    assert!(core::mem::offset_of!(Tm, daylight_saving) == 32);
    assert!(core::mem::offset_of!(Tm, utc_offset) == 40);
    assert!(core::mem::offset_of!(Tm, utc_name) == 48);
};

/// Translate musl's March-based year calculation exactly.
#[inline]
pub(super) fn year_to_secs(year: i64, is_leap: &mut bool) -> i64 {
    // musl writes `year-2ULL <= 136`; the unsigned conversion is material for
    // years before 2, so retain it rather than replacing it with a signed test.
    if (year as u64).wrapping_sub(2) <= 136 {
        let year = year as c_int;
        let mut leaps = (year - 68) >> 2;
        if (year - 68) & 3 == 0 {
            leaps -= 1;
            *is_leap = true;
        } else {
            *is_leap = false;
        }
        return i64::from(year - 70)
            .wrapping_mul(31_536_000)
            .wrapping_add(i64::from(leaps).wrapping_mul(SECONDS_PER_DAY));
    }

    let mut cycles = (year.wrapping_sub(100) / 400) as c_int;
    let mut remainder = (year.wrapping_sub(100) % 400) as c_int;
    if remainder < 0 {
        cycles -= 1;
        remainder += 400;
    }

    let centuries: c_int;
    let leaps: c_int;
    if remainder == 0 {
        *is_leap = true;
        centuries = 0;
        leaps = 0;
    } else {
        if remainder >= 200 {
            if remainder >= 300 {
                centuries = 3;
                remainder -= 300;
            } else {
                centuries = 2;
                remainder -= 200;
            }
        } else if remainder >= 100 {
            centuries = 1;
            remainder -= 100;
        } else {
            centuries = 0;
        }
        if remainder == 0 {
            *is_leap = false;
            leaps = 0;
        } else {
            leaps = remainder / 4;
            remainder %= 4;
            *is_leap = remainder == 0;
        }
    }

    let total_leaps = i64::from(leaps)
        .wrapping_add(i64::from(cycles).wrapping_mul(97))
        .wrapping_add(i64::from(centuries).wrapping_mul(24))
        .wrapping_sub(i64::from(*is_leap));
    year.wrapping_sub(100)
        .wrapping_mul(31_536_000)
        .wrapping_add(total_leaps.wrapping_mul(SECONDS_PER_DAY))
        .wrapping_add(946_684_800)
        .wrapping_add(SECONDS_PER_DAY)
}

/// Translate musl's normalized January-based month offset.
#[inline]
pub(super) fn month_to_secs(month: c_int, is_leap: bool) -> i64 {
    let mut seconds = SECS_THROUGH_MONTH[month as usize];
    if is_leap && month >= 2 {
        seconds = seconds.wrapping_add(SECONDS_PER_DAY);
    }
    seconds
}

/// Normalize C input fields into musl's signed UTC second count.
#[inline]
pub(super) fn tm_to_secs(value: &Tm) -> i64 {
    let mut year = i64::from(value.year);
    let mut month = value.month;
    if !(0..12).contains(&month) {
        let mut adjustment = month / 12;
        month %= 12;
        if month < 0 {
            adjustment = adjustment.wrapping_sub(1);
            month += 12;
        }
        year = year.wrapping_add(i64::from(adjustment));
    }

    let mut is_leap = false;
    let mut seconds = year_to_secs(year, &mut is_leap);
    seconds = seconds.wrapping_add(month_to_secs(month, is_leap));
    seconds = seconds.wrapping_add(
        i64::from(value.month_day)
            .wrapping_sub(1)
            .wrapping_mul(SECONDS_PER_DAY),
    );
    seconds = seconds.wrapping_add(i64::from(value.hours).wrapping_mul(3_600));
    seconds = seconds.wrapping_add(i64::from(value.minutes).wrapping_mul(60));
    seconds.wrapping_add(i64::from(value.seconds))
}

/// Translate musl's signed seconds-to-normalized-fields calculation.
#[inline]
pub(super) fn secs_to_tm(seconds: i64, output: &mut Tm) -> bool {
    if seconds < i64::from(c_int::MIN).wrapping_mul(31_622_400)
        || seconds > i64::from(c_int::MAX).wrapping_mul(31_622_400)
    {
        return false;
    }

    let elapsed = seconds.wrapping_sub(LEAPOCH);
    let mut days = elapsed / SECONDS_PER_DAY;
    let mut remaining_seconds = (elapsed % SECONDS_PER_DAY) as c_int;
    if remaining_seconds < 0 {
        remaining_seconds += SECONDS_PER_DAY as c_int;
        days = days.wrapping_sub(1);
    }

    let mut week_day = ((3_i64.wrapping_add(days)) % 7) as c_int;
    if week_day < 0 {
        week_day += 7;
    }

    let mut quadricentennial_cycles = (days / DAYS_PER_400Y) as c_int;
    let mut remaining_days = (days % DAYS_PER_400Y) as c_int;
    if remaining_days < 0 {
        remaining_days += DAYS_PER_400Y as c_int;
        quadricentennial_cycles -= 1;
    }
    let mut centennial_cycles = remaining_days / DAYS_PER_100Y as c_int;
    if centennial_cycles == 4 {
        centennial_cycles -= 1;
    }
    remaining_days -= centennial_cycles * DAYS_PER_100Y as c_int;
    let mut quadrennial_cycles = remaining_days / DAYS_PER_4Y as c_int;
    if quadrennial_cycles == 25 {
        quadrennial_cycles -= 1;
    }
    remaining_days -= quadrennial_cycles * DAYS_PER_4Y as c_int;
    let mut remaining_years = remaining_days / 365;
    if remaining_years == 4 {
        remaining_years -= 1;
    }
    remaining_days -= remaining_years * 365;

    let leap = remaining_years == 0
        && (quadrennial_cycles != 0 || centennial_cycles == 0);
    let mut year_day = remaining_days + 31 + 28 + c_int::from(leap);
    if year_day >= 365 + c_int::from(leap) {
        year_day -= 365 + c_int::from(leap);
    }

    let mut years = i64::from(remaining_years)
        .wrapping_add(i64::from(quadrennial_cycles).wrapping_mul(4))
        .wrapping_add(i64::from(centennial_cycles).wrapping_mul(100))
        .wrapping_add(i64::from(quadricentennial_cycles).wrapping_mul(400));
    let mut months = 0_i32;
    for days_in_month in DAYS_IN_MONTH {
        if days_in_month <= remaining_days {
            remaining_days -= days_in_month;
            months += 1;
        } else {
            break;
        }
    }
    if months >= 10 {
        months -= 12;
        years = years.wrapping_add(1);
    }

    let tm_year = years.wrapping_add(100);
    if tm_year > i64::from(c_int::MAX) || tm_year < i64::from(c_int::MIN) {
        return false;
    }

    output.year = tm_year as c_int;
    output.month = months + 2;
    output.month_day = remaining_days + 1;
    output.week_day = week_day;
    output.year_day = year_day;
    output.hours = remaining_seconds / 3_600;
    output.minutes = remaining_seconds / 60 % 60;
    output.seconds = remaining_seconds % 60;
    true
}

/// Build one complete UTC record for the two selected caller-buffered
/// conversions. This is a private Rust helper, not a C ABI export.
pub(super) fn secs_to_utc_tm(seconds: i64) -> Option<Tm> {
    let mut output = Tm {
        seconds: 0,
        minutes: 0,
        hours: 0,
        month_day: 0,
        month: 0,
        year: 0,
        week_day: 0,
        year_day: 0,
        daylight_saving: 0,
        utc_offset: 0,
        utc_name: core::ptr::null(),
    };
    if !secs_to_tm(seconds, &mut output) {
        return None;
    }
    output.daylight_saving = 0;
    output.utc_offset = 0;
    output.utc_name = UTC.as_ptr().cast::<c_char>();
    Some(output)
}

/// Normalize one caller-owned UTC `struct tm` and return its Unix seconds.
///
/// # Safety
///
/// `value` must designate initialized, writable 56-byte Linux/x86-64
/// `struct tm` storage for the duration of the call. C supplies no null or
/// partially initialized fallback. On a representability failure the complete
/// caller record is left untouched and initial-TLS errno becomes
/// `EOVERFLOW`; a successful `-1` result remains a valid pre-epoch instant.
#[no_mangle]
pub unsafe extern "C" fn timegm(value: *mut Tm) -> c_long {
    // SAFETY: the C caller supplies initialized exact `struct tm` storage.
    let input = unsafe { value.read() };
    let seconds = tm_to_secs(&input);
    let Some(normalized) = secs_to_utc_tm(seconds) else {
        // SAFETY: this C error boundary owns the selected initial-TLS errno.
        unsafe { set_errno(EOVERFLOW) };
        return -1;
    };
    // SAFETY: the C caller supplied writable exact `struct tm` storage.
    unsafe { value.write(normalized) };
    seconds
}
