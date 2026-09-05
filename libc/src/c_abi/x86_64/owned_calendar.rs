//! Owned C calendar conversions, pinned musl 1.2.6 (MIT), commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417: localtime[_r].c, mktime.c,
//! gmtime.c, asctime[_r].c and ctime[_r].c. UTC arithmetic remains in timegm;
//! owned_timezone owns TZ/rules/TZif state, owned_strftime owns formatting.
//! Separate static result objects preserve source overwrite/lifetime contracts.

use core::{ffi::{c_char, c_int, c_long}, ptr};
use super::{errno, gmtime_r, owned_timezone, timegm::{self, Tm}};

pub(super) const ZERO: Tm = Tm { seconds: 0, minutes: 0, hours: 0, month_day: 0,
    month: 0, year: 0, week_day: 0, year_day: 0, daylight_saving: 0,
    utc_offset: 0, utc_name: ptr::null() };
static mut LOCAL_RESULT: Tm = ZERO;
static mut UTC_RESULT: Tm = ZERO;
static mut ASCII_RESULT: [u8; 26] = [0; 26];
unsafe extern "C" {
    fn snprintf(output: *mut c_char, size: usize, format: *const c_char, ...) -> c_int;
    fn nl_langinfo(item: c_int) -> *mut c_char;
}

/// Convert an epoch count into local civil fields.
/// # Safety
/// Input is readable time_t storage; output is writable struct tm storage,
/// non-overlapping with input. Returned tm_zone is borrowed until TZ changes;
/// callers coordinate environment changes and subsequent use of zone strings.
#[no_mangle]
pub unsafe extern "C" fn localtime_r(input: *const c_long, output: *mut Tm) -> *mut Tm {
    unsafe {
        let seconds = *input;
        if seconds < c_int::MIN as i64 * 31622400 || seconds > c_int::MAX as i64 * 31622400 {
            errno::set_errno(75); return ptr::null_mut();
        }
        let zone = owned_timezone::zone(seconds, false);
        // Source publishes these three fields even if shifted calendar
        // conversion subsequently overflows; untouched fields need not be read.
        ptr::addr_of_mut!((*output).daylight_saving).write(zone.daylight);
        ptr::addr_of_mut!((*output).utc_offset).write(zone.offset);
        ptr::addr_of_mut!((*output).utc_name).write(zone.name);
        let mut result = ZERO;
        if !timegm::secs_to_tm(seconds + zone.offset, &mut result) {
            errno::set_errno(75); return ptr::null_mut();
        }
        result.daylight_saving = zone.daylight;
        result.utc_offset = zone.offset;
        result.utc_name = zone.name;
        output.write(result);
        output
    }
}

/// Normalize local civil fields, resolving explicit or inferred DST as musl.
/// # Safety
/// Value is initialized readable/writable struct tm storage. Zone-name and
/// environment coordination follow localtime_r. Failure leaves value untouched.
#[no_mangle]
pub unsafe extern "C" fn mktime(value: *mut Tm) -> c_long {
    unsafe {
        let input = value.read();
        let mut seconds = timegm::tm_to_secs(&input);
        let local = owned_timezone::zone(seconds, true);
        if input.daylight_saving >= 0 && local.daylight != input.daylight_saving {
            seconds -= local.opposite-local.offset;
        }
        seconds -= local.offset;
        let zone = owned_timezone::zone(seconds, false);
        let mut result = ZERO;
        if !timegm::secs_to_tm(seconds + zone.offset, &mut result) {
            errno::set_errno(75); return -1;
        }
        result.daylight_saving = zone.daylight;
        result.utc_offset = zone.offset;
        result.utc_name = zone.name;
        value.write(result);
        seconds
    }
}

/// Return static local-time storage, overwritten by the next localtime/ctime.
/// # Safety
/// Input is readable time_t storage. Callers exclude concurrent use of this
/// static result and honor localtime_r's borrowed zone-name lifetime.
#[no_mangle]
pub unsafe extern "C" fn localtime(input: *const c_long) -> *mut Tm {
    unsafe { localtime_r(input, ptr::addr_of_mut!(LOCAL_RESULT)) }
}

/// Return static UTC storage, overwritten by the next gmtime call.
/// # Safety
/// Input is readable time_t storage; callers exclude concurrent use of the
/// shared result. Use gmtime_r for caller-owned storage.
#[no_mangle]
pub unsafe extern "C" fn gmtime(input: *const c_long) -> *mut Tm {
    unsafe { gmtime_r::gmtime_r(input, ptr::addr_of_mut!(UTC_RESULT)) }
}

/// Format the fixed C 26-byte calendar string.
/// # Safety
/// Value is a readable initialized struct tm, output is non-overlapping
/// writable storage of at least 26 bytes. Fields must fit the mandated C
/// representation (including its four-digit year); like musl, overlong
/// representations trap rather than silently overflow caller storage.
#[no_mangle]
pub unsafe extern "C" fn asctime_r(value: *const Tm, output: *mut c_char) -> *mut c_char {
    unsafe {
        let tm = &*value;
        // LC_TIME is identical for every admitted locale, including C.
        let count = snprintf(output, 26, c"%.3s %.3s%3d %.2d:%.2d:%.2d %d\n".as_ptr(),
            nl_langinfo(0x20000 + tm.week_day),
            nl_langinfo(0x2000e + tm.month), tm.month_day,
            tm.hours, tm.minutes, tm.seconds, tm.year.wrapping_add(1900));
        if count >= 26 { core::arch::asm!("ud2", options(noreturn)); }
        output
    }
}

/// Return the fixed static C calendar string.
/// # Safety
/// Value satisfies asctime_r's field obligations. Callers exclude concurrent
/// use of this buffer, overwritten by subsequent asctime or ctime calls.
#[no_mangle]
pub unsafe extern "C" fn asctime(value: *const Tm) -> *mut c_char {
    unsafe { asctime_r(value, ptr::addr_of_mut!(ASCII_RESULT).cast()) }
}

/// Convert an epoch count to the static local C calendar string.
/// # Safety
/// Input and result lifetimes satisfy localtime and asctime; the year must fit
/// asctime's mandated representation. This call shares both static objects.
#[no_mangle]
pub unsafe extern "C" fn ctime(input: *const c_long) -> *mut c_char {
    unsafe { let tm = localtime(input); if tm.is_null() { ptr::null_mut() } else { asctime(tm) } }
}

/// Convert an epoch count to a caller-owned 26-byte local C calendar string.
/// # Safety
/// Input is readable time_t storage, output is non-overlapping writable
/// storage of at least 26 bytes, and the local year fits asctime's format.
#[no_mangle]
pub unsafe extern "C" fn ctime_r(input: *const c_long, output: *mut c_char) -> *mut c_char {
    unsafe {
        let mut tm = ZERO;
        if localtime_r(input, &mut tm).is_null() { ptr::null_mut() }
        else { asctime_r(&tm, output) }
    }
}
