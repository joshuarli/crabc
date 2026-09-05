//! Template-file calendar parsing for the installed runtime.
//!
//! Semantic translation of musl 1.2.6 `src/time/getdate.c`, release revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT, upstream COPYRIGHT).
//! `getdate` below maps the complete function, including its 100-byte fgets
//! chunks, persistent result, partial strptime writes, and getdate_err rules.
//! It supplies no inferred calendar defaults beyond the source's zero-initial
//! process-global record. The cancellation operation is deliberately the
//! source's setcancelstate(0), not a change to the cancellation type.

use core::{ffi::{c_char, c_int}, ptr};
use super::{errno, environment, owned_strptime, pthread_cancel,
    stdio_standard as stdio, timegm::Tm};

/// Shared error indicator; callers serialize accesses with `getdate`.
#[no_mangle]
pub static mut getdate_err: c_int = 0;

static mut RESULT: Tm = Tm {
    seconds: 0, minutes: 0, hours: 0, month_day: 0, month: 0, year: 0,
    week_day: 0, year_day: 0, daylight_saving: 0, utc_offset: 0,
    utc_name: ptr::null(),
};

/// Read DATEMSK templates and parse a complete input into shared calendar storage.
///
/// # Safety
/// `input` must be a readable NUL-terminated string. Callers must serialize
/// this function, accesses to `getdate_err`, and all accesses to the returned
/// record. A later call can overwrite the record even when parsing fails.
/// The process environment and timezone names must not be concurrently
/// mutated; `%Z` templates require the timezone state to be initialized.
#[no_mangle]
pub unsafe extern "C" fn getdate(input: *const c_char) -> *mut Tm {
    unsafe {
        let mask = environment::getenv(c"DATEMSK".as_ptr());
        let mut saved_state = 0;
        let mut result = ptr::null_mut();
        let mut file = ptr::null_mut();
        pthread_cancel::pthread_setcancelstate(0, &mut saved_state);
        if mask.is_null() {
            getdate_err = 1;
        } else {
            file = stdio::fopen(mask, c"rbe".as_ptr());
            if file.is_null() {
                getdate_err = if errno::get_errno() == 12 { 6 } else { 2 };
            } else {
                let mut format = [0 as c_char; 100];
                while !stdio::fgets(format.as_mut_ptr(), 100, file).is_null() {
                    let end = owned_strptime::strptime(input, format.as_ptr(), &raw mut RESULT);
                    if !end.is_null() && *end == 0 {
                        result = &raw mut RESULT;
                        break;
                    }
                }
                if result.is_null() {
                    getdate_err = if stdio::ferror(file) != 0 { 5 } else { 7 };
                }
            }
        }
        if !file.is_null() { stdio::fclose(file); }
        pthread_cancel::pthread_setcancelstate(saved_state, ptr::null_mut());
        result
    }
}
