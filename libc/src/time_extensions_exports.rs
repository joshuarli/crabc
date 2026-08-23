// C11 time extension. `TIME_UTC` is the only standardized base; an
// unsupported base is a query failure and must not modify the output object.

use super::{
    c_char, c_int, clock_gettime, locale_t, strftime, timespec, tm, CLOCK_REALTIME,
};

const CABI_TIME_UTC: c_int = 1;

#[no_mangle]
pub unsafe extern "C" fn timespec_get(output: *mut timespec, base: c_int) -> c_int {
    if base != CABI_TIME_UTC {
        return 0;
    }
    if clock_gettime(CLOCK_REALTIME, output) != 0 {
        return 0;
    }
    CABI_TIME_UTC
}

// crabc currently provides the C/POSIX time locale only, so a locale object
// cannot alter strftime's output.  Keeping this as a real forwarding entry
// point preserves the bounded-output and calendar-format behavior of
// strftime while satisfying musl's weak locale-aware ABI spelling.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn strftime_l(
    output: *mut c_char,
    maxsize: usize,
    format: *const c_char,
    value: *const tm,
    _locale: locale_t,
) -> usize {
    strftime(output, maxsize, format, value)
}
