//! Calendar text parsing for the installed C runtime.
//!
//! Translated from MIT-licensed musl 1.2.6 `src/time/strptime.c`, revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`. Numeric field widths, partial
//! writes on failure, recursive composite fields and century precedence map
//! directly to that source. The existing LC_TIME table provides names and
//! composite formats for C/POSIX/C.UTF-8. Week/epoch fields retain musl's
//! parse-only behavior; they do not infer calendar fields.
//!
//! One memory-safety correction is explicit: an unknown `%Z` name consumes
//! only ASCII letters and stops at NUL. Musl's signed subtraction in that
//! branch also admits NUL, reading into an adjacent guard page. The installed
//! probe retains both that oracle failure and the bounded candidate result.
//! Digits, punctuation, control bytes and high bytes also terminate the owned
//! fallback instead of being consumed by the source signed-character loop.

use core::{ffi::{c_char, c_int}, ptr};
use super::{owned_timezone, timegm::Tm};

unsafe extern "C" {
    fn nl_langinfo(item: c_int) -> *mut c_char;
    fn strlen(input: *const c_char) -> usize;
    fn strncasecmp(left: *const c_char, right: *const c_char, count: usize) -> c_int;
    fn strncmp(left: *const c_char, right: *const c_char, count: usize) -> c_int;
    fn strtoul(input: *const c_char, end: *mut *mut c_char, base: c_int) -> u64;
}

fn digit(value: u8) -> bool { value.is_ascii_digit() }
fn space(value: u8) -> bool { matches!(value, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12) }

/// Keep writes to individual fields: a C caller need not initialize fields
/// which its format never reads. Failed numeric ranges retain the parsed raw
/// value, matching the source's assignment before its range check.
unsafe fn numeric(mut input: *const u8, destination: *mut c_int,
    width: c_int, range: Option<(c_int, c_int)>, adjustment: c_int) -> *const u8 {
    unsafe {
        let mut negative = false;
        if range.is_none() {
            if *input == b'+' { input = input.add(1); }
            else if *input == b'-' { negative = true; input = input.add(1); }
        }
        if !digit(*input) { return ptr::null(); }
        *destination = 0;
        if let Some((minimum, count)) = range {
            let mut place = 1;
            while place <= minimum + count && digit(*input) {
                *destination = *destination * 10 + (*input - b'0') as c_int;
                input = input.add(1);
                place *= 10;
            }
            if destination.read().wrapping_sub(minimum) as u32 >= count as u32 {
                return ptr::null();
            }
        } else {
            let mut consumed = 0;
            while consumed < width && digit(*input) {
                *destination = destination.read().wrapping_mul(10).wrapping_add((*input - b'0') as c_int);
                input = input.add(1);
                consumed += 1;
            }
            if negative { *destination = destination.read().wrapping_neg(); }
        }
        *destination = destination.read().wrapping_sub(adjustment);
        input
    }
}

unsafe fn symbolic(input: *const u8, destination: *mut c_int,
    first: c_int, count: c_int) -> *const u8 {
    unsafe {
        for index in (0..2 * count).rev() {
            let name = nl_langinfo(first + index);
            let length = strlen(name);
            if strncasecmp(input.cast(), name, length) == 0 {
                *destination = index % count;
                return input.add(length);
            }
        }
        ptr::null()
    }
}

unsafe fn parse(mut input: *const u8, mut format: *const u8, value: *mut Tm) -> *const u8 {
    unsafe {
        let mut want_century = 0;
        let mut century: c_int = 0;
        let mut relative_year: c_int = 0;
        while *format != 0 {
            if *format != b'%' {
                if space(*format) { while space(*input) { input = input.add(1); } }
                else if *input != *format { return ptr::null(); }
                else { input = input.add(1); }
                format = format.add(1);
                continue;
            }
            format = format.add(1);
            if *format == b'+' { format = format.add(1); }
            let mut width = -1;
            if digit(*format) {
                let mut end = ptr::null_mut();
                width = strtoul(format.cast(), &mut end, 10) as c_int;
                format = end.cast();
            }
            let conversion = *format;
            // A dangling '%' is a failed format; do not advance beyond NUL.
            if conversion == 0 { return ptr::null(); }
            format = format.add(1);
            let mut dummy = 0;
            let mut numeric_field = None;
            match conversion {
                b'a' | b'A' => input = symbolic(input, ptr::addr_of_mut!((*value).week_day), 0x20000, 7),
                b'b' | b'B' | b'h' => input = symbolic(input, ptr::addr_of_mut!((*value).month), 0x2000e, 12),
                b'c' => input = parse(input, nl_langinfo(0x20028).cast(), value),
                b'C' => {
                    want_century |= 2;
                    numeric_field = Some((ptr::addr_of_mut!(century), if width < 0 { 2 } else { width }, None, 0));
                }
                b'd' | b'e' => numeric_field = Some((ptr::addr_of_mut!((*value).month_day), 0, Some((1, 31)), 0)),
                b'D' => input = parse(input, c"%m/%d/%y".as_ptr().cast(), value),
                b'F' => {
                    // The width bounds the complete date, not its year. Keep
                    // musl's signed-prefix/leading-zero treatment and 20-byte
                    // recursive scratch, including the consumed suffix repair.
                    let mut temporary = [0u8; 20];
                    let mut length = 0;
                    if matches!(*input, b'-' | b'+') {
                        temporary[length] = *input; length += 1; input = input.add(1);
                    }
                    while *input == b'0' && digit(*input.add(1)) { input = input.add(1); }
                    while *input != 0 && length < width as usize && length + 1 < temporary.len() {
                        temporary[length] = *input; input = input.add(1); length += 1;
                    }
                    let end = parse(temporary.as_ptr(), c"%12Y-%m-%d".as_ptr().cast(), value);
                    if end.is_null() { return ptr::null(); }
                    input = input.sub(length - end.offset_from(temporary.as_ptr()) as usize);
                }
                b'H' => numeric_field = Some((ptr::addr_of_mut!((*value).hours), 0, Some((0, 24)), 0)),
                b'I' => numeric_field = Some((ptr::addr_of_mut!((*value).hours), 0, Some((1, 12)), 0)),
                b'j' => numeric_field = Some((ptr::addr_of_mut!((*value).year_day), 0, Some((1, 366)), 1)),
                b'm' => numeric_field = Some((ptr::addr_of_mut!((*value).month), 0, Some((1, 12)), 1)),
                b'M' => numeric_field = Some((ptr::addr_of_mut!((*value).minutes), 0, Some((0, 60)), 0)),
                b'n' | b't' => { while space(*input) { input = input.add(1); } }
                b'p' => {
                    let mut matched = false;
                    for afternoon in 0..2 {
                        let name = nl_langinfo(0x20026 + afternoon);
                        let length = strlen(name);
                        if strncasecmp(input.cast(), name, length) == 0 {
                            (*value).hours = (*value).hours % 12 + afternoon * 12;
                            input = input.add(length); matched = true; break;
                        }
                    }
                    if !matched { return ptr::null(); }
                }
                b'r' => input = parse(input, nl_langinfo(0x2002b).cast(), value),
                b'R' => input = parse(input, c"%H:%M".as_ptr().cast(), value),
                b's' => {
                    if *input == b'-' { input = input.add(1); }
                    if !digit(*input) { return ptr::null(); }
                    while digit(*input) { input = input.add(1); }
                }
                b'S' => numeric_field = Some((ptr::addr_of_mut!((*value).seconds), 0, Some((0, 61)), 0)),
                b'T' => input = parse(input, c"%H:%M:%S".as_ptr().cast(), value),
                b'U' | b'W' => numeric_field = Some((ptr::addr_of_mut!(dummy), 0, Some((0, 54)), 0)),
                b'V' => numeric_field = Some((ptr::addr_of_mut!(dummy), 0, Some((1, 53)), 0)),
                b'g' => numeric_field = Some((ptr::addr_of_mut!(dummy), 2, None, 0)),
                b'G' => numeric_field = Some((ptr::addr_of_mut!(dummy), if width < 0 { 4 } else { width }, None, 0)),
                b'u' => numeric_field = Some((ptr::addr_of_mut!((*value).week_day), 0, Some((1, 7)), 0)),
                b'w' => numeric_field = Some((ptr::addr_of_mut!((*value).week_day), 0, Some((0, 7)), 0)),
                b'x' => input = parse(input, nl_langinfo(0x20029).cast(), value),
                b'X' => input = parse(input, nl_langinfo(0x2002a).cast(), value),
                b'y' => {
                    want_century |= 1;
                    numeric_field = Some((ptr::addr_of_mut!(relative_year), 2, None, 0));
                }
                b'Y' => {
                    want_century = 0;
                    numeric_field = Some((ptr::addr_of_mut!((*value).year), if width < 0 { 4 } else { width }, None, 1900));
                }
                b'z' => {
                    if !matches!(*input, b'+' | b'-') { return ptr::null(); }
                    for offset in 1..=4 { if !digit(*input.add(offset)) { return ptr::null(); } }
                    let seconds = (*input.add(1) - b'0') as i64 * 36000
                        + (*input.add(2) - b'0') as i64 * 3600
                        + (*input.add(3) - b'0') as i64 * 600
                        + (*input.add(4) - b'0') as i64 * 60;
                    (*value).utc_offset = if *input == b'-' { -seconds } else { seconds };
                    input = input.add(5);
                }
                b'Z' => {
                    let mut matched = false;
                    for daylight in 0..2 {
                        let name = owned_timezone::__tzname[daylight];
                        let length = strlen(name);
                        if strncmp(input.cast(), name, length) == 0 {
                            (*value).daylight_saving = daylight as c_int;
                            input = input.add(length); matched = true; break;
                        }
                    }
                    if !matched { while (*input).is_ascii_alphabetic() { input = input.add(1); } }
                }
                b'%' => { if *input != b'%' { return ptr::null(); } input = input.add(1); }
                _ => return ptr::null(),
            }
            if let Some((destination, digits, range, adjustment)) = numeric_field {
                input = numeric(input, destination, digits, range, adjustment);
            }
            if input.is_null() { return ptr::null(); }
        }
        if want_century != 0 {
            (*value).year = relative_year;
            if want_century & 2 != 0 {
                (*value).year = relative_year.wrapping_add(century.wrapping_mul(100).wrapping_sub(1900));
            } else if (*value).year <= 68 { (*value).year += 100; }
        }
        input
    }
}

// Musl's `src/time/strptime.c` object.
static_archive_member! { strptime_source {
    /// Parse C/POSIX/C.UTF-8 calendar text into the fields selected by `format`.
    ///
    /// # Safety
    /// `input` and `format` are readable NUL-terminated strings, disjoint from the
    /// writable, aligned `Tm` storage. Fields read by directives (notably `%p`)
    /// must be initialized. `%Z` uses the timezone names initialized by `tzset`;
    /// callers must serialize timezone mutation with their use. The returned
    /// pointer borrows `input`; null reports failure and may leave partial fields.
    #[no_mangle]
    pub unsafe extern "C" fn strptime(input: *const c_char, format: *const c_char,
        value: *mut Tm) -> *mut c_char {
        unsafe { parse(input.cast(), format.cast(), value).cast_mut().cast() }
    }
}}
