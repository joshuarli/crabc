//! Byte calendar formatting translated from musl 1.2.6 strftime.c (MIT),
//! revision 9fa28ece75d8a2191de7c5bb53bed224c5947417. Directive expansion,
//! ISO-week arithmetic, padding/extended-year rules and partial-buffer failure
//! semantics retain that source. Existing owned snprintf supplies integer
//! rendering; the existing C/POSIX/C.UTF-8 LC_TIME table supplies language data.
//! No locale database, wide formatting, or independent numeric formatter.

use core::{ffi::{c_char, c_int, c_void}, ptr};
use super::{owned_timezone, timegm::{self, Tm}};
unsafe extern "C" {
    fn snprintf(output: *mut c_char, capacity: usize, format: *const c_char, ...) -> c_int;
    fn strtoul(input: *const c_char, end: *mut *mut c_char, base: c_int) -> u64;
    fn nl_langinfo(item: c_int) -> *mut c_char;
    fn nl_langinfo_l(item: c_int, locale: *mut c_void) -> *mut c_char;
}

fn leap(mut year: i32) -> bool {
    if year > i32::MAX-1900 { year -= 2000; }
    year += 1900;
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
fn week_number(tm: &Tm) -> i32 {
    let day = tm.week_day as u32;
    let ordinal = tm.year_day as u32;
    let mut value = ordinal.wrapping_add(7).wrapping_sub(day.wrapping_add(6)%7) / 7;
    if day.wrapping_add(371).wrapping_sub(ordinal).wrapping_sub(2)%7 <= 2 { value += 1; }
    if value == 0 {
        value = 52;
        let december31 = day.wrapping_add(7).wrapping_sub(ordinal).wrapping_sub(1)%7;
        if december31 == 4 || (december31 == 5 && leap(tm.year%400-1)) { value += 1; }
    } else if value == 53 {
        let january1 = day.wrapping_add(371).wrapping_sub(ordinal)%7;
        if january1 != 4 && (january1 != 3 || !leap(tm.year)) { value = 1; }
    }
    value as i32
}
unsafe fn language(item: c_int, locale: Option<*mut c_void>) -> *const c_char {
    unsafe { match locale { Some(locale) => nl_langinfo_l(item, locale), None => nl_langinfo(item) } }
}
unsafe fn string(pointer: *const c_char) -> (*const u8, usize) {
    unsafe {
        let mut n = 0;
        while *pointer.add(n) != 0 { n += 1; }
        (pointer.cast(), n)
    }
}

unsafe fn directive(buffer: *mut u8, conversion: u8, tm: &Tm,
    locale: Option<*mut c_void>, pad: u8) -> Option<(*const u8, usize)> {
    unsafe {
        let mut width: i32 = 2;
        let mut default_pad = b'0';
        let mut recursive: *const c_char = ptr::null();
        let value: i64;
        match conversion {
            b'a' | b'A' => {
                if tm.week_day as u32 > 6 { return Some(string(c"-".as_ptr())); }
                return Some(string(language(0x20000 + tm.week_day + if conversion == b'A' { 7 } else { 0 }, locale)));
            }
            b'h' | b'b' | b'B' => {
                if tm.month as u32 > 11 { return Some(string(c"-".as_ptr())); }
                return Some(string(language(0x2000e + tm.month + if conversion == b'B' { 12 } else { 0 }, locale)));
            }
            b'c' => { recursive = language(0x20028, locale); value = 0; }
            b'C' => value = (1900i64 + tm.year as i64)/100,
            b'e' | b'd' => { if conversion == b'e' { default_pad = b'_'; } value = tm.month_day as i64; }
            b'D' => { recursive = c"%m/%d/%y".as_ptr(); value = 0; }
            b'F' => { recursive = c"%Y-%m-%d".as_ptr(); value = 0; }
            b'g' | b'G' => {
                let mut year = tm.year as i64 + 1900;
                if tm.year_day < 3 && week_number(tm) != 1 { year -= 1; }
                else if tm.year_day > 360 && week_number(tm) == 1 { year += 1; }
                if conversion == b'g' { year %= 100; } else { width = 4; }
                value = year;
            }
            b'H' => value = tm.hours as i64,
            b'I' => value = if tm.hours == 0 { 12 } else if tm.hours > 12 { tm.hours as i64-12 } else { tm.hours as i64 },
            b'j' => { value = tm.year_day.wrapping_add(1) as i64; width = 3; }
            b'm' => value = tm.month.wrapping_add(1) as i64,
            b'M' => value = tm.minutes as i64,
            b'n' => return Some((b"\n".as_ptr(), 1)),
            b'p' => return Some(string(language(if tm.hours >= 12 { 0x20027 } else { 0x20026 }, locale))),
            b'r' => { recursive = language(0x2002b, locale); value = 0; }
            b'R' => { recursive = c"%H:%M".as_ptr(); value = 0; }
            b's' => { value = timegm::tm_to_secs(tm).wrapping_sub(tm.utc_offset); width = 1; }
            b'S' => value = tm.seconds as i64,
            b't' => return Some((b"\t".as_ptr(), 1)),
            b'T' => { recursive = c"%H:%M:%S".as_ptr(); value = 0; }
            b'u' => { value = if tm.week_day != 0 { tm.week_day as i64 } else { 7 }; width = 1; }
            b'U' => value = ((tm.year_day as u32).wrapping_add(7).wrapping_sub(tm.week_day as u32)/7) as i64,
            b'W' => value = ((tm.year_day as u32).wrapping_add(7).wrapping_sub((tm.week_day as u32).wrapping_add(6)%7)/7) as i64,
            b'V' => value = week_number(tm) as i64,
            b'w' => { value = tm.week_day as i64; width = 1; }
            b'x' => { recursive = language(0x20029, locale); value = 0; }
            b'X' => { recursive = language(0x2002a, locale); value = 0; }
            b'y' => value = ((tm.year as i64 + 1900)%100).abs(),
            b'Y' => {
                value = tm.year as i64 + 1900;
                if value >= 10000 {
                    let n = snprintf(buffer.cast(), 100, c"+%lld".as_ptr(), value);
                    return Some((buffer, n as usize));
                }
                width = 4;
            }
            b'z' => {
                if tm.daylight_saving < 0 { return Some((c"".as_ptr().cast(), 0)); }
                let n = snprintf(buffer.cast(), 100, c"%+.4ld".as_ptr(),
                    (tm.utc_offset/3600).wrapping_mul(100) + tm.utc_offset%3600/60);
                return Some((buffer, n as usize));
            }
            b'Z' => return Some(if tm.daylight_saving < 0 { (c"".as_ptr().cast(), 0) }
                else { string(owned_timezone::tm_zone_name(tm)) }),
            b'%' => return Some((b"%".as_ptr(), 1)),
            _ => return None,
        }
        if !recursive.is_null() {
            let n = format(buffer, 100, recursive.cast(), tm, locale);
            return if n == 0 { None } else { Some((buffer, n)) };
        }
        let n = match if pad == 0 { default_pad } else { pad } {
            b'-' => snprintf(buffer.cast(), 100, c"%lld".as_ptr(), value),
            b'_' => snprintf(buffer.cast(), 100, c"%*lld".as_ptr(), width, value),
            _ => snprintf(buffer.cast(), 100, c"%0*lld".as_ptr(), width, value),
        };
        Some((buffer, n as usize))
    }
}

unsafe fn format(output: *mut u8, capacity: usize, mut input: *const u8,
    tm: &Tm, locale: Option<*mut c_void>) -> usize {
    unsafe {
        let mut length = 0;
        let mut buffer = [0u8; 100];
        while length < capacity {
            if *input == 0 { *output.add(length) = 0; return length; }
            if *input != b'%' { *output.add(length) = *input; length += 1; input = input.add(1); continue; }
            input = input.add(1);
            let mut pad = 0;
            if matches!(*input, b'-' | b'_' | b'0') { pad = *input; input = input.add(1); }
            let plus = *input == b'+';
            if plus { input = input.add(1); }
            let mut end = input.cast_mut().cast::<c_char>();
            let mut width = if (*input).wrapping_sub(b'0') < 10 {
                strtoul(input.cast(), &mut end, 10) as usize
            } else { 0 };
            let conversion = end.cast::<u8>().cast_const();
            if matches!(*conversion, b'C' | b'F' | b'G' | b'Y') {
                if width == 0 && conversion != input { width = 1; }
            } else { width = 0; }
            input = conversion;
            if *input == b'E' || *input == b'O' { input = input.add(1); }
            let Some((mut text, mut n)) = directive(buffer.as_mut_ptr(), *input, tm, locale, pad) else { break; };
            if width != 0 {
                if *text == b'+' || *text == b'-' { text = text.add(1); n -= 1; }
                while *text == b'0' && (*text.add(1)).wrapping_sub(b'0') < 10 { text = text.add(1); n -= 1; }
                if width < n { width = n; }
                let mut digits = 0;
                while (*text.add(digits)).wrapping_sub(b'0') < 10 { digits += 1; }
                if tm.year < -1900 {
                    *output.add(length) = b'-'; length += 1; width -= 1;
                } else if plus && digits.wrapping_add(width-n) >= if *conversion == b'C' { 3 } else { 5 } {
                    *output.add(length) = b'+'; length += 1; width -= 1;
                }
                while width > n && length < capacity { *output.add(length) = b'0'; length += 1; width -= 1; }
            }
            n = n.min(capacity-length);
            ptr::copy_nonoverlapping(text, output.add(length), n);
            length += n;
            input = input.add(1);
        }
        if capacity != 0 { if length == capacity { length = capacity-1; } *output.add(length) = 0; }
        0
    }
}

/// Format C/POSIX/C.UTF-8 calendar directives using the calling locale.
/// # Safety
/// Format is a readable NUL-terminated string; value is readable initialized
/// struct tm storage with the fields required by each directive. Output names
/// capacity writable bytes (and may be null when capacity is zero), disjoint
/// from format and value. Zone names obey the timezone owner's borrowed lifetime.
#[no_mangle]
pub unsafe extern "C" fn strftime(output: *mut c_char, capacity: usize,
    input: *const c_char, value: *const Tm) -> usize {
    unsafe { format(output.cast(), capacity, input.cast(), &*value, None) }
}

/// Format calendar directives using one admitted locale object.
/// # Safety
/// Pointer/capacity obligations are those of strftime. Locale is a live
/// C/POSIX/C.UTF-8 locale object returned by this runtime, not LC_GLOBAL_LOCALE.
#[no_mangle]
pub unsafe extern "C" fn strftime_l(output: *mut c_char, capacity: usize,
    input: *const c_char, value: *const Tm, locale: *mut c_void) -> usize {
    unsafe { format(output.cast(), capacity, input.cast(), &*value, Some(locale)) }
}
