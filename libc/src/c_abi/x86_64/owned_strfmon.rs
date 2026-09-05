//! Fixed-profile monetary formatting translated from musl 1.2.6
//! `src/locale/strfmon.c` (MIT), revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`.
//!
//! Musl's source parses the complete small POSIX monetary conversion grammar,
//! but does not consume `locale_t` or monetary locale data: its helper renders
//! every conversion through `snprintf("%*.*f", ...)`. The owned x86 leaf keeps
//! that exact boundary by directly calling the existing sibling
//! `stdio_format_scan::snprintf`, whose owned profile supplies binary64 `%f`.
//! This is C ABI compatibility machinery for the fixed C/POSIX/C.UTF-8
//! profile; it adds no locale database, locale-token validation, numeric
//! formatter, allocation, or Rust-facing API.

use core::ffi::{c_char, c_int, c_void, VaList};

use super::{errno, stdio_format_scan};

type Locale = *mut c_void;
const E2BIG: c_int = 7;

#[inline]
fn digit(value: u8) -> bool {
    value.is_ascii_digit()
}

/// Translate musl's private `vstrfmon_l` parser.
///
/// The source's locale parameter is intentionally not read: fixed C/POSIX/
/// C.UTF-8 data cannot change the `snprintf` call or any parsed field. Keeping
/// it in this private signature makes that source boundary explicit while
/// retaining an opaque `locale_t` ABI at `strfmon_l`.
unsafe fn format(
    output: *mut c_char,
    mut remaining: usize,
    _locale: Locale,
    mut input: *const c_char,
    mut args: VaList,
) -> isize {
    if remaining == 0 {
        return 0;
    }

    unsafe {
        let start = output.cast::<u8>();
        let mut destination = start;
        let mut format = input.cast::<u8>();

        while remaining != 0 && *format != 0 {
            if *format != b'%' {
                *destination = *format;
                destination = destination.add(1);
                format = format.add(1);
                remaining -= 1;
                continue;
            }
            format = format.add(1);
            if *format == b'%' {
                *destination = b'%';
                destination = destination.add(1);
                format = format.add(1);
                remaining -= 1;
                continue;
            }

            let mut fill = b' ';
            let mut no_grouping = false;
            let mut negative_parentheses = false;
            let mut no_symbol = false;
            let mut left = false;
            loop {
                match *format {
                    b'=' => {
                        format = format.add(1);
                        fill = *format;
                        format = format.add(1);
                    }
                    b'^' => {
                        no_grouping = true;
                        format = format.add(1);
                    }
                    b'(' => {
                        negative_parentheses = true;
                        format = format.add(1);
                    }
                    b'+' => format = format.add(1),
                    b'!' => {
                        no_symbol = true;
                        format = format.add(1);
                    }
                    b'-' => {
                        left = true;
                        format = format.add(1);
                    }
                    _ => break,
                }
            }

            let mut field_width = 0 as c_int;
            while digit(*format) {
                field_width = field_width
                    .wrapping_mul(10)
                    .wrapping_add((*format - b'0') as c_int);
                format = format.add(1);
            }

            let mut left_places = 0 as c_int;
            let mut right_places = 2 as c_int;
            if *format == b'#' {
                format = format.add(1);
                while digit(*format) {
                    left_places = left_places
                        .wrapping_mul(10)
                        .wrapping_add((*format - b'0') as c_int);
                    format = format.add(1);
                }
            }
            if *format == b'.' {
                format = format.add(1);
                right_places = 0;
                while digit(*format) {
                    right_places = right_places
                        .wrapping_mul(10)
                        .wrapping_add((*format - b'0') as c_int);
                    format = format.add(1);
                }
            }
            let international = *format == b'i';
            format = format.add(1);

            let mut width = left_places.wrapping_add(1).wrapping_add(right_places);
            if !left && field_width > width {
                width = field_width;
            }

            // These are deliberately parsed-but-inert, exactly as in musl's
            // fixed source. Retaining them prevents this local source map from
            // silently becoming a reduced grammar in a future change.
            let _ = (fill, no_grouping, negative_parentheses, no_symbol, international);
            let value = args.next_arg::<f64>();
            let rendered = stdio_format_scan::snprintf(
                destination.cast(),
                remaining,
                c"%*.*f".as_ptr(),
                width,
                right_places,
                value,
            ) as usize;
            // C assigns snprintf's `int` result to size_t before this check.
            // A negative result therefore also takes the source E2BIG path.
            if rendered >= remaining {
                errno::set_errno(E2BIG);
                return -1;
            }
            destination = destination.add(rendered);
            remaining -= rendered;
        }

        destination.offset_from(start)
    }
}

/// Format fixed-profile monetary text into a caller-owned byte buffer.
///
/// # Safety
/// `output` names `remaining` writable bytes and may be null only when
/// `remaining` is zero. `input` is readable through its NUL terminator and
/// does not overlap output. Every monetary conversion in `input` has the
/// promoted binary64 argument required by musl's parser. The source leaves
/// literal-only output unterminated, including when capacity remains; this
/// entry preserves that source behavior.
#[no_mangle]
pub unsafe extern "C" fn strfmon(
    output: *mut c_char,
    remaining: usize,
    input: *const c_char,
    args: ...,
) -> isize {
    // Musl passes CURRENT_LOCALE into an otherwise locale-independent helper.
    // Do not observe or validate a locale token here; that would add behavior
    // absent from its source and from this fixed monetary profile.
    unsafe { format(output, remaining, core::ptr::null_mut(), input, args) }
}

/// Format fixed-profile monetary text with an opaque locale token.
///
/// # Safety
/// Pointer, capacity, format, and variadic-argument obligations are those of
/// [`strfmon`]. `locale` is a live token supplied by the locale-object API for
/// the duration of this call. As in musl's `vstrfmon_l`, it is not
/// dereferenced, validated, retained, or used to select locale data.
#[no_mangle]
pub unsafe extern "C" fn strfmon_l(
    output: *mut c_char,
    remaining: usize,
    locale: Locale,
    input: *const c_char,
    args: ...,
) -> isize {
    unsafe { format(output, remaining, locale, input, args) }
}
