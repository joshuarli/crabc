//! Wide calendar formatting translated from musl 1.2.6 `src/time/wcsftime.c`
//! (MIT), revision `9fa28ece75d8a2191de7c5bb53bed224c5947417`.
//!
//! The source's parse, output-capacity, sign/width, conversion-error, and
//! truncation rules map directly below. `owned_strftime::format_directive`
//! remains the single source-faithful `__strftime_fmt_1` equivalent: this leaf
//! supplies musl's 100-byte/100-wide-character bridge through the owned C
//! `mbstowcs` and `wmemcpy` providers. The current locale contract remains
//! C/POSIX/C.UTF-8; this is not a general locale database or a separate
//! calendar-formatting algorithm.

use core::ffi::{c_char, c_int, c_void};

use super::{owned_strftime, timegm::Tm};

// Musl's `weak_alias(__wcsftime_l, wcsftime_l)` requires one ELF address and
// one ordinary weak override point. A Rust forwarding body would create a
// second address, so retain the source-specific alias directly in assembler.
core::arch::global_asm!(
    ".weak wcsftime_l",
    ".set wcsftime_l, __wcsftime_l",
);

unsafe extern "C" {
    fn wcstoul(input: *const c_int, end: *mut *mut c_int, base: c_int) -> u64;
    fn mbstowcs(output: *mut c_int, input: *const c_char, capacity: usize) -> usize;
    fn wmemcpy(output: *mut c_int, input: *const c_int, count: usize) -> *mut c_int;
}

/// Translate musl's `__wcsftime_l` loop while sharing its byte directive
/// expansion with `owned_strftime`.
unsafe fn format(output: *mut c_int, capacity: usize, mut input: *const c_int,
    value: *const Tm, locale: Option<*mut c_void>) -> usize {
    unsafe {
        let mut length = 0;
        let mut buffer = [0u8; 100];
        let mut wide_buffer = [0 as c_int; 100];
        while length < capacity {
            if *input == 0 {
                *output.add(length) = 0;
                return length;
            }
            if *input != b'%' as c_int {
                *output.add(length) = *input;
                length += 1;
                input = input.add(1);
                continue;
            }

            input = input.add(1);
            let mut pad = 0;
            if matches!(*input, value if value == b'-' as c_int || value == b'_' as c_int || value == b'0' as c_int) {
                pad = *input as u8;
                input = input.add(1);
            }
            let plus = *input == b'+' as c_int;
            if plus { input = input.add(1); }

            let mut end = input.cast_mut();
            let mut width = wcstoul(input, &mut end, 10);
            if matches!(*end, value if value == b'C' as c_int || value == b'F' as c_int || value == b'G' as c_int || value == b'Y' as c_int) {
                if width == 0 && end != input.cast_mut() { width = 1; }
            } else {
                width = 0;
            }
            input = end;
            if matches!(*input, value if value == b'E' as c_int || value == b'O' as c_int) {
                input = input.add(1);
            }

            // `wchar_t` is 32 bits on this owned x86 ABI. Do not narrow a
            // non-ASCII conversion into a different ASCII directive.
            let conversion = *input;
            let Some((byte_text, mut count)) = (conversion as u32 <= 0x7f)
                .then(|| owned_strftime::format_directive(
                    buffer.as_mut_ptr(), conversion as u8, &*value, locale, pad,
                ))
                .flatten()
            else { break; };
            count = mbstowcs(wide_buffer.as_mut_ptr(), byte_text.cast(), wide_buffer.len());
            if count == usize::MAX { return 0; }

            let mut text = wide_buffer.as_ptr();
            if width != 0 {
                while *text == b'+' as c_int || *text == b'-' as c_int
                    || (*text == b'0' as c_int && *text.add(1) != 0) {
                    text = text.add(1);
                    count = count.wrapping_sub(1);
                }
                width -= 1;
                if plus && (*value).year >= 10000 - 1900 {
                    *output.add(length) = b'+' as c_int;
                    length += 1;
                } else if (*value).year < -1900 {
                    *output.add(length) = b'-' as c_int;
                    length += 1;
                } else {
                    width += 1;
                }
                while width > count as u64 && length < capacity {
                    *output.add(length) = b'0' as c_int;
                    length += 1;
                    width -= 1;
                }
            }
            if count >= capacity - length { count = capacity - length; }
            wmemcpy(output.add(length), text, count);
            length += count;
            input = input.add(1);
        }
        if capacity != 0 {
            if length == capacity { length -= 1; }
            *output.add(length) = 0;
        }
        0
    }
}

/// Format C/POSIX/C.UTF-8 calendar text into wide characters using the calling
/// locale.
///
/// # Safety
/// `output` names `capacity` writable `wchar_t` values and may be null only
/// when `capacity` is zero. `input` is a readable NUL-terminated wide string;
/// `value` is readable initialized `struct tm` storage for every selected
/// directive. The output does not overlap either input. Zone-name borrows obey
/// the timezone owner's lifetime and callers serialize timezone mutation.
#[no_mangle]
pub unsafe extern "C" fn wcsftime(output: *mut c_int, capacity: usize,
    input: *const c_int, value: *const Tm) -> usize {
    unsafe { format(output, capacity, input, value, None) }
}

/// Format wide calendar text with one admitted locale object.
///
/// # Safety
/// Pointer/capacity obligations are those of `wcsftime`. `locale` is a live
/// C/POSIX/C.UTF-8 locale object returned by this runtime, not
/// `LC_GLOBAL_LOCALE`; it remains live throughout formatting.
#[no_mangle]
pub unsafe extern "C" fn __wcsftime_l(output: *mut c_int, capacity: usize,
    input: *const c_int, value: *const Tm, locale: *mut c_void) -> usize {
    unsafe { format(output, capacity, input, value, Some(locale)) }
}
