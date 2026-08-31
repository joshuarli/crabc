//! Fixed-locale completion for the staged x86 floating-conversion capability.
//!
//! This leaf completes `numeric.parse-float-locale` around the separately
//! translated narrow `strtof`/`strtod`/`strtold` scanner. Locale arguments are
//! intentionally ignored, matching musl and the repository's bounded
//! C/POSIX/C.UTF-8 locale profile. Wide floating input uses musl's 60-byte
//! refill adapter over that same scanner, wide integer input retains the
//! `intscan` end-pointer/range rules without an input-length cap, and the
//! legacy decimal functions use an allocation-free exact binary64-to-decimal
//! integer engine instead of importing `sprintf` and falsely selecting general
//! stdio formatting.
//!
//! ## Fixed source and license provenance
//!
//! The behavior and source mapping are pinned to musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, release SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`,
//! under musl's MIT license:
//!
//! - `src/locale/strtod_l.c` maps to the three public wrappers and three weak
//!   `__strto*_l` aliases in `float_parse_locale_aliases_x86_64.S`.
//! - `src/stdlib/wcstod.c`, `src/ctype/iswspace.c`, and the already translated
//!   `src/internal/{floatscan,shgetc}.c` map to
//!   `float_parse_locale_musl_x86_64.S`. The checked assembly was generated
//!   with the pinned native image's Alpine GCC 15.2.0, musl's
//!   `-std=c99 -ffreestanding -frounding-math` configuration, and private
//!   helper renaming; only labels/sections and the local whitespace helper were
//!   normalized for the Rust integrated assembler.
//! - `src/stdlib/wcstol.c` and `src/internal/intscan.c` map to the target-local
//!   wide scanner below. It preserves arbitrary-length NUL-terminated input;
//!   unlike the older AArch64 staging implementation in `libc/src/c_abi.rs`,
//!   it has no 256-byte narrowing buffer.
//! - `src/stdlib/{ecvt,fcvt,gcvt}.c` map to the exact decimal engine below.
//!   Musl obtains the same decimal rounding through its printf engine. Keeping
//!   the conversion local is an intentional ownership difference: no FILE,
//!   varargs, allocator, or general formatted-I/O ABI is selected.
//!
//! Linux/x86-64 uses four-byte `wchar_t`, LP64 integer widths, and x87
//! binary80-in-16-byte `long double`. Public callers retain the C APIs' normal
//! readable NUL-terminated input and writable output/end-pointer obligations.
//! The two legacy result functions retain musl's shared static-buffer lifetime
//! and are therefore not reentrant, exactly as their interface specifies.

use core::arch::asm;
use core::ffi::{
    c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong,
};

use super::errno;

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;
const BIG_BASE: u64 = 1_000_000_000;
const BIG_LIMBS: usize = 96;
const DECIMAL_DIGITS: usize = 800;
const GCVT_DIGITS: usize = 1_200;

#[derive(Clone, Copy)]
struct BigUnsigned {
    limbs: [u32; BIG_LIMBS],
    len: usize,
}

impl BigUnsigned {
    fn from_u64(mut value: u64) -> Self {
        let mut result = Self {
            limbs: [0; BIG_LIMBS],
            len: 0,
        };
        while value != 0 {
            result.limbs[result.len] = (value % BIG_BASE) as u32;
            result.len += 1;
            value /= BIG_BASE;
        }
        if result.len == 0 {
            result.len = 1;
        }
        result
    }

    fn multiply_small(&mut self, factor: u32) {
        let mut carry = 0u64;
        for index in 0..self.len {
            let product = u64::from(self.limbs[index]) * u64::from(factor) + carry;
            self.limbs[index] = (product % BIG_BASE) as u32;
            carry = product / BIG_BASE;
        }
        if carry != 0 {
            debug_assert!(self.len < BIG_LIMBS);
            self.limbs[self.len] = carry as u32;
            self.len += 1;
        }
    }
}

struct ExactDecimal {
    digits: [u8; DECIMAL_DIGITS],
    len: usize,
    scale: usize,
}

fn exact_decimal(bits: u64) -> ExactDecimal {
    let fraction = bits & ((UINT52_ONE << 52) - 1);
    let encoded_exponent = ((bits >> 52) & 0x7ff) as i32;
    let (mantissa, exponent_two) = if encoded_exponent == 0 {
        (fraction, -1_074)
    } else {
        ((UINT52_ONE << 52) | fraction, encoded_exponent - 1_023 - 52)
    };
    if mantissa == 0 {
        let mut digits = [0; DECIMAL_DIGITS];
        digits[0] = 0;
        return ExactDecimal {
            digits,
            len: 1,
            scale: 0,
        };
    }

    let mut integer = BigUnsigned::from_u64(mantissa);
    let scale;
    if exponent_two >= 0 {
        for _ in 0..exponent_two as usize {
            integer.multiply_small(2);
        }
        scale = 0;
    } else {
        scale = (-exponent_two) as usize;
        for _ in 0..scale {
            integer.multiply_small(5);
        }
    }

    let mut digits = [0u8; DECIMAL_DIGITS];
    let mut output = 0usize;
    let most = integer.limbs[integer.len - 1];
    let mut divisor = 100_000_000u32;
    while divisor > 1 && most < divisor {
        divisor /= 10;
    }
    loop {
        digits[output] = ((most / divisor) % 10) as u8;
        output += 1;
        if divisor == 1 {
            break;
        }
        divisor /= 10;
    }
    let mut limb_index = integer.len - 1;
    while limb_index != 0 {
        limb_index -= 1;
        let limb = integer.limbs[limb_index];
        let mut divisor = 100_000_000u32;
        while divisor != 0 {
            digits[output] = ((limb / divisor) % 10) as u8;
            output += 1;
            divisor /= 10;
        }
    }
    ExactDecimal {
        digits,
        len: output,
        scale,
    }
}

const UINT52_ONE: u64 = 1;

#[inline]
fn decimal_point(exact: &ExactDecimal) -> i32 {
    exact.len as i32 - exact.scale as i32
}

#[inline]
fn x87_rounding_direction() -> u16 {
    let mut control = 0u16;
    unsafe {
        asm!("fnstcw [{word}]", word = in(reg) &mut control, options(nostack, preserves_flags));
    }
    (control >> 10) & 3
}

fn should_increment(
    exact: &ExactDecimal,
    first_discarded: usize,
    retained_last: u8,
    negative: bool,
) -> bool {
    if first_discarded >= exact.len {
        return false;
    }
    let mut any_discarded = false;
    for &digit in &exact.digits[first_discarded..exact.len] {
        any_discarded |= digit != 0;
    }
    if !any_discarded {
        return false;
    }
    match x87_rounding_direction() {
        1 => negative,
        2 => !negative,
        3 => false,
        _ => {
            let next = exact.digits[first_discarded];
            if next > 5 {
                true
            } else if next < 5 {
                false
            } else {
                exact.digits[first_discarded + 1..exact.len]
                    .iter()
                    .any(|&digit| digit != 0)
                    || retained_last & 1 != 0
            }
        }
    }
}

fn round_significant(
    exact: &ExactDecimal,
    count: usize,
    negative: bool,
    output: &mut [u8],
) -> i32 {
    debug_assert!(count != 0 && count <= output.len());
    let mut point = decimal_point(exact);
    let copied = exact.len.min(count);
    output[..copied].copy_from_slice(&exact.digits[..copied]);
    output[copied..count].fill(0);
    if exact.len <= count
        || !should_increment(exact, count, output[count - 1], negative)
    {
        return point;
    }

    let mut index = count;
    while index != 0 {
        index -= 1;
        if output[index] != 9 {
            output[index] += 1;
            return point;
        }
        output[index] = 0;
    }
    output[0] = 1;
    point += 1;
    point
}

fn rounded_scaled_integer_len(
    exact: &ExactDecimal,
    fractional_digits: usize,
    negative: bool,
) -> usize {
    if exact.len == 1 && exact.digits[0] == 0 {
        return 0;
    }
    if exact.scale <= fractional_digits {
        return exact.len + fractional_digits - exact.scale;
    }

    let discarded = exact.scale - fractional_digits;
    if discarded > exact.len {
        return 0;
    }
    if discarded == exact.len {
        return if should_increment(exact, 0, 0, negative) { 1 } else { 0 };
    }
    let kept = exact.len - discarded;
    if !should_increment(exact, kept, exact.digits[kept - 1], negative) {
        return kept;
    }
    if exact.digits[..kept].iter().all(|&digit| digit == 9) {
        kept + 1
    } else {
        kept
    }
}

static mut LEGACY_RESULT: [c_char; 17] = [0; 17];
static LEGACY_ZERO_RESULT: [u8; 16] = *b"000000000000000\0";

#[inline]
unsafe fn legacy_result_ptr() -> *mut c_char {
    core::ptr::addr_of_mut!(LEGACY_RESULT).cast::<c_char>()
}

unsafe fn legacy_special(bits: u64, decimal: *mut c_int, sign: *mut c_int) -> *mut c_char {
    let result = unsafe { legacy_result_ptr() };
    let word: &[u8] = if bits & 0x000f_ffff_ffff_ffff != 0 {
        b"nan\0"
    } else {
        b"inf\0"
    };
    for (index, &byte) in word.iter().enumerate() {
        unsafe { core::ptr::write(result.add(index), byte as c_char) };
    }
    unsafe {
        core::ptr::write(decimal, 0);
        core::ptr::write(sign, (bits >> 63) as c_int);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn ecvt(
    value: f64,
    requested_digits: c_int,
    decimal: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    let bits = value.to_bits();
    if bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 {
        return unsafe { legacy_special(bits, decimal, sign) };
    }
    let mut count = requested_digits;
    if (count as u32).wrapping_sub(1) > 15 {
        count = 15;
    }
    let count = count as usize;
    let negative = bits >> 63 != 0;
    let exact = exact_decimal(bits & 0x7fff_ffff_ffff_ffff);
    let result = unsafe { legacy_result_ptr() };
    let output = unsafe { core::slice::from_raw_parts_mut(result.cast::<u8>(), 17) };
    let point = round_significant(&exact, count, negative, output);
    for digit in &mut output[..count] {
        *digit += b'0';
    }
    output[count] = 0;
    unsafe {
        core::ptr::write(decimal, point);
        core::ptr::write(sign, negative as c_int);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn fcvt(
    value: f64,
    requested_digits: c_int,
    decimal: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    let bits = value.to_bits();
    if bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 {
        return unsafe { legacy_special(bits, decimal, sign) };
    }
    let mut fractional = requested_digits;
    if fractional as u32 > 1_400 {
        fractional = 1_400;
    }
    let negative = bits >> 63 != 0;
    let exact = exact_decimal(bits & 0x7fff_ffff_ffff_ffff);
    let scaled_len = rounded_scaled_integer_len(&exact, fractional as usize, negative);
    if scaled_len == 0 {
        let mut zeroes = fractional;
        if zeroes > 14 {
            zeroes = 14;
        }
        unsafe {
            core::ptr::write(decimal, 1);
            core::ptr::write(sign, negative as c_int);
        }
        return LEGACY_ZERO_RESULT
            .as_ptr()
            .add((14 - zeroes) as usize)
            .cast_mut()
            .cast::<c_char>();
    }
    let point = scaled_len as i32 - fractional;
    unsafe { ecvt(value, fractional + point, decimal, sign) }
}

#[inline]
unsafe fn write_output(buffer: *mut c_char, index: &mut usize, byte: u8) {
    unsafe { core::ptr::write(buffer.add(*index), byte as c_char) };
    *index += 1;
}

unsafe fn write_exponent(buffer: *mut c_char, output: &mut usize, exponent: i32) {
    unsafe { write_output(buffer, output, if exponent < 0 { b'-' } else { b'+' }) };
    let mut magnitude = exponent.unsigned_abs();
    let mut digits = [0u8; 10];
    let mut len = 0usize;
    loop {
        digits[len] = (magnitude % 10) as u8;
        len += 1;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    if len < 2 {
        unsafe { write_output(buffer, output, b'0') };
    }
    while len != 0 {
        len -= 1;
        unsafe { write_output(buffer, output, b'0' + digits[len]) };
    }
}

#[no_mangle]
pub unsafe extern "C" fn gcvt(
    value: f64,
    requested_digits: c_int,
    buffer: *mut c_char,
) -> *mut c_char {
    let bits = value.to_bits();
    let negative = bits >> 63 != 0;
    let magnitude = bits & 0x7fff_ffff_ffff_ffff;
    let mut output = 0usize;
    if negative {
        unsafe { write_output(buffer, &mut output, b'-') };
    }
    if magnitude & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 {
        let word: &[u8] = if magnitude & 0x000f_ffff_ffff_ffff != 0 {
            b"nan"
        } else {
            b"inf"
        };
        for &byte in word {
            unsafe { write_output(buffer, &mut output, byte) };
        }
        unsafe { core::ptr::write(buffer.add(output), 0) };
        return buffer;
    }

    let precision = if requested_digits < 0 {
        6usize
    } else if requested_digits == 0 {
        1usize
    } else {
        (requested_digits as usize).min(GCVT_DIGITS)
    };
    let exact = exact_decimal(magnitude);
    let mut digits = [0u8; GCVT_DIGITS];
    let point = round_significant(&exact, precision, negative, &mut digits);
    let exponent = point - 1;
    let scientific = exponent < -4 || exponent >= precision as i32;

    if scientific {
        let mut end = precision;
        while end > 1 && digits[end - 1] == 0 {
            end -= 1;
        }
        unsafe { write_output(buffer, &mut output, b'0' + digits[0]) };
        if end > 1 {
            unsafe { write_output(buffer, &mut output, b'.') };
            for &digit in &digits[1..end] {
                unsafe { write_output(buffer, &mut output, b'0' + digit) };
            }
        }
        unsafe {
            write_output(buffer, &mut output, b'e');
            write_exponent(buffer, &mut output, exponent);
        }
    } else if point <= 0 {
        unsafe { write_output(buffer, &mut output, b'0') };
        let mut end = precision;
        while end != 0 && digits[end - 1] == 0 {
            end -= 1;
        }
        if end != 0 {
            unsafe { write_output(buffer, &mut output, b'.') };
            for _ in 0..(-point) as usize {
                unsafe { write_output(buffer, &mut output, b'0') };
            }
            for &digit in &digits[..end] {
                unsafe { write_output(buffer, &mut output, b'0' + digit) };
            }
        }
    } else {
        let integer_digits = point as usize;
        let copied_integer = integer_digits.min(precision);
        for &digit in &digits[..copied_integer] {
            unsafe { write_output(buffer, &mut output, b'0' + digit) };
        }
        for _ in copied_integer..integer_digits {
            unsafe { write_output(buffer, &mut output, b'0') };
        }
        if precision > integer_digits {
            let mut end = precision;
            while end > integer_digits && digits[end - 1] == 0 {
                end -= 1;
            }
            if end > integer_digits {
                unsafe { write_output(buffer, &mut output, b'.') };
                for &digit in &digits[integer_digits..end] {
                    unsafe { write_output(buffer, &mut output, b'0' + digit) };
                }
            }
        }
    }
    unsafe { core::ptr::write(buffer.add(output), 0) };
    buffer
}

#[inline]
fn wide_space(character: u32) -> bool {
    matches!(
        character,
        0x20 | 0x09 | 0x0a | 0x0d | 0x0b | 0x0c | 0x0085 | 0x2000 | 0x2001
            | 0x2002 | 0x2003 | 0x2004 | 0x2005 | 0x2006 | 0x2008 | 0x2009
            | 0x200a | 0x2028 | 0x2029 | 0x205f | 0x3000
    )
}

#[inline]
fn wide_digit(character: u32) -> u8 {
    match character {
        value @ 0x30..=0x39 => (value - 0x30) as u8,
        value @ 0x61..=0x7a => (value - 0x61 + 10) as u8,
        value @ 0x41..=0x5a => (value - 0x41 + 10) as u8,
        _ => u8::MAX,
    }
}

struct WideScanResult {
    value: u64,
    end: *const u32,
}

unsafe fn scan_wide(input: *const u32, requested_base: c_int, limit: u64) -> WideScanResult {
    if requested_base < 0 || requested_base == 1 || requested_base > 36 {
        unsafe { errno::set_errno(EINVAL) };
        return WideScanResult { value: 0, end: input };
    }
    let mut cursor = input;
    while wide_space(unsafe { core::ptr::read(cursor) }) {
        cursor = cursor.wrapping_add(1);
    }
    let mut negative = false;
    match unsafe { core::ptr::read(cursor) } {
        0x2d => {
            negative = true;
            cursor = cursor.wrapping_add(1);
        }
        0x2b => cursor = cursor.wrapping_add(1),
        _ => {}
    }

    let mut base = requested_base as u8;
    let digits_start;
    if (base == 0 || base == 16) && unsafe { core::ptr::read(cursor) } == 0x30 {
        let zero = cursor;
        cursor = cursor.wrapping_add(1);
        if unsafe { core::ptr::read(cursor) } | 0x20 == 0x78 {
            cursor = cursor.wrapping_add(1);
            if wide_digit(unsafe { core::ptr::read(cursor) }) >= 16 {
                return WideScanResult {
                    value: 0,
                    end: zero.wrapping_add(1),
                };
            }
            base = 16;
            digits_start = cursor;
        } else {
            if base == 0 {
                base = 8;
            }
            digits_start = zero;
        }
    } else {
        if base == 0 {
            base = 10;
        }
        if wide_digit(unsafe { core::ptr::read(cursor) }) >= base {
            unsafe { errno::set_errno(EINVAL) };
            return WideScanResult { value: 0, end: input };
        }
        digits_start = cursor;
    }

    cursor = digits_start;
    let radix = u64::from(base);
    let mut value = 0u64;
    let mut overflowed = false;
    loop {
        let digit = wide_digit(unsafe { core::ptr::read(cursor) });
        if digit >= base {
            break;
        }
        if value > (u64::MAX - u64::from(digit)) / radix {
            overflowed = true;
        } else if !overflowed {
            value = value * radix + u64::from(digit);
        }
        cursor = cursor.wrapping_add(1);
    }
    if overflowed {
        unsafe { errno::set_errno(ERANGE) };
        value = limit;
        if limit & 1 != 0 {
            negative = false;
        }
    }
    if value >= limit {
        if limit & 1 == 0 && !negative {
            unsafe { errno::set_errno(ERANGE) };
            value = limit - 1;
        } else if value > limit {
            unsafe { errno::set_errno(ERANGE) };
            value = limit;
        }
    }
    WideScanResult {
        value: if negative { value.wrapping_neg() } else { value },
        end: cursor,
    }
}

unsafe fn scan_wide_with_end(
    input: *const u32,
    end: *mut *mut u32,
    base: c_int,
    limit: u64,
) -> u64 {
    let result = unsafe { scan_wide(input, base, limit) };
    if !end.is_null() {
        unsafe { core::ptr::write(end, result.end.cast_mut()) };
    }
    result.value
}

#[no_mangle]
pub unsafe extern "C" fn wcstol(input: *const u32, end: *mut *mut u32, base: c_int) -> c_long {
    unsafe { scan_wide_with_end(input, end, base, c_long::MIN as u64) as c_long }
}

#[no_mangle]
pub unsafe extern "C" fn wcstoul(input: *const u32, end: *mut *mut u32, base: c_int) -> c_ulong {
    unsafe { scan_wide_with_end(input, end, base, c_ulong::MAX as u64) as c_ulong }
}

#[no_mangle]
pub unsafe extern "C" fn wcstoll(input: *const u32, end: *mut *mut u32, base: c_int) -> c_longlong {
    unsafe { scan_wide_with_end(input, end, base, c_longlong::MIN as u64) as c_longlong }
}

#[no_mangle]
pub unsafe extern "C" fn wcstoull(input: *const u32, end: *mut *mut u32, base: c_int) -> c_ulonglong {
    unsafe { scan_wide_with_end(input, end, base, c_ulonglong::MAX as u64) as c_ulonglong }
}

#[no_mangle]
pub unsafe extern "C" fn wcstoimax(input: *const u32, end: *mut *mut u32, base: c_int) -> c_long {
    unsafe { wcstoll(input, end, base) as c_long }
}

#[no_mangle]
pub unsafe extern "C" fn wcstoumax(input: *const u32, end: *mut *mut u32, base: c_int) -> c_ulong {
    unsafe { wcstoull(input, end, base) as c_ulong }
}
