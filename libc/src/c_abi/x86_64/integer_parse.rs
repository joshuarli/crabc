//! Selected static Linux/x86-64 integer-parsing C ABI.
//!
//! This artifact owns exactly `strtol`, `strtoul`, `strtoll`, `strtoull`,
//! `strtoimax`, `strtoumax`, `atoi`, `atol`, and `atoll`. It is a complete
//! narrow byte-string integer-conversion block: the `strto*` entries preserve
//! base validation, C-locale ASCII whitespace and digits, optional signs,
//! `0`/`0x` prefixes, end-pointer movement, range saturation, and the
//! calling thread's `errno`. The three convenience entries retain musl's
//! separate defined-input decimal loops and do not manufacture an `errno`
//! write. It is allocation-free and has no syscall, callback, mutable-global,
//! locale-selection, stdio, or random-state boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/stdlib/strtol.c` maps the six public `strto*` entries to one
//!   limit-parameterized scanner.
//! - `src/internal/intscan.c`, `src/internal/intscan.h`, `src/internal/shgetc.h`,
//!   and `src/internal/shgetc.c` map to the bounded NUL-terminated byte scan,
//!   including musl's invalid-base/no-conversion `EINVAL`, partial `0x`
//!   end-pointer rule, and signed/unsigned saturation choices.
//! - `src/stdlib/atoi.c`, `src/stdlib/atol.c`, and `src/stdlib/atoll.c` map
//!   to the three defined-input decimal convenience loops.
//!
//! C callers must pass a valid NUL-terminated input sequence and, when
//! non-null, a writable `char **` end pointer. The `atoi`/`atol`/`atoll`
//! overflow domain remains C undefined, as in musl; wrapping operations merely
//! prevent that undefined C input from acquiring a Rust panic/runtime path.
//! Floating, wide, locale-specific, internal `__strto*_internal`, allocation,
//! stdio, random, and general text-runtime behavior remain outside this
//! artifact.

use core::ffi::{c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong};

use super::errno;

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;

#[derive(Clone, Copy)]
struct ScanResult {
    value: u64,
    end: *const u8,
}

#[inline]
fn ascii_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

#[inline]
fn digit_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'z' => byte - b'a' + 10,
        b'A'..=b'Z' => byte - b'A' + 10,
        _ => u8::MAX,
    }
}

/// Scan one NUL-terminated C byte string using musl's `__intscan` result
/// rules for the public `strto*` entry points.
///
/// # Safety
///
/// `input` must remain readable through its terminating NUL byte. This is the
/// C API's ordinary string precondition; no Rust reference is formed from the
/// caller-owned storage.
unsafe fn scan(input: *const c_char, requested_base: c_int, limit: u64) -> ScanResult {
    let start = input.cast::<u8>();
    if requested_base < 0 || requested_base == 1 || requested_base > 36 {
        // musl's `__intscan` rejects before consuming any input.
        unsafe { errno::set_errno(EINVAL) };
        return ScanResult {
            value: 0,
            end: start,
        };
    }

    let mut cursor = start;
    while ascii_space(unsafe { core::ptr::read(cursor) }) {
        cursor = cursor.wrapping_add(1);
    }

    let mut negative = false;
    match unsafe { core::ptr::read(cursor) } {
        b'-' => {
            negative = true;
            cursor = cursor.wrapping_add(1);
        }
        b'+' => cursor = cursor.wrapping_add(1),
        _ => {}
    }

    let mut base = requested_base as u8;
    let digits_start;
    if (base == 0 || base == 16) && unsafe { core::ptr::read(cursor) } == b'0' {
        let zero = cursor;
        cursor = cursor.wrapping_add(1);
        if unsafe { core::ptr::read(cursor) } | 0x20 == b'x' {
            cursor = cursor.wrapping_add(1);
            if digit_value(unsafe { core::ptr::read(cursor) }) >= 16 {
                // `intscan` consumes only the leading zero for a bare or
                // malformed 0x prefix, leaves errno alone, and returns zero.
                return ScanResult {
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
        if digit_value(unsafe { core::ptr::read(cursor) }) >= base {
            // Like `shlim(f, 0)` in musl's no-conversion path, no leading
            // whitespace or sign contributes to the public end pointer.
            unsafe { errno::set_errno(EINVAL) };
            return ScanResult {
                value: 0,
                end: start,
            };
        }
        digits_start = cursor;
    }

    let mut cursor = digits_start;
    let radix = u64::from(base);
    let mut value = 0u64;
    let mut overflowed_u64 = false;
    loop {
        let digit = digit_value(unsafe { core::ptr::read(cursor) });
        if digit >= base {
            break;
        }
        if value > (u64::MAX - u64::from(digit)) / radix {
            overflowed_u64 = true;
        } else if !overflowed_u64 {
            value = value * radix + u64::from(digit);
        }
        cursor = cursor.wrapping_add(1);
    }

    if overflowed_u64 {
        // `intscan` consumes the entire digit run, fixes the result at the
        // caller's limit, and clears a sign for unsigned-limit saturation.
        unsafe { errno::set_errno(ERANGE) };
        value = limit;
        if limit & 1 != 0 {
            negative = false;
        }
    }

    if value >= limit {
        if limit & 1 == 0 && !negative {
            // Signed positive values may not reach the two's-complement
            // magnitude used to represent the negative minimum.
            unsafe { errno::set_errno(ERANGE) };
            value = limit - 1;
        } else if value > limit {
            unsafe { errno::set_errno(ERANGE) };
            value = limit;
        }
    }

    ScanResult {
        value: if negative { value.wrapping_neg() } else { value },
        end: cursor,
    }
}

/// Apply the public `strto*` end-pointer write after scanning.
///
/// # Safety
///
/// `endptr`, when non-null, must be writable for one C pointer as required by
/// the corresponding C API.
#[inline]
unsafe fn scan_with_endptr(
    input: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    limit: u64,
) -> u64 {
    let result = unsafe { scan(input, base, limit) };
    if !endptr.is_null() {
        unsafe { core::ptr::write(endptr, result.end.cast_mut().cast::<c_char>()) };
    }
    result.value
}

#[no_mangle]
pub unsafe extern "C" fn strtol(
    input: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    let magnitude_limit = c_long::MIN as u64;
    unsafe { scan_with_endptr(input, endptr, base, magnitude_limit) as c_long }
}

#[no_mangle]
pub unsafe extern "C" fn strtoul(
    input: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    unsafe { scan_with_endptr(input, endptr, base, c_ulong::MAX as u64) as c_ulong }
}

#[no_mangle]
pub unsafe extern "C" fn strtoll(
    input: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_longlong {
    let magnitude_limit = c_longlong::MIN as u64;
    unsafe { scan_with_endptr(input, endptr, base, magnitude_limit) as c_longlong }
}

#[no_mangle]
pub unsafe extern "C" fn strtoull(
    input: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulonglong {
    unsafe { scan_with_endptr(input, endptr, base, c_ulonglong::MAX as u64) as c_ulonglong }
}

/// Linux/x86-64 LP64 has `intmax_t == long`; musl maps this spelling through
/// `strtoll` after preserving the exact shared scan/end-pointer/errno rules.
#[no_mangle]
pub unsafe extern "C" fn strtoimax(
    input: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    unsafe { strtoll(input, endptr, base) as c_long }
}

/// Linux/x86-64 LP64 has `uintmax_t == unsigned long`; musl maps this spelling
/// through `strtoull` after preserving the exact shared scan rules.
#[no_mangle]
pub unsafe extern "C" fn strtoumax(
    input: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    unsafe { strtoull(input, endptr, base) as c_ulong }
}

/// Scan one defined-input base-ten `atoi` sequence without the `strtol`
/// saturation/errno path, matching musl's separate negative-accumulator loop.
///
/// # Safety
///
/// `input` must point to a readable NUL-terminated C string. Inputs whose
/// decimal result cannot be represented in the target signed type remain C
/// undefined and are intentionally outside the artifact's contract.
unsafe fn decimal_i32(input: *const c_char) -> c_int {
    let mut cursor = input.cast::<u8>();
    while ascii_space(unsafe { core::ptr::read(cursor) }) {
        cursor = cursor.wrapping_add(1);
    }
    let mut negative = false;
    match unsafe { core::ptr::read(cursor) } {
        b'-' => {
            negative = true;
            cursor = cursor.wrapping_add(1);
        }
        b'+' => cursor = cursor.wrapping_add(1),
        _ => {}
    }
    let mut value = 0i32;
    loop {
        let byte = unsafe { core::ptr::read(cursor) };
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .wrapping_mul(10)
            .wrapping_sub(i32::from(byte.wrapping_sub(b'0')));
        cursor = cursor.wrapping_add(1);
    }
    if negative { value } else { value.wrapping_neg() }
}

/// See [`decimal_i32`] for the C string and defined-input requirements.
unsafe fn decimal_long(input: *const c_char) -> c_long {
    let mut cursor = input.cast::<u8>();
    while ascii_space(unsafe { core::ptr::read(cursor) }) {
        cursor = cursor.wrapping_add(1);
    }
    let mut negative = false;
    match unsafe { core::ptr::read(cursor) } {
        b'-' => {
            negative = true;
            cursor = cursor.wrapping_add(1);
        }
        b'+' => cursor = cursor.wrapping_add(1),
        _ => {}
    }
    let mut value = 0 as c_long;
    loop {
        let byte = unsafe { core::ptr::read(cursor) };
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .wrapping_mul(10)
            .wrapping_sub(c_long::from(byte.wrapping_sub(b'0')));
        cursor = cursor.wrapping_add(1);
    }
    if negative { value } else { value.wrapping_neg() }
}

/// See [`decimal_i32`] for the C string and defined-input requirements.
unsafe fn decimal_long_long(input: *const c_char) -> c_longlong {
    let mut cursor = input.cast::<u8>();
    while ascii_space(unsafe { core::ptr::read(cursor) }) {
        cursor = cursor.wrapping_add(1);
    }
    let mut negative = false;
    match unsafe { core::ptr::read(cursor) } {
        b'-' => {
            negative = true;
            cursor = cursor.wrapping_add(1);
        }
        b'+' => cursor = cursor.wrapping_add(1),
        _ => {}
    }
    let mut value = 0 as c_longlong;
    loop {
        let byte = unsafe { core::ptr::read(cursor) };
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .wrapping_mul(10)
            .wrapping_sub(c_longlong::from(byte.wrapping_sub(b'0')));
        cursor = cursor.wrapping_add(1);
    }
    if negative { value } else { value.wrapping_neg() }
}

#[no_mangle]
pub unsafe extern "C" fn atoi(input: *const c_char) -> c_int {
    unsafe { decimal_i32(input) }
}

#[no_mangle]
pub unsafe extern "C" fn atol(input: *const c_char) -> c_long {
    unsafe { decimal_long(input) }
}

#[no_mangle]
pub unsafe extern "C" fn atoll(input: *const c_char) -> c_longlong {
    unsafe { decimal_long_long(input) }
}
