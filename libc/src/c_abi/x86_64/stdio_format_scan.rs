//! Bounded byte-string formatting and scanning for the static Linux/x86-64 C ABI.
//!
//! This target-local leaf owns exactly `snprintf`, `vsnprintf`, `sprintf`,
//! `vsprintf`, `sscanf`, and `vsscanf`.  It deliberately selects a useful
//! C-locale integer-and-byte-string grammar rather than pretending that a
//! formatter declaration is an implementation: output accepts literals,
//! `%%`, flags `-+ 0#`, numeric or `*` width/precision, integer length forms
//! `hh`, `h`, `l`, `ll`, `j`, `z`, and `t`, and `%d`/`%i`/`%u`/`%o`/`%x`/`%X`,
//! `%c`, `%s`, and count-store `%n`.  Input accepts literals and format
//! whitespace, assignment suppression and width, the same integer length
//! forms for `%d`/`%i`/`%u`/`%o`/`%x`/`%X`, plus `%c`, `%s`, and `%n`.
//!
//! The implementation is allocation-free and has no `FILE`, stream lock,
//! locale-object, floating conversion, wide-character, scanset, positional
//! argument, pointer-valued `%p`, or `printf`/`fprintf`/`scanf`/`fscanf`
//! boundary.  Valid C callers supply readable NUL-terminated format/input
//! strings and suitably sized writable destinations.  Integer scanner
//! overflow and unsupported conversion grammar remain outside this closed
//! artifact; unsupported
//! conversions fail closed with `EINVAL` rather than silently routing through
//! an ambient libc. `snprintf` additionally retains zero-capacity
//! null-destination behavior: it never dereferences a null destination when
//! the supplied capacity is zero.
//!
//! ## Fixed source and license provenance
//!
//! The behavior map is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the release archive whose
//! SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! Those sources carry musl's MIT license; `compat/upstreams.toml` records
//! the authoritative pin.
//!
//! | Pinned musl source | Owned bounded x86 translation |
//! | --- | --- |
//! | `src/stdio/vsnprintf.c`, `vsprintf.c`, `sprintf.c`, `snprintf.c` | byte-buffer count/truncation wrappers and C varargs entry boundary |
//! | `src/stdio/vfprintf.c` (`printf_core`) | selected integer/byte-string format parser, flag, width, precision, count-store, and conversion behavior |
//! | `src/stdio/sscanf.c`, `vsscanf.c`, `vfscanf.c`; `src/internal/intscan.c` | NUL-terminated byte scanner, assignment/count discipline, prefix admission, and selected integer/string conversions |
//!
//! The full musl formatter/scanner also owns floating and long-double
//! conversion, locale, wide input, scansets, positional arguments, stream
//! buffering/cancellation, and error propagation through its complete `FILE`
//! machinery.  None of those owners is imported here.  This leaf is evidence
//! for the named static byte-string contract only, never a general stdio or
//! x86 runtime claim.
//!
//! The active Linux/AArch64 implementation remains the broader compatibility
//! owner in `libc/src/c_abi.rs`, including stream, floating, wide, pointer, and
//! other formatting/scanning paths.  This target-local leaf neither reuses that
//! target root nor treats its selected byte-string subset as architecture
//! parity.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!(
    "the x86 stdio format/scan leaf requires little-endian Linux/x86-64"
);

use core::ffi::{
    c_char, c_int, c_long, c_longlong, c_uint, c_ulong, c_ulonglong, VaList,
};

use super::errno;

const EINVAL: c_int = 22;
const EOVERFLOW: c_int = 75;
const EOF: c_int = -1;

const FLAG_MINUS: u8 = 1 << 0;
const FLAG_PLUS: u8 = 1 << 1;
const FLAG_SPACE: u8 = 1 << 2;
const FLAG_ZERO: u8 = 1 << 3;
const FLAG_ALT: u8 = 1 << 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Length {
    None,
    Hh,
    H,
    L,
    Ll,
    J,
    Z,
    T,
}

#[inline]
fn ascii_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

#[inline]
fn digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[inline]
unsafe fn read_byte(pointer: *const u8) -> u8 {
    // SAFETY: every public entry's C string precondition requires a readable
    // byte through its terminating NUL.  Internal cursors advance only within
    // that sequence.
    unsafe { pointer.read() }
}

/// A counting `snprintf` sink.  It writes at most `cap - 1` data bytes and
/// always retains the would-have-written count needed by C99 truncation.
struct Output {
    destination: *mut u8,
    capacity: usize,
    count: usize,
    overflowed: bool,
}

impl Output {
    const fn new(destination: *mut u8, capacity: usize) -> Self {
        Self {
            destination,
            capacity,
            count: 0,
            overflowed: false,
        }
    }

    unsafe fn byte(&mut self, byte: u8) {
        if self.count.saturating_add(1) < self.capacity {
            // SAFETY: a nonzero C `snprintf` size requires a writable buffer;
            // the selected contract retains that standard caller obligation.
            unsafe { self.destination.add(self.count).write(byte) };
        }
        match self.count.checked_add(1) {
            Some(next) => self.count = next,
            None => self.overflowed = true,
        }
    }

    unsafe fn bytes(&mut self, source: *const u8, length: usize) {
        let writable = if !self.overflowed && self.capacity != 0 {
            let data_limit = self.capacity - 1;
            if self.count < data_limit {
                length.min(data_limit - self.count)
            } else {
                0
            }
        } else {
            0
        };
        let mut index = 0usize;
        while index < writable {
            // SAFETY: source points to exactly the caller/internal bytes that
            // this selected conversion has already bounded.
            unsafe {
                self.destination
                    .add(self.count + index)
                    .write(source.add(index).read())
            };
            index += 1;
        }
        match self.count.checked_add(length) {
            Some(next) => self.count = next,
            None => self.overflowed = true,
        }
    }

    unsafe fn repeated(&mut self, byte: u8, length: usize) {
        let writable = if !self.overflowed && self.capacity != 0 {
            let data_limit = self.capacity - 1;
            if self.count < data_limit {
                length.min(data_limit - self.count)
            } else {
                0
            }
        } else {
            0
        };
        let mut index = 0usize;
        while index < writable {
            unsafe { self.destination.add(self.count + index).write(byte) };
            index += 1;
        }
        match self.count.checked_add(length) {
            Some(next) => self.count = next,
            None => self.overflowed = true,
        }
    }

    unsafe fn finish(self) -> c_int {
        if self.capacity != 0 {
            let index = if self.count < self.capacity {
                self.count
            } else {
                self.capacity - 1
            };
            // SAFETY: index is in 0..capacity.  The C caller owns this
            // writable destination whenever capacity is nonzero.
            unsafe { self.destination.add(index).write(0) };
        }
        if self.overflowed || self.count > c_int::MAX as usize {
            // SAFETY: selected formatting's only explicit error condition is
            // a result that cannot fit C's `int` return type.
            unsafe { errno::set_errno(EOVERFLOW) };
            -1
        } else {
            self.count as c_int
        }
    }
}

#[inline]
unsafe fn parse_decimal(cursor: &mut *const u8) -> usize {
    let mut value = 0usize;
    while unsafe { read_byte(*cursor) }.is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add((unsafe { read_byte(*cursor) } - b'0') as usize);
        *cursor = (*cursor).wrapping_add(1);
    }
    value
}

#[inline]
unsafe fn parse_length(cursor: &mut *const u8) -> Length {
    let first = unsafe { read_byte(*cursor) };
    match first {
        b'h' => {
            *cursor = (*cursor).wrapping_add(1);
            if unsafe { read_byte(*cursor) } == b'h' {
                *cursor = (*cursor).wrapping_add(1);
                Length::Hh
            } else {
                Length::H
            }
        }
        b'l' => {
            *cursor = (*cursor).wrapping_add(1);
            if unsafe { read_byte(*cursor) } == b'l' {
                *cursor = (*cursor).wrapping_add(1);
                Length::Ll
            } else {
                Length::L
            }
        }
        b'j' => {
            *cursor = (*cursor).wrapping_add(1);
            Length::J
        }
        b'z' => {
            *cursor = (*cursor).wrapping_add(1);
            Length::Z
        }
        b't' => {
            *cursor = (*cursor).wrapping_add(1);
            Length::T
        }
        _ => Length::None,
    }
}

#[inline]
unsafe fn c_string_length(string: *const c_char, limit: Option<usize>) -> usize {
    let mut length = 0usize;
    while limit.is_none_or(|bound| length < bound)
        && unsafe { read_byte(string.cast::<u8>().add(length)) } != 0
    {
        length += 1;
    }
    length
}

unsafe fn write_number(
    output: &mut Output,
    mut value: u64,
    base: u8,
    uppercase: bool,
    sign: Option<u8>,
    alternate: bool,
    width: usize,
    precision: Option<usize>,
    flags: u8,
) {
    let nonzero = value != 0;
    let mut reversed = [0u8; 64];
    let mut digit_count = 0usize;
    if value != 0 {
        while value != 0 {
            let digit = (value % base as u64) as u8;
            reversed[digit_count] = match digit {
                0..=9 => b'0' + digit,
                _ if uppercase => b'A' + digit - 10,
                _ => b'a' + digit - 10,
            };
            digit_count += 1;
            value /= base as u64;
        }
    } else if precision != Some(0) {
        reversed[0] = b'0';
        digit_count = 1;
    }

    let mut prefix = [0u8; 3];
    let mut prefix_count = 0usize;
    if let Some(sign) = sign {
        prefix[prefix_count] = sign;
        prefix_count += 1;
    }
    if alternate && base == 16 && nonzero {
        prefix[prefix_count] = b'0';
        prefix[prefix_count + 1] = if uppercase { b'X' } else { b'x' };
        prefix_count += 2;
    }

    // C's alternate octal form makes the leading zero a precision property,
    // including the precision-zero value case.
    let zero_precision = precision.unwrap_or(0).saturating_sub(digit_count);
    let octal_zero = alternate
        && base == 8
        && (digit_count == 0
            || (nonzero && zero_precision == 0 && reversed[digit_count - 1] != b'0'));
    let digits_with_precision = digit_count
        .saturating_add(zero_precision)
        .saturating_add(octal_zero as usize);
    let content = prefix_count.saturating_add(digits_with_precision);
    let padding = width.saturating_sub(content);
    let zero_width = flags & FLAG_ZERO != 0 && flags & FLAG_MINUS == 0 && precision.is_none();

    if flags & FLAG_MINUS == 0 && !zero_width {
        unsafe { output.repeated(b' ', padding) };
    }
    unsafe { output.bytes(prefix.as_ptr(), prefix_count) };
    if flags & FLAG_MINUS == 0 && zero_width {
        unsafe { output.repeated(b'0', padding) };
    }
    if octal_zero {
        unsafe { output.byte(b'0') };
    }
    unsafe { output.repeated(b'0', zero_precision) };
    while digit_count != 0 {
        digit_count -= 1;
        unsafe { output.byte(reversed[digit_count]) };
    }
    if flags & FLAG_MINUS != 0 {
        unsafe { output.repeated(b' ', padding) };
    }
}

unsafe fn write_string(
    output: &mut Output,
    string: *const c_char,
    width: usize,
    precision: Option<usize>,
    flags: u8,
) {
    let fallback = b"(null)\0";
    let source = if string.is_null() {
        fallback.as_ptr()
    } else {
        string.cast::<u8>()
    };
    let length = unsafe { c_string_length(source.cast::<c_char>(), precision) };
    let padding = width.saturating_sub(length);
    if flags & FLAG_MINUS == 0 {
        unsafe { output.repeated(b' ', padding) };
    }
    unsafe { output.bytes(source, length) };
    if flags & FLAG_MINUS != 0 {
        unsafe { output.repeated(b' ', padding) };
    }
}

unsafe fn write_character(output: &mut Output, character: u8, width: usize, flags: u8) {
    let padding = width.saturating_sub(1);
    if flags & FLAG_MINUS == 0 {
        unsafe { output.repeated(b' ', padding) };
    }
    unsafe { output.byte(character) };
    if flags & FLAG_MINUS != 0 {
        unsafe { output.repeated(b' ', padding) };
    }
}

unsafe fn format_to_buffer(
    destination: *mut c_char,
    capacity: usize,
    format: *const c_char,
    args: &mut VaList<'_>,
) -> c_int {
    let mut output = Output::new(destination.cast::<u8>(), capacity);
    let mut cursor = format.cast::<u8>();
    loop {
        if output.overflowed || output.count > c_int::MAX as usize {
            return unsafe { output.finish() };
        }
        let current = unsafe { read_byte(cursor) };
        if current == 0 {
            break;
        }
        if current != b'%' {
            unsafe { output.byte(current) };
            cursor = cursor.wrapping_add(1);
            continue;
        }
        cursor = cursor.wrapping_add(1);
        if unsafe { read_byte(cursor) } == b'%' {
            unsafe { output.byte(b'%') };
            cursor = cursor.wrapping_add(1);
            continue;
        }

        let mut flags = 0u8;
        loop {
            match unsafe { read_byte(cursor) } {
                b'-' => flags |= FLAG_MINUS,
                b'+' => flags |= FLAG_PLUS,
                b' ' => flags |= FLAG_SPACE,
                b'0' => flags |= FLAG_ZERO,
                b'#' => flags |= FLAG_ALT,
                _ => break,
            }
            cursor = cursor.wrapping_add(1);
        }

        let width = if unsafe { read_byte(cursor) } == b'*' {
            cursor = cursor.wrapping_add(1);
            let raw = unsafe { args.next_arg::<c_int>() };
            if raw < 0 {
                flags |= FLAG_MINUS;
                raw.unsigned_abs() as usize
            } else {
                raw as usize
            }
        } else {
            unsafe { parse_decimal(&mut cursor) }
        };

        let precision = if unsafe { read_byte(cursor) } == b'.' {
            cursor = cursor.wrapping_add(1);
            if unsafe { read_byte(cursor) } == b'*' {
                cursor = cursor.wrapping_add(1);
                let raw = unsafe { args.next_arg::<c_int>() };
                (raw >= 0).then_some(raw as usize)
            } else {
                Some(unsafe { parse_decimal(&mut cursor) })
            }
        } else {
            None
        };
        if width > c_int::MAX as usize
            || precision.is_some_and(|value| value > c_int::MAX as usize)
        {
            output.overflowed = true;
            return unsafe { output.finish() };
        }
        let length = unsafe { parse_length(&mut cursor) };
        let specifier = unsafe { read_byte(cursor) };
        if specifier == 0 {
            // An incomplete conversion has no portable C behavior.  Make the
            // selected boundary deterministic rather than emitting it as text.
            unsafe { errno::set_errno(EINVAL) };
            return -1;
        }
        cursor = cursor.wrapping_add(1);

        match specifier {
            b'd' | b'i' => {
                let signed = match length {
                    Length::None => unsafe { args.next_arg::<c_int>() as i64 },
                    Length::Hh => unsafe { args.next_arg::<c_int>() as i8 as i64 },
                    Length::H => unsafe { args.next_arg::<c_int>() as i16 as i64 },
                    Length::L | Length::Z | Length::T => unsafe {
                        args.next_arg::<c_long>() as i64
                    },
                    Length::Ll | Length::J => unsafe {
                        args.next_arg::<c_longlong>() as i64
                    },
                };
                let negative = signed < 0;
                let magnitude = if negative {
                    signed.unsigned_abs()
                } else {
                    signed as u64
                };
                let sign = if negative {
                    Some(b'-')
                } else if flags & FLAG_PLUS != 0 {
                    Some(b'+')
                } else if flags & FLAG_SPACE != 0 {
                    Some(b' ')
                } else {
                    None
                };
                unsafe {
                    write_number(
                        &mut output,
                        magnitude,
                        10,
                        false,
                        sign,
                        false,
                        width,
                        precision,
                        flags,
                    )
                };
            }
            b'u' | b'o' | b'x' | b'X' => {
                let value = match length {
                    Length::None => unsafe { args.next_arg::<c_uint>() as u64 },
                    Length::Hh => unsafe { args.next_arg::<c_uint>() as u8 as u64 },
                    Length::H => unsafe { args.next_arg::<c_uint>() as u16 as u64 },
                    Length::L | Length::T => unsafe { args.next_arg::<c_ulong>() as u64 },
                    Length::Ll | Length::J => unsafe { args.next_arg::<c_ulonglong>() as u64 },
                    Length::Z => unsafe { args.next_arg::<usize>() as u64 },
                };
                let base = match specifier {
                    b'u' => 10,
                    b'o' => 8,
                    _ => 16,
                };
                unsafe {
                    write_number(
                        &mut output,
                        value,
                        base,
                        specifier == b'X',
                        None,
                        flags & FLAG_ALT != 0,
                        width,
                        precision,
                        flags,
                    )
                };
            }
            b'c' if length == Length::None => {
                let character = unsafe { args.next_arg::<c_int>() as u8 };
                unsafe { write_character(&mut output, character, width, flags) };
            }
            b's' if length == Length::None => {
                let string = unsafe { args.next_arg::<*const c_char>() };
                unsafe { write_string(&mut output, string, width, precision, flags) };
            }
            b'n' => unsafe { assign_count(args, length, output.count) },
            _ => {
                unsafe { errno::set_errno(EINVAL) };
                return -1;
            }
        }
    }
    unsafe { output.finish() }
}

/// Format the selected grammar into a bounded caller-owned byte buffer.
///
/// # Safety
///
/// `format` must be a readable NUL-terminated string and `args` must contain
/// the promoted types required by every selected directive.  When `capacity`
/// is nonzero, `destination` must be writable for that many bytes; it may be
/// null only when `capacity` is zero.  Every `%s` source must be readable
/// through its selected precision or NUL, and every `%n` destination must be
/// writable with the type selected by its length modifier.
#[no_mangle]
pub unsafe extern "C" fn vsnprintf(
    destination: *mut c_char,
    capacity: usize,
    format: *const c_char,
    mut args: VaList,
) -> c_int {
    unsafe { format_to_buffer(destination, capacity, format, &mut args) }
}

/// C-variadic entry for [`vsnprintf`]'s selected byte-buffer grammar.
///
/// # Safety
///
/// The destination and format obligations are the same as [`vsnprintf`].
/// Every variadic argument must have the promoted type required by its
/// directive, and every selected pointer argument must satisfy that
/// directive's readable or writable extent.
#[no_mangle]
pub unsafe extern "C" fn snprintf(
    destination: *mut c_char,
    capacity: usize,
    format: *const c_char,
    mut args: ...,
) -> c_int {
    unsafe { format_to_buffer(destination, capacity, format, &mut args) }
}

/// Format the selected grammar without an explicit destination bound.
///
/// # Safety
///
/// `destination` must be non-null and large enough for every produced byte and
/// the trailing NUL.  `format`, `args`, `%s`, and `%n` carry the same
/// obligations as [`vsnprintf`].
#[no_mangle]
pub unsafe extern "C" fn vsprintf(
    destination: *mut c_char,
    format: *const c_char,
    mut args: VaList,
) -> c_int {
    unsafe { format_to_buffer(destination, usize::MAX, format, &mut args) }
}

/// C-variadic entry for [`vsprintf`]'s selected unbounded-buffer grammar.
///
/// # Safety
///
/// `destination` must be non-null and large enough for the full result and
/// trailing NUL.  The format and variadic arguments must satisfy the same
/// type and extent obligations as [`snprintf`].
#[no_mangle]
pub unsafe extern "C" fn sprintf(
    destination: *mut c_char,
    format: *const c_char,
    mut args: ...,
) -> c_int {
    unsafe { format_to_buffer(destination, usize::MAX, format, &mut args) }
}

#[derive(Clone, Copy)]
enum ScanBase {
    Decimal,
    Auto,
    UnsignedDecimal,
    Octal,
    Hex,
}

#[derive(Clone, Copy)]
struct ScannedInteger {
    value: u64,
    negative: bool,
    next: *const u8,
}

unsafe fn skip_input_space(mut cursor: *const u8) -> *const u8 {
    while ascii_space(unsafe { read_byte(cursor) }) {
        cursor = cursor.wrapping_add(1);
    }
    cursor
}

/// Parse one selected scanf integer conversion.  The caller has already
/// skipped ordinary conversion whitespace.  Width counts every sign/prefix
/// byte, as musl's scanner does.
unsafe fn scan_integer(
    start: *const u8,
    width: usize,
    requested: ScanBase,
) -> Option<ScannedInteger> {
    let mut cursor = start;
    let mut used = 0usize;
    if used == width || unsafe { read_byte(cursor) } == 0 {
        return None;
    }
    let mut negative = false;
    let first = unsafe { read_byte(cursor) };
    if first == b'+' || first == b'-' {
        negative = first == b'-';
        cursor = cursor.wrapping_add(1);
        used += 1;
        if used == width || unsafe { read_byte(cursor) } == 0 {
            return None;
        }
    }

    let mut base = match requested {
        ScanBase::Decimal | ScanBase::UnsignedDecimal => 10u8,
        ScanBase::Octal => 8,
        ScanBase::Hex => 16,
        ScanBase::Auto => 0,
    };
    let mut value = 0u64;
    let mut digits = 0usize;

    if unsafe { read_byte(cursor) } == b'0' && (base == 0 || base == 16) {
        cursor = cursor.wrapping_add(1);
        used += 1;
        digits = 1;
        base = if base == 0 { 8 } else { 16 };
        if used < width {
            let look = unsafe { read_byte(cursor) };
            if look == b'x' || look == b'X' {
                cursor = cursor.wrapping_add(1);
                used += 1;
                digits = 0;
                if used == width {
                    return None;
                }
                let first_after_prefix = unsafe { read_byte(cursor) };
                if !digit_value(first_after_prefix).is_some_and(|digit| digit < 16) {
                    return None;
                }
                base = 16;
            }
        }
    } else if base == 0 {
        base = 10;
    }

    while used < width {
        let current = unsafe { read_byte(cursor) };
        if current == 0 {
            break;
        }
        let Some(digit) = digit_value(current) else {
            break;
        };
        if digit >= base {
            break;
        }
        value = value
            .wrapping_mul(base as u64)
            .wrapping_add(digit as u64);
        digits += 1;
        cursor = cursor.wrapping_add(1);
        used += 1;
    }
    (digits != 0).then_some(ScannedInteger {
        value,
        negative,
        next: cursor,
    })
}

unsafe fn assign_signed(args: &mut VaList<'_>, length: Length, value: u64, negative: bool) {
    let signed = if negative { value.wrapping_neg() } else { value };
    match length {
        Length::None => unsafe { args.next_arg::<*mut c_int>().write(signed as c_int) },
        Length::Hh => unsafe { args.next_arg::<*mut i8>().write(signed as i8) },
        Length::H => unsafe { args.next_arg::<*mut i16>().write(signed as i16) },
        Length::L | Length::Z | Length::T => unsafe {
            args.next_arg::<*mut c_long>().write(signed as c_long)
        },
        Length::Ll | Length::J => unsafe {
            args.next_arg::<*mut c_longlong>()
                .write(signed as c_longlong)
        },
    }
}

unsafe fn assign_unsigned(args: &mut VaList<'_>, length: Length, value: u64, negative: bool) {
    let unsigned = if negative { value.wrapping_neg() } else { value };
    match length {
        Length::None => unsafe { args.next_arg::<*mut c_uint>().write(unsigned as c_uint) },
        Length::Hh => unsafe { args.next_arg::<*mut u8>().write(unsigned as u8) },
        Length::H => unsafe { args.next_arg::<*mut u16>().write(unsigned as u16) },
        Length::L | Length::T => unsafe {
            args.next_arg::<*mut c_ulong>().write(unsigned as c_ulong)
        },
        Length::Ll | Length::J => unsafe {
            args.next_arg::<*mut c_ulonglong>()
                .write(unsigned as c_ulonglong)
        },
        Length::Z => unsafe { args.next_arg::<*mut usize>().write(unsigned as usize) },
    }
}

unsafe fn assign_count(args: &mut VaList<'_>, length: Length, count: usize) {
    match length {
        Length::None => unsafe { args.next_arg::<*mut c_int>().write(count as c_int) },
        Length::Hh => unsafe { args.next_arg::<*mut i8>().write(count as i8) },
        Length::H => unsafe { args.next_arg::<*mut i16>().write(count as i16) },
        Length::L | Length::Z | Length::T => unsafe {
            args.next_arg::<*mut c_long>().write(count as c_long)
        },
        Length::Ll | Length::J => unsafe {
            args.next_arg::<*mut c_longlong>()
                .write(count as c_longlong)
        },
    }
}

unsafe fn scan_from_string(
    input: *const c_char,
    format: *const c_char,
    args: &mut VaList<'_>,
) -> c_int {
    let mut cursor = input.cast::<u8>();
    let start = cursor;
    let mut directive = format.cast::<u8>();
    let mut assignments: c_int = 0;

    loop {
        let format_byte = unsafe { read_byte(directive) };
        if format_byte == 0 {
            return assignments;
        }
        if ascii_space(format_byte) {
            while ascii_space(unsafe { read_byte(directive) }) {
                directive = directive.wrapping_add(1);
            }
            cursor = unsafe { skip_input_space(cursor) };
            continue;
        }
        if format_byte != b'%' {
            if unsafe { read_byte(cursor) } == 0 {
                return if assignments == 0 { EOF } else { assignments };
            }
            if unsafe { read_byte(cursor) } != format_byte {
                return assignments;
            }
            cursor = cursor.wrapping_add(1);
            directive = directive.wrapping_add(1);
            continue;
        }
        directive = directive.wrapping_add(1);
        if unsafe { read_byte(directive) } == b'%' {
            cursor = unsafe { skip_input_space(cursor) };
            if unsafe { read_byte(cursor) } == 0 {
                return if assignments == 0 { EOF } else { assignments };
            }
            if unsafe { read_byte(cursor) } != b'%' {
                return assignments;
            }
            cursor = cursor.wrapping_add(1);
            directive = directive.wrapping_add(1);
            continue;
        }

        let suppress = if unsafe { read_byte(directive) } == b'*' {
            directive = directive.wrapping_add(1);
            true
        } else {
            false
        };
        let parsed_width = unsafe { parse_decimal(&mut directive) };
        let length = unsafe { parse_length(&mut directive) };
        let specifier = unsafe { read_byte(directive) };
        if specifier == 0 {
            unsafe { errno::set_errno(EINVAL) };
            return assignments;
        }
        directive = directive.wrapping_add(1);

        match specifier {
            b'd' | b'i' | b'u' | b'o' | b'x' | b'X' => {
                cursor = unsafe { skip_input_space(cursor) };
                let width = if parsed_width == 0 {
                    usize::MAX
                } else {
                    parsed_width
                };
                let base = match specifier {
                    b'd' => ScanBase::Decimal,
                    b'i' => ScanBase::Auto,
                    b'u' => ScanBase::UnsignedDecimal,
                    b'o' => ScanBase::Octal,
                    _ => ScanBase::Hex,
                };
                let Some(number) = (unsafe { scan_integer(cursor, width, base) }) else {
                    return if unsafe { read_byte(cursor) } == 0 && assignments == 0 {
                        EOF
                    } else {
                        assignments
                    };
                };
                cursor = number.next;
                if !suppress {
                    if specifier == b'd' || specifier == b'i' {
                        unsafe { assign_signed(args, length, number.value, number.negative) };
                    } else {
                        unsafe { assign_unsigned(args, length, number.value, number.negative) };
                    }
                    assignments += 1;
                }
            }
            b'c' if length == Length::None => {
                let width = if parsed_width == 0 { 1 } else { parsed_width };
                let mut copied = 0usize;
                let destination = if suppress {
                    core::ptr::null_mut()
                } else {
                    unsafe { args.next_arg::<*mut c_char>() }
                };
                while copied < width && unsafe { read_byte(cursor) } != 0 {
                    if !destination.is_null() {
                        // SAFETY: C's `%c` caller contract supplies a buffer
                        // of at least the explicitly selected width bytes.
                        unsafe { destination.add(copied).write(read_byte(cursor) as c_char) };
                    }
                    cursor = cursor.wrapping_add(1);
                    copied += 1;
                }
                if copied != width {
                    return if copied == 0 && assignments == 0 {
                        EOF
                    } else {
                        assignments
                    };
                }
                if !suppress {
                    assignments += 1;
                }
            }
            b's' if length == Length::None => {
                cursor = unsafe { skip_input_space(cursor) };
                let width = if parsed_width == 0 {
                    usize::MAX
                } else {
                    parsed_width
                };
                let destination = if suppress {
                    core::ptr::null_mut()
                } else {
                    unsafe { args.next_arg::<*mut c_char>() }
                };
                let mut copied = 0usize;
                while copied < width {
                    let byte = unsafe { read_byte(cursor) };
                    if byte == 0 || ascii_space(byte) {
                        break;
                    }
                    if !destination.is_null() {
                        unsafe { destination.add(copied).write(byte as c_char) };
                    }
                    cursor = cursor.wrapping_add(1);
                    copied += 1;
                }
                if copied == 0 {
                    return if unsafe { read_byte(cursor) } == 0 && assignments == 0 {
                        EOF
                    } else {
                        assignments
                    };
                }
                if !destination.is_null() {
                    unsafe { destination.add(copied).write(0) };
                }
                if !suppress {
                    assignments += 1;
                }
            }
            b'n' => {
                if !suppress {
                    let count = unsafe { cursor.offset_from(start) as usize };
                    unsafe { assign_count(args, length, count) };
                }
            }
            _ => {
                unsafe { errno::set_errno(EINVAL) };
                return assignments;
            }
        }
    }
}

/// Scan the selected grammar from a caller-owned NUL-terminated byte string.
///
/// # Safety
///
/// `input` and `format` must be readable through their terminating NULs.
/// `args` must contain a non-null writable destination of the exact type and
/// extent required by each nonsuppressed directive; `%c` needs its selected
/// width and `%s` also needs room for the trailing NUL.
#[no_mangle]
pub unsafe extern "C" fn vsscanf(
    input: *const c_char,
    format: *const c_char,
    mut args: VaList,
) -> c_int {
    unsafe { scan_from_string(input, format, &mut args) }
}

/// C-variadic entry for [`vsscanf`]'s selected NUL-string grammar.
///
/// # Safety
///
/// `input` and `format` must be readable NUL-terminated strings.  Every
/// variadic destination must be non-null, writable, correctly typed, and large
/// enough for the directive as described by [`vsscanf`].
#[no_mangle]
pub unsafe extern "C" fn sscanf(
    input: *const c_char,
    format: *const c_char,
    mut args: ...,
) -> c_int {
    unsafe { scan_from_string(input, format, &mut args) }
}
