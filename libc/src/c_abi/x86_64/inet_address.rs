//! Selected static Linux/x86-64 numeric internet-address C ABI.
//!
//! This leaf owns exactly `inet_pton`, `inet_ntop`, `__inet_aton`, its weak
//! same-address `inet_aton` alias, and `inet_addr`. It is an allocation-free,
//! syscall-free numeric IPv4/IPv6 conversion boundary. It composes only the
//! selected integer scanner for `inet_aton`'s historical base-zero grammar and
//! the initial-TLS C `errno` slot. It is not name resolution, socket
//! transport, protocol-database parsing, locale-aware text conversion, stdio,
//! a general C runtime, libc.so, a CRT, dynamic TLS, a loader, a sysroot, or
//! public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/network/inet_pton.c` maps to [`inet_pton`] and the private strict
//!   IPv4 and IPv6 scanners below.
//! - `src/network/inet_ntop.c` maps to [`inet_ntop`], including its textual
//!   longest-`:0` run selection and its intentionally different IPv4 versus
//!   IPv6 short-buffer writes.
//! - `src/network/inet_aton.c` maps to [`__inet_aton`] and the assembler
//!   `inet_aton` alias. Its call to the selected musl-shaped `strtoul` entry
//!   preserves that scanner's no-conversion and overflow `errno` effects.
//! - `src/network/inet_addr.c` maps to [`inet_addr`].
//!
//! No public entry validates null or unterminated caller pointers: those are
//! C-domain preconditions. In particular, the parsers deliberately retain
//! musl's partial output writes on a later parse failure, and `inet_ntop`
//! retains its `snprintf`-style partial IPv4 output while keeping a too-small
//! IPv6 destination untouched.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

use super::{errno, integer_parse};

const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const EAFNOSUPPORT: c_int = 97;
const ENOSPC: c_int = 28;

/// Match musl's C-locale `isdigit` predicate for an input byte.
#[inline]
fn decimal_digit(byte: u8) -> bool {
    byte.wrapping_sub(b'0') < 10
}

/// Map one byte through musl's `hexval` helper.
#[inline]
fn hex_value(byte: u8) -> c_int {
    if byte.wrapping_sub(b'0') < 10 {
        c_int::from(byte - b'0')
    } else {
        let lower = byte | 32;
        if lower.wrapping_sub(b'a') < 6 {
            c_int::from(lower - b'a' + 10)
        } else {
            -1
        }
    }
}

/// Append one decimal octet without a terminator.
///
/// # Safety
///
/// `output` must have room for the at-most-three decimal bytes written here.
#[inline]
unsafe fn write_decimal_octet(mut output: *mut u8, value: u8) -> *mut u8 {
    if value >= 100 {
        // SAFETY: the helper contract supplies this output byte.
        unsafe { output.write(b'0' + value / 100) };
        // SAFETY: one written byte leaves the next output position valid.
        output = unsafe { output.add(1) };
        // SAFETY: the helper contract supplies this output byte.
        unsafe { output.write(b'0' + (value / 10) % 10) };
        // SAFETY: one written byte leaves the next output position valid.
        output = unsafe { output.add(1) };
    } else if value >= 10 {
        // SAFETY: the helper contract supplies this output byte.
        unsafe { output.write(b'0' + value / 10) };
        // SAFETY: one written byte leaves the next output position valid.
        output = unsafe { output.add(1) };
    }
    // SAFETY: the helper contract supplies this final output byte.
    unsafe { output.write(b'0' + value % 10) };
    // SAFETY: this returns the position following the byte just written.
    unsafe { output.add(1) }
}

/// Append one nonzero-padded lowercase hexadecimal IPv6 word.
///
/// # Safety
///
/// `output` must have room for the at-most-four bytes written here.
#[inline]
unsafe fn write_hex_word(mut output: *mut u8, word: u16) -> *mut u8 {
    let mut emitted = false;
    for shift in [12u32, 8, 4, 0] {
        let digit = ((u32::from(word) >> shift) & 15) as u8;
        if emitted || digit != 0 || shift == 0 {
            let byte = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
            // SAFETY: the helper contract supplies this output byte.
            unsafe { output.write(byte) };
            // SAFETY: one written byte leaves the next output position valid.
            output = unsafe { output.add(1) };
            emitted = true;
        }
    }
    output
}

/// Append dotted-decimal IPv4 text without a terminator.
///
/// # Safety
///
/// `address` must designate four readable IPv4 bytes and `output` must have
/// room for the at-most-fifteen output bytes.
#[inline]
unsafe fn write_ipv4_text(mut output: *mut u8, address: *const u8) -> *mut u8 {
    for index in 0..4 {
        if index != 0 {
            // SAFETY: the helper contract supplies this separator byte.
            unsafe { output.write(b'.') };
            // SAFETY: one written byte leaves the next output position valid.
            output = unsafe { output.add(1) };
        }
        // SAFETY: `index` is one of the four caller-provided IPv4 bytes.
        let octet = unsafe { address.add(index).read() };
        // SAFETY: the helper's output-space contract covers this octet.
        output = unsafe { write_decimal_octet(output, octet) };
    }
    output
}

/// Return one network-order IPv6 word from sixteen readable address bytes.
///
/// # Safety
///
/// `address` must designate the complete sixteen-byte IPv6 input.
#[inline]
unsafe fn ipv6_word(address: *const u8, index: usize) -> u16 {
    let offset = index * 2;
    // SAFETY: callers use only indices zero through seven.
    let high = unsafe { address.add(offset).read() };
    // SAFETY: callers use only indices zero through seven.
    let low = unsafe { address.add(offset + 1).read() };
    (u16::from(high) << 8) | u16::from(low)
}

/// Recognize exactly the first twelve bytes that choose musl's mapped-v4
/// `inet_ntop` presentation.
///
/// # Safety
///
/// `address` must designate the complete sixteen-byte IPv6 input.
#[inline]
unsafe fn ipv4_mapped(address: *const u8) -> bool {
    for index in 0..10 {
        // SAFETY: `index` remains in the first twelve IPv6 input bytes.
        if unsafe { address.add(index).read() } != 0 {
            return false;
        }
    }
    // SAFETY: bytes ten and eleven are inside the sixteen-byte IPv6 input.
    let tenth = unsafe { address.add(10).read() };
    // SAFETY: byte eleven is inside the sixteen-byte IPv6 input.
    let eleventh = unsafe { address.add(11).read() };
    tenth == 255 && eleventh == 255
}

/// Count one known NUL-terminated byte string without pulling in `strlen`.
///
/// # Safety
///
/// `input` must designate a readable NUL-terminated byte sequence.
#[inline]
unsafe fn c_string_length(mut input: *const u8) -> usize {
    let mut length = 0usize;
    loop {
        // SAFETY: the helper contract supplies this C-string byte.
        if unsafe { input.read() } == 0 {
            return length;
        }
        // SAFETY: the non-NUL byte proves that the next C-string byte exists.
        input = unsafe { input.add(1) };
        length += 1;
    }
}

/// Count musl's `strspn(cursor, ":0")` run.
///
/// # Safety
///
/// `input` must designate a readable NUL-terminated byte sequence.
#[inline]
unsafe fn colon_zero_span(mut input: *const u8) -> usize {
    let mut length = 0usize;
    loop {
        // SAFETY: the helper contract supplies this C-string byte.
        let byte = unsafe { input.read() };
        if byte != b':' && byte != b'0' {
            return length;
        }
        // SAFETY: a `:` or `0` byte is non-NUL, so the next byte exists.
        input = unsafe { input.add(1) };
        length += 1;
    }
}

/// Copy a complete C string through its terminator.
///
/// # Safety
///
/// `source` must be a readable NUL-terminated byte sequence and `destination`
/// must have room for it including that terminator.
#[inline]
unsafe fn copy_c_string(mut destination: *mut u8, mut source: *const u8) {
    loop {
        // SAFETY: the helper contract supplies this source byte.
        let byte = unsafe { source.read() };
        // SAFETY: the helper contract supplies the corresponding output byte.
        unsafe { destination.write(byte) };
        if byte == 0 {
            return;
        }
        // SAFETY: the observed source byte was non-NUL, so its successor is
        // another readable C-string byte.
        source = unsafe { source.add(1) };
        // SAFETY: the destination capacity includes the successor byte.
        destination = unsafe { destination.add(1) };
    }
}

/// Reproduce the output-side behavior of the IPv4 `snprintf` call in musl's
/// `inet_ntop`, including NUL-terminated truncation when `capacity` is small.
///
/// # Safety
///
/// `source` must designate `source_length` readable bytes. When `capacity` is
/// nonzero, `destination` must designate exactly that many writable bytes.
#[inline]
unsafe fn snprintf_ipv4_copy(
    destination: *mut u8,
    capacity: usize,
    source: *const u8,
    source_length: usize,
) {
    if capacity == 0 {
        return;
    }
    let copied = core::cmp::min(source_length, capacity - 1);
    for index in 0..copied {
        // SAFETY: `index < source_length` is inside the rendered IPv4 bytes.
        let byte = unsafe { source.add(index).read() };
        // SAFETY: `index < copied < capacity` is one destination byte.
        unsafe { destination.add(index).write(byte) };
    }
    // SAFETY: `copied < capacity`, so this writes the snprintf terminator.
    unsafe { destination.add(copied).write(0) };
}

/// Parse musl's strict dotted-decimal `AF_INET` form.
///
/// # Safety
///
/// `source` must be a readable NUL-terminated C string and `destination` must
/// designate four writable bytes. As in musl, an invalid later component can
/// leave earlier destination bytes written.
unsafe fn inet_pton_ipv4(mut source: *const u8, destination: *mut u8) -> c_int {
    let mut component = 0usize;
    while component < 4 {
        let mut value = 0 as c_int;
        let mut digits = 0usize;
        while digits < 3 {
            // SAFETY: the caller's C-string contract supplies the lookahead.
            let byte = unsafe { source.add(digits).read() };
            if !decimal_digit(byte) {
                break;
            }
            value = 10 * value + c_int::from(byte - b'0');
            digits += 1;
        }
        // SAFETY: the source C-string supplies this first non-digit byte.
        let delimiter = unsafe { source.add(digits).read() };
        // SAFETY: the C-string contract supplies its first byte.
        let first = unsafe { source.read() };
        if digits == 0 || (digits > 1 && first == b'0') || value > 255 {
            return 0;
        }
        // SAFETY: `component` is one of the four caller-provided output bytes.
        unsafe { destination.add(component).write(value as u8) };
        if delimiter == 0 && component == 3 {
            return 1;
        }
        if delimiter != b'.' {
            return 0;
        }
        // SAFETY: the period is non-NUL, so the following C-string byte exists.
        source = unsafe { source.add(digits + 1) };
        component += 1;
    }
    0
}

/// Parse musl's compressed hexadecimal `AF_INET6` form.
///
/// # Safety
///
/// `source` must be a readable NUL-terminated C string and `destination` must
/// designate sixteen writable bytes. The final embedded-v4 parse intentionally
/// happens after the sixteen-byte provisional write, exactly as in musl.
unsafe fn inet_pton_ipv6(mut source: *const u8, destination: *mut u8) -> c_int {
    let mut words = [0u16; 8];
    let words_ptr = words.as_mut_ptr();
    let mut index = 0usize;
    let mut break_index = -1isize;
    let mut needs_ipv4_tail = false;

    // SAFETY: the caller's C-string contract supplies the first byte.
    if unsafe { source.read() } == b':' {
        // SAFETY: the first colon is non-NUL, so its successor is readable.
        source = unsafe { source.add(1) };
        // SAFETY: the caller's C-string contract supplies this byte.
        if unsafe { source.read() } != b':' {
            return 0;
        }
    }

    loop {
        // SAFETY: the caller's C-string contract supplies this byte.
        if unsafe { source.read() } == b':' && break_index < 0 {
            break_index = index as isize;
            // SAFETY: `index & 7` retains musl's bounded local-array index.
            unsafe { words_ptr.add(index & 7).write(0) };
            // SAFETY: this colon is non-NUL, so its successor is readable.
            source = unsafe { source.add(1) };
            // SAFETY: the caller's C-string contract supplies this byte.
            if unsafe { source.read() } == 0 {
                break;
            }
            if index == 7 {
                return 0;
            }
            // This is the `for` loop's increment after musl's `continue`.
            index += 1;
            continue;
        }

        let mut value = 0 as c_int;
        let mut digits = 0usize;
        while digits < 4 {
            // SAFETY: the caller's C-string contract supplies this lookahead.
            let digit = hex_value(unsafe { source.add(digits).read() });
            if digit < 0 {
                break;
            }
            value = 16 * value + digit;
            digits += 1;
        }
        if digits == 0 {
            return 0;
        }
        // SAFETY: `index & 7` retains musl's bounded local-array index.
        unsafe { words_ptr.add(index & 7).write(value as u16) };
        // SAFETY: the source C-string supplies this first non-hexadecimal byte.
        let delimiter = unsafe { source.add(digits).read() };
        if delimiter == 0 && (break_index >= 0 || index == 7) {
            break;
        }
        if index == 7 {
            return 0;
        }
        if delimiter != b':' {
            if delimiter != b'.' || (index < 6 && break_index < 0) {
                return 0;
            }
            needs_ipv4_tail = true;
            index += 1;
            // SAFETY: `index & 7` retains musl's bounded local-array index.
            unsafe { words_ptr.add(index & 7).write(0) };
            break;
        }
        // SAFETY: the colon is non-NUL, so its successor is readable.
        source = unsafe { source.add(digits + 1) };
        // This is the `for` loop's normal increment.
        index += 1;
    }

    if break_index >= 0 {
        let break_index = break_index as usize;
        let moved_words = index + 1 - break_index;
        let destination_start = break_index + 7 - index;
        let mut moved = moved_words;
        while moved != 0 {
            moved -= 1;
            // SAFETY: musl's `i`/`brk` invariants keep both local indices in
            // the eight-word temporary; descending order is its `memmove`.
            let word = unsafe { words_ptr.add(break_index + moved).read() };
            // SAFETY: see the preceding local-array invariant.
            unsafe { words_ptr.add(destination_start + moved).write(word) };
        }
        for zero_offset in 0..(7 - index) {
            // SAFETY: this is musl's bounded zero-fill of the compressed gap.
            unsafe { words_ptr.add(break_index + zero_offset).write(0) };
        }
    }

    for word_index in 0..8 {
        // SAFETY: `word_index` is one of the eight initialized temporary words.
        let word = unsafe { words_ptr.add(word_index).read() };
        // SAFETY: each pair lies in the sixteen-byte caller output.
        unsafe { destination.add(word_index * 2).write((word >> 8) as u8) };
        // SAFETY: each pair lies in the sixteen-byte caller output.
        unsafe { destination.add(word_index * 2 + 1).write(word as u8) };
    }
    if needs_ipv4_tail
        && unsafe {
            inet_pton(
                AF_INET,
                source.cast::<c_char>(),
                destination.add(12).cast::<c_void>(),
            )
        } <= 0
    {
        return 0;
    }
    1
}

/// Convert one numeric IPv4 or IPv6 address into network-order bytes.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string. For `AF_INET`,
/// `destination` must designate four writable bytes; for `AF_INET6`, it must
/// designate sixteen. Unsupported families do not dereference either pointer.
/// Failed parses may retain musl's prior partial destination writes.
#[no_mangle]
pub unsafe extern "C" fn inet_pton(
    address_family: c_int,
    source: *const c_char,
    destination: *mut c_void,
) -> c_int {
    match address_family {
        AF_INET => unsafe { inet_pton_ipv4(source.cast::<u8>(), destination.cast::<u8>()) },
        AF_INET6 => unsafe { inet_pton_ipv6(source.cast::<u8>(), destination.cast::<u8>()) },
        _ => {
            // SAFETY: this is the selected C ABI error boundary.
            unsafe { errno::set_errno(EAFNOSUPPORT) };
            -1
        }
    }
}

/// Convert an IPv4 or IPv6 address to musl's canonical numeric text.
///
/// # Safety
///
/// `address` must designate four readable bytes for `AF_INET` or sixteen for
/// `AF_INET6`. On a successful result, `destination` must have room for the
/// returned NUL-terminated string. For IPv4, a nonzero short `length` permits
/// musl's `snprintf`-style truncated write before `ENOSPC`; for IPv6 a short
/// length performs no destination write. Unsupported families do not
/// dereference either pointer.
#[no_mangle]
pub unsafe extern "C" fn inet_ntop(
    address_family: c_int,
    address: *const c_void,
    destination: *mut c_char,
    length: c_uint,
) -> *const c_char {
    let destination_bytes = destination.cast::<u8>();
    let capacity = length as usize;

    match address_family {
        AF_INET => {
            let mut buffer = [0u8; 16];
            let buffer_ptr = buffer.as_mut_ptr();
            // SAFETY: AF_INET supplies four input bytes and the local buffer
            // holds the fifteen rendered bytes plus its terminator.
            let rendered_length = unsafe {
                let end = write_ipv4_text(buffer_ptr, address.cast::<u8>());
                end.write(0);
                end.offset_from(buffer_ptr) as usize
            };
            // SAFETY: this exactly models the preceding musl `snprintf`.
            unsafe {
                snprintf_ipv4_copy(
                    destination_bytes,
                    capacity,
                    buffer_ptr.cast_const(),
                    rendered_length,
                )
            };
            if rendered_length < capacity {
                return destination_bytes.cast::<c_char>().cast_const();
            }
        }
        AF_INET6 => {
            let mut buffer = [0u8; 100];
            let buffer_ptr = buffer.as_mut_ptr();
            let mut output = buffer_ptr;
            let address_bytes = address.cast::<u8>();

            // SAFETY: `address_bytes` supplies the full sixteen-byte IPv6 input.
            if unsafe { ipv4_mapped(address_bytes) } {
                for word_index in 0..6 {
                    if word_index != 0 {
                        // SAFETY: the fixed 100-byte local buffer is ample.
                        unsafe { output.write(b':') };
                        // SAFETY: this follows the byte just written.
                        output = unsafe { output.add(1) };
                    }
                    // SAFETY: `word_index` stays inside the IPv6 input.
                    let word = unsafe { ipv6_word(address_bytes, word_index) };
                    // SAFETY: the fixed 100-byte local buffer is ample.
                    output = unsafe { write_hex_word(output, word) };
                }
                // SAFETY: the fixed 100-byte local buffer is ample.
                unsafe { output.write(b':') };
                // SAFETY: this follows the byte just written.
                output = unsafe { output.add(1) };
                // SAFETY: the last four bytes are the mapped IPv4 input.
                output = unsafe { write_ipv4_text(output, address_bytes.add(12)) };
            } else {
                for word_index in 0..8 {
                    if word_index != 0 {
                        // SAFETY: the fixed 100-byte local buffer is ample.
                        unsafe { output.write(b':') };
                        // SAFETY: this follows the byte just written.
                        output = unsafe { output.add(1) };
                    }
                    // SAFETY: `word_index` stays inside the IPv6 input.
                    let word = unsafe { ipv6_word(address_bytes, word_index) };
                    // SAFETY: the fixed 100-byte local buffer is ample.
                    output = unsafe { write_hex_word(output, word) };
                }
            }
            // SAFETY: the fixed 100-byte local buffer is ample.
            unsafe { output.write(0) };

            let mut cursor = 0usize;
            let mut best = 0usize;
            let mut max = 2usize;
            loop {
                // SAFETY: the rendered local buffer has a terminator below 100.
                let byte = unsafe { buffer_ptr.add(cursor).read() };
                if byte == 0 {
                    break;
                }
                if cursor == 0 || byte == b':' {
                    // SAFETY: this follows musl's bounded `strspn(buf+i, ":0")`.
                    let span = unsafe { colon_zero_span(buffer_ptr.add(cursor)) };
                    if span > max + usize::from(best == 0) {
                        best = cursor;
                        max = span;
                    }
                }
                cursor += 1;
            }
            if max > 3 {
                // SAFETY: a span greater than three establishes both positions.
                unsafe { buffer_ptr.add(best).write(b':') };
                // SAFETY: see the preceding bounded-span invariant.
                unsafe { buffer_ptr.add(best + 1).write(b':') };
                let moved_bytes = cursor - best - max + 1;
                for moved in 0..moved_bytes {
                    // SAFETY: this is leftward `memmove` within the known local
                    // string, including its terminator.
                    let byte = unsafe { buffer_ptr.add(best + max + moved).read() };
                    // SAFETY: this destination is inside the same local string.
                    unsafe { buffer_ptr.add(best + 2 + moved).write(byte) };
                }
            }
            // SAFETY: the compression keeps a NUL-terminated local string.
            let rendered_length = unsafe { c_string_length(buffer_ptr.cast_const()) };
            if rendered_length < capacity {
                // SAFETY: the successful length check proves destination room
                // through the source terminator, matching musl's `strcpy`.
                unsafe { copy_c_string(destination_bytes, buffer_ptr.cast_const()) };
                return destination_bytes.cast::<c_char>().cast_const();
            }
        }
        _ => {
            // SAFETY: this is the selected C ABI error boundary.
            unsafe { errno::set_errno(EAFNOSUPPORT) };
            return core::ptr::null();
        }
    }

    // SAFETY: this is the selected C ABI error boundary for either short case.
    unsafe { errno::set_errno(ENOSPC) };
    core::ptr::null()
}

// Musl's `weak_alias(__inet_aton, inet_aton)` requires equal symbol values,
// not a Rust forwarding wrapper. Mark the strong helper hidden and define the
// public weak spelling as an assembler alias so archive consumers retain the
// same link-time override and address contract.
core::arch::global_asm!(
    ".hidden __inet_aton",
    ".weak inet_aton",
    ".set inet_aton, __inet_aton",
);

/// Parse musl's historical one- through four-component IPv4 grammar.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string. On a successful
/// input, `destination` must designate four writable bytes. As in musl, a
/// range failure in a later component can leave the earlier output bytes
/// written, and the selected `strtoul` scanner owns its ordinary `errno`
/// effects.
#[no_mangle]
pub unsafe extern "C" fn __inet_aton(
    source: *const c_char,
    destination: *mut c_void,
) -> c_int {
    let mut cursor = source;
    let mut values = [0 as c_ulong; 4];
    let values_ptr = values.as_mut_ptr();
    let mut components = 0usize;

    while components < 4 {
        let mut end = core::ptr::null_mut::<c_char>();
        // SAFETY: the caller supplies the C string and this local end slot.
        let value = unsafe { integer_parse::strtoul(cursor, &mut end, 0) };
        // SAFETY: `strtoul` returns an in-string end pointer for valid input.
        let end_byte = unsafe { end.cast::<u8>().read() };
        // SAFETY: the caller's C-string contract supplies its first byte.
        let first = unsafe { cursor.cast::<u8>().read() };
        if end.cast_const() == cursor
            || (end_byte != 0 && end_byte != b'.')
            || !decimal_digit(first)
        {
            return 0;
        }
        // SAFETY: `components` is one of the four local value slots.
        unsafe { values_ptr.add(components).write(value) };
        if end_byte == 0 {
            break;
        }
        // SAFETY: the accepted period is non-NUL, so its successor is readable.
        cursor = unsafe { end.add(1) };
        components += 1;
    }
    if components == 4 {
        return 0;
    }

    if components == 0 {
        // SAFETY: all accessed locations are the four local value slots.
        let first = unsafe { values_ptr.read() };
        unsafe { values_ptr.add(1).write(first & 0x00ff_ffff) };
        unsafe { values_ptr.write(first >> 24) };
    }
    if components <= 1 {
        // SAFETY: all accessed locations are the four local value slots.
        let second = unsafe { values_ptr.add(1).read() };
        unsafe { values_ptr.add(2).write(second & 0x0000_ffff) };
        unsafe { values_ptr.add(1).write(second >> 16) };
    }
    if components <= 2 {
        // SAFETY: all accessed locations are the four local value slots.
        let third = unsafe { values_ptr.add(2).read() };
        unsafe { values_ptr.add(3).write(third & 0x0000_00ff) };
        unsafe { values_ptr.add(2).write(third >> 8) };
    }

    let destination = destination.cast::<u8>();
    for component in 0..4 {
        // SAFETY: `component` is one of the four local value slots.
        let value = unsafe { values_ptr.add(component).read() };
        if value > 255 {
            return 0;
        }
        // SAFETY: each iteration writes one of the four caller output bytes.
        unsafe { destination.add(component).write(value as u8) };
    }
    1
}

/// Parse an IPv4 address and return its stored network-order `in_addr_t`.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string. This follows
/// musl by calling the hidden strong `__inet_aton` implementation directly.
/// Keep this C ABI boundary materialized for the separate legacy
/// `inet_network` wrapper, whose exact musl source dependency is `inet_addr`.
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn inet_addr(source: *const c_char) -> u32 {
    let mut address = [0u8; 4];
    // SAFETY: the local array supplies the four writable `struct in_addr` bytes.
    if unsafe { __inet_aton(source, address.as_mut_ptr().cast::<c_void>()) } == 0 {
        return u32::MAX;
    }
    u32::from_ne_bytes(address)
}
