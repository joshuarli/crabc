//! Selected static Linux/x86-64 UTF/ASCII `iconv` C ABI.
//!
//! This leaf owns the fixed-profile descriptor boundary only: `iconv_open`,
//! `iconv`, and `iconv_close` for ASCII, UTF-8, UTF-16LE/BE, UTF-32LE/BE,
//! and the Linux/x86-64 little-endian 32-bit `WCHAR_T` representation.  A
//! descriptor is an encoded non-null token, so this selected profile needs no
//! allocation, global registry, locale object, or reset state.  Conversion
//! advances the caller's input and output pointers only for complete scalars;
//! incomplete input reports `EINVAL`, malformed input reports `EILSEQ`, and
//! insufficient output reports `E2BIG`.  Like musl's ASCII output map, an
//! otherwise valid non-ASCII scalar converts to `'*'` and increments the
//! successful substitution count.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/locale/iconv.c::{fuzzycmp,find_charmap,combine_to_from,
//!   extract_from,extract_to,iconv}` maps to exact name normalization, the
//!   non-allocating token, C pointer-progress/error behavior, and the selected
//!   UTF/ASCII codec.
//! - `src/locale/iconv_close.c::iconv_close` maps to the no-state close path.
//!
//! The existing AArch64 implementation in `libc/src/c_abi.rs` is the project
//! implementation oracle for the fixed UTF/ASCII codec and public symbol
//! shape.  This x86 leaf owns a separate target-specific descriptor and errno
//! boundary, and deliberately does not inherit that implementation's broader
//! legacy and stateful encoding surface.
//!
//! Musl's stateful BOM forms, UCS-2, ISO-2022-JP, and legacy codepage maps
//! require allocation or codepage data outside the fixed C/POSIX/C.UTF-8
//! compatibility profile and intentionally remain unsupported.  This module
//! does not read or mutate `setlocale` state: `iconv` names its encoding at
//! descriptor creation, while the named C locale/multibyte leaf separately
//! owns C/POSIX/C.UTF-8 state and `mbstate_t` semantics.  C callers must pass
//! valid NUL-terminated encoding names and, when a conversion is requested,
//! live writable pointer/count records and readable/writable byte ranges as
//! required by the public `iconv` ABI.  `inbuf == NULL` is the selected
//! stateless reset query and returns zero without touching `errno`.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 iconv leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::errno;

type IconvT = *mut c_void;

const E2BIG: c_int = 7;
const EILSEQ: c_int = 84;
const EINVAL: c_int = 22;

const ENC_UTF8: usize = 1;
const ENC_UTF16LE: usize = 2;
const ENC_UTF16BE: usize = 3;
const ENC_UTF32LE: usize = 4;
const ENC_UTF32BE: usize = 5;
const ENC_WCHAR_T: usize = 6;
const ENC_ASCII: usize = 7;

#[derive(Clone, Copy)]
enum DecodeError {
    Incomplete,
    Invalid,
}

#[derive(Clone, Copy)]
struct EncodeProgress {
    written: usize,
    substitutions: usize,
}

/// Match a C encoding spelling with musl's exact `fuzzycmp` byte rules.
///
/// Case is folded and ordinary punctuation between canonical name bytes is
/// skipped.  The arithmetic deliberately retains musl's boundary treatment:
/// `':'` and `'{'` are significant, and trailing punctuation is not skipped.
/// The caller's input must be readable through its NUL terminator, as required
/// by the public C string ABI; this helper forms no Rust reference from it.
unsafe fn name_matches(input: *const c_char, expected: &[u8]) -> bool {
    if input.is_null() {
        return false;
    }

    let mut cursor = input.cast::<u8>();
    // SAFETY: the caller supplies a NUL-terminated C encoding name.
    let mut byte = unsafe { core::ptr::read(cursor) };
    let mut expected_index = 0usize;
    while byte != 0 && expected_index != expected.len() {
        while byte != 0
            && (byte | 32).wrapping_sub(b'a') > 26
            && byte.wrapping_sub(b'0') > 10
        {
            cursor = cursor.wrapping_add(1);
            // SAFETY: the caller supplies a NUL-terminated C encoding name.
            byte = unsafe { core::ptr::read(cursor) };
        }
        if byte | 32 != expected[expected_index] {
            return false;
        }
        cursor = cursor.wrapping_add(1);
        expected_index += 1;
        // SAFETY: the caller supplies a NUL-terminated C encoding name.
        byte = unsafe { core::ptr::read(cursor) };
    }
    byte == 0 && expected_index == expected.len()
}

/// Return one selected fixed-profile encoding identifier.
///
/// The empty name follows musl's `iconv_open` default and selects UTF-8.  No
/// stateful BOM spelling or legacy codepage alias crosses this x86 boundary.
unsafe fn find_encoding(name: *const c_char) -> Option<usize> {
    if name.is_null() {
        return None;
    }
    // SAFETY: the public C ABI requires `name` to be readable for one byte.
    if unsafe { core::ptr::read(name.cast::<u8>()) } == 0 {
        return Some(ENC_UTF8);
    }
    if unsafe { name_matches(name, b"utf8") } || unsafe { name_matches(name, b"char") } {
        return Some(ENC_UTF8);
    }
    if unsafe { name_matches(name, b"utf16le") } {
        return Some(ENC_UTF16LE);
    }
    if unsafe { name_matches(name, b"utf16be") } {
        return Some(ENC_UTF16BE);
    }
    if unsafe { name_matches(name, b"utf32le") } || unsafe { name_matches(name, b"ucs4le") } {
        return Some(ENC_UTF32LE);
    }
    if unsafe { name_matches(name, b"utf32be") } || unsafe { name_matches(name, b"ucs4be") } {
        return Some(ENC_UTF32BE);
    }
    if unsafe { name_matches(name, b"wchart") } {
        return Some(ENC_WCHAR_T);
    }
    if unsafe { name_matches(name, b"ascii") }
        || unsafe { name_matches(name, b"usascii") }
        || unsafe { name_matches(name, b"iso646") }
        || unsafe { name_matches(name, b"iso646us") }
    {
        return Some(ENC_ASCII);
    }
    None
}

#[inline]
const fn encoding_is_selected(encoding: usize) -> bool {
    matches!(
        encoding,
        ENC_UTF8
            | ENC_UTF16LE
            | ENC_UTF16BE
            | ENC_UTF32LE
            | ENC_UTF32BE
            | ENC_WCHAR_T
            | ENC_ASCII
    )
}

#[inline]
fn make_descriptor(from: usize, to: usize) -> IconvT {
    ((from << 16) | (to << 1) | 1) as IconvT
}

#[inline]
fn extract_from(descriptor: IconvT) -> usize {
    (descriptor as usize) >> 16
}

#[inline]
fn extract_to(descriptor: IconvT) -> usize {
    ((descriptor as usize) >> 1) & 0x7fff
}

#[inline]
fn descriptor_is_selected(descriptor: IconvT) -> bool {
    let raw = descriptor as usize;
    raw & 1 != 0
        && encoding_is_selected(extract_from(descriptor))
        && encoding_is_selected(extract_to(descriptor))
}

#[inline]
unsafe fn read_byte(pointer: *const u8, offset: usize) -> u8 {
    // SAFETY: each decoder first proves that the caller's byte count covers
    // `offset`; the C ABI keeps the associated input range live.
    unsafe { core::ptr::read(pointer.wrapping_add(offset)) }
}

#[inline]
unsafe fn read_u16(pointer: *const u8, little_endian: bool) -> u32 {
    // SAFETY: the selected UTF-16 decoder proved at least two input bytes.
    let first = unsafe { read_byte(pointer, 0) } as u32;
    // SAFETY: the selected UTF-16 decoder proved at least two input bytes.
    let second = unsafe { read_byte(pointer, 1) } as u32;
    if little_endian {
        first | (second << 8)
    } else {
        (first << 8) | second
    }
}

#[inline]
unsafe fn read_u32(pointer: *const u8, little_endian: bool) -> u32 {
    // SAFETY: the selected UTF-32 decoder proved at least four input bytes.
    let first = unsafe { read_byte(pointer, 0) } as u32;
    // SAFETY: the selected UTF-32 decoder proved at least four input bytes.
    let second = unsafe { read_byte(pointer, 1) } as u32;
    // SAFETY: the selected UTF-32 decoder proved at least four input bytes.
    let third = unsafe { read_byte(pointer, 2) } as u32;
    // SAFETY: the selected UTF-32 decoder proved at least four input bytes.
    let fourth = unsafe { read_byte(pointer, 3) } as u32;
    if little_endian {
        first | (second << 8) | (third << 16) | (fourth << 24)
    } else {
        (first << 24) | (second << 16) | (third << 8) | fourth
    }
}

#[inline]
const fn scalar_is_valid(value: u32) -> bool {
    value < 0x110000 && !(value >= 0xd800 && value <= 0xdfff)
}

/// Decode one complete selected input scalar without touching caller records.
///
/// # Safety
///
/// `source` must remain readable for `source_left` bytes.  This preserves the
/// ordinary C `iconv` pointer/count precondition without forming a reference.
unsafe fn decode(
    encoding: usize,
    source: *const u8,
    source_left: usize,
) -> Result<(u32, usize), DecodeError> {
    if source_left == 0 {
        return Err(DecodeError::Incomplete);
    }

    match encoding {
        ENC_UTF8 => {
            // SAFETY: `source_left > 0` above covers this first byte.
            let first = unsafe { read_byte(source, 0) };
            if first < 0x80 {
                return Ok((first as u32, 1));
            }
            if first < 0xc2 || first > 0xf4 {
                return Err(DecodeError::Invalid);
            }
            let width = if first < 0xe0 {
                2
            } else if first < 0xf0 {
                3
            } else {
                4
            };
            if source_left < width {
                return Err(DecodeError::Incomplete);
            }
            // SAFETY: `source_left >= width` proves each continuation read.
            let second = unsafe { read_byte(source, 1) };
            if second & 0xc0 != 0x80 {
                return Err(DecodeError::Invalid);
            }
            let mut scalar = ((first & (0x7f >> width)) as u32) << 6 | (second & 0x3f) as u32;
            if width >= 3 {
                // SAFETY: `source_left >= width >= 3` covers this byte.
                let third = unsafe { read_byte(source, 2) };
                if third & 0xc0 != 0x80 {
                    return Err(DecodeError::Invalid);
                }
                scalar = (scalar << 6) | (third & 0x3f) as u32;
            }
            if width == 4 {
                // SAFETY: `source_left >= width == 4` covers this byte.
                let fourth = unsafe { read_byte(source, 3) };
                if fourth & 0xc0 != 0x80 {
                    return Err(DecodeError::Invalid);
                }
                scalar = (scalar << 6) | (fourth & 0x3f) as u32;
            }
            if !scalar_is_valid(scalar)
                || (width == 2 && scalar < 0x80)
                || (width == 3 && scalar < 0x800)
                || (width == 4 && scalar < 0x10000)
            {
                return Err(DecodeError::Invalid);
            }
            Ok((scalar, width))
        }
        ENC_UTF16LE | ENC_UTF16BE => {
            if source_left < 2 {
                return Err(DecodeError::Incomplete);
            }
            // SAFETY: the preceding count check covers this aligned-free read.
            let first = unsafe { read_u16(source, encoding == ENC_UTF16LE) };
            if (0xdc00..=0xdfff).contains(&first) {
                return Err(DecodeError::Invalid);
            }
            if !(0xd800..=0xdbff).contains(&first) {
                return Ok((first, 2));
            }
            if source_left < 4 {
                return Err(DecodeError::Incomplete);
            }
            // SAFETY: the preceding count check covers the second code unit.
            let second = unsafe { read_u16(source.wrapping_add(2), encoding == ENC_UTF16LE) };
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(DecodeError::Invalid);
            }
            Ok((0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00), 4))
        }
        ENC_UTF32LE | ENC_UTF32BE | ENC_WCHAR_T => {
            if source_left < 4 {
                return Err(DecodeError::Incomplete);
            }
            let little_endian = encoding != ENC_UTF32BE;
            // SAFETY: the preceding count check covers four byte reads.
            let scalar = unsafe { read_u32(source, little_endian) };
            if scalar_is_valid(scalar) {
                Ok((scalar, 4))
            } else {
                Err(DecodeError::Invalid)
            }
        }
        ENC_ASCII => {
            // SAFETY: `source_left > 0` above covers this read.
            let scalar = unsafe { read_byte(source, 0) } as u32;
            if scalar <= 0x7f {
                Ok((scalar, 1))
            } else {
                Err(DecodeError::Invalid)
            }
        }
        _ => Err(DecodeError::Invalid),
    }
}

#[inline]
unsafe fn write_byte(pointer: *mut u8, offset: usize, value: u8) {
    // SAFETY: each encoder proves the caller's output capacity before writing.
    unsafe { core::ptr::write(pointer.wrapping_add(offset), value) };
}

#[inline]
unsafe fn write_u16(pointer: *mut u8, value: u32, little_endian: bool) {
    let high = (value >> 8) as u8;
    let low = value as u8;
    if little_endian {
        // SAFETY: the selected UTF-16 encoder proved two output bytes.
        unsafe { write_byte(pointer, 0, low) };
        // SAFETY: the selected UTF-16 encoder proved two output bytes.
        unsafe { write_byte(pointer, 1, high) };
    } else {
        // SAFETY: the selected UTF-16 encoder proved two output bytes.
        unsafe { write_byte(pointer, 0, high) };
        // SAFETY: the selected UTF-16 encoder proved two output bytes.
        unsafe { write_byte(pointer, 1, low) };
    }
}

#[inline]
unsafe fn write_u32(pointer: *mut u8, value: u32, little_endian: bool) {
    let bytes = [
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ];
    if little_endian {
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 0, bytes[3]) };
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 1, bytes[2]) };
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 2, bytes[1]) };
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 3, bytes[0]) };
    } else {
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 0, bytes[0]) };
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 1, bytes[1]) };
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 2, bytes[2]) };
        // SAFETY: the selected UTF-32 encoder proved four output bytes.
        unsafe { write_byte(pointer, 3, bytes[3]) };
    }
}

/// Encode one valid Unicode scalar to the selected destination encoding.
///
/// `Err(())` is only insufficient output capacity.  All decoders ensure the
/// scalar is Unicode-valid before reaching this point; ASCII's musl-shaped
/// replacement output is therefore a successful conversion with one count.
unsafe fn encode(
    encoding: usize,
    scalar: u32,
    destination: *mut u8,
    destination_left: usize,
) -> Result<EncodeProgress, ()> {
    match encoding {
        ENC_UTF8 => {
            let width = if scalar < 0x80 {
                1
            } else if scalar < 0x800 {
                2
            } else if scalar < 0x10000 {
                3
            } else {
                4
            };
            if destination_left < width {
                return Err(());
            }
            match width {
                1 => {
                    // SAFETY: capacity was checked for one byte.
                    unsafe { write_byte(destination, 0, scalar as u8) };
                }
                2 => {
                    // SAFETY: capacity was checked for two bytes.
                    unsafe { write_byte(destination, 0, 0xc0 | (scalar >> 6) as u8) };
                    // SAFETY: capacity was checked for two bytes.
                    unsafe { write_byte(destination, 1, 0x80 | (scalar & 0x3f) as u8) };
                }
                3 => {
                    // SAFETY: capacity was checked for three bytes.
                    unsafe { write_byte(destination, 0, 0xe0 | (scalar >> 12) as u8) };
                    // SAFETY: capacity was checked for three bytes.
                    unsafe { write_byte(destination, 1, 0x80 | ((scalar >> 6) & 0x3f) as u8) };
                    // SAFETY: capacity was checked for three bytes.
                    unsafe { write_byte(destination, 2, 0x80 | (scalar & 0x3f) as u8) };
                }
                _ => {
                    // SAFETY: capacity was checked for four bytes.
                    unsafe { write_byte(destination, 0, 0xf0 | (scalar >> 18) as u8) };
                    // SAFETY: capacity was checked for four bytes.
                    unsafe { write_byte(destination, 1, 0x80 | ((scalar >> 12) & 0x3f) as u8) };
                    // SAFETY: capacity was checked for four bytes.
                    unsafe { write_byte(destination, 2, 0x80 | ((scalar >> 6) & 0x3f) as u8) };
                    // SAFETY: capacity was checked for four bytes.
                    unsafe { write_byte(destination, 3, 0x80 | (scalar & 0x3f) as u8) };
                }
            }
            Ok(EncodeProgress {
                written: width,
                substitutions: 0,
            })
        }
        ENC_UTF16LE | ENC_UTF16BE => {
            let little_endian = encoding == ENC_UTF16LE;
            if scalar < 0x10000 {
                if destination_left < 2 {
                    return Err(());
                }
                // SAFETY: capacity was checked for one UTF-16 code unit.
                unsafe { write_u16(destination, scalar, little_endian) };
                Ok(EncodeProgress {
                    written: 2,
                    substitutions: 0,
                })
            } else {
                if destination_left < 4 {
                    return Err(());
                }
                let adjusted = scalar - 0x10000;
                // SAFETY: capacity was checked for two UTF-16 code units.
                unsafe {
                    write_u16(destination, 0xd800 + (adjusted >> 10), little_endian)
                };
                // SAFETY: capacity was checked for two UTF-16 code units.
                unsafe {
                    write_u16(destination.wrapping_add(2), 0xdc00 + (adjusted & 0x3ff), little_endian)
                };
                Ok(EncodeProgress {
                    written: 4,
                    substitutions: 0,
                })
            }
        }
        ENC_UTF32LE | ENC_UTF32BE | ENC_WCHAR_T => {
            if destination_left < 4 {
                return Err(());
            }
            // `WCHAR_T` is little-endian native x86-64 scalar storage.
            let little_endian = encoding != ENC_UTF32BE;
            // SAFETY: capacity was checked for four bytes.
            unsafe { write_u32(destination, scalar, little_endian) };
            Ok(EncodeProgress {
                written: 4,
                substitutions: 0,
            })
        }
        ENC_ASCII => {
            if destination_left < 1 {
                return Err(());
            }
            let (value, substitutions) = if scalar <= 0x7f {
                (scalar as u8, 0)
            } else {
                (b'*', 1)
            };
            // SAFETY: capacity was checked for one byte.
            unsafe { write_byte(destination, 0, value) };
            Ok(EncodeProgress {
                written: 1,
                substitutions,
            })
        }
        _ => Err(()),
    }
}

#[inline]
unsafe fn publish_progress(
    input: *mut *mut c_char,
    input_left: *mut usize,
    output: *mut *mut c_char,
    output_left: *mut usize,
    source: *const u8,
    source_remaining: usize,
    destination: *mut u8,
    destination_remaining: usize,
) {
    // SAFETY: the public conversion precondition requires all four records to
    // be writable.  This function commits only completed scalar progress.
    unsafe {
        core::ptr::write(input, source.cast_mut().cast::<c_char>());
        core::ptr::write(input_left, source_remaining);
        core::ptr::write(output, destination.cast::<c_char>());
        core::ptr::write(output_left, destination_remaining);
    }
}

/// Open one selected allocation-free encoding descriptor.
#[no_mangle]
pub unsafe extern "C" fn iconv_open(
    tocode: *const c_char,
    fromcode: *const c_char,
) -> IconvT {
    // SAFETY: public callers provide NUL-terminated encoding names.
    let to = unsafe { find_encoding(tocode) };
    // SAFETY: public callers provide NUL-terminated encoding names.
    let from = unsafe { find_encoding(fromcode) };
    match (to, from) {
        (Some(to), Some(from)) => make_descriptor(from, to),
        _ => {
            // SAFETY: this error belongs to the calling C thread.
            unsafe { errno::set_errno(EINVAL) };
            usize::MAX as IconvT
        }
    }
}

/// Convert complete input scalars through one selected descriptor.
///
/// A null `inbuf` is the stateless reset query.  Otherwise all pointer/count
/// records and their source/destination ranges must satisfy the normal C
/// `iconv` preconditions.  Invalid descriptor or record pointers fail closed
/// with `EINVAL`; byte-sequence failures retain musl's pointer-progress rules.
#[no_mangle]
pub unsafe extern "C" fn iconv(
    descriptor: IconvT,
    input: *mut *mut c_char,
    input_left: *mut usize,
    output: *mut *mut c_char,
    output_left: *mut usize,
) -> usize {
    if !descriptor_is_selected(descriptor) {
        // SAFETY: this error belongs to the calling C thread.
        unsafe { errno::set_errno(EINVAL) };
        return usize::MAX;
    }
    if input.is_null() {
        return 0;
    }
    if input_left.is_null() {
        // SAFETY: this error belongs to the calling C thread.
        unsafe { errno::set_errno(EINVAL) };
        return usize::MAX;
    }
    // SAFETY: non-null record pointers are required by the selected ABI.
    let mut source = unsafe { core::ptr::read(input) }.cast::<u8>();
    // SAFETY: non-null record pointers are required by the selected ABI.
    let mut source_remaining = unsafe { core::ptr::read(input_left) };
    if source.is_null() || source_remaining == 0 {
        return 0;
    }
    if output.is_null() || output_left.is_null() {
        // SAFETY: this error belongs to the calling C thread.
        unsafe { errno::set_errno(EINVAL) };
        return usize::MAX;
    }
    // SAFETY: non-null record pointers are required by the selected ABI.
    let mut destination = unsafe { core::ptr::read(output) }.cast::<u8>();
    // SAFETY: non-null record pointers are required by the selected ABI.
    let mut destination_remaining = unsafe { core::ptr::read(output_left) };
    if destination.is_null() {
        // SAFETY: this error belongs to the calling C thread.
        unsafe { errno::set_errno(EINVAL) };
        return usize::MAX;
    }

    let from = extract_from(descriptor);
    let to = extract_to(descriptor);
    let mut substitutions = 0usize;
    while source_remaining != 0 {
        // SAFETY: the caller's input range remains readable for
        // `source_remaining` bytes throughout this conversion.
        let decoded = unsafe { decode(from, source, source_remaining) };
        let (scalar, consumed) = match decoded {
            Ok(value) => value,
            Err(DecodeError::Incomplete) => {
                // SAFETY: all public record pointers were validated above.
                unsafe {
                    publish_progress(
                        input,
                        input_left,
                        output,
                        output_left,
                        source,
                        source_remaining,
                        destination,
                        destination_remaining,
                    )
                };
                // SAFETY: this error belongs to the calling C thread.
                unsafe { errno::set_errno(EINVAL) };
                return usize::MAX;
            }
            Err(DecodeError::Invalid) => {
                // SAFETY: all public record pointers were validated above.
                unsafe {
                    publish_progress(
                        input,
                        input_left,
                        output,
                        output_left,
                        source,
                        source_remaining,
                        destination,
                        destination_remaining,
                    )
                };
                // SAFETY: this error belongs to the calling C thread.
                unsafe { errno::set_errno(EILSEQ) };
                return usize::MAX;
            }
        };
        // SAFETY: the caller's destination range remains writable for
        // `destination_remaining` bytes throughout this conversion.
        let encoded = unsafe { encode(to, scalar, destination, destination_remaining) };
        let progress = match encoded {
            Ok(value) => value,
            Err(()) => {
                // SAFETY: all public record pointers were validated above.
                unsafe {
                    publish_progress(
                        input,
                        input_left,
                        output,
                        output_left,
                        source,
                        source_remaining,
                        destination,
                        destination_remaining,
                    )
                };
                // SAFETY: this error belongs to the calling C thread.
                unsafe { errno::set_errno(E2BIG) };
                return usize::MAX;
            }
        };
        source = source.wrapping_add(consumed);
        source_remaining -= consumed;
        destination = destination.wrapping_add(progress.written);
        destination_remaining -= progress.written;
        substitutions += progress.substitutions;
    }

    // SAFETY: all public record pointers were validated above.
    unsafe {
        publish_progress(
            input,
            input_left,
            output,
            output_left,
            source,
            source_remaining,
            destination,
            destination_remaining,
        )
    };
    substitutions
}

/// Close one selected allocation-free descriptor.
#[no_mangle]
pub unsafe extern "C" fn iconv_close(descriptor: IconvT) -> c_int {
    if descriptor_is_selected(descriptor) {
        0
    } else {
        // SAFETY: this error belongs to the calling C thread.
        unsafe { errno::set_errno(EINVAL) };
        -1
    }
}
