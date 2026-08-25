// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Semantic port of the bounded, allocation-free support kernels in pinned
// mimalloc v3.5.0 `src/libc.c` and the directly required byte-memory helpers
// in `include/mimalloc/internal.h`.

/// Port of `_mi_toupper` for the byte-oriented C strings used by mimalloc.
#[inline]
pub(crate) const fn ascii_uppercase(byte: u8) -> u8 {
    if byte >= b'a' && byte <= b'z' {
        byte - b'a' + b'A'
    } else {
        byte
    }
}

/// Port of `_mi_strnicmp`.
///
/// # Safety
///
/// Except at a zero `maximum_length`, `left` and `right` must be non-null and
/// each must point to initialized bytes through the first NUL or
/// `maximum_length` bytes, whichever occurs first. The bytes must not be
/// concurrently mutated without synchronization for the duration of the call.
#[inline]
pub(crate) unsafe fn c_strnicmp(left: *const u8, right: *const u8, maximum_length: usize) -> i32 {
    if maximum_length == 0 {
        return 0;
    }

    let mut left_cursor = left;
    let mut right_cursor = right;
    let mut remaining = maximum_length;
    loop {
        // The caller guarantees that the current cursor is readable until a
        // NUL or the requested bound is reached.
        let left_byte = unsafe { left_cursor.read() };
        // This cursor has the same bounded-readable guarantee as `left_cursor`.
        let right_byte = unsafe { right_cursor.read() };
        if left_byte == 0 || right_byte == 0 || remaining == 0 {
            return if remaining == 0 {
                0
            } else {
                left_byte as i32 - right_byte as i32
            };
        }
        if ascii_uppercase(left_byte) != ascii_uppercase(right_byte) {
            return left_byte as i32 - right_byte as i32;
        }

        // The C condition spells its bound check last. Returning here avoids
        // its otherwise unobservable out-of-range re-read after the final
        // permitted equal byte.
        remaining = remaining.wrapping_sub(1);
        if remaining == 0 {
            return 0;
        }
        left_cursor = left_cursor.wrapping_add(1);
        right_cursor = right_cursor.wrapping_add(1);
    }
}

/// Port of `_mi_streq`, including its null-pointer result convention.
///
/// # Safety
///
/// Each non-null pointer must point to an initialized NUL-terminated byte
/// string. Neither string may be concurrently mutated without synchronization
/// for the duration of the comparison.
#[inline]
pub(crate) unsafe fn c_str_eq(left: *const u8, right: *const u8) -> bool {
    if left.is_null() || right.is_null() {
        return left.is_null() && right.is_null();
    }

    let mut left_cursor = left;
    let mut right_cursor = right;
    loop {
        // Both cursors remain within caller-provided NUL-terminated strings.
        let left_byte = unsafe { left_cursor.read() };
        // Both cursors remain within caller-provided NUL-terminated strings.
        let right_byte = unsafe { right_cursor.read() };
        if left_byte != right_byte {
            return false;
        }
        if left_byte == 0 {
            return true;
        }

        left_cursor = left_cursor.wrapping_add(1);
        right_cursor = right_cursor.wrapping_add(1);
    }
}

/// Port of `_mi_strlcpy`; returns whether all of `source` was copied.
///
/// # Safety
///
/// If `destination` is non-null and `destination_size` is nonzero, it must be
/// writable for `destination_size` bytes. If `source` is non-null, it must be
/// readable through its first NUL or `destination_size` bytes, whichever
/// occurs first. When either pointer is null or `destination_size` is zero,
/// the source's first byte must be readable when `source` is non-null. The
/// caller must synchronize any concurrent access. Raw-pointer use deliberately
/// permits the source and destination to overlap, matching the source loop.
#[inline]
pub(crate) unsafe fn c_strlcpy(
    destination: *mut u8,
    source: *const u8,
    destination_size: usize,
) -> bool {
    if destination.is_null() || source.is_null() || destination_size == 0 {
        return source.is_null() || unsafe { source.read() == 0 };
    }

    let mut destination_cursor = destination;
    let mut source_cursor = source;
    let mut remaining = destination_size;
    loop {
        // The caller supplies readable source storage until the terminating
        // NUL or the bounded copy point.
        let source_byte = unsafe { source_cursor.read() };
        if source_byte == 0 || remaining <= 1 {
            break;
        }
        // `destination_cursor` is inside the writable destination range.
        unsafe { destination_cursor.write(source_byte) };
        destination_cursor = destination_cursor.wrapping_add(1);
        source_cursor = source_cursor.wrapping_add(1);
        remaining = remaining.wrapping_sub(1);
    }

    // At least one destination byte remains after the bounded copy loop.
    unsafe { destination_cursor.write(0) };
    // `_mi_strlcpy` determines its success result from the source byte where
    // copying stopped, not from the number of destination bytes written.
    unsafe { source_cursor.read() == 0 }
}

/// Port of `_mi_strlcat`; returns whether all of `source` was appended.
///
/// # Safety
///
/// If `destination` is non-null and `destination_size` is nonzero, it must be
/// writable for `destination_size` bytes and initialized through the first NUL
/// or `destination_size` bytes, whichever occurs first. `source` follows
/// the bounded-readable requirement of [`c_strlcpy`]. When either pointer is
/// null or the destination size is zero, the source's first byte must be
/// readable when `source` is non-null. The caller must synchronize concurrent
/// access. Source and destination may overlap because the source loop permits
/// that raw-memory behavior.
#[inline]
pub(crate) unsafe fn c_strlcat(
    destination: *mut u8,
    source: *const u8,
    destination_size: usize,
) -> bool {
    if destination.is_null() || source.is_null() || destination_size == 0 {
        return source.is_null() || unsafe { source.read() == 0 };
    }

    let mut destination_cursor = destination;
    let mut remaining = destination_size;
    loop {
        // The destination is initialized through the bounded scan point.
        let destination_byte = unsafe { destination_cursor.read() };
        if destination_byte == 0 || remaining <= 1 {
            break;
        }
        destination_cursor = destination_cursor.wrapping_add(1);
        remaining = remaining.wrapping_sub(1);
    }

    // The source and the remaining writable destination tail satisfy
    // `c_strlcpy`'s caller obligations.
    unsafe { c_strlcpy(destination_cursor, source, remaining) }
}

/// Port of `_mi_strnlen`.
///
/// # Safety
///
/// If `source` is non-null and `maximum_length` is nonzero, it must point to
/// initialized bytes through the first NUL or `maximum_length` bytes,
/// whichever occurs first. The bytes must not be concurrently mutated without
/// synchronization for the duration of the call.
#[inline]
pub(crate) unsafe fn c_strnlen(source: *const u8, maximum_length: usize) -> usize {
    if source.is_null() {
        return 0;
    }

    let mut cursor = source;
    let mut length = 0;
    while length < maximum_length {
        // The bounded source contract makes the current cursor readable.
        if unsafe { cursor.read() == 0 } {
            break;
        }
        cursor = cursor.wrapping_add(1);
        length = length.wrapping_add(1);
    }
    length
}

/// Port of `_mi_strlen`, which bounds its search at `PTRDIFF_MAX`.
///
/// # Safety
///
/// If `source` is non-null, it must point to initialized bytes through its
/// first NUL or `isize::MAX` bytes, whichever occurs first. The bytes must not
/// be concurrently mutated without synchronization for the duration of the
/// call.
#[inline]
pub(crate) unsafe fn c_strlen(source: *const u8) -> usize {
    // `PTRDIFF_MAX` is `isize::MAX` on both fixed Linux 64-bit profiles.
    unsafe { c_strnlen(source, isize::MAX as usize) }
}

/// Port of `_mi_strnstr`; returns a pointer derived from `haystack` or null.
///
/// # Safety
///
/// If `haystack` is non-null, it must be initialized and readable through its
/// first NUL or `maximum_length` bytes, whichever occurs first. If `pattern`
/// is non-null, it must point to initialized bytes through its first NUL or
/// `isize::MAX` bytes, whichever occurs first. Neither byte range may be
/// concurrently mutated without synchronization for the duration of the
/// search. The returned pointer, if non-null, has `haystack` provenance and
/// is valid only while that underlying storage remains valid.
#[inline]
pub(crate) unsafe fn c_strnstr(
    haystack: *mut u8,
    maximum_length: usize,
    pattern: *const u8,
) -> *mut u8 {
    if haystack.is_null() {
        return core::ptr::null_mut();
    }
    if pattern.is_null() {
        return haystack;
    }

    // Both helpers retain the original pointers' provenance; this routine
    // never converts an address to an integer or reconstructs a pointer.
    let haystack_length = unsafe { c_strnlen(haystack.cast_const(), maximum_length) };
    let pattern_length = unsafe { c_strlen(pattern) };
    if pattern_length > haystack_length {
        return core::ptr::null_mut();
    }

    let last_start = haystack_length - pattern_length;
    let mut start = 0;
    loop {
        let mut index = 0;
        while index < pattern_length {
            // `start <= last_start` and `index < pattern_length` keep this
            // cursor inside the bounded haystack range supplied by the caller.
            let haystack_byte = unsafe { haystack.wrapping_add(start).wrapping_add(index).read() };
            // `index` remains before the pattern's terminating NUL.
            let pattern_byte = unsafe { pattern.wrapping_add(index).read() };
            if haystack_byte != pattern_byte {
                break;
            }
            index = index.wrapping_add(1);
        }
        if index == pattern_length {
            return haystack.wrapping_add(start);
        }
        if start == last_start {
            break;
        }
        start = start.wrapping_add(1);
    }

    core::ptr::null_mut()
}

/// Port of `_mi_memcpy`.
///
/// # Safety
///
/// At a nonzero `byte_count`, `source` must be initialized and readable for
/// `byte_count` bytes, `destination` must be writable for `byte_count` bytes,
/// and the ranges must not overlap. The caller must synchronize any concurrent
/// access. Zero-length copies do not inspect either pointer.
#[inline]
pub(crate) unsafe fn copy_bytes(destination: *mut u8, source: *const u8, byte_count: usize) {
    if byte_count == 0 {
        return;
    }

    // The caller provides valid, non-overlapping byte ranges just as C
    // `memcpy` requires.
    unsafe { core::ptr::copy_nonoverlapping(source, destination, byte_count) };
}

/// Port of `_mi_memset`.
///
/// # Safety
///
/// At a nonzero `byte_count`, `destination` must be writable for `byte_count`
/// bytes. The caller must synchronize any concurrent access. Zero-length fills
/// do not inspect the pointer.
#[inline]
pub(crate) unsafe fn fill_bytes(destination: *mut u8, value: i32, byte_count: usize) {
    if byte_count == 0 {
        return;
    }

    // C `memset` converts its `int` argument to an unsigned byte.
    unsafe { core::ptr::write_bytes(destination, value as u8, byte_count) };
}

/// Port of `_mi_memzero`.
///
/// # Safety
///
/// This has the same destination-validity and synchronization obligations as
/// [`fill_bytes`]. Zero-length fills do not inspect the pointer.
#[inline]
pub(crate) unsafe fn zero_bytes(destination: *mut u8, byte_count: usize) {
    // `_mi_memzero` is exactly `_mi_memset(dst, 0, n)` in the pinned header.
    unsafe { fill_bytes(destination, 0, byte_count) };
}

/// Port of `_mi_memcpy_aligned`.
///
/// # Safety
///
/// This has the same obligations as [`copy_bytes`], and both pointers must be
/// aligned to the fixed target's machine-word size. The alignment obligation is
/// retained for callers even though this scalar port does not add a separate
/// compiler alignment assumption.
#[inline]
pub(crate) unsafe fn copy_bytes_aligned(
    destination: *mut u8,
    source: *const u8,
    byte_count: usize,
) {
    unsafe { copy_bytes(destination, source, byte_count) };
}

/// Port of `_mi_memset_aligned`.
///
/// # Safety
///
/// This has the same obligations as [`fill_bytes`], and `destination` must be
/// aligned to the fixed target's machine-word size.
#[inline]
pub(crate) unsafe fn fill_bytes_aligned(destination: *mut u8, value: i32, byte_count: usize) {
    unsafe { fill_bytes(destination, value, byte_count) };
}

/// Port of `_mi_memzero_aligned`.
///
/// # Safety
///
/// This has the same obligations as [`zero_bytes`], and `destination` must be
/// aligned to the fixed target's machine-word size.
#[inline]
pub(crate) unsafe fn zero_bytes_aligned(destination: *mut u8, byte_count: usize) {
    unsafe { zero_bytes(destination, byte_count) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn ascii_uppercase_retains_non_lowercase_bytes() {
        assert_eq!(ascii_uppercase(b'a'), b'A');
        assert_eq!(ascii_uppercase(b'z'), b'Z');
        assert_eq!(ascii_uppercase(b'A'), b'A');
        assert_eq!(ascii_uppercase(b'0'), b'0');
        assert_eq!(ascii_uppercase(0x80), 0x80);
    }

    #[test]
    fn c_strnicmp_stops_at_the_bound_or_first_nul_and_returns_raw_byte_difference() {
        let lower = b"abCa\0";
        let upper = b"ABDB\0";

        // The source returns zero without inspecting either string at a zero bound.
        assert_eq!(unsafe { c_strnicmp(lower.as_ptr(), upper.as_ptr(), 0) }, 0);
        assert_eq!(unsafe { c_strnicmp(lower.as_ptr(), upper.as_ptr(), 2) }, 0);
        assert_eq!(unsafe { c_strnicmp(lower.as_ptr(), upper.as_ptr(), 3) }, -1);

        let left = b"a\0";
        let right = b"B\0";
        // Comparisons uppercase, but the mismatch result subtracts the original bytes.
        assert_eq!(unsafe { c_strnicmp(left.as_ptr(), right.as_ptr(), 1) }, 31);

        let nul = b"abc\0";
        let suffix = b"ABC!\0";
        assert_eq!(unsafe { c_strnicmp(nul.as_ptr(), suffix.as_ptr(), 3) }, 0);
        assert_eq!(unsafe { c_strnicmp(nul.as_ptr(), suffix.as_ptr(), 4) }, -33);
    }

    #[test]
    fn c_string_equality_has_the_upstream_null_and_terminator_behavior() {
        let empty = b"\0";
        let equal = b"same\0";
        let different = b"sane\0";

        assert!(unsafe { c_str_eq(ptr::null(), ptr::null()) });
        assert!(!unsafe { c_str_eq(ptr::null(), empty.as_ptr()) });
        assert!(unsafe { c_str_eq(equal.as_ptr(), equal.as_ptr()) });
        assert!(!unsafe { c_str_eq(equal.as_ptr(), different.as_ptr()) });
    }

    #[test]
    fn c_strlcpy_truncates_with_a_nul_and_reports_complete_copies() {
        let source = b"abcdef\0";
        let mut destination = [0xa5; 5];

        assert!(!unsafe { c_strlcpy(destination.as_mut_ptr(), source.as_ptr(), destination.len()) });
        assert_eq!(destination, *b"abcd\0");

        let mut untouched = [0x5a; 2];
        assert!(!unsafe { c_strlcpy(untouched.as_mut_ptr(), source.as_ptr(), 0) });
        assert_eq!(untouched, [0x5a; 2]);
        assert!(unsafe { c_strlcpy(untouched.as_mut_ptr(), ptr::null(), untouched.len()) });
        assert_eq!(untouched, [0x5a; 2]);

        let mut complete = [0xa5; 7];
        assert!(unsafe { c_strlcpy(complete.as_mut_ptr(), source.as_ptr(), complete.len()) });
        assert_eq!(complete, *b"abcdef\0");

        let empty = b"\0";
        assert!(unsafe { c_strlcpy(ptr::null_mut(), empty.as_ptr(), 1) });
        assert!(!unsafe { c_strlcpy(ptr::null_mut(), source.as_ptr(), 1) });
    }

    #[test]
    fn c_strlcat_respects_the_remaining_buffer_and_repairs_an_unterminated_destination() {
        let source = b"cdef\0";
        let mut destination = *b"ab\0zz";

        assert!(!unsafe { c_strlcat(destination.as_mut_ptr(), source.as_ptr(), destination.len()) });
        assert_eq!(destination, *b"abcd\0");

        let mut unterminated = *b"abcde";
        let short = b"q\0";
        assert!(!unsafe { c_strlcat(unterminated.as_mut_ptr(), short.as_ptr(), unterminated.len()) });
        assert_eq!(unterminated, *b"abcd\0");

        let mut complete = *b"ab\0zz";
        assert!(unsafe { c_strlcat(complete.as_mut_ptr(), b"c\0".as_ptr(), complete.len()) });
        assert_eq!(complete, *b"abc\0z");
    }

    #[test]
    fn c_string_lengths_and_searches_remain_bounded_and_retain_the_haystack_provenance() {
        let mut haystack = *b"abcabc\0tail";
        let pattern = b"bca\0";
        let absent = b"cabx\0";
        let empty = b"\0";

        assert_eq!(unsafe { c_strnlen(ptr::null(), 4) }, 0);
        assert_eq!(unsafe { c_strnlen(haystack.as_ptr(), 0) }, 0);
        assert_eq!(unsafe { c_strnlen(haystack.as_ptr(), 2) }, 2);
        assert_eq!(unsafe { c_strnlen(haystack.as_ptr(), haystack.len()) }, 6);
        assert_eq!(unsafe { c_strlen(haystack.as_ptr()) }, 6);

        assert_eq!(
            unsafe { c_strnstr(haystack.as_mut_ptr(), 6, pattern.as_ptr()) },
            unsafe { haystack.as_mut_ptr().add(1) }
        );
        assert!(unsafe { c_strnstr(haystack.as_mut_ptr(), 2, b"abc\0".as_ptr()) }.is_null());
        assert!(unsafe { c_strnstr(haystack.as_mut_ptr(), 6, absent.as_ptr()) }.is_null());
        assert_eq!(
            unsafe { c_strnstr(haystack.as_mut_ptr(), 6, empty.as_ptr()) },
            haystack.as_mut_ptr()
        );
        assert_eq!(
            unsafe { c_strnstr(haystack.as_mut_ptr(), 6, ptr::null()) },
            haystack.as_mut_ptr()
        );
        assert!(unsafe { c_strnstr(ptr::null_mut(), 6, ptr::null()) }.is_null());
    }

    #[test]
    fn byte_memory_kernels_copy_fill_and_zero_without_touching_zero_length_inputs() {
        let source = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut destination = [0u8; 8];

        unsafe { copy_bytes(destination.as_mut_ptr(), source.as_ptr(), source.len()) };
        assert_eq!(destination, source);

        unsafe { fill_bytes(destination.as_mut_ptr(), -1, destination.len()) };
        assert_eq!(destination, [0xff; 8]);
        unsafe { zero_bytes(destination.as_mut_ptr().wrapping_add(2), 4) };
        assert_eq!(destination, [0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff]);

        unsafe { copy_bytes(ptr::null_mut(), ptr::null(), 0) };
        unsafe { fill_bytes(ptr::null_mut(), 0, 0) };
        unsafe { zero_bytes(ptr::null_mut(), 0) };
    }

    #[test]
    fn aligned_byte_memory_kernels_preserve_the_nonoverlapping_byte_operations() {
        let source = [0x0123_4567_89ab_cdefusize, 0xfedc_ba98_7654_3210usize];
        let mut destination = [0usize; 2];
        let byte_len = core::mem::size_of_val(&source);

        unsafe {
            copy_bytes_aligned(
                destination.as_mut_ptr().cast(),
                source.as_ptr().cast(),
                byte_len,
            )
        };
        assert_eq!(destination, source);

        unsafe { fill_bytes_aligned(destination.as_mut_ptr().cast(), -1, byte_len) };
        assert_eq!(destination, [usize::MAX; 2]);
        unsafe { zero_bytes_aligned(destination.as_mut_ptr().cast(), byte_len) };
        assert_eq!(destination, [0; 2]);
    }
}
