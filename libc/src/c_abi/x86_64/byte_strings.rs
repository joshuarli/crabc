//! Selected static Linux/x86-64 C byte-string observation/search boundary.
//!
//! This leaf owns exactly one stateless, allocation-free C byte-string block:
//! `index`, `rindex`, `strchr`, `strchrnul`, `strcmp`, `strcspn`, `strlen`,
//! `strncmp`, `strnlen`, `strpbrk`, `strrchr`, `strspn`, and `strstr`. It
//! shares no syscall, `errno`, TLS, allocator, locale, or mutable tokenizer
//! state. It is not byte-string copying or concatenation, tokenization,
//! case-insensitive or locale-aware comparison, wide/multibyte text, stdio,
//! a general C runtime, libc.so, CRT, dynamic TLS, loader, sysroot, or public
//! x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/string/index.c`, `src/string/rindex.c`, `src/string/strchr.c`,
//!   `src/string/strchrnul.c`, `src/string/strcmp.c`,
//!   `src/string/strcspn.c`, `src/string/strlen.c`,
//!   `src/string/strncmp.c`, `src/string/strnlen.c`,
//!   `src/string/strpbrk.c`, `src/string/strrchr.c`,
//!   `src/string/strspn.c`, and `src/string/strstr.c` map respectively to
//!   the named public C entries below.
//! - Musl's hidden `__strchrnul` and `__memrchr`, and the `memchr` calls from
//!   `strnlen` and `strstr`, map to private helpers in this leaf. The complete
//!   musl library weak-aliases some of those helpers to wider public symbols;
//!   this deliberately closed archive does not export those neighboring APIs.
//!
//! The two intentional source-level differences preserve the same observable
//! C contracts at this boundary. First, `strlen` and `strchrnul` select their
//! musl sources' existing scalar fallback loops instead of the `__GNUC__`
//! word-load optimization, so every Rust raw read stays at one proven C-string
//! byte. Second, `strstr` retains musl's two-way factorization and shift-table
//! algorithm but grows its known non-NUL haystack prefix one byte at a time
//! rather than calling musl's bounded speculative `memchr(z, 0, grow)` probe.
//! That preserves the linear discovery invariant while keeping a terminator at
//! a protected page edge outside the next-page read set.

use core::{
    ffi::{c_char, c_int},
    ptr::{null, null_mut},
};

/// Locate `target` or the first NUL in one caller-owned C string.
///
/// # Safety
///
/// `cursor` must designate a readable NUL-terminated byte sequence. It may
/// advance only through that sequence and its terminator.
#[inline]
unsafe fn strchrnul_bytes(mut cursor: *const u8, target: u8) -> *const u8 {
    loop {
        // SAFETY: the helper contract supplies the current C-string byte.
        let byte = unsafe { cursor.read() };
        if byte == target || byte == 0 {
            return cursor;
        }
        // SAFETY: the observed byte was non-NUL, so the C-string contract
        // supplies its following byte.
        cursor = unsafe { cursor.add(1) };
    }
}

/// Find `target` without returning the C-string terminator as a match unless
/// it is the requested target.
///
/// # Safety
///
/// `cursor` must designate a readable NUL-terminated byte sequence.
#[inline]
unsafe fn find_byte_in_c_string(cursor: *const u8, target: u8) -> *const u8 {
    // SAFETY: the helper retains the same C-string obligation.
    let found = unsafe { strchrnul_bytes(cursor, target) };
    // SAFETY: `found` is either a matching byte or the readable terminator.
    if unsafe { found.read() } == target {
        found
    } else {
        null()
    }
}

/// Return the offset of `target` or the first NUL, whichever arrives first.
///
/// # Safety
///
/// `cursor` must designate a readable NUL-terminated byte sequence.
#[inline]
unsafe fn offset_to_byte_or_nul(mut cursor: *const u8, target: u8) -> usize {
    let mut offset = 0usize;
    loop {
        // SAFETY: the helper contract supplies the current C-string byte.
        let byte = unsafe { cursor.read() };
        if byte == target || byte == 0 {
            return offset;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        cursor = unsafe { cursor.add(1) };
        offset += 1;
    }
}

/// Find `target` in exactly `count` readable bytes.
///
/// # Safety
///
/// When `count` is nonzero, `cursor` must designate at least `count` readable
/// bytes. A null cursor is valid only with a zero count.
#[inline]
unsafe fn find_byte_in_range(cursor: *const u8, target: u8, count: usize) -> Option<usize> {
    let mut offset = 0usize;
    while offset < count {
        // SAFETY: `offset < count` keeps this read inside the supplied range.
        if unsafe { cursor.add(offset).read() } == target {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

/// Private `__memrchr`-shaped reverse search over an exact readable range.
///
/// # Safety
///
/// When `count` is nonzero, `cursor` must designate at least `count` readable
/// bytes. A null cursor is valid only with a zero count.
#[inline]
unsafe fn find_last_byte_in_range(
    cursor: *const u8,
    target: u8,
    mut count: usize,
) -> *const u8 {
    while count != 0 {
        count -= 1;
        // SAFETY: the decremented count remains one valid byte index.
        let candidate = unsafe { cursor.add(count) };
        // SAFETY: `candidate` lies inside the exact caller-owned range.
        if unsafe { candidate.read() } == target {
            return candidate;
        }
    }
    null()
}

#[inline]
fn insert_byte(byte_set: &mut [u64; 4], byte: u8) {
    byte_set[byte as usize / 64] |= 1u64 << (byte % 64);
}

#[inline]
fn contains_byte(byte_set: &[u64; 4], byte: u8) -> bool {
    byte_set[byte as usize / 64] & (1u64 << (byte % 64)) != 0
}

/// Return the number of bytes before the first NUL in `string`.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence for this
/// call. A null pointer is never valid.
#[no_mangle]
pub unsafe extern "C" fn strlen(string: *const c_char) -> usize {
    let mut cursor = string.cast::<u8>();
    let mut length = 0usize;
    loop {
        // SAFETY: the caller owns one readable NUL-terminated C string.
        if unsafe { cursor.read() } == 0 {
            return length;
        }
        // SAFETY: the observed byte was non-NUL, so the next C-string byte
        // exists for the following iteration.
        cursor = unsafe { cursor.add(1) };
        length += 1;
    }
}

/// Compare two C strings with musl's unsigned-byte result convention.
///
/// # Safety
///
/// `left` and `right` must each designate readable NUL-terminated byte
/// sequences for this call. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strcmp(left: *const c_char, right: *const c_char) -> c_int {
    let mut left = left.cast::<u8>();
    let mut right = right.cast::<u8>();
    loop {
        // SAFETY: the caller supplies both current C-string bytes.
        let left_byte = unsafe { left.read() };
        // SAFETY: the caller supplies both current C-string bytes.
        let right_byte = unsafe { right.read() };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
        if left_byte == 0 {
            return 0;
        }
        // SAFETY: equal non-NUL bytes prove both following C-string bytes.
        left = unsafe { left.add(1) };
        // SAFETY: equal non-NUL bytes prove both following C-string bytes.
        right = unsafe { right.add(1) };
    }
}

/// Compare at most `count` C-string bytes with unsigned-byte differences.
///
/// # Safety
///
/// If `count` is nonzero, `left` and `right` must each designate readable
/// byte sequences through either their first NUL or `count` bytes. Null
/// pointers are valid only when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn strncmp(
    left: *const c_char,
    right: *const c_char,
    count: usize,
) -> c_int {
    let mut offset = 0usize;
    while offset < count {
        // SAFETY: `offset < count` and the caller contract supply both bytes.
        let left_byte = unsafe { left.cast::<u8>().add(offset).read() };
        // SAFETY: `offset < count` and the caller contract supply both bytes.
        let right_byte = unsafe { right.cast::<u8>().add(offset).read() };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
        if left_byte == 0 {
            return 0;
        }
        offset += 1;
    }
    0
}

/// Locate `character` or the first terminating NUL in one C string.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence. A null
/// pointer is never valid.
#[no_mangle]
pub unsafe extern "C" fn strchrnul(string: *const c_char, character: c_int) -> *mut c_char {
    // SAFETY: the caller supplies the complete C-string input contract.
    unsafe { strchrnul_bytes(string.cast::<u8>(), character as u8) }
        .cast_mut()
        .cast::<c_char>()
}

/// Locate the first occurrence of `character` in one C string.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence. A null
/// pointer is never valid.
#[no_mangle]
pub unsafe extern "C" fn strchr(string: *const c_char, character: c_int) -> *mut c_char {
    // SAFETY: the caller supplies the complete C-string input contract.
    unsafe { find_byte_in_c_string(string.cast::<u8>(), character as u8) }
        .cast_mut()
        .cast::<c_char>()
}

/// Locate the final occurrence of `character` in one C string.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence. A null
/// pointer is never valid.
#[no_mangle]
pub unsafe extern "C" fn strrchr(string: *const c_char, character: c_int) -> *mut c_char {
    // SAFETY: the caller supplies the NUL-terminated string needed to size
    // the private inclusive reverse-search range.
    let length = unsafe { strlen(string) };
    // SAFETY: the range is the string's bytes plus its readable terminator.
    unsafe { find_last_byte_in_range(string.cast::<u8>(), character as u8, length + 1) }
        .cast_mut()
        .cast::<c_char>()
}

/// BSD-compatible forwarding alias for [`strchr`].
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence. A null
/// pointer is never valid.
#[no_mangle]
pub unsafe extern "C" fn index(string: *const c_char, character: c_int) -> *mut c_char {
    // SAFETY: this has exactly `strchr`'s C-string input contract.
    unsafe { strchr(string, character) }
}

/// BSD-compatible forwarding alias for [`strrchr`].
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence. A null
/// pointer is never valid.
#[no_mangle]
pub unsafe extern "C" fn rindex(string: *const c_char, character: c_int) -> *mut c_char {
    // SAFETY: this has exactly `strrchr`'s C-string input contract.
    unsafe { strrchr(string, character) }
}

/// Return the number of bytes before either `reject`'s first byte or NUL.
///
/// # Safety
///
/// `string` and `reject` must each designate readable NUL-terminated byte
/// sequences. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strcspn(string: *const c_char, reject: *const c_char) -> usize {
    let reject = reject.cast::<u8>();
    // SAFETY: `reject` is a readable C string under the caller contract.
    let first = unsafe { reject.read() };
    if first == 0 {
        // SAFETY: the caller supplies the input C string.
        return unsafe { strlen(string) };
    }
    // SAFETY: a non-NUL first byte proves the next reject byte exists.
    if unsafe { reject.add(1).read() } == 0 {
        // SAFETY: both caller strings meet the helper's C-string contract.
        return unsafe { offset_to_byte_or_nul(string.cast::<u8>(), first) };
    }

    let mut byte_set = [0u64; 4];
    let mut reject_cursor = reject;
    loop {
        // SAFETY: each non-NUL byte proves the next reject byte exists.
        let byte = unsafe { reject_cursor.read() };
        if byte == 0 {
            break;
        }
        insert_byte(&mut byte_set, byte);
        // SAFETY: the observed reject byte was non-NUL.
        reject_cursor = unsafe { reject_cursor.add(1) };
    }

    let mut string_cursor = string.cast::<u8>();
    let mut length = 0usize;
    loop {
        // SAFETY: the caller supplies the current input C-string byte.
        let byte = unsafe { string_cursor.read() };
        if byte == 0 || contains_byte(&byte_set, byte) {
            return length;
        }
        // SAFETY: a non-NUL input byte proves the following byte exists.
        string_cursor = unsafe { string_cursor.add(1) };
        length += 1;
    }
}

/// Return the number of bytes in the initial span drawn from `accept`.
///
/// # Safety
///
/// `string` and `accept` must each designate readable NUL-terminated byte
/// sequences. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strspn(string: *const c_char, accept: *const c_char) -> usize {
    let accept = accept.cast::<u8>();
    // SAFETY: `accept` is a readable C string under the caller contract.
    let first = unsafe { accept.read() };
    if first == 0 {
        return 0;
    }
    // SAFETY: a non-NUL first byte proves the next accept byte exists.
    if unsafe { accept.add(1).read() } == 0 {
        let mut cursor = string.cast::<u8>();
        let mut length = 0usize;
        loop {
            // SAFETY: the caller supplies the current input C-string byte.
            if unsafe { cursor.read() } != first {
                return length;
            }
            // SAFETY: the matching byte is non-NUL because `first` is.
            cursor = unsafe { cursor.add(1) };
            length += 1;
        }
    }

    let mut byte_set = [0u64; 4];
    let mut accept_cursor = accept;
    loop {
        // SAFETY: each non-NUL byte proves the next accept byte exists.
        let byte = unsafe { accept_cursor.read() };
        if byte == 0 {
            break;
        }
        insert_byte(&mut byte_set, byte);
        // SAFETY: the observed accept byte was non-NUL.
        accept_cursor = unsafe { accept_cursor.add(1) };
    }

    let mut cursor = string.cast::<u8>();
    let mut length = 0usize;
    loop {
        // SAFETY: the caller supplies the current input C-string byte.
        let byte = unsafe { cursor.read() };
        if byte == 0 || !contains_byte(&byte_set, byte) {
            return length;
        }
        // SAFETY: the observed input byte was non-NUL.
        cursor = unsafe { cursor.add(1) };
        length += 1;
    }
}

/// Locate the first byte in `string` present in `accept`.
///
/// # Safety
///
/// `string` and `accept` must each designate readable NUL-terminated byte
/// sequences. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strpbrk(
    string: *const c_char,
    accept: *const c_char,
) -> *mut c_char {
    // SAFETY: the caller supplies both complete C strings.
    let offset = unsafe { strcspn(string, accept) };
    // SAFETY: `strcspn`'s returned offset lies at or before the input NUL.
    let found = unsafe { string.cast::<u8>().add(offset) };
    // SAFETY: `found` is the input byte at the returned offset or its NUL.
    if unsafe { found.read() } == 0 {
        null_mut()
    } else {
        found.cast_mut().cast::<c_char>()
    }
}

/// Return the bounded length before NUL, without examining byte `count`.
///
/// # Safety
///
/// If `count` is nonzero, `string` must designate at least `count` readable
/// bytes. A null pointer is valid only when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn strnlen(string: *const c_char, count: usize) -> usize {
    // SAFETY: this is the private `memchr(string, 0, count)` source mapping.
    unsafe { find_byte_in_range(string.cast::<u8>(), 0, count) }.unwrap_or(count)
}

/// Find the first occurrence of the C string `needle` in `haystack`.
///
/// # Safety
///
/// `haystack` and `needle` must each designate readable NUL-terminated byte
/// sequences for this call. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strstr(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    // SAFETY: the caller supplies both C strings; the helper reads only their
    // individually proved non-NUL prefixes and terminators.
    unsafe { strstr_c_string(haystack.cast::<u8>(), needle.cast::<u8>()) }
        .cast_mut()
        .cast::<c_char>()
}

/// Page-safe raw-pointer translation of musl's two-way `strstr` search.
///
/// # Safety
///
/// `haystack` and `needle` must each designate readable NUL-terminated byte
/// sequences.
unsafe fn strstr_c_string(mut haystack: *const u8, needle: *const u8) -> *const u8 {
    // SAFETY: the helper contract supplies the first needle byte.
    let first = unsafe { needle.read() };
    if first == 0 {
        return haystack;
    }
    // SAFETY: both C strings meet the helper contract.
    haystack = unsafe { find_byte_in_c_string(haystack, first) };
    if haystack.is_null() {
        return null();
    }
    // SAFETY: a non-NUL first needle byte proves its following byte exists.
    if unsafe { needle.add(1).read() } == 0 {
        return haystack;
    }
    // SAFETY: the found haystack byte is non-NUL, so its next byte exists.
    if unsafe { haystack.add(1).read() } == 0 {
        return null();
    }
    // SAFETY: the same C-string argument establishes the third needle byte.
    if unsafe { needle.add(2).read() } == 0 {
        return unsafe { two_byte_strstr(haystack, needle) };
    }
    // SAFETY: the same C-string argument establishes the third haystack byte.
    if unsafe { haystack.add(2).read() } == 0 {
        return null();
    }
    // SAFETY: the same C-string argument establishes the fourth needle byte.
    if unsafe { needle.add(3).read() } == 0 {
        return unsafe { three_byte_strstr(haystack, needle) };
    }
    // SAFETY: the same C-string argument establishes the fourth haystack byte.
    if unsafe { haystack.add(3).read() } == 0 {
        return null();
    }
    // SAFETY: the same C-string argument establishes the fifth needle byte.
    if unsafe { needle.add(4).read() } == 0 {
        return unsafe { four_byte_strstr(haystack, needle) };
    }
    // SAFETY: both C strings remain valid for the two-way search.
    unsafe { two_way_strstr(haystack, needle) }
}

/// Search a two-byte non-NUL needle after `strstr_c_string`'s dispatch.
unsafe fn two_byte_strstr(haystack: *const u8, needle: *const u8) -> *const u8 {
    // SAFETY: the dispatch proved both needle bytes readable and non-NUL.
    let target = unsafe { (u16::from(needle.read()) << 8) | u16::from(needle.add(1).read()) };
    // SAFETY: the dispatch proved both initial haystack bytes readable/non-NUL.
    let mut previous = unsafe { haystack.read() };
    // SAFETY: the second haystack byte is readable after the dispatch.
    let mut cursor = unsafe { haystack.add(1) };
    loop {
        // SAFETY: `cursor` stays inside the C string through its terminator.
        let current = unsafe { cursor.read() };
        if current == 0 {
            return null();
        }
        if (u16::from(previous) << 8) | u16::from(current) == target {
            // SAFETY: `cursor` is at least the second byte of the candidate.
            return unsafe { cursor.sub(1) };
        }
        previous = current;
        // SAFETY: current was non-NUL, so the following C-string byte exists.
        cursor = unsafe { cursor.add(1) };
    }
}

/// Search a three-byte non-NUL needle after `strstr_c_string`'s dispatch.
unsafe fn three_byte_strstr(haystack: *const u8, needle: *const u8) -> *const u8 {
    // SAFETY: dispatch established all three needle bytes.
    let target = unsafe {
        (u32::from(needle.read()) << 16)
            | (u32::from(needle.add(1).read()) << 8)
            | u32::from(needle.add(2).read())
    };
    // SAFETY: dispatch established all three initial haystack bytes.
    let mut window = unsafe {
        (u32::from(haystack.read()) << 16)
            | (u32::from(haystack.add(1).read()) << 8)
            | u32::from(haystack.add(2).read())
    };
    // SAFETY: the third initial haystack byte is established by dispatch.
    let mut cursor = unsafe { haystack.add(2) };
    loop {
        if window == target {
            // SAFETY: cursor is two bytes after the candidate start.
            return unsafe { cursor.sub(2) };
        }
        // SAFETY: the existing window has a non-NUL last byte until the next
        // iteration's checked `next` value ends the search.
        cursor = unsafe { cursor.add(1) };
        // SAFETY: a preceding non-NUL C-string byte proves this next byte.
        let next = unsafe { cursor.read() };
        if next == 0 {
            return null();
        }
        window = ((window << 8) | u32::from(next)) & 0x00ff_ffff;
    }
}

/// Search a four-byte non-NUL needle after `strstr_c_string`'s dispatch.
unsafe fn four_byte_strstr(haystack: *const u8, needle: *const u8) -> *const u8 {
    // SAFETY: dispatch established all four needle bytes.
    let target = unsafe {
        (u32::from(needle.read()) << 24)
            | (u32::from(needle.add(1).read()) << 16)
            | (u32::from(needle.add(2).read()) << 8)
            | u32::from(needle.add(3).read())
    };
    // SAFETY: dispatch established all four initial haystack bytes.
    let mut window = unsafe {
        (u32::from(haystack.read()) << 24)
            | (u32::from(haystack.add(1).read()) << 16)
            | (u32::from(haystack.add(2).read()) << 8)
            | u32::from(haystack.add(3).read())
    };
    // SAFETY: the fourth initial haystack byte is established by dispatch.
    let mut cursor = unsafe { haystack.add(3) };
    loop {
        if window == target {
            // SAFETY: cursor is three bytes after the candidate start.
            return unsafe { cursor.sub(3) };
        }
        // SAFETY: the current window's final byte is non-NUL until `next` is
        // checked below.
        cursor = unsafe { cursor.add(1) };
        // SAFETY: a preceding non-NUL byte proves this next C-string byte.
        let next = unsafe { cursor.read() };
        if next == 0 {
            return null();
        }
        window = (window << 8) | u32::from(next);
    }
}

/// Musl's two-way search with page-safe incremental haystack discovery.
unsafe fn two_way_strstr(mut haystack: *const u8, needle: *const u8) -> *const u8 {
    let mut byte_set = [0u64; 4];
    let mut shift = [0usize; 256];
    let mut needle_length = 0usize;
    loop {
        // SAFETY: each iteration reads the next needle byte and stops at NUL.
        let byte = unsafe { needle.add(needle_length).read() };
        if byte == 0 {
            break;
        }
        insert_byte(&mut byte_set, byte);
        let Some(next_length) = needle_length.checked_add(1) else {
            return null();
        };
        shift[byte as usize] = next_length;
        needle_length = next_length;
    }

    let (forward_suffix, forward_period) = unsafe { maximal_suffix(needle, needle_length, false) };
    let (reverse_suffix, reverse_period) = unsafe { maximal_suffix(needle, needle_length, true) };
    let (suffix, mut period) = if reverse_suffix > forward_suffix {
        (reverse_suffix, reverse_period)
    } else {
        (forward_suffix, forward_period)
    };
    let critical = if suffix < 0 { 0 } else { suffix as usize + 1 };
    let periodic = period.checked_add(critical).is_some_and(|end| {
        end <= needle_length
            && (0..critical).all(|index| {
                // SAFETY: the period/end checks keep both indices inside the
                // known non-NUL needle prefix.
                unsafe { needle.add(index).read() == needle.add(period + index).read() }
            })
    });
    let remembered_after_match = if periodic {
        needle_length - period
    } else {
        let span = core::cmp::max(critical, needle_length - critical);
        let Some(nonperiodic_period) = span.checked_add(1) else {
            return null();
        };
        period = nonperiodic_period;
        0
    };

    let mut known = 0usize;
    let mut remembered = 0usize;
    loop {
        // SAFETY: the function's C-string input contract supplies this
        // candidate's bytes up to its first NUL.
        if !unsafe { grow_c_string_prefix(haystack, &mut known, needle_length) } {
            return null();
        }
        // SAFETY: `known >= needle_length` proves this final candidate byte.
        let last = unsafe { haystack.add(needle_length - 1).read() };
        if !contains_byte(&byte_set, last) {
            // SAFETY: prefix growth validates the requested candidate move.
            if !unsafe { advance_c_string_candidate(&mut haystack, &mut known, needle_length) } {
                return null();
            }
            remembered = 0;
            continue;
        }

        let mut skip = needle_length - shift[last as usize];
        if skip != 0 {
            if remembered_after_match != 0 && remembered != 0 && skip < period {
                skip = needle_length - period;
            }
            // SAFETY: prefix growth validates the requested candidate move.
            if !unsafe { advance_c_string_candidate(&mut haystack, &mut known, skip) } {
                return null();
            }
            remembered = 0;
            continue;
        }

        let mut index = core::cmp::max(critical, remembered);
        while index < needle_length {
            // SAFETY: prefix growth established the indexed haystack byte;
            // the needle-length scan established the corresponding needle byte.
            if unsafe { needle.add(index).read() } != unsafe { haystack.add(index).read() } {
                break;
            }
            index += 1;
        }
        if index < needle_length {
            let advance = index - critical + 1;
            // SAFETY: prefix growth validates the requested candidate move.
            if !unsafe { advance_c_string_candidate(&mut haystack, &mut known, advance) } {
                return null();
            }
            remembered = 0;
            continue;
        }

        index = critical;
        while index > remembered
            // SAFETY: both indexed bytes were established by the preceding
            // prefix/needle scans.
            && unsafe { needle.add(index - 1).read() == haystack.add(index - 1).read() }
        {
            index -= 1;
        }
        if index <= remembered {
            return haystack;
        }
        // SAFETY: prefix growth validates the period advance.
        if !unsafe { advance_c_string_candidate(&mut haystack, &mut known, period) } {
            return null();
        }
        remembered = remembered_after_match;
    }
}

/// Compute musl's critical maximal suffix and its candidate period.
unsafe fn maximal_suffix(needle: *const u8, needle_length: usize, reverse_order: bool) -> (isize, usize) {
    let mut suffix = -1isize;
    let mut candidate = 0usize;
    let mut offset = 1usize;
    let mut period = 1usize;
    while candidate + offset < needle_length {
        let left_index = if suffix < 0 {
            offset - 1
        } else {
            suffix as usize + offset
        };
        // SAFETY: the maximal-suffix invariant keeps both indices inside the
        // non-NUL needle prefix measured by `needle_length`.
        let left = unsafe { needle.add(left_index).read() };
        // SAFETY: `candidate + offset < needle_length` above proves this read.
        let right = unsafe { needle.add(candidate + offset).read() };
        if left == right {
            if offset == period {
                candidate += period;
                offset = 1;
            } else {
                offset += 1;
            }
        } else if if reverse_order { left < right } else { left > right } {
            candidate += offset;
            offset = 1;
            period = if suffix < 0 {
                candidate + 1
            } else {
                candidate - suffix as usize
            };
        } else {
            suffix = candidate as isize;
            candidate += 1;
            offset = 1;
            period = 1;
        }
    }
    (suffix, period)
}

/// Establish `needed` non-NUL bytes without reading after the terminator.
unsafe fn grow_c_string_prefix(base: *const u8, known: &mut usize, needed: usize) -> bool {
    while *known < needed {
        // SAFETY: earlier loop iterations proved every preceding C-string byte
        // non-NUL, so this next byte exists under the helper contract.
        if unsafe { base.add(*known).read() } == 0 {
            return false;
        }
        let Some(next_known) = known.checked_add(1) else {
            return false;
        };
        *known = next_known;
    }
    true
}

/// Advance one two-way candidate only through the known non-NUL prefix.
unsafe fn advance_c_string_candidate(
    haystack: &mut *const u8,
    known: &mut usize,
    advance: usize,
) -> bool {
    // SAFETY: this keeps the new candidate at or before the current C-string
    // terminator without reading after it.
    if !unsafe { grow_c_string_prefix(*haystack, known, advance) } {
        return false;
    }
    // SAFETY: the known-prefix invariant proves this pointer addition.
    *haystack = unsafe { haystack.add(advance) };
    *known -= advance;
    true
}
