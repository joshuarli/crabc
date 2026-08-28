//! Selected static Linux/x86-64 C bounded memory-search boundary.
//!
//! This leaf owns exactly three stateless, allocation-free byte-range
//! searches: `memchr`, GNU `memrchr`, and POSIX/GNU `memmem`. It has no
//! syscall, `errno`, TLS, allocator, locale, or mutable global-state boundary.
//! It is not copying or comparison, general string processing, locale-aware
//! text, stdio, libc.so, a CRT, pthread/TLS lifecycle, dynamic TLS, a loader,
//! a sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/string/memchr.c` maps to `memchr` and its private bounded
//!   first-byte helper below.
//! - `src/string/memrchr.c` maps to `memrchr` and its private reverse-search
//!   helper below. Musl exposes that implementation as `__memrchr` and then
//!   weak-aliases it to `memrchr`; this closed archive exports only the latter.
//! - `src/string/memmem.c` maps to `memmem`, its short 2/3/4-byte rolling
//!   searches, and its two-way critical-factorization route below.
//!
//! Two source-level adaptations preserve the same public bounded contracts.
//! The pinned `memchr.c` `__GNUC__` optimization may read whole native words;
//! this leaf retains its scalar fallback so every byte read lies in the exact
//! supplied range, including at a protected-page edge. `memmem.c` is expressed
//! through direct bounded raw-pointer loops rather than Rust slice indexing:
//! that keeps a stateless artifact from pulling panic support (and the separate
//! shared errno/TLS object) into its freestanding candidate, while retaining
//! musl's short-needle and linear two-way search structure.

use core::{
    ffi::{c_int, c_void},
    ptr::{null, null_mut},
};

/// Compare two exact byte sequences without selecting the wider `memcmp` ABI.
///
/// # Safety
///
/// `left` and `right` must each designate at least `count` readable bytes.
/// They may overlap, and either pointer may be null only when `count` is zero.
#[inline]
unsafe fn bytes_equal(mut left: *const u8, mut right: *const u8, mut count: usize) -> bool {
    while count != 0 {
        // SAFETY: each iteration consumes exactly one byte from both supplied
        // ranges before their proven remaining counts are decremented.
        if unsafe { left.read() } != unsafe { right.read() } {
            return false;
        }
        // SAFETY: the just-read nonfinal byte has a following in-range or
        // one-past position; no dereference occurs after the final advance.
        left = unsafe { left.add(1) };
        // SAFETY: identical reasoning applies to the other exact range.
        right = unsafe { right.add(1) };
        count = count.wrapping_sub(1);
    }
    true
}

/// Locate the first `target` in exactly `count` readable bytes.
///
/// # Safety
///
/// `memory` must designate at least `count` readable bytes. It may be null
/// only when `count` is zero.
#[inline]
unsafe fn find_first_byte(
    mut memory: *const u8,
    target: u8,
    mut count: usize,
) -> *const u8 {
    while count != 0 {
        // SAFETY: the helper's retained count proves this current byte exists.
        if unsafe { memory.read() } == target {
            return memory;
        }
        // SAFETY: the read consumed a byte from the exact range; advancing to
        // the following or one-past position does not dereference it yet.
        memory = unsafe { memory.add(1) };
        count = count.wrapping_sub(1);
    }
    null()
}

/// Locate the final `target` in exactly `count` readable bytes.
///
/// # Safety
///
/// `memory` must designate at least `count` readable bytes. It may be null
/// only when `count` is zero.
#[inline]
unsafe fn find_last_byte(memory: *const u8, target: u8, mut count: usize) -> *const u8 {
    while count != 0 {
        count = count.wrapping_sub(1);
        // SAFETY: the decremented count is one valid index in the exact range.
        let candidate = unsafe { memory.add(count) };
        // SAFETY: `candidate` is the proved in-range byte for this iteration.
        if unsafe { candidate.read() } == target {
            return candidate;
        }
    }
    null()
}

/// Locate `character` converted to `unsigned char` in an exact byte range.
///
/// # Safety
///
/// If `count` is nonzero, `memory` must designate at least `count` readable
/// bytes for this call. A null pointer is permitted only when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn memchr(
    memory: *const c_void,
    character: c_int,
    count: usize,
) -> *mut c_void {
    if count == 0 {
        return null_mut();
    }
    // SAFETY: the public nonzero-range contract is exactly the private helper
    // contract. Its result is either null or one pointer within that range.
    unsafe { find_first_byte(memory.cast::<u8>(), character as u8, count) }
        .cast_mut()
        .cast()
}

/// Locate the final `character` converted to `unsigned char` in an exact byte
/// range.
///
/// # Safety
///
/// If `count` is nonzero, `memory` must designate at least `count` readable
/// bytes for this call. A null pointer is permitted only when `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn memrchr(
    memory: *const c_void,
    character: c_int,
    count: usize,
) -> *mut c_void {
    if count == 0 {
        return null_mut();
    }
    // SAFETY: the public nonzero-range contract is exactly the private helper
    // contract. Its result is either null or one pointer within that range.
    unsafe { find_last_byte(memory.cast::<u8>(), character as u8, count) }
        .cast_mut()
        .cast()
}

/// Search an exact range for musl's 2/3/4-byte rolling window.
///
/// # Safety
///
/// `haystack` must designate `haystack_length` readable bytes, `needle` must
/// designate `width` readable bytes, `width` must be 2 through 4 inclusive,
/// and `haystack_length >= width`.
unsafe fn short_memmem(
    mut haystack: *const u8,
    mut haystack_length: usize,
    needle: *const u8,
    width: usize,
) -> *const u8 {
    let mut target = 0u32;
    let mut window = 0u32;
    let mut index = 0usize;
    while index < width {
        // SAFETY: `index < width` and the helper contract retain both bytes.
        target = (target << 8) | u32::from(unsafe { needle.add(index).read() });
        // SAFETY: `haystack_length >= width` retains the initial window.
        window = (window << 8) | u32::from(unsafe { haystack.add(index).read() });
        index = index.wrapping_add(1);
    }
    let mask = match width {
        2 => 0x0000_ffff,
        3 => 0x00ff_ffff,
        4 => u32::MAX,
        _ => return null(),
    };

    loop {
        if window == target {
            return haystack;
        }
        if haystack_length == width {
            return null();
        }
        // SAFETY: more than `width` bytes remain, so this incoming byte is
        // still inside the exact range before the candidate moves one byte.
        let incoming = unsafe { haystack.add(width).read() };
        window = ((window << 8) | u32::from(incoming)) & mask;
        // SAFETY: the current candidate has one byte to discard and at least
        // `width` bytes remain for the next candidate.
        haystack = unsafe { haystack.add(1) };
        haystack_length = haystack_length.wrapping_sub(1);
    }
}

/// Compute one of musl's two maximal suffixes for a long needle.
///
/// `usize::MAX` is the direct Rust spelling of musl's initial `size_t` `-1`.
/// The original algorithm's wrapping `ip + k` is retained explicitly; its
/// maintained invariants keep every resulting byte index inside `length`.
///
/// # Safety
///
/// `needle` must designate `length` readable bytes and `length` must be
/// nonzero.
unsafe fn maximal_suffix(
    needle: *const u8,
    length: usize,
    reverse_order: bool,
) -> (usize, usize) {
    let mut suffix = usize::MAX;
    let mut candidate = 0usize;
    let mut offset = 1usize;
    let mut period = 1usize;

    while candidate.wrapping_add(offset) < length {
        // SAFETY: musl's suffix-factorization invariant proves both wrapped
        // indexes select one byte in the caller's exact nonempty needle.
        let left = unsafe { needle.add(suffix.wrapping_add(offset)).read() };
        // SAFETY: the loop condition proves this candidate-side byte exists.
        let right = unsafe { needle.add(candidate.wrapping_add(offset)).read() };
        if left == right {
            if offset == period {
                candidate = candidate.wrapping_add(period);
                offset = 1;
            } else {
                offset = offset.wrapping_add(1);
            }
        } else if if reverse_order {
            left < right
        } else {
            left > right
        } {
            candidate = candidate.wrapping_add(offset);
            offset = 1;
            period = candidate.wrapping_sub(suffix);
        } else {
            suffix = candidate;
            candidate = candidate.wrapping_add(1);
            offset = 1;
            period = 1;
        }
    }
    (suffix, period)
}

/// Keep musl's linear two-way critical-factorization route for long needles.
///
/// # Safety
///
/// `haystack` must designate `haystack_length` readable bytes, `needle` must
/// designate `needle_length` readable bytes, and both lengths must be at least
/// five. The initial haystack range must be at least as long as the needle.
#[inline(never)]
unsafe fn two_way_memmem(
    mut haystack: *const u8,
    mut haystack_length: usize,
    needle: *const u8,
    needle_length: usize,
) -> *const u8 {
    let mut byte_set = [0u64; 4];
    let mut shift = [0usize; 256];
    let mut index = 0usize;
    while index < needle_length {
        // SAFETY: `index < needle_length` retains this exact needle byte.
        let byte = unsafe { needle.add(index).read() };
        let byte_index = byte as usize;
        // SAFETY: a u8 bucket is in 0..4, so this remains inside byte_set.
        let byte_set_word = unsafe { byte_set.as_mut_ptr().add(byte_index / 64) };
        // SAFETY: that pointer addresses the proved in-bounds local bucket.
        unsafe { *byte_set_word |= 1u64 << (byte % 64) };
        // SAFETY: a u8 is one valid index in the 256-entry local shift table.
        let shift_slot = unsafe { shift.as_mut_ptr().add(byte_index) };
        // SAFETY: `index < needle_length`, so this source-style one-based
        // shift remains valid for every searchable input object.
        unsafe { *shift_slot = index.wrapping_add(1) };
        index = index.wrapping_add(1);
    }

    // This is musl's two directional maximal-suffix calculation, including
    // its unsigned `-1` sentinel behavior.
    let (mut suffix, first_period) = unsafe { maximal_suffix(needle, needle_length, false) };
    let (other_suffix, mut period) = unsafe { maximal_suffix(needle, needle_length, true) };
    if other_suffix.wrapping_add(1) > suffix.wrapping_add(1) {
        suffix = other_suffix;
    } else {
        period = first_period;
    }

    let critical = suffix.wrapping_add(1);
    let periodic = if period <= needle_length && critical <= needle_length.wrapping_sub(period)
    {
        // SAFETY: the guards are musl's factorization bounds and retain two
        // exact `critical`-byte needle ranges.
        unsafe { bytes_equal(needle, needle.add(period), critical) }
    } else {
        false
    };
    let memory_after_match;
    if periodic {
        memory_after_match = needle_length.wrapping_sub(period);
    } else {
        // Source spelling: `MAX(ms, l-ms-1) + 1`, where `suffix` is `ms`.
        let opposite = needle_length
            .wrapping_sub(suffix)
            .wrapping_sub(1);
        period = if suffix > opposite { suffix } else { opposite }.wrapping_add(1);
        memory_after_match = 0;
    }

    let mut remembered = 0usize;
    loop {
        if haystack_length < needle_length {
            return null();
        }
        // SAFETY: the retained range has at least needle_length bytes, and a
        // long needle has a nonzero final index.
        let last = unsafe {
            haystack
                .add(needle_length.wrapping_sub(1))
                .read()
        };
        let last_index = last as usize;
        // SAFETY: u8 bucket selection stays within the four local words.
        let contains_last = unsafe {
            *byte_set.as_ptr().add(last_index / 64) & (1u64 << (last % 64)) != 0
        };
        if !contains_last {
            // SAFETY: exactly needle_length bytes remain in this discarded
            // prefix, so the next pointer remains in or one-past the range.
            haystack = unsafe { haystack.add(needle_length) };
            haystack_length = haystack_length.wrapping_sub(needle_length);
            remembered = 0;
            continue;
        }

        // SAFETY: last is a u8, so the table slot is one local valid entry.
        let mut advance = needle_length.wrapping_sub(unsafe {
            *shift.as_ptr().add(last_index)
        });
        if advance != 0 {
            if advance < remembered {
                advance = remembered;
            }
            // SAFETY: the two-way proof bounds the selected shift by the
            // current searchable suffix, so this preserves the exact range.
            haystack = unsafe { haystack.add(advance) };
            haystack_length = haystack_length.wrapping_sub(advance);
            remembered = 0;
            continue;
        }

        index = if critical > remembered {
            critical
        } else {
            remembered
        };
        while index < needle_length {
            // SAFETY: `index < needle_length <= haystack_length` retains both
            // compared bytes in their exact caller-owned ranges.
            if unsafe { needle.add(index).read() } != unsafe { haystack.add(index).read() } {
                break;
            }
            index = index.wrapping_add(1);
        }
        if index < needle_length {
            let advance = index.wrapping_sub(suffix);
            // SAFETY: a right-half mismatch advances by at least one and no
            // more than the searchable candidate range in musl's proof.
            haystack = unsafe { haystack.add(advance) };
            haystack_length = haystack_length.wrapping_sub(advance);
            remembered = 0;
            continue;
        }

        index = critical;
        while index > remembered {
            let previous = index.wrapping_sub(1);
            // SAFETY: previous remains one exact byte of both compared ranges.
            if unsafe { needle.add(previous).read() }
                != unsafe { haystack.add(previous).read() }
            {
                break;
            }
            index = previous;
        }
        if index <= remembered {
            return haystack;
        }
        // SAFETY: musl's period proof bounds this progress by the retained
        // range after an unsuccessful left-half comparison.
        haystack = unsafe { haystack.add(period) };
        haystack_length = haystack_length.wrapping_sub(period);
        remembered = memory_after_match;
    }
}

/// Locate the first complete `needle` byte sequence in `haystack`.
///
/// # Safety
///
/// If `haystack_length` is nonzero, `haystack` must designate at least that
/// many readable bytes. If `needle_length` is nonzero, `needle` must designate
/// at least that many readable bytes. The ranges may overlap. A null pointer
/// is permitted only with its corresponding zero length; an empty needle
/// returns `haystack` without examining either range.
#[no_mangle]
pub unsafe extern "C" fn memmem(
    haystack: *const c_void,
    haystack_length: usize,
    needle: *const c_void,
    needle_length: usize,
) -> *mut c_void {
    if needle_length == 0 {
        return haystack.cast_mut();
    }
    if haystack_length < needle_length {
        return null_mut();
    }

    let needle = needle.cast::<u8>();
    let mut remaining = haystack_length;
    // SAFETY: the public contract supplies the first byte of this nonempty
    // exact needle range.
    let first = unsafe { needle.read() };
    // SAFETY: the public haystack contract supplies the exact initial range.
    let search_start = unsafe { find_first_byte(haystack.cast::<u8>(), first, remaining) };
    if search_start.is_null() {
        return null_mut();
    }
    // The first pointer lies within the original haystack. Count the consumed
    // prefix without pointer subtraction so the remaining range stays explicit.
    let mut cursor = haystack.cast::<u8>();
    while cursor != search_start {
        // SAFETY: search_start came from the exact haystack range, so this
        // consumes only its known preceding prefix.
        cursor = unsafe { cursor.add(1) };
        remaining = remaining.wrapping_sub(1);
    }
    if needle_length == 1 {
        return search_start.cast_mut().cast();
    }
    if remaining < needle_length {
        return null_mut();
    }

    let found = match needle_length {
        2..=4 => {
            // SAFETY: the preceding check supplies all short-search ranges.
            unsafe { short_memmem(search_start, remaining, needle, needle_length) }
        }
        _ => {
            // SAFETY: the preceding check makes both long-search ranges exact,
            // nonempty, and at least five bytes at the needle boundary.
            unsafe { two_way_memmem(search_start, remaining, needle, needle_length) }
        }
    };
    found.cast_mut().cast()
}
