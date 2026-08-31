//! Selected static Linux/x86-64 `memccpy` C ABI boundary.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/string/memccpy.c::memccpy` to this one bounded byte-transfer
//! operation. The source first aligns equally misaligned ranges byte by byte,
//! then uses musl's `ONES`/`HIGHS` word test to leave a word containing the
//! truncated marker to the byte loop. It returns the byte after the copied
//! marker, or null after copying exactly `count` bytes with no marker.
//!
//! This target-local leaf owns no general bulk-memory family, C-string state,
//! locale, errno, TLS, allocation, syscall, stdio, resolver, socket, loader,
//! CRT, or public x86 support. `memcpy`, `memmove`, `memset`, `mempcpy`,
//! C-string copying/concatenation, and overlapping ranges remain separate
//! boundaries.

use core::{
    ffi::{c_int, c_void},
    ptr::null_mut,
};

const WORD_BYTES: usize = core::mem::size_of::<usize>();
const ALIGN_MASK: usize = WORD_BYTES - 1;
const ONES: usize = usize::MAX / u8::MAX as usize;
const HIGHS: usize = ONES * (u8::MAX as usize / 2 + 1);

/// Return whether a machine word contains at least one zero byte.
///
/// This is musl's `HASZERO` predicate expressed with wrapping subtraction so
/// the source's unsigned-word arithmetic stays defined in Rust.
#[inline]
fn has_zero_byte(word: usize) -> bool {
    word.wrapping_sub(ONES) & !word & HIGHS != 0
}

/// Copy through the first low-eight-bit `marker` byte in an exact range.
///
/// # Safety
///
/// When `count` is nonzero, `destination` and `source` must each designate
/// at least `count` readable/writable bytes respectively. Their ranges must not overlap,
/// matching C's `restrict` contract. Both null pointers are
/// accepted only when `count` is zero. The function never reads or writes
/// beyond the first `count` bytes and returns null when no truncated marker
/// occurs in that range.
#[no_mangle]
pub unsafe extern "C" fn memccpy(
    destination: *mut c_void,
    source: *const c_void,
    marker: c_int,
    count: usize,
) -> *mut c_void {
    let mut destination = destination.cast::<u8>();
    let mut source = source.cast::<u8>();
    let marker = marker as u8;
    let mut remaining = count;

    // Musl enters its word path only when equal low address bits let both
    // pointers become naturally aligned through the same byte prefix.
    if (source as usize & ALIGN_MASK) == (destination as usize & ALIGN_MASK) {
        while source as usize & ALIGN_MASK != 0 && remaining != 0 {
            // SAFETY: the caller supplied this current source byte and
            // destination byte; this loop advances only while one remains.
            let byte = unsafe { source.read() };
            // SAFETY: see the paired source read above.
            unsafe { destination.write(byte) };
            if byte == marker {
                // SAFETY: a just-written byte proves this one-past pointer
                // remains inside the caller's destination range.
                return unsafe { destination.add(1).cast() };
            }
            // SAFETY: the unconsumed-byte guard preserves both ranges.
            source = unsafe { source.add(1) };
            // SAFETY: the unconsumed-byte guard preserves both ranges.
            destination = unsafe { destination.add(1) };
            remaining -= 1;
        }

        if source as usize & ALIGN_MASK == 0 {
            let repeated_marker = ONES * marker as usize;
            while remaining >= WORD_BYTES {
                // Equal low address bits plus the byte prefix make both
                // pointers naturally aligned for musl's size_t transfer.
                let word = unsafe { source.cast::<usize>().read() };
                if has_zero_byte(word ^ repeated_marker) {
                    break;
                }
                // SAFETY: the `remaining >= WORD_BYTES` guard proves a full
                // aligned source word and matching destination word exist.
                unsafe { destination.cast::<usize>().write(word) };
                // SAFETY: the same full-word guard permits both advances.
                source = unsafe { source.add(WORD_BYTES) };
                // SAFETY: the same full-word guard permits both advances.
                destination = unsafe { destination.add(WORD_BYTES) };
                remaining -= WORD_BYTES;
            }
        }
    }

    while remaining != 0 {
        // SAFETY: the caller supplied this current source byte and
        // destination byte; this loop advances only while one remains.
        let byte = unsafe { source.read() };
        // SAFETY: see the paired source read above.
        unsafe { destination.write(byte) };
        if byte == marker {
            // SAFETY: a just-written byte proves this one-past pointer
            // remains inside the caller's destination range.
            return unsafe { destination.add(1).cast() };
        }
        // SAFETY: the unconsumed-byte guard preserves both ranges.
        source = unsafe { source.add(1) };
        // SAFETY: the unconsumed-byte guard preserves both ranges.
        destination = unsafe { destination.add(1) };
        remaining -= 1;
    }

    null_mut()
}
