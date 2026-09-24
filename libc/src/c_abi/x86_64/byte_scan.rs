//! SSE2 byte scans shared by the C byte-string and memory-search leaves.
//!
//! These two kernels serve `strlen`, `strchr`, `strchrnul`, `strcspn`'s
//! one-byte form, `strnlen`, `memchr`, and the first-byte screens of `strstr`
//! and `memmem`. Musl 1.2.6's `src/string/{strlen,strchrnul,memchr}.c` scan
//! one aligned native word at a time and stop at the first terminator or
//! match; these kernels keep each function's result contract and scan one
//! aligned SSE2 vector (part of the x86-64 baseline ABI, so there is no
//! feature detection) at a time instead.
//!
//! Read discipline. C permits a caller to pass a string that ends, or a
//! `memchr`/`strnlen` count that runs, up to an unmapped page as long as the
//! scan stops at the terminator or match, so a vector load must never reach a
//! page the scan would not touch byte by byte. Every load is therefore a
//! 16-byte-aligned `movdqa`, which cannot cross a page, of a vector holding at
//! least one byte the byte-wise scan would read: the first vector holds the
//! first byte, and each later vector is loaded only after every earlier byte
//! is proven neither a terminator nor a match. The 4-vector loop runs only on
//! 64-byte-aligned blocks, which also lie in one page. Lanes before the start
//! or past a bounded count are masked off and never inform the result.
//!
//! The loads are inline assembly rather than Rust reads because lanes past a
//! terminator, before the start, or past the count lie outside the caller's
//! Rust-visible object even though their page is mapped.

use core::arch::x86_64::{
    __m128i, _mm_cmpeq_epi8, _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8, _mm_setzero_si128,
};
use core::ptr::null;

const VECTOR: usize = 16;
const BLOCK: usize = 4 * VECTOR;

/// Load one 16-byte-aligned vector through assembly.
///
/// # Safety
///
/// `address` must be 16-byte aligned and lie in a readable page.
#[inline(always)]
unsafe fn load(address: *const u8) -> __m128i {
    let vector: __m128i;
    // SAFETY: the caller proves alignment and page readability; an aligned
    // 16-byte load cannot cross into the following page.
    unsafe {
        core::arch::asm!(
            "movdqa {vector}, xmmword ptr [{address}]",
            address = in(reg) address,
            vector = out(xmm_reg) vector,
            options(nostack, preserves_flags, readonly, pure),
        );
    }
    vector
}

/// Lane mask of bytes of `vector` equal to `first` or `second`.
#[inline(always)]
fn either(vector: __m128i, first: __m128i, second: __m128i) -> u32 {
    // SAFETY: SSE2 is part of the x86-64 baseline this target always enables.
    unsafe {
        _mm_movemask_epi8(_mm_or_si128(_mm_cmpeq_epi8(vector, first), _mm_cmpeq_epi8(vector, second)))
            as u32
    }
}

/// Lane mask of bytes of `vector` equal to `wanted`.
#[inline(always)]
fn equal(vector: __m128i, wanted: __m128i) -> u32 {
    // SAFETY: SSE2 is part of the x86-64 baseline this target always enables.
    unsafe { _mm_movemask_epi8(_mm_cmpeq_epi8(vector, wanted)) as u32 }
}

/// Return the first `target` byte or NUL terminator of one C string.
///
/// # Safety
///
/// `string` must designate a readable NUL-terminated byte sequence.
#[inline]
pub(super) unsafe fn find_byte_or_nul(string: *const u8, target: u8) -> *const u8 {
    // SAFETY: SSE2 is part of the x86-64 baseline.
    let (nul, wanted) = unsafe { (_mm_setzero_si128(), _mm_set1_epi8(target as i8)) };
    let skipped = string as usize % VECTOR;
    let mut vector = string.wrapping_sub(skipped);
    // SAFETY: the aligned vector holding `string[0]` shares its page.
    let mask = either(unsafe { load(vector) }, nul, wanted) >> skipped;
    if mask != 0 {
        return string.wrapping_add(mask.trailing_zeros() as usize);
    }
    // Each following vector starts just after a vector with no terminator,
    // so its first byte is a string byte.
    loop {
        vector = vector.wrapping_add(VECTOR);
        if vector as usize % BLOCK == 0 {
            break;
        }
        // SAFETY: see above.
        let mask = either(unsafe { load(vector) }, nul, wanted);
        if mask != 0 {
            return vector.wrapping_add(mask.trailing_zeros() as usize);
        }
    }
    loop {
        // SAFETY: the block's first byte is a string byte (as above) and a
        // 64-byte-aligned block lies in that byte's page.
        let (a, b, c, d) = unsafe {
            (load(vector), load(vector.wrapping_add(VECTOR)),
                load(vector.wrapping_add(2 * VECTOR)), load(vector.wrapping_add(3 * VECTOR)))
        };
        let (a, b, c, d) = (either(a, nul, wanted), either(b, nul, wanted),
            either(c, nul, wanted), either(d, nul, wanted));
        if a | b | c | d != 0 {
            let mask = u64::from(a) | u64::from(b) << 16 | u64::from(c) << 32 | u64::from(d) << 48;
            return vector.wrapping_add(mask.trailing_zeros() as usize);
        }
        vector = vector.wrapping_add(BLOCK);
    }
}

/// Return the first `target` among at most `count` bytes, or null.
///
/// Like musl's `memchr`, this stops at the first match: only the bytes up to
/// and including it (or all `count` bytes when there is none) must be
/// readable.
///
/// # Safety
///
/// `start` must designate readable bytes up to the first `target` or, when
/// there is none, `count` readable bytes. It may be null only when `count` is
/// zero.
#[inline]
pub(super) unsafe fn find_byte(start: *const u8, target: u8, count: usize) -> *const u8 {
    if count == 0 {
        return null();
    }
    // SAFETY: SSE2 is part of the x86-64 baseline.
    let wanted = unsafe { _mm_set1_epi8(target as i8) };
    let skipped = start as usize % VECTOR;
    let mut vector = start.wrapping_sub(skipped);
    // SAFETY: the aligned vector holding `start[0]` shares its page.
    let mut mask = equal(unsafe { load(vector) }, wanted) >> skipped;
    let first = VECTOR - skipped;
    if count <= first {
        mask &= low_lanes(count);
        return if mask != 0 { start.wrapping_add(mask.trailing_zeros() as usize) } else { null() };
    }
    if mask != 0 {
        return start.wrapping_add(mask.trailing_zeros() as usize);
    }
    // Bytes of the range not yet examined; each following vector starts at
    // one of them, after every earlier byte proved not to match.
    let mut remaining = count - first;
    loop {
        vector = vector.wrapping_add(VECTOR);
        if vector as usize % BLOCK == 0 && remaining >= BLOCK {
            break;
        }
        // SAFETY: see above.
        let mut mask = equal(unsafe { load(vector) }, wanted);
        if remaining <= VECTOR {
            mask &= low_lanes(remaining);
            return if mask != 0 { vector.wrapping_add(mask.trailing_zeros() as usize) } else { null() };
        }
        if mask != 0 {
            return vector.wrapping_add(mask.trailing_zeros() as usize);
        }
        remaining -= VECTOR;
    }
    loop {
        // SAFETY: the block is 64-byte aligned (one page), wholly inside the
        // range, and starts after every earlier byte proved not to match.
        let (a, b, c, d) = unsafe {
            (load(vector), load(vector.wrapping_add(VECTOR)),
                load(vector.wrapping_add(2 * VECTOR)), load(vector.wrapping_add(3 * VECTOR)))
        };
        let (a, b, c, d) = (equal(a, wanted), equal(b, wanted), equal(c, wanted), equal(d, wanted));
        if a | b | c | d != 0 {
            let mask = u64::from(a) | u64::from(b) << 16 | u64::from(c) << 32 | u64::from(d) << 48;
            return vector.wrapping_add(mask.trailing_zeros() as usize);
        }
        vector = vector.wrapping_add(BLOCK);
        remaining -= BLOCK;
        if remaining < BLOCK {
            break;
        }
    }
    while remaining != 0 {
        // SAFETY: the vector starts at an unexamined in-range byte.
        let mut mask = equal(unsafe { load(vector) }, wanted);
        if remaining <= VECTOR {
            mask &= low_lanes(remaining);
            return if mask != 0 { vector.wrapping_add(mask.trailing_zeros() as usize) } else { null() };
        }
        if mask != 0 {
            return vector.wrapping_add(mask.trailing_zeros() as usize);
        }
        vector = vector.wrapping_add(VECTOR);
        remaining -= VECTOR;
    }
    null()
}

/// Mask of the lowest `lanes` (1..=16) vector lanes.
#[inline(always)]
fn low_lanes(lanes: usize) -> u32 {
    debug_assert!((1..=VECTOR).contains(&lanes));
    (1u32 << lanes) - 1
}
