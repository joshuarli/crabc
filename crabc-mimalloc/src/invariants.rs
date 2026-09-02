// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/internal.h`:
// `_mi_is_power_of_two`, `_mi_align_up`, `_mi_align_down`, `_mi_divide_up`,
// `_mi_wsize_from_size`, `mi_slice_count_of_size`, and `mi_size_of_slices`.
// The Rust forms make the
// upstream caller preconditions explicit with `Option`; no overflow wrapping
// or invalid-alignment fallback is hidden at this boundary.

use crate::config::{ARENA_SLICE_SIZE, WORD_SIZE};

#[inline]
pub(crate) const fn is_power_of_two(value: usize) -> bool {
    // Pinned `_mi_is_power_of_two` deliberately treats zero as a power of
    // two. Callers that model an alignment boundary reject zero separately,
    // just as `mi_alignment_is_valid` does in the source.
    (value & value.wrapping_sub(1)) == 0
}

#[inline]
pub(crate) const fn align_down(value: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 {
        return None;
    }
    let mask = alignment - 1;
    if (alignment & mask) == 0 {
        Some(value & !mask)
    } else {
        // `_mi_align_down` uses this generic path for every nonzero,
        // non-power-of-two alignment.
        Some((value / alignment) * alignment)
    }
}

#[inline]
pub(crate) const fn align_up(value: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 {
        return None;
    }
    let mask = alignment - 1;
    match value.checked_add(mask) {
        Some(aligned) if (alignment & mask) == 0 => Some(aligned & !mask),
        // The product cannot overflow: `(aligned / alignment) * alignment`
        // is at most `aligned`, which was just checked above. This is the
        // generic division path in pinned `_mi_align_up`.
        Some(aligned) => Some((aligned / alignment) * alignment),
        None => None,
    }
}

#[inline]
pub(crate) const fn divide_up(size: usize, divider: usize) -> Option<usize> {
    if divider == 0 {
        return None;
    }
    match size.checked_add(divider - 1) {
        Some(value) => Some(value / divider),
        None => None,
    }
}

#[inline]
pub(crate) const fn word_count(size: usize) -> Option<usize> {
    divide_up(size, WORD_SIZE)
}

#[inline]
pub(crate) const fn slice_count_of_size(size: usize) -> Option<usize> {
    divide_up(size, ARENA_SLICE_SIZE)
}

#[inline]
pub(crate) const fn size_of_slices(count: usize) -> Option<usize> {
    count.checked_mul(ARENA_SLICE_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ARENA_SLICE_SIZE, WORD_SIZE};

    #[test]
    fn power_of_two_alignment_covers_boundaries_and_invalid_inputs() {
        for alignment in [1, 2, 4, 8, 16, 64, 4096, ARENA_SLICE_SIZE] {
            assert_eq!(align_down(0x12345, alignment), Some(0x12345 & !(alignment - 1)));
            assert_eq!(align_up(0x12345, alignment), Some((0x12345 + alignment - 1) & !(alignment - 1)));
        }
        assert_eq!(align_down(9, 0), None);
        assert_eq!(align_up(9, 0), None);
        assert_eq!(align_up(usize::MAX, 2), None);
    }

    #[test]
    fn non_power_of_two_alignment_follows_the_pinned_generic_division_path() {
        // `internal.h` first takes the power-of-two fast path, then uses
        // division for every other nonzero alignment. These values exercise
        // that second path rather than treating a valid source input as an
        // unsupported Rust boundary.
        assert_eq!(align_down(101, 24), Some(96));
        assert_eq!(align_up(101, 24), Some(120));
        assert_eq!(align_down(17, 6), Some(12));
        assert_eq!(align_up(17, 6), Some(18));

        // This is deliberately distinct from alignment validity: source
        // `_mi_is_power_of_two(0)` is true, while
        // `mi_alignment_is_valid(0)` rejects the input at its own boundary.
        assert!(is_power_of_two(0));
    }

    #[test]
    fn division_and_word_counts_do_not_wrap() {
        assert_eq!(divide_up(0, 64), Some(0));
        assert_eq!(divide_up(1, 64), Some(1));
        assert_eq!(divide_up(64, 64), Some(1));
        assert_eq!(divide_up(65, 64), Some(2));
        assert_eq!(divide_up(1, 0), None);
        assert_eq!(divide_up(usize::MAX, 2), None);

        for size in 0..=(WORD_SIZE * 4) {
            assert_eq!(word_count(size), Some((size + WORD_SIZE - 1) / WORD_SIZE));
        }
        assert_eq!(word_count(usize::MAX), None);
    }

    #[test]
    fn slice_conversion_preserves_exact_round_trip_when_representable() {
        for count in [0, 1, 2, 511, 512] {
            let size = size_of_slices(count).unwrap();
            assert_eq!(slice_count_of_size(size), Some(count));
        }
        assert_eq!(slice_count_of_size(ARENA_SLICE_SIZE + 1), Some(2));
        assert_eq!(size_of_slices(usize::MAX), None);
    }
}
