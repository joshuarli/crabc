// Copyright (c) 2019-2024 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license is recorded in `UPSTREAM.md`.
// SPDX-License-Identifier: MIT
//
// Semantic port of mimalloc v3.5.0 `include/mimalloc/bits.h`. Rust's integer
// intrinsics replace the pinned source's compiler-builtin selection; zero
// inputs retain mimalloc's explicitly defined 64-bit results.

pub(crate) const SIZE_BITS: usize = usize::BITS as usize;

#[inline]
pub(crate) const fn popcount(value: usize) -> usize {
    value.count_ones() as usize
}

#[inline]
pub(crate) const fn ctz(value: usize) -> usize {
    value.trailing_zeros() as usize
}

#[inline]
pub(crate) const fn clz(value: usize) -> usize {
    value.leading_zeros() as usize
}

/// Port of `mi_bsf`; `None` represents its false result for a zero input.
#[inline]
pub(crate) const fn bsf(value: usize) -> Option<usize> {
    if value == 0 {
        None
    } else {
        Some(ctz(value))
    }
}

/// Port of `mi_bsr`; `None` represents its false result for a zero input.
#[inline]
pub(crate) const fn bsr(value: usize) -> Option<usize> {
    if value == 0 {
        None
    } else {
        Some(SIZE_BITS - 1 - clz(value))
    }
}

#[inline]
pub(crate) const fn rotr(value: usize, shift: usize) -> usize {
    value.rotate_right((shift & (SIZE_BITS - 1)) as u32)
}

#[inline]
pub(crate) const fn rotl(value: usize, shift: usize) -> usize {
    value.rotate_left((shift & (SIZE_BITS - 1)) as u32)
}

#[inline]
pub(crate) const fn rotl32(value: u32, shift: u32) -> u32 {
    value.rotate_left(shift & 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_popcount(mut value: usize) -> usize {
        let mut count = 0;
        while value != 0 {
            count += value & 1;
            value >>= 1;
        }
        count
    }

    fn reference_ctz(mut value: usize) -> usize {
        if value == 0 {
            return SIZE_BITS;
        }
        let mut count = 0;
        while value & 1 == 0 {
            count += 1;
            value >>= 1;
        }
        count
    }

    fn reference_clz(value: usize) -> usize {
        if value == 0 {
            return SIZE_BITS;
        }
        let mut count = 0;
        let mut mask = 1usize << (SIZE_BITS - 1);
        while value & mask == 0 {
            count += 1;
            mask >>= 1;
        }
        count
    }

    fn reference_rotl(value: usize, shift: usize) -> usize {
        let shift = shift & (SIZE_BITS - 1);
        (value << shift) | (value >> (shift.wrapping_neg() & (SIZE_BITS - 1)))
    }

    fn reference_rotr(value: usize, shift: usize) -> usize {
        let shift = shift & (SIZE_BITS - 1);
        (value >> shift) | (value << (shift.wrapping_neg() & (SIZE_BITS - 1)))
    }

    fn reference_rotl32(value: u32, shift: u32) -> u32 {
        let shift = shift & 31;
        (value << shift) | (value >> (shift.wrapping_neg() & 31))
    }

    #[test]
    fn bit_counts_cover_zero_and_every_sixteen_bit_value() {
        assert_eq!(ctz(0), 64);
        assert_eq!(clz(0), 64);

        for value in 0usize..=u16::MAX as usize {
            assert_eq!(popcount(value), reference_popcount(value));
            assert_eq!(ctz(value), reference_ctz(value));
            assert_eq!(clz(value), reference_clz(value));
        }
    }

    #[test]
    fn bit_scans_leave_zero_unselected() {
        assert_eq!(bsf(0), None);
        assert_eq!(bsr(0), None);
        for index in 0..64 {
            let value = 1usize << index;
            assert_eq!(bsf(value), Some(index));
            assert_eq!(bsr(value), Some(index));
        }
    }

    #[test]
    fn rotations_mask_the_shift_like_the_upstream_fallback() {
        let value = 0x0123_4567_89ab_cdefusize;
        for shift in [0usize, 1, 7, 31, 32, 63, 64, 65, 127, 128] {
            assert_eq!(rotl(value, shift), reference_rotl(value, shift));
            assert_eq!(rotr(value, shift), reference_rotr(value, shift));
        }

        let value32 = 0x89ab_cdefu32;
        for shift in [0u32, 1, 7, 15, 31, 32, 33, 63, 64] {
            assert_eq!(rotl32(value32, shift), reference_rotl32(value32, shift));
        }
    }
}
