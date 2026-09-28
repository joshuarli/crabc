// Copyright (c) 2019-2024 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license.
// SPDX-License-Identifier: MIT
//
// Integer intrinsics provide the selected word-width operations. Zero counts
// return the word width, scans leave zero unselected, and rotations mask shifts
// to the word width.

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

/// Return no index for zero, matching the source operation's false result.
#[inline]
pub(crate) const fn bsf(value: usize) -> Option<usize> {
    if value == 0 {
        None
    } else {
        Some(ctz(value))
    }
}

/// Return no index for zero, matching the source operation's false result.
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m1_bit_arithmetic_c_rust_trace() {
        use std::{
            fmt::Write as _,
            string::{String, ToString},
            vec::Vec,
        };

        use crate::config::{GIB, KIB, MAX_VABITS, MIB, MIN_VABITS, WORD_SIZE};

        assert_eq!(SIZE_BITS, 64);
        assert_eq!(WORD_SIZE, 8);
        assert_eq!(MAX_VABITS, 47);
        assert_eq!(MIN_VABITS, 43);

        let geometry = [
            ("MI_INTPTR_SHIFT", WORD_SIZE.trailing_zeros() as usize),
            ("MI_INTPTR_SIZE", WORD_SIZE),
            ("MI_INTPTR_BITS", WORD_SIZE * 8),
            ("MI_SIZE_SHIFT", WORD_SIZE.trailing_zeros() as usize),
            ("MI_SIZE_SIZE", WORD_SIZE),
            ("MI_SIZE_BITS", SIZE_BITS),
            ("MI_MAX_VABITS", MAX_VABITS),
            ("MI_MIN_VABITS", MIN_VABITS),
            ("MI_KiB", KIB),
            ("MI_MiB", MIB),
            ("MI_GiB", GIB),
            ("sizeof_size_t", WORD_SIZE),
            ("sizeof_uintptr_t", WORD_SIZE),
        ];
        let boundaries = [
            0,
            u64::MAX,
            u64::MAX - 1,
            i64::MAX as u64,
            1u64 << 63,
            0xaaaa_aaaa_aaaa_aaaa,
            0x5555_5555_5555_5555,
            0x0000_ffff_0000_ffff,
            0xffff_0000_ffff_0000,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x0000_0000_ffff_ffff,
            0xffff_ffff_0000_0000,
        ];
        let mut values = Vec::with_capacity(653);
        values.extend(boundaries);
        for bit in 0..64 {
            let single_bit = 1u64 << bit;
            values.push(single_bit);
            values.push(!single_bit);
        }
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for _ in 0..512 {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            values.push(mixed ^ (mixed >> 31));
        }
        assert_eq!(values.len(), 653);

        let shifts = (0..64usize).chain([64, 65, 127, 128, 129, usize::MAX]);
        let shifts32 = (0..32u32).chain([32, 33, 63, 64, 65, u32::MAX]);
        let mut trace = String::new();
        writeln!(trace, "CRABC_MI_M1_BITS_TRACE_BEGIN").unwrap();
        for (name, value) in geometry {
            writeln!(trace, "g {name} {value}").unwrap();
        }
        for (index, value) in values.iter().copied().enumerate() {
            let value = value as usize;
            let bsf_value = bsf(value).map_or_else(|| String::from("-"), |bit| bit.to_string());
            let bsr_value = bsr(value).map_or_else(|| String::from("-"), |bit| bit.to_string());
            writeln!(
                trace,
                "v {index} {value:016x} {} {} {} {bsf_value} {bsr_value}",
                popcount(value),
                ctz(value),
                clz(value),
            )
            .unwrap();
            for shift in shifts.clone() {
                writeln!(
                    trace,
                    "r {index} {shift} {:016x} {:016x}",
                    rotr(value, shift),
                    rotl(value, shift),
                )
                .unwrap();
            }
            let value32 = value as u32;
            for shift in shifts32.clone() {
                writeln!(
                    trace,
                    "r32 {index} {shift} {value32:08x} {:08x}",
                    rotl32(value32, shift),
                )
                .unwrap();
            }
        }
        writeln!(trace, "CRABC_MI_M1_BITS_TRACE_END").unwrap();
        std::print!("{trace}");
    }
}
