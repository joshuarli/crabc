//! C-linkable compiler helpers owned by crabc's selected Linux targets.
//!
//! Both selected 64-bit little-endian ABIs pass a 128-bit integer in two
//! consecutive machine words for these compiler-runtime entries. `Uint128`
//! makes that representation explicit: the low word precedes the high word.
//! Keeping the
//! representation explicit avoids making this archive depend on Rust's
//! language-level `u128` operations, which could recursively request the very
//! helpers exported below.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(
    not(test),
    not(all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "linux",
        target_endian = "little",
        target_pointer_width = "64"
    ))
))]
compile_error!("crabc-builtins is only built for selected Linux 64-bit little-endian targets");

/// The selected target ABI representation of an unsigned 128-bit C integer.
///
/// This type exists solely to make the exported helper ABI explicit. It is not
/// a general public arithmetic API.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uint128 {
    pub lo: u64,
    pub hi: u64,
}

/// The selected target ABI floating aggregate representation of C
/// ``double _Complex``.
///
/// The compiler helper ABI passes the real and imaginary components in the
/// same floating-point registers as this two-`f64` C layout. It exists only
/// for `__muldc3`; it is not a general complex-number API.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ComplexDouble {
    pub real: f64,
    pub imaginary: f64,
}

/// Implement compiler-rt's IEEE recovery sequence for `(a + ib) * (c + id)`.
///
/// The ordinary four products use target floating-point instructions. The
/// NaN/infinity recovery preserves compiler-rt's observable C complex rules
/// without importing a compiler runtime or a general math library.
fn multiply_complex_double(mut a: f64, mut b: f64, mut c: f64, mut d: f64) -> ComplexDouble {
    let ac = a * c;
    let bd = b * d;
    let ad = a * d;
    let bc = b * c;
    let mut real = ac - bd;
    let mut imaginary = ad + bc;
    if real.is_nan() && imaginary.is_nan() {
        let mut recalculate = false;
        if a.is_infinite() || b.is_infinite() {
            a = (if a.is_infinite() { 1.0_f64 } else { 0.0_f64 }).copysign(a);
            b = (if b.is_infinite() { 1.0_f64 } else { 0.0_f64 }).copysign(b);
            if c.is_nan() {
                c = 0.0_f64.copysign(c);
            }
            if d.is_nan() {
                d = 0.0_f64.copysign(d);
            }
            recalculate = true;
        }
        if c.is_infinite() || d.is_infinite() {
            c = (if c.is_infinite() { 1.0_f64 } else { 0.0_f64 }).copysign(c);
            d = (if d.is_infinite() { 1.0_f64 } else { 0.0_f64 }).copysign(d);
            if a.is_nan() {
                a = 0.0_f64.copysign(a);
            }
            if b.is_nan() {
                b = 0.0_f64.copysign(b);
            }
            recalculate = true;
        }
        if !recalculate && (ac.is_infinite() || bd.is_infinite() || ad.is_infinite() || bc.is_infinite()) {
            if a.is_nan() {
                a = 0.0_f64.copysign(a);
            }
            if b.is_nan() {
                b = 0.0_f64.copysign(b);
            }
            if c.is_nan() {
                c = 0.0_f64.copysign(c);
            }
            if d.is_nan() {
                d = 0.0_f64.copysign(d);
            }
            recalculate = true;
        }
        if recalculate {
            real = f64::INFINITY * (a * c - b * d);
            imaginary = f64::INFINITY * (a * d + b * c);
        }
    }
    ComplexDouble { real, imaginary }
}

impl Uint128 {
    const ZERO: Self = Self { lo: 0, hi: 0 };
    const ONE: Self = Self { lo: 1, hi: 0 };

    #[inline]
    const fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    #[inline]
    const fn negative(self) -> bool {
        self.hi >> 63 != 0
    }

    #[inline]
    const fn bit(self, index: u32) -> bool {
        if index < 64 {
            ((self.lo >> index) & 1) != 0
        } else {
            ((self.hi >> (index - 64)) & 1) != 0
        }
    }

    #[inline]
    const fn with_bit(self, index: u32) -> Self {
        if index < 64 {
            Self {
                lo: self.lo | (1_u64 << index),
                hi: self.hi,
            }
        } else {
            Self {
                lo: self.lo,
                hi: self.hi | (1_u64 << (index - 64)),
            }
        }
    }

    #[inline]
    const fn cmp_unsigned(self, other: Self) -> core::cmp::Ordering {
        if self.hi < other.hi {
            core::cmp::Ordering::Less
        } else if self.hi > other.hi {
            core::cmp::Ordering::Greater
        } else if self.lo < other.lo {
            core::cmp::Ordering::Less
        } else if self.lo > other.lo {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    }

    #[inline]
    const fn add(self, other: Self) -> Self {
        let (lo, carry) = self.lo.overflowing_add(other.lo);
        Self {
            lo,
            hi: self.hi.wrapping_add(other.hi).wrapping_add(carry as u64),
        }
    }

    #[inline]
    const fn sub(self, other: Self) -> Self {
        let (lo, borrow) = self.lo.overflowing_sub(other.lo);
        Self {
            lo,
            hi: self.hi.wrapping_sub(other.hi).wrapping_sub(borrow as u64),
        }
    }

    #[inline]
    const fn negate(self) -> Self {
        Self {
            lo: !self.lo,
            hi: !self.hi,
        }
        .add(Self::ONE)
    }

    #[inline]
    const fn shl(self, shift: u32) -> Self {
        if shift >= 128 {
            Self::ZERO
        } else if shift >= 64 {
            Self {
                lo: 0,
                hi: self.lo << (shift - 64),
            }
        } else if shift == 0 {
            self
        } else {
            Self {
                lo: self.lo << shift,
                hi: (self.hi << shift) | (self.lo >> (64 - shift)),
            }
        }
    }

    #[inline]
    const fn shr(self, shift: u32) -> Self {
        if shift >= 128 {
            Self::ZERO
        } else if shift >= 64 {
            Self {
                lo: self.hi >> (shift - 64),
                hi: 0,
            }
        } else if shift == 0 {
            self
        } else {
            Self {
                lo: (self.lo >> shift) | (self.hi << (64 - shift)),
                hi: self.hi >> shift,
            }
        }
    }

    #[inline]
    const fn sar(self, shift: u32) -> Self {
        if shift >= 128 {
            return if self.negative() {
                Self {
                    lo: u64::MAX,
                    hi: u64::MAX,
                }
            } else {
                Self::ZERO
            };
        }
        if shift >= 64 {
            return Self {
                lo: ((self.hi as i64) >> (shift - 64)) as u64,
                hi: if self.negative() { u64::MAX } else { 0 },
            };
        }
        if shift == 0 {
            return self;
        }
        Self {
            lo: (self.lo >> shift) | (self.hi << (64 - shift)),
            hi: ((self.hi as i64) >> shift) as u64,
        }
    }

    /// Returns `(low, high)` for a 64-bit product without using `u128`.
    #[inline]
    const fn mul_word(left: u64, right: u64) -> (u64, u64) {
        let left_low = left & 0xffff_ffff;
        let left_high = left >> 32;
        let right_low = right & 0xffff_ffff;
        let right_high = right >> 32;
        let low_low = left_low * right_low;
        let low_high = left_low * right_high;
        let high_low = left_high * right_low;
        let high_high = left_high * right_high;
        let middle = (low_low >> 32)
            .wrapping_add(low_high & 0xffff_ffff)
            .wrapping_add(high_low & 0xffff_ffff);
        (
            (low_low & 0xffff_ffff) | (middle << 32),
            high_high
                .wrapping_add(low_high >> 32)
                .wrapping_add(high_low >> 32)
                .wrapping_add(middle >> 32),
        )
    }

    #[inline]
    const fn mul(self, other: Self) -> Self {
        let (lo, high) = Self::mul_word(self.lo, other.lo);
        Self {
            lo,
            hi: high
                .wrapping_add(self.lo.wrapping_mul(other.hi))
                .wrapping_add(self.hi.wrapping_mul(other.lo)),
        }
    }

    fn add_limb(words: &mut [u64; 4], mut index: usize, mut value: u64) {
        while value != 0 && index < words.len() {
            let (sum, carry) = words[index].overflowing_add(value);
            words[index] = sum;
            value = carry as u64;
            index += 1;
        }
    }

    /// Returns the full 256-bit unsigned product in little-endian limbs.
    fn mul_wide(self, other: Self) -> [u64; 4] {
        let mut words = [0_u64; 4];
        let (lo, hi) = Self::mul_word(self.lo, other.lo);
        Self::add_limb(&mut words, 0, lo);
        Self::add_limb(&mut words, 1, hi);
        let (lo, hi) = Self::mul_word(self.lo, other.hi);
        Self::add_limb(&mut words, 1, lo);
        Self::add_limb(&mut words, 2, hi);
        let (lo, hi) = Self::mul_word(self.hi, other.lo);
        Self::add_limb(&mut words, 1, lo);
        Self::add_limb(&mut words, 2, hi);
        let (lo, hi) = Self::mul_word(self.hi, other.hi);
        Self::add_limb(&mut words, 2, lo);
        Self::add_limb(&mut words, 3, hi);
        words
    }

    fn negate_wide(words: &mut [u64; 4]) {
        for word in words.iter_mut() {
            *word = !*word;
        }
        Self::add_limb(words, 0, 1);
    }

    fn mul_signed_overflow(self, other: Self) -> (Self, bool) {
        let negative = self.negative() != other.negative();
        let left = if self.negative() { self.negate() } else { self };
        let right = if other.negative() { other.negate() } else { other };
        let mut product = left.mul_wide(right);
        if negative {
            Self::negate_wide(&mut product);
        }
        let result = Self {
            lo: product[0],
            hi: product[1],
        };
        let extension = if result.negative() { u64::MAX } else { 0 };
        (result, product[2] != extension || product[3] != extension)
    }

    /// Performs unsigned long division without invoking a 128-bit operation.
    fn divmod_unsigned(numerator: Self, denominator: Self) -> (Self, Self) {
        if denominator.is_zero() {
            // Division by zero is undefined in the source language. Keep this
            // leaf total so it cannot panic or pull a panic runtime into the
            // archive; callers must not treat this result as a defined ABI.
            return (Self::ZERO, Self::ZERO);
        }
        if numerator.cmp_unsigned(denominator).is_lt() {
            return (Self::ZERO, numerator);
        }
        if denominator.hi >> 63 != 0 {
            return (Self::ONE, numerator.sub(denominator));
        }

        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        let mut bit = 128_u32;
        while bit != 0 {
            bit -= 1;
            remainder = remainder.shl(1);
            if numerator.bit(bit) {
                remainder.lo |= 1;
            }
            if !remainder.cmp_unsigned(denominator).is_lt() {
                remainder = remainder.sub(denominator);
                quotient = quotient.with_bit(bit);
            }
        }
        (quotient, remainder)
    }

    fn divmod_signed(numerator: Self, denominator: Self) -> (Self, Self) {
        let numerator_negative = numerator.negative();
        let denominator_negative = denominator.negative();
        let unsigned_numerator = if numerator_negative {
            numerator.negate()
        } else {
            numerator
        };
        let unsigned_denominator = if denominator_negative {
            denominator.negate()
        } else {
            denominator
        };
        let (mut quotient, mut remainder) =
            Self::divmod_unsigned(unsigned_numerator, unsigned_denominator);
        if numerator_negative != denominator_negative {
            quotient = quotient.negate();
        }
        if numerator_negative {
            remainder = remainder.negate();
        }
        (quotient, remainder)
    }
}

#[inline]
fn write_remainder(output: *mut Uint128, remainder: Uint128) {
    // SAFETY: __*divmodti4 follows compiler-rt's C ABI: its third argument is
    // a non-null, writable pointer to one Uint128 result slot owned by caller.
    unsafe { output.write(remainder) };
}

#[unsafe(no_mangle)]
pub extern "C" fn __multi3(left: Uint128, right: Uint128) -> Uint128 {
    left.mul(right)
}

#[unsafe(no_mangle)]
pub extern "C" fn __muldc3(a: f64, b: f64, c: f64, d: f64) -> ComplexDouble {
    multiply_complex_double(a, b, c, d)
}

#[unsafe(no_mangle)]
pub extern "C" fn __udivti3(numerator: Uint128, denominator: Uint128) -> Uint128 {
    Uint128::divmod_unsigned(numerator, denominator).0
}

#[unsafe(no_mangle)]
pub extern "C" fn __umodti3(numerator: Uint128, denominator: Uint128) -> Uint128 {
    Uint128::divmod_unsigned(numerator, denominator).1
}

/// # Safety
///
/// `remainder` must point to writable storage for one `Uint128`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __udivmodti4(
    numerator: Uint128,
    denominator: Uint128,
    remainder: *mut Uint128,
) -> Uint128 {
    let (quotient, value) = Uint128::divmod_unsigned(numerator, denominator);
    write_remainder(remainder, value);
    quotient
}

#[unsafe(no_mangle)]
pub extern "C" fn __divti3(numerator: Uint128, denominator: Uint128) -> Uint128 {
    Uint128::divmod_signed(numerator, denominator).0
}

#[unsafe(no_mangle)]
pub extern "C" fn __modti3(numerator: Uint128, denominator: Uint128) -> Uint128 {
    Uint128::divmod_signed(numerator, denominator).1
}

/// # Safety
///
/// `remainder` must point to writable storage for one `Uint128`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __divmodti4(
    numerator: Uint128,
    denominator: Uint128,
    remainder: *mut Uint128,
) -> Uint128 {
    let (quotient, value) = Uint128::divmod_signed(numerator, denominator);
    write_remainder(remainder, value);
    quotient
}

#[unsafe(no_mangle)]
pub extern "C" fn __ashlti3(value: Uint128, shift: i32) -> Uint128 {
    value.shl(shift as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn __lshrti3(value: Uint128, shift: i32) -> Uint128 {
    value.shr(shift as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn __ashrti3(value: Uint128, shift: i32) -> Uint128 {
    value.sar(shift as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn __clzti2(value: Uint128) -> i32 {
    if value.hi != 0 {
        value.hi.leading_zeros() as i32
    } else {
        (64 + value.lo.leading_zeros()) as i32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __ctzti2(value: Uint128) -> i32 {
    if value.lo != 0 {
        value.lo.trailing_zeros() as i32
    } else {
        (64 + value.hi.trailing_zeros()) as i32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __ffsti2(value: Uint128) -> i32 {
    if value.is_zero() {
        0
    } else {
        __ctzti2(value) + 1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __popcountti2(value: Uint128) -> i32 {
    (value.lo.count_ones() + value.hi.count_ones()) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn __parityti2(value: Uint128) -> i32 {
    __popcountti2(value) & 1
}

#[unsafe(no_mangle)]
pub extern "C" fn __bswapsi2(value: u32) -> u32 {
    value.swap_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn __bswapdi2(value: u64) -> u64 {
    value.swap_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn __bswapti2(value: Uint128) -> Uint128 {
    Uint128 {
        lo: value.hi.swap_bytes(),
        hi: value.lo.swap_bytes(),
    }
}

/// # Safety
///
/// `overflow` must point to writable storage for one C `int` represented by
/// Rust's ABI-compatible `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __addoti4(left: Uint128, right: Uint128, overflow: *mut i32) -> Uint128 {
    let result = left.add(right);
    let did_overflow = ((left.hi ^ result.hi) & (right.hi ^ result.hi)) >> 63 != 0;
    // SAFETY: the ABI contract documented above gives caller ownership of one
    // writable i32 slot at overflow.
    unsafe { overflow.write(did_overflow as i32) };
    result
}

/// # Safety
///
/// `overflow` must point to writable storage for one C `int` represented by
/// Rust's ABI-compatible `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __suboti4(left: Uint128, right: Uint128, overflow: *mut i32) -> Uint128 {
    let result = left.sub(right);
    let did_overflow = ((left.hi ^ right.hi) & (left.hi ^ result.hi)) >> 63 != 0;
    // SAFETY: the ABI contract documented above gives caller ownership of one
    // writable i32 slot at overflow.
    unsafe { overflow.write(did_overflow as i32) };
    result
}

/// # Safety
///
/// `overflow` must point to writable storage for one C `int` represented by
/// Rust's ABI-compatible `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __muloti4(left: Uint128, right: Uint128, overflow: *mut i32) -> Uint128 {
    let (result, did_overflow) = left.mul_signed_overflow(right);
    // SAFETY: the ABI contract documented above gives caller ownership of one
    // writable i32 slot at overflow.
    unsafe { overflow.write(did_overflow as i32) };
    result
}

#[cfg(test)]
mod tests {
    use super::{
        ComplexDouble, Uint128, __ashlti3, __ashrti3, __divti3, __lshrti3, __modti3, __muldc3,
        __multi3, __udivti3, __umodti3,
    };

    fn words(value: u128) -> Uint128 {
        Uint128 {
            lo: value as u64,
            hi: (value >> 64) as u64,
        }
    }

    fn value(words: Uint128) -> u128 {
        ((words.hi as u128) << 64) | words.lo as u128
    }

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 7;
        *state ^= *state >> 9;
        *state ^= *state << 8;
        *state
    }

    #[test]
    fn multiplication_matches_u128_low_half() {
        let mut state = 0xa0_6400_0000_0001_u64;
        for _ in 0..1_000 {
            let left = ((next(&mut state) as u128) << 64) | next(&mut state) as u128;
            let right = ((next(&mut state) as u128) << 64) | next(&mut state) as u128;
            assert_eq!(value(__multi3(words(left), words(right))), left.wrapping_mul(right));
        }
    }

    #[test]
    fn unsigned_division_and_remainder_match_u128() {
        let mut state = 0xa0_6400_0000_0002_u64;
        for _ in 0..1_000 {
            let numerator = ((next(&mut state) as u128) << 64) | next(&mut state) as u128;
            let mut denominator = ((next(&mut state) as u128) << 64) | next(&mut state) as u128;
            if denominator == 0 {
                denominator = 1;
            }
            assert_eq!(value(__udivti3(words(numerator), words(denominator))), numerator / denominator);
            assert_eq!(value(__umodti3(words(numerator), words(denominator))), numerator % denominator);
        }
    }

    #[test]
    fn signed_division_and_remainder_match_i128_except_source_ub() {
        let mut state = 0xa0_6400_0000_0003_u64;
        for _ in 0..1_000 {
            let numerator = (((next(&mut state) as u128) << 64) | next(&mut state) as u128) as i128;
            let mut denominator = (((next(&mut state) as u128) << 64) | next(&mut state) as u128) as i128;
            if denominator == 0 {
                denominator = 1;
            }
            if numerator == i128::MIN && denominator == -1 {
                continue;
            }
            assert_eq!(value(__divti3(words(numerator as u128), words(denominator as u128))) as i128, numerator / denominator);
            assert_eq!(value(__modti3(words(numerator as u128), words(denominator as u128))) as i128, numerator % denominator);
        }
    }

    #[test]
    fn shifts_cover_word_and_value_boundaries() {
        let input_value = 0x8123_4567_89ab_cdef_0123_4567_89ab_cdef_u128;
        let input = words(input_value);
        for shift in [0_i32, 1, 63, 64, 65, 127, 128, 129] {
            let expected_left = if shift >= 128 { 0 } else { input_value << shift };
            let expected_right = if shift >= 128 { 0 } else { input_value >> shift };
            let expected_arithmetic = if shift >= 128 {
                -1
            } else {
                (input_value as i128) >> shift
            };
            assert_eq!(value(__ashlti3(input, shift)), expected_left);
            assert_eq!(value(__lshrti3(input, shift)), expected_right);
            assert_eq!(value(__ashrti3(input, shift)) as i128, expected_arithmetic);
        }
    }

    #[test]
    fn double_complex_multiply_preserves_real_and_imaginary_components() {
        assert_eq!(
            __muldc3(3.0, 4.0, 3.0, 4.0),
            ComplexDouble {
                real: -7.0,
                imaginary: 24.0,
            }
        );
        let infinite = __muldc3(f64::INFINITY, 1.0, 2.0, 3.0);
        assert!(infinite.real.is_infinite());
        assert!(infinite.imaginary.is_infinite());
    }
}
