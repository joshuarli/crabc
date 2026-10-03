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

// Rust has no binary80 scalar ABI. These reviewed assembly entries receive
// padded binary80 stack arguments and return scalar/complex values in ST0 or
// ST0/ST1, while integer128 arguments and results use the integer register pair.
#[cfg(target_arch = "x86_64")]
mod x86_64_binary80;

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
/// for the complex compiler helpers; it is not a general complex-number API.
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

// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Adapted from LLVM compiler-rt 22.1.3 binary64 complex division.
// LLVM compiler-rt's binary64 scaling avoids libc calls and preserves the
// target rounding and underflow behavior through floating-point products.
#[cfg(target_arch = "x86_64")]
fn complex_division_normalize(significand: &mut u64) -> i32 {
    let shift = significand.leading_zeros() as i32 - (1_u64 << 52).leading_zeros() as i32;
    *significand <<= shift;
    1 - shift
}

#[cfg(target_arch = "x86_64")]
fn complex_division_logb(value: f64) -> f64 {
    let mut representation = value.to_bits();
    let exponent = ((representation >> 52) & 0x7ff) as i32;
    if exponent == 0x7ff {
        if representation >> 63 == 0 || value.is_nan() { value } else { -value }
    } else if value == 0.0 {
        f64::NEG_INFINITY
    } else if exponent != 0 {
        (exponent - 1023) as f64
    } else {
        representation &= 0x7fff_ffff_ffff_ffff;
        let shift = 1 - complex_division_normalize(&mut representation);
        let normalized_exponent = ((representation >> 52) & 0x7ff) as i32;
        (normalized_exponent - 1023 - shift) as f64
    }
}

#[cfg(target_arch = "x86_64")]
fn complex_division_scalbn(value: f64, scale: i32) -> f64 {
    let representation = value.to_bits();
    let mut exponent = ((representation >> 52) & 0x7ff) as i32;
    if value == 0.0 || exponent == 0x7ff {
        return value;
    }
    let mut significand = representation & 0x000f_ffff_ffff_ffff;
    if exponent == 0 {
        exponent += complex_division_normalize(&mut significand);
        significand &= !(1_u64 << 52);
    }
    exponent = exponent.saturating_add(scale);
    let sign = representation & (1_u64 << 63);
    if exponent >= 0x7ff {
        f64::from_bits(sign | (0x7fe_u64 << 52)) * 2.0
    } else if exponent <= 0 {
        let mut temporary = f64::from_bits(sign | (1_u64 << 52) | significand);
        exponent = exponent.saturating_add(1022).max(1);
        temporary *= f64::from_bits((exponent as u64) << 52);
        temporary
    } else {
        f64::from_bits(sign | ((exponent as u64) << 52) | significand)
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64_complex_classification;
#[cfg(target_arch = "x86_64")]
use x86_64_complex_classification::{
    complex_division_is_finite, complex_division_is_infinite, complex_division_is_nan,
    complex_division_ordered_less,
};

// Scaling the divisor first keeps its squared magnitude representable.
// The recovery branches distinguish zero divisors, infinite numerators, and
// infinite divisors only when both ordinary result components are NaN.
#[cfg(target_arch = "x86_64")]
fn divide_complex_double(mut a: f64, mut b: f64, mut c: f64, mut d: f64) -> ComplexDouble {
    let abs_c = c.abs();
    let abs_d = d.abs();
    let maximum = if complex_division_is_nan(abs_c) ||
        complex_division_ordered_less(abs_c, abs_d) { abs_d } else { abs_c };
    let logbw = complex_division_logb(maximum);
    let mut ilogbw = 0;
    if complex_division_is_finite(logbw) {
        ilogbw = logbw as i32;
        c = complex_division_scalbn(c, -ilogbw);
        d = complex_division_scalbn(d, -ilogbw);
    }
    let denominator = c * c + d * d;
    let mut real = complex_division_scalbn((a * c + b * d) / denominator, -ilogbw);
    let mut imaginary = complex_division_scalbn((b * c - a * d) / denominator, -ilogbw);
    if complex_division_is_nan(real) && complex_division_is_nan(imaginary) {
        if denominator == 0.0 && (!complex_division_is_nan(a) || !complex_division_is_nan(b)) {
            real = f64::INFINITY.copysign(c) * a;
            imaginary = f64::INFINITY.copysign(c) * b;
        } else if (complex_division_is_infinite(a) || complex_division_is_infinite(b)) && complex_division_is_finite(c) && complex_division_is_finite(d) {
            a = (if complex_division_is_infinite(a) { 1.0_f64 } else { 0.0_f64 }).copysign(a);
            b = (if complex_division_is_infinite(b) { 1.0_f64 } else { 0.0_f64 }).copysign(b);
            real = f64::INFINITY * (a * c + b * d);
            imaginary = f64::INFINITY * (b * c - a * d);
        } else if complex_division_is_infinite(logbw) && logbw > 0.0 && complex_division_is_finite(a) && complex_division_is_finite(b) {
            c = (if complex_division_is_infinite(c) { 1.0_f64 } else { 0.0_f64 }).copysign(c);
            d = (if complex_division_is_infinite(d) { 1.0_f64 } else { 0.0_f64 }).copysign(d);
            real = 0.0 * (a * c + b * d);
            imaginary = 0.0 * (b * c - a * d);
        }
    }
    ComplexDouble { real, imaginary }
}

// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Adapted from LLVM compiler-rt 22.1.3 single-precision complex kernels.
/// The SysV AMD64 C float-complex return carrier.
/// Both binary32 components share the low eight bytes of XMM0.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ComplexFloat {
    pub real: f32,
    pub imaginary: f32,
}

#[cfg(target_arch = "x86_64")]
fn multiply_complex_float(mut a: f32, mut b: f32, mut c: f32, mut d: f32) -> ComplexFloat {
    let ac = a * c;
    let bd = b * d;
    let ad = a * d;
    let bc = b * c;
    let mut real = ac - bd;
    let mut imaginary = ad + bc;
    if float_complex_is_nan(real) && float_complex_is_nan(imaginary) {
        let mut recalculate = false;
        if float_complex_is_infinite(a) || float_complex_is_infinite(b) {
            a = (if float_complex_is_infinite(a) { 1.0_f32 } else { 0.0_f32 }).copysign(a);
            b = (if float_complex_is_infinite(b) { 1.0_f32 } else { 0.0_f32 }).copysign(b);
            if float_complex_is_nan(c) {
                c = 0.0_f32.copysign(c);
            }
            if float_complex_is_nan(d) {
                d = 0.0_f32.copysign(d);
            }
            recalculate = true;
        }
        if float_complex_is_infinite(c) || float_complex_is_infinite(d) {
            c = (if float_complex_is_infinite(c) { 1.0_f32 } else { 0.0_f32 }).copysign(c);
            d = (if float_complex_is_infinite(d) { 1.0_f32 } else { 0.0_f32 }).copysign(d);
            if float_complex_is_nan(a) {
                a = 0.0_f32.copysign(a);
            }
            if float_complex_is_nan(b) {
                b = 0.0_f32.copysign(b);
            }
            recalculate = true;
        }
        if !recalculate && (float_complex_is_infinite(ac) || float_complex_is_infinite(bd) || float_complex_is_infinite(ad) || float_complex_is_infinite(bc)) {
            if float_complex_is_nan(a) {
                a = 0.0_f32.copysign(a);
            }
            if float_complex_is_nan(b) {
                b = 0.0_f32.copysign(b);
            }
            if float_complex_is_nan(c) {
                c = 0.0_f32.copysign(c);
            }
            if float_complex_is_nan(d) {
                d = 0.0_f32.copysign(d);
            }
            recalculate = true;
        }
        if recalculate {
            real = f32::INFINITY * (a * c - b * d);
            imaginary = f32::INFINITY * (a * d + b * c);
        }
    }
    ComplexFloat { real, imaginary }
}

#[cfg(target_arch = "x86_64")]
fn float_complex_division_normalize(significand: &mut u32) -> i32 {
    let shift = significand.leading_zeros() as i32 - (1_u32 << 23).leading_zeros() as i32;
    *significand <<= shift;
    1 - shift
}

#[cfg(target_arch = "x86_64")]
fn float_complex_division_logb(value: f32) -> f32 {
    let mut representation = value.to_bits();
    let exponent = ((representation >> 23) & 0xff) as i32;
    if exponent == 0xff {
        if representation >> 31 == 0 || value.is_nan() { value } else { -value }
    } else if value == 0.0 {
        f32::NEG_INFINITY
    } else if exponent != 0 {
        (exponent - 127) as f32
    } else {
        representation &= 0x7fff_ffff;
        let shift = 1 - float_complex_division_normalize(&mut representation);
        let normalized_exponent = ((representation >> 23) & 0xff) as i32;
        (normalized_exponent - 127 - shift) as f32
    }
}

#[cfg(target_arch = "x86_64")]
fn float_complex_division_scalbn(value: f32, scale: i32) -> f32 {
    let representation = value.to_bits();
    let mut exponent = ((representation >> 23) & 0xff) as i32;
    if value == 0.0 || exponent == 0xff {
        return value;
    }
    let mut significand = representation & 0x007f_ffff;
    if exponent == 0 {
        exponent += float_complex_division_normalize(&mut significand);
        significand &= !(1_u32 << 23);
    }
    exponent = exponent.saturating_add(scale);
    let sign = representation & (1_u32 << 31);
    if exponent >= 0xff {
        f32::from_bits(sign | (0xfe_u32 << 23)) * 2.0
    } else if exponent <= 0 {
        let mut temporary = f32::from_bits(sign | (1_u32 << 23) | significand);
        exponent = exponent.saturating_add(126).max(1);
        temporary *= f32::from_bits((exponent as u32) << 23);
        temporary
    } else {
        f32::from_bits(sign | ((exponent as u32) << 23) | significand)
    }
}

#[cfg(target_arch = "x86_64")]
use x86_64_complex_classification::{
    float_complex_is_finite, float_complex_is_infinite,
    float_complex_is_nan, float_complex_ordered_less,
};

#[cfg(target_arch = "x86_64")]
fn divide_complex_float(mut a: f32, mut b: f32, mut c: f32, mut d: f32) -> ComplexFloat {
    let abs_c = c.abs();
    let abs_d = d.abs();
    let maximum = if float_complex_is_nan(abs_c) ||
        float_complex_ordered_less(abs_c, abs_d) { abs_d } else { abs_c };
    let logbw = float_complex_division_logb(maximum);
    let mut ilogbw = 0;
    if float_complex_is_finite(logbw) {
        ilogbw = logbw as i32;
        c = float_complex_division_scalbn(c, -ilogbw);
        d = float_complex_division_scalbn(d, -ilogbw);
    }
    let denominator = c * c + d * d;
    let mut real = float_complex_division_scalbn((a * c + b * d) / denominator, -ilogbw);
    let imaginary_quotient = (b * c - a * d) / denominator;
    let mut imaginary = float_complex_division_scalbn(imaginary_quotient, -ilogbw);
    // Scaling a zero quotient returns that zero unchanged, so recovery
    // cannot apply. Preserve the pinned C compiler's short circuit here:
    // reading a subnormal real result would add a denormal exception.
    if imaginary_quotient.to_bits() & 0x7fff_ffff != 0 &&
        float_complex_is_nan(real) && float_complex_is_nan(imaginary) {
        if denominator == 0.0 && (!float_complex_is_nan(a) || !float_complex_is_nan(b)) {
            real = f32::INFINITY.copysign(c) * a;
            imaginary = f32::INFINITY.copysign(c) * b;
        } else if (float_complex_is_infinite(a) || float_complex_is_infinite(b)) && float_complex_is_finite(c) && float_complex_is_finite(d) {
            a = (if float_complex_is_infinite(a) { 1.0_f32 } else { 0.0_f32 }).copysign(a);
            b = (if float_complex_is_infinite(b) { 1.0_f32 } else { 0.0_f32 }).copysign(b);
            real = f32::INFINITY * (a * c + b * d);
            imaginary = f32::INFINITY * (b * c - a * d);
        } else if float_complex_is_infinite(logbw) && logbw > 0.0 && float_complex_is_finite(a) && float_complex_is_finite(b) {
            c = (if float_complex_is_infinite(c) { 1.0_f32 } else { 0.0_f32 }).copysign(c);
            d = (if float_complex_is_infinite(d) { 1.0_f32 } else { 0.0_f32 }).copysign(d);
            real = 0.0 * (a * c + b * d);
            imaginary = 0.0 * (b * c - a * d);
        }
    }
    ComplexFloat { real, imaginary }
}

/// Return `(a + ib) * (c + id)` using the SysV AMD64 float-complex ABI.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __mulsc3(a: f32, b: f32, c: f32, d: f32) -> ComplexFloat {
    multiply_complex_float(a, b, c, d)
}

/// Return `(a + ib) / (c + id)` using the SysV AMD64 float-complex ABI.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __divsc3(a: f32, b: f32, c: f32, d: f32) -> ComplexFloat {
    divide_complex_float(a, b, c, d)
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
    // SAFETY: callers use this writer only for a non-null, aligned pointer
    // to one writable Uint128 result slot owned by the caller.
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

/// Return `(a + ib) / (c + id)` using the compiler's binary64 complex ABI.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __divdc3(a: f64, b: f64, c: f64, d: f64) -> ComplexDouble {
    divide_complex_double(a, b, c, d)
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
/// `denominator` must be nonzero. On x86-64, `remainder` may be null to
/// request only the quotient. Otherwise it must point to aligned writable
/// storage for one `Uint128`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __udivmodti4(
    numerator: Uint128,
    denominator: Uint128,
    remainder: *mut Uint128,
) -> Uint128 {
    let (quotient, value) = Uint128::divmod_unsigned(numerator, denominator);
    // The unsigned x86 compiler-helper ABI permits a quotient-only call.
    // The signed sibling still requires its output slot.
    #[cfg(target_arch = "x86_64")]
    if remainder.is_null() {
        return quotient;
    }
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

/// GCC's x86-64 population-count ABI used by the accepted C allocator.
///
/// Keep this in the owned helper archive so baseline CPUs without POPCNT do
/// not import libgcc. The existing 128-bit helper uses the same LLVM primitive.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __popcountdi2(value: u64) -> i32 {
    value.count_ones() as i32
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

// Binary64 conversions use the compiler-builtins integer conversion branches.
// Two-word shifts preserve their integer bit operations without recursively
// requesting these same compiler helpers. Rounded mantissas can carry into
// the exponent; addition of the fields is therefore intentional.
#[cfg(target_arch = "x86_64")]
fn uint128_to_binary64_bits(value: Uint128) -> u64 {
    let leading = __clzti2(value) as u32;
    let normalized = value.shl(leading);
    let base = normalized.shr(75).lo;
    let dropped = normalized.shr(11).lo | (normalized.lo & 0xffff_ffff);
    let adjustment = dropped.wrapping_sub((dropped >> 63) & !base) >> 63;
    let exponent = if value.is_zero() { 0 } else { 1149 - leading as u64 };
    (exponent << 52) + base + adjustment
}

// The source conversion truncates finite in-range values, saturates infinities
// and overflow, and maps NaNs to zero. Unsigned conversion keeps the sign bit
// in its range comparison, making every negative input return zero. These
// total source branches do not make out-of-range C casts defined.
#[cfg(target_arch = "x86_64")]
fn binary64_to_uint128(value: f64, signed: bool) -> Uint128 {
    let original = value.to_bits();
    let negative = original >> 63 != 0;
    let bits = if signed { original & 0x7fff_ffff_ffff_ffff } else { original };
    let limit = if signed { 1150_u64 } else { 1151_u64 };
    if bits < 0x3ff0_0000_0000_0000 {
        Uint128::ZERO
    } else if bits < limit << 52 {
        let mantissa = Uint128 { lo: bits, hi: 0 }.shl(75);
        let mantissa = Uint128 { lo: mantissa.lo, hi: mantissa.hi | (1 << 63) };
        let magnitude = mantissa.shr((1150 - (bits >> 52)) as u32);
        if signed && negative { magnitude.negate() } else { magnitude }
    } else if bits <= 0x7ff0_0000_0000_0000 {
        if !signed { Uint128 { lo: u64::MAX, hi: u64::MAX } }
        else if negative { Uint128 { lo: 0, hi: 1 << 63 } }
        else { Uint128 { lo: u64::MAX, hi: (1 << 63) - 1 } }
    } else {
        Uint128::ZERO
    }
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __floatuntidf(value: Uint128) -> f64 {
    f64::from_bits(uint128_to_binary64_bits(value))
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __floattidf(value: Uint128) -> f64 {
    let magnitude = if value.negative() { value.negate() } else { value };
    f64::from_bits(uint128_to_binary64_bits(magnitude) | (value.hi & (1 << 63)))
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __fixdfti(value: f64) -> Uint128 {
    binary64_to_uint128(value, true)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __fixunsdfti(value: f64) -> Uint128 {
    binary64_to_uint128(value, false)
}

// Compress only the bits discarded by the binary32 mantissa. The low 96
// normalized bits contribute a sticky bit, preserving ties-to-even without
// an intermediate floating conversion or a recursively emitted cast helper.
#[cfg(target_arch = "x86_64")]
fn uint128_to_binary32_bits(value: Uint128) -> u32 {
    let leading = __clzti2(value) as u32;
    let normalized = value.shl(leading);
    let base = normalized.shr(104).lo as u32;
    let dropped_high = normalized.shr(72).lo as u32;
    let sticky = (normalized.lo != 0 || normalized.hi & 0xffff_ffff != 0) as u32;
    let dropped = dropped_high | sticky;
    let adjustment = dropped.wrapping_sub((dropped >> 31) & !base) >> 31;
    let exponent = if value.is_zero() { 0 } else { 253 - leading };
    // Addition permits a rounded mantissa to carry into the exponent,
    // including rounding the largest unsigned integers to positive infinity.
    (exponent << 23) + base + adjustment
}

// These total compiler-helper branches truncate in-range values, saturate
// overflow and infinities, and map NaNs to zero. They do not extend the valid
// domain of C casts. Keeping the unsigned sign bit maps negatives to zero.
#[cfg(target_arch = "x86_64")]
fn binary32_to_uint128(value: f32, signed: bool) -> Uint128 {
    let original = value.to_bits();
    let negative = original >> 31 != 0;
    let bits = if signed { original & 0x7fff_ffff } else { original };
    let limit = if signed { 254_u32 } else { 255_u32 };
    if bits < 0x3f80_0000 {
        Uint128::ZERO
    } else if bits < limit << 23 {
        let mantissa = Uint128 { lo: bits as u64, hi: 0 }.shl(104);
        let mantissa = Uint128 { lo: mantissa.lo, hi: mantissa.hi | (1 << 63) };
        let magnitude = mantissa.shr(254 - (bits >> 23));
        if signed && negative { magnitude.negate() } else { magnitude }
    } else if bits <= 0x7f80_0000 {
        if !signed { Uint128 { lo: u64::MAX, hi: u64::MAX } }
        else if negative { Uint128 { lo: 0, hi: 1 << 63 } }
        else { Uint128 { lo: u64::MAX, hi: (1 << 63) - 1 } }
    } else {
        Uint128::ZERO
    }
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __floatuntisf(value: Uint128) -> f32 {
    f32::from_bits(uint128_to_binary32_bits(value))
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __floattisf(value: Uint128) -> f32 {
    let magnitude = if value.negative() { value.negate() } else { value };
    f32::from_bits(uint128_to_binary32_bits(magnitude) | ((value.hi >> 32) as u32 & (1 << 31)))
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __fixsfti(value: f32) -> Uint128 {
    binary32_to_uint128(value, true)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn __fixunssfti(value: f32) -> Uint128 {
    binary32_to_uint128(value, false)
}

#[cfg(test)]
mod tests {
    use super::{
        ComplexDouble, Uint128, __ashlti3, __ashrti3, __divti3, __lshrti3, __modti3, __muldc3,
        __multi3, __udivti3, __umodti3,
    };

    #[cfg(target_arch = "x86_64")]
    use super::{__divdc3, complex_division_scalbn};

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn double_complex_division_scales_subnormal_divisors_without_losing_the_quotient() {
        assert_eq!(__divdc3(3.0, 4.0, 1.0, 2.0),
            ComplexDouble { real: 2.2, imaginary: -0.4 });
        for value in [f64::MIN_POSITIVE, f64::from_bits(1), f64::from_bits(0x000f_ffff_ffff_ffff)] {
            assert_eq!(__divdc3(value, 0.0, value, 0.0),
                ComplexDouble { real: 1.0, imaginary: 0.0 });
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn double_complex_division_recovers_zero_and_infinite_divisor_signs() {
        let zero_divisor = __divdc3(3.0, 4.0, -0.0, 0.0);
        assert_eq!(zero_divisor.real, f64::NEG_INFINITY);
        assert_eq!(zero_divisor.imaginary, f64::NEG_INFINITY);
        let infinite_divisor = __divdc3(3.0, 4.0, f64::NEG_INFINITY, f64::INFINITY);
        assert_eq!(infinite_divisor.real.to_bits(), 0.0_f64.to_bits());
        assert_eq!(infinite_divisor.imaginary.to_bits(), (-0.0_f64).to_bits());
        let infinite_numerator = __divdc3(f64::INFINITY, f64::INFINITY, 1.0, 0.0);
        assert_eq!(infinite_numerator.real, f64::INFINITY);
        assert_eq!(infinite_numerator.imaginary, f64::INFINITY);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn complex_division_scaling_preserves_ieee_boundary_representations() {
        assert_eq!(complex_division_scalbn(f64::MIN_POSITIVE, -52).to_bits(), 1);
        assert_eq!(complex_division_scalbn(f64::from_bits(1), 1074), 1.0);
        assert_eq!(complex_division_scalbn(-0.0, 1024).to_bits(), (-0.0_f64).to_bits());
        assert_eq!(complex_division_scalbn(f64::MAX, 1), f64::INFINITY);
    }

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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn allocator_population_count_helper_matches_bitwise_count() {
        for shift in 0..64 {
            for input in [0, u64::MAX, 1 << shift, !(1 << shift), 0x5555_aaaa_3333_cccc] {
                let expected = (0..64).map(|bit| ((input >> bit) & 1) as i32).sum::<i32>();
                assert_eq!(super::__popcountdi2(input), expected);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn binary64_casts_preserve_total_source_range_and_nan_branches() {
        let unsigned_max = Uint128 { lo: u64::MAX, hi: u64::MAX };
        let signed_max = Uint128 { lo: u64::MAX, hi: (1 << 63) - 1 };
        let signed_min = Uint128 { lo: 0, hi: 1 << 63 };
        for input in [f64::NAN, f64::from_bits(0xfff0_0000_0000_0001)] {
            assert_eq!(super::__fixdfti(input), Uint128::ZERO);
            assert_eq!(super::__fixunsdfti(input), Uint128::ZERO);
        }
        for input in [f64::INFINITY, f64::from_bits(0x47e0_0000_0000_0000)] {
            assert_eq!(super::__fixdfti(input), signed_max);
        }
        for input in [f64::NEG_INFINITY, -f64::from_bits(0x47e0_0000_0000_0000)] {
            assert_eq!(super::__fixdfti(input), signed_min);
            assert_eq!(super::__fixunsdfti(input), Uint128::ZERO);
        }
        assert_eq!(super::__fixunsdfti(f64::INFINITY), unsigned_max);
        assert_eq!(super::__fixunsdfti(f64::from_bits(0x47f0_0000_0000_0000)), unsigned_max);
        assert_eq!(super::__floatuntidf(unsigned_max).to_bits(), 0x47f0_0000_0000_0000);
        assert_eq!(super::__floattidf(signed_min).to_bits(), 0xc7e0_0000_0000_0000);
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn unsigned_divmod_accepts_null_remainder_for_quotient_only() {
        let maximum = Uint128 { lo: u64::MAX, hi: u64::MAX };
        for (numerator, denominator, expected) in [
            (Uint128::ZERO, words(7), Uint128::ZERO),
            (words(7), words(3), words(2)),
            (words(3), words(7), Uint128::ZERO),
            (maximum, words(3), Uint128 { lo: 0x5555_5555_5555_5555, hi: 0x5555_5555_5555_5555 }),
            (maximum, Uint128 { lo: 0, hi: 1 << 63 }, Uint128::ONE),
            (Uint128 { lo: 5, hi: 1 }, Uint128 { lo: 0, hi: 1 }, Uint128::ONE),
        ] {
            // SAFETY: all divisors are nonzero; the unsigned x86 helper's
            // null remainder requests a quotient without an output write.
            let quotient = unsafe { super::__udivmodti4(numerator, denominator, core::ptr::null_mut()) };
            assert_eq!(quotient, expected);
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
