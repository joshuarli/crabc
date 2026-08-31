//! Selected static Linux/x86-64 `fmod`/`fmodf` C ABI leaf.
//!
//! This target-private Rust mapping follows pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/math/fmod.c` maps to [`fmod`];
//! - `src/math/fmodf.c` maps to [`fmodf`].
//!
//! Musl reduces raw IEEE significands by normalization, repeated unsigned
//! subtraction, and rescaling.  The source's invalid-domain expression stays
//! deliberately arithmetic here: zero divisors, infinite `x`, and signaling
//! NaNs take `(x * y) / (x * y)`, which preserves musl's `FE_INVALID` boundary.
//! Raw exponent/fraction classification avoids an accidental comparison before
//! that expression.  The ordinary integer reduction itself neither converts
//! nor changes the caller's MXCSR rounding mode.
//!
//! System V AMD64 passes binary64/binary32 `x` in `xmm0`, `y` in `xmm1`, and
//! returns through `xmm0`.  This leaf deliberately owns only `fmod` and
//! `fmodf`; it excludes binary80 `fmodl`, `remainder*`, `remquo*`, `modf*`,
//! fenv rounding/truncation, special and complex math, general libm, family
//! completion, promotion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math fmod leaf requires little-endian Linux/x86-64");

const F64_EXPONENT_MASK: u64 = 0x7ff0_0000_0000_0000;
const F64_FRACTION_MASK: u64 = 0x000f_ffff_ffff_ffff;
const F32_EXPONENT_MASK: u32 = 0x7f80_0000;
const F32_FRACTION_MASK: u32 = 0x007f_ffff;

/// Matches musl's non-signaling raw binary64 `isnan` classification.
#[inline]
fn is_nan_f64(bits: u64) -> bool {
    bits & F64_EXPONENT_MASK == F64_EXPONENT_MASK && bits & F64_FRACTION_MASK != 0
}

/// Matches musl's non-signaling raw binary32 `isnan` classification.
#[inline]
fn is_nan_f32(bits: u32) -> bool {
    bits & F32_EXPONENT_MASK == F32_EXPONENT_MASK && bits & F32_FRACTION_MASK != 0
}

/// Returns the binary64 remainder with musl's sign, subnormal, and domain rule.
#[no_mangle]
pub extern "C" fn fmod(x: f64, y: f64) -> f64 {
    let mut x_bits = x.to_bits();
    let mut y_bits = y.to_bits();
    let mut x_exponent = ((x_bits >> 52) & 0x7ff) as i32;
    let mut y_exponent = ((y_bits >> 52) & 0x7ff) as i32;
    let x_sign = x_bits >> 63;

    if y_bits << 1 == 0 || is_nan_f64(y_bits) || x_exponent == 0x7ff {
        return (x * y) / (x * y);
    }
    if x_bits << 1 <= y_bits << 1 {
        if x_bits << 1 == y_bits << 1 {
            return 0.0 * x;
        }
        return x;
    }

    if x_exponent == 0 {
        let mut top = x_bits << 12;
        while top >> 63 == 0 {
            x_exponent -= 1;
            top <<= 1;
        }
        x_bits <<= (-x_exponent + 1) as u32;
    } else {
        x_bits &= u64::MAX >> 12;
        x_bits |= 1_u64 << 52;
    }
    if y_exponent == 0 {
        let mut top = y_bits << 12;
        while top >> 63 == 0 {
            y_exponent -= 1;
            top <<= 1;
        }
        y_bits <<= (-y_exponent + 1) as u32;
    } else {
        y_bits &= u64::MAX >> 12;
        y_bits |= 1_u64 << 52;
    }

    while x_exponent > y_exponent {
        let reduced = x_bits.wrapping_sub(y_bits);
        if reduced >> 63 == 0 {
            if reduced == 0 {
                return 0.0 * x;
            }
            x_bits = reduced;
        }
        x_bits <<= 1;
        x_exponent -= 1;
    }
    let reduced = x_bits.wrapping_sub(y_bits);
    if reduced >> 63 == 0 {
        if reduced == 0 {
            return 0.0 * x;
        }
        x_bits = reduced;
    }
    while x_bits >> 52 == 0 {
        x_bits <<= 1;
        x_exponent -= 1;
    }

    if x_exponent > 0 {
        x_bits -= 1_u64 << 52;
        x_bits |= (x_exponent as u64) << 52;
    } else {
        x_bits >>= (-x_exponent + 1) as u32;
    }
    x_bits |= x_sign << 63;
    f64::from_bits(x_bits)
}

/// Returns the binary32 remainder with musl's sign, subnormal, and domain rule.
#[no_mangle]
pub extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    let mut x_bits = x.to_bits();
    let mut y_bits = y.to_bits();
    let mut x_exponent = ((x_bits >> 23) & 0xff) as i32;
    let mut y_exponent = ((y_bits >> 23) & 0xff) as i32;
    let x_sign = x_bits & 0x8000_0000;

    if y_bits << 1 == 0 || is_nan_f32(y_bits) || x_exponent == 0xff {
        return (x * y) / (x * y);
    }
    if x_bits << 1 <= y_bits << 1 {
        if x_bits << 1 == y_bits << 1 {
            return 0.0_f32 * x;
        }
        return x;
    }

    if x_exponent == 0 {
        let mut top = x_bits << 9;
        while top >> 31 == 0 {
            x_exponent -= 1;
            top <<= 1;
        }
        x_bits <<= (-x_exponent + 1) as u32;
    } else {
        x_bits &= u32::MAX >> 9;
        x_bits |= 1_u32 << 23;
    }
    if y_exponent == 0 {
        let mut top = y_bits << 9;
        while top >> 31 == 0 {
            y_exponent -= 1;
            top <<= 1;
        }
        y_bits <<= (-y_exponent + 1) as u32;
    } else {
        y_bits &= u32::MAX >> 9;
        y_bits |= 1_u32 << 23;
    }

    while x_exponent > y_exponent {
        let reduced = x_bits.wrapping_sub(y_bits);
        if reduced >> 31 == 0 {
            if reduced == 0 {
                return 0.0_f32 * x;
            }
            x_bits = reduced;
        }
        x_bits <<= 1;
        x_exponent -= 1;
    }
    let reduced = x_bits.wrapping_sub(y_bits);
    if reduced >> 31 == 0 {
        if reduced == 0 {
            return 0.0_f32 * x;
        }
        x_bits = reduced;
    }
    while x_bits >> 23 == 0 {
        x_bits <<= 1;
        x_exponent -= 1;
    }

    if x_exponent > 0 {
        x_bits -= 1_u32 << 23;
        x_bits |= (x_exponent as u32) << 23;
    } else {
        x_bits >>= (-x_exponent + 1) as u32;
    }
    x_bits |= x_sign;
    f32::from_bits(x_bits)
}
