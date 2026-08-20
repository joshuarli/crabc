// Native binary128 complex exp/log/pow for the AArch64 long-double ABI.
//
// musl 1.2.6 intentionally implements the long-double complex entry points as
// the following compositions (the 53-bit ABI simply aliases the double
// entry points):
//
//     cexpl(z)       = cexp(z)
//     clogl(z)       = CMPLXL(logl(cabsl(z)), cargl(z))
//     cpowl(z, c)    = cexpl(c * clogl(z))
//
// This file keeps that composition, but does not use the current f64-backed
// long-double adapters.  The real exp/log reductions below are binary128
// throughout; cexpl's sine/cosine reduction is shared with the musl-faithful
// primary helper in math_f128_complex_primary.rs.  `hypotl` and `atan2l` are
// the native binary128 implementations in math_f128.rs.
//
// The shared primary reduction covers the normal finite range needed by
// complex arithmetic and rejects arguments beyond its explicit binary128
// Payne--Hanek table range.  No glibc symbols or semantics are involved.

#[cfg(target_arch = "aarch64")]
const F128_LN2_HI: f128 =
    f128::from_bits(0x3ffe62e42fefa39ef356000000000000);

#[cfg(target_arch = "aarch64")]
const F128_LN2_LO: f128 =
    f128::from_bits(0x3fbe93c7673007e60000000000000000);

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_pow2(e: i32) -> f128 {
    // The smallest binary128 subnormal is 2^-16494.  Constructing powers of
    // two from their representation avoids depending on the f64 `scalbnl`
    // compatibility adapter.
    if e > 16383 {
        return f128::INFINITY;
    }
    if e < -16494 {
        return 0.0_f128;
    }
    if e >= -16382 {
        return f128::from_bits(((e + 16383) as u128) << 112);
    }
    f128::from_bits(1u128 << (e + 16494) as u32)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_scalbn(x: f128, n: i32) -> f128 {
    if x == 0.0_f128 || !x.is_finite() || n == 0 {
        return x;
    }
    if n > 16383 {
        // A subnormal can legitimately need more than the largest represent-
        // able *single* power of two during normalization (for example,
        // 2^-16494 * 2^16494 == 1).  Apply the scale in two finite steps.
        return (x * f128_pow2(16383)) * f128_pow2(n - 16383);
    }
    x * f128_pow2(n)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_round_integer(x: f128) -> f128 {
    // Round to nearest, ties to even, without calling floorl/nearbyintl.
    // This is enough for the bounded exp reduction below; trig uses the
    // primary helper's matching musl reduction.
    if !x.is_finite() {
        return x;
    }
    let bits = x.to_bits();
    let sign = bits & (1u128 << 127);
    let abs_bits = bits & !(1u128 << 127);
    let raw_exp = ((abs_bits >> 112) & 0x7fff) as i32;
    if raw_exp == 0 {
        return x;
    }
    let e = raw_exp - 0x3fff;
    if e >= 112 {
        return x;
    }
    if e < -1 {
        return f128::from_bits(sign);
    }
    if e == -1 {
        // Binary128's exact half is a tie and rounds to the even integer 0.
        return if f128::from_bits(abs_bits) > 0.5_f128 {
            f128::from_bits(sign | (0x3fffu128 << 112))
        } else {
            f128::from_bits(sign)
        };
    }

    let fraction_mask = (1u128 << (112 - e as u32)) - 1;
    let truncated = abs_bits & !fraction_mask;
    let remainder = abs_bits & fraction_mask;
    let halfway = 1u128 << (111 - e as u32);
    let odd = ((truncated >> (112 - e as u32)) & 1) != 0;
    let round_up = remainder > halfway || (remainder == halfway && odd);
    let truncated = f128::from_bits(truncated);
    if round_up {
        if sign != 0 { -truncated + -1.0_f128 } else { truncated + 1.0_f128 }
    } else if sign != 0 {
        -truncated
    } else {
        truncated
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_round_i32(x: f128) -> i32 {
    let x = f128_round_integer(x);
    if x >= 2147483647.0_f128 {
        return i32::MAX;
    }
    if x <= -2147483648.0_f128 {
        return i32::MIN;
    }
    let bits = x.to_bits();
    let negative = bits & (1u128 << 127) != 0;
    let abs_bits = bits & !(1u128 << 127);
    let raw_exp = ((abs_bits >> 112) & 0x7fff) as i32;
    if raw_exp == 0 {
        return 0;
    }
    let e = raw_exp - 0x3fff;
    if e < 0 {
        return 0;
    }
    let sig = (1u128 << 112) | (abs_bits & ((1u128 << 112) - 1));
    let value = if e >= 112 { sig << (e - 112) } else { sig >> (112 - e) };
    if negative { -(value as i32) } else { value as i32 }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_signed_zero(x: f128) -> f128 {
    f128::from_bits(x.to_bits() & (1u128 << 127))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_signed_one(x: f128) -> f128 {
    f128::from_bits((x.to_bits() & (1u128 << 127)) | (0x3fffu128 << 112))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_exp_reduced(x: f128) -> (f128, i32) {
    let n = f128_round_i32(x / F128_LN2_HI);
    let nf = n as f128;
    let r = (x - nf * F128_LN2_HI) - nf * F128_LN2_LO;

    // The reduced interval is [-ln(2)/2, ln(2)/2].  The Taylor form has
    // monotonically decreasing terms there; 40 terms leave a large margin
    // beyond binary128 precision and retain musl's exp(x)=exp(r)*2^n shape.
    let mut term = 1.0_f128;
    let mut sum = 1.0_f128;
    for i in 1..=40 {
        term *= r / (i as f128);
        sum += term;
    }
    (sum, n)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_exp_native(x: f128) -> f128 {
    // The primary M6 helper carries musl's three-part ln(2) reduction and a
    // longer binary128 Taylor kernel.  Keep this wrapper so the complex
    // exceptional-value code below remains easy to audit against cexp.c.
    m6_f128_primary_exp(x)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_log_native(x: f128) -> f128 {
    if x.is_nan() {
        return x;
    }
    if x == 0.0_f128 {
        return f128::NEG_INFINITY;
    }
    if x.is_sign_negative() {
        return f128::NAN;
    }
    if x.is_infinite() {
        return x;
    }

    let bits = x.to_bits();
    let raw_exp = ((bits >> 112) & 0x7fff) as i32;
    let (e, m) = if raw_exp != 0 {
        let e = raw_exp - 0x3fff;
        (e, f128_scalbn(x, -e))
    } else {
        let fraction = bits & ((1u128 << 112) - 1);
        let leading = 127 - fraction.leading_zeros() as i32;
        let e = -16382 - (112 - leading);
        (e, f128_scalbn(x, -e))
    };

    // log(m) = 2 * atanh((m-1)/(m+1)), m in [1, 2).  Unlike a f64 cast,
    // this retains every binary128 input bit, including subnormal inputs.
    let t = (m - 1.0_f128) / (m + 1.0_f128);
    let t2 = t * t;
    let mut power = t;
    let mut sum = t;
    for k in 1..=56 {
        power *= t2;
        sum += power / ((2 * k + 1) as f128);
    }
    (2.0_f128 * sum)
        + (e as f128) * F128_LN2_HI
        + (e as f128) * F128_LN2_LO
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_sincos_native(x: f128) -> (f128, f128) {
    // Reuse the native primary path's musl __rem_pio2l split.  The earlier
    // local reduction was adequate for ordinary values but lost enough low
    // bits at 13.37 to miss os-test's strict binary128 interval after the
    // large exp(90.01) scale was applied.
    m6_f128_primary_sincos(x)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_complex_mul(a: M4ComplexLong, b: M4ComplexLong) -> M4ComplexLong {
    // This is the C99 complex-product recovery used by musl/compiler complex
    // lowering.  It prevents 0*Inf from destroying a recoverable infinite
    // result, while retaining NaNs in ordinary finite cases.
    let ac = a.re * b.re;
    let bd = a.im * b.im;
    let ad = a.re * b.im;
    let bc = a.im * b.re;
    let mut re = ac - bd;
    let mut im = ad + bc;
    if re.is_nan() && im.is_nan() {
        let mut ar = a.re;
        let mut ai = a.im;
        let mut br = b.re;
        let mut bi = b.im;
        let mut recover = false;
        if ar.is_infinite() || ai.is_infinite() {
            ar = if ar.is_infinite() { f128_signed_one(ar) } else { f128_signed_zero(ar) };
            ai = if ai.is_infinite() { f128_signed_one(ai) } else { f128_signed_zero(ai) };
            if br.is_nan() { br = f128_signed_zero(br); }
            if bi.is_nan() { bi = f128_signed_zero(bi); }
            recover = true;
        }
        if br.is_infinite() || bi.is_infinite() {
            br = if br.is_infinite() { f128_signed_one(br) } else { f128_signed_zero(br) };
            bi = if bi.is_infinite() { f128_signed_one(bi) } else { f128_signed_zero(bi) };
            if ar.is_nan() { ar = f128_signed_zero(ar); }
            if ai.is_nan() { ai = f128_signed_zero(ai); }
            recover = true;
        }
        if !recover && (ac.is_infinite() || bd.is_infinite() || ad.is_infinite() || bc.is_infinite()) {
            if ar.is_nan() { ar = f128_signed_zero(ar); }
            if ai.is_nan() { ai = f128_signed_zero(ai); }
            if br.is_nan() { br = f128_signed_zero(br); }
            if bi.is_nan() { bi = f128_signed_zero(bi); }
            recover = true;
        }
        if recover {
            re = f128::INFINITY * (ar * br - ai * bi);
            im = f128::INFINITY * (ar * bi + ai * br);
        }
    }
    M4ComplexLong { re, im }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_cexp(z: M4ComplexLong) -> M4ComplexLong {
    let x = z.re;
    let y = z.im;

    // These branches mirror musl 1.2.6's cexp.c before the real exp call.
    if y == 0.0_f128 {
        return M4ComplexLong { re: f128_exp_native(x), im: y };
    }
    if x == 0.0_f128 {
        let (s, c) = f128_sincos_native(y);
        return M4ComplexLong { re: c, im: s };
    }
    if !y.is_finite() {
        if x.is_infinite() && x.is_sign_negative() {
            return M4ComplexLong { re: 0.0_f128, im: 0.0_f128 };
        }
        if x.is_infinite() && x.is_sign_positive() {
            return M4ComplexLong { re: x, im: y - y };
        }
        return M4ComplexLong { re: y - y, im: y - y };
    }

    let (s, c) = f128_sincos_native(y);
    if x > 8000.0_f128 && x <= 11357.0_f128 {
        // Equivalent to musl's __ldexp_cexp: scale the trigonometric factors
        // after multiplying by the bounded exp mantissa.
        let (mantissa, exponent) = f128_exp_reduced(x);
        return M4ComplexLong {
            re: f128_scalbn(c * mantissa, exponent),
            im: f128_scalbn(s * mantissa, exponent),
        };
    }
    let e = f128_exp_native(x);
    M4ComplexLong { re: e * c, im: e * s }
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn cexpl(z: M4ComplexLong) -> M4ComplexLong {
    f128_cexp(z)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn clogl(z: M4ComplexLong) -> M4ComplexLong {
    // Exactly musl's long-double composition: logl(cabsl(z)) + i*cargl(z).
    M4ComplexLong {
        re: f128_log_native(hypotl(z.re, z.im)),
        im: atan2l(z.im, z.re),
    }
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn cpowl(z: M4ComplexLong, c: M4ComplexLong) -> M4ComplexLong {
    // Exactly musl 1.2.6's cpowl.c reduction, with both operations retaining
    // the native binary128 complex representation.
    f128_cexp(f128_complex_mul(c, clogl(z)))
}
