// Binary128 complex inverse functions for the AArch64 long-double
// ABI.
//
// musl's long-double complex inverse functions are deliberately small
// translations of the corresponding identities: casinl is written in terms
// of clogl and csqrtl, cacosl is derived from casinl, catanl uses the real
// atan2l/logl formula, and the hyperbolic inverses rotate those functions.
// Keep those identities here, but keep every real intermediate in binary128.
// The ordinary long-double compatibility layer narrows to f64 and therefore
// cannot be used by these entry points.

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_complex(re: f128, im: f128) -> M4ComplexLong {
    M4ComplexLong { re, im }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_log(x: f128) -> f128 {
    // AArch64 uses IEEE binary128 for long double.  musl 1.2.6 still
    // carries a TODO f64 fallback for its logl binary128 branch; the complex
    // identities below need the operation natively, so use the same
    // logarithm decomposition as musl's long-double implementation and
    // evaluate the odd atanh series in f128 instead of narrowing to f64.
    const LN2: f128 =
        6.93147180559945309417232121458176568e-1_f128;
    const SQRT2: f128 =
        1.41421356237309504880168872420969808_f128;
    const INV_SQRT2: f128 =
        7.07106781186547524400844362104849039e-1_f128;

    if x.is_nan() || x == f128::INFINITY {
        return x;
    }
    if x == 0.0_f128 {
        // log(+-0) is -inf.  The sign is immaterial to the result, while
        // retaining a direct infinity avoids depending on the target's
        // floating-point exception mode for a deliberate zero divide.
        return f128::NEG_INFINITY;
    }
    if x < 0.0_f128 {
        return f128::NAN;
    }

    // Extract x = m * 2^e.  For a subnormal, first normalize by an exact
    // power of two; this keeps the decomposition valid all the way down to
    // the smallest binary128 value.
    let mut bits = x.to_bits();
    let mut exponent = ((bits >> 112) & 0x7fff) as i32 - 0x3fff;
    let mut value = x;
    if ((bits >> 112) & 0x7fff) == 0 {
        const SCALE_UP: f128 = f128::from_bits((0x3fff + 200u128) << 112);
        value *= SCALE_UP;
        bits = value.to_bits();
        // Re-read the normalized exponent.  The original zero exponent is
        // only the encoding of a subnormal, not its mathematical exponent.
        exponent = ((bits >> 112) & 0x7fff) as i32 - 0x3fff - 200;
    }

    let fraction = bits & ((1u128 << 112) - 1);
    let mut mantissa = f128::from_bits((0x3fffu128 << 112) | fraction);

    // Restrict m to [1/sqrt(2), sqrt(2)] before using
    // log(m) = 2 atanh((m-1)/(m+1)).  This makes |z| <= 0.1716, so the
    // fixed 72-term series leaves a large margin beyond 113 bits.
    if mantissa > SQRT2 {
        mantissa *= 0.5_f128;
        exponent += 1;
    } else if mantissa < INV_SQRT2 {
        mantissa *= 2.0_f128;
        exponent -= 1;
    }

    let z = (mantissa - 1.0_f128) / (mantissa + 1.0_f128);
    let z2 = z * z;
    let mut term = z;
    let mut sum = z;
    let mut denominator = 3u32;
    for _ in 0..72 {
        term *= z2;
        sum += term / denominator as f128;
        denominator += 2;
    }
    2.0_f128 * sum + (exponent as f128) * LN2
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_clog(re: f128, im: f128) -> M4ComplexLong {
    // This is clogl(z) = log(hypotl(re, im)) + i atan2l(im, re).  Both real
    // operations remain binary128 (`hypotl` and `atan2l` are native helpers
    // in math_f128.rs).
    m6_f128_complex(m6_f128_log(hypotl(re, im)), atan2l(im, re))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_csqrt(re: f128, im: f128) -> M4ComplexLong {
    // Algorithm 312, matching musl's csqrtl identity.  Scale the largest
    // finite inputs before forming re + hypot(re, im), just as musl's
    // csqrt implementation does for the narrower formats; the addition can
    // otherwise overflow even though the final square root is representable.
    if re == 0.0_f128 && im == 0.0_f128 {
        return m6_f128_complex(0.0_f128, im);
    }
    if im.is_infinite() {
        return m6_f128_complex(f128::INFINITY, im);
    }
    if re.is_nan() {
        return m6_f128_complex(re, (im - im) / (im - im));
    }
    if re.is_infinite() {
        if re.is_sign_negative() {
            return m6_f128_complex((im - im).abs(), m6_f128_copysign(re, im));
        }
        return m6_f128_complex(re, m6_f128_copysign(im - im, im));
    }

    const F128_MAX: f128 = f128::from_bits(
        (0x7ffe_u128 << 112) | ((1u128 << 112) - 1),
    );
    let threshold = F128_MAX / (1.0_f128 + 1.41421356237309504880168872420969808_f128);
    let scale = re.abs() >= threshold || im.abs() >= threshold;
    let (re, im) = if scale {
        (re * 0.25_f128, im * 0.25_f128)
    } else {
        (re, im)
    };

    let result = if re >= 0.0_f128 {
        let t = f128_sqrt((re + hypotl(re, im)) * 0.5_f128);
        m6_f128_complex(t, im / (2.0_f128 * t))
    } else {
        let t = f128_sqrt((-re + hypotl(re, im)) * 0.5_f128);
        m6_f128_complex(im.abs() / (2.0_f128 * t), m6_f128_copysign(t, im))
    };
    if scale {
        m6_f128_complex(result.re * 2.0_f128, result.im * 2.0_f128)
    } else {
        result
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_copysign(x: f128, sign: f128) -> f128 {
    f128::from_bits((x.to_bits() & !(1u128 << 127)) | (sign.to_bits() & (1u128 << 127)))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_casin(z: M4ComplexLong) -> M4ComplexLong {
    // musl 1.2.6 src/complex/casinl.c (the non-64-bit-long-double branch):
    //   w = 1 - (x-y)(x+y) - 2ixy
    //   r = clogl(-y + ix + csqrtl(w))
    //   casinl(z) = imag(r) - i real(r)
    let x = z.re;
    let y = z.im;

    // Keep the one-infinity and NaN cases out of the identity above.  Its
    // intermediate products intentionally overflow for infinite arguments,
    // while C99's principal-value rules preserve the approach direction.
    const PI_2: f128 =
        1.57079632679489661923132169163975144_f128;
    const PI_4: f128 =
        7.85398163397448309615660845819875721e-1_f128;
    if x == 0.0_f128 && y == 0.0_f128 {
        return m6_f128_complex(x, y);
    }
    if x.is_infinite() {
        if y.is_infinite() {
            return m6_f128_complex(
                m6_f128_copysign(PI_4, x),
                m6_f128_copysign(f128::INFINITY, y),
            );
        }
        if y.is_nan() {
            return m6_f128_complex(f128::NAN, f128::INFINITY);
        }
        return m6_f128_complex(
            m6_f128_copysign(PI_2, x),
            m6_f128_copysign(f128::INFINITY, y),
        );
    }
    if y.is_infinite() {
        if x.is_nan() {
            return m6_f128_complex(f128::NAN, y);
        }
        return m6_f128_complex(m6_f128_copysign(0.0_f128, x), y);
    }
    if x.is_nan() {
        // musl's complex inverse family propagates a real NaN into both
        // components here, including NaN + i0. Keeping the zero would make
        // the cacosl/casinhl rotations lose their required NaN component.
        return m6_f128_complex(x, x);
    }
    if y.is_nan() {
        if x == 0.0_f128 {
            return m6_f128_complex(x, y);
        }
        return m6_f128_complex(y, y);
    }

    let w_re = 1.0_f128 - (x - y) * (x + y);
    let w_im = -2.0_f128 * x * y;
    let root = m6_f128_csqrt(w_re, w_im);
    let r = m6_f128_clog(-y + root.re, x + root.im);
    m6_f128_complex(r.im, -r.re)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_cacos(z: M4ComplexLong) -> M4ComplexLong {
    // PI/2 is the high-precision binary128 literal used by musl's cacosl.c.
    const PI_2: f128 =
        1.57079632679489661923132169163975144_f128;
    let w = m6_f128_casin(z);
    m6_f128_complex(PI_2 - w.re, -w.im)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_catan(z: M4ComplexLong) -> M4ComplexLong {
    // musl 1.2.6 src/complex/catanl.c, preserving its operation order.
    let x = z.re;
    let y = z.im;

    // The algebraic identity is well-conditioned for finite inputs, but
    // turns x=+/-Inf (or y=+/-Inf) into Inf/Inf and loses the principal-value
    // limit.  These are the special-value branches used by musl's catan
    // family: the finite component determines the signed zero on the other
    // axis, and a NaN paired with an infinity does not erase that direction.
    const PI_2: f128 =
        1.57079632679489661923132169163975144_f128;
    if x == 0.0_f128 && y == 0.0_f128 {
        return m6_f128_complex(x, y);
    }
    if x.is_infinite() {
        let real = m6_f128_copysign(PI_2, x);
        if y.is_nan() {
            return m6_f128_complex(real, 0.0_f128);
        }
        return m6_f128_complex(real, m6_f128_copysign(0.0_f128, y));
    }
    if y.is_infinite() {
        let real = if x.is_nan() {
            x
        } else {
            m6_f128_copysign(PI_2, x)
        };
        return m6_f128_complex(real, m6_f128_copysign(0.0_f128, y));
    }
    if x.is_nan() {
        if y == 0.0_f128 {
            return m6_f128_complex(x, y);
        }
        return m6_f128_complex(x, x);
    }
    if y.is_nan() {
        return m6_f128_complex(y, y);
    }

    let x2 = x * x;
    let mut a = 1.0_f128 - x2 - y * y;
    let t = atan2l(2.0_f128 * x, a) * 0.5_f128;
    let real = t;

    let t = y - 1.0_f128;
    a = x2 + t * t;
    let t = y + 1.0_f128;
    a = (x2 + t * t) / a;
    m6_f128_complex(real, 0.25_f128 * m6_f128_log(a))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_casinh(z: M4ComplexLong) -> M4ComplexLong {
    let w = m6_f128_casin(m6_f128_complex(-z.im, z.re));
    m6_f128_complex(w.im, -w.re)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_cacosh(z: M4ComplexLong) -> M4ComplexLong {
    let im_negative = z.im.is_sign_negative();
    let w = m6_f128_cacos(z);
    if im_negative {
        m6_f128_complex(w.im, -w.re)
    } else {
        m6_f128_complex(-w.im, w.re)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_catanh(z: M4ComplexLong) -> M4ComplexLong {
    let w = m6_f128_catan(m6_f128_complex(-z.im, z.re));
    m6_f128_complex(w.im, -w.re)
}
