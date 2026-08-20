// M4 C99 complex transcendental exports.
//
// The formulas and exceptional-value branches follow musl's src/complex
// implementations.  Double and float use crabc's already-ported real
// elementary functions.  AArch64's binary128 long-double entry points use the
// native implementations in the math_f128_complex_* modules below; RISC-V
// retains the f64 compatibility boundary used by the existing real exports.

#[inline]
fn m4_cd(re: f64, im: f64) -> M4ComplexDouble {
    M4ComplexDouble { re, im }
}

#[inline]
fn m4_cd_add(a: M4ComplexDouble, b: M4ComplexDouble) -> M4ComplexDouble {
    m4_cd(a.re + b.re, a.im + b.im)
}

#[inline]
fn m4_cd_sqrt(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_csqrt_double(z)
}

#[inline]
fn m4_cd_clog(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_cd(log(hypot(z.re, z.im)), unsafe { atan2(z.im, z.re) })
}

#[inline]
fn m4_cd_scaled_exp(x: f64, y: f64, exponent: c_int) -> M4ComplexDouble {
    // This is musl's __ldexp_cexp reduction.  Reducing by k*ln(2) keeps the
    // call to exp finite, while scalbn applies the exponent after the sine or
    // cosine multiplication so values near an axis do not become Inf*0.
    const K: c_int = 1799;
    const K_LN2: f64 = 1246.97177782734161156;
    let reduced = exp(x - K_LN2);
    let scale = K + exponent;
    // Normalize exp(x-k*ln2) to the top of the exponent range, as musl's
    // __frexp_exp does.  This keeps tiny sin/cos components from underflowing
    // before the final exponent is applied.
    let mut reduced_exponent = 0;
    let reduced_mantissa = unsafe { frexp(reduced, &mut reduced_exponent) };
    let normalized = scalbn(reduced_mantissa, 1023);
    let final_scale = scale + reduced_exponent - 1023;
    m4_cd(
        scalbn(cos(y) * normalized, final_scale),
        scalbn(sin(y) * normalized, final_scale),
    )
}

#[inline]
fn m4_cd_exp(z: M4ComplexDouble) -> M4ComplexDouble {
    let x = z.re;
    let y = z.im;
    if y == 0.0 {
        return m4_cd(exp(x), y);
    }
    if x == 0.0 {
        return m4_cd(cos(y), sin(y));
    }
    if !y.is_finite() {
        if is_inf(x) && x.is_sign_negative() {
            return m4_cd(0.0, 0.0);
        }
        if is_inf(x) && x.is_sign_positive() {
            return m4_cd(x, y - y);
        }
        return m4_cd(y - y, y - y);
    }
    if x >= 709.0 && x < 1455.0 {
        return m4_cd_scaled_exp(x, y, 0);
    }
    let e = exp(x);
    m4_cd(e * cos(y), e * sin(y))
}

#[inline]
fn m4_csqrt_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let a = z.re;
    let b = z.im;

    // musl's csqrt special cases.
    if a == 0.0 && b == 0.0 {
        return m4_cd(0.0, b);
    }
    if is_inf(b) {
        return m4_cd(f64::INFINITY, b);
    }
    if is_nan(a) {
        return m4_cd(a, (b - b) / (b - b));
    }
    if is_inf(a) {
        if a.is_sign_negative() {
            return m4_cd((b - b).abs(), copysign(a, b));
        }
        return m4_cd(a, copysign(b - b, b));
    }

    // Algorithm 312, CACM vol. 10 (1967), scaled like musl to avoid
    // overflowing a + hypot(a,b) for components close to DBL_MAX.
    let threshold = f64::MAX / (1.0 + 1.4142135623730951);
    let scale = a.abs() >= threshold || b.abs() >= threshold;
    let (a, b) = if scale { (a * 0.25, b * 0.25) } else { (a, b) };
    let result = if a >= 0.0 {
        let t = sqrt((a + hypot(a, b)) * 0.5);
        m4_cd(t, b / (2.0 * t))
    } else {
        let t = sqrt((-a + hypot(a, b)) * 0.5);
        m4_cd(b.abs() / (2.0 * t), copysign(t, b))
    };
    if scale {
        m4_cd(result.re * 2.0, result.im * 2.0)
    } else {
        result
    }
}

#[inline]
fn m4_csinh_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let x = z.re;
    let y = z.im;

    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return m4_cd(sinh(x), y);
        }
        if x.abs() < 22.0 {
            return m4_cd(sinh(x) * cos(y), cosh(x) * sin(y));
        }
        if x.abs() < 710.0 {
            let h = exp(x.abs()) * 0.5;
            return m4_cd(copysign(h, x) * cos(y), h * sin(y));
        }
        if x.abs() < 1455.0 {
            let scaled = m4_cd_scaled_exp(x.abs(), y, -1);
            return m4_cd(copysign(scaled.re, x), scaled.im);
        }
        let h = f64::from_bits(0x7fe0000000000000) * x;
        return m4_cd(h * cos(y), h * h * sin(y));
    }

    // Preserve musl's useful zero/infinity boundaries before the general
    // NaN path.  In particular, sinh(+-Inf + i0) retains both signs.
    if x == 0.0 && !y.is_finite() {
        return m4_cd(copysign(0.0, x * (y - y)), y - y);
    }
    if y == 0.0 && !x.is_finite() {
        if is_inf(x) {
            return m4_cd(x, y);
        }
        return m4_cd(x, copysign(0.0, y));
    }
    if x.is_finite() && !y.is_finite() {
        return m4_cd(y - y, x * (y - y));
    }
    if is_inf(x) {
        // musl's exponent test covers NaN as well as infinity here:
        // sinh(+-Inf + iNaN) is +-Inf + iNaN.
        if !y.is_finite() {
            return m4_cd(x * x, x * (y - y));
        }
        return m4_cd(x * cos(y), f64::INFINITY * sin(y));
    }
    m4_cd((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn m4_ccosh_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let x = z.re;
    let y = z.im;

    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return m4_cd(cosh(x), x * y);
        }
        if x.abs() < 22.0 {
            return m4_cd(cosh(x) * cos(y), sinh(x) * sin(y));
        }
        if x.abs() < 710.0 {
            let h = exp(x.abs()) * 0.5;
            return m4_cd(h * cos(y), copysign(h, x) * sin(y));
        }
        if x.abs() < 1455.0 {
            let scaled = m4_cd_scaled_exp(x.abs(), y, -1);
            return m4_cd(scaled.re, copysign(scaled.im, x));
        }
        let h = f64::from_bits(0x7fe0000000000000) * x;
        return m4_cd(h * h * cos(y), h * sin(y));
    }

    if x == 0.0 && !y.is_finite() {
        return m4_cd(y - y, copysign(0.0, x * (y - y)));
    }
    if y == 0.0 && !x.is_finite() {
        if is_inf(x) {
            return m4_cd(x * x, copysign(0.0, x) * y);
        }
        return m4_cd(x, copysign(0.0, (x + x) * y));
    }
    if x.is_finite() && !y.is_finite() {
        return m4_cd(y - y, x * (y - y));
    }
    if is_inf(x) {
        // Keep the NaN-imaginary branch alongside infinity, as in musl.
        if !y.is_finite() {
            return m4_cd(x * x, x * (y - y));
        }
        return m4_cd((x * x) * cos(y), x * sin(y));
    }
    m4_cd((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn m4_ctanh_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let x = z.re;
    let y = z.im;

    if is_nan(x) {
        return m4_cd(x, if y == 0.0 { y } else { x * y });
    }
    if is_inf(x) {
        return m4_cd(
            copysign(1.0, x),
            copysign(0.0, if is_inf(y) { y } else { sin(y) * cos(y) }),
        );
    }
    if !y.is_finite() {
        return m4_cd(if x == 0.0 { x } else { y - y }, y - y);
    }
    if x.abs() >= 22.0 {
        let e = exp(-x.abs());
        return m4_cd(copysign(1.0, x), 4.0 * sin(y) * cos(y) * e * e);
    }

    // Kahan's stable formulation from musl's ctanh.c.
    let t = tan(y);
    let beta = 1.0 + t * t;
    let s = sinh(x);
    let rho = sqrt(1.0 + s * s);
    let denom = 1.0 + beta * s * s;
    m4_cd((beta * rho * s) / denom, t / denom)
}

#[inline]
fn m4_csin_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let w = m4_csinh_double(m4_cd(-z.im, z.re));
    m4_cd(w.im, -w.re)
}

#[inline]
fn m4_ccos_double(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_ccosh_double(m4_cd(-z.im, z.re))
}

#[inline]
fn m4_ctan_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let w = m4_ctanh_double(m4_cd(-z.im, z.re));
    m4_cd(w.im, -w.re)
}

#[inline]
fn m4_catan_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let x = z.re;
    let y = z.im;
    let x2 = x * x;
    let a = 1.0 - x2 - y * y;
    let real = 0.5 * unsafe { atan2(2.0 * x, a) };
    let den = x2 + (y - 1.0) * (y - 1.0);
    let num = x2 + (y + 1.0) * (y + 1.0);
    m4_cd(real, 0.25 * log(num / den))
}

#[inline]
fn m4_casin_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let x = z.re;
    let y = z.im;
    let w = m4_cd(1.0 - (x - y) * (x + y), -2.0 * x * y);
    let r = m4_cd_clog(m4_cd_add(m4_cd(-y, x), m4_cd_sqrt(w)));
    m4_cd(r.im, -r.re)
}

#[inline]
fn m4_cacos_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let w = m4_casin_double(z);
    m4_cd(1.57079632679489661923 - w.re, -w.im)
}

#[inline]
fn m4_casinh_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let w = m4_casin_double(m4_cd(-z.im, z.re));
    m4_cd(w.im, -w.re)
}

#[inline]
fn m4_cacosh_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let im_negative = z.im.is_sign_negative();
    let w = m4_cacos_double(z);
    if im_negative {
        m4_cd(w.im, -w.re)
    } else {
        m4_cd(-w.im, w.re)
    }
}

#[inline]
fn m4_catanh_double(z: M4ComplexDouble) -> M4ComplexDouble {
    let w = m4_catan_double(m4_cd(-z.im, z.re));
    m4_cd(w.im, -w.re)
}

#[inline]
fn m4_cf(re: f32, im: f32) -> M4ComplexFloat {
    M4ComplexFloat { re, im }
}

#[inline]
fn m4_cf_add(a: M4ComplexFloat, b: M4ComplexFloat) -> M4ComplexFloat {
    m4_cf(a.re + b.re, a.im + b.im)
}

#[inline]
fn m4_cf_sqrt(z: M4ComplexFloat) -> M4ComplexFloat {
    let a = z.re;
    let b = z.im;
    if a == 0.0 && b == 0.0 {
        return m4_cf(0.0, b);
    }
    if is_inff(b) {
        return m4_cf(f32::INFINITY, b);
    }
    if is_nanf(a) {
        return m4_cf(a, (b - b) / (b - b));
    }
    if is_inff(a) {
        if a.is_sign_negative() {
            return m4_cf((b - b).abs(), copysignf(a, b));
        }
        return m4_cf(a, copysignf(b - b, b));
    }
    // Keep the Algorithm 312 intermediates in double precision, as musl's
    // csqrtf does.  Rounding the hypot/sqrt expression in float first can
    // move a result onto the rejected side of the generated one-ulp interval.
    let a = a as f64;
    let b = b as f64;
    let result = if a >= 0.0 {
        let t = sqrt((a + hypot(a, b)) * 0.5);
        m4_cf(t as f32, (b / (2.0 * t)) as f32)
    } else {
        let t = sqrt((-a + hypot(a, b)) * 0.5);
        m4_cf((b.abs() / (2.0 * t)) as f32, copysignf(t as f32, b as f32))
    };
    result
}

#[inline]
fn m4_cf_clog(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_cf(logf(hypotf(z.re, z.im)), unsafe { atan2f(z.im, z.re) })
}

#[inline]
fn m4_cf_scaled_exp(x: f32, y: f32, exponent: c_int) -> M4ComplexFloat {
    const K: c_int = 235;
    const K_LN2: f32 = 162.88958740;
    let reduced = expf(x - K_LN2);
    let scale = K + exponent;
    let mut reduced_exponent = 0;
    let reduced_mantissa = unsafe { frexpf(reduced, &mut reduced_exponent) };
    let normalized = scalbnf(reduced_mantissa, 127);
    let final_scale = scale + reduced_exponent - 127;
    m4_cf(
        scalbnf(cosf(y) * normalized, final_scale),
        scalbnf(sinf(y) * normalized, final_scale),
    )
}

#[inline]
fn m4_csinh_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let x = z.re;
    let y = z.im;
    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return m4_cf(sinhf(x), y);
        }
        if x.abs() < 11.0 {
            return m4_cf(sinhf(x) * cosf(y), coshf(x) * sinf(y));
        }
        if x.abs() < 89.0 {
            let h = expf(x.abs()) * 0.5;
            return m4_cf(copysignf(h, x) * cosf(y), h * sinf(y));
        }
        if x.abs() < 192.0 {
            let scaled = m4_cf_scaled_exp(x.abs(), y, -1);
            return m4_cf(copysignf(scaled.re, x), scaled.im);
        }
        let h = f32::from_bits(0x7f000000) * x;
        return m4_cf(h * cosf(y), h * h * sinf(y));
    }
    if x == 0.0 && !y.is_finite() {
        return m4_cf(copysignf(0.0, x * (y - y)), y - y);
    }
    if y == 0.0 && !x.is_finite() {
        if is_inff(x) {
            return m4_cf(x, y);
        }
        return m4_cf(x, copysignf(0.0, y));
    }
    if x.is_finite() && !y.is_finite() {
        return m4_cf(y - y, x * (y - y));
    }
    if is_inff(x) {
        if !y.is_finite() {
            return m4_cf(x * x, x * (y - y));
        }
        return m4_cf(x * cosf(y), f32::INFINITY * sinf(y));
    }
    m4_cf((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn m4_ccosh_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let x = z.re;
    let y = z.im;
    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return m4_cf(coshf(x), x * y);
        }
        if x.abs() < 11.0 {
            return m4_cf(coshf(x) * cosf(y), sinhf(x) * sinf(y));
        }
        if x.abs() < 89.0 {
            let h = expf(x.abs()) * 0.5;
            return m4_cf(h * cosf(y), copysignf(h, x) * sinf(y));
        }
        if x.abs() < 192.0 {
            let scaled = m4_cf_scaled_exp(x.abs(), y, -1);
            return m4_cf(scaled.re, copysignf(scaled.im, x));
        }
        let h = f32::from_bits(0x7f000000) * x;
        return m4_cf(h * h * cosf(y), h * sinf(y));
    }
    if x == 0.0 && !y.is_finite() {
        return m4_cf(y - y, copysignf(0.0, x * (y - y)));
    }
    if y == 0.0 && !x.is_finite() {
        if is_inff(x) {
            return m4_cf(x * x, copysignf(0.0, x) * y);
        }
        return m4_cf(x, copysignf(0.0, (x + x) * y));
    }
    if x.is_finite() && !y.is_finite() {
        return m4_cf(y - y, x * (y - y));
    }
    if is_inff(x) {
        if !y.is_finite() {
            return m4_cf(x * x, x * (y - y));
        }
        return m4_cf((x * x) * cosf(y), x * sinf(y));
    }
    m4_cf((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn m4_ctanh_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let x = z.re;
    let y = z.im;
    if is_nanf(x) {
        return m4_cf(x, if y == 0.0 { y } else { x * y });
    }
    if is_inff(x) {
        return m4_cf(
            copysignf(1.0, x),
            copysignf(0.0, if is_inff(y) { y } else { sinf(y) * cosf(y) }),
        );
    }
    if !y.is_finite() {
        return m4_cf(if x == 0.0 { x } else { y - y }, y - y);
    }
    if x.abs() >= 11.0 {
        let e = expf(-x.abs());
        return m4_cf(copysignf(1.0, x), 4.0 * sinf(y) * cosf(y) * e * e);
    }
    let t = tanf(y);
    let beta = 1.0f32 + t * t;
    let s = sinhf(x);
    let rho = sqrtf(1.0 + s * s);
    let denom = 1.0 + beta * s * s;
    m4_cf((beta * rho * s) / denom, t / denom)
}

#[inline]
fn m4_csin_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let w = m4_csinh_float(m4_cf(-z.im, z.re));
    m4_cf(w.im, -w.re)
}

#[inline]
fn m4_ccos_float(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_ccosh_float(m4_cf(-z.im, z.re))
}

#[inline]
fn m4_ctan_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let w = m4_ctanh_float(m4_cf(-z.im, z.re));
    m4_cf(w.im, -w.re)
}

#[inline]
fn m4_catan_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let x = z.re;
    let y = z.im;
    let x2 = x * x;
    let a = 1.0 - x2 - y * y;
    let real = 0.5 * unsafe { atan2f(2.0 * x, a) };
    let den = x2 + (y - 1.0) * (y - 1.0);
    let num = x2 + (y + 1.0) * (y + 1.0);
    m4_cf(real, 0.25 * logf(num / den))
}

#[inline]
fn m4_casin_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let x = z.re;
    let y = z.im;
    let w = m4_cf(1.0 - (x - y) * (x + y), -2.0 * x * y);
    let r = m4_cf_clog(m4_cf_add(m4_cf(-y, x), m4_cf_sqrt(w)));
    m4_cf(r.im, -r.re)
}

#[inline]
fn m4_cacos_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let w = m4_casin_float(z);
    m4_cf(1.5707964 - w.re, -w.im)
}

#[inline]
fn m4_casinh_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let w = m4_casin_float(m4_cf(-z.im, z.re));
    m4_cf(w.im, -w.re)
}

#[inline]
fn m4_cacosh_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let im_negative = z.im.is_sign_negative();
    let w = m4_cacos_float(z);
    if im_negative {
        m4_cf(w.im, -w.re)
    } else {
        m4_cf(-w.im, w.re)
    }
}

#[inline]
fn m4_catanh_float(z: M4ComplexFloat) -> M4ComplexFloat {
    let w = m4_catan_float(m4_cf(-z.im, z.re));
    m4_cf(w.im, -w.re)
}

// Export the double and float entry points.
#[no_mangle]
pub extern "C" fn cexp(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_cd_exp(z)
}

#[no_mangle]
pub extern "C" fn clog(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_cd_clog(z)
}

#[no_mangle]
pub extern "C" fn csin(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_csin_double(z)
}

#[no_mangle]
pub extern "C" fn ccos(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_ccos_double(z)
}

#[no_mangle]
pub extern "C" fn ctan(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_ctan_double(z)
}

#[no_mangle]
pub extern "C" fn csqrt(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_csqrt_double(z)
}

#[no_mangle]
pub extern "C" fn csinh(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_csinh_double(z)
}

#[no_mangle]
pub extern "C" fn ccosh(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_ccosh_double(z)
}

#[no_mangle]
pub extern "C" fn ctanh(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_ctanh_double(z)
}

#[no_mangle]
pub extern "C" fn casin(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_casin_double(z)
}

#[no_mangle]
pub extern "C" fn cacos(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_cacos_double(z)
}

#[no_mangle]
pub extern "C" fn catan(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_catan_double(z)
}

#[no_mangle]
pub extern "C" fn casinh(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_casinh_double(z)
}

#[no_mangle]
pub extern "C" fn cacosh(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_cacosh_double(z)
}

#[no_mangle]
pub extern "C" fn catanh(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_catanh_double(z)
}

#[no_mangle]
pub extern "C" fn cexpf(z: M4ComplexFloat) -> M4ComplexFloat {
    let x = z.re;
    let y = z.im;
    if y == 0.0 {
        return m4_cf(expf(x), y);
    }
    if x == 0.0 {
        return m4_cf(cosf(y), sinf(y));
    }
    if !y.is_finite() {
        if is_inff(x) && x.is_sign_negative() {
            return m4_cf(0.0, 0.0);
        }
        if is_inff(x) && x.is_sign_positive() {
            return m4_cf(x, y - y);
        }
        return m4_cf(y - y, y - y);
    }
    if x >= 88.0 && x < 193.0 {
        return m4_cf_scaled_exp(x, y, 0);
    }
    let e = expf(x);
    m4_cf(e * cosf(y), e * sinf(y))
}

#[no_mangle]
pub extern "C" fn clogf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_cf_clog(z)
}

#[no_mangle]
pub extern "C" fn csinf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_csin_float(z)
}

#[no_mangle]
pub extern "C" fn ccosf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_ccos_float(z)
}

#[no_mangle]
pub extern "C" fn ctanf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_ctan_float(z)
}

#[no_mangle]
pub extern "C" fn csqrtf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_cf_sqrt(z)
}

#[no_mangle]
pub extern "C" fn csinhf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_csinh_float(z)
}

#[no_mangle]
pub extern "C" fn ccoshf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_ccosh_float(z)
}

#[no_mangle]
pub extern "C" fn ctanhf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_ctanh_float(z)
}

#[no_mangle]
pub extern "C" fn casinf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_casin_float(z)
}

#[no_mangle]
pub extern "C" fn cacosf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_cacos_float(z)
}

#[no_mangle]
pub extern "C" fn catanf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_catan_float(z)
}

#[no_mangle]
pub extern "C" fn casinhf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_casinh_float(z)
}

#[no_mangle]
pub extern "C" fn cacoshf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_cacosh_float(z)
}

#[no_mangle]
pub extern "C" fn catanhf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_catanh_float(z)
}

// x86_64 uses the 64-bit long-double ABI, so these are aliases at the ABI
// boundary.  AArch64 uses native binary128 implementations below.  RISC-V
// retains the preexisting f64 compatibility boundary used by math_compat.rs.
#[cfg(target_arch = "x86_64")]
macro_rules! m4_long_complex_aliases {
    ($($name:ident => $helper:ident),* $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name(z: M4ComplexLong) -> M4ComplexLong {
                $helper(z)
            }
        )*
    };
}

#[cfg(target_arch = "x86_64")]
m4_long_complex_aliases!(
    cexpl => cexp,
    clogl => clog,
    csinl => csin,
    ccosl => ccos,
    ctanl => ctan,
    csqrtl => csqrt,
    csinhl => csinh,
    ccoshl => ccosh,
    ctanhl => ctanh,
    casinl => casin,
    cacosl => cacos,
    catanl => catan,
    casinhl => casinh,
    cacoshl => cacosh,
    catanhl => catanh,
);

#[cfg(target_arch = "riscv64")]
#[inline]
fn m4_cl_to_double(z: M4ComplexLong) -> M4ComplexDouble {
    m4_cd(z.re as f64, z.im as f64)
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn m4_cl_from_double(z: M4ComplexDouble) -> M4ComplexLong {
    M4ComplexLong { re: z.re as f128, im: z.im as f128 }
}

#[cfg(target_arch = "riscv64")]
macro_rules! m4_long_complex_compat {
    ($($name:ident => $helper:ident),* $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name(z: M4ComplexLong) -> M4ComplexLong {
                m4_cl_from_double($helper(m4_cl_to_double(z)))
            }
        )*
    };
}

#[cfg(target_arch = "riscv64")]
m4_long_complex_compat!(
    cexpl => m4_cd_exp,
    clogl => m4_cd_clog,
    csinl => m4_csin_double,
    ccosl => m4_ccos_double,
    ctanl => m4_ctan_double,
    csqrtl => m4_csqrt_double,
    csinhl => m4_csinh_double,
    ccoshl => m4_ccosh_double,
    ctanhl => m4_ctanh_double,
    casinl => m4_casin_double,
    cacosl => m4_cacos_double,
    catanl => m4_catan_double,
    casinhl => m4_casinh_double,
    cacoshl => m4_cacosh_double,
    catanhl => m4_catanh_double,
);

// The native AArch64 long-double ABI is binary128. These inverse functions
// therefore bypass the legacy f64 compatibility aliases above.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn casinl(z: M4ComplexLong) -> M4ComplexLong { m6_f128_casin(z) }

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn cacosl(z: M4ComplexLong) -> M4ComplexLong { m6_f128_cacos(z) }

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn catanl(z: M4ComplexLong) -> M4ComplexLong { m6_f128_catan(z) }

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn casinhl(z: M4ComplexLong) -> M4ComplexLong { m6_f128_casinh(z) }

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn cacoshl(z: M4ComplexLong) -> M4ComplexLong { m6_f128_cacosh(z) }

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn catanhl(z: M4ComplexLong) -> M4ComplexLong { m6_f128_catanh(z) }
