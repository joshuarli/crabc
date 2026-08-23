// C99 complex transcendental exports.
//
// The formulas and exceptional-value branches follow musl's src/complex
// implementations.  Double and float use crabc's already-ported real
// elementary functions.  AArch64's binary128 long-double entry points use the
// native implementations in the math_f128_complex_* modules below; RISC-V
// retains the f64 compatibility boundary used by the existing real exports.

#[inline]
fn cabi_cd(re: f64, im: f64) -> ComplexDouble {
    ComplexDouble { re, im }
}

#[inline]
fn cabi_cd_add(a: ComplexDouble, b: ComplexDouble) -> ComplexDouble {
    cabi_cd(a.re + b.re, a.im + b.im)
}

#[inline]
fn cabi_cd_sqrt(z: ComplexDouble) -> ComplexDouble {
    cabi_csqrt_double(z)
}

#[inline]
fn cabi_cd_clog(z: ComplexDouble) -> ComplexDouble {
    cabi_cd(log(hypot(z.re, z.im)), unsafe { atan2(z.im, z.re) })
}

#[inline]
fn cabi_cd_scaled_exp(x: f64, y: f64, exponent: c_int) -> ComplexDouble {
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
    cabi_cd(
        scalbn(cos(y) * normalized, final_scale),
        scalbn(sin(y) * normalized, final_scale),
    )
}

#[inline]
fn cabi_cd_exp(z: ComplexDouble) -> ComplexDouble {
    let x = z.re;
    let y = z.im;
    if y == 0.0 {
        return cabi_cd(exp(x), y);
    }
    if x == 0.0 {
        return cabi_cd(cos(y), sin(y));
    }
    if !y.is_finite() {
        if is_inf(x) && x.is_sign_negative() {
            return cabi_cd(0.0, 0.0);
        }
        if is_inf(x) && x.is_sign_positive() {
            return cabi_cd(x, y - y);
        }
        return cabi_cd(y - y, y - y);
    }
    if x >= 709.0 && x < 1455.0 {
        return cabi_cd_scaled_exp(x, y, 0);
    }
    let e = exp(x);
    cabi_cd(e * cos(y), e * sin(y))
}

#[inline]
fn cabi_csqrt_double(z: ComplexDouble) -> ComplexDouble {
    let a = z.re;
    let b = z.im;

    // musl's csqrt special cases.
    if a == 0.0 && b == 0.0 {
        return cabi_cd(0.0, b);
    }
    if is_inf(b) {
        return cabi_cd(f64::INFINITY, b);
    }
    if is_nan(a) {
        return cabi_cd(a, (b - b) / (b - b));
    }
    if is_inf(a) {
        if a.is_sign_negative() {
            return cabi_cd((b - b).abs(), copysign(a, b));
        }
        return cabi_cd(a, copysign(b - b, b));
    }

    // Algorithm 312, CACM vol. 10 (1967), scaled like musl to avoid
    // overflowing a + hypot(a,b) for components close to DBL_MAX.
    let threshold = f64::MAX / (1.0 + 1.4142135623730951);
    let scale = a.abs() >= threshold || b.abs() >= threshold;
    let (a, b) = if scale { (a * 0.25, b * 0.25) } else { (a, b) };
    let result = if a >= 0.0 {
        let t = sqrt((a + hypot(a, b)) * 0.5);
        cabi_cd(t, b / (2.0 * t))
    } else {
        let t = sqrt((-a + hypot(a, b)) * 0.5);
        cabi_cd(b.abs() / (2.0 * t), copysign(t, b))
    };
    if scale {
        cabi_cd(result.re * 2.0, result.im * 2.0)
    } else {
        result
    }
}

#[inline]
fn cabi_csinh_double(z: ComplexDouble) -> ComplexDouble {
    let x = z.re;
    let y = z.im;

    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return cabi_cd(sinh(x), y);
        }
        if x.abs() < 22.0 {
            return cabi_cd(sinh(x) * cos(y), cosh(x) * sin(y));
        }
        if x.abs() < 710.0 {
            let h = exp(x.abs()) * 0.5;
            return cabi_cd(copysign(h, x) * cos(y), h * sin(y));
        }
        if x.abs() < 1455.0 {
            let scaled = cabi_cd_scaled_exp(x.abs(), y, -1);
            return cabi_cd(copysign(scaled.re, x), scaled.im);
        }
        let h = f64::from_bits(0x7fe0000000000000) * x;
        return cabi_cd(h * cos(y), h * h * sin(y));
    }

    // Preserve musl's useful zero/infinity boundaries before the general
    // NaN path.  In particular, sinh(+-Inf + i0) retains both signs.
    if x == 0.0 && !y.is_finite() {
        return cabi_cd(copysign(0.0, x * (y - y)), y - y);
    }
    if y == 0.0 && !x.is_finite() {
        if is_inf(x) {
            return cabi_cd(x, y);
        }
        return cabi_cd(x, copysign(0.0, y));
    }
    if x.is_finite() && !y.is_finite() {
        return cabi_cd(y - y, x * (y - y));
    }
    if is_inf(x) {
        // musl's exponent test covers NaN as well as infinity here:
        // sinh(+-Inf + iNaN) is +-Inf + iNaN.
        if !y.is_finite() {
            return cabi_cd(x * x, x * (y - y));
        }
        return cabi_cd(x * cos(y), f64::INFINITY * sin(y));
    }
    cabi_cd((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn cabi_ccosh_double(z: ComplexDouble) -> ComplexDouble {
    let x = z.re;
    let y = z.im;

    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return cabi_cd(cosh(x), x * y);
        }
        if x.abs() < 22.0 {
            return cabi_cd(cosh(x) * cos(y), sinh(x) * sin(y));
        }
        if x.abs() < 710.0 {
            let h = exp(x.abs()) * 0.5;
            return cabi_cd(h * cos(y), copysign(h, x) * sin(y));
        }
        if x.abs() < 1455.0 {
            let scaled = cabi_cd_scaled_exp(x.abs(), y, -1);
            return cabi_cd(scaled.re, copysign(scaled.im, x));
        }
        let h = f64::from_bits(0x7fe0000000000000) * x;
        return cabi_cd(h * h * cos(y), h * sin(y));
    }

    if x == 0.0 && !y.is_finite() {
        return cabi_cd(y - y, copysign(0.0, x * (y - y)));
    }
    if y == 0.0 && !x.is_finite() {
        if is_inf(x) {
            return cabi_cd(x * x, copysign(0.0, x) * y);
        }
        return cabi_cd(x, copysign(0.0, (x + x) * y));
    }
    if x.is_finite() && !y.is_finite() {
        return cabi_cd(y - y, x * (y - y));
    }
    if is_inf(x) {
        // Keep the NaN-imaginary branch alongside infinity, as in musl.
        if !y.is_finite() {
            return cabi_cd(x * x, x * (y - y));
        }
        return cabi_cd((x * x) * cos(y), x * sin(y));
    }
    cabi_cd((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn cabi_ctanh_double(z: ComplexDouble) -> ComplexDouble {
    let x = z.re;
    let y = z.im;

    if is_nan(x) {
        return cabi_cd(x, if y == 0.0 { y } else { x * y });
    }
    if is_inf(x) {
        return cabi_cd(
            copysign(1.0, x),
            copysign(0.0, if is_inf(y) { y } else { sin(y) * cos(y) }),
        );
    }
    if !y.is_finite() {
        return cabi_cd(if x == 0.0 { x } else { y - y }, y - y);
    }
    if x.abs() >= 22.0 {
        let e = exp(-x.abs());
        return cabi_cd(copysign(1.0, x), 4.0 * sin(y) * cos(y) * e * e);
    }

    // Kahan's stable formulation from musl's ctanh.c.
    let t = tan(y);
    let beta = 1.0 + t * t;
    let s = sinh(x);
    let rho = sqrt(1.0 + s * s);
    let denom = 1.0 + beta * s * s;
    cabi_cd((beta * rho * s) / denom, t / denom)
}

#[inline]
fn cabi_csin_double(z: ComplexDouble) -> ComplexDouble {
    let w = cabi_csinh_double(cabi_cd(-z.im, z.re));
    cabi_cd(w.im, -w.re)
}

#[inline]
fn cabi_ccos_double(z: ComplexDouble) -> ComplexDouble {
    cabi_ccosh_double(cabi_cd(-z.im, z.re))
}

#[inline]
fn cabi_ctan_double(z: ComplexDouble) -> ComplexDouble {
    let w = cabi_ctanh_double(cabi_cd(-z.im, z.re));
    cabi_cd(w.im, -w.re)
}

#[inline]
fn cabi_catan_double(z: ComplexDouble) -> ComplexDouble {
    let x = z.re;
    let y = z.im;
    let x2 = x * x;
    let a = 1.0 - x2 - y * y;
    let real = 0.5 * unsafe { atan2(2.0 * x, a) };
    let den = x2 + (y - 1.0) * (y - 1.0);
    let num = x2 + (y + 1.0) * (y + 1.0);
    cabi_cd(real, 0.25 * log(num / den))
}

#[inline]
fn cabi_casin_double(z: ComplexDouble) -> ComplexDouble {
    let x = z.re;
    let y = z.im;
    let w = cabi_cd(1.0 - (x - y) * (x + y), -2.0 * x * y);
    let r = cabi_cd_clog(cabi_cd_add(cabi_cd(-y, x), cabi_cd_sqrt(w)));
    cabi_cd(r.im, -r.re)
}

#[inline]
fn cabi_cacos_double(z: ComplexDouble) -> ComplexDouble {
    let w = cabi_casin_double(z);
    cabi_cd(1.57079632679489661923 - w.re, -w.im)
}

#[inline]
fn cabi_casinh_double(z: ComplexDouble) -> ComplexDouble {
    let w = cabi_casin_double(cabi_cd(-z.im, z.re));
    cabi_cd(w.im, -w.re)
}

#[inline]
fn cabi_cacosh_double(z: ComplexDouble) -> ComplexDouble {
    let im_negative = z.im.is_sign_negative();
    let w = cabi_cacos_double(z);
    if im_negative {
        cabi_cd(w.im, -w.re)
    } else {
        cabi_cd(-w.im, w.re)
    }
}

#[inline]
fn cabi_catanh_double(z: ComplexDouble) -> ComplexDouble {
    let w = cabi_catan_double(cabi_cd(-z.im, z.re));
    cabi_cd(w.im, -w.re)
}

#[inline]
fn cabi_cf(re: f32, im: f32) -> ComplexFloat {
    ComplexFloat { re, im }
}

#[inline]
fn cabi_cf_add(a: ComplexFloat, b: ComplexFloat) -> ComplexFloat {
    cabi_cf(a.re + b.re, a.im + b.im)
}

#[inline]
fn cabi_cf_sqrt(z: ComplexFloat) -> ComplexFloat {
    let a = z.re;
    let b = z.im;
    if a == 0.0 && b == 0.0 {
        return cabi_cf(0.0, b);
    }
    if is_inff(b) {
        return cabi_cf(f32::INFINITY, b);
    }
    if is_nanf(a) {
        return cabi_cf(a, (b - b) / (b - b));
    }
    if is_inff(a) {
        if a.is_sign_negative() {
            return cabi_cf((b - b).abs(), copysignf(a, b));
        }
        return cabi_cf(a, copysignf(b - b, b));
    }
    // Keep the Algorithm 312 intermediates in double precision, as musl's
    // csqrtf does.  Rounding the hypot/sqrt expression in float first can
    // move a result onto the rejected side of the generated one-ulp interval.
    let a = a as f64;
    let b = b as f64;
    let result = if a >= 0.0 {
        let t = sqrt((a + hypot(a, b)) * 0.5);
        cabi_cf(t as f32, (b / (2.0 * t)) as f32)
    } else {
        let t = sqrt((-a + hypot(a, b)) * 0.5);
        cabi_cf((b.abs() / (2.0 * t)) as f32, copysignf(t as f32, b as f32))
    };
    result
}

#[inline]
fn cabi_cf_clog(z: ComplexFloat) -> ComplexFloat {
    cabi_cf(logf(hypotf(z.re, z.im)), unsafe { atan2f(z.im, z.re) })
}

#[inline]
fn cabi_cf_scaled_exp(x: f32, y: f32, exponent: c_int) -> ComplexFloat {
    const K: c_int = 235;
    const K_LN2: f32 = 162.88958740;
    let reduced = expf(x - K_LN2);
    let scale = K + exponent;
    let mut reduced_exponent = 0;
    let reduced_mantissa = unsafe { frexpf(reduced, &mut reduced_exponent) };
    let normalized = scalbnf(reduced_mantissa, 127);
    let final_scale = scale + reduced_exponent - 127;
    cabi_cf(
        scalbnf(cosf(y) * normalized, final_scale),
        scalbnf(sinf(y) * normalized, final_scale),
    )
}

#[inline]
fn cabi_csinh_float(z: ComplexFloat) -> ComplexFloat {
    let x = z.re;
    let y = z.im;
    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return cabi_cf(sinhf(x), y);
        }
        if x.abs() < 11.0 {
            return cabi_cf(sinhf(x) * cosf(y), coshf(x) * sinf(y));
        }
        if x.abs() < 89.0 {
            let h = expf(x.abs()) * 0.5;
            return cabi_cf(copysignf(h, x) * cosf(y), h * sinf(y));
        }
        if x.abs() < 192.0 {
            let scaled = cabi_cf_scaled_exp(x.abs(), y, -1);
            return cabi_cf(copysignf(scaled.re, x), scaled.im);
        }
        let h = f32::from_bits(0x7f000000) * x;
        return cabi_cf(h * cosf(y), h * h * sinf(y));
    }
    if x == 0.0 && !y.is_finite() {
        return cabi_cf(copysignf(0.0, x * (y - y)), y - y);
    }
    if y == 0.0 && !x.is_finite() {
        if is_inff(x) {
            return cabi_cf(x, y);
        }
        return cabi_cf(x, copysignf(0.0, y));
    }
    if x.is_finite() && !y.is_finite() {
        return cabi_cf(y - y, x * (y - y));
    }
    if is_inff(x) {
        if !y.is_finite() {
            return cabi_cf(x * x, x * (y - y));
        }
        return cabi_cf(x * cosf(y), f32::INFINITY * sinf(y));
    }
    cabi_cf((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn cabi_ccosh_float(z: ComplexFloat) -> ComplexFloat {
    let x = z.re;
    let y = z.im;
    if x.is_finite() && y.is_finite() {
        if y == 0.0 {
            return cabi_cf(coshf(x), x * y);
        }
        if x.abs() < 11.0 {
            return cabi_cf(coshf(x) * cosf(y), sinhf(x) * sinf(y));
        }
        if x.abs() < 89.0 {
            let h = expf(x.abs()) * 0.5;
            return cabi_cf(h * cosf(y), copysignf(h, x) * sinf(y));
        }
        if x.abs() < 192.0 {
            let scaled = cabi_cf_scaled_exp(x.abs(), y, -1);
            return cabi_cf(scaled.re, copysignf(scaled.im, x));
        }
        let h = f32::from_bits(0x7f000000) * x;
        return cabi_cf(h * h * cosf(y), h * sinf(y));
    }
    if x == 0.0 && !y.is_finite() {
        return cabi_cf(y - y, copysignf(0.0, x * (y - y)));
    }
    if y == 0.0 && !x.is_finite() {
        if is_inff(x) {
            return cabi_cf(x * x, copysignf(0.0, x) * y);
        }
        return cabi_cf(x, copysignf(0.0, (x + x) * y));
    }
    if x.is_finite() && !y.is_finite() {
        return cabi_cf(y - y, x * (y - y));
    }
    if is_inff(x) {
        if !y.is_finite() {
            return cabi_cf(x * x, x * (y - y));
        }
        return cabi_cf((x * x) * cosf(y), x * sinf(y));
    }
    cabi_cf((x * x) * (y - y), (x + x) * (y - y))
}

#[inline]
fn cabi_ctanh_float(z: ComplexFloat) -> ComplexFloat {
    let x = z.re;
    let y = z.im;
    if is_nanf(x) {
        return cabi_cf(x, if y == 0.0 { y } else { x * y });
    }
    if is_inff(x) {
        return cabi_cf(
            copysignf(1.0, x),
            copysignf(0.0, if is_inff(y) { y } else { sinf(y) * cosf(y) }),
        );
    }
    if !y.is_finite() {
        return cabi_cf(if x == 0.0 { x } else { y - y }, y - y);
    }
    if x.abs() >= 11.0 {
        let e = expf(-x.abs());
        return cabi_cf(copysignf(1.0, x), 4.0 * sinf(y) * cosf(y) * e * e);
    }
    let t = tanf(y);
    let beta = 1.0f32 + t * t;
    let s = sinhf(x);
    let rho = sqrtf(1.0 + s * s);
    let denom = 1.0 + beta * s * s;
    cabi_cf((beta * rho * s) / denom, t / denom)
}

#[inline]
fn cabi_csin_float(z: ComplexFloat) -> ComplexFloat {
    let w = cabi_csinh_float(cabi_cf(-z.im, z.re));
    cabi_cf(w.im, -w.re)
}

#[inline]
fn cabi_ccos_float(z: ComplexFloat) -> ComplexFloat {
    cabi_ccosh_float(cabi_cf(-z.im, z.re))
}

#[inline]
fn cabi_ctan_float(z: ComplexFloat) -> ComplexFloat {
    let w = cabi_ctanh_float(cabi_cf(-z.im, z.re));
    cabi_cf(w.im, -w.re)
}

#[inline]
fn cabi_catan_float(z: ComplexFloat) -> ComplexFloat {
    let x = z.re;
    let y = z.im;
    let x2 = x * x;
    let a = 1.0 - x2 - y * y;
    let real = 0.5 * unsafe { atan2f(2.0 * x, a) };
    let den = x2 + (y - 1.0) * (y - 1.0);
    let num = x2 + (y + 1.0) * (y + 1.0);
    cabi_cf(real, 0.25 * logf(num / den))
}

#[inline]
fn cabi_casin_float(z: ComplexFloat) -> ComplexFloat {
    let x = z.re;
    let y = z.im;
    let w = cabi_cf(1.0 - (x - y) * (x + y), -2.0 * x * y);
    let r = cabi_cf_clog(cabi_cf_add(cabi_cf(-y, x), cabi_cf_sqrt(w)));
    cabi_cf(r.im, -r.re)
}

#[inline]
fn cabi_cacos_float(z: ComplexFloat) -> ComplexFloat {
    let w = cabi_casin_float(z);
    cabi_cf(1.5707964 - w.re, -w.im)
}

#[inline]
fn cabi_casinh_float(z: ComplexFloat) -> ComplexFloat {
    let w = cabi_casin_float(cabi_cf(-z.im, z.re));
    cabi_cf(w.im, -w.re)
}

#[inline]
fn cabi_cacosh_float(z: ComplexFloat) -> ComplexFloat {
    let im_negative = z.im.is_sign_negative();
    let w = cabi_cacos_float(z);
    if im_negative {
        cabi_cf(w.im, -w.re)
    } else {
        cabi_cf(-w.im, w.re)
    }
}

#[inline]
fn cabi_catanh_float(z: ComplexFloat) -> ComplexFloat {
    let w = cabi_catan_float(cabi_cf(-z.im, z.re));
    cabi_cf(w.im, -w.re)
}

// Export the double and float entry points.  Select the ABI path at compile
// time so the fallback body is not left as unreachable code in native builds.


macro_rules! cabi_export_complex_double {
    ($($name:ident => $long:ident),* $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name(z: ComplexDouble) -> ComplexDouble {
                cabi_long_to_double($long(cabi_double_to_long(z)))
            }
        )*
    };
}



cabi_export_complex_double!(
    cexp => cexpl,
    clog => clogl,
    csin => csinl,
    ccos => ccosl,
    ctan => ctanl,
    csqrt => csqrtl,
    csinh => csinhl,
    ccosh => ccoshl,
    ctanh => ctanhl,
    casin => casinl,
    cacos => cacosl,
    catan => catanl,
    casinh => casinhl,
    cacosh => cacoshl,
    catanh => catanhl,
);



macro_rules! cabi_export_complex_float {
    ($($name:ident => $long:ident),* $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name(z: ComplexFloat) -> ComplexFloat {
                cabi_long_to_float($long(cabi_float_to_long(z)))
            }
        )*
    };
}



cabi_export_complex_float!(
    cexpf => cexpl,
    clogf => clogl,
    csinf => csinl,
    ccosf => ccosl,
    ctanf => ctanl,
    csqrtf => csqrtl,
    csinhf => csinhl,
    ccoshf => ccoshl,
    ctanhf => ctanhl,
    casinf => casinl,
    cacosf => cacosl,
    catanf => catanl,
    casinhf => casinhl,
    cacoshf => cacoshl,
    catanhf => catanhl,
);



// x86_64 uses the 64-bit long-double ABI, so these are aliases at the ABI
// boundary.  AArch64 uses native binary128 implementations below.  RISC-V
// retains the preexisting f64 compatibility boundary used by math_compat.rs.












// The native AArch64 long-double ABI is binary128. These inverse functions
// therefore bypass the legacy f64 compatibility aliases above.
#[no_mangle]
pub extern "C" fn casinl(z: ComplexLong) -> ComplexLong { f128_casin(z) }

#[no_mangle]
pub extern "C" fn cacosl(z: ComplexLong) -> ComplexLong { f128_cacos(z) }

#[no_mangle]
pub extern "C" fn catanl(z: ComplexLong) -> ComplexLong { f128_catan(z) }

#[no_mangle]
pub extern "C" fn casinhl(z: ComplexLong) -> ComplexLong { f128_casinh(z) }

#[no_mangle]
pub extern "C" fn cacoshl(z: ComplexLong) -> ComplexLong { f128_cacosh(z) }

#[no_mangle]
pub extern "C" fn catanhl(z: ComplexLong) -> ComplexLong { f128_catanh(z) }
