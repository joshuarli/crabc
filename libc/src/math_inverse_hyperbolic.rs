// Translated from musl: acosh.c, acoshf.c, asinh.c, asinhf.c.
//
// The range reductions here are important.  The direct definitions from
// libm are numerically adequate for ordinary inputs, but they do not make
// this libc's IEEE domain, signed-zero, and large-argument behavior explicit.

// acosh(x) = log(x + sqrt(x*x - 1))
#[no_mangle]
pub extern "C" fn acosh(x: f64) -> f64 {
    let e = (asuint64(x) >> 52) & 0x7ff;

    // x < 1 is a domain error in the called sqrt/log operation.  Reducing
    // x-1 first also avoids cancellation close to x == 1.
    if e < 0x3ff + 1 {
        let xm1 = x - 1.0;
        return invhyper_log1p(xm1 + sqrt(xm1 * xm1 + 2.0 * xm1));
    }
    if e < 0x3ff + 26 {
        return log(2.0 * x - 1.0 / (x + sqrt(x * x - 1.0)));
    }

    // For sufficiently large x, sqrt(x*x-1) rounds to x and the correction
    // is below one ulp.  This path also naturally gives NaN for NaN and
    // negative infinity through log, while +infinity remains +infinity.
    log(x) + 0.693147180559945309417232121458176568
}

// acoshf(x) = logf(x + sqrtf(x*x - 1))
#[no_mangle]
pub extern "C" fn acoshf(x: f32) -> f32 {
    let a = asuint(x) & 0x7fff_ffff;

    if a < 0x3f800000 + (1 << 23) {
        let xm1 = x - 1.0;
        return invhyper_log1pf(xm1 + sqrtf(xm1 * xm1 + 2.0 * xm1));
    }
    if a < 0x3f800000 + (12 << 23) {
        return logf(2.0 * x - 1.0 / (x + sqrtf(x * x - 1.0)));
    }

    logf(x) + 0.693147180559945309417232121458176568f32
}

// asinh(x) = sign(x) * log(|x| + sqrt(x*x + 1))
#[no_mangle]
pub extern "C" fn asinh(x: f64) -> f64 {
    let bits = asuint64(x);
    let e = (bits >> 52) & 0x7ff;
    let sign = bits >> 63;
    let mut ax = asdouble(bits & 0x7fff_ffff_ffff_ffff);

    if e >= 0x3ff + 26 {
        // |x| >= 2^26, including infinities and NaNs.
        ax = log(ax) + 0.693147180559945309417232121458176568;
    } else if e >= 0x3ff + 1 {
        ax = log(2.0 * ax + 1.0 / (sqrt(ax * ax + 1.0) + ax));
    } else if e >= 0x3ff - 26 {
        ax = invhyper_log1p(ax + ax * ax / (sqrt(ax * ax + 1.0) + 1.0));
    } else {
        // Preserve the exact input (including signed zero), while making a
        // nonzero tiny argument raise the inexact flag as musl does.
        force_eval(ax + asdouble(0x4770_0000_0000_0000));
    }

    if sign != 0 { -ax } else { ax }
}

// asinhf(x) = sign(x) * logf(|x| + sqrtf(x*x + 1))
#[no_mangle]
pub extern "C" fn asinhf(x: f32) -> f32 {
    let bits = asuint(x);
    let a = bits & 0x7fff_ffff;
    let sign = bits >> 31;
    let mut ax = asfloat(a);

    if a >= 0x3f800000 + (12 << 23) {
        ax = logf(ax) + 0.693147180559945309417232121458176568f32;
    } else if a >= 0x3f800000 + (1 << 23) {
        ax = logf(2.0 * ax + 1.0 / (sqrtf(ax * ax + 1.0) + ax));
    } else if a >= 0x3f800000 - (12 << 23) {
        ax = invhyper_log1pf(ax + ax * ax / (sqrtf(ax * ax + 1.0) + 1.0));
    } else {
        force_eval(ax + asfloat(0x7b80_0000));
    }

    if sign != 0 { -ax } else { ax }
}

// musl's log1p reduction, kept private because this slice only needs the
// accuracy of log1p around the reduced arguments produced above.
#[inline]
fn invhyper_log1p(x: f64) -> f64 {
    const LN2_HI: f64 = asdouble(0x3fe6_2e42_fee0_0000);
    const LN2_LO: f64 = asdouble(0x3dea_39ef_3579_3c76);
    const LG1: f64 = 6.666666666666735130e-01;
    const LG2: f64 = 3.999999999940941908e-01;
    const LG3: f64 = 2.857142874366239149e-01;
    const LG4: f64 = 2.222219843214978396e-01;
    const LG5: f64 = 1.818357216161805012e-01;
    const LG6: f64 = 1.531383769920937332e-01;
    const LG7: f64 = 1.479819860511658591e-01;

    let hx = (asuint64(x) >> 32) as u32;
    let mut k: i32 = 1;
    let f: f64;
    let c: f64;

    if hx < 0x3fda_827a || (hx >> 31) != 0 {
        if hx >= 0xbff0_0000 {
            if x == -1.0 { return __math_divzero(1); }
            return __math_invalid(x);
        }
        if (hx << 1) < (0x3ca0_0000 << 1) {
            if hx & 0x7ff0_0000 == 0 { force_eval(x as f32); }
            return x;
        }
        if hx <= 0xbfd2_bec4 {
            k = 0;
            c = 0.0;
            f = x;
        } else {
            f = 0.0;
            c = 0.0;
        }
    } else if hx >= 0x7ff0_0000 {
        return x;
    } else {
        f = 0.0;
        c = 0.0;
    }

    let (f, c, k) = if k != 0 {
        let u = 1.0 + x;
        let mut ui = asuint64(u);
        let mut hu = (ui >> 32) as u32;
        hu = hu.wrapping_add(0x3ff0_0000 - 0x3fe6_a09e);
        let k = (hu >> 20) as i32 - 0x3ff;
        let c = if k < 54 {
            let c = if k >= 2 { 1.0 - (u - x) } else { x - (u - 1.0) };
            c / u
        } else {
            0.0
        };
        hu = (hu & 0x000f_ffff) + 0x3fe6_a09e;
        ui = (ui & 0xffff_ffff) | ((hu as u64) << 32);
        (asdouble(ui) - 1.0, c, k)
    } else {
        (f, c, k)
    };

    let hfsq = 0.5 * f * f;
    let s = f / (2.0 + f);
    let z = s * s;
    let w = z * z;
    let t1 = w * (LG2 + w * (LG4 + w * LG6));
    let t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
    let r = t2 + t1;
    let dk = k as f64;
    s * (hfsq + r) + (dk * LN2_LO + c) - hfsq + f + dk * LN2_HI
}

#[inline]
fn invhyper_log1pf(x: f32) -> f32 {
    const LN2_HI: f32 = asfloat(0x3f31_7180);
    const LN2_LO: f32 = asfloat(0x3717_f7d1);
    const LG1: f32 = asfloat(0x3f2a_aaaa);
    const LG2: f32 = asfloat(0x3ecc_ce13);
    const LG3: f32 = asfloat(0x3e91_e9ee);
    const LG4: f32 = asfloat(0x3e78_9e26);

    let ix = asuint(x);
    let mut k: i32 = 1;
    let f: f32;
    let c: f32;

    if ix < 0x3ed4_13d0 || (ix >> 31) != 0 {
        if ix >= 0xbf80_0000 {
            if x == -1.0 { return __math_divzerof(1); }
            return __math_invalidf(x);
        }
        if (ix << 1) < (0x3380_0000 << 1) {
            if ix & 0x7f80_0000 == 0 { force_eval(x * x); }
            return x;
        }
        if ix <= 0xbe95_f619 {
            k = 0;
            c = 0.0;
            f = x;
        } else {
            f = 0.0;
            c = 0.0;
        }
    } else if ix >= 0x7f80_0000 {
        return x;
    } else {
        f = 0.0;
        c = 0.0;
    }

    let (f, c, k) = if k != 0 {
        let u = 1.0f32 + x;
        let mut iu = asuint(u);
        iu = iu.wrapping_add(0x3f80_0000 - 0x3f35_04f3);
        let k = (iu >> 23) as i32 - 0x7f;
        let c = if k < 25 {
            let c = if k >= 2 { 1.0 - (u - x) } else { x - (u - 1.0) };
            c / u
        } else {
            0.0
        };
        iu = (iu & 0x007f_ffff) + 0x3f35_04f3;
        (asfloat(iu) - 1.0, c, k)
    } else {
        (f, c, k)
    };

    let s = f / (2.0 + f);
    let z = s * s;
    let w = z * z;
    let t1 = w * (LG2 + w * LG4);
    let t2 = z * (LG1 + w * LG3);
    let r = t2 + t1;
    let hfsq = 0.5 * f * f;
    let dk = k as f32;
    s * (hfsq + r) + (dk * LN2_LO + c) - hfsq + f + dk * LN2_HI
}
