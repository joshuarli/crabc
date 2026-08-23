// C99 complex-power exports.
//
// musl defines cpow(z, c) as cexp(c * clog(z)) and cpowf likewise.  Keep
// that reduction visible here instead of routing through a real libm power:
// clog supplies the principal branch for the base, while cexp supplies the
// corresponding exceptional-value behavior.  The products are written out
// at the Rust ABI boundary so the libc does not need a compiler-provided
// __muldc3/__mulsc3 helper.

#[inline]
fn cabi_cd_mul(a: ComplexDouble, b: ComplexDouble) -> ComplexDouble {
    // This is the recovery step used by the compiler's __muldc3 helper.
    // The ordinary component products are correct for finite values, but
    // 0*Inf can turn an otherwise recoverable infinite complex product into
    // NaN+iNaN.  musl's `c * clog(z)` is lowered through that C99 operation,
    // so preserve its Annex G special-value behavior at this boundary.
    let ac = a.re * b.re;
    let bd = a.im * b.im;
    let ad = a.re * b.im;
    let bc = a.im * b.re;
    let mut re = ac - bd;
    let mut im = ad + bc;

    if is_nan(re) && is_nan(im) {
        let mut ar = a.re;
        let mut ai = a.im;
        let mut br = b.re;
        let mut bi = b.im;
        let mut recalculate = false;
        if is_inf(ar) || is_inf(ai) {
            ar = copysign(if is_inf(ar) { 1.0 } else { 0.0 }, ar);
            ai = copysign(if is_inf(ai) { 1.0 } else { 0.0 }, ai);
            if is_nan(br) {
                br = copysign(0.0, br);
            }
            if is_nan(bi) {
                bi = copysign(0.0, bi);
            }
            recalculate = true;
        }
        if is_inf(br) || is_inf(bi) {
            br = copysign(if is_inf(br) { 1.0 } else { 0.0 }, br);
            bi = copysign(if is_inf(bi) { 1.0 } else { 0.0 }, bi);
            if is_nan(ar) {
                ar = copysign(0.0, ar);
            }
            if is_nan(ai) {
                ai = copysign(0.0, ai);
            }
            recalculate = true;
        }
        if !recalculate && (is_inf(ac) || is_inf(bd) || is_inf(ad) || is_inf(bc)) {
            if is_nan(ar) {
                ar = copysign(0.0, ar);
            }
            if is_nan(ai) {
                ai = copysign(0.0, ai);
            }
            if is_nan(br) {
                br = copysign(0.0, br);
            }
            if is_nan(bi) {
                bi = copysign(0.0, bi);
            }
            recalculate = true;
        }
        if recalculate {
            re = f64::INFINITY * (ar * br - ai * bi);
            im = f64::INFINITY * (ar * bi + ai * br);
        }
    }

    cabi_cd(re, im)
}

#[inline]
fn cabi_cf_mul(a: ComplexFloat, b: ComplexFloat) -> ComplexFloat {
    let ac = a.re * b.re;
    let bd = a.im * b.im;
    let ad = a.re * b.im;
    let bc = a.im * b.re;
    let mut re = ac - bd;
    let mut im = ad + bc;

    if is_nanf(re) && is_nanf(im) {
        let mut ar = a.re;
        let mut ai = a.im;
        let mut br = b.re;
        let mut bi = b.im;
        let mut recalculate = false;
        if is_inff(ar) || is_inff(ai) {
            ar = copysignf(if is_inff(ar) { 1.0 } else { 0.0 }, ar);
            ai = copysignf(if is_inff(ai) { 1.0 } else { 0.0 }, ai);
            if is_nanf(br) {
                br = copysignf(0.0, br);
            }
            if is_nanf(bi) {
                bi = copysignf(0.0, bi);
            }
            recalculate = true;
        }
        if is_inff(br) || is_inff(bi) {
            br = copysignf(if is_inff(br) { 1.0 } else { 0.0 }, br);
            bi = copysignf(if is_inff(bi) { 1.0 } else { 0.0 }, bi);
            if is_nanf(ar) {
                ar = copysignf(0.0, ar);
            }
            if is_nanf(ai) {
                ai = copysignf(0.0, ai);
            }
            recalculate = true;
        }
        if !recalculate && (is_inff(ac) || is_inff(bd) || is_inff(ad) || is_inff(bc)) {
            if is_nanf(ar) {
                ar = copysignf(0.0, ar);
            }
            if is_nanf(ai) {
                ai = copysignf(0.0, ai);
            }
            if is_nanf(br) {
                br = copysignf(0.0, br);
            }
            if is_nanf(bi) {
                bi = copysignf(0.0, bi);
            }
            recalculate = true;
        }
        if recalculate {
            re = f32::INFINITY * (ar * br - ai * bi);
            im = f32::INFINITY * (ar * bi + ai * br);
        }
    }

    cabi_cf(re, im)
}

#[inline]
fn cabi_cpow_double(z: ComplexDouble, c: ComplexDouble) -> ComplexDouble {
    cabi_cd_exp(cabi_cd_mul(c, cabi_cd_clog(z)))
}

#[inline]
fn cabi_cpow_float(z: ComplexFloat, c: ComplexFloat) -> ComplexFloat {
    cexpf(cabi_cf_mul(c, cabi_cf_clog(z)))
}

// Export the double and float entry points.  Keep the float reduction in
// terms of the float helpers, matching musl's cpowf.c rather than narrowing
// through the double implementation.
#[no_mangle]
pub extern "C" fn cpow(z: ComplexDouble, c: ComplexDouble) -> ComplexDouble {
    cabi_long_to_double(cpowl(cabi_double_to_long(z), cabi_double_to_long(c)))
}

#[no_mangle]
pub extern "C" fn cpowf(z: ComplexFloat, c: ComplexFloat) -> ComplexFloat {
    cabi_long_to_float(cpowl(cabi_float_to_long(z), cabi_float_to_long(c)))
}
