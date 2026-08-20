// M4 C99 complex-power exports.
//
// musl defines cpow(z, c) as cexp(c * clog(z)) and cpowf likewise.  Keep
// that reduction visible here instead of routing through a real libm power:
// clog supplies the principal branch for the base, while cexp supplies the
// corresponding exceptional-value behavior.  The products are written out
// at the Rust ABI boundary so the libc does not need a compiler-provided
// __muldc3/__mulsc3 helper.

#[inline]
fn m4_cd_mul(a: M4ComplexDouble, b: M4ComplexDouble) -> M4ComplexDouble {
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

    m4_cd(re, im)
}

#[inline]
fn m4_cf_mul(a: M4ComplexFloat, b: M4ComplexFloat) -> M4ComplexFloat {
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

    m4_cf(re, im)
}

#[inline]
fn m4_cpow_double(z: M4ComplexDouble, c: M4ComplexDouble) -> M4ComplexDouble {
    m4_cd_exp(m4_cd_mul(c, m4_cd_clog(z)))
}

#[inline]
fn m4_cpow_float(z: M4ComplexFloat, c: M4ComplexFloat) -> M4ComplexFloat {
    cexpf(m4_cf_mul(c, m4_cf_clog(z)))
}

// Export the double and float entry points.  Keep the float reduction in
// terms of the float helpers, matching musl's cpowf.c rather than narrowing
// through the double implementation.
#[no_mangle]
pub extern "C" fn cpow(z: M4ComplexDouble, c: M4ComplexDouble) -> M4ComplexDouble {
    m4_cpow_double(z, c)
}

#[no_mangle]
pub extern "C" fn cpowf(z: M4ComplexFloat, c: M4ComplexFloat) -> M4ComplexFloat {
    m4_cpow_float(z, c)
}

// x86_64 follows musl's 64-bit long-double ABI, so cpowl is the same ABI as
// cpow.  AArch64/riscv64 carry binary128 complex values across the public
// boundary; use the existing f64 compatibility boundary after preserving
// that layout.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn cpowl(z: M4ComplexLong, c: M4ComplexLong) -> M4ComplexLong {
    m4_cpow_double(z, c)
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn cpowl(z: M4ComplexLong, c: M4ComplexLong) -> M4ComplexLong {
    // musl's cpowl.c uses cexpl(c * clogl(z)) for binary128 long double.
    // Existing complex transcendentals intentionally use f64-compatible
    // arithmetic, so convert each operand only after receiving its ABI-
    // correct binary128 pair and convert the result back before returning.
    let z = m4_cl_to_double(z);
    let c = m4_cl_to_double(c);
    m4_cl_from_double(m4_cpow_double(z, c))
}
