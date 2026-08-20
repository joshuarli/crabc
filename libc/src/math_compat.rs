// ============================================================
// Remaining C99/POSIX math entry points
//
// The crate already carries `libm` for algorithms that have not yet been
// ported literally from musl.  Keep these exports in one place so the
// boundary is explicit: a function moves to the dedicated math_*.rs port as
// soon as its musl algorithm is brought in, at which point this adapter is
// removed.  AArch64 and riscv64 use the C ABI's binary128 `long double`, so
// every *l entry point below has a target-specific ABI-correct declaration.
// ============================================================

// musl keeps __fpclassifyl as a real ABI entry point.  crabc follows the
// target C ABI: x86_64 is configured with binary64 long double, while
// AArch64 and riscv64 pass IEEE binary128 in registers/stack slots described
// by Rust's f128.  Classify the representation directly so subnormals and
// non-canonical NaNs do not get narrowed through f64.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn __fpclassifyl(x: f64) -> c_int {
    let bits = x.to_bits();
    let exponent = (bits >> 52) & 0x7ff;
    if exponent == 0 {
        if (bits << 1) != 0 { FP_SUBNORMAL } else { FP_ZERO }
    } else if exponent == 0x7ff {
        if (bits << 12) != 0 { FP_NAN } else { FP_INFINITE }
    } else {
        FP_NORMAL
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn __fpclassifyl(x: f128) -> c_int {
    let bits = x.to_bits();
    let exponent = (bits >> 112) & 0x7fff;
    let fraction = bits & ((1u128 << 112) - 1);
    if exponent == 0 {
        if fraction != 0 { FP_SUBNORMAL } else { FP_ZERO }
    } else if exponent == 0x7fff {
        if fraction != 0 { FP_NAN } else { FP_INFINITE }
    } else {
        FP_NORMAL
    }
}

macro_rules! compat_unary {
    ($double:ident, $float:ident, $double_impl:path, $float_impl:path) => {
        #[no_mangle]
        pub extern "C" fn $double(x: f64) -> f64 { $double_impl(x) }
        #[no_mangle]
        pub extern "C" fn $float(x: f32) -> f32 { $float_impl(x) }
    };
}

macro_rules! compat_binary {
    ($double:ident, $float:ident, $double_impl:path, $float_impl:path) => {
        #[no_mangle]
        pub extern "C" fn $double(x: f64, y: f64) -> f64 { $double_impl(x, y) }
        #[no_mangle]
        pub extern "C" fn $float(x: f32, y: f32) -> f32 { $float_impl(x, y) }
    };
}

macro_rules! compat_long_unary {
    ($long:ident, $implementation:path) => {
        #[cfg(target_arch = "x86_64")]
        #[no_mangle]
        pub extern "C" fn $long(x: f64) -> f64 { $implementation(x) }
        #[cfg(not(target_arch = "x86_64"))]
        #[no_mangle]
        pub extern "C" fn $long(x: f128) -> f128 { $implementation(x as f64) as f128 }
    };
}

macro_rules! compat_long_unary_weak {
    ($long:ident, $implementation:path) => {
        #[cfg(target_arch = "x86_64")]
        #[no_mangle]
        #[linkage = "weak"]
        pub extern "C" fn $long(x: f64) -> f64 { $implementation(x) }
        #[cfg(not(target_arch = "x86_64"))]
        #[no_mangle]
        #[linkage = "weak"]
        pub extern "C" fn $long(x: f128) -> f128 { $implementation(x as f64) as f128 }
    };
}

macro_rules! compat_long_binary {
    ($long:ident, $implementation:path) => {
        #[cfg(target_arch = "x86_64")]
        #[no_mangle]
        pub extern "C" fn $long(x: f64, y: f64) -> f64 { $implementation(x, y) }
        #[cfg(not(target_arch = "x86_64"))]
        #[no_mangle]
        pub extern "C" fn $long(x: f128, y: f128) -> f128 {
            $implementation(x as f64, y as f64) as f128
        }
    };
}

macro_rules! compat_long_ternary {
    ($long:ident, $implementation:path) => {
        #[cfg(target_arch = "x86_64")]
        #[no_mangle]
        pub extern "C" fn $long(x: f64, y: f64, z: f64) -> f64 { $implementation(x, y, z) }
        #[cfg(not(target_arch = "x86_64"))]
        #[no_mangle]
        pub extern "C" fn $long(x: f128, y: f128, z: f128) -> f128 {
            $implementation(x as f64, y as f64, z as f64) as f128
        }
    };
}

macro_rules! compat_long_to_int {
    ($long:ident, $implementation:path, $result:ty) => {
        #[cfg(target_arch = "x86_64")]
        #[no_mangle]
        pub extern "C" fn $long(x: f64) -> $result { $implementation(x) as $result }
        #[cfg(not(target_arch = "x86_64"))]
        #[no_mangle]
        pub extern "C" fn $long(x: f128) -> $result { $implementation(x as f64) as $result }
    };
}

compat_unary!(atanh, atanhf, libm::atanh, libm::atanhf);
compat_unary!(cbrt, cbrtf, libm::cbrt, libm::cbrtf);
compat_unary!(erf, erff, libm::erf, libm::erff);
compat_unary!(erfc, erfcf, libm::erfc, libm::erfcf);
compat_unary!(exp2, exp2f, libm::exp2, libm::exp2f);
// expm1/expm1f are implemented by the musl-derived hyperbolic slice.  The
// libm adapters that originally lived here lose the required underflow and
// directed-rounding status behavior at the small and negative-large edges.
#[no_mangle]
pub extern "C" fn expm1(x: f64) -> f64 {
    if x.is_sign_negative() && x.is_finite() {
        // expm1(x) cannot overflow for a negative finite x.  The reduced
        // polynomial may nevertheless set OFC on AArch64 while evaluating a
        // discarded intermediate; keep the caller's prior OFC state but
        // suppress that spurious status.
        unsafe {
            let prior = fetestexcept(FE_OVERFLOW);
            feclearexcept(FE_OVERFLOW);
            let result = hyper_expm1(x);
            feclearexcept(FE_OVERFLOW);
            if prior != 0 { feraiseexcept(FE_OVERFLOW); }
            result
        }
    } else {
        hyper_expm1(x)
    }
}
#[no_mangle]
pub extern "C" fn expm1f(x: f32) -> f32 {
    if x.is_sign_negative() && x.is_finite() {
        unsafe {
            let prior = fetestexcept(FE_OVERFLOW);
            feclearexcept(FE_OVERFLOW);
            let result = hyper_expm1f(x);
            feclearexcept(FE_OVERFLOW);
            if prior != 0 { feraiseexcept(FE_OVERFLOW); }
            result
        }
    } else {
        hyper_expm1f(x)
    }
}
#[no_mangle]
pub extern "C" fn log1p(x: f64) -> f64 {
    if x == -1.0 { return __math_divzero(1); }
    libm::log1p(x)
}
#[no_mangle]
pub extern "C" fn log1pf(x: f32) -> f32 {
    if x == -1.0 { return __math_divzerof(1); }
    libm::log1pf(x)
}

compat_binary!(nextafter, nextafterf, libm::nextafter, libm::nextafterf);
compat_binary!(remainder, remainderf, libm::remainder, libm::remainderf);

#[no_mangle]
pub extern "C" fn fdim(x: f64, y: f64) -> f64 {
    if is_nan(x) { return x; }
    if is_nan(y) { return y; }
    if x <= y { 0.0 } else { x - y }
}
#[no_mangle]
pub extern "C" fn fdimf(x: f32, y: f32) -> f32 {
    if is_nanf(x) { return x; }
    if is_nanf(y) { return y; }
    if x <= y { 0.0 } else { x - y }
}

#[no_mangle]
pub extern "C" fn fmax(x: f64, y: f64) -> f64 {
    if is_nan(x) { return y; }
    if is_nan(y) { return x; }
    if x == y {
        if x == 0.0 { if x.is_sign_negative() && y.is_sign_negative() { -0.0 } else { 0.0 } } else { x }
    } else if x > y { x } else { y }
}
#[no_mangle]
pub extern "C" fn fmaxf(x: f32, y: f32) -> f32 {
    if is_nanf(x) { return y; }
    if is_nanf(y) { return x; }
    if x == y {
        if x == 0.0 { if x.is_sign_negative() && y.is_sign_negative() { -0.0 } else { 0.0 } } else { x }
    } else if x > y { x } else { y }
}
#[no_mangle]
pub extern "C" fn fmin(x: f64, y: f64) -> f64 {
    if is_nan(x) { return y; }
    if is_nan(y) { return x; }
    if x == y {
        if x == 0.0 && (x.is_sign_negative() || y.is_sign_negative()) { -0.0 } else { x }
    } else if x < y { x } else { y }
}
#[no_mangle]
pub extern "C" fn fminf(x: f32, y: f32) -> f32 {
    if is_nanf(x) { return y; }
    if is_nanf(y) { return x; }
    if x == y {
        if x == 0.0 && (x.is_sign_negative() || y.is_sign_negative()) { -0.0 } else { x }
    } else if x < y { x } else { y }
}

#[no_mangle]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 { libm::fma(x, y, z) }
#[no_mangle]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 { libm::fmaf(x, y, z) }

compat_long_unary!(acoshl, libm::acosh);
compat_long_unary!(acosl, libm::acos);
compat_long_unary!(asinhl, libm::asinh);
compat_long_unary!(asinl, libm::asin);
compat_long_unary!(atanhl, libm::atanh);
compat_long_unary!(atanl, libm::atan);
#[cfg(target_arch = "x86_64")]
compat_long_binary!(atan2l, libm::atan2);
compat_long_unary!(cbrtl, libm::cbrt);
compat_long_unary!(ceill, ceil);
compat_long_binary!(copysignl, copysign);
compat_long_unary!(coshl, cosh);
compat_long_unary!(cosl, cos);
compat_long_unary!(erfcl, libm::erfc);
compat_long_unary!(erfl, libm::erf);
compat_long_unary!(exp2l, libm::exp2);
compat_long_unary!(expl, exp);
compat_long_unary!(expm1l, libm::expm1);
compat_long_unary!(fabsl, fabs);
compat_long_binary!(fdiml, libm::fdim);
compat_long_ternary!(fmal, libm::fma);
compat_long_unary!(floorl, floor);
compat_long_binary!(fmaxl, libm::fmax);
compat_long_binary!(fminl, libm::fmin);
compat_long_binary!(fmodl, fmod);
#[cfg(target_arch = "x86_64")]
compat_long_binary!(hypotl, hypot);
compat_long_unary!(log10l, log10);
compat_long_unary!(log1pl, libm::log1p);
compat_long_unary!(log2l, log2);
compat_long_unary!(logl, log);
compat_long_binary!(nextafterl, libm::nextafter);
compat_long_binary!(powl, pow);
compat_long_binary!(remainderl, libm::remainder);
compat_long_unary!(roundl, round);
compat_long_unary!(sinhl, sinh);
compat_long_unary!(sinl, sin);
compat_long_unary!(sqrtl, sqrt);
compat_long_unary!(tanhl, tanh);
compat_long_unary!(tanl, tan);
compat_long_unary!(truncl, trunc);

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn drem(x: f64, y: f64) -> f64 { libm::remainder(x, y) }
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn dremf(x: f32, y: f32) -> f32 { libm::remainderf(x, y) }

#[no_mangle]
pub extern "C" fn exp10(x: f64) -> f64 { libm::pow(10.0, x) }
#[no_mangle]
pub extern "C" fn exp10f(x: f32) -> f32 { libm::powf(10.0, x) }
compat_long_unary!(exp10l, exp10);
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn pow10(x: f64) -> f64 { exp10(x) }
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn pow10f(x: f32) -> f32 { exp10f(x) }
compat_long_unary_weak!(pow10l, exp10);

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn frexpl(x: f64, exponent: *mut c_int) -> f64 {
    frexp(x, exponent)
}
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn frexpl(x: f128, exponent: *mut c_int) -> f128 {
    frexp(x as f64, exponent) as f128
}

#[no_mangle]
pub extern "C" fn ilogb(x: f64) -> c_int {
    if x == 0.0 || is_nan(x) || is_inf(x) { unsafe { feraiseexcept(FE_INVALID); } }
    libm::ilogb(x)
}
#[no_mangle]
pub extern "C" fn ilogbf(x: f32) -> c_int {
    if x == 0.0 || is_nanf(x) || is_inff(x) { unsafe { feraiseexcept(FE_INVALID); } }
    libm::ilogbf(x)
}
compat_long_to_int!(ilogbl, libm::ilogb, c_int);

#[no_mangle]
pub extern "C" fn j1(x: f64) -> f64 { libm::j1(x) }
#[no_mangle]
pub extern "C" fn j1f(x: f32) -> f32 { libm::j1f(x) }
#[no_mangle]
pub extern "C" fn j0f(x: f32) -> f32 { libm::j0f(x) }
#[no_mangle]
pub extern "C" fn jnf(n: c_int, x: f32) -> f32 { libm::jnf(n, x) }
#[no_mangle]
pub extern "C" fn y0f(x: f32) -> f32 {
    if x == 0.0 { return __math_divzerof(1); }
    if x < 0.0 { return __math_invalidf(x); }
    libm::y0f(x)
}
#[no_mangle]
pub extern "C" fn ynf(n: c_int, x: f32) -> f32 {
    if x == 0.0 {
        return __math_divzerof(if n < 0 && (n & 1) != 0 { 0 } else { 1 });
    }
    if x < 0.0 { return __math_invalidf(x); }
    libm::ynf(n, x)
}
#[no_mangle]
pub extern "C" fn y1(x: f64) -> f64 {
    if x == 0.0 { return __math_divzero(1); }
    if x < 0.0 { return __math_invalid(x); }
    libm::y1(x)
}
#[no_mangle]
pub extern "C" fn y1f(x: f32) -> f32 {
    if x == 0.0 { return __math_divzerof(1); }
    if x < 0.0 { return __math_invalidf(x); }
    libm::y1f(x)
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ldexpl(x: f64, exponent: c_int) -> f64 { ldexp(x, exponent) }
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn ldexpl(x: f128, exponent: c_int) -> f128 {
    ldexp(x as f64, exponent) as f128
}

compat_long_unary!(lgammal, libm::lgamma);
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn lgammal_r(x: f64, sign: *mut c_int) -> f64 { lgamma_r_impl(x, sign) }
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn lgammal_r(x: f128, sign: *mut c_int) -> f128 {
    lgamma_r_impl(x as f64, sign) as f128
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __lgammal_r(x: f64, sign: *mut c_int) -> f64 {
    lgamma_r_impl(x, sign)
}
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn __lgammal_r(x: f128, sign: *mut c_int) -> f128 {
    lgamma_r_impl(x as f64, sign) as f128
}

#[no_mangle]
pub extern "C" fn llround(x: f64) -> c_longlong { round(x) as c_longlong }
#[no_mangle]
pub extern "C" fn llroundf(x: f32) -> c_longlong { roundf(x) as c_longlong }
compat_long_to_int!(llroundl, round, c_longlong);
#[no_mangle]
pub extern "C" fn lround(x: f64) -> c_long { round(x) as c_long }
#[no_mangle]
pub extern "C" fn lroundf(x: f32) -> c_long { roundf(x) as c_long }
compat_long_to_int!(lroundl, round, c_long);

#[no_mangle]
pub extern "C" fn logb(x: f64) -> f64 {
    if x == 0.0 { return __math_divzero(1); }
    if x.is_nan() || x.is_infinite() { return x.abs(); }
    libm::ilogb(x) as f64
}
#[no_mangle]
pub extern "C" fn logbf(x: f32) -> f32 {
    if x == 0.0 { return __math_divzerof(1); }
    if x.is_nan() || x.is_infinite() { return x.abs(); }
    libm::ilogbf(x) as f32
}
compat_long_unary!(logbl, logb);

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn modfl(x: f64, integer: *mut f64) -> f64 { modf(x, integer) }
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn modfl(x: f128, integer: *mut f128) -> f128 {
    let mut integral = 0.0;
    let fraction = modf(x as f64, &mut integral);
    if !integer.is_null() { *integer = integral as f128; }
    fraction as f128
}

#[no_mangle]
pub unsafe extern "C" fn nearbyint(x: f64) -> f64 {
    // AArch64 has a dedicated current-rounding instruction that suppresses
    // FE_INEXACT.  Calling rint here lets LLVM legally lower the operation to
    // FRINTX after the environment-restoration sequence, which reintroduces
    // the very flag nearbyint is required to avoid.
    #[cfg(target_arch = "aarch64")]
    {
        let result: f64;
        core::arch::asm!(
            "frinti {result:d}, {input:d}",
            result = out(vreg) result,
            input = in(vreg) x,
            options(nostack),
        );
        return result;
    }

    // rint uses ordinary arithmetic to honor the current rounding mode.  On
    // x86 that arithmetic may set the x87 status word even after MXCSR is
    // cleared, so save and restore the complete environment and then replay
    // every newly raised exception except FE_INEXACT (nearbyint's contract).
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut env = core::mem::MaybeUninit::<fenv_t>::uninit();
        fegetenv(env.as_mut_ptr());
        let before = fetestexcept(FE_ALL_EXCEPT);
        let result = rint(x);
        let after = fetestexcept(FE_ALL_EXCEPT);
        fesetenv(env.as_ptr());
        // Some targets report the arithmetic status through a second FP status
        // register when the saved environment is restored.  Make the one
        // deliberately suppressed flag explicit after restoration as well.
        feclearexcept(FE_INEXACT);
        if before & FE_INEXACT != 0 { feraiseexcept(FE_INEXACT); }
        let raised = (after & !before) & !FE_INEXACT;
        if raised != 0 { feraiseexcept(raised); }
        return result;
    }
}
#[no_mangle]
pub unsafe extern "C" fn nearbyintf(x: f32) -> f32 {
    #[cfg(target_arch = "aarch64")]
    {
        let result: f32;
        core::arch::asm!(
            "frinti {result:s}, {input:s}",
            result = out(vreg) result,
            input = in(vreg) x,
            options(nostack),
        );
        result
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut env = core::mem::MaybeUninit::<fenv_t>::uninit();
        fegetenv(env.as_mut_ptr());
        let before = fetestexcept(FE_ALL_EXCEPT);
        let result = rintf(x);
        let after = fetestexcept(FE_ALL_EXCEPT);
        fesetenv(env.as_ptr());
        feclearexcept(FE_INEXACT);
        if before & FE_INEXACT != 0 { feraiseexcept(FE_INEXACT); }
        let raised = (after & !before) & !FE_INEXACT;
        if raised != 0 { feraiseexcept(raised); }
        result
    }
}
compat_long_unary!(nearbyintl, rint);
#[no_mangle]
pub extern "C" fn nexttoward(x: f64, y: f64) -> f64 { libm::nextafter(x, y) }
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn nexttowardf(x: f32, y: f64) -> f32 { libm::nextafterf(x, y as f32) }
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn nexttowardf(x: f32, y: f128) -> f32 { libm::nextafterf(x, y as f32) }
compat_long_binary!(nexttowardl, libm::nextafter);

#[no_mangle]
pub unsafe extern "C" fn remquo(x: f64, y: f64, quotient: *mut c_int) -> f64 {
    let (value, bits) = libm::remquo(x, y);
    if !quotient.is_null() { *quotient = bits; }
    value
}
#[no_mangle]
pub unsafe extern "C" fn remquof(x: f32, y: f32, quotient: *mut c_int) -> f32 {
    let (value, bits) = libm::remquof(x, y);
    if !quotient.is_null() { *quotient = bits; }
    value
}
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn remquol(x: f64, y: f64, quotient: *mut c_int) -> f64 {
    remquo(x, y, quotient)
}
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn remquol(x: f128, y: f128, quotient: *mut c_int) -> f128 {
    remquo(x as f64, y as f64, quotient) as f128
}

compat_long_unary!(rintl, rint);

#[no_mangle]
pub extern "C" fn scalb(x: f64, exponent: f64) -> f64 {
    // The exponent is not consulted when the significand is NaN.  In
    // particular scalb(NaN, +/-Inf) must stay NaN rather than taking the
    // infinity branches below.
    if x.is_nan() { return x; }
    if exponent.is_nan() { return exponent; }
    if x == 0.0 {
        if exponent == f64::INFINITY { return __math_invalid(x); }
        return x;
    }
    if exponent == f64::INFINITY {
        return if x.is_sign_negative() { f64::NEG_INFINITY } else { f64::INFINITY };
    }
    if exponent == f64::NEG_INFINITY {
        if x.is_infinite() { return __math_invalid(x); }
        return if x.is_sign_negative() { -0.0 } else { 0.0 };
    }
    if exponent != trunc(exponent) {
        fp_force_eval(exponent + 1.0e300);
        return __math_invalid(x);
    }
    if exponent > c_int::MAX as f64 { return scalbn(x, 2048); }
    if exponent < c_int::MIN as f64 { return scalbn(x, -2048); }
    scalbn(x, exponent as c_int)
}
#[no_mangle]
pub extern "C" fn scalbf(x: f32, exponent: f32) -> f32 {
    if x.is_nan() { return x; }
    if exponent.is_nan() { return exponent; }
    if x == 0.0 {
        if exponent == f32::INFINITY { return __math_invalidf(x); }
        return x;
    }
    if exponent == f32::INFINITY {
        return if x.is_sign_negative() { f32::NEG_INFINITY } else { f32::INFINITY };
    }
    if exponent == f32::NEG_INFINITY {
        if x.is_infinite() { return __math_invalidf(x); }
        return if x.is_sign_negative() { -0.0 } else { 0.0 };
    }
    if exponent != truncf(exponent) {
        fp_force_evalf(exponent + 1.0e30);
        return __math_invalidf(x);
    }
    if exponent > c_int::MAX as f32 { return scalbnf(x, 256); }
    if exponent < c_int::MIN as f32 { return scalbnf(x, -256); }
    scalbnf(x, exponent as c_int)
}
#[no_mangle]
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn scalblnl(x: f64, exponent: c_long) -> f64 { scalbln(x, exponent) }
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn scalblnl(x: f128, exponent: c_long) -> f128 {
    scalbln(x as f64, exponent) as f128
}
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn scalbnl(x: f64, exponent: c_int) -> f64 { scalbn(x, exponent) }
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn scalbnl(x: f128, exponent: c_int) -> f128 {
    scalbn(x as f64, exponent) as f128
}

#[no_mangle]
pub unsafe extern "C" fn sincos(x: f64, sin_out: *mut f64, cos_out: *mut f64) {
    let (sin_value, cos_value) = libm::sincos(x);
    if !sin_out.is_null() { *sin_out = sin_value; }
    if !cos_out.is_null() { *cos_out = cos_value; }
}
#[no_mangle]
pub unsafe extern "C" fn sincosf(x: f32, sin_out: *mut f32, cos_out: *mut f32) {
    let (sin_value, cos_value) = libm::sincosf(x);
    if !sin_out.is_null() { *sin_out = sin_value; }
    if !cos_out.is_null() { *cos_out = cos_value; }
}
#[no_mangle]
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sincosl(x: f64, sin_out: *mut f64, cos_out: *mut f64) {
    sincos(x, sin_out, cos_out)
}
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn sincosl(x: f128, sin_out: *mut f128, cos_out: *mut f128) {
    let (sin_value, cos_value) = libm::sincos(x as f64);
    if !sin_out.is_null() { *sin_out = sin_value as f128; }
    if !cos_out.is_null() { *cos_out = cos_value as f128; }
}

#[no_mangle]
pub extern "C" fn tgammaf(x: f32) -> f32 {
    if x < 0.0 && x == truncf(x) { return __math_invalidf(x); }
    libm::tgammaf(x)
}
compat_long_unary!(tgammal, libm::tgamma);
