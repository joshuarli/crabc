// C99 complex-number primitives.
//
// C represents `_Complex T` as two adjacent real values.  Keep that layout
// explicit at the Rust ABI boundary: in particular, AArch64's `long double`
// is IEEE binary128 (`f128`).

#[repr(C)]
pub struct ComplexDouble {
    re: f64,
    im: f64,
}

#[repr(C)]
pub struct ComplexFloat {
    re: f32,
    im: f32,
}


#[repr(C)]
pub struct ComplexLong {
    re: f128,
    im: f128,
}

#[inline]
fn cabi_double_to_long(z: ComplexDouble) -> ComplexLong {
    ComplexLong { re: z.re as f128, im: z.im as f128 }
}

#[inline]
fn cabi_float_to_long(z: ComplexFloat) -> ComplexLong {
    ComplexLong { re: z.re as f128, im: z.im as f128 }
}

#[inline]
fn cabi_long_to_double(z: ComplexLong) -> ComplexDouble {
    ComplexDouble { re: z.re as f64, im: z.im as f64 }
}

#[inline]
fn cabi_long_to_float(z: ComplexLong) -> ComplexFloat {
    ComplexFloat { re: z.re as f32, im: z.im as f32 }
}

#[inline]
fn cabi_cproj_double(z: ComplexDouble) -> ComplexDouble {
    // C99 projects every complex value with an infinite component to the
    // point at positive infinity on the real axis.  The imaginary zero keeps
    // the sign of the original imaginary component.
    if is_inf(z.re) || is_inf(z.im) {
        ComplexDouble {
            re: f64::INFINITY,
            im: copysign(0.0, z.im),
        }
    } else {
        z
    }
}

#[inline]
fn cabi_cproj_float(z: ComplexFloat) -> ComplexFloat {
    if is_inff(z.re) || is_inff(z.im) {
        ComplexFloat {
            re: f32::INFINITY,
            im: copysignf(0.0, z.im),
        }
    } else {
        z
    }
}


#[inline]
fn cabi_cproj_long(z: ComplexLong) -> ComplexLong {
    if z.re.is_infinite() || z.im.is_infinite() {
        ComplexLong {
            re: f128::INFINITY,
            im: f128::from_bits(if z.im.is_sign_negative() {
                1u128 << 127
            } else {
                0
            }),
        }
    } else {
        z
    }
}

#[no_mangle]
pub extern "C" fn creal(z: ComplexDouble) -> f64 {
    z.re
}

#[no_mangle]
pub extern "C" fn crealf(z: ComplexFloat) -> f32 {
    z.re
}


#[no_mangle]
pub extern "C" fn creall(z: ComplexLong) -> f128 {
    z.re
}

#[no_mangle]
pub extern "C" fn cimag(z: ComplexDouble) -> f64 {
    z.im
}

#[no_mangle]
pub extern "C" fn cimagf(z: ComplexFloat) -> f32 {
    z.im
}


#[no_mangle]
pub extern "C" fn cimagl(z: ComplexLong) -> f128 {
    z.im
}

#[no_mangle]
pub extern "C" fn conj(z: ComplexDouble) -> ComplexDouble {
    ComplexDouble { re: z.re, im: -z.im }
}

#[no_mangle]
pub extern "C" fn conjf(z: ComplexFloat) -> ComplexFloat {
    ComplexFloat { re: z.re, im: -z.im }
}


#[no_mangle]
pub extern "C" fn conjl(z: ComplexLong) -> ComplexLong {
    ComplexLong { re: z.re, im: -z.im }
}

#[no_mangle]
pub extern "C" fn cproj(z: ComplexDouble) -> ComplexDouble {
    cabi_cproj_double(z)
}

#[no_mangle]
pub extern "C" fn cprojf(z: ComplexFloat) -> ComplexFloat {
    cabi_cproj_float(z)
}


#[no_mangle]
pub extern "C" fn cprojl(z: ComplexLong) -> ComplexLong {
    cabi_cproj_long(z)
}

#[no_mangle]
pub extern "C" fn cabs(z: ComplexDouble) -> f64 {
    cabi_cabs_double(z)
}

#[no_mangle]
pub extern "C" fn cabsf(z: ComplexFloat) -> f32 {
    cabi_cabs_float(z)
}

#[inline]
fn cabi_cabs_double(z: ComplexDouble) -> f64 {
    // The source contract checks the correctly rounded binary64 result,
    // while the native target has binary128 long double. Retain the extra
    // precision through the root and round only at the ABI edge; the musl
    // double hypot path can otherwise land one ulp below the interval.
    hypotl(z.re as f128, z.im as f128) as f64
}



#[inline]
fn cabi_cabs_float(z: ComplexFloat) -> f32 {
    hypotl(z.re as f128, z.im as f128) as f32
}




#[no_mangle]
pub extern "C" fn cabsl(z: ComplexLong) -> f128 {
    hypotl(z.re, z.im)
}

#[no_mangle]
pub extern "C" fn carg(z: ComplexDouble) -> f64 {
    cabi_carg_double(z)
}

#[no_mangle]
pub extern "C" fn cargf(z: ComplexFloat) -> f32 {
    cabi_carg_float(z)
}

#[inline]
fn cabi_carg_double(z: ComplexDouble) -> f64 {
    cargl(cabi_double_to_long(z)) as f64
}



#[inline]
fn cabi_carg_float(z: ComplexFloat) -> f32 {
    cargl(cabi_float_to_long(z)) as f32
}




#[no_mangle]
pub extern "C" fn cargl(z: ComplexLong) -> f128 {
    atan2l(z.im, z.re)
}
