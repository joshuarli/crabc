// M4 C99 complex-number primitives.
//
// C represents `_Complex T` as two adjacent real values.  Keep that layout
// explicit at the Rust ABI boundary: in particular, AArch64's `long double`
// is IEEE binary128 (`f128`), not the 64-bit long-double ABI used by the
// x86_64 test builds.

#[repr(C)]
pub struct M4ComplexDouble {
    re: f64,
    im: f64,
}

#[repr(C)]
pub struct M4ComplexFloat {
    re: f32,
    im: f32,
}

#[cfg(target_arch = "x86_64")]
pub type M4ComplexLong = M4ComplexDouble;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[repr(C)]
pub struct M4ComplexLong {
    re: f128,
    im: f128,
}

#[inline]
fn m4_cproj_double(z: M4ComplexDouble) -> M4ComplexDouble {
    // C99 projects every complex value with an infinite component to the
    // point at positive infinity on the real axis.  The imaginary zero keeps
    // the sign of the original imaginary component.
    if is_inf(z.re) || is_inf(z.im) {
        M4ComplexDouble {
            re: f64::INFINITY,
            im: copysign(0.0, z.im),
        }
    } else {
        z
    }
}

#[inline]
fn m4_cproj_float(z: M4ComplexFloat) -> M4ComplexFloat {
    if is_inff(z.re) || is_inff(z.im) {
        M4ComplexFloat {
            re: f32::INFINITY,
            im: copysignf(0.0, z.im),
        }
    } else {
        z
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn m4_cproj_long(z: M4ComplexLong) -> M4ComplexLong {
    m4_cproj_double(z)
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[inline]
fn m4_cproj_long(z: M4ComplexLong) -> M4ComplexLong {
    if z.re.is_infinite() || z.im.is_infinite() {
        M4ComplexLong {
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
pub extern "C" fn creal(z: M4ComplexDouble) -> f64 {
    z.re
}

#[no_mangle]
pub extern "C" fn crealf(z: M4ComplexFloat) -> f32 {
    z.re
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn creall(z: M4ComplexLong) -> f64 {
    z.re
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn creall(z: M4ComplexLong) -> f128 {
    z.re
}

#[no_mangle]
pub extern "C" fn cimag(z: M4ComplexDouble) -> f64 {
    z.im
}

#[no_mangle]
pub extern "C" fn cimagf(z: M4ComplexFloat) -> f32 {
    z.im
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn cimagl(z: M4ComplexLong) -> f64 {
    z.im
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn cimagl(z: M4ComplexLong) -> f128 {
    z.im
}

#[no_mangle]
pub extern "C" fn conj(z: M4ComplexDouble) -> M4ComplexDouble {
    M4ComplexDouble { re: z.re, im: -z.im }
}

#[no_mangle]
pub extern "C" fn conjf(z: M4ComplexFloat) -> M4ComplexFloat {
    M4ComplexFloat { re: z.re, im: -z.im }
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn conjl(z: M4ComplexLong) -> M4ComplexLong {
    conj(z)
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn conjl(z: M4ComplexLong) -> M4ComplexLong {
    M4ComplexLong { re: z.re, im: -z.im }
}

#[no_mangle]
pub extern "C" fn cproj(z: M4ComplexDouble) -> M4ComplexDouble {
    m4_cproj_double(z)
}

#[no_mangle]
pub extern "C" fn cprojf(z: M4ComplexFloat) -> M4ComplexFloat {
    m4_cproj_float(z)
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn cprojl(z: M4ComplexLong) -> M4ComplexLong {
    m4_cproj_long(z)
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn cprojl(z: M4ComplexLong) -> M4ComplexLong {
    m4_cproj_long(z)
}

#[no_mangle]
pub extern "C" fn cabs(z: M4ComplexDouble) -> f64 {
    hypot(z.re, z.im)
}

#[no_mangle]
pub extern "C" fn cabsf(z: M4ComplexFloat) -> f32 {
    hypotf(z.re, z.im)
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn cabsl(z: M4ComplexLong) -> f64 {
    hypotl(z.re, z.im)
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn cabsl(z: M4ComplexLong) -> f128 {
    hypotl(z.re, z.im)
}

#[no_mangle]
pub extern "C" fn carg(z: M4ComplexDouble) -> f64 {
    unsafe { atan2(z.im, z.re) }
}

#[no_mangle]
pub extern "C" fn cargf(z: M4ComplexFloat) -> f32 {
    unsafe { atan2f(z.im, z.re) }
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn cargl(z: M4ComplexLong) -> f64 {
    atan2l(z.im, z.re)
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
#[no_mangle]
pub extern "C" fn cargl(z: M4ComplexLong) -> f128 {
    atan2l(z.im, z.re)
}
