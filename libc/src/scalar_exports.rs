// scalar math and bit-index compatibility exports.

use super::{
    c_int, c_long, c_longlong, frexp, frexpf, is_finite, is_finitef, is_inf, is_inff, is_nan,
    is_nanf, scalbn, scalbnf,
};

#[no_mangle]
pub extern "C" fn finite(x: f64) -> c_int {
    is_finite(x) as c_int
}

#[no_mangle]
pub extern "C" fn finitef(x: f32) -> c_int {
    is_finitef(x) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn significand(x: f64) -> f64 {
    if x == 0.0 || is_nan(x) || is_inf(x) { return x; }
    let mut exponent = 0;
    scalbn(frexp(x, &mut exponent), 1)
}

#[no_mangle]
pub unsafe extern "C" fn significandf(x: f32) -> f32 {
    if x == 0.0 || is_nanf(x) || is_inff(x) { return x; }
    let mut exponent = 0;
    scalbnf(frexpf(x, &mut exponent), 1)
}

#[no_mangle]
pub extern "C" fn ffs(value: c_int) -> c_int {
    if value == 0 { 0 } else { value.trailing_zeros() as c_int + 1 }
}

#[no_mangle]
pub extern "C" fn ffsl(value: c_long) -> c_int {
    if value == 0 { 0 } else { value.trailing_zeros() as c_int + 1 }
}

#[no_mangle]
pub extern "C" fn ffsll(value: c_longlong) -> c_int {
    if value == 0 { 0 } else { value.trailing_zeros() as c_int + 1 }
}
