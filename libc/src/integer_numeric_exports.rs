// integer and NaN utility entry points.
//
// On the AArch64 musl ABI, intmax_t is long and uintmax_t is unsigned long.
// Keeping the wrappers here means the shared integer parser remains the single
// source of overflow, base, end-pointer, and errno behavior.

use super::{c_char, c_int, c_long, c_uint, c_ulong, strtoll, strtoull};

#[repr(C)]
pub struct CabiImaxDiv {
    quot: c_long,
    rem: c_long,
}

#[no_mangle]
pub unsafe extern "C" fn imaxabs(value: c_long) -> c_long {
    if value < 0 { value.wrapping_neg() } else { value }
}

#[no_mangle]
pub unsafe extern "C" fn imaxdiv(numerator: c_long, denominator: c_long) -> CabiImaxDiv {
    CabiImaxDiv {
        quot: numerator / denominator,
        rem: numerator % denominator,
    }
}

#[no_mangle]
pub unsafe extern "C" fn strtoimax(
    input: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
) -> c_long {
    strtoll(input, end, base) as c_long
}

#[no_mangle]
pub unsafe extern "C" fn strtoumax(
    input: *const c_char,
    end: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    strtoull(input, end, base) as c_ulong
}

#[no_mangle]
pub unsafe extern "C" fn nan(_tag: *const c_char) -> f64 {
    f64::from_bits(0x7ff8_0000_0000_0000)
}

#[no_mangle]
pub unsafe extern "C" fn nanf(_tag: *const c_char) -> f32 {
    f32::from_bits(0x7fc0_0000)
}



#[no_mangle]
pub unsafe extern "C" fn nanl(_tag: *const c_char) -> f128 {
    f128::from_bits(0x7fff_8000_0000_0000_0000_0000_0000_0000)
}

#[inline]
unsafe fn cabi_rand_r_temper(mut value: c_uint) -> c_uint {
    value ^= value >> 11;
    value ^= (value << 7) & 0x9d2c_5680;
    value ^= (value << 15) & 0xefc6_0000;
    value ^ (value >> 18)
}

#[no_mangle]
pub unsafe extern "C" fn rand_r(seed: *mut c_uint) -> c_int {
    *seed = (*seed).wrapping_mul(1103515245).wrapping_add(12345);
    (cabi_rand_r_temper(*seed) >> 1) as c_int
}
