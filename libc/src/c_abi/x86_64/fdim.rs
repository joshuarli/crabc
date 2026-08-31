//! Selected static Linux/x86-64 positive-difference C ABI leaf.
//!
//! This is a literal semantic translation of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/math/fdim.c` maps to [`fdim`];
//! - `src/math/fdimf.c` maps to [`fdimf`].
//!
//! The NaN tests use an opaque IEEE payload observation, matching musl's
//! `isnan` predicate without executing an ordered comparison first. That keeps
//! a NaN operand's left-to-right return choice and avoids introducing an
//! invalid exception before the selected subtraction. Ordinary `x - y` remains
//! a native SSE operation, so a positive non-exact difference observes the
//! caller's MXCSR rounding mode and reports its normal hardware exceptions.
//!
//! This leaf intentionally owns only binary64/binary32 positive-part
//! subtraction. `fdiml`, `exp10*`/`pow10*`, current-rounding and
//! integer-result conversions, special functions, binary80 math, errno
//! policy, general libm, category/family completion, promotion, and public x86 support remain outside this artifact.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 fdim leaf requires little-endian Linux/x86-64");

// Keep the checked representation in an integer object. Rust's ordinary
// floating-point comparison lowering may use UCOMIS, which signals invalid
// for a signaling NaN and would not preserve musl's bit-classification path.
#[inline(never)]
fn observed_double_bits(x: f64) -> u64 {
    let bits = x.to_bits();
    // SAFETY: `bits` is a valid aligned initialized local u64. Volatile access
    // preserves the integer observation instead of allowing a floating-point
    // comparison substitution.
    unsafe { core::ptr::read_volatile(&bits) }
}

#[inline(never)]
fn observed_float_bits(x: f32) -> u32 {
    let bits = x.to_bits();
    // SAFETY: identical reasoning to `observed_double_bits` for this local.
    unsafe { core::ptr::read_volatile(&bits) }
}

#[inline]
fn is_nan(x: f64) -> bool {
    let bits = observed_double_bits(x);
    ((bits >> 52) & 0x7ff) == 0x7ff && (bits << 12) != 0
}

#[inline]
fn is_nanf(x: f32) -> bool {
    let bits = observed_float_bits(x);
    ((bits >> 23) & 0xff) == 0xff && (bits << 9) != 0
}

/// Return the non-negative difference of two binary64 values.
///
/// NaNs retain musl's left-to-right operand choice. For non-NaN operands,
/// the selected subtraction is intentionally left to the x86 SSE environment.
#[no_mangle]
pub extern "C" fn fdim(x: f64, y: f64) -> f64 {
    if is_nan(x) {
        return x;
    }
    if is_nan(y) {
        return y;
    }
    if x > y { x - y } else { 0.0 }
}

/// Return the non-negative difference of two binary32 values.
///
/// The caller's MXCSR rounding and exception state govern the selected
/// subtraction just as for [`fdim`].
#[no_mangle]
pub extern "C" fn fdimf(x: f32, y: f32) -> f32 {
    if is_nanf(x) {
        return x;
    }
    if is_nanf(y) {
        return y;
    }
    if x > y { x - y } else { 0.0 }
}
