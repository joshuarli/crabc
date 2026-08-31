//! Selected static Linux/x86-64 `trunc`/`truncf` C ABI leaf.
//!
//! This target-private Rust mapping follows pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/math/trunc.c` maps to [`trunc`];
//! - `src/math/truncf.c` maps to [`truncf`].
//!
//! Both source functions inspect the IEEE exponent and clear only the
//! fractional payload bits. When an input has a fractional component, musl's
//! `FORCE_EVAL(x + 0x1p120f)` raises the normal current-environment
//! `FE_INEXACT` result without changing the returned bit pattern. The volatile
//! stores below retain that observable SSE addition: they are not a general
//! fenv API, do not change the caller's rounding direction, and do not touch
//! NaNs because exponent-all-ones inputs return before the addition.
//!
//! System V AMD64 passes and returns binary64/binary32 in `xmm0`. This leaf
//! deliberately excludes binary80 `truncl`, `round*`, `rint*`/`nearbyint*`,
//! `fdim*`, special and complex math, general libm, family completion,
//! promotion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math trunc leaf requires little-endian Linux/x86-64");

const FORCE_EVAL_F64: f64 = f64::from_bits(0x4770_0000_0000_0000);
const FORCE_EVAL_F32: f32 = f32::from_bits(0x7b80_0000);

/// Retain musl's binary64 `FORCE_EVAL` side effect.
#[inline(never)]
fn force_eval_f64(value: f64) {
    let mut sink = 0.0_f64;
    // SAFETY: the local is valid writable storage. Volatile storage makes the
    // force-evaluation addition an observable operation rather than dead code.
    unsafe { core::ptr::write_volatile(&mut sink, value + FORCE_EVAL_F64) };
}

/// Retain musl's binary32 `FORCE_EVAL` side effect.
#[inline(never)]
fn force_eval_f32(value: f32) {
    let mut sink = 0.0_f32;
    // SAFETY: the local is valid writable storage. Volatile storage makes the
    // force-evaluation addition an observable operation rather than dead code.
    unsafe { core::ptr::write_volatile(&mut sink, value + FORCE_EVAL_F32) };
}

/// Removes a binary64 fractional field toward zero with musl's inexact rule.
#[no_mangle]
pub extern "C" fn trunc(value: f64) -> f64 {
    let bits = value.to_bits();
    let mut exponent = ((bits >> 52) & 0x7ff) as i32 - 0x3ff + 12;

    if exponent >= 52 + 12 {
        return value;
    }
    if exponent < 12 {
        exponent = 1;
    }
    let fractional_mask = u64::MAX >> exponent;
    if bits & fractional_mask == 0 {
        return value;
    }
    force_eval_f64(value);
    f64::from_bits(bits & !fractional_mask)
}

/// Removes a binary32 fractional field toward zero with musl's inexact rule.
#[no_mangle]
pub extern "C" fn truncf(value: f32) -> f32 {
    let bits = value.to_bits();
    let mut exponent = ((bits >> 23) & 0xff) as i32 - 0x7f + 9;

    if exponent >= 23 + 9 {
        return value;
    }
    if exponent < 9 {
        exponent = 1;
    }
    let fractional_mask = u32::MAX >> exponent;
    if bits & fractional_mask == 0 {
        return value;
    }
    force_eval_f32(value);
    f32::from_bits(bits & !fractional_mask)
}
