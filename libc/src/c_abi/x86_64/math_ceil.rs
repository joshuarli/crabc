//! Selected static Linux/x86-64 `ceil`/`ceilf` C ABI leaf.
//!
//! ## Fixed source and license provenance
//!
//! `math_ceil_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive whose SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_ceil.py` verifies the normalized source
//! tree digest and the pinned GCC 15.2.0 input before translating exactly
//! `src/math/ceil.c` and `src/math/ceilf.c`. Those musl-authored MIT files
//! use raw IEEE exponent/fraction tests and volatile `FORCE_EVAL` arithmetic;
//! their license and exact release provenance are recorded in
//! `compat/upstreams.toml`. This is not a linked foreign object and the Rust
//! build never invokes a C compiler.
//!
//! The generator uses musl's fixed `-frounding-math` source profile. It keeps
//! binary64's `toint` add/subtract sequence and binary32's raw-mask result
//! transformation plus its forced binary32 addition.  In particular, finite
//! fractional inputs retain musl's `FE_INEXACT` behavior while every caller
//! rounding direction produces a fixed mathematical ceiling; the differential
//! compares raw binary32/binary64 results, requested/observed directions, and
//! IEEE exception flags against pinned musl.
//!
//! System V AMD64 passes and returns binary64/binary32 through `xmm0`. This
//! leaf deliberately owns only `ceil` and `ceilf`; it excludes binary80
//! `ceill`, floor, fma, fmod, cbrt, special and complex math, fenv API/policy,
//! general libm, family completion, promotion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math ceil leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_ceil_musl_x86_64.S"),
    options(att_syntax),
);
