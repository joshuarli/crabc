//! Selected static Linux/x86-64 `round`/`roundf` C ABI leaf.
//!
//! ## Fixed source and license provenance
//!
//! `math_round_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive whose SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_round.py` verifies the normalized source
//! tree digest and the pinned GCC 15.2.0 input before translating exactly
//! `src/math/round.c` and `src/math/roundf.c`. Those musl-authored MIT files
//! normalize the input sign, use a `toint` add/subtract sequence, and apply the
//! half-away correction; their license and exact release provenance
//! are recorded in `compat/upstreams.toml`. This is not a linked foreign object
//! and the Rust build never invokes a C compiler.
//!
//! The generator uses musl's fixed `-frounding-math` source profile. It keeps
//! the source's volatile `FORCE_EVAL` behavior for nonzero magnitudes below
//! one half, including its observable `FE_INEXACT` result, while preserving
//! half-away-from-zero values independent of the caller's active direction.
//! The differential compares raw binary32/binary64 results, requested and
//! observed directions, and IEEE exception flags against pinned musl.
//!
//! System V AMD64 passes and returns binary64/binary32 through `xmm0`. This
//! leaf deliberately owns only `round` and `roundf`; it excludes binary80
//! `roundl`, fenv API/policy, `rint*`/`nearbyint*`, truncation, directed
//! ceiling/floor, fma, fmod, cbrt, special and complex math, general libm,
//! family completion, promotion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math round leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_round_musl_x86_64.S"),
    options(att_syntax),
);
