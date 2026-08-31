//! Private static Linux/x86-64 binary32/binary64 `exp2` C ABI leaf.
//!
//! `math_exp2_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_exp2.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/exp2.c` retains musl's binary64 range reduction, table/polynomial
//!   reconstruction, signed infinity/NaN handling, explicit subnormal rounding,
//!   and overflow/underflow signaling.
//! - `src/math/exp2f.c` retains its distinct binary32 threshold and
//!   binary32-table polynomial rather than promoting the public `float`
//!   boundary through binary64.
//! - `src/math/{exp_data,exp2f_data}.c` are renamed local data providers for
//!   the binary64 and binary32 tables, respectively. They do not select musl's
//!   adjacent `exp`, `expf`, or `pow` entry points.
//! - `src/math/__math_{o,u,x}flow{,f}.c` are renamed local range-scaling
//!   providers. The closure is complete inside this checked assembly unit; it
//!   neither calls ambient `libm` nor shares a special-math provider.
//!
//! The generator fixes `-frounding-math`, `-ffp-contract=off`, standard
//! excess-precision semantics, SSE scalar evaluation, and disabled loop/SLP
//! vectorization. Thus musl's `WANT_ROUNDING` branches preserve requested
//! MXCSR rounding and IEEE flags without selecting a fenv API or rounding
//! policy. No x87/binary80 promotion, FMA, AVX, or packed-SIMD path is added.
//!
//! System V AMD64 passes and returns binary64 or binary32 in `xmm0`.
//! `exp2l` is representation-distinct and remains outside this leaf; neither
//! it nor long-double/general math is selected.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, general libm/libc.so, CRT/TLS
//! lifecycle, loader, sysroot, x86 promotion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static exp2 leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_exp2_musl_x86_64.S"),
    options(att_syntax),
);
