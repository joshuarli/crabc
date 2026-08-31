//! Private static Linux/x86-64 binary32/binary64 `expm1` C ABI leaf.
//!
//! `math_expm1_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_expm1.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/expm1.c` retains musl's binary64 range reduction, polynomial
//!   reconstruction, raw-subnormal `FORCE_EVAL((float)x)` behavior, signed
//!   infinity/NaN handling, and overflow scaling.
//! - `src/math/expm1f.c` retains the distinct binary32 reduction constants,
//!   polynomial, raw-subnormal `FORCE_EVAL(x*x)` behavior, and binary32
//!   overflow scaling rather than promoting the public `float` boundary.
//!
//! They form a direct no-call source closure: there are no tables, helper
//! providers, ambient `libm` calls, or selected `math.special` state. The
//! FreeBSD/Sun `msun` provenance retains the Sun Microsystems 1993 permissive
//! notice at the head of the checked assembly; ordinary musl portions retain
//! musl's MIT license as recorded in `compat/upstreams.toml`.
//!
//! The generator fixes `-frounding-math`, `-ffp-contract=off`, standard
//! excess-precision semantics, scalar SSE evaluation, and disabled loop/SLP
//! vectorization. Thus musl's source arithmetic preserves requested MXCSR
//! direction and IEEE flags—including its tiny/subnormal force evaluation—
//! without selecting a fenv API or rounding policy. No x87/binary80 promotion,
//! FMA, AVX, or packed-SIMD path is added.
//!
//! System V AMD64 passes and returns binary64 or binary32 in `xmm0`.
//! `expm1l` is representation-distinct and remains outside this leaf; neither
//! it nor long-double/general math is selected.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, general libm/libc.so, CRT/TLS
//! lifecycle, loader, sysroot, x86 promotion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static expm1 leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_expm1_musl_x86_64.S"),
    options(att_syntax),
);
