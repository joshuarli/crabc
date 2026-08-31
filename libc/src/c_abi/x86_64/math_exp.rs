//! Selected static Linux/x86-64 `exp`/`expf` C ABI leaf.
//!
//! ## Fixed source and license provenance
//!
//! `math_exp_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive whose SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_exp.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before translating exactly
//! `src/math/exp.c`, `src/math/expf.c`, `src/math/exp_data.c`,
//! `src/math/exp2f_data.c`, `src/math/__math_oflow.c`,
//! `src/math/__math_oflowf.c`, `src/math/__math_uflow.c`,
//! `src/math/__math_uflowf.c`, `src/math/__math_xflow.c`, and
//! `src/math/__math_xflowf.c`. The Arm MIT notices remain in the checked
//! input. The two data tables and six overflow/underflow helpers are renamed
//! and localized in that assembly input, so they do not become public archive
//! exports. The musl 1.2.6 MIT distribution license and exact release
//! provenance are recorded in `compat/upstreams.toml`; this is not a linked
//! foreign object and the Rust build never invokes a C compiler.
//!
//! The generator fixes `-frounding-math`, standard excess precision, scalar
//! SSE, and no-FMA/no-AVX code generation. That bounded source closure
//! preserves musl's table argument reduction, close-to-zero rule, scalar
//! polynomial evaluation, large-result `specialcase` reconstruction, gradual
//! subnormal handling, and explicit overflow/underflow expressions rather
//! than delegating to an ambient exponential provider. The focused native
//! differential compares raw binary32/binary64 results, requested and
//! observed MXCSR directions, and IEEE exception flags against the same
//! pinned musl build. The harness uses existing selected fenv entries only to
//! reset and observe MXCSR; this leaf does not select fenv API or policy.
//!
//! System V AMD64 passes and returns binary64/binary32 in `xmm0`. This leaf
//! deliberately owns only `exp` and `expf`; it excludes binary80 `expl`,
//! exp2/expm1 and all log families, inverse/direct trigonometry, fma/hypot/
//! fmod/remainder, rounding/truncation/ceiling/floor, roots, special and
//! complex math, general libm, errno policy, family completion, promotion,
//! and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math exp leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_exp_musl_x86_64.S"),
    options(att_syntax),
);
