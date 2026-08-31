//! Selected static Linux/x86-64 `log2`/`log2f` C ABI leaf.
//!
//! ## Fixed source and license provenance
//!
//! `math_log2_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive whose SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_log2.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before translating exactly
//! `src/math/log2.c`, `src/math/log2f.c`, `src/math/log2_data.c`,
//! `src/math/log2f_data.c`, `src/math/__math_divzero.c`,
//! `src/math/__math_divzerof.c`, `src/math/__math_invalid.c`, and
//! `src/math/__math_invalidf.c`.  The Arm MIT notices remain in the checked
//! input.  The data tables and IEEE error-expression helpers are renamed and
//! localized in that one assembly input, so they do not become public archive
//! exports.  The musl 1.2.6 MIT distribution license and exact release
//! provenance are recorded in `compat/upstreams.toml`; this is not a linked
//! foreign object and the Rust build never invokes a C compiler.
//!
//! The generator fixes `-frounding-math`, standard excess precision, scalar
//! SSE, and no-FMA/no-AVX code generation.  That bounded source closure
//! preserves musl's close-to-one reconstruction, subnormal normalization,
//! table reduction, exact powers-of-two paths, sign-sensitive zero/domain
//! expressions, and quiet/signaling-NaN behavior rather than delegating to an
//! ambient log provider.  The focused native differential compares raw
//! binary32/binary64 results, requested and observed MXCSR directions, and
//! IEEE exception flags against the same pinned musl build.  The harness uses
//! existing selected fenv entries only to reset and observe MXCSR; this leaf
//! does not select fenv API or policy.
//!
//! System V AMD64 passes and returns binary64/binary32 in `xmm0`.  This leaf
//! deliberately owns only `log2` and `log2f`; it excludes binary80 `log2l`,
//! log/log1p/log10 and exp/expm1/exp2 families, inverse trigonometry,
//! fma/hypot/fmod/remainder, rounding/truncation/ceiling/floor, square-root
//! and cube-root families, special and complex math, general libm, errno
//! policy, family completion, promotion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math log2 leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_log2_musl_x86_64.S"),
    options(att_syntax),
);
