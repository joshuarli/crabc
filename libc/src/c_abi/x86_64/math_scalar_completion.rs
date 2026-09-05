//! Owned-static Linux/x86-64 scalar `fma`, `hypot`, and `log1p` C ABI leaf.
//!
//! `math_scalar_completion_musl_x86_64.S` is a checked assembly translation
//! of pinned musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! from the release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_scalar_completion.py` checks the complete
//! source-tree digest and pinned GCC 15.2.0 wrapper before it writes the fixed
//! PIC assembly. Rust's build never invokes a C compiler or links host libm.
//!
//! ## Exact source map and closure
//!
//! - `src/math/x86_64/{fma,fmaf}.c` map to musl's generic
//!   `src/math/{fma,fmaf}.c` paths because the generator forbids FMA3/FMA4.
//!   `fma` retains its exact integer-product/alignment calculation and one
//!   localized `src/math/scalbn.c` provider. `fmaf` preserves musl's binary64
//!   intermediate, half-way correction, and existing fenv calls.
//! - `src/math/{hypot,hypotf}.c` retain their independent scaling and
//!   split-square paths. They call only the existing scalar `sqrt`/`sqrtf`
//!   owners, exactly as musl source does; no second root provider is copied.
//! - `src/math/{log1p,log1pf}.c` retain musl's raw classification, subnormal,
//!   pole/domain, rational-reduction, and directed reconstruction paths. They
//!   have no callable source dependency.
//!
//! The generator fixes scalar SSE evaluation, standard excess precision,
//! `-frounding-math`, `-ffp-contract=off`, and disabled AVX/vector/FMA paths.
//! It mechanically namespaces translation-unit locals and makes `scalbn`
//! private, preserving the caller-visible MXCSR result/exception behavior
//! without introducing an ambient provider. Musl-authored source keeps musl's
//! MIT license, and retained source-specific notices appear in the assembly.
//!
//! System V AMD64 passes binary64/binary32 values through XMM registers:
//! `fma` has three operands in `xmm0..xmm2`; `hypot` has two in `xmm0..xmm1`;
//! and `log1p` has one in `xmm0`; every result returns in `xmm0`. The x87
//! binary80 `fmal`, `hypotl`, and `log1pl` ABI is intentionally separate.
//!
//! This leaf is selected only by `x86-owned-static-runtime`, so it leaves the
//! frozen default archive untouched. It does not complete a math capability or
//! family, establish a general libm/libc, or promote x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the owned scalar-math leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_scalar_completion_musl_x86_64.S"),
    options(att_syntax),
);
