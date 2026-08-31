//! Private static Linux/x86-64 GNU binary64 `exp10`/`pow10` C ABI leaf.
//!
//! `math_exp10_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_exp10.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/exp10.c` retains musl's integral-table path for `|n| < 16`,
//!   fractional `exp2(log2(10) * y)` reconstruction, large-magnitude `pow`
//!   path, and GNU weak same-address `pow10` alias.
//! - `src/math/modf.c`, `src/math/exp2.c`, `src/math/pow.c`, `src/math/fabs.c`,
//!   `src/math/exp_data.c`, and `src/math/pow_data.c` retain the source-specific
//!   split, scalar reductions, and fixed table data.
//! - `src/math/__math_invalid.c`, `src/math/__math_oflow.c`,
//!   `src/math/__math_uflow.c`, and `src/math/__math_xflow.c` retain the
//!   exceptional result and IEEE-flag expressions reached by the closed
//!   arithmetic paths.
//!
//! Every closure provider, table, and helper is renamed and emitted `.local`.
//! Only strong `exp10` and weak same-address `pow10` remain public, so no public
//! `modf`, `exp2`, `pow`, `fabs`, table, or error-helper entry is selected or
//! accidentally exported. The preserved Arm notices stay in the checked
//! assembly; ordinary musl portions retain musl's MIT license as recorded in
//! `compat/upstreams.toml`.
//!
//! The generator fixes `-frounding-math`, `-ffp-contract=off`, standard
//! excess-precision semantics, scalar SSE evaluation, and disabled loop/SLP
//! vectorization. It preserves musl's source operation order and caller-visible
//! MXCSR results and IEEE flags without selecting a fenv API or policy. No
//! x87/binary80 promotion, FMA, AVX, or packed-SIMD path is added.
//!
//! System V AMD64 passes and returns binary64 in `xmm0`; `pow10` has exactly
//! the same address and ABI as `exp10`. Binary32 `exp10f`/`pow10f`, binary80
//! `exp10l`/`pow10l`, public `modf`/`exp2`/`pow`/`fabs`, fenv policy, special
//! and complex math, and all long-double ABI remain outside this leaf.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, `math.special`, `math.complex`,
//! general libm/libc.so, CRT/TLS lifecycle, loader, sysroot, x86 promotion, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static exp10 leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_exp10_musl_x86_64.S"),
    options(att_syntax),
);
