//! Private static Linux/x86-64 binary32/binary64 `sinh`/`sinhf` C ABI leaf.
//!
//! `math_sinh_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_sinh.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/sinh.c` and `src/math/sinhf.c` retain musl's raw sign and
//!   magnitude classification, tiny-input rule, stable `expm1` reconstruction,
//!   and overflow reconstruction selection.
//! - `src/math/expm1.c`, `src/math/expm1f.c`, `src/math/__expo2.c`, and
//!   `src/math/__expo2f.c` retain the fixed polynomial/reduction path and the
//!   overflow-safe scaling sequence required by the public entries.
//! - `src/math/exp.c`, `src/math/expf.c`, `src/math/exp_data.c`, and
//!   `src/math/exp2f_data.c`, plus `src/math/__math_oflow.c`,
//!   `src/math/__math_oflowf.c`, `src/math/__math_uflow.c`,
//!   `src/math/__math_uflowf.c`, `src/math/__math_xflow.c`, and
//!   `src/math/__math_xflowf.c`, are the exact local exponent table/error
//!   closure called only by the local overflow reconstruction path.
//!
//! Every closure provider is renamed, localized, and emitted `.local`: no
//! local `exp`/`expf`/`expm1`/`expm1f`, table, or error-helper spelling can
//! select an existing public exponential artifact or become an ambient-libm
//! provider. The preserved Sun and Arm notices stay in the checked assembly;
//! ordinary musl portions retain musl's MIT license as recorded in
//! `compat/upstreams.toml`.
//!
//! The generator fixes `-frounding-math`, `-ffp-contract=off`, standard
//! excess-precision semantics, scalar SSE evaluation, and disabled loop/SLP
//! vectorization. It preserves musl's source operation order and
//! caller-visible MXCSR results and IEEE flags without selecting a fenv API or policy.
//! No x87/binary80 promotion, FMA, AVX, or packed-SIMD path is added.
//!
//! System V AMD64 passes and returns binary64 or binary32 in `xmm0`. `sinhl`,
//! `cosh*`, `tanh*`, public exp/expm1 families, direct/inverse trigonometry,
//! and all long-double ABI remain outside this leaf.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, `math.special`, `math.complex`,
//! general libm/libc.so, CRT/TLS lifecycle, loader, sysroot, x86 promotion, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static sinh leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_sinh_musl_x86_64.S"),
    options(att_syntax),
);
