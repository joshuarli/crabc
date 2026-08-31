//! Private static Linux/x86-64 binary32/binary64 `asinh`/`asinhf` C ABI leaf.
//!
//! `math_asinh_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_asinh.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/asinh.c` and `src/math/asinhf.c` retain musl's raw sign and
//!   magnitude classification, signed tiny-input rule, log-plus-ln2 large
//!   reconstruction, reciprocal-square-root middle reconstruction, log1p
//!   near-one reconstruction, and final sign restoration.
//! - `src/math/log.c`, `src/math/logf.c`, `src/math/log_data.c`, and
//!   `src/math/logf_data.c` retain their table reduction, close-to-one path,
//!   subnormal normalization, and invalid/divide-by-zero handling required by
//!   the local large and middle paths.
//! - `src/math/log1p.c` and `src/math/log1pf.c` retain fixed correction and
//!   polynomial paths for the local near-one reconstruction.
//! - `src/math/sqrt.c`, `src/math/sqrtf.c`, and `src/math/sqrt_data.c` retain
//!   the integer Goldschmidt/table square-root path and all-rounding adjustment.
//! - `src/math/__math_invalid.c`, `src/math/__math_invalidf.c`,
//!   `src/math/__math_divzero.c`, and `src/math/__math_divzerof.c` are the
//!   exact local IEEE expression helpers reached only through local log/sqrt.
//!
//! Every closure provider is renamed, localized, and emitted `.local`: no
//! local `log`/`logf`/`log1p`/`log1pf`/`sqrt`/`sqrtf`, table, or error-helper
//! spelling can select an existing public artifact or become an ambient-libm
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
//! System V AMD64 passes and returns binary64 or binary32 in `xmm0`. `asinhl`,
//! `acosh*`, `atanh*`, public log/log1p/sqrt families, direct trigonometry,
//! and all long-double ABI remain outside this leaf.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, `math.special`, `math.complex`,
//! general libm/libc.so, CRT/TLS lifecycle, loader, sysroot, x86 promotion, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static asinh leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_asinh_musl_x86_64.S"),
    options(att_syntax),
);
