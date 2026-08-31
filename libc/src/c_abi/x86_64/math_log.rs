//! Private static Linux/x86-64 binary32/binary64 `log` C ABI leaf.
//!
//! `math_log_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_log.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/log.c` retains musl's binary64 raw classification, subnormal
//!   normalization, close-to-one all-rounding branch, table reduction, and
//!   polynomial reconstruction.
//! - `src/math/logf.c` retains its distinct binary32 table reduction,
//!   subnormal normalization, directed-one boundary, and binary64 internal
//!   evaluation before the binary32 return rather than promoting the public
//!   boundary.
//! - `src/math/log_data.c`, `logf_data.c`, `__math_divzero{,f}.c`, and
//!   `__math_invalid{,f}.c` are the complete direct providers. Their renamed
//!   `__log_data`, `__logf_data`, `__math_divzero{,f}`, and
//!   `__math_invalid{,f}` symbols are local to this translation and cannot
//!   become public `math.special` or ambient-libm providers.
//!
//! The Arm/MIT source notices are retained in the checked assembly and ordinary
//! musl portions retain musl's MIT license as recorded in
//! `compat/upstreams.toml`. The generator fixes `-frounding-math`,
//! `-ffp-contract=off`, standard excess-precision semantics, scalar SSE
//! evaluation, and disabled loop/SLP vectorization. Thus the close-to-one
//! directed-zero path and zero/negative domain flags are observed through
//! MXCSR without selecting a fenv API or rounding policy. No x87/binary80
//! promotion, FMA, AVX, or packed-SIMD path is added.
//!
//! System V AMD64 passes and returns binary64 or binary32 in `xmm0`. `logl` is
//! representation-distinct and remains outside this leaf; neither it nor
//! long-double/general math is selected.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, general libm/libc.so, CRT/TLS
//! lifecycle, loader, sysroot, x86 promotion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static log leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_log_musl_x86_64.S"),
    options(att_syntax),
);
