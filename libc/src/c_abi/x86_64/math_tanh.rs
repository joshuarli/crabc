//! Private static Linux/x86-64 binary32/binary64 `tanh` C ABI leaf.
//!
//! `math_tanh_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_tanh.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/tanh.c` and `src/math/tanhf.c` retain musl's distinct
//!   binary64/binary32 absolute-value classification, saturation, subnormal,
//!   signed-zero, and NaN paths without promoting the public `float` boundary.
//! - `src/math/expm1.c` and `src/math/expm1f.c` provide the matching
//!   exponential-minus-one reconstruction used by those sources. They are
//!   renamed within this assembly, so neither becomes a call to the separately
//!   selected public `expm1`/`expm1f` C ABI nor an ambient-libm dependency.
//!
//! Every closure provider is renamed and emitted `.local`: its implementation
//! cannot become a public `math.elementary`, `math.special`, or ambient-libm
//! provider. The preserved FreeBSD/Sun notices stay in the checked assembly;
//! ordinary musl portions retain musl's MIT license as recorded in
//! `compat/upstreams.toml`.
//!
//! The generator fixes `-frounding-math`, `-ffp-contract=off`, standard
//! excess-precision semantics, scalar SSE evaluation, and disabled loop/SLP
//! vectorization. It preserves musl's operation order and caller-visible MXCSR
//! results and IEEE flags without selecting a fenv API or rounding policy. No
//! x87/binary80 promotion, FMA, AVX, or packed-SIMD path is added.
//!
//! System V AMD64 passes and returns binary64 or binary32 in `xmm0`. `tanhl`
//! and all binary80 argument/return ABI remain outside this leaf; similarly,
//! `tan`/`tanf`, sine/cosine, complex, special, and inverse-hyperbolic entry
//! points are not selected.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, `math.special`, `math.complex`,
//! general libm/libc.so, CRT/TLS lifecycle, loader, sysroot, x86 promotion, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static tanh leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_tanh_musl_x86_64.S"),
    options(att_syntax),
);
