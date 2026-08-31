//! Private static Linux/x86-64 binary32/binary64 `sin` C ABI leaf.
//!
//! `math_sin_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_sin.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/sin.c` and `src/math/sinf.c` retain musl's distinct binary64/binary32
//!   raw classification, small-input paths, quadrant selection, and NaN/large
//!   argument behavior without promoting the public `float` boundary.
//! - `src/math/__sin.c`, `__cos.c`, `__sindf.c`, and `__cosdf.c` retain the
//!   fixed generic kernel polynomials used after reduction.
//! - `src/math/__rem_pio2.c`, `__rem_pio2f.c`, and `__rem_pio2_large.c` retain
//!   moderate and large argument reduction, including the fixed multiword
//!   `2/pi` data. Their local `floor.c` and `scalbn.c` dependencies are part of
//!   this exact source closure, not calls to separately selected public C ABI
//!   entries.
//!
//! Every closure provider is renamed and emitted `.local`: the kernel,
//! reduction, `floor`, and `scalbn` symbols cannot become public
//! `math.elementary`, `math.special`, or ambient-libm providers. The preserved
//! Sun notices stay in the checked assembly; ordinary musl
//! portions retain musl's MIT license as recorded in `compat/upstreams.toml`.
//!
//! The generator fixes `-frounding-math`, `-ffp-contract=off`, standard
//! excess-precision semantics, scalar SSE evaluation, and disabled loop/SLP
//! vectorization. It preserves musl's kernel/reduction operation order and
//! caller-visible MXCSR results and IEEE flags without selecting a fenv API or
//! rounding policy. No x87/binary80 promotion, FMA, AVX, or packed-SIMD path
//! is added.
//!
//! System V AMD64 passes and returns binary64 or binary32 in `xmm0`. `sinl`,
//! `sincos*`, and all long-double argument-reduction ABI remain outside this
//! leaf.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, `math.special`, `math.complex`,
//! general libm/libc.so, CRT/TLS lifecycle, loader, sysroot, x86 promotion, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static sin leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_sin_musl_x86_64.S"),
    options(att_syntax),
);
