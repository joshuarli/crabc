//! Private static Linux/x86-64 binary32/binary64 `pow` C ABI leaf.
//!
//! `math_pow_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_pow.py` verifies the normalized complete
//! source-tree digest and pinned GCC 15.2.0 input before writing fixed
//! assembly. The Rust build never invokes a C compiler.
//!
//! ## Exact source map and closure
//!
//! - `src/math/pow.c` and `src/math/powf.c` retain musl's distinct binary64/
//!   binary32 raw classification, signed-integer-exponent rules, zero/pole and
//!   infinity/NaN behavior, fixed logarithm/exponential table paths, and typed
//!   overflow/underflow behavior without promoting the public `float` boundary.
//! - `src/math/exp_data.c`, `src/math/pow_data.c`, `src/math/exp2f_data.c`, and
//!   `src/math/powf_data.c` retain the exact fixed polynomial/table data.
//! - `src/math/__math_{invalid,oflow,uflow,xflow}.c` and their binary32
//!   counterparts retain source-specific exceptional-result/flag behavior.
//!   `src/math/fabs.c` is a local provider, not a public bit-sign dependency.
//!
//! Every function and data provider is renamed and emitted `.local`: it cannot
//! become a public `math.elementary`, `math.special`, or ambient-libm provider.
//! The preserved Arm notices stay in the checked assembly; ordinary musl
//! portions retain musl's MIT license as recorded in
//! `compat/upstreams.toml`.
//!
//! The generator fixes `-frounding-math`, `-ffp-contract=off`, standard
//! excess-precision semantics, scalar SSE evaluation, and disabled loop/SLP
//! vectorization. It preserves musl's table and exceptional-result operation
//! ordering plus caller-visible MXCSR results and IEEE flags without selecting
//! a fenv API or rounding policy. No x87/binary80 promotion, FMA ISA, AVX, or
//! packed-SIMD path is added.
//!
//! System V AMD64 passes the binary64/binary32 base and exponent in `xmm0` and
//! `xmm1`, then returns the corresponding result in `xmm0`. `powl` and all
//! binary80 argument/return ABI remain outside this leaf; similarly, public
//! exp/log/exp2, `fma`, and `fabs` entries are not selected.
//!
//! This is a private non-capability artifact inside still-planned
//! `libc.text-math-locale-stdio`. It does not complete `math.elementary`,
//! select `math.elementary-fenv-sensitive`, `math.special`, `math.complex`,
//! general libm/libc.so, CRT/TLS lifecycle, loader, sysroot, x86 promotion, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 static pow leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_pow_musl_x86_64.S"),
    options(att_syntax),
);
