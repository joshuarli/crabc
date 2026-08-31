//! Selected static Linux/x86-64 `cbrt`/`cbrtf` C ABI leaf.
//!
//! ## Fixed source and license provenance
//!
//! `math_cbrt_musl_x86_64.S` is a checked assembly translation of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the
//! release archive whose SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_cbrt.py` verifies the normalized source
//! tree digest and the pinned GCC 15.2.0 input before translating exactly
//! `src/math/cbrt.c` and `src/math/cbrtf.c`. Those FreeBSD-derived `msun`
//! files preserve Sun Microsystems' 1993 permissive notice, reproduced at the
//! head of the checked assembly. This is not a linked foreign object and the
//! Rust build never invokes a C compiler.
//!
//! The generator uses musl's fixed `-frounding-math` source profile. It keeps
//! the source's binary64 polynomial/Newton operation order and `cbrtf`'s final
//! MXCSR-directed binary64-to-binary32 conversion, which is observably
//! different from an otherwise similar Rust lowering in directed modes. The
//! static differential therefore compares raw binary32/binary64 results and
//! IEEE exception flags over all four rounding directions against pinned musl.
//!
//! System V AMD64 passes and returns binary64/binary32 through `xmm0`. This
//! leaf deliberately owns only `cbrt` and `cbrtf`; it excludes binary80
//! `cbrtl`, `fma`/`fmaf`, fmod, special and complex math, fenv APIs/rounding
//! work, general libm, family completion, promotion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math cbrt leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_cbrt_musl_x86_64.S"),
    options(att_syntax),
);
