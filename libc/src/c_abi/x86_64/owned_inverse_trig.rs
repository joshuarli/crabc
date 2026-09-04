//! Owned-static Linux/x86-64 binary32/binary64 inverse-trigonometry C ABI.
//!
//! `owned_inverse_trig_musl_x86_64.S` is a checked assembly translation of
//! pinned musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! from the release archive with SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_owned_inverse_trig.py` verifies the normalized
//! complete source tree and pinned GCC 15.2.0 input before writing the fixed
//! assembly. The Rust build never invokes a C compiler or links host `libm`.
//!
//! ## Exact source map and closure
//!
//! - `src/math/{asin,acos,atan,atan2}.c` provide `asin`, `acos`, `atan`, and
//!   `atan2` with musl's binary64 argument reductions, domain behavior,
//!   signed-zero, subnormal, NaN, infinity, rounding, and IEEE-flag paths.
//! - `src/math/{asinf,acosf,atanf,atan2f}.c` provide the corresponding
//!   binary32 entries without widening their public boundary through binary64
//!   or binary80 callers.
//! - `atan2` and `atan2f` call the paired selected `atan` and `atanf` symbols.
//!   `asin`, `acos`, and `asinf` call the existing exact static `sqrt` owner;
//!   `acosf` calls its `sqrtf` sibling, exactly as the musl sources do. No
//!   other scalar, complex, special, long-double, or ambient-libm provider is
//!   selected. Their argument reductions retain the existing scalar `fabs` and
//!   `fabsf` providers. That `sqrt` owner co-locates an independent `sqrtl`
//!   ABI entry, but this leaf's direct musl call graph invokes only its
//!   binary64 and binary32 entries.
//!
//! The compiler inputs preserve musl's scalar SSE operation order with
//! `-frounding-math`, standard excess precision, contracted-FMA disabled, and
//! vectorization disabled. TU-local helpers and labels are mechanically
//! namespaced. The retained FreeBSD/Sun notices in the checked assembly are
//! the source-specific license provenance; ordinary musl portions remain MIT
//! as recorded in `compat/upstreams.toml`.
//!
//! System V AMD64 passes binary32/binary64 arguments and results in XMM
//! registers. This component intentionally excludes `asinl`, `acosl`,
//! `atanl`, and `atan2l`, whose binary80 ABI remains an independent owner.
//! It is only selected by `x86-owned-static-runtime`: it does not alter the
//! frozen default archive, make a capability or family complete, establish a
//! full sysroot audit, promote x86, or change public support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the owned inverse-trigonometry leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("owned_inverse_trig_musl_x86_64.S"),
    options(att_syntax),
);
