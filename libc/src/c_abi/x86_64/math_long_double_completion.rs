//! Private Linux/x86-64 binary80 `fdiml` and GNU `exp10l`/`pow10l` closure.
//!
//! This opt-in leaf is a checked GCC 15.2.0 assembly translation of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from
//! the release archive whose SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_long_double_completion.py` validates the
//! normalized musl tree digest and compiler identity before writing the fixed
//! assembly included below.  Rust's build never invokes a foreign compiler.
//!
//! ## Exact source map and target boundary
//!
//! - `src/math/fdiml.c` maps the non-binary64 branch to strong `fdiml`: raw
//!   left-to-right NaN selection through the existing exact `__fpclassifyl`,
//!   positive zero for `x <= y`, and the one x87 `x - y` path whose exceptions
//!   and directed result remain caller-visible.
//! - `src/math/exp10l.c` maps its `LDBL_MANT_DIG == 64`,
//!   `LDBL_MAX_EXP == 16384` branch to strong `exp10l` and musl's weak
//!   same-address `pow10l` alias.  It retains the exponent-bit table test,
//!   exact `[-15, 15]` decimal table, fractional `exp2l(log2(10) * y)` path,
//!   and `powl(10, x)` fallback.
//! - Existing target-owned dependencies include `__fpclassifyl` from
//!   `math_x87_extended.rs`, `modfl` from `math_special.rs`, `exp2l` from
//!   `math_x87_extended.rs`, and `powl` from `math_elementary_long_double.rs`.
//!   They are linked by their public C ABI spellings exactly as musl's source calls them; this
//!   leaf does not create a second provider or borrow the AArch64 binary128 implementations.
//!   `powl`'s already-proved x87 closure in turn needs exact
//!   `__fpclassifyl`/`__signbitl`, `fabsl`, `floorl`, `frexpl`, `scalbnl`, and
//!   its local polynomial helpers.  The focused link proof admits exactly that
//!   transitive closure and rejects every adjacent math/runtime export.
//!
//! System V AMD64 passes each `long double` stack argument in a 16-byte slot
//! and returns its defined ten-byte binary80 value in `st(0)`.  The source's
//! `ldshape.se` observation reads only that binary80 sign/exponent word; the
//! ABI padding is neither read nor defined.  The focused native runner proves
//! this representation/calling boundary separately from its musl behavioral
//! record differential, including all four x87/MXCSR rounding modes.
//!
//! This opt-in leaf alone does not change the default selected-static export root or select a
//! family. Its aggregate native-evidence slice selects only
//! `math.elementary-fenv-sensitive`; it does not select a general libm/libc,
//! CRT/TLS lifecycle, loader, sysroot, promotion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 binary80 math closure requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_long_double_completion_musl_x86_64.S"),
    options(att_syntax),
);
