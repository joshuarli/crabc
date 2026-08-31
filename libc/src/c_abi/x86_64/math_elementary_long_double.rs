//! Complete static Linux/x86-64 `math.elementary-long-double` C ABI leaf.
//!
//! This module owns the eighteen binary80 entries that were not already
//! supplied by `math_x87_extended`. Together the two leaves own the exact
//! 35-symbol `math.elementary-long-double` capability recorded in
//! `compat/crabc-rs/coverage.toml`: `acoshl`, `acosl`, `asinhl`, `asinl`,
//! `atan2l`, `atanhl`, `atanl`, `cbrtl`, `ceill`, `copysignl`, `coshl`,
//! `cosl`, `exp2l`, `expl`, `expm1l`, `fabsl`, `floorl`, `fmal`, `fmaxl`,
//! `fminl`, `fmodl`, `hypotl`, `log10l`, `log1pl`, `log2l`, `logl`, `powl`,
//! `roundl`, `sincosl`, `sinhl`, `sinl`, `sqrtl`, `tanhl`, `tanl`, and
//! `truncl`.
//!
//! ## Fixed source and license provenance
//!
//! `math_elementary_long_double_musl_x86_64.S` is an owned assembly
//! translation of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the release archive whose
//! SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `compat/x86_64/generate_libc_math_elementary_long_double.py` verifies the
//! normalized complete source-tree digest and pinned GCC 15.2.0 before
//! producing the checked assembly. The Rust build never invokes a C compiler.
//!
//! The public source map is:
//!
//! - `src/math/{acoshl,asinhl,atanhl,coshl,cosl,sinhl,sinl,tanhl,tanl}.c`
//!   for inverse, circular, and hyperbolic functions;
//! - `src/math/{cbrtl,copysignl,fmaxl,fminl,hypotl,roundl,sincosl}.c` for
//!   elementary construction, sign, extrema, norm, rounding, and paired
//!   sine/cosine entries;
//! - `src/math/fmal.c` for correctly rounded fused multiply-add behavior;
//! - `src/math/powl.c` for x87 binary80 exponentiation.
//!
//! The normal musl portions retain musl's MIT license. The generator preserves
//! the source-specific permissive notices for FreeBSD-derived `cbrtl` and
//! `fmal` and OpenBSD-derived `powl` in the checked assembly. The fixed private
//! trigonometric closure is `__cosl`, `__sinl`, `__tanl`, `__rem_pio2l`,
//! `__rem_pio2_large`, `__polevll`, plus binary64 `floor`/`scalbn` needed only
//! by argument reduction. Those names are mechanically prefixed and local, so
//! this leaf does not accidentally expose or select another elementary
//! capability.
//!
//! The public sources deliberately compose the already evidenced exact x87
//! leaves (`log1pl`, `logl`, `sqrtl`, `expl`, `expm1l`, `fabsl`, `floorl`, and
//! other members listed above), the `math.special` decomposition/stepping
//! leaves (`__fpclassifyl`, `__signbitl`, `frexpl`, `ilogbl`, `nextafterl`, and
//! `scalbnl`), and the selected x87/MXCSR fenv owner used by musl's `fmal`.
//! Reusing those closed boundaries neither changes their contracts nor turns
//! this capability into standalone fenv, special, or binary64 math support.
//!
//! Every public argument and return keeps the System V AMD64 long-double ABI:
//! each input is a 16-byte align-16 stack slot with ten defined binary80 bytes,
//! scalar results leave in x87 `st0`, and `sincosl` receives ordinary pointer
//! arguments for its two binary80 outputs. The algorithms retain musl's own
//! internal binary64 estimate/argument-reduction steps where upstream uses
//! them, but no public binary80 boundary narrows through `double`.
//!
//! This closes only the named private static `math.elementary-long-double`
//! capability. It is not `math.elementary-fenv-sensitive`, numeric parsing,
//! complex math, a general `libm`/`libc.so`, CRT/TLS lifecycle, allocator,
//! loader, sysroot, family completion, x86 promotion, full parity, or public
//! x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the math.elementary-long-double leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_elementary_long_double_musl_x86_64.S"),
    options(att_syntax),
);
