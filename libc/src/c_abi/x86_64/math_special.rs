//! Complete static Linux/x86-64 `math.special` C ABI leaf.
//!
//! This module owns the 80 entries still missing from the 90-symbol
//! `math.special` capability in `compat/crabc-rs/coverage.toml`. The remaining
//! ten classifiers, sign predicates, binary80 conversions, and long-double
//! remainder entries are composed from the independently evidenced
//! `math_complex` and `math_x87_extended` leaves. It additionally owns musl's
//! observable `__signgam`/weak-`signgam` state required by `lgamma*`; that data
//! does not select the broader process-environment capability.
//!
//! ## Fixed source and license provenance
//!
//! `math_special_musl_x86_64.S` is an owned assembly translation of pinned
//! musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the release archive whose
//! SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! Its exact compiler/source input and mechanical symbol localization are
//! reproducible with `compat/x86_64/generate_libc_math_special.py`.
//! Musl-authored sources retain musl's MIT license. The FreeBSD-derived
//! fdlibm error/Bessel/gamma sources retain Sun Microsystems' 1993 permissive
//! notice, and the OpenBSD binary80 `erfl`/`lgammal`/`tgammal` sources also
//! retain Stephen L. Moshier's 2008 permissive notice. Those source-specific
//! notices are reproduced by the generator at the top of the checked assembly.
//! This translation is not a linked foreign object and the Rust build never
//! invokes a C compiler.
//!
//! The public source map covers:
//!
//! - `src/math/{erf,erff,erfl}.c` for binary32/binary64/binary80 error
//!   functions;
//! - `src/math/{j0,j0f,j1,j1f,jn,jnf}.c` for the complete Bessel block;
//! - `src/math/{lgamma,lgamma_r,lgammaf,lgammaf_r,lgammal,tgamma,tgammaf,
//!   tgammal,signgam}.c` for gamma behavior and its sign state;
//! - `src/math/{finite,finitef,frexp,frexpf,frexpl,ilogb,ilogbf,ilogbl,
//!   ldexp,ldexpf,ldexpl,logb,logbf,logbl,modf,modff,modfl,nan,nanf,nanl,
//!   nextafter,nextafterf,nextafterl,nexttoward,nexttowardf,nexttowardl,
//!   remainder,remainderf,remquo,remquof,scalb,scalbf,scalbln,scalblnf,
//!   scalblnl,scalbn,scalbnf,scalbnl,significand,significandf}.c` for the
//!   decomposition, stepping, scaling, and historical compatibility entries;
//! - `src/math/x86_64/{lrint,lrintf,llrint,llrintf}.c` plus
//!   `src/math/{lround,lroundf,lroundl,llround,llroundf,llroundl}.c` for the
//!   exact SysV integer-return block.
//!
//! Musl's special functions internally require sine/cosine, exp/log/pow,
//! square root, directed rounding, argument reduction, and coefficient data.
//! The generator includes their exact musl providers under local
//! `crabc_x86_math_special_*` names. They are private implementation detail:
//! they do not export or select `math.elementary`,
//! `math.elementary-long-double`, or `math.elementary-fenv-sensitive`.
//! Existing exact binary80 `expl`, `fabsl`, `floorl`, `logl`, classifiers, and
//! sign predicates remain explicit dependencies on the two prior x87 leaves.
//!
//! The translation preserves the System V AMD64 ABI directly: float/double
//! arguments and results use SSE registers; signed `int`/`long`/`long long`
//! results use the appropriate `eax`/`rax` width; and every C `long double`
//! input, output, pointer payload, mixed `nexttoward*` operand, and gamma sign
//! call retains the 16-byte stack/storage and x87 binary80 `st0` convention.
//! No binary80 operation narrows through binary64.
//!
//! This closes only the named private static `math.special` capability. It is
//! not general scalar/complex math, a dynamic `libc.so`, CRT/TLS lifecycle,
//! allocator, loader, sysroot, family completion, x86 promotion, full parity,
//! or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the math.special leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_special_musl_x86_64.S"),
    options(att_syntax),
);
