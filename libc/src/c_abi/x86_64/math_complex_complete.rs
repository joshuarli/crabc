//! Complete private static Linux/x86-64 `math.complex` C ABI leaf.
//!
//! This leaf owns the 57 entries missing from the 66-symbol `math.complex`
//! capability in `compat/crabc-rs/coverage.toml`. The nine `creal*`, `cimag*`,
//! and `conj*` foundation entries remain in `math_complex.rs`; together these
//! two leaves are the exact capability surface. No scalar elementary function
//! becomes public merely because a complex algorithm uses it internally.
//!
//! ## Fixed source and license provenance
//!
//! `math_complex_complete_musl_x86_64.S` is an owned assembly translation of
//! pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the release archive whose
//! SHA-256 is
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! The exact compiler/source input and mechanical symbol localization are
//! reproducible with
//! `compat/x86_64/generate_libc_math_complex_complete.py`. The generator
//! verifies the normalized complete source tree, pins GCC 15.2.0, and retains
//! each copyright-bearing source notice verbatim in the checked assembly.
//! This translation is not a linked foreign object and the Rust build never
//! invokes a C compiler.
//!
//! The public source map is every corresponding musl `src/complex/*.c` file:
//!
//! - `cabs*`, `carg*`, and `cproj*` own magnitude, phase, and projection;
//! - `cacos*`, `cacosh*`, `casin*`, `casinh*`, `catan*`, and `catanh*` own
//!   inverse circular/hyperbolic functions;
//! - `ccos*`, `ccosh*`, `csin*`, `csinh*`, `ctan*`, and `ctanh*` own circular
//!   and hyperbolic functions;
//! - `cexp*`, `clog*`, `cpow*`, and `csqrt*` own exponential, logarithmic,
//!   power, and square-root functions;
//! - private `__cexp.c` and `__cexpf.c` own scaled exponential support.
//!
//! Those sources require scalar atan/atan2, trigonometric, hyperbolic,
//! exp/log, hypot, scaling, square-root, argument-reduction, error, and data
//! providers. The generator includes their exact musl sources under local
//! `crabc_x86_math_complex_*` names. They do not export or select
//! `math.elementary`, `math.elementary-long-double`, or
//! `math.elementary-fenv-sensitive`. Existing exact `__fpclassifyl`,
//! `__signbitl`, `atan2l`, `logl`, and `sqrtl` remain explicit dependencies
//! on prior selected leaves.
//!
//! `cpow*` need the compiler complex-multiply ABI helpers. The checked
//! translation includes direct source translations of LLVM compiler-rt
//! 22.1.3 `lib/builtins/{mulsc3,muldc3,mulxc3}.c`, under Apache-2.0 WITH
//! LLVM-exception. Their four-product and NaN/infinity recovery sequence is
//! unchanged; the three symbols are localized implementation details. This
//! extends the already-pinned `__muldc3` source oracle recorded in
//! `builtins/UPSTREAM.md`; it does not add a linked compiler runtime or a new
//! production dependency.
//!
//! The translation preserves the System V AMD64 ABI: float/double complex
//! arguments and results use the specified SSE register classes, while every
//! C `long double` and `_Complex long double` argument, component, and result
//! retains 16-byte binary80 storage and the x87 `st0`/`st1` return convention.
//! Musl 1.2.6's x86 source intentionally implements `ccoshl`, `cexpl`,
//! `csinhl`, `csqrtl`, and `ctanhl` as FIXME-marked wrappers through the
//! corresponding binary64 complex functions. That internal narrowing is
//! preserved exactly as source-oracle behavior; it does not change their
//! binary80 public ABI. The remaining long-complex algorithms use musl's
//! x87 paths directly.
//!
//! This closes only the named private static `math.complex` capability. It is
//! not general scalar math, a dynamic `libc.so`, CRT/TLS lifecycle, allocator,
//! loader, sysroot, family completion, x86 promotion, full parity, or public
//! x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the complete math.complex leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    include_str!("math_complex_complete_musl_x86_64.S"),
    options(att_syntax),
);
