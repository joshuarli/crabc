// Cohesive musl-derived numerical algorithms that intentionally share the
// enclosing C ABI namespace's private bit, fenv, and f128 helpers.  This is
// a lexical aggregation, not a generic module boundary.

include!("math_helpers.rs");
include!("math_bitmanip.rs");
include!("math_sqrtfmod.rs");
include!("math_trig.rs");
include!("math_exp.rs");
include!("math_log.rs");
include!("math_pow.rs");
include!("math_hypot.rs");
include!("math_hyperbolic.rs");
include!("math_inverse_hyperbolic.rs");
include!("math_invtrig.rs");
include!("math_lrint.rs");
include!("math_bessel.rs");
include!("math_gamma.rs");
include!("math_compat.rs");
include!("math_f128.rs");
