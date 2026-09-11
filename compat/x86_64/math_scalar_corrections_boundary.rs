//! Pure boundary proof compiles the actual production modules unchanged.
//! The installed sysroot test separately proves their runtime integration.
#![no_std]

#[path = "../../libc/src/c_abi/x86_64/math_scalar_completion.rs"]
mod math_scalar_completion;
#[path = "../../libc/src/c_abi/x86_64/math_pow.rs"]
mod math_pow;
#[path = "../../libc/src/c_abi/x86_64/math_elementary_long_double.rs"]
mod math_elementary_long_double;
#[path = "../../libc/src/c_abi/x86_64/math_special.rs"]
mod math_special;
#[path = "../../libc/src/c_abi/x86_64/math_complex.rs"]
mod math_complex;
#[path = "../../libc/src/c_abi/x86_64/math_x87_extended.rs"]
mod math_x87_extended;
#[path = "../../libc/src/c_abi/x86_64/fenv.rs"]
mod fenv;
#[path = "../../libc/src/c_abi/x86_64/elementary_sqrt.rs"]
mod elementary_sqrt;
#[path = "../../libc/src/c_abi/x86_64/fenv_rounding.rs"]
mod fenv_rounding;
