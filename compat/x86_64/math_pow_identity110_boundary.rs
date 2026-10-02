#![no_std]

include!("../../libc/src/c_abi/x86_64/static_archive_member.rs");

#[path = "../../libc/src/c_abi/x86_64/fenv.rs"]
mod fenv;
#[path = "../../libc/src/c_abi/x86_64/math_pow.rs"]
mod math_pow;
