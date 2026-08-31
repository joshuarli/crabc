//! Selected static Linux/x86-64 square-root C ABI leaf.
//!
//! This target-private leaf maps the complete pinned musl 1.2.6
//! (`9fa28ece75d8a2191de7c5bb53bed224c5947417`) x86-64 implementation of
//! exactly three elementary functions, under musl's MIT license:
//!
//! - `src/math/x86_64/sqrt.c` maps to the scalar `sqrtsd` entry below;
//! - `src/math/x86_64/sqrtf.c` maps to the scalar `sqrtss` entry below;
//! - `src/math/x86_64/sqrtl.c` maps to the x87 `fsqrt` entry below.
//!
//! The instruction choice is observable C behavior. `sqrt` and `sqrtf`
//! consume MXCSR rounding and exception state, while the x87 binary80
//! `sqrtl` consumes the x87 control word and status state. Rust has no stable
//! C binary80 type, so the System V AMD64 stack-argument and `st0` return ABI
//! stays in assembly rather than borrowing AArch64's binary128 math code.
//!
//! The paired native fixture proves all four rounding modes, signed zero,
//! infinities, NaNs, negative-domain `FE_INVALID`, and inexact results against
//! pinned musl. This remains one selected static artifact inside the planned
//! math family: it does not select any other elementary operation, general
//! libm, complex math, errno policy, libc.so, CRT, loader, sysroot, family
//! completion, promotion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 square-root leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    r#"
    .text

    .p2align 4
    .global sqrt
    .type sqrt,@function
sqrt:
    sqrtsd xmm0, xmm0
    ret
    .size sqrt, .-sqrt

    .p2align 4
    .global sqrtf
    .type sqrtf,@function
sqrtf:
    sqrtss xmm0, xmm0
    ret
    .size sqrtf, .-sqrtf

    /* System V AMD64 classifies long double as X87. The argument therefore
       occupies 16 bytes of stack storage beginning at rsp+8; the binary80
       result returns in st0. */
    .p2align 4
    .global sqrtl
    .type sqrtl,@function
sqrtl:
    fld tbyte ptr [rsp + 8]
    fsqrt
    ret
    .size sqrtl, .-sqrtl

    .section .note.GNU-stack, "", @progbits
"#,
);
