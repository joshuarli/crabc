//! Selected static Linux/x86-64 bit-sign math C ABI leaf.
//!
//! This target-private assembly is a literal operation-level mapping of
//! pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/math/fabs.c` maps to [`fabs`];
//! - `src/math/fabsf.c` maps to [`fabsf`];
//! - `src/math/copysign.c` maps to [`copysign`];
//! - `src/math/copysignf.c` maps to [`copysignf`].
//!
//! Each leaf rewrites only IEEE sign bits through SSE logical masks. Logical
//! `and*`/`or*` instructions neither compare nor perform arithmetic, so they
//! preserve binary32/binary64 NaN payload and signaling state without raising
//! `FE_INVALID`; they also leave the caller's MXCSR rounding direction and
//! existing exception flags untouched. The System V AMD64 ABI passes and
//! returns the selected scalar forms in `xmm0` (`copysign*` receives its sign
//! source in `xmm1`). Binary80 `fabsl`/`copysignl`, fdim, rounding, special,
//! general math, family completion, promotion, and public x86 support remain
//! outside this artifact.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 math bit-sign leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    r#"
    .text

    .p2align 4
    .global fabs
    .type fabs,@function
fabs:
    andpd xmm0, xmmword ptr [rip + .Lcrabc_x86_math_bit_sign_abs64]
    ret
    .size fabs, .-fabs

    .p2align 4
    .global fabsf
    .type fabsf,@function
fabsf:
    andps xmm0, xmmword ptr [rip + .Lcrabc_x86_math_bit_sign_abs32]
    ret
    .size fabsf, .-fabsf

    .p2align 4
    .global copysign
    .type copysign,@function
copysign:
    andpd xmm0, xmmword ptr [rip + .Lcrabc_x86_math_bit_sign_abs64]
    andpd xmm1, xmmword ptr [rip + .Lcrabc_x86_math_bit_sign_sign64]
    orpd xmm0, xmm1
    ret
    .size copysign, .-copysign

    .p2align 4
    .global copysignf
    .type copysignf,@function
copysignf:
    andps xmm0, xmmword ptr [rip + .Lcrabc_x86_math_bit_sign_abs32]
    andps xmm1, xmmword ptr [rip + .Lcrabc_x86_math_bit_sign_sign32]
    orps xmm0, xmm1
    ret
    .size copysignf, .-copysignf

    .section .rodata
    .p2align 4
.Lcrabc_x86_math_bit_sign_abs64:
    .quad 0x7fffffffffffffff
    .quad 0xffffffffffffffff
.Lcrabc_x86_math_bit_sign_sign64:
    .quad 0x8000000000000000
    .quad 0x0000000000000000
.Lcrabc_x86_math_bit_sign_abs32:
    .long 0x7fffffff
    .long 0xffffffff
    .long 0xffffffff
    .long 0xffffffff
.Lcrabc_x86_math_bit_sign_sign32:
    .long 0x80000000
    .long 0x00000000
    .long 0x00000000
    .long 0x00000000

    .section .note.GNU-stack, "", @progbits
"#,
);
