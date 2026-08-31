//! Selected static Linux/x86-64 binary32/binary64 extrema C ABI leaf.
//!
//! This is a direct control-flow translation of pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT
//! license:
//!
//! - `src/math/fmax.c` maps to [`fmax`];
//! - `src/math/fmaxf.c` maps to [`fmaxf`];
//! - `src/math/fmin.c` maps to [`fmin`];
//! - `src/math/fminf.c` maps to [`fminf`].
//!
//! Musl first tests each operand with `isnan`, then uses the operands' sign
//! bits to select the required signed zero before making an ordered compare.
//! The assembly preserves that sequence with raw IEEE exponent/fraction tests:
//! a quiet or signaling NaN never reaches `ucomis*`, so it cannot create a
//! spurious `FE_INVALID`. It returns musl's selected other operand for one or
//! two NaNs, returns +0 from `fmax*` and -0 from `fmin*` for opposed zero
//! signs, and makes an SSE comparison only once both operands are known not to
//! be NaNs. No operation changes MXCSR.
//!
//! This target-private leaf owns exactly `fmax`, `fmaxf`, `fmin`, and `fminf`.
//! It excludes `fmaxl`/`fminl`, `fdim*`, bit-sign functions, current- or
//! integer-result rounding, binary80/x87 math, special and complex functions,
//! errno policy, general libm, libc.so, CRT/TLS lifecycle, loader, sysroot,
//! family completion, promotion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 binary32/binary64 extrema leaf requires little-endian Linux/x86-64");

// Integer classification precedes each UCOMIS instruction. In particular,
// UCOMIS would signal invalid for an sNaN, while musl's `isnan` path merely
// chooses an operand and returns it.
core::arch::global_asm!(
    r#"
    .text

    .p2align 4
    .global fmax
    .type fmax,@function
fmax:
    movq rax, xmm0
    mov rdx, rax
    shr rdx, 52
    and edx, 0x7ff
    cmp edx, 0x7ff
    jne .Lcrabc_fmax_x_not_nan
    shl rax, 12
    test rax, rax
    jnz .Lcrabc_fmax_return_y
.Lcrabc_fmax_x_not_nan:
    movq rax, xmm1
    mov rdx, rax
    shr rdx, 52
    and edx, 0x7ff
    cmp edx, 0x7ff
    jne .Lcrabc_fmax_y_not_nan
    shl rax, 12
    test rax, rax
    jnz .Lcrabc_fmax_return_x
.Lcrabc_fmax_y_not_nan:
    movq rax, xmm0
    movq rdx, xmm1
    xor rdx, rax
    jns .Lcrabc_fmax_same_sign
    test rax, rax
    js .Lcrabc_fmax_return_y
    ret
.Lcrabc_fmax_same_sign:
    ucomisd xmm0, xmm1
    jb .Lcrabc_fmax_return_y
.Lcrabc_fmax_return_x:
    ret
.Lcrabc_fmax_return_y:
    movapd xmm0, xmm1
    ret
    .size fmax, .-fmax

    .p2align 4
    .global fmaxf
    .type fmaxf,@function
fmaxf:
    movd eax, xmm0
    mov edx, eax
    shr edx, 23
    and edx, 0xff
    cmp edx, 0xff
    jne .Lcrabc_fmaxf_x_not_nan
    shl eax, 9
    test eax, eax
    jnz .Lcrabc_fmaxf_return_y
.Lcrabc_fmaxf_x_not_nan:
    movd eax, xmm1
    mov edx, eax
    shr edx, 23
    and edx, 0xff
    cmp edx, 0xff
    jne .Lcrabc_fmaxf_y_not_nan
    shl eax, 9
    test eax, eax
    jnz .Lcrabc_fmaxf_return_x
.Lcrabc_fmaxf_y_not_nan:
    movd eax, xmm0
    movd edx, xmm1
    xor edx, eax
    jns .Lcrabc_fmaxf_same_sign
    test eax, eax
    js .Lcrabc_fmaxf_return_y
    ret
.Lcrabc_fmaxf_same_sign:
    ucomiss xmm0, xmm1
    jb .Lcrabc_fmaxf_return_y
.Lcrabc_fmaxf_return_x:
    ret
.Lcrabc_fmaxf_return_y:
    movaps xmm0, xmm1
    ret
    .size fmaxf, .-fmaxf

    .p2align 4
    .global fmin
    .type fmin,@function
fmin:
    movq rax, xmm0
    mov rdx, rax
    shr rdx, 52
    and edx, 0x7ff
    cmp edx, 0x7ff
    jne .Lcrabc_fmin_x_not_nan
    shl rax, 12
    test rax, rax
    jnz .Lcrabc_fmin_return_y
.Lcrabc_fmin_x_not_nan:
    movq rax, xmm1
    mov rdx, rax
    shr rdx, 52
    and edx, 0x7ff
    cmp edx, 0x7ff
    jne .Lcrabc_fmin_y_not_nan
    shl rax, 12
    test rax, rax
    jnz .Lcrabc_fmin_return_x
.Lcrabc_fmin_y_not_nan:
    movq rax, xmm0
    movq rdx, xmm1
    xor rdx, rax
    jns .Lcrabc_fmin_same_sign
    test rax, rax
    js .Lcrabc_fmin_return_x
    movapd xmm0, xmm1
    ret
.Lcrabc_fmin_same_sign:
    ucomisd xmm0, xmm1
    jb .Lcrabc_fmin_return_x
.Lcrabc_fmin_return_y:
    movapd xmm0, xmm1
    ret
.Lcrabc_fmin_return_x:
    ret
    .size fmin, .-fmin

    .p2align 4
    .global fminf
    .type fminf,@function
fminf:
    movd eax, xmm0
    mov edx, eax
    shr edx, 23
    and edx, 0xff
    cmp edx, 0xff
    jne .Lcrabc_fminf_x_not_nan
    shl eax, 9
    test eax, eax
    jnz .Lcrabc_fminf_return_y
.Lcrabc_fminf_x_not_nan:
    movd eax, xmm1
    mov edx, eax
    shr edx, 23
    and edx, 0xff
    cmp edx, 0xff
    jne .Lcrabc_fminf_y_not_nan
    shl eax, 9
    test eax, eax
    jnz .Lcrabc_fminf_return_x
.Lcrabc_fminf_y_not_nan:
    movd eax, xmm0
    movd edx, xmm1
    xor edx, eax
    jns .Lcrabc_fminf_same_sign
    test eax, eax
    js .Lcrabc_fminf_return_x
    movaps xmm0, xmm1
    ret
.Lcrabc_fminf_same_sign:
    ucomiss xmm0, xmm1
    jb .Lcrabc_fminf_return_x
.Lcrabc_fminf_return_y:
    movaps xmm0, xmm1
    ret
.Lcrabc_fminf_return_x:
    ret
    .size fminf, .-fminf

    .section .note.GNU-stack, "", @progbits
"#,
);
