//! Selected static Linux/x86-64 x87 long-double elementary math leaf.
//!
//! This module preserves the target-specific binary80 implementations from
//! pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license. Its
//! exact source map is:
//!
//! - `src/math/x86_64/{acosl,asinl,atanl,atan2l}.s` map the inverse-trigonometric
//!   entries to `FPATAN` and the x87 square-root construction;
//! - `src/math/x86_64/{exp2l,expl,expm1l}.s` map the exponential block to the
//!   x87 `F2XM1`/`FSCALE` algorithms, including musl's range and underflow
//!   handling;
//! - `src/math/x86_64/{logl,log1pl,log2l,log10l}.s` map the logarithm block to
//!   `FYL2X`/`FYL2XP1` with musl's near-zero `log1pl` selection;
//! - `src/math/x86_64/{floorl,ceill,truncl}.s`, `lrintl.c`, and `llrintl.c`
//!   map the locally owned rounding/conversion block while preserving the
//!   caller's x87 control word;
//! - `src/math/x86_64/{fmodl,remainderl,remquol}.c` map the iterative
//!   `FPREM`/`FPREM1` block, including `remquol`'s signed low quotient bits;
//! - `src/math/x86_64/fabsl.c` maps directly to `FABS`. The separately selected
//!   `fenv_rounding.rs` and `elementary_sqrt.rs` leaves remain the archive's
//!   single `rintl.c` and `sqrtl.c` owners; the focused differential composes
//!   both sibling symbols.
//!
//! The implementation difference is lexical only: Rust has no stable native
//! C `long double`, so the fixed System V AMD64 stack argument and x87 return
//! ABI is carried in one `global_asm!` leaf. No operation promotes or narrows
//! through binary64, and the focused native differential compares the defined
//! ten binary80 bytes and exception flags in all four rounding modes. This
//! artifact does not select long-double trigonometric, power, hyperbolic,
//! gamma/Bessel/error, or complex transcendental families; it is not scalar
//! math completion, `libc.so`, a CRT, loader, sysroot, promotion gate, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x87 extended-math leaf requires little-endian Linux/x86-64");

// Keep the fixed upstream spellings in AT&T syntax where practical. The eight
// upstream inline-assembly C leaves are expressed as equivalent complete ABI
// entries because stable Rust cannot name an x87 `long double` operand. The
// exp2l entry has its own text section: it is a real binary80 dependency of
// `math_long_double_completion.rs`, and section GC must not retain unrelated
// public x87 siblings merely because they share this Rust assembly input.
core::arch::global_asm!(
    r#"
    .text
    .section .text.crabc_x86_math_x87_extended_other,"ax",@progbits

    .p2align 4
    .global acosl
    .type acosl,@function
acosl:
    fldt 8(%rsp)
    fld %st(0)
    fld1
    fsub %st(0),%st(1)
    fadd %st(2)
    fmulp
    fsqrt
    fabs
    fxch %st(1)
    fpatan
    ret
    .size acosl, .-acosl

    .p2align 4
    .global asinl
    .type asinl,@function
asinl:
    fldt 8(%rsp)
    fld %st(0)
    fld1
    fsub %st(0),%st(1)
    fadd %st(2)
    fmulp
    fsqrt
    fpatan
    ret
    .size asinl, .-asinl

    .p2align 4
    .global atanl
    .type atanl,@function
atanl:
    fldt 8(%rsp)
    fld1
    fpatan
    ret
    .size atanl, .-atanl

    .p2align 4
    .global atan2l
    .type atan2l,@function
atan2l:
    fldt 8(%rsp)
    fldt 24(%rsp)
    fpatan
    ret
    .size atan2l, .-atan2l

    /* floorl.s also owns ceill and truncl. Its temporary control word uses
       the now-dead first input slot and is restored before return. */
    .section .text.floorl,"ax",@progbits
    .p2align 4
    .global floorl
    .type floorl,@function
floorl:
    fldt 8(%rsp)
    mov $0x7,%al
.Lcrabc_x87_round_with_control:
    fstcw 8(%rsp)
    mov 9(%rsp),%ah
    mov %al,9(%rsp)
    fldcw 8(%rsp)
    frndint
    mov %ah,9(%rsp)
    fldcw 8(%rsp)
    ret
    .size floorl, .-floorl

    .section .text.crabc_x86_math_x87_extended_other,"ax",@progbits
    .p2align 4
    .global ceill
    .type ceill,@function
ceill:
    fldt 8(%rsp)
    mov $0xb,%al
    jmp .Lcrabc_x87_round_with_control
    .size ceill, .-ceill

    .p2align 4
    .global truncl
    .type truncl,@function
truncl:
    fldt 8(%rsp)
    mov $0xf,%al
    jmp .Lcrabc_x87_round_with_control
    .size truncl, .-truncl

    /* musl exp2l.s owns both exp2l and expm1l. */
    .section .text.expm1l,"ax",@progbits
    .p2align 4
    .global expm1l
    .type expm1l,@function
expm1l:
    fldt 8(%rsp)
    fldl2e
    fmulp
    movl $0xc2820000,-4(%rsp)
    flds -4(%rsp)
    fucomip %st(1),%st
    fld1
    jb .Lcrabc_x87_expm1_general
    fstp %st(1)
    fchs
    ret
.Lcrabc_x87_expm1_general:
    fld %st(1)
    fabs
    fucomip %st(1),%st
    fstp %st(0)
    ja .Lcrabc_x87_expm1_scale
    f2xm1
    ret
.Lcrabc_x87_expm1_scale:
    push %rax
    call .Lcrabc_x87_exp2_inner
    pop %rax
    fld1
    fsubrp
    ret
    .size expm1l, .-expm1l

    .section .text.exp2l,"ax",@progbits
    .p2align 4
    .global exp2l
    .type exp2l,@function
exp2l:
    fldt 8(%rsp)
.Lcrabc_x87_exp2_inner:
    fld %st(0)
    sub $16,%rsp
    fstpt (%rsp)
    mov 8(%rsp),%ax
    and $0x7fff,%ax
    cmp $0x3fff+13,%ax
    jb .Lcrabc_x87_exp2_small
    cmp $0x3fff+15,%ax
    jae .Lcrabc_x87_exp2_extreme
    fsts (%rsp)
    cmpl $0xc67ff800,(%rsp)
    jb .Lcrabc_x87_exp2_reduce
    movl $0x5f000000,(%rsp)
    flds (%rsp)
    fld %st(1)
    fsub %st(1)
    faddp
    fucomip %st(1),%st
    je .Lcrabc_x87_exp2_reduce
    movl $1,(%rsp)
    flds (%rsp)
    fdiv %st(1)
    fstps (%rsp)
.Lcrabc_x87_exp2_reduce:
    fld1
    fld %st(1)
    frndint
    fxch %st(2)
    fsub %st(2)
    f2xm1
    faddp
.Lcrabc_x87_exp2_scale:
    fscale
    fstp %st(1)
    add $16,%rsp
    ret
.Lcrabc_x87_exp2_extreme:
    xor %eax,%eax
.Lcrabc_x87_exp2_small:
    cmp $0x3fff-64,%ax
    fld1
    jb .Lcrabc_x87_exp2_scale
    fstpt (%rsp)
    fistl 8(%rsp)
    fildl 8(%rsp)
    fsubrp %st(1)
    addl $0x3fff,8(%rsp)
    f2xm1
    fld1
    faddp
    fldt (%rsp)
    fmulp
    add $16,%rsp
    ret
    .size exp2l, .-exp2l

    .section .text.crabc_x86_math_x87_extended_other,"ax",@progbits
    /* musl expl.s: exp(x) = 2^hi + 2^hi (2^lo - 1), where hi+lo
       retains the exact extended-precision log2(e)*x product. */
    .p2align 4
    .global expl
    .type expl,@function
expl:
    fldt 8(%rsp)
    mov 16(%rsp), %ax
    or $0x8000, %ax
    sub $0xbfdf, %ax
    cmp $45, %ax
    jbe .Lcrabc_x87_exp_interesting
    test %ax, %ax
    fld1
    js .Lcrabc_x87_exp_tiny
    fscale
    fstp %st(1)
    ret
.Lcrabc_x87_exp_tiny:
    faddp
    ret
.Lcrabc_x87_exp_interesting:
    fldl2e
    subq $48, %rsp
    fmul %st(1),%st
    fld %st(0)
    fstpt (%rsp)
    fstpt 16(%rsp)
    fstpt 32(%rsp)
    call exp2l@PLT
    fld %st(0)
    fstpt (%rsp)
    cmpw $0x7fff, 8(%rsp)
    je .Lcrabc_x87_exp_done
    fldt 32(%rsp)
    fldt 16(%rsp)
    fld %st(1)
    movq $0x41f0000000100000,%rax
    pushq %rax
    fldl (%rsp)
    fmulp
    fld %st(2)
    fsub %st(1), %st
    faddp
    fld %st(2)
    fsub %st(1), %st
    movq $0x3ff7154765200000,%rax
    pushq %rax
    fldl (%rsp)
    fld %st(2)
    fmul %st(1), %st
    fsubp %st, %st(4)
    fmul %st(1), %st
    faddp %st, %st(3)
    movq $0x3de705fc2f000000,%rax
    pushq %rax
    fldl (%rsp)
    fmul %st, %st(2)
    fmulp %st, %st(1)
    fxch %st(2)
    faddp
    faddp
    movq $0xbfbe,%rax
    pushq %rax
    movq $0x82f0025f2dc582ee,%rax
    pushq %rax
    fldt (%rsp)
    addq $40,%rsp
    fmulp %st, %st(2)
    faddp
    f2xm1
    fmul %st(1), %st
    faddp
.Lcrabc_x87_exp_done:
    addq $48, %rsp
    ret
    .size expl, .-expl

    .p2align 4
    .global log10l
    .type log10l,@function
log10l:
    fldlg2
    fldt 8(%rsp)
    fyl2x
    ret
    .size log10l, .-log10l

    .p2align 4
    .global log1pl
    .type log1pl,@function
log1pl:
    mov 14(%rsp),%eax
    fldln2
    and $0x7fffffff,%eax
    fldt 8(%rsp)
    cmp $0x3ffd9400,%eax
    ja .Lcrabc_x87_log1p_general
    fyl2xp1
    ret
.Lcrabc_x87_log1p_general:
    fld1
    faddp
    fyl2x
    ret
    .size log1pl, .-log1pl

    .p2align 4
    .global log2l
    .type log2l,@function
log2l:
    fld1
    fldt 8(%rsp)
    fyl2x
    ret
    .size log2l, .-log2l

    .p2align 4
    .global logl
    .type logl,@function
logl:
    fldln2
    fldt 8(%rsp)
    fyl2x
    ret
    .size logl, .-logl

    .section .text.fabsl,"ax",@progbits
    .p2align 4
    .global fabsl
    .type fabsl,@function
fabsl:
    fldt 8(%rsp)
    fabs
    ret
    .size fabsl, .-fabsl

    .section .text.crabc_x86_math_x87_extended_other,"ax",@progbits
    .p2align 4
    .global fmodl
    .type fmodl,@function
fmodl:
    fldt 24(%rsp)
    fldt 8(%rsp)
.Lcrabc_x87_fmod_loop:
    fprem
    fnstsw %ax
    test $0x400,%ax
    jne .Lcrabc_x87_fmod_loop
    fstp %st(1)
    ret
    .size fmodl, .-fmodl

    .p2align 4
    .global lrintl
    .type lrintl,@function
lrintl:
    fldt 8(%rsp)
    fistpll -8(%rsp)
    movq -8(%rsp),%rax
    ret
    .size lrintl, .-lrintl

    .p2align 4
    .global llrintl
    .type llrintl,@function
llrintl:
    fldt 8(%rsp)
    fistpll -8(%rsp)
    movq -8(%rsp),%rax
    ret
    .size llrintl, .-llrintl

    .p2align 4
    .global remainderl
    .type remainderl,@function
remainderl:
    fldt 24(%rsp)
    fldt 8(%rsp)
.Lcrabc_x87_remainder_loop:
    fprem1
    fnstsw %ax
    test $0x400,%ax
    jne .Lcrabc_x87_remainder_loop
    fstp %st(1)
    ret
    .size remainderl, .-remainderl

    .p2align 4
    .global remquol
    .type remquol,@function
remquol:
    fldt 24(%rsp)
    fldt 8(%rsp)
.Lcrabc_x87_remquo_loop:
    fprem1
    fnstsw %ax
    test $0x400,%ax
    jne .Lcrabc_x87_remquo_loop
    fstp %st(1)
    movzwl %ax,%edx
    mov %edx,%ecx
    shr $9,%ecx
    and $1,%ecx
    mov %edx,%r8d
    shr $13,%r8d
    and $2,%r8d
    or %r8d,%ecx
    shr $6,%edx
    and $4,%edx
    or %edx,%ecx
    movzbl 17(%rsp),%edx
    xor 33(%rsp),%dl
    test $0x80,%dl
    jz .Lcrabc_x87_remquo_store
    neg %ecx
.Lcrabc_x87_remquo_store:
    mov %ecx,(%rdi)
    ret
    .size remquol, .-remquol

    .section .note.GNU-stack, "", @progbits
"#,
    options(att_syntax),
);
