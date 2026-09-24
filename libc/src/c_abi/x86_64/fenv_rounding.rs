//! Selected static Linux/x86-64 fenv-sensitive rounding C ABI leaf.
//!
//! This is a target-private semantic port of the corresponding pinned musl
//! 1.2.6 release sources at commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/math/rint.c` and `rintf.c` map to the SSE2 add/subtract-by-`toint`
//!   sequences below, retaining default x86-64 `FLT_EVAL_METHOD == 0` and
//!   MXCSR rounding/exception behavior;
//! - `src/math/x86_64/rintl.c`, which replaces the generic `rintl.c` on this
//!   target, maps to one `FRNDINT` under the caller's x87 control word;
//! - `src/math/nearbyint.c`, `nearbyintf.c`, and `nearbyintl.c` map to the
//!   wrappers which preserve an already-raised `FE_INEXACT` and otherwise
//!   clear only the inexact raised by the paired `rint*` operation.
//!
//! AArch64 owns the same six public C entry points in `math_lrint.rs` and
//! `math_compat.rs`, but its binary128 long-double ABI and `frinti` instruction
//! cannot cross this boundary. Rust also has no stable C binary80 type, so the
//! x87 scalar argument/return ABI remains in assembly. The native fixture
//! proves all four rounding modes, exact signed-zero results, inexact flag
//! behavior, and preexisting-exception preservation against pinned musl.
//!
//! This leaf selects no `exp10*`/`pow10*`, `fdim*`, integer-result rounding,
//! general elementary math, libc.so, loader, sysroot, family completion,
//! promotion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 fenv-sensitive rounding leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    r#"
    .section .text.rint, "ax", @progbits
    .p2align 4
    .global rint
    .type rint,@function
rint:
    movq rax, xmm0
    mov rcx, rax
    shr rcx, 52
    and ecx, 0x7ff
    cmp ecx, 0x433
    jae .Lcrabc_x86_rint_return
    bt rax, 63
    jc .Lcrabc_x86_rint_negative
    addsd xmm0, qword ptr [rip + .Lcrabc_x86_rint_to_int]
    subsd xmm0, qword ptr [rip + .Lcrabc_x86_rint_to_int]
    jmp .Lcrabc_x86_rint_zero
.Lcrabc_x86_rint_negative:
    subsd xmm0, qword ptr [rip + .Lcrabc_x86_rint_to_int]
    addsd xmm0, qword ptr [rip + .Lcrabc_x86_rint_to_int]
.Lcrabc_x86_rint_zero:
    pxor xmm1, xmm1
    ucomisd xmm0, xmm1
    jne .Lcrabc_x86_rint_return
    shr rax, 63
    shl rax, 63
    movq xmm0, rax
.Lcrabc_x86_rint_return:
    ret
    .size rint, .-rint

    .section .text.rintf, "ax", @progbits
    .p2align 4
    .global rintf
    .type rintf,@function
rintf:
    movd eax, xmm0
    mov ecx, eax
    shr ecx, 23
    and ecx, 0xff
    cmp ecx, 0x96
    jae .Lcrabc_x86_rintf_return
    bt eax, 31
    jc .Lcrabc_x86_rintf_negative
    addss xmm0, dword ptr [rip + .Lcrabc_x86_rintf_to_int]
    subss xmm0, dword ptr [rip + .Lcrabc_x86_rintf_to_int]
    jmp .Lcrabc_x86_rintf_zero
.Lcrabc_x86_rintf_negative:
    subss xmm0, dword ptr [rip + .Lcrabc_x86_rintf_to_int]
    addss xmm0, dword ptr [rip + .Lcrabc_x86_rintf_to_int]
.Lcrabc_x86_rintf_zero:
    pxor xmm1, xmm1
    ucomiss xmm0, xmm1
    jne .Lcrabc_x86_rintf_return
    and eax, 0x80000000
    movd xmm0, eax
.Lcrabc_x86_rintf_return:
    ret
    .size rintf, .-rintf

    /* musl src/math/x86_64/rintl.c, which replaces the generic rintl.c on
       this target: FRNDINT under the caller's x87 control word. It quiets a
       signaling NaN and raises FE_INVALID for it and for unsupported binary80
       encodings, which the generic add/subtract sequence does not. */
    .section .text.rintl, "ax", @progbits
    .p2align 4
    .global rintl
    .type rintl,@function
rintl:
    fld tbyte ptr [rsp + 8]
    frndint
    ret
    .size rintl, .-rintl

    /* Keep the fenv observation, arithmetic, and conditional flag clear in
       one assembly sequence. A compiler that does not model FENV_ACCESS may
       otherwise legally move the rint call after feclearexcept. */
    .section .text.nearbyint, "ax", @progbits
    .p2align 4
    .global nearbyint
    .type nearbyint,@function
nearbyint:
    push rbx
    sub rsp, 16
    movsd qword ptr [rsp], xmm0
    mov edi, 32
    call fetestexcept
    mov ebx, eax
    movsd xmm0, qword ptr [rsp]
    add rsp, 16
    call rint
    test ebx, ebx
    jnz .Lcrabc_x86_nearbyint_done
    sub rsp, 16
    movsd qword ptr [rsp], xmm0
    mov edi, 32
    call feclearexcept
    movsd xmm0, qword ptr [rsp]
    add rsp, 16
.Lcrabc_x86_nearbyint_done:
    pop rbx
    ret
    .size nearbyint, .-nearbyint

    .section .text.nearbyintf, "ax", @progbits
    .p2align 4
    .global nearbyintf
    .type nearbyintf,@function
nearbyintf:
    push rbx
    sub rsp, 16
    movss dword ptr [rsp], xmm0
    mov edi, 32
    call fetestexcept
    mov ebx, eax
    movss xmm0, dword ptr [rsp]
    add rsp, 16
    call rintf
    test ebx, ebx
    jnz .Lcrabc_x86_nearbyintf_done
    sub rsp, 16
    movss dword ptr [rsp], xmm0
    mov edi, 32
    call feclearexcept
    movss xmm0, dword ptr [rsp]
    add rsp, 16
.Lcrabc_x86_nearbyintf_done:
    pop rbx
    ret
    .size nearbyintf, .-nearbyintf

    /* nearbyintl needs the public binary80 stack ABI on both calls. Preserve
       the result across musl's selected feclearexcept leaf explicitly even
       though that leaf does not itself disturb st0. */
    .section .text.nearbyintl, "ax", @progbits
    .p2align 4
    .global nearbyintl
    .type nearbyintl,@function
nearbyintl:
    push rbx
    mov edi, 32
    call fetestexcept
    mov ebx, eax
    mov rax, qword ptr [rsp + 16]
    mov rdx, qword ptr [rsp + 24]
    sub rsp, 16
    mov qword ptr [rsp], rax
    mov qword ptr [rsp + 8], rdx
    call rintl
    add rsp, 16
    test ebx, ebx
    jnz .Lcrabc_x86_nearbyintl_done
    sub rsp, 16
    fstp tbyte ptr [rsp]
    mov edi, 32
    call feclearexcept
    fld tbyte ptr [rsp]
    add rsp, 16
.Lcrabc_x86_nearbyintl_done:
    pop rbx
    ret
    .size nearbyintl, .-nearbyintl

    .section .rodata.fenv_rounding, "a", @progbits
    .p2align 3
.Lcrabc_x86_rint_to_int:
    .quad 0x4330000000000000
.Lcrabc_x86_rintf_to_int:
    .long 0x4b000000

    .section .note.GNU-stack, "", @progbits
"#,
);
