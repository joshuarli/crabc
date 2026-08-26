//! Linux/x86-64 source-only `setjmp` continuation boundary.
//!
//! This leaf is intentionally not selected by `crabc-libc`: its target root
//! and surrounding C ABI state remain Linux/AArch64-only until the complete
//! x86 runtime is proven. The standalone native probe links this exact SysV
//! assembly with one C fixture to establish the x86 machine-context and
//! signal-mask contract without pretending that an x86 libc artifact exists.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 setjmp leaf requires little-endian Linux/x86-64");

/*
 * The public jmp_buf begins with eight machine words: RBX, RBP, R12-R15,
 * post-return RSP, and RIP. `sigsetjmp` uses the following word temporarily
 * for the caller return address, then its 128-byte public mask storage at
 * offset 72. Keep the whole transfer in one assembly unit: a Rust wrapper
 * would save and resume its own frame rather than the C caller's frame.
 */
core::arch::global_asm!(
    r#"
    .text

    .p2align 4
    .global setjmp
    .global __setjmp
    .global _setjmp
    .type setjmp,@function
    .type __setjmp,@function
    .type _setjmp,@function
setjmp:
__setjmp:
_setjmp:
    mov qword ptr [rdi], rbx
    mov qword ptr [rdi + 8], rbp
    mov qword ptr [rdi + 16], r12
    mov qword ptr [rdi + 24], r13
    mov qword ptr [rdi + 32], r14
    mov qword ptr [rdi + 40], r15
    lea rdx, [rsp + 8]
    mov qword ptr [rdi + 48], rdx
    mov rdx, qword ptr [rsp]
    mov qword ptr [rdi + 56], rdx
    xor eax, eax
    ret
    .size setjmp, .-setjmp
    .size __setjmp, .-__setjmp
    .size _setjmp, .-_setjmp

    .p2align 4
    .global longjmp
    .global _longjmp
    .type longjmp,@function
    .type _longjmp,@function
longjmp:
_longjmp:
    xor eax, eax
    cmp esi, 1
    adc eax, esi
    mov rbx, qword ptr [rdi]
    mov rbp, qword ptr [rdi + 8]
    mov r12, qword ptr [rdi + 16]
    mov r13, qword ptr [rdi + 24]
    mov r14, qword ptr [rdi + 32]
    mov r15, qword ptr [rdi + 40]
    mov rsp, qword ptr [rdi + 48]
    jmp qword ptr [rdi + 56]
    .size longjmp, .-longjmp
    .size _longjmp, .-_longjmp

    .p2align 4
    .global sigsetjmp
    .global __sigsetjmp
    .type sigsetjmp,@function
    .type __sigsetjmp,@function
sigsetjmp:
__sigsetjmp:
    test esi, esi
    je setjmp
    pop qword ptr [rdi + 64]
    mov qword ptr [rdi + 80], rbx
    mov rbx, rdi
    call __setjmp
    push qword ptr [rbx + 64]
    mov rdi, rbx
    mov esi, eax
    mov rbx, qword ptr [rbx + 80]
    jmp .Lcrabc_x86_64_sigsetjmp_tail
    .size sigsetjmp, .-sigsetjmp
    .size __sigsetjmp, .-__sigsetjmp

    .p2align 4
.Lcrabc_x86_64_sigsetjmp_tail:
    mov r8d, esi
    xor edx, edx
    lea rsi, [rdi + 72]
    xor eax, eax
    test r8d, r8d
    mov r10d, 8
    mov edi, 2
    cmove rdx, rsi
    cmove rsi, rax
    mov eax, 14
    syscall
    mov eax, r8d
    ret

    .p2align 4
    .global siglongjmp
    .type siglongjmp,@function
siglongjmp:
    sub rsp, 8
    call _longjmp
    .size siglongjmp, .-siglongjmp

    .section .note.GNU-stack,"",@progbits
"#
);
