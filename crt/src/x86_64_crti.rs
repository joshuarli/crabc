#![no_std]

//! Opening `.init` and `.fini` fragments for x86-64 static PIE.

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .section .init,"ax",@progbits
    .global _init
    .type _init,@function
_init:
    push rbp
    mov rbp, rsp

    .section .fini,"ax",@progbits
    .global _fini
    .type _fini,@function
_fini:
    push rbp
    mov rbp, rsp

    .section .note.GNU-stack,"",@progbits
"#,
);

// musl 1.2.6 crt/aarch64/crti.s, MIT license.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .section .init,"ax",%progbits
    .global _init
    .type _init,%function
    .align 2
_init:
    stp x29, x30, [sp, -16]!
    mov x29, sp

    .section .fini,"ax",%progbits
    .global _fini
    .type _fini,%function
    .align 2
_fini:
    stp x29, x30, [sp, -16]!
    mov x29, sp

    .section .note.GNU-stack,"",%progbits
"#,
);
