#![no_std]

//! Opening `.init` and `.fini` fragments for x86-64 static PIE.

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
