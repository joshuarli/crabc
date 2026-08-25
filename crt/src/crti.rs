#![no_std]

//! Opening `.init` and `.fini` fragments for the AArch64 C-linker contract.
//!
//! Intermediate input sections run between this object and `crtn.o`; keeping
//! the prologue in its own Rust-hosted object gives the conventional linker
//! order without importing an external assembly source.

core::arch::global_asm!(
    r#"
    .section .init,"ax",@progbits
    .global _init
    .type _init,%function
_init:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    .section .fini,"ax",@progbits
    .global _fini
    .type _fini,%function
_fini:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    .section .note.GNU-stack,"",@progbits
"#,
);
