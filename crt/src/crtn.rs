#![no_std]

//! Closing `.init` and `.fini` fragments for the AArch64 C-linker contract.

core::arch::global_asm!(
    r#"
    .section .init,"ax",@progbits
    ldp x29, x30, [sp], #16
    ret

    .section .fini,"ax",@progbits
    ldp x29, x30, [sp], #16
    ret

    .section .note.GNU-stack,"",@progbits
"#,
);
