#![no_std]

//! Closing `.init` and `.fini` fragments for x86-64 static PIE.

core::arch::global_asm!(
    r#"
    .section .init,"ax",@progbits
    pop rbp
    ret

    .section .fini,"ax",@progbits
    pop rbp
    ret

    .section .note.GNU-stack,"",@progbits
"#,
);
