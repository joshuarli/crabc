#![no_std]

//! Closing `.init` and `.fini` fragments for x86-64 static PIE.

#[cfg(target_arch = "x86_64")]
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

// musl 1.2.6 crt/aarch64/crtn.s, MIT license.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .section .init,"ax",%progbits
    ldp x29, x30, [sp], 16
    ret

    .section .fini,"ax",%progbits
    ldp x29, x30, [sp], 16
    ret

    .section .note.GNU-stack,"",%progbits
"#,
);
