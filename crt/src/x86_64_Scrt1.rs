#![no_std]

//! Position-independent Linux/x86-64 dynamic-PIE application entry.
//!
//! The entry is deliberately minimal and leaves the original initial stack
//! untouched until normal Rust startup parses it. An ELF interpreter has
//! already relocated this image; `%rdx` is deliberately not consumed as a
//! finalizer because pinned musl 1.2.6 x86-64 `Scrt1.o` passes a null finalizer
//! to `__libc_start_main` instead.

mod x86_64_array_boundaries;
mod x86_64_dynamic_startup;

pub use x86_64_dynamic_startup::__crabc_x86_64_dynamic_start;

// This private marker is a future crabc-loader admission check, not an ELF
// export or a current loader-to-CRT handoff. Pinned musl ignores it, which
// keeps this evidence executable with the declared C/POSIX oracle.
core::arch::global_asm!(
    r#"
    .section .note.crabc.owned-crt,"a",@note
    .balign 4
    .long 6
    .long 4
    .long 0x43525401
    .asciz "CRABC"
    .balign 4
    .long 1
    .balign 4
"#,
);

core::arch::global_asm!(
    r#"
    .intel_syntax noprefix
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    // Preserve only the original stack and establish the SysV call frame.
    // Do not read the GOT, TLS, or loader `%rdx` before the direct handoff.
    mov r15, rsp
    xor ebp, ebp
    and rsp, -16
    mov rdi, r15
    call {startup}
    ud2
    .size _start, .-_start

    .att_syntax prefix
    .section .note.GNU-stack,"",@progbits
"#,
    startup = sym __crabc_x86_64_dynamic_start,
);
