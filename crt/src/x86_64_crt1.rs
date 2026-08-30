#![no_std]

//! Conventional Linux/x86-64 static `ET_EXEC` application entry.
//!
//! `crt1.o` receives the untouched kernel stack, establishes the SysV entry
//! frame, and transfers it to the shared static startup path. Unlike
//! `x86_64_rcrt1.rs`, an ordinary static executable has no self-relocation
//! phase: its final link has already resolved every startup boundary. The
//! shared path still delegates initial TLS materialization to libc before any
//! executable lifecycle callback.

mod x86_64_array_boundaries;
mod x86_64_startup;

pub use x86_64_startup::__crabc_x86_64_static_pie_start;

core::arch::global_asm!(
    r#"
    .intel_syntax noprefix
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    // Preserve the kernel-owned initial stack outside Rust allocation
    // provenance, establish the required SysV call alignment, and enter the
    // ordinary static startup path. Do not read the GOT or TLS before libc
    // has validated and installed the executable's initial TLS image.
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
    startup = sym __crabc_x86_64_static_pie_start,
);
