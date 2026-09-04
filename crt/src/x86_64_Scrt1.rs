#![no_std]

//! Position-independent Linux/x86-64 dynamic-PIE application entry.
//!
//! The entry is deliberately minimal and leaves the original initial stack
//! untouched until normal Rust startup parses it. An ELF interpreter has
//! already relocated this image. Default mode preserves pinned musl 1.2.6's
//! null-finalizer convention. Explicit owned lifecycle mode captures `%rdx`
//! and authenticates it against the private owned handoff before libc entry.

mod x86_64_array_boundaries;
mod x86_64_dynamic_startup;

pub use x86_64_dynamic_startup::__crabc_x86_64_dynamic_start;

// This private marker is the crabc-loader's owned-entry admission check, not
// an ELF export or the lifecycle handoff record. Pinned musl ignores it, which
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

#[cfg(not(crabc_general_dynamic_lifecycle))]
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

// Only the owned dynamic lifecycle mode consumes the loader's conventional
// rtld_fini register. Preserve it as the second Rust argument before any
// call, then authenticate it against the existing owned handoff record.
#[cfg(crabc_general_dynamic_lifecycle)]
core::arch::global_asm!(
    r#"
    .intel_syntax noprefix
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    mov r15, rsp
    mov rsi, rdx
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
