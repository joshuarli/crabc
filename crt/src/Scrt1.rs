#![no_std]
#![feature(naked_functions)]

//! Position-independent dynamic-PIE application entry object.

mod normal_entry;
mod array_boundaries;
mod startup;

pub use startup::__crabc_start;

// `ldso` recognizes this bounded private ELF note before it transfers
// control to `_start`. It is deliberately a note rather than an undefined
// lifecycle symbol: the marker is not part of libc's exported ABI and an
// owned executable remains runnable under the pinned musl oracle loader.
//
// Namesz includes the terminating NUL. Type `0x4352_5401` and descriptor
// revision one form the exact loader/CRT contract audited by `crt/build.py`.
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
