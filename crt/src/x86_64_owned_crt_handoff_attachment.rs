#![no_std]

//! Main-resident reader of the owned interpreter's x86 CRT handoff slot.
//!
//! The combined crt1.o (`x86_64_crt1.rs`) is also linked into static
//! executables, which must not retain an unresolved loader symbol. It
//! therefore never imports `__crabc_x86_64_owned_crt_handoff` itself; the
//! installed dynamic product partial-links this object into
//! crabc-dynamic-attach.o, which only dynamic executables link, and whose
//! strong `__crabc_x86_64_attached_owned_crt_handoff` overrides crt1.o's
//! null-returning weak default.
//!
//! The slot is read exactly as Scrt1.o's `x86_64_dynamic_startup.rs` does: a
//! non-relaxable `R_X86_64_GOTPCREL` keeps one GOT slot for the interpreter's
//! `GLOB_DAT`; the crt1.o caller tests the value for null before any use. The
//! reader is hidden, so no executable exports it.

core::arch::global_asm!(
    ".att_syntax prefix",
    ".weak __crabc_x86_64_owned_crt_handoff",
    ".type __crabc_x86_64_owned_crt_handoff,@object",
    ".text",
    ".global __crabc_x86_64_attached_owned_crt_handoff",
    ".hidden __crabc_x86_64_attached_owned_crt_handoff",
    ".type __crabc_x86_64_attached_owned_crt_handoff,@function",
    "__crabc_x86_64_attached_owned_crt_handoff:",
    "lea __crabc_x86_64_owned_crt_handoff@GOTPCREL(%rip), %rax",
    "mov (%rax), %rax",
    "ret",
    ".size __crabc_x86_64_attached_owned_crt_handoff, .-__crabc_x86_64_attached_owned_crt_handoff",
    ".intel_syntax noprefix",
);
