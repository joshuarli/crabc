#![no_std]

// This source-only probe selects only the pinned-musl-derived x86 C fenv
// leaf. It deliberately does not select the AArch64-only crabc-libc crate
// root or claim that a complete x86 C runtime exists.
#[path = "../../libc/src/c_abi/x86_64/fenv.rs"]
mod fenv;
