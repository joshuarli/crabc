#![no_std]

// This source-only probe selects the exact x86 control-transfer assembly
// without selecting `crabc-libc`, whose target root remains AArch64-only.
#[path = "../../libc/src/c_abi/x86_64/setjmp.rs"]
mod setjmp;
