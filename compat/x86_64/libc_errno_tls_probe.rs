#![no_std]
#![feature(thread_local)]

// This source-only probe selects the bounded x86 errno implementation without
// selecting `crabc-libc` or its AArch64-only crate root.
#[path = "../../libc/src/c_abi/x86_64/errno.rs"]
mod errno;
