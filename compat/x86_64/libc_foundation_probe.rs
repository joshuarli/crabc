#![no_std]
#![feature(thread_local)]

// This source-only probe composes only the x86 raw-syscall, initial-TLS errno,
// fixed-musl fenv, and fixed-musl memory leaves. It deliberately does not
// build the separately selected crabc-libc archive or claim a complete x86 C
// runtime.
#[path = "../../libc/src/c_abi/x86_64/foundation.rs"]
mod foundation;
