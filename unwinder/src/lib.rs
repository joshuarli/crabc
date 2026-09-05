//! Build root for the separately linked, allocation-free native x86 unwinder.
//! Rust std owns personality and panic handling; this crate enables neither.
#![no_std]
#[cfg(not(all(target_arch = "x86_64", target_os = "linux", target_env = "musl", target_endian = "little")))]
compile_error!("the owned unwinder is qualified only for native Linux/x86-64 musl ABI");
extern crate unwinding;
