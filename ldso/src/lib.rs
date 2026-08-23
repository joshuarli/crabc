#![no_std]
#![no_main]
#![feature(linkage)]

//! Linux/AArch64 dynamic linker.

#[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_endian = "little")))]
compile_error!("crabc-ldso supports Linux/AArch64 little-endian only");

mod aarch64;
mod loader;
