#![cfg_attr(not(test), no_std)]
#![feature(linkage)]
#![feature(f128)]
#![feature(thread_local)]

//! Linux/AArch64 C runtime and compatibility ABI.

#[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_endian = "little")))]
compile_error!("crabc-libc supports Linux/AArch64 little-endian only");

mod c_abi;

// A small set of lexical compatibility fragments names these C ABI exports
// through `crate::`. Keep that internal path stable while their implementation
// remains owned by `c_abi`; this is not a public Rust facade.
pub(crate) use c_abi::{
    __errno_location, free, getpid, malloc, memcpy, memset, mkdir, regmatch_t, regoff_t,
    regex_t, strlen, syscall, FILE,
};
pub(crate) use core::ffi::c_void;
