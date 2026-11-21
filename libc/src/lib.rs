#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    any(
        all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
        all(target_os = "linux", target_arch = "x86_64", target_endian = "little")
    ),
    feature(linkage)
)]
#![cfg_attr(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    feature(f128)
)]
#![feature(thread_local)]

//! Linux C runtime and compatibility ABI.

#[cfg(not(any(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    all(target_os = "linux", target_arch = "x86_64", target_endian = "little"),
)))]
compile_error!("crabc-libc supports Linux/x86-64 and Linux/AArch64 little-endian");

// The historical root filename is retained for existing source contracts;
// cfg-disjoint owned_dynamic_runtime/dynamic_tls select shared startup and
// loader-owned TLS without duplicating leaf state.
#[path = "c_abi/x86_64/static_c_abi.rs"]
mod x86_64_static_c_abi;
