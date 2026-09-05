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

// Linux/AArch64 remains the complete public C runtime. The x86 branch below
// selects the established C ABI leaf owners. The explicit owned-dynamic feature
// replaces only startup/TLS ownership for the staged installed shared product;
// neither linkage mode promotes x86 to public-platform support.
#[cfg(not(any(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    all(target_os = "linux", target_arch = "x86_64", target_endian = "little"),
)))]
compile_error!(
    "crabc-libc supports Linux/AArch64 little-endian and selected staged static Linux/x86-64 C ABI slices"
);

#[cfg(all(target_os = "linux", target_arch = "aarch64", target_endian = "little"))]
mod c_abi;

// Keep this target root deliberately separate from `c_abi`: that module owns
// the active AArch64 runtime composition and its target-specific assembly,
// records, allocator, and runtime state. The x86 root selects its separately
// evidenced C ABI leaves. The historical root filename is retained for
// existing source contracts; cfg-disjoint owned_dynamic_runtime/dynamic_tls
// select shared startup and loader-owned TLS without duplicating leaf state.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_endian = "little"))]
#[path = "c_abi/x86_64/static_c_abi.rs"]
mod x86_64_static_c_abi;

// A small set of lexical compatibility fragments names these C ABI exports
// through `crate::`. Keep that internal path stable while their implementation
// remains owned by `c_abi`; this is not a public Rust facade.
#[cfg(all(target_os = "linux", target_arch = "aarch64", target_endian = "little"))]
pub(crate) use c_abi::{
    __errno_location, free, getpid, malloc, memcpy, memset, mkdir, regmatch_t, regoff_t,
    regex_t, strlen, syscall, FILE,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64", target_endian = "little"))]
pub(crate) use core::ffi::c_void;
