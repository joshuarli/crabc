#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    feature(linkage)
)]
#![cfg_attr(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    feature(f128)
)]
#![feature(thread_local)]

//! Linux C runtime and compatibility ABI.

// Linux/AArch64 remains the complete public C runtime. The x86 branch below
// selects only separately evidenced static C ABI leaves; it is not a dynamic
// libc, CRT, sysroot, or public-platform target.
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
// records, allocator, and runtime state. The x86 archive has only its proven
// raw-syscall-to-initial-TLS-errno leaves and selected fixed memory, fenv,
// continuation bootstrap primitives, and bounded C signal slices.
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
