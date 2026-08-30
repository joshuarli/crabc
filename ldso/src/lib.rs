#![no_std]
#![no_main]
#![cfg_attr(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    feature(linkage)
)]

//! Linux/AArch64 dynamic linker.

// The x86 root is a deliberately feature-gated, private admission target for
// the fixed native evidence graph. It does not broaden the public loader
// support boundary or select a portable loader architecture.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little",
    feature = "x86_64-initial-interpreter"
))]
#[path = "x86_64_initial_graph.rs"]
mod x86_64_initial_graph;

#[cfg(all(target_os = "linux", target_arch = "aarch64", target_endian = "little"))]
mod aarch64;
#[cfg(all(target_os = "linux", target_arch = "aarch64", target_endian = "little"))]
mod loader;

#[cfg(not(any(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    all(
        target_os = "linux",
        target_arch = "x86_64",
        target_endian = "little",
        feature = "x86_64-initial-interpreter"
    )
)))]
compile_error!(
    "crabc-ldso supports Linux/AArch64 little-endian; the private x86 initial-interpreter root requires --features x86_64-initial-interpreter"
);
