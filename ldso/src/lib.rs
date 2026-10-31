#![no_std]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(feature = "x86_64-owned-dynamic-runtime", feature(linkage))]
#![cfg_attr(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    feature(linkage)
)]

//! Linux dynamic linker for AArch64 and x86-64.

// The x86 roots are feature-gated private targets. The original root retains
// the fixed graph; the separate general-initial roots admit either a non-TLS
// graph or one initial TLS generation retained by the loader.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little",
    feature = "x86_64-owned-dynamic-runtime"
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
        feature = "x86_64-owned-dynamic-runtime"
    )
)))]
compile_error!(
    "crabc-ldso supports Linux/AArch64 little-endian; the x86-64 root requires --features x86_64-owned-dynamic-runtime"
);
