#![no_std]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(feature = "x86_64-owned-dynamic-runtime", feature(linkage))]

//! Linux dynamic linker for AArch64 and x86-64.

// The x86 roots are feature-gated private targets. The original root retains
// the fixed graph; the separate general-initial roots admit either a non-TLS
// graph or one initial TLS generation retained by the loader.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    feature = "x86_64-owned-dynamic-runtime"
))]
#[path = "x86_64_initial_graph.rs"]
mod x86_64_initial_graph;

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        feature = "x86_64-owned-dynamic-runtime"
    )
)))]
compile_error!(
    "crabc-ldso requires Linux little-endian x86-64 or AArch64 and --features x86_64-owned-dynamic-runtime"
);
