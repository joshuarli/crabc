#![no_std]
#![no_main]
#![cfg_attr(
    all(target_os = "linux", target_arch = "aarch64", target_endian = "little"),
    feature(linkage)
)]

//! Linux/AArch64 dynamic linker.

// The x86 roots are deliberately feature-gated private evidence targets. The
// original root retains the fixed graph; the separate general-initial roots
// admit either a non-TLS graph or one initial TLS generation retained by the
// loader. Neither broadens the public loader support boundary or selects
// portability.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little",
    any(
        feature = "x86_64-initial-interpreter",
        feature = "x86_64-general-initial-interpreter",
        feature = "x86_64-general-initial-tls-interpreter",
        feature = "x86_64-general-initial-tls-runtime-v1-interpreter",
        feature = "x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter"
    )
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
        any(
            feature = "x86_64-initial-interpreter",
            feature = "x86_64-general-initial-interpreter",
            feature = "x86_64-general-initial-tls-interpreter",
            feature = "x86_64-general-initial-tls-runtime-v1-interpreter",
            feature = "x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter"
        )
    )
)))]
compile_error!(
    "crabc-ldso supports Linux/AArch64 little-endian; a private x86 root requires --features x86_64-initial-interpreter, x86_64-general-initial-interpreter, x86_64-general-initial-tls-interpreter, x86_64-general-initial-tls-runtime-v1-interpreter, or x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter"
);
