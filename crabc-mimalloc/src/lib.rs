//! Linux/AArch64 allocator-engine port of the pinned mimalloc upstream.
//!
//! The crate contains source-mapped allocator foundations and one private,
//! explicit single-thread small-allocation lifecycle over a caller-managed
//! external arena and page map. It deliberately exposes no public allocator
//! API or process/TLS lifecycle yet; medium, large, aligned, realloc, remote
//! free, teardown, and integration slices remain incomplete.
//! The public C allocator ABI, including `errno`, remains owned by
//! `crabc-libc`; this crate must not depend on it.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// This is the sole production platform. `cfg(miri)` selects a private test
// instrument only: it never makes a non-Linux/AArch64 target supported by the
// allocator engine or production build.
#[cfg(all(
    not(miri),
    not(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_endian = "little"
    ))
))]
compile_error!("crabc-mimalloc supports Linux/AArch64 little-endian only");

mod bits;
mod atomic;
mod arena;
mod bitmap;
mod bootstrap;
mod config;
mod free_list;
mod invariants;
mod lock;
mod once;
#[cfg(miri)]
#[path = "os_host_model.rs"]
mod os;
#[cfg(not(miri))]
mod os;
mod page;
mod page_map;
mod provenance;
mod random;
mod size_class;
mod single_thread;
mod support;
mod types;
