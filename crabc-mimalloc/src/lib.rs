//! Linux/AArch64 allocator-engine port of the pinned mimalloc upstream.
//!
//! The crate contains source-mapped allocator foundations and one private,
//! explicit single-thread ordinary-allocation lifecycle over a caller-managed
//! external arena and page map. That lifecycle covers small, medium, large,
//! and singleton pages, checked counted allocation, ordinary reallocation,
//! arena-bounded aligned operations, and the separately owned OS-aligned
//! singleton path below the metadata-alignment limit. The crate deliberately
//! exposes no production allocator API or process/TLS lifecycle yet; a
//! default-off test-adapter feature owns the only public operation context.
//! Remote-free and one-page abandonment protocols are present as bounded
//! substrates; allocation routing, production thread/TLS teardown, terminal
//! abandoned-page release, and integration remain incomplete.
//! The public C allocator ABI, including `errno`, remains owned by
//! `crabc-libc`; this crate must not depend on it.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(thread_local)]

#[cfg(feature = "test-adapter")]
extern crate alloc as rust_alloc;

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
mod aligned;
mod abandoned;
mod alloc;
mod atomic;
mod arena;
mod bitmap;
mod bootstrap;
mod config;
mod compiler_tls;
mod free_list;
mod invariants;
mod lock;
mod once;
mod os_page;
#[cfg(miri)]
#[path = "os_host_model.rs"]
mod os;
#[cfg(not(miri))]
mod os;
mod page;
mod page_map;
mod provenance;
mod random;
mod remote_free;
mod size_class;
mod single_thread;
mod support;
#[cfg(feature = "test-adapter")]
mod test_context;
mod thread_local;
mod types;

#[cfg(feature = "test-adapter")]
pub use test_context::{
    TestAllocatorContext, TestContextAllocationError, TestContextFreeError,
    TestContextInitError, TestContextPointerError, TestContextShutdownError,
};
