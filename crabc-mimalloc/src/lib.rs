//! Linux/AArch64 allocator-engine port of the pinned mimalloc upstream.
//!
//! Linux/x86-64 compilation exists only for private, native C/Rust allocator
//! differential evidence. It neither selects nor exposes a public x86 crabc,
//! libc, loader, facade, or allocator backend.
//!
//! The crate contains source-mapped allocator foundations and one private,
//! explicit single-thread ordinary-allocation lifecycle over a caller-managed
//! external arena and page map. That lifecycle covers small, medium, large,
//! and singleton pages, checked counted allocation, ordinary reallocation,
//! arena-bounded aligned operations, and the separately owned OS-aligned
//! singleton path below the metadata-alignment limit. The crate deliberately
//! exposes no production allocator API; a default-off test-adapter feature
//! owns the only public operation context. Private static ticket-zero and
//! regular-key dynamic Theap attachments exist. One bounded source-order
//! process-main coordinator establishes the static Heap, detached metadata
//! readiness, global PageMap, and ticket-zero roots; it does not choose
//! options, reserve the process-shared arena, initialize pthread/TLS keys, or
//! own process shutdown. A paired sidecar can retain one caller-selected
//! source-managed arena mapping. One crate-private ticket-zero static owner or
//! one sequential later-thread owner may bind that exact pair to the arena's
//! embedded `pages_main` bitmap for one complete page-engine and
//! scoped-producer lifetime; concurrent/general later-thread page routing,
//! owner exit, and runtime allocation routing remain incomplete.
//! Remote-free and one-page abandonment protocols are bounded substrates;
//! allocation routing and terminal abandoned-page release remain incomplete.
//! The public C allocator ABI, including `errno`, remains owned by
//! `crabc-libc`; this crate must not depend on it.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(thread_local)]

#[cfg(feature = "test-adapter")]
extern crate alloc as rust_alloc;

// These are the explicit allocator-engine target profiles. The AArch64
// profile is the production-integration target; the x86-64 profile is native
// parity evidence only. `cfg(miri)` selects a private test instrument: it
// never makes another target supported by the allocator engine or a public
// production build.
#[cfg(all(
    not(miri),
    not(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_endian = "little"
    ))
))]
compile_error!("crabc-mimalloc supports Linux/AArch64 production and private Linux/x86-64 allocator evidence only");

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
mod dynamic_theap;
mod free_list;
mod invariants;
mod lock;
mod main_theap;
mod main_heap_thread;
mod main_heap_page;
mod main_static_page;
mod meta;
mod once;
mod os_page;
mod owned_tls_key_registry;
#[cfg(miri)]
#[path = "os_host_model.rs"]
mod os;
#[cfg(not(miri))]
mod os;
mod page;
mod page_map;
mod process_arena;
mod process_init;
mod process_page_map;
mod provenance;
mod random;
mod remote_free;
mod runtime_lifecycle;
mod size_class;
mod single_thread;
mod subproc;
mod support;
#[cfg(feature = "test-adapter")]
mod test_context;
mod thread_local;
mod tld;
mod types;

#[cfg(feature = "test-adapter")]
pub use test_context::{
    TestAllocatorContext, TestContextAllocationError, TestContextFreeError,
    TestContextInitError, TestContextPointerError, TestContextShutdownError,
};

// This is deliberately a Rust-only, documentation-hidden friend boundary for
// `crabc-libc`. It owns no C ABI, allocator routing, or backend selection.
// Keeping the narrow lifecycle control surface here lets the engine retain its
// source-shaped owners without depending on libc or public pthread APIs.
#[doc(hidden)]
pub mod __crabc_runtime {
    pub use crate::runtime_lifecycle::{
        ThreadAttachResult, ThreadFinishResult, TicketZeroLaterThreadPageResult,
        TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
        TicketZeroRemoteFreeProducer, TicketZeroRemoteFreeProducerPair,
        after_fork_child, after_fork_parent,
        attach_current_thread, before_fork,
        finish_current_thread_after_user_destructors, initialize_process,
        process_is_active, ticket_zero_allocate, ticket_zero_free,
        ticket_zero_later_thread_page_roundtrip,
        ticket_zero_later_thread_persistent_local_workload,
        ticket_zero_later_thread_remote_free_roundtrip, ticket_zero_reallocate,
    };
}
