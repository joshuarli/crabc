//! Linux allocator-engine port of the pinned mimalloc upstream.
//!
//! AArch64 retains its selected integration. Native x86-64 has an explicit
//! private backend with source-owned process, thread, Heap and Theap lifetimes.
//! Compiling this crate does not select that backend or enable public x86
//! support; libc owns compile-time backend selection.
//!
//! The native engine retains independent thread owners, routes clients through
//! the process PageMap, and uses page-local atomic remote publication. Source
//! collection coordinates retirement, abandonment, reclamation and owner exit.
//! The source APIs expose allocation, options and Heap operations without
//! depending on libc. The hidden runtime interface carries startup facts and
//! thread/fork/process lifecycle transitions from libc. Test-only operation
//! contexts remain separate from that runtime route.
//!
//! The public C allocator ABI, including `errno` and symbol interposition,
//! remains owned by `crabc-libc`; this crate must not depend on it.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(thread_local)]

#[cfg(feature = "test-adapter")]
extern crate alloc as rust_alloc;
#[cfg(test)]
extern crate std;

// These are the explicit allocator-engine target profiles. The AArch64
// profile retains its selected integration; the x86-64 profile also supports
// the explicitly selected private runtime backend. `cfg(miri)` selects the
// private `crabc-core` kernel model as a test instrument: it never makes
// another target supported
// by the allocator engine or a public production build.
#[cfg(all(
    not(miri),
    not(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_endian = "little"
    ))
))]
compile_error!("crabc-mimalloc supports Linux/AArch64 and private Linux/x86-64 allocator integration only");

mod bits;
mod aligned;
mod abandoned;
mod alloc;
mod atomic;
mod arena;
#[cfg(target_arch = "x86_64")]
mod arena_print;
mod bitmap;
mod bootstrap;
mod config;
mod compiler_tls;
mod dynamic_theap;
mod deferred_free;
mod diagnostic_output;
mod free_list;
mod invariants;
#[cfg(target_arch = "x86_64")]
mod local_fast_path;
#[cfg(all(test, target_arch = "x86_64"))]
mod native_local_trace;
#[cfg(all(test, target_arch = "x86_64", feature = "native-runtime-test-audit"))]
mod mapped_large_owner_exit;
#[cfg(all(test, feature = "native-runtime-test-audit", target_arch = "x86_64"))]
mod arena_singleton_regular_exit;
#[cfg(all(test, target_arch = "x86_64", feature = "native-runtime-test-audit"))]
mod arena_singleton_split_exit;
mod lock;
mod main_theap;
mod main_heap_thread;
mod main_heap_page;
mod main_static_page;
mod meta;
mod once;
mod os_page;
mod page_backing;
mod owned_tls_key_registry;
// Under `cfg(miri)` this same module runs over `crabc-core`'s Miri kernel
// model; only the raw syscall seams below it are replaced.
mod os;
mod page;
#[cfg(target_arch = "x86_64")]
mod page_validity;
mod page_map;
mod process_arena;
mod process_init;
mod process_page_map;
mod provenance;
mod random;
mod remote_free;
mod runtime_lifecycle;
mod size_class;
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub mod source_api;
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub mod source_options_api;
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub mod source_heap_api;
mod single_thread;
mod statistics;
mod subproc;
mod support;
#[cfg(feature = "native-runtime-test-audit")]
mod theap_trace_audit;
// Some native lifecycle fixtures intentionally terminalize process-global
// source state.  Their test-only child-exec boundary lives outside the
// production allocator modules so a full unit binary can retain every fixture
// without inheriting an earlier fixture's irreversible owner.
#[cfg(test)]
mod test_process;
#[cfg(feature = "test-adapter")]
mod test_context;
mod thread_local;
mod tld;
mod types;

#[cfg(feature = "test-adapter")]
pub use test_context::{
    TestAllocatorContext, TestContextAllocationError, TestContextFreeError,
    TestContextInitError, TestContextInitFailure, TestContextPointerError,
    TestContextShutdownError,
};

// This is deliberately a Rust-only, documentation-hidden friend boundary for
// `crabc-libc`. It owns no C ABI, allocator routing, or backend selection.
// Keeping the narrow lifecycle control surface here lets the engine retain its
// source-shaped owners without depending on libc or public pthread APIs.
#[doc(hidden)]
pub mod __crabc_runtime {
    #[cfg(target_arch = "x86_64")]
    pub use crate::process_init::SourceErrnoStore;
    pub use crate::runtime_lifecycle::{
        NativeAllocatorThreadDescriptor, NativeAllocatorPinnedThreadRegistry,
        NativeAllocatorDescriptorRetirement, native_allocator_descriptor_retirement,
        NativeAllocatorCallbackBoundaryError, NativeAllocatorQuiescenceError,
        NativeAllocatorForkQuiescence, NativeAllocatorForkChildRepair,
        NativeAllocatorForkChildContinuation, NativeAllocatorChildRetainedThreadRegistry,
        NativeAllocatorRawForkCopyGuard, NativeAllocatorRawForkCopyError,
        NativeAllocatorTerminalQuiescence, current_native_allocator_thread_descriptor,
        native_allocator_initial_thread_descriptor, register_current_native_allocator_worker_descriptor,
        with_native_allocator_callback_boundary, with_native_allocator_diagnostic_callback,
        begin_native_allocator_terminal_quiescence, begin_native_allocator_fork_quiescence,
        begin_native_allocator_source_fork_quiescence,
        begin_native_allocator_raw_fork_copy,
    };

    #[cfg(target_arch = "x86_64")]
    pub use crate::runtime_lifecycle::{
        NativeAllocatorTlsSpan, current_native_allocator_timer_tls_spans,
        prepare_native_process_destroy, capture_native_process_destroy_request,
        NativeProcessDestroyRequest, NativePreparedProcessDestroy, NativeProcessDestroyError,
        native_process_done_action, NativeProcessDoneInvocation, NativeProcessDoneAction,
    };

    #[cfg(target_arch = "x86_64")]
    pub use crate::diagnostic_output::RuntimeStderrOutput;
    #[cfg(target_arch = "x86_64")]
    pub use crate::source_api;
    #[cfg(target_arch = "x86_64")]
    pub use crate::source_options_api;
    #[cfg(target_arch = "x86_64")]
    pub use crate::source_heap_api;
    #[cfg(target_arch = "x86_64")]
    pub use crate::runtime_lifecycle::{
        NativeProcessStartupFacts, publish_native_process_startup_facts,
    };
    #[cfg(feature = "native-runtime-test-audit")]
    pub use crate::runtime_lifecycle::{
        NativeRuntimeCurrentThreadAttachmentAudit, NativeRuntimeFirstArenaPolicyAudit,
        NativeRuntimeForkAdmissionAudit, NativeRuntimeLifecycleAudit,
        NativeRuntimeLiveClientPageAudit, NativeRuntimeLiveClientPageMapSpanAudit,
        NativeRuntimeArenaSpanTestAudit, NativeRuntimeArenaSpanStateTestAudit,
        NativeRuntimeProcessDoneRetainedLocalPageAudit,
        NativeRuntimeProcessDoneTerminalPurgeAudit,
        NativeRuntimeOwnerExitCollectionRendezvous,
        native_runtime_current_thread_attachment_test_audit,
        native_runtime_first_arena_policy_test_audit, native_runtime_fork_admission_test_audit,
        native_runtime_current_local_page_test_audit,
        native_runtime_current_local_page_same_test_audit,
        native_runtime_lifecycle_test_audit,
        native_runtime_main_heap_os_abandoned_empty_test_audit,
        native_runtime_metadata_page_map_test_audit,
        native_runtime_live_client_uses_startup_regular_arena_test_audit,
        native_runtime_live_client_page_map_span_test_audit,
        native_runtime_live_client_page_test_audit, native_runtime_live_client_memory_kind_test_audit,
        native_runtime_live_client_arena_span_test_audit, native_runtime_arena_span_state_test_audit,
        native_runtime_live_client_slice_pcommitted_test_audit,
        native_runtime_live_client_page_geometry_test_audit, NativeRuntimeLiveClientPageGeometryAudit,
        native_runtime_process_options_test_audit, NativeRuntimeProcessOptionsAudit,
        native_runtime_process_done_retained_live_page_test_audit,
        native_runtime_process_done_retained_local_page_test_audit,
        native_runtime_process_done_retained_local_preflight_test_audit,
        native_runtime_process_done_retained_page_retired_test_audit,
        native_runtime_process_done_retained_worker_matches_current_thread_test_audit,
        native_runtime_process_done_terminal_purge_test_audit,
        native_runtime_test_arm_owner_exit_collection_rendezvous,
        native_runtime_current_owner_theap_trace_test_audit,
    };
    #[cfg(feature = "native-runtime-test-audit")]
    pub use crate::subproc::lifecycle::child_destroy_finish_test_audit;
    #[cfg(feature = "native-runtime-test-audit")]
    pub use crate::theap_trace_audit::{
        NativeTheapTraceBlock, NativeTheapTraceDirect, NativeTheapTraceFact, NativeTheapTracePage,
    };

    #[cfg(feature = "native-runtime-test-fault")]
    pub use crate::runtime_lifecycle::{
        NativeRuntimeTestUnmapFailure, NativeRuntimeTestUnmapRange,
        native_runtime_test_fail_next_unmap,
    };

    #[cfg(all(feature = "native-runtime-test-audit", feature = "native-runtime-test-fault"))]
    pub use crate::runtime_lifecycle::{
        NativeRuntimeTerminalVmCurrentAudit, native_runtime_terminal_vm_current_test_audit,
    };

    #[cfg(feature = "native-runtime-test-audit")]
    pub use crate::process_init::{NativeSourceErrorAudit, native_runtime_take_source_error_test_audit};

    pub use crate::runtime_lifecycle::{
        SelectedProcessDoneResult, ThreadAttachResult, ThreadFinalProcessExitOwnerResult,
        ThreadFinishResult,
        NativePageAllocationResult, NativePageFreeResult,
        after_fork_child, after_fork_parent,
        attach_current_thread, before_fork,
        finish_current_thread_after_user_destructors,
        finish_current_thread_native_after_user_destructors, initialize_process,
        finish_selected_default_release_process_after_user_atexit,
        process_is_active, prepare_native_initial_thread_owner,
        prepare_native_later_thread_arena,
        retain_current_thread_native_owner_after_process_done_nonfinal,
        reinitialize_current_thread_native_owner_for_final_process_exit,
        native_allocate, native_allocate_aligned, native_allocate_aligned_at, native_free,
        native_reallocate, native_reallocate_aligned, native_reallocate_aligned_at,
        native_reallocate_source, native_collect,
        native_reallocate_zeroed, native_reallocate_aligned_zeroed,
        native_usable_size, native_block_size, native_pointer_is_mapped, native_os_page_size,
        NativeDeferredFreeCallback, register_native_deferred_free_callback,
    };

    // The retired ticket-zero scheduler's friend seam. Production selects the
    // persistent pointer-first `native_*` owners above; only historical
    // fixtures and the test-only ticket-zero C soak adapter drive these.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    pub use crate::runtime_lifecycle::{
        TicketZeroLaterThreadPageResult,
        TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
        TicketZeroRemoteFreeProducer, TicketZeroRemoteFreeProducerPair,
        TicketZeroSingleRemoteFreePublisher,
        ticket_zero_allocate, ticket_zero_free,
        ticket_zero_allocate_aligned, ticket_zero_usable_size,
        ticket_zero_later_thread_page_roundtrip,
        ticket_zero_later_thread_persistent_local_workload,
        ticket_zero_later_thread_remote_free_roundtrip, ticket_zero_reallocate,
    };

    #[cfg(test)]
    pub use crate::runtime_lifecycle::{
        TicketZeroOwnerExitFreeConsumer, TicketZeroOwnerExitFreeOutcome,
        TicketZeroOwnerExitFreeRoute, TicketZeroOwnerExitMappedMediumRemoteFreeProducer,
        TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair,
        TicketZeroOwnerExitMappedMediumRemoteFreePublisher,
        TicketZeroOwnerExitReclaimConsumer, TicketZeroOwnerExitReclaimOutcome,
        TicketZeroOwnerExitReclaimRoute, TicketZeroOwnerExitRemoteFreeProducer,
        TicketZeroOwnerExitRemoteFreeProducerPair, TicketZeroOwnerExitRemoteFreePublisher,
        ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish,
        ticket_zero_later_thread_active_session_rejects_normal_finish,
        ticket_zero_later_thread_all_free_session_through_normal_finish,
        ticket_zero_later_thread_mapped_regular_owner_exit_through_normal_finish,
        ticket_zero_later_thread_mapped_regular_owner_exit_reclaim_through_normal_finish,
        ticket_zero_later_thread_retired_then_live_session_owner_exit_through_normal_finish,
        ticket_zero_later_thread_single_source_published_session_through_normal_finish,
        ticket_zero_later_thread_source_published_session_through_normal_finish,
        ticket_zero_later_thread_session_owner_exit_through_normal_finish,
        ticket_zero_later_thread_session_owner_exit_with_initial_mapped_medium_post_exit_publisher_through_normal_finish,
        ticket_zero_later_thread_session_owner_exit_with_post_exit_mapped_medium_publisher_through_normal_finish,
        ticket_zero_later_thread_session_owner_exit_with_post_exit_publisher_through_normal_finish,
    };
}
