// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/subproc.c:158-194 (`mi_subproc_new`),
// src/subproc.c:202-263 (`mi_subproc_unsafe_destroy`, `mi_subproc_destroy`),
// src/subproc.c:283-299 (`mi_subproc_add_current_thread`), src/init.c:306-360
// and 452-480 (`_mi_thread_init_with_heap`, `_mi_thread_done`),
// and src/heap.c:130-235 (`_mi_heap_new_for_subproc`, `mi_heap_free_theaps`,
// `mi_heap_free`, `_mi_heap_force_destroy`).

//! Source-ordered creation and destruction of one child subprocess.
//!
//! [`new_child`] is `mi_subproc_new` for a root child of the process main
//! subprocess, called on a later-main thread through that thread's
//! attachment and owner-local page engine: the parent metadata allocator
//! issues the child image and its metadata Theap, the child joins the source
//! subprocess list, the parent user Heap allocates the child main Heap, and
//! the metadata Theap attaches to that Heap on the parent's detached TLD.
//! Each failure releases what source releases, in source order; a failure
//! that source cannot observe (a lock error after a list mutation) retains
//! the exact remaining owner instead of freeing it.
//!
//! [`destroy_child`] is `mi_subproc_destroy` for such a child: registry
//! unlink, metadata-Theap detach and free (merging its statistics into the
//! Heap), child main-Heap unlink and free, the child-to-process-main
//! statistics merge, arena destruction, and finally the child image. It
//! resumes at the owner's current stage, so a retryable step can be called
//! again with the returned owner.
//!
//! [`add_current_thread`] is `mi_subproc_add_current_thread`: a fresh thread
//! gets an ordinary TLD and Theap from the child's metadata Theap and
//! publishes that Theap as its default Theap, while a thread whose default
//! Theap is already initialized is refused. [`ChildThreadMember::thread_done`]
//! is the matching `_mi_thread_done`. A member does not borrow its child:
//! each admitted thread keeps its own page-engine state and runs page
//! operations without a child or PageMap lock. Ordinary owned destruction
//! refuses while a member is registered; native destruction may instead
//! destroy a permanently quiescent child and retain its record for member exit.
//!
//! [`native_subproc_new`], [`native_subproc_add_current_thread`],
//! [`native_subproc_visit_heaps`], and [`native_subproc_destroy`] are the
//! production entry points over one process-lived [`NativeChildSubprocess`]
//! record per child. The child main Heap image is an ordinary native-runtime
//! allocation, so destruction may run on any runtime thread that may free,
//! as source `_mi_free_subproc_safe` does. Context operations serialize on
//! the record lock, in place of source `theap_meta_lock` and `heaps_lock`.
//!
//! An admitted thread's [`ChildThreadMember`] moves into that thread's
//! `CURRENT_CHILD_MEMBER` slot. The native runtime entry points in
//! `runtime_lifecycle` test the slot first and route the thread's
//! allocation, local free, and reallocation through its own child Theap
//! ([`native_child_thread_allocate`], [`native_child_thread_free_local`]),
//! as source reaches them through the thread's default Theap; a free of a
//! block owned by another thread takes the ordinary remote-free route. The
//! runtime thread-exit entry runs [`native_child_thread_done`].
//!
//! [`destroy_all_native_children_terminal`] is the child walk of
//! `_mi_subprocs_unsafe_destroy_all` at process destruction, which, as in
//! source, destroys a child even under threads that still belong to it.
//!
//! A finishing child thread hands its pages with live blocks to the child
//! main Heap ([`ChildThreadMember::thread_done`]); [`free_child_block_nonlocal`]
//! frees such blocks, or blocks of another thread's page, from any thread.
//!
//! Nested children obtain their context and detached Theap from the actual
//! parent's metadata route. Their parent-issued control storage retains that
//! parent independently until final TLS finish returns the exact allocation.
//! Live child metadata blocks at destruction are released with the child arenas,
//! as in source. The source `_mi_thread_locals_thread_done` call in
//! `mi_subproc_destroy` releases the destroying thread's dynamic thread-local
//! table, which no child lifecycle here allocates.

use crate::main_heap_page::{
    MainHeapThreadOwnerLocalPageEngine, MainHeapThreadOwnerLocalPageEngineAccessError,
};
use crate::main_heap_thread::{MainHeapThreadAttachment, MainHeapThreadAttachmentError};
use crate::meta::{
    ChildContextCreateFailure, ChildContextCreateStage, ChildContextOwner, ChildParentMetadata,
    ChildHeapRelease, ChildHeapStorage, ChildMainHeapBindFailure, ChildMainHeapContextOwner,
    ChildMainHeapReleaseError,
    ChildMainHeapReleaseFailure, ChildMainHeapStage, ChildMetadataPageEngineError,
    ChildMetadataTheapError, ChildThreadOwner, ChildThreadStartError, ChildThreadStartFailure,
    ChildThreadTeardownError, MetaError,
};
use crate::compiler_tls::{default_theap, set_default_theap, set_fast_slot};
use crate::process_init::ProcessMainBackingBinding;
use crate::subproc::registry::{SourceSubprocessRegistry, SourceSubprocessRegistryError};
use crate::types::heap_registry::SourceHeapRegistryError;
use crate::types::Theap;

/// Why pinned `mi_subproc_new` returned a null identifier. Every allocation
/// made by the attempt has been released in source order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildSubprocessNewError {
    /// The calling thread has no usable attachment to the process main Heap.
    Attachment(MainHeapThreadAttachmentError),
    /// `_mi_meta_zalloc(parent, sizeof(mi_subproc_t))` failed.
    ContextAllocation(MetaError),
    /// `_mi_meta_zalloc(parent, sizeof(mi_theap_t))` failed; the child image
    /// was freed first.
    MetadataTheapAllocation(MetaError),
    /// `mi_subproc_init` refused the image before any list mutation.
    Registry(SourceSubprocessRegistryError),
    /// `mi_heap_zalloc(parent->heap_main)` returned null; the metadata Theap
    /// was freed and the child unlinked and freed.
    HeapAllocation,
    /// The parent owner-local engine could not be entered for that
    /// allocation; handled like a null allocation.
    ParentAccess(MainHeapThreadOwnerLocalPageEngineAccessError),
}

/// A creation step failed after a transition that cannot be undone safely.
/// The value owns every remaining capability; drop never frees any of them.
#[must_use = "a retained child subprocess owner must stay retained"]
pub(crate) enum ChildSubprocessRetained<'main> {
    Context {
        owner: ChildContextOwner,
        stage: ChildContextCreateStage,
    },
    HeapBind(ChildMainHeapBindFailure<'main>),
    Child {
        owner: ChildMainHeapContextOwner<'main>,
        error: ChildMetadataTheapError,
    },
}

#[must_use = "a child subprocess creation failure may retain its owner"]
pub(crate) enum ChildSubprocessNewFailure<'main> {
    Released(ChildSubprocessNewError),
    Retained(ChildSubprocessRetained<'main>),
}

impl core::fmt::Debug for ChildSubprocessNewFailure<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Released(error) => formatter.debug_tuple("Released").field(error).finish(),
            Self::Retained(ChildSubprocessRetained::Context { stage, .. }) => {
                formatter.debug_struct("RetainedContext").field("stage", stage).finish()
            }
            Self::Retained(ChildSubprocessRetained::HeapBind(failure)) => {
                formatter.debug_tuple("RetainedHeapBind").field(&failure.error).finish()
            }
            Self::Retained(ChildSubprocessRetained::Child { error, .. }) => {
                formatter.debug_tuple("RetainedChild").field(error).finish()
            }
        }
    }
}

/// Pinned `mi_subproc_new` for a root child of the process main subprocess.
///
/// The returned owner is the child's identity and the sole authority for
/// [`destroy_child`]. It borrows the parent Heap owner's lifetime because the
/// child main Heap image is a parent user-Heap allocation.
///
/// # Safety
/// `registry` is the process subprocess registry in which the attachment's
/// subprocess is the initialized main member. The caller runs on the
/// attachment's thread, owns its page engine for the call, and no other child
/// initializer or registry teardown races this creation.
pub(crate) unsafe fn new_child<'main>(
    registry: &'static SourceSubprocessRegistry,
    attachment: &mut MainHeapThreadAttachment<'main>,
    heap_owner: &mut MainHeapThreadOwnerLocalPageEngine<'main>,
) -> Result<ChildMainHeapContextOwner<'main>, ChildSubprocessNewFailure<'main>> {
    let (parent, config) = match (attachment.subprocess(), attachment.memory_config()) {
        (Ok(parent), Ok(config)) => (parent, config),
        (Err(error), _) | (_, Err(error)) => {
            return Err(ChildSubprocessNewFailure::Released(ChildSubprocessNewError::Attachment(error)));
        }
    };
    let metadata = attachment.parent_metadata_allocator();
    // SAFETY: forwarded registry, thread, and exclusion obligations.
    unsafe {
        new_child_with(
            registry,
            ChildParentMetadata::Process { allocator: metadata, main: parent, config },
            parent,
            config,
            || {
            match heap_owner.allocate_child_heap_storage(attachment) {
                Ok(Some(storage)) => Ok(ChildHeapStorage::Parent(storage)),
                Ok(None) => Err(ChildSubprocessNewError::HeapAllocation),
                Err(error) => Err(ChildSubprocessNewError::ParentAccess(error)),
            }
        })
    }
}

/// The body of [`new_child`] for either child Heap storage route.
///
/// # Safety
/// `registry` holds `parent` as its initialized main member, `metadata` is
/// `parent`'s metadata allocator, `allocate_heap` performs the source
/// `mi_heap_zalloc(parent->heap_main)` on the calling thread, and no other
/// child initializer or registry teardown races this creation.
unsafe fn new_child_with<'heap>(
    registry: &'static SourceSubprocessRegistry,
    metadata: ChildParentMetadata,
    parent: &'static crate::subproc::MainSubprocess,
    config: crate::os::MemoryConfig,
    allocate_heap: impl FnOnce() -> Result<ChildHeapStorage<'heap>, ChildSubprocessNewError>,
) -> Result<ChildMainHeapContextOwner<'heap>, ChildSubprocessNewFailure<'heap>> {
    let released = |error| Err(ChildSubprocessNewFailure::Released(error));

    // subproc.c:161-172: child image, then metadata Theap (whose failure
    // frees the child image first; `allocate` performs that rollback).
    let mut context = match ChildContextOwner::allocate_with(metadata, parent, config) {
        Ok(context) => context,
        Err(ChildContextCreateFailure::Allocation { stage, error }) => {
            return released(match stage {
                ChildContextCreateStage::AllocateContext => {
                    ChildSubprocessNewError::ContextAllocation(error)
                }
                _ => ChildSubprocessNewError::MetadataTheapAllocation(error),
            });
        }
        Err(ChildContextCreateFailure::Retained { owner, stage, .. }) => {
            return Err(ChildSubprocessNewFailure::Retained(
                ChildSubprocessRetained::Context { owner, stage },
            ));
        }
    };

    // subproc.c:175 `mi_subproc_init`: parent, sequence, then list prepend.
    let memory = context.with_lease(|lease| lease.context_memory_id());
    let registered = metadata.with_identity(|parent_identity| {
        context.with_image(|child| {
            // SAFETY: the owner pins the exact parent-issued child image and
            // its Malloc provenance; the caller excludes racing registry
            // teardown and the parent belongs to this registry.
            unsafe { registry.initialize_child(child.as_ref().get_ref(), parent_identity, memory) }
        }).unwrap_or(Err(SourceSubprocessRegistryError::InvalidMembership))
    }).unwrap_or(Err(SourceSubprocessRegistryError::InvalidMembership));
    if let Err(error) = registered {
        // A refusal before list insertion leaves the image unpublished; a
        // lock failure after insertion makes `release_unpublished` refuse.
        return match context.release_unpublished() {
            Ok(()) => released(ChildSubprocessNewError::Registry(error)),
            Err(failure) => {
                Err(ChildSubprocessNewFailure::Retained(
                    ChildSubprocessRetained::Context { owner: failure.owner, stage: failure.stage },
                ))
            },
        };
    }

    // subproc.c:178 `_mi_heap_new_for_subproc(subproc, 0, true)`: the child
    // main Heap is zero-allocated from the parent's main Heap.
    let storage = match allocate_heap() {
        Ok(storage) => storage,
        Err(error) => {
            // subproc.c:179-182: free the unattached metadata Theap, then
            // `mi_subproc_destroy` unlinks and frees the child image.
            // SAFETY: no Heap allocation exists and no child operation can
            // run before this function returns the owner.
            return match unsafe { context.rollback_after_child_heap_allocation_failure(registry) } {
                Ok(()) => released(error),
                Err(failure) => {
                    Err(ChildSubprocessNewFailure::Retained(
                        ChildSubprocessRetained::Context { owner: failure.owner, stage: failure.stage },
                    ))
                },
            };
        }
    };
    let mut child = context.bind_heap_storage(storage).map_err(|failure| {
        ChildSubprocessNewFailure::Retained(ChildSubprocessRetained::HeapBind(failure))
    })?;

    // heap.c:_mi_heap_init plus subproc.c:190-191: Heap list membership and
    // the metadata Theap on the parent's detached TLD.
    // SAFETY: the child is registered and this function is its sole
    // initializer; `metadata` issued both parent capabilities.
    if let Err(error) = unsafe { child.initialize_heap_and_metadata_theap(config) } {
        return Err(ChildSubprocessNewFailure::Retained(
            ChildSubprocessRetained::Child { owner: child, error },
        ));
    }
    Ok(child)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildSubprocessDestroyError {
    /// A scoped callback still retains the actual child owner.
    #[cfg(target_arch = "x86_64")]
    CallbackActive,
    /// The owner is not a created child or is terminally retained.
    InvalidState,
    /// External huge-release ownership bits could not be allocated before
    /// source teardown. The complete live child remains available for retry.
    #[cfg(target_arch = "x86_64")]
    TrackingAllocation(MetaError),
    Attachment(MainHeapThreadAttachmentError),
    /// Registry unlink or the metadata-page drain that must precede it.
    Registry(ChildMetadataPageEngineError),
    /// The destroying thread's regular TLS table could not be released.
    ThreadLocalsRelease,
    MetadataTheapDetach(ChildMetadataTheapError),
    MetadataTheapRelease(ChildMainHeapReleaseError),
    HeapUnlink(SourceHeapRegistryError),
    /// Process destruction could not force-destroy a non-main child Heap.
    NonMainHeapDestroy(crate::types::heap_registry::lifecycle::HeapReleaseError),
    /// Process destruction could not detach a child-thread Theap.
    ChildThreadTheapDetach(ChildMainHeapReleaseError),
}

#[must_use = "a failed child subprocess destruction retains its owner"]
pub(crate) enum ChildSubprocessDestroyFailure<'main, 'tracking> {
    /// The owner records how far destruction progressed. A registry step
    /// that failed before mutating the list may be retried by calling
    /// [`destroy_child`] again; every later failure leaves it terminal.
    Retained {
        owner: ChildMainHeapContextOwner<'main>,
        error: ChildSubprocessDestroyError,
    },
    /// Heap free, arena destruction, or the final child-image release.
    Release(ChildMainHeapReleaseFailure<'main, 'tracking>),
}

impl core::fmt::Debug for ChildSubprocessDestroyFailure<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Retained { error, .. } => formatter.debug_tuple("Retained").field(error).finish(),
            Self::Release(ChildMainHeapReleaseFailure::Retained { stage, error, .. }) => formatter
                .debug_struct("Release")
                .field("stage", stage)
                .field("error", error)
                .finish(),
            Self::Release(ChildMainHeapReleaseFailure::ArenaBacking { .. }) => {
                formatter.write_str("Release(ArenaBacking)")
            }
            Self::Release(ChildMainHeapReleaseFailure::Terminal { .. }) => {
                formatter.write_str("Release(Terminal)")
            }
        }
    }
}

/// Pinned `mi_subproc_destroy` for a child created by [`new_child`],
/// resuming at the owner's current destruction stage.
///
/// `tracking` supplies the huge-page release bitmap words that the child's
/// arena destruction may need (see `ProcessArenaBacking::destroy_all`); it
/// must lie outside every child arena.
///
/// # Safety
/// No thread uses the child and no child block is used again: every child
/// thread has finished, live child metadata blocks are released with the
/// child arenas, and no child operation or registry teardown can race
/// destruction. `registry` admitted the child. The caller runs on the
/// attachment thread whose owner-local engine allocated the child main Heap.
pub(crate) unsafe fn destroy_child<'main, 'tracking>(
    child: ChildMainHeapContextOwner<'main>,
    registry: &'static SourceSubprocessRegistry,
    binding: ProcessMainBackingBinding,
    tracking: &'tracking mut [usize],
    attachment: &mut MainHeapThreadAttachment<'main>,
    heap_owner: &mut MainHeapThreadOwnerLocalPageEngine<'main>,
) -> Result<(), ChildSubprocessDestroyFailure<'main, 'tracking>> {
    let config = match attachment.memory_config() {
        Ok(config) => config,
        Err(error) => {
            return Err(ChildSubprocessDestroyFailure::Retained {
                owner: child,
                error: ChildSubprocessDestroyError::Attachment(error),
            });
        }
    };
    let metadata = attachment.parent_metadata_allocator();
    // SAFETY: forwarded obligations; this attachment's engine allocated the
    // child Heap image.
    unsafe {
        destroy_child_with(
            child, registry, binding, tracking, metadata, config,
            ChildHeapRelease::Parent { heap_owner, attachment }, false,
        )
    }
}

/// The body of [`destroy_child`] for either child Heap storage route.
///
/// # Safety
/// As for [`destroy_child`], with `metadata` the parent's metadata allocator
/// and `release` the free route matching the child's Heap storage.
unsafe fn destroy_child_with<'heap, 'tracking>(
    mut child: ChildMainHeapContextOwner<'heap>,
    registry: &'static SourceSubprocessRegistry,
    binding: ProcessMainBackingBinding,
    tracking: &'tracking mut [usize],
    metadata: core::pin::Pin<&'static crate::meta::MetaAllocator>,
    config: crate::os::MemoryConfig,
    release: ChildHeapRelease<'_, 'heap>,
    under_threads: bool,
) -> Result<(), ChildSubprocessDestroyFailure<'heap, 'tracking>> {
    // Process destruction, and `mi_subproc_destroy` of a child that threads
    // still belong to, destroy the child under those threads.
    let terminal = under_threads || matches!(release, ChildHeapRelease::Terminal);
    let release_thread_locals = matches!(release, ChildHeapRelease::Native);
    let mut release = Some(release);
    loop {
        let step = match child.stage() {
            // subproc.c:207-221: remove the child from the subprocess list,
            // then force-destroy each non-main Heap. Rust destroys the
            // non-main Heaps first: their page releases go through the
            // child's page backing, which requires its registry membership,
            // and nothing in that destruction reads the subprocess list. A
            // destroy that the live-thread check refuses changes nothing.
            // SAFETY: forwarded quiescence and exact-registry obligations.
            ChildMainHeapStage::HeapReady if terminal => unsafe {
                destroy_non_main_heaps(&mut child, binding).and_then(|()| {
                    // Regular slots and the fast root leave the destroying
                    // thread before the child's main Heap is detached.
                    if release_thread_locals
                        && !crate::subproc::main_heaps::release_current_thread_locals_for_child_destroy()
                    { return Err(ChildSubprocessDestroyError::ThreadLocalsRelease); }
                    child
                        .unlink_registry_and_detach_pages_terminal(registry, binding)
                        .map_err(ChildSubprocessDestroyError::Registry)
                })
            },
            // SAFETY: as above.
            ChildMainHeapStage::HeapReady => unsafe {
                if child.with_child_image(|image| image.get_ref().identity().live_thread_count()) != Some(0) {
                    Err(ChildSubprocessDestroyError::Registry(ChildMetadataPageEngineError::LiveThreads))
                } else {
                    destroy_non_main_heaps(&mut child, binding).and_then(|()| {
                        // The source keeps default and cached Theaps live
                        // while releasing regular slots and the fast root.
                        if release_thread_locals
                            && !crate::subproc::main_heaps::release_current_thread_locals_for_child_destroy()
                        { return Err(ChildSubprocessDestroyError::ThreadLocalsRelease); }
                        child
                            .unlink_registry_and_finish_metadata_pages(registry, binding)
                            .map_err(ChildSubprocessDestroyError::Registry)
                    })
                }
            },
            // heap.c:151-155 `_mi_heap_detach_theaps` of the main Heap: the
            // remaining child-thread Theaps, then the metadata Theap.
            // SAFETY: registry unlink succeeded, terminal quiescence holds for
            // the terminal steps, and `metadata` attached the metadata Theap.
            ChildMainHeapStage::RegistryUnlinked => unsafe {
                let threads = if terminal {
                    child.detach_child_thread_theaps_terminal()
                        .map_err(ChildSubprocessDestroyError::ChildThreadTheapDetach)
                } else {
                    Ok(())
                };
                threads.and_then(|()| {
                    child
                        .detach_metadata_theap(metadata, config)
                        .map_err(ChildSubprocessDestroyError::MetadataTheapDetach)
                })
            },
            // heap.c:158-172: merge its statistics, then `_mi_theap_decref`.
            // SAFETY: both list edges were removed by the previous step.
            ChildMainHeapStage::TheapDetached => unsafe {
                child
                    .release_metadata_theap_after_detach()
                    .map_err(ChildSubprocessDestroyError::MetadataTheapRelease)
            },
            // heap.c:205-219: statistics, count, and list removal.
            // SAFETY: the metadata Theap was the Heap's only Theap.
            ChildMainHeapStage::MetadataTheapReleased => unsafe {
                child.unlink_child_heap().map_err(ChildSubprocessDestroyError::HeapUnlink)
            },
            ChildMainHeapStage::HeapListRemoved
            | ChildMainHeapStage::HeapStorageReleased
            | ChildMainHeapStage::ArenaBackingDestroyed => {
                // heap.c:223-226 Heap image free, then subproc.c:231-252.
                // SAFETY: every list transition completed above and the
                // caller's route matches the child Heap storage.
                let release = release.take().expect("the release route is consumed once");
                return unsafe { child.release_after_empty_heap_teardown_with(tracking, release) }
                    .map_err(ChildSubprocessDestroyFailure::Release);
            }
            ChildMainHeapStage::Registered | ChildMainHeapStage::Terminal => {
                Err(ChildSubprocessDestroyError::InvalidState)
            }
        };
        if let Err(error) = step {
            return Err(ChildSubprocessDestroyFailure::Retained { owner: child, error });
        }
    }
}

/// `_mi_heap_force_destroy` of every non-main Heap of `child`
/// (`subproc.c:215-221`), in list order, just before its registry unlink.
///
/// # Safety
/// No thread uses the child again (all its threads finished, or permanent
/// terminal quiescence).
unsafe fn destroy_non_main_heaps(
    child: &mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
) -> Result<(), ChildSubprocessDestroyError> {
    let main = child.main_heap_pointer().ok_or(ChildSubprocessDestroyError::InvalidState)?;
    loop {
        let mut first = None;
        let visited = child.visit_heaps(|heap| {
            if heap == main {
                return true;
            }
            first = Some(heap);
            false
        });
        if !matches!(visited, Some(Ok(_))) {
            return Err(ChildSubprocessDestroyError::InvalidState);
        }
        let Some(heap) = first else { return Ok(()) };
        // SAFETY: forwarded quiescence; `heap` is a non-main Heap of `child`.
        unsafe { crate::types::heap_registry::lifecycle::child_heap_force_destroy_for_subprocess_destroy(child, binding, heap) }
            .map_err(ChildSubprocessDestroyError::NonMainHeapDestroy)?;
    }
}

/// A thread that [`add_current_thread`] admitted to a child subprocess: its
/// ordinary TLD and regular Theap on the child main Heap, installed as the
/// thread's default Theap and the main-Heap fast slot.
///
/// The member does not borrow the child, so other threads may use the child
/// meanwhile. Its registration keeps the child's live thread count raised
/// until [`Self::thread_done`] completes, so ordinary owned destruction
/// refuses. Native destruction may release a permanently quiescent child
/// under this member; its later exit then uses only the retained native record.
/// Dropping a member frees nothing and leaves its roots and registration intact.
#[must_use = "a child subprocess thread must finish through thread_done"]
pub(crate) struct ChildThreadMember {
    owner: ChildThreadOwner,
}

/// Result of pinned `mi_subproc_add_current_thread`.
#[must_use = "an admitted child thread must finish through thread_done"]
pub(crate) enum ChildThreadAddOutcome {
    Added(ChildThreadMember),
    /// The thread's default Theap is already initialized, so source returns
    /// without a change (`subproc.c:291-296`). Source warns only when that
    /// Theap belongs to another subprocess.
    AlreadyInitialized { in_other_subprocess: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildThreadDoneError {
    /// Called on a thread other than the one the member admitted.
    WrongThread,
    /// `child` is not the context that admitted the member.
    WrongChild,
    /// A page could not be handed to the child main Heap (a failed page
    /// transition). The member's engine is terminal.
    PagesRemain,
    /// Page drain or release could not run; the member is unchanged.
    PageEngine(ChildMetadataPageEngineError),
    /// A Theap of a non-main Heap could not be drained or released: one with
    /// a live block (which cannot be abandoned to a non-main Heap yet), or a
    /// metadata failure. The member's state is terminal.
    HeapTheap(crate::meta::ChildHeapTheapError),
    /// A teardown step after the roots were reset failed; the member is
    /// terminally retained.
    Teardown(ChildThreadTeardownError),
}

/// Pinned `mi_subproc_add_current_thread` (`subproc.c:283-299`) followed by
/// `_mi_thread_init_with_heap(child->heap_main)` (`init.c:306-360`).
///
/// A thread whose default Theap is already initialized is refused. A fresh
/// thread gets an ordinary TLD and regular Theap from the child's metadata
/// Theap, publishes that Theap as its default Theap and in the child main
/// Heap's fast slot, then counts in the child's `threads` statistic.
///
/// # Safety
/// The caller runs on the thread being admitted and owns its compiler-TLS
/// default/cached/fast roots for the member's lifetime. No other operation on
/// `child` runs concurrently with this call.
pub(crate) unsafe fn add_current_thread(
    child: &mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
) -> Result<ChildThreadAddOutcome, ChildThreadStartFailure> {
    // subproc.c:286-288: a child without a main Heap is ignored.
    if child.stage() != ChildMainHeapStage::HeapReady {
        return Err(ChildThreadStartFailure::Rejected(ChildThreadStartError::InvalidTransition));
    }
    let identity = child.identity_pointer().ok_or(ChildThreadStartFailure::Rejected(
        ChildThreadStartError::InvalidTransition,
    ))?;
    // subproc.c:289-296 reads the current default Theap before any change.
    // SAFETY: the default root is this thread's own, and the caller excludes
    // any concurrent transition of it.
    let current = unsafe { Theap::initialized_default_subprocess_at(default_theap()) };
    if let Some(subprocess) = current {
        return Ok(ChildThreadAddOutcome::AlreadyInitialized {
            in_other_subprocess: !subprocess.is_null() && subprocess != identity,
        });
    }
    // init.c:326-341: TLD and Theap allocation and `_mi_theap_init`.
    // SAFETY: forwarded current-thread ownership and child exclusion.
    let mut owner = unsafe { child.begin_child_thread(binding) }?;
    let Some(theap) = owner.theap_pointer() else {
        return Err(ChildThreadStartFailure::Retained {
            owner,
            error: ChildThreadStartError::InvalidTransition,
        });
    };
    // init.c:345-347: the default root first, then the child main Heap's
    // slot, which is the fast key for every main Heap (heap.c:136).
    set_default_theap(theap);
    set_fast_slot(Some(theap.cast()));
    // init.c:353: `threads` counts in the Theap's subprocess.
    let counted = owner.with_child_image(|image| {
        image.get_ref().identity().record_statistics_thread_attached();
    });
    debug_assert!(counted.is_some(), "an attached child owner projects its image");
    Ok(ChildThreadAddOutcome::Added(ChildThreadMember { owner }))
}

impl ChildThreadMember {
    /// Runs one ordinary page-engine operation through this thread's Theap.
    ///
    /// # Safety
    /// As for `ChildThreadOwner::with_page_engine`: the caller is the admitted
    /// thread and no competing mutation of its TLD/Theap runs.
    pub(crate) unsafe fn with_page_engine<R>(
        &mut self,
        binding: ProcessMainBackingBinding,
        operation: impl for<'session, 'child> FnOnce(
            core::pin::Pin<&'child crate::subproc::ChildSubprocessImage>,
            &mut crate::single_thread::ChildOrdinaryPageAllocator<'session, 'child, 'static>,
        ) -> R,
    ) -> Result<R, ChildMetadataPageEngineError> {
        // SAFETY: forwarded caller obligations.
        unsafe { self.owner.with_page_engine(binding, operation) }
    }

    #[inline]
    pub(crate) fn theap_pointer(&self) -> Option<core::ptr::NonNull<Theap>> {
        self.owner.theap_pointer()
    }

    #[inline]
    pub(crate) const fn sequence(&self) -> crate::types::ThreadSequence { self.owner.sequence() }

    #[inline]
    pub(crate) const fn thread(&self) -> crate::types::LiveThreadId { self.owner.thread() }

    /// This member's thread owner, for the Heap operations of
    /// `types::heap_registry::lifecycle`.
    #[inline]
    pub(crate) fn owner_mut(&mut self) -> &mut crate::meta::ChildThreadOwner { &mut self.owner }

    /// Projects the child subprocess image this thread belongs to.
    pub(crate) fn with_child_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(core::pin::Pin<&'image crate::subproc::ChildSubprocessImage>) -> R,
    ) -> Option<R> {
        self.owner.with_child_image(operation)
    }

    /// Pinned `_mi_thread_done` (`init.c:452-480`) for this child thread:
    /// release its all-free pages and abandon every page with a live block
    /// to the child main Heap, clear the fast slot, count the thread out of
    /// the child's `threads` statistic, reset the default and cached roots to
    /// the empty Theap, then detach and free the Theap and TLD
    /// (`mi_thread_theaps_done`, `mi_tld_free`). Blocks that outlive the
    /// thread stay valid; any thread may free them later.
    ///
    /// # Safety
    /// The caller is the admitted thread, no allocation through this member
    /// is in progress, `child` is the context that admitted it, and
    /// no other operation on the child runs concurrently with this call.
    pub(crate) unsafe fn thread_done(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: ProcessMainBackingBinding,
    ) -> Result<(), ChildThreadDoneError> {
        if crate::compiler_tls::current_thread_identity() != Some(self.owner.thread()) {
            return Err(ChildThreadDoneError::WrongThread);
        }
        if !self.owner.belongs_to(child) {
            return Err(ChildThreadDoneError::WrongChild);
        }
        // init.c:465 `_mi_thread_locals_thread_done`, then init.c:392-395 for
        // the thread's Theaps of non-main Heaps.
        let owner: *mut crate::meta::ChildThreadOwner = &mut self.owner;
        let child_pointer: *mut ChildMainHeapContextOwner<'_> = child;
        // SAFETY: forwarded current-thread obligations; neither pointer is
        // otherwise borrowed for the call.
        unsafe { crate::meta::ChildThreadOwner::drain_heap_theaps_for_thread_done(owner, child_pointer, binding) }
            .map_err(ChildThreadDoneError::HeapTheap)?;
        // init.c:392-395 `_mi_theap_collect_abandon`: release the all-free
        // pages and hand every page with a live block to the child main Heap.
        // SAFETY: forwarded current-thread and quiescence obligations.
        let drained = unsafe {
            self.owner.with_page_engine(binding, |_child, engine| unsafe {
                engine.collect_abandon_for_thread_done()
            })
        }
        .map_err(ChildThreadDoneError::PageEngine)?;
        if !drained {
            return Err(ChildThreadDoneError::PagesRemain);
        }
        // init.c:465 `_mi_thread_locals_thread_done` clears the fast slot.
        set_fast_slot(None);
        // init.c:468.
        let counted = self.owner.with_child_image(|image| {
            image.get_ref().identity().record_statistics_thread_detached();
        });
        debug_assert!(counted.is_some(), "an attached child owner projects its image");
        // init.c:396-397, after the (already complete) page drain.
        // SAFETY: the immutable source empty Theap is process-static and non-null.
        let empty = unsafe {
            core::ptr::NonNull::new_unchecked(crate::bootstrap::empty_default_theap_ptr())
        };
        set_default_theap(empty);
        // init.c:397 and 401-419 for the Theaps of non-main Heaps.
        // SAFETY: forwarded; their pages are gone.
        unsafe { self.owner.release_heap_theaps_for_thread_done(child, binding) }
            .map_err(ChildThreadDoneError::HeapTheap)?;
        // init.c:401-419 and `mi_tld_free`.
        // SAFETY: forwarded obligations; the roots no longer name the Theap.
        unsafe { self.owner.teardown(child, binding) }.map_err(ChildThreadDoneError::Teardown)
    }
}

/// One production child subprocess. Its address is the `mi_subproc_id_t`
/// returned by [`native_subproc_new`].
///
/// Operations that need the child context (thread admission and finish,
/// Heap visitation, destruction) serialize on `lock`, as source serializes
/// them on `theap_meta_lock` and `heaps_lock`. An admitted thread's page
/// operations do not take it.
pub(crate) struct NativeChildSubprocess {
    lock: crate::lock::PrivateLock,
    owner: core::cell::UnsafeCell<Option<ChildMainHeapContextOwner<'static>>>,
    /// On x86, the enclosing child allocation transfers here after source
    /// teardown; other targets retain their separate control allocation.
    /// Release waits for the last actual TLS member to finish.
    storage: core::cell::UnsafeCell<Option<crate::meta::ChildMetadataAllocation>>,
    /// Exact parent-issued destruction scratch exists only when published
    /// huge owners need raw failure bits. Its pending owner retains those
    /// bits through retry and never enlarges the inline birth control image.
    #[cfg(target_arch = "x86_64")]
    destroy_state: core::cell::UnsafeCell<Option<crate::meta::ChildMetadataAllocation>>,
    parent_metadata: ChildParentMetadata,
    /// A nested child's parent-issued context outlives source teardown when
    /// actual TLS still retains its inline record. Keep that parent pinned
    /// until the exact context allocation returns at final record release.
    #[cfg(target_arch = "x86_64")]
    parent_admission: core::cell::UnsafeCell<Option<NativeChildCallbackLease>>,
    registry: &'static SourceSubprocessRegistry,
    /// Actual compiler-TLS member tokens, including a failed finish whose
    /// source thread registration already ended. The record survives child
    /// destruction until the last retained token completes terminal finish.
    members: core::cell::UnsafeCell<usize>,
    /// Admission retained across callbacks after owner projections and locks end.
    #[cfg(target_arch = "x86_64")]
    callback_leases: core::sync::atomic::AtomicUsize,
}

// SAFETY: every access to the owner, storage, and member-count cells happens
// with `lock` held, except the
// creator's initialization before the id is returned and the destroyer's
// final teardown after the owner is gone; the id contract excludes any other
// operation on the record in both windows.
unsafe impl Sync for NativeChildSubprocess {}

/// Production `mi_subproc_id_t` for a child subprocess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeSubprocessId(core::ptr::NonNull<NativeChildSubprocess>);

// SAFETY: the id is an address; the record it names is `Sync`.
unsafe impl Send for NativeSubprocessId {}
// SAFETY: as above.
unsafe impl Sync for NativeSubprocessId {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeSubprocessError {
    /// The native runtime has not completed startup.
    NotReady,
    /// The record's parent-metadata block could not be allocated.
    RecordAllocation(crate::meta::MetaError),
    /// Source `mi_subproc_new` returned null; everything was released.
    New(ChildSubprocessNewError),
    /// A step failed after a transition that cannot be undone; its owners are
    /// retained (leaked) rather than freed.
    Retained,
    /// The record lock failed.
    Lock(crabc_core::Errno),
    /// Destruction refused before any change: a thread still belongs to the
    /// child, or another retryable step failed. The id stays valid.
    DestroyRefused(ChildSubprocessDestroyError),
    /// The child context is gone (already destroyed or terminally retained).
    Gone,
    /// Native allocator admission is closed (process destruction or a
    /// thread that is not registered with the runtime).
    Closed,
}

impl NativeSubprocessId {
    /// # Safety
    /// The id was returned by [`native_subproc_new`] and has not been
    /// destroyed.
    unsafe fn record(self) -> &'static NativeChildSubprocess {
        // SAFETY: forwarded id contract; the record lives until destroy.
        unsafe { self.0.as_ref() }
    }

    /// Runs `operation` on the child context under the record lock.
    ///
    /// # Safety
    /// As for [`Self::record`].
    pub(crate) unsafe fn with_owner<R>(
        self,
        operation: impl FnOnce(&mut Option<ChildMainHeapContextOwner<'static>>) -> R,
    ) -> Result<R, NativeSubprocessError> {
        // SAFETY: forwarded id contract.
        let record = unsafe { self.record() };
        let guard = record.lock.lock().map_err(NativeSubprocessError::Lock)?;
        // SAFETY: the held lock serializes every access to the owner cell.
        let value = operation(unsafe { &mut *record.owner.get() });
        guard.unlock().map_err(NativeSubprocessError::Lock)?;
        Ok(value)
    }
}

/// One actual child-record admission retained while no owner projection or
/// private lock spans user callbacks. The record's count is the final release
/// target, after every callback-derived process view has ended.
#[cfg(target_arch = "x86_64")]
struct NativeChildCallbackLease(core::ptr::NonNull<NativeChildSubprocess>);

#[cfg(target_arch = "x86_64")]
impl Drop for NativeChildCallbackLease {
    fn drop(&mut self) {
        // SAFETY: acquisition retained the record independently of a child
        // projection. Destruction cannot take its owner while this count is
        // nonzero. This field-only decrement is the final record access.
        unsafe { &*core::ptr::addr_of!((*self.0.as_ptr()).callback_leases) }
            .fetch_sub(1, core::sync::atomic::Ordering::Release);
    }
}

/// # Safety
/// The caller retains this exact live id while independent record custody is
/// acquired. No projection or lock survives successful acquisition.
#[cfg(target_arch = "x86_64")]
unsafe fn acquire_native_child_record_lease(id: NativeSubprocessId)
    -> Result<(core::ptr::NonNull<crate::subproc::SubprocessIdentity>, NativeChildCallbackLease), NativeSubprocessError> {
    let mut admitted = None;
    // SAFETY: the actual caller retains the original id. This short
    // projection validates its owner before independent custody begins.
    let result = unsafe { id.with_owner(|owner| {
        let child = owner.as_mut().ok_or(NativeSubprocessError::Gone)?;
        if child.stage() != ChildMainHeapStage::HeapReady {
            return Err(NativeSubprocessError::Retained);
        }
        let identity = core::ptr::NonNull::new(child.identity_pointer()
            .ok_or(NativeSubprocessError::Gone)?).ok_or(NativeSubprocessError::Gone)?;
        let count = &*core::ptr::addr_of!((*id.0.as_ptr()).callback_leases);
        count.fetch_update(core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed, |value| value.checked_add(1))
            .map_err(|_| NativeSubprocessError::Retained)?;
        admitted = Some((identity, NativeChildCallbackLease(id.0)));
        Ok(())
    }) };
    if !matches!(result, Ok(Ok(()))) {
        // An unlock failure after actual custody changed cannot undo
        // that admission or advertise an owner suitable for callbacks.
        if let Some((_, lease)) = admitted { core::mem::forget(lease); }
        return Err(result.err().unwrap_or(NativeSubprocessError::Retained));
    }
    Ok(admitted.expect("validated original child admission"))
}

/// Actual admission to one child arena group and its detached metadata.
/// It retains the original record independently of TLS and ends only after
/// every reservation projection and diagnostic callback has ended.
#[cfg(target_arch = "x86_64")]
pub(crate) struct NativeChildArenaAdmission {
    id: NativeSubprocessId,
    binding: ProcessMainBackingBinding,
    identity: core::ptr::NonNull<crate::subproc::SubprocessIdentity>,
    config: crate::os::MemoryConfig,
    _child: NativeChildCallbackLease,
    _operation: crate::runtime_lifecycle::NativeSubprocessOperation,
}

#[cfg(target_arch = "x86_64")]
impl NativeChildArenaAdmission {
    /// Selects only the current actual child membership. A failed child
    /// admission never supplies the process-main arena or metadata owner.
    pub(crate) fn acquire_current() -> Option<Result<Self, NativeSubprocessError>> {
        // SAFETY: the current thread alone owns this slot. Copy only its
        // original identity and binding before taking any allocator lock.
        let (id, binding) = {
            let current = unsafe { current_child_member() }.as_ref()?;
            (current.record_member.id(), current.binding)
        };
        Some(Self::acquire(id, binding))
    }

    fn acquire(id: NativeSubprocessId, binding: ProcessMainBackingBinding)
        -> Result<Self, NativeSubprocessError> {
        let operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
            .ok_or(NativeSubprocessError::Closed)?;
        let config = binding.page_map().memory_config().map_err(|_| NativeSubprocessError::NotReady)?;
        // SAFETY: the current member or existing actual admission retains
        // this original id through independent record custody acquisition.
        let (identity, child) = unsafe { acquire_native_child_record_lease(id) }?;
        Ok(Self { id, binding, identity, config, _child: child, _operation: operation })
    }

    pub(crate) fn config(&self) -> crate::os::MemoryConfig { self.config }

    /// # Safety
    /// This actual admission must remain retained until every returned view,
    /// reservation owner and cleanup continuation has ended. The static
    /// spelling cannot itself establish the reclaimable child's lifetime.
    pub(crate) unsafe fn process(&self) -> crate::os::VmProcess<'static> {
        // SAFETY: the counted admission prevents original child retirement;
        // the caller additionally retains it through every derived owner.
        crate::os::VmProcess::new(self.binding.process().policy(), unsafe { self.identity.as_ref() })
    }

    /// # Safety
    /// As for `process`: every derived arena or cleanup owner must retain
    /// this admission until its final child-image access has ended.
    pub(crate) unsafe fn backing(&self) -> &'static crate::arena::ProcessArenaBacking {
        // SAFETY: this is the original admitted identity, never TLS reselected.
        unsafe { self.identity.as_ref() }.arena_backing()
    }

    /// Issues a zeroed tracker from the original child's detached Theap.
    /// The returned exact capability independently retains that child until
    /// its storage has returned, including a failed metadata free.
    pub(crate) fn allocate_tracker(&self, bytes: usize) -> Result<NativeChildArenaMetadata, MetaError> {
        let retained = Self::acquire(self.id, self.binding).map_err(|_| MetaError::Closed)?;
        let route = ChildParentMetadata::Child { id: self.id, binding: self.binding };
        let allocation = route.allocate(bytes)?;
        Ok(NativeChildArenaMetadata { route, allocation, admission: Some(retained) })
    }
}

/// One child-issued huge-release tracker and its actual issuing admission.
/// Failed storage return leaves the same capability and issuer retained.
#[cfg(target_arch = "x86_64")]
pub(crate) struct NativeChildArenaMetadata {
    route: ChildParentMetadata,
    allocation: crate::meta::ChildMetadataAllocation,
    admission: Option<NativeChildArenaAdmission>,
}

#[cfg(target_arch = "x86_64")]
impl NativeChildArenaMetadata {
    /// Reports remaining client-release authority, not issuer availability.
    /// A consumed or rejected client can never supply bytes or another free.
    pub(crate) fn can_retry_free(&self) -> bool {
        self.admission.is_some() && self.allocation.is_live()
    }

    pub(crate) fn pointer(&self) -> core::ptr::NonNull<u8> {
        assert!(self.can_retry_free(), "released or rejected tracker has no live projection");
        self.allocation.pointer()
    }

    /// Returns the original capability once. A pre-entry or non-consuming
    /// refusal retains the same client for retry. An admitted terminal error
    /// retains issuer custody but grants no bytes or another client free.
    pub(crate) fn free(&mut self) -> Result<(), MetaError> {
        if self.admission.is_none() { return Err(MetaError::ForeignOwner); }
        if !self.allocation.is_live() { return Err(MetaError::ReleasedOrStale); }
        self.route.free(&mut self.allocation)?;
        self.admission.take();
        Ok(())
    }
}

/// Retains the actual child owner across a synchronous callback, after the
/// caller's page-engine and metadata projections have ended. Nested ordinary
/// allocation is allowed: neither a private lock nor a TLS/member reference
/// survives into the callback. A process view is scoped to this admission and
/// cannot replace or extend the owner lease.
///
/// # Safety
/// `heap` is a live published Heap retained while admission is acquired;
/// a process-main Heap is refused. The selected member may belong to another
/// parked thread. The caller retains its selected Heap, Theap, member, and
/// any in-flight client for the complete source allocation operation.
/// The callback must not delete that selected Heap, finish its selected member,
/// or free its in-flight client. All exclusive page-engine, child and member
/// projections ended before this call. Other ordinary allocation may reenter.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn with_native_child_callback_owner<R>(
    heap: core::ptr::NonNull<crate::types::Heap>,
    callback: impl for<'scope> FnOnce(crate::os::VmProcess<'scope>) -> R,
) -> Option<R> {
    // SAFETY: forwarded live selected-owner and callback obligations.
    unsafe { try_with_native_child_callback_owner(heap, callback) }.ok()
}

/// A refused child callback admission. Only lock contention can be retried;
/// no owner, scope, or release authority is returned on either error.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeChildCallbackAdmissionError {
    Busy,
    Invalid,
}

/// Acquires a child callback scope without waiting for its record lock.
/// A caller may retry `Busy` only after every allocator projection and lock
/// has ended, while retaining the same source-valid selected owner. Failed
/// gates, unavailable children, and partially completed admission are final
/// refusals rather than transient allocation failures.
///
/// # Safety
/// `heap` is a live published Heap; process-main Heaps are refused. Any
/// selected Theap, member, and existing in-flight client stay live through
/// acquisition and the synchronous callback. No engine, member, or child
/// projection or allocator lock crosses this call. The callback must not
/// destroy its selected Heap, finish its member, or free its in-flight client.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn try_with_native_child_callback_owner<R>(
    heap: core::ptr::NonNull<crate::types::Heap>,
    callback: impl for<'scope> FnOnce(crate::os::VmProcess<'scope>) -> R,
) -> Result<R, NativeChildCallbackAdmissionError> {
    use NativeChildCallbackAdmissionError::{Busy, Invalid};
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter().ok_or(Invalid)?;
    let (binding, registry) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs().ok_or(Invalid)?;
    // SAFETY: the caller retains this Heap. Only its immutable identity is
    // copied; mutable Heap lists are not projected.
    let identity = unsafe { crate::types::Heap::subprocess_pointer_at(heap) };
    if identity.is_null() || identity == crate::subproc::MainSubprocess::global().identity_ptr() {
        return Err(Invalid);
    }
    // SAFETY: the source list gate retains the original image. The closure
    // only tries the record lock and cannot wait, allocate, or invoke users.
    let retained = unsafe { registry.with_registered_child_image(identity, |image| {
        let record = image.native_record().ok_or(Invalid)?;
        // Teardown takes the record lock before the source registry gate.
        // A try-only acquire avoids reversing that waiting order.
        let guard = (&*core::ptr::addr_of!((*record.as_ptr()).lock)).try_lock().ok_or(Busy)?;
        let owner = &mut *(*record.as_ptr()).owner.get();
        let valid = owner.as_mut().is_some_and(|child| {
            child.stage() == ChildMainHeapStage::HeapReady
                && child.identity_pointer() == Some(image.identity_pointer())
                && image.identity_pointer() == identity
        });
        if !valid {
            guard.unlock().map_err(|_| Invalid)?;
            return Err(Invalid);
        }
        let count = &*core::ptr::addr_of!((*record.as_ptr()).callback_leases);
        if count.fetch_update(core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed, |value| value.checked_add(1)).is_err()
        {
            guard.unlock().map_err(|_| Invalid)?;
            return Err(Invalid);
        }
        let lease = NativeChildCallbackLease(record);
        if guard.unlock().is_err() {
            // Actual custody already changed. Keep the owner pinned and
            // never advertise this partial admission as retryable.
            core::mem::forget(lease);
            return Err(Invalid);
        }
        Ok((lease, image.identity_pointer()))
    }) };
    let (lease, retained_identity) = match retained {
        Ok(Some(Ok(acquired))) => acquired,
        Ok(Some(Err(error))) => return Err(error),
        Err(crate::subproc::registry::RegisteredChildImageLookupError::GateRelease {
            acquired: Ok((lease, _)), ..
        }) => {
            // Gate release failed after admission. Keep actual custody and
            // refuse callbacks terminally; dropping it would imply success.
            core::mem::forget(lease);
            return Err(Invalid);
        }
        _ => return Err(Invalid),
    };
    // SAFETY: this real admission prevents child reclamation. The identity
    // view is scoped to the callback and never replaces its record lease.
    let process = crate::os::VmProcess::new(binding.process().policy(), unsafe { &*retained_identity });
    let result = callback(process);
    drop(lease);
    Ok(result)
}

/// An actual child admission for a private, not-yet-initialized Theap.
/// The pending initializer owns its allocation separately; this admission
/// retains the original child, selected Heap, and process across callbacks.
/// It grants no initialized-Theap allocation authority.
#[cfg(target_arch = "x86_64")]
struct NativeChildInitializationAdmission {
    heap: core::ptr::NonNull<crate::types::Heap>,
    output: &'static crate::diagnostic_output::OutputOwner,
    _child: NativeChildCallbackLease,
    _operation: crate::runtime_lifecycle::NativeSubprocessOperation,
}

/// Synchronous initializer admissions share the existing thread-owned TLS
/// root. Each actual ticket retains its own admission, including nested
/// initializers of the same Heap; no scalar count supplies their lifetime.
#[cfg(target_arch = "x86_64")]
struct NativeChildInitializationScope {
    admission: Option<NativeChildInitializationAdmission>,
    previous: *const Self,
    _pinned: core::marker::PhantomPinned,
}

#[cfg(target_arch = "x86_64")]
impl NativeChildInitializationScope {
    /// Keeps a failed original initializer's admission after its exact keeper
    /// has been retained terminally. No linked image is rolled back or freed.
    unsafe fn retain_at(scope: core::ptr::NonNull<Self>) {
        let admission = unsafe { (*scope.as_ptr()).admission.take() }
            .expect("original initializer admission retained once");
        // SAFETY: a short current-thread field projection after all callback
        // and metadata projections ended. A nested failure may already own
        // the terminal slot; its independent admission must remain retained.
        let slot = unsafe { &mut (*CURRENT_CHILD_MEMBER.get()).retained_initialization };
        if slot.is_none() { *slot = Some(admission); }
        else { core::mem::forget(admission); }
    }

    /// Reads the original route without retaining a scope projection across
    /// any option getter or entropy warning.
    unsafe fn output_at(scope: core::ptr::NonNull<Self>) -> &'static crate::diagnostic_output::OutputOwner {
        unsafe { (*scope.as_ptr()).admission.as_ref() }
            .expect("live original initializer admission").output
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for NativeChildInitializationScope {
    fn drop(&mut self) {
        // SAFETY: the scope is pinned and synchronous nested admissions have
        // ended before this stack entry is removed. No projection survives.
        unsafe {
            assert_eq!((*CURRENT_CHILD_MEMBER.get()).initialization, self as *const _);
            (*CURRENT_CHILD_MEMBER.get()).initialization = self.previous;
        }
    }
}

/// Admits the original child before allocating a private initializer image.
/// No record, child, member, Heap, or metadata projection crosses callbacks.
///
/// # Safety
/// The id and selected published Heap are live and belong to the same child.
/// The caller retains its actual pending initializer keeper across callbacks
/// and supplies that same keeper to completion. An auxiliary initializer's
/// actual member and TLD remain retained until completion or terminal custody.
#[cfg(target_arch = "x86_64")]
unsafe fn with_native_child_initialization_scope<R>(
    id: NativeSubprocessId,
    heap: core::ptr::NonNull<crate::types::Heap>,
    operation: impl FnOnce(core::ptr::NonNull<NativeChildInitializationScope>) -> R,
) -> Result<R, NativeSubprocessError> {
    if unsafe { (*CURRENT_CHILD_MEMBER.get()).retained_initialization.is_some() } {
        return Err(NativeSubprocessError::Retained);
    }
    let admitted_operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
        .ok_or(NativeSubprocessError::Closed)?;
    let output = crate::process_init::process_output_owner().ok_or(NativeSubprocessError::NotReady)?;
    let mut lease = None;
    // SAFETY: the original id and Heap remain live. This short record
    // projection ends before preparation, option reads, or warning delivery.
    let admitted = unsafe { id.with_owner(|owner| {
        let child = owner.as_mut().ok_or(NativeSubprocessError::Gone)?;
        if child.stage() != ChildMainHeapStage::HeapReady
            || child.identity_pointer() != Some(crate::types::Heap::subprocess_pointer_at(heap))
        { return Err(NativeSubprocessError::Retained); }
        let count = &*core::ptr::addr_of!((*id.0.as_ptr()).callback_leases);
        count.fetch_update(core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed, |value| value.checked_add(1))
            .map_err(|_| NativeSubprocessError::Retained)?;
        lease = Some(NativeChildCallbackLease(id.0));
        Ok(())
    }) };
    if !matches!(admitted, Ok(Ok(()))) {
        if let Some(lease) = lease { core::mem::forget(lease); }
        return Err(admitted.err().unwrap_or(NativeSubprocessError::Retained));
    }
    let previous = unsafe { (*CURRENT_CHILD_MEMBER.get()).initialization };
    let mut scope = core::pin::pin!(NativeChildInitializationScope {
        admission: Some(NativeChildInitializationAdmission { heap, output,
            _child: lease.expect("actual initializer record admission"), _operation: admitted_operation }),
        previous, _pinned: core::marker::PhantomPinned,
    });
    let pointer = unsafe { core::ptr::NonNull::from(scope.as_mut().get_unchecked_mut()) };
    unsafe { (*CURRENT_CHILD_MEMBER.get()).initialization = pointer.as_ptr(); }
    Ok(operation(pointer))
}

/// Completes one original prepared child image through the selected live
/// source options. The keeper and actual admission remain held while entropy
/// warnings run; guarded reads occur afterward so callback changes are visible.
///
/// # Safety
/// The caller owns the exact initializer keeper that produced `phase` and
/// retains it, the original child admission, and any existing member/TLD.
/// No record, member, Heap, Theap, TLD, or metadata projection crosses this
/// call. The same keeper must consume the ready phase or retain its failure.
#[cfg(target_arch = "x86_64")]
unsafe fn initialize_native_child_theap_source(
    scope: core::ptr::NonNull<NativeChildInitializationScope>,
    phase: crate::types::PreparedTheapInitialization,
) -> Result<crate::types::ReadyTheapInitialization, crate::types::TheapMainStaticInitError> {
    let output = unsafe { NativeChildInitializationScope::output_at(scope) };
    let options = unsafe { crate::types::SourceTheapOptions::capture_from_output(output) };
    let linked = match unsafe { phase.apply_source_options_and_attach_with_failure_owner(options) }
        .map_err(|failure| failure.error())?
    {
        crate::types::TheapRandomInitialization::SplitComplete(linked) => linked,
        crate::types::TheapRandomInitialization::FirstHead(first) => {
            let prepared = crate::random::PreparedRandomInitialization::prepare_normal();
            if prepared.requires_warning() {
                // SAFETY: the actual initialization admission and original
                // keeper remain owned; all allocator projections have ended.
                unsafe { output.warning_from_source_options(
                    crate::diagnostic_output::SourceFormattedMessage::from_source_formatted(
                        c"unable to use secure randomness\n",
                    ),
                ) };
            }
            // SAFETY: genuine entropy refusal completed its source warning;
            // a complete strong fill has no warning obligation.
            let material = unsafe { prepared.after_warning() };
            unsafe { first.finish_random_initialization(material) }
        }
    };
    #[cfg(feature = "mi-guarded")]
    {
        let sample = unsafe { crate::types::GuardedSampleOptions::capture_from_output(output) };
        let sampled = unsafe { linked.apply_guarded_sample_options(sample) };
        let bounds = unsafe { crate::types::GuardedSizeOptions::capture_from_output(output) };
        Ok(unsafe { sampled.apply_guarded_size_options(bounds) })
    }
    #[cfg(not(feature = "mi-guarded"))]
    Ok(linked.finish_without_guarded_options())
}

/// Production pinned `mi_subproc_new` (`subproc.c:158-194`) for a root
/// child of the process main subprocess, on any runtime thread that may
/// allocate: the child main Heap image is an ordinary allocation through
/// the native runtime entry points, as source allocates it from the calling
/// thread's Theap for the parent main Heap.
pub(crate) fn native_subproc_new() -> Result<NativeSubprocessId, NativeSubprocessError> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
        .ok_or(NativeSubprocessError::Closed)?;
    let (binding, registry) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .ok_or(NativeSubprocessError::NotReady)?;
    let parent = crate::subproc::MainSubprocess::global();
    if binding.process().main_subprocess().is_none_or(|main| !core::ptr::eq(main, parent)) {
        return Err(NativeSubprocessError::NotReady);
    }
    let config = binding.page_map().memory_config().map_err(|_| NativeSubprocessError::NotReady)?;
    let metadata = crate::meta::MetaAllocator::global();
    let parent_metadata = match current_child_id() {
        Some(id) => ChildParentMetadata::Child { id, binding },
        None => ChildParentMetadata::Process { allocator: metadata, main: parent, config },
    };
    #[cfg(target_arch = "x86_64")]
    let parent_admission = match parent_metadata {
        ChildParentMetadata::Child { id, .. } => {
            // SAFETY: the calling thread's actual member retains this parent
            // while the nested child acquires its own exact issuer custody.
            Some(unsafe { acquire_native_child_record_lease(id) }?.1)
        },
        ChildParentMetadata::Process { .. } => None,
    };
    #[cfg(not(target_arch = "x86_64"))]
    let mut storage = parent_metadata
        .allocate(core::mem::size_of::<NativeChildSubprocess>())
        .map_err(NativeSubprocessError::RecordAllocation)?;
    #[cfg(not(target_arch = "x86_64"))]
    let record = storage.pointer().cast::<NativeChildSubprocess>();
    #[cfg(not(target_arch = "x86_64"))]
    if record.as_ptr().addr() % core::mem::align_of::<NativeChildSubprocess>() != 0 {
        return match parent_metadata.free(&mut storage) {
            Ok(()) => Err(NativeSubprocessError::RecordAllocation(crate::meta::MetaError::InitializationRetained)),
            Err(_) => Err(NativeSubprocessError::Retained),
        };
    }
    // SAFETY: the registry holds `parent` as its main member once startup is
    // READY; `metadata` is the parent's allocator; the native allocation runs
    // on this thread; nothing else can observe the new child yet.
    let child = unsafe {
        new_child_with(registry, parent_metadata, parent, config, || {
            crate::meta::NativeChildHeapImage::allocate()
                .map(ChildHeapStorage::Native)
                .ok_or(ChildSubprocessNewError::HeapAllocation)
        })
    };
    let mut child = match child {
        Ok(child) => child,
        Err(ChildSubprocessNewFailure::Released(error)) => {
            #[cfg(target_arch = "x86_64")]
            return Err(NativeSubprocessError::New(error));
            #[cfg(not(target_arch = "x86_64"))]
            return match parent_metadata.free(&mut storage) {
                Ok(()) => Err(NativeSubprocessError::New(error)),
                Err(_) => Err(NativeSubprocessError::Retained),
            };
        },
        Err(ChildSubprocessNewFailure::Retained(_)) => {
            // The unpublished child still owns exact parent-issued blocks;
            // a retained creation failure cannot release their actual issuer.
            #[cfg(target_arch = "x86_64")]
            core::mem::forget(parent_admission);
            return Err(NativeSubprocessError::Retained);
        },
    };
    #[cfg(target_arch = "x86_64")]
    let record = child.with_child_image(|image| image.native_control_pointer())
        .ok_or(NativeSubprocessError::Retained)?;
    // SAFETY: the block is exclusively owned, zeroed, large enough, and
    // aligned for the record, which is written whole before the id escapes.
    unsafe {
        record.as_ptr().write(NativeChildSubprocess {
            lock: crate::lock::PrivateLock::new(),
            owner: core::cell::UnsafeCell::new(Some(child)),
            #[cfg(target_arch = "x86_64")]
            storage: core::cell::UnsafeCell::new(None),
            #[cfg(not(target_arch = "x86_64"))]
            storage: core::cell::UnsafeCell::new(Some(storage)),
            #[cfg(target_arch = "x86_64")]
            destroy_state: core::cell::UnsafeCell::new(None),
            parent_metadata,
            #[cfg(target_arch = "x86_64")]
            parent_admission: core::cell::UnsafeCell::new(parent_admission),
            registry,
            members: core::cell::UnsafeCell::new(0),
            #[cfg(target_arch = "x86_64")]
            callback_leases: core::sync::atomic::AtomicUsize::new(0),
        });
    }
    // SAFETY: the record was written whole above and nothing else can reach
    // the new child yet.
    let owner = unsafe { &mut *record.as_ref().owner.get() };
    let published = owner.as_mut()
        .and_then(|child| child.with_child_image(|image| image.get_ref().publish_native_record(record)));
    debug_assert_eq!(published, Some(true), "a new child publishes its record once");
    Ok(NativeSubprocessId(record))
}

/// One actual compiler-TLS member's retention of its original record.
/// Source thread registration may end before metadata teardown succeeds;
/// this token ends only when the real TLS member completes finish. Dropping
/// it does not release the count or infer that terminal finish happened.
#[must_use = "the actual child TLS member retains its record until explicit finish"]
struct NativeChildRecordMember {
    id: Option<NativeSubprocessId>,
}

impl NativeChildRecordMember {
    fn id(&self) -> NativeSubprocessId {
        self.id.expect("a published child TLS member retains its record")
    }

    /// Consumes this actual member's record retention once.
    ///
    /// # Safety
    /// The exact record lock is held. The member has completed ordinary
    /// teardown or the child is gone and no child image is touched again.
    unsafe fn finish_locked(&mut self) -> Result<bool, NativeSubprocessError> {
        let id = self.id.ok_or(NativeSubprocessError::Gone)?;
        // SAFETY: the actual token retains this original record and its
        // held lock excludes admission, destruction, and another finish.
        let members = unsafe { &mut *id.record().members.get() };
        let remaining = members.checked_sub(1).ok_or(NativeSubprocessError::Retained)?;
        *members = remaining;
        self.id = None;
        Ok(remaining == 0)
    }
}

/// The child membership of the current thread, set by
/// [`native_subproc_add_current_thread`] and cleared by
/// [`native_child_thread_done`]. The native runtime allocation entry points
/// route an admitted thread's allocations and local frees through `member`.
struct CurrentChildMember {
    record_member: NativeChildRecordMember,
    binding: ProcessMainBackingBinding,
    member: ChildThreadMember,
    #[cfg(target_arch = "x86_64")]
    generic_frequency_captures: usize,
    #[cfg(target_arch = "x86_64")]
    allocation_scope: *const NativeChildAllocationScope,
    #[cfg(target_arch = "x86_64")]
    retained_fresh_issuer: Option<NativeChildRetainedFreshIssuer>,
}

struct NativeChildThreadSlot {
    member: Option<CurrentChildMember>,
    #[cfg(target_arch = "x86_64")]
    initialization: *const NativeChildInitializationScope,
    #[cfg(target_arch = "x86_64")]
    retained_initialization: Option<NativeChildInitializationAdmission>,
}

#[thread_local]
static CURRENT_CHILD_MEMBER: core::cell::UnsafeCell<NativeChildThreadSlot> =
    core::cell::UnsafeCell::new(NativeChildThreadSlot {
        member: None,
        #[cfg(target_arch = "x86_64")]
        initialization: core::ptr::null(),
        #[cfg(target_arch = "x86_64")]
        retained_initialization: None,
    });

/// A child-subprocess membership is an attached pthread owner, so a timer
/// callback's application TLS reset cannot replace this live membership.
#[cfg(target_arch = "x86_64")]
pub(crate) fn native_timer_tls_span() -> crate::runtime_lifecycle::NativeAllocatorTlsSpan {
    crate::runtime_lifecycle::NativeAllocatorTlsSpan::of(core::ptr::addr_of!(CURRENT_CHILD_MEMBER))
}

/// The current thread's child membership slot.
///
/// # Safety
/// The caller is on the current thread and forms no other reference to the
/// slot while the returned one is live; native entry points are not
/// reentrant within one child page operation.
#[inline]
unsafe fn current_child_member() -> &'static mut Option<CurrentChildMember> {
    // SAFETY: a `#[thread_local]` is reachable only from its own thread;
    // the caller guarantees exclusive use.
    unsafe { &mut (*CURRENT_CHILD_MEMBER.get()).member }
}

/// Whether the current thread belongs to a child subprocess. This is the
/// native entry points' one-load routing test.
#[inline]
pub(crate) fn current_thread_is_child_member() -> bool {
    // SAFETY: a short read of the current thread's own slot.
    unsafe { (*CURRENT_CHILD_MEMBER.get()).member.is_some() }
}

/// The child the current thread belongs to (`mi_subproc_current` for a
/// member), or `None` for a thread of the process main subprocess.
pub(crate) fn current_child_id() -> Option<NativeSubprocessId> {
    // SAFETY: a short read of the current thread's own slot.
    unsafe { (*CURRENT_CHILD_MEMBER.get()).member.as_ref().map(|member| member.record_member.id()) }
}

/// The main Heap of the current thread's child (`mi_heap_main` for a
/// member), or `None` when the thread is not a member or the child is gone.
pub(crate) fn current_child_main_heap() -> Option<core::ptr::NonNull<crate::types::Heap>> {
    let id = current_child_id()?;
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    // SAFETY: this member retains its native record through exit; its lock
    // excludes owner teardown during this projection. A destroyed child has
    // no owner and produces no Heap pointer.
    unsafe { id.with_owner(|owner| owner.as_ref().and_then(|child| child.main_heap_pointer())) }.ok().flatten()
}

impl NativeSubprocessId {
    /// The opaque `mi_subproc_id_t` pointer of this child.
    pub(crate) fn as_ptr(self) -> *mut core::ffi::c_void {
        self.0.as_ptr().cast()
    }

    /// The id a C caller passes back.
    ///
    /// # Safety
    /// `pointer` is a value [`Self::as_ptr`] returned for a live child.
    pub(crate) unsafe fn from_ptr(pointer: core::ptr::NonNull<core::ffi::c_void>) -> Self {
        Self(pointer.cast())
    }
}

/// Result of [`native_subproc_add_current_thread`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeChildThreadAdd {
    /// The thread now allocates from the child.
    Added,
    /// The thread's default Theap was already initialized; nothing changed.
    AlreadyInitialized { in_other_subprocess: bool },
    /// Admission failed; see [`ChildThreadStartFailure`]. A retained partial
    /// owner is dropped without freeing anything and the child stays alive.
    Failed(ChildThreadStartError),
}

/// Native child admission stages source callbacks outside the original
/// record and metadata projections. The direct owner route remains useful
/// for isolated lifecycle fixtures and the non-x86 implementation.
///
/// # Safety
/// The id is live, and this thread owns its default/cached/fast TLS roots.
#[cfg(target_arch = "x86_64")]
unsafe fn add_native_child_thread_source(
    id: NativeSubprocessId, binding: ProcessMainBackingBinding,
) -> Result<(Result<ChildThreadAddOutcome, ChildThreadStartFailure>, Option<NativeChildRecordMember>), NativeSubprocessError> {
    let (heap, identity) = unsafe { id.with_owner(|owner| {
        let child = owner.as_mut().ok_or(NativeSubprocessError::Gone)?;
        if child.stage() != ChildMainHeapStage::HeapReady { return Err(NativeSubprocessError::Retained); }
        Ok((child.main_heap_pointer().ok_or(NativeSubprocessError::Retained)?,
            child.identity_pointer().ok_or(NativeSubprocessError::Retained)?))
    }) }??;
    // SAFETY: only this thread reads its own original default root.
    if let Some(subprocess) = unsafe { Theap::initialized_default_subprocess_at(default_theap()) } {
        return Ok((Ok(ChildThreadAddOutcome::AlreadyInitialized {
            in_other_subprocess: !subprocess.is_null() && subprocess != identity,
        }), None));
    }
    unsafe { with_native_child_initialization_scope(id, heap, |scope| {
        let mut prepared = None;
        let entered = unsafe { id.with_owner(|owner| {
            if let Some(child) = owner.as_mut() {
                // Capture actual custody before a later record unlock can
                // fail; an outer error never drops an issued initializer.
                prepared = Some(unsafe { child.prepare_child_thread_initialization(binding) });
            }
        }) };
        if entered.is_err() {
            if let Some(candidate) = prepared.take() {
                match candidate {
                    Ok(pending) => core::mem::forget(pending),
                    Err(ChildThreadStartFailure::Retained { owner, .. }) => core::mem::forget(owner),
                    Err(ChildThreadStartFailure::Rejected(_)) => {}
                }
            }
            unsafe { NativeChildInitializationScope::retain_at(scope) };
            return Err(entered.err().expect("failed original record operation"));
        }
        let pending = match prepared {
            Some(Ok(pending)) => pending,
            Some(Err(failure)) => {
                if matches!(&failure, ChildThreadStartFailure::Retained { .. }) {
                    unsafe { NativeChildInitializationScope::retain_at(scope) };
                }
                return Ok((Err(failure), None));
            }
            None => return Err(NativeSubprocessError::Gone),
        };
        let (keeper, phase) = pending.into_phase();
        let ready = match unsafe { initialize_native_child_theap_source(scope, phase) } {
            Ok(ready) => ready,
            Err(error) => {
                let failure = keeper.retain(error);
                unsafe { NativeChildInitializationScope::retain_at(scope) };
                return Ok((Err(failure), None));
            }
        };
        // SAFETY: this ready phase belongs to the exact keeper retained
        // across all callbacks by the original child initialization admission.
        let mut owner = match unsafe { keeper.complete_source(ready) } {
            Ok(owner) => owner,
            Err(failure) => {
                unsafe { NativeChildInitializationScope::retain_at(scope) };
                return Ok((Err(failure), None));
            }
        };
        let Some(theap) = owner.theap_pointer() else {
            unsafe { NativeChildInitializationScope::retain_at(scope) };
            return Ok((Err(ChildThreadStartFailure::Retained {
                owner, error: ChildThreadStartError::InvalidTransition,
            }), None));
        };
        let mut token = None;
        let counted = unsafe { id.with_owner(|_| {
            let members = &mut *(*id.0.as_ptr()).members.get();
            let next = members.checked_add(1).ok_or(NativeSubprocessError::Retained)?;
            *members = next;
            token = Some(NativeChildRecordMember { id: Some(id) });
            Ok(())
        }) };
        if let Err(error) = counted.and_then(|result| result) {
            // This exact initialized owner and any already-issued token
            // remain retained even when final record administration failed.
            core::mem::forget(owner);
            if let Some(token) = token { core::mem::forget(token); }
            unsafe { NativeChildInitializationScope::retain_at(scope) };
            return Err(error);
        }
        set_default_theap(theap);
        set_fast_slot(Some(theap.cast()));
        let counted = owner.with_child_image(|image| {
            image.get_ref().identity().record_statistics_thread_attached();
        });
        debug_assert!(counted.is_some(), "an attached child owner projects its image");
        Ok((Ok(ChildThreadAddOutcome::Added(ChildThreadMember { owner })), token))
    }) }?
}

/// Production `mi_subproc_add_current_thread` for a child from
/// [`native_subproc_new`]; see [`add_current_thread`]. On success the
/// member moves into the current thread's slot, so the native runtime
/// allocation entry points route this thread to the child.
///
/// # Safety
/// The id is live. The caller runs on the thread being admitted and owns its
/// compiler-TLS roots until [`native_child_thread_done`].
pub(crate) unsafe fn native_subproc_add_current_thread(
    id: NativeSubprocessId,
) -> Result<NativeChildThreadAdd, NativeSubprocessError> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
        .ok_or(NativeSubprocessError::Closed)?;
    // SAFETY: current-thread slot, no other reference live.
    if unsafe { current_child_member() }.is_some() {
        // Source finds the default Theap initialized and returns.
        return Ok(NativeChildThreadAdd::AlreadyInitialized { in_other_subprocess: false });
    }
    let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .ok_or(NativeSubprocessError::NotReady)?;
    // SAFETY: forwarded id and current-thread obligations; the record lock
    // excludes every other operation on the child context.
    #[cfg(target_arch = "x86_64")]
    let (outcome, record_member) = unsafe { add_native_child_thread_source(id, binding) }?;
    #[cfg(not(target_arch = "x86_64"))]
    let (outcome, record_member) = unsafe {
        id.with_owner(|owner| match owner.as_mut() {
            Some(child) => {
                // Reserve a representable count before source admission can
                // mutate lists. Only an actual added member issues a token.
                let members = &mut *id.record().members.get();
                let next = members.checked_add(1).ok_or(NativeSubprocessError::Retained)?;
                let outcome = add_current_thread(child, binding);
                let token = if matches!(outcome, Ok(ChildThreadAddOutcome::Added(_))) {
                    *members = next;
                    Some(NativeChildRecordMember { id: Some(id) })
                } else { None };
                Ok((outcome, token))
            }
            None => Err(NativeSubprocessError::Gone),
        })
    }??;
    Ok(match outcome {
        Ok(ChildThreadAddOutcome::Added(member)) => {
            // SAFETY: current-thread slot, checked empty above.
            // A child member allocates from its own Theap; the main owner's
            // local fast-path publication no longer applies.
            #[cfg(target_arch = "x86_64")]
            crate::local_fast_path::withdraw();
            *unsafe { current_child_member() } = Some(CurrentChildMember {
                record_member: record_member.expect("actual admission issued its record token"), binding, member,
                #[cfg(target_arch = "x86_64")]
                generic_frequency_captures: 0,
                #[cfg(target_arch = "x86_64")]
                allocation_scope: core::ptr::null(),
                #[cfg(target_arch = "x86_64")]
                retained_fresh_issuer: None,
            });
            NativeChildThreadAdd::Added
        }
        Ok(ChildThreadAddOutcome::AlreadyInitialized { in_other_subprocess }) => {
            NativeChildThreadAdd::AlreadyInitialized { in_other_subprocess }
        }
        Err(ChildThreadStartFailure::Rejected(error)) => NativeChildThreadAdd::Failed(error),
        Err(ChildThreadStartFailure::Retained { owner, error }) => {
            // The actual initialization admission retains the child, and this
            // exact terminal owner retains its allocated images/registration.
            core::mem::forget(owner);
            NativeChildThreadAdd::Failed(error)
        }
    })
}

/// Finishes the current child thread (`_mi_thread_done`); see
/// [`ChildThreadMember::thread_done`]. The slot is cleared only on success.
/// Returns `None` when the thread is not a child member.
pub(crate) fn native_child_thread_done() -> Option<Result<(), NativeChildThreadDoneError>> {
    #[cfg(target_arch = "x86_64")]
    if unsafe { !(*CURRENT_CHILD_MEMBER.get()).initialization.is_null()
        || (*CURRENT_CHILD_MEMBER.get()).retained_initialization.is_some() }
    {
        return Some(Err(NativeChildThreadDoneError::Subprocess(NativeSubprocessError::Retained)));
    }
    // SAFETY: current-thread slot, no other reference live.
    let slot = unsafe { current_child_member() };
    let current = slot.as_mut()?;
    #[cfg(target_arch = "x86_64")]
    if current.generic_frequency_captures != 0
        || !current.allocation_scope.is_null() || current.retained_fresh_issuer.is_some()
    {
        return Some(Err(NativeChildThreadDoneError::Subprocess(NativeSubprocessError::Retained)));
    }
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(Err(NativeChildThreadDoneError::Subprocess(NativeSubprocessError::Closed)));
    };
    let id = current.record_member.id();
    let binding = current.binding;
    let member = &mut current.member;
    let record_member = &mut current.record_member;
    // SAFETY: this is the admitted thread; its caller has ended every use of
    // its allocations (thread exit), and the record lock excludes every
    // other context operation.
    let mut orphaned_last = None;
    let done = unsafe {
        id.with_owner(|owner| match owner.as_mut() {
            Some(child) => {
                unsafe { member.thread_done(child, binding) }
                    .map_err(NativeChildThreadDoneError::Done)?;
                // SAFETY: actual teardown succeeded under this exact record
                // lock; a failed teardown leaves the token and count intact.
                unsafe { record_member.finish_locked() }
                    .map_err(NativeChildThreadDoneError::Subprocess)?;
                Ok(())
            }
            None => {
                // The child was destroyed under this thread. Its member,
                // TLD, Theaps, and roots name released child memory.
                // SAFETY: only the retained record is touched under its lock.
                orphaned_last = Some(unsafe { record_member.finish_locked() }
                    .map_err(NativeChildThreadDoneError::Subprocess)?);
                Ok(())
            }
        })
    };
    let result = match done {
        Ok(result) => result,
        Err(error) => Err(NativeChildThreadDoneError::Subprocess(error)),
    };
    if result.is_ok() {
        if let Some(last) = orphaned_last {
            // Nothing of the destroyed child is touched: the member is
            // forgotten and the compiler-TLS roots return to their pristine
            // images before the thread's own teardown reads them.
            if let Some(current) = slot.take() {
                core::mem::forget(current);
            }
            crate::compiler_tls::reset_roots_after_destroyed_child();
            if last {
                // SAFETY: the child is gone and this was its last thread, so
                // no operation on the record can run or start.
                let _ = unsafe { free_record(id.0) };
            }
            return Some(Ok(()));
        }
        *slot = None;
    }
    Some(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeChildThreadDoneError {
    Done(ChildThreadDoneError),
    Subprocess(NativeSubprocessError),
}

/// The allocation branch of the native runtime entry points: allocates for
/// an admitted child thread through its own Theap. `None` when the current
/// thread is not a child member. Deferred-free callbacks are not invoked on
/// this route yet.
///
/// `aligned` is `None` for an ordinary `_mi_theap_malloc_zero` request and
/// `Some((alignment, offset))` for `mi_theap_malloc_zero_aligned_at`.
pub(crate) fn native_child_thread_allocate(
    request: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Option<crate::runtime_lifecycle::NativePageAllocationResult> {
    use crate::runtime_lifecycle::NativePageAllocationResult;
    // SAFETY: current-thread slot, no other reference live.
    let current = unsafe { current_child_member() }.as_mut()?;
    let binding = current.binding;
    // SAFETY: this is the admitted thread operating on its own Theap.
    let block = unsafe {
        current.member.with_page_engine(binding, |_child, engine| match (aligned, zero) {
            (None, zero) => engine.allocate(request, zero),
            (Some((alignment, offset)), true) => engine.allocate_aligned_zeroed_at(request, alignment, offset),
            (Some((alignment, offset)), false) => engine.allocate_aligned_at(request, alignment, offset),
        })
    };
    Some(match block {
        Ok(Some(block)) => NativePageAllocationResult::Allocated(block),
        Ok(None) => NativePageAllocationResult::AllocationFailed,
        Err(_) => NativePageAllocationResult::Retained,
    })
}

/// The local-free branch of the native runtime entry points: frees a block
/// of a page that the current child thread owns. `None` when the current
/// thread is not a child member.
///
/// # Safety
/// `block` is a live native allocation on a page the current thread owns.
pub(crate) unsafe fn native_child_thread_free_local(
    block: core::ptr::NonNull<u8>,
) -> Option<crate::runtime_lifecycle::NativePageFreeResult> {
    use crate::runtime_lifecycle::NativePageFreeResult;
    // SAFETY: current-thread slot, no other reference live.
    let current = unsafe { current_child_member() }.as_mut()?;
    let (id, binding) = (current.record_member.id(), current.binding);
    // SAFETY: the live block keeps its page.
    let owner_theap = unsafe { binding.page_map().lookup_live_allocation(block) }
        .ok()
        .flatten()
        .map(|allocation| unsafe { crate::types::Page::theap_at(allocation.page()) });
    if owner_theap.is_some_and(|theap| Some(theap) != current.member.theap_pointer().map(core::ptr::NonNull::as_ptr)) {
        // A page of this thread's Theap for a non-main Heap: its engine runs
        // under the record lock, as the Heap operations do.
        let owner: *mut crate::meta::ChildThreadOwner = current.member.owner_mut();
        // SAFETY: the admitted thread; the record lock excludes every other
        // context operation.
        let freed = unsafe {
            id.with_owner(|child| match child.as_mut() {
                Some(child) => crate::meta::ChildThreadOwner::free_block(owner, child, binding, block).is_ok(),
                None => false,
            })
        };
        return Some(if freed == Ok(true) { NativePageFreeResult::Freed } else { NativePageFreeResult::Retained });
    }
    // SAFETY: the admitted thread frees its own live block.
    let freed = unsafe {
        current.member.with_page_engine(binding, |_child, engine| unsafe { engine.free(block) })
    };
    Some(match freed {
        Ok(Ok(())) => NativePageFreeResult::Freed,
        Ok(Err(_)) | Err(_) => NativePageFreeResult::Retained,
    })
}

/// `mi_abandoned_page_try_reclaim` (`free.c:423-469`) of a claimed child page
/// into the current thread, when it is a member of a child and has a Theap
/// for the page's Heap; see `meta::ChildThreadOwner::reclaim_on_free`.
/// The record lock is not taken: reclaim runs no nested allocation.
pub(crate) fn native_child_reclaim_on_free(
    candidate: crate::abandoned::ReclaimOnFreeCandidate<'_, crate::single_thread::ChildMappedAbandonedPage<'static>>,
) -> crate::abandoned::ReclaimOnFreeOutcome {
    // SAFETY: current-thread slot, no other reference live.
    let Some(current) = (unsafe { current_child_member() }).as_mut() else {
        return crate::abandoned::ReclaimOnFreeOutcome::Declined;
    };
    let binding = current.binding;
    let owner: *mut crate::meta::ChildThreadOwner = current.member.owner_mut();
    // SAFETY: the admitted thread; the owner is not otherwise borrowed.
    unsafe { crate::meta::ChildThreadOwner::reclaim_on_free(owner, core::ptr::null_mut(), binding, candidate) }
}

/// Production `mi_heap_malloc(heap, size)` on the current child thread; see
/// `types::heap_registry::lifecycle::child_heap_allocate`. `None` when the
/// current thread is not a child member.
///
/// # Safety
/// `heap` is a live non-main Heap of the current thread's child.
pub(crate) unsafe fn native_child_heap_allocate(
    heap: core::ptr::NonNull<crate::types::Heap>,
    size: usize,
) -> Option<Option<core::ptr::NonNull<u8>>> {
    // SAFETY: forwarded Heap and current-thread obligations.
    unsafe { native_child_heap_allocate_variant(heap, size, None, false) }
}

/// The zeroing and offset-aligned forms of the current child's Heap
/// allocation, after the source entry has checked alignment.
///
/// # Safety
/// `heap` is a live non-main Heap of the current thread's child; `aligned`
/// contains a valid power-of-two alignment and its source offset.
pub(crate) unsafe fn native_child_heap_allocate_variant(
    heap: core::ptr::NonNull<crate::types::Heap>,
    size: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Option<Option<core::ptr::NonNull<u8>>> {
    // SAFETY: current-thread slot, no other reference live.
    let current = unsafe { current_child_member() }.as_mut()?;
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(None);
    };
    let (id, binding) = (current.record_member.id(), current.binding);
    let member = &mut current.member;
    // SAFETY: forwarded; the record lock excludes every other context operation.
    let allocated = unsafe {
        id.with_owner(|child| match child.as_mut() {
            Some(child) => crate::types::heap_registry::lifecycle::child_heap_allocate_variant(child, member, binding, heap, size, aligned, zero)
                .ok()
                .flatten(),
            None => None,
        })
    };
    Some(allocated.ok().flatten())
}

/// Allocate through this thread's already initialized child Heap Theap
/// without selecting the Heap or replacing the cached Theap.
///
/// # Safety
/// `theap` belongs to a live non-main Heap of the current child and this
/// thread's attached TLD. Its Heap and TLD remain live for the call.
pub(crate) unsafe fn native_child_theap_allocate(
    theap: core::ptr::NonNull<crate::types::Theap>,
    size: usize,
    zero: bool,
) -> Option<Option<core::ptr::NonNull<u8>>> {
    // SAFETY: forwarded current-thread Theap lifetime.
    unsafe { native_child_theap_allocate_variant(theap, size, None, zero) }
}

/// A counted option capture on the actual current child member. It owns no
/// payload projection, and failed admission or resume leaves that member
/// retained rather than making its allocator state available for retirement.
#[must_use = "resume the originating child issuer or retain its member"]
#[cfg(target_arch = "x86_64")]
struct NativeChildGenericFrequencyCapture {
    id: NativeSubprocessId,
    theap: core::ptr::NonNull<crate::types::Theap>,
}

#[cfg(target_arch = "x86_64")]
impl NativeChildGenericFrequencyCapture {
    /// # Safety
    /// The request came from this exact Theap's engine. Its actual child,
    /// member, TLD, selected Heap, and Theap remain retained for the complete
    /// synchronous allocation. No projection or lock spans the getter.
    unsafe fn begin(theap: core::ptr::NonNull<crate::types::Theap>,
        request: &crate::types::GenericAllocationFrequencyRequest) -> Option<Self>
    {
        if !request.matches_theap(theap) { return None; }
        // SAFETY: the caller is this thread and ended every engine/member
        // projection. The count prevents its slot from being finished or replaced.
        let current = unsafe { current_child_member() }.as_mut()?;
        current.generic_frequency_captures = current.generic_frequency_captures.checked_add(1)?;
        Some(Self { id: current.record_member.id(), theap })
    }

    /// # Safety
    /// The source getter ended and the originating engine completed its
    /// short resume with this request. The actual member was not replaced.
    unsafe fn complete(self) -> bool {
        // SAFETY: the retained capture excludes thread finish; no callback
        // or engine projection is live during this field-only settlement.
        let Some(current) = unsafe { current_child_member() }.as_mut() else { return false; };
        if current.record_member.id() != self.id || current.generic_frequency_captures == 0 { return false; }
        current.generic_frequency_captures -= 1;
        true
    }
}

/// A real child source admission acquired while the original READY owner
/// is held. The actual member owns its issuing TLD/Theap; the child lease
/// retains its context and source registration independently of projections.
#[cfg(target_arch = "x86_64")]
struct NativeChildOriginalIssuer {
    id: NativeSubprocessId,
    theap: core::ptr::NonNull<crate::types::Theap>,
    heap: core::ptr::NonNull<crate::types::Heap>,
    _child: NativeChildCallbackLease,
    _operation: crate::runtime_lifecycle::NativeSubprocessOperation,
}

/// Terminal original custody, including a task that a refused engine could
/// not take. A marker can refuse teardown but never replaces this admission.
#[cfg(target_arch = "x86_64")]
struct NativeChildRetainedFreshIssuer {
    issuer: NativeChildOriginalIssuer,
    _task: Option<crate::single_thread::PendingFreshOsPageInitialization>,
}

/// A stack-pinned synchronous selected-issuer scope. Linked scopes allow
/// nested allocation on the same or another Heap without a capacity bound.
#[cfg(target_arch = "x86_64")]
struct NativeChildAllocationScope {
    issuer: Option<NativeChildOriginalIssuer>,
    previous: *const Self,
    installed: bool,
    _pin: core::marker::PhantomPinned,
}

#[cfg(target_arch = "x86_64")]
impl NativeChildAllocationScope {
    unsafe fn issuer_at(scope: core::ptr::NonNull<Self>)
        -> (core::ptr::NonNull<crate::types::Theap>, core::ptr::NonNull<crate::types::Heap>) {
        // SAFETY: the original stack owner keeps this scope pinned; this short
        // issuer projection ends before any callback or source operation.
        let issuer = unsafe { &*core::ptr::addr_of!((*scope.as_ptr()).issuer) }
            .as_ref().expect("the active scope retains its original issuer");
        (issuer.theap, issuer.heap)
    }

    unsafe fn retain_at(scope: core::ptr::NonNull<Self>, task: Option<crate::single_thread::PendingFreshOsPageInitialization>) {
        // SAFETY: no projection or callback is live; the scope excludes this
        // member's finish and replacement. Its exact admission moves once.
        let current = unsafe { current_child_member() }.as_mut().expect("the admitted member is retained");
        assert!(current.retained_fresh_issuer.is_none());
        assert_eq!(current.record_member.id(), unsafe { &*core::ptr::addr_of!((*scope.as_ptr()).issuer) }
            .as_ref().expect("one original issuer").id);
        current.retained_fresh_issuer = Some(NativeChildRetainedFreshIssuer {
            issuer: unsafe { &mut *core::ptr::addr_of_mut!((*scope.as_ptr()).issuer) }
                .take().expect("one original issuer"), _task: task,
        });
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for NativeChildAllocationScope {
    fn drop(&mut self) {
        if !self.installed { return; }
        // SAFETY: the pinned scope is current-thread-only and synchronous;
        // nested scopes ended first and no member projection remains live.
        let current = unsafe { current_child_member() }.as_mut().expect("the scope retains its member");
        assert_eq!(current.allocation_scope, core::ptr::from_ref(self));
        current.allocation_scope = self.previous;
    }
}

/// # Safety
/// The original READY owner was acquired before any candidate. Its caller
/// retains the actual selected Heap, Theap and member through this scope;
/// pointer checks only refuse a different original issuer.
#[cfg(target_arch = "x86_64")]
unsafe fn with_native_child_allocation_scope<R>(
    owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
    operation: impl FnOnce(core::ptr::NonNull<NativeChildAllocationScope>) -> R,
) -> Result<R, NativeChildAllocationRefusal> {
    let theap = owner.selected_theap();
    // SAFETY: this original owner retains the initialized selected Theap.
    let heap = core::ptr::NonNull::new(unsafe { crate::types::Theap::heap_at(theap) })
        .ok_or(NativeChildAllocationRefusal::Retained)?;
    let (id, main_theap) = {
        // SAFETY: a short projection of the actual current member, before
        // any source callback or candidate; no reference escapes this block.
        let current = unsafe { current_child_member() }.as_ref().ok_or(NativeChildAllocationRefusal::Unavailable)?;
        if current.retained_fresh_issuer.is_some() { return Err(NativeChildAllocationRefusal::Retained); }
        (current.record_member.id(), current.member.theap_pointer().ok_or(NativeChildAllocationRefusal::Unavailable)?)
    };
    if unsafe { crate::types::Theap::tld_at(theap) != crate::types::Theap::tld_at(main_theap) } {
        return Err(NativeChildAllocationRefusal::Retained);
    }
    let admitted_operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
        .ok_or(NativeChildAllocationRefusal::Retained)?;
    // SAFETY: the original READY child lease already retains this exact
    // record and registration. The short record lock verifies its original
    // context before acquiring independent actual custody, without callbacks.
    let child = unsafe { id.with_owner(|child| {
        let child = child.as_mut()?;
        if child.identity_pointer()? != owner.process().subprocess() as *const _ as *mut _ { return None; }
        let record = id.record();
        record.callback_leases.fetch_update(core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed, |value| value.checked_add(1)).ok()?;
        Some(NativeChildCallbackLease(id.0))
    }) }.map_err(|_| NativeChildAllocationRefusal::Retained)?.ok_or(NativeChildAllocationRefusal::Retained)?;
    let mut scope = core::pin::pin!(NativeChildAllocationScope {
        issuer: Some(NativeChildOriginalIssuer { id, theap, heap, _child: child, _operation: admitted_operation }),
        previous: core::ptr::null(), installed: false, _pin: core::marker::PhantomPinned,
    });
    // SAFETY: the stack pin keeps the intrusive current-thread link stable.
    // The operation may change custody fields but never moves this scope.
    let scope = unsafe { scope.as_mut().get_unchecked_mut() };
    let current = unsafe { current_child_member() }.as_mut().ok_or(NativeChildAllocationRefusal::Retained)?;
    scope.previous = current.allocation_scope;
    current.allocation_scope = core::ptr::from_ref(scope);
    scope.installed = true;
    let original = core::ptr::NonNull::from(scope);
    // No scope or member projection survives the callback. Its original stack
    // owner retains the pin while the driver uses only short field operations.
    Ok(operation(original))
}

/// Source request selected before entering an exact child Theap engine.
/// Canonical guarded requests enter the counted generic path directly.
enum NativeChildAllocationRequest {
    Ordinary { size: usize, aligned: Option<(usize, usize)>, zero: bool },
    #[cfg(target_arch = "x86_64")]
    GuardedCanonical { source_size: usize },
}

enum NativeChildAllocationRefusal {
    Unavailable,
    Retained,
}

/// Direct ordinary or aligned allocation on a retained non-main child
/// Theap. The default and cached roots keep their existing selection.
///
/// # Safety
/// `theap` is linked to a live Heap of the calling child's attached TLD;
/// alignment, when present, has passed the source precheck. The caller
/// retains that exact member, Heap, TLD, and Theap throughout any synchronous
/// getter or allocation callback and the resumed allocation; nested callbacks
/// cannot retire or replace those selected issuers.
pub(crate) unsafe fn native_child_theap_allocate_variant(
    theap: core::ptr::NonNull<crate::types::Theap>,
    size: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Option<Option<core::ptr::NonNull<u8>>> {
    if !current_thread_is_child_member() { return None; }
    // SAFETY: forwarded exact issuer retention and source geometry obligations.
    match unsafe { native_child_theap_allocate_request(theap,
        NativeChildAllocationRequest::Ordinary { size, aligned, zero }) }
    {
        Ok(block) => Some(block),
        Err(NativeChildAllocationRefusal::Unavailable) => None,
        Err(NativeChildAllocationRefusal::Retained) => Some(None),
    }
}

/// Allocates the exact padded, OS-page-rounded canonical guarded extent on
/// the current child's already selected main or non-main Theap. Admission or
/// continuation refusal is distinct from a completed source allocation miss.
///
/// # Safety
/// The original native allocation owner was admitted before this attempt.
/// The caller retains that exact child member, Heap, TLD, and Theap through
/// every getter/callback and continuation; none may be retired or replaced.
/// `source_size` passed the source guarded geometry checks. This returns no
/// diagnostic authority and manufactures no allocation-owner admission.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn native_child_theap_allocate_guarded_canonical(
    theap: core::ptr::NonNull<crate::types::Theap>,
    source_size: usize,
) -> crate::runtime_lifecycle::NativeGuardedCanonicalAllocationProgress {
    use crate::runtime_lifecycle::NativeGuardedCanonicalAllocationProgress as Progress;
    if !current_thread_is_child_member() { return Progress::OtherDomain; }
    if !crate::config::GUARDED { return Progress::Refused; }
    // SAFETY: forwarded original admission and exact selected issuer custody.
    match unsafe { native_child_theap_allocate_request(theap,
        NativeChildAllocationRequest::GuardedCanonical { source_size }) }
    {
        Ok(block) => Progress::Complete(block),
        Err(_) => Progress::Refused,
    }
}

/// Runs one source request without projecting an owner or engine across a
/// callback. Each resume uses the same member's exact selected source engine.
///
/// # Safety
/// The caller retains the exact selected member, Heap, TLD, and Theap for
/// the whole operation, including getters/callbacks and resumed allocation.
unsafe fn native_child_theap_allocate_request(
    theap: core::ptr::NonNull<crate::types::Theap>,
    request: NativeChildAllocationRequest,
) -> Result<Option<core::ptr::NonNull<u8>>, NativeChildAllocationRefusal> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the caller retains its actual initialized member and selected
        // Heap, TLD and Theap. READY admission precedes the candidate and stays
        // live through every callback, source observation and terminal outcome.
        return unsafe { crate::runtime_lifecycle::with_native_allocation_owner(theap, |owner| {
            with_native_child_allocation_scope(&owner, |scope| {
                native_child_theap_allocate_request_in_owner(theap, request, &owner, scope)
            })?
        }) }.map_err(|_| NativeChildAllocationRefusal::Retained)?;
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe { native_child_theap_allocate_request_in_owner(theap, request) }
}

/// Captures phase custody before the original short engine finishes. A late
/// outer failure cannot erase an unfinished original task returned inside it.
///
/// # Safety
/// The caller continuously retains the exact issuing member, Heap, TLD and
/// Theap; no callback or projection spans this engine operation.
unsafe fn with_native_child_allocation_phase(
    theap: core::ptr::NonNull<crate::types::Theap>,
    operation: impl for<'session, 'image> FnOnce(
        &mut crate::single_thread::ChildOrdinaryPageAllocator<'session, 'image, 'static>,
    ) -> Result<crate::single_thread::DeferredFreeAllocationPhase, NativeChildAllocationRefusal>,
) -> Result<crate::single_thread::DeferredFreeAllocationPhase, NativeChildAllocationRefusal> {
    let mut phase = None;
    let entered = unsafe { with_native_child_heap_theap_engine(theap, |engine| {
        phase = Some(operation(engine));
    }) }.is_some();
    match phase {
        #[cfg(target_arch = "x86_64")]
        Some(Ok(crate::single_thread::DeferredFreeAllocationPhase::FreshInitialization(task))) =>
            Ok(crate::single_thread::DeferredFreeAllocationPhase::FreshInitialization(task)),
        Some(result) if entered => result,
        _ => Err(NativeChildAllocationRefusal::Unavailable),
    }
}

/// Drives the source phases under the actual original admission acquired
/// before the candidate. This path never creates a startup metadata witness.
///
/// # Safety
/// The caller retains the actual selected member, Heap, TLD and Theap for
/// this complete synchronous operation; every short projection ends before
/// callbacks. On x86 the supplied READY owner was admitted before allocation.
unsafe fn native_child_theap_allocate_request_in_owner(
    theap: core::ptr::NonNull<crate::types::Theap>,
    request: NativeChildAllocationRequest,
    #[cfg(target_arch = "x86_64")] owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
    #[cfg(target_arch = "x86_64")] scope: core::ptr::NonNull<NativeChildAllocationScope>,
) -> Result<Option<core::ptr::NonNull<u8>>, NativeChildAllocationRefusal> {
    use crate::single_thread::{DeferredFreeAllocationPhase, GenericAllocationCollection};
    #[cfg(target_arch = "x86_64")]
    let canonical = matches!(&request, NativeChildAllocationRequest::GuardedCanonical { .. });
    #[cfg(not(target_arch = "x86_64"))]
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
        .ok_or(NativeChildAllocationRefusal::Retained)?;
    // SAFETY: forwarded exact current-thread Theap lifetime. Each engine
    // projection ends before a deferred-free callback can reenter allocation.
    let mut phase = unsafe { with_native_child_allocation_phase(theap, |engine| match request {
        NativeChildAllocationRequest::Ordinary { size, aligned, zero } => Ok::<_, NativeChildAllocationRefusal>(match aligned {
            None => engine.begin_deferred_free_allocation(size, zero),
            Some((alignment, offset)) => engine.begin_deferred_free_aligned_allocation_at(size, alignment, offset, zero),
        }),
        #[cfg(target_arch = "x86_64")]
        NativeChildAllocationRequest::GuardedCanonical { source_size } =>
            engine.begin_deferred_free_guarded_canonical_checked(source_size)
                .map_err(|_| NativeChildAllocationRefusal::Retained),
    }) }?;
    loop {
        match phase {
            DeferredFreeAllocationPhase::Complete(block) => return Ok(block),
            #[cfg(target_arch = "x86_64")]
            DeferredFreeAllocationPhase::FreshInitialization(task) => {
                let (original_theap, heap) = unsafe { NativeChildAllocationScope::issuer_at(scope) };
                if original_theap != theap || !task.matches_theap(original_theap) {
                    unsafe { NativeChildAllocationScope::retain_at(scope, Some(task)) };
                    return Err(NativeChildAllocationRefusal::Retained);
                }
                #[cfg(any(feature = "mi-debug-1", feature = "mi-debug-2", feature = "mi-debug-3"))]
                let task = if matches!(task.failure(), crate::single_thread::FreshOsPageInitializationFailure::SourceObservation(_)) {
                    // SAFETY: the actual READY owner predates this candidate;
                    // all engine/member projections and locks ended. The task
                    // still retains its original registration and backing.
                    match unsafe { task.dispatch(owner) } {
                        Ok(never) => match never {},
                        Err(mut task) => {
                            // SAFETY: this actual original admission moves the
                            // one unfinished task into its persistent member
                            // slot before the outer owner ends. A mark error
                            // can follow publication; custody remains retained.
                            let _ = unsafe { task.ensure_retirement_refusal(theap, heap) };
                            unsafe { NativeChildAllocationScope::retain_at(scope, Some(task)) };
                            return Err(NativeChildAllocationRefusal::Retained);
                        }
                    }
                } else { task };
                let mut pending = Some(task);
                let mut retained = false;
                // SAFETY: this same actual original owner still retains its
                // issuer. The external task slot survives both cleanup refusal
                // and any later outer engine-finish failure.
                let _ = unsafe { with_native_child_heap_theap_engine(theap, |engine| {
                    let task = pending.take().expect("one original fresh task");
                    match unsafe { engine.cleanup_fresh_os_initialization(task) } {
                        Ok(()) => {},
                        Err(task) => {
                            retained = true;
                            if let Err(task) = engine.retain_fresh_os_initialization(task) {
                                pending = Some(task);
                            }
                        }
                    }
                }) };
                if retained || pending.is_some() {
                    if pending.is_some() {
                        // SAFETY: this member accepts the exact unconsumed
                        // original task. Engine Drop did not transfer it to
                        // a session slot, so this is its sole marker publisher.
                        // A mark error never drops task or issuer custody.
                        let _ = unsafe { pending.as_mut().expect("one unaccepted original task")
                            .ensure_retirement_refusal(theap, heap) };
                    }
                    // Engine Drop marks and transfers an accepted task into
                    // its original persistent slot. An unaccepted task moves
                    // with this actual member's retained admission. Neither
                    // path guesses ownership from the marker or replays free.
                    unsafe { NativeChildAllocationScope::retain_at(scope, pending) };
                    return Err(NativeChildAllocationRefusal::Retained);
                }
                // Cleanup consumed the task before any later finish error.
                // An OS release retry remains with its existing source owner;
                // it must not recreate or mark an unfinished metadata task.
                return Err(NativeChildAllocationRefusal::Retained);
            }
            #[cfg(target_arch = "x86_64")]
            DeferredFreeAllocationPhase::GenericFrequency { request, continuation } => {
                // SAFETY: the originating engine projection ended above. The
                // public call retains the exact selected Heap, Theap and member.
                let capture = unsafe { NativeChildGenericFrequencyCapture::begin(theap, &request) }.ok_or(NativeChildAllocationRefusal::Unavailable)?;
                // SAFETY: that actual retained issuer keeps its immutable Heap
                // publication live; pointer equality is only an admission check.
                let heap = core::ptr::NonNull::new(unsafe { crate::types::Theap::heap_at(capture.theap) }).ok_or(NativeChildAllocationRefusal::Unavailable)?;
                let frequency = loop {
                    // SAFETY: no member/engine projection or allocator lock
                    // spans this getter. The counted record lease retains the
                    // actual child owner, and the member count excludes finish.
                    match unsafe { try_with_native_child_callback_owner(heap, |process| {
                        process.policy().generic_collect_frequency()
                    }) } {
                        Ok(frequency) => break frequency,
                        Err(NativeChildCallbackAdmissionError::Busy) => core::hint::spin_loop(),
                        Err(NativeChildCallbackAdmissionError::Invalid) => return Err(NativeChildAllocationRefusal::Retained),
                    }
                };
                // SAFETY: the capture retained the same actual member and the
                // caller retained its selected Heap/Theap throughout the getter.
                // A fresh short engine resumes the originating request only.
                let resumed = unsafe { with_native_child_allocation_phase(capture.theap, |engine| {
                    if canonical {
                        unsafe { engine.resume_guarded_canonical_frequency_checked(request, frequency, continuation) }
                            .map_err(|_| NativeChildAllocationRefusal::Retained)
                    } else {
                        Ok(unsafe { engine.resume_generic_allocation_frequency(request, frequency, continuation) })
                    }
                }) }?;
                // SAFETY: the getter and fresh engine projection both ended;
                // the request was consumed by that exact admitted issuer.
                if !unsafe { capture.complete() } { return Err(NativeChildAllocationRefusal::Retained); }
                phase = resumed;
            }
            DeferredFreeAllocationPhase::Collect { collection, continuation } => {
                // SAFETY: the caller retains this Theap and its attached TLD
                // throughout the synchronous callback and resumed operation.
                let tld = core::ptr::NonNull::new(unsafe { crate::types::Theap::tld_at(theap) }).ok_or(NativeChildAllocationRefusal::Unavailable)?;
                let force = matches!(collection, GenericAllocationCollection::Force);
                if let Ok(invocation) = crate::deferred_free::begin_process(theap, tld, force) {
                    let _ = unsafe { crate::__crabc_runtime::with_native_allocator_callback_boundary(|| unsafe { invocation.invoke() }) };
                }
                phase = unsafe { with_native_child_allocation_phase(theap, |engine| {
                    #[cfg(target_arch = "x86_64")]
                    if canonical {
                        return engine.resume_deferred_free_guarded_canonical_checked(collection, continuation)
                            .map_err(|_| NativeChildAllocationRefusal::Retained);
                    }
                    Ok::<_, NativeChildAllocationRefusal>(engine.resume_deferred_free_allocation(collection, continuation))
                }) }?;
            }
        }
    }
}

/// Borrow only the current member's exact selected child Theap engine for one
/// operation; no child-record or engine projection escapes this call.
///
/// # Safety
/// The Theap belongs to this thread's attached child TLD and live Heap. The
/// caller retains both against destruction and invokes no callback while
/// the projection is held.
unsafe fn with_native_child_heap_theap_engine<R>(
    theap: core::ptr::NonNull<crate::types::Theap>,
    operation: impl for<'session, 'image> FnOnce(
        &mut crate::single_thread::ChildOrdinaryPageAllocator<'session, 'image, 'static>,
    ) -> R,
) -> Option<R> {
    #[cfg(target_arch = "x86_64")]
    if unsafe { (*CURRENT_CHILD_MEMBER.get()).retained_initialization.is_some() } { return None; }
    // SAFETY: the current thread alone accesses its membership slot.
    let current = (unsafe { current_child_member() }).as_mut()?;
    let (id, binding) = (current.record_member.id(), current.binding);
    let main_theap = current.member.theap_pointer()?;
    let owner = current.member.owner_mut() as *mut crate::meta::ChildThreadOwner;
    // SAFETY: the caller retains this Theap; the current owner retains its TLD.
    let heap = core::ptr::NonNull::new(unsafe { crate::types::Theap::heap_at(theap) })?;
    let same_tld = unsafe { crate::types::Theap::tld_at(theap) == crate::types::Theap::tld_at(main_theap) };
    if !same_tld { return None; }
    // SAFETY: the record lock excludes concurrent child context operations.
    let result = unsafe {
        id.with_owner(|child| match child.as_mut() {
            Some(child) => {
                let same_child = child.identity_pointer().is_some_and(|identity| {
                    heap.as_ref().subprocess_pointer() == identity
                });
                if !same_child { return None; }
                if child.main_heap_pointer() == Some(heap) {
                    if theap != main_theap { return None; }
                    // SAFETY: the actual current member retains this fixed
                    // main Theap; no callback crosses the short projection.
                    return (*owner).with_page_engine(binding, |_image, engine| operation(engine)).ok();
                }
                crate::meta::ChildThreadOwner::with_heap_theap_page_engine(
                    owner, child, binding, theap, operation,
                )
                .ok()
            }
            None => None,
        })
    };
    result.ok().flatten()
}

/// Returns one captured canonical client through its original child issuer.
/// `None` identifies a non-child current domain. Inner consumption is settled
/// before a later engine-finish failure can erase the operation's outcome.
///
/// # Safety
/// The original allocation owner predates the canonical attempt and retains
/// the exact selected member, Heap, TLD, Theap, and live captured allocation
/// through this callback-free cleanup. A consumed client is never retried or
/// returned as live, even when the final lifecycle result is an error.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn native_child_theap_free_captured_with_progress(
    theap: core::ptr::NonNull<crate::types::Theap>,
    allocation: crate::process_page_map::LiveAllocationPointer,
) -> Option<crate::single_thread::LocalClientFreeProgress> {
    use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
    if !current_thread_is_child_member() { return None; }
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(Progress::RefusedBeforeConsumption(FreeError::Lifecycle));
    };
    let mut progress = None;
    // SAFETY: the original owner retains the captured canonical client and
    // exact selected issuer; the engine borrows no payload across callbacks.
    let finished = unsafe { with_native_child_heap_theap_engine(theap, |engine| {
        progress = Some(unsafe { engine.free_captured_live_allocation_with_progress(allocation) });
    }) }.is_some();
    Some(match progress {
        Some(Progress::Consumed(Ok(()))) if !finished =>
            Progress::Consumed(Err(FreeError::Lifecycle)),
        Some(progress) => progress,
        None => Progress::RefusedBeforeConsumption(FreeError::Lifecycle),
    })
}

/// Retains a failed original auxiliary image and poisons its actual member
/// before ending the initializer's callback scope. No image is reselected.
#[cfg(target_arch = "x86_64")]
unsafe fn retain_native_child_heap_initializer(
    scope: core::ptr::NonNull<NativeChildInitializationScope>,
    id: NativeSubprocessId,
    failure: crate::meta::ChildHeapTheapInitializationFailure,
) {
    // SAFETY: the actual scope excludes finish/replacement of this member;
    // no allocator projection or callback survives this short settlement.
    if let Some(current) = unsafe { current_child_member() }.as_mut() {
        if current.record_member.id() == id {
            let retained = current.member.owner_mut().retain_heap_theap_initialization_failure(&failure);
            debug_assert!(retained, "the failure keeper belongs to its original member");
        }
    }
    core::mem::forget(failure);
    unsafe { NativeChildInitializationScope::retain_at(scope) };
}

/// # Safety
/// The selected Heap and this thread's actual member/TLD remain retained
/// across preparation, callbacks, and completion of the same owned ticket.
#[cfg(target_arch = "x86_64")]
unsafe fn native_child_heap_theap_source(
    heap: core::ptr::NonNull<crate::types::Heap>,
) -> Option<core::ptr::NonNull<crate::types::Theap>> {
    if unsafe { (*CURRENT_CHILD_MEMBER.get()).retained_initialization.is_some() } { return None; }
    let (id, binding) = {
        let current = unsafe { current_child_member() }.as_ref()?;
        (current.record_member.id(), current.binding)
    };
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let main = unsafe { id.with_owner(|owner| {
        let child = owner.as_mut()?;
        if child.identity_pointer() != Some(crate::types::Heap::subprocess_pointer_at(heap)) { return None; }
        Some(child.main_heap_pointer() == Some(heap))
    }) }.ok().flatten()?;
    if main {
        return unsafe { id.with_owner(|owner| {
            let child = owner.as_mut()?;
            let current = current_child_member().as_mut()?;
            if current.record_member.id() != id { return None; }
            let owner = current.member.owner_mut();
            let base = owner.theap_pointer()?;
            if crate::compiler_tls::fast_slot_peek().map(|slot| slot.cast::<Theap>()) != Some(base)
                || crate::types::Theap::heap_at(base) != heap.as_ptr() { return None; }
            owner.cached_set(child, binding, base).ok()?;
            Some(base)
        }) }.ok().flatten();
    }
    unsafe { with_native_child_initialization_scope(id, heap, |scope| {
        let mut selection = None;
        let entered = unsafe { id.with_owner(|owner| {
            let Some(child) = owner.as_mut() else { return; };
            let Some(current) = current_child_member().as_mut() else { return; };
            if current.record_member.id() != id { return; }
            selection = Some(current.member.owner_mut().prepare_heap_theap_selection(child, binding, heap));
        }) };
        if entered.is_err() {
            if let Some(Ok(selection)) = selection.take() {
                let failure = match selection {
                    crate::meta::ChildHeapTheapSelection::Pending(pending) => Some(pending.into_phase().0.retain_refusal()),
                    crate::meta::ChildHeapTheapSelection::Retained(failure) => Some(failure),
                    crate::meta::ChildHeapTheapSelection::Existing(_) => None,
                };
                if let Some(failure) = failure {
                    unsafe { retain_native_child_heap_initializer(scope, id, failure) };
                    return None;
                }
            }
            unsafe { NativeChildInitializationScope::retain_at(scope) };
            return None;
        }
        let pending = match selection?.ok()? {
            crate::meta::ChildHeapTheapSelection::Existing(theap) => return Some(theap),
            crate::meta::ChildHeapTheapSelection::Pending(pending) => pending,
            crate::meta::ChildHeapTheapSelection::Retained(failure) => {
                unsafe { retain_native_child_heap_initializer(scope, id, failure) };
                return None;
            }
        };
        let (keeper, phase) = pending.into_phase();
        let ready = match unsafe { initialize_native_child_theap_source(scope, phase) } {
            Ok(ready) => ready,
            Err(error) => {
                unsafe { retain_native_child_heap_initializer(scope, id, keeper.retain(error)) };
                return None;
            }
        };
        let mut original = Some((keeper, ready));
        let mut completed = None;
        let finished = unsafe { id.with_owner(|owner| {
            let Some(child) = owner.as_mut() else { return; };
            let Some(current) = current_child_member().as_mut() else { return; };
            if current.record_member.id() != id { return; }
            let (keeper, ready) = original.take().expect("original initializer consumed once");
            completed = Some(current.member.owner_mut().complete_heap_theap_initialization(child, binding, keeper, ready));
        }) };
        if let Some((keeper, _ready)) = original {
            unsafe { retain_native_child_heap_initializer(scope, id, keeper.retain_refusal()) };
            return None;
        }
        match completed {
            Some(Ok(theap)) if finished.is_ok() => Some(theap),
            Some(Err(failure)) => {
                unsafe { retain_native_child_heap_initializer(scope, id, failure) };
                None
            }
            Some(Ok(_)) | None => {
                // Publication may have completed before the outer unlock
                // failed. Retain actual admission; never replay the keeper.
                unsafe { NativeChildInitializationScope::retain_at(scope) };
                None
            }
        }
    }) }.ok().flatten()
}

/// Resolve the current child thread's Theap for a live Heap. The child main
/// Heap keeps its fixed-slot Theap; a non-main Heap may create a per-thread
/// Theap. Both paths publish the selected Theap in the cache.
///
/// # Safety
/// `heap` is a live Heap held against destruction for the call. A Heap of a
/// different subprocess is refused without selecting or creating a Theap.
pub(crate) unsafe fn native_child_heap_theap(
    heap: core::ptr::NonNull<crate::types::Heap>,
) -> Option<core::ptr::NonNull<crate::types::Theap>> {
    #[cfg(target_arch = "x86_64")]
    { return unsafe { native_child_heap_theap_source(heap) }; }
    #[cfg(not(target_arch = "x86_64"))]
    {
    // SAFETY: the current thread alone accesses its membership slot.
    let current = (unsafe { current_child_member() }).as_mut()?;
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let (id, binding) = (current.record_member.id(), current.binding);
    let member = &mut current.member;
    // SAFETY: the child record lock excludes another context operation,
    // and the current thread owns its Theap and dynamic local slot.
    let selected = unsafe {
        id.with_owner(|child| match child.as_mut() {
            Some(child) => {
                // A Heap from another subprocess must not publish a Theap
                // into this member's dynamic local slot.
                let same_child = child.identity_pointer().is_some_and(|identity| {
                    heap.as_ref().subprocess_pointer() == identity
                });
                if !same_child {
                    return None;
                }
                let owner = member.owner_mut();
                if child.main_heap_pointer() == Some(heap) {
                    let base = owner.theap_pointer()?;
                    // SAFETY: the owner retains its fixed Theap while the
                    // child record and current-thread slot are held.
                    if crate::compiler_tls::fast_slot_peek().map(|slot| slot.cast::<crate::types::Theap>()) != Some(base)
                        || unsafe { crate::types::Theap::heap_at(base) } != heap.as_ptr()
                    {
                        return None;
                    }
                    // SAFETY: this thread owns the fixed Theap and cache.
                    unsafe { owner.cached_set(child, binding, base) }.ok()?;
                    Some(base)
                } else {
                    // SAFETY: the checked Heap is live in this child.
                    unsafe { owner.heap_theap(child, binding, heap) }.ok()
                }
            }
            None => None,
        })
    };
    selected.ok().flatten()
    }
}

/// Collect an exact live Theap of this child member without resolving its
/// Heap's cached selector. The source callback runs before any owner or
/// child-record projection is borrowed.
///
/// # Safety
/// `theap` belongs to this thread's attached child TLD and live Heap,
/// retained against destruction for the complete synchronous collection.
pub(crate) unsafe fn native_child_theap_collect(
    theap: core::ptr::NonNull<crate::types::Theap>,
    force: bool,
) {
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return };
    // SAFETY: caller retains the initialized Theap and its current TLD.
    let Some(tld) = core::ptr::NonNull::new(unsafe { crate::types::Theap::tld_at(theap) }) else { return };
    if let Ok(invocation) = crate::deferred_free::begin_process(theap, tld, force) {
        // SAFETY: no child or engine reference survives across user code.
        let _ = unsafe { crate::__crabc_runtime::with_native_allocator_callback_boundary(|| unsafe { invocation.invoke() }) };
    }
    // SAFETY: only the current thread accesses its member slot.
    let Some(current) = (unsafe { current_child_member() }).as_mut() else { return };
    let (id, binding) = (current.record_member.id(), current.binding);
    let Some(main) = current.member.theap_pointer() else { return };
    if unsafe { crate::types::Theap::tld_at(main) } != tld.as_ptr() { return; }
    let collection = if force {
        crate::single_thread::GenericAllocationCollection::Force
    } else {
        crate::single_thread::GenericAllocationCollection::Full
    };
    let collect = |engine: &mut crate::single_thread::ChildOrdinaryPageAllocator<'_, '_, 'static>| {
        engine.resume_deferred_free_allocation(collection, crate::single_thread::DeferredFreeAllocationContinuation::Collection)
    };
    let owner = current.member.owner_mut() as *mut crate::meta::ChildThreadOwner;
    if theap == main {
        // SAFETY: the current member owns its fixed main Theap exclusively.
        let _ = unsafe { (*owner).with_page_engine(binding, |_image, engine| collect(engine)) };
    } else {
        // SAFETY: the caller retains the member's non-main Theap and child;
        // the child-record lock excludes concurrent context mutation.
        let _ = unsafe { id.with_owner(|child| {
            if let Some(child) = child.as_mut() {
                let _ = crate::meta::ChildThreadOwner::with_heap_theap_page_engine(
                    owner, child, binding, theap, collect,
                );
            }
        }) };
    }
}

/// Select the current child thread's Theap for a live Heap.
///
/// # Safety
/// The Heap remains live through the selection and is not destroyed
/// concurrently. A Heap of another subprocess is refused.
pub(crate) unsafe fn native_child_heap_select_theap(heap: core::ptr::NonNull<crate::types::Heap>) -> bool {
    // SAFETY: forwarded Heap and current-thread obligations.
    unsafe { native_child_heap_theap(heap) }.is_some()
}

/// Frees a block on a page of a child subprocess's main Heap that the
/// current thread does not own (`mi_free_block_mt` with collection); see
/// `single_thread::free_child_page_block_nonlocal`. `None` when the block's
/// page belongs to the process main subprocess.
///
/// # Safety
/// `allocation` is an exact live allocation observed through `binding`'s
/// PageMap, and its child is not destroyed during the call.
pub(crate) unsafe fn free_child_block_nonlocal(
    binding: ProcessMainBackingBinding,
    allocation: crate::process_page_map::LiveAllocationPointer,
    reclaim: impl FnOnce(
        crate::abandoned::ReclaimOnFreeCandidate<'_, crate::single_thread::ChildMappedAbandonedPage<'static>>,
    ) -> crate::abandoned::ReclaimOnFreeOutcome,
) -> Option<crate::single_thread::ChildNonlocalFreeResult> {
    use crate::single_thread::ChildNonlocalFreeResult;
    // SAFETY: the live block keeps its page and Heap alive.
    let (heap, identity) = unsafe { crate::types::Heap::child_heap_of_page(allocation.page()) }?;
    // `ChildSubprocessImage` is `repr(C)` with its identity first, and the
    // live block keeps its child allocated for the call.
    // SAFETY: as above; the image is pinned in its parent metadata block.
    let child = unsafe { core::pin::Pin::new_unchecked(&*identity.as_ptr().cast::<crate::subproc::ChildSubprocessImage>()) };
    let Ok(child_process) = crate::os::ChildVmProcess::new(binding.process(), child) else {
        return Some(ChildNonlocalFreeResult::Refused);
    };
    let Ok(pair) = crate::process_arena::ChildProcessPageArenaLease::join(binding.page_map(), child_process) else {
        return Some(ChildNonlocalFreeResult::Refused);
    };
    // SAFETY: this free touches only the PageMap range of the one page that
    // its publication claims, as a child page engine does for its own pages.
    let Ok(page_map) = (unsafe { pair.page_map_for_owned_ranges() }) else {
        return Some(ChildNonlocalFreeResult::Refused);
    };
    let backing = crate::page_backing::ChildMetadataArenaBacking::new(pair);
    // SAFETY: forwarded; `backing` pairs this child's arenas with `page_map`.
    Some(unsafe { crate::single_thread::free_child_page_block_nonlocal(allocation, page_map, &backing, heap, reclaim) })
}

/// Production `mi_heap_new` on the current child thread; see
/// `types::heap_registry::lifecycle::child_heap_new`. `None` when the
/// current thread is not a child member.
pub(crate) fn native_child_heap_new() -> Option<
    Result<
        Result<core::ptr::NonNull<crate::types::Heap>, crate::types::heap_registry::lifecycle::HeapNewError>,
        NativeSubprocessError,
    >,
> {
    native_child_heap_new_in_arena(crate::arena::ArenaId::none())
}

/// Source `mi_heap_new_in_arena` on the current child member. A selected
/// parent must belong to that child; the record lock retains its identity
/// during Heap publication.
pub(crate) fn native_child_heap_new_in_arena(arena: crate::arena::ArenaId) -> Option<
    Result<
        Result<core::ptr::NonNull<crate::types::Heap>, crate::types::heap_registry::lifecycle::HeapNewError>,
        NativeSubprocessError,
    >,
> {
    // SAFETY: current-thread slot, no other reference live.
    let current = unsafe { current_child_member() }.as_mut()?;
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(Err(NativeSubprocessError::Closed));
    };
    let (id, binding) = (current.record_member.id(), current.binding);
    let member = &mut current.member;
    let keys = crate::types::heap_registry::lifecycle::HeapKeySource::global();
    // SAFETY: this is the admitted thread; the record lock excludes every
    // other context operation, in place of source `heaps_lock`.
    Some(unsafe {
        id.with_owner(|owner| match owner.as_mut() {
            Some(child) => {
                let owned = child.identity_pointer().is_some_and(|identity| {
                    arena.as_ptr().is_null() || unsafe { (*arena.as_ptr()).subprocess == identity }
                });
                if !owned {
                    return Ok(Err(crate::types::heap_registry::lifecycle::HeapNewError::InvalidChild));
                }
                Ok(crate::types::heap_registry::lifecycle::child_heap_new_in_arena(
                    child, member, binding, keys, arena,
                ))
            }
            None => Err(NativeSubprocessError::Gone),
        })
    }.and_then(|result| result))
}

/// Reserve a source arena in the current child subprocess's own arena group.
/// The child record pins that group through every published arena and its
/// eventual subprocess teardown.
pub(crate) fn native_child_reserve_os_memory(
    size: usize,
    commit: bool,
    allow_large: bool,
    exclusive: bool,
) -> Option<Result<crate::arena::ArenaId, crate::arena::ReserveOsMemoryFailure>> {
    use crate::arena::ReserveOsMemoryFailure::Unmanaged;
    // SAFETY: the current thread alone accesses its membership slot.
    let current = (unsafe { current_child_member() }).as_mut()?;
    let result = (|| {
        let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter().ok_or(Unmanaged)?;
        let binding = current.binding;
        let config = binding.page_map().memory_config().map_err(|_| Unmanaged)?;
        let access = if commit { crate::os::MapAccess::Committed } else { crate::os::MapAccess::Reserved };
        // SAFETY: the current default Theap belongs to this admitted thread
        // and no other operation borrows its random image during reservation.
        let mut random = unsafe { crate::os::CurrentDefaultTheapRandom::new() };
        // SAFETY: the record lock retains the child context and excludes
        // teardown while the exact child arena backing publishes its owner.
        unsafe {
            current.record_member.id().with_owner(|owner| {
                owner.as_mut().and_then(|child| child.with_child_image(|image| {
                    let process = crate::os::ChildVmProcess::new(binding.process(), image).ok()?;
                    Some(image.identity().arena_backing().reserve_os_memory_reporting_failure(
                        process.process(), config, size, access, allow_large, exclusive, Some(&mut random),
                    ))
                }).flatten())
            })
        }
        .map_err(|_| Unmanaged)?
        .ok_or(Unmanaged)?
    })();
    Some(result)
}

/// Register caller-owned mapped memory in the current child's arena group.
/// The child record lock retains its pinned identity through publication;
/// teardown retires the arena before that identity can be released.
///
/// # Safety
/// `start..start + size` remains one live caller-owned mapping through the
/// child's arena, Heap, Theap, and page lifetime. Initial flags are truthful,
/// and the caller alone owns its final unmap after child teardown.
pub(crate) unsafe fn native_child_manage_os_memory_ex(
    start: *mut u8,
    size: usize,
    initially_committed: bool,
    is_pinned: bool,
    initially_zero: bool,
    numa_node: i32,
    exclusive: bool,
) -> Option<crate::arena::ArenaId> {
    // SAFETY: this thread exclusively accesses its own child membership.
    let current = (unsafe { current_child_member() }).as_mut()?;
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let binding = current.binding;
    let config = binding.page_map().memory_config().ok()?;
    // SAFETY: the record lock excludes child destruction and retains its
    // pinned image while the external arena is published in that image's
    // exact registry. The caller retains the external mapping separately.
    unsafe {
        current.record_member.id().with_owner(|owner| owner.as_mut().and_then(|child| {
            child.with_child_image(|image| {
                let process = crate::os::ChildVmProcess::new(binding.process(), image).ok()?;
                image.identity().arena_backing().install_owned_external_os_arena_for_child(
                    process, config, start, size, initially_committed, is_pinned,
                    initially_zero, numa_node, exclusive,
                ).ok().map(|managed| managed.arena_id())
            }).flatten()
        })).ok().flatten()
    }
}

/// Register caller-owned callback-managed memory in the current child's
/// arena group. A failed prepublication commit recovers the lease without
/// taking the external mapping or its terminal unmap right from the caller.
///
/// # Safety
/// The caller retains the mapping, callback, and callback argument through
/// child teardown. Initial flags are truthful, the callback admits contained
/// transitions, and no other owner can unmap or mutate this range meanwhile.
pub(crate) unsafe fn native_child_manage_memory(
    managed_size: usize,
    lease: crate::arena::ProcessExternalArenaLease,
    numa_node: i32,
    exclusive: bool,
) -> Option<crate::arena::ArenaId> {
    // SAFETY: this thread exclusively accesses its own child membership.
    let current = (unsafe { current_child_member() }).as_mut()?;
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let binding = current.binding;
    let config = binding.page_map().memory_config().ok()?;
    // SAFETY: the child record lock retains the pinned image through
    // publication and the image's arena backing retires this callback lease
    // before child destruction. No terminal unmap right enters the record.
    unsafe {
        current.record_member.id().with_owner(|owner| owner.as_mut().and_then(|child| {
            child.with_child_image(|image| {
                let process = crate::os::ChildVmProcess::new(binding.process(), image).ok()?;
                let result = image.identity().arena_backing()
                    .install_owned_external_callback_arena_for_child(
                        process, config, managed_size, lease, numa_node, exclusive,
                    );
                match result {
                    Ok(managed) => Some(managed.arena_id()),
                    Err(failure) => {
                        // A returned lease has no published owner; a retained
                        // lease stays in the arena until child teardown.
                        let _ = failure.into_returned_lease();
                        None
                    }
                }
            }).flatten()
        })).ok().flatten()
    }
}

/// Production child Heap deletion or destruction selected by the Heap's
/// subprocess identity. A caller outside that child retains its own thread
/// membership while deletion transfers live pages to the child's main Heap.
///
/// # Safety
/// `heap` is a live child Heap that no thread uses during the call; after
/// destruction none of its clients is used again. The caller retains its
/// runtime thread owner through the release.
pub(crate) unsafe fn native_child_heap_release(
    heap: core::ptr::NonNull<crate::types::Heap>,
    destroy: bool,
) -> Option<
    Result<
        Result<
            crate::types::heap_registry::lifecycle::HeapReleaseOutcome,
            crate::types::heap_registry::lifecycle::HeapReleaseError,
        >,
        NativeSubprocessError,
    >,
> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: every linked initializer owns its exact original admission
        // and remains pinned until its synchronous nested scopes have ended.
        let slot = unsafe { &*CURRENT_CHILD_MEMBER.get() };
        if slot.retained_initialization.is_some() {
            return Some(Err(NativeSubprocessError::Retained));
        }
        let mut initialization = slot.initialization;
        while !initialization.is_null() {
            let scope = unsafe { &*initialization };
            if scope.admission.as_ref().is_some_and(|admission| admission.heap == heap) {
                return Some(Err(NativeSubprocessError::Retained));
            }
            initialization = scope.previous;
        }
        // SAFETY: a short current-thread read of actual scoped custody; every
        // linked scope is pinned until synchronous nested scopes have ended.
        let current = unsafe { current_child_member() }.as_ref();
        if let Some(current) = current {
            if current.retained_fresh_issuer.as_ref().is_some_and(|retained| retained.issuer.heap == heap) {
                return Some(Err(NativeSubprocessError::Retained));
            }
            let mut scope = current.allocation_scope;
            while !scope.is_null() {
                let retained = unsafe { &*scope };
                if retained.issuer.as_ref().is_some_and(|issuer| issuer.heap == heap) {
                    return Some(Err(NativeSubprocessError::Retained));
                }
                scope = retained.previous;
            }
        }
    }
    // Read only the caller's identity before any selector can borrow its
    // member slot again. No member projection crosses the target record lock.
    let current_id = unsafe { current_child_member() }.as_ref().map(|member| member.record_member.id());
    // Source permits a caller outside the Heap's subprocess to release it.
    // The Heap's identity selects its child record; the current thread's
    // membership cannot stand in for a different child's owner.
    let subprocess = unsafe { heap.as_ref().subprocess_pointer() };
    if subprocess != crate::subproc::MainSubprocess::global().identity_ptr() {
        // SAFETY: a live child Heap keeps its source subprocess image pinned;
        // the identity is its first field and its record remains published.
        let image = unsafe { &*subprocess.cast::<crate::subproc::ChildSubprocessImage>() };
        let id = NativeSubprocessId(image.native_record()?);
        if current_id != Some(id) {
            let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
                return Some(Err(NativeSubprocessError::Closed));
            };
            let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
                .ready_child_subprocess_inputs() else {
                return Some(Err(NativeSubprocessError::NotReady));
            };
            let target_theap = if destroy {
                None
            } else {
                let Some(theap) = foreign_child_heap_delete_target_theap() else {
                    return Some(Err(NativeSubprocessError::NotReady));
                };
                Some(theap)
            };
            // SAFETY: the source Heap and record are live; the record lock
            // excludes other child lifecycle operations for the release.
            return Some(unsafe {
                id.with_owner(|owner| {
                    owner.as_mut()
                        .map(|child| unsafe {
                            match target_theap {
                                Some(theap) => crate::types::heap_registry::lifecycle::child_heap_delete_foreign(
                                    child, binding, heap, theap,
                                ),
                                None => crate::types::heap_registry::lifecycle::child_heap_destroy_foreign(
                                    child, binding, heap,
                                ),
                            }
                        })
                        .ok_or(NativeSubprocessError::Gone)
                })
                .and_then(|result| result)
            });
        }
    }
    // SAFETY: the foreign route has returned and no selector borrows this slot.
    let current = unsafe { current_child_member() }.as_mut()?;
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(Err(NativeSubprocessError::Closed));
    };
    let (id, binding) = (current.record_member.id(), current.binding);
    let member = &mut current.member;
    // SAFETY: forwarded obligations; the record lock serializes the list.
    Some(unsafe {
        id.with_owner(|owner| match owner.as_mut() {
            Some(child) if destroy => Ok(crate::types::heap_registry::lifecycle::child_heap_destroy(
                child, member, binding, heap,
            )),
            Some(child) => Ok(crate::types::heap_registry::lifecycle::child_heap_delete(
                child, member, binding, heap,
            )),
            None => Err(NativeSubprocessError::Gone),
        })
    }.and_then(|result| result))
}

/// Main Heaps share the fast TLS key. Resolving a foreign child's main
/// Heap therefore selects the caller's main Theap, while page ownership
/// still moves to that child. Select through the caller's own main Heap
/// before locking the target record; an auxiliary default remains unchanged.
fn foreign_child_heap_delete_target_theap() -> Option<core::ptr::NonNull<crate::types::Theap>> {
    if crate::source_heap_api::theap_get_default().is_null() {
        return None;
    }
    let heap = crate::source_heap_api::heap_main();
    // SAFETY: initialization retains the caller's main Heap and thread owner
    // in its own subprocess. The ordinary selector retains the cache reference.
    core::ptr::NonNull::new(unsafe { crate::source_heap_api::heap_theap(heap) }
        .cast::<crate::types::Theap>())
}

/// Production `mi_subproc_visit_heaps` (`subproc.c:303-313`).
///
/// # Safety
/// The id is live. `visitor` must not operate on this child.
pub(crate) unsafe fn native_subproc_visit_heaps(
    id: NativeSubprocessId,
    mut visitor: impl FnMut(core::ptr::NonNull<crate::types::Heap>) -> bool,
) -> Result<bool, NativeSubprocessError> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
        .ok_or(NativeSubprocessError::Closed)?;
    // SAFETY: forwarded id contract.
    unsafe {
        id.with_owner(|owner| {
            let visited: Result<bool, crate::types::heap_registry::SourceHeapRegistryError> = owner
                .as_mut()
                .and_then(|child| child.visit_heaps(&mut visitor))
                .ok_or(NativeSubprocessError::Gone)?;
            visited.map_err(|_| NativeSubprocessError::Retained)
        })
    }?
}

/// Production pinned `mi_subproc_destroy` for a child from
/// [`native_subproc_new`], on any runtime thread that may free.
///
/// A child that threads still belong to is destroyed under them, as source
/// does; each of them later finishes without touching the child, and the
/// last one frees the record. After success the id is invalid. A failure
/// after the first irreversible step retains the remaining owners and
/// returns `Retained`.
///
/// # Safety
/// The id is live, no other operation on this id runs concurrently with
/// the call, no block of the child is used again, and a thread that still
/// belongs to the child makes no allocator call during or after the call
/// other than its own thread finish.
pub(crate) unsafe fn native_subproc_destroy(id: NativeSubprocessId) -> Result<(), NativeSubprocessError> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
        .ok_or(NativeSubprocessError::Closed)?;
    // SAFETY: forwarded id contract; the native runtime is admitted.
    unsafe { destroy_record(id, ChildHeapRelease::Native) }
}

/// Pinned `_mi_subprocs_unsafe_destroy_all`'s child walk
/// (`subproc.c:265-277`) at process destruction: each child still in the
/// source subprocess list, in list order, is destroyed as by
/// `mi_subproc_unsafe_destroy` before the process main subprocess. Each
/// child is reached from the list through the production record that
/// [`native_subproc_new`] published in its image.
///
/// The native entry points are closed, so the child main Heap image is left
/// on its process-main page for the main-subprocess destruction that follows
/// (see [`ChildHeapRelease::Terminal`]). As in source, a child that threads
/// still belong to is destroyed under them: their Theaps' pages and list
/// edges are detached, and their TLDs, Theaps, and roots are left naming
/// released child memory that the closed entry points never reach again. A
/// list member without a production record, or a failed step, returns an
/// error that stops the walk; process destruction then retains the main
/// subprocess too.
///
/// # Safety
/// Permanent terminal admission holds: every native entry point and child
/// context operation has drained and none can start, the process coordinator
/// is still ready, and no child block is used again. The caller destroys the
/// main subprocess next.
pub(crate) unsafe fn destroy_all_native_children_terminal() -> Result<(), NativeSubprocessError> {
    let (_, registry) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .ok_or(NativeSubprocessError::NotReady)?;
    loop {
        // SAFETY: terminal admission excludes every other list user.
        let child = unsafe { registry.first_child_terminal() }.map_err(|_| NativeSubprocessError::Retained)?;
        let Some(child) = child else { return Ok(()) };
        // SAFETY: a linked child stays allocated until its destruction below.
        let record = unsafe { child.as_ref() }.native_record().ok_or(NativeSubprocessError::Retained)?;
        // SAFETY: a published record lives until its child is destroyed, and
        // terminal admission excludes every other operation on it.
        unsafe { destroy_record(NativeSubprocessId(record), ChildHeapRelease::Terminal) }?;
    }
}

/// The exact preallocated header and trailing failure bits for one native
/// child destruction. The record owns its parent-issued allocation; a pending
/// raw failure borrows only the same allocation's separate trailing words.
#[cfg(target_arch = "x86_64")]
struct NativeChildArenaDestroyState {
    pending: Option<crate::arena::DestroyedArenas<'static>>,
    words: usize,
}

#[cfg(target_arch = "x86_64")]
impl NativeChildArenaDestroyState {
    fn tracking_offset() -> usize {
        let alignment = core::mem::align_of::<usize>();
        (core::mem::size_of::<Self>() + alignment - 1) & !(alignment - 1)
    }
}

/// # Safety
/// The caller holds this exact record lock and its actual child context.
/// No prior failure-bit projection or raw retry is live. The returned bits
/// remain in the record's exact parent-issued allocation through every raw
/// release failure, and may never outlive its final successful storage return.
#[cfg(target_arch = "x86_64")]
unsafe fn native_child_destroy_tracking(
    record: core::ptr::NonNull<NativeChildSubprocess>,
    child: &mut ChildMainHeapContextOwner<'static>,
) -> Result<&'static mut [usize], NativeSubprocessError> {
    let slot = unsafe { &mut *(*record.as_ptr()).destroy_state.get() };
    if slot.is_none() {
        let words = child.with_child_image(|image| unsafe {
            image.identity().arena_backing().terminal_tracking_words()
        }).ok_or(NativeSubprocessError::Retained)?
            .map_err(|_| NativeSubprocessError::Retained)?;
        if words == 0 { return Ok(&mut []); }
        let bytes = words.checked_mul(core::mem::size_of::<usize>())
            .and_then(|bytes| NativeChildArenaDestroyState::tracking_offset().checked_add(bytes))
            .ok_or(NativeSubprocessError::Retained)?;
        let route = unsafe { (*record.as_ptr()).parent_metadata };
        let allocation = route.allocate(bytes).map_err(|error| NativeSubprocessError::DestroyRefused(
            ChildSubprocessDestroyError::TrackingAllocation(error)))?;
        let state = allocation.pointer().cast::<NativeChildArenaDestroyState>();
        // Parent metadata guarantees ordinary word alignment; this exact
        // fresh capability receives a complete header before publication.
        assert_eq!(state.as_ptr().addr() % core::mem::align_of::<NativeChildArenaDestroyState>(), 0);
        unsafe { state.as_ptr().write(NativeChildArenaDestroyState { pending: None, words }); }
        *slot = Some(allocation);
    }
    let allocation = slot.as_ref().expect("retained native destruction scratch");
    if !allocation.is_live() { return Err(NativeSubprocessError::Retained); }
    let state = allocation.pointer().cast::<NativeChildArenaDestroyState>();
    // SAFETY: the lock excludes every other use, and a retained raw retry
    // must have ended before this sole mutable bit projection is formed.
    if unsafe { (*state.as_ptr()).pending.is_some() } { return Err(NativeSubprocessError::Retained); }
    let words = unsafe { (*state.as_ptr()).words };
    Ok(unsafe { core::slice::from_raw_parts_mut(
        allocation.pointer().as_ptr().add(NativeChildArenaDestroyState::tracking_offset()).cast(), words,
    ) })
}

/// Pinned `mi_subproc_unsafe_destroy` for one production record, then the
/// record itself. `release` is `Native` inside native admission and
/// `Terminal` under permanent terminal admission.
///
/// # Safety
/// The id is live, no other operation on it runs concurrently, and no block
/// of the child is used again.
unsafe fn destroy_record(
    id: NativeSubprocessId,
    release: ChildHeapRelease<'_, 'static>,
) -> Result<(), NativeSubprocessError> {
    let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .ok_or(NativeSubprocessError::NotReady)?;
    let config = binding.page_map().memory_config().map_err(|_| NativeSubprocessError::NotReady)?;
    let metadata = crate::meta::MetaAllocator::global();
    let terminal = matches!(release, ChildHeapRelease::Terminal);
    // SAFETY: forwarded id contract.
    let record = unsafe { id.record() };
    let destroyed = unsafe {
        id.with_owner(|owner| {
            // Check before taking any owner or changing a source list. The
            // callback holds no child lock, so nested allocation can proceed.
            #[cfg(target_arch = "x86_64")]
            if record.callback_leases.load(core::sync::atomic::Ordering::Acquire) != 0 {
                return Err(NativeSubprocessError::DestroyRefused(ChildSubprocessDestroyError::CallbackActive));
            }
            #[cfg(target_arch = "x86_64")]
            let pending = unsafe { (*record.destroy_state.get()).as_ref().and_then(|allocation| {
                (*allocation.pointer().cast::<NativeChildArenaDestroyState>().as_ptr()).pending.take()
            }) };
            let mut child = match owner.take() {
                Some(child) => child,
                None if unsafe { (*record.storage.get()).is_some() } => {
                    // Source teardown finished, but an exact metadata return
                    // refused. Retry only final record storage return when no
                    // actual TLS member still retains this same record.
                    return Ok(unsafe { *record.members.get() });
                }
                None => return Err(NativeSubprocessError::Gone),
            };
            #[cfg(target_arch = "x86_64")]
            if let Some(destroyed) = pending {
                let failure = ChildMainHeapReleaseFailure::ArenaBacking { owner: child, destroyed };
                child = match failure.retry_arena_backing() {
                    Ok(child) => child,
                    Err(ChildMainHeapReleaseFailure::ArenaBacking { owner: child, destroyed }) => {
                        let state = unsafe { (*record.destroy_state.get()).as_ref().unwrap().pointer()
                            .cast::<NativeChildArenaDestroyState>() };
                        unsafe { (*state.as_ptr()).pending = Some(destroyed); }
                        *owner = Some(child);
                        return Err(NativeSubprocessError::Retained);
                    }
                    Err(_) => unreachable!("raw retry retains its original child arena owner"),
                };
            }
            #[cfg(target_arch = "x86_64")]
            let tracking = if child.stage() == ChildMainHeapStage::ArenaBackingDestroyed {
                &mut []
            } else {
                match unsafe { native_child_destroy_tracking(id.0, &mut child) } {
                    Ok(tracking) => tracking,
                    Err(error) => { *owner = Some(child); return Err(error); }
                }
            };
            #[cfg(not(target_arch = "x86_64"))]
            let tracking = &mut [];
            // Source destroys a child under its permanently quiescent
            // threads. Rust TLS can still retain a member after the source
            // registration ended, so actual tokens retain this control record.
            let source_live = child
                .with_child_image(|image| image.get_ref().identity().live_thread_count())
                .unwrap_or(0);
            // SAFETY: the held record lock serializes actual token custody.
            let members = unsafe { *record.members.get() };
            // SAFETY: the record lock excludes thread admission and finish.
            // The caller has permanently quiesced every member and ended all
            // child-block use before the terminal path releases their images.
            match destroy_child_with(
                child, record.registry, binding, tracking, metadata, config, release, source_live != 0 || members != 0,
            ) {
                Ok(()) => {
                    // Destruction consumes no actual TLS token; each member
                    // later completes its own terminal finish against this record.
                    Ok(members)
                }
                Err(ChildSubprocessDestroyFailure::Retained { owner: child, error }) => {
                    let refused = child.stage() == ChildMainHeapStage::HeapReady;
                    *owner = Some(child);
                    Err(if refused {
                        NativeSubprocessError::DestroyRefused(error)
                    } else {
                        NativeSubprocessError::Retained
                    })
                }
                Err(ChildSubprocessDestroyFailure::Release(ChildMainHeapReleaseFailure::Retained {
                    owner: child, ..
                })) => {
                    *owner = Some(child);
                    Err(NativeSubprocessError::Retained)
                }
                #[cfg(target_arch = "x86_64")]
                Err(ChildSubprocessDestroyFailure::Release(ChildMainHeapReleaseFailure::ArenaBacking { owner: child, destroyed })) => {
                    let state = unsafe { (*record.destroy_state.get()).as_ref().unwrap().pointer()
                        .cast::<NativeChildArenaDestroyState>() };
                    unsafe { (*state.as_ptr()).pending = Some(destroyed); }
                    *owner = Some(child);
                    Err(NativeSubprocessError::Retained)
                }
                // The remaining owners are dropped without freeing anything.
                Err(ChildSubprocessDestroyFailure::Release(_)) => Err(NativeSubprocessError::Retained),
            }
        })
    }??;
    if destroyed != 0 && !terminal {
        // Ordinary destruction preserves actual TLS tokens until final finish.
        return Ok(());
    }
    // Permanent terminal exclusion makes every remaining TLS token
    // unreachable. Releasing this exact record now returns a nested child's
    // parent custody before source teardown visits that ancestor.
    // The child is gone and the lock is released; no other operation on this
    // id may run (caller contract), so the record can be taken apart.
    // SAFETY: exclusive by the id contract; the owner cell is empty.
    unsafe { free_record(id.0) }
}

/// Transfers the enclosing exact allocation after all source image users
/// have ended. The control record then retains it through orphan TLS finish.
///
/// # Safety
/// The caller exclusively owns this record's child teardown under its lock;
/// the child identity is detached and no source image projection remains.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn retain_native_child_control_storage(
    record: core::ptr::NonNull<NativeChildSubprocess>,
    storage: crate::meta::ChildMetadataAllocation,
) {
    // SAFETY: teardown holds the record lock and owns the one capability.
    let slot = unsafe { &mut *record.as_ref().storage.get() };
    assert!(slot.is_none(), "child control custody transfers only once");
    *slot = Some(storage);
}

/// Frees a record whose child is gone.
///
/// # Safety
/// No operation on the record runs or can start.
unsafe fn free_record(record: core::ptr::NonNull<NativeChildSubprocess>) -> Result<(), NativeSubprocessError> {
    // SAFETY: forwarded exclusivity; the owner cell is empty. Copy every
    // release input before the parent free invalidates this inline record.
    // No reference to the record spans its enclosing allocation's return.
    #[cfg(target_arch = "x86_64")]
    {
        let scratch = unsafe { &mut *(*record.as_ptr()).destroy_state.get() };
        if let Some(allocation) = scratch.as_mut() {
            // General metadata release rejects admitted failures terminally;
            // no stale header or failure-bit projection may follow that edge.
            if !allocation.is_live() { return Err(NativeSubprocessError::Retained); }
            let state = allocation.pointer().cast::<NativeChildArenaDestroyState>();
            if unsafe { (*state.as_ptr()).pending.is_some() } { return Err(NativeSubprocessError::Retained); }
            let parent = unsafe { (*record.as_ptr()).parent_metadata };
            parent.free(allocation).map_err(|_| NativeSubprocessError::Retained)?;
            scratch.take();
        }
    }
    let mut storage = unsafe { (*(*record.as_ptr()).storage.get()).take() }
        .ok_or(NativeSubprocessError::Retained)?;
    let parent_metadata = unsafe { (*record.as_ptr()).parent_metadata };
    #[cfg(target_arch = "x86_64")]
    let parent_admission = unsafe { (*(*record.as_ptr()).parent_admission.get()).take() };
    if parent_metadata.free(&mut storage).is_err() {
        // The unreturned exact context remains parent-issued storage. Keep
        // its original issuer retained even when no caller can retry it.
        #[cfg(target_arch = "x86_64")]
        core::mem::forget(parent_admission);
        return Err(NativeSubprocessError::Retained);
    }
    // The exact context is now returned, and the final child-record access
    // ended before the parent's admission can permit its own destruction.
    #[cfg(target_arch = "x86_64")]
    drop(parent_admission);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::main_heap_page::tests::with_owner_local_fixture;
    use crate::statistics::FinalStatisticsSnapshot;
    use crate::subproc::{MainSubprocess, SubprocessIdentity};
    use std::vec::Vec;

    fn registry_members(registry: &SourceSubprocessRegistry) -> Vec<*mut SubprocessIdentity> {
        registry.test_members()
    }

    fn identity(child: &mut ChildMainHeapContextOwner<'_>) -> *mut SubprocessIdentity {
        child.identity_pointer().expect("a created child projects its identity")
    }

    fn main_totals(parent: &MainSubprocess) -> FinalStatisticsSnapshot {
        parent.statistics().final_output_snapshot()
    }

    /// The process inputs of a child subprocess fixture over one attached
    /// later-main fixture thread: an isolated source registry holding main,
    /// and a READY binding over the fixture's PageMap with the C oracles'
    /// arena policy (one minimum-size reservation, no eager commit).
    pub(crate) fn child_fixture_inputs(
        attachment: &mut MainHeapThreadAttachment<'_>,
        pair: crate::process_arena::ProcessPageArenaLease,
    ) -> (&'static MainSubprocess, &'static SourceSubprocessRegistry, ProcessMainBackingBinding) {
        let parent = attachment.subprocess().expect("the fixture attaches to main");
        let config = attachment.memory_config().expect("the attachment is live");
        let registry = std::boxed::Box::leak(std::boxed::Box::new(SourceSubprocessRegistry::new()));
        // SAFETY: this isolated fixture exclusively owns the main image.
        unsafe { registry.initialize_main(parent) }.expect("main joins the registry");
        let mut vm_options = crate::config::VmOptions::uninitialized();
        vm_options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        vm_options.set(crate::config::VmOption::ArenaReserve,
            (crate::config::ARENA_MIN_SIZE / crate::config::KIB) as i64);
        vm_options.set(crate::config::VmOption::ArenaEagerCommit, 0);
        // SAFETY: leaked isolated binding over the fixture's own map.
        let binding = unsafe {
            crate::process_init::ProcessMainInitializationStorage::test_static_owner()
                .test_bind_vm_process_to_existing_page_map(
                    config, vm_options, parent, pair.page_map_lease(),
                )
        }
        .expect("children use the parent's policy and process PageMap");
        // Startup is complete, so a fresh thread may own child pages.
        assert!(binding.test_publish_ready());
        (parent, registry, binding)
    }

    /// The ordered fields cover child creation, Heap visitation, and
    /// destruction across the child record's lifetime.
    #[test]
    fn source_ordered_child_subprocess_lifecycle_trace() {
        with_owner_local_fixture(true, |attachment, mut heap_owner, pair| {
            let (parent, registry, binding) = child_fixture_inputs(attachment, pair);

            let mut trace: Vec<i64> = Vec::new();
            let main_identity = parent.identity_ptr();
            trace.push(registry_members(registry).len() as i64);

            // SAFETY: the registry holds main, the call runs on the attached
            // fixture thread, and no other child operation exists.
            let mut first = unsafe { new_child(registry, attachment, &mut heap_owner) }
                .expect("the first child is created");
            let first_identity = identity(&mut first);
            let members = registry_members(registry);
            trace.push(members.len() as i64);
            trace.push(i64::from(members.first() == Some(&first_identity)));
            let facts = first.test_created_child_facts(parent).expect("a ready child");
            trace.push(facts.sequence as i64);
            trace.push(i64::from(facts.parent_is_main));
            trace.push(facts.heap_count as i64);
            trace.push(facts.heap_total_count as i64);
            trace.push(i64::from(facts.heap_list_is_main_only));
            trace.push(facts.main_heap_sequence as i64);
            trace.push(i64::from(facts.main_heap_names_child));
            trace.push(i64::from(facts.metadata_theap_is_heap_only_member));
            trace.push(i64::from(facts.metadata_theap_on_parent_detached_tld));
            trace.push(facts.live_threads as i64);
            trace.push(facts.total_threads as i64);
            trace.push(facts.arena_count as i64);
            trace.push(facts.heaps_current);

            let mut second = unsafe { new_child(registry, attachment, &mut heap_owner) }
                .expect("the second child is created");
            let second_identity = identity(&mut second);
            let members = registry_members(registry);
            trace.push(members.len() as i64);
            trace.push(i64::from(
                members.first() == Some(&second_identity) && members.get(1) == Some(&first_identity),
            ));
            trace.push(second.test_created_child_facts(parent).unwrap().sequence as i64);

            // `mi_subproc_visit_heaps`: every Heap, then an early stop.
            let (visited_all, visited_count) = first.test_visit_heaps(|_| true);
            trace.push(i64::from(visited_all));
            trace.push(visited_count as i64);
            let (visited_all, visited_count) = first.test_visit_heaps(|_| false);
            trace.push(i64::from(visited_all));
            trace.push(visited_count as i64);

            // `_mi_meta_zalloc(child, 64)` reserves the first child arena.
            let main_arenas_before = parent.arena_backing().registry().count();
            let arena_count = first
                .with_metadata_page_engine(binding, |child, engine| {
                    let block = engine.allocate(64, true).expect("child metadata allocates");
                    let count = child.get_ref().identity().arena_backing().registry().count();
                    // SAFETY: the exact live block allocated just above.
                    unsafe { engine.free(block) }.expect("child metadata frees");
                    count
                })
                .expect("the child metadata engine is available");
            trace.push(arena_count as i64);
            trace.push(parent.arena_backing().registry().count() as i64 - main_arenas_before as i64);
            let first_reserved = first
                .test_created_child_facts(parent)
                .unwrap()
                .statistics
                .reserved
                .current;
            trace.push(i64::from(first_reserved > 0));

            // `mi_subproc_add_current_thread` on this thread, which already
            // belongs to the main subprocess, changes nothing.
            // SAFETY: the fixture thread owns its roots; no other child
            // operation runs.
            let refused = unsafe { add_current_thread(&mut first, binding) };
            trace.push(i64::from(matches!(
                refused,
                Ok(ChildThreadAddOutcome::AlreadyInitialized { in_other_subprocess: true })
            )));
            drop(refused);
            let facts = first.test_created_child_facts(parent).unwrap();
            trace.push(facts.live_threads as i64);
            trace.push(facts.total_threads as i64);

            // A fresh thread joins the child, allocates and frees one block,
            // and finishes; see `worker_main` in the C oracle.
            struct Shared<T>(T);
            // SAFETY: the scoped worker is the only user of the child owner
            // and binding until it is joined.
            unsafe impl<T> Send for Shared<T> {}
            let shared = Shared((&mut first, binding, first_identity));
            let worker = std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, child_identity) = shared.0;
                    let mut values: Vec<i64> = Vec::new();
                    // SAFETY: this fresh thread owns its pristine roots, and
                    // the joined scope excludes every other child operation.
                    let outcome = unsafe { add_current_thread(child, binding) };
                    let mut member = match outcome {
                        Ok(ChildThreadAddOutcome::Added(member)) => member,
                        Ok(ChildThreadAddOutcome::AlreadyInitialized { in_other_subprocess }) => {
                            panic!("a fresh thread is already initialized (other: {in_other_subprocess})")
                        }
                        Err(ChildThreadStartFailure::Rejected(error)) => {
                            panic!("the child rejects a fresh thread: {error:?}")
                        }
                        Err(ChildThreadStartFailure::Retained { error, .. }) => {
                            panic!("the child retains a fresh thread: {error:?}")
                        }
                    };
                    let theap = member.theap_pointer().expect("an attached member has a Theap");
                    let (live, total, statistics, heap_identity) = member
                        .with_child_image(|image| {
                            let identity = image.get_ref().identity();
                            (
                                identity.live_thread_count(),
                                identity.total_thread_count(),
                                identity.statistics().final_output_snapshot(),
                                identity.ready_main_heap_identity().expect("a ready child Heap"),
                            )
                        })
                        .expect("the member projects its child");
                    values.push(live as i64);
                    values.push(total as i64);
                    values.push(statistics.threads.current);
                    values.push(statistics.theaps.current);
                    // SAFETY: the member retains its Theap and only this
                    // thread uses it.
                    let theap_ref = unsafe { theap.as_ref() };
                    values.push(i64::from(
                        core::ptr::eq(default_theap().as_ptr(), theap.as_ptr())
                            && crate::compiler_tls::fast_slot_peek() == Some(theap.cast())
                            && core::ptr::NonNull::new(theap_ref.heap())
                                .is_some_and(|heap| heap_identity.matches(heap))
                            && !theap_ref.is_detached(),
                    ));
                    // SAFETY: the default root names this thread's own Theap.
                    values.push(i64::from(
                        unsafe { Theap::initialized_default_subprocess_at(default_theap()) }
                            == Some(child_identity),
                    ));
                    values.push(member.sequence().get() as i64);
                    let thread = member.thread().get();
                    // SAFETY: the admitted thread runs its own page engine.
                    let (page_heap, page_owner) = unsafe {
                        member.with_page_engine(binding, |_image, engine| {
                            let block = engine.allocate(64, false).expect("the child thread allocates");
                            // SAFETY: the exact live block allocated above.
                            let page = &*engine.page_for_block(block);
                            let facts = (page.heap(), page.owner_thread_id());
                            // SAFETY: the exact live block allocated above.
                            engine.free(block).expect("the child thread frees");
                            facts
                        })
                    }
                    .expect("the admitted thread's page engine runs");
                    values.push(i64::from(
                        core::ptr::NonNull::new(page_heap).is_some_and(|heap| heap_identity.matches(heap)),
                    ));
                    values.push(i64::from(page_owner == thread));
                    // SAFETY: the only block was freed; this is the admitted thread.
                    unsafe { member.thread_done(child, binding) }.expect("the child thread finishes");
                    // SAFETY: the reset default root is the empty Theap.
                    values.push(i64::from(
                        unsafe { Theap::initialized_default_subprocess_at(default_theap()) }.is_none(),
                    ));
                    drop(member);
                    values
                })
                .join()
                .expect("the child thread completes")
            });
            trace.extend(worker);
            let facts = first.test_created_child_facts(parent).unwrap();
            trace.push(facts.live_threads as i64);
            trace.push(facts.total_threads as i64);
            trace.push(facts.statistics.threads.current);
            trace.push(facts.statistics.theaps.current);
            trace.push(facts.statistics.threads.total);

            let before = main_totals(parent);
            // SAFETY: the child has no users, blocks, or threads left.
            unsafe {
                destroy_child(first, registry, binding, &mut [], attachment, &mut heap_owner)
            }
            .expect("the older child is destroyed from the middle of the list");
            let after = main_totals(parent);
            let members = registry_members(registry);
            trace.push(members.len() as i64);
            trace.push(i64::from(
                members.first() == Some(&second_identity) && members.get(1) == Some(&main_identity),
            ));
            trace.push(after.heaps.total - before.heaps.total);
            trace.push(i64::from(after.reserved.current - before.reserved.current == first_reserved));
            trace.push(after.arena_count - before.arena_count);
            trace.push(i64::from(after.pages.total > before.pages.total));
            trace.push(after.threads.total - before.threads.total);
            trace.push(after.pages.current - before.pages.current);

            // A child destroyed with a live metadata block.
            second
                .with_metadata_page_engine(binding, |_child, engine| {
                    engine.allocate(64, true).expect("child metadata allocates");
                })
                .expect("the child metadata engine is available");
            let second_facts = second.test_created_child_facts(parent).unwrap();
            trace.push(second_facts.statistics.pages.current);
            let before = main_totals(parent);
            // SAFETY: the child has no users or threads; its live metadata
            // block is released with the child arenas, as in source.
            unsafe {
                destroy_child(second, registry, binding, &mut [], attachment, &mut heap_owner)
            }
            .expect("the newest child is destroyed from the list head");
            let after = main_totals(parent);
            trace.push(registry_members(registry).len() as i64);
            trace.push(after.pages.current - before.pages.current);
            trace.push(i64::from(
                after.reserved.current - before.reserved.current
                    == second_facts.statistics.reserved.current,
            ));

            let mut third = unsafe { new_child(registry, attachment, &mut heap_owner) }
                .expect("a later child is created after destruction");
            trace.push(third.test_created_child_facts(parent).unwrap().sequence as i64);
            unsafe {
                destroy_child(third, registry, binding, &mut [], attachment, &mut heap_owner)
            }
            .expect("the later child is destroyed");
            trace.push(registry_members(registry).len() as i64);
            // `mi_subproc_current()` and `mi_subproc_main()` on this thread.
            trace.push(i64::from(core::ptr::eq(
                attachment.subprocess().unwrap().identity_ptr(),
                main_identity,
            )));

            // Page handoff at thread finish; see `handoff_main` in the C
            // oracle. A thread finishes with three live blocks, then this
            // thread (outside the child, so never reclaiming) frees two.
            let mut fourth = unsafe { new_child(registry, attachment, &mut heap_owner) }
                .expect("the handoff child is created");
            let handoff_heap = fourth.main_heap_pointer().expect("a ready child Heap");
            let shared = Shared((&mut fourth, binding));
            let [small0, small1, medium] = std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding) = shared.0;
                    // SAFETY: a fresh thread owns its pristine roots; the
                    // joined scope excludes every other child operation.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) = (unsafe { add_current_thread(child, binding) }) else {
                        panic!("a fresh thread joins the handoff child");
                    };
                    // SAFETY: the admitted thread runs its own page engine.
                    let blocks = unsafe {
                        member.with_page_engine(binding, |_image, engine| {
                            let small0 = engine.allocate(64, false).expect("allocates");
                            let freed = engine.allocate(64, false).expect("allocates");
                            let small1 = engine.allocate(64, false).expect("allocates");
                            let medium = engine.allocate(3000, false).expect("allocates");
                            // SAFETY: the exact live block allocated above.
                            unsafe { engine.free(freed) }.expect("frees");
                            [small0, small1, medium].map(|block| block.as_ptr().addr())
                        })
                    }
                    .expect("the admitted thread's page engine runs");
                    // SAFETY: the admitted thread; its live blocks are handed off.
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes with live blocks");
                    drop(member);
                    blocks
                })
                .join()
                .expect("the handoff thread completes")
            });
            let block = |address: usize| core::ptr::NonNull::new(address as *mut u8).unwrap();
            let page_of = |address: usize| {
                // SAFETY: the block is live and observed through the fixture PageMap.
                unsafe { binding.page_map().lookup_live_allocation(block(address)) }
                    .expect("the PageMap is ready").expect("a live block").page()
            };
            let abandoned = |trace: &mut Vec<i64>, page: core::ptr::NonNull<crate::types::Page>| {
                // SAFETY: the page holds a live block; raw scalar reads only.
                let state = unsafe { crate::types::Page::abandonment_state_at(page) };
                let thread = unsafe { state.xthread_id.as_ref() }.load(core::sync::atomic::Ordering::Relaxed)
                    & !(crate::types::PAGE_FLAG_MASK as usize);
                trace.push(i64::from(thread <= crate::types::THREAD_ID_ABANDONED_MAPPED));
                trace.push(i64::from(thread == crate::types::THREAD_ID_ABANDONED_MAPPED));
                let bin = crate::size_class::bin(state.block_size).expect("a sized page");
                // SAFETY: the child main Heap is live.
                trace.push(unsafe { handoff_heap.as_ref() }.abandoned_count(bin).unwrap() as i64);
                trace.push(unsafe { *state.used.as_ptr() } as i64);
            };
            let free_remote = |address: usize| {
                // SAFETY: as above; this thread is outside the child.
                let allocation = unsafe { binding.page_map().lookup_live_allocation(block(address)) }
                    .unwrap().unwrap();
                unsafe { free_child_block_nonlocal(binding, allocation, |_| crate::abandoned::ReclaimOnFreeOutcome::Declined) }.expect("a child page")
            };
            let (small_page, medium_page) = (page_of(small0), page_of(medium));
            let handoff_facts = fourth.test_created_child_facts(parent).unwrap();
            trace.push(handoff_facts.live_threads as i64);
            trace.push(i64::from(small_page != medium_page && page_of(small1) == small_page));
            // SAFETY: both pages hold live blocks.
            trace.push(i64::from(unsafe {
                small_page.as_ref().heap() == handoff_heap.as_ptr() && medium_page.as_ref().heap() == handoff_heap.as_ptr()
            }));
            abandoned(&mut trace, small_page);
            abandoned(&mut trace, medium_page);
            assert_eq!(free_remote(small0), crate::single_thread::ChildNonlocalFreeResult::Freed);
            abandoned(&mut trace, small_page);
            // SAFETY: the medium page still holds its live block.
            let medium_bin = crate::size_class::bin(unsafe { medium_page.as_ref() }.block_size()).unwrap();
            assert_eq!(free_remote(medium), crate::single_thread::ChildNonlocalFreeResult::Released);
            // SAFETY: the child main Heap is live.
            trace.push(unsafe { handoff_heap.as_ref() }.abandoned_count(medium_bin).unwrap() as i64);
            // SAFETY: the child has no threads; its last live block goes with
            // its arenas, as in source.
            unsafe {
                destroy_child(fourth, registry, binding, &mut [], attachment, &mut heap_owner)
            }
            .expect("the handoff child is destroyed with a live abandoned block");
            trace.push(registry_members(registry).len() as i64);

            for (index, value) in trace.iter().enumerate() {
                std::println!("m6.subproc.lifecycle.{index}={value}");
            }
            heap_owner.finish(attachment).expect("the parent engine is quiescent");
            attachment
                .finish_after_user_destructors()
                .expect("the parent attachment completes after its children");
        });
    }

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    fn native_backing() -> ProcessMainBackingBinding {
        crate::process_init::ProcessMainInitializationStorage::global()
            .ready_child_subprocess_inputs()
            .expect("the isolated runtime is READY")
            .0
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_creation_metadata_failure_returns_parent_custody_before_retry() {
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_creation_metadata_failure_returns_parent_custody_before_retry",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let (_, registry) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap();
                let metadata = crate::meta::MetaAllocator::global();
                let members = registry_members(registry);
                let capabilities = metadata.test_allocation_audit().live_capability_count;
                for context_failure in [true, false] {
                    let request = if context_failure {
                        core::mem::size_of::<crate::subproc::ChildSubprocessImage>()
                    } else { core::mem::size_of::<Theap>() };
                    metadata.test_fail_next_direct_zeroed_size(request);
                    let failure = native_subproc_new().expect_err("the exact source metadata request fails");
                    assert!(matches!((context_failure, failure),
                        (true, NativeSubprocessError::New(ChildSubprocessNewError::ContextAllocation(_)))
                        | (false, NativeSubprocessError::New(ChildSubprocessNewError::MetadataTheapAllocation(_)))));
                    assert_eq!(registry_members(registry), members,
                        "failed creation publishes no child registry member");
                    assert_eq!(metadata.test_allocation_audit().live_capability_count, capabilities,
                        "source reverse rollback returns every exact parent capability");
                    let retry = native_subproc_new().expect("the same parent can retry creation");
                    // SAFETY: no member, client, callback, or other operation
                    // has been admitted to this newly created retry child.
                    assert_eq!(unsafe { native_subproc_destroy(retry) }, Ok(()));
                    assert_eq!(registry_members(registry), members);
                    assert_eq!(metadata.test_allocation_audit().live_capability_count, capabilities,
                        "complete retry releases its enclosing control exactly once");
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_manage_external_os_memory_retains_child_context_and_caller_mapping() {
        use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors,
            native_collect, prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment,
            ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_manage_external_os_memory_retains_child_context_and_caller_mapping",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("a child context");
                // SAFETY: this test alone owns the reserved raw mapping and
                // trims only the prefix and suffix outside the aligned span.
                let raw = unsafe { crabc_core::mm::mmap_raw(
                    core::ptr::null_mut(), ARENA_MIN_SIZE + ARENA_ALIGNMENT,
                    0, 0x22, -1, 0,
                ) }.expect("caller reservation");
                let aligned = (raw as usize + ARENA_ALIGNMENT - 1) & !(ARENA_ALIGNMENT - 1);
                let prefix = aligned - raw as usize;
                let suffix = ARENA_ALIGNMENT - prefix;
                if prefix != 0 {
                    // SAFETY: these caller-owned bytes precede the aligned
                    // arena span and no allocator owner has observed them.
                    unsafe { crabc_core::mm::munmap_raw(raw, prefix) }.unwrap();
                }
                if suffix != 0 {
                    // SAFETY: these caller-owned bytes follow the aligned
                    // arena span and no allocator owner has observed them.
                    unsafe { crabc_core::mm::munmap_raw((aligned + ARENA_MIN_SIZE) as *mut u8, suffix) }.unwrap();
                }
                let worker = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let mut arena = core::ptr::null_mut();
                    assert!(unsafe { crate::source_heap_api::manage_os_memory_ex(
                        aligned as *mut core::ffi::c_void, ARENA_MIN_SIZE,
                        false, false, true, -1, true, &mut arena,
                    ) }, "the member registers its caller-owned reserved mapping in the child");
                    assert!(!arena.is_null());
                    let heap = unsafe { crate::source_heap_api::heap_new_in_arena(arena) };
                    assert!(!heap.is_null());
                    let theap = unsafe { crate::source_heap_api::heap_theap(heap) };
                    assert!(!theap.is_null());
                    let block = unsafe { crate::source_heap_api::heap_malloc(heap, 80) }
                        .value.expect("selected child page allocation");
                    assert!(theap as usize >= aligned && (theap as usize) - aligned < ARENA_MIN_SIZE);
                    assert!(block.as_ptr() as usize >= aligned && (block.as_ptr() as usize) - aligned < ARENA_MIN_SIZE);
                    assert_eq!(unsafe { crate::source_api::free(block.as_ptr()) }, crate::source_api::FreeOutcome::Freed);
                    assert!(unsafe { crate::source_heap_api::heap_release(heap, true) });
                    native_collect(true);
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                    arena as usize
                });
                let arena = worker.join().expect("member finished");
                let parent_registry = crate::subproc::MainSubprocess::global().arena_backing().registry();
                assert!((0..parent_registry.count()).all(|index| {
                    // SAFETY: the parent registry remains live through this
                    // isolated process and publishes only stable arena slots.
                    unsafe { parent_registry.arena_at(index) }.is_none_or(|entry|
                        core::ptr::from_ref(entry) as usize != arena)
                }), "the child arena is absent from the parent registry");
                let (child_owns_arena, purge_calls) = unsafe { id.with_owner(|owner| {
                    owner.as_mut().and_then(|child| child.with_child_image(|image| {
                        let registry = image.identity().arena_backing().registry();
                        let owns_arena = (0..registry.count()).any(|index| {
                            // SAFETY: the child record lock keeps every
                            // published slot stable through this lookup.
                            unsafe { registry.arena_at(index) }.is_some_and(|entry|
                                core::ptr::from_ref(entry) as usize == arena)
                        });
                        (owns_arena,
                         image.identity().vm_statistics().snapshot().purge_calls)
                    }))
                }) }.expect("child record remains live").expect("child image remains live");
                assert!(child_owns_arena, "the child registry publishes the exact external arena");
                assert!(purge_calls > 0, "forced collection purges the child's external OS arena");
                let second = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let mut size = 0;
                    let area = unsafe { crate::source_heap_api::arena_area(
                        arena as *mut core::ffi::c_void, &mut size,
                    ) };
                    assert_eq!(area as usize, aligned);
                    assert_eq!(size, ARENA_MIN_SIZE);
                    let heap = unsafe { crate::source_heap_api::heap_new_in_arena(arena as *mut core::ffi::c_void) };
                    assert!(!heap.is_null());
                    let block = unsafe { crate::source_heap_api::heap_malloc(heap, 96) }
                        .value.expect("second worker selected allocation");
                    assert!(block.as_ptr() as usize >= aligned && (block.as_ptr() as usize) - aligned < ARENA_MIN_SIZE);
                    assert!(unsafe { crate::source_heap_api::arena_contains(
                        arena as *mut core::ffi::c_void, block.as_ptr().cast(),
                    ) });
                    assert_eq!(unsafe { crate::source_api::free(block.as_ptr()) }, crate::source_api::FreeOutcome::Freed);
                    assert!(unsafe { crate::source_heap_api::heap_release(heap, true) });
                    native_collect(true);
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                second.join().expect("second member finished");
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
                let mut residency = 0u8;
                // SAFETY: the external mapping stays owned by this caller
                // after child teardown and mincore writes one output byte.
                assert!(unsafe { crabc_core::mm::mincore_raw(aligned as *mut u8, 4096, &mut residency) }.is_ok());
                // SAFETY: both workers finished, their selected pages and
                // Heaps were released, and child teardown retired the arena;
                // only this caller retains the exact mapped span.
                unsafe { crabc_core::mm::munmap_raw(aligned as *mut u8, ARENA_MIN_SIZE) }.unwrap();
            },
        );
    }

    /// Through the production entry points, a child thread finishes with
    /// live blocks: its pages pass to the child main Heap, another thread
    /// frees one block (the page stays abandoned) and the only block of
    /// another page (the page is released), and `native_subproc_destroy`
    /// then destroys the child with its last block still live.
    /// Pinned `mi_subproc_destroy` destroys a child under a thread that still
    /// belongs to it (`subproc.c:201-257`): the member keeps a live block and
    /// a non-main Heap with a cached Theap and a live block, and stays idle.
    /// The child's statistics merge into main with the member still counted
    /// and its cached Theap for the Heap still live, and the member's later
    /// thread finish touches nothing of the destroyed child.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_subproc_destroy_destroys_a_child_under_its_live_thread() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors, native_allocate_aligned,
            prepare_native_later_thread_arena, test_initialize_process_from_host_environment,
            NativePageAllocationResult, ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_subproc_destroy_destroys_a_child_under_its_live_thread",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("the initial thread creates a child");
                let main = crate::subproc::MainSubprocess::global();
                let before = main.statistics().final_output_snapshot();
                let (ready_send, ready_receive) = std::sync::mpsc::channel();
                let (stop_send, stop_receive) = std::sync::mpsc::channel::<()>();
                let worker = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: the fresh thread registers its own descriptor once.
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    // SAFETY: a fresh thread owns its pristine roots.
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let foreign_heap = core::ptr::NonNull::new(
                        crate::subproc::MainSubprocess::global().ready_main_heap_pointer()
                    ).expect("the process main Heap is live");
                    // SAFETY: the process main Heap remains live for the call.
                    assert!(!unsafe { native_child_heap_select_theap(foreign_heap) });
                    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(200, 16, false)
                        else { panic!("child allocation"); };
                    unsafe { block.as_ptr().write_bytes(0x55, 200) };
                    let heap = native_child_heap_new().expect("a member").expect("a live record").expect("a Heap");
                    let heap_block = unsafe { native_child_heap_allocate(heap, 64) }.expect("a member").expect("a block");
                    unsafe { heap_block.as_ptr().write_bytes(0x66, 64) };
                    ready_send.send(()).unwrap();
                    stop_receive.recv().unwrap();
                    // The destroyed child is not reached again.
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                    assert!(!current_thread_is_child_member());
                });
                ready_receive.recv().unwrap();
                // SAFETY: the member is idle and never uses a child block again.
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
                let after = main.statistics().final_output_snapshot();
                assert_eq!((after.threads.total - before.threads.total, after.threads.current - before.threads.current), (1, 1));
                assert_eq!((after.heaps.total - before.heaps.total, after.heaps.current - before.heaps.current), (2, 0));
                assert_eq!((after.theaps.total - before.theaps.total, after.theaps.current - before.theaps.current), (2, 1));
                stop_send.send(()).unwrap();
                worker.join().expect("the orphaned member finishes");
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn child_arena_admission_retains_original_metadata_across_failed_storage_return() {
        use crate::runtime_lifecycle::{prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment, NativePageFreeResult};
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::child_arena_admission_retains_original_metadata_across_failed_storage_return",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                assert!(NativeChildArenaAdmission::acquire_current().is_none());
                let id = native_subproc_new().expect("root child");
                let worker = std::thread::spawn(move || {
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let admission = NativeChildArenaAdmission::acquire_current().expect("actual child").expect("retained arena admission");
                    let original = unsafe { id.with_owner(|owner| owner.as_mut().unwrap().identity_pointer().unwrap()) }.unwrap();
                    assert_eq!(unsafe { admission.process() }.subprocess() as *const _, original.cast_const());
                    assert!(core::ptr::eq(unsafe { admission.backing() }, unsafe { &*original }.arena_backing()));
                    assert!(unsafe { id.record() }.lock.try_lock().is_some(), "reservation admission parks owner lock");
                    let mut tracker = admission.allocate_tracker(64).expect("original child metadata tracker");
                    let pointer = tracker.pointer();
                    assert!(unsafe { core::slice::from_raw_parts(pointer.as_ptr(), 64) }.iter().all(|byte| *byte == 0));
                    assert_eq!(unsafe { id.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 2);
                    // Ordinary allocation can reenter while the original arena
                    // and metadata capabilities remain retained without locks.
                    let Some(crate::runtime_lifecycle::NativePageAllocationResult::Allocated(client)) =
                        native_child_thread_allocate(80, Some((16, 0)), false) else { panic!("child client"); };
                    assert_eq!(unsafe { crate::runtime_lifecycle::native_free(client) }, NativePageFreeResult::Freed);
                    unsafe { id.with_owner(|owner| owner.as_mut().unwrap().test_fail_next_metadata_session_setup()) }.unwrap();
                    assert_eq!(tracker.free(), Err(MetaError::InitializationRetained));
                    assert_eq!(tracker.pointer(), pointer, "failed return keeps the exact capability");
                    assert_eq!(unsafe { id.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 2);
                    tracker.free().expect("same original metadata release retries");
                    assert_eq!(tracker.free(), Err(MetaError::ForeignOwner), "successful return cannot run twice");
                    assert_eq!(unsafe { id.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 1);
                    drop(admission);
                    assert_eq!(unsafe { id.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 0);
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                });
                worker.join().expect("child reservation metadata controls");
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_huge_teardown_keeps_exact_context_and_failed_page_set_for_retry() {
        use crate::runtime_lifecycle::{prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment};
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_huge_teardown_keeps_exact_context_and_failed_page_set_for_retry",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let child = native_subproc_new().unwrap();
                let creator = std::thread::spawn(move || {
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(child) }, Ok(NativeChildThreadAdd::Added));
                    let admission = NativeChildArenaAdmission::acquire_current().unwrap().unwrap();
                    // Real anonymous mappings stand in only for unavailable
                    // huge primitives. Publication, child ownership, destructive
                    // free, exact failure bits and raw retry use production paths.
                    let allocation = crate::os::HugeOsAllocation::test_registry_allocation(
                        unsafe { admission.process() }, admission.config(), 3);
                    let base = allocation.base().as_ptr().addr();
                    unsafe { admission.backing().install_owned_huge_allocation_for_retained_process(
                        admission.config(), allocation, -1, false) }.unwrap_or_else(|_| panic!("exact child huge publication"));
                    let count = unsafe { admission.backing() }.registry().count();
                    drop(admission);
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                    (base, count)
                });
                let (base, count) = creator.join().unwrap();
                let original = unsafe { child.with_owner(|owner| owner.as_mut().unwrap().identity_pointer().unwrap()) }.unwrap();
                let words = unsafe { child.with_owner(|owner| owner.as_mut().unwrap()
                    .with_child_image(|image| image.identity().arena_backing().terminal_tracking_words()).unwrap().unwrap()) }.unwrap();
                let metadata = crate::meta::MetaAllocator::global();
                let before = metadata.test_allocation_audit().live_capability_count;
                metadata.test_fail_next_direct_zeroed_size(NativeChildArenaDestroyState::tracking_offset()
                    + words * core::mem::size_of::<usize>());
                assert_eq!(unsafe { native_subproc_destroy(child) }, Err(NativeSubprocessError::DestroyRefused(
                    ChildSubprocessDestroyError::TrackingAllocation(MetaError::AllocationUnavailable))));
                assert_eq!(metadata.test_allocation_audit().live_capability_count, before,
                    "failed scratch allocation consumes no parent metadata capability");
                unsafe { child.with_owner(|owner| {
                    let child = owner.as_mut().expect("whole child survives tracking refusal");
                    assert_eq!(child.stage(), ChildMainHeapStage::HeapReady);
                    assert_eq!(child.identity_pointer(), Some(original));
                    child.with_child_image(|image| {
                        assert!(image.identity().is_registered());
                        assert_eq!(image.identity().arena_backing().registry().count(), count);
                    }).unwrap();
                }) }.unwrap();
                let fault = crate::os::fault::install(crate::os::fault::Plan::at(
                    crate::os::fault::Point::Unmap, count + 1, crabc_core::Errno::NOMEM));
                // SAFETY: the only child member finished and every published
                // mapping is unused. The production record owns final teardown.
                assert_eq!(unsafe { native_subproc_destroy(child) }, Err(NativeSubprocessError::Retained));
                std::println!("child-huge.teardown-unmaps={}", fault.observed());
                assert_eq!(fault.observed(), count + 2, "the source pass releases regular backing and attempts all three huge pages");
                let accounted = unsafe { child.with_owner(|owner| {
                    let owner = owner.as_mut().expect("same child context retains unresolved raw free");
                    assert_eq!(owner.identity_pointer(), Some(original));
                    owner.with_child_image(|image| {
                        assert_eq!(image.identity().arena_backing().registry().count(), 0);
                        image.identity().vm_statistics().snapshot()
                    }).unwrap()
                }) }.unwrap();
                let mut resident = 0u8;
                for page in 0..3 {
                    let address = core::ptr::with_exposed_provenance_mut(base + page * crate::config::GIB);
                    assert_eq!(unsafe { crabc_core::mm::mincore_raw(address, 4096, &mut resident) }.is_ok(), page == 1,
                        "only the exact failed huge page remains mapped");
                }
                fault.set(crate::os::fault::Plan::at(crate::os::fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                assert_eq!(unsafe { native_subproc_destroy(child) }, Err(NativeSubprocessError::Retained));
                assert_eq!(fault.observed(), 1, "raw retry reaches only the retained failed page");
                let after = unsafe { child.with_owner(|owner| owner.as_mut().unwrap()
                    .with_child_image(|image| image.identity().vm_statistics().snapshot()).unwrap()) }.unwrap();
                assert_eq!(after, accounted, "raw retry never repeats source accounting");
                fault.set(crate::os::fault::Plan::disabled());
                assert_eq!(unsafe { native_subproc_destroy(child) }, Ok(()));
                assert_eq!(unsafe { crabc_core::mm::mincore_raw(core::ptr::with_exposed_provenance_mut(
                    base + crate::config::GIB), 4096, &mut resident) }.is_ok(), false);
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn terminal_child_tree_releases_parent_issuer_after_permanent_tls_exclusion() {
        use crate::runtime_lifecycle::{prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment, NativeAllocatorThreadDescriptor,
            NativeAllocatorPinnedThreadRegistry};
        struct Registry(std::vec::Vec<core::ptr::NonNull<NativeAllocatorThreadDescriptor>>);
        // SAFETY: this fixture includes the initial descriptor and exactly
        // two registered workers. Both workers remain parked until the sealed
        // child tree has been destroyed, with no registration or removal race.
        unsafe impl NativeAllocatorPinnedThreadRegistry for Registry {
            fn visit_descriptors(&self, visitor: &mut dyn FnMut(core::ptr::NonNull<NativeAllocatorThreadDescriptor>)) {
                for descriptor in &self.0 { visitor(*descriptor); }
            }
        }
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::terminal_child_tree_releases_parent_issuer_after_permanent_tls_exclusion",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let parent = native_subproc_new().unwrap();
                let (created, receive) = std::sync::mpsc::channel();
                let (stop_parent, parked_parent) = std::sync::mpsc::channel::<()>();
                let creator = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(parent) }, Ok(NativeChildThreadAdd::Added));
                    let nested = native_subproc_new().unwrap();
                    created.send((nested, descriptor.as_ptr().expose_provenance())).unwrap();
                    let _ = parked_parent.recv();
                    // Permanent exclusion forbids every further native entry,
                    // including thread finish through these retired TLS roots.
                });
                let (nested, parent_descriptor) = receive.recv().unwrap();
                let (ready, receive) = std::sync::mpsc::channel();
                let (stop_nested, parked_nested) = std::sync::mpsc::channel::<()>();
                let worker = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(nested) }, Ok(NativeChildThreadAdd::Added));
                    ready.send(descriptor.as_ptr().expose_provenance()).unwrap();
                    let _ = parked_nested.recv();
                });
                let nested_descriptor = receive.recv().unwrap();
                let registry = Registry(std::vec![
                    crate::runtime_lifecycle::native_allocator_initial_thread_descriptor().unwrap(),
                    // SAFETY: the parked workers retain their original published
                    // descriptors at these addresses until after child teardown.
                    unsafe { core::ptr::NonNull::new_unchecked(core::ptr::with_exposed_provenance_mut(parent_descriptor)) },
                    unsafe { core::ptr::NonNull::new_unchecked(core::ptr::with_exposed_provenance_mut(nested_descriptor)) },
                ]);
                // SAFETY: all participating descriptors are pinned, no native
                // operation or callback runs, and this fixture never reopens or
                // consults any transferred TLS member after permanent closure.
                let terminal = unsafe { crate::runtime_lifecycle::begin_native_allocator_terminal_quiescence(&registry) }.unwrap();
                drop(terminal);
                assert_eq!(unsafe { destroy_all_native_children_terminal() }, Ok(()),
                    "newest nested child returns issuer custody before its parent retires");
                stop_nested.send(()).unwrap();
                stop_parent.send(()).unwrap();
                worker.join().unwrap();
                creator.join().unwrap();
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn nested_child_terminal_record_retains_its_parent_until_final_tls_finish() {
        use crate::runtime_lifecycle::{prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment};
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::nested_child_terminal_record_retains_its_parent_until_final_tls_finish",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let parent = native_subproc_new().expect("main creates parent child");
                let creator = std::thread::spawn(move || {
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(parent) }, Ok(NativeChildThreadAdd::Added));
                    // Refuse the first exact parent metadata entry before
                    // any context allocation, then retry the same source route.
                    unsafe { parent.with_owner(|owner| owner.as_mut().unwrap().test_fail_next_metadata_session_setup()) }.unwrap();
                    assert_eq!(native_subproc_new(), Err(NativeSubprocessError::New(
                        ChildSubprocessNewError::ContextAllocation(MetaError::InitializationRetained))));
                    assert_eq!(unsafe { parent.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 0,
                        "released creation failure returns independent parent custody");
                    let nested = native_subproc_new().expect("same actual parent retries nested child creation");
                    assert_eq!(unsafe { parent.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 1);
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                    nested
                });
                let nested = creator.join().expect("parent member completes");
                let (ready, entered) = std::sync::mpsc::channel();
                let (finish, resume) = std::sync::mpsc::channel::<bool>();
                let worker = std::thread::spawn(move || {
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(nested) }, Ok(NativeChildThreadAdd::Added));
                    ready.send(()).unwrap();
                    // A failed audit ends without consulting a released child.
                    if !resume.recv().unwrap_or(false) { return; }
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                });
                entered.recv().unwrap();
                // SAFETY: the nested member is parked and its sole subsequent
                // allocator action is final thread finish after source teardown.
                assert_eq!(unsafe { native_subproc_destroy(nested) }, Ok(()));
                // Source child lifetime ended, but its exact parent-issued
                // context still contains the orphaned member's control record.
                // Observe custody before probing parent retirement so a failed
                // regression never lets that member reach freed parent storage.
                let retained = unsafe { parent.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire);
                std::println!("nested-terminal.parent-admissions={retained}");
                assert_eq!(retained, 1, "the exact parent stays owned through the delayed record release");
                // Internal admission check; no caller claims source child use
                // after teardown, and the actual record owner must refuse here.
                assert_eq!(unsafe { destroy_record(parent, ChildHeapRelease::Native) },
                    Err(NativeSubprocessError::DestroyRefused(ChildSubprocessDestroyError::CallbackActive)));
                finish.send(true).unwrap();
                worker.join().expect("last actual nested TLS token releases its record");
                assert_eq!(unsafe { parent.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 0);
                assert_eq!(unsafe { native_subproc_destroy(parent) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_callback_owner_parks_projections_and_releases_nested_leases() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors,
            prepare_native_later_thread_arena, test_initialize_process_from_host_environment,
            NativePageFreeResult, ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_callback_owner_parks_projections_and_releases_nested_leases",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().unwrap();
                let worker = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: this fresh worker owns its descriptor and roots.
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let heap = native_child_heap_new().unwrap().unwrap().unwrap();
                    let block = unsafe { native_child_heap_allocate(heap, 80) }.unwrap().unwrap();
                    // SAFETY: this worker retains its selected Heap and exact
                    // client; the callback performs no selected-owner teardown.
                    assert_eq!(unsafe { with_native_child_callback_owner(heap, |process| {
                        let record = id.record();
                        assert!(record.lock.try_lock().is_some(), "no child lock crosses the callback");
                        assert_eq!(process.subprocess() as *const _, crate::types::Heap::subprocess_pointer_at(heap).cast_const());
                        assert_eq!(record.callback_leases.load(core::sync::atomic::Ordering::Acquire), 1);
                        with_native_child_callback_owner(heap, |_| {
                            assert_eq!(record.callback_leases.load(core::sync::atomic::Ordering::Acquire), 2);
                            // This probes internal admission, not a public
                            // concurrent-destruction contract or source qualification.
                            assert_eq!(destroy_record(id, ChildHeapRelease::Native),
                                Err(NativeSubprocessError::DestroyRefused(ChildSubprocessDestroyError::CallbackActive)));
                            let nested = native_child_heap_allocate(heap, 33).unwrap()
                                .expect("same-Heap allocation reenters after its engine parked");
                            assert_eq!(crate::runtime_lifecycle::native_free(nested), NativePageFreeResult::Freed);
                            7
                        }).unwrap()
                    }) }, Some(7));
                    // SAFETY: both scopes ended; this member still owns the child.
                    assert_eq!(unsafe { id.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 0);
                    assert_eq!(unsafe { crate::runtime_lifecycle::native_free(block) }, NativePageFreeResult::Freed);
                    assert!(unsafe { native_child_heap_release(heap, false) }.unwrap().unwrap().is_ok());
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                worker.join().unwrap();
                // SAFETY: all clients and members ended before destruction.
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_callback_owner_retains_foreign_heap_from_original_registry_allocation() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors,
            prepare_native_later_thread_arena, test_initialize_process_from_host_environment,
            NativePageFreeResult, ThreadFinishResult,
        };
        struct SharedHeap(core::ptr::NonNull<crate::types::Heap>);
        // SAFETY: the worker retains this Heap and its client while parked;
        // channels exclude every teardown and client use during observation.
        unsafe impl Send for SharedHeap {}
        impl SharedHeap { fn pointer(&self) -> core::ptr::NonNull<crate::types::Heap> { self.0 } }
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_callback_owner_retains_foreign_heap_from_original_registry_allocation",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let child = native_subproc_new().unwrap();
                let neighbor = native_subproc_new().unwrap();
                let (ready_send, ready_receive) = std::sync::mpsc::channel();
                let (resume_send, resume_receive) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(child) }, Ok(NativeChildThreadAdd::Added));
                    let heap = native_child_heap_new().unwrap().unwrap().unwrap();
                    let client = unsafe { native_child_heap_allocate(heap, 80) }.unwrap().unwrap();
                    ready_send.send(SharedHeap(heap)).unwrap();
                    resume_receive.recv().unwrap();
                    assert_eq!(unsafe { crate::runtime_lifecycle::native_free(client) }, NativePageFreeResult::Freed);
                    assert!(unsafe { native_child_heap_release(heap, false) }.unwrap().unwrap().is_ok());
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                let heap = ready_receive.recv().unwrap().pointer();
                // An existing record operation may hold the child lock. The
                // registry lookup must refuse without waiting or acquiring a
                // count, then permit admission once that operation ends.
                let (locked_send, locked_receive) = std::sync::mpsc::channel();
                let (unlock_send, unlock_receive) = std::sync::mpsc::channel();
                let locker = std::thread::spawn(move || {
                    // SAFETY: the parked member retains this original child
                    // while the actual owner operation holds its record lock.
                    unsafe { child.with_owner(|owner| {
                        assert!(owner.is_some());
                        locked_send.send(()).unwrap();
                        unlock_receive.recv().unwrap();
                    }) }.unwrap();
                });
                locked_receive.recv().unwrap();
                assert!(unsafe { with_native_child_callback_owner(heap, |_| panic!("contended child is not admitted")) }.is_none());
                assert_eq!(unsafe { try_with_native_child_callback_owner::<()>(heap, |_| panic!("busy acquisition invokes no user code")) },
                    Err(NativeChildCallbackAdmissionError::Busy));
                assert_eq!(unsafe { child.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 0);
                unlock_send.send(()).unwrap();
                locker.join().unwrap();
                // SAFETY: the parked worker retains its real Heap, member and
                // client; this caller observes only scoped owner facts.
                assert_eq!(unsafe { with_native_child_callback_owner(heap, |process| {
                    assert_eq!(process.subprocess() as *const _, crate::types::Heap::subprocess_pointer_at(heap).cast_const());
                    assert_eq!(child.record().callback_leases.load(core::sync::atomic::Ordering::Acquire), 1);
                    assert_eq!(neighbor.record().callback_leases.load(core::sync::atomic::Ordering::Acquire), 0);
                    assert!(child.record().lock.try_lock().is_some());
                    assert_eq!(destroy_record(child, ChildHeapRelease::Native),
                        Err(NativeSubprocessError::DestroyRefused(ChildSubprocessDestroyError::CallbackActive)));
                    // Reentry uses the actual calling thread's process-main
                    // allocator, without substituting its identity for the child.
                    let crate::runtime_lifecycle::NativePageAllocationResult::Allocated(nested) =
                        crate::runtime_lifecycle::native_allocate_aligned(33, 16, false)
                        else { panic!("the foreign caller reenters its own allocator"); };
                    assert_eq!(crate::runtime_lifecycle::native_free(nested), NativePageFreeResult::Freed);
                    11
                }) }, Some(11));
                assert_eq!(unsafe { child.record() }.callback_leases.load(core::sync::atomic::Ordering::Acquire), 0);
                let main_heap = core::ptr::NonNull::new(crate::subproc::MainSubprocess::global().ready_main_heap_pointer()).unwrap();
                assert!(unsafe { with_native_child_callback_owner(main_heap, |_| panic!("main is not a child owner")) }.is_none());
                assert_eq!(unsafe { try_with_native_child_callback_owner::<()>(main_heap, |_| panic!("invalid domain invokes no user code")) },
                    Err(NativeChildCallbackAdmissionError::Invalid));
                resume_send.send(()).unwrap();
                worker.join().unwrap();
                // SAFETY: all members and clients ended before destruction.
                assert_eq!(unsafe { native_subproc_destroy(child) }, Ok(()));
                assert_eq!(unsafe { native_subproc_destroy(neighbor) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn child_thread_teardown_removes_freed_metadata_custody_on_late_release_error() {
        use crate::runtime_lifecycle::{prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment};
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::child_thread_teardown_removes_freed_metadata_custody_on_late_release_error",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                // Select genuine OS pages so retiring an empty metadata page
                // reaches the mapping release boundary instead of an arena slice.
                crate::source_options_api::option_set(crate::config::SourceOption::ArenaReserve as i32, 0);
                crate::source_options_api::option_set(crate::config::SourceOption::DisallowArenaAlloc as i32, 1);
                let id = native_subproc_new().expect("a live child");
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().expect("ready parent");
                // Ordinary metadata clients fill one real source page. The
                // next worker's Theap must therefore occupy a separate page.
                let mut fillers = unsafe { id.with_owner(|owner| {
                    owner.as_mut().expect("live child").with_metadata_page_engine(binding, |_, engine| {
                        let first = engine.allocate_zeroed(core::mem::size_of::<Theap>())
                            .expect("first metadata client");
                        // SAFETY: this exact current client retains its page
                        // for the bounded immutable backing-kind observation.
                        assert!(unsafe { (*engine.page_for_block(first)).memid().is_os() },
                            "the fault control uses a real OS-backed metadata page");
                        let reserved = unsafe { engine.current_allocation_page_reserved(first) }
                            .expect("live page reservation");
                        let mut clients = std::vec![first];
                        while clients.len() < reserved {
                            clients.push(engine.allocate_zeroed(core::mem::size_of::<Theap>())
                                .expect("same source class metadata client"));
                        }
                        clients
                    }).expect("complete metadata operation")
                }) }.expect("child lock");
                let (ready, entered) = std::sync::mpsc::channel();
                let (finish, resume) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    assert!(unsafe {
                        crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(
                            crate::runtime_lifecycle::current_native_allocator_thread_descriptor())
                    });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    ready.send(()).expect("worker ready");
                    resume.recv().expect("finish permission");
                    let fault = crate::os::fault::install(crate::os::fault::Plan::at(
                        crate::os::fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                    let result = native_child_thread_done();
                    std::println!("teardown.result={result:?}; unmaps={}", fault.observed());
                    assert_eq!(fault.observed(), 1, "the real release fault is reached");
                    assert!(matches!(result, Some(Err(_))));
                    let current = unsafe { current_child_member() }.as_ref().expect("actual retained member");
                    std::println!("teardown.theap_custody={}", current.member.owner.theap_pointer().is_some());
                    assert!(current.member.owner.theap_pointer().is_none(),
                        "consumed metadata storage is not left as a live TLS block token");
                    // The failed mapping stays with the retained child. No
                    // released image or registration is used again.
                });
                entered.recv().expect("registered worker");
                // Return one actual client from the full page. Two ordinary
                // same-class pages now exist, so source retirement releases
                // the worker's empty page immediately instead of delaying it.
                let filler = fillers.remove(0);
                unsafe { id.with_owner(|owner| {
                    owner.as_mut().expect("live child").with_metadata_page_engine(binding, |_, engine| {
                        unsafe { engine.free(filler) }.expect("owned filler returned once");
                    }).expect("complete metadata operation")
                }) }.expect("child lock");
                finish.send(()).expect("worker may finish");
                worker.join().expect("retained-error control completes");
                // Remaining clients and their child stay retained; this fault
                // control does not destroy a context carrying release rights.
                let _ = fillers;
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn child_destroy_retains_record_until_failed_teardown_member_finishes() {
        use crate::runtime_lifecycle::{prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment};
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::child_destroy_retains_record_until_failed_teardown_member_finishes",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("a live child");
                let (retained, observed) = std::sync::mpsc::channel();
                let (terminal, complete) = std::sync::mpsc::channel::<bool>();
                let worker = std::thread::spawn(move || {
                    assert!(unsafe {
                        crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(
                            crate::runtime_lifecycle::current_native_allocator_thread_descriptor())
                    });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    // The actual teardown removes source registration before
                    // admitting the metadata engine that returns its images.
                    unsafe { id.with_owner(|owner| {
                        owner.as_mut().expect("live child").test_fail_next_metadata_session_setup();
                    }) }.expect("exclusive child failure control");
                    assert_eq!(native_child_thread_done(), Some(Err(NativeChildThreadDoneError::Done(
                        ChildThreadDoneError::Teardown(crate::meta::ChildThreadTeardownError::PageEngine(
                            crate::meta::ChildMetadataPageEngineError::SessionNotReady))))));
                    let current = unsafe { current_child_member() }.as_ref().expect("actual retained TLS member");
                    assert!(current.member.owner.theap_pointer().is_some(),
                        "a refused engine admission consumes no metadata client");
                    retained.send(()).expect("failed member parked");
                    // An audit failure ends this worker without consulting
                    // any child record, image, root, or allocation again.
                    if !complete.recv().unwrap_or(false) { return; }
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                    assert!(unsafe { current_child_member() }.is_none());
                });
                observed.recv().expect("actual TLS member retained after failure");
                // SAFETY: the worker is parked outside allocator operations;
                // its actual TLS capability remains retained until signalled.
                let context_address = unsafe { id.with_owner(|owner| {
                    let child = owner.as_mut().expect("live retained child");
                    assert_eq!(child.with_child_image(|image| image.get_ref().identity().live_thread_count()), Some(0));
                    child.with_child_image(|image| core::ptr::from_ref(image.get_ref()).addr()).unwrap()
                }) }.expect("exclusive source registration observation");
                let metadata = crate::meta::MetaAllocator::global();
                let before = metadata.test_allocation_audit().live_capability_count;
                // SAFETY: every child client is permanently quiescent. The
                // worker's next allocator operation is its own terminal finish.
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
                let after = metadata.test_allocation_audit().live_capability_count;
                std::println!("retained-record.before={before}; after={after}");
                assert_eq!(after + 1, before,
                    "metadata Theap returns while actual TLS retains the enclosing context capability");
                // SAFETY: the parked actual member retains the record and no
                // finish or other record operation can overlap this observation.
                let retained_context = unsafe { (*id.record().storage.get()).as_ref()
                    .expect("context custody moved to its embedded control").pointer().as_ptr().addr() };
                assert_eq!(retained_context, context_address,
                    "terminal control retains the original parent-issued context allocation");
                terminal.send(true).expect("audited record remains allocated");
                worker.join().expect("actual retained member completes terminal finish");
                assert_eq!(metadata.test_allocation_audit().live_capability_count + 1, after,
                    "the last real TLS member returns the enclosing context capability exactly once");
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn child_guarded_canonical_transport_uses_original_main_and_auxiliary_issuers() {
        use crate::runtime_lifecycle::{finish_current_thread_native_after_user_destructors,
            prepare_native_later_thread_arena, test_initialize_process_from_host_environment,
            with_native_allocation_owner, NativeGuardedCanonicalAllocationProgress, ThreadFinishResult};
        use crate::single_thread::LocalClientFreeProgress;
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::child_guarded_canonical_transport_uses_original_main_and_auxiliary_issuers",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("a live child");
                std::thread::spawn(move || {
                    assert!(unsafe {
                        crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(
                            crate::runtime_lifecycle::current_native_allocator_thread_descriptor())
                    });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let main = current_child_main_heap().expect("actual child main Heap");
                    let auxiliary = native_child_heap_new().unwrap().unwrap().unwrap();
                    for heap in [main, auxiliary] {
                        // SAFETY: this worker retains both actual child Heaps
                        // and its own member through each selection and scope.
                        let theap = unsafe { native_child_heap_theap(heap) }.expect("actual selected issuer");
                        // SAFETY: original owner admission precedes every
                        // canonical candidate and remains held through cleanup.
                        assert_eq!(unsafe { with_native_allocation_owner(theap, |owner| {
                            assert_eq!(owner.selected_theap(), theap);
                            let result = unsafe { native_child_theap_allocate_guarded_canonical(theap, 8192) };
                            let NativeGuardedCanonicalAllocationProgress::Complete(Some(block)) = result
                                else { panic!("healthy selected child source attempt completes"); };
                            // SAFETY: the original admitted owner retains the
                            // canonical client and its exact PageMap metadata.
                            let captured = unsafe { owner.page_map().unwrap().lookup_live_allocation(block) }
                                .unwrap().expect("original canonical source client");
                            assert_eq!(unsafe { native_child_theap_free_captured_with_progress(theap, captured) },
                                Some(LocalClientFreeProgress::Consumed(Ok(()))));
                            // The consumed client is never accessed or freed again.
                        }) }, Ok(()));
                    }
                    // SAFETY: the auxiliary canonical client was consumed and
                    // every original allocation scope ended before Heap release.
                    assert!(unsafe { native_child_heap_release(auxiliary, false) }.unwrap().unwrap().is_ok());
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                }).join().expect("both actual selected child issuers complete");
                // SAFETY: all actual member tokens and clients ended before destruction.
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn child_fresh_os_assertion_retains_original_issuer_during_output_reentry() {
        use crate::process_page_map::ProcessPageMapRoot;
        use crate::types::{Page, PageValiditySnapshot, Theap};
        use core::ptr::NonNull;
        const CHILD: &str = "CRABC_CHILD_FRESH_OS_ASSERTION";
        struct Probe {
            id: NativeSubprocessId,
            theap: NonNull<Theap>,
            map: ProcessPageMapRoot,
            observed: core::cell::Cell<Option<(NonNull<Page>, NonNull<u8>, usize)>>,
        }
        unsafe fn observe(state: &PageValiditySnapshot, page: NonNull<Page>, argument: *mut core::ffi::c_void) {
            // SAFETY: the scoped fixture and engine retain this probe and the
            // original fresh committed backing. No client or list is published.
            let probe = unsafe { &*argument.cast::<Probe>() };
            assert!(probe.observed.get().is_none());
            assert_eq!(state.used, 0);
            assert_eq!(state.capacity, 0);
            assert!(state.free.is_null());
            assert_eq!(unsafe { probe.map.lookup_registered_page(state.area.as_ptr()) }.unwrap(), Some(page));
            probe.observed.set(Some((page, state.area, state.area_bytes)));
            // SAFETY: only the engine and observer own this initialized byte
            // of the unpublished committed block area.
            unsafe { state.area.as_ptr().write(0x5a) };
        }
        unsafe fn passive(_: &PageValiditySnapshot, _: NonNull<Page>, _: *mut core::ffi::c_void) {}
        unsafe extern "C" fn output(message: *const core::ffi::c_char, argument: *mut core::ffi::c_void) {
            unsafe extern "C" { fn write(fd: core::ffi::c_int, bytes: *const u8, size: usize) -> isize; }
            // SAFETY: synchronous assertion delivery retains the registered
            // argument, original candidate, selected issuer and child admission.
            let probe = unsafe { &*argument.cast::<Probe>() };
            let message = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if message.starts_with(b"mimalloc: assertion failed:") {
                let (page, area, bytes) = probe.observed.get().expect("real observation before dispatch");
                assert_eq!(current_child_id(), Some(probe.id));
                assert!(matches!(native_child_thread_done(), Some(Err(
                    NativeChildThreadDoneError::Subprocess(NativeSubprocessError::Retained)))));
                let heap = NonNull::new(unsafe { Theap::heap_at(probe.theap) }).unwrap();
                // SAFETY: the actual scope retains this Heap. Release is an
                // admission attempt and must refuse before any detach or free.
                assert!(matches!(unsafe { native_child_heap_release(heap, true) },
                    Some(Err(NativeSubprocessError::Retained))));
                assert_eq!(unsafe { probe.map.lookup_registered_page(area.as_ptr()) }.unwrap(), Some(page));
                let state = unsafe { Page::validity_snapshot_at(page) };
                assert_eq!((state.used, state.capacity), (0, 0));
                assert!(state.free.is_null());
                assert!(state.local_free.is_null());
                // Every engine/member projection ended before this actual
                // native reentry; the unfinished candidate remains registered.
                let nested = unsafe { crate::page_validity::with_fresh_page_initialization_observer_for_test(
                    passive, core::ptr::null_mut(), || native_child_theap_allocate(probe.theap, 96, false)
                ) }.unwrap().expect("original selected child issuer permits ordinary reentry");
                assert!(nested.addr().get() < area.addr().get() || nested.addr().get() >= area.addr().get() + bytes);
                assert_eq!(unsafe { crate::runtime_lifecycle::native_free(nested) },
                    crate::runtime_lifecycle::NativePageFreeResult::Freed);
                assert_eq!(unsafe { probe.map.lookup_registered_page(area.as_ptr()) }.unwrap(), Some(page));
                assert_eq!(unsafe { area.as_ptr().read() }, 0x5a);
                let marker = b"original child fresh backing retained during native reentry\n";
                assert_eq!(unsafe { write(2, marker.as_ptr(), marker.len()) }, marker.len() as isize);
            }
            assert_eq!(unsafe { write(2, message.as_ptr(), message.len()) }, message.len() as isize);
        }
        if let Some(selected) = std::env::var_os(CHILD) {
            assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(no_output) }));
            assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
            let id = native_subproc_new().expect("actual child source owner");
            std::thread::spawn(move || {
                assert!(unsafe { crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(
                    crate::runtime_lifecycle::current_native_allocator_thread_descriptor()) });
                assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                let heap = if selected == "auxiliary" { native_child_heap_new().unwrap().unwrap().unwrap() }
                    else { current_child_main_heap().unwrap() };
                let theap = unsafe { native_child_heap_theap(heap) }.unwrap();
                crate::source_options_api::option_set(crate::config::SourceOption::ArenaReserve as i32, 0);
                crate::source_options_api::option_set(crate::config::SourceOption::DisallowArenaAlloc as i32, 1);
                // SAFETY: actual READY owner admission precedes the candidate,
                // with this worker retaining its original member and Heap.
                unsafe { crate::runtime_lifecycle::with_native_allocation_owner(theap, |owner| {
                    let probe = Probe { id, theap, map: owner.page_map().unwrap(),
                        observed: core::cell::Cell::new(None) };
                    owner.output().register_output(Some(output), core::ptr::from_ref(&probe).cast_mut().cast());
                    crate::page_validity::with_fresh_page_initialization_observer_for_test(
                        observe, core::ptr::from_ref(&probe).cast_mut().cast(), || {
                            let _ = native_child_theap_allocate_variant(theap, 7, Some((128 * 1024, 0)), false);
                            panic!("actual source zero assertion cannot return");
                        });
                }) }.expect("original selected child READY admission");
            }).join().unwrap();
            return;
        }
        use std::os::unix::process::ExitStatusExt;
        for selected in ["main", "auxiliary"] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "subproc::lifecycle::tests::child_fresh_os_assertion_retains_original_issuer_during_output_reentry",
                    "--nocapture", "--test-threads=1"])
                .current_dir(std::env::temp_dir()).env(CHILD, selected).output().unwrap();
            let stderr = std::string::String::from_utf8_lossy(&result.stderr);
            assert_eq!(result.status.signal(), Some(6), "{selected}: {stderr}");
            assert!(stderr.contains("original child fresh backing retained during native reentry"), "{selected}: {stderr}");
            assert!(stderr.contains("mi_mem_is_zero(page_start, mi_page_committed(page))"), "{selected}: {stderr}");
        }
    }

    /// A live Heap of one child cannot become another child's cached Theap.
    /// Both child images remain live during the attempted selection.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_heap_selector_refuses_another_childs_heap() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors, prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment, ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_heap_selector_refuses_another_childs_heap",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let first = native_subproc_new().expect("the first child");
                let second = native_subproc_new().expect("the second child");
                let (heap_send, heap_receive) = std::sync::mpsc::channel();
                let (release_send, release_receive) = std::sync::mpsc::channel::<()>();
                let owner = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(first) }, Ok(NativeChildThreadAdd::Added));
                    let heap = native_child_heap_new().expect("a member").expect("a live child").expect("a Heap");
                    heap_send.send(heap.as_ptr().addr()).unwrap();
                    release_receive.recv().unwrap();
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                let foreign_address = heap_receive.recv().unwrap();
                let probe = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(second) }, Ok(NativeChildThreadAdd::Added));
                    let foreign = core::ptr::NonNull::new(foreign_address as *mut crate::types::Heap).unwrap();
                    // SAFETY: the first child holds this Heap live until the probe returns.
                    if unsafe { native_child_heap_select_theap(foreign) } {
                        // A foreign Theap may now be linked into both child
                        // lifecycles, so stop before either one is destroyed.
                        std::process::exit(3);
                    }
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                probe.join().expect("the foreign Heap is refused");
                release_send.send(()).unwrap();
                owner.join().expect("the owning thread finishes");
                assert_eq!(unsafe { native_subproc_destroy(second) }, Ok(()));
                assert_eq!(unsafe { native_subproc_destroy(first) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_child_heap_theap_reselects_the_main_cache() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors, prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment, ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::public_child_heap_theap_reselects_the_main_cache",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("a live child");
                std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let main = current_child_main_heap().expect("the child main Heap");
                    let heap = native_child_heap_new().expect("a member").expect("a live child").expect("a Heap");
                    // SAFETY: this thread retains both child Heaps through the selections.
                    let other = unsafe { crate::source_heap_api::heap_theap(heap.as_ptr().cast()) };
                    assert!(!other.is_null());
                    assert_eq!(crate::compiler_tls::cached_theap().as_ptr().cast(), other);
                    let base = crate::compiler_tls::default_theap();
                    assert_ne!(crate::compiler_tls::cached_theap(), base);
                    // SAFETY: the child main Heap remains live for this thread.
                    let selected = unsafe { crate::source_heap_api::heap_theap(main.as_ptr().cast()) };
                    assert_eq!(selected, base.as_ptr().cast());
                    assert_eq!(crate::compiler_tls::cached_theap(), base);
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                }).join().expect("the child worker completes");
                // SAFETY: the worker has finished and no child Heap has users.
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_child_theap_direct_allocation_and_default_restore() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors, native_free, prepare_native_later_thread_arena,
            test_initialize_process_from_host_environment, NativePageFreeResult, ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::public_child_theap_direct_allocation_and_default_restore",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("a live child");
                std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let heap = native_child_heap_new().expect("a member").expect("a live child").expect("a Heap");
                    let heap_ptr = heap.as_ptr().cast();
                    // SAFETY: this thread retains the child Heap and its selected Theap.
                    let selected = unsafe { crate::source_heap_api::heap_theap(heap_ptr) };
                    assert!(!selected.is_null());
                    let base = crate::source_heap_api::theap_get_default();
                    let main = current_child_main_heap().expect("the child main Heap");
                    // SAFETY: this thread retains the child main Heap.
                    assert_eq!(unsafe { crate::source_heap_api::heap_theap(main.as_ptr().cast()) }, base);
                    let cached = crate::compiler_tls::cached_theap();
                    // SAFETY: the selected Theap and Heap remain live.
                    let direct = unsafe { crate::source_heap_api::theap_malloc(selected, 48, false) }.value.expect("direct block");
                    assert_eq!(crate::compiler_tls::cached_theap(), cached);
                    assert_eq!(unsafe { crate::source_heap_api::heap_of(direct.as_ptr()) }, heap_ptr);
                    // SAFETY: the candidate is this thread's initialized live Theap.
                    assert_eq!(unsafe { crate::source_heap_api::theap_set_default(selected) }, base);
                    let default_block = crate::source_api::malloc(80).value.expect("default block");
                    assert_eq!(crate::source_heap_api::theap_get_default(), selected);
                    assert_eq!(crate::compiler_tls::cached_theap(), cached);
                    assert_eq!(unsafe { crate::source_heap_api::heap_of(default_block.as_ptr()) }, heap_ptr);
                    // SAFETY: the original default remains live until restoration.
                    assert_eq!(unsafe { crate::source_heap_api::theap_set_default(base) }, selected);
                    assert_eq!(crate::source_heap_api::theap_get_default(), base);
                    assert_eq!(unsafe { native_free(default_block) }, NativePageFreeResult::Freed);
                    assert_eq!(unsafe { native_free(direct) }, NativePageFreeResult::Freed);
                    assert!(unsafe { crate::source_heap_api::heap_release(heap_ptr, true) });
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                }).join().expect("the child worker completes");
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_thread_finishes_with_live_blocks_and_the_child_is_destroyed() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
            prepare_native_later_thread_arena, test_initialize_process_from_host_environment,
            NativePageAllocationResult, NativePageFreeResult, ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_thread_finishes_with_live_blocks_and_the_child_is_destroyed",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("the initial thread creates a child");
                let blocks = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: the fresh thread registers its own descriptor once.
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    // SAFETY: a fresh thread owns its pristine roots.
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let allocate = |size| match native_allocate_aligned(size, 16, false) {
                        NativePageAllocationResult::Allocated(block) => block.as_ptr().addr(),
                        _ => panic!("child allocation"),
                    };
                    let blocks = [allocate(64), allocate(64), allocate(3000)];
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                    blocks
                })
                .join()
                .expect("the child thread finishes with live blocks");
                let free = |address: usize| {
                    // SAFETY: each block is live and freed once.
                    unsafe { native_free(core::ptr::NonNull::new(address as *mut u8).unwrap()) }
                };
                assert_eq!(free(blocks[0]), NativePageFreeResult::Freed, "the page stays abandoned");
                assert_eq!(free(blocks[2]), NativePageFreeResult::Freed, "the page is released");
                // SAFETY: the id is live and the remaining block is never used again.
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
    }

    /// The production entry points in a fresh runtime process. Two fresh
    /// registered threads join one child and then allocate, reallocate, and
    /// free through the ordinary native runtime entry points, which route
    /// them to their own child Theaps: concurrently, with blocks freed across
    /// child threads and between the child and the main subprocess. A child
    /// thread creates and deletes a non-main Heap. Ordinary destruction refuses while
    /// the threads belong to the child; they finish through the runtime's
    /// thread-exit entry, and a runtime worker other than the creator
    /// destroys the child.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_child_threads_allocate_concurrently_and_another_thread_destroys() {
        use crate::runtime_lifecycle::{
            attach_current_thread, finish_current_thread_native_after_user_destructors,
            native_allocate_aligned, native_free, native_reallocate, native_usable_size,
            prepare_native_later_thread_arena, test_initialize_process_from_host_environment,
            NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
            ThreadFinishResult,
        };
        use core::sync::atomic::{AtomicPtr, Ordering};

        fn allocate(size: usize) -> core::ptr::NonNull<u8> {
            match native_allocate_aligned(size, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!("native allocation failed"),
            }
        }
        fn free(block: core::ptr::NonNull<u8>) {
            // SAFETY: each block is a live native allocation freed once.
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        }
        fn register() {
            let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
            // SAFETY: the fresh thread registers its own descriptor once.
            assert!(unsafe {
                crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
            });
        }

        crate::test_process::run_in_fresh_process(
            "subproc::lifecycle::tests::native_child_threads_allocate_concurrently_and_another_thread_destroys",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("the initial thread creates a child");
                let mut heaps = 0;
                assert_eq!(unsafe { native_subproc_visit_heaps(id, |_| { heaps += 1; true }) }, Ok(true));
                assert_eq!(heaps, 1, "a new child has only its main Heap");
                // A main-subprocess block that a child thread frees.
                let main_block = allocate(48);
                let main_block_slot = AtomicPtr::new(main_block.as_ptr());
                // Blocks each child thread hands to the other, and one to main.
                let handoff = [AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut())];
                let to_main = AtomicPtr::new(core::ptr::null_mut());

                let admitted = std::sync::Barrier::new(3);
                let exchanged = std::sync::Barrier::new(3);
                let holding = std::sync::Barrier::new(3);
                let release = std::sync::Barrier::new(3);
                std::thread::scope(|scope| {
                    for index in 0..2 {
                        let (admitted, exchanged, holding, release) = (&admitted, &exchanged, &holding, &release);
                        let (handoff, to_main, main_block_slot) = (&handoff, &to_main, &main_block_slot);
                        scope.spawn(move || {
                            register();
                            // SAFETY: a fresh thread owns its pristine roots.
                            assert_eq!(unsafe { native_subproc_add_current_thread(id) },
                                Ok(NativeChildThreadAdd::Added));
                            assert_eq!(unsafe { native_subproc_add_current_thread(id) },
                                Ok(NativeChildThreadAdd::AlreadyInitialized { in_other_subprocess: false }));
                            admitted.wait();
                            let mut kept = allocate(64);
                            for round in 0..256usize {
                                let next = allocate(64 + round % 3 * 64);
                                // SAFETY: `next` holds at least 64 bytes.
                                unsafe { next.as_ptr().write_bytes(round as u8, 64) };
                                free(core::mem::replace(&mut kept, next));
                            }
                            // SAFETY: `kept` is live; the result replaces it.
                            let grown = match unsafe { native_reallocate(Some(kept), 4096) } {
                                NativePageAllocationResult::Allocated(block) => block,
                                _ => panic!("child reallocation failed"),
                            };
                            assert_eq!(unsafe { *grown.as_ptr() }, 255, "reallocation keeps the prefix");
                            assert!(unsafe { native_usable_size(grown) }.is_some_and(|size| size >= 4096));
                            // A non-main Heap lives and dies on this thread.
                            let heap = native_child_heap_new()
                                .expect("a child member").expect("the child record is live")
                                .expect("the child thread creates a Heap");
                            assert_eq!(
                                unsafe { native_child_heap_release(heap, false) },
                                Some(Ok(Ok(crate::types::heap_registry::lifecycle::HeapReleaseOutcome::Released))),
                            );
                            handoff[index].store(allocate(32).as_ptr(), Ordering::Release);
                            if index == 0 {
                                to_main.store(allocate(32).as_ptr(), Ordering::Release);
                                free(core::ptr::NonNull::new(main_block_slot.swap(core::ptr::null_mut(), Ordering::AcqRel)).unwrap());
                            }
                            exchanged.wait();
                            // Free the other child thread's block remotely.
                            free(core::ptr::NonNull::new(handoff[1 - index].swap(core::ptr::null_mut(), Ordering::AcqRel)).unwrap());
                            holding.wait();
                            release.wait();
                            free(grown);
                            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                        });
                    }
                    admitted.wait();
                    exchanged.wait();
                    free(core::ptr::NonNull::new(to_main.swap(core::ptr::null_mut(), Ordering::AcqRel)).unwrap());
                    holding.wait();
                    release.wait();
                });

                std::thread::scope(|scope| {
                    scope.spawn(|| {
                        register();
                        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                        // SAFETY: the id is live and no child block is used again.
                        assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
                        assert_eq!(
                            finish_current_thread_native_after_user_destructors(),
                            ThreadFinishResult::Finished,
                        );
                    }).join().expect("a runtime worker destroys the child");
                });
            },
        );
    }

}

/// Scheduling observations for isolated subprocess ownership regressions.
/// Ordinary allocator builds contain neither the callback slot nor these calls.
#[cfg(feature = "native-runtime-test-audit")]
pub mod child_destroy_finish_test_audit {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Event {
        FinishLeaseBeforeChildLock,
        FinishWaitingForDetach,
        DetachClaimBeforeEdgeClear,
        DetachedBeforeNextMember,
        DestroyBusyBeforeUnlock,
        FinishErrorAfterUnlock,
    }

    type Callback = unsafe fn(Event);

    struct CallbackSlot {
        locked: AtomicBool,
        callback: UnsafeCell<Option<Callback>>,
    }

    // SAFETY: every access to the callback word holds the atomic slot lock.
    unsafe impl Sync for CallbackSlot {}

    static SLOT: CallbackSlot = CallbackSlot {
        locked: AtomicBool::new(false),
        callback: UnsafeCell::new(None),
    };

    fn with_slot<R>(body: impl FnOnce(&mut Option<Callback>) -> R) -> R {
        while SLOT.locked.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed,
        ).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: this holder exclusively owns the callback word. The short
        // closure only copies or replaces the word and cannot invoke a callback.
        let result = body(unsafe { &mut *SLOT.callback.get() });
        SLOT.locked.store(false, Ordering::Release);
        result
    }

    #[must_use = "keep the scheduling callback installed until all observed operations join"]
    pub struct InstalledCallback(());

    impl Drop for InstalledCallback {
        fn drop(&mut self) {
            with_slot(|slot| *slot = None);
        }
    }

    /// Installs one allocation-free event observer.
    ///
    /// # Safety
    /// The callback must not unwind, reenter the allocator, or inspect allocator
    /// storage. It may pause a calling thread using test-owned synchronization.
    /// The caller retains all callback state until every observed operation has
    /// joined, and drops the returned guard only after those operations finish.
    /// An event grants no permission to access child, TLD, or TLS marker storage.
    pub unsafe fn install(callback: Callback) -> Option<InstalledCallback> {
        with_slot(|slot| {
            if slot.is_some() { return None; }
            *slot = Some(callback);
            Some(InstalledCallback(()))
        })
    }

    pub(crate) fn notify(event: Event) {
        let callback = with_slot(|slot| *slot);
        if let Some(callback) = callback {
            // SAFETY: installation retains callback state through all operations;
            // the slot lock is released before any scheduling rendezvous.
            unsafe { callback(event) };
        }
    }
}
