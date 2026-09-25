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
//! operations without a child or PageMap lock, and destruction refuses while
//! any member's registration keeps the child's live thread count raised.
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
//! Not yet covered: nested children, deferred-free callbacks on the child
//! allocation route. Live
//! child metadata blocks at destruction are released with the child arenas,
//! as in source. The source `_mi_thread_locals_thread_done` call in
//! `mi_subproc_destroy` releases the destroying thread's dynamic thread-local
//! table, which no child lifecycle here allocates.

use crate::main_heap_page::{
    MainHeapThreadOwnerLocalPageEngine, MainHeapThreadOwnerLocalPageEngineAccessError,
};
use crate::main_heap_thread::{MainHeapThreadAttachment, MainHeapThreadAttachmentError};
use crate::meta::{
    ChildContextCreateFailure, ChildContextCreateStage, ChildContextOwner,
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
        new_child_with(registry, metadata, parent, config, || {
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
    metadata: core::pin::Pin<&'static crate::meta::MetaAllocator>,
    parent: &'static crate::subproc::MainSubprocess,
    config: crate::os::MemoryConfig,
    allocate_heap: impl FnOnce() -> Result<ChildHeapStorage<'heap>, ChildSubprocessNewError>,
) -> Result<ChildMainHeapContextOwner<'heap>, ChildSubprocessNewFailure<'heap>> {
    let released = |error| Err(ChildSubprocessNewFailure::Released(error));

    // subproc.c:161-172: child image, then metadata Theap (whose failure
    // frees the child image first; `allocate` performs that rollback).
    let mut context = match ChildContextOwner::allocate(metadata, parent, config) {
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
    let registered = context
        .with_image(|child| {
            // SAFETY: the owner pins the exact parent-issued child image and
            // its Malloc provenance; the caller excludes racing registry
            // teardown and the parent is the registry's main member.
            unsafe { registry.initialize_child(child.as_ref().get_ref(), parent, memory) }
        })
        .unwrap_or(Err(SourceSubprocessRegistryError::InvalidMembership));
    if let Err(error) = registered {
        // A refusal before list insertion leaves the image unpublished; a
        // lock failure after insertion makes `release_unpublished` refuse.
        return match context.release_unpublished() {
            Ok(()) => released(ChildSubprocessNewError::Registry(error)),
            Err(failure) => Err(ChildSubprocessNewFailure::Retained(
                ChildSubprocessRetained::Context { owner: failure.owner, stage: failure.stage },
            )),
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
                Err(failure) => Err(ChildSubprocessNewFailure::Retained(
                    ChildSubprocessRetained::Context { owner: failure.owner, stage: failure.stage },
                )),
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
    /// The owner is not a created child or is terminally retained.
    InvalidState,
    Attachment(MainHeapThreadAttachmentError),
    /// Registry unlink or the metadata-page drain that must precede it.
    Registry(ChildMetadataPageEngineError),
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
            ChildHeapRelease::Parent { heap_owner, attachment },
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
) -> Result<(), ChildSubprocessDestroyFailure<'heap, 'tracking>> {
    // Process destruction destroys a child that threads may still belong to.
    let terminal = matches!(release, ChildHeapRelease::Terminal);
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
/// meanwhile; the member's registration keeps the child's live thread count
/// raised, and destruction refuses until [`Self::thread_done`] completes.
/// Dropping a member without `thread_done` leaves the roots installed and
/// the child retained, as dropping its `ChildThreadOwner` does.
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
    /// This record's own parent-metadata block, moved out to free it.
    storage: core::cell::UnsafeCell<Option<crate::meta::MetaAllocation<'static>>>,
    registry: &'static SourceSubprocessRegistry,
}

// SAFETY: every access to the two cells happens with `lock` held, except the
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
    unsafe fn with_owner<R>(
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
    // The Rust record is allocated first so that no child state exists when
    // it fails; source has no such record.
    let mut storage = metadata
        .zalloc_for_main_subprocess(config, parent, core::mem::size_of::<NativeChildSubprocess>())
        .map_err(NativeSubprocessError::RecordAllocation)?;
    let record = storage.pointer().cast::<NativeChildSubprocess>();
    if record.as_ptr().addr() % core::mem::align_of::<NativeChildSubprocess>() != 0 {
        return match metadata.free(&mut storage) {
            Ok(()) => Err(NativeSubprocessError::RecordAllocation(crate::meta::MetaError::InitializationRetained)),
            Err(_) => Err(NativeSubprocessError::Retained),
        };
    }
    // SAFETY: the registry holds `parent` as its main member once startup is
    // READY; `metadata` is the parent's allocator; the native allocation runs
    // on this thread; nothing else can observe the new child yet.
    let child = unsafe {
        new_child_with(registry, metadata, parent, config, || {
            crate::meta::NativeChildHeapImage::allocate()
                .map(ChildHeapStorage::Native)
                .ok_or(ChildSubprocessNewError::HeapAllocation)
        })
    };
    let child = match child {
        Ok(child) => child,
        Err(ChildSubprocessNewFailure::Released(error)) => {
            return match metadata.free(&mut storage) {
                Ok(()) => Err(NativeSubprocessError::New(error)),
                Err(_) => Err(NativeSubprocessError::Retained),
            };
        }
        // The retained owners are dropped without freeing anything.
        Err(ChildSubprocessNewFailure::Retained(_)) => return Err(NativeSubprocessError::Retained),
    };
    // SAFETY: the block is exclusively owned, zeroed, large enough, and
    // aligned for the record, which is written whole before the id escapes.
    unsafe {
        record.as_ptr().write(NativeChildSubprocess {
            lock: crate::lock::PrivateLock::new(),
            owner: core::cell::UnsafeCell::new(Some(child)),
            storage: core::cell::UnsafeCell::new(Some(storage)),
            registry,
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

/// The child membership of the current thread, set by
/// [`native_subproc_add_current_thread`] and cleared by
/// [`native_child_thread_done`]. The native runtime allocation entry points
/// route an admitted thread's allocations and local frees through `member`.
struct CurrentChildMember {
    id: NativeSubprocessId,
    binding: ProcessMainBackingBinding,
    member: ChildThreadMember,
}

#[thread_local]
static CURRENT_CHILD_MEMBER: core::cell::UnsafeCell<Option<CurrentChildMember>> =
    core::cell::UnsafeCell::new(None);

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
    unsafe { &mut *CURRENT_CHILD_MEMBER.get() }
}

/// Whether the current thread belongs to a child subprocess. This is the
/// native entry points' one-load routing test.
#[inline]
pub(crate) fn current_thread_is_child_member() -> bool {
    // SAFETY: a short read of the current thread's own slot.
    unsafe { (*CURRENT_CHILD_MEMBER.get()).is_some() }
}

/// The child the current thread belongs to (`mi_subproc_current` for a
/// member), or `None` for a thread of the process main subprocess.
pub(crate) fn current_child_id() -> Option<NativeSubprocessId> {
    // SAFETY: a short read of the current thread's own slot.
    unsafe { (*CURRENT_CHILD_MEMBER.get()).as_ref().map(|member| member.id) }
}

/// The main Heap of the current thread's child (`mi_heap_main` for a
/// member), or `None` when the thread is not a member or the child is gone.
pub(crate) fn current_child_main_heap() -> Option<core::ptr::NonNull<crate::types::Heap>> {
    let id = current_child_id()?;
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    // SAFETY: a member's child stays live while the member does.
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
    let outcome = unsafe {
        id.with_owner(|owner| match owner.as_mut() {
            Some(child) => Ok(add_current_thread(child, binding)),
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
            *unsafe { current_child_member() } = Some(CurrentChildMember { id, binding, member });
            NativeChildThreadAdd::Added
        }
        Ok(ChildThreadAddOutcome::AlreadyInitialized { in_other_subprocess }) => {
            NativeChildThreadAdd::AlreadyInitialized { in_other_subprocess }
        }
        Err(ChildThreadStartFailure::Rejected(error) | ChildThreadStartFailure::Retained { error, .. }) => {
            NativeChildThreadAdd::Failed(error)
        }
    })
}

/// Finishes the current child thread (`_mi_thread_done`); see
/// [`ChildThreadMember::thread_done`]. The slot is cleared only on success.
/// Returns `None` when the thread is not a child member.
pub(crate) fn native_child_thread_done() -> Option<Result<(), NativeChildThreadDoneError>> {
    // SAFETY: current-thread slot, no other reference live.
    let slot = unsafe { current_child_member() };
    let current = slot.as_mut()?;
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(Err(NativeChildThreadDoneError::Subprocess(NativeSubprocessError::Closed)));
    };
    let id = current.id;
    let binding = current.binding;
    let member = &mut current.member;
    // SAFETY: this is the admitted thread; its caller has ended every use of
    // its allocations (thread exit), and the record lock excludes every
    // other context operation.
    let done = unsafe {
        id.with_owner(|owner| match owner.as_mut() {
            Some(child) => unsafe { member.thread_done(child, binding) }
                .map_err(NativeChildThreadDoneError::Done),
            None => Err(NativeChildThreadDoneError::Subprocess(NativeSubprocessError::Gone)),
        })
    };
    let result = match done {
        Ok(result) => result,
        Err(error) => Err(NativeChildThreadDoneError::Subprocess(error)),
    };
    if result.is_ok() {
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
    let (id, binding) = (current.id, current.binding);
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
    // SAFETY: current-thread slot, no other reference live.
    let current = unsafe { current_child_member() }.as_mut()?;
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(None);
    };
    let (id, binding) = (current.id, current.binding);
    let member = &mut current.member;
    // SAFETY: forwarded; the record lock excludes every other context operation.
    let allocated = unsafe {
        id.with_owner(|child| match child.as_mut() {
            Some(child) => crate::types::heap_registry::lifecycle::child_heap_allocate(child, member, binding, heap, size, false)
                .ok()
                .flatten(),
            None => None,
        })
    };
    Some(allocated.ok().flatten())
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
    // SAFETY: current-thread slot, no other reference live.
    let current = unsafe { current_child_member() }.as_mut()?;
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(Err(NativeSubprocessError::Closed));
    };
    let (id, binding) = (current.id, current.binding);
    let member = &mut current.member;
    let keys = crate::types::heap_registry::lifecycle::HeapKeySource::global();
    // SAFETY: this is the admitted thread; the record lock excludes every
    // other context operation, in place of source `heaps_lock`.
    Some(unsafe {
        id.with_owner(|owner| match owner.as_mut() {
            Some(child) => Ok(crate::types::heap_registry::lifecycle::child_heap_new(
                child, member, binding, keys,
            )),
            None => Err(NativeSubprocessError::Gone),
        })
    }.and_then(|result| result))
}

/// Production `mi_heap_delete` (or, with `destroy`, `mi_heap_destroy`) on
/// the current child thread; see
/// `types::heap_registry::lifecycle::child_heap_delete`. `None` when the
/// current thread is not a child member.
///
/// # Safety
/// `heap` is the current child's main Heap or a Heap created for it that no
/// thread uses.
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
    // SAFETY: current-thread slot, no other reference live.
    let current = unsafe { current_child_member() }.as_mut()?;
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Some(Err(NativeSubprocessError::Closed));
    };
    let (id, binding) = (current.id, current.binding);
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
/// It refuses, leaving the id valid, while a thread still belongs to the
/// child (source would destroy it under that thread). After success the id
/// is invalid. A failure after the first irreversible step retains the
/// remaining owners and returns `Retained`.
///
/// # Safety
/// The id is live, no other operation on this id runs concurrently with
/// the call, and no block of the child is used again.
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
    // SAFETY: forwarded id contract.
    let record = unsafe { id.record() };
    let destroyed = unsafe {
        id.with_owner(|owner| {
            let child = owner.take().ok_or(NativeSubprocessError::Gone)?;
            // SAFETY: the record lock excludes thread admission and finish,
            // the unlink step refuses while a thread belongs to the child,
            // and the caller never uses a child block again.
            match destroy_child_with(
                child, record.registry, binding, &mut [], metadata, config, release,
            ) {
                Ok(()) => Ok(()),
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
                // The remaining owners are dropped without freeing anything.
                Err(ChildSubprocessDestroyFailure::Release(_)) => Err(NativeSubprocessError::Retained),
            }
        })
    }??;
    // The child is gone and the lock is released; no other operation on this
    // id may run (caller contract), so the record can be taken apart.
    // SAFETY: exclusive by the id contract; the owner cell is empty.
    let mut storage = unsafe { (*record.storage.get()).take() }.ok_or(NativeSubprocessError::Retained)?;
    metadata.free(&mut storage).map_err(|_| NativeSubprocessError::Retained)
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

    /// Pinned-C/Rust differential for `mi_subproc_new`, `mi_subproc_destroy`,
    /// and `mi_subproc_visit_heaps`; `compat/allocator/subprocess_lifecycle.c`
    /// prints the same ordered fields.
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

    /// Through the production entry points, a child thread finishes with
    /// live blocks: its pages pass to the child main Heap, another thread
    /// frees one block (the page stays abandoned) and the only block of
    /// another page (the page is released), and `native_subproc_destroy`
    /// then destroys the child with its last block still live.
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
    /// thread creates and deletes a non-main Heap. Destruction refuses while
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
                    // SAFETY: the id is live; this is the only destroy.
                    assert_eq!(
                        unsafe { native_subproc_destroy(id) },
                        Err(NativeSubprocessError::DestroyRefused(
                            ChildSubprocessDestroyError::Registry(ChildMetadataPageEngineError::LiveThreads),
                        )),
                        "a child with live threads is not destroyed",
                    );
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
