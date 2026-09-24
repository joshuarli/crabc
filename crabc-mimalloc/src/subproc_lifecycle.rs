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
//! is the matching `_mi_thread_done`.
//!
//! Not yet covered: non-main Heaps in the child, nested children, routing
//! the native runtime's allocation entries through an admitted thread's
//! default Theap, abandoning a finishing child thread's live pages, and
//! destroying a child whose metadata Theap still has live blocks. Source
//! releases such blocks with the child arenas; here the child metadata pages
//! must be free first. The source `_mi_thread_locals_thread_done` call in
//! `mi_subproc_destroy` releases the destroying thread's dynamic thread-local
//! table, which no child lifecycle here allocates.

use crate::main_heap_page::{
    MainHeapThreadOwnerLocalPageEngine, MainHeapThreadOwnerLocalPageEngineAccessError,
};
use crate::main_heap_thread::{MainHeapThreadAttachment, MainHeapThreadAttachmentError};
use crate::meta::{
    ChildContextCreateFailure, ChildContextCreateStage, ChildContextOwner,
    ChildMainHeapBindFailure, ChildMainHeapContextOwner, ChildMainHeapReleaseError,
    ChildMainHeapReleaseFailure, ChildMainHeapStage, ChildMetadataPageEngineError,
    ChildMetadataTheapError, ChildThreadOwner, ChildThreadStartError, ChildThreadStartFailure,
    ChildThreadTeardownError, MetaError,
};
use crate::compiler_tls::{default_theap, set_cached_theap, set_default_theap, set_fast_slot};
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
    let released = |error| Err(ChildSubprocessNewFailure::Released(error));
    let (parent, config) = match (attachment.subprocess(), attachment.memory_config()) {
        (Ok(parent), Ok(config)) => (parent, config),
        (Err(error), _) | (_, Err(error)) => {
            return released(ChildSubprocessNewError::Attachment(error));
        }
    };
    let metadata = attachment.parent_metadata_allocator();

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
    let heap_error = match heap_owner.allocate_child_heap_storage(attachment) {
        Ok(Some(storage)) => Ok(storage),
        Ok(None) => Err(ChildSubprocessNewError::HeapAllocation),
        Err(error) => Err(ChildSubprocessNewError::ParentAccess(error)),
    };
    let storage = match heap_error {
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
    let mut child = context.bind_parent_heap_storage(storage).map_err(|failure| {
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
/// No thread uses the child: every child client, metadata block, and page
/// has been freed, and no child operation or registry teardown can race
/// destruction. `registry` admitted the child. The caller runs on the
/// attachment thread whose owner-local engine allocated the child main Heap.
pub(crate) unsafe fn destroy_child<'main, 'tracking>(
    mut child: ChildMainHeapContextOwner<'main>,
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
    loop {
        let step = match child.stage() {
            // subproc.c:207-211: remove the child from the subprocess list.
            // SAFETY: forwarded quiescence and exact-registry obligations.
            ChildMainHeapStage::HeapReady => unsafe {
                child
                    .unlink_registry_and_finish_metadata_pages(registry, binding)
                    .map_err(ChildSubprocessDestroyError::Registry)
            },
            // heap.c:151-155 `_mi_heap_detach_theaps` for the metadata Theap.
            // SAFETY: registry unlink succeeded and `metadata` attached it.
            ChildMainHeapStage::RegistryUnlinked => unsafe {
                child
                    .detach_metadata_theap(metadata, config)
                    .map_err(ChildSubprocessDestroyError::MetadataTheapDetach)
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
                // SAFETY: every list transition completed above and this
                // attachment's engine allocated the child Heap image.
                return unsafe {
                    child.release_after_empty_heap_teardown(tracking, heap_owner, attachment)
                }
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

/// A thread that [`add_current_thread`] admitted to a child subprocess: its
/// ordinary TLD and regular Theap on the child main Heap, installed as the
/// thread's default Theap and the main-Heap fast slot.
///
/// The member borrows the child owner, so the child cannot be destroyed
/// while the thread belongs to it. Dropping a member without
/// [`Self::thread_done`] leaves the roots installed and retains the child
/// terminally, as dropping its `ChildThreadOwner` does.
#[must_use = "a child subprocess thread must finish through thread_done"]
pub(crate) struct ChildThreadMember<'owner, 'main> {
    owner: ChildThreadOwner<'owner, 'main>,
}

/// Result of pinned `mi_subproc_add_current_thread`.
#[must_use = "an admitted child thread must finish through thread_done"]
pub(crate) enum ChildThreadAddOutcome<'owner, 'main> {
    Added(ChildThreadMember<'owner, 'main>),
    /// The thread's default Theap is already initialized, so source returns
    /// without a change (`subproc.c:291-296`). Source warns only when that
    /// Theap belongs to another subprocess.
    AlreadyInitialized { in_other_subprocess: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildThreadDoneError {
    /// Called on a thread other than the one the member admitted.
    WrongThread,
    /// A live block remains on one of the thread's pages. Source abandons
    /// such pages to the child main Heap; this port has no child abandonment
    /// route yet, so the member stays attached with its roots installed.
    PagesRemain,
    /// Page drain or release could not run; the member is unchanged.
    PageEngine(ChildMetadataPageEngineError),
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
/// `child` runs concurrently.
pub(crate) unsafe fn add_current_thread<'owner, 'main>(
    child: &'owner mut ChildMainHeapContextOwner<'main>,
    binding: ProcessMainBackingBinding,
) -> Result<ChildThreadAddOutcome<'owner, 'main>, ChildThreadStartFailure<'owner, 'main>> {
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

impl ChildThreadMember<'_, '_> {
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

    /// Projects the child subprocess image this thread belongs to.
    pub(crate) fn with_child_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(core::pin::Pin<&'image crate::subproc::ChildSubprocessImage>) -> R,
    ) -> Option<R> {
        self.owner.with_child_image(operation)
    }

    /// Pinned `_mi_thread_done` (`init.c:452-480`) for this child thread:
    /// clear the fast slot, count the thread out of the child's `threads`
    /// statistic, reset the default and cached roots to the empty Theap,
    /// then detach and free the Theap and TLD (`mi_thread_theaps_done`,
    /// `mi_tld_free`).
    ///
    /// Every block allocated through the thread must be freed first; see
    /// [`ChildThreadDoneError::PagesRemain`].
    ///
    /// # Safety
    /// The caller is the admitted thread, no allocation through this member
    /// is live or in progress, and no other operation on the child runs.
    pub(crate) unsafe fn thread_done(
        &mut self,
        binding: ProcessMainBackingBinding,
    ) -> Result<(), ChildThreadDoneError> {
        if crate::compiler_tls::current_thread_identity() != Some(self.owner.thread()) {
            return Err(ChildThreadDoneError::WrongThread);
        }
        // Rust has no child page abandonment yet, so prove before the first
        // source step that every page drains; source `_mi_theap_collect_abandon`
        // would otherwise abandon the rest.
        // SAFETY: forwarded current-thread and quiescence obligations.
        let drained = unsafe {
            self.owner.with_page_engine(binding, |_child, engine| engine.finish_pages_in_place())
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
        set_cached_theap(empty);
        // init.c:401-419 and `mi_tld_free`.
        // SAFETY: forwarded obligations; the roots no longer name the Theap.
        unsafe { self.owner.teardown(binding) }.map_err(ChildThreadDoneError::Teardown)
    }
}

#[cfg(test)]
mod tests {
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

    /// Pinned-C/Rust differential for `mi_subproc_new`, `mi_subproc_destroy`,
    /// and `mi_subproc_visit_heaps`; `compat/allocator/subprocess_lifecycle.c`
    /// prints the same ordered fields.
    #[test]
    fn source_ordered_child_subprocess_lifecycle_trace() {
        with_owner_local_fixture(true, |attachment, mut heap_owner, pair| {
            let parent = attachment.subprocess().expect("the fixture attaches to main");
            let config = attachment.memory_config().expect("the attachment is live");
            let registry = std::boxed::Box::leak(std::boxed::Box::new(
                SourceSubprocessRegistry::new(),
            ));
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
                    unsafe { member.thread_done(binding) }.expect("the child thread finishes");
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

            unsafe {
                destroy_child(second, registry, binding, &mut [], attachment, &mut heap_owner)
            }
            .expect("the newest child is destroyed from the list head");
            trace.push(registry_members(registry).len() as i64);

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

            for (index, value) in trace.iter().enumerate() {
                std::println!("m6.subproc.lifecycle.{index}={value}");
            }
            heap_owner.finish(attachment).expect("the parent engine is quiescent");
            attachment
                .finish_after_user_destructors()
                .expect("the parent attachment completes after its children");
        });
    }
}
