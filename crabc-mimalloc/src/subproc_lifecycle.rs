// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/subproc.c:158-194 (`mi_subproc_new`),
// src/subproc.c:202-263 (`mi_subproc_unsafe_destroy`, `mi_subproc_destroy`),
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
//! Not yet covered: non-main Heaps in the child, ordinary child threads
//! (`mi_subproc_add_current_thread`), nested children, and destroying a child
//! whose metadata Theap still has live blocks. Source releases such blocks
//! with the child arenas; here the child metadata pages must be free first.
//! The source `_mi_thread_locals_thread_done` call in `mi_subproc_destroy`
//! releases the destroying thread's dynamic thread-local table, which no
//! child lifecycle here allocates.

use crate::main_heap_page::{
    MainHeapThreadOwnerLocalPageEngine, MainHeapThreadOwnerLocalPageEngineAccessError,
};
use crate::main_heap_thread::{MainHeapThreadAttachment, MainHeapThreadAttachmentError};
use crate::meta::{
    ChildContextCreateFailure, ChildContextCreateStage, ChildContextOwner,
    ChildMainHeapBindFailure, ChildMainHeapContextOwner, ChildMainHeapReleaseError,
    ChildMainHeapReleaseFailure, ChildMainHeapStage, ChildMetadataPageEngineError,
    ChildMetadataTheapError, MetaError,
};
use crate::process_init::ProcessMainBackingBinding;
use crate::subproc::registry::{SourceSubprocessRegistry, SourceSubprocessRegistryError};
use crate::types::heap_registry::SourceHeapRegistryError;

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
        child.test_identity_pointer().expect("a created child projects its identity")
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
