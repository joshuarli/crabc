// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/heap.c:103-160,175-260 (`_mi_heap_init`,
// `_mi_heap_new_for_subproc`, `mi_heap_new_in_arena`, `mi_heap_new`,
// `mi_heap_free`, `mi_heap_delete`, `_mi_heap_force_destroy`,
// `mi_heap_destroy`) and src/threadlocal.c:288-315 (`_mi_thread_local_create`,
// `_mi_thread_local_free`).

//! First-class non-main Heaps (`mi_heap_new`, `mi_heap_delete`,
//! `mi_heap_destroy`) for a thread admitted to a child subprocess.
//!
//! A Heap image is a [`NonMainHeapImage`]: the source Heap at offset zero,
//! so the Heap address is the `mi_heap_t*` identity, followed by the Rust
//! lease for its dynamic thread-local slot. As in source, the image is an
//! ordinary allocation from the calling thread's subprocess main Heap, and
//! the slot is a key of the process-global thread-local registry.
//!
//! Not yet covered: per-thread Theaps of a non-main Heap and therefore
//! Heaps that own pages (delete and destroy refuse such a Heap), exclusive
//! arenas, and Heaps of the process main subprocess.

use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use super::{Heap, SourceHeapRegistryError};
use crate::meta::{ChildMainHeapContextOwner, ChildMetadataPageEngineError, MetaAllocator};
use crate::owned_tls_key_registry::{
    OwnedThreadLocalKeyError, OwnedThreadLocalKeyLease, OwnedThreadLocalKeyRegistry,
};
use crate::process_init::ProcessMainBackingBinding;
use crate::subproc::lifecycle::ChildThreadMember;
use crate::subproc::MainSubprocess;

/// One non-main Heap allocation: the source Heap at offset zero, then the
/// lease of its dynamic thread-local slot.
#[repr(C)]
pub(crate) struct NonMainHeapImage {
    heap: Heap,
    slot: Option<OwnedThreadLocalKeyLease>,
}

/// The process-global thread-local key registry and the main-subprocess
/// metadata owner that allocates its bitmap (`threadlocal.c` always
/// allocates it in the main subprocess).
#[derive(Clone, Copy)]
pub(crate) struct HeapKeySource {
    pub(crate) registry: &'static OwnedThreadLocalKeyRegistry,
    pub(crate) subprocess: &'static MainSubprocess,
    pub(crate) metadata: core::pin::Pin<&'static MetaAllocator>,
}

impl HeapKeySource {
    /// The production process registry.
    pub(crate) fn global() -> Self {
        Self {
            registry: OwnedThreadLocalKeyRegistry::global(),
            subprocess: MainSubprocess::global(),
            metadata: MetaAllocator::global(),
        }
    }
}

/// Why `mi_heap_new` returned null. Everything the attempt allocated has
/// been released in source order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapNewError {
    /// `mi_heap_zalloc(subproc->heap_main)` failed.
    ImageAllocation(ChildMetadataPageEngineError),
    /// `_mi_thread_local_create` returned no key; the image was freed.
    ThreadLocal(OwnedThreadLocalKeyError),
    /// The child context could not project its image or main Heap.
    InvalidChild,
    /// A step failed after the image became visible; the image is retained.
    Retained,
    /// List insertion failed; the image and key are retained.
    List(SourceHeapRegistryError),
}

/// Outcome of `mi_heap_delete` and `mi_heap_destroy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapReleaseOutcome {
    Released,
    /// Source warns "cannot delete/destroy the main heap" and returns.
    MainHeapRefused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapReleaseError {
    /// The Heap still has a Theap or a page, which this port cannot move or
    /// destroy yet; nothing changed.
    NotEmpty,
    InvalidChild,
    /// A step after list removal failed; the remaining state is retained.
    Retained,
    List(SourceHeapRegistryError),
}

/// Pinned `mi_heap_new` (`mi_heap_new_in_arena(0)`) on a thread admitted to
/// `child`: allocate the zeroed image from the child main Heap through the
/// thread's Theap, create its thread-local slot, initialize it, and push it
/// on the child's Heap list.
///
/// # Safety
/// The caller is the thread `member` admitted to `child`, and no other
/// operation on `child` runs concurrently.
pub(crate) unsafe fn child_heap_new(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    keys: HeapKeySource,
) -> Result<NonNull<Heap>, HeapNewError> {
    let config = binding.page_map().memory_config().map_err(|_| HeapNewError::InvalidChild)?;
    // heap.c:136 `mi_heap_zalloc(heap_main, sizeof(mi_heap_t))`.
    // SAFETY: forwarded current-thread obligation.
    let block = unsafe {
        member.with_page_engine(binding, |_child, engine| {
            engine.allocate(size_of::<NonMainHeapImage>(), true)
        })
    }
    .map_err(HeapNewError::ImageAllocation)?
    .ok_or(HeapNewError::ImageAllocation(ChildMetadataPageEngineError::SessionNotReady))?;
    let image = block.cast::<NonMainHeapImage>();
    // heap.c:139-144 `_mi_thread_local_create`; failure frees the image.
    let slot = if image.as_ptr().addr() % align_of::<NonMainHeapImage>() != 0 {
        Err(HeapNewError::Retained)
    } else {
        keys.registry
            .claim_for_main_subprocess(config, keys.subprocess, keys.metadata)
            .map_err(HeapNewError::ThreadLocal)
    };
    let slot = match slot {
        Ok(slot) => slot,
        Err(error) => {
            // SAFETY: the exact live block allocated above; nothing names it.
            let freed = unsafe {
                member.with_page_engine(binding, |_child, engine| unsafe { engine.free(block) })
            };
            return match freed {
                Ok(Ok(())) => Err(error),
                _ => Err(HeapNewError::Retained),
            };
        }
    };
    let key = slot.key().raw();
    let memory = crate::types::MemoryId::malloc(block.as_ptr(), size_of::<NonMainHeapImage>(), true);
    // SAFETY: the zeroed block is exclusively owned, large enough, and
    // aligned; the image is written whole before any list publishes it.
    unsafe {
        image.as_ptr().write(NonMainHeapImage { heap: Heap::bootstrap_empty(), slot: Some(slot) });
    }
    let heap = image.cast::<Heap>();
    let linked = child.with_child_image(|image_ref| {
        let identity = image_ref.identity();
        // SAFETY: the image is exclusively owned until the list publishes it,
        // and stays pinned in its allocation until `mi_heap_free`.
        let heap = unsafe { &mut *heap.as_ptr() };
        // heap.c:103-114, then the list push at 115-124.
        heap.initialize_non_main(identity, key, core::ptr::null_mut(), memory);
        // SAFETY: the Heap was initialized for this subprocess just above.
        unsafe { identity.heap_list().link_non_main(heap, identity) }
    });
    match linked {
        Some(Ok(())) => Ok(heap),
        Some(Err(error)) => Err(HeapNewError::List(error)),
        None => Err(HeapNewError::InvalidChild),
    }
}

/// Pinned `mi_heap_delete` on a thread admitted to `child`, for a Heap that
/// owns no Theap and no page.
///
/// # Safety
/// As for [`child_heap_new`]; `heap` is the main Heap of `child` or a Heap
/// that [`child_heap_new`] returned for it and that no thread uses.
pub(crate) unsafe fn child_heap_delete(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    // heap.c:231-237: refuse the main Heap, then `mi_heap_free_theaps` and
    // `_mi_heap_move_pages`, which have nothing to do for an empty Heap.
    // SAFETY: forwarded obligations.
    unsafe { release_empty_heap(child, member, binding, heap) }
}

/// Pinned `mi_heap_destroy` on a thread admitted to `child`, for a Heap that
/// owns no Theap and no page.
///
/// # Safety
/// As for [`child_heap_delete`].
pub(crate) unsafe fn child_heap_destroy(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    // heap.c:253-259 then `_mi_heap_force_destroy`: `mi_heap_free_theaps`
    // and `_mi_heap_destroy_pages` have nothing to do for an empty Heap.
    // SAFETY: forwarded obligations.
    unsafe { release_empty_heap(child, member, binding, heap) }
}

/// The shared `mi_heap_free` (`heap.c:175-226`) for an empty non-main Heap.
///
/// # Safety
/// As for [`child_heap_delete`].
unsafe fn release_empty_heap(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    let main = child.main_heap_pointer().ok_or(HeapReleaseError::InvalidChild)?;
    if heap == main {
        return Ok(HeapReleaseOutcome::MainHeapRefused);
    }
    // SAFETY: by the caller contract the Heap is a live non-main image that
    // no thread uses; list operations below hold the list lock.
    let heap_ref = unsafe { &mut *heap.as_ptr() };
    if !heap_ref.is_without_theaps_or_pages() {
        return Err(HeapReleaseError::NotEmpty);
    }
    // heap.c:201-203 `mi_heap_stats_merge_to_main`.
    // SAFETY: `main` is this child's live main Heap.
    unsafe { heap_ref.merge_statistics_to_main(main) };
    // heap.c:205-212 count, statistic, and list removal.
    let unlinked = child
        .with_child_image(|image| {
            let identity = image.identity();
            // SAFETY: the Heap has no Theap and stays pinned until its free.
            unsafe { identity.heap_list().unlink_non_main(heap_ref, identity) }
        })
        .ok_or(HeapReleaseError::InvalidChild)?;
    unlinked.map_err(HeapReleaseError::List)?;
    // heap.c:220-224 `_mi_thread_local_free(heap->theap)`.
    let image = heap.cast::<NonMainHeapImage>();
    // SAFETY: the image is off every list and exclusively owned now.
    let mut slot = unsafe { (*image.as_ptr()).slot.take() }.ok_or(HeapReleaseError::Retained)?;
    slot.release().map_err(|_| HeapReleaseError::Retained)?;
    // heap.c:225 `_mi_free_subproc_safe(heap)`.
    // SAFETY: the exact live image block; nothing names it any longer.
    let freed = unsafe {
        member.with_page_engine(binding, |_child, engine| unsafe { engine.free(image.cast()) })
    };
    match freed {
        Ok(Ok(())) => Ok(HeapReleaseOutcome::Released),
        _ => Err(HeapReleaseError::Retained),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_heap_page::tests::with_owner_local_fixture;
    use crate::subproc::lifecycle::tests::child_fixture_inputs;
    use crate::subproc::lifecycle::{add_current_thread, destroy_child, new_child, ChildThreadAddOutcome};
    use crate::thread_local::TLS_INDEX_MASK;
    use std::vec::Vec;

    fn push_counts(trace: &mut Vec<i64>, child: &mut ChildMainHeapContextOwner<'_>) {
        let (live, total, heaps) = child
            .with_child_image(|image| {
                let identity = image.identity();
                let (live, total, _) = identity.heap_list().test_counts();
                (live, total, identity.statistics().final_output_snapshot().heaps)
            })
            .expect("the child projects its image");
        trace.extend([live as i64, total as i64, heaps.current, heaps.total]);
    }

    fn push_heap(trace: &mut Vec<i64>, child: &mut ChildMainHeapContextOwner<'_>, heap: NonNull<Heap>) {
        let identity = child.identity_pointer().expect("the child projects its identity");
        // SAFETY: the Heap is live and no list operation runs.
        let (sequence, subprocess, no_arena, numa, no_theaps, key) =
            unsafe { heap.as_ref() }.test_non_main_facts();
        trace.extend([
            sequence as i64,
            i64::from(subprocess == identity),
            i64::from(no_arena),
            i64::from(numa),
            i64::from(no_theaps),
            (key & TLS_INDEX_MASK) as i64,
            (key >> crate::thread_local::TLS_INDEX_BITS) as i64,
        ]);
    }

    /// The child's Heap list in order, with each member's `prev` link.
    fn list_is(child: &mut ChildMainHeapContextOwner<'_>, expected: &[NonNull<Heap>]) -> bool {
        let mut current = child
            .with_child_image(|image| image.identity().heap_list().test_head())
            .expect("the child projects its image");
        let mut previous = core::ptr::null_mut();
        for heap in expected {
            if current != heap.as_ptr() {
                return false;
            }
            // SAFETY: members are live and no list operation runs.
            let (prev, next) = unsafe { Heap::test_links(*heap) };
            if prev != previous {
                return false;
            }
            previous = current;
            current = next;
        }
        current.is_null()
    }

    fn list_length(child: &mut ChildMainHeapContextOwner<'_>) -> i64 {
        let mut count = 0;
        child.visit_heaps(|_| { count += 1; true })
            .expect("the child projects its image")
            .expect("the Heap-list lock is uncontended");
        count
    }

    /// Pinned-C/Rust differential for `mi_heap_new`, `mi_heap_delete`, and
    /// `mi_heap_destroy` of Heaps that never allocate, on a thread of a child
    /// subprocess; `compat/allocator/heap_lifecycle.c` prints the same fields.
    #[test]
    fn source_ordered_empty_heap_lifecycle_trace() {
        with_owner_local_fixture(true, |attachment, mut heap_owner, pair| {
            let (parent, registry, binding) = child_fixture_inputs(attachment, pair);
            let keys = HeapKeySource {
                registry: OwnedThreadLocalKeyRegistry::test_static_owner(),
                subprocess: parent,
                metadata: attachment.parent_metadata_allocator(),
            };
            // SAFETY: the registry holds main, the call runs on the attached
            // fixture thread, and no other child operation exists.
            let mut child = unsafe { new_child(registry, attachment, &mut heap_owner) }
                .expect("the child is created");

            struct Shared<T>(T);
            // SAFETY: the scoped worker is the only user of these until joined.
            unsafe impl<T> Send for Shared<T> {}
            let shared = Shared((&mut child, binding, keys));
            let mut trace = std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, keys) = shared.0;
                    let mut trace: Vec<i64> = Vec::new();
                    // SAFETY: a fresh thread owns its pristine roots.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) =
                        (unsafe { add_current_thread(child, binding) })
                    else {
                        panic!("a fresh thread joins the child");
                    };
                    let main = child.main_heap_pointer().expect("the child has a main Heap");
                    push_counts(&mut trace, child);

                    // SAFETY (each call below): this is the admitted thread
                    // and the scoped worker is the only child operation.
                    let first = unsafe { child_heap_new(child, &mut member, binding, keys) }
                        .expect("the first Heap is created");
                    push_heap(&mut trace, child, first);
                    let second = unsafe { child_heap_new(child, &mut member, binding, keys) }
                        .expect("the second Heap is created");
                    push_heap(&mut trace, child, second);
                    push_counts(&mut trace, child);
                    trace.push(i64::from(list_is(child, &[second, first, main])));
                    let mut visited = 0;
                    let all = child.visit_heaps(|_| { visited += 1; true }).unwrap().unwrap();
                    trace.push(i64::from(all));
                    trace.push(visited);

                    assert_eq!(unsafe { child_heap_delete(child, &mut member, binding, main) },
                        Ok(HeapReleaseOutcome::MainHeapRefused));
                    assert_eq!(unsafe { child_heap_destroy(child, &mut member, binding, main) },
                        Ok(HeapReleaseOutcome::MainHeapRefused));
                    trace.push(list_length(child));

                    assert_eq!(unsafe { child_heap_delete(child, &mut member, binding, first) },
                        Ok(HeapReleaseOutcome::Released));
                    push_counts(&mut trace, child);
                    trace.push(i64::from(list_is(child, &[second, main])));
                    assert_eq!(unsafe { child_heap_destroy(child, &mut member, binding, second) },
                        Ok(HeapReleaseOutcome::Released));
                    push_counts(&mut trace, child);
                    trace.push(i64::from(list_is(child, &[main])));

                    let third = unsafe { child_heap_new(child, &mut member, binding, keys) }
                        .expect("a later Heap is created");
                    push_heap(&mut trace, child, third);
                    push_counts(&mut trace, child);
                    assert_eq!(unsafe { child_heap_delete(child, &mut member, binding, third) },
                        Ok(HeapReleaseOutcome::Released));
                    push_counts(&mut trace, child);
                    // SAFETY: every Heap image was freed through this thread.
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes");
                    trace
                })
                .join()
                .expect("the child thread completes")
            });
            trace.push(list_length(&mut child));
            // SAFETY: the child has no users, threads, or live blocks left.
            unsafe { destroy_child(child, registry, binding, &mut [], attachment, &mut heap_owner) }
                .expect("the child is destroyed");
            for (index, value) in trace.iter().enumerate() {
                std::println!("m6.heap.lifecycle.{index}={value}");
            }
            heap_owner.finish(attachment).expect("the parent engine is quiescent");
            attachment
                .finish_after_user_destructors()
                .expect("the parent attachment completes after its children");
        });
    }
}
