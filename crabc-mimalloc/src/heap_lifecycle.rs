// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/heap.c:59-99 (`_mi_heap_theap_get_or_init`),
// 103-160,162-260 (`_mi_heap_init`, `mi_heap_free_theaps`,
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
//! [`child_heap_allocate`] allocates through the calling thread's Theap for
//! the Heap (`_mi_heap_theap`: the cached Theap, else the Theap on the Heap's
//! thread-local slot, else a fresh one), whose first fresh page from an arena
//! allocates the Heap's per-arena page record from the child main Heap
//! through the thread's main-Heap Theap, as `mi_arena_pages_alloc` does; see
//! `meta::ChildHeapTheapImage`. [`child_heap_destroy`] frees the Heap's
//! Theaps, destroys its pages with their live blocks, and frees the Heap;
//! [`child_heap_delete`] instead moves the pages that hold live blocks to the
//! child main Heap as abandoned pages. A thread that finishes abandons its
//! non-main Theaps' live pages to their Heaps' own records, and subprocess
//! and process destruction force-destroy non-main Heaps with their Theaps and
//! pages ([`child_heap_force_destroy_for_subprocess_destroy`]).
//!
//! Abandoned pages of child Heaps are reclaimed as in source: into the
//! freeing thread's Theap for the page's Heap (`mi_abandoned_page_try_reclaim`,
//! `ChildThreadOwner::reclaim_on_free`), and by an allocating Theap of the
//! Heap before a fresh page (`mi_arenas_page_try_find_abandoned`). OS-backed
//! pages use the Heap's OS-abandoned list.
//!
//! Not yet covered: exclusive arenas and Heaps of the process main
//! subprocess.

use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use super::{Heap, SourceHeapRegistryError};
use crate::meta::{ChildHeapTheapError, ChildMainHeapContextOwner, ChildMetadataPageEngineError, ChildThreadOwner, MetaAllocator};
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
    // heap.c:136 `mi_heap_zalloc(heap_main, sizeof(mi_heap_t))` reaches the
    // thread's main-Heap Theap through `_mi_heap_theap(heap_main)`, which
    // makes it the cached Theap (and so may free a destroyed Heap's Theap).
    let owner = member.owner_mut();
    let main_theap = owner.theap_pointer().ok_or(HeapNewError::InvalidChild)?;
    // SAFETY: forwarded current-thread obligation.
    unsafe { owner.cached_set(child, binding, main_theap) }.map_err(|_| HeapNewError::Retained)?;
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

/// Pinned `mi_heap_malloc(heap, size)` (and the zeroing variant) on a thread
/// admitted to `child`: through this thread's Theap for `heap`
/// (`_mi_heap_theap`, created on first use), allocating from that Theap's
/// pages. `None` is source out-of-memory.
///
/// # Safety
/// As for [`child_heap_new`]; `heap` is a live non-main Heap of `child`.
pub(crate) unsafe fn child_heap_allocate(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
    size: usize,
    zero: bool,
) -> Result<Option<NonNull<u8>>, HeapAllocateError> {
    let owner = member.owner_mut();
    // SAFETY: forwarded current-thread and exclusion obligations.
    let theap = unsafe { owner.heap_theap(child, binding, heap) }.map_err(HeapAllocateError::Theap)?;
    let owner: *mut ChildThreadOwner = owner;
    // SAFETY: as above; neither pointer is otherwise borrowed for the call.
    unsafe {
        ChildThreadOwner::with_heap_theap_page_engine(owner, child, binding, theap, |engine| engine.allocate(size, zero))
    }
    .map_err(HeapAllocateError::PageEngine)
}

/// Why [`child_heap_allocate`] could not run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapAllocateError {
    Theap(ChildHeapTheapError),
    PageEngine(ChildMetadataPageEngineError),
}

/// Pinned `mi_free` of `block` on a thread admitted to `child`: the owning
/// Theap's engine when one of this thread's Theaps owns its page, otherwise
/// the nonlocal route.
///
/// # Safety
/// As for [`child_heap_new`]; `block` is a live allocation freed once.
pub(crate) unsafe fn child_thread_free(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    block: NonNull<u8>,
) -> Result<(), ChildHeapTheapError> {
    let owner: *mut ChildThreadOwner = member.owner_mut();
    // SAFETY: forwarded.
    unsafe { ChildThreadOwner::free_block(owner, child, binding, block) }
}

/// Pinned `mi_heap_delete` (`heap.c:228-238`) on a thread admitted to
/// `child`: `mi_heap_free_theaps`, then `_mi_heap_move_pages` hands every
/// page that still holds live blocks to the child main Heap as an abandoned
/// page (freeing the empty ones), then `mi_heap_free`. The target Theap is
/// `_mi_heap_theap(heap_main)`, which becomes the cached Theap.
///
/// # Safety
/// As for [`child_heap_new`]; `heap` is the main Heap of `child` or a Heap
/// that [`child_heap_new`] returned for it.
pub(crate) unsafe fn child_heap_delete(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    // heap.c:231-237.
    let Some(main) = child.main_heap_pointer() else { return Err(HeapReleaseError::InvalidChild) };
    if main == heap {
        return Ok(HeapReleaseOutcome::MainHeapRefused);
    }
    // SAFETY: forwarded obligations.
    unsafe { free_heap_theaps(child, member, binding, heap) }?;
    // `mi_heap_delete_pages`: `_mi_heap_theap(heap_target)`.
    let owner = member.owner_mut();
    let theap = owner.theap_pointer().ok_or(HeapReleaseError::InvalidChild)?;
    // SAFETY: the calling thread's live main-Heap Theap.
    unsafe { owner.cached_set(child, binding, theap) }.map_err(|_| HeapReleaseError::Retained)?;
    let target = crate::single_thread::NonMainHeapPageTarget { heap: main, theap };
    // SAFETY: forwarded obligations; the Theaps are detached above.
    unsafe {
        delete_heap_pages(child, binding, heap, Some(target))?;
        release_heap(child, member, binding, heap)
    }
}

/// Pinned `mi_heap_destroy` (`heap.c:240-259`) on a thread admitted to
/// `child`: `mi_heap_free_theaps`, then `_mi_heap_destroy_pages` frees every
/// page of the Heap with its live blocks, then `mi_heap_free`. A Theap that
/// is still some thread's cached Theap stays allocated until that thread
/// drops the reference, as in source.
///
/// # Safety
/// As for [`child_heap_delete`]; no block of the Heap is used again.
pub(crate) unsafe fn child_heap_destroy(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    // heap.c:253-259.
    if child.main_heap_pointer() == Some(heap) {
        return Ok(HeapReleaseOutcome::MainHeapRefused);
    }
    // SAFETY: forwarded obligations.
    unsafe {
        free_heap_theaps(child, member, binding, heap)?;
        delete_heap_pages(child, binding, heap, None)?;
        release_heap(child, member, binding, heap)
    }
}

/// `mi_heap_delete_pages` over the child's arenas; see
/// `single_thread::delete_non_main_heap_pages`.
///
/// # Safety
/// Every Theap of `heap` is detached; otherwise as for [`child_heap_delete`].
unsafe fn delete_heap_pages(
    child: &mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
    target: Option<crate::single_thread::NonMainHeapPageTarget>,
) -> Result<(), HeapReleaseError> {
    let done = child.with_child_image(|image| {
        let image = image.get_ref();
        // SAFETY: the child image outlives this call; a 'static projection
        // for the child page backing, as the nonlocal free route forms.
        let image: core::pin::Pin<&'static crate::subproc::ChildSubprocessImage> =
            unsafe { core::pin::Pin::new_unchecked(&*core::ptr::from_ref(image)) };
        let Ok(child_process) = crate::os::ChildVmProcess::new(binding.process(), image) else { return false };
        let Ok(pair) = crate::process_arena::ChildProcessPageArenaLease::join(binding.page_map(), child_process) else {
            return false;
        };
        // SAFETY: the detached Heap's pages are owned by this operation.
        let Ok(page_map) = (unsafe { pair.page_map_for_owned_ranges() }) else { return false };
        let backing = crate::page_backing::ChildMetadataArenaBacking::new(pair);
        // SAFETY: forwarded.
        unsafe {
            crate::single_thread::delete_non_main_heap_pages(
                heap, target, image.identity().arena_backing().registry(), page_map, &backing,
            )
        }
    });
    if done == Some(true) { Ok(()) } else { Err(HeapReleaseError::Retained) }
}

/// `mi_heap_free_theaps` (`heap.c:162-182`): every Theap of `heap` leaves
/// its thread's TLD list and the Heap's, merges its statistics into the
/// Heap, and drops the Heap's reference (`_mi_theap_decref`), which frees
/// it unless a thread still caches it.
///
/// # Safety
/// As for [`child_heap_delete`].
unsafe fn free_heap_theaps(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<(), HeapReleaseError> {
    let identity = child
        .with_child_image(|image| core::ptr::NonNull::from(image.get_ref().identity()))
        .ok_or(HeapReleaseError::InvalidChild)?;
    let owner = member.owner_mut();
    let mut released = Ok(());
    // SAFETY: the Heap and its Theaps are live, and the child record lock
    // excludes other operations on this Heap.
    let detached = unsafe {
        heap.as_ref().detach_and_take_theaps(identity.as_ref(), |theap| {
            heap.as_ref().merge_detached_theap_statistics(theap.as_ref());
            if let Err(error) = owner.theap_decref(child, binding, theap) {
                released = Err(error);
            }
        })
    };
    detached.map_err(HeapReleaseError::List)?;
    released.map_err(|_| HeapReleaseError::Retained)
}

/// The shared `mi_heap_free` (`heap.c:185-226`) for a non-main Heap whose
/// Theaps and pages are gone: its per-arena page records are freed, then
/// statistics, counts, list, thread-local slot, and image.
///
/// # Safety
/// As for [`child_heap_delete`].
unsafe fn release_heap(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    // heap.c:185-194 `_mi_free_subproc_safe(arena_pages)` for each record.
    let owner: *mut ChildThreadOwner = member.owner_mut();
    let child_pointer: *mut ChildMainHeapContextOwner<'_> = child;
    // SAFETY: the live Heap; each record is a live block of the child main
    // Heap, freed once; neither pointer is otherwise borrowed meanwhile.
    let freed = unsafe {
        heap.as_ref().take_non_main_arena_pages(|block| {
            ChildThreadOwner::free_block(owner, child_pointer, binding, block).is_ok()
        })
    };
    if !freed {
        return Err(HeapReleaseError::Retained);
    }
    // SAFETY: forwarded obligations.
    let Some(image) = (unsafe { unlink_empty_heap(child, heap) })? else {
        return Ok(HeapReleaseOutcome::MainHeapRefused);
    };
    // heap.c:225 `_mi_free_subproc_safe(heap)`.
    // SAFETY: the exact live image block; nothing names it any longer.
    match unsafe { ChildThreadOwner::free_block(owner, child_pointer, binding, image.cast()) } {
        Ok(()) => Ok(HeapReleaseOutcome::Released),
        Err(_) => Err(HeapReleaseError::Retained),
    }
}

/// Pinned `_mi_heap_force_destroy(heap, false)` of a non-main child Heap
/// inside `mi_subproc_unsafe_destroy` (`subproc.c:215-221`), just before the
/// child's registry unlink (see `subproc::lifecycle::destroy_child_with`): `mi_heap_free_theaps` (the Theaps of threads that
/// still belong to the child leave their TLDs; a Theap whose last reference
/// goes is counted out of `theaps`), `_mi_heap_destroy_pages`, and
/// `mi_heap_free`. Blocks are not freed one by one: the Theap images and the
/// Heap's page records and image are live blocks in the child's metadata and
/// main-Heap pages, which the child's arena destruction releases right after,
/// where source frees them with `_mi_meta_free` / `_mi_free_subproc_safe`
/// (frees with no statistic in the release profile that the arena release
/// makes unobservable).
///
/// # Safety
/// No thread uses `heap` or `child` again, and `heap` is a Heap of `child`
/// other than its main Heap.
pub(crate) unsafe fn child_heap_force_destroy_for_subprocess_destroy(
    child: &mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<(), HeapReleaseError> {
    let identity = child
        .with_child_image(|image| core::ptr::NonNull::from(image.get_ref().identity()))
        .ok_or(HeapReleaseError::InvalidChild)?;
    // SAFETY: the Heap, its Theaps, and the child stay live; nothing else
    // runs on the child.
    unsafe {
        heap.as_ref().detach_and_take_theaps(identity.as_ref(), |theap| {
            heap.as_ref().merge_detached_theap_statistics(theap.as_ref());
            if crate::types::Theap::decref_at(theap) && !crate::types::Theap::is_detached_at(theap) {
                identity.as_ref().record_statistics_theap_unlinked();
            }
        })
    }
    .map_err(HeapReleaseError::List)?;
    // SAFETY: the Theaps are detached above.
    unsafe { delete_heap_pages(child, binding, heap, None) }?;
    // SAFETY: the live Heap; its records go with the child arenas.
    if !unsafe { heap.as_ref() }.take_non_main_arena_pages(|_record| true) {
        return Err(HeapReleaseError::Retained);
    }
    // SAFETY: forwarded obligations.
    match unsafe { unlink_empty_heap(child, heap) }? {
        Some(_image) => Ok(()),
        None => Err(HeapReleaseError::InvalidChild),
    }
}

/// `mi_heap_free` up to the image free: refuse the main Heap (`None`) and a
/// Heap with a Theap or page, merge statistics to the main Heap, remove the
/// count and list edges, and release the thread-local slot. Returns the image
/// that the caller frees or retains.
///
/// # Safety
/// `heap` is the main Heap of `child` or a live non-main Heap of it that no
/// thread uses, and no other operation on `child` runs concurrently.
unsafe fn unlink_empty_heap(
    child: &mut ChildMainHeapContextOwner<'_>,
    heap: NonNull<Heap>,
) -> Result<Option<NonNull<NonMainHeapImage>>, HeapReleaseError> {
    let main = child.main_heap_pointer().ok_or(HeapReleaseError::InvalidChild)?;
    if heap == main {
        return Ok(None);
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
    Ok(Some(image))
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

    /// The Rust page-engine state beside a non-main Heap's Theap does not
    /// move its metadata block out of the source `sizeof(mi_theap_t)` size
    /// class, so metadata page use matches source.
    #[test]
    fn child_heap_theap_image_keeps_the_theap_size_class() {
        assert_eq!(
            crate::size_class::bin(size_of::<crate::meta::ChildHeapTheapImage>()),
            crate::size_class::bin(size_of::<crate::types::Theap>()),
        );
    }

    /// An OS-backed page that a finished thread abandoned to a non-main Heap
    /// moves with `mi_heap_delete` to the child main Heap's OS-abandoned
    /// list (`arena.c:2502-2513,2562-2604`), and its block's later free
    /// unabandons and unmaps it there.
    #[test]
    fn heap_delete_moves_an_abandoned_os_page_to_the_main_heap() {
        with_owner_local_fixture(true, |attachment, mut heap_owner, pair| {
            let (parent, registry, binding) = child_fixture_inputs(attachment, pair);
            let keys = HeapKeySource {
                registry: OwnedThreadLocalKeyRegistry::test_static_owner(),
                subprocess: parent,
                metadata: attachment.parent_metadata_allocator(),
            };
            // SAFETY: the registry holds main; this is the attached fixture thread.
            let mut child = unsafe { new_child(registry, attachment, &mut heap_owner) }.expect("the child is created");
            struct Shared<T>(T);
            // SAFETY: each scoped worker is the only user until joined.
            unsafe impl<T> Send for Shared<T> {}
            let main = child.main_heap_pointer().unwrap();
            let shared = Shared((&mut child, binding, keys));
            let (heap, block) = std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, keys) = shared.0;
                    // SAFETY: a fresh thread owns its pristine roots.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) = (unsafe { add_current_thread(child, binding) }) else {
                        panic!("a fresh thread joins the child");
                    };
                    let heap = unsafe { child_heap_new(child, &mut member, binding, keys) }.expect("a Heap");
                    let theap = unsafe { member.owner_mut().heap_theap(child, binding, heap) }.expect("a Theap");
                    let owner: *mut ChildThreadOwner = member.owner_mut();
                    let child_pointer: *mut ChildMainHeapContextOwner<'_> = &mut *child;
                    let block = unsafe {
                        ChildThreadOwner::with_heap_theap_page_engine(owner, child_pointer, binding, theap, |engine| {
                            engine.allocate_aligned(10 * crate::config::KIB + 1, 128 * crate::config::KIB).unwrap()
                        })
                    }
                    .expect("the Heap engine runs");
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes with its OS page");
                    Shared((heap, block))
                })
                .join()
                .expect("the allocating thread completes")
                .0
            });
            let page = unsafe { binding.page_map().lookup_live_allocation(block) }.unwrap().unwrap().page();
            assert_eq!(unsafe { Heap::os_abandoned_head_at(heap) }, page.as_ptr());
            let shared = Shared((&mut child, binding, heap));
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, heap) = shared.0;
                    // SAFETY: a fresh thread owns its pristine roots.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) = (unsafe { add_current_thread(child, binding) }) else {
                        panic!("a fresh thread joins the child");
                    };
                    assert_eq!(unsafe { child_heap_delete(child, &mut member, binding, heap) },
                        Ok(HeapReleaseOutcome::Released));
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes");
                })
                .join()
                .expect("the deleting thread completes");
            });
            assert_eq!(unsafe { Heap::os_abandoned_head_at(main) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref() }.heap(), main.as_ptr());
            let allocation = unsafe { binding.page_map().lookup_live_allocation(block) }.unwrap().unwrap();
            assert_eq!(
                unsafe { crate::subproc::lifecycle::free_child_block_nonlocal(binding, allocation, |_| crate::abandoned::ReclaimOnFreeOutcome::Declined) },
                Some(crate::single_thread::ChildNonlocalFreeResult::Released),
            );
            assert!(unsafe { Heap::os_abandoned_head_at(main) }.is_null());
            // SAFETY: the child has no users or threads left.
            unsafe { destroy_child(child, registry, binding, &mut [], attachment, &mut heap_owner) }
                .expect("the child is destroyed");
            heap_owner.finish(attachment).expect("the parent engine is quiescent");
            attachment.finish_after_user_destructors().expect("the parent attachment completes");
        });
    }

    /// A failed OS unmap on a non-main Heap's Theap is retained on the
    /// thread for a raw retry, as the main-Heap Theap's is, rather than
    /// leaked: that Theap's engine stops at `RetryPending` and the retry
    /// completes it.
    #[test]
    fn non_main_heap_theap_retains_a_failed_os_unmap_for_retry() {
        with_owner_local_fixture(true, |attachment, mut heap_owner, pair| {
            let (parent, registry, binding) = child_fixture_inputs(attachment, pair);
            let keys = HeapKeySource {
                registry: OwnedThreadLocalKeyRegistry::test_static_owner(),
                subprocess: parent,
                metadata: attachment.parent_metadata_allocator(),
            };
            // SAFETY: the registry holds main; this is the attached fixture thread.
            let mut child = unsafe { new_child(registry, attachment, &mut heap_owner) }.expect("the child is created");
            struct Shared<T>(T);
            // SAFETY: the scoped worker is the only user until joined.
            unsafe impl<T> Send for Shared<T> {}
            let shared = Shared((&mut child, binding, keys));
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, keys) = shared.0;
                    // SAFETY: a fresh thread owns its pristine roots.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) = (unsafe { add_current_thread(child, binding) }) else {
                        panic!("a fresh thread joins the child");
                    };
                    let heap = unsafe { child_heap_new(child, &mut member, binding, keys) }.expect("a Heap");
                    let theap = unsafe { member.owner_mut().heap_theap(child, binding, heap) }.expect("a Theap");
                    let fault = crate::os::fault::install(crate::os::fault::Plan::disabled());
                    let owner: *mut ChildThreadOwner = member.owner_mut();
                    let child_pointer: *mut ChildMainHeapContextOwner<'_> = child;
                    // SAFETY: the admitted thread's own Theap; nothing else runs.
                    let released = unsafe {
                        ChildThreadOwner::with_heap_theap_page_engine(owner, child_pointer, binding, theap, |engine| {
                            // The source-aligned singleton route owns a distinct OS mapping.
                            let block = engine.allocate_aligned(crate::config::SMALL_MAX_OBJ_SIZE + 1, 128 * 1024)
                                .expect("an OS-backed block");
                            assert!(unsafe { (*engine.page_for_block(block)).memid().kind().is_os() });
                            fault.set(crate::os::fault::Plan::at(crate::os::fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                            unsafe { engine.free(block) }.expect("the free succeeds while its unmap is retained");
                        })
                    };
                    assert_eq!(released, Err(ChildMetadataPageEngineError::EngineRetained));
                    fault.set(crate::os::fault::Plan::disabled());
                    assert!(member.owner_mut().test_has_heap_theap_pending_os_release());
                    assert_eq!(unsafe { ChildThreadOwner::test_heap_theap_engine_state(theap) },
                        crate::meta::ChildPageEngineState::RetryPending);
                    assert_eq!(unsafe { member.owner_mut().retry_heap_theap_pending_os_release() }, Ok(true));
                    assert!(!member.owner_mut().test_has_heap_theap_pending_os_release());
                    assert_eq!(unsafe { ChildThreadOwner::test_heap_theap_engine_state(theap) },
                        crate::meta::ChildPageEngineState::RetryComplete);
                    assert_eq!(unsafe { child_heap_destroy(child, &mut member, binding, heap) },
                        Ok(HeapReleaseOutcome::Released));
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes");
                })
                .join()
                .expect("the child thread completes");
            });
            // SAFETY: the child has no users or threads left.
            unsafe { destroy_child(child, registry, binding, &mut [], attachment, &mut heap_owner) }
                .expect("the child is destroyed");
            heap_owner.finish(attachment).expect("the parent engine is quiescent");
            attachment.finish_after_user_destructors().expect("the parent attachment completes");
        });
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
            let mut outlived: Option<(NonNull<Heap>, NonNull<u8>, NonNull<Heap>, NonNull<u8>)> = None;
            let shared = Shared((&mut child, binding, keys, &mut outlived));
            let mut trace = std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, keys, outlived) = shared.0;
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

                    // Per-thread Theaps and `mi_heap_destroy` with live pages;
                    // see the matching C section.
                    let main_theap = member.theap_pointer().expect("the member's main-Heap Theap");
                    let theaps = |child: &mut ChildMainHeapContextOwner<'_>| {
                        child.with_child_image(|image| image.identity().statistics().final_output_snapshot().theaps)
                            .expect("the child projects its image")
                    };
                    let fourth = unsafe { child_heap_new(child, &mut member, binding, keys) }
                        .expect("the fourth Heap is created");
                    // SAFETY (below): live Theaps and Heaps; no list operation
                    // runs on another thread.
                    trace.push(i64::from(unsafe { fourth.as_ref() }.test_theaps_head().is_null()));
                    trace.push(member.owner_mut().test_thread_local_count() as i64);
                    let allocate_in = |child: &mut ChildMainHeapContextOwner<'_>, member: &mut crate::subproc::lifecycle::ChildThreadMember, heap: NonNull<Heap>, size| {
                        unsafe { child_heap_allocate(child, member, binding, heap, size, false) }
                            .expect("the Heap allocation runs")
                            .expect("the Heap allocates")
                    };
                    let allocate = |child: &mut ChildMainHeapContextOwner<'_>, member: &mut crate::subproc::lifecycle::ChildThreadMember, size| {
                        allocate_in(child, member, fourth, size)
                    };
                    let a = allocate(child, &mut member, 64);
                    let theap = NonNull::new(unsafe { fourth.as_ref() }.test_theaps_head()).expect("a Theap");
                    let (hnext, hprev, tnext, _tprev, tld) = unsafe { crate::types::Theap::test_list_links(theap) };
                    trace.push(i64::from(hnext.is_null() && hprev.is_null()
                        && unsafe { crate::types::Theap::heap_at(theap) } == fourth.as_ptr()));
                    let (_, _, _, main_tprev, main_tld) = unsafe { crate::types::Theap::test_list_links(main_theap) };
                    trace.push(i64::from(tld == main_tld
                        && unsafe { crate::types::ThreadLocalData::theaps_head_at(NonNull::new(tld).unwrap()) } == theap.as_ptr()
                        && tnext == main_theap.as_ptr() && main_tprev == theap.as_ptr()));
                    trace.push(unsafe { theap.as_ref() }.refcount() as i64);
                    trace.push(i64::from(crate::compiler_tls::cached_theap() == theap));
                    trace.push(member.owner_mut().test_thread_local_count() as i64);
                    trace.push(i64::from(member.owner_mut().test_heap_slot(fourth) == theap.as_ptr().cast()));
                    let statistics = theaps(child);
                    trace.push(statistics.current);
                    trace.push(statistics.total);
                    trace.push(unsafe { theap.as_ref() }.page_count() as i64);
                    let page_of = |block: NonNull<u8>| {
                        unsafe { binding.page_map().lookup_live_allocation(block) }.unwrap().unwrap().page()
                    };
                    trace.push(i64::from(unsafe { page_of(a).as_ref() }.heap() == fourth.as_ptr()));
                    trace.push(unsafe { fourth.as_ref() }.test_arena_page_record_count() as i64);
                    let b = allocate(child, &mut member, 1000);
                    let c = allocate(child, &mut member, 64);
                    trace.push(unsafe { theap.as_ref() }.page_count() as i64);
                    trace.push(i64::from(page_of(a) == page_of(c) && page_of(a) != page_of(b)));
                    unsafe { child_thread_free(child, &mut member, binding, c) }.expect("the Heap block is freed");
                    // SAFETY: the page holds the live block `a`.
                    trace.push(unsafe { *crate::types::Page::abandonment_state_at(page_of(a)).used.as_ptr() } as i64);

                    assert_eq!(unsafe { child_heap_destroy(child, &mut member, binding, fourth) },
                        Ok(HeapReleaseOutcome::Released));
                    trace.push(theaps(child).current);
                    let (_, _, _, main_tprev, main_tld) = unsafe { crate::types::Theap::test_list_links(main_theap) };
                    trace.push(i64::from(
                        unsafe { crate::types::ThreadLocalData::theaps_head_at(NonNull::new(main_tld).unwrap()) } == main_theap.as_ptr()
                            && main_tprev.is_null(),
                    ));
                    let (_, _, _, _, destroyed_tld) = unsafe { crate::types::Theap::test_list_links(theap) };
                    trace.push(i64::from(crate::compiler_tls::cached_theap() == theap && destroyed_tld.is_null()));
                    trace.push(unsafe { theap.as_ref() }.refcount() as i64);
                    push_counts(&mut trace, child);
                    trace.push(i64::from(list_is(child, &[main])));

                    // The next Heap image comes from the main Heap through
                    // `_mi_heap_theap(heap_main)`, freeing the cached Theap.
                    let fifth = unsafe { child_heap_new(child, &mut member, binding, keys) }
                        .expect("the fifth Heap is created");
                    trace.push(i64::from(crate::compiler_tls::cached_theap() == main_theap));
                    trace.push(theaps(child).current);
                    // mi_heap_delete with live pages moves them to the main Heap.
                    let d = allocate_in(child, &mut member, fifth, 64);
                    let e = allocate_in(child, &mut member, fifth, 1000);
                    let (d_page, e_page) = (page_of(d), page_of(e));
                    assert_eq!(unsafe { child_heap_delete(child, &mut member, binding, fifth) },
                        Ok(HeapReleaseOutcome::Released));
                    trace.push(i64::from(unsafe {
                        d_page.as_ref().heap() == main.as_ptr() && e_page.as_ref().heap() == main.as_ptr()
                    }));
                    let count_of = |heap: NonNull<Heap>, page: NonNull<crate::types::Page>| {
                        // SAFETY: the page and Heap are live.
                        let bin = crate::size_class::bin(unsafe { page.as_ref() }.block_size()).unwrap();
                        unsafe { heap.as_ref() }.abandoned_count(bin).unwrap() as i64
                    };
                    let thread_of = |page: NonNull<crate::types::Page>| {
                        // SAFETY: the page holds a live block; atomic reads.
                        let state = unsafe { crate::types::Page::abandonment_state_at(page) };
                        unsafe { state.xthread_id.as_ref() }.load(core::sync::atomic::Ordering::Relaxed)
                            & !(crate::types::PAGE_FLAG_MASK as usize)
                    };
                    trace.push(i64::from(thread_of(d_page) <= crate::types::THREAD_ID_ABANDONED_MAPPED));
                    trace.push(i64::from(thread_of(d_page) == crate::types::THREAD_ID_ABANDONED_MAPPED));
                    trace.push(count_of(main, d_page));
                    trace.push(count_of(main, e_page));
                    trace.push(unsafe { *crate::types::Page::abandonment_state_at(d_page).used.as_ptr() } as i64);
                    trace.push(theaps(child).current);
                    push_counts(&mut trace, child);
                    let d_bin = crate::size_class::bin(unsafe { d_page.as_ref() }.block_size()).unwrap();
                    unsafe { child_thread_free(child, &mut member, binding, d) }.expect("the moved block is freed");
                    trace.push(unsafe { main.as_ref() }.abandoned_count(d_bin).unwrap() as i64);
                    // A thread that finishes with a live block on a non-main
                    // Heap's page abandons that page to the Heap.
                    let sixth = unsafe { child_heap_new(child, &mut member, binding, keys) }
                        .expect("the sixth Heap is created");
                    let sixth_block = allocate_in(child, &mut member, sixth, 64);
                    // An OS-backed block on another Heap joins that Heap's
                    // OS-abandoned list when this thread finishes.
                    let seventh = unsafe { child_heap_new(child, &mut member, binding, keys) }
                        .expect("the seventh Heap is created");
                    let seventh_theap = unsafe { member.owner_mut().heap_theap(child, binding, seventh) }.expect("a Theap");
                    let owner: *mut ChildThreadOwner = member.owner_mut();
                    let child_pointer: *mut ChildMainHeapContextOwner<'_> = &mut *child;
                    let seventh_block = unsafe {
                        ChildThreadOwner::with_heap_theap_page_engine(owner, child_pointer, binding, seventh_theap, |engine| {
                            let block = engine.allocate_aligned(10 * crate::config::KIB + 1, 128 * crate::config::KIB)
                                .expect("an OS-backed block");
                            assert!(unsafe { (*engine.page_for_block(block)).memid().kind().is_os() });
                            block
                        })
                    }
                    .expect("the Heap engine runs");
                    *outlived = Some((sixth, sixth_block, seventh, seventh_block));
                    // SAFETY: every Heap image was freed through this thread.
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes");
                    trace
                })
                .join()
                .expect("the child thread completes")
            });
            trace.push(list_length(&mut child));
            // `_mi_thread_done` released the cached Theap.
            let theaps = child
                .with_child_image(|image| image.identity().statistics().final_output_snapshot().theaps)
                .expect("the child projects its image");
            trace.push(theaps.current);
            trace.push(theaps.total);
            let (sixth, sixth_block, seventh, seventh_block) = outlived.expect("the worker left its Heaps");
            // SAFETY: the block is live and observed through the fixture PageMap.
            let sixth_page = unsafe { binding.page_map().lookup_live_allocation(sixth_block) }.unwrap().unwrap().page();
            trace.push(i64::from(unsafe {
                sixth_page.as_ref().heap() == sixth.as_ptr() && sixth.as_ref().test_theaps_head().is_null()
            }));
            let state = unsafe { crate::types::Page::abandonment_state_at(sixth_page) };
            trace.push(i64::from(
                unsafe { state.xthread_id.as_ref() }.load(core::sync::atomic::Ordering::Relaxed)
                    & !(crate::types::PAGE_FLAG_MASK as usize)
                    == crate::types::THREAD_ID_ABANDONED_MAPPED,
            ));
            let bin = crate::size_class::bin(state.block_size).unwrap();
            trace.push(unsafe { sixth.as_ref() }.abandoned_count(bin).unwrap() as i64);

            let seventh_page = unsafe { binding.page_map().lookup_live_allocation(seventh_block) }.unwrap().unwrap().page();
            let (seventh_next, seventh_prev) = unsafe { crate::types::Page::test_list_links(seventh_page) };
            trace.push(i64::from(
                unsafe { Heap::os_abandoned_head_at(seventh) } == seventh_page.as_ptr()
                    && seventh_next.is_null() && seventh_prev.is_null(),
            ));
            let state = unsafe { crate::types::Page::abandonment_state_at(seventh_page) };
            trace.push(i64::from(
                unsafe { state.xthread_id.as_ref() }.load(core::sync::atomic::Ordering::Relaxed)
                    & !(crate::types::PAGE_FLAG_MASK as usize)
                    == crate::types::THREAD_ID_ABANDONED,
            ));
            // This thread is outside the child, so its free never reclaims.
            let allocation = unsafe { binding.page_map().lookup_live_allocation(seventh_block) }.unwrap().unwrap();
            assert_eq!(
                unsafe { crate::subproc::lifecycle::free_child_block_nonlocal(binding, allocation, |_| crate::abandoned::ReclaimOnFreeOutcome::Declined) },
                Some(crate::single_thread::ChildNonlocalFreeResult::Released),
            );
            trace.push(i64::from(unsafe { Heap::os_abandoned_head_at(seventh) }.is_null()));

            // Reclaim; see `abandon_main` and `reclaim_main` in the C oracle.
            let child_ref = &mut child;
            let handoff = std::thread::scope(|scope| {
                let shared = Shared((&mut *child_ref, binding));
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding) = shared.0;
                    // SAFETY: a fresh thread owns its pristine roots.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) = (unsafe { add_current_thread(child, binding) }) else {
                        panic!("a fresh thread joins the child");
                    };
                    // SAFETY: the admitted thread runs its own engine.
                    let blocks = unsafe {
                        member.with_page_engine(binding, |_image, engine| {
                            [engine.allocate(64, false).unwrap(), engine.allocate(64, false).unwrap()]
                                .map(|block| block.as_ptr().addr())
                        })
                    }
                    .expect("the thread allocates");
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes");
                    blocks
                })
                .join()
                .expect("the abandoning thread completes")
            });
            let reclaim_trace = std::thread::scope(|scope| {
                let shared = Shared((&mut *child_ref, binding, sixth, sixth_block, handoff));
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, sixth, sixth_block, handoff) = shared.0;
                    let mut trace: Vec<i64> = Vec::new();
                    // SAFETY: a fresh thread owns its pristine roots.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) = (unsafe { add_current_thread(child, binding) }) else {
                        panic!("a fresh thread joins the child");
                    };
                    let main = child.main_heap_pointer().unwrap();
                    let theap = member.theap_pointer().unwrap();
                    let block = |address: usize| NonNull::new(address as *mut u8).unwrap();
                    let page_of = |block: NonNull<u8>| {
                        unsafe { binding.page_map().lookup_live_allocation(block) }.unwrap().unwrap().page()
                    };
                    let thread_of = |page: NonNull<crate::types::Page>| {
                        let state = unsafe { crate::types::Page::abandonment_state_at(page) };
                        unsafe { state.xthread_id.as_ref() }.load(core::sync::atomic::Ordering::Relaxed)
                            & !(crate::types::PAGE_FLAG_MASK as usize)
                    };
                    let used = |page: NonNull<crate::types::Page>| unsafe {
                        *crate::types::Page::abandonment_state_at(page).used.as_ptr()
                    } as i64;
                    let page = page_of(block(handoff[1]));
                    let bin = crate::size_class::bin(unsafe { page.as_ref() }.block_size()).unwrap();
                    trace.push(unsafe { main.as_ref() }.abandoned_count(bin).unwrap() as i64);
                    unsafe { child_thread_free(child, &mut member, binding, block(handoff[0])) }.expect("the free runs");
                    trace.push(i64::from(
                        thread_of(page) > crate::types::THREAD_ID_ABANDONED_MAPPED
                            && unsafe { page.as_ref() }.theap() == theap.as_ptr()
                            && thread_of(page) == member.thread().get(),
                    ));
                    trace.push(used(page));
                    trace.push(unsafe { main.as_ref() }.abandoned_count(bin).unwrap() as i64);
                    trace.push(unsafe { theap.as_ref() }.page_count() as i64);
                    let sixth_page = page_of(sixth_block);
                    let sixth_bin = crate::size_class::bin(unsafe { sixth_page.as_ref() }.block_size()).unwrap();
                    let reused = unsafe { child_heap_allocate(child, &mut member, binding, sixth, 64, false) }
                        .expect("the Heap allocation runs").expect("the Heap allocates");
                    trace.push(i64::from(page_of(reused) == sixth_page && thread_of(sixth_page) > crate::types::THREAD_ID_ABANDONED_MAPPED));
                    let heap_theap = unsafe { sixth.as_ref() }.test_theaps_head();
                    let (_, _, _, _, heap_theap_tld) = unsafe { crate::types::Theap::test_list_links(NonNull::new(heap_theap).unwrap()) };
                    let (_, _, _, _, main_tld) = unsafe { crate::types::Theap::test_list_links(theap) };
                    trace.push(i64::from(unsafe { sixth_page.as_ref() }.theap() == heap_theap && heap_theap_tld == main_tld));
                    trace.push(used(sixth_page));
                    trace.push(unsafe { sixth.as_ref() }.abandoned_count(sixth_bin).unwrap() as i64);
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes");
                    trace
                })
                .join()
                .expect("the reclaiming thread completes")
            });
            trace.extend(reclaim_trace);
            // `mi_subproc_destroy` force-destroys the non-main Heap with its
            // abandoned page and live block.
            // SAFETY: the child has no users or threads left.
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
