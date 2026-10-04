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
//! An explicitly selected arena belongs to this child and retains every
//! Theap and page allocated from it. Process-main Heaps use their separate
//! owner while sharing these source list and page transitions.

use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use super::{Heap, SourceHeapRegistryError};
use crate::types::Theap;
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
    /// The complete release must not be retried because earlier list and
    /// count transitions have already consumed their original authority.
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
    // SAFETY: forwarded child and current-thread obligations.
    unsafe { child_heap_new_in_arena(child, member, binding, keys, crate::arena::ArenaId::none()) }
}

/// The selected-parent form of source `mi_heap_new_in_arena`. A non-null
/// parent remains owned by this child until its Heap, Theaps, and pages end.
///
/// # Safety
/// As for [`child_heap_new`]; `arena` is null or a live parent arena owned by
/// this child and retained through every allocation made from the Heap.
pub(crate) unsafe fn child_heap_new_in_arena(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    keys: HeapKeySource,
    arena: crate::arena::ArenaId,
) -> Result<NonNull<Heap>, HeapNewError> {
    let config = binding.page_map().memory_config().map_err(|_| HeapNewError::InvalidChild)?;
    // heap.c:136 `mi_heap_zalloc(heap_main, sizeof(mi_heap_t))` reaches the
    // thread's main-Heap Theap through `_mi_heap_theap(heap_main)`, which
    // makes it the cached Theap (and so may free a destroyed Heap's Theap).
    let owner = member.owner_mut();
    let main_theap = owner.theap_pointer().ok_or(HeapNewError::InvalidChild)?;
    // SAFETY: forwarded current-thread obligation.
    unsafe { owner.cached_set(child, binding, main_theap) }.map_err(|_| HeapNewError::Retained)?;
    #[cfg(target_arch = "x86_64")]
    let image_size = crate::source_heap_api::SOURCE_HEAP_IMAGE_REQUEST_SIZE;
    #[cfg(not(target_arch = "x86_64"))]
    let image_size = size_of::<NonMainHeapImage>();
    // SAFETY: forwarded current-thread obligation.
    let (block, extent_invalid) = unsafe {
        member.with_page_engine(binding, |_child, engine| {
            let block = engine.allocate(image_size, true)?;
            // The allocating engine owns this PageMap. A process-global
            // usable-size query cannot observe an independent child binding.
            #[cfg(target_arch = "x86_64")]
            // SAFETY: this engine just returned the exact live private block.
            let extent_invalid = unsafe { engine.usable_size(block) }
                .is_none_or(|usable| usable < image_size);
            #[cfg(not(target_arch = "x86_64"))]
            let extent_invalid = false;
            Some((block, extent_invalid))
        })
    }
    .map_err(HeapNewError::ImageAllocation)?
    .ok_or(HeapNewError::ImageAllocation(ChildMetadataPageEngineError::SessionNotReady))?;
    let image = block.cast::<NonMainHeapImage>();
    // heap.c:139-144 `_mi_thread_local_create`; failure frees the image.
    let slot = if image.as_ptr().addr() % align_of::<NonMainHeapImage>() != 0
        || extent_invalid
    {
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
    let memory = crate::types::MemoryId::malloc(block.as_ptr(), image_size, true);
    // SAFETY: the zeroed block is exclusively owned, large enough, and
    // aligned. The slot moves once into its sole release owner before Heap
    // initialization and list publication. A refused child projection retains
    // this allocation and key without reading or dropping its Heap bytes.
    unsafe {
        #[cfg(not(target_arch = "x86_64"))]
        Heap::write_bootstrap_empty_at(image.cast());
        core::ptr::addr_of_mut!((*image.as_ptr()).slot).write(Some(slot));
    }
    let heap = image.cast::<Heap>();
    let linked = child.with_child_image(|image_ref| {
        let identity = image_ref.identity();
        // SAFETY: the image is exclusively owned until the list publishes it,
        // and stays pinned in its allocation until `mi_heap_free`.
        // heap.c:103-114, then the list push at 115-124.
        #[cfg(target_arch = "x86_64")]
        unsafe { Heap::write_non_main_at(heap, identity, key, arena.as_ptr(), memory) };
        let heap = unsafe { &mut *heap.as_ptr() };
        #[cfg(not(target_arch = "x86_64"))]
        heap.initialize_non_main(identity, key, arena.as_ptr(), memory);
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
    // SAFETY: forwarded child Heap and owner obligations.
    unsafe { child_heap_allocate_variant(child, member, binding, heap, size, None, zero) }
}

/// The offset-aligned forms of a child Heap allocation use the same Theap
/// selected for an ordinary request from that Heap.
///
/// # Safety
/// As for [`child_heap_allocate`]; `aligned` is a valid source alignment and
/// offset pair.
pub(crate) unsafe fn child_heap_allocate_variant(
    child: &mut ChildMainHeapContextOwner<'_>,
    member: &mut ChildThreadMember,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
    size: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Result<Option<NonNull<u8>>, HeapAllocateError> {
    let owner = member.owner_mut();
    // SAFETY: forwarded current-thread and exclusion obligations.
    let theap = unsafe { owner.heap_theap(child, binding, heap) }.map_err(HeapAllocateError::Theap)?;
    let owner: *mut ChildThreadOwner = owner;
    // SAFETY: as above; neither pointer is otherwise borrowed for the call.
    unsafe {
        ChildThreadOwner::with_heap_theap_page_engine(owner, child, binding, theap, |engine| match aligned {
            None => engine.allocate(size, zero),
            Some((alignment, offset)) if zero => engine.allocate_aligned_zeroed_at(size, alignment, offset),
            Some((alignment, offset)) => engine.allocate_aligned_at(size, alignment, offset),
        })
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
/// that [`child_heap_new`] returned for it. Any failed full release retains
/// backing terminally after possible list/page mutations; do not use this
/// Heap again or repeat its complete release transition.
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

/// `mi_heap_delete` by a caller outside the child's subprocess. Live pages
/// move to the child's main Heap, while their transfer statistics use the
/// caller's main Theap selected through the shared main-Heap TLS key.
///
/// # Safety
/// `heap` is a live Heap of `child`, no thread uses it during the call, and
/// `theap` is the caller's initialized main Theap retained through the
/// release. The child record lock excludes concurrent lifecycle operations.
pub(crate) unsafe fn child_heap_delete_foreign(
    child: &mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
    theap: NonNull<Theap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    let main = child.main_heap_pointer().ok_or(HeapReleaseError::InvalidChild)?;
    let target = crate::single_thread::NonMainHeapPageTarget { heap: main, theap };
    // SAFETY: the caller retains this Theap and both child Heap identities.
    unsafe { child_heap_release_foreign(child, binding, heap, Some(target)) }
}

/// `mi_heap_destroy` of a child Heap by a thread outside that subprocess.
/// Its former owner may have exited, so all detached Theaps and Heap-owned
/// blocks are released through their child backing without a caller TLD.
///
/// # Safety
/// `heap` is a live non-main Heap of `child`, no thread uses it during this
/// call, and no block of it is used after the call. The child record lock
/// excludes concurrent child lifecycle operations.
pub(crate) unsafe fn child_heap_destroy_foreign(
    child: &mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    // SAFETY: no client is used after this destructive release.
    unsafe { child_heap_release_foreign(child, binding, heap, None) }
}

/// The source detach, page move or destruction, and Heap-image free for a
/// foreign caller. Child backing remains the authority for every release;
/// no temporary caller TLD or subprocess identity is installed.
///
/// # Safety
/// As for the foreign delete or destroy entry; `target`, when present, is
/// the child's main Heap and the caller's retained main Theap.
unsafe fn child_heap_release_foreign(
    child: &mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    heap: NonNull<Heap>,
    target: Option<crate::single_thread::NonMainHeapPageTarget>,
) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    if child.main_heap_pointer() == Some(heap) {
        return Ok(HeapReleaseOutcome::MainHeapRefused);
    }
    let identity = child
        .with_child_image(|image| core::ptr::NonNull::from(image.get_ref().identity()))
        .ok_or(HeapReleaseError::InvalidChild)?;
    let mut released = true;
    // SAFETY: the Heap's Theap list is stable under the child record lock.
    unsafe {
        heap.as_ref().detach_and_take_theaps(identity.as_ref(), |theap| {
            heap.as_ref().merge_detached_theap_statistics(theap.as_ref());
            if !Theap::decref_at(theap) {
                return;
            }
            if !Theap::is_detached_at(theap) {
                identity.as_ref().record_statistics_theap_unlinked();
            }
            let memory = theap.as_ref().memory_id();
            if memory.arena_memory().is_some() {
                // SAFETY: this was the Theap's final reference and its list
                // edge was just removed; the child retains the arena.
                core::ptr::drop_in_place(theap.as_ptr());
                released &= child.with_child_image(|image| {
                    unsafe { image.get_ref().identity().arena_backing().release_slices(memory) }
                }) == Some(true);
            } else {
                let mut freed = false;
                let result = child.with_metadata_page_engine(binding, |_child, engine| {
                    freed = unsafe { engine.free(theap.cast()) }.is_ok();
                });
                released &= result.is_ok() && freed;
            }
        })
    }
    .map_err(HeapReleaseError::List)?;
    if !released {
        return Err(HeapReleaseError::Retained);
    }
    // SAFETY: every Theap is detached; live clients move with their pages
    // on delete and are discarded only on the destructive release.
    unsafe { delete_heap_pages(child, binding, heap, target) }?;
    // SAFETY: each record remains a live child block until its own free.
    #[cfg(target_arch = "x86_64")]
    let records_released = unsafe { heap.as_ref().take_non_main_arena_pages(|record| {
        unsafe { free_foreign_child_block_with_progress(binding, record) }
    }) };
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: retain the historical terminal legacy record-free contract.
    let records_released = unsafe { heap.as_ref().legacy_take_non_main_arena_pages(|record| {
        unsafe { free_foreign_child_block(binding, record) }
    }) };
    if !records_released {
        return Err(HeapReleaseError::Retained);
    }
    // SAFETY: the Heap now has no Theap or page and the child owns it.
    let image = unsafe { unlink_empty_heap(child, heap) }?.ok_or(HeapReleaseError::InvalidChild)?;
    // SAFETY: the image has left every Heap list and remains a live block.
    if unsafe { free_foreign_child_block(binding, image.cast()) } {
        Ok(HeapReleaseOutcome::Released)
    } else {
        Err(HeapReleaseError::Retained)
    }
}

/// `_mi_free_subproc_safe` on a caller outside the child's TLDs. Source
/// publishes the block without claiming an abandoned page for collection.
///
/// # Safety
/// `block` is one exact live child allocation that no other thread frees.
#[cfg(target_arch = "x86_64")]
unsafe fn free_foreign_child_block_with_progress(binding: ProcessMainBackingBinding, block: NonNull<u8>) -> crate::single_thread::LocalClientFreeProgress {
    use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
    // SAFETY: the block stays live until its remote publication completes.
    let Some(allocation) = (unsafe { binding.page_map().lookup_live_allocation(block) }).ok().flatten() else {
        return Progress::RefusedBeforeConsumption(FreeError::Lifecycle);
    };
    // SAFETY: the caller is outside the child's TLDs and cannot own this page.
    match unsafe { crate::remote_free::push_live_allocation_without_collect(allocation) } {
        Ok(()) => Progress::Consumed(Ok(())),
        Err(_) => Progress::RefusedBeforeConsumption(FreeError::Lifecycle),
    }
}

/// # Safety
/// `block` is an exact live foreign child allocation, retained until publication.
#[cfg(target_arch = "x86_64")]
unsafe fn free_foreign_child_block(binding: ProcessMainBackingBinding, block: NonNull<u8>) -> bool {
    matches!(unsafe { free_foreign_child_block_with_progress(binding, block) },
        crate::single_thread::LocalClientFreeProgress::Consumed(Ok(())))
}

/// Historical foreign metadata free, with the caller retaining complete
/// backing terminally after a false result.
///
/// # Safety
/// `block` is one exact live foreign child allocation, freed once.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn free_foreign_child_block(binding: ProcessMainBackingBinding, block: NonNull<u8>) -> bool {
    // SAFETY: the block remains live until source remote publication.
    let Some(allocation) = (unsafe { binding.page_map().lookup_live_allocation(block) }).ok().flatten() else {
        return false;
    };
    // SAFETY: this caller does not own the page.
    unsafe { crate::remote_free::push_live_allocation_without_collect(allocation) }.is_ok()
}

/// Frees Heap administration with the source `allow_collect=false` policy.
/// A page owned by this caller uses its ordinary local engine; a foreign or
/// abandoned page receives only a remote-list publication. Its later owner or
/// subprocess collector retains responsibility for draining and releasing it.
///
/// # Safety
/// `owner` is this thread's admitted child owner, `child` and `binding` retain
/// its allocation backing, and `block` is an exact live block freed once.
#[cfg(target_arch = "x86_64")]
unsafe fn free_heap_metadata_with_progress(
    owner: *mut ChildThreadOwner,
    child: *mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    block: NonNull<u8>,
) -> crate::single_thread::LocalClientFreeProgress {
    use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
    // SAFETY: the caller retains this exact live block through publication.
    let Some(allocation) = (unsafe { binding.page_map().lookup_live_allocation(block) }).ok().flatten() else {
        return Progress::RefusedBeforeConsumption(FreeError::Lifecycle);
    };
    let local = crate::compiler_tls::current_thread_identity()
        .is_some_and(|thread| allocation.is_associated_with(thread));
    if local {
        // SAFETY: this thread owns the page, and no projection crosses the
        // owning engine's local free operation.
        unsafe { ChildThreadOwner::free_local_heap_metadata_with_progress(owner, child, binding, allocation) }
    } else {
        // SAFETY: this caller does not own the page; source preserves its low
        // owner bit and does not collect or reclaim it from this metadata free.
        match unsafe { crate::remote_free::push_live_allocation_without_collect(allocation) } {
            Ok(()) => Progress::Consumed(Ok(())),
            Err(_) => Progress::RefusedBeforeConsumption(FreeError::Lifecycle),
        }
    }
}

/// # Safety
/// The admitted child owner and exact live metadata block obey the same
/// obligations as `free_heap_metadata_with_progress`. Failure may follow
/// consumption and is terminal for this full Heap release operation.
#[cfg(target_arch = "x86_64")]
unsafe fn free_heap_metadata(
    owner: *mut ChildThreadOwner,
    child: *mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    block: NonNull<u8>,
) -> bool {
    matches!(unsafe { free_heap_metadata_with_progress(owner, child, binding, block) },
        crate::single_thread::LocalClientFreeProgress::Consumed(Ok(())))
}

/// Historical local metadata free with unclassified terminal failures.
///
/// # Safety
/// `owner` is this thread's admitted child owner, `child` and `binding`
/// retain its backing, and `block` is an exact live allocation freed once.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn free_heap_metadata(
    owner: *mut ChildThreadOwner,
    child: *mut ChildMainHeapContextOwner<'_>,
    binding: ProcessMainBackingBinding,
    block: NonNull<u8>,
) -> bool {
    // SAFETY: the exact live block remains held until source consumption.
    let Some(allocation) = (unsafe { binding.page_map().lookup_live_allocation(block) }).ok().flatten() else {
        return false;
    };
    let local = crate::compiler_tls::current_thread_identity()
        .is_some_and(|thread| allocation.is_associated_with(thread));
    if local {
        drop(allocation);
        // SAFETY: this admitted owner holds the exact local allocation.
        unsafe { ChildThreadOwner::free_block(owner, child, binding, block) }.is_ok()
    } else {
        // SAFETY: the caller does not own this page; collect remains disabled.
        unsafe { crate::remote_free::push_live_allocation_without_collect(allocation) }.is_ok()
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
    #[cfg(target_arch = "x86_64")]
    let freed = unsafe {
        heap.as_ref().take_non_main_arena_pages(|block| {
            free_heap_metadata_with_progress(owner, child_pointer, binding, block)
        })
    };
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: retain this target's source metadata-free and terminal policy.
    let freed = unsafe {
        heap.as_ref().legacy_take_non_main_arena_pages(|block| {
            free_heap_metadata(owner, child_pointer, binding, block)
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
    if unsafe { free_heap_metadata(owner, child_pointer, binding, image.cast()) } {
        Ok(HeapReleaseOutcome::Released)
    } else {
        Err(HeapReleaseError::Retained)
    }
}

/// Pinned `_mi_heap_force_destroy(heap, false)` of a non-main child Heap
/// inside `mi_subproc_unsafe_destroy` (`subproc.c:215-221`), just before the
/// child's registry unlink (see `subproc::lifecycle::destroy_child_with`): `mi_heap_free_theaps` (the Theaps of threads that
/// still belong to the child leave their TLDs; a Theap whose last reference
/// goes is counted out of `theaps`), `_mi_heap_destroy_pages`, and
/// `mi_heap_free`. Blocks are not freed one by one: the Theap images and the
/// Heap's page records and image are live blocks in the child's metadata,
/// selected arena, and main-Heap pages, which child arena destruction releases right after,
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
    #[cfg(target_arch = "x86_64")]
    let records_transferred = unsafe { heap.as_ref().take_non_main_arena_pages(|_record| {
        crate::single_thread::LocalClientFreeProgress::Consumed(Ok(()))
    }) };
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: terminal bulk teardown retains the records' complete backing.
    let records_transferred = unsafe { heap.as_ref().legacy_take_non_main_arena_pages(|_| true) };
    if !records_transferred {
        return Err(HeapReleaseError::Retained);
    }
    // SAFETY: forwarded obligations.
    match unsafe { unlink_empty_heap(child, heap) }? {
        Some(_image) => Ok(()),
        None => Err(HeapReleaseError::InvalidChild),
    }
}

/// `_mi_heap_init` and the list push (`heap.c:103-124`) of a non-main Heap
/// of `subprocess` into a fresh zeroed image block, with its key `slot`.
///
/// # Safety
/// `block` is an exclusively owned zeroed block of at least
/// the source Heap request extent on x86-64, or `size_of::<NonMainHeapImage>()`
/// bytes on other targets; `subprocess` is live. A non-null
/// `exclusive_arena` names a live parent of this subprocess and remains live
/// for every Theap and page linked to the returned Heap.
pub(crate) unsafe fn initialize_and_link_non_main_heap(
    block: NonNull<u8>,
    slot: OwnedThreadLocalKeyLease,
    subprocess: &crate::subproc::SubprocessIdentity,
    exclusive_arena: crate::arena::ArenaId,
) -> Result<NonNull<Heap>, HeapNewError> {
    if block.as_ptr().addr() % align_of::<NonMainHeapImage>() != 0 {
        return Err(HeapNewError::Retained);
    }
    let key = slot.key().raw();
    #[cfg(target_arch = "x86_64")]
    let image_size = crate::source_heap_api::SOURCE_HEAP_IMAGE_REQUEST_SIZE;
    #[cfg(not(target_arch = "x86_64"))]
    let image_size = size_of::<NonMainHeapImage>();
    let memory = crate::types::MemoryId::malloc(block.as_ptr(), image_size, true);
    let image = block.cast::<NonMainHeapImage>();
    // SAFETY: the forwarded extent and exclusive fresh-storage obligations
    // cover both fields. Retain the slot in its sole release owner before
    // the complete Heap initialization and subsequent list publication.
    unsafe {
        #[cfg(not(target_arch = "x86_64"))]
        Heap::write_bootstrap_empty_at(image.cast());
        core::ptr::addr_of_mut!((*image.as_ptr()).slot).write(Some(slot));
    }
    let heap = image.cast::<Heap>();
    // SAFETY: the image is exclusively owned until the push publishes it.
    #[cfg(target_arch = "x86_64")]
    unsafe { Heap::write_non_main_at(heap, subprocess, key, exclusive_arena.as_ptr(), memory) };
    let heap_ref = unsafe { &mut *heap.as_ptr() };
    #[cfg(not(target_arch = "x86_64"))]
    heap_ref.initialize_non_main(subprocess, key, exclusive_arena.as_ptr(), memory);
    // SAFETY: the Heap was initialized for this subprocess just above.
    unsafe { subprocess.heap_list().link_non_main(heap_ref, subprocess) }.map_err(HeapNewError::List)?;
    Ok(heap)
}

/// Releases a detached Heap's exact key lease before removing its owner.
/// A refusal keeps the live or terminal lease in the retained Heap image.
///
/// # Safety
/// `image` is the exclusively retained live allocation of a non-main Heap
/// already removed from every source list, with no Theap, page, or TLS slot
/// user. No projection of its key field overlaps this operation.
unsafe fn release_heap_thread_local_key(
    image: NonNull<NonMainHeapImage>,
) -> Result<(), HeapReleaseError> {
    // SAFETY: project only the exact field in the caller's retained image;
    // registry release cannot free or replace that containing allocation.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!((*image.as_ptr()).slot) };
    let lease = slot.as_mut().ok_or(HeapReleaseError::Retained)?;
    lease.release().map_err(|_| HeapReleaseError::Retained)?;
    // The registry consumed this claim. Remove only the released token;
    // every error above retains its original ownership disposition in place.
    let _ = slot.take();
    Ok(())
}

/// [`unlink_empty_heap`] for a Heap of any subprocess given its main Heap:
/// statistics to `main`, count and list removal, and the key release;
/// returns the image for the caller's free.
///
/// # Safety
/// `heap` is a live non-main Heap of `subprocess` without Theaps or pages
/// that no thread uses, and `main` that subprocess's main Heap.
pub(crate) unsafe fn unlink_non_main_heap(
    heap: NonNull<Heap>,
    main: NonNull<Heap>,
    subprocess: &crate::subproc::SubprocessIdentity,
) -> Result<NonNull<NonMainHeapImage>, HeapReleaseError> {
    // SAFETY: forwarded.
    let heap_ref = unsafe { &mut *heap.as_ptr() };
    if !heap_ref.is_without_theaps_or_pages() {
        return Err(HeapReleaseError::NotEmpty);
    }
    // SAFETY: `main` is the subprocess's live main Heap.
    unsafe { heap_ref.merge_statistics_to_main(main) };
    // SAFETY: the Heap has no Theap and stays pinned until its free.
    unsafe { subprocess.heap_list().unlink_non_main(heap_ref, subprocess) }.map_err(HeapReleaseError::List)?;
    let image = heap.cast::<NonMainHeapImage>();
    // SAFETY: the image is off every list and exclusively owned now.
    unsafe { release_heap_thread_local_key(image) }?;
    Ok(image)
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
    unsafe { release_heap_thread_local_key(image) }?;
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

    /// The selected Theap's exact arena bitmap span, observed only while both
    /// workers are paused outside allocator operations.
    fn selected_theap_slice_is_free(arena: crate::arena::ArenaId, memory: crate::types::MemoryId) -> bool {
        let span = memory.arena_memory().expect("the selected Theap owns an arena slice");
        assert_eq!(span.arena, arena.as_ptr());
        // SAFETY: the child retains this published arena, and the workers do
        // not mutate its free bitmap during this observation.
        let view = unsafe { crate::arena::ArenaView::from_ptr(arena.as_ptr()) }.unwrap();
        let free = unsafe { view.slices_free() }.unwrap();
        free.is_set_range(span.slice_index as usize, span.slice_count as usize) == Some(true)
    }

    /// A Heap deletion detaches both workers' selected Theaps, but the last
    /// cached worker keeps its exact arena slice until it selects its main
    /// Heap. The child counts follow the same source list/refcount sequence.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn child_selected_arena_two_workers_hold_and_release_exact_theap_slices() {
        use crate::runtime_lifecycle::{
            finish_current_thread_native_after_user_destructors, native_free,
            prepare_native_later_thread_arena, test_initialize_process_from_host_environment,
            NativePageFreeResult, ThreadFinishResult,
        };
        use crate::subproc::lifecycle::{
            current_child_main_heap, native_child_heap_new_in_arena, native_child_heap_theap,
            native_child_reserve_os_memory, native_subproc_add_current_thread,
            native_subproc_destroy, native_subproc_new, NativeChildThreadAdd,
        };
        unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}
        crate::test_process::run_in_fresh_process(
            "types::heap_registry::lifecycle::tests::child_selected_arena_two_workers_hold_and_release_exact_theap_slices",
            || {
                assert!(test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(prepare_native_later_thread_arena());
                let child = native_subproc_new().expect("a live child");
                let (created_send, created_receive) = std::sync::mpsc::channel();
                let (joined_send, joined_receive) = std::sync::mpsc::channel();
                let (start_second_send, start_second_receive) = std::sync::mpsc::channel();
                let (second_ready_send, second_ready_receive) = std::sync::mpsc::channel();
                let (release_second_send, release_second_receive) = std::sync::mpsc::channel();
                let (second_released_send, second_released_receive) = std::sync::mpsc::channel();
                let (finish_second_send, finish_second_receive) = std::sync::mpsc::channel();

                let first = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(child) }, Ok(NativeChildThreadAdd::Added));
                    let main = current_child_main_heap().expect("the child main Heap");
                    let arena = native_child_reserve_os_memory(128 * 1024 * 1024, true, false, true, &mut None)
                        .expect("a child member").expect("a selected arena");
                    let heap = native_child_heap_new_in_arena(arena).expect("a child member")
                        .expect("a live child").expect("a selected Heap");
                    let identity = unsafe { heap.as_ref() }.subprocess_pointer();
                    created_send.send(heap.as_ptr().addr()).unwrap();
                    joined_receive.recv().unwrap();
                    // SAFETY: the child and both main Theaps are live. The
                    // second worker has joined but has not selected `heap`.
                    let baseline = unsafe { &*identity }.statistics().final_output_snapshot().theaps;
                    let first = unsafe { native_child_heap_theap(heap) }.expect("the first selected Theap");
                    let first_memory = unsafe { first.as_ref() }.memory_id();
                    let block = unsafe { crate::source_heap_api::heap_malloc(heap.as_ptr().cast(), 64) }
                        .value.expect("the first selected page");
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    assert_eq!(unsafe { native_child_heap_theap(heap) }, Some(first));
                    start_second_send.send(()).unwrap();
                    let second = NonNull::new(second_ready_receive.recv().unwrap() as *mut crate::types::Theap)
                        .expect("the second selected Theap");
                    let second_memory = unsafe { second.as_ref() }.memory_id();
                    let first_span = first_memory.arena_memory().unwrap();
                    let second_span = second_memory.arena_memory().unwrap();
                    assert_eq!(first_span.arena, arena.as_ptr());
                    assert_eq!(second_span.arena, arena.as_ptr());
                    assert_ne!(first_span.slice_index, second_span.slice_index);
                    assert!(!selected_theap_slice_is_free(arena, first_memory));
                    assert!(!selected_theap_slice_is_free(arena, second_memory));
                    assert_eq!(unsafe { heap.as_ref() }.test_theaps_head(), second.as_ptr());
                    let (second_next, _, _, _, second_tld) = unsafe { crate::types::Theap::test_list_links(second) };
                    let (first_next, _, _, _, first_tld) = unsafe { crate::types::Theap::test_list_links(first) };
                    assert_eq!(second_next, first.as_ptr());
                    assert!(first_next.is_null());
                    assert_ne!(first_tld, second_tld);
                    assert_eq!(unsafe { crate::types::ThreadLocalData::theaps_head_at(NonNull::new(first_tld).unwrap()) }, first.as_ptr());
                    assert_eq!(unsafe { crate::types::ThreadLocalData::theaps_head_at(NonNull::new(second_tld).unwrap()) }, second.as_ptr());
                    assert_eq!((unsafe { first.as_ref() }.refcount(), unsafe { second.as_ref() }.refcount()), (2, 2));
                    let before = unsafe { &*identity }.statistics().final_output_snapshot().theaps;
                    assert_eq!((before.current - baseline.current, before.total - baseline.total), (2, 2));
                    std::println!("unit.two_before={},{},{},{},{},{}",
                        i64::from(unsafe { heap.as_ref() }.test_theaps_head() == second.as_ptr()
                            && second_next == first.as_ptr() && first_next.is_null()),
                        i64::from(first_tld != second_tld
                            && unsafe { crate::types::ThreadLocalData::theaps_head_at(NonNull::new(first_tld).unwrap()) } == first.as_ptr()
                            && unsafe { crate::types::ThreadLocalData::theaps_head_at(NonNull::new(second_tld).unwrap()) } == second.as_ptr()),
                        i64::from(first_span.arena == arena.as_ptr() && second_span.arena == arena.as_ptr()
                            && first_span.slice_index != second_span.slice_index),
                        i64::from(!selected_theap_slice_is_free(arena, first_memory)
                            && !selected_theap_slice_is_free(arena, second_memory)),
                        i64::from(unsafe { first.as_ref() }.refcount() == 2 && unsafe { second.as_ref() }.refcount() == 2),
                        i64::from(before.current - baseline.current == 2 && before.total - baseline.total == 2));
                    std::println!("unit.two_refs={},{}", unsafe { first.as_ref() }.refcount(), unsafe { second.as_ref() }.refcount());

                    assert!(unsafe { crate::source_heap_api::heap_release(heap.as_ptr().cast(), false) });
                    let (detached_next, detached_prev, _, _, detached_tld) =
                        unsafe { crate::types::Theap::test_list_links(second) };
                    assert!(detached_tld.is_null());
                    assert_eq!(unsafe { second.as_ref() }.refcount(), 1);
                    assert!(selected_theap_slice_is_free(arena, first_memory));
                    assert!(!selected_theap_slice_is_free(arena, second_memory));
                    assert_eq!(unsafe { &*identity }.statistics().final_output_snapshot().theaps.current - baseline.current, 1);
                    std::println!("unit.two_detached={},{},{},{}",
                        i64::from(detached_tld.is_null() && detached_next.is_null() && detached_prev.is_null()),
                        unsafe { second.as_ref() }.refcount(),
                        i64::from(selected_theap_slice_is_free(arena, first_memory)
                            && !selected_theap_slice_is_free(arena, second_memory)),
                        unsafe { &*identity }.statistics().final_output_snapshot().theaps.current - baseline.current);
                    assert_eq!(unsafe { native_child_heap_theap(main) }, Some(crate::compiler_tls::default_theap()));
                    std::println!("unit.two_first_released={},{},{}",
                        i64::from(selected_theap_slice_is_free(arena, first_memory)),
                        i64::from(!selected_theap_slice_is_free(arena, second_memory)),
                        unsafe { &*identity }.statistics().final_output_snapshot().theaps.current - baseline.current);

                    let probe = native_child_heap_new_in_arena(arena).unwrap().unwrap().unwrap();
                    let probe_theap = unsafe { native_child_heap_theap(probe) }.expect("a probe Theap");
                    assert_ne!(probe_theap, second);
                    assert_eq!(unsafe { probe_theap.as_ref() }.memory_id().arena_memory().unwrap().arena, arena.as_ptr());
                    assert!(unsafe { crate::source_heap_api::heap_release(probe.as_ptr().cast(), true) });
                    assert_eq!(unsafe { native_child_heap_theap(main) }, Some(crate::compiler_tls::default_theap()));
                    assert!(!selected_theap_slice_is_free(arena, second_memory));
                    assert_eq!(unsafe { &*identity }.statistics().final_output_snapshot().theaps.current - baseline.current, 1);
                    std::println!("unit.two_held={},{}",
                        i64::from(!selected_theap_slice_is_free(arena, second_memory)),
                        unsafe { &*identity }.statistics().final_output_snapshot().theaps.current - baseline.current);

                    release_second_send.send(()).unwrap();
                    second_released_receive.recv().unwrap();
                    assert!(selected_theap_slice_is_free(arena, second_memory));
                    assert_eq!(unsafe { &*identity }.statistics().final_output_snapshot().theaps.current - baseline.current, 0);
                    std::println!("unit.two_released={},{}",
                        i64::from(selected_theap_slice_is_free(arena, second_memory)),
                        i64::from(unsafe { &*identity }.statistics().final_output_snapshot().theaps.current - baseline.current == 0));
                    let final_heap = native_child_heap_new_in_arena(arena).unwrap().unwrap().unwrap();
                    let final_theap = unsafe { native_child_heap_theap(final_heap) }.expect("a final selected Theap");
                    assert_eq!(unsafe { final_theap.as_ref() }.memory_id().arena_memory().unwrap().arena, arena.as_ptr());
                    assert!(unsafe { crate::source_heap_api::heap_release(final_heap.as_ptr().cast(), true) });
                    assert_eq!(unsafe { native_child_heap_theap(main) }, Some(crate::compiler_tls::default_theap()));
                    finish_second_send.send(()).unwrap();
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });

                let heap_address = created_receive.recv().unwrap();
                let second = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(child) }, Ok(NativeChildThreadAdd::Added));
                    let main = current_child_main_heap().expect("the child main Heap");
                    assert!(unsafe { native_child_heap_theap(main) }.is_some());
                    joined_send.send(()).unwrap();
                    start_second_receive.recv().unwrap();
                    let heap = NonNull::new(heap_address as *mut Heap).unwrap();
                    let selected = unsafe { native_child_heap_theap(heap) }.expect("the second selected Theap");
                    let block = unsafe { crate::source_heap_api::heap_malloc(heap.as_ptr().cast(), 96) }
                        .value.expect("the second selected page");
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    assert_eq!(unsafe { native_child_heap_theap(heap) }, Some(selected));
                    second_ready_send.send(selected.as_ptr().addr()).unwrap();
                    release_second_receive.recv().unwrap();
                    assert_eq!(unsafe { native_child_heap_theap(main) }, Some(crate::compiler_tls::default_theap()));
                    second_released_send.send(()).unwrap();
                    finish_second_receive.recv().unwrap();
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                second.join().expect("the second worker finishes");
                first.join().expect("the first worker finishes");
                // SAFETY: both workers have finished and no child Heap is used.
                assert_eq!(unsafe { native_subproc_destroy(child) }, Ok(()));
            },
        );
    }

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

    /// Source terminal OS release consumes the page and its VM accounting
    /// even when munmap fails. Heap and thread teardown must not rediscover
    /// that consumed page or retry its raw mapping.
    #[test]
    fn non_main_heap_theap_consumes_failed_os_unmap_without_teardown_retry() {
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
            let failed_range = std::thread::scope(|scope| {
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
                    let identity = child.with_child_image(|image| NonNull::from(image.identity())).unwrap();
                    let mut client_address = 0usize;
                    let mut reserved_before_free = 0i64;
                    let mut committed_before_free = 0i64;
                    let ranges = fault.capture_unmap_ranges();
                    let owner: *mut ChildThreadOwner = member.owner_mut();
                    let child_pointer: *mut ChildMainHeapContextOwner<'_> = child;
                    // SAFETY: the admitted thread's own Theap; nothing else runs.
                    let released = unsafe {
                        ChildThreadOwner::with_heap_theap_page_engine(owner, child_pointer, binding, theap, |engine| {
                            // The source-aligned singleton route owns a distinct OS mapping.
                            let block = engine.allocate_aligned(crate::config::SMALL_MAX_OBJ_SIZE + 1, 128 * 1024)
                                .expect("an OS-backed block");
                            assert!(unsafe { (*engine.page_for_block(block)).memid().kind().is_os() });
                            client_address = block.as_ptr().addr();
                            let before = unsafe { identity.as_ref() }.vm_statistics().snapshot();
                            reserved_before_free = before.reserved_current;
                            committed_before_free = before.committed_current;
                            fault.set(crate::os::fault::Plan::at(crate::os::fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                            unsafe { engine.free(block) }.expect("source free consumes the client despite failed unmap");
                        })
                    };
                    assert_eq!(released, Ok(()));
                    assert_eq!(fault.observed(), 1);
                    let (attempts, count) = ranges.all().expect("the bounded terminal release trace");
                    assert_eq!(count, 1);
                    let failed_range = attempts[0];
                    let after = unsafe { identity.as_ref() }.vm_statistics().snapshot();
                    assert_eq!(reserved_before_free - after.reserved_current, failed_range.1 as i64);
                    assert!(committed_before_free > after.committed_current);
                    assert!(!member.owner_mut().test_has_heap_theap_pending_os_release());
                    assert_eq!(unsafe { ChildThreadOwner::test_heap_theap_engine_state(theap) },
                        crate::meta::ChildPageEngineState::Active);
                    assert_eq!(unsafe { member.owner_mut().retry_heap_theap_pending_os_release() }, Ok(false));
                    assert!(!member.owner_mut().test_has_heap_theap_pending_os_release());
                    assert_eq!(unsafe { identity.as_ref() }.vm_statistics().snapshot(), after);
                    assert_eq!(fault.observed(), 1);
                    // This probes only the former address. No consumed client
                    // or metadata image is dereferenced after the free.
                    assert!(unsafe { binding.page_map().lookup_registered_page(
                        core::ptr::with_exposed_provenance_mut(client_address),
                    ) }.unwrap().is_none());
                    assert_eq!(unsafe { child_heap_destroy(child, &mut member, binding, heap) },
                        Ok(HeapReleaseOutcome::Released));
                    unsafe { member.thread_done(child, binding) }.expect("the thread finishes");
                    assert_eq!(fault.observed(), 1, "neither Heap nor thread teardown retries the source-consumed mapping");
                    assert_eq!(ranges.all().unwrap().1, 1);
                    failed_range
                })
                .join()
                .expect("the child thread completes")
            });
            // SAFETY: the child has no users or threads left.
            unsafe { destroy_child(child, registry, binding, &mut [], attachment, &mut heap_owner) }
                .expect("the child is destroyed");
            heap_owner.finish(attachment).expect("the parent engine is quiescent");
            attachment.finish_after_user_destructors().expect("the parent attachment completes");
            let mut resident = 0u8;
            // SAFETY: every allocator user and owner has finished. Only the
            // exact raw mapping refused by munmap remains; this cleanup has
            // no PageMap, Heap, client or VM-accounting capability to reuse.
            unsafe {
                let address = core::ptr::with_exposed_provenance_mut(failed_range.0);
                assert!(crabc_core::mm::mincore_raw(address, 4096, &mut resident).is_ok());
                crabc_core::mm::munmap_raw(address, failed_range.1).expect("raw-only fixture cleanup");
            }
        });
    }

    #[test]
    fn heap_key_release_refusal_retains_the_exact_lease_in_its_image() {
        with_owner_local_fixture(true, |attachment, mut heap_owner, pair| {
            let (parent, registry, binding) = child_fixture_inputs(attachment, pair);
            let keys = HeapKeySource {
                registry: OwnedThreadLocalKeyRegistry::test_static_owner(),
                subprocess: parent,
                metadata: attachment.parent_metadata_allocator(),
            };
            // SAFETY: this fixture exclusively retains its parent and child.
            let mut child = unsafe { new_child(registry, attachment, &mut heap_owner) }.unwrap();
            struct Shared<T>(T);
            // SAFETY: the scoped worker exclusively owns this state until join.
            unsafe impl<T> Send for Shared<T> {}
            let shared = Shared((&mut child, binding, keys));
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let shared = shared;
                    let (child, binding, keys) = shared.0;
                    // SAFETY: this fresh worker owns its pristine thread roots.
                    let Ok(ChildThreadAddOutcome::Added(mut member)) =
                        (unsafe { add_current_thread(child, binding) }) else { panic!("child attachment"); };
                    for direct_unlink in [false, true] {
                        // SAFETY: the admitted worker is the sole child user.
                        let heap = unsafe { child_heap_new(child, &mut member, binding, keys) }.unwrap();
                        let image = heap.cast::<NonMainHeapImage>();
                        let key = unsafe { (*image.as_ptr()).slot.as_ref().unwrap().key().raw() };
                        assert_eq!(keys.registry.test_live_lease_count(), 1);
                        keys.registry.test_fail_next_release_lock();
                        // SAFETY: this live Heap has no Theap or application
                        // pages, and no other thread uses its lists or key.
                        let result = if direct_unlink {
                            let main = child.main_heap_pointer().unwrap();
                            child.with_child_image(|image| unsafe {
                                unlink_non_main_heap(heap, main, image.identity())
                            }).unwrap().map(|_| HeapReleaseOutcome::Released)
                        } else {
                            unsafe { child_heap_destroy(child, &mut member, binding, heap) }
                        };
                        assert_eq!(result, Err(HeapReleaseError::Retained));
                        // SAFETY: the refused release retains the original live
                        // image, already off its Heap list. Only the exact key
                        // lease is settled here; no list transition is retried.
                        let slot = unsafe { &mut *core::ptr::addr_of_mut!((*image.as_ptr()).slot) };
                        let retained = slot.as_mut().expect("the image retains the unreleased key lease");
                        assert_eq!(retained.key().raw(), key);
                        assert_eq!(keys.registry.test_live_lease_count(), 1);
                        retained.release().expect("the unchanged exact lease retries its own release");
                        slot.take();
                        assert_eq!(keys.registry.test_live_lease_count(), 0);
                        // SAFETY: key release completed; no source pointer or
                        // field view names this original live Heap image now.
                        assert!(unsafe { free_heap_metadata(member.owner_mut(), child, binding, image.cast()) });
                    }
                    // SAFETY: all images and key leases have been released.
                    unsafe { member.thread_done(child, binding) }.unwrap();
                }).join().unwrap();
            });
            // SAFETY: the sole worker joined with every Heap and key released.
            unsafe { destroy_child(child, registry, binding, &mut [], attachment, &mut heap_owner) }
                .ok().expect("the child is destroyed");
            heap_owner.finish(attachment).expect("the parent engine is quiescent");
            attachment.finish_after_user_destructors().expect("the parent attachment completes");
        });
    }

    /// Emits the source-ordered state of empty child Heaps across creation,
    /// deletion, and destruction, including list and count transitions.
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
                    // The Heap image must retain its ordinary allocation in
                    // this child's PageMap through publication and deletion.
                    let usable = unsafe {
                        member.with_page_engine(binding, |_child, engine| {
                            unsafe { engine.usable_size(first.cast()) }
                        })
                    }.expect("the allocating engine remains available")
                        .expect("the live Heap image is in its allocating PageMap");
                    assert!(usable >= size_of::<NonMainHeapImage>());
                    #[cfg(target_arch = "x86_64")]
                    assert!(usable >= crate::source_heap_api::SOURCE_HEAP_IMAGE_REQUEST_SIZE);
                    assert_eq!(first.as_ptr().addr() % align_of::<NonMainHeapImage>(), 0);
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
