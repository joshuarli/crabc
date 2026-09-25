// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/heap.c:59-259 (`_mi_heap_theap_get_or_init`,
// `_mi_heap_new_for_subproc`, `mi_heap_free_theaps`, `mi_heap_free`,
// `mi_heap_delete`, `_mi_heap_force_destroy`, `mi_heap_destroy`),
// src/theap.c:236-445, src/init.c:377-480, src/threadlocal.c:103-202,
// src/prim/prim-tls.c:211-229, and src/arena.c:1661-1672,2531-2644.

//! Non-main Heaps of the process main subprocess (`mi_heap_new` on an
//! ordinary thread).
//!
//! A Heap is a `NonMainHeapImage` allocated from the process main Heap
//! through the calling thread's native owner, on a key of the process-global
//! thread-local registry, pushed on the main subprocess's Heap list. A
//! thread's Theap for such a Heap is a [`MainHeapTheapImage`] from the
//! process metadata (`_mi_theap_alloc` with `_mi_meta_zalloc`) at the head of
//! the thread's TLD list, stored on the thread's regular thread-local slot
//! array (a `ThreadLocalBackingOwner`, also process metadata) and cached with
//! the source reference counts. It pages like a child thread's Theap for a
//! non-main Heap: its own queues and page state over the process arena
//! registry, with the Heap's own per-arena page records, whose allocation
//! nests an allocation from the main Heap through the thread's native owner
//! (`mi_arena_pages_alloc`); see `meta::ChildHeapTheapImage` for why each
//! Theap keeps its own engine state.
//!
//! The native runtime entry points route here: a local free of a block on
//! such a Theap's page, a nonlocal free of a block on such a Heap's page,
//! and thread exit, which collects and abandons the thread's non-main Theaps
//! before the thread's own teardown.
//!
//! Not yet covered: exclusive arenas, `mi_heap_collect`, and process
//! destruction with non-main main-subprocess Heaps alive.

use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use crate::compiler_tls::{cached_theap, default_theap, set_cached_theap};
use crate::meta::{ChildPageEngineState, MetaAllocation, MetaAllocator};
use crate::os_page::OsAlignedPageOwner;
use crate::process_init::{ProcessMainBackingBinding, ProcessMainInitializationStorage};
use crate::runtime_lifecycle::{native_allocate_aligned, native_free, NativePageAllocationResult, NativePageFreeResult};
use crate::subproc::MainSubprocess;
use crate::thread_local::{ThreadLocalBackingOwner, ThreadLocalKey, ThreadLocalSlotIndex, TLS_INDEX_BITS, TLS_INDEX_MASK};
use crate::types::heap_registry::lifecycle::{HeapKeySource, HeapReleaseError, HeapReleaseOutcome, NonMainHeapImage};
use crate::types::{Heap, LiveThreadId, MemoryId, Theap, ThreadLocalData, ThreadSequence};

/// One thread's Theap for a non-main Heap of the process main subprocess:
/// the source `mi_theap_t` at offset zero, then this Theap's own page-engine
/// state and the metadata capability of this very block (so any thread that
/// drops the last reference can free it).
#[repr(C)]
pub(crate) struct MainHeapTheapImage {
    theap: Theap,
    page_engine: ChildPageEngineState,
    allocation: Option<MetaAllocation<'static>>,
}

/// The calling thread's state for its Theaps of non-main Heaps.
struct ThreadHeaps {
    /// The regular thread-local slot array (`mi_thread_locals_t`).
    thread_locals: Option<ThreadLocalBackingOwner>,
    /// The one retained raw-unmap retry of these Theaps, with the Theap whose
    /// engine it latched (`None` once that Theap is freed).
    pending_os_release: Option<(Option<NonNull<Theap>>, OsAlignedPageOwner)>,
}

#[thread_local]
static THREAD_HEAPS: UnsafeCell<ThreadHeaps> =
    UnsafeCell::new(ThreadHeaps { thread_locals: None, pending_os_release: None });

/// # Safety
/// The caller is on the current thread and forms no other reference to the
/// state while the returned one is live.
#[inline]
unsafe fn thread_heaps() -> &'static mut ThreadHeaps {
    // SAFETY: a `#[thread_local]` is reachable only from its own thread.
    unsafe { &mut *THREAD_HEAPS.get() }
}

/// The calling thread's identity in the process main subprocess.
#[derive(Clone, Copy)]
struct MainThread {
    theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    thread: LiveThreadId,
    sequence: ThreadSequence,
    numa_node: i32,
}

/// The calling thread when it is attached to the process main subprocess
/// (its default Theap is initialized there) and not a child member.
fn current_main_thread() -> Option<MainThread> {
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return None;
    }
    let theap = default_theap();
    // SAFETY: the default root names this thread's Theap or the empty one.
    let tld = NonNull::new(unsafe { Theap::tld_at(theap) })?;
    let main = MainSubprocess::global();
    // SAFETY: an initialized default Theap keeps its TLD live.
    let tld_ref = unsafe { tld.as_ref() };
    let thread = LiveThreadId::new(tld_ref.thread_id())?;
    if crate::compiler_tls::current_thread_identity() != Some(thread)
        // SAFETY: the Theap's Heap is the process main Heap or null.
        || unsafe { Theap::heap_at(theap) }.is_null()
        || !tld_ref.matches_subprocess_attached_lifecycle(thread, tld_ref.thread_sequence(), main.identity())
    {
        return None;
    }
    Some(MainThread { theap, tld, thread, sequence: tld_ref.thread_sequence(), numa_node: tld_ref.numa_node() })
}

fn binding() -> Option<ProcessMainBackingBinding> {
    ProcessMainInitializationStorage::global().ready_child_subprocess_inputs().map(|(binding, _)| binding)
}

/// The regular thread-local key a Heap's Theaps use (`heap->theap`).
fn heap_key(heap: NonNull<Heap>) -> Option<ThreadLocalKey> {
    // SAFETY: the caller's live Heap; an immutable field.
    let raw = unsafe { heap.as_ref() }.regular_theap_slot() as u64;
    ThreadLocalKey::from_parts(ThreadLocalSlotIndex::new((raw & TLS_INDEX_MASK) as usize)?, raw >> TLS_INDEX_BITS)
}

/// Whether `heap` is a non-main Heap of the process main subprocess.
fn is_main_subprocess_heap(heap: NonNull<Heap>) -> bool {
    // SAFETY: the caller's live Heap; immutable fields.
    let heap = unsafe { heap.as_ref() };
    !heap.is_subprocess_main() && core::ptr::eq(heap.subprocess_pointer(), MainSubprocess::global().identity().as_ptr())
}

/// `_mi_thread_local_get` on this thread's slot array.
fn thread_local_get(key: ThreadLocalKey) -> *mut () {
    // SAFETY: the current thread's own state.
    let state = unsafe { thread_heaps() };
    state.thread_locals.as_mut().and_then(|owner| owner.get(key).ok()).unwrap_or(core::ptr::null_mut())
}

/// `_mi_thread_local_set` on this thread's slot array, created on first use.
fn thread_local_set(key: ThreadLocalKey, value: *mut ()) -> bool {
    let Some(config) = binding().and_then(|binding| binding.page_map().memory_config().ok()) else { return false };
    // SAFETY: the current thread's own state.
    let state = unsafe { thread_heaps() };
    if state.thread_locals.is_none() {
        // SAFETY: this module is the only owner of the main-subprocess
        // thread's regular slot root, which no native owner uses.
        match unsafe { ThreadLocalBackingOwner::begin(config) } {
            Ok(owner) => state.thread_locals = Some(owner),
            Err(_) => return false,
        }
    }
    state.thread_locals.as_mut().is_some_and(|owner| owner.set(key, value).is_ok())
}

/// `_mi_theap_cached_set` (`prim-tls.c:211-229`).
fn cached_set(theap: NonNull<Theap>) {
    let previous = cached_theap();
    if previous == theap {
        return;
    }
    set_cached_theap(theap);
    // SAFETY: both are live Theaps of this thread or the empty Theap.
    unsafe {
        Theap::incref_at(theap);
        theap_decref(previous);
    }
}

/// `_mi_theap_decref` with `mi_theap_free_mem` (`theap.c:347-370`) for a
/// Theap of a non-main main-subprocess Heap (or this thread's default Theap,
/// whose Heap reference keeps it above zero).
///
/// # Safety
/// `theap` is live and holds the reference being dropped; a Theap freed here
/// is on no list and no root names it.
unsafe fn theap_decref(theap: NonNull<Theap>) {
    // SAFETY: forwarded.
    if !unsafe { Theap::decref_at(theap) } {
        return;
    }
    // SAFETY: a freed Theap is not detached (it belonged to a Heap).
    if !unsafe { Theap::is_detached_at(theap) } {
        MainSubprocess::global().identity().record_statistics_theap_unlinked();
    }
    // SAFETY: the current thread's own state.
    if let Some((named @ Some(_), _)) = unsafe { thread_heaps() }.pending_os_release.as_mut() {
        if *named == Some(theap) {
            *named = None;
        }
    }
    let image = theap.cast::<MainHeapTheapImage>().as_ptr();
    // SAFETY: the image holds its own capability; it is moved out before the
    // block is released.
    let allocation = unsafe { core::ptr::replace(core::ptr::addr_of_mut!((*image).allocation), None) };
    if let Some(mut allocation) = allocation {
        let _ = MetaAllocator::global().free(&mut allocation);
    }
}

/// Pinned `_mi_heap_theap` (`prim-tls.h:389-397`, `heap.c:59-99`) on this
/// thread for a non-main Heap of the process main subprocess.
fn heap_theap(thread: MainThread, heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    let cached = cached_theap();
    // SAFETY: the cached root names a live Theap or the empty Theap.
    if unsafe { Theap::heap_at(cached) } == heap.as_ptr() {
        return Some(cached);
    }
    let key = heap_key(heap)?;
    let theap = match NonNull::new(thread_local_get(key).cast::<Theap>()) {
        Some(theap) => theap,
        None => {
            let theap = create_theap(thread, heap)?;
            // `_mi_heap_theap_set`.
            if !thread_local_set(key, theap.as_ptr().cast()) {
                return None;
            }
            theap
        }
    };
    cached_set(theap);
    Some(theap)
}

/// `_mi_theap_create(heap, tld)` (`theap.c:307-341`).
fn create_theap(thread: MainThread, heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    let binding = binding()?;
    let config = binding.page_map().memory_config().ok()?;
    let size = size_of::<MainHeapTheapImage>();
    let allocation = MetaAllocator::global()
        .zalloc_for_main_subprocess(config, MainSubprocess::global(), size)
        .ok()?;
    let block = allocation.pointer();
    let image = block.cast::<MainHeapTheapImage>().as_ptr();
    // SAFETY: a fresh, exclusively owned, zeroed block; the Rust fields are
    // written whole before the Theap is published. The TLD is this thread's
    // and the Heap's lists take their own locks.
    let initialized = unsafe {
        core::ptr::addr_of_mut!((*image).page_engine).write(ChildPageEngineState::Active);
        core::ptr::addr_of_mut!((*image).allocation).write(Some(allocation));
        let theap = &mut (*image).theap;
        theap.set_dynamic_metadata_memid(MemoryId::malloc(block.as_ptr(), size, true))
            && theap
                .initialize_dynamic_metadata_on_tld(
                    &mut *heap.as_ptr(),
                    &mut *thread.tld.as_ptr(),
                    crate::types::TheapPageMode::OrdinaryAbandoning,
                    true,
                )
                .is_ok()
    };
    if !initialized {
        return None;
    }
    // theap.c:290-292.
    MainSubprocess::global().identity().record_statistics_theap_linked();
    Some(block.cast())
}

/// Runs one page operation on `theap`, this thread's Theap for a non-main
/// Heap of the process main subprocess, with that Theap's own engine state.
fn with_theap_engine<R>(
    thread: MainThread,
    theap: NonNull<Theap>,
    operation: impl for<'session> FnOnce(
        &mut crate::single_thread::PageAllocatorEngine<
            'static,
            'static,
            crate::types::metadata_session::ChildOrdinaryTheapPageSession<'session, 'static>,
            crate::page_backing::RuntimeFirstRegularPageBacking,
        >,
    ) -> R,
) -> Option<R> {
    let binding = binding()?;
    if !binding.is_active() || !binding.is_allocation_ready() {
        return None;
    }
    // SAFETY: a live Theap of this thread.
    let heap = NonNull::new(unsafe { Theap::heap_at(theap) })?;
    let image = theap.cast::<MainHeapTheapImage>().as_ptr();
    // SAFETY: the Theap's own state field, used only by its engine.
    let page_engine = unsafe { &mut (*image).page_engine };
    let mut pending_os_release = None;
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), thread.numa_node);
    // SAFETY: this engine registers and unregisters only its own pages.
    let page_map = unsafe { binding.page_map().page_map_for_owned_ranges() }.ok()?;
    let mut allocate_arena_pages = |size: usize, alignment: usize| -> Option<NonNull<u8>> {
        // `mi_heap_zalloc_aligned(heap_main)` through `_mi_heap_theap`.
        cached_set(thread.theap);
        match native_allocate_aligned(size, alignment, true) {
            NativePageAllocationResult::Allocated(block) => Some(block),
            _ => None,
        }
    };
    // SAFETY: this thread's live TLD/Theap and the Heap outlive the
    // operation, which runs on this thread only.
    let session = unsafe {
        crate::types::metadata_session::ChildOrdinaryTheapPageSession::new_for_main_subprocess_heap(
            MainSubprocess::global(), thread.tld, theap, heap, thread.thread, thread.sequence,
            &mut pending_os_release, &mut *page_engine, &mut allocate_arena_pages,
        )
    }?;
    // SAFETY: the process registry backing and its PageMap are held for the
    // operation.
    let mut engine = unsafe {
        crate::single_thread::PageAllocatorEngine::activate_owned_session(session, backing, page_map, thread.sequence)
    };
    let value = operation(&mut engine);
    let finished = engine.finish_owned_session().map_err(drop).is_ok();
    if let Some(owner) = pending_os_release.take() {
        // SAFETY: the current thread's own state.
        let slot = unsafe { &mut thread_heaps().pending_os_release };
        if slot.is_none() && *page_engine == ChildPageEngineState::RetryPending {
            *slot = Some((Some(theap), owner));
        } else {
            core::mem::forget(owner);
            *page_engine = ChildPageEngineState::Poisoned;
        }
    }
    finished.then_some(value)
}

/// Pinned `mi_heap_new()` (`heap.c:127-157`) on an ordinary thread of the
/// process main subprocess: the image from the process main Heap (the
/// thread's main-Heap Theap becoming the cached Theap), a dynamic key, then
/// `_mi_heap_init` and the list push. `None` is source null.
pub(crate) fn native_heap_new() -> Option<NonNull<Heap>> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let thread = current_main_thread()?;
    let binding = binding()?;
    let config = binding.page_map().memory_config().ok()?;
    cached_set(thread.theap);
    let block = match native_allocate_aligned(size_of::<NonMainHeapImage>(), align_of::<NonMainHeapImage>(), true) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => return None,
    };
    let keys = HeapKeySource::global();
    let slot = match keys.registry.claim_for_main_subprocess(config, keys.subprocess, keys.metadata) {
        Ok(slot) => slot,
        Err(_) => {
            // SAFETY: the exact live block allocated above.
            let _ = unsafe { native_free(block) };
            return None;
        }
    };
    let identity = MainSubprocess::global().identity();
    // SAFETY: a fresh, zeroed, exclusively owned image block.
    unsafe { crate::types::heap_registry::lifecycle::initialize_and_link_non_main_heap(block, slot, identity) }.ok()
}

/// Pinned `mi_heap_malloc` and its zeroing and aligned forms on the calling
/// thread for a non-main Heap of the process main subprocess.
///
/// # Safety
/// `heap` is a live Heap from [`native_heap_new`].
pub(crate) unsafe fn native_heap_allocate(
    heap: NonNull<Heap>,
    size: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Option<NonNull<u8>> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let thread = current_main_thread()?;
    if !is_main_subprocess_heap(heap) {
        return None;
    }
    let theap = heap_theap(thread, heap)?;
    with_theap_engine(thread, theap, |engine| match (aligned, zero) {
        (None, zero) => engine.allocate(size, zero),
        (Some((alignment, offset)), true) => engine.allocate_aligned_zeroed_at(size, alignment, offset),
        (Some((alignment, offset)), false) => engine.allocate_aligned_at(size, alignment, offset),
    })
    .flatten()
}

/// The calling thread's Theap for a non-main Heap that owns `page`, when
/// that page is local to it: the native local free routes such a block here.
///
/// # Safety
/// `page` is the page of a live block associated with the calling thread.
pub(crate) unsafe fn local_heap_theap_of_page(page: NonNull<crate::types::Page>) -> Option<NonNull<Theap>> {
    // SAFETY: forwarded; a raw field read of a page this thread owns.
    let theap = NonNull::new(unsafe { crate::types::Page::theap_at(page) })?;
    let thread = current_main_thread()?;
    // SAFETY: a page this thread owns names one of its live Theaps.
    (theap != thread.theap && unsafe { Theap::tld_at(theap) } == thread.tld.as_ptr()).then_some(theap)
}

/// The native local free of `block` through `theap` (see
/// [`local_heap_theap_of_page`]).
///
/// # Safety
/// `block` is live on a page `theap` owns, and freed once.
pub(crate) unsafe fn native_free_local(theap: NonNull<Theap>, block: NonNull<u8>) -> NativePageFreeResult {
    let Some(thread) = current_main_thread() else { return NativePageFreeResult::Retained };
    // SAFETY: forwarded.
    match with_theap_engine(thread, theap, |engine| unsafe { engine.free(block) }) {
        Some(Ok(())) => NativePageFreeResult::Freed,
        _ => NativePageFreeResult::Retained,
    }
}

/// The non-main Heap of the process main subprocess that owns `page`.
///
/// # Safety
/// `page` is the page of a live block.
pub(crate) unsafe fn heap_of_page(page: NonNull<crate::types::Page>) -> Option<NonNull<Heap>> {
    // SAFETY: forwarded; the page's Heap is immutable while a block lives.
    let heap = NonNull::new(unsafe { page.as_ref() }.heap())?;
    is_main_subprocess_heap(heap).then_some(heap)
}

/// `mi_free_block_mt` with `mi_free_try_collect_mt` for a block of such a
/// Heap that the calling thread does not own, reclaiming into its Theap for
/// the Heap when source would.
///
/// # Safety
/// `allocation` is an exact live allocation on a page of `heap`.
pub(crate) unsafe fn native_free_nonlocal(
    heap: NonNull<Heap>,
    allocation: crate::process_page_map::LiveAllocationPointer,
) -> NativePageFreeResult {
    let Some(binding) = binding() else { return NativePageFreeResult::Retained };
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), -1);
    // SAFETY: this free touches only the claimed page's range.
    let Ok(page_map) = (unsafe { binding.page_map().page_map_for_owned_ranges() }) else {
        return NativePageFreeResult::Retained;
    };
    // SAFETY: forwarded.
    match unsafe {
        crate::single_thread::free_child_page_block_nonlocal(allocation, page_map, &backing, heap, reclaim_on_free)
    } {
        crate::single_thread::ChildNonlocalFreeResult::Freed | crate::single_thread::ChildNonlocalFreeResult::Released => {
            NativePageFreeResult::Freed
        }
        _ => NativePageFreeResult::Retained,
    }
}

/// `mi_abandoned_page_try_reclaim` (`free.c:423-469`) into the calling
/// thread's Theap for the claimed page's Heap, if it has one.
fn reclaim_on_free(
    candidate: crate::abandoned::ReclaimOnFreeCandidate<'_, crate::single_thread::ChildMappedAbandonedPage<'static>>,
) -> crate::abandoned::ReclaimOnFreeOutcome {
    use crate::abandoned::ReclaimOnFreeOutcome::Declined;
    let Some(thread) = current_main_thread() else { return Declined };
    let Some(heap) = NonNull::new(candidate.page_heap()) else { return Declined };
    let Some(theap) = heap_key(heap).and_then(|key| NonNull::new(thread_local_get(key).cast::<Theap>())) else {
        return Declined;
    };
    // SAFETY: a Theap on this thread's slots is live.
    if unsafe { Theap::heap_at(theap) } != heap.as_ptr() {
        return Declined;
    }
    with_theap_engine(thread, theap, |engine| engine.reclaim_abandoned_page_on_free(candidate)).unwrap_or(Declined)
}

/// Pinned `mi_heap_delete` (`heap.c:228-238`) or, with `destroy`,
/// `mi_heap_destroy` (`heap.c:240-259`) of a non-main Heap of the process
/// main subprocess on the calling thread: `mi_heap_free_theaps`, then
/// `_mi_heap_move_pages` to the process main Heap (the calling thread's
/// main-Heap Theap as target and cached Theap) or `_mi_heap_destroy_pages`,
/// then `mi_heap_free` (page records and image back to the main Heap).
///
/// # Safety
/// `heap` is a live Heap from [`native_heap_new`] or the process main Heap;
/// after a destroy no block of it is used again.
pub(crate) unsafe fn native_heap_release(heap: NonNull<Heap>, destroy: bool) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter().ok_or(HeapReleaseError::InvalidChild)?;
    let thread = current_main_thread().ok_or(HeapReleaseError::InvalidChild)?;
    // SAFETY: the caller's live Heap.
    if unsafe { heap.as_ref() }.is_subprocess_main() {
        return Ok(HeapReleaseOutcome::MainHeapRefused);
    }
    if !is_main_subprocess_heap(heap) {
        return Err(HeapReleaseError::InvalidChild);
    }
    let main_subprocess = MainSubprocess::global();
    let main_heap = NonNull::new(main_subprocess.ready_main_heap_pointer()).ok_or(HeapReleaseError::InvalidChild)?;
    // `mi_heap_free_theaps`.
    // SAFETY: the Heap and its Theaps are live.
    unsafe {
        heap.as_ref().detach_and_take_theaps(main_subprocess.identity(), |theap| {
            heap.as_ref().merge_detached_theap_statistics(theap.as_ref());
            theap_decref(theap);
        })
    }
    .map_err(HeapReleaseError::List)?;
    let target = if destroy {
        None
    } else {
        // `mi_heap_delete_pages`: `_mi_heap_theap(heap_target)`.
        cached_set(thread.theap);
        Some(crate::single_thread::NonMainHeapPageTarget { heap: main_heap, theap: thread.theap })
    };
    let binding = binding().ok_or(HeapReleaseError::InvalidChild)?;
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), thread.numa_node);
    // SAFETY: the detached Heap's pages are owned by this operation.
    let page_map = unsafe { binding.page_map().page_map_for_owned_ranges() }.map_err(|_| HeapReleaseError::Retained)?;
    // SAFETY: every Theap of the Heap is detached above.
    let moved = unsafe {
        crate::single_thread::delete_non_main_heap_pages(
            heap, target, main_subprocess.arena_backing().registry(), page_map, &backing,
        )
    };
    if !moved {
        return Err(HeapReleaseError::Retained);
    }
    // `mi_heap_free`: page records, then statistics, counts, list, key, and
    // image, each record and the image back through the native free.
    // SAFETY: the live Heap; each record is a live main-Heap block.
    let freed = unsafe { heap.as_ref() }.take_non_main_arena_pages(|record| {
        // SAFETY: the exact live record block, freed once.
        (unsafe { native_free(record) }) == NativePageFreeResult::Freed
    });
    if !freed {
        return Err(HeapReleaseError::Retained);
    }
    // SAFETY: forwarded; the Heap has no Theap or page left.
    let image = unsafe { crate::types::heap_registry::lifecycle::unlink_non_main_heap(heap, main_heap, main_subprocess.identity()) }?;
    // SAFETY: the exact live image block; nothing names it any longer.
    match unsafe { native_free(image.cast()) } {
        NativePageFreeResult::Freed => Ok(HeapReleaseOutcome::Released),
        _ => Err(HeapReleaseError::Retained),
    }
}

/// `mi_thread_theaps_done` (`init.c:377-421`) and
/// `_mi_thread_locals_thread_done` for the calling thread's Theaps of
/// non-main Heaps of the process main subprocess, before the thread's own
/// finish: the slot array is freed, each such Theap is collected with its
/// live pages abandoned to its Heap, the cached Theap is reset, and each
/// leaves its Heap and TLD and drops the Heap's reference. `false` when a
/// Theap could not be drained.
pub(crate) fn native_thread_done() -> bool {
    let Some(thread) = current_main_thread() else { return true };
    // SAFETY: the current thread's own state.
    let state = unsafe { thread_heaps() };
    if let Some(mut owner) = state.thread_locals.take() {
        if owner.teardown().is_err() {
            return false;
        }
    }
    // SAFETY: this thread's live TLD; only this thread changes its list
    // other than a Heap free, which detaches under the TLD lock.
    let mut current = unsafe { ThreadLocalData::theaps_head_at(thread.tld) };
    while let Some(theap) = NonNull::new(current) {
        // SAFETY: a live list member.
        current = unsafe { Theap::tld_next_at(theap) };
        if theap == thread.theap {
            continue;
        }
        let drained = with_theap_engine(thread, theap, |engine| {
            // SAFETY: this finishing thread's own Theap.
            (unsafe { engine.collect_abandon_child_thread_done(theap, thread.thread) }) && engine.finish_quiescent_in_place()
        });
        if drained != Some(true) {
            return false;
        }
    }
    // SAFETY: the immutable source empty Theap is process-static.
    let empty = unsafe { NonNull::new_unchecked(crate::bootstrap::empty_default_theap_ptr()) };
    cached_set(empty);
    let identity = MainSubprocess::global().identity();
    // SAFETY: as above.
    let mut current = unsafe { ThreadLocalData::theaps_head_at(thread.tld) };
    while let Some(theap) = NonNull::new(current) {
        // SAFETY: read before the Theap leaves the list.
        current = unsafe { Theap::tld_next_at(theap) };
        if theap == thread.theap {
            continue;
        }
        // SAFETY: the drained Theap owns no page.
        if unsafe { ThreadLocalData::detach_theap_for_thread_done(thread.tld, theap, identity) }.is_err() {
            return false;
        }
        // SAFETY: the Heap's reference, dropped once.
        unsafe { theap_decref(theap) };
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::vec::Vec;

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    /// Pinned-C/Rust differential for Heaps of the process main subprocess on
    /// the main thread (`compat/allocator/heap_lifecycle.c` with `main`):
    /// test-api.c's heap-os1, heap-os2, and heap-many shapes.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn source_ordered_main_subprocess_heap_trace() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::source_ordered_main_subprocess_heap_trace",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                // The main thread's first allocation initializes its owner.
                let first = match native_allocate_aligned(16, 16, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    _ => panic!("the main thread allocates"),
                };
                unsafe { native_free(first) };
                let mut trace: Vec<i64> = Vec::new();
                let main = MainSubprocess::global();
                let identity = main.identity();
                let main_heap = NonNull::new(main.ready_main_heap_pointer()).unwrap();
                let theap = default_theap();
                let tld = NonNull::new(unsafe { Theap::tld_at(theap) }).unwrap();
                let theaps = || identity.statistics().final_output_snapshot().theaps;
                let heap_count = || identity.heap_list().test_counts().0 as i64;
                let (theaps0, heaps0) = (theaps(), heap_count());
                let page_of = |block: NonNull<u8>| {
                    let binding = binding().unwrap();
                    unsafe { binding.page_map().lookup_live_allocation(block) }.unwrap().unwrap().page()
                };
                let links = |t: NonNull<Theap>| unsafe { Theap::test_list_links(t) };

                // heap-os1.
                let h = native_heap_new().expect("a Heap");
                trace.push(i64::from(unsafe { h.as_ref() }.subprocess_pointer() == identity.as_ptr()
                    && unsafe { h.as_ref() }.test_theaps_head().is_null()
                    && identity.heap_list().test_head() == h.as_ptr()));
                trace.push(heap_count() - heaps0);
                let p = unsafe { native_heap_allocate(h, 1 << 20, Some((2 << 20, 0)), false) }.expect("an OS block");
                let page = page_of(p);
                let h_theap = NonNull::new(unsafe { h.as_ref() }.test_theaps_head()).unwrap();
                trace.push(i64::from(unsafe { page.as_ref() }.heap() == h.as_ptr()
                    && unsafe { page.as_ref() }.memid().kind().is_os()
                    && unsafe { page.as_ref() }.theap() == h_theap.as_ptr()));
                let (_, _, h_tnext, _, h_tld) = links(h_theap);
                trace.push(i64::from(h_tld == tld.as_ptr()
                    && unsafe { ThreadLocalData::theaps_head_at(tld) } == h_theap.as_ptr()
                    && h_tnext == theap.as_ptr()));
                trace.push(i64::from(cached_theap() == h_theap));
                trace.push(theaps().current - theaps0.current);
                assert_eq!(unsafe { native_heap_release(h, false) }, Ok(HeapReleaseOutcome::Released));
                trace.push(i64::from(unsafe { page.as_ref() }.heap() == main_heap.as_ptr()
                    && unsafe { Heap::os_abandoned_head_at(main_heap) } == page.as_ptr()));
                let (_, _, _, main_tprev, _) = links(theap);
                trace.push(i64::from(unsafe { ThreadLocalData::theaps_head_at(tld) } == theap.as_ptr() && main_tprev.is_null()));
                trace.push(heap_count() - heaps0);
                assert_eq!(unsafe { native_free(p) }, NativePageFreeResult::Freed);
                trace.push(i64::from(unsafe { Heap::os_abandoned_head_at(main_heap) }.is_null()));

                // heap-os2.
                let h2 = native_heap_new().expect("a second Heap");
                trace.push(i64::from(cached_theap() == theap));
                trace.push(theaps().current - theaps0.current);
                let mut failed = 0;
                for _ in 0..10 {
                    match unsafe { native_heap_allocate(h2, 1 << 20, Some((2 << 20, 0)), false) } {
                        Some(block) => unsafe { block.as_ptr().cast::<i32>().write(42) },
                        None => failed += 1,
                    }
                }
                trace.push(failed);
                trace.push(unsafe { NonNull::new(h2.as_ref().test_theaps_head()).unwrap().as_ref() }.page_count() as i64);
                assert_eq!(unsafe { native_heap_release(h2, true) }, Ok(HeapReleaseOutcome::Released));
                trace.push(i64::from(unsafe { Heap::os_abandoned_head_at(main_heap) }.is_null()));
                trace.push(heap_count() - heaps0);

                // heap-many.
                let mut heaps = Vec::new();
                let mut allocated = true;
                for _ in 0..1000 {
                    let Some(heap) = native_heap_new() else { allocated = false; break };
                    heaps.push(heap);
                    if unsafe { native_heap_allocate(heap, 32, None, false) }.is_none() { allocated = false; break }
                }
                trace.push(i64::from(allocated));
                trace.push(heap_count() - heaps0);
                let slots = || crate::compiler_tls::dynamic_backing_peek()
                    .map_or(0, |backing| unsafe { backing.as_ref() }.count() as i64);
                trace.push(slots());
                trace.push(theaps().current - theaps0.current);
                let mut on_tld = 0;
                let mut current = unsafe { ThreadLocalData::theaps_head_at(tld) };
                while let Some(t) = NonNull::new(current) {
                    on_tld += 1;
                    current = unsafe { Theap::tld_next_at(t) };
                }
                trace.push(on_tld);
                for heap in heaps {
                    assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
                }
                trace.push(heap_count() - heaps0);
                trace.push(i64::from(identity.heap_list().test_head() == main_heap.as_ptr()
                    && unsafe { Heap::test_links(main_heap) }.1.is_null()));
                trace.push(i64::from(unsafe { ThreadLocalData::theaps_head_at(tld) } == theap.as_ptr()));
                trace.push(theaps().current - theaps0.current);
                trace.push(theaps().total - theaps0.total);
                trace.push(slots());
                for (index, value) in trace.iter().enumerate() {
                    std::println!("m6.heap.main.{index}={value}");
                }
            },
        );
    }
}
