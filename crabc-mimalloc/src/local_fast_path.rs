// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT

//! Owner-local allocation and free fast paths of pinned mimalloc v3.5.0.
//!
//! Source map:
//! - `src/alloc-aligned.c:212-236` (`mi_theap_malloc_zero_aligned_at`'s
//!   direct small-page head), `src/alloc.c:31-60` (`mi_page_malloc_zero`),
//!   and `src/page.c:879-915,1091-1113` (`_mi_malloc_generic`'s
//!   `generic_count` step and `mi_page_queue_lookup_free_first`);
//! - `src/free.c:223-234` (`mi_free_nonnull`'s `xtid == 0` branch),
//!   `src/free.c:28-54` (`mi_free_block_local`), and `src/page.c:424-457`
//!   (`_mi_page_retire`'s retain branch).
//!
//! These run in front of the runtime's phase and owner-cell machinery, only
//! for a Theap published by `main_heap_thread::owner_local_fast_theap`, and
//! only for the source's common case. Every other case returns without
//! mutating anything, and the caller continues on the complete path, which
//! makes the identical source decision. They never perform generic
//! administration, queue search beyond the first head, page extension,
//! fresh-page allocation, `_mi_page_free`, `_mi_page_unfull`, or remote frees.
//! For a regular medium queue head, the source's generic fallback performs
//! the same quick collect after administration has no work to do; this path
//! declines before a pop that would move the page to its full queue.
//!
//! They keep the checks the normal-release C build performs and no others:
//! as in `mi_block_next` without `MI_ENCODE_FREELIST`, list links are
//! trusted to name blocks of their page, which holds for every valid
//! program. The complete path's `LocalFreeList` keeps its containment checks.

use core::ptr::NonNull;

use crate::config::{
    BIN_HUGE, MAX_ALIGN_SIZE, MEDIUM_MAX_OBJ_SIZE, PAGE_MAX_START_BLOCK_ALIGN2,
    PAGE_OSPAGE_BLOCK_ALIGN2, PAGES_DIRECT, SMALL_MAX_OBJ_SIZE, SMALL_SIZE_MAX, WORD_SIZE,
};
#[cfg(feature = "mi-stat-1")]
use crate::config::LARGE_MAX_OBJ_SIZE;
use crate::single_thread::{RETIRE_CYCLES, RETIRE_MAX_PAGES};
use crate::types::{Block, Page, Theap};
use crate::{invariants, size_class};

/// The one per-thread publication the fast paths read: the owner's Theap
/// and its process PageMap, valid until the next owner transition.
///
/// It is written only by [`publish`], after an owner operation that left
/// its engine healthy (see `PageAllocatorEngine::local_fast_owner`) while the
/// thread's fast and default TLS roots name that Theap and the thread is not
/// a child-subprocess member. Every transition that could invalidate it
/// clears it through [`withdraw`] first: a persistent owner cell leaving
/// `Active` (a new borrow, teardown, retention), an owner-local engine state
/// other than `Borrowed -> Idle`, a store to any fast/default/cached/dynamic
/// TLS root, child-subprocess admission, fork preparation, and
/// reclaim-on-free. Process-wide state (activity, process-done) and the
/// thread's lifecycle bytes are still checked per operation by the runtime.
#[derive(Clone, Copy)]
pub(crate) struct LocalFastOwner {
    pub(crate) theap: NonNull<Theap>,
    /// The engine's process PageMap, which lives for the process.
    pub(crate) page_map: NonNull<crate::page_map::PageMap>,
}

#[thread_local]
static mut PUBLISHED_THEAP: *mut Theap = core::ptr::null_mut();
#[thread_local]
static mut PUBLISHED_PAGE_MAP: *const crate::page_map::PageMap = core::ptr::null();

/// The validated owner-local fast publication belongs to the pthread, not
/// to one timer callback's application TLS lifetime.
#[cfg(target_arch = "x86_64")]
pub(crate) fn native_timer_tls_spans() -> [crate::runtime_lifecycle::NativeAllocatorTlsSpan; 2] {
    use crate::runtime_lifecycle::NativeAllocatorTlsSpan as Span;
    [
        Span::of(core::ptr::addr_of!(PUBLISHED_THEAP)),
        Span::of(core::ptr::addr_of!(PUBLISHED_PAGE_MAP)),
    ]
}

/// Publishes `owner` for the current thread's fast paths, or withdraws the
/// publication when `owner` is `None` or the TLS roots do not select it.
#[inline]
pub(crate) fn publish(owner: Option<LocalFastOwner>) {
    let owner = owner.filter(|owner| {
        crate::compiler_tls::fast_slot_peek() == Some(owner.theap.cast())
            && crate::compiler_tls::default_theap() == owner.theap
            && !crate::subproc::lifecycle::current_thread_is_child_member()
    });
    // SAFETY: current-thread compiler TLS scalar writes.
    unsafe {
        PUBLISHED_THEAP = owner.map_or(core::ptr::null_mut(), |owner| owner.theap.as_ptr());
        PUBLISHED_PAGE_MAP = owner.map_or(core::ptr::null(), |owner| owner.page_map.as_ptr());
    }
}

/// Clears the current thread's publication (see [`LocalFastOwner`]).
#[inline(always)]
pub(crate) fn withdraw() {
    // SAFETY: current-thread compiler TLS scalar write.
    unsafe { PUBLISHED_THEAP = core::ptr::null_mut() };
}

/// The current thread's publication, if any.
#[inline(always)]
pub(crate) fn published() -> Option<LocalFastOwner> {
    // SAFETY: current-thread compiler TLS scalar reads; `publish` writes the
    // page map whenever it writes a non-null Theap.
    unsafe {
        let theap = NonNull::new(PUBLISHED_THEAP)?;
        Some(LocalFastOwner { theap, page_map: NonNull::new_unchecked(PUBLISHED_PAGE_MAP.cast_mut()) })
    }
}

/// Source `alloc-aligned.c:mi_malloc_is_naturally_aligned` for requests up
/// to `SMALL_SIZE_MAX`, where `mi_good_size` is the bin size.
#[inline]
fn is_naturally_aligned_small(size: usize, alignment: usize) -> Option<bool> {
    if alignment > size {
        return Some(false);
    }
    let block_size = size_class::bin_size(size_class::bin(size)?)?;
    Some(
        (block_size <= PAGE_MAX_START_BLOCK_ALIGN2 && block_size.is_power_of_two())
            || (alignment == PAGE_OSPAGE_BLOCK_ALIGN2 && block_size % PAGE_OSPAGE_BLOCK_ALIGN2 == 0),
    )
}

/// Allocates one small direct or regular queue-head block from
/// `theap`'s own pages, or returns `None` having changed nothing.
///
/// `alignment` is `None` for the ordinary entry (`_mi_theap_malloc_zero`)
/// and the requested alignment for the aligned entry at offset zero
/// (`mi_theap_malloc_zero_aligned_at`). Both take the source order: the
/// direct page's immediate head (`_mi_page_malloc_zero`, which leaves
/// `retire_expire` alone), when aligned entries find it suitably aligned;
/// an eight-byte request with 16-byte alignment first uses the source's
/// 31-byte overallocated base through that base class's direct or queue head;
/// otherwise, for an ordinary or naturally aligned small request,
/// `_mi_malloc_generic`'s counter step and its queue-head
/// `mi_page_free_quick_collect`, which clears `retire_expire` before the
/// pop. A regular small request above the direct-cache range reaches the
/// same queue-head step from `_mi_malloc_generic`. A medium ordinary request
/// reaches it through `mi_malloc_generic_fallback` after its administration
/// check. Both fast branches require the counter below its threshold; the
/// medium branch also declines a pop that would move the page to its full
/// queue.
///
/// # Safety
///
/// `theap` must come from the current thread's publication ([`published`])
/// with the runtime gates of `runtime_lifecycle::native_local_fast_owner`
/// checked in this same native operation, so this thread exclusively owns the Theap's ordinary fields and
/// every ordinary page field of its queued pages. An `alignment` that is not
/// a power of two is declined.
#[inline(never)]
pub(crate) unsafe fn allocate(
    theap: NonNull<Theap>,
    size: usize,
    alignment: Option<usize>,
    zero: bool,
) -> Option<NonNull<u8>> {
    if alignment.is_some_and(|alignment| !alignment.is_power_of_two()) {
        return None;
    }
    if size == WORD_SIZE && alignment == Some(MAX_ALIGN_SIZE) {
        // SAFETY: forwarded exclusive owner contract. This aligned request
        // takes the source's overallocated ordinary allocation branch.
        return unsafe { allocate_eight_byte_overalloc_head(theap, zero) };
    }
    if alignment.is_some_and(|alignment| alignment > size) {
        return None;
    }
    let direct_small = size <= SMALL_SIZE_MAX;
    if !direct_small && (size > MEDIUM_MAX_OBJ_SIZE || alignment.is_some()) {
        return None;
    }
    let mut observed_empty_direct_page = core::ptr::null_mut();
    if direct_small {
        // Release small allocation preserves the original requested bytes,
        // including zero: direct slot zero and bin one both supply a word
        // block while level-two statistics retain the unrounded request.
        let direct_index = invariants::word_count(size)?;
        if direct_index >= PAGES_DIRECT {
            return None;
        }
        let direct = unsafe { Theap::local_direct_page_at(theap, direct_index) }?;
        // The initialized cache contains only the readable empty-page
        // sentinel or a live queue page. The sentinel's free head is null.
        // SAFETY: the owner's published Theap keeps every direct slot non-null.
        let page = unsafe { NonNull::new_unchecked(direct) };
        // SAFETY: the pointer names a live page or the immutable sentinel.
        let head = unsafe { Page::free_list_head_at(page) };
        if !head.is_null() {
            if alignment.is_some_and(|alignment| head.addr() & (alignment - 1) != 0) {
                return None;
            }
            // SAFETY: a non-null head excludes the sentinel; the owner controls
            // this live page's ordinary local-list fields and immediate head.
            let block = unsafe { pop_selected_head(page, head, zero) };
            #[cfg(feature = "mi-stat-1")]
            unsafe { record_normal_allocation(theap, page, size) };
            return Some(block);
        }
        observed_empty_direct_page = direct;
        if let Some(alignment) = alignment {
            if !is_naturally_aligned_small(size, alignment)? {
                return None;
            }
        }
    }
    // A direct small head can supply a block without regular-page classification.
    // The eight-word request uses bin eight when its direct head is empty.
    let bin = if size == 8 * WORD_SIZE { 8 } else { size_class::bin(size)? };
    let first = NonNull::new(unsafe { Theap::local_queue_at(theap, bin) }?.first())?;
    if size > SMALL_MAX_OBJ_SIZE {
        // SAFETY: the queue head is a live page of this Theap.
        let block_size = unsafe { Page::block_size_at(first) };
        if block_size <= SMALL_MAX_OBJ_SIZE
            || block_size > MEDIUM_MAX_OBJ_SIZE
            || unsafe { Page::owner_used_at(first) } + 1 >= usize::from(unsafe { Page::reserved_at(first) })
        {
            // `mi_malloc_generic_fallback` moves a newly full medium page
            // to the full queue after its pop, which belongs to the complete
            // owner path.
            return None;
        }
    }
    // A small queue's bin already fixes its page class; the source's
    // queue-head lookup does not recheck the page's block size.
    // The counter step below touches only the Theap. Keep the owner-only
    // local head observed during this preflight for the source quick collect;
    // no other owner can change either ordinary free-list field between them.
    // Carry the selected head through the counter step so the pop needs no
    // second page-state projection just to recover the same pointer.
    let (selected_head, local_head) = unsafe {
        let state = Page::local_free_list_state_at(first);
        // The current owner cannot change an immediate head between the
        // direct lookup and this queue lookup. Reuse that empty observation
        // only when the queue still names the same page.
        let immediate_head = if first.as_ptr() == observed_empty_direct_page {
            core::ptr::null_mut()
        } else {
            *state.free.as_ptr()
        };
        let local_head = if immediate_head.is_null() {
            *state.local_free.as_ptr()
        } else {
            core::ptr::null_mut()
        };
        (if immediate_head.is_null() { local_head } else { immediate_head }, local_head)
    };
    if selected_head.is_null() {
        // An empty head needs `mi_page_queue_find_free_ex`.
        return None;
    }
    // SAFETY: the caller owns the Theap's generic counters.
    if !unsafe { Theap::advance_generic_count_below_administration_at(theap) } {
        return None;
    }
    // SAFETY: exclusive ordinary-field ownership, as above. The head has an
    // immediate or local-free block, so the selected block remains live
    // through the source quick collect and pop.
    let block = unsafe {
        quick_collect_before_pop(first, local_head);
        // `mi_page_queue_lookup_free_first` clears this owner-only byte once
        // it selects the head.
        Page::set_retire_expire_at(first, 0);
        pop_selected_head(first, selected_head, zero)
    };
    // SAFETY: the queue head remains live through the owner-local pop.
    #[cfg(feature = "mi-stat-1")]
    unsafe { record_normal_allocation(theap, first, size) };
    debug_assert!(alignment.is_none_or(|alignment| block.as_ptr().addr() & (alignment - 1) == 0));
    Some(block)
}

/// The eight-byte, 16-aligned case of
/// `mi_theap_malloc_zero_aligned_at_overalloc`.
/// Its base request uses the source's minimum size before alignment padding.
/// An empty direct head may still use the ordinary queue head after its quick
/// local collection; page search and extension stay on the full path.
///
/// # Safety
///
/// `theap` is the published exclusive owner for this operation.
#[inline(never)]
unsafe fn allocate_eight_byte_overalloc_head(theap: NonNull<Theap>, zero: bool) -> Option<NonNull<u8>> {
    let request = MAX_ALIGN_SIZE + MAX_ALIGN_SIZE - 1;
    let alignment = MAX_ALIGN_SIZE;
    let direct_index = invariants::word_count(request)?;
    if direct_index >= PAGES_DIRECT {
        return None;
    }
    // SAFETY: the published owner keeps each direct slot initialized to a
    // live page or the immutable empty-page sentinel.
    let page = unsafe { NonNull::new_unchecked(Theap::local_direct_page_at(theap, direct_index)?) };
    let head = unsafe { Page::free_list_head_at(page) };
    let (page, base) = if !head.is_null() {
        // SAFETY: a non-null head excludes the sentinel. This owner controls
        // the ordinary list, and the source allocates this base first.
        (page, unsafe { pop_selected_head(page, head, zero) })
    } else {
        let bin = size_class::bin(request)?;
        let first = NonNull::new(unsafe { Theap::local_queue_at(theap, bin) }?.first())?;
        // SAFETY: the queue head is a live owner page. The direct head's
        // empty observation remains valid while this owner runs.
        let (selected_head, local_head) = unsafe {
            let state = Page::local_free_list_state_at(first);
            let immediate_head = if first == page {
                core::ptr::null_mut()
            } else {
                *state.free.as_ptr()
            };
            let local_head = if immediate_head.is_null() {
                *state.local_free.as_ptr()
            } else {
                core::ptr::null_mut()
            };
            (if immediate_head.is_null() { local_head } else { immediate_head }, local_head)
        };
        if selected_head.is_null() {
            return None;
        }
        // SAFETY: the published owner exclusively controls this counter.
        if !unsafe { Theap::advance_generic_count_below_administration_at(theap) } {
            return None;
        }
        // SAFETY: the selected owner head remains stable through the source
        // quick collect, countdown clear, and ordinary block pop.
        let base = unsafe {
            quick_collect_before_pop(first, local_head);
            Page::set_retire_expire_at(first, 0);
            pop_selected_head(first, selected_head, zero)
        };
        (first, base)
    };
    // The source rounds the client pointer up to the next alignment boundary.
    // Negating the address modulo a power of two gives exactly that padding.
    let adjustment = (0usize.wrapping_sub(base.as_ptr().addr())) & (alignment - 1);
    if adjustment != 0 {
        // The interior flag shares the source atomic owner word. Its relaxed
        // update leaves the same owner and full-page bits intact.
        unsafe { Page::set_has_interior_pointers_at(page, true) };
    }
    #[cfg(feature = "mi-stat-1")]
    unsafe { record_normal_allocation(theap, page, request) };
    // The padded request leaves at least `alignment - 1` bytes beyond the
    // minimum base size, so this adjusted client stays inside the block.
    Some(unsafe { NonNull::new_unchecked(base.as_ptr().add(adjustment)) })
}

/// The ordinary eight-word allocation when its direct page or regular queue
/// head already has a block. The caller continues through the complete owner
/// path if neither head can supply one without administration.
///
/// # Safety
///
/// `theap` must be the current thread's published owner after the runtime
/// admission and owner checks. This thread exclusively owns its ordinary
/// queue and page fields for the duration of this operation.
#[inline(always)]
pub(crate) unsafe fn allocate_ordinary_eight_word(theap: NonNull<Theap>) -> Option<NonNull<u8>> {
    // SAFETY: the caller holds the published live owner for this operation.
    let direct = unsafe { Theap::local_direct_page_at(theap, 8) }?;
    // SAFETY: an initialized direct slot names a live page or the sentinel.
    let direct_page = unsafe { NonNull::new_unchecked(direct) };
    let direct_head = unsafe { Page::free_list_head_at(direct_page) };
    if !direct_head.is_null() {
        // SAFETY: a non-null head excludes the sentinel and belongs to this owner.
        let block = unsafe { pop_selected_head(direct_page, direct_head, false) };
        #[cfg(feature = "mi-stat-1")]
        unsafe { record_normal_allocation(theap, direct_page, 8 * WORD_SIZE) };
        return Some(block);
    }
    let first = NonNull::new(unsafe { Theap::local_queue_at(theap, 8) }?.first())?;
    // SAFETY: the selected queue head is live and its ordinary fields belong
    // to this thread. The direct head cannot change between these reads.
    let (selected_head, local_head) = unsafe {
        let state = Page::local_free_list_state_at(first);
        let immediate_head = if first.as_ptr() == direct {
            core::ptr::null_mut()
        } else {
            *state.free.as_ptr()
        };
        let local_head = if immediate_head.is_null() { *state.local_free.as_ptr() } else { core::ptr::null_mut() };
        (if immediate_head.is_null() { local_head } else { immediate_head }, local_head)
    };
    if selected_head.is_null() {
        return None;
    }
    // SAFETY: the caller owns this Theap's ordinary generic counter.
    if !unsafe { Theap::advance_generic_count_below_administration_at(theap) } {
        return None;
    }
    // SAFETY: exclusive ordinary-field ownership keeps the selected head
    // stable through quick collection and pop.
    let block = unsafe {
        quick_collect_before_pop(first, local_head);
        Page::set_retire_expire_at(first, 0);
        pop_selected_head(first, selected_head, false)
    };
    #[cfg(feature = "mi-stat-1")]
    unsafe { record_normal_allocation(theap, first, 8 * WORD_SIZE) };
    Some(block)
}

/// Frees one owner-local block of `theap` without leaving the page's queue,
/// or returns `false` having changed nothing.
///
/// This is `mi_free_nonnull`'s `xtid == 0` case (thread-owned page with no
/// full or interior-pointer flag) followed by `mi_free_block_local`. When
/// the free empties a page whose countdown is zero, only `_mi_page_retire`'s
/// retain branch is taken here; a page `_mi_page_retire` would release, and
/// every other case, stays on the complete path.
///
/// # Safety
///
/// Same Theap contract as [`allocate`]. `page` must be the PageMap page
/// registered for `block`, and `block` an exact live allocation that the
/// caller consumes, with `current_thread` the caller's thread identity.
/// A foreign page grants access only to its atomic identity; its owner may
/// concurrently mutate every ordinary field while this attempt declines.
#[inline]
pub(crate) unsafe fn free(
    theap: NonNull<Theap>,
    page: NonNull<Page>,
    block: NonNull<u8>,
    current_thread: usize,
) -> bool {
    // SAFETY: the live client keeps initialized metadata stable. Project only
    // its atomic identity until it proves this thread owns the ordinary
    // fields; even a whole-page shared borrow would race with a foreign owner.
    let producer = unsafe { Page::remote_free_producer_state_at(page) };
    let owner = unsafe { producer.xthread_id.as_ref() }
        .load(core::sync::atomic::Ordering::Acquire);
    if owner != current_thread {
        return false;
    }
    // SAFETY: the exact identity equality also excludes both page flags.
    // This thread now owns the ordinary fields, and this snapshot ends before
    // their local mutation. Remote producers retain only disjoint atomics.
    let (page_theap, used, retire_expire) = unsafe {
        (Page::theap_identity_at(page), Page::owner_used_at(page), Page::retire_expire_at(page))
    };
    if page_theap != theap.as_ptr() {
        return false;
    }
    // An exact live block implies `used > 0`; source `mi_free_block_local`
    // decrements this count without a separate preflight.
    if used == 1 && retire_expire == 0 {
        // SAFETY: this is the same owner-local page and exact live block;
        // the preflight below leaves the page untouched if it cannot retain.
        return unsafe { retire_last_local_free(theap, page, block) };
    }
    // SAFETY: the owner exclusively controls the ordinary local-list fields,
    // and the caller consumes exact live `block` of this page.
    #[cfg(feature = "mi-stat-1")]
    unsafe { record_normal_free(theap, page) };
    unsafe { push_local_free(page, block) };
    true
}

/// Preflights the source retain branch before the last local free mutates its
/// page. Keeping this rare queue work out of line leaves the ordinary local
/// free's owner check and list push in a small inlined body.
///
/// # Safety
///
/// The caller exclusively owns `theap` and `page`'s ordinary fields; `page`
/// belongs to `theap`, has exactly one used block, and `block` is that exact
/// live allocation. The page's retirement countdown is zero. The exact raw
/// owner-word check in [`free`] also proves both page flags are clear.
#[cold]
#[inline(never)]
unsafe fn retire_last_local_free(
    theap: NonNull<Theap>,
    page: NonNull<Page>,
    block: NonNull<u8>,
) -> bool {
    // SAFETY: the caller holds the page live and owns its ordinary geometry.
    let block_size = unsafe { Page::block_size_at(page) };
    // `_mi_page_retire` on an unflagged, non-huge page selects its ordinary
    // queue: keep it only in the retain branch. An eight-word regular page
    // always has multiple reserved blocks; a forced singleton starts with a
    // larger base request even when its client's requested size is small.
    if block_size != 8 * WORD_SIZE && unsafe { Page::reserved_at(page) } <= 1 {
        return false;
    }
    // A page with multiple reserved blocks uses a word-aligned regular bin
    // size, so its queue number needs no request-size rounding.
    // The eight-word class uses bin eight and the small-page countdown.
    // Carry both decisions through this common retirement free.
    let (bin, cycles) = if block_size == 8 * WORD_SIZE {
        (8, RETIRE_CYCLES)
    } else {
        (
            size_class::bin_for_regular_page_block_size(block_size),
            if block_size <= SMALL_MAX_OBJ_SIZE { RETIRE_CYCLES } else { RETIRE_CYCLES / 4 },
        )
    };
    if bin >= BIN_HUGE {
        return false;
    }
    // SAFETY: exclusive owner-local Theap, as above.
    let Some(queue) = (unsafe { Theap::local_queue_at(theap, bin) }) else { return false };
    let count = queue.count();
    // A sole queued page satisfies the retirement cap and needs no small-block exception.
    if count != 1 && (count > RETIRE_MAX_PAGES || block_size >= SMALL_SIZE_MAX) {
        return false;
    }
    // SAFETY: this consumes the exact live block after all fallbacks have
    // been ruled out; the owner controls the page's local-list fields.
    #[cfg(feature = "mi-stat-1")]
    unsafe { record_normal_free(theap, page) };
    unsafe { push_local_free(page, block) };
    // The general retire path clears the interior-pointer flag here. The
    // exact raw owner-word check found it clear, and this owner has not set it.
    // SAFETY: exclusive owner-local Theap, as above.
    unsafe { Theap::record_page_retired_at(theap) };
    // SAFETY: `used == 0` now, and the owner controls this byte and the
    // Theap's retirement bounds.
    unsafe {
        Page::set_retire_expire_at(page, cycles);
        let noted = Theap::note_local_retired_bin_at(theap, bin);
        debug_assert!(noted, "an ordinary queue bin is below BIN_FULL");
    }
    true
}

/// Records a successful pop through the owner's statistics tail alone.
///
/// # Safety
/// The caller retains both images and owns the completed normal-page pop;
/// `requested_size` is the internal request used by that allocation branch.
#[cfg(feature = "mi-stat-1")]
#[inline]
unsafe fn record_normal_allocation(theap: NonNull<Theap>, page: NonNull<Page>, requested_size: usize) {
    // SAFETY: this owner retains the page's fixed geometry and statistics;
    // neither projection covers mutable queue, count, or Heap-list fields.
    unsafe {
        Theap::record_local_normal_allocation_statistics_at(theap, requested_size, Page::block_size_at(page));
    }
}

/// Records a consumed owner-local binned block before its free-list change.
///
/// # Safety
///
/// `theap` owns the live `page` on this thread and the caller has completed
/// every preflight that could decline the free.
#[cfg(feature = "mi-stat-1")]
#[inline]
unsafe fn record_normal_free(theap: NonNull<Theap>, page: NonNull<Page>) {
    // SAFETY: the caller keeps both source objects live and exclusively owns
    // their ordinary fields through this free.
    let block_size = unsafe { Page::block_size_at(page) };
    if block_size <= LARGE_MAX_OBJ_SIZE {
        unsafe { Theap::record_local_normal_free_statistics_at(theap, block_size) };
    }
}

/// `mi_page_malloc_zero`'s pop of the selected head, with its zeroing branch
/// (`free_is_zero` pages skip the clear; the link word is always cleared).
///
/// # Safety
///
/// The caller exclusively owns `page`'s ordinary local-list fields. `block`
/// is its non-null immediate head, or its local head selected while the
/// immediate list was empty; in the latter case the local list was cleared
/// before this call. Every link names a block of this page (the source
/// invariant `mi_block_next` relies on in normal release).
#[inline(always)]
unsafe fn pop_selected_head(page: NonNull<Page>, block: *mut Block, zero: bool) -> NonNull<u8> {
    // SAFETY: forwarded; this projects only the owner's ordinary fields.
    let state = unsafe { Page::local_free_list_state_at(page) };
    // SAFETY: forwarded non-empty selected list of valid block links.
    unsafe {
        let link = block.cast::<*mut Block>();
        let next = *link;
        *link = core::ptr::null_mut();
        *state.free.as_ptr() = next;
        *state.used.as_ptr() += 1;
        let block = NonNull::new_unchecked(block.cast::<u8>());
        if zero && !*state.free_is_zero.as_ptr() {
            // SAFETY: the page remains live; its block size is stable under
            // the owner's ordinary-field mutation above.
            core::ptr::write_bytes(block.as_ptr(), 0, Page::block_size_at(page));
        }
        block
    }
}

/// The owner-only part of `mi_page_free_quick_collect` before an immediate
/// pop. `local_head` is the exact local head when the immediate list was empty,
/// or null when the immediate list was non-empty. The pop writes the selected
/// block's successor directly to `free`, omitting the intermediate local-head
/// store that no other thread can observe.
///
/// # Safety
///
/// Same ownership contract as [`pop_selected_head`]. `local_head` must be the
/// page's unchanged local head observed while its immediate head was null,
/// or null when that immediate head was non-null.
#[inline(always)]
unsafe fn quick_collect_before_pop(page: NonNull<Page>, local_head: *mut Block) {
    if local_head.is_null() {
        return;
    }
    // SAFETY: forwarded ordinary-field ownership. An immediate head needs
    // no collection, so construct the page-state projection only when the
    // local list must transfer to the immediate list before the pop.
    unsafe {
        let state = Page::local_free_list_state_at(page);
        *state.local_free.as_ptr() = core::ptr::null_mut();
        *state.free_is_zero.as_ptr() = false;
    }
}

/// `mi_free_block_local`'s push onto `local_free` and `used` decrement.
///
/// # Safety
///
/// The caller exclusively owns the live page's ordinary local-list fields
/// and consumes `block`, an exact live block of that page. `used` is nonzero,
/// and every existing local-free link names a block of this page.
#[inline(always)]
unsafe fn push_local_free(page: NonNull<Page>, block: NonNull<u8>) {
    // SAFETY: forwarded ordinary-field ownership and consumed live block.
    unsafe {
        let state = Page::local_free_list_state_at(page);
        *block.as_ptr().cast::<*mut Block>() = *state.local_free.as_ptr();
        *state.used.as_ptr() -= 1;
        *state.local_free.as_ptr() = block.as_ptr().cast::<Block>();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicPtr, Ordering};
    use std::boxed::Box;
    use std::sync::Barrier;

    #[test]
    fn foreign_free_declines_while_owner_updates_ordinary_page_state() {
        let mut page = Box::new(Page::remote_free_test_page(2, 1));
        let page_pointer = AtomicPtr::new(core::ptr::from_mut(&mut *page));
        let mut block = [0usize; 2];
        let block_pointer = AtomicPtr::new(block.as_mut_ptr().cast::<u8>());
        let start = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let page = NonNull::new(page_pointer.load(Ordering::Relaxed)).unwrap();
                // SAFETY: the initialized fixture stays live until both threads
                // join; only this source owner writes ordinary page fields.
                let state = unsafe { Page::remote_free_owner_state_at(page) }.unwrap();
                start.wait();
                unsafe { *state.used.as_ptr() = 2 };
            });
            let page = NonNull::new(page_pointer.load(Ordering::Relaxed)).unwrap();
            let block = NonNull::new(block_pointer.load(Ordering::Relaxed)).unwrap();
            start.wait();
            // SAFETY: the fixture retains its counted client and initialized
            // metadata. Identity 16 is foreign to the source owner 12, so the
            // local attempt must decline without reading any ordinary field
            // or touching this client. The sentinel Theap is never dereferenced.
            assert!(!unsafe { free(NonNull::dangling(), page, block, 16) });
        });
        assert_eq!(page.used(), 2);
        assert_eq!(block, [0; 2]);
    }
}
