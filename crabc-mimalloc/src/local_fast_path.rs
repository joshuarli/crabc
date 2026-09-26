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
//! makes the identical source decision. In particular the fast paths never
//! reach `_mi_malloc_generic`'s fallback (administration, queue search,
//! extension, fresh pages), `_mi_page_free`, `_mi_page_unfull`, or remote
//! frees.
//!
//! They keep the checks the normal-release C build performs and no others:
//! as in `mi_block_next` without `MI_ENCODE_FREELIST`, list links are
//! trusted to name blocks of their page, which holds for every valid
//! program. The complete path's `LocalFreeList` keeps its containment checks.

use core::ptr::NonNull;

use crate::config::{
    BIN_HUGE, PAGE_MAX_START_BLOCK_ALIGN2, PAGE_OSPAGE_BLOCK_ALIGN2, PAGES_DIRECT, SMALL_MAX_OBJ_SIZE,
    SMALL_SIZE_MAX, WORD_SIZE,
};
use crate::single_thread::{RETIRE_CYCLES, RETIRE_MAX_PAGES};
use crate::types::{Block, EMPTY_PAGE, Page, Theap};
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

/// Allocates one small block from `theap`'s own pages, or returns `None`
/// having changed nothing.
///
/// `alignment` is `None` for the ordinary entry (`_mi_theap_malloc_zero`)
/// and the requested alignment for the aligned entry at offset zero
/// (`mi_theap_malloc_zero_aligned_at`). Both take the source order: the
/// direct page's immediate head (`_mi_page_malloc_zero`, which leaves
/// `retire_expire` alone), when aligned entries find it suitably aligned;
/// otherwise, for an ordinary or naturally aligned request,
/// `_mi_malloc_generic`'s counter step and its queue-head
/// `mi_page_free_quick_collect`, which clears `retire_expire` before the
/// pop.
///
/// # Safety
///
/// `theap` must come from the current thread's publication ([`published`])
/// with the runtime gates of `runtime_lifecycle::native_local_fast_owner`
/// checked in this same native operation, so this thread exclusively owns the Theap's ordinary fields and
/// every ordinary page field of its queued pages. An `alignment` that is not
/// a power of two is declined.
#[inline]
pub(crate) unsafe fn allocate(
    theap: NonNull<Theap>,
    size: usize,
    alignment: Option<usize>,
    zero: bool,
) -> Option<NonNull<u8>> {
    if size < WORD_SIZE
        || size > SMALL_SIZE_MAX
        || alignment.is_some_and(|alignment| !alignment.is_power_of_two() || alignment > size)
    {
        return None;
    }
    let direct_index = invariants::word_count(size)?;
    if direct_index >= PAGES_DIRECT {
        return None;
    }
    // SAFETY: the caller's contract makes this the exclusively owned live
    // Theap; the shared projection is the one page sessions use for reads.
    let theap_ref = unsafe { theap.as_ref() };
    let direct = theap_ref.direct_page(direct_index)?;
    if direct != EMPTY_PAGE.as_ptr() {
        // The initialized direct cache contains only the empty-page
        // sentinel or a live queue page, as the source direct lookup does.
        // SAFETY: the owner's published Theap keeps that cache initialized;
        // the sentinel was excluded above.
        let page = unsafe { NonNull::new_unchecked(direct) };
        // SAFETY: a direct entry names a live page of this Theap.
        let head = unsafe { page.as_ref() }.free_list_head();
        if !head.is_null() {
            if alignment.is_some_and(|alignment| head.addr() & (alignment - 1) != 0) {
                return None;
            }
            // SAFETY: the owner exclusively controls this live page's
            // ordinary local-list fields and its non-null immediate head.
            return Some(unsafe { pop_immediate(page, zero) });
        }
    }

    if let Some(alignment) = alignment {
        if !is_naturally_aligned_small(size, alignment)? {
            return None;
        }
    }
    let bin = size_class::bin(size)?;
    let first = NonNull::new(theap_ref.queue(bin)?.first())?;
    // SAFETY: the queue head is a live page of this Theap.
    let first_ref = unsafe { first.as_ref() };
    if first_ref.block_size() > SMALL_MAX_OBJ_SIZE || !first_ref.has_owner_exit_collectable_local_free() {
        // An empty head needs `mi_page_queue_find_free_ex`.
        return None;
    }
    // SAFETY: the caller owns the Theap's generic counters.
    if !unsafe { Theap::advance_generic_count_below_administration_at(theap) } {
        return None;
    }
    // SAFETY: exclusive ordinary-field ownership, as above. The head has an
    // immediate or local-free block, so `mi_page_free_quick_collect` leaves
    // `free` non-null for the pop.
    let block = unsafe {
        quick_collect(first);
        // `mi_page_queue_lookup_free_first` clears this owner-only byte once
        // it selects the head.
        Page::set_retire_expire_at(first, 0);
        pop_immediate(first, zero)
    };
    debug_assert!(alignment.is_none_or(|alignment| block.as_ptr().addr() & (alignment - 1) == 0));
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
#[inline]
pub(crate) unsafe fn free(
    theap: NonNull<Theap>,
    page: NonNull<Page>,
    block: NonNull<u8>,
    current_thread: usize,
) -> bool {
    // SAFETY: the live client keeps its page registered and initialized.
    // This read-only snapshot ends before the owner mutates ordinary fields.
    let (owner, page_theap, used, retire_expire) = {
        let page_ref = unsafe { page.as_ref() };
        (
            page_ref.owner_thread_id(),
            page_ref.theap(),
            page_ref.used(),
            page_ref.retire_expire(),
        )
    };
    if owner != current_thread || page_theap != theap.as_ptr() {
        return false;
    }
    if used == 0 {
        return false;
    }
    if used == 1 && retire_expire == 0 {
        // SAFETY: this is the same owner-local page and exact live block;
        // the preflight below leaves the page untouched if it cannot retain.
        return unsafe { retire_last_local_free(theap, page, block) };
    }
    // SAFETY: the owner exclusively controls the ordinary local-list fields,
    // and the caller consumes exact live `block` of this page.
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
/// live allocation. The page's retirement countdown is zero.
#[cold]
#[inline(never)]
unsafe fn retire_last_local_free(
    theap: NonNull<Theap>,
    page: NonNull<Page>,
    block: NonNull<u8>,
) -> bool {
    // SAFETY: the caller holds the page live and owns its ordinary geometry.
    let page_ref = unsafe { page.as_ref() };
    let block_size = page_ref.block_size();
    let reserved = page_ref.reserved();
    // `_mi_page_retire` on an unflagged, non-huge page selects its ordinary
    // queue: keep it only in the retain branch.
    let Some(bin) = size_class::bin(block_size) else { return false };
    if bin >= BIN_HUGE || reserved <= 1 {
        return false;
    }
    // SAFETY: exclusive owner-local Theap, as above.
    let Some(queue) = (unsafe { theap.as_ref() }).queue(bin) else { return false };
    let count = queue.count();
    if count > RETIRE_MAX_PAGES || !(count == 1 || block_size < SMALL_SIZE_MAX) {
        return false;
    }
    // SAFETY: this consumes the exact live block after all fallbacks have
    // been ruled out; the owner controls the page's local-list fields.
    unsafe { push_local_free(page, block) };
    // SAFETY: a fresh shared projection after the local-list writes; the
    // flag is the page's atomic `xthread_id` word.
    unsafe { page.as_ref() }.set_has_interior_pointers(false);
    // SAFETY: exclusive owner-local Theap, as above.
    unsafe { theap.as_ref() }.record_page_retired();
    let cycles = if block_size <= SMALL_MAX_OBJ_SIZE { RETIRE_CYCLES } else { RETIRE_CYCLES / 4 };
    // SAFETY: `used == 0` now, and the owner controls this byte and the
    // Theap's retirement bounds.
    unsafe {
        Page::set_retire_expire_at(page, cycles);
        let noted = Theap::note_local_retired_bin_at(theap, bin);
        debug_assert!(noted, "an ordinary queue bin is below BIN_FULL");
    }
    true
}

/// `mi_page_malloc_zero`'s pop of the immediate head, with its zeroing
/// branch (`free_is_zero` pages skip the clear; the link word is always
/// cleared).
///
/// # Safety
///
/// The caller exclusively owns `page`'s ordinary local-list fields, its
/// immediate list is non-empty, and every link names a block of this page
/// (the source invariant `mi_block_next` relies on in normal release).
#[inline(always)]
unsafe fn pop_immediate(page: NonNull<Page>, zero: bool) -> NonNull<u8> {
    // SAFETY: forwarded; this projects only the owner's ordinary fields.
    let state = unsafe { Page::local_free_list_state_at(page) };
    // SAFETY: forwarded non-empty immediate list of valid block links.
    unsafe {
        let block = *state.free.as_ptr();
        let link = block.cast::<*mut Block>();
        let next = *link;
        *link = core::ptr::null_mut();
        *state.free.as_ptr() = next;
        *state.used.as_ptr() += 1;
        let block = NonNull::new_unchecked(block.cast::<u8>());
        if zero && !*state.free_is_zero.as_ptr() {
            core::ptr::write_bytes(block.as_ptr(), 0, state.block_size);
        }
        block
    }
}

/// `mi_page_free_quick_collect` after the caller saw `free` or `local_free`
/// non-empty.
///
/// # Safety
///
/// Same ownership contract as [`pop_immediate`].
#[inline(always)]
unsafe fn quick_collect(page: NonNull<Page>) {
    // SAFETY: forwarded ordinary-field ownership.
    unsafe {
        let state = Page::local_free_list_state_at(page);
        if (*state.free.as_ptr()).is_null() {
            *state.free.as_ptr() = *state.local_free.as_ptr();
            *state.local_free.as_ptr() = core::ptr::null_mut();
            *state.free_is_zero.as_ptr() = false;
        }
    }
}

/// `mi_free_block_local`'s push onto `local_free` and `used` decrement.
///
/// # Safety
///
/// Same ownership contract as [`pop_immediate`]; `block` is an exact live
/// block of `page` that the caller consumes, and `used` is nonzero.
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
