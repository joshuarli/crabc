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
//! They keep the checks the normal-release C build performs and add only
//! the `LocalFreeList` containment check every Rust free-list access makes.

use core::ptr::NonNull;

use crate::config::{
    BIN_HUGE, PAGE_MAX_START_BLOCK_ALIGN2, PAGE_OSPAGE_BLOCK_ALIGN2, PAGES_DIRECT, SMALL_MAX_OBJ_SIZE,
    SMALL_SIZE_MAX, WORD_SIZE,
};
use crate::free_list::LocalFreeList;
use crate::single_thread::{RETIRE_CYCLES, RETIRE_MAX_PAGES};
use crate::types::{EMPTY_PAGE, Page, Theap};
use crate::{invariants, size_class};

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
/// `theap` must be the current thread's published owner-local fast Theap
/// (`main_heap_thread::owner_local_fast_theap`) with the runtime gates of
/// `runtime_lifecycle::native_local_fast_theap` checked in this same native
/// operation, so this thread exclusively owns the Theap's ordinary fields and
/// every ordinary page field of its queued pages. Any `alignment` must be a
/// valid power of two.
#[inline]
pub(crate) unsafe fn allocate(
    theap: NonNull<Theap>,
    size: usize,
    alignment: Option<usize>,
    zero: bool,
) -> Option<NonNull<u8>> {
    if size < WORD_SIZE || size > SMALL_SIZE_MAX || alignment.is_some_and(|alignment| alignment > size) {
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
        let page = NonNull::new(direct)?;
        // SAFETY: a direct entry names a live page of this Theap.
        let head = unsafe { page.as_ref() }.free_list_head();
        if !head.is_null() {
            if alignment.is_some_and(|alignment| head.addr() & (alignment - 1) != 0) {
                return None;
            }
            // SAFETY: the owner exclusively controls this page's ordinary
            // local-list fields and the popped head block.
            let mut free_list = unsafe { LocalFreeList::from_page_at(page) }.ok()?;
            return free_list.pop(zero).ok()?;
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
    // immediate or local-free block, so quick collection and the pop below
    // succeed unless that list is corrupt; the complete path then rejects the
    // same list.
    let mut free_list = unsafe { LocalFreeList::from_page_at(first) }.ok()?;
    if !free_list.quick_collect().ok()? {
        return None;
    }
    // SAFETY: `mi_page_queue_lookup_free_first` clears this owner-only byte
    // once it selects the head.
    unsafe { Page::set_retire_expire_at(first, 0) };
    let block = free_list.pop(zero).ok()??;
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
    let (owner, page_theap, used, retire_expire, block_size, reserved) = {
        let page_ref = unsafe { page.as_ref() };
        (
            page_ref.owner_thread_id(),
            page_ref.theap(),
            page_ref.used(),
            page_ref.retire_expire(),
            page_ref.block_size(),
            page_ref.reserved(),
        )
    };
    if owner != current_thread || page_theap != theap.as_ptr() {
        return false;
    }
    let retire = used == 1 && retire_expire == 0;
    let mut retire_bin = 0;
    if retire {
        // `_mi_page_retire` on an unflagged, non-huge page selects its
        // ordinary queue: keep it only in the retain branch.
        let Some(bin) = size_class::bin(block_size) else { return false };
        if bin >= BIN_HUGE || reserved <= 1 {
            return false;
        }
        // SAFETY: exclusive owner-local Theap, as in `allocate`.
        let Some(queue) = (unsafe { theap.as_ref() }).queue(bin) else { return false };
        let count = queue.count();
        if count > RETIRE_MAX_PAGES || !(count == 1 || block_size < SMALL_SIZE_MAX) {
            return false;
        }
        retire_bin = bin;
    }
    // SAFETY: the owner exclusively controls the ordinary local-list fields;
    // `push_local` validates `block` before writing any link.
    let Ok(mut free_list) = (unsafe { LocalFreeList::from_page_at(page) }) else { return false };
    // SAFETY: forwarded exact-live, consumed-block contract.
    if unsafe { free_list.push_local(block) }.is_err() {
        return false;
    }
    if retire {
        // SAFETY: a fresh shared projection after the local-list writes; the
        // flag is the page's atomic `xthread_id` word.
        unsafe { page.as_ref() }.set_has_interior_pointers(false);
        // SAFETY: exclusive owner-local Theap, as in `allocate`.
        unsafe { theap.as_ref() }.record_page_retired();
        let cycles = if block_size <= SMALL_MAX_OBJ_SIZE { RETIRE_CYCLES } else { RETIRE_CYCLES / 4 };
        // SAFETY: `used == 0` now, and the owner controls this byte and the
        // Theap's retirement bounds.
        unsafe {
            Page::set_retire_expire_at(page, cycles);
            let noted = Theap::note_local_retired_bin_at(theap, retire_bin);
            debug_assert!(noted, "an ordinary queue bin is below BIN_FULL");
        }
    }
    true
}
