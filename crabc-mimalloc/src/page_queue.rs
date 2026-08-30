// Copyright (c) 2018-2024, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page-queue.c:40-55,147-172,204-274,
// 252-423` (predicates, the test-only validity oracle, intrusive queue
// membership, and the direct-cache-before-page-count queue-removal order).
// The generic owner-exit coordinator below owns only this source queue half;
// deferred-free, retired-page, page-local collection, abandonment publication,
// PageMap/backing release, and TLD/Theap detach stay at their respective
// lifecycle boundaries.

use core::ptr::{NonNull, null_mut};
use core::sync::atomic::Ordering;

use crate::config::{BIN_FULL, LARGE_MAX_OBJ_WSIZE, PAGES_DIRECT, SMALL_SIZE_MAX, WORD_SIZE};
use crate::invariants;
use crate::size_class;
#[cfg(test)]
use crate::config::LARGE_MAX_OBJ_SIZE;

use super::{EMPTY_PAGE, Page, PageQueue, Theap, PAGE_IN_FULL_QUEUE};

/// Port of `mi_page_queue_is_huge`.
#[inline]
pub(crate) const fn page_queue_is_huge(queue: &PageQueue) -> bool {
    queue.block_size == (LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE
}

/// Port of `mi_page_queue_is_full`.
#[inline]
pub(crate) const fn page_queue_is_full(queue: &PageQueue) -> bool {
    queue.block_size == (LARGE_MAX_OBJ_WSIZE + 2) * WORD_SIZE
}

/// Port of `mi_page_queue_is_special`.
#[inline]
pub(crate) const fn page_queue_is_special(queue: &PageQueue) -> bool {
    queue.block_size > LARGE_MAX_OBJ_WSIZE * WORD_SIZE
}

/// Port of `mi_page_queue_count`.
#[inline]
pub(crate) const fn page_queue_count(queue: &PageQueue) -> usize {
    queue.count
}

/// The page-local conclusion of one source `_mi_theap_page_collect` visit.
///
/// The callback passed to [`theap_collect_abandon_queues`] chooses only this
/// source lifetime branch after force/false free collection. It does not name
/// a page kind, size bin, mapping kind, or test fixture geometry: an empty
/// page is released and every other page is detached for its source-specific
/// abandonment publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TheapCollectAbandonPageAction {
    /// The collectors proved the page all free, so the post-detach hook must
    /// perform its ordinary PageMap/backing release.
    Release,
    /// The page still has live blocks, so the post-detach hook must publish
    /// its source abandonment ownership before the old Theap/TLD can detach.
    Abandon,
}

/// Failure from the generic queue half of `_mi_theap_collect_abandon`.
///
/// A callback failure can occur after a one-way queue detach. The caller owns
/// the corresponding terminal-retention policy; this helper never retries a
/// different queue, invents a fresh page, or reattaches the former owner.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TheapCollectAbandonError<E> {
    /// A page-local collector or post-detach source transition failed.
    Page(E),
    /// The caller violated the exclusive complete-queue invariant.
    QueueInvariant,
}

/// Visits the actual source queues for `MI_ABANDON` in pinned order.
///
/// This is the queue coordinator seam for a future complete
/// `_mi_theap_collect_abandon` owner-exit path. Its caller performs deferred
/// free processing and retired-page collection first, then supplies the two
/// page-local source transitions: force/false collection before detachment,
/// followed by exact release or abandonment publication. The helper covers
/// every queue through `BIN_FULL`, saves the successor before either callback
/// can detach the current page, and performs the source queue mutation in the
/// required order: intrusive removal, direct-small cache repair, then Theap
/// page-count decrement.
///
/// This is intentionally not a public allocator entry point and does not
/// detach the Theap/TLD, choose a page geometry, publish an abandonment
/// bitmap, or release PageMap/mapping state. Those source-specific lifetimes
/// remain in the owner-exit layer that calls this seam.
///
/// # Safety
///
/// `theap` must be initialized and exclusively owned for the whole call. Its
/// queues must be complete, acyclic, and contain exactly `page_count` live
/// initialized pages. Both callbacks may mutate only the current page's
/// page-local source state; they must not alter queue links, queue membership,
/// direct-cache entries, or `theap.page_count`. `finish_page` may release the
/// current page only after this helper has detached it. No producer may race
/// any non-atomic page field or queue transition.
pub(crate) unsafe fn theap_collect_abandon_queues<E>(
    theap: &mut Theap,
    mut collect_page: impl FnMut(usize, NonNull<Page>) -> Result<TheapCollectAbandonPageAction, E>,
    mut finish_page: impl FnMut(
        &Theap,
        usize,
        NonNull<Page>,
        TheapCollectAbandonPageAction,
    ) -> Result<(), E>,
) -> Result<(), TheapCollectAbandonError<E>> {
    // This is the source `mi_theap_visit_pages` fast empty case. A live
    // Theap with zero pages has no queue transition to make.
    if theap.page_count == 0 {
        return Ok(());
    }

    let expected_page_count = theap.page_count;
    let mut visited_page_count = 0usize;

    // `MI_ABANDON` passes `include_full = true`, unlike ordinary collection.
    for bin in 0..=BIN_FULL {
        let mut remaining = theap
            .pages
            .get(bin)
            .ok_or(TheapCollectAbandonError::QueueInvariant)?
            .count;
        let mut current = theap
            .pages
            .get(bin)
            .ok_or(TheapCollectAbandonError::QueueInvariant)?
            .first;

        while remaining != 0 {
            let page = NonNull::new(current).ok_or(TheapCollectAbandonError::QueueInvariant)?;
            // SAFETY: the caller's queue-completeness and exclusive-owner
            // proof keeps the current page and its successor link valid.
            // Saving this edge is the source visitor's required protection
            // against either post-detach callback retiring current metadata.
            let next = unsafe { page.as_ref().next };
            let action = collect_page(bin, page).map_err(TheapCollectAbandonError::Page)?;

            // SAFETY: the caller proves `page` remains a current member of
            // this exact complete queue; the callback contract forbids it
            // from changing links or membership before this source removal.
            unsafe { theap_collect_abandon_detach_page(theap, bin, page)? };
            finish_page(theap, bin, page, action).map_err(TheapCollectAbandonError::Page)?;

            visited_page_count = visited_page_count
                .checked_add(1)
                .ok_or(TheapCollectAbandonError::QueueInvariant)?;
            current = next;
            remaining -= 1;
        }

        if !current.is_null() {
            return Err(TheapCollectAbandonError::QueueInvariant);
        }
    }

    if visited_page_count != expected_page_count || theap.page_count != 0 {
        return Err(TheapCollectAbandonError::QueueInvariant);
    }
    Ok(())
}

/// Removes one current queue member as the common queue half of source
/// `_mi_page_free` or `_mi_page_abandon` during Theap owner exit.
///
/// The direct cache must reflect the new queue head before `page_count`
/// changes. Keeping those operations together prevents a caller-selected
/// page-shape wrapper from accidentally repairing only direct-small paths.
unsafe fn theap_collect_abandon_detach_page<E>(
    theap: &mut Theap,
    bin: usize,
    page: NonNull<Page>,
) -> Result<(), TheapCollectAbandonError<E>> {
    let queue = theap
        .pages
        .get_mut(bin)
        .ok_or(TheapCollectAbandonError::QueueInvariant)? as *mut PageQueue;
    // SAFETY: the caller proves this is a valid exclusive current membership.
    unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
    if !theap_collect_abandon_update_direct_cache(theap, bin) {
        return Err(TheapCollectAbandonError::QueueInvariant);
    }
    if !theap.note_page_removed() {
        return Err(TheapCollectAbandonError::QueueInvariant);
    }
    Ok(())
}

/// Ports `mi_theap_queue_first_update` for the owner-exit detach path.
///
/// It is deliberately local to the generic coordinator: source queue removal
/// repairs the direct cache even when the next owner-exit action is an arena,
/// OS, regular, full, or singleton release. Non-small queues are a source
/// no-op.
fn theap_collect_abandon_update_direct_cache(theap: &mut Theap, bin: usize) -> bool {
    let Some(queue) = theap.pages.get(bin) else {
        return false;
    };
    let block_size = queue.block_size;
    if block_size > SMALL_SIZE_MAX {
        return true;
    }
    let Some(index) = invariants::word_count(block_size) else {
        return false;
    };
    if index >= PAGES_DIRECT || size_class::bin(block_size) != Some(bin) {
        return false;
    }
    let replacement = if queue.first.is_null() {
        EMPTY_PAGE.as_ptr()
    } else {
        queue.first
    };
    if theap.pages_free_direct[index] == replacement {
        return true;
    }

    let start = if index <= 1 {
        0
    } else {
        let Some(mut previous) = bin.checked_sub(1) else {
            return false;
        };
        while previous > 0
            && theap
                .pages
                .get(previous)
                .is_some_and(|queue| size_class::bin(queue.block_size) == Some(bin))
        {
            previous -= 1;
        }
        let Some(previous_size) = theap.pages.get(previous).map(|queue| queue.block_size) else {
            return false;
        };
        let Some(previous_index) = invariants::word_count(previous_size) else {
            return false;
        };
        match previous_index.checked_add(1) {
            Some(start) => start.min(index),
            None => return false,
        }
    };

    for direct in start..=index {
        theap.pages_free_direct[direct] = replacement;
    }
    true
}

/// Reads the `MI_PAGE_IN_FULL_QUEUE` membership bit.
#[inline]
pub(crate) fn page_is_in_full(page: &Page) -> bool {
    page.xthread_id.load(Ordering::Relaxed) & PAGE_IN_FULL_QUEUE != 0
}

/// Applies the `mi_page_set_in_full` metadata transition owned by this slice.
///
/// The source helper also maintains `mi_theap_t::pages_full_size`. That
/// aggregate and the owning theap lifecycle are absent, so queue membership
/// writes only the page-resident atomic flag here. Its Relaxed operation is
/// exactly the `mi_page_flags_set` operation used by the source helper.
#[inline]
fn page_set_in_full_membership(page: &Page, in_full: bool) {
    if in_full {
        page.xthread_id
            .fetch_or(PAGE_IN_FULL_QUEUE, Ordering::Relaxed);
    } else {
        page.xthread_id
            .fetch_and(!PAGE_IN_FULL_QUEUE, Ordering::Relaxed);
    }
}

/// Port of `mi_page_queue_remove`'s intrusive membership transition.
///
/// # Safety
///
/// `page` must be non-null, valid, and exclusively mutable. `queue` must be
/// the complete, acyclic doubly linked queue containing `page`; its count and
/// endpoint pointers must agree with every linked page. The caller must hold
/// the owning theap's queue synchronization, so no concurrent operation may
/// read or mutate these links. The page's block-size/special-queue relation
/// must satisfy the source helper's assertion: either its block size equals
/// the queue's block size, it is a huge page in the huge queue, or it is
/// marked in-full in the full queue.
///
/// This metadata-only port intentionally excludes the source's absent theap
/// page-count and direct-page-cache updates.
pub(crate) unsafe fn page_queue_remove_metadata(queue: &mut PageQueue, page: *mut Page) {
    // SAFETY: the caller guarantees that `page` is a valid uniquely mutable
    // member of `queue`, so reading its two intrusive links is valid.
    let page_ref = unsafe { &mut *page };

    if !page_ref.prev.is_null() {
        // SAFETY: `page_ref.prev` is another valid member of the caller's
        // complete queue and exclusive queue ownership permits relinking it.
        unsafe { (*page_ref.prev).next = page_ref.next };
    }
    if !page_ref.next.is_null() {
        // SAFETY: `page_ref.next` is another valid member of the caller's
        // complete queue and exclusive queue ownership permits relinking it.
        unsafe { (*page_ref.next).prev = page_ref.prev };
    }
    if page as *const Page == queue.last.cast_const() {
        queue.last = page_ref.prev;
    }
    if page as *const Page == queue.first.cast_const() {
        queue.first = page_ref.next;
    }
    queue.count -= 1;
    page_ref.next = null_mut();
    page_ref.prev = null_mut();
    page_set_in_full_membership(page_ref, false);
}

/// Port of `mi_page_queue_push`'s intrusive membership transition.
///
/// # Safety
///
/// `page` must be non-null, valid, exclusively mutable, and detached. The
/// caller must exclusively own the complete acyclic queue and every page it
/// links. `page` must either have `queue`'s block size, be a huge page in the
/// huge queue, or already be marked in-full for the full queue. No concurrent
/// queue mutation or observation may race with the operation.
///
/// This metadata-only port intentionally excludes the source's absent theap
/// page-count and direct-page-cache updates.
pub(crate) unsafe fn page_queue_push_metadata(queue: &mut PageQueue, page: *mut Page) {
    // SAFETY: the caller guarantees `page` is valid, detached, and uniquely
    // mutable for insertion into this exclusively owned queue.
    let page_ref = unsafe { &mut *page };
    let page = page_ref as *mut Page;

    page_set_in_full_membership(page_ref, page_queue_is_full(queue));
    page_ref.next = queue.first;
    page_ref.prev = null_mut();
    if !queue.first.is_null() {
        // SAFETY: the old head is a valid page in the caller's exclusively
        // owned queue, so its predecessor can be updated to the new head.
        unsafe { (*queue.first).prev = page };
        queue.first = page;
    } else {
        queue.first = page;
        queue.last = page;
    }
    queue.count += 1;
}

/// Port of `mi_page_queue_push_at_end`'s intrusive membership transition.
///
/// # Safety
///
/// `page` must be non-null, valid, exclusively mutable, and detached. The
/// caller must exclusively own the complete acyclic queue and every page it
/// links. `page` must either have `queue`'s block size, be a huge page in the
/// huge queue, or already be marked in-full for the full queue. No concurrent
/// queue mutation or observation may race with the operation.
///
/// This metadata-only port intentionally excludes the source's absent theap
/// page-count and direct-page-cache updates.
pub(crate) unsafe fn page_queue_push_at_end_metadata(queue: &mut PageQueue, page: *mut Page) {
    // SAFETY: the caller guarantees `page` is valid, detached, and uniquely
    // mutable for insertion into this exclusively owned queue.
    let page_ref = unsafe { &mut *page };
    let page = page_ref as *mut Page;

    page_set_in_full_membership(page_ref, page_queue_is_full(queue));
    page_ref.prev = queue.last;
    page_ref.next = null_mut();
    if !queue.last.is_null() {
        // SAFETY: the old tail is a valid page in the caller's exclusively
        // owned queue, so its successor can be updated to the new tail.
        unsafe { (*queue.last).next = page };
        queue.last = page;
    } else {
        queue.first = page;
        queue.last = page;
    }
    queue.count += 1;
}

/// Port of `mi_page_queue_move_to_front`'s intrusive membership transition.
///
/// # Safety
///
/// `page` must be non-null, valid, exclusively mutable, and a member of
/// `queue`. `queue` and its complete acyclic page chain must be exclusively
/// owned for the entire operation, with the source-required
/// block-size/special-queue relation preserved: same block size, huge page in
/// the huge queue, or a page marked in-full in the full queue. No concurrent
/// queue mutation or observation may race with the operation.
///
/// This metadata-only port intentionally excludes the source's absent theap
/// page-count and direct-page-cache updates.
pub(crate) unsafe fn page_queue_move_to_front_metadata(queue: &mut PageQueue, page: *mut Page) {
    if page as *const Page == queue.first.cast_const() {
        return;
    }
    // SAFETY: this function's caller guarantees the complete queue-membership
    // contract required by both source-ordered component transitions.
    unsafe { page_queue_remove_metadata(queue, page) };
    // SAFETY: `page_queue_remove_metadata` just detached the valid page while the same
    // exclusive queue ownership remains in force.
    unsafe { page_queue_push_metadata(queue, page) };
}

/// Port of `mi_page_queue_enqueue_from_ex`'s intrusive membership transition.
///
/// With `enqueue_at_end == false`, the pinned source deliberately inserts the
/// page in the second position of a non-empty destination queue, rather than
/// at its head; this operation preserves that policy exactly.
///
/// # Safety
///
/// `page` must be non-null, valid, and exclusively mutable. `from` must be
/// the complete acyclic queue containing it; `to` must be a complete acyclic
/// queue that does not contain it; the two queues and every linked page must
/// be disjoint and exclusively owned. Both counts and endpoints must be
/// accurate. The page and queues must satisfy one source relation: its block
/// size matches both queues; it matches `to` while `from` is full; it matches
/// `from` while `to` is full; or it is huge and `to` is huge or full. No
/// concurrent queue mutation or observation may race with the operation.
///
/// This metadata-only port intentionally excludes the source's absent
/// direct-page-cache updates.
pub(crate) unsafe fn page_queue_enqueue_from_ex_metadata(
    to: &mut PageQueue,
    from: &mut PageQueue,
    enqueue_at_end: bool,
    page: *mut Page,
) {
    // SAFETY: the caller guarantees that `page` is a valid uniquely mutable
    // member of `from`, with both complete queues exclusively owned.
    let page_ref = unsafe { &mut *page };
    let page = page_ref as *mut Page;

    if !page_ref.prev.is_null() {
        // SAFETY: the predecessor belongs to `from`'s valid, exclusively
        // owned page chain and can be relinked around `page`.
        unsafe { (*page_ref.prev).next = page_ref.next };
    }
    if !page_ref.next.is_null() {
        // SAFETY: the successor belongs to `from`'s valid, exclusively owned
        // page chain and can be relinked around `page`.
        unsafe { (*page_ref.next).prev = page_ref.prev };
    }
    if page as *const Page == from.last.cast_const() {
        from.last = page_ref.prev;
    }
    if page as *const Page == from.first.cast_const() {
        from.first = page_ref.next;
    }
    from.count -= 1;

    to.count += 1;
    if enqueue_at_end {
        page_ref.prev = to.last;
        page_ref.next = null_mut();
        if !to.last.is_null() {
            // SAFETY: the old destination tail belongs to `to`'s valid,
            // exclusively owned chain and accepts `page` as its successor.
            unsafe { (*to.last).next = page };
            to.last = page;
        } else {
            to.first = page;
            to.last = page;
        }
    } else if !to.first.is_null() {
        // SAFETY: the old head is valid in `to`'s exclusively owned chain;
        // reading its successor preserves the source's second-place insert.
        let next = unsafe { (*to.first).next };
        page_ref.prev = to.first;
        page_ref.next = next;
        // SAFETY: the old head is valid and uniquely mutable through the
        // caller's exclusive ownership of the complete destination queue.
        unsafe { (*to.first).next = page };
        if !next.is_null() {
            // SAFETY: the former second page remains valid in the destination
            // chain and must point back to the inserted page.
            unsafe { (*next).prev = page };
        } else {
            to.last = page;
        }
    } else {
        page_ref.prev = null_mut();
        page_ref.next = null_mut();
        to.first = page;
        to.last = page;
    }

    page_set_in_full_membership(page_ref, page_queue_is_full(to));
}

/// Port of `mi_page_queue_enqueue_from`.
///
/// # Safety
///
/// Has the same requirements as [`page_queue_enqueue_from_ex_metadata`].
#[inline]
pub(crate) unsafe fn page_queue_enqueue_from_metadata(
    to: &mut PageQueue,
    from: &mut PageQueue,
    page: *mut Page,
) {
    // SAFETY: this helper forwards its unchanged caller obligations to the
    // source-equivalent `enqueue_at_end` operation.
    unsafe { page_queue_enqueue_from_ex_metadata(to, from, true, page) };
}

/// Port of `mi_page_queue_enqueue_from_full`.
///
/// # Safety
///
/// Has the same requirements as [`page_queue_enqueue_from_ex_metadata`]; in addition,
/// `from` must be the source full queue and `to` the matching regular queue.
#[inline]
pub(crate) unsafe fn page_queue_enqueue_from_full_metadata(
    to: &mut PageQueue,
    from: &mut PageQueue,
    page: *mut Page,
) {
    // SAFETY: this helper forwards its unchanged caller obligations to the
    // source-equivalent `enqueue_at_end` operation.
    unsafe { page_queue_enqueue_from_ex_metadata(to, from, true, page) };
}

/// Test-only validator corresponding to mimalloc v3.5.0
/// `_mi_page_queue_is_valid` (`src/page-queue.c:147-172`).
///
/// The pinned helper is assertion-backed and therefore returns `true` only
/// after all checks pass. This Rust seam returns `false` for the same invalid
/// metadata instead, so focused tests can exercise each boundary without
/// aborting the test process. The caller must keep `theap`, `queue`, and every
/// page reachable through `queue->first` initialized and exclusively stable
/// for the duration of this call; the queue links must be dereferenceable.
///
/// # Safety
///
/// `queue` must be null or point to an initialized `PageQueue`. If non-null,
/// every non-null `first`/`next` link must point to an initialized `Page` that
/// remains alive and immobile for this call; `theap` is only compared and may
/// be null when validating detached test fixtures.
#[cfg(test)]
pub(crate) unsafe fn page_queue_is_valid_for_test(
    theap: *mut Theap,
    queue: *const PageQueue,
) -> bool {
    if queue.is_null() {
        return false;
    }

    // SAFETY: the caller guarantees that `queue` names an initialized queue
    // whose reachable page links remain valid for this exclusive check.
    let queue = unsafe { &*queue };
    let Some(queue_wsize) = queue
        .block_size
        .checked_add(WORD_SIZE.saturating_sub(1))
        .map(|size| size / WORD_SIZE)
    else {
        return false;
    };

    let mut count = 0usize;
    let mut previous = null_mut();
    let mut current = queue.first;
    while !current.is_null() {
        // SAFETY: each queue link is required by the caller to name an
        // initialized page in the same stable intrusive list.
        let page = unsafe { &*current };
        if page.prev != previous {
            return false;
        }

        // `mi_page_is_huge` is singleton-plus-(large-size or OS-base-before-
        // metadata) in the pinned source. The latter is retained here even
        // though production queue ownership does not construct OS-huge pages.
        let page_is_huge = page.reserved == 1
            && (page.block_size > LARGE_MAX_OBJ_SIZE
                || match page.memid().os_memory() {
                    Some(memory) => (memory.base as usize) < (current as usize),
                    None => false,
                });
        if page_is_in_full(page) {
            if queue_wsize != LARGE_MAX_OBJ_WSIZE + 2 {
                return false;
            }
        } else if page_is_huge {
            if queue_wsize != LARGE_MAX_OBJ_WSIZE + 1 {
                return false;
            }
        } else if page.block_size != queue.block_size {
            return false;
        }

        if page.theap != theap {
            return false;
        }
        if page.next.is_null() && queue.last != current {
            return false;
        }

        let Some(next_count) = count.checked_add(1) else {
            return false;
        };
        count = next_count;
        previous = current;
        current = page.next;
    }

    queue.count == count
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    fn page(block_size: usize) -> Page {
        let mut page = Page::empty();
        page.block_size = block_size;
        page
    }

    #[test]
    fn queue_predicates_distinguish_regular_huge_and_full_sentinels() {
        let regular = PageQueue::empty(16);
        let huge = PageQueue::empty((LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE);
        let full = PageQueue::empty((LARGE_MAX_OBJ_WSIZE + 2) * WORD_SIZE);

        assert!(!page_queue_is_huge(&regular));
        assert!(!page_queue_is_full(&regular));
        assert!(!page_queue_is_special(&regular));
        assert_eq!(page_queue_count(&regular), 0);
        assert!(page_queue_is_huge(&huge));
        assert!(!page_queue_is_full(&huge));
        assert!(page_queue_is_special(&huge));
        assert!(!page_queue_is_huge(&full));
        assert!(page_queue_is_full(&full));
        assert!(page_queue_is_special(&full));
    }

    unsafe fn assert_queue(queue: &PageQueue, expected: &[*mut Page]) {
        assert!(unsafe {
            page_queue_is_valid_for_test(null_mut(), core::ptr::from_ref(queue))
        });
        assert_eq!(queue.count, expected.len());
        assert_eq!(queue.first, expected.first().copied().unwrap_or(null_mut()));
        assert_eq!(queue.last, expected.last().copied().unwrap_or(null_mut()));

        let mut previous = null_mut();
        let mut current = queue.first;
        for &page in expected {
            assert_eq!(current, page);
            // SAFETY: every test creates a valid acyclic queue from its local
            // pages before validating its links.
            let page = unsafe { &*current };
            assert_eq!(page.prev, previous);
            previous = current;
            current = page.next;
        }
        assert!(current.is_null());
    }

    #[test]
    fn source_queue_validator_rejects_null_and_malformed_metadata() {
        let block_size = 16;
        let mut queue = PageQueue::empty(block_size);
        let mut first = page(block_size);
        let mut last = page(block_size);

        // SAFETY: both pages are local, detached, and exclusively owned by
        // this test while the queue is assembled and validated.
        unsafe {
            page_queue_push_at_end_metadata(&mut queue, &mut first);
            page_queue_push_at_end_metadata(&mut queue, &mut last);
            assert!(page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::from_ref(&queue),
            ));
            assert!(!page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::null(),
            ));

            last.test_set_queue_prev(null_mut());
            assert!(!page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::from_ref(&queue),
            ));
            last.test_set_queue_prev(&mut first);

            queue.count += 1;
            assert!(!page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::from_ref(&queue),
            ));
            queue.count -= 1;

            first.abandoned_test_set_theap(core::ptr::NonNull::<Theap>::dangling().as_ptr());
            assert!(!page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::from_ref(&queue),
            ));
        }
    }

    #[test]
    fn source_queue_validator_accepts_huge_and_full_queue_sentinels() {
        let mut huge = PageQueue::empty((LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE);
        let mut huge_page = page((LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE);
        assert!(huge_page.set_capacity_reserved(1, 1));

        // SAFETY: the singleton page is detached and exclusively owned by
        // this test for the queue insertion and validator check.
        unsafe {
            page_queue_push_at_end_metadata(&mut huge, &mut huge_page);
            assert!(page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::from_ref(&huge),
            ));
        }

        let mut full = PageQueue::empty((LARGE_MAX_OBJ_WSIZE + 2) * WORD_SIZE);
        let mut full_page = page(16);
        // SAFETY: the singleton page is detached and exclusively owned by
        // this test for the full-queue insertion and validator check.
        unsafe {
            page_queue_push_at_end_metadata(&mut full, &mut full_page);
            assert!(page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::from_ref(&full),
            ));
            full.block_size = 16;
            assert!(!page_queue_is_valid_for_test(
                null_mut(),
                core::ptr::from_ref(&full),
            ));
        }
    }

    #[test]
    fn push_and_push_at_end_keep_both_queue_ends_and_backlinks() {
        let block_size = 16;
        let mut queue = PageQueue::empty(block_size);
        let mut first = page(block_size);
        let mut last = page(block_size);
        let mut new_first = page(block_size);

        // SAFETY: each page is detached, valid for exclusive mutation, and
        // belongs to this exclusively borrowed queue's block-size class.
        unsafe {
            page_queue_push_metadata(&mut queue, &mut first);
            page_queue_push_at_end_metadata(&mut queue, &mut last);
            page_queue_push_metadata(&mut queue, &mut new_first);
            assert_queue(
                &queue,
                &[
                    &mut new_first as *mut Page,
                    &mut first as *mut Page,
                    &mut last as *mut Page,
                ],
            );
        }
    }

    #[test]
    fn remove_detaches_head_middle_and_tail_and_preserves_remaining_links() {
        let block_size = 16;
        let mut queue = PageQueue::empty(block_size);
        let mut first = page(block_size);
        let mut middle = page(block_size);
        let mut last = page(block_size);

        // SAFETY: the three local pages form this queue's complete, acyclic
        // membership and are exclusively mutable for the test.
        unsafe {
            page_queue_push_at_end_metadata(&mut queue, &mut first);
            page_queue_push_at_end_metadata(&mut queue, &mut middle);
            page_queue_push_at_end_metadata(&mut queue, &mut last);

            page_queue_remove_metadata(&mut queue, &mut middle);
            assert!(middle.next.is_null());
            assert!(middle.prev.is_null());
            assert_queue(&queue, &[&mut first as *mut Page, &mut last as *mut Page]);

            page_queue_remove_metadata(&mut queue, &mut first);
            assert!(first.next.is_null());
            assert!(first.prev.is_null());
            assert_queue(&queue, &[&mut last as *mut Page]);

            page_queue_remove_metadata(&mut queue, &mut last);
            assert!(last.next.is_null());
            assert!(last.prev.is_null());
            assert_queue(&queue, &[]);
        }
    }

    #[test]
    fn move_to_front_preserves_count_and_relinks_the_former_tail() {
        let block_size = 16;
        let mut queue = PageQueue::empty(block_size);
        let mut first = page(block_size);
        let mut middle = page(block_size);
        let mut last = page(block_size);

        // SAFETY: the pages are exclusively mutable and are the complete
        // membership of this valid queue.
        unsafe {
            page_queue_push_at_end_metadata(&mut queue, &mut first);
            page_queue_push_at_end_metadata(&mut queue, &mut middle);
            page_queue_push_at_end_metadata(&mut queue, &mut last);
            page_queue_move_to_front_metadata(&mut queue, &mut last);
            assert_queue(
                &queue,
                &[
                    &mut last as *mut Page,
                    &mut first as *mut Page,
                    &mut middle as *mut Page,
                ],
            );
        }
    }

    #[test]
    fn enqueue_from_appends_to_the_destination_without_changing_total_membership() {
        let block_size = 16;
        let mut from = PageQueue::empty(block_size);
        let mut to = PageQueue::empty(block_size);
        let mut first = page(block_size);
        let mut moved = page(block_size);
        let mut last = page(block_size);
        let mut destination = page(block_size);

        // SAFETY: all four local pages are exclusively mutable and each starts
        // detached before the two valid queues are assembled.
        unsafe {
            page_queue_push_at_end_metadata(&mut from, &mut first);
            page_queue_push_at_end_metadata(&mut from, &mut moved);
            page_queue_push_at_end_metadata(&mut from, &mut last);
            page_queue_push_at_end_metadata(&mut to, &mut destination);

            page_queue_enqueue_from_metadata(&mut to, &mut from, &mut moved);

            assert_queue(&from, &[&mut first as *mut Page, &mut last as *mut Page]);
            assert_queue(
                &to,
                &[
                    &mut destination as *mut Page,
                    &mut moved as *mut Page,
                ],
            );
        }
    }

    #[test]
    fn enqueue_from_ex_preserves_the_source_second_position_policy() {
        let block_size = 16;
        let mut from = PageQueue::empty(block_size);
        let mut to = PageQueue::empty(block_size);
        let mut moved = page(block_size);
        let mut destination_first = page(block_size);
        let mut destination_last = page(block_size);

        // SAFETY: each local page is valid and exclusively mutable; the source
        // queue and destination queue have disjoint complete membership.
        unsafe {
            page_queue_push_at_end_metadata(&mut from, &mut moved);
            page_queue_push_at_end_metadata(&mut to, &mut destination_first);
            page_queue_push_at_end_metadata(&mut to, &mut destination_last);

            page_queue_enqueue_from_ex_metadata(&mut to, &mut from, false, &mut moved);

            assert_queue(&from, &[]);
            assert_queue(
                &to,
                &[
                    &mut destination_first as *mut Page,
                    &mut moved as *mut Page,
                    &mut destination_last as *mut Page,
                ],
            );
        }
    }

    #[test]
    fn full_queue_transfer_sets_and_clears_the_page_membership_flag() {
        let block_size = 16;
        let mut regular = PageQueue::empty(block_size);
        let mut full = PageQueue::empty((LARGE_MAX_OBJ_WSIZE + 2) * WORD_SIZE);
        let mut page = page(block_size);

        // SAFETY: the local page is valid and exclusively mutable, and moves
        // between these two disjoint queues as required by the source helpers.
        unsafe {
            page_queue_push_metadata(&mut regular, &mut page);
            assert!(!page_is_in_full(&page));

            page_queue_enqueue_from_metadata(&mut full, &mut regular, &mut page);
            assert!(page_is_in_full(&page));
            assert_queue(&regular, &[]);
            assert_queue(&full, &[&mut page as *mut Page]);

            page_queue_enqueue_from_full_metadata(&mut regular, &mut full, &mut page);
            assert!(!page_is_in_full(&page));
            assert_queue(&regular, &[&mut page as *mut Page]);
            assert_queue(&full, &[]);
        }
    }

    #[test]
    fn generic_collect_abandon_visits_mixed_queues_in_source_order() {
        let mut theap = Theap::empty();
        let small_bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let medium_bin = crate::size_class::bin(LARGE_MAX_OBJ_SIZE / 2)
            .expect("medium size has a regular bin");
        assert!(small_bin < medium_bin && medium_bin < BIN_FULL);

        let small_size = theap.queue(small_bin).unwrap().block_size();
        let medium_size = theap.queue(medium_bin).unwrap().block_size();
        let mut small_first = page(small_size);
        let mut small_second = page(small_size);
        let mut medium = page(medium_size);
        let mut full = page(medium_size);
        let small_first = NonNull::from(&mut small_first);
        let small_second = NonNull::from(&mut small_second);
        let medium = NonNull::from(&mut medium);
        let full = NonNull::from(&mut full);

        // SAFETY: the four local pages begin detached and the test owns the
        // complete source queue image while it assembles it.
        unsafe {
            page_queue_push_at_end_metadata(theap.queue_mut(small_bin).unwrap(), small_first.as_ptr());
            page_queue_push_at_end_metadata(theap.queue_mut(small_bin).unwrap(), small_second.as_ptr());
            page_queue_push_at_end_metadata(theap.queue_mut(medium_bin).unwrap(), medium.as_ptr());
            page_queue_push_at_end_metadata(theap.queue_mut(BIN_FULL).unwrap(), full.as_ptr());
        }
        for _ in 0..4 {
            theap.note_page_added();
        }
        assert!(theap_collect_abandon_update_direct_cache(&mut theap, small_bin));
        let small_direct = invariants::word_count(small_size).unwrap();
        assert_eq!(theap.direct_page(small_direct), Some(small_first.as_ptr()));

        let mut visits = std::vec::Vec::new();
        let mut finished = std::vec::Vec::new();
        // SAFETY: the test has exclusive access to the complete, acyclic
        // mixed queue image and the callbacks alter neither membership nor
        // links. They only record the exact source sequence.
        unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                |bin, page| {
                    visits.push((bin, page));
                    Ok::<_, ()>(if page == small_second {
                        TheapCollectAbandonPageAction::Abandon
                    } else {
                        TheapCollectAbandonPageAction::Release
                    })
                },
                |theap, bin, page, action| {
                    finished.push((bin, page, action, theap.page_count(), theap.direct_page(small_direct)));
                    Ok::<_, ()>(())
                },
            )
            .expect("the valid mixed Theap completes its source queue traversal");
        }

        assert_eq!(
            visits,
            std::vec![
                (small_bin, small_first),
                (small_bin, small_second),
                (medium_bin, medium),
                (BIN_FULL, full),
            ],
            "regular bins precede BIN_FULL and the saved small successor remains visitable"
        );
        assert_eq!(
            finished,
            std::vec![
                (
                    small_bin,
                    small_first,
                    TheapCollectAbandonPageAction::Release,
                    3,
                    Some(small_second.as_ptr()),
                ),
                (
                    small_bin,
                    small_second,
                    TheapCollectAbandonPageAction::Abandon,
                    2,
                    Some(EMPTY_PAGE.as_ptr()),
                ),
                (
                    medium_bin,
                    medium,
                    TheapCollectAbandonPageAction::Release,
                    1,
                    Some(EMPTY_PAGE.as_ptr()),
                ),
                (
                    BIN_FULL,
                    full,
                    TheapCollectAbandonPageAction::Release,
                    0,
                    Some(EMPTY_PAGE.as_ptr()),
                ),
            ],
            "each post-detach action observes the source direct-cache repair before page-count decrement"
        );
        assert!(theap.queue(small_bin).unwrap().is_empty());
        assert!(theap.queue(medium_bin).unwrap().is_empty());
        assert!(theap.queue(BIN_FULL).unwrap().is_empty());
        assert_eq!(theap.page_count(), 0);
        assert!(!page_is_in_full(unsafe { full.as_ref() }));
    }

    #[test]
    fn generic_collect_abandon_rejects_a_queue_count_mismatch() {
        let mut theap = Theap::empty();
        let bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let block_size = theap.queue(bin).unwrap().block_size();
        let mut only = page(block_size);
        let only = NonNull::from(&mut only);

        // SAFETY: the page is initially detached and locally owned. The
        // subsequent manually paired Theap count makes only the queue's
        // source count malformed for this rejection test.
        unsafe { page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), only.as_ptr()) };
        theap.note_page_added();
        theap.queue_mut(bin).unwrap().count += 1;

        // SAFETY: links themselves remain valid and exclusive; the primitive
        // must reject the count/image disagreement rather than following a
        // nonexistent successor.
        let result = unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                |_bin, _page| Ok::<_, ()>(TheapCollectAbandonPageAction::Release),
                |_theap, _bin, _page, _action| Ok::<_, ()>(()),
            )
        };
        assert_eq!(result, Err(TheapCollectAbandonError::QueueInvariant));
    }
}
