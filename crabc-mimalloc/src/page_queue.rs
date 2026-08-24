// Copyright (c) 2018-2024, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page-queue.c:40-55,252-423`
// (page-queue predicates and intrusive queue membership operations). The
// source's direct-page cache and `mi_theap_t` accounting require the absent
// theap lifecycle state and remain outside this bounded metadata-only slice.
// The mutating Rust names therefore end in `_metadata`: they are the exact
// intrusive link/count/flag kernels, not yet the complete live allocator
// operations named by the corresponding C functions.

use core::ptr::null_mut;
use core::sync::atomic::Ordering;

use crate::config::{LARGE_MAX_OBJ_WSIZE, WORD_SIZE};

use super::{Page, PageQueue, PAGE_IN_FULL_QUEUE};

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
}
