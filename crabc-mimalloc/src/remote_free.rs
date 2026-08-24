// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/free.c:62-97`
// (`mi_free_block_mt`) and `src/page.c:150-201`
// (`mi_page_thread_collect_to_local` and `mi_page_thread_free_collect`), with
// the exact `mi_thread_free_t` low-bit representation from
// `include/mimalloc/types.h:388-418`.
//
// This bounded Milestone 5 slice handles only remote push and owner
// collection for a live owner-associated page. It deliberately excludes
// the separate `_mi_deferred_free` callback, abandonment/adoption, TLS/theap
// attachment, page retirement, page release, and Loom modeling.

use core::ptr::{self, NonNull};

use crate::atomic::{word_cas_weak_acq_rel, word_load_relaxed};
use crate::types::{
    Block, Page, PageRemoteFreeOwnerState, PageRemoteFreeProducerState, ThreadFree,
    PAGE_FLAG_MASK, THREAD_ID_ABANDONED, THREAD_ID_ABANDONED_MAPPED,
    THREAD_ID_DETACHED,
};

const THREAD_FREE_OWNED: ThreadFree = 1;
const THREAD_FREE_BLOCK_MASK: ThreadFree = !THREAD_FREE_OWNED;

/// The bounded remote-free protocol encountered a state whose lifecycle is
/// not yet implemented, or an invalid remote-list accounting condition.
///
/// These errors preserve the source boundary rather than claiming recovery
/// for allocator misuse. In particular, a collection accounting error occurs
/// only after the owner has detached the corrupted remote list, as in the C
/// path that reports and leaves that list uncollected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteFreeError {
    /// The page is abandoned, detached, retired, or otherwise lacks its live
    /// associated owner record.
    NotOwnerAssociated,
    /// A caller supplied a block whose address cannot encode in the source
    /// low-bit `mi_thread_free_t` representation.
    UnalignedBlock,
    /// The detached remote list contains more blocks than this page capacity.
    TooManyRemoteBlocks,
    /// The detached remote list would decrement `used` below zero.
    UsedCountUnderflow,
}

/// Publishes one remote free to a live owner-associated page.
///
/// This is the frozen normal-release `mi_free_block_mt` push from
/// `src/free.c:80-87`. It writes `block->next` before each attempted AcqRel
/// weak CAS, so a successful release publication makes that link visible to
/// owner collection's acquiring CAS. A failed CAS updates the expected head
/// with Acquire and retries with a freshly linked block, exactly preserving
/// the source's LIFO remote list.
///
/// # Safety
///
/// `page` must remain initialized, live, and associated with one owner for
/// the whole call and until the successful publication is eventually
/// collected. It must not be detached, abandoned, retired, reused, or
/// released while any producer can retain it. `block` must be a distinct,
/// aligned current allocation from this exact page, exclusively owned by this
/// caller, and not previously freed. No caller may access its first word after
/// this succeeds. The caller must use the corresponding owner collection
/// before it permits local allocation/free-list access to the collected block.
/// This raw pinned-page boundary deliberately creates no producer `&Page`:
/// the producer reads only the two atomic source fields.
pub(crate) unsafe fn push(
    page: NonNull<Page>,
    block: NonNull<u8>,
) -> Result<(), RemoteFreeError> {
    if block.as_ptr().addr() & THREAD_FREE_OWNED != 0 {
        return Err(RemoteFreeError::UnalignedBlock);
    }
    // SAFETY: the caller supplies the pinned live-page and lifecycle proof.
    // This derives only atomic subobject pointers; it does not read `theap`.
    let state = unsafe { Page::remote_free_producer_state_at(page) };
    if !producer_has_live_thread_identity(&state) {
        return Err(RemoteFreeError::NotOwnerAssociated);
    }

    // SAFETY: `state` names the initialized `xthread_free` atomic field.
    let word = unsafe { state.xthread_free.as_ref() };
    let mut previous = word_load_relaxed(word);
    loop {
        if !is_owned(previous) {
            return Err(RemoteFreeError::NotOwnerAssociated);
        }
        let previous_block = thread_free_block(previous);
        // SAFETY: the caller retains exclusive ownership of `block`; the
        // source normal-release profile stores its unencoded next pointer
        // before the release half of the publishing compare/exchange.
        unsafe { block_set_next(block.cast(), previous_block) };
        let replacement = thread_free_create(block.cast().as_ptr(), is_owned(previous))
            .expect("the checked block alignment preserves the low owner bit");
        if word_cas_weak_acq_rel(word, &mut previous, replacement) {
            return Ok(());
        }
    }
}

/// Atomically detaches remote frees and merges them into the owner's local
/// free list.
///
/// This ports `mi_page_thread_free_collect` followed by
/// `mi_page_thread_collect_to_local` in `src/page.c:150-201`. The successful
/// weak CAS keeps the exact source AcqRel/Acquire pair and retains the low
/// ownership bit while clearing only the block-pointer portion. It therefore
/// races safely with another producer: a producer that loses the race retries
/// against the owned empty head, while a producer that wins is included in the
/// detached LIFO list.
///
/// # Safety
///
/// `page` must be a live owner-associated page and this caller must be its
/// sole owner for the non-atomic `used` and `local_free` fields. Every block
/// reachable from the detached remote list must be a valid, unencoded block
/// link written by [`push`] and stay live through this call. The surrounding
/// lifecycle must prohibit abandonment, detachment, retirement, reuse, and
/// release while producers or this collection can access the page. This raw
/// pinned-page boundary derives only owner field pointers; it does not create
/// a concurrent `&mut Page`.
pub(crate) unsafe fn collect(page: NonNull<Page>) -> Result<usize, RemoteFreeError> {
    // SAFETY: the caller supplies the sole-owner and stable live-page proof.
    let state = unsafe { Page::remote_free_owner_state_at(page) }
        .ok_or(RemoteFreeError::NotOwnerAssociated)?;
    collect_state(state)
}

fn collect_state(state: PageRemoteFreeOwnerState) -> Result<usize, RemoteFreeError> {
    // SAFETY: state construction proved this is the initialized page atomic.
    let xthread_free = unsafe { state.xthread_free.as_ref() };
    let mut previous = word_load_relaxed(xthread_free);
    loop {
        if !is_owned(previous) {
            return Err(RemoteFreeError::NotOwnerAssociated);
        }
        let head = thread_free_block(previous);
        let Some(head) = NonNull::new(head) else {
            return Ok(0);
        };
        let replacement = thread_free_create(ptr::null_mut(), is_owned(previous))
            .expect("a null thread-free head always preserves its owner bit");
        if word_cas_weak_acq_rel(xthread_free, &mut previous, replacement) {
            // SAFETY: a successful AcqRel detach synchronizes with every
            // producer's release publication in the captured list. The caller
            // of `collect` supplied the sole owner proof for non-atomic page
            // fields and each source-shaped unencoded block link.
            return unsafe { collect_detached_to_local(state, head) };
        }
    }
}

/// Consumes one already detached source thread-free list into `local_free`.
///
/// # Safety
///
/// `head` must be the detached valid unencoded list described by `state`; no
/// producer may mutate any node in that list after the successful detach.
unsafe fn collect_detached_to_local(
    state: PageRemoteFreeOwnerState,
    head: NonNull<Block>,
) -> Result<usize, RemoteFreeError> {
    if state.capacity == 0 {
        return Err(RemoteFreeError::TooManyRemoteBlocks);
    }

    // `mi_page_thread_collect_to_local` walks to the tail before it changes
    // either page count or local-list head. In the frozen no-padding,
    // unencoded profile, the only source check here is list count versus page
    // capacity and `used`.
    let mut count = 1usize;
    let mut tail = head;
    loop {
        // SAFETY: the caller proves `tail` is one live source free-list node
        // whose first word was initialized before the release publication.
        let next = unsafe { block_next(tail) };
        let Some(next) = NonNull::new(next) else {
            break;
        };
        if count >= state.capacity as usize {
            return Err(RemoteFreeError::TooManyRemoteBlocks);
        }
        count += 1;
        tail = next;
    }
    // SAFETY: the AcqRel detach completed above and the caller has the owner
    // proof for these exact non-atomic fields. These are disjoint from the
    // producer-visible atomic word and no whole-page reference is formed.
    let used = unsafe { &mut *state.used.as_ptr() };
    if count > *used {
        return Err(RemoteFreeError::UsedCountUnderflow);
    }
    // SAFETY: see the `used` field borrow above.
    let local_free = unsafe { &mut *state.local_free.as_ptr() };

    // SAFETY: the detached tail and the owner's former local head are valid
    // disjoint source list fragments. Linking them before the owner publishes
    // the new local head preserves the existing local-free merge invariant.
    unsafe { block_set_next(tail, *local_free) };
    *local_free = head.as_ptr();
    *used -= count;
    Ok(count)
}

#[inline]
const fn is_owned(thread_free: ThreadFree) -> bool {
    thread_free & THREAD_FREE_OWNED != 0
}

#[inline]
fn producer_has_live_thread_identity(state: &PageRemoteFreeProducerState) -> bool {
    // SAFETY: producer state carries a direct pointer to the initialized
    // atomic xthread identity field; no non-atomic page field is inspected.
    let thread_id = unsafe { state.xthread_id.as_ref() }
        .load(core::sync::atomic::Ordering::Acquire)
        & !PAGE_FLAG_MASK;
    thread_id != THREAD_ID_ABANDONED
        && thread_id != THREAD_ID_ABANDONED_MAPPED
        && thread_id != THREAD_ID_DETACHED
}

#[inline]
fn thread_free_block(thread_free: ThreadFree) -> *mut Block {
    // `mi_thread_free_t` stores a pointer in all bits except the low owner
    // bit. `expose_provenance` recorded that provenance when publishing; this
    // restores it after atomically loading the exact C word representation.
    core::ptr::with_exposed_provenance_mut(thread_free & THREAD_FREE_BLOCK_MASK)
}

#[inline]
fn thread_free_create(block: *mut Block, owned: bool) -> Result<ThreadFree, RemoteFreeError> {
    let address = block.expose_provenance();
    if address & THREAD_FREE_OWNED != 0 {
        return Err(RemoteFreeError::UnalignedBlock);
    }
    Ok(address | usize::from(owned))
}

#[inline]
unsafe fn block_next(block: NonNull<Block>) -> *mut Block {
    // SAFETY: callers prove that `block` is a valid normal-release source
    // free-list node. This direct first-word pointer read is exactly
    // `mi_block_next` with `MI_ENCODE_FREELIST == 0`.
    unsafe { ptr::read(block.as_ptr().cast::<*mut Block>()) }
}

#[inline]
unsafe fn block_set_next(block: NonNull<Block>, next: *mut Block) {
    // SAFETY: callers prove exclusive access to `block`'s first word. This
    // is exactly `mi_block_set_next` with `MI_ENCODE_FREELIST == 0`; no extra
    // atomic link is introduced because publication is the head CAS.
    unsafe { ptr::write(block.as_ptr().cast::<*mut Block>(), next) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Barrier;
    use std::thread;

    #[repr(align(16))]
    struct TestBlock([u8; 16]);

    impl TestBlock {
        fn pointer(&mut self) -> NonNull<u8> {
            NonNull::from(&mut self.0).cast()
        }
    }

    #[test]
    fn remote_push_keeps_the_owner_bit_and_owner_collection_merges_before_local_frees() {
        let mut page = Page::remote_free_test_page(4, 4);
        let page_raw = NonNull::from(&mut page);
        let mut local = TestBlock([0; 16]);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let local_pointer = local.pointer();
        let first_pointer = first.pointer();
        let second_pointer = second.pointer();
        page.remote_free_test_set_local_free(local_pointer.cast().as_ptr());

        // SAFETY: this fixture remains live and owner-associated for both
        // remote publications, and each test block is freed exactly once.
        unsafe {
            push(page_raw, first_pointer).expect("the associated page accepts a remote free");
            push(page_raw, second_pointer).expect("the associated page accepts a remote free");
        }

        assert_eq!(page.remote_free_test_head() & 1, 1);
        assert_eq!(page.remote_free_test_head() & !1, second_pointer.as_ptr().addr());

        // SAFETY: the producer operations are complete and this thread is the
        // sole page owner for the local-free merge.
        assert_eq!(unsafe { collect(page_raw) }, Ok(2));
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.remote_free_test_used(), 2);
        assert_eq!(
            page.remote_free_test_local_chain(),
            [second_pointer.as_ptr(), first_pointer.as_ptr(), local_pointer.as_ptr()]
        );
    }

    #[test]
    fn owner_collection_of_an_empty_remote_list_preserves_the_owned_empty_word() {
        let mut page = Page::remote_free_test_page(1, 1);
        let page_raw = NonNull::from(&mut page);

        // SAFETY: no producer has published and this is the only owner.
        assert_eq!(unsafe { collect(page_raw) }, Ok(0));
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.remote_free_test_used(), 1);
    }

    #[test]
    fn remote_push_rejects_a_page_without_live_owner_association() {
        let mut page = Page::remote_free_test_unassociated();
        let page_raw = NonNull::from(&mut page);
        let mut block = TestBlock([0; 16]);
        let block_pointer = block.pointer();

        // SAFETY: this deliberately violates the live-owner precondition to
        // verify that the bounded protocol refuses the unsupported state.
        assert_eq!(unsafe { push(page_raw, block_pointer) }, Err(RemoteFreeError::NotOwnerAssociated));
    }

    #[test]
    fn remote_push_rejects_an_abandoned_page_even_if_the_old_theap_pointer_remains() {
        let mut page = Page::remote_free_test_page(1, 1);
        let page_raw = NonNull::from(&mut page);
        let mut block = TestBlock([0; 16]);
        let block_pointer = block.pointer();
        page.remote_free_test_mark_abandoned();

        // SAFETY: this intentionally supplies an unsupported abandoned page
        // to verify that the bounded protocol does not take the source's
        // ownership-claim/abandoned-collection branch.
        assert_eq!(unsafe { push(page_raw, block_pointer) }, Err(RemoteFreeError::NotOwnerAssociated));
    }

    /// A test-only sharing wrapper. Producers access only the `AtomicUsize`
    /// xthread head and their own block's first word; the owner touches the
    /// non-atomic page fields only after every scoped producer has joined.
    /// It is deliberately not a `Sync` implementation for `Page` itself.
    #[repr(transparent)]
    struct ConcurrentTestPage(Page);

    // SAFETY: see the type-level protocol above. This wrapper never exposes
    // mutable page access while producer threads are live.
    unsafe impl Sync for ConcurrentTestPage {}

    impl ConcurrentTestPage {
        fn page_pointer(&self) -> NonNull<Page> {
            // SAFETY: this derives a raw metadata address without creating a
            // `Page` reference. The test wrapper owns the stable stack slot.
            unsafe {
                NonNull::new_unchecked(core::ptr::addr_of!(self.0).cast_mut())
            }
        }
    }

    #[test]
    fn std_multi_producer_pushes_are_all_collected_once() {
        const PRODUCERS: usize = 8;
        const BLOCKS_PER_PRODUCER: usize = 64;
        const BLOCKS: usize = PRODUCERS * BLOCKS_PER_PRODUCER;

        let page = ConcurrentTestPage(Page::remote_free_test_page(BLOCKS as u16, BLOCKS));
        let mut blocks: [TestBlock; BLOCKS] = std::array::from_fn(|_| TestBlock([0; 16]));

        thread::scope(|scope| {
            for producer_blocks in blocks.chunks_mut(BLOCKS_PER_PRODUCER) {
                let page = &page;
                scope.spawn(move || {
                    for block in producer_blocks {
                        // SAFETY: the scoped owner keeps the page and every
                        // block live; each producer uniquely owns this block
                        // while it publishes it exactly once.
                        let block = block.pointer();
                        unsafe {
                            push(page.page_pointer(), block)
                                .expect("the live associated page stays publishable");
                        }
                    }
                });
            }
        });

        // SAFETY: all producers joined before the sole owner collects.
        assert_eq!(unsafe { collect(page.page_pointer()) }, Ok(BLOCKS));
        assert_eq!(page.0.remote_free_test_head(), 1);
        assert_eq!(page.0.remote_free_test_used(), 0);
        assert_eq!(page.0.remote_free_test_local_chain_len(BLOCKS + 1), BLOCKS);
    }

    #[test]
    fn owner_collection_races_a_producer_without_losing_or_double_collecting_blocks() {
        const BLOCKS: usize = 128;

        let page = ConcurrentTestPage(Page::remote_free_test_page(BLOCKS as u16, BLOCKS));
        let mut blocks: [TestBlock; BLOCKS] = std::array::from_fn(|_| TestBlock([0; 16]));
        let started = Barrier::new(2);
        let complete = AtomicBool::new(false);
        let mut collected = 0;

        thread::scope(|scope| {
            let page = &page;
            let started = &started;
            let complete = &complete;
            let producer_blocks = &mut blocks;
            scope.spawn(move || {
                // SAFETY: the page and every block remain pinned and live for
                // the full scope. This thread creates only the producer's
                // atomic-field projection and frees each block exactly once.
                unsafe {
                    push(page.page_pointer(), producer_blocks[0].pointer())
                        .expect("the first remote publication succeeds");
                }
                started.wait();
                for block in &mut producer_blocks[1..] {
                    // SAFETY: see the first publication above.
                    let block = block.pointer();
                    unsafe {
                        push(page.page_pointer(), block)
                            .expect("the associated page stays publishable");
                    }
                    thread::yield_now();
                }
                complete.store(true, Ordering::Release);
            });

            started.wait();
            while !complete.load(Ordering::Acquire) {
                // SAFETY: this is the sole owner. `collect` creates only its
                // atomic and direct local_free/used field projections; it
                // never creates a whole-page reference that aliases producer
                // access to the pinned page's atomic fields.
                collected += unsafe { collect(page.page_pointer()) }
                    .expect("owner collection preserves the live-page state");
                thread::yield_now();
            }
        });

        // SAFETY: scope join and the acquire completion observation ensure no
        // producer remains before this final owner collection.
        collected += unsafe { collect(page.page_pointer()) }
            .expect("final owner collection succeeds");
        assert_eq!(collected, BLOCKS);
        assert_eq!(page.0.remote_free_test_head(), 1);
        assert_eq!(page.0.remote_free_test_used(), 0);
        assert_eq!(page.0.remote_free_test_local_chain_len(BLOCKS + 1), BLOCKS);
    }
}
