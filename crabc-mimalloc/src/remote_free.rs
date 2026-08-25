// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/free.c:62-97,396-417`
// (`mi_free_block_mt` and `mi_abandoned_page_unown_from_free`) and `src/page.c:150-269`
// (`mi_page_thread_collect_to_local`, `mi_page_thread_free_collect`, and
// `_mi_page_free_collect_partly`), with
// the exact `mi_thread_free_t` low-bit representation from
// `include/mimalloc/types.h:388-418`.
//
// This bounded Milestone 5 slice handles remote push and owner collection for
// live owner-associated pages, plus the narrow `allow_collect=true` head
// transitions used by `abandoned`, including its expected-head unown tail.
// It deliberately excludes the separate `_mi_deferred_free` callback, general
// allocation/free routing, TLS/theap attachment, and general page retirement
// or release. `single_thread.rs` is the sole bounded consumer that follows a
// successful detach with false-force full-page collection, whose caller proves
// live producers are joined/quiescent before its queue transition. The
// explicit detached metadata branch has no remote producer path and does not
// call this module.
// `remote_free_loom.rs` separately models this module's
// exact head CAS transitions with Loom; it does not model page lifetime, raw
// block pointers, or owner-local mutation.

use core::ptr::{self, NonNull};

use crate::atomic::{
    AtomicWord, word_cas_weak_acq_rel, word_load_relaxed, word_or_acq_rel,
};
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
    /// `_mi_page_free_collect_partly` reached its last-head fast path but the
    /// atomic head no longer named the source-provided block. This is an
    /// invalid caller/concurrent-lifetime state; collection must retain the
    /// page rather than detach an unrelated list.
    PartialHeadMismatch,
}

/// Result of `mi_free_block_mt(..., allow_collect=true)` on an abandoned page.
///
/// A producer that changed an unowned word into an owned word has acquired the
/// source obligation to run the abandoned-page collection decision. The
/// bounded abandonment module owns that decision; a producer that found an
/// existing owner only published its block to that owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbandonedRemotePush {
    PublishedToExistingOwner,
    ClaimedUnownedPage,
}

/// Result of the source `mi_page_claim_ownership` low-bit transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AbandonedOwnerClaim {
    ClaimedUnowned,
    AlreadyOwned,
}

/// One atomic head observation from `mi_abandoned_page_unown`.
///
/// A nonempty owned word cannot be released: its current owner must collect
/// the returned remote head and then retry. `NotOwned` is a violated caller
/// invariant rather than a recoverable ownership transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AbandonedOwnerHeadTransition {
    Released,
    RemotePublished(ThreadFree),
    NotOwned,
}

/// One result of the source's expected-head release attempt in
/// `mi_abandoned_page_unown_from_free`.
///
/// Unlike [`AbandonedOwnerHeadTransition`], this preserves a known small-page
/// head when the first AcqRel CAS succeeds. A failed weak CAS leaves the
/// decision with an owned empty or nonempty word so `abandoned` can follow the
/// source's collect/free/reabandon loop without ever retrying reclamation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AbandonedExpectedHeadTransition {
    Released,
    OwnedEmpty,
    RemotePublished,
    NotOwned,
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
    let block = block.cast::<Block>();
    let block_address = block.as_ptr().expose_provenance();
    publish_to_head(word, block_address, |previous_block| {
        // SAFETY: the caller retains exclusive ownership of `block`; the
        // source normal-release profile stores its unencoded next pointer
        // before the release half of the publishing compare/exchange.
        unsafe { block_set_next(block, thread_free_block(previous_block)) };
    })
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

/// Publishes a remote free after a page has entered one of the source
/// abandoned identities.
///
/// This is `src/free.c:80-95` with `allow_collect=true`: unlike [`push`], its
/// successful CAS always writes the low owner bit. If the previous word was
/// unowned, the caller receives [`AbandonedRemotePush::ClaimedUnownedPage`]
/// and must immediately perform the source free/reclaim/re-abandon/unown
/// decision before it releases the page lifetime.
///
/// # Safety
///
/// `page` must remain initialized and live through the publication and any
/// resulting owner collection. It must be an abandoned page whose ordinary
/// metadata and remote blocks remain valid; `block` must be one aligned,
/// exclusively owned live allocation of that exact page and not previously
/// freed. A caller receiving `ClaimedUnownedPage` owns the page's ordinary
/// state until it transfers or releases the low owner bit according to the
/// abandoned-page protocol. This function creates no producer `&Page`.
pub(crate) unsafe fn push_abandoned(
    page: NonNull<Page>,
    block: NonNull<u8>,
) -> Result<AbandonedRemotePush, RemoteFreeError> {
    if block.as_ptr().addr() & THREAD_FREE_OWNED != 0 {
        return Err(RemoteFreeError::UnalignedBlock);
    }
    // SAFETY: caller supplies the stable initialized abandoned metadata.
    let state = unsafe { Page::remote_free_producer_state_at(page) };
    if !producer_has_abandoned_thread_identity(&state) {
        return Err(RemoteFreeError::NotOwnerAssociated);
    }
    // SAFETY: state names initialized atomic source fields only.
    let head = unsafe { state.xthread_free.as_ref() };
    let block = block.cast::<Block>();
    let block_address = block.as_ptr().expose_provenance();
    let was_owned = publish_to_head_with_owner(head, block_address, |_| true, |previous_block| {
        // SAFETY: caller retains exclusive ownership of this just-freed block
        // until the AcqRel head publication succeeds.
        unsafe { block_set_next(block, thread_free_block(previous_block)) };
    })?;
    Ok(if was_owned {
        AbandonedRemotePush::PublishedToExistingOwner
    } else {
        AbandonedRemotePush::ClaimedUnownedPage
    })
}

/// Collects an abandoned page's remote list after the caller has claimed its
/// low owner bit.
///
/// This is the same `page.c:150-201` list operation as [`collect`], but its
/// narrow raw projection permits the two abandoned `xthread_id` encodings and
/// deliberately never reads the source-stale `theap` pointer.
///
/// # Safety
///
/// `page` must remain live and abandoned with its low owner bit held by this
/// caller. The caller must be the sole writer of `used` and `local_free`, and
/// every published block must remain valid until the detached list is merged.
pub(crate) unsafe fn collect_abandoned(page: NonNull<Page>) -> Result<usize, RemoteFreeError> {
    // SAFETY: caller supplies abandoned ownership and metadata lifetime.
    let state = unsafe { Page::abandoned_remote_free_owner_state_at(page) }
        .ok_or(RemoteFreeError::NotOwnerAssociated)?;
    collect_state(state)
}

/// Collects the predecessor list of one just-published abandoned remote free.
///
/// This is the small-page `_mi_page_free_collect_partly` path from
/// `page.c:245-269`. It intentionally leaves `head` in `xthread_free` so the
/// caller can preserve `mi_abandoned_page_unown_from_free`'s expected-head
/// release fast path. If that head is the sole remaining used block, it uses
/// the ordinary atomic collector to make the all-free result exact.
///
/// # Safety
///
/// `page` must remain initialized and abandoned while this caller owns its
/// low `xthread_free` bit. `head` must be the exact aligned block that this
/// caller just published and must still be reachable from that owned atomic
/// list. The page metadata, every predecessor block, and every owner-local
/// free-list field must remain live and exclusively mutable by this caller
/// until the operation finishes. Other producers may retain only their
/// atomic page projection and may not access a predecessor after this method
/// detaches it from `head`. The caller must also have established the source
/// small-page geometry invariant, `reserved >= 16`.
pub(crate) unsafe fn collect_abandoned_partly(
    page: NonNull<Page>,
    head: NonNull<u8>,
) -> Result<usize, RemoteFreeError> {
    if head.as_ptr().addr() & THREAD_FREE_OWNED != 0 {
        return Err(RemoteFreeError::UnalignedBlock);
    }
    // SAFETY: caller supplies the abandoned owner/lifetime proof. This names
    // only the owner-owned source fields needed by the partial collector.
    let state = unsafe { Page::abandoned_remote_free_owner_state_at(page) }
        .ok_or(RemoteFreeError::NotOwnerAssociated)?;
    // SAFETY: the caller proves `head` is one exact source block in this
    // page's atomic remote list.
    unsafe { collect_partly_state(state, head.cast()) }
}

fn collect_state(state: PageRemoteFreeOwnerState) -> Result<usize, RemoteFreeError> {
    // SAFETY: state construction proved this is the initialized page atomic.
    let xthread_free = unsafe { state.xthread_free.as_ref() };
    let detached = detach_from_head(xthread_free)?;
    let Some(head) = NonNull::new(thread_free_block(detached)) else {
        return Ok(0);
    };
    // SAFETY: a successful AcqRel detach synchronizes with every producer's
    // release publication in the captured list. The caller of `collect`
    // supplied the sole owner proof for non-atomic page fields and each
    // source-shaped unencoded block link.
    unsafe { collect_detached_to_local(state, head) }
}

/// Source `_mi_page_free_collect_partly` under a caller-held abandoned owner
/// bit. It only severs the supplied head from its predecessor list; the head
/// remains atomically reachable until the source's later unown transition.
unsafe fn collect_partly_state(
    state: PageRemoteFreeOwnerState,
    head: NonNull<Block>,
) -> Result<usize, RemoteFreeError> {
    // SAFETY: caller proves `head` is a valid source block and the low owner
    // bit excludes ordinary-field mutation by another owner.
    let next = unsafe { block_next(head) };
    let mut collected = 0;
    if let Some(next) = NonNull::new(next) {
        // SAFETY: the source leaves its just-published head in the atomic
        // list but detaches its already-linked predecessor chain before it
        // moves that chain into owner-local state.
        unsafe { block_set_next(head, ptr::null_mut()) };
        // SAFETY: `next` is now detached from the remote head and the caller
        // owns every affected ordinary field through the low owner bit.
        collected = unsafe { collect_detached_to_local(state, next) }?;
        // `_mi_page_free_collect_partly` performs the ordinary non-force
        // local transfer immediately after consuming predecessor blocks.
        move_local_to_free_if_empty(state);
    }

    // When only the supplied head remains used, source assertions prove it is
    // still the atomic head and has no predecessor. Validate those facts at
    // the Rust raw boundary before the final atomic collect.
    if unsafe { *state.used.as_ptr() } == 1 {
        let observed = word_load_relaxed(unsafe { state.xthread_free.as_ref() });
        if !is_owned(observed)
            || thread_free_block_address(observed) != head.as_ptr().addr()
            || !unsafe { block_next(head) }.is_null()
        {
            return Err(RemoteFreeError::PartialHeadMismatch);
        }
        // SAFETY: the validated final head remains atomically reachable; the
        // ordinary collector detaches it with the source AcqRel CAS and
        // accounts the final used block exactly.
        collected += collect_state(state)?;
        move_local_to_free_if_empty(state);
    }
    Ok(collected)
}

/// The non-force local portion of `_mi_page_free_collect` used by the
/// partial collector. It moves the owner-local list only when `free` remains
/// empty; it deliberately does not append to an existing free list.
fn move_local_to_free_if_empty(state: PageRemoteFreeOwnerState) {
    // SAFETY: the caller holds the low owner bit and this raw state projects
    // exactly the source fields that the collection routine owns.
    unsafe {
        let local_free = *state.local_free.as_ptr();
        if !local_free.is_null() && (*state.free.as_ptr()).is_null() {
            *state.free.as_ptr() = local_free;
            *state.local_free.as_ptr() = ptr::null_mut();
            *state.free_is_zero.as_ptr() = false;
        }
    }
}

/// The narrow atomic boundary for the `mi_thread_free_t` head only.
///
/// The production implementation is `AtomicUsize`; the test-only Loom model
/// implements this exact two-operation boundary for `loom::AtomicUsize`.
/// No allocator data structure is generic over atomics, and the model cannot
/// enter a production build.
trait ThreadFreeHead {
    fn load_relaxed(&self) -> ThreadFree;

    fn cas_weak_acq_rel(&self, expected: &mut ThreadFree, replacement: ThreadFree) -> bool;

    fn fetch_or_acq_rel(&self, value: ThreadFree) -> ThreadFree;
}

impl ThreadFreeHead for AtomicWord {
    #[inline]
    fn load_relaxed(&self) -> ThreadFree {
        word_load_relaxed(self)
    }

    #[inline]
    fn cas_weak_acq_rel(&self, expected: &mut ThreadFree, replacement: ThreadFree) -> bool {
        word_cas_weak_acq_rel(self, expected, replacement)
    }

    #[inline]
    fn fetch_or_acq_rel(&self, value: ThreadFree) -> ThreadFree {
        word_or_acq_rel(self, value)
    }
}

/// Claims an abandoned page's low owner bit with the exact source AcqRel OR.
///
/// This is the atomic half of `mi_page_claim_ownership`. Bitmap disposition
/// remains with `abandoned`: a failed bitmap reader must restore its bit.
pub(super) fn claim_abandoned_owner(head: &AtomicWord) -> AbandonedOwnerClaim {
    claim_abandoned_owner_with(head)
}

fn claim_abandoned_owner_with<H>(head: &H) -> AbandonedOwnerClaim
where
    H: ThreadFreeHead + ?Sized,
{
    if is_owned(head.fetch_or_acq_rel(THREAD_FREE_OWNED)) {
        AbandonedOwnerClaim::AlreadyOwned
    } else {
        AbandonedOwnerClaim::ClaimedUnowned
    }
}

/// Observes or releases one abandoned owner head using the source CAS loop.
///
/// The optional hook is empty in production. The bounded deterministic test
/// uses it at the source interleaving point after observing an empty owned
/// head and before attempting to clear ownership.
pub(super) fn try_unown_abandoned_head<F>(
    head: &AtomicWord,
    before_release_cas: &mut Option<F>,
) -> AbandonedOwnerHeadTransition
where
    F: FnOnce(),
{
    try_unown_abandoned_head_with(head, before_release_cas)
}

/// Attempts the first `mi_abandoned_page_unown_from_free` transition:
/// `(expected_block | owned) -> expected_block`.
///
/// The caller supplies the source-captured block address (or zero after a
/// full collector). A success transfers the low owner bit while retaining that
/// exact small-page block in the atomic list. On a weak-CAS miss this reports
/// only whether the observed owned list needs collection; source policy stays
/// in `abandoned.rs` so it can decide terminal release or reabandonment.
pub(super) fn try_unown_abandoned_expected_head<F>(
    head: &AtomicWord,
    expected_block: ThreadFree,
    before_release_cas: &mut Option<F>,
) -> Result<AbandonedExpectedHeadTransition, RemoteFreeError>
where
    F: FnOnce(),
{
    try_unown_abandoned_expected_head_with(head, expected_block, before_release_cas)
}

fn try_unown_abandoned_head_with<H, F>(
    head: &H,
    before_release_cas: &mut Option<F>,
) -> AbandonedOwnerHeadTransition
where
    H: ThreadFreeHead + ?Sized,
    F: FnOnce(),
{
    let mut previous = head.load_relaxed();
    loop {
        if !is_owned(previous) {
            return AbandonedOwnerHeadTransition::NotOwned;
        }
        if thread_free_block_address(previous) != 0 {
            return AbandonedOwnerHeadTransition::RemotePublished(previous);
        }
        if let Some(before_release_cas) = before_release_cas.take() {
            before_release_cas();
        }
        let mut expected = previous;
        if head.cas_weak_acq_rel(&mut expected, 0) {
            return AbandonedOwnerHeadTransition::Released;
        }
        // Acquire failure observation is either a spurious retry or a remote
        // publisher's nonempty owned word. The next iteration distinguishes
        // those states without losing the collection obligation.
        previous = expected;
    }
}

fn try_unown_abandoned_expected_head_with<H, F>(
    head: &H,
    expected_block: ThreadFree,
    before_release_cas: &mut Option<F>,
) -> Result<AbandonedExpectedHeadTransition, RemoteFreeError>
where
    H: ThreadFreeHead + ?Sized,
    F: FnOnce(),
{
    let expected = thread_free_create_address(expected_block, true)?;
    let replacement = thread_free_create_address(expected_block, false)?;
    if let Some(before_release_cas) = before_release_cas.take() {
        before_release_cas();
    }
    let mut observed = expected;
    if head.cas_weak_acq_rel(&mut observed, replacement) {
        return Ok(AbandonedExpectedHeadTransition::Released);
    }
    if !is_owned(observed) {
        return Ok(AbandonedExpectedHeadTransition::NotOwned);
    }
    if thread_free_block_address(observed) == 0 {
        Ok(AbandonedExpectedHeadTransition::OwnedEmpty)
    } else {
        Ok(AbandonedExpectedHeadTransition::RemotePublished)
    }
}

/// The source `mi_free_block_mt` head publication loop, factored only at its
/// atomic boundary so the test-only Loom model executes the exact production
/// load/CAS transition and ordering pair. `set_next` is the source store to
/// the producer-owned block's first word and runs again after each failed CAS.
fn publish_to_head<H, F>(
    head: &H,
    block: ThreadFree,
    set_next: F,
) -> Result<(), RemoteFreeError>
where
    H: ThreadFreeHead + ?Sized,
    F: FnMut(ThreadFree),
{
    publish_to_head_with_owner(head, block, is_owned, set_next).map(|_| ())
}

/// Shared source `mi_free_block_mt` head publication loop.
///
/// `owner_after_publication` is the sole semantic difference between an
/// associated-page remote free (preserve the old low bit) and an
/// `allow_collect=true` abandoned free (always set it). Returning the low-bit
/// state of the successfully replaced word lets the latter identify the
/// source ownership claim without duplicating any CAS transition. The Loom
/// model continues to execute [`publish_to_head`]'s preserve-owner form; a
/// later abandoned model can exercise this exact policy parameter as well.
fn publish_to_head_with_owner<H, O, F>(
    head: &H,
    block: ThreadFree,
    owner_after_publication: O,
    mut set_next: F,
) -> Result<bool, RemoteFreeError>
where
    H: ThreadFreeHead + ?Sized,
    O: Fn(ThreadFree) -> bool,
    F: FnMut(ThreadFree),
{
    if block & THREAD_FREE_OWNED != 0 {
        return Err(RemoteFreeError::UnalignedBlock);
    }

    let mut previous = head.load_relaxed();
    loop {
        if !is_owned(previous) {
            // A normal associated-page publisher must retain an owner, but
            // an abandoned `allow_collect` publisher is intentionally allowed
            // to take it. The policy sees the exact source old word.
            if !owner_after_publication(previous) {
                return Err(RemoteFreeError::NotOwnerAssociated);
            }
        }
        set_next(thread_free_block_address(previous));
        let replacement = thread_free_create_address(block, owner_after_publication(previous))
            .expect("the checked block alignment preserves the low owner bit");
        if head.cas_weak_acq_rel(&mut previous, replacement) {
            return Ok(is_owned(previous));
        }
    }
}

/// The source owner-side `mi_page_thread_free_collect` head detach loop.
///
/// The returned word retains the low owner bit. A zero block portion means
/// the source fast path found no remote list and therefore performed no CAS.
/// The Loom model calls this same function and validates that every observed
/// detached word preserves ownership across producer publication races.
fn detach_from_head<H>(head: &H) -> Result<ThreadFree, RemoteFreeError>
where
    H: ThreadFreeHead + ?Sized,
{
    let mut previous = head.load_relaxed();
    loop {
        if !is_owned(previous) {
            return Err(RemoteFreeError::NotOwnerAssociated);
        }
        if thread_free_block_address(previous) == 0 {
            return Ok(previous);
        }
        let replacement = thread_free_create_address(0, is_owned(previous))
            .expect("a null thread-free head always preserves its owner bit");
        if head.cas_weak_acq_rel(&mut previous, replacement) {
            return Ok(previous);
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
fn producer_has_abandoned_thread_identity(state: &PageRemoteFreeProducerState) -> bool {
    // SAFETY: producer state contains only initialized atomic subobjects.
    let thread_id = unsafe { state.xthread_id.as_ref() }
        .load(core::sync::atomic::Ordering::Acquire)
        & !PAGE_FLAG_MASK;
    thread_id == THREAD_ID_ABANDONED || thread_id == THREAD_ID_ABANDONED_MAPPED
}

#[inline]
fn thread_free_block(thread_free: ThreadFree) -> *mut Block {
    // `mi_thread_free_t` stores a pointer in all bits except the low owner
    // bit. `expose_provenance` recorded that provenance when publishing; this
    // restores it after atomically loading the exact C word representation.
    core::ptr::with_exposed_provenance_mut(thread_free_block_address(thread_free))
}

#[inline]
const fn thread_free_block_address(thread_free: ThreadFree) -> ThreadFree {
    thread_free & THREAD_FREE_BLOCK_MASK
}

#[inline]
fn thread_free_create_address(
    address: ThreadFree,
    owned: bool,
) -> Result<ThreadFree, RemoteFreeError> {
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
    fn abandoned_partly_collection_keeps_its_head_atomic_and_moves_prior_frees() {
        // The pinned source uses this path only for small pages, which have
        // at least sixteen reserved blocks. The newest remote block remains
        // in `xthread_free`; only its already-linked predecessor moves to the
        // ordinary free list without an atomic detach.
        let mut page = Page::remote_free_test_page(16, 3);
        let page_raw = NonNull::from(&mut page);
        page.remote_free_test_mark_abandoned();
        let mut first = TestBlock([0; 16]);
        let mut head = TestBlock([0; 16]);
        let first_pointer = first.pointer();
        let head_pointer = head.pointer();

        assert_eq!(
            unsafe { push_abandoned(page_raw, first_pointer) },
            Ok(AbandonedRemotePush::PublishedToExistingOwner)
        );
        assert_eq!(
            unsafe { push_abandoned(page_raw, head_pointer) },
            Ok(AbandonedRemotePush::PublishedToExistingOwner)
        );

        assert_eq!(
            unsafe { collect_abandoned_partly(page_raw, head_pointer) },
            Ok(1)
        );
        assert_eq!(page.remote_free_test_head(), head_pointer.as_ptr().addr() | 1);
        assert_eq!(page.remote_free_test_used(), 2);
        assert_eq!(page.remote_free_test_free(), first_pointer.cast::<Block>().as_ptr());
        assert!(page.remote_free_test_local_free().is_null());
        assert!(!page.remote_free_test_free_is_zero());
    }

    #[test]
    fn abandoned_partly_collection_detaches_its_last_head_when_the_page_becomes_empty() {
        let mut page = Page::remote_free_test_page(16, 1);
        let page_raw = NonNull::from(&mut page);
        page.remote_free_test_mark_abandoned();
        let mut head = TestBlock([0; 16]);
        let head_pointer = head.pointer();

        assert_eq!(
            unsafe { push_abandoned(page_raw, head_pointer) },
            Ok(AbandonedRemotePush::PublishedToExistingOwner)
        );
        assert_eq!(
            unsafe { collect_abandoned_partly(page_raw, head_pointer) },
            Ok(1)
        );
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.remote_free_test_used(), 0);
        assert_eq!(page.remote_free_test_free(), head_pointer.cast::<Block>().as_ptr());
        assert!(page.remote_free_test_local_free().is_null());
        assert!(!page.remote_free_test_free_is_zero());
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

    /// Emits the fixed, address-independent native x86-64 differential
    /// record for the live-owner `mi_free_block_mt` publication and
    /// `mi_page_thread_free_collect` merge.  The matching pinned-C probe
    /// creates its two publications through one quiescent `pthread` and then
    /// calls the private owner collector; this test uses the same stable
    /// two-block protocol under the test-only scoped sharing proof.
    ///
    /// It deliberately does not exercise public allocation routing,
    /// abandoned-page ownership, page retirement, or thread teardown.  The
    /// test page remains live and owner-associated until its worker joins and
    /// the sole owner has completed the collection.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_64_live_owner_remote_free_trace_matches_pinned_c_protocol() {
        const PRODUCER_COUNT: usize = 2;
        let page = ConcurrentTestPage(Page::remote_free_test_page(4, PRODUCER_COUNT));
        let mut blocks = [TestBlock([0; 16]), TestBlock([0; 16])];

        let initial_head = page.0.remote_free_test_head();
        let initial_used = page.0.remote_free_test_used();
        // SAFETY: the test wrapper owns this initialized page for the whole
        // scoped protocol and this read projects only its atomic producer
        // fields before any worker starts.
        let initial_producer_state = unsafe { Page::remote_free_producer_state_at(page.page_pointer()) };
        let initial_live_owner_associated = producer_has_live_thread_identity(&initial_producer_state);
        let initial_remote_count = usize::from(!thread_free_block(initial_head).is_null());
        assert_eq!(initial_head, 1, "the test page begins owner-marked and empty");
        assert_eq!(initial_used, PRODUCER_COUNT);
        assert!(initial_live_owner_associated);
        assert_eq!(initial_remote_count, 0);

        // The worker owns only its two blocks and the remote atomic
        // projection.  It completes both publications before the owner
        // derives any owner-only list or accounting projection.
        thread::scope(|scope| {
            let page = &page;
            let worker_blocks = &mut blocks;
            scope.spawn(move || {
                let first = worker_blocks[0].pointer();
                let second = worker_blocks[1].pointer();
                // SAFETY: the scoped owner pins the test page and both blocks
                // for this entire worker lifetime; each block is published
                // exactly once and no owner-local field is touched here.
                unsafe {
                    push(page.page_pointer(), first)
                        .expect("the first live-owner remote publication succeeds");
                    push(page.page_pointer(), second)
                        .expect("the second live-owner remote publication succeeds");
                }
            });
        });

        let first = blocks[0].pointer();
        let second = blocks[1].pointer();
        let published_head = page.0.remote_free_test_head();
        let published_head_block = NonNull::new(thread_free_block(published_head))
            .expect("both worker publications leave a nonempty remote head");
        // SAFETY: the two joined worker publications initialized this exact
        // source-format list before their release CAS operations.
        let published_predecessor = unsafe { block_next(published_head_block) };
        let published_first_link = NonNull::new(published_predecessor)
            .expect("the newest publication links to the first publication");
        // SAFETY: the first worker block is the terminal source-format node.
        let published_tail_is_empty = unsafe { block_next(published_first_link) }.is_null();
        let published_remote_count = 1 + usize::from(!published_predecessor.is_null());
        let published_head_is_latest = published_head_block.as_ptr().cast::<u8>() == second.as_ptr();
        let published_latest_predecessor_is_first = published_predecessor.cast::<u8>() == first.as_ptr();
        let published_nonempty = !thread_free_block(published_head).is_null();
        let published_used_unchanged = page.0.remote_free_test_used() == initial_used;
        let published_actual_live_count = page
            .0
            .remote_free_test_used()
            .checked_sub(published_remote_count)
            .expect("the detached remote count cannot exceed source used accounting");

        assert_eq!(published_head & 1, 1, "publication retains the owner bit");
        assert!(published_head_is_latest);
        assert!(published_latest_predecessor_is_first);
        assert!(published_tail_is_empty);
        assert!(published_nonempty);
        assert_eq!(published_remote_count, PRODUCER_COUNT);
        assert!(published_used_unchanged);
        assert_eq!(published_actual_live_count, 0);

        // SAFETY: the worker joined, this is the sole live owner, and the
        // test page plus both published blocks stay valid until this exact
        // detach-and-local-merge completes.
        let collected_count = unsafe { collect(page.page_pointer()) }
            .expect("owner collection preserves the live-page protocol");
        let collected_head = page.0.remote_free_test_head();
        let collected_local = NonNull::new(page.0.remote_free_test_local_free())
            .expect("the collected two-block list becomes local_free");
        // SAFETY: collection made this bounded local list owner-only.
        let collected_predecessor = unsafe { block_next(collected_local) };
        let collected_first_link = NonNull::new(collected_predecessor)
            .expect("the collected local list retains both publications");
        // SAFETY: the first publication remains the terminal local node.
        let collected_tail_is_empty = unsafe { block_next(collected_first_link) }.is_null();
        let collected_local_count = 1 + usize::from(!collected_predecessor.is_null());
        let collected_lifo = collected_local.as_ptr().cast::<u8>() == second.as_ptr()
            && collected_predecessor.cast::<u8>() == first.as_ptr()
            && collected_tail_is_empty;
        let collected_head_owned = collected_head & 1 == 1;
        let collected_head_empty = thread_free_block(collected_head).is_null();
        let post_collect_remote_count = usize::from(!thread_free_block(collected_head).is_null());
        let list_cycle_free = published_tail_is_empty && collected_tail_is_empty;
        let valid = page.0.remote_free_test_used() == 0
            && collected_count == PRODUCER_COUNT
            && collected_head_owned
            && collected_head_empty
            && collected_local_count == PRODUCER_COUNT
            && collected_lifo
            && list_cycle_free;

        assert!(valid, "the bounded owner collection must preserve every trace invariant");

        std::println!("CRABC_MI_LIVE_OWNER_REMOTE_FREE_TRACE_BEGIN");
        std::println!("trace.live_owner_remote.producer_count={PRODUCER_COUNT}");
        std::println!("trace.live_owner_remote.same_page=1");
        std::println!(
            "trace.live_owner_remote.initial_live_owner_associated={}",
            u8::from(initial_live_owner_associated),
        );
        std::println!("trace.live_owner_remote.initial_used={initial_used}");
        std::println!(
            "trace.live_owner_remote.initial_capacity_ge_used={}",
            u8::from(4 >= initial_used),
        );
        std::println!(
            "trace.live_owner_remote.initial_head_owned={}",
            u8::from(initial_head & 1 == 1),
        );
        std::println!(
            "trace.live_owner_remote.initial_head_empty={}",
            u8::from(thread_free_block(initial_head).is_null()),
        );
        std::println!("trace.live_owner_remote.initial_remote_count={initial_remote_count}");
        std::println!(
            "trace.live_owner_remote.published_used_unchanged={}",
            u8::from(published_used_unchanged),
        );
        std::println!(
            "trace.live_owner_remote.published_head_owned={}",
            u8::from(published_head & 1 == 1),
        );
        std::println!(
            "trace.live_owner_remote.published_head_is_latest={}",
            u8::from(published_head_is_latest),
        );
        std::println!(
            "trace.live_owner_remote.published_latest_predecessor_is_first={}",
            u8::from(published_latest_predecessor_is_first),
        );
        std::println!(
            "trace.live_owner_remote.published_nonempty={}",
            u8::from(published_nonempty),
        );
        std::println!(
            "trace.live_owner_remote.published_remote_count={published_remote_count}",
        );
        std::println!(
            "trace.live_owner_remote.post_join_remote_count={published_remote_count}",
        );
        std::println!(
            "trace.live_owner_remote.published_actual_live_count={published_actual_live_count}",
        );
        std::println!("trace.live_owner_remote.collected_count={collected_count}");
        std::println!(
            "trace.live_owner_remote.collected_used={}",
            page.0.remote_free_test_used(),
        );
        std::println!(
            "trace.live_owner_remote.collected_head_owned={}",
            u8::from(collected_head_owned),
        );
        std::println!(
            "trace.live_owner_remote.collected_head_empty={}",
            u8::from(collected_head_empty),
        );
        std::println!(
            "trace.live_owner_remote.post_collect_remote_count={post_collect_remote_count}",
        );
        std::println!(
            "trace.live_owner_remote.collected_local_count={collected_local_count}",
        );
        std::println!("trace.live_owner_remote.collected_lifo={}", u8::from(collected_lifo));
        std::println!("trace.live_owner_remote.list_cycle_free={}", u8::from(list_cycle_free));
        std::println!("trace.live_owner_remote.valid={}", u8::from(valid));
        std::println!("CRABC_MI_LIVE_OWNER_REMOTE_FREE_TRACE_END");
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

#[cfg(all(test, feature = "loom"))]
#[path = "remote_free_loom.rs"]
mod loom_tests;
