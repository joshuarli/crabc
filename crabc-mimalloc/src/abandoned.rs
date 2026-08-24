// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page.c:276-302`,
// `src/arena.c:631-671,725-778,1304-1355`, `src/free.c:372-514`, and
// `include/mimalloc/internal.h:1008-1039,1111-1119`.
//
// This Milestone 5 substrate models only the transition of one live page
// between an owner and an abandoned arena-map entry. It deliberately excludes
// allocation/free routing, queues, TLS/theap registration, terminal page
// release, and metadata reuse.

use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;

use crate::arena::ArenaAbandonedPages;
use crate::atomic::{word_cas_weak_release, word_load_relaxed};
use crate::bitmap::AbandonedBitmapClaim;
use crate::config::ARENA_BIN_COUNT;
use crate::remote_free::{
    self, AbandonedOwnerClaim, AbandonedOwnerHeadTransition, RemoteFreeError,
};
use crate::size_class;
use crate::types::{
    LiveThreadId, MemoryId, MemoryKind, Page, PageAbandonmentState, Theap, PAGE_FLAG_MASK,
    THREAD_ID_ABANDONED, THREAD_ID_ABANDONED_MAPPED,
};

const THREAD_FREE_OWNED: usize = 1;

/// One exact `pages_abandoned[bin]` image selected by its owning arena-page
/// lifecycle.
///
/// The source protocol is indifferent to whether the image lives in an
/// arena's main pages record or in a non-main Heap's `mi_arena_pages_t`. This
/// deliberately small capability keeps that choice at the owner boundary:
/// callers can publish, claim, and quiescently clear only the bin and arena
/// slice the capability already proved. It is not a general bitmap view.
pub(crate) trait MappedAbandonedPages {
    fn bin(&self) -> usize;
    fn page_slice_index(&self, memory: MemoryId) -> Option<usize>;
    /// Checks the one source bit before identity publication. A false result
    /// is a pre-mutation invalid-owner state, never permission to overwrite a
    /// concurrent abandoned page.
    fn is_clear(&self, slice_index: usize) -> bool;
    fn publish(&self, slice_index: usize) -> bool;
    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim;
    fn clear_once_set(&self, slice_index: usize) -> bool;
    /// Completes `arena.c:1405-1408` after the caller has cleared the
    /// page's mapped-abandoned identity. Main-arena images have no
    /// heap-local counter; a dynamic Heap capability consumes its paired
    /// `heap->abandoned_count[bin]` here, rather than while the bit is still
    /// visible.
    fn decrement_after_identity_clear(&self) -> bool;
}

/// Result of the bitmap-low-bit part of mapped abandonment adoption.
///
/// A dynamic owner can clear the source bit but fail to consume its exact
/// paired Heap counter. That is already a post-claim state: callers must keep
/// the claimed page terminally rather than treat it as an ordinary miss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappedAbandonedClaim {
    None,
    Claimed(usize),
    CountDecrementFailed(usize),
}

impl MappedAbandonedPages for ArenaAbandonedPages<'_> {
    #[inline]
    fn bin(&self) -> usize { self.bin() }

    #[inline]
    fn page_slice_index(&self, memory: MemoryId) -> Option<usize> {
        self.page_slice_index(memory)
    }

    #[inline]
    fn is_clear(&self, slice_index: usize) -> bool {
        self.bitmap_is_clear(slice_index)
    }

    #[inline]
    fn publish(&self, slice_index: usize) -> bool { self.publish(slice_index) }

    #[inline]
    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        match self.try_claim(thread_sequence, claim) {
            Some(slice_index) => MappedAbandonedClaim::Claimed(slice_index),
            None => MappedAbandonedClaim::None,
        }
    }

    #[inline]
    fn clear_once_set(&self, slice_index: usize) -> bool {
        self.clear_once_set(slice_index)
    }

    #[inline]
    fn decrement_after_identity_clear(&self) -> bool { true }
}

/// The bounded abandonment protocol refused an invalid source-state handoff.
///
/// Every error leaves page lifetime with its caller; none invents a fallback
/// that would release or reuse metadata while a producer or bitmap reader can
/// still reach it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbandonError {
    NotOwnedAssociated,
    NotAbandoned,
    MissingMappedArenaBitmap,
    ArenaBitmapDoesNotMatchPage,
    BitmapQuiescenceFailed,
    MappedBitAlreadyPublished,
    MappedPublicationFailed,
    AbandonedCountDecrementFailed,
    InvalidPageGeometry,
    RemoteFree(RemoteFreeError),
}

/// Result of abandoning one page without performing terminal page release.
///
/// `Empty` retains the low owner bit exactly until a later page-release slice
/// consumes the page. This makes the current absence of metadata reuse
/// explicit instead of treating an empty page as safely reusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbandonResult {
    Empty,
    UnownedMapped,
    UnownedUnmapped,
}

/// One successfully claimed mapped-abandoned page reassociated with a new
/// owner. It carries no destructor: queue insertion and page lifetime remain
/// later source slices.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AdoptedPage {
    page: NonNull<Page>,
    collected_remote_blocks: usize,
}

/// A source bitmap claim that crossed the low-owner boundary but could not
/// finish reassociation. Its raw page stays with the caller's consuming
/// terminal owner; the bitmap bit is intentionally still clear and retrying
/// would fabricate a second owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetainedAdoptFailure {
    page: NonNull<Page>,
    error: AbandonError,
}

impl RetainedAdoptFailure {
    #[inline]
    pub(crate) const fn page(self) -> NonNull<Page> { self.page }

    #[inline]
    pub(crate) const fn error(self) -> AbandonError { self.error }
}

impl AdoptedPage {
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> {
        self.page
    }

    #[inline]
    pub(crate) const fn collected_remote_blocks(&self) -> usize {
        self.collected_remote_blocks
    }
}

/// Ports `page.c:_mi_page_abandon` and the mapped/unmapped publication half
/// of `arena.c:_mi_arenas_page_abandon` for one already queue-detached page.
///
/// A regular arena page becomes `ABANDONED_MAPPED`, publishes exactly one bit,
/// and only then releases the low `xthread_free` ownership bit. Full,
/// singleton, and non-arena pages retain the ordinary `ABANDONED` identity and
/// are not published into an arena bitmap. Empty pages are deliberately
/// returned as [`AbandonResult::Empty`] rather than released because terminal
/// free/reuse is outside this bounded slice.
///
/// # Safety
///
/// `page` must be initialized, live, queue-detached, and uniquely owned by
/// this caller through entry. Its `theap` pointer, memory provenance, and all
/// block metadata must remain live through the transition. Remote producers
/// may retain only their atomic source projection and each must eventually be
/// collected or become the next low-bit owner. When `map` is supplied, it must
/// be the initialized source `pages_abandoned[bin]` map capability for this
/// page's exact live arena, whether it is the arena main image or one bound
/// non-main Heap image; no page metadata may be released or reused while the
/// returned state can be observed.
pub(crate) unsafe fn abandon<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    map: Option<&M>,
) -> Result<AbandonResult, AbandonError> {
    // SAFETY: caller supplies the owner/lifetime proof for the pre-abandon
    // collection. It validates the live associated identity before ordinary
    // local state is touched.
    unsafe { remote_free::collect(page) }.map_err(AbandonError::RemoteFree)?;
    // SAFETY: caller retains the page lifecycle proof and has collected the
    // pre-abandon remote list. This projects raw fields only.
    unsafe { abandon_after_collect(page, map) }
}

/// The identity/publication half of [`abandon`] after the caller has already
/// performed exact false-force collection.
///
/// This lets the page engine retain source order (`remote` then `local`, then
/// queue detach, then arena-map publication) without re-running the remote
/// detach through the older stand-alone substrate.
///
/// # Safety
///
/// `page` has the same stable, uniquely owned, queue-detached lifecycle proof
/// as [`abandon`], and the caller has just completed the false-force local
/// collection. No raw page lease may be released or repurposed through this
/// transition.
pub(crate) unsafe fn abandon_after_collect<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    map: Option<&M>,
) -> Result<AbandonResult, AbandonError> {
    // SAFETY: caller retains the page lifecycle proof and has collected the
    // pre-abandon remote list. This projects raw fields only.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || !is_live_associated(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved == 0 || state.block_size == 0 {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if page_is_empty(&state) {
        return Ok(AbandonResult::Empty);
    }

    // `arena.c` computes a size-class bin before it publishes. The main
    // abandoned map deliberately ends at `MI_MAX_SINGLETON_BIN`: partially
    // used arena singleton/huge-bin pages are left unmapped for a free to
    // reclaim, just like non-arena and full pages.
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    let mapped_bin = (!page_is_full(&state) && state.memid.kind() == MemoryKind::Arena)
        .then_some(bin)
        .filter(|&bin| bin < ARENA_BIN_COUNT);
    let mapped_slice = if let Some(bin) = mapped_bin {
        let map = map.ok_or(AbandonError::MissingMappedArenaBitmap)?;
        if bin != map.bin() {
            return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
        }
        let slice_index = map
            .page_slice_index(state.memid)
            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)?;
        if !map.is_clear(slice_index) {
            return Err(AbandonError::MappedBitAlreadyPublished);
        }
        Some((map, slice_index))
    } else {
        None
    };

    set_abandoned_identity(&state);
    if let Some((map, slice_index)) = mapped_slice {
        // Source order is significant: readers can only use a published bit
        // after the mapped abandoned identity exists.
        unsafe { state.xthread_id.as_ref() }
            .fetch_or(THREAD_ID_ABANDONED_MAPPED, Ordering::Relaxed);
        if !map.publish(slice_index) {
            // The identity has already changed. Callers must retain this as
            // terminal rather than retrying from a fictionally live page.
            return Err(AbandonError::MappedPublicationFailed);
        }
    }
    unown(page, map)
}

/// Searches one source `pages_abandoned[bin]` map and claims/reassociates the
/// first resolver-provided page that remains mapped-abandoned and unowned.
///
/// The resolver is intentionally explicit so each arena-page owner supplies
/// its own exact slice-to-metadata boundary. It must resolve an exact bitmap
/// slice to its stable `Page` metadata. On a failed low-bit ownership claim,
/// the shared bitmap primitive restores the bit before returning, which is
/// the required `arena.c:655-671` quiescence handoff to a concurrent
/// `unabandon`.
///
/// # Safety
///
/// `target_theap` and every page yielded by `resolve` must remain initialized
/// and address-stable. `target_thread` must be the live identity of
/// `target_theap`. Each resolved page must be live mapped-abandoned metadata
/// for that exact map slice; the caller must ensure it cannot be released or
/// reused while the map reader or returned [`AdoptedPage`] exists. No resolver
/// may create a `&mut Page` concurrent with a producer atomic projection.
#[cfg(test)]
unsafe fn try_adopt<M: MappedAbandonedPages + ?Sized, F>(
    map: &M,
    thread_sequence: usize,
    target_theap: NonNull<Theap>,
    target_thread: LiveThreadId,
    resolve: F,
) -> Result<Option<AdoptedPage>, AbandonError>
where
    F: FnMut(usize) -> Option<NonNull<Page>>,
{
    unsafe {
        try_adopt_with(
            map,
            thread_sequence,
            target_theap,
            target_thread,
            resolve,
            || {},
            || {},
        )
    }
}

/// Retained-error form of [`try_adopt`] for a consuming page-engine handoff.
///
/// Unlike the earlier substrate helper, a failure after successful bitmap/low
/// owner claim is not compressed into a bare error: its caller must retain the
/// exact page until an explicit later terminal policy exists.
pub(crate) unsafe fn try_adopt_retained<M: MappedAbandonedPages + ?Sized, F>(
    map: &M,
    thread_sequence: usize,
    target_theap: NonNull<Theap>,
    target_thread: LiveThreadId,
    mut resolve: F,
) -> Result<Option<AdoptedPage>, RetainedAdoptFailure>
where
    F: FnMut(usize) -> Option<NonNull<Page>>,
{
    let mut claimed_page = None;
    let claimed = map.try_claim(thread_sequence, |slice_index| {
        let Some(page) = resolve(slice_index) else {
            return AbandonedBitmapClaim::KeepSet;
        };
        // SAFETY: resolver proves the atomic abandoned owner field is live;
        // no ordinary state is inspected before the AcqRel owner claim.
        let state = unsafe { Page::abandonment_atomic_state_at(page) };
        if remote_free::claim_abandoned_owner(unsafe { state.xthread_free.as_ref() })
            == AbandonedOwnerClaim::AlreadyOwned
        {
            return AbandonedBitmapClaim::KeepSet;
        }
        claimed_page = Some(page);
        AbandonedBitmapClaim::Claimed
    });
    let page = match claimed {
        MappedAbandonedClaim::None => return Ok(None),
        MappedAbandonedClaim::Claimed(_) => {
            claimed_page.expect("a claimed abandoned bitmap bit records its page")
        }
        MappedAbandonedClaim::CountDecrementFailed(_) => {
            return Err(RetainedAdoptFailure {
                page: claimed_page.expect("a claimed bitmap bit records its page before counting"),
                error: AbandonError::AbandonedCountDecrementFailed,
            });
        }
    };
    let fail = |error| RetainedAdoptFailure { page, error };

    // Source arena claim first drains while the page retains its abandoned
    // identity, then page reclaim reassociates and drains the live owner.
    let abandoned_collected = match unsafe { remote_free::collect_abandoned(page) } {
        Ok(collected) => collected,
        Err(error) => return Err(fail(AbandonError::RemoteFree(error))),
    };
    // SAFETY: the successful low-bit claim permits ordinary-state projection.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED_MAPPED {
        return Err(fail(AbandonError::NotAbandoned));
    }
    // SAFETY: source `_mi_theap_page_reclaim` writes the target before its
    // second collection; caller's consuming handoff keeps both owners live.
    unsafe { ptr::write(state.theap.as_ptr(), target_theap.as_ptr()) };
    set_thread_identity(&state, target_thread.get());
    let collected = match unsafe { remote_free::collect(page) } {
        Ok(collected) => collected,
        Err(error) => return Err(fail(AbandonError::RemoteFree(error))),
    };
    Ok(Some(AdoptedPage {
        page,
        collected_remote_blocks: abandoned_collected + collected,
    }))
}

/// Testable inner form of [`try_adopt`]. The source algorithm has no callback;
/// this private one-shot hook exists only to deterministically publish a
/// remote free at each source interleaving: after the low ownership claim,
/// and after abandoned-owner collection but before reassociation.
#[cfg(test)]
unsafe fn try_adopt_with<M: MappedAbandonedPages + ?Sized, F, H, I>(
    map: &M,
    thread_sequence: usize,
    target_theap: NonNull<Theap>,
    target_thread: LiveThreadId,
    mut resolve: F,
    after_claim: H,
    after_abandoned_collection: I,
) -> Result<Option<AdoptedPage>, AbandonError>
where
    F: FnMut(usize) -> Option<NonNull<Page>>,
    H: FnOnce(),
    I: FnOnce(),
{
    let mut claimed_page = None;
    let claimed = map.try_claim(thread_sequence, |slice_index| {
        let Some(page) = resolve(slice_index) else {
            return AbandonedBitmapClaim::KeepSet;
        };
        // SAFETY: resolver/caller prove stable initialized metadata. Before
        // the low-bit OR succeeds, this deliberately projects only that one
        // atomic word and reads no identity/provenance/ordinary state.
        let state = unsafe { Page::abandonment_atomic_state_at(page) };
        // `mi_page_claim_ownership`: the old value identifies whether a
        // concurrent free won. The AcqRel operation is the sole ownership
        // claim; ordinary fields remain untouched on failure.
        let claim = remote_free::claim_abandoned_owner(unsafe { state.xthread_free.as_ref() });
        if claim == AbandonedOwnerClaim::AlreadyOwned {
            return AbandonedBitmapClaim::KeepSet;
        }
        // SAFETY: success acquired the source owner bit. The resolver's
        // unsafe contract guarantees this exact bitmap slice/page relation;
        // use debug assertions for source-internal consistency only after
        // ownership makes ordinary fields readable.
        let state = unsafe { Page::abandonment_state_at(page) };
        debug_assert_eq!(map.page_slice_index(state.memid), Some(slice_index));
        debug_assert_eq!(source_thread_identity(&state), THREAD_ID_ABANDONED_MAPPED);
        claimed_page = Some(page);
        AbandonedBitmapClaim::Claimed
    });

    let page = match claimed {
        MappedAbandonedClaim::None => return Ok(None),
        MappedAbandonedClaim::Claimed(_) => {
            claimed_page.expect("a claimed abandoned bitmap bit records its page")
        }
        MappedAbandonedClaim::CountDecrementFailed(_) => {
            return Err(AbandonError::AbandonedCountDecrementFailed);
        }
    };
    after_claim();
    // `arena.c:_mi_arenas_try_find_abandoned` first drains an abandoned
    // owner's remote list while it still carries the abandoned identity.
    // A later `_mi_theap_page_reclaim` installs the target Theap and performs
    // the normal live-owner collection again before queue insertion.
    let abandoned_collected = unsafe { remote_free::collect_abandoned(page) }
        .map_err(AbandonError::RemoteFree)?;
    after_abandoned_collection();
    // SAFETY: the successful AcqRel OR acquired the only source owner bit;
    // map success retained the bit clear, so no alternate reader can adopt it.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED_MAPPED {
        return Err(AbandonError::NotAbandoned);
    }
    // `_mi_theap_page_reclaim` calls `mi_page_set_theap` before collection.
    // It retains all low page flags through the Release weak-CAS loop.
    unsafe { ptr::write(state.theap.as_ptr(), target_theap.as_ptr()) };
    set_thread_identity(&state, target_thread.get());
    // SAFETY: reassociation installs a live owner identity and the caller's
    // page lifetime proof still covers every published remote block.
    let collected = unsafe { remote_free::collect(page) }.map_err(AbandonError::RemoteFree)?;
    Ok(Some(AdoptedPage {
        page,
        collected_remote_blocks: abandoned_collected + collected,
    }))
}

fn unown<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    map: Option<&M>,
) -> Result<AbandonResult, AbandonError> {
    unown_with(page, map, || {})
}

/// Source `mi_abandoned_page_unown` loop with its sole interleaving point
/// factored for a deterministic protocol regression. The production caller
/// supplies no hook; it exists only so the test can publish exactly between
/// the empty-head observation and the weak CAS.
fn unown_with<M: MappedAbandonedPages + ?Sized, F>(
    page: NonNull<Page>,
    map: Option<&M>,
    before_release_cas: F,
) -> Result<AbandonResult, AbandonError>
where
    F: FnOnce(),
{
    // SAFETY: callers preserve page lifetime; this produces raw field pointers
    // only and the low owner bit below authorizes ordinary-state access.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || !is_abandoned(&state) {
        return Err(AbandonError::NotAbandoned);
    }
    let xthread_free = unsafe { state.xthread_free.as_ref() };
    let mut before_release_cas = Some(before_release_cas);
    loop {
        match remote_free::try_unown_abandoned_head(xthread_free, &mut before_release_cas) {
            AbandonedOwnerHeadTransition::Released => return Ok(if source_thread_identity(&state) == THREAD_ID_ABANDONED_MAPPED {
                AbandonResult::UnownedMapped
            } else {
                AbandonResult::UnownedUnmapped
            }),
            AbandonedOwnerHeadTransition::RemotePublished(_) => {
                // SAFETY: this caller still holds the owner bit and the
                // abandoned-page lifetime proof; collection touches only
                // owner fields.
                unsafe { remote_free::collect_abandoned(page) }
                    .map_err(AbandonError::RemoteFree)?;
                if page_is_empty(&state) {
                    unabandon_mapped(&state, map)?;
                    return Ok(AbandonResult::Empty);
                }
            }
            AbandonedOwnerHeadTransition::NotOwned => {
                return Err(AbandonError::NotOwnedAssociated);
            }
        }
    }
}

fn unabandon_mapped<M: MappedAbandonedPages + ?Sized>(
    state: &PageAbandonmentState,
    map: Option<&M>,
) -> Result<(), AbandonError> {
    if source_thread_identity(state) != THREAD_ID_ABANDONED_MAPPED {
        return Ok(());
    }
    let map = map.ok_or(AbandonError::MissingMappedArenaBitmap)?;
    let slice_index = map
        .page_slice_index(state.memid)
        .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)?;
    if !map.clear_once_set(slice_index) {
        return Err(AbandonError::BitmapQuiescenceFailed);
    }
    // `mi_page_clear_abandoned_mapped` preserves only page flags.
    unsafe { state.xthread_id.as_ref() }.fetch_and(PAGE_FLAG_MASK, Ordering::Relaxed);
    if !map.decrement_after_identity_clear() {
        // The bitmap and page identity are already clear, so this cannot be
        // represented as a recoverable pre-mutation failure.
        return Err(AbandonError::AbandonedCountDecrementFailed);
    }
    Ok(())
}

fn set_abandoned_identity(state: &PageAbandonmentState) {
    // `mi_page_set_theap(page, NULL)` briefly clears the ordinary pointer,
    // publishes the abandoned identity with Release CAS while preserving page
    // flags, then `page.c:_mi_page_abandon` restores the old pointer so a
    // same-theap free can reclaim it later.
    let stale_theap = unsafe { ptr::read(state.theap.as_ptr()) };
    unsafe { ptr::write(state.theap.as_ptr(), ptr::null_mut()) };
    set_thread_identity(state, THREAD_ID_ABANDONED);
    unsafe { ptr::write(state.theap.as_ptr(), stale_theap) };
}

fn set_thread_identity(state: &PageAbandonmentState, thread_id: usize) {
    debug_assert_eq!(thread_id & PAGE_FLAG_MASK, 0);
    let xthread_id = unsafe { state.xthread_id.as_ref() };
    let mut previous = xthread_id.load(Ordering::Relaxed);
    loop {
        let replacement = thread_id | (previous & PAGE_FLAG_MASK);
        if word_cas_weak_release(xthread_id, &mut previous, replacement) {
            return;
        }
    }
}

#[inline]
fn source_thread_identity(state: &PageAbandonmentState) -> usize {
    unsafe { state.xthread_id.as_ref() }.load(Ordering::Acquire) & !PAGE_FLAG_MASK
}

#[inline]
fn is_live_associated(state: &PageAbandonmentState) -> bool {
    let thread_id = source_thread_identity(state);
    thread_id != THREAD_ID_ABANDONED && thread_id != THREAD_ID_ABANDONED_MAPPED
}

#[inline]
fn is_abandoned(state: &PageAbandonmentState) -> bool {
    matches!(source_thread_identity(state), THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED)
}

#[inline]
fn is_owned(state: &PageAbandonmentState) -> bool {
    is_owned_word(word_load_relaxed(unsafe { state.xthread_free.as_ref() }))
}

#[inline]
const fn is_owned_word(word: usize) -> bool {
    word & THREAD_FREE_OWNED != 0
}

#[inline]
fn page_is_empty(state: &PageAbandonmentState) -> bool {
    // SAFETY: caller holds the source owner bit whenever it observes `used`.
    unsafe { *state.used.as_ptr() == 0 }
}

#[inline]
fn page_is_full(state: &PageAbandonmentState) -> bool {
    // SAFETY: same owner-bit proof as `page_is_empty`.
    unsafe { *state.used.as_ptr() == usize::from(state.reserved) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::MaybeUninit;
    use core::sync::atomic::AtomicI64;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::arena::ArenaView;
    use crate::bitmap::{BitmapLayout, BitmapView};
    use crate::config::{ARENA_BIN_COUNT, BCHUNK_BITS};
    use crate::types::{Arena, ArenaPages, Heap, MemoryId, ThreadLocalData};

    #[repr(align(64))]
    struct BitmapStorage {
        bytes: [MaybeUninit<u8>; 192],
    }

    impl BitmapStorage {
        const fn uninit() -> Self {
            Self {
                bytes: [const { MaybeUninit::uninit() }; 192],
            }
        }
    }

    #[repr(align(16))]
    struct TestBlock([u8; 16]);

    impl TestBlock {
        fn pointer(&mut self) -> NonNull<u8> {
            NonNull::from(&mut self.0).cast()
        }
    }

    /// Test-only sharing proof: scoped producers use only raw atomic page
    /// fields, while ordinary page state remains owner-only through each
    /// collection loop. `Page` itself intentionally remains non-`Sync`.
    #[repr(transparent)]
    struct ConcurrentPage(Page);

    unsafe impl Sync for ConcurrentPage {}

    impl ConcurrentPage {
        fn pointer(&self) -> NonNull<Page> {
            unsafe { NonNull::new_unchecked(core::ptr::addr_of!(self.0).cast_mut()) }
        }
    }

    fn map_fixture(storage: &mut BitmapStorage) -> Arena {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap();
        }
        let bitmap = storage.bytes.as_mut_ptr().cast::<u8>();
        let mut maps = [core::ptr::null_mut(); ARENA_BIN_COUNT];
        maps[1] = bitmap;
        Arena {
            memid: MemoryId::none(),
            subprocess: core::ptr::null_mut(),
            arena_index: 0,
            start: core::ptr::null_mut(),
            slice_count: BCHUNK_BITS,
            info_slices: 0,
            numa_node: -1,
            is_exclusive: false,
            purge_expire: AtomicI64::new(0),
            commit_function: None,
            commit_function_argument: core::ptr::null_mut(),
            total_size: 0,
            parent: core::ptr::null_mut(),
            slices_free: core::ptr::null_mut(),
            slices_committed: core::ptr::null_mut(),
            slices_dirty: core::ptr::null_mut(),
            slices_purge: core::ptr::null_mut(),
            pages_meta: core::ptr::null_mut(),
            pages_main: ArenaPages {
                pages: core::ptr::null_mut(),
                pages_abandoned: maps,
            },
        }
    }

    fn mapped_page(arena: &mut Arena, used: usize) -> Page {
        let mut page = Page::remote_free_test_page(4, used);
        assert!(unsafe { page.abandoned_test_set_arena_memory(arena, 17, 1) });
        page
    }

    fn bind_adopting_theap(
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
        theap: &mut Theap,
        thread_id: LiveThreadId,
    ) -> NonNull<Theap> {
        tld.attach_bootstrap_exclusive(thread_id);
        assert!(theap.bind_exclusive_single_thread(heap, tld));
        NonNull::from(theap)
    }

    #[test]
    fn abandoned_arena_page_is_published_before_it_becomes_unowned() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 3);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
    }

    #[test]
    fn full_or_non_arena_pages_abandon_unmapped() {
        let mut page = Page::remote_free_test_page(3, 3);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(
            unsafe { abandon(page_raw, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::UnownedUnmapped)
        );
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), 0);
    }

    #[test]
    fn partial_arena_singleton_bin_abandons_unmapped() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let mut page = mapped_page(&mut arena, 1);
        // `MI_BIN_HUGE` is outside `pages_abandoned[0..ARENA_BIN_COUNT]`.
        // The page remains partial, but `arena.c` must leave it unmapped.
        page.set_block_size(crate::config::LARGE_MAX_OBJ_SIZE + 1);
        assert!(size_class::bin(page.block_size()).unwrap() >= ARENA_BIN_COUNT);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(
            unsafe { abandon(page_raw, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::UnownedUnmapped)
        );
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), 0);
    }

    #[test]
    fn empty_page_reports_terminal_release_without_reusing_metadata() {
        let mut page = Page::remote_free_test_page(2, 0);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(
            unsafe { abandon(page_raw, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::Empty)
        );
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.abandoned_test_thread_id(), 12);
    }

    #[test]
    fn failed_adoption_republishes_the_bitmap_before_the_reader_returns() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 3);
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { remote_free::push_abandoned(page_raw, block.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut target_heap = Heap::bootstrap_empty();
        let mut target_tld = ThreadLocalData::detached();
        let mut target_theap = Theap::empty();
        let target = bind_adopting_theap(
            &mut target_heap,
            &mut target_tld,
            &mut target_theap,
            thread_id,
        );
        assert_eq!(
            unsafe { try_adopt(&map, 0, target, thread_id, |_| Some(page_raw)) },
            Ok(None)
        );
        assert!(map.is_published(17));
        assert_eq!(page.remote_free_test_head() & 1, 1);
    }

    #[test]
    fn successful_adoption_reassociates_and_collects_remote_frees() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let page = ConcurrentPage(mapped_page(&mut arena, 3));
        let page_raw = page.pointer();
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut target_heap = Heap::bootstrap_empty();
        let mut target_tld = ThreadLocalData::detached();
        let mut target_theap = Theap::empty();
        let target = bind_adopting_theap(
            &mut target_heap,
            &mut target_tld,
            &mut target_theap,
            thread_id,
        );
        let adopter_claimed = Arc::new(Barrier::new(2));
        let producer_published = Arc::new(Barrier::new(2));
        let page_for_producer = &page;
        let map_for_adopter = &map;
        let block_for_producer = &mut block;
        let adopted = thread::scope(|scope| {
            let claim_for_producer = Arc::clone(&adopter_claimed);
            let published_for_producer = Arc::clone(&producer_published);
            scope.spawn(move || {
                claim_for_producer.wait();
                assert_eq!(
                    unsafe {
                        remote_free::push_abandoned(
                            page_for_producer.pointer(),
                            block_for_producer.pointer(),
                        )
                    },
                    Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner)
                );
                published_for_producer.wait();
            });
            unsafe {
                try_adopt_with(
                    map_for_adopter,
                    0,
                    target,
                    thread_id,
                    |_| Some(page_raw),
                    || {
                        adopter_claimed.wait();
                        producer_published.wait();
                    },
                    || {},
                )
            }
            .unwrap()
            .expect("the mapped unowned page is adoptable")
        });

        assert_eq!(adopted.page(), page_raw);
        assert_eq!(adopted.collected_remote_blocks(), 1);
        assert_eq!(page.0.abandoned_test_thread_id(), thread_id.get());
        assert_eq!(page.0.remote_free_test_head(), 1);
        assert_eq!(page.0.remote_free_test_used(), 2);
        assert!(!map.is_published(17));
    }

    #[test]
    fn producer_between_abandoned_and_live_adoption_collections_is_drained_live() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let page = ConcurrentPage(mapped_page(&mut arena, 3));
        let page_raw = page.pointer();
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut target_heap = Heap::bootstrap_empty();
        let mut target_tld = ThreadLocalData::detached();
        let mut target_theap = Theap::empty();
        let target = bind_adopting_theap(
            &mut target_heap,
            &mut target_tld,
            &mut target_theap,
            thread_id,
        );
        let abandoned_collected = Arc::new(Barrier::new(2));
        let producer_published = Arc::new(Barrier::new(2));
        let page_for_producer = &page;
        let map_for_adopter = &map;
        let block_for_producer = &mut block;
        let adopted = thread::scope(|scope| {
            let collected_for_producer = Arc::clone(&abandoned_collected);
            let published_for_producer = Arc::clone(&producer_published);
            scope.spawn(move || {
                collected_for_producer.wait();
                assert_eq!(
                    unsafe {
                        remote_free::push_abandoned(
                            page_for_producer.pointer(),
                            block_for_producer.pointer(),
                        )
                    },
                    Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner)
                );
                published_for_producer.wait();
            });
            unsafe {
                try_adopt_with(
                    map_for_adopter,
                    0,
                    target,
                    thread_id,
                    |_| Some(page_raw),
                    || {},
                    || {
                        abandoned_collected.wait();
                        producer_published.wait();
                    },
                )
            }
            .unwrap()
            .expect("the mapped unowned page is adoptable")
        });

        assert_eq!(adopted.page(), page_raw);
        assert_eq!(adopted.collected_remote_blocks(), 1);
        assert_eq!(page.0.abandoned_test_thread_id(), thread_id.get());
        assert_eq!(page.0.remote_free_test_head(), 1);
        assert_eq!(page.0.remote_free_test_used(), 2);
        assert!(!map.is_published(17));
    }

    #[test]
    fn producer_between_unown_observation_and_cas_is_collected_before_release() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let page = ConcurrentPage(mapped_page(&mut arena, 3));
        assert_eq!(unsafe { abandon(page.pointer(), Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        assert_eq!(
            unsafe { remote_free::push_abandoned(page.pointer(), first.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );
        let owner_observed_empty = Arc::new(Barrier::new(2));
        let producer_published = Arc::new(Barrier::new(2));
        let page = &page;
        let map = &map;
        let second_for_producer = &mut second;

        thread::scope(|scope| {
            let owner_for_producer = Arc::clone(&owner_observed_empty);
            let published_for_producer = Arc::clone(&producer_published);
            scope.spawn(move || {
                owner_for_producer.wait();
                assert_eq!(
                    unsafe {
                        remote_free::push_abandoned(page.pointer(), second_for_producer.pointer())
                    },
                    Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner)
                );
                published_for_producer.wait();
            });
            assert_eq!(
                unown_with(page.pointer(), Some(map), || {
                    owner_observed_empty.wait();
                    producer_published.wait();
                }),
                Ok(AbandonResult::UnownedMapped)
            );
        });

        assert_eq!(page.0.remote_free_test_head(), 0);
        assert_eq!(page.0.remote_free_test_used(), 1);
        assert_eq!(page.0.remote_free_test_local_chain_len(3), 2);
    }
}
