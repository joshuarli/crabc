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
// `remote_free_loom.rs` separately models this module's exact head CAS and
// compact page-lifetime-word transitions with Loom; it does not model raw
// block pointers or owner-local mutation.

use core::ptr::{self, NonNull};

use crate::atomic::{
    AtomicWord, word_cas_weak_acq_rel, word_load_acquire, word_load_relaxed, word_or_acq_rel,
    word_sub_acq_rel,
};
use crate::types::{
    Block, Page, PageRemoteFreeOwnerState, PageRemoteFreeProducerState, ThreadFree,
    PAGE_FLAG_MASK, THREAD_ID_ABANDONED, THREAD_ID_ABANDONED_MAPPED,
    THREAD_ID_DETACHED,
};

const THREAD_FREE_OWNED: ThreadFree = 1;
const THREAD_FREE_BLOCK_MASK: ThreadFree = !THREAD_FREE_OWNED;

// The low 32 bits form a page-local Rust lifetime supplement.  The source
// remote head stays unchanged: it remains the exact `mi_thread_free_t` low-bit
// list from `types.h`.  The page owner supplies one additional word only until
// PageMap lookup/release can retain this proof in `Page` itself.
//
// `ACTIVE` admits a producer that already resolved this exact PageMap entry;
// each admitted publisher adds `PUBLICATION_ONE` before it touches the source
// `xthread_id` or `xthread_free` atomics. `OWNER_DRAINING` admits exactly the
// source owner while it detaches `xthread_free`; it never blocks a producer.
// `TERMINALLY_RETAINED` records an irreversible post-detach source failure.
// An owner may close the lifetime only from `ACTIVE` with none of these states
// held. The high 32 bits distinguish a later reuse of the same metadata
// address from the PageMap generation read by a producer. This is intentionally
// a constant-size per-page state, not a client ledger or owner registry.
const LIVE_REMOTE_PAGE_ACTIVE: usize = 1;
const LIVE_REMOTE_PAGE_PUBLICATION_ONE: usize = 1 << 1;
const LIVE_REMOTE_PAGE_PUBLICATION_MASK: usize = 0x3fff_fffe;
const LIVE_REMOTE_PAGE_TERMINALLY_RETAINED: usize = 1 << 30;
const LIVE_REMOTE_PAGE_OWNER_DRAINING: usize = 1 << 31;
const LIVE_REMOTE_PAGE_GENERATION_SHIFT: usize = 32;

/// One compact page-owned lifetime state for a live remote-free producer.
///
/// This supplements, but never changes, mimalloc's source `xthread_free`
/// protocol.  Pinned `free.c:80-87` relies on a valid client to keep its page
/// live through the atomic push.  Rust needs the same proof at the raw
/// PageMap-to-page boundary without borrowing the owner's Theap or retaining a
/// registry entry per allocation.  The eventual `Page` field must initialize
/// this state when it publishes its PageMap entry and must call
/// [`Self::begin_retirement`] only after the normal source collection proof
/// establishes that there is no live client and no detached remote list.
///
/// It is `repr(transparent)` so the intended page field stays one atomic word.
#[repr(transparent)]
pub(crate) struct LiveRemoteFreePageState {
    word: AtomicWord,
}

/// A page-lifetime generation captured with a PageMap lookup.
///
/// A remote producer passes this value back to [`LiveRemoteFreePageState`]
/// before it creates any raw page-field projection.  A closed and
/// reinitialized page receives a different generation, preventing a stale
/// lookup from pinning a later page at the same metadata address.
pub(crate) type LiveRemoteFreePageGeneration = u32;

/// A publisher could not safely enter the requested source page lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveRemoteFreePagePublicationError {
    /// The PageMap observation refers to an earlier metadata lifetime.
    StaleGeneration,
    /// The page is retiring or already retired and accepts no new producer.
    Retired,
    /// A prior post-detach source failure permanently retained this page.
    TerminallyRetained,
    /// The page-local publication count cannot represent another producer.
    PublicationCountOverflow,
}

/// An owner could not begin PageMap/metadata retirement for this page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveRemoteFreePageRetirementError {
    /// The owner supplied an earlier page lifetime.
    StaleGeneration,
    /// One or more publishers have entered but not completed `mi_free_block_mt`.
    PublishersInFlight,
    /// The source owner is currently detaching `xthread_free` into `local_free`.
    OwnerCollectionInProgress,
    /// An irreversible source collection failure retains this page/map owner.
    TerminallyRetained,
    /// A prior owner already closed this exact lifetime.
    AlreadyRetired,
}

/// Reinitialization did not start from the requested closed page lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveRemoteFreePageReinitializeError {
    /// The caller's metadata generation was superseded.
    StaleGeneration,
    /// The page is still accepting live remote-free publishers.
    StillLive,
    /// A malformed state records publishers after the lifetime was closed.
    PublishersInFlight,
    /// A malformed state retains an owner-side collector after the lifetime closed.
    OwnerCollectionInProgress,
    /// An irreversible source collection failure forbids metadata reuse.
    TerminallyRetained,
    /// Reusing this metadata address would repeat a PageMap generation.
    /// The caller must retain the closed page rather than permit ABA reuse.
    GenerationExhausted,
}

/// A source live-owner remote publication could not finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveRemoteFreePushError {
    /// The PageMap lifetime no longer admitted this producer.
    Lifetime(LiveRemoteFreePagePublicationError),
    /// The pinned `mi_free_block_mt` atomic source transition rejected input.
    Source(RemoteFreeError),
}

/// A live page could not start its source owner-side remote-list collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveRemoteFreePageOwnerCollectionError {
    /// The PageMap observation refers to an earlier metadata lifetime.
    StaleGeneration,
    /// The page is retiring or already retired.
    Retired,
    /// A prior post-detach source failure permanently retained this page.
    TerminallyRetained,
    /// The unique source page owner already has an active collector.
    OwnerCollectionInProgress,
}

/// A generic live-page collection failed before or during the source drain.
pub(crate) enum LiveRemoteFreePageCollectError<'page> {
    /// The page-local lifetime rejected the owner-side collector.
    Lifetime(LiveRemoteFreePageOwnerCollectionError),
    /// A pre-detach source check rejected the collection; normal owner cleanup
    /// remains available because no source head was irreversibly changed.
    Source(RemoteFreeError),
    /// `mi_page_thread_free_collect` detached the source head and then
    /// rejected its list/accounting. The returned terminal owner is the only
    /// auditable retained lifetime; it permanently blocks retirement/reuse.
    Terminal {
        owner: LiveRemoteFreePageTerminal<'page>,
        source: RemoteFreeError,
    },
}

/// One admitted live remote publisher.
///
/// Dropping this guard completes the page-local lifetime half of the source
/// publication.  It does not collect the remote head: the actual owner still
/// performs `mi_page_thread_free_collect` through [`collect`].
#[must_use = "a live remote publication must keep the page lifetime pinned until its source atomic push completes"]
pub(crate) struct LiveRemoteFreePagePublication<'page> {
    state: &'page LiveRemoteFreePageState,
    generation: LiveRemoteFreePageGeneration,
}

/// The sole owner-side drain of one live page's source remote-free head.
///
/// The guard maps to `mi_page_thread_free_collect` in pinned `src/page.c`.
/// Its state bit excludes PageMap retirement while the owner mutates
/// `used`/`local_free`, but does not change `mi_free_block_mt`: a foreign
/// thread may continue to publish through the atomic source head and will be
/// consumed by this or a later source collection.
#[must_use = "a live owner collector must finish before the page lifetime can retire"]
pub(crate) struct LiveRemoteFreePageOwnerCollection<'page> {
    state: &'page LiveRemoteFreePageState,
    generation: LiveRemoteFreePageGeneration,
}

/// The unique retained owner after an irreversible owner-side source failure.
///
/// This type carries no PageMap, Theap, queue, or allocator capability. Its
/// retained state bit is the durable ownership record: even if a caller drops
/// this audit token, page retirement and metadata reuse remain refused rather
/// than guessing how to reconstruct a detached remote list.
#[must_use = "a terminal collection failure retains exactly one page-lifetime owner"]
pub(crate) struct LiveRemoteFreePageTerminal<'page> {
    state: &'page LiveRemoteFreePageState,
    generation: LiveRemoteFreePageGeneration,
}

impl LiveRemoteFreePageState {
    /// Creates the initial active lifetime for one initialized page.
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            word: AtomicWord::new(live_remote_page_word(1, true, 0)),
        }
    }

    /// Reads the current PageMap generation with acquire synchronization.
    #[inline]
    pub(crate) fn current_generation(&self) -> LiveRemoteFreePageGeneration {
        live_remote_page_generation(word_load_acquire(&self.word))
    }

    /// Pins one resolved live page until its source remote-head push completes.
    ///
    /// This is a raw PageMap boundary, not a lookup API: the caller must have
    /// obtained `generation` together with the page pointer through an
    /// acquire-stable PageMap entry.  While the returned guard exists, the
    /// owner cannot begin this page lifetime's retirement.  The guard grants
    /// no access to owner-local page fields, queues, Theap, or PageMap state.
    #[inline]
    pub(crate) fn begin_publication(
        &self,
        generation: LiveRemoteFreePageGeneration,
    ) -> Result<LiveRemoteFreePagePublication<'_>, LiveRemoteFreePagePublicationError> {
        begin_live_remote_page_publication_with(&self.word, generation)?;
        Ok(LiveRemoteFreePagePublication {
            state: self,
            generation,
        })
    }

    /// Closes this page lifetime before PageMap unregistration or metadata
    /// release.
    ///
    /// The caller must already hold the source page owner and must have
    /// collected `xthread_free` so source `used` proves no client or remote
    /// list remains.  `PublishersInFlight` is not an allocator failure: the
    /// owner must continue source collection and retry after those producers
    /// have completed their atomic publications.
    #[inline]
    pub(crate) fn begin_retirement(
        &self,
        generation: LiveRemoteFreePageGeneration,
    ) -> Result<(), LiveRemoteFreePageRetirementError> {
        begin_live_remote_page_retirement_with(&self.word, generation)
    }

    /// Begins the source owner-side `xthread_free` collection for this page.
    ///
    /// The caller must be the one live source page owner and therefore the
    /// sole writer of `used`, `local_free`, and `free`. Remote producers retain
    /// only the disjoint atomic source fields; unlike a scheduler or registry,
    /// this page-local guard does not wait for or reject them.
    #[inline]
    pub(crate) fn begin_owner_collection(
        &self,
        generation: LiveRemoteFreePageGeneration,
    ) -> Result<LiveRemoteFreePageOwnerCollection<'_>, LiveRemoteFreePageOwnerCollectionError>
    {
        begin_live_remote_page_owner_collection_with(&self.word, generation)?;
        Ok(LiveRemoteFreePageOwnerCollection {
            state: self,
            generation,
        })
    }

    /// Starts the next page lifetime after the old one was closed.
    ///
    /// This must run before publishing a new PageMap entry for reused metadata.
    /// It never reopens a live page, and it does not register a page itself.
    #[inline]
    pub(crate) fn reinitialize(
        &self,
        generation: LiveRemoteFreePageGeneration,
    ) -> Result<LiveRemoteFreePageGeneration, LiveRemoteFreePageReinitializeError> {
        reinitialize_live_remote_page_with(&self.word, generation)
    }
}

impl Drop for LiveRemoteFreePagePublication<'_> {
    #[inline]
    fn drop(&mut self) {
        finish_live_remote_page_publication_with(&self.state.word, self.generation);
    }
}

impl<'page> LiveRemoteFreePageOwnerCollection<'page> {
    /// Detaches and merges the source `xthread_free` head exactly once.
    ///
    /// # Safety
    ///
    /// `page` must be this guard's live, associated page. The caller must be
    /// its sole source owner for all non-atomic page fields and retain its
    /// block area through the collection. Foreign threads may run [`push_live`]
    /// concurrently, but no path may abandon, detach, reuse, or release this
    /// page until this guard drops and the owner completes source collection.
    #[inline]
    unsafe fn collect(&self, page: NonNull<Page>) -> Result<usize, RemoteFreeError> {
        // SAFETY: the caller supplies the same owner and page-lifetime proof
        // required by `collect`; this guard adds retirement exclusion only.
        unsafe { collect(page) }
    }

    /// Converts a post-detach source failure into the only retained page owner.
    ///
    /// This is intentionally private to the generic [`collect_live`] seam so
    /// a caller cannot accidentally drop an owner guard after an irreversible
    /// `mi_page_thread_free_collect` error and make the page reusable.
    fn into_terminal(self) -> LiveRemoteFreePageTerminal<'page> {
        retain_live_remote_page_terminal_with(&self.state.word, self.generation);
        let state = self.state;
        let generation = self.generation;
        // The terminal transition above clears `OWNER_DRAINING` while setting
        // `TERMINALLY_RETAINED`. Forgetting this guard is therefore confined
        // to the explicit retained-error owner, never a normal success path.
        core::mem::forget(self);
        LiveRemoteFreePageTerminal { state, generation }
    }
}

impl Drop for LiveRemoteFreePageOwnerCollection<'_> {
    #[inline]
    fn drop(&mut self) {
        finish_live_remote_page_owner_collection_with(&self.state.word, self.generation);
    }
}

impl LiveRemoteFreePageTerminal<'_> {
    /// Identifies the permanently retained page lifetime for test/state audit.
    #[inline]
    pub(crate) const fn generation(&self) -> LiveRemoteFreePageGeneration {
        self.generation
    }

    /// Returns whether this token still names the retained lifetime.
    #[inline]
    pub(crate) fn is_retained(&self) -> bool {
        let state = word_load_acquire(&self.state.word);
        live_remote_page_generation(state) == self.generation
            && state & LIVE_REMOTE_PAGE_TERMINALLY_RETAINED != 0
    }
}

/// Publishes one source-shaped live remote free under a page-local lifetime
/// pin.
///
/// This is the integration seam for general pointer-centered `free`: PageMap
/// lookup supplies `page` plus `generation`, canonical block recovery supplies
/// `block`, then this function performs the existing `mi_free_block_mt` CAS.
/// It consults no owner registry and records no allocation identity.  The
/// lifetime pin covers exactly the raw producer projection and source atomic
/// publication; it drops before an owner can retire the page.
///
/// # Safety
///
/// `page`, `generation`, and `lifetime` must be one PageMap-published page
/// lifetime. `block` must be the aligned canonical block for one current
/// allocation from that page. The caller must not publish PageMap removal,
/// page reuse, abandonment, or owner-local mutation outside the source
/// protocol while this operation is in progress. On success the block is
/// consumed exactly as by [`push`]; on error the caller retains its block.
pub(crate) unsafe fn push_live(
    lifetime: &LiveRemoteFreePageState,
    generation: LiveRemoteFreePageGeneration,
    page: NonNull<Page>,
    block: NonNull<u8>,
) -> Result<(), LiveRemoteFreePushError> {
    let publication = lifetime
        .begin_publication(generation)
        .map_err(LiveRemoteFreePushError::Lifetime)?;
    // SAFETY: the caller's PageMap lifetime proof and the guard above keep
    // the exact page metadata live until the source AcqRel publication has
    // completed. `push` touches only the producer-visible source atomics.
    let result = unsafe { push(page, block) }.map_err(LiveRemoteFreePushError::Source);
    drop(publication);
    result
}

/// Performs one generic owner-side remote-list drain for a live page.
///
/// This is the live counterpart to [`collect`] and the narrow integration seam
/// for ordinary allocation/free slow paths: it establishes page-local
/// retirement exclusion, executes pinned `mi_page_thread_free_collect` plus
/// `mi_page_thread_collect_to_local`, then releases only that exclusion. It
/// intentionally does not force collection, requeue a page, inspect an owner
/// registry, or decide PageMap release.
///
/// # Safety
///
/// `page`, `generation`, and `lifetime` must describe one live associated
/// PageMap entry. The caller must be the sole source owner of the ordinary
/// page fields and preserve the page/block-area lifetime while this function
/// runs. It may race only with source-shaped [`push_live`] producers.
pub(crate) unsafe fn collect_live<'page>(
    lifetime: &'page LiveRemoteFreePageState,
    generation: LiveRemoteFreePageGeneration,
    page: NonNull<Page>,
) -> Result<usize, LiveRemoteFreePageCollectError<'page>> {
    let collection = lifetime
        .begin_owner_collection(generation)
        .map_err(LiveRemoteFreePageCollectError::Lifetime)?;
    // SAFETY: the caller's source owner proof plus the guard keep the page
    // metadata and ordinary fields stable while `collect` detaches one atomic
    // head. Producers may publish only to the successor head.
    match unsafe { collection.collect(page) } {
        Ok(collected) => {
            drop(collection);
            Ok(collected)
        }
        Err(source) if collection_error_is_post_detach(source) => {
            let owner = collection.into_terminal();
            Err(LiveRemoteFreePageCollectError::Terminal { owner, source })
        }
        Err(source) => {
            drop(collection);
            Err(LiveRemoteFreePageCollectError::Source(source))
        }
    }
}

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

/// Distinguishes errors reached after the source remote-head detach.
///
/// `collect_state` can reject these two conditions only from
/// `collect_detached_to_local`, after `detach_from_head` successfully changed
/// `xthread_free` to its owned-empty form. They therefore require terminal
/// retention; all other errors are pre-detach validation failures in the live
/// owner collection path.
#[inline]
const fn collection_error_is_post_detach(error: RemoteFreeError) -> bool {
    matches!(
        error,
        RemoteFreeError::TooManyRemoteBlocks | RemoteFreeError::UsedCountUnderflow
    )
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

/// Atomic operations used by the compact page-lifetime word.
///
/// This is deliberately separate from [`ThreadFreeHead`]: the source
/// `mi_thread_free_t` head is not repurposed as a Rust lifetime counter. Both
/// the production `AtomicUsize` and the Loom adapter below execute this exact
/// acquire / AcqRel transition surface.
trait LiveRemoteFreePageLifetimeWord {
    fn load_acquire(&self) -> usize;

    fn cas_weak_acq_rel(&self, expected: &mut usize, replacement: usize) -> bool;

    fn fetch_sub_acq_rel(&self, value: usize) -> usize;
}

impl LiveRemoteFreePageLifetimeWord for AtomicWord {
    #[inline]
    fn load_acquire(&self) -> usize {
        word_load_acquire(self)
    }

    #[inline]
    fn cas_weak_acq_rel(&self, expected: &mut usize, replacement: usize) -> bool {
        word_cas_weak_acq_rel(self, expected, replacement)
    }

    #[inline]
    fn fetch_sub_acq_rel(&self, value: usize) -> usize {
        word_sub_acq_rel(self, value)
    }
}

/// The source-independent producer admission transition.
///
/// A successful AcqRel CAS pins the metadata lifetime before a publisher can
/// derive `Page::remote_free_producer_state_at`. An owner closing this same
/// generation observes that count through its own AcqRel CAS; there is no
/// registry scan or owner/TLD dependency in either path.
fn begin_live_remote_page_publication_with<H>(
    word: &H,
    generation: LiveRemoteFreePageGeneration,
) -> Result<(), LiveRemoteFreePagePublicationError>
where
    H: LiveRemoteFreePageLifetimeWord + ?Sized,
{
    let mut observed = word.load_acquire();
    loop {
        if live_remote_page_generation(observed) != generation {
            return Err(LiveRemoteFreePagePublicationError::StaleGeneration);
        }
        if observed & LIVE_REMOTE_PAGE_TERMINALLY_RETAINED != 0 {
            return Err(LiveRemoteFreePagePublicationError::TerminallyRetained);
        }
        if observed & LIVE_REMOTE_PAGE_ACTIVE == 0 {
            return Err(LiveRemoteFreePagePublicationError::Retired);
        }
        if observed & LIVE_REMOTE_PAGE_PUBLICATION_MASK == LIVE_REMOTE_PAGE_PUBLICATION_MASK {
            return Err(LiveRemoteFreePagePublicationError::PublicationCountOverflow);
        }
        let replacement = observed + LIVE_REMOTE_PAGE_PUBLICATION_ONE;
        if word.cas_weak_acq_rel(&mut observed, replacement) {
            return Ok(());
        }
    }
}

/// Completes one source remote-head publication.
///
/// The guard that calls this function is the only way a successful admission
/// can complete, so underflow would mean an internal one-way lifecycle bug.
fn finish_live_remote_page_publication_with<H>(
    word: &H,
    generation: LiveRemoteFreePageGeneration,
) where
    H: LiveRemoteFreePageLifetimeWord + ?Sized,
{
    let previous = word.fetch_sub_acq_rel(LIVE_REMOTE_PAGE_PUBLICATION_ONE);
    debug_assert_eq!(live_remote_page_generation(previous), generation);
    debug_assert_ne!(previous & LIVE_REMOTE_PAGE_ACTIVE, 0);
    debug_assert_ne!(previous & LIVE_REMOTE_PAGE_PUBLICATION_MASK, 0);
}

/// Acquires the one source owner-side collection slot without affecting remote
/// producer admission. This is a page-local serialization of owner-only
/// fields, not a global allocator scheduler or a replacement for the source
/// `xthread_free` ownership bit.
fn begin_live_remote_page_owner_collection_with<H>(
    word: &H,
    generation: LiveRemoteFreePageGeneration,
) -> Result<(), LiveRemoteFreePageOwnerCollectionError>
where
    H: LiveRemoteFreePageLifetimeWord + ?Sized,
{
    let mut observed = word.load_acquire();
    loop {
        if live_remote_page_generation(observed) != generation {
            return Err(LiveRemoteFreePageOwnerCollectionError::StaleGeneration);
        }
        if observed & LIVE_REMOTE_PAGE_TERMINALLY_RETAINED != 0 {
            return Err(LiveRemoteFreePageOwnerCollectionError::TerminallyRetained);
        }
        if observed & LIVE_REMOTE_PAGE_ACTIVE == 0 {
            return Err(LiveRemoteFreePageOwnerCollectionError::Retired);
        }
        if observed & LIVE_REMOTE_PAGE_OWNER_DRAINING != 0 {
            return Err(LiveRemoteFreePageOwnerCollectionError::OwnerCollectionInProgress);
        }
        let replacement = observed | LIVE_REMOTE_PAGE_OWNER_DRAINING;
        if word.cas_weak_acq_rel(&mut observed, replacement) {
            return Ok(());
        }
    }
}

/// Releases the owner-side collection slot after source list accounting.
///
/// Producer publication can change only the count portion while this guard is
/// held, so the AcqRel loop preserves each successful producer admission.
fn finish_live_remote_page_owner_collection_with<H>(
    word: &H,
    generation: LiveRemoteFreePageGeneration,
) where
    H: LiveRemoteFreePageLifetimeWord + ?Sized,
{
    let mut observed = word.load_acquire();
    loop {
        debug_assert_eq!(live_remote_page_generation(observed), generation);
        debug_assert_ne!(observed & LIVE_REMOTE_PAGE_ACTIVE, 0);
        debug_assert_ne!(observed & LIVE_REMOTE_PAGE_OWNER_DRAINING, 0);
        let replacement = observed & !LIVE_REMOTE_PAGE_OWNER_DRAINING;
        if word.cas_weak_acq_rel(&mut observed, replacement) {
            return;
        }
    }
}

/// Marks a post-detach collection failure terminally retained.
///
/// `collect_detached_to_local` may reject list accounting only after the
/// source head CAS succeeded. Clearing the drain bit alone would make that
/// detached/partially accounted page eligible for another lifecycle decision,
/// so this single AcqRel transition preserves one auditable page owner and
/// blocks every future publication, drain, retirement, and reuse attempt.
fn retain_live_remote_page_terminal_with<H>(
    word: &H,
    generation: LiveRemoteFreePageGeneration,
) where
    H: LiveRemoteFreePageLifetimeWord + ?Sized,
{
    let mut observed = word.load_acquire();
    loop {
        debug_assert_eq!(live_remote_page_generation(observed), generation);
        debug_assert_ne!(observed & LIVE_REMOTE_PAGE_ACTIVE, 0);
        debug_assert_ne!(observed & LIVE_REMOTE_PAGE_OWNER_DRAINING, 0);
        let replacement = (observed | LIVE_REMOTE_PAGE_TERMINALLY_RETAINED)
            & !LIVE_REMOTE_PAGE_OWNER_DRAINING;
        if word.cas_weak_acq_rel(&mut observed, replacement) {
            return;
        }
    }
}

/// The source-independent owner close transition.
///
/// Closing is intentionally a single compare/exchange from the active,
/// zero-publisher word. A losing producer rechecks the same page generation;
/// it can never increment a page after the owner has closed that lifetime.
fn begin_live_remote_page_retirement_with<H>(
    word: &H,
    generation: LiveRemoteFreePageGeneration,
) -> Result<(), LiveRemoteFreePageRetirementError>
where
    H: LiveRemoteFreePageLifetimeWord + ?Sized,
{
    let mut observed = word.load_acquire();
    loop {
        if live_remote_page_generation(observed) != generation {
            return Err(LiveRemoteFreePageRetirementError::StaleGeneration);
        }
        if observed & LIVE_REMOTE_PAGE_TERMINALLY_RETAINED != 0 {
            return Err(LiveRemoteFreePageRetirementError::TerminallyRetained);
        }
        if observed & LIVE_REMOTE_PAGE_ACTIVE == 0 {
            return Err(LiveRemoteFreePageRetirementError::AlreadyRetired);
        }
        if observed & LIVE_REMOTE_PAGE_PUBLICATION_MASK != 0 {
            return Err(LiveRemoteFreePageRetirementError::PublishersInFlight);
        }
        if observed & LIVE_REMOTE_PAGE_OWNER_DRAINING != 0 {
            return Err(LiveRemoteFreePageRetirementError::OwnerCollectionInProgress);
        }
        let replacement = observed & !LIVE_REMOTE_PAGE_ACTIVE;
        if word.cas_weak_acq_rel(&mut observed, replacement) {
            return Ok(());
        }
    }
}

/// Reopens only a closed page lifetime with a distinct PageMap generation.
fn reinitialize_live_remote_page_with<H>(
    word: &H,
    generation: LiveRemoteFreePageGeneration,
) -> Result<LiveRemoteFreePageGeneration, LiveRemoteFreePageReinitializeError>
where
    H: LiveRemoteFreePageLifetimeWord + ?Sized,
{
    let mut observed = word.load_acquire();
    loop {
        if live_remote_page_generation(observed) != generation {
            return Err(LiveRemoteFreePageReinitializeError::StaleGeneration);
        }
        if observed & LIVE_REMOTE_PAGE_TERMINALLY_RETAINED != 0 {
            return Err(LiveRemoteFreePageReinitializeError::TerminallyRetained);
        }
        if observed & LIVE_REMOTE_PAGE_ACTIVE != 0 {
            return Err(LiveRemoteFreePageReinitializeError::StillLive);
        }
        if observed & LIVE_REMOTE_PAGE_PUBLICATION_MASK != 0 {
            return Err(LiveRemoteFreePageReinitializeError::PublishersInFlight);
        }
        if observed & LIVE_REMOTE_PAGE_OWNER_DRAINING != 0 {
            return Err(LiveRemoteFreePageReinitializeError::OwnerCollectionInProgress);
        }
        let Some(next_generation) = generation.checked_add(1) else {
            return Err(LiveRemoteFreePageReinitializeError::GenerationExhausted);
        };
        let replacement = live_remote_page_word(next_generation, true, 0);
        if word.cas_weak_acq_rel(&mut observed, replacement) {
            return Ok(next_generation);
        }
    }
}

#[inline]
const fn live_remote_page_word(
    generation: LiveRemoteFreePageGeneration,
    active: bool,
    publications: usize,
) -> usize {
    ((generation as usize) << LIVE_REMOTE_PAGE_GENERATION_SHIFT)
        | publications
        | if active { LIVE_REMOTE_PAGE_ACTIVE } else { 0 }
}

#[inline]
const fn live_remote_page_generation(word: usize) -> LiveRemoteFreePageGeneration {
    (word >> LIVE_REMOTE_PAGE_GENERATION_SHIFT) as LiveRemoteFreePageGeneration
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
    fn live_remote_page_lifetime_holds_retirement_until_publication_completes() {
        let state = LiveRemoteFreePageState::new();
        let generation = state.current_generation();
        let publication = state
            .begin_publication(generation)
            .expect("a fresh page accepts its first remote publisher");

        assert_eq!(
            state.begin_retirement(generation),
            Err(LiveRemoteFreePageRetirementError::PublishersInFlight),
            "the page may not lose its PageMap/metadata lifetime while the producer still holds its source publication pin"
        );

        drop(publication);

        assert_eq!(
            state.begin_retirement(generation),
            Ok(()),
            "the owner may begin terminal retirement after the remote publication completes"
        );
        let next_generation = state
            .reinitialize(generation)
            .expect("a closed page may begin its next source lifetime");
        assert_ne!(next_generation, generation);
        assert!(
            matches!(
                state.begin_publication(generation),
                Err(LiveRemoteFreePagePublicationError::StaleGeneration)
            ),
            "a stale PageMap observation cannot acquire the reused page's new lifetime"
        );
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

    #[test]
    fn live_page_lifetime_drives_multiple_source_remote_publications_without_owner_lookup() {
        const PRODUCERS: usize = 4;
        const BLOCKS_PER_PRODUCER: usize = 16;
        const BLOCKS: usize = PRODUCERS * BLOCKS_PER_PRODUCER;

        let page = ConcurrentTestPage(Page::remote_free_test_page(BLOCKS as u16, BLOCKS));
        let lifetime = LiveRemoteFreePageState::new();
        let generation = lifetime.current_generation();
        let mut blocks: [TestBlock; BLOCKS] = std::array::from_fn(|_| TestBlock([0; 16]));

        thread::scope(|scope| {
            for producer_blocks in blocks.chunks_mut(BLOCKS_PER_PRODUCER) {
                let page = &page;
                let lifetime = &lifetime;
                scope.spawn(move || {
                    for block in producer_blocks {
                        // SAFETY: each worker owns one exact current block;
                        // `push_live` admits only this PageMap generation and
                        // then runs the existing source remote-head CAS. The
                        // test owner touches ordinary page fields only after
                        // every producer has joined.
                        unsafe {
                            push_live(lifetime, generation, page.page_pointer(), block.pointer())
                                .expect("the page-local lifetime admits each remote publication");
                        }
                    }
                });
            }
        });

        // SAFETY: all production-shaped source publishers joined, so this is
        // the exclusive owner collection that accounts their remote list
        // under the page-local retirement exclusion.
        assert!(matches!(
            unsafe { collect_live(&lifetime, generation, page.page_pointer()) },
            Ok(BLOCKS)
        ));
        assert_eq!(page.0.remote_free_test_head(), 1);
        assert_eq!(page.0.remote_free_test_used(), 0);
        assert_eq!(
            lifetime.begin_retirement(generation),
            Ok(()),
            "the source-empty page may close its PageMap lifetime after collection"
        );
    }

    #[test]
    fn live_owner_collection_allows_remote_publication_before_retirement() {
        let page = ConcurrentTestPage(Page::remote_free_test_page(1, 1));
        let lifetime = LiveRemoteFreePageState::new();
        let generation = lifetime.current_generation();
        let collection = lifetime
            .begin_owner_collection(generation)
            .expect("the live source owner starts one page-local thread-free drain");
        let mut block = TestBlock([0; 16]);

        assert_eq!(
            lifetime.begin_retirement(generation),
            Err(LiveRemoteFreePageRetirementError::OwnerCollectionInProgress),
            "PageMap retirement waits for the owner-side source collector"
        );

        thread::scope(|scope| {
            let lifetime = &lifetime;
            scope.spawn(|| {
                // SAFETY: the exact client remains live while the owner drain
                // holds this page lifetime. The source collector accepts a
                // concurrent producer through the unchanged remote-head CAS.
                unsafe {
                    push_live(lifetime, generation, page.page_pointer(), block.pointer())
                        .expect("the drain does not reject a legal remote producer");
                }
            });
        });

        // SAFETY: the joined producer has completed its source publication;
        // this guard is the sole owner-side remote-list collector.
        assert_eq!(unsafe { collection.collect(page.page_pointer()) }, Ok(1));
        assert_eq!(page.0.remote_free_test_used(), 0);
        drop(collection);
        assert_eq!(
            lifetime.begin_retirement(generation),
            Ok(()),
            "only the source-empty page may retire after the owner drain completes"
        );
    }

    #[test]
    fn post_detach_collection_error_terminally_retains_the_page_lifetime() {
        let page = ConcurrentTestPage(Page::remote_free_test_page(1, 0));
        let lifetime = LiveRemoteFreePageState::new();
        let generation = lifetime.current_generation();
        let mut block = TestBlock([0; 16]);

        // SAFETY: this deliberately invalid accounting image keeps the source
        // page/producer atomics live but has `used == 0` for one published
        // block. The owner collector must detach before it observes the
        // underflow, exercising the irreversible source error boundary.
        assert_eq!(
            unsafe { push_live(&lifetime, generation, page.page_pointer(), block.pointer()) },
            Ok(())
        );
        let terminal = match unsafe { collect_live(&lifetime, generation, page.page_pointer()) } {
            Err(LiveRemoteFreePageCollectError::Terminal { owner, source }) => {
                assert_eq!(source, RemoteFreeError::UsedCountUnderflow);
                owner
            }
            _ => panic!("expected a retained post-detach collection failure"),
        };

        assert_eq!(terminal.generation(), generation);
        assert!(terminal.is_retained(), "the returned token audits retention");
        assert_eq!(page.0.remote_free_test_head(), 1, "the source head stayed detached");
        assert_eq!(
            lifetime.begin_retirement(generation),
            Err(LiveRemoteFreePageRetirementError::TerminallyRetained),
            "the detached list error may not reopen PageMap retirement"
        );
        assert_eq!(
            lifetime.reinitialize(generation),
            Err(LiveRemoteFreePageReinitializeError::TerminallyRetained),
            "the retained page metadata may not be reused under the old generation"
        );
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
