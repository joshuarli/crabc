// Copyright (c) 2018-2024, Microsoft Research, Daan Leijen
// Portions derived from pinned mimalloc v3.5.0 `src/theap.c`:
// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page-queue.c:40-55,147-172,204-274,
// 252-423` (predicates, the test-only validity oracle, intrusive queue
// membership, and the direct-cache-before-page-count queue-removal order), and
// `src/theap.c:18-45,85-137` (`MI_ABANDON` prepass, saved-successor visitor,
// and all-free versus live-page owner-exit split). The generic owner-exit
// coordinator below owns only source callback ordering and the queue half;
// concrete deferred-free, retired-page, page-local collection, abandonment
// publication, PageMap/backing release, and TLD/Theap detach stay at their
// respective lifecycle boundaries.

use core::marker::PhantomData;
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
/// [`TheapCollectAbandonCallbacks::collect_page`] chooses only this source
/// lifetime branch after force/false free collection. It does not name a page
/// kind, size bin, mapping kind, or test fixture geometry: an empty page is
/// released and every other page is detached for its source-specific
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

/// The two source prepasses that precede every `MI_ABANDON` page visit.
///
/// Pinned `mi_theap_collect_ex` calls deferred-free collection before retired
/// page collection. [`theap_collect_abandon_queues`] owns that ordering rather
/// than trusting an owner-exit caller to reproduce it before entering the
/// page-action callbacks.
#[must_use = "the source prepass must be passed to the collect-abandon coordinator"]
pub(crate) struct TheapCollectAbandonPrepass<DeferredFrees, RetiredPages> {
    deferred_frees: DeferredFrees,
    retired_pages: RetiredPages,
}

impl<DeferredFrees, RetiredPages> TheapCollectAbandonPrepass<DeferredFrees, RetiredPages> {
    /// Records the source-order prepass callbacks without running either one.
    #[inline]
    pub(crate) const fn new(deferred_frees: DeferredFrees, retired_pages: RetiredPages) -> Self {
        Self {
            deferred_frees,
            retired_pages,
        }
    }

    /// Runs the two source prepasses and creates the otherwise-unforgeable
    /// proof required by page-action callbacks.
    #[inline]
    fn run<E>(
        &mut self,
        theap: &mut Theap,
    ) -> Result<TheapCollectAbandonPageActionsReady, TheapCollectAbandonFailure<E>>
    where
        DeferredFrees: FnMut(&mut Theap) -> Result<(), E>,
        RetiredPages: FnMut(&mut Theap) -> Result<(), E>,
    {
        (self.deferred_frees)(theap)
            .map_err(TheapCollectAbandonFailure::DeferredFrees)?;
        (self.retired_pages)(theap)
            .map_err(TheapCollectAbandonFailure::RetiredPages)?;
        Ok(TheapCollectAbandonPageActionsReady(()))
    }
}

/// Evidence that the source deferred-free and retired-page prepasses finished.
///
/// Its field is private so only [`TheapCollectAbandonPrepass::run`] can create
/// it. Page callbacks borrow this proof, which makes the coordinator's source
/// ordering part of their type-level boundary.
pub(crate) struct TheapCollectAbandonPageActionsReady(());

/// One current page in the source `MI_ABANDON` traversal.
///
/// This capability is minted only after deferred-free then retired-page
/// collection. It deliberately omits the source bin and mutable Theap, so a
/// caller cannot turn this generic coordinator into a page-shape route or
/// bypass queue detachment before choosing the source all-free/live result.
pub(crate) struct TheapCollectAbandonCurrentPage<'ready> {
    page: NonNull<Page>,
    _prepass: &'ready TheapCollectAbandonPageActionsReady,
}

impl TheapCollectAbandonCurrentPage<'_> {
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> {
        self.page
    }
}

/// A page whose all-free source state was detached from its Theap queue.
///
/// The callback receives this only after intrusive removal, direct-cache
/// repair, and page-count transition. It owns no release algorithm: the
/// existing PageMap/backing release boundary remains responsible for that
/// source-specific work.
pub(crate) struct TheapCollectAbandonReleasedPage<'ready> {
    page: NonNull<Page>,
    theap: &'ready Theap,
    _prepass: &'ready TheapCollectAbandonPageActionsReady,
}

impl TheapCollectAbandonReleasedPage<'_> {
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> {
        self.page
    }

    /// Observes the source count after this page's one-way queue detach.
    #[inline]
    pub(crate) const fn page_count_after_detach(&self) -> usize {
        self.theap.page_count()
    }

    /// Observes the repaired direct-cache entry without exposing a mutable
    /// Theap or the source queue/bin used to reach this page.
    #[inline]
    pub(crate) fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.theap.direct_page(index)
    }
}

/// A page with live blocks whose source queue membership was detached.
///
/// This is the counterpart of [`TheapCollectAbandonReleasedPage`]. Its
/// callback publishes existing abandonment ownership; it does not duplicate
/// PageMap, bitmap, arena, or mapping-release logic here.
pub(crate) struct TheapCollectAbandonAbandonedPage<'ready> {
    page: NonNull<Page>,
    theap: &'ready Theap,
    _prepass: &'ready TheapCollectAbandonPageActionsReady,
}

impl TheapCollectAbandonAbandonedPage<'_> {
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> {
        self.page
    }

    /// Observes the source count after this page's one-way queue detach.
    #[inline]
    pub(crate) const fn page_count_after_detach(&self) -> usize {
        self.theap.page_count()
    }

    /// Observes the repaired direct-cache entry without exposing a mutable
    /// Theap or the source queue/bin used to reach this page.
    #[inline]
    pub(crate) fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.theap.direct_page(index)
    }
}

/// The point at which a generic owner-exit traversal became terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TheapCollectAbandonTerminalPhase {
    /// Deferred-free processing failed before retired-page collection.
    DeferredFrees,
    /// Retired-page collection failed before regular page traversal.
    RetiredPages,
    /// Per-page force/false collection failed while the page remained queued.
    CollectPage,
    /// The all-free release continuation failed after queue detachment.
    ReleasePage,
    /// The live-page abandonment continuation failed after queue detachment.
    AbandonPage,
    /// The exclusive complete-queue invariant was not preserved.
    QueueInvariant,
}

/// The non-forgeable state handed to a terminal-retention callback.
///
/// It describes whether the current page remains queued or was already
/// detached, without lending mutable queue or geometry authority. The one
/// returned [`TheapCollectAbandonRetainedOwner`] retains the exclusive Theap
/// borrow until the caller handles that terminal state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TheapCollectAbandonTerminalContext {
    phase: TheapCollectAbandonTerminalPhase,
    page: Option<NonNull<Page>>,
    page_detached: bool,
    remaining_page_count: usize,
}

impl TheapCollectAbandonTerminalContext {
    #[inline]
    pub(crate) const fn phase(&self) -> TheapCollectAbandonTerminalPhase {
        self.phase
    }

    #[inline]
    pub(crate) const fn page(&self) -> Option<NonNull<Page>> {
        self.page
    }

    #[inline]
    pub(crate) const fn page_is_detached(&self) -> bool {
        self.page_detached
    }

    #[inline]
    pub(crate) const fn remaining_page_count(&self) -> usize {
        self.remaining_page_count
    }
}

/// The caller's one retained terminal owner for a failed owner-exit drain.
///
/// The private lifetime marker keeps the exclusive Theap borrow tied to this
/// owner. A failure therefore cannot silently resume ordinary queue work with
/// a detached page or incomplete queue image still in flight.
#[must_use = "a failed collect-abandon drain must retain its unique terminal owner"]
#[derive(Debug)]
pub(crate) struct TheapCollectAbandonRetainedOwner<'theap, Owner> {
    owner: Owner,
    terminal: TheapCollectAbandonTerminalContext,
    _theap: PhantomData<&'theap mut Theap>,
}

impl<Owner> TheapCollectAbandonRetainedOwner<'_, Owner> {
    #[inline]
    pub(crate) fn owner(&self) -> &Owner {
        &self.owner
    }

    #[inline]
    pub(crate) fn owner_mut(&mut self) -> &mut Owner {
        &mut self.owner
    }

    #[inline]
    pub(crate) const fn terminal_context(&self) -> TheapCollectAbandonTerminalContext {
        self.terminal
    }
}

/// Failure from the generic queue half of `_mi_theap_collect_abandon`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TheapCollectAbandonFailure<E> {
    /// Deferred-free processing failed before retired-page collection.
    DeferredFrees(E),
    /// Retired-page collection failed before regular page traversal.
    RetiredPages(E),
    /// Page-local force/false collection failed before queue detachment.
    CollectPage(E),
    /// The all-free continuation failed after queue detachment.
    ReleasePage(E),
    /// The live-page abandonment continuation failed after queue detachment.
    AbandonPage(E),
    /// The caller violated the exclusive complete-queue invariant.
    QueueInvariant,
}

impl<E> TheapCollectAbandonFailure<E> {
    #[inline]
    const fn terminal_phase(&self) -> TheapCollectAbandonTerminalPhase {
        match self {
            Self::DeferredFrees(_) => TheapCollectAbandonTerminalPhase::DeferredFrees,
            Self::RetiredPages(_) => TheapCollectAbandonTerminalPhase::RetiredPages,
            Self::CollectPage(_) => TheapCollectAbandonTerminalPhase::CollectPage,
            Self::ReleasePage(_) => TheapCollectAbandonTerminalPhase::ReleasePage,
            Self::AbandonPage(_) => TheapCollectAbandonTerminalPhase::AbandonPage,
            Self::QueueInvariant => TheapCollectAbandonTerminalPhase::QueueInvariant,
        }
    }
}

/// A failed coordinator call always returns exactly one terminal owner.
///
/// The coordinator invokes [`TheapCollectAbandonCallbacks::retain_terminal`]
/// once for every error path, including prepass and queue-invariant failures.
/// It never retries another queue, invents a fresh page, or reattaches the
/// former owner.
#[derive(Debug)]
pub(crate) enum TheapCollectAbandonError<'theap, E, Owner> {
    Terminal {
        failure: TheapCollectAbandonFailure<E>,
        retained: TheapCollectAbandonRetainedOwner<'theap, Owner>,
    },
}

/// Source-order callbacks for one complete `MI_ABANDON` Theap traversal.
///
/// The coordinator alone runs deferred-free then retired-page prepasses,
/// selects every queue through `BIN_FULL`, and performs queue detach/direct
/// repair/page-count mutation. Callbacks receive opaque phase capabilities
/// instead of a bin or mutable Theap, so they cannot select a test geometry or
/// run release/abandon before that common source transition.
pub(crate) trait TheapCollectAbandonCallbacks {
    type Error;
    type Retained;

    /// Force/false-collect one current page and report only its source
    /// all-free versus still-live conclusion.
    fn collect_page(
        &mut self,
        page: TheapCollectAbandonCurrentPage<'_>,
    ) -> Result<TheapCollectAbandonPageAction, Self::Error>;

    /// Finish the existing release path for one all-free detached page.
    fn release_page(
        &mut self,
        page: TheapCollectAbandonReleasedPage<'_>,
    ) -> Result<(), Self::Error>;

    /// Publish existing abandonment ownership for one live detached page.
    fn abandon_page(
        &mut self,
        page: TheapCollectAbandonAbandonedPage<'_>,
    ) -> Result<(), Self::Error>;

    /// Retains the only terminal owner when the coordinator cannot finish.
    ///
    /// If `terminal.page_is_detached()` is true, the returned owner must keep
    /// that page's source state valid and fail closed; it must not attempt to
    /// reattach it to the departing Theap.
    fn retain_terminal(
        &mut self,
        terminal: TheapCollectAbandonTerminalContext,
    ) -> Self::Retained;
}

/// Visits the actual source queues for `MI_ABANDON` in pinned order.
///
/// This is the generic queue coordinator for
/// `_mi_theap_collect_abandon`. It runs
/// [`TheapCollectAbandonPrepass`] first, preserving source deferred-free then
/// retired-page order before it enters a [`TheapCollectAbandonCallbacks`]
/// page callback. The otherwise-unforgeable
/// [`TheapCollectAbandonPageActionsReady`] borrow makes that order part of the
/// callback capabilities. The helper then covers every queue through
/// `BIN_FULL`, saves the successor before a continuation can retire current
/// metadata, and performs the source queue mutation in the required order:
/// intrusive removal, direct-small cache repair, then Theap page-count
/// decrement.
///
/// This is intentionally not a public allocator entry point and does not
/// detach the Theap/TLD, choose a page geometry, publish an abandonment
/// bitmap, or duplicate PageMap/mapping release state. Those source-specific
/// lifetimes remain in the owner-exit layer that supplies the callbacks.
///
/// # Safety
///
/// `theap` must be initialized and exclusively owned for the whole call. Its
/// queues must be complete, acyclic, and contain only live initialized pages
/// after the prepass returns; each queue's count, endpoints, and backlinks must
/// match its membership. `theap.page_count` may be inconsistent only as a
/// fail-closed invariant input: no pointer validity may depend on that scalar,
/// and the coordinator will retain the partial drain terminally. Prepass
/// callbacks may perform only their source deferred-free or retired-page
/// transitions and must leave that valid exclusive queue image.
/// [`TheapCollectAbandonCallbacks::collect_page`] may mutate only current
/// page-local source state and must not alter queue links, queue membership,
/// direct-cache entries, or `theap.page_count`.
/// `release_page` and `abandon_page` may act only after this helper has
/// detached the current page. A failing continuation must leave enough state
/// for `retain_terminal` to retain one owner. No producer may race any
/// non-atomic page field or queue transition.
pub(crate) unsafe fn theap_collect_abandon_queues<'theap, DeferredFrees, RetiredPages, Callbacks>(
    theap: &'theap mut Theap,
    mut prepass: TheapCollectAbandonPrepass<DeferredFrees, RetiredPages>,
    callbacks: &mut Callbacks,
) -> Result<(), TheapCollectAbandonError<'theap, Callbacks::Error, Callbacks::Retained>>
where
    DeferredFrees: FnMut(&mut Theap) -> Result<(), Callbacks::Error>,
    RetiredPages: FnMut(&mut Theap) -> Result<(), Callbacks::Error>,
    Callbacks: TheapCollectAbandonCallbacks,
{
    // `mi_theap_collect_ex` runs this complete prepass even when the visitor
    // finds no pages, so the source empty fast path follows rather than
    // bypasses the typed prerequisite boundary.
    let page_actions_ready = match prepass.run(theap) {
        Ok(ready) => ready,
        Err(failure) => {
            return Err(theap_collect_abandon_terminal_failure(
                theap,
                callbacks,
                failure,
                None,
                false,
            ));
        }
    };

    // This is the source `mi_theap_visit_pages` fast empty case. Since this
    // boundary accepts `page_count` as a fallible aggregate, prove the actual
    // queue image is empty before trusting zero and returning successfully.
    if theap.page_count == 0 {
        for bin in 0..=BIN_FULL {
            let Some(queue) = theap.pages.get(bin) else {
                return Err(theap_collect_abandon_terminal_failure(
                    theap,
                    callbacks,
                    TheapCollectAbandonFailure::QueueInvariant,
                    None,
                    false,
                ));
            };
            if queue.count != 0 || !queue.first.is_null() || !queue.last.is_null() {
                return Err(theap_collect_abandon_terminal_failure(
                    theap,
                    callbacks,
                    TheapCollectAbandonFailure::QueueInvariant,
                    None,
                    false,
                ));
            }
        }
        return Ok(());
    }

    let expected_page_count = theap.page_count;
    let mut visited_page_count = 0usize;

    // `MI_ABANDON` passes `include_full = true`, unlike ordinary collection.
    for bin in 0..=BIN_FULL {
        let Some(queue) = theap.pages.get(bin) else {
            return Err(theap_collect_abandon_terminal_failure(
                theap,
                callbacks,
                TheapCollectAbandonFailure::QueueInvariant,
                None,
                false,
            ));
        };
        let mut remaining = queue.count;
        let mut current = queue.first;

        while remaining != 0 {
            let Some(page) = NonNull::new(current) else {
                return Err(theap_collect_abandon_terminal_failure(
                    theap,
                    callbacks,
                    TheapCollectAbandonFailure::QueueInvariant,
                    None,
                    false,
                ));
            };
            // SAFETY: the caller's queue-completeness and exclusive-owner
            // proof keeps the current page and its successor link valid.
            // Saving this edge is the source visitor's required protection
            // against either detached-page continuation retiring current
            // metadata.
            let next = unsafe { page.as_ref().next };
            let action = match callbacks.collect_page(TheapCollectAbandonCurrentPage {
                page,
                _prepass: &page_actions_ready,
            }) {
                Ok(action) => action,
                Err(error) => {
                    return Err(theap_collect_abandon_terminal_failure(
                        theap,
                        callbacks,
                        TheapCollectAbandonFailure::CollectPage(error),
                        Some(page),
                        false,
                    ));
                }
            };

            // SAFETY: the caller proves `page` remains a current member of
            // this exact complete queue; the current-page capability forbids
            // changing links or membership before this source removal.
            if let Err(detach) = unsafe { theap_collect_abandon_detach_page(theap, bin, page) } {
                return Err(theap_collect_abandon_terminal_failure(
                    theap,
                    callbacks,
                    TheapCollectAbandonFailure::QueueInvariant,
                    Some(page),
                    matches!(detach, TheapCollectAbandonDetachFailure::Detached),
                ));
            }

            match action {
                TheapCollectAbandonPageAction::Release => {
                    if let Err(error) = callbacks.release_page(TheapCollectAbandonReleasedPage {
                        page,
                        theap: &*theap,
                        _prepass: &page_actions_ready,
                    }) {
                        return Err(theap_collect_abandon_terminal_failure(
                            theap,
                            callbacks,
                            TheapCollectAbandonFailure::ReleasePage(error),
                            Some(page),
                            true,
                        ));
                    }
                }
                TheapCollectAbandonPageAction::Abandon => {
                    if let Err(error) = callbacks.abandon_page(TheapCollectAbandonAbandonedPage {
                        page,
                        theap: &*theap,
                        _prepass: &page_actions_ready,
                    }) {
                        return Err(theap_collect_abandon_terminal_failure(
                            theap,
                            callbacks,
                            TheapCollectAbandonFailure::AbandonPage(error),
                            Some(page),
                            true,
                        ));
                    }
                }
            }

            let Some(next_visited_page_count) = visited_page_count.checked_add(1) else {
                return Err(theap_collect_abandon_terminal_failure(
                    theap,
                    callbacks,
                    TheapCollectAbandonFailure::QueueInvariant,
                    None,
                    false,
                ));
            };
            visited_page_count = next_visited_page_count;
            current = next;
            remaining -= 1;
        }

        if !current.is_null() {
            return Err(theap_collect_abandon_terminal_failure(
                theap,
                callbacks,
                TheapCollectAbandonFailure::QueueInvariant,
                NonNull::new(current),
                false,
            ));
        }
    }

    if visited_page_count != expected_page_count || theap.page_count != 0 {
        return Err(theap_collect_abandon_terminal_failure(
            theap,
            callbacks,
            TheapCollectAbandonFailure::QueueInvariant,
            None,
            false,
        ));
    }
    Ok(())
}

/// Converts one failed source transition into its single retained terminal
/// owner. The lifetime marker in that owner keeps the exclusive Theap borrow
/// unavailable to ordinary queue operations until the caller resolves the
/// failure.
fn theap_collect_abandon_terminal_failure<'theap, Callbacks>(
    theap: &'theap mut Theap,
    callbacks: &mut Callbacks,
    failure: TheapCollectAbandonFailure<Callbacks::Error>,
    page: Option<NonNull<Page>>,
    page_detached: bool,
) -> TheapCollectAbandonError<'theap, Callbacks::Error, Callbacks::Retained>
where
    Callbacks: TheapCollectAbandonCallbacks,
{
    let terminal = TheapCollectAbandonTerminalContext {
        phase: failure.terminal_phase(),
        page,
        page_detached,
        remaining_page_count: theap.page_count(),
    };
    let owner = callbacks.retain_terminal(terminal);
    TheapCollectAbandonError::Terminal {
        failure,
        retained: TheapCollectAbandonRetainedOwner {
            owner,
            terminal,
            _theap: PhantomData,
        },
    }
}

/// Whether failure occurred before or after one page's queue detach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TheapCollectAbandonDetachFailure {
    StillQueued,
    Detached,
}

/// Removes one current queue member as the common queue half of source
/// `_mi_page_free` or `_mi_page_abandon` during Theap owner exit.
///
/// The direct cache must reflect the new queue head before `page_count`
/// changes. Keeping those operations together prevents a caller-selected
/// page-shape wrapper from accidentally repairing only direct-small paths.
unsafe fn theap_collect_abandon_detach_page(
    theap: &mut Theap,
    bin: usize,
    page: NonNull<Page>,
) -> Result<(), TheapCollectAbandonDetachFailure> {
    let Some(queue) = theap.pages.get_mut(bin) else {
        return Err(TheapCollectAbandonDetachFailure::StillQueued);
    };
    let queue = queue as *mut PageQueue;
    // SAFETY: the caller proves this is a valid exclusive current membership.
    unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
    if !theap_collect_abandon_update_direct_cache(theap, bin) {
        return Err(TheapCollectAbandonDetachFailure::Detached);
    }
    if !theap.note_page_removed() {
        return Err(TheapCollectAbandonDetachFailure::Detached);
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
    extern crate std;

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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MixedCollectAbandonEvent {
        DeferredFrees,
        RetiredPages,
        Collect(NonNull<Page>, usize, usize),
        Release(NonNull<Page>, usize, Option<*mut Page>),
        Abandon(NonNull<Page>, usize, Option<*mut Page>),
    }

    struct MixedCollectAbandonCallbacks<'a> {
        small_direct: usize,
        events: &'a core::cell::RefCell<std::vec::Vec<MixedCollectAbandonEvent>>,
        terminal_calls: &'a core::cell::Cell<usize>,
    }

    impl TheapCollectAbandonCallbacks for MixedCollectAbandonCallbacks<'_> {
        type Error = ();
        type Retained = ();

        fn collect_page(
            &mut self,
            page: TheapCollectAbandonCurrentPage<'_>,
        ) -> Result<TheapCollectAbandonPageAction, Self::Error> {
            let page = page.page();
            // SAFETY: every synthetic producer has joined before the source
            // owner begins this traversal. The test keeps the page and all
            // published blocks live and gives this callback sole access to
            // the page-local owner fields.
            let collected = unsafe { crate::remote_free::collect(page) }
                .expect("the source owner force-collects the joined remote list");
            // SAFETY: the same joined-producer and exclusive-owner proof makes
            // the post-collection `used` observation stable.
            let used = unsafe { page.as_ref() }.remote_free_test_used();
            self.events.borrow_mut().push(MixedCollectAbandonEvent::Collect(
                page, collected, used,
            ));
            Ok(if used == 0 {
                TheapCollectAbandonPageAction::Release
            } else {
                TheapCollectAbandonPageAction::Abandon
            })
        }

        fn release_page(
            &mut self,
            page: TheapCollectAbandonReleasedPage<'_>,
        ) -> Result<(), Self::Error> {
            self.events.borrow_mut().push(MixedCollectAbandonEvent::Release(
                page.page(),
                page.page_count_after_detach(),
                page.direct_page(self.small_direct),
            ));
            Ok(())
        }

        fn abandon_page(
            &mut self,
            page: TheapCollectAbandonAbandonedPage<'_>,
        ) -> Result<(), Self::Error> {
            // SAFETY: the coordinator detached this page and the test retains
            // its sole metadata owner. Marking the synthetic page abandoned
            // represents the source publication performed by this callback.
            unsafe { page.page().as_mut() }.remote_free_test_mark_abandoned();
            self.events.borrow_mut().push(MixedCollectAbandonEvent::Abandon(
                page.page(),
                page.page_count_after_detach(),
                page.direct_page(self.small_direct),
            ));
            Ok(())
        }

        fn retain_terminal(
            &mut self,
            _terminal: TheapCollectAbandonTerminalContext,
        ) -> Self::Retained {
            self.terminal_calls.set(self.terminal_calls.get() + 1);
        }
    }

    #[repr(align(16))]
    struct MixedCollectAbandonRemoteBlock([u8; 16]);

    impl MixedCollectAbandonRemoteBlock {
        fn pointer(&mut self) -> NonNull<u8> {
            NonNull::from(&mut self.0).cast()
        }
    }

    fn remotely_freed_page(block_size: usize, used: usize) -> Page {
        let mut page = Page::remote_free_test_page(
            u16::try_from(used).expect("the focused test page fits source capacity"),
            used,
        );
        page.block_size = block_size;
        page
    }

    #[test]
    fn generic_collect_abandon_drains_a_mixed_theap_in_source_order() {
        let mut theap = Theap::empty();
        let small_bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let medium_bin = crate::size_class::bin(LARGE_MAX_OBJ_SIZE / 2)
            .expect("medium size has a regular bin");
        assert!(small_bin < medium_bin && medium_bin < BIN_FULL);

        let small_size = theap.queue(small_bin).unwrap().block_size();
        let medium_size = theap.queue(medium_bin).unwrap().block_size();
        let mut small_first = remotely_freed_page(small_size, 1);
        let mut small_second = remotely_freed_page(small_size, 2);
        let mut medium = remotely_freed_page(medium_size, 1);
        let mut full = remotely_freed_page(medium_size, 1);
        let small_first = NonNull::from(&mut small_first);
        let small_second = NonNull::from(&mut small_second);
        let medium = NonNull::from(&mut medium);
        let full = NonNull::from(&mut full);

        // SAFETY: the four local pages begin detached and the test owns the
        // complete source queue image while it assembles it.
        unsafe {
            page_queue_push_at_end_metadata(
                theap.queue_mut(small_bin).unwrap(),
                small_first.as_ptr(),
            );
            page_queue_push_at_end_metadata(
                theap.queue_mut(small_bin).unwrap(),
                small_second.as_ptr(),
            );
            page_queue_push_at_end_metadata(theap.queue_mut(medium_bin).unwrap(), medium.as_ptr());
            page_queue_push_at_end_metadata(theap.queue_mut(BIN_FULL).unwrap(), full.as_ptr());
        }
        for _ in 0..4 {
            theap.note_page_added();
        }
        assert!(theap_collect_abandon_update_direct_cache(&mut theap, small_bin));
        let small_direct = invariants::word_count(small_size).unwrap();
        assert_eq!(theap.direct_page(small_direct), Some(small_first.as_ptr()));
        assert!(page_is_in_full(unsafe { full.as_ref() }));

        let mut small_first_remote = MixedCollectAbandonRemoteBlock([0; 16]);
        let mut small_second_remote = MixedCollectAbandonRemoteBlock([0; 16]);
        let mut medium_remote = MixedCollectAbandonRemoteBlock([0; 16]);
        let mut full_remote = MixedCollectAbandonRemoteBlock([0; 16]);
        // SAFETY: each block and its exact live owner-associated page stay
        // pinned until the coordinator has collected all four joined remote
        // publications. Every block is published exactly once.
        unsafe {
            crate::remote_free::push(small_first, small_first_remote.pointer()).unwrap();
            crate::remote_free::push(small_second, small_second_remote.pointer()).unwrap();
            crate::remote_free::push(medium, medium_remote.pointer()).unwrap();
            crate::remote_free::push(full, full_remote.pointer()).unwrap();
        }

        let events = core::cell::RefCell::new(std::vec::Vec::new());
        let terminal_calls = core::cell::Cell::new(0usize);
        let mut callbacks = MixedCollectAbandonCallbacks {
            small_direct,
            events: &events,
            terminal_calls: &terminal_calls,
        };

        // SAFETY: the test has exclusive access to the complete, acyclic
        // mixed queue image. The typed callbacks can only choose all-free or
        // live-page continuations; the coordinator owns the queue transitions.
        assert!(unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                TheapCollectAbandonPrepass::new(
                    |theap: &mut Theap| {
                        assert_eq!(theap.page_count(), 4);
                        events
                            .borrow_mut()
                            .push(MixedCollectAbandonEvent::DeferredFrees);
                        Ok::<_, ()>(())
                    },
                    |theap: &mut Theap| {
                        assert_eq!(theap.page_count(), 4);
                        events
                            .borrow_mut()
                            .push(MixedCollectAbandonEvent::RetiredPages);
                        Ok::<_, ()>(())
                    },
                ),
                &mut callbacks,
            )
            .is_ok()
        });

        assert_eq!(
            events.into_inner(),
            std::vec![
                MixedCollectAbandonEvent::DeferredFrees,
                MixedCollectAbandonEvent::RetiredPages,
                MixedCollectAbandonEvent::Collect(small_first, 1, 0),
                MixedCollectAbandonEvent::Release(
                    small_first,
                    3,
                    Some(small_second.as_ptr()),
                ),
                MixedCollectAbandonEvent::Collect(small_second, 1, 1),
                MixedCollectAbandonEvent::Abandon(
                    small_second,
                    2,
                    Some(EMPTY_PAGE.as_ptr()),
                ),
                MixedCollectAbandonEvent::Collect(medium, 1, 0),
                MixedCollectAbandonEvent::Release(
                    medium,
                    1,
                    Some(EMPTY_PAGE.as_ptr()),
                ),
                MixedCollectAbandonEvent::Collect(full, 1, 0),
                MixedCollectAbandonEvent::Release(full, 0, Some(EMPTY_PAGE.as_ptr())),
            ],
            "deferred then retired prepasses precede remote collection and every release/abandon continuation through BIN_FULL"
        );
        assert_eq!(terminal_calls.get(), 0);
        assert!(theap.queue(small_bin).unwrap().is_empty());
        assert!(theap.queue(medium_bin).unwrap().is_empty());
        assert!(theap.queue(BIN_FULL).unwrap().is_empty());
        assert_eq!(theap.page_count(), 0);
        assert!(!page_is_in_full(unsafe { full.as_ref() }));
    }

    #[derive(Debug, Eq, PartialEq)]
    enum TerminalFailure {
        AbandonPublication,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct TerminalOwner {
        retain_call: usize,
    }

    struct TerminalFailureCallbacks<'a> {
        only: NonNull<Page>,
        small_direct: usize,
        abandon_transition: &'a core::cell::Cell<Option<(usize, Option<*mut Page>)>>,
        retain_calls: &'a core::cell::Cell<usize>,
    }

    impl TheapCollectAbandonCallbacks for TerminalFailureCallbacks<'_> {
        type Error = TerminalFailure;
        type Retained = TerminalOwner;

        fn collect_page(
            &mut self,
            page: TheapCollectAbandonCurrentPage<'_>,
        ) -> Result<TheapCollectAbandonPageAction, Self::Error> {
            assert_eq!(page.page(), self.only);
            Ok(TheapCollectAbandonPageAction::Abandon)
        }

        fn release_page(
            &mut self,
            _page: TheapCollectAbandonReleasedPage<'_>,
        ) -> Result<(), Self::Error> {
            panic!("the live page must select only the abandonment continuation")
        }

        fn abandon_page(
            &mut self,
            page: TheapCollectAbandonAbandonedPage<'_>,
        ) -> Result<(), Self::Error> {
            assert_eq!(page.page(), self.only);
            self.abandon_transition.set(Some((
                page.page_count_after_detach(),
                page.direct_page(self.small_direct),
            )));
            Err(TerminalFailure::AbandonPublication)
        }

        fn retain_terminal(
            &mut self,
            terminal: TheapCollectAbandonTerminalContext,
        ) -> Self::Retained {
            assert_eq!(terminal.phase(), TheapCollectAbandonTerminalPhase::AbandonPage);
            assert_eq!(terminal.page(), Some(self.only));
            assert!(terminal.page_is_detached());
            assert_eq!(terminal.remaining_page_count(), 0);
            let retain_call = self.retain_calls.get() + 1;
            self.retain_calls.set(retain_call);
            TerminalOwner { retain_call }
        }
    }

    #[test]
    fn generic_collect_abandon_terminal_failure_retains_one_detached_owner() {
        let mut theap = Theap::empty();
        let bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let block_size = theap.queue(bin).unwrap().block_size();
        let mut only = page(block_size);
        let only = NonNull::from(&mut only);
        // SAFETY: the local page begins detached and this test owns the
        // complete one-member source queue image.
        unsafe { page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), only.as_ptr()) };
        theap.note_page_added();
        assert!(theap_collect_abandon_update_direct_cache(&mut theap, bin));
        let small_direct = invariants::word_count(block_size).unwrap();

        let abandon_transition = core::cell::Cell::new(None);
        let retain_calls = core::cell::Cell::new(0usize);
        let mut callbacks = TerminalFailureCallbacks {
            only,
            small_direct,
            abandon_transition: &abandon_transition,
            retain_calls: &retain_calls,
        };

        // SAFETY: the local image is complete and exclusive. The injected
        // failure leaves the detached page untouched so the terminal owner can
        // retain it instead of fabricating a retry or reattachment.
        let result = unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                TheapCollectAbandonPrepass::new(
                    |_theap: &mut Theap| Ok::<_, TerminalFailure>(()),
                    |_theap: &mut Theap| Ok::<_, TerminalFailure>(()),
                ),
                &mut callbacks,
            )
        };

        let retained = match result {
            Err(TheapCollectAbandonError::Terminal { failure, retained }) => {
                assert_eq!(
                    failure,
                    TheapCollectAbandonFailure::AbandonPage(
                        TerminalFailure::AbandonPublication,
                    ),
                );
                retained
            }
            Ok(()) => panic!("the injected abandonment-publication failure must be terminal"),
        };
        assert_eq!(
            abandon_transition.get(),
            Some((0, Some(EMPTY_PAGE.as_ptr()))),
            "the terminal callback observes direct-cache repair before page-count transition completes"
        );
        assert_eq!(retain_calls.get(), 1);
        assert_eq!(retained.owner(), &TerminalOwner { retain_call: 1 });
        assert_eq!(
            retained.terminal_context().phase(),
            TheapCollectAbandonTerminalPhase::AbandonPage,
        );
        assert!(retained.terminal_context().page_is_detached());
        assert!(unsafe { only.as_ref() }.is_queue_detached());

        drop(retained);
        assert_eq!(theap.page_count(), 0);
        assert!(theap.queue(bin).unwrap().is_empty());
        assert_eq!(theap.direct_page(small_direct), Some(EMPTY_PAGE.as_ptr()));
    }

    #[test]
    fn generic_collect_abandon_prepass_failure_retains_the_untouched_owner() {
        let mut theap = Theap::empty();
        let bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let block_size = theap.queue(bin).unwrap().block_size();
        let mut only = page(block_size);
        let only = NonNull::from(&mut only);
        // SAFETY: this test exclusively constructs one complete source queue
        // and keeps its page live through the rejected prepass.
        unsafe { page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), only.as_ptr()) };
        theap.note_page_added();
        assert!(theap_collect_abandon_update_direct_cache(&mut theap, bin));
        let small_direct = invariants::word_count(block_size).unwrap();
        let mut callbacks = QueueInvariantCallbacks {
            terminal_calls: core::cell::Cell::new(0),
        };

        // SAFETY: the queue image is valid and exclusive. The injected
        // deferred-free failure occurs before either queue or page callback
        // may mutate it.
        let result = unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                TheapCollectAbandonPrepass::new(
                    |_theap: &mut Theap| Err::<(), _>(()),
                    |_theap: &mut Theap| panic!("retired collection cannot follow deferred failure"),
                ),
                &mut callbacks,
            )
        };
        let retained = match result {
            Err(TheapCollectAbandonError::Terminal { failure, retained }) => {
                assert_eq!(failure, TheapCollectAbandonFailure::DeferredFrees(()));
                retained
            }
            Ok(()) => panic!("the injected prepass failure must retain the untouched owner"),
        };
        assert_eq!(callbacks.terminal_calls.get(), 1);
        assert_eq!(
            retained.owner().phase(),
            TheapCollectAbandonTerminalPhase::DeferredFrees,
        );
        assert_eq!(retained.owner().page(), None);
        assert!(!retained.owner().page_is_detached());
        assert_eq!(retained.owner().remaining_page_count(), 1);
        drop(retained);
        assert_eq!(theap.page_count(), 1);
        assert_eq!(theap.direct_page(small_direct), Some(only.as_ptr()));
        // SAFETY: no prepass or page action mutated the complete queue image.
        unsafe { assert_queue(theap.queue(bin).unwrap(), &[only.as_ptr()]) };
    }

    struct MidDrainFailureCallbacks {
        first: NonNull<Page>,
        second: NonNull<Page>,
        small_direct: usize,
        collect_calls: usize,
        release_calls: usize,
        terminal_calls: usize,
    }

    impl TheapCollectAbandonCallbacks for MidDrainFailureCallbacks {
        type Error = TerminalFailure;
        type Retained = TheapCollectAbandonTerminalContext;

        fn collect_page(
            &mut self,
            page: TheapCollectAbandonCurrentPage<'_>,
        ) -> Result<TheapCollectAbandonPageAction, Self::Error> {
            self.collect_calls += 1;
            if page.page() == self.first {
                Ok(TheapCollectAbandonPageAction::Release)
            } else {
                assert_eq!(page.page(), self.second);
                Err(TerminalFailure::AbandonPublication)
            }
        }

        fn release_page(
            &mut self,
            page: TheapCollectAbandonReleasedPage<'_>,
        ) -> Result<(), Self::Error> {
            assert_eq!(page.page(), self.first);
            assert_eq!(page.page_count_after_detach(), 1);
            assert_eq!(page.direct_page(self.small_direct), Some(self.second.as_ptr()));
            self.release_calls += 1;
            Ok(())
        }

        fn abandon_page(
            &mut self,
            _page: TheapCollectAbandonAbandonedPage<'_>,
        ) -> Result<(), Self::Error> {
            panic!("the second page fails during collection while still queued")
        }

        fn retain_terminal(
            &mut self,
            terminal: TheapCollectAbandonTerminalContext,
        ) -> Self::Retained {
            self.terminal_calls += 1;
            terminal
        }
    }

    #[test]
    fn generic_collect_abandon_mid_drain_failure_retains_the_remaining_queue() {
        let mut theap = Theap::empty();
        let bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let block_size = theap.queue(bin).unwrap().block_size();
        let mut first = page(block_size);
        let mut second = page(block_size);
        let first = NonNull::from(&mut first);
        let second = NonNull::from(&mut second);
        // SAFETY: the two pages begin detached and the test owns their one
        // complete acyclic source queue throughout the partial drain.
        unsafe {
            page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), first.as_ptr());
            page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), second.as_ptr());
        }
        theap.note_page_added();
        theap.note_page_added();
        assert!(theap_collect_abandon_update_direct_cache(&mut theap, bin));
        let small_direct = invariants::word_count(block_size).unwrap();
        let mut callbacks = MidDrainFailureCallbacks {
            first,
            second,
            small_direct,
            collect_calls: 0,
            release_calls: 0,
            terminal_calls: 0,
        };

        // SAFETY: the source queue is complete and exclusive. The injected
        // second-page collection failure happens before that page's one-way
        // detach, while the first page's successful release remains final.
        let result = unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                TheapCollectAbandonPrepass::new(
                    |_theap: &mut Theap| Ok::<_, TerminalFailure>(()),
                    |_theap: &mut Theap| Ok::<_, TerminalFailure>(()),
                ),
                &mut callbacks,
            )
        };
        let retained = match result {
            Err(TheapCollectAbandonError::Terminal { failure, retained }) => {
                assert_eq!(
                    failure,
                    TheapCollectAbandonFailure::CollectPage(
                        TerminalFailure::AbandonPublication,
                    ),
                );
                retained
            }
            Ok(()) => panic!("the injected mid-drain collection failure must be terminal"),
        };
        assert_eq!(callbacks.collect_calls, 2);
        assert_eq!(callbacks.release_calls, 1);
        assert_eq!(callbacks.terminal_calls, 1);
        assert_eq!(retained.owner().page(), Some(second));
        assert_eq!(
            retained.owner().phase(),
            TheapCollectAbandonTerminalPhase::CollectPage,
        );
        assert!(!retained.owner().page_is_detached());
        assert_eq!(retained.owner().remaining_page_count(), 1);
        assert!(unsafe { first.as_ref() }.is_queue_detached());
        drop(retained);
        assert_eq!(theap.page_count(), 1);
        assert_eq!(theap.direct_page(small_direct), Some(second.as_ptr()));
        // SAFETY: the failed current page never left this one-member queue.
        unsafe { assert_queue(theap.queue(bin).unwrap(), &[second.as_ptr()]) };
    }

    struct QueueInvariantCallbacks {
        terminal_calls: core::cell::Cell<usize>,
    }

    impl TheapCollectAbandonCallbacks for QueueInvariantCallbacks {
        type Error = ();
        type Retained = TheapCollectAbandonTerminalContext;

        fn collect_page(
            &mut self,
            _page: TheapCollectAbandonCurrentPage<'_>,
        ) -> Result<TheapCollectAbandonPageAction, Self::Error> {
            Ok(TheapCollectAbandonPageAction::Release)
        }

        fn release_page(
            &mut self,
            _page: TheapCollectAbandonReleasedPage<'_>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn abandon_page(
            &mut self,
            _page: TheapCollectAbandonAbandonedPage<'_>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn retain_terminal(
            &mut self,
            terminal: TheapCollectAbandonTerminalContext,
        ) -> Self::Retained {
            self.terminal_calls.set(self.terminal_calls.get() + 1);
            terminal
        }
    }

    #[test]
    fn generic_collect_abandon_retains_a_page_count_invariant_failure() {
        let mut theap = Theap::empty();
        let bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let block_size = theap.queue(bin).unwrap().block_size();
        let mut only = page(block_size);
        let only = NonNull::from(&mut only);

        // SAFETY: the page is initially detached and locally owned. The
        // queue itself stays complete and valid; only the separate Theap
        // aggregate is made inconsistent for this fail-closed audit.
        unsafe { page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), only.as_ptr()) };
        theap.note_page_added();
        theap.note_page_added();
        let mut callbacks = QueueInvariantCallbacks {
            terminal_calls: core::cell::Cell::new(0),
        };

        // SAFETY: all queue links, membership counts, and endpoints remain
        // valid and exclusive. Only `theap.page_count` is inconsistent, which
        // this coordinator explicitly accepts as a typed fail-closed input.
        let result = unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                TheapCollectAbandonPrepass::new(
                    |_theap: &mut Theap| Ok::<_, ()>(()),
                    |_theap: &mut Theap| Ok::<_, ()>(()),
                ),
                &mut callbacks,
            )
        };
        let retained = match result {
            Err(TheapCollectAbandonError::Terminal { failure, retained }) => {
                assert_eq!(failure, TheapCollectAbandonFailure::QueueInvariant);
                retained
            }
            Ok(()) => panic!("the malformed queue must be retained terminally"),
        };
        assert_eq!(callbacks.terminal_calls.get(), 1);
        assert_eq!(
            retained.owner().phase(),
            TheapCollectAbandonTerminalPhase::QueueInvariant,
        );
        assert_eq!(retained.owner().remaining_page_count(), 1);
        drop(retained);
        assert_eq!(theap.page_count(), 1);
        assert!(theap.queue(bin).unwrap().is_empty());
    }

    #[test]
    fn generic_collect_abandon_rejects_a_false_empty_page_count_without_detaching() {
        let mut theap = Theap::empty();
        let bin = crate::size_class::bin(16).expect("small size has a regular bin");
        let block_size = theap.queue(bin).unwrap().block_size();
        let mut only = page(block_size);
        let only = NonNull::from(&mut only);

        // SAFETY: the page is initially detached and locally owned. This
        // creates one valid non-empty queue while deliberately leaving the
        // separate aggregate `page_count` at zero.
        unsafe { page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), only.as_ptr()) };
        let mut callbacks = QueueInvariantCallbacks {
            terminal_calls: core::cell::Cell::new(0),
        };

        // SAFETY: queue links, membership count, endpoints, and ownership are
        // valid and exclusive. Only the accepted fallible aggregate is false.
        let result = unsafe {
            theap_collect_abandon_queues(
                &mut theap,
                TheapCollectAbandonPrepass::new(
                    |_theap: &mut Theap| Ok::<_, ()>(()),
                    |_theap: &mut Theap| Ok::<_, ()>(()),
                ),
                &mut callbacks,
            )
        };
        let retained = match result {
            Err(TheapCollectAbandonError::Terminal { failure, retained }) => {
                assert_eq!(failure, TheapCollectAbandonFailure::QueueInvariant);
                retained
            }
            Ok(()) => panic!("the false empty aggregate must be retained terminally"),
        };
        assert_eq!(callbacks.terminal_calls.get(), 1);
        assert_eq!(retained.owner().page(), None);
        assert!(!retained.owner().page_is_detached());
        assert_eq!(retained.owner().remaining_page_count(), 0);
        drop(retained);
        assert_eq!(theap.page_count(), 0);
        // SAFETY: the fail-closed fast-path audit cannot detach the page.
        unsafe { assert_queue(theap.queue(bin).unwrap(), &[only.as_ptr()]) };
    }

    #[test]
    fn generic_collect_direct_cache_updates_the_rounded_small_bin_aliases() {
        let mut theap = Theap::empty();
        // Pinned `mi_bin` rounds the three-word size in queue 3 into queue
        // 4. Therefore `mi_theap_queue_first_update(&pages[4])` must refresh
        // both direct entries 3 and 4, skipping back over the alias rather
        // than starting at `pages[4]`'s own rounded size alone.
        let bin = 4;
        let block_size = theap.queue(bin).unwrap().block_size();
        assert_eq!(invariants::word_count(block_size), Some(4));
        assert_eq!(crate::size_class::bin(block_size), Some(bin));
        assert_eq!(
            crate::size_class::bin(theap.queue(bin - 1).unwrap().block_size()),
            Some(bin),
            "the immediately preceding source queue aliases this rounded small bin"
        );
        assert_ne!(
            crate::size_class::bin(theap.queue(bin - 2).unwrap().block_size()),
            Some(bin),
            "the next predecessor establishes the source direct-cache boundary"
        );

        let mut page = page(block_size);
        let page = NonNull::from(&mut page);
        // SAFETY: the local page begins detached and this focused test owns
        // the complete one-member source queue image.
        unsafe { page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), page.as_ptr()) };

        assert!(theap_collect_abandon_update_direct_cache(&mut theap, bin));
        assert_eq!(theap.direct_page(2), Some(EMPTY_PAGE.as_ptr()));
        assert_eq!(theap.direct_page(3), Some(page.as_ptr()));
        assert_eq!(theap.direct_page(4), Some(page.as_ptr()));
        assert_eq!(theap.direct_page(5), Some(EMPTY_PAGE.as_ptr()));
    }

    #[test]
    fn generic_collect_direct_cache_stops_at_the_predecessor_bin_boundary() {
        let mut theap = Theap::empty();
        // At queue 9, the direct table's index is ten words. The preceding
        // queue has the eight-word size and belongs to bin 8, so the pinned
        // source starts the update at direct index 9. It must retain the
        // predecessor's entries 7 and 8 rather than overwriting from zero.
        let previous_bin = 8;
        let bin = 9;
        let previous_size = theap.queue(previous_bin).unwrap().block_size();
        let block_size = theap.queue(bin).unwrap().block_size();
        assert_eq!(invariants::word_count(previous_size), Some(8));
        assert_eq!(invariants::word_count(block_size), Some(10));
        assert_eq!(crate::size_class::bin(previous_size), Some(previous_bin));
        assert_eq!(crate::size_class::bin(block_size), Some(bin));

        let mut previous = page(previous_size);
        let mut page = page(block_size);
        let previous = NonNull::from(&mut previous);
        let page = NonNull::from(&mut page);
        // SAFETY: both pages are detached and each queue has one local,
        // exclusively owned member for this direct-cache source test.
        unsafe {
            page_queue_push_at_end_metadata(
                theap.queue_mut(previous_bin).unwrap(),
                previous.as_ptr(),
            );
            page_queue_push_at_end_metadata(theap.queue_mut(bin).unwrap(), page.as_ptr());
        }

        assert!(theap_collect_abandon_update_direct_cache(&mut theap, previous_bin));
        assert!(theap_collect_abandon_update_direct_cache(&mut theap, bin));
        assert_eq!(theap.direct_page(6), Some(EMPTY_PAGE.as_ptr()));
        assert_eq!(theap.direct_page(7), Some(previous.as_ptr()));
        assert_eq!(theap.direct_page(8), Some(previous.as_ptr()));
        assert_eq!(theap.direct_page(9), Some(page.as_ptr()));
        assert_eq!(theap.direct_page(10), Some(page.as_ptr()));
        assert_eq!(theap.direct_page(11), Some(EMPTY_PAGE.as_ptr()));
    }
}
