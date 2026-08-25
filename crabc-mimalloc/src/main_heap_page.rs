// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:236-360,377-421,448-481`,
// `src/theap.c:89-152`, `src/page.c:214-302,414-518,574-644`,
// `src/page-queue.c:204-330`,
// `src/arena.c:631-778,781-821,870-1037,951-1153,1183-1204,1240-1282`, and
// `src/page-map.c:228-365`, and `src/free.c:372-514`.

//! Page-bearing later-thread attachment to the source static main Heap.
//!
//! The normal source `_mi_thread_init_with_heap(mi_heap_main())` branch gives
//! every later thread a metadata TLD/Theap but keeps the one process-static
//! main Heap. `MainHeapThreadProcessPageAllocator` joins that exact later
//! owner to the same frozen process PageMap/arena pair used by the bounded
//! ticket-zero page owner. It holds the pair's exclusive Rust PageMap
//! lifecycle lease for its complete engine and scoped remote-producer
//! lifetime, and uses the selected arena's in-place `pages_main` bitmap.
//!
//! This is deliberately one sequential later-thread page lifecycle, not
//! process initialization, a dynamic heap-local bitmap path, or pthread
//! integration. In addition to its normal empty finish, it owns one first
//! source-shaped `_mi_thread_done` boundary: a consuming exit drain clears the
//! fixed main fast slot, force-collects every queue, and releases only pages
//! that become all-free before returning to attachment root/list/TLD teardown.
//! Eight disjoint sole-page exceptions retain their PageMap/arena ownership
//! through final client frees: a full arena singleton, an OS-aligned
//! singleton, a mapped one-block medium,
//! full medium and full large pages, full non-direct and direct small pages,
//! and a nonfull small-or-medium page. The full regular cases begin unmapped
//! and reabandon into the static-main bitmap only after source's mostly-used
//! threshold; the nonfull route becomes a typed process route before its old
//! Theap/TLD tears down. A separate aggregate exception first
//! force-releases tracked retired regular pages, then source-traverses every
//! remaining live nonfull regular small, medium, or large arena page only when
//! every queued member has that supported shape: it releases pages made empty
//! by force collection and registers every survivor in one linear process
//! route. Each route free serializes its plain PageMap operation briefly. One
//! explicit consuming edge additionally reclaims only the sole mapped nonfull
//! medium route into a fresh later-main engine: it claims that exact bitmap
//! member and requeues it at the source tail. Its test-only real reserved
//! on-demand medium prefix commits its next page area directly before extension;
//! a direct-commit failure reabandones that same candidate for its one consuming
//! retry. It has no automatic allocation scan or fresh-page fallback.
//! Small/direct, full, aggregate, concurrent,
//! singleton, unmapped, and huge adoption remain absent, as do source deferred
//! callbacks and arena collection.

use core::ptr::NonNull;

use crate::arena::ArenaId;
use crate::main_heap_thread::{
    MainHeapThreadAttachment, MainHeapThreadAttachmentError, MainHeapThreadPageDrainSession,
    MainHeapThreadPageSession, MainHeapThreadPageSessionError,
};
use crate::process_arena::{ProcessPageArenaLease, ProcessPageArenaLeaseError};
use crate::process_page_map::{
    ProcessPageMapError, ProcessPageMapMutationLease, ProcessPageMapPostExitAccess,
};
use crate::single_thread::{
    FreeError, PageAllocatorEngine, RemoteFreePreparationError, RemoteFreeProducer,
    ThreadExitMappedRegularPostExitAdoptError,
    ThreadExitMappedRegularPostExitAdoptOutcome,
    ThreadExitMappedRegularPostExitAbandonError,
    ThreadExitMappedRegularPostExitAbandonFailure,
    ThreadExitMappedRegularPostExitFreeError,
    ThreadExitMappedRegularPostExitFreeOutcome,
    ThreadExitMappedRegularPostExitParts,
    ThreadExitMappedRegularPostExitTeardownTerminal,
    ThreadExitFullMediumPostExitAbandonError,
    ThreadExitFullMediumPostExitAbandonFailure,
    ThreadExitFullMediumPostExitFreeError,
    ThreadExitFullMediumPostExitFreeOutcome,
    ThreadExitFullMediumPostExitParts,
    ThreadExitFullMediumPostExitTeardownTerminal,
    ThreadExitFullLargePostExitAbandonError,
    ThreadExitFullLargePostExitAbandonFailure,
    ThreadExitFullLargePostExitFreeError,
    ThreadExitFullLargePostExitFreeOutcome,
    ThreadExitFullLargePostExitParts,
    ThreadExitFullLargePostExitTeardownTerminal,
    ThreadExitFullDirectSmallPostExitAbandonError,
    ThreadExitFullDirectSmallPostExitAbandonFailure,
    ThreadExitFullDirectSmallPostExitFreeError,
    ThreadExitFullDirectSmallPostExitFreeOutcome,
    ThreadExitFullDirectSmallPostExitParts,
    ThreadExitFullDirectSmallPostExitTeardownTerminal,
    ThreadExitFullNonDirectSmallPostExitAbandonError,
    ThreadExitFullNonDirectSmallPostExitAbandonFailure,
    ThreadExitFullNonDirectSmallPostExitFreeError,
    ThreadExitFullNonDirectSmallPostExitFreeOutcome,
    ThreadExitFullNonDirectSmallPostExitParts,
    ThreadExitFullNonDirectSmallPostExitTeardownTerminal,
    ThreadExitMappedRegularPagesPostExitAbandonError,
    ThreadExitMappedRegularPagesPostExitAbandonFailure,
    ThreadExitMappedRegularPagesPostExitAbandonOutcome,
    ThreadExitMappedRegularPagesPostExitFreeError,
    ThreadExitMappedRegularPagesPostExitFreeOutcome,
    ThreadExitMappedRegularPagesPostExitParts,
    ThreadExitMappedRegularPagesPostExitTeardownTerminal,
    ThreadExitMappedOneBlockAbandonError, ThreadExitMappedOneBlockAbandonFailure,
    ThreadExitMappedOneBlockHandoff, ThreadExitMappedOneBlockRemoteFreeError,
    ThreadExitMappedOneBlockRemoteFreeFailure,
    ThreadExitSingletonAbandonError, ThreadExitSingletonAbandonFailure,
    ThreadExitSingletonHandoff, ThreadExitSingletonRemoteFreeError,
    ThreadExitSingletonRemoteFreeFailure,
};
#[cfg(test)]
use crate::types::Page;

#[cfg(test)]
extern crate std;

/// One bounded page engine for a later metadata Theap linked to `mi_heap_main`.
///
/// Field order is intentional: an unfinished drop first gives the generic
/// engine a chance to latch the later attachment terminal, then drops the
/// process PageMap lifecycle lease, which poisons rather than reopens a root
/// that may retain live entries or a producer relation.
#[must_use = "a later main-heap process page allocator must finish or retain its owner explicitly"]
pub(crate) struct MainHeapThreadProcessPageAllocator<'attachment, 'main> {
    engine: PageAllocatorEngine<'static, 'static, MainHeapThreadPageSession<'attachment, 'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// The post-fast-slot later-main owner that can only finish its all-free
/// source thread-exit drain. It retains the process-map mutation lease until
/// every page release is complete or the exact draining attachment is kept
/// terminally retained.
#[must_use = "a later main-heap thread-exit drain must finish or remain retained"]
pub(crate) struct MainHeapThreadProcessPageExitDrain<'attachment, 'main> {
    engine: PageAllocatorEngine<'static, 'static, MainHeapThreadPageDrainSession<'attachment, 'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// One sole full arena or OS-aligned singleton detached by the later-main
/// post-fast-slot owner-exit drain. It retains the same exclusive process
/// PageMap lifecycle lease until its exact final client free has released the
/// registered span or the source state is terminally retained.
#[must_use = "a later-main singleton handoff must release or retain its page explicitly"]
pub(crate) struct MainHeapThreadProcessPageExitSingletonHandoff<'attachment, 'main> {
    handoff: ThreadExitSingletonHandoff<
        'static,
        'static,
        MainHeapThreadPageDrainSession<'attachment, 'main>,
    >,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// One sole medium arena page detached as mapped-abandoned by the later-main
/// post-fast-slot owner-exit drain. It retains the same exclusive process
/// PageMap lifecycle lease until its exact final client free empties and
/// releases the registered span or the source state is terminally retained.
#[must_use = "a later-main mapped one-block handoff must release or retain its page explicitly"]
pub(crate) struct MainHeapThreadProcessPageExitMappedOneBlockHandoff<'attachment, 'main> {
    handoff: ThreadExitMappedOneBlockHandoff<
        'static,
        'static,
        MainHeapThreadPageDrainSession<'attachment, 'main>,
    >,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// One sole nonfull small-or-medium page that outlives its former
/// later Theap/TLD.
///
/// The source abandonment transition has already detached the page from every
/// old queue/direct/page-count owner, and `page_map_access` now serializes the
/// PageMap lookup -> abandoned-free -> terminal-release decision for each
/// client block. It also admits one explicit consuming allocation-time
/// handoff: a sole mapped nonfull medium page may transfer into a fresh
/// later-main owner, claim its exact static-main bitmap member, and requeue
/// at the source tail. It deliberately does not scan arbitrary routes, take a
/// fresh-page fallback, adopt small/direct/full/aggregate members, or expose
/// concurrent producer protocol.
#[must_use = "a post-exit mapped regular route must release every client block or remain terminally retained"]
pub(crate) struct MainHeapThreadProcessPageExitMappedRegularRoute<'main> {
    parts: ThreadExitMappedRegularPostExitParts<'main, 'static>,
    page_map_access: ProcessPageMapPostExitAccess,
}

// SAFETY: the route contains no borrow of the departed attachment, TLD, or
// Theap. Its retained arena/Heap addresses are process-stable; source-plain
// PageMap access is serialized by `ProcessPageMapPostExitAccess`, static Heap
// projection by `MainStaticHeapLease`, and the consuming free API preserves
// one route owner at a time. Sending it is therefore the intended client-free
// handoff after thread exit, not permission to share it concurrently.
unsafe impl Send for MainHeapThreadProcessPageExitMappedRegularRoute<'_> {}

/// A target later-main owner retained after it consumed a mapped regular
/// process route but could not complete the one supported medium reclaim.
///
/// Field order is intentional: an unfinished engine first latches the fresh
/// later attachment, then the long PageMap lease poisons rather than reopens
/// a root whose source page may have crossed a bitmap, low-owner, or Theap
/// reassociation boundary. `parts` preserves the exact source span and page
/// identity for terminal evidence; it offers no second adoption path.
#[must_use = "a failed mapped-medium adoption retains its target owner terminally"]
pub(crate) struct MainHeapThreadProcessPageExitMappedRegularAdoption<'attachment, 'main> {
    engine: PageAllocatorEngine<'static, 'static, MainHeapThreadPageSession<'attachment, 'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
    parts: ThreadExitMappedRegularPostExitParts<'main, 'static>,
}

/// A target later-main owner whose direct on-demand page-area commit failed
/// only after it restored the exact source page to mapped abandonment.
///
/// This preserves the fresh target attachment plus its long PageMap lease;
/// it must not convert those capabilities back into a short post-exit route
/// while the registered page remains live. Its one consuming retry starts
/// from the source-restored bitmap/count pair and may reclaim only the same
/// retained `parts.page` candidate.
#[must_use = "a reabandoned mapped-medium owner must retry its exact candidate or remain terminally retained"]
pub(crate) struct MainHeapThreadProcessPageExitMappedRegularReabandonedAdoption<
    'attachment,
    'main,
> {
    engine: PageAllocatorEngine<'static, 'static, MainHeapThreadPageSession<'attachment, 'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
    parts: ThreadExitMappedRegularPostExitParts<'main, 'static>,
    pair: ProcessPageArenaLease,
}

/// One sole full medium page that begins post-exit life as source-unmapped
/// abandonment and can later reabandon into the static-main bitmap.
///
/// The old later Theap/TLD is already gone. `parts` retains only its exact
/// arena/Heap/span facts plus the source unmapped-or-mapped state, while
/// `page_map_access` serializes each PageMap lookup -> failed-reclaim free ->
/// possible terminal release. The route is deliberately sequential: it does
/// not grant reclaim, requeue, allocation-time adoption, or concurrent
/// client-free authority.
#[must_use = "a post-exit full-medium route must release every client block or remain terminally retained"]
pub(crate) struct MainHeapThreadProcessPageExitFullMediumRoute<'main> {
    parts: ThreadExitFullMediumPostExitParts<'main, 'static>,
    page_map_access: ProcessPageMapPostExitAccess,
}

// SAFETY: this route retains no borrow of the detached attachment, TLD, or
// Theap. Its arena and static Heap references are process-stable, map access
// is serialized by `ProcessPageMapPostExitAccess`, and its consuming API
// keeps the source failed-reclaim owner decision linear. Sending moves that
// one owner; it does not authorize concurrent frees or allocation-time use.
unsafe impl Send for MainHeapThreadProcessPageExitFullMediumRoute<'_> {}

/// One sole full large page that begins post-exit life as source-unmapped
/// abandonment and can later reabandon into the static-main bitmap.
///
/// This has the same upstream full-regular state machine as the medium route,
/// but its stable page span is the large 64-slice arena extent. `parts` keeps
/// that class explicit through every post-exit free and release check; the
/// route remains sequential and exposes no allocation-time reclaim, requeue,
/// adoption, or concurrent client-free capability.
#[must_use = "a post-exit full-large route must release every client block or remain terminally retained"]
pub(crate) struct MainHeapThreadProcessPageExitFullLargeRoute<'main> {
    parts: ThreadExitFullLargePostExitParts<'main, 'static>,
    page_map_access: ProcessPageMapPostExitAccess,
}

// SAFETY: like the full-medium route, this stores only process-stable
// arena/static-Heap facts and short PageMap access. Its consuming API keeps
// the source failed-reclaim owner decision linear; sending transfers one owner
// and never permits shared frees or allocation-time use.
unsafe impl Send for MainHeapThreadProcessPageExitFullLargeRoute<'_> {}

/// One sole full direct small page that begins post-exit life as source-
/// unmapped abandonment and can later reabandon into the static-main bitmap.
///
/// Its rounded `block_size` is at most `SMALL_SIZE_MAX`, so the source keeps
/// the full page in its ordinary small queue and its exact rounded direct-cache
/// range names that queue head. `parts` captures the direct-small partial
/// failed-reclaim branch after queue removal has cleared that range but before
/// the old Theap/TLD is removed. The route remains sequential and provides no
/// allocation-time claim, reclaim, requeue, adoption, or concurrent free.
#[must_use = "a post-exit full direct small route must release every client block or remain terminally retained"]
pub(crate) struct MainHeapThreadProcessPageExitFullDirectSmallRoute<'main> {
    parts: ThreadExitFullDirectSmallPostExitParts<'main, 'static>,
    page_map_access: ProcessPageMapPostExitAccess,
}

// SAFETY: this holds only process-stable arena/static-Heap facts and serialized
// short PageMap access. Its consuming API transfers one failed-reclaim owner
// decision and cannot overlap frees or allocation-time use.
unsafe impl Send for MainHeapThreadProcessPageExitFullDirectSmallRoute<'_> {}

/// One sole full non-direct small page that begins post-exit life as
/// source-unmapped abandonment and can later reabandon into the static-main
/// bitmap.
///
/// Unlike a direct small page, this page's rounded `block_size` exceeds
/// `SMALL_SIZE_MAX`, so its full source state remains in the ordinary small
/// queue rather than the direct-cache image. `parts` captures that class and
/// its ordinary failed-reclaim collector before the old Theap/TLD is removed.
/// The route stays sequential and offers no
/// allocation-time reclaim, requeue, adoption, or concurrent free authority.
#[must_use = "a post-exit full non-direct small route must release every client block or remain terminally retained"]
pub(crate) struct MainHeapThreadProcessPageExitFullNonDirectSmallRoute<'main> {
    parts: ThreadExitFullNonDirectSmallPostExitParts<'main, 'static>,
    page_map_access: ProcessPageMapPostExitAccess,
}

// SAFETY: like the other full routes, this contains only process-stable
// arena/static-Heap facts and serialized short PageMap access. Its consuming
// API transfers one failed-reclaim owner decision; it never permits shared
// frees or allocation-time use.
unsafe impl Send for MainHeapThreadProcessPageExitFullNonDirectSmallRoute<'_> {}

/// One aggregate process route for every regular small, medium, or large arena
/// page that remained live during one later-main `_mi_thread_done` traversal.
///
/// `parts` is a typed registry over the still-published PageMap entries and
/// their exact static-main abandoned bitmap/count pairs. It deliberately does
/// not retain raw page pointers or the departed attachment; each linear client
/// free re-resolves and validates one page while `page_map_access` holds the
/// short plain-entry exclusion boundary. A fresh engine may serialize an
/// independent map operation between frees, but no current engine receives a
/// capability to claim, reclaim, or requeue these mapped-abandoned pages.
#[must_use = "an aggregate post-exit mapped regular-pages route must release every registered page or remain terminally retained"]
pub(crate) struct MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main> {
    parts: ThreadExitMappedRegularPagesPostExitParts<'main, 'static>,
    page_map_access: ProcessPageMapPostExitAccess,
}

// SAFETY: this route contains no borrow of the detached attachment, TLD, or
// Theap. Its PageMap/bitmap registry is process-stable, `parts` is explicitly
// !Sync, and its consuming free API plus short map access permit one route
// owner at a time. Sending it transfers that owner; it does not permit
// concurrent frees, allocation-time adoption, or requeue/reclaim.
unsafe impl Send for MainHeapThreadProcessPageExitMappedRegularPagesRoute<'_> {}

/// A pre-publication refusal while opening a later-thread process page owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageAllocatorBeginError {
    Pair(ProcessPageArenaLeaseError),
    Attachment(MainHeapThreadAttachmentError),
    /// The metadata TLD/Theap attachment belongs to a different process-main
    /// image than the already paired PageMap and arena.
    SubprocessMismatch,
    /// The pair's frozen map/arena configuration differs from the metadata
    /// configuration that initialized this later TLD/Theap.
    ConfigurationMismatch,
    Session(MainHeapThreadPageSessionError),
    PageMap(ProcessPageMapError),
}

/// A pre-transfer or retained-terminal outcome while a mapped regular
/// post-exit route attempts the one supported fresh later-main medium
/// adoption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularAdoptError {
    /// The source route is small rather than the deliberately supported
    /// medium shape. Its post-exit client-free route remains unchanged.
    SourceNotMedium,
    Pair(ProcessPageArenaLeaseError),
    Attachment(MainHeapThreadAttachmentError),
    SubprocessMismatch,
    ConfigurationMismatch,
    /// The target pair's stable PageMap root differs from the route's short
    /// post-exit access capability.
    PageMapRootMismatch,
    ArenaMismatch,
    Session(MainHeapThreadPageSessionError),
    PageMap(ProcessPageMapError),
    /// The source bitmap had no currently claimable exact page. The target
    /// owner is retained; this slice never turns that miss into fresh page
    /// allocation.
    Pending,
    /// Direct page-area commitment failed after queue-tail restoration, and
    /// source `_mi_page_abandon` restored the exact mapped-abandoned
    /// bitmap/count pair for the bounded same-candidate retry.
    PageCommit(ProcessPageArenaLeaseError),
    Route(ThreadExitMappedRegularPostExitAdoptError),
}

/// A failed mapped-medium adoption preserves either the original route before
/// any target engine exists, or a terminal target owner after the short route
/// transferred to a long PageMap lifecycle. A returned original route still
/// carries its own PageMap error state: only a ready route can continue its
/// normal client-free tail.
#[must_use = "a failed mapped-medium adoption retains its original or target owner"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularAdoptFailure<'attachment, 'main> {
    /// No target engine was created, so the caller retains this exact route.
    /// A ready route may continue its client-free tail; a reported PageMap
    /// poison remains terminal under that route's existing contract.
    Rejected {
        route: MainHeapThreadProcessPageExitMappedRegularRoute<'main>,
        error: MainHeapThreadProcessPageExitMappedRegularAdoptError,
    },
    /// The target long lifecycle exists. A source bitmap/owner/reassociation
    /// step may have changed, or the intentionally unsupported no-claim path
    /// must not fall through into a fresh allocation.
    Retained {
        adoption: MainHeapThreadProcessPageExitMappedRegularAdoption<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitMappedRegularAdoptError,
    },
    /// The direct commit itself failed, but the target completed the source
    /// false-collect -> queue detach -> mapped abandonment tail. This owner
    /// may consume itself only through its same-candidate [`retry`](
    /// MainHeapThreadProcessPageExitMappedRegularReabandonedAdoption::retry)
    /// method; it is not a recovered short route or a fresh-page fallback.
    Reabandoned {
        adoption:
            MainHeapThreadProcessPageExitMappedRegularReabandonedAdoption<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitMappedRegularAdoptError,
    },
}

/// The outcomes while consuming a later-thread shared process page engine.
#[must_use = "a retained later-thread page allocator still owns live page state"]
pub(crate) enum MainHeapThreadProcessPageAllocatorFinishError<'attachment, 'main> {
    /// Pages, queues, a scoped producer, or a detached OS-release owner
    /// remain. The engine and process map mutation lease remain coupled for
    /// an explicit retry or terminal decision.
    Retained(MainHeapThreadProcessPageAllocator<'attachment, 'main>),
    /// The engine became empty but the process-private PageMap lease observed
    /// a post-Release wake failure. The map owner is terminally poisoned.
    PageMap(ProcessPageMapError),
}

/// A consuming transition that could not enter the post-fast-slot all-free
/// drain without retaining its original normal page engine.
#[must_use = "a failed later-main thread-exit transition retains its page allocator"]
pub(crate) enum MainHeapThreadProcessPageExitDrainFailure<'attachment, 'main> {
    Retained {
        allocator: MainHeapThreadProcessPageAllocator<'attachment, 'main>,
        error: MainHeapThreadAttachmentError,
    },
}

/// The outcomes while finishing the bounded all-free later-main exit drain.
#[must_use = "a retained later-main thread-exit drain still owns live source state"]
pub(crate) enum MainHeapThreadProcessPageExitDrainFinishError<'attachment, 'main> {
    /// A live page, failed force collection, or pending OS release remains.
    /// The attachment is already post-fast-slot, so only this retained drain
    /// may make a later source-complete owner-exit decision.
    Retained(MainHeapThreadProcessPageExitDrain<'attachment, 'main>),
    /// Every page drained, but PageMap lifecycle release observed a post-
    /// Release wake failure. The map owner is terminally poisoned while the
    /// attachment remains in its valid empty post-fast-slot state for explicit
    /// root/list/TLD teardown.
    PageMap(ProcessPageMapError),
}

/// The source-state reason one later-main full singleton could not cross from
/// its post-fast-slot drain into the final-free handoff.
pub(crate) type MainHeapThreadProcessPageExitSingletonAbandonError =
    ThreadExitSingletonAbandonError;

/// The retained later-main owner after a full-singleton handoff attempt.
#[must_use = "a failed later-main singleton abandonment retains its source owner"]
pub(crate) enum MainHeapThreadProcessPageExitSingletonAbandonFailure<'attachment, 'main> {
    /// No queue or page identity changed, so the drain stays available for an
    /// explicit later decision.
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitSingletonAbandonError,
    },
    /// Collection may have detached source free state. The drain remains the
    /// only valid owner and cannot re-enter normal allocation.
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitSingletonAbandonError,
    },
    /// Queue/page ownership crossed into the handoff before the later source
    /// condition became terminal.
    Terminal {
        handoff: MainHeapThreadProcessPageExitSingletonHandoff<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitSingletonAbandonError,
    },
}

/// The source-state reason the detached later-main singleton's final free
/// could not complete its failed-reclaim release.
pub(crate) type MainHeapThreadProcessPageExitSingletonRemoteFreeError =
    ThreadExitSingletonRemoteFreeError;

/// The retained later-main singleton handoff after a final-free attempt.
#[must_use = "a failed later-main singleton free retains its handoff"]
pub(crate) enum MainHeapThreadProcessPageExitSingletonRemoteFreeFailure<'attachment, 'main> {
    Rejected {
        handoff: MainHeapThreadProcessPageExitSingletonHandoff<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitSingletonRemoteFreeError,
    },
    Terminal {
        handoff: MainHeapThreadProcessPageExitSingletonHandoff<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitSingletonRemoteFreeError,
    },
}

/// The source-state reason one later-main sole medium page could not cross
/// from its post-fast-slot drain into the mapped one-block final-free handoff.
pub(crate) type MainHeapThreadProcessPageExitMappedOneBlockAbandonError =
    ThreadExitMappedOneBlockAbandonError;

/// The retained later-main owner after a mapped-one-block handoff attempt.
#[must_use = "a failed later-main mapped one-block abandonment retains its source owner"]
pub(crate) enum MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure<'attachment, 'main> {
    /// No queue or page identity changed, so the drain stays available for an
    /// explicit later source decision.
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitMappedOneBlockAbandonError,
    },
    /// Force or false collection may have detached source free state. The
    /// drain remains the only valid owner and cannot re-enter normal allocation.
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitMappedOneBlockAbandonError,
    },
    /// Queue/page ownership crossed into the handoff before the later source
    /// condition became terminal.
    Terminal {
        handoff: MainHeapThreadProcessPageExitMappedOneBlockHandoff<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitMappedOneBlockAbandonError,
    },
}

/// The source-state reason the mapped one-block handoff's final free could
/// not complete its source empty-page release.
pub(crate) type MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeError =
    ThreadExitMappedOneBlockRemoteFreeError;

/// The retained later-main mapped one-block handoff after its final-free attempt.
#[must_use = "a failed later-main mapped one-block free retains its handoff"]
pub(crate) enum MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeFailure<'attachment, 'main> {
    Rejected {
        handoff: MainHeapThreadProcessPageExitMappedOneBlockHandoff<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeError,
    },
    Terminal {
        handoff: MainHeapThreadProcessPageExitMappedOneBlockHandoff<'attachment, 'main>,
        error: MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeError,
    },
}

/// The result of handling one client free through the post-exit mapped
/// regular route.
#[must_use = "a still-live mapped regular route remains responsible for later client frees"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularFreeResult<'main> {
    StillLive(MainHeapThreadProcessPageExitMappedRegularRoute<'main>),
    Released,
}

/// A process-map or source-route reason one post-exit client free could not
/// finish normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularFreeError {
    PageMap(ProcessPageMapError),
    Route(ThreadExitMappedRegularPostExitFreeError),
}

/// A retained post-exit route after one client-free attempt.
#[must_use = "a failed post-exit client free must retain or terminally record its route"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularFreeFailure<'main> {
    /// The supplied block had no current PageMap entry, so no source page
    /// state changed and the route can be used with its actual client block.
    Rejected {
        route: MainHeapThreadProcessPageExitMappedRegularRoute<'main>,
        error: MainHeapThreadProcessPageExitMappedRegularFreeError,
    },
    /// The source route may have acquired an owner bit, changed a bitmap, or
    /// observed a poison/wake failure. Retain it only as terminal state.
    Terminal {
        route: MainHeapThreadProcessPageExitMappedRegularRoute<'main>,
        error: MainHeapThreadProcessPageExitMappedRegularFreeError,
    },
    /// The all-free release completed, but the final PageMap quiescence
    /// transition observed a wake failure and poisoned the root. No live page
    /// route remains to retry.
    ReleasedPageMapPoisoned {
        error: ProcessPageMapError,
    },
}

/// A failure while crossing a later-main post-fast-slot drain from its full
/// medium `BIN_FULL` member into the sequential unmapped-to-mapped process
/// route.
#[must_use = "a failed full-medium process-route transition retains its exact source state"]
pub(crate) enum MainHeapThreadProcessPageExitFullMediumRouteBeginFailure<'attachment, 'main> {
    /// The preflight rejected before source collection or queue detachment.
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullMediumPostExitAbandonError,
    },
    /// Force/false collection or a later source transition may have changed
    /// the drain, so it remains the sole retained owner.
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullMediumPostExitAbandonError,
    },
    /// The page detached but old root/list/TLD teardown did not finish. The
    /// long PageMap lifecycle stays coupled to the retained source facts.
    Teardown {
        terminal: ThreadExitFullMediumPostExitTeardownTerminal<'attachment, 'main, 'static>,
        page_map_lifecycle: ProcessPageMapMutationLease,
    },
    /// The old Theap/TLD is gone, but conversion of the long map lifecycle
    /// to short post-exit access failed and poisoned the map root.
    PageMap {
        parts: ThreadExitFullMediumPostExitParts<'main, 'static>,
        error: ProcessPageMapError,
    },
}

/// The result of one sequential client free through the full-medium route.
#[must_use = "a still-live full-medium route remains responsible for later client frees"]
pub(crate) enum MainHeapThreadProcessPageExitFullMediumFreeResult<'main> {
    StillLive(MainHeapThreadProcessPageExitFullMediumRoute<'main>),
    Released,
}

/// A process-map or source-route reason one full-medium client free could not
/// finish normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageExitFullMediumFreeError {
    PageMap(ProcessPageMapError),
    Route(ThreadExitFullMediumPostExitFreeError),
}

/// A retained full-medium route after one client-free attempt.
#[must_use = "a failed full-medium post-exit free must retain or terminally record its route"]
pub(crate) enum MainHeapThreadProcessPageExitFullMediumFreeFailure<'main> {
    /// No PageMap entry existed for the supplied block, so no source owner
    /// state changed and the route can still receive its actual client block.
    Rejected {
        route: MainHeapThreadProcessPageExitFullMediumRoute<'main>,
        error: MainHeapThreadProcessPageExitFullMediumFreeError,
    },
    /// The raw tail may have acquired a low owner bit or changed its
    /// unmapped/mapped publication state. Retain this route terminally.
    Terminal {
        route: MainHeapThreadProcessPageExitFullMediumRoute<'main>,
        error: MainHeapThreadProcessPageExitFullMediumFreeError,
    },
    /// The last page released, but PageMap quiescence observed a wake failure
    /// and poisoned the root. No live route remains to retry.
    ReleasedPageMapPoisoned {
        error: ProcessPageMapError,
    },
}

/// A failure while crossing a later-main post-fast-slot drain from its full
/// large `BIN_FULL` member into the sequential unmapped-to-mapped process
/// route.
#[must_use = "a failed full-large process-route transition retains its exact source state"]
pub(crate) enum MainHeapThreadProcessPageExitFullLargeRouteBeginFailure<'attachment, 'main> {
    /// The preflight rejected before source collection or queue detachment.
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullLargePostExitAbandonError,
    },
    /// Force/false collection or a later source transition may have changed
    /// the drain, so it remains the sole retained owner.
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullLargePostExitAbandonError,
    },
    /// The page detached but old root/list/TLD teardown did not finish. The
    /// long PageMap lifecycle stays coupled to the retained source facts.
    Teardown {
        terminal: ThreadExitFullLargePostExitTeardownTerminal<'attachment, 'main, 'static>,
        page_map_lifecycle: ProcessPageMapMutationLease,
    },
    /// The old Theap/TLD is gone, but conversion of the long map lifecycle to
    /// short post-exit access failed and poisoned the map root.
    PageMap {
        parts: ThreadExitFullLargePostExitParts<'main, 'static>,
        error: ProcessPageMapError,
    },
}

/// The result of one sequential client free through the full-large route.
#[must_use = "a still-live full-large route remains responsible for later client frees"]
pub(crate) enum MainHeapThreadProcessPageExitFullLargeFreeResult<'main> {
    StillLive(MainHeapThreadProcessPageExitFullLargeRoute<'main>),
    Released,
}

/// A process-map or source-route reason one full-large client free could not
/// finish normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageExitFullLargeFreeError {
    PageMap(ProcessPageMapError),
    Route(ThreadExitFullLargePostExitFreeError),
}

/// A retained full-large route after one client-free attempt.
#[must_use = "a failed full-large post-exit free must retain or terminally record its route"]
pub(crate) enum MainHeapThreadProcessPageExitFullLargeFreeFailure<'main> {
    /// No PageMap entry existed for the supplied block, so no source owner
    /// state changed and the route can still receive its actual client block.
    Rejected {
        route: MainHeapThreadProcessPageExitFullLargeRoute<'main>,
        error: MainHeapThreadProcessPageExitFullLargeFreeError,
    },
    /// The raw tail may have acquired a low owner bit or changed its
    /// unmapped/mapped publication state. Retain this route terminally.
    Terminal {
        route: MainHeapThreadProcessPageExitFullLargeRoute<'main>,
        error: MainHeapThreadProcessPageExitFullLargeFreeError,
    },
    /// The last page released, but PageMap quiescence observed a wake failure
    /// and poisoned the root. No live route remains to retry.
    ReleasedPageMapPoisoned {
        error: ProcessPageMapError,
    },
}

/// A failure while crossing a later-main post-fast-slot drain from one full
/// direct small member in its ordinary size bin into the sequential
/// unmapped-to-mapped process route.
#[must_use = "a failed full direct small process-route transition retains its exact source state"]
pub(crate) enum MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure<'attachment, 'main> {
    /// The preflight rejected before source collection, direct-cache update,
    /// or queue detachment.
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullDirectSmallPostExitAbandonError,
    },
    /// Force/false collection or a later source transition may have changed
    /// the drain, so it remains the sole retained owner.
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullDirectSmallPostExitAbandonError,
    },
    /// The page detached and cleared its direct-cache range but old root/list/
    /// TLD teardown did not finish. The long PageMap lifecycle stays coupled
    /// to the retained source facts.
    Teardown {
        terminal: ThreadExitFullDirectSmallPostExitTeardownTerminal<'attachment, 'main, 'static>,
        page_map_lifecycle: ProcessPageMapMutationLease,
    },
    /// The old Theap/TLD is gone, but conversion of the long map lifecycle to
    /// short post-exit access failed and poisoned the map root.
    PageMap {
        parts: ThreadExitFullDirectSmallPostExitParts<'main, 'static>,
        error: ProcessPageMapError,
    },
}

/// The result of one sequential client free through the full direct small
/// route.
#[must_use = "a still-live full direct small route remains responsible for later client frees"]
pub(crate) enum MainHeapThreadProcessPageExitFullDirectSmallFreeResult<'main> {
    StillLive(MainHeapThreadProcessPageExitFullDirectSmallRoute<'main>),
    Released,
}

/// A process-map or source-route reason one full direct small client free
/// could not finish normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageExitFullDirectSmallFreeError {
    PageMap(ProcessPageMapError),
    Route(ThreadExitFullDirectSmallPostExitFreeError),
}

/// A retained full direct small route after one client-free attempt.
#[must_use = "a failed full direct small post-exit free must retain or terminally record its route"]
pub(crate) enum MainHeapThreadProcessPageExitFullDirectSmallFreeFailure<'main> {
    /// No PageMap entry existed for the supplied block, so no source owner
    /// state changed and the route can still receive its actual client block.
    Rejected {
        route: MainHeapThreadProcessPageExitFullDirectSmallRoute<'main>,
        error: MainHeapThreadProcessPageExitFullDirectSmallFreeError,
    },
    /// The raw tail may have acquired a low owner bit or changed its
    /// unmapped/mapped publication state. Retain this route terminally.
    Terminal {
        route: MainHeapThreadProcessPageExitFullDirectSmallRoute<'main>,
        error: MainHeapThreadProcessPageExitFullDirectSmallFreeError,
    },
    /// The last page released, but PageMap quiescence observed a wake failure
    /// and poisoned the root. No live route remains to retry.
    ReleasedPageMapPoisoned {
        error: ProcessPageMapError,
    },
}

/// A failure while crossing a later-main post-fast-slot drain from one full
/// non-direct small member in its ordinary size bin into the sequential
/// unmapped-to-mapped process route.
#[must_use = "a failed full non-direct small process-route transition retains its exact source state"]
pub(crate) enum MainHeapThreadProcessPageExitFullNonDirectSmallRouteBeginFailure<'attachment, 'main> {
    /// The preflight rejected before source collection or queue detachment.
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullNonDirectSmallPostExitAbandonError,
    },
    /// Force/false collection or a later source transition may have changed
    /// the drain, so it remains the sole retained owner.
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitFullNonDirectSmallPostExitAbandonError,
    },
    /// The page detached but old root/list/TLD teardown did not finish. The
    /// long PageMap lifecycle stays coupled to the retained source facts.
    Teardown {
        terminal: ThreadExitFullNonDirectSmallPostExitTeardownTerminal<
            'attachment,
            'main,
            'static,
        >,
        page_map_lifecycle: ProcessPageMapMutationLease,
    },
    /// The old Theap/TLD is gone, but conversion of the long map lifecycle to
    /// short post-exit access failed and poisoned the map root.
    PageMap {
        parts: ThreadExitFullNonDirectSmallPostExitParts<'main, 'static>,
        error: ProcessPageMapError,
    },
}

/// The result of one sequential client free through the full non-direct small
/// route.
#[must_use = "a still-live full non-direct small route remains responsible for later client frees"]
pub(crate) enum MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult<'main> {
    StillLive(MainHeapThreadProcessPageExitFullNonDirectSmallRoute<'main>),
    Released,
}

/// A process-map or source-route reason one full non-direct small client free
/// could not finish normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageExitFullNonDirectSmallFreeError {
    PageMap(ProcessPageMapError),
    Route(ThreadExitFullNonDirectSmallPostExitFreeError),
}

/// A retained full non-direct small route after one client-free attempt.
#[must_use = "a failed full non-direct small post-exit free must retain or terminally record its route"]
pub(crate) enum MainHeapThreadProcessPageExitFullNonDirectSmallFreeFailure<'main> {
    /// No PageMap entry existed for the supplied block, so no source owner
    /// state changed and the route can still receive its actual client block.
    Rejected {
        route: MainHeapThreadProcessPageExitFullNonDirectSmallRoute<'main>,
        error: MainHeapThreadProcessPageExitFullNonDirectSmallFreeError,
    },
    /// The raw tail may have acquired a low owner bit or changed its
    /// unmapped/mapped publication state. Retain this route terminally.
    Terminal {
        route: MainHeapThreadProcessPageExitFullNonDirectSmallRoute<'main>,
        error: MainHeapThreadProcessPageExitFullNonDirectSmallFreeError,
    },
    /// The last page released, but PageMap quiescence observed a wake failure
    /// and poisoned the root. No live route remains to retry.
    ReleasedPageMapPoisoned {
        error: ProcessPageMapError,
    },
}

/// A failure while crossing a later-main drain from its old Theap/TLD into
/// the first actual process-owned mapped regular route.
#[must_use = "a failed mapped regular process-route transition retains its exact source state"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure<'attachment, 'main> {
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitMappedRegularPostExitAbandonError,
    },
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitMappedRegularPostExitAbandonError,
    },
    /// The old attachment could not finish its root/list/TLD teardown after
    /// source page detachment. The long process-map lease remains coupled to
    /// the terminal attachment/page facts.
    Teardown {
        terminal: ThreadExitMappedRegularPostExitTeardownTerminal<'attachment, 'main, 'static>,
        page_map_lifecycle: ProcessPageMapMutationLease,
    },
    /// The old Theap/TLD is gone and the page facts remain retained, but the
    /// long map guard could not become a short post-exit route. The map root
    /// is poisoned by that transfer failure.
    PageMap {
        parts: ThreadExitMappedRegularPostExitParts<'main, 'static>,
        error: ProcessPageMapError,
    },
}

/// The aggregate mapped regular-pages traversal either opened its process route or
/// became an ordinary empty post-fast-slot drain. A `Drained` result has no
/// live PageMap registration and must still use the normal drain/attachment
/// finish boundary.
#[must_use = "the aggregate traversal outcome retains either its process route or empty drain"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin<'attachment, 'main> {
    Route(MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main>),
    Drained(MainHeapThreadProcessPageExitDrain<'attachment, 'main>),
}

/// A failure while crossing a later-main drain into the aggregate regular-pages
/// process route. The preflight refusal leaves the drain intact; every later
/// source transition retains it terminally until a broader lifecycle exists.
#[must_use = "a failed aggregate mapped regular-pages route transition retains its exact source state"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure<'attachment, 'main> {
    Rejected {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitMappedRegularPagesPostExitAbandonError,
    },
    RetainedDrain {
        drain: MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        error: ThreadExitMappedRegularPagesPostExitAbandonError,
    },
    /// Source page transitions completed but old root/list/TLD teardown
    /// failed. The detached page registry and long map lifecycle remain one
    /// terminal owner; no short route has been exposed.
    Teardown {
        terminal: ThreadExitMappedRegularPagesPostExitTeardownTerminal<'attachment, 'main, 'static>,
        page_map_lifecycle: ProcessPageMapMutationLease,
    },
    /// The former Theap/TLD is gone, but the long map lifecycle could not be
    /// converted to short access. The map root is poisoned and the registry
    /// remains retained for an explicit terminal decision.
    PageMap {
        parts: ThreadExitMappedRegularPagesPostExitParts<'main, 'static>,
        error: ProcessPageMapError,
    },
}

/// The result of one client free through the aggregate post-exit registry.
#[must_use = "a nonterminal aggregate result retains the only route owner"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularPagesFreeResult<'main> {
    StillLive(MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main>),
    ReleasedPage(MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main>),
    ReleasedAll,
}

/// A process-map or source-route reason one aggregate client free could not
/// complete normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularPagesFreeError {
    PageMap(ProcessPageMapError),
    Route(ThreadExitMappedRegularPagesPostExitFreeError),
}

/// A retained aggregate route after one client-free attempt.
#[must_use = "a failed aggregate post-exit free must retain or terminally record its route"]
pub(crate) enum MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure<'main> {
    /// The supplied block was absent from the current PageMap, so the route
    /// did not acquire a source owner bit and can be used with a valid block.
    Rejected {
        route: MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main>,
        error: MainHeapThreadProcessPageExitMappedRegularPagesFreeError,
    },
    /// The source tail may have changed an abandoned owner bit, bitmap/count,
    /// PageMap entry, or ordinary page state. Retain this route only as a
    /// terminal owner rather than attempting a generic retry.
    Terminal {
        route: MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main>,
        error: MainHeapThreadProcessPageExitMappedRegularPagesFreeError,
    },
    /// The last page physically released, but the final map quiescence wake
    /// failed and poisoned the root. No live aggregate route remains.
    ReleasedAllPageMapPoisoned {
        error: ProcessPageMapError,
    },
}

impl<'attachment, 'main> MainHeapThreadProcessPageAllocator<'attachment, 'main> {
    /// Starts one source-shaped page lifecycle for a later main-heap thread.
    ///
    /// The exact PageMap/arena tuple and frozen configuration are checked
    /// before the later attachment is mutably borrowed as a page session. The
    /// resulting map mutation lease then excludes a second safe page engine
    /// from the source map's plain entry accesses until this engine and any
    /// scoped producer have become quiescent.
    pub(crate) fn begin(
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
        pair: ProcessPageArenaLease,
    ) -> Result<Self, MainHeapThreadProcessPageAllocatorBeginError> {
        let attachment_subprocess = attachment
            .subprocess()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Attachment)?;
        let process = pair
            .subprocess()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        if !core::ptr::eq(attachment_subprocess.as_ptr(), process.as_ptr()) {
            return Err(MainHeapThreadProcessPageAllocatorBeginError::SubprocessMismatch);
        }
        let attachment_config = attachment
            .memory_config()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Attachment)?;
        let pair_config = pair
            .memory_config()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        if attachment_config != pair_config {
            return Err(MainHeapThreadProcessPageAllocatorBeginError::ConfigurationMismatch);
        }
        let arena = pair
            .arena()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        let session = attachment
            .page_session()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Session)?;
        let page_map_lifecycle = pair
            .begin_page_lifecycle()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        let page_map = page_map_lifecycle
            .page_map()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::PageMap)?;
        // SAFETY: `pair` proved the exact process identity/root/configuration,
        // the retained mutation lease serializes the source map's plain
        // entries, and `session` keeps the current metadata Theap plus the
        // live static-main Heap lease alive for this complete engine.
        let engine = unsafe {
            PageAllocatorEngine::activate_later_main_thread(
                session,
                arena,
                ArenaId::none(),
                page_map,
            )
        };
        Ok(Self {
            engine,
            page_map_lifecycle,
        })
    }

    /// Allocates one ordinary block through the later-thread source page
    /// engine.
    #[inline]
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        self.engine.allocate(request, zero)
    }

    /// Frees one current allocation belonging to this exact later-thread
    /// owner.
    ///
    /// # Safety
    ///
    /// `block` must be one current allocation returned by this engine. It
    /// must not have been freed, transferred to a scoped producer, or used
    /// concurrently through another owner.
    #[inline]
    pub(crate) unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), FreeError> {
        unsafe { self.engine.free(block) }
    }

    /// Runs the bounded local retired-page collector after every scoped
    /// producer has joined.
    #[inline]
    pub(crate) fn collect_retired(&mut self, force: bool) -> bool {
        self.engine.collect_retired(force)
    }

    /// Prepares one joined scoped remote free for a live later-thread page.
    ///
    /// # Safety
    ///
    /// `block` must be a current allocation in this engine. The producer must
    /// publish or cancel before this owner resumes allocation, collection,
    /// finish, or drop.
    #[inline]
    pub(crate) unsafe fn begin_remote_free<'owner>(
        &'owner mut self,
        block: NonNull<u8>,
    ) -> Result<RemoteFreeProducer<'owner>, RemoteFreePreparationError> {
        unsafe { self.engine.begin_remote_free(block) }
    }

    /// Consumes the ordinary later-main allocator into its bounded source
    /// thread-exit page drain. On success the returned owner deliberately has
    /// no allocate/free/producer APIs: the fixed fast TLS slot is already
    /// clear, so it may only force-collect and release all-free pages before
    /// the attachment's final root/list/TLD teardown.
    pub(crate) fn begin_thread_exit_drain(
        self,
    ) -> Result<
        MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        MainHeapThreadProcessPageExitDrainFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.begin_thread_exit_drain() {
            Ok(engine) => Ok(MainHeapThreadProcessPageExitDrain {
                engine,
                page_map_lifecycle,
            }),
            Err((engine, error)) => Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                allocator: Self {
                    engine,
                    page_map_lifecycle,
                },
                error,
            }),
        }
    }

    /// Finishes only after every page, queue, map entry, bitmap transition,
    /// and scoped producer is quiescent. The caller must then invoke the
    /// attachment's source-ordered user-destructor/teardown boundary.
    pub(crate) fn finish(
        self,
    ) -> Result<(), MainHeapThreadProcessPageAllocatorFinishError<'attachment, 'main>> {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.finish() {
            Ok(()) => page_map_lifecycle
                .finish()
                .map_err(MainHeapThreadProcessPageAllocatorFinishError::PageMap),
            Err(engine) => Err(MainHeapThreadProcessPageAllocatorFinishError::Retained(Self {
                engine,
                page_map_lifecycle,
            })),
        }
    }

    #[cfg(test)]
    #[inline]
    unsafe fn test_page_for_block(&self, block: NonNull<u8>) -> *mut Page {
        unsafe { self.engine.page_for_block(block) }
    }

    #[cfg(test)]
    #[inline]
    fn test_direct_page(&self, index: usize) -> Option<*mut Page> {
        self.engine.direct_page(index)
    }

    #[cfg(test)]
    #[inline]
    fn test_queue_count(&self, bin: usize) -> Option<usize> {
        self.engine.queue_count(bin)
    }

    #[cfg(test)]
    #[inline]
    fn test_enable_page_commit_on_demand(&mut self) {
        self.engine.test_enable_page_commit_on_demand();
    }

    #[cfg(test)]
    #[inline]
    fn test_set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        self.engine.set_direct_page_for_test(index, page)
    }
}

impl<'attachment, 'main> MainHeapThreadProcessPageExitDrain<'attachment, 'main> {
    /// Detaches the one source full-singleton owner-exit case after the fixed
    /// main fast slot is clear. The returned handoff retains the exact process
    /// PageMap mutation lease, so no later page owner can observe a live
    /// registration as though this drain had completed.
    ///
    /// # Safety
    ///
    /// `block` must be the sole current allocation in one full arena or
    /// OS-aligned singleton owned by this exact post-fast-slot drain. No
    /// scoped producer may remain, and all client aliases must remain live
    /// only until the handoff's exact final-free operation or terminal
    /// retention.
    pub(crate) unsafe fn abandon_full_singleton(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitSingletonHandoff<'attachment, 'main>,
        MainHeapThreadProcessPageExitSingletonAbandonFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: the post-fast-slot `MainHeapThreadPageDrainSession` retains
        // the source root transition, its exact TLD/Theap/Heap relation, and
        // the matching process map/arena lifetime through this result.
        match unsafe { engine.abandon_full_singleton_after_thread_exit(block) } {
            Ok(handoff) => Ok(MainHeapThreadProcessPageExitSingletonHandoff {
                handoff,
                page_map_lifecycle,
            }),
            Err(ThreadExitSingletonAbandonFailure::Rejected { engine, error }) => {
                Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Rejected {
                    drain: Self {
                        engine,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
            Err(ThreadExitSingletonAbandonFailure::RetainedEngine { engine, error }) => {
                Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::RetainedDrain {
                    drain: Self {
                        engine,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
            Err(ThreadExitSingletonAbandonFailure::Terminal { handoff, error }) => {
                Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Terminal {
                    handoff: MainHeapThreadProcessPageExitSingletonHandoff {
                        handoff,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
        }
    }

    /// Detaches the one source mapped regular-page owner-exit case after the
    /// fixed main fast slot is clear: a sole medium arena page with exactly one
    /// live client block. The returned handoff retains the exact process PageMap
    /// mutation lease while source `pages_abandoned[bin]` remains published.
    ///
    /// # Safety
    ///
    /// `block` must be the sole current allocation in one sole medium arena
    /// page owned by this exact post-fast-slot drain. No scoped producer may
    /// remain, and all client aliases must remain live only until the handoff's
    /// exact final-free operation or terminal retention.
    pub(crate) unsafe fn abandon_mapped_one_block(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitMappedOneBlockHandoff<'attachment, 'main>,
        MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: the post-fast-slot `MainHeapThreadPageDrainSession` retains
        // the source root transition, exact TLD/Theap/Heap relation, matching
        // process map/arena lifetime, and final-free authority through result.
        match unsafe { engine.abandon_mapped_one_block_after_thread_exit(block) } {
            Ok(handoff) => Ok(MainHeapThreadProcessPageExitMappedOneBlockHandoff {
                handoff,
                page_map_lifecycle,
            }),
            Err(ThreadExitMappedOneBlockAbandonFailure::Rejected { engine, error }) => {
                Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::Rejected {
                    drain: Self {
                        engine,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
            Err(ThreadExitMappedOneBlockAbandonFailure::RetainedEngine { engine, error }) => {
                Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain: Self {
                        engine,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
            Err(ThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::Terminal {
                    handoff: MainHeapThreadProcessPageExitMappedOneBlockHandoff {
                        handoff,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
        }
    }

    /// Transfers one sole nonfull small-or-medium page into the
    /// first true process post-exit route. On success the old later Theap/TLD
    /// has already been detached and freed; later client frees use only short
    /// process PageMap access plus stable main-Heap/arena facts. For a small
    /// page, a direct small member proves and clears its complete rounded
    /// source direct-cache range rather than classifying by request size.
    ///
    /// # Safety
    ///
    /// `block` must be one exact current canonical allocation in the sole
    /// small-or-medium regular page owned by this post-fast-slot
    /// drain. No producer may survive. Every client alias in that page must
    /// remain live only until the returned route consumes it exactly once or
    /// is retained terminally. This first route is linear and does not provide
    /// general concurrent frees, allocation-time reclaim, or a multi-page
    /// traversal.
    pub(crate) unsafe fn abandon_mapped_small_or_medium_to_process_route(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitMappedRegularRoute<'main>,
        MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: this wrapper's draining session proves the fixed-fast-slot
        // source boundary; its caller supplies the exact live-page/block
        // proof required by the specialized queue-detach transition.
        let detach = match unsafe {
            engine.abandon_mapped_small_or_medium_to_process_route(block)
        } {
            Ok(detach) => detach,
            Err(ThreadExitMappedRegularPostExitAbandonFailure::Rejected { engine, error }) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::Rejected {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
            Err(ThreadExitMappedRegularPostExitAbandonFailure::RetainedEngine {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::RetainedDrain {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
        };

        let parts = match detach.finish_thread_owner() {
            Ok(parts) => parts,
            Err(terminal) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::Teardown {
                        terminal,
                        page_map_lifecycle,
                    },
                );
            }
        };
        // SAFETY: `parts` is the one typed process-lived owner required by
        // this transfer. It retains the page's stable arena/heap/bitmap/span
        // facts and every later route call encloses plain map access in the
        // returned short guard.
        match unsafe { page_map_lifecycle.into_post_exit_access() } {
            Ok(page_map_access) => Ok(MainHeapThreadProcessPageExitMappedRegularRoute {
                parts,
                page_map_access,
            }),
            Err(error) => Err(
                MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::PageMap {
                    parts,
                    error,
                },
            ),
        }
    }

    /// Transfers one sole full medium page from the source full queue into a
    /// sequential post-exit process route. Source abandonment intentionally
    /// leaves a full regular page unmapped; sequential client frees remain in
    /// that state through the mostly-used threshold and the first later free
    /// reabandons it into the static-main bitmap before the mapped tail takes
    /// over. The old later Theap/TLD is fully torn down before this method
    /// returns a route.
    ///
    /// # Safety
    ///
    /// `block` must be one exact current canonical allocation in the only
    /// full medium page of this post-fast-slot drain. No producer may survive.
    /// Every client alias in that page must be consumed exactly once through
    /// the returned linear route or retained terminally. This bounded owner
    /// does not provide concurrent frees, allocation-time reclaim/requeue, or
    /// a traversal for additional source pages.
    pub(crate) unsafe fn abandon_full_medium_to_process_route(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullMediumRoute<'main>,
        MainHeapThreadProcessPageExitFullMediumRouteBeginFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: the draining session proves this is after the fixed source
        // fast-slot boundary, and the caller supplies the exact full-medium
        // page/block proof required for the queue-detach transition.
        let detach = match unsafe { engine.abandon_full_medium_to_process_route(block) } {
            Ok(detach) => detach,
            Err(ThreadExitFullMediumPostExitAbandonFailure::Rejected { engine, error }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullMediumRouteBeginFailure::Rejected {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
            Err(ThreadExitFullMediumPostExitAbandonFailure::RetainedEngine {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullMediumRouteBeginFailure::RetainedDrain {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
        };

        let parts = match detach.finish_thread_owner() {
            Ok(parts) => parts,
            Err(terminal) => {
                return Err(
                    MainHeapThreadProcessPageExitFullMediumRouteBeginFailure::Teardown {
                        terminal,
                        page_map_lifecycle,
                    },
                );
            }
        };
        // SAFETY: `parts` is now the only source-shaped owner of the page's
        // stable arena/Heap/span facts and its unmapped-to-mapped state. Each
        // later client free reacquires plain PageMap exclusion only for its
        // complete lookup, owner-bit tail, and possible terminal release.
        match unsafe { page_map_lifecycle.into_post_exit_access() } {
            Ok(page_map_access) => Ok(MainHeapThreadProcessPageExitFullMediumRoute {
                parts,
                page_map_access,
            }),
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullMediumRouteBeginFailure::PageMap {
                    parts,
                    error,
                },
            ),
        }
    }

    /// Transfers one sole full large page from the source full queue into a
    /// sequential post-exit process route. Like source full-medium abandonment,
    /// it begins unmapped, crosses into the static-main bitmap only after the
    /// mostly-used boundary, and tears down the old later Theap/TLD before the
    /// route is exposed. The large class retains its full arena span through
    /// the terminal PageMap -> `pages_main` -> metadata -> slice release.
    ///
    /// # Safety
    ///
    /// `block` must be one exact current canonical allocation in the only full
    /// large page of this post-fast-slot drain. No producer may survive. Every
    /// client alias in that page must be consumed exactly once through the
    /// returned linear route or retained terminally. This bounded owner does
    /// not provide concurrent frees, allocation-time reclaim/requeue, or a
    /// traversal for additional source pages.
    pub(crate) unsafe fn abandon_full_large_to_process_route(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullLargeRoute<'main>,
        MainHeapThreadProcessPageExitFullLargeRouteBeginFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: the draining session proves this is after the fixed source
        // fast-slot boundary, and the caller supplies the exact full-large
        // page/block proof required for the queue-detach transition.
        let detach = match unsafe { engine.abandon_full_large_to_process_route(block) } {
            Ok(detach) => detach,
            Err(ThreadExitFullLargePostExitAbandonFailure::Rejected { engine, error }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullLargeRouteBeginFailure::Rejected {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
            Err(ThreadExitFullLargePostExitAbandonFailure::RetainedEngine {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullLargeRouteBeginFailure::RetainedDrain {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
        };

        let parts = match detach.finish_thread_owner() {
            Ok(parts) => parts,
            Err(terminal) => {
                return Err(
                    MainHeapThreadProcessPageExitFullLargeRouteBeginFailure::Teardown {
                        terminal,
                        page_map_lifecycle,
                    },
                );
            }
        };
        // SAFETY: `parts` is now the only source-shaped owner of the large
        // page's stable arena/Heap/span facts and its unmapped-to-mapped state.
        // Each later client free reacquires plain PageMap exclusion only for
        // its complete lookup, owner-bit tail, and possible terminal release.
        match unsafe { page_map_lifecycle.into_post_exit_access() } {
            Ok(page_map_access) => Ok(MainHeapThreadProcessPageExitFullLargeRoute {
                parts,
                page_map_access,
            }),
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullLargeRouteBeginFailure::PageMap {
                    parts,
                    error,
                },
            ),
        }
    }

    /// Transfers one sole full direct small page from its ordinary source size
    /// bin into a sequential post-exit process route. This full-small shape
    /// remains in its regular queue with the exact rounded direct-cache image;
    /// source queue removal clears that image before page-count detach. Source
    /// abandonment then leaves it unmapped, and sequential client frees remain
    /// there through the mostly-used threshold before the mapped tail takes
    /// over. The old later Theap/TLD is fully torn down before this method
    /// returns a route.
    ///
    /// # Safety
    ///
    /// `block` must be one exact current canonical allocation in the only full
    /// direct small page of this post-fast-slot drain. Its rounded block size
    /// must not exceed `SMALL_SIZE_MAX`, its source direct-cache range must be
    /// exact, and `reserved >= 16` must hold for free.c's partial collector.
    /// No producer may survive. Every client alias in that page must be
    /// consumed exactly once through the returned linear route or retained
    /// terminally. This bounded owner does not provide concurrent frees,
    /// allocation-time reclaim/requeue, or a traversal for additional pages.
    pub(crate) unsafe fn abandon_full_direct_small_to_process_route(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullDirectSmallRoute<'main>,
        MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: the drain proves this is after the fixed source fast-slot
        // boundary, and the caller supplies the exact full direct-small
        // page/block proof required for regular-queue/direct-cache detachment.
        let detach = match unsafe { engine.abandon_full_direct_small_to_process_route(block) } {
            Ok(detach) => detach,
            Err(ThreadExitFullDirectSmallPostExitAbandonFailure::Rejected {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::Rejected {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
            Err(ThreadExitFullDirectSmallPostExitAbandonFailure::RetainedEngine {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::RetainedDrain {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
        };

        let parts = match detach.finish_thread_owner() {
            Ok(parts) => parts,
            Err(terminal) => {
                return Err(
                    MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::Teardown {
                        terminal,
                        page_map_lifecycle,
                    },
                );
            }
        };
        // SAFETY: `parts` is now the only source-shaped owner of the direct
        // small page's stable arena/Heap/span facts and its unmapped-to-mapped
        // state. Each later client free reacquires plain PageMap exclusion only
        // for complete lookup, owner-bit tail, and possible terminal release.
        match unsafe { page_map_lifecycle.into_post_exit_access() } {
            Ok(page_map_access) => Ok(MainHeapThreadProcessPageExitFullDirectSmallRoute {
                parts,
                page_map_access,
            }),
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::PageMap {
                    parts,
                    error,
                },
            ),
        }
    }

    /// Transfers one sole full non-direct small page from its ordinary source
    /// size bin into a sequential post-exit process route. Full small is not
    /// the `BIN_FULL` shape: the pinned source retains it in the regular queue
    /// when its rounded block size exceeds `SMALL_SIZE_MAX`. Source abandonment
    /// still leaves it unmapped; sequential client frees remain there through
    /// the mostly-used threshold and the first later free reabandons it into
    /// the exact static-main bitmap/count pair before the mapped tail takes
    /// over. The old later Theap/TLD is fully torn down before this method
    /// returns a route.
    ///
    /// # Safety
    ///
    /// `block` must be one exact current canonical allocation in the only full
    /// non-direct small page of this post-fast-slot drain. Its rounded block
    /// size must exceed `SMALL_SIZE_MAX`. No producer may survive. Every
    /// client alias in that page must be consumed exactly once through the
    /// returned linear route or
    /// retained terminally. This bounded owner does not provide concurrent
    /// frees, allocation-time reclaim/requeue, or a traversal for additional
    /// source pages.
    pub(crate) unsafe fn abandon_full_non_direct_small_to_process_route(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullNonDirectSmallRoute<'main>,
        MainHeapThreadProcessPageExitFullNonDirectSmallRouteBeginFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: the draining session proves this is after the fixed source
        // fast-slot boundary, and the caller supplies the exact non-direct
        // full-small page/block proof required for regular-queue detachment.
        let detach = match unsafe { engine.abandon_full_non_direct_small_to_process_route(block) }
        {
            Ok(detach) => detach,
            Err(ThreadExitFullNonDirectSmallPostExitAbandonFailure::Rejected {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullNonDirectSmallRouteBeginFailure::Rejected {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
            Err(ThreadExitFullNonDirectSmallPostExitAbandonFailure::RetainedEngine {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitFullNonDirectSmallRouteBeginFailure::RetainedDrain {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
        };

        let parts = match detach.finish_thread_owner() {
            Ok(parts) => parts,
            Err(terminal) => {
                return Err(
                    MainHeapThreadProcessPageExitFullNonDirectSmallRouteBeginFailure::Teardown {
                        terminal,
                        page_map_lifecycle,
                    },
                );
            }
        };
        // SAFETY: `parts` is now the only source-shaped owner of the small
        // page's stable arena/Heap/span facts and its unmapped-to-mapped state.
        // Each later client free reacquires plain PageMap exclusion only for
        // its complete lookup, owner-bit tail, and possible terminal release.
        match unsafe { page_map_lifecycle.into_post_exit_access() } {
            Ok(page_map_access) => Ok(MainHeapThreadProcessPageExitFullNonDirectSmallRoute {
                parts,
                page_map_access,
            }),
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullNonDirectSmallRouteBeginFailure::PageMap {
                    parts,
                    error,
                },
            ),
        }
    }

    /// Traverses every currently live mapped regular small, medium, or large
    /// arena page into one process-owned post-exit registry. Unlike the older
    /// sole-page route,
    /// this preserves the full source `MI_ABANDON` page visitation order:
    /// force-collect each page, release pages that become all-free, then
    /// false-collect, queue-detach, and publish every remaining supported
    /// arena page.
    ///
    /// The returned route remains deliberately linear. Its short PageMap
    /// operations serialize with a fresh engine, but no current engine gets a
    /// capability to claim/reclaim/requeue any of its mapped-abandoned
    /// members; it does not expose a general allocation-time adoption or
    /// concurrent free protocol. If collection makes every page empty,
    /// `Drained` preserves the ordinary attachment finish path instead of
    /// inventing an empty process route.
    ///
    /// # Safety
    ///
    /// No scoped producer may survive. Every currently live page must be a
    /// nonfull regular small, medium, or large page in the paired process
    /// arena. Every client alias must be consumed exactly once through the resulting route
    /// or retained terminally. This may only run after the fixed later-main
    /// fast slot has cleared; no old-Theap access may occur after a successful
    /// route begins.
    pub(crate) unsafe fn abandon_mapped_regular_pages_to_process_route(
        self,
    ) -> Result<
        MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin<'attachment, 'main>,
        MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        // SAFETY: this wrapper supplies the source post-fast-slot drain and
        // its unique PageMap/arena ownership to the exact aggregate traversal.
        let detach = match unsafe { engine.abandon_mapped_regular_pages_to_process_route() } {
            Ok(ThreadExitMappedRegularPagesPostExitAbandonOutcome::Drained(engine)) => {
                return Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(
                    Self {
                        engine,
                        page_map_lifecycle,
                    },
                ));
            }
            Ok(ThreadExitMappedRegularPagesPostExitAbandonOutcome::Detached(detach)) => detach,
            Err(ThreadExitMappedRegularPagesPostExitAbandonFailure::Rejected { engine, error }) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
            Err(ThreadExitMappedRegularPagesPostExitAbandonFailure::RetainedEngine {
                engine,
                error,
            }) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                        drain: Self {
                            engine,
                            page_map_lifecycle,
                        },
                        error,
                    },
                );
            }
        };

        let parts = match detach.finish_thread_owner() {
            Ok(parts) => parts,
            Err(terminal) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Teardown {
                        terminal,
                        page_map_lifecycle,
                    },
                );
            }
        };
        // SAFETY: the aggregate parts are the sole registry for all remaining
        // registered pages; every later lookup/free/release runs through the
        // short access capability returned by this transfer.
        match unsafe { page_map_lifecycle.into_post_exit_access() } {
            Ok(page_map_access) => Ok(
                MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(
                    MainHeapThreadProcessPageExitMappedRegularPagesRoute {
                        parts,
                        page_map_access,
                    },
                ),
            ),
            Err(error) => Err(
                MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::PageMap {
                    parts,
                    error,
                },
            ),
        }
    }

    /// Finishes the all-free half of source `_mi_theap_collect_abandon` and
    /// then releases the paired process PageMap lifecycle. A successful return
    /// leaves the borrowed attachment in `DrainingPages`; callers must finish
    /// its explicit root/list/TLD boundary with
    /// [`MainHeapThreadAttachment::finish_after_page_drain`].
    pub(crate) fn finish(
        self,
    ) -> Result<(), MainHeapThreadProcessPageExitDrainFinishError<'attachment, 'main>> {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.finish_after_all_free_thread_exit() {
            Ok(()) => page_map_lifecycle
                .finish()
                .map_err(MainHeapThreadProcessPageExitDrainFinishError::PageMap),
            Err(engine) => Err(MainHeapThreadProcessPageExitDrainFinishError::Retained(Self {
                engine,
                page_map_lifecycle,
            })),
        }
    }

    #[cfg(test)]
    #[inline]
    fn test_direct_page(&self, index: usize) -> Option<*mut Page> {
        self.engine.direct_page(index)
    }

    #[cfg(test)]
    #[inline]
    fn test_queue_count(&self, bin: usize) -> Option<usize> {
        self.engine.queue_count(bin)
    }
}

impl<'attachment, 'main> MainHeapThreadProcessPageExitSingletonHandoff<'attachment, 'main> {
    #[cfg(test)]
    #[inline]
    fn test_has_pending_os_release(&self) -> bool {
        self.handoff.test_has_pending_os_release()
    }

    /// Performs the handoff's one final client free. The source fast-root
    /// transition already made the departed later Theap unavailable for
    /// reclamation; only the raw failed-reclaim all-free result is admitted.
    ///
    /// # Safety
    ///
    /// `block` must be the exact once-live allocation transferred by
    /// [`MainHeapThreadProcessPageExitDrain::abandon_full_singleton`]. It must
    /// not have been freed, republished, or accessed through any alias after
    /// this call.
    pub(crate) unsafe fn remote_free_after_failed_reclaim(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        MainHeapThreadProcessPageExitSingletonRemoteFreeFailure<'attachment, 'main>,
    > {
        let Self {
            handoff,
            page_map_lifecycle,
        } = self;
        // SAFETY: the linear handoff owns the sole PageMap registration and
        // client block lifetime through the source failed-reclaim tail.
        match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
            Ok(engine) => Ok(MainHeapThreadProcessPageExitDrain {
                engine,
                page_map_lifecycle,
            }),
            Err(ThreadExitSingletonRemoteFreeFailure::Rejected { handoff, error }) => {
                Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Rejected {
                    handoff: Self {
                        handoff,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
            Err(ThreadExitSingletonRemoteFreeFailure::Terminal { handoff, error }) => {
                Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Terminal {
                    handoff: Self {
                        handoff,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
        }
    }
}

impl<'attachment, 'main>
    MainHeapThreadProcessPageExitMappedOneBlockHandoff<'attachment, 'main>
{
    /// Performs the handoff's one final client free. Source mapped-page free
    /// checks for empty after collection before it considers reclamation; this
    /// handoff admits only that all-free result and then releases its exact
    /// PageMap/main-arena/metadata/slice ownership.
    ///
    /// # Safety
    ///
    /// `block` must be the exact once-live allocation transferred by
    /// [`MainHeapThreadProcessPageExitDrain::abandon_mapped_one_block`]. It
    /// must not have been freed, republished, or accessed through any alias
    /// after this call.
    pub(crate) unsafe fn remote_free_to_empty(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeFailure<'attachment, 'main>,
    > {
        let Self {
            handoff,
            page_map_lifecycle,
        } = self;
        // SAFETY: the linear handoff owns the sole PageMap registration, main
        // abandoned bitmap capability, and client block lifetime through the
        // source empty-before-reclaim tail.
        match unsafe { handoff.remote_free_to_empty(block) } {
            Ok(engine) => Ok(MainHeapThreadProcessPageExitDrain {
                engine,
                page_map_lifecycle,
            }),
            Err(ThreadExitMappedOneBlockRemoteFreeFailure::Rejected { handoff, error }) => {
                Err(MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeFailure::Rejected {
                    handoff: Self {
                        handoff,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
            Err(ThreadExitMappedOneBlockRemoteFreeFailure::Terminal { handoff, error }) => {
                Err(MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeFailure::Terminal {
                    handoff: Self {
                        handoff,
                        page_map_lifecycle,
                    },
                    error,
                })
            }
        }
    }
}

impl<'main> MainHeapThreadProcessPageExitFullMediumRoute<'main> {
    /// Routes one exact client free after the originating later Theap/TLD has
    /// completed source teardown. A full medium page starts unmapped and may
    /// cross into mapped abandonment only after source's mostly-used boundary.
    ///
    /// # Safety
    ///
    /// `block` must be an exact once-live canonical allocation in this one
    /// detached full-medium page. It must not be freed, transferred, or used
    /// through another route concurrently. The route is consuming so callers
    /// cannot safely overlap source owner-bit decisions; general concurrent
    /// free routing and allocation-time reclaim/requeue remain out of scope.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullMediumFreeResult<'main>,
        MainHeapThreadProcessPageExitFullMediumFreeFailure<'main>,
    > {
        let Self {
            mut parts,
            page_map_access,
        } = self;
        let free = page_map_access.with_page_map(|page_map| {
            // SAFETY: this API carries the exact client-block obligation into
            // one complete source failed-reclaim decision. The short map
            // access remains held through lookup, possible unmapped-to-mapped
            // reabandonment, and any all-free terminal release.
            unsafe { parts.remote_free_after_thread_exit(page_map, block) }
        });
        match free {
            Ok(Ok(ThreadExitFullMediumPostExitFreeOutcome::StillLive)) => Ok(
                MainHeapThreadProcessPageExitFullMediumFreeResult::StillLive(Self {
                    parts,
                    page_map_access,
                }),
            ),
            Ok(Ok(ThreadExitFullMediumPostExitFreeOutcome::Released)) => {
                // SAFETY: the source terminal release removed the page's
                // PageMap publication, any mapped bitmap/count state, normal
                // arena bit, metadata, and backing slices. No live route fact
                // remains after the final map quiescence transition.
                match unsafe { page_map_access.finish_after_all_pages_released() } {
                    Ok(()) => Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::Released),
                    Err(error) => Err(
                        MainHeapThreadProcessPageExitFullMediumFreeFailure::ReleasedPageMapPoisoned {
                            error,
                        },
                    ),
                }
            }
            Ok(Err(error)) => {
                let route = Self {
                    parts,
                    page_map_access,
                };
                let error = MainHeapThreadProcessPageExitFullMediumFreeError::Route(error);
                if matches!(
                    error,
                    MainHeapThreadProcessPageExitFullMediumFreeError::Route(
                        ThreadExitFullMediumPostExitFreeError::Unmapped
                    )
                ) {
                    Err(MainHeapThreadProcessPageExitFullMediumFreeFailure::Rejected {
                        route,
                        error,
                    })
                } else {
                    Err(MainHeapThreadProcessPageExitFullMediumFreeFailure::Terminal {
                        route,
                        error,
                    })
                }
            }
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullMediumFreeFailure::Terminal {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitFullMediumFreeError::PageMap(error),
                },
            ),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn test_is_mapped(&self) -> bool {
        self.parts.test_is_mapped()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_abandoned_count(&self) -> Option<usize> {
        self.parts.test_abandoned_count()
    }
}

impl<'main> MainHeapThreadProcessPageExitFullLargeRoute<'main> {
    /// Routes one exact client free after the originating later Theap/TLD has
    /// completed source teardown. A full large page starts unmapped and may
    /// cross into mapped abandonment only after source's mostly-used boundary.
    ///
    /// # Safety
    ///
    /// `block` must be an exact once-live canonical allocation in this one
    /// detached full-large page. It must not be freed, transferred, or used
    /// through another route concurrently. The route is consuming so callers
    /// cannot safely overlap source owner-bit decisions; general concurrent
    /// free routing and allocation-time reclaim/requeue remain out of scope.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullLargeFreeResult<'main>,
        MainHeapThreadProcessPageExitFullLargeFreeFailure<'main>,
    > {
        let Self {
            mut parts,
            page_map_access,
        } = self;
        let free = page_map_access.with_page_map(|page_map| {
            // SAFETY: this API carries the exact client-block obligation into
            // one complete source failed-reclaim decision. The short map
            // access remains held through lookup, possible unmapped-to-mapped
            // reabandonment, and any all-free terminal release.
            unsafe { parts.remote_free_after_thread_exit(page_map, block) }
        });
        match free {
            Ok(Ok(ThreadExitFullLargePostExitFreeOutcome::StillLive)) => Ok(
                MainHeapThreadProcessPageExitFullLargeFreeResult::StillLive(Self {
                    parts,
                    page_map_access,
                }),
            ),
            Ok(Ok(ThreadExitFullLargePostExitFreeOutcome::Released)) => {
                // SAFETY: the source terminal release removed the page's
                // PageMap publication, any mapped bitmap/count state, normal
                // arena bit, metadata, and all 64 backing slices. No live
                // route fact remains after the final map quiescence transition.
                match unsafe { page_map_access.finish_after_all_pages_released() } {
                    Ok(()) => Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::Released),
                    Err(error) => Err(
                        MainHeapThreadProcessPageExitFullLargeFreeFailure::ReleasedPageMapPoisoned {
                            error,
                        },
                    ),
                }
            }
            Ok(Err(error)) => {
                let route = Self {
                    parts,
                    page_map_access,
                };
                let error = MainHeapThreadProcessPageExitFullLargeFreeError::Route(error);
                if matches!(
                    error,
                    MainHeapThreadProcessPageExitFullLargeFreeError::Route(
                        ThreadExitFullLargePostExitFreeError::Unmapped
                    )
                ) {
                    Err(MainHeapThreadProcessPageExitFullLargeFreeFailure::Rejected {
                        route,
                        error,
                    })
                } else {
                    Err(MainHeapThreadProcessPageExitFullLargeFreeFailure::Terminal {
                        route,
                        error,
                    })
                }
            }
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullLargeFreeFailure::Terminal {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitFullLargeFreeError::PageMap(error),
                },
            ),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn test_is_mapped(&self) -> bool {
        self.parts.test_is_mapped()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_abandoned_count(&self) -> Option<usize> {
        self.parts.test_abandoned_count()
    }
}

impl<'main> MainHeapThreadProcessPageExitFullDirectSmallRoute<'main> {
    /// Routes one exact client free after the originating later Theap/TLD has
    /// completed source teardown. This full direct small page starts unmapped
    /// and may cross into mapped abandonment only after the source's
    /// mostly-used boundary. Its partial collector remains selected by the
    /// stored direct-sized block geometry.
    ///
    /// # Safety
    ///
    /// `block` must be an exact once-live canonical allocation in this one
    /// detached full direct small page. It must not be freed, transferred, or
    /// used through another route concurrently. The route is consuming so
    /// callers cannot safely overlap source owner-bit decisions; general
    /// concurrent free routing and allocation-time reclaim/requeue remain out
    /// of scope.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullDirectSmallFreeResult<'main>,
        MainHeapThreadProcessPageExitFullDirectSmallFreeFailure<'main>,
    > {
        let Self {
            mut parts,
            page_map_access,
        } = self;
        let free = page_map_access.with_page_map(|page_map| {
            // SAFETY: this API carries the exact client-block obligation into
            // one complete source failed-reclaim decision. The short map
            // access remains held through lookup, possible unmapped-to-mapped
            // reabandonment, and any all-free terminal release.
            unsafe { parts.remote_free_after_thread_exit(page_map, block) }
        });
        match free {
            Ok(Ok(ThreadExitFullDirectSmallPostExitFreeOutcome::StillLive)) => Ok(
                MainHeapThreadProcessPageExitFullDirectSmallFreeResult::StillLive(Self {
                    parts,
                    page_map_access,
                }),
            ),
            Ok(Ok(ThreadExitFullDirectSmallPostExitFreeOutcome::Released)) => {
                // SAFETY: the source terminal release removed the page's
                // PageMap publication, any mapped bitmap/count state, normal
                // arena bit, metadata, and backing slice. No live route fact
                // remains after the final map quiescence transition.
                match unsafe { page_map_access.finish_after_all_pages_released() } {
                    Ok(()) => Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::Released),
                    Err(error) => Err(
                        MainHeapThreadProcessPageExitFullDirectSmallFreeFailure::ReleasedPageMapPoisoned {
                            error,
                        },
                    ),
                }
            }
            Ok(Err(error)) => {
                let route = Self {
                    parts,
                    page_map_access,
                };
                let error = MainHeapThreadProcessPageExitFullDirectSmallFreeError::Route(error);
                if matches!(
                    error,
                    MainHeapThreadProcessPageExitFullDirectSmallFreeError::Route(
                        ThreadExitFullDirectSmallPostExitFreeError::Unmapped
                    )
                ) {
                    Err(MainHeapThreadProcessPageExitFullDirectSmallFreeFailure::Rejected {
                        route,
                        error,
                    })
                } else {
                    Err(MainHeapThreadProcessPageExitFullDirectSmallFreeFailure::Terminal {
                        route,
                        error,
                    })
                }
            }
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullDirectSmallFreeFailure::Terminal {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitFullDirectSmallFreeError::PageMap(error),
                },
            ),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn test_is_mapped(&self) -> bool {
        self.parts.test_is_mapped()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_abandoned_count(&self) -> Option<usize> {
        self.parts.test_abandoned_count()
    }
}

impl<'main> MainHeapThreadProcessPageExitFullNonDirectSmallRoute<'main> {
    /// Routes one exact client free after the originating later Theap/TLD has
    /// completed source teardown. This full non-direct small page starts
    /// unmapped and may cross into mapped abandonment only after source's
    /// mostly-used boundary.
    ///
    /// # Safety
    ///
    /// `block` must be an exact once-live canonical allocation in this one
    /// detached full non-direct small page. It must not be freed, transferred,
    /// or used through another route concurrently. The route is consuming so
    /// callers cannot safely overlap source owner-bit decisions; general
    /// concurrent free routing and allocation-time reclaim/requeue remain out
    /// of scope.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult<'main>,
        MainHeapThreadProcessPageExitFullNonDirectSmallFreeFailure<'main>,
    > {
        let Self {
            mut parts,
            page_map_access,
        } = self;
        let free = page_map_access.with_page_map(|page_map| {
            // SAFETY: this API carries the exact client-block obligation into
            // one complete source failed-reclaim decision. The short map
            // access remains held through lookup, possible unmapped-to-mapped
            // reabandonment, and any all-free terminal release.
            unsafe { parts.remote_free_after_thread_exit(page_map, block) }
        });
        match free {
            Ok(Ok(ThreadExitFullNonDirectSmallPostExitFreeOutcome::StillLive)) => Ok(
                MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::StillLive(Self {
                    parts,
                    page_map_access,
                }),
            ),
            Ok(Ok(ThreadExitFullNonDirectSmallPostExitFreeOutcome::Released)) => {
                // SAFETY: the source terminal release removed the page's
                // PageMap publication, any mapped bitmap/count state, normal
                // arena bit, metadata, and backing slice. No live route fact
                // remains after the final map quiescence transition.
                match unsafe { page_map_access.finish_after_all_pages_released() } {
                    Ok(()) => Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::Released),
                    Err(error) => Err(
                        MainHeapThreadProcessPageExitFullNonDirectSmallFreeFailure::ReleasedPageMapPoisoned {
                            error,
                        },
                    ),
                }
            }
            Ok(Err(error)) => {
                let route = Self {
                    parts,
                    page_map_access,
                };
                let error = MainHeapThreadProcessPageExitFullNonDirectSmallFreeError::Route(error);
                if matches!(
                    error,
                    MainHeapThreadProcessPageExitFullNonDirectSmallFreeError::Route(
                        ThreadExitFullNonDirectSmallPostExitFreeError::Unmapped
                    )
                ) {
                    Err(MainHeapThreadProcessPageExitFullNonDirectSmallFreeFailure::Rejected {
                        route,
                        error,
                    })
                } else {
                    Err(MainHeapThreadProcessPageExitFullNonDirectSmallFreeFailure::Terminal {
                        route,
                        error,
                    })
                }
            }
            Err(error) => Err(
                MainHeapThreadProcessPageExitFullNonDirectSmallFreeFailure::Terminal {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitFullNonDirectSmallFreeError::PageMap(error),
                },
            ),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn test_is_mapped(&self) -> bool {
        self.parts.test_is_mapped()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_abandoned_count(&self) -> Option<usize> {
        self.parts.test_abandoned_count()
    }
}

impl<'main> MainHeapThreadProcessPageExitMappedRegularRoute<'main> {
    /// Consumes this one mapped regular post-exit route into a fresh
    /// later-main page engine when it has the completed medium-page shape.
    ///
    /// The source route is intentionally explicit rather than an allocation
    /// search: it transfers the same PageMap access capability to the new
    /// long engine, claims only its stable page identity, then restores source
    /// queue-tail order. A bitmap miss and every post-transfer failure retain
    /// the target owner; this slice never allocates a fresh replacement or
    /// broadens into small, full, aggregate, or concurrent adoption.
    pub(crate) fn adopt_into_later_main<'attachment>(
        self,
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
        pair: ProcessPageArenaLease,
    ) -> Result<
        MainHeapThreadProcessPageAllocator<'attachment, 'main>,
        MainHeapThreadProcessPageExitMappedRegularAdoptFailure<'attachment, 'main>,
    > {
        let Self {
            parts,
            page_map_access,
        } = self;
        if !parts.supports_later_main_adoption() {
            return Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::SourceNotMedium,
                },
            );
        }
        let attachment_subprocess = match attachment.subprocess() {
            Ok(subprocess) => subprocess,
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Attachment(
                            error,
                        ),
                    },
                );
            }
        };
        let pair_subprocess = match pair.subprocess() {
            Ok(subprocess) => subprocess,
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Pair(error),
                    },
                );
            }
        };
        if !core::ptr::eq(attachment_subprocess.as_ptr(), pair_subprocess.as_ptr())
            || !core::ptr::eq(
                attachment_subprocess.as_ptr(),
                parts.main_heap_subprocess().as_ptr(),
            )
        {
            return Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::SubprocessMismatch,
                },
            );
        }
        let attachment_config = match attachment.memory_config() {
            Ok(config) => config,
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Attachment(
                            error,
                        ),
                    },
                );
            }
        };
        let pair_config = match pair.memory_config() {
            Ok(config) => config,
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Pair(error),
                    },
                );
            }
        };
        if attachment_config != pair_config {
            return Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error:
                        MainHeapThreadProcessPageExitMappedRegularAdoptError::ConfigurationMismatch,
                },
            );
        }
        let pair_root = match pair.page_map_root() {
            Ok(root) => root,
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Pair(error),
                    },
                );
            }
        };
        match page_map_access.matches_root(pair_root) {
            Ok(true) => {}
            Ok(false) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error:
                            MainHeapThreadProcessPageExitMappedRegularAdoptError::PageMapRootMismatch,
                    },
                );
            }
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::PageMap(error),
                    },
                );
            }
        }
        let arena = match pair.arena() {
            Ok(arena) => arena,
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Pair(error),
                    },
                );
            }
        };
        if !parts.matches_arena(&arena) {
            return Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::ArenaMismatch,
                },
            );
        }
        let session = match attachment.page_session() {
            Ok(session) => session,
            Err(error) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Session(error),
                    },
                );
            }
        };
        let page_map_lifecycle = match unsafe { page_map_access.into_mutation_lease() } {
            Ok(lifecycle) => lifecycle,
            Err((page_map_access, error)) => {
                return Err(
                    MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                        route: Self {
                            parts,
                            page_map_access,
                        },
                        error: MainHeapThreadProcessPageExitMappedRegularAdoptError::PageMap(error),
                    },
                );
            }
        };
        // A successful short-to-long bridge holds this exact guard and its
        // ready root. No other state transition can invalidate the root while
        // this lease remains live; preserving that invariant here avoids a
        // second unpaired PageMap access branch after ownership transferred.
        let page_map = page_map_lifecycle
            .page_map()
            .expect("a successful post-exit PageMap bridge retains its ready long lease");
        // SAFETY: all preflight proved the attachment/pair/source identities,
        // and `page_map_lifecycle` now serializes this complete target engine.
        let mut engine = unsafe {
            PageAllocatorEngine::activate_later_main_thread(
                session,
                arena,
                ArenaId::none(),
                page_map,
            )
        };
        match unsafe { parts.adopt_into_later_main(&mut engine, pair) } {
            Ok(ThreadExitMappedRegularPostExitAdoptOutcome::Reclaimed) => {
                Ok(MainHeapThreadProcessPageAllocator {
                    engine,
                    page_map_lifecycle,
                })
            }
            Ok(ThreadExitMappedRegularPostExitAdoptOutcome::Reabandoned(error)) => Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                    adoption: MainHeapThreadProcessPageExitMappedRegularReabandonedAdoption {
                        engine,
                        page_map_lifecycle,
                        parts,
                        pair,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::PageCommit(error),
                },
            ),
            Ok(ThreadExitMappedRegularPostExitAdoptOutcome::Pending) => Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                    adoption: MainHeapThreadProcessPageExitMappedRegularAdoption {
                        engine,
                        page_map_lifecycle,
                        parts,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Pending,
                },
            ),
            Err(error) => Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                    adoption: MainHeapThreadProcessPageExitMappedRegularAdoption {
                        engine,
                        page_map_lifecycle,
                        parts,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Route(error),
                },
            ),
        }
    }

    /// Routes one exact client free after the originating later Theap/TLD has
    /// completed source teardown.
    ///
    /// # Safety
    ///
    /// `block` must be an exact once-live canonical allocation in this
    /// route's one detached page. It must not be freed, transferred, or
    /// concurrently used through another route. The route is consuming so a
    /// caller cannot safely overlap two source owner-claim decisions; general
    /// concurrent free routing remains a later lifecycle slice.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitMappedRegularFreeResult<'main>,
        MainHeapThreadProcessPageExitMappedRegularFreeFailure<'main>,
    > {
        let Self {
            parts,
            page_map_access,
        } = self;
        let free = page_map_access.with_page_map(|page_map| {
            // SAFETY: this public boundary carries the exact client-block
            // obligation into the source-shaped mapped abandoned-free tail;
            // `with_page_map` retains the plain PageMap exclusion until the
            // lookup, atomic free, and any all-free release have completed.
            unsafe { parts.remote_free_after_thread_exit(page_map, block) }
        });
        match free {
            Ok(Ok(ThreadExitMappedRegularPostExitFreeOutcome::StillLive)) => {
                Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(
                    Self {
                        parts,
                        page_map_access,
                    },
                ))
            }
            Ok(Ok(ThreadExitMappedRegularPostExitFreeOutcome::Released)) => {
                // SAFETY: the source terminal release above removed the
                // mapped identity/bit/count, full PageMap span, ordinary
                // arena bit, metadata, and backing slices. No route state is
                // left after this final quiescence transition.
                match unsafe { page_map_access.finish_after_all_pages_released() } {
                    Ok(()) => Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released),
                    Err(error) => Err(
                        MainHeapThreadProcessPageExitMappedRegularFreeFailure::ReleasedPageMapPoisoned {
                            error,
                        },
                    ),
                }
            }
            Ok(Err(error)) => {
                let route = Self {
                    parts,
                    page_map_access,
                };
                let error = MainHeapThreadProcessPageExitMappedRegularFreeError::Route(error);
                if matches!(
                    error,
                    MainHeapThreadProcessPageExitMappedRegularFreeError::Route(
                        ThreadExitMappedRegularPostExitFreeError::Unmapped
                    )
                ) {
                    Err(MainHeapThreadProcessPageExitMappedRegularFreeFailure::Rejected {
                        route,
                        error,
                    })
                } else {
                    Err(MainHeapThreadProcessPageExitMappedRegularFreeFailure::Terminal {
                        route,
                        error,
                    })
                }
            }
            Err(error) => Err(
                MainHeapThreadProcessPageExitMappedRegularFreeFailure::Terminal {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularFreeError::PageMap(error),
                },
            ),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_abandoned_count(&self) -> Option<usize> {
        self.parts.test_abandoned_count()
    }
}

impl<'attachment, 'main>
    MainHeapThreadProcessPageExitMappedRegularReabandonedAdoption<'attachment, 'main>
{
    /// Retries only the exact mapped-medium page whose failed direct commit
    /// re-published its original static-main bitmap/count pair.
    ///
    /// This is the bounded source retry shape after `mi_page_fresh_alloc`
    /// returns null from its failed `mi_page_extend_free` branch. It does not
    /// reopen short PageMap access, attach a new target, scan a bitmap, or
    /// allocate a fresh replacement page.
    pub(crate) fn retry(
        self,
    ) -> Result<
        MainHeapThreadProcessPageAllocator<'attachment, 'main>,
        MainHeapThreadProcessPageExitMappedRegularAdoptFailure<'attachment, 'main>,
    > {
        let Self {
            mut engine,
            page_map_lifecycle,
            parts,
            pair,
        } = self;
        // SAFETY: this owner retains the exact long PageMap mutation lease,
        // fresh target session, route facts, and paired arena capability that
        // completed the preceding reabandonment. No short-access or fresh
        // page path can interleave with this same-candidate retry.
        match unsafe { parts.adopt_into_later_main(&mut engine, pair) } {
            Ok(ThreadExitMappedRegularPostExitAdoptOutcome::Reclaimed) => {
                Ok(MainHeapThreadProcessPageAllocator {
                    engine,
                    page_map_lifecycle,
                })
            }
            Ok(ThreadExitMappedRegularPostExitAdoptOutcome::Reabandoned(error)) => Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                    adoption: Self {
                        engine,
                        page_map_lifecycle,
                        parts,
                        pair,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::PageCommit(error),
                },
            ),
            Ok(ThreadExitMappedRegularPostExitAdoptOutcome::Pending) => Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                    adoption: MainHeapThreadProcessPageExitMappedRegularAdoption {
                        engine,
                        page_map_lifecycle,
                        parts,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Pending,
                },
            ),
            Err(error) => Err(
                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                    adoption: MainHeapThreadProcessPageExitMappedRegularAdoption {
                        engine,
                        page_map_lifecycle,
                        parts,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularAdoptError::Route(error),
                },
            ),
        }
    }
}

impl<'main> MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main> {
    /// Routes one exact client free through the aggregate post-exit registry.
    ///
    /// # Safety
    ///
    /// `block` must be an exact once-live canonical allocation in one page
    /// transferred by
    /// [`MainHeapThreadProcessPageExitDrain::abandon_mapped_regular_pages_to_process_route`].
    /// It must not have been freed, transferred, or concurrently used through
    /// another route. This consuming API serializes one source abandoned-owner
    /// decision at a time; it deliberately does not make the aggregate route a
    /// concurrent free or allocation-time claim interface.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        MainHeapThreadProcessPageExitMappedRegularPagesFreeResult<'main>,
        MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure<'main>,
    > {
        let Self {
            mut parts,
            page_map_access,
        } = self;
        let free = page_map_access.with_page_map(|page_map| {
            // SAFETY: this boundary carries the caller's exact client-block
            // proof into the source mapped failed-reclaim tail. The complete
            // short map operation encloses lookup, owner-bit claim, bitmap/
            // count transition, and any terminal span release.
            unsafe { parts.remote_free_after_thread_exit(page_map, block) }
        });
        match free {
            Ok(Ok(ThreadExitMappedRegularPagesPostExitFreeOutcome::StillLive)) => {
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(
                    Self {
                        parts,
                        page_map_access,
                    },
                ))
            }
            Ok(Ok(ThreadExitMappedRegularPagesPostExitFreeOutcome::ReleasedPage)) => {
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(
                    Self {
                        parts,
                        page_map_access,
                    },
                ))
            }
            Ok(Ok(ThreadExitMappedRegularPagesPostExitFreeOutcome::ReleasedAll)) => {
                // The source release above removed the last mapped
                // identity/bitmap/count, complete PageMap span, ordinary
                // arena bit, metadata, and backing slices. Drop the empty
                // registry before explicitly reopening the process map.
                drop(parts);
                // SAFETY: `ReleasedAll` is emitted only after the route's
                // count reached zero following a complete terminal release.
                match unsafe { page_map_access.finish_after_all_pages_released() } {
                    Ok(()) => Ok(
                        MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedAll,
                    ),
                    Err(error) => Err(
                        MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure::ReleasedAllPageMapPoisoned {
                            error,
                        },
                    ),
                }
            }
            Ok(Err(error)) => {
                let route = Self {
                    parts,
                    page_map_access,
                };
                let error = MainHeapThreadProcessPageExitMappedRegularPagesFreeError::Route(error);
                if matches!(
                    error,
                    MainHeapThreadProcessPageExitMappedRegularPagesFreeError::Route(
                        ThreadExitMappedRegularPagesPostExitFreeError::Unmapped
                    )
                ) {
                    Err(
                        MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure::Rejected {
                            route,
                            error,
                        },
                    )
                } else {
                    Err(
                        MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure::Terminal {
                            route,
                            error,
                        },
                    )
                }
            }
            Err(error) => Err(
                MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure::Terminal {
                    route: Self {
                        parts,
                        page_map_access,
                    },
                    error: MainHeapThreadProcessPageExitMappedRegularPagesFreeError::PageMap(error),
                },
            ),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn test_remaining_pages(&self) -> usize {
        self.parts.test_remaining_pages()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler_tls::fast_slot_peek;
    use crate::config::{
        ARENA_ALIGNMENT, ARENA_MIN_SIZE, LARGE_MAX_OBJ_SIZE, MEDIUM_MAX_OBJ_SIZE,
        PAGES_DIRECT, SMALL_MAX_OBJ_SIZE, SMALL_SIZE_MAX, WORD_SIZE,
    };
    use crate::main_heap_thread::{
        MainHeapThreadAttachment, MainHeapThreadAttachmentBeginError,
    };
    use crate::main_theap::{MainStaticAttachmentStorage, MainStaticTheapAttachment};
    use crate::meta::MetaAllocator;
    use crate::os::{fault, MapAccess, Mapping, MemoryConfig, PageSize};
    use crate::os_page::PublishedOsAlignedPage;
    use crate::process_arena::{ProcessSharedArenaLease, ProcessSharedArenaStorage};
    use crate::process_page_map::{ProcessPageMapLease, ProcessPageMapStorage};
    use crate::subproc::MainSubprocess;
    use crate::types::{BIN_BLOCK_SIZES, EMPTY_PAGE, THREAD_ID_ABANDONED_MAPPED};
    use crabc_core::Errno;
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn paired_process_owner(
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> (ProcessPageMapLease, ProcessSharedArenaLease) {
        let page_map = ProcessPageMapStorage::test_static_owner()
            .initialize(config, subprocess)
            .expect("the isolated process map initializes");
        let mapping = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        )
        .expect("the test owns one complete source arena mapping");
        let arena = match ProcessSharedArenaStorage::test_static_owner()
            .install_one_owned_external_arena(page_map, mapping)
        {
            Ok(arena) => arena,
            Err(_) => panic!("the selected mapping becomes the one process arena"),
        };
        (page_map, arena)
    }

    fn paired_reserved_process_owner(
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> (ProcessPageMapLease, ProcessSharedArenaLease) {
        let page_map = ProcessPageMapStorage::test_static_owner()
            .initialize(config, subprocess)
            .expect("the isolated process map initializes");
        let mapping = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Reserved,
        )
        .expect("the test owns one complete reserved source arena mapping");
        let arena = match ProcessSharedArenaStorage::test_static_owner()
            .install_one_owned_external_arena(page_map, mapping)
        {
            Ok(arena) => arena,
            Err(_) => panic!("the selected reserved mapping becomes the one process arena"),
        };
        (page_map, arena)
    }

    #[test]
    fn later_thread_page_engine_uses_the_static_main_heap_and_in_place_arena_bitmap() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let expected_heap = {
                let mut main = unsafe {
                    MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
                }
                .expect("ticket zero attaches the source-static main images");
                let expected = main.test_heap_pointer() as usize;
                let main_heap = main
                    .shared_main_heap_lease()
                    .expect("the live main attachment lends its static heap");

                thread::scope(|scope| {
                    let worker = scope.spawn(move || {
                        let arena = process_arena
                            .arena()
                            .expect("the process arena remains published for the worker lifecycle");
                        let mut owner = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap,
                                metadata,
                                config,
                            )
                        } {
                            Ok(owner) => owner,
                            Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                panic!("later source thread attachment rejected: {error:?}")
                            }
                            Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                                panic!("later source thread attachment retained: {error:?}")
                            }
                        };
                        let expected_theap = owner.test_theap_pointer().expect("metadata Theap stays live");
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                            .expect("the matched process pair admits the later-thread page engine");
                        assert!(matches!(
                            page_map.begin_page_lifecycle(),
                            Err(ProcessPageMapError::LifecycleBusy)
                        ));
                        let block = allocator
                            .allocate(37, false)
                            .expect("the later thread allocates a source regular page");
                        let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                            .expect("the later block remains PageMap-published");
                        // SAFETY: the engine retains the map lease and this
                        // exact current allocation/page relation.
                        let memory = unsafe { page.as_ref().memid() };
                        let slice = memory
                            .arena_memory()
                            .expect("the later page uses the paired arena")
                            .slice_index as usize;
                        assert_eq!(unsafe { page.as_ref().heap() } as usize, expected);
                        assert_eq!(unsafe { page.as_ref().theap() }, expected_theap);
                        assert_eq!(
                            unsafe { arena.pages() }.unwrap().is_set_range(slice, 1),
                            Some(true),
                            "fresh later pages set the main Heap's embedded bitmap"
                        );
                        assert_eq!(
                            unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                            page.as_ptr(),
                            "the process map observes the fully initialized later page"
                        );
                        // SAFETY: `block` is still this exact engine's local allocation.
                        unsafe { allocator.free(block) }.expect("the local later free succeeds");
                        assert!(matches!(
                            allocator.finish(),
                            Ok(())
                        ), "all-free release clears the page engine");
                        owner
                            .finish_after_user_destructors()
                            .expect("the empty later source thread tears down after its page engine");
                    });
                    worker.join().expect("the later page owner remains current-thread local");
                });
                main.teardown()
                    .expect("the static main images retire after later page teardown");
                expected
            };
            assert_ne!(expected_heap, 0);
            let mutation = page_map
                .begin_page_lifecycle()
                .expect("the finished later engine releases the process map lease");
            mutation.finish().expect("the empty follow-on map lifetime releases");
        })
        .join()
        .expect("later main-heap page fixture remains current-thread local");
    }

    #[test]
    fn later_thread_rejects_a_foreign_process_pair_before_static_heap_or_map_mutation() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let foreign_subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (foreign_map, foreign_arena) = paired_process_owner(config, foreign_subprocess);
            let pair = ProcessPageArenaLease::join(foreign_map, foreign_arena)
                .expect("the foreign map and arena remain internally matched");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the independent main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    assert!(matches!(
                        MainHeapThreadProcessPageAllocator::begin(&mut owner, pair),
                        Err(MainHeapThreadProcessPageAllocatorBeginError::SubprocessMismatch)
                    ));
                    owner
                        .finish_after_user_destructors()
                        .expect("the foreign-pair rejection leaves the later owner no-page");
                });
                worker.join().expect("foreign pair check remains on the worker thread");
            });
            let mutation = foreign_map
                .begin_page_lifecycle()
                .expect("a foreign-pair refusal never takes or poisons its map lease");
            mutation.finish().expect("the untouched foreign map remains reusable");
            main.teardown()
                .expect("the foreign-pair refusal leaves the static main owner intact");
        })
        .join()
        .expect("foreign later-pair fixture remains current-thread local");
    }

    #[test]
    fn later_thread_scoped_remote_producer_is_collected_before_source_teardown() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let block = allocator.allocate(37, false).expect("the later page allocates");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the regular page remains mapped");
                    let capacity = unsafe { page.as_ref().capacity() as usize };
                    let mut local_blocks = std::vec::Vec::with_capacity(capacity);
                    local_blocks.push(block);
                    while unsafe { page.as_ref().used() } < capacity {
                        let next = allocator.allocate(37, false).expect("the direct page supplies capacity");
                        assert_eq!(unsafe { allocator.test_page_for_block(next) }, page.as_ptr());
                        local_blocks.push(next);
                    }
                    let producer = unsafe { allocator.begin_remote_free(block) }
                        .expect("the full regular later page admits its scoped producer");
                    thread::scope(|scope| {
                        let producer_thread = scope.spawn(move || producer.publish());
                        match producer_thread.join().expect("the scoped producer completes") {
                            Ok(()) => {}
                            Err((producer, _)) => {
                                let _ = producer.cancel();
                                panic!("the later remote producer must publish its exact page block");
                            }
                        }
                    });
                    let reused = allocator
                        .allocate(37, false)
                        .expect("the normal later scan false-collects the joined remote block");
                    assert_eq!(reused, block);
                    // SAFETY: collection returned this same remote block to local ownership.
                    unsafe { allocator.free(reused) }.expect("the reused remote block frees locally");
                    for local in local_blocks.into_iter().skip(1) {
                        // SAFETY: each sibling was never transferred and remains local.
                        unsafe { allocator.free(local) }.expect("the later sibling frees locally");
                    }
                    assert!(matches!(
                        allocator.finish(),
                        Ok(())
                    ), "all pages drain before user-destructor teardown");
                    owner
                        .finish_after_user_destructors()
                        .expect("the later owner tears down only after its producer joined");
                });
                worker.join().expect("later producer fixture remains scoped to its owner thread");
            });
            main.teardown()
                .expect("the static main owner waits for the later producer lifecycle");
        })
        .join()
        .expect("later remote-producer fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_force_collects_joined_remote_full_page_before_teardown() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena stays published through thread exit");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the later thread allocates one regular page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the regular page stays PageMap-published");
                    let memory = unsafe { page.as_ref().memid() };
                    let slice = memory
                        .arena_memory()
                        .expect("the full page belongs to the paired arena")
                        .slice_index as usize;
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    assert!(capacity > 1, "the owner-exit page must have a remote-free route");
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the source page reaches its full queue");
                        assert_eq!(unsafe { allocator.test_page_for_block(block) }, page.as_ptr());
                        blocks.push(block);
                    }

                    // Keep every client free in the joined remote head. Normal
                    // collection is deliberately skipped: source thread exit
                    // must clear the fast slot and take `_mi_page_free_collect`
                    // with `force == true` before it can prove this page empty.
                    for block in blocks {
                        let producer = unsafe { allocator.begin_remote_free(block) }
                            .expect("the full later page admits each scoped remote free");
                        thread::scope(|scope| {
                            let worker = scope.spawn(move || producer.publish());
                            match worker.join().expect("the remote producer completes") {
                                Ok(()) => {}
                                Err((producer, error)) => {
                                    let _ = producer.cancel();
                                    panic!("the remote free publishes before thread exit: {error:?}");
                                }
                            }
                        });
                    }
                    assert_eq!(unsafe { page.as_ref().used() }, capacity);

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    assert!(matches!(drain.finish(), Ok(())));
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "forced owner-exit collection unregisters the full PageMap span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "all-free owner exit clears the shared main bitmap before slice release"
                    );
                    owner
                        .finish_after_page_drain()
                        .expect("the now-empty later owner completes source root/list/TLD teardown");
                });
                worker.join().expect("later owner-exit fixture remains current-thread local");
            });

            main.teardown()
                .expect("the static main owner retires after the page-bearing later exit");
        })
        .join()
        .expect("later owner-exit fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_full_singleton_handoff_releases_after_its_final_free() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena stays published through thread exit");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let block = allocator
                        .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                        .expect("the later thread allocates one full arena singleton");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the singleton stays PageMap-published before thread exit");
                    let memory = unsafe { page.as_ref().memid() };
                    let slice = memory
                        .arena_memory()
                        .expect("the singleton belongs to the paired arena")
                        .slice_index as usize;
                    assert_eq!(unsafe { page.as_ref().reserved() }, 1);
                    assert_eq!(unsafe { page.as_ref().used() }, 1);

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    assert!(
                        fast_slot_peek().is_none(),
                        "the source fast root clears before owner-exit abandonment"
                    );

                    // SAFETY: `block` is the sole current allocation in the
                    // exact full singleton retained by this post-fast-slot
                    // process-map lifecycle.
                    let handoff = match unsafe { drain.abandon_full_singleton(block) } {
                        Ok(handoff) => handoff,
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Rejected {
                            drain,
                            error,
                        })
                        | Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the full singleton enters the owner-exit handoff: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("singleton abandonment does not retain a terminal owner: {error:?}");
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                        page.as_ptr(),
                        "the detached singleton remains registered until its final client free"
                    );

                    // SAFETY: this is the handoff's exact once-live client
                    // allocation. The cleared fixed fast slot is the bounded
                    // source proof that the one reclaim attempt must fail.
                    let drain = match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Rejected {
                            handoff,
                            error,
                        })
                        | Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("the singleton final free releases its sole page: {error:?}");
                        }
                    };
                    assert!(matches!(drain.finish(), Ok(())));
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) }.is_null(),
                        "the final free unregisters the full singleton PageMap span before map release"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final free clears pages_main before it returns the arena slice"
                    );
                    owner
                        .finish_after_page_drain()
                        .expect("the all-free handoff returns to source root/list/TLD teardown");
                });
                worker.join().expect("later singleton handoff remains current-thread local");
            });

            main.teardown()
                .expect("the static main owner retires after the singleton handoff");
        })
        .join()
        .expect("later singleton handoff fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_os_aligned_singleton_handoff_releases_after_its_final_free() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later OS-singleton source attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later OS-singleton source attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let block = allocator
                        .engine
                        .allocate_aligned(7, 128 * 1024)
                        .expect("the later owner creates one source OS-aligned singleton");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the OS singleton stays PageMap-published before thread exit");
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(page_ref.reserved(), 1);
                    assert_eq!(page_ref.used(), 1);
                    assert!(page_ref.memid().is_os());
                    let published = unsafe { PublishedOsAlignedPage::from_page(config, page) }
                        .expect("the source OS singleton retains its complete terminal-release token");
                    assert!(unsafe {
                        published.page_map_entries_match(
                            page_map.page_map().expect("the process PageMap remains published"),
                        )
                    });

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before OS-singleton collection: {error:?}");
                        }
                    };
                    assert!(
                        fast_slot_peek().is_none(),
                        "the source fast root clears before OS-singleton abandonment"
                    );

                    // SAFETY: `block` is the sole current allocation in the
                    // exact full OS-aligned singleton retained by this
                    // post-fast-slot process-map lifecycle.
                    let handoff = match unsafe { drain.abandon_full_singleton(block) } {
                        Ok(handoff) => handoff,
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Rejected {
                            drain,
                            error,
                        })
                        | Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the OS-aligned singleton enters the owner-exit handoff: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("OS-singleton abandonment does not retain a terminal owner: {error:?}");
                        }
                    };
                    assert!(unsafe {
                        published.page_map_entries_match(
                            page_map.page_map().expect("the process PageMap remains published"),
                        )
                    });
                    let abandoned_head = {
                        let mut heap = main_heap
                            .lock_heap()
                            .expect("the static main Heap remains projectable through OS abandonment");
                        let head = heap.heap_mut().test_os_abandoned_page_head();
                        heap.unlock()
                            .expect("the static main Heap unlocks after OS-list observation");
                        head
                    };
                    assert_eq!(
                        abandoned_head,
                        page.as_ptr(),
                        "source OS abandonment links the detached singleton before it clears the low owner"
                    );

                    // SAFETY: this is the handoff's exact once-live client
                    // allocation. The cleared fixed fast slot is the bounded
                    // source proof that the one reclaim attempt must fail.
                    let drain = match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Rejected {
                            handoff,
                            error,
                        })
                        | Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("the OS-singleton final free releases its sole page: {error:?}");
                        }
                    };
                    let abandoned_head = {
                        let mut heap = main_heap
                            .lock_heap()
                            .expect("the static main Heap remains projectable through OS release");
                        let head = heap.heap_mut().test_os_abandoned_page_head();
                        heap.unlock()
                            .expect("the static main Heap unlocks after OS-list removal observation");
                        head
                    };
                    assert!(
                        abandoned_head.is_null(),
                        "source OS release removes the all-free singleton from the private list before unmap"
                    );
                    assert!(matches!(drain.finish(), Ok(())));
                    for offset in (0..published.layout().page_map_size())
                        .step_by(crate::config::ARENA_SLICE_SIZE)
                    {
                        assert!(unsafe {
                            page_map
                                .page_map()
                                .expect("the process PageMap remains published")
                                .checked_lookup(published.slice_start().as_ptr().wrapping_add(offset))
                        }
                        .is_null());
                    }
                    owner
                        .finish_after_page_drain()
                        .expect("the all-free OS singleton returns to source root/list/TLD teardown");
                });
                worker
                    .join()
                    .expect("later OS-singleton handoff remains current-thread local");
            });

            main.teardown()
                .expect("the static main owner retires after the OS-singleton handoff");
        })
        .join()
        .expect("later OS-singleton handoff fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_os_aligned_singleton_handoff_retains_failed_unmap_terminally() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let fault = fault::install(fault::Plan::disabled());
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later failed-unmap source attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later failed-unmap source attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let block = allocator
                        .engine
                        .allocate_aligned(7, 128 * 1024)
                        .expect("the later owner creates one source OS-aligned singleton");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the OS singleton remains PageMap-published before thread exit");
                    let published = unsafe { PublishedOsAlignedPage::from_page(config, page) }
                        .expect("the source OS singleton retains its complete terminal-release token");
                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before failed OS release: {error:?}");
                        }
                    };
                    let handoff = match unsafe { drain.abandon_full_singleton(block) } {
                        Ok(handoff) => handoff,
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Rejected {
                            drain,
                            error,
                        })
                        | Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the OS singleton enters the failed-unmap handoff: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("OS abandonment unexpectedly retained terminal ownership: {error:?}");
                        }
                    };

                    fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
                    // SAFETY: this remains the handoff's exact once-live
                    // client block. The source fast-root proof still makes
                    // the one reclaim attempt fail before terminal release.
                    let handoff = match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
                        Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Terminal {
                            handoff,
                            error: ThreadExitSingletonRemoteFreeError::Release,
                        }) => handoff,
                        Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("failed OS unmap retains the exact release terminal: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitSingletonRemoteFreeFailure::Rejected {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("the exact OS singleton final free is not rejected: {error:?}");
                        }
                        Ok(drain) => {
                            core::mem::forget(drain);
                            panic!("the configured OS unmap failure must retain its handoff");
                        }
                    };
                    assert_eq!(
                        fault.observed(),
                        1,
                        "the terminal OS release attempts exactly one source unmap"
                    );
                    fault.set(fault::Plan::disabled());
                    assert!(
                        handoff.test_has_pending_os_release(),
                        "failed unmap retains the unique published mapping owner in the handoff engine"
                    );
                    let abandoned_head = {
                        let mut heap = main_heap
                            .lock_heap()
                            .expect("the static main Heap remains projectable through failed OS release");
                        let head = heap.heap_mut().test_os_abandoned_page_head();
                        heap.unlock()
                            .expect("the static main Heap unlocks after failed-release list observation");
                        head
                    };
                    assert!(
                        abandoned_head.is_null(),
                        "the source list removal precedes the failed terminal unmap"
                    );
                    for offset in (0..published.layout().page_map_size())
                        .step_by(crate::config::ARENA_SLICE_SIZE)
                    {
                        assert!(unsafe {
                            page_map
                                .page_map()
                                .expect("the process PageMap remains published")
                                .checked_lookup(published.slice_start().as_ptr().wrapping_add(offset))
                        }
                        .is_null());
                    }

                    // Dropping the terminal handoff moves the raw published
                    // mapping owner into the later attachment and latches it.
                    // This slice has no public retry lifecycle for that owner,
                    // so retain this isolated fixture rather than destroying
                    // a still-mapped source object in Drop.
                    drop(handoff);
                    assert!(matches!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned)
                    ));
                    core::mem::forget(owner);
                });
                worker
                    .join()
                    .expect("failed OS-singleton handoff remains current-thread local");
            });

            // The terminal attachment retains its published mapping owner;
            // source main teardown must not run across that unfinished owner.
            core::mem::forget(main);
        })
        .join()
        .expect("failed OS-singleton handoff fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_one_block_handoff_releases_after_its_final_free() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena stays published through thread exit");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let block = allocator
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("the later thread allocates one regular medium-page block");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the regular page stays PageMap-published before thread exit");
                    let page_ref = unsafe { page.as_ref() };
                    let memory = page_ref.memid();
                    let slice = memory
                        .arena_memory()
                        .expect("the regular page belongs to the paired arena")
                        .slice_index as usize;
                    let bin = crate::size_class::bin(page_ref.block_size())
                        .expect("the regular page has one source bin");
                    assert!(page_ref.reserved() > 1);
                    assert_eq!(page_ref.used(), 1);
                    assert!(bin < crate::config::ARENA_BIN_COUNT);

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    assert!(
                        fast_slot_peek().is_none(),
                        "the source fast root clears before mapped abandonment"
                    );

                    // SAFETY: `block` is the sole current allocation in the
                    // sole medium regular arena page retained by this
                    // post-fast-slot process-map lifecycle.
                    let handoff = match unsafe { drain.abandon_mapped_one_block(block) } {
                        Ok(handoff) => handoff,
                        Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::Rejected {
                            drain,
                            error,
                        })
                        | Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the medium page enters the mapped owner-exit handoff: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("mapped abandonment does not retain a terminal owner: {error:?}");
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                        page.as_ptr(),
                        "the mapped-abandoned page remains registered until its final client free"
                    );
                    assert!(
                        arena
                            .abandoned_pages(bin)
                            .expect("the medium bin has a main arena abandoned map")
                            .is_published(slice),
                        "mapped abandonment publishes the exact main-heap abandoned bit before final free"
                    );
                    let mapped_count = {
                        let mut heap = main_heap
                            .lock_heap()
                            .expect("the shared static heap remains live through mapped abandonment");
                        let count = heap
                            .heap_mut()
                            .abandoned_count(bin)
                            .expect("the medium bin has a source heap abandoned counter");
                        heap.unlock()
                            .expect("the static heap projection unlocks after count observation");
                        count
                    };
                    assert_eq!(
                        mapped_count,
                        1,
                        "main-heap mapped publication increments its paired source abandoned counter"
                    );

                    // SAFETY: this is the handoff's exact once-live client
                    // allocation. With one live block, source abandoned-free
                    // collection must become empty before any reclaim branch.
                    let drain = match unsafe { handoff.remote_free_to_empty(block) } {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeFailure::Rejected {
                            handoff,
                            error,
                        })
                        | Err(MainHeapThreadProcessPageExitMappedOneBlockRemoteFreeFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("the mapped one-block final free releases its sole page: {error:?}");
                        }
                    };
                    assert!(matches!(drain.finish(), Ok(())));
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) }.is_null(),
                        "the final free unregisters the mapped page span before map release"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final free clears pages_main before it returns the arena slice"
                    );
                    assert!(
                        !arena
                            .abandoned_pages(bin)
                            .expect("the medium bin remains inspectable after release")
                            .is_published(slice),
                        "the final free quiesces and clears the mapped-abandoned bit before slice release"
                    );
                    let final_count = {
                        let mut heap = main_heap
                            .lock_heap()
                            .expect("the shared static heap remains live through mapped release");
                        let count = heap
                            .heap_mut()
                            .abandoned_count(bin)
                            .expect("the medium bin keeps its source heap abandoned counter");
                        heap.unlock()
                            .expect("the static heap projection unlocks after final count observation");
                        count
                    };
                    assert_eq!(
                        final_count,
                        0,
                        "mapped final release consumes its paired main-heap abandoned counter"
                    );
                    owner
                        .finish_after_page_drain()
                        .expect("the mapped handoff returns to source root/list/TLD teardown");
                });
                worker.join().expect("later mapped handoff remains current-thread local");
            });

            main.teardown()
                .expect("the static main owner retires after the mapped handoff");
        })
        .join()
        .expect("later mapped handoff fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_one_block_handoff_rejects_before_detach_when_another_page_is_live() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the owner-exit boundary");
                    let regular = allocator
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates the medium one-block page");
                    let regular_page = unsafe { allocator.test_page_for_block(regular) };
                    let other = allocator
                        .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates another live arena page");
                    let other_page = unsafe { allocator.test_page_for_block(other) };

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    let drain = match unsafe { drain.abandon_mapped_one_block(regular) } {
                        Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::Rejected {
                            drain,
                            error,
                        }) => {
                            assert_eq!(
                                error,
                                MainHeapThreadProcessPageExitMappedOneBlockAbandonError::NotOnlyPage,
                                "the bounded handoff refuses to skip source queue traversal"
                            );
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the sole-page check is pre-collection: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitMappedOneBlockAbandonFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("the sole-page check is pre-detach: {error:?}");
                        }
                        Ok(handoff) => {
                            core::mem::forget(handoff);
                            panic!("a second live page must block the mapped handoff");
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(regular.as_ptr()) },
                        regular_page,
                        "the regular page remains registered after the pre-detach refusal"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(other.as_ptr()) },
                        other_page,
                        "the other page remains registered after the pre-detach refusal"
                    );
                    assert_eq!(unsafe { (*regular_page).used() }, 1);

                    // A general traversal is still intentionally absent; keep
                    // this isolated post-fast-slot image terminal after the
                    // pre-detach proof rather than inventing cleanup.
                    core::mem::forget(drain);
                    core::mem::forget(owner);
                });
                worker.join().expect("multi-page mapped boundary remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("multi-page mapped handoff fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_singleton_handoff_rejects_before_detach_when_another_page_is_live() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the owner-exit boundary");
                    let other = allocator
                        .allocate(16, false)
                        .expect("the fixture creates an earlier live page");
                    let other_page = unsafe { allocator.test_page_for_block(other) };
                    let singleton = allocator
                        .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates the later full singleton");
                    let singleton_page = unsafe { allocator.test_page_for_block(singleton) };

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    let drain = match unsafe { drain.abandon_full_singleton(singleton) } {
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Rejected {
                            drain,
                            error,
                        }) => {
                            assert_eq!(
                                error,
                                MainHeapThreadProcessPageExitSingletonAbandonError::NotOnlyPage,
                                "the bounded handoff refuses to skip source queue traversal"
                            );
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the sole-page check is pre-collection: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitSingletonAbandonFailure::Terminal {
                            handoff,
                            error,
                        }) => {
                            core::mem::forget(handoff);
                            panic!("the sole-page check is pre-detach: {error:?}");
                        }
                        Ok(handoff) => {
                            core::mem::forget(handoff);
                            panic!("a second live page must block the singleton handoff");
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(other.as_ptr()) },
                        other_page,
                        "the earlier page remains registered after the pre-detach refusal"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(singleton.as_ptr()) },
                        singleton_page,
                        "the singleton remains registered after the pre-detach refusal"
                    );
                    assert_eq!(unsafe { (*singleton_page).used() }, 1);

                    // A general traversal is still intentionally absent; keep
                    // this isolated post-fast-slot image terminal after the
                    // pre-detach proof rather than inventing cleanup.
                    core::mem::forget(drain);
                    core::mem::forget(owner);
                });
                worker.join().expect("multi-page singleton boundary remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("multi-page singleton boundary fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_collects_later_full_pages_before_retaining_an_earlier_live_page() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena stays published through thread exit");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the owner-exit boundary");

                    let live = allocator
                        .allocate(16, false)
                        .expect("the fixture creates an earlier live small page");
                    let live_page = NonNull::new(unsafe { allocator.test_page_for_block(live) })
                        .expect("the small page stays PageMap-published");

                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates a later regular page");
                    let full_page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the later regular page stays PageMap-published");
                    assert_ne!(live_page, full_page);
                    let full_memory = unsafe { full_page.as_ref().memid() };
                    let full_slice = full_memory
                        .arena_memory()
                        .expect("the full page belongs to the paired arena")
                        .slice_index as usize;
                    let capacity = unsafe { full_page.as_ref().reserved() as usize };
                    assert!(capacity > 1, "the later page must reach the full queue");
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the later regular page reaches its full queue");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            full_page.as_ptr()
                        );
                        blocks.push(block);
                    }
                    for block in blocks {
                        let producer = unsafe { allocator.begin_remote_free(block) }
                            .expect("the later full page admits each scoped remote free");
                        thread::scope(|scope| {
                            let worker = scope.spawn(move || producer.publish());
                            match worker.join().expect("the remote producer completes") {
                                Ok(()) => {}
                                Err((producer, error)) => {
                                    let _ = producer.cancel();
                                    panic!("the remote free publishes before thread exit: {error:?}");
                                }
                            }
                        });
                    }

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    let retained = match drain.finish() {
                        Err(MainHeapThreadProcessPageExitDrainFinishError::Retained(drain)) => {
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitDrainFinishError::PageMap(error)) => {
                            panic!("a retained live page cannot finish the PageMap lifecycle: {error:?}")
                        }
                        Ok(()) => panic!("the earlier live page must retain the thread-exit drain"),
                    };

                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the drain force-collects and releases a later full page before retaining"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(full_slice, 1),
                        Some(true),
                        "the later all-free page clears the shared main bitmap before retention"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(live.as_ptr()) },
                        live_page.as_ptr(),
                        "the earlier live page remains registered for a future general abandonment route"
                    );

                    drop(retained);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "a retained post-fast-slot drain cannot imitate root/list/TLD teardown"
                    );
                    core::mem::forget(owner);
                });
                worker.join().expect("mixed owner-exit fixture remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("mixed owner-exit fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_retains_a_nonempty_page_after_the_fast_slot_is_clear() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the owner-exit boundary");
                    let block = allocator
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates one still-live regular page");
                    let page = unsafe { allocator.test_page_for_block(block) };

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("the attached owner must clear its fast slot before traversal: {error:?}");
                        }
                    };
                    let retained = match drain.finish() {
                        Err(MainHeapThreadProcessPageExitDrainFinishError::Retained(drain)) => {
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitDrainFinishError::PageMap(error)) => {
                            panic!("a live page cannot reach PageMap release: {error:?}")
                        }
                        Ok(()) => panic!("the bounded all-free drain must not release a live page"),
                    };
                    drop(retained);

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping a retained post-fast-slot drain cannot imitate list/TLD teardown"
                    );
                    assert!(matches!(
                        page_map.begin_page_lifecycle(),
                        Err(ProcessPageMapError::Poisoned)
                    ));
                    assert_eq!(
                        unsafe {
                            page_map
                                .test_retained_page_map()
                                .expect("the terminal root retains its process map image")
                                .checked_lookup(block.as_ptr())
                        },
                        page,
                        "the retained drain leaves the live PageMap registration intact"
                    );
                    // The source-complete abandonment path is intentionally
                    // absent; keep this isolated live owner terminal.
                    core::mem::forget(owner);
                });
                worker.join().expect("nonempty owner-exit fixture remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("nonempty owner-exit fixture remains current-thread local");
    }

    #[test]
    fn unfinished_later_page_engine_poison_retains_the_attachment_and_process_map() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the retained-page fixture");
                    let block = allocator.allocate(37, false).expect("the fixture creates one live page");
                    let page = unsafe { allocator.test_page_for_block(block) };
                    drop(allocator);
                    assert_eq!(
                        owner.finish_after_user_destructors(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping a live later page engine cannot imitate source thread teardown"
                    );
                    assert!(matches!(
                        page_map.begin_page_lifecycle(),
                        Err(ProcessPageMapError::Poisoned)
                    ));
                    assert_eq!(
                        unsafe {
                            page_map
                                .test_retained_page_map()
                                .expect("the terminal process root retains its map image")
                                .checked_lookup(block.as_ptr())
                        },
                        page,
                        "the terminal map retains the live later page registration"
                    );
                    core::mem::forget(owner);
                });
                worker.join().expect("retained later page fixture remains current-thread local");
            });
            // The static main Heap still contains the retained later Theap,
            // so no bounded source teardown exists for this intentionally
            // terminal test image.
            core::mem::forget(main);
        })
        .join()
        .expect("unfinished later page fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_tears_down_before_two_client_frees() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the regular post-exit route");
                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates a medium regular page");
                    let second = allocator
                        .allocate(request, false)
                        .expect("the fixture keeps two client blocks live in that page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the first client block is PageMap-published");
                    assert_eq!(
                        unsafe { allocator.test_page_for_block(second) },
                        page.as_ptr(),
                        "the fixture keeps both client blocks in the same medium page"
                    );
                    let memory = unsafe { page.as_ref().memid() };
                    let slice = memory
                        .arena_memory()
                        .expect("the regular page belongs to the paired arena")
                        .slice_index as usize;

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit reaches its post-fast-slot drain: {error:?}");
                        }
                    };
                    let route = match unsafe {
                        drain.abandon_mapped_small_or_medium_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!(
                            "the sole nonfull medium page crosses into the process-owned post-exit route"
                        ),
                    };

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the route releases the old Theap/TLD before any client free"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the detached page remains PageMap-routable after TLD teardown"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(false),
                        "the ordinary main-arena bit remains live until the final client free"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));

                    let route = match unsafe { route.remote_free_after_thread_exit(first) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(route)) => {
                            route
                        }
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released) => {
                            panic!("one of two client frees cannot release the page")
                        }
                        Err(_) => panic!("the first client free stays routed after TLD teardown"),
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(second.as_ptr()) },
                        page.as_ptr(),
                        "the first client free leaves the still-live page registered"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));

                    match unsafe { route.remote_free_after_thread_exit(second) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released) => {}
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(route)) => {
                            core::mem::forget(route);
                            panic!("the second client free releases the now-empty page")
                        }
                        Err(_) => panic!("the final client free releases the detached page"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the final release unregisters the full PageMap span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final release clears the ordinary main-arena bit before slice return"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the completed post-exit route reopens an empty process-map lifecycle"
                    );
                });
                worker
                    .join()
                    .expect("post-exit client frees remain local to the later owner fixture");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("post-exit mapped regular route fixture remains current-thread local");
    }

    fn assert_later_thread_exit_mapped_medium_route_adoption(
        exhaust_immediate_blocks: bool,
    ) {
        thread::spawn(move || {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the reclaim route");
                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let mut source = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source attachment retained: {error:?}")
                        }
                    };
                    let mut source_allocator = MainHeapThreadProcessPageAllocator::begin(&mut source, pair)
                        .expect("the source attachment admits one medium page");
                    let first = source_allocator
                        .allocate(request, false)
                        .expect("the source creates one medium page");
                    let second = source_allocator
                        .allocate(request, false)
                        .expect("the source keeps two client blocks live in that page");
                    let page = NonNull::new(unsafe { source_allocator.test_page_for_block(first) })
                        .expect("the source medium page stays PageMap-published");
                    assert_eq!(
                        unsafe { source_allocator.test_page_for_block(second) },
                        page.as_ptr(),
                        "the source fixture keeps both client blocks in the sole medium page"
                    );
                    let mut inherited = std::vec![first, second];
                    let extension = if exhaust_immediate_blocks {
                        while !unsafe { page.as_ref().free_list_head() }.is_null() {
                            let block = source_allocator
                                .allocate(request, false)
                                .expect("the source extends only its sole medium page");
                            assert_eq!(
                                unsafe { source_allocator.test_page_for_block(block) },
                                page.as_ptr(),
                                "exhausting immediate capacity never takes a fresh arena page"
                            );
                            inherited.push(block);
                        }
                        let page_ref = unsafe { page.as_ref() };
                        assert!(
                            page_ref.used() == usize::from(page_ref.capacity())
                                && page_ref.capacity() < page_ref.reserved(),
                            "the source route leaves a nonfull medium page exactly at its extend boundary"
                        );
                        assert_eq!(
                            page_ref.slice_pcommitted(),
                            0,
                            "the committed arena fixture admits only the source no-commit extension branch"
                        );
                        let extend = crate::page::page_extend_count(
                            page_ref.capacity(),
                            page_ref.reserved(),
                            page_ref.block_size(),
                            page_ref.slice_pcommitted(),
                        )
                        .expect("the exhausted source medium page has one valid extension count");
                        assert!(extend > 0, "the bounded branch has capacity left to extend");
                        Some((page_ref.capacity(), extend))
                    } else {
                        let spare = source_allocator
                            .allocate(request, false)
                            .expect("the source can retain one immediately reusable medium block");
                        assert_eq!(
                            unsafe { source_allocator.test_page_for_block(spare) },
                            page.as_ptr(),
                            "the source's reusable block belongs to the same sole medium page"
                        );
                        unsafe {
                            source_allocator
                                .free(spare)
                                .expect("the source returns one block to the immediate local free list");
                        }
                        None
                    };
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Medium),
                        "the adoption boundary starts with the narrow medium source class"
                    );
                    assert!(
                        page_ref.used() > 0 && page_ref.used() < usize::from(page_ref.reserved()),
                        "the source page is nonfull before its owner exits"
                    );
                    if exhaust_immediate_blocks {
                        assert!(
                            page_ref.free_list_head().is_null(),
                            "the exhausted fixture reaches the source extension boundary before exit"
                        );
                    }
                    let bin = crate::size_class::bin(page_ref.block_size())
                        .expect("the medium source page has one regular bin");
                    let memory = page_ref.memid();
                    let slice = memory
                        .arena_memory()
                        .expect("the source page belongs to the paired arena")
                        .slice_index as usize;

                    let drain = source_allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("source owner reaches its post-fast-slot drain: {error:?}");
                    });
                    let route = match unsafe {
                        drain.abandon_mapped_small_or_medium_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!("the sole nonfull medium page enters its mapped post-exit route"),
                    };
                    assert_eq!(
                        source.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the source Theap/TLD is gone before a fresh owner can reclaim its page"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));
                    assert_eq!(
                        unsafe { page.as_ref().free_list_head().is_null() },
                        exhaust_immediate_blocks,
                        "source owner-exit collection exposes either an immediate block or the extension boundary"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the mapped route retains the exact source PageMap entry"
                    );

                    let mut target = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("fresh target attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("fresh target attachment retained: {error:?}")
                        }
                    };
                    let mut target_allocator = match route.adopt_into_later_main(&mut target, pair) {
                        Ok(allocator) => allocator,
                        Err(MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                            error,
                            ..
                        }) => panic!(
                            "the exact mapped medium route transfers into the fresh later-main page owner: {error:?}"
                        ),
                        Err(MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                            error,
                            ..
                        }) => panic!(
                            "the exact mapped medium route transfers into the fresh later-main page owner: {error:?}"
                        ),
                        Err(MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                            error,
                            ..
                        }) => panic!(
                            "the committed source fixture cannot enter the on-demand reabandon branch: {error:?}"
                        ),
                    };

                    assert_eq!(
                        unsafe { target_allocator.test_page_for_block(first) },
                        page.as_ptr(),
                        "the new owner retains the original first client block's PageMap identity"
                    );
                    assert_eq!(
                        unsafe { target_allocator.test_page_for_block(second) },
                        page.as_ptr(),
                        "the new owner retains the original second client block's PageMap identity"
                    );
                    {
                        let mut heap = main_heap
                            .lock_heap()
                            .expect("the static main Heap remains projectable after reclaim");
                        assert_eq!(
                            heap.heap_mut().abandoned_count(bin),
                            Some(0),
                            "successful source reclaim consumes the paired static-main abandoned count"
                        );
                        heap.unlock()
                            .expect("the reclaim observation releases the static-main heap projection");
                    }
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(false),
                        "reclaim retains the original ordinary arena-page ownership instead of taking a fresh slice"
                    );
                    assert_eq!(
                        target_allocator.test_queue_count(bin),
                        Some(1),
                        "source reclaim restores the exact page at the target regular queue tail"
                    );
                    if let Some((capacity_before, extend)) = extension {
                        let page_ref = unsafe { page.as_ref() };
                        assert_eq!(
                            page_ref.capacity(),
                            capacity_before + extend,
                            "source reclaim extends the exact page before normal allocation resumes"
                        );
                        assert!(
                            !page_ref.free_list_head().is_null(),
                            "the source extension publishes an immediate block before return"
                        );
                    }

                    let reused = target_allocator
                        .allocate(request, false)
                        .expect("the target allocates from the reclaimed medium page before fresh allocation");
                    assert_eq!(
                        unsafe { target_allocator.test_page_for_block(reused) },
                        page.as_ptr(),
                        "the first target allocation reuses the exact source page"
                    );

                    unsafe {
                        for block in inherited {
                            target_allocator
                                .free(block)
                                .expect("the target frees every inherited client block");
                        }
                        target_allocator
                            .free(reused)
                            .expect("the target frees its reclaimed-page allocation");
                    }
                    match target_allocator.finish() {
                        Ok(()) => {}
                        Err(_) => panic!("the reclaimed target page lifecycle finishes after every client free"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "normal target cleanup unregisters the reclaimed page only after its final free"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "normal target cleanup clears the original arena bit before releasing its slice"
                    );
                    assert_eq!(
                        target.finish_after_user_destructors(),
                        Ok(()),
                        "the fresh target completes its ordinary later-thread teardown after the reclaimed page is gone"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the reclaimed page's normal release reopens the process-map lifecycle"
                    );
                });
                worker
                    .join()
                    .expect("the source and target reclaim fixture remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("mapped medium reclaim fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_medium_route_adopts_into_a_fresh_later_owner() {
        assert_later_thread_exit_mapped_medium_route_adoption(false);
    }

    #[test]
    fn later_thread_exit_mapped_medium_route_extends_before_returning_a_fresh_later_owner() {
        assert_later_thread_exit_mapped_medium_route_adoption(true);
    }

    fn assert_later_thread_exit_mapped_medium_on_demand_adoption(
        fail_first_page_area_commit: bool,
    ) {
        thread::spawn(move || {
            let fault = fault::install(fault::Plan::disabled());
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_reserved_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the reserved process map and arena form one source image");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the reserved paired arena remains published through the route");
                    let mut source = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("on-demand source attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("on-demand source attachment retained: {error:?}")
                        }
                    };
                    let mut source_allocator = MainHeapThreadProcessPageAllocator::begin(&mut source, pair)
                        .expect("the reserved source attachment admits one medium page");
                    source_allocator.test_enable_page_commit_on_demand();
                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = source_allocator
                        .allocate(request, false)
                        .expect("the source commits exactly its first medium-page prefix");
                    let page = NonNull::new(unsafe { source_allocator.test_page_for_block(first) })
                        .expect("the first on-demand client block is PageMap-published");
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Medium),
                        "the source fixture selects the bounded medium page class"
                    );
                    assert!(
                        page_ref.slice_pcommitted() != 0,
                        "the test-only fresh seam records an actual source on-demand prefix"
                    );
                    assert!(
                        page_ref.free_list_head().is_null(),
                        "one source block exhausts the initial committed medium prefix"
                    );
                    assert!(
                        page_ref.used() > 0 && page_ref.used() < usize::from(page_ref.reserved()),
                        "the on-demand page stays nonfull before its owner exits"
                    );
                    let source_capacity = page_ref.capacity();
                    let source_pcommitted = page_ref.slice_pcommitted();
                    let source_used = page_ref.used();
                    let source_free = page_ref.free_list_head();
                    let bin = crate::size_class::bin(page_ref.block_size())
                        .expect("the medium source page has one regular bin");
                    let memory = page_ref.memid();
                    let slice = memory
                        .arena_memory()
                        .expect("the source page belongs to the paired reserved arena")
                        .slice_index as usize;
                    let slice_start = arena
                        .slice_start(slice)
                        .expect("the source slice still has its registered leading address");
                    let page_start = page
                        .as_ptr()
                        .addr()
                        .checked_add(page_ref.page_offset())
                        .expect("the fresh source page offset is representable");
                    let page_slice_offset = page_start
                        .checked_sub(slice_start.addr())
                        .expect("the fresh source block area begins inside its leading slice");
                    let extension_plan = crate::page::page_area_commit_plan(
                        source_capacity,
                        page_ref.reserved(),
                        page_ref.block_size(),
                        source_pcommitted,
                        config.page_size().bytes(),
                        page_slice_offset,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Medium)
                            .expect("the medium source span is fixed")
                            * crate::config::ARENA_SLICE_SIZE,
                    )
                    .expect("the exhausted source prefix has one valid direct page-area extension");
                    assert!(extension_plan.extend > 0);
                    assert!(extension_plan.commit_size > 0);

                    let drain = source_allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("on-demand source owner reaches its post-fast-slot drain: {error:?}");
                    });
                    let route = match unsafe {
                        drain.abandon_mapped_small_or_medium_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!(
                            "the sole on-demand nonfull medium page enters its mapped post-exit route"
                        ),
                    };
                    assert_eq!(
                        source.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the source Theap/TLD is gone before the fresh owner reclaims its prefix"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));

                    let mut target = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("on-demand target attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("on-demand target attachment retained: {error:?}")
                        }
                    };
                    let target_theap = target
                        .test_theap_pointer()
                        .expect("the fresh target Theap remains live for source reassociation");
                    let mut target_allocator = if fail_first_page_area_commit {
                        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
                        let reabandoned = match route.adopt_into_later_main(&mut target, pair) {
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                                    adoption,
                                    error:
                                        MainHeapThreadProcessPageExitMappedRegularAdoptError::PageCommit(
                                            ProcessPageArenaLeaseError::Arena(
                                                crate::process_arena::ProcessSharedArenaError::Mapping(
                                                    Errno::NOMEM,
                                                ),
                                            ),
                                        ),
                                },
                            ) => adoption,
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                                    route,
                                    error,
                                },
                            ) => {
                                core::mem::forget(route);
                                panic!("the source route must transfer before direct commit: {error:?}");
                            }
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                                    adoption,
                                    error,
                                },
                            ) => {
                                core::mem::forget(adoption);
                                panic!("a direct commit failure must reabandon rather than retain: {error:?}");
                            }
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                                    adoption,
                                    error,
                                },
                            ) => {
                                core::mem::forget(adoption);
                                panic!("the injected direct commit failure has the exact mapping error: {error:?}");
                            }
                            Ok(allocator) => {
                                core::mem::forget(allocator);
                                panic!("the injected direct commit failure cannot return a normal target");
                            }
                        };
                        assert_eq!(
                            unsafe { page.as_ref().slice_pcommitted() },
                            source_pcommitted,
                            "a failed direct mapping commit leaves the source page prefix count unchanged"
                        );
                        assert_eq!(
                            unsafe { page.as_ref().capacity() },
                            source_capacity,
                            "a failed direct mapping commit precedes every free-list capacity write"
                        );
                        assert_eq!(unsafe { page.as_ref().used() }, source_used);
                        assert_eq!(unsafe { page.as_ref().free_list_head() }, source_free);
                        assert_eq!(
                            reabandoned.engine.queue_count(bin),
                            Some(0),
                            "source reabandon removes the page from the failed target queue"
                        );
                        assert_eq!(
                            unsafe { page.as_ref().abandoned_test_thread_id() },
                            THREAD_ID_ABANDONED_MAPPED,
                            "source reabandon restores the mapped-abandoned identity"
                        );
                        assert_eq!(
                            unsafe { page.as_ref().theap() },
                            target_theap,
                            "source reabandon retains the target Theap pointer for same-owner reclaim"
                        );
                        assert_eq!(
                            unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                            page.as_ptr(),
                            "the failed direct commit keeps the exact PageMap registration"
                        );
                        assert_eq!(
                            unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                            Some(false),
                            "the failed direct commit keeps the ordinary arena-page bit"
                        );
                        {
                            let mut heap = main_heap
                                .lock_heap()
                                .expect("the static main Heap remains projectable after reabandon");
                            assert_eq!(
                                heap.heap_mut().abandoned_count(bin),
                                Some(1),
                                "source reabandon restores the exact paired static-main count"
                            );
                            heap.unlock()
                                .expect("the reabandon observation releases the static-main heap projection");
                        }
                        assert!(matches!(
                            page_map.begin_page_lifecycle(),
                            Err(ProcessPageMapError::LifecycleBusy)
                        ));
                        fault.set(fault::Plan::disabled());
                        match reabandoned.retry() {
                            Ok(allocator) => allocator,
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                                    adoption,
                                    error,
                                },
                            ) => {
                                core::mem::forget(adoption);
                                panic!("the disabled mapping fault permits the same candidate retry: {error:?}");
                            }
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                                    adoption,
                                    error,
                                },
                            ) => {
                                core::mem::forget(adoption);
                                panic!("the same candidate retry cannot retain terminally: {error:?}");
                            }
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                                    route,
                                    error,
                                },
                            ) => {
                                core::mem::forget(route);
                                panic!("a long same-candidate retry cannot reopen a short route: {error:?}");
                            }
                        }
                    } else {
                        match route.adopt_into_later_main(&mut target, pair) {
                            Ok(allocator) => allocator,
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                                    error,
                                    ..
                                },
                            ) => panic!("the reserved medium source route transfers into the target: {error:?}"),
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                                    error,
                                    ..
                                },
                            ) => panic!("the reserved medium source route cannot retain: {error:?}"),
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                                    error,
                                    ..
                                },
                            ) => panic!("the fault-free direct mapping commit cannot reabandon: {error:?}"),
                        }
                    };

                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        page_ref.slice_pcommitted(),
                        extension_plan.next_slice_pcommitted,
                        "successful source direct commitment publishes its new OS-page count"
                    );
                    assert_eq!(
                        page_ref.capacity(),
                        source_capacity + extension_plan.extend,
                        "direct commitment precedes exactly one source free-list extension"
                    );
                    assert!(!page_ref.free_list_head().is_null());
                    assert_eq!(target_allocator.test_queue_count(bin), Some(1));
                    assert_eq!(
                        unsafe { target_allocator.test_page_for_block(first) },
                        page.as_ptr(),
                        "the target retains the original PageMap identity after on-demand reclaim"
                    );
                    let reused = target_allocator
                        .allocate(request, false)
                        .expect("the target allocates the directly committed second source block");
                    assert_eq!(
                        unsafe { target_allocator.test_page_for_block(reused) },
                        page.as_ptr(),
                        "the target reuses the exact source page instead of taking a fresh slice"
                    );
                    unsafe {
                        target_allocator
                            .free(first)
                            .expect("the original prefix block remains normally freeable");
                        target_allocator
                            .free(reused)
                            .expect("the directly committed extension block remains normally freeable");
                    }
                    match target_allocator.finish() {
                        Ok(()) => {}
                        Err(_) => panic!("the on-demand reclaimed target lifecycle finishes after both frees"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "normal target cleanup unregisters the re-adopted page"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "normal target cleanup clears the original ordinary arena bit"
                    );
                    assert_eq!(
                        target.finish_after_user_destructors(),
                        Ok(()),
                        "the fresh target tears down after the re-adopted page is released"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the finished re-adoption lifecycle reopens the process map"
                    );
                });
                worker
                    .join()
                    .expect("on-demand mapped-medium adoption remains local to its fixture thread");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("reserved mapped-medium adoption fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_medium_on_demand_commits_before_reuse() {
        assert_later_thread_exit_mapped_medium_on_demand_adoption(false);
    }

    #[test]
    fn later_thread_exit_mapped_medium_on_demand_reabandons_after_commit_failure_then_retries() {
        assert_later_thread_exit_mapped_medium_on_demand_adoption(true);
    }

    /// Independent source model of `mi_theap_queue_first_update`'s direct
    /// range. This test-side calculation intentionally uses the frozen queue
    /// table rather than `PageAllocatorEngine`'s helper, so the route fixture
    /// catches a shared bad cache-range translation.
    fn source_direct_cache_range(block_size: usize) -> (usize, usize) {
        let index = crate::invariants::word_count(block_size)
            .expect("the rounded source block size has a direct-cache index");
        assert!(index < PAGES_DIRECT, "the direct range stays in source bounds");
        if index <= 1 {
            return (0, index);
        }

        let bin = crate::size_class::bin(block_size)
            .expect("the direct source block size has one regular queue bin");
        assert!(bin > 0, "a direct cache index above one has a predecessor bin");
        let mut previous = bin - 1;
        while previous > 0
            && crate::size_class::bin(BIN_BLOCK_SIZES[previous]) == Some(bin)
        {
            previous -= 1;
        }
        let start = crate::invariants::word_count(BIN_BLOCK_SIZES[previous])
            .expect("the source predecessor block size has a word count")
            .checked_add(1)
            .expect("the direct range start cannot overflow")
            .min(index);
        (start, index)
    }

    fn assert_small_regular_route(request: usize, direct: bool, reject_adoption: bool) {
        thread::spawn(move || {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the small post-exit route");
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates one small regular page");
                    let second = allocator
                        .allocate(request, false)
                        .expect("the fixture keeps two client blocks live in the page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the first client block is PageMap-published");
                    assert_eq!(
                        unsafe { allocator.test_page_for_block(second) },
                        page.as_ptr(),
                        "the fixture keeps both client blocks in the same small page"
                    );
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Small),
                        "the request stays in the small source page class"
                    );
                    if direct {
                        assert!(
                            page_ref.block_size() <= SMALL_SIZE_MAX,
                            "the rounded source block size stays in the direct-cache range"
                        );
                        let direct_index = crate::invariants::word_count(page_ref.block_size())
                            .expect("the rounded direct block size has a source cache index");
                        let (direct_start, direct_end) =
                            source_direct_cache_range(page_ref.block_size());
                        assert_eq!(direct_index, direct_end);
                        for index in 0..PAGES_DIRECT {
                            let expected = if index >= direct_start && index <= direct_end {
                                page.as_ptr()
                            } else {
                                EMPTY_PAGE.as_ptr()
                            };
                            assert_eq!(
                                allocator.test_direct_page(index),
                                Some(expected),
                                "the source direct-cache image covers only its exact rounded range"
                            );
                        }
                    } else {
                        assert!(
                            page_ref.block_size() > SMALL_SIZE_MAX,
                            "the small page bypasses the source direct-cache threshold"
                        );
                    }
                    assert!(
                        page_ref.used() < usize::from(page_ref.reserved()),
                        "the small page stays nonfull before its owner exits"
                    );
                    let memory = page_ref.memid();
                    let slice = memory
                        .arena_memory()
                        .expect("the regular page belongs to the paired arena")
                        .slice_index as usize;

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit reaches its post-fast-slot drain: {error:?}");
                        }
                    };
                    let route = match unsafe {
                        drain.abandon_mapped_small_or_medium_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!(
                            "the sole nonfull small page crosses into the process-owned post-exit route"
                        ),
                    };

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the route releases the old Theap/TLD before any client free"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the detached small page remains PageMap-routable after TLD teardown"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(false),
                        "the ordinary main-arena bit remains live until the final client free"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));

                    let route = if reject_adoption {
                        let mut target = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap,
                                metadata,
                                config,
                            )
                        } {
                            Ok(owner) => owner,
                            Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                panic!("fresh small-route target attachment rejected: {error:?}")
                            }
                            Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                                panic!("fresh small-route target attachment retained: {error:?}")
                            }
                        };
                        let route = match route.adopt_into_later_main(&mut target, pair) {
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                                    route,
                                    error,
                                },
                            ) => {
                                assert_eq!(
                                    error,
                                    MainHeapThreadProcessPageExitMappedRegularAdoptError::SourceNotMedium,
                                    "a small mapped route rejects before PageMap access or target-engine transfer"
                                );
                                route
                            }
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                                    adoption,
                                    error,
                                },
                            ) => {
                                core::mem::forget(adoption);
                                panic!(
                                    "a small mapped route rejects before any target state transition: {error:?}"
                                );
                            }
                            Err(
                                MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                                    adoption,
                                    error,
                                },
                            ) => {
                                core::mem::forget(adoption);
                                panic!(
                                    "a small mapped route cannot enter the medium page-commit branch: {error:?}"
                                );
                            }
                            Ok(allocator) => {
                                core::mem::forget(allocator);
                                panic!("a small mapped route cannot become a normal allocation owner");
                            }
                        };
                        assert_eq!(
                            target.finish_after_user_destructors(),
                            Ok(()),
                            "the pre-transfer small refusal leaves the fresh target attachment empty"
                        );
                        assert_eq!(
                            unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                            page.as_ptr(),
                            "the pre-transfer small refusal leaves the exact PageMap entry untouched"
                        );
                        assert_eq!(route.test_abandoned_count(), Some(1));
                        route
                    } else {
                        route
                    };

                    let route = match unsafe { route.remote_free_after_thread_exit(first) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(route)) => {
                            route
                        }
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released) => {
                            panic!("one of two client frees cannot release the small page")
                        }
                        Err(_) => panic!("the first client free stays routed after TLD teardown"),
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(second.as_ptr()) },
                        page.as_ptr(),
                        "the first client free leaves the still-live small page registered"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));

                    match unsafe { route.remote_free_after_thread_exit(second) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released) => {}
                        Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(route)) => {
                            core::mem::forget(route);
                            panic!("the second client free releases the now-empty small page")
                        }
                        Err(_) => panic!("the final client free releases the detached small page"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the final release unregisters the full PageMap span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final release clears the ordinary main-arena bit before slice return"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the completed post-exit route reopens an empty process-map lifecycle"
                    );
                });
                worker
                    .join()
                    .expect("post-exit small client frees remain local to the later owner fixture");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("post-exit small route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_tears_down_before_two_non_direct_small_client_frees() {
        assert_small_regular_route(SMALL_SIZE_MAX + WORD_SIZE, false, false);
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_accepts_non_direct_small_upper_boundary() {
        assert_small_regular_route(SMALL_MAX_OBJ_SIZE, false, false);
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_tears_down_before_two_direct_small_client_frees() {
        assert_small_regular_route(WORD_SIZE, true, false);
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_accepts_direct_small_upper_boundary() {
        assert_small_regular_route(SMALL_SIZE_MAX, true, false);
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_rejects_direct_small_allocation_adoption() {
        assert_small_regular_route(WORD_SIZE, true, true);
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_refuses_malformed_direct_image_before_detach() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the malformed-direct-image fixture");
                    let block = allocator
                        .allocate(SMALL_SIZE_MAX, false)
                        .expect("the fixture creates one source direct-cache small page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the direct small page remains PageMap-published before thread exit");
                    let direct_index = crate::invariants::word_count(unsafe { page.as_ref().block_size() })
                        .expect("the rounded direct block size has a source cache index");
                    assert_eq!(allocator.test_direct_page(direct_index), Some(page.as_ptr()));
                    assert!(
                        allocator.test_set_direct_page(
                            direct_index,
                            crate::types::EMPTY_PAGE.as_ptr(),
                        ),
                        "the fixture can model one stale direct-cache slot"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let drain = match unsafe {
                        drain.abandon_mapped_small_or_medium_to_process_route(block)
                    } {
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::Rejected {
                                drain,
                                error,
                            },
                        ) => {
                            assert_eq!(
                                error,
                                ThreadExitMappedRegularPostExitAbandonError::NotOnlyPage,
                                "a stale direct-cache image rejects before source collection or detachment"
                            );
                            drain
                        }
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::RetainedDrain {
                                drain,
                                error,
                            },
                        ) => {
                            core::mem::forget(drain);
                            panic!("the direct-image preflight rejects before a source transition: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the direct-image preflight rejects before Theap/TLD teardown");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the direct-image preflight rejects before PageMap-route transfer: {error:?}");
                        }
                        Ok(route) => {
                            core::mem::forget(route);
                            panic!("a malformed direct-cache image cannot cross into the process route");
                        }
                    };
                    assert_eq!(
                        drain.test_direct_page(direct_index),
                        Some(crate::types::EMPTY_PAGE.as_ptr()),
                        "the rejected preflight leaves the stale direct slot untouched"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                        page.as_ptr(),
                        "the direct-image refusal leaves PageMap publication untouched"
                    );
                    assert_eq!(
                        unsafe { page.as_ref().used() },
                        1,
                        "the direct-image refusal leaves the source object count untouched"
                    );

                    drop(drain);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping the rejected drain cannot imitate process-route teardown"
                    );
                    core::mem::forget(owner);
                });
                worker
                    .join()
                    .expect("the malformed direct-image refusal remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("malformed direct-image route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_refuses_full_non_direct_small_before_detach() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the full non-direct-small refusal fixture");
                    let request = SMALL_SIZE_MAX + WORD_SIZE;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates one non-direct small regular page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the small page remains PageMap-published before thread exit");
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    assert!(capacity > 1, "the small page has a full-state boundary");
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the fixture fills the non-direct small page");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            page.as_ptr(),
                            "the fixture fills exactly one non-direct small page"
                        );
                        blocks.push(block);
                    }
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Small),
                        "the full page remains in the admitted small source class"
                    );
                    assert!(
                        page_ref.block_size() > SMALL_SIZE_MAX,
                        "the full page bypasses the source direct-cache threshold"
                    );
                    assert_eq!(
                        page_ref.used(),
                        usize::from(page_ref.reserved()),
                        "the fixture reaches the source full object count"
                    );
                    assert!(
                        !crate::types::page_queue::page_is_in_full(page_ref),
                        "small full pages may remain in their regular queue, so count validation is required"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let drain = match unsafe {
                        drain.abandon_mapped_regular_pages_to_process_route()
                    } {
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                                drain,
                                error,
                            },
                        ) => {
                            assert_eq!(
                                error,
                                ThreadExitMappedRegularPagesPostExitAbandonError::NotMappedRegular,
                                "a full non-direct small page rejects before source collection or detachment"
                            );
                            drain
                        }
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                                drain,
                                error,
                            },
                        ) => {
                            core::mem::forget(drain);
                            panic!("the full small boundary rejects before a source transition: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the full small boundary rejects before Theap/TLD teardown");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the full small boundary rejects before PageMap-route transfer: {error:?}");
                        }
                        Ok(route) => {
                            core::mem::forget(route);
                            panic!("a full non-direct small page cannot cross into the process route");
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the full-small refusal leaves PageMap publication untouched"
                    );
                    assert_eq!(
                        unsafe { page.as_ref().used() },
                        capacity,
                        "the full-small refusal leaves the source object count untouched"
                    );

                    drop(drain);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping the rejected drain cannot imitate process-route teardown"
                    );
                    core::mem::forget(owner);
                });
                worker
                    .join()
                    .expect("the full non-direct-small refusal remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("full non-direct-small process-route refusal fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_full_medium_route_reabandons_after_mostly_used_frees() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the full-medium fixture");
                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates one medium regular page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the full-medium page stays PageMap-published");
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    assert!(
                        capacity >= 16,
                        "the chosen medium geometry exposes the source mostly-used unmapped phase"
                    );
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the fixture fills exactly one medium page");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            page.as_ptr(),
                            "the fixture does not allocate a second medium page"
                        );
                        blocks.push(block);
                    }
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Medium),
                        "the source route begins with a regular medium page"
                    );
                    assert_eq!(
                        page_ref.used(),
                        capacity,
                        "the fixture reaches the full medium-page boundary"
                    );
                    assert!(
                        crate::types::page_queue::page_is_in_full(page_ref),
                        "a full medium page enters the source full queue"
                    );
                    let memory = page_ref.memid();
                    let slice = memory
                        .arena_memory()
                        .expect("the full medium page belongs to the paired arena")
                        .slice_index as usize;

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let mut route = match unsafe {
                        drain.abandon_full_medium_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!(
                            "the full medium page enters its sequential post-exit process route"
                        ),
                    };

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the full-medium route tears down the old Theap/TLD before client frees"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the initially unmapped full page remains PageMap-routable after teardown"
                    );
                    assert!(
                        !route.test_is_mapped(),
                        "a full medium page begins source-abandoned without a bitmap publication"
                    );
                    assert_eq!(
                        route.test_abandoned_count(),
                        Some(0),
                        "the initial full-page state has no static-main abandoned count"
                    );

                    let unmapped_frees = capacity / 8;
                    assert!(unmapped_frees > 0);
                    let mut index = 0usize;
                    while index < unmapped_frees {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::Released) => {
                                panic!("a mostly-used medium page cannot release before all client frees")
                            }
                            Err(_) => panic!("a mostly-used full page remains an unmapped route"),
                        };
                        assert!(
                            !route.test_is_mapped(),
                            "the source keeps a page unmapped through its mostly-used threshold"
                        );
                        assert_eq!(route.test_abandoned_count(), Some(0));
                        index += 1;
                    }

                    route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::StillLive(route)) => {
                            route
                        }
                        Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::Released) => {
                            panic!("the first below-mostly-used free cannot release the full medium page")
                        }
                        Err(_) => panic!("the first below-mostly-used free reabandons the page to mapped"),
                    };
                    assert!(
                        route.test_is_mapped(),
                        "the source reabandons the page into the static-main bitmap below mostly used"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));
                    index += 1;

                    while index + 1 < capacity {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::Released) => {
                                panic!("a nonfinal mapped client free cannot release the medium page")
                            }
                            Err(_) => panic!("a mapped medium client free remains in the route"),
                        };
                        assert!(route.test_is_mapped());
                        index += 1;
                    }

                    match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::Released) => {}
                        Ok(MainHeapThreadProcessPageExitFullMediumFreeResult::StillLive(route)) => {
                            core::mem::forget(route);
                            panic!("the final client free releases the full-medium route")
                        }
                        Err(_) => panic!("the final client free releases the full-medium route"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the final route release unregisters the medium PageMap span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final route release clears the ordinary main-arena bit"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the completed full-medium route reopens an empty process map"
                    );
                });
                worker
                    .join()
                    .expect("the full-medium process route remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("full-medium post-exit route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_full_large_route_reabandons_after_mostly_used_frees() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the full-large fixture");
                    let request = MEDIUM_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates one large regular page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the full-large page stays PageMap-published");
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    assert!(
                        capacity >= 16,
                        "the chosen large geometry exposes the source mostly-used unmapped phase"
                    );
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the fixture fills exactly one large page");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            page.as_ptr(),
                            "the fixture does not allocate a second large page"
                        );
                        blocks.push(block);
                    }
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Large),
                        "the source route begins with a regular large page"
                    );
                    assert_eq!(
                        page_ref.used(),
                        capacity,
                        "the fixture reaches the full large-page boundary"
                    );
                    assert!(
                        crate::types::page_queue::page_is_in_full(page_ref),
                        "a full large page enters the source full queue"
                    );
                    let memory = page_ref.memid();
                    let arena_memory = memory
                        .arena_memory()
                        .expect("the full large page belongs to the paired arena");
                    let slice = arena_memory.slice_index as usize;
                    let slice_count = arena_memory.slice_count as usize;
                    assert_eq!(
                        slice_count,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Large).unwrap(),
                        "the route retains the source large page's complete 64-slice span"
                    );
                    let slice_start = arena
                        .slice_start(slice)
                        .expect("the large arena span has a source start address");

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let mut route = match unsafe {
                        drain.abandon_full_large_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!(
                            "the full large page enters its sequential post-exit process route"
                        ),
                    };

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the full-large route tears down the old Theap/TLD before client frees"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the initially unmapped full page remains PageMap-routable after teardown"
                    );
                    assert!(
                        !route.test_is_mapped(),
                        "a full large page begins source-abandoned without a bitmap publication"
                    );
                    assert_eq!(
                        route.test_abandoned_count(),
                        Some(0),
                        "the initial full-page state has no static-main abandoned count"
                    );

                    let unmapped_frees = capacity / 8;
                    assert!(unmapped_frees > 0);
                    let mut index = 0usize;
                    while index < unmapped_frees {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::Released) => {
                                panic!("a mostly-used large page cannot release before all client frees")
                            }
                            Err(_) => panic!("a mostly-used full page remains an unmapped route"),
                        };
                        assert!(
                            !route.test_is_mapped(),
                            "the source keeps a page unmapped through its mostly-used threshold"
                        );
                        assert_eq!(route.test_abandoned_count(), Some(0));
                        index += 1;
                    }

                    route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::StillLive(route)) => {
                            route
                        }
                        Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::Released) => {
                            panic!("the first below-mostly-used free cannot release the full large page")
                        }
                        Err(_) => panic!("the first below-mostly-used free reabandons the page to mapped"),
                    };
                    assert!(
                        route.test_is_mapped(),
                        "the source reabandons the page into the static-main bitmap below mostly used"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));
                    index += 1;

                    while index + 1 < capacity {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::Released) => {
                                panic!("a nonfinal mapped client free cannot release the large page")
                            }
                            Err(_) => panic!("a mapped large client free remains in the route"),
                        };
                        assert!(route.test_is_mapped());
                        index += 1;
                    }

                    match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::Released) => {}
                        Ok(MainHeapThreadProcessPageExitFullLargeFreeResult::StillLive(route)) => {
                            core::mem::forget(route);
                            panic!("the final client free releases the full-large route")
                        }
                        Err(_) => panic!("the final client free releases the full-large route"),
                    }
                    for offset in 0..slice_count {
                        let address = unsafe { slice_start.add(offset * crate::config::ARENA_SLICE_SIZE) };
                        assert!(
                            unsafe { page_map.page_map().unwrap().checked_lookup(address) }.is_null(),
                            "the final route release unregisters every large PageMap slice"
                        );
                    }
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final route release clears the ordinary main-arena bit"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the completed full-large route reopens an empty process map"
                    );
                });
                worker
                    .join()
                    .expect("the full-large process route remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("full-large post-exit route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_full_non_direct_small_route_reabandons_after_mostly_used_frees() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the full non-direct-small fixture");
                    let request = SMALL_SIZE_MAX + WORD_SIZE;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates one non-direct small regular page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the full non-direct small page stays PageMap-published");
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the fixture fills exactly one non-direct small page");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            page.as_ptr(),
                            "the fixture does not allocate a second small page"
                        );
                        blocks.push(block);
                    }
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Small),
                        "the source route begins with a regular small page"
                    );
                    assert!(
                        page_ref.block_size() > SMALL_SIZE_MAX,
                        "the source route intentionally excludes the direct-cache small range"
                    );
                    assert_eq!(
                        page_ref.used(),
                        capacity,
                        "the fixture reaches the full small-page boundary"
                    );
                    assert!(
                        !crate::types::page_queue::page_is_in_full(page_ref),
                        "a full small page remains in its source regular queue"
                    );
                    let memory = page_ref.memid();
                    let arena_memory = memory
                        .arena_memory()
                        .expect("the full small page belongs to the paired arena");
                    let slice = arena_memory.slice_index as usize;
                    assert_eq!(
                        arena_memory.slice_count as usize,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Small).unwrap(),
                        "the route retains the source small page's one-slice span"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let mut route = match unsafe {
                        drain.abandon_full_non_direct_small_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!(
                            "the full non-direct small page enters its sequential post-exit process route"
                        ),
                    };

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the full-small route tears down the old Theap/TLD before client frees"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the initially unmapped full small page remains PageMap-routable after teardown"
                    );
                    assert!(
                        !route.test_is_mapped(),
                        "a full small page begins source-abandoned without a bitmap publication"
                    );
                    assert_eq!(
                        route.test_abandoned_count(),
                        Some(0),
                        "the initial full-small state has no static-main abandoned count"
                    );

                    let unmapped_frees = capacity / 8;
                    assert!(unmapped_frees > 0);
                    let mut index = 0usize;
                    while index < unmapped_frees {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::Released) => {
                                panic!("a mostly-used small page cannot release before all client frees")
                            }
                            Err(_) => panic!("a mostly-used full small page remains an unmapped route"),
                        };
                        assert!(
                            !route.test_is_mapped(),
                            "the source keeps a small page unmapped through its mostly-used threshold"
                        );
                        assert_eq!(route.test_abandoned_count(), Some(0));
                        index += 1;
                    }

                    route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::StillLive(route)) => {
                            route
                        }
                        Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::Released) => {
                            panic!("the first below-mostly-used free cannot release the full small page")
                        }
                        Err(_) => panic!("the first below-mostly-used free reabandons the page to mapped"),
                    };
                    assert!(
                        route.test_is_mapped(),
                        "the source reabandons the small page into the static-main bitmap below mostly used"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));
                    index += 1;

                    while index + 1 < capacity {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::Released) => {
                                panic!("a nonfinal mapped client free cannot release the small page")
                            }
                            Err(_) => panic!("a mapped small client free remains in the route"),
                        };
                        assert!(route.test_is_mapped());
                        index += 1;
                    }

                    match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::Released) => {}
                        Ok(MainHeapThreadProcessPageExitFullNonDirectSmallFreeResult::StillLive(route)) => {
                            core::mem::forget(route);
                            panic!("the final client free releases the full non-direct-small route")
                        }
                        Err(_) => panic!("the final client free releases the full non-direct-small route"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the final route release unregisters the small PageMap span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final route release clears the ordinary main-arena bit"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the completed full non-direct-small route reopens an empty process map"
                    );
                });
                worker
                    .join()
                    .expect("the full non-direct-small process route remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("full non-direct-small post-exit route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_full_direct_small_route_reabandons_after_mostly_used_frees() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the full direct-small fixture");
                    let request = SMALL_SIZE_MAX;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates one direct small regular page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the full direct small page stays PageMap-published");
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    assert!(
                        capacity >= 16,
                        "the source direct partial collector requires the pinned reserved floor"
                    );
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the fixture fills exactly one direct small page");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            page.as_ptr(),
                            "the fixture does not allocate a second direct small page"
                        );
                        blocks.push(block);
                    }
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Small),
                        "the source route begins with a regular small page"
                    );
                    assert!(
                        page_ref.block_size() <= SMALL_SIZE_MAX,
                        "the source route intentionally remains in the direct-cache range"
                    );
                    assert_eq!(
                        page_ref.used(),
                        capacity,
                        "the fixture reaches the full direct small-page boundary"
                    );
                    assert!(
                        !crate::types::page_queue::page_is_in_full(page_ref),
                        "the frozen full-retain profile leaves this full direct small page in its regular queue"
                    );
                    let (direct_start, direct_end) = source_direct_cache_range(page_ref.block_size());
                    for index in 0..PAGES_DIRECT {
                        let expected = if index >= direct_start && index <= direct_end {
                            page.as_ptr()
                        } else {
                            EMPTY_PAGE.as_ptr()
                        };
                        assert_eq!(
                            allocator.test_direct_page(index),
                            Some(expected),
                            "the full direct small page retains its complete rounded source cache image"
                        );
                    }
                    let memory = page_ref.memid();
                    let arena_memory = memory
                        .arena_memory()
                        .expect("the full direct small page belongs to the paired arena");
                    let slice = arena_memory.slice_index as usize;
                    assert_eq!(
                        arena_memory.slice_count as usize,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Small).unwrap(),
                        "the route retains the source direct small page's one-slice span"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let mut route = match unsafe {
                        drain.abandon_full_direct_small_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!(
                            "the full direct small page enters its sequential post-exit process route"
                        ),
                    };

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the full direct-small route tears down the old Theap/TLD before client frees"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the initially unmapped full direct small page remains PageMap-routable after teardown"
                    );
                    assert!(
                        !route.test_is_mapped(),
                        "a full direct small page begins source-abandoned without a bitmap publication"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(0));

                    // `_mi_page_free_collect_partly` leaves the just-pushed
                    // atomic head for the next remote free to collect. The
                    // source therefore still observes `used == capacity` on
                    // the first free, and crosses the strictly-below-mostly-
                    // used boundary one client free later than the normal
                    // collector path.
                    let unmapped_frees = capacity / 8 + 1;
                    assert!(unmapped_frees > 0);
                    let mut index = 0usize;
                    while index < unmapped_frees {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::Released) => {
                                panic!("a mostly-used direct small page cannot release before all client frees")
                            }
                            Err(_) => panic!("a mostly-used full direct small page remains an unmapped route"),
                        };
                        assert!(
                            !route.test_is_mapped(),
                            "the source keeps a direct small page unmapped through its retained partial-collector head"
                        );
                        assert_eq!(route.test_abandoned_count(), Some(0));
                        index += 1;
                    }

                    route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::StillLive(route)) => route,
                        Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::Released) => {
                            panic!("the first post-head below-mostly-used free cannot release the full direct small page")
                        }
                        Err(_) => panic!("the first post-head below-mostly-used free reabandons the direct page to mapped"),
                    };
                    assert!(
                        route.test_is_mapped(),
                        "the source reabandons the direct small page into the static-main bitmap below mostly used"
                    );
                    assert_eq!(route.test_abandoned_count(), Some(1));
                    index += 1;

                    while index + 1 < capacity {
                        route = match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                            Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::StillLive(route)) => {
                                route
                            }
                            Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::Released) => {
                                panic!("a nonfinal mapped direct small client free cannot release the page")
                            }
                            Err(_) => panic!("a mapped direct small client free remains in the route"),
                        };
                        assert!(route.test_is_mapped());
                        index += 1;
                    }

                    match unsafe { route.remote_free_after_thread_exit(blocks[index]) } {
                        Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::Released) => {}
                        Ok(MainHeapThreadProcessPageExitFullDirectSmallFreeResult::StillLive(route)) => {
                            core::mem::forget(route);
                            panic!("the final client free releases the full direct-small route")
                        }
                        Err(_) => panic!("the final client free releases the full direct-small route"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the final route release unregisters the direct small PageMap span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "the final route release clears the ordinary main-arena bit"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the completed full direct-small route reopens an empty process map"
                    );
                });
                worker
                    .join()
                    .expect("the full direct-small process route remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("full direct-small post-exit route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_full_direct_small_route_refuses_stale_rounded_direct_cache_before_detach() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the full-direct-cache refusal fixture");
                    let request = SMALL_SIZE_MAX;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates one direct small page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the full direct small page stays PageMap-published");
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    assert!(capacity >= 16, "the source partial collector floor remains visible");
                    let mut allocated = 1usize;
                    while allocated < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the fixture fills exactly one direct small page");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            page.as_ptr(),
                            "the refusal fixture does not create a second direct small page"
                        );
                        allocated += 1;
                    }
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(page_ref.used(), capacity);
                    assert!(
                        page_ref.block_size() <= SMALL_SIZE_MAX
                            && !crate::types::page_queue::page_is_in_full(page_ref),
                        "the refusal begins with the direct full-small queue shape"
                    );
                    let bin = crate::size_class::bin(page_ref.block_size())
                        .expect("the full direct-small page has one regular source bin");
                    let (_direct_start, direct_end) = source_direct_cache_range(page_ref.block_size());
                    assert_eq!(allocator.test_direct_page(direct_end), Some(page.as_ptr()));
                    assert!(
                        allocator.test_set_direct_page(direct_end, EMPTY_PAGE.as_ptr()),
                        "the fixture can model one stale full direct-cache slot"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let drain = match unsafe {
                        drain.abandon_full_direct_small_to_process_route(first)
                    } {
                        Err(
                            MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::Rejected {
                                drain,
                                error,
                            },
                        ) => {
                            assert_eq!(
                                error,
                                ThreadExitFullDirectSmallPostExitAbandonError::NotOnlyPage,
                                "a stale rounded direct-cache slot rejects before source collection or detachment"
                            );
                            drain
                        }
                        Err(
                            MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::RetainedDrain {
                                drain,
                                error,
                            },
                        ) => {
                            core::mem::forget(drain);
                            panic!("the full direct-cache preflight rejects before a source transition: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the full direct-cache preflight rejects before Theap/TLD teardown");
                        }
                        Err(MainHeapThreadProcessPageExitFullDirectSmallRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the full direct-cache preflight rejects before PageMap-route transfer: {error:?}");
                        }
                        Ok(route) => {
                            core::mem::forget(route);
                            panic!("a malformed full direct-cache image cannot cross into the process route");
                        }
                    };
                    assert_eq!(
                        drain.test_direct_page(direct_end),
                        Some(EMPTY_PAGE.as_ptr()),
                        "the rejected full-direct preflight leaves the stale cache slot untouched"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        page.as_ptr(),
                        "the rejected full-direct preflight leaves PageMap publication untouched"
                    );
                    assert_eq!(
                        unsafe { page.as_ref().used() },
                        capacity,
                        "the rejected full-direct preflight leaves the source object count untouched"
                    );
                    assert_eq!(
                        drain.test_queue_count(bin),
                        Some(1),
                        "the rejected full-direct preflight leaves its sole source queue member attached"
                    );
                    assert!(
                        !crate::types::page_queue::page_is_in_full(unsafe { page.as_ref() }),
                        "the rejected full-direct preflight leaves the ordinary source queue placement untouched"
                    );

                    drop(drain);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping the rejected full-direct drain cannot imitate process-route teardown"
                    );
                    core::mem::forget(owner);
                });
                worker
                    .join()
                    .expect("the full direct-cache refusal remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("full direct-cache refusal fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_refuses_another_live_page_before_detach() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the rejection fixture");
                    let regular = allocator
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates a medium regular page");
                    let regular_page = unsafe { allocator.test_page_for_block(regular) };
                    let other = allocator
                        .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates a second live source page");
                    let other_page = unsafe { allocator.test_page_for_block(other) };

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit enters its post-fast-slot drain: {error:?}");
                        }
                    };
                    let drain = match unsafe {
                        drain.abandon_mapped_small_or_medium_to_process_route(regular)
                    } {
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::Rejected {
                                drain,
                                error,
                            },
                        ) => {
                            assert_eq!(
                                error,
                                ThreadExitMappedRegularPostExitAbandonError::NotOnlyPage,
                                "the first route cannot skip another source page"
                            );
                            drain
                        }
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::RetainedDrain {
                                drain,
                                error,
                            },
                        ) => {
                            core::mem::forget(drain);
                            panic!("the sole-page check precedes source collection: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the sole-page check precedes Theap/TLD teardown");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the sole-page check precedes PageMap-route transfer: {error:?}");
                        }
                        Ok(route) => {
                            core::mem::forget(route);
                            panic!("a second live page must block the one-page process route");
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(regular.as_ptr()) },
                        regular_page,
                        "the target page remains registered after the pre-detach refusal"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(other.as_ptr()) },
                        other_page,
                        "the other live page remains registered after the pre-detach refusal"
                    );

                    drop(drain);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping the retained drain cannot imitate process-route teardown"
                    );
                    core::mem::forget(owner);
                });
                worker
                    .join()
                    .expect("the process-route refusal remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("post-exit mapped regular route refusal fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_route_can_move_to_the_client_free_thread() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the cross-thread route");
                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator.allocate(request, false).unwrap();
                    let second = allocator.allocate(request, false).unwrap();
                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let route = match unsafe {
                        drain.abandon_mapped_small_or_medium_to_process_route(first)
                    } {
                        Ok(route) => route,
                        Err(_) => panic!("the sole medium page enters the movable process route"),
                    };
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the producing thread has no surviving Theap/TLD route"
                    );
                    (
                        route,
                        first.as_ptr().expose_provenance(),
                        second.as_ptr().expose_provenance(),
                    )
                });
                let (route, first_address, second_address) = worker
                    .join()
                    .expect("the post-exit route transfers out of its originating thread");
                // The client aliases are ordinary C-like raw addresses. The
                // worker exposed their still-live allocation provenance before
                // transfer; recreate a pointer only for the consuming free.
                let first = NonNull::new(core::ptr::with_exposed_provenance_mut(first_address))
                    .expect("the first client address remains non-null");
                let second = NonNull::new(core::ptr::with_exposed_provenance_mut(second_address))
                    .expect("the second client address remains non-null");
                let route = match unsafe { route.remote_free_after_thread_exit(first) } {
                    Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(route)) => {
                        route
                    }
                    Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released) => {
                        panic!("one of two cross-thread client frees cannot release the page")
                    }
                    Err(_) => panic!("the first cross-thread client free remains routable"),
                };
                match unsafe { route.remote_free_after_thread_exit(second) } {
                    Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released) => {}
                    Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(route)) => {
                        core::mem::forget(route);
                        panic!("the second cross-thread client free releases the page")
                    }
                    Err(_) => panic!("the final cross-thread client free releases the page"),
                }
                assert!(
                    unsafe {
                        page_map
                            .page_map()
                            .unwrap()
                            .checked_lookup(core::ptr::with_exposed_provenance::<u8>(first_address))
                    }
                    .is_null(),
                    "the moved route still performs the final PageMap release"
                );
            });
            core::mem::forget(main);
        })
        .join()
        .expect("moved post-exit route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_tears_down_and_releases_mixed_pages() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the multi-page route");
                    let small_request = WORD_SIZE;
                    let small_first = allocator
                        .allocate(small_request, false)
                        .expect("the fixture creates the first direct small page client");
                    let small_page = NonNull::new(unsafe { allocator.test_page_for_block(small_first) })
                        .expect("the direct small page is PageMap-published");
                    let small_remaining = allocator
                        .allocate(small_request, false)
                        .expect("the fixture keeps a second live direct small client");
                    assert_eq!(
                        unsafe { allocator.test_page_for_block(small_remaining) },
                        small_page.as_ptr(),
                        "the direct small clients share one nonfull regular page"
                    );
                    let small_page_ref = unsafe { small_page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(small_page_ref.block_size()),
                        Some(crate::types::PageKind::Small),
                        "the first aggregate member remains a small page"
                    );
                    assert!(
                        small_page_ref.block_size() <= SMALL_SIZE_MAX
                            && small_page_ref.reserved() >= 16,
                        "the aggregate member satisfies the source direct-small partial-collect precondition"
                    );
                    let (small_direct_start, small_direct_end) =
                        source_direct_cache_range(small_page_ref.block_size());
                    for index in 0..PAGES_DIRECT {
                        let expected = if index >= small_direct_start && index <= small_direct_end {
                            small_page.as_ptr()
                        } else {
                            EMPTY_PAGE.as_ptr()
                        };
                        assert_eq!(
                            allocator.test_direct_page(index),
                            Some(expected),
                            "the aggregate preflight starts from the complete source direct-cache image"
                        );
                    }
                    let medium_request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(medium_request, false)
                        .expect("the fixture creates the first medium page");
                    let first_page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the first page is PageMap-published");
                    let first_remaining = allocator
                        .allocate(medium_request, false)
                        .expect("the fixture keeps a second live medium client");
                    assert_eq!(
                        unsafe { allocator.test_page_for_block(first_remaining) },
                        first_page.as_ptr(),
                        "the two medium clients share one nonfull regular page"
                    );
                    let second = allocator
                        .allocate(MEDIUM_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates one live large page");
                    let second_page = NonNull::new(unsafe { allocator.test_page_for_block(second) })
                        .expect("the large page is PageMap-published");
                    assert_ne!(
                        second_page,
                        first_page,
                        "the medium and large requests keep separate source pages"
                    );
                    assert_ne!(
                        small_page,
                        first_page,
                        "the direct small and medium requests keep separate source pages"
                    );
                    assert_ne!(
                        small_page,
                        second_page,
                        "the direct small and large requests keep separate source pages"
                    );
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe {
                            first_page.as_ref().block_size()
                        }),
                        Some(crate::types::PageKind::Medium),
                        "the first route member remains a medium page"
                    );
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe {
                            second_page.as_ref().block_size()
                        }),
                        Some(crate::types::PageKind::Large),
                        "the second route member crosses the source large-page boundary"
                    );
                    assert_eq!(small_page_ref.used(), 2);
                    assert_eq!(unsafe { first_page.as_ref().used() }, 2);
                    assert_eq!(unsafe { second_page.as_ref().used() }, 1);

                    let small_memory = small_page_ref.memid();
                    let small_slice = small_memory
                        .arena_memory()
                        .expect("the direct small page belongs to the paired arena")
                        .slice_index as usize;
                    let first_memory = unsafe { first_page.as_ref().memid() };
                    let first_slice = first_memory
                        .arena_memory()
                        .expect("the first medium page belongs to the paired arena")
                        .slice_index as usize;
                    let second_memory = unsafe { second_page.as_ref().memid() };
                    let second_slice = second_memory
                        .arena_memory()
                        .expect("the large page belongs to the paired arena")
                        .slice_index as usize;
                    let second_slice_count = second_memory
                        .arena_memory()
                        .expect("the large page retains arena provenance")
                        .slice_count as usize;
                    assert_eq!(
                        second_slice_count,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Large).unwrap(),
                        "the mixed route retains the large page's full span"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let route = match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => route,
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
                            core::mem::forget(drain);
                            panic!("mixed live small, medium, and large pages cannot become an empty drain")
                        }
                        Err(_) => panic!("the mixed regular pages enter one post-exit process route"),
                    };

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the aggregate route tears down the old Theap/TLD before client frees"
                    );
                    assert_eq!(route.test_remaining_pages(), 3);
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(small_first.as_ptr()) },
                        small_page.as_ptr(),
                        "the direct small page remains routed after teardown"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) },
                        first_page.as_ptr(),
                        "the first abandoned page remains routed after teardown"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(second.as_ptr()) },
                        second_page.as_ptr(),
                        "the second abandoned page remains routed after teardown"
                    );

                    let route = match unsafe { route.remote_free_after_thread_exit(small_first) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(route)) => route,
                        Ok(_) => panic!("one of two retained direct-small clients cannot release its page"),
                        Err(_) => panic!("the first direct-small client remains routable"),
                    };
                    let route = match unsafe { route.remote_free_after_thread_exit(first) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(route)) => route,
                        Ok(_) => panic!("one of two retained medium clients cannot release its page"),
                        Err(_) => panic!("the first medium client remains routable"),
                    };
                    let route = match unsafe { route.remote_free_after_thread_exit(second) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => route,
                        Ok(_) => panic!("the large page releases while both small and medium pages remain routed"),
                        Err(_) => panic!("the large page releases through the aggregate route"),
                    };
                    assert_eq!(route.test_remaining_pages(), 2);
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(second.as_ptr()) }.is_null(),
                        "the released second page unregisters only its own span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(second_slice, 1),
                        Some(true),
                        "the released large page clears its ordinary arena bit"
                    );
                    assert_eq!(
                        unsafe { arena.slices_free() }
                            .unwrap()
                            .is_set_range(second_slice, second_slice_count),
                        Some(true),
                        "the released large page returns its complete arena span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(first_slice, 1),
                        Some(false),
                        "the medium page remains ordinary-arena owned until its final client free"
                    );

                    let route = match unsafe { route.remote_free_after_thread_exit(small_remaining) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => route,
                        Ok(_) => panic!("the final direct-small client releases one page while medium remains routed"),
                        Err(_) => panic!("the final direct-small client releases through the aggregate route"),
                    };
                    assert_eq!(route.test_remaining_pages(), 1);
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(small_first.as_ptr()) }.is_null(),
                        "the final direct-small free unregisters its page"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(small_slice, 1),
                        Some(true),
                        "the final direct-small free clears its ordinary arena bit"
                    );

                    match unsafe { route.remote_free_after_thread_exit(first_remaining) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedAll) => {}
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(route))
                        | Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => {
                            core::mem::forget(route);
                            panic!("the final retained client releases the last routed page")
                        }
                        Err(_) => panic!("the final routed page releases its span"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the final aggregate release unregisters the remaining page"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "only the last routed page reopens the empty process map"
                    );
                });
                worker
                    .join()
                    .expect("the aggregate route remains local to its later owner fixture");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("multi-page post-exit route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_releases_retired_large_before_live_medium() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the retirement fixture");
                    let retired = allocator
                        .allocate(MEDIUM_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates a retired large page");
                    let retired_page = NonNull::new(unsafe { allocator.test_page_for_block(retired) })
                        .expect("the large page is PageMap-published");
                    let live = allocator
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates a live medium page in another bin");
                    let live_page = NonNull::new(unsafe { allocator.test_page_for_block(live) })
                        .expect("the live medium page is PageMap-published");
                    assert_ne!(
                        retired_page, live_page,
                        "the retirement fixture keeps an all-free and live page independently queued"
                    );
                    assert_ne!(
                        crate::size_class::bin(unsafe { retired_page.as_ref().block_size() }),
                        crate::size_class::bin(unsafe { live_page.as_ref().block_size() }),
                        "distinct medium and large bins prevent the live allocation from reviving the retired page"
                    );
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe {
                            retired_page.as_ref().block_size()
                        }),
                        Some(crate::types::PageKind::Large),
                        "the first page has the source large geometry"
                    );
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe {
                            live_page.as_ref().block_size()
                        }),
                        Some(crate::types::PageKind::Medium),
                        "the live route member remains a medium page"
                    );
                    let retired_memory = unsafe { retired_page.as_ref().memid() };
                    let retired_slice = retired_memory
                        .arena_memory()
                        .expect("the retired large page belongs to the paired arena")
                        .slice_index as usize;
                    let retired_slice_count = retired_memory
                        .arena_memory()
                        .expect("the retired large page retains arena provenance")
                        .slice_count as usize;
                    assert_eq!(
                        retired_slice_count,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Large).unwrap(),
                        "the retired page has the full large regular span"
                    );

                    // SAFETY: this is the first large page's one current
                    // local allocation. Its normal free leaves a source
                    // retired page in the queue, while the other bin remains
                    // live for the post-exit process route.
                    unsafe { allocator.free(retired) }
                        .expect("the ordinary local free retires the empty large page");
                    assert_eq!(unsafe { retired_page.as_ref().used() }, 0);
                    assert_ne!(
                        unsafe { retired_page.as_ref().retire_expire() },
                        0,
                        "ordinary local free leaves this empty regular page retired"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(retired.as_ptr()) },
                        retired_page.as_ptr(),
                        "retirement retains the PageMap span until the source thread-exit prepass"
                    );
                    assert_eq!(unsafe { live_page.as_ref().used() }, 1);

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let route = match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => route,
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
                            core::mem::forget(drain);
                            panic!("one live medium page still requires a process route")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the retired-page source prepass releases before the live medium route: {error:?}")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("retired-page collection retains only a failed source transition: {error:?}")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the retired-page prepass still tears down the old Theap/TLD")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the live page transfers its short PageMap route: {error:?}")
                        }
                    };
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the route tears down the old Theap/TLD after source retirement"
                    );
                    assert_eq!(route.test_remaining_pages(), 1);
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(retired.as_ptr()) }.is_null(),
                        "the retired page releases before the live page is published into the route"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(retired_slice, 1),
                        Some(true),
                        "the source retirement prepass clears the retired page's ordinary arena bit"
                    );
                    assert_eq!(
                        unsafe { arena.slices_free() }
                            .unwrap()
                            .is_set_range(retired_slice, retired_slice_count),
                        Some(true),
                        "the source retirement prepass releases the retired large span"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(live.as_ptr()) },
                        live_page.as_ptr(),
                        "only the live medium page remains PageMap-registered for its client free"
                    );

                    match unsafe { route.remote_free_after_thread_exit(live) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedAll) => {}
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(route))
                        | Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => {
                            core::mem::forget(route);
                            panic!("the one live routed page releases after its final client free")
                        }
                        Err(_) => panic!("the final live client releases through the aggregate route"),
                    }
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the live route's final release reopens the process map after retirement"
                    );
                });
                worker
                    .join()
                    .expect("the retired-page aggregate fixture remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("retired-page aggregate fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_rejects_malformed_direct_image_before_mutation() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the malformed-direct-image fixture");
                    let block = allocator
                        .allocate(WORD_SIZE, false)
                        .expect("the fixture creates one live direct small page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the direct small page remains PageMap-published before thread exit");
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe {
                            page.as_ref().block_size()
                        }),
                        Some(crate::types::PageKind::Small),
                        "the refusal fixture starts in the aggregate route's direct-small class"
                    );
                    let direct_index = crate::invariants::word_count(unsafe { page.as_ref().block_size() })
                        .expect("the direct small block size has a source cache index");
                    assert_eq!(allocator.test_direct_page(direct_index), Some(page.as_ptr()));
                    assert!(
                        allocator.test_set_direct_page(direct_index, EMPTY_PAGE.as_ptr()),
                        "the fixture can model one stale direct-cache slot"
                    );
                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });

                    let drain = match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                            drain,
                            error,
                        }) => {
                            assert_eq!(
                                error,
                                ThreadExitMappedRegularPagesPostExitAbandonError::Queue,
                                "a stale direct-cache slot rejects before source retirement or queue mutation"
                            );
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the stale direct image must reject before a source transition: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the stale direct image must reject before Theap/TLD teardown")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the stale direct image must reject before PageMap-route transfer: {error:?}")
                        }
                        Ok(route) => {
                            core::mem::forget(route);
                            panic!("a malformed direct-cache image cannot cross into an aggregate route")
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                        page.as_ptr(),
                        "the malformed direct-image preflight leaves PageMap publication untouched"
                    );
                    assert_eq!(unsafe { page.as_ref().used() }, 1);
                    assert_eq!(
                        drain.test_direct_page(direct_index),
                        Some(EMPTY_PAGE.as_ptr()),
                        "the rejected preflight leaves the stale direct slot untouched"
                    );
                    drop(drain);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping the rejected drain cannot imitate an owner-exit route"
                    );
                    core::mem::forget(owner);
                });
                worker
                    .join()
                    .expect("the malformed direct-image refusal remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("malformed aggregate direct-image fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_rejects_malformed_prev_before_mutation() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the malformed-queue fixture");
                    let block = allocator
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates one live medium page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the page remains PageMap-published before thread exit");
                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });

                    // SAFETY: the test owns the complete drain and injects a
                    // self predecessor only to prove the aggregate preflight
                    // rejects before it calls the unsafe queue-removal kernel.
                    unsafe { (*page.as_ptr()).test_set_queue_prev(page.as_ptr()) };
                    let drain = match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                            drain,
                            error,
                        }) => {
                            assert_eq!(
                                error,
                                ThreadExitMappedRegularPagesPostExitAbandonError::Queue,
                                "a malformed predecessor link rejects before source retirement or collection"
                            );
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the malformed predecessor must reject before mutation: {error:?}");
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the malformed predecessor must reject before Theap/TLD teardown")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the malformed predecessor must reject before PageMap-route transfer: {error:?}")
                        }
                        Ok(route) => {
                            core::mem::forget(route);
                            panic!("the malformed predecessor cannot cross into an aggregate route")
                        }
                    };
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                        page.as_ptr(),
                        "the malformed preflight leaves PageMap publication untouched"
                    );
                    assert_eq!(unsafe { page.as_ref().used() }, 1);
                    drop(drain);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping the malformed retained drain cannot imitate an owner-exit route"
                    );
                    core::mem::forget(owner);
                });
                worker
                    .join()
                    .expect("the malformed queue regression remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("the malformed aggregate queue fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_releases_large_page_span() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through the large route");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one large aggregate page");
                    let block = allocator
                        .allocate(MEDIUM_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates one nonfull large page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the large page remains PageMap-published before thread exit");
                    let page_ref = unsafe { page.as_ref() };
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(crate::types::PageKind::Large),
                        "the request crosses the medium-to-large source boundary"
                    );
                    assert!(
                        page_ref.used() < usize::from(page_ref.reserved()),
                        "the large page remains a regular rather than full queue member"
                    );
                    let memory = page_ref
                        .memid()
                        .arena_memory()
                        .expect("the large page belongs to the paired arena");
                    let slice = memory.slice_index as usize;
                    let slice_count = memory.slice_count as usize;
                    assert_eq!(
                        slice_count,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Large).unwrap(),
                        "the large page retains its complete regular arena span"
                    );
                    let trailing_slice = arena
                        .slice_start(slice + slice_count - 1)
                        .expect("the large span's final slice remains in the paired arena");
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(trailing_slice) },
                        page.as_ptr(),
                        "fresh large-page publication covers every slice in its span"
                    );
                    assert_eq!(
                        unsafe { arena.slices_free() }
                            .unwrap()
                            .is_set_range(slice, slice_count),
                        Some(false),
                        "the live large page owns all of its arena slices"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let route = match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => route,
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
                            core::mem::forget(drain);
                            panic!("one live large page requires a post-exit process route")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the source regular large page must pass aggregate preflight: {error:?}")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("the large route cannot retain before a source transition: {error:?}")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("the large route tears down the old Theap/TLD")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("the large route transfers its short PageMap access: {error:?}")
                        }
                    };
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the large route tears down the former Theap/TLD before client free"
                    );
                    assert_eq!(route.test_remaining_pages(), 1);

                    match unsafe { route.remote_free_after_thread_exit(block) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedAll) => {}
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(route))
                        | Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => {
                            core::mem::forget(route);
                            panic!("the large page's final client free releases its only route member")
                        }
                        Err(_) => panic!("the large page's final client free releases its full span"),
                    }
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(trailing_slice) }.is_null(),
                        "the final large-page release unregisters the trailing PageMap slice"
                    );
                    assert_eq!(
                        unsafe { arena.slices_free() }
                            .unwrap()
                            .is_set_range(slice, slice_count),
                        Some(true),
                        "the final large-page release returns every arena slice"
                    );
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the one large route member reopens the empty process map"
                    );
                });
                worker
                    .join()
                    .expect("the large aggregate route fixture remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("large aggregate route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_selects_each_large_page_bin_after_claim() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits a multi-bin route");
                    let first = allocator
                        .allocate(MEDIUM_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates the first large page");
                    let second = allocator
                        .allocate(LARGE_MAX_OBJ_SIZE / 2, false)
                        .expect("the fixture creates a second large page in another bin");
                    let first_page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the first page remains PageMap-published");
                    let second_page = NonNull::new(unsafe { allocator.test_page_for_block(second) })
                        .expect("the second page remains PageMap-published");
                    assert_ne!(first_page, second_page, "different large bins own distinct pages");
                    assert_ne!(
                        crate::size_class::bin(unsafe { first_page.as_ref().block_size() }),
                        crate::size_class::bin(unsafe { second_page.as_ref().block_size() }),
                        "the aggregate route must select its bitmap/count capability after each owner claim"
                    );
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe {
                            first_page.as_ref().block_size()
                        }),
                        Some(crate::types::PageKind::Large),
                        "the first selected bin remains in the source large-page class"
                    );
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe {
                            second_page.as_ref().block_size()
                        }),
                        Some(crate::types::PageKind::Large),
                        "the second selected bin remains in the source large-page class"
                    );
                    assert_eq!(unsafe { first_page.as_ref().used() }, 1);
                    assert_eq!(unsafe { second_page.as_ref().used() }, 1);

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let route = match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => route,
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
                            core::mem::forget(drain);
                            panic!("two live large pages cannot become an empty drain")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("multi-bin route preflight rejected: {error:?}")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                            drain,
                            error,
                        }) => {
                            core::mem::forget(drain);
                            panic!("multi-bin route retained after a source transition: {error:?}")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Teardown {
                            terminal,
                            ..
                        }) => {
                            core::mem::forget(terminal);
                            panic!("multi-bin route tears down the old Theap/TLD")
                        }
                        Err(MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::PageMap {
                            parts,
                            error,
                        }) => {
                            core::mem::forget(parts);
                            panic!("multi-bin route transfers its PageMap access: {error:?}")
                        }
                    };
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::TornDown),
                        "the multi-bin route tears down its old Theap/TLD before any client free"
                    );
                    assert_eq!(route.test_remaining_pages(), 2);

                    let route = match unsafe { route.remote_free_after_thread_exit(first) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => route,
                        Ok(_) => panic!("the first one-block page releases while the second remains registered"),
                        Err(_) => panic!("the first bin resolves its paired mapped bitmap/count after claim"),
                    };
                    assert_eq!(route.test_remaining_pages(), 1);
                    match unsafe { route.remote_free_after_thread_exit(second) } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedAll) => {}
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(route))
                        | Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => {
                            core::mem::forget(route);
                            panic!("the second bin releases the final registered page")
                        }
                        Err(_) => panic!("the second bin resolves its paired mapped bitmap/count after claim"),
                    }
                    assert_eq!(
                        page_map.begin_page_lifecycle().unwrap().finish(),
                        Ok(()),
                        "the final multi-bin release reopens the process map"
                    );
                });
                worker
                    .join()
                    .expect("the multi-bin aggregate route remains local to its later owner fixture");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("multi-bin aggregate route fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_mapped_regular_pages_route_returns_drained_after_large_force_collection() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena remains published through large force collection");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the force-collection fixture");
                    let request = MEDIUM_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates a large page");
                    let second = allocator
                        .allocate(request, false)
                        .expect("the fixture creates a second live client in that page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the large page remains PageMap-published");
                    assert_eq!(
                        unsafe { allocator.test_page_for_block(second) },
                        page.as_ptr(),
                        "the two remote clients share one nonfull large page"
                    );
                    assert_eq!(
                        crate::size_class::page_kind_for_block_size(unsafe { page.as_ref().block_size() }),
                        Some(crate::types::PageKind::Large),
                        "the force-collection fixture crosses the source large-page boundary"
                    );
                    assert!(
                        unsafe { page.as_ref().used() } < usize::from(unsafe { page.as_ref().reserved() }),
                        "the aggregate preflight admits a regular rather than full page"
                    );
                    let memory = unsafe { page.as_ref().memid() }
                        .arena_memory()
                        .expect("the large page belongs to the paired arena");
                    let slice = memory.slice_index as usize;
                    let slice_count = memory.slice_count as usize;
                    assert_eq!(
                        slice_count,
                        crate::page::regular_page_slice_count(crate::types::PageKind::Large).unwrap(),
                        "force collection owns the complete large-page span"
                    );

                    for block in [first, second] {
                        let producer = unsafe { allocator.begin_remote_free(block) }
                            .expect("each live large client admits a scoped remote producer");
                        thread::scope(|scope| {
                            let publisher = scope.spawn(move || producer.publish());
                            match publisher.join().expect("the remote producer publishes") {
                                Ok(()) => {}
                                Err((producer, error)) => {
                                    let _ = producer.cancel();
                                    panic!("the remote client publishes before owner exit: {error:?}");
                                }
                            }
                        });
                    }
                    assert_eq!(
                        unsafe { page.as_ref().used() },
                        2,
                        "the joined remote frees remain for source force collection"
                    );

                    let drain = allocator.begin_thread_exit_drain().unwrap_or_else(|failure| {
                        let MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, error } = failure;
                        core::mem::forget(allocator);
                        panic!("thread exit enters its post-fast-slot drain: {error:?}");
                    });
                    let drain = match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => drain,
                        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => {
                            core::mem::forget(route);
                            panic!("force collection releases every client before a process route is needed")
                        }
                        Err(_) => panic!("force collection keeps the large page in the source traversal"),
                    };
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the source force pass releases the all-free large span before route creation"
                    );
                    assert_eq!(
                        unsafe { arena.slices_free() }
                            .unwrap()
                            .is_set_range(slice, slice_count),
                        Some(true),
                        "the source force pass returns every large-page arena slice"
                    );
                    assert!(matches!(drain.finish(), Ok(())));
                    owner
                        .finish_after_page_drain()
                        .expect("the ordinary drained result retains the normal later-owner finish");
                });
                worker
                    .join()
                    .expect("the force-collection aggregate fixture remains local to its later owner");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("force-collected aggregate fixture remains current-thread local");
    }
}
