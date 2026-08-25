// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
//
// Copyright (c) 2018-2024, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
//
// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/alloc.c:21-103,130-191`
// (`mi_page_malloc_zero`, `mi_theap_malloc_small_zero_nonnull`, generic
// allocation dispatch, and ordinary realloc), `src/alloc-aligned.c:68-241,
// 347-388` (natural/overallocated aligned allocation and aligned realloc),
// `src/free.c:28-50,104-114,372-514,522-542` (local free, abandoned
// `allow_collect` reclaim, interior-base recovery, and aligned usable size),
// `src/page.c:150-269,276-302,374-388,460-522,708-1069` (remote/local and
// small partial-head collection, non-abandoning post-enqueue full-page collection,
// full-page collection, free-page search, full-page retention,
// retirement, forced retry, regular and huge page selection),
// `src/page-queue.c:64-121,126-423` (size-bin/direct-cache selection and
// queue mutations), `src/arena.c:674-723,950-1283` (heap-local arena-pages
// selection, fresh regular/singleton metadata, arena-page registration,
// page-map publication, and release ordering), and
// `include/mimalloc/internal.h:650-654,945-949`
// (direct-page, size-bin, and full-page predicates).
//
// This is the intentionally bounded normal-release lifecycle for exactly one
// pinned exclusive theap. Ordinary activation supplies a live default theap;
// the detached metadata wrapper supplies its own PrivateLock and reuses the
// same exclusive mutation engine. It accepts only caller-managed external
// arenas and a caller-initialized page map. This engine does not construct or
// generalize TLS/Heap lifecycle; its narrow dynamic session instead borrows
// one caller-pinned first-class Heap. Separately, ticket-zero and one
// later-thread main-Heap session can borrow a matched process map/arena under
// its explicit mutation lease. There is no general lock-free remote-free
// routing, abandonment/free/reabandon routing, OS arena reservation, or public
// API here. One consuming dynamic same-owner handoff covers only a mapped
// regular arena page; it may adopt that exact page or consume one same-origin
// `allow_collect` remote free, returning it after exact all-free arena release
// or retaining it for other terminal outcomes. A separate post-TLS dynamic
// drain first force-collects already-retired all-free pages, then owns one
// full one-block arena singleton through source queue detach, unmapped
// abandonment, failed reclaim, and all-free release; it is not a general
// owner-exit traversal or remote-free route.
// The separately bounded later-main drain force-scans all-free pages, then
// admits three sole-page handoffs: the same unmapped full singleton shape, one
// medium regular page with one live block, and one nonfull medium page with
// one or more live blocks. The one-block handoff uses the static main
// `pages_abandoned[bin]` image plus paired `abandoned_count[bin]`, and accepts
// only its source empty-before-reclaim final free. The sole-page process route
// performs the same mapped publication, then tears down the old Theap/TLD and
// retains only stable map/arena/Heap facts for linear later client frees. A
// separate aggregate transition source-traverses every live nonfull
// medium-or-large arena page when no other page shape remains, releases pages
// made empty by force collection, and registers surviving mapped pages without
// retaining a raw former-Theap page list. Neither process route reclaims or
// requeues a live page.
// A bounded false-force collector runs in
// the source regular candidate scan and in the non-abandoning full-page pass.
// `RemoteFreeProducer` is one private linear, scoped route to create that
// publication for an exact active non-huge regular or `BIN_FULL` allocation;
// it is not general remote-free routing. The explicit detached metadata
// session has no remote producer path and performs only the local false-force
// portion. A false-force collection error permanently retains private poison
// rather than guessing remote-list ownership or taking a fresh/release path.
// Ordinary small, medium, large, and singleton pages retain their pinned
// source geometry and queue transitions. This lifecycle also supports ordinary
// and valid in-arena aligned/reallocation operations plus the source OS-aligned
// singleton branch between `MI_PAGE_MAX_OVERALLOC_ALIGN` and
// `MI_PAGE_META_ALIGNMENT`. The owning bootstrap session is exclusive and the
// arena backing plus its metadata must remain pinned for the whole session;
// OS-aligned singleton mappings instead carry their own explicit provenance.

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::ptr::NonNull;

use crate::abandoned::{self, AbandonError, AbandonResult, RetainedAdoptFailure};
use crate::arena::{ArenaId, ArenaView, MainArenaMappedAbandonedPage, release_arena_slices};
use crate::{aligned, alloc, support};
use crate::bootstrap::{
    BootstrapError, ExclusiveTheapBootstrap, ExclusiveTheapSession, TheapPageSession,
};
use crate::dynamic_theap::{
    DynamicTheapError, DynamicTheapPageDrainSession, DynamicTheapPageSession,
};
use crate::main_heap_thread::{
    MainHeapThreadAttachment, MainHeapThreadAttachmentError, MainHeapThreadPageDrainSession,
    MainHeapThreadPageSession,
};
use crate::main_theap::{MainStaticHeapLease, MainStaticHeapLeaseError, MainStaticPageSession};
use crate::config::{
    ARENA_BIN_COUNT, ARENA_SLICE_SIZE, BIN_COUNT, BIN_FULL, BIN_HUGE, PAGES_DIRECT,
    SMALL_MAX_OBJ_SIZE, SMALL_SIZE_MAX, WORD_SIZE,
};
use crate::free_list::{FreeListError, LocalFreeList};
use crate::invariants;
use crate::os_page::{OsAlignedPageClaim, OsAlignedPageOwner, PublishedOsAlignedPage};
use crate::page;
use crate::page_map::PageMap;
use crate::remote_free::{self, RemoteFreeError};
use crate::size_class;
use crate::subproc::MainSubprocess;
use crate::types::{EMPTY_PAGE, LiveThreadId, MemoryId, MemoryKind, Page, PageKind, Theap};
use crate::types::page_queue::{
    page_is_in_full, page_queue_enqueue_from_full_metadata,
    page_queue_enqueue_from_metadata, page_queue_push_metadata,
    page_queue_move_to_front_metadata, page_queue_push_at_end_metadata,
    page_queue_remove_metadata,
};

const RETIRE_CYCLES: u8 = 16;
const RETIRE_MAX_PAGES: usize = 3;
const PAGE_MAX_CANDIDATES: isize = 4;

/// One failed source owner-side page collection boundary.
///
/// These are private invalid-owner/lifecycle observations. The collector
/// cannot safely continue queue transitions after one because source
/// collection has rejected either remote ownership or raw local geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageCollectError {
    Remote(RemoteFreeError),
    Local(FreeListError),
    InvalidOwnerState,
    /// A post-collection page release or queue lifecycle invariant failed.
    /// The source transition may already have cleared map/queue ownership, so
    /// this is retained exactly like a collection error rather than retried.
    Lifecycle,
    /// Test-only failure before `remote_free::collect` can detach producer
    /// state. This exact variant is the sole cleanup-recoverable provenance.
    #[cfg(test)]
    InjectedBeforeDetach,
}

/// One permanently retained owner-side collection failure.
///
/// Either source force mode may have detached a remote list before it reports
/// an error, and a following release may already have cleared map or queue
/// ownership. Retaining the exact page and, when applicable, the block already
/// removed from its local list prevents later entry points from pretending the
/// allocator can safely select, release, or mutate that state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedPageCollectPoison {
    page: NonNull<Page>,
    error: PageCollectError,
    popped_block: Option<NonNull<u8>>,
    // Only the cfg(test) injection can set this. Real errors may follow a
    // remote detach and must remain permanently retained even in test builds.
    test_recoverable: bool,
}

/// One source `mi_page_to_full` failure after its queue transition boundary.
///
/// `Collection` is observed only after the page has entered `BIN_FULL`; its
/// retained failure record permanently poisons this private allocator so that
/// state cannot be reclassified as a fresh-allocation/OOM miss. `Lifecycle`
/// occurs before enqueue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageToFullError {
    Lifecycle,
    Collection(PageCollectError),
}

/// One terminal private failure while a generic owner-side allocation path is
/// inspecting or collecting an active regular page.
///
/// `Ok(None)` remains the source no-page/OOM signal eligible for one forced
/// retry. This distinct result prevents a failed remote/local collection or
/// queue invariant from being misread as OOM after it may already have
/// detached a corrupt remote list. The allocator retains a persistent poison
/// record before returning this error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericPathError {
    Collection(PageCollectError),
    Local(FreeListError),
    Lifecycle,
}

impl From<PageToFullError> for GenericPathError {
    #[inline]
    fn from(error: PageToFullError) -> Self {
        match error {
            PageToFullError::Lifecycle => Self::Lifecycle,
            PageToFullError::Collection(error) => Self::Collection(error),
        }
    }
}

/// One prevalidated terminal backing span. Arena and OS-aligned singleton
/// pages keep materially different ownership: an arena span returns a claim
/// to its bitmap, while an OS singleton holds a unique raw mapping reclaim
/// right and secondary metadata aliases.
enum ReleaseSpan {
    Arena {
        memory: MemoryId,
        slice_start: *mut u8,
        size: usize,
    },
    Os(PublishedOsAlignedPage),
}

/// One invalid local free at the explicit exclusive-theap boundary.
///
/// These are allocator-state failures, not a replacement for the C ABI's
/// invalid-free policy. The eventual libc facade owns that policy; this
/// no-std engine instead refuses to mutate page state when the pinned local
/// ownership proof is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FreeError {
    /// A prior false-force collection failure retained terminal page state.
    CollectionPoisoned,
    /// The address maps to no current ordinary page in this explicit lifecycle.
    Unmapped,
    /// The mapped page is not owned by this pinned exclusive theap.
    ForeignPage,
    /// The block is not one live scalar allocation from that page.
    InvalidBlock(FreeListError),
    /// A queue, page map, or arena ownership invariant could not be preserved.
    Lifecycle,
}

/// One non-mutating failure to prepare a scoped remote free.
///
/// This is deliberately separate from [`RemoteFreeError`]: preparation still
/// holds the exclusive owner and has not published a remote-list link. The
/// admitted page is either an active matching regular non-huge-bin member or
/// an active `BIN_FULL` member, each with a bounded owner-side collection route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteFreePreparationError {
    /// A prior false-force collection failure retained terminal page state.
    CollectionPoisoned,
    /// The detached metadata session deliberately has no remote producer path.
    DetachedSession,
    /// The client address maps to no current page in this allocator's map.
    Unmapped,
    /// The mapped page belongs to another exclusive theap.
    ForeignPage,
    /// The client pointer does not recover one initialized current block.
    InvalidBlock(FreeListError),
    /// The page's source owner identity or low owned bit changed unexpectedly.
    InvalidOwnerState,
    /// This live page is neither an active matching regular member nor an
    /// active full-queue member, so no owner-side route can consume it.
    PageNotInCollectibleQueue,
}

/// One linear, caller-scoped remote-free transfer from a live regular or full
/// page.
///
/// The type stores only page and client/block raw addresses; its owner borrow
/// is zero-sized. That borrow prevents safe allocation, local free,
/// collection, retirement, page-map teardown, or allocator teardown until
/// this capability is published or cancelled. It is `!Sync` by the explicit
/// marker, and `Send` only so a scoped worker can publish the one transferred
/// block before the owner resumes. Dropping the token does not publish or
/// locally free the block; callers must consume it with [`Self::publish`] or
/// [`Self::cancel`].
#[must_use = "a remote-free producer must be published or cancelled before the owner can resume"]
pub(crate) struct RemoteFreeProducer<'owner> {
    page: NonNull<Page>,
    canonical_block: NonNull<u8>,
    client_block: NonNull<u8>,
    _owner: PhantomData<&'owner mut ()>,
    // `Cell` is intentionally !Sync. The explicit unsafe Send impl below
    // grants only one scoped producer transfer, never shared access.
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: `begin_remote_free` grants this capability only after it has pinned
// the exact live regular-or-full page and canonical current block under the
// allocator's exclusive borrow. The token carries no runtime allocator
// reference; moving it to one scoped worker permits only `remote_free::push`.
// Its erased exclusive-owner phantom borrow prevents safe engine/session/page-map
// mutation until the worker has consumed or cancelled the token.
unsafe impl Send for RemoteFreeProducer<'_> {}

impl<'owner> RemoteFreeProducer<'owner> {
    /// Publishes the transferred canonical block through the exact bounded
    /// live-owner remote-free push.
    ///
    /// The token's scoped owner borrow keeps its page, page-map entry, and
    /// allocation live. `RemoteFreeError` is detected before publication, so
    /// an error returns this intact capability for explicit cancellation or a
    /// caller-visible terminal decision.
    pub(crate) fn publish(self) -> Result<(), (Self, RemoteFreeError)> {
        // SAFETY: construction proved the exact page/block and retained the
        // owner borrow for the source producer lifetime.
        match unsafe { remote_free::push(self.page, self.canonical_block) } {
            Ok(()) => Ok(()),
            Err(error) => Err((self, error)),
        }
    }

    /// Cancels publication and restores the exact original client pointer to
    /// the caller, leaving all allocator state unchanged.
    #[inline]
    pub(crate) fn cancel(self) -> NonNull<u8> {
        self.client_block
    }
}

/// Generic private ordinary-allocation engine over one narrow page owner.
///
/// This value owns either the static [`ExclusiveTheapSession`], a ticket-zero
/// or later-thread main-Heap page session, or a dynamic attachment-backed
/// page session, so it is the only operation capable of mutating that
/// session's pinned Theap. It borrows the arena and page map
/// rather than reserving VM itself. Dropping it does not
/// collect, abandon, unregister, or release any page: callers must force a
/// collection before they dismantle the supplied arena or page map.
pub(crate) struct PageAllocatorEngine<'arena, 'map, Session: TheapPageSession> {
    session: Session,
    arena: ArenaView<'arena>,
    requested_arena: ArenaId,
    page_map: &'map PageMap,
    thread_sequence: usize,
    // At most one OS-aligned singleton can be detached but unreclaimed in
    // this private lifecycle. Keeping its unique owner here makes a failed
    // `munmap` retryable without inventing arena/page-map provenance.
    pending_os_release: Option<OsAlignedPageOwner>,
    // A failed false-force collection may have detached remote state. This is
    // permanent in production: the retained record prevents every later
    // public allocator operation from crossing that ownership boundary.
    collection_poison: Option<RetainedPageCollectPoison>,
    // The one-shot hook fails before remote detachment, so tests alone can
    // clear the retained record and complete fixture cleanup. No production
    // recovery exists because a real failure can have ambiguous ownership.
    #[cfg(test)]
    page_free_collect_failure_once: bool,
    // Records a source `mi_page_to_full` enqueue for focused dynamic-mode
    // evidence even when the immediately following full collector unfulls an
    // otherwise unchanged page before the public allocation returns.
    #[cfg(test)]
    last_page_to_full: Option<NonNull<Page>>,
    // A successful explicit shutdown disarms Drop. Otherwise Drop must leave
    // a dynamic attachment terminally retained rather than discarding this
    // engine's poison/pending-release knowledge and allowing false teardown.
    shutdown_complete: bool,
}

/// The engine state that remains valid while a consuming lifecycle changes
/// only its typed page-session owner. Keeping it separate prevents a
/// thread-exit transition from manufacturing a second PageMap/arena/OS-owner
/// capability while it replaces `DynamicTheapPageSession` with its narrower
/// post-TLS drain session.
struct PageAllocatorEngineState<'arena, 'map> {
    arena: ArenaView<'arena>,
    requested_arena: ArenaId,
    page_map: &'map PageMap,
    thread_sequence: usize,
    pending_os_release: Option<OsAlignedPageOwner>,
    collection_poison: Option<RetainedPageCollectPoison>,
    #[cfg(test)]
    page_free_collect_failure_once: bool,
    #[cfg(test)]
    last_page_to_full: Option<NonNull<Page>>,
    shutdown_complete: bool,
}

/// Existing static-session spelling/API. The generic engine above is private
/// implementation structure, not a public first-class heap abstraction.
pub(crate) type SingleThreadAllocator<'bootstrap, 'arena, 'map> =
    PageAllocatorEngine<'arena, 'map, ExclusiveTheapSession<'bootstrap>>;

/// Private dynamic attachment specialization of the same page engine.
pub(crate) type DynamicTheapAllocator<'attach, 'heap, 'arena, 'map> =
    PageAllocatorEngine<'arena, 'map, DynamicTheapPageSession<'attach, 'heap>>;

/// A deliberately narrow post-TLS dynamic page-drain owner. It is not a
/// general allocator: source thread exit has already cleared the Heap's
/// dynamic regular slot. Its finishing boundary force-collects existing
/// retired all-free pages, while its only live-page operation is the exact
/// full singleton abandonment/free/release path needed to prove that later
/// remote frees cannot reclaim the departed Theap.
#[must_use = "a dynamic thread-exit drain must release or retain its page before attachment teardown"]
pub(crate) struct DynamicThreadExitDrain<'attach, 'heap, 'arena, 'map> {
    engine: PageAllocatorEngine<'arena, 'map, DynamicTheapPageDrainSession<'attach, 'heap>>,
}

/// One queue-detached arena singleton abandoned by a dynamic thread-exit
/// drain. The token retains the pre-list-detach Theap/TLD/Heap/arena-image
/// owner until its one source failed-reclaim free either releases the page or
/// records a terminal state for a later general lifecycle implementation.
#[must_use = "an owner-exit singleton handoff must be consumed or terminally retained"]
pub(crate) struct DynamicThreadExitSingletonHandoff<'attach, 'heap, 'arena, 'map> {
    drain: DynamicThreadExitDrain<'attach, 'heap, 'arena, 'map>,
    page: NonNull<Page>,
    terminal: bool,
}

/// One queue-detached arena singleton whose source thread-exit transition has
/// made the original Theap unavailable for reclamation.
///
/// Construction is private to dedicated post-TLS/fast-slot drain
/// specializations. The current later-main wrapper uses this shared storage;
/// the dynamic path retains its separately audited regular-TLS-clear endpoint
/// because that source reclaim-failure proof is materially different. The
/// token keeps the exact draining session, arena, PageMap, and client-block
/// lifetime coupled until its sole final free either releases the page or
/// records a terminal owner. It is not a general abandoned-page handle.
#[must_use = "a thread-exit singleton handoff must be consumed or terminally retained"]
pub(crate) struct ThreadExitSingletonHandoff<'arena, 'map, Session: TheapPageSession> {
    engine: PageAllocatorEngine<'arena, 'map, Session>,
    page: NonNull<Page>,
    terminal: bool,
}

/// One queue-detached, mapped-abandoned medium page with exactly one live
/// client block at later-main owner exit. The token retains the post-fast-slot
/// drain, process PageMap, arena bitmap image, and client block until that
/// exact free makes the page empty and releases it, or a terminal state is
/// retained. It deliberately cannot reclaim or requeue a live page.
#[must_use = "a mapped one-block owner-exit handoff must be consumed or terminally retained"]
pub(crate) struct ThreadExitMappedOneBlockHandoff<'arena, 'map, Session: TheapPageSession> {
    engine: PageAllocatorEngine<'arena, 'map, Session>,
    page: NonNull<Page>,
    bin: usize,
    terminal: bool,
}

/// One source-mapped regular page after `_mi_page_abandon` has removed it
/// from its departing later Theap but before that Theap/TLD is torn down.
///
/// Unlike [`ThreadExitMappedOneBlockHandoff`], this intentionally carries no
/// engine and no page pointer. Its sole role is to bridge one exactly
/// queue-detached, mapped-abandoned medium page into a process-owned route.
/// The final route re-resolves the page under a short PageMap guard for every
/// client free, so it cannot retain a Rust borrow of the departed Theap.
#[must_use = "a detached mapped regular page must become a process route or remain terminally retained"]
pub(crate) struct ThreadExitMappedRegularPostExitDetach<'attachment, 'main, 'arena> {
    session: MainHeapThreadPageDrainSession<'attachment, 'main>,
    parts: ThreadExitMappedRegularPostExitParts<'main, 'arena>,
}

/// The process-lifetime facts needed to route one already detached mapped
/// regular page. This has no reference or pointer to the old Theap/TLD.
#[must_use = "post-exit mapped-page facts must remain coupled to PageMap access until final release"]
pub(crate) struct ThreadExitMappedRegularPostExitParts<'main, 'arena> {
    arena: ArenaView<'arena>,
    main_heap: MainStaticHeapLease<'main>,
    memory: MemoryId,
    slice_start: *mut u8,
    size: usize,
    bin: usize,
}

/// A post-detach failure while tearing down the old later Theap/TLD. The
/// page remains represented by `parts`, but its PageMap long lease has not
/// yet been transferred, so the caller must retain the terminal owner rather
/// than treating the thread exit as complete.
#[must_use = "a failed post-exit Theap/TLD teardown retains the detached page state"]
pub(crate) struct ThreadExitMappedRegularPostExitTeardownTerminal<'attachment, 'main, 'arena> {
    parts: ThreadExitMappedRegularPostExitParts<'main, 'arena>,
    attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    error: MainHeapThreadAttachmentError,
}

/// Every mapped medium-or-large arena page detached by one source-order
/// `_mi_theap_collect_abandon` traversal, before the former later Theap/TLD
/// is torn down.
///
/// The page membership registry is deliberately not a Rust list of raw
/// pointers. Each member remains registered in the process PageMap and in its
/// exact static-main `pages_abandoned[bin]` bitmap/count pair; the returned
/// parts re-resolve a page only while holding the short process-map route.
/// That preserves upstream's lookup/bitmap registries without retaining a
/// borrow of the departing Theap or creating an allocator-owned collection.
#[must_use = "detached mapped medium-or-large pages must become one process route or remain terminally retained"]
pub(crate) struct ThreadExitMappedMediumLargePagesPostExitDetach<'attachment, 'main, 'arena> {
    session: MainHeapThreadPageDrainSession<'attachment, 'main>,
    parts: ThreadExitMappedMediumLargePagesPostExitParts<'main, 'arena>,
}

/// The typed process-lifetime registry for one linear aggregate post-exit
/// route. `remaining_pages` counts only spans that remain PageMap-registered;
/// it is decremented after each complete PageMap -> ordinary-bit -> metadata
/// -> arena-slice terminal release. It stores no former-Theap pointer and no
/// raw page list, so allocation-time adoption, reclaim/requeue, and general
/// concurrent routing remain outside this bounded owner.
#[must_use = "aggregate post-exit page facts must remain coupled to PageMap access until every span is released"]
pub(crate) struct ThreadExitMappedMediumLargePagesPostExitParts<'main, 'arena> {
    arena: ArenaView<'arena>,
    main_heap: MainStaticHeapLease<'main>,
    remaining_pages: usize,
    // The route is movable but intentionally not shareable. Its consuming
    // free API plus the post-exit PageMap guard serialize the source owner-bit
    // decision; a shared reference would falsely suggest concurrent routing.
    _not_sync: PhantomData<Cell<()>>,
}

/// A post-detach failure while tearing down the old later Theap/TLD after an
/// aggregate mapped medium-and-large traversal. The registry remains retained,
/// but the long PageMap lifecycle has not crossed to a short process route, so
/// the caller must keep this terminal owner rather than treating exit as
/// complete.
#[must_use = "a failed aggregate post-exit teardown retains every detached page state"]
pub(crate) struct ThreadExitMappedMediumLargePagesPostExitTeardownTerminal<'attachment, 'main, 'arena> {
    parts: ThreadExitMappedMediumLargePagesPostExitParts<'main, 'arena>,
    attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    error: MainHeapThreadAttachmentError,
}

/// A source-boundary refusal while one post-TLS/fast-slot owner abandons its
/// sole full arena singleton.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitSingletonAbandonError {
    Collection,
    Unmapped,
    ForeignPage,
    NonArena,
    NotFullSingleton,
    /// The current drain owns additional queue/direct/page state, so it
    /// cannot skip source traversal order by detaching one singleton early.
    NotOnlyPage,
    NotActiveFull,
    InvalidBlock,
    Queue,
    UnexpectedAbandonOutcome(AbandonResult),
    Abandon(AbandonError),
}

/// The exact retained source owner after a singleton-abandon attempt.
#[must_use = "a failed thread-exit singleton abandonment retains its source owner"]
pub(crate) enum ThreadExitSingletonAbandonFailure<'arena, 'map, Session: TheapPageSession> {
    /// Every check was pre-detach, so normal drain ownership remains intact.
    Rejected {
        engine: PageAllocatorEngine<'arena, 'map, Session>,
        error: ThreadExitSingletonAbandonError,
    },
    /// A false-force collection may already have detached remote state. The
    /// draining engine is retained and cannot resume ordinary allocation.
    RetainedEngine {
        engine: PageAllocatorEngine<'arena, 'map, Session>,
        error: ThreadExitSingletonAbandonError,
    },
    /// Queue/page ownership crossed into the handoff before the later source
    /// state was found invalid.
    Terminal {
        handoff: ThreadExitSingletonHandoff<'arena, 'map, Session>,
        error: ThreadExitSingletonAbandonError,
    },
}

/// One source-boundary outcome while the sole post-owner-exit singleton
/// receives its final client free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitSingletonRemoteFreeError {
    Terminal,
    Unmapped,
    InvalidBlock,
    Release,
    UnexpectedFreeOutcome(abandoned::UnmappedAbandonedFreeResult),
    Abandon(AbandonError),
}

/// The exact retained singleton handoff after its final-free attempt.
#[must_use = "a failed thread-exit singleton free retains its handoff"]
pub(crate) enum ThreadExitSingletonRemoteFreeFailure<'arena, 'map, Session: TheapPageSession> {
    Rejected {
        handoff: ThreadExitSingletonHandoff<'arena, 'map, Session>,
        error: ThreadExitSingletonRemoteFreeError,
    },
    Terminal {
        handoff: ThreadExitSingletonHandoff<'arena, 'map, Session>,
        error: ThreadExitSingletonRemoteFreeError,
    },
}

/// A source-boundary refusal while one post-fast-slot owner maps its sole
/// medium page with exactly one current client block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedOneBlockAbandonError {
    Collection,
    Unmapped,
    ForeignPage,
    NonArena,
    NotMappedOneBlock,
    /// The current drain owns additional queue/direct/page state, so it
    /// cannot skip source traversal order by detaching one regular page early.
    NotOnlyPage,
    NotActiveRegular,
    InvalidBlock,
    MissingMainArenaPages,
    Queue,
    UnexpectedAbandonOutcome(AbandonResult),
    Abandon(AbandonError),
}

/// A source-boundary refusal while a later-main post-fast-slot drain tries to
/// transfer one nonfull medium page to the process-owned post-exit route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedRegularPostExitAbandonError {
    Collection,
    Unmapped,
    ForeignPage,
    NonArena,
    NotMappedRegular,
    /// This first route is deliberately one page only. It does not skip the
    /// source traversal of any other queue/direct entry.
    NotOnlyPage,
    NotActiveRegular,
    InvalidBlock,
    MissingMainArenaPages,
    Queue,
    PostDetachState,
    UnexpectedAbandonOutcome(AbandonResult),
    Abandon(AbandonError),
}

/// The retained source owner after a mapped regular post-exit route attempt.
#[must_use = "a failed mapped regular post-exit transition retains its draining engine"]
pub(crate) enum ThreadExitMappedRegularPostExitAbandonFailure<'attachment, 'main, 'arena, 'map> {
    /// All checks completed before force collection or queue detachment.
    Rejected {
        engine: PageAllocatorEngine<
            'arena,
            'map,
            MainHeapThreadPageDrainSession<'attachment, 'main>,
        >,
        error: ThreadExitMappedRegularPostExitAbandonError,
    },
    /// A source collection, queue, or abandonment transition may already
    /// have changed state. The drain is the only valid retained owner.
    RetainedEngine {
        engine: PageAllocatorEngine<
            'arena,
            'map,
            MainHeapThreadPageDrainSession<'attachment, 'main>,
        >,
        error: ThreadExitMappedRegularPostExitAbandonError,
    },
}

/// The exact retained source owner after one mapped-one-block abandon attempt.
#[must_use = "a failed mapped one-block abandonment retains its source owner"]
pub(crate) enum ThreadExitMappedOneBlockAbandonFailure<'arena, 'map, Session: TheapPageSession> {
    /// Every check was pre-detach, so the post-fast-slot drain remains
    /// available for an explicit later source decision.
    Rejected {
        engine: PageAllocatorEngine<'arena, 'map, Session>,
        error: ThreadExitMappedOneBlockAbandonError,
    },
    /// Force or false collection may have detached source free state. The
    /// draining engine is retained and cannot resume ordinary allocation.
    RetainedEngine {
        engine: PageAllocatorEngine<'arena, 'map, Session>,
        error: ThreadExitMappedOneBlockAbandonError,
    },
    /// Queue/page ownership crossed into the handoff before the later source
    /// condition became terminal.
    Terminal {
        handoff: ThreadExitMappedOneBlockHandoff<'arena, 'map, Session>,
        error: ThreadExitMappedOneBlockAbandonError,
    },
}

/// One source-boundary outcome while a mapped one-block owner-exit handoff
/// receives its final client free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedOneBlockRemoteFreeError {
    Terminal,
    Unmapped,
    InvalidBlock,
    MissingMainArenaPages,
    ConcurrentOwner,
    Release,
    Abandon(AbandonError),
}

/// One outcome while a process-owned mapped regular page handles a client
/// free after the originating later Theap/TLD no longer exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedRegularPostExitFreeOutcome {
    /// The page remains mapped-abandoned and unowned for a later route call.
    StillLive,
    /// The client free made the page empty and completed its terminal release.
    Released,
}

/// A terminal or rejecting condition while a post-exit route handles one
/// client free. Every variant leaves the caller responsible for retaining the
/// route until it makes an explicit terminal decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedRegularPostExitFreeError {
    Unmapped,
    MainHeap(MainStaticHeapLeaseError),
    MissingMainArenaPages,
    ConcurrentOwner,
    Abandon(AbandonError),
    Release,
}

/// A source-boundary refusal while a later-main post-fast-slot drain prepares
/// its complete mapped medium-and-large owner-exit traversal. `Rejected` is
/// reserved for this non-mutating preflight; every force collection or later page
/// transition retains the draining engine because source state may have
/// changed already.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedMediumLargePagesPostExitAbandonError {
    Collection,
    ForeignPage,
    NonArena,
    NotMappedMediumLarge,
    MissingMainArenaPages,
    Queue,
    Release,
    RouteCountOverflow,
    PostDetachState,
    UnexpectedAbandonOutcome(AbandonResult),
    Abandon(AbandonError),
}

/// The retained source owner after an aggregate mapped medium-and-large
/// owner-exit traversal attempt.
#[must_use = "a failed aggregate mapped medium-and-large post-exit transition retains its draining engine"]
pub(crate) enum ThreadExitMappedMediumLargePagesPostExitAbandonFailure<'attachment, 'main, 'arena, 'map> {
    /// The complete queue/direct/page preflight rejected before its first
    /// source force collection, so the drain remains available for an
    /// explicitly different lifecycle decision.
    Rejected {
        engine: PageAllocatorEngine<
            'arena,
            'map,
            MainHeapThreadPageDrainSession<'attachment, 'main>,
        >,
        error: ThreadExitMappedMediumLargePagesPostExitAbandonError,
    },
    /// Force/false collection, all-free release, queue detachment, or mapped
    /// publication may have progressed. The drain remains the only valid
    /// terminal owner; it cannot resume ordinary allocation.
    RetainedEngine {
        engine: PageAllocatorEngine<
            'arena,
            'map,
            MainHeapThreadPageDrainSession<'attachment, 'main>,
        >,
        error: ThreadExitMappedMediumLargePagesPostExitAbandonError,
    },
}

/// The result of one source-order aggregate owner-exit traversal.
#[must_use = "an aggregate traversal must either retain its route or return its empty drain"]
pub(crate) enum ThreadExitMappedMediumLargePagesPostExitAbandonOutcome<'attachment, 'main, 'arena, 'map> {
    /// At least one live medium-or-large page crossed into the typed process
    /// registry.
    Detached(ThreadExitMappedMediumLargePagesPostExitDetach<'attachment, 'main, 'arena>),
    /// Force collection made every preflighted page all-free. The ordinary
    /// empty drain still owns the later attachment's root/list/TLD finish.
    Drained(
        PageAllocatorEngine<'arena, 'map, MainHeapThreadPageDrainSession<'attachment, 'main>>,
    ),
}

/// One result while a linear aggregate post-exit route handles a client free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedMediumLargePagesPostExitFreeOutcome {
    /// The selected page remains mapped-abandoned and the registry is intact.
    StillLive,
    /// One selected page completed terminal release while another registered
    /// page remains in this same aggregate route.
    ReleasedPage,
    /// The selected page was the registry's last PageMap-registered span.
    ReleasedAll,
}

/// A terminal or rejecting condition while the aggregate post-exit registry
/// handles one client free. An `Unmapped` lookup is pre-mutation; every other
/// result may have acquired an owner bit or changed source publication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadExitMappedMediumLargePagesPostExitFreeError {
    Unmapped,
    MainHeap(MainStaticHeapLeaseError),
    ConcurrentOwner,
    Abandon(AbandonError),
    Release,
}

/// The exact retained mapped-one-block handoff after its final-free attempt.
#[must_use = "a failed mapped one-block free retains its handoff"]
pub(crate) enum ThreadExitMappedOneBlockRemoteFreeFailure<'arena, 'map, Session: TheapPageSession> {
    Rejected {
        handoff: ThreadExitMappedOneBlockHandoff<'arena, 'map, Session>,
        error: ThreadExitMappedOneBlockRemoteFreeError,
    },
    Terminal {
        handoff: ThreadExitMappedOneBlockHandoff<'arena, 'map, Session>,
        error: ThreadExitMappedOneBlockRemoteFreeError,
    },
}

/// A failed consuming transition into the post-TLS dynamic page-drain state.
/// The original engine stays retained because a post-slot-clear failure may
/// already have changed root or backing ownership.
#[must_use = "a failed dynamic thread-exit drain retains its page engine"]
pub(crate) enum DynamicThreadExitDrainFailure<'attach, 'heap, 'arena, 'map> {
    Retained {
        engine: DynamicTheapAllocator<'attach, 'heap, 'arena, 'map>,
        error: DynamicTheapError,
    },
}

/// One source-boundary refusal while a draining dynamic owner abandons its
/// exact full singleton. `Rejected` is pre-detach; `RetainedDrain` has already
/// poisoned a false-force collection, while `Terminal` retains a page that
/// crossed queue/identity ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicThreadExitSingletonAbandonError {
    Collection,
    Unmapped,
    ForeignPage,
    NonArena,
    NotFullSingleton,
    NotActiveFull,
    InvalidBlock,
    Queue,
    UnexpectedAbandonOutcome(AbandonResult),
    Abandon(AbandonError),
}

#[must_use = "a failed owner-exit singleton abandonment retains its source owner"]
pub(crate) enum DynamicThreadExitSingletonAbandonFailure<'attach, 'heap, 'arena, 'map> {
    Rejected {
        drain: DynamicThreadExitDrain<'attach, 'heap, 'arena, 'map>,
        error: DynamicThreadExitSingletonAbandonError,
    },
    RetainedDrain {
        drain: DynamicThreadExitDrain<'attach, 'heap, 'arena, 'map>,
        error: DynamicThreadExitSingletonAbandonError,
    },
    Terminal {
        handoff: DynamicThreadExitSingletonHandoff<'attach, 'heap, 'arena, 'map>,
        error: DynamicThreadExitSingletonAbandonError,
    },
}

/// One source-boundary outcome while a dynamic thread-exit singleton receives
/// its final free after the regular TLS slot made the upstream reclaim attempt
/// impossible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicThreadExitSingletonRemoteFreeError {
    Terminal,
    Unmapped,
    InvalidBlock,
    Release,
    UnexpectedFreeOutcome(abandoned::UnmappedAbandonedFreeResult),
    Abandon(AbandonError),
}

#[must_use = "a failed owner-exit singleton free retains its handoff"]
pub(crate) enum DynamicThreadExitSingletonRemoteFreeFailure<'attach, 'heap, 'arena, 'map> {
    Rejected {
        handoff: DynamicThreadExitSingletonHandoff<'attach, 'heap, 'arena, 'map>,
        error: DynamicThreadExitSingletonRemoteFreeError,
    },
    Terminal {
        handoff: DynamicThreadExitSingletonHandoff<'attach, 'heap, 'arena, 'map>,
        error: DynamicThreadExitSingletonRemoteFreeError,
    },
}

/// One rejected pre-handoff observation. Every variant is checked before the
/// source queue detach; the returned engine has not entered abandoned state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicMappedAbandonError {
    Collection,
    Unmapped,
    ForeignPage,
    NonArena,
    FullOrSpecial,
    NotActiveRegular,
    MissingDynamicArenaPages,
    EmptyAfterCollection,
    Abandon(AbandonError),
}

/// A consuming dynamic mapped-abandon result. A caller that receives
/// [`Self::Rejected`] regains its still-live engine; a post-detach source
/// failure instead retains the engine inside [`Self::Terminal`] so normal
/// allocation/free/finish cannot resume across an ambiguous owner boundary.
#[must_use = "a mapped-abandon failure retains either the engine or a terminal handoff"]
pub(crate) enum DynamicMappedAbandonFailure<'attach, 'heap, 'arena, 'map> {
    Rejected {
        engine: DynamicTheapAllocator<'attach, 'heap, 'arena, 'map>,
        error: DynamicMappedAbandonError,
    },
    Terminal {
        handoff: DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>,
        error: DynamicMappedAbandonError,
    },
}

/// A dynamic exact-page handoff that owns the entire page engine while its
/// page is mapped-abandoned. Forgetting it conservatively retains the engine,
/// attachment, page map, arena image, bitmap bit, and page; it cannot reveal a
/// normal allocator able to free or reuse abandoned state.
#[must_use = "a mapped-abandoned page must be adopted or terminally retained"]
pub(crate) struct DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map> {
    engine: DynamicTheapAllocator<'attach, 'heap, 'arena, 'map>,
    page: NonNull<Page>,
    bin: usize,
    memory: MemoryId,
    terminal: bool,
}

/// A claimed mapped page that could not finish reassociation. The page may
/// hold the low owner bit and no bitmap bit, so only retained terminal storage
/// is sound in this bounded slice.
#[must_use = "a mapped-adoption failure retains the handoff capability"]
pub(crate) enum DynamicMappedAdoptFailure<'attach, 'heap, 'arena, 'map> {
    /// The map contained no currently claimable exact page. Ownership remains
    /// mapped/unowned and the caller may retry only through this token.
    Pending(DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>),
    /// A post-claim source failure retained the exact claimed page.
    Claimed {
        handoff: DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>,
        retained: RetainedAdoptFailure,
    },
    /// Queue reassociation could not complete after an ownership transition.
    /// The token is terminal; normal engine access is intentionally absent.
    Terminal(DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>),
}

/// One source-boundary outcome while a mapped-abandoned dynamic page receives
/// an `allow_collect=true` remote free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicMappedRemoteFreeError {
    Terminal,
    InvalidBlock,
    ReclaimDisabled,
    MissingDynamicArenaPages,
    ConcurrentOwner,
    Release,
    Queue,
    Abandon(AbandonError),
}

/// A consuming mapped remote-free operation that could not restore ordinary
/// dynamic page-engine ownership. Pre-mutation refusals keep a retryable
/// handoff; every source ownership transition retains the handoff terminally.
#[must_use = "a mapped remote-free failure retains its handoff capability"]
pub(crate) enum DynamicMappedRemoteFreeFailure<'attach, 'heap, 'arena, 'map> {
    Rejected {
        handoff: DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>,
        error: DynamicMappedRemoteFreeError,
    },
    Terminal {
        handoff: DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>,
        error: DynamicMappedRemoteFreeError,
    },
}

impl<'bootstrap, 'arena, 'map>
    PageAllocatorEngine<'arena, 'map, ExclusiveTheapSession<'bootstrap>>
{
    /// Activates the sole live default theap for this ordinary-page lifecycle.
    ///
    /// `bootstrap` must already occupy address-stable storage. `arena` must
    /// denote a registry-published external arena whose backing allocation and
    /// metadata remain alive until this value and every allocation returned by
    /// it have been retired. `page_map` is consumed as one exclusive mutable
    /// borrow, preventing safe construction of a second local lifecycle over
    /// the source-plain entries. It must remain initialized and exclusively
    /// synchronized with these lookup/register/unregister calls. `requested_arena`
    /// is normally [`ArenaId::none`] for nonexclusive external arenas, or the
    /// parent arena identity for an exclusive arena.
    pub(crate) fn activate(
        bootstrap: Pin<&'bootstrap mut ExclusiveTheapBootstrap>,
        thread_id: LiveThreadId,
        arena: ArenaView<'arena>,
        requested_arena: ArenaId,
        page_map: &'map mut PageMap,
        thread_sequence: usize,
    ) -> Result<Self, BootstrapError> {
        let session = bootstrap.activate_live(thread_id)?;
        Ok(Self {
            session,
            arena,
            requested_arena,
            page_map,
            thread_sequence,
            pending_os_release: None,
            collection_poison: None,
            #[cfg(test)]
            page_free_collect_failure_once: false,
            #[cfg(test)]
            last_page_to_full: None,
            shutdown_complete: false,
        })
    }

    /// Activates the detached process metadata theap over the same source
    /// page/arena lifecycle. Every later operation must be externally
    /// serialized by the metadata private lock; this is not a thread-local or
    /// remote-free-capable allocator instance.
    pub(crate) fn activate_detached(
        bootstrap: Pin<&'bootstrap mut ExclusiveTheapBootstrap>,
        subprocess: &'static MainSubprocess,
        arena: ArenaView<'arena>,
        requested_arena: ArenaId,
        page_map: &'map mut PageMap,
        thread_sequence: usize,
    ) -> Result<Self, BootstrapError> {
        let session = bootstrap.activate_detached_for_main_subprocess(subprocess)?;
        Ok(Self {
            session,
            arena,
            requested_arena,
            page_map,
            thread_sequence,
            pending_os_release: None,
            collection_poison: None,
            #[cfg(test)]
            page_free_collect_failure_once: false,
            #[cfg(test)]
            last_page_to_full: None,
            shutdown_complete: false,
        })
    }
}

impl<'attach, 'heap, 'arena, 'map>
    PageAllocatorEngine<'arena, 'map, DynamicTheapPageSession<'attach, 'heap>>
{
    /// Instantiates the existing source page engine over one already validated
    /// non-abandoning dynamic Theap session. The thread sequence is read from
    /// the retained metadata TLD, never supplied independently by a caller.
    pub(crate) fn activate_dynamic(
        session: DynamicTheapPageSession<'attach, 'heap>,
        arena: ArenaView<'arena>,
        requested_arena: ArenaId,
        page_map: &'map mut PageMap,
    ) -> Self {
        let thread_sequence = session.thread_sequence();
        Self {
            session,
            arena,
            requested_arena,
            page_map,
            thread_sequence,
            pending_os_release: None,
            collection_poison: None,
            #[cfg(test)]
            page_free_collect_failure_once: false,
            #[cfg(test)]
            last_page_to_full: None,
            shutdown_complete: false,
        }
    }

    /// Begins the bounded dynamic thread-exit page-drain transition.
    ///
    /// This consumes the ordinary dynamic page engine before it clears the
    /// Heap's regular TLS slot. On success, only
    /// [`DynamicThreadExitDrain`] remains; it cannot resume normal allocation
    /// and may only abandon/release the one source-bound singleton path below.
    /// A failed transition retains the original engine because the attachment
    /// may already have entered a terminal post-slot-clear state.
    pub(crate) fn begin_thread_exit_drain(
        self,
    ) -> Result<
        DynamicThreadExitDrain<'attach, 'heap, 'arena, 'map>,
        DynamicThreadExitDrainFailure<'attach, 'heap, 'arena, 'map>,
    > {
        if self.is_collection_poisoned() || self.pending_os_release.is_some() {
            return Err(DynamicThreadExitDrainFailure::Retained {
                engine: self,
                error: DynamicTheapError::Poisoned,
            });
        }
        let (session, state) = self.into_session_and_state();
        match session.begin_thread_exit_drain() {
            Ok(session) => Ok(DynamicThreadExitDrain {
                engine: PageAllocatorEngine::<DynamicTheapPageSession<'attach, 'heap>>::from_session_and_state(
                    session, state,
                ),
            }),
            Err((session, error)) => Err(DynamicThreadExitDrainFailure::Retained {
                engine: PageAllocatorEngine::<DynamicTheapPageSession<'attach, 'heap>>::from_session_and_state(
                    session, state,
                ),
                error,
            }),
        }
    }

    /// Moves one live mapped regular dynamic page into its exact heap-local
    /// abandoned bitmap. This consumes the engine: after source queue detach
    /// the only way back to ordinary allocation/free is the returned linear
    /// [`DynamicMappedPageHandoff`]'s same-owner adoption or one same-origin
    /// `allow_collect` remote-free reclaim.
    ///
    /// # Safety
    ///
    /// `block` must be one current allocation in this engine's matching live
    /// regular page. It is not freed by this operation; every client alias
    /// must remain live until the page is adopted again or the handoff is
    /// terminally retained. No scoped remote producer may survive entry.
    pub(crate) unsafe fn abandon_mapped_regular(
        mut self,
        block: NonNull<u8>,
    ) -> Result<DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>, DynamicMappedAbandonFailure<'attach, 'heap, 'arena, 'map>> {
        let reject = |engine, error| DynamicMappedAbandonFailure::Rejected { engine, error };
        if self.is_collection_poisoned() || self.pending_os_release.is_some() {
            return Err(reject(self, DynamicMappedAbandonError::Collection));
        }
        // SAFETY: the consuming engine retains the exclusive PageMap borrow.
        let page = unsafe { self.page_map.checked_lookup(block.as_ptr()) };
        let Some(page) = NonNull::new(page) else {
            return Err(reject(self, DynamicMappedAbandonError::Unmapped));
        };
        // SAFETY: the page map keeps this metadata live while the engine owns
        // the only ordinary queue/list mutation capability.
        let page_ref = unsafe { page.as_ref() };
        if !self.owns_page(page_ref) || page_ref.heap() != self.session.theap().heap() {
            return Err(reject(self, DynamicMappedAbandonError::ForeignPage));
        }
        let memory = page_ref.memid();
        if memory.kind() != MemoryKind::Arena {
            return Err(reject(self, DynamicMappedAbandonError::NonArena));
        }
        let Some(bin) = size_class::bin(page_ref.block_size()) else {
            return Err(reject(self, DynamicMappedAbandonError::FullOrSpecial));
        };
        if bin >= crate::config::ARENA_BIN_COUNT || page_is_in_full(page_ref) {
            return Err(reject(self, DynamicMappedAbandonError::FullOrSpecial));
        }
        // `release_span` is also the exact mapped-arena geometry and full
        // PageMap-span witness. Prove it before any queue/identity mutation;
        // a leading-slice lookup alone could otherwise name stale or corrupt
        // secondary map entries.
        let exact_arena_span = match (
            self.release_span(page.as_ptr()),
            memory.arena_memory(),
        ) {
            (Some(ReleaseSpan::Arena { memory: span_memory, .. }), Some(expected)) => {
                span_memory.arena_memory().is_some_and(|actual| {
                    actual.arena == expected.arena
                        && actual.slice_index == expected.slice_index
                        && actual.slice_count == expected.slice_count
                })
            }
            _ => false,
        };
        if !exact_arena_span {
            return Err(reject(self, DynamicMappedAbandonError::Unmapped));
        }
        if !self.page_is_active_queue_member(bin, page) {
            return Err(reject(self, DynamicMappedAbandonError::NotActiveRegular));
        }
        let Some(canonical_block) = self.canonical_block_start(page_ref, block) else {
            return Err(reject(self, DynamicMappedAbandonError::NotActiveRegular));
        };
        // SAFETY: all immutable facts derived from `page_ref` above are now
        // copied. This temporary whole-page projection performs only local
        // geometry validation and ends before later raw/session mutation.
        let preflight = match unsafe { LocalFreeList::from_page(&mut *page.as_ptr()) } {
            Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
            Err(error) => Err(error),
        };
        if preflight.is_err() {
            return Err(reject(self, DynamicMappedAbandonError::NotActiveRegular));
        }
        if self
            .session
            .mapped_abandoned_page(&self.arena, bin, memory)
            .is_none()
        {
            return Err(reject(self, DynamicMappedAbandonError::MissingDynamicArenaPages));
        }

        // `_mi_page_abandon` force-collects before queue removal. This exact
        // dynamic handoff accepts no outstanding producer, so a successful
        // collection cannot newly make the page empty through a later token.
        if let Err(error) = self.page_free_collect_false(page) {
            self.retain_page_collect_poison(page, error, None);
            return Err(reject(self, DynamicMappedAbandonError::Collection));
        }
        // SAFETY: collection completed while the page remains queue-linked;
        // this reads the owner-local count under the exclusive engine.
        if unsafe { page.as_ref().used() } == 0 {
            return Err(reject(self, DynamicMappedAbandonError::EmptyAfterCollection));
        }

        let queue = match self.session.queue_mut(bin) {
            Some(queue) => queue as *mut _,
            None => return Err(reject(self, DynamicMappedAbandonError::NotActiveRegular)),
        };
        // SAFETY: exact membership was proven before collection and no
        // producer token can coexist with this consuming engine operation.
        unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
        if !self.session.note_page_removed() {
            let handoff = DynamicMappedPageHandoff {
                engine: self,
                page,
                bin,
                memory,
                terminal: true,
            };
            return Err(DynamicMappedAbandonFailure::Terminal {
                handoff,
                error: DynamicMappedAbandonError::NotActiveRegular,
            });
        }
        self.update_direct_cache(bin);
        let abandoned = {
            let map = self
                .session
                .mapped_abandoned_page(&self.arena, bin, memory)
                .expect("prevalidated dynamic mapped page remains owner-bound");
            // SAFETY: exact source order is collection, queue detach, then
            // identity/bitmap/count/unown. The capability fixes arena/bin/slice.
            unsafe { abandoned::abandon_after_collect(page, Some(&map)) }
        };
        match abandoned {
            Ok(AbandonResult::UnownedMapped) => Ok(DynamicMappedPageHandoff {
                engine: self,
                page,
                bin,
                memory,
                terminal: false,
            }),
            Ok(result) => {
                let error = match result {
                    AbandonResult::Empty => DynamicMappedAbandonError::EmptyAfterCollection,
                    AbandonResult::UnownedUnmapped => DynamicMappedAbandonError::FullOrSpecial,
                    AbandonResult::UnownedMapped => unreachable!(),
                };
                let handoff = DynamicMappedPageHandoff {
                    engine: self,
                    page,
                    bin,
                    memory,
                    terminal: true,
                };
                Err(DynamicMappedAbandonFailure::Terminal { handoff, error })
            }
            Err(error) => {
                let handoff = DynamicMappedPageHandoff {
                    engine: self,
                    page,
                    bin,
                    memory,
                    terminal: true,
                };
                Err(DynamicMappedAbandonFailure::Terminal {
                    handoff,
                    error: DynamicMappedAbandonError::Abandon(error),
                })
            }
        }
    }

    /// Test-only non-mutating attachment preflight. This deliberately cannot
    /// call teardown while the engine owns the dynamic page session.
    #[cfg(test)]
    pub(crate) fn test_attachment_teardown_preflight(&mut self) -> Result<(), crate::dynamic_theap::DynamicTheapError> {
        self.session.test_teardown_preflight()
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_arena_pages_image(
        &self,
        memory: MemoryId,
    ) -> Option<(
        NonNull<crate::types::ArenaPages>,
        crate::arena::ArenaPagesLayout,
        MemoryId,
        bool,
    )> {
        self.session.test_arena_pages_image(memory)
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_main_arena_page_is_clear(&self, memory: MemoryId) -> bool {
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        // SAFETY: the engine retains the registry-published arena view. This
        // is a nonmutating test witness for the dynamic/local bitmap split.
        unsafe { self.arena.pages() }
            .and_then(|pages| pages.is_clear_range(arena_memory.slice_index as usize, 1))
            == Some(true)
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_abandoned_page_is_clear(
        &self,
        bin: usize,
        memory: MemoryId,
    ) -> bool {
        let Some(slice) = memory.arena_memory().map(|memory| memory.slice_index as usize) else {
            return false;
        };
        self.session
            .mapped_abandoned_page(&self.arena, bin, memory)
            .is_some_and(|map| crate::abandoned::MappedAbandonedPages::is_clear(&map, slice))
    }

}

impl<'main, 'arena, 'map> PageAllocatorEngine<'arena, 'map, MainStaticPageSession<'main>> {
    /// Activates the existing source page engine over the ticket-zero static
    /// owner. Unlike the caller-managed test/dynamic constructors, this takes
    /// only a shared PageMap reference: the caller must hold the private
    /// process-root mutation lease for this complete engine and every scoped
    /// remote producer lifetime.
    ///
    /// # Safety
    ///
    /// `page_map` must be the final process-global map matched to `arena` and
    /// serialized by a live `ProcessPageMapMutationLease`. No other plain
    /// PageMap registration, lookup, or unregistration may overlap this
    /// engine. `session` must be the matching ticket-zero static owner.
    pub(crate) unsafe fn activate_main_static(
        session: MainStaticPageSession<'main>,
        arena: ArenaView<'arena>,
        requested_arena: ArenaId,
        page_map: &'map PageMap,
    ) -> Self {
        let thread_sequence = session.thread_sequence();
        Self {
            session,
            arena,
            requested_arena,
            page_map,
            thread_sequence,
            pending_os_release: None,
            collection_poison: None,
            #[cfg(test)]
            page_free_collect_failure_once: false,
            #[cfg(test)]
            last_page_to_full: None,
            shutdown_complete: false,
        }
    }
}

impl<'attachment, 'main, 'arena, 'map>
    PageAllocatorEngine<'arena, 'map, MainHeapThreadPageSession<'attachment, 'main>>
{
    /// Activates the existing source page engine for one later metadata Theap
    /// linked to `mi_heap_main()`. Like the ticket-zero specialization, the
    /// PageMap is a shared reference only because its paired process owner
    /// retains the exclusive mutation lease for the complete engine and every
    /// scoped remote producer lifetime.
    ///
    /// # Safety
    ///
    /// `page_map` must be the final process-global map paired with `arena`
    /// and serialized by a live `ProcessPageMapMutationLease`. `session` must
    /// retain the exact current later-thread Theap and a live static-main Heap
    /// lease for that same process image.
    pub(crate) unsafe fn activate_later_main_thread(
        session: MainHeapThreadPageSession<'attachment, 'main>,
        arena: ArenaView<'arena>,
        requested_arena: ArenaId,
        page_map: &'map PageMap,
    ) -> Self {
        let thread_sequence = session.thread_sequence();
        Self {
            session,
            arena,
            requested_arena,
            page_map,
            thread_sequence,
            pending_os_release: None,
            collection_poison: None,
            #[cfg(test)]
            page_free_collect_failure_once: false,
            #[cfg(test)]
            last_page_to_full: None,
            shutdown_complete: false,
        }
    }

    /// Consumes one ordinary later-main page engine into the source
    /// post-fast-slot page-drain state. Unlike normal `finish`, this path
    /// deliberately reaches every queue, including `BIN_FULL`, with the
    /// force collector needed by `_mi_theap_collect_abandon` before it decides
    /// whether each page can be released. A transition failure retains the
    /// original engine because no allocation API may resume after a visible
    /// thread-exit root transition.
    pub(crate) fn begin_thread_exit_drain(
        self,
    ) -> Result<
        PageAllocatorEngine<'arena, 'map, MainHeapThreadPageDrainSession<'attachment, 'main>>,
        (
            PageAllocatorEngine<'arena, 'map, MainHeapThreadPageSession<'attachment, 'main>>,
            MainHeapThreadAttachmentError,
        ),
    > {
        if self.is_collection_poisoned() || self.pending_os_release.is_some() {
            return Err((self, MainHeapThreadAttachmentError::Poisoned));
        }
        let (session, state) = self.into_session_and_state();
        match session.begin_thread_exit_drain() {
            Ok(session) => Ok(
                PageAllocatorEngine::<MainHeapThreadPageSession<'attachment, 'main>>::from_session_and_state(
                    session, state,
                ),
            ),
            Err((session, error)) => Err((
                PageAllocatorEngine::<MainHeapThreadPageSession<'attachment, 'main>>::from_session_and_state(
                    session, state,
                ),
                error,
            )),
        }
    }
}

impl<'attachment, 'main, 'arena, 'map>
    PageAllocatorEngine<'arena, 'map, MainHeapThreadPageDrainSession<'attachment, 'main>>
{
    /// Completes the first bounded later-main source owner-exit traversal.
    ///
    /// Source `_mi_theap_collect_abandon` force-collects every ordinary and
    /// full queue before releasing all-free pages or abandoning the remaining
    /// live pages. This deliberately ports only the all-free side: it visits
    /// every queue and force-appends joined remote/local frees, releases each
    /// page that reaches zero use through the existing PageMap -> `pages_main`
    /// -> metadata -> arena-slice order, and retains this drain if any page
    /// remains live. General regular/unmapped/huge abandonment, deferred
    /// callbacks, arena collection, and later free/reclaim routing remain
    /// outside this capability.
    pub(crate) fn finish_after_all_free_thread_exit(mut self) -> Result<(), Self> {
        if self.is_collection_poisoned() || self.pending_os_release.is_some() {
            return Err(self);
        }

        // Source visits every queue before it starts the broader live-page
        // abandonment decision. This bounded port preserves that complete
        // force-collection/release pass, but records a live page instead of
        // queue-detaching or abandoning it. The retained post-fast-slot owner
        // is the explicit boundary where a later source-complete traversal
        // must resume.
        let mut retained_live_page = false;
        for bin in 0..BIN_COUNT {
            let mut page = match self.session.queue(bin) {
                Some(queue) => queue.first(),
                None => return Err(self),
            };
            while !page.is_null() {
                // SAFETY: the drain retains the sole queue mutation capability
                // and every producer has joined before it can be consumed.
                // Preserve the successor before all-free release may retire
                // this page's metadata and return its arena slices.
                let next = unsafe { (*page).next() };
                let Some(page_nonnull) = NonNull::new(page) else {
                    return Err(self);
                };
                if let Err(error) = self.page_free_collect_force(page_nonnull) {
                    self.retain_page_collect_poison(page_nonnull, error, None);
                    return Err(self);
                }
                // SAFETY: the source force collector completed while the
                // page remains queue-linked under this exclusive drain.
                if unsafe { page_nonnull.as_ref().used() } != 0 {
                    // Do not queue-detach or abandon a live page here, but
                    // keep visiting later queues: source force collection
                    // must not leave a joined remote/free list beyond the
                    // first live page. The retained drain represents the
                    // resulting post-fast-slot state until a later
                    // source-complete traversal exists.
                    retained_live_page = true;
                } else if !self.release_page(bin, page) {
                    // `release_page` can fail after queue removal and PageMap
                    // unregistration. A second pass could then mistake its
                    // empty queue/count for completed drain, so retain a
                    // terminal page-specific record rather than retrying.
                    self.retain_page_collect_poison(
                        page_nonnull,
                        PageCollectError::Lifecycle,
                        None,
                    );
                    return Err(self);
                }
                page = next;
            }
        }

        if retained_live_page
            || self.is_collection_poisoned()
            || self.pending_os_release.is_some()
            || self.session.theap().page_count() != 0
        {
            return Err(self);
        }
        for bin in 0..BIN_COUNT {
            if !self.session.queue(bin).is_some_and(|queue| queue.count() == 0) {
                return Err(self);
            }
        }
        for index in 0..PAGES_DIRECT {
            if self.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                return Err(self);
            }
        }
        self.shutdown_complete = true;
        Ok(())
    }

    /// Detaches the one source full-singleton owner-exit case after the fixed
    /// main fast slot has already been cleared. This specialization is the
    /// only later-main caller of the private generic transition below; its
    /// session construction proves the post-fast-slot source state.
    ///
    /// # Safety
    ///
    /// `block` must be the sole current allocation in the exact full arena
    /// singleton owned by this draining later-main engine. No scoped producer
    /// may survive, and every client alias must remain live only until the
    /// returned handoff consumes this exact block once or is retained.
    pub(crate) unsafe fn abandon_full_singleton_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        ThreadExitSingletonHandoff<'arena, 'map, MainHeapThreadPageDrainSession<'attachment, 'main>>,
        ThreadExitSingletonAbandonFailure<'arena, 'map, MainHeapThreadPageDrainSession<'attachment, 'main>>,
    > {
        // SAFETY: this specialization's post-fast-slot session supplies the
        // source owner-exit/reclaim-failure proof required by the shared
        // queue-detach and failed-reclaim handoff.
        unsafe { abandon_full_singleton_after_thread_exit(self, block) }
    }

    /// Detaches the one source mapped-abandoned regular-page owner-exit case:
    /// a sole medium arena page with exactly one live client block. Its final
    /// free must make the page empty before source reclaim is considered, so
    /// the paired handoff never exposes a live-page reclaim or requeue route.
    ///
    /// # Safety
    ///
    /// `block` must be the sole current allocation in one active medium arena
    /// page owned by this exact post-fast-slot drain. No scoped producer may
    /// survive, and all client aliases must remain live only until the returned
    /// handoff consumes this exact block once or is retained.
    pub(crate) unsafe fn abandon_mapped_one_block_after_thread_exit(
        self,
        block: NonNull<u8>,
    ) -> Result<
        ThreadExitMappedOneBlockHandoff<
            'arena,
            'map,
            MainHeapThreadPageDrainSession<'attachment, 'main>,
        >,
        ThreadExitMappedOneBlockAbandonFailure<
            'arena,
            'map,
            MainHeapThreadPageDrainSession<'attachment, 'main>,
        >,
    > {
        // SAFETY: this specialization's post-fast-slot session supplies the
        // source owner-exit proof. The narrow generic transition below retains
        // the matching PageMap/arena/bitmap and exact final-free authority.
        unsafe { abandon_mapped_one_block_after_thread_exit(self, block) }
    }

    /// Detaches one sole nonfull medium arena page into a process-owned route
    /// after the fixed main fast slot has cleared.
    ///
    /// This is the first route that actually releases the old later
    /// Theap/TLD while client blocks remain live. It deliberately accepts one
    /// page only and preserves source order: force collection from
    /// `_mi_theap_collect_abandon`, `_mi_page_abandon`'s false collection,
    /// queue/page-count detach, mapped identity/bitmap/count publication,
    /// then transfer to a short process PageMap route. It does not yet claim
    /// allocation-time bitmap adoption, requeue/reclaim, small/large pages,
    /// multiple pages, or concurrent client-free routing.
    ///
    /// # Safety
    ///
    /// `block` must be one current canonical allocation in the exact sole
    /// medium regular page owned by this draining engine. No scoped producer
    /// may survive. Every client alias in that page must remain valid only
    /// through the returned process route or an explicitly retained terminal
    /// owner.
    pub(crate) unsafe fn abandon_mapped_medium_to_process_route(
        mut self,
        block: NonNull<u8>,
    ) -> Result<
        ThreadExitMappedRegularPostExitDetach<'attachment, 'main, 'arena>,
        ThreadExitMappedRegularPostExitAbandonFailure<'attachment, 'main, 'arena, 'map>,
    > {
        let reject = |engine, error| {
            ThreadExitMappedRegularPostExitAbandonFailure::Rejected { engine, error }
        };
        let retained = |engine, error| {
            ThreadExitMappedRegularPostExitAbandonFailure::RetainedEngine { engine, error }
        };
        if self.is_collection_poisoned() || self.pending_os_release.is_some() {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::Collection,
            ));
        }

        // SAFETY: this consuming engine still owns the complete long PageMap
        // lifecycle, so the source-plain lookup cannot race ordinary writes.
        let page = unsafe { self.page_map.checked_lookup(block.as_ptr()) };
        let Some(page) = NonNull::new(page) else {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::Unmapped,
            ));
        };
        // SAFETY: the map publication and exclusive drain retain this page's
        // ordinary fields for the complete pre-detach validation below.
        let page_ref = unsafe { page.as_ref() };
        if !self.owns_page(page_ref) || page_ref.heap() != self.session.theap().heap() {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::ForeignPage,
            ));
        }
        if page_ref.memid().kind() != MemoryKind::Arena {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::NonArena,
            ));
        }
        let Some(bin) = size_class::bin(page_ref.block_size()) else {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::NotMappedRegular,
            ));
        };
        if size_class::page_kind_for_block_size(page_ref.block_size()) != Some(PageKind::Medium)
            || page_ref.block_size() <= SMALL_SIZE_MAX
            || bin >= ARENA_BIN_COUNT
            || bin == BIN_FULL
            || page_ref.reserved() <= 1
            || page_ref.used() == 0
            || page_is_in_full(page_ref)
        {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::NotMappedRegular,
            ));
        }

        // This first post-exit route intentionally cannot skip source queue
        // traversal or leave a second page behind. Verify the complete owner
        // image before its first force collection can change local state.
        let mut sole_page = self.session.theap().page_count() == 1;
        for queue_bin in 0..BIN_COUNT {
            let expected = if queue_bin == bin { 1 } else { 0 };
            if !self
                .session
                .queue(queue_bin)
                .is_some_and(|queue| queue.count() == expected)
            {
                sole_page = false;
                break;
            }
        }
        if sole_page {
            for index in 0..PAGES_DIRECT {
                if self.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                    sole_page = false;
                    break;
                }
            }
        }
        if !sole_page {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::NotOnlyPage,
            ));
        }

        // Preserve an exact full-span release witness before queue/identity
        // mutation. The later process route rechecks it while holding each
        // short map guard, but cannot reconstruct a missing source span.
        let (memory, slice_start, size) = match self.release_span(page.as_ptr()) {
            Some(ReleaseSpan::Arena {
                memory,
                slice_start,
                size,
            }) => (memory, slice_start, size),
            Some(ReleaseSpan::Os(_)) | None => {
                return Err(reject(
                    self,
                    ThreadExitMappedRegularPostExitAbandonError::Unmapped,
                ));
            }
        };
        if self.main_heap_abandoned_page(bin).is_none() {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::MissingMainArenaPages,
            ));
        }
        if !self.page_is_active_queue_member(bin, page) {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::NotActiveRegular,
            ));
        }
        let Some(canonical_block) = self.canonical_block_start(page_ref, block) else {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::InvalidBlock,
            ));
        };
        // SAFETY: the exclusive pre-detach owner validates only local geometry
        // and the lower used bound; it does not change any source state.
        let preflight = match unsafe { LocalFreeList::from_page(&mut *page.as_ptr()) } {
            Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
            Err(error) => Err(error),
        };
        if preflight.is_err() {
            return Err(reject(
                self,
                ThreadExitMappedRegularPostExitAbandonError::InvalidBlock,
            ));
        }

        // `mi_theap_collect_ex(MI_ABANDON)` force-collects first. Its page
        // can become all-free through already joined source state, in which
        // case the caller retains this drain rather than inventing a live
        // process route for a page the ordinary release path must handle.
        if let Err(error) = self.page_free_collect_force(page) {
            self.retain_page_collect_poison(page, error, None);
            return Err(retained(
                self,
                ThreadExitMappedRegularPostExitAbandonError::Collection,
            ));
        }
        if unsafe { page.as_ref().used() } == 0 {
            return Err(retained(
                self,
                ThreadExitMappedRegularPostExitAbandonError::NotMappedRegular,
            ));
        }
        // `_mi_page_abandon` follows with its ordinary false collection just
        // before it removes the queue member and publishes abandonment.
        if let Err(error) = self.page_free_collect_false(page) {
            self.retain_page_collect_poison(page, error, None);
            return Err(retained(
                self,
                ThreadExitMappedRegularPostExitAbandonError::Collection,
            ));
        }
        // SAFETY: both source collectors completed under the exclusive drain.
        let after_collect = unsafe { page.as_ref() };
        if size_class::page_kind_for_block_size(after_collect.block_size()) != Some(PageKind::Medium)
            || size_class::bin(after_collect.block_size()) != Some(bin)
            || after_collect.block_size() <= SMALL_SIZE_MAX
            || after_collect.reserved() <= 1
            || after_collect.used() == 0
            || page_is_in_full(after_collect)
        {
            return Err(retained(
                self,
                ThreadExitMappedRegularPostExitAbandonError::NotMappedRegular,
            ));
        }

        let queue = match self.session.queue_mut(bin) {
            Some(queue) => queue as *mut _,
            None => {
                return Err(retained(
                    self,
                    ThreadExitMappedRegularPostExitAbandonError::Queue,
                ));
            }
        };
        // SAFETY: the exact sole active queue member was prevalidated and no
        // producer can coexist with this consuming post-fast-slot drain.
        unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
        if !self.session.note_page_removed() {
            return Err(retained(
                self,
                ThreadExitMappedRegularPostExitAbandonError::Queue,
            ));
        }
        // Medium pages have no direct cache entry, but preserve the normal
        // queue-remove boundary in case a stale image would otherwise hide a
        // broken source invariant.
        self.update_direct_cache(bin);

        let abandoned = match self.main_heap_abandoned_page(bin) {
            Some(map) => {
                // SAFETY: this is the source force -> false -> queue/count
                // detach -> mapped identity/bit/count/unown order. `map`
                // names the exact static-main bitmap/count pair.
                unsafe { abandoned::abandon_after_collect(page, Some(&map)) }
            }
            None => {
                return Err(retained(
                    self,
                    ThreadExitMappedRegularPostExitAbandonError::MissingMainArenaPages,
                ));
            }
        };
        match abandoned {
            Ok(AbandonResult::UnownedMapped) => {}
            Ok(outcome) => {
                return Err(retained(
                    self,
                    ThreadExitMappedRegularPostExitAbandonError::UnexpectedAbandonOutcome(outcome),
                ));
            }
            Err(error) => {
                return Err(retained(
                    self,
                    ThreadExitMappedRegularPostExitAbandonError::Abandon(error),
                ));
            }
        }

        // Only now may the old engine release its attachment borrow. The
        // abandoned page has no queue/direct/page-count ownership left, while
        // the returned `parts` retain the independent map/arena/heap facts.
        if self.is_collection_poisoned()
            || self.pending_os_release.is_some()
            || self.session.theap().page_count() != 0
        {
            return Err(retained(
                self,
                ThreadExitMappedRegularPostExitAbandonError::PostDetachState,
            ));
        }
        for queue_bin in 0..BIN_COUNT {
            if !self
                .session
                .queue(queue_bin)
                .is_some_and(|queue| queue.count() == 0)
            {
                return Err(retained(
                    self,
                    ThreadExitMappedRegularPostExitAbandonError::PostDetachState,
                ));
            }
        }
        for index in 0..PAGES_DIRECT {
            if self.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                return Err(retained(
                    self,
                    ThreadExitMappedRegularPostExitAbandonError::PostDetachState,
                ));
            }
        }

        let (session, state) = self.into_session_and_state();
        let main_heap = session.main_heap_lease();
        let PageAllocatorEngineState {
            arena,
            requested_arena: _,
            page_map: _,
            thread_sequence: _,
            pending_os_release,
            collection_poison,
            #[cfg(test)]
            page_free_collect_failure_once: _,
            #[cfg(test)]
            last_page_to_full: _,
            shutdown_complete: _,
        } = state;
        debug_assert!(pending_os_release.is_none());
        debug_assert!(collection_poison.is_none());
        drop(pending_os_release);
        let _ = collection_poison;

        Ok(ThreadExitMappedRegularPostExitDetach {
            session,
            parts: ThreadExitMappedRegularPostExitParts {
                arena,
                main_heap,
                memory,
                slice_start,
                size,
                bin,
            },
        })
    }

    /// Ports the retired-page portion of
    /// `src/page.c:_mi_theap_collect_retired(theap, true)` that precedes the
    /// aggregate mapped medium-and-large route's normal page traversal.
    ///
    /// The source `MI_ABANDON` path runs this pass after deferred callbacks
    /// and before it visits ordinary/full queues. This bounded route has no
    /// deferred-callback capability, but it must still force-release an
    /// already-empty, locally retired regular page before deciding which live
    /// pages enter its process registry. The shared-main later Theap is
    /// constructed in the normal `allow_page_abandon` mode, so the source's
    /// non-abandoning full-queue branch is unreachable here; running the
    /// generic [`Self::collect_retired`] helper would incorrectly add its
    /// arena-purge work to an `MI_ABANDON` transition.
    ///
    /// The caller first proves the entire queue image has only the supported
    /// medium-or-large shape, permitting an empty member only when its source
    /// retirement countdown is nonzero. Therefore a prepass release failure
    /// retains this post-fast-slot drain rather than mutating an otherwise
    /// rejected mixed page-class image.
    fn collect_retired_before_mapped_medium_large_route(
        &mut self,
    ) -> Result<(), ThreadExitMappedMediumLargePagesPostExitAbandonError> {
        debug_assert!(
            self.session.theap().allows_page_abandon(),
            "the shared-main later Theap has the source abandoning option image"
        );

        let (minimum, maximum) = self.session.retired_bounds();
        self.session.reset_retired_bounds();
        if minimum >= BIN_FULL || minimum > maximum {
            return Ok(());
        }

        for bin in minimum..=maximum {
            let mut page = match self.session.queue(bin) {
                Some(queue) => queue.first(),
                None => return Err(ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue),
            };
            let mut visited = 0usize;
            while !page.is_null() && visited < RETIRE_MAX_PAGES {
                visited += 1;
                let page_nonnull = match NonNull::new(page) {
                    Some(page) => page,
                    None => return Err(ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue),
                };
                // SAFETY: the structural preflight retains exclusive queue
                // ownership. Preserve the successor before source release can
                // retire this page's metadata and arena span.
                let next = unsafe { page_nonnull.as_ref().next() };
                let expire = unsafe { page_nonnull.as_ref().retire_expire() };
                if expire == 0 {
                    break;
                }
                if unsafe { page_nonnull.as_ref().used() } == 0 {
                    // `_mi_page_try_retire` decrements first, even when the
                    // forced source branch immediately frees the page.
                    unsafe { (*page_nonnull.as_ptr()).set_retire_expire(expire - 1) };
                    if !self.release_page(bin, page_nonnull.as_ptr()) {
                        return Err(ThreadExitMappedMediumLargePagesPostExitAbandonError::Release);
                    }
                } else {
                    // A page revived before this source pass is no longer
                    // retired; the later normal traversal still validates and
                    // abandons it as one live medium-or-large page.
                    unsafe { (*page_nonnull.as_ptr()).set_retire_expire(0) };
                }
                page = next;
            }
        }
        Ok(())
    }

    /// Traverses every live mapped medium-or-large page of this post-fast-slot
    /// later owner in the same source order as `_mi_theap_collect_abandon`.
    ///
    /// A complete non-mutating structural preflight requires every current
    /// queue member to be a nonfull medium-or-large arena page that can use
    /// the static main Heap's exact bitmap/count pairing, and every direct
    /// slot to be empty. It admits an empty member only when that page is
    /// source-retired.
    /// The source retired-page prepass then releases those spans before the
    /// normal traversal force-collects, false-collects and detaches each
    /// remaining live page for mapped-abandoned publication. The aggregate
    /// process route is a typed registry over those source PageMap and bitmap
    /// entries, not a local list of raw page pointers.
    ///
    /// It deliberately has no allocation-time claim, reclaim/requeue, or
    /// concurrent client-free policy. The caller must retain its linear route
    /// until all PageMap-registered pages release, and ordinary page engines
    /// remain excluded by the same process-map lifecycle throughout.
    ///
    /// # Safety
    ///
    /// No scoped producer may survive, and every currently live page of this
    /// drain must have only client aliases that will be consumed exactly once
    /// through the returned route (or retained terminally). The caller must
    /// use this only after the concrete later-main fast-slot-clear transition;
    /// no former-Theap dereference is valid after the returned detach tears it
    /// down.
    pub(crate) unsafe fn abandon_mapped_medium_large_pages_to_process_route(
        mut self,
    ) -> Result<
        ThreadExitMappedMediumLargePagesPostExitAbandonOutcome<'attachment, 'main, 'arena, 'map>,
        ThreadExitMappedMediumLargePagesPostExitAbandonFailure<'attachment, 'main, 'arena, 'map>,
    > {
        let reject = |engine, error| {
            ThreadExitMappedMediumLargePagesPostExitAbandonFailure::Rejected { engine, error }
        };
        let retained = |engine, error| {
            ThreadExitMappedMediumLargePagesPostExitAbandonFailure::RetainedEngine { engine, error }
        };
        if self.is_collection_poisoned() || self.pending_os_release.is_some() {
            return Err(reject(
                self,
                ThreadExitMappedMediumLargePagesPostExitAbandonError::Collection,
            ));
        }

        // Before source retirement or force collection can change local
        // ownership, prove that *every* page has the one bounded
        // mapped medium-and-large route. This is the aggregate registry
        // boundary: it rejects full/small/singleton/OS pages and malformed
        // queue images without partially detaching an earlier member. In
        // particular, prove each
        // queue's empty endpoints, head predecessor, every predecessor link,
        // terminal successor, and tail before the later unsafe remove kernel
        // relies on that complete doubly linked image. A zero-used member is
        // valid only when normal local free left it in the source retired
        // state; the following source-order prepass must release it before
        // live routing.
        let expected_page_count = self.session.theap().page_count();
        let mut observed_page_count = 0usize;
        for queue_bin in 0..BIN_COUNT {
            let Some(queue) = self.session.queue(queue_bin) else {
                return Err(reject(
                    self,
                    ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                ));
            };
            let mut remaining = queue.count();
            if remaining == 0 {
                if !queue.is_empty() {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                    ));
                }
                continue;
            }

            let mut page = queue.first();
            let mut previous = core::ptr::null_mut();
            while remaining != 0 {
                let Some(page_nonnull) = NonNull::new(page) else {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                    ));
                };
                // SAFETY: the exclusive drain retains every queue member's
                // initialized metadata for this preflight. No source state is
                // changed until this complete pass succeeds.
                let page_ref = unsafe { page_nonnull.as_ref() };
                if page_ref.prev() != previous {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                    ));
                }
                if !self.owns_page(page_ref) || page_ref.heap() != self.session.theap().heap() {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::ForeignPage,
                    ));
                }
                if page_ref.memid().kind() != MemoryKind::Arena {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::NonArena,
                    ));
                }
                let Some(bin) = size_class::bin(page_ref.block_size()) else {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::NotMappedMediumLarge,
                    ));
                };
                if queue_bin != bin
                    || !matches!(
                        size_class::page_kind_for_block_size(page_ref.block_size()),
                        Some(PageKind::Medium | PageKind::Large)
                    )
                    || page_ref.block_size() <= SMALL_SIZE_MAX
                    || bin >= ARENA_BIN_COUNT
                    || bin == BIN_FULL
                    || page_ref.reserved() <= 1
                    || (page_ref.used() == 0 && page_ref.retire_expire() == 0)
                    || page_ref.used() >= usize::from(page_ref.reserved())
                    || page_is_in_full(page_ref)
                {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::NotMappedMediumLarge,
                    ));
                }
                if queue.block_size() != page_ref.block_size()
                    || !matches!(self.release_span(page_nonnull.as_ptr()), Some(ReleaseSpan::Arena { .. }))
                {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::NotMappedMediumLarge,
                    ));
                }
                if self.main_heap_abandoned_page(bin).is_none() {
                    return Err(reject(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::MissingMainArenaPages,
                    ));
                }
                observed_page_count = match observed_page_count.checked_add(1) {
                    Some(count) => count,
                    None => {
                        return Err(reject(
                            self,
                            ThreadExitMappedMediumLargePagesPostExitAbandonError::RouteCountOverflow,
                        ));
                    }
                };
                // SAFETY: the queue is exclusively stable during this
                // preflight; bounded `remaining` makes a malformed cycle
                // reject through the final tail check rather than loop.
                page = unsafe { page_nonnull.as_ref().next() };
                previous = page_nonnull.as_ptr();
                remaining -= 1;
            }
            if !page.is_null() || queue.last() != previous {
                return Err(reject(
                    self,
                    ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                ));
            }
        }
        if observed_page_count != expected_page_count {
            return Err(reject(
                self,
                ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
            ));
        }
        for index in 0..PAGES_DIRECT {
            if self.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                return Err(reject(
                    self,
                    ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                ));
            }
        }

        // `mi_theap_collect_ex(MI_ABANDON)` releases tracked retired regular
        // pages before it visits queues for the force/abandon decision. Keep
        // this separate from `collect_retired`: abandoning a later owner must
        // not run its generic arena-purge pass. A failed release may already
        // have changed queue/map/arena ownership, so retain this drain.
        if let Err(error) = self.collect_retired_before_mapped_medium_large_route() {
            return Err(retained(self, error));
        }

        let mut detached_pages = 0usize;
        for bin in 0..BIN_COUNT {
            let mut page = match self.session.queue(bin) {
                Some(queue) => queue.first(),
                None => {
                    return Err(retained(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                    ));
                }
            };
            while !page.is_null() {
                let Some(page_nonnull) = NonNull::new(page) else {
                    return Err(retained(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                    ));
                };
                // Preserve the successor before an all-free source release
                // can retire this page's metadata and backing arena slices.
                // SAFETY: queue ownership remains exclusive through this
                // source-order visit.
                let next = unsafe { page_nonnull.as_ref().next() };

                // `_mi_theap_page_collect` force-collects first. A page that
                // reaches zero use follows the ordinary all-free release,
                // including before any mapped-abandoned publication.
                if let Err(error) = self.page_free_collect_force(page_nonnull) {
                    self.retain_page_collect_poison(page_nonnull, error, None);
                    return Err(retained(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Collection,
                    ));
                }
                if unsafe { page_nonnull.as_ref().used() } == 0 {
                    if !self.release_page(bin, page_nonnull.as_ptr()) {
                        return Err(retained(
                            self,
                            ThreadExitMappedMediumLargePagesPostExitAbandonError::Release,
                        ));
                    }
                    page = next;
                    continue;
                }

                // `_mi_page_abandon` performs one ordinary false collection
                // before it decides between its own all-free release and
                // queue detach/mapped publication.
                if let Err(error) = self.page_free_collect_false(page_nonnull) {
                    self.retain_page_collect_poison(page_nonnull, error, None);
                    return Err(retained(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Collection,
                    ));
                }
                if unsafe { page_nonnull.as_ref().used() } == 0 {
                    if !self.release_page(bin, page_nonnull.as_ptr()) {
                        return Err(retained(
                            self,
                            ThreadExitMappedMediumLargePagesPostExitAbandonError::Release,
                        ));
                    }
                    page = next;
                    continue;
                }

                // The non-mutating preflight proved this shape before the
                // source collectors. Recheck the ordinary geometry after the
                // collectors before queue ownership crosses the boundary.
                // SAFETY: both collectors completed under this exclusive
                // owner; the page remains linked until the remove below.
                let page_ref = unsafe { page_nonnull.as_ref() };
                if !matches!(
                    size_class::page_kind_for_block_size(page_ref.block_size()),
                    Some(PageKind::Medium | PageKind::Large)
                )
                    || size_class::bin(page_ref.block_size()) != Some(bin)
                    || page_ref.block_size() <= SMALL_SIZE_MAX
                    || bin >= ARENA_BIN_COUNT
                    || bin == BIN_FULL
                    || page_ref.reserved() <= 1
                    || page_ref.used() == 0
                    || page_ref.used() >= usize::from(page_ref.reserved())
                    || page_is_in_full(page_ref)
                {
                    return Err(retained(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::NotMappedMediumLarge,
                    ));
                }

                let queue = match self.session.queue_mut(bin) {
                    Some(queue) => queue as *mut _,
                    None => {
                        return Err(retained(
                            self,
                            ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                        ));
                    }
                };
                // SAFETY: this exact page remains linked in its preflighted
                // queue and no producer may coexist with the consuming drain.
                unsafe { page_queue_remove_metadata(&mut *queue, page_nonnull.as_ptr()) };
                if !self.session.note_page_removed() {
                    return Err(retained(
                        self,
                        ThreadExitMappedMediumLargePagesPostExitAbandonError::Queue,
                    ));
                }
                self.update_direct_cache(bin);

                let abandoned = match self.main_heap_abandoned_page(bin) {
                    Some(map) => {
                        // Source order is force -> false -> queue/count
                        // detach -> mapped identity/bit/count -> unown. The
                        // returned process registry owns the later free.
                        unsafe { abandoned::abandon_after_collect(page_nonnull, Some(&map)) }
                    }
                    None => {
                        return Err(retained(
                            self,
                            ThreadExitMappedMediumLargePagesPostExitAbandonError::MissingMainArenaPages,
                        ));
                    }
                };
                match abandoned {
                    Ok(AbandonResult::UnownedMapped) => {
                        detached_pages = match detached_pages.checked_add(1) {
                            Some(count) => count,
                            None => {
                                return Err(retained(
                                    self,
                                    ThreadExitMappedMediumLargePagesPostExitAbandonError::RouteCountOverflow,
                                ));
                            }
                        };
                    }
                    Ok(outcome) => {
                        return Err(retained(
                            self,
                            ThreadExitMappedMediumLargePagesPostExitAbandonError::UnexpectedAbandonOutcome(outcome),
                        ));
                    }
                    Err(error) => {
                        return Err(retained(
                            self,
                            ThreadExitMappedMediumLargePagesPostExitAbandonError::Abandon(error),
                        ));
                    }
                }
                page = next;
            }
        }

        // Source traversal has either released every page or transferred every
        // surviving page into the PageMap/bitmap registry. No old queue,
        // direct cache, or Theap page count may remain before attachment
        // teardown becomes sound.
        if self.is_collection_poisoned()
            || self.pending_os_release.is_some()
            || self.session.theap().page_count() != 0
        {
            return Err(retained(
                self,
                ThreadExitMappedMediumLargePagesPostExitAbandonError::PostDetachState,
            ));
        }
        for queue_bin in 0..BIN_COUNT {
            if !self
                .session
                .queue(queue_bin)
                .is_some_and(|queue| queue.is_empty())
            {
                return Err(retained(
                    self,
                    ThreadExitMappedMediumLargePagesPostExitAbandonError::PostDetachState,
                ));
            }
        }
        for index in 0..PAGES_DIRECT {
            if self.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                return Err(retained(
                    self,
                    ThreadExitMappedMediumLargePagesPostExitAbandonError::PostDetachState,
                ));
            }
        }

        if detached_pages == 0 {
            return Ok(ThreadExitMappedMediumLargePagesPostExitAbandonOutcome::Drained(self));
        }

        let (session, state) = self.into_session_and_state();
        let main_heap = session.main_heap_lease();
        let PageAllocatorEngineState {
            arena,
            requested_arena: _,
            page_map: _,
            thread_sequence: _,
            pending_os_release,
            collection_poison,
            #[cfg(test)]
            page_free_collect_failure_once: _,
            #[cfg(test)]
            last_page_to_full: _,
            shutdown_complete: _,
        } = state;
        debug_assert!(pending_os_release.is_none());
        debug_assert!(collection_poison.is_none());
        drop(pending_os_release);
        let _ = collection_poison;

        Ok(ThreadExitMappedMediumLargePagesPostExitAbandonOutcome::Detached(
            ThreadExitMappedMediumLargePagesPostExitDetach {
                session,
                parts: ThreadExitMappedMediumLargePagesPostExitParts {
                    arena,
                    main_heap,
                    remaining_pages: detached_pages,
                    _not_sync: PhantomData,
                },
            },
        ))
    }
}

/// Performs the source queue-detach/unmapped-abandon part for the bounded
/// post-owner-exit full-singleton slice.
///
/// This is private implementation structure rather than a general session
/// operation. Each caller must prove that its source TLS/fast-root transition
/// has made the former Theap unavailable to `mi_free_try_collect_mt`, and that
/// it retains the matching PageMap, arena image, and final-free authority.
///
/// # Safety
///
/// `block` must be the sole current allocation in one active full arena
/// singleton of `engine`. No scoped producer may survive. The caller must use
/// this only after its concrete source thread-exit root transition, so the
/// later [`ThreadExitSingletonHandoff::remote_free_after_failed_reclaim`]
/// cannot reclaim the departed owner.
unsafe fn abandon_full_singleton_after_thread_exit<'arena, 'map, Session: TheapPageSession>(
    mut engine: PageAllocatorEngine<'arena, 'map, Session>,
    block: NonNull<u8>,
) -> Result<
    ThreadExitSingletonHandoff<'arena, 'map, Session>,
    ThreadExitSingletonAbandonFailure<'arena, 'map, Session>,
> {
    let reject = |engine, error| ThreadExitSingletonAbandonFailure::Rejected { engine, error };
    let retained = |engine, error| ThreadExitSingletonAbandonFailure::RetainedEngine {
        engine,
        error,
    };
    if engine.is_collection_poisoned() || engine.pending_os_release.is_some() {
        return Err(reject(engine, ThreadExitSingletonAbandonError::Collection));
    }

    // SAFETY: the consuming engine retains the exclusive PageMap lifecycle
    // that its caller holds through the returned handoff or terminal owner.
    let page = unsafe { engine.page_map.checked_lookup(block.as_ptr()) };
    let Some(page) = NonNull::new(page) else {
        return Err(reject(engine, ThreadExitSingletonAbandonError::Unmapped));
    };
    // SAFETY: the checked PageMap entry keeps this metadata live; no queue or
    // ordinary field mutates until every preflight below completes.
    let page_ref = unsafe { page.as_ref() };
    if !engine.owns_page(page_ref) || page_ref.heap() != engine.session.theap().heap() {
        return Err(reject(engine, ThreadExitSingletonAbandonError::ForeignPage));
    }
    if page_ref.memid().kind() != MemoryKind::Arena {
        return Err(reject(engine, ThreadExitSingletonAbandonError::NonArena));
    }
    if size_class::page_kind_for_block_size(page_ref.block_size()) != Some(PageKind::Singleton)
        || size_class::bin(page_ref.block_size()) != Some(BIN_HUGE)
        || page_ref.reserved() != 1
        || page_ref.used() != 1
        || !page_is_in_full(page_ref)
    {
        return Err(reject(engine, ThreadExitSingletonAbandonError::NotFullSingleton));
    }

    // This vertical slice never skips over another live or all-free page.
    // Source `_mi_theap_collect_abandon` visits every queue before normal TLD
    // teardown; limiting this handoff to the sole page makes its local
    // false-force/queue detach sequence equivalent without claiming a general
    // traversal or ordering policy.
    let mut sole_page = engine.session.theap().page_count() == 1;
    for bin in 0..BIN_COUNT {
        let expected = if bin == BIN_FULL { 1 } else { 0 };
        if !engine
            .session
            .queue(bin)
            .is_some_and(|queue| queue.count() == expected)
        {
            sole_page = false;
            break;
        }
    }
    if sole_page {
        for index in 0..PAGES_DIRECT {
            if engine.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                sole_page = false;
                break;
            }
        }
    }
    if !sole_page {
        return Err(reject(engine, ThreadExitSingletonAbandonError::NotOnlyPage));
    }

    // `release_span` proves every map entry and the full singleton arena
    // geometry before source collection and queue detachment. A leading-slice
    // lookup cannot stand in for the later all-free unregister obligation.
    if !matches!(engine.release_span(page.as_ptr()), Some(ReleaseSpan::Arena { .. })) {
        return Err(reject(engine, ThreadExitSingletonAbandonError::Unmapped));
    }
    if !engine.page_is_active_queue_member(BIN_FULL, page) {
        return Err(reject(engine, ThreadExitSingletonAbandonError::NotActiveFull));
    }
    let Some(canonical_block) = engine.canonical_block_start(page_ref, block) else {
        return Err(reject(engine, ThreadExitSingletonAbandonError::InvalidBlock));
    };
    // SAFETY: the stable singleton's local geometry is exclusively owned by
    // the drain; this temporary projection ends before queue mutation.
    let preflight = match unsafe { LocalFreeList::from_page(&mut *page.as_ptr()) } {
        Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
        Err(error) => Err(error),
    };
    if preflight.is_err() {
        return Err(reject(engine, ThreadExitSingletonAbandonError::InvalidBlock));
    }

    // `_mi_theap_collect_abandon` reaches this full singleton after its force
    // collector; the only-block/live/no-producer proof makes that force-only
    // local append unreachable. `_mi_page_abandon` then performs this exact
    // false collection before it detaches the full-queue member.
    if let Err(error) = engine.page_free_collect_false(page) {
        engine.retain_page_collect_poison(page, error, None);
        return Err(retained(engine, ThreadExitSingletonAbandonError::Collection));
    }
    // SAFETY: collection completed under the exclusive drain while the page
    // remains queue-linked. A different result is terminal rather than a
    // license to choose another source release/reclassification path.
    if unsafe { page.as_ref().used() } != 1 {
        return Err(retained(
            engine,
            ThreadExitSingletonAbandonError::NotFullSingleton,
        ));
    }

    let queue = match engine.session.queue_mut(BIN_FULL) {
        Some(queue) => queue as *mut _,
        None => return Err(retained(engine, ThreadExitSingletonAbandonError::Queue)),
    };
    // SAFETY: preflight proved this exact initialized singleton is the sole
    // linked full-queue member and the drain owns every queue mutation.
    unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
    if !engine.session.note_page_removed() {
        return Err(ThreadExitSingletonAbandonFailure::Terminal {
            handoff: ThreadExitSingletonHandoff {
                engine,
                page,
                terminal: true,
            },
            error: ThreadExitSingletonAbandonError::Queue,
        });
    }

    // A full singleton's high source bin is not eligible for `pages_abandoned`.
    // Consume the associated identity only after queue/count detachment, and
    // leave its atomic low owner bit clear for the exact failed-reclaim free.
    match unsafe { abandoned::abandon_unmappable_after_collect(page) } {
        Ok(AbandonResult::UnownedUnmapped) => Ok(ThreadExitSingletonHandoff {
            engine,
            page,
            terminal: false,
        }),
        Ok(outcome) => Err(ThreadExitSingletonAbandonFailure::Terminal {
            handoff: ThreadExitSingletonHandoff {
                engine,
                page,
                terminal: true,
            },
            error: ThreadExitSingletonAbandonError::UnexpectedAbandonOutcome(outcome),
        }),
        Err(error) => Err(ThreadExitSingletonAbandonFailure::Terminal {
            handoff: ThreadExitSingletonHandoff {
                engine,
                page,
                terminal: true,
            },
            error: ThreadExitSingletonAbandonError::Abandon(error),
        }),
    }
}

/// Performs the source force-collect/queue-detach/mapped-abandon part for one
/// sole, one-live-block medium page at post-owner-exit.
///
/// This remains private implementation structure rather than a general
/// regular-page owner-exit traversal. Its sole-page proof is what makes its
/// one-page force pass source-shaped without asserting an ordering policy for
/// other queues; its one-block proof is what makes the paired final free reach
/// the source empty decision before any reclaim branch.
///
/// # Safety
///
/// `block` must be the sole current allocation in one active medium arena page
/// of `engine`. No scoped producer may survive. The caller must use this only
/// after its concrete source thread-exit root transition and retain the
/// matching PageMap, main-arena bitmap, and final-free authority through the
/// returned handoff or terminal owner.
unsafe fn abandon_mapped_one_block_after_thread_exit<'arena, 'map, Session: TheapPageSession>(
    mut engine: PageAllocatorEngine<'arena, 'map, Session>,
    block: NonNull<u8>,
) -> Result<
    ThreadExitMappedOneBlockHandoff<'arena, 'map, Session>,
    ThreadExitMappedOneBlockAbandonFailure<'arena, 'map, Session>,
> {
    let reject = |engine, error| ThreadExitMappedOneBlockAbandonFailure::Rejected { engine, error };
    let retained = |engine, error| ThreadExitMappedOneBlockAbandonFailure::RetainedEngine {
        engine,
        error,
    };
    if engine.is_collection_poisoned() || engine.pending_os_release.is_some() {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::Collection,
        ));
    }

    // SAFETY: the consuming engine retains the exclusive PageMap lifecycle
    // that its caller holds through the returned handoff or terminal owner.
    let page = unsafe { engine.page_map.checked_lookup(block.as_ptr()) };
    let Some(page) = NonNull::new(page) else {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::Unmapped,
        ));
    };
    // SAFETY: the checked PageMap entry keeps this metadata live; no queue or
    // ordinary field mutates until every preflight below completes.
    let page_ref = unsafe { page.as_ref() };
    if !engine.owns_page(page_ref) || page_ref.heap() != engine.session.theap().heap() {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::ForeignPage,
        ));
    }
    if page_ref.memid().kind() != MemoryKind::Arena {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::NonArena,
        ));
    }
    let Some(bin) = size_class::bin(page_ref.block_size()) else {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::NotMappedOneBlock,
        ));
    };
    if size_class::page_kind_for_block_size(page_ref.block_size()) != Some(PageKind::Medium)
        || page_ref.block_size() <= SMALL_SIZE_MAX
        || bin >= ARENA_BIN_COUNT
        || bin == BIN_FULL
        || page_ref.reserved() <= 1
        || page_ref.used() != 1
        || page_is_in_full(page_ref)
    {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::NotMappedOneBlock,
        ));
    }

    // Source `_mi_theap_collect_abandon` force-collects every queue before it
    // abandons live pages. This narrow handoff can run the target page's exact
    // force then false pass only because it proves every other queue/direct
    // entry is empty; it does not claim a general traversal/release order.
    let mut sole_page = engine.session.theap().page_count() == 1;
    for queue_bin in 0..BIN_COUNT {
        let expected = if queue_bin == bin { 1 } else { 0 };
        if !engine
            .session
            .queue(queue_bin)
            .is_some_and(|queue| queue.count() == expected)
        {
            sole_page = false;
            break;
        }
    }
    if sole_page {
        for index in 0..PAGES_DIRECT {
            if engine.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                sole_page = false;
                break;
            }
        }
    }
    if !sole_page {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::NotOnlyPage,
        ));
    }

    // `release_span` proves every map entry and the regular arena geometry
    // before source collection and queue detachment. The exact main-arena map
    // capability must also exist before the page can cross its bitmap boundary.
    if !matches!(engine.release_span(page.as_ptr()), Some(ReleaseSpan::Arena { .. })) {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::Unmapped,
        ));
    }
    if engine.main_heap_abandoned_page(bin).is_none() {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::MissingMainArenaPages,
        ));
    }
    if !engine.page_is_active_queue_member(bin, page) {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::NotActiveRegular,
        ));
    }
    let Some(canonical_block) = engine.canonical_block_start(page_ref, block) else {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::InvalidBlock,
        ));
    };
    // SAFETY: the stable page's local geometry is exclusively owned by the
    // drain; this temporary projection ends before queue mutation.
    let preflight = match unsafe { LocalFreeList::from_page(&mut *page.as_ptr()) } {
        Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
        Err(error) => Err(error),
    };
    if preflight.is_err() {
        return Err(reject(
            engine,
            ThreadExitMappedOneBlockAbandonError::InvalidBlock,
        ));
    }

    // `_mi_theap_collect_abandon` first runs the force visitor and then
    // `_mi_page_abandon` invokes its false collector. Keep both source phases
    // explicit: a pre-existing joined/local free can turn this page all-free,
    // in which case the handoff must retain the post-fast-slot drain instead
    // of detaching a fictitiously one-live-block page.
    if let Err(error) = engine.page_free_collect_force(page) {
        engine.retain_page_collect_poison(page, error, None);
        return Err(retained(
            engine,
            ThreadExitMappedOneBlockAbandonError::Collection,
        ));
    }
    // SAFETY: force collection completed while the page remains queue-linked
    // under the exclusive drain.
    if unsafe { page.as_ref().used() } != 1 {
        return Err(retained(
            engine,
            ThreadExitMappedOneBlockAbandonError::NotMappedOneBlock,
        ));
    }
    if let Err(error) = engine.page_free_collect_false(page) {
        engine.retain_page_collect_poison(page, error, None);
        return Err(retained(
            engine,
            ThreadExitMappedOneBlockAbandonError::Collection,
        ));
    }
    // SAFETY: false collection completed while the page remains queue-linked;
    // the source handoff admits only the same medium one-block geometry.
    let after_collect = unsafe { page.as_ref() };
    if size_class::page_kind_for_block_size(after_collect.block_size()) != Some(PageKind::Medium)
        || size_class::bin(after_collect.block_size()) != Some(bin)
        || after_collect.block_size() <= SMALL_SIZE_MAX
        || after_collect.reserved() <= 1
        || after_collect.used() != 1
        || page_is_in_full(after_collect)
    {
        return Err(retained(
            engine,
            ThreadExitMappedOneBlockAbandonError::NotMappedOneBlock,
        ));
    }

    let queue = match engine.session.queue_mut(bin) {
        Some(queue) => queue as *mut _,
        None => {
            return Err(retained(
                engine,
                ThreadExitMappedOneBlockAbandonError::Queue,
            ));
        }
    };
    // SAFETY: preflight proved this exact initialized page is the sole linked
    // regular-queue member and the drain owns every queue mutation.
    unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
    if !engine.session.note_page_removed() {
        return Err(ThreadExitMappedOneBlockAbandonFailure::Terminal {
            handoff: ThreadExitMappedOneBlockHandoff {
                engine,
                page,
                bin,
                terminal: true,
            },
            error: ThreadExitMappedOneBlockAbandonError::Queue,
        });
    }
    // This is a no-op for a medium page, but preserves the source queue-remove
    // boundary and keeps any invalid stale direct image from becoming hidden.
    engine.update_direct_cache(bin);

    let abandoned = match engine.main_heap_abandoned_page(bin) {
        Some(map) => {
            // SAFETY: exact source order is force collection, false collection,
            // queue/count detach, then identity/bitmap/unown. The map binds the
            // main arena and bin; `abandon_after_collect` validates its slice.
            unsafe { abandoned::abandon_after_collect(page, Some(&map)) }
        }
        None => {
            return Err(ThreadExitMappedOneBlockAbandonFailure::Terminal {
                handoff: ThreadExitMappedOneBlockHandoff {
                    engine,
                    page,
                    bin,
                    terminal: true,
                },
                error: ThreadExitMappedOneBlockAbandonError::MissingMainArenaPages,
            });
        }
    };
    match abandoned {
        Ok(AbandonResult::UnownedMapped) => Ok(ThreadExitMappedOneBlockHandoff {
            engine,
            page,
            bin,
            terminal: false,
        }),
        Ok(outcome) => Err(ThreadExitMappedOneBlockAbandonFailure::Terminal {
            handoff: ThreadExitMappedOneBlockHandoff {
                engine,
                page,
                bin,
                terminal: true,
            },
            error: ThreadExitMappedOneBlockAbandonError::UnexpectedAbandonOutcome(outcome),
        }),
        Err(error) => Err(ThreadExitMappedOneBlockAbandonFailure::Terminal {
            handoff: ThreadExitMappedOneBlockHandoff {
                engine,
                page,
                bin,
                terminal: true,
            },
            error: ThreadExitMappedOneBlockAbandonError::Abandon(error),
        }),
    }
}

impl<'arena, 'map, Session: TheapPageSession> ThreadExitSingletonHandoff<'arena, 'map, Session> {
    /// Frees the handoff's exact sole client block after the concrete source
    /// thread-exit transition made owner reclamation impossible.
    ///
    /// # Safety
    ///
    /// `block` must be the exact once-live allocation transferred by the
    /// specialized owner-exit handoff. It must not have been freed, republished,
    /// or accessed through any alias after this call.
    pub(crate) unsafe fn remote_free_after_failed_reclaim(
        mut self,
        block: NonNull<u8>,
    ) -> Result<
        PageAllocatorEngine<'arena, 'map, Session>,
        ThreadExitSingletonRemoteFreeFailure<'arena, 'map, Session>,
    > {
        let reject = |handoff, error| ThreadExitSingletonRemoteFreeFailure::Rejected {
            handoff,
            error,
        };
        let terminal = |handoff, error| ThreadExitSingletonRemoteFreeFailure::Terminal {
            handoff,
            error,
        };
        if self.terminal {
            return Err(terminal(self, ThreadExitSingletonRemoteFreeError::Terminal));
        }
        // SAFETY: this linear handoff retains the PageMap lifecycle and exact
        // stable metadata until it either releases or becomes terminal.
        if unsafe { self.engine.page_map.checked_lookup(block.as_ptr()) } != self.page.as_ptr() {
            return Err(reject(self, ThreadExitSingletonRemoteFreeError::Unmapped));
        }
        // SAFETY: the handoff owns this stable initialized page; this observes
        // only its canonical allocation geometry before atomic publication.
        let page_ref = unsafe { self.page.as_ref() };
        let Some(canonical_block) = self.engine.canonical_block_start(page_ref, block) else {
            return Err(reject(self, ThreadExitSingletonRemoteFreeError::InvalidBlock));
        };
        let preflight = match unsafe { LocalFreeList::from_page(&mut *self.page.as_ptr()) } {
            Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
            Err(error) => Err(error),
        };
        if preflight.is_err()
            || !matches!(
                self.engine.release_span(self.page.as_ptr()),
                Some(ReleaseSpan::Arena { .. })
            )
        {
            return Err(reject(self, ThreadExitSingletonRemoteFreeError::InvalidBlock));
        }

        // Construction is private to specialized post-exit drains whose root
        // transition proves `mi_free_try_collect_mt` cannot reclaim the
        // departed Theap. This helper therefore owns only the raw
        // failed-reclaim tail and its all-free terminal release.
        match unsafe { abandoned::free_unmappable_after_failed_reclaim(self.page, canonical_block) } {
            Ok(abandoned::UnmappedAbandonedFreeResult::Empty) => {
                if self
                    .engine
                    .release_queue_detached_abandoned_arena_page(self.page)
                {
                    Ok(self.engine)
                } else {
                    self.terminal = true;
                    Err(terminal(self, ThreadExitSingletonRemoteFreeError::Release))
                }
            }
            Ok(outcome) => {
                self.terminal = true;
                Err(terminal(
                    self,
                    ThreadExitSingletonRemoteFreeError::UnexpectedFreeOutcome(outcome),
                ))
            }
            Err(error) => {
                self.terminal = true;
                Err(terminal(self, ThreadExitSingletonRemoteFreeError::Abandon(error)))
            }
        }
    }
}

impl<'arena, 'map, Session: TheapPageSession>
    ThreadExitMappedOneBlockHandoff<'arena, 'map, Session>
{
    /// Frees the handoff's exact one live block and admits only the source
    /// all-free result, which occurs before `mi_free_try_collect_mt` could
    /// attempt same-owner reclamation.
    ///
    /// # Safety
    ///
    /// `block` must be the exact once-live allocation transferred by the
    /// specialized owner-exit handoff. It must not have been freed,
    /// republished, or accessed through any alias after this call.
    pub(crate) unsafe fn remote_free_to_empty(
        mut self,
        block: NonNull<u8>,
    ) -> Result<
        PageAllocatorEngine<'arena, 'map, Session>,
        ThreadExitMappedOneBlockRemoteFreeFailure<'arena, 'map, Session>,
    > {
        let reject = |handoff, error| ThreadExitMappedOneBlockRemoteFreeFailure::Rejected {
            handoff,
            error,
        };
        let terminal = |handoff, error| ThreadExitMappedOneBlockRemoteFreeFailure::Terminal {
            handoff,
            error,
        };
        if self.terminal {
            return Err(terminal(
                self,
                ThreadExitMappedOneBlockRemoteFreeError::Terminal,
            ));
        }
        // SAFETY: this linear handoff retains the PageMap lifecycle and exact
        // stable metadata until it either releases or becomes terminal.
        if unsafe { self.engine.page_map.checked_lookup(block.as_ptr()) } != self.page.as_ptr() {
            return Err(reject(
                self,
                ThreadExitMappedOneBlockRemoteFreeError::Unmapped,
            ));
        }
        // SAFETY: the handoff owns this stable initialized page; this observes
        // only its canonical allocation geometry before atomic publication.
        let page_ref = unsafe { self.page.as_ref() };
        if self.bin >= ARENA_BIN_COUNT
            || page_ref.memid().kind() != MemoryKind::Arena
            || size_class::page_kind_for_block_size(page_ref.block_size()) != Some(PageKind::Medium)
            || size_class::bin(page_ref.block_size()) != Some(self.bin)
            || page_ref.block_size() <= SMALL_SIZE_MAX
            || page_ref.reserved() <= 1
            || page_ref.used() != 1
            || page_is_in_full(page_ref)
        {
            return Err(reject(
                self,
                ThreadExitMappedOneBlockRemoteFreeError::InvalidBlock,
            ));
        }
        let Some(canonical_block) = self.engine.canonical_block_start(page_ref, block) else {
            return Err(reject(
                self,
                ThreadExitMappedOneBlockRemoteFreeError::InvalidBlock,
            ));
        };
        let preflight = match unsafe { LocalFreeList::from_page(&mut *self.page.as_ptr()) } {
            Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
            Err(error) => Err(error),
        };
        if preflight.is_err()
            || !matches!(
                self.engine.release_span(self.page.as_ptr()),
                Some(ReleaseSpan::Arena { .. })
            )
        {
            return Err(reject(
                self,
                ThreadExitMappedOneBlockRemoteFreeError::InvalidBlock,
            ));
        }
        let Some(map) = self.engine.main_heap_abandoned_page(self.bin) else {
            return Err(reject(
                self,
                ThreadExitMappedOneBlockRemoteFreeError::MissingMainArenaPages,
            ));
        };

        // The sole-medium/one-live-block handoff proves that source collection
        // reaches the empty decision before the mapped-page reclaim branch.
        // This helper therefore cannot return a requeued/reclaimed live page.
        match unsafe { abandoned::free_mapped_one_block_to_empty(self.page, canonical_block, &map) } {
            Ok(abandoned::MappedAbandonedFreeToEmptyResult::Empty) => {
                if self
                    .engine
                    .release_queue_detached_abandoned_arena_page(self.page)
                {
                    Ok(self.engine)
                } else {
                    self.terminal = true;
                    Err(terminal(
                        self,
                        ThreadExitMappedOneBlockRemoteFreeError::Release,
                    ))
                }
            }
            Ok(abandoned::MappedAbandonedFreeToEmptyResult::PublishedToExistingOwner) => {
                self.terminal = true;
                Err(terminal(
                    self,
                    ThreadExitMappedOneBlockRemoteFreeError::ConcurrentOwner,
                ))
            }
            Err(error) => {
                self.terminal = true;
                Err(terminal(
                    self,
                    ThreadExitMappedOneBlockRemoteFreeError::Abandon(error),
                ))
            }
        }
    }
}

impl<'attachment, 'main, 'arena>
    ThreadExitMappedRegularPostExitDetach<'attachment, 'main, 'arena>
{
    /// Tears down the old later Theap/TLD after its one remaining page has
    /// crossed into `parts`. The process PageMap lease remains outside this
    /// transition and must be transferred only after this source owner is
    /// gone.
    pub(crate) fn finish_thread_owner(
        self,
    ) -> Result<
        ThreadExitMappedRegularPostExitParts<'main, 'arena>,
        ThreadExitMappedRegularPostExitTeardownTerminal<'attachment, 'main, 'arena>,
    > {
        let Self { session, parts } = self;
        // SAFETY: the specialized transition that constructed this value
        // proved page count/queues/direct caches empty after source queue
        // detachment, and `parts` carries the sole remaining page authority.
        let attachment = unsafe { session.into_attachment_after_process_page_route() };
        // SAFETY: `parts` is retained through both outcomes below, so no live
        // page can reach the just-detached Theap/TLD after this call.
        match unsafe { attachment.finish_after_detached_process_page_route() } {
            Ok(()) => Ok(parts),
            Err(error) => Err(ThreadExitMappedRegularPostExitTeardownTerminal {
                parts,
                attachment,
                error,
            }),
        }
    }
}

impl<'attachment, 'main, 'arena>
    ThreadExitMappedMediumLargePagesPostExitDetach<'attachment, 'main, 'arena>
{
    /// Tears down the old later Theap/TLD only after every surviving
    /// medium-or-large page has crossed into the typed PageMap/bitmap registry.
    /// The process
    /// map lease remains outside this transition and can become a short route
    /// only after the old source owner is gone.
    pub(crate) fn finish_thread_owner(
        self,
    ) -> Result<
        ThreadExitMappedMediumLargePagesPostExitParts<'main, 'arena>,
        ThreadExitMappedMediumLargePagesPostExitTeardownTerminal<'attachment, 'main, 'arena>,
    > {
        let Self { session, parts } = self;
        // SAFETY: the aggregate traversal proved every old queue/direct/page
        // owner is empty and moved every remaining PageMap registration into
        // `parts`; the attachment can no longer be reached by a route free.
        let attachment = unsafe { session.into_attachment_after_process_page_route() };
        // SAFETY: `parts` survives both outcomes, retaining the full static
        // arena/Heap registry while the former Theap/TLD is removed.
        match unsafe { attachment.finish_after_detached_process_page_route() } {
            Ok(()) => Ok(parts),
            Err(error) => Err(ThreadExitMappedMediumLargePagesPostExitTeardownTerminal {
                parts,
                attachment,
                error,
            }),
        }
    }
}

impl<'main, 'arena> ThreadExitMappedMediumLargePagesPostExitParts<'main, 'arena> {
    /// Handles one source mapped abandoned-page free under one complete short
    /// process PageMap operation.
    ///
    /// # Safety
    ///
    /// `block` must be one exact once-live canonical allocation of a page in
    /// this aggregate route. It must not be freed, transferred, or used by a
    /// concurrent route. The caller must retain the route linearly until this
    /// method reports the last registered page released or an explicit
    /// terminal state is retained.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        &mut self,
        page_map: &PageMap,
        block: NonNull<u8>,
    ) -> Result<
        ThreadExitMappedMediumLargePagesPostExitFreeOutcome,
        ThreadExitMappedMediumLargePagesPostExitFreeError,
    > {
        if self.remaining_pages == 0 {
            return Err(ThreadExitMappedMediumLargePagesPostExitFreeError::Release);
        }
        // SAFETY: the enclosing `ProcessPageMapPostExitAccess` closure keeps
        // the source-plain PageMap entry stable until the raw owner-bit tail
        // and any terminal release below complete. Route membership is the
        // caller's exact client-block obligation; the route contains no raw
        // pointer that could outlive this lookup.
        let page = NonNull::new(unsafe { page_map.checked_lookup(block.as_ptr()) })
            .ok_or(ThreadExitMappedMediumLargePagesPostExitFreeError::Unmapped)?;

        // Hold the static main Heap's short projection for the complete raw
        // tail. The map selector runs only after it has acquired the page's
        // abandoned low owner bit, which is the first legal point to inspect
        // the ordinary memory and size fields needed to choose its bin.
        let mut heap = self
            .main_heap
            .lock_heap()
            .map_err(ThreadExitMappedMediumLargePagesPostExitFreeError::MainHeap)?;
        let result = match unsafe {
            abandoned::free_mapped_after_failed_reclaim_select_map(
                page,
                block,
                |memory, block_size| {
                    let Some(bin) = size_class::bin(block_size) else {
                        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
                    };
                    if !matches!(
                        size_class::page_kind_for_block_size(block_size),
                        Some(PageKind::Medium | PageKind::Large)
                    )
                        || block_size <= SMALL_SIZE_MAX
                        || bin >= ARENA_BIN_COUNT
                        || bin == BIN_FULL
                        || memory.kind() != MemoryKind::Arena
                    {
                        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
                    }
                    self.arena
                        .main_heap_abandoned_page(NonNull::from(heap.heap_mut()), bin)
                        .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                },
            )
        } {
            Ok(abandoned::MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped) => {
                Ok(ThreadExitMappedMediumLargePagesPostExitFreeOutcome::StillLive)
            }
            Ok(abandoned::MappedAbandonedFreeAfterFailedReclaimResult::Empty) => {
                if !unsafe { self.release_empty_page(page_map, page) } {
                    Err(ThreadExitMappedMediumLargePagesPostExitFreeError::Release)
                } else if self.remaining_pages == 1 {
                    self.remaining_pages = 0;
                    Ok(ThreadExitMappedMediumLargePagesPostExitFreeOutcome::ReleasedAll)
                } else {
                    self.remaining_pages -= 1;
                    Ok(ThreadExitMappedMediumLargePagesPostExitFreeOutcome::ReleasedPage)
                }
            }
            Ok(abandoned::MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner) => {
                Err(ThreadExitMappedMediumLargePagesPostExitFreeError::ConcurrentOwner)
            }
            Err(error) => Err(ThreadExitMappedMediumLargePagesPostExitFreeError::Abandon(error)),
        };
        match (result, heap.unlock()) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (_, Err(error)) => Err(ThreadExitMappedMediumLargePagesPostExitFreeError::MainHeap(
                MainStaticHeapLeaseError::Lock(error),
            )),
            (Err(error), Ok(())) => Err(error),
        }
    }

    /// Completes the aggregate route's all-free arena release after the raw
    /// helper has removed the selected page's mapped identity/bit/count while
    /// retaining its low owner bit. Re-derive every span fact under the short
    /// map lock: an aggregate registry intentionally carries no stale page
    /// pointer, bin, or range cache from the departed Theap.
    unsafe fn release_empty_page(&self, page_map: &PageMap, mut page: NonNull<Page>) -> bool {
        // SAFETY: the raw helper returned `Empty`, so this route owns the
        // selected page's low bit and can inspect its ordinary geometry until
        // metadata retirement below completes.
        let page_ref = unsafe { page.as_ref() };
        let memory = page_ref.memid();
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if arena_memory.arena != core::ptr::from_ref(self.arena.arena()).cast_mut() {
            return false;
        }
        let slice_index = arena_memory.slice_index as usize;
        let slice_count = arena_memory.slice_count as usize;
        let Some(size) = slice_count.checked_mul(ARENA_SLICE_SIZE) else {
            return false;
        };
        let Some(slice_start) = self.arena.slice_start(slice_index) else {
            return false;
        };
        let block_size = page_ref.block_size();
        let Some(bin) = size_class::bin(block_size) else {
            return false;
        };
        let kind = match size_class::page_kind_for_block_size(block_size) {
            Some(PageKind::Medium) => PageKind::Medium,
            Some(PageKind::Large) => PageKind::Large,
            _ => return false,
        };
        if block_size <= SMALL_SIZE_MAX
            || bin >= ARENA_BIN_COUNT
            || bin == BIN_FULL
            || page_ref.reserved() <= 1
            || page_ref.used() != 0
            || !page_ref.is_queue_detached()
            || slice_count != page::regular_page_slice_count(kind).unwrap_or(0)
        {
            return false;
        }
        let Some(usable_offset) = page::page_usable_start_offset(block_size) else {
            return false;
        };
        let Some(expected_reserved) = page::reserved_object_count(size, usable_offset, block_size)
        else {
            return false;
        };
        let Some(span_end) = slice_start.addr().checked_add(size) else {
            return false;
        };
        let Some(expected_start) = slice_start.addr().checked_add(usable_offset) else {
            return false;
        };
        if page_ref.reserved() != expected_reserved
            || expected_start >= span_end
            || expected_start.checked_sub(page.as_ptr().addr()) != Some(page_ref.page_offset())
        {
            return false;
        }
        for offset in (0..size).step_by(ARENA_SLICE_SIZE) {
            let Some(address) = slice_start.addr().checked_add(offset) else {
                return false;
            };
            // SAFETY: the complete post-exit map operation excludes ordinary
            // writers. Every registered slice must still name this exact
            // queue-detached page before the source terminal unregister.
            if unsafe { page_map.checked_lookup(address as *const u8) } != page.as_ptr() {
                return false;
            }
        }
        // SAFETY: the full-span check above proves this is precisely the
        // PageMap publication that remains after mapped identity removal.
        if unsafe { page_map.unregister_range(slice_start, size) }.is_err() {
            return false;
        }
        // Preserve source order: PageMap unregister, ordinary main-arena bit
        // clear, metadata retirement, and finally arena-slice release. The
        // ordinary bitmap has one bit at the page's first slice even though a
        // regular medium or large page spans multiple arena slices.
        if unsafe { self.arena.pages() }
            .and_then(|pages| pages.clear_range(slice_index, 1))
            != Some(true)
        {
            return false;
        }
        // SAFETY: source queue/page-count ownership ended before Theap/TLD
        // teardown, and all remaining map/bitmap publications are gone.
        let Some(retired) = (unsafe { page.as_mut().retire_exclusive() }) else {
            return false;
        };
        let Some(retired_memory) = retired.arena_memory() else {
            return false;
        };
        if retired_memory.arena != arena_memory.arena
            || retired_memory.slice_index != arena_memory.slice_index
            || retired_memory.slice_count != arena_memory.slice_count
        {
            return false;
        }
        // SAFETY: the retired memory is the exact external-arena span whose
        // map, ordinary bitmap, and metadata predecessors just completed.
        unsafe { release_arena_slices(retired) }
    }

    #[cfg(test)]
    pub(crate) const fn test_remaining_pages(&self) -> usize {
        self.remaining_pages
    }
}

impl<'main, 'arena> ThreadExitMappedRegularPostExitParts<'main, 'arena> {
    /// Performs the source mapped abandoned-page free tail under one complete
    /// process PageMap operation.
    ///
    /// # Safety
    ///
    /// `block` must be one exact, once-live canonical allocation in this
    /// route's one page. It must not have been freed, transferred to another
    /// route, or used concurrently through a second caller. The route is
    /// deliberately linear in this first slice; general concurrent free
    /// routing and allocation-time claiming remain separate work.
    pub(crate) unsafe fn remote_free_after_thread_exit(
        &self,
        page_map: &PageMap,
        block: NonNull<u8>,
    ) -> Result<
        ThreadExitMappedRegularPostExitFreeOutcome,
        ThreadExitMappedRegularPostExitFreeError,
    > {
        let Some(span_end) = self.slice_start.addr().checked_add(self.size) else {
            return Err(ThreadExitMappedRegularPostExitFreeError::Release);
        };
        if block.as_ptr().addr() < self.slice_start.addr() || block.as_ptr().addr() >= span_end {
            // This address-only span check is safe before the source owner-bit
            // claim and prevents this route from accidentally selecting a
            // distinct page in a concurrently active process map. Exact
            // block liveness remains the unsafe caller obligation below.
            return Err(ThreadExitMappedRegularPostExitFreeError::Unmapped);
        }
        // SAFETY: the caller's exact client-block proof plus this complete
        // PageMap closure keeps the lookup result live for the source atomic
        // abandoned-free transition below.
        let page = NonNull::new(unsafe { page_map.checked_lookup(block.as_ptr()) })
            .ok_or(ThreadExitMappedRegularPostExitFreeError::Unmapped)?;

        // The static main Heap remains process-live even after the departing
        // Theap is gone. Hold its short projection for the exact
        // bitmap/count capability so no bare bitmap can lose the paired
        // `abandoned_count[bin]` mutation.
        let mut heap = self
            .main_heap
            .lock_heap()
            .map_err(ThreadExitMappedRegularPostExitFreeError::MainHeap)?;
        let map = match self
            .arena
            .main_heap_abandoned_page(NonNull::from(heap.heap_mut()), self.bin)
        {
            Some(map) => map,
            None => {
                let unlock = heap.unlock();
                return match unlock {
                    Ok(()) => Err(ThreadExitMappedRegularPostExitFreeError::MissingMainArenaPages),
                    Err(error) => Err(ThreadExitMappedRegularPostExitFreeError::MainHeap(
                        MainStaticHeapLeaseError::Lock(error),
                    )),
                };
            }
        };

        // SAFETY: the caller supplies the canonical client block; `map`
        // binds this route's static-main arena/bin/count pair. The raw helper
        // obtains the abandoned low owner bit before it reads ordinary page
        // fields, so this route never dereferences the departed Theap.
        let result = match unsafe { abandoned::free_mapped_after_failed_reclaim(page, block, &map) } {
            Ok(abandoned::MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped) => {
                Ok(ThreadExitMappedRegularPostExitFreeOutcome::StillLive)
            }
            Ok(abandoned::MappedAbandonedFreeAfterFailedReclaimResult::Empty) => {
                if unsafe { self.release_empty_page(page_map, page) } {
                    Ok(ThreadExitMappedRegularPostExitFreeOutcome::Released)
                } else {
                    Err(ThreadExitMappedRegularPostExitFreeError::Release)
                }
            }
            Ok(abandoned::MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner) => {
                Err(ThreadExitMappedRegularPostExitFreeError::ConcurrentOwner)
            }
            Err(error) => Err(ThreadExitMappedRegularPostExitFreeError::Abandon(error)),
        };
        match (result, heap.unlock()) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (_, Err(error)) => Err(ThreadExitMappedRegularPostExitFreeError::MainHeap(
                MainStaticHeapLeaseError::Lock(error),
            )),
            (Err(error), Ok(())) => Err(error),
        }
    }

    /// Completes the all-free source arena release after the raw helper has
    /// removed the mapped abandoned identity/bit/count and retained the low
    /// owner bit. It repeats the full span check under the current short map
    /// guard rather than trusting a page pointer captured before TLD teardown.
    unsafe fn release_empty_page(&self, page_map: &PageMap, mut page: NonNull<Page>) -> bool {
        let Some(expected_memory) = self.memory.arena_memory() else {
            return false;
        };
        if !core::ptr::eq(
            expected_memory.arena,
            core::ptr::from_ref(self.arena.arena()).cast_mut(),
        ) {
            return false;
        }
        {
            // SAFETY: `free_mapped_after_failed_reclaim` returned `Empty`, so
            // this route holds the page's abandoned low owner bit while it
            // validates and releases the remaining ordinary fields.
            let page_ref = unsafe { page.as_ref() };
            let Some(actual_memory) = page_ref.memid().arena_memory() else {
                return false;
            };
            if actual_memory.arena != expected_memory.arena
                || actual_memory.slice_index != expected_memory.slice_index
                || actual_memory.slice_count != expected_memory.slice_count
                || page_ref.used() != 0
                || !page_ref.is_queue_detached()
            {
                return false;
            }
            for offset in (0..self.size).step_by(ARENA_SLICE_SIZE) {
                let Some(address) = self.slice_start.addr().checked_add(offset) else {
                    return false;
                };
                // SAFETY: this complete post-exit PageMap operation excludes
                // ordinary map writers. Every slice must still name exactly
                // the page whose source identity just became empty.
                if unsafe { page_map.checked_lookup(address as *const u8) } != page.as_ptr() {
                    return false;
                }
            }
        }
        // SAFETY: the preceding full-span check proved that this exact
        // source-plain range remains registered to `page` under the current
        // post-exit map exclusion boundary.
        if unsafe { page_map.unregister_range(self.slice_start, self.size) }.is_err() {
            return false;
        }
        // The ordinary main-arena page bit remains distinct from the mapped
        // abandoned bit cleared by the raw helper. Preserve source order:
        // PageMap unregister, ordinary page-image clear, metadata retirement,
        // then arena-slice return.
        if unsafe { self.arena.pages() }
            .and_then(|pages| pages.clear_range(expected_memory.slice_index as usize, 1))
            != Some(true)
        {
            return false;
        }
        // SAFETY: every queue/direct owner was detached before the old Theap
        // was torn down, the page is empty, and both PageMap/ordinary bitmap
        // publications are gone before source metadata reset.
        let Some(retired) = (unsafe { page.as_mut().retire_exclusive() }) else {
            return false;
        };
        let Some(retired_memory) = retired.arena_memory() else {
            return false;
        };
        if retired_memory.arena != expected_memory.arena
            || retired_memory.slice_index != expected_memory.slice_index
            || retired_memory.slice_count != expected_memory.slice_count
        {
            return false;
        }
        // SAFETY: `retired` is the exact still-outstanding external-arena
        // span whose map, bitmap, and metadata predecessors just completed.
        unsafe { release_arena_slices(retired) }
    }

    #[cfg(test)]
    pub(crate) fn test_abandoned_count(&self) -> Option<usize> {
        let mut heap = self.main_heap.lock_heap().ok()?;
        let count = heap.heap_mut().abandoned_count(self.bin);
        heap.unlock().ok()?;
        count
    }
}

impl<'attach, 'heap, 'arena, 'map>
    DynamicThreadExitDrain<'attach, 'heap, 'arena, 'map>
{
    /// Abandons one exact full arena singleton after the dynamic regular TLS
    /// slot has been cleared for thread exit.
    ///
    /// This is the one owner-exit branch for which the current bounded
    /// lifecycle has both sides of the source handoff: a full singleton cannot
    /// enter `pages_abandoned`, and its later sole remote free must therefore
    /// take `free.c:mi_free_try_collect_mt`'s failed-reclaim all-free tail.
    /// No general page traversal, nonempty owner-exit page, or producer route
    /// is exposed by this drain capability.
    ///
    /// # Safety
    ///
    /// `block` must be the one current canonical allocation in a full
    /// singleton owned by this exact draining engine. No producer may retain
    /// the block or its page, and all client aliases must stay valid only until
    /// the returned handoff consumes this exact block once or is retained
    /// terminally.
    pub(crate) unsafe fn abandon_full_singleton(
        mut self,
        block: NonNull<u8>,
    ) -> Result<
        DynamicThreadExitSingletonHandoff<'attach, 'heap, 'arena, 'map>,
        DynamicThreadExitSingletonAbandonFailure<'attach, 'heap, 'arena, 'map>,
    > {
        let reject = |drain, error| DynamicThreadExitSingletonAbandonFailure::Rejected {
            drain,
            error,
        };
        let retained = |drain, error| DynamicThreadExitSingletonAbandonFailure::RetainedDrain {
            drain,
            error,
        };
        if self.engine.is_collection_poisoned() || self.engine.pending_os_release.is_some() {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::Collection));
        }

        // SAFETY: this drain retains the sole PageMap mutation capability
        // until the returned handoff terminally releases or retains the page.
        let page = unsafe { self.engine.page_map.checked_lookup(block.as_ptr()) };
        let Some(page) = NonNull::new(page) else {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::Unmapped));
        };
        // SAFETY: the checked PageMap entry keeps this page metadata live; no
        // queue or ordinary-field mutation occurs until every preflight below
        // has completed.
        let page_ref = unsafe { page.as_ref() };
        if !self.engine.owns_page(page_ref)
            || page_ref.heap() != self.engine.session.theap().heap()
        {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::ForeignPage));
        }
        if page_ref.memid().kind() != MemoryKind::Arena {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::NonArena));
        }
        if size_class::page_kind_for_block_size(page_ref.block_size()) != Some(PageKind::Singleton)
            || size_class::bin(page_ref.block_size()) != Some(BIN_HUGE)
            || page_ref.reserved() != 1
            || page_ref.used() != 1
            || !page_is_in_full(page_ref)
        {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::NotFullSingleton));
        }
        // `release_span` proves every map entry and singleton arena geometry
        // before source collection and queue detach. A leading-slice lookup is
        // not enough: the eventual all-free path unregisters this full span.
        if !matches!(self.engine.release_span(page.as_ptr()), Some(ReleaseSpan::Arena { .. })) {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::Unmapped));
        }
        if !self.engine.page_is_active_queue_member(BIN_FULL, page) {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::NotActiveFull));
        }
        let Some(canonical_block) = self.engine.canonical_block_start(page_ref, block) else {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::InvalidBlock));
        };
        // SAFETY: this uses only the stable singleton's local geometry while
        // the drain owns its page and no producer can coexist with entry.
        let preflight = match unsafe { LocalFreeList::from_page(&mut *page.as_ptr()) } {
            Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
            Err(error) => Err(error),
        };
        if preflight.is_err() {
            return Err(reject(self, DynamicThreadExitSingletonAbandonError::InvalidBlock));
        }

        // `_mi_theap_collect_abandon` first calls the force collector, then
        // `_mi_page_abandon` calls the false collector immediately before
        // queue removal. This exact one-block full singleton has no local or
        // immediate free list to append while its one client block is live, so
        // the force-only append branch is unreachable; the latter source
        // false collector is the state-changing operation represented here.
        // Any collection failure may already have detached remote state, so
        // retain this drain rather than presenting a retryable pre-detach
        // owner. A future route that admits a page with local free state must
        // port the force collector separately rather than reuse this proof.
        if let Err(error) = self.engine.page_free_collect_false(page) {
            self.engine.retain_page_collect_poison(page, error, None);
            return Err(retained(
                self,
                DynamicThreadExitSingletonAbandonError::Collection,
            ));
        }
        // This bounded route has no producer and begins at a one-block full
        // singleton. A different post-collection state is already beyond the
        // pre-detach contract, so keep the drain rather than guessing whether
        // it can be released or reclassified.
        if unsafe { page.as_ref().used() } != 1 {
            return Err(retained(
                self,
                DynamicThreadExitSingletonAbandonError::NotFullSingleton,
            ));
        }

        let queue = match self.engine.session.queue_mut(BIN_FULL) {
            Some(queue) => queue as *mut _,
            None => {
                return Err(retained(
                    self,
                    DynamicThreadExitSingletonAbandonError::Queue,
                ));
            }
        };
        // SAFETY: preflight proved this exact initialized singleton is linked
        // in the complete full queue; the drain exclusively owns its links.
        unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
        if !self.engine.session.note_page_removed() {
            return Err(DynamicThreadExitSingletonAbandonFailure::Terminal {
                handoff: DynamicThreadExitSingletonHandoff {
                    drain: self,
                    page,
                    terminal: true,
                },
                error: DynamicThreadExitSingletonAbandonError::Queue,
            });
        }

        // The high singleton bin is not eligible for arena bitmap mapping.
        // This consumes the source associated identity only after queue/count
        // removal and leaves its low atomic owner bit clear for the later
        // failed-reclaim free to claim.
        let abandoned = unsafe { abandoned::abandon_unmappable_after_collect(page) };
        match abandoned {
            Ok(AbandonResult::UnownedUnmapped) => Ok(DynamicThreadExitSingletonHandoff {
                drain: self,
                page,
                terminal: false,
            }),
            Ok(outcome) => Err(DynamicThreadExitSingletonAbandonFailure::Terminal {
                handoff: DynamicThreadExitSingletonHandoff {
                    drain: self,
                    page,
                    terminal: true,
                },
                error: DynamicThreadExitSingletonAbandonError::UnexpectedAbandonOutcome(outcome),
            }),
            Err(error) => Err(DynamicThreadExitSingletonAbandonFailure::Terminal {
                handoff: DynamicThreadExitSingletonHandoff {
                    drain: self,
                    page,
                    terminal: true,
                },
                error: DynamicThreadExitSingletonAbandonError::Abandon(error),
            }),
        }
    }

    /// Force-collects post-TLS retired pages, then finishes the page-drain
    /// owner only after its source queues, direct caches, and page count are
    /// empty. The attachment remains in its `DrainingPages` state until this
    /// wrapper drops; the fixture or future thread-exit coordinator then
    /// performs the separate root/list teardown.
    pub(crate) fn finish(self) -> bool {
        match self.engine.finish() {
            Ok(()) => true,
            Err(engine) => {
                drop(engine);
                false
            }
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_dynamic_regular_slot_is_clear(&self) -> bool {
        self.engine.session.test_dynamic_regular_slot_is_clear()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_cached_root_still_names_the_draining_theap(&self) -> bool {
        self.engine
            .session
            .test_cached_root_still_names_the_draining_theap()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_page_count(&self) -> usize {
        self.engine.session.theap().page_count()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) unsafe fn test_page_for_block(&self, block: NonNull<u8>) -> *mut Page {
        // SAFETY: this is a read-only test witness while the drain owns the
        // page map and no raw page lifetime escapes it.
        unsafe { self.engine.page_for_block(block) }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_dynamic_arena_page_is_clear(&self, memory: MemoryId) -> bool {
        self.engine.session.test_dynamic_arena_page_is_clear(memory)
    }
}

impl<'attach, 'heap, 'arena, 'map>
    DynamicThreadExitSingletonHandoff<'attach, 'heap, 'arena, 'map>
{
    /// Frees the singleton's one client block after source owner exit made
    /// reclamation impossible by clearing the dynamic regular TLS slot.
    ///
    /// The handoff cannot route a nonempty page back into normal allocation:
    /// that needs the broader abandoned-owner lifecycle. For this one-block
    /// singleton, the source collector must make the page all-free and the
    /// handoff owns the exact PageMap/arena-image release capability.
    ///
    /// # Safety
    ///
    /// `block` must be the exact once-live client allocation transferred by
    /// [`DynamicThreadExitDrain::abandon_full_singleton`]. It must not have
    /// been freed, republished, or accessed through any alias after this call.
    pub(crate) unsafe fn remote_free_after_failed_reclaim(
        mut self,
        block: NonNull<u8>,
    ) -> Result<
        DynamicThreadExitDrain<'attach, 'heap, 'arena, 'map>,
        DynamicThreadExitSingletonRemoteFreeFailure<'attach, 'heap, 'arena, 'map>,
    > {
        let reject = |handoff, error| DynamicThreadExitSingletonRemoteFreeFailure::Rejected {
            handoff,
            error,
        };
        let terminal = |handoff, error| DynamicThreadExitSingletonRemoteFreeFailure::Terminal {
            handoff,
            error,
        };
        if self.terminal {
            return Err(terminal(self, DynamicThreadExitSingletonRemoteFreeError::Terminal));
        }
        // SAFETY: the handoff retains the only PageMap owner for this
        // abandoned page. Verify that the caller did not present a different
        // mapping before its atomic free can claim abandoned ownership.
        if unsafe { self.drain.engine.page_map.checked_lookup(block.as_ptr()) } != self.page.as_ptr() {
            return Err(reject(self, DynamicThreadExitSingletonRemoteFreeError::Unmapped));
        }
        // SAFETY: the handoff keeps the stable source metadata alive and this
        // preflight observes only its allocation geometry.
        let page_ref = unsafe { self.page.as_ref() };
        let Some(canonical_block) = self.drain.engine.canonical_block_start(page_ref, block) else {
            return Err(reject(self, DynamicThreadExitSingletonRemoteFreeError::InvalidBlock));
        };
        let preflight = match unsafe { LocalFreeList::from_page(&mut *self.page.as_ptr()) } {
            Ok(free_list) => free_list.validate_local_free_preflight(canonical_block),
            Err(error) => Err(error),
        };
        if preflight.is_err()
            || !matches!(
                self.drain.engine.release_span(self.page.as_ptr()),
                Some(ReleaseSpan::Arena { .. })
            )
        {
            return Err(reject(self, DynamicThreadExitSingletonRemoteFreeError::InvalidBlock));
        }

        // `DynamicTheapPageDrainSession` is constructible only after
        // `begin_page_drain` clears the associated dynamic regular TLS slot.
        // That is the concrete source proof that the one reclaim attempt in
        // `mi_free_try_collect_mt` fails before this helper's raw tail.
        let result = unsafe {
            abandoned::free_unmappable_after_failed_reclaim(self.page, canonical_block)
        };
        match result {
            Ok(abandoned::UnmappedAbandonedFreeResult::Empty) => {
                if self
                    .drain
                    .engine
                    .release_queue_detached_abandoned_arena_page(self.page)
                {
                    Ok(self.drain)
                } else {
                    self.terminal = true;
                    Err(terminal(
                        self,
                        DynamicThreadExitSingletonRemoteFreeError::Release,
                    ))
                }
            }
            Ok(outcome) => {
                self.terminal = true;
                Err(terminal(
                    self,
                    DynamicThreadExitSingletonRemoteFreeError::UnexpectedFreeOutcome(outcome),
                ))
            }
            Err(error) => {
                self.terminal = true;
                Err(terminal(
                    self,
                    DynamicThreadExitSingletonRemoteFreeError::Abandon(error),
                ))
            }
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_page_count(&self) -> usize {
        self.drain.engine.session.theap().page_count()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_dynamic_regular_slot_is_clear(&self) -> bool {
        self.drain.engine.session.test_dynamic_regular_slot_is_clear()
    }
}

impl<'attach, 'heap, 'arena, 'map>
    DynamicMappedPageHandoff<'attach, 'heap, 'arena, 'map>
{
    /// Frees one still-live client block through the source mapped-abandoned
    /// `allow_collect=true` path and restores this exact page to its original
    /// dynamic Theap when the frozen same-origin reclaim rule accepts it.
    ///
    /// This is deliberately narrower than general abandoned free routing.
    /// The handoff owns the only engine/session/page-map/arena-image mutation
    /// capability, so it can prove the current Theap is the page's original
    /// live owner and uses the pinned default `page_reclaim_on_free = 0` /
    /// unlimited same-origin queue-reclaim profile. A concurrent producer
    /// that already owns the abandoned page remains terminal. An all-free
    /// result instead has the exact queue-detached arena release authority
    /// retained by this handoff and follows the source terminal order.
    ///
    /// # Safety
    ///
    /// `block` must be one current, exactly-once client allocation from this
    /// handoff's exact mapped page. It must not have been freed, transferred
    /// to another producer, or accessed after this call. The caller must keep
    /// all page metadata and the still-live allocations of that page stable
    /// for the result's complete lifecycle.
    pub(crate) unsafe fn remote_free_and_reclaim(
        mut self,
        block: NonNull<u8>,
    ) -> Result<
        DynamicTheapAllocator<'attach, 'heap, 'arena, 'map>,
        DynamicMappedRemoteFreeFailure<'attach, 'heap, 'arena, 'map>,
    > {
        let reject = |handoff, error| DynamicMappedRemoteFreeFailure::Rejected {
            handoff,
            error,
        };
        let terminal = |handoff, error| DynamicMappedRemoteFreeFailure::Terminal {
            handoff,
            error,
        };
        if self.terminal {
            return Err(terminal(self, DynamicMappedRemoteFreeError::Terminal));
        }
        let Some(target_thread) = self.engine.session.thread_id() else {
            self.terminal = true;
            return Err(terminal(self, DynamicMappedRemoteFreeError::Terminal));
        };
        if !self.engine.session.theap().allows_page_reclaim() {
            return Err(reject(self, DynamicMappedRemoteFreeError::ReclaimDisabled));
        }
        let canonical_block = {
            // SAFETY: the handoff retains the source page registration and
            // metadata; this preflight only recovers an aligned block base.
            let page = unsafe { self.page.as_ref() };
            match self.engine.canonical_block_start(page, block) {
                Some(block) => block,
                None => return Err(reject(self, DynamicMappedRemoteFreeError::InvalidBlock)),
            }
        };
        let target_theap = NonNull::from(self.engine.session.theap());
        let result = {
            let Some(map) = self.engine.session.mapped_abandoned_page(
                &self.engine.arena,
                self.bin,
                self.memory,
            ) else {
                return Err(reject(
                    self,
                    DynamicMappedRemoteFreeError::MissingDynamicArenaPages,
                ));
            };
            // SAFETY: this token retains the exact mapped-abandoned page,
            // map bit/count image, original live Theap, and client-block
            // ownership required by the source allow-collect transition.
            unsafe {
                abandoned::free_mapped_and_reclaim(
                    self.page,
                    canonical_block,
                    &map,
                    target_theap,
                    target_thread,
                )
            }
        };
        match result {
            Ok(abandoned::MappedAbandonedFreeResult::Reclaimed { .. }) => {
                if !self.requeue_reclaimed() {
                    self.terminal = true;
                    return Err(terminal(self, DynamicMappedRemoteFreeError::Queue));
                }
                Ok(self.engine)
            }
            Ok(abandoned::MappedAbandonedFreeResult::PublishedToExistingOwner) => {
                self.terminal = true;
                Err(terminal(self, DynamicMappedRemoteFreeError::ConcurrentOwner))
            }
            Ok(abandoned::MappedAbandonedFreeResult::Empty) => {
                if self
                    .engine
                    .release_queue_detached_abandoned_arena_page(self.page)
                {
                    Ok(self.engine)
                } else {
                    self.terminal = true;
                    Err(terminal(self, DynamicMappedRemoteFreeError::Release))
                }
            }
            Err(error) => {
                self.terminal = true;
                Err(terminal(self, DynamicMappedRemoteFreeError::Abandon(error)))
            }
        }
    }

    /// Reclaims this exact dynamic mapped page into the same pinned Theap and
    /// appends it to its original regular queue. It consumes the token so
    /// normal engine access becomes available only after source reassociation,
    /// second live-owner collection, queue insertion, direct-cache update,
    /// and page-count restoration have all completed.
    pub(crate) fn adopt(
        mut self,
    ) -> Result<
        DynamicTheapAllocator<'attach, 'heap, 'arena, 'map>,
        DynamicMappedAdoptFailure<'attach, 'heap, 'arena, 'map>,
    > {
        if self.terminal {
            return Err(DynamicMappedAdoptFailure::Terminal(self));
        }
        let target_theap = NonNull::from(self.engine.session.theap());
        let Some(target_thread) = self.engine.session.thread_id() else {
            self.terminal = true;
            return Err(DynamicMappedAdoptFailure::Terminal(self));
        };
        let expected_slice = match self.memory.arena_memory() {
            Some(memory) => memory.slice_index as usize,
            None => {
                self.terminal = true;
                return Err(DynamicMappedAdoptFailure::Terminal(self));
            }
        };
        let result = {
            let Some(map) = self.engine.session.mapped_abandoned_page(
                &self.engine.arena,
                self.bin,
                self.memory,
            ) else {
                self.terminal = true;
                return Err(DynamicMappedAdoptFailure::Terminal(self));
            };
            let arena = &self.engine.arena;
            let page_map = self.engine.page_map;
            // SAFETY: the token owns the entire engine, so the source page,
            // arena image, PageMap entry, and target Theap remain live. The
            // purpose-bound map restricts bitmap claim to this exact slice.
            unsafe {
                abandoned::try_adopt_retained(
                    &map,
                    self.engine.thread_sequence,
                    target_theap,
                    target_thread,
                    |slice_index| {
                        if slice_index != expected_slice {
                            return None;
                        }
                        let start = arena.slice_start(slice_index)?;
                        let resolved = NonNull::new(page_map.checked_lookup(start))?;
                        // A bitmap bit can name only this token's stable
                        // page. Reject before the source low-owner claim; a
                        // foreign map entry must remain untouched.
                        (resolved == self.page).then_some(resolved)
                    },
                )
            }
        };
        match result {
            Ok(Some(adopted)) if adopted.page() == self.page => {}
            Ok(None) => return Err(DynamicMappedAdoptFailure::Pending(self)),
            Ok(Some(_)) => {
                self.terminal = true;
                return Err(DynamicMappedAdoptFailure::Terminal(self));
            }
            Err(retained) => {
                self.terminal = true;
                return Err(DynamicMappedAdoptFailure::Claimed {
                    handoff: self,
                    retained,
                });
            }
        }
        if !self.requeue_reclaimed() {
            self.terminal = true;
            return Err(DynamicMappedAdoptFailure::Terminal(self));
        }
        Ok(self.engine)
    }

    /// Appends an already reassociated page and restores the exact Theap
    /// queue/count/direct-cache state shared by same-owner adoption and its
    /// mapped remote-free reclaim branch.
    fn requeue_reclaimed(&mut self) -> bool {
        let Some(queue) = self.engine.session.queue_mut(self.bin) else {
            return false;
        };
        // SAFETY: the caller has completed the source reassociation for this
        // exact detached page, and this linear handoff retains sole queue
        // mutation authority.
        unsafe { page_queue_push_at_end_metadata(queue, self.page.as_ptr()) };
        self.engine.session.note_page_added();
        self.engine.update_direct_cache(self.bin);
        true
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn page(&self) -> NonNull<Page> { self.page }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_page_count(&self) -> usize {
        self.engine.session.theap().page_count()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_abandoned_count(&self) -> Option<usize> {
        let heap = self.engine.session.theap().heap();
        // SAFETY: the token owns the complete engine/session and preserves
        // its caller-pinned Heap until it is adopted or terminally retained.
        unsafe { heap.as_ref() }?.abandoned_count(self.bin)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_bin(&self) -> usize { self.bin }

    #[cfg(test)]
    pub(crate) fn test_dynamic_abandoned_page_is_set(&self) -> bool {
        let Some(slice) = self.memory.arena_memory().map(|memory| memory.slice_index as usize) else {
            return false;
        };
        self.engine
            .session
            .mapped_abandoned_page(&self.engine.arena, self.bin, self.memory)
            .is_some_and(|map| !crate::abandoned::MappedAbandonedPages::is_clear(&map, slice))
    }

    #[cfg(test)]
    pub(crate) fn test_main_arena_page_is_clear(&self) -> bool {
        let Some(memory) = self.memory.arena_memory() else {
            return false;
        };
        // SAFETY: token ownership retains its registry-published arena view;
        // this is a read-only disjointness witness.
        unsafe { self.engine.arena.pages() }
            .and_then(|pages| pages.is_clear_range(memory.slice_index as usize, 1))
            == Some(true)
    }
}

impl<'arena, 'map, Session: TheapPageSession> PageAllocatorEngine<'arena, 'map, Session> {

    /// Consumes this Drop-bearing engine without running its conservative
    /// unfinished-engine latch, returning its unique typed session separately
    /// from the PageMap/arena state. Callers must immediately reassemble one
    /// engine (possibly with a different session type) or retain both parts.
    fn into_session_and_state(self) -> (Session, PageAllocatorEngineState<'arena, 'map>) {
        let this = ManuallyDrop::new(self);
        let this_ptr = (&this as *const ManuallyDrop<Self>).cast::<Self>();
        // SAFETY: `this` suppresses `Drop`; every field is moved exactly once
        // into the returned session/state pair and no reference escapes this
        // method. The caller retains the obligation to reassemble or retain
        // those exact capabilities before either can be dropped.
        unsafe {
            (
                core::ptr::read(core::ptr::addr_of!((*this_ptr).session)),
                PageAllocatorEngineState {
                    arena: core::ptr::read(core::ptr::addr_of!((*this_ptr).arena)),
                    requested_arena: core::ptr::read(core::ptr::addr_of!((*this_ptr).requested_arena)),
                    page_map: core::ptr::read(core::ptr::addr_of!((*this_ptr).page_map)),
                    thread_sequence: core::ptr::read(core::ptr::addr_of!((*this_ptr).thread_sequence)),
                    pending_os_release: core::ptr::read(core::ptr::addr_of!((*this_ptr).pending_os_release)),
                    collection_poison: core::ptr::read(core::ptr::addr_of!((*this_ptr).collection_poison)),
                    #[cfg(test)]
                    page_free_collect_failure_once: core::ptr::read(core::ptr::addr_of!((*this_ptr).page_free_collect_failure_once)),
                    #[cfg(test)]
                    last_page_to_full: core::ptr::read(core::ptr::addr_of!((*this_ptr).last_page_to_full)),
                    shutdown_complete: core::ptr::read(core::ptr::addr_of!((*this_ptr).shutdown_complete)),
                },
            )
        }
    }

    /// Reassembles one engine from the unique state produced by
    /// [`Self::into_session_and_state`]. This is intentionally the only way
    /// the thread-exit conversion changes a typed session owner.
    fn from_session_and_state<NewSession: TheapPageSession>(
        session: NewSession,
        state: PageAllocatorEngineState<'arena, 'map>,
    ) -> PageAllocatorEngine<'arena, 'map, NewSession> {
        PageAllocatorEngine {
            session,
            arena: state.arena,
            requested_arena: state.requested_arena,
            page_map: state.page_map,
            thread_sequence: state.thread_sequence,
            pending_os_release: state.pending_os_release,
            collection_poison: state.collection_poison,
            #[cfg(test)]
            page_free_collect_failure_once: state.page_free_collect_failure_once,
            #[cfg(test)]
            last_page_to_full: state.last_page_to_full,
            shutdown_complete: state.shutdown_complete,
        }
    }

    /// Returns the stable source `page->theap` identity of this exclusive
    /// lifecycle. The detached metadata wrapper uses it only for the exact
    /// `_mi_meta_is_meta_page` pointer comparison; it never dereferences an
    /// abandoned page's origin pointer.
    #[inline]
    pub(crate) fn theap_identity(&self) -> *mut Theap {
        self.session.theap() as *const Theap as *mut Theap
    }

    /// Explicitly quiesces this bounded page lifecycle. A successful finish
    /// force-collects releases, leaves no direct/queue/page state, no retained
    /// poison, and no pending OS release; only then may a dynamic attachment
    /// outlive the engine and proceed to its own source teardown.
    pub(crate) fn finish(mut self) -> Result<(), Self> {
        if self.is_collection_poisoned() || self.pending_os_release.is_some() {
            return Err(self);
        }
        if !self.collect_retired(true)
            || self.is_collection_poisoned()
            || self.pending_os_release.is_some()
            || self.session.theap().page_count() != 0
        {
            return Err(self);
        }
        for bin in 0..BIN_COUNT {
            if !self.session.queue(bin).is_some_and(|queue| queue.count() == 0) {
                return Err(self);
            }
        }
        for index in 0..PAGES_DIRECT {
            if self.session.direct_page(index) != Some(EMPTY_PAGE.as_ptr()) {
                return Err(self);
            }
        }
        self.shutdown_complete = true;
        Ok(())
    }

    /// Looks up one current page while the caller holds this lifecycle's
    /// external exclusion. The detached metadata owner uses this only in a
    /// focused identity regression; no raw page lifetime escapes the lock.
    #[cfg(test)]
    #[inline]
    pub(crate) unsafe fn page_for_block(&self, block: NonNull<u8>) -> *mut Page {
        unsafe { self.page_map.checked_lookup(block.as_ptr()) }
    }

    /// Allocates one normal-release ordinary block, optionally clearing its
    /// full source block size.
    ///
    /// Requests through `MI_SMALL_SIZE_MAX` retain the direct-cache path.
    /// Other valid requests follow `mi_find_page`: ordinary queue bins use the
    /// frozen `mi_good_size` result, while the huge bin uses
    /// `_mi_os_good_alloc_size` and a one-block singleton page. Aligned and
    /// interior-pointer allocation remain a separate lifecycle slice.
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        if self.is_collection_poisoned() {
            return None;
        }
        // `mi_malloc_generic` normalizes a C zero request to one word before
        // entering the ordinary size-class machinery. The returned block is
        // distinct and freeable even though callers may not dereference it.
        let request = request.max(WORD_SIZE);
        if !size_class::request_size_is_valid(request) {
            return None;
        }

        if request <= SMALL_SIZE_MAX {
            return self.allocate_small_direct(request, zero);
        }

        self.allocate_generic(request, zero)
    }

    fn allocate_small_direct(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        let bin = size_class::bin(request)?;
        let direct_index = invariants::word_count(request)?;
        if direct_index >= PAGES_DIRECT {
            return None;
        }

        loop {
            let direct = self.session.direct_page(direct_index)?;
            if direct == EMPTY_PAGE.as_ptr() {
                let block_size = size_class::bin_size(bin)?;
                let page = self.allocate_fresh_page(block_size, PageKind::Small)?;
                self.push_regular_page(bin, page);
                continue;
            }

            let page = NonNull::new(direct)?;
            match self.pop_immediate_local(page, zero) {
                Ok(Some(block)) => return Some(block),
                Ok(None) => {
                    // `mi_page_malloc_zero` falls through to generic search
                    // when this immediate-list-only direct lookup misses.
                    // That scan first performs `_mi_page_free_collect(false)`
                    // before it could extend or classify this page full, so a
                    // joined remote publication is reusable in source order.
                    let block_size = size_class::bin_size(bin)?;
                    return self.allocate_generic_with_retry(
                        bin,
                        block_size,
                        PageKind::Small,
                        zero,
                    );
                }
                Err(_) => return None,
            }
        }
    }

    /// The no-direct-cache half of `mi_find_page` plus
    /// `mi_malloc_generic_fallback`. A failed fresh claim is retried once
    /// after forced retired-page collection, exactly at the generic OOM
    /// boundary; a non-huge queue is otherwise searched by its source bin.
    fn allocate_generic(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        let bin = size_class::bin(request)?;
        if bin == BIN_HUGE {
            let block_size = self.page_map.memory_config().good_alloc_size(request);
            if block_size == 0 || block_size < request {
                return None;
            }
            return self.allocate_generic_with_retry(bin, block_size, PageKind::Singleton, zero);
        }

        let page_size = self.page_map.memory_config().page_size().bytes();
        let block_size = size_class::good_size(request, page_size)?;
        if size_class::bin(block_size)? != bin {
            return None;
        }
        let kind = size_class::page_kind_for_block_size(block_size)?;
        if kind == PageKind::Singleton {
            return None;
        }
        self.allocate_generic_with_retry(bin, block_size, kind, zero)
    }

    fn allocate_generic_with_retry(
        &mut self,
        bin: usize,
        block_size: usize,
        kind: PageKind,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        for attempt in 0..2 {
            match self.allocate_generic_once(bin, block_size, kind, zero) {
                Ok(Some(block)) => return Some(block),
                // Only the source no-page/OOM result may force collection
                // and retry. A collection/list/queue error can have crossed
                // a private ownership boundary and must not take fallback.
                Err(_) => return None,
                Ok(None) => {}
            }
            if attempt == 0 && !self.collect_retired(true) {
                return None;
            }
        }
        None
    }

    fn allocate_generic_once(
        &mut self,
        bin: usize,
        block_size: usize,
        kind: PageKind,
        zero: bool,
    ) -> Result<Option<NonNull<u8>>, GenericPathError> {
        // Huge pages contain exactly one block and are never candidates for
        // queue reuse. The fresh page enters the huge queue only long enough
        // for the source full-page transition below.
        if bin == BIN_HUGE {
            let Some(page) = self.allocate_fresh_page(block_size, kind) else {
                return Ok(None);
            };
            self.push_regular_page(bin, page);
            let block = self
                .pop_or_extend(page, zero)
                .map_err(GenericPathError::Local)?
                .ok_or(GenericPathError::Lifecycle)?;
            self.move_regular_to_full(bin, page.as_ptr(), Some(block))
                .map_err(GenericPathError::from)?;
            return Ok(Some(block));
        }

        let Some(page) = self.find_generic_queue_page(bin, block_size, kind)? else {
            return Ok(None);
        };
        match self.pop_or_extend(page, zero) {
            Ok(Some(block)) => {
                // `mi_malloc_generic_fallback` moves a full medium, large,
                // or singleton page immediately. Small pages use the source
                // retain-count path while a later queue scan considers them.
                let full = unsafe {
                    let page = page.as_ref();
                    page.used() == page.reserved() as usize
                };
                if block_size > SMALL_MAX_OBJ_SIZE && full {
                    self.move_regular_to_full(bin, page.as_ptr(), Some(block))
                        .map_err(GenericPathError::from)?;
                }
                Ok(Some(block))
            }
            // `find_generic_queue_page` returns only a source-immediately-
            // available page. A contrary result is a local-list invariant
            // failure, not a reason to select a different page or retry OOM.
            Ok(None) => Err(GenericPathError::Lifecycle),
            Err(error) => Err(GenericPathError::Local(error)),
        }
    }

    /// Ports `mi_page_queue_lookup_free_first` and
    /// `mi_page_queue_find_free_ex` for an ordinary queue. In particular it
    /// retains up to the pinned `page_full_retain` small full pages, searches
    /// up to the pinned candidate limit for a fuller reusable page, releases
    /// an all-free previous candidate, and moves the final candidate to the
    /// queue head. The regular fresh-page fallback performs the source's
    /// non-forced retired-page collection before it claims a span.
    fn find_generic_queue_page(
        &mut self,
        bin: usize,
        block_size: usize,
        kind: PageKind,
    ) -> Result<Option<NonNull<Page>>, GenericPathError> {
        let first = self
            .session
            .queue(bin)
            .ok_or(GenericPathError::Lifecycle)?
            .first();
        if let Some(first) = NonNull::new(first) {
            match self.page_quick_collect(first) {
                Ok(true) => {
                    // `mi_page_queue_lookup_free_first` leaves its head in
                    // place and clears retirement only after choosing it.
                    let page = unsafe { first.as_ptr().as_mut() }
                        .ok_or(GenericPathError::Lifecycle)?;
                    page.set_retire_expire(0);
                    return Ok(Some(first));
                }
                Ok(false) => {}
                Err(error) => return Err(GenericPathError::Local(error)),
            }
        }

        let mut page = first;
        let mut candidate: *mut Page = core::ptr::null_mut();
        let mut candidate_limit = 0isize;
        let mut page_full_retain = if block_size > SMALL_MAX_OBJ_SIZE {
            0
        } else {
            self.session.theap().page_full_retain()
        };

        while !page.is_null() {
            // SAFETY: `page` is a current queue member. Save its successor
            // before a source transition can move either current or an older
            // candidate to the full queue or release that candidate.
            let next = unsafe { (*page).next() };
            candidate_limit -= 1;
            let page_nonnull = match NonNull::new(page) {
                Some(page) => page,
                None => return Err(GenericPathError::Lifecycle),
            };
            // Unlike the separate head fast path above, the source candidate
            // scan only observes the immediate `free` head here. It must not
            // move an existing `local_free` before the false-force operation
            // has first detached the producer-owned remote list.
            let mut immediate_available = unsafe { !(*page).free_list_head().is_null() };
            if !immediate_available {
                // `mi_page_queue_find_free_ex` performs full false-force
                // collection before deciding this regular page is full or
                // expandable. `page_quick_collect` stays local-only above;
                // this is the exact remote detach then local transfer path.
                if let Err(error) = self.page_free_collect_false(page_nonnull) {
                    self.retain_page_collect_poison(page_nonnull, error, None);
                    return Err(GenericPathError::Collection(error));
                }
                immediate_available = unsafe { !(*page).free_list_head().is_null() };
            }
            // SAFETY: this source-plain lifecycle has exclusive queue/page
            // ownership for the duration of the candidate scan.
            let expandable = unsafe { (*page).capacity() < (*page).reserved() };

            if !immediate_available && !expandable {
                page_full_retain -= 1;
                if page_full_retain < 0 {
                    self.move_regular_to_full(bin, page, None)
                        .map_err(GenericPathError::from)?;
                }
            } else {
                if candidate.is_null() {
                    candidate = page;
                    candidate_limit = PAGE_MAX_CANDIDATES;
                } else {
                    // SAFETY: candidate remains queue-linked until either the
                    // explicit all-free release below or its final move.
                    let candidate_is_all_free = unsafe { (*candidate).used() == 0 };
                    if candidate_is_all_free {
                        if !self.release_page(bin, candidate) {
                            return Err(GenericPathError::Lifecycle);
                        }
                        candidate = page;
                    } else {
                        // `mi_page_is_mostly_used`: avoid preferring a page
                        // whose remaining capacity is within its final eighth.
                        let page_reserved = unsafe { (*page).reserved() as usize };
                        let page_used = unsafe { (*page).used() };
                        let mostly_used = page_reserved
                            .checked_sub(page_used)
                            .map(|free| free <= page_reserved / 8)
                            .unwrap_or(true);
                        if page_used >= unsafe { (*candidate).used() } && !mostly_used {
                            candidate = page;
                        }
                    }
                }
                if immediate_available || candidate_limit <= 0 {
                    break;
                }
            }
            page = next;
        }

        if let Some(candidate) = NonNull::new(candidate) {
            match self.page_make_immediate(candidate) {
                Ok(true) => {}
                Ok(false) => return Err(GenericPathError::Lifecycle),
                Err(error) => return Err(GenericPathError::Local(error)),
            }
            let queue = self
                .session
                .queue_mut(bin)
                .ok_or(GenericPathError::Lifecycle)? as *mut _;
            // SAFETY: the candidate remains a member of this exclusively
            // owned regular queue; moving it changes no page-count state.
            unsafe { page_queue_move_to_front_metadata(&mut *queue, candidate.as_ptr()) };
            self.update_direct_cache(bin);
            // SAFETY: choosing this valid live candidate mirrors the source
            // post-search retirement reset.
            let page = unsafe { candidate.as_ptr().as_mut() }
                .ok_or(GenericPathError::Lifecycle)?;
            page.set_retire_expire(0);
            return Ok(Some(candidate));
        }

        if !self.collect_retired(false) {
            return Err(GenericPathError::Lifecycle);
        }
        let Some(fresh) = self.allocate_fresh_page(block_size, kind) else {
            return Ok(None);
        };
        self.push_regular_page(bin, fresh);
        Ok(Some(fresh))
    }

    /// Performs the source's local-only `mi_page_free_quick_collect` without
    /// extending capacity. Queue candidate search uses this first to decide
    /// whether a page has an immediately reusable block.
    fn page_quick_collect(&mut self, page: NonNull<Page>) -> Result<bool, FreeListError> {
        // SAFETY: callers name an active queue page while this exclusive
        // lifecycle owns its local free-list and associated theap.
        let page = unsafe { &mut *page.as_ptr() };
        // SAFETY: the active page's source geometry and exclusive local-list
        // conditions are maintained by fresh publication and queue ownership.
        let mut free_list = unsafe { LocalFreeList::from_page(page) }?;
        free_list.quick_collect()
    }

    /// Extends only the source-selected candidate when it has no immediate
    /// local block. `mi_page_queue_find_free_ex` performs this after the
    /// bounded candidate search rather than while it scans the queue head.
    fn page_make_immediate(&mut self, page: NonNull<Page>) -> Result<bool, FreeListError> {
        // SAFETY: callers name the selected live queue page, and this method
        // performs no queue or page-map operation while the list is borrowed.
        let page = unsafe { &mut *page.as_ptr() };
        // SAFETY: the selected page retains the fresh-publication local-list
        // geometry and exclusive ownership invariant.
        let mut free_list = unsafe { LocalFreeList::from_page(page) }?;
        if free_list.quick_collect()? {
            return Ok(true);
        }
        if free_list.capacity() < free_list.reserved() {
            let _ = free_list.extend()?;
            return free_list.quick_collect();
        }
        Ok(false)
    }

    /// Allocates a zero-filled ordinary block.
    #[inline]
    pub(crate) fn allocate_zeroed(&mut self, request: usize) -> Option<NonNull<u8>> {
        self.allocate(request, true)
    }

    /// Allocates a zero-filled `count * size` byte block.
    ///
    /// This is the private `mi_count_size_overflow` + calloc path. An
    /// unrepresentable product returns `None` before any page, arena, or
    /// free-list transition. It remains caller-managed and does not expose a
    /// public C ABI or errno policy.
    #[inline]
    pub(crate) fn allocate_zeroed_count(
        &mut self,
        count: usize,
        size: usize,
    ) -> Option<NonNull<u8>> {
        self.allocate(size_class::count_size(count, size)?, true)
    }

    /// Allocates one valid aligned block with zero offset.
    ///
    /// This covers natural and overallocated arena alignment through
    /// `MI_PAGE_MAX_OVERALLOC_ALIGN` (64 KiB), plus the source OS-aligned
    /// singleton route through but excluding `MI_PAGE_META_ALIGNMENT`
    /// (256 MiB). The latter accepts only zero offset and owns a distinct OS
    /// mapping; 256 MiB and higher remain rejected by the pinned metadata
    /// safety limit.
    #[inline]
    pub(crate) fn allocate_aligned(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Option<NonNull<u8>> {
        self.allocate_aligned_at_inner(size, alignment, 0, false)
    }

    /// Allocates one valid in-arena block whose `pointer + offset` is aligned.
    ///
    /// The offset is an address equation, not an in-range byte index. As in
    /// pinned mimalloc, it may exceed `size`; only power-of-two alignments up
    /// through `MI_PAGE_MAX_OVERALLOC_ALIGN` are available in this lifecycle.
    #[inline]
    pub(crate) fn allocate_aligned_at(
        &mut self,
        size: usize,
        alignment: usize,
        offset: usize,
    ) -> Option<NonNull<u8>> {
        self.allocate_aligned_at_inner(size, alignment, offset, false)
    }

    /// Allocates one zero-filled valid aligned block with zero offset.
    #[inline]
    pub(crate) fn allocate_aligned_zeroed(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Option<NonNull<u8>> {
        self.allocate_aligned_at_inner(size, alignment, 0, true)
    }

    /// Allocates one zero-filled valid in-arena offset-aligned block.
    #[inline]
    pub(crate) fn allocate_aligned_zeroed_at(
        &mut self,
        size: usize,
        alignment: usize,
        offset: usize,
    ) -> Option<NonNull<u8>> {
        self.allocate_aligned_at_inner(size, alignment, offset, true)
    }

    /// Performs checked counted zero allocation before the bounded aligned
    /// path. Product overflow leaves all allocator state unmodified.
    #[inline]
    pub(crate) fn allocate_aligned_zeroed_count_at(
        &mut self,
        count: usize,
        size: usize,
        alignment: usize,
        offset: usize,
    ) -> Option<NonNull<u8>> {
        self.allocate_aligned_at_inner(size_class::count_size(count, size)?, alignment, offset, true)
    }

    #[inline]
    pub(crate) fn allocate_aligned_zeroed_count(
        &mut self,
        count: usize,
        size: usize,
        alignment: usize,
    ) -> Option<NonNull<u8>> {
        self.allocate_aligned_zeroed_count_at(count, size, alignment, 0)
    }

    /// The exact `mi_theap_malloc_zero_aligned_at` subset with arena-backed
    /// provenance. The fast branch uses only an already-immediate small
    /// free-list head; it never extends or substitutes a different page before
    /// the generic natural/overallocated source selection.
    fn allocate_aligned_at_inner(
        &mut self,
        size: usize,
        alignment: usize,
        offset: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if self.is_collection_poisoned() {
            return None;
        }
        if !size_class::alignment_is_valid(alignment) {
            return None;
        }
        if let Some(block) = self.allocate_aligned_small_head(size, alignment, offset, zero) {
            return Some(block);
        }

        let os_page_size = self.page_map.memory_config().page_size().bytes();
        match aligned::allocation_plan(size, alignment, offset, os_page_size)? {
            aligned::AlignedAllocationPlan::Natural => {
                let block = self.allocate(size, zero)?;
                let is_aligned = block.as_ptr().addr() & (alignment - 1) == 0;
                if is_aligned {
                    return Some(block);
                }
                // The plan's source geometry proves this branch unreachable.
                // Keep a release-build failure explicit and balanced rather
                // than returning an invalid alignment or leaking the block.
                let _ = unsafe { self.free(block) };
                None
            }
            aligned::AlignedAllocationPlan::Overallocate { request } => {
                let base = self.allocate(request, zero)?;
                let adjustment = match aligned::pointer_adjustment(
                    base.as_ptr().addr(),
                    alignment,
                    offset,
                ) {
                    Some(adjustment) => adjustment,
                    None => {
                        // SAFETY: `base` is the just-created current block;
                        // this defensive impossible-kernel outcome must not
                        // leave an arena claim live.
                        let _ = unsafe { self.free(base) };
                        return None;
                    }
                };
                let block = match NonNull::new(base.as_ptr().wrapping_add(adjustment)) {
                    Some(block) => block,
                    None => {
                        // SAFETY: see the matching pointer-adjustment branch.
                        let _ = unsafe { self.free(base) };
                        return None;
                    }
                };
                if adjustment != 0 {
                    // SAFETY: `base` remains a current allocation, so its
                    // page-map entry and metadata are live for this exact
                    // source interior-pointer flag transition.
                    let page = unsafe { self.page_map.checked_lookup(base.as_ptr()) };
                    let Some(page) = (unsafe { page.as_ref() }) else {
                        // SAFETY: `base` is still current despite the failed
                        // publication proof, so it can be balanced locally.
                        let _ = unsafe { self.free(base) };
                        return None;
                    };
                    if !self.owns_page(page) {
                        let _ = unsafe { self.free(base) };
                        return None;
                    }
                    page.set_has_interior_pointers(true);
                }
                Some(block)
            }
            // `alloc-aligned.c` routes this through an OS-aligned singleton
            // outside arenas. Its primary/secondary metadata and mapping
            // release provenance are deliberately distinct from arena pages.
            aligned::AlignedAllocationPlan::HugeSingleton { request, alignment } => {
                self.allocate_os_aligned_singleton(request, alignment, zero)
            }
        }
    }

    /// Allocates the source OS-aligned singleton branch for an alignment
    /// strictly between `MI_PAGE_MAX_OVERALLOC_ALIGN` and
    /// `MI_PAGE_META_ALIGNMENT`. This is intentionally not an arena fallback:
    /// the mapping owns its metadata prefix and its terminal release right.
    fn allocate_os_aligned_singleton(
        &mut self,
        request: usize,
        alignment: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if !self.retry_pending_os_release() {
            return None;
        }
        let config = self.page_map.memory_config();
        let block_size = config.good_alloc_size(request);
        if block_size == 0 || block_size < request {
            return None;
        }
        let page = self.allocate_fresh_os_aligned_page(block_size, alignment)?;
        match self.pop_or_extend(page, zero) {
            Ok(Some(block)) => {
                match self.move_regular_to_full(BIN_HUGE, page.as_ptr(), Some(block)) {
                    Ok(()) => Some(block),
                    Err(PageToFullError::Lifecycle) => {
                        // SAFETY: this failure occurs before full-queue
                        // enqueue, so the just-popped sole allocation can
                        // still restore its fresh OS mapping normally.
                        let _ = unsafe { self.free(block) };
                        None
                    }
                    Err(PageToFullError::Collection(_)) => {
                        // The page is already full-queue-owned and source
                        // false-force collection may have detached a corrupt
                        // remote list. Retain that terminal state rather than
                        // rolling back or presenting it as a fresh/OOM miss.
                        None
                    }
                }
            }
            Ok(None) | Err(_) => {
                // The fresh helper extended exactly one block before queue
                // publication, so this branch is an invariant failure. Its
                // mapping has not escaped and must not remain queue-owned.
                let _ = self.release_page(BIN_HUGE, page.as_ptr());
                None
            }
        }
    }

    /// Tries the opportunistic source small-page free-head fast path. `None`
    /// means either that it does not apply or that no matching immediate head
    /// exists; the generic aligned selector then owns the next transition.
    fn allocate_aligned_small_head(
        &mut self,
        size: usize,
        alignment: usize,
        offset: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if size > SMALL_SIZE_MAX || alignment > size {
            return None;
        }
        let direct_index = invariants::word_count(size)?;
        if direct_index >= PAGES_DIRECT {
            return None;
        }
        let page = self.session.direct_page(direct_index)?;
        if page == EMPTY_PAGE.as_ptr() {
            return None;
        }
        // SAFETY: the direct cache is owned exclusively by this lifecycle and
        // names only its current regular pages.
        let page_ref = unsafe { page.as_ref() }?;
        let head = NonNull::new(page_ref.free_list_head().cast::<u8>())?;
        if head.as_ptr().addr().wrapping_add(offset) & (alignment - 1) != 0 {
            return None;
        }
        let block = self.pop_or_extend(NonNull::new(page)?, zero).ok()??;
        debug_assert_eq!(block, head);
        Some(block)
    }

    /// Reallocates one ordinary allocation. `None` is the C null-pointer
    /// case. A failed replacement preserves `block`; `reallocate(Some(p), 0)`
    /// instead returns a distinct non-null zero-size block and frees `p` only
    /// after that replacement is fully initialized.
    ///
    /// # Safety
    ///
    /// When present, `block` must be one current allocation from this exact
    /// allocator, with no aliased access during the operation.
    pub(crate) unsafe fn reallocate(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        unsafe { self.reallocate_inner(block, new_size, false) }
    }

    /// Reallocates one ordinary allocation and zeroes the source-defined
    /// replacement extent. This is the bounded `rezalloc`/`recalloc` core.
    ///
    /// # Safety
    ///
    /// The caller obligations are identical to [`Self::reallocate`].
    pub(crate) unsafe fn reallocate_zeroed(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        unsafe { self.reallocate_inner(block, new_size, true) }
    }

    /// Core `mi_theap_realloc_zero_ex` behavior for the one owning heap.
    unsafe fn reallocate_inner(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if self.is_collection_poisoned() {
            return None;
        }
        let Some(block) = block else {
            return self.allocate(new_size, zero);
        };
        // SAFETY: the public reallocation contract proves that `block` stays
        // live and exclusively accessible through this decision and possible
        // replacement copy.
        let old_usable = unsafe { self.usable_size(block) }?;
        let plan = alloc::reallocation_plan(Some(old_usable), new_size, true);
        if plan == alloc::ReallocationPlan::Reuse {
            return Some(block);
        }

        let replacement = self.allocate(new_size, false)?;
        // SAFETY: successful local allocation returns one current block.
        let Some(new_usable) = (unsafe { self.usable_size(replacement) }) else {
            // SAFETY: preserve the old allocation and balance the just-made
            // replacement if an internal page-map proof unexpectedly fails.
            let _ = unsafe { self.free(replacement) };
            return None;
        };
        let alloc::ReallocationPlan::Replace { copy_size, .. } = plan else {
            return None;
        };
        if let Some(range) = alloc::replacement_zero_range(plan, new_usable, zero) {
            // SAFETY: ordinary blocks begin at source block bases and are
            // machine-word aligned; the range is checked against new usable.
            unsafe {
                support::zero_bytes_aligned(
                    replacement.as_ptr().wrapping_add(range.start),
                    range.end - range.start,
                )
            };
        } else if alloc::replacement_zeros_first_byte(new_size, zero) {
            // SAFETY: every successful allocator block has at least one byte.
            unsafe { replacement.as_ptr().write(0) };
        }
        // SAFETY: replacement and old live blocks are distinct because the old
        // block remains allocated, and `copy_size` is their checked overlap.
        unsafe { support::copy_bytes_aligned(replacement.as_ptr(), block.as_ptr(), copy_size) };
        // SAFETY: source frees the old allocation only after allocation,
        // zeroing, and copy all succeeded.
        if unsafe { self.free(block) }.is_err() {
            // SAFETY: retaining the old allocation remains preferable to
            // leaking the fully independent replacement on an invariant fault.
            let _ = unsafe { self.free(replacement) };
            return None;
        }
        Some(replacement)
    }

    /// Reallocates one zero-offset aligned allocation. Valid alignment remains
    /// bounded to the arena and OS-singleton subset described by
    /// [`Self::allocate_aligned`].
    ///
    /// # Safety
    ///
    /// When present, `block` must be current and satisfy the original aligned
    /// allocation contract for this allocator.
    #[inline]
    pub(crate) unsafe fn reallocate_aligned(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
    ) -> Option<NonNull<u8>> {
        unsafe { self.reallocate_aligned_at_inner(block, new_size, alignment, 0, false) }
    }

    /// Reallocates one offset-aligned allocation.
    ///
    /// # Safety
    ///
    /// The caller obligations are identical to [`Self::reallocate_aligned`],
    /// with the supplied `offset` matching the original address equation.
    #[inline]
    pub(crate) unsafe fn reallocate_aligned_at(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
        offset: usize,
    ) -> Option<NonNull<u8>> {
        unsafe { self.reallocate_aligned_at_inner(block, new_size, alignment, offset, false) }
    }

    /// Reallocates and zeroes a valid aligned allocation with zero offset.
    ///
    /// # Safety
    ///
    /// The caller obligations are identical to [`Self::reallocate_aligned`].
    #[inline]
    pub(crate) unsafe fn reallocate_aligned_zeroed(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
    ) -> Option<NonNull<u8>> {
        unsafe { self.reallocate_aligned_at_inner(block, new_size, alignment, 0, true) }
    }

    /// Reallocates and zeroes a valid offset-aligned allocation.
    ///
    /// # Safety
    ///
    /// The caller obligations are identical to [`Self::reallocate_aligned_at`].
    #[inline]
    pub(crate) unsafe fn reallocate_aligned_zeroed_at(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
        offset: usize,
    ) -> Option<NonNull<u8>> {
        unsafe { self.reallocate_aligned_at_inner(block, new_size, alignment, offset, true) }
    }

    unsafe fn reallocate_aligned_at_inner(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
        offset: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if self.is_collection_poisoned() {
            return None;
        }
        if !size_class::alignment_is_valid(alignment) {
            return None;
        }
        if alignment <= core::mem::size_of::<usize>() && offset == 0 {
            // SAFETY: this is the source delegation for ordinary alignment.
            return unsafe { self.reallocate_inner(block, new_size, zero) };
        }
        let Some(block) = block else {
            return self.allocate_aligned_at_inner(new_size, alignment, offset, zero);
        };
        // SAFETY: caller proves the current aligned allocation remains live.
        let old_usable = unsafe { self.usable_size(block) }?;
        if aligned::realloc_can_reuse(
            block.as_ptr().addr(),
            old_usable,
            new_size,
            alignment,
            offset,
        ) {
            return Some(block);
        }

        let replacement = self.allocate_aligned_at_inner(new_size, alignment, offset, false)?;
        // SAFETY: replacement is current and its aligned usable size is valid.
        let Some(new_usable) = (unsafe { self.usable_size(replacement) }) else {
            // SAFETY: this mirrors ordinary replacement failure cleanup while
            // retaining the original aligned allocation untouched.
            let _ = unsafe { self.free(replacement) };
            return None;
        };
        let plan = alloc::reallocation_plan(Some(old_usable), new_size, false);
        let alloc::ReallocationPlan::Replace { copy_size, .. } = plan else {
            return None;
        };
        if let Some(range) = aligned::replacement_zero_range(copy_size, new_usable, zero) {
            // SAFETY: an offset-aligned client pointer need not be word
            // aligned, so aligned realloc uses the source's arbitrary memcpy
            // and memzero kernels.
            unsafe {
                support::zero_bytes(
                    replacement.as_ptr().wrapping_add(range.start),
                    range.end - range.start,
                )
            };
        }
        // SAFETY: live replacement and old ranges do not overlap and the
        // checked copy extent fits both adjusted usable sizes.
        unsafe { support::copy_bytes(replacement.as_ptr(), block.as_ptr(), copy_size) };
        // SAFETY: the old block remains live until replacement work completes.
        if unsafe { self.free(block) }.is_err() {
            // SAFETY: see ordinary replacement failure handling above.
            let _ = unsafe { self.free(replacement) };
            return None;
        }
        Some(replacement)
    }

    /// Returns the source usable size for one live local allocation.
    ///
    /// Base allocations expose their full page block size. Once a page has an
    /// adjusted aligned allocation, each queried pointer is first recovered to
    /// its canonical base and reports that block size less its own adjustment.
    ///
    /// # Safety
    ///
    /// `block` must be a current allocation returned by this exact allocator,
    /// and it must not have been freed, retired, or moved into a dismantled
    /// page map. This inspection does not validate arbitrary raw pointers.
    pub(crate) unsafe fn usable_size(&self, block: NonNull<u8>) -> Option<usize> {
        if self.is_collection_poisoned() {
            return None;
        }
        // SAFETY: the caller's live-allocation contract excludes concurrent
        // page-map mutation and keeps the mapped metadata alive.
        let page = unsafe { self.page_map.checked_lookup(block.as_ptr()) };
        let page = unsafe { page.as_ref() }?;
        if !self.owns_page(page) {
            return None;
        }
        let base = self.canonical_block_start(page, block)?;
        if page.has_interior_pointers() {
            aligned::usable_size(page.block_size(), block.as_ptr().addr(), base.as_ptr().addr())
        } else {
            Some(page.block_size())
        }
    }

    /// Returns one local block by page-map lookup and source local-free push.
    ///
    /// # Safety
    ///
    /// `block` must be exactly one current block returned by this allocator,
    /// must not have been previously freed, and no alias may access it after
    /// this call. The caller must also retain the allocator's exclusive-theap
    /// mutation capability. This primitive does not implement the general
    /// lock-free remote-free protocol; a detached metadata wrapper may call it
    /// from another thread only while its process-private lock supplies that
    /// same exclusive mutation condition.
    pub(crate) unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), FreeError> {
        if self.is_collection_poisoned() {
            return Err(FreeError::CollectionPoisoned);
        }
        // SAFETY: the caller's live-local-allocation contract excludes a
        // simultaneous page-map registration or unregistration for this block.
        let page = unsafe { self.page_map.checked_lookup(block.as_ptr()) };
        let page = NonNull::new(page).ok_or(FreeError::Unmapped)?;
        // SAFETY: page-map registration keeps the returned metadata live until
        // this lifecycle unregisters it, and this `&mut self` owns the only
        // local mutation capability.
        let page = unsafe { &mut *page.as_ptr() };
        if !self.owns_page(page) {
            return Err(FreeError::ForeignPage);
        }
        let base = self
            .canonical_block_start(page, block)
            .ok_or(FreeError::InvalidBlock(FreeListError::InvalidBlock))?;

        let (used, in_full, bin) = {
            // SAFETY: this lifecycle owns the page, its blocks, and all local
            // free-list metadata. It never exposes a remote or concurrent path.
            let mut free_list = unsafe { LocalFreeList::from_page(page) }
                .map_err(FreeError::InvalidBlock)?;
            // SAFETY: the public caller contract proves exactly-once ownership
            // of `block`; the borrowed list additionally validates the
            // canonical base block's page range
            // and initialized-capacity membership before writing a link.
            unsafe { free_list.push_local(base) }
                .map_err(FreeError::InvalidBlock)?;
            (free_list.used(), page_is_in_full(page), size_class::bin(page.block_size()))
        };
        let bin = bin.ok_or(FreeError::Lifecycle)?;

        if used == 0 {
            // `mi_page_retire` clears the page-wide interior marker only once
            // every allocation from the page has returned. Clearing it for an
            // individual aligned free would make another live interior
            // pointer unfreeable and give it the wrong usable size.
            page.set_has_interior_pointers(false);
            if in_full {
                // A full page with its final local block returned is not a
                // regular retired page in the source; release it directly.
                if self.release_page(BIN_FULL, page as *mut Page) {
                    return Ok(());
                }
                return Err(FreeError::Lifecycle);
            }
            if self.retire_or_release(bin, page as *mut Page) {
                return Ok(());
            }
            return Err(FreeError::Lifecycle);
        }

        if in_full {
            if self.move_full_to_regular(bin, page as *mut Page) {
                return Ok(());
            }
            return Err(FreeError::Lifecycle);
        }
        Ok(())
    }

    /// Transfers one current regular-or-full-page allocation to a scoped
    /// remote producer.
    ///
    /// A full page is consumed by `collect_full_pages_non_abandoning`; a
    /// regular page is consumed by the matching generic queue scan, including
    /// a small direct-cache miss that falls through to that scan. Admission
    /// proves exact membership in either route before publication. Singleton
    /// and huge queues have no bounded regular route. This method mutates
    /// neither the client block nor any page/list/map field.
    ///
    /// # Safety
    ///
    /// `block` must be one exact current allocation returned by this
    /// allocator, must not have been freed or previously transferred, and all
    /// client access must transfer to the returned token. The token must be
    /// published by a joined/scoped worker or cancelled before the owner may
    /// resume. This is not a general asynchronous free route: callers must
    /// preserve the raw page/block lifetime and join the worker before owner
    /// collection, retirement, or teardown.
    pub(crate) unsafe fn begin_remote_free<'owner>(
        &'owner mut self,
        block: NonNull<u8>,
    ) -> Result<RemoteFreeProducer<'owner>, RemoteFreePreparationError> {
        if self.is_collection_poisoned() {
            return Err(RemoteFreePreparationError::CollectionPoisoned);
        }
        let thread = self
            .session
            .thread_id()
            .ok_or(RemoteFreePreparationError::DetachedSession)?;
        // SAFETY: the exclusive owner prevents a concurrent page-map mutation
        // and keeps registered metadata live for this non-mutating lookup.
        let page = unsafe { self.page_map.checked_lookup(block.as_ptr()) };
        let page = NonNull::new(page).ok_or(RemoteFreePreparationError::Unmapped)?;
        // SAFETY: the map entry remains live under this owner's exclusive
        // lifecycle. No raw page reference escapes the returned token.
        let page = unsafe { &mut *page.as_ptr() };
        if !self.owns_page(page) {
            return Err(RemoteFreePreparationError::ForeignPage);
        }
        let page_pointer = NonNull::from(&mut *page);
        // SAFETY: exclusive owner preflight keeps this initialized page-map
        // entry live and prevents its identity/owner transition.
        if !unsafe { Page::is_live_owner_for_thread_at(page_pointer, thread) } {
            return Err(RemoteFreePreparationError::InvalidOwnerState);
        }
        let canonical_block = self
            .canonical_block_start(page, block)
            .ok_or(RemoteFreePreparationError::InvalidBlock(
                FreeListError::InvalidBlock,
            ))?;
        // SAFETY: this exclusive preflight borrows the ordinary page state but
        // does not mutate it; the source geometry is validated before the
        // remote producer gets only raw atomic-field access.
        let free_list = unsafe { LocalFreeList::from_page(page) }
            .map_err(RemoteFreePreparationError::InvalidBlock)?;
        free_list
            .validate_local_free_preflight(canonical_block)
            .map_err(RemoteFreePreparationError::InvalidBlock)?;
        if !self.page_has_active_collection_route(page_pointer) {
            return Err(RemoteFreePreparationError::PageNotInCollectibleQueue);
        }
        Ok(RemoteFreeProducer {
            page: page_pointer,
            canonical_block,
            client_block: block,
            _owner: PhantomData,
            _not_sync: PhantomData,
        })
    }

    /// Finds the canonical source block for a current allocation. When any
    /// allocation in its page was overallocated and adjusted, mimalloc marks
    /// the page and derives the block base using `_mi_page_ptr_unalign`; the
    /// resulting raw pointer preserves the caller allocation's provenance.
    fn canonical_block_start(&self, page: &Page, block: NonNull<u8>) -> Option<NonNull<u8>> {
        if !page.has_interior_pointers() {
            return Some(block);
        }
        // SAFETY: the caller already proved this live page's allocation
        // contract. `Page::start` is valid for its source-described block
        // area, and this helper only derives the same allocation's base.
        let page_start = unsafe { page.start() };
        let base_address = aligned::recover_block_start(
            block.as_ptr().addr(),
            page_start.addr(),
            page.block_size(),
        )?;
        let adjustment = block.as_ptr().addr().checked_sub(base_address)?;
        NonNull::new(block.as_ptr().wrapping_sub(adjustment))
    }

    /// Retries the one detached OS mapping which could not be unmapped during
    /// an earlier fresh rollback or terminal free.
    fn retry_pending_os_release(&mut self) -> bool {
        let Some(owner) = self.pending_os_release.take() else {
            return true;
        };
        // SAFETY: a `Published` owner enters this slot only after its queue,
        // page-map entries, aliases, and primary metadata were detached. A
        // `Claim` owner is still private. Neither state has a live reader.
        match unsafe { owner.release() } {
            Ok(()) => true,
            Err(failure) => {
                self.park_pending_os_release(failure.into_owner());
                false
            }
        }
    }

    /// Stores the only outstanding OS-aligned mapping release right.
    ///
    /// Every creation path retries this slot before it can claim a second OS
    /// mapping, so two pending owners are an internal-state impossibility.
    fn park_pending_os_release(&mut self, owner: OsAlignedPageOwner) {
        assert!(
            self.pending_os_release.is_none(),
            "OS-aligned singleton release ownership must stay unique"
        );
        self.pending_os_release = Some(owner);
    }

    /// Releases an unpublished fresh claim or records it for retry on an
    /// `unmap` failure. Parking preserves the mapping's exact ownership while
    /// its already-rolled-back metadata remains private.
    fn release_unpublished_claim_or_park(&mut self, claim: OsAlignedPageClaim) {
        match claim.release() {
            Ok(()) => {}
            Err(failure) => {
                self.park_pending_os_release(failure.into_owner());
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn has_pending_os_release(&self) -> bool {
        self.pending_os_release.is_some()
    }

    /// Collects source-retired regular pages and one external-arena purge pass.
    /// `force` releases every currently retired page in the tracked range and
    /// forces any scheduled unpinned arena decommit; `false` decrements the
    /// normal retirement countdown and observes the pinned 4-second arena
    /// expiry. After the regular retired-bin pass, the non-abandoning source
    /// branch also scans BIN_FULL: it detaches already-published remote frees,
    /// runs only `_mi_page_free_collect(page, false)`'s local transfer, then
    /// releases all-free pages or returns no-longer-full pages to their exact
    /// regular bin before the arena purge. A live session performs remote
    /// detach first; the explicit detached session has no remote producer
    /// path and performs only the source local false-force portion. In either
    /// case, callers must prove producers joined/quiescent before the later
    /// queue helpers borrow page metadata during their transitions.
    pub(crate) fn collect_retired(&mut self, force: bool) -> bool {
        if self.is_collection_poisoned() {
            return false;
        }
        if !self.retry_pending_os_release() {
            return false;
        }
        let (minimum, maximum) = self.session.retired_bounds();
        self.session.reset_retired_bounds();
        if minimum < BIN_FULL && minimum <= maximum {
            for bin in minimum..=maximum {
                let mut page = match self.session.queue(bin) {
                    Some(queue) => queue.first(),
                    None => return false,
                };
                let mut visited = 0usize;
                while !page.is_null() && visited < RETIRE_MAX_PAGES {
                    visited += 1;
                    // SAFETY: every queue link is owned exclusively by this
                    // session; save the successor before a possible release.
                    let next = unsafe { (*page).next() };
                    let expire = unsafe { (*page).retire_expire() };
                    if expire == 0 {
                        break;
                    }
                    if unsafe { (*page).used() } == 0 {
                        let next_expire = expire - 1;
                        unsafe { (*page).set_retire_expire(next_expire) };
                        if force || next_expire == 0 {
                            if !self.release_page(bin, page) {
                                return false;
                            }
                        } else if !self.session.note_retired_bin(bin) {
                            return false;
                        }
                    } else {
                        unsafe { (*page).set_retire_expire(0) };
                    }
                    page = next;
                }
            }
        }
        if !self.collect_full_pages_non_abandoning() {
            return false;
        }
        self.arena
            .collect_scheduled_purge(self.page_map.memory_config().page_size(), force)
    }

    /// Ports `mi_theap_collect_full_pages` for this explicitly
    /// non-abandoning session. It saves each full-queue successor before
    /// false-force collection because release can retire the current
    /// metadata. Live sessions first detach remote publication; detached
    /// sessions have no remote producer path.
    fn collect_full_pages_non_abandoning(&mut self) -> bool {
        if self.session.theap().allows_page_abandon() {
            return true;
        }
        let mut page = match self.session.queue(BIN_FULL) {
            Some(queue) => queue.first(),
            None => return false,
        };
        while !page.is_null() {
            // SAFETY: the source full queue and its links are exclusively
            // owned by this session. Save before potential queue detach/release.
            let next = unsafe { (*page).next() };
            let page_nonnull = match NonNull::new(page) {
                Some(page) => page,
                None => return false,
            };
            if let Err(error) = self.page_free_collect_false(page_nonnull) {
                self.retain_page_collect_poison(page_nonnull, error, None);
                return false;
            }
            // SAFETY: false-force collection preserves this live current
            // page until the following exact full/all-free decision.
            let used = unsafe { (*page).used() };
            let reserved = unsafe { (*page).reserved() as usize };
            if used != reserved {
                if used == 0 {
                    if !self.release_page(BIN_FULL, page) {
                        return false;
                    }
                } else {
                    let bin = match size_class::bin(unsafe { (*page).block_size() }) {
                        Some(bin) if bin < BIN_FULL => bin,
                        _ => return false,
                    };
                    if !self.move_full_to_regular(bin, page) {
                        return false;
                    }
                }
            }
            page = next;
        }
        true
    }

    /// Exact false-force `_mi_page_free_collect` ordering for one active
    /// regular or full page: a live owner detaches/merges remote frees first,
    /// then transfers `local_free` only if `free` remains null. The explicit
    /// detached metadata session has no remote producer path and starts at
    /// that local transfer. It deliberately does not append a local list or
    /// create a delayed/deferred state.
    fn page_free_collect_false(
        &mut self,
        page: NonNull<Page>,
    ) -> Result<(), PageCollectError> {
        #[cfg(test)]
        if core::mem::take(&mut self.page_free_collect_failure_once) {
            // This test seam fails before `remote_free::collect` can detach
            // producer state. Production failures are never recoverable: they
            // may instead follow a partial remote-list ownership transition.
            return Err(PageCollectError::InjectedBeforeDetach);
        }
        let expected_thread = self.session.thread_id();
        if expected_thread.is_some() {
            // SAFETY: the active regular-or-full owner preserves page
            // lifetime and exclusive ordinary fields. A remote producer may
            // retain only its disjoint atomic state; the caller proves it
            // joined before the later queue transition or potential release.
            unsafe { remote_free::collect(page) }.map_err(PageCollectError::Remote)?;
        }
        // SAFETY: a live owner completed remote detach. A detached session
        // instead has `THREAD_ID_DETACHED` and its explicit externally
        // serialized no-remote-producer contract. Either proof derives raw
        // local fields without a whole-page mutable borrow.
        let state = unsafe { Page::local_collect_state_for_owner_at(page, expected_thread) }
            .ok_or(PageCollectError::InvalidOwnerState)?;
        // SAFETY: see `Page::local_collect_state_for_owner_at`; this performs
        // only the source false-force transfer of owner-local ordinary fields.
        unsafe { crate::free_list::collect_local_false(state) }
            .map_err(PageCollectError::Local)?;
        Ok(())
    }

    /// Exact force `_mi_page_free_collect` ordering used before the bounded
    /// later-main thread-exit release decision: detach any joined remote list,
    /// then append the owner-local deferred list to the immediate free list.
    ///
    /// This must stay distinct from [`Self::page_free_collect_false`]. The
    /// latter intentionally leaves `local_free` deferred for ordinary live
    /// allocation paths, whereas source `_mi_theap_collect_abandon` uses
    /// `force == true` before testing whether a departing owner's page can be
    /// released.
    fn page_free_collect_force(
        &mut self,
        page: NonNull<Page>,
    ) -> Result<(), PageCollectError> {
        #[cfg(test)]
        if core::mem::take(&mut self.page_free_collect_failure_once) {
            // Preserve the same pre-detach-only test seam as the false-force
            // collector; production errors may follow remote detachment and
            // are terminally retained by the caller.
            return Err(PageCollectError::InjectedBeforeDetach);
        }
        let expected_thread = self.session.thread_id();
        if expected_thread.is_some() {
            // SAFETY: the source drain still owns the live Theap/page while
            // every scoped producer has joined. Remote state is the only
            // concurrently published component and is detached first.
            unsafe { remote_free::collect(page) }.map_err(PageCollectError::Remote)?;
        }
        // SAFETY: remote state is detached above for live owners; detached
        // sessions retain their explicit no-producer proof. This obtains only
        // the narrow local-list projection for the exact current owner.
        let state = unsafe { Page::local_collect_state_for_owner_at(page, expected_thread) }
            .ok_or(PageCollectError::InvalidOwnerState)?;
        // SAFETY: the source force path validates and appends `local_free`
        // behind the immediate free list before the all-free `used` test.
        unsafe { crate::free_list::collect_local(state, true) }
            .map_err(PageCollectError::Local)?;
        Ok(())
    }

    #[inline]
    fn is_collection_poisoned(&self) -> bool {
        self.collection_poison.is_some()
    }

    /// Records the first owner-side collection failure before its caller can
    /// perform any fallback, fresh-page, release, or additional queue
    /// transition.
    fn retain_page_collect_poison(
        &mut self,
        page: NonNull<Page>,
        error: PageCollectError,
        popped_block: Option<NonNull<u8>>,
    ) {
        assert!(
            self.collection_poison.is_none(),
            "a terminal page collection failure must be retained once"
        );
        #[cfg(test)]
        let test_recoverable = matches!(error, PageCollectError::InjectedBeforeDetach);
        #[cfg(not(test))]
        let test_recoverable = false;
        self.collection_poison = Some(RetainedPageCollectPoison {
            page,
            error,
            popped_block,
            test_recoverable,
        });
    }

    #[cfg(test)]
    pub(crate) fn inject_page_free_collect_failure_once(&mut self) {
        assert!(
            !self.page_free_collect_failure_once,
            "the focused test injection is one-shot"
        );
        self.page_free_collect_failure_once = true;
    }

    #[cfg(test)]
    fn retained_page_collect_poison(&self) -> Option<RetainedPageCollectPoison> {
        self.collection_poison
    }

    #[cfg(test)]
    pub(crate) fn test_has_collection_poison(&self) -> bool {
        self.collection_poison.is_some()
    }

    #[cfg(test)]
    pub(crate) fn test_last_page_to_full(&self) -> Option<NonNull<Page>> {
        self.last_page_to_full
    }

    /// Removes only an `InjectedBeforeDetach` poison record so an isolated
    /// fixture can finish returning its known live allocations. Real errors
    /// return `None` even in cfg(test): they may have detached remote state,
    /// so clearing one would manufacture false ownership recovery.
    #[cfg(test)]
    fn take_page_collect_poison_for_fixture_cleanup(
        &mut self,
    ) -> Option<RetainedPageCollectPoison> {
        if !self.collection_poison?.test_recoverable {
            return None;
        }
        self.collection_poison.take()
    }

    #[cfg(test)]
    pub(crate) fn queue_count(&self, bin: usize) -> Option<usize> {
        self.session.queue(bin).map(|queue| queue.count())
    }

    #[cfg(test)]
    fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.session.direct_page(index)
    }

    fn pop_or_extend(
        &mut self,
        page: NonNull<Page>,
        zero: bool,
    ) -> Result<Option<NonNull<u8>>, FreeListError> {
        // SAFETY: callers name one selected or freshly published active page
        // whose local-list and queue transitions this exclusive session owns.
        let page = unsafe { &mut *page.as_ptr() };
        // SAFETY: that active-page ownership supplies the initialized
        // exclusive live-page conditions required by the borrowed free list.
        let mut free_list = unsafe { LocalFreeList::from_page(page) }?;
        if let Some(block) = free_list.pop(zero)? {
            page.set_retire_expire(0);
            return Ok(Some(block));
        }
        if free_list.quick_collect()? {
            if let Some(block) = free_list.pop(zero)? {
                page.set_retire_expire(0);
                return Ok(Some(block));
            }
        }
        if free_list.capacity() < free_list.reserved() {
            let _ = free_list.extend()?;
            if let Some(block) = free_list.pop(zero)? {
                page.set_retire_expire(0);
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    /// Performs only the direct source `page->free` allocation attempt.
    ///
    /// `mi_page_malloc_zero` must not quick-collect `local_free` or extend
    /// here: an empty immediate list enters `_mi_malloc_generic`, whose queue
    /// scan first performs the source false-force remote detach/merge before
    /// deciding whether it can extend or move a page to `BIN_FULL`.
    fn pop_immediate_local(
        &mut self,
        page: NonNull<Page>,
        zero: bool,
    ) -> Result<Option<NonNull<u8>>, FreeListError> {
        // SAFETY: the direct cache names one regular page owned exclusively
        // by this lifecycle; no producer token can coexist with this borrow.
        let page = unsafe { &mut *page.as_ptr() };
        // SAFETY: the direct page retains initialized local-list geometry.
        let mut free_list = unsafe { LocalFreeList::from_page(page) }?;
        let block = free_list.pop(zero)?;
        if block.is_some() {
            page.set_retire_expire(0);
        }
        Ok(block)
    }

    /// Performs the `alloc-aligned.c`/`arena.c` fresh OS-singleton sequence.
    ///
    /// The claim remains unpublished while primary metadata, any secondary
    /// aliases, the one-block free list, and the source-clipped page-map span
    /// are prepared. Only after the huge queue owns a fully initialized page
    /// does `into_published` transfer its exact mapping release right into
    /// the page's copied OS `MemoryId`.
    fn allocate_fresh_os_aligned_page(
        &mut self,
        block_size: usize,
        alignment: usize,
    ) -> Option<NonNull<Page>> {
        // A failed earlier OS-aligned release owns the sole pending slot. It
        // must be retried before claiming another mapping; ordinary arena
        // pages intentionally do not depend on this token.
        if !self.retry_pending_os_release() {
            return None;
        }
        let config = self.page_map.memory_config();
        let claim = match OsAlignedPageClaim::allocate(config, block_size, alignment) {
            Ok(claim) => claim,
            Err(failure) => {
                if let Some(owner) = failure.into_owner() {
                    self.park_pending_os_release(owner);
                }
                return None;
            }
        };
        let layout = claim.layout();
        let metadata = match claim.metadata() {
            Some(metadata) => metadata,
            None => {
                self.release_unpublished_claim_or_park(claim);
                return None;
            }
        };
        let slice_start = match claim.slice_start() {
            Some(slice_start) => slice_start,
            None => {
                self.release_unpublished_claim_or_park(claim);
                return None;
            }
        };
        let memory = match claim.memory_id() {
            Ok(memory) => memory,
            Err(_) => {
                self.release_unpublished_claim_or_park(claim);
                return None;
            }
        };
        let page = match unsafe {
            self.session.publish_fresh_page(
                metadata,
                layout.block_size(),
                layout.page_offset(),
                1,
                0,
                memory.initially_zero(),
                memory,
            )
        } {
            Some(page) => page,
            None => {
                self.release_unpublished_claim_or_park(claim);
                return None;
            }
        };
        if unsafe { !claim.publish_secondary_metadata(page) } {
            self.rollback_fresh_os_aligned(claim, page, false, false);
            return None;
        }

        let initialized = (|| {
            // SAFETY: `page` was initialized from the live OS claim's primary
            // metadata and describes its committed one-block area. No queue
            // or map observer sees it until this initialization completes.
            let mut free_list = unsafe { LocalFreeList::from_page(&mut *page.as_ptr()) }.ok()?;
            (free_list.extend().ok()? == 1).then_some(())
        })();
        if initialized.is_none() {
            self.rollback_fresh_os_aligned(claim, page, true, false);
            return None;
        }

        // SAFETY: the primary is fully initialized; the exact source-clipped
        // range is the only part published to page-map lookup. Larger OS
        // mappings retain their full extent solely in `MemoryId`.
        if unsafe {
            self.page_map
                .register_range(slice_start.as_ptr(), layout.page_map_size(), page)
        }
        .is_err()
        {
            self.rollback_fresh_os_aligned(claim, page, true, false);
            return None;
        }

        self.push_regular_page(BIN_HUGE, page);
        // This is an infallible handoff under `OsAlignedPageClaim`'s private
        // state machine: construction returns only an active `Mapping`; the
        // only method that can close it is the consuming `release`, which has
        // not run; and `into_published` performs no syscall after checking
        // that active bit. Its Result preserves the lower-level defensive API,
        // not a recoverable post-queue publication branch. A normal `None`
        // here would strand the queue and erase the only claim token.
        match claim.into_published() {
            Ok(_) => {}
            Err(_) => unreachable!("an unconsumed OS-aligned claim stays active"),
        }
        Some(page)
    }

    /// Reverses an unpublished OS-aligned fresh attempt without consulting the
    /// arena bitmap. The order mirrors its publication: clear page-map state,
    /// then aliases, then primary metadata, then the still-local mapping.
    fn rollback_fresh_os_aligned(
        &mut self,
        claim: OsAlignedPageClaim,
        page: NonNull<Page>,
        aliases_published: bool,
        page_map_registered: bool,
    ) {
        let layout = claim.layout();
        if page_map_registered {
            let Some(slice_start) = claim.slice_start() else {
                return;
            };
            // SAFETY: no allocation or queue entry escaped this failed fresh
            // attempt, so this exact registration is private.
            if unsafe {
                self.page_map
                    .unregister_range(slice_start.as_ptr(), layout.page_map_size())
            }
            .is_err()
            {
                // Preserve the active claim and metadata rather than reclaim a
                // mapping while a stale page-map entry could still name it.
                return;
            }
        }
        if aliases_published && !unsafe { claim.clear_secondary_metadata(page) } {
            // An alias ownership mismatch is a terminal provenance fault: do
            // not reclaim the mapping while an alias could still name it.
            return;
        }
        // SAFETY: failed fresh pages were never queue linked and retain no
        // live block, so only this session owns their primary retirement.
        if unsafe { self.session.retire_page(&mut *page.as_ptr()) }.is_none() {
            return;
        }
        self.release_unpublished_claim_or_park(claim);
    }

    /// Performs the fresh-page half of `_mi_arenas_page_alloc` for an
    /// ordinary, non-aligned request. `kind` is derived from the selected
    /// block size before this function is entered, so all source span and
    /// reserved-count transitions stay together with the claim provenance.
    fn allocate_fresh_page(
        &mut self,
        block_size: usize,
        kind: PageKind,
    ) -> Option<NonNull<Page>> {
        let slice_count = match kind {
            PageKind::Small | PageKind::Medium | PageKind::Large => {
                page::regular_page_slice_count(kind)?
            }
            PageKind::Singleton => page::singleton_page_slice_count(block_size)?,
        };
        let allocation_size = slice_count.checked_mul(ARENA_SLICE_SIZE)?;
        let claim = self.arena.try_claim_suitable_slices(
            self.requested_arena,
            slice_count,
            true,
            self.thread_sequence,
        )?;
        let slice_start = claim.start();
        let memory = claim.memory_id();
        let metadata = match claim.page_metadata() {
            Some(metadata) => metadata,
            None => {
                let _ = claim.release();
                return None;
            }
        };
        let usable_offset = match page::page_usable_start_offset(block_size) {
            Some(offset) => offset,
            None => {
                let _ = claim.release();
                return None;
            }
        };
        let usable_start = match slice_start.addr().checked_add(usable_offset) {
            Some(start) => start,
            None => {
                let _ = claim.release();
                return None;
            }
        };
        let page_offset = match usable_start.checked_sub(metadata.as_ptr().addr()) {
            Some(offset) => offset,
            None => {
                let _ = claim.release();
                return None;
            }
        };
        let reserved = match kind {
            PageKind::Singleton => 1,
            PageKind::Small | PageKind::Medium | PageKind::Large => {
                match page::reserved_object_count(allocation_size, usable_offset, block_size) {
                    Some(reserved) => reserved,
                    None => {
                        let _ = claim.release();
                        return None;
                    }
                }
            }
        };

        if !self
            .session
            .ensure_arena_pages(&self.arena, self.page_map.memory_config())
        {
            let _ = claim.release();
            return None;
        }

        // SAFETY: `claim` owns the exact unregistered slice and selected
        // metadata record exclusively. The caller-pinned session owns the
        // only mutable theap/heap image. Publication writes a fresh Page value
        // before any map or queue observer can reach it.
        let page = unsafe {
            self.session.publish_fresh_page(
                metadata,
                block_size,
                page_offset,
                reserved,
                0,
                memory.initially_zero(),
                memory,
            )
        };
        let Some(page) = page else {
            let _ = claim.release();
            return None;
        };

        let registered_in_arena = self.session.set_arena_page(&self.arena, memory);
        if !registered_in_arena {
            self.rollback_fresh(page, slice_start, allocation_size, memory, false, false);
            return None;
        }
        // SAFETY: `page` is fully initialized and remains address-stable until
        // the matching unregister below. This serial lifecycle excludes a
        // lookup racing this source-plain page-map write.
        if unsafe {
            self.page_map
                .register_range(slice_start, allocation_size, page)
        }
        .is_err()
        {
            self.rollback_fresh(page, slice_start, allocation_size, memory, true, false);
            return None;
        }

        let initialized = (|| {
            // SAFETY: source fresh-page publication has installed all geometry
            // and exclusive ownership fields; no queue or map operation below
            // mutates the page while this local-list borrow is live.
            let mut free_list = unsafe { LocalFreeList::from_page(&mut *page.as_ptr()) }.ok()?;
            if free_list.extend().ok()? == 0 {
                return None;
            }
            Some(())
        })();
        if initialized.is_none() {
            self.rollback_fresh(page, slice_start, allocation_size, memory, true, true);
            return None;
        }
        Some(page)
    }

    fn rollback_fresh(
        &mut self,
        page: NonNull<Page>,
        slice_start: *mut u8,
        allocation_size: usize,
        memory: MemoryId,
        arena_registered: bool,
        page_map_registered: bool,
    ) {
        if page_map_registered {
            // SAFETY: this serial rollback writes the same range just
            // registered above; no allocation was handed out.
            let _ = unsafe {
                self.page_map
                    .unregister_range(slice_start, allocation_size)
            };
        }
        if arena_registered {
            if memory.arena_memory().is_some() {
                // The exact session-selected bitmap bit was set by this
                // fresh attempt and no page-map reader can observe rollback.
                let _ = self.session.clear_arena_page(&self.arena, memory);
            }
        }
        // SAFETY: no queue/direct-cache entry names this failed fresh page, so
        // the pinned session owns its terminal metadata transition.
        let _ = unsafe { self.session.retire_page(&mut *page.as_ptr()) };
        // SAFETY: `memory` is the still-outstanding claim consumed by this
        // failed attempt; no successful page exists for its slices.
        let _ = unsafe { release_arena_slices(memory) };
    }

    fn push_regular_page(&mut self, bin: usize, page: NonNull<Page>) {
        let queue = match self.session.queue_mut(bin) {
            Some(queue) => queue as *mut _,
            None => return,
        };
        // SAFETY: fresh pages are detached and exclusively owned by this
        // session; `queue` is their matching source block-size queue.
        unsafe { page_queue_push_metadata(&mut *queue, page.as_ptr()) };
        self.session.note_page_added();
        self.update_direct_cache(bin);
    }

    /// Ports the non-abandoning `mi_page_to_full` branch.
    ///
    /// After enqueue it must run a second false-force collection immediately,
    /// even though a prior generic scan may already have collected. The source
    /// permits a producer between those points. Post-enqueue collection errors
    /// retain the full-queue page and popped block in permanent allocator
    /// poison; callers must not retry as OOM or select a fresh page.
    fn move_regular_to_full(
        &mut self,
        bin: usize,
        page: *mut Page,
        popped_block: Option<NonNull<u8>>,
    ) -> Result<(), PageToFullError> {
        let regular = match self.session.queue_mut(bin) {
            Some(queue) => queue as *mut _,
            None => return Err(PageToFullError::Lifecycle),
        };
        let full = match self.session.queue_mut(BIN_FULL) {
            Some(queue) => queue as *mut _,
            None => return Err(PageToFullError::Lifecycle),
        };
        let page = NonNull::new(page).ok_or(PageToFullError::Lifecycle)?;
        // SAFETY: `page` is one exhausted selected regular page and the
        // session exclusively owns both disjoint queue records and its links.
        unsafe { page_queue_enqueue_from_metadata(&mut *full, &mut *regular, page.as_ptr()) };
        #[cfg(test)]
        {
            self.last_page_to_full = Some(page);
        }
        self.update_direct_cache(bin);
        match self.page_free_collect_false(page) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.retain_page_collect_poison(page, error, popped_block);
                Err(PageToFullError::Collection(error))
            }
        }
    }

    fn move_full_to_regular(&mut self, bin: usize, page: *mut Page) -> bool {
        let regular = match self.session.queue_mut(bin) {
            Some(queue) => queue as *mut _,
            None => return false,
        };
        let full = match self.session.queue_mut(BIN_FULL) {
            Some(queue) => queue as *mut _,
            None => return false,
        };
        // SAFETY: source local free made this previously full page reusable;
        // the owning session exclusively controls the full and regular queues.
        unsafe { page_queue_enqueue_from_full_metadata(&mut *regular, &mut *full, page) };
        self.update_direct_cache(bin);
        true
    }

    fn retire_or_release(&mut self, bin: usize, page: *mut Page) -> bool {
        let page = unsafe { page.as_mut() };
        let Some(page) = page else {
            return false;
        };
        let count = match self.session.queue(bin) {
            Some(queue) => queue.count(),
            None => return false,
        };
        if bin < BIN_HUGE
            && count <= RETIRE_MAX_PAGES
            && (count == 1 || page.block_size() < SMALL_SIZE_MAX)
        {
            let cycles = if page.block_size() <= SMALL_MAX_OBJ_SIZE {
                RETIRE_CYCLES
            } else {
                RETIRE_CYCLES / 4
            };
            page.set_retire_expire(cycles);
            return self.session.note_retired_bin(bin);
        }
        self.release_page(bin, page as *mut Page)
    }

    fn release_page(&mut self, bin: usize, page: *mut Page) -> bool {
        let Some(span) = self.release_span(page) else {
            return false;
        };
        let queue = match self.session.queue_mut(bin) {
            Some(queue) => queue as *mut _,
            None => return false,
        };
        // SAFETY: this session owns the complete queue and its local page;
        // source release first detaches from the queue/direct cache.
        unsafe { page_queue_remove_metadata(&mut *queue, page) };
        if !self.session.note_page_removed() {
            return false;
        }
        if bin != BIN_FULL {
            self.update_direct_cache(bin);
        }

        match span {
            ReleaseSpan::Arena {
                memory,
                slice_start,
                size,
            } => {
                // SAFETY: `memory` describes the prevalidated, still
                // map-published span; no plain lookup overlaps this explicit
                // lifecycle transition.
                if unsafe { self.page_map.unregister_range(slice_start, size) }.is_err() {
                    self.reinsert_after_release_failure(bin, page);
                    return false;
                }
                if !self.session.clear_arena_page(&self.arena, memory) {
                    // The map is already clear, so do not release the arena
                    // span on an arena-page registration invariant failure. It
                    // remains a visible diagnostic leak rather than a
                    // use-after-release.
                    return false;
                }
                // SAFETY: queue/direct/map membership is gone and local free
                // state is fully free, so the session may reset metadata
                // before slice release.
                let retired = unsafe { self.session.retire_page(&mut *page) };
                if retired.is_none() {
                    return false;
                }
                // SAFETY: source ordering has unregistered the page before
                // this exact outstanding external-arena claim is returned to
                // its free bitmap.
                unsafe { release_arena_slices(memory) }
            }
            ReleaseSpan::Os(published) => {
                let layout = published.layout();
                let expected_memory = published.memory_id();
                // SAFETY: `PublishedOsAlignedPage` prevalidated the exact
                // clipped source range while it still mapped to this primary.
                if unsafe {
                    self.page_map.unregister_range(
                        published.slice_start().as_ptr(),
                        layout.page_map_size(),
                    )
                }
                .is_err()
                {
                    self.reinsert_after_release_failure(bin, page);
                    return false;
                }
                // SAFETY: page-map lookup is gone before the secondary slots
                // are cleared, and this single-thread lifecycle has no other
                // aligned metadata reader.
                if unsafe { !published.clear_secondary_metadata() } {
                    return false;
                }
                // SAFETY: this primary is detached, entirely free, and its
                // aliases are clear; it can no longer be observed after the
                // following exact mapping reclamation.
                let Some(retired) = (unsafe { self.session.retire_page(&mut *page) }) else {
                    return false;
                };
                let Some(retired_os) = retired.os_memory() else {
                    return false;
                };
                let Some(expected_os) = expected_memory.os_memory() else {
                    return false;
                };
                if !retired.is_os()
                    || retired_os.base != expected_os.base
                    || retired_os.size != expected_os.size
                    || retired.initially_committed() != expected_memory.initially_committed()
                    || retired.initially_zero() != expected_memory.initially_zero()
                {
                    return false;
                }
                // SAFETY: `published` owns the unique raw release right and
                // all map/alias/primary metadata predecessors now completed.
                match unsafe { published.reclaim() } {
                    Ok(()) => true,
                    Err(failure) => {
                        // The caller's block is already semantically free:
                        // queue, map, aliases, and primary are detached. Keep
                        // its sole raw mapping owner for collection/shutdown
                        // retry and still report this local free as accepted.
                        self.park_pending_os_release(failure.into_owner());
                        true
                    }
                }
            }
        }
    }

    /// Completes `_mi_arenas_page_free` for the all-free result of a mapped
    /// abandoned-page remote free.
    ///
    /// Unlike [`Self::release_page`], source abandonment already removed this
    /// exact page from its queue/direct cache and decremented the live Theap
    /// page count. The caller therefore must not perform either transition a
    /// second time. It instead proves the retained page is still all-free and
    /// detached, then preserves the source terminal ordering: unregister the
    /// full PageMap span, clear the exact ordinary arena-page bit, retire
    /// metadata, and return the arena slices. Any failure after unregistration
    /// is terminal because reconstructing a visible owner would be unsound.
    fn release_queue_detached_abandoned_arena_page(&mut self, page: NonNull<Page>) -> bool {
        let Some(ReleaseSpan::Arena {
            memory,
            slice_start,
            size,
        }) = self.release_span(page.as_ptr())
        else {
            return false;
        };
        // SAFETY: the linear mapped-page handoff remains the sole owner of
        // this initialized page until this terminal transition completes.
        let page_ref = unsafe { page.as_ref() };
        if page_ref.used() != 0 || !page_ref.is_queue_detached() {
            return false;
        }
        // SAFETY: `release_span` proved this exact page still owns every
        // registered slice of its arena span. No ordinary queue/producer
        // capability remains after the all-free abandoned-free result.
        if unsafe { self.page_map.unregister_range(slice_start, size) }.is_err() {
            return false;
        }
        if !self.session.clear_arena_page(&self.arena, memory) {
            // The map is already clear; retain terminal ownership rather than
            // returning slices while the ordinary arena-page image remains
            // visible as allocated.
            return false;
        }
        // SAFETY: the source all-free result proved there is no remote list;
        // this method just proved queue detachment and removed every map and
        // arena-page publication predecessor before resetting metadata.
        if unsafe { self.session.retire_page(&mut *page.as_ptr()) }.is_none() {
            return false;
        }
        // SAFETY: map and ordinary page-image removal now precede return of
        // this exact one outstanding external-arena span.
        unsafe { release_arena_slices(memory) }
    }

    /// Validates every arena or OS-aligned page-map fact needed for terminal
    /// release before a caller removes a queue member or releases a page that
    /// abandonment already detached. This preserves the distinct source
    /// release provenance instead of treating an OS mapping as an
    /// external-arena bitmap claim.
    fn release_span(&self, page: *mut Page) -> Option<ReleaseSpan> {
        let page = NonNull::new(page)?;
        // SAFETY: each caller retains the exact initialized page through this
        // preflight, either by exclusive queue ownership or by its linear
        // queue-detached abandoned-page handoff.
        let page_ref = unsafe { page.as_ref() };
        let memory = page_ref.memid();
        if memory.is_os() {
            // SAFETY: this preflight holds exclusive live-page ownership and
            // serializes the page-map observations named by the constructor.
            let published = unsafe {
                PublishedOsAlignedPage::from_page(self.page_map.memory_config(), page)
            }?;
            // SAFETY: the returned token carries the exact clipped range and
            // primary address whose entries must still name this page.
            if unsafe { !published.page_map_entries_match(self.page_map) } {
                return None;
            }
            return Some(ReleaseSpan::Os(published));
        }
        let arena_memory = memory.arena_memory()?;
        if arena_memory.arena != core::ptr::from_ref(self.arena.arena()).cast_mut() {
            return None;
        }
        let slice_index = arena_memory.slice_index as usize;
        let slice_count = arena_memory.slice_count as usize;
        let size = slice_count.checked_mul(ARENA_SLICE_SIZE)?;
        let slice_start = self.arena.slice_start(slice_index)?;
        let block_size = page_ref.block_size();
        let kind = size_class::page_kind_for_block_size(block_size)?;
        let expected_slice_count = match kind {
            PageKind::Small | PageKind::Medium | PageKind::Large => {
                page::regular_page_slice_count(kind)?
            }
            PageKind::Singleton => page::singleton_page_slice_count(block_size)?,
        };
        if slice_count != expected_slice_count {
            return None;
        }
        // Validate page geometry in integer space. Calling `Page::start` on
        // malformed metadata would itself require the very layout guarantee
        // this preflight is meant to establish. Regular pages derive their
        // complete object count from the span; ordinary singleton pages always
        // reserve exactly one block.
        let usable_offset = page::page_usable_start_offset(block_size)?;
        let expected_reserved = match kind {
            PageKind::Small | PageKind::Medium | PageKind::Large => {
                page::reserved_object_count(size, usable_offset, block_size)?
            }
            PageKind::Singleton => 1,
        };
        if page_ref.reserved() != expected_reserved {
            return None;
        }
        let expected_start = slice_start.addr().checked_add(usable_offset)?;
        if expected_start >= slice_start.addr().checked_add(size)?
            || expected_start.checked_sub(page.as_ptr().addr())? != page_ref.page_offset()
        {
            return None;
        }
        // SAFETY: this explicit lifecycle serializes all source-plain map
        // accesses. Checking every claimed slice before queue removal proves
        // that terminal unregistration targets exactly the map range published
        // for this one page, rather than merely its leading slice.
        for offset in (0..size).step_by(ARENA_SLICE_SIZE) {
            let address = slice_start.addr().checked_add(offset)? as *const u8;
            if unsafe { self.page_map.checked_lookup(address) } != page.as_ptr() {
                return None;
            }
        }
        Some(ReleaseSpan::Arena {
            memory,
            slice_start,
            size,
        })
    }

    fn reinsert_after_release_failure(&mut self, bin: usize, page: *mut Page) {
        let Some(page) = NonNull::new(page) else {
            return;
        };
        let Some(queue) = self.session.queue_mut(bin) else {
            return;
        };
        // SAFETY: failed unregister leaves the page metadata valid; putting it
        // back preserves the owning queue rather than releasing live storage.
        unsafe { page_queue_push_metadata(queue, page.as_ptr()) };
        self.session.note_page_added();
        if bin != BIN_FULL {
            self.update_direct_cache(bin);
        }
    }

    fn update_direct_cache(&mut self, bin: usize) {
        let (block_size, first) = match self.session.queue(bin) {
            Some(queue) => (queue.block_size(), queue.first()),
            None => return,
        };
        if block_size > SMALL_SIZE_MAX {
            return;
        }
        let Some(index) = invariants::word_count(block_size) else {
            return;
        };
        if index >= PAGES_DIRECT {
            return;
        }
        let page = if first.is_null() { EMPTY_PAGE.as_ptr() } else { first };
        if self.session.direct_page(index) == Some(page) {
            return;
        }

        let mut start = 0usize;
        if index > 1 && bin > 0 {
            let mut previous = bin - 1;
            while previous > 0 {
                let previous_size = match self.session.queue(previous) {
                    Some(queue) => queue.block_size(),
                    None => return,
                };
                if size_class::bin(previous_size) != Some(bin) {
                    break;
                }
                previous -= 1;
            }
            let previous_size = match self.session.queue(previous) {
                Some(queue) => queue.block_size(),
                None => return,
            };
            start = invariants::word_count(previous_size)
                .and_then(|value| value.checked_add(1))
                .unwrap_or(index)
                .min(index);
        }
        for direct in start..=index {
            let _ = self.session.set_direct_page(direct, page);
        }
    }

    /// Proves that one live page remains linked in exactly `bin`'s owner
    /// queue. The exclusive allocator borrow makes the count and links stable
    /// for this bounded O(n) pre-publication validation; a producer token is
    /// not created until after this traversal has ended.
    fn page_is_active_queue_member(&self, bin: usize, target: NonNull<Page>) -> bool {
        let Some(queue) = self.session.queue(bin) else {
            return false;
        };
        if bin != BIN_FULL {
            // SAFETY: this same exclusive pre-publication validation keeps
            // target's initialized immutable geometry stable.
            if queue.block_size() != unsafe { target.as_ref().block_size() } {
                return false;
            }
        }
        let mut page = queue.first();
        let mut remaining = queue.count();
        while remaining != 0 {
            if page.is_null() {
                return false;
            }
            if page == target.as_ptr() {
                return true;
            }
            // SAFETY: the exclusive owner keeps every link stable during
            // this bounded queue-membership validation.
            page = unsafe { (*page).next() };
            remaining -= 1;
        }
        false
    }

    /// Returns whether this live page has an exact bounded owner-side remote
    /// collection route. Full pages are consumed by the non-abandoning full
    /// scan; regular pages must be linked in their derived non-huge size bin,
    /// where direct misses compose into the generic scan. A matching flag
    /// alone is insufficient: unlinked pages cannot safely admit a producer.
    fn page_has_active_collection_route(&self, page: NonNull<Page>) -> bool {
        // SAFETY: callers first prove the map-published live page under this
        // exclusive allocator borrow; this reads immutable owner metadata.
        let page_ref = unsafe { page.as_ref() };
        if page_is_in_full(page_ref) {
            return self.page_is_active_queue_member(BIN_FULL, page);
        }
        let Some(bin) = size_class::bin(page_ref.block_size()) else {
            return false;
        };
        bin < BIN_HUGE && self.page_is_active_queue_member(bin, page)
    }

    /// Binds the static main Heap's installed in-place arena bitmap to its
    /// paired source `abandoned_count[bin]` entry. The dynamic Heap path has
    /// a distinct typed arena-pages owner and must never use this capability.
    fn main_heap_abandoned_page(
        &self,
        bin: usize,
    ) -> Option<MainArenaMappedAbandonedPage<'arena>> {
        let heap = NonNull::new(self.session.theap().heap())?;
        self.arena.main_heap_abandoned_page(heap, bin)
    }

    fn owns_page(&self, page: &Page) -> bool {
        page.theap() == self.session.theap() as *const _ as *mut _
    }
}

impl<'arena, 'map, Session: TheapPageSession> Drop
    for PageAllocatorEngine<'arena, 'map, Session>
{
    fn drop(&mut self) {
        if !self.shutdown_complete {
            if let Some(owner) = self.pending_os_release.take() {
                if let Err(owner) = self.session.retain_unfinished_os_release(owner) {
                    // Static sessions have no longer-lived attachment in
                    // which to retain this allocation-free retry token. The
                    // owner has no destructor, so explicitly leaking it is
                    // the only non-destructive Drop behavior; dynamic
                    // sessions instead store it in their terminal owner.
                    core::mem::forget(owner);
                }
            }
            // This is intentionally non-destructive. Ticket-zero static,
            // dynamic, and later-main sessions retain their attachment and
            // any pending OS release authority but become terminal; exclusive
            // bootstrap sessions are otherwise inert. A Drop cannot
            // manufacture source collection, page release, or attachment
            // teardown.
            self.session.latch_unfinished_page_engine();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::arena::{ArenaRegistry, CommitHook, manage_external_in_place};
    use crate::config::{
        ARENA_ALIGNMENT, ARENA_MIN_SIZE, LARGE_MAX_OBJ_SIZE, MAX_ALIGN_SIZE,
        MAX_ALLOC_SIZE, MEDIUM_MAX_OBJ_SIZE, PAGE_MAX_OVERALLOC_ALIGN,
        KIB, SMALL_MAX_OBJ_SIZE, MIB, WORD_SIZE,
    };
    use crate::os::{MapAccess, Mapping, MemoryConfig, PageSize, fault};
    use crabc_core::Errno;
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::vec::Vec;

    struct AlignedRegion {
        pointer: NonNull<u8>,
        layout: Layout,
    }

    impl AlignedRegion {
        fn zeroed() -> Self {
            let layout = Layout::from_size_align(ARENA_MIN_SIZE, ARENA_ALIGNMENT).unwrap();
            // SAFETY: the test retains the returned allocation and deallocates
            // it with this exact layout after every allocator page is forced
            // through the explicit retirement/release path.
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            Self { pointer, layout }
        }

        fn as_ptr(&mut self) -> *mut u8 {
            self.pointer.as_ptr()
        }
    }

    impl Drop for AlignedRegion {
        fn drop(&mut self) {
            // SAFETY: `pointer` was allocated once with `layout` and all
            // allocator references have been collected before fixture exit.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    struct PageMetadataCommitScript {
        calls: AtomicUsize,
        fail_call: AtomicUsize,
    }

    impl PageMetadataCommitScript {
        const fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail_call: AtomicUsize::new(0),
            }
        }
    }

    unsafe extern "C" fn page_metadata_commit(
        commit: bool,
        _start: *mut u8,
        _size: usize,
        is_zero: *mut bool,
        user_argument: *mut c_void,
    ) -> bool {
        // SAFETY: the test supplies the address of one live script for the
        // arena's complete lifetime and the hook makes no aliased mutation.
        let script = unsafe { &*user_argument.cast::<PageMetadataCommitScript>() };
        let call = script.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if !commit || script.fail_call.load(Ordering::Relaxed) == call {
            return false;
        }
        if !is_zero.is_null() {
            // SAFETY: this is the optional out-parameter supplied by the
            // arena commit boundary, valid for the duration of the callback.
            unsafe { is_zero.write(true) };
        }
        true
    }

    fn with_allocator(test: impl FnOnce(&mut SingleThreadAllocator<'_, '_, '_>)) {
        let mut region = AlignedRegion::zeroed();
        let registry = ArenaRegistry::new(null_mut());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                true,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(),
            1024 * 1024,
            false,
            false,
        );
        let mut page_map = PageMap::initialize(config, 0, true).unwrap();
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let mut allocator = SingleThreadAllocator::activate(
            bootstrap.as_mut(),
            LiveThreadId::new(12).unwrap(),
            arena,
            ArenaId::none(),
            &mut page_map,
            0,
        )
        .unwrap();

        test(&mut allocator);
        assert!(allocator.collect_retired(true));
        drop(allocator);
        // SAFETY: force collection removed every page-map entry and all local
        // users before the explicit page-map destruction boundary.
        unsafe { page_map.destroy() }.unwrap();
    }

    /// Runs one externally serialized detached metadata-theap lifecycle.
    ///
    /// This mirrors `MetaAllocator`'s source `THREAD_ID_DETACHED` mode while
    /// retaining an isolated caller-managed arena and page map for the
    /// full-page collection regression below.
    fn with_detached_allocator(test: impl FnOnce(&mut SingleThreadAllocator<'_, '_, '_>)) {
        let mut region = AlignedRegion::zeroed();
        let registry = ArenaRegistry::new(null_mut());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                true,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(),
            1024 * 1024,
            false,
            false,
        );
        let mut page_map = PageMap::initialize(config, 0, true).unwrap();
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let mut allocator = SingleThreadAllocator::activate_detached(
            bootstrap.as_mut(),
            MainSubprocess::test_static_owner(),
            arena,
            ArenaId::none(),
            &mut page_map,
            0,
        )
        .unwrap();

        test(&mut allocator);
        assert!(allocator.collect_retired(true));
        drop(allocator);
        // SAFETY: force collection removed every page-map entry and all local
        // users before the explicit page-map destruction boundary.
        unsafe { page_map.destroy() }.unwrap();
    }

    fn with_unpinned_mapping_allocator(
        test: impl FnOnce(&mut SingleThreadAllocator<'_, '_, '_>, &mut Mapping),
    ) {
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(),
            1024 * 1024,
            false,
            false,
        );
        let mut mapping = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        )
        .unwrap();
        let registry = ArenaRegistry::new(null_mut());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                mapping.base().unwrap(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                mapping.initially_committed(),
                false,
                mapping.initially_zero(),
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let mut page_map = PageMap::initialize(config, 0, true).unwrap();
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let mut allocator = SingleThreadAllocator::activate(
            bootstrap.as_mut(),
            LiveThreadId::new(12).unwrap(),
            arena,
            ArenaId::none(),
            &mut page_map,
            0,
        )
        .unwrap();

        test(&mut allocator, &mut mapping);
        assert!(allocator.collect_retired(true));
        drop(allocator);
        // SAFETY: force collection has removed every published page-map entry
        // before the source-plain map is explicitly dismantled.
        unsafe { page_map.destroy() }.unwrap();
        mapping.unmap().unwrap();
    }

    fn append_unique(requests: &mut [usize], count: &mut usize, request: usize) {
        if requests[..*count].contains(&request) {
            return;
        }
        assert!(*count < requests.len());
        requests[*count] = request;
        *count += 1;
    }

    fn small_boundaries() -> ([usize; 384], usize) {
        let mut requests = [0; 384];
        let mut count = 0;
        let mut previous = usize::MAX;
        for request in 0..=SMALL_SIZE_MAX {
            let usable = size_class::good_size(request, 4096).unwrap();
            if request == 0 || usable != previous {
                if request > 0 {
                    append_unique(&mut requests, &mut count, request - 1);
                }
                append_unique(&mut requests, &mut count, request);
                if request < SMALL_SIZE_MAX {
                    append_unique(&mut requests, &mut count, request + 1);
                }
            }
            previous = usable;
        }
        (requests, count)
    }

    unsafe fn bytes_equal(pointer: NonNull<u8>, size: usize, byte: u8) -> bool {
        for index in 0..size {
            // SAFETY: test callers pass one currently allocated block and the
            // loop is bounded by its request/usable size.
            if unsafe { pointer.as_ptr().add(index).read() } != byte {
                return false;
            }
        }
        true
    }

    unsafe fn write_bytes(pointer: NonNull<u8>, size: usize, byte: u8) {
        // SAFETY: callers retain one unique current allocation for the exact
        // requested range while this test-only helper initializes its bytes.
        unsafe { core::ptr::write_bytes(pointer.as_ptr(), byte, size) };
    }

    unsafe fn content_hash(pointer: NonNull<u8>, size: usize) -> u64 {
        let mut value = 14_695_981_039_346_656_037u64;
        for index in 0..size {
            // SAFETY: callers retain one current allocation covering the
            // exact address-independent trace extent.
            value ^= unsafe { pointer.as_ptr().add(index).read() } as u64;
            value = value.wrapping_mul(1_099_511_628_211);
        }
        value
    }

    fn mapped_span(
        allocator: &SingleThreadAllocator<'_, '_, '_>,
        block: NonNull<u8>,
        expected_kind: PageKind,
    ) -> (*mut u8, usize, usize) {
        // SAFETY: the caller retains `block` as a current allocation and this
        // single-thread fixture serializes the source-plain page-map lookup.
        let page = unsafe { allocator.page_map.checked_lookup(block.as_ptr()) };
        assert!(!page.is_null());
        // SAFETY: the live page-map registration keeps this page metadata
        // address-stable until the test returns the block and collects it.
        let page = unsafe { &*page };
        assert_eq!(size_class::page_kind_for_block_size(page.block_size()), Some(expected_kind));
        let memory = page.memid().arena_memory().unwrap();
        let start = allocator.arena.slice_start(memory.slice_index as usize).unwrap();
        let size = memory.slice_count as usize * ARENA_SLICE_SIZE;
        for offset in (0..size).step_by(ARENA_SLICE_SIZE) {
            let address = start.wrapping_add(offset);
            // SAFETY: every page-map entry across the published source span
            // remains stable while this test holds the allocation live.
            assert_eq!(unsafe { allocator.page_map.checked_lookup(address) }, page as *const Page as *mut Page);
        }
        (start, size, page.block_size())
    }

    #[test]
    fn page_metadata_commit_failure_returns_the_fresh_claim_for_reuse() {
        let mut region = AlignedRegion::zeroed();
        let registry = ArenaRegistry::new(null_mut());
        let script = PageMetadataCommitScript::new();
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                false,
                true,
                true,
                -1,
                false,
                Some(CommitHook::new(
                    page_metadata_commit,
                    (&script as *const PageMetadataCommitScript).cast_mut().cast(),
                )),
            )
        }
        .unwrap();
        let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        // Hold the first ordinary run after the arena-info prefix. The
        // allocator must then claim the following ordinary slice, whose page
        // metadata prefix still needs its own hook invocation.
        let held = arena
            .try_claim_suitable_slices(ArenaId::none(), 7, false, 0)
            .unwrap();
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(),
            1024 * 1024,
            false,
            false,
        );
        let mut page_map = PageMap::initialize(config, 0, true).unwrap();
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let mut allocator = SingleThreadAllocator::activate(
            bootstrap.as_mut(),
            LiveThreadId::new(12).unwrap(),
            arena,
            ArenaId::none(),
            &mut page_map,
            0,
        )
        .unwrap();

        let calls_before_fresh = script.calls.load(Ordering::Relaxed);
        // First the claimed ordinary slice commits, then `page_metadata` tries
        // the aligned metadata prefix. Fail exactly that second call.
        script
            .fail_call
            .store(calls_before_fresh + 2, Ordering::Relaxed);
        assert!(allocator.allocate(37, false).is_none());
        let reused = allocator
            .arena
            .try_claim_suitable_slices(ArenaId::none(), 1, false, 0)
            .unwrap();
        assert_eq!(reused.slice_index(), held.slice_index() + held.slice_count());
        assert!(reused.release());

        script.fail_call.store(0, Ordering::Relaxed);
        let block = allocator.allocate(37, false).unwrap();
        // SAFETY: the retry returned one current local allocation exactly once.
        unsafe { allocator.free(block).unwrap() };
        assert!(allocator.collect_retired(true));
        drop(allocator);
        assert!(held.release());
        // SAFETY: every fresh-page map registration was retired before this
        // fixture dismantles its explicit source-plain page map.
        unsafe { page_map.destroy() }.unwrap();
    }

    #[test]
    fn arena_page_bitmap_failure_after_publication_returns_the_fresh_claim() {
        with_allocator(|allocator| {
            let probe = allocator
                .arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                .unwrap();
            let slice_index = probe.slice_index();
            assert!(probe.release());

            // Reproduce an inconsistent preexisting arena-page bit. Fresh
            // publication has succeeded by the time this source transition
            // rejects the duplicate bit, so the lifecycle must retire metadata
            // and return the claim despite there being no map registration.
            let marked = unsafe {
                allocator
                    .arena
                    .pages()
                    .unwrap()
                    .set_range(slice_index, 1)
                    .unwrap()
                    .all_transitioned()
            };
            assert!(marked);
            assert!(allocator.allocate(37, false).is_none());
            assert_eq!(
                unsafe {
                    allocator
                        .arena
                        .pages()
                        .unwrap()
                        .clear_range(slice_index, 1)
                },
                Some(true),
            );
            let reused = allocator
                .arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                .unwrap();
            assert_eq!(reused.slice_index(), slice_index);
            assert!(reused.release());
        });
    }

    #[test]
    fn forced_unpinned_arena_decommit_failure_keeps_retry_state_and_external_mapping() {
        let fault = fault::install(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        with_unpinned_mapping_allocator(|allocator, mapping| {
            let block = allocator.allocate(37, false).unwrap();
            let slice_index = {
                // SAFETY: `block` is current, so its page-map entry and page
                // metadata remain live until the immediately following free.
                let page = unsafe { allocator.page_map.checked_lookup(block.as_ptr()) };
                assert!(!page.is_null());
                // SAFETY: the map registration owns this metadata while the
                // current block stays live.
                unsafe { (*page).memid().arena_memory().unwrap().slice_index as usize }
            };
            // SAFETY: `block` is the single current allocation in this test.
            unsafe { allocator.free(block).unwrap() };

            // Forced page retirement schedules then claims the exact free
            // slice. The injected default `purge_decommits=1` failure must
            // restore availability but retain the retry bit for collection.
            assert!(!allocator.collect_retired(true));
            let arena_memory = unsafe { allocator.page_map.checked_lookup(block.as_ptr()) };
            assert!(arena_memory.is_null());
            assert_eq!(
                unsafe { allocator.arena.slices_free() }
                    .unwrap()
                    .is_set_range(slice_index, 1),
                Some(true),
            );
            assert_eq!(
                unsafe { allocator.arena.slices_purge() }
                    .unwrap()
                    .is_set_range(slice_index, 1),
                Some(true),
            );
            assert!(mapping.base().is_ok(), "arena purge must not unmap external backing");

            // A completed failed purge no longer owns this range, so a fresh
            // page may claim it. The stale retry bit stays scheduled until the
            // next free/collection transition safely owns the range again.
            let retry = allocator.allocate(37, false).unwrap();
            // SAFETY: `retry` is a distinct current allocation from this test
            // allocator and is returned exactly once.
            unsafe { allocator.free(retry).unwrap() };
            assert!(allocator.collect_retired(true));
            assert_eq!(
                unsafe { allocator.arena.slices_purge() }
                    .unwrap()
                    .is_clear_range(slice_index, 1),
                Some(true),
            );
            assert!(mapping.base().is_ok(), "only context teardown may unmap backing");
        });
        assert!(fault.observed() >= 1);
    }

    #[test]
    fn forced_pinned_external_arena_skips_default_decommit() {
        let fault = fault::install(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        with_allocator(|allocator| {
            let block = allocator.allocate(37, false).unwrap();
            // SAFETY: the test owns this one live block and returns it once.
            unsafe { allocator.free(block).unwrap() };
            assert!(allocator.collect_retired(true));
            assert_eq!(
                unsafe { allocator.arena.slices_purge() }
                    .unwrap()
                    .is_clear_range(allocator.arena.arena().info_slices, 1),
                Some(true),
            );
        });
        assert_eq!(fault.observed(), 0);
    }

    #[test]
    fn small_trace_matches_the_pinned_address_independent_oracle_record() {
        with_allocator(|allocator| {
            let (requests, count) = small_boundaries();
            assert_eq!(count, 62, "pinned release small good-size transitions");

            std::println!("CRABC_MI_SMALL_TRACE_BEGIN");
            std::println!("trace.boundary.count={count}");
            for (index, request) in requests[..count].iter().copied().enumerate() {
                let first = allocator.allocate(request, false).unwrap();
                let second = allocator.allocate(request, false).unwrap();
                let usable = unsafe { allocator.usable_size(first) }.unwrap();
                assert!(usable >= request);
                assert_eq!(usable, unsafe { allocator.usable_size(second) }.unwrap());
                let pattern = 0x41u8 + (index % 47) as u8;
                // SAFETY: `first` is a live unique allocation of at least the
                // requested byte count and has not been freed yet.
                unsafe { core::ptr::write_bytes(first.as_ptr(), pattern, request) };

                std::println!("trace.boundary.{index}.request={request}");
                std::println!("trace.boundary.{index}.usable={usable}");
                std::println!("trace.boundary.{index}.distinct={}", u8::from(first != second));
                std::println!(
                    "trace.boundary.{index}.word_aligned={}",
                    u8::from(first.as_ptr().addr() % WORD_SIZE == 0)
                );
                std::println!(
                    "trace.boundary.{index}.max_aligned={}",
                    u8::from(first.as_ptr().addr() % MAX_ALIGN_SIZE == 0)
                );
                std::println!(
                    "trace.boundary.{index}.preserved={}",
                    u8::from(unsafe { bytes_equal(first, request, pattern) })
                );
                // SAFETY: these exact current allocations are returned once,
                // in the same source-local default-theap session.
                unsafe {
                    allocator.free(second).unwrap();
                    allocator.free(first).unwrap();
                }
            }

            let zeroed = allocator.allocate_zeroed(37).unwrap();
            let zero_usable = unsafe { allocator.usable_size(zeroed) }.unwrap();
            std::println!("trace.zero.request=37");
            std::println!("trace.zero.usable={zero_usable}");
            std::println!(
                "trace.zero.cleared={}",
                u8::from(unsafe { bytes_equal(zeroed, 37, 0) })
            );
            // SAFETY: `zeroed` remains current and uniquely owned here.
            unsafe { allocator.free(zeroed).unwrap() };

            let mut live = [NonNull::dangling(); 96];
            for (index, block) in live.iter_mut().enumerate() {
                *block = allocator.allocate(SMALL_SIZE_MAX, false).unwrap();
                // SAFETY: each element is a distinct current allocation.
                unsafe { core::ptr::write_bytes(block.as_ptr(), (index + 1) as u8, SMALL_SIZE_MAX) };
            }
            let mut preserved = true;
            for (index, block) in live.iter().copied().enumerate() {
                preserved &= unsafe { bytes_equal(block, SMALL_SIZE_MAX, (index + 1) as u8) };
            }
            for ordinal in 0..96 {
                let index = (ordinal * 37) % 96;
                // SAFETY: the permutation visits every current allocation once.
                unsafe { allocator.free(live[index]).unwrap() };
            }
            std::println!("trace.repeat.count=96");
            std::println!("trace.repeat.fill_preserved={}", u8::from(preserved));
            std::println!("CRABC_MI_SMALL_TRACE_END");
        });
    }

    #[test]
    fn generic_page_kinds_publish_the_exact_span_and_good_size_boundaries() {
        with_allocator(|allocator| {
            let requests = [
                SMALL_SIZE_MAX,
                SMALL_SIZE_MAX + 1,
                SMALL_MAX_OBJ_SIZE - 1,
                SMALL_MAX_OBJ_SIZE,
                SMALL_MAX_OBJ_SIZE + 1,
                MEDIUM_MAX_OBJ_SIZE - 1,
                MEDIUM_MAX_OBJ_SIZE,
                MEDIUM_MAX_OBJ_SIZE + 1,
                LARGE_MAX_OBJ_SIZE - 1,
                LARGE_MAX_OBJ_SIZE,
                LARGE_MAX_OBJ_SIZE + 1,
            ];
            let mut starts = [null_mut(); 11];
            let mut start_count = 0usize;

            for request in requests {
                let block = allocator.allocate(request, false).unwrap();
                let expected_usable = if request <= LARGE_MAX_OBJ_SIZE {
                    size_class::good_size(
                        request,
                        allocator.page_map.memory_config().page_size().bytes(),
                    )
                    .unwrap()
                } else {
                    allocator.page_map.memory_config().good_alloc_size(request)
                };
                let expected_kind = size_class::page_kind_for_block_size(expected_usable).unwrap();
                let expected_slices = match expected_kind {
                    PageKind::Small | PageKind::Medium | PageKind::Large => {
                        page::regular_page_slice_count(expected_kind).unwrap()
                    }
                    PageKind::Singleton => page::singleton_page_slice_count(expected_usable).unwrap(),
                };
                assert_eq!(unsafe { allocator.usable_size(block) }, Some(expected_usable));
                let (start, size, block_size) = mapped_span(allocator, block, expected_kind);
                assert_eq!(size, expected_slices * ARENA_SLICE_SIZE);
                assert_eq!(block_size, expected_usable);
                starts[start_count] = start;
                start_count += 1;
                // SAFETY: each boundary allocation remains live exactly until
                // this matching local free below.
                unsafe { allocator.free(block).unwrap() };
            }

            assert!(allocator.collect_retired(true));
            for start in starts[..start_count].iter().copied() {
                // SAFETY: forced collection completed every retired page's
                // whole-span unregister transition before arena release.
                assert!(unsafe { allocator.page_map.checked_lookup(start) }.is_null());
            }
        });
    }

    #[test]
    fn generic_medium_and_large_full_pages_unfull_and_release_their_whole_spans() {
        with_allocator(|allocator| {
            for request in [SMALL_MAX_OBJ_SIZE + 1, MEDIUM_MAX_OBJ_SIZE + 1] {
                let first = allocator.allocate(request, false).unwrap();
                let expected_kind = if request <= MEDIUM_MAX_OBJ_SIZE {
                    PageKind::Medium
                } else {
                    PageKind::Large
                };
                let (start, size, block_size) = mapped_span(allocator, first, expected_kind);
                // SAFETY: `first` is current and maps to live metadata for the
                // following source-reserved count inspection.
                let page = unsafe { allocator.page_map.checked_lookup(first.as_ptr()).as_ref() }.unwrap();
                let count = page.reserved() as usize;
                assert!(count > 1 && count <= 64);
                let bin = size_class::bin(block_size).unwrap();
                let mut blocks = [NonNull::dangling(); 64];
                blocks[0] = first;
                for block in blocks.iter_mut().take(count).skip(1) {
                    *block = allocator.allocate(request, false).unwrap();
                }
                assert_eq!(allocator.queue_count(bin), Some(0));
                assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

                // Returning one block from a full regular page moves it to
                // its source size bin before the remaining local frees.
                unsafe { allocator.free(blocks[0]).unwrap() };
                assert_eq!(allocator.queue_count(bin), Some(1));
                assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
                for block in blocks.into_iter().take(count).skip(1) {
                    // SAFETY: every array slot names a distinct current block.
                    unsafe { allocator.free(block).unwrap() };
                }
                assert!(allocator.collect_retired(true));
                for offset in (0..size).step_by(ARENA_SLICE_SIZE) {
                    // SAFETY: source release unregistered the full span prior
                    // to returning the external arena slices.
                    assert!(unsafe { allocator.page_map.checked_lookup(start.wrapping_add(offset)) }.is_null());
                }
            }
        });
    }

    #[test]
    fn singleton_pages_use_the_huge_queue_and_release_without_retirement() {
        with_allocator(|allocator| {
            let request = LARGE_MAX_OBJ_SIZE + 1;
            let block = allocator.allocate(request, false).unwrap();
            let (start, size, _) = mapped_span(allocator, block, PageKind::Singleton);
            assert_eq!(allocator.queue_count(BIN_HUGE), Some(0));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            // SAFETY: a singleton's sole returned block leaves its full page
            // all free, so the special queue follows immediate release.
            unsafe { allocator.free(block).unwrap() };
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            for offset in (0..size).step_by(ARENA_SLICE_SIZE) {
                // SAFETY: special-page release unregisters every mapped slice.
                assert!(unsafe { allocator.page_map.checked_lookup(start.wrapping_add(offset)) }.is_null());
            }
        });
    }

    #[test]
    fn generic_zeroing_clears_a_reused_medium_block() {
        with_allocator(|allocator| {
            let request = SMALL_MAX_OBJ_SIZE + 1;
            let block = allocator.allocate(request, false).unwrap();
            // SAFETY: the current block has at least `request` writable bytes.
            unsafe { core::ptr::write_bytes(block.as_ptr(), 0xa5, request) };
            // SAFETY: return that exact local block once for reuse.
            unsafe { allocator.free(block).unwrap() };
            let zeroed = allocator.allocate_zeroed(request).unwrap();
            assert!(unsafe { bytes_equal(zeroed, request, 0) });
            // SAFETY: `zeroed` is still current and uniquely owned here.
            unsafe { allocator.free(zeroed).unwrap() };
        });
    }

    #[test]
    fn generic_fresh_failure_force_collects_retired_span_and_retries_once() {
        with_allocator(|allocator| {
            let retired_request = MEDIUM_MAX_OBJ_SIZE + 1;
            let retry_request = LARGE_MAX_OBJ_SIZE;
            let retired_size = size_class::good_size(
                retired_request,
                allocator.page_map.memory_config().page_size().bytes(),
            )
            .unwrap();
            let retry_size = size_class::good_size(
                retry_request,
                allocator.page_map.memory_config().page_size().bytes(),
            )
            .unwrap();
            assert_ne!(size_class::bin(retired_size), size_class::bin(retry_size));

            let retired = allocator.allocate(retired_request, false).unwrap();
            // SAFETY: returning the sole current block leaves this regular
            // large page source-retired but still arena-owned.
            unsafe { allocator.free(retired).unwrap() };

            // Claim every other usable slice. The different retry bin cannot
            // reuse the retired page, so its first fresh attempt fails. The
            // generic source path must force-collect, regain this exact
            // 64-slice span, and then retry once successfully.
            let mut held = Vec::new();
            while let Some(claim) = allocator
                .arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            {
                held.push(claim);
            }
            let retried = allocator.allocate(retry_request, false).unwrap();
            assert_eq!(unsafe { allocator.usable_size(retried) }, Some(retry_size));
            // SAFETY: this is the exact current retry allocation.
            unsafe { allocator.free(retried).unwrap() };
            assert!(allocator.collect_retired(true));
            for claim in held {
                assert!(claim.release());
            }
        });
    }

    #[test]
    fn generic_small_queue_retains_full_pages_then_moves_a_reusable_candidate_to_front() {
        with_allocator(|allocator| {
            let request = SMALL_SIZE_MAX + 1;
            let bin = size_class::bin(request).unwrap();
            let first = allocator.allocate(request, false).unwrap();
            // SAFETY: the first allocation maps to a fresh live page whose
            // source-reserved count is stable until all test blocks return.
            let page = unsafe { allocator.page_map.checked_lookup(first.as_ptr()).as_ref() }.unwrap();
            let count = page.reserved() as usize;
            assert!(count > 1);
            let mut blocks = Vec::with_capacity(count * 4);
            blocks.push(first);
            while blocks.len() < count * 4 {
                blocks.push(allocator.allocate(request, false).unwrap());
            }

            // The fourth page is the queue head and full. The third page is
            // next and also full, until this local free supplies the scan's
            // first immediate candidate. The pinned retain count keeps the
            // earlier small full pages in the regular queue long enough for
            // the bounded candidate scan to reach it.
            let third_first = count * 2;
            let third_page = unsafe { allocator.page_map.checked_lookup(blocks[third_first].as_ptr()) };
            assert_eq!(allocator.session.queue(bin).unwrap().first(), unsafe {
                allocator.page_map.checked_lookup(blocks[count * 3].as_ptr())
            });
            // SAFETY: this one exact third-page block is still live.
            unsafe { allocator.free(blocks[third_first]).unwrap() };
            let reused = allocator.allocate(request, false).unwrap();
            assert_eq!(reused, blocks[third_first]);
            assert_eq!(allocator.session.queue(bin).unwrap().first(), third_page);
            blocks[third_first] = reused;

            for block in blocks {
                // SAFETY: each current allocation is returned exactly once;
                // the replaced third slot is the sole post-reuse owner.
                unsafe { allocator.free(block).unwrap() };
            }
            assert!(allocator.collect_retired(true));
        });
    }

    #[test]
    fn all_small_good_size_boundaries_select_the_source_direct_cache_page() {
        with_allocator(|allocator| {
            let (requests, count) = small_boundaries();
            for request in requests[..count].iter().copied() {
                let block = allocator.allocate(request, false).unwrap();
                let direct = invariants::word_count(request.max(WORD_SIZE)).unwrap();
                let mapped = unsafe { allocator.page_map.checked_lookup(block.as_ptr()) };
                assert_eq!(allocator.direct_page(direct), Some(mapped));
                // SAFETY: `block` is the exact current allocation for this
                // direct-cache assertion.
                unsafe { allocator.free(block).unwrap() };
            }
        });
    }

    #[test]
    fn zero_request_normalizes_to_distinct_naturally_aligned_word_blocks() {
        with_allocator(|allocator| {
            let first = allocator.allocate(0, false).unwrap();
            let second = allocator.allocate(0, false).unwrap();
            assert_ne!(first, second);
            assert_eq!(first.as_ptr().addr() % WORD_SIZE, 0);
            assert_eq!(second.as_ptr().addr() % WORD_SIZE, 0);
            // SAFETY: both blocks are current normalized word allocations.
            assert_eq!(unsafe { allocator.usable_size(first) }, Some(WORD_SIZE));
            assert_eq!(unsafe { allocator.usable_size(second) }, Some(WORD_SIZE));

            // SAFETY: each zero-size request still owns one normalized word
            // block and is returned exactly once.
            unsafe {
                allocator.free(first).unwrap();
                allocator.free(second).unwrap();
            }
        });
    }

    #[test]
    fn local_free_moves_a_full_page_back_to_its_regular_queue() {
        with_allocator(|allocator| {
            // A generic medium page takes the source full-queue transition
            // on its final allocation; small pages intentionally retain a
            // bounded number of full regular members.
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator.allocate(request, false).unwrap();
            // SAFETY: `first` remains current while this fixture fills its
            // exact page, then takes one block from the successor.
            let page = NonNull::new(unsafe { allocator.page_for_block(first) }).unwrap();
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(capacity + 1);
            blocks.push(first);
            while blocks.len() <= capacity {
                blocks.push(allocator.allocate(request, false).unwrap());
            }
            let bin = size_class::bin(request).unwrap();
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            // SAFETY: only this element is returned; it makes the retained
            // full page usable again while the remaining blocks stay live.
            unsafe { allocator.free(blocks[0]).unwrap() };
            assert_eq!(allocator.queue_count(bin), Some(2));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            for block in blocks.into_iter().skip(1) {
                // SAFETY: every remaining element is still live exactly once.
                unsafe { allocator.free(block).unwrap() };
            }
        });
    }

    #[test]
    fn full_page_false_collection_reclaims_a_joined_remote_block_for_ordinary_reuse() {
        with_allocator(|allocator| {
            // A medium page enters `BIN_FULL` immediately when its final
            // generic allocation exhausts it; small-page retention is a
            // separate source policy and not this collector's subject.
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let bin = size_class::bin(request).unwrap();
            let first = allocator.allocate(request, false).unwrap();
            // SAFETY: `first` is a current allocation in this live exclusive
            // session; the page map retains its metadata through the scoped
            // producer and the following owner collection.
            let page = NonNull::new(unsafe { allocator.page_for_block(first) }).unwrap();
            let capacity = unsafe { page.as_ref().reserved() as usize };
            assert!(capacity > 1);

            // Consume the first medium page and allocate one block from its
            // successor. The next direct allocation moved the exhausted page
            // into BIN_FULL, exactly as the non-abandoning source branch does.
            let mut blocks = Vec::with_capacity(capacity + 1);
            blocks.push(first);
            while blocks.len() <= capacity {
                blocks.push(allocator.allocate(request, false).unwrap());
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { page.as_ref().used() }, capacity);

            // SAFETY: `first` is an exact current allocation from this live
            // allocator's full page. This transfers all client use to the
            // scoped producer until it publishes or cancels.
            let producer = unsafe { allocator.begin_remote_free(first) }
                .expect("the full live page admits one remote producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined
                    .join()
                    .expect("the scoped remote producer must not panic")
                {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let block = producer.cancel();
                        panic!("full live page rejected remote block {block:?}: {error:?}");
                    }
                }
            });

            // The source full-page collector detaches remote frees even when
            // no regular retirement range exists, then makes this page a
            // regular candidate. This assertion is red before that collector
            // is integrated: current `collect_retired(false)` strands it.
            assert!(allocator.collect_retired(false));
            assert_eq!(unsafe { page.as_ref().used() }, capacity - 1);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            assert_eq!(allocator.queue_count(bin), Some(2));

            // `mi_page_queue_enqueue_from_full` appends the reclaimed page,
            // so exhaust the one preceding regular page before the ordinary
            // allocator reaches the exact remotely returned block.
            let mut filler = Vec::with_capacity(capacity - 1);
            let reused = loop {
                let block = allocator.allocate(request, false).unwrap();
                if block == first {
                    break block;
                }
                filler.push(block);
            };
            assert_eq!(filler.len(), capacity - 1);
            blocks[0] = reused;

            for block in blocks.into_iter().chain(filler) {
                // SAFETY: the remote block was reclaimed into this ordinary
                // lifecycle exactly once, and every other block remains one
                // current allocation from this fixture.
                unsafe { allocator.free(block).unwrap() };
            }
        });
    }

    #[test]
    fn full_page_false_collection_releases_a_joined_remotely_empty_page() {
        with_allocator(|allocator| {
            // See the matching reuse regression: choose a medium page so the
            // source generic allocation transitions its exact full page.
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator.allocate(request, false).unwrap();
            // SAFETY: `first` is a current allocation from this live owner
            // session. The page map and arena retain its complete page while
            // the scoped producers publish and the owner collects.
            let page = NonNull::new(unsafe { allocator.page_for_block(first) }).unwrap();
            let capacity = unsafe { page.as_ref().reserved() as usize };
            assert!(capacity > 1);

            // Fill this page and take one allocation from its successor so
            // the full queue owns exactly this first page.
            let mut blocks = Vec::with_capacity(capacity + 1);
            blocks.push(first);
            while blocks.len() <= capacity {
                blocks.push(allocator.allocate(request, false).unwrap());
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            let page_count_before = allocator.session.theap().page_count();

            for block in blocks[..capacity].iter().copied() {
                // SAFETY: this exact full-page allocation transfers only to
                // the one scoped worker. Publishing/joining each token before
                // creating the next keeps the mutable owner borrow linear.
                let producer = unsafe { allocator.begin_remote_free(block) }
                    .expect("the full live page admits each remote producer");
                thread::scope(|scope| {
                    let joined = scope.spawn(move || producer.publish());
                    match joined
                        .join()
                        .expect("the scoped remote producer must not panic")
                    {
                        Ok(()) => {}
                        Err((producer, error)) => {
                            let block = producer.cancel();
                            panic!("full live page rejected remote block {block:?}: {error:?}");
                        }
                    }
                });
            }

            // `mi_theap_collect_full_pages` saves `next`, collects, and then
            // takes its all-free `_mi_page_free` branch. Do not dereference
            // `page` after this point: its metadata and backing are retired.
            assert!(allocator.collect_retired(false));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            assert_eq!(allocator.session.theap().page_count(), page_count_before - 1);
            // SAFETY: page-map lookup is an owner observation only; this
            // exact block address was unregistered before release.
            assert!(unsafe { allocator.page_map.checked_lookup(first.as_ptr()) }.is_null());

            let successor = blocks.pop().unwrap();
            drop(blocks);
            // SAFETY: the successor remains the one current allocation not
            // published remotely; the released page's former blocks are gone.
            unsafe { allocator.free(successor).unwrap() };
        });
    }

    #[test]
    fn full_page_remote_producer_is_send() {
        fn assert_send<T: Send>() {}

        assert_send::<RemoteFreeProducer<'static>>();
    }

    #[test]
    fn regular_generic_remote_publication_is_collected_before_full_classification() {
        with_allocator(|allocator| {
            let request = SMALL_SIZE_MAX + 1;
            let block = allocator.allocate(request, false).unwrap();
            // SAFETY: this current generic allocation remains map-published
            // while the scoped producer and owner-side queue search run.
            let page = NonNull::new(unsafe { allocator.page_for_block(block) }).unwrap();
            let capacity = unsafe { page.as_ref().capacity() as usize };
            assert!(capacity < unsafe { page.as_ref().reserved() as usize });
            let mut local_blocks = Vec::with_capacity(capacity);
            local_blocks.push(block);
            while unsafe { page.as_ref().used() } < capacity {
                let next = allocator.allocate(request, false).unwrap();
                assert_eq!(unsafe { allocator.page_for_block(next) }, page.as_ptr());
                local_blocks.push(next);
            }
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            let bin = size_class::bin(unsafe { page.as_ref().block_size() }).unwrap();
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));

            // SAFETY: this exact live regular allocation transfers only to
            // the joined scoped producer. The generic source route must
            // detach it before it decides this no-immediate page is full.
            let producer = unsafe { allocator.begin_remote_free(block) }
                .expect("the regular generic page should admit its producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined
                    .join()
                    .expect("the scoped remote producer must not panic")
                {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let block = producer.cancel();
                        panic!("regular generic page rejected remote block {block:?}: {error:?}");
                    }
                }
            });

            // A regular page with a remotely published live block is not all
            // free yet: forced retirement must preserve its map and queue
            // until the exact generic search consumes the publication.
            assert!(allocator.collect_retired(true));
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));

            let reused = allocator
                .allocate(request, false)
                .expect("generic search must collect and reuse the remote block");
            assert_eq!(reused, block);
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));

            // SAFETY: owner-side collection returned the exact published
            // allocation once, so this is its matching local free.
            unsafe { allocator.free(reused).unwrap() };
            for local in local_blocks.into_iter().skip(1) {
                // SAFETY: these sibling allocations were never transferred
                // and remain exact current local blocks on this page.
                unsafe { allocator.free(local).unwrap() };
            }
        });
    }

    #[test]
    fn page_to_full_collects_a_remote_publication_after_the_enqueue() {
        with_allocator(|allocator| {
            // A medium page reaches BIN_FULL on its final generic pop. Fill
            // it and take one successor allocation so the source local free
            // can unfull the exact first page below.
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator.allocate(request, false).unwrap();
            // SAFETY: this current allocation's map-published page stays live
            // through the joined producer, owner-side move, and cleanup.
            let page = NonNull::new(unsafe { allocator.page_for_block(first) }).unwrap();
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let bin = size_class::bin(request).unwrap();
            let mut blocks = Vec::with_capacity(capacity + 1);
            blocks.push(first);
            while blocks.len() <= capacity {
                blocks.push(allocator.allocate(request, false).unwrap());
            }
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // SAFETY: this local free moves the exact full page back to its
            // regular queue while preserving its block in local_free.
            unsafe { allocator.free(blocks[0]).unwrap() };
            assert_eq!(unsafe { page.as_ref().used() }, capacity - 1);
            assert_eq!(allocator.queue_count(bin), Some(2));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));

            // The source unfull operation appends the target after the one
            // successor regular page. Fill that successor first so the next
            // ordinary generic allocation must exercise the target's head
            // quick-collect and later page-to-full transition.
            let successor = NonNull::new(unsafe { allocator.page_for_block(blocks[capacity]) })
                .expect("the successor allocation remains map-published");
            while unsafe { successor.as_ref().used() }
                < unsafe { successor.as_ref().reserved() as usize }
            {
                let filler = allocator
                    .allocate(request, false)
                    .expect("the successor page has an immediate block");
                assert_eq!(unsafe { allocator.page_for_block(filler) }, successor.as_ptr());
                blocks.push(filler);
            }
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // SAFETY: this distinct current allocation remains live on the
            // now-regular page until its scoped producer publishes it.
            let producer = unsafe { allocator.begin_remote_free(blocks[1]) }
                .expect("the unfull regular page admits the remote producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined
                    .join()
                    .expect("the scoped remote producer must not panic")
                {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let block = producer.cancel();
                        panic!("post-enqueue remote block {block:?} was rejected: {error:?}");
                    }
                }
            });

            // The head quick-collect chooses the local free block without
            // touching the remote head. Its pop makes the page full again;
            // `mi_page_to_full` must then do its second false-force collection
            // after enqueue, installing the remote block and lowering used.
            let local_reused = allocator
                .allocate(request, false)
                .expect("the regular local-free block remains reusable");
            assert_eq!(local_reused, blocks[0]);
            assert_eq!(unsafe { page.as_ref().used() }, capacity - 1);
            assert_eq!(
                unsafe { page.as_ref().free_list_head().cast::<u8>() },
                blocks[1].as_ptr(),
            );
            assert_eq!(allocator.queue_count(bin), Some(0));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));

            // The ordinary non-abandoning full pass later unfulls this page.
            // It can then return the exact remote block to local ownership.
            assert!(allocator.collect_retired(false));
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            let remote_reused = allocator
                .allocate(request, false)
                .expect("the post-enqueue collected remote block is reusable");
            assert_eq!(remote_reused, blocks[1]);
            blocks[0] = local_reused;
            blocks[1] = remote_reused;
            for block in blocks {
                // SAFETY: both published blocks were reclaimed exactly once,
                // and every remaining fixture block stayed locally owned.
                unsafe { allocator.free(block).unwrap() };
            }
        });
    }

    #[test]
    fn page_to_full_collection_failure_permanently_retains_the_popped_block() {
        with_allocator(|allocator| {
            // Match the post-enqueue source transition above: target is the
            // only regular page, with one local head and a distinct remote
            // publication, while its successor stays full.
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator.allocate(request, false).unwrap();
            let page = NonNull::new(unsafe { allocator.page_for_block(first) }).unwrap();
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let bin = size_class::bin(request).unwrap();
            let mut blocks = Vec::with_capacity(capacity + 1);
            blocks.push(first);
            while blocks.len() <= capacity {
                blocks.push(allocator.allocate(request, false).unwrap());
            }
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // SAFETY: this exact local free unfulls only the target page.
            unsafe { allocator.free(blocks[0]).unwrap() };
            let successor = NonNull::new(unsafe { allocator.page_for_block(blocks[capacity]) })
                .expect("the successor remains map-published");
            while unsafe { successor.as_ref().used() }
                < unsafe { successor.as_ref().reserved() as usize }
            {
                let filler = allocator
                    .allocate(request, false)
                    .expect("the successor has an immediate block");
                assert_eq!(unsafe { allocator.page_for_block(filler) }, successor.as_ptr());
                blocks.push(filler);
            }
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // SAFETY: the remote block remains current on the one regular
            // target page until the scoped producer consumes its token.
            let producer = unsafe { allocator.begin_remote_free(blocks[1]) }
                .expect("the target regular page admits the remote producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined
                    .join()
                    .expect("the scoped remote producer must not panic")
                {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let block = producer.cancel();
                        panic!("post-enqueue remote block {block:?} was rejected: {error:?}");
                    }
                }
            });

            // `page_quick_collect` first pops the local head. The next
            // source collection is `mi_page_to_full`'s post-enqueue
            // false-force pass; make that pass fail before remote detach.
            allocator.inject_page_free_collect_failure_once();
            assert_eq!(allocator.allocate(request, false), None);
            let retained = allocator
                .retained_page_collect_poison()
                .expect("the post-enqueue failure must retain terminal state");
            assert_eq!(retained.page, page);
            assert_eq!(retained.error, PageCollectError::InjectedBeforeDetach);
            assert_eq!(retained.popped_block, Some(blocks[0]));
            assert!(
                retained.test_recoverable,
                "only the injected pre-detach failure permits fixture cleanup"
            );
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            assert!(unsafe { page.as_ref().free_list_head().is_null() });
            assert_eq!(allocator.queue_count(bin), Some(0));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));

            // Every production entry point stops before page-map, queue, or
            // local-list mutation while the exact failure record is retained.
            let used_before = unsafe { page.as_ref().used() };
            let free_before = unsafe { page.as_ref().free_list_head() };
            assert_eq!(allocator.allocate_zeroed_count(1, request), None);
            assert_eq!(allocator.allocate_aligned(request, WORD_SIZE), None);
            assert_eq!(unsafe { allocator.reallocate(Some(blocks[2]), request) }, None);
            assert_eq!(unsafe { allocator.usable_size(blocks[2]) }, None);
            assert_eq!(
                unsafe { allocator.free(blocks[2]) },
                Err(FreeError::CollectionPoisoned)
            );
            assert!(matches!(
                unsafe { allocator.begin_remote_free(blocks[2]) },
                Err(RemoteFreePreparationError::CollectionPoisoned)
            ));
            assert!(!allocator.collect_retired(false));
            assert_eq!(unsafe { page.as_ref().used() }, used_before);
            assert_eq!(unsafe { page.as_ref().free_list_head() }, free_before);
            assert_eq!(allocator.queue_count(bin), Some(0));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));

            // The test-only injection failed before remote detach, so this
            // fixture may explicitly remove the record and resume only to
            // return its already-known blocks. Production has no such path.
            let retained = allocator
                .take_page_collect_poison_for_fixture_cleanup()
                .expect("the fixture must take its own injected record");
            let popped = retained
                .popped_block
                .expect("the failed post-enqueue pop remains retained");
            assert!(allocator.collect_retired(false));
            // SAFETY: after the joined remote collection, `popped` and every
            // non-remote fixture block remains one exact local allocation.
            unsafe { allocator.free(popped).unwrap() };
            for block in blocks.into_iter().skip(2) {
                // SAFETY: the second fixture block was consumed by remote
                // collection; every later block was never transferred or freed.
                unsafe { allocator.free(block).unwrap() };
            }
            assert!(allocator.collect_retired(true));
        });
    }

    #[test]
    fn small_direct_remote_publication_retries_the_direct_page_before_full_transition() {
        with_allocator(|allocator| {
            let request = SMALL_SIZE_MAX;
            let block = allocator.allocate(request, false).unwrap();
            // SAFETY: this is the current direct-cache allocation; the test
            // retains its map-published page through the joined producer.
            let page = NonNull::new(unsafe { allocator.page_for_block(block) }).unwrap();
            let capacity = unsafe { page.as_ref().capacity() as usize };
            assert!(capacity < unsafe { page.as_ref().reserved() as usize });
            let mut local_blocks = Vec::with_capacity(capacity);
            local_blocks.push(block);
            while unsafe { page.as_ref().used() } < capacity {
                let next = allocator.allocate(request, false).unwrap();
                assert_eq!(unsafe { allocator.page_for_block(next) }, page.as_ptr());
                local_blocks.push(next);
            }
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            let bin = size_class::bin(unsafe { page.as_ref().block_size() }).unwrap();
            let direct = invariants::word_count(request.max(WORD_SIZE)).unwrap();
            assert_eq!(allocator.direct_page(direct), Some(page.as_ptr()));
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));

            // SAFETY: this exact regular direct allocation transfers only to
            // the joined producer. Its next direct fallback must collect it
            // before it could classify the page as full.
            let producer = unsafe { allocator.begin_remote_free(block) }
                .expect("the regular direct page should admit its producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined
                    .join()
                    .expect("the scoped remote producer must not panic")
                {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let block = producer.cancel();
                        panic!("regular direct page rejected remote block {block:?}: {error:?}");
                    }
                }
            });

            let reused = allocator
                .allocate(request, false)
                .expect("direct fallback must collect and reuse the remote block");
            assert_eq!(
                reused,
                block,
                "direct fallback selected page={:?}, origin={:?}, regular={:?}, full={:?}, used={}",
                unsafe { allocator.page_for_block(reused) },
                page.as_ptr(),
                allocator.queue_count(bin),
                allocator.queue_count(BIN_FULL),
                unsafe { page.as_ref().used() },
            );
            assert_eq!(unsafe { page.as_ref().used() }, capacity);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));

            // SAFETY: the direct fallback returned this one allocation to
            // local ownership, so this balances the live page normally.
            unsafe { allocator.free(reused).unwrap() };
            for local in local_blocks.into_iter().skip(1) {
                // SAFETY: these sibling allocations were never transferred
                // and remain exact current local blocks on this page.
                unsafe { allocator.free(local).unwrap() };
            }
        });
    }

    #[test]
    fn detached_session_rejects_remote_producer_without_mutation() {
        with_detached_allocator(|allocator| {
            let block = allocator.allocate(SMALL_SIZE_MAX, false).unwrap();
            // SAFETY: this detached fixture remains externally serialized;
            // lookup observes the exact registered local allocation page.
            let page = NonNull::new(unsafe { allocator.page_for_block(block) }).unwrap();
            let used_before = unsafe { page.as_ref().used() };

            // SAFETY: the block is exact/current, but the detached metadata
            // session has no remote producer path by contract.
            assert!(matches!(
                unsafe { allocator.begin_remote_free(block) },
                Err(RemoteFreePreparationError::DetachedSession)
            ));
            assert_eq!(unsafe { page.as_ref().used() }, used_before);

            // SAFETY: detached rejection did not publish or transfer the
            // client allocation, so ordinary local free remains valid.
            unsafe { allocator.free(block).unwrap() };
        });
    }

    #[test]
    fn remote_producer_rejects_an_unlinked_regular_page_without_mutation() {
        with_allocator(|allocator| {
            let request = SMALL_SIZE_MAX;
            let block = allocator.allocate(request, false).unwrap();
            // SAFETY: this current direct allocation remains map-published
            // while the fixture temporarily removes only its queue link.
            let page = NonNull::new(unsafe { allocator.page_for_block(block) }).unwrap();
            let bin = size_class::bin(unsafe { page.as_ref().block_size() }).unwrap();
            let direct = invariants::word_count(request).unwrap();
            let used_before = unsafe { page.as_ref().used() };
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.direct_page(direct), Some(page.as_ptr()));

            let queue = allocator
                .session
                .queue_mut(bin)
                .expect("the active regular bin exists") as *mut _;
            // SAFETY: the exclusive fixture owns this queue and exact member;
            // unlinking it models a stale/unrouted page without touching its
            // map, free-list, or allocation state.
            unsafe { page_queue_remove_metadata(&mut *queue, page.as_ptr()) };
            allocator.update_direct_cache(bin);
            assert_eq!(allocator.queue_count(bin), Some(0));

            // SAFETY: `block` remains exact/current, but this unlinked page
            // lacks either bounded owner-side collection route.
            assert!(matches!(
                unsafe { allocator.begin_remote_free(block) },
                Err(RemoteFreePreparationError::PageNotInCollectibleQueue)
            ));
            assert_eq!(unsafe { page.as_ref().used() }, used_before);
            assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());

            // SAFETY: no producer was created, so this restores exactly the
            // unmodified live page to its original regular queue and cache.
            unsafe { page_queue_push_metadata(&mut *queue, page.as_ptr()) };
            allocator.update_direct_cache(bin);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.direct_page(direct), Some(page.as_ptr()));

            // SAFETY: rejected preparation retained local ownership of this
            // exact original allocation.
            unsafe { allocator.free(block).unwrap() };
        });
    }

    #[test]
    fn full_page_remote_producer_cancellation_restores_the_original_interior_client() {
        with_allocator(|allocator| {
            let client = allocator
                .allocate_aligned_at(SMALL_MAX_OBJ_SIZE, 64, 1)
                .unwrap();
            // The source offset alignment equation forces this client address
            // away from the word-aligned canonical free-list block.
            assert_eq!(client.as_ptr().addr().wrapping_add(1) & 63, 0);
            // SAFETY: `client` is the current adjusted allocation and the map
            // retains its page through the following full-page setup.
            let page = NonNull::new(unsafe { allocator.page_for_block(client) }).unwrap();
            assert!(unsafe { page.as_ref().has_interior_pointers() });
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let mut fillers = Vec::with_capacity(capacity);
            while fillers.len() + 1 < capacity {
                fillers.push(
                    allocator
                        .allocate_aligned_at(SMALL_MAX_OBJ_SIZE, 64, 1)
                        .unwrap(),
                );
            }
            let successor = allocator
                .allocate_aligned_at(SMALL_MAX_OBJ_SIZE, 64, 1)
                .unwrap();
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // SAFETY: `client` is one exact full-page allocation transferred
            // to the token. No producer is started, so cancellation must
            // return the unadjusted client pointer without mutation.
            let producer = unsafe { allocator.begin_remote_free(client) }
                .expect("the full live adjusted page admits one producer");
            assert_ne!(producer.canonical_block, client);
            assert_eq!(producer.client_block, client);
            let restored = producer.cancel();
            assert_eq!(restored, client);
            assert_eq!(unsafe { page.as_ref().used() }, capacity);

            // SAFETY: cancellation restored the exact adjusted client pointer
            // to local ownership; free must recover its canonical base and
            // make the formerly full page regular again.
            unsafe { allocator.free(restored).unwrap() };
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            for block in fillers {
                // SAFETY: these are the remaining distinct current blocks on
                // the same page, still locally owned after cancellation.
                unsafe { allocator.free(block).unwrap() };
            }
            // SAFETY: this separate current allocation made the original
            // page full and remains local throughout the test.
            unsafe { allocator.free(successor).unwrap() };
        });
    }

    #[test]
    fn detached_full_page_collection_skips_the_live_remote_protocol() {
        with_detached_allocator(|allocator| {
            // A medium generic page reaches the exact `BIN_FULL` collector
            // branch without depending on small-page retention.
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator.allocate(request, false).unwrap();
            // SAFETY: this is one current allocation in the externally
            // serialized detached session; its page remains map-published
            // through the collection and following local cleanup.
            let page = NonNull::new(unsafe { allocator.page_for_block(first) }).unwrap();
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(capacity + 1);
            blocks.push(first);
            while blocks.len() <= capacity {
                blocks.push(allocator.allocate(request, false).unwrap());
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // The detached bootstrap has no remote-free path. The source
            // full-page pass must therefore preserve its local false-force
            // decision instead of attempting the live-owner remote protocol.
            let collected = allocator.collect_retired(false);

            for block in blocks {
                // SAFETY: every block remains one distinct current local
                // allocation. This cleanup runs before the red assertion, so
                // an intentionally failing pre-fix test does not strand a
                // page-map entry or arena span.
                unsafe { allocator.free(block).unwrap() };
            }
            assert!(allocator.collect_retired(true));
            assert!(collected);
        });
    }

    #[test]
    fn forced_collection_unregisters_before_releasing_the_external_slice() {
        with_allocator(|allocator| {
            let block = allocator.allocate(37, false).unwrap();
            // SAFETY: the block is current and returned once.
            unsafe { allocator.free(block).unwrap() };
            assert!(allocator.collect_retired(true));
            // SAFETY: collection is complete and the prior page-map range has
            // been explicitly unregistered before the arena slice release.
            assert!(unsafe { allocator.page_map.checked_lookup(block.as_ptr()) }.is_null());
        });
    }

    #[test]
    fn zeroing_clears_reused_local_blocks_and_invalid_free_does_not_mutate_state() {
        with_allocator(|allocator| {
            let block = allocator.allocate(37, false).unwrap();
            // SAFETY: this current block can receive the test payload.
            unsafe { core::ptr::write_bytes(block.as_ptr(), 0xa5, 37) };
            // SAFETY: the block is returned once to make it a local-free node.
            unsafe { allocator.free(block).unwrap() };
            let zeroed = allocator.allocate_zeroed(37).unwrap();
            assert!(unsafe { bytes_equal(zeroed, 37, 0) });
            let invalid = NonNull::new(unsafe { zeroed.as_ptr().add(1) }).unwrap();
            // SAFETY: this intentionally violates the exact-block requirement;
            // the implementation must reject it before changing list state.
            assert_eq!(unsafe { allocator.free(invalid) }, Err(FreeError::InvalidBlock(FreeListError::InvalidBlock)));
            // SAFETY: `zeroed` is still live after the rejected invalid free.
            unsafe { allocator.free(zeroed).unwrap() };
        });
    }

    #[test]
    fn counted_zero_allocation_checks_overflow_and_clears_the_full_live_block() {
        with_allocator(|allocator| {
            assert!(allocator.allocate_zeroed_count(usize::MAX, 2).is_none());
            assert!(allocator
                .allocate_aligned_zeroed_count_at(usize::MAX, 2, 64, 7)
                .is_none());

            let counted = allocator.allocate_zeroed_count(3, 17).unwrap();
            let counted_usable = unsafe { allocator.usable_size(counted) }.unwrap();
            assert!(counted_usable >= 51);
            assert!(unsafe { bytes_equal(counted, counted_usable, 0) });

            let aligned_counted = allocator
                .allocate_aligned_zeroed_count(2, 17, 64)
                .unwrap();
            assert_eq!(aligned_counted.as_ptr().addr() & 63, 0);
            let aligned_counted_usable = unsafe { allocator.usable_size(aligned_counted) }.unwrap();
            assert!(aligned_counted_usable >= 34);
            assert!(unsafe { bytes_equal(aligned_counted, aligned_counted_usable, 0) });

            let aligned_zeroed = allocator.allocate_aligned_zeroed(17, 32).unwrap();
            assert_eq!(aligned_zeroed.as_ptr().addr() & 31, 0);
            let aligned_zeroed_usable = unsafe { allocator.usable_size(aligned_zeroed) }.unwrap();
            assert!(unsafe { bytes_equal(aligned_zeroed, aligned_zeroed_usable, 0) });

            let max_aligned = allocator
                .allocate_aligned_zeroed_at(7, PAGE_MAX_OVERALLOC_ALIGN, 3)
                .unwrap();
            assert_eq!(
                max_aligned.as_ptr().addr().wrapping_add(3) & (PAGE_MAX_OVERALLOC_ALIGN - 1),
                0,
            );
            let max_usable = unsafe { allocator.usable_size(max_aligned) }.unwrap();
            assert!(max_usable >= 7);
            assert!(unsafe { bytes_equal(max_aligned, max_usable, 0) });

            // `alloc-aligned.c` rejects this metadata-limit boundary rather
            // than attempting an OS singleton whose metadata prefix cannot
            // safely represent the source layout.
            assert!(allocator
                .allocate_aligned(7, 256 * MIB)
                .is_none());

            // SAFETY: each pointer is a distinct current allocation.
            unsafe { allocator.free(counted).unwrap() };
            unsafe { allocator.free(aligned_counted).unwrap() };
            unsafe { allocator.free(aligned_zeroed).unwrap() };
            unsafe { allocator.free(max_aligned).unwrap() };
        });
    }

    #[test]
    fn os_aligned_singletons_publish_clipped_maps_aliases_and_reclaim_their_mapping() {
        with_allocator(|allocator| {
            for (request, alignment, aliases_expected) in [
                (7usize, 128 * KIB, false),
                (3 * ARENA_SLICE_SIZE, MIB, true),
            ] {
                let block = allocator.allocate_aligned(request, alignment).unwrap();
                assert_eq!(block.as_ptr().addr() & (alignment - 1), 0);
                // SAFETY: this current allocation retains the complete primary
                // page metadata and its source-clipped map registration.
                let primary = unsafe { allocator.page_map.checked_lookup(block.as_ptr()) };
                let primary = NonNull::new(primary).unwrap();
                let page = unsafe { primary.as_ref() };
                let expected_request = match aligned::allocation_plan(
                    request,
                    alignment,
                    0,
                    allocator.page_map.memory_config().page_size().bytes(),
                ) {
                    Some(aligned::AlignedAllocationPlan::HugeSingleton { request, .. }) => request,
                    plan => panic!("expected OS-aligned singleton plan, got {plan:?}"),
                };
                let expected_block_size = allocator
                    .page_map
                    .memory_config()
                    .good_alloc_size(expected_request);
                assert_eq!(page.block_size(), expected_block_size);
                assert_eq!(page.reserved(), 1);
                assert_eq!(page.slice_pcommitted(), 0);
                assert!(page.memid().is_os());
                assert_eq!(page.aligned_alias_owner(), primary.as_ptr());
                assert_eq!(unsafe { page.start() }, block.as_ptr());

                // SAFETY: the primary is live, exclusive, and still has every
                // published map/metadata predecessor required by this exact
                // reconstruction.
                let published = unsafe {
                    PublishedOsAlignedPage::from_page(
                        allocator.page_map.memory_config(),
                        primary,
                    )
                }
                .unwrap();
                let layout = published.layout();
                assert_eq!(layout.block_size(), expected_block_size);
                assert_eq!(layout.alignment(), alignment);
                assert_eq!(layout.metadata_slot_count() > 1, aliases_expected);
                let slice_start = published.slice_start();
                for offset in (0..layout.page_map_size()).step_by(ARENA_SLICE_SIZE) {
                    // SAFETY: source map registration remains live until the
                    // matching local free below triggers terminal release.
                    assert_eq!(
                        unsafe {
                            allocator
                                .page_map
                                .checked_lookup(slice_start.as_ptr().wrapping_add(offset))
                        },
                        primary.as_ptr(),
                    );
                }
                if aliases_expected {
                    let base = slice_start.as_ptr().wrapping_sub(layout.alignment());
                    let alias_offset = layout
                        .metadata_offset()
                        .checked_add(core::mem::size_of::<Page>())
                        .unwrap();
                    // SAFETY: this second committed metadata slot is a live
                    // source alias until terminal release clears it before
                    // reclaiming the containing OS mapping.
                    let alias = unsafe { &*base.wrapping_add(alias_offset).cast::<Page>() };
                    assert_eq!(alias.aligned_alias_owner(), primary.as_ptr());
                }

                // SAFETY: a singleton is full after its sole allocation, so
                // this free executes the immediate full-page terminal order:
                // clipped unregister, aliases clear, primary retire, exact
                // published-mapping reclaim.
                unsafe { allocator.free(block).unwrap() };
                for offset in (0..layout.page_map_size()).step_by(ARENA_SLICE_SIZE) {
                    // SAFETY: lookup is integer-indexed and the source-clipped
                    // entry was cleared before the mapping was unmapped.
                    assert!(unsafe {
                        allocator
                            .page_map
                            .checked_lookup(slice_start.as_ptr().wrapping_add(offset))
                    }
                    .is_null());
                }
            }

            // The last valid power-of-two below the metadata limit stays on
            // the OS-aligned route; the exact 256 MiB limit is rejected.
            let near_limit = allocator.allocate_aligned(7, 128 * MIB).unwrap();
            assert_eq!(near_limit.as_ptr().addr() & (128 * MIB - 1), 0);
            unsafe { allocator.free(near_limit).unwrap() };
            assert!(allocator.allocate_aligned(7, 256 * MIB).is_none());
        });
    }

    #[test]
    fn os_aligned_reclaim_failure_parks_the_detached_owner_for_retry() {
        let fault = fault::install(fault::Plan::disabled());
        with_allocator(|allocator| {
            let block = allocator.allocate_aligned(7, 128 * KIB).unwrap();
            fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
            // SAFETY: this is the sole live block in the OS singleton. The
            // terminal release detaches all metadata before the injected
            // reclaim error parks its unique mapping owner.
            unsafe { allocator.free(block).unwrap() };
            assert!(allocator.has_pending_os_release());
            // The semantic free cleared lookup before parking, so the same
            // pointer can no longer be accepted as a current allocation.
            assert_eq!(unsafe { allocator.free(block) }, Err(FreeError::Unmapped));
            // Reclaim must succeed before another OS-aligned claim can begin.
            // Keep the injected `unmap` failure active for this allocation's
            // mandatory pending-owner retry, while an arena allocation stays
            // independent of the OS singleton release provenance.
            fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
            assert!(allocator.allocate_aligned(7, 128 * KIB).is_none());
            assert!(allocator.has_pending_os_release());
            let arena_block = allocator.allocate(37, false).unwrap();
            // SAFETY: this ordinary block is current and arena-owned.
            unsafe { allocator.free(arena_block).unwrap() };
            // Re-arm the same source `Unmap` seam to prove collection leaves
            // the exact parked owner available while release failure persists.
            fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
            assert!(!allocator.collect_retired(true));

            fault.set(fault::Plan::disabled());
            assert!(allocator.collect_retired(true));
            assert!(!allocator.has_pending_os_release());
        });
    }

    #[test]
    fn failed_os_claim_commit_cleanup_parks_the_unpublished_owner_for_retry() {
        let fault = fault::install(fault::Plan::disabled());
        with_allocator(|allocator| {
            // The paired seam first rejects metadata commit, then rejects the
            // claim's required rollback unmap. The failure must return no
            // allocation while retaining the exact unpublished mapping owner.
            fault.set(fault::Plan::at_pair(
                fault::Point::Commit,
                1,
                fault::Point::Unmap,
                1,
                Errno::NOMEM,
            ));
            assert!(allocator.allocate_aligned(7, 128 * KIB).is_none());
            assert!(allocator.has_pending_os_release());

            // A still-failing retry blocks only another OS singleton claim;
            // arena allocation does not share that release owner.
            fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
            assert!(allocator.allocate_aligned(7, 128 * KIB).is_none());
            let arena_block = allocator.allocate(37, false).unwrap();
            // SAFETY: `arena_block` is a distinct live arena allocation.
            unsafe { allocator.free(arena_block).unwrap() };

            fault.set(fault::Plan::disabled());
            assert!(allocator.collect_retired(true));
            assert!(!allocator.has_pending_os_release());
        });
    }

    #[test]
    fn aligned_small_head_natural_and_overallocated_blocks_keep_their_base_contract() {
        with_allocator(|allocator| {
            let ordinary = allocator.allocate(17, false).unwrap();
            let direct = invariants::word_count(17).unwrap();
            let page = allocator.direct_page(direct).unwrap();
            // SAFETY: `ordinary` is still current and this page is its exact
            // source direct-cache page before the local free below.
            let ordinary_page = unsafe { allocator.page_map.checked_lookup(ordinary.as_ptr()) };
            assert_eq!(ordinary_page, page);
            // SAFETY: return the exact allocation to make it the immediate
            // source free-list head consumed by the aligned fast path.
            unsafe { allocator.free(ordinary).unwrap() };
            let head = unsafe { NonNull::new((*page).free_list_head().cast::<u8>()) }.unwrap();
            assert_eq!(head.as_ptr().addr() & (MAX_ALIGN_SIZE - 1), 0);

            let fast = allocator.allocate_aligned_at(17, MAX_ALIGN_SIZE, 0).unwrap();
            assert_eq!(fast, head);
            assert_eq!(fast.as_ptr().addr() & (MAX_ALIGN_SIZE - 1), 0);

            // This empty direct cache takes the source natural-alignment
            // branch rather than the opportunistic existing-head branch.
            let natural = allocator.allocate_aligned(31, MAX_ALIGN_SIZE).unwrap();
            assert_eq!(natural.as_ptr().addr() & (MAX_ALIGN_SIZE - 1), 0);

            // An ordinary base allocation and two offset-aligned allocations
            // share the overallocated 80-byte page. The page-wide marker must
            // allow base and adjusted frees and remain true until all adjusted
            // owners have returned.
            let base = allocator.allocate(80, false).unwrap();
            let adjusted_one = allocator.allocate_aligned_at(17, 64, 7).unwrap();
            let adjusted_two = allocator.allocate_aligned_at(17, 64, 7).unwrap();
            assert_eq!(adjusted_one.as_ptr().addr().wrapping_add(7) & 63, 0);
            assert_eq!(adjusted_two.as_ptr().addr().wrapping_add(7) & 63, 0);
            let adjusted_page = unsafe { allocator.page_map.checked_lookup(adjusted_one.as_ptr()) };
            assert_eq!(adjusted_page, unsafe { allocator.page_map.checked_lookup(base.as_ptr()) });
            assert_eq!(adjusted_page, unsafe { allocator.page_map.checked_lookup(adjusted_two.as_ptr()) });
            // SAFETY: all three allocations retain their shared page metadata.
            let adjusted_page = unsafe { &*adjusted_page };
            assert!(adjusted_page.has_interior_pointers());
            let block_start = aligned::recover_block_start(
                adjusted_one.as_ptr().addr(),
                unsafe { adjusted_page.start() }.addr(),
                adjusted_page.block_size(),
            )
            .unwrap();
            assert_eq!(
                unsafe { allocator.usable_size(adjusted_one) },
                aligned::usable_size(
                    adjusted_page.block_size(),
                    adjusted_one.as_ptr().addr(),
                    block_start,
                ),
            );

            // SAFETY: these current allocations exercise the canonical base
            // recovery while other adjusted blocks still keep the marker live.
            unsafe { allocator.free(base).unwrap() };
            assert!(adjusted_page.has_interior_pointers());
            unsafe { allocator.free(adjusted_one).unwrap() };
            assert!(adjusted_page.has_interior_pointers());
            unsafe { allocator.free(adjusted_two).unwrap() };
            assert!(!adjusted_page.has_interior_pointers());
            unsafe { allocator.free(fast).unwrap() };
            unsafe { allocator.free(natural).unwrap() };
        });
    }

    #[test]
    fn ordinary_realloc_uses_floor_half_and_preserves_rezalloc_bytes() {
        with_allocator(|allocator| {
            let original = allocator.allocate(33, false).unwrap();
            let original_usable = unsafe { allocator.usable_size(original) }.unwrap();
            assert!(original_usable >= 33);
            // SAFETY: fill the entire source usable range so the replacement
            // copy extent is directly observable below.
            unsafe { write_bytes(original, original_usable, 0x5a) };

            let floor_half = original_usable / 2;
            let reused = unsafe { allocator.reallocate(Some(original), floor_half) }.unwrap();
            assert_eq!(reused, original);
            let replacement = unsafe { allocator.reallocate(Some(reused), floor_half - 1) }.unwrap();
            assert_ne!(replacement, reused);
            assert!(unsafe { bytes_equal(replacement, floor_half - 1, 0x5a) });

            let replacement_usable = unsafe { allocator.usable_size(replacement) }.unwrap();
            // SAFETY: seed the complete old usable range before a zeroed grow
            // that must allocate a distinct block and zero from the source
            // last-word extent through the new usable end.
            unsafe { write_bytes(replacement, replacement_usable, 0x3c) };
            let grown = unsafe {
                allocator.reallocate_zeroed(Some(replacement), replacement_usable + 17)
            }
            .unwrap();
            let grown_usable = unsafe { allocator.usable_size(grown) }.unwrap();
            assert_ne!(grown, replacement);
            assert!(unsafe { bytes_equal(grown, replacement_usable, 0x3c) });
            assert!(unsafe {
                bytes_equal(
                    NonNull::new(grown.as_ptr().wrapping_add(replacement_usable)).unwrap(),
                    grown_usable - replacement_usable,
                    0,
                )
            });

            let zero_size = unsafe { allocator.reallocate(Some(grown), 0) }.unwrap();
            assert_ne!(zero_size, grown);
            // SAFETY: a successful source-compatible zero-size replacement
            // explicitly clears its first byte before freeing `grown`.
            assert_eq!(unsafe { zero_size.as_ptr().read() }, 0);
            unsafe { allocator.free(zero_size).unwrap() };
        });
    }

    #[test]
    fn aligned_realloc_uses_ceil_half_and_zeroes_replacement_growth() {
        with_allocator(|allocator| {
            let original = allocator.allocate_aligned_at(33, 64, 7).unwrap();
            let original_usable = unsafe { allocator.usable_size(original) }.unwrap();
            assert!(original_usable >= 33);
            unsafe { write_bytes(original, original_usable, 0x96) };

            // `usable - usable / 2` is ceil(usable / 2), unlike the ordinary
            // floor-half condition. Exactly that lower bound reuses the block.
            let ceil_half = original_usable - original_usable / 2;
            let reused = unsafe {
                allocator.reallocate_aligned_at(Some(original), ceil_half, 64, 7)
            }
            .unwrap();
            assert_eq!(reused, original);
            let replacement = unsafe {
                allocator.reallocate_aligned_at(Some(reused), ceil_half - 1, 64, 7)
            }
            .unwrap();
            assert_ne!(replacement, reused);
            assert_eq!(replacement.as_ptr().addr().wrapping_add(7) & 63, 0);
            assert!(unsafe { bytes_equal(replacement, ceil_half - 1, 0x96) });

            let replacement_usable = unsafe { allocator.usable_size(replacement) }.unwrap();
            unsafe { write_bytes(replacement, replacement_usable, 0x47) };
            let grown = unsafe {
                allocator.reallocate_aligned_zeroed_at(
                    Some(replacement),
                    replacement_usable + 17,
                    64,
                    7,
                )
            }
            .unwrap();
            let grown_usable = unsafe { allocator.usable_size(grown) }.unwrap();
            assert_ne!(grown, replacement);
            assert_eq!(grown.as_ptr().addr().wrapping_add(7) & 63, 0);
            assert!(unsafe { bytes_equal(grown, replacement_usable, 0x47) });
            assert!(unsafe {
                bytes_equal(
                    NonNull::new(grown.as_ptr().wrapping_add(replacement_usable)).unwrap(),
                    grown_usable - replacement_usable,
                    0,
                )
            });
            unsafe { allocator.free(grown).unwrap() };

            // The zero-offset wrappers delegate through the ordinary-aligned
            // path while retaining the same in-arena valid-alignment bound.
            let zero_offset = allocator.allocate_aligned(33, MAX_ALIGN_SIZE).unwrap();
            let initial_usable = unsafe { allocator.usable_size(zero_offset) }.unwrap();
            unsafe { write_bytes(zero_offset, initial_usable, 0x2b) };
            let zero_offset = unsafe {
                allocator.reallocate_aligned(Some(zero_offset), initial_usable + 1, MAX_ALIGN_SIZE)
            }
            .unwrap();
            let zero_offset_usable = unsafe { allocator.usable_size(zero_offset) }.unwrap();
            assert!(unsafe { bytes_equal(zero_offset, initial_usable, 0x2b) });
            unsafe { write_bytes(zero_offset, zero_offset_usable, 0x2b) };
            let zero_offset = unsafe {
                allocator.reallocate_aligned_zeroed(
                    Some(zero_offset),
                    zero_offset_usable + 17,
                    MAX_ALIGN_SIZE,
                )
            }
            .unwrap();
            assert!(unsafe { bytes_equal(zero_offset, zero_offset_usable, 0x2b) });
            unsafe { allocator.free(zero_offset).unwrap() };
        });
    }

    #[test]
    fn failed_realloc_preserves_the_original_live_block() {
        with_allocator(|allocator| {
            let original = allocator.allocate(64, false).unwrap();
            unsafe { write_bytes(original, 64, 0xa7) };

            // Consume every other arena slice. The live original prevents its
            // own small page from retirement, so the generic large request's
            // mandated force-collect/retry cannot manufacture a 64-slice span.
            let mut held = Vec::new();
            while let Some(claim) = allocator
                .arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            {
                held.push(claim);
            }
            assert!(unsafe { allocator.reallocate(Some(original), LARGE_MAX_OBJ_SIZE) }.is_none());
            assert!(unsafe { bytes_equal(original, 64, 0xa7) });

            // SAFETY: failure deliberately leaves `original` live and intact.
            unsafe { allocator.free(original).unwrap() };
            assert!(allocator.collect_retired(true));
            for claim in held {
                assert!(claim.release());
            }
        });
    }

    #[test]
    fn fundamental_trace_matches_the_pinned_address_independent_oracle_record() {
        with_allocator(|allocator| {
            std::println!("CRABC_MI_FUNDAMENTAL_TRACE_BEGIN");

            for (name, request) in [
                ("small", SMALL_MAX_OBJ_SIZE),
                ("medium", SMALL_MAX_OBJ_SIZE + 1),
                ("large", MEDIUM_MAX_OBJ_SIZE + 1),
                ("singleton", LARGE_MAX_OBJ_SIZE + 1),
            ] {
                let block = allocator.allocate(request, false).unwrap();
                let usable = unsafe { allocator.usable_size(block) }.unwrap();
                std::println!("trace.fundamental.class.{name}.request={request}");
                std::println!("trace.fundamental.class.{name}.usable={usable}");
                std::println!(
                    "trace.fundamental.class.{name}.success={}",
                    u8::from(usable >= request),
                );
                unsafe { allocator.free(block).unwrap() };
            }

            let calloc_count = 7usize;
            let calloc_size = 13usize;
            let calloc_total = calloc_count * calloc_size;
            let zeroed = allocator
                .allocate_zeroed_count(calloc_count, calloc_size)
                .unwrap();
            let zeroed_usable = unsafe { allocator.usable_size(zeroed) }.unwrap();
            std::println!("trace.fundamental.calloc.count={calloc_count}");
            std::println!("trace.fundamental.calloc.size={calloc_size}");
            std::println!("trace.fundamental.calloc.usable={zeroed_usable}");
            std::println!(
                "trace.fundamental.calloc.cleared={}",
                u8::from(unsafe { bytes_equal(zeroed, calloc_total, 0) }),
            );
            std::println!(
                "trace.fundamental.calloc.content_hash={}",
                unsafe { content_hash(zeroed, calloc_total) },
            );
            unsafe { allocator.free(zeroed).unwrap() };

            let overflow_count = usize::MAX;
            let overflow_size = 2usize;
            let overflow = allocator.allocate_zeroed_count(overflow_count, overflow_size);
            std::println!("trace.fundamental.calloc_overflow.count={overflow_count}");
            std::println!("trace.fundamental.calloc_overflow.size={overflow_size}");
            std::println!(
                "trace.fundamental.calloc_overflow.returns_null={}",
                u8::from(overflow.is_none()),
            );

            let realloc_null = unsafe { allocator.reallocate(None, 41) }.unwrap();
            unsafe { write_bytes(realloc_null, 41, 0x31) };
            std::println!("trace.fundamental.realloc_null.request=41");
            std::println!(
                "trace.fundamental.realloc_null.usable={}",
                unsafe { allocator.usable_size(realloc_null) }.unwrap(),
            );
            std::println!(
                "trace.fundamental.realloc_null.content_hash={}",
                unsafe { content_hash(realloc_null, 41) },
            );
            unsafe { allocator.free(realloc_null).unwrap() };

            let grow_original_size = 257usize;
            let grow_size = 8193usize;
            let grow = allocator.allocate(grow_original_size, false).unwrap();
            unsafe { write_bytes(grow, grow_original_size, 0x42) };
            let grow_before = unsafe { content_hash(grow, grow_original_size) };
            let grow = unsafe { allocator.reallocate(Some(grow), grow_size) }.unwrap();
            let grow_after = unsafe { content_hash(grow, grow_original_size) };
            std::println!(
                "trace.fundamental.realloc_grow.original_size={grow_original_size}"
            );
            std::println!("trace.fundamental.realloc_grow.new_size={grow_size}");
            std::println!(
                "trace.fundamental.realloc_grow.usable={}",
                unsafe { allocator.usable_size(grow) }.unwrap(),
            );
            std::println!(
                "trace.fundamental.realloc_grow.preserved={}",
                u8::from(grow_before == grow_after),
            );
            std::println!("trace.fundamental.realloc_grow.content_hash={grow_after}");

            let shrink_size = 71usize;
            let shrink_expected = unsafe { content_hash(grow, shrink_size) };
            let grow = unsafe { allocator.reallocate(Some(grow), shrink_size) }.unwrap();
            let shrink_after = unsafe { content_hash(grow, shrink_size) };
            std::println!("trace.fundamental.realloc_shrink.new_size={shrink_size}");
            std::println!(
                "trace.fundamental.realloc_shrink.usable={}",
                unsafe { allocator.usable_size(grow) }.unwrap(),
            );
            std::println!(
                "trace.fundamental.realloc_shrink.preserved={}",
                u8::from(shrink_expected == shrink_after),
            );
            std::println!("trace.fundamental.realloc_shrink.content_hash={shrink_after}");
            unsafe { allocator.free(grow).unwrap() };

            let failure_preserved = allocator.allocate(59, false).unwrap();
            unsafe { write_bytes(failure_preserved, 59, 0x73) };
            let failure_before = unsafe { content_hash(failure_preserved, 59) };
            let failed = unsafe {
                allocator.reallocate(Some(failure_preserved), MAX_ALLOC_SIZE + 1)
            };
            let failure_after = unsafe { content_hash(failure_preserved, 59) };
            std::println!(
                "trace.fundamental.realloc_failure.request={}",
                MAX_ALLOC_SIZE + 1,
            );
            std::println!(
                "trace.fundamental.realloc_failure.returns_null={}",
                u8::from(failed.is_none()),
            );
            std::println!(
                "trace.fundamental.realloc_failure.preserved={}",
                u8::from(failure_before == failure_after),
            );
            std::println!(
                "trace.fundamental.realloc_failure.content_hash={failure_after}"
            );
            unsafe { allocator.free(failure_preserved).unwrap() };

            let size_zero = allocator.allocate(59, false).unwrap();
            let size_zero = unsafe { allocator.reallocate(Some(size_zero), 0) }.unwrap();
            std::println!("trace.fundamental.realloc_size_zero.request=0");
            std::println!("trace.fundamental.realloc_size_zero.returns_nonnull=1");
            std::println!(
                "trace.fundamental.realloc_size_zero.usable={}",
                unsafe { allocator.usable_size(size_zero) }.unwrap(),
            );
            unsafe { allocator.free(size_zero).unwrap() };

            let aligned_size = 97usize;
            let aligned_alignment = 256usize;
            let aligned = allocator
                .allocate_aligned(aligned_size, aligned_alignment)
                .unwrap();
            let aligned_usable = unsafe { allocator.usable_size(aligned) }.unwrap();
            std::println!("trace.fundamental.aligned.size={aligned_size}");
            std::println!("trace.fundamental.aligned.alignment={aligned_alignment}");
            std::println!("trace.fundamental.aligned.usable={aligned_usable}");
            std::println!(
                "trace.fundamental.aligned.valid={}",
                u8::from(
                    aligned_usable >= aligned_size
                        && aligned.as_ptr().addr() % aligned_alignment == 0
                ),
            );
            unsafe { allocator.free(aligned).unwrap() };

            let offset_size = 191usize;
            let offset_alignment = 512usize;
            let offset = 13usize;
            let offset_aligned = allocator
                .allocate_aligned_at(offset_size, offset_alignment, offset)
                .unwrap();
            let offset_usable = unsafe { allocator.usable_size(offset_aligned) }.unwrap();
            std::println!("trace.fundamental.offset_aligned.size={offset_size}");
            std::println!(
                "trace.fundamental.offset_aligned.alignment={offset_alignment}"
            );
            std::println!("trace.fundamental.offset_aligned.offset={offset}");
            std::println!("trace.fundamental.offset_aligned.usable={offset_usable}");
            std::println!(
                "trace.fundamental.offset_aligned.valid={}",
                u8::from(
                    offset_usable >= offset_size
                        && offset_aligned.as_ptr().addr().wrapping_add(offset)
                            % offset_alignment
                            == 0
                ),
            );
            unsafe { allocator.free(offset_aligned).unwrap() };

            let forced_oom_request = MAX_ALLOC_SIZE + 1;
            let forced_oom = allocator.allocate(forced_oom_request, false);
            std::println!("trace.fundamental.oom.request={forced_oom_request}");
            std::println!("trace.fundamental.oom.classification_invalid_request=1");
            std::println!(
                "trace.fundamental.oom.returns_null={}",
                u8::from(forced_oom.is_none()),
            );
            std::println!("CRABC_MI_FUNDAMENTAL_TRACE_END");
        });
    }
}
