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
// `src/free.c:28-50,104-114,522-542` (local free, interior-base recovery,
// and aligned usable size),
// `src/page.c:150-242,374-388,460-522,708-1069` (remote/local free
// collection, non-abandoning post-enqueue full-page collection,
// full-page collection, free-page search, full-page retention,
// retirement, forced retry, regular and huge page selection),
// `src/page-queue.c:64-121,126-423` (size-bin/direct-cache selection and
// queue mutations), `src/arena.c:950-1283` (fresh regular/singleton page
// metadata, arena-page registration, page-map publication, and release
// ordering), and `include/mimalloc/internal.h:650-654,945-949`
// (direct-page, size-bin, and full-page predicates).
//
// This is the intentionally bounded normal-release lifecycle for exactly one
// pinned exclusive theap. Ordinary activation supplies a live default theap;
// the detached metadata wrapper supplies its own PrivateLock and reuses the
// same exclusive mutation engine. It accepts only caller-managed external
// arenas and a caller-initialized page map. There is no TLS, first-class heap,
// general lock-free remote-free routing, page abandonment, OS arena
// reservation, or public API here. A bounded false-force collector runs in
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
use core::pin::Pin;
use core::ptr::NonNull;

use crate::arena::{ArenaId, ArenaView, release_arena_slices};
use crate::{aligned, alloc, support};
use crate::bootstrap::{BootstrapError, ExclusiveTheapBootstrap, ExclusiveTheapSession};
use crate::config::{
    ARENA_SLICE_SIZE, BIN_FULL, BIN_HUGE, PAGES_DIRECT, SMALL_MAX_OBJ_SIZE,
    SMALL_SIZE_MAX, WORD_SIZE,
};
use crate::free_list::{FreeListError, LocalFreeList};
use crate::invariants;
use crate::os_page::{OsAlignedPageClaim, OsAlignedPageOwner, PublishedOsAlignedPage};
use crate::page;
use crate::page_map::PageMap;
use crate::remote_free::{self, RemoteFreeError};
use crate::size_class;
use crate::subproc::MainSubprocess;
use crate::types::{EMPTY_PAGE, LiveThreadId, MemoryId, Page, PageKind, Theap};
use crate::types::page_queue::{
    page_is_in_full, page_queue_enqueue_from_full_metadata,
    page_queue_enqueue_from_metadata, page_queue_push_metadata,
    page_queue_move_to_front_metadata, page_queue_remove_metadata,
};

const RETIRE_CYCLES: u8 = 16;
const RETIRE_MAX_PAGES: usize = 3;
const PAGE_MAX_CANDIDATES: isize = 4;

/// One failed source false-force page collection boundary.
///
/// These are private invalid-owner/lifecycle observations. The collector
/// cannot safely continue queue transitions after one because source
/// collection has rejected either remote ownership or raw local geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageCollectError {
    Remote(RemoteFreeError),
    Local(FreeListError),
    InvalidOwnerState,
    /// Test-only failure before `remote_free::collect` can detach producer
    /// state. This exact variant is the sole cleanup-recoverable provenance.
    #[cfg(test)]
    InjectedBeforeDetach,
}

/// One permanently retained false-force collection failure.
///
/// A false-force collector may have detached a remote list before it reports
/// an error. Retaining the exact page and, when applicable, the block already
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
        slice_index: usize,
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
pub(crate) struct RemoteFreeProducer<'owner, 'bootstrap, 'arena, 'map> {
    page: NonNull<Page>,
    canonical_block: NonNull<u8>,
    client_block: NonNull<u8>,
    _owner: PhantomData<&'owner mut SingleThreadAllocator<'bootstrap, 'arena, 'map>>,
    // `Cell` is intentionally !Sync. The explicit unsafe Send impl below
    // grants only one scoped producer transfer, never shared access.
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: `begin_remote_free` grants this capability only after it has pinned
// the exact live regular-or-full page and canonical current block under the
// allocator's exclusive borrow. The token carries no runtime allocator
// reference; moving it to one scoped worker permits only `remote_free::push`.
// Its `&mut SingleThreadAllocator` phantom borrow prevents safe owner/page-map
// mutation until the worker has consumed or cancelled the token.
unsafe impl Send for RemoteFreeProducer<'_, '_, '_, '_> {}

impl<'owner, 'bootstrap, 'arena, 'map> RemoteFreeProducer<'owner, 'bootstrap, 'arena, 'map> {
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

/// One exclusive ordinary-allocation lifecycle over a caller-owned external arena.
///
/// This value owns the activated [`ExclusiveTheapSession`], so it is the
/// only operation capable of mutating the pinned exclusive theap. It borrows the
/// arena and page map rather than reserving VM itself. Dropping it does not
/// collect, abandon, unregister, or release any page: callers must force a
/// collection before they dismantle the supplied arena or page map.
pub(crate) struct SingleThreadAllocator<'bootstrap, 'arena, 'map> {
    session: ExclusiveTheapSession<'bootstrap>,
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
}

impl<'bootstrap, 'arena, 'map> SingleThreadAllocator<'bootstrap, 'arena, 'map> {
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
        })
    }

    /// Returns the stable source `page->theap` identity of this exclusive
    /// lifecycle. The detached metadata wrapper uses it only for the exact
    /// `_mi_meta_is_meta_page` pointer comparison; it never dereferences an
    /// abandoned page's origin pointer.
    #[inline]
    pub(crate) fn theap_identity(&self) -> *mut Theap {
        self.session.theap() as *const Theap as *mut Theap
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
    ) -> Result<RemoteFreeProducer<'owner, 'bootstrap, 'arena, 'map>, RemoteFreePreparationError> {
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
    fn has_pending_os_release(&self) -> bool {
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

    #[inline]
    fn is_collection_poisoned(&self) -> bool {
        self.collection_poison.is_some()
    }

    /// Records the first false-force failure before its caller can perform
    /// any fallback, fresh-page, release, or additional queue transition.
    fn retain_page_collect_poison(
        &mut self,
        page: NonNull<Page>,
        error: PageCollectError,
        popped_block: Option<NonNull<u8>>,
    ) {
        assert!(
            self.collection_poison.is_none(),
            "a terminal false-force collection failure must be retained once"
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
    fn inject_page_free_collect_failure_once(&mut self) {
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
    fn queue_count(&self, bin: usize) -> Option<usize> {
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
        let slice_index = claim.slice_index();
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

        let registered_in_arena = unsafe {
            match self.arena.pages() {
                Some(pages) => match pages.set_range(slice_index, 1) {
                    Some(transition) => transition.all_transitioned(),
                    None => false,
                },
                None => false,
            }
        };
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
            if let Some(arena_memory) = memory.arena_memory() {
                // SAFETY: the page bitmap bit was set by this exact fresh
                // attempt and no page-map reader can observe the rollback.
                if let Some(pages) = unsafe { self.arena.pages() } {
                    let _ = pages.clear_range(arena_memory.slice_index as usize, 1);
                }
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
                slice_index,
            } => {
                // SAFETY: `memory` describes the prevalidated, still
                // map-published span; no plain lookup overlaps this explicit
                // lifecycle transition.
                if unsafe { self.page_map.unregister_range(slice_start, size) }.is_err() {
                    self.reinsert_after_release_failure(bin, page);
                    return false;
                }
                let cleared = unsafe {
                    self.arena
                        .pages()
                        .and_then(|pages| pages.clear_range(slice_index, 1))
                };
                if cleared != Some(true) {
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

    /// Validates every arena or OS-aligned page-map fact needed for terminal
    /// release before detaching a queue member. This preserves the distinct
    /// source release provenance instead of treating an OS mapping as an
    /// external-arena bitmap claim.
    fn release_span(&self, page: *mut Page) -> Option<ReleaseSpan> {
        let page = NonNull::new(page)?;
        // SAFETY: only a page currently linked in this session's queue reaches
        // this helper, so its metadata remains live for this preflight.
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
            slice_index,
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

    fn owns_page(&self, page: &Page) -> bool {
        page.theap() == self.session.theap() as *const _ as *mut _
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

        assert_send::<RemoteFreeProducer<'static, 'static, 'static, 'static>>();
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
