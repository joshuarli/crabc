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
// (`mi_page_malloc_zero`, `mi_theap_malloc_small_zero_nonnull`, and generic
// allocation dispatch), `src/free.c:28-50` (`mi_free_block_local`),
// `src/page.c:360-522,708-1069` (free-page search, full-page retention,
// retirement, forced retry, regular and huge page selection),
// `src/page-queue.c:64-121,126-423` (size-bin/direct-cache selection and
// queue mutations), `src/arena.c:950-1283` (fresh regular/singleton page
// metadata, arena-page registration, page-map publication, and release
// ordering), and `include/mimalloc/internal.h:650-654,945-949`
// (direct-page, size-bin, and full-page predicates).
//
// This is the intentionally bounded normal-release lifecycle for exactly one
// pinned default theap. It accepts only caller-managed external arenas and a
// caller-initialized page map. There is no TLS, first-class heap, remote free,
// page abandonment, OS arena reservation, aligned allocation, or realloc path
// here. Ordinary small, medium, large, and singleton pages retain their
// pinned source geometry and queue transitions. The owning bootstrap session
// is exclusive and the arena backing plus its metadata must remain pinned for
// the whole session.

use core::pin::Pin;
use core::ptr::NonNull;

use crate::arena::{ArenaId, ArenaView, release_arena_slices};
use crate::bootstrap::{BootstrapError, DefaultSingleThreadBootstrap, DefaultSingleThreadSession};
use crate::config::{
    ARENA_SLICE_SIZE, BIN_FULL, BIN_HUGE, PAGES_DIRECT, SMALL_MAX_OBJ_SIZE,
    SMALL_SIZE_MAX,
};
use crate::free_list::{FreeListError, LocalFreeList};
use crate::invariants;
use crate::page;
use crate::page_map::PageMap;
use crate::size_class;
use crate::types::{EMPTY_PAGE, LiveThreadId, MemoryId, Page, PageKind};
use crate::types::page_queue::{
    page_is_in_full, page_queue_enqueue_from_full_metadata,
    page_queue_enqueue_from_metadata, page_queue_push_metadata,
    page_queue_move_to_front_metadata, page_queue_remove_metadata,
};

const RETIRE_CYCLES: u8 = 16;
const RETIRE_MAX_PAGES: usize = 3;
const PAGE_MAX_CANDIDATES: isize = 4;

/// One invalid local free at the explicit default-theap boundary.
///
/// These are allocator-state failures, not a replacement for the C ABI's
/// invalid-free policy. The eventual libc facade owns that policy; this
/// no-std engine instead refuses to mutate page state when the pinned local
/// ownership proof is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FreeError {
    /// The address maps to no current ordinary page in this explicit lifecycle.
    Unmapped,
    /// The mapped page is not owned by this pinned default theap.
    ForeignPage,
    /// The block is not one live scalar allocation from that page.
    InvalidBlock(FreeListError),
    /// A queue, page map, or arena ownership invariant could not be preserved.
    Lifecycle,
}

/// One exclusive ordinary-allocation lifecycle over a caller-owned external arena.
///
/// This value owns the activated [`DefaultSingleThreadSession`], so it is the
/// only operation capable of mutating the pinned default theap. It borrows the
/// arena and page map rather than reserving VM itself. Dropping it does not
/// collect, abandon, unregister, or release any page: callers must force a
/// collection before they dismantle the supplied arena or page map.
pub(crate) struct SingleThreadAllocator<'bootstrap, 'arena, 'map> {
    session: DefaultSingleThreadSession<'bootstrap>,
    arena: ArenaView<'arena>,
    requested_arena: ArenaId,
    page_map: &'map PageMap,
    thread_sequence: usize,
}

impl<'bootstrap, 'arena, 'map> SingleThreadAllocator<'bootstrap, 'arena, 'map> {
    /// Activates the sole default theap for this ordinary-page lifecycle.
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
        bootstrap: Pin<&'bootstrap mut DefaultSingleThreadBootstrap>,
        thread_id: LiveThreadId,
        arena: ArenaView<'arena>,
        requested_arena: ArenaId,
        page_map: &'map mut PageMap,
        thread_sequence: usize,
    ) -> Result<Self, BootstrapError> {
        let session = bootstrap.activate(thread_id)?;
        Ok(Self {
            session,
            arena,
            requested_arena,
            page_map,
            thread_sequence,
        })
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
            match self.pop_or_extend(page, zero) {
                Ok(Some(block)) => return Some(block),
                Ok(None) => {
                    // The direct page is fully initialized and exhausted. In
                    // this bounded default-theap mode it is retained locally
                    // in the full queue, never abandoned.
                    if !self.move_regular_to_full(bin, page.as_ptr()) {
                        return None;
                    }
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
            if let Some(block) = self.allocate_generic_once(bin, block_size, kind, zero) {
                return Some(block);
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
    ) -> Option<NonNull<u8>> {
        // Huge pages contain exactly one block and are never candidates for
        // queue reuse. The fresh page enters the huge queue only long enough
        // for the source full-page transition below.
        if bin == BIN_HUGE {
            let page = self.allocate_fresh_page(block_size, kind)?;
            self.push_regular_page(bin, page);
            let block = self.pop_or_extend(page, zero).ok()??;
            if !self.move_regular_to_full(bin, page.as_ptr()) {
                return None;
            }
            return Some(block);
        }

        let page = self.find_generic_queue_page(bin, block_size, kind)?;
        match self.pop_or_extend(page, zero) {
            Ok(Some(block)) => {
                // `mi_malloc_generic_fallback` moves a full medium, large,
                // or singleton page immediately. Small pages use the source
                // retain-count path while a later queue scan considers them.
                let full = unsafe {
                    let page = page.as_ref();
                    page.used() == page.reserved() as usize
                };
                if block_size > SMALL_MAX_OBJ_SIZE && full
                    && !self.move_regular_to_full(bin, page.as_ptr())
                {
                    return None;
                }
                Some(block)
            }
            // `find_generic_queue_page` returns only a source-immediately-
            // available page. A contrary result is a local-list invariant
            // failure, not a reason to select a different queue member.
            Ok(None) | Err(_) => None,
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
    ) -> Option<NonNull<Page>> {
        let first = self.session.queue(bin)?.first();
        if let Some(first) = NonNull::new(first) {
            match self.page_quick_collect(first) {
                Ok(true) => {
                    // `mi_page_queue_lookup_free_first` leaves its head in
                    // place and clears retirement only after choosing it.
                    unsafe { first.as_ptr().as_mut() }?.set_retire_expire(0);
                    return Some(first);
                }
                Ok(false) => {}
                Err(_) => return None,
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
            let immediate_available = match NonNull::new(page) {
                Some(page) => match self.page_quick_collect(page) {
                    Ok(available) => available,
                    Err(_) => return None,
                },
                None => return None,
            };
            // SAFETY: this source-plain lifecycle has exclusive queue/page
            // ownership for the duration of the candidate scan.
            let expandable = unsafe { (*page).capacity() < (*page).reserved() };

            if !immediate_available && !expandable {
                page_full_retain -= 1;
                if page_full_retain < 0 && !self.move_regular_to_full(bin, page) {
                    return None;
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
                            return None;
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
                Ok(false) | Err(_) => return None,
            }
            let queue = self.session.queue_mut(bin)? as *mut _;
            // SAFETY: the candidate remains a member of this exclusively
            // owned regular queue; moving it changes no page-count state.
            unsafe { page_queue_move_to_front_metadata(&mut *queue, candidate.as_ptr()) };
            self.update_direct_cache(bin);
            // SAFETY: choosing this valid live candidate mirrors the source
            // post-search retirement reset.
            unsafe { candidate.as_ptr().as_mut() }?.set_retire_expire(0);
            return Some(candidate);
        }

        if !self.collect_retired(false) {
            return None;
        }
        let fresh = self.allocate_fresh_page(block_size, kind)?;
        self.push_regular_page(bin, fresh);
        Some(fresh)
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

    /// Returns the full usable block size for one live local ordinary allocation.
    ///
    /// # Safety
    ///
    /// `block` must be a current allocation returned by this exact allocator,
    /// and it must not have been freed, retired, or moved into a dismantled
    /// page map. This inspection does not validate arbitrary raw pointers.
    pub(crate) unsafe fn usable_size(&self, block: NonNull<u8>) -> Option<usize> {
        // SAFETY: the caller's live-allocation contract excludes concurrent
        // page-map mutation and keeps the mapped metadata alive.
        let page = unsafe { self.page_map.checked_lookup(block.as_ptr()) };
        let page = unsafe { page.as_ref() }?;
        if !self.owns_page(page) {
            return None;
        }
        Some(page.block_size())
    }

    /// Returns one local block by page-map lookup and source local-free push.
    ///
    /// # Safety
    ///
    /// `block` must be exactly one current block returned by this allocator,
    /// must not have been previously freed, and no alias may access it after
    /// this call. The caller must also retain the allocator's exclusive
    /// default-theap capability; remote frees are deliberately not accepted.
    pub(crate) unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), FreeError> {
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

        let (used, in_full, bin) = {
            // SAFETY: this lifecycle owns the page, its blocks, and all local
            // free-list metadata. It never exposes a remote or concurrent path.
            let mut free_list = unsafe { LocalFreeList::from_page(page) }
                .map_err(FreeError::InvalidBlock)?;
            // SAFETY: the public caller contract proves exactly-once ownership
            // of `block`; the borrowed list additionally validates page range
            // and initialized-capacity membership before writing a link.
            unsafe { free_list.push_local(block) }
                .map_err(FreeError::InvalidBlock)?;
            (free_list.used(), page_is_in_full(page), size_class::bin(page.block_size()))
        };
        let bin = bin.ok_or(FreeError::Lifecycle)?;

        if used == 0 {
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

    /// Collects source-retired regular pages. `force` releases every currently
    /// retired page in the tracked range; `false` decrements the normal
    /// retirement countdown. This intentionally does not visit the full queue:
    /// a local free transitions full pages back to their regular bin first.
    pub(crate) fn collect_retired(&mut self, force: bool) -> bool {
        let (minimum, maximum) = self.session.retired_bounds();
        if minimum >= BIN_FULL || minimum > maximum {
            self.session.reset_retired_bounds();
            return true;
        }

        self.session.reset_retired_bounds();
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
        true
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
        // SAFETY: callers obtain `page` only from this session's direct cache,
        // whose membership and ownership transitions are exclusively below.
        let page = unsafe { &mut *page.as_ptr() };
        // SAFETY: the direct-cache ownership contract supplies the exact
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

    fn move_regular_to_full(&mut self, bin: usize, page: *mut Page) -> bool {
        let regular = match self.session.queue_mut(bin) {
            Some(queue) => queue as *mut _,
            None => return false,
        };
        let full = match self.session.queue_mut(BIN_FULL) {
            Some(queue) => queue as *mut _,
            None => return false,
        };
        // SAFETY: `page` is the exhausted direct regular page and the session
        // exclusively owns both disjoint queue records and their links.
        unsafe { page_queue_enqueue_from_metadata(&mut *full, &mut *regular, page) };
        self.update_direct_cache(bin);
        true
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
        let Some((memory, slice_start, size, slice_index)) = self.release_span(page) else {
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

        // SAFETY: `memory` describes the prevalidated, still map-published
        // span; no plain lookup overlaps this explicit lifecycle transition.
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
            // The map is already clear, so do not release the arena span on an
            // arena-page registration invariant failure. It remains a visible
            // diagnostic leak rather than a use-after-release.
            return false;
        }
        // SAFETY: queue/direct/map membership is gone and local free state is
        // fully free, so the session may reset metadata before slice release.
        let retired = unsafe { self.session.retire_page(&mut *page) };
        if retired.is_none() {
            return false;
        }
        // SAFETY: source ordering has unregistered the page before this exact
        // outstanding external-arena claim is returned to its free bitmap.
        unsafe { release_arena_slices(memory) }
    }

    /// Validates every external-arena and page-map fact needed for terminal
    /// release before detaching a queue member. This makes malformed retained
    /// provenance a recoverable lifecycle error rather than an orphaned page.
    fn release_span(&self, page: *mut Page) -> Option<(MemoryId, *mut u8, usize, usize)> {
        let page = NonNull::new(page)?;
        // SAFETY: only a page currently linked in this session's queue reaches
        // this helper, so its metadata remains live for this preflight.
        let page_ref = unsafe { page.as_ref() };
        let memory = page_ref.memid();
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
        Some((memory, slice_start, size, slice_index))
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
        MEDIUM_MAX_OBJ_SIZE, SMALL_MAX_OBJ_SIZE, WORD_SIZE,
    };
    use crate::os::{MemoryConfig, PageSize};
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        let bootstrap = DefaultSingleThreadBootstrap::new();
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
        let bootstrap = DefaultSingleThreadBootstrap::new();
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
                let direct = invariants::word_count(request).unwrap();
                let mapped = unsafe { allocator.page_map.checked_lookup(block.as_ptr()) };
                assert_eq!(allocator.direct_page(direct), Some(mapped));
                // SAFETY: `block` is the exact current allocation for this
                // direct-cache assertion.
                unsafe { allocator.free(block).unwrap() };
            }
        });
    }

    #[test]
    fn local_free_moves_a_full_page_back_to_its_regular_queue() {
        with_allocator(|allocator| {
            let mut blocks = [NonNull::dangling(); 65];
            for block in &mut blocks {
                *block = allocator.allocate(SMALL_SIZE_MAX, false).unwrap();
            }
            let bin = size_class::bin(SMALL_SIZE_MAX).unwrap();
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
}
