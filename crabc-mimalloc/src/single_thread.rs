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
// (`mi_page_malloc_zero`, `mi_theap_malloc_small_zero_nonnull`, and direct
// small-page selection), `src/free.c:28-50` (`mi_free_block_local`),
// `src/page.c:708-902,360-522` (free-page search, fresh page queueing,
// full-page retention, retirement, and forced retired-page collection),
// `src/page-queue.c:126-423` (direct-cache range maintenance around queue
// mutations), `src/arena.c:950-1114,1210-1283` (fresh regular page metadata,
// arena-page registration, page-map publication, and release ordering), and
// `include/mimalloc/internal.h:650-654,945-949` (direct-page and size-bin
// selection).
//
// This is the intentionally bounded normal-release lifecycle for exactly one
// pinned default theap. It accepts only caller-managed external arenas and a
// caller-initialized page map. There is no TLS, first-class heap, remote free,
// page abandonment, OS arena reservation, large/medium/aligned allocation, or
// realloc path here. The owning bootstrap session is exclusive and the arena
// backing plus its metadata must remain pinned for the whole session.

use core::pin::Pin;
use core::ptr::NonNull;

use crate::arena::{ArenaId, ArenaView, release_arena_slices};
use crate::bootstrap::{BootstrapError, DefaultSingleThreadBootstrap, DefaultSingleThreadSession};
use crate::config::{ARENA_SLICE_SIZE, BIN_FULL, PAGES_DIRECT, SMALL_SIZE_MAX, SMALL_PAGE_SIZE};
use crate::free_list::{FreeListError, LocalFreeList};
use crate::invariants;
use crate::page;
use crate::page_map::PageMap;
use crate::size_class;
use crate::types::{EMPTY_PAGE, LiveThreadId, MemoryId, Page};
use crate::types::page_queue::{
    page_is_in_full, page_queue_enqueue_from_full_metadata,
    page_queue_enqueue_from_metadata, page_queue_push_metadata,
    page_queue_remove_metadata,
};

const RETIRE_CYCLES: u8 = 16;
const RETIRE_MAX_PAGES: usize = 3;

/// One invalid local free at the explicit default-theap boundary.
///
/// These are allocator-state failures, not a replacement for the C ABI's
/// invalid-free policy. The eventual libc facade owns that policy; this
/// no-std engine instead refuses to mutate page state when the pinned local
/// ownership proof is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmallFreeError {
    /// The address maps to no current small page in this explicit lifecycle.
    Unmapped,
    /// The mapped page is not owned by this pinned default theap.
    ForeignPage,
    /// The block is not one live scalar allocation from that page.
    InvalidBlock(FreeListError),
    /// A queue, page map, or arena ownership invariant could not be preserved.
    Lifecycle,
}

/// One exclusive small-allocation lifecycle over a caller-owned external arena.
///
/// This value owns the activated [`DefaultSingleThreadSession`], so it is the
/// only operation capable of mutating the pinned default theap. It borrows the
/// arena and page map rather than reserving VM itself. Dropping it does not
/// collect, abandon, unregister, or release any page: callers must force a
/// collection before they dismantle the supplied arena or page map.
pub(crate) struct SingleThreadSmallAllocator<'bootstrap, 'arena, 'map> {
    session: DefaultSingleThreadSession<'bootstrap>,
    arena: ArenaView<'arena>,
    requested_arena: ArenaId,
    page_map: &'map PageMap,
    thread_sequence: usize,
}

impl<'bootstrap, 'arena, 'map> SingleThreadSmallAllocator<'bootstrap, 'arena, 'map> {
    /// Activates the sole default theap for this small-page lifecycle.
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

    /// Allocates one normal-release small block, optionally clearing its full
    /// source block size. Requests above `MI_SMALL_SIZE_MAX` intentionally
    /// return `None`; medium, large, singleton, aligned, and generic paths are
    /// separate future lifecycle slices.
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        if request > SMALL_SIZE_MAX {
            return None;
        }
        let bin = size_class::bin(request)?;
        let direct_index = invariants::word_count(request)?;
        if direct_index >= PAGES_DIRECT {
            return None;
        }

        loop {
            let direct = self.session.direct_page(direct_index)?;
            if direct == EMPTY_PAGE.as_ptr() {
                let page = self.allocate_fresh_regular_page(bin)?;
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

    /// Allocates a zero-filled small block.
    #[inline]
    pub(crate) fn allocate_zeroed(&mut self, request: usize) -> Option<NonNull<u8>> {
        self.allocate(request, true)
    }

    /// Returns the full usable block size for one live local small allocation.
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
    pub(crate) unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), SmallFreeError> {
        // SAFETY: the caller's live-local-allocation contract excludes a
        // simultaneous page-map registration or unregistration for this block.
        let page = unsafe { self.page_map.checked_lookup(block.as_ptr()) };
        let page = NonNull::new(page).ok_or(SmallFreeError::Unmapped)?;
        // SAFETY: page-map registration keeps the returned metadata live until
        // this lifecycle unregisters it, and this `&mut self` owns the only
        // local mutation capability.
        let page = unsafe { &mut *page.as_ptr() };
        if !self.owns_page(page) {
            return Err(SmallFreeError::ForeignPage);
        }

        let (used, in_full, bin) = {
            // SAFETY: this lifecycle owns the page, its blocks, and all local
            // free-list metadata. It never exposes a remote or concurrent path.
            let mut free_list = unsafe { LocalFreeList::from_page(page) }
                .map_err(SmallFreeError::InvalidBlock)?;
            // SAFETY: the public caller contract proves exactly-once ownership
            // of `block`; the borrowed list additionally validates page range
            // and initialized-capacity membership before writing a link.
            unsafe { free_list.push_local(block) }
                .map_err(SmallFreeError::InvalidBlock)?;
            (free_list.used(), page_is_in_full(page), size_class::bin(page.block_size()))
        };
        let bin = bin.ok_or(SmallFreeError::Lifecycle)?;

        if used == 0 {
            if in_full {
                // A full page with its final local block returned is not a
                // regular retired page in the source; release it directly.
                if self.release_page(BIN_FULL, page as *mut Page) {
                    return Ok(());
                }
                return Err(SmallFreeError::Lifecycle);
            }
            if self.retire_or_release(bin, page as *mut Page) {
                return Ok(());
            }
            return Err(SmallFreeError::Lifecycle);
        }

        if in_full {
            if self.move_full_to_regular(bin, page as *mut Page) {
                return Ok(());
            }
            return Err(SmallFreeError::Lifecycle);
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

    fn allocate_fresh_regular_page(&mut self, bin: usize) -> Option<NonNull<Page>> {
        let block_size = size_class::bin_size(bin)?;
        if block_size == 0 || block_size > SMALL_SIZE_MAX {
            return None;
        }
        let claim = self.arena.try_claim_suitable_slices(
            self.requested_arena,
            1,
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
        let reserved = match page::reserved_object_count(SMALL_PAGE_SIZE, usable_offset, block_size) {
            Some(reserved) => reserved,
            None => {
                let _ = claim.release();
                return None;
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
            self.rollback_fresh(page, slice_start, memory, false, false);
            return None;
        }
        // SAFETY: `page` is fully initialized and remains address-stable until
        // the matching unregister below. This serial lifecycle excludes a
        // lookup racing this source-plain page-map write.
        if unsafe {
            self.page_map
                .register_range(slice_start, ARENA_SLICE_SIZE, page)
        }
        .is_err()
        {
            self.rollback_fresh(page, slice_start, memory, true, false);
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
            self.rollback_fresh(page, slice_start, memory, true, true);
            return None;
        }
        Some(page)
    }

    fn rollback_fresh(
        &mut self,
        page: NonNull<Page>,
        slice_start: *mut u8,
        memory: MemoryId,
        arena_registered: bool,
        page_map_registered: bool,
    ) {
        if page_map_registered {
            // SAFETY: this serial rollback writes the same range just
            // registered above; no allocation was handed out.
            let _ = unsafe {
                self.page_map
                    .unregister_range(slice_start, ARENA_SLICE_SIZE)
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
        if count <= RETIRE_MAX_PAGES
            && (count == 1 || page.block_size() < SMALL_SIZE_MAX)
        {
            page.set_retire_expire(RETIRE_CYCLES);
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
        // This bounded small-page slice owns exactly the one fresh regular
        // 64KiB slice it claimed. Larger page kinds are deliberately absent.
        if slice_count != 1 {
            return None;
        }
        let size = slice_count.checked_mul(ARENA_SLICE_SIZE)?;
        let slice_start = self.arena.slice_start(slice_index)?;
        let block_size = page_ref.block_size();
        if block_size == 0 || block_size > SMALL_SIZE_MAX {
            return None;
        }
        // Validate `page_offset` in integer space. Calling `Page::start` on
        // malformed metadata would itself require the very layout guarantee
        // this preflight is meant to establish.
        let usable_offset = page::page_usable_start_offset(block_size)?;
        let expected_start = slice_start.addr().checked_add(usable_offset)?;
        if expected_start >= slice_start.addr().checked_add(size)?
            || expected_start.checked_sub(page.as_ptr().addr())? != page_ref.page_offset()
        {
            return None;
        }
        // SAFETY: this explicit lifecycle serializes all source-plain map
        // accesses. Keeping this equality before queue removal proves that
        // terminal unregistration will target the page's actual map span.
        if unsafe { self.page_map.checked_lookup(slice_start) } != page.as_ptr() {
            return None;
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
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE, MAX_ALIGN_SIZE, WORD_SIZE};
    use crate::os::{MemoryConfig, PageSize};
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    fn with_allocator(test: impl FnOnce(&mut SingleThreadSmallAllocator<'_, '_, '_>)) {
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
        let mut allocator = SingleThreadSmallAllocator::activate(
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
        let mut allocator = SingleThreadSmallAllocator::activate(
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
            assert_eq!(unsafe { allocator.free(invalid) }, Err(SmallFreeError::InvalidBlock(FreeListError::InvalidBlock)));
            // SAFETY: `zeroed` is still live after the rejected invalid free.
            unsafe { allocator.free(zeroed).unwrap() };
        });
    }
}
