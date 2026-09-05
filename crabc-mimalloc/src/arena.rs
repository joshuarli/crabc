// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// Copyright (c) 2019-2026 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/theap.c:308-334` (the selected
// requested-arena Theap allocation reservation), `src/arena.c:32-219` (arena identity,
// suitability, registry indexing, geometry, and arena memory IDs),
// `src/arena.c:1573-1659` (registry insertion and exact metadata/bitmap
// sizing), `src/arena.c:674-723` (lazy non-main `heap->arena_pages`
// allocation/Acquire lookup/Release publication), `src/arena.c:240-335`
// (single-arena slice claims,
// committed/dirty/zero observations, and commit rollback),
// `src/arena.c:832-1037` (aligned page metadata selection, fresh-page prefix
// commitment, and publication),
// `src/arena.c:1433-1490` (arena slice release),
// `src/arena.c:631-671,725-778,1304-1409` (ordinary-page proof plus mapped
// abandoned-page bitmap/count publication, claim, and quiescent clear),
// `src/arena.c:2238-2409` (default delayed arena purge scheduling and forced
// collection), and
// `src/arena.c:1676-1917` (in-place arena initialization, metadata
// reservation, external/regular-OS provenance, region alignment, and 16-GiB
// splitting).
// This substrate deliberately stops before arena iteration/search across the
// registry-wide arena search, fresh page routing beyond the one bounded
// heap-local `arena_pages` owner and its exact mapped-regular handoff,
// theap/TLS state, NUMA option lookup, statistics, and allocator-backed
// metadata.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::num::NonZeroUsize;
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicI64, AtomicPtr, Ordering};

use crate::atomic::{
    i64_cas_strong_acq_rel, i64_load_relaxed, i64_store_release,
    pointer_cas_strong_release, pointer_load_acquire, word_cas_strong_release,
    word_load_relaxed, AtomicWord,
};
use crate::abandoned::{MappedAbandonedClaim, MappedAbandonedPages};
use crate::bitmap::{
    AbandonedBitmapClaim, BinnedBitmapLayout, BinnedBitmapView, BitmapLayout,
    BitmapView, BCHUNK_SIZE,
};
use crate::config::{
    ARENA_ALIGNMENT, ARENA_BIN_COUNT, ARENA_MAX_SIZE, ARENA_MIN_OBJ_SIZE, ARENA_MIN_OBJ_SLICES,
    ARENA_MIN_SIZE, ARENA_SLICE_SIZE,
    BCHUNK_BITS, BITMAP_MAX_BIT_COUNT, MAX_ARENAS, PAGE_META_ALIGNED_COUNT,
};
use crate::invariants;
use crate::meta::{MetaAllocation, MetaAllocator, MetaError};
use crate::os::{self, DecommitOutcome, PageSize};
use crate::os::MemoryConfig;
use crate::subproc::MainSubprocess;
use crate::types::{
    Arena, ArenaPages, CommitFunction, Heap, HeapArenaPagesError, MemoryId,
    MemoryKind, Page, Subprocess, Theap, ThreadSequence,
};

#[path = "arena_selection.rs"]
mod selection;
pub(crate) use selection::{ArenaReservationPlan, ArenaSearch};

#[path = "arena_owned.rs"]
mod owned;
pub(crate) use owned::{ProcessArenaBacking, ProcessArenaInstallFailure};

// Fixed `src/options.c` defaults for the frozen v3.5.0 profile. This remains
// an arena-local delay because the one-thread slice has no source subprocess
// global-expiry owner or registry iteration policy yet.
const DEFAULT_PURGE_DELAY_MILLISECONDS: i64 = 1_000;
const DEFAULT_ARENA_PURGE_MULTIPLIER: i64 = 4;
const DEFAULT_ARENA_PURGE_DELAY_MILLISECONDS: i64 =
    DEFAULT_PURGE_DELAY_MILLISECONDS * DEFAULT_ARENA_PURGE_MULTIPLIER;

// Pinned v3.5.0's complete C `mi_theap_t` rounds to exactly this one source
// minimum-object slice in `_mi_theap_alloc`'s requested-arena branch. The C
// layout probe carries the companion complete-C-type assertion; this Rust
// assertion verifies only the fixed source constant, never a Rust/C Theap
// layout equality.
const _: [(); 1] = [(); (ARENA_MIN_OBJ_SLICES == 1) as usize];
// This is deliberately a Rust-prefix capacity proof, not an assertion about
// the complete pinned C `mi_theap_t`. The independent C layout probe remains
// the only proof about that full C type.
const _: [(); 1] = [(); (size_of::<Theap>() <= ARENA_MIN_OBJ_SIZE) as usize];
const _: [(); 1] = [(); (align_of::<Theap>() <= ARENA_MIN_OBJ_SIZE) as usize];
const _: [(); 1] = [(); (ARENA_ALIGNMENT % align_of::<Theap>() == 0) as usize];
const _: [(); 1] = [(); (ARENA_SLICE_SIZE % align_of::<Theap>() == 0) as usize];

/// Opaque public-source arena identity. Only parent arenas can become IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArenaId(Option<NonNull<Arena>>);

impl ArenaId {
    #[inline]
    pub(crate) const fn none() -> Self {
        Self(None)
    }

    /// Converts a source arena pointer to an ID after checking the parent-only
    /// identity invariant.
    ///
    /// # Safety
    ///
    /// `arena`, when non-null, must point to a live, registry-published arena.
    pub(crate) unsafe fn from_arena(arena: *mut Arena) -> Option<Self> {
        let Some(arena) = NonNull::new(arena) else {
            return Some(Self::none());
        };
        if unsafe { !arena.as_ref().parent.is_null() } {
            return None;
        }
        Some(Self(Some(arena)))
    }

    #[inline]
    pub(crate) const fn as_ptr(self) -> *mut Arena {
        match self.0 {
            Some(arena) => arena.as_ptr(),
            None => null_mut(),
        }
    }

    /// Returns the complete source area owned by a parent arena ID.
    ///
    /// # Safety
    ///
    /// The ID's backing external region must still be live.
    pub(crate) unsafe fn area(self) -> Option<(*mut u8, usize)> {
        let arena = self.0?;
        let arena = unsafe { arena.as_ref() };
        Some((arena.start, arena.total_size))
    }
}

/// Exact arena suitability relation used for requested exclusive arenas.
///
/// # Safety
///
/// Non-null pointers must name live initialized arenas.
pub(crate) unsafe fn arena_is_suitable(candidate: *mut Arena, requested: ArenaId) -> bool {
    let requested = requested.as_ptr();
    if candidate == requested {
        return true;
    }
    let Some(candidate) = NonNull::new(candidate) else {
        return false;
    };
    let candidate = unsafe { candidate.as_ref() };
    if requested.is_null() && !candidate.is_exclusive {
        return true;
    }
    !candidate.parent.is_null() && candidate.parent == requested
}

/// Applies [`arena_is_suitable`] to the arena provenance arm of a memory ID.
///
/// # Safety
///
/// Arena pointers carried by `memory` and `requested` must remain live.
pub(crate) unsafe fn memory_is_suitable(memory: MemoryId, requested: ArenaId) -> bool {
    let candidate = memory
        .arena_memory()
        .map_or(null_mut(), |arena| arena.arena);
    unsafe { arena_is_suitable(candidate, requested) }
}

/// Fixed-capacity source registry with Release publication and Acquire lookup.
pub(crate) struct ArenaRegistry {
    subprocess: AtomicPtr<Subprocess>,
    count: AtomicWord,
    arenas: [AtomicPtr<Arena>; MAX_ARENAS],
}

// SAFETY: every slot is independently atomically published. The subprocess
// pointer is selected once before registry publication, then only read as an
// immutable opaque identity and never dereferenced here.
unsafe impl Send for ArenaRegistry {}
unsafe impl Sync for ArenaRegistry {}

impl ArenaRegistry {
    pub(crate) const fn new(subprocess: *mut Subprocess) -> Self {
        Self {
            subprocess: AtomicPtr::new(subprocess),
            count: AtomicWord::new(0),
            arenas: [const { AtomicPtr::new(null_mut()) }; MAX_ARENAS],
        }
    }

    #[inline]
    pub(crate) fn count(&self) -> usize {
        word_load_relaxed(&self.count)
    }

    #[inline]
    pub(crate) fn subprocess(&self) -> *mut Subprocess {
        self.subprocess.load(Ordering::Acquire)
    }

    /// Selects the one source subprocess identity before any arena becomes
    /// visible through this registry.
    ///
    /// A same-identity retry is permitted only while the registry is still
    /// empty. Rebinding a populated registry would make its arena and bitmap
    /// pointers name a different subprocess, so it is rejected even if the
    /// address matches.
    ///
    /// # Safety
    ///
    /// The caller must hold the one-time initialization authority for this
    /// registry: no concurrent `insert` or arena publication may occur until
    /// this call returns. In particular, observing `count == 0` here is not a
    /// synchronization protocol with `insert`; it is a pre-publication
    /// invariant supplied by the caller. `subprocess` must be the process-long
    /// identity that every subsequently inserted arena names.
    #[inline]
    pub(crate) unsafe fn bind_subprocess_before_publication(
        &self,
        subprocess: *mut Subprocess,
    ) -> bool {
        if subprocess.is_null() || self.count() != 0 {
            return false;
        }
        let expected = core::ptr::null_mut();
        if self
            .subprocess
            .compare_exchange(
                expected,
                subprocess,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return true;
        }
        let found = self.subprocess.load(Ordering::Acquire);
        core::ptr::eq(found, subprocess)
    }

    #[inline]
    pub(crate) fn is_bound_to_subprocess(&self, subprocess: *mut Subprocess) -> bool {
        core::ptr::eq(self.subprocess(), subprocess)
    }

    /// Acquire-loads one previously allocated registry slot.
    ///
    /// # Safety
    ///
    /// The external storage of any returned arena must still be live.
    pub(crate) unsafe fn arena_at(&self, index: usize) -> Option<&Arena> {
        if index >= self.count() || index >= MAX_ARENAS {
            return None;
        }
        let arena = pointer_load_acquire(&self.arenas[index]);
        unsafe { arena.as_ref() }
    }

    /// Publishes an initialized arena, first reusing null slots and then
    /// growing the source's high-water count.
    ///
    /// # Safety
    ///
    /// `arena` must be uniquely owned, fully initialized, and remain live
    /// until the registry is quiesced. It must not already be registered.
    unsafe fn insert(&self, arena: *mut Arena) -> bool {
        if arena.is_null() {
            return false;
        }
        let mut count = self.count();
        for index in 0..count {
            if pointer_load_acquire(&self.arenas[index]).is_null() {
                unsafe { (*arena).arena_index = index };
                let mut expected = null_mut();
                if pointer_cas_strong_release(&self.arenas[index], &mut expected, arena) {
                    return true;
                }
            }
        }

        while count < MAX_ARENAS {
            let desired_count = count + 1;
            if word_cas_strong_release(&self.count, &mut count, desired_count) {
                unsafe { (*arena).arena_index = count };
                let mut expected = null_mut();
                if pointer_cas_strong_release(&self.arenas[count], &mut expected, arena) {
                    return true;
                }
            }
        }
        unsafe {
            (*arena).arena_index = 0;
            (*arena).subprocess = null_mut();
        }
        false
    }
}

/// Exact fixed-header plus dynamic-bitmap sizing for `mi_arena_pages_t`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArenaPagesLayout {
    slice_count: usize,
    bitmap_base: usize,
    bitmap_layout: BitmapLayout,
    byte_size: usize,
}

impl ArenaPagesLayout {
    pub(crate) fn for_slice_count(slice_count: usize) -> Option<Self> {
        let slice_count = if slice_count == 0 {
            BCHUNK_BITS
        } else {
            slice_count
        };
        if slice_count % BCHUNK_BITS != 0 {
            return None;
        }
        let bitmap_layout = BitmapLayout::for_bit_count(slice_count)?;
        let bitmap_base = invariants::align_up(size_of::<ArenaPages>(), BCHUNK_SIZE)?;
        let bitmap_count = 1usize.checked_add(ARENA_BIN_COUNT)?;
        let bitmaps_size = bitmap_count.checked_mul(bitmap_layout.byte_size())?;
        let byte_size = bitmap_base.checked_add(bitmaps_size)?;
        Some(Self {
            slice_count,
            bitmap_base,
            bitmap_layout,
            byte_size,
        })
    }

    #[inline]
    pub(crate) const fn slice_count(self) -> usize { self.slice_count }
    #[inline]
    pub(crate) const fn bitmap_base(self) -> usize { self.bitmap_base }
    #[inline]
    pub(crate) const fn bitmap_layout(self) -> BitmapLayout { self.bitmap_layout }
    #[inline]
    pub(crate) const fn byte_size(self) -> usize { self.byte_size }

    /// Returns the exact byte offset of one source `mi_bitmap_t` image.
    ///
    /// Bitmap zero is `mi_arena_pages_t::pages`; the following
    /// `ARENA_BIN_COUNT` images are the source `pages_abandoned[bin]` array.
    /// Naming the offset here keeps the private per-heap owner from treating
    /// the flexible C tail as a guessed Rust array layout.
    #[inline]
    pub(crate) const fn bitmap_offset(self, bitmap: usize) -> Option<usize> {
        if bitmap > ARENA_BIN_COUNT {
            return None;
        }
        let stride = self.bitmap_layout.byte_size();
        match bitmap.checked_mul(stride) {
            Some(offset) => self.bitmap_base.checked_add(offset),
            None => None,
        }
    }
}

/// One private failure while forming or retiring an allocator-owned dynamic
/// `mi_arena_pages_t` image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicArenaPagesOwnerError {
    Layout,
    Metadata(MetaError),
    Image,
    Heap(HeapArenaPagesError),
    ForeignArena,
    UnboundArenaSubprocess,
    ForeignArenaSubprocess,
    ForeignHeap,
    NotPublished,
    NonEmpty,
    Terminal,
}

/// Result of allocating the typed dynamic arena-pages image.
///
/// A metadata allocation failure has not formed an owner. An impossible
/// typed-image failure, in contrast, returns the exact retained capability so
/// the attachment cannot silently lose release authority.
pub(crate) enum DynamicArenaPagesOwnerCreateError {
    Error(DynamicArenaPagesOwnerError),
    Retained(DynamicArenaPagesOwner),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicArenaPagesOwnerState {
    Prepared,
    Published,
    Terminal,
    Released,
}

/// One linear, heap-local `mi_arena_pages_t` allocation for one dynamic Heap
/// and one source arena.
///
/// Pinned `mi_heap_ensure_arena_pages` lazily allocates this image for a
/// non-main heap, then stores it in `heap->arena_pages[arena_idx]` under the
/// private lock. This owner keeps the aligned `MetaAllocation` capability and
/// never aliases the arena's process-main `pages_main` / `pages_abandoned`
/// bitmaps. Its exact-page capability serves one consuming mapped-regular
/// handoff; general abandonment movement, multiple-arena ownership, and the
/// full source heap destruction protocol remain absent.
#[must_use = "dynamic arena-pages metadata must remain with its dynamic Heap owner"]
pub(crate) struct DynamicArenaPagesOwner {
    metadata: core::pin::Pin<&'static MetaAllocator>,
    allocation: Option<MetaAllocation<'static>>,
    heap: NonNull<Heap>,
    arena: NonNull<Arena>,
    arena_index: usize,
    layout: ArenaPagesLayout,
    state: DynamicArenaPagesOwnerState,
}

impl DynamicArenaPagesOwner {
    /// Allocates and initializes the source-sized image before it can be
    /// published into a Heap slot.
    ///
    /// The caller supplies an already registry-published `ArenaView`. Before
    /// any metadata allocation, this validates the source-initialized arena
    /// subprocess field against the attachment's selected main identity and
    /// snapshots its immutable registry index. Later operations use the raw
    /// arena pointer only for exact memory-ID identity checks.
    pub(crate) fn create(
        metadata: core::pin::Pin<&'static MetaAllocator>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        heap: &Heap,
        arena: &ArenaView<'_>,
    ) -> Result<Self, DynamicArenaPagesOwnerCreateError> {
        let source_arena = arena.arena();
        if source_arena.subprocess.is_null() {
            return Err(DynamicArenaPagesOwnerCreateError::Error(
                DynamicArenaPagesOwnerError::UnboundArenaSubprocess,
            ));
        }
        if !core::ptr::eq(source_arena.subprocess, subprocess.as_ptr()) {
            return Err(DynamicArenaPagesOwnerCreateError::Error(
                DynamicArenaPagesOwnerError::ForeignArenaSubprocess,
            ));
        }
        let layout = ArenaPagesLayout::for_slice_count(source_arena.slice_count)
            .ok_or(DynamicArenaPagesOwnerCreateError::Error(
                DynamicArenaPagesOwnerError::Layout,
            ))?;
        let mut allocation = metadata
            .zalloc_aligned_for_main_subprocess(config, subprocess, layout.byte_size(), BCHUNK_SIZE)
            .map_err(|error| {
                DynamicArenaPagesOwnerCreateError::Error(DynamicArenaPagesOwnerError::Metadata(error))
            })?;
        if !allocation.initialize_dynamic_arena_pages(metadata, layout) {
            return Err(DynamicArenaPagesOwnerCreateError::Retained(Self {
                metadata,
                allocation: Some(allocation),
                heap: NonNull::from(heap),
                arena: arena.arena,
                arena_index: source_arena.arena_index,
                layout,
                state: DynamicArenaPagesOwnerState::Terminal,
            }));
        }
        Ok(Self {
            metadata,
            allocation: Some(allocation),
            heap: NonNull::from(heap),
            arena: arena.arena,
            arena_index: source_arena.arena_index,
            layout,
            state: DynamicArenaPagesOwnerState::Prepared,
        })
    }

    #[inline]
    pub(crate) fn is_for_arena(&self, arena: &ArenaView<'_>) -> bool {
        self.arena == arena.arena
    }

    #[inline]
    pub(crate) fn is_published_for(&self, heap: &Heap) -> bool {
        self.state == DynamicArenaPagesOwnerState::Published
            && core::ptr::eq(self.heap.as_ptr(), core::ptr::from_ref(heap).cast_mut())
            && self
                .header_pointer()
                .is_some_and(|header| {
                    heap.dynamic_arena_pages_at(self.arena_index) == Some(header)
                })
    }

    /// Performs `mi_heap_ensure_arena_pages`'s non-main allocation branch:
    /// publish only an entirely initialized image under the Heap lock.
    pub(crate) fn publish(&mut self, heap: &Heap) -> Result<(), DynamicArenaPagesOwnerError> {
        if self.state != DynamicArenaPagesOwnerState::Prepared {
            return Err(if self.state == DynamicArenaPagesOwnerState::Terminal {
                DynamicArenaPagesOwnerError::Terminal
            } else {
                DynamicArenaPagesOwnerError::NotPublished
            });
        }
        if !core::ptr::eq(self.heap.as_ptr(), core::ptr::from_ref(heap).cast_mut()) {
            return Err(DynamicArenaPagesOwnerError::ForeignHeap);
        }
        let header = self.header_pointer().ok_or(DynamicArenaPagesOwnerError::Image)?;
        match heap.publish_dynamic_arena_pages(self.arena_index, header) {
            Ok(()) => {
                self.state = DynamicArenaPagesOwnerState::Published;
                Ok(())
            }
            Err(error) => {
                // An unlock error may follow the Release store. Re-read the
                // exact slot so the retained state never calls that outcome
                // a pre-publication retry.
                if heap.dynamic_arena_pages_at(self.arena_index) == Some(header) {
                    self.state = DynamicArenaPagesOwnerState::Terminal;
                }
                Err(DynamicArenaPagesOwnerError::Heap(error))
            }
        }
    }

    /// Marks one source arena slice as named by this dynamic Heap only after
    /// fresh page metadata exists and before page-map registration.
    pub(crate) fn set_page(&self, memory: MemoryId) -> bool {
        let Some(index) = self.slice_index(memory) else {
            return false;
        };
        self.with_pages(|pages| pages.set_range(index, 1))
            .is_some_and(|transition| transition.is_some_and(|run| run.all_transitioned()))
    }

    /// Clears exactly one dynamic Heap page bit after its PageMap range was
    /// removed and before the arena slice claim is released.
    pub(crate) fn clear_page(&self, memory: MemoryId) -> bool {
        let Some(index) = self.slice_index(memory) else {
            return false;
        };
        self.with_pages(|pages| pages.clear_range(index, 1)) == Some(Some(true))
    }

    #[inline]
    pub(crate) fn page_is_set(&self, memory: MemoryId) -> bool {
        let Some(index) = self.slice_index(memory) else {
            return false;
        };
        self.with_pages(|pages| pages.is_clear_range(index, 1)) == Some(Some(false))
    }

    #[inline]
    pub(crate) fn is_empty_published(&self) -> bool {
        self.state == DynamicArenaPagesOwnerState::Published && self.is_empty()
    }

    /// Proves that this one dynamic Heap image retains exactly one ordinary
    /// arena page and no mapped-abandoned publication. This is the source
    /// precondition for the bounded post-exit singleton transfer: after its
    /// Theap/TLD has gone, the detached owner may clear only this bit before
    /// it unpublishes and frees the image.
    pub(crate) fn has_exactly_one_page(&self, memory: MemoryId) -> bool {
        let Some(index) = self.slice_index(memory) else {
            return false;
        };
        if !self.page_is_set(memory) {
            return false;
        }
        let page_bits_are_exact = self.with_pages(|pages| {
            let before_is_clear = index == 0
                || pages.is_clear_range(0, index) == Some(true);
            let after_start = match index.checked_add(1) {
                Some(start) => start,
                None => return false,
            };
            let after_is_clear = after_start == self.layout.slice_count()
                || pages.is_clear_range(after_start, self.layout.slice_count() - after_start)
                    == Some(true);
            before_is_clear && after_is_clear
        }) == Some(true);
        page_bits_are_exact
            && (0..ARENA_BIN_COUNT).all(|bin| {
                self.with_abandoned(bin, |pages| {
                    pages.is_clear_range(0, self.layout.slice_count())
                }) == Some(Some(true))
            })
    }

    /// Forms the sole production capability allowed to publish one dynamic
    /// `pages_abandoned[bin]` bit. Its constructor requires the exact source
    /// arena, an already page-map-published ordinary slice, and a mapped
    /// regular bin; it cannot manufacture an abandoned identity for an
    /// arbitrary `MemoryId`.
    pub(crate) fn mapped_abandoned_page(
        &self,
        arena: &ArenaView<'_>,
        bin: usize,
        memory: MemoryId,
    ) -> Option<DynamicArenaMappedAbandonedPage<'_>> {
        if !self.is_for_arena(arena) || bin >= ARENA_BIN_COUNT || !self.page_is_set(memory) {
            return None;
        }
        Some(DynamicArenaMappedAbandonedPage {
            owner: self,
            bin,
            memory,
            slice_index: self.slice_index(memory)?,
        })
    }

    /// Removes this exact Heap slot and frees its retained capability only
    /// after every ordinary/abandoned bit is clear. A lock/free failure is a
    /// terminal invalid-owner state; this owner never reconstructs or retries
    /// uncertain metadata ownership.
    pub(crate) fn unpublish_and_free(
        &mut self,
        heap: &Heap,
    ) -> Result<(), DynamicArenaPagesOwnerError> {
        if self.state != DynamicArenaPagesOwnerState::Published {
            return Err(if self.state == DynamicArenaPagesOwnerState::Terminal {
                DynamicArenaPagesOwnerError::Terminal
            } else {
                DynamicArenaPagesOwnerError::NotPublished
            });
        }
        let header = self.header_pointer().ok_or(DynamicArenaPagesOwnerError::Image)?;
        if !core::ptr::eq(self.heap.as_ptr(), core::ptr::from_ref(heap).cast_mut())
            || heap.dynamic_arena_pages_at(self.arena_index) != Some(header)
        {
            return Err(DynamicArenaPagesOwnerError::ForeignHeap);
        }
        if !self.is_empty() {
            return Err(DynamicArenaPagesOwnerError::NonEmpty);
        }
        if let Err(error) = heap.remove_dynamic_arena_pages(self.arena_index, header) {
            // As above, a failing unlock may already have made the removal
            // visible. Retain the still-live allocation terminally instead
            // of claiming the original slot can be retried.
            if heap.dynamic_arena_pages_at(self.arena_index).is_none() {
                self.state = DynamicArenaPagesOwnerState::Terminal;
            }
            return Err(DynamicArenaPagesOwnerError::Heap(error));
        }
        let allocation = self
            .allocation
            .as_mut()
            .ok_or(DynamicArenaPagesOwnerError::Terminal)?;
        if let Err(error) = self.metadata.free(allocation) {
            self.state = DynamicArenaPagesOwnerState::Terminal;
            return Err(DynamicArenaPagesOwnerError::Metadata(error));
        }
        self.allocation = None;
        self.state = DynamicArenaPagesOwnerState::Released;
        Ok(())
    }

    #[inline]
    fn header_pointer(&self) -> Option<NonNull<ArenaPages>> {
        self.allocation
            .as_ref()?
            .dynamic_arena_pages_pointer(self.metadata, self.layout)
    }

    #[inline]
    fn slice_index(&self, memory: MemoryId) -> Option<usize> {
        let arena_memory = memory.arena_memory()?;
        if arena_memory.arena != self.arena.as_ptr() {
            return None;
        }
        let index = arena_memory.slice_index as usize;
        (index < self.layout.slice_count()).then_some(index)
    }

    #[inline]
    fn with_pages<R>(&self, operation: impl FnOnce(&BitmapView<'_>) -> R) -> Option<R> {
        if self.state != DynamicArenaPagesOwnerState::Published {
            return None;
        }
        self.allocation
            .as_ref()?
            .with_dynamic_arena_pages(self.metadata, self.layout, operation)
    }

    #[inline]
    fn with_abandoned<R>(
        &self,
        bin: usize,
        operation: impl FnOnce(&BitmapView<'_>) -> R,
    ) -> Option<R> {
        if self.state != DynamicArenaPagesOwnerState::Published {
            return None;
        }
        self.allocation
            .as_ref()?
            .with_dynamic_arena_abandoned_pages(self.metadata, self.layout, bin, operation)
    }

    fn is_empty(&self) -> bool {
        self.with_pages(|pages| pages.is_clear_range(0, self.layout.slice_count()))
            == Some(Some(true))
            && (0..ARENA_BIN_COUNT).all(|bin| {
                self.with_abandoned(bin, |pages| pages.is_clear_range(0, self.layout.slice_count()))
                    == Some(Some(true))
            })
    }

    #[inline]
    fn increment_abandoned_count(&self, bin: usize) {
        // SAFETY: this owner is created for exactly one pinned Heap and no
        // capability can retarget that raw identity.
        unsafe { self.heap.as_ref() }.increment_abandoned_count(bin);
    }

    #[inline]
    fn decrement_abandoned_count(&self, bin: usize) -> bool {
        // SAFETY: successful bitmap claim/clear consumes one prior publish
        // in this exact owner/bin pair.
        unsafe { self.heap.as_ref() }.decrement_abandoned_count(bin)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_image(&self) -> Option<(NonNull<ArenaPages>, ArenaPagesLayout, MemoryId)> {
        Some((self.header_pointer()?, self.layout, self.allocation.as_ref()?.memory_id()))
    }

    /// Test-only raw observation of one dynamic `pages_abandoned[bin]` bit.
    /// Production callers must instead form [`DynamicArenaMappedAbandonedPage`]
    /// so the ordinary page-image publication remains part of their capability
    /// proof. The terminal release test needs this narrower witness precisely
    /// after that ordinary bit has been cleared.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_abandoned_page_is_clear(&self, bin: usize, memory: MemoryId) -> bool {
        let Some(slice_index) = self.slice_index(memory) else {
            return false;
        };
        self.with_abandoned(bin, |pages| pages.is_clear_range(slice_index, 1)) == Some(Some(true))
    }
}

/// One exact mapped regular dynamic page that may be published to its one
/// `pages_abandoned[bin]` position after `abandoned.rs` installed the matching
/// source page identity. This is intentionally not constructible from a raw
/// bitmap or caller-provided slice number.
pub(crate) struct DynamicArenaMappedAbandonedPage<'owner> {
    owner: &'owner DynamicArenaPagesOwner,
    bin: usize,
    memory: MemoryId,
    slice_index: usize,
}

impl MappedAbandonedPages for DynamicArenaMappedAbandonedPage<'_> {
    #[inline]
    fn bin(&self) -> usize { self.bin }

    #[inline]
    fn page_slice_index(&self, memory: MemoryId) -> Option<usize> {
        let left = memory.arena_memory()?;
        let right = self.memory.arena_memory()?;
        (left.arena == right.arena
            && left.slice_index == right.slice_index
            && left.slice_count == right.slice_count)
            .then_some(self.slice_index)
    }

    #[inline]
    fn is_clear(&self, slice_index: usize) -> bool {
        slice_index == self.slice_index
            // `mi_page_arena_pages` asserts that the heap-local ordinary
            // `pages` bit still names this page before the corresponding
            // abandoned bit is observed. Do not make a stale dynamic bitmap
            // entry an allocation/reclaim candidate after terminal release
            // has removed that ordinary ownership record.
            && self.owner.page_is_set(self.memory)
            && self
                .owner
                .with_abandoned(self.bin, |pages| pages.is_clear_range(slice_index, 1))
                == Some(Some(true))
    }

    #[inline]
    fn publish(&self, slice_index: usize) -> bool {
        // The ordinary page image is published before the abandoned image in
        // `arena.c:_mi_arenas_page_abandon`; terminal release clears it only
        // after the abandoned path has quiesced. Keeping that relation at
        // this narrow capability prevents an already released dynamic slice
        // from being republished by a delayed abandon path.
        if slice_index != self.slice_index || !self.owner.page_is_set(self.memory) {
            return false;
        }
        let published = self.owner
            .with_abandoned(self.bin, |pages| pages.set_range(slice_index, 1))
            .is_some_and(|transition| transition.is_some_and(|run| run.all_transitioned()));
        if published {
            self.owner.increment_abandoned_count(self.bin);
        }
        published
    }

    #[inline]
    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        let claimed = self.owner
            .with_abandoned(self.bin, |pages| {
                let mut claim = claim;
                pages.try_find_and_claim_abandoned(thread_sequence, |slice_index| {
                    if slice_index == self.slice_index && self.owner.page_is_set(self.memory) {
                        claim(slice_index)
                    } else {
                        // A rejected candidate must be returned to the
                        // bitmap. In particular, never consume a stale
                        // abandoned bit whose ordinary heap-local `pages`
                        // authority has already disappeared.
                        AbandonedBitmapClaim::KeepSet
                    }
                })
            });
        let Some(claimed) = claimed else {
            return MappedAbandonedClaim::None;
        };
        let Some(slice_index) = claimed else {
            return MappedAbandonedClaim::None;
        };
        {
            let decremented = self.owner.decrement_abandoned_count(self.bin);
            if !decremented {
                return MappedAbandonedClaim::CountDecrementFailed(slice_index);
            }
        }
        MappedAbandonedClaim::Claimed(slice_index)
    }

    #[inline]
    fn clear_once_set(&self, slice_index: usize) -> bool {
        slice_index == self.slice_index
            && self
                .owner
                .with_abandoned(self.bin, |pages| {
                    // SAFETY: the dynamic owner was formed with this live,
                    // process-long subprocess and retains the arena image.
                    let subprocess = unsafe { &*self.owner.arena.as_ref().subprocess };
                    pages.clear_once_set(subprocess, slice_index)
                })
                == Some(Some(()))
    }

    #[inline]
    fn decrement_after_identity_clear(&self) -> bool {
        let decremented = self.owner.decrement_abandoned_count(self.bin);
        debug_assert!(
            decremented,
            "mapped unabandon must consume its paired heap count"
        );
        decremented
    }
}

/// Complete in-place metadata layout reserved at the start of one arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArenaInfoLayout {
    slice_count: usize,
    page_size: usize,
    arena_offset: usize,
    bitmap_base: usize,
    ordinary_bitmap: BitmapLayout,
    free_bitmap: BinnedBitmapLayout,
    bitmaps_end: usize,
    info_slices: usize,
}

impl ArenaInfoLayout {
    pub(crate) fn for_slice_count(slice_count: usize, page_size: usize) -> Option<Self> {
        let slice_count = if slice_count == 0 { BCHUNK_BITS } else { slice_count };
        if slice_count % BCHUNK_BITS != 0
            || slice_count > BITMAP_MAX_BIT_COUNT
            || !page_size.is_power_of_two()
        {
            return None;
        }
        let ordinary_bitmap = BitmapLayout::for_bit_count(slice_count)?;
        let free_bitmap = BinnedBitmapLayout::for_bit_count(slice_count)?;
        let page_meta_slices = page_metadata_slice_count()?;
        let arena_offset = invariants::size_of_slices(page_meta_slices)?;
        let arena_header_size = invariants::align_up(size_of::<Arena>(), BCHUNK_SIZE)?;
        let bitmap_base = arena_offset.checked_add(arena_header_size)?;
        let ordinary_bitmap_count = 4usize.checked_add(ARENA_BIN_COUNT)?;
        let ordinary_bytes = ordinary_bitmap_count.checked_mul(ordinary_bitmap.byte_size())?;
        let bitmaps_end = bitmap_base
            .checked_add(free_bitmap.byte_size())?
            .checked_add(ordinary_bytes)?;
        let info_size = invariants::align_up(bitmaps_end, page_size)?;
        let info_slices = invariants::slice_count_of_size(info_size)?;
        Some(Self {
            slice_count,
            page_size,
            arena_offset,
            bitmap_base,
            ordinary_bitmap,
            free_bitmap,
            bitmaps_end,
            info_slices,
        })
    }

    #[inline]
    pub(crate) const fn slice_count(self) -> usize { self.slice_count }
    #[inline]
    pub(crate) const fn page_size(self) -> usize { self.page_size }
    #[inline]
    pub(crate) const fn arena_offset(self) -> usize { self.arena_offset }
    #[inline]
    pub(crate) const fn bitmap_base(self) -> usize { self.bitmap_base }
    #[inline]
    pub(crate) const fn ordinary_bitmap(self) -> BitmapLayout { self.ordinary_bitmap }
    #[inline]
    pub(crate) const fn free_bitmap(self) -> BinnedBitmapLayout { self.free_bitmap }
    #[inline]
    pub(crate) const fn bitmaps_end(self) -> usize { self.bitmaps_end }
    #[inline]
    pub(crate) const fn info_slices(self) -> usize { self.info_slices }
    #[inline]
    pub(crate) const fn info_size(self) -> usize { self.info_slices * ARENA_SLICE_SIZE }
}

#[inline]
pub(crate) fn page_metadata_slice_count() -> Option<usize> {
    let bytes = PAGE_META_ALIGNED_COUNT.checked_mul(size_of::<Page>())?;
    invariants::slice_count_of_size(bytes)
}

/// Pure alignment and splitting plan for an externally supplied region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExternalArenaPlan {
    prefix_bytes: usize,
    aligned_address: usize,
    total_slice_count: usize,
    total_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArenaSplit {
    address: usize,
    slice_count: usize,
    total_size: usize,
    parent_index: Option<usize>,
}

impl ExternalArenaPlan {
    pub(crate) fn from_address(address: usize, size: usize) -> Option<Self> {
        if address == 0 {
            return None;
        }
        let aligned_address = invariants::align_up(address, ARENA_ALIGNMENT)?;
        let prefix_bytes = aligned_address.checked_sub(address)?;
        if prefix_bytes != 0
            && (prefix_bytes >= size || size.checked_sub(prefix_bytes)? < ARENA_ALIGNMENT)
        {
            return None;
        }
        let usable_size = size.checked_sub(prefix_bytes)?;
        let raw_slices = usable_size / ARENA_SLICE_SIZE;
        let total_slice_count = invariants::align_down(raw_slices, BCHUNK_BITS)?;
        let total_size = invariants::size_of_slices(total_slice_count)?;
        if total_size < ARENA_MIN_SIZE {
            return None;
        }
        Some(Self {
            prefix_bytes,
            aligned_address,
            total_slice_count,
            total_size,
        })
    }

    #[inline]
    pub(crate) const fn prefix_bytes(self) -> usize { self.prefix_bytes }
    #[inline]
    pub(crate) const fn aligned_address(self) -> usize { self.aligned_address }
    #[inline]
    pub(crate) const fn total_slice_count(self) -> usize { self.total_slice_count }
    #[inline]
    pub(crate) const fn total_size(self) -> usize { self.total_size }

    pub(crate) const fn arena_count(self) -> usize {
        (self.total_slice_count + BITMAP_MAX_BIT_COUNT - 1) / BITMAP_MAX_BIT_COUNT
    }

    pub(crate) fn split(self, index: usize) -> Option<ArenaSplit> {
        if index >= self.arena_count() {
            return None;
        }
        let preceding_slices = index.checked_mul(BITMAP_MAX_BIT_COUNT)?;
        let remaining = self.total_slice_count.checked_sub(preceding_slices)?;
        let slice_count = core::cmp::min(remaining, BITMAP_MAX_BIT_COUNT);
        let byte_offset = invariants::size_of_slices(preceding_slices)?;
        let address = self.aligned_address.checked_add(byte_offset)?;
        Some(ArenaSplit {
            address,
            slice_count,
            total_size: if index == 0 { self.total_size } else { 0 },
            parent_index: if index == 0 { None } else { Some(0) },
        })
    }
}

impl ArenaSplit {
    #[inline]
    pub(crate) const fn address(self) -> usize { self.address }
    #[inline]
    pub(crate) const fn slice_count(self) -> usize { self.slice_count }
    #[inline]
    pub(crate) const fn total_size(self) -> usize { self.total_size }
    #[inline]
    pub(crate) const fn parent_index(self) -> Option<usize> { self.parent_index }
}

/// Optional externally supplied metadata commit hook.
#[derive(Clone, Copy)]
pub(crate) struct CommitHook {
    function: CommitFunction,
    argument: *mut c_void,
}

impl CommitHook {
    pub(crate) const fn new(function: CommitFunction, argument: *mut c_void) -> Self {
        Self { function, argument }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManageArenaError {
    InvalidRegion,
    InvalidPageSize,
    MetadataDoesNotFit,
    CommitRequired,
    CommitFailed,
    RegistryFull,
    BitmapInitialization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedExternalRegion {
    arena_id: ArenaId,
    total_size: usize,
    managed_size: usize,
}

impl ManagedExternalRegion {
    #[inline]
    pub(crate) const fn arena_id(self) -> ArenaId { self.arena_id }
    #[inline]
    pub(crate) const fn total_size(self) -> usize { self.total_size }
    #[inline]
    pub(crate) const fn managed_size(self) -> usize { self.managed_size }
    #[inline]
    pub(crate) const fn is_complete(self) -> bool { self.total_size == self.managed_size }
}

/// Registers an externally supplied region as one or more in-place arenas.
///
/// The first arena retains the external memory ID and total ownership size;
/// later 16-GiB sub-arenas retain `MemoryKind::None` and point to the first.
/// If a later registry insertion fails, the source's partial-success contract
/// is preserved by reducing the parent ownership size to the managed prefix.
///
/// # Safety
///
/// `start..start + size` must be one live writable allocation/provenance range
/// for the entire registry lifetime. Bytes described as already committed and
/// zero must truly have those properties. When `initially_committed` is false,
/// `commit_hook` must make each metadata prefix writable before returning true.
/// No other thread may access the region until this function returns.
/// The registry must be bound to an initialized subprocess that remains live
/// for every arena and bitmap view; their unconditional statistics events
/// access that owner through shared atomics.
pub(crate) unsafe fn manage_external_in_place(
    registry: &ArenaRegistry,
    start: *mut u8,
    size: usize,
    page_size: PageSize,
    initially_committed: bool,
    is_pinned: bool,
    initially_zero: bool,
    numa_node: i32,
    exclusive: bool,
    commit_hook: Option<CommitHook>,
) -> Result<ManagedExternalRegion, ManageArenaError> {
    let memory = MemoryId::external(
        start,
        size,
        initially_committed,
        is_pinned,
        initially_zero,
    );
    unsafe {
        manage_in_place(
            registry,
            start,
            size,
            page_size,
            initially_committed,
            numa_node,
            exclusive,
            commit_hook,
            memory,
        )
    }
}

/// Registers one regular OS mapping as one or more in-place arenas.
///
/// This is the `mi_reserve_os_memory_ex2` memory-ID branch after its regular
/// aligned map has succeeded. It deliberately records `MemoryKind::Os`, never
/// a large-page or externally supplied backing kind; reservation policy stays
/// with the caller which owns that map's later release decision.
///
/// # Safety
///
/// `start..start + size` must remain the exact live regular OS mapping for the
/// registry lifetime. `memory` must be the exact unpinned `MemoryKind::Os`
/// provenance for that complete range, including its commitment and zero
/// observations. When it starts reserved, `commit_hook` must make every
/// requested metadata prefix writable before returning true. No other thread
/// may access the region until this function returns.
/// The registry's initialized subprocess must outlive every resulting arena
/// and bitmap view, including later subprocess statistics updates.
pub(crate) unsafe fn manage_os_in_place(
    registry: &ArenaRegistry,
    start: *mut u8,
    size: usize,
    page_size: PageSize,
    memory: MemoryId,
    numa_node: i32,
    exclusive: bool,
    commit_hook: Option<CommitHook>,
) -> Result<ManagedExternalRegion, ManageArenaError> {
    let Some(os_memory) = memory.os_memory() else {
        return Err(ManageArenaError::InvalidRegion);
    };
    if memory.kind() != MemoryKind::Os
        || memory.is_pinned()
        || os_memory.base != start
        || os_memory.size != size
    {
        return Err(ManageArenaError::InvalidRegion);
    }
    let initially_committed = memory.initially_committed();
    unsafe {
        manage_in_place(
            registry,
            start,
            size,
            page_size,
            initially_committed,
            numa_node,
            exclusive,
            commit_hook,
            memory,
        )
    }
}

/// Common source management loop after the caller selected the backing
/// provenance. The two public entry points above keep `MI_MEM_EXTERNAL` and
/// regular `MI_MEM_OS` distinct while preserving the same source arena setup.
///
/// # Safety
///
/// The caller upholds the backing range and commitment contract documented by
/// its public entry point. `memory` must describe that same complete range.
unsafe fn manage_in_place(
    registry: &ArenaRegistry,
    start: *mut u8,
    size: usize,
    page_size: PageSize,
    initially_committed: bool,
    numa_node: i32,
    exclusive: bool,
    commit_hook: Option<CommitHook>,
    mut memory: MemoryId,
) -> Result<ManagedExternalRegion, ManageArenaError> {
    let plan = ExternalArenaPlan::from_address(start as usize, size)
        .ok_or(ManageArenaError::InvalidRegion)?;
    let aligned_start = unsafe { start.add(plan.prefix_bytes()) };
    let mut parent = null_mut();
    let mut parent_id = ArenaId::none();
    let mut managed_size = 0usize;

    for index in 0..plan.arena_count() {
        let split = plan.split(index).ok_or(ManageArenaError::InvalidRegion)?;
        let offset = split.address() - plan.aligned_address();
        let arena_start = unsafe { aligned_start.add(offset) };
        let arena_size = invariants::size_of_slices(split.slice_count())
            .ok_or(ManageArenaError::InvalidRegion)?;
        let initialized = unsafe {
            initialize_arena_in_place(
                registry,
                arena_start,
                arena_size,
                split.slice_count(),
                parent,
                split.total_size(),
                page_size.bytes(),
                numa_node,
                exclusive,
                memory,
                initially_committed,
                commit_hook,
            )
        };
        match initialized {
            Ok(arena) => {
                if parent.is_null() {
                    parent = arena;
                    parent_id = unsafe { ArenaId::from_arena(arena) }
                        .ok_or(ManageArenaError::RegistryFull)?;
                    memory.relinquish_ownership();
                }
                managed_size = managed_size
                    .checked_add(arena_size)
                    .ok_or(ManageArenaError::InvalidRegion)?;
            }
            Err(error) if parent.is_null() => return Err(error),
            Err(_) => {
                unsafe { (*parent).total_size = managed_size };
                return Ok(ManagedExternalRegion {
                    arena_id: parent_id,
                    total_size: plan.total_size(),
                    managed_size,
                });
            }
        }
    }

    Ok(ManagedExternalRegion {
        arena_id: parent_id,
        total_size: plan.total_size(),
        managed_size,
    })
}

/// A live, contiguous claim from one initialized external arena.
///
/// The claim has no destructor: its owner transfers the exact source release
/// obligation either through [`Self::release`], through
/// [`Self::release_for_subprocess`] when the source caller carries a
/// subprocess identity, or, when later page lifecycle code stores the
/// provenance, through the same `ProcessArenaBacking::release_slices` for a
/// process-owned claim, or the historical [`release_arena_slices`] for an
/// explicitly external selected-arena claim. Keeping that transfer
/// explicit prevents an implicit drop from returning slices while a page still
/// refers to them.
pub(crate) struct ArenaSliceClaim<'arena> {
    arena: NonNull<Arena>,
    start: NonNull<u8>,
    memory: MemoryId,
    backing: Option<&'arena ProcessArenaBacking>,
    _arena: PhantomData<&'arena Arena>,
}

impl ArenaSliceClaim<'_> {
    #[inline]
    pub(crate) const fn start(&self) -> *mut u8 {
        self.start.as_ptr()
    }

    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.memory
    }

    #[inline]
    pub(crate) fn slice_index(&self) -> usize {
        // Constructed only by `MemoryId::from_arena` in
        // `ArenaView::try_claim_suitable_slices`.
        self.memory.arena_memory().unwrap().slice_index as usize
    }

    #[inline]
    pub(crate) fn slice_count(&self) -> usize {
        // Constructed only by `MemoryId::from_arena` in
        // `ArenaView::try_claim_suitable_slices`.
        self.memory.arena_memory().unwrap().slice_count as usize
    }

    /// Returns the aligned metadata slot for this fresh arena-page claim.
    ///
    /// This is only the `mi_arena_page_meta` selection-and-commit boundary.
    /// The future fresh-page path owns the subsequent zero initialization and
    /// field publication from `mi_arenas_page_alloc_fresh`; it must not expose
    /// the returned `Page` to page-map or queue users beforehand.
    pub(crate) fn page_metadata(&self) -> Option<NonNull<Page>> {
        let arena = unsafe { self.arena.as_ref() };
        let arena_memory = self.memory.arena_memory()?;
        if arena_memory.arena != self.arena.as_ptr() {
            return None;
        }
        let slice_index = arena_memory.slice_index as usize;
        let metadata_slice_index =
            invariants::align_down(slice_index, PAGE_META_ALIGNED_COUNT)?;
        let metadata_slice_count = page_metadata_slice_count()?;
        let metadata_end = metadata_slice_index.checked_add(metadata_slice_count)?;
        if metadata_end > arena.slice_count {
            return None;
        }

        let layout = BitmapLayout::for_bit_count(arena.slice_count)?;
        let committed = unsafe {
            BitmapView::attach(arena.slices_committed, layout.byte_size(), layout)
        }?;
        if committed.is_clear_range(metadata_slice_index, 1)? {
            let metadata_start = arena_slice_start(arena, metadata_slice_index)?;
            let metadata_size = invariants::size_of_slices(metadata_slice_count)?;
            let commit = arena.commit_function?;
            let committed_now = unsafe {
                commit(
                    true,
                    metadata_start,
                    metadata_size,
                    null_mut(),
                    arena.commit_function_argument,
                )
            };
            if !committed_now {
                return None;
            }
            committed.set_range(metadata_slice_index, metadata_slice_count)?;
        }

        let metadata_start = arena_slice_start(arena, metadata_slice_index)?;
        let page_offset = slice_index
            .checked_sub(metadata_slice_index)?
            .checked_mul(size_of::<Page>())?;
        NonNull::new(unsafe { metadata_start.add(page_offset).cast::<Page>() })
    }

    /// Commits the initial prefix of one freshly claimed on-demand page.
    ///
    /// This is the `mi_arenas_page_alloc_fresh` `mi_arena_commit` call after
    /// the claim has deliberately observed `initially_committed == false`.
    /// It intentionally does not mutate `slices_committed`: a partial page
    /// prefix is tracked by `Page::slice_pcommitted`, while that bitmap records
    /// complete source arena slices. The bounded test-only page-on-demand
    /// seam reaches this only for a process-owned arena with its stable commit
    /// callback; an arena with no callback remains an explicit unsupported
    /// source-policy path here.
    #[inline]
    pub(crate) fn commit_initial_page_prefix(&self, size: usize) -> bool {
        let Some(span_size) = self.slice_count().checked_mul(ARENA_SLICE_SIZE) else {
            return false;
        };
        if size == 0 || size > span_size {
            return false;
        }
        let arena = unsafe { self.arena.as_ref() };
        let Some(commit) = arena.commit_function else {
            return false;
        };
        let mut is_zero = false;
        // SAFETY: `self` owns the exact live slice span, the validated prefix
        // begins at its leading slice, and the arena callback is stable while
        // the registered arena remains live.
        unsafe {
            commit(
                true,
                self.start.as_ptr(),
                size,
                &mut is_zero,
                arena.commit_function_argument,
            )
        }
    }

    /// Returns this exact claim to its source free bitmap.
    ///
    /// Consuming the claim makes a second safe release impossible. `false`
    /// reports a violated source ownership invariant, including an already
    /// free span introduced through an unsafe external release.
    #[inline]
    pub(crate) fn release(self) -> bool {
        if let Some(backing) = self.backing {
            return unsafe { backing.release_slices(self.memory) };
        }
        unsafe { release_arena_slices(self.memory) }
    }

    /// Returns this exact claim to its source free bitmap for `subprocess`.
    ///
    /// This is the selected `MI_MEM_ARENA` identity gate in
    /// `src/subproc.c:_mi_meta_free` and `src/arena.c:_mi_arenas_free`:
    /// source requires `arena->subproc == subproc` before it schedules an
    /// optional purge or returns the span to `slices_free`. A foreign
    /// subprocess is rejected before either mutation and receives the exact
    /// unchanged claim back in `Err`. The bounded Rust API makes that source
    /// assertion an explicit safe refusal; it does not model C diagnostics or
    /// a general `mi_subproc_t` lifecycle.
    ///
    /// `Ok(false)` has the same consumed, non-retryable invalid-ownership
    /// meaning as [`Self::release`]: this safe claim should normally make the
    /// source free-bit transition succeed, while a violated underlying source
    /// invariant may already have scheduled a purge before reporting false.
    #[inline]
    pub(crate) fn release_for_subprocess(
        self,
        subprocess: &MainSubprocess,
    ) -> Result<bool, Self> {
        // SAFETY: `ArenaSliceClaim` is formed only from the live arena behind
        // its borrowing `ArenaView`; the same source lifetime obligation that
        // permits `release` makes this identity read valid.
        let arena = unsafe { self.arena.as_ref() };
        if !core::ptr::eq(arena.subprocess, subprocess.as_ptr()) {
            return Err(self);
        }
        Ok(self.release())
    }
}

/// One private reservation for the requested-arena arm of
/// `src/theap.c:_mi_theap_alloc`.
///
/// Pinned C rounds its complete `mi_theap_t` request to one
/// `MI_ARENA_MIN_OBJ_SIZE` slice, asks only the already selected parent arena
/// for committed storage, and records the resulting `MI_MEM_ARENA` identity
/// before `_mi_theap_init` performs any Theap initialization or publication.
/// Reservation by itself captures that allocation/provenance boundary only:
/// it does not construct a Rust [`crate::types::Theap`] prefix, claim a C
/// `sizeof(mi_theap_t)` equivalence, attach a TLD, publish a heap/TLS/list
/// root, or implement `_mi_theap_create`. Its consuming
/// [`Self::materialize_rust_theap_prefix`] transition is the separate bounded
/// Rust-prefix owner.
///
/// The stored subprocess identity makes a release through a foreign process
/// structurally unavailable. Its explicit consuming [`Self::release`] follows
/// the existing selected arena release gate; dropping either the reservation
/// or a later prefix owner deliberately retains the slice rather than
/// guessing cleanup for a partially completed source lifecycle.
#[must_use = "an exclusive-arena Theap reservation must be explicitly released or retained"]
pub(crate) struct ExclusiveArenaTheapReservation<'arena, 'subprocess> {
    claim: ArenaSliceClaim<'arena>,
    subprocess: &'subprocess MainSubprocess,
}

impl<'arena, 'subprocess> ExclusiveArenaTheapReservation<'arena, 'subprocess> {
    /// Returns the selected source `mi_memid_t` result that a future complete
    /// Theap owner must store before `_mi_theap_init` copies its empty image.
    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.claim.memory_id()
    }

    #[inline]
    pub(crate) fn slice_index(&self) -> usize {
        self.claim.slice_index()
    }

    #[inline]
    pub(crate) fn slice_count(&self) -> usize {
        self.claim.slice_count()
    }

    /// Releases this exact requested-arena reservation through its selected
    /// subprocess identity.
    ///
    /// `Ok(false)` is the underlying consumed, non-retryable arena-free
    /// invariant result. `Err(Self)` is retained only if an impossible future
    /// mutation invalidates the arena/subprocess identity before the existing
    /// source gate; it preserves the exact reservation rather than guessing a
    /// different release owner.
    #[inline]
    pub(crate) fn release(self) -> Result<bool, Self> {
        let Self { claim, subprocess } = self;
        match claim.release_for_subprocess(subprocess) {
            Ok(released) => Ok(released),
            Err(claim) => Err(Self { claim, subprocess }),
        }
    }

    /// Materializes the bounded Rust [`Theap`] prefix in this exact source
    /// arena slice.
    ///
    /// Pinned `_mi_theap_alloc` returns raw aligned storage and writes only
    /// `theap->memid` before `_mi_theap_init` copies its empty image. Rust
    /// must first establish a valid value in that raw storage so the later
    /// source-order prefix initializer can safely preserve and replace it.
    /// The returned linear owner retains both the raw storage and the
    /// selected subprocess release capability; it deliberately does not
    /// expose an untyped allocation address or auto-release on Drop.
    ///
    /// # Safety
    ///
    /// No live Rust object may already occupy this exact claimed slice. The
    /// caller must retain the returned owner until it either finishes the
    /// matching detach/clear/release sequence or is intentionally retained as
    /// a terminal source-owner failure.
    #[inline]
    pub(crate) unsafe fn materialize_rust_theap_prefix(
        self,
    ) -> ExclusiveArenaTheapStorage<'arena, 'subprocess> {
        let prefix = NonNull::new(self.claim.start().cast::<Theap>())
            .expect("an arena slice claim always has a non-null start");
        debug_assert_eq!(prefix.as_ptr().addr() % align_of::<Theap>(), 0);
        // SAFETY: the caller proves this exact raw source slice has no live
        // Rust object. The static prefix-fit assertions above prove its
        // placement fits within the one selected source minimum-object slice.
        unsafe { prefix.as_ptr().write(Theap::empty()) };
        ExclusiveArenaTheapStorage {
            reservation: self,
            prefix,
        }
    }
}

/// One typed Rust Theap-prefix image occupying a selected requested-parent
/// arena slice.
///
/// This is intentionally not a complete C `mi_theap_t` allocation: Rust's
/// [`Theap`] stops before the unported statistics tail and any conditional C
/// fields. It owns only the prefix object and its exact arena reservation, so
/// an arena-specific lifecycle can preserve `_mi_theap_alloc` provenance and
/// `_mi_theap_init` ordering without claiming C-layout equivalence.
///
/// The raw prefix has no destructor-backed owner. Its explicit
/// [`Self::drop_prefix_then_release`] transition drops the initialized Rust
/// prefix only after source detachment cleared its live links/refcount, then
/// returns its now-untyped slice through the selected subprocess. Dropping
/// this storage otherwise deliberately retains the source slice.
#[must_use = "an arena-backed Theap prefix must be detached and released or retained terminally"]
pub(crate) struct ExclusiveArenaTheapStorage<'arena, 'subprocess> {
    reservation: ExclusiveArenaTheapReservation<'arena, 'subprocess>,
    prefix: NonNull<Theap>,
}

impl<'arena, 'subprocess> ExclusiveArenaTheapStorage<'arena, 'subprocess> {
    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.reservation.memory_id()
    }

    /// Projects the one initialized Rust prefix while this linear storage
    /// owner remains live. No raw alias is returned.
    #[inline]
    pub(crate) fn prefix_mut(&mut self) -> &mut Theap {
        // SAFETY: `materialize_rust_theap_prefix` initialized exactly this
        // object, and the linear owner supplies the only safe mutable route.
        unsafe { self.prefix.as_mut() }
    }

    /// Test-only address observation for the typed Rust prefix. It does not
    /// lend dereference authority or claim any complete C-layout identity.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_prefix_address(&self) -> usize {
        self.prefix.as_ptr().addr()
    }

    /// Drops the cleared Rust prefix and then releases its selected arena
    /// slice.
    ///
    /// The Rust `TheapRandomImage` has a real destructor, unlike the C source
    /// image. It must run before `slices_free` makes these bytes reusable. A
    /// rejected selected-subprocess gate therefore returns only the exact
    /// still-retained reservation: the prefix is already destroyed and cannot
    /// safely be reconstructed or projected again.
    ///
    /// # Safety
    ///
    /// The caller must have detached both intrusive lists and completed the
    /// arena Theap's final refcount transition. No raw pointer/reference to
    /// the prefix may survive this consuming transition.
    #[inline]
    pub(crate) unsafe fn drop_prefix_then_release(
        self,
    ) -> Result<bool, ExclusiveArenaTheapReservation<'arena, 'subprocess>> {
        let Self {
            reservation,
            prefix,
        } = self;
        // SAFETY: forwarded from this method's caller. This drop zeroizes the
        // Rust random image while its raw slice is still exclusively claimed.
        unsafe { core::ptr::drop_in_place(prefix.as_ptr()) };
        reservation.release()
    }
}

/// Returns an arena-backed source span to `slices_free`.
///
/// This is the arena branch of `_mi_arenas_free`, including the frozen-default
/// deferred decommit schedule before the span returns to `slices_free`. It is
/// separate from [`ArenaSliceClaim::release`] because the later page lifecycle
/// stores only `MemoryId` in `Page`.
///
/// # Safety
///
/// `memory` must be the still-live, arena-backed provenance of exactly one
/// outstanding claim. Its arena must remain registry-published and live for
/// the call, and no other operation may release the same span. The source
/// binned bitmap is atomic, but a false result signals that these ownership
/// obligations were already violated; callers must not treat it as a retry.
pub(crate) unsafe fn release_arena_slices(memory: MemoryId) -> bool {
    let Some(arena_memory) = memory.arena_memory() else {
        return false;
    };
    let Some(arena) = NonNull::new(arena_memory.arena) else {
        return false;
    };
    let arena = unsafe { arena.as_ref() };
    let slice_index = arena_memory.slice_index as usize;
    let slice_count = arena_memory.slice_count as usize;
    if !arena_slice_range_is_usable(arena, slice_index, slice_count) {
        return false;
    }

    let Some(layout) = BinnedBitmapLayout::for_bit_count(arena.slice_count) else {
        return false;
    };
    let Some(free) = (unsafe {
        BinnedBitmapView::attach(arena.slices_free, layout.byte_size(), layout)
    }) else {
        return false;
    };
    if !schedule_arena_purge(arena, slice_index, slice_count) {
        return false;
    }
    free.set_range(slice_index, slice_count) == Some(true)
}

/// Ports `mi_arena_schedule_purge` for the frozen default option image.
///
/// Normal anonymous external backing is unpinned and therefore schedules the
/// default 4-second delayed `purge_decommits=1` path. Pinned backing keeps the
/// source's strict skip. The source clock has no failure return; this port
/// cannot make optional purge scheduling a terminal ownership transition:
/// if the direct clock fails or the delay cannot be represented, the caller
/// returns the slice to the free bitmap without scheduling a purge.
fn schedule_arena_purge(arena: &Arena, slice_index: usize, slice_count: usize) -> bool {
    if arena.memid.is_pinned() {
        return true;
    }
    let Some(layout) = BitmapLayout::for_bit_count(arena.slice_count) else {
        return false;
    };
    let Some(purge) = (unsafe {
        BitmapView::attach(arena.slices_purge, layout.byte_size(), layout)
    }) else {
        return false;
    };
    let Ok(now) = os::monotonic_milliseconds() else {
        return true;
    };
    let Some(expire) = now.checked_add(DEFAULT_ARENA_PURGE_DELAY_MILLISECONDS) else {
        return true;
    };
    let mut expected = 0;
    let _ = i64_cas_strong_acq_rel(&arena.purge_expire, &mut expected, expire);
    purge.set_range(slice_index, slice_count).is_some()
}

#[inline]
fn arena_slice_start(arena: &Arena, slice_index: usize) -> Option<*mut u8> {
    if slice_index >= arena.slice_count {
        return None;
    }
    let offset = invariants::size_of_slices(slice_index)?;
    Some(unsafe { arena.start.add(offset) })
}

/// Checks the source's reservation boundaries before accepting an untyped
/// arena `MemoryId` for release. A valid claim can never overlap the initial
/// info prefix or any later aligned page-metadata prefix.
fn arena_slice_range_is_usable(arena: &Arena, slice_index: usize, slice_count: usize) -> bool {
    if slice_count == 0 {
        return false;
    }
    let Some(end) = slice_index.checked_add(slice_count) else {
        return false;
    };
    if end > arena.slice_count {
        return false;
    }
    let Some(metadata_slice_count) = page_metadata_slice_count() else {
        return false;
    };
    let mut metadata_start = 0usize;
    while metadata_start < arena.slice_count {
        let reserved = if metadata_start == 0 {
            arena.info_slices
        } else {
            metadata_slice_count
        };
        let Some(reserved_end) = metadata_start.checked_add(reserved) else {
            return false;
        };
        if slice_index < reserved_end && end > metadata_start {
            return false;
        }
        let Some(next) = metadata_start.checked_add(PAGE_META_ALIGNED_COUNT) else {
            return false;
        };
        metadata_start = next;
    }
    true
}

#[allow(clippy::too_many_arguments)]
unsafe fn initialize_arena_in_place(
    registry: &ArenaRegistry,
    start: *mut u8,
    region_size: usize,
    slice_count: usize,
    parent: *mut Arena,
    total_size: usize,
    page_size: usize,
    numa_node: i32,
    exclusive: bool,
    memory: MemoryId,
    metadata_already_accessible: bool,
    commit_hook: Option<CommitHook>,
) -> Result<*mut Arena, ManageArenaError> {
    if start.is_null()
        || (start as usize) % ARENA_ALIGNMENT != 0
        || slice_count == 0
        || slice_count > BITMAP_MAX_BIT_COUNT
        || slice_count % BCHUNK_BITS != 0
        || region_size < ARENA_MIN_SIZE
    {
        return Err(ManageArenaError::InvalidRegion);
    }
    let layout = ArenaInfoLayout::for_slice_count(slice_count, page_size)
        .ok_or(ManageArenaError::InvalidPageSize)?;
    if slice_count < layout.info_slices() + 1 || region_size < layout.info_size() {
        return Err(ManageArenaError::MetadataDoesNotFit);
    }

    if !memory.initially_committed() && !metadata_already_accessible {
        let Some(hook) = commit_hook else {
            return Err(ManageArenaError::CommitRequired);
        };
        let committed = unsafe {
            (hook.function)(true, start, layout.info_size(), null_mut(), hook.argument)
        };
        if !committed {
            return Err(ManageArenaError::CommitFailed);
        }
    }
    if !memory.initially_zero() {
        unsafe { core::ptr::write_bytes(start, 0, layout.info_size()) };
    }

    let arena = unsafe { start.add(layout.arena_offset()).cast::<Arena>() };
    let ordinary_size = layout.ordinary_bitmap().byte_size();
    let mut cursor = unsafe { start.add(layout.bitmap_base()) };
    let slices_free = cursor;
    cursor = unsafe { cursor.add(layout.free_bitmap().byte_size()) };
    let slices_committed = cursor;
    cursor = unsafe { cursor.add(ordinary_size) };
    let slices_dirty = cursor;
    cursor = unsafe { cursor.add(ordinary_size) };
    let slices_purge = cursor;
    cursor = unsafe { cursor.add(ordinary_size) };
    let pages = cursor;
    cursor = unsafe { cursor.add(ordinary_size) };
    let mut pages_abandoned = [null_mut(); ARENA_BIN_COUNT];
    for pointer in &mut pages_abandoned {
        *pointer = cursor;
        cursor = unsafe { cursor.add(ordinary_size) };
    }
    if cursor as usize - start as usize != layout.bitmaps_end() {
        return Err(ManageArenaError::BitmapInitialization);
    }

    let hook_function = commit_hook.map(|hook| hook.function);
    let hook_argument = commit_hook.map_or(null_mut(), |hook| hook.argument);
    unsafe {
        arena.write(Arena {
            memid: memory,
            subprocess: registry.subprocess(),
            arena_index: 0,
            start,
            slice_count,
            info_slices: layout.info_slices(),
            numa_node,
            is_exclusive: exclusive,
            purge_expire: AtomicI64::new(0),
            commit_function: hook_function,
            commit_function_argument: hook_argument,
            total_size,
            parent,
            slices_free,
            slices_committed,
            slices_dirty,
            slices_purge,
            pages_meta: null_mut(),
            pages_main: ArenaPages {
                pages,
                pages_abandoned,
            },
        })
    };

    let mut free = unsafe {
        BinnedBitmapView::initialize(
            registry.subprocess(),
            slices_free,
            layout.free_bitmap().byte_size(),
            layout.free_bitmap(),
            true,
        )
    }
    .ok_or(ManageArenaError::BitmapInitialization)?;
    let mut committed = unsafe {
        BitmapView::initialize(
            slices_committed,
            ordinary_size,
            layout.ordinary_bitmap(),
            true,
        )
    }
    .ok_or(ManageArenaError::BitmapInitialization)?;
    let mut dirty = unsafe {
        BitmapView::initialize(
            slices_dirty,
            ordinary_size,
            layout.ordinary_bitmap(),
            true,
        )
    }
    .ok_or(ManageArenaError::BitmapInitialization)?;
    unsafe {
        BitmapView::initialize(
            slices_purge,
            ordinary_size,
            layout.ordinary_bitmap(),
            true,
        )
    }
    .ok_or(ManageArenaError::BitmapInitialization)?;
    unsafe {
        BitmapView::initialize(pages, ordinary_size, layout.ordinary_bitmap(), true)
    }
    .ok_or(ManageArenaError::BitmapInitialization)?;
    for pointer in pages_abandoned {
        unsafe {
            BitmapView::initialize(pointer, ordinary_size, layout.ordinary_bitmap(), true)
        }
        .ok_or(ManageArenaError::BitmapInitialization)?;
    }

    let page_meta_slices = page_metadata_slice_count()
        .ok_or(ManageArenaError::MetadataDoesNotFit)?;
    let mut index = 0;
    while index < slice_count {
        let reserved = if index == 0 {
            layout.info_slices()
        } else {
            page_meta_slices
        };
        let start_index = index + reserved;
        let mut count = PAGE_META_ALIGNED_COUNT - reserved;
        if start_index < slice_count {
            if start_index + count > slice_count {
                count = slice_count - start_index;
            }
            unsafe { free.unsafe_set_range_local(start_index, count) }
                .ok_or(ManageArenaError::BitmapInitialization)?;
        }
        index += PAGE_META_ALIGNED_COUNT;
    }
    if memory.initially_committed() {
        unsafe { committed.unsafe_set_range_local(0, slice_count) }
            .ok_or(ManageArenaError::BitmapInitialization)?;
    }
    if !memory.initially_zero() {
        unsafe { dirty.unsafe_set_range_local(0, slice_count) }
            .ok_or(ManageArenaError::BitmapInitialization)?;
    }

    if unsafe { registry.insert(arena) } {
        Ok(arena)
    } else {
        Err(ManageArenaError::RegistryFull)
    }
}

/// Lifetime-bound inspection of an initialized in-place arena.
pub(crate) struct ArenaView<'arena> {
    arena: NonNull<Arena>,
    _arena: PhantomData<&'arena Arena>,
}

/// One initialized main-heap `pages_abandoned[bin]` bitmap of a live arena.
///
/// This bitmap-only view binds the image to its source arena and size-class
/// bin. The abandonment substrate uses it in source-state unit tests; a
/// production static-main owner must upgrade it to
/// [`MainArenaMappedAbandonedPage`] so its paired Heap count cannot be lost.
/// A dynamic Heap instead receives the separate purpose-bound
/// `DynamicArenaMappedAbandonedPage` capability for one exact mapped page.
pub(crate) struct ArenaAbandonedPages<'arena> {
    arena: NonNull<Arena>,
    bin: usize,
    bitmap: BitmapView<'arena>,
}

impl ArenaAbandonedPages<'_> {
    /// Returns the one source slice index only when this map owns the page's
    /// arena provenance. A multi-slice page has one abandonment-map bit at its
    /// first slice, exactly as `arena.c` does.
    #[inline]
    pub(crate) fn page_slice_index(&self, memory: MemoryId) -> Option<usize> {
        let memory = memory.arena_memory()?;
        if memory.arena != self.arena.as_ptr() {
            return None;
        }
        let index = memory.slice_index as usize;
        (index < self.bitmap.max_bits()).then_some(index)
    }

    #[inline]
    pub(crate) fn bitmap_is_clear(&self, slice_index: usize) -> bool {
        self.bitmap.is_clear_range(slice_index, 1) == Some(true)
    }

    /// Returns whether the static-main ordinary `pages` image still names
    /// this slice.
    ///
    /// This is the source assertion in `mi_page_arena_pages` that precedes
    /// every `pages_abandoned[bin]` access. The bit is not an alternate
    /// PageMap lookup: the caller still supplies the PageMap lifetime proof.
    /// It only rejects a stale abandoned bitmap entry after the owner has
    /// cleared the static-main ordinary page record. Rejected candidates must
    /// remain set so a concurrent source `unabandon` can observe reader
    /// quiescence instead of losing the only process-visible page owner.
    #[inline]
    fn main_page_is_set(&self, slice_index: usize) -> bool {
        if slice_index >= self.bitmap.max_bits() {
            return false;
        }
        // SAFETY: `ArenaAbandonedPages` borrows this same initialized arena
        // for its full lifetime. `ArenaView::pages` only attaches to the
        // immutable-size, in-place source bitmap and performs atomic reads.
        let Some(arena) = (unsafe { ArenaView::from_ptr(self.arena.as_ptr()) }) else {
            return false;
        };
        let Some(pages) = (unsafe { arena.pages() }) else {
            return false;
        };
        pages.is_set_range(slice_index, 1) == Some(true)
    }

    #[inline]
    pub(crate) const fn bin(&self) -> usize {
        self.bin
    }

    /// Publishes one available abandoned page after its abandoned-mapped
    /// identity has been installed. `true` is the source `was_clear` result;
    /// callers must treat `false` as a violated one-page publication invariant.
    #[inline]
    pub(crate) fn publish(&self, slice_index: usize) -> bool {
        matches!(
            self.bitmap.set_range(slice_index, 1),
            Some(transition) if transition.all_transitioned()
        )
    }

    /// Searches with the exact source abandoned-page bitmap claim protocol.
    #[inline]
    pub(crate) fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> Option<usize>
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        self.bitmap
            .try_find_and_claim_abandoned(thread_sequence, claim)
    }

    /// Removes one mapped abandoned page only after any failed concurrent
    /// reader restored its bit. This is `_mi_arenas_page_unabandon`'s required
    /// bitmap quiescence boundary.
    #[inline]
    pub(crate) fn clear_once_set(&self, slice_index: usize) -> bool {
        // SAFETY: this view retains the arena and its initialized subprocess
        // owner for the bitmap lifetime, as required when forming the arena.
        let Some(subprocess) = (unsafe { self.arena.as_ref().subprocess.as_ref() }) else {
            return false;
        };
        self.bitmap.clear_once_set(subprocess, slice_index) == Some(())
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn is_published(&self, slice_index: usize) -> bool {
        self.bitmap.is_set_range(slice_index, 1) == Some(true)
    }
}

/// One exact static-main Heap pairing for an in-place
/// `Arena::pages_main.pages_abandoned[bin]` bitmap.
///
/// `arena.c:_mi_arenas_page_abandon` increments the owning Heap's relaxed
/// `abandoned_count[bin]` immediately after it publishes this bitmap bit; its
/// claim and unabandon paths consume that same count after their paired bit or
/// identity transition. A bare [`ArenaAbandonedPages`] is intentionally only a
/// bitmap view. This capability is the production static-main owner that keeps
/// the bitmap and count inseparable.
pub(crate) struct MainArenaMappedAbandonedPage<'arena> {
    bitmap: ArenaAbandonedPages<'arena>,
    heap: NonNull<Heap>,
}

impl MappedAbandonedPages for MainArenaMappedAbandonedPage<'_> {
    #[inline]
    fn bin(&self) -> usize { self.bitmap.bin() }

    #[inline]
    fn page_slice_index(&self, memory: MemoryId) -> Option<usize> {
        self.bitmap.page_slice_index(memory)
    }

    #[inline]
    fn is_clear(&self, slice_index: usize) -> bool {
        self.bitmap.main_page_is_set(slice_index)
            && self.bitmap.bitmap_is_clear(slice_index)
    }

    #[inline]
    fn publish(&self, slice_index: usize) -> bool {
        // Source `mi_page_arena_pages` verifies that this main-Heap image
        // still owns the ordinary page bit before it publishes the matching
        // abandoned bit. Without that proof a delayed abandon could create a
        // reclaimable bitmap entry after PageMap/metadata release.
        if !self.bitmap.main_page_is_set(slice_index) {
            return false;
        }
        if !self.bitmap.publish(slice_index) {
            return false;
        }
        // SAFETY: construction verifies that this is the static main Heap
        // currently paired with the exact in-place arena-pages image.
        unsafe { self.heap.as_ref() }.increment_abandoned_count(self.bitmap.bin());
        true
    }

    #[inline]
    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        let mut claim = claim;
        let Some(slice_index) = self.bitmap.try_claim(thread_sequence, |slice_index| {
            if self.bitmap.main_page_is_set(slice_index) {
                claim(slice_index)
            } else {
                // This is the exact rejected-claim branch of
                // `mi_arena_try_claim_abandoned`: restore the source bit and
                // leave its paired count untouched. A caller may retain the
                // stale owner for failure handling, but may not fabricate an
                // adopted page from an ordinary-image mismatch.
                AbandonedBitmapClaim::KeepSet
            }
        }) else {
            return MappedAbandonedClaim::None;
        };
        // SAFETY: a successful claim consumes exactly one prior publication
        // through this same static Heap/bin pairing.
        if unsafe { self.heap.as_ref() }.decrement_abandoned_count(self.bitmap.bin()) {
            MappedAbandonedClaim::Claimed(slice_index)
        } else {
            MappedAbandonedClaim::CountDecrementFailed(slice_index)
        }
    }

    #[inline]
    fn clear_once_set(&self, slice_index: usize) -> bool {
        self.bitmap.clear_once_set(slice_index)
    }

    #[inline]
    fn decrement_after_identity_clear(&self) -> bool {
        // SAFETY: `unabandon_mapped` has already quiesced and cleared the
        // exact bitmap bit and identity paired to this source count.
        unsafe { self.heap.as_ref() }.decrement_abandoned_count(self.bitmap.bin())
    }
}

impl<'arena> ArenaView<'arena> {
    /// # Safety
    ///
    /// `arena` must remain live and registry-published for `'arena`. Any
    /// non-null subprocess must remain initialized and live for every view;
    /// operations requiring that binding reject a null subprocess.
    pub(crate) unsafe fn from_ptr(arena: *mut Arena) -> Option<Self> {
        Some(Self {
            arena: NonNull::new(arena)?,
            _arena: PhantomData,
        })
    }

    #[inline]
    pub(crate) fn arena(&self) -> &Arena {
        unsafe { self.arena.as_ref() }
    }

    #[inline]
    pub(crate) fn size(&self) -> Option<usize> {
        invariants::size_of_slices(self.arena().slice_count)
    }

    pub(crate) fn slice_start(&self, slice_index: usize) -> Option<*mut u8> {
        arena_slice_start(self.arena(), slice_index)
    }

    /// Claims one contiguous source span when this arena satisfies `requested`.
    ///
    /// This is the concrete external-arena half of `mi_arena_try_alloc_at`.
    /// `None` preserves the source's single failure result for unsuitability,
    /// exhaustion, malformed internal bitmap state, and commit-hook failure.
    /// On a failed commit the free claim is rolled back while the dirty bits
    /// deliberately remain set, exactly as in the pinned source.
    pub(crate) fn try_claim_suitable_slices(
        &self,
        requested: ArenaId,
        slice_count: usize,
        commit: bool,
        thread_sequence: usize,
    ) -> Option<ArenaSliceClaim<'arena>> {
        self.try_claim_slices_with_owner(requested, slice_count, commit, thread_sequence, None)
    }

    fn try_claim_slices_with_owner(
        &self,
        requested: ArenaId,
        slice_count: usize,
        commit: bool,
        thread_sequence: usize,
        owner: Option<&owned::OwnedArenaMapping>,
    ) -> Option<ArenaSliceClaim<'arena>> {
        let arena = self.arena();
        if slice_count == 0
            || slice_count > arena.slice_count
            || !unsafe { arena_is_suitable(self.arena.as_ptr(), requested) }
        {
            return None;
        }
        let free = unsafe { self.slices_free() }?;
        let committed = unsafe { self.slices_committed() }?;
        let dirty = unsafe { self.slices_dirty() }?;
        // The source claim has a nonzero slice count bounded by the arena
        // image, so form the byte span before changing `slices_free`. This
        // checked length lets the later Linux reuse boundary be infallible:
        // `_mi_os_reuse` cannot introduce a late allocation-failure edge
        // after `mi_bbitmap_try_find_and_clearN` succeeds.
        let size = invariants::size_of_slices(slice_count).and_then(NonZeroUsize::new)?;
        let slice_index = free.try_find_and_claim(thread_sequence, slice_count)?;
        let rollback = || free.set_range(slice_index, slice_count) == Some(true);

        let Some(start) = self.slice_start(slice_index).and_then(NonNull::new) else {
            let _ = rollback();
            return None;
        };
        let Some(mut memory) = (unsafe {
            MemoryId::from_arena(self.arena.as_ptr(), slice_index, slice_count)
        }) else {
            let _ = rollback();
            return None;
        };
        memory.is_pinned = arena.memid.is_pinned();

        // `mi_bitmap_setN` returns whether every selected dirty bit was
        // previously clear. The result is the source's zero observation for
        // a range whose backing external memory was initially zero.
        let mut touched_slices = 0;
        if arena.memid.initially_zero() {
            let Some(dirty_transition) = dirty.set_range(slice_index, slice_count) else {
                let _ = rollback();
                return None;
            };
            memory.initially_zero = dirty_transition.all_transitioned();
            touched_slices = slice_count - dirty_transition.already_set();
        }

        if commit {
            let Some(already_committed) = committed.popcount_range(slice_index, slice_count)
            else {
                let _ = rollback();
                return None;
            };
            if already_committed < slice_count {
                let mut commit_zero = false;
                let committed_now = if let Some(owner) = owner {
                    owner.commit(start.as_ptr(), size.get(), already_committed * ARENA_SLICE_SIZE)
                } else if let Some(commit_function) = arena.commit_function {
                    unsafe {
                        commit_function(true, start.as_ptr(), size.get(), &mut commit_zero,
                            arena.commit_function_argument)
                    }
                } else {
                    false
                };
                if !committed_now {
                    // `mi_arena_try_alloc_at` returns only ownership here;
                    // the dirty observation remains deliberately sticky.
                    let _ = rollback();
                    return None;
                }
                if commit_zero {
                    memory.initially_zero = true;
                }
                if committed.set_range(slice_index, slice_count).is_none() {
                    let _ = rollback();
                    return None;
                }
            } else {
                // Pinned `src/arena.c:296-307` calls `_mi_os_reuse` only
                // after the binned free claim succeeded and the ordinary
                // bitmap reports this exact span fully committed. The Linux
                // primitive is a contained-range no-op; retain its caller
                // ordering before publishing `initially_committed` without
                // transferring the external mapping owner or adding an
                // allocation-failure path.
                match os::reuse_arena_range(start, size) {
                    crate::os::ReuseOutcome::NoOp => {}
                }
                if let Some(owner) = owner {
                    if owner.config.has_overcommit() && touched_slices > 0 && !arena.memid.is_pinned() {
                        owner.process.subprocess().vm_statistics()
                            .committed_increase(touched_slices * ARENA_SLICE_SIZE);
                    }
                }
            }
            memory.initially_committed = true;
        } else {
            let Some(is_committed) = committed.is_set_range(slice_index, slice_count) else {
                let _ = rollback();
                return None;
            };
            memory.initially_committed = is_committed;
            if !is_committed {
                // Source accounting treats a mixed commitment observation as
                // uncommitted: it first observes all bits set, then clears the
                // exact span. The source's set transition, not a separate
                // popcount, supplies the already-committed statistics input.
                let Some(transition) = committed.set_range(slice_index, slice_count) else {
                    let _ = rollback();
                    return None;
                };
                if committed.clear_range(slice_index, slice_count).is_none() {
                    let _ = rollback();
                    return None;
                }
                if let Some(owner) = owner {
                    owner.process.subprocess().vm_statistics()
                        .committed_decrease(transition.already_set() * ARENA_SLICE_SIZE);
                }
            }
        }

        Some(ArenaSliceClaim {
            arena: self.arena,
            start,
            memory,
            backing: None,
            _arena: PhantomData,
        })
    }

    /// Reserves the one source slice used by the requested-parent-arena arm
    /// of `_mi_theap_alloc`.
    ///
    /// This models a caller-selected direct parent as the source
    /// `heap->exclusive_arena` value; it neither binds nor inspects a
    /// [`Heap`]. No registry search, child-arena selection, metadata
    /// allocation, or OS fallback is admitted here. This is only the first
    /// requested-parent pass: pinned
    /// `mi_forall_arenas` visits a non-null requested parent once, and
    /// `mi_arena_is_suitable` accepts that exact parent before consulting
    /// `is_exclusive`. A source TLD with a nonnegative NUMA node makes a
    /// separate second requested-parent pass; this reservation has no NUMA
    /// input and deliberately does not model it. Therefore this accepts either
    /// value of `Arena::is_exclusive`, but rejects a subarena and a foreign
    /// subprocess before any bitmap mutation.
    ///
    /// The returned reservation carries only the one-slice arena claim and
    /// `MemoryId`; source Theap construction, `theap->memid` storage,
    /// `_mi_theap_init`, and every publication/lifecycle step remain a later
    /// consuming owner.
    #[inline]
    pub(crate) fn try_reserve_exclusive_theap<'subprocess>(
        &self,
        subprocess: &'subprocess MainSubprocess,
        thread_sequence: ThreadSequence,
    ) -> Option<ExclusiveArenaTheapReservation<'arena, 'subprocess>> {
        let arena = self.arena();
        if !arena.parent.is_null() || !core::ptr::eq(arena.subprocess, subprocess.as_ptr()) {
            return None;
        }
        // SAFETY: `ArenaView` proves this exact candidate is live and
        // registry-published. The preceding parent test makes its source ID
        // the requested parent form rather than a subarena identity.
        let requested = unsafe { ArenaId::from_arena(self.arena.as_ptr()) }?;
        let claim = self.try_claim_suitable_slices(
            requested,
            ARENA_MIN_OBJ_SLICES,
            true,
            thread_sequence.get(),
        )?;
        Some(ExclusiveArenaTheapReservation { claim, subprocess })
    }

    /// # Safety
    ///
    /// No independent non-atomic view may alias the free bitmap.
    pub(crate) unsafe fn slices_free(&self) -> Option<BinnedBitmapView<'arena>> {
        let layout = BinnedBitmapLayout::for_bit_count(self.arena().slice_count)?;
        unsafe { BinnedBitmapView::attach(self.arena().slices_free, layout.byte_size(), layout) }
    }

    /// # Safety
    ///
    /// No independent non-atomic view may alias the selected ordinary bitmap.
    unsafe fn ordinary_bitmap(&self, pointer: *mut u8) -> Option<BitmapView<'arena>> {
        let layout = BitmapLayout::for_bit_count(self.arena().slice_count)?;
        unsafe { BitmapView::attach(pointer, layout.byte_size(), layout) }
    }

    pub(crate) unsafe fn slices_committed(&self) -> Option<BitmapView<'arena>> {
        unsafe { self.ordinary_bitmap(self.arena().slices_committed) }
    }

    pub(crate) unsafe fn slices_dirty(&self) -> Option<BitmapView<'arena>> {
        unsafe { self.ordinary_bitmap(self.arena().slices_dirty) }
    }

    pub(crate) unsafe fn slices_purge(&self) -> Option<BitmapView<'arena>> {
        unsafe { self.ordinary_bitmap(self.arena().slices_purge) }
    }

    /// Forces or observes the default delayed arena decommit schedule.
    ///
    /// This is the one-arena, one-thread subset of `_mi_arenas_collect`: a
    /// forced collection ignores the 4-second expiry, while non-forced
    /// collection leaves not-yet-expired work alone. Each scheduled run first
    /// removes its `slices_purge` bits, then temporarily claims `slices_free`;
    /// this preserves the source rule that allocation cannot reuse bytes while
    /// the purge owns them. A direct decommit error restores free availability,
    /// records the same purge bits, and makes retry immediately eligible.
    pub(crate) fn collect_scheduled_purge(&self, page_size: PageSize, force: bool) -> bool {
        let arena = self.arena();
        if arena.memid.is_pinned() {
            return true;
        }
        let expire = i64_load_relaxed(&arena.purge_expire);
        if expire == 0 {
            return true;
        }
        if !force {
            let Ok(now) = os::monotonic_milliseconds() else {
                return false;
            };
            if expire > now {
                return true;
            }
        }

        // Source clears the arena expiry before atomically visiting scheduled
        // ranges, so a concurrent later release belongs to the next pass.
        // This bounded lifecycle has one thread but preserves that state edge.
        i64_store_release(&arena.purge_expire, 0);
        let Some(purge) = (unsafe { self.slices_purge() }) else {
            return false;
        };
        // `_mi_bitmap_forall_setc_rangesn(..., 1, ...)` dispatches to the
        // generic source visitor: snapshot the conservative map, atomically
        // exchange a data field, then offer its field-bounded ranges. If this
        // Rust callback exposes a retryable error, returning false makes the
        // visitor restore only its not-yet-visited snapshot suffix; the
        // current range's owner has already rescheduled its own failed work.
        purge.visit_set_ranges_clear(|slice_index, slice_count| {
            self.purge_scheduled_range(page_size, slice_index, slice_count)
        })
    }

    /// Attempts the source full-range purge claim, then retries individual
    /// slices when one allocation prevents the contiguous claim.
    fn purge_scheduled_range(
        &self,
        page_size: PageSize,
        slice_index: usize,
        slice_count: usize,
    ) -> bool {
        let Some(free) = (unsafe { self.slices_free() }) else {
            return false;
        };
        match free.try_clear_within_chunk(slice_index, slice_count) {
            Some(true) => self.purge_owned_range(page_size, slice_index, slice_count),
            Some(false) => {
                for offset in 0..slice_count {
                    if !self.purge_scheduled_slice(page_size, slice_index + offset) {
                        // The source visitor would continue after a failed
                        // individual claim. Our explicit OS error instead
                        // ends this collection so its retry result stays
                        // observable; restore the as-yet-unvisited scheduled
                        // suffix rather than silently losing that work.
                        let remaining_start = slice_index + offset + 1;
                        let remaining_count = slice_count - offset - 1;
                        if remaining_count != 0 {
                            let rescheduled = unsafe { self.slices_purge() }
                                .and_then(|purge| {
                                    purge.set_range(remaining_start, remaining_count)
                                })
                                .is_some();
                            if rescheduled {
                                i64_store_release(&self.arena().purge_expire, 1);
                            }
                        }
                        return false;
                    }
                }
                true
            }
            None => false,
        }
    }

    /// Processes one scheduled slice after a full-range free-bitmap claim did
    /// not succeed. A false free claim means allocation won the race and the
    /// source-cleared purge bit must stay clear; a successful claim has the
    /// normal retryable decommit ownership transition.
    fn purge_scheduled_slice(&self, page_size: PageSize, slice_index: usize) -> bool {
        let Some(free) = (unsafe { self.slices_free() }) else {
            return false;
        };
        match free.try_clear_within_chunk(slice_index, 1) {
            Some(true) => self.purge_owned_range(page_size, slice_index, 1),
            Some(false) => true,
            None => false,
        }
    }

    /// Purges an arena range already removed from `slices_free`, then restores
    /// availability. This retains the distinct external backing ownership: it
    /// invokes only the non-owning source decommit primitive and never unmaps.
    fn purge_owned_range(
        &self,
        page_size: PageSize,
        slice_index: usize,
        slice_count: usize,
    ) -> bool {
        let arena = self.arena();
        let Some(size) = invariants::size_of_slices(slice_count) else {
            return self.restore_failed_purge(slice_index, slice_count);
        };
        let Some(start) = self.slice_start(slice_index) else {
            return self.restore_failed_purge(slice_index, slice_count);
        };
        let Some(committed) = (unsafe { self.slices_committed() }) else {
            return self.restore_failed_purge(slice_index, slice_count);
        };
        let Some(committed_transition) = committed.set_range(slice_index, slice_count) else {
            return self.restore_failed_purge(slice_index, slice_count);
        };
        let all_committed = committed_transition.already_set() == slice_count;
        let needs_recommit = match arena.commit_function {
            Some(commit) => {
                // SAFETY: external arena initialization recorded this hook and
                // argument for the exact live backing span. `slices_free` is
                // clear for this range, giving the hook exclusive ownership.
                unsafe {
                    commit(
                        false,
                        start,
                        size,
                        core::ptr::null_mut(),
                        arena.commit_function_argument,
                    )
                }
            }
            None => match unsafe { os::decommit_arena_range(page_size, start, size) } {
                Ok(Some(DecommitOutcome::DoesNotNeedRecommit)) | Ok(None) => false,
                // In the frozen Linux release profile, `_mi_prim_decommit`
                // sets `needs_recommit = false` after its MADV_DONTNEED
                // attempt even when that advisory reports an error. The
                // source reports the error but consumes this purge work, with
                // the live mapping still accessible and committed.
                Err(_) => false,
            },
        };
        if (needs_recommit || !all_committed)
            && committed.clear_range(slice_index, slice_count) != Some(true)
        {
            return self.restore_failed_purge(slice_index, slice_count);
        }
        let Some(free) = (unsafe { self.slices_free() }) else {
            return self.restore_failed_purge(slice_index, slice_count);
        };
        free.set_range(slice_index, slice_count) == Some(true)
    }

    /// Restores allocator availability after an injected/default decommit
    /// failure and records the exact span for a later forced collection. The
    /// retry expiry is deliberately immediate: the error itself already made
    /// the current collection observable as failed, so delaying an explicit
    /// retry would invent policy absent from the source error path.
    fn restore_failed_purge(&self, slice_index: usize, slice_count: usize) -> bool {
        let arena = self.arena();
        let restored = unsafe { self.slices_free() }
            .and_then(|free| free.set_range(slice_index, slice_count))
            == Some(true);
        let rescheduled = unsafe { self.slices_purge() }
            .and_then(|purge| purge.set_range(slice_index, slice_count))
            .is_some();
        if restored && rescheduled {
            i64_store_release(&arena.purge_expire, 1);
        }
        false
    }

    pub(crate) unsafe fn pages(&self) -> Option<BitmapView<'arena>> {
        unsafe { self.ordinary_bitmap(self.arena().pages_main.pages) }
    }

    /// Attaches to one initialized main-heap abandoned-page bitmap.
    ///
    /// Dynamic heap-local `ArenaPages` images are intentionally not created
    /// here. The returned capability is valid only while this `ArenaView`
    /// keeps the in-place arena metadata live.
    pub(crate) fn abandoned_pages(&self, bin: usize) -> Option<ArenaAbandonedPages<'arena>> {
        if bin >= ARENA_BIN_COUNT {
            return None;
        }
        let bitmap = unsafe { self.ordinary_bitmap(self.arena().pages_main.pages_abandoned[bin]) }?;
        Some(ArenaAbandonedPages {
            arena: self.arena,
            bin,
            bitmap,
        })
    }

    /// Returns the sole production capability for a static-main mapped
    /// abandoned page. It proves the main Heap still points at this arena's
    /// embedded `pages_main` image before allowing a bitmap publication to
    /// mutate its paired `abandoned_count` entry.
    #[inline]
    pub(crate) fn main_heap_abandoned_page(
        &self,
        heap: NonNull<Heap>,
        bin: usize,
    ) -> Option<MainArenaMappedAbandonedPage<'arena>> {
        // SAFETY: the caller retains the static main Heap through its page
        // session. This constructor only observes immutable identity and its
        // atomic arena-pages slot before binding the counter capability.
        let heap_ref = unsafe { heap.as_ref() };
        let pages = NonNull::from(&self.arena().pages_main);
        if !heap_ref.is_main_static()
            || heap_ref.arena_pages_at(self.arena().arena_index) != Some(pages)
        {
            return None;
        }
        Some(MainArenaMappedAbandonedPage {
            bitmap: self.abandoned_pages(bin)?,
            heap,
        })
    }
}

const _: [(); 8] = [(); align_of::<Arena>()];
const _: [(); 648] = [(); size_of::<Arena>()];
const _: [(); ARENA_MAX_SIZE] = [(); BITMAP_MAX_BIT_COUNT * ARENA_SLICE_SIZE];

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::main_theap::{
        MainStaticAttachmentStorage, MainStaticTheapAttachment, MainStaticTheapError,
        RequestedParentArenaTheapBeginFailure, RequestedParentArenaTheapError,
    };
    use core::pin::Pin;
    use std::alloc::{alloc_zeroed, dealloc, Layout};
    use std::boxed::Box;

    struct AlignedRegion {
        pointer: NonNull<u8>,
        layout: Layout,
    }

    impl AlignedRegion {
        fn zeroed(size: usize) -> Self {
            let layout = Layout::from_size_align(size, ARENA_ALIGNMENT).unwrap();
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            Self { pointer, layout }
        }

        fn as_ptr(&mut self) -> *mut u8 {
            self.pointer.as_ptr()
        }
    }

    impl Drop for AlignedRegion {
        fn drop(&mut self) {
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    struct CommitScript {
        calls: std::sync::atomic::AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
        allocation_is_zero: bool,
    }

    impl CommitScript {
        fn new(allocation_is_zero: bool) -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                fail: std::sync::atomic::AtomicBool::new(false),
                allocation_is_zero,
            }
        }
    }

    unsafe extern "C" fn scripted_commit(
        commit: bool,
        _start: *mut u8,
        _size: usize,
        is_zero: *mut bool,
        user_argument: *mut c_void,
    ) -> bool {
        let script = unsafe { &*user_argument.cast::<CommitScript>() };
        script
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !commit || script.fail.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        if !is_zero.is_null() {
            unsafe { is_zero.write(script.allocation_is_zero) };
        }
        true
    }

    /// Records the source callback's decommit request. Returning true from
    /// the `commit = false` arm is the pinned `_mi_os_purge_ex` contract for
    /// an external callback which says that its range needs recommit before a
    /// future committed claim.
    struct RecommitPurgeScript {
        false_calls: std::sync::atomic::AtomicUsize,
        false_start: std::sync::atomic::AtomicUsize,
        false_size: std::sync::atomic::AtomicUsize,
    }

    impl RecommitPurgeScript {
        fn new() -> Self {
            Self {
                false_calls: std::sync::atomic::AtomicUsize::new(0),
                false_start: std::sync::atomic::AtomicUsize::new(0),
                false_size: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    unsafe extern "C" fn recommit_after_purge(
        commit: bool,
        start: *mut u8,
        size: usize,
        _is_zero: *mut bool,
        user_argument: *mut c_void,
    ) -> bool {
        let script = unsafe { &*user_argument.cast::<RecommitPurgeScript>() };
        if !commit {
            script
                .false_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            script
                .false_start
                .store(start.addr(), std::sync::atomic::Ordering::Relaxed);
            script
                .false_size
                .store(size, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        true
    }

    #[test]
    fn metadata_sizing_reserves_exact_source_slices_and_bitmap_headers() {
        assert_eq!(size_of::<Page>(), 128);
        assert_eq!(page_metadata_slice_count(), Some(8));

        let pages = ArenaPagesLayout::for_slice_count(BCHUNK_BITS).unwrap();
        assert_eq!(pages.slice_count(), BCHUNK_BITS);
        assert_eq!(pages.bitmap_base(), 512);
        assert_eq!(pages.bitmap_layout().byte_size(), 192);
        assert_eq!(pages.byte_size(), 12_416);

        let info = ArenaInfoLayout::for_slice_count(BCHUNK_BITS, 4096).unwrap();
        assert_eq!(info.arena_offset(), 8 * ARENA_SLICE_SIZE);
        assert_eq!(info.bitmap_base(), 524_992);
        assert_eq!(info.free_bitmap().byte_size(), 512);
        assert_eq!(info.ordinary_bitmap().byte_size(), 192);
        assert_eq!(info.bitmaps_end(), 537_984);
        assert_eq!(info.info_slices(), 9);
        assert_eq!(info.info_size(), 9 * ARENA_SLICE_SIZE);
    }

    #[test]
    fn dynamic_arena_pages_layout_names_every_source_bitmap_at_its_exact_offset() {
        let layout = ArenaPagesLayout::for_slice_count(BCHUNK_BITS).unwrap();
        let bitmap_size = layout.bitmap_layout().byte_size();

        assert_eq!(layout.bitmap_offset(0), Some(layout.bitmap_base()));
        assert_eq!(
            layout.bitmap_offset(ARENA_BIN_COUNT),
            Some(layout.bitmap_base() + ARENA_BIN_COUNT * bitmap_size)
        );
        assert_eq!(layout.bitmap_offset(ARENA_BIN_COUNT + 1), None);
        assert_eq!(
            layout.byte_size(),
            layout.bitmap_base() + (1 + ARENA_BIN_COUNT) * bitmap_size
        );
    }

    #[test]
    fn external_alignment_and_minimum_size_follow_manage_os_memory_checks() {
        let aligned = ARENA_ALIGNMENT;
        let minimum = ExternalArenaPlan::from_address(aligned, ARENA_MIN_SIZE).unwrap();
        assert_eq!(minimum.prefix_bytes(), 0);
        assert_eq!(minimum.total_size(), ARENA_MIN_SIZE);
        assert_eq!(minimum.total_slice_count(), BCHUNK_BITS);

        assert!(ExternalArenaPlan::from_address(aligned, ARENA_MIN_SIZE - 1).is_none());
        assert!(ExternalArenaPlan::from_address(aligned - 1, ARENA_MIN_SIZE + 1).is_none());

        let realigned = ExternalArenaPlan::from_address(
            aligned - 1,
            ARENA_ALIGNMENT + ARENA_MIN_SIZE,
        )
        .unwrap();
        assert_eq!(realigned.prefix_bytes(), 1);
        assert_eq!(realigned.aligned_address(), aligned);
        assert!(realigned.total_size() >= ARENA_ALIGNMENT);
    }

    #[test]
    fn regions_over_sixteen_gib_split_into_one_owner_and_subarenas() {
        let size = ARENA_MAX_SIZE + ARENA_MIN_SIZE;
        let plan = ExternalArenaPlan::from_address(ARENA_ALIGNMENT, size).unwrap();
        assert_eq!(plan.arena_count(), 2);
        let owner = plan.split(0).unwrap();
        assert_eq!(owner.address(), ARENA_ALIGNMENT);
        assert_eq!(owner.slice_count(), BITMAP_MAX_BIT_COUNT);
        assert_eq!(owner.total_size(), size);
        assert_eq!(owner.parent_index(), None);
        let child = plan.split(1).unwrap();
        assert_eq!(child.address(), ARENA_ALIGNMENT + ARENA_MAX_SIZE);
        assert_eq!(child.slice_count(), BCHUNK_BITS);
        assert_eq!(child.total_size(), 0);
        assert_eq!(child.parent_index(), Some(0));
    }

    #[test]
    fn in_place_initialization_marks_only_usable_slices_free_and_preserves_flags() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                false,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        assert!(managed.is_complete());
        assert_eq!(managed.total_size(), ARENA_MIN_SIZE);
        assert_eq!(managed.managed_size(), ARENA_MIN_SIZE);
        assert_eq!(registry.count(), 1);

        let arena = unsafe { registry.arena_at(0) }.unwrap();
        assert_eq!(arena.memid.kind(), crate::types::MemoryKind::External);
        assert_eq!(arena.info_slices, 9);
        assert_eq!(arena.total_size, ARENA_MIN_SIZE);
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        assert_eq!(view.size(), Some(ARENA_MIN_SIZE));
        assert_eq!(view.slice_start(0), Some(arena.start));
        assert!(view.slice_start(BCHUNK_BITS).is_none());

        let free = unsafe { view.slices_free() }.unwrap();
        assert_eq!(free.is_clear_range(0, arena.info_slices), Some(true));
        assert_eq!(
            free.is_set_range(arena.info_slices, BCHUNK_BITS - arena.info_slices),
            Some(true),
        );
        let committed = unsafe { view.slices_committed() }.unwrap();
        assert_eq!(committed.is_set_range(0, BCHUNK_BITS), Some(true));
        let dirty = unsafe { view.slices_dirty() }.unwrap();
        assert_eq!(dirty.is_set_range(0, BCHUNK_BITS), Some(true));
        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(purge.is_clear_range(0, BCHUNK_BITS), Some(true));
        let pages = unsafe { view.pages() }.unwrap();
        assert_eq!(pages.is_clear_range(0, BCHUNK_BITS), Some(true));
    }

    #[test]
    fn arena_memory_ids_and_exclusive_suitability_preserve_parent_relations() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                2,
                true,
                None,
            )
        }
        .unwrap();
        let arena = managed.arena_id().as_ptr();
        let memory = unsafe { MemoryId::from_arena(arena, 9, 1) }.unwrap();
        assert!(unsafe { memory_is_suitable(memory, managed.arena_id()) });
        assert!(!unsafe { memory_is_suitable(MemoryId::none(), managed.arena_id()) });
        assert!(unsafe { memory_is_suitable(MemoryId::none(), ArenaId::none()) });
        assert_eq!(memory.arena_memory().unwrap().slice_index, 9);

        let view = unsafe { ArenaView::from_ptr(arena) }.unwrap();
        assert!(view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .is_none());
        let requested = view
            .try_claim_suitable_slices(managed.arena_id(), 1, true, 0)
            .unwrap();
        assert!(requested.release());
    }

    #[test]
    fn exclusive_arena_theap_reservation_uses_only_its_requested_parent_slice() {
        let selected = MainSubprocess::test_static_owner();
        let foreign = MainSubprocess::test_static_owner();
        let sequence = ThreadSequence::from_previous_total_count(11);
        let registry = ArenaRegistry::new(null_mut());
        assert!(unsafe { registry.bind_subprocess_before_publication(selected.as_ptr()) });

        let mut selected_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let selected_managed = unsafe {
            manage_external_in_place(
                &registry,
                selected_region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                3,
                false,
                None,
            )
        }
        .unwrap();
        let mut other_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let other_managed = unsafe {
            manage_external_in_place(
                &registry,
                other_region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();

        let selected_view = unsafe { ArenaView::from_ptr(selected_managed.arena_id().as_ptr()) }
            .expect("the selected parent arena is published");
        let other_view = unsafe { ArenaView::from_ptr(other_managed.arena_id().as_ptr()) }
            .expect("the unrelated parent arena is published");
        assert!(
            !selected_view.arena().is_exclusive,
            "a heap's requested parent does not require arena::is_exclusive"
        );
        let first = selected_view.arena().info_slices;
        let usable = BCHUNK_BITS - first;
        let other_first = other_view.arena().info_slices;
        let other_usable = BCHUNK_BITS - other_first;
        let selected_free = unsafe { selected_view.slices_free() }.unwrap();
        let selected_purge = unsafe { selected_view.slices_purge() }.unwrap();
        let other_free = unsafe { other_view.slices_free() }.unwrap();
        assert_eq!(selected_free.is_set_range(first, usable), Some(true));
        assert_eq!(selected_purge.is_clear_range(first, usable), Some(true));
        assert_eq!(other_free.is_set_range(other_first, other_usable), Some(true));

        assert!(
            selected_view
                .try_reserve_exclusive_theap(foreign, sequence)
                .is_none(),
            "a foreign subprocess must fail before the source free bitmap changes"
        );
        assert_eq!(other_free.is_set_range(other_first, other_usable), Some(true));
        assert_eq!(selected_free.is_set_range(first, usable), Some(true));
        assert_eq!(selected_purge.is_clear_range(first, usable), Some(true));
        assert_eq!(
            selected_view
                .arena()
                .purge_expire
                .load(core::sync::atomic::Ordering::Acquire),
            0,
        );

        let reservation = selected_view
            .try_reserve_exclusive_theap(selected, sequence)
            .expect("the selected requested parent supplies one Theap reservation");
        assert_eq!(reservation.slice_index(), first);
        assert_eq!(reservation.slice_count(), ARENA_MIN_OBJ_SLICES);
        let memory = reservation.memory_id();
        assert_eq!(memory.kind(), crate::types::MemoryKind::Arena);
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        assert!(!memory.is_pinned());
        let arena_memory = memory.arena_memory().expect("reservation preserves arena provenance");
        assert_eq!(arena_memory.arena, selected_managed.arena_id().as_ptr());
        assert_eq!(arena_memory.slice_index as usize, first);
        assert_eq!(arena_memory.slice_count as usize, ARENA_MIN_OBJ_SLICES);
        assert_eq!(selected_free.is_clear_range(first, ARENA_MIN_OBJ_SLICES), Some(true));
        assert_eq!(selected_purge.is_clear_range(first, ARENA_MIN_OBJ_SLICES), Some(true));
        assert_eq!(
            selected_view
                .arena()
                .purge_expire
                .load(core::sync::atomic::Ordering::Acquire),
            0,
        );
        assert_eq!(other_free.is_set_range(other_first, other_usable), Some(true));

        let released = match reservation.release() {
            Ok(released) => released,
            Err(_) => panic!("the reservation retains the selected subprocess identity"),
        };
        assert!(released);
        assert_eq!(selected_free.is_set_range(first, ARENA_MIN_OBJ_SLICES), Some(true));
        assert_eq!(selected_purge.is_set_range(first, ARENA_MIN_OBJ_SLICES), Some(true));
        assert!(
            selected_view
                .arena()
                .purge_expire
                .load(core::sync::atomic::Ordering::Acquire)
                > 0
        );

        let retry = selected_view
            .try_reserve_exclusive_theap(selected, sequence)
            .expect("the same requested parent slice becomes available again");
        assert_eq!(retry.slice_index(), first);
        assert!(
            !retry.memory_id().initially_zero(),
            "the exact released slice retains its source dirty-bit observation"
        );
        assert!(matches!(retry.release(), Ok(true)));

        let blocker = selected_view
            .try_claim_suitable_slices(selected_managed.arena_id(), usable, true, sequence.get())
            .expect("the selected parent has one complete usable span");
        assert!(
            selected_view
                .try_reserve_exclusive_theap(selected, sequence)
                .is_none(),
            "a requested-parent failure must not search the unrelated arena or fall back to OS memory"
        );
        assert_eq!(other_free.is_set_range(other_first, other_usable), Some(true));
        assert!(
            matches!(blocker.release_for_subprocess(selected), Ok(true)),
            "the selected source identity returns the exhausted parent span"
        );
    }

    #[test]
    fn requested_parent_arena_theap_prefix_lifecycle() {
        std::thread::spawn(|| {
            let selected = MainSubprocess::test_static_owner();
            let foreign = MainSubprocess::test_static_owner();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, selected)
            }
            .expect("the live default Theap supplies the source caller TLD");
            let thread_sequence = main
                .tld()
                .expect("the default TLD remains current")
                .thread_sequence();
            assert_eq!(thread_sequence.get(), 0);

            let registry = ArenaRegistry::new(null_mut());
            assert!(unsafe { registry.bind_subprocess_before_publication(selected.as_ptr()) });
            let mut selected_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
            let selected_managed = unsafe {
                manage_external_in_place(
                    &registry,
                    selected_region.as_ptr(),
                    ARENA_MIN_SIZE,
                    PageSize::new(4096).unwrap(),
                    true,
                    false,
                    true,
                    3,
                    false,
                    None,
                )
            }
            .expect("the selected parent arena is initialized");
            let mut other_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
            let other_managed = unsafe {
                manage_external_in_place(
                    &registry,
                    other_region.as_ptr(),
                    ARENA_MIN_SIZE,
                    PageSize::new(4096).unwrap(),
                    true,
                    false,
                    true,
                    -1,
                    false,
                    None,
                )
            }
            .expect("the unrelated parent arena is initialized");
            let selected_view = unsafe { ArenaView::from_ptr(selected_managed.arena_id().as_ptr()) }
                .expect("the selected parent remains published");
            let other_view = unsafe { ArenaView::from_ptr(other_managed.arena_id().as_ptr()) }
                .expect("the unrelated parent remains published");
            let first_slice = selected_view.arena().info_slices;
            let other_first_slice = other_view.arena().info_slices;
            let selected_free = unsafe { selected_view.slices_free() }.unwrap();
            let other_free = unsafe { other_view.slices_free() }.unwrap();
            let expected_start = selected_view
                .slice_start(first_slice)
                .expect("the first usable selected slice has an address");

            let mut heap = Box::pin(Heap::bootstrap_empty());
            // SAFETY: this fixture owns the one fresh pinned Heap for the
            // exact duration of the exclusive requested-parent attachment.
            assert!(unsafe {
                Pin::get_unchecked_mut(heap.as_mut())
                    .initialize_dynamic_binding_for_requested_arena(
                        selected,
                        2,
                        selected_managed.arena_id().as_ptr(),
                    )
            });
            assert_eq!(selected_free.is_set_range(first_slice, 1), Some(true));
            assert_eq!(
                other_free.is_set_range(
                    other_first_slice,
                    BCHUNK_BITS - other_first_slice,
                ),
                Some(true),
            );
            assert!(
                selected_view
                    .try_reserve_exclusive_theap(foreign, thread_sequence)
                    .is_none(),
                "a foreign subprocess cannot consume the selected parent before prefix construction"
            );
            assert_eq!(
                selected_free.is_set_range(first_slice, 1),
                Some(true),
                "foreign refusal leaves the selected parent bitmap untouched"
            );

            let reservation = selected_view
                .try_reserve_exclusive_theap(selected, thread_sequence)
                .expect("only the requested parent supplies the Theap slice");
            let mut owner = match main.attach_requested_parent_arena_theap(heap.as_mut(), reservation) {
                Ok(owner) => owner,
                Err(_) => panic!("the prepared source-shaped prefix attachment succeeds"),
            };

            assert!(owner.is_attached());
            assert_eq!(
                owner.test_theap_prefix_address(),
                expected_start.addr(),
                "the Rust prefix occupies the selected arena slice itself"
            );
            let memory = owner.memory_id().expect("the live prefix retains a memory ID");
            assert_eq!(memory.kind(), crate::types::MemoryKind::Arena);
            assert!(
                memory.initially_zero(),
                "the first selected slice preserves the external arena's fresh-zero observation"
            );
            let arena_memory = memory
                .arena_memory()
                .expect("the live prefix retains exact arena provenance");
            assert_eq!(arena_memory.arena, selected_managed.arena_id().as_ptr());
            assert_eq!(arena_memory.slice_index as usize, first_slice);
            assert_eq!(arena_memory.slice_count as usize, ARENA_MIN_OBJ_SLICES);
            assert_eq!(selected_free.is_clear_range(first_slice, 1), Some(true));
            assert_eq!(
                other_free.is_set_range(
                    other_first_slice,
                    BCHUNK_BITS - other_first_slice,
                ),
                Some(true),
                "the attached requested-parent Theap never searches another arena"
            );

            owner
                .teardown()
                .expect("the page-free prefix detaches before returning its exact slice");
            assert!(owner.is_torn_down());
            assert_eq!(
                selected.live_thread_count(),
                1,
                "the auxiliary prefix leaves the source default TLD live"
            );
            assert_eq!(selected_free.is_set_range(first_slice, 1), Some(true));
            assert_eq!(
                other_free.is_set_range(
                    other_first_slice,
                    BCHUNK_BITS - other_first_slice,
                ),
                Some(true),
            );

            drop(owner);
            let mut rejected_heap = Box::pin(Heap::bootstrap_empty());
            let rejected_reservation = selected_view
                .try_reserve_exclusive_theap(selected, thread_sequence)
                .expect("the selected parent provides the unchanged pre-materialization claim");
            let rejected_slice = rejected_reservation.slice_index();
            assert_eq!(selected_free.is_clear_range(rejected_slice, 1), Some(true));
            let rejected_reservation = match main.attach_requested_parent_arena_theap(
                rejected_heap.as_mut(),
                rejected_reservation,
            ) {
                Err(RequestedParentArenaTheapBeginFailure::Rejected { error, reservation }) => {
                    assert_eq!(error, RequestedParentArenaTheapError::HeapBinding);
                    reservation
                }
                Err(RequestedParentArenaTheapBeginFailure::Retained { .. }) => {
                    panic!("an invalid caller Heap rejects before prefix materialization")
                }
                Ok(_) => panic!("an unbound caller Heap cannot attach the Arena prefix"),
            };
            assert_eq!(rejected_reservation.slice_index(), rejected_slice);
            let rejected_memory = rejected_reservation.memory_id();
            assert_eq!(rejected_memory.kind(), crate::types::MemoryKind::Arena);
            assert_eq!(
                rejected_memory
                    .arena_memory()
                    .expect("the unchanged rejection retains Arena provenance")
                    .arena,
                selected_managed.arena_id().as_ptr()
            );
            let rejected_released = match rejected_reservation.release() {
                Ok(released) => released,
                Err(_) => panic!("the unchanged rejection claim keeps its selected release capability"),
            };
            assert!(rejected_released);
            assert_eq!(selected_free.is_set_range(first_slice, 1), Some(true));

            // SAFETY: the first owner detached its only list member, returned
            // the selected slice, and retired this caller-pinned Heap image.
            // The fixture now establishes a fresh source `mi_heap_init`
            // input against the same live selected parent.
            assert!(unsafe {
                Pin::get_unchecked_mut(heap.as_mut())
                    .initialize_dynamic_binding_for_requested_arena(
                        selected,
                        2,
                        selected_managed.arena_id().as_ptr(),
                    )
            });
            let retry = selected_view
                .try_reserve_exclusive_theap(selected, thread_sequence)
                .expect("the exact selected slice is reusable for a second Theap lifecycle");
            assert_eq!(retry.slice_index(), first_slice);
            assert!(
                !retry.memory_id().initially_zero(),
                "returning the prefix preserves the source dirty observation"
            );
            let mut retry_owner = match main.attach_requested_parent_arena_theap(heap.as_mut(), retry) {
                Ok(owner) => owner,
                Err(_) => panic!("the dirty selected slice remains valid Rust-prefix storage"),
            };
            assert!(retry_owner.is_attached());
            assert_eq!(retry_owner.test_theap_prefix_address(), expected_start.addr());
            assert_eq!(selected_free.is_clear_range(first_slice, 1), Some(true));
            retry_owner
                .teardown()
                .expect("the dirty reused prefix also detaches before its exact slice returns");
            assert!(retry_owner.is_torn_down());
            assert_eq!(selected.live_thread_count(), 1);
            assert_eq!(selected_free.is_set_range(first_slice, 1), Some(true));
            drop(retry_owner);

            // SAFETY: the second owner returned its exact slice and retired
            // the caller Heap, so this final isolated branch starts a third
            // source-shaped caller Heap solely to prove that dropping a live
            // owner preserves its terminal claim and poisons the main owner.
            assert!(unsafe {
                Pin::get_unchecked_mut(heap.as_mut())
                    .initialize_dynamic_binding_for_requested_arena(
                        selected,
                        2,
                        selected_managed.arena_id().as_ptr(),
                    )
            });
            let terminal_reservation = selected_view
                .try_reserve_exclusive_theap(selected, thread_sequence)
                .expect("the selected returned slice remains claimable before the terminal-owner check");
            let terminal_slice = terminal_reservation.slice_index();
            let mut terminal_owner = match main.attach_requested_parent_arena_theap(
                heap.as_mut(),
                terminal_reservation,
            ) {
                Ok(owner) => owner,
                Err(_) => panic!("the terminal-owner check begins from a valid live prefix"),
            };
            assert!(terminal_owner.is_attached());
            drop(terminal_owner);
            assert_eq!(
                selected_free.is_clear_range(terminal_slice, 1),
                Some(true),
                "dropping a live owner never releases a partially linked source claim"
            );
            assert_eq!(main.teardown(), Err(MainStaticTheapError::Poisoned));
            assert_eq!(selected.live_thread_count(), 1);
        })
        .join()
        .expect("the isolated requested-parent lifecycle assertion thread succeeds");
    }

    #[test]
    fn suitable_slice_claim_exhausts_and_release_reuses_its_contiguous_span() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
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
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let usable_slices = BCHUNK_BITS - view.arena().info_slices;

        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), usable_slices, true, 17)
            .unwrap();
        assert_eq!(claim.slice_index(), view.arena().info_slices);
        assert_eq!(claim.slice_count(), usable_slices);
        assert_eq!(Some(claim.start()), view.slice_start(view.arena().info_slices));
        let page_metadata = claim.page_metadata().unwrap();
        assert_eq!(
            page_metadata.as_ptr().cast::<u8>(),
            unsafe {
                view.arena()
                    .start
                    .add(view.arena().info_slices * size_of::<Page>())
            },
        );
        assert!(claim.memory_id().is_pinned());
        assert!(claim.memory_id().initially_committed());
        assert!(claim.memory_id().initially_zero());
        assert!(view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 17)
            .is_none());

        assert!(claim.release());
        let reused = view
            .try_claim_suitable_slices(ArenaId::none(), usable_slices, true, 17)
            .unwrap();
        assert_eq!(reused.slice_index(), view.arena().info_slices);
        assert!(!reused.memory_id().initially_zero());
        assert!(reused.release());
    }

    #[test]
    fn commit_failure_returns_claimed_slices_without_rolling_back_dirty_observation() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let script = CommitScript::new(false);
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                false,
                false,
                true,
                -1,
                false,
                Some(CommitHook::new(
                    scripted_commit,
                    (&script as *const CommitScript).cast_mut().cast(),
                )),
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let index = view.arena().info_slices;
        let deferred = view
            .try_claim_suitable_slices(ArenaId::none(), 1, false, 3)
            .unwrap();
        assert!(!deferred.memory_id().initially_committed());
        assert!(deferred.memory_id().initially_zero());
        assert!(deferred.release());
        script
            .fail
            .store(true, std::sync::atomic::Ordering::Relaxed);

        assert!(view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 3)
            .is_none());
        let free = unsafe { view.slices_free() }.unwrap();
        let committed = unsafe { view.slices_committed() }.unwrap();
        let dirty = unsafe { view.slices_dirty() }.unwrap();
        assert_eq!(free.is_set_range(index, 1), Some(true));
        assert_eq!(committed.is_clear_range(index, 1), Some(true));
        assert_eq!(dirty.is_set_range(index, 1), Some(true));

        script
            .fail
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let retry = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 3)
            .unwrap();
        assert!(retry.memory_id().initially_committed());
        assert!(!retry.memory_id().initially_zero());
        assert!(retry.release());
        assert_eq!(script.calls.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    #[test]
    fn successful_external_commit_hook_can_report_a_zero_committed_slice() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let script = CommitScript::new(true);
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                false,
                false,
                false,
                -1,
                false,
                Some(CommitHook::new(
                    scripted_commit,
                    (&script as *const CommitScript).cast_mut().cast(),
                )),
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let index = view.arena().info_slices;

        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .unwrap();
        assert!(claim.memory_id().initially_committed());
        assert!(claim.memory_id().initially_zero());
        assert_eq!(
            unsafe { view.slices_committed() }
                .unwrap()
                .is_set_range(index, 1),
            Some(true),
        );
        assert!(claim.release());
        assert_eq!(script.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn fully_committed_arena_claim_invokes_linux_reuse_for_its_exact_span() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let slice_index = view.arena().info_slices;
        let start = view
            .slice_start(slice_index)
            .and_then(NonNull::new)
            .expect("the first usable source arena slice has one non-null start");
        let slice_count = 2;
        let size = invariants::size_of_slices(slice_count)
            .and_then(NonZeroUsize::new)
            .expect("the exact two-slice source span has a checked nonzero size");
        let reuse = os::test_install_arena_reuse_witness(start, size);

        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), slice_count, true, 0)
            .expect("the precommitted source span is claimable");

        assert_eq!(claim.slice_count(), slice_count);
        assert!(claim.memory_id().initially_committed());
        assert!(claim.release());
        assert_eq!(
            reuse.calls(),
            1,
            "pinned src/arena.c:296-307 reuses the exact already committed claimed span"
        );
    }

    #[test]
    fn unpinned_slice_release_schedules_the_default_delayed_decommit_before_reuse() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .unwrap();
        let slice_index = claim.slice_index();

        assert!(claim.release());

        let free = unsafe { view.slices_free() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(purge.is_set_range(slice_index, 1), Some(true));
        assert_eq!(free.is_set_range(slice_index, 1), Some(true));
        assert!(view.arena().purge_expire.load(core::sync::atomic::Ordering::Acquire) > 0);
    }

    #[test]
    fn external_purge_callback_recommit_clears_committed_bits_for_a_later_uncommitted_claim() {
        // Pinned `src/arena.c:2254-2282` marks the selected range committed
        // before `_mi_os_purge_ex`. Its custom callback arm in
        // `src/os.c:655-680` returns the callback boolean as
        // `needs_recommit`, so a true `commit = false` result must clear the
        // exact committed range before the source returns it to `slices_free`.
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let script = RecommitPurgeScript::new();
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                Some(CommitHook::new(
                    recommit_after_purge,
                    (&script as *const RecommitPurgeScript).cast_mut().cast(),
                )),
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let slice_index = view.arena().info_slices;
        let slice_count = 2;
        let start = view
            .slice_start(slice_index)
            .expect("the first usable external slice has an exact source address");
        let size = invariants::size_of_slices(slice_count)
            .expect("the selected source slice span has a checked size");

        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), slice_count, true, 0)
            .expect("the initially committed exact external span is claimable");
        assert!(claim.memory_id().initially_committed());
        assert!(claim.release());

        let free = unsafe { view.slices_free() }.unwrap();
        let committed = unsafe { view.slices_committed() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(committed.is_set_range(slice_index, slice_count), Some(true));
        assert_eq!(purge.is_set_range(slice_index, slice_count), Some(true));

        assert!(view.collect_scheduled_purge(PageSize::new(4096).unwrap(), true));
        assert_eq!(
            script
                .false_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the forced source purge invokes the external callback exactly once"
        );
        assert_eq!(
            script
                .false_start
                .load(std::sync::atomic::Ordering::Relaxed),
            start.addr(),
            "the callback receives the selected source span start"
        );
        assert_eq!(
            script
                .false_size
                .load(std::sync::atomic::Ordering::Relaxed),
            size,
            "the callback receives the selected source span size"
        );
        assert_eq!(committed.is_clear_range(slice_index, slice_count), Some(true));
        assert_eq!(free.is_set_range(slice_index, slice_count), Some(true));
        assert_eq!(purge.is_clear_range(slice_index, slice_count), Some(true));
        assert_eq!(
            view.arena().purge_expire.load(core::sync::atomic::Ordering::Acquire),
            0,
            "the forced collection consumes its selected purge work"
        );

        let uncommitted = view
            .try_claim_suitable_slices(ArenaId::none(), slice_count, false, 0)
            .expect("the purged external span is returned to the free bitmap");
        assert!(
            !uncommitted.memory_id().initially_committed(),
            "the callback's needs-recommit result clears the later uncommitted observation"
        );
        assert!(uncommitted.release());
    }

    #[test]
    fn scheduled_purge_splits_a_run_at_each_source_bitmap_field_boundary() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let script = CommitScript::new(false);
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                Some(CommitHook::new(
                    scripted_commit,
                    (&script as *const CommitScript).cast_mut().cast(),
                )),
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        assert_eq!(view.arena().info_slices, 9);

        // Hold the usable prefix so the next exact free claim starts at 63.
        // Pinned `mi_arena_try_purge` uses the generic
        // `_mi_bitmap_forall_setc_rangesn(..., 1, ...)` visitor, whose runs
        // cannot cross a 64-bit `mi_bfield_t` boundary.
        let prefix = view
            .try_claim_suitable_slices(ArenaId::none(), 54, true, 0)
            .expect("the selected 9..63 prefix is usable");
        assert_eq!(prefix.slice_index(), view.arena().info_slices);
        assert_eq!(prefix.slice_count(), crate::bitmap::BFIELD_BITS - 10);

        let boundary = view
            .try_claim_suitable_slices(ArenaId::none(), 2, true, 0)
            .expect("the selected 63..65 boundary span is usable");
        assert_eq!(boundary.slice_index(), crate::bitmap::BFIELD_BITS - 1);
        assert_eq!(boundary.slice_count(), 2);
        assert!(boundary.release());

        let calls_before = script.calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(view.collect_scheduled_purge(PageSize::new(4096).unwrap(), true));
        assert_eq!(
            script.calls.load(std::sync::atomic::Ordering::Relaxed),
            calls_before + 2,
            "the source visitor invokes the default decommit callback once per 64-bit field"
        );
        let free = unsafe { view.slices_free() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(free.is_set_range(crate::bitmap::BFIELD_BITS - 1, 2), Some(true));
        assert_eq!(purge.is_clear_range(crate::bitmap::BFIELD_BITS - 1, 2), Some(true));

        assert!(prefix.release());
    }

    #[test]
    fn scheduled_purge_retries_the_free_sibling_after_partial_allocation_reclaim() {
        // Pinned `mi_arena_try_purge_visitor` first claims a whole scheduled
        // run. When an allocation has reclaimed one slice, its failed whole
        // claim retries each slice: the allocation-won slice stays unavailable
        // while a free sibling is still purged. Keep the reclaim live through
        // collection so this observes that source fallback rather than an
        // ordinary two-slice purge.
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let script = CommitScript::new(false);
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                Some(CommitHook::new(
                    scripted_commit,
                    (&script as *const CommitScript).cast_mut().cast(),
                )),
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let first_usable_slice = view.arena().info_slices;
        assert_eq!(first_usable_slice, 9);

        let scheduled = view
            .try_claim_suitable_slices(ArenaId::none(), 2, true, 0)
            .expect("the selected external arena has a two-slice free run");
        assert_eq!(scheduled.slice_index(), first_usable_slice);
        assert!(scheduled.release());

        let reclaimed = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .expect("the low slice is reclaimed before forced purge collection");
        assert_eq!(reclaimed.slice_index(), first_usable_slice);

        let calls_before = script.calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(view.collect_scheduled_purge(PageSize::new(4096).unwrap(), true));
        assert_eq!(
            script.calls.load(std::sync::atomic::Ordering::Relaxed),
            calls_before + 1,
            "only the still-free sibling reaches the external decommit callback"
        );

        let free = unsafe { view.slices_free() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(free.is_clear_range(first_usable_slice, 1), Some(true));
        assert_eq!(
            free.is_set_range(first_usable_slice + 1, 1),
            Some(true),
        );
        assert_eq!(purge.is_clear_range(first_usable_slice, 2), Some(true));

        assert!(reclaimed.release());
    }

    #[test]
    fn clock_failure_skips_optional_purge_without_losing_the_released_slice() {
        let _fault = crate::os::fault::install(crate::os::fault::Plan::at(
            crate::os::fault::Point::Clock,
            1,
            crabc_core::Errno::NOMEM,
        ));
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .unwrap();
        let slice_index = claim.slice_index();

        assert!(claim.release());

        let free = unsafe { view.slices_free() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(free.is_set_range(slice_index, 1), Some(true));
        assert_eq!(purge.is_clear_range(slice_index, 1), Some(true));
        assert_eq!(
            view.arena().purge_expire.load(core::sync::atomic::Ordering::Acquire),
            0,
        );
    }

    #[test]
    fn pinned_slice_release_skips_purge_scheduling() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
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
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .unwrap();
        let slice_index = claim.slice_index();

        assert!(claim.release());

        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(purge.is_clear_range(slice_index, 1), Some(true));
        assert_eq!(
            view.arena().purge_expire.load(core::sync::atomic::Ordering::Acquire),
            0,
        );
    }

    #[test]
    fn arena_release_rejects_foreign_subprocess_before_purge_or_free_then_releases_selected_claim() {
        // `src/subproc.c:_mi_meta_free` routes non-Malloc metadata through
        // `_mi_arenas_free(subproc, ...)`; its `MI_MEM_ARENA` branch asserts
        // this exact arena/subprocess identity before it schedules purge or
        // returns a free bitmap span. Keep this fixture unpinned: an incorrect
        // release that schedules purge before checking identity would change
        // observable purge state. A rejected foreign caller must leave both
        // purge and free-bitmap state unchanged.
        let selected = MainSubprocess::test_static_owner();
        let foreign = MainSubprocess::test_static_owner();
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(selected.as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .expect("the selected arena has one usable slice claim");
        let slice_index = claim.slice_index();
        let free = unsafe { view.slices_free() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        assert_eq!(free.is_clear_range(slice_index, 1), Some(true));
        assert_eq!(purge.is_clear_range(slice_index, 1), Some(true));
        assert_eq!(
            view.arena().purge_expire.load(core::sync::atomic::Ordering::Acquire),
            0,
        );

        let claim = claim
            .release_for_subprocess(foreign)
            .expect_err("a foreign subprocess must be rejected before Rust purge/free state changes");
        assert_eq!(free.is_clear_range(slice_index, 1), Some(true));
        assert_eq!(purge.is_clear_range(slice_index, 1), Some(true));
        assert_eq!(
            view.arena().purge_expire.load(core::sync::atomic::Ordering::Acquire),
            0,
        );

        let released = match claim.release_for_subprocess(selected) {
            Ok(released) => released,
            Err(_) => panic!("the selected subprocess may return its exact arena claim"),
        };
        assert!(released);
        assert_eq!(free.is_set_range(slice_index, 1), Some(true));

        let retry = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .expect("the selected release restores the exact free bitmap bit");
        assert_eq!(retry.slice_index(), slice_index);
        let released_retry = match retry.release_for_subprocess(selected) {
            Ok(released) => released,
            Err(_) => panic!("the selected retry owns the same arena/subprocess pair"),
        };
        assert!(released_retry);
    }

    #[test]
    fn abandoned_reclaim_main_map_rejects_an_orphan_bit_without_consuming_it() {
        // This deliberately injects the impossible-after-publication image
        // that source assertions exclude: a `pages_abandoned` bit exists but
        // the matching ordinary `pages` bit does not. The reclaim primitive
        // must preserve that bit and its count for the terminal owner rather
        // than hand out a page whose PageMap/metadata lifetime is no longer
        // represented by the main Heap image.
        let subprocess = MainSubprocess::test_static_owner();
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                false,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let bin = 1;
        let slice_index = view.arena().info_slices;

        let mut heap = Heap::bootstrap_empty();
        heap.initialize_main_static(subprocess, MemoryId::static_kind_only());
        heap.install_main_arena_pages(
            subprocess,
            view.arena().arena_index,
            NonNull::from(&view.arena().pages_main),
        )
        .unwrap();
        let map = view
            .main_heap_abandoned_page(NonNull::from(&heap), bin)
            .expect("the static main Heap owns this arena's in-place image");

        // Test-only raw setup models a fault after an abandoned-bit
        // publication but before the ordinary image can prove page lifetime.
        let raw = view.abandoned_pages(bin).unwrap();
        assert!(raw.publish(slice_index));
        heap.increment_abandoned_count(bin);

        let mut ownership_attempts = 0;
        assert_eq!(
            map.try_claim(0, |_| {
                ownership_attempts += 1;
                AbandonedBitmapClaim::Claimed
            }),
            MappedAbandonedClaim::None,
        );
        assert_eq!(ownership_attempts, 0);
        assert!(raw.is_published(slice_index));
        assert_eq!(heap.abandoned_count(bin), Some(1));
    }

    #[test]
    fn abandoned_reclaim_main_map_retains_rejected_boundary_candidate_count() {
        // This is the valid source order across adjacent atomic bitmap words:
        // the main Heap records ordinary page ownership first, then
        // abandonment publishes matching bits and counts. A rejected low-word
        // ownership claim restores its bit and leaves both counts intact;
        // only the later source unabandon/claim transitions consume them.
        let subprocess = MainSubprocess::test_static_owner();
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                false,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let bin = 1;
        let rejected = crate::bitmap::BFIELD_BITS - 1;
        let later_word = crate::bitmap::BFIELD_BITS;
        let pages = unsafe { view.pages() }.unwrap();
        assert!(pages.set_range(rejected, 2).is_some());

        let mut heap = Heap::bootstrap_empty();
        heap.initialize_main_static(subprocess, MemoryId::static_kind_only());
        heap.install_main_arena_pages(
            subprocess,
            view.arena().arena_index,
            NonNull::from(&view.arena().pages_main),
        )
        .unwrap();
        let map = view
            .main_heap_abandoned_page(NonNull::from(&heap), bin)
            .expect("the static main Heap owns this arena's in-place image");

        assert!(map.is_clear(rejected));
        assert!(map.is_clear(later_word));
        assert!(map.publish(rejected));
        assert!(map.publish(later_word));
        assert_eq!(heap.abandoned_count(bin), Some(2));

        let mut ownership_attempts = 0;
        assert_eq!(
            map.try_claim(0, |candidate| {
                ownership_attempts += 1;
                assert_eq!(candidate, rejected);
                AbandonedBitmapClaim::KeepSet
            }),
            MappedAbandonedClaim::None,
        );
        assert_eq!(ownership_attempts, 1);
        let raw = view.abandoned_pages(bin).unwrap();
        assert!(raw.is_published(rejected));
        assert!(raw.is_published(later_word));
        assert_eq!(heap.abandoned_count(bin), Some(2));

        // `_mi_arenas_page_unabandon` waits for the rejected reader before it
        // clears its exact bit, clears the mapped identity, and only then
        // consumes the paired Heap count. A fresh source search can now reach
        // the next-word candidate.
        assert!(map.clear_once_set(rejected));
        assert!(map.decrement_after_identity_clear());
        assert_eq!(heap.abandoned_count(bin), Some(1));
        assert_eq!(
            map.try_claim(0, |candidate| {
                ownership_attempts += 1;
                assert_eq!(candidate, later_word);
                AbandonedBitmapClaim::Claimed
            }),
            MappedAbandonedClaim::Claimed(later_word),
        );
        assert_eq!(ownership_attempts, 2);
        assert!(map.is_clear(rejected));
        assert!(!raw.is_published(later_word));
        assert_eq!(heap.abandoned_count(bin), Some(0));
    }

    #[test]
    fn purge_owned_slice_cannot_be_claimed_for_allocation() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        let managed = unsafe {
            manage_external_in_place(
                &registry,
                region.as_ptr(),
                ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(),
                true,
                false,
                true,
                -1,
                false,
                None,
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let slice_index = view.arena().info_slices;
        let free = unsafe { view.slices_free() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();

        // This is the collector's source `mi_bbitmap_try_clearNC` ownership
        // state between clearing the scheduled bit and returning availability.
        assert_eq!(free.try_clear_within_chunk(slice_index, 1), Some(true));
        assert!(purge.set_range(slice_index, 1).is_some());
        let other_claim = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .unwrap();
        assert_ne!(other_claim.slice_index(), slice_index);
        assert!(other_claim.release());

        assert_eq!(purge.clear_range(slice_index, 1), Some(true));
        assert_eq!(free.set_range(slice_index, 1), Some(true));
        let claim = view
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .unwrap();
        assert_eq!(claim.slice_index(), slice_index);
        assert!(claim.release());
    }
}
