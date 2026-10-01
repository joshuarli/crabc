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
    Page, Subprocess, Theap, ThreadSequence,
};
#[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
use crate::types::MemoryKind;

#[path = "arena_selection.rs"]
mod selection;
pub(crate) use selection::{ArenaCandidates, ArenaReservationPlan, ArenaSearch, arena_max_object_size};

#[path = "arena_owned.rs"]
mod owned;
pub(crate) use owned::{PreparedSourceInitializationRelease, SourceInitializationReleaseDecision,
    SourceInitializationReleaseError, SourceInitializationReleaseOutcome, SourceInitializationReleaseStep,
    SourceInitializationPurgeTask, CompletedSourceInitializationPurge, SourceInitializationPurgeResult,
    arena_purge_delay, ReserveOsMemoryFailure, ArenaDestroyError, DestroyedArenas, ArenaPageCommitError, FirstRegularStartupArenaSelection,
    ProcessArenaBacking, ProcessArenaInstallFailure, ProcessExternalArenaLease, HugeArenaReserveError,
    HugeArenaCleanupError, StartupArenaReservationOutcomes};

#[cfg(test)]
pub(crate) use owned::m2_external_callback_trace;

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

    /// Tests the source slice range of this parent, then its published child
    /// ranges in the calling subprocess. A parent's owned mapping can exceed
    /// its own slice range after a large external region is split.
    ///
    /// # Safety
    /// The ID and every published arena inspected through `registry` remain
    /// live for the query. The registry is the calling thread's subprocess.
    pub(crate) unsafe fn contains_in(self, registry: &ArenaRegistry, pointer: *const u8) -> bool {
        let Some(parent) = self.0 else { return false };
        // SAFETY: the caller retains the parent and its published children.
        let parent = unsafe { parent.as_ref() };
        if arena_strictly_contains(parent, pointer) {
            return true;
        }
        for index in 0..registry.count() {
            // SAFETY: the caller retains every arena published by this registry.
            let Some(arena) = (unsafe { registry.arena_at(index) }) else { continue };
            if (core::ptr::eq(arena, parent) || core::ptr::eq(arena.parent, parent))
                && arena_strictly_contains(arena, pointer)
            {
                return true;
            }
        }
        false
    }
}

/// Source arena containment excludes the end address and uses the slice
/// range, which can be shorter than a parent arena's total backing span.
fn arena_strictly_contains(arena: &Arena, pointer: *const u8) -> bool {
    let Some(size) = invariants::size_of_slices(arena.slice_count) else { return false };
    let address = pointer as usize;
    let start = arena.start as usize;
    address >= start && address - start < size
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
// pointer is selected once before registry publication. After a fresh slot's
// Release pointer publication succeeds, `insert` dereferences the matching
// process-long arena pointer solely to perform the source's relaxed private
// event update; the registry binding and every initialized arena retain that
// owner for the arena's whole published lifetime.
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

    /// Acquire-loads one published arena identity without borrowing its image.
    /// The caller must retain its backing before projecting any fields.
    pub(crate) fn arena_print_pointer(&self, index: usize) -> Option<NonNull<Arena>> {
        if index >= self.count() || index >= MAX_ARENAS { return None; }
        NonNull::new(pointer_load_acquire(&self.arenas[index]))
    }

    /// Publishes an initialized arena, first reusing null slots and then
    /// growing the source's high-water count.
    ///
    /// # Safety
    ///
    /// `arena` must be uniquely owned, fully initialized, and remain live
    /// until the registry is quiesced. It must not already be registered. Its
    /// `subprocess` pointer must equal this registry's initialized binding and
    /// remain valid for that same lifetime, because a newly published
    /// high-water slot performs the source's subprocess counter update.
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
                    // Pinned `mi_arenas_add` increments only after this fresh
                    // high-water slot's pointer publication succeeds. A
                    // reused null slot and every failed publication bypass it.
                    // SAFETY: `insert` requires the initialized arena and
                    // registry to carry the same non-null, process-long
                    // subprocess pointer. All production constructors bind
                    // before management; the only nullable registry state is
                    // the pre-publication construction state.
                    let subprocess = unsafe {
                        core::ptr::NonNull::new_unchecked((*arena).subprocess)
                    };
                    debug_assert!(core::ptr::eq(subprocess.as_ptr(), self.subprocess()));
                    unsafe {
                        subprocess
                            .as_ref()
                            .arena_statistics()
                            .high_water_arena_published();
                    }
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
        let guard_size = if crate::config::SECURE_LEVEL > 0 { page_size } else { 0 };
        let info_size = invariants::align_up(bitmaps_end, page_size)?.checked_add(guard_size)?;
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
    /// The source OS guard is one base page whenever security is enabled.
    /// Its arena-info reservation is independent of whether backing is pinned.
    #[inline]
    pub(crate) const fn guard_size(self) -> usize {
        if crate::config::SECURE_LEVEL > 0 { self.page_size } else { 0 }
    }

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

    /// The warning pinned `mi_manage_os_memory_ex2` prints when it rejects
    /// this region (`src/arena.c:1800-1820`): a nonnull start whose aligned
    /// remainder is below one arena alignment, or a whole-chunk span below
    /// `MI_ARENA_MIN_SIZE`. `None` for an accepted region or a null start,
    /// which the source rejects silently.
    pub(crate) fn source_rejection_warning(address: usize, size: usize)
        -> Option<crate::diagnostic_output::SourceFormattedMessage> {
        use crate::diagnostic_output::SourceFormattedMessage;
        if address == 0 || Self::from_address(address, size).is_some() {
            return None;
        }
        let aligned_address = invariants::align_up(address, ARENA_ALIGNMENT)?;
        let prefix_bytes = aligned_address - address;
        if prefix_bytes != 0 && (prefix_bytes >= size || size - prefix_bytes < ARENA_ALIGNMENT) {
            return Some(SourceFormattedMessage::arena_too_small_after_alignment(address, size));
        }
        let usable_size = size - prefix_bytes;
        Some(SourceFormattedMessage::arena_not_large_enough(
            usable_size / crate::config::KIB, ARENA_MIN_SIZE / crate::config::KIB))
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

    /// Invokes the exact source callback retained by a process-lived owner.
    ///
    /// # Safety
    ///
    /// The owner that formed this hook proves that the callback, user argument,
    /// and requested range remain valid for this invocation. A purge caller
    /// supplies a null zero pointer. A metadata commit also supplies null;
    /// a page-claim commit supplies a writable output.
    #[inline]
    pub(crate) unsafe fn invoke(
        self,
        commit: bool,
        start: *mut u8,
        size: usize,
        is_zero: *mut bool,
    ) -> bool {
        unsafe { (self.function)(commit, start, size, is_zero, self.argument) }
    }
}

/// Synchronous secure metadata transition borrowed from its live owner.
/// The initializer never retains this callback in a published arena. Failure
/// reporting belongs to the callback: source initialization continues after
/// an unsuccessful guard operation, but cannot invent an absent owner.
#[derive(Clone, Copy)]
pub(super) struct MetadataGuardHook<'owner> {
    function: unsafe fn(*mut u8, usize, *const c_void),
    argument: *const c_void,
    _owner: core::marker::PhantomData<&'owner c_void>,
}

impl<'owner> MetadataGuardHook<'owner> {
    pub(super) fn new<T>(function: unsafe fn(*mut u8, usize, *const c_void), owner: &'owner T) -> Self {
        Self { function, argument: core::ptr::from_ref(owner).cast(),
            _owner: core::marker::PhantomData }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManageArenaError {
    InvalidRegion,
    InvalidPageSize,
    MetadataDoesNotFit,
    CommitRequired,
    CommitFailed,
    GuardRequired,
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
#[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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
    unsafe {
        manage_os_in_place_with_numa_source(
            registry,
            start,
            size,
            page_size,
            memory,
            || numa_node,
            exclusive,
            commit_hook,
        )
    }
}

/// Registers one regular OS mapping while deferring its source NUMA choice
/// until each arena has passed metadata preparation.
///
/// Pinned `src/arena.c:1676-1740` validates the region, commits and zeroes its
/// metadata prefix, and only then selects the stored `arena->numa_node`.
/// This private companion preserves that ordering for the policy-bound first
/// regular arena without giving a failed map or metadata commit a topology
/// observation side effect.
///
/// # Safety
///
/// The caller must uphold [`manage_os_in_place`]'s complete mapping and
/// callback contract. `numa_node_source` must be synchronous, must not retain
/// an arena pointer or mapping capability, and must return a source-valid node
/// for every arena the bounded manager initializes.
#[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
pub(crate) unsafe fn manage_os_in_place_with_numa_source<N>(
    registry: &ArenaRegistry,
    start: *mut u8,
    size: usize,
    page_size: PageSize,
    memory: MemoryId,
    numa_node_source: N,
    exclusive: bool,
    commit_hook: Option<CommitHook>,
) -> Result<ManagedExternalRegion, ManageArenaError>
where
    N: FnMut() -> i32,
{
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
        manage_in_place_with_publisher_and_numa_source(
            registry,
            start,
            size,
            page_size,
            initially_committed,
            numa_node_source,
            exclusive,
            commit_hook,
            commit_hook,
            None,
            memory,
            |arena| {
                if registry.insert(arena) {
                    Ok(())
                } else {
                    Err(ManageArenaError::RegistryFull)
                }
            },
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
    memory: MemoryId,
) -> Result<ManagedExternalRegion, ManageArenaError> {
    unsafe {
        manage_in_place_with_publisher_and_numa_source(
            registry,
            start,
            size,
            page_size,
            initially_committed,
            || numa_node,
            exclusive,
            commit_hook,
            commit_hook,
            None,
            memory,
            |arena| {
                if registry.insert(arena) {
                    Ok(())
                } else {
                    Err(ManageArenaError::RegistryFull)
                }
            },
        )
    }
}

/// Initializes each in-place arena before its caller publishes it.
///
/// The source callback can reenter the process arena owner while metadata is
/// being made accessible. Keeping callback-bearing preparation separate from
/// registry insertion lets that owner release its reserve lock for the
/// callback and reacquire it only for the source publication transition.
///
/// # Safety
///
/// The caller upholds the normal in-place range and memory provenance contract.
/// The publisher must either make exactly one arena registry-visible, or return
/// without exposing it. Once it returns success, the arena is permanent.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn manage_in_place_with_publisher<F>(
    registry: &ArenaRegistry,
    start: *mut u8,
    size: usize,
    page_size: PageSize,
    initially_committed: bool,
    numa_node: i32,
    exclusive: bool,
    commit_hook: Option<CommitHook>,
    memory: MemoryId,
    publish: F,
) -> Result<ManagedExternalRegion, ManageArenaError>
where
    F: FnMut(*mut Arena) -> Result<(), ManageArenaError>,
{
    unsafe {
        manage_in_place_with_publisher_and_numa_source(
            registry,
            start,
            size,
            page_size,
            initially_committed,
            || numa_node,
            exclusive,
            commit_hook,
            commit_hook,
            None,
            memory,
            publish,
        )
    }
}

/// Common source management loop with a node source that runs only at the
/// `mi_arena_initialize` field-write position.
///
/// This stays private to arena owners whose retained policy can supply a node
/// only after the preceding metadata preparation has succeeded.
#[allow(clippy::too_many_arguments)]
unsafe fn manage_in_place_with_publisher_and_numa_source<F, N>(
    registry: &ArenaRegistry,
    start: *mut u8,
    size: usize,
    page_size: PageSize,
    initially_committed: bool,
    mut numa_node_source: N,
    exclusive: bool,
    commit_hook: Option<CommitHook>,
    metadata_commit_hook: Option<CommitHook>,
    metadata_guard_hook: Option<MetadataGuardHook<'_>>,
    mut memory: MemoryId,
    mut publish: F,
) -> Result<ManagedExternalRegion, ManageArenaError>
where
    F: FnMut(*mut Arena) -> Result<(), ManageArenaError>,
    N: FnMut() -> i32,
{
    // `mi_arenas_add` always receives the source subprocess that owns the
    // arena. Rust permits constructing a registry before that one-time
    // binding, but never publishing through it: a successful fresh slot must
    // update the mandatory process-owned source counter immediately after
    // pointer publication.
    if registry.subprocess().is_null() {
        return Err(ManageArenaError::InvalidRegion);
    }
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
            prepare_arena_in_place(
                registry,
                arena_start,
                arena_size,
                split.slice_count(),
                parent,
                split.total_size(),
                page_size.bytes(),
                &mut numa_node_source,
                exclusive,
                memory,
                initially_committed,
                commit_hook,
                metadata_commit_hook,
                metadata_guard_hook,
            )
        };
        match initialized {
            Ok(arena) => {
                if let Err(error) = publish(arena) {
                    if parent.is_null() {
                        return Err(error);
                    }
                    unsafe { (*parent).total_size = managed_size };
                    return Ok(ManagedExternalRegion {
                        arena_id: parent_id,
                        total_size: plan.total_size(),
                        managed_size,
                    });
                }
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

/// Original arena-claim custody between short source initialization
/// projections. Raw issuer facts identify the inverse transition; they never
/// retain a backing, grant an arena lifetime, or authorize an inferred free.
/// The actual admitted owner must remain independently pinned until explicit
/// restoration, transfer to a linked Theap, or terminal retention completes.
#[must_use = "initialization custody must be restored, transferred, or explicitly retained"]
pub(crate) struct SourceInitializationClaimCustody {
    arena: NonNull<Arena>,
    start: NonNull<u8>,
    memory: MemoryId,
    issuer: NonNull<ProcessArenaBacking>,
    arena_index: usize,
    subprocess: NonNull<Subprocess>,
}

/// A refused inverse transition has not returned any slices or consumed the
/// original custody. The caller retains that token and its actual owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceInitializationClaimCustodyError {
    WrongBacking,
    TerminalBacking,
    UnpublishedArena,
    SourceIdentityMismatch,
    InvalidClaimSpan,
    MissingBackingOwner,
    ClaimNoLongerOutstanding,
}

impl SourceInitializationClaimCustody {
    /// Transfers the original release obligation to a source-published Theap.
    /// This returns the stored observation, never a new release capability.
    ///
    /// # Safety
    /// The actual retained issuer remains alive, the Theap carries this exact
    /// original memory identity, and its TLD/Heap links now retain its image
    /// for the complete source lifecycle. No pre-link failure or independent
    /// claim release may remain. Partial initialization that cannot transfer
    /// the normal lifecycle must instead retain custody terminally.
    pub(crate) unsafe fn into_published_memory(self) -> MemoryId { self.memory }

    /// Consumes custody without returning a possibly published span. The
    /// source owner thereafter retains that span through quiescent teardown;
    /// no claim, retry, or implicit bitmap release is manufactured here.
    pub(crate) fn retain_terminal(self) {}
}

impl ArenaSliceClaim<'_> {
    /// Consumes the original process-backed claim before ending its short
    /// issuing projection. An unbacked or foreign claim is returned unchanged.
    /// The resulting token has no destructor and retains no Rust arena borrow.
    ///
    /// # Safety
    /// An independently pinned actual admitted owner must retain this exact
    /// backing, source identity, published arena and mapping through every
    /// callback and subsequent inverse, linked transfer or terminal retention.
    /// For a child, the original record's callback lease must stay live, and
    /// its selected Heap and current member must exclude self-teardown. That
    /// real admission must prevent destruction, replacement and address reuse;
    /// the copied pointers and an erased projection lifetime prove none of
    /// those obligations. Custody must not escape the retained owner scope.
    pub(crate) unsafe fn into_source_initialization_custody(
        self,
    ) -> Result<SourceInitializationClaimCustody, Self> {
        let Some(backing) = self.backing else { return Err(self); };
        // SAFETY: the original claim still retains its live arena projection.
        // Only scalar identities survive this read, under the external owner
        // lifetime obligation required for the consuming transition above.
        let arena = unsafe { self.arena.as_ref() };
        let Some(subprocess) = NonNull::new(arena.subprocess) else { return Err(self); };
        if backing.registry().arena_print_pointer(arena.arena_index) != Some(self.arena)
            || !backing.registry().is_bound_to_subprocess(subprocess.as_ptr()) {
            return Err(self);
        }
        Ok(SourceInitializationClaimCustody {
            arena: self.arena, start: self.start, memory: self.memory,
            issuer: NonNull::from(backing), arena_index: arena.arena_index, subprocess,
        })
    }

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
            let committed_now = if let Some(commit) = arena.commit_function {
                unsafe {
                    commit(
                        true,
                        metadata_start,
                        metadata_size,
                        null_mut(),
                        arena.commit_function_argument,
                    )
                }
            } else {
                self.backing?.commit_external_os_page_area(arena, metadata_start, metadata_size)
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
    /// complete source arena slices. A caller-owned OS arena uses the source
    /// null-callback branch and keeps its mapping release right with the caller.
    #[inline]
    pub(crate) fn commit_initial_page_prefix(&self, size: usize) -> bool {
        let Some(span_size) = self.slice_count().checked_mul(ARENA_SLICE_SIZE) else {
            return false;
        };
        if size == 0 || size > span_size {
            return false;
        }
        let arena = unsafe { self.arena.as_ref() };
        if let Some(commit) = arena.commit_function {
            let mut is_zero = false;
            // SAFETY: `self` owns the exact live slice span, the validated
            // prefix begins at its leading slice, and the arena callback is
            // stable while the registered arena remains live.
            unsafe {
                commit(
                    true,
                    self.start.as_ptr(),
                    size,
                    &mut is_zero,
                    arena.commit_function_argument,
                )
            }
        } else {
            self.backing.is_some_and(|backing| backing.commit_external_os_page_area(
                arena, self.start.as_ptr(), size,
            ))
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

/// Exact source reservation retained after a possibly mutating release
/// invariant failure. It exposes provenance only; no retry, typed prefix, or
/// slice-release capability can be recovered through this terminal state.
pub(crate) struct TerminalArenaTheapReservation<'arena, 'subprocess> {
    reservation: ExclusiveArenaTheapReservation<'arena, 'subprocess>,
}

impl TerminalArenaTheapReservation<'_, '_> {
    pub(crate) fn memory_id(&self) -> MemoryId { self.reservation.memory_id() }
}

impl<'arena, 'subprocess> ExclusiveArenaTheapReservation<'arena, 'subprocess> {
    /// The start of this still-owned, committed requested-arena slice.
    /// The address is valid only while this reservation remains live; callers
    /// must place at most one image there and clear it before release.
    #[inline]
    pub(crate) fn start(&self) -> *mut u8 {
        self.claim.start()
    }

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

    /// Preserves the exact reservation if the source release invariant fails.
    /// The returned owner is terminal diagnostic ownership, never permission
    /// to repeat a possibly partially applied bitmap/purge transition.
    pub(crate) fn release_retaining_failure(self)
        -> Result<(), TerminalArenaTheapReservation<'arena, 'subprocess>> {
        let arena = unsafe { self.claim.arena.as_ref() };
        if !core::ptr::eq(arena.subprocess, self.subprocess.as_ptr()) {
            return Err(TerminalArenaTheapReservation { reservation: self });
        }
        let released = if let Some(backing) = self.claim.backing {
            unsafe { backing.release_slices(self.claim.memory) }
        } else {
            unsafe { release_arena_slices(self.claim.memory) }
        };
        if released { Ok(()) } else { Err(TerminalArenaTheapReservation { reservation: self }) }
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
    /// Retains the original initialized prefix capability without creating a
    /// whole-image reference. Its local fields may be mutated only by a
    /// sealed owner-bound session that excludes overlapping local access;
    /// this pointer grants no independent release or extended lifetime.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub(crate) fn prefix_pointer(&self) -> NonNull<Theap> { self.prefix }

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

    /// Borrows the initialized source image while the exact arena claim lives.
    pub(crate) fn prefix(&self) -> &Theap {
        // SAFETY: materialization wrote the prefix and this owner retains it.
        unsafe { self.prefix.as_ref() }
    }

    /// Drops a detached prefix while retaining its raw arena release owner.
    ///
    /// # Safety
    /// Both lists, all pages and references must be detached; the final
    /// refcount transition must have completed, with no surviving aliases.
    pub(crate) unsafe fn drop_prefix_for_release(self)
        -> ExclusiveArenaTheapReservation<'arena, 'subprocess> {
        let Self { reservation, prefix } = self;
        unsafe { core::ptr::drop_in_place(prefix.as_ptr()) };
        reservation
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
/// source's strict skip. A failed monotonic query uses the source `clock()`
/// fallback, so the released span remains eligible for delayed purge.
/// If the delay cannot be represented, the caller still returns the slice to
/// the free bitmap without making optional purge terminal.
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
    let now = os::source_clock_now();
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
unsafe fn prepare_arena_in_place<N>(
    registry: &ArenaRegistry,
    start: *mut u8,
    region_size: usize,
    slice_count: usize,
    parent: *mut Arena,
    total_size: usize,
    page_size: usize,
    numa_node_source: &mut N,
    exclusive: bool,
    memory: MemoryId,
    metadata_already_accessible: bool,
    commit_hook: Option<CommitHook>,
    metadata_commit_hook: Option<CommitHook>,
    metadata_guard_hook: Option<MetadataGuardHook<'_>>,
) -> Result<*mut Arena, ManageArenaError>
where
    N: FnMut() -> i32,
{
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

    if memory.initially_committed() && !memory.is_pinned() && layout.guard_size() > 0 {
        // Geometry-only and policy-less callers cannot borrow a different
        // subprocess's VM policy or silently omit this source transition.
        let hook = metadata_guard_hook.ok_or(ManageArenaError::GuardRequired)?;
        // SAFETY: the complete validated region and borrowed transition owner
        // remain live. No typed arena header or bitmap exists across callbacks.
        unsafe { (hook.function)(start.add(layout.info_size() - layout.guard_size()),
            layout.guard_size(), hook.argument) };
    }

    if !memory.initially_committed() && !metadata_already_accessible {
        let Some(hook) = metadata_commit_hook else {
            return Err(ManageArenaError::CommitRequired);
        };
        // Pinned backing commits the whole metadata span; ordinary reserved
        // backing keeps its final OS guard page inaccessible from birth.
        let commit_size = layout.info_size() - if memory.is_pinned() { 0 } else { layout.guard_size() };
        let committed = unsafe {
            (hook.function)(true, start, commit_size, null_mut(), hook.argument)
        };
        if !committed {
            return Err(ManageArenaError::CommitFailed);
        }
    }
    if !memory.initially_zero() {
        // Even pinned backing excludes the guard from metadata zeroing.
        // No typed header or bitmap extends into that final OS page.
        unsafe { core::ptr::write_bytes(start, 0, layout.info_size() - layout.guard_size()) };
    }

    // Pinned `mi_arena_initialize` invokes `_mi_os_numa_node()` only after
    // this exact metadata commit/zero preparation succeeds. A failed source
    // map or commit therefore leaves its policy-local count cache untouched.
    let numa_node = numa_node_source();

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

    Ok(arena)
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
        owner: Option<&owned::OwnedArenaAllocation>,
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
                    let outcome = owner.commit_with_outcome(
                        start.as_ptr(),
                        size.get(),
                        already_committed * ARENA_SLICE_SIZE,
                    );
                    commit_zero = outcome.is_zero();
                    outcome.succeeded()
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
                        owner.process().subprocess().vm_statistics()
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
                    owner.process().subprocess().vm_statistics()
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

    /// Source `_mi_theap_alloc`'s exclusive-arena arm:
    /// `_mi_arenas_alloc(heap, align_up(sizeof(mi_theap_t),
    /// MI_ARENA_MIN_OBJ_SIZE), true, true, heap->exclusive_arena,
    /// tld->thread_seq, tld->numa_node, &memid)`.
    ///
    /// This models a caller-selected direct parent as the source
    /// `heap->exclusive_arena` value; it neither binds nor inspects a
    /// [`Heap`]. `thread_sequence` and `numa_node` are the caller TLD's
    /// source fields and `disallow_arena_alloc` is the caller policy's
    /// `mi_option_disallow_arena_alloc` value. The `_mi_arenas_alloc_aligned`
    /// arena arm runs only when that option is off (the one-minimum-object size
    /// always lies within `mi_arena_max_object_size`). Its
    /// `mi_forall_suitable_arenas` search visits the non-null requested parent
    /// once per pass, and `mi_arena_is_suitable_ex` skips the NUMA predicate
    /// for a requested arena, so a nonnegative `numa_node` repeats the same
    /// claim once more after a first-pass miss (for example a failed commit
    /// callback). `allow_large` is true, so a pinned parent remains suitable,
    /// and the exact parent is accepted whatever its `is_exclusive` value.
    /// Requested-arena `mi_arenas_try_alloc` never reserves a fresh arena and
    /// `mi_arena_os_alloc_aligned` refuses a requested arena, so every miss
    /// returns `None` without OS memory. A subarena or foreign subprocess is
    /// rejected before any bitmap mutation.
    ///
    /// The returned reservation carries only the one-slice arena claim and
    /// `MemoryId`; source Theap construction, `theap->memid` storage,
    /// `_mi_theap_init`, and every publication/lifecycle step remain a later
    /// consuming owner.
    #[inline]
    pub(crate) fn try_reserve_exclusive_theap<'subprocess>(
        &self,
        subprocess: &'subprocess MainSubprocess,
        disallow_arena_alloc: bool,
        thread_sequence: ThreadSequence,
        numa_node: i32,
    ) -> Option<ExclusiveArenaTheapReservation<'arena, 'subprocess>> {
        let arena = self.arena();
        if !arena.parent.is_null() || !core::ptr::eq(arena.subprocess, subprocess.as_ptr()) {
            return None;
        }
        if disallow_arena_alloc {
            return None;
        }
        // SAFETY: `ArenaView` proves this exact candidate is live and
        // registry-published. The preceding parent test makes its source ID
        // the requested parent form rather than a subarena identity.
        let requested = unsafe { ArenaId::from_arena(self.arena.as_ptr()) }?;
        let passes = if numa_node < 0 { 1 } else { 2 };
        let claim = (0..passes).find_map(|_| self.try_claim_suitable_slices(
            requested,
            ARENA_MIN_OBJ_SLICES,
            true,
            thread_sequence.get(),
        ))?;
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
            let now = os::source_clock_now();
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
                let Some(subprocess) = NonNull::new(arena.subprocess) else {
                    return self.restore_failed_purge(slice_index, slice_count);
                };
                // The source purge records the attempted raw span before it
                // asks an external owner whether recommit will be needed.
                // SAFETY: a published arena retains its bound subprocess for
                // every scheduled purge of its live in-place bitmap image.
                unsafe { subprocess.as_ref() }.vm_statistics().purge(size);
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
            None => {
                let Some(subprocess) = NonNull::new(arena.subprocess) else {
                    return self.restore_failed_purge(slice_index, slice_count);
                };
                match unsafe { os::decommit_arena_range(page_size, start, size) } {
                    Ok(Some(DecommitOutcome::DoesNotNeedRecommit)) | Ok(None) => false,
                    Ok(Some(DecommitOutcome::NeedsRecommit)) => {
                        // SAFETY: this published arena retains its subprocess;
                        // source debug charges only a successful advisory span.
                        unsafe { subprocess.as_ref() }.vm_statistics().committed_decrease(size);
                        true
                    },
                    // An advisory error retains accounting while source debug
                    // protection may still require recommit before later reuse.
                    Err(_) => os::decommit_needs_recommit(),
                }
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

    /// Returns the sole production capability for a mapped abandoned page of
    /// a subprocess main Heap (the static process main Heap or a child's).
    /// It proves the main Heap still points at this arena's embedded
    /// `pages_main` image before allowing a bitmap publication to mutate its
    /// paired `abandoned_count` entry.
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
        if !heap_ref.is_subprocess_main()
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
pub(crate) mod tests {
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

    #[cfg(target_arch = "x86_64")]
    struct ExternalRefusalTrace {
        order: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
        refuse_first: std::sync::atomic::AtomicBool,
        null_metadata_zero: std::sync::atomic::AtomicBool,
        claim_zero_output: std::sync::atomic::AtomicBool,
        null_purge_zero: std::sync::atomic::AtomicBool,
        last_start: std::sync::atomic::AtomicUsize,
        last_size: std::sync::atomic::AtomicUsize,
    }

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn external_refusal_callback(
        commit: bool, start: *mut u8, size: usize, is_zero: *mut bool, argument: *mut c_void,
    ) -> bool {
        // SAFETY: the test leaks the trace and keeps its one external range
        // live for every synchronous callback and arena bitmap observation.
        let trace = unsafe { &*argument.cast::<ExternalRefusalTrace>() };
        trace.order.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |order| Some(order * 10 + if commit { 1 } else { 2 })).unwrap();
        let call = trace.calls.fetch_add(1, Ordering::AcqRel) + 1;
        trace.last_start.store(start as usize, Ordering::Release);
        trace.last_size.store(size, Ordering::Release);
        if !commit {
            trace.null_purge_zero.store(is_zero.is_null(), Ordering::Release);
            return true;
        }
        if call <= 2 {
            trace.null_metadata_zero.store(is_zero.is_null(), Ordering::Release);
        } else {
            trace.claim_zero_output.store(!is_zero.is_null(), Ordering::Release);
        }
        if !is_zero.is_null() {
            // SAFETY: the caller supplied the writable output for a claim.
            unsafe { is_zero.write(true) };
        }
        !trace.refuse_first.swap(false, Ordering::AcqRel)
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_external_callback_refusal_c_rust_trace() {
        use crate::page_map::PageMap;
        let region = Box::leak(Box::new(AlignedRegion::zeroed(ARENA_MIN_SIZE)));
        let base = region.as_ptr();
        let subprocess = MainSubprocess::test_static_owner();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(), 1024 * 1024, true, false,
        );
        let page_map = PageMap::initialize(config, 0, true)
            .expect("the isolated lookup map initializes");
        let trace = Box::leak(Box::new(ExternalRefusalTrace {
            order: std::sync::atomic::AtomicUsize::new(0),
            calls: std::sync::atomic::AtomicUsize::new(0),
            refuse_first: std::sync::atomic::AtomicBool::new(true),
            null_metadata_zero: std::sync::atomic::AtomicBool::new(false),
            claim_zero_output: std::sync::atomic::AtomicBool::new(false),
            null_purge_zero: std::sync::atomic::AtomicBool::new(false),
            last_start: std::sync::atomic::AtomicUsize::new(0),
            last_size: std::sync::atomic::AtomicUsize::new(0),
        }));
        let hook = Some(CommitHook::new(
            external_refusal_callback, (trace as *mut ExternalRefusalTrace).cast(),
        ));
        let before = subprocess.vm_statistics().snapshot();
        // SAFETY: the external range and callback trace are leaked; the
        // registry's subprocess owner remains live throughout this fixture.
        let first = unsafe { manage_external_in_place(
            &registry, base, ARENA_MIN_SIZE, config.page_size(), false, false,
            false, -1, false, hook,
        ) };
        let mut residency = 0u8;
        // SAFETY: this initialized PageMap and the external mapped page stay
        // live; `mincore` receives one writable residency byte.
        let refused = first == Err(ManageArenaError::CommitFailed)
            && registry.count() == 0
            && trace.order.load(Ordering::Acquire) == 1
            && trace.null_metadata_zero.load(Ordering::Acquire)
            && unsafe { page_map.checked_lookup(base) }.is_null()
            && unsafe { crabc_core::mm::mincore_raw(base, 4096, &mut residency) }.is_ok()
            && subprocess.vm_statistics().snapshot() == before;
        // SAFETY: the refusal published no arena or writes, so the same live
        // external range and callback retain their original ownership.
        let managed = unsafe { manage_external_in_place(
            &registry, base, ARENA_MIN_SIZE, config.page_size(), false, false,
            false, -1, false, hook,
        ) }.expect("the returned external range retries without a new map");
        // SAFETY: the returned arena ID was published by this live registry;
        // the external backing stays mapped through every bitmap observation.
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }
            .expect("the retry publishes one arena");
        let arena = view.arena();
        let memory = arena.memid;
        let owner = arena.start == base
            && memory.kind() == MemoryKind::External
            && memory.os_memory().is_some_and(|os| os.base == base && os.size == ARENA_MIN_SIZE)
            && registry.count() == 1 && trace.order.load(Ordering::Acquire) == 11;
        let info = arena.info_slices;
        // SAFETY: these are distinct in-place bitmap images and no other
        // owner accesses the isolated arena while this trace runs.
        let free = unsafe { view.slices_free() }.unwrap();
        let committed = unsafe { view.slices_committed() }.unwrap();
        let dirty = unsafe { view.slices_dirty() }.unwrap();
        let initial_bitmap = free.is_clear_range(0, info) == Some(true)
            && free.is_set_range(info, arena.slice_count - info) == Some(true)
            && committed.is_clear_range(0, arena.slice_count) == Some(true)
            && dirty.is_set_range(0, arena.slice_count) == Some(true);
        let claim = view.try_claim_suitable_slices(ArenaId::none(), 2, true, 0)
            .expect("the external arena commits one live claim");
        let index = claim.slice_index();
        let start = claim.start() as usize;
        let claimed = claim.memory_id().kind() == MemoryKind::Arena
            && claim.memory_id().arena_memory().is_some_and(|a| a.arena == managed.arena_id().as_ptr())
            && trace.order.load(Ordering::Acquire) == 111
            && trace.claim_zero_output.load(Ordering::Acquire)
            && trace.last_start.load(Ordering::Acquire) == start
            && trace.last_size.load(Ordering::Acquire) == 2 * ARENA_SLICE_SIZE
            && free.is_clear_range(index, 2) == Some(true)
            && committed.is_set_range(index, 2) == Some(true);
        assert!(claim.release());
        assert!(view.collect_scheduled_purge(config.page_size(), true));
        let after = subprocess.vm_statistics().snapshot();
        let purge_state = trace.order.load(Ordering::Acquire) == 1112
            && trace.null_purge_zero.load(Ordering::Acquire)
            && trace.last_start.load(Ordering::Acquire) == start
            && trace.last_size.load(Ordering::Acquire) == 2 * ARENA_SLICE_SIZE
            && committed.is_clear_range(index, 2) == Some(true)
            && after.purge_calls == before.purge_calls + 1
            && after.purged == before.purged + (2 * ARENA_SLICE_SIZE) as i64;
        residency = 0;
        // SAFETY: the lookup map and external base remain live after the
        // claim's bitmap release; `mincore` writes one residency byte.
        let released = free.is_set_range(index, 2) == Some(true)
            && unsafe { page_map.checked_lookup(start as *const u8) }.is_null()
            && unsafe { crabc_core::mm::mincore_raw(base, 4096, &mut residency) }.is_ok()
            && after.mmap_calls == before.mmap_calls
            && after.reserved_current == before.reserved_current;
        for (field, value) in [
            ("refused", usize::from(refused)), ("owner", usize::from(owner)),
            ("initial_bitmap", usize::from(initial_bitmap)),
            ("claimed", usize::from(claimed)), ("purge_state", usize::from(purge_state)),
            ("released_external_live", usize::from(released)),
            ("callback_order", trace.order.load(Ordering::Acquire)),
            ("callback_count", trace.calls.load(Ordering::Acquire)),
        ] {
            std::println!("m2.external_refusal.{field}={value}");
        }
        assert!(refused && owner && initial_bitmap && claimed && purge_state && released);
        assert_eq!(trace.order.load(Ordering::Acquire), 1112);
        assert_eq!(trace.calls.load(Ordering::Acquire), 4);
    }

    /// Runs the external-arena half of a fresh on-demand page's first prefix
    /// while the source callback can refuse it. The returned relations are
    /// consumed by the paired OS publication oracle and by the focused test.
    pub(crate) fn on_demand_arena_prefix_callback_relations() -> [bool; 4] {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let subprocess = MainSubprocess::test_static_owner();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let script = CommitScript::new(false);
        let managed = unsafe {
            manage_external_in_place(
                &registry, region.as_ptr(), ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(), false, false, false, -1, true,
                Some(CommitHook::new(
                    scripted_commit, (&script as *const CommitScript).cast_mut().cast(),
                )),
            )
        }.unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let claim = view.try_claim_suitable_slices(managed.arena_id(), 8, false, 1)
            .expect("reserved on-demand arena span");
        assert!(claim.page_metadata().is_some());
        let calls_before = script.calls.load(std::sync::atomic::Ordering::Relaxed);
        let stats_before = subprocess.vm_statistics().snapshot();
        script.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = !claim.commit_initial_page_prefix(ARENA_SLICE_SIZE);
        let callback_failed = failed
            && script.calls.load(std::sync::atomic::Ordering::Relaxed) == calls_before + 1
            && !claim.memory_id().initially_committed();
        let index = claim.slice_index();
        let free = unsafe { view.slices_free() }.unwrap();
        let mapping_retained = free.is_clear_range(index, 8) == Some(true)
            && region.as_ptr() == view.arena().start;
        let callback_statistics = subprocess.vm_statistics().snapshot() == stats_before;
        assert!(claim.release());
        script.fail.store(false, std::sync::atomic::Ordering::Relaxed);
        let retry = view.try_claim_suitable_slices(managed.arena_id(), 8, false, 1)
            .expect("released span is reusable");
        let recovered = retry.slice_index() == index
            && retry.commit_initial_page_prefix(ARENA_SLICE_SIZE);
        assert!(retry.release());
        [callback_failed, mapping_retained, callback_statistics, recovered]
    }

    #[test]
    fn on_demand_arena_prefix_callback_failure_retains_external_owner_and_reuses_span() {
        assert_eq!(on_demand_arena_prefix_callback_relations(), [true; 4]);
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
        // Encoded free lists and padding retain the two source Page keys;
        // their larger image reserves one additional metadata slice.
        let keyed = crate::config::PAGE_KEY_COUNT == 2;
        assert_eq!(size_of::<Page>(), if keyed { 144 } else { 128 });
        assert_eq!(size_of::<Arena>(), 648);
        assert_eq!(page_metadata_slice_count(), Some(if keyed { 9 } else { 8 }));

        let pages = ArenaPagesLayout::for_slice_count(BCHUNK_BITS).unwrap();
        assert_eq!(pages.slice_count(), BCHUNK_BITS);
        assert_eq!(pages.bitmap_base(), 512);
        assert_eq!(pages.bitmap_layout().byte_size(), 192);
        assert_eq!(pages.byte_size(), 12_416);

        let info = ArenaInfoLayout::for_slice_count(BCHUNK_BITS, 4096).unwrap();
        assert_eq!(info.arena_offset(), if keyed { 589_824 } else { 524_288 });
        assert_eq!(info.bitmap_base(), if keyed { 590_528 } else { 524_992 });
        assert_eq!(info.free_bitmap().byte_size(), 512);
        assert_eq!(info.ordinary_bitmap().byte_size(), 192);
        assert_eq!(info.bitmaps_end(), if keyed { 603_520 } else { 537_984 });
        assert_eq!(info.guard_size(), if crate::config::SECURE_LEVEL > 0 { 4096 } else { 0 });
        assert_eq!(info.info_slices(), if keyed { 10 } else { 9 });
        assert_eq!(info.info_size(), if keyed { 655_360 } else { 589_824 });
    }

    #[test]
    fn secure_info_layout_reserves_the_os_guard_at_the_bitmap_slice_boundary() {
        let layout = ArenaInfoLayout::for_slice_count(13 * BCHUNK_BITS, 4096).unwrap();
        let keyed = crate::config::PAGE_KEY_COUNT == 2;
        let secure = crate::config::SECURE_LEVEL > 0;
        // The source aligns the complete bitmap image to an OS page before
        // adding its guard. Page keys shift that image by a metadata slice,
        // so the same guard crosses the next slice boundary in both layouts.
        assert_eq!(size_of::<Page>(), if keyed { 144 } else { 128 });
        assert_eq!(page_metadata_slice_count(), Some(if keyed { 9 } else { 8 }));
        assert_eq!(layout.bitmap_base(), if keyed { 590_528 } else { 524_992 });
        assert_eq!(layout.ordinary_bitmap().byte_size(), 960);
        assert_eq!(layout.free_bitmap().byte_size(), 1280);
        assert_eq!(layout.bitmaps_end(), if keyed { 654_208 } else { 588_672 });
        assert_eq!(layout.guard_size(), if secure { 4096 } else { 0 });
        assert_eq!(layout.info_slices(), match (keyed, secure) {
            (false, false) => 9, (false, true) | (true, false) => 10, (true, true) => 11,
        });
        assert_eq!(layout.info_size(), match (keyed, secure) {
            (false, false) => 589_824, (false, true) | (true, false) => 655_360,
            (true, true) => 720_896,
        });
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
    fn public_arena_contains_excludes_end_and_other_registered_parent() {
        let mut first_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let mut second_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let subprocess = MainSubprocess::test_static_owner();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        // SAFETY: both writable external regions and their subprocess owner
        // remain live until all arena identity and range observations finish.
        let first = unsafe { manage_external_in_place(
            &registry, first_region.as_ptr(), ARENA_MIN_SIZE, PageSize::new(4096).unwrap(),
            true, false, true, -1, true, None,
        ) }.unwrap();
        let second = unsafe { manage_external_in_place(
            &registry, second_region.as_ptr(), ARENA_MIN_SIZE, PageSize::new(4096).unwrap(),
            true, false, true, -1, true, None,
        ) }.unwrap();
        let first_id = first.arena_id();
        let second_id = second.arena_id();
        let start = first_region.as_ptr();
        let end = (start as usize + ARENA_MIN_SIZE) as *const u8;
        // SAFETY: both IDs and the registry remain live and published.
        unsafe {
            assert!(first_id.contains_in(&registry, start));
            assert!(first_id.contains_in(&registry, start.add(ARENA_MIN_SIZE - 1)));
            assert!(!first_id.contains_in(&registry, end));
            assert!(!first_id.contains_in(&registry, second_region.as_ptr()));
            assert!(second_id.contains_in(&registry, second_region.as_ptr()));
            assert!(!ArenaId::none().contains_in(&registry, start));
            assert!(!first_id.contains_in(&registry, core::ptr::null()));
        }
    }

    #[cfg(all(target_arch = "x86_64", any(feature = "mi-secure-1", feature = "mi-secure-2")))]
    #[test]
    fn secure_committed_metadata_without_a_guard_capability_retains_unpublished_bytes() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let base = region.as_ptr();
        let registry = ArenaRegistry::new(MainSubprocess::test_static_owner().as_ptr());
        // SAFETY: this region owns its exclusive live, writable first byte.
        unsafe { base.write(0xa5) };
        let result = unsafe { manage_external_in_place(
            &registry, base, ARENA_MIN_SIZE, PageSize::new(4096).unwrap(),
            true, false, false, -1, false, None,
        ) };
        let preserved = unsafe { base.read() };
        std::println!("secure.info.missing_guard={}:{}:{}",
            result.is_err(), registry.count(), preserved);
        assert!(matches!(result, Err(ManageArenaError::GuardRequired)));
        assert_eq!(registry.count(), 0);
        assert_eq!(preserved, 0xa5);
    }

    #[test]
    fn in_place_initialization_marks_only_usable_slices_free_and_preserves_flags() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let subprocess = MainSubprocess::test_static_owner();
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
        assert!(managed.is_complete());
        assert_eq!(managed.total_size(), ARENA_MIN_SIZE);
        assert_eq!(managed.managed_size(), ARENA_MIN_SIZE);
        assert_eq!(registry.count(), 1);
        assert_eq!(
            subprocess.arena_statistics().snapshot().arena_count,
            1,
            "src/arena.c counts only a newly published high-water arena slot",
        );

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
    fn unbound_registry_refuses_management_before_any_source_publication() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(null_mut());
        let error = unsafe {
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
        .unwrap_err();

        assert_eq!(error, ManageArenaError::InvalidRegion);
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn reused_null_registry_slot_does_not_repeat_the_high_water_event() {
        let subprocess = MainSubprocess::test_static_owner();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let mut first_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let first = unsafe {
            manage_external_in_place(
                &registry,
                first_region.as_ptr(),
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
        assert!(first.is_complete());
        assert_eq!(subprocess.arena_statistics().snapshot().arena_count, 1);

        // Model the source registry state after an arena slot becomes NULL.
        // The original external region remains live and is never inspected
        // after this controlled test transition.
        registry.arenas[0].store(null_mut(), Ordering::Release);
        let mut replacement_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let replacement = unsafe {
            manage_external_in_place(
                &registry,
                replacement_region.as_ptr(),
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

        assert!(replacement.is_complete());
        assert_eq!(registry.count(), 1);
        assert_eq!(
            subprocess.arena_statistics().snapshot().arena_count,
            1,
            "pinned src/arena.c returns from a reused NULL slot before arena_count",
        );
    }

    #[test]
    fn failed_arena_preparation_never_records_a_high_water_publication() {
        let subprocess = MainSubprocess::test_static_owner();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let error = unsafe {
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
                None,
            )
        }
        .unwrap_err();

        assert_eq!(error, ManageArenaError::CommitRequired);
        assert_eq!(registry.count(), 0);
        assert_eq!(
            subprocess.arena_statistics().snapshot().arena_count,
            0,
            "pinned src/arena.c reaches arena_count only after successful pointer publication",
        );
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
                .try_reserve_exclusive_theap(foreign, false, sequence, -1)
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
            .try_reserve_exclusive_theap(selected, false, sequence, -1)
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
            .try_reserve_exclusive_theap(selected, false, sequence, -1)
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
                .try_reserve_exclusive_theap(selected, false, sequence, -1)
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
                    .try_reserve_exclusive_theap(foreign, false, thread_sequence, -1)
                    .is_none(),
                "a foreign subprocess cannot consume the selected parent before prefix construction"
            );
            assert_eq!(
                selected_free.is_set_range(first_slice, 1),
                Some(true),
                "foreign refusal leaves the selected parent bitmap untouched"
            );

            let mut disallowing = crate::config::VmOptions::uninitialized();
            disallowing.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
            disallowing.set(crate::config::VmOption::DisallowArenaAlloc, 1);
            let disallowing = crate::os::VmPolicy::new(disallowing).unwrap();
            assert!(matches!(
                main.reserve_requested_parent_arena_theap(&selected_view, &disallowing),
                Err(RequestedParentArenaTheapError::TheapArenaUnavailable)
            ), "the source disallow_arena_alloc gate refuses the exclusive-arena Theap");
            assert_eq!(selected_free.is_set_range(first_slice, 1), Some(true));
            let mut defaults = crate::config::VmOptions::uninitialized();
            defaults.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
            let defaults = crate::os::VmPolicy::new(defaults).unwrap();
            let reservation = main
                .reserve_requested_parent_arena_theap(&selected_view, &defaults)
                .ok()
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
                .try_reserve_exclusive_theap(selected, false, thread_sequence, -1)
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
                .try_reserve_exclusive_theap(selected, false, thread_sequence, -1)
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
                .try_reserve_exclusive_theap(selected, false, thread_sequence, -1)
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

    /// Source `_mi_theap_alloc`'s exclusive-arena arm: `disallow_arena_alloc`
    /// refuses before any claim, and a nonnegative TLD NUMA node repeats the
    /// requested parent once after a first-pass miss (here a failed commit).
    #[test]
    fn exclusive_theap_reservation_honors_disallow_and_the_second_numa_pass() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let subprocess = MainSubprocess::test_static_owner();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
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
                true,
                Some(CommitHook::new(
                    scripted_commit,
                    (&script as *const CommitScript).cast_mut().cast(),
                )),
            )
        }
        .unwrap();
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        let index = view.arena().info_slices;
        let free = unsafe { view.slices_free() }.unwrap();
        let sequence = ThreadSequence::from_previous_total_count(0);
        // Managing the region already committed its metadata slices.
        let managed_calls = script.calls.load(std::sync::atomic::Ordering::Relaxed);
        let calls = || script.calls.load(std::sync::atomic::Ordering::Relaxed) - managed_calls;

        assert!(view.try_reserve_exclusive_theap(subprocess, true, sequence, 0).is_none());
        assert_eq!(calls(), 0, "disallow_arena_alloc refuses before the commit callback");
        assert_eq!(free.is_set_range(index, 1), Some(true));

        script.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(view.try_reserve_exclusive_theap(subprocess, false, sequence, -1).is_none());
        assert_eq!(calls(), 1, "a negative NUMA node makes one requested-arena pass");
        assert!(view.try_reserve_exclusive_theap(subprocess, false, sequence, 0).is_none());
        assert_eq!(calls(), 3, "a nonnegative NUMA node repeats the requested parent");
        assert_eq!(free.is_set_range(index, 1), Some(true));

        // Fail only the first-pass commit: the second pass then succeeds.
        struct FailFirst { calls: std::sync::atomic::AtomicUsize, armed: std::sync::atomic::AtomicBool }
        unsafe extern "C" fn fail_first(commit: bool, _start: *mut u8, _size: usize,
            is_zero: *mut bool, argument: *mut c_void) -> bool {
            let script = unsafe { &*argument.cast::<FailFirst>() };
            let call = script.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if !commit || (call == 0 && script.armed.load(std::sync::atomic::Ordering::Relaxed)) {
                return false;
            }
            if !is_zero.is_null() { unsafe { is_zero.write(false) }; }
            true
        }
        let mut second_region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let first_fail = FailFirst { calls: std::sync::atomic::AtomicUsize::new(0),
            armed: std::sync::atomic::AtomicBool::new(false) };
        let second = unsafe {
            manage_external_in_place(&registry, second_region.as_ptr(), ARENA_MIN_SIZE,
                PageSize::new(4096).unwrap(), false, false, true, -1, true,
                Some(CommitHook::new(fail_first,
                    (&first_fail as *const FailFirst).cast_mut().cast())))
        }
        .unwrap();
        let second_view = unsafe { ArenaView::from_ptr(second.arena_id().as_ptr()) }.unwrap();
        first_fail.calls.store(0, std::sync::atomic::Ordering::Relaxed);
        first_fail.armed.store(true, std::sync::atomic::Ordering::Relaxed);
        let reservation = second_view
            .try_reserve_exclusive_theap(subprocess, false, sequence, 3)
            .expect("the second requested-arena pass commits after the first fails");
        assert_eq!(first_fail.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert!(reservation.memory_id().initially_committed());
        let start = reservation.start().addr();
        let selected_slice = reservation.slice_index();
        let (area, length) = unsafe { second.arena_id().area() }.unwrap();
        assert!(start >= area.addr() && start - area.addr() < length);
        assert_eq!(reservation.memory_id().arena_memory().unwrap().slice_count as usize,
            ARENA_MIN_OBJ_SLICES);
        assert!(matches!(reservation.release(), Ok(true)));
        assert_eq!(unsafe { second_view.slices_free() }.unwrap()
            .is_set_range(selected_slice, 1), Some(true));
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
    fn clock_failure_uses_source_fallback_for_arena_purge_schedule_and_collection() {
        let fault = crate::os::fault::install(crate::os::fault::Plan::at(
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
        assert_eq!(fault.observed(), 1);
        assert_eq!(purge.is_set_range(slice_index, 1), Some(true));
        assert_ne!(view.arena().purge_expire.load(core::sync::atomic::Ordering::Acquire), 0);

        // An already expired range must still be collected when the preferred
        // clock fails again. The source low-resolution clock is nonnegative.
        view.arena().purge_expire.store(-1, core::sync::atomic::Ordering::Release);
        fault.set(crate::os::fault::Plan::at(
            crate::os::fault::Point::Clock, 1, crabc_core::Errno::NOMEM,
        ));
        assert!(view.collect_scheduled_purge(PageSize::new(4096).unwrap(), false));
        assert_eq!(fault.observed(), 1);
        assert_eq!(purge.is_clear_range(slice_index, 1), Some(true));
        assert_eq!(free.is_set_range(slice_index, 1), Some(true));
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

    /// A rejected fresh arena remains absent from the registry even when its
    /// failed cleanup leaves raw VM mapped beside a later healthy claim.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_fresh_arena_dual_fault_c_rust_trace() {
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        use crate::os::{VmPolicy, VmProcess, fault};
        use core::ffi::{c_char, c_void, CStr};
        use core::sync::atomic::{AtomicPtr, Ordering};

        static ENVIRONMENT: AtomicPtr<*const c_char> = AtomicPtr::new(core::ptr::null_mut());

        unsafe fn environment() -> *const *const c_char {
            ENVIRONMENT.load(Ordering::Acquire).cast_const()
        }

        unsafe extern "C" fn default_output(_message: *const c_char) {}

        struct Warnings {
            fragments: std::sync::Mutex<std::vec::Vec<(std::vec::Vec<u8>, i64, i64, i64)>>,
            subprocess: *const crate::subproc::SubprocessIdentity,
        }

        unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
            // SAFETY: registration is synchronous and the stack capture and
            // subprocess identity stay live until callback removal below.
            let warnings = unsafe { &*(argument as *const Warnings) };
            let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
            if bytes.is_empty() { return; }
            let snapshot = unsafe { &*warnings.subprocess }.vm_statistics().snapshot();
            warnings.fragments.lock().unwrap().push((bytes.to_vec(),
                snapshot.reserved_current, snapshot.committed_current, snapshot.commit_calls));
        }

        let entries = Box::leak(Box::new([
            b"mimalloc_arena_reserve=32M\0".as_ptr().cast(),
            b"mimalloc_arena_eager_commit=0\0".as_ptr().cast(),
            b"mimalloc_arena_is_numa_local=0\0".as_ptr().cast(),
            b"mimalloc_allow_large_os_pages=0\0".as_ptr().cast(),
            b"mimalloc_allow_thp=0\0".as_ptr().cast(),
            b"mimalloc_purge_delay=-1\0".as_ptr().cast(),
            b"mimalloc_show_errors=1\0".as_ptr().cast(),
            b"mimalloc_max_warnings=100\0".as_ptr().cast(),
            core::ptr::null(),
        ]));
        ENVIRONMENT.store(entries.as_mut_ptr(), Ordering::Release);
        let output = Box::leak(Box::new(OutputOwner::new(default_output)));
        // SAFETY: the environment image and output live for the entire
        // process policy and every synchronous diagnostic in this fixture.
        unsafe { output.initialize_source_options(environment) };
        let subprocess = MainSubprocess::test_static_owner();
        let warnings = Warnings {
            fragments: std::sync::Mutex::new(std::vec::Vec::new()),
            subprocess: subprocess.identity(),
        };
        // SAFETY: the callback is removed before the stack capture expires.
        unsafe { output.register_output(Some(capture as OutputCallback),
            &warnings as *const Warnings as *mut c_void) };
        let policy = Box::leak(Box::new(
            unsafe { VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(), 1 << 20, true, false,
        );
        let backing = subprocess.arena_backing();
        let search = ArenaSearch { heap_sequence: 0, heap_count: 1,
            thread_sequence: 0, numa_node: -1, requested: ArenaId::none(),
            allow_pinned: true };
        let before_vm = subprocess.vm_statistics().snapshot();
        let before_arena = subprocess.arena_statistics().snapshot();
        let registry_before = backing.registry().count();
        warnings.fragments.lock().unwrap().clear();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit, 1, fault::Point::Unmap, 1, crabc_core::Errno::NOMEM,
        ));
        let protection = fault.capture_protection_ranges();
        let unmaps = fault.capture_unmap_ranges();
        // SAFETY: this isolated subprocess owns its sole arena backing and
        // no concurrent claim, metadata reader, or destroy operation runs.
        let rejected = unsafe { backing.try_allocate_slices(
            process, config, search, 1, ARENA_SLICE_SIZE, true,
        ) };
        let refused = rejected.is_none() && fault.observed() == 1
            && fault.secondary_observed() == 1;
        let cleanup_calls = fault.secondary_observed();
        let no_memory_id = rejected.is_none();
        let (protect_attempts, protect_count) = protection.attempts().expect("bounded metadata commit");
        let (protected_address, metadata_size, protection_flags) = protect_attempts[0];
        drop(protection);
        let (unmap_attempts, unmap_count) = unmaps.all().expect("bounded aligned reservation cleanup");
        let (escaped_address, escaped_size) = unmap_attempts[unmap_count - 1];
        drop(unmaps);
        let metadata_exact = protected_address == escaped_address && protection_flags == 3;
        let failed_registry = backing.registry().count();
        let after_failed_vm = subprocess.vm_statistics().snapshot();
        let after_failed_arena = subprocess.arena_statistics().snapshot();
        let mut residency = 0u8;
        // SAFETY: the selected failed unmap leaves its exact page-aligned
        // mapping live; mincore writes only the supplied residency byte.
        let escaped_live = unsafe { crabc_core::mm::mincore_raw(
            escaped_address as *mut u8, 4096, &mut residency,
        ) }.is_ok();
        fault.set(fault::Plan::disabled());

        // SAFETY: the same isolated arena backing and process pair remain
        // live; the failed map has no published registry or bitmap owner.
        let claim = unsafe { backing.try_allocate_slices(
            process, config, search, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("later fresh arena supplies one committed slice");
        let memory = claim.memory_id();
        let arena_memory = memory.arena_memory().unwrap();
        // SAFETY: the new claim pins its newly published arena while this
        // test inspects the source bitmap and MemoryId fields.
        let view = unsafe { ArenaView::from_ptr(arena_memory.arena) }.unwrap();
        let arena = view.arena();
        let recovery_memory = memory.kind() == MemoryKind::Arena
            && arena.memid.kind() == MemoryKind::Os
            && arena.memid.os_base().map(|base| base.value()) == Some(arena.start as usize)
            && arena.memid.size() == Some(escaped_size)
            && !arena.memid.initially_committed();
        let recovery_registry = backing.registry().count();
        let index = claim.slice_index();
        let free = unsafe { view.slices_free() }.unwrap();
        let committed = unsafe { view.slices_committed() }.unwrap();
        let recovery_bitmap_claimed = free.is_clear_range(index, 1) == Some(true)
            && committed.is_set_range(index, 1) == Some(true);
        // SAFETY: the prior map is escaped, still live, and has no arena or
        // claim capability; the healthy claim owns a disjoint arena span.
        let prior_live_during_recovery = unsafe { crabc_core::mm::mincore_raw(
            escaped_address as *mut u8, 4096, &mut residency,
        ) }.is_ok();
        let recovery_vm = subprocess.vm_statistics().snapshot();
        let recovery_arena = subprocess.arena_statistics().snapshot();
        let warnings_before_release = warnings.fragments.lock().unwrap().len();
        let claim_released = claim.release()
            && free.is_set_range(index, 1) == Some(true)
            && backing.registry().count() == recovery_registry;
        // SAFETY: release returns only the slice. The registered arena and
        // earlier escaped mapping remain mapped and independently owned.
        let recovery_mapping_live = unsafe { crabc_core::mm::mincore_raw(
            arena.start, 4096, &mut residency,
        ) }.is_ok();
        let prior_live_after_release = unsafe { crabc_core::mm::mincore_raw(
            escaped_address as *mut u8, 4096, &mut residency,
        ) }.is_ok();
        let release_warnings = warnings.fragments.lock().unwrap().len() - warnings_before_release;
        let before_raw_vm = subprocess.vm_statistics().snapshot();
        // SAFETY: the escaped failed reservation has no registry, bitmap, or
        // claim owner; this is its exact retained raw mapping range.
        let raw_cleanup = unsafe { crabc_core::mm::munmap_raw(
            escaped_address as *mut u8, escaped_size,
        ) }.is_ok();
        // SAFETY: raw cleanup completed; no reference into this abandoned
        // range survives and mincore is a read-only kernel query.
        let raw_gone = unsafe { crabc_core::mm::mincore_raw(
            escaped_address as *mut u8, 4096, &mut residency,
        ) }.is_err();
        let raw_no_stats = subprocess.vm_statistics().snapshot() == before_raw_vm;

        let fragments = warnings.fragments.lock().unwrap();
        let mut warning_fragments = 0usize;
        let mut warning_bodies = 0usize;
        let mut warning_order = 0usize;
        let mut fallback_warning_before_stats = true;
        let mut warning_commit_before_stats = false;
        let mut warning_meta_before_stats = false;
        let mut warning_free_before_stats = false;
        for (bytes, reserved, committed_bytes, commit_calls) in fragments.iter() {
            if bytes.starts_with(b"mimalloc: warning: thread 0x") {
                warning_fragments += 1;
                continue;
            }
            warning_bodies += 1;
            let category = if bytes.starts_with(b"cannot commit OS memory") { 1 }
                else if bytes.starts_with(b"unable to commit meta-data for OS memory") { 2 }
                else if bytes.starts_with(b"unable to free OS memory") { 3 }
                else if bytes.starts_with(b"unable to allocate aligned OS memory directly") { 4 }
                else { 0 };
            warning_order = warning_order * 10 + category;
            if category == 4 {
                fallback_warning_before_stats = *reserved == before_vm.reserved_current + escaped_size as i64
                    && *committed_bytes == before_vm.committed_current
                    && *commit_calls == before_vm.commit_calls;
            }
            if category == 1 {
                warning_commit_before_stats = *reserved == before_vm.reserved_current + escaped_size as i64
                    && *committed_bytes == before_vm.committed_current
                    && *commit_calls == before_vm.commit_calls + 1;
            }
            if category == 2 {
                warning_meta_before_stats = *reserved == before_vm.reserved_current + escaped_size as i64
                    && *committed_bytes == before_vm.committed_current
                    && *commit_calls == before_vm.commit_calls + 1;
            }
            if category == 3 {
                warning_free_before_stats = *reserved == before_vm.reserved_current + escaped_size as i64
                    && *committed_bytes == before_vm.committed_current
                    && *commit_calls == before_vm.commit_calls + 1;
            }
        }
        drop(fragments);
        for (field, value) in [
            ("refused", i64::from(refused)),
            ("no_memory_id", i64::from(no_memory_id)),
            ("registry_before", registry_before as i64),
            ("failed_registry", failed_registry as i64),
            ("metadata_calls", protect_count as i64),
            ("metadata_size", metadata_size as i64),
            ("metadata_exact", i64::from(metadata_exact)),
            ("cleanup_calls", cleanup_calls as i64),
            ("escaped_size", escaped_size as i64),
            ("escaped_aligned", i64::from(escaped_address % ARENA_ALIGNMENT == 0)),
            ("escaped_live", i64::from(escaped_live)),
            ("warning_fragments", warning_fragments as i64),
            ("warning_bodies", warning_bodies as i64),
            ("warning_order", warning_order as i64),
            ("fallback_warning_before_stats", i64::from(fallback_warning_before_stats)),
            ("warning_commit_before_stats", i64::from(warning_commit_before_stats)),
            ("warning_meta_before_stats", i64::from(warning_meta_before_stats)),
            ("warning_free_before_stats", i64::from(warning_free_before_stats)),
            ("reserved_after_failure", after_failed_vm.reserved_current - before_vm.reserved_current),
            ("committed_after_failure", after_failed_vm.committed_current - before_vm.committed_current),
            ("mmap_after_failure", after_failed_vm.mmap_calls - before_vm.mmap_calls),
            ("commit_after_failure", after_failed_vm.commit_calls - before_vm.commit_calls),
            ("arena_after_failure", after_failed_arena.arena_count - before_arena.arena_count),
            ("recovery_memory", i64::from(recovery_memory)),
            ("recovery_slice_index", index as i64),
            ("recovery_slice_count", arena_memory.slice_count as i64),
            ("recovery_initially_committed", i64::from(memory.initially_committed())),
            ("recovery_initially_zero", i64::from(memory.initially_zero())),
            ("recovery_is_pinned", i64::from(memory.is_pinned())),
            ("recovery_arena_info_slices", arena.info_slices as i64),
            ("recovery_arena_size", arena.memid.size().unwrap() as i64),
            ("recovery_registry", recovery_registry as i64),
            ("recovery_bitmap_claimed", i64::from(recovery_bitmap_claimed)),
            ("prior_live_during_recovery", i64::from(prior_live_during_recovery)),
            ("recovery_reserved_delta", recovery_vm.reserved_current - before_vm.reserved_current),
            ("recovery_committed_delta", recovery_vm.committed_current - before_vm.committed_current),
            ("recovery_mmap_delta", recovery_vm.mmap_calls - before_vm.mmap_calls),
            ("recovery_commit_delta", recovery_vm.commit_calls - before_vm.commit_calls),
            ("recovery_arena_delta", recovery_arena.arena_count - before_arena.arena_count),
            ("claim_released", i64::from(claim_released)),
            ("recovery_mapping_live", i64::from(recovery_mapping_live)),
            ("prior_live_after_release", i64::from(prior_live_after_release)),
            ("release_warnings", release_warnings as i64),
            ("raw_cleanup", i64::from(raw_cleanup)),
            ("raw_gone", i64::from(raw_gone)),
            ("raw_no_stats", i64::from(raw_no_stats)),
        ] {
            std::println!("{field}={value}");
        }
        assert!(refused && no_memory_id && metadata_exact && escaped_live
            && warning_commit_before_stats && warning_meta_before_stats
            && warning_free_before_stats
            && recovery_memory && recovery_bitmap_claimed && prior_live_during_recovery
            && claim_released && recovery_mapping_live && prior_live_after_release
            && raw_cleanup && raw_gone && raw_no_stats);
        drop(fault);
        // SAFETY: no stack-backed warning capture remains available after
        // callback removal; the healthy arena remains process-lived.
        unsafe { output.register_output(None, core::ptr::null_mut()) };
    }

    /// A failed delayed decommit consumes the scheduled visit while the
    /// committed slice and neighboring live claim retain their owners.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_delayed_purge_failure_c_rust_trace() {
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        use crate::os::{VmPolicy, VmProcess, fault};
        use core::ffi::{c_char, c_void, CStr};
        use core::sync::atomic::{AtomicPtr, Ordering};

        static ENVIRONMENT: AtomicPtr<*const c_char> = AtomicPtr::new(core::ptr::null_mut());
        unsafe fn environment() -> *const *const c_char {
            ENVIRONMENT.load(Ordering::Acquire).cast_const()
        }
        unsafe extern "C" fn default_output(_message: *const c_char) {}
        struct Warnings {
            bodies: std::sync::Mutex<std::vec::Vec<(std::vec::Vec<u8>, i64, i64, i64)>>,
            subprocess: *const crate::subproc::SubprocessIdentity,
        }
        unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
            // SAFETY: callback registration remains live during every
            // synchronous diagnostic, and the stack capture is removed below.
            let warnings = unsafe { &*(argument as *const Warnings) };
            let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
            if !bytes.starts_with(b"cannot decommit OS memory") { return; }
            let vm = unsafe { &*warnings.subprocess }.vm_statistics().snapshot();
            let arena = unsafe { &*warnings.subprocess }.arena_statistics().snapshot();
            warnings.bodies.lock().unwrap().push((bytes.to_vec(),
                vm.purge_calls, vm.purged, arena.arena_purges));
        }

        let entries = Box::leak(Box::new([
            b"mimalloc_arena_reserve=32M\0".as_ptr().cast(),
            b"mimalloc_arena_eager_commit=0\0".as_ptr().cast(),
            b"mimalloc_arena_is_numa_local=0\0".as_ptr().cast(),
            b"mimalloc_allow_large_os_pages=0\0".as_ptr().cast(),
            b"mimalloc_allow_thp=0\0".as_ptr().cast(),
            b"mimalloc_purge_delay=100000\0".as_ptr().cast(),
            b"mimalloc_arena_purge_mult=1\0".as_ptr().cast(),
            b"mimalloc_purge_decommits=1\0".as_ptr().cast(),
            b"mimalloc_show_errors=1\0".as_ptr().cast(),
            b"mimalloc_max_warnings=100\0".as_ptr().cast(),
            core::ptr::null(),
        ]));
        ENVIRONMENT.store(entries.as_mut_ptr(), Ordering::Release);
        let output = Box::leak(Box::new(OutputOwner::new(default_output)));
        // SAFETY: the environment image and output live through this process
        // policy and every synchronous callback below.
        unsafe { output.initialize_source_options(environment) };
        let subprocess = MainSubprocess::test_static_owner();
        let warnings = Warnings {
            bodies: std::sync::Mutex::new(std::vec::Vec::new()),
            subprocess: subprocess.identity(),
        };
        // SAFETY: callback removal precedes the stack capture's end.
        unsafe { output.register_output(Some(capture as OutputCallback),
            &warnings as *const Warnings as *mut c_void) };
        // SAFETY: this fresh process owner has completed option initialization
        // before policy selection, and the output owner remains process-lived.
        let policy = Box::leak(Box::new(
            unsafe { VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(), 1 << 20, true, false,
        );
        let backing = subprocess.arena_backing();
        let search = ArenaSearch { heap_sequence: 0, heap_count: 1,
            thread_sequence: 0, numa_node: -1, requested: ArenaId::none(),
            allow_pinned: true };
        let fault = fault::install(fault::Plan::disabled());
        // SAFETY: the isolated backing is bound to this process and has no
        // concurrent registry publisher, claims, or purge visitor.
        let released = unsafe { backing.try_allocate_slices(
            process, config, search, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("first committed arena slice");
        let memory = released.memory_id();
        let arena_id = memory.arena_memory().unwrap().arena;
        // SAFETY: the first claim pins this published parent arena.
        let requested = ArenaSearch { requested: unsafe { ArenaId::from_arena(arena_id) }.unwrap(), ..search };
        let survivor = unsafe { backing.try_allocate_slices(
            process, config, requested, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("neighboring live slice");
        let index = released.slice_index();
        let survivor_index = survivor.slice_index();
        let released_address = released.start();
        let survivor_address = survivor.start();
        // SAFETY: both claims pin their published arena and its bitmap storage.
        let view = unsafe { ArenaView::from_ptr(arena_id) }.unwrap();
        let arena = view.arena();
        let free = unsafe { view.slices_free() }.unwrap();
        let committed = unsafe { view.slices_committed() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        let mut residency = 0u8;
        // SAFETY: the arena and both claimed slices are live page-aligned mappings.
        let setup = backing.registry().count() == 1
            && memory.kind() == MemoryKind::Arena
            && arena.memid.kind() == MemoryKind::Os
            && index == 9 && survivor_index == 10
            && unsafe { crabc_core::mm::mincore_raw(arena.start, 4096, &mut residency) }.is_ok()
            && unsafe { crabc_core::mm::mincore_raw(released_address, 4096, &mut residency) }.is_ok()
            && unsafe { crabc_core::mm::mincore_raw(survivor_address, 4096, &mut residency) }.is_ok();
        let before_vm = subprocess.vm_statistics().snapshot();
        let before_arena = subprocess.arena_statistics().snapshot();
        assert!(released.release());
        let pending_purge = purge.is_set_range(index, 1) == Some(true);
        let pending_committed = committed.is_set_range(index, 1) == Some(true);
        let pending_free = free.is_set_range(index, 1) == Some(true);
        let pending_survivor = free.is_clear_range(survivor_index, 1) == Some(true);
        let pending_expiry = arena.purge_expire.load(Ordering::Relaxed) > 0;
        let pending = pending_purge && pending_committed && pending_free
            && pending_survivor && pending_expiry;
        let pending_no_advice = warnings.bodies.lock().unwrap().is_empty()
            && subprocess.vm_statistics().snapshot().purge_calls == before_vm.purge_calls;
        fault.set(fault::Plan::at(fault::Point::Decommit, 1, crabc_core::Errno::IO));
        let advice = fault.capture_advice_range();
        // SAFETY: the released slice is still held by this arena; there is
        // no concurrent claim or purge visitor during forced collection.
        assert!(unsafe { backing.collect_purge(process, config, true, true, 0) });
        let after_first_vm = subprocess.vm_statistics().snapshot();
        let after_first_arena = subprocess.arena_statistics().snapshot();
        let consumed = purge.is_clear_range(index, 1) == Some(true)
            && committed.is_set_range(index, 1) == Some(true)
            && free.is_set_range(index, 1) == Some(true)
            && free.is_clear_range(survivor_index, 1) == Some(true)
            && arena.purge_expire.load(Ordering::Relaxed) == 0;
        let first_calls = advice.count();
        let first_exact = usize::from(advice.range() == Some((
            released_address as usize, ARENA_SLICE_SIZE, 4,
        )));
        let first_warnings = warnings.bodies.lock().unwrap().len();
        let warning_after_stats = warnings.bodies.lock().unwrap().iter().filter(|(body, calls, bytes, visits)| {
            *calls == before_vm.purge_calls + 1
                && *bytes == before_vm.purged + ARENA_SLICE_SIZE as i64
                && *visits == before_arena.arena_purges + 1
                && body.windows(b"error: 5 (0x05)".len()).any(|part| part == b"error: 5 (0x05)")
                && body.windows(b"size: 0x10000 bytes".len()).any(|part| part == b"size: 0x10000 bytes")
        }).count();
        let first_purges = after_first_vm.purge_calls - before_vm.purge_calls;
        let first_bytes = after_first_vm.purged - before_vm.purged;
        let first_visits = after_first_arena.arena_purges - before_arena.arena_purges;
        let first_committed = after_first_vm.committed_current - before_vm.committed_current;
        fault.set(fault::Plan::disabled());
        assert!(unsafe { backing.collect_purge(process, config, true, true, 0) });
        let after_second_vm = subprocess.vm_statistics().snapshot();
        let after_second_arena = subprocess.arena_statistics().snapshot();
        let no_retry = advice.count() == first_calls
            && warnings.bodies.lock().unwrap().len() == first_warnings
            && after_second_vm.purge_calls - before_vm.purge_calls == first_purges
            && after_second_arena.arena_purges - before_arena.arena_purges == first_visits;
        drop(advice);
        let later = unsafe { backing.try_allocate_slices(
            process, config, requested, 2, ARENA_SLICE_SIZE, true,
        ) }.expect("independent two-slice claim");
        let later_index = later.slice_index();
        let later_disjoint = later_index > survivor_index
            && later.start() != released_address
            && free.is_clear_range(later_index, 2) == Some(true);
        assert!(later.release());
        let later_pending = purge.is_set_range(later_index, 2) == Some(true)
            && free.is_clear_range(survivor_index, 1) == Some(true);
        // SAFETY: the arena stays mapped through the live survivor claim.
        let owner_live = unsafe { crabc_core::mm::mincore_raw(
            arena.start, 4096, &mut residency,
        ) }.is_ok() && unsafe { crabc_core::mm::mincore_raw(
            survivor_address, 4096, &mut residency,
        ) }.is_ok() && backing.registry().count() == 1
            && subprocess.vm_statistics().snapshot().reserved_current == before_vm.reserved_current;
        assert!(survivor.release());
        // SAFETY: releasing a slice preserves its process-owned arena mapping.
        let terminal = unsafe { crabc_core::mm::mincore_raw(
            arena.start, 4096, &mut residency,
        ) }.is_ok() && backing.registry().count() == 1
            && free.is_set_range(survivor_index, 1) == Some(true);
        let final_vm = subprocess.vm_statistics().snapshot();
        let final_arena = subprocess.arena_statistics().snapshot();
        for (field, value) in [
            ("setup", i64::from(setup)), ("pending", i64::from(pending)),
            ("pending_purge", i64::from(pending_purge)),
            ("pending_committed", i64::from(pending_committed)),
            ("pending_free", i64::from(pending_free)),
            ("pending_survivor", i64::from(pending_survivor)),
            ("pending_expiry", i64::from(pending_expiry)),
            ("pending_no_advice", i64::from(pending_no_advice)),
            ("consumed", i64::from(consumed)), ("first_calls", first_calls as i64),
            ("first_exact", first_exact as i64), ("first_warnings", first_warnings as i64),
            ("warning_after_stats", warning_after_stats as i64),
            ("first_purges", first_purges), ("first_bytes", first_bytes),
            ("first_visits", first_visits), ("first_committed", first_committed),
            ("no_retry", i64::from(no_retry)),
            ("later_disjoint", i64::from(later_disjoint)),
            ("later_pending", i64::from(later_pending)),
            ("owner_live", i64::from(owner_live)), ("terminal", i64::from(terminal)),
            ("released_slice", index as i64), ("survivor_slice", survivor_index as i64),
            ("later_slice", later_index as i64), ("registry", backing.registry().count() as i64),
            ("reserved", final_vm.reserved_current - before_vm.reserved_current),
            ("purge_calls", final_vm.purge_calls - before_vm.purge_calls),
            ("purged_bytes", final_vm.purged - before_vm.purged),
            ("arena_purges", final_arena.arena_purges - before_arena.arena_purges),
            ("advice_calls", first_calls as i64), ("warnings", first_warnings as i64),
        ] {
            std::println!("m2.delayed_purge_failure.{field}={value}");
        }
        assert!(setup && pending && pending_no_advice && consumed && no_retry
            && later_disjoint && later_pending && owner_live && terminal);
        drop(fault);
        // SAFETY: callback removal prevents further use of stack capture.
        unsafe { output.register_output(None, core::ptr::null_mut()) };
    }

    /// Disjoint delayed ranges preserve their independent OS advice outcomes
    /// while a claimed slice between them remains live.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_delayed_purge_mixed_outcome_c_rust_trace() {
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        use crate::os::{VmPolicy, VmProcess, fault};
        use core::ffi::{c_char, c_void, CStr};
        use core::sync::atomic::{AtomicPtr, Ordering};

        static ENVIRONMENT: AtomicPtr<*const c_char> = AtomicPtr::new(core::ptr::null_mut());
        unsafe fn environment() -> *const *const c_char {
            ENVIRONMENT.load(Ordering::Acquire).cast_const()
        }
        unsafe extern "C" fn default_output(_message: *const c_char) {}
        struct Warnings {
            bodies: std::sync::Mutex<std::vec::Vec<(std::vec::Vec<u8>, i64, i64, i64, i64, usize)>>,
            subprocess: *const crate::subproc::SubprocessIdentity,
            advice: AtomicPtr<c_void>,
        }
        unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
            // SAFETY: the callback and its stack capture remain live until
            // explicit removal; the advice capture is installed during the
            // synchronous collection that can issue this diagnostic.
            let warnings = unsafe { &*(argument as *const Warnings) };
            let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
            if !bytes.starts_with(b"cannot decommit OS memory") { return; }
            let subprocess = unsafe { &*warnings.subprocess };
            let vm = subprocess.vm_statistics().snapshot();
            let arena = subprocess.arena_statistics().snapshot();
            let advice = warnings.advice.load(Ordering::Acquire);
            let count = if advice.is_null() { 0 } else {
                // SAFETY: the pointer names the live capture around this
                // synchronous diagnostic and is cleared before its drop.
                unsafe { &*(advice as *const fault::AdviceRangeCapture<'_>) }.count()
            };
            warnings.bodies.lock().unwrap().push((bytes.to_vec(),
                vm.purge_calls, vm.purged, arena.arena_purges,
                vm.committed_current, count));
        }

        let entries = Box::leak(Box::new([
            b"mimalloc_arena_reserve=32M\0".as_ptr().cast(),
            b"mimalloc_arena_eager_commit=0\0".as_ptr().cast(),
            b"mimalloc_arena_is_numa_local=0\0".as_ptr().cast(),
            b"mimalloc_allow_large_os_pages=0\0".as_ptr().cast(),
            b"mimalloc_allow_thp=0\0".as_ptr().cast(),
            b"mimalloc_purge_delay=100000\0".as_ptr().cast(),
            b"mimalloc_arena_purge_mult=1\0".as_ptr().cast(),
            b"mimalloc_purge_decommits=1\0".as_ptr().cast(),
            b"mimalloc_show_errors=1\0".as_ptr().cast(),
            b"mimalloc_max_warnings=100\0".as_ptr().cast(),
            core::ptr::null(),
        ]));
        ENVIRONMENT.store(entries.as_mut_ptr(), Ordering::Release);
        let output = Box::leak(Box::new(OutputOwner::new(default_output)));
        // SAFETY: the environment image and output remain process-lived.
        unsafe { output.initialize_source_options(environment) };
        let subprocess = MainSubprocess::test_static_owner();
        let warnings = Warnings {
            bodies: std::sync::Mutex::new(std::vec::Vec::new()),
            subprocess: subprocess.identity(),
            advice: AtomicPtr::new(core::ptr::null_mut()),
        };
        // SAFETY: removal below precedes the stack capture's end.
        unsafe { output.register_output(Some(capture as OutputCallback),
            &warnings as *const Warnings as *mut c_void) };
        // SAFETY: source options are initialized and the output owner stays live.
        let policy = Box::leak(Box::new(
            unsafe { VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(), 1 << 20, true, false,
        );
        let backing = subprocess.arena_backing();
        let search = ArenaSearch { heap_sequence: 0, heap_count: 1,
            thread_sequence: 0, numa_node: -1, requested: ArenaId::none(),
            allow_pinned: true };
        let fault = fault::install(fault::Plan::disabled());
        // SAFETY: this isolated process owns its sole backing; no concurrent
        // claim, registry mutation, or purge visitor occurs.
        let first = unsafe { backing.try_allocate_slices(
            process, config, search, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("first committed slice");
        let arena_id = first.memory_id().arena_memory().unwrap().arena;
        // SAFETY: the first claim pins this published parent arena.
        let requested = ArenaSearch { requested: unsafe { ArenaId::from_arena(arena_id) }.unwrap(), ..search };
        let neighbor = unsafe { backing.try_allocate_slices(
            process, config, requested, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("live neighboring slice");
        let second = unsafe { backing.try_allocate_slices(
            process, config, requested, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("second committed slice");
        let a = first.slice_index();
        let middle = neighbor.slice_index();
        let b = second.slice_index();
        let a_address = first.start();
        let middle_address = neighbor.start();
        let b_address = second.start();
        // SAFETY: all three claims pin their published arena and bitmaps.
        let view = unsafe { ArenaView::from_ptr(arena_id) }.unwrap();
        let arena = view.arena();
        let free = unsafe { view.slices_free() }.unwrap();
        let committed = unsafe { view.slices_committed() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        let mut residency = 0u8;
        // SAFETY: the arena and each claim are live page-aligned mappings.
        let setup = backing.registry().count() == 1
            && arena.memid.kind() == MemoryKind::Os
            && a == 9 && middle == 10 && b == 11
            && unsafe { crabc_core::mm::mincore_raw(arena.start, 4096, &mut residency) }.is_ok()
            && unsafe { crabc_core::mm::mincore_raw(a_address, 4096, &mut residency) }.is_ok()
            && unsafe { crabc_core::mm::mincore_raw(middle_address, 4096, &mut residency) }.is_ok()
            && unsafe { crabc_core::mm::mincore_raw(b_address, 4096, &mut residency) }.is_ok();
        // SAFETY: the live neighboring claim uniquely owns this byte.
        unsafe { middle_address.write_volatile(0x7b) };
        let before_vm = subprocess.vm_statistics().snapshot();
        let before_arena = subprocess.arena_statistics().snapshot();
        assert!(first.release());
        assert!(second.release());
        let pending = purge.is_set_range(a, 1) == Some(true)
            && purge.is_set_range(b, 1) == Some(true)
            && purge.is_clear_range(middle, 1) == Some(true)
            && committed.is_set_range(a, 1) == Some(true)
            && committed.is_set_range(b, 1) == Some(true)
            && free.is_set_range(a, 1) == Some(true)
            && free.is_set_range(b, 1) == Some(true)
            && free.is_clear_range(middle, 1) == Some(true)
            && arena.purge_expire.load(Ordering::Relaxed) > 0;
        let pending_quiet = warnings.bodies.lock().unwrap().is_empty()
            && subprocess.vm_statistics().snapshot().purge_calls == before_vm.purge_calls;
        fault.set(fault::Plan::at(fault::Point::Decommit, 1, crabc_core::Errno::IO));
        let advice = fault.capture_advice_range();
        warnings.advice.store((&advice as *const fault::AdviceRangeCapture<'_>) as *mut c_void,
            Ordering::Release);
        // SAFETY: both released ranges and their live neighbor stay within
        // the same owned arena throughout this isolated forced collection.
        assert!(unsafe { backing.collect_purge(process, config, true, true, 0) });
        warnings.advice.store(core::ptr::null_mut(), Ordering::Release);
        let (ordered_advice, advice_count) = advice.ranges().expect("bounded advice sequence");
        let ordered = advice_count == 2
            && ordered_advice[0] == (a_address as usize, ARENA_SLICE_SIZE, 4)
            && ordered_advice[1] == (b_address as usize, ARENA_SLICE_SIZE, 4);
        let bitmaps = purge.is_clear_range(a, 1) == Some(true)
            && purge.is_clear_range(b, 1) == Some(true)
            && committed.is_set_range(a, 1) == Some(true)
            && committed.is_set_range(b, 1) == Some(true)
            && free.is_set_range(a, 1) == Some(true)
            && free.is_set_range(b, 1) == Some(true)
            && free.is_clear_range(middle, 1) == Some(true)
            && arena.purge_expire.load(Ordering::Relaxed) == 0;
        let after_vm = subprocess.vm_statistics().snapshot();
        let after_arena = subprocess.arena_statistics().snapshot();
        let bodies = warnings.bodies.lock().unwrap();
        let warning_count = bodies.len();
        let warning_order = bodies.iter().filter(|body| body.5 == 1).count();
        let warning_stats = bodies.iter().filter(|(text, calls, bytes, visits, committed_bytes, _)| {
            *calls == before_vm.purge_calls + 1
                && *bytes == before_vm.purged + ARENA_SLICE_SIZE as i64
                && *visits == before_arena.arena_purges + 1
                && *committed_bytes == before_vm.committed_current
                && text.windows(b"error: 5 (0x05)".len()).any(|part| part == b"error: 5 (0x05)")
                && text.windows(b"size: 0x10000 bytes".len()).any(|part| part == b"size: 0x10000 bytes")
        }).count();
        drop(bodies);
        let collected_calls = after_vm.purge_calls - before_vm.purge_calls;
        let collected_bytes = after_vm.purged - before_vm.purged;
        let collected_visits = after_arena.arena_purges - before_arena.arena_purges;
        let committed_delta = after_vm.committed_current - before_vm.committed_current;
        fault.set(fault::Plan::disabled());
        assert!(unsafe { backing.collect_purge(process, config, true, true, 0) });
        let after_second = subprocess.vm_statistics().snapshot();
        let after_second_arena = subprocess.arena_statistics().snapshot();
        let no_retry = advice.count() == 2 && warnings.bodies.lock().unwrap().len() == 1
            && after_second.purge_calls - before_vm.purge_calls == collected_calls
            && after_second_arena.arena_purges - before_arena.arena_purges == collected_visits;
        drop(advice);
        // SAFETY: the live neighbor still owns its exact mapped byte.
        let survivor = unsafe { crabc_core::mm::mincore_raw(
            arena.start, 4096, &mut residency,
        ) }.is_ok() && unsafe { crabc_core::mm::mincore_raw(
            middle_address, 4096, &mut residency,
        ) }.is_ok() && unsafe { middle_address.read_volatile() } == 0x7b
            && free.is_clear_range(middle, 1) == Some(true)
            && backing.registry().count() == 1;
        assert!(neighbor.release());
        // SAFETY: releasing the final claim preserves its process-owned arena.
        let terminal = unsafe { crabc_core::mm::mincore_raw(
            arena.start, 4096, &mut residency,
        ) }.is_ok() && backing.registry().count() == 1
            && free.is_set_range(middle, 1) == Some(true)
            && subprocess.vm_statistics().snapshot().reserved_current == before_vm.reserved_current;
        let final_vm = subprocess.vm_statistics().snapshot();
        let final_arena = subprocess.arena_statistics().snapshot();
        for (field, value) in [
            ("setup", i64::from(setup)), ("pending", i64::from(pending)),
            ("pending_quiet", i64::from(pending_quiet)), ("ordered", i64::from(ordered)),
            ("bitmaps", i64::from(bitmaps)), ("advice_count", advice_count as i64),
            ("warning_count", warning_count as i64),
            ("warning_order", warning_order as i64), ("warning_stats", warning_stats as i64),
            ("collected_calls", collected_calls), ("collected_bytes", collected_bytes),
            ("collected_visits", collected_visits), ("committed_delta", committed_delta),
            ("no_retry", i64::from(no_retry)), ("survivor", i64::from(survivor)),
            ("terminal", i64::from(terminal)), ("a_slice", a as i64),
            ("neighbor_slice", middle as i64), ("b_slice", b as i64),
            ("registry", backing.registry().count() as i64),
            ("reserved_delta", final_vm.reserved_current - before_vm.reserved_current),
            ("purge_calls", final_vm.purge_calls - before_vm.purge_calls),
            ("purged_bytes", final_vm.purged - before_vm.purged),
            ("arena_purges", final_arena.arena_purges - before_arena.arena_purges),
        ] {
            std::println!("m2.delayed_purge_mixed.{field}={value}");
        }
        assert!(setup && pending && pending_quiet && ordered && bitmaps
            && no_retry && survivor && terminal);
        drop(fault);
        // SAFETY: callback removal prevents future use of its stack capture.
        unsafe { output.register_output(None, core::ptr::null_mut()) };
    }
}
