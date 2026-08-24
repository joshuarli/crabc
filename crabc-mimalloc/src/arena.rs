// Copyright (c) 2019-2026 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/arena.c:32-219` (arena identity,
// suitability, registry indexing, geometry, and arena memory IDs),
// `src/arena.c:1573-1659` (registry insertion and exact metadata/bitmap
// sizing), `src/arena.c:240-335` (single-arena slice claims,
// committed/dirty/zero observations, and commit rollback),
// `src/arena.c:911-947` (aligned page metadata selection and commitment),
// `src/arena.c:1433-1490` (arena slice release),
// `src/arena.c:2238-2409` (default delayed arena purge scheduling and forced
// collection), and
// `src/arena.c:1676-1917` (in-place arena initialization, metadata
// reservation, external-region alignment, and 16-GiB splitting).
// This substrate deliberately stops before arena iteration/search across the
// registry, per-heap `arena_pages` ownership, fresh-page lifecycle and page
// map registration, theap/TLS state, NUMA option lookup,
// statistics, and allocator-backed metadata.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicI64, AtomicPtr, Ordering};

use crate::atomic::{
    i64_cas_strong_acq_rel, i64_load_relaxed, i64_store_release,
    pointer_cas_strong_release, pointer_load_acquire, word_cas_strong_release,
    word_load_relaxed, AtomicWord,
};
use crate::bitmap::{
    AbandonedBitmapClaim, BinnedBitmapLayout, BinnedBitmapView, BitmapLayout,
    BitmapView, BCHUNK_SIZE,
};
use crate::config::{
    ARENA_ALIGNMENT, ARENA_BIN_COUNT, ARENA_MAX_SIZE, ARENA_MIN_SIZE, ARENA_SLICE_SIZE,
    BCHUNK_BITS, BITMAP_MAX_BIT_COUNT, MAX_ARENAS, PAGE_META_ALIGNED_COUNT,
};
use crate::invariants;
use crate::os::{self, DecommitOutcome, PageSize};
use crate::types::{
    Arena, ArenaPages, CommitFunction, MemoryId, Page, Subprocess,
};

// Fixed `src/options.c` defaults for the frozen v3.5.0 profile. This remains
// an arena-local delay because the one-thread slice has no source subprocess
// global-expiry owner or registry iteration policy yet.
const DEFAULT_PURGE_DELAY_MILLISECONDS: i64 = 1_000;
const DEFAULT_ARENA_PURGE_MULTIPLIER: i64 = 4;
const DEFAULT_ARENA_PURGE_DELAY_MILLISECONDS: i64 =
    DEFAULT_PURGE_DELAY_MILLISECONDS * DEFAULT_ARENA_PURGE_MULTIPLIER;

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

/// Registers an external region as one or more in-place arenas.
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
    let plan = ExternalArenaPlan::from_address(start as usize, size)
        .ok_or(ManageArenaError::InvalidRegion)?;
    let aligned_start = unsafe { start.add(plan.prefix_bytes()) };
    let mut parent = null_mut();
    let mut parent_id = ArenaId::none();
    let mut managed_size = 0usize;
    let mut memory = MemoryId::external(
        start,
        size,
        initially_committed,
        is_pinned,
        initially_zero,
    );

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
/// obligation either through [`Self::release`] or, when later page lifecycle
/// code stores the provenance, through [`release_arena_slices`]. Keeping that
/// transfer explicit prevents an implicit drop from returning slices while a
/// page still refers to them.
pub(crate) struct ArenaSliceClaim<'arena> {
    arena: NonNull<Arena>,
    start: NonNull<u8>,
    memory: MemoryId,
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

    /// Returns this exact claim to its source free bitmap.
    ///
    /// Consuming the claim makes a second safe release impossible. `false`
    /// reports a violated source ownership invariant, including an already
    /// free span introduced through an unsafe external release.
    #[inline]
    pub(crate) fn release(self) -> bool {
        unsafe { release_arena_slices(self.memory) }
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
/// This capability binds the bitmap to its source arena and size-class bin.
/// The abandonment substrate uses it to prevent a caller from publishing a
/// page into an arbitrary ordinary bitmap; it does not represent dynamic
/// per-heap `mi_arena_pages_t` allocation, which still belongs to the later
/// heap/theap lifecycle slice.
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
        self.bitmap.clear_once_set(slice_index) == Some(())
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn is_published(&self, slice_index: usize) -> bool {
        self.bitmap.is_set_range(slice_index, 1) == Some(true)
    }
}

impl<'arena> ArenaView<'arena> {
    /// # Safety
    ///
    /// `arena` must remain live and registry-published for `'arena`.
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
        if arena.memid.initially_zero() {
            let Some(dirty_transition) = dirty.set_range(slice_index, slice_count) else {
                let _ = rollback();
                return None;
            };
            memory.initially_zero = dirty_transition.all_transitioned();
        }

        if commit {
            let Some(already_committed) = committed.popcount_range(slice_index, slice_count)
            else {
                let _ = rollback();
                return None;
            };
            if already_committed < slice_count {
                let Some(commit_function) = arena.commit_function else {
                    let _ = rollback();
                    return None;
                };
                let Some(size) = invariants::size_of_slices(slice_count) else {
                    let _ = rollback();
                    return None;
                };
                let mut commit_zero = false;
                let committed_now = unsafe {
                    commit_function(
                        true,
                        start.as_ptr(),
                        size,
                        &mut commit_zero,
                        arena.commit_function_argument,
                    )
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
                // exact span. There are no statistics in this isolated slice.
                if committed.set_range(slice_index, slice_count).is_none()
                    || committed.clear_range(slice_index, slice_count).is_none()
                {
                    let _ = rollback();
                    return None;
                }
            }
        }

        Some(ArenaSliceClaim {
            arena: self.arena,
            start,
            memory,
            _arena: PhantomData,
        })
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
        let mut slice_index = arena.info_slices;
        while slice_index < arena.slice_count {
            let Some(purge) = (unsafe { self.slices_purge() }) else {
                return false;
            };
            let Some(is_scheduled) = purge.is_set_range(slice_index, 1) else {
                return false;
            };
            if !is_scheduled {
                slice_index += 1;
                continue;
            }

            // `_mi_bitmap_forall_setc_rangesn` visits at most one bchunk at a
            // time. Preserve that grouping before the source fallback tries
            // individual slices if a concurrent allocation blocks the full run.
            let remaining_in_chunk = BCHUNK_BITS - (slice_index % BCHUNK_BITS);
            let maximum = core::cmp::min(remaining_in_chunk, arena.slice_count - slice_index);
            let mut slice_count = 1usize;
            while slice_count < maximum {
                let Some(next_scheduled) = purge.is_set_range(slice_index + slice_count, 1)
                else {
                    return false;
                };
                if !next_scheduled {
                    break;
                }
                slice_count += 1;
            }
            if purge.clear_range(slice_index, slice_count) != Some(true) {
                return false;
            }
            if !self.purge_scheduled_range(page_size, slice_index, slice_count) {
                return false;
            }
            slice_index += slice_count;
        }
        true
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
                Err(_) => return self.restore_failed_purge(slice_index, slice_count),
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
}

const _: [(); 8] = [(); align_of::<Arena>()];
const _: [(); 648] = [(); size_of::<Arena>()];
const _: [(); ARENA_MAX_SIZE] = [(); BITMAP_MAX_BIT_COUNT * ARENA_SLICE_SIZE];

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::alloc::{alloc_zeroed, dealloc, Layout};

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
        let registry = ArenaRegistry::new(null_mut());
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
        let registry = ArenaRegistry::new(null_mut());
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
    fn suitable_slice_claim_exhausts_and_release_reuses_its_contiguous_span() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
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
        let registry = ArenaRegistry::new(null_mut());
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
        let registry = ArenaRegistry::new(null_mut());
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
    fn unpinned_slice_release_schedules_the_default_delayed_decommit_before_reuse() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(null_mut());
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
    fn clock_failure_skips_optional_purge_without_losing_the_released_slice() {
        let _fault = crate::os::fault::install(crate::os::fault::Plan::at(
            crate::os::fault::Point::Clock,
            1,
            crabc_core::Errno::NOMEM,
        ));
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(null_mut());
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
    fn purge_owned_slice_cannot_be_claimed_for_allocation() {
        let mut region = AlignedRegion::zeroed(ARENA_MIN_SIZE);
        let registry = ArenaRegistry::new(null_mut());
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
