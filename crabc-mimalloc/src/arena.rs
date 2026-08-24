// Copyright (c) 2019-2026 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/arena.c:32-219` (arena identity,
// suitability, registry indexing, geometry, and arena memory IDs),
// `src/arena.c:1573-1659` (registry insertion and exact metadata/bitmap
// sizing), and `src/arena.c:1676-1917` (in-place arena initialization,
// metadata reservation, external-region alignment, and 16-GiB splitting).
// This substrate deliberately stops before arena page allocation/search,
// per-heap `arena_pages` ownership, purge lifecycle, theap/TLS state, NUMA
// option lookup, statistics, and allocator-backed metadata.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicI64, AtomicPtr};

use crate::atomic::{
    pointer_cas_strong_release, pointer_load_acquire, word_cas_strong_release,
    word_load_relaxed, AtomicWord,
};
use crate::bitmap::{
    BinnedBitmapLayout, BinnedBitmapView, BitmapLayout, BitmapView, BCHUNK_SIZE,
};
use crate::config::{
    ARENA_ALIGNMENT, ARENA_BIN_COUNT, ARENA_MAX_SIZE, ARENA_MIN_SIZE, ARENA_SLICE_SIZE,
    BCHUNK_BITS, BITMAP_MAX_BIT_COUNT, MAX_ARENAS, PAGE_META_ALIGNED_COUNT,
};
use crate::invariants;
use crate::os::PageSize;
use crate::types::{
    Arena, ArenaPages, CommitFunction, MemoryId, Page, Subprocess,
};

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
    subprocess: *mut Subprocess,
    count: AtomicWord,
    arenas: [AtomicPtr<Arena>; MAX_ARENAS],
}

// SAFETY: every slot is independently atomically published. The subprocess
// pointer is an immutable opaque identity and is never dereferenced here.
unsafe impl Send for ArenaRegistry {}
unsafe impl Sync for ArenaRegistry {}

impl ArenaRegistry {
    pub(crate) const fn new(subprocess: *mut Subprocess) -> Self {
        Self {
            subprocess,
            count: AtomicWord::new(0),
            arenas: [const { AtomicPtr::new(null_mut()) }; MAX_ARENAS],
        }
    }

    #[inline]
    pub(crate) fn count(&self) -> usize {
        word_load_relaxed(&self.count)
    }

    #[inline]
    pub(crate) const fn subprocess(&self) -> *mut Subprocess {
        self.subprocess
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
        if slice_index >= self.arena().slice_count {
            return None;
        }
        let offset = invariants::size_of_slices(slice_index)?;
        Some(unsafe { self.arena().start.add(offset) })
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

    pub(crate) unsafe fn pages(&self) -> Option<BitmapView<'arena>> {
        unsafe { self.ordinary_bitmap(self.arena().pages_main.pages) }
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
    }
}
