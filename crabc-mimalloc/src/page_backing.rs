// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source map: mimalloc v3.5.0 src/arena.c:98-129,781-870 and
// src/init.c:184-205. See UPSTREAM.md for the fixed revision and license.

//! Backing capabilities of the existing page engine. The historical
//! selected-arena capability and process-main metadata capability remain
//! distinct types: no empty ArenaView or synthetic initial arena is needed
//! when source policy chooses an OS page before any arena exists.

use crate::arena::{ArenaId, ArenaSearch, ArenaSliceClaim, ArenaView, ProcessArenaBacking};
use crate::config::{ARENA_MIN_OBJ_SIZE, ARENA_SLICE_SIZE, PAGE_META_ALIGNMENT, PAGE_META_ALIGNED_COUNT};
use crate::os::{MemoryConfig, VmProcess};
use crate::types::{MemoryId, Page};

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::arena::ArenaView<'_> {}
    impl Sealed for super::ProcessMetadataPageBacking {}
}

pub(crate) trait PageBacking<'arena>: sealed::Sealed {
    fn selected_arena(&self) -> Option<&ArenaView<'arena>>;
    /// # Safety
    /// An arena `memory` must come from an outstanding live claim or page
    /// whose arena lifetime the caller retains. This validates source owner
    /// identity, not arbitrary or dangling client-supplied arena addresses.
    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'arena>>;
    fn process(&self) -> Option<VmProcess<'static>> { None }
    fn claim(&self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize) -> Option<ArenaSliceClaim<'arena>>;
    /// # Safety
    /// `memory` is one outstanding claim of this exact backing owner. All
    /// page-map entries and metadata aliases must be removed, no client or
    /// lookup may remain, and this caller owns the unique slice release right.
    unsafe fn release(&self, memory: MemoryId) -> bool;
    fn collect(&self, config: MemoryConfig, force: bool, thread_sequence: usize) -> bool;
}

impl<'arena> PageBacking<'arena> for ArenaView<'arena> {
    fn selected_arena(&self) -> Option<&ArenaView<'arena>> { Some(self) }
    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'arena>> {
        let arena = memory.arena_memory()?.arena;
        if arena != core::ptr::from_ref(self.arena()).cast_mut() { return None; }
        // SAFETY: the selected view already retains this exact live arena.
        unsafe { ArenaView::from_ptr(arena) }
    }
    fn claim(&self, _: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize) -> Option<ArenaSliceClaim<'arena>> {
        self.try_claim_suitable_slices(requested, slices, commit, thread_sequence)
    }
    unsafe fn release(&self, memory: MemoryId) -> bool {
        unsafe { self.arena_for_memory(memory) }.is_some()
            && unsafe { crate::arena::release_arena_slices(memory) }
    }
    fn collect(&self, config: MemoryConfig, force: bool, _: usize) -> bool {
        self.collect_scheduled_purge(config.page_size(), force)
    }
}

/// The process-main metadata Theap uses the source main Heap (hseq zero)
/// and detached TLD (thread_seq zero), not a separately reserved metadata
/// arena. Its owning MetaAllocator must serialize operations, retain this
/// exact process pair and shared PageMap, and prohibit destruction while any
/// page or lookup remains live. This is not a general dynamic-Heap selector.
#[derive(Clone, Copy)]
pub(crate) struct ProcessMetadataPageBacking {
    process: VmProcess<'static>,
}

impl ProcessMetadataPageBacking {
    pub(crate) fn new(process: VmProcess<'static>) -> Self { Self { process } }
    fn backing(&self) -> &'static ProcessArenaBacking { self.process.subprocess().arena_backing() }

    fn max_object_size(&self) -> usize {
        let requested = self.process.policy().arena_max_object_size_bytes();
        let rounded = requested.wrapping_add(ARENA_SLICE_SIZE - 1) & !(ARENA_SLICE_SIZE - 1);
        let metadata = (PAGE_META_ALIGNED_COUNT * core::mem::size_of::<Page>()
            + ARENA_SLICE_SIZE - 1) & !(ARENA_SLICE_SIZE - 1);
        rounded.clamp(ARENA_MIN_OBJ_SIZE, PAGE_META_ALIGNMENT - metadata)
    }
}

impl PageBacking<'static> for ProcessMetadataPageBacking {
    fn selected_arena(&self) -> Option<&ArenaView<'static>> { None }
    fn process(&self) -> Option<VmProcess<'static>> { Some(self.process) }
    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'static>> {
        let pointer = memory.arena_memory()?.arena;
        let registry = self.backing().registry();
        // SAFETY: the caller retains the live source arena provenance. Use
        // its immutable published index, not a hot-path registry traversal.
        let view = unsafe { ArenaView::from_ptr(pointer) }?;
        let published = unsafe { registry.arena_at(view.arena().arena_index) }?;
        (core::ptr::from_ref(published).cast_mut() == pointer).then_some(view)
    }
    fn claim(&self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize) -> Option<ArenaSliceClaim<'static>> {
        if self.process.policy().disallow_arena_alloc()
            || slices > self.max_object_size() / ARENA_SLICE_SIZE { return None; }
        // Source hseq zero selects the thread-sequence branch before reading
        // heap_count. No dynamic heap-count authority is fabricated here.
        let search = ArenaSearch { heap_sequence: 0, heap_count: 0, thread_sequence,
            numa_node: -1, requested, allow_pinned: true };
        unsafe { self.backing().try_allocate_slices(self.process, config, search,
            slices, ARENA_SLICE_SIZE, commit) }
    }
    unsafe fn release(&self, memory: MemoryId) -> bool {
        unsafe { self.arena_for_memory(memory) }.is_some()
            && unsafe { self.backing().release_slices(memory) }
    }
    fn collect(&self, config: MemoryConfig, force: bool, thread_sequence: usize) -> bool {
        unsafe { self.backing().collect_purge(self.process, config, force, false, thread_sequence) };
        true
    }
}
