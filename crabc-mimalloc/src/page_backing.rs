// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source map: mimalloc v3.5.0 src/arena.c:98-129,781-870,1216-1283 and
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
    /// # Safety
    /// The caller uniquely owns the page release after removing its PageMap
    /// and arena-page publication. Account its prefix once before retirement.
    unsafe fn account_page_commit_before_release(&self, _: MemoryId, _: usize) -> bool { true }
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

/// The two already-selected arena owners admitted to the permanent
/// ticket-zero page engine.
///
/// `SelectedSidecar` preserves the historical lazy first-arena owner.  The
/// source-start variant retains a validated committed regular parent and
/// delegates every actual claim/release/purge to its process-owned registry.
/// It retains the process policy as well: after the exact source arena search
/// refuses an unsuitable page shape, `mi_arenas_page_alloc_fresh_area` takes
/// its existing direct-OS fallback.  It must not turn that refusal into a
/// second, private sidecar arena.
pub(crate) enum RuntimeFirstRegularPageBacking {
    SelectedSidecar(ArenaView<'static>),
    SourceRegistry { process: VmProcess<'static>, numa_node: i32 },
    SourceStartupRegular {
        process: VmProcess<'static>,
        startup_arena: ArenaView<'static>,
        numa_node: i32,
    },
}

impl RuntimeFirstRegularPageBacking {
    #[inline]
    pub(crate) fn selected_sidecar(arena: ArenaView<'static>) -> Self {
        Self::SelectedSidecar(arena)
    }

    /// Forms the process-owned source-start route after the process binding
    /// has checked its one published regular parent.  The constructor does
    /// not reserve, search, or relax that admission.
    #[inline]
    pub(crate) fn source_startup_regular(
        process: VmProcess<'static>,
        startup_arena: ArenaView<'static>,
        numa_node: i32,
    ) -> Self {
        Self::SourceStartupRegular { process, startup_arena, numa_node }
    }

    /// Uses the process registry with the source search/reserve/search policy.
    /// No startup reservation outcome or single-parent geometry is required.
    pub(crate) fn source_registry(process: VmProcess<'static>, numa_node: i32) -> Self {
        Self::SourceRegistry { process, numa_node }
    }

    #[inline]
    fn selected_matches_memory(&self, memory: MemoryId) -> Option<ArenaView<'static>> {
        let pointer = memory.arena_memory()?.arena;
        let selected = match self {
            Self::SelectedSidecar(arena) => arena,
            Self::SourceStartupRegular { startup_arena, .. } => startup_arena,
            Self::SourceRegistry { .. } => return None,
        };
        if pointer != core::ptr::from_ref(selected.arena()).cast_mut() {
            return None;
        }
        // SAFETY: each enum variant retains the selected registry-published
        // arena for process lifetime. The pointer equality above prevents an
        // arbitrary MemoryId from becoming a backing view.
        unsafe { ArenaView::from_ptr(pointer) }
    }

    /// Resolves a process-owned regular arena through its source-published
    /// registry slot. A source `try_allocate_slices` fallback can reserve one
    /// later regular parent, so release/accounting must validate the returned
    /// claim's real registry identity rather than require it to equal the
    /// original startup parent.
    unsafe fn process_arena_for_memory(
        process: VmProcess<'static>,
        memory: MemoryId,
    ) -> Option<ArenaView<'static>> {
        let pointer = memory.arena_memory()?.arena;
        let registry = process.subprocess().arena_backing().registry();
        // SAFETY: the caller retains a live page/claim MemoryId. Its arena
        // identity is inspected only against the immutable published slot.
        let view = unsafe { ArenaView::from_ptr(pointer) }?;
        // SAFETY: `arena_index` comes from the copied live arena image; the
        // registry returns only a process-published stable arena slot.
        let published = unsafe { registry.arena_at(view.arena().arena_index) }?;
        (core::ptr::from_ref(published).cast_mut() == pointer).then_some(view)
    }

    fn max_process_arena_object_size(process: VmProcess<'static>) -> usize {
        let requested = process.policy().arena_max_object_size_bytes();
        let rounded = requested.wrapping_add(ARENA_SLICE_SIZE - 1) & !(ARENA_SLICE_SIZE - 1);
        let metadata = (PAGE_META_ALIGNED_COUNT * core::mem::size_of::<Page>()
            + ARENA_SLICE_SIZE - 1) & !(ARENA_SLICE_SIZE - 1);
        rounded.clamp(ARENA_MIN_OBJ_SIZE, PAGE_META_ALIGNMENT - metadata)
    }
}

impl sealed::Sealed for RuntimeFirstRegularPageBacking {}

impl PageBacking<'static> for RuntimeFirstRegularPageBacking {
    fn selected_arena(&self) -> Option<&ArenaView<'static>> {
        match self {
            Self::SelectedSidecar(arena) => Some(arena),
            Self::SourceStartupRegular { startup_arena, .. } => Some(startup_arena),
            Self::SourceRegistry { .. } => None,
        }
    }

    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'static>> {
        match self {
            Self::SelectedSidecar(_) => self.selected_matches_memory(memory),
            // SAFETY: the PageBacking caller supplies a current arena MemoryId
            // from this process-owned claim or page; the helper validates its
            // immutable published registry identity before forming a view.
            Self::SourceStartupRegular { process, .. } | Self::SourceRegistry { process, .. } => unsafe {
                Self::process_arena_for_memory(*process, memory)
            },
        }
    }

    fn process(&self) -> Option<VmProcess<'static>> {
        match self {
            Self::SelectedSidecar(_) => None,
            Self::SourceStartupRegular { process, .. } | Self::SourceRegistry { process, .. } => Some(*process),
        }
    }

    fn claim(
        &self,
        config: MemoryConfig,
        requested: ArenaId,
        slices: usize,
        commit: bool,
        thread_sequence: usize,
    ) -> Option<ArenaSliceClaim<'static>> {
        match self {
            Self::SelectedSidecar(arena) => {
                arena.try_claim_suitable_slices(requested, slices, commit, thread_sequence)
            }
            Self::SourceStartupRegular { process, numa_node, .. } | Self::SourceRegistry { process, numa_node } => {
                // Pinned `mi_arenas_page_alloc_fresh_area` reaches
                // `mi_arenas_try_alloc` with the ticket-zero main heap's zero
                // sequence and its already-stored TLD NUMA value. Preserve
                // the whole source search/reserve/search transition here;
                // `PageAllocatorEngine` owns only the separate direct-OS
                // fallback after arena eligibility rejects the request.
                if process.policy().disallow_arena_alloc()
                    || slices > Self::max_process_arena_object_size(*process) / ARENA_SLICE_SIZE
                {
                    return None;
                }
                let search = ArenaSearch {
                    heap_sequence: 0,
                    heap_count: 0,
                    thread_sequence,
                    numa_node: *numa_node,
                    requested,
                    allow_pinned: true,
                };
                // SAFETY: this variant's construction proves the exact
                // process-owned registry/policy remain live; the page engine
                // owns any returned source claim until release.
                unsafe {
                    process
                        .subprocess()
                        .arena_backing()
                        .try_allocate_slices(*process, config, search, slices,
                            ARENA_SLICE_SIZE, commit)
                }
            }
        }
    }

    unsafe fn release(&self, memory: MemoryId) -> bool {
        match self {
            Self::SelectedSidecar(_) => {
                self.selected_matches_memory(memory).is_some()
                    && unsafe { crate::arena::release_arena_slices(memory) }
            }
            Self::SourceStartupRegular { process, .. } | Self::SourceRegistry { process, .. } => {
                // SAFETY: `memory` is the current exact page/claim held by
                // this backing; registry identity is checked before release.
                unsafe { Self::process_arena_for_memory(*process, memory) }.is_some()
                    && unsafe { process.subprocess().arena_backing().release_slices(memory) }
            }
        }
    }

    unsafe fn account_page_commit_before_release(&self, memory: MemoryId, committed: usize) -> bool {
        match self {
            Self::SelectedSidecar(_) => true,
            Self::SourceStartupRegular { process, .. } | Self::SourceRegistry { process, .. } => {
                // SAFETY: `memory` belongs to the current live source page;
                // the helper rejects unregistered/foreign arena identities.
                unsafe { Self::process_arena_for_memory(*process, memory) }.is_some()
                    && unsafe {
                        process
                            .subprocess()
                            .arena_backing()
                            .account_page_commit_before_release(memory, committed)
                    }
            }
        }
    }

    fn collect(&self, config: MemoryConfig, force: bool, thread_sequence: usize) -> bool {
        match self {
            Self::SelectedSidecar(arena) => {
                arena.collect_scheduled_purge(config.page_size(), force)
            }
            Self::SourceStartupRegular { process, .. } | Self::SourceRegistry { process, .. } => {
                // SAFETY: the page engine retains this process-owned backing
                // and every page claim it has published; the source backing
                // performs its normal process-wide purge traversal.
                unsafe {
                    process.subprocess().arena_backing().collect_purge(
                        *process,
                        config,
                        force,
                        false,
                        thread_sequence,
                    )
                }
            }
        }
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
    unsafe fn account_page_commit_before_release(&self, memory: MemoryId, committed: usize) -> bool {
        unsafe { self.arena_for_memory(memory) }.is_some()
            && unsafe { self.backing().account_page_commit_before_release(memory, committed) }
    }
    fn collect(&self, config: MemoryConfig, force: bool, thread_sequence: usize) -> bool {
        unsafe { self.backing().collect_purge(self.process, config, force, false, thread_sequence) }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::config::{VmOptions, VmOption, VmOptionEnvironment};
    use crate::os::{PageSize, VmPolicy};
    use crate::subproc::MainSubprocess;
    use std::boxed::Box;

    #[test]
    fn collection_propagates_owned_arena_bitmap_invariant_failure() {
        let _fault = crate::os::fault::install(crate::os::fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaReserve, 64 * 1024);
        let policy = Box::leak(Box::new(VmPolicy::new(options).unwrap()));
        policy.finish_preloading();
        let process = VmProcess::new(policy, MainSubprocess::test_static_owner());
        let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false);
        let backing = ProcessMetadataPageBacking::new(process);
        assert!(backing.collect(config, true, 0), "an empty owner is a successful no-op");
        let claim = backing.claim(config, ArenaId::none(), 1, true, 0).unwrap();
        let arena = claim.memory_id().arena_memory().unwrap().arena;
        assert!(claim.release());
        // This isolated owner has no outstanding claim or concurrent user.
        // Replace only the bitmap pointer (not its allocation) to exercise
        // the checked invariant boundary without dereferencing invalid data.
        let saved = unsafe { (*arena).slices_purge };
        unsafe { (*arena).slices_purge = core::ptr::null_mut(); }
        let collected = backing.collect(config, true, 0);
        unsafe { (*arena).slices_purge = saved; }
        assert!(!collected, "the page engine must observe the owned purge failure");
    }
}
