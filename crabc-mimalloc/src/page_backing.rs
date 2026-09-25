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
    impl Sealed for super::ChildMetadataArenaBacking<'_> {}
}

/// A value-owned candidate cursor. It retains registry/arena lifetime facts,
/// never a reference to an enclosing mutable page engine.
pub(crate) enum PageArenaSearch<'arena> {
    Selected(Option<ArenaView<'arena>>),
    Registry(crate::arena::ArenaCandidates<'arena>),
}

impl<'arena> Iterator for PageArenaSearch<'arena> {
    type Item = ArenaView<'arena>;
    fn next(&mut self) -> Option<Self::Item> {
        match self { Self::Selected(arena) => arena.take(), Self::Registry(arenas) => arenas.next() }
    }
}

pub(crate) trait PageBacking<'arena>: sealed::Sealed {
    fn selected_arena(&self) -> Option<&ArenaView<'arena>>;
    fn reclaim_arenas(&self, _requested: ArenaId, _thread_sequence: usize) -> PageArenaSearch<'arena> {
        PageArenaSearch::Selected(self.selected_arena().and_then(|arena| {
            // SAFETY: the backing retains this arena throughout the engine operation.
            unsafe { ArenaView::from_ptr(core::ptr::from_ref(arena.arena()).cast_mut()) }
        }))
    }
    /// # Safety
    /// An arena `memory` must come from an outstanding live claim or page
    /// whose arena lifetime the caller retains. This validates source owner
    /// identity, not arbitrary or dangling client-supplied arena addresses.
    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'arena>>;
    fn process(&self) -> Option<VmProcess<'arena>> { None }
    fn claim(&self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize) -> Option<ArenaSliceClaim<'arena>>;
    fn claim_with_random(&self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize, _random: crate::os::OsRandom<'_>)
        -> Option<ArenaSliceClaim<'arena>>
    {
        self.claim(config, requested, slices, commit, thread_sequence)
    }
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
    #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
    SelectedSidecar(ArenaView<'static>),
    SourceRegistry { process: VmProcess<'static>, numa_node: i32 },
    SourceStartupRegular {
        process: VmProcess<'static>,
        startup_arena: ArenaView<'static>,
        numa_node: i32,
    },
}

impl RuntimeFirstRegularPageBacking {
    #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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

    #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
            Self::SelectedSidecar(arena) => Some(arena),
            Self::SourceStartupRegular { startup_arena, .. } => Some(startup_arena),
            Self::SourceRegistry { .. } => None,
        }
    }

    fn reclaim_arenas(&self, requested: ArenaId, thread_sequence: usize) -> PageArenaSearch<'static> {
        match self {
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
            Self::SelectedSidecar(arena) => PageArenaSearch::Selected(unsafe {
                ArenaView::from_ptr(core::ptr::from_ref(arena.arena()).cast_mut())
            }),
            Self::SourceStartupRegular { process, .. } | Self::SourceRegistry { process, .. } => {
                // Pinned arena.c:725-776 searches all NUMA nodes, allowing
                // pinned arenas, in the same rotated source registry order.
                let search = ArenaSearch { heap_sequence: 0, heap_count: 0,
                    thread_sequence, numa_node: -1, requested, allow_pinned: true };
                // SAFETY: this backing retains the process registry and every
                // published arena; ordinary allocation cannot destroy them.
                PageArenaSearch::Registry(unsafe {
                    process.subprocess().arena_backing().registry().suitable_arenas(search)
                })
            }
        }
    }

    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'static>> {
        match self {
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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
        self.claim_with_random(config, requested, slices, commit, thread_sequence, None)
    }

    fn claim_with_random(
        &self,
        config: MemoryConfig,
        requested: ArenaId,
        slices: usize,
        commit: bool,
        thread_sequence: usize,
        random: crate::os::OsRandom<'_>,
    ) -> Option<ArenaSliceClaim<'static>> {
        match self {
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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
                        .try_allocate_slices_with_random(*process, config, search, slices,
                            ARENA_SLICE_SIZE, commit, random)
                }
            }
        }
    }

    unsafe fn release(&self, memory: MemoryId) -> bool {
        match self {
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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
            #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
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

/// Arena-slice source for child metadata pages. The PageMap remains process
/// global, while reserve, bitmap, statistics, and teardown target this exact
/// pinned child identity. This is not yet a page allocator/session.
#[derive(Clone, Copy)]
pub(crate) struct ChildMetadataArenaBacking<'child> {
    pair: crate::process_arena::ChildProcessPageArenaLease<'child>,
}

impl<'child> ChildMetadataArenaBacking<'child> {
    pub(crate) fn new(
        pair: crate::process_arena::ChildProcessPageArenaLease<'child>,
    ) -> Self {
        Self { pair }
    }

    fn process(&self) -> VmProcess<'child> { self.pair.child().process() }

    fn max_object_size(&self) -> usize {
        let requested = self.process().policy().arena_max_object_size_bytes();
        let rounded = requested.wrapping_add(ARENA_SLICE_SIZE - 1) & !(ARENA_SLICE_SIZE - 1);
        let metadata = (PAGE_META_ALIGNED_COUNT * core::mem::size_of::<Page>()
            + ARENA_SLICE_SIZE - 1) & !(ARENA_SLICE_SIZE - 1);
        rounded.clamp(ARENA_MIN_OBJ_SIZE, PAGE_META_ALIGNMENT - metadata)
    }
}

impl<'child> PageBacking<'child> for ChildMetadataArenaBacking<'child> {
    fn selected_arena(&self) -> Option<&ArenaView<'child>> { None }
    fn reclaim_arenas(&self, requested: ArenaId, thread_sequence: usize) -> PageArenaSearch<'child> {
        // `mi_forall_suitable_arenas` over the child's own arenas
        // (`arena.c:725-776`), in the source rotated registry order.
        let search = ArenaSearch { heap_sequence: 0, heap_count: 0,
            thread_sequence, numa_node: -1, requested, allow_pinned: true };
        // SAFETY: the pair retains the registered child and its published
        // arenas for the engine operation.
        PageArenaSearch::Registry(unsafe { self.pair.arena_backing().registry().suitable_arenas(search) })
    }
    fn process(&self) -> Option<VmProcess<'child>> { Some(self.process()) }
    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'child>> {
        unsafe { ChildMetadataArenaBacking::arena_for_memory(self, memory) }
    }
    fn claim(&self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize) -> Option<ArenaSliceClaim<'child>> {
        self.claim_child_arena_slices_with_random(config, requested, slices, commit,
            thread_sequence, None)
    }
    fn claim_with_random(&self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize, random: crate::os::OsRandom<'_>)
        -> Option<ArenaSliceClaim<'child>> {
        self.claim_child_arena_slices_with_random(config, requested, slices, commit,
            thread_sequence, random)
    }
    unsafe fn release(&self, memory: MemoryId) -> bool {
        unsafe { ChildMetadataArenaBacking::release(self, memory) }
    }
    unsafe fn account_page_commit_before_release(&self, memory: MemoryId, committed: usize) -> bool {
        unsafe { ChildMetadataArenaBacking::account_page_commit_before_release(self, memory, committed) }
    }
    fn collect(&self, config: MemoryConfig, force: bool, thread_sequence: usize) -> bool {
        ChildMetadataArenaBacking::collect(self, config, force, thread_sequence)
    }
}

impl<'child> ChildMetadataArenaBacking<'child> {
    /// # Safety
    /// `memory` must be one live child-owned page/claim with all PageMap
    /// entries and page metadata aliases removed before returning its slices.
    unsafe fn arena_for_memory(&self, memory: MemoryId) -> Option<ArenaView<'child>> {
        let pointer = memory.arena_memory()?.arena;
        let backing = self.pair.arena_backing();
        // SAFETY: callers keep the child page/capability live; the pair keeps
        // the registered child backing alive while this lookup runs.
        let view = unsafe { ArenaView::from_ptr(pointer) }?;
        let published = unsafe { backing.registry().arena_at(view.arena().arena_index) }?;
        (core::ptr::from_ref(published).cast_mut() == pointer).then_some(view)
    }

    /// Admits slices for this registered child using caller-supplied search
    /// sequence and random source. This is generic child arena admission: it
    /// does not establish the child metadata-Theap source route. A caller
    /// using that route must retain and supply the source TLD sequence/random
    /// capability for the whole operation; tests with synthetic random state
    /// prove only child arena routing and bitmap release.
    pub(crate) fn claim_child_arena_slices_with_random(
        &self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize, random: crate::os::OsRandom<'_>)
        -> Option<ArenaSliceClaim<'child>>
    {
        // Validate the child backing before the lower route can search or
        // claim an already-published child arena.
        if self.pair.memory_config().ok()? != config { return None; }
        let process = self.process();
        let arena_backing = self.pair.arena_backing();
        if !arena_backing.child_binding_matches(process, config)
            || process.policy().disallow_arena_alloc()
            || slices > self.max_object_size() / ARENA_SLICE_SIZE { return None; }
        let child = self.pair.child();
        let search = ArenaSearch {
            heap_sequence: 0,
            heap_count: 0,
            thread_sequence,
            numa_node: -1,
            requested,
            allow_pinned: true,
        };
        // SAFETY: the pair retains the exact registered child, and the
        // caller retains the supplied random source for this operation. The
        // child metadata-Theap caller must supply sequence zero from its
        // detached TLD and the child metadata-Theap's initialized random
        // image (seeded by that TLD during Theap initialization); this generic
        // admission API does not encode those source facts.
        unsafe {
            self.pair.arena_backing().try_allocate_child_slices_with_random(
                child, config, search, slices, ARENA_SLICE_SIZE, commit, random,
            )
        }
    }

    /// # Safety
    /// `memory` must be the exact child page span after PageMap unregister,
    /// arena-bitmap clearing, and metadata teardown; this consumes its unique
    /// slice-release right.
    pub(crate) unsafe fn release(&self, memory: MemoryId) -> bool {
        unsafe { self.arena_for_memory(memory) }.is_some()
            && unsafe { self.pair.arena_backing().release_slices(memory) }
    }

    /// # Safety
    /// The caller uniquely owns this page's release transition after
    /// PageMap/bitmap removal and passes its exact committed prefix once.
    pub(crate) unsafe fn account_page_commit_before_release(&self, memory: MemoryId, committed: usize) -> bool {
        unsafe { self.arena_for_memory(memory) }.is_some()
            && unsafe { self.pair.arena_backing().account_page_commit_before_release(memory, committed) }
    }

    pub(crate) fn collect(&self, config: MemoryConfig, force: bool, thread_sequence: usize) -> bool {
        unsafe { self.pair.arena_backing().collect_purge(
            self.process(), config, force, false, thread_sequence,
        ) }
    }
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
        self.claim_with_random(config, requested, slices, commit, thread_sequence, None)
    }

    fn claim_with_random(&self, config: MemoryConfig, requested: ArenaId, slices: usize,
        commit: bool, thread_sequence: usize, random: crate::os::OsRandom<'_>) -> Option<ArenaSliceClaim<'static>> {
        if self.process.policy().disallow_arena_alloc()
            || slices > self.max_object_size() / ARENA_SLICE_SIZE { return None; }
        // Source hseq zero selects the thread-sequence branch before reading
        // heap_count. No dynamic heap-count authority is fabricated here.
        let search = ArenaSearch { heap_sequence: 0, heap_count: 0, thread_sequence,
            numa_node: -1, requested, allow_pinned: true };
        unsafe { self.backing().try_allocate_slices_with_random(self.process, config, search,
            slices, ARENA_SLICE_SIZE, commit, random) }
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
    fn source_registry_reclaim_visits_prior_regular_and_simulated_huge_arenas() {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        let policy = Box::leak(Box::new(VmPolicy::new(options).unwrap()));
        let subprocess = MainSubprocess::test_static_owner();
        let process = VmProcess::new(policy, subprocess);
        let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false);
        // SAFETY: this private empty registry has no publication or reader.
        assert!(unsafe { subprocess.arena_backing().registry()
            .bind_subprocess_before_publication(subprocess.as_ptr()) });
        let mut mappings = std::vec::Vec::new();
        let mut identities = std::vec::Vec::new();
        for pinned in [false, true, false] {
            let mapping = crate::os::Mapping::map_aligned_for_allocator(config,
                crate::config::ARENA_MIN_SIZE, crate::config::ARENA_ALIGNMENT,
                crate::os::MapAccess::Committed).unwrap();
            // SAFETY: private mappings and the subprocess outlive every view.
            let managed = unsafe { crate::arena::manage_external_in_place(
                subprocess.arena_backing().registry(), mapping.base().unwrap(),
                crate::config::ARENA_MIN_SIZE, config.page_size(),
                true, false, true, -1, false, None,
            ) }.unwrap();
            let identity = managed.arena_id();
            // Simulate the source huge-arena pinned classification; no huge
            // mapping or NUMA policy operation participates in this test.
            unsafe { (*identity.as_ptr()).memid.is_pinned = pinned; }
            identities.push(identity.as_ptr());
            mappings.push(mapping);
        }
        let backing = RuntimeFirstRegularPageBacking::source_registry(process, -1);
        let selected: std::vec::Vec<_> = backing.reclaim_arenas(ArenaId::none(), 1)
            .map(|arena| core::ptr::from_ref(arena.arena()).cast_mut()).collect();
        assert_eq!(selected, [identities[1], identities[0], identities[2]],
            "source main-heap reclaim searches older regular and pinned arenas before the newest");
        drop(backing);
        for mut mapping in mappings { mapping.unmap().unwrap(); }
    }

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
