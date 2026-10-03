// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: pinned mimalloc v3.5.0 src/arena.c:106-128,341-406,417-569.
//
//! Arena reservation geometry and source-order registry search. Option values
//! are snapshots read by the process VM owner, not a second option store.
//! Backing selection retains memory provenance through explicit release.
//! Consuming page queues and Heap/Theap owners retain allocation lifetimes.

use super::{ArenaId, ArenaRegistry, ArenaSliceClaim, ArenaView, arena_is_suitable};
use crate::config::{
    ARENA_MAX_CHUNK_OBJ_SIZE, ARENA_MAX_SIZE, ARENA_MIN_SIZE,
    ARENA_SLICE_SIZE, MAX_ARENAS,
};
use crate::invariants;
use crate::os::{MapAccess, MemoryConfig, VmPolicy};

/// Source `mi_arena_max_object_size` for the default aligned page-metadata
/// layout (`MI_PAGE_META_IS_ALIGNED`): the slice-rounded
/// `arena_max_object_size` option, clamped between one minimum object slice
/// and `mi_arena_max_fixed_object_size`.
pub(crate) fn arena_max_object_size(policy: &VmPolicy) -> usize {
    use crate::config::{ARENA_MIN_OBJ_SIZE, PAGE_META_ALIGNED_COUNT, PAGE_META_ALIGNMENT};
    let metadata = (PAGE_META_ALIGNED_COUNT * core::mem::size_of::<crate::types::Page>())
        .next_multiple_of(ARENA_SLICE_SIZE);
    let fixed = PAGE_META_ALIGNMENT - metadata;
    // Source `_mi_align_up` wraps like this on an out-of-range option.
    let requested = policy.arena_max_object_size_bytes()
        .wrapping_add(ARENA_SLICE_SIZE - 1) & !(ARENA_SLICE_SIZE - 1);
    if requested <= ARENA_MIN_OBJ_SIZE {
        ARENA_MIN_OBJ_SIZE
    } else if requested >= fixed {
        fixed
    } else {
        requested
    }
}

/// The two possible source reservation attempts, before any mapping or stats
/// mutation. A nonzero primary reservation result permits the size-bounded
/// fallback; any retained primary mapping keeps its independent cleanup owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArenaReservationPlan {
    pub(crate) primary_size: usize,
    pub(crate) fallback_size: Option<usize>,
    pub(crate) access: MapAccess,
    pub(crate) adjust_committed: bool,
}

impl ArenaReservationPlan {
    /// The `mi_arena_reserve` plan from the policy's live `arena_reserve`,
    /// `arena_eager_commit`, and `allow_large_os_pages` descriptors, read at
    /// the source point (`src/arena.c:347,386-387`).
    pub(crate) fn for_policy(
        config: MemoryConfig,
        arena_count: usize,
        requested_size: usize,
        policy: &VmPolicy,
    ) -> Option<Self> {
        Self::new(
            config,
            arena_count,
            requested_size,
            policy.arena_reserve_bytes(),
            policy.arena_eager_commit(),
            policy.allow_large_os_pages(),
        )
    }

    pub(crate) fn new(
        config: MemoryConfig,
        arena_count: usize,
        requested_size: usize,
        reserve_option_bytes: usize,
        eager_commit: i64,
        large_pages_enabled: bool,
    ) -> Option<Self> {
        if arena_count > MAX_ARENAS - 4 || reserve_option_bytes == 0 {
            return None;
        }
        let reserve = if config.has_virtual_reserve() {
            reserve_option_bytes
        } else {
            reserve_option_bytes / 4
        };
        // The option byte value is aligned with unsigned source arithmetic
        // before the minimum and maximum arena clamps. A valid large KiB
        // option can therefore wrap to zero and still select a bounded arena.
        let mut reserve = reserve.wrapping_add(ARENA_SLICE_SIZE - 1)
            & !(ARENA_SLICE_SIZE - 1);
        if (1..=128).contains(&arena_count) {
            let multiplier = 1usize << (arena_count / 8).min(16);
            // Source keeps the unscaled option when multiplication overflows.
            if let Some(scaled) = reserve.checked_mul(multiplier) {
                reserve = scaled;
            }
        }
        let required = invariants::align_up(
            requested_size.checked_add(ARENA_MAX_CHUNK_OBJ_SIZE)?,
            ARENA_MAX_CHUNK_OBJ_SIZE,
        )?;
        let primary_size = reserve.max(required).clamp(ARENA_MIN_SIZE, ARENA_MAX_SIZE);
        if primary_size < required {
            return None;
        }
        let commit = eager_commit == 1
            || (eager_commit == 2 && (config.has_overcommit() || large_pages_enabled));
        let small = 4 * ARENA_MIN_SIZE;
        Some(Self {
            primary_size,
            fallback_size: (primary_size > small && small > required).then_some(small),
            access: if commit { MapAccess::Committed } else { MapAccess::Reserved },
            adjust_committed: config.has_overcommit() && commit,
        })
    }
}

/// Source heap/thread inputs to one `mi_arenas_try_find_free` call. These
/// values describe the requesting source owner; they do not retain that Heap
/// or manufacture a replacement sequence/count authority.
#[derive(Clone, Copy)]
pub(crate) struct ArenaSearch {
    pub(crate) heap_sequence: usize,
    pub(crate) heap_count: usize,
    pub(crate) thread_sequence: usize,
    pub(crate) numa_node: i32,
    pub(crate) requested: ArenaId,
    pub(crate) allow_pinned: bool,
}

impl ArenaSearch {
    pub(crate) fn start_index(self, cycle: usize) -> usize {
        if cycle <= 1 {
            return 0;
        }
        if self.heap_sequence == 0 || self.heap_count <= 1 || cycle > 0x8ff {
            return self.thread_sequence % cycle;
        }
        let fraction = (cycle * 256) / self.heap_count;
        if fraction == 0 {
            return self.heap_sequence % cycle;
        }
        let mut start = (fraction * (self.heap_sequence % self.heap_count)) / 256;
        if fraction >= 512 {
            start += self.thread_sequence % (fraction / 256);
        }
        start
    }

    pub(crate) fn registry_index(count: usize, turn: usize, start: usize) -> Option<usize> {
        if turn >= count {
            return None;
        }
        let cycle = count - 1;
        if turn == cycle {
            return Some(turn);
        }
        let candidate = turn + start;
        Some(if candidate >= cycle { candidate - cycle } else { candidate })
    }
}

/// Source `mi_forall_suitable_arenas` traversal. A value retains only the
/// process registry and copied search inputs, never a page-engine borrow.
pub(crate) struct ArenaCandidates<'arena> {
    registry: &'arena ArenaRegistry,
    search: ArenaSearch,
    pass: usize,
    count: usize,
    turn: usize,
    start: usize,
    heap_list: Option<&'arena crate::types::heap_registry::SubprocessHeapList>,
}

impl<'arena> Iterator for ArenaCandidates<'arena> {
    type Item = ArenaView<'arena>;

    fn next(&mut self) -> Option<Self::Item> {
        let passes = if self.search.numa_node < 0 { 1 } else { 2 };
        while self.pass < passes {
            if self.turn >= self.count {
                self.pass += 1;
                if self.pass == passes { return None; }
                self.count = self.registry.count();
                if let Some(heap_list) = self.heap_list {
                    self.search.heap_count = heap_list.live_count_relaxed();
                }
                // Each NUMA pass observes one registry count and live Heap
                // count, and computes its spreading start once.
                // New publications become visible
                // when the next pass begins, without restarting this pass.
                self.start = self.search.start_index(self.count.saturating_sub(1));
                self.turn = 0;
                continue;
            }
            let turn = self.turn;
            self.turn += 1;
            let pointer = if !self.search.requested.as_ptr().is_null() {
                if turn != 0 { self.turn = self.count; continue; }
                self.search.requested.as_ptr()
            } else {
                let index = ArenaSearch::registry_index(self.count, turn, self.start)?;
                // SAFETY: construction retains all published arenas and
                // excludes destruction for the cursor's complete lifetime.
                match unsafe { self.registry.arena_at(index) } {
                    Some(arena) => core::ptr::from_ref(arena).cast_mut(),
                    None => continue,
                }
            };
            // SAFETY: a requested parent shares that same retained lifetime.
            let Some(arena) = (unsafe { pointer.as_ref() }) else { continue; };
            if !self.search.allow_pinned && arena.memid.is_pinned() { continue; }
            if !unsafe { arena_is_suitable(pointer, self.search.requested) } { continue; }
            if self.search.requested.as_ptr().is_null() {
                let numa_suitable = self.search.numa_node < 0 || arena.numa_node < 0
                    || arena.numa_node == self.search.numa_node;
                if numa_suitable != (self.pass == 0) { continue; }
            }
            return unsafe { ArenaView::from_ptr(pointer) };
        }
        None
    }
}

impl ArenaRegistry {
    /// # Safety
    /// Every published arena and `search.requested` must remain live through
    /// the cursor and every returned view; exclude registry destruction.
    pub(crate) unsafe fn suitable_arenas(&self, search: ArenaSearch) -> ArenaCandidates<'_> {
        unsafe { self.suitable_arenas_with_heap_list(search, None) }
    }

    /// Uses the retained subprocess's live Heap count at each source pass.
    /// The count grants no Heap lifetime; the caller separately retains the
    /// requesting Heap and registry throughout traversal and callbacks.
    ///
    /// # Safety
    /// Published arenas and any requested parent remain live through the
    /// cursor. A supplied list belongs to that same retained subprocess;
    /// neither registry destruction nor subprocess retirement may overlap.
    pub(crate) unsafe fn suitable_arenas_with_heap_list<'arena>(
        &'arena self, mut search: ArenaSearch,
        heap_list: Option<&'arena crate::types::heap_registry::SubprocessHeapList>,
    ) -> ArenaCandidates<'arena> {
        let count = self.count();
        if let Some(heap_list) = heap_list {
            search.heap_count = heap_list.live_count_relaxed();
        }
        let start = search.start_index(count.saturating_sub(1));
        ArenaCandidates { registry: self, search, pass: 0, count, turn: 0, start, heap_list }
    }

    /// Searches the source NUMA-preferred pass, then only nonpreferred arenas.
    /// The newest slot is tried last. A requested parent is tried once per
    /// pass, including the source's second attempt when NUMA is nonnegative.
    /// This function neither reserves a new arena nor falls back to the OS.
    ///
    /// # Safety
    ///
    /// Every published registry arena and `search.requested` must remain live
    /// for the returned claim's borrow of this registry. The caller must keep
    /// the source subprocess and any commit callback arguments alive for the
    /// same interval, and exclude registry destruction during this search.
    pub(crate) unsafe fn try_find_free(
        &self,
        search: ArenaSearch,
        slice_count: usize,
        alignment: usize,
        commit: bool,
    ) -> Option<ArenaSliceClaim<'_>> {
        unsafe {
            self.try_find_free_with(search, slice_count, alignment, |view| {
                view.try_claim_suitable_slices(search.requested, slice_count, commit, search.thread_sequence)
            })
        }
    }

    /// Shares the source candidate order with process-owned commitment. The
    /// callback may claim only the supplied live arena; failed claims continue
    /// the same pass rather than restarting or skipping its NUMA preference.
    pub(super) unsafe fn try_find_free_with<'arena>(
        &'arena self,
        search: ArenaSearch,
        slice_count: usize,
        alignment: usize,
        claim: impl FnMut(ArenaView<'arena>) -> Option<ArenaSliceClaim<'arena>>,
    ) -> Option<ArenaSliceClaim<'arena>> {
        unsafe { self.try_find_free_with_heap_list(search, None, slice_count, alignment, claim) }
    }

    /// Same candidate search with the caller's independently retained live
    /// Heap count. Every callback and any returned claim retain the original
    /// arena; a refusal changes neither that lifetime nor the next candidate.
    ///
    /// # Safety
    /// The original search obligations apply. A supplied Heap list belongs
    /// to the registry's retained subprocess and outlives every pass.
    pub(super) unsafe fn try_find_free_with_heap_list<'arena>(
        &'arena self, search: ArenaSearch,
        heap_list: Option<&'arena crate::types::heap_registry::SubprocessHeapList>,
        slice_count: usize, alignment: usize,
        mut claim: impl FnMut(ArenaView<'arena>) -> Option<ArenaSliceClaim<'arena>>,
    ) -> Option<ArenaSliceClaim<'arena>> {
        if alignment > ARENA_SLICE_SIZE || slice_count == 0 {
            return None;
        }
        // SAFETY: the caller retains the registry and requested parent for
        // this complete search and any returned live claim.
        for view in unsafe { self.suitable_arenas_with_heap_list(search, heap_list) } {
            if let Some(claim) = claim(view) { return Some(claim); }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::arena::manage_external_in_place;
    use crate::config::{ARENA_ALIGNMENT, GIB};
    use crate::os::{Mapping, PageSize};
    use crate::subproc::MainSubprocess;

    fn config(overcommit: bool) -> MemoryConfig {
        MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, overcommit, false)
    }

    fn search() -> ArenaSearch {
        ArenaSearch { heap_sequence: 0, heap_count: 1, thread_sequence: 0,
            numa_node: -1, requested: ArenaId::none(), allow_pinned: true }
    }

    #[test]
    fn reservation_size_option_alignment_wraps_before_source_minimum_clamp() {
        let reserve_bytes = (usize::MAX / 1024) * 1024;
        let plan = ArenaReservationPlan::new(config(true), 0, ARENA_SLICE_SIZE,
            reserve_bytes, 0, false).expect("wrapped reserve still accommodates a slice");
        // One requested slice plus a complete metadata chunk rounds to two
        // chunks before the arena bounds are applied.
        assert_eq!(plan.primary_size, 2 * ARENA_MIN_SIZE);
        assert_eq!(plan.fallback_size, None);
    }

    #[test]
    fn reservation_scales_only_counts_one_through_128_and_preserves_fallback_headroom() {
        for (count, expected) in [(0, GIB), (7, GIB), (8, 2 * GIB), (16, 4 * GIB),
                                  (128, ARENA_MAX_SIZE), (129, GIB)] {
            let plan = ArenaReservationPlan::new(config(true), count, ARENA_SLICE_SIZE,
                GIB, 2, false).unwrap();
            assert_eq!(plan.primary_size, expected);
            assert_eq!(plan.fallback_size, Some(4 * ARENA_MIN_SIZE));
            assert_eq!(plan.access, MapAccess::Committed);
            assert!(plan.adjust_committed);
        }
        assert!(ArenaReservationPlan::new(config(true), MAX_ARENAS - 3,
            ARENA_SLICE_SIZE, GIB, 2, false).is_none());
        assert!(ArenaReservationPlan::new(config(true), 0, ARENA_SLICE_SIZE,
            0, 2, false).is_none());
        assert!(ArenaReservationPlan::new(config(true), 0, ARENA_MAX_SIZE,
            GIB, 2, false).is_none());
        let equal_headroom = 3 * ARENA_MIN_SIZE;
        assert_eq!(ArenaReservationPlan::new(config(true), 0, equal_headroom,
            GIB, 2, false).unwrap().fallback_size, None);
        for (eager, large, commit) in [(0,false,false), (1,false,true), (2,false,false),
                                      (2,true,true), (3,true,false)] {
            let plan = ArenaReservationPlan::new(config(false), 0, ARENA_SLICE_SIZE,
                GIB, eager, large).unwrap();
            assert_eq!(plan.access, if commit { MapAccess::Committed } else { MapAccess::Reserved });
            assert!(!plan.adjust_committed);
        }
    }

    #[test]
    fn registry_search_prefers_numa_and_retains_exact_requested_and_pinned_boundaries() {
        let subprocess = MainSubprocess::new();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let mut mappings = std::vec::Vec::new();
        let mut identities = std::vec::Vec::new();
        for numa in [0, 1, -1] {
            let mapping = Mapping::map_aligned_for_allocator(config(false), ARENA_MIN_SIZE,
                ARENA_ALIGNMENT, MapAccess::Committed).unwrap();
            // SAFETY: mappings and subprocess remain live until every claim
            // is released below; no registry destruction races these calls.
            let managed = unsafe { manage_external_in_place(&registry,
                mapping.base().unwrap(), ARENA_MIN_SIZE, config(false).page_size(),
                true, false, true, numa, false, None) }.unwrap();
            identities.push(managed.arena_id());
            mappings.push(mapping);
        }
        let mut request = search();
        request.numa_node = 1;
        let claim = unsafe { registry.try_find_free(request, 1, ARENA_SLICE_SIZE, true) }.unwrap();
        assert_eq!(claim.memory_id().arena_memory().unwrap().arena, identities[1].as_ptr());
        assert!(claim.release());
        request.numa_node = 8;
        let claim = unsafe { registry.try_find_free(request, 1, ARENA_SLICE_SIZE, true) }.unwrap();
        assert_eq!(claim.memory_id().arena_memory().unwrap().arena, identities[2].as_ptr());
        assert!(claim.release());
        request.requested = identities[0];
        let claim = unsafe { registry.try_find_free(request, 1, ARENA_SLICE_SIZE, true) }.unwrap();
        assert_eq!(claim.memory_id().arena_memory().unwrap().arena, identities[0].as_ptr());
        assert!(claim.release());
        // SAFETY: all claims were released, no concurrent reader exists, and
        // the mapping keeps this source header live for the remaining calls.
        unsafe { (*identities[0].as_ptr()).memid.is_pinned = true; }
        request.allow_pinned = false;
        assert!(unsafe { registry.try_find_free(request, 1, ARENA_SLICE_SIZE, true) }.is_none());
        request.allow_pinned = true;
        let claim = unsafe { registry.try_find_free(request, 1, ARENA_SLICE_SIZE, true) }.unwrap();
        assert!(claim.memory_id().is_pinned());
        assert!(claim.release());
        assert!(unsafe { registry.try_find_free(request, 1, 2 * ARENA_SLICE_SIZE, true) }.is_none());
        // No claim or arena view survives the explicit mapping release.
        for mut mapping in mappings { mapping.unmap().unwrap(); }
    }

    #[test]
    fn failed_candidates_refresh_registry_and_spreading_at_the_numa_pass_boundary() {
        let subprocess = MainSubprocess::new();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let mut mappings = std::vec::Vec::new();
        let mut identities = std::vec::Vec::new();
        for _ in 0..4 {
            mappings.push(Mapping::map_aligned_for_allocator(config(false), ARENA_MIN_SIZE,
                ARENA_ALIGNMENT, MapAccess::Committed).unwrap());
        }
        for (index, numa) in [0, 1, 0].into_iter().enumerate() {
            // SAFETY: the retained caller-owned mappings and subprocess
            // outlive every view and claim; destruction is excluded.
            let managed = unsafe { manage_external_in_place(&registry,
                mappings[index].base().unwrap(), ARENA_MIN_SIZE, config(false).page_size(),
                true, false, true, numa, false, None) }.unwrap();
            identities.push(managed.arena_id());
        }
        let request = ArenaSearch { heap_sequence: 2, heap_count: 3,
            numa_node: 1, ..search() };
        let mut attempted = std::vec::Vec::new();
        // SAFETY: all candidate mappings remain live, including the new
        // publication. Each refusal consumes no claim; only the final
        // candidate issues one outstanding claim returned below.
        let claim = unsafe { registry.try_find_free_with(request, 1, ARENA_SLICE_SIZE, |view| {
            attempted.push(core::ptr::from_ref(view.arena()).cast_mut());
            if attempted.len() == 1 {
                let managed = manage_external_in_place(&registry,
                    mappings[3].base().unwrap(), ARENA_MIN_SIZE, config(false).page_size(),
                    true, false, true, 0, false, None).unwrap();
                identities.push(managed.arena_id());
            }
            if attempted.len() < 4 { return None; }
            view.try_claim_suitable_slices(request.requested, 1, true, request.thread_sequence)
        }) }.unwrap();
        assert_eq!(attempted, std::vec![identities[1].as_ptr(), identities[2].as_ptr(),
            identities[0].as_ptr(), identities[3].as_ptr()]);
        assert_eq!(claim.memory_id().arena_memory().unwrap().arena, identities[3].as_ptr());
        assert!(claim.release());
        for mut mapping in mappings { mapping.unmap().unwrap(); }
    }

    #[test]
    fn requested_exhaustion_preserves_sibling_and_exact_released_slice_retry() {
        let subprocess = MainSubprocess::new();
        let registry = ArenaRegistry::new(subprocess.as_ptr());
        let mut mappings = std::vec::Vec::new();
        let mut identities = std::vec::Vec::new();
        for numa in [0, 1] {
            let mapping = Mapping::map_aligned_for_allocator(config(false), ARENA_MIN_SIZE,
                ARENA_ALIGNMENT, MapAccess::Committed).unwrap();
            // SAFETY: these caller-owned mappings and subprocess remain live
            // until all exact claims below are released; no destruction races.
            let managed = unsafe { manage_external_in_place(&registry, mapping.base().unwrap(),
                ARENA_MIN_SIZE, config(false).page_size(), true, false, true, numa, false, None) }.unwrap();
            identities.push(managed.arena_id());
            mappings.push(mapping);
        }
        let requested = ArenaSearch { requested: identities[0], numa_node: 1, ..search() };
        let mut held = std::vec::Vec::new();
        while let Some(claim) = unsafe { registry.try_find_free(requested, 1, ARENA_SLICE_SIZE, true) } {
            assert_eq!(claim.memory_id().arena_memory().unwrap().arena, identities[0].as_ptr());
            held.push(claim);
        }
        assert!(!held.is_empty());
        // Exhaustion of a requested parent cannot consume a sibling span.
        assert!(unsafe { registry.try_find_free(requested, 1, ARENA_SLICE_SIZE, true) }.is_none());
        let sibling = unsafe { registry.try_find_free(ArenaSearch { numa_node: 1, ..search() },
            1, ARENA_SLICE_SIZE, true) }.unwrap();
        assert_eq!(sibling.memory_id().arena_memory().unwrap().arena, identities[1].as_ptr());
        assert!(sibling.release());
        let released = held.pop().unwrap();
        let address = released.start();
        assert!(released.release());
        let mut attempts = 0;
        // A clean refusal on the first NUMA pass retains exact slice custody;
        // the requested parent is retried on the second pass despite affinity.
        let retry = unsafe { registry.try_find_free_with(requested, 1, ARENA_SLICE_SIZE, |view| {
            attempts += 1;
            assert_eq!(core::ptr::from_ref(view.arena()).cast_mut(), identities[0].as_ptr());
            if attempts == 1 { return None; }
            view.try_claim_suitable_slices(requested.requested, 1, true, requested.thread_sequence)
        }) }.unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(retry.start(), address);
        assert!(retry.release());
        for claim in held { assert!(claim.release()); }
        for mut mapping in mappings { mapping.unmap().unwrap(); }
    }

    #[test]
    fn emit_native_arena_search_order_trace() {
        let mut ordinal = 0;
        for count in [0, 1, 2, 3, 8, 17, 129, 2305] {
            for heap_count in [0, 1, 2, 3, 8, 1024, 1_000_000] {
                for heap_sequence in [0, 1, 7, usize::MAX] {
                    for thread_sequence in [0, 1, 5, usize::MAX] {
                        let request = ArenaSearch { heap_count, heap_sequence,
                            thread_sequence, ..search() };
                        let cycle = if count == 0 { 0 } else { count - 1 };
                        std::println!("m2.arena.selection.{ordinal}={}", request.start_index(cycle));
                        ordinal += 1;
                        let mut seen = std::vec![false; count];
                        for turn in 0..count {
                            let index = ArenaSearch::registry_index(count, turn, request.start_index(cycle)).unwrap();
                            assert!(!seen[index]);
                            seen[index] = true;
                            if turn == count - 1 { assert_eq!(index, turn); }
                        }
                        assert!(ArenaSearch::registry_index(count, count, request.start_index(cycle)).is_none());
                    }
                }
            }
        }
        assert_eq!(ordinal, 896);
    }
}
