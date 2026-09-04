// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: pinned mimalloc v3.5.0 src/arena.c:341-406,417-569.
//
//! Arena reservation geometry and source-order registry search. Option values
//! are snapshots read by the process VM owner, not a second option store.
//! M2 owns backing selection, memory provenance and release. Page queues and
//! Heap/Theap lifetime remain the consuming M3/M6 owners.

use super::{ArenaId, ArenaRegistry, ArenaSliceClaim, ArenaView, arena_is_suitable};
use crate::config::{
    ARENA_MAX_CHUNK_OBJ_SIZE, ARENA_MAX_SIZE, ARENA_MIN_SIZE,
    ARENA_SLICE_SIZE, MAX_ARENAS,
};
use crate::invariants;
use crate::os::{MapAccess, MemoryConfig};

/// The two possible source reservation attempts, before any mapping or stats
/// mutation. A fallback is permitted only after clean failure of the primary;
/// retained mapping ownership is never permission for another attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArenaReservationPlan {
    pub(crate) primary_size: usize,
    pub(crate) fallback_size: Option<usize>,
    pub(crate) access: MapAccess,
    pub(crate) adjust_committed: bool,
}

impl ArenaReservationPlan {
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
        let mut reserve = invariants::align_up(reserve, ARENA_SLICE_SIZE)?;
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
    fn start_index(self, cycle: usize) -> usize {
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

    fn registry_index(self, count: usize, turn: usize) -> Option<usize> {
        if turn >= count {
            return None;
        }
        let cycle = count - 1;
        if turn == cycle {
            return Some(turn);
        }
        let candidate = turn + self.start_index(cycle);
        Some(if candidate >= cycle { candidate - cycle } else { candidate })
    }
}

impl ArenaRegistry {
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
        if alignment > ARENA_SLICE_SIZE || slice_count == 0 {
            return None;
        }
        let passes = if search.numa_node < 0 { 1 } else { 2 };
        for pass in 0..passes {
            // The source takes a new relaxed high-water snapshot per pass.
            let count = self.count();
            for turn in 0..count {
                let pointer = if !search.requested.as_ptr().is_null() {
                    if turn != 0 { break; }
                    search.requested.as_ptr()
                } else {
                    let index = search.registry_index(count, turn)?;
                    match unsafe { self.arena_at(index) } {
                        Some(arena) => core::ptr::from_ref(arena).cast_mut(),
                        None => continue,
                    }
                };
                let Some(arena) = (unsafe { pointer.as_ref() }) else { continue; };
                if !search.allow_pinned && arena.memid.is_pinned() { continue; }
                if !unsafe { arena_is_suitable(pointer, search.requested) } { continue; }
                if search.requested.as_ptr().is_null() {
                    let numa_suitable = search.numa_node < 0 || arena.numa_node < 0
                        || arena.numa_node == search.numa_node;
                    if numa_suitable != (pass == 0) { continue; }
                }
                let view = unsafe { ArenaView::from_ptr(pointer) }?;
                if let Some(claim) = view.try_claim_suitable_slices(
                    search.requested, slice_count, commit, search.thread_sequence,
                ) {
                    return Some(claim);
                }
            }
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
                            let index = request.registry_index(count, turn).unwrap();
                            assert!(!seen[index]);
                            seen[index] = true;
                            if turn == count - 1 { assert_eq!(index, turn); }
                        }
                        assert!(request.registry_index(count, count).is_none());
                    }
                }
            }
        }
        assert_eq!(ordinal, 896);
    }
}
