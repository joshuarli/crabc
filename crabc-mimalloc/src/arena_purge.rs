// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: pinned mimalloc v3.5.0 src/arena.c:1433-1483,2238-2447.

//! Source policy-aware release, delayed purge and subprocess purge traversal.
//! The arena owner retains both the bitmap range and its exact VM pair; it
//! does not route ordinary OS backing through an external callback policy.

use super::{OwnedArenaMapping, ProcessArenaBacking};
use crate::arena::{ArenaView, arena_slice_range_is_usable};
use crate::atomic::{AtomicGuardWord, i64_cas_strong_acq_rel, i64_load_relaxed,
    i64_store_release, try_atomic_guard};
use crate::config::ARENA_SLICE_SIZE;
use crate::invariants;
use crate::os::{self, MemoryConfig, VmProcess};
use crate::types::MemoryId;
use core::sync::atomic::Ordering;

// Source mi_arenas_try_purge has one process-global, nonblocking guard, not
// one blocking purge mutex per subprocess or per arena.
pub(super) static PURGE_GUARD: AtomicGuardWord = AtomicGuardWord::new(0);

fn purge_delay(delay: i64, multiplier: i64) -> i64 {
    if delay < 0 || multiplier < 0 { return -1; }
    if delay == 0 || multiplier == 0 { return 0; }
    match (delay as usize).checked_mul(multiplier as usize) {
        Some(total) if total <= i64::MAX as usize => total as i64,
        _ => delay,
    }
}

#[cfg(test)]
mod tests {
    use super::purge_delay;

    #[test]
    fn source_purge_delay_retains_disabled_immediate_and_overflow_fallbacks() {
        assert_eq!(purge_delay(1000, 4), 4000);
        assert_eq!(purge_delay(-1, 0), -1);
        assert_eq!(purge_delay(0, -1), -1);
        assert_eq!(purge_delay(0, 4), 0);
        assert_eq!(purge_delay(1000, 0), 0);
        assert_eq!(purge_delay(i64::MAX, 2), i64::MAX);
        assert_eq!(purge_delay(i64::MAX, i64::MAX), i64::MAX);
        assert_eq!(purge_delay(i64::MAX / 4, 4), (i64::MAX / 4) * 4);
    }
}

impl ProcessArenaBacking {
    /// Returns an exact process-owned slice span through `_mi_arenas_free`.
    /// The optional purge precedes the free-bitmap set, including immediate
    /// purging while the caller still owns the range.
    ///
    /// # Safety
    ///
    /// `memory` must represent this process owner's one outstanding arena
    /// claim. All page aliases, PageMap readers and producers must already be
    /// quiescent for that span. No second release may overlap this one.
    pub(crate) unsafe fn release_slices(&self, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        let Some(view) = (unsafe { ArenaView::from_ptr(memory.arena) }) else { return false; };
        let arena = view.arena();
        let start = memory.slice_index as usize;
        let count = memory.slice_count as usize;
        if !arena_slice_range_is_usable(arena, start, count) { return false; }
        let Some(owner) = (unsafe { self.mapping_for_arena(arena) }) else { return false; };
        if !self.schedule_purge(&view, owner, start, count) { return false; }
        unsafe { view.slices_free() }.and_then(|free| free.set_range(start, count)) == Some(true)
    }

    fn schedule_purge(&self, view: &ArenaView<'_>, owner: &OwnedArenaMapping,
        start: usize, count: usize) -> bool {
        let policy = owner.process.policy();
        let delay = purge_delay(policy.purge_delay_milliseconds(), policy.arena_purge_multiplier());
        if view.arena().memid.is_pinned() || delay < 0 || owner.process.is_preloading() { return true; }
        if delay == 0 { return purge_claimed(view, owner, start, count).is_some(); }
        let Ok(now) = os::monotonic_milliseconds() else { return true; };
        // The source clock is nonnegative and successful native deadlines
        // remain representable. An unavailable/overflowing clock must not
        // turn optional purge into ownership loss.
        let Some(expire) = now.checked_add(delay) else { return true; };
        let mut expected = 0;
        if i64_cas_strong_acq_rel(&view.arena().purge_expire, &mut expected, expire) {
            let mut global_expected = 0;
            let _ = i64_cas_strong_acq_rel(&self.purge_expire, &mut global_expected, expire);
        }
        unsafe { view.slices_purge() }.and_then(|purge| purge.set_range(start, count)).is_some()
    }

    /// Runs `mi_arenas_try_purge` with its nonblocking global guard, source
    /// traversal rotation, visit budget and subprocess expiration state.
    /// Returning false reports a violated internal bitmap/backing invariant;
    /// advisory VM failures retain source scheduling behavior, not a new
    /// retry schedule or a second statistics update.
    ///
    /// # Safety
    ///
    /// `process` and `config` must be this owner's fixed binding, and every
    /// published arena must remain live throughout the traversal. Outstanding
    /// allocations obey the source atomic free-bitmap ownership protocol.
    pub(crate) unsafe fn collect_purge(&self, process: VmProcess<'_>, config: MemoryConfig,
        force: bool, visit_all: bool, thread_sequence: usize) -> bool {
        let policy = process.policy();
        let delay = purge_delay(policy.purge_delay_milliseconds(), policy.arena_purge_multiplier());
        if process.is_preloading() || delay <= 0 { return true; }
        let Ok(now) = os::monotonic_milliseconds() else { return true; };
        self.collect_purge_at(process, config, force, visit_all, thread_sequence, now, delay)
    }

    fn collect_purge_at(&self, process: VmProcess<'_>, config: MemoryConfig,
        force: bool, visit_all: bool, thread_sequence: usize, now: i64, delay: i64) -> bool {
        let global_expire = self.purge_expire.load(Ordering::Acquire);
        if !visit_all && !force && (global_expire == 0 || global_expire > now) { return true; }
        let count = self.registry.count();
        if count == 0 { return true; }
        let Some(_guard) = try_atomic_guard(&PURGE_GUARD) else { return true; };
        if global_expire > now {
            if let Some(next) = now.checked_add(delay / 10) { i64_store_release(&self.purge_expire, next); }
        }
        let start = thread_sequence % count;
        let mut budget = if visit_all { count } else { count / 4 + 1 };
        let mut all_visited = true;
        let mut any_pending_or_purged = false;
        for turn in 0..count {
            let candidate = turn + start;
            let index = if candidate >= count { candidate - count } else { candidate };
            let Some(arena) = (unsafe { self.registry.arena_at(index) }) else { continue; };
            let Some(view) = (unsafe { ArenaView::from_ptr(core::ptr::from_ref(arena).cast_mut()) }) else { return false; };
            let Some(owner) = (unsafe { self.mapping_for_arena(arena) }) else { return false; };
            if !core::ptr::eq(owner.process.policy(), process.policy()) || owner.config != config { return false; }
            let Some(purged) = self.try_purge_arena(&view, owner, now, force) else { return false; };
            if purged >= 0 {
                any_pending_or_purged = true;
                if purged >= 1 {
                    if budget <= 1 { all_visited = false; break; }
                    budget -= 1;
                }
            }
        }
        if all_visited && !any_pending_or_purged { i64_store_release(&self.purge_expire, 0); }
        true
    }

    fn try_purge_arena(&self, view: &ArenaView<'_>, owner: &OwnedArenaMapping,
        now: i64, force: bool) -> Option<i8> {
        let arena = view.arena();
        if arena.memid.is_pinned() { return Some(-1); }
        let expire = i64_load_relaxed(&arena.purge_expire);
        if expire == 0 { return Some(-1); }
        if !force && expire > now { return Some(0); }
        i64_store_release(&arena.purge_expire, 0);
        self.arena_purges.increase(1);
        let purge = unsafe { view.slices_purge() }?;
        let minimum = invariants::slice_count_of_size(owner.process.policy().minimal_purge_size(owner.config))?;
        let mut any_purged = false;
        let mut valid = true;
        let visited = purge.visit_set_ranges_clear_aligned(minimum, |start, count| {
            match try_purge_range(view, owner, start, count) {
                Some(true) => any_purged = true,
                Some(false) if count > 1 => {
                    for offset in 0..count {
                        match try_purge_range(view, owner, start + offset, 1) {
                            Some(purged) => any_purged |= purged,
                            None => { valid = false; return false; }
                        }
                    }
                }
                Some(false) => {}
                None => { valid = false; return false; }
            }
            true
        });
        (visited && valid).then_some(if any_purged { 1 } else { -1 })
    }
}

/// Purges only after successful free-bitmap exclusion, then restores the
/// exact source availability range irrespective of advisory VM success.
fn try_purge_range(view: &ArenaView<'_>, owner: &OwnedArenaMapping,
    start: usize, count: usize) -> Option<bool> {
    let free = unsafe { view.slices_free() }?;
    if !free.try_clear_within_chunk(start, count)? { return Some(false); }
    let result = purge_claimed(view, owner, start, count);
    let restored = free.set_range(start, count) == Some(true);
    if result.is_none() || !restored { return None; }
    Some(true)
}

/// Source `mi_arena_purge`: count the mixed commitment observation before
/// calling the exact paired VM policy; preserve Linux's no-recommit outcome
/// even when MADV_DONTNEED reports an advisory error.
fn purge_claimed(view: &ArenaView<'_>, owner: &OwnedArenaMapping,
    start: usize, count: usize) -> Option<bool> {
    let committed = unsafe { view.slices_committed() }?;
    let transition = committed.set_range(start, count)?;
    let all_committed = transition.already_set() == count;
    let address = view.slice_start(start)?;
    let offset = (address as usize).checked_sub(owner.mapping.base().ok()? as usize)?;
    let size = count.checked_mul(ARENA_SLICE_SIZE)?;
    let stat_size = transition.already_set().checked_mul(ARENA_SLICE_SIZE)?;
    let needs_recommit = owner.mapping.purge_for_process(owner.process, offset, size,
        all_committed, stat_size).unwrap_or(false);
    if needs_recommit || !all_committed { committed.clear_range(start, count)?; }
    Some(needs_recommit)
}
