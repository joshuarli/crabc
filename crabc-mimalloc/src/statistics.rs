// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/stats.c:25-63`,
// `include/mimalloc-stats.h:29-116`, and
// `include/mimalloc/internal.h:394-398`.

//! Typed unconditional subprocess statistics used by the staged allocator.
//!
//! These are source event records, not a public `mi_stats_t` layout or an
//! optional `MI_STAT` reporting implementation.  The pinned macros execute
//! their count/counter updates even at `MI_STAT=0`; each owner therefore names
//! only the fields it actually drives and cannot turn a VM event into an
//! untracked observer callback.

use crate::atomic::{
    i64_add_from_relaxed, i64_add_relaxed, i64_load_relaxed, i64_max_relaxed, AtomicI64Value,
};

/// Source `mi_stat_count_t` using `mi_stat_update_mt`'s relaxed update order.
pub(crate) struct StatCount {
    pub(crate) total: AtomicI64Value,
    pub(crate) peak: AtomicI64Value,
    pub(crate) current: AtomicI64Value,
}

impl StatCount {
    pub(crate) const fn new() -> Self {
        Self {
            total: AtomicI64Value::new(0),
            peak: AtomicI64Value::new(0),
            current: AtomicI64Value::new(0),
        }
    }

    /// Mirrors `mi_stat_update_mt`: current, then peak, then positive total.
    #[inline]
    pub(crate) fn update(&self, amount: i64) {
        if amount == 0 {
            return;
        }
        let previous = i64_add_relaxed(&self.current, amount);
        i64_max_relaxed(&self.peak, previous.wrapping_add(amount));
        if amount > 0 {
            i64_add_relaxed(&self.total, amount);
        }
    }

    /// Mirrors `mi_stat_adjust_mt`, used only to repair source accounting
    /// around partially committed ranges. It is intentionally distinct from
    /// [`Self::update`]: the total may move down and peak moves only when it
    /// exactly matched the prior total.
    #[inline]
    pub(crate) fn adjust(&self, amount: i64) {
        if amount == 0 {
            return;
        }
        let peak = i64_load_relaxed(&self.peak);
        i64_add_relaxed(&self.current, amount);
        let prior_total = i64_add_relaxed(&self.total, amount);
        if prior_total == peak {
            i64_add_relaxed(&self.peak, amount);
        }
    }

    /// Adds one selected source record in `mi_stats_add` order.
    ///
    /// Pinned `src/stats.c:99-114` first adds `total`, then samples the
    /// source peak and current values, adds current, and finally raises the
    /// destination peak from that prior destination current plus source peak.
    /// These are deliberately relaxed, non-transactional observations: a
    /// concurrent source update may appear in only part of this aggregation,
    /// exactly as it may in the C implementation.
    #[inline]
    fn add_from(&self, source: &Self) {
        if core::ptr::eq(self, source) {
            return;
        }
        i64_add_from_relaxed(&self.total, &source.total);
        let source_peak = i64_load_relaxed(&source.peak);
        let source_current = i64_load_relaxed(&source.current);
        let destination_current = i64_add_relaxed(&self.current, source_current);
        i64_max_relaxed(
            &self.peak,
            destination_current.wrapping_add(source_peak),
        );
    }
}

/// Source `mi_stat_counter_t`: a relaxed, monotonically increasing total.
pub(crate) struct StatCounter {
    pub(crate) total: AtomicI64Value,
}

/// The two unconditional subprocess counter fields driven by the selected
/// arena lifecycle receiver.
///
/// Source map: pinned mimalloc v3.5.0 `src/arena.c:1573-1605` increments
/// `arena_count` only after a fresh high-water slot has published its arena
/// pointer; `src/arena.c:2362-2385` increments `arena_purges` immediately
/// after consuming an eligible expiry. Both calls expand through
/// `include/mimalloc/internal.h:394` to the relaxed counter operation in
/// `src/stats.c:43-45`. This remains a private process event owner, not a
/// `mi_stats_t` layout, statistics collector, or reporting API.
pub(crate) struct ArenaStatistics {
    arena_count: StatCounter,
    arena_purges: StatCounter,
}

/// One read-only observation of the selected source arena lifecycle events.
///
/// This evidence-only value deliberately exposes no generic adjustment path:
/// its two fields name the exact pinned `mi_stats_t` counters that the bounded
/// Rust arena registry and delayed-purge receivers mutate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArenaStatisticsSnapshot {
    pub(crate) arena_count: i64,
    pub(crate) arena_purges: i64,
}

impl ArenaStatistics {
    pub(crate) const fn new() -> Self {
        Self {
            arena_count: StatCounter::new(),
            arena_purges: StatCounter::new(),
        }
    }

    /// Records the source's successful fresh high-water arena publication.
    #[inline]
    pub(crate) fn high_water_arena_published(&self) {
        self.arena_count.increase(1);
    }

    /// Records the source's consumption of an eligible arena purge expiry.
    #[inline]
    pub(crate) fn arena_purge_expiry_consumed(&self) {
        self.arena_purges.increase(1);
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> ArenaStatisticsSnapshot {
        ArenaStatisticsSnapshot {
            arena_count: i64_load_relaxed(&self.arena_count.total),
            arena_purges: i64_load_relaxed(&self.arena_purges.total),
        }
    }
}

impl StatCounter {
    pub(crate) const fn new() -> Self {
        Self {
            total: AtomicI64Value::new(0),
        }
    }

    #[inline]
    pub(crate) fn increase(&self, amount: usize) {
        // The pinned macro casts its `size_t` argument directly to int64_t.
        // Both native profiles are two's-complement LP64, so Rust's explicit
        // narrowing cast retains that source bit pattern.
        i64_add_relaxed(&self.total, amount as i64);
    }

    /// Mirrors `mi_stat_counter_add_mt` for one selected source field.
    #[inline]
    fn add_from(&self, source: &Self) {
        if core::ptr::eq(self, source) {
            return;
        }
        i64_add_from_relaxed(&self.total, &source.total);
    }
}

/// The exact subprocess statistics fields reached by `src/os.c` VM paths.
///
/// It intentionally leaves heap/theap aggregation and the rest of
/// `mi_stats_t` out of scope. `MainSubprocess` owns this state alongside its
/// bitmap subset, so VM map/commit/release paths have the same lifetime as the
/// source subprocess rather than a detached test-only counter.
pub(crate) struct VmStatistics {
    reserved: StatCount,
    committed: StatCount,
    reset: StatCounter,
    purged: StatCounter,
    mmap_calls: StatCounter,
    commit_calls: StatCounter,
    reset_calls: StatCounter,
    purge_calls: StatCounter,
}

/// One read-only observation of the VM counters driven by this component.
///
/// This is evidence data, not a generalized statistics ABI: field names track
/// the exact pinned `src/os.c` counters and count records that this owner
/// mutates. It lets native differential tests assert source event timing
/// without exposing a generic arbitrary-adjust API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VmStatisticsSnapshot {
    pub(crate) reserved_total: i64,
    pub(crate) reserved_peak: i64,
    pub(crate) reserved_current: i64,
    pub(crate) committed_total: i64,
    pub(crate) committed_peak: i64,
    pub(crate) committed_current: i64,
    pub(crate) reset: i64,
    pub(crate) purged: i64,
    pub(crate) mmap_calls: i64,
    pub(crate) commit_calls: i64,
    pub(crate) reset_calls: i64,
    pub(crate) purge_calls: i64,
}

impl VmStatistics {
    pub(crate) const fn new() -> Self {
        Self {
            reserved: StatCount::new(),
            committed: StatCount::new(),
            reset: StatCounter::new(),
            purged: StatCounter::new(),
            mmap_calls: StatCounter::new(),
            commit_calls: StatCounter::new(),
            reset_calls: StatCounter::new(),
            purge_calls: StatCounter::new(),
        }
    }

    #[inline]
    pub(crate) fn mmap_call(&self) { self.mmap_calls.increase(1); }

    #[inline]
    pub(crate) fn reserve_increase(&self, bytes: usize) {
        self.reserved.update(bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn reserve_decrease(&self, bytes: usize) {
        self.reserved.update(-bytes_to_i64(bytes));
    }

    /// Mirrors `_mi_stat_adjust_decrease(&_mi_stats_main.reserved, ...)` in
    /// the partial-overmap release path.  This is intentionally not folded
    /// into [`Self::reserve_decrease`]: `mi_stat_adjust_mt` has different
    /// total/peak behavior from `mi_stat_update_mt`.
    #[inline]
    pub(crate) fn reserved_adjust_decrease(&self, bytes: usize) {
        self.reserved.adjust(-bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_increase(&self, bytes: usize) {
        self.committed.update(bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_decrease(&self, bytes: usize) {
        self.committed.update(-bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_adjust_increase(&self, bytes: usize) {
        self.committed.adjust(bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_adjust_decrease(&self, bytes: usize) {
        self.committed.adjust(-bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn commit_call(&self) { self.commit_calls.increase(1); }

    #[inline]
    pub(crate) fn reset(&self, bytes: usize) {
        self.reset.increase(bytes);
        self.reset_calls.increase(1);
    }

    #[inline]
    pub(crate) fn purge(&self, bytes: usize) {
        self.purged.increase(bytes);
        self.purge_calls.increase(1);
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> VmStatisticsSnapshot {
        VmStatisticsSnapshot {
            reserved_total: i64_load_relaxed(&self.reserved.total),
            reserved_peak: i64_load_relaxed(&self.reserved.peak),
            reserved_current: i64_load_relaxed(&self.reserved.current),
            committed_total: i64_load_relaxed(&self.committed.total),
            committed_peak: i64_load_relaxed(&self.committed.peak),
            committed_current: i64_load_relaxed(&self.committed.current),
            reset: i64_load_relaxed(&self.reset.total),
            purged: i64_load_relaxed(&self.purged.total),
            mmap_calls: i64_load_relaxed(&self.mmap_calls.total),
            commit_calls: i64_load_relaxed(&self.commit_calls.total),
            reset_calls: i64_load_relaxed(&self.reset_calls.total),
            purge_calls: i64_load_relaxed(&self.purge_calls.total),
        }
    }
}

/// The selected process-owned subset of source `mi_subproc_t::stats`.
///
/// Pinned `include/mimalloc/types.h:651-680` gives every subprocess one
/// `mi_stats_t`, rather than independent VM and arena statistic objects.
/// The staged port represents only the fields its current source-mapped
/// production paths drive: the `src/os.c` VM fields and the two `src/arena.c`
/// lifecycle counters. It deliberately excludes the public layout/header,
/// reporting, callback, heap, and Theap fields.
pub(crate) struct SubprocessStatistics {
    vm: VmStatistics,
    arena: ArenaStatistics,
}

/// A read-only selected snapshot of one subprocess statistics owner.
///
/// Each member is relaxed independently, as are the source reads. Consumers
/// must not treat this as a consistent point-in-time public `mi_stats_t` ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SubprocessStatisticsSnapshot {
    pub(crate) vm: VmStatisticsSnapshot,
    pub(crate) arena: ArenaStatisticsSnapshot,
}

impl SubprocessStatistics {
    pub(crate) const fn new() -> Self {
        Self {
            vm: VmStatistics::new(),
            arena: ArenaStatistics::new(),
        }
    }

    #[inline]
    pub(crate) fn vm(&self) -> &VmStatistics {
        &self.vm
    }

    #[inline]
    pub(crate) fn arena(&self) -> &ArenaStatistics {
        &self.arena
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> SubprocessStatisticsSnapshot {
        SubprocessStatisticsSnapshot {
            vm: self.vm.snapshot(),
            arena: self.arena.snapshot(),
        }
    }

    /// Merges the selected fields using the filtered `MI_STAT_FIELDS()` order.
    ///
    /// This is the private equivalent of `mi_stats_add` in
    /// `src/stats.c:121-142`. The source applies it during non-main subprocess
    /// teardown, which the staged port does not yet model. The field order is
    /// material: adding a count samples and updates its own relaxed atomics
    /// before the next field. A future owner may add a source field only at
    /// its declaration position here, with its real producer and source-level
    /// evidence; this is not a generic counter registry.
    #[inline]
    pub(crate) fn add_from(&self, source: &Self) {
        if core::ptr::eq(self, source) {
            return;
        }

        // Selected `MI_STAT_FIELDS()` declaration order from
        // `include/mimalloc-stats.h:41-82`.
        self.vm.reserved.add_from(&source.vm.reserved);
        self.vm.committed.add_from(&source.vm.committed);
        self.vm.reset.add_from(&source.vm.reset);
        self.vm.purged.add_from(&source.vm.purged);
        self.vm.mmap_calls.add_from(&source.vm.mmap_calls);
        self.vm.commit_calls.add_from(&source.vm.commit_calls);
        self.vm.reset_calls.add_from(&source.vm.reset_calls);
        self.vm.purge_calls.add_from(&source.vm.purge_calls);
        self.arena.arena_count.add_from(&source.arena.arena_count);
        self.arena.arena_purges.add_from(&source.arena.arena_purges);
    }
}

#[inline]
fn bytes_to_i64(bytes: usize) -> i64 {
    bytes as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_update_and_adjust_preserve_the_two_source_algorithms() {
        let count = StatCount::new();
        count.update(10);
        count.update(-4);
        assert_eq!(i64_load_relaxed(&count.current), 6);
        assert_eq!(i64_load_relaxed(&count.total), 10);
        assert_eq!(i64_load_relaxed(&count.peak), 10);

        count.adjust(-2);
        assert_eq!(i64_load_relaxed(&count.current), 4);
        assert_eq!(i64_load_relaxed(&count.total), 8);
        assert_eq!(
            i64_load_relaxed(&count.peak),
            8,
            "mi_stat_adjust_mt compares the old total to peak before it adds"
        );
        count.adjust(2);
        assert_eq!(i64_load_relaxed(&count.total), 10);
        assert_eq!(i64_load_relaxed(&count.peak), 10);
    }

    #[test]
    fn arena_events_are_two_relaxed_source_counters_without_a_generic_adjustment() {
        let events = ArenaStatistics::new();
        assert_eq!(
            events.snapshot(),
            ArenaStatisticsSnapshot {
                arena_count: 0,
                arena_purges: 0,
            }
        );

        events.high_water_arena_published();
        events.arena_purge_expiry_consumed();
        events.arena_purge_expiry_consumed();
        assert_eq!(
            events.snapshot(),
            ArenaStatisticsSnapshot {
                arena_count: 1,
                arena_purges: 2,
            }
        );
    }

    #[test]
    fn vm_statistics_exposes_only_named_vm_source_events() {
        let stats = VmStatistics::new();
        stats.mmap_call();
        stats.reserve_increase(4096);
        stats.reserved_adjust_decrease(512);
        stats.committed_increase(4096);
        stats.commit_call();
        stats.committed_decrease(1024);
        stats.reset(512);
        stats.purge(256);

        assert_eq!(i64_load_relaxed(&stats.mmap_calls.total), 1);
        assert_eq!(i64_load_relaxed(&stats.reserved.current), 3584);
        assert_eq!(i64_load_relaxed(&stats.committed.current), 3072);
        assert_eq!(i64_load_relaxed(&stats.commit_calls.total), 1);
        assert_eq!(i64_load_relaxed(&stats.reset.total), 512);
        assert_eq!(i64_load_relaxed(&stats.reset_calls.total), 1);
        assert_eq!(i64_load_relaxed(&stats.purged.total), 256);
        assert_eq!(i64_load_relaxed(&stats.purge_calls.total), 1);
    }

    #[test]
    fn subprocess_statistics_merges_selected_fields_in_source_declaration_order() {
        let destination = SubprocessStatistics::new();
        destination.vm().reserve_increase(5);
        destination.vm().reserve_decrease(3);
        destination.vm().committed_increase(2);
        destination.vm().reset(3);
        destination.vm().mmap_call();
        destination.arena().high_water_arena_published();

        let source = SubprocessStatistics::new();
        source.vm().reserve_increase(7);
        source.vm().reserve_decrease(2);
        source.vm().committed_increase(11);
        source.vm().commit_call();
        source.vm().reset(5);
        source.vm().purge(13);
        source.arena().high_water_arena_published();
        source.arena().arena_purge_expiry_consumed();

        destination.add_from(&source);
        assert_eq!(
            destination.snapshot(),
            SubprocessStatisticsSnapshot {
                vm: VmStatisticsSnapshot {
                    reserved_total: 12,
                    reserved_peak: 9,
                    reserved_current: 7,
                    committed_total: 13,
                    committed_peak: 13,
                    committed_current: 13,
                    reset: 8,
                    purged: 13,
                    mmap_calls: 1,
                    commit_calls: 1,
                    reset_calls: 2,
                    purge_calls: 1,
                },
                arena: ArenaStatisticsSnapshot {
                    arena_count: 2,
                    arena_purges: 1,
                },
            }
        );
    }

    #[test]
    fn subprocess_statistics_rejects_self_aggregation_without_double_counting() {
        let statistics = SubprocessStatistics::new();
        statistics.vm().reserve_increase(4096);
        statistics.vm().commit_call();
        statistics.arena().high_water_arena_published();
        let before = statistics.snapshot();

        statistics.add_from(&statistics);

        assert_eq!(statistics.snapshot(), before);
    }
}
