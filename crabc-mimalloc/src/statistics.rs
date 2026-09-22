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
    i64_add_from_relaxed, i64_add_relaxed, i64_load_relaxed, i64_max_relaxed,
    i64_store_relaxed, AtomicI64Value,
};
use crate::config::{BIN_HUGE, STAT_LEVEL};

/// `MI_STAT_VERSION` in the pinned `include/mimalloc-stats.h`.
const STAT_VERSION: usize = 5;
/// The source's `MI_BIN_HUGE + 1` statistics-bin width.
const STAT_BIN_COUNT: usize = BIN_HUGE + 1;
/// `MI_CBIN_COUNT` in the pinned v3.5.0 `mimalloc-stats.h` enum.
const STAT_CHUNK_BIN_COUNT: usize = 6;

/// Source `mi_stat_count_t` using `mi_stat_update_mt`'s relaxed update order.
#[repr(C)]
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

    #[inline]
    fn reset(&self) {
        i64_store_relaxed(&self.total, 0);
        i64_store_relaxed(&self.peak, 0);
        i64_store_relaxed(&self.current, 0);
    }
}

/// Source `mi_stat_counter_t`: a relaxed, monotonically increasing total.
#[repr(C)]
pub(crate) struct StatCounter {
    pub(crate) total: AtomicI64Value,
}

/// A selected arena-event projection into one shared subprocess `mi_stats_t`.
///
/// Source map: pinned mimalloc v3.5.0 `src/arena.c:1573-1605` increments
/// `arena_count` only after a fresh high-water slot has published its arena
/// pointer; `src/arena.c:2362-2385` increments `arena_purges` immediately
/// after consuming an eligible expiry. Both calls expand through
/// `include/mimalloc/internal.h:394` to the relaxed counter operation in
/// `src/stats.c:43-45`. It is a typed producer view, not another statistic
/// object or a public reporting API.
pub(crate) struct ArenaStatistics<'statistics> {
    statistics: &'statistics HeapTheapStatistics,
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

impl<'statistics> ArenaStatistics<'statistics> {
    #[inline]
    const fn from_statistics(statistics: &'statistics HeapTheapStatistics) -> Self {
        Self { statistics }
    }

    /// Records the source's successful fresh high-water arena publication.
    #[inline]
    pub(crate) fn high_water_arena_published(&self) {
        self.statistics.arena_count.increase(1);
    }

    /// Records the source's consumption of an eligible arena purge expiry.
    #[inline]
    pub(crate) fn arena_purge_expiry_consumed(&self) {
        self.statistics.arena_purges.increase(1);
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> ArenaStatisticsSnapshot {
        ArenaStatisticsSnapshot {
            arena_count: i64_load_relaxed(&self.statistics.arena_count.total),
            arena_purges: i64_load_relaxed(&self.statistics.arena_purges.total),
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

    #[inline]
    fn reset(&self) {
        i64_store_relaxed(&self.total, 0);
    }
}

/// The complete private `mi_stats_t` image owned by one Heap or Theap.
///
/// Pinned `include/mimalloc/types.h:561-598,618-639` places this tail after
/// each source object.  Keeping the complete v3.5.0 field and bin layout here
/// is necessary for `stats.c:_mi_stats_merge_into`: a filtered prefix could
/// not truthfully promise the source reset or later declaration-order merge.
/// The current selected `MI_STAT=0` engine mutates only the event methods
/// below; the remaining source fields stay present and zero until their
/// producer is mapped.  This is private state, not a public `mi_stats_t` ABI
/// or reporting interface.
///
/// Every atomically sampled value follows `stats.c`'s relaxed operations.
/// Consequently a merge is deliberately not a transactional snapshot: a
/// concurrent source producer can be observed by only part of the merge, just
/// as it can in the pinned C implementation.
#[repr(C)]
pub(crate) struct HeapTheapStatistics {
    size: usize,
    version: usize,

    // `MI_STAT_FIELDS()` in declaration order.
    pages: StatCount,
    reserved: StatCount,
    committed: StatCount,
    reset: StatCounter,
    purged: StatCounter,
    page_committed: StatCount,
    pages_abandoned: StatCount,
    threads: StatCount,
    malloc_normal: StatCount,
    malloc_huge: StatCount,
    malloc_requested: StatCount,
    mmap_calls: StatCounter,
    commit_calls: StatCounter,
    reset_calls: StatCounter,
    purge_calls: StatCounter,
    arena_count: StatCounter,
    malloc_normal_count: StatCounter,
    malloc_huge_count: StatCounter,
    malloc_guarded_count: StatCounter,
    arena_rollback_count: StatCounter,
    arena_purges: StatCounter,
    pages_extended: StatCounter,
    pages_retire: StatCounter,
    page_searches: StatCounter,
    page_searches_count: StatCounter,
    segments: StatCount,
    segments_abandoned: StatCount,
    segments_cache: StatCount,
    segments_reserved: StatCount,
    heaps: StatCount,
    theaps: StatCount,
    pages_reclaim_on_alloc: StatCounter,
    pages_reclaim_on_free: StatCounter,
    pages_reabandon_full: StatCounter,
    pages_unabandon_busy_wait: StatCounter,
    heaps_delete_wait: StatCounter,

    // The source's reserved extension records and binned tails.
    stat_reserved: [StatCount; 4],
    stat_counter_reserved: [StatCounter; 4],
    malloc_bins: [StatCount; STAT_BIN_COUNT],
    page_bins: [StatCount; STAT_BIN_COUNT],
    chunk_bins: [StatCount; STAT_CHUNK_BIN_COUNT],
}

/// Read-only evidence for the active Theap/Heap source events.
///
/// These independently relaxed loads deliberately expose no arbitrary update
/// capability and are not a public statistics callback or formatting API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeapTheapStatisticsSnapshot {
    pub(crate) pages_total: i64,
    pub(crate) pages_current: i64,
    pub(crate) pages_retire: i64,
    pub(crate) page_searches: i64,
    pub(crate) page_searches_count: i64,
    pub(crate) pages_abandoned_total: i64,
    pub(crate) pages_abandoned_current: i64,
    pub(crate) pages_reclaim_on_alloc: i64,
    pub(crate) page_bin_total: [i64; STAT_BIN_COUNT],
    pub(crate) page_bin_current: [i64; STAT_BIN_COUNT],
}

impl HeapTheapStatistics {
    pub(crate) const fn new() -> Self {
        Self {
            size: core::mem::size_of::<Self>(),
            version: STAT_VERSION,
            pages: StatCount::new(),
            reserved: StatCount::new(),
            committed: StatCount::new(),
            reset: StatCounter::new(),
            purged: StatCounter::new(),
            page_committed: StatCount::new(),
            pages_abandoned: StatCount::new(),
            threads: StatCount::new(),
            malloc_normal: StatCount::new(),
            malloc_huge: StatCount::new(),
            malloc_requested: StatCount::new(),
            mmap_calls: StatCounter::new(),
            commit_calls: StatCounter::new(),
            reset_calls: StatCounter::new(),
            purge_calls: StatCounter::new(),
            arena_count: StatCounter::new(),
            malloc_normal_count: StatCounter::new(),
            malloc_huge_count: StatCounter::new(),
            malloc_guarded_count: StatCounter::new(),
            arena_rollback_count: StatCounter::new(),
            arena_purges: StatCounter::new(),
            pages_extended: StatCounter::new(),
            pages_retire: StatCounter::new(),
            page_searches: StatCounter::new(),
            page_searches_count: StatCounter::new(),
            segments: StatCount::new(),
            segments_abandoned: StatCount::new(),
            segments_cache: StatCount::new(),
            segments_reserved: StatCount::new(),
            heaps: StatCount::new(),
            theaps: StatCount::new(),
            pages_reclaim_on_alloc: StatCounter::new(),
            pages_reclaim_on_free: StatCounter::new(),
            pages_reabandon_full: StatCounter::new(),
            pages_unabandon_busy_wait: StatCounter::new(),
            heaps_delete_wait: StatCounter::new(),
            stat_reserved: [const { StatCount::new() }; 4],
            stat_counter_reserved: [const { StatCounter::new() }; 4],
            malloc_bins: [const { StatCount::new() }; STAT_BIN_COUNT],
            page_bins: [const { StatCount::new() }; STAT_BIN_COUNT],
            chunk_bins: [const { StatCount::new() }; STAT_CHUNK_BIN_COUNT],
        }
    }

    /// Ports `mi_stats_add` followed by `mi_stats_init` in
    /// `src/stats.c:124-142,446-451`.
    ///
    /// The caller supplies the source lifetime exclusion required by the C
    /// transition. `&self` is sufficient for the source's relaxed atomics;
    /// this method does not acquire a lock or alter Heap/Theap lifecycle.
    #[inline]
    pub(crate) fn merge_from_and_reset(&self, source: &Self) {
        if core::ptr::eq(self, source) {
            return;
        }

        self.pages.add_from(&source.pages);
        self.reserved.add_from(&source.reserved);
        self.committed.add_from(&source.committed);
        self.reset.add_from(&source.reset);
        self.purged.add_from(&source.purged);
        self.page_committed.add_from(&source.page_committed);
        self.pages_abandoned.add_from(&source.pages_abandoned);
        self.threads.add_from(&source.threads);
        self.malloc_normal.add_from(&source.malloc_normal);
        self.malloc_huge.add_from(&source.malloc_huge);
        self.malloc_requested.add_from(&source.malloc_requested);
        self.mmap_calls.add_from(&source.mmap_calls);
        self.commit_calls.add_from(&source.commit_calls);
        self.reset_calls.add_from(&source.reset_calls);
        self.purge_calls.add_from(&source.purge_calls);
        self.arena_count.add_from(&source.arena_count);
        self.malloc_normal_count.add_from(&source.malloc_normal_count);
        self.malloc_huge_count.add_from(&source.malloc_huge_count);
        self.malloc_guarded_count.add_from(&source.malloc_guarded_count);
        self.arena_rollback_count.add_from(&source.arena_rollback_count);
        self.arena_purges.add_from(&source.arena_purges);
        self.pages_extended.add_from(&source.pages_extended);
        self.pages_retire.add_from(&source.pages_retire);
        self.page_searches.add_from(&source.page_searches);
        self.page_searches_count.add_from(&source.page_searches_count);
        self.segments.add_from(&source.segments);
        self.segments_abandoned.add_from(&source.segments_abandoned);
        self.segments_cache.add_from(&source.segments_cache);
        self.segments_reserved.add_from(&source.segments_reserved);
        self.heaps.add_from(&source.heaps);
        self.theaps.add_from(&source.theaps);
        self.pages_reclaim_on_alloc.add_from(&source.pages_reclaim_on_alloc);
        self.pages_reclaim_on_free.add_from(&source.pages_reclaim_on_free);
        self.pages_reabandon_full.add_from(&source.pages_reabandon_full);
        self.pages_unabandon_busy_wait.add_from(&source.pages_unabandon_busy_wait);
        self.heaps_delete_wait.add_from(&source.heaps_delete_wait);

        for index in 0..self.stat_reserved.len() {
            self.stat_reserved[index].add_from(&source.stat_reserved[index]);
        }
        for index in 0..self.stat_counter_reserved.len() {
            self.stat_counter_reserved[index].add_from(&source.stat_counter_reserved[index]);
        }
        // `stats.c` adds malloc bins only at `MI_STAT > 1`; the selected
        // normal-release profile is `MI_STAT == 0`.
        if STAT_LEVEL > 1 {
            for index in 0..self.malloc_bins.len() {
                self.malloc_bins[index].add_from(&source.malloc_bins[index]);
            }
        }
        for index in 0..self.page_bins.len() {
            self.page_bins[index].add_from(&source.page_bins[index]);
        }
        for index in 0..self.chunk_bins.len() {
            self.chunk_bins[index].add_from(&source.chunk_bins[index]);
        }

        source.reset_after_merge();
    }

    #[inline]
    fn reset_after_merge(&self) {
        self.pages.reset();
        self.reserved.reset();
        self.committed.reset();
        self.reset.reset();
        self.purged.reset();
        self.page_committed.reset();
        self.pages_abandoned.reset();
        self.threads.reset();
        self.malloc_normal.reset();
        self.malloc_huge.reset();
        self.malloc_requested.reset();
        self.mmap_calls.reset();
        self.commit_calls.reset();
        self.reset_calls.reset();
        self.purge_calls.reset();
        self.arena_count.reset();
        self.malloc_normal_count.reset();
        self.malloc_huge_count.reset();
        self.malloc_guarded_count.reset();
        self.arena_rollback_count.reset();
        self.arena_purges.reset();
        self.pages_extended.reset();
        self.pages_retire.reset();
        self.page_searches.reset();
        self.page_searches_count.reset();
        self.segments.reset();
        self.segments_abandoned.reset();
        self.segments_cache.reset();
        self.segments_reserved.reset();
        self.heaps.reset();
        self.theaps.reset();
        self.pages_reclaim_on_alloc.reset();
        self.pages_reclaim_on_free.reset();
        self.pages_reabandon_full.reset();
        self.pages_unabandon_busy_wait.reset();
        self.heaps_delete_wait.reset();
        for field in &self.stat_reserved { field.reset(); }
        for field in &self.stat_counter_reserved { field.reset(); }
        for field in &self.malloc_bins { field.reset(); }
        for field in &self.page_bins { field.reset(); }
        for field in &self.chunk_bins { field.reset(); }
    }

    #[inline]
    pub(crate) fn page_registered(&self, bin: usize) -> bool {
        let Some(page_bin) = self.page_bins.get(bin) else {
            return false;
        };
        self.pages.update(1);
        page_bin.update(1);
        true
    }

    #[inline]
    pub(crate) fn page_released(&self, bin: usize) -> bool {
        let Some(page_bin) = self.page_bins.get(bin) else {
            return false;
        };
        page_bin.update(-1);
        self.pages.update(-1);
        true
    }

    #[inline]
    pub(crate) fn page_retired(&self) { self.pages_retire.increase(1); }

    #[inline]
    pub(crate) fn pages_searched(&self, count: usize) {
        self.page_searches.increase(count);
        self.page_searches_count.increase(1);
    }

    #[inline]
    pub(crate) fn mapped_page_reclaimed_on_alloc(&self) {
        self.pages_abandoned.update(-1);
        self.pages_reclaim_on_alloc.increase(1);
    }

    #[inline]
    pub(crate) fn page_abandoned(&self) {
        self.pages_abandoned.update(1);
    }

    /// Preserves `arena.c:1376-1378`: counter, adjusted decrement, then the
    /// ordinary abandonment producer which adds the current record back.
    #[inline]
    pub(crate) fn page_reabandoned_from_full(&self) {
        self.pages_reabandon_full.increase(1);
        self.pages_abandoned.adjust(-1);
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> HeapTheapStatisticsSnapshot {
        let mut page_bin_total = [0; STAT_BIN_COUNT];
        let mut page_bin_current = [0; STAT_BIN_COUNT];
        for index in 0..STAT_BIN_COUNT {
            page_bin_total[index] = i64_load_relaxed(&self.page_bins[index].total);
            page_bin_current[index] = i64_load_relaxed(&self.page_bins[index].current);
        }
        HeapTheapStatisticsSnapshot {
            pages_total: i64_load_relaxed(&self.pages.total),
            pages_current: i64_load_relaxed(&self.pages.current),
            pages_retire: i64_load_relaxed(&self.pages_retire.total),
            page_searches: i64_load_relaxed(&self.page_searches.total),
            page_searches_count: i64_load_relaxed(&self.page_searches_count.total),
            pages_abandoned_total: i64_load_relaxed(&self.pages_abandoned.total),
            pages_abandoned_current: i64_load_relaxed(&self.pages_abandoned.current),
            pages_reclaim_on_alloc: i64_load_relaxed(&self.pages_reclaim_on_alloc.total),
            page_bin_total,
            page_bin_current,
        }
    }
}

/// The VM-event projection into one shared subprocess `mi_stats_t`.
///
/// The source VM paths and Heap merges therefore mutate one source-ordered
/// record with the subprocess lifetime, rather than independent counters.
pub(crate) struct VmStatistics<'statistics> {
    statistics: &'statistics HeapTheapStatistics,
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

impl<'statistics> VmStatistics<'statistics> {
    #[inline]
    const fn from_statistics(statistics: &'statistics HeapTheapStatistics) -> Self {
        Self { statistics }
    }

    #[inline]
    pub(crate) fn mmap_call(&self) { self.statistics.mmap_calls.increase(1); }

    #[inline]
    pub(crate) fn reserve_increase(&self, bytes: usize) {
        self.statistics.reserved.update(bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn reserve_decrease(&self, bytes: usize) {
        self.statistics.reserved.update(-bytes_to_i64(bytes));
    }

    /// Mirrors `_mi_stat_adjust_decrease(&_mi_stats_main.reserved, ...)` in
    /// the partial-overmap release path.  This is intentionally not folded
    /// into [`Self::reserve_decrease`]: `mi_stat_adjust_mt` has different
    /// total/peak behavior from `mi_stat_update_mt`.
    #[inline]
    pub(crate) fn reserved_adjust_decrease(&self, bytes: usize) {
        self.statistics.reserved.adjust(-bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_increase(&self, bytes: usize) {
        self.statistics.committed.update(bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_decrease(&self, bytes: usize) {
        self.statistics.committed.update(-bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_adjust_increase(&self, bytes: usize) {
        self.statistics.committed.adjust(bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn committed_adjust_decrease(&self, bytes: usize) {
        self.statistics.committed.adjust(-bytes_to_i64(bytes));
    }

    #[inline]
    pub(crate) fn commit_call(&self) { self.statistics.commit_calls.increase(1); }

    #[inline]
    pub(crate) fn reset(&self, bytes: usize) {
        self.statistics.reset.increase(bytes);
        self.statistics.reset_calls.increase(1);
    }

    #[inline]
    pub(crate) fn purge(&self, bytes: usize) {
        self.statistics.purged.increase(bytes);
        self.statistics.purge_calls.increase(1);
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> VmStatisticsSnapshot {
        VmStatisticsSnapshot {
            reserved_total: i64_load_relaxed(&self.statistics.reserved.total),
            reserved_peak: i64_load_relaxed(&self.statistics.reserved.peak),
            reserved_current: i64_load_relaxed(&self.statistics.reserved.current),
            committed_total: i64_load_relaxed(&self.statistics.committed.total),
            committed_peak: i64_load_relaxed(&self.statistics.committed.peak),
            committed_current: i64_load_relaxed(&self.statistics.committed.current),
            reset: i64_load_relaxed(&self.statistics.reset.total),
            purged: i64_load_relaxed(&self.statistics.purged.total),
            mmap_calls: i64_load_relaxed(&self.statistics.mmap_calls.total),
            commit_calls: i64_load_relaxed(&self.statistics.commit_calls.total),
            reset_calls: i64_load_relaxed(&self.statistics.reset_calls.total),
            purge_calls: i64_load_relaxed(&self.statistics.purge_calls.total),
        }
    }
}

/// The complete private source `mi_subproc_t::stats` record.
///
/// Pinned `include/mimalloc/types.h:651-680` gives every subprocess one
/// `mi_stats_t`, rather than independent VM, arena, Heap, and Theap statistic
/// objects. This private source-shaped image retains the header, every field,
/// and each bin tail so `heap.c` can merge a complete Heap record without
/// discarding unproduced fields. The selected `MI_STAT=0` producers still
/// mutate only their applicable fields; unimplemented source producers remain
/// zero. It is not a public layout, reporting, or callback API.
pub(crate) struct SubprocessStatistics {
    statistics: HeapTheapStatistics,
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
            statistics: HeapTheapStatistics::new(),
        }
    }

    #[inline]
    pub(crate) fn vm(&self) -> VmStatistics<'_> {
        VmStatistics::from_statistics(&self.statistics)
    }

    #[inline]
    pub(crate) fn arena(&self) -> ArenaStatistics<'_> {
        ArenaStatistics::from_statistics(&self.statistics)
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> SubprocessStatisticsSnapshot {
        SubprocessStatisticsSnapshot {
            vm: self.vm().snapshot(),
            arena: self.arena().snapshot(),
        }
    }

    /// Read-only private observation of source fields that do not belong to
    /// the existing VM/arena snapshot contract. It supports lifecycle proof
    /// without making `mi_stats_t` a public Rust or C layout API.
    #[inline]
    pub(crate) fn source_snapshot(&self) -> HeapTheapStatisticsSnapshot {
        self.statistics.snapshot()
    }

    /// Merges a source Heap record into this owning subprocess and resets it.
    ///
    /// This is `heap.c:27-35`'s `_mi_stats_merge_into` destination. The
    /// source caller owns unlink/count/lifetime transitions; this method only
    /// carries the full `stats.c` declaration-order relaxed merge/reset.
    #[inline]
    pub(crate) fn merge_heap_and_reset(&self, heap_statistics: &HeapTheapStatistics) {
        self.statistics.merge_from_and_reset(heap_statistics);
    }

    /// Records `init.c`'s completed default-Theap thread attachment.
    #[inline]
    pub(crate) fn thread_attached(&self) {
        self.statistics.threads.update(1);
    }

    /// Records `init.c`'s thread-exit adjustment before Theap destruction.
    #[inline]
    pub(crate) fn thread_detached(&self) {
        self.statistics.threads.update(-1);
    }

    /// Records `heap.c` publication of one Heap in the subprocess list.
    #[inline]
    pub(crate) fn heap_linked(&self) {
        self.statistics.heaps.update(1);
    }

    /// Records `heap.c` removal of one Heap from the subprocess list.
    #[inline]
    pub(crate) fn heap_unlinked(&self) {
        self.statistics.heaps.update(-1);
    }

    /// Records `theap.c` publication of one non-detached Theap.
    #[inline]
    pub(crate) fn theap_linked(&self) {
        self.statistics.theaps.update(1);
    }

    /// Records `theap.c` release of one non-detached Theap backing image.
    #[inline]
    pub(crate) fn theap_unlinked(&self) {
        self.statistics.theaps.update(-1);
    }

    /// Records one source retry while a Theap list detach lock is busy.
    #[inline]
    pub(crate) fn heap_delete_waited(&self) {
        self.statistics.heaps_delete_wait.increase(1);
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
    fn heap_theap_statistics_keep_the_source_layout_and_merge_reset_order() {
        assert_eq!(core::mem::size_of::<StatCount>(), 24);
        assert_eq!(core::mem::size_of::<StatCounter>(), 8);
        assert_eq!(core::mem::size_of::<HeapTheapStatistics>(), 4_368);

        let destination = HeapTheapStatistics::new();
        let source = HeapTheapStatistics::new();
        assert_eq!(destination.size, 4_368);
        assert_eq!(destination.version, STAT_VERSION);

        assert!(destination.page_registered(3));
        assert!(source.page_registered(3));
        source.page_retired();
        source.pages_searched(2);
        source.page_abandoned();
        source.mapped_page_reclaimed_on_alloc();
        source.page_reabandoned_from_full();
        source.page_abandoned();

        destination.merge_from_and_reset(&source);

        assert_eq!(
            destination.snapshot(),
            HeapTheapStatisticsSnapshot {
                pages_total: 2,
                pages_current: 2,
                pages_retire: 1,
                page_searches: 2,
                page_searches_count: 1,
                pages_abandoned_total: 1,
                pages_abandoned_current: 0,
                pages_reclaim_on_alloc: 1,
                page_bin_total: {
                    let mut bins = [0; STAT_BIN_COUNT];
                    bins[3] = 2;
                    bins
                },
                page_bin_current: {
                    let mut bins = [0; STAT_BIN_COUNT];
                    bins[3] = 2;
                    bins
                },
            }
        );
        assert_eq!(source.snapshot(), HeapTheapStatisticsSnapshot {
            pages_total: 0,
            pages_current: 0,
            pages_retire: 0,
            page_searches: 0,
            page_searches_count: 0,
            pages_abandoned_total: 0,
            pages_abandoned_current: 0,
            pages_reclaim_on_alloc: 0,
            page_bin_total: [0; STAT_BIN_COUNT],
            page_bin_current: [0; STAT_BIN_COUNT],
        });
        assert_eq!(source.size, 4_368);
        assert_eq!(source.version, STAT_VERSION);
    }

    #[test]
    fn arena_events_are_two_relaxed_source_counters_without_a_generic_adjustment() {
        let statistics = SubprocessStatistics::new();
        let events = statistics.arena();
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
        let statistics = SubprocessStatistics::new();
        let stats = statistics.vm();
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

        let source = HeapTheapStatistics::new();
        source.reserved.update(7);
        source.reserved.update(-2);
        source.committed.update(11);
        source.commit_calls.increase(1);
        source.reset.increase(5);
        source.reset_calls.increase(1);
        source.purged.increase(13);
        source.purge_calls.increase(1);
        source.arena_count.increase(1);
        source.arena_purges.increase(1);

        destination.merge_heap_and_reset(&source);
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

        statistics.merge_heap_and_reset(&statistics.statistics);

        assert_eq!(statistics.snapshot(), before);
    }
}
