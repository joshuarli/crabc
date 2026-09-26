// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/stats.c:25-63,356-430,436-447,568-597`,
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

/// Pinned `stats.c`'s one process-wide `mi_process_start` scalar.
///
/// The value is deliberately separate from the private per-owner statistics
/// images. `init.c` initializes it after option parsing and before `_mi_os_init`;
/// final output reads the elapsed value at its actual source print edge.
static PROCESS_START_MILLISECONDS: AtomicI64Value = AtomicI64Value::new(0);

/// Mirrors `_mi_stats_init`: initialize the source process clock once when
/// its current scalar is zero.
///
/// The source state itself is a plain static reached during process
/// initialization. This private Rust operation preserves that zero-sentinel
/// rule and relies on the process owner's single initialization transition;
/// it is not a general clock or synchronization API.
#[inline]
pub(crate) fn initialize_process_clock() {
    if i64_load_relaxed(&PROCESS_START_MILLISECONDS) == 0 {
        i64_store_relaxed(
            &PROCESS_START_MILLISECONDS,
            crate::os::source_process_clock_start(),
        );
    }
}

/// Mirrors `mi_process_info`'s `_mi_clock_end(mi_process_start)` observation.
///
/// The process owner calls this at the final statistics print edge. It has no
/// heap, Theap, TLS, VM, or lifecycle effect.
#[inline]
pub(crate) fn process_elapsed_msecs() -> i64 {
    crate::os::source_process_clock_end(i64_load_relaxed(&PROCESS_START_MILLISECONDS))
}

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

    /// Mirrors `mi_stat_adjust_mt`, used to repair source accounting around
    /// partially committed ranges. It changes current and total without
    /// changing the peak previously observed by [`Self::update`].
    #[inline]
    pub(crate) fn adjust(&self, amount: i64) {
        if amount == 0 {
            return;
        }
        i64_add_relaxed(&self.current, amount);
        i64_add_relaxed(&self.total, amount);
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

/// The source bitmap producers' typed view into the one subprocess image.
///
/// Pinned `src/bitmap.c:109-129` increases `pages_unabandon_busy_wait` when
/// the clear-once reader has to wait, and `src/bitmap.c:1643-1647` updates
/// the first five `chunk_bins` records as bin-map bits transition. Both write
/// `mi_subproc_t::stats`; this view deliberately owns no duplicate record.
#[derive(Clone, Copy)]
pub(crate) struct BitmapStatistics<'statistics> {
    statistics: &'statistics HeapTheapStatistics,
}

/// One relaxed observation of a source chunk-bin count record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BitmapChunkStatisticsSnapshot {
    pub(crate) total: i64,
    pub(crate) peak: i64,
    pub(crate) current: i64,
}

/// Read-only bitmap statistics from the shared subprocess source image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BitmapStatisticsSnapshot {
    pub(crate) chunk_bins: [BitmapChunkStatisticsSnapshot; STAT_CHUNK_BIN_COUNT],
    pub(crate) pages_unabandon_busy_wait: i64,
}

impl<'statistics> BitmapStatistics<'statistics> {
    #[inline]
    const fn from_statistics(statistics: &'statistics HeapTheapStatistics) -> Self {
        Self { statistics }
    }

    /// Records the source's one clear-once reader busy-wait observation.
    #[inline]
    pub(crate) fn busy_wait(&self) {
        self.statistics.pages_unabandon_busy_wait.increase(1);
    }

    /// Records one binned-bitmap source transition in its existing chunk bin.
    ///
    /// `MI_CBIN_NONE` has no producer in `mi_bbitmap_set_chunk_bin`, so the
    /// caller may mutate only the five mapped source bins.
    #[inline]
    pub(crate) fn chunk_bin_update(&self, index: usize, amount: i64) -> bool {
        let Some(bin) = self.statistics.chunk_bins.get(index) else {
            return false;
        };
        if index >= STAT_CHUNK_BIN_COUNT - 1 {
            return false;
        }
        bin.update(amount);
        true
    }

    #[inline]
    pub(crate) fn snapshot(&self) -> BitmapStatisticsSnapshot {
        let mut chunk_bins = [
            BitmapChunkStatisticsSnapshot {
                total: 0,
                peak: 0,
                current: 0,
            };
            STAT_CHUNK_BIN_COUNT
        ];
        for (index, snapshot) in chunk_bins.iter_mut().enumerate() {
            let bin = &self.statistics.chunk_bins[index];
            *snapshot = BitmapChunkStatisticsSnapshot {
                total: i64_load_relaxed(&bin.total),
                peak: i64_load_relaxed(&bin.peak),
                current: i64_load_relaxed(&bin.current),
            };
        }
        BitmapStatisticsSnapshot {
            chunk_bins,
            pages_unabandon_busy_wait: i64_load_relaxed(
                &self.statistics.pages_unabandon_busy_wait.total,
            ),
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

    /// Mirrors `__mi_stat_counter_increase`, the plain (non-`_mt`) add that
    /// `mi_theap_stat_counter_increase` selects for a Theap's own counters.
    ///
    /// Only the Theap's owning thread writes these fields while it is
    /// attached; other threads merely read or merge them. A relaxed load
    /// and store is therefore the exact source update without a locked
    /// read-modify-write, and a concurrent reader observes either value just
    /// as it may in the C implementation.
    #[inline]
    fn increase_owner_local(&self, amount: usize) {
        i64_store_relaxed(&self.total, i64_load_relaxed(&self.total).wrapping_add(amount as i64));
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
    pub(crate) threads_total: i64,
    pub(crate) threads_peak: i64,
    pub(crate) threads_current: i64,
    pub(crate) page_searches: i64,
    pub(crate) page_searches_count: i64,
    pub(crate) pages_abandoned_total: i64,
    pub(crate) pages_abandoned_current: i64,
    pub(crate) pages_reclaim_on_alloc: i64,
    pub(crate) pages_reclaim_on_free: i64,
    pub(crate) page_bin_total: [i64; STAT_BIN_COUNT],
    pub(crate) page_bin_current: [i64; STAT_BIN_COUNT],
}

/// One scalar copy of the source `mi_stat_count_t` fields used by the final
/// process-output adapter.
///
/// `stats.c` reads every member independently with relaxed loads before it
/// formats a line.  This is therefore deliberately a captured display input,
/// not a transactional snapshot and not a public `mi_stats_t` representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalStatCount {
    pub(crate) peak: i64,
    pub(crate) total: i64,
    pub(crate) current: i64,
}

/// The committed-memory defaults that pinned `mi_process_info` establishes
/// before its Unix primitive can overwrite process observations.
///
/// Pinned `stats.c:568-588` derives both current and peak commit from the
/// main subprocess, seeds current/peak RSS from those same values, and then
/// calls `_mi_prim_process_info`. Linux leaves the current fields alone and
/// overwrites the peak RSS/user/system/fault fields only when `getrusage`
/// succeeds.  This renderer-only scalar image lets the process owner retain
/// those exact defaults when its raw sampler fails; it carries no subprocess
/// reference or sampling capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessInfoCommittedDefaults {
    pub(crate) current_bytes: usize,
    pub(crate) peak_bytes: usize,
}

/// The exact `MI_STAT == 0` field subset consumed by `stats.c`'s process-end
/// display path.
///
/// The renderer never reads a Heap, Theap, subprocess, VM policy, or TLS root.
/// Its process-state caller captures this scalar image only after it has
/// completed the source-prescribed merge order.  Fields whose `MI_STAT == 0`
/// branches cannot print are intentionally absent; this is neither a general
/// statistics callback API nor a replacement for [`HeapTheapStatistics`]'s
/// complete private source layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalStatisticsSnapshot {
    pub(crate) pages: FinalStatCount,
    pub(crate) page_committed: FinalStatCount,
    pub(crate) pages_abandoned: FinalStatCount,
    pub(crate) threads: FinalStatCount,
    pub(crate) reserved: FinalStatCount,
    pub(crate) committed: FinalStatCount,
    pub(crate) theaps: FinalStatCount,
    pub(crate) heaps: FinalStatCount,
    pub(crate) reset: i64,
    pub(crate) purged: i64,
    pub(crate) mmap_calls: i64,
    pub(crate) commit_calls: i64,
    pub(crate) reset_calls: i64,
    pub(crate) purge_calls: i64,
    pub(crate) arena_count: i64,
    pub(crate) malloc_guarded_count: i64,
    pub(crate) arena_rollback_count: i64,
    pub(crate) pages_reclaim_on_alloc: i64,
    pub(crate) pages_reclaim_on_free: i64,
    pub(crate) pages_reabandon_full: i64,
    pub(crate) pages_unabandon_busy_wait: i64,
    pub(crate) pages_extended: i64,
    pub(crate) pages_retire: i64,
    pub(crate) page_searches: i64,
    pub(crate) page_searches_count: i64,
    pub(crate) heaps_delete_wait: i64,
}

impl FinalStatisticsSnapshot {
    /// Captures the main-subprocess committed defaults used by
    /// `mi_process_info` before `_mi_prim_process_info`.
    ///
    /// This is deliberately a scalar accessor on an already-captured final
    /// snapshot. It neither reloads statistics nor obtains a source owner.
    #[inline]
    pub(crate) const fn process_info_committed_defaults(&self) -> ProcessInfoCommittedDefaults {
        ProcessInfoCommittedDefaults {
            current_bytes: source_process_info_committed_bytes(self.committed.current),
            peak_bytes: source_process_info_committed_bytes(self.committed.peak),
        }
    }
}

/// Pinned `stats.c:575-576`'s signed `int64_t` to `size_t` conversion.
#[inline]
const fn source_process_info_committed_bytes(value: i64) -> usize {
    if value < 0 {
        0
    } else if value < isize::MAX as i64 {
        value as usize
    } else {
        isize::MAX as usize
    }
}

#[inline]
fn final_stat_count(stat: &StatCount) -> FinalStatCount {
    FinalStatCount {
        peak: i64_load_relaxed(&stat.peak),
        total: i64_load_relaxed(&stat.total),
        current: i64_load_relaxed(&stat.current),
    }
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

    /// Test-only source-layout records for the pinned native C/Rust
    /// differential. The complete field sequence and both tail arrays are
    /// recorded so matching `sizeof` alone cannot hide a reordered member.
    #[cfg(test)]
    pub(crate) fn layout_records() -> [(&'static str, usize); 49] {
        use core::mem::{align_of, offset_of, size_of};

        [
            ("sizeof.mi_stat_count_t", size_of::<StatCount>()),
            ("alignof.mi_stat_count_t", align_of::<StatCount>()),
            ("sizeof.mi_stat_counter_t", size_of::<StatCounter>()),
            ("alignof.mi_stat_counter_t", align_of::<StatCounter>()),
            ("offsetof.mi_stats_t.size", offset_of!(Self, size)),
            ("offsetof.mi_stats_t.version", offset_of!(Self, version)),
            ("offsetof.mi_stats_t.pages", offset_of!(Self, pages)),
            ("offsetof.mi_stats_t.reserved", offset_of!(Self, reserved)),
            ("offsetof.mi_stats_t.committed", offset_of!(Self, committed)),
            ("offsetof.mi_stats_t.reset", offset_of!(Self, reset)),
            ("offsetof.mi_stats_t.purged", offset_of!(Self, purged)),
            (
                "offsetof.mi_stats_t.page_committed",
                offset_of!(Self, page_committed),
            ),
            (
                "offsetof.mi_stats_t.pages_abandoned",
                offset_of!(Self, pages_abandoned),
            ),
            ("offsetof.mi_stats_t.threads", offset_of!(Self, threads)),
            (
                "offsetof.mi_stats_t.malloc_normal",
                offset_of!(Self, malloc_normal),
            ),
            ("offsetof.mi_stats_t.malloc_huge", offset_of!(Self, malloc_huge)),
            (
                "offsetof.mi_stats_t.malloc_requested",
                offset_of!(Self, malloc_requested),
            ),
            ("offsetof.mi_stats_t.mmap_calls", offset_of!(Self, mmap_calls)),
            (
                "offsetof.mi_stats_t.commit_calls",
                offset_of!(Self, commit_calls),
            ),
            ("offsetof.mi_stats_t.reset_calls", offset_of!(Self, reset_calls)),
            ("offsetof.mi_stats_t.purge_calls", offset_of!(Self, purge_calls)),
            ("offsetof.mi_stats_t.arena_count", offset_of!(Self, arena_count)),
            (
                "offsetof.mi_stats_t.malloc_normal_count",
                offset_of!(Self, malloc_normal_count),
            ),
            (
                "offsetof.mi_stats_t.malloc_huge_count",
                offset_of!(Self, malloc_huge_count),
            ),
            (
                "offsetof.mi_stats_t.malloc_guarded_count",
                offset_of!(Self, malloc_guarded_count),
            ),
            (
                "offsetof.mi_stats_t.arena_rollback_count",
                offset_of!(Self, arena_rollback_count),
            ),
            ("offsetof.mi_stats_t.arena_purges", offset_of!(Self, arena_purges)),
            (
                "offsetof.mi_stats_t.pages_extended",
                offset_of!(Self, pages_extended),
            ),
            ("offsetof.mi_stats_t.pages_retire", offset_of!(Self, pages_retire)),
            (
                "offsetof.mi_stats_t.page_searches",
                offset_of!(Self, page_searches),
            ),
            (
                "offsetof.mi_stats_t.page_searches_count",
                offset_of!(Self, page_searches_count),
            ),
            ("offsetof.mi_stats_t.segments", offset_of!(Self, segments)),
            (
                "offsetof.mi_stats_t.segments_abandoned",
                offset_of!(Self, segments_abandoned),
            ),
            (
                "offsetof.mi_stats_t.segments_cache",
                offset_of!(Self, segments_cache),
            ),
            (
                "offsetof.mi_stats_t._segments_reserved",
                offset_of!(Self, segments_reserved),
            ),
            ("offsetof.mi_stats_t.heaps", offset_of!(Self, heaps)),
            ("offsetof.mi_stats_t.theaps", offset_of!(Self, theaps)),
            (
                "offsetof.mi_stats_t.pages_reclaim_on_alloc",
                offset_of!(Self, pages_reclaim_on_alloc),
            ),
            (
                "offsetof.mi_stats_t.pages_reclaim_on_free",
                offset_of!(Self, pages_reclaim_on_free),
            ),
            (
                "offsetof.mi_stats_t.pages_reabandon_full",
                offset_of!(Self, pages_reabandon_full),
            ),
            (
                "offsetof.mi_stats_t.pages_unabandon_busy_wait",
                offset_of!(Self, pages_unabandon_busy_wait),
            ),
            (
                "offsetof.mi_stats_t.heaps_delete_wait",
                offset_of!(Self, heaps_delete_wait),
            ),
            (
                "offsetof.mi_stats_t._stat_reserved",
                offset_of!(Self, stat_reserved),
            ),
            (
                "offsetof.mi_stats_t._stat_counter_reserved",
                offset_of!(Self, stat_counter_reserved),
            ),
            (
                "offsetof.mi_stats_t.malloc_bins",
                offset_of!(Self, malloc_bins),
            ),
            ("offsetof.mi_stats_t.page_bins", offset_of!(Self, page_bins)),
            ("offsetof.mi_stats_t.chunk_bins", offset_of!(Self, chunk_bins)),
            ("sizeof.mi_stats_t", size_of::<Self>()),
            ("alignof.mi_stats_t", align_of::<Self>()),
        ]
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
        self.add_from(source);
        source.reset_after_merge();
    }

    /// `mi_stats_copy` (`src/stats.c:613-618`) into a caller's `mi_stats_t`:
    /// `false`, copying nothing, unless its header names this layout and
    /// version. Every field is copied with the relaxed loads of this image;
    /// like the source `memcpy`, a concurrent producer may be seen in part.
    ///
    /// # Safety
    /// `destination` is valid for reads and writes of `size_of::<Self>()`
    /// bytes, suitably aligned, and not otherwise accessed during the call.
    pub(crate) unsafe fn copy_into_source_image(&self, destination: *mut u8) -> bool {
        const WORD: usize = core::mem::size_of::<i64>();
        const _: () = assert!(core::mem::size_of::<HeapTheapStatistics>() % WORD == 0);
        // SAFETY: the caller supplies a readable header.
        let (size, version) = unsafe {
            (destination.cast::<usize>().read(), destination.cast::<usize>().add(1).read())
        };
        if size != core::mem::size_of::<Self>() || version != STAT_VERSION {
            return false;
        }
        let source = core::ptr::from_ref(self).cast::<u8>();
        let mut offset = 2 * core::mem::size_of::<usize>();
        while offset < core::mem::size_of::<Self>() {
            // SAFETY: every field after the two-word header is an `i64`
            // atomic of this `repr(C)` image (the layout records pin it), so
            // each word is an `AtomicI64` on both sides.
            unsafe {
                let value = (*source.add(offset).cast::<AtomicI64Value>()).load(core::sync::atomic::Ordering::Relaxed);
                destination.add(offset).cast::<i64>().write(value);
            }
            offset += WORD;
        }
        true
    }

    /// `mi_stats_add` (`src/stats.c:124-142`) into a caller's `mi_stats_t`
    /// that [`Self::copy_into_source_image`] validated.
    ///
    /// # Safety
    /// As [`Self::copy_into_source_image`], after a successful copy.
    pub(crate) unsafe fn add_into_source_image(&self, destination: *mut u8) {
        // SAFETY: a validated caller image has exactly this layout; the
        // caller excludes other access, and its fields are plain words that
        // the relaxed atomics of `add_from` may treat as atomics.
        let destination = unsafe { &*destination.cast::<Self>() };
        destination.add_from(self);
    }

    /// `mi_stats_add` without the reset: counts and counters in
    /// declaration order, then the binned tails.
    fn add_from(&self, source: &Self) {
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

    /// `page.c:_mi_page_retire`'s `mi_theap_stat_counter_increase`; only a
    /// Theap owner records it (see [`StatCounter::increase_owner_local`]).
    #[inline]
    pub(crate) fn page_retired(&self) { self.pages_retire.increase_owner_local(1); }

    /// `page.c:mi_page_queue_find_free_ex`'s two Theap counter increases,
    /// recorded only by the Theap owner.
    #[inline]
    pub(crate) fn pages_searched(&self, count: usize) {
        self.page_searches.increase_owner_local(count);
        self.page_searches_count.increase_owner_local(1);
    }

    #[inline]
    pub(crate) fn mapped_page_reclaimed_on_alloc(&self) {
        self.pages_abandoned.update(-1);
        self.pages_reclaim_on_alloc.increase(1);
    }

    /// Records the source free-triggered abandoned-page reclaim after its
    /// reassociation, false collection, and queue insertion have completed:
    /// `_mi_arenas_page_unabandon`'s `pages_abandoned` decrease, then
    /// `mi_abandoned_page_try_reclaim`'s `pages_reclaim_on_free` increase.
    #[inline]
    pub(crate) fn page_reclaimed_on_free(&self) {
        self.pages_abandoned.update(-1);
        self.pages_reclaim_on_free.increase(1);
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
            threads_total: i64_load_relaxed(&self.threads.total),
            threads_peak: i64_load_relaxed(&self.threads.peak),
            threads_current: i64_load_relaxed(&self.threads.current),
            page_searches: i64_load_relaxed(&self.page_searches.total),
            page_searches_count: i64_load_relaxed(&self.page_searches_count.total),
            pages_abandoned_total: i64_load_relaxed(&self.pages_abandoned.total),
            pages_abandoned_current: i64_load_relaxed(&self.pages_abandoned.current),
            pages_reclaim_on_alloc: i64_load_relaxed(&self.pages_reclaim_on_alloc.total),
            pages_reclaim_on_free: i64_load_relaxed(&self.pages_reclaim_on_free.total),
            page_bin_total,
            page_bin_current,
        }
    }

    /// Captures only the selected release-profile values that `stats.c` can
    /// render at final process output.
    ///
    /// The caller owns the source lifecycle exclusion and the preceding
    /// Theap/Heap-to-subprocess merges.  Each field remains a separate relaxed
    /// load, matching `stats.c`; no lock, mutation, or owner capability is
    /// acquired here.
    #[inline]
    pub(crate) fn final_output_snapshot(&self) -> FinalStatisticsSnapshot {
        FinalStatisticsSnapshot {
            pages: final_stat_count(&self.pages),
            page_committed: final_stat_count(&self.page_committed),
            pages_abandoned: final_stat_count(&self.pages_abandoned),
            threads: final_stat_count(&self.threads),
            reserved: final_stat_count(&self.reserved),
            committed: final_stat_count(&self.committed),
            theaps: final_stat_count(&self.theaps),
            heaps: final_stat_count(&self.heaps),
            reset: i64_load_relaxed(&self.reset.total),
            purged: i64_load_relaxed(&self.purged.total),
            mmap_calls: i64_load_relaxed(&self.mmap_calls.total),
            commit_calls: i64_load_relaxed(&self.commit_calls.total),
            reset_calls: i64_load_relaxed(&self.reset_calls.total),
            purge_calls: i64_load_relaxed(&self.purge_calls.total),
            arena_count: i64_load_relaxed(&self.arena_count.total),
            malloc_guarded_count: i64_load_relaxed(&self.malloc_guarded_count.total),
            arena_rollback_count: i64_load_relaxed(&self.arena_rollback_count.total),
            pages_reclaim_on_alloc: i64_load_relaxed(&self.pages_reclaim_on_alloc.total),
            pages_reclaim_on_free: i64_load_relaxed(&self.pages_reclaim_on_free.total),
            pages_reabandon_full: i64_load_relaxed(&self.pages_reabandon_full.total),
            pages_unabandon_busy_wait: i64_load_relaxed(&self.pages_unabandon_busy_wait.total),
            pages_extended: i64_load_relaxed(&self.pages_extended.total),
            pages_retire: i64_load_relaxed(&self.pages_retire.total),
            page_searches: i64_load_relaxed(&self.page_searches.total),
            page_searches_count: i64_load_relaxed(&self.page_searches_count.total),
            heaps_delete_wait: i64_load_relaxed(&self.heaps_delete_wait.total),
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

    /// Returns the bitmap producer view of this same subprocess image.
    #[inline]
    pub(crate) fn bitmap(&self) -> BitmapStatistics<'_> {
        BitmapStatistics::from_statistics(&self.statistics)
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

    /// Captures the renderer-only scalar view after the process owner has
    /// completed its source-ordered final statistics merges.
    #[inline]
    pub(crate) fn final_output_snapshot(&self) -> FinalStatisticsSnapshot {
        self.statistics.final_output_snapshot()
    }

    /// See [`HeapTheapStatistics::copy_into_source_image`].
    ///
    /// # Safety
    /// As there.
    #[inline]
    pub(crate) unsafe fn copy_into_source_image(&self, destination: *mut u8) -> bool {
        // SAFETY: forwarded.
        unsafe { self.statistics.copy_into_source_image(destination) }
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

    /// Merges a destroyed child subprocess's complete record into this
    /// process-main record and resets the child record.
    ///
    /// This is `subproc.c:233-236`. It precedes the child's arena
    /// destruction, so those later releases decrease only the reset child
    /// record and the process-main record keeps the child's reservations.
    #[inline]
    pub(crate) fn merge_child_subprocess_and_reset(&self, child: &SubprocessStatistics) {
        self.statistics.merge_from_and_reset(&child.statistics);
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

/// The `mi_json_buf_t` of pinned `src/stats.c:659-693`: a caller buffer, or
/// one grown by `mi_rezalloc` through `grow`.
pub(crate) struct JsonBuffer<'grow> {
    buffer: *mut u8,
    size: usize,
    used: usize,
    grow: Option<&'grow mut dyn FnMut(*mut u8, usize) -> *mut u8>,
}

impl<'grow> JsonBuffer<'grow> {
    /// A caller-supplied buffer of `size > 0` bytes, zeroed first as the
    /// source does.
    ///
    /// # Safety
    /// `buffer` is valid for writes of `size` bytes and not otherwise
    /// accessed while this value lives.
    pub(crate) unsafe fn fixed(buffer: *mut u8, size: usize) -> Self {
        // SAFETY: the caller's buffer contract.
        unsafe { buffer.write_bytes(0, size) };
        Self { buffer, size, used: 0, grow: None }
    }

    /// An allocator-grown buffer: `grow(old, new_size)` is the source
    /// `mi_rezalloc` and returns null on failure, leaving `old` owned.
    pub(crate) fn growing(grow: &'grow mut dyn FnMut(*mut u8, usize) -> *mut u8) -> Self {
        Self { buffer: core::ptr::null_mut(), size: 0, used: 0, grow: Some(grow) }
    }

    /// `mi_json_buf_expand`.
    pub(crate) fn expand(&mut self) -> bool {
        if !self.buffer.is_null() && self.size > 0 {
            // SAFETY: `size` bytes are owned.
            unsafe { self.buffer.add(self.size - 1).write(0) };
        }
        let Some(grow) = self.grow.as_mut() else { return false };
        if self.size > usize::MAX / 2 {
            return false;
        }
        let new_size = if self.size == 0 {
            crate::source_api::good_size(12 * crate::config::KIB)
        } else {
            2 * self.size
        };
        let buffer = grow(self.buffer, new_size);
        if buffer.is_null() {
            return false;
        }
        self.buffer = buffer;
        self.size = new_size;
        true
    }

    /// `mi_json_buf_print`.
    fn print(&mut self, message: &[u8]) {
        if self.used + 1 >= self.size && self.grow.is_none() {
            return;
        }
        for &byte in message {
            if self.used + 1 >= self.size && !self.expand() {
                return;
            }
            // SAFETY: `used < size` bytes are owned.
            unsafe { self.buffer.add(self.used).write(byte) };
            self.used += 1;
        }
        // SAFETY: as above.
        unsafe { self.buffer.add(self.used).write(0) };
    }

    /// The source's final check: `NULL` (after freeing a grown buffer via
    /// `free`) when the output did not fit.
    pub(crate) fn finish(self, free: impl FnOnce(*mut u8)) -> *mut u8 {
        if self.used + 1 >= self.size {
            if self.grow.is_some() && !self.buffer.is_null() {
                free(self.buffer);
            }
            return core::ptr::null_mut();
        }
        self.buffer
    }
}

/// One `_mi_snprintf(buf, 128, ...)` line: at most 127 bytes are kept.
struct JsonLine {
    bytes: [u8; 127],
    length: usize,
}

impl JsonLine {
    const fn new() -> Self { Self { bytes: [0; 127], length: 0 } }
    fn as_bytes(&self) -> &[u8] { &self.bytes[..self.length] }
}

impl core::fmt::Write for JsonLine {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let copied = core::cmp::min(self.bytes.len() - self.length, value.len());
        self.bytes[self.length..self.length + copied].copy_from_slice(&value.as_bytes()[..copied]);
        self.length += copied;
        Ok(())
    }
}

/// `mi_process_info`'s results as the JSON `"process"` object prints them.
#[derive(Clone, Copy)]
pub(crate) struct JsonProcessInfo {
    pub(crate) elapsed: usize,
    pub(crate) user: usize,
    pub(crate) system: usize,
    pub(crate) page_faults: usize,
    pub(crate) rss_current: usize,
    pub(crate) rss_peak: usize,
    pub(crate) commit_current: usize,
    pub(crate) commit_peak: usize,
}

impl HeapTheapStatistics {
    /// Borrows a caller's source `mi_stats_t` whose header names this layout
    /// and version, as `mi_stats_get_json_from` requires.
    ///
    /// # Safety
    /// `image` is null or valid for reads of a two-word header and, when that
    /// header matches, of the whole image for `'image`, with only atomic or
    /// no concurrent writes.
    pub(crate) unsafe fn from_source_image<'image>(image: *const u8) -> Option<&'image Self> {
        if image.is_null() || image.addr() % core::mem::align_of::<Self>() != 0 {
            return None;
        }
        // SAFETY: the caller supplies a readable header.
        let (size, version) = unsafe { (image.cast::<usize>().read(), image.cast::<usize>().add(1).read()) };
        if size != core::mem::size_of::<Self>() || version != STAT_VERSION {
            return None;
        }
        // SAFETY: a matching header names this exact `repr(C)` layout (the
        // layout records pin it), every field after the header is an `i64`
        // read atomically, and the caller keeps the image live.
        Some(unsafe { &*image.cast::<Self>() })
    }

    /// The body of pinned `mi_stats_get_json_from` (`src/stats.c:764-826`)
    /// after its buffer is set up.
    pub(crate) fn render_json(&self, process: JsonProcessInfo, out: &mut JsonBuffer<'_>) {
        use core::fmt::Write;
        fn count(out: &mut JsonBuffer<'_>, prefix: &str, stat: &StatCount, suffix: &str, comma: bool) {
            let mut line = JsonLine::new();
            let _ = write!(
                line,
                "{prefix}{{ \"total\": {}, \"peak\": {}, \"current\": {}{suffix} }}{}\n",
                i64_load_relaxed(&stat.total), i64_load_relaxed(&stat.peak), i64_load_relaxed(&stat.current),
                if comma { "," } else { "" },
            );
            out.print(line.as_bytes());
        }
        let value = |out: &mut JsonBuffer<'_>, name: &str, value: i64| {
            let mut line = JsonLine::new();
            let _ = write!(line, "  \"{name}\": {value},\n");
            out.print(line.as_bytes());
        };
        let size = |out: &mut JsonBuffer<'_>, name: &str, value: usize, comma: bool| {
            let mut line = JsonLine::new();
            let _ = write!(line, "    \"{name}\": {value}{}\n", if comma { "," } else { "" });
            out.print(line.as_bytes());
        };
        let count_value = |out: &mut JsonBuffer<'_>, name: &str, stat: &StatCount| {
            let mut line = JsonLine::new();
            let _ = write!(line, "  \"{name}\": ");
            out.print(line.as_bytes());
            count(out, "", stat, "", true);
        };
        let counter = |out: &mut JsonBuffer<'_>, name: &str, stat: &StatCounter| value(out, name, i64_load_relaxed(&stat.total));

        out.print(b"{\n");
        value(out, "stat_version", STAT_VERSION as i64);
        value(out, "mimalloc_version", 30_500);
        out.print(b"  \"process\": {\n");
        size(out, "elapsed_msecs", process.elapsed, true);
        size(out, "user_msecs", process.user, true);
        size(out, "system_msecs", process.system, true);
        size(out, "page_faults", process.page_faults, true);
        size(out, "rss_current", process.rss_current, true);
        size(out, "rss_peak", process.rss_peak, true);
        size(out, "commit_current", process.commit_current, true);
        size(out, "commit_peak", process.commit_peak, false);
        out.print(b"  },\n");

        // `MI_STAT_FIELDS()` in declaration order.
        count_value(out, "pages", &self.pages);
        count_value(out, "reserved", &self.reserved);
        count_value(out, "committed", &self.committed);
        counter(out, "reset", &self.reset);
        counter(out, "purged", &self.purged);
        count_value(out, "page_committed", &self.page_committed);
        count_value(out, "pages_abandoned", &self.pages_abandoned);
        count_value(out, "threads", &self.threads);
        count_value(out, "malloc_normal", &self.malloc_normal);
        count_value(out, "malloc_huge", &self.malloc_huge);
        count_value(out, "malloc_requested", &self.malloc_requested);
        counter(out, "mmap_calls", &self.mmap_calls);
        counter(out, "commit_calls", &self.commit_calls);
        counter(out, "reset_calls", &self.reset_calls);
        counter(out, "purge_calls", &self.purge_calls);
        counter(out, "arena_count", &self.arena_count);
        counter(out, "malloc_normal_count", &self.malloc_normal_count);
        counter(out, "malloc_huge_count", &self.malloc_huge_count);
        counter(out, "malloc_guarded_count", &self.malloc_guarded_count);
        counter(out, "arena_rollback_count", &self.arena_rollback_count);
        counter(out, "arena_purges", &self.arena_purges);
        counter(out, "pages_extended", &self.pages_extended);
        counter(out, "pages_retire", &self.pages_retire);
        counter(out, "page_searches", &self.page_searches);
        counter(out, "page_searches_count", &self.page_searches_count);
        count_value(out, "segments", &self.segments);
        count_value(out, "segments_abandoned", &self.segments_abandoned);
        count_value(out, "segments_cache", &self.segments_cache);
        count_value(out, "_segments_reserved", &self.segments_reserved);
        count_value(out, "heaps", &self.heaps);
        count_value(out, "theaps", &self.theaps);
        counter(out, "pages_reclaim_on_alloc", &self.pages_reclaim_on_alloc);
        counter(out, "pages_reclaim_on_free", &self.pages_reclaim_on_free);
        counter(out, "pages_reabandon_full", &self.pages_reabandon_full);
        counter(out, "pages_unabandon_busy_wait", &self.pages_unabandon_busy_wait);
        counter(out, "heaps_delete_wait", &self.heaps_delete_wait);

        // `mi_json_buf_print_count_bin`: the bin's block size and page kind.
        let bins = |out: &mut JsonBuffer<'_>, name: &[u8], stats: &[StatCount; STAT_BIN_COUNT]| {
            out.print(b"  \"");
            out.print(name);
            out.print(b"\": [\n");
            for (bin, stat) in stats.iter().enumerate() {
                let block_size = crate::size_class::bin_size(bin).unwrap_or(0);
                let page_size = if block_size <= crate::config::SMALL_MAX_OBJ_SIZE {
                    crate::config::SMALL_PAGE_SIZE
                } else if block_size <= crate::config::MEDIUM_MAX_OBJ_SIZE {
                    crate::config::MEDIUM_PAGE_SIZE
                } else if block_size <= crate::config::LARGE_MAX_OBJ_SIZE {
                    crate::config::LARGE_PAGE_SIZE
                } else {
                    0
                };
                let mut suffix = JsonLine::new();
                let _ = write!(suffix, ", \"block_size\": {block_size}, \"page_size\": {page_size}");
                // SAFETY: `write!` above wrote only ASCII.
                let suffix = unsafe { core::str::from_utf8_unchecked(suffix.as_bytes()) };
                count(out, "    ", stat, suffix, bin != BIN_HUGE);
            }
            out.print(b"  ],\n");
        };
        bins(out, b"malloc_bins", &self.malloc_bins);
        bins(out, b"page_bins", &self.page_bins);
        out.print(b"  \"chunk_bins\": [\n");
        for (bin, stat) in self.chunk_bins.iter().enumerate() {
            // `mi_chunkbin_t`: SMALL, OTHER, MEDIUM, LARGE, HUGE, NONE.
            let name = ["S", "X", "M", "L", "H", " "][bin];
            let mut suffix = JsonLine::new();
            let _ = write!(suffix, ", \"bin\": \"{name}\"");
            // SAFETY: ASCII only.
            let suffix = unsafe { core::str::from_utf8_unchecked(suffix.as_bytes()) };
            count(out, "    ", stat, suffix, bin != STAT_CHUNK_BIN_COUNT - 1);
        }
        out.print(b"  ]\n");
        out.print(b"}\n");
    }
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
            10,
            "mi_stat_adjust_mt leaves the observed peak unchanged"
        );
        count.adjust(2);
        assert_eq!(i64_load_relaxed(&count.total), 10);
        assert_eq!(i64_load_relaxed(&count.peak), 10);
        count.adjust(7);
        assert_eq!(i64_load_relaxed(&count.current), 13);
        assert_eq!(i64_load_relaxed(&count.total), 17);
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
        // Each source reclaim unabandons a page that an abandonment counted.
        source.page_abandoned();
        source.page_reclaimed_on_free();
        source.page_reabandoned_from_full();
        source.page_abandoned();

        destination.merge_from_and_reset(&source);

        assert_eq!(
            destination.snapshot(),
            HeapTheapStatisticsSnapshot {
                pages_total: 2,
                pages_current: 2,
                pages_retire: 1,
                threads_total: 0,
                threads_peak: 0,
                threads_current: 0,
                page_searches: 2,
                page_searches_count: 1,
                pages_abandoned_total: 2,
                pages_abandoned_current: 0,
                pages_reclaim_on_alloc: 1,
                pages_reclaim_on_free: 1,
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
            threads_total: 0,
            threads_peak: 0,
            threads_current: 0,
            page_searches: 0,
            page_searches_count: 0,
            pages_abandoned_total: 0,
            pages_abandoned_current: 0,
            pages_reclaim_on_alloc: 0,
            pages_reclaim_on_free: 0,
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
    fn bitmap_producers_and_heap_merges_share_the_one_subprocess_image() {
        let destination = SubprocessStatistics::new();
        let bitmap = destination.bitmap();
        assert!(bitmap.chunk_bin_update(0, 1));
        assert!(bitmap.chunk_bin_update(0, -1));
        assert!(bitmap.chunk_bin_update(4, 1));
        assert!(!bitmap.chunk_bin_update(STAT_CHUNK_BIN_COUNT - 1, 1));
        bitmap.busy_wait();

        let source = HeapTheapStatistics::new();
        source.chunk_bins[4].update(2);
        source.pages_unabandon_busy_wait.increase(3);
        destination.merge_heap_and_reset(&source);

        let snapshot = destination.bitmap().snapshot();
        assert_eq!(snapshot.chunk_bins[0].total, 1);
        assert_eq!(snapshot.chunk_bins[0].current, 0);
        assert_eq!(snapshot.chunk_bins[4].total, 3);
        assert_eq!(snapshot.chunk_bins[4].current, 3);
        assert_eq!(snapshot.chunk_bins[STAT_CHUNK_BIN_COUNT - 1].total, 0);
        assert_eq!(snapshot.pages_unabandon_busy_wait, 4);
        assert_eq!(i64_load_relaxed(&source.chunk_bins[4].current), 0);
        assert_eq!(i64_load_relaxed(&source.pages_unabandon_busy_wait.total), 0);
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

        assert_eq!(i64_load_relaxed(&stats.statistics.mmap_calls.total), 1);
        assert_eq!(i64_load_relaxed(&stats.statistics.reserved.current), 3584);
        assert_eq!(i64_load_relaxed(&stats.statistics.committed.current), 3072);
        assert_eq!(i64_load_relaxed(&stats.statistics.commit_calls.total), 1);
        assert_eq!(i64_load_relaxed(&stats.statistics.reset.total), 512);
        assert_eq!(i64_load_relaxed(&stats.statistics.reset_calls.total), 1);
        assert_eq!(i64_load_relaxed(&stats.statistics.purged.total), 256);
        assert_eq!(i64_load_relaxed(&stats.statistics.purge_calls.total), 1);
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
