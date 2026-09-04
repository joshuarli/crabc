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
    i64_add_relaxed, i64_load_relaxed, i64_max_relaxed, AtomicI64Value,
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
}

/// Source `mi_stat_counter_t`: a relaxed, monotonically increasing total.
pub(crate) struct StatCounter {
    pub(crate) total: AtomicI64Value,
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
        assert_eq!(i64_load_relaxed(&count.peak), 10);
        count.adjust(2);
        assert_eq!(i64_load_relaxed(&count.total), 10);
        assert_eq!(i64_load_relaxed(&count.peak), 10);
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
}
