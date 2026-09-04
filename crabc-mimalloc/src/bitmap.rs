// Copyright (c) 2019-2026 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
//
// Copyright (c) 2019-2024 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/bitmap.h:61-123,231-340` (64-bit
// field/chunk representation plus ordinary and binned dynamic headers),
// `include/mimalloc-stats.h:85-93` (chunk-bin classification), and
// `src/bitmap.c:26-568,594-915,933-1246` (field masks, field/chunk index
// arithmetic, atomic set/clear, rollback, set-run selection, scalar relaxed
// chunk observations, caller-owned bitmap initialization, range operations,
// and conservative chunkmap maintenance), `src/bitmap.c:109-129,920-928,
// 1024-1042,1297-1420,1425-1432` (the abandoned-page single-bit claim
// visitor, its conservative-map repair, reverse set-bit and count
// observations, and clear-once-set reader quiescence),
// `src/bitmap.c:1437-1460` (the selected scalar read-only set-bit visitor),
// `src/bitmap.c:1462-1521` (the selected scalar clear-range visitor and its
// default `rangesn` dispatch), plus `src/bitmap.c:1583-1784,1794-1997`
// (binned initialization, size bins, two-level claims, and exact multi-chunk
// rollback). The native bitmap component also covers all scalar callback
// dispositions and range/observer paths, including unconditional subprocess
// counters (`src/stats.c::mi_stat_update_mt` and `__mi_stat_counter_increase_mt`).
// The legacy selected M2 C/Rust traces below cover the
// abandoned visitor's reject/restore, accepted-claim, and stale-map repair;
// the scalar clear-range visitor's completed and stopped field-bounded walks;
// the `rangesn` wrapper's selected aligned/delegated paths; and a direct
// 65-chunk read-only set-bit walk across the first chunk-map field boundary;
// and the binned inverse-BSR observer's rounded padding and descending
// chunk/field walk. `bitmap_native_tests.rs` and its pinned C fixture extend
// this to the complete scalar bitmap boundary, not allocator integration.
// The allocator-owned dynamic TLS registry projects its typed metadata
// capability only transiently through the ordinary lowest-bit claim path below;
// it does not add a general bitmap metadata ownership API.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use crate::atomic::{
    word_and_acq_rel, word_cas_strong_acq_rel, word_cas_strong_relaxed,
    word_cas_weak_acq_rel, word_exchange_relaxed, word_exchange_release,
    word_load_acquire, word_load_relaxed, word_or_acq_rel, word_or_relaxed,
    word_store_release, AtomicWord,
};
use crate::bits::{bsf, bsr, clz, ctz, popcount};
use crate::config::BCHUNK_BITS;

#[cfg(test)]
#[path = "bitmap_native_tests.rs"]
mod native_tests;

// Statistics translation: Copyright (c) 2018-2026 Microsoft Research, Daan
// Leijen, MIT. Source: pinned `src/stats.c:25-63`, `include/mimalloc-stats.h:
// 29-116`, and `include/mimalloc/internal.h:394-398`.
/// The unconditional bitmap subset of `mi_subproc_t::stats`, not a
/// `mi_stats_t` ABI image. Even `MI_STAT=0` executes these source events.
/// `stats.c::mi_stat_update_mt` updates current, then peak, then positive
/// total with relaxed signed 64-bit atomics; observations are not snapshots.
pub(crate) struct BitmapStatistics {
    chunk_bins: [BitmapStatCount; 5],
    pages_unabandon_busy_wait: crate::atomic::AtomicI64Value,
}

struct BitmapStatCount {
    total: crate::atomic::AtomicI64Value,
    peak: crate::atomic::AtomicI64Value,
    current: crate::atomic::AtomicI64Value,
}

impl BitmapStatCount {
    const fn new() -> Self {
        Self {
            total: crate::atomic::AtomicI64Value::new(0),
            peak: crate::atomic::AtomicI64Value::new(0),
            current: crate::atomic::AtomicI64Value::new(0),
        }
    }

    fn update(&self, amount: i64) {
        let previous = crate::atomic::i64_add_relaxed(&self.current, amount);
        crate::atomic::i64_max_relaxed(&self.peak, previous.wrapping_add(amount));
        if amount > 0 {
            crate::atomic::i64_add_relaxed(&self.total, amount);
        }
    }
}

impl BitmapStatistics {
    pub(crate) const fn new() -> Self {
        Self {
            chunk_bins: [const { BitmapStatCount::new() }; 5],
            pages_unabandon_busy_wait: crate::atomic::AtomicI64Value::new(0),
        }
    }

    fn busy_wait(&self) {
        crate::atomic::i64_add_relaxed(&self.pages_unabandon_busy_wait, 1);
    }
}

/// `MI_BFIELD_BITS` for the configured 64-bit Linux target profiles.
pub(crate) const BFIELD_BITS: usize = usize::BITS as usize;
pub(crate) const BCHUNK_FIELDS: usize = BCHUNK_BITS / BFIELD_BITS;
pub(crate) const BCHUNK_SIZE: usize = BCHUNK_BITS / 8;
const BFIELD_LO_BIT8: usize = usize::MAX / 0xff;
const BFIELD_HI_BIT8: usize = BFIELD_LO_BIT8 << 7;

const _: [(); 64] = [(); BFIELD_BITS];
const _: [(); 8] = [(); BCHUNK_FIELDS];
const _: [(); 64] = [(); BCHUNK_SIZE];

/// A checked `mi_bfield_mask` boundary. The C helper asserts these inputs;
/// this pure Rust boundary rejects them before any shift can overflow or panic.
#[inline]
pub(crate) const fn field_mask(bit_count: usize, shift_left: usize) -> Option<usize> {
    if bit_count == 0 || shift_left >= BFIELD_BITS {
        return None;
    }
    match bit_count.checked_add(shift_left) {
        Some(end) if end <= BFIELD_BITS => {
            let mask = if bit_count == BFIELD_BITS {
                usize::MAX
            } else {
                (1usize << bit_count) - 1
            };
            Some(mask << shift_left)
        }
        _ => None,
    }
}

/// The unchecked core of `mi_bfield_mask` for values derived from a validated
/// `ChunkRun` or a source-selected field position. Its callers preserve the C
/// helper's `0 < bit_count`, `bit_count + shift_left <= BFIELD_BITS` invariant.
#[inline]
const fn field_mask_valid(bit_count: usize, shift_left: usize) -> usize {
    let mask = if bit_count == BFIELD_BITS {
        usize::MAX
    } else {
        (1usize << bit_count) - 1
    };
    mask << shift_left
}

/// A checked bit index in one v3.5.0 bitmap chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChunkIndex(usize);

impl ChunkIndex {
    #[inline]
    pub(crate) const fn new(index: usize) -> Option<Self> {
        if index < BCHUNK_BITS {
            Some(Self(index))
        } else {
            None
        }
    }

    #[inline]
    pub(crate) const fn field_index(self) -> usize {
        self.0 / BFIELD_BITS
    }

    #[inline]
    pub(crate) const fn field_bit_index(self) -> usize {
        self.0 % BFIELD_BITS
    }
}

#[derive(Clone, Copy)]
struct ChunkRun {
    index: usize,
    len: usize,
}

impl ChunkRun {
    #[inline]
    const fn new(index: usize, len: usize) -> Option<Self> {
        if len == 0 || index >= BCHUNK_BITS {
            return None;
        }
        match index.checked_add(len) {
            Some(end) if end <= BCHUNK_BITS => Some(Self { index, len }),
            _ => None,
        }
    }
}

/// Result data preserved from the upstream `setN`/`clearN` field protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RunTransition {
    all_transitioned: bool,
    already_set: usize,
    maybe_all_clear: bool,
}

impl RunTransition {
    #[inline]
    pub(crate) const fn all_clear(already_set: usize) -> Self {
        Self {
            all_transitioned: already_set == 0,
            already_set,
            maybe_all_clear: false,
        }
    }

    #[inline]
    pub(crate) const fn all_set() -> Self {
        Self {
            all_transitioned: true,
            already_set: 0,
            maybe_all_clear: false,
        }
    }

    #[inline]
    pub(crate) const fn all_transitioned(self) -> bool {
        self.all_transitioned
    }

    #[inline]
    pub(crate) const fn already_set(self) -> usize {
        self.already_set
    }

    #[inline]
    pub(crate) const fn maybe_all_clear(self) -> bool {
        self.maybe_all_clear
    }
}

/// Result of conditionally clearing a set run to claim it.
///
/// `temporarily_unclaimed` is the source's `did_temp_clear_bits`: an optimistic
/// multi-bit clear observed a partial match and restored the changed bits. A
/// later chunk-map owner must treat that as a conservative-map repair event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TryClaim {
    claimed: bool,
    maybe_all_clear: bool,
    temporarily_unclaimed: bool,
}

/// Source-directed disposition after an abandoned-page bitmap reader has
/// atomically removed one candidate bit.
///
/// `KeepSet` is not a rollback convenience: `arena.c:655-671` requires it
/// after a failed ownership claim so a concurrent `unabandon` can observe the
/// reader's completion through [`BitmapView::clear_once_set`]. The generic
/// `bitmap.c:1340-1370` callback also admits refusal without restoration:
/// [`Self::Discarded`] expresses `claim == false && keep_set == false`.
/// The arena owner must continue to use `KeepSet` whenever an unabandoning
/// writer can be waiting for that restoration; bitmap-level removal alone
/// establishes no page ownership or reclamation permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbandonedBitmapClaim {
    /// The candidate page ownership claim succeeded; retain the bit clear.
    Claimed,
    /// Ownership was unavailable; restore the bit before returning to search.
    KeepSet,
    /// Refuse this candidate without restoring it, and continue the search.
    /// The caller has separately established that no owner needs restoration.
    Discarded,
}

impl TryClaim {
    #[inline]
    pub(crate) const fn claimed(maybe_all_clear: bool, temporarily_unclaimed: bool) -> Self {
        Self {
            claimed: true,
            maybe_all_clear,
            temporarily_unclaimed,
        }
    }

    #[inline]
    pub(crate) const fn rejected(temporarily_unclaimed: bool) -> Self {
        Self {
            claimed: false,
            maybe_all_clear: false,
            temporarily_unclaimed,
        }
    }

    #[inline]
    pub(crate) const fn is_claimed(self) -> bool {
        self.claimed
    }

    #[inline]
    pub(crate) const fn maybe_all_clear(self) -> bool {
        self.maybe_all_clear
    }

    #[inline]
    pub(crate) const fn temporarily_unclaimed(self) -> bool {
        self.temporarily_unclaimed
    }
}

#[derive(Clone, Copy)]
struct FieldTryClaim {
    result: TryClaim,
    previous: usize,
}

#[derive(Clone, Copy)]
struct ChunkSearchClaim {
    index: Option<usize>,
    temporarily_unclaimed: bool,
}

impl ChunkSearchClaim {
    #[inline]
    const fn found(index: usize, temporarily_unclaimed: bool) -> Self {
        Self {
            index: Some(index),
            temporarily_unclaimed,
        }
    }

    #[inline]
    const fn not_found(temporarily_unclaimed: bool) -> Self {
        Self {
            index: None,
            temporarily_unclaimed,
        }
    }
}

/// One cache-aligned `mi_bchunk_t` for the frozen 64-bit configuration.
///
/// A set bit denotes an available bit, matching the upstream binned bitmap.
/// Claiming a run atomically clears it; unclaiming sets it. All mutating field
/// operations use the `atomic` facade's AcqRel pair exactly as
/// `mi_bfield_atomic_{set,clear,try_clear_*}`. Reads used to observe a claim
/// use Acquire, while optimistic search probes remain Relaxed as upstream.
#[repr(C, align(64))]
pub(crate) struct Chunk {
    fields: [AtomicWord; BCHUNK_FIELDS],
}

impl Chunk {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            fields: [const { AtomicWord::new(0) }; BCHUNK_FIELDS],
        }
    }

    #[inline]
    const fn all_set() -> Self {
        Self {
            fields: [const { AtomicWord::new(usize::MAX) }; BCHUNK_FIELDS],
        }
    }

    #[inline]
    fn field(&self, field_index: usize) -> &AtomicWord {
        &self.fields[field_index]
    }

    /// Atomically sets an available run, preserving `mi_bchunk_setN`'s
    /// per-field transition and `already_set` accounting.
    pub(crate) fn set_run(&self, index: usize, len: usize) -> Option<RunTransition> {
        let run = ChunkRun::new(index, len)?;
        let mut field_index = run.index / BFIELD_BITS;
        let mut field_bit_index = run.index % BFIELD_BITS;
        let mut remaining = run.len;
        let mut all_transitioned = true;
        let mut already_set = 0;

        while remaining != 0 {
            let field_len = core::cmp::min(BFIELD_BITS - field_bit_index, remaining);
            let mask = field_mask_valid(field_len, field_bit_index);
            let old = word_or_acq_rel(self.field(field_index), mask);
            let already_set_field = popcount(old & mask);
            all_transitioned &= already_set_field == 0;
            already_set += already_set_field;
            remaining -= field_len;
            field_index += 1;
            field_bit_index = 0;
        }

        Some(RunTransition {
            all_transitioned,
            already_set,
            maybe_all_clear: false,
        })
    }

    /// Returns a previously claimed run to the available set. This is the
    /// source `mi_bchunk_setN` transition under the bitmap's claim convention.
    #[inline]
    pub(crate) fn unclaim_run(&self, index: usize, len: usize) -> Option<RunTransition> {
        self.set_run(index, len)
    }

    /// Atomically clears an available run without requiring that it was fully
    /// available, preserving `mi_bchunk_clearN`'s aggregate transition result.
    pub(crate) fn clear_run(&self, index: usize, len: usize) -> Option<RunTransition> {
        let run = ChunkRun::new(index, len)?;
        let mut field_index = run.index / BFIELD_BITS;
        let mut field_bit_index = run.index % BFIELD_BITS;
        let mut remaining = run.len;
        let mut all_transitioned = true;
        let mut maybe_all_clear = true;

        while remaining != 0 {
            let field_len = core::cmp::min(BFIELD_BITS - field_bit_index, remaining);
            let mask = field_mask_valid(field_len, field_bit_index);
            let old = word_and_acq_rel(self.field(field_index), !mask);
            all_transitioned &= (old & mask) == mask;
            maybe_all_clear &= (old & !mask) == 0;
            remaining -= field_len;
            field_index += 1;
            field_bit_index = 0;
        }

        Some(RunTransition {
            all_transitioned,
            already_set: 0,
            maybe_all_clear,
        })
    }

    #[inline]
    pub(crate) fn is_set_run(&self, index: usize, len: usize) -> bool {
        self.is_xset_run(true, index, len)
    }

    #[inline]
    pub(crate) fn is_clear_run(&self, index: usize, len: usize) -> bool {
        self.is_xset_run(false, index, len)
    }

    fn is_xset_run(&self, set: bool, index: usize, len: usize) -> bool {
        let Some(run) = ChunkRun::new(index, len) else {
            return false;
        };
        let mut field_index = run.index / BFIELD_BITS;
        let mut field_bit_index = run.index % BFIELD_BITS;
        let mut remaining = run.len;

        while remaining != 0 {
            let field_len = core::cmp::min(BFIELD_BITS - field_bit_index, remaining);
            let mask = field_mask_valid(field_len, field_bit_index);
            let value = word_load_acquire(self.field(field_index));
            if if set { (value & mask) != mask } else { (value & mask) != 0 } {
                return false;
            }
            remaining -= field_len;
            field_index += 1;
            field_bit_index = 0;
        }
        true
    }

    pub(crate) fn popcount_run(&self, index: usize, len: usize) -> Option<usize> {
        let run = ChunkRun::new(index, len)?;
        let mut field_index = run.index / BFIELD_BITS;
        let mut field_bit_index = run.index % BFIELD_BITS;
        let mut remaining = run.len;
        let mut count = 0;

        while remaining != 0 {
            let field_len = core::cmp::min(BFIELD_BITS - field_bit_index, remaining);
            let mask = field_mask_valid(field_len, field_bit_index);
            count += popcount(word_load_acquire(self.field(field_index)) & mask);
            remaining -= field_len;
            field_index += 1;
            field_bit_index = 0;
        }
        Some(count)
    }

    /// Port of `mi_bchunk_all_are_clear_relaxed`'s scalar fallback.
    ///
    /// Each field is read with the source's Relaxed ordering, in increasing
    /// field order. Concurrent mutation can make this a mixed-time observation,
    /// not an atomic snapshot; callers may only use a positive result where the
    /// upstream protocol permits that conservative race.
    #[inline]
    pub(crate) fn all_are_clear_relaxed(&self) -> bool {
        for field_index in 0..BCHUNK_FIELDS {
            if word_load_relaxed(self.field(field_index)) != 0 {
                return false;
            }
        }
        true
    }

    /// Port of `mi_bchunk_all_are_set_relaxed`'s scalar fallback.
    ///
    /// Like the pinned implementation, this is a Relaxed per-field observation
    /// rather than a linearizable chunk-wide snapshot. It is only valid for
    /// protocols that tolerate a concurrently stale answer.
    #[inline]
    pub(crate) fn all_are_set_relaxed(&self) -> bool {
        for field_index in 0..BCHUNK_FIELDS {
            if word_load_relaxed(self.field(field_index)) != usize::MAX {
                return false;
            }
        }
        true
    }

    /// Port of `mi_bchunk_bsr`: return the highest set bit in the source's
    /// high-to-low field order, using Relaxed loads. The result is valid only
    /// for the individual field observation that produced it; another thread
    /// may change the chunk immediately after this method returns.
    #[inline]
    pub(crate) fn highest_set_relaxed(&self) -> Option<usize> {
        for field_index in (0..BCHUNK_FIELDS).rev() {
            if let Some(bit_index) = bsr(word_load_relaxed(self.field(field_index))) {
                return Some(field_index * BFIELD_BITS + bit_index);
            }
        }
        None
    }

    /// Port of `mi_bchunk_bsr_inv`: return the highest clear bit in the
    /// source's high-to-low field order. Its Relaxed per-field observation has
    /// the same non-snapshot concurrent invariant as `highest_set_relaxed`.
    #[inline]
    pub(crate) fn highest_clear_relaxed(&self) -> Option<usize> {
        for field_index in (0..BCHUNK_FIELDS).rev() {
            if let Some(bit_index) = bsr(!word_load_relaxed(self.field(field_index))) {
                return Some(field_index * BFIELD_BITS + bit_index);
            }
        }
        None
    }

    /// Port of `mi_bchunk_popcount`: sum Relaxed field observations in source
    /// order. The count is not a concurrent snapshot, but it needs no unsafe
    /// access because each field is an `AtomicWord`.
    #[inline]
    pub(crate) fn popcount_relaxed(&self) -> usize {
        let mut count = 0;
        for field_index in 0..BCHUNK_FIELDS {
            count += popcount(word_load_relaxed(self.field(field_index)));
        }
        count
    }

    /// Port of `mi_bchunk_try_clearN`: claim a specific fully-set run by
    /// clearing it. Cross-field runs are allowed; failure restores every field
    /// already cleared by this invocation, just as the pinned source does.
    pub(crate) fn try_claim_at(&self, index: usize, len: usize) -> Option<TryClaim> {
        let run = ChunkRun::new(index, len)?;
        let start_field = run.index / BFIELD_BITS;
        let start_bit = run.index % BFIELD_BITS;
        let first_len = core::cmp::min(BFIELD_BITS - start_bit, run.len);
        let first_mask = field_mask_valid(first_len, start_bit);
        let first = self.try_clear_mask(start_field, first_mask);
        if !first.result.claimed {
            return Some(first.result);
        }

        let mut maybe_all_clear = first.result.maybe_all_clear;
        let mut remaining = run.len - first_len;
        let mut field_index = start_field + 1;
        while remaining != 0 {
            let field_len = core::cmp::min(BFIELD_BITS, remaining);
            let claim = if field_len == BFIELD_BITS {
                self.try_clear_full_field(field_index)
            } else {
                self.try_clear_mask(
                    field_index,
                    field_mask_valid(field_len, 0),
                )
            };
            if !claim.result.claimed {
                self.restore_claimed_prefix(start_field, start_bit, first_len, field_index);
                return Some(TryClaim::rejected(true));
            }
            maybe_all_clear &= claim.result.maybe_all_clear;
            remaining -= field_len;
            field_index += 1;
        }

        Some(TryClaim::claimed(maybe_all_clear, false))
    }

    /// Port of `mi_bchunk_try_find_and_clear*` for a single chunk. The scan
    /// order is low-to-high, with the source's byte-aligned `n == 8` path and
    /// its cross-field run search retained. It never crosses a chunk boundary.
    pub(crate) fn try_claim_run(&self, len: usize) -> Option<usize> {
        self.try_claim_run_detailed(len).index
    }

    fn try_claim_run_detailed(&self, len: usize) -> ChunkSearchClaim {
        if len == 0 || len > BCHUNK_BITS {
            return ChunkSearchClaim::not_found(false);
        }
        if len == 1 {
            return match self.try_claim_one() {
                Some(index) => ChunkSearchClaim::found(index, false),
                None => ChunkSearchClaim::not_found(false),
            };
        }
        if len == 8 {
            return self.try_claim_byte();
        }
        if len <= BFIELD_BITS {
            return self.try_claim_run_within_field_width(len);
        }
        self.try_claim_run_across_fields(len)
    }

    fn try_clear_mask(&self, field_index: usize, mask: usize) -> FieldTryClaim {
        let previous = word_load_relaxed(self.field(field_index));
        if previous & mask != mask {
            return FieldTryClaim {
                result: TryClaim {
                    claimed: false,
                    maybe_all_clear: previous == 0,
                    temporarily_unclaimed: false,
                },
                previous,
            };
        }
        self.try_clear_mask_optimistic(field_index, mask)
    }

    fn try_clear_mask_optimistic(&self, field_index: usize, mask: usize) -> FieldTryClaim {
        let previous = word_and_acq_rel(self.field(field_index), !mask);
        if previous & mask == mask {
            return FieldTryClaim {
                result: TryClaim::claimed((previous & !mask) == 0, false),
                previous,
            };
        }

        let temporarily_unclaimed = previous & mask != 0;
        if temporarily_unclaimed {
            word_or_acq_rel(self.field(field_index), previous & mask);
        }
        FieldTryClaim {
            result: TryClaim {
                claimed: false,
                maybe_all_clear: previous == 0,
                temporarily_unclaimed,
            },
            previous,
        }
    }

    fn try_clear_full_field(&self, field_index: usize) -> FieldTryClaim {
        let mut previous = word_load_relaxed(self.field(field_index));
        let claimed = if previous == usize::MAX {
            word_cas_strong_acq_rel(self.field(field_index), &mut previous, 0)
        } else {
            false
        };
        FieldTryClaim {
            result: TryClaim {
                claimed,
                maybe_all_clear: if claimed { true } else { previous == 0 },
                temporarily_unclaimed: false,
            },
            previous,
        }
    }

    fn restore_claimed_prefix(
        &self,
        start_field: usize,
        start_bit: usize,
        first_len: usize,
        failed_field: usize,
    ) {
        let first_mask = field_mask_valid(first_len, start_bit);
        let mut field = failed_field;
        while field > start_field {
            field -= 1;
            let mask = if field == start_field {
                first_mask
            } else {
                usize::MAX
            };
            if field == start_field {
                word_or_acq_rel(self.field(field), mask);
            } else {
                word_exchange_release(self.field(field), mask);
            }
        }
    }

    fn try_claim_one(&self) -> Option<usize> {
        for field_index in 0..BCHUNK_FIELDS {
            let mut value = word_load_relaxed(self.field(field_index));
            if value == 0 {
                continue;
            }
            let mut tries = 0;
            loop {
                let mask = value & value.wrapping_neg();
                let previous = word_and_acq_rel(self.field(field_index), !mask);
                if previous & mask == mask {
                    return Some(field_index * BFIELD_BITS + ctz(mask));
                }
                value = previous;
                tries += 1;
                if value == 0 || tries > 4 {
                    break;
                }
            }
        }
        None
    }

    fn try_claim_byte(&self) -> ChunkSearchClaim {
        let mut temporarily_unclaimed = false;
        for field_index in 0..BCHUNK_FIELDS {
            let mut value = word_load_relaxed(self.field(field_index));
            if value == 0 {
                continue;
            }
            let mut tries = 0;
            loop {
                let has_set8 = ((!value).wrapping_sub(BFIELD_LO_BIT8)
                    & (value & BFIELD_HI_BIT8))
                    >> 7;
                let Some(bit_index) = bsf(has_set8) else {
                    break;
                };
                let claim = self.try_clear_mask_optimistic(
                    field_index,
                    field_mask_valid(8, bit_index),
                );
                temporarily_unclaimed |= claim.result.temporarily_unclaimed();
                if claim.result.claimed {
                    return ChunkSearchClaim::found(
                        field_index * BFIELD_BITS + bit_index,
                        temporarily_unclaimed,
                    );
                }
                value = claim.previous;
                tries += 1;
                if value == 0 || tries > 4 {
                    break;
                }
            }
        }
        ChunkSearchClaim::not_found(temporarily_unclaimed)
    }

    fn try_claim_run_within_field_width(&self, len: usize) -> ChunkSearchClaim {
        let Some(base_mask) = field_mask(len, 0) else {
            return ChunkSearchClaim::not_found(false);
        };
        let mut temporarily_unclaimed = false;
        for field_index in 0..BCHUNK_FIELDS {
            let mut previous = word_load_relaxed(self.field(field_index));
            let mut value = previous;

            while let Some(bit_index) = bsf(value) {
                if bit_index + len > BFIELD_BITS {
                    break;
                }
                let mask = base_mask << bit_index;
                if value & mask == mask {
                    let claim = self.try_clear_mask_optimistic(field_index, mask);
                    previous = claim.previous;
                    temporarily_unclaimed |= claim.result.temporarily_unclaimed();
                    if claim.result.claimed {
                        return ChunkSearchClaim::found(
                            field_index * BFIELD_BITS + bit_index,
                            temporarily_unclaimed,
                        );
                    }
                    value = previous;
                } else {
                    value &= value.wrapping_add(1usize << bit_index);
                }
            }

            if value != 0 && field_index + 1 < BCHUNK_FIELDS {
                let post = clz(!value);
                if post != 0 {
                    let pre = ctz(!word_load_relaxed(self.field(field_index + 1)));
                    if post + pre >= len {
                        let index = field_index * BFIELD_BITS + (BFIELD_BITS - post);
                        let claim = self.try_claim_at(index, len).unwrap_or(TryClaim::rejected(false));
                        temporarily_unclaimed |= claim.temporarily_unclaimed();
                        if claim.claimed {
                            return ChunkSearchClaim::found(index, temporarily_unclaimed);
                        }
                    }
                }
            }
        }
        ChunkSearchClaim::not_found(temporarily_unclaimed)
    }

    fn try_claim_run_across_fields(&self, len: usize) -> ChunkSearchClaim {
        let skip_count = (len - 1) / BFIELD_BITS;
        let mut field_index = 0;
        let mut temporarily_unclaimed = false;
        while field_index < BCHUNK_FIELDS - skip_count {
            let mut remaining = len;
            let value = word_load_relaxed(self.field(field_index));
            let mut ones = clz(!value);
            let index = field_index * BFIELD_BITS + (BFIELD_BITS - ones);

            if ones >= remaining {
                remaining = 0;
            } else if ones != 0 {
                remaining -= ones;
                let mut next = 1;
                while field_index + next < BCHUNK_FIELDS {
                    let next_value = word_load_relaxed(self.field(field_index + next));
                    ones = ctz(!next_value);
                    if ones >= remaining {
                        remaining = 0;
                        break;
                    }
                    if ones == BFIELD_BITS {
                        next += 1;
                        remaining -= BFIELD_BITS;
                    } else {
                        field_index += next - 1;
                        break;
                    }
                }
            }

            if remaining == 0 {
                let claim = self.try_claim_at(index, len).unwrap_or(TryClaim::rejected(false));
                temporarily_unclaimed |= claim.temporarily_unclaimed();
                if claim.claimed {
                    return ChunkSearchClaim::found(index, temporarily_unclaimed);
                }
            }
            field_index += 1;
        }
        ChunkSearchClaim::not_found(temporarily_unclaimed)
    }
}

const _: [(); BCHUNK_SIZE] = [(); size_of::<Chunk>()];
const _: [(); BCHUNK_SIZE] = [(); align_of::<Chunk>()];

/// The fixed prefix before `mi_bitmap_t::chunks`.
///
/// `BitmapLayout::byte_size` appends its caller-selected number of chunks to
/// this exact prefix. Keeping the trailing chunks outside this type prevents a
/// Rust owned or const-generic bitmap from accidentally becoming the allocator
/// ownership model.
#[repr(C, align(64))]
struct BitmapPrefix {
    chunk_count: AtomicWord,
    // `mi_bitmap_t` pads the count to one `mi_bchunk_t` before the chunkmap.
    // This keeps `chunkmap` and the dynamic `chunks` tail BCHUNK aligned.
    padding: [usize; BCHUNK_SIZE / size_of::<usize>() - 1],
    chunkmap: Chunk,
}

const BITMAP_MAX_CHUNK_COUNT: usize = BCHUNK_BITS;
const BITMAP_MAX_BIT_COUNT: usize = BITMAP_MAX_CHUNK_COUNT * BCHUNK_BITS;
const BITMAP_CHUNKS_OFFSET: usize = size_of::<BitmapPrefix>();

const _: [(); BCHUNK_SIZE] = [(); align_of::<BitmapPrefix>()];
const _: [(); BCHUNK_SIZE * 2] = [(); BITMAP_CHUNKS_OFFSET];
const _: [(); 0] = [(); BITMAP_CHUNKS_OFFSET % BCHUNK_SIZE];

/// A checked dynamic layout for a caller-owned `mi_bitmap_t` equivalent.
///
/// The pinned C implementation asserts a positive, BCHUNK-aligned bit count
/// no larger than its one-chunk chunkmap can represent. This checked boundary
/// preserves that contract rather than choosing a partial final chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BitmapLayout {
    chunk_count: usize,
}

impl BitmapLayout {
    /// Returns the exact dynamic layout for `bit_count` bits.
    #[inline]
    pub(crate) const fn for_bit_count(bit_count: usize) -> Option<Self> {
        if bit_count == 0
            || bit_count > BITMAP_MAX_BIT_COUNT
            || bit_count % BCHUNK_BITS != 0
        {
            return None;
        }

        Some(Self {
            chunk_count: bit_count / BCHUNK_BITS,
        })
    }

    #[inline]
    pub(crate) const fn chunk_count(self) -> usize {
        self.chunk_count
    }

    #[inline]
    pub(crate) const fn max_bits(self) -> usize {
        self.chunk_count * BCHUNK_BITS
    }

    /// The exact C `offsetof(mi_bitmap_t, chunks) + N * MI_BCHUNK_SIZE`.
    #[inline]
    pub(crate) const fn byte_size(self) -> usize {
        BITMAP_CHUNKS_OFFSET + self.chunk_count * BCHUNK_SIZE
    }
}

#[derive(Clone, Copy)]
struct BitmapRange {
    index: usize,
    len: usize,
}

impl BitmapRange {
    #[inline]
    const fn new(index: usize, len: usize, max_bits: usize) -> Option<Self> {
        if len == 0 || index >= max_bits {
            return None;
        }
        match index.checked_add(len) {
            Some(end) if end <= max_bits => Some(Self { index, len }),
            _ => None,
        }
    }
}

/// A lifetime-bound, caller-owned dynamically sized bitmap.
///
/// This is deliberately a view: it never allocates, deallocates, owns, or
/// grows its backing memory. The future arena/page-map owner selects a
/// [`BitmapLayout`] and supplies BCHUNK-aligned storage for that exact prefix
/// plus its dynamic chunk tail.
pub(crate) struct BitmapView<'storage> {
    storage: NonNull<u8>,
    layout: BitmapLayout,
    // Initialization begins from a raw pointer, so retain the caller's
    // exclusive storage lifetime in the type even though concurrent atomic
    // operations subsequently take `&self`.
    _storage: PhantomData<&'storage mut [u8]>,
}

// Safety: `initialize` requires storage to remain valid for `'storage` and
// installs only atomic shared-state access behind `&self`. The sole local
// non-atomic operation requires `&mut self` plus its documented quiescence.
unsafe impl Send for BitmapView<'_> {}
unsafe impl Sync for BitmapView<'_> {}

impl<'storage> BitmapView<'storage> {
    /// Initialize a dynamic bitmap in caller-provided storage.
    ///
    /// `storage` is the start of the C-shaped header, not the first bitmap
    /// chunk. It must be aligned to `BCHUNK_SIZE`, valid and writable for at
    /// least `layout.byte_size()` bytes, and exclusively owned for the entire
    /// initialization. The returned view must not outlive that storage, and no
    /// other view or raw access may initialize, move, deallocate, or mutate it
    /// without observing the atomic protocol. In particular, the published
    /// `chunk_count` is immutable after this call; changing it could make a
    /// later checked range name storage outside the supplied allocation.
    ///
    /// When `already_zero` is false, this writes zeroes across the complete
    /// layout before publishing `chunk_count` with the source's Release store.
    /// When it is true, every byte in that layout must already be initialized
    /// to zero and represent properly aligned zero-valued `AtomicWord`
    /// locations; this is the direct Rust boundary for C's no-memzero path.
    /// In both modes no concurrent observer may access the bitmap until this
    /// constructor returns (or is otherwise synchronized with that Release
    /// publication).
    ///
    /// # Safety
    ///
    /// The caller must meet all storage, initialization, lifetime, exclusivity,
    /// and concurrency obligations above. In particular, `storage_byte_count`
    /// must describe one allocation/provenance range containing the full layout.
    #[inline]
    pub(crate) unsafe fn initialize(
        storage: *mut u8,
        storage_byte_count: usize,
        layout: BitmapLayout,
        already_zero: bool,
    ) -> Option<Self> {
        if storage.is_null()
            || (storage as usize) % BCHUNK_SIZE != 0
            || storage_byte_count < layout.byte_size()
        {
            return None;
        }

        if !already_zero {
            // The caller supplies one writable allocation through this exact
            // layout size, matching `_mi_memzero_aligned(bitmap, size)`.
            unsafe { core::ptr::write_bytes(storage, 0, layout.byte_size()) };
        }

        let prefix = storage.cast::<BitmapPrefix>();
        // Source order is significant: publish all-zero chunkmap/chunks first,
        // then make the dynamically selected count visible with Release.
        unsafe { word_store_release(&(*prefix).chunk_count, layout.chunk_count) };

        Some(Self {
            // The null case is rejected above.
            storage: unsafe { NonNull::new_unchecked(storage) },
            layout,
            _storage: PhantomData,
        })
    }

    /// Initializes a fresh allocator-provided all-zero bitmap image.
    ///
    /// This gives the allocator-owned TLS-key registry a named fresh-image
    /// path distinct from [`Self::publish_preserved`]. It deliberately cannot
    /// be used for a copied expansion image: that path has live nonzero bits
    /// and must retain them through the preserved publication operation.
    ///
    /// # Safety
    ///
    /// The `initialize` all-zero storage and exclusive-publication contract
    /// applies exactly as documented above.
    #[inline]
    pub(crate) unsafe fn initialize_zeroed(
        storage: *mut u8,
        storage_byte_count: usize,
        layout: BitmapLayout,
    ) -> Option<Self> {
        // SAFETY: this narrow name exposes only the fresh all-zero branch of
        // the fully documented generic constructor.
        unsafe { Self::initialize(storage, storage_byte_count, layout, true) }
    }

    /// Publishes a copied nonzero bitmap image for a larger exact layout.
    ///
    /// This is the narrow `mi_bitmap_init(..., already_zero = true)` branch
    /// used by `mi_thread_local_create_expand`: the caller copied a valid
    /// smaller image into fresh zeroed storage, so clearing the whole larger
    /// layout would destroy live claims. It only Release-publishes the new
    /// count; the caller then marks the appended range available.
    ///
    /// # Safety
    ///
    /// `storage` must be BCHUNK-aligned and writable for this exact layout,
    /// with a copied initialized prefix and zeroed appended bytes. It must
    /// remain exclusively inaccessible until appended-range setup completes.
    #[inline]
    pub(crate) unsafe fn publish_preserved(
        storage: *mut u8,
        storage_byte_count: usize,
        layout: BitmapLayout,
    ) -> Option<Self> {
        if storage.is_null()
            || (storage as usize) % BCHUNK_SIZE != 0
            || storage_byte_count != layout.byte_size()
        {
            return None;
        }
        let prefix = storage.cast::<BitmapPrefix>();
        // The copied prefix/chunks and zeroed tail precede this exact source
        // initialization predicate.
        unsafe { word_store_release(&(*prefix).chunk_count, layout.chunk_count) };
        Some(Self {
            storage: unsafe { NonNull::new_unchecked(storage) },
            layout,
            _storage: PhantomData,
        })
    }

    /// Attaches to a bitmap image initialized for this exact dynamic layout.
    ///
    /// # Safety
    ///
    /// The storage and publication obligations of [`Self::initialize`] must
    /// remain valid for `'storage`. The caller must not create a concurrent
    /// alias that performs non-atomic access or initializes the same image.
    pub(crate) unsafe fn attach(
        storage: *mut u8,
        storage_byte_count: usize,
        layout: BitmapLayout,
    ) -> Option<Self> {
        if storage.is_null()
            || (storage as usize) % BCHUNK_SIZE != 0
            || storage_byte_count < layout.byte_size()
        {
            return None;
        }
        let prefix = storage.cast::<BitmapPrefix>();
        if unsafe { word_load_relaxed(&(*prefix).chunk_count) } != layout.chunk_count {
            return None;
        }
        Some(Self {
            storage: unsafe { NonNull::new_unchecked(storage) },
            layout,
            _storage: PhantomData,
        })
    }

    #[inline]
    fn prefix(&self) -> &BitmapPrefix {
        // `initialize` validates alignment, initializes the exact prefix, and
        // ties this pointer's allocation lifetime to `self`.
        unsafe { &*self.storage.as_ptr().cast::<BitmapPrefix>() }
    }

    #[inline]
    fn chunks_ptr(&self) -> *mut Chunk {
        // `BitmapPrefix` is BCHUNK-sized and the caller supplied the trailing
        // storage asserted by `BitmapLayout::byte_size`.
        unsafe { self.storage.as_ptr().add(BITMAP_CHUNKS_OFFSET).cast::<Chunk>() }
    }

    #[inline]
    fn chunk(&self, chunk_index: usize) -> &Chunk {
        debug_assert!(chunk_index < self.layout.chunk_count());
        // The private range validator keeps all safe callers within the
        // dynamically selected trailing chunk count.
        unsafe { &*self.chunks_ptr().add(chunk_index) }
    }

    #[inline]
    fn chunkmap(&self) -> &Chunk {
        &self.prefix().chunkmap
    }

    /// `mi_bitmap_size` for this initialized view's selected dynamic layout.
    #[inline]
    pub(crate) const fn byte_size(&self) -> usize {
        self.layout.byte_size()
    }

    /// A Relaxed observation of the Release-published dynamic chunk count.
    #[inline]
    pub(crate) fn chunk_count(&self) -> usize {
        word_load_relaxed(&self.prefix().chunk_count)
    }

    #[inline]
    pub(crate) fn max_bits(&self) -> usize {
        self.chunk_count() * BCHUNK_BITS
    }

    #[inline]
    fn range(&self, index: usize, len: usize) -> Option<BitmapRange> {
        BitmapRange::new(index, len, self.max_bits())
    }

    #[inline]
    fn chunkmap_set(&self, chunk_index: usize) {
        debug_assert!(chunk_index < self.chunk_count());
        // A set chunkmap bit is conservative. Preserve the source's order:
        // the data chunk has already been set before this AcqRel update.
        let _ = self.chunkmap().set_run(chunk_index, 1);
    }

    /// The source's two-observation conservative chunkmap clear protocol.
    ///
    /// Relaxed whole-chunk observations are intentionally not snapshots. A
    /// concurrent setter may land between them; setting the map bit again on
    /// the second non-clear observation avoids retaining a false clear state.
    #[inline]
    fn chunkmap_try_clear(&self, chunk_index: usize) -> bool {
        let chunk = self.chunk(chunk_index);
        if !chunk.all_are_clear_relaxed() {
            return false;
        }
        let _ = self.chunkmap().clear_run(chunk_index, 1);
        if !chunk.all_are_clear_relaxed() {
            self.chunkmap_set(chunk_index);
            return false;
        }
        true
    }

    /// Local-only port of `mi_bitmap_unsafe_setN`, including its source order.
    ///
    /// The range is checked instead of attempting C's assertion-plus-paranoia
    /// fallback: zero, overflowing, and out-of-bounds ranges return `None`.
    /// This leaves no ambiguous partial operation for an assertion-violating
    /// Rust caller.
    ///
    /// # Safety
    ///
    /// The caller must have exclusive, quiescent access to every touched data
    /// chunk and its chunkmap bits for this call. No thread may concurrently
    /// use any atomic bitmap operation or retain an alias that can observe the
    /// middle-chunk non-atomic writes. A range that spans multiple chunks must
    /// start at a chunk boundary: the source computes its conservative map
    /// count from `len`, and every non-binned upstream caller preserves that
    /// shape. The bitmap must have been initialized by
    /// [`BitmapView::initialize`] and remain live for the call.
    #[inline]
    pub(crate) unsafe fn unsafe_set_range_local(
        &mut self,
        index: usize,
        len: usize,
    ) -> Option<()> {
        let range = self.range(index, len)?;
        let mut chunk_index = range.index / BCHUNK_BITS;
        let chunk_index_start = chunk_index;
        let chunk_index_count =
            range.len / BCHUNK_BITS + usize::from(range.len % BCHUNK_BITS != 0);

        // Upstream sets the corresponding conservative map sequence before
        // writing data chunks.
        let _ = self
            .chunkmap()
            .set_run(chunk_index_start, chunk_index_count);

        let mut chunk_bit_index = range.index % BCHUNK_BITS;
        let mut remaining = range.len;
        let first_len = core::cmp::min(BCHUNK_BITS - chunk_bit_index, remaining);
        let _ = self.chunk(chunk_index).set_run(chunk_bit_index, first_len);

        chunk_index += 1;
        remaining -= first_len;
        let middle_chunk_count = remaining / BCHUNK_BITS;
        for middle_offset in 0..middle_chunk_count {
            // This is the source's local `_mi_memset(..., ~0, ...)` path. The
            // safety contract supplies the exclusive non-atomic access that
            // C's helper requires for these fully covered chunks.
            unsafe {
                self.chunks_ptr()
                    .add(chunk_index + middle_offset)
                    .write(Chunk::all_set())
            };
        }
        chunk_index += middle_chunk_count;
        remaining -= middle_chunk_count * BCHUNK_BITS;

        if remaining != 0 {
            chunk_bit_index = 0;
            let _ = self.chunk(chunk_index).set_run(chunk_bit_index, remaining);
        }
        Some(())
    }

    /// Port of `mi_bitmap_setN` with source-ordered per-chunk map updates.
    ///
    /// `None` rejects the C assertion-invalid zero, overflowing, or
    /// out-of-bounds range. On success, `RunTransition::already_set` is the
    /// source's aggregate `already_set` output.
    pub(crate) fn set_range(&self, index: usize, len: usize) -> Option<RunTransition> {
        let range = self.range(index, len)?;
        let mut chunk_index = range.index / BCHUNK_BITS;
        let mut chunk_bit_index = range.index % BCHUNK_BITS;
        let mut remaining = range.len;
        let mut all_transitioned = true;
        let mut already_set = 0;

        while remaining != 0 {
            let chunk_len = core::cmp::min(BCHUNK_BITS - chunk_bit_index, remaining);
            let transition = self.chunk(chunk_index).set_run(chunk_bit_index, chunk_len)?;
            all_transitioned &= transition.all_transitioned();
            already_set += transition.already_set();
            self.chunkmap_set(chunk_index);
            remaining -= chunk_len;
            chunk_bit_index = 0;
            chunk_index += 1;
        }

        Some(RunTransition {
            all_transitioned,
            already_set,
            maybe_all_clear: false,
        })
    }

    /// Port of `mi_bitmap_clearN` with source-ordered conservative map repair.
    ///
    /// `None` rejects the C assertion-invalid zero, overflowing, or
    /// out-of-bounds range; `Some(true)` means every requested bit transitioned
    /// from set to clear.
    pub(crate) fn clear_range(&self, index: usize, len: usize) -> Option<bool> {
        let range = self.range(index, len)?;
        let mut chunk_index = range.index / BCHUNK_BITS;
        let mut chunk_bit_index = range.index % BCHUNK_BITS;
        let mut remaining = range.len;
        let mut all_transitioned = true;

        while remaining != 0 {
            let chunk_len = core::cmp::min(BCHUNK_BITS - chunk_bit_index, remaining);
            let transition = self.chunk(chunk_index).clear_run(chunk_bit_index, chunk_len)?;
            all_transitioned &= transition.all_transitioned();
            if transition.maybe_all_clear() {
                let _ = self.chunkmap_try_clear(chunk_index);
            }
            remaining -= chunk_len;
            chunk_bit_index = 0;
            chunk_index += 1;
        }
        Some(all_transitioned)
    }

    /// Visits every set bit in source snapshot order without changing the bitmap.
    ///
    /// This is the scalar `_mi_bitmap_forall_set` algorithm. It snapshots each
    /// conservative chunk-map field with Relaxed ordering, then snapshots each
    /// named data field with the same ordering. Set bits are offered low-to-high
    /// as one-slice callbacks; a refusal stops immediately. Unlike the clearing
    /// visitor families below, this routine neither exchanges data fields nor
    /// repairs conservative chunk-map bits.
    ///
    /// The pinned source assumes every set chunk-map bit names a live data
    /// chunk. A checked Rust view instead ignores a stale out-of-layout map bit
    /// without deriving an out-of-bounds pointer, while retaining that map bit.
    pub(crate) fn visit_set_bits<F>(&self, mut visit: F) -> bool
    where
        F: FnMut(usize, usize) -> bool,
    {
        let chunk_count = self.chunk_count();
        let chunkmap_field_count = (chunk_count + BFIELD_BITS - 1) / BFIELD_BITS;
        for chunkmap_field_index in 0..chunkmap_field_count {
            let mut chunkmap_entry =
                word_load_relaxed(self.chunkmap().field(chunkmap_field_index));
            while chunkmap_entry != 0 {
                let chunkmap_bit = ctz(chunkmap_entry);
                chunkmap_entry &= chunkmap_entry.wrapping_sub(1);
                let chunk_index = chunkmap_field_index * BFIELD_BITS + chunkmap_bit;
                if chunk_index >= chunk_count {
                    continue;
                }

                let chunk = self.chunk(chunk_index);
                for field_index in 0..BCHUNK_FIELDS {
                    let mut bits = word_load_relaxed(chunk.field(field_index));
                    while bits != 0 {
                        let bit_index = ctz(bits);
                        bits &= bits.wrapping_sub(1);
                        let slice_index =
                            chunk_index * BCHUNK_BITS + field_index * BFIELD_BITS + bit_index;
                        if !visit(slice_index, 1) {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Visits the source's maximal set ranges while atomically clearing them.
    ///
    /// This is the scalar `mi_bitmap_forall_setc_ranges` algorithm used by
    /// the default arena-purge path. It first snapshots each conservative
    /// chunk-map field with Relaxed ordering, then exchanges each named data
    /// field with zero using the same ordering. Set runs are low-to-high and
    /// never cross a source `mi_bfield_t` boundary. A callback refusal leaves
    /// the current visited run clear, restores only the as-yet-unvisited bits
    /// from that exchanged field with a Relaxed OR, and stops the traversal.
    ///
    /// Like the source, successful traversal deliberately leaves conservative
    /// chunk-map bits set; a future bitmap-specific operation owns any map
    /// repair. A stale map bit beyond this checked dynamic layout is ignored
    /// rather than indexing outside caller-owned storage.
    pub(crate) fn visit_set_ranges_clear<F>(&self, mut visit: F) -> bool
    where
        F: FnMut(usize, usize) -> bool,
    {
        let chunkmap_field_count = (self.chunk_count() + BFIELD_BITS - 1) / BFIELD_BITS;
        for chunkmap_field_index in 0..chunkmap_field_count {
            let mut chunkmap_entry =
                word_load_relaxed(self.chunkmap().field(chunkmap_field_index));
            while chunkmap_entry != 0 {
                let chunkmap_bit = ctz(chunkmap_entry);
                chunkmap_entry &= chunkmap_entry.wrapping_sub(1);
                let chunk_index = chunkmap_field_index * BFIELD_BITS + chunkmap_bit;
                if chunk_index >= self.chunk_count() {
                    // The pinned source asserts this map/layout invariant. A
                    // checked view retains the map's conservative state but
                    // never derives an out-of-bounds data-chunk pointer.
                    continue;
                }

                let chunk = self.chunk(chunk_index);
                for field_index in 0..BCHUNK_FIELDS {
                    let field = chunk.field(field_index);
                    let mut bits = word_exchange_relaxed(field, 0);
                    while bits != 0 {
                        let bit_index = ctz(bits);
                        let run_len = ctz(!(bits >> bit_index));
                        debug_assert!(run_len != 0);
                        debug_assert!(bit_index + run_len <= BFIELD_BITS);
                        let run_mask = field_mask_valid(run_len, bit_index);
                        bits &= !run_mask;
                        let slice_index =
                            chunk_index * BCHUNK_BITS + field_index * BFIELD_BITS + bit_index;
                        if !visit(slice_index, run_len) {
                            if bits != 0 {
                                let _ = word_or_relaxed(field, bits);
                            }
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Visits only complete source-aligned set windows while atomically clearing them.
    ///
    /// This is the non-default scalar branch of
    /// `_mi_bitmap_forall_setc_rangesn`. `rngslices <= 1` uses the source
    /// generic visitor, which finds maximal ranges instead; larger values are
    /// capped at one source `mi_bfield_t`. For the selected branch, each field
    /// is exchanged with zero using Relaxed ordering, then only fully set,
    /// `rngslices`-aligned windows are offered low-to-high. Partial windows and
    /// a non-divisible field suffix are restored with Relaxed OR.
    ///
    /// A callback refusal leaves its current complete window clear, restores
    /// both previously skipped partial windows and every not-yet-visited bit
    /// in the exchanged field, and stops. As in the pinned source, successful
    /// traversal deliberately retains conservative chunk-map bits. A stale map
    /// bit beyond this checked dynamic layout is ignored rather than indexing
    /// outside caller-owned storage.
    pub(crate) fn visit_set_ranges_clear_aligned<F>(
        &self,
        rngslices: usize,
        mut visit: F,
    ) -> bool
    where
        F: FnMut(usize, usize) -> bool,
    {
        if rngslices <= 1 {
            return self.visit_set_ranges_clear(visit);
        }
        let rngslices = core::cmp::min(rngslices, BFIELD_BITS);
        let chunkmap_field_count = (self.chunk_count() + BFIELD_BITS - 1) / BFIELD_BITS;
        for chunkmap_field_index in 0..chunkmap_field_count {
            let mut chunkmap_entry =
                word_load_relaxed(self.chunkmap().field(chunkmap_field_index));
            while chunkmap_entry != 0 {
                let chunkmap_bit = ctz(chunkmap_entry);
                chunkmap_entry &= chunkmap_entry.wrapping_sub(1);
                let chunk_index = chunkmap_field_index * BFIELD_BITS + chunkmap_bit;
                if chunk_index >= self.chunk_count() {
                    // The pinned source asserts this map/layout invariant. A
                    // checked view retains the map's conservative state but
                    // never derives an out-of-bounds data-chunk pointer.
                    continue;
                }

                let chunk = self.chunk(chunk_index);
                for field_index in 0..BCHUNK_FIELDS {
                    let field = chunk.field(field_index);
                    let bits = word_exchange_relaxed(field, 0);
                    let mut skipped = 0usize;
                    let mut shift = 0usize;
                    while shift <= BFIELD_BITS - rngslices {
                        let window_mask = field_mask_valid(rngslices, shift);
                        if bits & window_mask == window_mask {
                            let slice_index =
                                chunk_index * BCHUNK_BITS + field_index * BFIELD_BITS + shift;
                            if !visit(slice_index, rngslices) {
                                let after_window = shift + rngslices;
                                let not_yet_visited = if after_window < BFIELD_BITS {
                                    bits & (usize::MAX << after_window)
                                } else {
                                    0
                                };
                                debug_assert_eq!(not_yet_visited & skipped, 0);
                                let restore = not_yet_visited | skipped;
                                if restore != 0 {
                                    let _ = word_or_relaxed(field, restore);
                                }
                                return false;
                            }
                        } else {
                            skipped |= bits & window_mask;
                        }
                        shift += rngslices;
                    }
                    if shift < BFIELD_BITS {
                        // The source leaves a non-divisible field suffix
                        // unvisited and restores it with the partial windows.
                        skipped |= bits & (usize::MAX << shift);
                    }
                    if skipped != 0 {
                        let _ = word_or_relaxed(field, skipped);
                    }
                }
            }
        }
        true
    }

    /// Port of `mi_bitmap_popcountN`.
    ///
    /// `None` rejects the C assertion-invalid zero, overflowing, or
    /// out-of-bounds range. The successful result is an Acquire per-field
    /// observation, not a bitmap-wide concurrent snapshot.
    pub(crate) fn popcount_range(&self, index: usize, len: usize) -> Option<usize> {
        let range = self.range(index, len)?;
        let mut chunk_index = range.index / BCHUNK_BITS;
        let mut chunk_bit_index = range.index % BCHUNK_BITS;
        let mut remaining = range.len;
        let mut count = 0;

        while remaining != 0 {
            let chunk_len = core::cmp::min(BCHUNK_BITS - chunk_bit_index, remaining);
            count += self.chunk(chunk_index).popcount_run(chunk_bit_index, chunk_len)?;
            remaining -= chunk_len;
            chunk_bit_index = 0;
            chunk_index += 1;
        }
        Some(count)
    }

    /// Port of `mi_bitmap_is_xsetN` for a requested set/clear value.
    ///
    /// `None` rejects the C assertion-invalid zero, overflowing, or
    /// out-of-bounds range. A successful answer is an Acquire per-field
    /// observation and is not a bitmap-wide concurrent snapshot.
    pub(crate) fn is_xset_range(&self, set: bool, index: usize, len: usize) -> Option<bool> {
        let range = self.range(index, len)?;
        let mut chunk_index = range.index / BCHUNK_BITS;
        let mut chunk_bit_index = range.index % BCHUNK_BITS;
        let mut remaining = range.len;

        while remaining != 0 {
            let chunk_len = core::cmp::min(BCHUNK_BITS - chunk_bit_index, remaining);
            let is_xset = if set {
                self.chunk(chunk_index).is_set_run(chunk_bit_index, chunk_len)
            } else {
                self.chunk(chunk_index).is_clear_run(chunk_bit_index, chunk_len)
            };
            if !is_xset {
                return Some(false);
            }
            remaining -= chunk_len;
            chunk_bit_index = 0;
            chunk_index += 1;
        }
        Some(true)
    }

    #[inline]
    pub(crate) fn is_set_range(&self, index: usize, len: usize) -> Option<bool> {
        self.is_xset_range(true, index, len)
    }

    #[inline]
    pub(crate) fn is_clear_range(&self, index: usize, len: usize) -> Option<bool> {
        self.is_xset_range(false, index, len)
    }

    /// Port of `mi_bitmap_is_all_clear`.
    #[inline]
    pub(crate) fn is_all_clear(&self) -> bool {
        // A checked layout always has a positive maximum bit count.
        self.is_clear_range(0, self.max_bits()).unwrap_or(false)
    }

    /// Port of `mi_bitmap_bsr`: find the highest set data bit through the
    /// conservative chunk map without changing either image.
    ///
    /// The source reads one chunk-map field in descending order, derives its
    /// highest set map bit, and then scans every lower chunk in that field
    /// from high to low. This deliberately tolerates a stale but still
    /// in-layout high chunk-map entry: a lower live data chunk can still win.
    /// Both the map and data reads are Relaxed, so the answer is only the
    /// source-shaped per-field observation, not a concurrent snapshot.
    ///
    /// Pinned C asserts that every selected map bit is within its dynamic
    /// trailing layout. The checked Rust view caps that final scan to its
    /// initialized chunk count, preserving all valid-image traversal while
    /// refusing to derive an out-of-bounds chunk from a stale invalid map bit.
    pub(crate) fn highest_set_relaxed(&self) -> Option<usize> {
        let chunk_count = self.chunk_count();
        let chunkmap_field_count = (chunk_count + BFIELD_BITS - 1) / BFIELD_BITS;
        for chunkmap_field_index in (0..chunkmap_field_count).rev() {
            let chunkmap_entry =
                word_load_relaxed(self.chunkmap().field(chunkmap_field_index));
            let Some(highest_map_bit) = bsr(chunkmap_entry) else {
                continue;
            };

            let chunk_base = chunkmap_field_index * BFIELD_BITS;
            let valid_chunk_count = core::cmp::min(
                chunk_count.saturating_sub(chunk_base),
                BFIELD_BITS,
            );
            let scan_count = core::cmp::min(highest_map_bit + 1, valid_chunk_count);
            for chunk_offset in (0..scan_count).rev() {
                let chunk_index = chunk_base + chunk_offset;
                if let Some(chunk_bit) = self.chunk(chunk_index).highest_set_relaxed() {
                    return Some(chunk_index * BCHUNK_BITS + chunk_bit);
                }
            }
        }
        None
    }

    /// Port of `mi_bitmap_popcount`: count set data bits selected by the
    /// conservative chunk map without changing either image.
    ///
    /// The pinned source walks chunk-map fields and their set bits low to high,
    /// then sums each selected chunk's fields with Relaxed loads. A stale
    /// in-layout map bit consequently contributes zero for an empty data
    /// chunk; this observer neither repairs that map bit nor reads data from a
    /// chunk whose map bit was not observed set. Like the source, its result is
    /// a mixed-time observation under concurrent mutation, not a snapshot.
    ///
    /// Pinned C requires every selected map bit to name dynamic trailing
    /// storage. The checked Rust view skips an out-of-layout stale bit rather
    /// than deriving an out-of-bounds chunk pointer, while retaining that map
    /// bit unchanged.
    #[inline]
    pub(crate) fn popcount_relaxed(&self) -> usize {
        let chunk_count = self.chunk_count();
        let chunkmap_field_count = (chunk_count + BFIELD_BITS - 1) / BFIELD_BITS;
        let mut count = 0;

        for chunkmap_field_index in 0..chunkmap_field_count {
            let mut chunkmap_entry =
                word_load_relaxed(self.chunkmap().field(chunkmap_field_index));
            while chunkmap_entry != 0 {
                let chunkmap_bit = ctz(chunkmap_entry);
                chunkmap_entry &= chunkmap_entry.wrapping_sub(1);
                let chunk_index = chunkmap_field_index * BFIELD_BITS + chunkmap_bit;
                if chunk_index < chunk_count {
                    count += self.chunk(chunk_index).popcount_relaxed();
                }
            }
        }
        count
    }

    /// Finds and atomically claims the lowest available bit through ordinary
    /// `mi_bitmap_find(..., tseq = 0, n = 1)` traversal.
    ///
    /// It does not raw-scan bitmap words: every candidate comes from the
    /// conservative chunk map, the source one-bit AcqRel claim is used, and a
    /// drained candidate repairs that map before search continues.
    #[inline]
    pub(crate) fn try_find_and_claim_lowest(&self) -> Option<usize> {
        let field_count = (self.chunk_count() + BFIELD_BITS - 1) / BFIELD_BITS;
        for field_index in 0..field_count {
            let mut candidates = word_load_relaxed(self.chunkmap().field(field_index));
            while candidates != 0 {
                let candidate = ctz(candidates);
                candidates &= candidates.wrapping_sub(1);
                let chunk_index = field_index * BFIELD_BITS + candidate;
                if chunk_index >= self.chunk_count() {
                    // Checked Rust ignores a stale map bit instead of naming
                    // storage beyond this dynamic image.
                    continue;
                }
                if let Some(bit) = self.chunk(chunk_index).try_claim_one() {
                    return Some(chunk_index * BCHUNK_BITS + bit);
                }
                let _ = self.chunkmap_try_clear(chunk_index);
            }
        }
        None
    }

    /// Finds one set bit using the source's abandoned-page reader order,
    /// atomically removes it, and lets the page-ownership transition decide
    /// whether that bit remains removed.
    ///
    /// This is the narrow `mi_bitmap_try_find_and_claim` visitor used only by
    /// `arena.c` abandoned-page adoption. It retains the source's relaxed
    /// chunkmap observations, high-bit bounded cycle, `tseq % 8` spreading,
    /// AcqRel bit claim, and conservative map repair. `claim` runs only while
    /// its candidate bit is clear. If it reports [`AbandonedBitmapClaim::KeepSet`],
    /// this method restores the bit and its conservative map before it can
    /// return or inspect another candidate.
    pub(crate) fn try_find_and_claim_abandoned<F>(
        &self,
        thread_sequence: usize,
        mut claim: F,
    ) -> Option<usize>
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        let chunkmap_field_count = (self.chunk_count() + BFIELD_BITS - 1) / BFIELD_BITS;
        for chunkmap_field in 0..chunkmap_field_count {
            let chunkmap_entry = word_load_relaxed(self.chunkmap().field(chunkmap_field));
            let Some(highest) = bsr(chunkmap_entry) else {
                continue;
            };
            let cycle = highest + 1;
            // `mi_bitmap_find` first reduces `tseq` to eight buckets, then
            // `mi_bfield_cycle_iterate` applies its 32-bit modulo.
            let start = ((thread_sequence as u32 as usize) % 8) % cycle;
            let cycle_mask = field_mask_valid(cycle - start, start);
            let mut primary = chunkmap_entry & cycle_mask;
            let mut rest = chunkmap_entry & !cycle_mask;

            while primary != 0 || rest != 0 {
                let candidates = if primary != 0 {
                    &mut primary
                } else {
                    &mut rest
                };
                let candidate_bit = ctz(*candidates);
                *candidates &= candidates.wrapping_sub(1);
                let chunk_index = chunkmap_field * BFIELD_BITS + candidate_bit;
                if chunk_index >= self.chunk_count() {
                    // The source regards this as an internal invariant. A
                    // checked Rust view instead ignores a stale invalid map
                    // bit, never indexing outside its caller-owned storage.
                    continue;
                }
                let chunk = self.chunk(chunk_index);
                let Some(chunk_bit) = chunk.try_claim_one() else {
                    // The chunkmap is conservative: a failed bit claim may
                    // discover that its chunk was already drained.
                    let _ = self.chunkmap_try_clear(chunk_index);
                    continue;
                };
                let index = chunk_index * BCHUNK_BITS + chunk_bit;
                match claim(index) {
                    AbandonedBitmapClaim::Claimed => return Some(index),
                    AbandonedBitmapClaim::Discarded => (),
                    AbandonedBitmapClaim::KeepSet => {
                        let restored = chunk.set_run(chunk_bit, 1);
                        debug_assert!(matches!(restored, Some(transition) if transition.all_transitioned()));
                        self.chunkmap_set(chunk_index);
                    }
                }
            }
        }
        None
    }

    /// Clears one abandoned-page map bit, waiting until a temporary reader
    /// restores it when that reader lost the page ownership claim.
    ///
    /// This is the exact `mi_bitmap_clear_once_set` path used by
    /// `_mi_arenas_page_unabandon`. A Relaxed observation avoids the usual
    /// acquire cost. If a reader has temporarily cleared the bit, the second
    /// Acquire observation and yielding loop establish the source's bitmap
    /// quiescence: the writer does not clear permanently until that reader has
    /// restored its failed candidate. A successful weak CAS uses AcqRel and
    /// leaves the conservative chunk map set, as upstream does.
    pub(crate) fn clear_once_set(&self, subprocess: &crate::subproc::MainSubprocess, index: usize) -> Option<()> {
        self.clear_once_set_with(subprocess, index, || {})
    }

    fn clear_once_set_with<F>(&self, subprocess: &crate::subproc::MainSubprocess, index: usize, mut observed_temporary_clear: F) -> Option<()>
    where
        F: FnMut(),
    {
        let range = self.range(index, 1)?;
        let chunk_index = range.index / BCHUNK_BITS;
        let chunk_bit = range.index % BCHUNK_BITS;
        let field_index = chunk_bit / BFIELD_BITS;
        let bit_index = chunk_bit % BFIELD_BITS;
        let mask = field_mask_valid(1, bit_index);
        let field = self.chunk(chunk_index).field(field_index);
        let mut previous = word_load_relaxed(field);
        loop {
            if previous & mask == 0 {
                observed_temporary_clear();
                previous = word_load_acquire(field);
                if previous & mask == 0 {
                    subprocess.bitmap_statistics().busy_wait();
                }
                while previous & mask == 0 {
                    // `sched_yield` is the Linux no-libc equivalent of the
                    // pinned `_mi_prim_thread_yield` busy-wait backoff. Its
                    // failure cannot turn a required quiescence wait into a
                    // successful clear, so retain the loop either way.
                    let _ = crate::os::thread_yield();
                    previous = word_load_acquire(field);
                }
            }
            let replacement = previous & !mask;
            if word_cas_weak_acq_rel(field, &mut previous, replacement) {
                return Some(());
            }
        }
    }

    #[cfg(test)]
    fn clear_once_set_observing_temporary_clear<F>(&self, index: usize, observer: F) -> Option<()>
    where
        F: FnMut(),
    {
        self.clear_once_set_with(crate::subproc::MainSubprocess::test_static_owner(), index, observer)
    }
}

/// The frozen v3.5.0 size classes assigned to free-slice chunks.
///
/// `None` is deliberately represented even though it has no dedicated
/// chunk-map: it means that a completely free chunk has not yet been reserved
/// for one of the five allocation size classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChunkBin {
    Small,
    Other,
    Medium,
    Large,
    Huge,
    None,
}

impl ChunkBin {
    const MAPPED_COUNT: usize = 5;

    #[inline]
    pub(crate) const fn of_slice_count(slice_count: usize) -> Self {
        if slice_count == 1 {
            Self::Small
        } else if slice_count == 8 {
            Self::Medium
        } else if slice_count == BFIELD_BITS {
            // `MI_ENABLE_LARGE_PAGES` is true in the frozen profile.
            Self::Large
        } else if slice_count > BCHUNK_BITS {
            Self::Huge
        } else {
            Self::Other
        }
    }

    #[inline]
    const fn index(self) -> usize {
        match self {
            Self::Small => 0,
            Self::Other => 1,
            Self::Medium => 2,
            Self::Large => 3,
            Self::Huge => 4,
            Self::None => 5,
        }
    }

    #[inline]
    const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Small,
            1 => Self::Other,
            2 => Self::Medium,
            3 => Self::Large,
            4 => Self::Huge,
            _ => Self::None,
        }
    }
}

/// Fixed prefix of `mi_bbitmap_t` before its dynamic `chunks` tail.
#[repr(C, align(64))]
struct BinnedBitmapPrefix {
    chunk_count: AtomicWord,
    chunk_max_accessed: AtomicWord,
    subprocess: *mut crate::types::Subprocess,
    padding: [usize; BCHUNK_SIZE / size_of::<usize>() - 3],
    chunkmap: Chunk,
    chunkmap_bins: [Chunk; ChunkBin::MAPPED_COUNT],
}

const BINNED_BITMAP_CHUNKS_OFFSET: usize = size_of::<BinnedBitmapPrefix>();

const _: [(); BCHUNK_SIZE] = [(); align_of::<BinnedBitmapPrefix>()];
const _: [(); 7 * BCHUNK_SIZE] = [(); BINNED_BITMAP_CHUNKS_OFFSET];
const _: [(); 0] = [(); BINNED_BITMAP_CHUNKS_OFFSET % BCHUNK_SIZE];

/// Checked dynamic layout returned by `mi_bbitmap_size`.
///
/// Unlike the ordinary bitmap layout, the source rounds a positive bit count
/// up to a whole chunk. The rounded capacity is part of the resulting view;
/// callers that need to hide padding retain their original logical bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BinnedBitmapLayout {
    chunk_count: usize,
}

impl BinnedBitmapLayout {
    pub(crate) const fn for_bit_count(bit_count: usize) -> Option<Self> {
        if bit_count == 0 || bit_count > BITMAP_MAX_BIT_COUNT {
            return None;
        }
        let Some(rounded) = bit_count.checked_add(BCHUNK_BITS - 1) else {
            return None;
        };
        let chunk_count = rounded / BCHUNK_BITS;
        if chunk_count == 0 || chunk_count > BITMAP_MAX_CHUNK_COUNT {
            return None;
        }
        Some(Self { chunk_count })
    }

    #[inline]
    pub(crate) const fn chunk_count(self) -> usize {
        self.chunk_count
    }

    #[inline]
    pub(crate) const fn max_bits(self) -> usize {
        self.chunk_count * BCHUNK_BITS
    }

    #[inline]
    pub(crate) const fn byte_size(self) -> usize {
        BINNED_BITMAP_CHUNKS_OFFSET + self.chunk_count * BCHUNK_SIZE
    }
}

/// Lifetime-bound view over a caller-owned `mi_bbitmap_t` image.
pub(crate) struct BinnedBitmapView<'storage> {
    storage: NonNull<u8>,
    layout: BinnedBitmapLayout,
    _storage: PhantomData<&'storage mut [u8]>,
}

// SAFETY: initialization establishes the source's atomic representation and
// ties all later access to the backing region. Non-atomic initialization is
// available only through `&mut self` under an explicit quiescence contract.
unsafe impl Send for BinnedBitmapView<'_> {}
unsafe impl Sync for BinnedBitmapView<'_> {}

impl<'storage> BinnedBitmapView<'storage> {
    /// Initializes a binned bitmap in caller-owned BCHUNK-aligned storage.
    ///
    /// # Safety
    ///
    /// `storage` must be one exclusively owned writable allocation covering
    /// `layout.byte_size()` bytes for `'storage`. If `already_zero` is true,
    /// the complete image must already contain initialized zero bytes. No
    /// concurrent observer may access it until this call returns.
    /// `subprocess` must point to a live initialized `MainSubprocess` that
    /// outlives this image and every attached view; bin transitions update
    /// its statistics through shared atomic access.
    pub(crate) unsafe fn initialize(
        subprocess: *mut crate::types::Subprocess,
        storage: *mut u8,
        storage_byte_count: usize,
        layout: BinnedBitmapLayout,
        already_zero: bool,
    ) -> Option<Self> {
        if subprocess.is_null() || storage.is_null()
            || (storage as usize) % BCHUNK_SIZE != 0
            || storage_byte_count < layout.byte_size()
        {
            return None;
        }
        if !already_zero {
            unsafe { core::ptr::write_bytes(storage, 0, layout.byte_size()) };
        }
        let prefix = storage.cast::<BinnedBitmapPrefix>();
        // Preserve `mi_bbitmap_init` order: publish the count, then install the
        // constant subprocess statistics owner before returning the view.
        unsafe { word_store_release(&(*prefix).chunk_count, layout.chunk_count) };
        unsafe { (*prefix).subprocess = subprocess };
        Some(Self {
            storage: unsafe { NonNull::new_unchecked(storage) },
            layout,
            _storage: PhantomData,
        })
    }

    /// Attaches to an image previously initialized for this exact layout.
    ///
    /// # Safety
    ///
    /// The storage and publication obligations of [`Self::initialize`] must
    /// remain in force, and the caller must not create an alias that performs
    /// non-atomic access for the returned lifetime.
    pub(crate) unsafe fn attach(
        storage: *mut u8,
        storage_byte_count: usize,
        layout: BinnedBitmapLayout,
    ) -> Option<Self> {
        if storage.is_null()
            || (storage as usize) % BCHUNK_SIZE != 0
            || storage_byte_count < layout.byte_size()
        {
            return None;
        }
        let prefix = storage.cast::<BinnedBitmapPrefix>();
        if unsafe { word_load_relaxed(&(*prefix).chunk_count) } != layout.chunk_count
            || unsafe { (*prefix).subprocess.is_null() }
        {
            return None;
        }
        Some(Self {
            storage: unsafe { NonNull::new_unchecked(storage) },
            layout,
            _storage: PhantomData,
        })
    }

    #[inline]
    fn prefix(&self) -> &BinnedBitmapPrefix {
        unsafe { &*self.storage.as_ptr().cast::<BinnedBitmapPrefix>() }
    }

    #[inline]
    fn chunks_ptr(&self) -> *mut Chunk {
        unsafe {
            self.storage
                .as_ptr()
                .add(BINNED_BITMAP_CHUNKS_OFFSET)
                .cast::<Chunk>()
        }
    }

    #[inline]
    fn chunk(&self, chunk_index: usize) -> &Chunk {
        debug_assert!(chunk_index < self.layout.chunk_count());
        unsafe { &*self.chunks_ptr().add(chunk_index) }
    }

    #[inline]
    fn chunkmap(&self) -> &Chunk {
        &self.prefix().chunkmap
    }

    #[inline]
    fn bin_map(&self, bin: ChunkBin) -> &Chunk {
        debug_assert!(bin.index() < ChunkBin::MAPPED_COUNT);
        &self.prefix().chunkmap_bins[bin.index()]
    }

    #[inline]
    pub(crate) const fn byte_size(&self) -> usize {
        self.layout.byte_size()
    }

    #[inline]
    pub(crate) fn chunk_count(&self) -> usize {
        word_load_relaxed(&self.prefix().chunk_count)
    }

    #[inline]
    pub(crate) fn max_bits(&self) -> usize {
        self.chunk_count() * BCHUNK_BITS
    }

    #[inline]
    pub(crate) fn subprocess(&self) -> *mut crate::types::Subprocess {
        self.prefix().subprocess
    }

    #[inline]
    pub(crate) fn max_accessed_chunk(&self) -> usize {
        word_load_relaxed(&self.prefix().chunk_max_accessed)
    }

    /// Port of `mi_bbitmap_bsr_inv`: scan every rounded bitmap chunk from
    /// high to low for its highest clear bit. This deliberately does not use
    /// the conservative set-bit chunk map; as noted in the pinned source, the
    /// rounded top-padding remains observable here.
    ///
    /// Each chunk result is only a Relaxed observation. This narrow helper is
    /// not a binned allocation search or a concurrent snapshot.
    pub(crate) fn highest_clear_relaxed(&self) -> Option<usize> {
        for chunk_index in (0..self.chunk_count()).rev() {
            if let Some(index) = self.chunk(chunk_index).highest_clear_relaxed() {
                return Some(chunk_index * BCHUNK_BITS + index);
            }
        }
        None
    }

    pub(crate) fn chunk_bin(&self, chunk_index: usize) -> Option<ChunkBin> {
        if chunk_index >= self.chunk_count() {
            return None;
        }
        for index in 0..ChunkBin::MAPPED_COUNT {
            let bin = ChunkBin::from_index(index);
            if self.bin_map(bin).is_set_run(chunk_index, 1) {
                return Some(bin);
            }
        }
        Some(ChunkBin::None)
    }

    fn set_chunk_bin(&self, chunk_index: usize, selected: ChunkBin) {
        debug_assert!(chunk_index < self.chunk_count());
        // SAFETY: initialize/attach retain the live source subprocess owner
        // for the entire image lifetime, including these atomic updates.
        let stats = unsafe { &*self.subprocess() }.bitmap_statistics();
        for index in 0..ChunkBin::MAPPED_COUNT {
            let bin = ChunkBin::from_index(index);
            if bin == selected {
                if self.bin_map(bin).set_run(chunk_index, 1).is_some_and(|change| change.all_transitioned()) {
                    stats.chunk_bins[index].update(1);
                }
            } else {
                if self.bin_map(bin).clear_run(chunk_index, 1).is_some_and(|change| change.all_transitioned()) {
                    stats.chunk_bins[index].update(-1);
                }
            }
        }
    }

    fn set_max_accessed(&self, chunk_index: usize) {
        let mut old_max = word_load_relaxed(&self.prefix().chunk_max_accessed);
        if chunk_index > old_max {
            let _ = word_cas_strong_relaxed(
                &self.prefix().chunk_max_accessed,
                &mut old_max,
                chunk_index,
            );
        }
    }

    fn chunkmap_set(&self, chunk_index: usize, check_all_set: bool) {
        debug_assert!(chunk_index < self.chunk_count());
        if check_all_set && self.chunk(chunk_index).all_are_set_relaxed() {
            self.set_chunk_bin(chunk_index, ChunkBin::None);
        }
        let _ = self.chunkmap().set_run(chunk_index, 1);
        self.set_max_accessed(chunk_index);
    }

    fn chunkmap_try_clear(&self, chunk_index: usize) -> bool {
        let chunk = self.chunk(chunk_index);
        if !chunk.all_are_clear_relaxed() {
            return false;
        }
        let _ = self.chunkmap().clear_run(chunk_index, 1);
        if !chunk.all_are_clear_relaxed() {
            let _ = self.chunkmap().set_run(chunk_index, 1);
            return false;
        }
        self.set_max_accessed(chunk_index);
        true
    }

    /// Local-only `mi_bbitmap_unsafe_setN`.
    ///
    /// # Safety
    ///
    /// The caller must have exclusive quiescent access to every touched chunk
    /// and its conservative map bits. Multi-chunk ranges must start at a chunk
    /// boundary, matching all source callers of the non-atomic middle-chunk
    /// path.
    pub(crate) unsafe fn unsafe_set_range_local(
        &mut self,
        index: usize,
        len: usize,
    ) -> Option<()> {
        let range = BitmapRange::new(index, len, self.max_bits())?;
        let chunk_start = range.index / BCHUNK_BITS;
        let map_count = range.len / BCHUNK_BITS + usize::from(range.len % BCHUNK_BITS != 0);
        let touched_count = (range.index % BCHUNK_BITS)
            .checked_add(range.len)?
            .checked_add(BCHUNK_BITS - 1)?
            / BCHUNK_BITS;
        // `mi_bchunks_unsafe_setN` derives its map span from `n` alone. Its
        // arena callers may begin inside a chunk only when the range ends on a
        // chunk boundary; reject any other shape before it could leave the
        // conservative map missing the final touched chunk.
        if touched_count != map_count {
            return None;
        }
        let _ = self.chunkmap().set_run(chunk_start, map_count);

        let mut chunk_index = chunk_start;
        let mut chunk_bit = range.index % BCHUNK_BITS;
        let mut remaining = range.len;
        let first = core::cmp::min(BCHUNK_BITS - chunk_bit, remaining);
        let _ = self.chunk(chunk_index).set_run(chunk_bit, first);
        chunk_index += 1;
        remaining -= first;

        let whole_chunks = remaining / BCHUNK_BITS;
        for offset in 0..whole_chunks {
            unsafe {
                self.chunks_ptr()
                    .add(chunk_index + offset)
                    .write(Chunk::all_set())
            };
        }
        chunk_index += whole_chunks;
        remaining -= whole_chunks * BCHUNK_BITS;
        if remaining != 0 {
            chunk_bit = 0;
            let _ = self.chunk(chunk_index).set_run(chunk_bit, remaining);
        }
        Some(())
    }

    pub(crate) fn set_range(&self, index: usize, len: usize) -> Option<bool> {
        let range = BitmapRange::new(index, len, self.max_bits())?;
        let mut chunk_index = range.index / BCHUNK_BITS;
        let mut chunk_bit = range.index % BCHUNK_BITS;
        let mut remaining = range.len;
        let mut all_clear = true;
        while remaining != 0 {
            let count = core::cmp::min(BCHUNK_BITS - chunk_bit, remaining);
            let transition = self.chunk(chunk_index).set_run(chunk_bit, count)?;
            all_clear &= transition.all_transitioned();
            self.chunkmap_set(chunk_index, true);
            remaining -= count;
            chunk_bit = 0;
            chunk_index += 1;
        }
        Some(all_clear)
    }

    pub(crate) fn is_xset_range(&self, set: bool, index: usize, len: usize) -> Option<bool> {
        let range = BitmapRange::new(index, len, self.max_bits())?;
        let mut chunk_index = range.index / BCHUNK_BITS;
        let mut chunk_bit = range.index % BCHUNK_BITS;
        let mut remaining = range.len;
        while remaining != 0 {
            let count = core::cmp::min(BCHUNK_BITS - chunk_bit, remaining);
            if !self.chunk(chunk_index).is_xset_run(set, chunk_bit, count) {
                return Some(false);
            }
            remaining -= count;
            chunk_bit = 0;
            chunk_index += 1;
        }
        Some(true)
    }

    #[inline]
    pub(crate) fn is_set_range(&self, index: usize, len: usize) -> Option<bool> {
        self.is_xset_range(true, index, len)
    }

    #[inline]
    pub(crate) fn is_clear_range(&self, index: usize, len: usize) -> Option<bool> {
        self.is_xset_range(false, index, len)
    }

    /// Exact single-chunk `mi_bbitmap_try_clearNC` boundary.
    pub(crate) fn try_clear_within_chunk(&self, index: usize, len: usize) -> Option<bool> {
        let range = BitmapRange::new(index, len, self.max_bits())?;
        if len > BCHUNK_BITS {
            return None;
        }
        let chunk_index = range.index / BCHUNK_BITS;
        let chunk_bit = range.index % BCHUNK_BITS;
        if chunk_bit.checked_add(len)? > BCHUNK_BITS {
            return None;
        }
        let result = self.chunk(chunk_index).try_claim_at(chunk_bit, len)?;
        if result.is_claimed() && result.maybe_all_clear() {
            let _ = self.chunkmap_try_clear(chunk_index);
        } else if result.temporarily_unclaimed() {
            self.chunkmap_set(chunk_index, false);
        }
        Some(result.is_claimed())
    }

    /// Binned two-level search with the source's thread spreading, bin order,
    /// specialized one-chunk claims, and huge-object chunk rollback.
    pub(crate) fn try_find_and_claim(&self, thread_sequence: usize, len: usize) -> Option<usize> {
        if len == 0 || len > self.max_bits() {
            return None;
        }
        if len > BCHUNK_BITS {
            return self.try_find_and_claim_chunks(len);
        }
        self.try_find_and_claim_within_chunk(thread_sequence, len)
    }

    fn try_find_and_claim_within_chunk(
        &self,
        thread_sequence: usize,
        len: usize,
    ) -> Option<usize> {
        let cmap_max_count = (self.chunk_count() + BFIELD_BITS - 1) / BFIELD_BITS;
        let chunk_accessed = self.max_accessed_chunk();
        let cmap_accessed = chunk_accessed / BFIELD_BITS;
        let cmap_accessed_bits = 1 + chunk_accessed % BFIELD_BITS;
        let cmap_mask = field_mask_valid(cmap_max_count, 0);
        let cmap_cycle = cmap_accessed + 1;
        let requested_bin = ChunkBin::of_slice_count(len);

        let outer_start = (thread_sequence as u32 as usize) % cmap_cycle;
        let outer_cycle_mask = field_mask_valid(cmap_cycle - outer_start, outer_start);
        let mut outer_primary = cmap_mask & outer_cycle_mask;
        let mut outer_rest = cmap_mask & !outer_cycle_mask;
        while outer_primary != 0 || outer_rest != 0 {
            let source = if outer_primary != 0 {
                &mut outer_primary
            } else {
                &mut outer_rest
            };
            let cmap_index = ctz(*source);
            *source &= source.wrapping_sub(1);

            let cmap_entry = word_load_relaxed(self.chunkmap().field(cmap_index));
            if cmap_entry == 0 {
                continue;
            }
            let entry_cycle = if cmap_index != cmap_accessed {
                BFIELD_BITS
            } else {
                cmap_accessed_bits
            };
            let mut bin_masks = [0usize; 6];
            bin_masks[ChunkBin::None.index()] = cmap_entry;
            for bin_index in 0..ChunkBin::MAPPED_COUNT {
                let bin = ChunkBin::from_index(bin_index);
                let value = word_load_relaxed(self.bin_map(bin).field(cmap_index)) & cmap_entry;
                bin_masks[bin_index] = value;
                bin_masks[ChunkBin::None.index()] &= !value;
            }

            let mut bin = ChunkBin::Small;
            loop {
                let entry = bin_masks[bin.index()];
                let start = (thread_sequence as u32 as usize) % entry_cycle;
                let cycle_mask = field_mask_valid(entry_cycle - start, start);
                let mut primary = entry & cycle_mask;
                let mut rest = entry & !cycle_mask;
                while primary != 0 || rest != 0 {
                    let source = if primary != 0 { &mut primary } else { &mut rest };
                    let entry_index = ctz(*source);
                    *source &= source.wrapping_sub(1);
                    let chunk_index = cmap_index * BFIELD_BITS + entry_index;
                    if chunk_index >= self.chunk_count() {
                        continue;
                    }
                    let result = self.chunk(chunk_index).try_claim_run_detailed(len);
                    if let Some(chunk_bit) = result.index {
                        if chunk_bit == 0 && bin == ChunkBin::None {
                            self.set_chunk_bin(chunk_index, requested_bin);
                        }
                        return Some(chunk_index * BCHUNK_BITS + chunk_bit);
                    }
                    if result.temporarily_unclaimed {
                        self.chunkmap_set(chunk_index, false);
                    } else {
                        let _ = self.chunkmap_try_clear(chunk_index);
                    }
                }

                if bin == ChunkBin::None {
                    break;
                }
                bin = if bin == requested_bin {
                    ChunkBin::None
                } else {
                    ChunkBin::from_index(bin.index() + 1)
                };
            }
        }
        None
    }

    fn try_find_and_claim_chunks(&self, len: usize) -> Option<usize> {
        let required = (len + BCHUNK_BITS - 1) / BCHUNK_BITS;
        if self.chunk_count() < required {
            return None;
        }
        let mut chunk_index = 0;
        while chunk_index <= self.chunk_count() - required {
            let mut count = 0;
            while count < required && self.chunk(chunk_index + count).all_are_set_relaxed() {
                count += 1;
            }
            if count == required {
                if self.try_claim_chunks_at(chunk_index, len) {
                    for offset in 0..count {
                        self.set_chunk_bin(chunk_index + offset, ChunkBin::Huge);
                    }
                    return Some(chunk_index * BCHUNK_BITS);
                }
                count = 0;
            }
            chunk_index += count + 1;
        }
        None
    }

    fn try_claim_chunks_at(&self, chunk_index: usize, len: usize) -> bool {
        if len == 0
            || chunk_index >= self.chunk_count()
            || chunk_index
                .checked_mul(BCHUNK_BITS)
                .and_then(|start| start.checked_add(len))
                .is_none_or(|end| end > self.max_bits())
        {
            return false;
        }
        let mut remaining = len;
        let mut claimed_count = 0;
        while remaining != 0 {
            let count = core::cmp::min(remaining, BCHUNK_BITS);
            let Some(claim) = self.chunk(chunk_index + claimed_count).try_claim_at(0, count) else {
                break;
            };
            if !claim.is_claimed() {
                break;
            }
            remaining -= count;
            claimed_count += 1;
        }
        if remaining == 0 {
            return true;
        }
        while claimed_count != 0 {
            claimed_count -= 1;
            let _ = self
                .chunk(chunk_index + claimed_count)
                .set_run(0, BCHUNK_BITS);
            self.chunkmap_set(chunk_index + claimed_count, false);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[repr(align(64))]
    struct BitmapTestStorage {
        bytes: [MaybeUninit<u8>; 320],
    }

    #[repr(align(64))]
    struct BinnedBitmapTestStorage {
        bytes: [MaybeUninit<u8>; 640],
    }

    // This image crosses the first source `mi_bfield_t` boundary in the
    // chunk-map: chunk 0 lives in map field 0, while chunk 64 lives in map
    // field 1. It is intentionally test storage only; `BitmapView` remains a
    // caller-owned dynamic view rather than a fixed Rust bitmap owner.
    const SET_VISITOR_CHUNK_COUNT: usize = BFIELD_BITS + 1;
    const SET_VISITOR_STORAGE_BYTES: usize =
        BITMAP_CHUNKS_OFFSET + SET_VISITOR_CHUNK_COUNT * BCHUNK_SIZE;

    #[repr(align(64))]
    struct BitmapSetVisitorTestStorage {
        bytes: [MaybeUninit<u8>; SET_VISITOR_STORAGE_BYTES],
    }

    impl BitmapTestStorage {
        const fn uninit() -> Self {
            Self {
                bytes: [const { MaybeUninit::uninit() }; 320],
            }
        }
    }

    impl BinnedBitmapTestStorage {
        const fn uninit() -> Self {
            Self {
                bytes: [const { MaybeUninit::uninit() }; 640],
            }
        }
    }

    impl BitmapSetVisitorTestStorage {
        const fn uninit() -> Self {
            Self {
                bytes: [const { MaybeUninit::uninit() }; SET_VISITOR_STORAGE_BYTES],
            }
        }
    }

    #[test]
    fn binned_bitmap_layout_rounds_to_chunks_and_preserves_the_source_header() {
        assert_eq!(BinnedBitmapLayout::for_bit_count(0), None);
        assert_eq!(BinnedBitmapLayout::for_bit_count(1).unwrap().chunk_count(), 1);
        assert_eq!(
            BinnedBitmapLayout::for_bit_count(BCHUNK_BITS).unwrap().byte_size(),
            8 * BCHUNK_SIZE,
        );
        assert_eq!(
            BinnedBitmapLayout::for_bit_count(BCHUNK_BITS + 1)
                .unwrap()
                .chunk_count(),
            2,
        );
        assert_eq!(
            BinnedBitmapLayout::for_bit_count(BCHUNK_BITS + 1)
                .unwrap()
                .byte_size(),
            9 * BCHUNK_SIZE,
        );
        assert_eq!(BinnedBitmapLayout::for_bit_count(BITMAP_MAX_BIT_COUNT + 1), None);
    }

    #[test]
    fn binned_highest_clear_scans_the_source_rounded_top_padding() {
        // `mi_bbitmap_bsr_inv` deliberately scans the rounded `chunk_count`
        // capacity rather than the requested logical count; the pinned source
        // records this as a TODO at `src/bitmap.c:1619`.
        let logical_bit_count = BCHUNK_BITS + 1;
        let layout = BinnedBitmapLayout::for_bit_count(logical_bit_count).unwrap();
        assert_eq!(layout.chunk_count(), 2);
        assert_eq!(layout.max_bits(), BCHUNK_BITS * 2);
        let mut storage = BinnedBitmapTestStorage::uninit();
        let bitmap = unsafe {
            BinnedBitmapView::initialize(
                crate::subproc::MainSubprocess::test_static_owner().as_ptr(),
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        // Initialization leaves the conservative set-bit map empty. The
        // inverse scan must still inspect every data chunk and return the
        // highest bit of the rounded (therefore padded) second chunk.
        assert!(bitmap.chunkmap().all_are_clear_relaxed());
        assert_eq!(
            bitmap.highest_clear_relaxed(),
            Some(layout.max_bits() - 1),
        );
    }

    #[test]
    fn binned_highest_clear_scans_chunks_and_fields_from_high_to_low() {
        let layout = BinnedBitmapLayout::for_bit_count(BCHUNK_BITS * 2).unwrap();
        let mut storage = BinnedBitmapTestStorage::uninit();
        let bitmap = unsafe {
            BinnedBitmapView::initialize(
                crate::subproc::MainSubprocess::test_static_owner().as_ptr(),
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        assert_eq!(bitmap.set_range(0, layout.max_bits()), Some(true));
        assert_eq!(bitmap.highest_clear_relaxed(), None);

        let lower_chunk = BCHUNK_BITS - 1;
        let upper_chunk_lower_field = BCHUNK_BITS + BFIELD_BITS + 9;
        let upper_chunk_higher_field = BCHUNK_BITS + BCHUNK_BITS - BFIELD_BITS + 3;
        assert_eq!(bitmap.try_clear_within_chunk(lower_chunk, 1), Some(true));
        assert_eq!(
            bitmap.try_clear_within_chunk(upper_chunk_lower_field, 1),
            Some(true)
        );
        assert_eq!(
            bitmap.try_clear_within_chunk(upper_chunk_higher_field, 1),
            Some(true)
        );

        // `mi_bbitmap_bsr_inv` descends chunks, and `mi_bchunk_bsr_inv`
        // descends fields within a selected chunk.
        assert_eq!(
            bitmap.highest_clear_relaxed(),
            Some(upper_chunk_higher_field),
        );
        assert_eq!(bitmap.set_range(upper_chunk_higher_field, 1), Some(true));
        assert_eq!(
            bitmap.highest_clear_relaxed(),
            Some(upper_chunk_lower_field),
        );
        assert_eq!(bitmap.set_range(upper_chunk_lower_field, 1), Some(true));
        assert_eq!(bitmap.highest_clear_relaxed(), Some(lower_chunk));
    }

    /// Emits the address-free Rust half of the selected pinned-C
    /// `mi_bbitmap_bsr_inv` differential. One fresh logical 513-bit image
    /// proves that this observer sees source-rounded top padding even while its
    /// conservative chunk map is empty. A separate two-chunk image proves the
    /// high-to-low chunk and field order without exercising binned search or
    /// chunk-map maintenance.
    #[test]
    fn emit_m2_binned_bitmap_bsr_inv_c_rust_trace() {
        extern crate std;

        const PADDING_LOGICAL_BIT_COUNT: usize = BCHUNK_BITS + 1;
        const SCAN_BIT_COUNT: usize = BCHUNK_BITS * 2;
        const LOWER_INDEX: usize = BCHUNK_BITS - 1;
        const UPPER_LOWER_FIELD_INDEX: usize = BCHUNK_BITS + BFIELD_BITS + 9;
        const UPPER_HIGHER_FIELD_INDEX: usize = BCHUNK_BITS + BCHUNK_BITS - BFIELD_BITS + 3;

        let padding_layout = BinnedBitmapLayout::for_bit_count(PADDING_LOGICAL_BIT_COUNT).unwrap();
        let mut padding_storage = BinnedBitmapTestStorage::uninit();
        let padding = unsafe {
            BinnedBitmapView::initialize(
                crate::subproc::MainSubprocess::test_static_owner().as_ptr(),
                padding_storage.bytes.as_mut_ptr().cast(),
                padding_storage.bytes.len(),
                padding_layout,
                false,
            )
            .unwrap()
        };
        let padding_chunkmap_empty = padding.chunkmap().all_are_clear_relaxed();
        let padding_result = padding.highest_clear_relaxed();
        let padding_returned_found = padding_result.is_some();
        let padding_index = padding_result.unwrap_or(0);

        let scan_layout = BinnedBitmapLayout::for_bit_count(SCAN_BIT_COUNT).unwrap();
        let mut scan_storage = BinnedBitmapTestStorage::uninit();
        let scan = unsafe {
            BinnedBitmapView::initialize(
                crate::subproc::MainSubprocess::test_static_owner().as_ptr(),
                scan_storage.bytes.as_mut_ptr().cast(),
                scan_storage.bytes.len(),
                scan_layout,
                false,
            )
            .unwrap()
        };
        let scan_seeded = (0..scan.chunk_count()).all(|chunk_index| {
            matches!(
                scan.chunk(chunk_index).set_run(0, BCHUNK_BITS),
                Some(transition) if transition.all_transitioned()
            )
        });
        let scan_chunkmap_empty_before = scan.chunkmap().all_are_clear_relaxed();
        let scan_cleared = [LOWER_INDEX, UPPER_LOWER_FIELD_INDEX, UPPER_HIGHER_FIELD_INDEX]
            .into_iter()
            .all(|index| {
                matches!(
                    scan.chunk(index / BCHUNK_BITS)
                        .clear_run(index % BCHUNK_BITS, 1),
                    Some(transition) if transition.all_transitioned()
                )
            });

        let first_result = scan.highest_clear_relaxed();
        let first_returned_found = first_result.is_some();
        let first_index = first_result.unwrap_or(0);
        let first_restored = first_result
            .and_then(|index| scan.chunk(index / BCHUNK_BITS).set_run(index % BCHUNK_BITS, 1))
            .is_some_and(RunTransition::all_transitioned);

        let second_result = scan.highest_clear_relaxed();
        let second_returned_found = second_result.is_some();
        let second_index = second_result.unwrap_or(0);
        let second_restored = second_result
            .and_then(|index| scan.chunk(index / BCHUNK_BITS).set_run(index % BCHUNK_BITS, 1))
            .is_some_and(RunTransition::all_transitioned);

        let third_result = scan.highest_clear_relaxed();
        let third_returned_found = third_result.is_some();
        let third_index = third_result.unwrap_or(0);
        let third_restored = third_result
            .and_then(|index| scan.chunk(index / BCHUNK_BITS).set_run(index % BCHUNK_BITS, 1))
            .is_some_and(RunTransition::all_transitioned);

        let drained_returned_found = scan.highest_clear_relaxed().is_some();
        let scan_chunkmap_empty_after = scan.chunkmap().all_are_clear_relaxed();

        assert_eq!(padding_layout.chunk_count(), 2);
        assert_eq!(padding_layout.max_bits(), SCAN_BIT_COUNT);
        assert_eq!(padding_layout.byte_size(), 9 * BCHUNK_SIZE);
        assert!(padding_chunkmap_empty);
        assert!(padding_returned_found);
        assert_eq!(padding_index, SCAN_BIT_COUNT - 1);
        assert_eq!(scan_layout.chunk_count(), 2);
        assert_eq!(scan_layout.byte_size(), 9 * BCHUNK_SIZE);
        assert!(scan_seeded);
        assert!(scan_chunkmap_empty_before);
        assert!(scan_cleared);
        assert!(first_returned_found);
        assert_eq!(first_index, UPPER_HIGHER_FIELD_INDEX);
        assert!(first_restored);
        assert!(second_returned_found);
        assert_eq!(second_index, UPPER_LOWER_FIELD_INDEX);
        assert!(second_restored);
        assert!(third_returned_found);
        assert_eq!(third_index, LOWER_INDEX);
        assert!(third_restored);
        assert!(!drained_returned_found);
        assert!(scan_chunkmap_empty_after);

        macro_rules! emit {
            ($name:expr, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        std::println!("CRABC_MI_M2_BINNED_BITMAP_BSR_INV_TRACE_BEGIN");
        emit!("m2.bbitmap_bsr_inv.control.bfield_bits", BFIELD_BITS);
        emit!("m2.bbitmap_bsr_inv.control.bchunk_bits", BCHUNK_BITS);
        emit!(
            "m2.bbitmap_bsr_inv.padding.logical_bit_count",
            PADDING_LOGICAL_BIT_COUNT
        );
        emit!("m2.bbitmap_bsr_inv.padding.chunk_count", padding.chunk_count());
        emit!("m2.bbitmap_bsr_inv.padding.max_bits", padding.max_bits());
        emit!("m2.bbitmap_bsr_inv.padding.byte_size", padding.byte_size());
        emit!(
            "m2.bbitmap_bsr_inv.padding.chunkmap_empty",
            padding_chunkmap_empty
        );
        emit!(
            "m2.bbitmap_bsr_inv.padding.returned_found",
            padding_returned_found
        );
        emit!("m2.bbitmap_bsr_inv.padding.index", padding_index);
        emit!("m2.bbitmap_bsr_inv.scan.chunk_count", scan.chunk_count());
        emit!("m2.bbitmap_bsr_inv.scan.byte_size", scan.byte_size());
        emit!(
            "m2.bbitmap_bsr_inv.scan.chunkmap_empty_before",
            scan_chunkmap_empty_before
        );
        emit!(
            "m2.bbitmap_bsr_inv.scan.first_returned_found",
            first_returned_found
        );
        emit!("m2.bbitmap_bsr_inv.scan.first_index", first_index);
        emit!(
            "m2.bbitmap_bsr_inv.scan.second_returned_found",
            second_returned_found
        );
        emit!("m2.bbitmap_bsr_inv.scan.second_index", second_index);
        emit!(
            "m2.bbitmap_bsr_inv.scan.third_returned_found",
            third_returned_found
        );
        emit!("m2.bbitmap_bsr_inv.scan.third_index", third_index);
        emit!(
            "m2.bbitmap_bsr_inv.scan.drained_returned_found",
            drained_returned_found
        );
        emit!(
            "m2.bbitmap_bsr_inv.scan.chunkmap_empty_after",
            scan_chunkmap_empty_after
        );
        std::println!("CRABC_MI_M2_BINNED_BITMAP_BSR_INV_TRACE_END");
    }

    #[test]
    fn binned_claim_specializations_keep_chunk_boundaries_and_size_bins() {
        let layout = BinnedBitmapLayout::for_bit_count(BCHUNK_BITS * 2).unwrap();
        let mut storage = BinnedBitmapTestStorage::uninit();
        let mut bitmap = unsafe {
            BinnedBitmapView::initialize(
                crate::subproc::MainSubprocess::test_static_owner().as_ptr(),
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        unsafe { bitmap.unsafe_set_range_local(0, bitmap.max_bits()).unwrap() };
        assert_eq!(bitmap.try_find_and_claim(7, 1), Some(0));
        assert_eq!(bitmap.chunk_bin(0), Some(ChunkBin::Small));
        assert_eq!(bitmap.try_find_and_claim(7, 8), Some(8));
        // The NX source path is not field-aligned: after the one- and
        // byte-sized claims, the next 64-bit run starts at bit 16.
        assert_eq!(bitmap.try_find_and_claim(7, BFIELD_BITS), Some(16));

        let whole_chunk = bitmap.try_find_and_claim(7, BCHUNK_BITS).unwrap();
        assert_eq!(whole_chunk, BCHUNK_BITS);
        assert_eq!(bitmap.chunk_bin(1), Some(ChunkBin::Other));
        assert_eq!(bitmap.try_find_and_claim(0, 0), None);
        assert_eq!(bitmap.try_find_and_claim(0, bitmap.max_bits() + 1), None);
    }

    #[test]
    fn failed_multi_chunk_claim_restores_each_fully_claimed_prefix_chunk() {
        let layout = BinnedBitmapLayout::for_bit_count(BCHUNK_BITS * 2).unwrap();
        let mut storage = BinnedBitmapTestStorage::uninit();
        let mut bitmap = unsafe {
            BinnedBitmapView::initialize(
                crate::subproc::MainSubprocess::test_static_owner().as_ptr(),
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        unsafe { bitmap.unsafe_set_range_local(0, bitmap.max_bits()).unwrap() };
        assert!(bitmap.try_clear_within_chunk(BCHUNK_BITS, 1).unwrap());

        assert!(!bitmap.try_claim_chunks_at(0, BCHUNK_BITS + 1));
        assert!(bitmap.chunk(0).all_are_set_relaxed());
        assert!(bitmap.chunk(1).is_clear_run(0, 1));
        assert!(bitmap.chunkmap().is_set_run(0, 1));
    }

    #[test]
    fn field_masks_and_chunk_indices_preserve_the_64_bit_source_boundary() {
        assert_eq!(field_mask(0, 0), None);
        assert_eq!(field_mask(1, 0), Some(1));
        assert_eq!(field_mask(1, BFIELD_BITS - 1), Some(1usize << (BFIELD_BITS - 1)));
        assert_eq!(field_mask(BFIELD_BITS, 0), Some(usize::MAX));
        assert_eq!(field_mask(BFIELD_BITS, 1), None);
        assert_eq!(field_mask(1, BFIELD_BITS), None);
        assert_eq!(field_mask(usize::MAX, 1), None);

        assert_eq!(ChunkIndex::new(0), Some(ChunkIndex::new(0).unwrap()));
        assert_eq!(ChunkIndex::new(BFIELD_BITS - 1).unwrap().field_index(), 0);
        assert_eq!(ChunkIndex::new(BFIELD_BITS - 1).unwrap().field_bit_index(), BFIELD_BITS - 1);
        assert_eq!(ChunkIndex::new(BFIELD_BITS).unwrap().field_index(), 1);
        assert_eq!(ChunkIndex::new(BFIELD_BITS).unwrap().field_bit_index(), 0);
        assert_eq!(ChunkIndex::new(BCHUNK_BITS - 1).unwrap().field_index(), BCHUNK_FIELDS - 1);
        assert_eq!(ChunkIndex::new(BCHUNK_BITS), None);
    }

    #[test]
    fn zero_one_maximum_and_cross_field_runs_have_explicit_source_boundaries() {
        let chunk = Chunk::new();

        assert!(chunk.set_run(0, 0).is_none());
        assert!(chunk.clear_run(0, 0).is_none());
        assert!(chunk.try_claim_at(0, 0).is_none());
        assert_eq!(chunk.try_claim_run(0), None);

        let one = chunk.unclaim_run(0, 1).unwrap();
        assert!(one.all_transitioned());
        assert_eq!(one.already_set(), 0);
        assert!(!one.maybe_all_clear());
        assert!(chunk.is_set_run(0, 1));
        let one_claim = chunk.try_claim_at(0, 1).unwrap();
        assert!(one_claim.is_claimed());
        assert!(one_claim.maybe_all_clear());
        assert!(!one_claim.temporarily_unclaimed());
        assert!(chunk.is_clear_run(0, 1));
        let repeated_clear = chunk.clear_run(0, 1).unwrap();
        assert!(!repeated_clear.all_transitioned());
        assert!(repeated_clear.maybe_all_clear());

        assert!(chunk.set_run(usize::MAX, 1).is_none());

        assert_eq!(chunk.set_run(0, BCHUNK_BITS), Some(RunTransition::all_clear(0)));
        assert_eq!(chunk.popcount_run(0, BCHUNK_BITS), Some(BCHUNK_BITS));
        assert_eq!(chunk.try_claim_at(0, BCHUNK_BITS), Some(TryClaim::claimed(true, false)));
        assert!(chunk.is_clear_run(0, BCHUNK_BITS));

        assert_eq!(chunk.set_run(BFIELD_BITS - 3, 6), Some(RunTransition::all_clear(0)));
        assert!(chunk.is_set_run(BFIELD_BITS - 3, 6));
        assert_eq!(chunk.try_claim_at(BFIELD_BITS - 3, 6), Some(TryClaim::claimed(true, false)));
        assert!(chunk.is_clear_run(BFIELD_BITS - 3, 6));

        assert_eq!(chunk.set_run(BCHUNK_BITS - 1, 2), None);
        assert_eq!(chunk.try_claim_at(BCHUNK_BITS - 1, 2), None);
    }

    #[test]
    fn failed_cross_field_try_claim_restores_the_previously_cleared_prefix() {
        let chunk = Chunk::new();
        assert_eq!(chunk.set_run(0, BCHUNK_BITS), Some(RunTransition::all_clear(0)));
        assert_eq!(chunk.clear_run(BFIELD_BITS + 1, 1), Some(RunTransition::all_set()));

        let rejected = chunk.try_claim_at(BFIELD_BITS - 2, 5).unwrap();
        assert!(!rejected.is_claimed());
        assert!(rejected.temporarily_unclaimed());
        assert!(chunk.is_set_run(BFIELD_BITS - 2, 2));
        assert!(chunk.is_set_run(BFIELD_BITS, 1));
        assert!(chunk.is_clear_run(BFIELD_BITS + 1, 1));
        assert!(chunk.is_set_run(BFIELD_BITS + 2, 1));
    }

    #[test]
    fn source_ordered_try_claim_selects_lowest_set_run_and_rejects_oversized_runs() {
        let chunk = Chunk::new();
        assert_eq!(chunk.set_run(7, 3), Some(RunTransition::all_clear(0)));
        assert_eq!(chunk.set_run(BFIELD_BITS - 2, 6), Some(RunTransition::all_clear(0)));
        assert_eq!(chunk.try_claim_run(3), Some(7));
        assert_eq!(chunk.try_claim_run(6), Some(BFIELD_BITS - 2));
        assert_eq!(chunk.try_claim_run(1), None);
        assert_eq!(chunk.try_claim_run(BCHUNK_BITS + 1), None);
    }

    #[test]
    fn eight_bit_claims_keep_the_source_byte_alignment_and_large_runs_cross_fields() {
        let byte_chunk = Chunk::new();
        assert_eq!(byte_chunk.set_run(1, 8), Some(RunTransition::all_clear(0)));
        assert_eq!(byte_chunk.try_claim_run(8), None);
        assert_eq!(byte_chunk.set_run(16, 8), Some(RunTransition::all_clear(0)));
        assert_eq!(byte_chunk.try_claim_run(8), Some(16));

        let large_chunk = Chunk::new();
        assert_eq!(large_chunk.set_run(BFIELD_BITS - 3, 130), Some(RunTransition::all_clear(0)));
        assert_eq!(large_chunk.try_claim_run(130), Some(BFIELD_BITS - 3));
        assert!(large_chunk.is_clear_run(BFIELD_BITS - 3, 130));
    }

    #[test]
    fn relaxed_chunk_observers_preserve_reverse_scan_and_full_chunk_boundaries() {
        let chunk = Chunk::new();
        assert!(chunk.all_are_clear_relaxed());
        assert!(!chunk.all_are_set_relaxed());
        assert_eq!(chunk.highest_set_relaxed(), None);
        assert_eq!(chunk.highest_clear_relaxed(), Some(BCHUNK_BITS - 1));
        assert_eq!(chunk.popcount_relaxed(), 0);

        assert_eq!(chunk.set_run(2, 1), Some(RunTransition::all_clear(0)));
        assert_eq!(
            chunk.set_run(BFIELD_BITS + 9, 1),
            Some(RunTransition::all_clear(0))
        );
        assert_eq!(
            chunk.set_run(BCHUNK_BITS - 1, 1),
            Some(RunTransition::all_clear(0))
        );
        assert!(!chunk.all_are_clear_relaxed());
        assert_eq!(chunk.highest_set_relaxed(), Some(BCHUNK_BITS - 1));
        assert_eq!(chunk.popcount_relaxed(), 3);

        let highest_field_clear = chunk.clear_run(BCHUNK_BITS - 1, 1).unwrap();
        assert!(highest_field_clear.all_transitioned());
        assert_eq!(highest_field_clear.already_set(), 0);
        assert!(highest_field_clear.maybe_all_clear());
        assert_eq!(chunk.highest_set_relaxed(), Some(BFIELD_BITS + 9));

        assert_eq!(chunk.set_run(0, BCHUNK_BITS), Some(RunTransition::all_clear(2)));
        assert!(chunk.all_are_set_relaxed());
        assert!(!chunk.all_are_clear_relaxed());
        assert_eq!(chunk.highest_set_relaxed(), Some(BCHUNK_BITS - 1));
        assert_eq!(chunk.highest_clear_relaxed(), None);
        assert_eq!(chunk.popcount_relaxed(), BCHUNK_BITS);

        assert_eq!(
            chunk.clear_run(BFIELD_BITS * 4 + 13, 1),
            Some(RunTransition::all_set())
        );
        assert_eq!(chunk.highest_clear_relaxed(), Some(BFIELD_BITS * 4 + 13));
        assert_eq!(chunk.popcount_relaxed(), BCHUNK_BITS - 1);
    }

    #[test]
    fn concurrent_single_bit_claims_are_exclusive() {
        extern crate std;

        use std::sync::{Arc, Barrier};
        use std::thread;

        let chunk = Arc::new(Chunk::new());
        assert_eq!(chunk.set_run(0, 1), Some(RunTransition::all_clear(0)));
        let start = Arc::new(Barrier::new(3));
        let mut workers = std::vec::Vec::new();

        for _ in 0..2 {
            let worker_chunk = Arc::clone(&chunk);
            let worker_start = Arc::clone(&start);
            workers.push(thread::spawn(move || {
                worker_start.wait();
                worker_chunk.try_claim_run(1)
            }));
        }

        start.wait();
        let claims = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .count();
        assert_eq!(claims, 1);
        assert!(chunk.is_clear_run(0, 1));
    }

    #[test]
    fn bitmap_layout_is_a_chunk_aligned_dynamic_trailing_storage_contract() {
        assert_eq!(BitmapLayout::for_bit_count(0), None);
        assert_eq!(BitmapLayout::for_bit_count(BCHUNK_BITS - 1), None);
        assert_eq!(BitmapLayout::for_bit_count(BCHUNK_BITS + 1), None);
        assert_eq!(BitmapLayout::for_bit_count(BCHUNK_BITS * BCHUNK_BITS + BCHUNK_BITS), None);

        let one_chunk = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        assert_eq!(one_chunk.chunk_count(), 1);
        assert_eq!(one_chunk.max_bits(), BCHUNK_BITS);
        assert_eq!(one_chunk.byte_size(), BITMAP_CHUNKS_OFFSET + BCHUNK_SIZE);
        assert_eq!(one_chunk.byte_size() % BCHUNK_SIZE, 0);

        let three_chunks = BitmapLayout::for_bit_count(BCHUNK_BITS * 3).unwrap();
        assert_eq!(three_chunks.chunk_count(), 3);
        assert_eq!(three_chunks.max_bits(), BCHUNK_BITS * 3);
        assert_eq!(three_chunks.byte_size(), 320);
    }

    #[test]
    fn bitmap_view_initializes_dynamic_storage_and_preserves_cross_chunk_operations() {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS * 3).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let mut bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        assert_eq!(bitmap.byte_size(), layout.byte_size());
        assert_eq!(bitmap.chunk_count(), 3);
        assert_eq!(bitmap.max_bits(), BCHUNK_BITS * 3);
        assert_eq!(bitmap.popcount_range(0, bitmap.max_bits()), Some(0));
        assert_eq!(bitmap.is_clear_range(BCHUNK_BITS - 2, 5), Some(true));
        assert!(bitmap.is_all_clear());

        assert_eq!(bitmap.set_range(BCHUNK_BITS - 2, 5), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.popcount_range(BCHUNK_BITS - 2, 5), Some(5));
        assert_eq!(bitmap.is_set_range(BCHUNK_BITS - 2, 5), Some(true));
        assert!(bitmap.chunkmap().is_set_run(0, 1));
        assert!(bitmap.chunkmap().is_set_run(1, 1));
        assert_eq!(bitmap.set_range(BCHUNK_BITS - 2, 5).unwrap().already_set(), 5);

        assert_eq!(bitmap.clear_range(BCHUNK_BITS - 2, 2), Some(true));
        assert!(bitmap.chunkmap().is_clear_run(0, 1));
        assert!(bitmap.chunkmap().is_set_run(1, 1));
        assert_eq!(bitmap.clear_range(BCHUNK_BITS, 3), Some(true));
        assert!(bitmap.chunkmap().is_clear_run(1, 1));
        assert!(bitmap.is_all_clear());

        unsafe { bitmap.unsafe_set_range_local(0, BCHUNK_BITS * 2).unwrap() };
        assert_eq!(bitmap.popcount_range(0, BCHUNK_BITS * 2), Some(BCHUNK_BITS * 2));
        assert!(bitmap.chunkmap().is_set_run(0, 2));
        assert_eq!(bitmap.clear_range(0, BCHUNK_BITS * 2), Some(true));
        assert!(bitmap.is_all_clear());
    }

    #[test]
    fn bitmap_highest_set_scan_skips_a_stale_high_chunk_and_preserves_the_map() {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS * 3).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        assert_eq!(bitmap.highest_set_relaxed(), None);
        assert_eq!(bitmap.set_range(7, 1), Some(RunTransition::all_clear(0)));
        let high = BCHUNK_BITS * 2 + BFIELD_BITS + 9;
        assert_eq!(bitmap.set_range(high, 1), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.highest_set_relaxed(), Some(high));

        // `_mi_bitmap_forall_setc_ranges` can leave this conservative-map
        // shape. Direct data clearing isolates `mi_bitmap_bsr`'s stale-high
        // scan without making this test another visitor route.
        assert!(bitmap
            .chunk(2)
            .clear_run(BFIELD_BITS + 9, 1)
            .unwrap()
            .all_transitioned());
        assert!(bitmap.chunkmap().is_set_run(2, 1));
        assert_eq!(bitmap.highest_set_relaxed(), Some(7));
        assert!(bitmap.chunkmap().is_set_run(2, 1));
    }

    #[test]
    fn bitmap_highest_set_caps_an_out_of_layout_chunkmap_bit() {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS * 3).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        assert_eq!(bitmap.set_range(7, 1), Some(RunTransition::all_clear(0)));
        // Pinned C asserts that this map bit names a dynamic trailing chunk.
        // The checked view must cap the reverse scan to its three initialized
        // chunks, still find the lower live bit, and leave the conservative
        // map untouched.
        word_or_relaxed(bitmap.chunkmap().field(0), 1usize << (BFIELD_BITS - 1));
        let before = word_load_relaxed(bitmap.chunkmap().field(0));
        assert_eq!(bitmap.highest_set_relaxed(), Some(7));
        assert_eq!(word_load_relaxed(bitmap.chunkmap().field(0)), before);
    }

    #[test]
    fn bitmap_popcount_relaxed_scans_conservative_map_fields_without_repair() {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS * SET_VISITOR_CHUNK_COUNT).unwrap();
        let mut storage = BitmapSetVisitorTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        let low = 1;
        let stale = (BFIELD_BITS - 1) * BCHUNK_BITS + BFIELD_BITS + 3;
        let next_chunkmap_field = BFIELD_BITS * BCHUNK_BITS + BFIELD_BITS * 2 + 5;
        for index in [low, stale, next_chunkmap_field] {
            assert!(bitmap.set_range(index, 1).unwrap().all_transitioned());
        }
        assert_eq!(bitmap.popcount_relaxed(), 3);

        let chunkmap_field_0_before = word_load_relaxed(bitmap.chunkmap().field(0));
        let chunkmap_field_1_before = word_load_relaxed(bitmap.chunkmap().field(1));
        assert_eq!(
            chunkmap_field_0_before,
            1 | (1usize << (BFIELD_BITS - 1)),
        );
        assert_eq!(chunkmap_field_1_before, 1);

        // A source visitor can leave an in-layout conservative-map bit after
        // clearing data. `mi_bitmap_popcount` still selects that empty chunk,
        // counts zero from it, and must not repair its map bit.
        assert!(bitmap
            .chunk(BFIELD_BITS - 1)
            .clear_run(BFIELD_BITS + 3, 1)
            .unwrap()
            .all_transitioned());
        assert_eq!(bitmap.popcount_relaxed(), 2);
        assert_eq!(
            word_load_relaxed(bitmap.chunkmap().field(0)),
            chunkmap_field_0_before,
        );
        assert_eq!(
            word_load_relaxed(bitmap.chunkmap().field(1)),
            chunkmap_field_1_before,
        );

        // Pinned C asserts this final map bit is in the dynamic tail. The
        // checked view retains it but refuses to turn it into an out-of-bounds
        // data-chunk access.
        assert!(bitmap
            .chunkmap()
            .set_run(BFIELD_BITS + BFIELD_BITS - 1, 1)
            .unwrap()
            .all_transitioned());
        assert_eq!(bitmap.popcount_relaxed(), 2);
        assert_eq!(
            word_load_relaxed(bitmap.chunkmap().field(1)),
            chunkmap_field_1_before | (1usize << (BFIELD_BITS - 1)),
        );
    }

    #[test]
    fn clear_set_range_visitor_uses_source_field_snapshots_and_retains_the_conservative_map() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        assert_eq!(bitmap.set_range(1, 2), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(5, 2), Some(RunTransition::all_clear(0)));
        assert_eq!(
            bitmap.set_range(BFIELD_BITS - 2, 4),
            Some(RunTransition::all_clear(0)),
        );
        let mut visits = std::vec::Vec::new();

        assert!(bitmap.visit_set_ranges_clear(|slice_index, slice_count| {
            visits.push((slice_index, slice_count));
            true
        }));

        assert_eq!(
            visits,
            std::vec![(1, 2), (5, 2), (BFIELD_BITS - 2, 2), (BFIELD_BITS, 2)],
        );
        assert_eq!(bitmap.is_clear_range(0, BCHUNK_BITS), Some(true));
        // `_mi_bitmap_forall_setc_ranges` consumes data fields but does not
        // repair the conservative chunk map after an all-clear visit.
        assert!(bitmap.chunkmap().is_set_run(0, 1));
    }

    #[test]
    fn clear_set_range_visitor_restores_only_unvisited_snapshot_bits_after_a_callback_stop() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        assert_eq!(bitmap.set_range(1, 2), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(5, 2), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(BFIELD_BITS, 2), Some(RunTransition::all_clear(0)));
        let mut visits = std::vec::Vec::new();

        assert!(!bitmap.visit_set_ranges_clear(|slice_index, slice_count| {
            visits.push((slice_index, slice_count));
            false
        }));

        assert_eq!(visits, std::vec![(1, 2)]);
        // The callback's already-visited range stays clear. The rest of its
        // source field is restored by the visitor, and later fields never
        // leave their pre-visitor state.
        assert_eq!(bitmap.is_clear_range(1, 2), Some(true));
        assert_eq!(bitmap.is_set_range(5, 2), Some(true));
        assert_eq!(bitmap.is_set_range(BFIELD_BITS, 2), Some(true));
        assert!(bitmap.chunkmap().is_set_run(0, 1));
    }

    #[test]
    fn aligned_clear_range_visitor_restores_partial_windows_and_top_padding() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        assert_eq!(bitmap.set_range(0, 3), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(3, 2), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(6, 3), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(BFIELD_BITS - 1, 1), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(BFIELD_BITS, 3), Some(RunTransition::all_clear(0)));
        let mut visits = std::vec::Vec::new();

        assert!(bitmap.visit_set_ranges_clear_aligned(3, |slice_index, slice_count| {
            visits.push((slice_index, slice_count));
            true
        }));

        assert_eq!(visits, std::vec![(0, 3), (6, 3), (BFIELD_BITS, 3)]);
        assert_eq!(bitmap.is_clear_range(0, 3), Some(true));
        assert_eq!(bitmap.is_set_range(3, 2), Some(true));
        assert_eq!(bitmap.is_clear_range(6, 3), Some(true));
        assert_eq!(bitmap.is_set_range(BFIELD_BITS - 1, 1), Some(true));
        assert_eq!(bitmap.is_clear_range(BFIELD_BITS, 3), Some(true));
        assert!(bitmap.chunkmap().is_set_run(0, 1));
    }

    #[test]
    fn aligned_clear_range_visitor_restores_skipped_and_future_bits_after_a_callback_stop() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        assert_eq!(bitmap.set_range(0, 2), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(3, 3), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(6, 3), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(BFIELD_BITS - 1, 1), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(BFIELD_BITS, 3), Some(RunTransition::all_clear(0)));
        let mut visits = std::vec::Vec::new();

        assert!(!bitmap.visit_set_ranges_clear_aligned(3, |slice_index, slice_count| {
            visits.push((slice_index, slice_count));
            false
        }));

        assert_eq!(visits, std::vec![(3, 3)]);
        assert_eq!(bitmap.is_set_range(0, 2), Some(true));
        assert_eq!(bitmap.is_clear_range(3, 3), Some(true));
        assert_eq!(bitmap.is_set_range(6, 3), Some(true));
        assert_eq!(bitmap.is_set_range(BFIELD_BITS - 1, 1), Some(true));
        assert_eq!(bitmap.is_set_range(BFIELD_BITS, 3), Some(true));
        assert!(bitmap.chunkmap().is_set_run(0, 1));
    }

    #[test]
    fn aligned_clear_range_visitor_delegates_or_caps_at_source_bounds() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut delegated_storage = BitmapTestStorage::uninit();
        let delegated = unsafe {
            BitmapView::initialize(
                delegated_storage.bytes.as_mut_ptr().cast(),
                delegated_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        assert_eq!(delegated.set_range(1, 2), Some(RunTransition::all_clear(0)));
        let mut delegated_visits = std::vec::Vec::new();
        assert!(delegated.visit_set_ranges_clear_aligned(0, |slice_index, slice_count| {
            delegated_visits.push((slice_index, slice_count));
            true
        }));
        assert_eq!(delegated_visits, std::vec![(1, 2)]);

        let mut one_storage = BitmapTestStorage::uninit();
        let one = unsafe {
            BitmapView::initialize(
                one_storage.bytes.as_mut_ptr().cast(),
                one_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        assert_eq!(one.set_range(1, 2), Some(RunTransition::all_clear(0)));
        let mut one_visits = std::vec::Vec::new();
        assert!(one.visit_set_ranges_clear_aligned(1, |slice_index, slice_count| {
            one_visits.push((slice_index, slice_count));
            true
        }));
        assert_eq!(one_visits, std::vec![(1, 2)]);

        let mut capped_storage = BitmapTestStorage::uninit();
        let capped = unsafe {
            BitmapView::initialize(
                capped_storage.bytes.as_mut_ptr().cast(),
                capped_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        assert_eq!(
            capped.set_range(0, BFIELD_BITS),
            Some(RunTransition::all_clear(0)),
        );
        let mut capped_visits = std::vec::Vec::new();
        assert!(capped.visit_set_ranges_clear_aligned(
            BFIELD_BITS + 1,
            |slice_index, slice_count| {
                capped_visits.push((slice_index, slice_count));
                true
            }
        ));
        assert_eq!(capped_visits, std::vec![(0, BFIELD_BITS)]);
    }

    #[test]
    fn set_bit_visitor_crosses_chunkmap_fields_without_mutating_snapshots() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS * SET_VISITOR_CHUNK_COUNT).unwrap();
        let mut complete_storage = BitmapSetVisitorTestStorage::uninit();
        let complete = unsafe {
            BitmapView::initialize(
                complete_storage.bytes.as_mut_ptr().cast(),
                complete_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        for index in [1, BFIELD_BITS + 1, BFIELD_BITS * BCHUNK_BITS + 2] {
            assert_eq!(
                complete.set_range(index, 1),
                Some(RunTransition::all_clear(0))
            );
        }
        let complete_before = (
            word_load_relaxed(complete.chunk(0).field(0)),
            word_load_relaxed(complete.chunk(0).field(1)),
            word_load_relaxed(complete.chunk(BFIELD_BITS).field(0)),
            word_load_relaxed(complete.chunkmap().field(0)),
            word_load_relaxed(complete.chunkmap().field(1)),
        );
        let mut complete_visits = std::vec::Vec::new();

        assert!(complete.visit_set_bits(|slice_index, slice_count| {
            complete_visits.push((slice_index, slice_count));
            true
        }));
        assert_eq!(
            complete_visits,
            std::vec![(1, 1), (BFIELD_BITS + 1, 1), (BFIELD_BITS * BCHUNK_BITS + 2, 1)]
        );
        assert_eq!(
            (
                word_load_relaxed(complete.chunk(0).field(0)),
                word_load_relaxed(complete.chunk(0).field(1)),
                word_load_relaxed(complete.chunk(BFIELD_BITS).field(0)),
                word_load_relaxed(complete.chunkmap().field(0)),
                word_load_relaxed(complete.chunkmap().field(1)),
            ),
            complete_before,
            "the source read-only visitor must not clear data or repair its conservative map"
        );

        let mut stopped_storage = BitmapSetVisitorTestStorage::uninit();
        let stopped = unsafe {
            BitmapView::initialize(
                stopped_storage.bytes.as_mut_ptr().cast(),
                stopped_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        for index in [1, BFIELD_BITS + 1, BFIELD_BITS * BCHUNK_BITS + 2] {
            assert_eq!(
                stopped.set_range(index, 1),
                Some(RunTransition::all_clear(0))
            );
        }
        let stopped_before = (
            word_load_relaxed(stopped.chunk(0).field(0)),
            word_load_relaxed(stopped.chunk(0).field(1)),
            word_load_relaxed(stopped.chunk(BFIELD_BITS).field(0)),
            word_load_relaxed(stopped.chunkmap().field(0)),
            word_load_relaxed(stopped.chunkmap().field(1)),
        );
        let mut stopped_visits = std::vec::Vec::new();

        assert!(!stopped.visit_set_bits(|slice_index, slice_count| {
            stopped_visits.push((slice_index, slice_count));
            stopped_visits.len() != 2
        }));
        assert_eq!(stopped_visits, std::vec![(1, 1), (BFIELD_BITS + 1, 1)]);
        assert_eq!(
            (
                word_load_relaxed(stopped.chunk(0).field(0)),
                word_load_relaxed(stopped.chunk(0).field(1)),
                word_load_relaxed(stopped.chunk(BFIELD_BITS).field(0)),
                word_load_relaxed(stopped.chunkmap().field(0)),
                word_load_relaxed(stopped.chunkmap().field(1)),
            ),
            stopped_before,
            "a callback stop must leave data, later chunks, and the conservative map untouched"
        );

        let mut stale_storage = BitmapSetVisitorTestStorage::uninit();
        let stale = unsafe {
            BitmapView::initialize(
                stale_storage.bytes.as_mut_ptr().cast(),
                stale_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        // The source relies on a valid layout and would form `chunks[65]` for
        // this map bit. The checked Rust view must instead preserve the stale
        // bit without naming storage outside its 65-chunk caller image.
        word_or_relaxed(stale.chunkmap().field(1), 1 << 1);
        let mut stale_visits = std::vec::Vec::new();
        assert!(stale.visit_set_bits(|slice_index, slice_count| {
            stale_visits.push((slice_index, slice_count));
            true
        }));
        assert!(stale_visits.is_empty());
        assert_eq!(word_load_relaxed(stale.chunkmap().field(1)), 1 << 1);
    }

    #[test]
    fn preserved_publication_keeps_a_nonzero_prefix_and_ordinary_lowest_claim_repairs_chunkmap() {
        let old_layout = BitmapLayout::for_bit_count(BCHUNK_BITS * 2).unwrap();
        let expanded_layout = BitmapLayout::for_bit_count(BCHUNK_BITS * 3).unwrap();
        let mut old_storage = BitmapTestStorage::uninit();
        let mut old = unsafe {
            BitmapView::initialize(
                old_storage.bytes.as_mut_ptr().cast(),
                old_layout.byte_size(),
                old_layout,
                false,
            )
            .unwrap()
        };
        // SAFETY: this test owns the unshared initial image and records two
        // available old-prefix bits before copying it into the larger image.
        unsafe { old.unsafe_set_range_local(7, 1).unwrap() };
        unsafe { old.unsafe_set_range_local(BCHUNK_BITS + 3, 1).unwrap() };
        drop(old);

        let mut expanded_storage = BitmapTestStorage::uninit();
        // SAFETY: `expanded_storage` is aligned private storage for exactly
        // the larger image; zeroing its appended range precedes the source
        // copied-prefix publication branch.
        unsafe {
            core::ptr::write_bytes(
                expanded_storage.bytes.as_mut_ptr().cast::<u8>(),
                0,
                expanded_layout.byte_size(),
            );
            core::ptr::copy_nonoverlapping(
                old_storage.bytes.as_ptr().cast::<u8>(),
                expanded_storage.bytes.as_mut_ptr().cast::<u8>(),
                old_layout.byte_size(),
            );
        }
        let mut expanded = unsafe {
            BitmapView::publish_preserved(
                expanded_storage.bytes.as_mut_ptr().cast(),
                expanded_layout.byte_size(),
                expanded_layout,
            )
            .unwrap()
        };
        assert_eq!(expanded.is_set_range(7, 1), Some(true));
        assert_eq!(expanded.is_set_range(BCHUNK_BITS + 3, 1), Some(true));
        assert_eq!(
            expanded.is_clear_range(old_layout.max_bits(), BCHUNK_BITS),
            Some(true),
            "preserved publication leaves the appended chunk clear until its source free-bit setup"
        );
        // SAFETY: this test still has exclusive access while it models the
        // registry's appended-only free transition.
        unsafe {
            expanded
                .unsafe_set_range_local(old_layout.max_bits(), BCHUNK_BITS)
                .unwrap()
        };
        assert_eq!(expanded.try_find_and_claim_lowest(), Some(7));

        let one_chunk = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut repair_storage = BitmapTestStorage::uninit();
        let mut repair = unsafe {
            BitmapView::initialize(
                repair_storage.bytes.as_mut_ptr().cast(),
                one_chunk.byte_size(),
                one_chunk,
                false,
            )
            .unwrap()
        };
        // SAFETY: this local setup creates one conservative map candidate.
        unsafe { repair.unsafe_set_range_local(0, BCHUNK_BITS).unwrap() };
        assert!(repair.chunkmap().is_set_run(0, 1));
        // Deliberately leave the map conservative/stale while draining only
        // the data chunk. This is the ordinary find path's repair condition.
        assert!(repair
            .chunk(0)
            .clear_run(0, BCHUNK_BITS)
            .expect("the complete checked source chunk is clearable")
            .all_transitioned());
        assert!(repair.chunkmap().is_set_run(0, 1));
        assert_eq!(repair.try_find_and_claim_lowest(), None);
        assert!(repair.chunkmap().is_clear_run(0, 1));

        // SAFETY: still exclusive test storage; a new regular bit must be
        // selected by the ordinary low-to-high source traversal.
        unsafe { repair.unsafe_set_range_local(17, 1).unwrap() };
        assert_eq!(repair.try_find_and_claim_lowest(), Some(17));
    }

    #[test]
    fn bitmap_view_checked_ranges_reject_zero_overflow_and_out_of_bounds_requests() {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let mut bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        assert_eq!(bitmap.set_range(0, 0), None);
        assert_eq!(bitmap.clear_range(0, 0), None);
        assert_eq!(bitmap.popcount_range(0, 0), None);
        assert_eq!(bitmap.is_set_range(0, 0), None);
        assert_eq!(bitmap.is_clear_range(BCHUNK_BITS, 1), None);
        assert_eq!(bitmap.set_range(BCHUNK_BITS - 1, 2), None);
        assert_eq!(bitmap.clear_range(usize::MAX, 1), None);
        assert!(unsafe { bitmap.unsafe_set_range_local(BCHUNK_BITS, 1) }.is_none());
    }

    #[test]
    fn abandoned_claim_restores_a_failed_page_ownership_candidate_before_continuing() {
        use core::cell::Cell;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        assert_eq!(bitmap.set_range(17, 1), Some(RunTransition::all_clear(0)));

        let calls = Cell::new(0);
        let first_search = bitmap.try_find_and_claim_abandoned(5, |_| {
            let call = calls.get();
            calls.set(call + 1);
            assert_eq!(call, 0);
            AbandonedBitmapClaim::KeepSet
        });

        // `mi_bitmap_find` snapshots each source candidate once. A failed
        // callback restores the bit for the *next* search; it must not spin
        // on the same candidate in one traversal.
        assert_eq!(first_search, None);
        assert_eq!(calls.get(), 1);
        assert_eq!(bitmap.is_set_range(17, 1), Some(true));
        let second_search = bitmap.try_find_and_claim_abandoned(5, |_| {
            calls.set(calls.get() + 1);
            AbandonedBitmapClaim::Claimed
        });
        assert_eq!(second_search, Some(17));
        assert_eq!(calls.get(), 2);
        assert_eq!(bitmap.is_clear_range(17, 1), Some(true));
    }

    /// Emits the address-free Rust half of the selected
    /// `_mi_bitmap_forall_setc_ranges` differential. The complete stage has
    /// two ordinary runs and one run split at the source 64-bit field
    /// boundary; the reject stage proves that the current range stays clear
    /// while only the remaining snapshot bits of that field are restored.
    #[test]
    fn emit_m2_bitmap_clear_range_c_rust_trace() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut complete_storage = BitmapTestStorage::uninit();
        let complete = unsafe {
            BitmapView::initialize(
                complete_storage.bytes.as_mut_ptr().cast(),
                complete_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let complete_set_transitioned = matches!(
            (
                complete.set_range(1, 2),
                complete.set_range(5, 2),
                complete.set_range(BFIELD_BITS - 2, 4),
            ),
            (
                Some(first),
                Some(second),
                Some(third),
            ) if first.all_transitioned()
                && second.all_transitioned()
                && third.all_transitioned()
        );
        let mut complete_ranges = std::vec::Vec::new();
        let complete_returned_completed = complete.visit_set_ranges_clear(|slice_index, slice_count| {
            complete_ranges.push((slice_index, slice_count));
            true
        });
        let complete_range_0 = complete_ranges.first().copied().unwrap_or((usize::MAX, usize::MAX));
        let complete_range_1 = complete_ranges.get(1).copied().unwrap_or((usize::MAX, usize::MAX));
        let complete_range_2 = complete_ranges.get(2).copied().unwrap_or((usize::MAX, usize::MAX));
        let complete_range_3 = complete_ranges.get(3).copied().unwrap_or((usize::MAX, usize::MAX));
        let complete_data_cleared = complete.is_clear_range(0, BCHUNK_BITS) == Some(true);
        let complete_chunkmap_retained = complete.chunkmap().is_set_run(0, 1);

        let mut reject_storage = BitmapTestStorage::uninit();
        let reject = unsafe {
            BitmapView::initialize(
                reject_storage.bytes.as_mut_ptr().cast(),
                reject_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let reject_set_transitioned = matches!(
            (
                reject.set_range(1, 2),
                reject.set_range(5, 2),
                reject.set_range(BFIELD_BITS, 2),
            ),
            (
                Some(first),
                Some(second),
                Some(third),
            ) if first.all_transitioned()
                && second.all_transitioned()
                && third.all_transitioned()
        );
        let mut reject_ranges = std::vec::Vec::new();
        let reject_returned_completed = reject.visit_set_ranges_clear(|slice_index, slice_count| {
            reject_ranges.push((slice_index, slice_count));
            false
        });
        let reject_range = reject_ranges.first().copied().unwrap_or((usize::MAX, usize::MAX));
        let reject_visited_range_cleared = reject.is_clear_range(1, 2) == Some(true);
        let reject_unvisited_same_field_restored = reject.is_set_range(5, 2) == Some(true);
        let reject_later_field_untouched = reject.is_set_range(BFIELD_BITS, 2) == Some(true);
        let reject_chunkmap_retained = reject.chunkmap().is_set_run(0, 1);

        assert!(complete_set_transitioned);
        assert!(complete_returned_completed);
        assert_eq!(
            complete_ranges,
            std::vec![(1, 2), (5, 2), (BFIELD_BITS - 2, 2), (BFIELD_BITS, 2)],
        );
        assert!(complete_data_cleared);
        assert!(complete_chunkmap_retained);
        assert!(reject_set_transitioned);
        assert!(!reject_returned_completed);
        assert_eq!(reject_ranges, std::vec![(1, 2)]);
        assert!(reject_visited_range_cleared);
        assert!(reject_unvisited_same_field_restored);
        assert!(reject_later_field_untouched);
        assert!(reject_chunkmap_retained);

        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        std::println!("CRABC_MI_M2_BITMAP_CLEAR_RANGE_TRACE_BEGIN");
        emit!("m2.bitmap_range.control.bfield_bits", BFIELD_BITS);
        emit!("m2.bitmap_range.control.bchunk_bits", BCHUNK_BITS);
        emit!("m2.bitmap_range.layout.byte_size", layout.byte_size());
        emit!("m2.bitmap_range.complete.chunk_count", complete.chunk_count());
        emit!("m2.bitmap_range.complete.set_transitioned", complete_set_transitioned);
        emit!("m2.bitmap_range.complete.returned_completed", complete_returned_completed);
        emit!("m2.bitmap_range.complete.callback_count", complete_ranges.len());
        emit!("m2.bitmap_range.complete.range_0_index", complete_range_0.0);
        emit!("m2.bitmap_range.complete.range_0_count", complete_range_0.1);
        emit!("m2.bitmap_range.complete.range_1_index", complete_range_1.0);
        emit!("m2.bitmap_range.complete.range_1_count", complete_range_1.1);
        emit!("m2.bitmap_range.complete.range_2_index", complete_range_2.0);
        emit!("m2.bitmap_range.complete.range_2_count", complete_range_2.1);
        emit!("m2.bitmap_range.complete.range_3_index", complete_range_3.0);
        emit!("m2.bitmap_range.complete.range_3_count", complete_range_3.1);
        emit!("m2.bitmap_range.complete.data_cleared", complete_data_cleared);
        emit!("m2.bitmap_range.complete.chunkmap_retained", complete_chunkmap_retained);
        emit!("m2.bitmap_range.reject.set_transitioned", reject_set_transitioned);
        emit!("m2.bitmap_range.reject.returned_completed", reject_returned_completed);
        emit!("m2.bitmap_range.reject.callback_count", reject_ranges.len());
        emit!("m2.bitmap_range.reject.range_index", reject_range.0);
        emit!("m2.bitmap_range.reject.range_count", reject_range.1);
        emit!("m2.bitmap_range.reject.visited_range_cleared", reject_visited_range_cleared);
        emit!(
            "m2.bitmap_range.reject.unvisited_same_field_restored",
            reject_unvisited_same_field_restored
        );
        emit!("m2.bitmap_range.reject.later_field_untouched", reject_later_field_untouched);
        emit!("m2.bitmap_range.reject.chunkmap_retained", reject_chunkmap_retained);
        std::println!("CRABC_MI_M2_BITMAP_CLEAR_RANGE_TRACE_END");
    }

    /// Emits the address-free Rust half of the selected
    /// `_mi_bitmap_forall_setc_rangesn` differential. The `rngslices == 3`
    /// paths prove aligned completed windows, partial-window/suffix retention,
    /// and refusal restoration after an earlier skipped window. Separate
    /// images prove the source's `<= 1` generic delegation and its cap above
    /// one source field.
    #[test]
    fn emit_m2_bitmap_rangesn_c_rust_trace() {
        extern crate std;

        const ALIGNED_RNGSLICES: usize = 3;
        const CAPPED_REQUEST: usize = BFIELD_BITS + 1;
        const COMPLETE_FIELD_0_AFTER: usize = 0xb000_0000_0000_00c0;
        const REJECT_FIELD_0_AFTER: usize = 0xb000_0000_0000_0ec5;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();

        let mut complete_storage = BitmapTestStorage::uninit();
        let complete = unsafe {
            BitmapView::initialize(
                complete_storage.bytes.as_mut_ptr().cast(),
                complete_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let complete_set_transitioned = matches!(
            (
                complete.set_range(0, 8),
                complete.set_range(9, 3),
                complete.set_range(60, 2),
                complete.set_range(63, 1),
            ),
            (Some(first), Some(second), Some(third), Some(fourth))
                if first.all_transitioned()
                    && second.all_transitioned()
                    && third.all_transitioned()
                    && fourth.all_transitioned()
        );
        let mut complete_ranges = std::vec::Vec::new();
        let complete_returned_completed = complete.visit_set_ranges_clear_aligned(
            ALIGNED_RNGSLICES,
            |slice_index, slice_count| {
                complete_ranges.push((slice_index, slice_count));
                true
            },
        );
        let complete_field_0_after = word_load_relaxed(complete.chunk(0).field(0));
        let complete_chunkmap_field_0_after = word_load_relaxed(complete.chunkmap().field(0));

        let mut reject_storage = BitmapTestStorage::uninit();
        let reject = unsafe {
            BitmapView::initialize(
                reject_storage.bytes.as_mut_ptr().cast(),
                reject_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let reject_set_transitioned = matches!(
            (
                reject.set_range(0, 1),
                reject.set_range(2, 4),
                reject.set_range(6, 2),
                reject.set_range(9, 3),
                reject.set_range(60, 2),
                reject.set_range(63, 1),
                reject.set_range(BFIELD_BITS, 3),
            ),
            (
                Some(first),
                Some(second),
                Some(third),
                Some(fourth),
                Some(fifth),
                Some(sixth),
                Some(seventh),
            ) if first.all_transitioned()
                && second.all_transitioned()
                && third.all_transitioned()
                && fourth.all_transitioned()
                && fifth.all_transitioned()
                && sixth.all_transitioned()
                && seventh.all_transitioned()
        );
        let mut reject_ranges = std::vec::Vec::new();
        let reject_returned_completed = reject.visit_set_ranges_clear_aligned(
            ALIGNED_RNGSLICES,
            |slice_index, slice_count| {
                reject_ranges.push((slice_index, slice_count));
                false
            },
        );
        let reject_field_0_after = word_load_relaxed(reject.chunk(0).field(0));
        let reject_field_1_after = word_load_relaxed(reject.chunk(0).field(1));
        let reject_chunkmap_field_0_after = word_load_relaxed(reject.chunkmap().field(0));

        let mut delegation_zero_storage = BitmapTestStorage::uninit();
        let delegation_zero = unsafe {
            BitmapView::initialize(
                delegation_zero_storage.bytes.as_mut_ptr().cast(),
                delegation_zero_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let delegation_zero_set_transitioned = matches!(
            (
                delegation_zero.set_range(0, 8),
                delegation_zero.set_range(9, 3),
                delegation_zero.set_range(60, 2),
                delegation_zero.set_range(63, 1),
            ),
            (Some(first), Some(second), Some(third), Some(fourth))
                if first.all_transitioned()
                    && second.all_transitioned()
                    && third.all_transitioned()
                    && fourth.all_transitioned()
        );
        let mut delegation_zero_ranges = std::vec::Vec::new();
        let delegation_zero_returned_completed = delegation_zero.visit_set_ranges_clear_aligned(
            0,
            |slice_index, slice_count| {
                delegation_zero_ranges.push((slice_index, slice_count));
                true
            },
        );
        let delegation_zero_field_0_after =
            word_load_relaxed(delegation_zero.chunk(0).field(0));
        let delegation_zero_chunkmap_field_0_after =
            word_load_relaxed(delegation_zero.chunkmap().field(0));

        let mut delegation_one_storage = BitmapTestStorage::uninit();
        let delegation_one = unsafe {
            BitmapView::initialize(
                delegation_one_storage.bytes.as_mut_ptr().cast(),
                delegation_one_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let delegation_one_set_transitioned = matches!(
            (
                delegation_one.set_range(0, 8),
                delegation_one.set_range(9, 3),
                delegation_one.set_range(60, 2),
                delegation_one.set_range(63, 1),
            ),
            (Some(first), Some(second), Some(third), Some(fourth))
                if first.all_transitioned()
                    && second.all_transitioned()
                    && third.all_transitioned()
                    && fourth.all_transitioned()
        );
        let mut delegation_one_ranges = std::vec::Vec::new();
        let delegation_one_returned_completed = delegation_one.visit_set_ranges_clear_aligned(
            1,
            |slice_index, slice_count| {
                delegation_one_ranges.push((slice_index, slice_count));
                true
            },
        );
        let delegation_one_field_0_after = word_load_relaxed(delegation_one.chunk(0).field(0));
        let delegation_one_chunkmap_field_0_after =
            word_load_relaxed(delegation_one.chunkmap().field(0));

        let mut capped_storage = BitmapTestStorage::uninit();
        let capped = unsafe {
            BitmapView::initialize(
                capped_storage.bytes.as_mut_ptr().cast(),
                capped_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let capped_set_transitioned = matches!(
            capped.set_range(0, BFIELD_BITS),
            Some(transition) if transition.all_transitioned()
        );
        let mut capped_ranges = std::vec::Vec::new();
        let capped_returned_completed = capped.visit_set_ranges_clear_aligned(
            CAPPED_REQUEST,
            |slice_index, slice_count| {
                capped_ranges.push((slice_index, slice_count));
                true
            },
        );
        let capped_field_0_after = word_load_relaxed(capped.chunk(0).field(0));
        let capped_chunkmap_field_0_after = word_load_relaxed(capped.chunkmap().field(0));

        let generic_ranges = std::vec![(0, 8), (9, 3), (60, 2), (63, 1)];
        assert!(complete_set_transitioned);
        assert!(complete_returned_completed);
        assert_eq!(complete_ranges, std::vec![(0, 3), (3, 3), (9, 3)]);
        assert_eq!(complete_field_0_after, COMPLETE_FIELD_0_AFTER);
        assert_eq!(complete_chunkmap_field_0_after, 1);
        assert!(reject_set_transitioned);
        assert!(!reject_returned_completed);
        assert_eq!(reject_ranges, std::vec![(3, 3)]);
        assert_eq!(reject_field_0_after, REJECT_FIELD_0_AFTER);
        assert_eq!(reject_field_1_after, 7);
        assert_eq!(reject_chunkmap_field_0_after, 1);
        assert!(delegation_zero_set_transitioned);
        assert!(delegation_zero_returned_completed);
        assert_eq!(delegation_zero_ranges, generic_ranges);
        assert_eq!(delegation_zero_field_0_after, 0);
        assert_eq!(delegation_zero_chunkmap_field_0_after, 1);
        assert!(delegation_one_set_transitioned);
        assert!(delegation_one_returned_completed);
        assert_eq!(delegation_one_ranges, generic_ranges);
        assert_eq!(delegation_one_field_0_after, 0);
        assert_eq!(delegation_one_chunkmap_field_0_after, 1);
        assert!(capped_set_transitioned);
        assert!(capped_returned_completed);
        assert_eq!(capped_ranges, std::vec![(0, BFIELD_BITS)]);
        assert_eq!(capped_field_0_after, 0);
        assert_eq!(capped_chunkmap_field_0_after, 1);

        macro_rules! emit {
            ($name:expr, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        macro_rules! emit_ranges {
            ($prefix:literal, $ranges:expr, $count:expr) => {
                emit!(concat!($prefix, ".callback_count"), $ranges.len());
                emit!(concat!($prefix, ".range_0_index"), $ranges[0].0);
                emit!(concat!($prefix, ".range_0_count"), $ranges[0].1);
                emit!(concat!($prefix, ".range_1_index"), $ranges[1].0);
                emit!(concat!($prefix, ".range_1_count"), $ranges[1].1);
                if $count > 2 {
                    emit!(concat!($prefix, ".range_2_index"), $ranges[2].0);
                    emit!(concat!($prefix, ".range_2_count"), $ranges[2].1);
                }
                if $count > 3 {
                    emit!(concat!($prefix, ".range_3_index"), $ranges[3].0);
                    emit!(concat!($prefix, ".range_3_count"), $ranges[3].1);
                }
            };
        }
        std::println!("CRABC_MI_M2_BITMAP_RANGESN_TRACE_BEGIN");
        emit!("m2.bitmap_rangesn.control.bfield_bits", BFIELD_BITS);
        emit!("m2.bitmap_rangesn.control.bchunk_bits", BCHUNK_BITS);
        emit!(
            "m2.bitmap_rangesn.control.aligned_rngslices",
            ALIGNED_RNGSLICES
        );
        emit!("m2.bitmap_rangesn.control.capped_request", CAPPED_REQUEST);
        emit!("m2.bitmap_rangesn.layout.byte_size", layout.byte_size());
        emit!(
            "m2.bitmap_rangesn.r3_complete.returned_completed",
            complete_returned_completed
        );
        emit_ranges!("m2.bitmap_rangesn.r3_complete", complete_ranges, 3);
        emit!(
            "m2.bitmap_rangesn.r3_complete.field_0_after",
            complete_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.r3_complete.chunkmap_field_0_after",
            complete_chunkmap_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.r3_reject.returned_completed",
            reject_returned_completed
        );
        emit!(
            "m2.bitmap_rangesn.r3_reject.callback_count",
            reject_ranges.len()
        );
        emit!(
            "m2.bitmap_rangesn.r3_reject.range_0_index",
            reject_ranges[0].0
        );
        emit!(
            "m2.bitmap_rangesn.r3_reject.range_0_count",
            reject_ranges[0].1
        );
        emit!(
            "m2.bitmap_rangesn.r3_reject.field_0_after",
            reject_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.r3_reject.field_1_after",
            reject_field_1_after
        );
        emit!(
            "m2.bitmap_rangesn.r3_reject.chunkmap_field_0_after",
            reject_chunkmap_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.delegation_zero.returned_completed",
            delegation_zero_returned_completed
        );
        emit_ranges!(
            "m2.bitmap_rangesn.delegation_zero",
            delegation_zero_ranges,
            4
        );
        emit!(
            "m2.bitmap_rangesn.delegation_zero.field_0_after",
            delegation_zero_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.delegation_zero.chunkmap_field_0_after",
            delegation_zero_chunkmap_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.delegation_one.returned_completed",
            delegation_one_returned_completed
        );
        emit_ranges!(
            "m2.bitmap_rangesn.delegation_one",
            delegation_one_ranges,
            4
        );
        emit!(
            "m2.bitmap_rangesn.delegation_one.field_0_after",
            delegation_one_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.delegation_one.chunkmap_field_0_after",
            delegation_one_chunkmap_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.cap_over.returned_completed",
            capped_returned_completed
        );
        emit!(
            "m2.bitmap_rangesn.cap_over.callback_count",
            capped_ranges.len()
        );
        emit!(
            "m2.bitmap_rangesn.cap_over.range_0_index",
            capped_ranges[0].0
        );
        emit!(
            "m2.bitmap_rangesn.cap_over.range_0_count",
            capped_ranges[0].1
        );
        emit!(
            "m2.bitmap_rangesn.cap_over.field_0_after",
            capped_field_0_after
        );
        emit!(
            "m2.bitmap_rangesn.cap_over.chunkmap_field_0_after",
            capped_chunkmap_field_0_after
        );
        std::println!("CRABC_MI_M2_BITMAP_RANGESN_TRACE_END");
    }

    /// Emits the address-free Rust half of the selected
    /// `_mi_bitmap_forall_set` differential. Fresh 65-chunk images cross the
    /// first source chunk-map field boundary. One completes the low-to-high
    /// scalar walk, while the other stops at its second callback; neither walk
    /// may change a data field or repair the conservative chunk map.
    #[test]
    fn emit_m2_bitmap_forall_set_c_rust_trace() {
        extern crate std;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS * SET_VISITOR_CHUNK_COUNT).unwrap();
        let selected_indices = [1, BFIELD_BITS + 1, BFIELD_BITS * BCHUNK_BITS + 2];

        let mut complete_storage = BitmapSetVisitorTestStorage::uninit();
        let complete = unsafe {
            BitmapView::initialize(
                complete_storage.bytes.as_mut_ptr().cast(),
                complete_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let complete_seeded = selected_indices.into_iter().all(|index| {
            matches!(
                complete.set_range(index, 1),
                Some(transition) if transition.all_transitioned()
            )
        });
        let mut complete_visits = std::vec::Vec::new();
        let complete_returned_completed = complete.visit_set_bits(|slice_index, slice_count| {
            complete_visits.push((slice_index, slice_count));
            true
        });
        let complete_chunk_0_field_0_after = word_load_relaxed(complete.chunk(0).field(0));
        let complete_chunk_0_field_1_after = word_load_relaxed(complete.chunk(0).field(1));
        let complete_chunk_64_field_0_after =
            word_load_relaxed(complete.chunk(BFIELD_BITS).field(0));
        let complete_chunkmap_field_0_after = word_load_relaxed(complete.chunkmap().field(0));
        let complete_chunkmap_field_1_after = word_load_relaxed(complete.chunkmap().field(1));

        let mut reject_storage = BitmapSetVisitorTestStorage::uninit();
        let reject = unsafe {
            BitmapView::initialize(
                reject_storage.bytes.as_mut_ptr().cast(),
                reject_storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let reject_seeded = selected_indices.into_iter().all(|index| {
            matches!(
                reject.set_range(index, 1),
                Some(transition) if transition.all_transitioned()
            )
        });
        let mut reject_visits = std::vec::Vec::new();
        let reject_returned_completed = reject.visit_set_bits(|slice_index, slice_count| {
            reject_visits.push((slice_index, slice_count));
            reject_visits.len() != 2
        });
        let reject_chunk_0_field_0_after = word_load_relaxed(reject.chunk(0).field(0));
        let reject_chunk_0_field_1_after = word_load_relaxed(reject.chunk(0).field(1));
        let reject_chunk_64_field_0_after = word_load_relaxed(reject.chunk(BFIELD_BITS).field(0));
        let reject_chunkmap_field_0_after = word_load_relaxed(reject.chunkmap().field(0));
        let reject_chunkmap_field_1_after = word_load_relaxed(reject.chunkmap().field(1));

        assert_eq!(layout.byte_size(), SET_VISITOR_STORAGE_BYTES);
        assert!(complete_seeded);
        assert!(complete_returned_completed);
        assert_eq!(
            complete_visits,
            std::vec![(1, 1), (BFIELD_BITS + 1, 1), (BFIELD_BITS * BCHUNK_BITS + 2, 1)]
        );
        assert_eq!(complete_chunk_0_field_0_after, 1 << 1);
        assert_eq!(complete_chunk_0_field_1_after, 1 << 1);
        assert_eq!(complete_chunk_64_field_0_after, 1 << 2);
        assert_eq!(complete_chunkmap_field_0_after, 1);
        assert_eq!(complete_chunkmap_field_1_after, 1);
        assert!(reject_seeded);
        assert!(!reject_returned_completed);
        assert_eq!(reject_visits, std::vec![(1, 1), (BFIELD_BITS + 1, 1)]);
        assert_eq!(reject_chunk_0_field_0_after, 1 << 1);
        assert_eq!(reject_chunk_0_field_1_after, 1 << 1);
        assert_eq!(reject_chunk_64_field_0_after, 1 << 2);
        assert_eq!(reject_chunkmap_field_0_after, 1);
        assert_eq!(reject_chunkmap_field_1_after, 1);

        macro_rules! emit {
            ($name:expr, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        std::println!("CRABC_MI_M2_BITMAP_SET_TRACE_BEGIN");
        emit!("m2.bitmap_set.control.bfield_bits", BFIELD_BITS);
        emit!("m2.bitmap_set.control.bchunk_bits", BCHUNK_BITS);
        emit!("m2.bitmap_set.control.chunk_count", SET_VISITOR_CHUNK_COUNT);
        emit!("m2.bitmap_set.layout.byte_size", layout.byte_size());
        emit!("m2.bitmap_set.complete.seeded", complete_seeded);
        emit!(
            "m2.bitmap_set.complete.returned_completed",
            complete_returned_completed
        );
        emit!("m2.bitmap_set.complete.callback_count", complete_visits.len());
        emit!("m2.bitmap_set.complete.visit_0_index", complete_visits[0].0);
        emit!("m2.bitmap_set.complete.visit_0_count", complete_visits[0].1);
        emit!("m2.bitmap_set.complete.visit_1_index", complete_visits[1].0);
        emit!("m2.bitmap_set.complete.visit_1_count", complete_visits[1].1);
        emit!("m2.bitmap_set.complete.visit_2_index", complete_visits[2].0);
        emit!("m2.bitmap_set.complete.visit_2_count", complete_visits[2].1);
        emit!(
            "m2.bitmap_set.complete.chunk_0_field_0_after",
            complete_chunk_0_field_0_after
        );
        emit!(
            "m2.bitmap_set.complete.chunk_0_field_1_after",
            complete_chunk_0_field_1_after
        );
        emit!(
            "m2.bitmap_set.complete.chunk_64_field_0_after",
            complete_chunk_64_field_0_after
        );
        emit!(
            "m2.bitmap_set.complete.chunkmap_field_0_after",
            complete_chunkmap_field_0_after
        );
        emit!(
            "m2.bitmap_set.complete.chunkmap_field_1_after",
            complete_chunkmap_field_1_after
        );
        emit!("m2.bitmap_set.reject.seeded", reject_seeded);
        emit!(
            "m2.bitmap_set.reject.returned_completed",
            reject_returned_completed
        );
        emit!("m2.bitmap_set.reject.callback_count", reject_visits.len());
        emit!("m2.bitmap_set.reject.visit_0_index", reject_visits[0].0);
        emit!("m2.bitmap_set.reject.visit_0_count", reject_visits[0].1);
        emit!("m2.bitmap_set.reject.visit_1_index", reject_visits[1].0);
        emit!("m2.bitmap_set.reject.visit_1_count", reject_visits[1].1);
        emit!(
            "m2.bitmap_set.reject.chunk_0_field_0_after",
            reject_chunk_0_field_0_after
        );
        emit!(
            "m2.bitmap_set.reject.chunk_0_field_1_after",
            reject_chunk_0_field_1_after
        );
        emit!(
            "m2.bitmap_set.reject.chunk_64_field_0_after",
            reject_chunk_64_field_0_after
        );
        emit!(
            "m2.bitmap_set.reject.chunkmap_field_0_after",
            reject_chunkmap_field_0_after
        );
        emit!(
            "m2.bitmap_set.reject.chunkmap_field_1_after",
            reject_chunkmap_field_1_after
        );
        std::println!("CRABC_MI_M2_BITMAP_SET_TRACE_END");
    }

    /// Emits the address-free Rust half of the selected `mi_bitmap_try_find_and_claim`
    /// differential. The one-chunk image rejects its only source-snapshot
    /// candidate with `keep_set`, so the visitor must restore both the bit and
    /// conservative chunk-map state before the next traversal can claim that
    /// same bit. This proves neither general bitmap visitation nor the
    /// concurrent `clear_once_set` protocol.
    #[test]
    fn emit_m2_bitmap_abandoned_claim_c_rust_trace() {
        extern crate std;

        use core::cell::Cell;

        const THREAD_SEQUENCE: usize = 5;
        const SELECTED_INDEX: usize = 17;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };

        let initial_set_transitioned = matches!(
            bitmap.set_range(SELECTED_INDEX, 1),
            Some(transition) if transition.all_transitioned()
        );
        let callback_count = Cell::new(0usize);
        let reject_callback_index = Cell::new(usize::MAX);
        let rejected = bitmap.try_find_and_claim_abandoned(THREAD_SEQUENCE, |slice_index| {
            assert_eq!(callback_count.get(), 0);
            callback_count.set(1);
            reject_callback_index.set(slice_index);
            AbandonedBitmapClaim::KeepSet
        });
        let rejected_returned_claimed = rejected.is_some();
        let reject_callback_count = callback_count.get();
        let rejected_bit_restored = bitmap.is_set_range(SELECTED_INDEX, 1) == Some(true);
        let rejected_chunkmap_retained = bitmap.chunkmap().is_set_run(0, 1);

        let accept_callback_index = Cell::new(usize::MAX);
        let accepted = bitmap.try_find_and_claim_abandoned(THREAD_SEQUENCE, |slice_index| {
            assert_eq!(callback_count.get(), 1);
            callback_count.set(2);
            accept_callback_index.set(slice_index);
            AbandonedBitmapClaim::Claimed
        });
        let accepted_returned_claimed = accepted.is_some();
        let accepted_claimed_index = accepted.unwrap_or(usize::MAX);
        let accept_callback_count = callback_count.get() - reject_callback_count;
        let accepted_bit_cleared = bitmap.is_clear_range(SELECTED_INDEX, 1) == Some(true);
        let accepted_chunkmap_retained = bitmap.chunkmap().is_set_run(0, 1);

        // A successful bit claim intentionally leaves the conservative map
        // set. The next source snapshot finds the drained chunk, invokes no
        // ownership callback, and repairs that stale map bit.
        let drained = bitmap.try_find_and_claim_abandoned(THREAD_SEQUENCE, |_| {
            panic!("a drained bitmap chunk must not invoke the ownership callback")
        });
        let drained_returned_claimed = drained.is_some();
        let drained_callback_count = callback_count.get()
            - reject_callback_count
            - accept_callback_count;
        let drained_chunkmap_cleared = bitmap.chunkmap().is_clear_run(0, 1);

        assert!(initial_set_transitioned);
        assert!(!rejected_returned_claimed);
        assert_eq!(reject_callback_count, 1);
        assert_eq!(reject_callback_index.get(), SELECTED_INDEX);
        assert!(rejected_bit_restored);
        assert!(rejected_chunkmap_retained);
        assert!(accepted_returned_claimed);
        assert_eq!(accept_callback_count, 1);
        assert_eq!(accept_callback_index.get(), SELECTED_INDEX);
        assert_eq!(accepted_claimed_index, SELECTED_INDEX);
        assert!(accepted_bit_cleared);
        assert!(accepted_chunkmap_retained);
        assert!(!drained_returned_claimed);
        assert_eq!(drained_callback_count, 0);
        assert!(drained_chunkmap_cleared);

        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        std::println!("CRABC_MI_M2_BITMAP_ABANDONED_CLAIM_TRACE_BEGIN");
        emit!("m2.bitmap.control.bfield_bits", BFIELD_BITS);
        emit!("m2.bitmap.control.bchunk_bits", BCHUNK_BITS);
        emit!("m2.bitmap.control.thread_sequence", THREAD_SEQUENCE);
        emit!("m2.bitmap.control.selected_index", SELECTED_INDEX);
        emit!("m2.bitmap.layout.byte_size", layout.byte_size());
        emit!("m2.bitmap.setup.chunk_count", layout.chunk_count());
        emit!("m2.bitmap.setup.initial_set_transitioned", initial_set_transitioned);
        emit!("m2.bitmap.reject.returned_claimed", rejected_returned_claimed);
        emit!("m2.bitmap.reject.callback_count", reject_callback_count);
        emit!("m2.bitmap.reject.callback_index", reject_callback_index.get());
        emit!("m2.bitmap.reject.bit_restored", rejected_bit_restored);
        emit!("m2.bitmap.reject.chunkmap_retained", rejected_chunkmap_retained);
        emit!("m2.bitmap.accept.returned_claimed", accepted_returned_claimed);
        emit!("m2.bitmap.accept.callback_count", accept_callback_count);
        emit!("m2.bitmap.accept.callback_index", accept_callback_index.get());
        emit!("m2.bitmap.accept.claimed_index", accepted_claimed_index);
        emit!("m2.bitmap.accept.bit_cleared", accepted_bit_cleared);
        emit!("m2.bitmap.accept.chunkmap_retained", accepted_chunkmap_retained);
        emit!("m2.bitmap.drain.returned_claimed", drained_returned_claimed);
        emit!("m2.bitmap.drain.callback_count", drained_callback_count);
        emit!("m2.bitmap.drain.chunkmap_cleared", drained_chunkmap_cleared);
        std::println!("CRABC_MI_M2_BITMAP_ABANDONED_CLAIM_TRACE_END");
    }

    #[test]
    fn abandoned_reclaim_bitmap_rejected_reader_quiesces_before_later_word_retry() {
        extern crate std;

        use std::sync::{Arc, Barrier};
        use std::thread;

        // `mi_bchunk_try_find_and_clear` visits a bitmap *chunk* once per
        // `mi_bitmap_find` snapshot. The two candidates deliberately share
        // that chunk but occupy adjacent atomic `mi_bfield_t` words. The
        // rejected low-word reader must restore its bit before `unabandon`
        // clears it, while another reader may claim the high-word candidate.
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        let rejected = BFIELD_BITS - 1;
        let later_word = BFIELD_BITS;
        assert_eq!(bitmap.set_range(rejected, 1), Some(RunTransition::all_clear(0)));
        assert_eq!(bitmap.set_range(later_word, 1), Some(RunTransition::all_clear(0)));

        let bitmap = &bitmap;
        let reader_has_claimed = Arc::new(Barrier::new(2));
        let clearer_observed_temporary_clear = Arc::new(Barrier::new(2));
        let allow_restore = Arc::new(Barrier::new(2));

        thread::scope(|scope| {
            let reader_for_thread = Arc::clone(&reader_has_claimed);
            let restore_for_thread = Arc::clone(&allow_restore);
            scope.spawn(move || {
                assert_eq!(
                    bitmap.try_find_and_claim_abandoned(0, |slice_index| {
                        assert_eq!(slice_index, rejected);
                        reader_for_thread.wait();
                        restore_for_thread.wait();
                        AbandonedBitmapClaim::KeepSet
                    }),
                    None,
                );
            });
            reader_has_claimed.wait();

            // The source's one-chunk visitor does not retry `rejected` in
            // this snapshot. Its temporary clear leaves the adjacent field
            // independently available to a concurrent source reader.
            assert_eq!(
                bitmap.try_find_and_claim_abandoned(0, |slice_index| {
                    assert_eq!(slice_index, later_word);
                    AbandonedBitmapClaim::Claimed
                }),
                Some(later_word),
            );

            let clearer_for_thread = Arc::clone(&clearer_observed_temporary_clear);
            scope.spawn(move || {
                assert_eq!(
                    bitmap.clear_once_set_observing_temporary_clear(rejected, || {
                        clearer_for_thread.wait();
                    }),
                    Some(())
                );
            });
            // `clear_once_set` has seen the temporary zero but cannot remove
            // it permanently until the rejected owner claim restores it.
            clearer_observed_temporary_clear.wait();
            allow_restore.wait();
        });

        assert_eq!(bitmap.is_clear_range(rejected, 1), Some(true));
        assert_eq!(bitmap.is_clear_range(later_word, 1), Some(true));
    }

    #[test]
    fn abandoned_clear_once_set_waits_for_a_failed_reader_to_restore_its_bit() {
        extern crate std;

        use std::sync::{Arc, Barrier};
        use std::thread;

        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let bitmap = unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap()
        };
        assert_eq!(bitmap.set_range(3, 1), Some(RunTransition::all_clear(0)));
        let bitmap = &bitmap;
        let reader_has_claimed = Arc::new(Barrier::new(2));
        let clearer_observed_temporary_clear = Arc::new(Barrier::new(2));
        let allow_restore = Arc::new(Barrier::new(2));

        thread::scope(|scope| {
            let reader_for_thread = Arc::clone(&reader_has_claimed);
            let restore_for_thread = Arc::clone(&allow_restore);
            scope.spawn(move || {
                assert_eq!(
                    bitmap.try_find_and_claim_abandoned(0, |_| {
                        reader_for_thread.wait();
                        restore_for_thread.wait();
                        AbandonedBitmapClaim::KeepSet
                    }),
                    None
                );
            });
            reader_has_claimed.wait();
            let clearer_for_thread = Arc::clone(&clearer_observed_temporary_clear);
            scope.spawn(move || {
                assert_eq!(
                    bitmap.clear_once_set_observing_temporary_clear(3, || {
                        clearer_for_thread.wait();
                    }),
                    Some(())
                );
            });
            // This rendezvous is reached immediately after the clearer read
            // the temporary zero and before the reader receives permission to
            // restore it. The regression cannot pass merely because the
            // reader happened to win the race first.
            clearer_observed_temporary_clear.wait();
            allow_restore.wait();
        });

        assert_eq!(bitmap.is_clear_range(3, 1), Some(true));
    }

    #[test]
    fn bitmap_view_rejects_invalid_storage_before_accessing_it() {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let storage_pointer = storage.bytes.as_mut_ptr().cast::<u8>();

        assert!(unsafe {
            BitmapView::initialize(core::ptr::null_mut(), layout.byte_size(), layout, false)
        }
        .is_none());
        assert!(unsafe {
            BitmapView::initialize(storage_pointer.add(1), layout.byte_size(), layout, false)
        }
        .is_none());
        assert!(unsafe {
            BitmapView::initialize(storage_pointer, layout.byte_size() - 1, layout, false)
        }
        .is_none());
    }

    #[test]
    fn bitmap_view_accepts_caller_initialized_zero_storage_without_rezeroing() {
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        let mut storage = BitmapTestStorage::uninit();
        let storage_pointer = storage.bytes.as_mut_ptr().cast::<u8>();
        unsafe { core::ptr::write_bytes(storage_pointer, 0, layout.byte_size()) };

        let bitmap = unsafe {
            BitmapView::initialize(storage_pointer, storage.bytes.len(), layout, true).unwrap()
        };
        assert_eq!(bitmap.chunk_count(), 1);
        assert!(bitmap.is_all_clear());
    }
}
