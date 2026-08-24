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
// and conservative chunkmap maintenance), plus `src/bitmap.c:1583-1784,
// 1794-1997` (binned initialization, size bins, two-level claims, and exact
// multi-chunk rollback). This slice intentionally excludes visitors,
// callbacks, statistics-counter integration, `clear_once_set`/yielding, and
// allocator-backed bitmap metadata.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use crate::atomic::{
    word_and_acq_rel, word_cas_strong_acq_rel, word_cas_strong_relaxed,
    word_exchange_release, word_load_acquire, word_load_relaxed, word_or_acq_rel,
    word_store_release, AtomicWord,
};
use crate::bits::{bsf, bsr, clz, ctz, popcount};
use crate::config::BCHUNK_BITS;

/// `MI_BFIELD_BITS` for the sole 64-bit Linux/AArch64 target.
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
    pub(crate) unsafe fn initialize(
        subprocess: *mut crate::types::Subprocess,
        storage: *mut u8,
        storage_byte_count: usize,
        layout: BinnedBitmapLayout,
        already_zero: bool,
    ) -> Option<Self> {
        if storage.is_null()
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
        for index in 0..ChunkBin::MAPPED_COUNT {
            let bin = ChunkBin::from_index(index);
            if bin == selected {
                let _ = self.bin_map(bin).set_run(chunk_index, 1);
            } else {
                let _ = self.bin_map(bin).clear_run(chunk_index, 1);
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
    fn binned_claim_specializations_keep_chunk_boundaries_and_size_bins() {
        let layout = BinnedBitmapLayout::for_bit_count(BCHUNK_BITS * 2).unwrap();
        let mut storage = BinnedBitmapTestStorage::uninit();
        let mut bitmap = unsafe {
            BinnedBitmapView::initialize(
                core::ptr::null_mut(),
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
                core::ptr::null_mut(),
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
