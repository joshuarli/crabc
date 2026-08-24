// Copyright (c) 2018-2024, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
//
// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/internal.h:822-829,
// 880-915,1301-1309`, `src/page.c:33-39,646-670`, and
// `src/arena.c:971-1010,1053-1068,1155-1168,1183-1204`. This module isolates
// only page geometry: slice counts, the default aligned-metadata usable start,
// object counts, relative offsets, and the default-profile capacity-extension
// bound. It neither dereferences page metadata nor selects an arena, mapping,
// page kind, or allocation policy.

use crate::config::{
    ARENA_SLICE_SIZE, LARGE_PAGE_SIZE, MEDIUM_PAGE_SIZE, SMALL_PAGE_SIZE, WORD_SIZE,
};
use crate::invariants;
use crate::types::PageKind;

const PAGE_BLOCK_START_MAX_OFFSET: usize = 8 * usize::BITS as usize;
const PAGE_MAX_EXTEND_SIZE: usize = 8 * 1024;
const PAGE_MIN_EXTEND: usize = 1;

/// Returns the number of arena slices for an already-selected regular page
/// kind, as in `src/arena.c:_mi_arenas_page_alloc`.
///
/// `None` rejects `PageKind::Singleton`: its size depends on the requested
/// block size and is derived by [`singleton_page_slice_count`] instead.
#[inline]
pub(crate) const fn regular_page_slice_count(kind: PageKind) -> Option<usize> {
    let page_size = match kind {
        PageKind::Small => SMALL_PAGE_SIZE,
        PageKind::Medium => MEDIUM_PAGE_SIZE,
        PageKind::Large => LARGE_PAGE_SIZE,
        PageKind::Singleton => return None,
    };
    invariants::slice_count_of_size(page_size)
}

/// Returns the allocation span for a singleton page in the default
/// `MI_SECURE < 2`, aligned-metadata profile.
///
/// This is `mi_slice_count_of_size(info_size + block_size)` with the
/// source-selected `info_size == 0`. `None` represents a zero block size or
/// rounding overflow, both excluded by the C allocation path's preconditions.
#[inline]
pub(crate) const fn singleton_page_slice_count(block_size: usize) -> Option<usize> {
    if block_size == 0 {
        return None;
    }
    invariants::slice_count_of_size(block_size)
}

/// Returns `block_start`, the usable-page start relative to the page's first
/// arena slice, for the frozen aligned-metadata profile.
///
/// This ports `src/arena.c:988-994`. Metadata is separate, so the normal
/// start is zero; selected pointer-sized power-of-two block sizes receive one
/// block of offset. `None` makes the positive `block_size` precondition of
/// later source divisions explicit.
#[inline]
pub(crate) const fn page_usable_start_offset(block_size: usize) -> Option<usize> {
    if block_size == 0 {
        return None;
    }
    if block_size >= WORD_SIZE
        && block_size <= PAGE_BLOCK_START_MAX_OFFSET
        && invariants::is_power_of_two(block_size)
    {
        Some(block_size)
    } else {
        Some(0)
    }
}

/// Computes `mi_page_size` without accessing a `mi_page_t`.
///
/// `None` represents the source helper's positive-block-size precondition or
/// a product that the C page-state invariants make unrepresentable.
#[inline]
pub(crate) const fn page_area_size(block_size: usize, reserved: u16) -> Option<usize> {
    if block_size == 0 {
        return None;
    }
    block_size.checked_mul(reserved as usize)
}

/// Calculates the `reserved` field set by `mi_arenas_page_alloc_fresh` for a
/// non-OS-aligned page: `(page_noguard_size - block_start) / block_size`.
///
/// `None` exposes the source assertions that the start lies in the page, at
/// least one object fits, and the count fits the `uint16_t` page field. The
/// forced-one-object OS-aligned singleton case is allocation policy and is
/// deliberately not represented by this arithmetic kernel.
#[inline]
pub(crate) const fn reserved_object_count(
    page_noguard_size: usize,
    block_start: usize,
    block_size: usize,
) -> Option<u16> {
    if block_size == 0 || block_start > page_noguard_size {
        return None;
    }
    let reserved = (page_noguard_size - block_start) / block_size;
    if reserved == 0 || reserved > u16::MAX as usize {
        return None;
    }
    Some(reserved as u16)
}

/// Computes the relative byte offset used by `mi_page_block_at`.
///
/// The source permits `index == reserved` to form its one-past-page endpoint;
/// `None` rejects a zero block size, an index beyond that endpoint, or a
/// multiplication overflow.
#[inline]
pub(crate) const fn page_block_offset(
    block_size: usize,
    index: usize,
    reserved: u16,
) -> Option<usize> {
    if block_size == 0 || index > reserved as usize {
        return None;
    }
    index.checked_mul(block_size)
}

/// Returns the offset relative to an arena slice used by
/// `mi_page_slice_offset_of` for an already-derived usable start.
///
/// `None` represents only addition overflow; callers obtain a valid
/// `usable_start_offset` from [`page_usable_start_offset`].
#[inline]
pub(crate) const fn page_slice_offset(
    usable_start_offset: usize,
    offset_relative_to_page_start: usize,
) -> Option<usize> {
    usable_start_offset.checked_add(offset_relative_to_page_start)
}

/// Validates the scalar capacity/reserved relation required by page
/// initialization and extension without inspecting a page's free lists.
///
/// The empty bootstrap prototype in `types.rs` is intentionally outside this
/// fresh-page geometry contract; real initialized pages require `reserved > 0`.
#[inline]
pub(crate) const fn page_counts_are_valid(capacity: u16, reserved: u16) -> bool {
    reserved != 0 && capacity <= reserved
}

/// Returns the next number of objects initialized by `mi_page_extend_free` in
/// the frozen default profile, before any free-list writes occur.
///
/// `slice_committed` is the already-committed byte count relative to the
/// slice start (`mi_page_slice_committed`), where zero means fully committed.
/// `None` makes the source page-count invariant, nonzero block size, and
/// checked intermediate arithmetic explicit. A result of zero means the page
/// is already at its reserved capacity and mirrors the source's early return.
#[inline]
pub(crate) const fn page_extend_count(
    capacity: u16,
    reserved: u16,
    block_size: usize,
    slice_committed: usize,
) -> Option<u16> {
    if !page_counts_are_valid(capacity, reserved) || block_size == 0 {
        return None;
    }

    let available = (reserved - capacity) as usize;
    if available == 0 {
        return Some(0);
    }

    let mut max_extend = if block_size >= PAGE_MAX_EXTEND_SIZE {
        PAGE_MIN_EXTEND
    } else {
        PAGE_MAX_EXTEND_SIZE / block_size
    };
    if max_extend < PAGE_MIN_EXTEND {
        max_extend = PAGE_MIN_EXTEND;
    }

    let mut extend = if available < max_extend {
        available
    } else {
        max_extend
    };
    if slice_committed > 0 {
        let extend_size = match extend.checked_mul(block_size) {
            Some(value) => value,
            None => return None,
        };
        if extend_size > ARENA_SLICE_SIZE {
            extend = match invariants::divide_up(ARENA_SLICE_SIZE, block_size) {
                Some(value) => value,
                None => return None,
            };
        }
    }

    if extend == 0 || extend > available || extend > u16::MAX as usize {
        return None;
    }
    Some(extend as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ARENA_SLICE_SIZE, LARGE_PAGE_SIZE, MEDIUM_PAGE_SIZE, SMALL_PAGE_SIZE, WORD_SIZE,
    };
    use crate::types::PageKind;

    #[test]
    fn regular_page_slice_counts_follow_each_source_page_size_transition() {
        assert_eq!(regular_page_slice_count(PageKind::Small), Some(1));
        assert_eq!(regular_page_slice_count(PageKind::Medium), Some(8));
        assert_eq!(regular_page_slice_count(PageKind::Large), Some(64));
        assert_eq!(regular_page_slice_count(PageKind::Singleton), None);

        assert_eq!(
            regular_page_slice_count(PageKind::Small),
            Some(SMALL_PAGE_SIZE / ARENA_SLICE_SIZE),
        );
        assert_eq!(
            regular_page_slice_count(PageKind::Medium),
            Some(MEDIUM_PAGE_SIZE / ARENA_SLICE_SIZE),
        );
        assert_eq!(
            regular_page_slice_count(PageKind::Large),
            Some(LARGE_PAGE_SIZE / ARENA_SLICE_SIZE),
        );
    }

    #[test]
    fn singleton_slice_rounding_changes_only_at_arena_slice_boundaries() {
        assert_eq!(singleton_page_slice_count(0), None);
        assert_eq!(singleton_page_slice_count(1), Some(1));
        assert_eq!(singleton_page_slice_count(ARENA_SLICE_SIZE - 1), Some(1));
        assert_eq!(singleton_page_slice_count(ARENA_SLICE_SIZE), Some(1));
        assert_eq!(singleton_page_slice_count(ARENA_SLICE_SIZE + 1), Some(2));
        assert_eq!(singleton_page_slice_count(usize::MAX), None);
    }

    #[test]
    fn separated_metadata_start_offset_matches_the_power_of_two_window() {
        assert_eq!(page_usable_start_offset(0), None);
        assert_eq!(page_usable_start_offset(WORD_SIZE - 1), Some(0));
        assert_eq!(page_usable_start_offset(WORD_SIZE), Some(WORD_SIZE));
        assert_eq!(page_usable_start_offset(2 * WORD_SIZE), Some(2 * WORD_SIZE));
        assert_eq!(page_usable_start_offset(512), Some(512));
        assert_eq!(page_usable_start_offset(513), Some(0));
        assert_eq!(page_usable_start_offset(3 * WORD_SIZE), Some(0));
    }

    #[test]
    fn reserved_objects_apply_the_source_floor_and_u16_page_metadata_bound() {
        assert_eq!(reserved_object_count(SMALL_PAGE_SIZE, 0, WORD_SIZE), Some(8192));
        assert_eq!(
            reserved_object_count(SMALL_PAGE_SIZE, WORD_SIZE, WORD_SIZE),
            Some(8191),
        );
        assert_eq!(reserved_object_count(MEDIUM_PAGE_SIZE, 0, 10 * 1024), Some(51));
        assert_eq!(reserved_object_count(LARGE_PAGE_SIZE, 0, 512 * 1024), Some(8));

        assert_eq!(reserved_object_count(u16::MAX as usize, 0, 1), Some(u16::MAX));
        assert_eq!(reserved_object_count(ARENA_SLICE_SIZE, 0, 1), None);
        assert_eq!(reserved_object_count(ARENA_SLICE_SIZE, ARENA_SLICE_SIZE, 1), None);
        assert_eq!(reserved_object_count(ARENA_SLICE_SIZE, 0, 0), None);
    }

    #[test]
    fn area_and_block_offsets_preserve_the_inclusive_one_past_block_boundary() {
        assert_eq!(page_area_size(16, 4), Some(64));
        assert_eq!(page_area_size(usize::MAX, 2), None);
        assert_eq!(page_area_size(0, 1), None);

        assert_eq!(page_block_offset(16, 0, 4), Some(0));
        assert_eq!(page_block_offset(16, 3, 4), Some(48));
        assert_eq!(page_block_offset(16, 4, 4), Some(64));
        assert_eq!(page_block_offset(16, 5, 4), None);
        assert_eq!(page_block_offset(1, u16::MAX as usize, u16::MAX), Some(u16::MAX as usize));
        assert_eq!(page_block_offset(1, u16::MAX as usize + 1, u16::MAX), None);
        assert_eq!(page_block_offset(usize::MAX, 2, 2), None);

        assert_eq!(page_slice_offset(512, 0), Some(512));
        assert_eq!(page_slice_offset(512, ARENA_SLICE_SIZE - 512), Some(ARENA_SLICE_SIZE));
        assert_eq!(page_slice_offset(usize::MAX, 1), None);
    }

    #[test]
    fn capacity_extension_retains_the_default_eight_kib_touch_bound() {
        assert!(page_counts_are_valid(0, 1));
        assert!(page_counts_are_valid(8, 8));
        assert!(!page_counts_are_valid(0, 0));
        assert!(!page_counts_are_valid(9, 8));

        assert_eq!(page_extend_count(0, 1024, WORD_SIZE, 0), Some(1024));
        assert_eq!(page_extend_count(0, 1025, WORD_SIZE, 0), Some(1024));
        assert_eq!(page_extend_count(0, 3, 4096, 0), Some(2));
        assert_eq!(page_extend_count(0, 3, 4097, 0), Some(1));
        assert_eq!(page_extend_count(0, 2, 8192, 0), Some(1));
        assert_eq!(page_extend_count(8, 8, WORD_SIZE, 0), Some(0));
        assert_eq!(page_extend_count(9, 8, WORD_SIZE, 0), None);
        assert_eq!(page_extend_count(0, 0, WORD_SIZE, 0), None);

        // For the default `MI_MIN_EXTEND == 1`, on-demand commitment keeps
        // the same source result even when one block exceeds one arena slice.
        assert_eq!(
            page_extend_count(0, 2, ARENA_SLICE_SIZE + 1, WORD_SIZE),
            Some(1),
        );
        assert_eq!(page_extend_count(0, 2, usize::MAX, WORD_SIZE), None);
    }
}
