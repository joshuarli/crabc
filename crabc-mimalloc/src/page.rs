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
// 880-915,1301-1309`, `src/page.c:33-39,574-644,646-670`, and
// `src/arena.c:870-1037,1053-1068,1155-1168,1183-1204`. This module isolates
// only page geometry: slice counts, the default aligned-metadata usable start,
// object counts, relative offsets, initial/extended on-demand commitment
// arithmetic, and the default-profile capacity-extension bound. It neither
// dereferences page metadata nor selects an arena, mapping, page kind, or
// allocation policy.

use crate::config::{
    ARENA_SLICE_SIZE, LARGE_PAGE_SIZE, MEDIUM_PAGE_SIZE, PAGE_MIN_COMMIT_SIZE, SMALL_PAGE_SIZE,
    WORD_SIZE,
};
use crate::invariants;
use crate::types::PageKind;
use crate::os::PageSize;

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

/// Returns the complete aligned-metadata singleton allocation span.
///
/// Secure level two aligns the client span to the actual OS guard-page size
/// and reserves one extra OS page before rounding to arena slices. This tail
/// remains accessible at secure levels one and two; page protection belongs
/// to the higher source security levels. `None` rejects zero or overflow.
#[inline]
pub(crate) const fn singleton_page_slice_count(block_size: usize, os_page_size: PageSize) -> Option<usize> {
    if block_size == 0 {
        return None;
    }
    let allocation_size = if crate::config::SECURE_LEVEL >= 2 {
        let aligned = match invariants::align_up(block_size, os_page_size.bytes()) {
            Some(aligned) => aligned,
            None => return None,
        };
        match aligned.checked_add(os_page_size.bytes()) {
            Some(size) => size,
            None => return None,
        }
    } else {
        block_size
    };
    invariants::slice_count_of_size(allocation_size)
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

/// Calculates the number of PageMap slices registered for a regular page.
///
/// This mirrors the pinned mimalloc v3.5.0 `src/page-map.c:139-145` span
/// calculation: derive `mi_page_area` as `block_size * reserved`, clip an
/// area larger than `LARGE_PAGE_SIZE` to `LARGE_PAGE_SIZE -
/// ARENA_SLICE_SIZE`, then add the whole-slice prefix before the page start:
/// `ceil(page_area / ARENA_SLICE_SIZE) +
/// floor(page_start_offset / ARENA_SLICE_SIZE)`.
/// `page_start_offset` is the byte offset from `mi_page_slice_start(page)` to
/// `mi_page_area(page)`, so offsets within a slice intentionally contribute
/// zero. `None` rejects an uninitialized page or checked arithmetic overflow.
#[inline]
pub(crate) const fn page_map_slice_count(
    block_size: usize,
    reserved: u16,
    page_start_offset: usize,
) -> Option<usize> {
    if block_size == 0 || reserved == 0 {
        return None;
    }
    let page_area = match page_area_size(block_size, reserved) {
        Some(page_area) if page_area > LARGE_PAGE_SIZE => {
            match LARGE_PAGE_SIZE.checked_sub(ARENA_SLICE_SIZE) {
                Some(page_area) => page_area,
                None => return None,
            }
        }
        Some(page_area) => page_area,
        None => return None,
    };
    let area_slice_count = match invariants::slice_count_of_size(page_area) {
        Some(slice_count) => slice_count,
        None => return None,
    };
    let leading_slice_count = page_start_offset / ARENA_SLICE_SIZE;
    area_slice_count.checked_add(leading_slice_count)
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
/// the selected build profile, before any free-list writes occur.
///
/// `slice_pcommitted` is the source count of committed OS pages relative to
/// the slice start (`mi_page_slice_committed`), where zero means fully
/// committed. `None` makes the source page-count invariant, nonzero block
/// size, and checked intermediate arithmetic explicit. A result of zero means
/// the page is already at its reserved capacity and mirrors the source's
/// early return.
#[inline]
pub(crate) const fn page_extend_count(
    capacity: u16,
    reserved: u16,
    block_size: usize,
    slice_pcommitted: u16,
) -> Option<u16> {
    page_extend_count_at_secure_level(capacity, reserved, block_size, slice_pcommitted,
        crate::config::SECURE_LEVEL)
}

/// Applies the source-selected minimum while retaining commitment bounds.
#[inline]
pub(crate) const fn page_extend_count_at_secure_level(
    capacity: u16,
    reserved: u16,
    block_size: usize,
    slice_pcommitted: u16,
    secure_level: usize,
) -> Option<u16> {
    if secure_level > 5 { return None; }
    let minimum = if secure_level >= 2 { 8 * secure_level } else { PAGE_MIN_EXTEND };
    if !page_counts_are_valid(capacity, reserved) || block_size == 0 {
        return None;
    }

    let available = (reserved - capacity) as usize;
    if available == 0 {
        return Some(0);
    }

    let mut max_extend = if block_size >= PAGE_MAX_EXTEND_SIZE {
        minimum
    } else {
        PAGE_MAX_EXTEND_SIZE / block_size
    };
    if max_extend < minimum {
        max_extend = minimum;
    }

    let mut extend = if available < max_extend {
        available
    } else {
        max_extend
    };
    if slice_pcommitted != 0 {
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

/// The source `mi_page_extend_free` page-area commitment delta for one
/// already-selected on-demand page.
///
/// `slice_pcommitted` and `next_slice_pcommitted` are OS-page counts, while
/// `commit_offset` and `commit_size` are bytes relative to the page's leading
/// arena slice. `commit_size == 0` means the already-recorded prefix covers
/// the next source free-list extension; callers still perform that extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageAreaCommitPlan {
    pub(crate) extend: u16,
    pub(crate) commit_offset: usize,
    pub(crate) commit_size: usize,
    pub(crate) next_slice_pcommitted: u16,
}

/// Computes the initial prefix `mi_arenas_page_alloc_fresh` commits for an
/// on-demand regular page.
///
/// The returned count is stored in `mi_page_t::slice_pcommitted` only after
/// the source `mi_arena_commit` call succeeds. `page_span_size` is the whole
/// claimed arena span, not merely the usable object area, because the source
/// clips its initial commitment to `page_noguard_size`.
#[inline]
pub(crate) fn initial_page_slice_pcommitted(
    usable_start_offset: usize,
    block_size: usize,
    page_span_size: usize,
    os_page_size: usize,
) -> Option<u16> {
    if block_size == 0
        || page_span_size == 0
        || os_page_size == 0
        || !invariants::is_power_of_two(os_page_size)
    {
        return None;
    }
    let minimum_commit = if PAGE_MIN_COMMIT_SIZE >= os_page_size {
        PAGE_MIN_COMMIT_SIZE
    } else {
        os_page_size
    };
    let first_block_end = usable_start_offset.checked_add(block_size)?;
    if first_block_end > page_span_size {
        return None;
    }
    let committed = invariants::align_up(first_block_end, minimum_commit)?.min(page_span_size);
    if committed == 0 || committed % os_page_size != 0 {
        return None;
    }
    let page_count = committed / os_page_size;
    if page_count > u16::MAX as usize {
        return None;
    }
    Some(page_count as u16)
}

/// Computes the source direct `_mi_os_commit` transition that precedes
/// `mi_page_free_list_extend` for a nonzero `slice_pcommitted` page.
///
/// `page_slice_offset` is `mi_page_slice_offset_of(page, 0)`, and
/// `page_span_size` is the complete page claim. The plan rejects impossible
/// metadata before any mapping operation, so callers cannot turn a malformed
/// prefix count into an out-of-range OS commit.
#[inline]
pub(crate) fn page_area_commit_plan(
    capacity: u16,
    reserved: u16,
    block_size: usize,
    slice_pcommitted: u16,
    os_page_size: usize,
    page_slice_offset: usize,
    page_span_size: usize,
) -> Option<PageAreaCommitPlan> {
    if slice_pcommitted == 0
        || page_span_size == 0
        || os_page_size == 0
        || !invariants::is_power_of_two(os_page_size)
    {
        return None;
    }
    let current_commit = (slice_pcommitted as usize).checked_mul(os_page_size)?;
    if current_commit > page_span_size || page_slice_offset >= page_span_size {
        return None;
    }
    // An already initialized block range must fit the recorded committed
    // prefix. The C routine can trust its live `mi_page_t`; this pure boundary
    // makes that prerequisite explicit before it turns a corrupt count into a
    // mapping request.
    let initialized_extent = page_slice_offset
        .checked_add((capacity as usize).checked_mul(block_size)?)?;
    if initialized_extent > current_commit {
        return None;
    }
    let extend = page_extend_count(capacity, reserved, block_size, slice_pcommitted)?;
    if extend == 0 {
        return Some(PageAreaCommitPlan {
            extend,
            commit_offset: 0,
            commit_size: 0,
            next_slice_pcommitted: slice_pcommitted,
        });
    }
    let minimum_commit = if PAGE_MIN_COMMIT_SIZE >= os_page_size {
        PAGE_MIN_COMMIT_SIZE
    } else {
        os_page_size
    };
    let extended_capacity = (capacity as usize).checked_add(extend as usize)?;
    let extended_size = extended_capacity.checked_mul(block_size)?;
    let required_extent = page_slice_offset.checked_add(extended_size)?;
    let needed_commit = invariants::align_up(required_extent, minimum_commit)?;
    if needed_commit > page_span_size || needed_commit % os_page_size != 0 {
        return None;
    }
    if needed_commit <= current_commit {
        return Some(PageAreaCommitPlan {
            extend,
            commit_offset: current_commit,
            commit_size: 0,
            next_slice_pcommitted: slice_pcommitted,
        });
    }
    let next_page_count = needed_commit / os_page_size;
    if next_page_count > u16::MAX as usize {
        return None;
    }
    Some(PageAreaCommitPlan {
        extend,
        commit_offset: current_commit,
        commit_size: needed_commit - current_commit,
        next_slice_pcommitted: next_page_count as u16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ARENA_SLICE_SIZE, KIB, LARGE_PAGE_SIZE, MEDIUM_PAGE_SIZE, SMALL_MAX_OBJ_SIZE,
        SMALL_PAGE_SIZE, WORD_SIZE,
    };
    use crate::types::PageKind;
use crate::os::PageSize;

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
    fn singleton_slice_rounding_includes_only_the_selected_source_guard_extent() {
        #[cfg(target_arch = "x86_64")]
        let page_sizes = [4096];
        #[cfg(target_arch = "aarch64")]
        let page_sizes = [4096, 16384, 65536];
        for page_bytes in page_sizes {
            let page_size = PageSize::new(page_bytes).unwrap();
            assert_eq!(singleton_page_slice_count(0, page_size), None);
            assert_eq!(singleton_page_slice_count(usize::MAX, page_size), None);
            for block in [1, (ARENA_SLICE_SIZE - page_bytes).max(1), ARENA_SLICE_SIZE - page_bytes + 1,
                          ARENA_SLICE_SIZE, ARENA_SLICE_SIZE + 1] {
                let span = if crate::config::SECURE_LEVEL >= 2 {
                    invariants::align_up(block, page_bytes).unwrap() + page_bytes
                } else { block };
                assert_eq!(singleton_page_slice_count(block, page_size),
                    invariants::slice_count_of_size(span));
            }
        }
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
    fn page_map_slice_counts_follow_source_area_clip_and_start_offset() {
        assert_eq!(page_map_slice_count(98_304, 42, 0), Some(63));
        assert_eq!(page_map_slice_count(12 * KIB, 42, 0), Some(8));
        assert_eq!(
            page_map_slice_count(12 * KIB, 42, ARENA_SLICE_SIZE),
            Some(9),
        );
        assert_eq!(
            page_map_slice_count(12 * KIB, 42, ARENA_SLICE_SIZE - 1),
            Some(8),
        );

        // The area is clipped before the whole-slice start offset is added.
        assert_eq!(page_map_slice_count(LARGE_PAGE_SIZE, 2, 0), Some(63));
        assert_eq!(
            page_map_slice_count(LARGE_PAGE_SIZE, 2, ARENA_SLICE_SIZE),
            Some(64),
        );
    }

    #[test]
    fn page_map_slice_count_rejects_uninitialized_pages_and_area_overflow() {
        assert_eq!(page_map_slice_count(0, 1, 0), None);
        assert_eq!(page_map_slice_count(1, 0, 0), None);
        assert_eq!(page_map_slice_count(usize::MAX, 2, 0), None);
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
            page_extend_count(0, 2, ARENA_SLICE_SIZE + 1, 1),
            Some(1),
        );
        assert_eq!(page_extend_count(0, 2, usize::MAX, 1), None);
    }

    #[test]
    fn secure_extension_minimum_still_obeys_reserved_and_commit_limits() {
        for level in 0..=5 {
            let minimum = if level < 2 { 1 } else { 8 * level };
            assert_eq!(page_extend_count_at_secure_level(0, 100, 8192, 0, level),
                Some(minimum as u16));
            assert_eq!(page_extend_count_at_secure_level(0, 3, 8192, 0, level),
                Some(core::cmp::min(minimum, 3) as u16));
            assert_eq!(page_extend_count_at_secure_level(0, 100, 8192, 1, level),
                Some(core::cmp::min(minimum, ARENA_SLICE_SIZE / 8192) as u16));
            assert_eq!(page_extend_count_at_secure_level(100, 100, 8192, 0, level), Some(0));
        }
        assert_eq!(page_extend_count_at_secure_level(0, 100, 8192, 0, 6), None);
    }

    #[test]
    fn on_demand_page_commit_plans_keep_os_page_counts_and_byte_ranges_distinct() {
        let page_size = 4096;
        let span = MEDIUM_PAGE_SIZE;
        let block_size = SMALL_MAX_OBJ_SIZE + 8;
        let offset = page_usable_start_offset(block_size).unwrap();
        let initial = initial_page_slice_pcommitted(offset, block_size, span, page_size)
            .expect("the first source block fits in a bounded medium prefix");
        assert_eq!(initial, 4, "the 16 KiB source minimum is four OS pages");

        let plan = page_area_commit_plan(
            1,
            reserved_object_count(span, offset, block_size).unwrap(),
            block_size,
            initial,
            page_size,
            offset,
            span,
        )
        .expect("the second source block has one page-area commit plan");
        assert_eq!(plan.extend, 1);
        assert_eq!(plan.commit_offset, 16 * KIB);
        assert_eq!(plan.commit_size, 16 * KIB);
        assert_eq!(plan.next_slice_pcommitted, 8);
    }

    #[test]
    fn on_demand_page_commit_plans_reject_malformed_prefixes_before_mapping() {
        let page_size = 4096;
        assert!(page_area_commit_plan(1, 2, 8192, 0, page_size, 0, MEDIUM_PAGE_SIZE).is_none());
        assert!(page_area_commit_plan(1, 2, 8192, 1, 0, 0, MEDIUM_PAGE_SIZE).is_none());
        assert!(page_area_commit_plan(1, 2, 8192, 200, page_size, 0, 64 * KIB).is_none());
        assert!(page_area_commit_plan(1, 2, 8192, 1, page_size, 0, MEDIUM_PAGE_SIZE).is_none());
        assert!(initial_page_slice_pcommitted(0, 8192, 0, page_size).is_none());
        assert!(initial_page_slice_pcommitted(0, 8192, MEDIUM_PAGE_SIZE, 3).is_none());
    }

    #[cfg(target_arch = "x86_64")]
    #[derive(Clone, Copy)]
    struct PageFaultAllocationSnapshot {
        malloc_normal: crate::statistics::FinalStatCount,
        malloc_requested: crate::statistics::FinalStatCount,
        malloc_bins: [crate::statistics::FinalStatCount; crate::config::BIN_HUGE + 1],
    }

    #[cfg(target_arch = "x86_64")]
    fn page_fault_allocation_snapshot(image: &crate::statistics::HeapTheapStatistics) -> PageFaultAllocationSnapshot {
        use crate::atomic::i64_load_relaxed;
        use crate::statistics::{FinalStatCount, HeapTheapStatistics, StatCount};
        let records = HeapTheapStatistics::layout_records();
        let offset = |name| records.iter().find(|(key, _)| *key == name).unwrap().1;
        let count = |offset: usize| {
            assert!(offset + core::mem::size_of::<StatCount>() <= core::mem::size_of::<HeapTheapStatistics>());
            // SAFETY: the initialized source-layout image is exclusively owned
            // by this fixture. Its layout records identify real StatCount fields,
            // and no statistics copy or update overlaps these relaxed loads.
            let field = unsafe { &*core::ptr::from_ref(image).cast::<u8>().add(offset).cast::<StatCount>() };
            FinalStatCount { total: i64_load_relaxed(&field.total), peak: i64_load_relaxed(&field.peak), current: i64_load_relaxed(&field.current) }
        };
        let bins = offset("offsetof.mi_stats_t.malloc_bins");
        PageFaultAllocationSnapshot {
            malloc_normal: count(offset("offsetof.mi_stats_t.malloc_normal")),
            malloc_requested: count(offset("offsetof.mi_stats_t.malloc_requested")),
            malloc_bins: core::array::from_fn(|index| count(bins + index * core::mem::size_of::<StatCount>())),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn failed_second_regular_extension_commit_retries_same_page_statistics() {
        crate::test_process::run_in_fresh_process(
            "page::tests::failed_second_regular_extension_commit_retries_same_page_statistics",
            || {
                use core::ffi::{c_char, c_int, c_void};
                use core::ptr::NonNull;
                use core::sync::atomic::{AtomicUsize, Ordering};
                use crate::config::SourceOption;
                use crate::diagnostic_output::RuntimeStderrOutput;
                use crate::os::fault;
                use crate::runtime_lifecycle::{
                    self, NativePageAllocationResult, NativePageFreeResult,
                };
                use crate::statistics::{
                    FinalStatisticsSnapshot, HeapTheapStatistics,
                    HeapTheapStatisticsSnapshot,
                };

                unsafe extern "C" {
                    static mut stderr: *mut c_void;
                    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
                }

                static WARNINGS: AtomicUsize = AtomicUsize::new(0);

                unsafe extern "C" fn source_stderr(message: *const c_char) {
                    // SAFETY: the process-lifetime musl FILE is the selected
                    // stderr destination and the message is NUL terminated.
                    unsafe { let _ = fputs(message, stderr); }
                }

                unsafe extern "C" fn capture_warning(message: *const c_char, _: *mut c_void) {
                    // SAFETY: the output owner supplies a NUL-terminated
                    // fragment while invoking this registered callback.
                    let bytes = unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes();
                    if bytes.windows(b"cannot commit OS memory".len())
                        .any(|window| window == b"cannot commit OS memory")
                    {
                        WARNINGS.fetch_add(1, Ordering::Relaxed);
                    }
                }

                fn stats() -> (FinalStatisticsSnapshot, HeapTheapStatisticsSnapshot, PageFaultAllocationSnapshot) {
                    let mut image = HeapTheapStatistics::new();
                    // SAFETY: this local source-layout image owns the exact
                    // header and is exclusively mutable until the copy ends.
                    assert!(unsafe { runtime_lifecycle::native_stats_get(core::ptr::from_mut(&mut image).cast()) });
                    (image.final_output_snapshot(), image.snapshot(), page_fault_allocation_snapshot(&image))
                }

                fn show(
                    stage: &str,
                    before: (FinalStatisticsSnapshot, HeapTheapStatisticsSnapshot, PageFaultAllocationSnapshot),
                    warnings: usize,
                    failures: usize,
                ) {
                    let (now, bins, allocation) = stats();
                    let old = before.0;
                    std::println!("{stage}.pages_extended={}", now.pages_extended - old.pages_extended);
                    std::println!("{stage}.page_committed={},{},{}",
                        now.page_committed.total - old.page_committed.total,
                        now.page_committed.peak - old.page_committed.peak,
                        now.page_committed.current - old.page_committed.current);
                    std::println!("{stage}.pages={},{},{}",
                        now.pages.total - old.pages.total,
                        now.pages.peak - old.pages.peak,
                        now.pages.current - old.pages.current);
                    std::println!("{stage}.requested={},{},{}",
                        allocation.malloc_requested.total - before.2.malloc_requested.total,
                        allocation.malloc_requested.peak - before.2.malloc_requested.peak,
                        allocation.malloc_requested.current - before.2.malloc_requested.current);
                    std::println!("{stage}.normal={},{},{}",
                        allocation.malloc_normal.total - before.2.malloc_normal.total,
                        allocation.malloc_normal.peak - before.2.malloc_normal.peak,
                        allocation.malloc_normal.current - before.2.malloc_normal.current);
                    for (index, (current, previous)) in allocation.malloc_bins.iter()
                        .zip(before.2.malloc_bins.iter()).enumerate()
                    {
                        if current.total > previous.total {
                            std::println!("{stage}.bin={index}:{},{},{}",
                                current.total - previous.total,
                                current.peak - previous.peak,
                                current.current - previous.current);
                        }
                    }
                    for (index, (current, previous)) in bins.page_bin_total.iter()
                        .zip(before.1.page_bin_total.iter()).enumerate()
                    {
                        if current > previous {
                            std::println!("{stage}.page_bin={index}:{},{}",
                                current - previous,
                                bins.page_bin_current[index] - before.1.page_bin_current[index]);
                        }
                    }
                    std::println!("{stage}.commit_calls={}", now.commit_calls - old.commit_calls);
                    std::println!("{stage}.warnings={warnings}");
                    std::println!("{stage}.failures={failures}");
                }

                // SAFETY: the FILE callback remains callable for this whole
                // fresh process and preserves the source stderr operation.
                assert!(runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { RuntimeStderrOutput::new(source_stderr) },
                ));
                crate::source_options_api::option_set(SourceOption::PageCommitOnDemand as c_int, 1);
                crate::source_options_api::option_set(SourceOption::ArenaEagerCommit as c_int, 0);
                crate::source_options_api::option_set(SourceOption::ShowErrors as c_int, 1);
                // SAFETY: the callback and null context remain valid until
                // this fresh test process exits.
                unsafe { crate::source_options_api::register_output(Some(capture_warning), core::ptr::null_mut()) };

                let before = stats();
                let matrix = std::env::var_os("CRABC_MI_STATISTICS_MATRIX").is_some();
                let faulted = std::env::var_os("CRABC_MI_STATISTICS_FAULT_CONTROL") != Some(std::ffi::OsString::from("success"));
                let mut blocks: [Option<NonNull<u8>>; 256] = [None; 256];
                blocks[0] = match runtime_lifecycle::native_allocate(64, false) {
                    NativePageAllocationResult::Allocated(pointer) => Some(pointer),
                    _ => panic!("first regular allocation failed before fault"),
                };
                // SAFETY: this fresh process owns every live client and
                // serializes all page mutations around the scalar projection.
                let initial = unsafe {
                    runtime_lifecycle::native_runtime_live_client_page_geometry_test_audit(blocks[0].unwrap())
                }.expect("the exact live regular client has stable page geometry");
                let initial_capacity = usize::from(initial.capacity);
                let mut filled_capacity = initial_capacity;
                let mut filled_extensions = 1;
                let mut allocated = 1;
                let filled = loop {
                    assert!(filled_capacity > 0 && filled_capacity + 2 <= blocks.len());
                    while allocated < filled_capacity {
                        let pointer = match runtime_lifecycle::native_allocate(64, false) {
                            NativePageAllocationResult::Allocated(pointer) => pointer,
                            _ => panic!("regular allocation failed before fault"),
                        };
                        assert!(blocks[..allocated].iter().all(|previous| *previous != Some(pointer)));
                        blocks[allocated] = Some(pointer);
                        allocated += 1;
                    }
                    // SAFETY: every client remains live and exclusively owned
                    // while this quiescent read copies the source page fields.
                    let current = unsafe {
                        runtime_lifecycle::native_runtime_live_client_page_geometry_test_audit(blocks[0].unwrap())
                    }.unwrap();
                    assert_eq!(usize::from(current.capacity), filled_capacity);
                    assert_eq!(current.used, filled_capacity);
                    assert!(current.free_head_is_null && current.local_free_head_is_null);
                    let slice_offset = current.page_slice_offset.expect("the controlled regular page belongs to an arena");
                    let extend = super::page_extend_count(current.capacity, current.reserved,
                        current.block_size, current.slice_pcommitted).unwrap();
                    assert!(extend > 0 && current.slice_pcommitted > 0);
                    let required = crate::invariants::align_up(
                        slice_offset + (usize::from(current.capacity) + usize::from(extend)) * current.block_size,
                        crate::config::PAGE_MIN_COMMIT_SIZE.max(4096),
                    ).unwrap();
                    if required > usize::from(current.slice_pcommitted) * 4096 { break current; }
                    blocks[allocated] = match runtime_lifecycle::native_allocate(64, false) {
                        NativePageAllocationResult::Allocated(pointer) => Some(pointer),
                        _ => panic!("accessible next extension failed before fault"),
                    };
                    assert!(blocks[..allocated].iter().all(|previous| *previous != blocks[allocated]));
                    allocated += 1;
                    // SAFETY: the first exact client remains live throughout
                    // this owner-only capacity extension and scalar read.
                    filled_capacity = usize::from(unsafe {
                        runtime_lifecycle::native_runtime_live_client_page_geometry_test_audit(blocks[0].unwrap())
                    }.unwrap().capacity);
                    filled_extensions += 1;
                };
                for (index, block) in blocks[..filled_capacity].iter().enumerate() {
                    // SAFETY: these distinct live allocations each own their
                    // requested 64-byte client span until the final frees.
                    unsafe { block.unwrap().as_ptr().write_bytes((index + 1) as u8, 64) };
                }
                std::println!("CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_BEGIN");
                std::println!("profile.level={}", crate::config::STAT_LEVEL);
                if matrix {
                    std::println!("profile.debug={}", crate::config::DEBUG_LEVEL);
                    std::println!("profile.guarded={}", usize::from(crate::config::GUARDED));
                    std::println!("profile.guarded_sample_rate={}", crate::source_options_api::option_get(SourceOption::GuardedSampleRate as c_int));
                    std::println!("profile.faulted={}", usize::from(faulted));
                    std::println!("geometry.initial_capacity={initial_capacity}");
                    std::println!("geometry.filled_capacity={filled_capacity}");
                    std::println!("geometry.filled_extensions={filled_extensions}");
                    std::println!("geometry.block_size={}", filled.block_size);
                    std::println!("geometry.slice_pcommitted={}", filled.slice_pcommitted);
                    std::println!("geometry.slice_offset={}", filled.page_slice_offset.unwrap());
                    std::println!("geometry.used={}", filled.used);
                    std::println!("geometry.reserved={}", filled.reserved);
                    std::println!("geometry.free_empty={}", usize::from(filled.free_head_is_null && filled.local_free_head_is_null));
                }
                std::println!("profile.on_demand={}",
                    crate::source_options_api::option_get(SourceOption::PageCommitOnDemand as c_int));
                std::println!("profile.eager_arena={}",
                    crate::source_options_api::option_get(SourceOption::ArenaEagerCommit as c_int));
                std::println!("profile.show_errors={}",
                    crate::source_options_api::option_get(SourceOption::ShowErrors as c_int));
                show("filled", before, WARNINGS.load(Ordering::Relaxed), 0);

                let fault = faulted.then(|| fault::install(fault::Plan::at(fault::Point::Commit, 1, crabc_core::Errno::NOMEM)));
                blocks[filled_capacity] = match runtime_lifecycle::native_allocate(64, false) {
                    NativePageAllocationResult::Allocated(pointer) => Some(pointer),
                    _ => panic!("fallback allocation after one failed page commit failed"),
                };
                // SAFETY: the original live clients remain owned by this
                // thread across the fault and fallback allocation.
                let after = unsafe { runtime_lifecycle::native_runtime_live_client_page_geometry_test_audit(blocks[0].unwrap()) }.unwrap();
                if matrix {
                    std::println!("failed_allocation.original_prefix={}", usize::from(after.capacity == filled.capacity && after.slice_pcommitted == filled.slice_pcommitted && after.used == filled.used));
                }
                let intact = blocks[..filled_capacity].iter().enumerate().all(|(index, block)| {
                    // SAFETY: this live requested span is readable and no
                    // allocator operation is allowed to overwrite client bytes.
                    unsafe { core::slice::from_raw_parts(block.unwrap().as_ptr(), 64) }.iter().all(|byte| *byte == (index + 1) as u8)
                });
                assert!(intact);
                if matrix { std::println!("failed_allocation.client_bytes={}", usize::from(intact)); }
                let first = blocks[0].unwrap().as_ptr().addr() >> 16;
                std::println!("failed_allocation.same_page={}", usize::from(blocks[filled_capacity].unwrap().as_ptr().addr() >> 16 == first));
                std::println!("failed_allocation.nonnull=1");
                if let Some(fault) = &fault { assert!(fault.observed() >= 1, "the source direct commit was reached"); }
                show("failed_allocation", before, WARNINGS.load(Ordering::Relaxed), usize::from(faulted));

                // SAFETY: this exact fallback allocation is still live and
                // owned by the current thread; the result consumes it once.
                assert_eq!(unsafe { runtime_lifecycle::native_free(blocks[filled_capacity].take().unwrap()) }, NativePageFreeResult::Freed);
                runtime_lifecycle::native_collect(true);
                blocks[filled_capacity + 1] = match runtime_lifecycle::native_allocate(64, false) {
                    NativePageAllocationResult::Allocated(pointer) => Some(pointer),
                    _ => panic!("same-page retry allocation failed"),
                };
                let intact = blocks[..filled_capacity].iter().enumerate().all(|(index, block)| {
                    // SAFETY: every original client remains live through the
                    // same-page retry and still owns these requested bytes.
                    unsafe { core::slice::from_raw_parts(block.unwrap().as_ptr(), 64) }.iter().all(|byte| *byte == (index + 1) as u8)
                });
                assert!(intact);
                if matrix { std::println!("retry.client_bytes={}", usize::from(intact)); }
                std::println!("retry.same_page={}", usize::from(blocks[filled_capacity + 1].unwrap().as_ptr().addr() >> 16 == first));
                std::println!("retry.nonnull=1");
                show("retry", before, WARNINGS.load(Ordering::Relaxed), usize::from(faulted));
                for block in blocks.into_iter().flatten() {
                    // SAFETY: each pointer names one distinct live local
                    // allocation and is consumed exactly once here.
                    assert_eq!(unsafe { runtime_lifecycle::native_free(block) }, NativePageFreeResult::Freed);
                }
                show("freed", before, WARNINGS.load(Ordering::Relaxed), usize::from(faulted));
                std::println!("CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_END");
            },
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn failed_initial_regular_page_commit_recovers_source_statistics() {
        crate::test_process::run_in_fresh_process(
            "page::tests::failed_initial_regular_page_commit_recovers_source_statistics",
            || {
                use core::ffi::{c_char, c_int, c_void};
                use core::sync::atomic::{AtomicUsize, Ordering};
                use crate::config::SourceOption;
                use crate::diagnostic_output::RuntimeStderrOutput;
                use crate::os::fault;
                use crate::runtime_lifecycle::{self, NativePageAllocationResult, NativePageFreeResult};
                use crate::statistics::{FinalStatisticsSnapshot, HeapTheapStatistics, HeapTheapStatisticsSnapshot};

                unsafe extern "C" {
                    static mut stderr: *mut c_void;
                    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
                }

                let matrix = std::env::var("CRABC_MI_STATISTICS_MATRIX").as_deref() == Ok("1");
                let faulted = !matrix || std::env::var("CRABC_MI_STATISTICS_FAULT_CONTROL").as_deref() != Ok("success");

                static WARNINGS: AtomicUsize = AtomicUsize::new(0);

                unsafe extern "C" fn source_stderr(message: *const c_char) {
                    // SAFETY: the process-lifetime FILE accepts this NUL-terminated fragment.
                    unsafe { let _ = fputs(message, stderr); }
                }

                unsafe extern "C" fn capture_warning(message: *const c_char, _: *mut c_void) {
                    // SAFETY: the callback receives a live NUL-terminated fragment.
                    let bytes = unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes();
                    if bytes.windows(b"cannot commit OS memory".len())
                        .any(|window| window == b"cannot commit OS memory")
                    {
                        WARNINGS.fetch_add(1, Ordering::Relaxed);
                    }
                }

                fn stats() -> (FinalStatisticsSnapshot, HeapTheapStatisticsSnapshot) {
                    let mut image = HeapTheapStatistics::new();
                    // SAFETY: this local source-layout image is exclusively mutable until copied.
                    assert!(unsafe { runtime_lifecycle::native_stats_get(core::ptr::from_mut(&mut image).cast()) });
                    (image.final_output_snapshot(), image.snapshot())
                }

                fn show(stage: &str, before: (FinalStatisticsSnapshot, HeapTheapStatisticsSnapshot), failures: usize) {
                    let (now, bins) = stats();
                    let old = before.0;
                    // Disabled scalar fields in the public statistics image are zero.
                    #[cfg(not(feature = "mi-stat-2"))]
                    let zero = crate::statistics::FinalStatCount { total: 0, peak: 0, current: 0 };
                    #[cfg(feature = "mi-stat-2")]
                    let requested = (now.malloc_requested, old.malloc_requested);
                    #[cfg(not(feature = "mi-stat-2"))]
                    let requested = (zero, zero);
                    #[cfg(feature = "mi-stat-1")]
                    let normal = (now.malloc_normal, old.malloc_normal);
                    #[cfg(not(feature = "mi-stat-1"))]
                    let normal = (zero, zero);
                    for (name, value, prior) in [
                        ("pages", now.pages, old.pages),
                        ("page_committed", now.page_committed, old.page_committed),
                        ("reserved", now.reserved, old.reserved),
                        ("committed", now.committed, old.committed),
                        ("requested", requested.0, requested.1),
                        ("normal", normal.0, normal.1),
                    ] {
                        std::println!("{stage}.{name}={},{},{}",
                            value.total - prior.total, value.peak - prior.peak,
                            value.current - prior.current);
                    }
                    #[cfg(feature = "mi-stat-2")]
                    for (index, (current, previous)) in now.malloc_bins.iter()
                        .zip(old.malloc_bins.iter()).enumerate()
                    {
                        if current.total > previous.total {
                            std::println!("{stage}.bin={index}:{},{},{}",
                                current.total - previous.total,
                                current.peak - previous.peak,
                                current.current - previous.current);
                        }
                    }
                    for (index, (current, previous)) in bins.page_bin_total.iter()
                        .zip(before.1.page_bin_total.iter()).enumerate()
                    {
                        if current > previous {
                            std::println!("{stage}.page_bin={index}:{},{}",
                                current - previous,
                                bins.page_bin_current[index] - before.1.page_bin_current[index]);
                        }
                    }
                    std::println!("{stage}.commit_calls={}", now.commit_calls - old.commit_calls);
                    std::println!("{stage}.warnings={}", WARNINGS.load(Ordering::Relaxed));
                    std::println!("{stage}.failures={failures}");
                }

                // SAFETY: the FILE callback remains valid for this fresh process.
                assert!(runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { RuntimeStderrOutput::new(source_stderr) },
                ));
                crate::source_options_api::option_set(SourceOption::PageCommitOnDemand as c_int, 1);
                crate::source_options_api::option_set(SourceOption::ArenaEagerCommit as c_int, 0);
                crate::source_options_api::option_set(SourceOption::ShowErrors as c_int, 1);
                // SAFETY: the static callback and null context remain valid until process exit.
                unsafe { crate::source_options_api::register_output(Some(capture_warning), core::ptr::null_mut()) };
                if matrix {
                    crate::source_options_api::option_set(SourceOption::GuardedSampleRate as c_int, 0);
                    let theap = crate::source_heap_api::theap_get_default();
                    assert!(!theap.is_null());
                    // SAFETY: this fresh thread exclusively retains its initialized Theap.
                    unsafe { crate::source_heap_api::theap_guarded_set_sample_rate(theap, 0, 0) };
                }
                let warm = match runtime_lifecycle::native_allocate(64, false) {
                    NativePageAllocationResult::Allocated(pointer) => pointer,
                    _ => panic!("arena warmup allocation failed"),
                };
                // SAFETY: the warmed allocation is live and locally owned.
                assert_eq!(unsafe { runtime_lifecycle::native_free(warm) }, NativePageFreeResult::Freed);
                let before = stats();
                std::println!("CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_BEGIN");
                std::println!("profile.level={}", crate::config::STAT_LEVEL);
                if matrix {
                    std::println!("profile.debug={}", crate::config::DEBUG_LEVEL);
                    std::println!("profile.guarded={}", usize::from(crate::config::GUARDED));
                    std::println!("profile.faulted={}", usize::from(faulted));
                    std::println!("profile.sample_rate={}", crate::source_options_api::option_get(SourceOption::GuardedSampleRate as c_int));
                    #[cfg(feature = "mi-guarded")]
                    {
                        let theap = core::ptr::NonNull::new(crate::source_heap_api::theap_get_default().cast::<crate::types::Theap>()).unwrap();
                        // SAFETY: no allocation or rate change overlaps this local owner's scalar read.
                        std::println!("profile.theap_sample_rate={}", unsafe { crate::types::Theap::guarded_sample_rate_at(theap) });
                    }
                }
                std::println!("profile.on_demand={}",
                    crate::source_options_api::option_get(SourceOption::PageCommitOnDemand as c_int));
                std::println!("profile.eager_arena={}",
                    crate::source_options_api::option_get(SourceOption::ArenaEagerCommit as c_int));
                std::println!("profile.show_errors={}",
                    crate::source_options_api::option_get(SourceOption::ShowErrors as c_int));
                show("before", before, 0);
                let fault = fault::install(fault::Plan::at(fault::Point::Commit, if faulted { 1 } else { usize::MAX }, crabc_core::Errno::NOMEM));
                let protections = fault.capture_protection_ranges();
                let block = match runtime_lifecycle::native_allocate(100000, false) {
                    NativePageAllocationResult::Allocated(pointer) => Some(pointer),
                    _ => None,
                };
                std::println!("fault.nonnull={}", usize::from(block.is_some()));
                let (ranges, count) = protections.attempts().expect("bounded raw protect capture");
                assert!(count >= if faulted { 2 } else { 1 }, "the selected initial commit must reach the kernel or retry");
                std::println!("fault.commit_size={}", ranges[0].1);
                assert!(fault.observed() >= if faulted { 2 } else { 1 }, "the selected first commit must be observed");
                if matrix {
                    let pointer = block.expect("live client after initial commit");
                    // SAFETY: this client exclusively owns its requested writable prefix.
                    unsafe { core::ptr::write_bytes(pointer.as_ptr(), 0x35, 100000) };
                }
                show("fault", before, usize::from(faulted));
                let recovered = match runtime_lifecycle::native_allocate(100000, false) {
                    NativePageAllocationResult::Allocated(pointer) => Some(pointer),
                    _ => None,
                };
                std::println!("recovery.nonnull={}", usize::from(recovered.is_some()));
                if matrix {
                    let first = block.unwrap();
                    let second = recovered.expect("live recovery client");
                    // SAFETY: both distinct clients remain live until the frees below; all
                    // reads and writes stay inside their requested 100000-byte prefixes.
                    let (bytes, owned) = unsafe {
                        assert!(runtime_lifecycle::native_usable_size(first).unwrap() >= 100000);
                        assert!(runtime_lifecycle::native_usable_size(second).unwrap() >= 100000);
                        core::ptr::write_bytes(second.as_ptr(), 0xb7, 100000);
                        let bytes = core::slice::from_raw_parts(first.as_ptr(), 100000).iter().all(|byte| *byte == 0x35)
                            && core::slice::from_raw_parts(second.as_ptr(), 100000).iter().all(|byte| *byte == 0xb7);
                        let main = crate::source_heap_api::heap_main();
                        (bytes, crate::source_api::check_owned(first.as_ptr()) && crate::source_api::check_owned(second.as_ptr())
                            && crate::source_heap_api::heap_contains(main, first.as_ptr())
                            && crate::source_heap_api::heap_contains(main, second.as_ptr()))
                    };
                    std::println!("recovery.client_bytes={}", usize::from(bytes));
                    std::println!("recovery.clients_distinct={}", usize::from(first.as_ptr().addr().abs_diff(second.as_ptr().addr()) >= 100000));
                    std::println!("recovery.clients_owned={}", usize::from(owned));
                }
                show("recovery", before, usize::from(faulted));
                for pointer in [block, recovered].into_iter().flatten() {
                    // SAFETY: each distinct allocation remains live and locally owned.
                    assert_eq!(unsafe { runtime_lifecycle::native_free(pointer) }, NativePageFreeResult::Freed);
                }
                show("freed", before, usize::from(faulted));
                std::println!("CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_END");
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-stat-2"))]
    #[test]
    fn failed_os_page_release_preserves_source_statistics() {
        crate::test_process::run_in_fresh_process(
            "page::tests::failed_os_page_release_preserves_source_statistics",
            || {
                use core::ffi::{c_char, c_int, c_void};
                use core::sync::atomic::{AtomicUsize, Ordering};
                use crate::config::SourceOption;
                use crate::diagnostic_output::RuntimeStderrOutput;
                use crate::os::fault;
                use crate::runtime_lifecycle::{self, NativePageAllocationResult};
                use crate::statistics::{FinalStatisticsSnapshot, HeapTheapStatistics};

                unsafe extern "C" {
                    static mut stderr: *mut c_void;
                    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
                }

                static WARNINGS: AtomicUsize = AtomicUsize::new(0);

                unsafe extern "C" fn source_stderr(message: *const c_char) {
                    // SAFETY: the process-lifetime FILE is a valid destination
                    // for the NUL-terminated output fragment.
                    unsafe { let _ = fputs(message, stderr); }
                }

                unsafe extern "C" fn capture_warning(message: *const c_char, _: *mut c_void) {
                    // SAFETY: the registered output callback receives a live
                    // NUL-terminated fragment for the duration of this call.
                    let bytes = unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes();
                    if bytes.windows(b"unable to free OS memory".len())
                        .any(|window| window == b"unable to free OS memory")
                    {
                        WARNINGS.fetch_add(1, Ordering::Relaxed);
                    }
                }

                fn stats() -> (FinalStatisticsSnapshot, crate::statistics::HeapTheapStatisticsSnapshot) {
                    let mut image = HeapTheapStatistics::new();
                    // SAFETY: the local image has the source header and is
                    // exclusively mutable during this snapshot.
                    assert!(unsafe { runtime_lifecycle::native_stats_get(core::ptr::from_mut(&mut image).cast()) });
                    (image.final_output_snapshot(), image.snapshot())
                }

                fn show(stage: &str, before: (FinalStatisticsSnapshot, crate::statistics::HeapTheapStatisticsSnapshot), failures: usize) {
                    let (now, bins) = stats();
                    let old = before.0;
                    std::println!("{stage}.pages={},{},{}", now.pages.total - old.pages.total,
                        now.pages.peak - old.pages.peak, now.pages.current - old.pages.current);
                    std::println!("{stage}.reserved={},{},{}", now.reserved.total - old.reserved.total,
                        now.reserved.peak - old.reserved.peak, now.reserved.current - old.reserved.current);
                    std::println!("{stage}.committed={},{},{}", now.committed.total - old.committed.total,
                        now.committed.peak - old.committed.peak, now.committed.current - old.committed.current);
                    std::println!("{stage}.normal={},{},{}", now.malloc_normal.total - old.malloc_normal.total,
                        now.malloc_normal.peak - old.malloc_normal.peak, now.malloc_normal.current - old.malloc_normal.current);
                    for (index, (current, previous)) in bins.page_bin_total.iter()
                        .zip(before.1.page_bin_total.iter()).enumerate()
                    {
                        if current > previous {
                            std::println!("{stage}.page_bin={index}:{},{}", current - previous,
                                bins.page_bin_current[index] - before.1.page_bin_current[index]);
                        }
                    }
                    std::println!("{stage}.warnings={}", WARNINGS.load(Ordering::Relaxed));
                    std::println!("{stage}.failures={failures}");
                }

                // SAFETY: the callback remains valid through process exit.
                assert!(runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { RuntimeStderrOutput::new(source_stderr) },
                ));
                crate::source_options_api::option_set(SourceOption::DisallowArenaAlloc as c_int, 1);
                crate::source_options_api::option_set(SourceOption::ShowErrors as c_int, 1);
                // SAFETY: the static callback and null context remain valid
                // until this fresh process exits.
                unsafe { crate::source_options_api::register_output(Some(capture_warning), core::ptr::null_mut()) };
                let warm = match runtime_lifecycle::native_allocate(100000, false) {
                    NativePageAllocationResult::Allocated(pointer) => pointer,
                    _ => panic!("OS-backed warm allocation failed"),
                };
                // SAFETY: the warmed allocation remains live and local.
                assert_eq!(unsafe { runtime_lifecycle::native_free(warm) }, runtime_lifecycle::NativePageFreeResult::Freed);
                runtime_lifecycle::native_collect(true);
                let before = stats();
                let block = match runtime_lifecycle::native_allocate(100000, false) {
                    NativePageAllocationResult::Allocated(pointer) => pointer,
                    _ => panic!("OS-backed large allocation failed"),
                };
                std::println!("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_BEGIN");
                std::println!("profile.level=2");
                std::println!("profile.disallow_arena={}",
                    crate::source_options_api::option_get(SourceOption::DisallowArenaAlloc as c_int));
                show("allocated", before, 0);
                // SAFETY: this exact live local allocation is consumed once;
                // collection later releases its retired page.
                let free_result = unsafe { runtime_lifecycle::native_free(block) };
                show("freed", before, 0);
                let fault = fault::install(fault::Plan::at(fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                let unmaps = fault.capture_unmap_ranges();
                runtime_lifecycle::native_collect(true);
                assert_eq!(fault.observed(), 1, "the page release reached the raw unmap");
                let (ranges, count) = unmaps.all().expect("bounded raw unmap capture");
                assert!(count > 0 && ranges[0].0 <= block.as_ptr().addr()
                    && block.as_ptr().addr() - ranges[0].0 < ranges[0].1,
                    "the failed unmap must contain the released page");
                show("failed_release", before, 1);
                std::println!("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_END");
                std::println!("release.retained={}", usize::from(free_result == runtime_lifecycle::NativePageFreeResult::Retained));
            },
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn failed_regular_page_release_preserves_source_statistics() {
        crate::test_process::run_in_fresh_process(
            "page::tests::failed_regular_page_release_preserves_source_statistics",
            || {
                use core::ffi::{c_char, c_int, c_void};
                use core::sync::atomic::{AtomicUsize, Ordering};
                use crate::config::SourceOption;
                use crate::diagnostic_output::RuntimeStderrOutput;
                use crate::os::fault;
                use crate::runtime_lifecycle::{self, NativePageAllocationResult};
                use crate::statistics::{FinalStatisticsSnapshot, HeapTheapStatistics};

                unsafe extern "C" {
                    static mut stderr: *mut c_void;
                    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
                }

                static WARNINGS: AtomicUsize = AtomicUsize::new(0);

                unsafe extern "C" fn source_stderr(message: *const c_char) {
                    // SAFETY: the process-lifetime FILE is a valid destination
                    // for the NUL-terminated output fragment.
                    unsafe { let _ = fputs(message, stderr); }
                }

                unsafe extern "C" fn capture_warning(message: *const c_char, _: *mut c_void) {
                    // SAFETY: the registered output callback receives a live
                    // NUL-terminated fragment for the duration of this call.
                    let bytes = unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes();
                    if bytes.windows(b"unable to free OS memory".len())
                        .any(|window| window == b"unable to free OS memory")
                    {
                        WARNINGS.fetch_add(1, Ordering::Relaxed);
                    }
                }

                fn stats() -> (FinalStatisticsSnapshot, crate::statistics::HeapTheapStatisticsSnapshot, PageFaultAllocationSnapshot) {
                    let mut image = HeapTheapStatistics::new();
                    // SAFETY: the local image has the source header and is
                    // exclusively mutable during this snapshot.
                    assert!(unsafe { runtime_lifecycle::native_stats_get(core::ptr::from_mut(&mut image).cast()) });
                    (image.final_output_snapshot(), image.snapshot(), page_fault_allocation_snapshot(&image))
                }

                fn show(stage: &str, before: (FinalStatisticsSnapshot, crate::statistics::HeapTheapStatisticsSnapshot, PageFaultAllocationSnapshot), failures: usize) {
                    let (now, bins, allocation) = stats();
                    let old = before.0;
                    std::println!("{stage}.pages={},{},{}", now.pages.total - old.pages.total,
                        now.pages.peak - old.pages.peak, now.pages.current - old.pages.current);
                    std::println!("{stage}.reserved={},{},{}", now.reserved.total - old.reserved.total,
                        now.reserved.peak - old.reserved.peak, now.reserved.current - old.reserved.current);
                    std::println!("{stage}.committed={},{},{}", now.committed.total - old.committed.total,
                        now.committed.peak - old.committed.peak, now.committed.current - old.committed.current);
                    std::println!("{stage}.normal={},{},{}", allocation.malloc_normal.total - before.2.malloc_normal.total,
                        allocation.malloc_normal.peak - before.2.malloc_normal.peak, allocation.malloc_normal.current - before.2.malloc_normal.current);
                    for (index, (current, previous)) in bins.page_bin_total.iter()
                        .zip(before.1.page_bin_total.iter()).enumerate()
                    {
                        if current > previous {
                            std::println!("{stage}.page_bin={index}:{},{}", current - previous,
                                bins.page_bin_current[index] - before.1.page_bin_current[index]);
                        }
                    }
                    std::println!("{stage}.warnings={}", WARNINGS.load(Ordering::Relaxed));
                    std::println!("{stage}.failures={failures}");
                }

                // SAFETY: the callback remains valid through process exit.
                assert!(runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { RuntimeStderrOutput::new(source_stderr) },
                ));
                crate::source_options_api::option_set(SourceOption::DisallowArenaAlloc as c_int, 1);
                crate::source_options_api::option_set(SourceOption::ShowErrors as c_int, 1);
                // SAFETY: the static callback and null context remain valid
                // until this fresh process exits.
                unsafe { crate::source_options_api::register_output(Some(capture_warning), core::ptr::null_mut()) };
                let warm = match runtime_lifecycle::native_allocate(64, false) {
                    NativePageAllocationResult::Allocated(pointer) => pointer,
                    _ => panic!("OS-backed regular warm allocation failed"),
                };
                // SAFETY: the warmed allocation remains live and local.
                assert_eq!(unsafe { runtime_lifecycle::native_free(warm) }, runtime_lifecycle::NativePageFreeResult::Freed);
                runtime_lifecycle::native_collect(true);
                let matrix = std::env::var_os("CRABC_MI_STATISTICS_MATRIX").is_some();
                let faulted = std::env::var_os("CRABC_MI_STATISTICS_FAULT_CONTROL") != Some(std::ffi::OsString::from("success"));
                let guarded_matrix = matrix && crate::config::GUARDED;
                let survivor = guarded_matrix.then(|| {
                    let pointer = match runtime_lifecycle::native_allocate(128, false) {
                        NativePageAllocationResult::Allocated(pointer) => pointer,
                        _ => panic!("independent live regular client allocation failed"),
                    };
                    // SAFETY: this live allocation owns its requested span,
                    // independent of the page selected for release below.
                    unsafe { pointer.as_ptr().write_bytes(0x5a, 128) };
                    pointer
                });
                let before = stats();
                let block = match runtime_lifecycle::native_allocate(64, false) {
                    NativePageAllocationResult::Allocated(pointer) => pointer,
                    _ => panic!("OS-backed regular allocation failed"),
                };
                std::println!("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_BEGIN");
                std::println!("profile.level={}", crate::config::STAT_LEVEL);
                if matrix {
                    std::println!("profile.debug={}", crate::config::DEBUG_LEVEL);
                    std::println!("profile.faulted={}", usize::from(faulted));
                    // SAFETY: the exact live local allocation is read without
                    // a concurrent free or page metadata mutation.
                    std::println!("allocation.usable={}", unsafe { runtime_lifecycle::native_usable_size(block) }.expect("live regular usable size"));
                    // SAFETY: the same exact live client retains its page
                    // while the independent scalar reports physical block size.
                    std::println!("geometry.block_size={}", unsafe { runtime_lifecycle::native_block_size(block) }.expect("live regular physical block size"));
                }
                if guarded_matrix {
                    std::println!("profile.guarded={}", usize::from(crate::config::GUARDED));
                    std::println!("profile.guarded_sample_rate={}", crate::source_options_api::option_get(SourceOption::GuardedSampleRate as c_int));
                    #[cfg(feature = "mi-guarded")]
                    {
                        // SAFETY: allocation initialized this thread's default
                        // Theap and no sampler mutation overlaps this read.
                        let rate = unsafe { crate::types::Theap::guarded_sample_rate_at(crate::compiler_tls::default_theap()) };
                        assert_eq!(rate, 0);
                        std::println!("profile.theap_guarded_sample_rate={rate}");
                    }
                    #[cfg(feature = "native-runtime-test-audit")]
                    {
                        // SAFETY: this exact live client keeps its immutable
                        // memid registered throughout the quiescent sample.
                        let kind = unsafe { runtime_lifecycle::native_runtime_live_client_memory_kind_test_audit(block) }.unwrap();
                        assert_eq!(kind, 3);
                        std::println!("allocation.os_backed={}", usize::from(kind == 3));
                    }
                    // SAFETY: the still-live target owns 64 requested bytes;
                    // these bytes are observed only before consuming its free.
                    unsafe { block.as_ptr().write_bytes(0xa5, 64) };
                    let intact = unsafe { core::slice::from_raw_parts(block.as_ptr(), 64) }.iter().all(|byte| *byte == 0xa5);
                    assert!(intact);
                    std::println!("allocated.client_bytes={}", usize::from(intact));
                }
                std::println!("profile.disallow_arena={}",
                    crate::source_options_api::option_get(SourceOption::DisallowArenaAlloc as c_int));
                show("allocated", before, 0);
                // SAFETY: this exact live local allocation is consumed once;
                // collection later releases its retired page.
                let free_result = unsafe { runtime_lifecycle::native_free(block) };
                show("freed", before, 0);
                let fault = fault::install(fault::Plan::at(fault::Point::Unmap, if faulted { 1 } else { usize::MAX }, crabc_core::Errno::NOMEM));
                if guarded_matrix { assert_eq!(free_result, runtime_lifecycle::NativePageFreeResult::Freed); }
                let unmaps = fault.capture_unmap_ranges();
                runtime_lifecycle::native_collect(true);
                assert_eq!(fault.observed(), 1, "the page release reached the raw unmap");
                let (ranges, count) = unmaps.all().expect("bounded raw unmap capture");
                assert_eq!(count, 1);
                assert!(ranges[0].0 <= block.as_ptr().addr()
                        && block.as_ptr().addr() - ranges[0].0 < ranges[0].1,
                        "the captured OS release must contain the consumed client");
                show("failed_release", before, usize::from(faulted));
                if let Some(survivor) = survivor {
                    let mapping_present = || {
                        let (base, length) = ranges[0];
                        assert!(base != 0 && length != 0 && base % 4096 == 0 && length % 4096 == 0);
                        for offset in (0..length).step_by(4096) {
                            let mut residency = 0;
                            // SAFETY: mincore samples the captured OS extent
                            // without borrowing retired Page or client storage.
                            let result = unsafe { crabc_core::mm::mincore_raw((base + offset) as *mut u8, 4096, &mut residency) };
                            assert!(result.is_ok() || result == Err(crabc_core::Errno::NOMEM));
                            assert_eq!(result.is_ok(), faulted);
                        }
                        usize::from(faulted)
                    };
                    let survivor_bytes = || {
                        // SAFETY: this independent live client still owns its
                        // requested span throughout collection and recovery.
                        unsafe { core::slice::from_raw_parts(survivor.as_ptr(), 128) }.iter().all(|byte| *byte == 0x5a)
                    };
                    std::println!("failed_release.mapping_present={}", mapping_present());
                    assert!(survivor_bytes());
                    std::println!("failed_release.survivor_bytes=1");
                    let released = stats().0;
                    runtime_lifecycle::native_collect(true);
                    let recollected = stats().0;
                    let unchanged = released.pages == recollected.pages && released.reserved == recollected.reserved && released.committed == recollected.committed;
                    assert!(unchanged);
                    assert_eq!(unmaps.all().unwrap().1, 1);
                    assert_eq!(fault.observed(), 1);
                    std::println!("recollect.no_unmap=1");
                    std::println!("recollect.mapping_present={}", mapping_present());
                    assert!(survivor_bytes());
                    std::println!("recollect.survivor_bytes=1");
                    std::println!("recollect.counters_unchanged={}", usize::from(unchanged));
                    let recovery = match runtime_lifecycle::native_allocate(64, false) {
                        NativePageAllocationResult::Allocated(pointer) => pointer,
                        _ => panic!("fresh regular allocation after release failed"),
                    };
                    // SAFETY: this distinct new live allocation owns its
                    // requested bytes; the consumed target is never accessed.
                    unsafe { recovery.as_ptr().write_bytes(0x3c, 64) };
                    let intact = unsafe { core::slice::from_raw_parts(recovery.as_ptr(), 64) }.iter().all(|byte| *byte == 0x3c);
                    assert!(intact && survivor_bytes() && recovery != survivor);
                    std::println!("recovery.nonnull=1");
                    std::println!("recovery.distinct_from_survivor=1");
                    std::println!("recovery.client_bytes=1");
                    std::println!("recovery.survivor_bytes=1");
                    // SAFETY: these distinct live local clients are each
                    // consumed exactly once after the final observations.
                    assert_eq!(unsafe { runtime_lifecycle::native_free(recovery) }, runtime_lifecycle::NativePageFreeResult::Freed);
                    assert_eq!(unsafe { runtime_lifecycle::native_free(survivor) }, runtime_lifecycle::NativePageFreeResult::Freed);
                    if faulted {
                        // SAFETY: the source consumed its page registration
                        // and left this exact captured range mapped. No client
                        // or Page capability survives; this is fixture cleanup.
                        unsafe { crabc_core::mm::munmap_raw(ranges[0].0 as *mut u8, ranges[0].1) }.unwrap();
                    }
                }
                std::println!("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_END");
                std::println!("release.retained={}", usize::from(free_result == runtime_lifecycle::NativePageFreeResult::Retained));
            },
        );
    }
}
