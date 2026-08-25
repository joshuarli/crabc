// Copyright (c) 2018-2024, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
//
// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page-queue.c:64-121`
// (`mi_bin`, `_mi_bin`, `_mi_bin_size`, and `mi_good_size`),
// `include/mimalloc/internal.h:503-623` (`mi_alignment_is_valid`,
// `_mi_wsize_from_size`, and `mi_count_size_overflow`), and
// `src/arena.c:1183-1208` (regular-page versus singleton object-size
// transitions). The Rust `Option` results make C assertion preconditions and
// overflow outcomes explicit; this private module exposes no allocator
// operation or public API.

use crate::bits;
use crate::config::{
    BIN_HUGE, LARGE_MAX_OBJ_SIZE, LARGE_MAX_OBJ_WSIZE, MAX_ALLOC_SIZE,
    MEDIUM_MAX_OBJ_SIZE, PADDING_SIZE, PAGE_MAX_OVERALLOC_ALIGN, SMALL_MAX_OBJ_SIZE,
};
use crate::invariants;
use crate::types::{PageKind, BIN_BLOCK_SIZES};

/// Port of `mi_alignment_is_valid`.
///
/// `0` remains invalid even though upstream's lower-level
/// `_mi_is_power_of_two` treats it as a power of two.
#[inline]
pub(crate) const fn alignment_is_valid(alignment: usize) -> bool {
    alignment != 0 && invariants::is_power_of_two(alignment)
}

/// Port of `mi_count_size_overflow` as an explicit checked product.
///
/// Upstream writes `SIZE_MAX` and returns `true` on overflow. `None` carries
/// that same rejected-request outcome without introducing an allocator error
/// channel into this errno-free engine layer.
#[inline]
pub(crate) const fn count_size(count: usize, size: usize) -> Option<usize> {
    if count == 1 {
        Some(size)
    } else {
        count.checked_mul(size)
    }
}

/// Port of `_mi_wsize_from_size`.
///
/// The C helper asserts that adding one machine word cannot overflow. `None`
/// represents a caller that violates that precondition.
#[inline]
pub(crate) const fn wsize_from_size(size: usize) -> Option<usize> {
    invariants::word_count(size)
}

/// Port of `src/page-queue.c:mi_bin` for the frozen default Linux 64-bit profiles.
///
/// The profile has `MI_ALIGN2W`, so word sizes through eight use their direct
/// queue number. Larger regular sizes use mimalloc's three high-bit size-class
/// selection; sizes above `MI_LARGE_MAX_OBJ_WSIZE` use the huge queue.
#[inline]
pub(crate) const fn bin(size: usize) -> Option<usize> {
    let mut wsize = match wsize_from_size(size) {
        Some(value) => value,
        None => return None,
    };

    if wsize <= 8 {
        return Some(if wsize <= 1 { 1 } else { (wsize + 1) & !1 });
    }
    if wsize > LARGE_MAX_OBJ_WSIZE {
        return Some(BIN_HUGE);
    }

    wsize -= 1;
    let highest_bit = usize::BITS as usize - 1 - bits::clz(wsize);
    let bin = ((highest_bit << 2) + ((wsize >> (highest_bit - 2)) & 0x03)) - 3;
    Some(bin)
}

/// Port of `_mi_bin_size`.
///
/// The C helper asserts `bin <= MI_BIN_HUGE`; `None` makes the same bound
/// explicit and intentionally excludes the full-page sentinel queue.
#[inline]
pub(crate) const fn bin_size(bin: usize) -> Option<usize> {
    if bin <= BIN_HUGE {
        Some(BIN_BLOCK_SIZES[bin])
    } else {
        None
    }
}

/// Port of `mi_good_size` for a validated selected Linux-profile OS page size.
///
/// The pinned default has no padding. The expression remains written in terms
/// of `PADDING_SIZE` so its source invariant stays visible: small objects use
/// their queue block size, larger valid requests round to the supplied OS page
/// size, and requests above `MI_MAX_ALLOC_SIZE` are returned unchanged.
#[inline]
pub(crate) const fn good_size(size: usize, os_page_size: usize) -> Option<usize> {
    if size <= LARGE_MAX_OBJ_SIZE - PADDING_SIZE {
        let padded_size = size + PADDING_SIZE;
        let bin = match bin(padded_size) {
            Some(value) => value,
            None => return None,
        };
        return bin_size(bin);
    }
    if size <= MAX_ALLOC_SIZE - PADDING_SIZE {
        if !alignment_is_valid(os_page_size) {
            return None;
        }
        return invariants::align_up(size + PADDING_SIZE, os_page_size);
    }
    Some(size)
}

/// The request bound checked by `src/page.c:mi_find_page` before allocating.
#[inline]
pub(crate) const fn request_size_is_valid(size: usize) -> bool {
    size <= MAX_ALLOC_SIZE
}

/// Port of the default-profile size branches in `_mi_arenas_page_alloc`.
///
/// A zero block size cannot initialize a page; C reaches a later division by
/// that value only under an internal allocator invariant, so the Rust boundary
/// rejects it eagerly. The default profile enables large pages.
#[inline]
pub(crate) const fn page_kind_for_block_size(block_size: usize) -> Option<PageKind> {
    if block_size == 0 {
        None
    } else if block_size <= SMALL_MAX_OBJ_SIZE {
        Some(PageKind::Small)
    } else if block_size <= MEDIUM_MAX_OBJ_SIZE {
        Some(PageKind::Medium)
    } else if block_size <= LARGE_MAX_OBJ_SIZE {
        Some(PageKind::Large)
    } else {
        Some(PageKind::Singleton)
    }
}

/// Port of the alignment-first selection in `_mi_arenas_page_alloc`.
///
/// Alignments through `MI_PAGE_MAX_OVERALLOC_ALIGN` retain ordinary size
/// selection. Larger power-of-two alignments force a singleton page; larger
/// non-power-of-two values violate the upstream caller assertion.
#[inline]
pub(crate) const fn page_kind_for_request(
    block_size: usize,
    block_alignment: usize,
) -> Option<PageKind> {
    if block_size == 0 {
        return None;
    }
    if block_alignment > PAGE_MAX_OVERALLOC_ALIGN {
        return if invariants::is_power_of_two(block_alignment) {
            Some(PageKind::Singleton)
        } else {
            None
        };
    }
    page_kind_for_block_size(block_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BIN_COUNT, BIN_FULL, BIN_HUGE, LARGE_MAX_OBJ_SIZE, LARGE_MAX_OBJ_WSIZE,
        MAX_ALLOC_SIZE, MAX_SINGLETON_BIN, MEDIUM_MAX_OBJ_SIZE, SMALL_MAX_OBJ_SIZE,
        WORD_SIZE,
    };
    use crate::types::{PageKind, BIN_BLOCK_SIZES};

    fn reference_wsize_from_size(size: usize) -> Option<usize> {
        if size > usize::MAX - (WORD_SIZE - 1) {
            return None;
        }
        Some((size / WORD_SIZE) + usize::from(size % WORD_SIZE != 0))
    }

    fn reference_bin(size: usize) -> Option<usize> {
        let wsize = reference_wsize_from_size(size)?;
        if wsize <= 8 {
            return Some(if wsize <= 1 { 1 } else { (wsize + 1) & !1 });
        }
        if wsize > LARGE_MAX_OBJ_WSIZE {
            return Some(BIN_HUGE);
        }

        let rounded_size = wsize * WORD_SIZE;
        for bin in 1..=MAX_SINGLETON_BIN {
            if BIN_BLOCK_SIZES[bin] >= rounded_size {
                return Some(bin);
            }
        }
        unreachable!("the frozen queue table covers every regular word size");
    }

    fn reference_good_size(size: usize, os_page_size: usize) -> Option<usize> {
        if size <= LARGE_MAX_OBJ_SIZE {
            return Some(BIN_BLOCK_SIZES[reference_bin(size)?]);
        }
        if size <= MAX_ALLOC_SIZE {
            let remainder = size % os_page_size;
            return Some(if remainder == 0 {
                size
            } else {
                size + (os_page_size - remainder)
            });
        }
        Some(size)
    }

    #[test]
    fn alignment_and_count_validation_reject_only_the_upstream_invalid_cases() {
        for alignment in [1, 2, 4, 8, 16, 64, 4096, 16 * 1024, 64 * 1024] {
            assert!(alignment_is_valid(alignment));
        }
        for alignment in [0, 3, 6, 12, usize::MAX] {
            assert!(!alignment_is_valid(alignment));
        }

        assert_eq!(count_size(0, usize::MAX), Some(0));
        assert_eq!(count_size(1, usize::MAX), Some(usize::MAX));
        assert_eq!(count_size(2, usize::MAX), None);
        assert_eq!(count_size(usize::MAX, 2), None);
        assert_eq!(count_size(usize::MAX / 2, 2), Some(usize::MAX - 1));
    }

    #[test]
    fn default_linux_64_two_word_alignment_skips_odd_small_bins() {
        assert_eq!(bin(2 * WORD_SIZE), Some(2));
        assert_eq!(bin(2 * WORD_SIZE + 1), Some(4));
        assert_eq!(bin(3 * WORD_SIZE), Some(4));
        assert_eq!(bin(4 * WORD_SIZE + 1), Some(6));
        assert_eq!(bin(7 * WORD_SIZE), Some(8));
    }

    #[test]
    fn word_size_rounding_covers_each_word_boundary_and_size_edges() {
        for word in 0..=LARGE_MAX_OBJ_WSIZE + 1 {
            let first = word * WORD_SIZE;
            for size in [first.saturating_sub(1), first, first + 1] {
                assert_eq!(wsize_from_size(size), reference_wsize_from_size(size));
            }
        }

        assert_eq!(wsize_from_size(usize::MAX - (WORD_SIZE - 1)), Some(usize::MAX / WORD_SIZE));
        assert_eq!(wsize_from_size(usize::MAX - (WORD_SIZE - 2)), None);
        assert_eq!(wsize_from_size(usize::MAX), None);
    }

    #[test]
    fn every_queue_boundary_matches_an_independent_size_table_reference() {
        for (queue, &boundary) in BIN_BLOCK_SIZES.iter().enumerate() {
            for size in [boundary.saturating_sub(1), boundary, boundary + 1] {
                assert_eq!(bin(size), reference_bin(size), "queue {queue}, size {size}");
            }
        }

        for size in 0..=(LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE {
            assert_eq!(bin(size), reference_bin(size), "size {size}");
        }

        for bin_index in 0..=BIN_HUGE {
            assert_eq!(bin_size(bin_index), Some(BIN_BLOCK_SIZES[bin_index]));
        }
        assert_eq!(bin_size(BIN_FULL), None);
        assert_eq!(bin_size(BIN_COUNT), None);

        for size in [
            MAX_ALLOC_SIZE.saturating_sub(1),
            MAX_ALLOC_SIZE,
            MAX_ALLOC_SIZE + 1,
            usize::MAX - (WORD_SIZE - 1),
            usize::MAX - (WORD_SIZE - 2),
            usize::MAX,
        ] {
            assert_eq!(bin(size), reference_bin(size), "size edge {size}");
        }
    }

    #[test]
    fn default_profile_leaves_only_the_source_defined_queue_bins_reachable() {
        let mut reachable = [false; BIN_COUNT];
        for size in 0..=(LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE {
            reachable[bin(size).unwrap()] = true;
        }

        assert!(!reachable[0]);
        for bin_index in 1..=MAX_SINGLETON_BIN {
            let expected = !matches!(bin_index, 3 | 5 | 7);
            assert_eq!(reachable[bin_index], expected, "regular bin {bin_index}");
        }
        for bin_index in (MAX_SINGLETON_BIN + 1)..BIN_HUGE {
            assert!(!reachable[bin_index], "inactive queue bin {bin_index}");
        }
        assert!(reachable[BIN_HUGE]);
        assert!(!reachable[BIN_FULL]);
    }

    #[test]
    fn good_size_tracks_regular_bin_and_huge_os_page_transitions() {
        for os_page_size in [4096, 16 * 1024, 64 * 1024] {
            for (queue, &boundary) in BIN_BLOCK_SIZES.iter().enumerate() {
                if boundary > LARGE_MAX_OBJ_SIZE {
                    continue;
                }
                for size in [boundary.saturating_sub(1), boundary, boundary + 1] {
                    assert_eq!(
                        good_size(size, os_page_size),
                        reference_good_size(size, os_page_size),
                        "queue {queue}, page size {os_page_size}, size {size}",
                    );
                }
            }
            for size in [
                LARGE_MAX_OBJ_SIZE.saturating_sub(1),
                LARGE_MAX_OBJ_SIZE,
                LARGE_MAX_OBJ_SIZE + 1,
                MAX_ALLOC_SIZE.saturating_sub(1),
                MAX_ALLOC_SIZE,
                MAX_ALLOC_SIZE + 1,
                usize::MAX,
            ] {
                assert_eq!(good_size(size, os_page_size), reference_good_size(size, os_page_size));
            }
        }

        assert_eq!(good_size(LARGE_MAX_OBJ_SIZE + 1, 0), None);
        assert_eq!(good_size(LARGE_MAX_OBJ_SIZE + 1, 3), None);
        assert_eq!(good_size(usize::MAX, 0), Some(usize::MAX));
    }

    #[test]
    fn request_limit_and_regular_page_kind_transitions_match_arena_selection() {
        for size in [
            0,
            1,
            MAX_ALLOC_SIZE.saturating_sub(1),
            MAX_ALLOC_SIZE,
        ] {
            assert!(request_size_is_valid(size));
        }
        assert!(!request_size_is_valid(MAX_ALLOC_SIZE + 1));
        assert!(!request_size_is_valid(usize::MAX));

        for (boundary, expected) in [
            (SMALL_MAX_OBJ_SIZE, PageKind::Small),
            (MEDIUM_MAX_OBJ_SIZE, PageKind::Medium),
            (LARGE_MAX_OBJ_SIZE, PageKind::Large),
        ] {
            assert_eq!(page_kind_for_block_size(boundary.saturating_sub(1)), Some(expected));
            assert_eq!(page_kind_for_block_size(boundary), Some(expected));
        }
        assert_eq!(page_kind_for_block_size(SMALL_MAX_OBJ_SIZE + 1), Some(PageKind::Medium));
        assert_eq!(page_kind_for_block_size(MEDIUM_MAX_OBJ_SIZE + 1), Some(PageKind::Large));
        assert_eq!(page_kind_for_block_size(LARGE_MAX_OBJ_SIZE + 1), Some(PageKind::Singleton));
        assert_eq!(page_kind_for_block_size(0), None);
    }

    #[test]
    fn over_aligned_requests_use_singleton_pages_or_reject_invalid_alignment() {
        let ordinary_block = SMALL_MAX_OBJ_SIZE;
        assert_eq!(
            page_kind_for_request(ordinary_block, crate::config::PAGE_MAX_OVERALLOC_ALIGN),
            Some(PageKind::Small),
        );
        assert_eq!(
            page_kind_for_request(ordinary_block, 2 * crate::config::PAGE_MAX_OVERALLOC_ALIGN),
            Some(PageKind::Singleton),
        );
        assert_eq!(
            page_kind_for_request(ordinary_block, crate::config::PAGE_MAX_OVERALLOC_ALIGN + 1),
            None,
        );
    }
}
