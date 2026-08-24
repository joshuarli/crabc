// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/alloc-aligned.c:18-28,68-188,
// 191-241,347-388` (`mi_malloc_is_naturally_aligned`, aligned over-allocation,
// pointer adjustment, and aligned realloc reuse) and `src/free.c:104-114,
// 522-542` (interior-pointer recovery and aligned usable size).
//
// These are address-independent selection and checked pointer-arithmetic
// kernels. Live page flags, allocation, copying, zeroing, and release stay in
// the owning allocator lifecycle.

use crate::config::{
    MAX_ALIGN_SIZE, MAX_ALLOC_SIZE, PAGE_MAX_OVERALLOC_ALIGN,
    PAGE_MAX_START_BLOCK_ALIGN2, PAGE_OSPAGE_BLOCK_ALIGN2, SMALL_SIZE_MAX,
};
use crate::size_class;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AlignedAllocationPlan {
    Natural,
    Overallocate { request: usize },
    HugeSingleton { request: usize, alignment: usize },
}

pub(crate) const fn allocation_plan(
    size: usize,
    alignment: usize,
    offset: usize,
    os_page_size: usize,
) -> Option<AlignedAllocationPlan> {
    if size > MAX_ALLOC_SIZE || !size_class::alignment_is_valid(alignment) {
        return None;
    }

    if offset == 0 {
        if alignment <= size {
            let block_size = match size_class::good_size(size, os_page_size) {
                Some(block_size) => block_size,
                None => return None,
            };
            let naturally_aligned = (block_size <= PAGE_MAX_START_BLOCK_ALIGN2
                && block_size.is_power_of_two())
                || (alignment == PAGE_OSPAGE_BLOCK_ALIGN2
                    && block_size % PAGE_OSPAGE_BLOCK_ALIGN2 == 0);
            if naturally_aligned {
                return Some(AlignedAllocationPlan::Natural);
            }
        }
    }

    if alignment > PAGE_MAX_OVERALLOC_ALIGN {
        if offset != 0 {
            return None;
        }
        let request = if size <= SMALL_SIZE_MAX {
            SMALL_SIZE_MAX + 1
        } else {
            size
        };
        return Some(AlignedAllocationPlan::HugeSingleton { request, alignment });
    }

    let base_request = if size < MAX_ALIGN_SIZE { MAX_ALIGN_SIZE } else { size };
    let request = match base_request.checked_add(alignment - 1) {
        Some(request) => request,
        None => return None,
    };
    if request > MAX_ALLOC_SIZE {
        return None;
    }
    Some(AlignedAllocationPlan::Overallocate { request })
}

pub(crate) const fn pointer_adjustment(
    address: usize,
    alignment: usize,
    offset: usize,
) -> Option<usize> {
    if !size_class::alignment_is_valid(alignment) {
        return None;
    }
    let misalignment = address.wrapping_add(offset) & (alignment - 1);
    Some(if misalignment == 0 {
        0
    } else {
        alignment - misalignment
    })
}

pub(crate) const fn recover_block_start(
    pointer: usize,
    page_start: usize,
    block_size: usize,
) -> Option<usize> {
    if block_size == 0 {
        return None;
    }
    let difference = match pointer.checked_sub(page_start) {
        Some(difference) => difference,
        None => return None,
    };
    let adjustment = if block_size.is_power_of_two() {
        difference & (block_size - 1)
    } else {
        difference % block_size
    };
    pointer.checked_sub(adjustment)
}

pub(crate) const fn usable_size(block_size: usize, pointer: usize, block_start: usize) -> Option<usize> {
    let adjustment = match pointer.checked_sub(block_start) {
        Some(adjustment) => adjustment,
        None => return None,
    };
    block_size.checked_sub(adjustment)
}

pub(crate) const fn realloc_can_reuse(
    pointer: usize,
    usable: usize,
    new_size: usize,
    alignment: usize,
    offset: usize,
) -> bool {
    if !size_class::alignment_is_valid(alignment) {
        return false;
    }
    new_size <= usable
        && new_size >= usable - (usable / 2)
        && pointer.wrapping_add(offset) & (alignment - 1) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const OS_PAGE: usize = 4096;

    #[test]
    fn aligned_plan_preserves_natural_overallocation_and_huge_transitions() {
        assert_eq!(allocation_plan(16, 16, 0, OS_PAGE), Some(AlignedAllocationPlan::Natural));
        assert_eq!(allocation_plan(17, 16, 0, OS_PAGE), Some(AlignedAllocationPlan::Natural));
        assert_eq!(
            allocation_plan(17, 32, 0, OS_PAGE),
            Some(AlignedAllocationPlan::Overallocate { request: 48 })
        );
        assert_eq!(
            allocation_plan(0, PAGE_MAX_OVERALLOC_ALIGN, 7, OS_PAGE),
            Some(AlignedAllocationPlan::Overallocate {
                request: MAX_ALIGN_SIZE + PAGE_MAX_OVERALLOC_ALIGN - 1,
            })
        );
        assert_eq!(
            allocation_plan(8, PAGE_MAX_OVERALLOC_ALIGN * 2, 0, OS_PAGE),
            Some(AlignedAllocationPlan::HugeSingleton {
                request: SMALL_SIZE_MAX + 1,
                alignment: PAGE_MAX_OVERALLOC_ALIGN * 2,
            })
        );
        assert_eq!(allocation_plan(8, PAGE_MAX_OVERALLOC_ALIGN * 2, 1, OS_PAGE), None);
        assert_eq!(allocation_plan(8, 0, 0, OS_PAGE), None);
        assert_eq!(allocation_plan(8, 24, 0, OS_PAGE), None);
        assert_eq!(allocation_plan(MAX_ALLOC_SIZE + 1, 16, 0, OS_PAGE), None);
        assert_eq!(allocation_plan(MAX_ALLOC_SIZE, 16, 0, OS_PAGE), None);
    }

    #[test]
    fn pointer_adjustment_aligns_pointer_plus_offset() {
        for alignment in [1usize, 8, 16, 64, 4096, 65536] {
            for address in [0x1000usize, 0x1001, 0x103f, usize::MAX - 7] {
                for offset in [0usize, 1, 7, alignment.saturating_sub(1)] {
                    let adjust = pointer_adjustment(address, alignment, offset).unwrap();
                    assert!(adjust < alignment);
                    assert_eq!(address.wrapping_add(adjust).wrapping_add(offset) & (alignment - 1), 0);
                }
            }
        }
        assert_eq!(pointer_adjustment(0x1000, 0, 0), None);
        assert_eq!(pointer_adjustment(0x1000, 12, 0), None);
    }

    #[test]
    fn interior_pointer_recovers_source_block_for_power_of_two_and_other_sizes() {
        assert_eq!(recover_block_start(0x108f, 0x1000, 64), Some(0x1080));
        assert_eq!(recover_block_start(0x108f, 0x1000, 48), Some(0x1060));
        assert_eq!(recover_block_start(0x0fff, 0x1000, 64), None);
        assert_eq!(recover_block_start(0x108f, 0x1000, 0), None);
    }

    #[test]
    fn aligned_usable_size_subtracts_only_the_interior_adjustment() {
        assert_eq!(usable_size(128, 0x1040, 0x1000), Some(64));
        assert_eq!(usable_size(128, 0x1000, 0x1000), Some(128));
        assert_eq!(usable_size(32, 0x1040, 0x1000), None);
        assert_eq!(usable_size(32, 0x0fff, 0x1000), None);
    }

    #[test]
    fn aligned_realloc_reuses_only_a_sufficiently_full_aligned_block() {
        assert!(realloc_can_reuse(0x1040, 128, 64, 64, 0));
        assert!(realloc_can_reuse(0x1040, 128, 128, 64, 0));
        assert!(!realloc_can_reuse(0x1040, 128, 63, 64, 0));
        assert!(realloc_can_reuse(0x1040, 127, 64, 64, 0));
        assert!(!realloc_can_reuse(0x1040, 127, 63, 64, 0));
        assert!(!realloc_can_reuse(0x1040, 128, 129, 64, 0));
        assert!(!realloc_can_reuse(0x1040, 128, 64, 128, 1));
        assert!(!realloc_can_reuse(0x1040, 128, 64, 0, 0));
    }
}
