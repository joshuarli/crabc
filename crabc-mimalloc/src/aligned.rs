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
// These are address-independent selection, checked pointer-arithmetic, and
// aligned-reallocation extent kernels. Live page flags, allocation, copying,
// zeroing, and release stay in the owning allocator lifecycle.

use core::mem::size_of;
use core::ops::Range;

use crate::config::{
    MAX_ALIGN_SIZE, MAX_ALLOC_SIZE, PAGE_MAX_OVERALLOC_ALIGN,
    PAGE_MAX_START_BLOCK_ALIGN2, PAGE_META_ALIGNMENT, PAGE_OSPAGE_BLOCK_ALIGN2,
    SMALL_SIZE_MAX,
};
use crate::alloc::{
    AllocationPointerFacts, OrdinaryReallocationSource, PointerReallocationDecision,
    PointerReplacement, PointerReplacementWork, ordinary_reallocation_decision,
    pointer_replacement_decision,
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
        if offset != 0 || alignment >= PAGE_META_ALIGNMENT {
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

/// Returns the aligned-rezalloc zero extent after a successful replacement.
///
/// Unlike ordinary realloc, pinned `alloc-aligned.c` cannot round this start
/// down: an arbitrary offset can make the returned pointer unaligned. It
/// subtracts exactly one word from the copy extent and uses the unaligned byte
/// kernel so padding at that boundary is initialized before the old bytes are
/// copied back over it.
#[inline]
pub(crate) const fn replacement_zero_range(
    copy_size: usize,
    new_usable: usize,
    zero: bool,
) -> Option<Range<usize>> {
    let zero_start = if copy_size >= size_of::<isize>() {
        copy_size - size_of::<isize>()
    } else {
        0
    };
    if zero && new_usable > zero_start {
        Some(zero_start..new_usable)
    } else {
        None
    }
}

/// Selects the pinned aligned-realloc reuse or replacement path from one
/// pointer-facts and target-Heap classification.
///
/// Pinned `mi_theap_realloc_zero_aligned_at` delegates natural alignment to
/// ordinary realloc, including its exact source-page/target-Heap reuse proof.
/// Only the over-aligned path omits that Heap comparison and uses the source's
/// exact usable-size, ceil-half, and pointer-plus-offset alignment predicate.
#[inline]
pub(crate) fn aligned_reallocation_decision<P: AllocationPointerFacts>(
    source: OrdinaryReallocationSource<P>,
    new_size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Option<PointerReallocationDecision<P>> {
    if !size_class::alignment_is_valid(alignment) {
        return None;
    }
    if alignment <= size_of::<usize>() && offset == 0 {
        return Some(ordinary_reallocation_decision(source, new_size, zero));
    }
    let source = source.into_overaligned_pointer();
    let source = match source {
        Some(pointer) => {
            if realloc_can_reuse(
                pointer.client_address(),
                pointer.usable_size(),
                new_size,
                alignment,
                offset,
            ) {
                return Some(PointerReallocationDecision::Reuse(pointer));
            }
            Some(pointer)
        }
        None => None,
    };

    let old_usable = source.as_ref().map(AllocationPointerFacts::usable_size).unwrap_or(0);
    let copy_size = core::cmp::min(new_size, old_usable);
    let zero_start = if copy_size >= size_of::<isize>() {
        copy_size - size_of::<isize>()
    } else {
        0
    };
    Some(pointer_replacement_decision(
        source,
        new_size,
        zero,
        zero_start,
        false,
    ))
}

/// Computes aligned replacement initialization from the replacement pointer's
/// usable extent.
///
/// The encoded plan carries the selected branch's initialization policy:
/// natural alignment retains ordinary realloc's zero-size compatibility
/// clear, while the over-aligned branch uses its unrounded zero start.
#[inline]
pub(crate) fn aligned_replacement_work<P: AllocationPointerFacts>(
    replacement: &P,
    plan: &PointerReplacement<P>,
) -> PointerReplacementWork {
    crate::alloc::ordinary_replacement_work(replacement, plan)
}

#[cfg(test)]
fn pointer_facts_from_page_geometry(
    client_address: usize,
    page_start: usize,
    block_size: usize,
    has_interior_pointers: bool,
) -> Option<crate::alloc::TestAllocationPointer> {
    if client_address < page_start {
        return None;
    }
    let canonical_address = if has_interior_pointers {
        recover_block_start(client_address, page_start, block_size)?
    } else {
        client_address
    };
    let usable_size = usable_size(block_size, client_address, canonical_address)?;
    crate::alloc::TestAllocationPointer::new(
        client_address,
        canonical_address,
        block_size,
        usable_size,
    )
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
        assert_eq!(allocation_plan(8, PAGE_META_ALIGNMENT, 0, OS_PAGE), None);
        assert_eq!(allocation_plan(8, 2 * PAGE_META_ALIGNMENT, 0, OS_PAGE), None);
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

    #[test]
    fn aligned_rezalloc_keeps_the_unaligned_previous_last_word_extent() {
        assert_eq!(replacement_zero_range(31, 144, true), Some(23..144));
        assert_eq!(replacement_zero_range(7, 144, true), Some(0..144));
        assert_eq!(replacement_zero_range(31, 23, true), None);
        assert_eq!(replacement_zero_range(31, 144, false), None);
    }

    #[test]
    fn page_pointer_facts_recover_exact_and_adjusted_clients() {
        let exact = pointer_facts_from_page_geometry(0x1080, 0x1000, 64, false)
            .expect("a normal page derives facts directly from its block size");
        assert_eq!(exact.client_address(), 0x1080);
        assert_eq!(exact.canonical_address(), 0x1080);
        assert!(!exact.is_interior());
        assert_eq!(crate::alloc::malloc_usable_size(&exact), 64);

        let adjusted = pointer_facts_from_page_geometry(0x1079, 0x1000, 96, true)
            .expect("an adjusted aligned client recovers its source block");
        assert_eq!(adjusted.client_address(), 0x1079);
        assert_eq!(adjusted.canonical_address(), 0x1060);
        assert!(adjusted.is_interior());
        assert_eq!(adjusted.interior_adjustment(), 25);
        assert_eq!(crate::alloc::malloc_usable_size(&adjusted), 71);

        assert!(pointer_facts_from_page_geometry(0x0fff, 0x1000, 64, true).is_none());
    }

    #[test]
    fn aligned_reallocation_uses_adjusted_usable_extent_and_source_threshold() {
        let old = pointer_facts_from_page_geometry(0x1079, 0x1000, 96, true)
            .expect("the adjusted client is live");

        assert_eq!(
            aligned_reallocation_decision(
                crate::alloc::OrdinaryReallocationSource::replacement_required(old),
                36,
                64,
                7,
                false,
            ),
            Some(crate::alloc::PointerReallocationDecision::Reuse(old)),
            "aligned realloc accepts exactly ceil(usable / 2) without an owner route"
        );

        let replacement = aligned_reallocation_decision(
            crate::alloc::OrdinaryReallocationSource::replacement_required(old),
            35,
            64,
            7,
            false,
        )
        .expect("a valid alignment still selects replacement when too much would be wasted");
        assert!(matches!(
            replacement,
            crate::alloc::PointerReallocationDecision::Replace(_)
        ));
        assert_eq!(
            aligned_reallocation_decision(
                crate::alloc::OrdinaryReallocationSource::replacement_required(old),
                36,
                24,
                7,
                false,
            ),
            None
        );
    }

    #[test]
    fn natural_aligned_reallocation_requires_the_exact_target_heap_proof() {
        let old = crate::alloc::TestAllocationPointer::exact(0x2000, 128).unwrap();

        assert!(matches!(
            aligned_reallocation_decision(
                crate::alloc::OrdinaryReallocationSource::replacement_required(old),
                64,
                8,
                0,
                false,
            ),
            Some(crate::alloc::PointerReallocationDecision::Replace(_))
        ));
        assert_eq!(
            aligned_reallocation_decision(
                crate::alloc::OrdinaryReallocationSource::current_target_for_test(old),
                64,
                8,
                0,
                false,
            ),
            Some(crate::alloc::PointerReallocationDecision::Reuse(old))
        );
    }

    #[test]
    fn natural_aligned_reallocation_preserves_ordinary_null_and_zero_size_branches() {
        let null = aligned_reallocation_decision::<crate::alloc::TestAllocationPointer>(
            crate::alloc::OrdinaryReallocationSource::null(),
            64,
            8,
            0,
            false,
        )
        .expect("natural alignment is valid");
        let crate::alloc::PointerReallocationDecision::Replace(null) = null else {
            panic!("a null source must allocate a replacement");
        };
        assert_eq!(null.source(), None);
        assert_eq!(null.request_size(), 64);

        let old = crate::alloc::TestAllocationPointer::exact(0x2000, 128).unwrap();
        let zero = aligned_reallocation_decision(
            crate::alloc::OrdinaryReallocationSource::current_target_for_test(old),
            0,
            8,
            0,
            false,
        )
        .expect("natural alignment is valid");
        let crate::alloc::PointerReallocationDecision::Replace(zero) = zero else {
            panic!("ordinary zero-size realloc must replace its source");
        };
        assert_eq!(zero.source(), Some(&old));
        assert_eq!(zero.copy_size(), 0);

        let replacement = crate::alloc::TestAllocationPointer::exact(0x4000, 8).unwrap();
        let work = aligned_replacement_work(&replacement, &zero);
        assert_eq!(work.zero_range(), None);
        assert!(work.zeros_first_byte());
    }
}
