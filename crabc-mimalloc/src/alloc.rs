// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/alloc.c:379-439`
// (`mi_theap_realloc_zero_ex`). This module owns the address-independent
// reallocation decision and copy/zero extents. Allocation, byte access, old
// block release, and failure preservation stay in the live allocator owner.

use core::mem::size_of;
use core::ops::Range;

use crate::invariants;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReallocationPlan {
    Reuse,
    Replace {
        copy_size: usize,
        zero_start: usize,
    },
}

/// Selects the source ordinary-realloc reuse or replacement path.
///
/// `old_usable == None` represents a null original pointer. A zero-size
/// replacement never reuses an old allocation: this preserves the pinned
/// behavior that successful `realloc(p, 0)` returns a distinct freeable
/// zero-size allocation and frees `p` only after that allocation succeeds.
#[inline]
pub(crate) const fn reallocation_plan(
    old_usable: Option<usize>,
    new_size: usize,
    same_heap: bool,
) -> ReallocationPlan {
    let old_usable = match old_usable {
        Some(old_usable) => old_usable,
        None => 0,
    };
    if new_size <= old_usable
        && new_size >= old_usable / 2
        && new_size > 0
        && same_heap
    {
        return ReallocationPlan::Reuse;
    }

    let copy_size = if new_size < old_usable { new_size } else { old_usable };
    let word_size = size_of::<isize>();
    let zero_candidate = if copy_size >= word_size {
        copy_size - word_size
    } else {
        0
    };
    let zero_start = match invariants::align_down(zero_candidate, word_size) {
        Some(zero_start) => zero_start,
        None => 0,
    };
    ReallocationPlan::Replace { copy_size, zero_start }
}

/// Returns the source zero-initialization extent for rezalloc/recalloc.
///
/// The previous allocation's last word is included deliberately so padding
/// and newly exposed bytes are initialized even when the copy endpoint is not
/// word-aligned. `new_usable` is the usable size of the successful replacement
/// allocation, not merely the requested size.
#[inline]
pub(crate) const fn replacement_zero_range(
    plan: ReallocationPlan,
    new_usable: usize,
    zero: bool,
) -> Option<Range<usize>> {
    let ReallocationPlan::Replace { zero_start, .. } = plan else {
        return None;
    };
    if zero && new_usable > zero_start {
        Some(zero_start..new_usable)
    } else {
        None
    }
}

/// Ordinary realloc explicitly clears byte zero on a successful zero-size
/// replacement when the caller did not request rezalloc zeroing.
#[inline]
pub(crate) const fn replacement_zeros_first_byte(new_size: usize, zero: bool) -> bool {
    new_size == 0 && !zero
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_realloc_reuse_uses_the_source_floor_half_threshold() {
        assert_eq!(reallocation_plan(Some(128), 64, true), ReallocationPlan::Reuse);
        assert_eq!(reallocation_plan(Some(127), 63, true), ReallocationPlan::Reuse);
        assert!(matches!(
            reallocation_plan(Some(127), 62, true),
            ReallocationPlan::Replace { .. }
        ));
        assert!(matches!(
            reallocation_plan(Some(128), 64, false),
            ReallocationPlan::Replace { .. }
        ));
        assert!(matches!(
            reallocation_plan(Some(128), 0, true),
            ReallocationPlan::Replace { .. }
        ));
        assert!(matches!(
            reallocation_plan(None, 0, true),
            ReallocationPlan::Replace { .. }
        ));
    }

    #[test]
    fn replacement_preserves_only_the_request_old_usable_intersection() {
        assert_eq!(
            reallocation_plan(Some(31), 128, true),
            ReallocationPlan::Replace {
                copy_size: 31,
                zero_start: 16,
            }
        );
        assert_eq!(
            reallocation_plan(Some(128), 31, true),
            ReallocationPlan::Replace {
                copy_size: 31,
                zero_start: 16,
            }
        );
        assert_eq!(
            reallocation_plan(None, 64, true),
            ReallocationPlan::Replace {
                copy_size: 0,
                zero_start: 0,
            }
        );
    }

    #[test]
    fn rezalloc_zeroing_includes_the_previous_last_aligned_word() {
        let plan = reallocation_plan(Some(31), 128, true);
        assert_eq!(replacement_zero_range(plan, 144, true), Some(16..144));
        assert_eq!(replacement_zero_range(plan, 144, false), None);
        assert_eq!(replacement_zero_range(ReallocationPlan::Reuse, 144, true), None);
    }

    #[test]
    fn zero_size_realloc_has_the_source_compatibility_clear() {
        assert!(replacement_zeros_first_byte(0, false));
        assert!(!replacement_zeros_first_byte(0, true));
        assert!(!replacement_zeros_first_byte(1, false));
    }
}
