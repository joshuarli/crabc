// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/alloc.c:364-377` (`mi_expand`) and
// `src/alloc.c:379-439` (`mi_theap_realloc_zero_ex`). This module owns the
// address-independent expansion/reallocation decisions and copy/zero extents.
// Allocation, byte access, old block release, and failure preservation stay in
// the live allocator owner.

use core::mem::size_of;
use core::ops::Range;
use core::ptr::NonNull;

use crate::invariants;
use crate::process_page_map::LiveAllocationPointer;
use crate::types::Heap;

/// Selects the pinned `mi_expand` result after its non-null pointer has been
/// validated and its usable size observed.
///
/// The frozen normal release profile has `MI_PADDING == 0`, so source
/// `mi_expand` returns its input exactly when `new_size` fits that usable
/// extent. Retaining the padding condition makes a future configuration change
/// fail closed just as the pinned C branch does.
#[inline]
pub(crate) const fn expansion_fits(usable_size: usize, new_size: usize) -> bool {
    crate::config::PADDING_SIZE == 0 && new_size <= usable_size
}

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

/// The immutable pointer facts consumed by usable-size and realloc.
///
/// The production implementation is the operation-scoped result of
/// [`crate::process_page_map::ProcessPageMapLease::lookup_live_allocation`].
/// Keeping this interface limited to source geometry prevents realloc from
/// treating a PageMap observation as page ownership. In particular, ordinary
/// in-place reuse requires a separate [`CurrentTargetHeapAllocation`] proof.
pub(crate) trait AllocationPointerFacts {
    /// Returns the exact client address supplied to the PageMap lookup.
    fn client_address(&self) -> usize;

    /// Returns the canonical source block address recovered from page geometry.
    fn canonical_address(&self) -> usize;

    /// Returns the page's immutable source block size.
    fn block_size(&self) -> usize;

    /// Returns the usable extent beginning at the exact client address.
    fn usable_size(&self) -> usize;
}

impl AllocationPointerFacts for LiveAllocationPointer {
    #[inline]
    fn client_address(&self) -> usize { self.client().as_ptr().addr() }

    #[inline]
    fn canonical_address(&self) -> usize { self.canonical_block().as_ptr().addr() }

    #[inline]
    fn block_size(&self) -> usize { self.block_size() }

    #[inline]
    fn usable_size(&self) -> usize { self.usable_size() }
}

/// Proof that an allocation's page belongs to the target Theap's exact Heap.
///
/// Pinned `mi_theap_realloc_zero_ex` permits ordinary in-place reuse only
/// after comparing `mi_page_heap(page)` with `_mi_theap_heap(theap)`. The
/// PageMap pointer facts intentionally cannot manufacture this proof: reading
/// the page's non-atomic Heap field requires current local-page authority.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CurrentTargetHeapAllocation<P> {
    pointer: P,
}

impl<P: AllocationPointerFacts> CurrentTargetHeapAllocation<P> {
    /// Returns the exact pointer facts covered by this target-Heap proof.
    #[inline]
    pub(crate) const fn pointer(&self) -> &P { &self.pointer }

    #[inline]
    fn into_pointer(self) -> P { self.pointer }
}

enum OrdinaryReallocationSourceState<P> {
    Null,
    CurrentTargetHeap(CurrentTargetHeapAllocation<P>),
    ReplacementRequired(P),
}

/// Ownership classification paired with an ordinary realloc source pointer.
///
/// The current-target variant is private and can be created only by
/// [`prove_current_target_heap`]. A caller that lacks local-page authority can
/// still preserve its operation-scoped pointer facts by selecting the public
/// replacement-required constructor.
pub(crate) struct OrdinaryReallocationSource<P>(OrdinaryReallocationSourceState<P>);

impl<P: AllocationPointerFacts> OrdinaryReallocationSource<P> {
    #[inline]
    pub(crate) const fn null() -> Self {
        Self(OrdinaryReallocationSourceState::Null)
    }

    #[inline]
    pub(crate) const fn replacement_required(pointer: P) -> Self {
        Self(OrdinaryReallocationSourceState::ReplacementRequired(pointer))
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn current_target_for_test(pointer: P) -> Self {
        Self(OrdinaryReallocationSourceState::CurrentTargetHeap(
            CurrentTargetHeapAllocation { pointer },
        ))
    }

    #[inline]
    fn pointer(&self) -> Option<&P> {
        match &self.0 {
            OrdinaryReallocationSourceState::Null => None,
            OrdinaryReallocationSourceState::CurrentTargetHeap(target) => Some(target.pointer()),
            OrdinaryReallocationSourceState::ReplacementRequired(pointer) => Some(pointer),
        }
    }

    #[inline]
    fn into_pointer(self) -> Option<P> {
        match self.0 {
            OrdinaryReallocationSourceState::Null => None,
            OrdinaryReallocationSourceState::CurrentTargetHeap(target) => {
                Some(target.into_pointer())
            }
            OrdinaryReallocationSourceState::ReplacementRequired(pointer) => Some(pointer),
        }
    }

    /// Erases the ordinary target-Heap distinction after aligned realloc has
    /// selected its pinned over-aligned branch.
    #[inline]
    pub(crate) fn into_overaligned_pointer(self) -> Option<P> {
        self.into_pointer()
    }
}

/// Checks the pinned ordinary-realloc target-Heap relation under local-page
/// authority.
///
/// # Safety
///
/// `pointer` must describe an exact current allocation whose source page is
/// locally and exclusively owned by the caller for this check. `target_heap`
/// must be the live Heap of the current target Theap. Those obligations must
/// keep the page initialized and its ordinary `heap` field stable until this
/// function returns. A returned current-target classification must be consumed
/// before that local authority ends; a mismatch preserves the pointer facts in
/// the replacement-required classification.
#[inline]
pub(crate) unsafe fn prove_current_target_heap(
    pointer: LiveAllocationPointer,
    target_heap: NonNull<Heap>,
) -> OrdinaryReallocationSource<LiveAllocationPointer> {
    // SAFETY: the caller's local-page authority permits a short shared
    // projection of this owner-only field and excludes a concurrent reclaim,
    // reassociation, or final release while it is read.
    let page_heap = unsafe { pointer.page().as_ref().heap() };
    if core::ptr::eq(page_heap, target_heap.as_ptr()) {
        OrdinaryReallocationSource(OrdinaryReallocationSourceState::CurrentTargetHeap(
            CurrentTargetHeapAllocation { pointer },
        ))
    } else {
        OrdinaryReallocationSource::replacement_required(pointer)
    }
}

/// Returns the source usable extent from an already classified live pointer.
///
/// This performs no owner, client-ledger, or route lookup. Interior-pointer
/// adjustment has already been derived from the page's immutable geometry by
/// the PageMap pointer-facts boundary.
#[inline]
pub(crate) fn malloc_usable_size<P: AllocationPointerFacts>(pointer: &P) -> usize {
    pointer.usable_size()
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PointerReplacement<P> {
    source: Option<P>,
    request_size: usize,
    zero: bool,
    copy_size: usize,
    zero_start: usize,
    zeros_first_byte: bool,
}

impl<P: AllocationPointerFacts> PointerReplacement<P> {
    #[inline]
    pub(crate) const fn source(&self) -> Option<&P> { self.source.as_ref() }

    #[inline]
    pub(crate) const fn request_size(&self) -> usize { self.request_size }

    #[inline]
    pub(crate) const fn copy_size(&self) -> usize { self.copy_size }

    #[inline]
    fn into_source(self) -> Option<P> { self.source }
}

/// Pointer-centered result of the pinned realloc selection phase.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PointerReallocationDecision<P> {
    /// The old allocation satisfies every source in-place condition.
    Reuse(P),
    /// Replacement allocation and its later copy/free work remain necessary.
    Replace(PointerReplacement<P>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PointerReplacementWork {
    copy_size: usize,
    zero_range: Option<Range<usize>>,
    zeros_first_byte: bool,
}

impl PointerReplacementWork {
    #[inline]
    pub(crate) const fn copy_size(&self) -> usize { self.copy_size }

    #[inline]
    pub(crate) fn zero_range(&self) -> Option<Range<usize>> {
        self.zero_range.clone()
    }

    #[inline]
    pub(crate) const fn zeros_first_byte(&self) -> bool { self.zeros_first_byte }

    #[inline]
    const fn needs_initialization(&self) -> bool {
        self.zero_range.is_some() || self.zeros_first_byte
    }
}

/// Creates one replacement decision with source-specific zeroing policy.
///
/// `zero_start` is computed differently by ordinary and aligned realloc. The
/// ordinary source rounds down to a word boundary; aligned realloc preserves
/// an arbitrary offset and subtracts one word without rounding.
#[inline]
pub(crate) fn pointer_replacement_decision<P: AllocationPointerFacts>(
    source: Option<P>,
    request_size: usize,
    zero: bool,
    zero_start: usize,
    zeros_first_byte: bool,
) -> PointerReallocationDecision<P> {
    let old_usable = source.as_ref().map(AllocationPointerFacts::usable_size).unwrap_or(0);
    let copy_size = core::cmp::min(request_size, old_usable);
    PointerReallocationDecision::Replace(PointerReplacement {
        source,
        request_size,
        zero,
        copy_size,
        zero_start,
        zeros_first_byte,
    })
}

/// Selects pinned ordinary realloc reuse or caller-controlled replacement.
///
/// The source classification carries the typed current-target proof instead
/// of a boolean or caller identity. A foreign, abandoned, or
/// same-thread/different-Heap page therefore selects replacement even when its
/// usable extent would fit.
#[inline]
pub(crate) fn ordinary_reallocation_decision<P: AllocationPointerFacts>(
    source: OrdinaryReallocationSource<P>,
    new_size: usize,
    zero: bool,
) -> PointerReallocationDecision<P> {
    let source = match source.0 {
        OrdinaryReallocationSourceState::CurrentTargetHeap(target) => {
            if matches!(
                reallocation_plan(Some(target.pointer().usable_size()), new_size, true),
                ReallocationPlan::Reuse
            ) {
                return PointerReallocationDecision::Reuse(target.into_pointer());
            }
            OrdinaryReallocationSource::replacement_required(target.into_pointer())
        }
        OrdinaryReallocationSourceState::ReplacementRequired(pointer) => {
            OrdinaryReallocationSource::replacement_required(pointer)
        }
        OrdinaryReallocationSourceState::Null => OrdinaryReallocationSource::null(),
    };
    let old_usable = source.pointer().map(AllocationPointerFacts::usable_size);
    let zero_start = match reallocation_plan(old_usable, new_size, false) {
        ReallocationPlan::Replace { zero_start, .. } => zero_start,
        // `same_heap=false` makes reuse impossible; retaining this fallback
        // keeps an internal decision mismatch fail closed into replacement.
        ReallocationPlan::Reuse => 0,
    };
    pointer_replacement_decision(
        source.into_pointer(),
        new_size,
        zero,
        zero_start,
        replacement_zeros_first_byte(new_size, zero),
    )
}

/// Computes initialization and copy extents after ordinary replacement
/// allocation succeeds.
#[inline]
pub(crate) fn ordinary_replacement_work<P: AllocationPointerFacts>(
    replacement: &P,
    plan: &PointerReplacement<P>,
) -> PointerReplacementWork {
    let zero_range = if plan.zero && replacement.usable_size() > plan.zero_start {
        Some(plan.zero_start..replacement.usable_size())
    } else {
        None
    };
    PointerReplacementWork {
        copy_size: plan.copy_size,
        zero_range,
        zeros_first_byte: plan.zeros_first_byte,
    }
}

/// Executes the source allocate/initialize/copy/general-free replacement
/// order while leaving each allocator action under caller control.
///
/// Allocation is always uninitialized, matching pinned realloc. Failure
/// returns before any copy or free callback, so the old allocation remains
/// live. After success the old pointer is released only through the supplied
/// general pointer-centered free callback.
#[inline]
pub(crate) fn execute_pointer_reallocation<P, Allocate, ReplacementWork, Initialize, Copy, Free>(
    decision: PointerReallocationDecision<P>,
    allocate: Allocate,
    replacement_work: ReplacementWork,
    initialize: Initialize,
    copy: Copy,
    free: Free,
) -> Option<P>
where
    P: AllocationPointerFacts,
    Allocate: FnOnce(usize, bool) -> Option<P>,
    ReplacementWork: FnOnce(&P, &PointerReplacement<P>) -> PointerReplacementWork,
    Initialize: FnOnce(&P, &PointerReplacementWork),
    Copy: FnOnce(&P, &P, usize),
    Free: FnOnce(P),
{
    match decision {
        PointerReallocationDecision::Reuse(pointer) => Some(pointer),
        PointerReallocationDecision::Replace(plan) => {
            let replacement = allocate(plan.request_size(), false)?;
            let work = replacement_work(&replacement, &plan);
            if work.needs_initialization() {
                initialize(&replacement, &work);
            }
            if let Some(source) = plan.into_source() {
                copy(&replacement, &source, work.copy_size());
                free(source);
            }
            Some(replacement)
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TestAllocationPointer {
    client_address: usize,
    canonical_address: usize,
    block_size: usize,
    usable_size: usize,
}

#[cfg(test)]
impl TestAllocationPointer {
    pub(crate) const fn new(
        client_address: usize,
        canonical_address: usize,
        block_size: usize,
        usable_size: usize,
    ) -> Option<Self> {
        if client_address == 0
            || canonical_address == 0
            || canonical_address > client_address
            || block_size == 0
            || usable_size > block_size
        {
            return None;
        }
        Some(Self { client_address, canonical_address, block_size, usable_size })
    }

    pub(crate) const fn exact(client_address: usize, block_size: usize) -> Option<Self> {
        Self::new(client_address, client_address, block_size, block_size)
    }

    pub(crate) const fn is_interior(self) -> bool {
        self.client_address != self.canonical_address
    }

    pub(crate) const fn interior_adjustment(self) -> usize {
        self.client_address - self.canonical_address
    }
}

#[cfg(test)]
impl AllocationPointerFacts for TestAllocationPointer {
    fn client_address(&self) -> usize { self.client_address }

    fn canonical_address(&self) -> usize { self.canonical_address }

    fn block_size(&self) -> usize { self.block_size }

    fn usable_size(&self) -> usize { self.usable_size }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    #[test]
    fn expand_uses_the_full_usable_extent_only_in_the_no_padding_profile() {
        assert_eq!(crate::config::PADDING_SIZE, 0);
        assert!(expansion_fits(64, 0));
        assert!(expansion_fits(64, 31));
        assert!(expansion_fits(64, 64));
        assert!(!expansion_fits(64, 65));
    }

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

    #[test]
    fn foreign_owner_replacement_uses_pointer_facts_and_general_callbacks() {
        let old = TestAllocationPointer::exact(0x2000, 128)
            .expect("a normal live block has facts");
        let replacement =
            TestAllocationPointer::exact(0x4000, 80).expect("a replacement live block has facts");
        let decision = ordinary_reallocation_decision(
            OrdinaryReallocationSource::replacement_required(old),
            64,
            false,
        );
        let calls = RefCell::new(Vec::new());

        let result = execute_pointer_reallocation(
            decision,
            |request, zero| {
                calls.borrow_mut().push("allocate");
                assert_eq!(request, 64);
                assert!(!zero, "replacement allocation stays uninitialized");
                Some(replacement)
            },
            ordinary_replacement_work,
            |new, work| {
                calls.borrow_mut().push("initialize");
                assert_eq!(*new, replacement);
                assert_eq!(work.zero_range(), None);
                assert!(!work.zeros_first_byte());
            },
            |new, source, copy_size| {
                calls.borrow_mut().push("copy");
                assert_eq!(*new, replacement);
                assert_eq!(*source, old);
                assert_eq!(copy_size, 64);
            },
            |source| {
                calls.borrow_mut().push("free");
                assert_eq!(source, old);
            },
        );

        assert_eq!(result, Some(replacement));
        assert_eq!(*calls.borrow(), ["allocate", "copy", "free"]);
        assert_eq!(old.client_address(), 0x2000);
        assert_eq!(old.canonical_address(), 0x2000);
        assert_eq!(malloc_usable_size(&old), 128);
    }

    #[test]
    fn pointer_reallocation_preserves_old_on_allocation_failure_and_keeps_zero_size_order() {
        let old = TestAllocationPointer::exact(0x2000, 128)
            .expect("a normal live block has facts");
        let failed = ordinary_reallocation_decision(
            OrdinaryReallocationSource::replacement_required(old),
            256,
            false,
        );
        let failed_calls = RefCell::new(Vec::new());

        let failed_result = execute_pointer_reallocation(
            failed,
            |request, zero| {
                failed_calls.borrow_mut().push("allocate");
                assert_eq!(request, 256);
                assert!(!zero);
                None
            },
            |_, _| unreachable!("replacement work follows a successful allocation"),
            |_, _| unreachable!("initialization follows a successful allocation"),
            |_, _, _| unreachable!("copy follows a successful allocation"),
            |_| unreachable!("the old allocation survives allocation failure"),
        );

        assert_eq!(failed_result, None);
        assert_eq!(*failed_calls.borrow(), ["allocate"]);
        assert_eq!(old, TestAllocationPointer::exact(0x2000, 128).unwrap());

        let zero_size = ordinary_reallocation_decision(
            OrdinaryReallocationSource(OrdinaryReallocationSourceState::CurrentTargetHeap(
                CurrentTargetHeapAllocation { pointer: old },
            )),
            0,
            false,
        );
        let replacement =
            TestAllocationPointer::exact(0x5000, 8).expect("zero allocation is freeable");
        let zero_calls = RefCell::new(Vec::new());
        let zero_result = execute_pointer_reallocation(
            zero_size,
            |request, zero| {
                zero_calls.borrow_mut().push("allocate");
                assert_eq!(request, 0);
                assert!(!zero, "ordinary zero-size replacement starts uninitialized");
                Some(replacement)
            },
            ordinary_replacement_work,
            |new, work| {
                zero_calls.borrow_mut().push("initialize");
                assert_eq!(*new, replacement);
                assert_eq!(work.copy_size(), 0);
                assert_eq!(work.zero_range(), None);
                assert!(work.zeros_first_byte());
            },
            |new, source, copy_size| {
                zero_calls.borrow_mut().push("copy");
                assert_eq!(*new, replacement);
                assert_eq!(*source, old);
                assert_eq!(copy_size, 0);
            },
            |source| {
                zero_calls.borrow_mut().push("free");
                assert_eq!(source, old);
            },
        );

        assert_eq!(zero_result, Some(replacement));
        assert_eq!(*zero_calls.borrow(), ["allocate", "initialize", "copy", "free"]);
    }

    #[test]
    fn ordinary_reuse_requires_the_exact_current_target_heap_proof() {
        let old = TestAllocationPointer::exact(0x2000, 128).unwrap();
        let other = TestAllocationPointer::exact(0x4000, 128).unwrap();

        assert!(matches!(
            ordinary_reallocation_decision(
                OrdinaryReallocationSource::replacement_required(old),
                64,
                false,
            ),
            PointerReallocationDecision::Replace(_)
        ));
        assert!(matches!(
            ordinary_reallocation_decision(
                OrdinaryReallocationSource::replacement_required(other),
                64,
                false,
            ),
            PointerReallocationDecision::Replace(_)
        ));
        assert_eq!(
            ordinary_reallocation_decision(
                OrdinaryReallocationSource(OrdinaryReallocationSourceState::CurrentTargetHeap(
                    CurrentTargetHeapAllocation { pointer: old },
                )),
                64,
                false,
            ),
            PointerReallocationDecision::Reuse(old)
        );
    }
}
