// Copyright (c) 2023-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/internal.h:717-763`
// (two-level page-map constants and `_mi_page_map_index`) and
// `src/page-map.c:253-276,355-383,407-458` (virtual-bit bounds, reserve
// counts, and submap-spanning ranges). This foundation contains address and
// range arithmetic only; it does not advertise page-map allocation,
// publication, registration, lookup, or reclamation.

use crate::config::{
    ARENA_SLICE_SHIFT, ARENA_SLICE_SIZE, MAX_VABITS, MIN_VABITS,
    PAGE_MAP_SUB_COUNT, PAGE_MAP_SUB_SHIFT,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageMapLocation {
    pub(crate) map_index: usize,
    pub(crate) sub_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageMapSpan {
    pub(crate) map_index: usize,
    pub(crate) sub_index: usize,
    pub(crate) slice_count: usize,
}

/// Applies the pinned two-level page-map bounds in the same order as
/// `mi_page_map_init_once`.
///
/// A zero configured value selects the observed OS value. The extra first
/// clamp keeps the shift used to size the top-level map non-negative.
pub(crate) const fn effective_virtual_address_bits(
    configured: usize,
    observed: usize,
) -> usize {
    let mut virtual_bits = if configured == 0 { observed } else { configured };
    let minimum_shift_bits = PAGE_MAP_SUB_SHIFT + ARENA_SLICE_SHIFT;
    if virtual_bits < minimum_shift_bits {
        virtual_bits = minimum_shift_bits;
    }
    if virtual_bits < MIN_VABITS {
        virtual_bits = MIN_VABITS;
    }
    if virtual_bits > MAX_VABITS {
        virtual_bits = MAX_VABITS;
    }
    virtual_bits
}

/// Decomposes an address into the top-level page-map index and its submap
/// index. Bytes within one arena slice deliberately have the same location.
pub(crate) const fn location_of_address(address: usize) -> PageMapLocation {
    let slice_index = address / ARENA_SLICE_SIZE;
    PageMapLocation {
        map_index: slice_index / PAGE_MAP_SUB_COUNT,
        sub_index: slice_index % PAGE_MAP_SUB_COUNT,
    }
}

/// Returns the number of top-level entries required to cover `virtual_bits`.
/// Values that cannot be represented by the source expression are rejected.
pub(crate) const fn reserve_count(virtual_bits: usize) -> Option<usize> {
    let address_shift = PAGE_MAP_SUB_SHIFT + ARENA_SLICE_SHIFT;
    if virtual_bits < address_shift || virtual_bits >= usize::BITS as usize {
        return None;
    }
    1usize.checked_shl((virtual_bits - address_shift) as u32)
}

/// A validated cursor over the same submap-sized spans consumed by
/// `mi_page_map_set_range_prim`.
pub(crate) struct PageMapRange {
    location: PageMapLocation,
    remaining: usize,
}

impl PageMapRange {
    pub(crate) fn new(location: PageMapLocation, slice_count: usize) -> Option<Self> {
        if location.sub_index >= PAGE_MAP_SUB_COUNT {
            return None;
        }
        if slice_count != 0 {
            // The source advances `idx` after every non-empty span, including
            // the final one, so a starting `usize::MAX` is not representable.
            let first_span = PAGE_MAP_SUB_COUNT - location.sub_index;
            let remaining_after_first = slice_count.saturating_sub(first_span);
            let following_spans = remaining_after_first
                .checked_add(PAGE_MAP_SUB_COUNT - 1)?
                / PAGE_MAP_SUB_COUNT;
            location.map_index.checked_add(following_spans + 1)?;
        }
        Some(Self {
            location,
            remaining: slice_count,
        })
    }
}

impl Iterator for PageMapRange {
    type Item = PageMapSpan;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let slice_count = self
            .remaining
            .min(PAGE_MAP_SUB_COUNT - self.location.sub_index);
        let span = PageMapSpan {
            map_index: self.location.map_index,
            sub_index: self.location.sub_index,
            slice_count,
        };
        self.remaining -= slice_count;
        self.location.map_index += 1;
        self.location.sub_index = 0;
        Some(span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ARENA_SLICE_SIZE, MAX_VABITS, MIN_VABITS, PAGE_MAP_SUB_COUNT,
    };

    #[test]
    fn virtual_address_bits_follow_the_exact_two_level_clamp_order() {
        assert_eq!(effective_virtual_address_bits(0, 39), MIN_VABITS);
        assert_eq!(effective_virtual_address_bits(0, MIN_VABITS), MIN_VABITS);
        assert_eq!(effective_virtual_address_bits(0, 47), 47);
        assert_eq!(effective_virtual_address_bits(0, 52), MAX_VABITS);
        assert_eq!(effective_virtual_address_bits(44, 52), 44);
        assert_eq!(effective_virtual_address_bits(MAX_VABITS + 1, 39), MAX_VABITS);
    }

    #[test]
    fn index_splits_at_every_slice_and_submap_boundary() {
        let submap_span = PAGE_MAP_SUB_COUNT * ARENA_SLICE_SIZE;
        for address in [
            0,
            1,
            ARENA_SLICE_SIZE - 1,
            ARENA_SLICE_SIZE,
            submap_span - 1,
            submap_span,
            submap_span + ARENA_SLICE_SIZE,
            (1usize << MAX_VABITS) - 1,
        ] {
            let location = location_of_address(address);
            let slice = address / ARENA_SLICE_SIZE;
            assert_eq!(location.map_index, slice / PAGE_MAP_SUB_COUNT);
            assert_eq!(location.sub_index, slice % PAGE_MAP_SUB_COUNT);
        }

        assert_eq!(location_of_address(0), PageMapLocation { map_index: 0, sub_index: 0 });
        assert_eq!(
            location_of_address(submap_span),
            PageMapLocation { map_index: 1, sub_index: 0 },
        );
    }

    #[test]
    fn reserve_count_covers_the_configured_address_space_without_overflow() {
        assert_eq!(reserve_count(MIN_VABITS), Some(1usize << (MIN_VABITS - 29)));
        assert_eq!(reserve_count(MAX_VABITS), Some(1usize << 19));
        assert_eq!(reserve_count(28), None);
        assert_eq!(reserve_count(usize::BITS as usize), None);
    }

    #[test]
    fn range_cursor_splits_without_skipping_or_extending_slices() {
        let start = PageMapLocation {
            map_index: 7,
            sub_index: PAGE_MAP_SUB_COUNT - 2,
        };
        let mut cursor = PageMapRange::new(start, PAGE_MAP_SUB_COUNT + 5).unwrap();
        assert_eq!(
            cursor.next(),
            Some(PageMapSpan { map_index: 7, sub_index: PAGE_MAP_SUB_COUNT - 2, slice_count: 2 }),
        );
        assert_eq!(
            cursor.next(),
            Some(PageMapSpan { map_index: 8, sub_index: 0, slice_count: PAGE_MAP_SUB_COUNT }),
        );
        assert_eq!(
            cursor.next(),
            Some(PageMapSpan { map_index: 9, sub_index: 0, slice_count: 3 }),
        );
        assert_eq!(cursor.next(), None);
        assert_eq!(cursor.next(), None);

        assert!(PageMapRange::new(start, 0).is_some());
        assert!(PageMapRange::new(PageMapLocation { map_index: usize::MAX, sub_index: 0 }, 1).is_none());
        assert!(PageMapRange::new(PageMapLocation { map_index: 0, sub_index: PAGE_MAP_SUB_COUNT }, 1).is_none());
    }
}
