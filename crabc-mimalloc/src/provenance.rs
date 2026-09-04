// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h`:
// `mi_memkind_is_os`, `mi_memkind_needs_no_free`, and `mi_memid_*`; plus
// `include/mimalloc/internal.h:_mi_memid_create*`, `_mi_memid_size`, and
// `_mi_is_aligned`.
// `Address` is a Rust language-boundary value type: it retains only an address
// number and never reconstructs a pointer, so a future pointer-bearing path
// must retain an appropriate provenance-bearing pointer separately.

use crate::invariants;
use crate::types::{MemoryId, MemoryInfo, MemoryKind, OsMemory};

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Address(usize);

impl Address {
    #[inline]
    pub(crate) const fn new(value: usize) -> Self {
        Self(value)
    }

    #[inline]
    pub(crate) fn from_ptr<T>(pointer: *const T) -> Self {
        Self(pointer.addr())
    }

    #[inline]
    pub(crate) const fn value(self) -> usize {
        self.0
    }

    #[inline]
    pub(crate) const fn checked_add(self, bytes: usize) -> Option<Self> {
        match self.0.checked_add(bytes) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[inline]
    pub(crate) const fn is_aligned_to(self, alignment: usize) -> bool {
        // `_mi_is_aligned` treats zero as an unconstrained alignment. Keep
        // that predicate separate from `align_down`, whose division contract
        // deliberately rejects zero.
        if alignment == 0 {
            return true;
        }
        match invariants::align_down(self.0, alignment) {
            Some(aligned) => aligned == self.0,
            None => false,
        }
    }

    #[inline]
    pub(crate) const fn align_down(self, alignment: usize) -> Option<Self> {
        match invariants::align_down(self.0, alignment) {
            Some(aligned) => Some(Self(aligned)),
            None => None,
        }
    }
}

impl MemoryId {
    /// Constructs the source `MI_MEM_MALLOC` provenance used for a block from
    /// the dedicated metadata theap. This does not mean the public C
    /// `malloc` ABI: metadata allocation remains a private process-runtime
    /// operation with its own lifetime and lock contract.
    #[inline]
    pub(crate) const fn malloc(base: *mut u8, size: usize, initially_zero: bool) -> Self {
        Self {
            info: MemoryInfo {
                malloc: crate::types::MallocMemory { base, size },
            },
            kind: MemoryKind::Malloc,
            is_pinned: true,
            initially_committed: true,
            initially_zero,
        }
    }

    #[inline]
    pub(crate) fn malloc_memory(&self) -> Option<crate::types::MallocMemory> {
        if self.kind == MemoryKind::Malloc {
            // SAFETY: `MemoryId::malloc` initializes this union member and no
            // other constructor assigns `MemoryKind::Malloc`.
            Some(unsafe { self.info.malloc })
        } else {
            None
        }
    }

    #[inline]
    pub(crate) const fn os(
        base: *mut u8,
        size: usize,
        committed: bool,
        zero: bool,
        is_large: bool,
    ) -> Self {
        Self {
            info: MemoryInfo {
                os: OsMemory { base, size },
            },
            kind: MemoryKind::Os,
            is_pinned: is_large,
            initially_committed: committed,
            initially_zero: zero,
        }
    }

    /// Constructs `_mi_memid_create_os(...); memid.memkind = MI_MEM_OS_HUGE`.
    ///
    /// Huge-page ownership retains the same `mem.os` base/complete-size union
    /// and pinned initial state as a large regular OS allocation, but its
    /// terminal source free path must release one 1-GiB primitive map at a
    /// time. Keeping the discriminant separate prevents that owner from being
    /// passed to an ordinary one-range `munmap` release path.
    #[inline]
    pub(crate) const fn os_huge(
        base: *mut u8,
        size: usize,
        committed: bool,
        zero: bool,
    ) -> Self {
        Self {
            info: MemoryInfo {
                os: OsMemory { base, size },
            },
            kind: MemoryKind::OsHuge,
            is_pinned: true,
            initially_committed: committed,
            initially_zero: zero,
        }
    }

    #[inline]
    pub(crate) fn os_base(&self) -> Option<Address> {
        if !self.is_os() {
            return None;
        }
        // SAFETY: `MemoryId::os` initializes the `os` union member for every
        // OS kind. Later OS-huge/remap constructors preserve that same member.
        Some(Address::from_ptr(unsafe { self.info.os.base }))
    }

    #[inline]
    pub(crate) fn size(&self) -> Option<usize> {
        match self.kind() {
            MemoryKind::Os | MemoryKind::OsHuge | MemoryKind::OsRemap => {
                // SAFETY: all OS variants use the `os` member by construction.
                Some(unsafe { self.info.os.size })
            }
            MemoryKind::Arena => {
                // SAFETY: arena IDs use the `arena` member by construction.
                invariants::size_of_slices(unsafe { self.info.arena.slice_count as usize })
            }
            MemoryKind::Malloc => {
                // SAFETY: malloc IDs use the `malloc` member by construction.
                Some(unsafe { self.info.malloc.size })
            }
            MemoryKind::None | MemoryKind::External | MemoryKind::Static => Some(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MemoryKind;

    #[test]
    fn memory_kind_classification_matches_the_pinned_source_ranges() {
        assert!(!MemoryKind::None.is_os());
        assert!(!MemoryKind::External.is_os());
        assert!(!MemoryKind::Static.is_os());
        assert!(MemoryKind::Os.is_os());
        assert!(MemoryKind::OsHuge.is_os());
        assert!(MemoryKind::OsRemap.is_os());
        assert!(!MemoryKind::Arena.is_os());
        assert!(!MemoryKind::Malloc.is_os());

        assert!(MemoryKind::None.needs_no_free());
        assert!(MemoryKind::External.needs_no_free());
        assert!(MemoryKind::Static.needs_no_free());
        assert!(!MemoryKind::Os.needs_no_free());
        assert!(!MemoryKind::OsHuge.needs_no_free());
        assert!(!MemoryKind::OsRemap.needs_no_free());
        assert!(!MemoryKind::Arena.needs_no_free());
        assert!(!MemoryKind::Malloc.needs_no_free());
    }

    #[test]
    fn address_alignment_keeps_provenance_out_of_integer_operations() {
        let address = Address::new(0x1234_5678);
        // Pinned `internal.h:_mi_is_aligned` treats a zero alignment as no
        // constraint. This is distinct from the alignment-producing helpers,
        // which reject zero before division.
        assert!(address.is_aligned_to(0));
        assert!(address.is_aligned_to(8));
        assert!(!address.is_aligned_to(16));
        assert_eq!(address.checked_add(8), Some(Address::new(0x1234_5680)));
        assert_eq!(Address::new(usize::MAX).checked_add(1), None);
        assert_eq!(address.align_down(64), Some(Address::new(0x1234_5640)));
        assert_eq!(address.align_down(48), Some(Address::new(0x1234_5660)));
    }

    #[test]
    fn memory_ids_preserve_kind_specific_static_construction() {
        let static_id = MemoryId::static_kind_only();
        assert_eq!(static_id.kind(), MemoryKind::Static);
        assert!(static_id.needs_no_free());
        assert!(!static_id.is_pinned());
        assert!(!static_id.initially_committed());
        assert!(!static_id.initially_zero());
        assert_eq!(static_id.size(), Some(0));
        let static_memory = static_id.static_memory().unwrap();
        assert_eq!(static_memory.base, core::ptr::null_mut());
        assert_eq!(static_memory.size, 0);
        assert_eq!(MemoryId::static_empty().kind(), MemoryKind::Static);

        let mut static_bytes = [0u8; 3];
        let static_image = MemoryId::static_allocation(static_bytes.as_mut_ptr(), static_bytes.len());
        assert_eq!(static_image.kind(), MemoryKind::Static);
        assert!(static_image.needs_no_free());
        assert!(static_image.is_pinned());
        assert!(static_image.initially_committed());
        assert_eq!(static_image.size(), Some(0));
        let static_memory = static_image.static_memory().unwrap();
        assert_eq!(static_memory.base, static_bytes.as_mut_ptr());
        assert_eq!(static_memory.size, static_bytes.len());

        let mut bytes = [0u8; 1];
        let os_id = MemoryId::os(bytes.as_mut_ptr(), 8192, false, true, false);
        assert_eq!(os_id.kind(), MemoryKind::Os);
        assert!(os_id.is_os());
        assert_eq!(os_id.size(), Some(8192));
        assert_eq!(os_id.os_base(), Some(Address::from_ptr(bytes.as_ptr())));
        assert!(!os_id.initially_committed());
        assert!(os_id.initially_zero());

        let huge_id = MemoryId::os_huge(bytes.as_mut_ptr(), 1024 * 1024 * 1024, true, false);
        assert_eq!(huge_id.kind(), MemoryKind::OsHuge);
        assert!(huge_id.is_os());
        assert!(huge_id.is_pinned());
        assert!(huge_id.initially_committed());
        assert!(!huge_id.initially_zero());
        assert_eq!(huge_id.os_base(), Some(Address::from_ptr(bytes.as_ptr())));
        assert_eq!(huge_id.size(), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn memory_id_constructors_keep_the_pinned_union_and_size_rules() {
        let mut byte = 0_u8;
        let pointer = core::ptr::from_mut(&mut byte);

        let none = MemoryId::none();
        assert_eq!(none.kind(), MemoryKind::None);
        assert!(!none.is_pinned());
        assert!(!none.initially_committed());
        assert!(!none.initially_zero());
        assert_eq!(none.size(), Some(0));

        let static_kind_only = MemoryId::static_kind_only();
        let static_memory = static_kind_only.static_memory().unwrap();
        assert_eq!(static_memory.base, core::ptr::null_mut());
        assert_eq!(static_memory.size, 0);
        assert_eq!(static_kind_only.size(), Some(0));

        let static_allocation = MemoryId::static_allocation(pointer, 37);
        let static_memory = static_allocation.static_memory().unwrap();
        assert_eq!(static_memory.base, pointer);
        assert_eq!(static_memory.size, 37);
        assert!(static_allocation.is_pinned());
        assert!(static_allocation.initially_committed());
        assert!(!static_allocation.initially_zero());
        assert_eq!(static_allocation.size(), Some(0));

        let malloc = MemoryId::malloc(pointer, 41, true);
        let malloc_memory = malloc.malloc_memory().unwrap();
        assert_eq!(malloc.kind(), MemoryKind::Malloc);
        assert_eq!(malloc_memory.base, pointer);
        assert_eq!(malloc_memory.size, 41);
        assert!(malloc.is_pinned());
        assert!(malloc.initially_committed());
        assert!(malloc.initially_zero());
        assert_eq!(malloc.size(), Some(41));

        let os = MemoryId::os(pointer, 43, false, true, true);
        let os_memory = os.os_memory().unwrap();
        assert_eq!(os.kind(), MemoryKind::Os);
        assert_eq!(os_memory.base, pointer);
        assert_eq!(os_memory.size, 43);
        assert!(os.is_pinned());
        assert!(!os.initially_committed());
        assert!(os.initially_zero());
        assert_eq!(os.size(), Some(43));
    }
}
