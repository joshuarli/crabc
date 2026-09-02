// Copyright (c) 2023-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/internal.h:717-763`
// (two-level page-map constants and `_mi_page_map_index`) and
// `src/page-map.c:228-513` (reservation, incremental commitment, two-level
// publication, range registration/rollback, lookup, and destruction).

use core::cell::UnsafeCell;
use core::mem::size_of;
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crabc_core::{Errno, Result};

use crate::config::{
    ARENA_SLICE_SHIFT, ARENA_SLICE_SIZE, MAX_VABITS, MIN_VABITS,
    PAGE_MAP_SUB_COUNT, PAGE_MAP_SUB_SHIFT,
};
use crate::invariants;
use crate::lock::PrivateLock;
use crate::os::{MapAccess, Mapping, MemoryConfig};
use crate::types::{MemoryId, Page};

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

const PAGE_MAP_SUB_SIZE: usize = PAGE_MAP_SUB_COUNT * size_of::<*mut Page>();

/// One source-plain page pointer.
///
/// Upstream deliberately makes these entries non-atomic. Registration,
/// unregistration, and lookup therefore carry the same external
/// synchronization requirement instead of silently strengthening the data
/// structure into a different algorithm.
#[repr(transparent)]
struct PageEntry(UnsafeCell<*mut Page>);

// SAFETY: `PageEntry` is only accessed by unsafe methods whose caller contract
// prohibits an unsynchronized read/write or write/write overlap.
unsafe impl Sync for PageEntry {}

impl PageEntry {
    const fn empty() -> Self { Self(UnsafeCell::new(null_mut())) }
}

/// The mapped prefix of the source `mi_page_map_t` flexible-array object.
///
/// `submaps[0]` is the first raw pointer word. Further words immediately
/// follow this header through the reserved mapping. They stay kernel-zeroed
/// until atomically published; [`AtomicPtr::from_ptr`] supplies the atomic
/// access view without concurrent placement construction.
#[repr(C)]
pub(crate) struct PageMapHeader {
    committed_count: AtomicUsize,
    reserved_size: usize,
    memid: MemoryId,
    lock: PrivateLock,
    submaps: [UnsafeCell<*mut PageEntry>; 1],
}

/// Caller-owned root publication for one live mapped [`PageMapHeader`].
pub(crate) struct PageMapRoot {
    current: AtomicPtr<PageMapHeader>,
}

impl PageMapRoot {
    pub(crate) const fn empty() -> Self {
        Self { current: AtomicPtr::new(null_mut()) }
    }

    /// Publishes a fully initialized, stable page map.
    ///
    /// # Safety
    ///
    /// `page_map` must retain its mapped header until the root is cleared and
    /// all Acquire readers have quiesced.
    pub(crate) unsafe fn publish(&self, page_map: &PageMap) {
        assert!(page_map.active, "cannot publish a destroyed page map");
        self.current.store(page_map.header.as_ptr(), Ordering::Release);
    }

    pub(crate) fn load(&self) -> Option<NonNull<PageMapHeader>> {
        NonNull::new(self.current.load(Ordering::Acquire))
    }

    /// Clears the root after its owner has stopped new readers.
    pub(crate) fn clear(&self) -> Option<NonNull<PageMapHeader>> {
        NonNull::new(self.current.swap(null_mut(), Ordering::AcqRel))
    }
}

/// An explicitly owned, non-RAII two-level page map.
///
/// The top-level mapping includes the source's trailing, eagerly available
/// submap zero. Later submaps transfer their mapping ownership into their
/// published base pointer and are reclaimed exactly once by [`PageMap::destroy`].
/// No `Drop` implementation performs kernel transitions.
pub(crate) struct PageMap {
    mapping: Mapping,
    config: MemoryConfig,
    header: NonNull<PageMapHeader>,
    reserved_count: usize,
    active: bool,
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    submap_allocations: AtomicUsize,
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    published_submap_count: AtomicUsize,
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    registered_entry_count: AtomicUsize,
    #[cfg(test)]
    fail_next_top_release: bool,
}

// SAFETY: top-level fields are immutable or atomic after construction. The
// source-plain entries retain the unsafe external synchronization contract.
unsafe impl Send for PageMap {}
unsafe impl Sync for PageMap {}

impl PageMap {
    /// Returns the immutable OS-memory facts captured when this source page
    /// map was initialized.
    ///
    /// Fresh-page selection must use the same frozen page size and
    /// `_mi_os_good_alloc_size` policy as page-map mappings.  The value is
    /// `Copy` and contains no mutable option state, so exposing this narrow
    /// observation does not weaken the page map's external synchronization
    /// contract.
    #[inline]
    pub(crate) const fn memory_config(&self) -> MemoryConfig {
        self.config
    }

    /// Reserves and initializes the source two-level page map.
    pub(crate) fn initialize(
        config: MemoryConfig,
        configured_virtual_bits: usize,
        force_commit: bool,
    ) -> Result<Self> {
        let virtual_bits = effective_virtual_address_bits(
            configured_virtual_bits,
            config.virtual_address_bits(),
        );
        let virtual_reserve_count = reserve_count(virtual_bits).ok_or(Errno::INVAL)?;
        let header_bytes = mapped_size_for_count(virtual_reserve_count).ok_or(Errno::NOMEM)?;
        let reserved_size = invariants::align_up(header_bytes, config.page_size().bytes())
            .ok_or(Errno::NOMEM)?;
        let reserved_count = page_map_count_of_size(reserved_size);
        let extra_reserve_size = reserved_size
            .checked_add(PAGE_MAP_SUB_SIZE)
            .ok_or(Errno::NOMEM)?;
        let commit_all = virtual_bits == crate::config::MIN_VABITS
            || reserved_size <= 64 * 1024
            || force_commit
            || config.has_overcommit();
        let access = if commit_all { MapAccess::Committed } else { MapAccess::Reserved };
        let mut mapping = Mapping::map_aligned_for_allocator(
            config,
            extra_reserve_size,
            config.page_size().bytes(),
            access,
        )?;
        let base = mapping.base()?;
        let header = NonNull::new(base.cast::<PageMapHeader>()).ok_or(Errno::NOMEM)?;

        let committed_count = if commit_all {
            page_map_count_of_size(reserved_size)
        } else {
            let minimum_count = reserve_count(crate::config::MIN_VABITS).ok_or(Errno::INVAL)?;
            let minimum_bytes = mapped_size_for_count(minimum_count)
                .and_then(|bytes| invariants::align_up(bytes, config.page_size().bytes()))
                .ok_or(Errno::NOMEM)?;
            if let Err(error) = mapping.commit(0, minimum_bytes) {
                let _ = mapping.unmap();
                return Err(error);
            }
            page_map_count_of_size(minimum_bytes)
        };

        let sub0 = base.wrapping_add(reserved_size).cast::<PageEntry>();
        if !commit_all {
            if let Err(error) = mapping.commit(reserved_size, PAGE_MAP_SUB_SIZE) {
                let _ = mapping.unmap();
                return Err(error);
            }
        }
        // SAFETY: the trailing submap is committed, exclusively owned, and is
        // exactly `PAGE_MAP_SUB_SIZE` bytes at pointer alignment.
        unsafe { initialize_submap(sub0) };
        let memid = MemoryId::os(
            base,
            extra_reserve_size,
            commit_all,
            mapping.initially_zero(),
            false,
        );
        // Source order initializes mapped fields only after the initial top
        // extent and trailing submap are accessible. The header is exclusively
        // owned here. Only its first flexible-array word is explicitly
        // written; later words retain fresh anonymous-map zero state.
        unsafe {
            header.as_ptr().write(PageMapHeader {
                committed_count: AtomicUsize::new(0),
                reserved_size,
                memid,
                lock: PrivateLock::new(),
                submaps: [UnsafeCell::new(null_mut())],
            });
        }
        // Source order: first publish the committed top-level extent, then the
        // eagerly reserved submap zero. A later root Release publishes both.
        unsafe { &*header.as_ptr() }
            .committed_count
            .store(committed_count, Ordering::Release);
        unsafe { atomic_submap_slot(header.as_ref(), 0) }.store(sub0, Ordering::Release);

        Ok(Self {
            mapping,
            config,
            header,
            reserved_count,
            active: true,
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            submap_allocations: AtomicUsize::new(0),
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            published_submap_count: AtomicUsize::new(1),
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            registered_entry_count: AtomicUsize::new(0),
            #[cfg(test)]
            fail_next_top_release: false,
        })
    }

    pub(crate) fn committed_count(&self) -> Result<usize> {
        Ok(self.header()?.committed_count.load(Ordering::Acquire))
    }

    pub(crate) const fn reserved_count(&self) -> usize { self.reserved_count }

    /// Returns a read-only ownership audit after callers have established the
    /// PageMap's normal external no-mutation boundary. This test-only view
    /// counts source-plain live registrations rather than treating retained
    /// process-lifetime submaps as worker-owned leaks.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    pub(crate) fn test_registered_entry_count(&self) -> Result<usize> {
        self.header()?;
        Ok(self.registered_entry_count.load(Ordering::Acquire))
    }

    /// Counts published submaps and the lazy publications that created them.
    /// Both are process-map ownership observations, not allocator policy.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    pub(crate) fn test_published_submap_count(&self) -> Result<usize> {
        self.header()?;
        Ok(self.published_submap_count.load(Ordering::Acquire))
    }

    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    #[inline]
    pub(crate) fn test_lazy_submap_allocation_count(&self) -> usize {
        self.submap_allocations.load(Ordering::Relaxed)
    }

    #[inline]
    fn header(&self) -> Result<&PageMapHeader> {
        if !self.active {
            return Err(Errno::INVAL);
        }
        // SAFETY: the non-RAII Mapping owner keeps the initialized mapped
        // header live while `active` is true. A failed release retains that
        // state so callers can retry without losing the ownership record.
        Ok(unsafe { self.header.as_ref() })
    }

    fn ensure_committed(&self, index: usize) -> Result<()> {
        if index >= self.reserved_count {
            return Err(Errno::NOMEM);
        }
        if index < self.header()?.committed_count.load(Ordering::Relaxed)
            || index < self.header()?.committed_count.load(Ordering::Acquire)
        {
            return Ok(());
        }

        let required_bytes = size_of::<PageMapHeader>()
            .checked_add(
                index
                    .checked_mul(size_of::<*mut PageEntry>())
                    .ok_or(Errno::NOMEM)?,
            )
            .ok_or(Errno::NOMEM)?;
        let commit_size = invariants::align_up(required_bytes, crate::config::ARENA_SLICE_SIZE)
            .ok_or(Errno::NOMEM)?
            .min(self.header()?.reserved_size);
        let commit_count = page_map_count_of_size(commit_size);
        self.mapping.commit(0, commit_size)?;
        // Fresh anonymous committed pages already contain valid aligned null
        // raw-pointer words. No placement writes race another source-faithful
        // unlocked commit; only this Release exposes the new extent.
        self.header()?
            .committed_count
            .store(commit_count, Ordering::Release);
        Ok(())
    }

    fn submap_at(&self, index: usize) -> Result<Option<NonNull<PageEntry>>> {
        let header = self.header()?;
        if index >= header.committed_count.load(Ordering::Acquire) {
            return Ok(None);
        }
        // SAFETY: the Acquire count proves the raw pointer word is committed;
        // its atomic view is aligned and pairs with submap publication.
        Ok(NonNull::new(
            unsafe { atomic_submap_slot(header, index) }.load(Ordering::Acquire),
        ))
    }

    fn ensure_submap_at(&self, index: usize) -> Result<NonNull<PageEntry>> {
        self.ensure_committed(index)?;
        if let Some(submap) = self.submap_at(index)? {
            return Ok(submap);
        }

        let guard = self.header()?.lock.lock()?;
        let result = if let Some(submap) = self.submap_at(index)? {
            Ok(submap)
        } else {
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            self.submap_allocations.fetch_add(1, Ordering::Relaxed);
            let mut candidate = Mapping::map_aligned_for_allocator(
                self.config,
                PAGE_MAP_SUB_SIZE,
                self.config.page_size().bytes(),
                MapAccess::Committed,
            )?;
            let candidate_base = candidate.base()?.cast::<PageEntry>();
            // SAFETY: the candidate mapping is exclusively owned and committed.
            unsafe { initialize_submap(candidate_base) };
            // SAFETY: ensure_committed proved this raw pointer word committed
            // before the source page-map lock was acquired.
            let slot = unsafe { atomic_submap_slot(self.header()?, index) };
            match slot.compare_exchange(
                null_mut(),
                candidate_base,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    candidate.into_published()?;
                    #[cfg(any(test, feature = "native-runtime-test-audit"))]
                    self.published_submap_count.fetch_add(1, Ordering::Release);
                    NonNull::new(candidate_base).ok_or(Errno::NOMEM)
                }
                Err(winner) => {
                    candidate.unmap()?;
                    NonNull::new(winner).ok_or(Errno::NOMEM)
                }
            }
        };
        guard.unlock()?;
        result
    }

    /// Registers one page pointer over the arena slices intersecting a range.
    ///
    /// On failure the complete source range is replayed with null pointers,
    /// preserving the pinned rollback behavior.
    ///
    /// # Safety
    ///
    /// `page` must remain valid for every later lookup until the same range is
    /// unregistered. The caller must serialize overlapping entry writes and
    /// must prevent lookups from racing an overlapping write.
    pub(crate) unsafe fn register_range(
        &self,
        start: *const u8,
        size: usize,
        page: NonNull<Page>,
    ) -> Result<()> {
        let slice_count = divide_up(size, ARENA_SLICE_SIZE).ok_or(Errno::INVAL)?;
        let location = location_of_address(start.addr());
        if let Err(error) = unsafe { self.set_range_prim(location, slice_count, page.as_ptr()) } {
            let _ = unsafe { self.set_range_prim(location, slice_count, null_mut()) };
            return Err(error);
        }
        Ok(())
    }

    /// Clears a range, including failure paths whose page was never registered.
    ///
    /// # Safety
    ///
    /// The caller must uphold the same no-overlap synchronization contract as
    /// [`PageMap::register_range`].
    pub(crate) unsafe fn unregister_range(&self, start: *const u8, size: usize) -> Result<()> {
        let slice_count = divide_up(size, ARENA_SLICE_SIZE).ok_or(Errno::INVAL)?;
        unsafe {
            self.set_range_prim(location_of_address(start.addr()), slice_count, null_mut())
        }
    }

    /// Returns the registered page for an address, or null for any unchecked
    /// top-level/submap boundary.
    ///
    /// # Safety
    ///
    /// The caller must prevent this plain entry read from overlapping a
    /// registration or unregistration of the same arena slice.
    pub(crate) unsafe fn checked_lookup(&self, address: *const u8) -> *mut Page {
        let location = location_of_address(address.addr());
        if !self.active {
            return null_mut();
        }
        let Ok(Some(submap)) = self.submap_at(location.map_index) else {
            return null_mut();
        };
        // SAFETY: location arithmetic bounds sub_index and the caller excludes
        // a conflicting plain write.
        unsafe { *(*submap.as_ptr().add(location.sub_index)).0.get() }
    }

    unsafe fn set_range_prim(
        &self,
        location: PageMapLocation,
        slice_count: usize,
        page: *mut Page,
    ) -> Result<()> {
        let spans = PageMapRange::new(location, slice_count).ok_or(Errno::INVAL)?;
        for span in spans {
            let submap = self.ensure_submap_at(span.map_index)?;
            for sub_index in span.sub_index..span.sub_index + span.slice_count {
                // SAFETY: the submap has PAGE_MAP_SUB_COUNT initialized slots;
                // the iterator bounds the index and the caller owns the plain
                // entry synchronization contract.
                let entry = unsafe { (*submap.as_ptr().add(sub_index)).0.get() };
                // SAFETY: the iterator bounds the entry, and the caller owns
                // the source-plain registration synchronization contract.
                #[cfg(any(test, feature = "native-runtime-test-audit"))]
                // SAFETY: the same synchronized source-plain ownership that
                // permits the write also permits this audit-only old-value
                // observation.
                let previous = unsafe { entry.read() };
                // SAFETY: this is the one synchronized source-plain entry
                // write for the current register or unregister transition.
                unsafe { entry.write(page) };
                #[cfg(any(test, feature = "native-runtime-test-audit"))]
                match (previous.is_null(), page.is_null()) {
                    (true, false) => {
                        self.registered_entry_count.fetch_add(1, Ordering::Release);
                    }
                    (false, true) => {
                        self.registered_entry_count.fetch_sub(1, Ordering::Release);
                    }
                    (true, true) | (false, false) => {}
                }
            }
        }
        Ok(())
    }

    /// Reclaims all lazily published submaps and then the top-level mapping.
    ///
    /// A release failure leaves the remaining mappings owned so destruction
    /// can be diagnosed or retried.
    ///
    /// # Safety
    ///
    /// The caller must first clear every published root and establish that no
    /// raw root reader, lookup, registration, or unregistration remains live.
    pub(crate) unsafe fn destroy(&mut self) -> Result<()> {
        if !self.active {
            return Err(Errno::INVAL);
        }
        let count = self.header()?.committed_count.load(Ordering::Acquire);
        for index in 1..count {
            // SAFETY: the committed count proves this aligned raw pointer word
            // is accessible through its atomic view.
            let slot = unsafe { atomic_submap_slot(self.header()?, index) };
            let submap = slot.load(Ordering::Acquire);
            if !submap.is_null() {
                // SAFETY: exclusive `&mut self` plus documented quiescence owns
                // the unique release right transferred into this pointer.
                unsafe { Mapping::reclaim_published(submap.cast(), PAGE_MAP_SUB_SIZE) }?;
                slot.store(null_mut(), Ordering::Release);
            }
        }
        #[cfg(test)]
        if core::mem::replace(&mut self.fail_next_top_release, false) {
            return Err(Errno::NOMEM);
        }
        self.mapping.unmap()?;
        self.active = false;
        Ok(())
    }
}

#[inline]
const fn page_map_count_of_size(bytes: usize) -> usize {
    if bytes < size_of::<PageMapHeader>() {
        0
    } else {
        1 + (bytes - size_of::<PageMapHeader>()) / size_of::<*mut PageEntry>()
    }
}

#[inline]
const fn mapped_size_for_count(count: usize) -> Option<usize> {
    if count == 0 {
        return None;
    }
    match (count - 1).checked_mul(size_of::<*mut PageEntry>()) {
        Some(tail) => size_of::<PageMapHeader>().checked_add(tail),
        None => None,
    }
}

#[inline]
fn divide_up(value: usize, divisor: usize) -> Option<usize> {
    if value == 0 { return Some(0); }
    value.checked_add(divisor - 1).map(|sum| sum / divisor)
}

/// Views one committed raw flexible-array word atomically.
///
/// # Safety
///
/// `header` must identify a live mapped `PageMapHeader`, and `index` must be
/// within its currently committed top-level extent. The raw pointer word must
/// not be accessed non-atomically for the duration of this reference.
unsafe fn atomic_submap_slot<'a>(
    header: &'a PageMapHeader,
    index: usize,
) -> &'a AtomicPtr<PageEntry> {
    let first = core::ptr::addr_of!(header.submaps)
        .cast::<UnsafeCell<*mut PageEntry>>();
    let raw_word = unsafe { UnsafeCell::raw_get(first.add(index)) };
    unsafe { AtomicPtr::from_ptr(raw_word) }
}

unsafe fn initialize_submap(submap: *mut PageEntry) {
    for index in 0..PAGE_MAP_SUB_COUNT {
        unsafe { submap.add(index).write(PageEntry::empty()) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::config::{
        ARENA_SLICE_SIZE, MAX_VABITS, MIN_VABITS, PAGE_MAP_SUB_COUNT,
    };
    use crate::os::PageSize;
    use crate::types::EMPTY_PAGE;

    fn memory_config(overcommit: bool) -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4 * 1024).unwrap(),
            8 * 1024 * 1024,
            overcommit,
            false,
        )
    }

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
        assert_eq!(reserve_count(MAX_VABITS), Some(1usize << (MAX_VABITS - 29)));
        assert_eq!(reserve_count(28), None);
        assert_eq!(reserve_count(usize::BITS as usize), None);
    }

    #[test]
    fn mapped_header_changes_max_reservation_and_count_boundaries() {
        assert_eq!(size_of::<PageMapHeader>(), 56);
        let requested = reserve_count(MAX_VABITS).unwrap();
        let source_bytes = mapped_size_for_count(requested).unwrap();
        let source_reserved = invariants::align_up(source_bytes, 4 * 1024).unwrap();
        let flat_reserved = invariants::align_up(
            requested * size_of::<*mut PageEntry>(),
            4 * 1024,
        )
        .unwrap();

        assert_eq!(source_bytes, size_of::<PageMapHeader>() + (requested - 1) * 8);
        assert!(source_reserved > flat_reserved);
        assert_eq!(page_map_count_of_size(source_reserved), requested + 506);
    }

    #[test]
    fn header_inclusive_initial_and_extension_commit_counts_follow_source_formula() {
        let minimum = reserve_count(MIN_VABITS).unwrap();
        let initial_bytes = invariants::align_up(
            mapped_size_for_count(minimum).unwrap(),
            4 * 1024,
        )
        .unwrap();
        let initial_count = page_map_count_of_size(initial_bytes);
        assert_eq!(initial_count, minimum + 506);

        let required_index = initial_count + 1;
        let extension_bytes = invariants::align_up(
            size_of::<PageMapHeader>() + required_index * size_of::<*mut PageEntry>(),
            ARENA_SLICE_SIZE,
        )
        .unwrap();
        assert_eq!(extension_bytes, 192 * 1024);
        assert_eq!(page_map_count_of_size(extension_bytes), 24_570);
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

    #[test]
    fn initialization_root_publication_registration_lookup_and_destroy_form_one_lifecycle() {
        let mut page_map = std::boxed::Box::new(
            PageMap::initialize(memory_config(false), MAX_VABITS, false)
                .expect("reserve a partially committed two-level map"),
        );
        let minimum_count = reserve_count(MIN_VABITS).unwrap();
        let initial_size = invariants::align_up(
            mapped_size_for_count(minimum_count).unwrap(),
            4 * 1024,
        )
        .unwrap();
        let initial_count = page_map_count_of_size(initial_size);
        assert_eq!(page_map.committed_count(), Ok(initial_count));
        assert!(page_map.committed_count().unwrap() < page_map.reserved_count());
        let expected_reserved_size = invariants::align_up(
            mapped_size_for_count(reserve_count(MAX_VABITS).unwrap()).unwrap(),
            4 * 1024,
        )
        .unwrap();
        assert_eq!(page_map.header().unwrap().reserved_size, expected_reserved_size);
        assert_eq!(
            page_map.header().unwrap().memid.size(),
            Some(expected_reserved_size + PAGE_MAP_SUB_SIZE),
        );

        let root = PageMapRoot::empty();
        let stable = page_map.header;
        unsafe { root.publish(&page_map) };
        assert_eq!(root.load(), Some(stable));

        let map_index = initial_count + 1;
        let address = map_index * PAGE_MAP_SUB_COUNT * ARENA_SLICE_SIZE;
        let start = core::ptr::without_provenance::<u8>(address);
        let page = NonNull::from(EMPTY_PAGE.as_ref());
        unsafe {
            page_map
                .register_range(start, 2 * ARENA_SLICE_SIZE, page)
                .expect("commit a top-level extension and publish one submap");
            assert_eq!(page_map.test_registered_entry_count(), Ok(2));
            assert_eq!(page_map.test_published_submap_count(), Ok(2));
            assert_eq!(page_map.test_lazy_submap_allocation_count(), 1);
            assert_eq!(page_map.checked_lookup(start), page.as_ptr());
            assert_eq!(
                page_map.checked_lookup(start.wrapping_add(ARENA_SLICE_SIZE)),
                page.as_ptr(),
            );
            page_map
                .unregister_range(start, 2 * ARENA_SLICE_SIZE)
                .expect("clear the exact registered range");
            assert!(page_map.checked_lookup(start).is_null());
            assert_eq!(page_map.test_registered_entry_count(), Ok(0));
        }
        let expected_extension_size = invariants::align_up(
            size_of::<PageMapHeader>() + map_index * size_of::<*mut PageEntry>(),
            ARENA_SLICE_SIZE,
        )
        .unwrap();
        assert_eq!(
            page_map.committed_count(),
            Ok(page_map_count_of_size(expected_extension_size)),
        );
        assert_eq!(root.clear(), Some(stable));
        page_map.fail_next_top_release = true;
        assert_eq!(unsafe { page_map.destroy() }, Err(Errno::NOMEM));
        assert!(page_map.committed_count().is_ok(), "failed release remains retryable");
        unsafe { page_map.destroy() }.expect("retry reclaims the top-level owner");
        assert_eq!(page_map.committed_count(), Err(Errno::INVAL));
        assert!(unsafe { page_map.checked_lookup(start) }.is_null());
        assert_eq!(
            unsafe { page_map.register_range(start, ARENA_SLICE_SIZE, page) },
            Err(Errno::INVAL),
        );
        assert_eq!(unsafe { page_map.destroy() }, Err(Errno::INVAL));
    }

    /// Emits the address-free M2 PageMap success differential record. Both
    /// halves use a controlled 4-KiB, non-overcommit configuration and reach
    /// the same selected source transitions: initial partial commitment, a
    /// two-submap extension, range clear, boundary rollback, and an absent
    /// root after destruction. The C global root is reset by destruction;
    /// Rust's separately owned [`PageMapRoot`] must be cleared before
    /// [`PageMap::destroy`], and the trace makes that ownership difference
    /// explicit. It does not cover C's cold-init static-empty-root failure
    /// behavior or allocation routing.
    #[test]
    fn emit_m2_page_map_init_c_rust_trace() {
        let mut page_map = std::boxed::Box::new(
            PageMap::initialize(memory_config(false), MAX_VABITS, false)
                .expect("initialize the selected partial two-level page map"),
        );
        let root = PageMapRoot::empty();
        let control_page_size = page_map.memory_config().page_size().bytes();
        let control_has_overcommit_false = !page_map.memory_config().has_overcommit();
        let control_max_vabits = MAX_VABITS;
        let layout_header_bytes = size_of::<PageMapHeader>();
        let layout_lock_bytes = size_of::<PrivateLock>();
        let init_root_empty_before = root.load().is_none();
        let init_reserve_count = reserve_count(MAX_VABITS)
            .expect("the frozen maximum virtual-address width has a reserve count");
        let init_reserved_count = page_map.reserved_count();
        let init_committed_count = page_map
            .committed_count()
            .expect("the initialized PageMap exposes its committed prefix");
        let init_root_published = {
            // SAFETY: the boxed map stays live until this test clears the
            // root after all observations and registrations finish.
            unsafe { root.publish(&page_map) };
            root.load().is_some()
        };
        let init_submap_zero_present = page_map
            .submap_at(0)
            .expect("submap-zero observation is in the committed prefix")
            .is_some();
        let init_committed_lt_reserved = init_committed_count < init_reserved_count;

        let extend_map_index = init_committed_count
            .checked_add(1)
            .expect("the selected committed prefix leaves a representable extension index");
        let extend_start_sub_index = PAGE_MAP_SUB_COUNT - 1;
        assert!(extend_map_index + 1 < init_reserved_count);
        let extend_start_slice = extend_map_index
            .checked_mul(PAGE_MAP_SUB_COUNT)
            .and_then(|index| index.checked_add(extend_start_sub_index))
            .expect("the selected two-submap registration start is representable");
        let extend_start_address = extend_start_slice
            .checked_mul(ARENA_SLICE_SIZE)
            .expect("the selected two-submap registration address is representable");
        let extend_start = core::ptr::without_provenance::<u8>(extend_start_address);
        let page = NonNull::from(EMPTY_PAGE.as_ref());

        // SAFETY: this test is the only map client and writes a valid stable
        // marker over the last slice of one submap and the first slice of the
        // next, so the source plain-entry contract is satisfied.
        unsafe {
            page_map
                .register_range(extend_start, 2 * ARENA_SLICE_SIZE, page)
                .expect("selected registration extends and publishes two submaps");
        }
        let extend_committed_after = page_map
            .committed_count()
            .expect("registration leaves the map live");
        let extend_committed_increased = extend_committed_after > init_committed_count;
        let extend_first_submap = page_map
            .submap_at(extend_map_index)
            .expect("first selected extension submap slot remains committed");
        let extend_second_submap = page_map
            .submap_at(extend_map_index + 1)
            .expect("second selected extension submap slot remains committed");
        let extend_first_submap_present = extend_first_submap.is_some();
        let extend_second_submap_present = extend_second_submap.is_some();
        let extend_submaps_distinct = match (extend_first_submap, extend_second_submap) {
            (Some(first), Some(second)) => first != second,
            (None, _) | (_, None) => false,
        };
        let extend_second = extend_start.wrapping_add(ARENA_SLICE_SIZE);
        let register_first_lookup_matches =
            unsafe { page_map.checked_lookup(extend_start) == page.as_ptr() };
        let register_second_lookup_matches =
            unsafe { page_map.checked_lookup(extend_second) == page.as_ptr() };

        // SAFETY: this remains the test's sole synchronized map transition.
        unsafe {
            page_map
                .unregister_range(extend_start, 2 * ARENA_SLICE_SIZE)
                .expect("exact registration range unregisters");
        }
        let unregister_first_lookup_absent = unsafe { page_map.checked_lookup(extend_start).is_null() };
        let unregister_second_lookup_absent = unsafe { page_map.checked_lookup(extend_second).is_null() };

        let rollback_map_index = init_reserved_count - 1;
        let rollback_start_slice = rollback_map_index
            .checked_mul(PAGE_MAP_SUB_COUNT)
            .and_then(|index| index.checked_add(PAGE_MAP_SUB_COUNT - 1))
            .expect("the source boundary rollback start is representable");
        let rollback_start_address = rollback_start_slice
            .checked_mul(ARENA_SLICE_SIZE)
            .expect("the source boundary rollback address is representable");
        let rollback_start = core::ptr::without_provenance::<u8>(rollback_start_address);
        let rollback_register_failed = unsafe {
            page_map.register_range(rollback_start, 2 * ARENA_SLICE_SIZE, page)
        } == Err(Errno::NOMEM);
        let rollback_submap_present = page_map
            .submap_at(rollback_map_index)
            .expect("the first boundary write may publish its source submap")
            .is_some();
        let rollback_entry_cleared = unsafe { page_map.checked_lookup(rollback_start).is_null() };
        let rollback_out_of_bounds_absent = unsafe {
            page_map
                .checked_lookup(rollback_start.wrapping_add(ARENA_SLICE_SIZE))
                .is_null()
        };

        assert_eq!(control_page_size, 4 * 1024);
        assert!(control_has_overcommit_false);
        assert_eq!(control_max_vabits, 48);
        assert_ne!(layout_header_bytes, 0);
        assert_ne!(layout_lock_bytes, 0);
        assert!(init_root_empty_before);
        assert!(init_root_published);
        assert_ne!(init_reserve_count, 0);
        assert!(init_committed_lt_reserved);
        assert!(init_submap_zero_present);
        assert!(extend_committed_increased);
        assert!(extend_first_submap_present);
        assert!(extend_second_submap_present);
        assert!(extend_submaps_distinct);
        assert!(register_first_lookup_matches);
        assert!(register_second_lookup_matches);
        assert!(unregister_first_lookup_absent);
        assert!(unregister_second_lookup_absent);
        assert!(rollback_register_failed);
        assert!(rollback_submap_present);
        assert!(rollback_entry_cleared);
        assert!(rollback_out_of_bounds_absent);

        let destroy_root_unpublished_before = root.clear().is_some();
        assert!(destroy_root_unpublished_before);
        // SAFETY: the root is cleared and the test owns the only page-map
        // client, so the selected destruction precondition holds.
        unsafe { page_map.destroy() }.expect("the test map destroys after root clear");
        let destroy_root_absent_after = root.load().is_none();
        assert!(destroy_root_absent_after);

        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        std::println!("CRABC_MI_M2_PAGE_MAP_TRACE_BEGIN");
        emit!("m2.page_map.control.page_size", control_page_size);
        emit!(
            "m2.page_map.control.has_overcommit_false",
            control_has_overcommit_false
        );
        emit!("m2.page_map.control.max_vabits", control_max_vabits);
        emit!("m2.page_map.layout.header_bytes", layout_header_bytes);
        emit!("m2.page_map.layout.lock_bytes", layout_lock_bytes);
        emit!("m2.page_map.init.root_empty_before", init_root_empty_before);
        emit!("m2.page_map.init.root_published", init_root_published);
        emit!("m2.page_map.init.reserve_count", init_reserve_count);
        emit!("m2.page_map.init.reserved_count", init_reserved_count);
        emit!("m2.page_map.init.committed_count", init_committed_count);
        emit!(
            "m2.page_map.init.committed_lt_reserved",
            init_committed_lt_reserved
        );
        emit!(
            "m2.page_map.init.submap_zero_present",
            init_submap_zero_present
        );
        emit!("m2.page_map.extend.map_index", extend_map_index);
        emit!(
            "m2.page_map.extend.start_sub_index",
            extend_start_sub_index
        );
        emit!("m2.page_map.extend.slice_count", 2usize);
        emit!(
            "m2.page_map.extend.committed_before",
            init_committed_count
        );
        emit!("m2.page_map.extend.committed_after", extend_committed_after);
        emit!(
            "m2.page_map.extend.committed_increased",
            extend_committed_increased
        );
        emit!(
            "m2.page_map.extend.first_submap_present",
            extend_first_submap_present
        );
        emit!(
            "m2.page_map.extend.second_submap_present",
            extend_second_submap_present
        );
        emit!("m2.page_map.extend.submaps_distinct", extend_submaps_distinct);
        emit!(
            "m2.page_map.register.first_lookup_matches",
            register_first_lookup_matches
        );
        emit!(
            "m2.page_map.register.second_lookup_matches",
            register_second_lookup_matches
        );
        emit!(
            "m2.page_map.unregister.first_lookup_absent",
            unregister_first_lookup_absent
        );
        emit!(
            "m2.page_map.unregister.second_lookup_absent",
            unregister_second_lookup_absent
        );
        emit!("m2.page_map.rollback.register_failed", rollback_register_failed);
        emit!("m2.page_map.rollback.submap_present", rollback_submap_present);
        emit!("m2.page_map.rollback.entry_cleared", rollback_entry_cleared);
        emit!(
            "m2.page_map.rollback.out_of_bounds_absent",
            rollback_out_of_bounds_absent
        );
        emit!(
            "m2.page_map.destroy.root_unpublished_before",
            destroy_root_unpublished_before
        );
        emit!(
            "m2.page_map.destroy.root_absent_after",
            destroy_root_absent_after
        );
        std::println!("CRABC_MI_M2_PAGE_MAP_TRACE_END");
    }

    #[test]
    fn failed_cross_boundary_registration_rolls_back_every_written_entry() {
        let mut page_map = PageMap::initialize(memory_config(false), MIN_VABITS, false)
            .expect("initialize the minimum source map");
        let final_index = page_map.reserved_count() - 1;
        let final_slice = final_index * PAGE_MAP_SUB_COUNT + (PAGE_MAP_SUB_COUNT - 1);
        let address = final_slice * ARENA_SLICE_SIZE;
        let start = core::ptr::without_provenance::<u8>(address);
        let page = NonNull::from(EMPTY_PAGE.as_ref());

        assert_eq!(
            unsafe { page_map.register_range(start, 2 * ARENA_SLICE_SIZE, page) },
            Err(Errno::NOMEM),
        );
        assert!(unsafe { page_map.checked_lookup(start) }.is_null());
        unsafe { page_map.destroy() }.expect("rollback leaves all mapping ownership intact");
    }

    #[test]
    fn concurrent_lazy_submap_publication_allocates_once_under_the_page_map_lock() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const THREADS: usize = 4;
        let page_map = Arc::new(
            PageMap::initialize(memory_config(false), MAX_VABITS, false)
                .expect("initialize a partial map"),
        );
        let target = page_map.committed_count().unwrap() + 3;
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut workers = std::vec::Vec::new();
        for _ in 0..THREADS {
            let page_map = Arc::clone(&page_map);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                page_map.ensure_submap_at(target).unwrap().as_ptr().addr()
            }));
        }
        let first = workers.remove(0).join().unwrap();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), first);
        }
        assert_eq!(page_map.submap_allocations.load(Ordering::Relaxed), 1);
        let mut page_map = Arc::try_unwrap(page_map).ok().expect("workers released the map");
        unsafe { page_map.destroy() }.expect("the sole published winner is reclaimed");
    }
}
