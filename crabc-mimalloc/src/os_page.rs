// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/alloc-aligned.c:68-145`,
// `src/arena.c:781-870,951-1120,1160-1211`, `src/os.c:87-97,453-467`,
// `src/page-map.c:460-496`, and `include/mimalloc/internal.h:772-793`.

//! OS ownership for singleton pages whose alignment exceeds the arena limit.
//!
//! In the frozen aligned-metadata profile, an alignment above 64 KiB cannot
//! use an arena. The source instead reserves one mapping aligned to 256 MiB,
//! places the block span after an alignment-sized prefix, and stores its page
//! metadata inside that prefix. [`OsAlignedPageClaim`] preserves that mapping
//! as an explicit, unpublished ownership token. A later page lifecycle may
//! borrow its derived addresses, publish page metadata, and finally transfer
//! the exact mapping base and rounded extent into [`MemoryId`]. It must either
//! perform that transfer or explicitly release the claim; this type has no
//! implicit `Drop` unmap.
//!
//! Queue membership, page publication, page-map registration, metadata alias
//! slots, and terminal page release remain with their owning lifecycle. This
//! module defines the geometry and raw OS claim only, so arena and OS
//! provenance cannot be silently interchanged.

use core::mem::size_of;
use core::ptr::NonNull;

use crabc_core::Errno;

use crate::config::{
    ARENA_SLICE_SIZE, LARGE_PAGE_SIZE, PAGE_MAX_OVERALLOC_ALIGN,
    PAGE_META_ALIGNMENT,
};
use crate::invariants;
use crate::os::{MapAccess, Mapping, MemoryConfig};
use crate::page;
use crate::types::{MemoryId, MemoryKind, Page};

/// The source phase at which an OS-aligned page claim failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OsAlignedPageFailureStage {
    Map,
    MetadataCommit,
    BlockCommit,
    Publish,
    Release,
}

/// One exact OS-aligned page failure, including failed cleanup when present.
///
/// Cleanup errors are not discarded: after a failed commit the mapping is
/// still live unless its explicit `unmap` succeeds, so callers must not treat
/// an unsuccessful rollback as if no ownership remained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OsAlignedPageError {
    stage: OsAlignedPageFailureStage,
    operation: Errno,
    cleanup: Option<Errno>,
}

impl OsAlignedPageError {
    #[inline]
    const fn new(stage: OsAlignedPageFailureStage, operation: Errno) -> Self {
        Self {
            stage,
            operation,
            cleanup: None,
        }
    }

    #[inline]
    const fn with_cleanup(
        stage: OsAlignedPageFailureStage,
        operation: Errno,
        cleanup: Option<Errno>,
    ) -> Self {
        Self {
            stage,
            operation,
            cleanup,
        }
    }

    #[inline]
    pub(crate) const fn stage(self) -> OsAlignedPageFailureStage {
        self.stage
    }

    #[inline]
    pub(crate) const fn operation(self) -> Errno {
        self.operation
    }

    #[inline]
    pub(crate) const fn cleanup(self) -> Option<Errno> {
        self.cleanup
    }
}

/// Address-independent geometry of one source OS-aligned singleton page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OsAlignedPageLayout {
    block_size: usize,
    alignment: usize,
    slice_count: usize,
    allocation_size: usize,
    mapping_length: usize,
    metadata_offset: usize,
    metadata_commit_size: usize,
    metadata_slot_count: usize,
    block_start_offset: usize,
    page_offset: usize,
    page_map_size: usize,
}

impl OsAlignedPageLayout {
    /// Computes the frozen-profile geometry before any mapping exists.
    ///
    /// This accepts only the OS-aligned branch: `alignment` must be a power of
    /// two strictly above `MI_PAGE_MAX_OVERALLOC_ALIGN` and strictly below
    /// `MI_PAGE_META_ALIGNMENT`. The upper bound is a source safety contract,
    /// not a convenient implementation limit.
    pub(crate) fn new(
        config: MemoryConfig,
        block_size: usize,
        alignment: usize,
    ) -> Option<Self> {
        if block_size == 0
            || alignment <= PAGE_MAX_OVERALLOC_ALIGN
            || alignment >= PAGE_META_ALIGNMENT
            || !invariants::is_power_of_two(alignment)
        {
            return None;
        }

        let slice_count = page::singleton_page_slice_count(block_size)?;
        let allocation_size = invariants::size_of_slices(slice_count)?;
        let requested_mapping_length = allocation_size.checked_add(alignment)?;
        let mapping_length = config.good_alloc_size(requested_mapping_length);
        if mapping_length < requested_mapping_length
            || mapping_length % config.page_size().bytes() != 0
        {
            return None;
        }

        let metadata_slot_count = if slice_count > 2 { 2 } else { slice_count };
        let prefix_page_count = invariants::divide_up(
            alignment.checked_add(ARENA_SLICE_SIZE)?,
            ARENA_SLICE_SIZE,
        )?;
        let metadata_commit_size = prefix_page_count
            .checked_add(metadata_slot_count)?
            .checked_mul(size_of::<Page>())?;
        let metadata_index = alignment / ARENA_SLICE_SIZE;
        let metadata_offset = metadata_index.checked_mul(size_of::<Page>())?;
        let metadata_end = metadata_offset.checked_add(
            metadata_slot_count.checked_mul(size_of::<Page>())?,
        )?;
        if metadata_slot_count == 0
            || metadata_end > metadata_commit_size
            || metadata_commit_size >= alignment
        {
            return None;
        }

        let block_start_offset = page::page_usable_start_offset(block_size)?;
        let page_offset = alignment
            .checked_add(block_start_offset)?
            .checked_sub(metadata_offset)?;

        // `mi_page_map_get_idx` deliberately clips huge-page registration to
        // one less than a large page. The complete mapping extent remains in
        // `MemoryId`; page-map reachability and OS ownership are not the same
        // span for blocks above 4 MiB.
        let mapped_area_size = if block_size > LARGE_PAGE_SIZE {
            LARGE_PAGE_SIZE.checked_sub(ARENA_SLICE_SIZE)?
        } else {
            block_size
        };
        let page_map_size = invariants::size_of_slices(
            invariants::slice_count_of_size(mapped_area_size)?,
        )?;

        Some(Self {
            block_size,
            alignment,
            slice_count,
            allocation_size,
            mapping_length,
            metadata_offset,
            metadata_commit_size,
            metadata_slot_count,
            block_start_offset,
            page_offset,
            page_map_size,
        })
    }

    #[inline]
    pub(crate) const fn block_size(self) -> usize {
        self.block_size
    }

    #[inline]
    pub(crate) const fn alignment(self) -> usize {
        self.alignment
    }

    #[inline]
    pub(crate) const fn slice_count(self) -> usize {
        self.slice_count
    }

    #[inline]
    pub(crate) const fn allocation_size(self) -> usize {
        self.allocation_size
    }

    #[inline]
    pub(crate) const fn mapping_length(self) -> usize {
        self.mapping_length
    }

    #[inline]
    pub(crate) const fn metadata_offset(self) -> usize {
        self.metadata_offset
    }

    #[inline]
    pub(crate) const fn metadata_commit_size(self) -> usize {
        self.metadata_commit_size
    }

    #[inline]
    pub(crate) const fn metadata_slot_count(self) -> usize {
        self.metadata_slot_count
    }

    #[inline]
    pub(crate) const fn block_start_offset(self) -> usize {
        self.block_start_offset
    }

    #[inline]
    pub(crate) const fn page_offset(self) -> usize {
        self.page_offset
    }

    #[inline]
    pub(crate) const fn page_map_size(self) -> usize {
        self.page_map_size
    }
}

/// An accessible but unpublished OS-aligned singleton mapping.
///
/// The metadata prefix and full block span are committed before construction
/// returns. Bytes between those ranges retain the source reserved protection.
pub(crate) struct OsAlignedPageClaim {
    mapping: Mapping,
    layout: OsAlignedPageLayout,
}

/// Unique terminal ownership reconstructed from one live OS-aligned page.
///
/// This token has no destructor. Its caller must either keep the live page
/// intact or complete the ordered alias-clear, primary-retire, and mapping
/// reclaim sequence. Construction is unsafe because `MemoryId` is copied in
/// the C layout and cannot itself enforce one unique `munmap` right.
pub(crate) struct PublishedOsAlignedPage {
    memory: MemoryId,
    layout: OsAlignedPageLayout,
    base: NonNull<u8>,
    slice_start: NonNull<u8>,
    primary: NonNull<Page>,
}

impl OsAlignedPageClaim {
    /// Reserves and commits one exact source OS-aligned singleton claim.
    pub(crate) fn allocate(
        config: MemoryConfig,
        block_size: usize,
        alignment: usize,
    ) -> Result<Self, OsAlignedPageError> {
        let layout = OsAlignedPageLayout::new(config, block_size, alignment)
            .ok_or_else(|| OsAlignedPageError::new(OsAlignedPageFailureStage::Map, Errno::INVAL))?;
        let mut mapping = Mapping::map_aligned_for_allocator(
            config,
            layout.mapping_length(),
            PAGE_META_ALIGNMENT,
            MapAccess::Reserved,
        )
        .map_err(|error| OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error))?;

        if let Err(error) = mapping.commit(0, layout.metadata_commit_size()) {
            let cleanup = mapping.unmap().err();
            return Err(OsAlignedPageError::with_cleanup(
                OsAlignedPageFailureStage::MetadataCommit,
                error,
                cleanup,
            ));
        }
        if let Err(error) = mapping.commit(layout.alignment(), layout.allocation_size()) {
            let cleanup = mapping.unmap().err();
            return Err(OsAlignedPageError::with_cleanup(
                OsAlignedPageFailureStage::BlockCommit,
                error,
                cleanup,
            ));
        }

        Ok(Self { mapping, layout })
    }

    #[inline]
    pub(crate) const fn layout(&self) -> OsAlignedPageLayout {
        self.layout
    }

    #[inline]
    pub(crate) fn base(&self) -> Result<*mut u8, OsAlignedPageError> {
        self.mapping
            .base()
            .map_err(|error| OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, error))
    }

    /// Returns the first source slice, after the reserved metadata prefix.
    pub(crate) fn slice_start(&self) -> Option<NonNull<u8>> {
        NonNull::new(self.base().ok()?.wrapping_add(self.layout.alignment()))
    }

    /// Returns the primary aligned metadata slot in the committed prefix.
    pub(crate) fn metadata(&self) -> Option<NonNull<Page>> {
        self.metadata_slot(0)
    }

    /// Returns one committed aligned-metadata slot for this singleton.
    pub(crate) fn metadata_slot(&self, index: usize) -> Option<NonNull<Page>> {
        if index >= self.layout.metadata_slot_count() {
            return None;
        }
        let offset = self
            .layout
            .metadata_offset()
            .checked_add(index.checked_mul(size_of::<Page>())?)?;
        NonNull::new(self.base().ok()?.wrapping_add(offset).cast::<Page>())
    }

    /// Publishes every secondary aligned metadata slot after the primary page.
    ///
    /// # Safety
    ///
    /// `primary` must equal [`Self::metadata`] and already contain the fully
    /// initialized live page for this claim. No lookup may overlap these
    /// source Release publications. The claim and primary must remain live
    /// until the slots are cleared after page-map unregistration.
    pub(crate) unsafe fn publish_secondary_metadata(
        &self,
        primary: NonNull<Page>,
    ) -> bool {
        if self.metadata() != Some(primary) {
            return false;
        }
        for index in 1..self.layout.metadata_slot_count() {
            let Some(slot) = self.metadata_slot(index) else {
                return false;
            };
            // SAFETY: the caller proves this claim's committed metadata prefix
            // is exclusively owned and its primary page is fully published.
            unsafe { Page::publish_aligned_alias_at(slot, primary) };
        }
        true
    }

    /// Clears secondary aligned metadata slots in reverse publication order.
    ///
    /// # Safety
    ///
    /// `primary` and every secondary slot must still be live in this claim.
    /// Page-map/metadata lookup readers must be quiescent, and the primary
    /// must not yet have been retired or its mapping released.
    pub(crate) unsafe fn clear_secondary_metadata(
        &self,
        primary: NonNull<Page>,
    ) -> bool {
        if self.metadata() != Some(primary) {
            return false;
        }
        for index in (1..self.layout.metadata_slot_count()).rev() {
            let Some(slot) = self.metadata_slot(index) else {
                return false;
            };
            // SAFETY: forwarded from the method's serialized live-slot
            // contract for this exact owner.
            if !unsafe { Page::clear_aligned_alias_at(slot, primary) } {
                return false;
            }
        }
        true
    }

    /// Describes the mapping while this claim still owns it.
    ///
    /// The source sets `initially_committed` after its two successful commit
    /// transitions so fresh-page initialization never commits the span again.
    pub(crate) fn memory_id(&self) -> Result<MemoryId, OsAlignedPageError> {
        Ok(MemoryId::os(
            self.base()?,
            self.layout.mapping_length(),
            true,
            self.mapping.initially_zero(),
            false,
        ))
    }

    /// Transfers exact OS ownership into the page's copied [`MemoryId`].
    pub(crate) fn into_published(self) -> Result<MemoryId, OsAlignedPageError> {
        let memory = self.memory_id()?;
        let published = self.mapping.into_published().map_err(|error| {
            OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, error)
        })?;
        debug_assert_eq!(published.addr(), memory.os_base().unwrap().value());
        Ok(memory)
    }

    /// Releases an unpublished claim after metadata/page rollback.
    pub(crate) fn release(mut self) -> Result<(), OsAlignedPageError> {
        self.mapping
            .unmap()
            .map_err(|error| OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error))
    }
}

impl PublishedOsAlignedPage {
    /// Reconstructs and validates the OS release right before queue removal.
    ///
    /// # Safety
    ///
    /// `primary` must be a live, exclusively owned page metadata record. Its
    /// copied OS `MemoryId` must still represent exactly one published mapping
    /// created by [`OsAlignedPageClaim::into_published`], and the caller must
    /// own the unique terminal release right. No concurrent metadata or page-
    /// map writer may inspect a partially completed terminal transition.
    pub(crate) unsafe fn from_page(
        config: MemoryConfig,
        primary: NonNull<Page>,
    ) -> Option<Self> {
        // SAFETY: the caller proves `primary` is live and exclusively owned.
        let page = unsafe { primary.as_ref() };
        if page.aligned_alias_owner() != primary.as_ptr()
            || page.reserved() != 1
            || page.slice_pcommitted() != 0
        {
            return None;
        }
        let memory = page.memid();
        if memory.kind() != MemoryKind::Os {
            return None;
        }
        let os = memory.os_memory()?;
        let base = NonNull::new(os.base)?;
        let block_size = page.block_size();
        let block_start_offset = page::page_usable_start_offset(block_size)?;
        let page_start_address = primary
            .as_ptr()
            .addr()
            .checked_add(page.page_offset())?;
        let slice_start_address = page_start_address.checked_sub(block_start_offset)?;
        let alignment = slice_start_address.checked_sub(base.as_ptr().addr())?;
        let layout = OsAlignedPageLayout::new(config, block_size, alignment)?;
        if layout.mapping_length() != os.size
            || layout.page_offset() != page.page_offset()
            || base.as_ptr().addr().checked_add(layout.metadata_offset())?
                != primary.as_ptr().addr()
        {
            return None;
        }
        let slice_start = NonNull::new(base.as_ptr().wrapping_add(layout.alignment()))?;
        if slice_start.as_ptr().addr() != slice_start_address {
            return None;
        }
        Some(Self {
            memory,
            layout,
            base,
            slice_start,
            primary,
        })
    }

    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.memory
    }

    #[inline]
    pub(crate) const fn layout(&self) -> OsAlignedPageLayout {
        self.layout
    }

    #[inline]
    pub(crate) const fn slice_start(&self) -> NonNull<u8> {
        self.slice_start
    }

    /// Validates the source-clipped page-map range before unregistration.
    ///
    /// # Safety
    ///
    /// The caller must serialize plain page-map reads and writes for this
    /// exact page range.
    pub(crate) unsafe fn page_map_entries_match(&self, page_map: &crate::page_map::PageMap) -> bool {
        for offset in (0..self.layout.page_map_size()).step_by(ARENA_SLICE_SIZE) {
            let address = self.slice_start.as_ptr().wrapping_add(offset);
            // SAFETY: forwarded from the serialized page-map contract.
            if unsafe { page_map.checked_lookup(address) } != self.primary.as_ptr() {
                return false;
            }
        }
        true
    }

    /// Clears every secondary metadata alias in reverse order.
    ///
    /// # Safety
    ///
    /// The page-map range must already be unregistered, metadata lookup readers
    /// must be quiescent, and the primary page must remain live until this
    /// operation completes.
    pub(crate) unsafe fn clear_secondary_metadata(&self) -> bool {
        for index in (1..self.layout.metadata_slot_count()).rev() {
            let offset = match self.layout.metadata_offset().checked_add(
                match index.checked_mul(size_of::<Page>()) {
                    Some(offset) => offset,
                    None => return false,
                },
            ) {
                Some(offset) => offset,
                None => return false,
            };
            let Some(slot) = NonNull::new(self.base.as_ptr().wrapping_add(offset).cast::<Page>())
            else {
                return false;
            };
            // SAFETY: the method contract proves this exact alias remains live
            // and exclusively names `primary` until the transition succeeds.
            if !unsafe { Page::clear_aligned_alias_at(slot, self.primary) } {
                return false;
            }
        }
        true
    }

    /// Reclaims the exact rounded mapping after all metadata is retired.
    ///
    /// # Safety
    ///
    /// The page-map range and every secondary alias must be clear, the primary
    /// page must be retired, all readers must be quiescent, and this token must
    /// retain the unique mapping release right.
    pub(crate) unsafe fn reclaim(self) -> Result<(), OsAlignedPageError> {
        // SAFETY: the method contract preserves the original published base,
        // exact rounded length, and unique terminal ownership.
        unsafe {
            Mapping::reclaim_published(self.base.as_ptr(), self.layout.mapping_length())
        }
        .map_err(|error| OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{KIB, MIB};
    use crate::os::PageSize;

    fn config(page_size: usize) -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(page_size).unwrap(),
            1024 * 1024,
            false,
            false,
        )
    }

    #[test]
    fn layout_rejects_arena_alignments_and_the_source_metadata_limit() {
        let config = config(4 * KIB);
        assert!(OsAlignedPageLayout::new(config, 4 * KIB, 64 * KIB).is_none());
        assert!(OsAlignedPageLayout::new(config, 4 * KIB, 96 * KIB).is_none());
        assert!(OsAlignedPageLayout::new(config, 4 * KIB, 256 * MIB).is_none());
        assert!(OsAlignedPageLayout::new(config, 4 * KIB, 512 * MIB).is_none());
        assert!(OsAlignedPageLayout::new(config, 0, 128 * KIB).is_none());

        let error = match OsAlignedPageClaim::allocate(config, 4 * KIB, 64 * KIB) {
            Ok(claim) => {
                claim.release().unwrap();
                panic!("arena-bounded alignment must not create an OS claim");
            }
            Err(error) => error,
        };
        assert_eq!(error.stage(), OsAlignedPageFailureStage::Map);
        assert_eq!(error.operation(), Errno::INVAL);
        assert_eq!(error.cleanup(), None);
    }

    #[test]
    fn small_os_aligned_layout_preserves_each_linux_aarch64_page_size() {
        for (page_size, block_size) in [
            (4 * KIB, 4 * KIB),
            (16 * KIB, 16 * KIB),
            (64 * KIB, 64 * KIB),
        ] {
            let layout = OsAlignedPageLayout::new(
                config(page_size),
                block_size,
                128 * KIB,
            )
            .unwrap();
            assert_eq!(layout.block_size(), block_size);
            assert_eq!(layout.slice_count(), 1);
            assert_eq!(layout.allocation_size(), 64 * KIB);
            assert_eq!(layout.mapping_length(), 192 * KIB);
            assert_eq!(layout.metadata_offset(), 2 * size_of::<Page>());
            assert_eq!(layout.metadata_slot_count(), 1);
            assert_eq!(layout.metadata_commit_size(), 4 * size_of::<Page>());
            assert_eq!(layout.block_start_offset(), 0);
            assert_eq!(
                layout.page_offset(),
                128 * KIB - 2 * size_of::<Page>()
            );
            assert_eq!(layout.page_map_size(), 64 * KIB);
        }
    }

    #[test]
    fn metadata_slots_and_good_os_size_follow_source_boundaries() {
        let config = config(4 * KIB);
        let one = OsAlignedPageLayout::new(config, 64 * KIB, 1 * MIB).unwrap();
        assert_eq!(one.metadata_slot_count(), 1);
        assert_eq!(one.metadata_offset(), 16 * size_of::<Page>());
        assert_eq!(one.metadata_commit_size(), 18 * size_of::<Page>());

        let two = OsAlignedPageLayout::new(config, 64 * KIB + 1, 1 * MIB).unwrap();
        assert_eq!(two.slice_count(), 2);
        assert_eq!(two.metadata_slot_count(), 2);
        assert_eq!(two.metadata_commit_size(), 19 * size_of::<Page>());

        let many = OsAlignedPageLayout::new(config, 3 * 64 * KIB, 4 * MIB).unwrap();
        assert_eq!(many.metadata_slot_count(), 2);
        assert_eq!(many.mapping_length(), 4 * MIB + 256 * KIB);
    }

    #[test]
    fn huge_page_map_span_is_clipped_without_clipping_mapping_ownership() {
        let config = config(64 * KIB);
        let exact_large =
            OsAlignedPageLayout::new(config, 4 * MIB, 128 * KIB).unwrap();
        assert_eq!(exact_large.page_map_size(), 4 * MIB);
        assert!(exact_large.mapping_length() >= exact_large.allocation_size() + 128 * KIB);

        let over_large =
            OsAlignedPageLayout::new(config, 4 * MIB + 1, 128 * KIB).unwrap();
        assert_eq!(over_large.page_map_size(), 4 * MIB - 64 * KIB);
        assert!(over_large.mapping_length() > over_large.page_map_size());
    }

    #[test]
    fn live_claim_commits_only_the_derived_ranges_and_releases_explicitly() {
        let claim = OsAlignedPageClaim::allocate(config(4 * KIB), 4 * KIB, 128 * KIB)
            .expect("OS-aligned singleton claim");
        let base = claim.base().unwrap();
        let slice_start = claim.slice_start().unwrap();
        let metadata = claim.metadata().unwrap();
        assert_eq!(base.addr() % PAGE_META_ALIGNMENT, 0);
        assert_eq!(slice_start.as_ptr().addr() % (128 * KIB), 0);
        assert_eq!(
            metadata.as_ptr().addr(),
            base.addr() + 2 * size_of::<Page>()
        );
        let memory = claim.memory_id().unwrap();
        assert!(memory.is_os());
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        assert_eq!(memory.size(), Some(192 * KIB));

        // SAFETY: both bytes lie inside ranges committed by this live claim.
        unsafe {
            base.write(0x51);
            slice_start.as_ptr().write(0x73);
            assert_eq!(base.read(), 0x51);
            assert_eq!(slice_start.as_ptr().read(), 0x73);
        }
        claim.release().unwrap();
    }
}
