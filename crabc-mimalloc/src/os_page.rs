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
//!
//! [`OsAlignedPageLayout::for_fresh_page`] also computes the same source
//! prefix, regular-page capacity, aliases, and clipped PageMap range for
//! ordinary OS-backed pages. The existing `new`/`allocate` entry points retain
//! their large-alignment-only contract; process-policy backing consumes the
//! generalized geometry separately.

use core::mem::size_of;
use core::ptr::NonNull;

use crabc_core::Errno;

use crate::config::{
    ARENA_SLICE_SIZE, LARGE_PAGE_SIZE, LARGE_MAX_OBJ_SIZE, PAGE_MAX_OVERALLOC_ALIGN,
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
    reserved: u16,
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
        Self::for_fresh_page(config, block_size, alignment)
    }

    /// Source `mi_arenas_page_alloc_fresh_area` geometry for both ordinary
    /// pages and alignment-forced singletons. The metadata prefix is at least
    /// one source slice even when the requested block alignment is one.
    /// This selects no arena or VM policy and transfers no backing ownership.
    pub(crate) fn for_fresh_page(
        config: MemoryConfig,
        block_size: usize,
        block_alignment: usize,
    ) -> Option<Self> {
        if block_size == 0 || block_alignment == 0
            || block_alignment >= PAGE_META_ALIGNMENT
            || !invariants::is_power_of_two(block_alignment)
        {
            return None;
        }
        let singleton = block_alignment > PAGE_MAX_OVERALLOC_ALIGN || block_size > LARGE_MAX_OBJ_SIZE;
        let slice_count = if singleton {
            page::singleton_page_slice_count(block_size)?
        } else {
            page::regular_page_slice_count(crate::size_class::page_kind_for_block_size(block_size)?)?
        };
        // `alignment` historically names the OS-aligned prefix. For ordinary
        // pages the same source quantity is max(block_alignment, PAGE_ALIGN).
        let alignment = block_alignment.max(ARENA_SLICE_SIZE);

        let allocation_size = invariants::size_of_slices(slice_count)?;
        let requested_mapping_length = allocation_size.checked_add(alignment)?;
        let mapping_length = config.good_alloc_size(requested_mapping_length);
        if mapping_length < requested_mapping_length
            || mapping_length % config.page_size().bytes() != 0
        {
            return None;
        }

        let metadata_slot_count = if singleton && slice_count > 2 { 2 } else { slice_count };
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
        let reserved = if block_alignment > PAGE_MAX_OVERALLOC_ALIGN {
            1
        } else {
            u16::try_from(allocation_size.checked_sub(block_start_offset)? / block_size).ok()?
        };
        if reserved == 0 { return None; }
        let page_offset = alignment
            .checked_add(block_start_offset)?
            .checked_sub(metadata_offset)?;

        // `mi_page_map_get_idx` deliberately clips huge-page registration to
        // one less than a large page. The complete mapping extent remains in
        // `MemoryId`; page-map reachability and OS ownership are not the same
        // span for blocks above 4 MiB.
        let area_size = block_size.checked_mul(usize::from(reserved))?;
        let mapped_area_size = if area_size > LARGE_PAGE_SIZE {
            LARGE_PAGE_SIZE.checked_sub(ARENA_SLICE_SIZE)?
        } else {
            area_size
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
            reserved,
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

    #[inline]
    pub(crate) const fn reserved(self) -> u16 { self.reserved }
}

#[cfg(test)]
mod ordinary_layout_tests {
    extern crate std;
    use super::*;
    use crate::os::PageSize;

    #[test]
    fn emit_native_fresh_os_page_geometry_trace() {
        let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(),
            1 << 20, false, false);
        let mut ordinal = 0;
        for alignment in [1, 128 * 1024] {
            for block_size in [16, 4096, 16384, 128 * 1024, 1024 * 1024,
                               8 * 1024 * 1024, 64 * 1024 * 1024] {
                let layout = OsAlignedPageLayout::for_fresh_page(config, block_size, alignment).unwrap();
                for value in [block_size, usize::from(layout.reserved()), layout.mapping_length(),
                              layout.alignment(), layout.metadata_offset(), layout.page_offset(),
                              layout.page_map_size()] {
                    std::println!("m2.arena.os_page.{ordinal}={value}");
                    ordinal += 1;
                }
                assert!(layout.metadata_commit_size() < layout.alignment());
                assert!(layout.page_map_size() <= layout.allocation_size());
                if alignment > PAGE_MAX_OVERALLOC_ALIGN { assert_eq!(layout.reserved(), 1); }
            }
        }
        assert_eq!(ordinal, 98);
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

/// The single, allocation-free owner of an OS-aligned singleton mapping after
/// it can no longer remain on a normal page queue.
///
/// An unpublished claim is still responsible for its mapping and any private
/// fresh-page rollback. A published token is admitted here only after page-map
/// entries, aliases, and primary metadata have been detached. Neither variant
/// has a destructor: callers must retry [`Self::release`] explicitly.
pub(crate) enum OsAlignedPageOwner {
    Claim(OsAlignedPageClaim),
    Published(PublishedOsAlignedPage),
}

/// One failed exact OS-aligned mapping release which retains its unique owner.
pub(crate) struct OsAlignedPageReleaseFailure {
    error: OsAlignedPageError,
    owner: OsAlignedPageOwner,
}

impl OsAlignedPageReleaseFailure {
    #[inline]
    pub(crate) const fn error(&self) -> OsAlignedPageError {
        self.error
    }

    #[inline]
    pub(crate) fn into_owner(self) -> OsAlignedPageOwner {
        self.owner
    }
}

/// A fresh OS-aligned claim failure which may retain a live rollback owner.
///
/// A map failure owns nothing. If a metadata/block commit fails and its
/// mandatory explicit `unmap` also fails, this value carries the live claim so
/// the allocator can park and retry it instead of losing the mapping.
pub(crate) struct OsAlignedPageAllocationFailure {
    error: OsAlignedPageError,
    claim: Option<OsAlignedPageClaim>,
}

impl OsAlignedPageAllocationFailure {
    #[inline]
    fn released(error: OsAlignedPageError) -> Self {
        Self { error, claim: None }
    }

    #[inline]
    fn with_claim(error: OsAlignedPageError, claim: OsAlignedPageClaim) -> Self {
        Self {
            error,
            claim: Some(claim),
        }
    }

    #[inline]
    pub(crate) const fn error(&self) -> OsAlignedPageError {
        self.error
    }

    #[inline]
    pub(crate) fn into_owner(self) -> Option<OsAlignedPageOwner> {
        self.claim.map(OsAlignedPageOwner::Claim)
    }
}

impl OsAlignedPageClaim {
    /// Reserves and commits one exact source OS-aligned singleton claim.
    pub(crate) fn allocate(
        config: MemoryConfig,
        block_size: usize,
        alignment: usize,
    ) -> Result<Self, OsAlignedPageAllocationFailure> {
        let layout = OsAlignedPageLayout::new(config, block_size, alignment)
            .ok_or_else(|| {
                OsAlignedPageAllocationFailure::released(OsAlignedPageError::new(
                    OsAlignedPageFailureStage::Map,
                    Errno::INVAL,
                ))
            })?;
        let mut mapping = match Mapping::map_aligned_for_allocator(
            config,
            layout.mapping_length(),
            PAGE_META_ALIGNMENT,
            MapAccess::Reserved,
        ) {
            Ok(mapping) => mapping,
            Err(failure) => {
                let error = OsAlignedPageError::new(
                    OsAlignedPageFailureStage::Map,
                    failure.error(),
                );
                return match failure.into_mapping() {
                    None => Err(OsAlignedPageAllocationFailure::released(error)),
                    Some(mapping) => Err(OsAlignedPageAllocationFailure::with_claim(
                        error,
                        Self { mapping, layout },
                    )),
                };
            }
        };

        if let Err(error) = mapping.commit(0, layout.metadata_commit_size()) {
            let failure = OsAlignedPageError::with_cleanup(
                OsAlignedPageFailureStage::MetadataCommit,
                error,
                mapping.unmap().err(),
            );
            return if failure.cleanup().is_some() {
                Err(OsAlignedPageAllocationFailure::with_claim(
                    failure,
                    Self { mapping, layout },
                ))
            } else {
                Err(OsAlignedPageAllocationFailure::released(failure))
            };
        }
        if let Err(error) = mapping.commit(layout.alignment(), layout.allocation_size()) {
            let failure = OsAlignedPageError::with_cleanup(
                OsAlignedPageFailureStage::BlockCommit,
                error,
                mapping.unmap().err(),
            );
            return if failure.cleanup().is_some() {
                Err(OsAlignedPageAllocationFailure::with_claim(
                    failure,
                    Self { mapping, layout },
                ))
            } else {
                Err(OsAlignedPageAllocationFailure::released(failure))
            };
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
    ///
    /// An `unmap` failure returns this exact still-live claim inside
    /// [`OsAlignedPageReleaseFailure`]. The caller must park or otherwise
    /// retain it for a later explicit retry; no implicit release occurs.
    pub(crate) fn release(mut self) -> Result<(), OsAlignedPageReleaseFailure> {
        match self.mapping.unmap() {
            Ok(()) => Ok(()),
            Err(error) => Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error),
                owner: OsAlignedPageOwner::Claim(self),
            }),
        }
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
        // The bounded W03 terminal tail owns normal `MI_MEM_OS` mappings
        // created by `OsAlignedPageClaim`. Pinned `MI_MEM_OS_HUGE` has its
        // own `mi_os_free_huge_os_pages` source release. `MI_MEM_OS_REMAP`
        // falls through the generic upstream release, but this bounded
        // adapter has no corresponding remap claim/provenance owner, so both
        // stay fail-closed here rather than treating this clipped `munmap`
        // capability as theirs.
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
    pub(crate) unsafe fn reclaim(self) -> Result<(), OsAlignedPageReleaseFailure> {
        // SAFETY: the method contract preserves the original published base,
        // exact rounded length, and unique terminal ownership.
        match unsafe {
            Mapping::reclaim_published(self.base.as_ptr(), self.layout.mapping_length())
        } {
            Ok(()) => Ok(()),
            Err(error) => Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error),
                owner: OsAlignedPageOwner::Published(self),
            }),
        }
    }
}

impl OsAlignedPageOwner {
    /// Retries the exact explicit release represented by this one owner.
    ///
    /// # Safety
    ///
    /// When this is [`Self::Published`], the caller must preserve the terminal
    /// detached-page preconditions documented by [`PublishedOsAlignedPage::reclaim`].
    /// An unpublished claim remains private and has no additional precondition.
    pub(crate) unsafe fn release(self) -> Result<(), OsAlignedPageReleaseFailure> {
        match self {
            Self::Claim(claim) => claim.release(),
            // SAFETY: forwarded from this method's published-owner contract.
            Self::Published(published) => unsafe { published.reclaim() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{KIB, MIB};
    use crate::os::{PageSize, fault};
    use crabc_core::Errno;

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
                assert!(matches!(claim.release(), Ok(())));
                panic!("arena-bounded alignment must not create an OS claim");
            }
            Err(error) => error,
        };
        assert_eq!(error.error().stage(), OsAlignedPageFailureStage::Map);
        assert_eq!(error.error().operation(), Errno::INVAL);
        assert_eq!(error.error().cleanup(), None);
    }

    #[test]
    fn small_os_aligned_layout_preserves_selected_linux_profile_geometry() {
        #[cfg(target_arch = "aarch64")]
        let cases = [
            (4 * KIB, 4 * KIB),
            (16 * KIB, 16 * KIB),
            (64 * KIB, 64 * KIB),
        ];
        #[cfg(target_arch = "x86_64")]
        let cases = [
            (4 * KIB, 4 * KIB),
            (4 * KIB, 16 * KIB),
            (4 * KIB, 64 * KIB),
        ];
        for (page_size, block_size) in cases {
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
        let config = config(4 * KIB);
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
        let claim = match OsAlignedPageClaim::allocate(config(4 * KIB), 4 * KIB, 128 * KIB) {
            Ok(claim) => claim,
            Err(_) => panic!("OS-aligned singleton claim"),
        };
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
        assert!(matches!(claim.release(), Ok(())));
    }

    #[test]
    fn failed_unpublished_release_retains_one_claim_for_retry() {
        let fault = fault::install(fault::Plan::disabled());
        let claim = match OsAlignedPageClaim::allocate(config(4 * KIB), 4 * KIB, 128 * KIB) {
            Ok(claim) => claim,
            Err(_) => panic!("OS-aligned singleton claim"),
        };
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let failure = match claim.release() {
            Ok(()) => panic!("the configured unpublished release must fail"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error().stage(), OsAlignedPageFailureStage::Release);
        assert_eq!(failure.error().operation(), Errno::NOMEM);
        let owner = failure.into_owner();
        fault.set(fault::Plan::disabled());
        match owner {
            OsAlignedPageOwner::Claim(claim) => assert!(matches!(claim.release(), Ok(()))),
            OsAlignedPageOwner::Published(_) => panic!("unpublished release changed owner kind"),
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn aligned_map_prefix_cleanup_failure_transfers_the_live_claim_owner() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            2,
            Errno::NOMEM,
        ));
        let mut config = config(4 * KIB);
        config.test_force_full_aligned_map_trim();

        let failure = match OsAlignedPageClaim::allocate(config, 4 * KIB, 128 * KIB) {
            Ok(claim) => {
                let _ = claim.release();
                panic!("the forced aligned-map prefix release must fail")
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error().stage(), OsAlignedPageFailureStage::Map);
        assert_eq!(failure.error().operation(), Errno::NOMEM);
        assert_eq!(failure.error().cleanup(), None);
        let owner = failure
            .into_owner()
            .expect("a failed alignment trim retains the unpublished OS claim");

        fault.set(fault::Plan::disabled());
        match owner {
            OsAlignedPageOwner::Claim(claim) => {
                assert!(matches!(claim.release(), Ok(())), "the exact retained overmap retries")
            }
            OsAlignedPageOwner::Published(_) => {
                panic!("an unpublished alignment failure cannot publish an OS page")
            }
        }
    }

    #[test]
    fn commit_failure_with_failed_cleanup_transfers_the_live_claim_owner() {
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit,
            1,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        let failure = match OsAlignedPageClaim::allocate(config(4 * KIB), 4 * KIB, 128 * KIB) {
            Ok(claim) => {
                assert!(matches!(claim.release(), Ok(())));
                panic!("the configured metadata commit must fail");
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error().stage(), OsAlignedPageFailureStage::MetadataCommit);
        assert_eq!(failure.error().operation(), Errno::NOMEM);
        assert_eq!(failure.error().cleanup(), Some(Errno::NOMEM));
        let owner = failure.into_owner().expect("failed cleanup retains its claim");
        fault.set(fault::Plan::disabled());
        match owner {
            OsAlignedPageOwner::Claim(claim) => assert!(matches!(claim.release(), Ok(()))),
            OsAlignedPageOwner::Published(_) => panic!("commit rollback cannot publish a page"),
        }
    }

    #[test]
    fn block_commit_failure_with_failed_cleanup_retains_the_live_claim_owner() {
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit,
            2,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        let failure = match OsAlignedPageClaim::allocate(config(4 * KIB), 4 * KIB, 128 * KIB) {
            Ok(claim) => {
                assert!(matches!(claim.release(), Ok(())));
                panic!("the configured block commit must fail");
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error().stage(), OsAlignedPageFailureStage::BlockCommit);
        assert_eq!(failure.error().operation(), Errno::NOMEM);
        assert_eq!(failure.error().cleanup(), Some(Errno::NOMEM));
        let owner = failure.into_owner().expect("failed cleanup retains its claim");
        fault.set(fault::Plan::disabled());
        match owner {
            OsAlignedPageOwner::Claim(claim) => assert!(matches!(claim.release(), Ok(()))),
            OsAlignedPageOwner::Published(_) => panic!("block rollback cannot publish a page"),
        }
    }
}
