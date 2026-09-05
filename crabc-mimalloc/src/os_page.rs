// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/alloc-aligned.c:68-145`,
// `src/arena.c:781-870,951-1120,1160-1297,1433-1444`,
// `src/os.c:87-97,258-294,453-467`,
// `src/page-map.c:460-496`, and `include/mimalloc/internal.h:772-793`.

//! OS ownership for ordinary pages and alignment-forced singletons.
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
//!
//! The paired ordinary path takes an explicit process VM owner; copied page
//! provenance alone cannot recreate that policy/statistics lifetime. Normal
//! release excludes the metadata prefix from committed-byte accounting. The
//! on-demand OS fallback keeps its page-area prefix separate from that
//! metadata commitment: it cannot publish a capacity or free-list link until
//! the initial prefix is actually writable, and terminal release accounts the
//! exact prefix rather than the reserved mapping suffix. Failed syscall
//! ownership survives without repeating its accounting event.
//! This is M2 backing ownership; normal M3 queue/free-list callers still own
//! page publication, retirement, and the choice of source commitment branch.

use core::mem::size_of;
use core::ptr::NonNull;

use crabc_core::Errno;

use crate::config::{
    ARENA_SLICE_SIZE, LARGE_PAGE_SIZE, LARGE_MAX_OBJ_SIZE, PAGE_MAX_OVERALLOC_ALIGN,
    PAGE_META_ALIGNMENT,
};
use crate::invariants;
use crate::os::{MapAccess, Mapping, MemoryConfig, NormalOsAllocation, VmProcess};
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
    process: Option<VmProcess<'static>>,
    initially_committed: bool,
    /// The exact source page-area commitment to remove if this private claim
    /// rolls back. Metadata commitment is deliberately excluded because its
    /// source call passes it as `stat_already_committed`.
    release_commit_size: usize,
    release_state: OsPageReleaseState,
    ready: bool,
}

/// A paired failed full release was already accounted and may be retried
/// raw. A failed aligned-map trim may instead have accounted only a prefix
/// or suffix: retain it terminally rather than invent a second full-range
/// accounting transition from an incomplete normal-allocation memory ID.
#[derive(Clone, Copy)]
enum OsPageReleaseState {
    Unaccounted,
    Accounted,
    RetainedAlignmentFailure(Errno),
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
    process: Option<VmProcess<'static>>,
    release_commit_size: usize,
    release_accounted: bool,
}

/// Non-owning geometry for one live process-owned on-demand OS page.
///
/// This validates the copied `MemoryId` and aligned page metadata without
/// reconstructing its terminal mapping-release capability. The page engine
/// uses it only while it exclusively owns a live page's next prefix
/// transition, then passes the derived subrange to
/// `Mapping::commit_published_for_process`.
#[derive(Clone, Copy)]
pub(crate) struct PublishedOnDemandOsPageArea {
    slice_start: NonNull<u8>,
    size: usize,
}

impl PublishedOnDemandOsPageArea {
    #[inline]
    pub(crate) const fn slice_start(self) -> NonNull<u8> { self.slice_start }

    #[inline]
    pub(crate) const fn size(self) -> usize { self.size }
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
    fn legacy(mapping: Mapping, layout: OsAlignedPageLayout, ready: bool) -> Self {
        Self {
            mapping,
            layout,
            process: None,
            initially_committed: true,
            release_commit_size: 0,
            release_state: OsPageReleaseState::Unaccounted,
            ready,
        }
    }

    /// Allocates the fully committed source ordinary/aligned OS-page area using one process
    /// pair. The caller has already exhausted the eligible arena route.
    /// Requested-arena and disallow-OS refusal remain checked here before VM
    /// ownership is acquired. Metadata commitment excludes its bytes from
    /// source statistics; the page-area commit counts its complete extent.
    /// This is the source `commit == true` branch, including all singletons;
    /// page-on-demand policy must not call it to represent an uncommitted area.
    pub(crate) fn allocate_for_process(
        process: VmProcess<'static>, config: MemoryConfig, block_size: usize,
        alignment: usize, requested: crate::arena::ArenaId,
    ) -> Result<Self, OsAlignedPageAllocationFailure> {
        let failed = |error| OsAlignedPageAllocationFailure::released(
            OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error));
        if process.policy().disallow_os_alloc() || !requested.as_ptr().is_null() {
            return Err(failed(Errno::NOMEM));
        }
        let layout = OsAlignedPageLayout::for_fresh_page(config, block_size, alignment)
            .ok_or_else(|| failed(Errno::INVAL))?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            layout.mapping_length(), PAGE_META_ALIGNMENT, MapAccess::Reserved, false, None);
        let mapping = match allocation {
            Ok(allocation) => allocation.into_mapping_and_memory().0,
            Err(failure) => {
                let error = failure.error();
                return match failure.into_mapping() {
                    None => Err(failed(error)),
                    Some(mapping) => Err(OsAlignedPageAllocationFailure::with_claim(
                        OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error),
                        Self {
                            mapping,
                            layout,
                            process: Some(process),
                            initially_committed: false,
                            release_commit_size: 0,
                            ready: false,
                            release_state: OsPageReleaseState::RetainedAlignmentFailure(error),
                        })),
                };
            }
        };
        let mut claim = Self {
            mapping,
            layout,
            process: Some(process),
            initially_committed: true,
            // Preserve the existing source full-commit release accounting:
            // the mapping suffix from `slice_start` is its source extent.
            release_commit_size: layout.mapping_length(),
            release_state: OsPageReleaseState::Unaccounted,
            ready: false,
        };
        let metadata_size = layout.metadata_commit_size();
        let result = claim.mapping.commit_for_process(process, 0, metadata_size, metadata_size)
            .map_err(|error| (OsAlignedPageFailureStage::MetadataCommit, error))
            .and_then(|_| claim.mapping.commit_for_process(process, layout.alignment(), layout.allocation_size(), 0)
                .map_err(|error| (OsAlignedPageFailureStage::BlockCommit, error)));
        if let Err((stage, error)) = result {
            return match claim.release() {
                Ok(()) => Err(OsAlignedPageAllocationFailure::released(OsAlignedPageError::new(stage, error))),
                Err(failure) => {
                    let cleanup = failure.error().operation();
                    let OsAlignedPageOwner::Claim(claim) = failure.into_owner() else {
                        unreachable!("unpublished claim cleanup retains that exact claim");
                    };
                    Err(OsAlignedPageAllocationFailure::with_claim(
                        OsAlignedPageError::with_cleanup(stage, error, Some(cleanup)), claim))
                }
            };
        }
        if !claim.mapping.initially_zero() {
            // SAFETY: the successful metadata commit makes this complete
            // still-private prefix writable before any Page is published.
            unsafe { core::ptr::write_bytes(claim.mapping.base().unwrap(), 0, metadata_size); }
        }
        claim.ready = true;
        Ok(claim)
    }

    /// Reserves the source OS fallback for a regular on-demand page.
    ///
    /// Pinned `arena.c` commits only its aligned metadata prefix here, then
    /// mistakenly records `memid.initially_committed = true` even though the
    /// block span is still `PROT_NONE`. That causes `mi_page_extend_free` to
    /// write its first free-list links before the backing is accessible. The
    /// native correction retains the same reservation and metadata commit,
    /// but keeps the commitment state false until
    /// [`Self::commit_initial_page_prefix`] succeeds. It does not change the
    /// source option policy or make an eager full-commit substitution.
    pub(crate) fn allocate_on_demand_for_process(
        process: VmProcess<'static>, config: MemoryConfig, block_size: usize,
        alignment: usize, requested: crate::arena::ArenaId,
    ) -> Result<Self, OsAlignedPageAllocationFailure> {
        let failed = |error| OsAlignedPageAllocationFailure::released(
            OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error));
        if process.policy().disallow_os_alloc() || !requested.as_ptr().is_null() {
            return Err(failed(Errno::NOMEM));
        }
        let layout = OsAlignedPageLayout::for_fresh_page(config, block_size, alignment)
            .ok_or_else(|| failed(Errno::INVAL))?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            layout.mapping_length(), PAGE_META_ALIGNMENT, MapAccess::Reserved, false, None);
        let mapping = match allocation {
            Ok(allocation) => allocation.into_mapping_and_memory().0,
            Err(failure) => {
                let error = failure.error();
                return match failure.into_mapping() {
                    None => Err(failed(error)),
                    Some(mapping) => Err(OsAlignedPageAllocationFailure::with_claim(
                        OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error),
                        Self {
                            mapping,
                            layout,
                            process: Some(process),
                            initially_committed: false,
                            release_commit_size: 0,
                            ready: false,
                            release_state: OsPageReleaseState::RetainedAlignmentFailure(error),
                        })),
                };
            }
        };
        let mut claim = Self {
            mapping,
            layout,
            process: Some(process),
            initially_committed: false,
            release_commit_size: 0,
            release_state: OsPageReleaseState::Unaccounted,
            ready: false,
        };
        let metadata_size = layout.metadata_commit_size();
        if let Err(error) = claim.mapping.commit_for_process(
            process,
            0,
            metadata_size,
            metadata_size,
        ) {
            return match claim.release() {
                Ok(()) => Err(OsAlignedPageAllocationFailure::released(
                    OsAlignedPageError::new(OsAlignedPageFailureStage::MetadataCommit, error),
                )),
                Err(failure) => {
                    let cleanup = failure.error().operation();
                    let OsAlignedPageOwner::Claim(claim) = failure.into_owner() else {
                        unreachable!("unpublished claim cleanup retains that exact claim");
                    };
                    Err(OsAlignedPageAllocationFailure::with_claim(
                        OsAlignedPageError::with_cleanup(
                            OsAlignedPageFailureStage::MetadataCommit,
                            error,
                            Some(cleanup),
                        ),
                        claim,
                    ))
                }
            };
        }
        if !claim.mapping.initially_zero() {
            // SAFETY: only the metadata prefix is accessible at this point;
            // no page or free-list metadata is published yet.
            unsafe { core::ptr::write_bytes(claim.mapping.base().unwrap(), 0, metadata_size); }
        }
        claim.ready = true;
        Ok(claim)
    }

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
                        Self::legacy(mapping, layout, false),
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
                    Self::legacy(mapping, layout, false),
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
                    Self::legacy(mapping, layout, false),
                ))
            } else {
                Err(OsAlignedPageAllocationFailure::released(failure))
            };
        }

        Ok(Self::legacy(mapping, layout, true))
    }

    #[inline]
    pub(crate) const fn layout(&self) -> OsAlignedPageLayout {
        self.layout
    }

    /// Commits the first regular-page prefix while this claim still retains
    /// its `Mapping` capability.
    ///
    /// This precedes page metadata capacity/free-list publication. A failure
    /// leaves both `initially_committed` and `release_commit_size` unchanged,
    /// so private rollback releases only the reservation and cannot publish a
    /// fictitious accessible page span.
    pub(crate) fn commit_initial_page_prefix(
        &mut self,
        size: usize,
    ) -> Result<(), OsAlignedPageError> {
        let Some(process) = self.process else {
            return Err(OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, Errno::INVAL));
        };
        if !self.ready
            || self.initially_committed
            || self.release_commit_size != 0
            || size == 0
            || size > self.layout.allocation_size()
        {
            return Err(OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, Errno::INVAL));
        }
        self.mapping
            .commit_for_process(process, self.layout.alignment(), size, 0)
            .map_err(|error| OsAlignedPageError::new(OsAlignedPageFailureStage::BlockCommit, error))?;
        self.release_commit_size = size;
        Ok(())
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
    /// A full source OS page records `initially_committed` after both commit
    /// transitions. The on-demand correction instead retains false here and
    /// records its successful prefix in `Page::slice_pcommitted`.
    pub(crate) fn memory_id(&self) -> Result<MemoryId, OsAlignedPageError> {
        if !self.ready {
            return Err(OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, Errno::INVAL));
        }
        Ok(MemoryId::os(
            self.base()?,
            self.layout.mapping_length(),
            self.initially_committed,
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
        let result = match (self.process, self.release_state) {
            (_, OsPageReleaseState::RetainedAlignmentFailure(error)) => Err(error),
            (Some(process), OsPageReleaseState::Unaccounted) => {
                self.release_state = OsPageReleaseState::Accounted;
                self.mapping.unmap_for_process(process, self.release_commit_size, false)
            }
            _ => self.mapping.unmap(),
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error),
                owner: OsAlignedPageOwner::Claim(self),
            }),
        }
    }
}

struct PublishedOsPageGeometry {
    memory: MemoryId,
    layout: OsAlignedPageLayout,
    base: NonNull<u8>,
    slice_start: NonNull<u8>,
}

/// Reconstructs only the immutable geometry of a live published normal OS
/// page. This deliberately carries no terminal release capability: extension
/// callers need a bounded raw commit span, whereas `PublishedOsAlignedPage`
/// is constructed only at an actual release boundary.
///
/// # Safety
///
/// `primary` must remain live and exclusively stable while its copied memory
/// identity and aligned metadata fields are read. `process_backed` selects the
/// ordinary process OS-page layout, whose regular-page alignment is valid only
/// for the paired process allocation route.
unsafe fn published_os_page_geometry(
    config: MemoryConfig,
    primary: NonNull<Page>,
    process_backed: bool,
) -> Option<PublishedOsPageGeometry> {
    // SAFETY: forwarded from this helper's stable-page contract.
    let page = unsafe { primary.as_ref() };
    if page.aligned_alias_owner() != primary.as_ptr()
        || (!process_backed && page.reserved() != 1)
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
    let layout = if process_backed {
        OsAlignedPageLayout::for_fresh_page(config, block_size, alignment)?
    } else {
        OsAlignedPageLayout::new(config, block_size, alignment)?
    };
    if layout.mapping_length() != os.size
        || layout.reserved() != page.reserved()
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
    Some(PublishedOsPageGeometry {
        memory,
        layout,
        base,
        slice_start,
    })
}

/// Returns the one source page area that a process-owned on-demand OS page
/// may commit after its `Mapping` has been published.
///
/// # Safety
///
/// `primary` must be a live, exclusively owned page whose original process
/// mapping was transferred by `OsAlignedPageClaim::into_published`. The caller
/// must retain the matching `VmProcess` and prove that its next prefix does
/// not race page release or another commitment transition.
pub(crate) unsafe fn published_on_demand_os_page_area_for_process(
    config: MemoryConfig,
    primary: NonNull<Page>,
) -> Option<PublishedOnDemandOsPageArea> {
    // SAFETY: forwarded from this helper's live-page contract.
    let page = unsafe { primary.as_ref() };
    if page.memid().initially_committed() || page.slice_pcommitted() == 0 {
        return None;
    }
    // SAFETY: this helper's caller retains the same stable primary.
    let geometry = unsafe { published_os_page_geometry(config, primary, true) }?;
    let committed = usize::from(page.slice_pcommitted())
        .checked_mul(config.page_size().bytes())?;
    if committed > geometry.layout.allocation_size() {
        return None;
    }
    Some(PublishedOnDemandOsPageArea {
        slice_start: geometry.slice_start,
        size: geometry.layout.allocation_size(),
    })
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
        unsafe { Self::from_page_with_process(config, primary, None) }
    }

    /// Reconstructs the exact ordinary/aligned process OS-page release right.
    ///
    /// # Safety
    ///
    /// The page and aliases must be live, and the caller must own the unique
    /// terminal release right from allocate_for_process/into_published under
    /// this exact pair. No concurrent metadata/PageMap writer may overlap.
    pub(crate) unsafe fn from_page_for_process(
        process: VmProcess<'static>, config: MemoryConfig, primary: NonNull<Page>,
    ) -> Option<Self> {
        unsafe { Self::from_page_with_process(config, primary, Some(process)) }
    }

    unsafe fn from_page_with_process(
        config: MemoryConfig, primary: NonNull<Page>, process: Option<VmProcess<'static>>,
    ) -> Option<Self> {
        // SAFETY: the caller proves `primary` is live and exclusively owned.
        let page = unsafe { primary.as_ref() };
        // SAFETY: this release constructor retains the live primary while it
        // validates its immutable source geometry.
        let geometry = unsafe { published_os_page_geometry(config, primary, process.is_some()) }?;
        let release_commit_size = if process.is_some() {
            if geometry.memory.initially_committed() {
                if page.slice_pcommitted() != 0 {
                    return None;
                }
                geometry.layout.mapping_length().checked_sub(geometry.layout.alignment())?
            } else {
                let committed = usize::from(page.slice_pcommitted())
                    .checked_mul(config.page_size().bytes())?;
                if committed == 0 || committed > geometry.layout.allocation_size() {
                    return None;
                }
                committed
            }
        } else {
            if page.slice_pcommitted() != 0 {
                return None;
            }
            0
        };
        Some(Self {
            memory: geometry.memory,
            layout: geometry.layout,
            base: geometry.base,
            slice_start: geometry.slice_start,
            primary,
            process,
            release_commit_size,
            release_accounted: false,
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
    pub(crate) unsafe fn reclaim(mut self) -> Result<(), OsAlignedPageReleaseFailure> {
        // SAFETY: the method contract preserves the original published base,
        // exact rounded length, and unique terminal ownership.
        let result = if let Some(process) = self.process.filter(|_| !self.release_accounted) {
            self.release_accounted = true;
            // Full OS pages preserve the existing source suffix accounting.
            // The native on-demand correction instead subtracts only the
            // prefix that reached a successful page-area commit; metadata
            // commitment was never included in the source statistic.
            unsafe { Mapping::reclaim_published_for_process(process, self.base.as_ptr(),
                self.layout.mapping_length(), self.release_commit_size, false) }
        } else {
            unsafe { Mapping::reclaim_published(self.base.as_ptr(), self.layout.mapping_length()) }
        };
        match result {
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
    extern crate std;
    use super::*;
    use crate::config::{KIB, MIB};
    use crate::os::{PageSize, fault};
    use crabc_core::Errno;

    fn process(disallow_os: bool) -> VmProcess<'static> {
        use crate::config::{VmOptions, VmOption, VmOptionEnvironment};
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::DisallowOsAlloc, i64::from(disallow_os));
        let policy = std::boxed::Box::leak(std::boxed::Box::new(crate::os::VmPolicy::new(options).unwrap()));
        policy.finish_preloading();
        VmProcess::new(policy, crate::subproc::MainSubprocess::test_static_owner())
    }

    #[test]
    fn paired_published_os_page_release_excludes_prefix_and_accounts_failed_release_once() {
        use crate::bootstrap::ExclusiveTheapBootstrap;
        let fault = fault::install(fault::Plan::disabled());
        let process = process(false);
        let mut bootstrap = std::boxed::Box::pin(ExclusiveTheapBootstrap::new());
        let mut session = bootstrap.as_mut().activate_detached_for_main_subprocess(process.subprocess()).unwrap();
        for (block, alignment) in [(16, 1), (4096, 1), (64 * MIB, 1), (4096, 128 * KIB)] {
            let before = process.subprocess().vm_statistics().snapshot();
            let claim = OsAlignedPageClaim::allocate_for_process(process, config(4 * KIB), block,
                alignment, crate::arena::ArenaId::none()).unwrap_or_else(|_| panic!("paired fresh OS page"));
            let layout = claim.layout();
            let memory = claim.memory_id().unwrap();
            let mut primary = unsafe { session.publish_fresh_page(claim.metadata().unwrap(), block,
                layout.page_offset(), layout.reserved(), 0, memory.initially_zero(), memory) }.unwrap();
            assert!(unsafe { claim.publish_secondary_metadata(primary) });
            let token = unsafe { PublishedOsAlignedPage::from_page_for_process(process, config(4 * KIB), primary) }
                .expect("ordinary and aligned page metadata retains exact paired release geometry");
            assert!(unsafe { claim.clear_secondary_metadata(primary) });
            assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
            claim.into_published().unwrap();
            fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
            let failure = unsafe { token.reclaim() }.err().expect("first release fault retains its token");
            let after = process.subprocess().vm_statistics().snapshot();
            assert_eq!(after.reserved_current, before.reserved_current);
            assert_eq!(after.committed_current - before.committed_current,
                layout.allocation_size() as i64 - (layout.mapping_length() - layout.alignment()) as i64,
                "source published release subtracts only the mapping suffix at slice_start");
            fault.set(fault::Plan::disabled());
            assert!(unsafe { failure.into_owner().release() }.is_ok());
            assert_eq!(process.subprocess().vm_statistics().snapshot(), after,
                "raw retry must not apply a second source accounting event");
        }
    }

    #[test]
    fn paired_fresh_os_page_commit_failure_retains_accounted_cleanup_owner() {
        let fault = fault::install(fault::Plan::disabled());
        for commit_call in [1, 2] {
            let process = process(false);
            let before = process.subprocess().vm_statistics().snapshot();
            fault.set(fault::Plan::at_pair(fault::Point::Commit, commit_call,
                fault::Point::Unmap, 1, Errno::NOMEM));
            let failure = OsAlignedPageClaim::allocate_for_process(process, config(4 * KIB), 4096,
                1, crate::arena::ArenaId::none()).err().expect("commit fault");
            assert_eq!(failure.error().cleanup(), Some(Errno::NOMEM));
            let OsAlignedPageOwner::Claim(claim) = failure.into_owner().expect("retained mapping") else { panic!("private claim") };
            assert!(claim.memory_id().is_err(), "failed commitment cannot publish a valid page");
            let after = process.subprocess().vm_statistics().snapshot();
            assert_eq!(after.reserved_current, before.reserved_current);
            assert_eq!(after.committed_current - before.committed_current, -(claim.layout().mapping_length() as i64));
            fault.set(fault::Plan::disabled());
            assert!(claim.release().is_ok());
            assert_eq!(process.subprocess().vm_statistics().snapshot(), after);
        }
    }

    #[test]
    fn paired_fresh_os_page_policy_refusal_acquires_no_mapping() {
        let process = process(true);
        let before = process.subprocess().vm_statistics().snapshot();
        let failure = OsAlignedPageClaim::allocate_for_process(process, config(4 * KIB), 64 * MIB,
            1, crate::arena::ArenaId::none()).err().expect("source disallow OS refusal");
        assert!(failure.into_owner().is_none());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
    }

    #[cfg(not(miri))]
    #[test]
    fn paired_alignment_trim_failure_is_retained_without_inventing_full_release_accounting() {
        // Reject the direct map so the overmap must trim at least one end,
        // independent of randomized native mmap placement.
        let fault = fault::install(fault::Plan::at_pair(fault::Point::Map, 1,
            fault::Point::Unmap, 1, Errno::NOMEM));
        let process = process(false);
        let config = config(4 * KIB);
        let failure = OsAlignedPageClaim::allocate_for_process(process, config, 4096,
            1, crate::arena::ArenaId::none()).err().expect("source aligned trim failure");
        let OsAlignedPageOwner::Claim(claim) = failure.into_owner().expect("retained trim owner") else { panic!("private claim") };
        assert!(claim.memory_id().is_err());
        let after = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::disabled());
        let retained = claim.release().err().expect("partial trim accounting is not a complete free token");
        assert_eq!(process.subprocess().vm_statistics().snapshot(), after);
        // Only this isolated test dismantles its terminal fixture. Production
        // retains the exact owner until aligned trim recovery is represented;
        // it must not synthesize a whole-map accounting correction.
        let OsAlignedPageOwner::Claim(mut claim) = retained.into_owner() else { panic!("private claim") };
        assert!(claim.mapping.unmap().is_ok());
    }

    #[test]
    fn emit_native_fresh_os_page_ownership_trace() {
        use crate::bootstrap::ExclusiveTheapBootstrap;
        let process = process(false);
        let mut bootstrap = std::boxed::Box::pin(ExclusiveTheapBootstrap::new());
        let mut session = bootstrap.as_mut().activate_detached_for_main_subprocess(process.subprocess()).unwrap();
        let mut ordinal = 0;
        for alignment in [1, 128 * KIB] {
            for block in [16, 4096, 16384, 128 * KIB, MIB, 8 * MIB, 64 * MIB] {
                let before = process.subprocess().vm_statistics().snapshot();
                let claim = OsAlignedPageClaim::allocate_for_process(process, config(4 * KIB), block,
                    alignment, crate::arena::ArenaId::none()).unwrap_or_else(|_| panic!("paired source OS page"));
                let layout = claim.layout();
                let memory = claim.memory_id().unwrap();
                let mut primary = unsafe { session.publish_fresh_page(claim.metadata().unwrap(), block,
                    layout.page_offset(), layout.reserved(), 0, memory.initially_zero(), memory) }.unwrap();
                assert!(unsafe { claim.publish_secondary_metadata(primary) });
                // The complete block area is writable, including the far
                // end of the 64 MiB source singleton that the old arena-only
                // metadata engine cannot obtain.
                let start = claim.slice_start().unwrap().as_ptr();
                unsafe {
                    assert_eq!(start.read(), 0);
                    assert_eq!(start.add(layout.allocation_size() - 1).read(), 0);
                    start.write(0x5a);
                    start.add(layout.allocation_size() - 1).write(0xa5);
                }
                let allocated = process.subprocess().vm_statistics().snapshot();
                let token = unsafe { PublishedOsAlignedPage::from_page_for_process(process, config(4 * KIB), primary) }.unwrap();
                assert!(unsafe { claim.clear_secondary_metadata(primary) });
                assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
                claim.into_published().unwrap();
                assert!(unsafe { token.reclaim() }.is_ok());
                let released = process.subprocess().vm_statistics().snapshot();
                for value in [allocated.reserved_current - before.reserved_current,
                    allocated.committed_current - before.committed_current,
                    allocated.commit_calls - before.commit_calls,
                    released.reserved_current - before.reserved_current,
                    released.committed_current - before.committed_current] {
                    std::println!("m2.arena.os_owner.{ordinal}={value}");
                    ordinal += 1;
                }
            }
        }
        assert_eq!(ordinal, 70);
    }

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
