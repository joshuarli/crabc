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
//! Queue/free-list callers own page publication, retirement, and the choice
//! of source commitment branch.

use core::cell::Cell;
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
    /// Comparison-only subprocess identity for a borrowed process claim. The
    /// child image stays owned by its external context capability; release
    /// must present a fresh short-lived `VmProcess` for this exact identity.
    process_identity: Option<NonNull<crate::subproc::SubprocessIdentity>>,
    initially_committed: bool,
    /// The source commitment charged by a direct page-area rollback. Once
    /// Page metadata takes the returned slice start, rollback clips this
    /// charge by the metadata prefix instead.
    release_commit_size: usize,
    /// A Page metadata owner has taken over the returned slice start. Its
    /// rollback frees from that start and clips the committed accounting.
    page_publication_started: Cell<bool>,
    release_state: OsPageReleaseState,
    ready: bool,
}

/// A paired failed full release was already accounted and may be retried
/// raw. An aligned-map trim failure never reaches this owner: the source
/// forgets and leaks the untrimmed range and returns the aligned middle.
#[derive(Clone, Copy)]
enum OsPageReleaseState {
    Unaccounted,
    Accounted,
    /// Metadata or PageMap rollback refused its ownership precondition.
    /// The mapping must remain live; raw unmap retry is not safe.
    RetainedPublicationFailure,
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
    process_identity: Option<NonNull<crate::subproc::SubprocessIdentity>>,
    release_commit_size: usize,
    release_accounted: bool,
}

/// Non-owning geometry for one live process-owned on-demand OS page.
///
/// This validates the copied `MemoryId` and aligned page metadata without
/// reconstructing its terminal mapping-release capability. The page engine
/// uses it only while it exclusively owns a live page's next prefix
/// transition, then passes the derived subrange to
/// `VmProcess::commit_direct_page_area` without reconstructing a second
/// mapping release capability.
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
/// has a destructor: callers must retry [`Self::release`] explicitly. A claim
/// whose publication rollback refused ownership remains terminally retained;
/// retry never bypasses that unresolved metadata boundary.
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
            process_identity: None,
            initially_committed: true,
            release_commit_size: 0,
            page_publication_started: Cell::new(false),
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
        Self::allocate_for_process_with_random(process, config, block_size, alignment, requested, None)
    }

    pub(crate) fn allocate_for_process_with_random(
        process: VmProcess<'static>, config: MemoryConfig, block_size: usize,
        alignment: usize, requested: crate::arena::ArenaId,
        random: crate::os::OsRandom<'_>,
    ) -> Result<Self, OsAlignedPageAllocationFailure> {
        let failed = |error| OsAlignedPageAllocationFailure::released(
            OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error));
        if process.policy().disallow_os_alloc() || !requested.as_ptr().is_null() {
            return Err(failed(Errno::NOMEM));
        }
        let layout = OsAlignedPageLayout::for_fresh_page(config, block_size, alignment)
            .ok_or_else(|| failed(Errno::INVAL))?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            layout.mapping_length(), PAGE_META_ALIGNMENT, MapAccess::Reserved, false, random);
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
                            process_identity: Some(NonNull::from(process.subprocess())),
                            initially_committed: false,
                            release_commit_size: 0,
                            ready: false,
                            page_publication_started: Cell::new(false),
                            release_state: OsPageReleaseState::Unaccounted,
                        })),
                };
            }
        };
        let mut claim = Self {
            mapping,
            layout,
            process: Some(process),
            process_identity: Some(NonNull::from(process.subprocess())),
            initially_committed: true,
            // Before the fresh area returns its slice start, an early commit
            // failure frees from the mapping base and charges its full extent.
            release_commit_size: layout.mapping_length(),
            page_publication_started: Cell::new(false),
            release_state: OsPageReleaseState::Unaccounted,
            ready: false,
        };
        let metadata_size = layout.metadata_commit_size();
        let result = claim.mapping.commit_for_process_with_warning(process, 0, metadata_size, metadata_size)
            .map_err(|error| (OsAlignedPageFailureStage::MetadataCommit, error))
            .and_then(|_| claim.mapping.commit_for_process_with_warning(process, layout.alignment(), layout.allocation_size(), 0)
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
        // Once the block area is committed, terminal free charges that area;
        // the metadata prefix was already excluded from committed statistics.
        claim.release_commit_size = layout.allocation_size();
        claim.ready = true;
        Ok(claim)
    }

    /// Process-paired allocation for a reclaimable child identity. Unlike
    /// the process-main entry point, this claim never stores a `VmProcess`;
    /// the external child owner retains the image and supplies a short pair
    /// for accounting/release.
    /// # Safety
    /// The caller retains the exact pinned subprocess image and external
    /// context owner until this claim is either published and reclaimed or
    /// explicitly released. The returned token carries only its comparison
    /// identity, not the context lifetime.
    pub(crate) unsafe fn allocate_for_borrowed_process_with_random(
        process: VmProcess<'_>, config: MemoryConfig, block_size: usize,
        alignment: usize, requested: crate::arena::ArenaId,
        random: crate::os::OsRandom<'_>,
    ) -> Result<Self, OsAlignedPageAllocationFailure> {
        let failed = |error| OsAlignedPageAllocationFailure::released(
            OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error));
        if process.policy().disallow_os_alloc() || !requested.as_ptr().is_null() {
            return Err(failed(Errno::NOMEM));
        }
        let layout = OsAlignedPageLayout::for_fresh_page(config, block_size, alignment)
            .ok_or_else(|| failed(Errno::INVAL))?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            layout.mapping_length(), PAGE_META_ALIGNMENT, MapAccess::Reserved, false, random);
        let mapping = match allocation {
            Ok(allocation) => allocation.into_mapping_and_memory().0,
            Err(failure) => {
                let error = failure.error();
                return match failure.into_mapping() {
                    None => Err(failed(error)),
                    Some(mapping) => Err(OsAlignedPageAllocationFailure::with_claim(
                        OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error),
                        Self {
                            mapping, layout, process: None,
                            process_identity: Some(NonNull::from(process.subprocess())),
                            initially_committed: false, release_commit_size: 0, ready: false,
                            page_publication_started: Cell::new(false),
                            release_state: OsPageReleaseState::Unaccounted,
                        },
                    )),
                };
            }
        };
        let mut claim = Self {
            mapping, layout, process: None,
            process_identity: Some(NonNull::from(process.subprocess())),
            initially_committed: true, release_commit_size: layout.mapping_length(),
            page_publication_started: Cell::new(false),
            release_state: OsPageReleaseState::Unaccounted, ready: false,
        };
        let metadata_size = layout.metadata_commit_size();
        let result = claim.mapping.commit_for_process_with_warning(process, 0, metadata_size, metadata_size)
            .map_err(|error| (OsAlignedPageFailureStage::MetadataCommit, error))
            .and_then(|_| claim.mapping.commit_for_process_with_warning(process, layout.alignment(),
                layout.allocation_size(), 0)
                .map_err(|error| (OsAlignedPageFailureStage::BlockCommit, error)));
        if let Err((stage, error)) = result {
            // SAFETY: this allocation call retains the exact input process
            // identity and sole private claim through rollback.
            return match unsafe { claim.release_for_process(process) } {
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
            // SAFETY: the successful metadata commit makes this prefix writable.
            unsafe { core::ptr::write_bytes(claim.mapping.base().unwrap(), 0, metadata_size); }
        }
        claim.release_commit_size = layout.allocation_size();
        claim.ready = true;
        Ok(claim)
    }

    /// # Safety
    /// Same external subprocess-image retention obligation as
    /// [`Self::allocate_for_borrowed_process_with_random`].
    pub(crate) unsafe fn allocate_on_demand_for_borrowed_process_with_random(
        process: VmProcess<'_>, config: MemoryConfig, block_size: usize,
        alignment: usize, requested: crate::arena::ArenaId,
        random: crate::os::OsRandom<'_>,
    ) -> Result<Self, OsAlignedPageAllocationFailure> {
        let failed = |error| OsAlignedPageAllocationFailure::released(
            OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error));
        if process.policy().disallow_os_alloc() || !requested.as_ptr().is_null() {
            return Err(failed(Errno::NOMEM));
        }
        let layout = OsAlignedPageLayout::for_fresh_page(config, block_size, alignment)
            .ok_or_else(|| failed(Errno::INVAL))?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            layout.mapping_length(), PAGE_META_ALIGNMENT, MapAccess::Reserved, false, random);
        let mapping = match allocation {
            Ok(allocation) => allocation.into_mapping_and_memory().0,
            Err(failure) => {
                let error = failure.error();
                return match failure.into_mapping() {
                    None => Err(failed(error)),
                    Some(mapping) => Err(OsAlignedPageAllocationFailure::with_claim(
                        OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error),
                        Self { mapping, layout, process: None,
                            process_identity: Some(NonNull::from(process.subprocess())),
                            initially_committed: false, release_commit_size: 0, ready: false,
                            page_publication_started: Cell::new(false),
                            release_state: OsPageReleaseState::Unaccounted },
                    )),
                };
            }
        };
        let mut claim = Self { mapping, layout, process: None,
            process_identity: Some(NonNull::from(process.subprocess())),
            initially_committed: false, release_commit_size: 0,
            page_publication_started: Cell::new(false),
            release_state: OsPageReleaseState::Unaccounted, ready: false };
        let metadata_size = layout.metadata_commit_size();
        if let Err(error) = claim.mapping.commit_for_process_with_warning(process, 0, metadata_size, metadata_size) {
            // SAFETY: this allocation call retains the exact input process
            // identity and sole private claim through rollback.
            return match unsafe { claim.release_for_process(process) } {
                Ok(()) => Err(OsAlignedPageAllocationFailure::released(
                    OsAlignedPageError::new(OsAlignedPageFailureStage::MetadataCommit, error))),
                Err(failure) => {
                    let cleanup = failure.error().operation();
                    let OsAlignedPageOwner::Claim(claim) = failure.into_owner() else {
                        unreachable!("unpublished claim cleanup retains that exact claim");
                    };
                    Err(OsAlignedPageAllocationFailure::with_claim(
                        OsAlignedPageError::with_cleanup(OsAlignedPageFailureStage::MetadataCommit,
                            error, Some(cleanup)), claim))
                }
            };
        }
        if !claim.mapping.initially_zero() {
            // SAFETY: metadata commit made the complete private prefix writable.
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
        Self::allocate_on_demand_for_process_with_random(process, config, block_size, alignment, requested, None)
    }

    pub(crate) fn allocate_on_demand_for_process_with_random(
        process: VmProcess<'static>, config: MemoryConfig, block_size: usize,
        alignment: usize, requested: crate::arena::ArenaId,
        random: crate::os::OsRandom<'_>,
    ) -> Result<Self, OsAlignedPageAllocationFailure> {
        let failed = |error| OsAlignedPageAllocationFailure::released(
            OsAlignedPageError::new(OsAlignedPageFailureStage::Map, error));
        if process.policy().disallow_os_alloc() || !requested.as_ptr().is_null() {
            return Err(failed(Errno::NOMEM));
        }
        let layout = OsAlignedPageLayout::for_fresh_page(config, block_size, alignment)
            .ok_or_else(|| failed(Errno::INVAL))?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            layout.mapping_length(), PAGE_META_ALIGNMENT, MapAccess::Reserved, false, random);
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
                            process_identity: Some(NonNull::from(process.subprocess())),
                            initially_committed: false,
                            release_commit_size: 0,
                            ready: false,
                            page_publication_started: Cell::new(false),
                            release_state: OsPageReleaseState::Unaccounted,
                        })),
                };
            }
        };
        let mut claim = Self {
            mapping,
            layout,
            process: Some(process),
            process_identity: Some(NonNull::from(process.subprocess())),
            initially_committed: false,
            release_commit_size: 0,
            page_publication_started: Cell::new(false),
            release_state: OsPageReleaseState::Unaccounted,
            ready: false,
        };
        let metadata_size = layout.metadata_commit_size();
        if let Err(error) = claim.mapping.commit_for_process_with_warning(
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
                // Aligned trim failures leak (source `mi_os_prim_free`),
                // so a failed map owns nothing.
                return Err(OsAlignedPageAllocationFailure::released(error));
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
    /// makes the claim unpublishable while retaining its mapping for private
    /// rollback. It leaves `initially_committed` and `release_commit_size`
    /// unchanged, so release accounts only the reservation.
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
        if let Err(error) = self.mapping.commit_for_process_with_warning(
            process, self.layout.alignment(), size, 0,
        ) {
            self.ready = false;
            return Err(OsAlignedPageError::new(OsAlignedPageFailureStage::BlockCommit, error));
        }
        self.release_commit_size = size;
        Ok(())
    }

    /// Child counterpart of [`Self::commit_initial_page_prefix`]. The
    /// external child context supplies the process pair only for this
    /// operation; the claim itself retains no borrowed subprocess image.
    pub(crate) fn commit_initial_page_prefix_for_process(
        &mut self, process: VmProcess<'_>, size: usize,
    ) -> Result<(), OsAlignedPageError> {
        if self.process_identity != Some(NonNull::from(process.subprocess()))
            || !self.ready || self.initially_committed || self.release_commit_size != 0
            || size == 0 || size > self.layout.allocation_size()
        {
            return Err(OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, Errno::INVAL));
        }
        if let Err(error) = self.mapping.commit_for_process_with_warning(
            process, self.layout.alignment(), size, 0,
        ) {
            self.ready = false;
            return Err(OsAlignedPageError::new(OsAlignedPageFailureStage::BlockCommit, error));
        }
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
        // From this publication onward, rollback frees from the returned
        // slice start and excludes the metadata prefix from its charge.
        self.page_publication_started.set(true);
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

    /// Retains this exact mapping after publication rollback rejected an
    /// ownership precondition. Unlike an ordinary unmap failure, metadata or
    /// PageMap entries may still name the mapping, so this state has no raw
    /// release continuation. It occupies the existing sole pending owner slot.
    pub(crate) fn retain_failed_publication(mut self) -> OsAlignedPageOwner {
        self.release_state = OsPageReleaseState::RetainedPublicationFailure;
        OsAlignedPageOwner::Claim(self)
    }

    #[inline]
    fn release_committed_size(&self) -> usize {
        if self.page_publication_started.get() && self.initially_committed {
            self.layout.mapping_length() - self.layout.alignment()
        } else {
            self.release_commit_size
        }
    }

    /// Releases an unpublished claim after metadata/page rollback.
    ///
    /// An `unmap` failure returns this exact still-live claim inside
    /// [`OsAlignedPageReleaseFailure`]. The caller must park or otherwise
    /// retain it for a later explicit retry; no implicit release occurs.
    pub(crate) fn release(mut self) -> Result<(), OsAlignedPageReleaseFailure> {
        if matches!(self.release_state, OsPageReleaseState::RetainedPublicationFailure) {
            return Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, Errno::INVAL),
                owner: OsAlignedPageOwner::Claim(self),
            });
        }
        let result = match (self.process, self.release_state) {
            (Some(process), OsPageReleaseState::Unaccounted) => {
                self.release_state = OsPageReleaseState::Accounted;
                let committed = self.release_committed_size();
                self.mapping.unmap_for_process_with_warning(process, committed, false, true)
            }
            (None, OsPageReleaseState::Unaccounted) if self.process_identity.is_some() => {
                Err(Errno::INVAL)
            }
            (_, OsPageReleaseState::Accounted) => self.mapping.unmap(),
            (None, OsPageReleaseState::Unaccounted) => self.mapping.unmap(),
            (_, OsPageReleaseState::RetainedPublicationFailure) => unreachable!(),
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error),
                owner: OsAlignedPageOwner::Claim(self),
            }),
        }
    }

    /// Releases a claim whose process pair is borrowed from a reclaimable
    /// child context. The token stores only the exact identity address; the
    /// caller keeps the child owner alive and supplies a fresh short borrow.
    /// Once process accounting is applied, a failed syscall is retried with
    /// raw `Mapping::unmap`, so the borrow need not outlive this call.
    /// # Safety
    /// The caller retains the exact subprocess identity image captured by
    /// this claim, with the sole terminal release right, through this call.
    pub(crate) unsafe fn release_for_process(
        mut self,
        process: VmProcess<'_>,
    ) -> Result<(), OsAlignedPageReleaseFailure> {
        if self.process_identity != Some(NonNull::from(process.subprocess())) {
            return Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, Errno::INVAL),
                owner: OsAlignedPageOwner::Claim(self),
            });
        }
        if matches!(self.release_state, OsPageReleaseState::RetainedPublicationFailure) {
            return Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Publish, Errno::INVAL),
                owner: OsAlignedPageOwner::Claim(self),
            });
        }
        let result = match self.release_state {
            OsPageReleaseState::Unaccounted => {
                // Pinned `_mi_os_prim_free` applies statistics even when the
                // syscall fails. Latch before the call so retry is raw-only.
                self.release_state = OsPageReleaseState::Accounted;
                let committed = self.release_committed_size();
                self.mapping.unmap_for_process_with_warning(process, committed, false, true)
            }
            OsPageReleaseState::Accounted => self.mapping.unmap(),
            OsPageReleaseState::RetainedPublicationFailure => unreachable!(),
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error),
                owner: OsAlignedPageOwner::Claim(self),
            }),
        }
    }

    /// Completes a retry after process accounting already ran. This takes no
    /// process pair, preventing stale child projections from being needed by
    /// the raw unmap continuation.
    /// # Safety
    /// The caller retains the exact subprocess/context image captured by
    /// this claim and still owns the sole terminal retry transition. This is
    /// intentionally processless; it is not authority to outlive the owner.
    pub(crate) unsafe fn retry_release(mut self) -> Result<(), OsAlignedPageReleaseFailure> {
        if !matches!(self.release_state, OsPageReleaseState::Accounted) {
            return Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, Errno::INVAL),
                owner: OsAlignedPageOwner::Claim(self),
            });
        }
        match self.mapping.unmap() {
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
        unsafe { Self::from_page_with_process(config, primary, None, None, false) }
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
        unsafe { Self::from_page_with_process(config, primary, Some(process),
            Some(NonNull::from(process.subprocess())), true) }
    }

    /// Reconstructs a published-page release token for a reclaimable child.
    /// The token retains only the identity address; its external child owner
    /// must remain live through this token's terminal release.
    ///
    /// # Safety
    ///
    /// The caller owns the unique terminal right to this exact page and keeps
    /// the child context pinned until release succeeds. No concurrent
    /// metadata or PageMap writer may overlap.
    pub(crate) unsafe fn from_page_for_borrowed_process(
        process: VmProcess<'_>, config: MemoryConfig, primary: NonNull<Page>,
    ) -> Option<Self> {
        // SAFETY: forwarded from this constructor's unique page/context
        // ownership contract; `None` prevents storing the short borrow.
        unsafe { Self::from_page_with_process(config, primary, None,
            Some(NonNull::from(process.subprocess())), true) }
    }

    unsafe fn from_page_with_process(
        config: MemoryConfig, primary: NonNull<Page>, process: Option<VmProcess<'static>>,
        process_identity: Option<NonNull<crate::subproc::SubprocessIdentity>>,
        process_backed: bool,
    ) -> Option<Self> {
        // SAFETY: the caller proves `primary` is live and exclusively owned.
        let page = unsafe { primary.as_ref() };
        // SAFETY: this release constructor retains the live primary while it
        // validates its immutable source geometry.
        let geometry = unsafe { published_os_page_geometry(config, primary, process_backed) }?;
        let release_commit_size = if process_backed {
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
            process_identity,
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
        if self.process.is_none() && self.process_identity.is_some() && !self.release_accounted {
            return Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, Errno::INVAL),
                owner: OsAlignedPageOwner::Published(self),
            });
        }
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

    /// Reclaims a borrowed-process publication. The exact identity must
    /// match; accounting is latched before the first syscall, and any retry
    /// uses the process-independent raw mapping owner.
    ///
    /// # Safety
    ///
    /// Same terminal PageMap/metadata/page quiescence requirements as
    /// [`Self::reclaim`], with the child context retained by the caller.
    pub(crate) unsafe fn reclaim_for_process(
        mut self, process: VmProcess<'_>,
    ) -> Result<(), OsAlignedPageReleaseFailure> {
        if self.process_identity != Some(NonNull::from(process.subprocess())) {
            return Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, Errno::INVAL),
                owner: OsAlignedPageOwner::Published(self),
            });
        }
        // SAFETY: forwarded from the terminal release contract. The process
        // statistics edge is applied exactly once even if munmap fails.
        let result = if self.release_accounted {
            // SAFETY: retained token still owns this exact mapping.
            unsafe { Mapping::reclaim_published(self.base.as_ptr(), self.layout.mapping_length()) }
        } else {
            self.release_accounted = true;
            unsafe { Mapping::reclaim_published_for_process(process, self.base.as_ptr(),
                self.layout.mapping_length(), self.release_commit_size, false) }
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error),
                owner: OsAlignedPageOwner::Published(self),
            }),
        }
    }

    /// Raw retry after process accounting was latched by a failed first
    /// reclaim. No subprocess or context projection is required.
    ///
    /// # Safety
    /// The mapping remains uniquely owned and terminal page/metadata
    /// preconditions remain satisfied.
    pub(crate) unsafe fn retry_reclaim(
        self,
    ) -> Result<(), OsAlignedPageReleaseFailure> {
        if !self.release_accounted {
            return Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, Errno::INVAL),
                owner: OsAlignedPageOwner::Published(self),
            });
        }
        // SAFETY: caller preserves the unique published mapping release right.
        match unsafe { Mapping::reclaim_published(self.base.as_ptr(), self.layout.mapping_length()) } {
            Ok(()) => Ok(()),
            Err(error) => Err(OsAlignedPageReleaseFailure {
                error: OsAlignedPageError::new(OsAlignedPageFailureStage::Release, error),
                owner: OsAlignedPageOwner::Published(self),
            }),
        }
    }
}

impl OsAlignedPageOwner {
    /// Returns whether this owner was created for this exact subprocess.
    /// Processless owners cannot be adopted by a child context because they
    /// have no identity edge tying their retry lifetime to that context.
    #[inline]
    pub(crate) fn belongs_to_subprocess(
        &self,
        subprocess: &crate::subproc::SubprocessIdentity,
    ) -> bool {
        let expected = Some(NonNull::from(subprocess));
        match self {
            Self::Claim(claim) => claim.process_identity == expected,
            Self::Published(page) => page.process_identity == expected,
        }
    }

    #[inline]
    pub(crate) fn raw_retry_ready(&self) -> bool {
        match self {
            Self::Claim(claim) => matches!(claim.release_state, OsPageReleaseState::Accounted),
            Self::Published(page) => page.release_accounted,
        }
    }

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

    /// Releases a process-paired owner using a short-lived pair. Both owner
    /// variants validate their captured identity; after the first failed
    /// syscall, their explicit accounting latch makes retries raw-only.
    ///
    /// # Safety
    ///
    /// Published owners require the same detached-page and quiescence
    /// guarantees as [`PublishedOsAlignedPage::reclaim`]. The caller must
    /// retain the external subprocess image until this owner is released.
    pub(crate) unsafe fn release_for_process(
        self, process: VmProcess<'_>,
    ) -> Result<(), OsAlignedPageReleaseFailure> {
        match self {
            // SAFETY: forwarded from this method's exact-context obligation.
            Self::Claim(claim) => unsafe { claim.release_for_process(process) },
            // SAFETY: forwarded from this method's published-owner contract.
            Self::Published(published) => unsafe { published.reclaim_for_process(process) },
        }
    }

    /// Explicitly retries only an already-accounted owner, without a process
    /// pair. Publication-retained and unaccounted states cannot enter here.
    ///
    /// # Safety
    /// The caller retains the exact subprocess/context image captured by the
    /// owner and remains its sole terminal release owner. Published owners
    /// also retain the quiescence obligations of
    /// [`PublishedOsAlignedPage::retry_reclaim`].
    pub(crate) unsafe fn retry_release(self) -> Result<(), OsAlignedPageReleaseFailure> {
        match self {
            // SAFETY: forwarded from this method's owner-retention contract.
            Self::Claim(claim) => unsafe { claim.retry_release() },
            // SAFETY: forwarded from this method's published-owner contract.
            Self::Published(published) => unsafe { published.retry_reclaim() },
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
    use core::ffi::{c_char, c_void, CStr};
    use core::sync::atomic::{AtomicI64, AtomicPtr, Ordering};

    static FRESH_OS_CLEANUP_ENVIRONMENT: AtomicPtr<*const c_char> =
        AtomicPtr::new(core::ptr::null_mut());

    unsafe fn fresh_os_cleanup_environment() -> *const *const c_char {
        FRESH_OS_CLEANUP_ENVIRONMENT.load(Ordering::Acquire).cast_const()
    }

    unsafe extern "C" fn fresh_os_cleanup_default_output(_message: *const c_char) {}

    struct FreshOsCleanupWarnings {
        fragments: std::sync::Mutex<std::vec::Vec<std::vec::Vec<u8>>>,
        subprocess: *const crate::subproc::SubprocessIdentity,
        reserved_at_commit_warning: AtomicI64,
        reserved_at_free_warning: AtomicI64,
        committed_at_free_warning: AtomicI64,
        reserved_at_allocation_warning: AtomicI64,
        committed_at_allocation_warning: AtomicI64,
        mmap_at_allocation_warning: AtomicI64,
    }

    unsafe extern "C" fn capture_fresh_os_cleanup_warning(
        message: *const c_char, argument: *mut c_void,
    ) {
        // SAFETY: registration and delivery are synchronous; the test retains
        // the exact capture and subprocess through the complete faulted call.
        let capture = unsafe { &*(argument as *const FreshOsCleanupWarnings) };
        let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
        if bytes.starts_with(b"cannot commit OS memory")
            || bytes.starts_with(b"unable to free OS memory")
            || bytes.starts_with(b"unable to allocate OS memory") {
            let current = unsafe { &*capture.subprocess }.vm_statistics().snapshot();
            if bytes.starts_with(b"cannot commit OS memory") {
                capture.reserved_at_commit_warning.store(current.reserved_current, Ordering::Release);
            } else if bytes.starts_with(b"unable to free OS memory") {
                capture.reserved_at_free_warning.store(current.reserved_current, Ordering::Release);
                capture.committed_at_free_warning.store(current.committed_current, Ordering::Release);
            } else {
                capture.reserved_at_allocation_warning.store(current.reserved_current, Ordering::Release);
                capture.committed_at_allocation_warning.store(current.committed_current, Ordering::Release);
                capture.mmap_at_allocation_warning.store(current.mmap_calls, Ordering::Release);
            }
        }
        if let Ok(mut fragments) = capture.fragments.lock() {
            fragments.push(bytes.to_vec());
        }
    }

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
        let mut session = bootstrap.as_mut().activate_detached_for_main_subprocess(
            process.main_subprocess().expect("fixture uses process main"),
        ).unwrap();
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
    fn borrowed_process_claim_rejects_identity_mismatch_and_retries_accounted_unmap_raw() {
        let fault = fault::install(fault::Plan::disabled());
        let parent = process(false);
        let foreign = process(false);
        // SAFETY: the fixture retains the exact process image through release.
        let claim = unsafe { OsAlignedPageClaim::allocate_for_borrowed_process_with_random(
            parent, config(4 * KIB), 4096, 1, crate::arena::ArenaId::none(), None,
        ) }.unwrap_or_else(|_| panic!("child-style process pair allocates exact claim"));
        fault.set(fault::Plan::disabled());
        let owner = OsAlignedPageOwner::Claim(claim);
        assert!(owner.belongs_to_subprocess(parent.subprocess()));
        assert!(!owner.belongs_to_subprocess(foreign.subprocess()));
        // Safe child-owner retention must reject both foreign and processless
        // mappings before it stores a retry right under the child context.
        let OsAlignedPageOwner::Claim(claim) = owner else { unreachable!() };
        let before = parent.subprocess().vm_statistics().snapshot();
        let other_before = foreign.subprocess().vm_statistics().snapshot();
        // SAFETY: both process images and the unique claim remain retained.
        let mismatch = unsafe { claim.release_for_process(foreign) }.expect_err("foreign process rejected");
        assert_eq!(fault.observed(), 0, "identity rejection precedes unmap");
        assert_eq!(parent.subprocess().vm_statistics().snapshot(), before);
        assert_eq!(foreign.subprocess().vm_statistics().snapshot(), other_before);
        let OsAlignedPageOwner::Claim(claim) = mismatch.into_owner() else { panic!("claim retained"); };

        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        // SAFETY: the exact captured process image remains live.
        let failed = unsafe { claim.release_for_process(parent) }.expect_err("first unmap is injected");
        assert_eq!(fault.observed(), 1);
        let after_account = parent.subprocess().vm_statistics().snapshot();
        assert_ne!(after_account, before, "source accounting precedes syscall result");
        let OsAlignedPageOwner::Claim(claim) = failed.into_owner() else { panic!("claim retained"); };

        // SAFETY: both process images and the unique retry owner remain live.
        let mismatch = unsafe { claim.release_for_process(foreign) }.expect_err("retry identity is checked");
        assert_eq!(fault.observed(), 1, "mismatch does not issue a second unmap");
        assert_eq!(parent.subprocess().vm_statistics().snapshot(), after_account);
        let OsAlignedPageOwner::Claim(claim) = mismatch.into_owner() else { panic!("claim retained"); };
        fault.set(fault::Plan::disabled());
        // SAFETY: this test retains both subprocess images and the unique
        // claim owner through the explicit retry.
        unsafe { claim.retry_release() }
            .unwrap_or_else(|_| panic!("raw retry succeeds without process projection"));
        assert_eq!(fault.observed(), 0, "raw retry does not enter a process syscall hook");
        assert_eq!(parent.subprocess().vm_statistics().snapshot(), after_account);
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

    fn fresh_os_area_metadata_commit_relations(cleanup_fails: bool) -> [i64; 5] {
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        let show_errors = b"mimalloc_show_errors=1\0";
        let max_warnings = b"mimalloc_max_warnings=100\0";
        let environment = std::boxed::Box::leak(std::boxed::Box::new([
            show_errors.as_ptr().cast(), max_warnings.as_ptr().cast(), core::ptr::null(),
        ]));
        FRESH_OS_CLEANUP_ENVIRONMENT.store(environment.as_mut_ptr(), Ordering::Release);
        let output = std::boxed::Box::leak(std::boxed::Box::new(
            OutputOwner::new(fresh_os_cleanup_default_output)));
        // SAFETY: the leaked environment and output remain live through the
        // synchronous source option initialization and fault receiver.
        unsafe { output.initialize_source_options(fresh_os_cleanup_environment) };
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let warnings = FreshOsCleanupWarnings {
            fragments: std::sync::Mutex::new(std::vec::Vec::new()),
            subprocess: subprocess.identity(),
            reserved_at_commit_warning: AtomicI64::new(i64::MIN),
            reserved_at_free_warning: AtomicI64::new(i64::MIN),
            committed_at_free_warning: AtomicI64::new(i64::MIN),
            reserved_at_allocation_warning: AtomicI64::new(i64::MIN),
            committed_at_allocation_warning: AtomicI64::new(i64::MIN),
            mmap_at_allocation_warning: AtomicI64::new(i64::MIN),
        };
        // SAFETY: this test retains the capture for every synchronous
        // callback and does not register another output route.
        unsafe { output.register_output(Some(capture_fresh_os_cleanup_warning as OutputCallback),
            &warnings as *const FreshOsCleanupWarnings as *mut c_void) };
        warnings.fragments.lock().unwrap().clear();
        let policy = std::boxed::Box::leak(std::boxed::Box::new(
            unsafe { crate::os::VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let before = process.subprocess().vm_statistics().snapshot();
        let plan = if cleanup_fails {
            fault::Plan::at_pair(fault::Point::Commit, 1,
                fault::Point::Unmap, 1, Errno::NOMEM)
        } else {
            fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM)
        };
        let fault = fault::install(plan);
        let unmaps = fault.capture_unmap_ranges();
        let failure = OsAlignedPageClaim::allocate_for_process(
            process, config(4 * KIB), 4096, 1, crate::arena::ArenaId::none(),
        ).err().expect("metadata commit fails");
        assert_eq!(failure.error().stage(), OsAlignedPageFailureStage::MetadataCommit);
        assert_eq!(failure.error().cleanup(), cleanup_fails.then_some(Errno::NOMEM));
        let owner = failure.into_owner();
        let length = 2 * ARENA_SLICE_SIZE;
        let (ranges, count) = unmaps.all().unwrap();
        assert!(count >= 1);
        let (base, released_length) = ranges[count - 1];
        assert_eq!(released_length, length,
            "the final unmap after aligned-map setup targets the complete claim");
        let mut residency = 0;
        // SAFETY: `base` is the page-aligned range observed at the one source
        // rollback unmap; the kernel query does not dereference the address.
        let mapped = unsafe { crabc_core::mm::mincore_raw(base as *mut u8, 4096,
            &mut residency) };
        if cleanup_fails {
            let Some(OsAlignedPageOwner::Claim(claim)) = owner.as_ref() else {
                panic!("failed cleanup retains one private claim")
            };
            assert!(claim.memory_id().is_err(), "failed metadata cannot publish");
            assert_eq!(claim.mapping.base().unwrap().addr(), base);
            assert_eq!(claim.mapping.length().unwrap(), length);
            assert!(mapped.is_ok(), "failed unmap retains the complete range");
        } else {
            assert!(owner.is_none(), "successful cleanup returns no retry owner");
            assert_eq!(mapped, Err(Errno::NOMEM), "successful cleanup unmaps the range");
        }
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.reserved_current - before.reserved_current, 0);
        assert_eq!(after.committed_current - before.committed_current, -(length as i64));
        assert_eq!(after.commit_calls - before.commit_calls, 1);
        let fragments = warnings.fragments.lock().unwrap();
        let receiver: std::vec::Vec<_> = fragments.chunks_exact(2).filter(|pair|
            pair[1].starts_with(b"cannot commit OS memory")
                || pair[1].starts_with(b"unable to free OS memory")
        ).flat_map(|pair| pair.iter()).collect();
        assert_eq!(receiver.len(), if cleanup_fails { 4 } else { 2 },
            "only failed source operations warn in two fragments: {fragments:?}");
        assert!(receiver[0].starts_with(b"mimalloc: warning: thread 0x"));
        assert!(receiver[1].starts_with(b"cannot commit OS memory (error: 12 (0x0C), address: 0x"));
        assert_eq!(warnings.reserved_at_commit_warning.load(Ordering::Acquire),
            before.reserved_current + length as i64);
        if cleanup_fails {
            assert!(receiver[2].starts_with(b"mimalloc: warning: thread 0x"));
            assert!(receiver[3].starts_with(b"unable to free OS memory (error: 12 (0x0C), size: 0x20000 bytes, address: 0x"));
            assert_eq!(warnings.reserved_at_free_warning.load(Ordering::Acquire),
                before.reserved_current + length as i64);
        } else {
            assert_eq!(warnings.reserved_at_free_warning.load(Ordering::Acquire), i64::MIN);
        }
        let receiver_len = receiver.len();
        let fragments_len = fragments.len();
        drop(fragments);
        drop(unmaps);
        fault.set(fault::Plan::disabled());
        if let Some(OsAlignedPageOwner::Claim(claim)) = owner {
            assert!(claim.release().is_ok(), "the retained owner retries raw only");
        }
        assert_eq!(process.subprocess().vm_statistics().snapshot(), after);
        assert_eq!(warnings.fragments.lock().unwrap().len(), fragments_len,
            "raw retry does not repeat a source warning");
        // SAFETY: remove the stack-backed capture before its owner returns;
        // later delivery through this leaked output can use only its default.
        unsafe { output.register_output(None, core::ptr::null_mut()) };
        [length as i64, after.reserved_current - before.reserved_current,
            after.committed_current - before.committed_current,
            (after.commit_calls - before.commit_calls) as i64, receiver_len as i64]
    }

    #[test]
    fn fresh_os_area_metadata_commit_and_cleanup_failure_warns_before_accounting() {
        let values = fresh_os_area_metadata_commit_relations(true);
        assert_eq!(values, [131072, 0, -131072, 1, 4]);
    }

    #[test]
    fn fresh_os_area_metadata_commit_failure_releases_exact_range() {
        let values = fresh_os_area_metadata_commit_relations(false);
        assert_eq!(values, [131072, 0, -131072, 1, 2]);
    }

    #[test]
    fn on_demand_initial_prefix_failure_cannot_publish_and_retains_raw_retry_owner() {
        let fault = fault::install(fault::Plan::disabled());
        let process = process(false);
        let before = process.subprocess().vm_statistics().snapshot();
        let mut claim = OsAlignedPageClaim::allocate_on_demand_for_process(
            process, config(4 * KIB), 16 * KIB, 1, crate::arena::ArenaId::none(),
        ).unwrap_or_else(|_| panic!("reserved OS page with committed metadata"));
        let mapped = process.subprocess().vm_statistics().snapshot();
        assert_eq!(mapped.committed_current, before.committed_current);
        assert_eq!(mapped.reserved_current - before.reserved_current,
            claim.layout().mapping_length() as i64);

        fault.set(fault::Plan::at_pair(fault::Point::Commit, 1,
            fault::Point::Unmap, 1, Errno::NOMEM));
        let prefix = page::initial_page_slice_pcommitted(
            claim.layout().block_start_offset(), claim.layout().block_size(),
            claim.layout().allocation_size(), 4 * KIB,
        ).expect("source initial prefix") as usize * 4 * KIB;
        let error = claim.commit_initial_page_prefix(prefix).expect_err("initial commit fault");
        assert_eq!(error.stage(), OsAlignedPageFailureStage::BlockCommit);
        assert_eq!(fault.observed(), 1);
        assert!(claim.memory_id().is_err(), "failed prefix cannot supply page provenance");
        let failure = match claim.release() {
            Ok(()) => panic!("failed unmap must retain the private owner"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error().operation(), Errno::NOMEM);
        let accounted = process.subprocess().vm_statistics().snapshot();
        assert_eq!(accounted.reserved_current, before.reserved_current);
        assert_eq!(accounted.committed_current, before.committed_current);
        fault.set(fault::Plan::disabled());
        let OsAlignedPageOwner::Claim(claim) = failure.into_owner() else {
            panic!("unpublished mapping remains a claim");
        };
        assert!(claim.release().is_ok());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), accounted);
    }

    #[test]
    fn borrowed_on_demand_initial_prefix_failure_cannot_publish_or_repeat_accounting() {
        let fault = fault::install(fault::Plan::disabled());
        let process = process(false);
        let before = process.subprocess().vm_statistics().snapshot();
        let mut claim = unsafe {
            OsAlignedPageClaim::allocate_on_demand_for_borrowed_process_with_random(
                process, config(4 * KIB), 4096, 1, crate::arena::ArenaId::none(), None,
            )
        }.unwrap_or_else(|_| panic!("borrowed on-demand OS area"));
        let prefix = usize::from(page::initial_page_slice_pcommitted(
            claim.layout().block_start_offset(), claim.layout().block_size(),
            claim.layout().allocation_size(), 4 * KIB,
        ).unwrap()) * 4 * KIB;
        fault.set(fault::Plan::at_pair(fault::Point::Commit, 1,
            fault::Point::Unmap, 1, Errno::NOMEM));
        assert_eq!(claim.commit_initial_page_prefix_for_process(process, prefix)
            .expect_err("initial commit fault").stage(), OsAlignedPageFailureStage::BlockCommit);
        assert!(claim.memory_id().is_err());
        let failure = unsafe { claim.release_for_process(process) }
            .err().expect("failed unmap retains borrowed owner");
        let accounted = process.subprocess().vm_statistics().snapshot();
        assert_eq!(accounted.reserved_current, before.reserved_current);
        assert_eq!(accounted.committed_current, before.committed_current);
        let OsAlignedPageOwner::Claim(claim) = failure.into_owner() else {
            panic!("private borrowed owner remains a claim");
        };
        fault.set(fault::Plan::disabled());
        assert!(unsafe { claim.retry_release() }.is_ok());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), accounted);
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

    /// Source `mi_os_prim_alloc_aligned` in the fresh OS page caller: a
    /// failed direct, prefix, or suffix release is counted, leaked, and the
    /// claim still succeeds with its aligned mapping; its later release
    /// accounts only the returned mapping.
    #[cfg(not(miri))]
    #[test]
    fn paired_alignment_trim_failure_leaks_and_returns_a_complete_claim() {
        let process = process(false);
        let mut memory_config = config(4 * KIB);
        memory_config.test_force_full_aligned_map_trim();
        for ordinal in 1..=3 {
            let fault = fault::install(fault::Plan::at(fault::Point::Unmap, ordinal, Errno::NOMEM));
            let before = process.subprocess().vm_statistics().snapshot();
            let capture = fault.capture_unmap_ranges();
            let claim = OsAlignedPageClaim::allocate_for_process(
                process, memory_config, 4096, 1, crate::arena::ArenaId::none(),
            )
            .unwrap_or_else(|_| panic!("a failed trim release does not fail the claim"));
            let (ranges, count) = capture.all().expect("bounded releases");
            drop(capture);
            assert_eq!(count, 3, "every source release edge still runs");
            let mapping_length = claim.layout().mapping_length();
            assert_eq!(claim.mapping.base().unwrap().addr() % PAGE_META_ALIGNMENT, 0);
            assert_eq!(claim.mapping.length(), Ok(mapping_length));
            let after = process.subprocess().vm_statistics().snapshot();
            assert_eq!(after.mmap_calls - before.mmap_calls, 2);
            assert_eq!(after.reserved_current - before.reserved_current, mapping_length as i64,
                "the failed release still applied its adjustment");
            let (leaked, leaked_length) = ranges[ordinal - 1];
            let mut residency = 0u8;
            // SAFETY: `mincore` only inspects this page-aligned range.
            assert!(unsafe { crabc_core::mm::mincore_raw(leaked as *mut u8, 4 * KIB, &mut residency) }.is_ok(),
                "the failed range leaks live");
            fault.set(fault::Plan::disabled());
            assert!(claim.release().is_ok());
            let released = process.subprocess().vm_statistics().snapshot();
            assert_eq!(released.reserved_current, before.reserved_current);
            // SAFETY: the leaked range is represented by no owner.
            unsafe { crabc_core::mm::munmap_raw(leaked as *mut u8, leaked_length) }
                .expect("fixture teardown of the leaked range");
        }
    }

    /// One faulted attempt of an OS publication case: the claim, metadata,
    /// PageMap publication, and release steps under `selected`'s fault plan,
    /// then the raw retry of any retained owner. Returns the nine source
    /// relations. The fault plan and PageMap submap counter are re-armed per
    /// attempt, so a repeated attempt sees the state the previous one left.
    ///
    /// A PageMap fault (cases 4 and 6) needs a previously absent lazy submap.
    /// As the pinned-C receiver does, a claim whose range shares an already
    /// present submap publishes without reaching the fault; it is released
    /// normally and the next claim, at the source hint's next address, is
    /// tried instead.
    fn os_publication_attempt(
        selected: usize,
        process: VmProcess<'static>,
        map: &crate::page_map::PageMap,
        session: &mut crate::bootstrap::ExclusiveTheapSession<'_>,
        fault: &fault::Guard,
    ) -> [bool; 9] {
        for _ in 0..16 {
            if let Some(facts) = os_publication_try(selected, process, map, session, fault) {
                return facts;
            }
        }
        panic!("OS publication case {selected} never reached an absent PageMap submap");
    }

    /// One claim of [`os_publication_attempt`]; `None` when a PageMap-fault
    /// case published into an already present submap and must try again.
    fn os_publication_try(
        selected: usize,
        process: VmProcess<'static>,
        map: &crate::page_map::PageMap,
        session: &mut crate::bootstrap::ExclusiveTheapSession<'_>,
        fault: &fault::Guard,
    ) -> Option<[bool; 9]> {
        let commit_ordinal = match selected { 2 | 5 => 1, 3 => 2, _ => usize::MAX };
        let submaps_before = map.test_lazy_submap_allocation_count();
        fault.set(if selected == 1 {
            fault::Plan::at_pair(fault::Point::Map, 1, fault::Point::Map, 1, Errno::NOMEM)
        } else {
            fault::Plan::at_pair(fault::Point::Commit, commit_ordinal,
                fault::Point::Unmap, if selected == 5 { 1 } else { usize::MAX }, Errno::NOMEM)
        });
        // The detached source Theap supplies the reservation hint random
        // image for each attempt, including a retry after a present submap.
        let mut random = unsafe { crate::os::CurrentTheapRandom::new(
            NonNull::from(session.theap()),
        ) };
        let allocation = OsAlignedPageClaim::allocate_for_process_with_random(
            process, config(4 * KIB), 128 * KIB, 128 * KIB,
            crate::arena::ArenaId::none(), Some(&mut random),
        );
        let mut facts = [false; 9];
        facts[8] = true;
        let owner = match allocation {
            Err(failure) => {
                let expected_stage = match selected {
                    1 => OsAlignedPageFailureStage::Map,
                    2 | 5 => OsAlignedPageFailureStage::MetadataCommit,
                    3 => OsAlignedPageFailureStage::BlockCommit,
                    _ => panic!("unexpected early OS claim failure"),
                };
                assert_eq!(failure.error().stage(), expected_stage);
                assert_eq!(failure.error().operation(), Errno::NOMEM);
                facts[0] = true;
                facts[1] = selected == 1 || fault.observed() == commit_ordinal;
                facts[2] = selected != 1 || (fault.observed() == 2 && fault.secondary_observed() == 1);
                facts[3] = selected == 1 || fault.secondary_observed() == 1;
                facts[4] = failure.error().cleanup().is_some() == (selected == 5);
                facts[5] = true; // no primary, aliases, or PageMap publication occurred
                let owner = failure.into_owner();
                assert_eq!(owner.is_some(), selected == 5);
                if let Some(OsAlignedPageOwner::Claim(claim)) = owner.as_ref() {
                    assert!(claim.memory_id().is_err());
                }
                owner
            }
            Ok(claim) => {
                assert!(matches!(selected, 4 | 6 | 7));
                facts[1] = fault.observed() == 2;
                let layout = claim.layout();
                let start = claim.slice_start().unwrap();
                let memory = claim.memory_id().unwrap();
                let mut primary = unsafe { session.publish_fresh_page(claim.metadata().unwrap(),
                    layout.block_size(), layout.page_offset(), layout.reserved(), 0,
                    memory.initially_zero(), memory) }.unwrap();
                assert!(unsafe { claim.publish_secondary_metadata(primary) });
                fault.set(if selected == 7 { fault::Plan::disabled() } else {
                    fault::Plan::at_pair(fault::Point::Map, 1, fault::Point::Unmap,
                        if selected == 6 { 1 } else { usize::MAX }, Errno::NOMEM)
                });
                let registered = unsafe {
                    map.register_range(start.as_ptr(), layout.page_map_size(), primary)
                }.is_ok();
                if registered && selected != 7 && fault.observed() == 0 {
                    // A present submap: release this successful page without
                    // a fault and let the caller claim the next address.
                    fault.set(fault::Plan::disabled());
                    claim.into_published().unwrap();
                    let published = unsafe { PublishedOsAlignedPage::from_page_for_process(
                        process, config(4 * KIB), primary) }.unwrap();
                    unsafe { map.unregister_range(start.as_ptr(), layout.page_map_size()) }.unwrap();
                    assert!(unsafe { published.clear_secondary_metadata() });
                    assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
                    assert!(unsafe { published.reclaim() }.is_ok());
                    return None;
                }
                facts[0] = registered == (selected == 7);
                facts[2] = selected == 7 || fault.observed() >= 1;
                let release = if registered {
                    // Transfer the sole release right before reconstructing
                    // a terminal Published token from its source MemoryId.
                    claim.into_published().unwrap();
                    let published = unsafe { PublishedOsAlignedPage::from_page_for_process(
                        process, config(4 * KIB), primary) }.unwrap();
                    unsafe { map.unregister_range(start.as_ptr(), layout.page_map_size()) }.unwrap();
                    assert!(unsafe { published.clear_secondary_metadata() });
                    assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
                    fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
                    unsafe { published.reclaim() }
                } else {
                    facts[8] = map.test_lazy_submap_allocation_count() - submaps_before == 2;
                    assert!(unsafe { claim.clear_secondary_metadata(primary) });
                    assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
                    claim.release()
                };
                facts[5] = unsafe { map.checked_lookup(start.as_ptr()) }.is_null();
                facts[3] = if selected == 7 { fault.observed() == 1 }
                    else { fault.secondary_observed() == 1 };
                facts[4] = release.is_err() == (selected >= 5);
                release.err().map(|failure| failure.into_owner())
            }
        };
        let before_retry = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::disabled());
        facts[6] = match owner {
            Some(owner) => unsafe { owner.release() }.is_ok(),
            None => true,
        };
        facts[7] = process.subprocess().vm_statistics().snapshot() == before_retry;
        Some(facts)
    }

    /// One fault-free OS page claim that publishes into the PageMap, resolves
    /// its block area there, and releases its exact Published token.
    fn os_publication_recovery(
        process: VmProcess<'static>,
        map: &crate::page_map::PageMap,
        session: &mut crate::bootstrap::ExclusiveTheapSession<'_>,
    ) -> bool {
        let mut random = unsafe { crate::os::CurrentTheapRandom::new(
            NonNull::from(session.theap()),
        ) };
        let Ok(claim) = OsAlignedPageClaim::allocate_for_process_with_random(
            process, config(4 * KIB), 128 * KIB, 128 * KIB,
            crate::arena::ArenaId::none(), Some(&mut random),
        ) else { return false };
        let layout = claim.layout();
        let start = claim.slice_start().unwrap();
        let memory = claim.memory_id().unwrap();
        let mut primary = unsafe { session.publish_fresh_page(claim.metadata().unwrap(),
            layout.block_size(), layout.page_offset(), layout.reserved(), 0,
            memory.initially_zero(), memory) }.unwrap();
        assert!(unsafe { claim.publish_secondary_metadata(primary) });
        if unsafe { map.register_range(start.as_ptr(), layout.page_map_size(), primary) }.is_err() {
            return false;
        }
        let published_in_map = unsafe { map.checked_lookup(start.as_ptr()) } == primary.as_ptr();
        claim.into_published().unwrap();
        let published = unsafe { PublishedOsAlignedPage::from_page_for_process(
            process, config(4 * KIB), primary) }.unwrap();
        unsafe { map.unregister_range(start.as_ptr(), layout.page_map_size()) }.unwrap();
        assert!(unsafe { published.clear_secondary_metadata() });
        assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
        published_in_map
            && unsafe { published.reclaim() }.is_ok()
            && unsafe { map.checked_lookup(start.as_ptr()) }.is_null()
    }

    /// Publishes one process-owned OS page and observes its complete mapping,
    /// PageMap reachability, and subprocess counters through terminal release.
    fn fresh_os_published_relations(block_size: usize, alignment: usize) -> ([bool; 6], [i64; 20]) {
        use crate::bootstrap::ExclusiveTheapBootstrap;
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        use crate::page_map::PageMap;
        let show_errors = b"mimalloc_show_errors=1\0";
        let max_warnings = b"mimalloc_max_warnings=100\0";
        let environment = std::boxed::Box::leak(std::boxed::Box::new([
            show_errors.as_ptr().cast(), max_warnings.as_ptr().cast(), core::ptr::null(),
        ]));
        FRESH_OS_CLEANUP_ENVIRONMENT.store(environment.as_mut_ptr(), Ordering::Release);
        let output = std::boxed::Box::leak(std::boxed::Box::new(
            OutputOwner::new(fresh_os_cleanup_default_output)));
        // SAFETY: the leaked environment and output outlive the synchronous
        // source option initialization and this receiver.
        unsafe { output.initialize_source_options(fresh_os_cleanup_environment) };
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let warnings = FreshOsCleanupWarnings {
            fragments: std::sync::Mutex::new(std::vec::Vec::new()),
            subprocess: subprocess.identity(),
            reserved_at_commit_warning: AtomicI64::new(i64::MIN),
            reserved_at_free_warning: AtomicI64::new(i64::MIN),
            committed_at_free_warning: AtomicI64::new(i64::MIN),
            reserved_at_allocation_warning: AtomicI64::new(i64::MIN),
            committed_at_allocation_warning: AtomicI64::new(i64::MIN),
            mmap_at_allocation_warning: AtomicI64::new(i64::MIN),
        };
        // SAFETY: the callback uses this stack-backed capture only while it
        // remains registered and every operation is synchronous.
        unsafe { output.register_output(Some(capture_fresh_os_cleanup_warning as OutputCallback),
            &warnings as *const FreshOsCleanupWarnings as *mut c_void) };
        let policy = std::boxed::Box::leak(std::boxed::Box::new(
            unsafe { crate::os::VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let mut map = PageMap::initialize_for_process(config(4 * KIB), 0, true, process).unwrap();
        let mut bootstrap = std::boxed::Box::pin(ExclusiveTheapBootstrap::new());
        let mut session = bootstrap.as_mut().activate_detached_for_main_subprocess(
            process.main_subprocess().expect("fixture uses process main")).unwrap();
        warnings.fragments.lock().unwrap().clear();
        let before = process.subprocess().vm_statistics().snapshot();
        let pages_before = session.theap().page_count();
        let fault = fault::install(fault::Plan::disabled());
        // SAFETY: the detached session pins and exclusively owns this Theap;
        // its random projection ends before page publication mutates it.
        let mut random = unsafe { crate::os::CurrentTheapRandom::new(
            NonNull::from(session.theap())) };
        let claim = OsAlignedPageClaim::allocate_for_process_with_random(process,
            config(4 * KIB), block_size, alignment, crate::arena::ArenaId::none(),
            Some(&mut random))
            .unwrap_or_else(|_| panic!("fresh OS page claim"));
        let layout = claim.layout();
        let memory = claim.memory_id().unwrap();
        let base = claim.base().unwrap();
        let start = claim.slice_start().unwrap();
        let mut primary = unsafe { session.publish_fresh_page(claim.metadata().unwrap(),
            layout.block_size(), layout.page_offset(), layout.reserved(), 0,
            memory.initially_zero(), memory) }.unwrap();
        assert!(unsafe { claim.publish_secondary_metadata(primary) });
        unsafe { map.register_range(start.as_ptr(), layout.page_map_size(), primary) }.unwrap();
        let live = process.subprocess().vm_statistics().snapshot();
        let pages_live = session.theap().page_count();
        let page_offset = unsafe { primary.as_ref().page_offset() };
        let page_reserved = unsafe { primary.as_ref().reserved() };
        let page_block_size = unsafe { primary.as_ref().block_size() };
        let last = start.as_ptr().wrapping_add(layout.block_start_offset()
            + (usize::from(page_reserved) - 1) * page_block_size);
        let registered = unsafe { map.checked_lookup(start.as_ptr()) } == primary.as_ptr()
            && unsafe { map.checked_lookup(last) } == primary.as_ptr();
        let mut residency = 0;
        let mapped = unsafe { crabc_core::mm::mincore_raw(base, 4096, &mut residency) }.is_ok();
        let unmaps = fault.capture_unmap_ranges();
        claim.into_published().unwrap();
        let published = unsafe { PublishedOsAlignedPage::from_page_for_process(
            process, config(4 * KIB), primary) }.unwrap();
        unsafe { map.unregister_range(start.as_ptr(), layout.page_map_size()) }.unwrap();
        assert!(unsafe { published.clear_secondary_metadata() });
        assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
        assert!(unsafe { published.reclaim() }.is_ok());
        let freed = process.subprocess().vm_statistics().snapshot();
        let pages_free = session.theap().page_count();
        let (ranges, count) = unmaps.all().unwrap();
        let exact_release = ranges[..count].iter().any(|&(address, length)|
            address == base.addr() && length == layout.mapping_length());
        let unmapped = unsafe { crabc_core::mm::mincore_raw(base, 4096, &mut residency) }
            == Err(Errno::NOMEM);
        let warning_count = warnings.fragments.lock().unwrap().len();
        let facts = [memory.is_os(), exact_release,
            registered && unsafe { map.checked_lookup(start.as_ptr()) }.is_null()
                && unsafe { map.checked_lookup(last) }.is_null(),
            mapped && unmapped, count == 1, warning_count == 0];
        let values = [layout.mapping_length() as i64,
            (start.as_ptr().addr() - base.addr()) as i64,
            layout.block_start_offset() as i64, page_offset as i64,
            i64::from(page_reserved), page_block_size as i64,
            i64::from(memory.initially_committed()), i64::from(memory.initially_zero()),
            live.reserved_current - before.reserved_current,
            live.committed_current - before.committed_current,
            live.commit_calls - before.commit_calls,
            freed.reserved_current - before.reserved_current,
            freed.committed_current - before.committed_current,
            freed.commit_calls - before.commit_calls,
            live.commit_calls - before.commit_calls, warning_count as i64,
            live.mmap_calls - before.mmap_calls,
            freed.mmap_calls - before.mmap_calls,
            (pages_live - pages_before) as i64,
            (pages_free as i64) - (pages_before as i64)];
        drop(unmaps);
        drop(fault);
        unsafe { map.destroy() }.unwrap();
        // SAFETY: remove the stack capture before it becomes invalid.
        unsafe { output.register_output(None, core::ptr::null_mut()) };
        (facts, values)
    }

    /// A failed published free leaves its mapping live after PageMap removal;
    /// the retained token retries only the raw primitive after accounting.
    fn published_os_failed_free_relations(block_size: usize, alignment: usize) -> ([bool; 8], [i64; 10]) {
        use crate::bootstrap::ExclusiveTheapBootstrap;
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        use crate::page_map::PageMap;
        let show_errors = b"mimalloc_show_errors=1\0";
        let max_warnings = b"mimalloc_max_warnings=100\0";
        let environment = std::boxed::Box::leak(std::boxed::Box::new([
            show_errors.as_ptr().cast(), max_warnings.as_ptr().cast(), core::ptr::null(),
        ]));
        FRESH_OS_CLEANUP_ENVIRONMENT.store(environment.as_mut_ptr(), Ordering::Release);
        let output = std::boxed::Box::leak(std::boxed::Box::new(
            OutputOwner::new(fresh_os_cleanup_default_output)));
        // SAFETY: leaked option storage and output remain live for this
        // synchronous receiver and its source option reads.
        unsafe { output.initialize_source_options(fresh_os_cleanup_environment) };
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let warnings = FreshOsCleanupWarnings {
            fragments: std::sync::Mutex::new(std::vec::Vec::new()),
            subprocess: subprocess.identity(),
            reserved_at_commit_warning: AtomicI64::new(i64::MIN),
            reserved_at_free_warning: AtomicI64::new(i64::MIN),
            committed_at_free_warning: AtomicI64::new(i64::MIN),
            reserved_at_allocation_warning: AtomicI64::new(i64::MIN),
            committed_at_allocation_warning: AtomicI64::new(i64::MIN),
            mmap_at_allocation_warning: AtomicI64::new(i64::MIN),
        };
        // SAFETY: callback delivery is synchronous and this capture remains
        // live until output registration is removed below.
        unsafe { output.register_output(Some(capture_fresh_os_cleanup_warning as OutputCallback),
            &warnings as *const FreshOsCleanupWarnings as *mut c_void) };
        let policy = std::boxed::Box::leak(std::boxed::Box::new(
            unsafe { crate::os::VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let mut map = PageMap::initialize_for_process(config(4 * KIB), 0, true, process).unwrap();
        let mut bootstrap = std::boxed::Box::pin(ExclusiveTheapBootstrap::new());
        let mut session = bootstrap.as_mut().activate_detached_for_main_subprocess(
            process.main_subprocess().expect("fixture uses process main")).unwrap();
        warnings.fragments.lock().unwrap().clear();
        let before = process.subprocess().vm_statistics().snapshot();
        let fault = fault::install(fault::Plan::disabled());
        // SAFETY: the exclusive session retains the pinned initialized Theap;
        // this random projection ends before Page metadata is published.
        let mut random = unsafe { crate::os::CurrentTheapRandom::new(
            NonNull::from(session.theap())) };
        let claim = OsAlignedPageClaim::allocate_for_process_with_random(process,
            config(4 * KIB), block_size, alignment, crate::arena::ArenaId::none(),
            Some(&mut random)).unwrap_or_else(|_| panic!("published OS claim"));
        let layout = claim.layout();
        let memory = claim.memory_id().unwrap();
        let base = claim.base().unwrap();
        let start = claim.slice_start().unwrap();
        let mut primary = unsafe { session.publish_fresh_page(claim.metadata().unwrap(),
            layout.block_size(), layout.page_offset(), layout.reserved(), 0,
            memory.initially_zero(), memory) }.unwrap();
        assert!(unsafe { claim.publish_secondary_metadata(primary) });
        unsafe { map.register_range(start.as_ptr(), layout.page_map_size(), primary) }.unwrap();
        let live = process.subprocess().vm_statistics().snapshot();
        let last = start.as_ptr().wrapping_add(layout.block_start_offset()
            + (usize::from(layout.reserved()) - 1) * layout.block_size());
        let registered = unsafe { map.checked_lookup(start.as_ptr()) } == primary.as_ptr()
            && unsafe { map.checked_lookup(last) } == primary.as_ptr();
        claim.into_published().unwrap();
        let published = unsafe { PublishedOsAlignedPage::from_page_for_process(
            process, config(4 * KIB), primary) }.unwrap();
        unsafe { map.unregister_range(start.as_ptr(), layout.page_map_size()) }.unwrap();
        assert!(unsafe { published.clear_secondary_metadata() });
        assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let unmaps = fault.capture_unmap_ranges();
        let failure = unsafe { published.reclaim() }.err().expect("failed terminal unmap");
        assert_eq!(failure.error().operation(), Errno::NOMEM);
        let OsAlignedPageOwner::Published(owner) = failure.into_owner() else {
            panic!("published page retains its release owner")
        };
        let freed = process.subprocess().vm_statistics().snapshot();
        let (ranges, count) = unmaps.all().unwrap();
        let exact_release = count == 1 && ranges[0] == (base.addr(), layout.mapping_length());
        let mut residency = 0;
        let retained = unsafe { crabc_core::mm::mincore_raw(base, 4096, &mut residency) }.is_ok();
        let fragments = warnings.fragments.lock().unwrap();
        let warning_order = fragments.len() == 2
            && fragments[0].starts_with(b"mimalloc: warning: thread 0x")
            && fragments[1].starts_with(std::format!(
                "unable to free OS memory (error: 12 (0x0C), size: 0x{:X} bytes, address: 0x",
                layout.mapping_length()).as_bytes());
        let warning_count = fragments.len();
        drop(fragments);
        let warning_reserved = warnings.reserved_at_free_warning.load(Ordering::Acquire);
        let warning_committed = warnings.committed_at_free_warning.load(Ordering::Acquire);
        let before_retry = process.subprocess().vm_statistics().snapshot();
        drop(unmaps);
        fault.set(fault::Plan::disabled());
        let retried = unsafe { owner.retry_reclaim() }.is_ok();
        let unmapped = unsafe { crabc_core::mm::mincore_raw(base, 4096, &mut residency) }
            == Err(Errno::NOMEM);
        let after_retry = process.subprocess().vm_statistics().snapshot();
        let retry_warning_count = warnings.fragments.lock().unwrap().len();
        let facts = [memory.kind() == crate::types::MemoryKind::Os
                && memory.size() == Some(layout.mapping_length()),
            registered && unsafe { map.checked_lookup(start.as_ptr()) }.is_null()
                && unsafe { map.checked_lookup(last) }.is_null(),
            exact_release, retained, warning_order,
            warning_reserved == live.reserved_current
                && warning_committed == live.committed_current,
            freed.reserved_current - before.reserved_current == ARENA_SLICE_SIZE as i64
                && freed.committed_current - before.committed_current == ARENA_SLICE_SIZE as i64
                && freed.commit_calls - before.commit_calls == 2
                && freed.mmap_calls - before.mmap_calls == 2,
            retried && unmapped && after_retry == before_retry
                && retry_warning_count == warning_count];
        let values = [layout.mapping_length() as i64,
            live.reserved_current - before.reserved_current,
            live.committed_current - before.committed_current,
            freed.reserved_current - before.reserved_current,
            freed.committed_current - before.committed_current,
            freed.commit_calls - before.commit_calls,
            freed.mmap_calls - before.mmap_calls,
            warning_count as i64,
            if warning_reserved == i64::MIN { -1 }
                else { warning_reserved - before.reserved_current },
            if warning_committed == i64::MIN { -1 }
                else { warning_committed - before.committed_current }];
        drop(fault);
        unsafe { map.destroy() }.unwrap();
        // SAFETY: no callback may retain this stack-backed capture.
        unsafe { output.register_output(None, core::ptr::null_mut()) };
        (facts, values)
    }

    /// A failed lazy PageMap allocation after both page commits returns no
    /// Page, releases the exact OS area, and leaves only the rollback submap.
    fn failed_os_page_map_relations() -> ([bool; 7], [i64; 8]) {
        use crate::bootstrap::ExclusiveTheapBootstrap;
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        use crate::page_map::PageMap;
        let show_errors = b"mimalloc_show_errors=1\0";
        let max_warnings = b"mimalloc_max_warnings=100\0";
        let environment = std::boxed::Box::leak(std::boxed::Box::new([
            show_errors.as_ptr().cast(), max_warnings.as_ptr().cast(), core::ptr::null(),
        ]));
        FRESH_OS_CLEANUP_ENVIRONMENT.store(environment.as_mut_ptr(), Ordering::Release);
        let output = std::boxed::Box::leak(std::boxed::Box::new(
            OutputOwner::new(fresh_os_cleanup_default_output)));
        // SAFETY: the leaked option storage and output remain live through
        // the synchronous source option reads and callback delivery.
        unsafe { output.initialize_source_options(fresh_os_cleanup_environment) };
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let warnings = FreshOsCleanupWarnings {
            fragments: std::sync::Mutex::new(std::vec::Vec::new()),
            subprocess: subprocess.identity(),
            reserved_at_commit_warning: AtomicI64::new(i64::MIN),
            reserved_at_free_warning: AtomicI64::new(i64::MIN),
            committed_at_free_warning: AtomicI64::new(i64::MIN),
            reserved_at_allocation_warning: AtomicI64::new(i64::MIN),
            committed_at_allocation_warning: AtomicI64::new(i64::MIN),
            mmap_at_allocation_warning: AtomicI64::new(i64::MIN),
        };
        // SAFETY: callback delivery is synchronous and the capture outlives
        // registration.
        unsafe { output.register_output(Some(capture_fresh_os_cleanup_warning as OutputCallback),
            &warnings as *const FreshOsCleanupWarnings as *mut c_void) };
        let policy = std::boxed::Box::leak(std::boxed::Box::new(
            unsafe { crate::os::VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let mut map = PageMap::initialize_for_process(config(4 * KIB), 0, true, process).unwrap();
        let mut bootstrap = std::boxed::Box::pin(ExclusiveTheapBootstrap::new());
        let mut session = bootstrap.as_mut().activate_detached_for_main_subprocess(
            process.main_subprocess().expect("fixture uses process main")).unwrap();
        let fault = fault::install(fault::Plan::disabled());
        for _ in 0..16 {
            warnings.fragments.lock().unwrap().clear();
            let before = process.subprocess().vm_statistics().snapshot();
            let pages_before = session.theap().page_count();
            // SAFETY: the pinned detached Theap remains exclusively owned
            // while its random projection is used for this claim.
            let mut random = unsafe { crate::os::CurrentTheapRandom::new(
                NonNull::from(session.theap())) };
            let claim = OsAlignedPageClaim::allocate_for_process_with_random(process,
                config(4 * KIB), 128 * KIB, 128 * KIB, crate::arena::ArenaId::none(),
                Some(&mut random)).unwrap_or_else(|_| panic!("fresh OS claim"));
            let layout = claim.layout();
            let memory = claim.memory_id().unwrap();
            let base = claim.base().unwrap();
            let start = claim.slice_start().unwrap();
            let mut primary = unsafe { session.publish_fresh_page(claim.metadata().unwrap(),
                layout.block_size(), layout.page_offset(), layout.reserved(), 0,
                memory.initially_zero(), memory) }.unwrap();
            assert!(unsafe { claim.publish_secondary_metadata(primary) });
            fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
            let unmaps = fault.capture_unmap_ranges();
            let registered = unsafe { map.register_range(start.as_ptr(),
                layout.page_map_size(), primary) }.is_ok();
            if registered && fault.observed() == 0 {
                drop(unmaps);
                fault.set(fault::Plan::disabled());
                claim.into_published().unwrap();
                let published = unsafe { PublishedOsAlignedPage::from_page_for_process(
                    process, config(4 * KIB), primary) }.unwrap();
                unsafe { map.unregister_range(start.as_ptr(), layout.page_map_size()) }.unwrap();
                assert!(unsafe { published.clear_secondary_metadata() });
                assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
                assert!(unsafe { published.reclaim() }.is_ok());
                continue;
            }
            assert!(!registered && fault.observed() >= 1,
                "registered={registered} maps={} retry={}",
                fault.observed(), fault.secondary_observed());
            let rollback_map = map.test_lazy_submap_allocation_count() >= 2;
            assert!(unsafe { claim.clear_secondary_metadata(primary) });
            assert!(session.retire_page(unsafe { primary.as_mut() }).is_some());
            let released = claim.release().is_ok();
            let after = process.subprocess().vm_statistics().snapshot();
            let (ranges, count) = unmaps.all().unwrap();
            let exact_release = count == 1
                && ranges[0] == (base.addr(), layout.mapping_length());
            let mut residency = 0;
            let unmapped = unsafe { crabc_core::mm::mincore_raw(base, 4096, &mut residency) }
                == Err(Errno::NOMEM);
            let fragments = warnings.fragments.lock().unwrap();
            let warning_order = fragments.len() == 4
                && fragments[0].starts_with(b"mimalloc: warning: thread 0x")
                && fragments[1].starts_with(b"unable to allocate OS memory (error: 12 (0x0C), addr: ")
                && fragments[2].starts_with(b"mimalloc: warning: thread 0x")
                && fragments[3] == b"internal error: unable to extend the page map\n";
            let warning_count = fragments.len();
            drop(fragments);
            let warning_reserved = warnings.reserved_at_allocation_warning.load(Ordering::Acquire);
            let warning_committed = warnings.committed_at_allocation_warning.load(Ordering::Acquire);
            let warning_mmap = warnings.mmap_at_allocation_warning.load(Ordering::Acquire);
            let facts = [released && session.theap().page_count() == pages_before,
                memory.is_os() && memory.size() == Some(layout.mapping_length()),
                unsafe { map.checked_lookup(start.as_ptr()) }.is_null(),
                exact_release && unmapped, rollback_map, warning_order,
                warning_reserved - before.reserved_current == layout.mapping_length() as i64
                    && warning_mmap - before.mmap_calls == 1];
            let values = [layout.mapping_length() as i64,
                after.reserved_current - before.reserved_current,
                after.committed_current - before.committed_current,
                after.commit_calls - before.commit_calls,
                after.mmap_calls - before.mmap_calls,
                warning_count as i64,
                warning_reserved - before.reserved_current,
                warning_committed - before.committed_current];
            drop(unmaps);
            drop(fault);
            unsafe { map.destroy() }.unwrap();
            // SAFETY: the stack capture cannot be used after deregistration.
            unsafe { output.register_output(None, core::ptr::null_mut()) };
            return (facts, values);
        }
        panic!("no fresh OS claim needed a lazy PageMap submap");
    }

    /// The same seven legal source transitions as the direct-included C
    /// arena/page-map receiver. C's void failed free exposes no retry owner;
    /// Rust must preserve an exact Claim or Published token and account once.
    /// Each case repeats its faulted request against the state the first
    /// failure left, which must reproduce the same relations, and then makes
    /// one fault-free request that must publish and release normally.
    #[test]
    fn emit_os_publication_fault_receiver_trace() {
        use crate::bootstrap::ExclusiveTheapBootstrap;
        use crate::page_map::PageMap;
        let fault = fault::install(fault::Plan::disabled());
        std::println!("CRABC_MI_M2_OS_PUBLICATION_TRACE_BEGIN");
        for selected in 1..=7 {
            let process = process(false);
            let mut map = PageMap::initialize(config(4 * KIB), 0, true).unwrap();
            let mut bootstrap = std::boxed::Box::pin(ExclusiveTheapBootstrap::new());
            let mut session = bootstrap.as_mut()
                .activate_detached_for_main_subprocess(
                    process.main_subprocess().expect("fixture uses process main"),
                ).unwrap();
            let first = os_publication_attempt(selected, process, &map, &mut session, &fault);
            let repeat = os_publication_attempt(selected, process, &map, &mut session, &fault);
            fault.set(fault::Plan::disabled());
            let recovered = os_publication_recovery(process, &map, &mut session);
            let mut facts = [false; 11];
            facts[..9].copy_from_slice(&first);
            facts[9] = repeat == first;
            facts[10] = recovered;
            assert!(facts.iter().all(|fact| *fact), "OS publication case {selected}: {facts:?} repeat {repeat:?}");
            for (field, value) in ["page_result", "commit_branch", "map_branch", "release_once",
                "cleanup_retention", "unreachable", "raw_retry", "retry_statistics", "map_rollback",
                "repeat_same_branch", "recovered_page_published"]
                .into_iter().zip(facts) {
                std::println!("os_publication.{selected}.{field}={}", u8::from(value));
            }
            // Each case has no live page, alias, map entry, or retained claim.
            unsafe { map.destroy() }.unwrap();
        }
        let process = process(false);
        let before = process.subprocess().vm_statistics().snapshot();
        let mut claim = OsAlignedPageClaim::allocate_on_demand_for_process(
            process, config(4 * KIB), 4096, 1, crate::arena::ArenaId::none(),
        ).unwrap_or_else(|_| panic!("on-demand OS area"));
        let layout = claim.layout();
        let mapped = process.subprocess().vm_statistics().snapshot();
        let memory = claim.memory_id().unwrap();
        let mapping_range = layout.mapping_length() == 2 * ARENA_SLICE_SIZE
            && mapped.reserved_current - before.reserved_current
                == layout.mapping_length() as i64;
        let metadata_commit_statistics = mapped.committed_current == before.committed_current
            && mapped.commit_calls - before.commit_calls == 1;
        let prefix = usize::from(page::initial_page_slice_pcommitted(
            layout.block_start_offset(), layout.block_size(),
            layout.allocation_size(), 4 * KIB,
        ).unwrap()) * 4 * KIB;
        claim.commit_initial_page_prefix(prefix).expect("writable first prefix");
        let committed = process.subprocess().vm_statistics().snapshot();
        let commit_state_divergence_witness = !memory.initially_committed()
            && committed.commit_calls - mapped.commit_calls == 1
            && committed.committed_current - mapped.committed_current == prefix as i64;
        assert!(claim.release().is_ok());
        let released = process.subprocess().vm_statistics().snapshot();
        let release_accounting_divergence_witness =
            released.reserved_current == before.reserved_current
            && released.committed_current == before.committed_current;
        for (field, value) in [
            ("mapping_range", mapping_range),
            ("metadata_commit_statistics", metadata_commit_statistics),
            ("commit_state_divergence_witness", commit_state_divergence_witness),
            ("release_accounting_divergence_witness", release_accounting_divergence_witness),
        ] {
            assert!(value, "on-demand OS receiver: {field}");
            std::println!("os_on_demand.{field}={}", u8::from(value));
        }
        let callback = crate::arena::tests::on_demand_arena_prefix_callback_relations();
        for (field, value) in ["callback_failed", "mapping_retained",
            "callback_statistics", "recovered"].into_iter().zip(callback) {
            assert!(value, "on-demand arena receiver: {field}");
            std::println!("arena_on_demand.{field}={}", u8::from(value));
        }
        drop(fault);
        let cleanup = fresh_os_area_metadata_commit_relations(true);
        for field in ["failed_unpublished", "memory_id_range", "leaked_range",
            "single_commit_and_release", "statistics", "warning_fragments_order",
            "warning_before_statistics", "raw_cleanup"] {
            std::println!("os_area_commit_cleanup.{field}=1");
        }
        let cleanup_released_values = fresh_os_area_metadata_commit_relations(false);
        for field in ["failed_unpublished", "memory_id_range", "exact_range",
            "single_commit_and_release", "statistics", "warning_fragments_order",
            "warning_before_statistics", "unmapped_after_cleanup"] {
            std::println!("os_area_commit_release.{field}=1");
        }
        let (published_facts, published_values) = fresh_os_published_relations(128 * KIB, 128 * KIB);
        for (field, value) in ["os_memory", "exact_mapping_release",
            "page_map_lifecycle", "kernel_mapping_lifecycle", "single_terminal_free",
            "warning_absent"].into_iter().zip(published_facts) {
            std::println!("os_area_published.{field}={}", u8::from(value));
        }
        let (failed_free_facts, failed_free_values) =
            published_os_failed_free_relations(128 * KIB, 128 * KIB);
        for (field, value) in ["os_memory", "page_map_unpublished",
            "exact_failed_release", "range_retained", "warning_fragments_order",
            "warning_before_statistics", "statistics_once", "raw_cleanup"]
            .into_iter().zip(failed_free_facts) {
            std::println!("os_area_published_free_failure.{field}={}", u8::from(value));
        }
        let (medium_success_facts, medium_success_values) =
            fresh_os_published_relations(32 * KIB, 1);
        let (medium_failed_facts, medium_failed_values) =
            published_os_failed_free_relations(32 * KIB, 1);
        for (field, value) in ["os_memory", "exact_release", "page_map_lifecycle",
            "kernel_mapping_lifecycle", "single_terminal_free", "warning_order"]
            .into_iter().zip([
                medium_success_facts[0], medium_success_facts[1], medium_success_facts[2],
                medium_success_facts[3], medium_success_facts[4], medium_success_facts[5],
            ]) {
            std::println!("os_medium_published.{field}={}", u8::from(value));
        }
        for (field, value) in ["os_memory", "exact_release", "page_map_lifecycle",
            "kernel_mapping_lifecycle", "single_terminal_free", "warning_order",
            "warning_before_statistics", "raw_cleanup"]
            .into_iter().zip([
                medium_failed_facts[0], medium_failed_facts[2], medium_failed_facts[1],
                medium_failed_facts[3], medium_failed_facts[2], medium_failed_facts[4],
                medium_failed_facts[5], medium_failed_facts[7],
            ]) {
            std::println!("os_medium_free_failure.{field}={}", u8::from(value));
        }
        let (failed_map_facts, failed_map_values) = failed_os_page_map_relations();
        for (field, value) in ["null_page", "mapping_range", "page_map_unpublished",
            "exact_release", "rollback_map", "warning_fragments_order",
            "warning_before_statistics"].into_iter().zip(failed_map_facts) {
            std::println!("os_area_page_map_failure.{field}={}", u8::from(value));
        }
        std::println!("CRABC_MI_M2_OS_PUBLICATION_TRACE_END");
        std::println!("CRABC_MI_M2_OS_ON_DEMAND_VALUES_BEGIN");
        for (field, value) in [
            ("mapping_length", layout.mapping_length() as i64),
            ("reserved_after_area", mapped.reserved_current - before.reserved_current),
            ("committed_after_area", mapped.committed_current - before.committed_current),
            ("commit_calls_after_area", mapped.commit_calls - before.commit_calls),
            ("memory_id_initially_committed", i64::from(memory.initially_committed())),
            ("expected_first_prefix", prefix as i64),
            ("block_prefix_commit_calls", committed.commit_calls - mapped.commit_calls),
            ("block_prefix_committed_bytes", committed.committed_current - mapped.committed_current),
            ("committed_after_release", released.committed_current - before.committed_current),
        ] {
            std::println!("os_on_demand.{field}={value}");
        }
        for (field, value) in ["mapping_length", "reserved_delta", "committed_delta",
            "commit_calls", "warning_fragments"].into_iter().zip(cleanup) {
            std::println!("os_area_commit_cleanup.{field}={value}");
        }
        for (field, value) in ["mapping_length", "reserved_delta", "committed_delta",
            "commit_calls", "warning_fragments"].into_iter().zip(cleanup_released_values) {
            std::println!("os_area_commit_release.{field}={value}");
        }
        for (field, value) in ["mapping_length", "slice_offset",
            "block_start_offset", "page_offset", "reserved", "block_size",
            "initially_committed", "initially_zero", "reserved_live", "committed_live",
            "commit_calls_live", "reserved_after_free", "committed_after_free",
            "commit_calls_after_free", "primitive_commits", "warning_fragments",
            "mmap_calls_live", "mmap_calls_after_free", "pages_live", "pages_after_free"]
            .into_iter().zip(published_values) {
            std::println!("os_area_published.{field}={value}");
        }
        for (field, value) in ["mapping_length", "reserved_live", "committed_live",
            "reserved_after_free", "committed_after_free", "commit_calls_after_free",
            "mmap_calls_after_free", "warning_fragments", "reserved_at_warning",
            "committed_at_warning"].into_iter().zip(failed_free_values) {
            std::println!("os_area_published_free_failure.{field}={value}");
        }
        for (field, value) in ["mapping_length", "slice_offset",
            "block_start_offset", "page_offset", "reserved", "block_size",
            "initially_committed", "initially_zero", "reserved_live", "committed_live",
            "commit_calls_live", "reserved_after_free", "committed_after_free",
            "commit_calls_after_free", "primitive_commits", "warning_fragments",
            "mmap_calls_live", "mmap_calls_after_free", "pages_live", "pages_after_free"]
            .into_iter().zip(medium_success_values) {
            std::println!("os_medium_published.{field}={value}");
        }
        for (field, value) in ["mapping_length", "reserved_live", "committed_live",
            "reserved_after_free", "committed_after_free", "commit_calls_after_free",
            "mmap_calls_after_free", "warning_fragments", "reserved_at_warning",
            "committed_at_warning"].into_iter().zip(medium_failed_values) {
            std::println!("os_medium_free_failure.{field}={value}");
        }
        for (field, value) in ["mapping_length", "reserved_after_failure",
            "committed_after_failure", "commit_calls_after_failure",
            "mmap_calls_after_failure", "warning_fragments", "reserved_at_warning",
            "committed_at_warning"].into_iter().zip(failed_map_values) {
            std::println!("os_area_page_map_failure.{field}={value}");
        }
        assert!(published_facts.into_iter().all(|value| value),
            "fresh OS published receiver: {published_facts:?}");
        assert!(failed_free_facts.into_iter().all(|value| value),
            "published OS failed free receiver: {failed_free_facts:?}");
        assert!(failed_map_facts.into_iter().all(|value| value),
            "failed OS PageMap receiver: {failed_map_facts:?}");
        std::println!("CRABC_MI_M2_OS_ON_DEMAND_VALUES_END");
    }

    #[test]
    fn emit_native_fresh_os_page_ownership_trace() {
        use crate::bootstrap::ExclusiveTheapBootstrap;
        let process = process(false);
        let mut bootstrap = std::boxed::Box::pin(ExclusiveTheapBootstrap::new());
        let mut session = bootstrap.as_mut().activate_detached_for_main_subprocess(
            process.main_subprocess().expect("fixture uses process main"),
        ).unwrap();
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

    /// The explicit-config OS-aligned claim receives the same source rule:
    /// a failed prefix release leaks the prefix and the claim succeeds.
    #[cfg(not(miri))]
    #[test]
    fn aligned_map_prefix_cleanup_failure_leaks_and_returns_the_claim() {
        let fault = fault::install(fault::Plan::at(fault::Point::Unmap, 2, Errno::NOMEM));
        let mut config = config(4 * KIB);
        config.test_force_full_aligned_map_trim();
        let capture = fault.capture_unmap_ranges();
        let claim = OsAlignedPageClaim::allocate(config, 4 * KIB, 128 * KIB)
            .unwrap_or_else(|_| panic!("a failed prefix release does not fail the claim"));
        let (ranges, count) = capture.all().expect("bounded releases");
        drop(capture);
        assert_eq!(count, 3);
        let (leaked, leaked_length) = ranges[1];
        assert_eq!(leaked + leaked_length, claim.mapping.base().unwrap().addr(),
            "the leaked prefix ends at the aligned claim");
        fault.set(fault::Plan::disabled());
        assert!(matches!(claim.release(), Ok(())));
        // SAFETY: the leaked prefix is represented by no owner.
        unsafe { crabc_core::mm::munmap_raw(leaked as *mut u8, leaked_length) }
            .expect("fixture teardown of the leaked prefix");
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
