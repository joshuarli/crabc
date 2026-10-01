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
use core::fmt;
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

#[cfg(feature = "native-runtime-test-audit")]
static LAST_AUDITED_PROCESS_MAP: AtomicPtr<PageMap> = AtomicPtr::new(null_mut());

/// Registered arena slices grouped by the quiescent page image they name.
/// A multi-slice page contributes once for each registered slice.
/// Medium state buckets overlap: `remote_pending` reads the atomic remote
/// head, `reusable` means either local free-list head is nonnull, and
/// `retired` means the page's retirement countdown is nonzero.
#[cfg(any(test, feature = "native-runtime-test-audit"))]
#[repr(C)]
#[derive(Default)]
pub struct PageMapClassTestAudit {
    pub registered_slices: usize,
    pub small_empty_slices: usize,
    pub small_used_slices: usize,
    pub medium_empty_slices: usize,
    pub medium_used_slices: usize,
    pub large_empty_slices: usize,
    pub large_used_slices: usize,
    pub singleton_empty_slices: usize,
    pub singleton_used_slices: usize,
    pub unknown_kind_slices: usize,
    pub abandoned_slices: usize,
    pub detached_slices: usize,
    pub attached_slices: usize,
    pub nonprimary_slices: usize,
    pub medium_abandoned_slices: usize,
    pub medium_detached_slices: usize,
    pub medium_attached_slices: usize,
    pub medium_remote_pending_slices: usize,
    pub medium_reusable_slices: usize,
    pub medium_retired_slices: usize,
}

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

pub(crate) const PAGE_MAP_SUB_SIZE: usize = PAGE_MAP_SUB_COUNT * size_of::<*mut Page>();

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

/// Linux x86-64 source-sized storage for the PageMap's private lock.
///
/// The source pthread mutex occupies 40 bytes at eight-byte alignment. Its
/// extent determines the flexible-array offset and thus reservation and lazy
/// commit counts. Keep that extent while using the existing private futex
/// lock; the remaining bytes are reserved storage, not a pthread ABI object.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(8))]
struct PageMapLock {
    inner: PrivateLock,
    reserved: [u8; 40 - size_of::<PrivateLock>()],
}

#[cfg(target_arch = "x86_64")]
impl PageMapLock {
    const fn new() -> Self {
        Self { inner: PrivateLock::new(), reserved: [0; 40 - size_of::<PrivateLock>()] }
    }

    fn lock(&self) -> Result<crate::lock::PrivateLockGuard<'_>> { self.inner.lock() }

    #[cfg(test)]
    fn try_lock(&self) -> Option<crate::lock::PrivateLockGuard<'_>> { self.inner.try_lock() }
}

#[cfg(target_arch = "aarch64")]
type PageMapLock = PrivateLock;

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
    lock: PageMapLock,
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

/// A PageMap bootstrap failure before the map can become a published owner.
///
/// Pinned `mi_page_map_init_once` releases its private mapping through
/// `_mi_os_free` after a failed initial or trailing-submap commit. A failed
/// `munmap` there is warned and the mapping leaks, so no mapping survives
/// any initialization failure.
pub(crate) enum PageMapInitializationError {
    /// Initialization failed; no mapping remains owned.
    Failed { error: Errno },
}

impl PageMapInitializationError {
    #[inline]
    fn failed(error: Errno) -> Self { Self::Failed { error } }

    /// Releases a private bootstrap mapping after a later initialization
    /// transition failed. As source `mi_os_prim_free` does, a failed release
    /// is warned through the process output route and the mapping leaks.
    #[inline]
    fn after_private_mapping_failure(
        mut mapping: Mapping, initialization: Errno, statistics: PageMapStatistics,
    ) -> Self {
        let address = mapping.base().map_or(0, |base| base as usize);
        let length = mapping.length().unwrap_or(0);
        // `_mi_os_free(subproc, pmap, extra_reserve_size, memid)` is a
        // still-committed free: it subtracts the full extent from both
        // counters whether or not `munmap` succeeds.
        statistics.release(length, length);
        if let Err(cleanup) = mapping.unmap() {
            crate::process_init::process_warning_message(
                crate::diagnostic_output::SourceFormattedMessage::os_free_failure(
                    cleanup, length, address));
        }
        Self::Failed { error: initialization }
    }
}

impl fmt::Debug for PageMapInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed { error } => formatter
                .debug_struct("PageMapInitializationError::Failed")
                .field("error", error)
                .finish(),
        }
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
    statistics: PageMapStatistics,
    source_process: Option<crate::os::VmProcess<'static>>,
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

    /// Reserves and initializes a private two-level page map whose VM events
    /// belong to no subprocess statistics owner (fixtures and the legacy
    /// private metadata map).
    pub(crate) fn initialize(
        config: MemoryConfig,
        configured_virtual_bits: usize,
        force_commit: bool,
    ) -> core::result::Result<Self, PageMapInitializationError> {
        Self::initialize_with_statistics(config, configured_virtual_bits, force_commit,
            PageMapStatistics(None))
    }

    /// Reserves and initializes the source process page map, recording its
    /// VM events in the main subprocess statistics as pinned `page-map.c`
    /// does through `_mi_subproc_main()`.
    pub(crate) fn initialize_for_subprocess(
        config: MemoryConfig,
        configured_virtual_bits: usize,
        force_commit: bool,
        subprocess: &'static crate::subproc::SubprocessIdentity,
    ) -> core::result::Result<Self, PageMapInitializationError> {
        Self::initialize_with_statistics(config, configured_virtual_bits, force_commit,
            PageMapStatistics(Some(subprocess)))
    }

    /// Reserves and initializes the process page map through `process`.
    ///
    /// Pinned `mi_page_map_init_once` maps through
    /// `_mi_os_alloc_aligned(subproc, extra_reserve_size, 1, commit, true)`:
    /// a failed direct map warns and falls back to the source aligned
    /// over-allocation and trim, so a first failed map attempt still
    /// initializes the map. That sequence (with its statistics and
    /// warnings) is `Mapping::map_aligned_for_process`; the later commits,
    /// lazy submaps, and releases account to the same subprocess.
    pub(crate) fn initialize_for_process(
        config: MemoryConfig,
        configured_virtual_bits: usize,
        force_commit: bool,
        process: crate::os::VmProcess<'static>,
    ) -> core::result::Result<Self, PageMapInitializationError> {
        Self::initialize_with_statistics_and_process(config, configured_virtual_bits, force_commit,
            PageMapStatistics(Some(process.subprocess())), Some(process))
    }

    fn initialize_with_statistics(
        config: MemoryConfig,
        configured_virtual_bits: usize,
        force_commit: bool,
        statistics: PageMapStatistics,
    ) -> core::result::Result<Self, PageMapInitializationError> {
        Self::initialize_with_statistics_and_process(config, configured_virtual_bits, force_commit,
            statistics, None)
    }

    fn initialize_with_statistics_and_process(
        config: MemoryConfig,
        configured_virtual_bits: usize,
        force_commit: bool,
        statistics: PageMapStatistics,
        process: Option<crate::os::VmProcess<'static>>,
    ) -> core::result::Result<Self, PageMapInitializationError> {
        let virtual_bits = effective_virtual_address_bits(
            configured_virtual_bits,
            config.virtual_address_bits(),
        );
        let virtual_reserve_count = reserve_count(virtual_bits)
            .ok_or(Errno::INVAL)
            .map_err(PageMapInitializationError::failed)?;
        let header_bytes = mapped_size_for_count(virtual_reserve_count)
            .ok_or(Errno::NOMEM)
            .map_err(PageMapInitializationError::failed)?;
        let reserved_size = invariants::align_up(header_bytes, config.page_size().bytes())
            .ok_or(Errno::NOMEM)
            .map_err(PageMapInitializationError::failed)?;
        let reserved_count = page_map_count_of_size(reserved_size);
        let extra_reserve_size = reserved_size
            .checked_add(PAGE_MAP_SUB_SIZE)
            .ok_or(Errno::NOMEM)
            .map_err(PageMapInitializationError::failed)?;
        let commit_all = virtual_bits == crate::config::MIN_VABITS
            || reserved_size <= 64 * 1024
            || force_commit
            || config.has_overcommit();
        let initial_commit_bytes = if commit_all {
            None
        } else {
            let minimum_count = reserve_count(crate::config::MIN_VABITS)
                .ok_or(Errno::INVAL)
                .map_err(PageMapInitializationError::failed)?;
            Some(
                mapped_size_for_count(minimum_count)
                    .and_then(|bytes| invariants::align_up(bytes, config.page_size().bytes()))
                    .ok_or(Errno::NOMEM)
                    .map_err(PageMapInitializationError::failed)?,
            )
        };
        let access = if commit_all { MapAccess::Committed } else { MapAccess::Reserved };
        // Linux anonymous `mmap` returns a base-page-aligned address. The
        // source passes this same base-page alignment to its aligned helper,
        // whose direct-map branch therefore already satisfies the request.
        // Keep the exact direct primitive here: no overmap cleanup owner can
        // arise from a statically page-aligned PageMap extent.
        // `_mi_os_alloc_aligned(subproc, extra_reserve_size, 1, commit, ...)`
        // maps (and accounts) `_mi_os_good_alloc_size(extra_reserve_size)`.
        let mapped_size = config.good_alloc_size(extra_reserve_size);
        let mapping = match process {
            // `mi_os_prim_alloc_aligned` accounts its own attempts, trims, and
            // warnings to the process subprocess.
            Some(process) => Mapping::map_aligned_for_process(process, config, mapped_size,
                config.page_size().bytes(), access, true, None, crate::os::ThpAdvice::Source)
                .map_err(|failure| failure.error()),
            None => statistics.map(Mapping::map_for_allocator(config, mapped_size, access),
                mapped_size, commit_all),
        };
        let mapping = match mapping {
            Ok(mapping) => mapping,
            Err(error) => {
                // `src/page-map.c:302-305`. Process startup holds no
                // allocator projection a callback could reenter, and no
                // output or error callback can be registered before it.
                let _ = crate::process_init::process_error_message(
                    crate::diagnostic_output::SourceErrorReport::PageMapReservation {
                        kib: extra_reserve_size / 1024,
                    },
                );
                return Err(PageMapInitializationError::failed(error));
            }
        };
        let base = match mapping.base() {
            Ok(base) => base,
            Err(error) => {
                return Err(PageMapInitializationError::after_private_mapping_failure(
                    mapping, error, statistics,
                ));
            }
        };
        let header = match NonNull::new(base.cast::<PageMapHeader>()) {
            Some(header) => header,
            None => {
                return Err(PageMapInitializationError::after_private_mapping_failure(
                    mapping,
                    Errno::NOMEM,
                    statistics,
                ));
            }
        };

        let committed_count = match initial_commit_bytes {
            None => page_map_count_of_size(reserved_size),
            Some(minimum_bytes) => {
                if let Err(error) = statistics.commit(mapping.commit(0, minimum_bytes), minimum_bytes) {
                    return Err(PageMapInitializationError::after_private_mapping_failure(
                        mapping, error, statistics,
                    ));
                }
                page_map_count_of_size(minimum_bytes)
            }
        };

        let sub0 = base.wrapping_add(reserved_size).cast::<PageEntry>();
        if !commit_all {
            if let Err(error) = statistics.commit(
                mapping.commit(reserved_size, PAGE_MAP_SUB_SIZE), PAGE_MAP_SUB_SIZE,
            ) {
                return Err(PageMapInitializationError::after_private_mapping_failure(
                    mapping, error, statistics,
                ));
            }
        }
        // SAFETY: the trailing submap is committed, exclusively owned, and is
        // exactly `PAGE_MAP_SUB_SIZE` bytes at pointer alignment.
        unsafe { initialize_submap(sub0) };
        let memid = MemoryId::os(
            base,
            mapped_size,
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
                lock: PageMapLock::new(),
                submaps: [UnsafeCell::new(null_mut())],
            });
        }
        // Source order: first publish the committed top-level extent, then the
        // eagerly reserved submap zero. A later root Release publishes both.
        unsafe { &*header.as_ptr() }
            .committed_count
            .store(committed_count, Ordering::Release);
        unsafe { atomic_submap_slot(header, 0) }.store(sub0, Ordering::Release);

        Ok(Self {
            mapping,
            config,
            statistics,
            source_process: process,
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

    /// The source `reserved_size`: the page-aligned header and entry span,
    /// excluding the trailing submap for the NULL address.
    #[cfg(feature = "native-runtime-test-audit")]
    pub(crate) fn reserved_size(&self) -> Result<usize> {
        Ok(self.header()?.reserved_size)
    }

    /// Returns a read-only ownership audit after callers have established the
    /// PageMap's normal external no-mutation boundary. This test-only view
    /// counts source-plain live registrations rather than treating retained
    /// process-lifetime submaps as worker-owned leaks.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    pub(crate) fn test_registered_entry_count(&self) -> Result<usize> {
        self.header()?;
        #[cfg(feature = "native-runtime-test-audit")]
        if self.statistics.0.is_some() {
            // The separate class audit is called immediately after this
            // process-map observation while its owner remains quiescent.
            LAST_AUDITED_PROCESS_MAP.store(core::ptr::from_ref(self).cast_mut(), Ordering::Release);
        }
        Ok(self.registered_entry_count.load(Ordering::Acquire))
    }

    /// Classifies each registered slice without acquiring a page or a map
    /// mutation right. The sum of the kind buckets and the sum of the owner
    /// buckets must each equal `registered_slices`.
    ///
    /// # Safety
    ///
    /// The caller must keep every registered page image alive and establish
    /// process-wide quiescence across registration, unregistration, page
    /// ownership changes, and page release for the entire scan.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    pub(crate) unsafe fn test_class_audit(&self) -> Result<PageMapClassTestAudit> {
        let mut audit = PageMapClassTestAudit::default();
        for index in 0..self.committed_count()? {
            let Some(submap) = self.submap_at(index)? else { continue; };
            for offset in 0..PAGE_MAP_SUB_COUNT {
                // SAFETY: the published submap bounds this entry; the caller
                // excludes entry mutation and retains every registered page.
                let page = unsafe { *(*submap.as_ptr().add(offset)).0.get() };
                let Some(page_ref) = (unsafe { page.as_ref() }) else { continue; };
                audit.registered_slices += 1;
                let used = page_ref.used() != 0;
                let kind = crate::size_class::page_kind_for_block_size(page_ref.block_size());
                match kind {
                    Some(crate::types::PageKind::Small) if used => audit.small_used_slices += 1,
                    Some(crate::types::PageKind::Small) => audit.small_empty_slices += 1,
                    Some(crate::types::PageKind::Medium) if used => audit.medium_used_slices += 1,
                    Some(crate::types::PageKind::Medium) => audit.medium_empty_slices += 1,
                    Some(crate::types::PageKind::Large) if used => audit.large_used_slices += 1,
                    Some(crate::types::PageKind::Large) => audit.large_empty_slices += 1,
                    Some(crate::types::PageKind::Singleton) if used => audit.singleton_used_slices += 1,
                    Some(crate::types::PageKind::Singleton) => audit.singleton_empty_slices += 1,
                    None => audit.unknown_kind_slices += 1,
                }
                let owner = page_ref.owner_thread_id() & !crate::types::PAGE_FLAG_MASK;
                match owner {
                    crate::types::THREAD_ID_ABANDONED
                    | crate::types::THREAD_ID_ABANDONED_MAPPED => {
                        audit.abandoned_slices += 1;
                        if kind == Some(crate::types::PageKind::Medium) {
                            audit.medium_abandoned_slices += 1;
                        }
                    }
                    crate::types::THREAD_ID_DETACHED => {
                        audit.detached_slices += 1;
                        if kind == Some(crate::types::PageKind::Medium) {
                            audit.medium_detached_slices += 1;
                        }
                    }
                    _ => {
                        audit.attached_slices += 1;
                        if kind == Some(crate::types::PageKind::Medium) {
                            audit.medium_attached_slices += 1;
                        }
                    }
                }
                if kind == Some(crate::types::PageKind::Medium) {
                    if page_ref.has_published_remote_free() {
                        audit.medium_remote_pending_slices += 1;
                    }
                    if page_ref.has_owner_exit_collectable_local_free() {
                        audit.medium_reusable_slices += 1;
                    }
                    if page_ref.retire_expire() != 0 {
                        audit.medium_retired_slices += 1;
                    }
                }
                if page_ref.aligned_alias_owner() != page {
                    audit.nonprimary_slices += 1;
                }
            }
        }
        if audit.registered_slices != self.registered_entry_count.load(Ordering::Acquire) {
            return Err(Errno::INVAL);
        }
        Ok(audit)
    }

    /// Counts registered slices whose page belongs to the source detached
    /// metadata Theap, using `subproc.c::_mi_meta_is_meta_page` identity.
    ///
    /// # Safety
    ///
    /// The caller must establish process-wide quiescence: no registration,
    /// unregistration, page ownership transition, or page release may overlap
    /// this scan. Every registered page must retain its initialized image.
    #[cfg(feature = "native-runtime-test-audit")]
    pub(crate) unsafe fn test_metadata_registered_entry_count(
        &self,
        subprocess: &crate::subproc::MainSubprocess,
    ) -> Result<usize> {
        let mut count = 0;
        for index in 0..self.committed_count()? {
            let Some(submap) = self.submap_at(index)? else { continue; };
            for offset in 0..PAGE_MAP_SUB_COUNT {
                // SAFETY: the published submap bounds this entry; the caller
                // excludes entry mutation and retains every registered page.
                let page = unsafe { *(*submap.as_ptr().add(offset)).0.get() };
                // SAFETY: null is admitted and every nonnull registered page
                // remains initialized and quiescent for this observation.
                if subprocess.is_metadata_page(unsafe { page.as_ref() }) {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Counts published submaps and the lazy publications that created them.
    /// Both are process-map ownership observations, not allocator policy.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    pub(crate) fn test_published_submap_count(&self) -> Result<usize> {
        self.header()?;
        Ok(self.published_submap_count.load(Ordering::Acquire))
    }

    /// Visits numeric `(base_address, byte_length)` spans of this map's
    /// actual retained mappings. The root owner includes embedded submap zero;
    /// each separately published lazy submap is reported once under the source
    /// publication lock. These numbers convey no pointer or release authority.
    ///
    /// # Safety
    /// The caller retains the ready VM owner and excludes terminal destruction
    /// for the entire visit. The callback may only record bounded stack scalars:
    /// it cannot allocate, invoke user callbacks, or reenter the allocator or
    /// map publication while the source publication lock is held.
    #[cfg(all(target_arch = "x86_64", any(test, feature = "native-runtime-test-audit")))]
    pub(crate) unsafe fn test_visit_mapping_extents(
        &self,
        mut visitor: impl FnMut(usize, usize),
    ) -> Result<()> {
        let header = self.header()?;
        let guard = header.lock.lock()?;
        visitor(self.mapping.base()?.addr(), self.mapping.length()?);
        let count = header.committed_count.load(Ordering::Acquire);
        for index in 1..count {
            // SAFETY: the Acquire count proves the aligned raw pointer word
            // committed. The actual source lock excludes submap publication,
            // and the caller's owner admission excludes mapping retirement.
            let submap = unsafe { atomic_submap_slot(self.header, index) }.load(Ordering::Acquire);
            if !submap.is_null() {
                visitor(submap.addr(), PAGE_MAP_SUB_SIZE);
            }
        }
        guard.unlock()?;
        Ok(())
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
        if let Err(error) = self.statistics.commit(self.mapping.commit(0, commit_size), commit_size) {
            // The failed OS commit has already advanced its call statistic.
            // Source reports that failure before the PageMap refusal; the
            // null replay may then commit the same top range successfully.
            let address = self.mapping.base()?.addr();
            let os_warning = crate::diagnostic_output::SourceFormattedMessage::os_commit_failure(
                error, address, commit_size,
            );
            let map_warning = crate::diagnostic_output::SourceFormattedMessage::from_source_formatted(
                c"unable to commit the allocation page-map on-demand\n",
            );
            if let Some(process) = self.source_process {
                process.policy().source_warning(os_warning);
                process.policy().source_warning(map_warning);
            } else {
                crate::process_init::process_warning_message(os_warning);
                crate::process_init::process_warning_message(map_warning);
            }
            return Err(error);
        }
        // Fresh anonymous committed pages already contain valid aligned null
        // raw-pointer words. No placement writes race another source-faithful
        // unlocked commit; only this Release exposes the new extent.
        self.header()?
            .committed_count
            .store(commit_count, Ordering::Release);
        Ok(())
    }

    fn submap_at(&self, index: usize) -> Result<Option<NonNull<PageEntry>>> {
        self.header()?;
        // SAFETY: `header` established that this map is active.
        Ok(unsafe { self.submap_at_active(index) })
    }

    /// # Safety
    /// The map must remain active throughout the lookup.
    #[inline(always)]
    unsafe fn submap_at_active(&self, index: usize) -> Option<NonNull<PageEntry>> {
        let header = self.header;
        // SAFETY: the caller keeps the initialized mapped header live.
        if index >= unsafe { header.as_ref() }.committed_count.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the Acquire count proves the raw pointer word is committed;
        // its atomic view is aligned and pairs with submap publication.
        NonNull::new(
            unsafe { atomic_submap_slot(header, index) }.load(Ordering::Acquire),
        )
    }

    fn ensure_submap_at(&self, index: usize) -> Result<NonNull<PageEntry>> {
        self.ensure_committed(index)?;
        if let Some(submap) = self.submap_at(index)? {
            return Ok(submap);
        }

        let guard = self.header()?.lock.lock()?;
        let mut failed_map = None;
        let result = (|| if let Some(submap) = self.submap_at(index)? {
            Ok(submap)
        } else {
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            self.submap_allocations.fetch_add(1, Ordering::Relaxed);
            // See `PageMap::initialize`: the requested alignment is exactly
            // the Linux base-page guarantee of this direct anonymous mapping.
            // `_mi_os_zalloc(subproc, submap_size)`: a committed good-size map.
            let mapped_size = self.config.good_alloc_size(PAGE_MAP_SUB_SIZE);
            let mapped = Mapping::map_for_allocator(self.config, PAGE_MAP_SUB_SIZE,
                MapAccess::Committed);
            let mut candidate = match mapped {
                Ok(mapping) => self.statistics.map(Ok(mapping), mapped_size, true)?,
                Err(error) => {
                    failed_map = Some(error);
                    return Err(error);
                }
            };
            let candidate_base = candidate.base()?.cast::<PageEntry>();
            // SAFETY: the candidate mapping is exclusively owned and committed.
            unsafe { initialize_submap(candidate_base) };
            // SAFETY: ensure_committed proved this raw pointer word committed
            // before the source page-map lock was acquired.
            self.header()?;
            let slot = unsafe { atomic_submap_slot(self.header, index) };
            // The pinned source retains this defensive CAS even under its
            // page-map lock. In this Rust port, `PageMapHeader::submaps` and
            // `atomic_submap_slot` are private to this module, and every
            // current writer takes this same lock and reloads the slot above.
            // A loser is therefore unreachable in the present ownership
            // graph; it remains source-shaped rather than a fault-injection
            // release path. Any future competing writer must take this lock
            // or first give a losing candidate an explicit retained owner.
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
                    let size = self.config.good_alloc_size(PAGE_MAP_SUB_SIZE);
                    self.statistics.release(size, size);
                    candidate.unmap()?;
                    NonNull::new(winner).ok_or(Errno::NOMEM)
                }
            }
        })();
        let unlock = guard.unlock();
        if let Some(error) = failed_map {
            // The callback may reenter PageMap. No submap was published, so
            // unlock first, deliver the failed OS allocation warning while
            // its source statistics still reflect the preceding page, then
            // charge the failed mmap before the PageMap warning and rollback.
            let allocation_warning = crate::diagnostic_output::SourceFormattedMessage::os_alloc_failure(
                error, 0, self.config.good_alloc_size(PAGE_MAP_SUB_SIZE), 1, true, false,
            );
            if let Some(process) = self.source_process {
                process.policy().source_warning(allocation_warning);
            } else {
                crate::process_init::process_warning_message(allocation_warning);
            }
            let _: Result<Mapping> = self.statistics.map(Err(error),
                self.config.good_alloc_size(PAGE_MAP_SUB_SIZE), true);
            let map_warning = crate::diagnostic_output::SourceFormattedMessage::from_source_formatted(
                c"internal error: unable to extend the page map\n",
            );
            if let Some(process) = self.source_process {
                process.policy().source_warning(map_warning);
            } else {
                crate::process_init::process_warning_message(map_warning);
            }
        }
        unlock?;
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
        if !self.active {
            return null_mut();
        }
        // SAFETY: the activity check above keeps the mapped header available.
        unsafe { self.checked_lookup_in_active_map(address) }
    }

    /// Looks up a possibly unregistered address in a map already known active.
    ///
    /// # Safety
    /// The map must remain active throughout this call. The caller must also
    /// exclude an overlapping registration or unregistration of the selected
    /// arena slice, as for `checked_lookup`.
    #[inline(always)]
    pub(crate) unsafe fn checked_lookup_in_active_map(&self, address: *const u8) -> *mut Page {
        let location = location_of_address(address.addr());
        let Some(submap) = (unsafe { self.submap_at_active(location.map_index) }) else {
            return null_mut();
        };
        // SAFETY: location arithmetic bounds sub_index and the caller excludes
        // a conflicting plain write.
        unsafe { *(*submap.as_ptr().add(location.sub_index)).0.get() }
    }

    /// Pinned `_mi_unchecked_ptr_page` for the two-level map: the page of an
    /// address inside a live registered allocation, with none of
    /// [`Self::checked_lookup`]'s activity, committed-count, and null-submap
    /// guards (normal-release `_mi_ptr_page` has none either).
    ///
    /// # Safety
    ///
    /// The map is active and `address` lies inside an allocation whose page
    /// range is registered and stays registered through this read, so its
    /// submap slot is committed and published; as for `checked_lookup`, no
    /// registration or unregistration of that slice overlaps the read.
    #[inline(always)]
    pub(crate) unsafe fn live_lookup(&self, address: *const u8) -> *mut Page {
        let location = location_of_address(address.addr());
        // SAFETY: an active map's header is live; the registered range proves
        // the slot committed and its submap published.
        unsafe {
            let submap = atomic_submap_slot(self.header, location.map_index).load(Ordering::Acquire);
            *(*submap.add(location.sub_index)).0.get()
        }
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
            self.header()?;
            let slot = unsafe { atomic_submap_slot(self.header, index) };
            let submap = slot.load(Ordering::Acquire);
            if !submap.is_null() {
                // SAFETY: exclusive `&mut self` plus documented quiescence owns
                // the unique release right transferred into this pointer.
                unsafe { Mapping::reclaim_published(submap.cast(), PAGE_MAP_SUB_SIZE) }?;
                // `_mi_os_free_ex(subproc, sub, MI_PAGE_MAP_SUB_SIZE, true, ...)`.
                self.statistics.release(PAGE_MAP_SUB_SIZE, PAGE_MAP_SUB_SIZE);
                slot.store(null_mut(), Ordering::Release);
            }
        }
        #[cfg(test)]
        if core::mem::replace(&mut self.fail_next_top_release, false) {
            return Err(Errno::NOMEM);
        }
        let length = self.mapping.length()?;
        self.mapping.unmap()?;
        // `_mi_os_free_ex(subproc, pmap, reserved_size, true, pmap->memid)`
        // frees the memid's complete extent as still committed.
        self.statistics.release(length, length);
        self.active = false;
        Ok(())
    }
}

/// Copies a quiescent process-map class audit after the scalar audit has
/// selected the exact map. This symbol exists only in native test products.
///
/// # Safety
///
/// `output` must name aligned writable `PageMapClassTestAudit` storage, and
/// `output_bytes` must equal its size. The caller
/// must have just obtained the process scalar audit, must keep that process
/// map and every registered page alive, and must exclude all allocator
/// operations until this scan completes.
#[cfg(feature = "native-runtime-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_mimalloc_page_map_class_test_audit(
    output: *mut core::ffi::c_void,
    output_bytes: usize,
) -> i32 {
    if output_bytes != size_of::<PageMapClassTestAudit>() { return -1; }
    let Some(output) = NonNull::new(output.cast::<PageMapClassTestAudit>()) else { return -1; };
    let Some(page_map) = NonNull::new(LAST_AUDITED_PROCESS_MAP.load(Ordering::Acquire)) else {
        return -1;
    };
    // SAFETY: the caller's process-wide quiescence keeps this last selected
    // process map and every registered page image live through the scan.
    let Ok(snapshot) = (unsafe { page_map.as_ref().test_class_audit() }) else { return -1; };
    // SAFETY: the caller supplies writable, correctly typed output storage.
    unsafe { output.as_ptr().write(snapshot) };
    0
}

/// The main-subprocess statistics owner of a process page map's VM events,
/// or none for a private map. Pinned `page-map.c` records every page-map
/// allocation, commit, and free on `_mi_subproc_main()` exactly as
/// `src/os.c` does for any other caller.
#[derive(Clone, Copy)]
struct PageMapStatistics(Option<&'static crate::subproc::SubprocessIdentity>);

impl PageMapStatistics {
    /// `mi_os_prim_alloc_at`: one `mmap_calls` event per attempt, then the
    /// reserved (and, when committed, committed) extent on success.
    fn map(self, result: Result<Mapping>, size: usize, committed: bool) -> Result<Mapping> {
        if let Some(subprocess) = self.0 {
            let statistics = subprocess.vm_statistics();
            statistics.mmap_call();
            if result.is_ok() {
                statistics.reserve_increase(size);
                if committed { statistics.committed_increase(size); }
            }
        }
        result
    }

    /// `_mi_os_commit`: one `commit_calls` event per attempt, then the
    /// committed extent on success.
    fn commit<T>(self, result: Result<T>, size: usize) -> Result<T> {
        if let Some(subprocess) = self.0 {
            let statistics = subprocess.vm_statistics();
            statistics.commit_call();
            if result.is_ok() { statistics.committed_increase(size); }
        }
        result
    }

    /// `mi_os_prim_free` without adjustment.
    fn release(self, reserved: usize, committed: usize) {
        if let Some(subprocess) = self.0 {
            let statistics = subprocess.vm_statistics();
            if committed != 0 { statistics.committed_decrease(committed); }
            statistics.reserve_decrease(reserved);
        }
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
/// `header` must identify a live mapped `PageMapHeader` with the provenance
/// of its whole mapping, and `index` must be within its currently committed
/// top-level extent. The raw pointer word must not be accessed
/// non-atomically for the duration of the returned reference.
///
/// A `&PageMapHeader` covers only the declared one-element `submaps` array,
/// so the committed flexible tail is projected from the raw mapping pointer.
unsafe fn atomic_submap_slot<'a>(
    header: NonNull<PageMapHeader>,
    index: usize,
) -> &'a AtomicPtr<PageEntry> {
    // SAFETY: the caller supplies a live mapped header; this only computes
    // the flexible array's address.
    let first = unsafe { core::ptr::addr_of!((*header.as_ptr()).submaps) }
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
    use crate::os::{PageSize, fault};
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
        assert_eq!(size_of::<PageMapHeader>(), if cfg!(target_arch = "x86_64") { 88 } else { 56 });
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(size_of::<PageMapLock>(), 40);
            assert_eq!(core::mem::align_of::<PageMapLock>(), 8);
            assert_eq!(core::mem::offset_of!(PageMapHeader, lock), 40);
            assert_eq!(core::mem::offset_of!(PageMapHeader, submaps), 80);
        }
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
        assert_eq!(page_map_count_of_size(source_reserved), requested + if cfg!(target_arch = "x86_64") { 502 } else { 506 });
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
        assert_eq!(initial_count, minimum + if cfg!(target_arch = "x86_64") { 502 } else { 506 });

        let required_index = initial_count + 1;
        let extension_bytes = invariants::align_up(
            size_of::<PageMapHeader>() + required_index * size_of::<*mut PageEntry>(),
            ARENA_SLICE_SIZE,
        )
        .unwrap();
        assert_eq!(extension_bytes, 192 * 1024);
        assert_eq!(page_map_count_of_size(extension_bytes), if cfg!(target_arch = "x86_64") { 24_566 } else { 24_570 });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn lazy_commit_extends_at_the_source_linux_header_boundary() {
        let mut page_map = PageMap::initialize(memory_config(false), 47, false)
            .expect("reserve the source lazy-commit profile");
        assert_eq!(page_map.header().unwrap().reserved_size, 2_101_248);
        assert_eq!(page_map.committed_count(), Ok(16_886));
        assert_eq!(page_map.reserved_count(), 262_646);

        // The last index whose complete source header fits in four slices
        // commits that prefix. Its successor needs a fifth slice even though
        // a smaller private lock representation would still fit in four.
        page_map.ensure_committed(32_757).unwrap();
        assert_eq!(page_map.committed_count(), Ok(32_758));
        page_map.ensure_committed(32_758).unwrap();
        assert_eq!(page_map.committed_count(), Ok(40_950));
        assert!(page_map.submap_at(32_758).unwrap().is_none());
        // SAFETY: no roots, registered ranges, or readers remain.
        unsafe { page_map.destroy() }.unwrap();
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mapping_extent_visit_reports_actual_owner_spans_without_embedded_submap_duplication() {
        let mut page_map = PageMap::initialize(memory_config(false), MAX_VABITS, false).unwrap();
        let root_span = (page_map.mapping.base().unwrap().addr(), page_map.mapping.length().unwrap());
        let embedded = page_map.submap_at(0).unwrap().unwrap().as_ptr().addr();
        assert!(embedded >= root_span.0);
        assert!(embedded + PAGE_MAP_SUB_SIZE <= root_span.0 + root_span.1);
        let mut initial = [(0, 0); 4];
        let mut initial_count = 0;
        // SAFETY: this fixture retains the actual map, no terminal destroy
        // runs, and the callback only records bounded stack scalars.
        unsafe { page_map.test_visit_mapping_extents(|base, length| {
            if let Some(slot) = initial.get_mut(initial_count) { *slot = (base, length); }
            initial_count += 1;
        }) }.unwrap();
        assert_eq!(initial_count, 1);
        assert_eq!(initial[0], root_span);

        let first = page_map.ensure_submap_at(1).unwrap().as_ptr().addr();
        let third = page_map.ensure_submap_at(3).unwrap().as_ptr().addr();
        assert!(page_map.submap_at(2).unwrap().is_none());
        let mut captured = [(0, 0); 4];
        let mut count = 0;
        let mut publication_locked = true;
        // SAFETY: the same real owner remains live. Atomic lock observation
        // and fixed stack writes cannot allocate or reenter publication.
        unsafe { page_map.test_visit_mapping_extents(|base, length| {
            publication_locked &= page_map.header().unwrap().lock.try_lock().is_none();
            if let Some(slot) = captured.get_mut(count) { *slot = (base, length); }
            count += 1;
        }) }.unwrap();
        assert!(publication_locked);
        assert_eq!(count, 3);
        assert_eq!(captured[..count], [root_span, (first, PAGE_MAP_SUB_SIZE), (third, PAGE_MAP_SUB_SIZE)]);
        assert_eq!(page_map.mapping.base().unwrap().addr(), root_span.0);
        assert_eq!(page_map.mapping.length().unwrap(), root_span.1);
        // SAFETY: no root, registered entries or observer remains live.
        unsafe { page_map.destroy() }.unwrap();
        // SAFETY: the inactive object is retained and no callback can run.
        assert_eq!(unsafe { page_map.test_visit_mapping_extents(|_, _| {
            panic!("retired mapping cannot be observed");
        }) }, Err(Errno::INVAL));
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
            Some(page_map.memory_config().good_alloc_size(expected_reserved_size + PAGE_MAP_SUB_SIZE)),
            "`_mi_os_alloc_aligned` maps the good-size extent",
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

    #[test]
    fn overlapping_range_churn_counts_registered_entries_instead_of_retained_submaps() {
        let mut page_map = PageMap::initialize(memory_config(false), MIN_VABITS, false)
            .expect("initialize the two-level page map");
        let first_slice = PAGE_MAP_SUB_COUNT - 3;
        let start = core::ptr::without_provenance::<u8>(first_slice * ARENA_SLICE_SIZE);
        let page = NonNull::from(EMPTY_PAGE.as_ref());
        let check = |expected: [bool; 8]| {
            let mut registered = 0;
            for (index, occupied) in expected.into_iter().enumerate() {
                let address = start.wrapping_add(index * ARENA_SLICE_SIZE);
                // SAFETY: no entry mutation overlaps this observation, and the
                // marker remains live for the whole test.
                let observed = unsafe { page_map.checked_lookup(address) };
                assert_eq!(observed, if occupied { page.as_ptr() } else { null_mut() });
                registered += usize::from(occupied);
            }
            assert_eq!(page_map.test_registered_entry_count(), Ok(registered));
        };

        check([false; 8]);
        // SAFETY: this test is the only map client and its marker stays live.
        unsafe {
            page_map.register_range(start, 4 * ARENA_SLICE_SIZE, page).unwrap();
        }
        check([true, true, true, true, false, false, false, false]);
        assert_eq!(page_map.test_published_submap_count(), Ok(2));

        // Replacing two live entries must only count the two newly occupied
        // slices, even though the range crosses a published submap boundary.
        unsafe {
            page_map.register_range(start.wrapping_add(2 * ARENA_SLICE_SIZE),
                4 * ARENA_SLICE_SIZE, page).unwrap();
        }
        check([true, true, true, true, true, true, false, false]);

        unsafe {
            page_map.unregister_range(start.wrapping_add(ARENA_SLICE_SIZE),
                4 * ARENA_SLICE_SIZE).unwrap();
        }
        check([true, false, false, false, false, true, false, false]);
        // Source unregistration also accepts ranges that are already clear.
        unsafe {
            page_map.unregister_range(start.wrapping_add(ARENA_SLICE_SIZE),
                4 * ARENA_SLICE_SIZE).unwrap();
        }
        check([true, false, false, false, false, true, false, false]);

        unsafe {
            page_map.register_range(start.wrapping_add(3 * ARENA_SLICE_SIZE),
                4 * ARENA_SLICE_SIZE, page).unwrap();
        }
        check([true, false, false, true, true, true, true, false]);
        unsafe { page_map.unregister_range(start, 8 * ARENA_SLICE_SIZE).unwrap() };
        check([false; 8]);
        assert_eq!(page_map.test_published_submap_count(), Ok(2));

        // SAFETY: this unpublished map has no readers or registered entries.
        unsafe { page_map.destroy() }.expect("release the map after churn");
    }

    #[test]
    fn page_class_audit_counts_registered_slices_and_abandoned_owner_state() {
        let mut page_map = PageMap::initialize(memory_config(false), MIN_VABITS, false)
            .expect("initialize the two-level page map");
        let mut page = std::boxed::Box::new(Page::remote_free_test_page(1, 1));
        let start = core::ptr::without_provenance::<u8>(4 * ARENA_SLICE_SIZE);
        // SAFETY: the boxed page remains stable and initialized until this
        // range is cleared; no other map client or page owner runs.
        unsafe {
            page_map.register_range(start, 2 * ARENA_SLICE_SIZE, NonNull::from(page.as_mut()))
                .expect("register the two-slice test page");
        }
        // SAFETY: this test is the only map and page client.
        let attached = unsafe { page_map.test_class_audit() }.unwrap();
        assert_eq!(attached.registered_slices, 2);
        assert_eq!(attached.small_used_slices, 2);
        assert_eq!(attached.attached_slices, 2);
        assert_eq!(attached.abandoned_slices, 0);

        page.set_block_size(crate::config::SMALL_MAX_OBJ_SIZE + 1);
        page.remote_free_test_set_local_free(NonNull::dangling().as_ptr());
        page.set_retire_expire(1);
        // SAFETY: the page's test-only state changed before this sole reader.
        let medium = unsafe { page_map.test_class_audit() }.unwrap();
        assert_eq!(medium.medium_used_slices, 2);
        assert_eq!(medium.medium_attached_slices, 2);
        assert_eq!(medium.medium_reusable_slices, 2);
        assert_eq!(medium.medium_retired_slices, 2);
        assert_eq!(medium.medium_remote_pending_slices, 0);

        page.remote_free_test_mark_abandoned();
        // SAFETY: the ownership transition finished before this sole reader.
        let abandoned = unsafe { page_map.test_class_audit() }.unwrap();
        assert_eq!(abandoned.registered_slices, 2);
        assert_eq!(abandoned.medium_used_slices, 2);
        assert_eq!(abandoned.medium_abandoned_slices, 2);
        assert_eq!(abandoned.abandoned_slices, 2);
        assert_eq!(abandoned.attached_slices, 0);

        // SAFETY: the test still owns the exact range and page lifetime.
        unsafe { page_map.unregister_range(start, 2 * ARENA_SLICE_SIZE).unwrap() };
        // SAFETY: no map writer or page owner runs during this empty scan.
        let cleared = unsafe { page_map.test_class_audit() }.unwrap();
        assert_eq!(cleared.registered_slices, 0);
        assert_eq!(cleared.medium_used_slices, 0);
        assert_eq!(cleared.abandoned_slices, 0);
        // SAFETY: the map has no root, readers, or registered entries.
        unsafe { page_map.destroy() }.unwrap();
    }

    /// Emits the address-free PageMap success differential record. Both
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
        let layout_lock_bytes = size_of::<PageMapLock>();
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
        // Pinned bits.h selects 47 user-address bits on x86-64, 48 on AArch64.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(control_max_vabits, 47);
        #[cfg(target_arch = "aarch64")]
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

    /// Emits the selected PageMap lazy-commit failure differential record.
    ///
    /// The pinned `mi_page_map_commit_entries` body fails before its Release
    /// `committed_count` publication and before `mi_page_map_ensure_submap_at`
    /// can allocate a submap. This Rust witness injects at the matching
    /// `Mapping::commit` boundary, proves that the existing top-level mapping
    /// remains the exact retry owner, then retries the one pending extension.
    /// It deliberately excludes cold initialization, range rollback, submap
    /// map failure, release failure, and concurrent publication.
    /// The source `mi_page_map_init_once` with its initial (1) or trailing-submap
    /// (2) commit failing and the cleanup unmap failing too. Initialization
    /// fails and the mapping leaks, exactly as the pinned C leaks it.
    #[cfg(not(miri))]
    #[test]
    fn emit_m2_page_map_init_cleanup_c_rust_trace() {
        let page = memory_config(false).page_size().bytes();
        let mut field = 0usize;
        let mut emit = |value: usize| {
            std::println!("m2.page_map.init_cleanup.{field}={value}");
            field += 1;
        };
        for ordinal in 1..=2usize {
            let fault = fault::install(fault::Plan::at_pair(
                fault::Point::Commit, ordinal, fault::Point::Unmap, 1, Errno::NOMEM,
            ));
            let capture = fault.capture_unmap_ranges();
            let result = PageMap::initialize(memory_config(false), MAX_VABITS, false);
            let failed = matches!(result, Err(PageMapInitializationError::Failed { .. }));
            let commit_calls = fault.observed();
            let failed_releases = fault.secondary_observed();
            let leaked = capture.all().and_then(|(ranges, count)| (count != 0).then(|| ranges[count - 1]));
            drop(capture);
            fault.set(fault::Plan::disabled());
            if let Ok(mut page_map) = result {
                // SAFETY: this unpublished fixture map has no other user.
                let _ = unsafe { page_map.destroy() };
            }
            let mut residency = 0u8;
            // SAFETY: `mincore` only reads the page tables of this range.
            let leaked_live = leaked.is_some_and(|(address, _)| unsafe {
                crabc_core::mm::mincore_raw(address as *mut u8, page, &mut residency)
            }.is_ok());
            emit(ordinal);
            emit(usize::from(failed));
            emit(commit_calls);
            emit(failed_releases);
            emit(usize::from(leaked_live));
            if let Some((address, length)) = leaked {
                // SAFETY: the leaked mapping is represented by no owner.
                unsafe { crabc_core::mm::munmap_raw(address as *mut u8, length) }
                    .expect("fixture teardown of the leaked PageMap mapping");
            }
        }
    }

    #[test]
    fn emit_m2_page_map_lazy_commit_failure_c_rust_trace() {
        let mut page_map = PageMap::initialize(memory_config(false), MAX_VABITS, false)
            .expect("initialize the selected partial two-level page map");
        let control_page_size = page_map.memory_config().page_size().bytes();
        let control_has_overcommit_false = !page_map.memory_config().has_overcommit();
        let control_max_vabits = MAX_VABITS;
        let committed_before = page_map
            .committed_count()
            .expect("the initialized PageMap exposes its committed prefix");
        let target = committed_before
            .checked_add(1)
            .expect("the selected lazy extension index is representable");
        assert!(target < page_map.reserved_count());
        let top_mapping = page_map
            .mapping
            .base()
            .expect("the initialized PageMap retains its top-level mapping");

        let fault = fault::install(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        let failure_returned = page_map.ensure_submap_at(target) == Err(Errno::NOMEM);
        let failure_commit_attempts = fault.observed();
        let failure_committed_unchanged = page_map.committed_count() == Ok(committed_before);
        // `submap_at` first checks the committed prefix, so this observes the
        // source's pre-publication boundary without reading an uncommitted
        // raw slot.
        let failure_no_submap_result = page_map.submap_at(target) == Ok(None);
        let failure_submap_allocation_attempts = page_map.test_lazy_submap_allocation_count();
        let failure_top_owner_retained = page_map.mapping.base() == Ok(top_mapping);

        fault.set(fault::Plan::disabled());
        let retry_submap = page_map
            .ensure_submap_at(target)
            .expect("the unchanged top-level owner retries the lazy extension");
        let retry_succeeded = page_map.submap_at(target) == Ok(Some(retry_submap));
        let retry_committed_advanced = page_map
            .committed_count()
            .expect("the successful retry leaves the PageMap active")
            > committed_before;
        let retry_submap_allocation_attempts = page_map.test_lazy_submap_allocation_count();

        // SAFETY: this test owns the only PageMap client and leaves no root or
        // registration to quiesce before releasing the successful retry.
        let cleanup_top_owner_released = unsafe { page_map.destroy() }.is_ok()
            && page_map.mapping.base() == Err(Errno::INVAL);

        assert_eq!(control_page_size, 4 * 1024);
        assert!(control_has_overcommit_false);
        // Keep the C/Rust trace control matched to the target's bits.h profile.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(control_max_vabits, 47);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(control_max_vabits, 48);
        assert!(failure_returned);
        assert_eq!(failure_commit_attempts, 1);
        assert!(failure_committed_unchanged);
        assert!(failure_no_submap_result);
        assert_eq!(failure_submap_allocation_attempts, 0);
        assert!(failure_top_owner_retained);
        assert!(retry_succeeded);
        assert!(retry_committed_advanced);
        assert_eq!(retry_submap_allocation_attempts, 1);
        assert!(cleanup_top_owner_released);

        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        std::println!("CRABC_MI_M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_BEGIN");
        emit!("m2.page_map.lazy_commit.control.page_size", control_page_size);
        emit!(
            "m2.page_map.lazy_commit.control.has_overcommit_false",
            control_has_overcommit_false
        );
        emit!("m2.page_map.lazy_commit.control.max_vabits", control_max_vabits);
        emit!(
            "m2.page_map.lazy_commit.failure.target_above_committed",
            target > committed_before
        );
        emit!(
            "m2.page_map.lazy_commit.failure.commit_attempts",
            failure_commit_attempts
        );
        emit!("m2.page_map.lazy_commit.failure.returned", failure_returned);
        emit!(
            "m2.page_map.lazy_commit.failure.committed_unchanged",
            failure_committed_unchanged
        );
        emit!(
            "m2.page_map.lazy_commit.failure.no_submap_result",
            failure_no_submap_result
        );
        emit!(
            "m2.page_map.lazy_commit.failure.submap_allocation_attempts",
            failure_submap_allocation_attempts
        );
        emit!(
            "m2.page_map.lazy_commit.failure.top_owner_retained",
            failure_top_owner_retained
        );
        emit!("m2.page_map.lazy_commit.retry.succeeded", retry_succeeded);
        emit!(
            "m2.page_map.lazy_commit.retry.committed_advanced",
            retry_committed_advanced
        );
        emit!(
            "m2.page_map.lazy_commit.retry.submap_present",
            retry_succeeded
        );
        emit!(
            "m2.page_map.lazy_commit.retry.submap_allocation_attempts",
            retry_submap_allocation_attempts
        );
        emit!(
            "m2.page_map.lazy_commit.cleanup.top_owner_released",
            cleanup_top_owner_released
        );
        std::println!("CRABC_MI_M2_PAGE_MAP_LAZY_COMMIT_FAILURE_TRACE_END");
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
    fn lazy_extension_commit_failure_preserves_the_top_level_mapping_for_retry() {
        let mut page_map = PageMap::initialize(memory_config(false), MAX_VABITS, false)
            .expect("initialize the selected partial map");
        let committed_before = page_map
            .committed_count()
            .expect("the initialized map exposes its committed prefix");
        let target = committed_before
            .checked_add(1)
            .expect("the selected map has a representable lazy-extension index");
        let top_mapping = page_map
            .mapping
            .base()
            .expect("the top-level mapping remains owned before the extension");
        let fault = fault::install(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));

        assert_eq!(page_map.ensure_submap_at(target), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1);
        assert_eq!(page_map.committed_count(), Ok(committed_before));
        assert_eq!(page_map.submap_at(target), Ok(None));
        assert_eq!(page_map.test_lazy_submap_allocation_count(), 0);
        assert_eq!(page_map.mapping.base(), Ok(top_mapping));

        fault.set(fault::Plan::disabled());
        let submap = page_map
            .ensure_submap_at(target)
            .expect("the same top-level mapping retries the lazy extension");
        assert_eq!(page_map.submap_at(target), Ok(Some(submap)));
        assert_eq!(page_map.test_lazy_submap_allocation_count(), 1);
        // SAFETY: this test owns the only PageMap client and has no root or
        // registered range to quiesce before the retryable release.
        unsafe { page_map.destroy() }.expect("the retried map release succeeds");
    }

    #[test]
    fn lazy_submap_mapping_failure_preserves_the_page_map_for_retry() {
        let mut page_map = PageMap::initialize(memory_config(false), MAX_VABITS, false)
            .expect("initialize the selected partial map");
        let committed_before = page_map
            .committed_count()
            .expect("the initialized map exposes its committed prefix");
        let target = committed_before
            .checked_add(1)
            .expect("the selected map has a representable lazy-extension index");
        let top_mapping = page_map
            .mapping
            .base()
            .expect("the top-level mapping remains owned before the extension");
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));

        assert_eq!(page_map.ensure_submap_at(target), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1);
        assert!(
            page_map.committed_count().expect("a failed lazy map keeps the PageMap live")
                > committed_before
        );
        assert_eq!(page_map.submap_at(target), Ok(None));
        assert_eq!(page_map.test_lazy_submap_allocation_count(), 1);
        assert_eq!(page_map.mapping.base(), Ok(top_mapping));

        fault.set(fault::Plan::disabled());
        let submap = page_map
            .ensure_submap_at(target)
            .expect("the same PageMap retries the lazy submap mapping");
        assert_eq!(page_map.submap_at(target), Ok(Some(submap)));
        assert_eq!(page_map.test_lazy_submap_allocation_count(), 2);
        // SAFETY: this test owns the only PageMap client and has no root or
        // registered range to quiesce before the retryable release.
        unsafe { page_map.destroy() }.expect("the retried map release succeeds");
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn failed_lazy_submap_warns_after_releasing_its_lock_and_retries() {
        static OUTPUT: std::sync::Mutex<std::vec::Vec<u8>> = std::sync::Mutex::new(std::vec::Vec::new());
        static MAP: AtomicPtr<PageMap> = AtomicPtr::new(null_mut());
        static WARNING_LOCK_WAS_FREE: core::sync::atomic::AtomicBool =
            core::sync::atomic::AtomicBool::new(false);

        unsafe extern "C" fn capture(message: *const core::ffi::c_char) {
            // SAFETY: the runtime output owner passes a live NUL-terminated
            // fragment for the duration of this callback.
            let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if bytes == b"internal error: unable to extend the page map\n" {
                let map = MAP.load(Ordering::Acquire);
                if !map.is_null() {
                    // SAFETY: the child owns this PageMap until after output
                    // delivery; this callback only probes its private lock.
                    let map = unsafe { &*map };
                    if let Ok(header) = map.header() {
                        WARNING_LOCK_WAS_FREE.store(header.lock.try_lock().is_some(), Ordering::Release);
                    }
                }
            }
            OUTPUT.lock().unwrap().extend_from_slice(bytes);
        }

        crate::test_process::run_in_fresh_process(
            "page_map::tests::failed_lazy_submap_warns_after_releasing_its_lock_and_retries",
            || {
                std::env::set_var("mimalloc_show_errors", "1");
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(capture) },
                ));
                OUTPUT.lock().unwrap().clear();
                let mut map = PageMap::initialize_for_subprocess(
                    memory_config(false), MAX_VABITS, false,
                    crate::subproc::MainSubprocess::global().identity(),
                ).expect("isolated map reservation");
                MAP.store(&mut map, Ordering::Release);
                let target = map.committed_count().unwrap() + 1;
                let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
                assert_eq!(map.ensure_submap_at(target), Err(Errno::NOMEM));
                assert_eq!(fault.observed(), 1);
                assert!(OUTPUT.lock().unwrap().windows(
                    b"internal error: unable to extend the page map\n".len(),
                ).any(|window| window == b"internal error: unable to extend the page map\n"));
                assert!(WARNING_LOCK_WAS_FREE.load(Ordering::Acquire));
                fault.set(fault::Plan::disabled());
                map.ensure_submap_at(target).expect("the same map retries");
                MAP.store(null_mut(), Ordering::Release);
                unsafe { map.destroy() }.expect("retryable map releases");
            },
        );
    }

    #[test]
    fn destroy_lazy_submap_release_failure_retains_the_exact_slot_for_retry() {
        let mut page_map = PageMap::initialize(memory_config(false), MAX_VABITS, false)
            .expect("initialize the selected partial map");
        let first_index = page_map
            .committed_count()
            .expect("the initialized map exposes its committed prefix")
            .checked_add(1)
            .expect("the selected map has a representable first lazy index");
        let second_index = first_index
            .checked_add(1)
            .expect("the selected map has a representable second lazy index");
        let first = page_map
            .ensure_submap_at(first_index)
            .expect("the first lazy submap is published");
        let second = page_map
            .ensure_submap_at(second_index)
            .expect("the second lazy submap is published");
        assert_ne!(first, second);
        let fault = fault::install(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));

        // SAFETY: this test owns the only PageMap client and has no root or
        // registered range. The injected failure must retain the first raw
        // published-submap owner in its exact slot.
        assert_eq!(unsafe { page_map.destroy() }, Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1);
        assert_eq!(page_map.submap_at(first_index), Ok(Some(first)));
        assert_eq!(page_map.submap_at(second_index), Ok(Some(second)));
        assert!(page_map.committed_count().is_ok());

        fault.set(fault::Plan::disabled());
        // SAFETY: the failed release did not clear either ownership slot, and
        // this test still supplies the destruction quiescence precondition.
        unsafe { page_map.destroy() }.expect("the retained submap slots retry to release");
    }

    #[test]
    fn destroy_top_mapping_release_failure_retains_the_exact_mapping_for_retry() {
        let mut page_map = PageMap::initialize(memory_config(false), MAX_VABITS, false)
            .expect("initialize the selected partial map");
        let first_index = page_map
            .committed_count()
            .expect("the initialized map exposes its committed prefix")
            .checked_add(1)
            .expect("the selected map has a representable first lazy index");
        let second_index = first_index
            .checked_add(1)
            .expect("the selected map has a representable second lazy index");
        page_map
            .ensure_submap_at(first_index)
            .expect("the first lazy submap is published");
        page_map
            .ensure_submap_at(second_index)
            .expect("the second lazy submap is published");
        let top_mapping = page_map
            .mapping
            .base()
            .expect("the top-level mapping remains owned before destruction");
        let fault = fault::install(fault::Plan::at(fault::Point::Unmap, 3, Errno::NOMEM));

        // SAFETY: this test owns the only PageMap client and has no root or
        // registered range. Two successful lazy-submap releases precede the
        // injected top-level release failure.
        assert_eq!(unsafe { page_map.destroy() }, Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 3);
        assert_eq!(page_map.submap_at(first_index), Ok(None));
        assert_eq!(page_map.submap_at(second_index), Ok(None));
        assert_eq!(page_map.mapping.base(), Ok(top_mapping));
        assert!(page_map.committed_count().is_ok());

        fault.set(fault::Plan::disabled());
        // SAFETY: only the original top-level Mapping remains, and this test
        // still supplies the destruction quiescence precondition.
        unsafe { page_map.destroy() }.expect("the retained top mapping retries to release");
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
