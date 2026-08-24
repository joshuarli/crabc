//! Miri-only model of the allocator's private mapping primitive boundary.
//!
//! This module is selected only by `cfg(miri)`. It is deliberately not a host
//! platform backend: fixed, page-aligned static regions represent a bounded
//! set of live anonymous mappings, so Miri can exercise allocator ownership
//! and lazy page-map publication without Linux/AArch64 syscalls. The model
//! records mapping and logical accessibility transitions. It does not model host protection
//! faults, kernel RSS, `MADV_FREE` reclamation, or Linux scheduling/process
//! observations; tests must not infer any of those properties from it.

use core::cell::UnsafeCell;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crabc_core::{Errno, Result};

use crate::invariants;

/// One Linux/AArch64 base-page size supplied by the process-start owner.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageSize(NonZeroUsize);

impl PageSize {
    /// Validates one Linux/AArch64 base-page size.
    #[inline]
    pub(crate) const fn new(bytes: usize) -> Option<Self> {
        match bytes {
            4_096 | 16_384 | 65_536 => {
                // SAFETY: Each enumerated base-page size is non-zero.
                Some(Self(unsafe { NonZeroUsize::new_unchecked(bytes) }))
            }
            _ => None,
        }
    }

    /// Returns the base-page byte size supplied at startup.
    #[inline]
    pub(crate) const fn bytes(self) -> usize {
        self.0.get()
    }
}

/// The allocation-free fragment of process-start information used here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartupInput {
    page_size: PageSize,
}

impl StartupInput {
    /// Builds the direct primitive input from a runtime-owned page size.
    #[inline]
    pub(crate) const fn new(page_size: PageSize) -> Self {
        Self { page_size }
    }

    /// Returns the page-size contract used by mappings from this input.
    #[inline]
    pub(crate) const fn page_size(self) -> PageSize {
        self.page_size
    }
}

/// Deterministic host-model counterpart of the Linux OS-memory policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryConfig {
    page_size: PageSize,
    large_page_size: usize,
    alloc_granularity: usize,
    physical_memory_in_kib: usize,
    virtual_address_bits: usize,
    has_overcommit: bool,
    has_partial_free: bool,
    has_virtual_reserve: bool,
    has_transparent_huge_pages: bool,
}

impl MemoryConfig {
    const DEFAULT_PHYSICAL_MEMORY_IN_KIB: usize = 32 * 1024 * 1024;
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    /// Returns fixed source fallbacks; this model never observes the host OS.
    pub(crate) const fn detect(startup: StartupInput) -> Self {
        Self::from_observations(
            startup.page_size(),
            Self::DEFAULT_PHYSICAL_MEMORY_IN_KIB,
            true,
            false,
        )
    }

    pub(crate) const fn from_observations(
        page_size: PageSize,
        physical_memory_in_kib: usize,
        has_overcommit: bool,
        has_transparent_huge_pages: bool,
    ) -> Self {
        Self {
            page_size,
            large_page_size: Self::LARGE_PAGE_SIZE,
            alloc_granularity: page_size.bytes(),
            physical_memory_in_kib,
            virtual_address_bits: crate::config::MAX_VABITS,
            has_overcommit,
            has_partial_free: true,
            has_virtual_reserve: true,
            has_transparent_huge_pages,
        }
    }

    #[inline]
    pub(crate) const fn page_size(self) -> PageSize { self.page_size }
    #[inline]
    pub(crate) const fn large_page_size(self) -> usize { self.large_page_size }
    #[inline]
    pub(crate) const fn alloc_granularity(self) -> usize { self.alloc_granularity }
    #[inline]
    pub(crate) const fn physical_memory_in_kib(self) -> usize { self.physical_memory_in_kib }
    #[inline]
    pub(crate) const fn virtual_address_bits(self) -> usize { self.virtual_address_bits }
    #[inline]
    pub(crate) const fn has_overcommit(self) -> bool { self.has_overcommit }
    #[inline]
    pub(crate) const fn has_partial_free(self) -> bool { self.has_partial_free }
    #[inline]
    pub(crate) const fn has_virtual_reserve(self) -> bool { self.has_virtual_reserve }
    #[inline]
    pub(crate) const fn has_transparent_huge_pages(self) -> bool {
        self.has_transparent_huge_pages
    }

    #[inline]
    pub(crate) const fn can_use_large_page(self, size: usize, alignment: usize) -> bool {
        self.large_page_size != 0
            && size % self.large_page_size == 0
            && alignment % self.large_page_size == 0
    }

    pub(crate) fn good_alloc_size(self, size: usize) -> usize {
        let alignment = if size < 512 * 1024 {
            self.page_size.bytes()
        } else if size < 2 * 1024 * 1024 {
            64 * 1024
        } else if size < 8 * 1024 * 1024 {
            256 * 1024
        } else if size < 32 * 1024 * 1024 {
            1024 * 1024
        } else {
            4 * 1024 * 1024
        };
        if size >= usize::MAX - alignment {
            size
        } else {
            invariants::align_up(size, alignment).unwrap_or(size)
        }
    }
}

/// The initial protection requested for a private anonymous mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapAccess {
    /// Reserve address space with no access until a later [`Mapping::commit`].
    Reserved,
    /// Create an immediately readable and writable anonymous mapping.
    Committed,
}

/// The known-zero outcome of one commit transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitOutcome {
    /// The mapping is accessible but the transition did not prove zero bytes.
    NotKnownZero,
}

/// The default-release decommit outcome on Linux.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecommitOutcome {
    /// The range may be reused without a recommit transition.
    DoesNotNeedRecommit,
}

// The model owns no dynamic memory. Sixteen 64-KiB slots model ordinary maps
// and lazy page-map submaps; one 5-MiB slot accommodates the maximum 48-bit
// top-level page-map reservation plus its trailing submap. All bases retain
// the production boundary's 64-KiB alignment.
const HOST_SMALL_CAPACITY: usize = 64 * 1024;
const HOST_SMALL_SLOTS: usize = 16;
const HOST_LARGE_CAPACITY: usize = 5 * 1024 * 1024;
const HOST_MAX_PAGES: usize = HOST_LARGE_CAPACITY / 4_096;

#[repr(C, align(65536))]
struct HostLargeMemory {
    bytes: UnsafeCell<[u8; HOST_LARGE_CAPACITY]>,
}

// SAFETY: the corresponding atomic slot owner grants one live `Mapping`
// exclusive access to each raw static region. The model never creates
// references into `bytes`.
unsafe impl Sync for HostLargeMemory {}

#[repr(C, align(65536))]
struct HostSmallMemory {
    bytes: UnsafeCell<[u8; HOST_SMALL_CAPACITY * HOST_SMALL_SLOTS]>,
}

unsafe impl Sync for HostSmallMemory {}

static HOST_LARGE_MEMORY: HostLargeMemory = HostLargeMemory {
    bytes: UnsafeCell::new([0; HOST_LARGE_CAPACITY]),
};
static HOST_SMALL_MEMORY: HostSmallMemory = HostSmallMemory {
    bytes: UnsafeCell::new([0; HOST_SMALL_CAPACITY * HOST_SMALL_SLOTS]),
};
static HOST_LARGE_IN_USE: AtomicBool = AtomicBool::new(false);
static HOST_SMALL_IN_USE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[derive(Clone, Copy)]
enum HostSlot {
    Large,
    Small(usize),
}

/// One bounded static-region mapping with an explicit, non-RAII release edge.
///
/// The logical accessibility mask tracks the production transitions so tests
/// can exercise their state ordering. It cannot make Miri fault a raw-pointer
/// access after [`Mapping::protect`]; callers must not treat this model as a
/// protection-fault oracle.
pub(crate) struct Mapping {
    address: *mut u8,
    length: usize,
    page_size: PageSize,
    initially_committed: bool,
    initially_zero: bool,
    // Page-map commitment can race exactly as it does in the production
    // boundary. Keep the model's observation mask atomic so that exercising
    // that protocol under Miri does not introduce a model-only data race.
    accessible_pages: AtomicU64,
    is_mapped: bool,
    slot: HostSlot,
}

impl Mapping {
    /// Reserves the host-model backing range as one private anonymous map.
    #[inline]
    pub(crate) fn map_anonymous(
        startup: StartupInput,
        length: usize,
        access: MapAccess,
    ) -> Result<Self> {
        validate_mapping_length(startup.page_size, length)?;
        if length > HOST_LARGE_CAPACITY {
            return Err(Errno::NOMEM);
        }
        fault_before(FaultPoint::Map)?;
        let (slot, address) = allocate_host_slot(length)?;
        // SAFETY: The atomic reservation above ensures this `Mapping` is the
        // sole owner of the complete static buffer. `length` was checked
        // against the buffer capacity, and no reference is created.
        unsafe { core::ptr::write_bytes(address, 0, length) };
        let page_count = length / startup.page_size.bytes();
        let accessible_pages = match access {
            MapAccess::Reserved => 0,
            MapAccess::Committed if page_count >= u64::BITS as usize => u64::MAX,
            MapAccess::Committed => page_mask(0, page_count),
        };

        Ok(Self {
            address,
            length,
            page_size: startup.page_size,
            initially_committed: matches!(access, MapAccess::Committed),
            initially_zero: true,
            accessible_pages: AtomicU64::new(accessible_pages),
            is_mapped: true,
            slot,
        })
    }

    pub(crate) fn map_for_allocator(
        config: MemoryConfig,
        length: usize,
        access: MapAccess,
    ) -> Result<Self> {
        Self::map_anonymous(StartupInput::new(config.page_size()), length, access)
    }

    pub(crate) fn map_aligned_for_allocator(
        config: MemoryConfig,
        length: usize,
        alignment: usize,
        access: MapAccess,
    ) -> Result<Self> {
        let page_size = config.page_size().bytes();
        if alignment < page_size || !alignment.is_power_of_two() {
            return Err(Errno::INVAL);
        }
        let mapping = Self::map_for_allocator(config, length, access)?;
        if mapping.address.addr() % alignment == 0 {
            Ok(mapping)
        } else {
            let mut mapping = mapping;
            mapping.unmap()?;
            Err(Errno::NOMEM)
        }
    }

    pub(crate) fn into_published(mut self) -> Result<*mut u8> {
        self.active()?;
        self.is_mapped = false;
        Ok(self.address)
    }

    /// # Safety
    ///
    /// The arguments must identify one uniquely owned host-model mapping
    /// transferred by `into_published`, with all accesses quiesced.
    pub(crate) unsafe fn reclaim_published(address: *mut u8, length: usize) -> Result<()> {
        fault_before(FaultPoint::Unmap)?;
        release_host_slot(address, length)
    }

    /// Returns whether the original anonymous mapping was zero initialized.
    #[inline]
    pub(crate) const fn initially_zero(&self) -> bool {
        self.initially_zero
    }

    /// Returns whether the original map request made the full range accessible.
    #[inline]
    pub(crate) const fn initially_committed(&self) -> bool {
        self.initially_committed
    }

    /// Returns the provenance-bearing base pointer of the live model mapping.
    #[inline]
    pub(crate) fn base(&self) -> Result<*mut u8> {
        self.active()?;
        Ok(self.address)
    }

    /// Returns the original mapping length while the mapping remains owned.
    #[inline]
    pub(crate) fn length(&self) -> Result<usize> {
        self.active()?;
        Ok(self.length)
    }

    #[cfg(test)]
    #[inline]
    fn page_is_accessible(&self, page_index: usize) -> bool {
        page_index < self.length / self.page_size.bytes()
            && page_index < u64::BITS as usize
            && (self.accessible_pages.load(Ordering::Acquire) & (1u64 << page_index)) != 0
    }

    /// Applies the production covering-page commit transition to model state.
    #[inline]
    pub(crate) fn commit(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<Option<CommitOutcome>> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Covering)? else {
            return Ok(None);
        };
        fault_before(FaultPoint::Commit)?;
        if let Some(mask) = range.tracked_page_mask() {
            self.accessible_pages.fetch_or(mask, Ordering::AcqRel);
        }
        Ok(Some(CommitOutcome::NotKnownZero))
    }

    /// Applies the production contained-page decommit transition to model state.
    #[inline]
    pub(crate) fn decommit(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<Option<DecommitOutcome>> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(None);
        };
        fault_before(FaultPoint::Decommit)?;
        // `MADV_DONTNEED` makes subsequently accessed private anonymous bytes
        // zero-filled. The host buffer selects that permitted outcome while
        // preserving the source-defined fact that decommit does not require a
        // recommit transition in this frozen profile.
        // SAFETY: `range.address` is provenance-preservingly derived from the
        // this live static mapping and `range.length` remains within it. No
        // reference into the range exists at this primitive boundary.
        unsafe { core::ptr::write_bytes(range.address, 0, range.length) };
        Ok(Some(DecommitOutcome::DoesNotNeedRecommit))
    }

    /// Records a successful reset/purge advisory without modeling reclamation.
    #[inline]
    pub(crate) fn purge(&self, offset: usize, length: usize) -> Result<bool> {
        let Some(_range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(true);
        };
        fault_before(FaultPoint::Purge)?;
        // Linux may retain or discard MADV_FREE contents. The model records
        // only the successful transition and intentionally makes no RSS or
        // later-content claim.
        Ok(true)
    }

    /// Applies the production contained-page protection transition to model state.
    #[inline]
    pub(crate) fn protect(&self, offset: usize, length: usize) -> Result<bool> {
        self.protect_with(offset, length, true)
    }

    /// Applies the production contained-page unprotection transition to model state.
    #[inline]
    pub(crate) fn unprotect(&self, offset: usize, length: usize) -> Result<bool> {
        self.protect_with(offset, length, false)
    }

    /// Explicitly releases the one host-model anonymous mapping.
    #[inline]
    pub(crate) fn unmap(&mut self) -> Result<()> {
        self.active()?;
        fault_before(FaultPoint::Unmap)?;
        self.accessible_pages.store(0, Ordering::Release);
        self.is_mapped = false;
        release_slot(self.slot);
        Ok(())
    }

    #[inline]
    fn protect_with(&self, offset: usize, length: usize, protect: bool) -> Result<bool> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(false);
        };
        fault_before(if protect {
            FaultPoint::Protect
        } else {
            FaultPoint::Unprotect
        })?;
        if let Some(mask) = range.tracked_page_mask() {
            if protect {
                self.accessible_pages.fetch_and(!mask, Ordering::AcqRel);
            } else {
                self.accessible_pages.fetch_or(mask, Ordering::AcqRel);
            }
        }
        Ok(true)
    }

    #[inline]
    fn active(&self) -> Result<()> {
        if self.is_mapped {
            Ok(())
        } else {
            Err(Errno::INVAL)
        }
    }

    #[inline]
    fn page_range(
        &self,
        offset: usize,
        length: usize,
        alignment: PageAlignment,
    ) -> Result<Option<MappingRange>> {
        self.active()?;
        let end = offset.checked_add(length).ok_or(Errno::INVAL)?;
        if end > self.length {
            return Err(Errno::INVAL);
        }
        if length == 0 {
            return Ok(None);
        }

        let page_size = self.page_size.bytes();
        let (start, end) = match alignment {
            PageAlignment::Covering => (
                invariants::align_down(offset, page_size).ok_or(Errno::INVAL)?,
                invariants::align_up(end, page_size).ok_or(Errno::INVAL)?,
            ),
            PageAlignment::Contained => (
                invariants::align_up(offset, page_size).ok_or(Errno::INVAL)?,
                invariants::align_down(end, page_size).ok_or(Errno::INVAL)?,
            ),
        };
        if end <= start {
            return Ok(None);
        }
        if end > self.length {
            return Err(Errno::INVAL);
        }

        let page_count = (end - start) / page_size;
        let first_page = start / page_size;
        Ok(Some(MappingRange {
            // SAFETY: `start < end <= self.length <= HOST_MAPPING_CAPACITY`.
            // `self.address` comes directly from the static buffer allocation,
            // so `add` preserves that allocation's provenance and stays in
            // bounds instead of reconstructing a pointer from an integer.
            address: unsafe { self.address.add(start) },
            length: end - start,
            first_page,
            page_count,
        }))
    }
}

#[derive(Clone, Copy)]
struct MappingRange {
    address: *mut u8,
    length: usize,
    first_page: usize,
    page_count: usize,
}

impl MappingRange {
    #[inline]
    fn tracked_page_mask(self) -> Option<u64> {
        if self.first_page >= u64::BITS as usize
            || self.page_count > u64::BITS as usize - self.first_page
        {
            None
        } else {
            Some(page_mask(self.first_page, self.page_count))
        }
    }
}

#[derive(Clone, Copy)]
enum PageAlignment {
    /// Expand over any partial first/last page, like `_mi_os_commit_ex`.
    Covering,
    /// Retain only full pages, like reset/decommit/protect in `src/os.c`.
    Contained,
}

#[inline]
fn allocate_host_slot(length: usize) -> Result<(HostSlot, *mut u8)> {
    if length <= HOST_SMALL_CAPACITY {
        loop {
            let current = HOST_SMALL_IN_USE.load(Ordering::Acquire);
            let Some(index) = (0..HOST_SMALL_SLOTS)
                .find(|index| current & (1usize << index) == 0)
            else {
                return Err(Errno::NOMEM);
            };
            let next = current | (1usize << index);
            if HOST_SMALL_IN_USE
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let base = HOST_SMALL_MEMORY.bytes.get().cast::<u8>();
                return Ok((HostSlot::Small(index), base.wrapping_add(index * HOST_SMALL_CAPACITY)));
            }
        }
    }
    if HOST_LARGE_IN_USE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(Errno::NOMEM);
    }
    Ok((HostSlot::Large, HOST_LARGE_MEMORY.bytes.get().cast::<u8>()))
}

fn release_slot(slot: HostSlot) {
    match slot {
        HostSlot::Large => HOST_LARGE_IN_USE.store(false, Ordering::Release),
        HostSlot::Small(index) => {
            HOST_SMALL_IN_USE.fetch_and(!(1usize << index), Ordering::Release);
        }
    }
}

fn release_host_slot(address: *mut u8, length: usize) -> Result<()> {
    if length == 0 {
        return Err(Errno::INVAL);
    }
    let large = HOST_LARGE_MEMORY.bytes.get().cast::<u8>();
    if address == large && length <= HOST_LARGE_CAPACITY {
        if HOST_LARGE_IN_USE.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        return Err(Errno::INVAL);
    }
    let small = HOST_SMALL_MEMORY.bytes.get().cast::<u8>();
    let offset = address.addr().checked_sub(small.addr()).ok_or(Errno::INVAL)?;
    if length > HOST_SMALL_CAPACITY || offset % HOST_SMALL_CAPACITY != 0 {
        return Err(Errno::INVAL);
    }
    let index = offset / HOST_SMALL_CAPACITY;
    if index >= HOST_SMALL_SLOTS {
        return Err(Errno::INVAL);
    }
    let mask = 1usize << index;
    let previous = HOST_SMALL_IN_USE.fetch_and(!mask, Ordering::AcqRel);
    if previous & mask == 0 { Err(Errno::INVAL) } else { Ok(()) }
}

#[inline]
fn page_mask(first_page: usize, page_count: usize) -> u64 {
    debug_assert!(page_count > 0);
    debug_assert!(first_page < HOST_MAX_PAGES);
    debug_assert!(first_page + page_count <= HOST_MAX_PAGES);
    let low = if page_count == u64::BITS as usize {
        u64::MAX
    } else {
        (1u64 << page_count) - 1
    };
    low << first_page
}

#[inline]
fn validate_mapping_length(page_size: PageSize, length: usize) -> Result<()> {
    if length == 0 || length % page_size.bytes() != 0 {
        Err(Errno::INVAL)
    } else {
        Ok(())
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FaultPoint {
    Map = 1,
    Commit = 2,
    Decommit = 3,
    Purge = 4,
    Protect = 5,
    Unprotect = 6,
    Unmap = 7,
}

#[cfg(not(test))]
#[inline]
fn fault_before(_point: FaultPoint) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod fault {
    use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

    use crabc_core::{Errno, Result};

    pub(crate) use super::FaultPoint as Point;

    const ANY_POINT: usize = 0;
    static LOCKED: AtomicBool = AtomicBool::new(false);
    static SELECTED_POINT: AtomicUsize = AtomicUsize::new(ANY_POINT);
    static FAILURE_ORDINAL: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED: AtomicUsize = AtomicUsize::new(0);
    static SECOND_SELECTED_POINT: AtomicUsize = AtomicUsize::new(ANY_POINT);
    static SECOND_FAILURE_ORDINAL: AtomicUsize = AtomicUsize::new(0);
    static SECOND_OBSERVED: AtomicUsize = AtomicUsize::new(0);
    // Setup releases before a paired primary failure must not consume the
    // explicit rollback-release injection which follows that failure.
    static SECOND_ENABLED: AtomicBool = AtomicBool::new(false);
    static FAILURE_ERROR: AtomicI32 = AtomicI32::new(Errno::NOMEM.raw());

    #[derive(Clone, Copy)]
    pub(crate) struct Plan {
        point: usize,
        ordinal: usize,
        second_point: usize,
        second_ordinal: usize,
        error: Errno,
    }

    impl Plan {
        pub(crate) const fn disabled() -> Self {
            Self {
                point: ANY_POINT,
                ordinal: 0,
                second_point: ANY_POINT,
                second_ordinal: 0,
                error: Errno::NOMEM,
            }
        }

        pub(crate) const fn any_nth(ordinal: usize, error: Errno) -> Self {
            Self {
                point: ANY_POINT,
                ordinal,
                second_point: ANY_POINT,
                second_ordinal: 0,
                error,
            }
        }

        pub(crate) const fn at(point: Point, ordinal: usize, error: Errno) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: ANY_POINT,
                second_ordinal: 0,
                error,
            }
        }

        pub(crate) const fn at_pair(
            point: Point,
            ordinal: usize,
            second_point: Point,
            second_ordinal: usize,
            error: Errno,
        ) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: second_point as usize,
                second_ordinal,
                error,
            }
        }
    }

    /// Serializes model tests around its one static mapping and global fault plan.
    pub(crate) struct Guard;

    pub(crate) fn install(plan: Plan) -> Guard {
        while LOCKED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        set(plan);
        Guard
    }

    impl Guard {
        pub(crate) fn set(&self, plan: Plan) {
            set(plan);
        }

        pub(crate) fn observed(&self) -> usize {
            OBSERVED.load(Ordering::Acquire)
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            set(Plan::disabled());
            LOCKED.store(false, Ordering::Release);
        }
    }

    #[inline]
    fn set(plan: Plan) {
        SELECTED_POINT.store(plan.point, Ordering::Relaxed);
        FAILURE_ORDINAL.store(plan.ordinal, Ordering::Relaxed);
        SECOND_SELECTED_POINT.store(plan.second_point, Ordering::Relaxed);
        SECOND_FAILURE_ORDINAL.store(plan.second_ordinal, Ordering::Relaxed);
        FAILURE_ERROR.store(plan.error.raw(), Ordering::Relaxed);
        OBSERVED.store(0, Ordering::Release);
        SECOND_OBSERVED.store(0, Ordering::Release);
        SECOND_ENABLED.store(false, Ordering::Release);
    }

    #[inline]
    pub(crate) fn before(point: Point) -> Result<()> {
        let selected = SELECTED_POINT.load(Ordering::Acquire);
        if selected == ANY_POINT || selected == point as usize {
            let ordinal = FAILURE_ORDINAL.load(Ordering::Acquire);
            if ordinal != 0 {
                let observed = OBSERVED.fetch_add(1, Ordering::AcqRel) + 1;
                if observed == ordinal {
                    SECOND_ENABLED.store(true, Ordering::Release);
                    let error = FAILURE_ERROR.load(Ordering::Acquire);
                    // SAFETY: `Plan` stores only the raw value of a valid
                    // `Errno`.
                    return Err(unsafe { Errno::from_raw(error).unwrap_unchecked() });
                }
            }
        }
        let second_selected = SECOND_SELECTED_POINT.load(Ordering::Acquire);
        if SECOND_ENABLED.load(Ordering::Acquire)
            && (second_selected == ANY_POINT || second_selected == point as usize)
        {
            let second_ordinal = SECOND_FAILURE_ORDINAL.load(Ordering::Acquire);
            if second_ordinal != 0 {
                let second_observed = SECOND_OBSERVED.fetch_add(1, Ordering::AcqRel) + 1;
                if second_observed == second_ordinal {
                    let error = FAILURE_ERROR.load(Ordering::Acquire);
                    // SAFETY: `Plan` stores only the raw value of a valid
                    // `Errno`.
                    return Err(unsafe { Errno::from_raw(error).unwrap_unchecked() });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[inline]
fn fault_before(point: FaultPoint) -> Result<()> {
    fault::before(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup(page_size: usize) -> StartupInput {
        StartupInput::new(PageSize::new(page_size).unwrap())
    }

    #[test]
    fn startup_page_size_matches_the_linux_aarch64_contract() {
        let _fault = fault::install(fault::Plan::disabled());
        assert!(PageSize::new(0).is_none());
        assert!(PageSize::new(3).is_none());
        for bytes in [4 * 1024, 16 * 1024, 64 * 1024] {
            assert_eq!(startup(bytes).page_size().bytes(), bytes);
        }
    }

    #[test]
    fn injected_memory_policy_is_deterministic_and_source_shaped() {
        let _fault = fault::install(fault::Plan::disabled());
        let page_size = PageSize::new(4 * 1024).unwrap();
        let config = MemoryConfig::from_observations(page_size, 123_456, false, true);
        assert_eq!(config.page_size(), page_size);
        assert_eq!(config.large_page_size(), 2 * 1024 * 1024);
        assert_eq!(config.alloc_granularity(), page_size.bytes());
        assert_eq!(config.physical_memory_in_kib(), 123_456);
        assert_eq!(config.virtual_address_bits(), crate::config::MAX_VABITS);
        assert!(!config.has_overcommit());
        assert!(config.has_partial_free());
        assert!(config.has_virtual_reserve());
        assert!(config.has_transparent_huge_pages());
        assert_eq!(config.good_alloc_size(1), 4 * 1024);
        assert_eq!(config.good_alloc_size(512 * 1024 + 1), 576 * 1024);
        assert!(config.can_use_large_page(2 * 1024 * 1024, 2 * 1024 * 1024));
        assert!(!config.can_use_large_page(2 * 1024 * 1024, 4 * 1024));

        let fallback = MemoryConfig::detect(StartupInput::new(page_size));
        assert_eq!(fallback.physical_memory_in_kib(), 32 * 1024 * 1024);
        assert!(fallback.has_overcommit());
        assert!(!fallback.has_transparent_huge_pages());
    }

    #[test]
    fn map_rejects_invalid_or_unmodelable_ranges_without_a_transition() {
        let _fault = fault::install(fault::Plan::disabled());
        let input = startup(4 * 1024);
        let page = input.page_size().bytes();

        assert!(matches!(
            Mapping::map_anonymous(input, 0, MapAccess::Reserved),
            Err(Errno::INVAL)
        ));
        assert!(matches!(
            Mapping::map_anonymous(input, page + 1, MapAccess::Reserved),
            Err(Errno::INVAL)
        ));
        assert!(matches!(
            Mapping::map_anonymous(input, HOST_LARGE_CAPACITY + page, MapAccess::Reserved),
            Err(Errno::NOMEM)
        ));
    }

    #[test]
    fn reserved_mapping_commits_a_covering_range_with_live_provenance() {
        let _fault = fault::install(fault::Plan::disabled());
        let input = startup(4 * 1024);
        let page = input.page_size().bytes();
        let mut mapping = Mapping::map_anonymous(input, 2 * page, MapAccess::Reserved)
            .expect("reserve the fixed host-model range");

        assert!(!mapping.initially_committed());
        assert!(mapping.initially_zero());
        assert_eq!(mapping.length(), Ok(2 * page));
        assert_eq!(
            mapping.commit(1, page),
            Ok(Some(CommitOutcome::NotKnownZero))
        );
        assert!(mapping.page_is_accessible(0));
        assert!(mapping.page_is_accessible(1));

        let base = mapping.base().expect("the mapping remains live after commit");
        assert_eq!(base.addr() % page, 0);
        // SAFETY: `base` is the live model mapping's provenance-bearing base.
        // `add` stays inside its two-page range, and no Rust reference aliases
        // these raw accesses. This is intentionally a pointer operation, not
        // address-to-pointer reconstruction, for Miri strict-provenance checks.
        unsafe {
            base.write(0x41);
            let tail = base.add((2 * page) - 1);
            tail.write(0x42);
            assert_eq!(base.read(), 0x41);
            assert_eq!(tail.read(), 0x42);
        }

        assert!(mapping.protect(0, page).expect("record protection"));
        assert!(!mapping.page_is_accessible(0));
        assert!(mapping.page_is_accessible(1));
        assert!(mapping.unprotect(0, page).expect("record unprotection"));
        assert!(mapping.page_is_accessible(0));
        mapping.unmap().expect("release the model mapping");
        assert_eq!(mapping.base(), Err(Errno::INVAL));
        assert_eq!(mapping.commit(0, page), Err(Errno::INVAL));
        assert_eq!(mapping.unmap(), Err(Errno::INVAL));
    }

    #[test]
    fn decommit_selects_zero_refault_without_claiming_purge_reclamation() {
        let _fault = fault::install(fault::Plan::disabled());
        let input = startup(4 * 1024);
        let page = input.page_size().bytes();
        let mut mapping = Mapping::map_anonymous(input, page, MapAccess::Committed)
            .expect("map one committed model page");
        let base = mapping.base().unwrap();
        assert!(mapping.page_is_accessible(0));

        // SAFETY: The mapping is initially committed and owns the buffer.
        unsafe { base.write(0xa5) };
        assert_eq!(mapping.decommit(1, page - 1), Ok(None));
        assert_eq!(
            mapping.decommit(0, page),
            Ok(Some(DecommitOutcome::DoesNotNeedRecommit))
        );
        // SAFETY: Decommit leaves this profile logically accessible; the host
        // model chooses the Linux private-anonymous zero-refault outcome.
        assert_eq!(unsafe { base.read() }, 0);
        assert!(mapping.purge(0, page).expect("record a successful purge"));
        mapping.unmap().expect("release the model mapping");
    }

    #[test]
    fn contained_range_transitions_leave_partial_pages_unmodified() {
        let _fault = fault::install(fault::Plan::disabled());
        let input = startup(4 * 1024);
        let page = input.page_size().bytes();
        let mut mapping = Mapping::map_anonymous(input, 2 * page, MapAccess::Committed)
            .expect("map two committed model pages");

        assert_eq!(mapping.decommit(1, page - 1), Ok(None));
        assert!(!mapping.protect(1, page - 1).expect("empty contained protect"));
        assert!(!mapping.unprotect(1, page - 1).expect("empty contained unprotect"));
        assert!(mapping.purge(1, page - 1).expect("empty purge succeeds"));
        mapping.unmap().expect("release the model mapping");
    }

    #[test]
    fn all_supported_page_sizes_fit_the_fixed_model_with_the_expected_initial_state() {
        let _fault = fault::install(fault::Plan::disabled());
        for page in [4 * 1024, 16 * 1024, 64 * 1024] {
            let mut mapping = Mapping::map_anonymous(startup(page), page, MapAccess::Committed)
                .expect("one supported page fits the fixed model");
            assert!(mapping.initially_committed());
            assert!(mapping.initially_zero());
            assert!(mapping.page_is_accessible(0));
            mapping.unmap().expect("release each model mapping before the next");
        }
    }

    #[test]
    fn operation_faults_preserve_the_mapping_lifecycle_without_fallbacks() {
        let fault = fault::install(fault::Plan::disabled());
        let input = startup(4 * 1024);
        let page = input.page_size().bytes();

        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            Mapping::map_anonymous(input, page, MapAccess::Reserved),
            Err(Errno::NOMEM)
        ));
        assert_eq!(fault.observed(), 1);
        fault.set(fault::Plan::disabled());

        let mut mapping = Mapping::map_anonymous(input, page, MapAccess::Committed)
            .expect("a failed map must not retain the one model slot");
        fault.set(fault::Plan::any_nth(2, Errno::NOMEM));
        assert_eq!(mapping.commit(0, page), Ok(Some(CommitOutcome::NotKnownZero)));
        assert_eq!(mapping.decommit(0, page), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 2, "the host model must preserve nth-operation injection");
        for point in [
            fault::Point::Commit,
            fault::Point::Decommit,
            fault::Point::Purge,
            fault::Point::Protect,
            fault::Point::Unprotect,
        ] {
            fault.set(fault::Plan::at(point, 1, Errno::NOMEM));
            let result = match point {
                fault::Point::Commit => mapping.commit(0, page).map(|_| ()),
                fault::Point::Decommit => mapping.decommit(0, page).map(|_| ()),
                fault::Point::Purge => mapping.purge(0, page).map(|_| ()),
                fault::Point::Protect => mapping.protect(0, page).map(|_| ()),
                fault::Point::Unprotect => mapping.unprotect(0, page).map(|_| ()),
                _ => unreachable!("the test enumerates only range transitions"),
            };
            assert_eq!(result, Err(Errno::NOMEM));
            assert_eq!(fault.observed(), 1);
        }

        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        assert_eq!(mapping.unmap(), Err(Errno::NOMEM));
        assert!(mapping.base().is_ok(), "failed unmap keeps ownership live");
        assert_eq!(fault.observed(), 1);
        fault.set(fault::Plan::disabled());
        mapping.unmap().expect("retry the explicit release after its injected failure");
    }
}
