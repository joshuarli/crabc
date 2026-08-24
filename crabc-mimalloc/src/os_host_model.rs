//! Miri-only model of the allocator's private mapping primitive boundary.
//!
//! This module is selected only by `cfg(miri)`. It is deliberately not a host
//! platform backend: a fixed, page-aligned static buffer represents one live
//! anonymous mapping at a time, so Miri can exercise the current allocator
//! foundations without Linux/AArch64 syscalls. The model records mapping and
//! logical accessibility transitions. It does not model host protection
//! faults, kernel RSS, `MADV_FREE` reclamation, or Linux scheduling/process
//! observations; tests must not infer any of those properties from it.

use core::cell::Cell;
use core::cell::UnsafeCell;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, Ordering};

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

// The model owns no dynamic memory. It deliberately limits one mapping to a
// single 64-KiB backing range, which accommodates one page at each supported
// Linux/AArch64 base-page size and up to sixteen 4-KiB pages. The alignment is
// sufficient for every supported page size, preserving the production map's
// base-pointer alignment precondition.
const HOST_MAPPING_CAPACITY: usize = 64 * 1024;
const HOST_MAX_PAGES: usize = HOST_MAPPING_CAPACITY / 4_096;

#[repr(C, align(65536))]
struct HostMemory {
    bytes: UnsafeCell<[u8; HOST_MAPPING_CAPACITY]>,
}

// SAFETY: `HOST_MAPPING_IN_USE` grants one live `Mapping` exclusive access to
// the raw static storage. The model never creates references into `bytes`.
unsafe impl Sync for HostMemory {}

static HOST_MEMORY: HostMemory = HostMemory {
    bytes: UnsafeCell::new([0; HOST_MAPPING_CAPACITY]),
};
static HOST_MAPPING_IN_USE: AtomicBool = AtomicBool::new(false);

/// One static-buffer mapping with an explicit, non-RAII release edge.
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
    accessible_pages: Cell<u64>,
    is_mapped: bool,
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
        if length > HOST_MAPPING_CAPACITY {
            return Err(Errno::NOMEM);
        }
        fault_before(FaultPoint::Map)?;

        if HOST_MAPPING_IN_USE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(Errno::NOMEM);
        }

        let address = host_memory_base();
        // SAFETY: The atomic reservation above ensures this `Mapping` is the
        // sole owner of the complete static buffer. `length` was checked
        // against the buffer capacity, and no reference is created.
        unsafe { core::ptr::write_bytes(address, 0, length) };
        let page_count = length / startup.page_size.bytes();
        let accessible_pages = match access {
            MapAccess::Reserved => 0,
            MapAccess::Committed => page_mask(0, page_count),
        };

        Ok(Self {
            address,
            length,
            page_size: startup.page_size,
            initially_committed: matches!(access, MapAccess::Committed),
            initially_zero: true,
            accessible_pages: Cell::new(accessible_pages),
            is_mapped: true,
        })
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
            && (self.accessible_pages.get() & (1u64 << page_index)) != 0
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
        self.accessible_pages
            .set(self.accessible_pages.get() | range.page_mask());
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
        // one live static mapping and `range.length` remains within it. No
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
        self.accessible_pages.set(0);
        self.is_mapped = false;
        HOST_MAPPING_IN_USE.store(false, Ordering::Release);
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
        let current = self.accessible_pages.get();
        let next = if protect {
            current & !range.page_mask()
        } else {
            current | range.page_mask()
        };
        self.accessible_pages.set(next);
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
    fn page_mask(self) -> u64 {
        page_mask(self.first_page, self.page_count)
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
fn host_memory_base() -> *mut u8 {
    HOST_MEMORY.bytes.get().cast::<u8>()
}

#[inline]
fn page_mask(first_page: usize, page_count: usize) -> u64 {
    debug_assert!(page_count > 0);
    debug_assert!(first_page < HOST_MAX_PAGES);
    debug_assert!(first_page + page_count <= HOST_MAX_PAGES);
    ((1u64 << page_count) - 1) << first_page
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
enum FaultPoint {
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
mod fault {
    use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

    use crabc_core::{Errno, Result};

    pub(super) use super::FaultPoint as Point;

    const ANY_POINT: usize = 0;
    static LOCKED: AtomicBool = AtomicBool::new(false);
    static SELECTED_POINT: AtomicUsize = AtomicUsize::new(ANY_POINT);
    static FAILURE_ORDINAL: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED: AtomicUsize = AtomicUsize::new(0);
    static FAILURE_ERROR: AtomicI32 = AtomicI32::new(Errno::NOMEM.raw());

    #[derive(Clone, Copy)]
    pub(super) struct Plan {
        point: usize,
        ordinal: usize,
        error: Errno,
    }

    impl Plan {
        pub(super) const fn disabled() -> Self {
            Self {
                point: ANY_POINT,
                ordinal: 0,
                error: Errno::NOMEM,
            }
        }

        pub(super) const fn any_nth(ordinal: usize, error: Errno) -> Self {
            Self {
                point: ANY_POINT,
                ordinal,
                error,
            }
        }

        pub(super) const fn at(point: Point, ordinal: usize, error: Errno) -> Self {
            Self {
                point: point as usize,
                ordinal,
                error,
            }
        }
    }

    /// Serializes model tests around its one static mapping and global fault plan.
    pub(super) struct Guard;

    pub(super) fn install(plan: Plan) -> Guard {
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
        pub(super) fn set(&self, plan: Plan) {
            set(plan);
        }

        pub(super) fn observed(&self) -> usize {
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
        FAILURE_ERROR.store(plan.error.raw(), Ordering::Relaxed);
        OBSERVED.store(0, Ordering::Release);
    }

    #[inline]
    pub(super) fn before(point: Point) -> Result<()> {
        let selected = SELECTED_POINT.load(Ordering::Acquire);
        if selected != ANY_POINT && selected != point as usize {
            return Ok(());
        }
        let ordinal = FAILURE_ORDINAL.load(Ordering::Acquire);
        if ordinal == 0 {
            return Ok(());
        }
        let observed = OBSERVED.fetch_add(1, Ordering::AcqRel) + 1;
        if observed == ordinal {
            let error = FAILURE_ERROR.load(Ordering::Acquire);
            // SAFETY: `Plan` stores only the raw value of a valid `Errno`.
            return Err(unsafe { Errno::from_raw(error).unwrap_unchecked() });
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
            Mapping::map_anonymous(input, HOST_MAPPING_CAPACITY + page, MapAccess::Reserved),
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
