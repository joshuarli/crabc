// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: pinned mimalloc v3.5.0 src/arena.c:1216-1283,1573-1611,1676-1912,
// 2167-2191 (huge reservation manage boundary), and src/page.c:630-705
// (page-area commitment before capacity publication).

//! Process-owned backing for the source arena registry.
//!
//! Unlike the historical one-arena `ProcessSharedArenaStorage` sidecar, this
//! is the arena group of one `MainSubprocess`: one reserve lock, one registry,
//! and the exact regular or huge OS owners of its published arenas. This Rust ownership group
//! is not an assertion about the complete C `mi_subproc_t` layout. Publication
//! retains backing until explicit quiescent `destroy_all` transfers it into
//! terminal release ownership. That caller must not infer shutdown authority
//! from an ordinary arena view; normal thread exit never destroys this group.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crabc_core::Errno;

use super::{ArenaId, ArenaRegistry, ArenaReservationPlan, ArenaSearch, ArenaSliceClaim, CommitHook, ExternalArenaPlan, ManageArenaError, ManagedExternalRegion};
use crate::config::{ARENA_ALIGNMENT, ARENA_MAX_SIZE, ARENA_MIN_SIZE, MAX_ARENAS};
use crate::lock::PrivateLock;
use crate::os::{MapAccess, Mapping, MemoryConfig, NormalOsAllocation, HugeOsAllocation, PageSize, VmProcess};
use crate::types::{Arena, MemoryId, MemoryKind};

#[path = "arena_purge.rs"]
mod purge;
pub(crate) use purge::arena_purge_delay;

#[path = "arena_destroy.rs"]
mod destroy;
pub(crate) use destroy::{ArenaDestroyError, DestroyedArenas};

#[path = "arena_huge.rs"]
mod huge;
pub(crate) use huge::{HugeArenaReserveError, HugeArenaCleanupError, StartupArenaReservationOutcomes};

const EMPTY: u8 = 0;
const INITIALIZING: u8 = 1;
const PUBLISHED: u8 = 2;
const RETAINED: u8 = 3;
const DESTROYED: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArenaPageCommitError {
    InvalidPageArea,
    Mapping(Errno),
}

/// Admission result for the one supported source-start regular arena bridge.
///
/// Pinned `mi_reserve_os_memory` can publish several arena forms before the
/// first ordinary allocation.  The ticket-zero bridge deliberately admits
/// only one committed, non-pinned regular parent as the sole registry member.
/// A nonempty source registry outside that finite shape must not be mistaken
/// for an absent option and silently redirected to the older one-arena
/// sidecar; later multi-arena/huge ownership remains a separate boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstRegularStartupArenaSelection {
    /// Source startup published no arena, so ordinary first-page fallback may
    /// take its existing source-shaped fresh reservation route.
    Absent,
    /// The sole source-published regular parent is eligible for ticket zero.
    Eligible(ArenaId),
    /// Source already published an arena outside this bridge's finite regular
    /// capability.  Callers must retain/refuse rather than fabricate fallback.
    ExistingOutsideFirstRegularCapability,
}

/// Why a `mi_reserve_os_memory_ex2` reservation failed. Each is source
/// `ENOMEM`; they differ in the C `errno` the path leaves behind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReserveOsMemoryFailure {
    /// The size check reported through `_mi_error_message` before any mapping.
    TooLarge,
    /// An OS primitive (`mmap`, or the cleanup `munmap`) failed with this code.
    Os(Errno),
    /// The mapping was made and released again without a failing primitive.
    Unmanaged,
}

/// Allocation-owner slots: one per publishable arena mapping plus one spare.
/// Source `mi_reserve_os_memory_ex2` maps and initializes a fresh arena (its
/// metadata commit is counted) before `mi_arenas_add` can report a full
/// registry, and only then frees the mapping. The spare lets that attempt run
/// when every registry entry is already published, and retains the exact
/// mapping if its cleanup unmap fails.
const ARENA_SLOT_COUNT: usize = MAX_ARENAS + 1;

struct ArenaAllocationSlot {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<OwnedArenaAllocation>>,
    #[cfg(test)]
    initializing_reads: core::sync::atomic::AtomicUsize,
}

impl ArenaAllocationSlot {
    const fn new() -> Self {
        Self { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()),
            #[cfg(test)]
            initializing_reads: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// # Safety
    ///
    /// PUBLISHED and RETAINED values are immutable until exclusive teardown;
    /// no borrow may survive the unsafe `destroy_all` transition.
    /// INITIALIZING requires the reserve lock or the callback capability for
    /// this exact slot: another arena's publication never protects it against
    /// initialization failure moving the mapping out or reusing the slot.
    unsafe fn initialized(&self) -> Option<&OwnedArenaAllocation> {
        let state = self.state.load(Ordering::Acquire);
        if state == EMPTY || state == DESTROYED { return None; }
        #[cfg(test)]
        if state == INITIALIZING { self.initializing_reads.fetch_add(1, Ordering::Relaxed); }
        Some(unsafe { (&*self.value.get()).assume_init_ref() })
    }
}

/// Result of one owner-bound source arena commit request.
///
/// The bool returned by a custom C callback has two different meanings. This
/// type keeps the commit success and zero observation together so a callback
/// cannot make an arena claim succeed while losing its source zero result.
#[derive(Clone, Copy)]
pub(super) struct ArenaCommitOutcome {
    committed: bool,
    is_zero: bool,
}

impl ArenaCommitOutcome {
    const fn failed() -> Self { Self { committed: false, is_zero: false } }
    const fn committed(is_zero: bool) -> Self { Self { committed: true, is_zero } }
    pub(super) const fn succeeded(self) -> bool { self.committed }
    pub(super) const fn is_zero(self) -> bool { self.is_zero }
}

/// One externally managed range and its source callback.
///
/// It retains no terminal mapping operation: pinned mi_manage_memory keeps
/// external-memory release with its caller. The callback is instead a
/// process-lived transition capability for this exact range.
///
/// # Safety
///
/// Construction proves that the range, callback function, and user argument
/// remain live and exclusive throughout installation and while the owning
/// ProcessArenaBacking has any published arena. The callback must accept
/// contained raw spans. Metadata commit and purge pass a null zero output;
/// page-claim commit passes a writable output. Every true commit result,
/// including metadata commit with a null output, makes the complete requested
/// span accessible before this owner writes its headers or bitmaps. It
/// synchronizes any state shared with concurrent or reentrant calls.
#[must_use = "an external callback lease must be installed or recovered"]
pub(crate) struct ProcessExternalArenaLease {
    base: NonNull<u8>,
    size: usize,
    memory: MemoryId,
    callback: CommitHook,
}

impl ProcessExternalArenaLease {
    /// Forms the process-lived external ownership and transition capability.
    ///
    /// # Safety
    ///
    /// `base..base + size`, `callback`, and its argument remain live and
    /// exclusive until every arena published from this lease is permanently
    /// quiescent. The callback accepts contained raw spans and synchronizes
    /// concurrent as well as reentrant calls. A metadata `commit=true` call
    /// may pass a null `is_zero`; a later claim commit passes a writable
    /// output. Every true commit result makes the complete requested span
    /// accessible, including a metadata call with a null output. A non-null
    /// output and the initial flags supplied here truthfully describe those
    /// accessible bytes.
    pub(crate) unsafe fn new(
        base: *mut u8,
        size: usize,
        initially_committed: bool,
        is_pinned: bool,
        initially_zero: bool,
        callback: CommitHook,
    ) -> Option<Self> {
        let base = NonNull::new(base)?;
        Some(Self {
            memory: MemoryId::external(
                base.as_ptr(),
                size,
                initially_committed,
                is_pinned,
                initially_zero,
            ),
            base,
            size,
            callback,
        })
    }

    #[inline]
    fn base(&self) -> *mut u8 { self.base.as_ptr() }

    #[inline]
    fn size(&self) -> usize { self.size }

    #[inline]
    fn memory(&self) -> MemoryId { self.memory }

    /// A preparation attempt wrote source headers and bitmaps before its
    /// first publication failed. The caller still owns the range, but a retry
    /// cannot claim that its metadata image remains zero.
    fn invalidate_zero_after_prepare(&mut self) {
        self.memory = MemoryId::external(
            self.base(),
            self.size,
            self.memory.initially_committed(),
            self.memory.is_pinned(),
            false,
        );
    }

    #[inline]
    fn contains(&self, start: *mut u8, size: usize) -> bool {
        let Some(offset) = (start as usize).checked_sub(self.base.as_ptr() as usize) else {
            return false;
        };
        offset.checked_add(size).is_some_and(|end| end <= self.size)
    }

    /// Proves the complete liberal `_mi_os_commit` coverage remains in this
    /// caller-owned external lease. The request itself belongs to one arena
    /// page area, while source floor/ceil normalization may cover its first
    /// or last base page too.
    fn contains_covering_page_area(&self, page_size: PageSize, start: *mut u8, size: usize) -> bool {
        if start.is_null() || size == 0 {
            return false;
        }
        let start_address = start.addr();
        let Some(end_address) = start_address.checked_add(size) else {
            return false;
        };
        let page_size = page_size.bytes();
        let Some(covering_start) = crate::invariants::align_down(start_address, page_size) else {
            return false;
        };
        let Some(covering_end) = crate::invariants::align_up(end_address, page_size) else {
            return false;
        };
        let base = self.base() as usize;
        let Some(lease_end) = base.checked_add(self.size) else {
            return false;
        };
        covering_start >= base && covering_end >= covering_start && covering_end <= lease_end
    }

    #[inline]
    unsafe fn commit(&self, start: *mut u8, size: usize) -> ArenaCommitOutcome {
        if !self.contains(start, size) {
            return ArenaCommitOutcome::failed();
        }
        let mut is_zero = false;
        let committed = unsafe { self.callback.invoke(true, start, size, &mut is_zero) };
        ArenaCommitOutcome { committed, is_zero: committed && is_zero }
    }

    #[inline]
    unsafe fn purge(&self, start: *mut u8, size: usize) -> Option<bool> {
        self.contains(start, size)
            .then(|| unsafe { self.callback.invoke(false, start, size, core::ptr::null_mut()) })
    }
}

/// Non-owning identity pair retained by an arena slot for synchronous
/// callbacks. It is intentionally not a `VmProcess<'static>`: a child arena
/// can use the same slot machinery only while its external child owner keeps
/// the pinned subprocess image alive through `destroy_all`.
#[derive(Clone, Copy)]
struct StoredVmProcess {
    policy: NonNull<crate::os::VmPolicy>,
    subprocess: NonNull<crate::subproc::SubprocessIdentity>,
}

impl StoredVmProcess {
    fn from_static_process(process: VmProcess<'static>) -> Self {
        Self {
            policy: NonNull::from(process.policy()),
            subprocess: NonNull::from(process.subprocess()),
        }
    }

    /// # Safety
    /// The process policy and subprocess image remain pinned and live until
    /// this arena slot is retired by quiescent `destroy_all`. For child use,
    /// the external child context owner must retain both through every page,
    /// callback, and arena teardown transition.
    unsafe fn from_retained_process(process: VmProcess<'_>) -> Self {
        Self {
            policy: NonNull::from(process.policy()),
            subprocess: NonNull::from(process.subprocess()),
        }
    }

    /// The returned short borrow is valid because the slot owner can only be
    /// observed while its containing backing is live; a reclaimable child
    /// owner must call `destroy_all` before releasing that context.
    fn project(&self) -> VmProcess<'_> {
        // SAFETY: every constructor either requires process-static input or
        // has the explicit retained-context obligation above. Slot access is
        // excluded by the backing's quiescent destruction contract.
        unsafe { VmProcess::new(self.policy.as_ref(), self.subprocess.as_ref()) }
    }

    fn matches(&self, process: VmProcess<'_>) -> bool {
        core::ptr::eq(self.policy.as_ptr(), process.policy())
            && core::ptr::eq(self.subprocess.as_ptr(), process.subprocess())
    }
}

pub(super) struct OwnedArenaAllocation {
    allocation: ArenaBacking,
    memory: MemoryId,
    process: StoredVmProcess,
    pub(super) config: MemoryConfig,
}

/// The registry retains exactly one source backing owner for every published
/// arena. Regular mapping and huge allocation remain consuming OS owners;
/// external memory carries only its process-lived callback lease and never an
/// unmap capability.
enum ArenaBacking {
    Regular(Mapping),
    Huge(HugeOsAllocation<'static>),
    External(ProcessExternalArenaLease),
}

impl ArenaBacking {
    fn base(&self) -> Result<*mut u8, Errno> {
        match self {
            Self::Regular(mapping) => mapping.base(),
            Self::Huge(allocation) => Ok(allocation.base().as_ptr()),
            Self::External(lease) => Ok(lease.base()),
        }
    }

    fn length(&self) -> Result<usize, Errno> {
        match self {
            Self::Regular(mapping) => mapping.length(),
            Self::Huge(allocation) => Ok(allocation.size()),
            Self::External(lease) => Ok(lease.size()),
        }
    }

    fn regular(&self) -> Option<&Mapping> {
        match self {
            Self::Regular(mapping) => Some(mapping),
            Self::Huge(_) | Self::External(_) => None,
        }
    }

    fn external(&self) -> Option<&ProcessExternalArenaLease> {
        match self {
            Self::External(lease) => Some(lease),
            Self::Regular(_) | Self::Huge(_) => None,
        }
    }
}

impl OwnedArenaAllocation {
    pub(super) fn process(&self) -> VmProcess<'_> { self.process.project() }

    pub(super) fn commit(
        &self,
        start: *mut u8,
        size: usize,
        already_committed: usize,
    ) -> bool {
        self.commit_with_outcome(start, size, already_committed).succeeded()
    }

    pub(super) fn commit_with_outcome(
        &self,
        start: *mut u8,
        size: usize,
        already_committed: usize,
    ) -> ArenaCommitOutcome {
        let Ok(base) = self.allocation.base() else {
            return ArenaCommitOutcome::failed();
        };
        let Some(offset) = (start as usize).checked_sub(base as usize) else {
            return ArenaCommitOutcome::failed();
        };
        let Ok(length) = self.allocation.length() else {
            return ArenaCommitOutcome::failed();
        };
        if offset.checked_add(size).is_none_or(|end| end > length) {
            return ArenaCommitOutcome::failed();
        }
        match &self.allocation {
            ArenaBacking::Regular(mapping) => {
                if mapping
                    .commit_for_process(self.process(), offset, size, already_committed)
                    .is_ok()
                {
                    ArenaCommitOutcome::committed(false)
                } else {
                    ArenaCommitOutcome::failed()
                }
            }
            ArenaBacking::Huge(_) => ArenaCommitOutcome::failed(),
            ArenaBacking::External(lease) => unsafe { lease.commit(start, size) },
        }
    }

    /// Performs the direct `_mi_os_commit` edge used only after an on-demand
    /// page's callback-backed first prefix. This must remain separate from
    /// [`Self::commit_with_outcome`]: source `mi_page_extend_free` has no
    /// `arena->commit_fun` call on this later extension.
    ///
    /// # Safety
    ///
    /// `start..start + size` is the caller's exclusive live page-prefix
    /// transition. For an external backing, its complete covering base-page
    /// range is validated against the process-lived lease before the raw
    /// process commitment runs.
    unsafe fn commit_direct_page_area(
        &self,
        start: *mut u8,
        size: usize,
    ) -> Result<(), ArenaPageCommitError> {
        let invalid = ArenaPageCommitError::InvalidPageArea;
        let base = self.allocation.base().map_err(|_| invalid)?;
        let offset = (start as usize).checked_sub(base as usize).ok_or(invalid)?;
        let length = self.allocation.length().map_err(|_| invalid)?;
        if offset.checked_add(size).is_none_or(|end| end > length) {
            return Err(invalid);
        }
        match &self.allocation {
            ArenaBacking::Regular(mapping) => mapping
                .commit_for_process(self.process(), offset, size, 0)
                .map(|_| ())
                .map_err(ArenaPageCommitError::Mapping),
            ArenaBacking::External(lease) => {
                if !lease.contains_covering_page_area(self.config.page_size(), start, size) {
                    return Err(invalid);
                }
                // SAFETY: the outer page owner exclusively owns the direct
                // prefix; the lease check above proves full source covering
                // range containment without acquiring unmap authority.
                unsafe { self.process().commit_direct_page_area(self.config.page_size(), start, size) }
                    .map(|_| ())
                    .map_err(ArenaPageCommitError::Mapping)
            }
            // Pinned huge arenas are initially committed and pinned. An
            // on-demand `mi_page_extend_free` cannot reach this owner.
            ArenaBacking::Huge(_) => Err(invalid),
        }
    }

    #[inline]
    pub(super) fn has_external_callback(&self) -> bool {
        self.allocation.external().is_some()
    }

    #[inline]
    pub(super) fn invoke_external_purge(
        &self,
        start: *mut u8,
        size: usize,
    ) -> Option<bool> {
        self.allocation
            .external()
            .and_then(|lease| unsafe { lease.purge(start, size) })
    }
}

/// Source `arenas`, `arena_count`, and `arena_reserve_lock` ownership.
///
/// Installation needs `&'static self`: callbacks and registry entries never
/// point into movable stack owners. The reserve lock serializes binding and
/// slot transitions; an arena's Release publication follows initialization
/// of its final mapping slot. Published slots remain immutable until exclusive
/// `destroy_all`; that boundary requires all page/bitmap/callback views to end
/// before any published mapping can be released.
pub(crate) struct ProcessArenaBacking {
    destroyed: AtomicBool,
    reserve_lock: PrivateLock,
    huge_reservation_lock: PrivateLock,
    huge_cleanup_retained: AtomicBool,
    huge_cleanup: UnsafeCell<Option<huge::PendingHugeCleanup>>,
    registry: ArenaRegistry,
    slots: [ArenaAllocationSlot; ARENA_SLOT_COUNT],
    purge_expire: crate::atomic::AtomicI64Value,
}

// SAFETY: the lock exclusively owns all unpublished slot transitions. Once
// published, slots and mappings remain fixed until the unsafe quiescent
// teardown boundary transfers ownership after all aliases end. Their shared VM
// transitions touch only caller-owned source ranges and atomic statistics.
// The separate huge reservation lock exclusively owns pending cleanup and its
// metadata tracker. Its lock may acquire reserve_lock, never the reverse; the
// metadata allocator is called only after reserve_lock has been released.
unsafe impl Sync for ProcessArenaBacking {}

impl ProcessArenaBacking {
    pub(crate) const fn new() -> Self {
        Self {
            destroyed: AtomicBool::new(false),
            reserve_lock: PrivateLock::new(),
            huge_reservation_lock: PrivateLock::new(),
            huge_cleanup_retained: AtomicBool::new(false),
            huge_cleanup: UnsafeCell::new(None),
            registry: ArenaRegistry::new(core::ptr::null_mut()),
            slots: [const { ArenaAllocationSlot::new() }; ARENA_SLOT_COUNT],
            purge_expire: crate::atomic::AtomicI64Value::new(0),
        }
    }

    #[inline]
    pub(crate) fn registry(&self) -> &ArenaRegistry { &self.registry }

    /// Checks that every installed child arena owner is bound to this exact
    /// VM policy/identity/configuration before a caller can search existing
    /// slices. An empty child group is admissible; its first installation
    /// establishes the binding under the same reserve lock.
    pub(crate) fn child_binding_matches(
        &self,
        process: VmProcess<'_>,
        config: MemoryConfig,
    ) -> bool {
        if self.destroyed.load(Ordering::Acquire) { return false; }
        let Ok(_guard) = self.reserve_lock.lock() else { return false; };
        self.binding_matches_locked(process, config)
    }

    /// Direct `_mi_os_commit` used by `mi_page_extend_free`, deliberately
    /// distinct from the arena callback used for a fresh page's first prefix.
    ///
    /// # Safety
    /// `memory` is an outstanding page span of this registry. The caller
    /// exclusively owns its commitment prefix and all newly accessible bytes;
    /// no release or overlapping page transition may run concurrently.
    pub(crate) unsafe fn commit_page_area(
        &self, memory: MemoryId, offset: usize, size: usize,
    ) -> Result<(), ArenaPageCommitError> {
        let invalid = ArenaPageCommitError::InvalidPageArea;
        let arena_memory = memory.arena_memory().ok_or(invalid)?;
        let view = unsafe { super::ArenaView::from_ptr(arena_memory.arena) }.ok_or(invalid)?;
        let owner = unsafe { self.allocation_for_arena(view.arena()) }.ok_or(invalid)?;
        let span = (arena_memory.slice_count as usize).checked_mul(super::ARENA_SLICE_SIZE)
            .ok_or(invalid)?;
        if size == 0 || offset.checked_add(size).is_none_or(|end| end > span) { return Err(invalid); }
        let start = view.slice_start(arena_memory.slice_index as usize).ok_or(invalid)?;
        let page_area = (start as usize).checked_add(offset).ok_or(invalid)? as *mut u8;
        // SAFETY: the exact arena MemoryId/span validation above identifies
        // one live claimed page area; its caller holds the unique prefix
        // transition until successful commitment publishes page capacity.
        unsafe { owner.commit_direct_page_area(page_area, size) }
    }

    /// Reconciles `mi_arenas_page_free_prim`'s on-demand prefix before the
    /// page metadata is retired and its complete slices become available.
    /// Complete slices enter the conservative commit bitmap; a partial tail
    /// is accounted as already decommitted, without an extra OS operation.
    ///
    /// # Safety
    /// The caller owns this live page's unique release right, has removed its
    /// PageMap and ordinary arena-page bit, and calls this exactly once with
    /// the page's actual committed prefix before returning its slices.
    pub(crate) unsafe fn account_page_commit_before_release(
        &self, memory: MemoryId, committed: usize,
    ) -> bool {
        if committed == 0 { return true; }
        let Some(arena_memory) = memory.arena_memory() else { return false; };
        let Some(view) = (unsafe { super::ArenaView::from_ptr(arena_memory.arena) }) else { return false; };
        let Some(owner) = (unsafe { self.allocation_for_arena(view.arena()) }) else { return false; };
        let Some(span) = (arena_memory.slice_count as usize).checked_mul(super::ARENA_SLICE_SIZE) else { return false; };
        if committed > span || committed % owner.config.page_size().bytes() != 0 { return false; }
        let Some(bitmap) = (unsafe { view.slices_committed() }) else { return false; };
        let whole = committed / super::ARENA_SLICE_SIZE;
        if whole != 0 && bitmap.set_range(arena_memory.slice_index as usize, whole).is_none() { return false; }
        let extra = committed % super::ARENA_SLICE_SIZE;
        if extra != 0 { owner.process().subprocess().vm_statistics().committed_decrease(extra); }
        true
    }

    /// Validates a new coordinator consumer against every arena mapping
    /// already retained by this process owner. This is a one-time binding
    /// check, not a page allocation/free scan. Taking the reserve lock excludes
    /// an unpublished slot being moved or reused while its owner is examined.
    pub(crate) fn matches_existing_process_binding(
        &self, process: VmProcess<'_>, config: MemoryConfig,
    ) -> Result<bool, Errno> {
        let _guard = self.reserve_lock.lock()?;
        Ok(self.binding_matches_locked(process, config))
    }

    /// Validates the exact source-start regular parent retained by process
    /// initialization before a ticket-zero page owner may search it.
    ///
    /// This does not search or claim a slice.  It establishes only the finite
    /// bridge shape: the `mimalloc_reserve_os_memory` success ID names the
    /// one registry-published, committed, ordinary OS parent bound to this
    /// process/configuration.  The later [`Self::try_find_free`] call still
    /// performs the pinned source NUMA/suitability/bitmap search and owns
    /// commitment accounting for its actual claim.
    pub(crate) fn first_regular_startup_arena_selection(
        &self,
        process: VmProcess<'static>,
        config: MemoryConfig,
        startup_arena: Option<ArenaId>,
    ) -> FirstRegularStartupArenaSelection {
        let Ok(_guard) = self.reserve_lock.lock() else {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        };
        if !self.binding_matches_locked(process, config) {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        }
        let count = self.registry.count();
        let Some(startup_arena) = startup_arena else {
            return if count == 0 {
                FirstRegularStartupArenaSelection::Absent
            } else {
                FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability
            };
        };
        if count != 1 || !self.registry.is_bound_to_subprocess(process.subprocess().as_ptr()) {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        }
        // SAFETY: the reserve lock excludes an initializing publisher while
        // the one source registry slot is inspected; published arena storage
        // remains process-lived by this backing contract.
        let Some(arena) = (unsafe { self.registry.arena_at(0) }) else {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        };
        if !core::ptr::eq(core::ptr::from_ref(arena).cast_mut(), startup_arena.as_ptr())
            || !arena.parent.is_null()
            || arena.memid.kind() != MemoryKind::Os
            || arena.memid.is_pinned()
            || !arena.memid.initially_committed()
        {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        }
        let Some(memory) = arena.memid.os_memory() else {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        };
        let Some(owner) = self.published_allocation(memory.base, memory.size) else {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        };
        if !matches!(owner.allocation, ArenaBacking::Regular(_))
            || !core::ptr::eq(owner.process().policy(), process.policy())
            || !core::ptr::eq(owner.process().subprocess(), process.subprocess())
            || owner.config != config
        {
            return FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability;
        }
        FirstRegularStartupArenaSelection::Eligible(startup_arena)
    }

    /// Reforms a view only after [`Self::first_regular_startup_arena_selection`]
    /// has repeated its stable process/registry/owner admission checks.
    pub(crate) fn first_regular_startup_arena_view(
        &self,
        process: VmProcess<'static>,
        config: MemoryConfig,
        startup_arena: ArenaId,
    ) -> Option<super::ArenaView<'static>> {
        match self.first_regular_startup_arena_selection(process, config, Some(startup_arena)) {
            FirstRegularStartupArenaSelection::Eligible(arena) if arena == startup_arena => {
                // SAFETY: the preceding locked admission proves this exact
                // registry-published parent and its process-lifetime owner.
                unsafe { super::ArenaView::from_ptr(arena.as_ptr()) }
            }
            FirstRegularStartupArenaSelection::Absent
            | FirstRegularStartupArenaSelection::Eligible(_)
            | FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability => None,
        }
    }

    /// Checks every stable owner while reserve_lock excludes mutation.
    ///
    /// An INITIALIZING external slot is already address-stable before its
    /// metadata callback runs. Reentrant setup may verify its fixed process
    /// pair and configuration, but ordinary arena lookup still refuses that
    /// state until the registry insertion publishes it.
    fn binding_matches_locked(&self, process: VmProcess<'_>, config: MemoryConfig) -> bool {
        let registered = self.registry.subprocess();
        if !registered.is_null() && registered != process.subprocess().as_ptr() {
            return false;
        }
        for slot in &self.slots {
            match slot.state.load(Ordering::Acquire) {
                EMPTY => continue,
                INITIALIZING | PUBLISHED | RETAINED => {}
                _ => return false,
            }
            // SAFETY: reserve_lock keeps the INITIALIZING owner stable, and
            // published or retained owners are immutable for process lifetime.
            let Some(owner) = (unsafe { slot.initialized() }) else {
                return false;
            };
            if !core::ptr::eq(owner.process().policy(), process.policy())
                || !core::ptr::eq(owner.process().subprocess(), process.subprocess())
                || owner.config != config
            {
                return false;
            }
        }
        true
    }

    /// Claims from existing process-owned arenas with source commitment and
    /// unconditional touched/mixed-commit accounting. Reservation and the OS
    /// fallback are separate decisions after this complete two-pass search.
    ///
    /// # Safety
    ///
    /// A non-null requested arena must be live for this process lifetime.
    /// The caller owns the returned span until explicit release and must not
    /// overlap page/bitmap users during its commitment or release transitions.
    pub(crate) unsafe fn try_find_free(
        &self, search: ArenaSearch, slice_count: usize, alignment: usize, commit: bool,
    ) -> Option<ArenaSliceClaim<'_>> {
        unsafe {
            self.registry.try_find_free_with(search, slice_count, alignment, |view| {
                let owner = self.allocation_for_arena(view.arena())?;
                let mut claim = view.try_claim_slices_with_owner(search.requested, slice_count, commit,
                    search.thread_sequence, Some(owner))?;
                claim.backing = Some(self);
                Some(claim)
            })
        }
    }

    /// Publishes one source-sized OS arena and retains its exact mapping.
    /// Failure before publication returns the complete mapping, including a
    /// failed metadata-commit attempt; it does not silently unmap or discard
    /// ownership. The source reservation caller decides its cleanup/retry.
    ///
    /// # Safety
    ///
    /// `mapping` must be exclusively transferred from an allocation through
    /// this exact `process` pair, with matching source `memory` provenance.
    /// `managed_size` is the source reservation request, not the OS-rounded
    /// mapping length; any rounded tail remains owned but is not arena space.
    /// No pointer or reference into it may survive from an earlier owner.
    /// `self` must be this subprocess's sole normal arena registry, and its
    /// VM policy/configuration must not change after any arena is published.
    pub(crate) unsafe fn install_owned_os_mapping(
        &'static self,
        process: VmProcess<'static>,
        config: MemoryConfig,
        managed_size: usize,
        mapping: Mapping,
        memory: MemoryId,
        numa_node: i32,
        exclusive: bool,
    ) -> Result<ManagedExternalRegion, ProcessArenaInstallFailure<'static>> {
        let _guard = match self.reserve_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(ProcessArenaInstallFailure {
                error: ManageArenaError::RegistryFull, mapping, memory, process,
            }),
        };
        unsafe { self.install_owned_os_mapping_locked(process,
            StoredVmProcess::from_static_process(process), config, managed_size, mapping, memory, numa_node, exclusive) }
    }

    /// The caller holds reserve_lock through every slot and registry write.
    unsafe fn install_owned_os_mapping_locked<'process>(
        &self, process: VmProcess<'process>, stored_process: StoredVmProcess, config: MemoryConfig,
        managed_size: usize, mapping: Mapping, memory: MemoryId, numa_node: i32, exclusive: bool,
    ) -> Result<ManagedExternalRegion, ProcessArenaInstallFailure<'process>> {
        let result = unsafe { self.install_owned_allocation_locked(process, stored_process, config, managed_size,
            ArenaBacking::Regular(mapping), memory, numa_node, exclusive) };
        result.map_err(|(error, allocation)| {
            let ArenaBacking::Regular(mapping) = allocation else { unreachable!() };
            ProcessArenaInstallFailure { error, mapping, memory, process }
        })
    }

    /// Installs caller-managed external memory with its source callback.
    ///
    /// The returned arena retains only the callback lease. It never obtains an
    /// unmap operation for external bytes. The reserve lock protects binding,
    /// stable-slot reservation, registry insertion, and first publication, but
    /// is deliberately released before every callback from metadata setup.
    ///
    /// # Safety
    ///
    /// The lease proves the external range and callback remain process-lived.
    /// This owner is the sole registry for process; its configuration is fixed
    /// after the first publication. No registry destruction or overlapping
    /// external owner may run while the published range is live.
    pub(crate) unsafe fn install_owned_external_callback_arena(
        &'static self,
        process: VmProcess<'static>,
        config: MemoryConfig,
        managed_size: usize,
        lease: ProcessExternalArenaLease,
        numa_node: i32,
        exclusive: bool,
    ) -> Result<ManagedExternalRegion, ProcessExternalArenaInstallFailure> {
        let start = lease.base();
        let size = lease.size();
        let memory = lease.memory();
        let hook = lease.callback;
        let guard = match self.reserve_lock.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(ProcessExternalArenaInstallFailure::Returned {
                    error: ManageArenaError::RegistryFull,
                    lease,
                });
            }
        };
        if !self.binding_matches_locked(process, config) {
            return Err(ProcessExternalArenaInstallFailure::Returned {
                error: ManageArenaError::InvalidRegion,
                lease,
            });
        }
        if self.registry.count() == 0 {
            // SAFETY: reserve_lock excludes every competing external prepare
            // and publication until the immutable process identity is bound.
            if !unsafe {
                self.registry
                    .bind_subprocess_before_publication(process.subprocess().as_ptr())
            } {
                return Err(ProcessExternalArenaInstallFailure::Returned {
                    error: ManageArenaError::InvalidRegion,
                    lease,
                });
            }
        } else if !self.registry.is_bound_to_subprocess(process.subprocess().as_ptr()) {
            return Err(ProcessExternalArenaInstallFailure::Returned {
                error: ManageArenaError::InvalidRegion,
                lease,
            });
        }
        if memory.kind() != MemoryKind::External
            || memory.os_memory().is_none_or(|stored| stored.base != start || stored.size != size)
            || managed_size != size
            || ExternalArenaPlan::from_address(start as usize, size).is_none()
        {
            if let Some(warning) = ExternalArenaPlan::source_rejection_warning(start as usize, size) {
                process.policy().source_warning(warning);
            }
            return Err(ProcessExternalArenaInstallFailure::Returned {
                error: ManageArenaError::InvalidRegion,
                lease,
            });
        }
        let Some(slot) = self
            .slots
            .iter()
            .find(|slot| slot.state.load(Ordering::Relaxed) == EMPTY)
        else {
            return Err(ProcessExternalArenaInstallFailure::Returned {
                error: ManageArenaError::RegistryFull,
                lease,
            });
        };
        unsafe {
            (*slot.value.get()).write(OwnedArenaAllocation {
                allocation: ArenaBacking::External(lease),
                memory,
                process: StoredVmProcess::from_static_process(process),
                config,
            });
        }
        slot.state.store(INITIALIZING, Ordering::Release);
        drop(guard);

        let result = unsafe {
            super::manage_in_place_with_publisher_and_numa_source(
                &self.registry,
                start,
                managed_size,
                config.page_size(),
                memory.initially_committed(),
                || {
                    // Pinned `mi_arena_initialize` resolves the optional
                    // local node only after this arena's metadata commit and
                    // zeroing succeeded. A failed callback must leave the
                    // process NUMA cache untouched.
                    if numa_node < 0 && process.policy().arena_is_numa_local() {
                        process.current_numa_node() as i32
                    } else { numa_node }
                },
                exclusive,
                Some(hook),
                memory,
                |arena| {
                    let _guard = self
                        .reserve_lock
                        .lock()
                        .map_err(|_| ManageArenaError::RegistryFull)?;
                    if !self.registry.is_bound_to_subprocess(process.subprocess().as_ptr()) {
                        return Err(ManageArenaError::InvalidRegion);
                    }
                    if self.registry.insert(arena) {
                        // The first inserted arena publishes this immutable
                        // whole-range lease before a later subarena callback
                        // can reenter and allocate through the parent.
                        slot.state.store(PUBLISHED, Ordering::Release);
                        Ok(())
                    } else {
                        Err(ManageArenaError::RegistryFull)
                    }
                },
            )
        };
        match result {
            Ok(managed) => Ok(managed),
            Err(error) => {
                let guard = match self.reserve_lock.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        slot.state.store(RETAINED, Ordering::Release);
                        return Err(ProcessExternalArenaInstallFailure::Retained { error });
                    }
                };
                if slot.state.load(Ordering::Acquire) != INITIALIZING {
                    drop(guard);
                    return Err(ProcessExternalArenaInstallFailure::Retained { error });
                }
                slot.state.store(EMPTY, Ordering::Release);
                let owner = unsafe { (*slot.value.get()).assume_init_read() };
                let ArenaBacking::External(mut lease) = owner.allocation else {
                    unreachable!();
                };
                lease.invalidate_zero_after_prepare();
                drop(guard);
                Err(ProcessExternalArenaInstallFailure::Returned { error, lease })
            }
        }
    }

    /// Installs the exact contiguous huge-primitive prefix in the same arena
    /// registry as regular reservations. Source multi-arena partial success
    /// retains the entire huge owner, including any unpublished suffix.
    /// No release is attempted here: pre-publication rejection returns the
    /// original owner so the reservation caller can supply its failed-page
    /// tracker and perform the source cleanup exactly once.
    ///
    /// # Safety
    /// This must be the allocation's subprocess arena group. The transferred
    /// allocation has no outstanding views, and config is its fixed process
    /// configuration. Published storage remains live for process lifetime.
    pub(crate) unsafe fn install_owned_huge_allocation(
        &'static self, config: MemoryConfig, allocation: HugeOsAllocation<'static>,
        numa_node: i32, exclusive: bool,
    ) -> Result<ManagedExternalRegion, ProcessHugeArenaInstallFailure> {
        let _guard = match self.reserve_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(ProcessHugeArenaInstallFailure {
                error: ManageArenaError::RegistryFull, allocation,
            }),
        };
        let process = allocation.process();
        let size = allocation.size();
        let memory = allocation.memory_id();
        unsafe { self.install_owned_allocation_locked(process, StoredVmProcess::from_static_process(process), config, size,
            ArenaBacking::Huge(allocation), memory, numa_node, exclusive) }
            .map_err(|(error, owner)| {
                let ArenaBacking::Huge(allocation) = owner else { unreachable!() };
                ProcessHugeArenaInstallFailure { error, allocation }
            })
    }

    /// Caller holds reserve_lock until slot publication or complete rollback.
    ///
    /// # Safety
    /// `process` and `stored_process` name the same immutable policy/identity
    /// pair, and the caller retains both plus this backing until every
    /// published slot/callback is quiescent and `destroy_all` has transferred
    /// all remaining owners. This applies to returned failure owners too.
    unsafe fn install_owned_allocation_locked(
        &self, process: VmProcess<'_>, stored_process: StoredVmProcess, config: MemoryConfig,
        managed_size: usize, allocation: ArenaBacking, memory: MemoryId,
        numa_node: i32, exclusive: bool,
    ) -> Result<ManagedExternalRegion, (ManageArenaError, ArenaBacking)> {
        let fail = |error, allocation| (error, allocation);
        if !stored_process.matches(process) {
            return Err(fail(ManageArenaError::InvalidRegion, allocation));
        }
        let start = match allocation.base() {
            Ok(start) => start,
            Err(_) => return Err(fail(ManageArenaError::InvalidRegion, allocation)),
        };
        let size = match allocation.length() {
            Ok(size) => size,
            Err(_) => return Err(fail(ManageArenaError::InvalidRegion, allocation)),
        };
        let exact = memory.os_memory().is_some_and(|os| os.base == start && os.size == size);
        let valid_kind = match &allocation {
            ArenaBacking::Regular(mapping) => memory.kind() == MemoryKind::Os
                && memory.is_pinned() == mapping.is_large()
                && memory.initially_zero() == mapping.initially_zero()
                && memory.initially_committed() == mapping.initially_committed(),
            ArenaBacking::Huge(_) => memory.kind() == MemoryKind::OsHuge
                && memory.is_pinned() && memory.initially_committed() && managed_size == size,
            ArenaBacking::External(lease) => memory.kind() == MemoryKind::External
                && lease.base() == start && lease.size() == size,
        };
        if exact && valid_kind && managed_size <= size {
            // `mi_manage_os_memory_ex2` warns before rejecting a region that
            // cannot hold one aligned minimum arena.
            if let Some(warning) = ExternalArenaPlan::source_rejection_warning(start as usize, managed_size) {
                process.policy().source_warning(warning);
                return Err(fail(ManageArenaError::InvalidRegion, allocation));
            }
        }
        if !exact || !valid_kind || managed_size < ARENA_MIN_SIZE
            || managed_size > size || (start as usize) % ARENA_ALIGNMENT != 0 {
            return Err(fail(ManageArenaError::InvalidRegion, allocation));
        }
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) == EMPTY { continue; }
            let owner = unsafe { slot.initialized().unwrap() };
            if !core::ptr::eq(owner.process().policy(), process.policy())
                || !core::ptr::eq(owner.process().subprocess(), process.subprocess())
                || owner.config != config
            {
                return Err(fail(ManageArenaError::InvalidRegion, allocation));
            }
            break;
        }
        if self.registry.count() == 0 {
            // SAFETY: this lock is the only normal registry publisher.
            if !unsafe { self.registry.bind_subprocess_before_publication(process.subprocess().as_ptr()) } {
                return Err(fail(ManageArenaError::InvalidRegion, allocation));
            }
        } else if !self.registry.is_bound_to_subprocess(process.subprocess().as_ptr()) {
            return Err(fail(ManageArenaError::InvalidRegion, allocation));
        }
        let Some(slot) = self.slots.iter().find(|slot| slot.state.load(Ordering::Relaxed) == EMPTY) else {
            return Err(fail(ManageArenaError::RegistryFull, allocation));
        };
        unsafe { (*slot.value.get()).write(OwnedArenaAllocation {
            allocation, memory, process: stored_process, config,
        }); }
        slot.state.store(INITIALIZING, Ordering::Release);
        let hook = (memory.kind() == MemoryKind::Os).then(||
            CommitHook::new(commit_owned_arena, (slot as *const ArenaAllocationSlot).cast_mut().cast()));
        // The internal hook carries Rust ownership, not an externally supplied
        // source callback. Its zero-already-committed path is exactly the OS
        // commit used by source arena initialization and page metadata.
        let result = unsafe {
            super::manage_in_place_with_publisher_and_numa_source(
                &self.registry, start, managed_size, config.page_size(),
                memory.initially_committed(),
                || {
                    // The source reads current NUMA only for an arena whose
                    // metadata preparation reached its initialization step.
                    if numa_node < 0 && process.policy().arena_is_numa_local() {
                        process.current_numa_node() as i32
                    } else { numa_node }
                },
                exclusive, hook, memory,
                |arena| {
                    if self.registry.insert(arena) {
                        Ok(())
                    } else {
                        Err(ManageArenaError::RegistryFull)
                    }
                },
            )
        };
        match result {
            Ok(managed) => {
                slot.state.store(PUBLISHED, Ordering::Release);
                Ok(managed)
            }
            Err(error) => {
                // manage_in_place returns Err only before its first registry
                // publication. Its synchronous callback has already returned.
                slot.state.store(EMPTY, Ordering::Release);
                let owner = unsafe { (*slot.value.get()).assume_init_read() };
                Err(fail(error, owner.allocation))
            }
        }
    }

    /// Retrieves only backing already published by this exact process owner.
    /// The arena must be live; this does not authorize access to arbitrary
    /// addresses or transfer the full mapping's destruction capability.
    unsafe fn allocation_for_arena(&self, arena: &Arena) -> Option<&OwnedArenaAllocation> {
        if !self.registry.is_bound_to_subprocess(arena.subprocess) { return None; }
        let parent = if arena.parent.is_null() { arena } else { unsafe { &*arena.parent } };
        let memory = parent.memid.os_memory()?;
        if let Some(owner) = self.published_allocation(memory.base, memory.size) {
            return Some(owner);
        }
        // Source registry publication can precede this target slot's final
        // PUBLISHED store. On this miss only, wait for the one initializing
        // publisher to finish and recheck. Never borrow unrelated temporary
        // slots: their failed manage may move/drop/reuse the contained owner.
        let _guard = self.reserve_lock.lock().ok()?;
        self.published_allocation(memory.base, memory.size)
    }

    fn published_allocation(&self, base: *mut u8, size: usize) -> Option<&OwnedArenaAllocation> {
        self.slots.iter().find_map(|slot| {
            if slot.state.load(Ordering::Acquire) != PUBLISHED { return None; }
            // SAFETY: a PUBLISHED slot remains fixed until exclusive teardown,
            // whose caller must exclude this lookup and every returned borrow.
            let owner = unsafe { slot.initialized()? };
            let stored = owner.memory.os_memory()?;
            (stored.base == base && stored.size == size).then_some(owner)
        })
    }

    /// Source `mi_arenas_try_alloc`: search, serialize one fresh reservation
    /// only when the observed registry count is unchanged, then search again.
    /// Failure is not an OS fallback: that distinct caller must still enforce
    /// disallow_os_alloc and requested-arena refusal before mapping a page.
    ///
    /// # Safety
    ///
    /// This must be the sole normal arena group for `process`, with its fixed
    /// configuration. The borrowed process policy and identity, plus this
    /// backing, remain pinned and live through every published slot, callback,
    /// retained cleanup owner, returned claim, and quiescent `destroy_all`.
    /// `search`'s requested arena and Heap/thread inputs must describe live
    /// source owners. The returned claim retains its exact range until
    /// explicit release; no registry destruction may overlap.
    pub(crate) unsafe fn try_allocate_slices(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        search: ArenaSearch, slice_count: usize, alignment: usize, commit: bool,
    ) -> Option<ArenaSliceClaim<'static>> {
        // SAFETY: legacy explicit callers retain the same source owner.
        unsafe { self.try_allocate_slices_with_random(process, config, search,
            slice_count, alignment, commit, None) }
    }

    /// Same source search/reserve/search operation with the current default
    /// random adapter used only at the existing OS hint draw sites.
    ///
    /// # Safety
    /// The caller must satisfy `try_allocate_slices` and retain the supplied
    /// source random operation's exclusive-access contract during each draw.
    /// The borrowed process policy/identity and backing remain live until all
    /// published owners and retained failures are retired by `destroy_all`.
    pub(crate) unsafe fn try_allocate_slices_with_random(
        &self, process: VmProcess<'_>, config: MemoryConfig,
        search: ArenaSearch, slice_count: usize, alignment: usize, commit: bool,
        random: crate::os::OsRandom<'_>,
    ) -> Option<ArenaSliceClaim<'_>> {
        let requested_size = slice_count.checked_mul(crate::config::ARENA_SLICE_SIZE)?;
        if requested_size == 0 || requested_size > ARENA_MAX_SIZE
            || alignment > crate::config::ARENA_SLICE_SIZE { return None; }
        if let Some(claim) = unsafe { self.try_find_free(search, slice_count, alignment, commit) } {
            return Some(claim);
        }
        if !search.requested.as_ptr().is_null() || process.policy().disallow_os_alloc() {
            return None;
        }
        let observed_count = self.registry.count();
        {
            let _guard = self.reserve_lock.lock().ok()?;
            if observed_count == self.registry.count() {
                let _ = unsafe { self.reserve_locked(process, config, requested_size, search.allow_pinned, random) };
            }
        }
        unsafe { self.try_find_free(search, slice_count, alignment, commit) }
    }

    /// The reservation step of [`Self::try_allocate_slices_with_random`] for
    /// an unrequested search over an empty registry, without claiming slices.
    ///
    /// That source search/reserve/search reaches `mi_arena_reserve` only when
    /// no published arena can serve the request; with no arena at all this
    /// performs exactly that reservation under the same lock and policy
    /// gates, then leaves every slice free (and clean). A refused reservation
    /// is not an error here: the later claim retries the complete source
    /// sequence, including its OS fallback.
    ///
    /// # Safety
    /// Same obligations as [`Self::try_allocate_slices_with_random`].
    pub(crate) unsafe fn reserve_first_arena_with_random(
        &self, process: VmProcess<'_>, config: MemoryConfig, requested_size: usize,
        allow_pinned: bool, random: crate::os::OsRandom<'_>,
    ) {
        if self.registry.count() != 0 || process.policy().disallow_os_alloc() {
            return;
        }
        let Ok(_guard) = self.reserve_lock.lock() else { return };
        if self.registry.count() == 0 {
            let _ = unsafe { self.reserve_locked(process, config, requested_size, allow_pinned, random) };
        }
    }

    /// Source `_mi_arenas_alloc_aligned` (and `_mi_arenas_alloc`, its
    /// slice-aligned form) for a requested arena.
    ///
    /// The arena arm runs only when `disallow_arena_alloc` is off, `size` lies
    /// in `ARENA_MIN_OBJ_SIZE..=mi_arena_max_object_size()`, `alignment` is at
    /// most one slice, and `align_offset` is zero; it searches just the
    /// requested arena (both NUMA passes) and never reserves. Every miss then
    /// reaches `mi_arena_os_alloc_aligned`, which refuses with `ENOMEM`
    /// because an arena was requested.
    ///
    /// The unrequested form is rejected with `EINVAL`: its OS fallback has no
    /// caller in pinned v3.5.0, whose sole caller (`_mi_theap_alloc`) always
    /// passes `heap->exclusive_arena`. Porting that caller shape needs the
    /// source OS allocation owner, not a silent refusal.
    ///
    /// # Safety
    /// Same obligations as [`Self::try_allocate_slices_with_random`]; the
    /// requested arena must be a live parent published by this backing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn try_allocate_requested_arena_object(
        &self, process: VmProcess<'_>, config: MemoryConfig, search: ArenaSearch,
        size: usize, alignment: usize, align_offset: usize, commit: bool,
    ) -> Result<ArenaSliceClaim<'_>, Errno> {
        if search.requested.as_ptr().is_null() { return Err(Errno::INVAL); }
        let policy = process.policy();
        if !policy.disallow_arena_alloc()
            && size >= crate::config::ARENA_MIN_OBJ_SIZE
            && size <= super::selection::arena_max_object_size(policy)
            && alignment <= crate::config::ARENA_SLICE_SIZE && align_offset == 0
        {
            let slice_count = size.div_ceil(crate::config::ARENA_SLICE_SIZE);
            // SAFETY: forwarded caller obligations. A requested search never
            // reserves, so no random draw can occur.
            if let Some(claim) = unsafe { self.try_allocate_slices_with_random(process, config,
                search, slice_count, alignment, commit, None) } {
                return Ok(claim);
            }
        }
        Err(Errno::NOMEM)
    }

    /// Source `_mi_theap_alloc`'s exclusive-arena arm for a process-owned
    /// requested parent: `_mi_arenas_alloc(heap, align_up(sizeof(mi_theap_t),
    /// MI_ARENA_MIN_OBJ_SIZE), true, true, heap->exclusive_arena,
    /// tld->thread_seq, tld->numa_node, &memid)`, routed through
    /// [`Self::try_allocate_requested_arena_object`]. That keeps the source
    /// `disallow_arena_alloc` gate, both requested-arena search passes for a
    /// nonnegative NUMA node, the owning allocation's commit accounting, and
    /// the refusing OS fallback (`ENOMEM`). `subprocess` must be the main
    /// subprocess named by `process`; any other identity is `EINVAL`.
    ///
    /// # Safety
    /// Same obligations as [`Self::try_allocate_requested_arena_object`];
    /// `exclusive_arena` must be a live parent published by this backing.
    pub(crate) unsafe fn try_reserve_exclusive_theap<'subprocess>(
        &self, process: VmProcess<'_>, config: MemoryConfig,
        subprocess: &'subprocess crate::subproc::MainSubprocess, exclusive_arena: ArenaId,
        thread_sequence: crate::types::ThreadSequence, numa_node: i32,
    ) -> Result<super::ExclusiveArenaTheapReservation<'_, 'subprocess>, Errno> {
        if exclusive_arena.as_ptr().is_null()
            || !process.main_subprocess().is_some_and(|main| core::ptr::eq(main, subprocess))
        {
            return Err(Errno::INVAL);
        }
        let size = core::mem::size_of::<crate::types::Theap>()
            .next_multiple_of(crate::config::ARENA_MIN_OBJ_SIZE);
        let search = ArenaSearch {
            heap_sequence: 0,
            heap_count: 1,
            thread_sequence: thread_sequence.get(),
            numa_node,
            requested: exclusive_arena,
            allow_pinned: true,
        };
        // SAFETY: forwarded caller obligations.
        let claim = unsafe { self.try_allocate_requested_arena_object(process, config, search,
            size, crate::config::ARENA_SLICE_SIZE, 0, true) }?;
        Ok(super::ExclusiveArenaTheapReservation { claim, subprocess })
    }

    /// Child-only regular arena allocation through the parent-bound VM policy
    /// and this exact child's arena group. Every claim borrows the backing;
    /// retained mapping callbacks keep a raw identity pair until the external
    /// child owner calls `destroy_all` before releasing its context.
    ///
    /// # Safety
    /// The caller retains the parent-issued `ChildMainHeapContextOwner` and
    /// its pinned child image until all returned claims are released and this
    /// backing's `destroy_all` has transferred every slot. No child teardown
    /// or registry mutation may overlap. `search` must carry the exact live
    /// child Heap/page facts; for the child metadata-Theap source path its
    /// thread sequence is zero from the parent detached TLD, while `random`
    /// is the child metadata Theap's exclusively borrowed random image,
    /// seeded from that TLD during Theap initialization.
    pub(crate) unsafe fn try_allocate_child_slices_with_random<'child>(
        &'child self,
        child: crate::os::ChildVmProcess<'child>,
        config: MemoryConfig,
        search: ArenaSearch,
        slice_count: usize,
        alignment: usize,
        commit: bool,
        random: crate::os::OsRandom<'_>,
    ) -> Option<ArenaSliceClaim<'child>> {
        let identity = child.identity();
        if !identity.is_registered_child_of(child.parent_identity())
            || !core::ptr::eq(identity.arena_backing(), self)
            || !self.child_binding_matches(child.process(), config)
        {
            return None;
        }
        unsafe {
            self.try_allocate_slices_with_random(
                child.process(), config, search, slice_count, alignment, commit, random,
            )
        }
    }

    /// Source `mi_arena_reserve`, called only under the source reserve lock.
    ///
    /// # Safety
    /// The caller holds `reserve_lock` and retains the borrowed process policy,
    /// identity, and backing until `destroy_all` transfers all published or
    /// terminal owners. `random` is exclusively borrowed for each source draw.
    unsafe fn reserve_locked(
        &self, process: VmProcess<'_>, config: MemoryConfig,
        requested_size: usize, allow_large: bool, mut random: crate::os::OsRandom<'_>,
    ) -> Option<ArenaId> {
        let plan = ArenaReservationPlan::for_policy(config, self.registry.count(), requested_size, process.policy())?;
        for size in [Some(plan.primary_size), plan.fallback_size].into_iter().flatten() {
            let stats = process.subprocess().vm_statistics();
            if plan.adjust_committed { stats.committed_adjust_decrease(size); }
            // Pinned `mi_arena_reserve` always reserves a shared arena.
            let result = unsafe { self.reserve_one_locked(process, config, size, plan.access, allow_large, false, random.as_deref_mut()) };
            if let Ok(id) = result { return Some(id); }
            if plan.adjust_committed { stats.committed_adjust_increase(size); }
        }
        None
    }

    /// Explicit source regular reservation (`mi_reserve_os_memory_ex2`), used
    /// after huge startup options. It may span multiple source arenas; the
    /// allocation owner retains any suffix after partial registry publication.
    /// An `exclusive` parent is suitable only for requests naming it (source
    /// `mi_arena_is_suitable`); the automatic `mi_arena_reserve` path never
    /// asks for one.
    ///
    /// # Safety
    /// This is the process's sole arena group with immutable configuration.
    /// The borrowed process policy/identity and backing remain live until all
    /// published ranges, callbacks, and retained failures are retired by
    /// `destroy_all`; no teardown overlaps. Any random image is exclusively
    /// borrowed from the current default Theap.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn reserve_os_memory_for_process(
        &'static self, process: VmProcess<'static>, config: MemoryConfig, size: usize,
        access: MapAccess, allow_large: bool, exclusive: bool, random: crate::os::OsRandom<'_>,
    ) -> Result<ArenaId, Errno> {
        // SAFETY: forwarded.
        unsafe { self.reserve_os_memory_reporting_failure(process, config, size, access, allow_large, exclusive, random) }
            .map_err(|_| Errno::NOMEM)
    }

    /// [`Self::reserve_os_memory_for_process`] with the failing step: the
    /// public entry needs it for the C `errno` the source path leaves (the
    /// failed OS primitive's code, or none).
    ///
    /// # Safety
    /// As [`Self::reserve_os_memory_for_process`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn reserve_os_memory_reporting_failure(
        &'static self, process: VmProcess<'static>, config: MemoryConfig, size: usize,
        access: MapAccess, allow_large: bool, exclusive: bool, random: crate::os::OsRandom<'_>,
    ) -> Result<ArenaId, ReserveOsMemoryFailure> {
        // `mi_reserve_os_memory_ex2` rounds a representable size up to one
        // slice, then reports a size above `MI_MAX_ALLOC_SIZE` (the rounded
        // one when rounding produced it) and returns `ENOMEM`
        // (`src/arena.c:1886-1894`). The report runs before any reservation
        // lock or mapping exists.
        let size = if size <= crate::config::MAX_ALLOC_SIZE {
            (size + (crate::config::ARENA_SLICE_SIZE - 1)) & !(crate::config::ARENA_SLICE_SIZE - 1)
        } else {
            size
        };
        if size > crate::config::MAX_ALLOC_SIZE {
            let _ = crate::process_init::process_error_message(
                crate::diagnostic_output::SourceErrorReport::ReservationTooLarge { size },
            );
            return Err(ReserveOsMemoryFailure::TooLarge);
        }
        let _guard = self.reserve_lock.lock().map_err(|_| ReserveOsMemoryFailure::Unmanaged)?;
        unsafe { self.reserve_one_locked(process, config, size, access, allow_large, exclusive, random) }
            .map_err(|error| error.map_or(ReserveOsMemoryFailure::Unmanaged, ReserveOsMemoryFailure::Os))
    }

    /// Source `mi_reserve_os_memory_ex2` regular aligned map/manage/free.
    /// A manage failure releases the unpublished mapping through source
    /// `_mi_os_free_ex`: a failed `munmap` is warned, still counted, and the
    /// mapping leaks, exactly as pinned C leaks it. The reservation simply
    /// fails; later reservations are unaffected.
    ///
    /// # Safety
    /// The caller holds `reserve_lock` and satisfies `reserve_locked`'s
    /// process/backing lifetime and random-access obligations.
    #[allow(clippy::too_many_arguments)]
    unsafe fn reserve_one_locked(
        &self, process: VmProcess<'_>, config: MemoryConfig,
        size: usize, access: MapAccess, allow_large: bool, exclusive: bool,
        random: crate::os::OsRandom<'_>,
    ) -> Result<ArenaId, Option<Errno>> {
        // Reserve a cleanup slot before acquiring any new OS ownership.
        self.slots.iter().find(|slot| slot.state.load(Ordering::Relaxed) == EMPTY).ok_or(None)?;
        let allocation = NormalOsAllocation::allocate_arena_base_for_process(process, config,
            size, ARENA_ALIGNMENT, access, allow_large, random);
        let (mut mapping, memory) = match allocation {
            Ok(allocation) => {
                let (mapping, memory) = allocation.into_mapping_and_memory();
                match unsafe { self.install_owned_os_mapping_locked(process,
                    StoredVmProcess::from_retained_process(process), config, size, mapping, memory, -1, exclusive) } {
                    Ok(managed) => return Ok(managed.arena_id()),
                    Err(failure) => { let (mapping, memory, _) = failure.into_parts(); (mapping, memory) }
                }
            }
            Err(failure) => {
                // Only a post-map allocation invariant rejection returns a
                // mapping here; aligned trim failures already leaked. A
                // failed primitive leaves its code in the C `errno`.
                let error = failure.error();
                let mapping = failure.into_mapping().ok_or(Some(error))?;
                let memory = MemoryId::os(mapping.base().expect("a returned OS failure owns an active mapping"),
                    mapping.length().expect("a returned OS failure owns its complete length"),
                    mapping.initially_committed(), mapping.initially_zero(), mapping.is_large());
                (mapping, memory)
            }
        };
        let commit_size = if memory.initially_committed() {
            memory.os_memory().expect("unpublished arena failure retains OS provenance").size
        } else { 0 };
        let address = memory.os_memory().map_or(0, |os| os.base as usize);
        let length = memory.os_memory().map_or(0, |os| os.size);
        if let Err(error) = mapping.unmap_for_process(process, commit_size, false) {
            // Dropping the still-mapped non-RAII owner leaks it, as the
            // source does after its warning.
            process.policy().source_warning(
                crate::diagnostic_output::SourceFormattedMessage::os_free_failure(error, length, address));
            return Err(Some(error));
        }
        Err(None)
    }
}

/// A callback-backed external installation either returns its complete lease
/// before first publication or retains it terminally when the finalization
/// lock could not establish that no registry entry escaped. A returned lease
/// conservatively loses its zero-image claim if preparation ran.
#[must_use = "external installation failure retains or returns the callback lease"]
pub(crate) enum ProcessExternalArenaInstallFailure {
    Returned {
        error: ManageArenaError,
        lease: ProcessExternalArenaLease,
    },
    Retained {
        error: ManageArenaError,
    },
}

impl ProcessExternalArenaInstallFailure {
    pub(crate) const fn error(&self) -> ManageArenaError {
        match self {
            Self::Returned { error, .. } | Self::Retained { error } => *error,
        }
    }

    pub(crate) fn into_returned_lease(self) -> Option<ProcessExternalArenaLease> {
        match self {
            Self::Returned { lease, .. } => Some(lease),
            Self::Retained { .. } => None,
        }
    }
}

/// Pre-publication huge rejection retains the full primitive-range owner.
#[must_use = "unpublished huge backing must be released or installed"]
pub(crate) struct ProcessHugeArenaInstallFailure {
    error: ManageArenaError,
    allocation: HugeOsAllocation<'static>,
}

impl ProcessHugeArenaInstallFailure {
    pub(crate) const fn error(&self) -> ManageArenaError { self.error }
    pub(crate) fn into_allocation(self) -> HugeOsAllocation<'static> { self.allocation }
}

/// An unpublished failure retains both the OS owner and its accounting pair.
pub(crate) struct ProcessArenaInstallFailure<'process> {
    error: ManageArenaError,
    mapping: Mapping,
    memory: MemoryId,
    process: VmProcess<'process>,
}

impl<'process> ProcessArenaInstallFailure<'process> {
    pub(crate) const fn error(&self) -> ManageArenaError { self.error }

    pub(crate) fn into_parts(self) -> (Mapping, MemoryId, VmProcess<'process>) {
        (self.mapping, self.memory, self.process)
    }
}

unsafe extern "C" fn commit_owned_arena(
    commit: bool, start: *mut u8, size: usize, is_zero: *mut bool, argument: *mut c_void,
) -> bool {
    let Some(slot) = (unsafe { argument.cast::<ArenaAllocationSlot>().as_ref() }) else { return false; };
    let Some(owner) = (unsafe { slot.initialized() }) else { return false; };
    let Ok(base) = owner.allocation.base() else { return false; };
    let Some(offset) = (start as usize).checked_sub(base as usize) else { return false; };
    let Ok(length) = owner.allocation.length() else { return false; };
    if offset.checked_add(size).is_none_or(|end| end > length) { return false; }
    if !is_zero.is_null() { unsafe { is_zero.write(false); } }
    if commit {
        owner.allocation.regular().is_some_and(|mapping|
            mapping.commit_for_process(owner.process(), offset, size, 0).is_ok())
    } else {
        // This arm's source result means "needs recommit", not syscall
        // success. Native Linux retains accessibility even when its advisory
        // discard reports an error. The complete policy purge caller also
        // supplies allow_reset and already-committed accounting separately.
        let Some(mapping) = owner.allocation.regular() else { return false; };
        let _ = mapping.decommit_for_process(owner.process(), offset, size, size);
        false
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::{ArenaId, ArenaView};
    use crate::bootstrap::ExclusiveTheapBootstrap;
    use crate::config::{ARENA_SLICE_SIZE, KIB, MIB, SMALL_MAX_OBJ_SIZE, VmOption, VmOptions, VmOptionEnvironment};
    use crate::os::{MapAccess, NormalOsAllocation, PageSize, VmPolicy, fault};
    use crate::page_map::PageMap;
    use crate::single_thread::ProcessMetadataPageAllocator;
    use crate::statistics::VmStatisticsSnapshot;
    use crate::subproc::MainSubprocess;
    use crabc_core::Errno;
    use std::boxed::Box;

    #[test]
    fn destroy_all_retires_regular_external_and_huge_owners_with_exact_retries() {
        let fault = fault::install(fault::Plan::disabled());
        let process = process();
        let backing = backing();
        install(backing, process, MapAccess::Committed);
        install(backing, process, MapAccess::Reserved);
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (external, base) = external_lease(process, ARENA_MIN_SIZE, true, true, trace);
        install_external(backing, process, ARENA_MIN_SIZE, external);
        trace.clear_observation();
        let before = process.subprocess().vm_statistics().snapshot();
        let count = backing.registry.count();
        // All fixture views have expired; the external map remains caller-owned.
        let destroyed = unsafe { backing.destroy_all(&mut []) }.unwrap();
        assert!(destroyed.is_released());
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(backing.registry.count(), 0);
        assert_eq!(trace.commits.load(Ordering::Acquire), 0);
        assert_eq!(trace.purges.load(Ordering::Acquire), 0);
        unsafe { base.add(ARENA_MIN_SIZE - 1).write(0x5a); }
        assert_eq!(unsafe { base.add(ARENA_MIN_SIZE - 1).read() }, 0x5a);
        std::println!();
        for (index, value) in [count as i64, backing.registry.count() as i64,
            before.reserved_current - after.reserved_current,
            before.committed_current - after.committed_current,
            trace.commits.load(Ordering::Acquire) as i64,
            trace.purges.load(Ordering::Acquire) as i64, 1].into_iter().enumerate() {
            std::println!("m2.arena.destroy.{index}={value}");
        }
        assert!(matches!(unsafe { backing.destroy_all(&mut []) }, Err(ArenaDestroyError::AlreadyDestroyed)));
        unsafe { crabc_core::mm::munmap_raw(base, ARENA_MIN_SIZE) }.unwrap();

        // Full parent provenance must survive failed free, including its
        // child arena headers. The successful retry never touches them.
        let process = self::process();
        let backing = self::backing();
        let size = ARENA_MAX_SIZE + ARENA_MIN_SIZE;
        unsafe { backing.reserve_os_memory_for_process(process, config(), size,
            MapAccess::Reserved, false, false, None) }.unwrap();
        assert_eq!(backing.registry.count(), 2);
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let mut destroyed = unsafe { backing.destroy_all(&mut []) }.unwrap();
        assert_eq!(fault.observed(), 1, "one parent owns both source arenas");
        assert!(!destroyed.is_released());
        assert_eq!(backing.registry.count(), 0);
        let accounted = process.subprocess().vm_statistics().snapshot();
        std::println!("m2.arena.destroy.7={}", fault.observed());
        std::println!("m2.arena.destroy.8={}", backing.registry.count());
        std::println!("m2.arena.destroy.9={}", usize::from(!destroyed.is_released()));
        fault.set(fault::Plan::disabled());
        destroyed.retry_raw().unwrap();
        assert!(destroyed.is_released());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), accounted);

        // Simulated huge primitives exercise exact failed-page bookkeeping,
        // not kernel huge-page availability or NUMA placement.
        for pages in [3, 17] {
            fault.set(fault::Plan::disabled());
            let process = self::process();
            let backing = self::backing();
            let huge = HugeOsAllocation::test_registry_allocation(process, config(), pages);
            let huge_base = huge.base();
            unsafe { backing.install_owned_huge_allocation(config(), huge, -1, false) }
                .unwrap_or_else(|_| panic!("simulated huge arena installs"));
            let expected_arenas = if pages == 3 { 1 } else { 2 };
            assert_eq!(backing.registry.count(), expected_arenas);
            let before_refusal = process.subprocess().vm_statistics().snapshot();
            fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
            assert!(matches!(unsafe { backing.destroy_all(&mut []) },
                Err(ArenaDestroyError::TrackingCapacity { required_words: 1 })));
            let inside = unsafe { core::slice::from_raw_parts_mut(
                huge_base.as_ptr().add(crate::config::GIB - 4096).cast::<usize>(), 1) };
            assert!(matches!(unsafe { backing.destroy_all(inside) },
                Err(ArenaDestroyError::TrackingInsideArena)));
            assert_eq!(fault.observed(), 0, "admission never attempts unmap");
            assert_eq!(process.subprocess().vm_statistics().snapshot(), before_refusal);
            assert_eq!(backing.registry.count(), expected_arenas, "capacity refusal precedes publication changes");
            let mut tracking = [0usize; 1];
            fault.set(fault::Plan::at(fault::Point::Unmap, 2, Errno::NOMEM));
            let mut destroyed = unsafe { backing.destroy_all(&mut tracking) }.unwrap();
            assert_eq!(fault.observed(), pages, "source huge free continues after an error");
            if pages == 3 {
                std::println!("m2.arena.destroy.10={}", fault.observed());
                std::println!("m2.arena.destroy.11={}", backing.registry.count());
                std::println!("m2.arena.destroy.12={}", usize::from(!destroyed.is_released()));
            }
            assert!(!destroyed.is_released());
            let accounted = process.subprocess().vm_statistics().snapshot();
            fault.set(fault::Plan::at(fault::Point::Unmap, 2, Errno::NOMEM));
            destroyed.retry_raw().unwrap();
            assert_eq!(fault.observed(), 1, "raw retry visits only the failed huge page");
            assert!(destroyed.is_released());
            assert_eq!(process.subprocess().vm_statistics().snapshot(), accounted);
        }
    }

    fn process() -> VmProcess<'static> {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        process_with_options(options)
    }

    fn process_with_options(options: VmOptions) -> VmProcess<'static> {
        let policy = Box::leak(Box::new(VmPolicy::new(options).unwrap()));
        // This direct fixture explicitly represents a process after its
        // preload interval; production transition belongs to process_init.
        policy.finish_preloading();
        VmProcess::new(policy, MainSubprocess::test_static_owner())
    }

    fn process_with_page_commit_on_demand() -> VmProcess<'static> {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::PageCommitOnDemand, 1);
        process_with_options(options)
    }

    fn config() -> MemoryConfig {
        MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false)
    }

    fn backing() -> &'static ProcessArenaBacking {
        Box::leak(Box::new(ProcessArenaBacking::new()))
    }

    fn mapped(process: VmProcess<'static>, access: MapAccess) -> (Mapping, MemoryId) {
        NormalOsAllocation::allocate_aligned_base_for_process(process, config(), ARENA_MIN_SIZE,
            ARENA_ALIGNMENT, access, false, None).unwrap().into_mapping_and_memory()
    }

    fn install(backing: &'static ProcessArenaBacking, process: VmProcess<'static>, access: MapAccess) -> ArenaId {
        if access == MapAccess::Committed {
            // The source lazy reserve adjusts before map, not after its
            // committed peak has already been observed.
            process.subprocess().vm_statistics().committed_adjust_decrease(ARENA_MIN_SIZE);
        }
        let (mapping, memory) = mapped(process, access);
        match unsafe { backing.install_owned_os_mapping(process, config(), ARENA_MIN_SIZE, mapping, memory, -1, false) } {
            Ok(managed) => { assert!(managed.is_complete()); managed.arena_id() }
            Err(failure) => std::panic!("owned arena installation: {:?}", failure.error()),
        }
    }

    fn search(requested: ArenaId) -> ArenaSearch {
        ArenaSearch { heap_sequence: 0, heap_count: 1, thread_sequence: 0,
            numa_node: -1, requested, allow_pinned: false }
    }

    struct ExternalCallbackTrace {
        commits: core::sync::atomic::AtomicUsize,
        purges: core::sync::atomic::AtomicUsize,
        last_start: core::sync::atomic::AtomicUsize,
        last_size: core::sync::atomic::AtomicUsize,
        commit_zero_output: core::sync::atomic::AtomicBool,
        commit_zero_is_non_null: core::sync::atomic::AtomicBool,
        commit_success: core::sync::atomic::AtomicBool,
        purge_needs_recommit: core::sync::atomic::AtomicBool,
        purge_zero_is_null: core::sync::atomic::AtomicBool,
    }

    impl ExternalCallbackTrace {
        fn new() -> Self {
            Self {
                commits: core::sync::atomic::AtomicUsize::new(0),
                purges: core::sync::atomic::AtomicUsize::new(0),
                last_start: core::sync::atomic::AtomicUsize::new(0),
                last_size: core::sync::atomic::AtomicUsize::new(0),
                commit_zero_output: core::sync::atomic::AtomicBool::new(false),
                commit_zero_is_non_null: core::sync::atomic::AtomicBool::new(false),
                commit_success: core::sync::atomic::AtomicBool::new(true),
                purge_needs_recommit: core::sync::atomic::AtomicBool::new(false),
                purge_zero_is_null: core::sync::atomic::AtomicBool::new(false),
            }
        }

        fn clear_observation(&self) {
            self.commits.store(0, Ordering::Release);
            self.purges.store(0, Ordering::Release);
            self.last_start.store(0, Ordering::Release);
            self.last_size.store(0, Ordering::Release);
            self.commit_zero_is_non_null.store(false, Ordering::Release);
            self.purge_zero_is_null.store(false, Ordering::Release);
        }
    }

    unsafe extern "C" fn external_transition_callback(
        commit: bool,
        start: *mut u8,
        size: usize,
        is_zero: *mut bool,
        argument: *mut c_void,
    ) -> bool {
        let Some(trace) = (unsafe { argument.cast::<ExternalCallbackTrace>().as_ref() }) else {
            return false;
        };
        trace.last_start.store(start as usize, Ordering::Release);
        trace.last_size.store(size, Ordering::Release);
        if commit {
            trace.commits.fetch_add(1, Ordering::AcqRel);
            trace.commit_zero_is_non_null.store(!is_zero.is_null(), Ordering::Release);
            if !is_zero.is_null() {
                unsafe {
                    is_zero.write(trace.commit_zero_output.load(Ordering::Acquire));
                }
            }
            trace.commit_success.load(Ordering::Acquire)
        } else {
            trace.purges.fetch_add(1, Ordering::AcqRel);
            trace.purge_zero_is_null.store(is_zero.is_null(), Ordering::Release);
            trace.purge_needs_recommit.load(Ordering::Acquire)
        }
    }

    /// Maps writable test storage and deliberately transfers only an external
    /// callback lease to the arena owner. The backing mapping and trace are
    /// leaked with the test's process-lived registry, matching the external
    /// caller's lifetime obligation without giving that owner unmap authority.
    fn external_lease(
        process: VmProcess<'static>,
        size: usize,
        initially_committed: bool,
        initially_zero: bool,
        trace: &'static ExternalCallbackTrace,
    ) -> (ProcessExternalArenaLease, *mut u8) {
        let base = external_storage(process, size);
        let lease = unsafe {
            ProcessExternalArenaLease::new(
                base,
                size,
                initially_committed,
                false,
                initially_zero,
                CommitHook::new(
                    external_transition_callback,
                    core::ptr::from_ref(trace).cast_mut().cast(),
                ),
            )
        }
        .unwrap();
        (lease, base)
    }

    fn install_external(
        backing: &'static ProcessArenaBacking,
        process: VmProcess<'static>,
        size: usize,
        lease: ProcessExternalArenaLease,
    ) -> ManagedExternalRegion {
        unsafe {
            backing.install_owned_external_callback_arena(
                process,
                config(),
                size,
                lease,
                -1,
                false,
            )
        }
        .unwrap_or_else(|failure| panic!("external arena installation: {:?}", failure.error()))
    }

    fn external_storage(process: VmProcess<'static>, size: usize) -> *mut u8 {
        let (mapping, _) = NormalOsAllocation::allocate_aligned_base_for_process(
            process,
            config(),
            size,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
            false,
            None,
        )
        .unwrap()
        .into_mapping_and_memory();
        let base = mapping.base().unwrap();
        core::mem::forget(mapping);
        base
    }

    struct ReentrantExternalInstall {
        backing: &'static ProcessArenaBacking,
        process: VmProcess<'static>,
        inner_lease: UnsafeCell<Option<ProcessExternalArenaLease>>,
        callback_calls: core::sync::atomic::AtomicUsize,
        binding_matches: core::sync::atomic::AtomicBool,
        inner_arena: core::sync::atomic::AtomicUsize,
    }

    // The source callback contract serializes this test fixture's one mutable
    // lease transfer. The callback reenters only on its first synchronous
    // metadata commit, after the outer installer released reserve_lock.
    unsafe impl Sync for ReentrantExternalInstall {}

    unsafe extern "C" fn reentrant_external_callback(
        commit: bool,
        _start: *mut u8,
        _size: usize,
        is_zero: *mut bool,
        argument: *mut c_void,
    ) -> bool {
        let Some(state) = (unsafe { argument.cast::<ReentrantExternalInstall>().as_ref() }) else {
            return false;
        };
        if commit && state.callback_calls.fetch_add(1, Ordering::AcqRel) == 0 {
            state.binding_matches.store(
                state
                    .backing
                    .matches_existing_process_binding(state.process, config())
                    .unwrap_or(false),
                Ordering::Release,
            );
            let lease = unsafe { (&mut *state.inner_lease.get()).take() }
                .expect("the reentrant callback has one inner external lease");
            let managed = unsafe {
                state.backing.install_owned_external_callback_arena(
                    state.process,
                    config(),
                    ARENA_MIN_SIZE,
                    lease,
                    -1,
                    false,
                )
            }
            .unwrap_or_else(|failure| {
                panic!("the callback reentry owns its returned lease: {:?}", failure.error())
            });
            state
                .inner_arena
                .store(managed.arena_id().as_ptr() as usize, Ordering::Release);
        }
        if !is_zero.is_null() {
            unsafe { is_zero.write(false) };
        }
        true
    }

    /// One address-free source-callback lifecycle record for the pinned-C
    /// differential. This reaches the process-lived typed owner rather than
    /// the legacy raw `Arena.commit_function` test seam.
    pub(crate) fn m2_external_callback_trace(fault_guard: &fault::Guard) -> [usize; 13] {
        let process = purge_process(0, false);
        let external_backing = backing();
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        trace.commit_zero_output.store(true, Ordering::Release);
        let (lease, _) = external_lease(process, ARENA_MIN_SIZE, false, false, trace);
        let id = install_external(external_backing, process, ARENA_MIN_SIZE, lease).arena_id();
        let managed_external_owner = unsafe { ArenaView::from_ptr(id.as_ptr()) }
            .is_some_and(|view| view.arena().memid.kind() == MemoryKind::External);
        trace.clear_observation();
        let claim = unsafe {
            external_backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true)
        }
        .expect("the external trace obtains one typed committed claim");
        let commit_zero_propagated = claim.memory_id().initially_zero()
            && trace.commits.load(Ordering::Acquire) == 1
            && trace.commit_zero_is_non_null.load(Ordering::Acquire)
            && trace.last_start.load(Ordering::Acquire) == claim.start() as usize
            && trace.last_size.load(Ordering::Acquire) == 2 * ARENA_SLICE_SIZE;

        trace.purge_needs_recommit.store(true, Ordering::Release);
        trace.clear_observation();
        fault_guard.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        let before = process.subprocess().vm_statistics().snapshot();
        let claim_start = claim.start() as usize;
        let claim_slice = claim.slice_index();
        let released = claim.release();
        let after = process.subprocess().vm_statistics().snapshot();
        let no_normal_advice = fault_guard.observed() == 0;
        fault_guard.set(fault::Plan::disabled());
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }
            .expect("the published external arena remains inspectable");
        let purge_raw_span_and_statistics = released
            && trace.purges.load(Ordering::Acquire) == 1
            && trace.purge_zero_is_null.load(Ordering::Acquire)
            && trace.last_start.load(Ordering::Acquire) == claim_start
            && trace.last_size.load(Ordering::Acquire) == 2 * ARENA_SLICE_SIZE
            && after.purge_calls == before.purge_calls + 1
            && after.purged == before.purged + (2 * ARENA_SLICE_SIZE) as i64;
        let purge_true_clears_commit = unsafe { view.slices_committed() }
            .and_then(|bitmap| bitmap.is_clear_range(claim_slice, 2)) == Some(true);
        trace.clear_observation();
        let recommit = unsafe {
            external_backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true)
        }
        .expect("the callback's needs-recommit result clears the typed bitmap");
        let recommit_reinvokes_callback = recommit.slice_index() == claim_slice
            && trace.commits.load(Ordering::Acquire) == 1
            && trace.last_start.load(Ordering::Acquire) == recommit.start() as usize
            && trace.last_size.load(Ordering::Acquire) == 2 * ARENA_SLICE_SIZE;

        let false_process = purge_process(0, false);
        let false_backing = backing();
        let false_trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (lease, _) = external_lease(false_process, ARENA_MIN_SIZE, false, false, false_trace);
        let false_id = install_external(false_backing, false_process, ARENA_MIN_SIZE, lease).arena_id();
        let false_claim = unsafe {
            false_backing.try_find_free(search(false_id), 2, ARENA_SLICE_SIZE, false)
        }
        .expect("the callback-false trace obtains a source range");
        let false_slice = false_claim.slice_index();
        externally_commit_range(false_backing, false_id, &false_claim, 2);
        false_trace.purge_needs_recommit.store(false, Ordering::Release);
        false_trace.clear_observation();
        let false_released = false_claim.release();
        let false_view = unsafe { ArenaView::from_ptr(false_id.as_ptr()) }.unwrap();
        let purge_false_preserves_commit = false_released
            && false_trace.purges.load(Ordering::Acquire) == 1
            && unsafe { false_view.slices_committed() }
                .and_then(|bitmap| bitmap.is_set_range(false_slice, 2)) == Some(true);

        let mixed_process = purge_process(0, false);
        let mixed_backing = backing();
        let mixed_trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (lease, _) = external_lease(mixed_process, ARENA_MIN_SIZE, false, false, mixed_trace);
        let mixed_id = install_external(mixed_backing, mixed_process, ARENA_MIN_SIZE, lease).arena_id();
        let mixed_claim = unsafe {
            mixed_backing.try_find_free(search(mixed_id), 2, ARENA_SLICE_SIZE, false)
        }
        .expect("the mixed callback trace obtains a source range");
        let mixed_slice = mixed_claim.slice_index();
        externally_commit_range(mixed_backing, mixed_id, &mixed_claim, 1);
        mixed_trace.purge_needs_recommit.store(false, Ordering::Release);
        mixed_trace.clear_observation();
        let mixed_released = mixed_claim.release();
        let mixed_view = unsafe { ArenaView::from_ptr(mixed_id.as_ptr()) }.unwrap();
        let purge_mixed_clears_commit = mixed_released
            && mixed_trace.purges.load(Ordering::Acquire) == 1
            && unsafe { mixed_view.slices_committed() }
                .and_then(|bitmap| bitmap.is_clear_range(mixed_slice, 2)) == Some(true);

        let negative_process = purge_process(-1, false);
        let negative_backing = backing();
        let negative_trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (lease, _) = external_lease(
            negative_process,
            ARENA_MIN_SIZE,
            true,
            false,
            negative_trace,
        );
        let negative_id = install_external(
            negative_backing,
            negative_process,
            ARENA_MIN_SIZE,
            lease,
        )
        .arena_id();
        let negative_claim = unsafe {
            negative_backing.try_find_free(search(negative_id), 2, ARENA_SLICE_SIZE, false)
        }
        .expect("the negative-delay trace obtains a fully committed claim");
        negative_trace.clear_observation();
        fault_guard.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        let negative_before = negative_process.subprocess().vm_statistics().snapshot();
        let negative_released = negative_claim.release();
        let negative_after = negative_process.subprocess().vm_statistics().snapshot();
        let negative_delay_skips_callback_and_statistics = negative_released
            && negative_trace.purges.load(Ordering::Acquire) == 0
            && negative_after == negative_before
            && fault_guard.observed() == 0;
        fault_guard.set(fault::Plan::disabled());
        let direct_page_extension = m2_external_page_extension_trace(fault_guard);

        [
            usize::from(managed_external_owner),
            usize::from(commit_zero_propagated),
            usize::from(purge_raw_span_and_statistics),
            usize::from(purge_true_clears_commit),
            usize::from(recommit_reinvokes_callback),
            usize::from(purge_false_preserves_commit),
            usize::from(purge_mixed_clears_commit),
            usize::from(negative_delay_skips_callback_and_statistics),
            usize::from(no_normal_advice),
            usize::from(external_backing.registry().count() == 1
                && false_backing.registry().count() == 1
                && mixed_backing.registry().count() == 1
                && negative_backing.registry().count() == 1),
            direct_page_extension[0],
            direct_page_extension[1],
            direct_page_extension[2],
        ]
    }

    #[test]
    fn external_metadata_callback_reenters_after_stable_slot_reservation_without_borrowing_it() {
        let _fault = fault::install(fault::Plan::disabled());
        let process = process();
        let backing = backing();
        let inner_trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (inner_lease, _) = external_lease(process, ARENA_MIN_SIZE, true, false, inner_trace);
        let outer_base = external_storage(process, ARENA_MIN_SIZE);
        let state = Box::leak(Box::new(ReentrantExternalInstall {
            backing,
            process,
            inner_lease: UnsafeCell::new(Some(inner_lease)),
            callback_calls: core::sync::atomic::AtomicUsize::new(0),
            binding_matches: core::sync::atomic::AtomicBool::new(false),
            inner_arena: core::sync::atomic::AtomicUsize::new(0),
        }));
        let outer_lease = unsafe {
            ProcessExternalArenaLease::new(
                outer_base,
                ARENA_MIN_SIZE,
                false,
                false,
                false,
                CommitHook::new(
                    reentrant_external_callback,
                    core::ptr::from_ref(state).cast_mut().cast(),
                ),
            )
        }
        .unwrap();
        let outer = install_external(backing, process, ARENA_MIN_SIZE, outer_lease).arena_id();
        assert_eq!(state.callback_calls.load(Ordering::Acquire), 1);
        assert!(state.binding_matches.load(Ordering::Acquire),
            "the reentrant validator may inspect its stable initializing owner under the lock");
        let inner = state.inner_arena.load(Ordering::Acquire) as *mut Arena;
        assert!(!inner.is_null());
        assert_eq!(backing.registry().count(), 2);
        assert!(unsafe { backing.allocation_for_arena(&*outer.as_ptr()) }.is_some());
        assert!(unsafe { backing.allocation_for_arena(&*inner) }.is_some());
        assert!(backing.slots.iter().all(|slot|
            slot.state.load(Ordering::Acquire) != INITIALIZING));
    }

    #[test]
    fn external_publication_rejection_returns_lease_and_late_partial_management_retains_full_owner() {
        let _fault = fault::install(fault::Plan::disabled());
        let process = process();
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));

        let rejected = backing();
        let regular = install(rejected, process, MapAccess::Committed);
        for entry in &rejected.registry.arenas {
            entry.store(regular.as_ptr(), Ordering::Relaxed);
        }
        rejected.registry.count.store(MAX_ARENAS, Ordering::Relaxed);
        let (lease, base) = external_lease(process, ARENA_MIN_SIZE, true, false, trace);
        let failure = match unsafe {
            rejected.install_owned_external_callback_arena(
                process,
                config(),
                ARENA_MIN_SIZE,
                lease,
                -1,
                false,
            )
        } {
            Ok(_) => panic!("a full registry rejects before this owner publishes"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), ManageArenaError::RegistryFull);
        let lease = failure.into_returned_lease().expect("the rejected first arena returns its lease");
        assert_eq!(lease.base(), base);
        assert!(rejected.slots.iter().skip(1).all(|slot| slot.state.load(Ordering::Acquire) == EMPTY));

        let partial = backing();
        let regular = install(partial, process, MapAccess::Committed);
        for entry in &partial.registry.arenas[..MAX_ARENAS - 1] {
            entry.store(regular.as_ptr(), Ordering::Relaxed);
        }
        partial.registry.count.store(MAX_ARENAS - 1, Ordering::Relaxed);
        let size = 17 * crate::config::GIB;
        let (lease, base) = external_lease(process, size, true, false, trace);
        let managed = install_external(partial, process, size, lease);
        assert!(!managed.is_complete());
        assert_eq!(managed.managed_size(), ARENA_MAX_SIZE);
        let owner = unsafe { partial.allocation_for_arena(&*managed.arena_id().as_ptr()) }.unwrap();
        let ArenaBacking::External(lease) = &owner.allocation else {
            panic!("partial external management retains its external lease");
        };
        assert_eq!(lease.base(), base);
        assert_eq!(lease.size(), size,
            "a later registry failure cannot discard the external suffix owner");
    }

    #[test]
    fn external_publication_rejection_invalidates_zero_before_returned_lease_retry() {
        let _fault = fault::install(fault::Plan::disabled());
        let process = process();
        let rejected = backing();
        let regular = install(rejected, process, MapAccess::Committed);
        for entry in &rejected.registry.arenas {
            entry.store(regular.as_ptr(), Ordering::Relaxed);
        }
        rejected.registry.count.store(MAX_ARENAS, Ordering::Relaxed);
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (lease, _) = external_lease(process, ARENA_MIN_SIZE, true, true, trace);
        let failure = unsafe {
            rejected.install_owned_external_callback_arena(
                process,
                config(),
                ARENA_MIN_SIZE,
                lease,
                -1,
                false,
            )
        }
        .expect_err("full source registry rejects only after external metadata preparation");
        assert_eq!(failure.error(), ManageArenaError::RegistryFull);
        let lease = failure.into_returned_lease()
            .expect("the unpublished external range stays with its caller");
        assert!(!lease.memory().initially_zero(),
            "written arena headers make a returned initially-zero lease conservative");

        let retry = backing();
        let managed = install_external(retry, process, ARENA_MIN_SIZE, lease);
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }
            .expect("the retry publishes a fresh arena image");
        let arena = view.arena();
        assert!(!arena.memid.initially_zero(),
            "retry clears the source metadata image before rebuilding its bitmaps");
        assert!(unsafe { retry.try_find_free(search(managed.arena_id()), 2, ARENA_SLICE_SIZE, false) }
            .is_some(), "retry rebuilds the expected free bitmap from the cleared image");
    }

    #[test]
    fn external_callback_commit_zero_and_prepublication_failure_return_the_typed_lease() {
        let _fault = fault::install(fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaIsNumaLocal, 1);
        let process = process_with_options(options);
        let backing = backing();
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        trace.commit_success.store(false, Ordering::Release);
        let (lease, base) = external_lease(process, ARENA_MIN_SIZE, false, false, trace);
        let failure = match unsafe {
            backing.install_owned_external_callback_arena(
                process,
                config(),
                ARENA_MIN_SIZE,
                lease,
                -1,
                false,
            )
        } {
            Ok(_) => panic!("a metadata callback failure must precede publication"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), ManageArenaError::CommitFailed);
        assert_eq!(backing.registry().count(), 0);
        assert!(backing.slots.iter().all(|slot| slot.state.load(Ordering::Acquire) == EMPTY));
        assert!(trace.commits.load(Ordering::Acquire) >= 1);
        assert_eq!(process.policy().test_numa_node_count_cache(), 0);
        let lease = failure
            .into_returned_lease()
            .expect("the unpublished callback lease returns to its caller");
        assert_eq!(lease.base(), base);

        trace.commit_success.store(true, Ordering::Release);
        trace.commit_zero_output.store(true, Ordering::Release);
        install_external(backing, process, ARENA_MIN_SIZE, lease);
        assert_ne!(process.policy().test_numa_node_count_cache(), 0);
        trace.clear_observation();
        let claim = unsafe {
            backing.try_find_free(search(ArenaId::none()), 2, ARENA_SLICE_SIZE, true)
        }
        .expect("the typed external owner commits a claimed source range");
        assert_eq!(trace.commits.load(Ordering::Acquire), 1);
        assert_eq!(trace.last_start.load(Ordering::Acquire), claim.start() as usize);
        assert_eq!(trace.last_size.load(Ordering::Acquire), 2 * ARENA_SLICE_SIZE);
        assert!(claim.memory_id().initially_zero(),
            "the callback's commit=true zero result reaches the arena claim");

        trace.commit_success.store(false, Ordering::Release);
        trace.clear_observation();
        assert!(unsafe {
            backing.try_find_free(search(ArenaId::none()), 2, ARENA_SLICE_SIZE, true)
        }
        .is_none());
        let failed_start = trace.last_start.load(Ordering::Acquire);
        assert_ne!(failed_start, 0);
        assert_eq!(trace.commits.load(Ordering::Acquire), 1);
        trace.commit_success.store(true, Ordering::Release);
        trace.clear_observation();
        let retry = unsafe {
            backing.try_find_free(search(ArenaId::none()), 2, ARENA_SLICE_SIZE, true)
        }
        .expect("a failed typed commit restores the exact free range");
        assert_eq!(retry.start() as usize, failed_start);
        assert_eq!(trace.commits.load(Ordering::Acquire), 1);
    }

    /// Records the external receiver's real `mi_page_extend_free` state.
    ///
    /// This must use a `ProcessMetadataPageAllocator` bound to the same
    /// subprocess backing that owns the external lease. The C differential
    /// invokes `mi_page_extend_free` on an actual external-heap page, so the
    /// matching Rust values observe `Page::free`, `capacity`, and
    /// `slice_pcommitted`, rather than a lower-level arena bitmap alone.
    fn m2_external_page_extension_trace(fault: &fault::Guard) -> [usize; 3] {
        let process = process_with_page_commit_on_demand();
        let backing = process.subprocess().arena_backing();
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (lease, _) = external_lease(process, ARENA_MIN_SIZE, false, false, trace);
        let id = install_external(backing, process, ARENA_MIN_SIZE, lease).arena_id();
        let mut page_map = PageMap::initialize(config(), 0, true)
            .expect("the isolated external process initializes its page map");
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        bootstrap
            .as_mut()
            .bind_detached_for_main_subprocess(
                process.main_subprocess().expect("fixture uses process main"),
            )
            .expect("the isolated process binds its detached metadata image before first demand");
        let mut allocator = unsafe {
            ProcessMetadataPageAllocator::activate_process_metadata(
                bootstrap.as_mut(), process, &page_map,
            )
        }
        .expect("the isolated process metadata session binds its external backing");
        let request = SMALL_MAX_OBJ_SIZE + 1;
        let first = allocator
            .allocate(request, false)
            .expect("the external source page commits its initial medium prefix");
        let page = NonNull::new(unsafe { allocator.page_for_block(first) })
            .expect("the initial external medium page is PageMap-published");
        let memory = unsafe { page.as_ref().memid() };
        assert_eq!(
            memory.arena_memory().map(|arena| arena.arena),
            Some(id.as_ptr()),
            "the real source page resolves to the installed external owner",
        );
        let owner = unsafe { backing.allocation_for_arena(&*id.as_ptr()) }
            .expect("the installed external arena retains its terminal owner");
        assert!(matches!(&owner.allocation, ArenaBacking::External(_)));
        assert_eq!(
            crate::size_class::page_kind_for_block_size(unsafe { page.as_ref().block_size() }),
            Some(crate::types::PageKind::Medium),
            "the external receiver uses the source medium-page extension shape",
        );
        assert!(unsafe { page.as_ref().slice_pcommitted() } != 0);
        assert!(unsafe { page.as_ref().free_list_head() }.is_null());
        assert!(
            trace.commits.load(Ordering::Acquire) > 0,
            "external metadata and the first page prefix use the real callback before it is cleared",
        );

        // Pinned `mi_page_extend_free` calls `_mi_os_commit` directly after
        // that initial callback-backed prefix. Its private Rust receiver must
        // leave the live Page unchanged when the direct commit faults.
        trace.clear_observation();
        let before = process.subprocess().vm_statistics().snapshot();
        let source_capacity = unsafe { page.as_ref().capacity() };
        let source_reserved = unsafe { page.as_ref().reserved() };
        let source_prefix = unsafe { page.as_ref().slice_pcommitted() };
        let source_free = unsafe { page.as_ref().free_list_head() };
        let source_local_free = unsafe { page.as_ref().remote_free_test_local_free() };
        assert!(source_prefix != 0);
        assert!(source_free.is_null());
        assert!(source_local_free.is_null());
        assert!(source_capacity < source_reserved);
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        // SAFETY: `page` came from this active allocator's PageMap and its
        // installed external backing retains it. The isolated session has no
        // concurrent owner or teardown path; the assertions above establish
        // the selected on-demand Page's prefix, exhausted lists, and capacity.
        let failure = !unsafe {
            allocator.test_extend_on_demand_page_before_allocation(page)
        };
        let failed = process.subprocess().vm_statistics().snapshot();
        let failure_consumes_direct_fault_without_callback = failure
            && failed.commit_calls == before.commit_calls + 1
            && failed.committed_current == before.committed_current
            && fault.observed() == 1
            && trace.commits.load(Ordering::Acquire) == 0;
        let failure_preserves_unpublished_page_area =
            unsafe { page.as_ref().capacity() } == source_capacity
                && unsafe { page.as_ref().slice_pcommitted() } == source_prefix
                && unsafe { page.as_ref().free_list_head() } == source_free;

        fault.set(fault::Plan::disabled());
        // SAFETY: the failed direct commit left this same live Page's
        // capacity, prefix, and free list unchanged, as asserted above; its
        // active allocator, PageMap publication, and external backing remain.
        let retry = unsafe {
            allocator.test_extend_on_demand_page_before_allocation(page)
        };
        let retried = process.subprocess().vm_statistics().snapshot();
        let retry_prefix = unsafe { page.as_ref().slice_pcommitted() };
        let requested_direct_commit = usize::from(
            retry_prefix.checked_sub(source_prefix)
                .expect("a successful source extension advances its committed prefix"),
        )
            * config().page_size().bytes();
        let retry_commits_directly_without_callback = retry
            && retried.commit_calls == before.commit_calls + 2
            && retried.committed_current
                == before.committed_current + requested_direct_commit as i64
            && unsafe { page.as_ref().capacity() } > source_capacity
            && retry_prefix > source_prefix
            && !unsafe { page.as_ref().free_list_head() }.is_null()
            && trace.commits.load(Ordering::Acquire) == 0;
        let reused = allocator
            .allocate(request, false)
            .expect("the refilled external page supplies its ordinary retry allocation");
        let retry_reuses_same_page = unsafe { allocator.page_for_block(reused) } == page.as_ptr();
        unsafe {
            allocator.free(first).expect("the first external page block remains freeable");
            allocator.free(reused).expect("the retried external page block remains freeable");
        }
        assert!(allocator.finish().is_ok(), "the external page fixture quiesces its source page");
        unsafe { page_map.destroy() }
            .expect("the quiesced isolated page map releases its owned mapping");

        [
            usize::from(failure_consumes_direct_fault_without_callback),
            usize::from(failure_preserves_unpublished_page_area),
            usize::from(retry_commits_directly_without_callback && retry_reuses_same_page),
        ]
    }

    #[test]
    fn external_page_extension_bypasses_callback_and_retries_the_direct_process_commit() {
        let fault = fault::install(fault::Plan::disabled());
        assert_eq!(m2_external_page_extension_trace(&fault), [1; 3]);
    }

    #[test]
    fn external_direct_page_area_rejects_an_out_of_range_span_before_commit() {
        let fault = fault::install(fault::Plan::disabled());
        let process = process();
        let backing = backing();
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (lease, _) = external_lease(process, ARENA_MIN_SIZE, false, false, trace);
        let id = install_external(backing, process, ARENA_MIN_SIZE, lease).arena_id();
        let claim = unsafe {
            backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, false)
        }
        .expect("the external arena supplies one uncommitted page-area span");
        let page = config().page_size().bytes();
        trace.clear_observation();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        let before_invalid = process.subprocess().vm_statistics().snapshot();
        let invalid = unsafe {
            backing.commit_page_area(claim.memory_id(), ARENA_SLICE_SIZE, page)
        };
        let invalid_area_rejected_before_commit = invalid == Err(ArenaPageCommitError::InvalidPageArea)
            && process.subprocess().vm_statistics().snapshot() == before_invalid
            && fault.observed() == 0
            && trace.commits.load(Ordering::Acquire) == 0;
        fault.set(fault::Plan::disabled());
        assert!(invalid_area_rejected_before_commit && claim.release());
    }

    #[test]
    fn external_callback_owner_keeps_the_source_alignment_prefix_numa_and_null_metadata_zero() {
        let _fault = fault::install(fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaIsNumaLocal, 1);
        let process = process_with_options(options);
        let backing = backing();
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let page = config().page_size().bytes();
        let storage = external_storage(process, 2 * ARENA_ALIGNMENT + page);
        let raw_base = unsafe { storage.add(page) };
        let prefix = (ARENA_ALIGNMENT - (raw_base as usize % ARENA_ALIGNMENT)) % ARENA_ALIGNMENT;
        assert_ne!(prefix, 0, "the fixture passes the source an unaligned external base");
        // `mi_manage_os_memory_ex2` rejects a nonzero prefix unless the
        // remaining source span is at least one arena-alignment unit, before
        // its later minimum-arena calculation.
        let raw_size = prefix + ARENA_ALIGNMENT;
        let lease = unsafe {
            ProcessExternalArenaLease::new(
                raw_base,
                raw_size,
                false,
                false,
                false,
                CommitHook::new(
                    external_transition_callback,
                    core::ptr::from_ref(trace).cast_mut().cast(),
                ),
            )
        }
        .expect("the external source span is non-null");
        let plan = ExternalArenaPlan::from_address(raw_base as usize, raw_size)
            .unwrap_or_else(|| panic!(
                "the source aligns this prefix into one full arena: base={:#x}, prefix={}, size={}, alignment={}, minimum={}",
                raw_base as usize, prefix, raw_size, ARENA_ALIGNMENT, ARENA_MIN_SIZE,
            ));
        let managed = unsafe {
            backing.install_owned_external_callback_arena(
                process,
                config(),
                raw_size,
                lease,
                -1,
                false,
            )
        }
        .unwrap_or_else(|failure| {
            panic!("an unaligned external range follows mi_manage_memory's prefix plan: {:?}",
                failure.error())
        });
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }
            .expect("the aligned parent arena is published");
        let arena = view.arena();
        assert_eq!(arena.start as usize, plan.aligned_address());
        assert_eq!(managed.total_size(), plan.total_size());
        assert_eq!(arena.memid.os_memory().unwrap().base, raw_base);
        assert_eq!(arena.memid.os_memory().unwrap().size, raw_size);
        assert_eq!(arena.numa_node, process.current_numa_node() as i32);
        assert!(trace.commits.load(Ordering::Acquire) >= 1);
        assert!(!trace.commit_zero_is_non_null.load(Ordering::Acquire),
            "source metadata commit supplies a null zero result pointer");
    }

    fn externally_commit_range(
        backing: &'static ProcessArenaBacking,
        id: ArenaId,
        claim: &ArenaSliceClaim<'_>,
        committed_slices: usize,
    ) {
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
        let owner = unsafe { backing.allocation_for_arena(view.arena()) }.unwrap();
        assert!(owner
            .commit_with_outcome(claim.start(), committed_slices * ARENA_SLICE_SIZE, 0)
            .succeeded());
        unsafe { view.slices_committed() }
            .unwrap()
            .set_range(claim.slice_index(), committed_slices)
            .unwrap();
    }

    #[test]
    fn external_callback_purge_uses_raw_span_and_tracks_all_true_and_mixed_recommit_bits() {
        let _fault = fault::install(fault::Plan::disabled());
        for (committed_slices, needs_recommit) in [(2usize, false), (2, true), (1, false)] {
            let process = purge_process(0, false);
            let backing = backing();
            let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
            // Keep the arena's full bitmap initially clear. Its setup callback
            // commits only metadata; the selected free span then records the
            // exact all-true or mixed bitmap state below.
            let (lease, _) = external_lease(process, ARENA_MIN_SIZE, false, false, trace);
            let id = install_external(backing, process, ARENA_MIN_SIZE, lease).arena_id();
            let claim = unsafe {
                backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, false)
            }
            .unwrap();
            let start = claim.slice_index();
            externally_commit_range(backing, id, &claim, committed_slices);
            trace.purge_needs_recommit.store(needs_recommit, Ordering::Release);
            trace.clear_observation();
            let before = process.subprocess().vm_statistics().snapshot();
            assert!(claim.release());
            let after = process.subprocess().vm_statistics().snapshot();
            assert_eq!(trace.purges.load(Ordering::Acquire), 1);
            assert!(trace.purge_zero_is_null.load(Ordering::Acquire));
            assert_eq!(trace.last_size.load(Ordering::Acquire), 2 * ARENA_SLICE_SIZE);
            assert_eq!(after.purge_calls, before.purge_calls + 1);
            assert_eq!(after.purged, before.purged + (2 * ARENA_SLICE_SIZE) as i64);
            let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
            let committed = unsafe { view.slices_committed() }
                .unwrap()
                .popcount_range(start, 2)
                .unwrap();
            let must_clear = needs_recommit || committed_slices != 2;
            assert_eq!(committed, if must_clear { 0 } else { 2 });

            trace.clear_observation();
            let retry = unsafe {
                backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true)
            }
            .unwrap();
            assert_eq!(retry.slice_index(), start);
            assert_eq!(trace.commits.load(Ordering::Acquire), usize::from(must_clear));
            if must_clear {
                assert_eq!(trace.last_start.load(Ordering::Acquire), retry.start() as usize);
                assert_eq!(trace.last_size.load(Ordering::Acquire), 2 * ARENA_SLICE_SIZE);
            }
        }
    }

    #[test]
    fn external_callback_negative_delay_skips_callback_and_statistics_before_normal_policy() {
        let _fault = fault::install(fault::Plan::disabled());
        let process = purge_process(-1, false);
        let backing = backing();
        let trace = Box::leak(Box::new(ExternalCallbackTrace::new()));
        let (lease, _) = external_lease(process, ARENA_MIN_SIZE, true, false, trace);
        let id = install_external(backing, process, ARENA_MIN_SIZE, lease).arena_id();
        let claim = unsafe {
            backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, false)
        }
        .unwrap();
        externally_commit_range(backing, id, &claim, 2);
        trace.clear_observation();
        let before = process.subprocess().vm_statistics().snapshot();
        assert!(claim.release());
        assert_eq!(trace.purges.load(Ordering::Acquire), 0);
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
    }

    #[test]
    fn huge_backing_shares_the_regular_registry_and_preserves_multi_arena_provenance() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let regular = install(backing, process, MapAccess::Committed);
        let huge = crate::os::HugeOsAllocation::test_registry_allocation(process, config(), 17);
        let memory = huge.memory_id();
        let managed = unsafe { backing.install_owned_huge_allocation(config(), huge, -1, false) }
            .unwrap_or_else(|failure| panic!("huge install: {:?}", failure.error()));
        assert!(managed.is_complete());
        assert_eq!(managed.managed_size(), 17 * crate::config::GIB);
        assert_eq!(backing.registry().count(), 3);
        let parent = unsafe { &*managed.arena_id().as_ptr() };
        assert_eq!(parent.memid.kind(), MemoryKind::OsHuge);
        assert_eq!(parent.memid.os_memory().unwrap().base, memory.os_memory().unwrap().base);
        let child = unsafe { backing.registry().arena_at(2) }.unwrap();
        assert_eq!(child.parent, managed.arena_id().as_ptr());
        assert_eq!(child.memid.kind(), MemoryKind::None);
        assert!(child.memid.is_pinned());
        assert!(unsafe { backing.allocation_for_arena(child) }.is_some());
        assert!(unsafe { backing.allocation_for_arena(&*regular.as_ptr()) }.is_some());
        let before = process.subprocess().vm_statistics().snapshot();
        let mut select = search(managed.arena_id());
        assert!(unsafe { backing.try_find_free(select, 1, 1, true) }.is_none());
        select.allow_pinned = true;
        let claim = unsafe { backing.try_find_free(select, 1, 1, true) }.unwrap();
        assert!(claim.memory_id().is_pinned());
        assert!(claim.release());
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.commit_calls, before.commit_calls);
        assert_eq!(after.committed_current, before.committed_current);
        let values = [backing.registry().count(), managed.managed_size() / crate::config::GIB,
            usize::from(parent.memid.kind() == MemoryKind::OsHuge),
            usize::from(child.parent == managed.arena_id().as_ptr()),
            usize::from(child.memid.kind() == MemoryKind::None), usize::from(child.memid.is_pinned()),
            (after.commit_calls - before.commit_calls) as usize,
            (after.committed_current - before.committed_current) as usize];
        for (index, value) in values.into_iter().enumerate() {
            std::println!("m2.huge.registry.{index}={value}");
        }
    }

    #[test]
    fn huge_registry_partial_publication_keeps_the_complete_primitive_owner() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let regular = install(backing, process, MapAccess::Committed);
        // Fill the isolated registry with already-live sentinels, leaving one
        // source slot. The test never searches these synthetic entries.
        for slot in &backing.registry.arenas[..MAX_ARENAS - 1] {
            slot.store(regular.as_ptr(), Ordering::Relaxed);
        }
        backing.registry.count.store(MAX_ARENAS - 1, Ordering::Relaxed);
        let huge = crate::os::HugeOsAllocation::test_registry_allocation(process, config(), 17);
        let base = huge.base();
        let managed = unsafe { backing.install_owned_huge_allocation(config(), huge, -1, false) }
            .unwrap_or_else(|failure| panic!("partial install: {:?}", failure.error()));
        assert!(!managed.is_complete());
        assert_eq!(managed.managed_size(), ARENA_MAX_SIZE);
        let parent = unsafe { &*managed.arena_id().as_ptr() };
        assert_eq!(parent.total_size, ARENA_MAX_SIZE);
        let owner = unsafe { backing.allocation_for_arena(parent) }.unwrap();
        let ArenaBacking::Huge(allocation) = &owner.allocation else { panic!("huge owner"); };
        assert_eq!(allocation.base(), base);
        assert_eq!(allocation.page_count(), 17, "unpublished suffix remains owned");
        assert_eq!(allocation.memory_id().os_memory().unwrap().size, 17 * crate::config::GIB);
    }

    #[test]
    fn huge_registry_rejection_returns_the_exact_unpublished_owner() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        install(backing, process, MapAccess::Committed);
        let foreign = self::process();
        let huge = crate::os::HugeOsAllocation::test_registry_allocation(foreign, config(), 1);
        let base = huge.base();
        let failure = match unsafe { backing.install_owned_huge_allocation(config(), huge, -1, false) } {
            Err(failure) => failure,
            Ok(_) => panic!("foreign policy must not publish"),
        };
        assert_eq!(failure.error(), ManageArenaError::InvalidRegion);
        let huge = failure.into_allocation();
        assert_eq!(huge.base(), base);
        assert_eq!(huge.page_count(), 1);
        assert_eq!(huge.memory_id().kind(), MemoryKind::OsHuge);
        assert_eq!(backing.registry().count(), 1);
        assert!(huge.release_for_process(&mut [0]).is_ok());
    }

    #[test]
    fn explicit_regular_reservation_preserves_multi_arena_source_spans() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let arena = unsafe { backing.reserve_os_memory_for_process(process, config(),
            17 * crate::config::GIB, MapAccess::Committed, false, false, None) }.unwrap();
        assert_eq!(backing.registry.count(), 2);
        let parent = unsafe { &*arena.as_ptr() };
        let child = unsafe { backing.registry.arena_at(1) }.unwrap();
        assert_eq!(parent.memid.kind(), MemoryKind::Os);
        assert_eq!(parent.total_size, 17 * crate::config::GIB);
        assert_eq!(child.parent, arena.as_ptr());
        assert_eq!(child.memid.kind(), MemoryKind::None);
        assert_eq!(unsafe { backing.allocation_for_arena(child) }.unwrap().allocation.length(),
            Ok(17 * crate::config::GIB));
    }

    #[test]
    fn owned_registry_preserves_requested_arena_extent_and_rounded_mapping_tail() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let requested = 63 * MIB;
        let (mapping, memory) = NormalOsAllocation::allocate_aligned_base_for_process(process,
            config(), requested, ARENA_ALIGNMENT, MapAccess::Reserved, false, None)
            .unwrap().into_mapping_and_memory();
        assert_eq!(mapping.length(), Ok(64 * MIB));
        let managed = match unsafe { backing.install_owned_os_mapping(process, config(), requested,
            mapping, memory, -1, false) } {
            Ok(managed) => managed,
            Err(failure) => std::panic!("requested-size installation: {:?}", failure.error()),
        };
        assert_eq!(managed.managed_size(), ARENA_MIN_SIZE);
        let view = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
        assert_eq!(view.size(), Some(ARENA_MIN_SIZE));
        assert_eq!(view.arena().memid.os_memory().unwrap().size, 64 * MIB);
        let owner = unsafe { backing.allocation_for_arena(view.arena()) }.unwrap();
        assert_eq!(owner.allocation.length(), Ok(64 * MIB));
    }

    #[test]
    fn emit_x86_64_automatic_arena_reservation_trace() {
        // Pinned `mi_arenas_try_alloc` starts with a free-range search, then
        // rejects a clean automatic-reservation miss while OS allocation is
        // disallowed.  These direct private owners deliberately bypass the
        // stopped ticket-zero/bootstrap bridge; the paired C oracle validates
        // the actual initialized Heap/TLD source roots for every worker.
        let _fault = fault::install(fault::Plan::disabled());
        let options = |disallow_os_alloc| {
            let mut options = VmOptions::uninitialized();
            options.initialize_all(|_| VmOptionEnvironment::Absent);
            options.set(VmOption::ArenaReserve, (ARENA_MIN_SIZE / KIB) as i64);
            options.set(VmOption::ArenaEagerCommit, 0);
            options.set(VmOption::DisallowOsAlloc, i64::from(disallow_os_alloc));
            options
        };
        let mut trace: std::vec::Vec<(&str, i64)> = std::vec::Vec::new();

        let disallow_process = process_with_options(options(true));
        let disallow_backing = backing();
        let before = disallow_process.subprocess().arena_statistics().snapshot();
        assert_eq!(disallow_backing.registry().count(), 0);
        assert_eq!(before.arena_count, 0);
        assert!(unsafe {
            disallow_backing.try_allocate_slices(disallow_process, config(), search(ArenaId::none()),
                256, ARENA_SLICE_SIZE, true)
        }.is_none());
        assert_eq!(disallow_backing.registry().count(), 0);
        assert_eq!(disallow_process.subprocess().arena_statistics().snapshot(), before);
        trace.extend([
            ("trace.automatic_arena.disallow.request_owner_inputs_valid", 1),
            ("trace.automatic_arena.disallow.initial_registry_empty", 1),
            ("trace.automatic_arena.disallow.initial_high_water_zero", 1),
            ("trace.automatic_arena.disallow.miss_rejected", 1),
            ("trace.automatic_arena.disallow.registry_unchanged", 1),
            ("trace.automatic_arena.disallow.high_water_unchanged", 1),
        ]);

        let sequential_process = process_with_options(options(false));
        let sequential_backing = backing();
        let before = sequential_process.subprocess().arena_statistics().snapshot();
        let mut claims = std::vec::Vec::new();
        for _ in 0..4 {
            claims.push(unsafe {
                sequential_backing.try_allocate_slices(sequential_process, config(), search(ArenaId::none()),
                    256, ARENA_SLICE_SIZE, true)
            }.expect("four 256-slice claims must reserve two source regular arenas"));
        }
        assert_eq!(sequential_backing.registry().count(), 2);
        assert_eq!(sequential_process.subprocess().arena_statistics().snapshot().arena_count - before.arena_count, 2);
        let first = claims.first().unwrap().memory_id().arena_memory().unwrap();
        let last = claims.last().unwrap().memory_id().arena_memory().unwrap();
        assert_ne!(first.arena, last.arena);
        for (index, claim) in claims.iter().enumerate() {
            for other in claims.iter().skip(index + 1) {
                let memory = claim.memory_id().arena_memory().unwrap();
                let compared = other.memory_id().arena_memory().unwrap();
                assert!(memory.arena != compared.arena
                    || (memory.slice_index as usize + 256 <= compared.slice_index as usize
                        || compared.slice_index as usize + 256 <= memory.slice_index as usize),
                    "same-arena live claims retain disjoint half-open source slice ranges");
            }
        }
        let released: std::vec::Vec<_> = claims.iter().map(|claim| {
            let memory = claim.memory_id().arena_memory().unwrap();
            (unsafe { ArenaId::from_arena(memory.arena) }.unwrap(), memory.slice_index as usize)
        }).collect();
        for claim in claims { assert!(claim.release()); }
        for (arena, start) in released {
            let view = unsafe { ArenaView::from_ptr(arena.as_ptr()) }.unwrap();
            assert_eq!(unsafe { view.slices_free() }.unwrap().is_set_range(start, 256), Some(true));
        }
        trace.extend([
            ("trace.automatic_arena.sequential.request_owner_inputs_valid", 1),
            ("trace.automatic_arena.sequential.four_claims_live", 1),
            ("trace.automatic_arena.sequential.second_arena_created", 1),
            ("trace.automatic_arena.sequential.high_water_delta", 2),
            ("trace.automatic_arena.sequential.first_last_arena_distinct", 1),
            ("trace.automatic_arena.sequential.ranges_distinct", 1),
            ("trace.automatic_arena.sequential.released_ranges_free", 1),
        ]);

        // This private fixture supplies distinct `ArenaSearch` inputs and
        // never manufactures a Rust Heap/TLD; C proves those physical roots.
        // It installs one private regular owner, retains every range returned
        // by the real source-shaped existing-arena search, and makes every
        // worker observe that exhaustion before actual `try_allocate_slices`
        // calls. The paired C setup reaches the equivalent state after its
        // worker TLD/Theap metadata allocation. The gates retain all new
        // claims for the parent observation but do not claim a simultaneous
        // internal reserve-lock miss or lock coalescing. The source's
        // unchanged-count check under `arena_reserve_lock` serializes
        // reservation without making it unique: a worker whose search missed
        // before another's publication, but whose count read follows it,
        // reserves again. Only interleaving-independent relations are
        // recorded: one to eight fresh arenas, statistics that agree with
        // the registry, and every claim in a fresh arena.
        let concurrent_process = process_with_options(options(false));
        let shared: &'static ProcessArenaBacking = backing();
        let existing = install(shared, concurrent_process, MapAccess::Reserved);
        assert_eq!(shared.registry().count(), 1);
        assert_eq!(concurrent_process.subprocess().arena_statistics().snapshot().arena_count, 1);
        let mut fillers = std::vec::Vec::new();
        let mut filler_ranges = std::vec::Vec::new();
        while let Some(claim) = unsafe {
            shared.try_find_free(search(ArenaId::none()), 1, ARENA_SLICE_SIZE, true)
        } {
            let memory = claim.memory_id().arena_memory().unwrap();
            assert_eq!(memory.arena, existing.as_ptr());
            filler_ranges.push(memory.slice_index as usize);
            fillers.push(claim);
            assert!(fillers.len() < 2048, "source regular arena geometry must be finite");
        }
        assert!(!fillers.is_empty());
        assert!(unsafe {
            shared.try_find_free(search(ArenaId::none()), 1, ARENA_SLICE_SIZE, true)
        }.is_none());
        let before = concurrent_process.subprocess().arena_statistics().snapshot();
        let inputs_ready = std::sync::Arc::new(std::sync::Barrier::new(8));
        let calls_start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let claims_ready = std::sync::Arc::new(std::sync::Barrier::new(9));
        let releases_start = std::sync::Arc::new(std::sync::Barrier::new(9));
        let mut workers = std::vec::Vec::new();
        for worker in 0..8 {
            let inputs_ready = inputs_ready.clone();
            let calls_start = calls_start.clone();
            let claims_ready = claims_ready.clone();
            let releases_start = releases_start.clone();
            workers.push(std::thread::spawn(move || {
                let source_input = ArenaSearch {
                    heap_sequence: 0,
                    heap_count: 1,
                    thread_sequence: worker,
                    numa_node: -1,
                    requested: ArenaId::none(),
                    allow_pinned: false,
                };
                inputs_ready.wait();
                let preclaim_miss = unsafe {
                    shared.try_find_free(source_input, 1, ARENA_SLICE_SIZE, true)
                }.is_none();
                calls_start.wait();
                let claim = unsafe {
                    shared.try_allocate_slices(concurrent_process, config(), source_input,
                        1, ARENA_SLICE_SIZE, true)
                }.expect("exhausted existing arena forces one source-shaped reservation");
                let memory = claim.memory_id().arena_memory().unwrap();
                claims_ready.wait();
                releases_start.wait();
                assert!(claim.release());
                (preclaim_miss, memory.arena as usize, memory.slice_index as usize)
            }));
        }
        claims_ready.wait();
        let workers: std::vec::Vec<_> = workers;
        let fresh = shared.registry().count() - 1;
        assert!((1..=8).contains(&fresh), "one to eight fresh arenas, got {fresh}");
        assert_eq!(concurrent_process.subprocess().arena_statistics().snapshot().arena_count
            - before.arena_count, fresh as _);
        let fresh_arenas: std::vec::Vec<usize> = (1..=fresh)
            .map(|index| unsafe { shared.registry().arena_at(index) }.unwrap() as *const Arena as usize)
            .collect();
        releases_start.wait();
        let workers: std::vec::Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert!(workers.iter().all(|worker| worker.0));
        assert!(workers.iter().all(|worker| fresh_arenas.contains(&worker.1)
            && worker.1 != existing.as_ptr() as usize), "every claim lies in a fresh arena");
        for (index, worker) in workers.iter().enumerate() {
            assert!(workers.iter().skip(index + 1).all(|other| {
                worker.1 != other.1 || worker.2 + 1 <= other.2 || other.2 + 1 <= worker.2
            }), "new-arena live claims retain disjoint half-open source slice ranges");
        }
        for (_, arena, start) in &workers {
            let new_view = unsafe { ArenaView::from_ptr(*arena as *mut Arena) }.unwrap();
            assert_eq!(unsafe { new_view.slices_free() }.unwrap().is_set_range(*start, 1), Some(true));
        }
        for filler in fillers { assert!(filler.release()); }
        let existing_view = unsafe { ArenaView::from_ptr(existing.as_ptr()) }.unwrap();
        for start in filler_ranges {
            assert_eq!(unsafe { existing_view.slices_free() }.unwrap().is_set_range(start, 1), Some(true));
        }
        trace.extend([
            ("trace.automatic_arena.concurrent.workers_ready_with_distinct_request_inputs", 8),
            ("trace.automatic_arena.concurrent.workers_observed_exhausted_existing_ranges", 1),
            ("trace.automatic_arena.concurrent.eight_new_arena_claims_live", 1),
            ("trace.automatic_arena.concurrent.one_to_eight_fresh_arenas_reserved", 1),
            ("trace.automatic_arena.concurrent.claims_in_fresh_arenas", 1),
            ("trace.automatic_arena.concurrent.new_ranges_distinct", 1),
            ("trace.automatic_arena.concurrent.retained_live_ranges_released", 1),
            ("trace.automatic_arena.concurrent.released_ranges_free", 1),
            ("trace.automatic_arena.valid", 1),
        ]);
        std::println!("CRABC_MI_AUTOMATIC_ARENA_RESERVATION_TRACE_BEGIN");
        for (key, value) in trace { std::println!("{key}={value}"); }
        std::println!("CRABC_MI_AUTOMATIC_ARENA_RESERVATION_TRACE_END");
    }

    #[test]
    fn automatic_reservation_outgrows_its_first_arena_and_serializes_concurrent_first_use() {
        let _fault = fault::install(fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaReserve, (ARENA_MIN_SIZE / KIB) as i64);
        options.set(VmOption::ArenaEagerCommit, 0);
        let process = process_with_options(options);
        let backing = backing();
        let mut claims = std::vec::Vec::new();
        for _ in 0..4 {
            claims.push(unsafe { backing.try_allocate_slices(process, config(), search(ArenaId::none()),
                256, ARENA_SLICE_SIZE, true) }.unwrap());
        }
        assert_eq!(backing.registry().count(), 2);
        assert_ne!(claims[0].memory_id().arena_memory().unwrap().arena,
            claims[3].memory_id().arena_memory().unwrap().arena);
        for claim in claims { assert!(claim.release()); }

        let concurrent = Box::leak(Box::new(ProcessArenaBacking::new()));
        let concurrent_process = VmProcess::new(process.policy(), MainSubprocess::test_static_owner());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut threads = std::vec::Vec::new();
        let shared: &'static ProcessArenaBacking = concurrent;
        for _ in 0..8 {
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let claim = unsafe { shared.try_allocate_slices(concurrent_process, config(),
                    search(ArenaId::none()), 1, ARENA_SLICE_SIZE, true) }.unwrap();
                barrier.wait();
                assert!(claim.release());
            }));
        }
        for thread in threads { thread.join().unwrap(); }
        assert_eq!(shared.registry().count(), 1);
    }

    /// Source `mi_arena_reserve`/`mi_reserve_os_memory_ex2`: a failed primary
    /// metadata commit whose cleanup `_mi_os_free_ex` `munmap` also fails is
    /// counted and leaked, and the source 128-MiB fallback is still tried and
    /// reserves the arena.
    #[test]
    fn failed_reservation_cleanup_leaks_once_and_the_fallback_still_reserves() {
        let fault = fault::install(fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaEagerCommit, 0);
        let process = process_with_options(options);
        let backing = backing();
        let before = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at_pair(fault::Point::Commit, 1, fault::Point::Unmap, 1, Errno::NOMEM));
        let capture = fault.capture_unmap_ranges();
        let claim = unsafe { backing.try_allocate_slices(process, config(), search(ArenaId::none()),
            1, ARENA_SLICE_SIZE, true) }.expect("the source fallback reserves after the leaked primary");
        let (ranges, count) = capture.all().expect("bounded releases");
        drop(capture);
        // The first release after the failed commit is the injected one;
        // the fallback reservation's own trims may follow it.
        assert!(fault.secondary_observed() >= 1, "the primary cleanup release failed");
        fault.set(fault::Plan::disabled());
        assert_eq!(backing.registry().count(), 1);
        let arena = unsafe { backing.registry().arena_at(0) }.unwrap();
        let published = arena.memid.os_memory().unwrap().size;
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.reserved_current - before.reserved_current, published as i64,
            "the leaked primary's reservation was still subtracted");
        // The failed cleanup is the only whole-primary release recorded.
        let (leaked, leaked_length) = ranges[..count].iter().copied()
            .max_by_key(|&(_, length)| length).expect("the primary cleanup was recorded");
        assert!(leaked_length > published, "the leaked range is the larger primary");
        assert!(claim.release());
        // SAFETY: the leaked primary mapping is represented by no owner.
        unsafe { crabc_core::mm::munmap_raw(leaked as *mut u8, leaked_length) }
            .expect("fixture teardown of the leaked primary");
    }

    #[test]
    fn owned_registry_retains_two_mappings_and_rejects_a_foreign_process_pair() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let first = install(backing, process, MapAccess::Reserved);
        let second = install(backing, process, MapAccess::Reserved);
        assert_ne!(first, second);
        assert_eq!(backing.registry().count(), 2);
        for id in [first, second] {
            let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
            assert_eq!(claim.memory_id().arena_memory().unwrap().arena, id.as_ptr());
            assert!(claim.memory_id().initially_committed());
            unsafe { claim.start().write(0x6d); }
            assert_eq!(unsafe { claim.start().read() }, 0x6d);
            assert!(claim.release());
        }
        let foreign = VmProcess::new(process.policy(), MainSubprocess::test_static_owner());
        let (mapping, memory) = mapped(foreign, MapAccess::Reserved);
        let original = mapping.base().unwrap();
        let failure = match unsafe { backing.install_owned_os_mapping(foreign, config(), ARENA_MIN_SIZE, mapping, memory, -1, false) } {
            Ok(_) => std::panic!("foreign pair was published"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), ManageArenaError::InvalidRegion);
        let (mut mapping, returned, pair) = failure.into_parts();
        assert_eq!(mapping.base().unwrap(), original);
        assert_eq!(returned.os_memory().unwrap().base, original);
        assert!(core::ptr::eq(pair.subprocess(), foreign.subprocess()));
        mapping.unmap_for_process(pair, 0, false).unwrap();
        assert_eq!(backing.registry().count(), 2);
    }

    #[test]
    fn live_arena_lookup_does_not_borrow_an_unrelated_initializing_mapping_slot() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let first = install(backing, process, MapAccess::Reserved);
        let second = install(backing, process, MapAccess::Reserved);
        let view = unsafe { ArenaView::from_ptr(second.as_ptr()) }.unwrap();
        let slot = &backing.slots[0];
        let _guard = backing.reserve_lock.lock().unwrap();
        // Model an unrelated prepublication slot ahead of the live target.
        // Its fully written value stays stable in this isolated witness, so
        // the old bug is observed as a forbidden borrow without executing a
        // Rust data race or moving bytes underneath an actual reference.
        // The lock also proves that the successful hot lookup must not take
        // a global lock just because an unrelated slot is initializing.
        assert_eq!(unsafe { slot.initialized() }.unwrap().memory.os_memory().unwrap().base,
            unsafe { first.area() }.unwrap().0);
        let before = slot.initializing_reads.load(Ordering::Relaxed);
        slot.state.store(INITIALIZING, Ordering::Release);
        let found = unsafe { backing.allocation_for_arena(view.arena()) };
        slot.state.store(PUBLISHED, Ordering::Release);
        assert!(found.is_some());
        assert_eq!(slot.initializing_reads.load(Ordering::Relaxed), before,
            "the target publication never authorizes borrowing another initializing slot");
    }

    #[test]
    fn target_arena_publication_window_rechecks_under_reserve_lock_before_borrowing() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let id = install(backing, process, MapAccess::Reserved);
        let address = id.as_ptr() as usize;
        let expected_base = unsafe { id.area() }.unwrap().0 as usize;
        let slot = &backing.slots[0];
        let guard = backing.reserve_lock.lock().unwrap();
        let before = slot.initializing_reads.load(Ordering::Relaxed);
        // Represent the actual source publication window: arena metadata is
        // already visible, but its publisher still owns the reserve lock and
        // has not made the mapping slot immutable for general readers.
        slot.state.store(INITIALIZING, Ordering::Release);
        let reader = std::thread::spawn(move || {
            let arena = unsafe { &*(address as *const Arena) };
            unsafe { backing.allocation_for_arena(arena) }.map(|owner| owner.allocation.base().unwrap() as usize)
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !backing.reserve_lock.test_is_contended() {
            assert!(std::time::Instant::now() < deadline, "publication miss must synchronize with its publisher");
            std::thread::yield_now();
        }
        assert_eq!(slot.initializing_reads.load(Ordering::Relaxed), before);
        slot.state.store(PUBLISHED, Ordering::Release);
        guard.unlock().unwrap();
        assert_eq!(reader.join().unwrap(), Some(expected_base));
        assert_eq!(slot.initializing_reads.load(Ordering::Relaxed), before);
    }

    fn purge_process(delay: i64, decommit: bool) -> VmProcess<'static> {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::PurgeDelay, delay);
        options.set(VmOption::PurgeDecommits, i64::from(decommit));
        process_with_options(options)
    }

    #[test]
    fn clock_failure_uses_source_fallback_for_process_arena_purge() {
        let fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = purge_process(100_000, true);
        let id = install(backing, process, MapAccess::Reserved);
        let claim = unsafe { backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, true) }.unwrap();
        let start = claim.slice_index();
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();

        fault.set(fault::Plan::at(fault::Point::Clock, 1, Errno::NOMEM));
        assert!(claim.release());
        assert_eq!(fault.observed(), 1);
        assert_eq!(unsafe { view.slices_purge() }.unwrap().is_set_range(start, 1), Some(true));
        assert!(crate::atomic::i64_load_relaxed(&view.arena().purge_expire) > 0);
        assert!(crate::atomic::i64_load_relaxed(&backing.purge_expire) > 0);

        crate::atomic::i64_store_release(&view.arena().purge_expire, -1);
        crate::atomic::i64_store_release(&backing.purge_expire, -1);
        let before_purges = process.subprocess().arena_statistics().snapshot().arena_purges;
        fault.set(fault::Plan::at(fault::Point::Clock, 1, Errno::NOMEM));
        assert!(unsafe { backing.collect_purge(process, config(), false, true, 0) });
        assert_eq!(fault.observed(), 1);
        assert_eq!(unsafe { view.slices_purge() }.unwrap().is_clear_range(start, 1), Some(true));
        assert_eq!(unsafe { view.slices_free() }.unwrap().is_set_range(start, 1), Some(true));
        assert_eq!(process.subprocess().arena_statistics().snapshot().arena_purges, before_purges + 1);
    }

    #[test]
    fn source_purge_guard_excludes_collection_without_losing_scheduled_work() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let id = install(backing, process, MapAccess::Reserved);
        let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
        assert!(claim.release());
        let before = process.subprocess().vm_statistics().snapshot();
        let before_arena_events = process.subprocess().arena_statistics().snapshot();
        let guard = crate::atomic::try_atomic_guard(&purge::PURGE_GUARD).unwrap();
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
        assert_eq!(process.subprocess().arena_statistics().snapshot(), before_arena_events,
            "the nonblocking source purge guard prevents the post-expiry counter update");
        drop(guard);
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        assert_eq!(process.subprocess().vm_statistics().snapshot().purge_calls, before.purge_calls + 1);
        assert_eq!(process.subprocess().arena_statistics().snapshot().arena_purges,
            before_arena_events.arena_purges + 1,
            "src/arena.c increments immediately after it clears an eligible expiry");
    }

    #[test]
    fn source_purge_rotation_budget_and_expiration_follow_the_registry_snapshot() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = purge_process(100_000, true);
        let mut arenas = std::vec::Vec::new();
        for _ in 0..3 {
            let id = install(backing, process, MapAccess::Reserved);
            arenas.push(id);
            let claim = unsafe { backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, true) }.unwrap();
            assert!(claim.release());
        }
        let expiry = |id: ArenaId| crate::atomic::i64_load_relaxed(unsafe { &(*id.as_ptr()).purge_expire });
        let before = process.subprocess().vm_statistics().snapshot();
        assert!(unsafe { backing.collect_purge(process, config(), false, false, 1) });
        assert!(unsafe { backing.collect_purge(process, config(), false, true, 1) });
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
        assert!(unsafe { backing.collect_purge(process, config(), true, false, 1) });
        assert_eq!(expiry(arenas[1]), 0);
        assert!(expiry(arenas[0]) > 0 && expiry(arenas[2]) > 0);
        assert_eq!(process.subprocess().arena_statistics().snapshot().arena_purges, 1);
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 2) });
        assert!(arenas.iter().all(|id| expiry(*id) == 0));
        assert_eq!(process.subprocess().arena_statistics().snapshot().arena_purges, 3);
        assert!(crate::atomic::i64_load_relaxed(&backing.purge_expire) > 0);
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        assert_eq!(crate::atomic::i64_load_relaxed(&backing.purge_expire), 0);
    }

    #[test]
    fn source_minimal_purge_windows_preserve_partial_bits_until_a_later_release() {
        let _fault = fault::install(fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::MinimalPurgeSize, (2 * ARENA_SLICE_SIZE / KIB) as i64);
        let process = process_with_options(options);
        let backing = backing();
        let id = install(backing, process, MapAccess::Reserved);
        let mut claims = std::vec::Vec::new();
        for _ in 0..3 {
            claims.push(unsafe { backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, true) }.unwrap());
        }
        claims.sort_by_key(|claim| claim.slice_index());
        let selected = if claims[0].slice_index() % 2 == 0 { 0 } else { 1 };
        let first = claims.remove(selected);
        let second = claims.remove(selected);
        let start = first.slice_index();
        assert_eq!(second.slice_index(), start + 1);
        assert_eq!(start % 2, 0);
        let before = process.subprocess().vm_statistics().snapshot();
        assert!(first.release());
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        assert_eq!(process.subprocess().vm_statistics().snapshot().purge_calls, before.purge_calls);
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
        assert_eq!(unsafe { view.slices_purge() }.unwrap().is_set_range(start, 1), Some(true));
        assert_eq!(crate::atomic::i64_load_relaxed(&view.arena().purge_expire), 0);
        assert!(second.release());
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.purge_calls - before.purge_calls, 1);
        assert_eq!(after.purged - before.purged, (2 * ARENA_SLICE_SIZE) as i64);
        assert_eq!(unsafe { view.slices_purge() }.unwrap().is_clear_range(start, 2), Some(true));
        for claim in claims { assert!(claim.release()); }
    }

    #[test]
    fn source_purge_consumes_advisory_failure_and_never_discards_reallocated_slices() {
        let fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let id = install(backing, process, MapAccess::Reserved);
        let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
        let start = claim.slice_index();
        assert!(claim.release());
        let live = unsafe { backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, true) }.unwrap();
        assert_eq!(live.slice_index(), start);
        unsafe { live.start().write(0x7b); }
        let before = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.purge_calls - before.purge_calls, 1);
        assert_eq!(after.purged - before.purged, ARENA_SLICE_SIZE as i64);
        assert_eq!(unsafe { live.start().read() }, 0x7b);
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
        assert_eq!(unsafe { view.slices_purge() }.unwrap().is_clear_range(start, 2), Some(true));
        assert_eq!(crate::atomic::i64_load_relaxed(&view.arena().purge_expire), 0);
        fault.set(fault::Plan::disabled());
        assert!(live.release());
    }

    #[test]
    fn source_disabled_and_preloading_purge_leave_no_scheduled_bits() {
        let _fault = fault::install(fault::Plan::disabled());
        for preloading in [false, true] {
            let process = if preloading {
                let mut options = VmOptions::uninitialized();
                options.initialize_all(|_| VmOptionEnvironment::Absent);
                let policy = Box::leak(Box::new(VmPolicy::new(options).unwrap()));
                VmProcess::new(policy, MainSubprocess::test_static_owner())
            } else { purge_process(-1, true) };
            let backing = backing();
            let id = install(backing, process, MapAccess::Reserved);
            let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
            let start = claim.slice_index();
            let before = process.subprocess().vm_statistics().snapshot();
            assert!(claim.release());
            assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
            assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
            let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
            assert_eq!(unsafe { view.slices_purge() }.unwrap().is_clear_range(start, 2), Some(true));
            assert_eq!(crate::atomic::i64_load_relaxed(&backing.purge_expire), 0);
        }
    }

    #[test]
    fn emit_native_owned_arena_purge_trace() {
        let _fault = fault::install(fault::Plan::disabled());
        let mut field = 0;
        for (delay, decommit, mixed) in [(0, true, false), (0, false, false),
            (0, false, true), (1000, true, false)] {
            let process = purge_process(delay, decommit);
            let backing = backing();
            let before_registry_events = process.subprocess().statistics().snapshot().arena;
            let id = install(backing, process, MapAccess::Reserved);
            let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, !mixed) }.unwrap();
            let start = claim.slice_index();
            let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
            if mixed {
                let owner = unsafe { backing.allocation_for_arena(view.arena()) }.unwrap();
                assert!(owner.commit(claim.start(), ARENA_SLICE_SIZE, 0));
                unsafe { view.slices_committed() }.unwrap().set_range(start, 1).unwrap();
            }
            let before = process.subprocess().statistics().snapshot().vm;
            let before_purge_events = process.subprocess().statistics().snapshot().arena;
            assert!(claim.release());
            assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
            let after = process.subprocess().statistics().snapshot().vm;
            let after_arena_events = process.subprocess().statistics().snapshot().arena;
            for value in [after.purge_calls - before.purge_calls, after.purged - before.purged,
                after.reset_calls - before.reset_calls, after.reset - before.reset,
                after.committed_current - before.committed_current,
                unsafe { view.slices_committed() }.unwrap().popcount_range(start, 2).unwrap() as i64,
                after_arena_events.arena_purges - before_purge_events.arena_purges,
                after_arena_events.arena_count - before_registry_events.arena_count] {
                std::println!("m2.arena.purge.{field}={value}"); field += 1;
            }
        }

        // This is the exact finite three-regular-arena relation of pinned
        // `mi_arenas_try_purge`: `_mi_arenas_collect` selects a start from
        // the caller's thread sequence, limits ordinary collection to
        // `count / 4 + 1`, visits every arena on request, then clears the
        // subprocess expiry only after a fully visited no-pending pass. The
        // seeded future deadline makes those state transitions independent
        // of scheduler time; emitted values are relations, never clocks.
        let process = purge_process(100_000, true);
        let backing = backing();
        let mut arenas: std::vec::Vec<(ArenaId, usize)> = std::vec::Vec::new();
        for _ in 0..3 {
            let id = install(backing, process, MapAccess::Reserved);
            let claim = unsafe { backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, true) }.unwrap();
            let start = claim.slice_index();
            assert!(claim.release());
            crate::atomic::i64_store_release(
                unsafe { &(*id.as_ptr()).purge_expire }, i64::MAX,
            );
            arenas.push((id, start));
        }
        crate::atomic::i64_store_release(&backing.purge_expire, i64::MAX);
        let registry_count = || backing.registry().count() as i64;
        let expiry_zero_mask = || arenas.iter().enumerate().fold(0i64, |mask, (index, (id, _))| {
            if crate::atomic::i64_load_relaxed(unsafe { &(*id.as_ptr()).purge_expire }) == 0 {
                mask | (1i64 << index)
            } else {
                mask
            }
        });
        let bitmap_mask = |kind| arenas.iter().enumerate().fold(0i64, |mask, (index, (id, start))| {
            let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
            let bit = match kind {
                0 => unsafe { view.slices_free() }.unwrap().is_set_range(*start, 1),
                1 => unsafe { view.slices_committed() }.unwrap().is_set_range(*start, 1),
                _ => unsafe { view.slices_purge() }.unwrap().is_set_range(*start, 1),
            };
            if bit == Some(true) { mask | (1i64 << index) } else { mask }
        });
        let global_state = || {
            let global = crate::atomic::i64_load_relaxed(&backing.purge_expire);
            if global == i64::MAX {
                1
            } else if global == 0 {
                0
            } else {
                assert!(global > 0 && global < i64::MAX);
                2
            }
        };
        assert_eq!(registry_count(), 3);
        assert_eq!(global_state(), 1);
        assert_eq!(expiry_zero_mask(), 0);
        assert_eq!(bitmap_mask(2), 7);
        assert_eq!(bitmap_mask(0), 7);
        assert_eq!(bitmap_mask(1), 7);
        for value in [registry_count(), bitmap_mask(0), bitmap_mask(1)] {
            std::println!("m2.arena.purge.{field}={value}"); field += 1;
        }

        let mut record_stage = |before_arena_purges: i64, before_purge_calls: i64, before_purged: i64| {
            let events = process.subprocess().statistics().snapshot();
            let arena_events = events.arena;
            let vm_events = events.vm;
            for value in [
                arena_events.arena_purges - before_arena_purges,
                vm_events.purge_calls - before_purge_calls,
                vm_events.purged - before_purged,
                registry_count(),
                global_state(),
                expiry_zero_mask(),
                bitmap_mask(2),
                bitmap_mask(0),
                bitmap_mask(1),
            ] {
                std::println!("m2.arena.purge.{field}={value}"); field += 1;
            }
        };

        let before_events = process.subprocess().statistics().snapshot();
        let before_arena = before_events.arena;
        let before_vm = before_events.vm;
        assert!(unsafe { backing.collect_purge(process, config(), false, false, 0) });
        let after_events = process.subprocess().statistics().snapshot();
        let after_arena = after_events.arena;
        let after_vm = after_events.vm;
        assert_eq!(after_arena.arena_purges - before_arena.arena_purges, 0);
        assert_eq!(after_vm.purge_calls - before_vm.purge_calls, 0);
        assert_eq!(after_vm.purged - before_vm.purged, 0);
        assert_eq!(global_state(), 1);
        assert_eq!(expiry_zero_mask(), 0);
        assert_eq!(bitmap_mask(2), 7);
        assert_eq!(bitmap_mask(0), 7);
        assert_eq!(bitmap_mask(1), 7);
        record_stage(before_arena.arena_purges, before_vm.purge_calls, before_vm.purged);

        let before_events = process.subprocess().statistics().snapshot();
        let before_arena = before_events.arena;
        let before_vm = before_events.vm;
        assert!(unsafe { backing.collect_purge(process, config(), false, true, 0) });
        let after_events = process.subprocess().statistics().snapshot();
        let after_arena = after_events.arena;
        let after_vm = after_events.vm;
        assert_eq!(after_arena.arena_purges - before_arena.arena_purges, 0);
        assert_eq!(after_vm.purge_calls - before_vm.purge_calls, 0);
        assert_eq!(after_vm.purged - before_vm.purged, 0);
        assert_eq!(global_state(), 2);
        assert_eq!(expiry_zero_mask(), 0);
        assert_eq!(bitmap_mask(2), 7);
        assert_eq!(bitmap_mask(0), 7);
        assert_eq!(bitmap_mask(1), 7);
        record_stage(before_arena.arena_purges, before_vm.purge_calls, before_vm.purged);

        let before_events = process.subprocess().statistics().snapshot();
        let before_arena = before_events.arena;
        let before_vm = before_events.vm;
        assert!(unsafe { backing.collect_purge(process, config(), true, false, 1) });
        let after_events = process.subprocess().statistics().snapshot();
        let after_arena = after_events.arena;
        let after_vm = after_events.vm;
        assert_eq!(after_arena.arena_purges - before_arena.arena_purges, 1);
        assert!(after_vm.purge_calls - before_vm.purge_calls > 0);
        assert!(after_vm.purged - before_vm.purged > 0);
        assert_eq!(registry_count(), 3);
        assert_eq!(global_state(), 2);
        assert_eq!(expiry_zero_mask(), 2);
        assert_eq!(bitmap_mask(2), 5);
        assert_eq!(bitmap_mask(0), 7);
        // Pinned Linux release MADV_DONTNEED keeps needs_recommit false here.
        assert_eq!(bitmap_mask(1), 7);
        record_stage(before_arena.arena_purges, before_vm.purge_calls, before_vm.purged);

        let before_events = process.subprocess().statistics().snapshot();
        let before_arena = before_events.arena;
        let before_vm = before_events.vm;
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 2) });
        let after_events = process.subprocess().statistics().snapshot();
        let after_arena = after_events.arena;
        let after_vm = after_events.vm;
        assert_eq!(after_arena.arena_purges - before_arena.arena_purges, 2);
        assert!(after_vm.purge_calls - before_vm.purge_calls > 0);
        assert!(after_vm.purged - before_vm.purged > 0);
        assert_eq!(registry_count(), 3);
        assert_eq!(global_state(), 2);
        assert_eq!(expiry_zero_mask(), 7);
        assert_eq!(bitmap_mask(2), 0);
        assert_eq!(bitmap_mask(0), 7);
        assert_eq!(bitmap_mask(1), 7);
        record_stage(before_arena.arena_purges, before_vm.purge_calls, before_vm.purged);

        let before_events = process.subprocess().statistics().snapshot();
        let before_arena = before_events.arena;
        let before_vm = before_events.vm;
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        let after_events = process.subprocess().statistics().snapshot();
        let after_arena = after_events.arena;
        let after_vm = after_events.vm;
        assert_eq!(after_arena.arena_purges - before_arena.arena_purges, 0);
        assert_eq!(after_vm.purge_calls - before_vm.purge_calls, 0);
        assert_eq!(after_vm.purged - before_vm.purged, 0);
        assert_eq!(registry_count(), 3);
        assert_eq!(global_state(), 0);
        assert_eq!(expiry_zero_mask(), 7);
        assert_eq!(bitmap_mask(2), 0);
        assert_eq!(bitmap_mask(0), 7);
        assert_eq!(bitmap_mask(1), 7);
        record_stage(before_arena.arena_purges, before_vm.purge_calls, before_vm.purged);

        // Pinned `mi_arena_try_purge_visitor` first tries to claim the entire
        // scheduled two-slice free range. A new one-slice claim can win that
        // source bitmap race before collection; the visitor must then retry
        // each slice, purge only the remaining free sibling, and atomically
        // consume the original purge range. This uses the regular owner and
        // collector rather than a synthetic bitmap transition.
        let process = purge_process(100_000, true);
        let fallback_backing = Box::leak(Box::new(ProcessArenaBacking::new()));
        let id = install(fallback_backing, process, MapAccess::Reserved);
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
        let claimed = unsafe {
            fallback_backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true)
        }
        .unwrap();
        let start = claimed.slice_index();
        let original = claimed.start();
        assert!(claimed.release());
        let live = unsafe {
            fallback_backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, true)
        }
        .unwrap();
        assert_eq!(live.slice_index(), start);
        assert_eq!(live.start(), original);
        unsafe { live.start().write(0x7b); }
        let range_mask = |kind| {
            (0..2).fold(0i64, |mask, offset| {
                let set = match kind {
                    0 => unsafe { view.slices_free() }.unwrap().is_set_range(start + offset, 1),
                    1 => unsafe { view.slices_purge() }.unwrap().is_set_range(start + offset, 1),
                    _ => unsafe { view.slices_committed() }.unwrap().is_set_range(start + offset, 1),
                };
                if set == Some(true) {
                    mask | (1i64 << offset)
                } else {
                    mask
                }
            })
        };
        let before_free_mask = range_mask(0);
        let before_purge_mask = range_mask(1);
        let before_committed_mask = range_mask(2);
        assert_eq!(before_free_mask, 2);
        assert_eq!(before_purge_mask, 3);
        assert_eq!(before_committed_mask, 3);
        let before_events = process.subprocess().statistics().snapshot();
        let before_vm = before_events.vm;
        let before_arena = before_events.arena;
        assert!(unsafe { fallback_backing.collect_purge(process, config(), true, true, 0) });
        let after_events = process.subprocess().statistics().snapshot();
        let after_vm = after_events.vm;
        let after_arena = after_events.arena;
        assert_eq!(after_vm.purge_calls - before_vm.purge_calls, 1);
        assert_eq!(after_vm.purged - before_vm.purged, ARENA_SLICE_SIZE as i64);
        assert_eq!(after_vm.reset_calls - before_vm.reset_calls, 0);
        assert_eq!(after_vm.reset - before_vm.reset, 0);
        assert_eq!(after_vm.committed_current - before_vm.committed_current, 0);
        assert_eq!(after_arena.arena_purges - before_arena.arena_purges, 1);
        assert_eq!(crate::atomic::i64_load_relaxed(&view.arena().purge_expire), 0);
        let after_free_mask = range_mask(0);
        let after_purge_mask = range_mask(1);
        let after_committed_mask = range_mask(2);
        assert_eq!(after_free_mask, 2);
        assert_eq!(after_purge_mask, 0);
        // Pinned Linux release MADV_DONTNEED reports no recommit requirement.
        assert_eq!(after_committed_mask, 3);
        assert_eq!(unsafe { live.start().read() }, 0x7b);
        for value in [
            i64::from(live.slice_index() == start),
            i64::from(live.start() == original),
            before_free_mask,
            before_purge_mask,
            before_committed_mask,
            after_vm.purge_calls - before_vm.purge_calls,
            after_vm.purged - before_vm.purged,
            after_vm.reset_calls - before_vm.reset_calls,
            after_vm.reset - before_vm.reset,
            after_vm.committed_current - before_vm.committed_current,
            after_arena.arena_purges - before_arena.arena_purges,
            i64::from(crate::atomic::i64_load_relaxed(&view.arena().purge_expire) == 0),
            after_free_mask,
            after_purge_mask,
            after_committed_mask,
            i64::from(unsafe { live.start().read() }),
        ] {
            std::println!("m2.arena.purge.{field}={value}"); field += 1;
        }
        assert!(live.release());
        assert_eq!(range_mask(0), 3);
        assert_eq!(range_mask(1), 1);
        assert!(crate::atomic::i64_load_relaxed(&view.arena().purge_expire) > 0);
        for value in [
            range_mask(0),
            range_mask(1),
            i64::from(crate::atomic::i64_load_relaxed(&view.arena().purge_expire) > 0),
        ] {
            std::println!("m2.arena.purge.{field}={value}"); field += 1;
        }
        assert_eq!(field, 99);
    }

    #[test]
    fn failed_owned_metadata_commit_returns_the_unpublished_allocation() {
        let fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let (mapping, memory) = mapped(process, MapAccess::Reserved);
        let original = mapping.base().unwrap();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        let failure = match unsafe { backing.install_owned_os_mapping(process, config(), ARENA_MIN_SIZE, mapping, memory, -1, false) } {
            Ok(_) => std::panic!("failed metadata commit was published"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), ManageArenaError::CommitFailed);
        assert_eq!(backing.registry().count(), 0);
        assert!(backing.slots.iter().all(|slot| slot.state.load(Ordering::Acquire) == EMPTY));
        let (mut mapping, _, pair) = failure.into_parts();
        assert_eq!(mapping.base().unwrap(), original);
        fault.set(fault::Plan::disabled());
        mapping.unmap_for_process(pair, 0, false).unwrap();
        let id = install(backing, process, MapAccess::Reserved);
        assert!(!id.as_ptr().is_null());
        assert_eq!(backing.registry().count(), 1);
    }

    #[test]
    fn failed_owned_metadata_commit_does_not_resolve_local_numa_policy() {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaIsNumaLocal, 1);
        let process = process_with_options(options);
        let backing = backing();
        let (mapping, memory) = mapped(process, MapAccess::Reserved);
        assert_eq!(process.policy().test_numa_node_count_cache(), 0);

        let fault = fault::install(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        let failure = unsafe {
            backing.install_owned_os_mapping(
                process, config(), ARENA_MIN_SIZE, mapping, memory, -1, false,
            )
        }
        .expect_err("metadata commit must fail before arena publication");
        assert_eq!(failure.error(), ManageArenaError::CommitFailed);
        assert_eq!(fault.observed(), 1);
        assert_eq!(backing.registry().count(), 0);
        assert_eq!(
            process.policy().test_numa_node_count_cache(),
            0,
            "source queries the local node only after metadata is committed",
        );
        fault.set(fault::Plan::disabled());
        let (mut mapping, _, owner) = failure.into_parts();
        mapping.unmap_for_process(owner, 0, false).unwrap();
    }

    #[test]
    fn failed_owned_slice_commit_returns_free_bits_but_retains_dirty_observation() {
        let fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let id = install(backing, process, MapAccess::Reserved);
        let before = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        assert!(unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.is_none());
        let failed = process.subprocess().vm_statistics().snapshot();
        assert_eq!(failed.committed_current, before.committed_current);
        assert_eq!(failed.commit_calls, before.commit_calls + 1);
        fault.set(fault::Plan::disabled());
        let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
        assert!(!claim.memory_id().initially_zero());
        assert!(claim.memory_id().initially_committed());
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.committed_current - before.committed_current, (2 * ARENA_SLICE_SIZE) as i64);
        assert!(claim.release());
    }

    #[test]
    fn owned_linux_decommit_callback_reports_no_recommit_not_syscall_success() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let id = install(backing, process, MapAccess::Reserved);
        let claim = unsafe { backing.try_find_free(search(id), 1, ARENA_SLICE_SIZE, true) }.unwrap();
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
        let arena = view.arena();
        unsafe { claim.start().write(0x5a); }
        let needs_recommit = unsafe { arena.commit_function.unwrap()(false, claim.start(), ARENA_SLICE_SIZE,
            core::ptr::null_mut(), arena.commit_function_argument) };
        assert!(!needs_recommit);
        assert_eq!(unsafe { claim.start().read() }, 0);
        unsafe { claim.start().write(0x3c); }
        assert_eq!(unsafe { claim.start().read() }, 0x3c);
        assert!(claim.release());
    }

    fn emit_claim(index: &mut usize, before: VmStatisticsSnapshot, after: VmStatisticsSnapshot,
        claim: &ArenaSliceClaim<'_>) {
        for value in [after.committed_current - before.committed_current,
            after.committed_total - before.committed_total, after.commit_calls - before.commit_calls,
            i64::from(claim.memory_id().initially_zero()), i64::from(claim.memory_id().initially_committed())] {
            std::println!("m2.arena.owned.{}={value}", *index);
            *index += 1;
        }
    }

    #[test]
    fn emit_native_owned_arena_commit_accounting_trace() {
        let _fault = fault::install(fault::Plan::disabled());
        let mut index = 0;
        let process = process();
        let eager = backing();
        let id = install(eager, process, MapAccess::Committed);
        for _ in 0..2 {
            let before = process.subprocess().vm_statistics().snapshot();
            let claim = unsafe { eager.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
            emit_claim(&mut index, before, process.subprocess().vm_statistics().snapshot(), &claim);
            assert!(claim.release());
        }
        let reserved = eager;
        let id = install(reserved, process, MapAccess::Reserved);
        let before = process.subprocess().vm_statistics().snapshot();
        let claim = unsafe { reserved.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
        emit_claim(&mut index, before, process.subprocess().vm_statistics().snapshot(), &claim);
        assert!(claim.release());

        // A different fresh arena supplies exactly one committed slice of a
        // two-slice range. Its commit=false source claim must subtract that
        // mixed observation and clear both commitment bits.
        let mixed = eager;
        let id = install(mixed, process, MapAccess::Reserved);
        let claim = unsafe { mixed.try_find_free(search(id), 2, ARENA_SLICE_SIZE, false) }.unwrap();
        let slice_index = claim.slice_index();
        let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
        let owner = unsafe { mixed.allocation_for_arena(view.arena()) }.unwrap();
        assert!(owner.commit(claim.start(), ARENA_SLICE_SIZE, 0));
        unsafe { view.slices_committed() }.unwrap().set_range(slice_index, 1).unwrap();
        assert!(claim.release());
        let before = process.subprocess().vm_statistics().snapshot();
        let claim = unsafe { mixed.try_find_free(search(id), 2, ARENA_SLICE_SIZE, false) }.unwrap();
        assert_eq!(claim.slice_index(), slice_index);
        emit_claim(&mut index, before, process.subprocess().vm_statistics().snapshot(), &claim);
        assert_eq!(unsafe { view.slices_committed() }.unwrap().popcount_range(slice_index, 2), Some(0));
        assert!(claim.release());
        assert_eq!(index, 20);
    }

    // ---- Native arena lifecycle differential -------------------------------
    //
    // Field-for-field Rust receiver of `compat/allocator/m2_arena_lifecycle_x86_64.c`.
    // Every scenario owns a fresh process arena group and subprocess image,
    // matching the C fixture's zeroed per-scenario `mi_subproc_t`, and drives
    // the production `try_allocate_slices` (`mi_arenas_try_alloc`) and
    // `ArenaSliceClaim::release` (`_mi_arenas_free`) entries. Values are
    // address-free source relations; `mmap_calls` is omitted because kernel
    // alignment luck legitimately changes the aligned-map attempt count.

    struct LifecycleTrace {
        field: usize,
    }

    impl LifecycleTrace {
        fn emit(&mut self, value: i64) {
            std::println!("m2.arena.lifecycle.{}={value}", self.field);
            self.field += 1;
        }

        fn emit_bool(&mut self, value: bool) {
            self.emit(i64::from(value));
        }

        fn marker(&mut self, scenario: i64) {
            self.emit(-1000 - scenario);
        }
    }

    #[derive(Clone, Copy)]
    struct LifecycleOwner {
        process: VmProcess<'static>,
        config: MemoryConfig,
        backing: &'static ProcessArenaBacking,
    }

    fn lifecycle_options(reserve_kib: i64, eager: i64, disallow_os: bool, numa_local: bool) -> VmOptions {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaReserve, reserve_kib);
        options.set(VmOption::ArenaEagerCommit, eager);
        options.set(VmOption::DisallowOsAlloc, i64::from(disallow_os));
        options.set(VmOption::DisallowArenaAlloc, 0);
        options.set(VmOption::ArenaIsNumaLocal, i64::from(numa_local));
        options.set(VmOption::AllowLargeOsPages, 0);
        options.set(VmOption::PurgeDelay, -1);
        options
    }

    fn lifecycle_owner(overcommit: bool, reserve_kib: i64, eager: i64, numa_local: bool) -> LifecycleOwner {
        LifecycleOwner {
            process: process_with_options(lifecycle_options(reserve_kib, eager, false, numa_local)),
            config: MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, overcommit, false),
            backing: backing(),
        }
    }

    /// The same subprocess registry observed through `disallow_os_alloc`.
    /// The C fixture flips the ambient option between two calls; Rust keeps
    /// each resolved option image immutable and presents the second image.
    fn lifecycle_disallowing(owner: LifecycleOwner, reserve_kib: i64, eager: i64) -> VmProcess<'static> {
        let policy = Box::leak(Box::new(
            VmPolicy::new(lifecycle_options(reserve_kib, eager, true, false)).unwrap(),
        ));
        policy.finish_preloading();
        VmProcess::new(policy, owner.process.subprocess())
    }

    #[derive(Clone, Copy)]
    struct LifecycleStats {
        reserved: i64,
        committed: i64,
        commit_calls: i64,
        arena_count: i64,
    }

    fn lifecycle_stats(owner: LifecycleOwner) -> LifecycleStats {
        let vm = owner.process.subprocess().vm_statistics().snapshot();
        let arena = owner.process.subprocess().arena_statistics().snapshot();
        LifecycleStats {
            reserved: vm.reserved_current,
            committed: vm.committed_current,
            commit_calls: vm.commit_calls,
            arena_count: arena.arena_count,
        }
    }

    fn emit_lifecycle_stats_delta(trace: &mut LifecycleTrace, owner: LifecycleOwner, before: LifecycleStats) {
        let after = lifecycle_stats(owner);
        trace.emit(after.reserved - before.reserved);
        trace.emit(after.committed - before.committed);
        trace.emit(after.commit_calls - before.commit_calls);
        trace.emit(after.arena_count - before.arena_count);
    }

    fn emit_lifecycle_arenas_from(trace: &mut LifecycleTrace, owner: LifecycleOwner, first: usize) {
        let count = owner.backing.registry().count();
        for index in first..count {
            // SAFETY: fixture arena groups are never destroyed.
            let arena = unsafe { owner.backing.registry().arena_at(index) }.expect("published arena");
            let view = unsafe { ArenaView::from_ptr(core::ptr::from_ref(arena).cast_mut()) }.unwrap();
            let free = unsafe { view.slices_free() }.unwrap();
            let free_count = (0..arena.slice_count)
                .filter(|&slice| free.is_set_range(slice, 1) == Some(true))
                .count();
            let committed = unsafe { view.slices_committed() }.unwrap();
            let dirty = unsafe { view.slices_dirty() }.unwrap();
            trace.emit(index as i64);
            trace.emit(arena.arena_index as i64);
            trace.emit(arena.slice_count as i64);
            trace.emit(arena.info_slices as i64);
            trace.emit((arena.total_size / ARENA_SLICE_SIZE) as i64);
            trace.emit_bool(arena.parent.is_null());
            trace.emit_bool(arena.memid.kind() == MemoryKind::Os);
            trace.emit_bool(arena.memid.initially_committed());
            trace.emit_bool(arena.memid.initially_zero());
            trace.emit_bool(arena.memid.is_pinned());
            trace.emit_bool(arena.is_exclusive);
            trace.emit(i64::from(arena.numa_node));
            trace.emit_bool(arena.start.addr() % ARENA_ALIGNMENT == 0);
            trace.emit(free_count as i64);
            trace.emit(committed.popcount_range(0, arena.slice_count).unwrap() as i64);
            trace.emit(dirty.popcount_range(0, arena.slice_count).unwrap() as i64);
        }
    }

    struct LifecycleClaim {
        claim: Option<ArenaSliceClaim<'static>>,
        slices: usize,
    }

    impl LifecycleClaim {
        fn is_some(&self) -> bool {
            self.claim.is_some()
        }

        fn arena(&self) -> ArenaId {
            let memory = self.claim.as_ref().unwrap().memory_id().arena_memory().unwrap();
            unsafe { ArenaId::from_arena(memory.arena) }.unwrap()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lifecycle_claim(
        trace: &mut LifecycleTrace, owner: LifecycleOwner, process: VmProcess<'static>,
        slices: usize, commit: bool, requested: ArenaId, numa_node: i32,
    ) -> LifecycleClaim {
        let before = lifecycle_stats(owner);
        let arenas_before = owner.backing.registry().count();
        let search = ArenaSearch {
            heap_sequence: 0,
            heap_count: 1,
            thread_sequence: 0,
            numa_node,
            requested,
            allow_pinned: true,
        };
        // SAFETY: each fixture group, its process pair, and every requested
        // parent remain live for the whole test; claims are released below.
        let claim = unsafe {
            owner.backing.try_allocate_slices(process, owner.config, search, slices,
                ARENA_SLICE_SIZE, commit)
        };
        trace.emit_bool(claim.is_some());
        trace.emit(owner.backing.registry().count() as i64);
        match &claim {
            Some(claim) => {
                let memory = claim.memory_id();
                let arena_memory = memory.arena_memory().unwrap();
                let arena = unsafe { &*arena_memory.arena };
                let view = unsafe { ArenaView::from_ptr(arena_memory.arena) }.unwrap();
                let slice_index = arena_memory.slice_index as usize;
                assert_eq!(view.slice_start(slice_index), Some(claim.start()));
                trace.emit(arena.arena_index as i64);
                trace.emit(slice_index as i64);
                trace.emit(i64::from(arena_memory.slice_count));
                trace.emit_bool(memory.initially_committed());
                trace.emit_bool(memory.initially_zero());
                trace.emit_bool(memory.is_pinned());
                trace.emit_bool(unsafe { view.slices_committed() }.unwrap()
                    .is_set_range(slice_index, slices) == Some(true));
            }
            None => for _ in 0..7 { trace.emit(-1); },
        }
        emit_lifecycle_stats_delta(trace, owner, before);
        emit_lifecycle_arenas_from(trace, owner, arenas_before);
        LifecycleClaim { claim, slices }
    }

    /// Rust receiver of the fixture's `object`: source `_mi_arenas_alloc_aligned`
    /// in a requested arena, committed and allowing pinned memory.
    #[allow(clippy::too_many_arguments)]
    fn lifecycle_object(
        trace: &mut LifecycleTrace, owner: LifecycleOwner, process: VmProcess<'static>,
        size: usize, alignment: usize, align_offset: usize, requested: ArenaId, numa_node: i32,
    ) -> LifecycleClaim {
        let before = lifecycle_stats(owner);
        let arenas_before = owner.backing.registry().count();
        let search = ArenaSearch {
            heap_sequence: 0, heap_count: 1, thread_sequence: 0, numa_node, requested,
            allow_pinned: true,
        };
        // SAFETY: the fixture group and requested parent live for the test.
        let result = unsafe { owner.backing.try_allocate_requested_arena_object(process,
            owner.config, search, size, alignment, align_offset, true) };
        trace.emit_bool(result.is_ok());
        trace.emit(match &result { Ok(_) => 0, Err(error) => i64::from(error.raw()) });
        trace.emit(owner.backing.registry().count() as i64);
        let mut slices = 0;
        match &result {
            Ok(claim) => {
                let memory = claim.memory_id();
                let arena_memory = memory.arena_memory().unwrap();
                let arena = unsafe { &*arena_memory.arena };
                let view = unsafe { ArenaView::from_ptr(arena_memory.arena) }.unwrap();
                let slice_index = arena_memory.slice_index as usize;
                slices = arena_memory.slice_count as usize;
                assert_eq!(view.slice_start(slice_index), Some(claim.start()));
                trace.emit(arena.arena_index as i64);
                trace.emit(slice_index as i64);
                trace.emit(slices as i64);
                trace.emit_bool(memory.initially_committed());
                trace.emit_bool(memory.initially_zero());
                trace.emit_bool(unsafe { view.slices_committed() }.unwrap()
                    .is_set_range(slice_index, slices) == Some(true));
            }
            Err(_) => for _ in 0..6 { trace.emit(-1); },
        }
        emit_lifecycle_stats_delta(trace, owner, before);
        emit_lifecycle_arenas_from(trace, owner, arenas_before);
        LifecycleClaim { claim: result.ok(), slices }
    }

    /// Rust receiver of the fixture's `theap_alloc`: the source
    /// `_mi_theap_alloc` exclusive-arena arm through the process backing.
    fn lifecycle_theap(
        trace: &mut LifecycleTrace, owner: LifecycleOwner, process: VmProcess<'static>,
        exclusive: ArenaId, numa_node: i32,
    ) -> Option<crate::arena::ExclusiveArenaTheapReservation<'static, 'static>> {
        let before = lifecycle_stats(owner);
        let arenas_before = owner.backing.registry().count();
        let subprocess = process.main_subprocess().expect("fixture process is main");
        // SAFETY: the fixture group and exclusive parent live for the test.
        let result = unsafe { owner.backing.try_reserve_exclusive_theap(process, owner.config,
            subprocess, exclusive, crate::types::ThreadSequence::from_previous_total_count(0), numa_node) };
        trace.emit_bool(result.is_ok());
        trace.emit(owner.backing.registry().count() as i64);
        let reservation = match result {
            Ok(reservation) => {
                let memory = reservation.memory_id();
                let arena_memory = memory.arena_memory().unwrap();
                assert_eq!(arena_memory.arena, exclusive.as_ptr());
                let view = unsafe { ArenaView::from_ptr(arena_memory.arena) }.unwrap();
                let slice_index = arena_memory.slice_index as usize;
                let slices = arena_memory.slice_count as usize;
                trace.emit(slice_index as i64);
                trace.emit(slices as i64);
                trace.emit_bool(memory.initially_committed());
                trace.emit_bool(memory.initially_zero());
                trace.emit_bool(unsafe { view.slices_committed() }.unwrap()
                    .is_set_range(slice_index, slices) == Some(true));
                Some(reservation)
            }
            Err(error) => {
                assert_eq!(error, Errno::NOMEM);
                for _ in 0..5 { trace.emit(-1); }
                None
            }
        };
        emit_lifecycle_stats_delta(trace, owner, before);
        emit_lifecycle_arenas_from(trace, owner, arenas_before);
        reservation
    }

    /// Rust receiver of the fixture's `meta_release`: `_mi_meta_free` of an
    /// Arena memory ID. Rust has no memory-ID dispatcher; the typed
    /// exclusive-arena Theap reservation is the only owner of that release.
    fn lifecycle_theap_release(trace: &mut LifecycleTrace, owner: LifecycleOwner,
        reservation: crate::arena::ExclusiveArenaTheapReservation<'static, 'static>) {
        let before = lifecycle_stats(owner);
        let memory = reservation.memory_id();
        trace.emit_bool(memory.kind().needs_no_free());
        let arena_memory = memory.arena_memory().unwrap();
        let view = unsafe { ArenaView::from_ptr(arena_memory.arena) }.unwrap();
        let index = arena_memory.slice_index as usize;
        let slices = arena_memory.slice_count as usize;
        assert!(matches!(reservation.release(), Ok(true)));
        trace.emit_bool(unsafe { view.slices_free() }.unwrap().is_set_range(index, slices) == Some(true));
        trace.emit_bool(unsafe { view.slices_purge() }.unwrap().is_set_range(index, slices) == Some(true));
        emit_lifecycle_stats_delta(trace, owner, before);
    }

    /// The C fixture's `emit_madvise_record`: every mapping-owned advisory
    /// call (decommit and reset both record before their injection point)
    /// and up to four advice values, padded with -1.
    fn emit_lifecycle_advice(trace: &mut LifecycleTrace, capture: &fault::AdviceRangeCapture<'_>) {
        let (ranges, count) = capture.ranges().expect("at most four advisory calls");
        trace.emit(count as i64);
        for (index, range) in ranges.iter().enumerate() {
            trace.emit(if index < count { i64::from(range.2) } else { -1 });
        }
    }

    #[derive(Clone, Copy)]
    struct LifecyclePurgeCounters {
        purge_calls: i64,
        purged: i64,
        reset_calls: i64,
        reset: i64,
        arena_purges: i64,
    }

    fn lifecycle_purge_counters(owner: LifecycleOwner) -> LifecyclePurgeCounters {
        let vm = owner.process.subprocess().vm_statistics().snapshot();
        let arena = owner.process.subprocess().arena_statistics().snapshot();
        LifecyclePurgeCounters {
            purge_calls: vm.purge_calls,
            purged: vm.purged,
            reset_calls: vm.reset_calls,
            reset: vm.reset,
            arena_purges: arena.arena_purges,
        }
    }

    fn emit_lifecycle_purge_counters_delta(trace: &mut LifecycleTrace, owner: LifecycleOwner,
        before: LifecyclePurgeCounters) {
        let after = lifecycle_purge_counters(owner);
        trace.emit(after.purge_calls - before.purge_calls);
        trace.emit(after.purged - before.purged);
        trace.emit(after.reset_calls - before.reset_calls);
        trace.emit(after.reset - before.reset);
        trace.emit(after.arena_purges - before.arena_purges);
    }

    /// A lifecycle owner whose options additionally select the source
    /// purge delay and purge-decommit policy.
    fn lifecycle_purge_owner(purge_delay: i64, purge_decommits: bool) -> LifecycleOwner {
        let mut options = lifecycle_options(32 * 1024, 0, false, false);
        options.set(VmOption::PurgeDelay, purge_delay);
        options.set(VmOption::PurgeDecommits, i64::from(purge_decommits));
        LifecycleOwner {
            process: process_with_options(options),
            config: MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false),
            backing: backing(),
        }
    }

    fn lifecycle_release(trace: &mut LifecycleTrace, owner: LifecycleOwner, item: &mut LifecycleClaim) {
        let claim = item.claim.take().expect("live lifecycle claim");
        let before = lifecycle_stats(owner);
        let arena_memory = claim.memory_id().arena_memory().unwrap();
        let view = unsafe { ArenaView::from_ptr(arena_memory.arena) }.unwrap();
        let index = arena_memory.slice_index as usize;
        assert!(claim.release());
        trace.emit_bool(unsafe { view.slices_free() }.unwrap().is_set_range(index, item.slices) == Some(true));
        trace.emit_bool(unsafe { view.slices_purge() }.unwrap().is_set_range(index, item.slices) == Some(true));
        emit_lifecycle_stats_delta(trace, owner, before);
    }

    #[test]
    fn emit_native_arena_lifecycle_trace() {
        let fault = fault::install(fault::Plan::disabled());
        let mut trace = LifecycleTrace { field: 0 };
        let chunk = crate::config::BCHUNK_BITS;
        let none = ArenaId::none();

        // 1. Reserved-growth and arena-count scaling after eight arenas.
        trace.marker(1);
        {
            let owner = lifecycle_owner(true, 128 * 1024, 0, false);
            let mut claims = std::vec::Vec::new();
            while claims.len() < 40 && owner.backing.registry().count() < 10 {
                let claim = lifecycle_claim(&mut trace, owner, owner.process, chunk, false, none, -1);
                assert!(claim.is_some());
                claims.push(claim);
            }
            trace.emit(claims.len() as i64);
            for claim in &mut claims { lifecycle_release(&mut trace, owner, claim); }
        }

        // 2. Commit transitions and same-span reclaim.
        trace.marker(2);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let mut first = lifecycle_claim(&mut trace, owner, p, 1, true, none, -1);
            let mut second = lifecycle_claim(&mut trace, owner, p, 2, false, none, -1);
            let mut third = lifecycle_claim(&mut trace, owner, p, 4, true, none, -1);
            lifecycle_release(&mut trace, owner, &mut first);
            let mut again = lifecycle_claim(&mut trace, owner, p, 1, true, none, -1);
            let mut again_uncommitted = lifecycle_claim(&mut trace, owner, p, 1, false, none, -1);
            lifecycle_release(&mut trace, owner, &mut second);
            let mut mixed = lifecycle_claim(&mut trace, owner, p, 3, false, none, -1);
            lifecycle_release(&mut trace, owner, &mut third);
            lifecycle_release(&mut trace, owner, &mut again);
            lifecycle_release(&mut trace, owner, &mut again_uncommitted);
            lifecycle_release(&mut trace, owner, &mut mixed);
        }

        // 3. Eager-commit option matrix under both overcommit observations.
        for (variant, (overcommit, eager)) in
            [(true, 1), (true, 2), (false, 2), (false, 1), (true, 0)].into_iter().enumerate()
        {
            trace.marker(3);
            trace.emit(variant as i64);
            let owner = lifecycle_owner(overcommit, 32 * 1024, eager, false);
            let p = owner.process;
            let mut committed = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            let mut uncommitted = lifecycle_claim(&mut trace, owner, p, 2, false, none, -1);
            lifecycle_release(&mut trace, owner, &mut committed);
            let mut reused = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            lifecycle_release(&mut trace, owner, &mut uncommitted);
            lifecycle_release(&mut trace, owner, &mut reused);
        }

        // 4. disallow_os_alloc refuses only the fresh reservation.
        trace.marker(4);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let disallowing = lifecycle_disallowing(owner, 32 * 1024, 0);
            let mut first = lifecycle_claim(&mut trace, owner, owner.process, chunk, false, none, -1);
            let refused = lifecycle_claim(&mut trace, owner, disallowing, chunk, false, none, -1);
            assert!(!refused.is_some());
            let mut second = lifecycle_claim(&mut trace, owner, owner.process, chunk, false, none, -1);
            assert!(second.is_some());
            lifecycle_release(&mut trace, owner, &mut first);
            lifecycle_release(&mut trace, owner, &mut second);
        }

        // 5. Requested and exclusive arenas.
        trace.marker(5);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let mut full = lifecycle_claim(&mut trace, owner, p, chunk, false, none, -1);
            let first = full.arena();
            let requested_full = lifecycle_claim(&mut trace, owner, p, chunk, false, first, -1);
            assert!(!requested_full.is_some());
            let mut requested_small = lifecycle_claim(&mut trace, owner, p, 1, false, first, -1);

            let before = lifecycle_stats(owner);
            let arenas_before = owner.backing.registry().count();
            let exclusive = unsafe {
                owner.backing.reserve_os_memory_for_process(p, owner.config, ARENA_MIN_SIZE,
                    MapAccess::Reserved, false, true, None)
            };
            trace.emit(match exclusive { Ok(_) => 0, Err(error) => i64::from(error.raw()) });
            trace.emit_bool(exclusive.is_ok());
            emit_lifecycle_stats_delta(&mut trace, owner, before);
            emit_lifecycle_arenas_from(&mut trace, owner, arenas_before);
            let exclusive = exclusive.unwrap();
            let mut unrequested = lifecycle_claim(&mut trace, owner, p, chunk, false, none, -1);
            assert!(!unrequested.is_some() || unrequested.arena() != exclusive);
            let mut in_exclusive = lifecycle_claim(&mut trace, owner, p, 2, true, exclusive, -1);
            assert!(in_exclusive.is_some() && in_exclusive.arena() == exclusive);
            lifecycle_release(&mut trace, owner, &mut in_exclusive);
            if unrequested.is_some() { lifecycle_release(&mut trace, owner, &mut unrequested); }
            lifecycle_release(&mut trace, owner, &mut requested_small);
            lifecycle_release(&mut trace, owner, &mut full);
        }

        // 6. Requests too large for the bounded reservation or arena.
        trace.marker(6);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let mut spanning = lifecycle_claim(&mut trace, owner, p, 1500, false, none, -1);
            let oversized = lifecycle_claim(&mut trace, owner, p,
                ARENA_MAX_SIZE / ARENA_SLICE_SIZE - 64, false, none, -1);
            assert!(!oversized.is_some());
            let impossible = lifecycle_claim(&mut trace, owner, p,
                ARENA_MAX_SIZE / ARENA_SLICE_SIZE + 1, false, none, -1);
            assert!(!impossible.is_some());
            if spanning.is_some() { lifecycle_release(&mut trace, owner, &mut spanning); }
        }

        // 7. Clean primary reservation failure with and without the source
        //    128-MiB fallback. The C seam fails every regular map at or above
        //    a byte threshold; here exactly the primary's direct and
        //    over-allocated source attempts fail.
        for (variant, eager) in [0, 1].into_iter().enumerate() {
            trace.marker(7);
            trace.emit(variant as i64);
            let owner = lifecycle_owner(true, 1024 * 1024, eager, false);
            fault.set(fault::Plan::at_pair(fault::Point::Map, 1, fault::Point::Map, 1, Errno::NOMEM));
            let mut fallback = lifecycle_claim(&mut trace, owner, owner.process, 1, true, none, -1);
            assert!(fallback.is_some());
            trace.emit_bool(fault.observed() > 0 && fault.secondary_observed() > 0);
            fault.set(fault::Plan::disabled());
            lifecycle_release(&mut trace, owner, &mut fallback);

            let bounded = lifecycle_owner(true, 128 * 1024, eager, false);
            fault.set(fault::Plan::at_pair(fault::Point::Map, 1, fault::Point::Map, 1, Errno::NOMEM));
            let refused = lifecycle_claim(&mut trace, bounded, bounded.process, 1, true, none, -1);
            assert!(!refused.is_some());
            trace.emit_bool(fault.observed() > 0 && fault.secondary_observed() > 0);
            fault.set(fault::Plan::disabled());
            let mut retried = lifecycle_claim(&mut trace, bounded, bounded.process, 1, true, none, -1);
            assert!(retried.is_some());
            lifecycle_release(&mut trace, bounded, &mut retried);
        }

        // 8. NUMA-local reservation and the second, nonmatching source pass.
        trace.marker(8);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, true);
            let p = owner.process;
            let mut local = lifecycle_claim(&mut trace, owner, p, 1, false, none, 0);
            let arena = local.arena();
            let node = unsafe { (*arena.as_ptr()).numa_node };
            trace.emit_bool(node >= 0);
            let mut remote = lifecycle_claim(&mut trace, owner, p, 1, false, none, node + 5);
            assert!(remote.is_some() && remote.arena() == arena);
            lifecycle_release(&mut trace, owner, &mut remote);
            lifecycle_release(&mut trace, owner, &mut local);
        }

        // 9. Exclusive explicit reservation spanning a parent and sub-arena.
        trace.marker(9);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let before = lifecycle_stats(owner);
            let parent = unsafe {
                owner.backing.reserve_os_memory_for_process(p, owner.config,
                    ARENA_MAX_SIZE + crate::config::GIB, MapAccess::Reserved, false, true, None)
            };
            trace.emit(match parent { Ok(_) => 0, Err(error) => i64::from(error.raw()) });
            trace.emit_bool(parent.is_ok());
            emit_lifecycle_stats_delta(&mut trace, owner, before);
            emit_lifecycle_arenas_from(&mut trace, owner, 0);
            let parent = parent.unwrap();
            assert_eq!(owner.backing.registry().count(), 2);
            let child = unsafe { owner.backing.registry().arena_at(1) }.unwrap();
            assert_eq!(child.parent, parent.as_ptr());
            let mut in_parent = lifecycle_claim(&mut trace, owner, p, 1, false, parent, -1);
            assert!(in_parent.is_some() && in_parent.arena() == parent);
            let mut shared = lifecycle_claim(&mut trace, owner, p, 1, false, none, -1);
            assert!(shared.is_some() && shared.arena() != parent);
            lifecycle_release(&mut trace, owner, &mut shared);
            lifecycle_release(&mut trace, owner, &mut in_parent);
        }

        // 10. Registry exhaustion and the automatic-reservation arena cap.
        trace.marker(10);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let mut reserved = 0usize;
            let mut error = 0i64;
            let mut before = lifecycle_stats(owner);
            while reserved <= MAX_ARENAS {
                before = lifecycle_stats(owner);
                match unsafe { owner.backing.reserve_os_memory_for_process(p, owner.config,
                    ARENA_MIN_SIZE, MapAccess::Reserved, false, false, None) } {
                    Ok(_) => reserved += 1,
                    Err(failure) => { error = i64::from(failure.raw()); break; }
                }
            }
            trace.emit(reserved as i64);
            trace.emit(error);
            trace.emit(owner.backing.registry().count() as i64);
            emit_lifecycle_stats_delta(&mut trace, owner, before);
            let refused = lifecycle_claim(&mut trace, owner, p, chunk, false, none, -1);
            assert!(!refused.is_some());
            let mut fits = lifecycle_claim(&mut trace, owner, p, 1, false, none, -1);
            assert!(fits.is_some());
            lifecycle_release(&mut trace, owner, &mut fits);
        }

        // 11. Sub-arena publication failure after a published parent.
        trace.marker(11);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            for _ in 0..MAX_ARENAS - 1 {
                unsafe { owner.backing.reserve_os_memory_for_process(p, owner.config,
                    ARENA_MIN_SIZE, MapAccess::Reserved, false, false, None) }.unwrap();
            }
            let before = lifecycle_stats(owner);
            let parent = unsafe {
                owner.backing.reserve_os_memory_for_process(p, owner.config,
                    ARENA_MAX_SIZE + crate::config::GIB, MapAccess::Reserved, false, false, None)
            };
            trace.emit(match parent { Ok(_) => 0, Err(error) => i64::from(error.raw()) });
            trace.emit_bool(parent.is_ok());
            emit_lifecycle_stats_delta(&mut trace, owner, before);
            emit_lifecycle_arenas_from(&mut trace, owner, MAX_ARENAS - 1);
            let parent = parent.unwrap();
            let mut in_parent = lifecycle_claim(&mut trace, owner, p, 2, true, parent, -1);
            assert!(in_parent.is_some() && in_parent.arena() == parent);
            lifecycle_release(&mut trace, owner, &mut in_parent);
        }

        // 12. Sub-arena metadata commit failure after a published parent.
        trace.marker(12);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let before = lifecycle_stats(owner);
            fault.set(fault::Plan::at(fault::Point::Commit, 2, Errno::NOMEM));
            let parent = unsafe {
                owner.backing.reserve_os_memory_for_process(p, owner.config,
                    ARENA_MAX_SIZE + crate::config::GIB, MapAccess::Reserved, false, false, None)
            };
            trace.emit_bool(fault.observed() >= 2);
            fault.set(fault::Plan::disabled());
            trace.emit(match parent { Ok(_) => 0, Err(error) => i64::from(error.raw()) });
            trace.emit_bool(parent.is_ok());
            emit_lifecycle_stats_delta(&mut trace, owner, before);
            emit_lifecycle_arenas_from(&mut trace, owner, 0);
            let parent = parent.unwrap();
            assert_eq!(owner.backing.registry().count(), 1);
            let mut in_parent = lifecycle_claim(&mut trace, owner, p, 2, true, parent, -1);
            assert!(in_parent.is_some() && in_parent.arena() == parent);
            let mut shared = lifecycle_claim(&mut trace, owner, p, 1, false, none, -1);
            assert!(shared.is_some());
            lifecycle_release(&mut trace, owner, &mut shared);
            lifecycle_release(&mut trace, owner, &mut in_parent);
        }

        // 13. `_mi_arenas_alloc(_aligned)` for a requested (exclusive) arena.
        trace.marker(13);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let exclusive = unsafe { owner.backing.reserve_os_memory_for_process(p, owner.config,
                ARENA_MIN_SIZE, MapAccess::Reserved, false, true, None) }.unwrap();
            let slice = crate::config::ARENA_SLICE_SIZE;
            let min = crate::config::ARENA_MIN_OBJ_SIZE;
            let max = super::super::selection::arena_max_object_size(p.policy());
            let mut theap = lifecycle_object(&mut trace, owner, p, min, slice, 0, exclusive, -1);
            assert!(theap.is_some());
            // No pinned caller reaches the unrequested OS fallback.
            let unrequested = ArenaSearch { heap_sequence: 0, heap_count: 1, thread_sequence: 0,
                numa_node: -1, requested: none, allow_pinned: true };
            assert_eq!(unsafe { owner.backing.try_allocate_requested_arena_object(p, owner.config,
                unrequested, min, slice, 0, true) }.err(), Some(Errno::INVAL));
            let mut largest = lifecycle_object(&mut trace, owner, p, 2 * MIB, slice, 0, exclusive, 2);
            assert!(largest.is_some());
            trace.emit((max / slice) as i64);
            let mut at_max = lifecycle_object(&mut trace, owner, p, max, slice, 0, exclusive, -1);
            if at_max.is_some() { lifecycle_release(&mut trace, owner, &mut at_max); }
            for (size, alignment, offset) in
                [(min - 1, slice, 0), (max + 1, slice, 0), (min, 2 * slice, 0), (min, slice, 16)]
            {
                let refused = lifecycle_object(&mut trace, owner, p, size, alignment, offset, exclusive, -1);
                assert!(!refused.is_some());
            }
            let mut options = lifecycle_options(32 * 1024, 0, false, false);
            options.set(VmOption::DisallowArenaAlloc, 1);
            let policy = Box::leak(Box::new(VmPolicy::new(options).unwrap()));
            policy.finish_preloading();
            let disallowing = VmProcess::new(policy, p.subprocess());
            let refused = lifecycle_object(&mut trace, owner, disallowing, min, slice, 0, exclusive, -1);
            assert!(!refused.is_some());
            let mut fill = std::vec::Vec::new();
            while fill.len() < 16 {
                let claim = lifecycle_object(&mut trace, owner, p, 2 * MIB, slice, 0, exclusive, -1);
                if !claim.is_some() { break; }
                fill.push(claim);
            }
            trace.emit(fill.len() as i64);
            for claim in &mut fill { lifecycle_release(&mut trace, owner, claim); }
            lifecycle_release(&mut trace, owner, &mut largest);
            lifecycle_release(&mut trace, owner, &mut theap);
        }

        // 14. Concurrent fresh reservation after exhausting the only arena.
        // Source reservation is serialized but not unique, so only the
        // interleaving-independent relations of the C fixture are compared.
        trace.marker(14);
        {
            use std::sync::{Arc, Barrier};
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let existing = unsafe { owner.backing.reserve_os_memory_for_process(p, owner.config,
                ARENA_MIN_SIZE, MapAccess::Reserved, false, false, None) }.unwrap();
            let mut fillers = std::vec::Vec::new();
            loop {
                let search = ArenaSearch { heap_sequence: 0, heap_count: 1, thread_sequence: 0,
                    numa_node: -1, requested: existing, allow_pinned: true };
                match unsafe { owner.backing.try_allocate_slices(p, owner.config, search, 1,
                    ARENA_SLICE_SIZE, false) } {
                    Some(claim) => fillers.push(LifecycleClaim { claim: Some(claim), slices: 1 }),
                    None => break,
                }
            }
            trace.emit(fillers.len() as i64);
            let start = Arc::new(Barrier::new(8));
            let claimed = Arc::new(Barrier::new(9));
            let release_all = Arc::new(Barrier::new(9));
            let before = lifecycle_stats(owner);
            let (sender, receiver) = std::sync::mpsc::channel();
            let workers: std::vec::Vec<_> = (0..8).map(|worker| {
                let (start, claimed, release_all) = (start.clone(), claimed.clone(), release_all.clone());
                let sender = sender.clone();
                std::thread::spawn(move || {
                    let search = ArenaSearch { heap_sequence: 0, heap_count: 1, thread_sequence: worker,
                        numa_node: -1, requested: ArenaId::none(), allow_pinned: true };
                    start.wait();
                    // SAFETY: the fixture group outlives every worker.
                    let claim = unsafe { owner.backing.try_allocate_slices(owner.process, owner.config,
                        search, 1, ARENA_SLICE_SIZE, false) };
                    let observed = claim.as_ref().map(|claim| {
                        let arena = claim.memory_id().arena_memory().unwrap().arena;
                        (arena as usize, unsafe { (*arena).arena_index }, claim.start() as usize)
                    });
                    sender.send(observed).unwrap();
                    claimed.wait();
                    release_all.wait();
                    if let Some(claim) = claim { assert!(claim.release()); }
                })
            }).collect();
            claimed.wait();
            let after = lifecycle_stats(owner);
            let observed: std::vec::Vec<_> = receiver.try_iter().flatten().collect();
            let fresh = owner.backing.registry().count() - 1;
            let arena = |index| unsafe { owner.backing.registry().arena_at(index) }.unwrap();
            let first_fresh = arena(1);
            let in_fresh = observed.iter().all(|&(pointer, index, _)|
                pointer != existing.as_ptr() as usize && index >= 1);
            let distinct = observed.iter().enumerate().all(|(index, (_, _, start))|
                observed[..index].iter().all(|(_, _, other)| other != start));
            let same_geometry = (1..=fresh).all(|index| {
                let arena = arena(index);
                arena.slice_count == first_fresh.slice_count
                    && arena.info_slices == first_fresh.info_slices && arena.parent.is_null()
            });
            let fresh_count = fresh as i64;
            trace.emit(observed.len() as i64);
            trace.emit_bool(in_fresh);
            trace.emit_bool(distinct);
            trace.emit_bool((1..=8).contains(&fresh));
            trace.emit_bool(same_geometry);
            trace.emit(first_fresh.slice_count as i64);
            trace.emit(first_fresh.info_slices as i64);
            trace.emit((after.reserved - before.reserved) / fresh_count);
            trace.emit((after.reserved - before.reserved) % fresh_count);
            trace.emit((after.committed - before.committed) / fresh_count);
            trace.emit((after.committed - before.committed) % fresh_count);
            trace.emit_bool(after.commit_calls - before.commit_calls == fresh_count);
            trace.emit_bool(after.arena_count - before.arena_count == fresh_count);
            release_all.wait();
            for worker in workers { worker.join().unwrap(); }
            let all_free = (1..=fresh).all(|index| {
                let arena = arena(index);
                let view = unsafe { ArenaView::from_ptr(core::ptr::from_ref(arena).cast_mut()) }.unwrap();
                let free = unsafe { view.slices_free() }.unwrap();
                (0..arena.slice_count).filter(|&slice| free.is_set_range(slice, 1) == Some(true)).count()
                    == arena.slice_count - arena.info_slices
            });
            trace.emit_bool(all_free);
            for claim in &mut fillers { lifecycle_release(&mut trace, owner, claim); }
        }

        // 15. `_mi_theap_alloc` in a reserved exclusive arena whose commit
        // fails once: one pass refuses, a nonnegative NUMA node's second pass
        // commits, and disallow_arena_alloc refuses before any search.
        trace.marker(15);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let exclusive = unsafe { owner.backing.reserve_os_memory_for_process(p, owner.config,
                ARENA_MIN_SIZE, MapAccess::Reserved, false, true, None) }.unwrap();
            fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
            let one_pass = lifecycle_theap(&mut trace, owner, p, exclusive, -1);
            trace.emit(fault.observed() as i64);
            fault.set(fault::Plan::disabled());
            assert!(one_pass.is_none());
            fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
            let second_pass = lifecycle_theap(&mut trace, owner, p, exclusive, 0);
            trace.emit(fault.observed() as i64);
            fault.set(fault::Plan::disabled());
            assert!(second_pass.is_some());
            let mut options = lifecycle_options(32 * 1024, 0, false, false);
            options.set(VmOption::DisallowArenaAlloc, 1);
            let policy = Box::leak(Box::new(VmPolicy::new(options).unwrap()));
            policy.finish_preloading();
            let disallowing = VmProcess::new(policy, p.subprocess());
            let disallowed = lifecycle_theap(&mut trace, owner, disallowing, exclusive, 0);
            assert!(disallowed.is_none());
            lifecycle_theap_release(&mut trace, owner, second_pass.unwrap());
        }

        // 16. A committed claim whose first-arena commit fails reserves a
        // fresh arena, then commits in the first arena on the second search.
        trace.marker(16);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            let mut first = lifecycle_claim(&mut trace, owner, p, 1, false, none, -1);
            fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
            let mut retried = lifecycle_claim(&mut trace, owner, p, 1, true, none, -1);
            trace.emit(fault.observed() as i64);
            fault.set(fault::Plan::disabled());
            assert!(retried.is_some() && retried.arena() == first.arena());
            lifecycle_release(&mut trace, owner, &mut retried);
            lifecycle_release(&mut trace, owner, &mut first);
        }

        // 17. Immediate purge on release through decommit: failure, success,
        // and a mixed-commitment range.
        trace.marker(17);
        {
            let owner = lifecycle_purge_owner(0, true);
            let p = owner.process;
            let mut failing = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            let mut succeeding = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            let mut mixed = lifecycle_claim(&mut trace, owner, p, 2, false, none, -1);
            for (index, item) in [&mut failing, &mut succeeding, &mut mixed].into_iter().enumerate() {
                let before = lifecycle_purge_counters(owner);
                fault.set(if index == 0 {
                    fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM)
                } else {
                    fault::Plan::disabled()
                });
                let capture = fault.capture_advice_range();
                lifecycle_release(&mut trace, owner, item);
                emit_lifecycle_advice(&mut trace, &capture);
                drop(capture);
                fault.set(fault::Plan::disabled());
                emit_lifecycle_purge_counters_delta(&mut trace, owner, before);
                emit_lifecycle_arenas_from(&mut trace, owner, 0);
            }
        }

        // 18. Immediate purge through reset: EAGAIN retry, a warning-only
        // error, and a not-fully-committed range that is not reset.
        trace.marker(18);
        {
            let owner = lifecycle_purge_owner(0, false);
            let p = owner.process;
            let mut again = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            let mut failing = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            let mut mixed = lifecycle_claim(&mut trace, owner, p, 2, false, none, -1);
            let errors = [Errno::AGAIN, Errno::NOMEM, Errno::NOMEM];
            for (index, item) in [&mut again, &mut failing, &mut mixed].into_iter().enumerate() {
                let before = lifecycle_purge_counters(owner);
                fault.set(if index < 2 {
                    fault::Plan::at(fault::Point::Purge, 1, errors[index])
                } else {
                    fault::Plan::disabled()
                });
                let capture = fault.capture_advice_range();
                lifecycle_release(&mut trace, owner, item);
                emit_lifecycle_advice(&mut trace, &capture);
                drop(capture);
                fault.set(fault::Plan::disabled());
                emit_lifecycle_purge_counters_delta(&mut trace, owner, before);
                emit_lifecycle_arenas_from(&mut trace, owner, 0);
            }
        }

        // 19. A delayed purge whose forced collection decommit fails consumes
        // the schedule; a second forced collection has nothing to retry.
        trace.marker(19);
        {
            let owner = lifecycle_purge_owner(10, true);
            let p = owner.process;
            let mut scheduled = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            let arena = scheduled.arena();
            lifecycle_release(&mut trace, owner, &mut scheduled);
            let view = unsafe { ArenaView::from_ptr(arena.as_ptr()) }.unwrap();
            let expire = || view.arena().purge_expire.load(Ordering::Acquire);
            trace.emit_bool(expire() != 0);
            for pass in 0..2 {
                let before = lifecycle_purge_counters(owner);
                fault.set(if pass == 0 {
                    fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM)
                } else {
                    fault::Plan::disabled()
                });
                let capture = fault.capture_advice_range();
                // SAFETY: the fixture group is live and its claims released.
                assert!(unsafe { owner.backing.collect_purge(p, owner.config, true, true, 0) });
                emit_lifecycle_advice(&mut trace, &capture);
                drop(capture);
                fault.set(fault::Plan::disabled());
                emit_lifecycle_purge_counters_delta(&mut trace, owner, before);
                trace.emit_bool(expire() == 0);
                let purge = unsafe { view.slices_purge() }.unwrap();
                trace.emit(purge.popcount_range(0, view.arena().slice_count).unwrap() as i64);
                emit_lifecycle_arenas_from(&mut trace, owner, 0);
            }
        }

        // 20. Reset EINVAL switches the process-global advice to
        // MADV_DONTNEED for this and every later reset; it runs last.
        trace.marker(20);
        {
            let owner = lifecycle_purge_owner(0, false);
            let p = owner.process;
            let mut first = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            let mut later = lifecycle_claim(&mut trace, owner, p, 2, true, none, -1);
            for (index, item) in [&mut first, &mut later].into_iter().enumerate() {
                let before = lifecycle_purge_counters(owner);
                fault.set(if index == 0 {
                    fault::Plan::at(fault::Point::Purge, 1, Errno::INVAL)
                } else {
                    fault::Plan::disabled()
                });
                let capture = fault.capture_advice_range();
                lifecycle_release(&mut trace, owner, item);
                emit_lifecycle_advice(&mut trace, &capture);
                drop(capture);
                fault.set(fault::Plan::disabled());
                emit_lifecycle_purge_counters_delta(&mut trace, owner, before);
            }
        }

        // 21. The fresh OS page caller: success and release, a metadata or
        // page-area commit failure whose cleanup unmap succeeds or fails,
        // and a release whose unmap fails. Rust accounts each release once
        // and retains a failed range for a raw retry without statistics.
        trace.marker(21);
        {
            use crate::os_page::{OsAlignedPageClaim, OsAlignedPageOwner};
            let mut options = lifecycle_options(32 * 1024, 0, false, false);
            options.set(VmOption::DisallowArenaAlloc, 1);
            let owner = LifecycleOwner {
                process: process_with_options(options),
                config: MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false),
                backing: backing(),
            };
            let p = owner.process;
            let retry = |claim: OsAlignedPageClaim| {
                // SAFETY: the fixture process image outlives this raw retry.
                assert!(unsafe { claim.retry_release() }.is_ok());
            };
            for variant in 0..6 {
                let before = lifecycle_stats(owner);
                let commit_failure = match variant { 1 | 3 => 1, 2 | 4 => 2, _ => 0 };
                fault.set(match variant {
                    1 | 2 => fault::Plan::at(fault::Point::Commit, commit_failure, Errno::NOMEM),
                    3 | 4 => fault::Plan::at_pair(fault::Point::Commit, commit_failure,
                        fault::Point::Unmap, 1, Errno::NOMEM),
                    _ => fault::Plan::at(fault::Point::Commit, usize::MAX, Errno::NOMEM),
                });
                let result = OsAlignedPageClaim::allocate_for_process(p, owner.config, 4096, 1, none);
                let commit_calls = fault.observed() as i64;
                fault.set(fault::Plan::disabled());
                trace.emit(variant);
                trace.emit_bool(result.is_ok());
                trace.emit(commit_calls);
                let (claim, retained) = match result {
                    Ok(claim) => (Some(claim), None),
                    Err(failure) => match failure.into_owner() {
                        Some(OsAlignedPageOwner::Claim(retained)) => (None, Some(retained)),
                        Some(OsAlignedPageOwner::Published(_)) => panic!("an unpublished claim"),
                        None => (None, None),
                    },
                };
                trace.emit_bool(retained.is_some());
                emit_lifecycle_stats_delta(&mut trace, owner, before);
                if let Some(retained) = retained {
                    retry(retained);
                    emit_lifecycle_stats_delta(&mut trace, owner, before);
                }
                let Some(claim) = claim else { continue; };
                let memory = claim.memory_id().unwrap();
                trace.emit_bool(memory.kind() == MemoryKind::Os);
                trace.emit_bool(memory.initially_committed());
                trace.emit_bool(claim.slice_start().map(|start| start.as_ptr() as usize)
                    == claim.base().ok().map(|base| base as usize + claim.layout().alignment()));
                let after_alloc = lifecycle_stats(owner);
                fault.set(if variant == 5 {
                    fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM)
                } else {
                    fault::Plan::at(fault::Point::Unmap, usize::MAX, Errno::NOMEM)
                });
                let released = claim.release();
                trace.emit(fault.observed() as i64);
                fault.set(fault::Plan::disabled());
                let retained = match released {
                    Ok(()) => None,
                    Err(failure) => match failure.into_owner() {
                        OsAlignedPageOwner::Claim(claim) => Some(claim),
                        OsAlignedPageOwner::Published(_) => panic!("an unpublished claim"),
                    },
                };
                trace.emit_bool(retained.is_some());
                emit_lifecycle_stats_delta(&mut trace, owner, after_alloc);
                if let Some(retained) = retained {
                    retry(retained);
                    emit_lifecycle_stats_delta(&mut trace, owner, after_alloc);
                }
            }
        }

        // 22. A fresh arena whose metadata commit and cleanup unmap both
        // fail: the reservation fails cleanly (the mapping leaks) and a
        // later request reserves again.
        trace.marker(22);
        {
            let owner = lifecycle_owner(true, 32 * 1024, 0, false);
            let p = owner.process;
            fault.set(fault::Plan::at_pair(fault::Point::Commit, 1, fault::Point::Unmap, 1, Errno::NOMEM));
            let capture = fault.capture_unmap_ranges();
            let refused = lifecycle_claim(&mut trace, owner, p, 1, true, none, -1);
            let leaked = capture.all().and_then(|(ranges, count)| (count != 0).then(|| ranges[count - 1]));
            drop(capture);
            let failed_cleanup = fault.secondary_observed() >= 1;
            fault.set(fault::Plan::disabled());
            assert!(!refused.is_some());
            trace.emit_bool(failed_cleanup);
            if failed_cleanup {
                let (address, length) = leaked.expect("the failed cleanup range was recorded");
                // SAFETY: the leaked range is represented by no owner.
                unsafe { crabc_core::mm::munmap_raw(address as *mut u8, length) }
                    .expect("fixture teardown of the leaked reservation");
            }
            let mut later = lifecycle_claim(&mut trace, owner, p, 1, true, none, -1);
            assert!(later.is_some());
            lifecycle_release(&mut trace, owner, &mut later);
        }

        // 23. The THP advice of a fresh arena reservation (see the C
        // fixture). At the default allow_thp=1 Rust advises MADV_NOHUGEPAGE,
        // the recorded CRABC-MI-ARENA-RESERVATION-NO-THP difference.
        trace.marker(23);
        for (allow_thp, eager) in [(1, 1), (1, 0), (2, 1), (2, 0), (0, 1)] {
            let mut options = lifecycle_options(32 * 1024, eager, false, false);
            options.set(VmOption::AllowThp, allow_thp);
            let owner = LifecycleOwner {
                process: process_with_options(options),
                config: MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false),
                backing: backing(),
            };
            let capture = fault.capture_advice_range();
            let mut item = lifecycle_claim(&mut trace, owner, owner.process, 1, true, none, -1);
            let (ranges, count) = capture.ranges().expect("at most four advisory calls");
            drop(capture);
            assert!(item.is_some());
            trace.emit(-2300);
            trace.emit(allow_thp);
            trace.emit(eager);
            trace.emit_bool(count > 0);
            trace.emit(if count > 0 { i64::from(ranges[count - 1].2) } else { -1 });
            trace.emit_bool(ranges[..count].iter().all(|range| range.2 == ranges[0].2));
            lifecycle_release(&mut trace, owner, &mut item);
        }

        trace.marker(24);
    }

    /// Rust half of the M2 failed-reservation warning differential
    /// (`compat/allocator/m2_reservation_warnings_x86_64.c`): the same three
    /// `mi_reserve_os_memory_ex2` failures under `show_errors`, printing each
    /// return code and its TID-normalized output fragments as hex.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn emit_m2_reservation_warnings_c_rust_trace() {
        static CAPTURE: std::sync::Mutex<std::vec::Vec<std::vec::Vec<u8>>> =
            std::sync::Mutex::new(std::vec::Vec::new());
        unsafe extern "C" fn capture(message: *const core::ffi::c_char) {
            // SAFETY: the output owner passes a non-null NUL-terminated fragment.
            let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes().to_vec();
            if !bytes.is_empty() { CAPTURE.lock().unwrap().push(bytes); }
        }
        fn print_case(name: &str, rc: i32) {
            let thread = std::format!("0x{:02X}", crate::os::thread_pointer_identity());
            let fragments: std::vec::Vec<std::string::String> = CAPTURE.lock().unwrap().drain(..)
                .map(|fragment| {
                    let text = std::string::String::from_utf8(fragment).expect("source messages are ASCII");
                    text.replace(&thread, "0xTID").bytes().map(|byte| std::format!("{byte:02x}")).collect()
                })
                .collect();
            std::println!("m2.reservation_warnings.{name}.rc={rc}");
            std::println!("m2.reservation_warnings.{name}.messages={}", fragments.join(":"));
        }
        fn reserve(size: usize, commit: bool, allow_large: bool) -> i32 {
            match crate::subproc::main_heaps::native_reserve_os_memory(size, commit, allow_large, false) {
                Ok(_) => 0,
                Err(_) => crabc_core::Errno::NOMEM.raw(),
            }
        }
        crate::test_process::run_in_fresh_process(
            "arena::owned::tests::emit_m2_reservation_warnings_c_rust_trace",
            || {
                // The fresh child strips inherited source options; this one
                // is its own fixture input, set before startup reads it.
                std::env::set_var("mimalloc_show_errors", "1");
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(capture)
                }));
                CAPTURE.lock().unwrap().clear();
                print_case("unmappable_committed", reserve(1 << 62, true, false));
                print_case("unmappable_reserved", reserve(1 << 62, false, true));
                print_case("too_small", reserve(100, true, false));
            },
        );
    }
}

#[cfg(test)]
pub(crate) use tests::m2_external_callback_trace;
