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
//! retains backing for process lifetime; quiescent subprocess destruction is
//! a separate caller and must not infer authority from an ordinary arena view.

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

#[path = "arena_huge.rs"]
mod huge;
pub(crate) use huge::{HugeArenaReserveError, HugeArenaCleanupError, StartupArenaReservationOutcomes};

const EMPTY: u8 = 0;
const INITIALIZING: u8 = 1;
const PUBLISHED: u8 = 2;
const RETAINED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArenaPageCommitError {
    InvalidPageArea,
    Mapping(Errno),
}

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
    /// PUBLISHED and RETAINED values are immutable for process lifetime.
    /// INITIALIZING requires the reserve lock or the callback capability for
    /// this exact slot: another arena's publication never protects it against
    /// initialization failure moving the mapping out or reusing the slot.
    unsafe fn initialized(&self) -> Option<&OwnedArenaAllocation> {
        let state = self.state.load(Ordering::Acquire);
        if state == EMPTY { return None; }
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

pub(super) struct OwnedArenaAllocation {
    allocation: ArenaBacking,
    memory: MemoryId,
    pub(super) process: VmProcess<'static>,
    pub(super) config: MemoryConfig,
    release_error: Option<Errno>,
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
                    .commit_for_process(self.process, offset, size, already_committed)
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
                .commit_for_process(self.process, offset, size, 0)
                .map(|_| ())
                .map_err(ArenaPageCommitError::Mapping),
            ArenaBacking::External(lease) => {
                if !lease.contains_covering_page_area(self.config.page_size(), start, size) {
                    return Err(invalid);
                }
                // SAFETY: the outer page owner exclusively owns the direct
                // prefix; the lease check above proves full source covering
                // range containment without acquiring unmap authority.
                unsafe { self.process.commit_direct_page_area(self.config.page_size(), start, size) }
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
/// of its final mapping slot. Published slots are immutable, and no method
/// here releases a published mapping while a page/bitmap view can exist.
pub(crate) struct ProcessArenaBacking {
    reserve_lock: PrivateLock,
    huge_reservation_lock: PrivateLock,
    huge_cleanup_retained: AtomicBool,
    huge_cleanup: UnsafeCell<Option<huge::PendingHugeCleanup>>,
    registry: ArenaRegistry,
    slots: [ArenaAllocationSlot; MAX_ARENAS],
    purge_expire: crate::atomic::AtomicI64Value,
    arena_purges: crate::statistics::StatCounter,
}

// SAFETY: the lock exclusively owns all unpublished slot transitions. Once
// published, slots and mappings are never moved or released. Their shared VM
// transitions touch only caller-owned source ranges and atomic statistics.
// The separate huge reservation lock exclusively owns pending cleanup and its
// metadata tracker. Its lock may acquire reserve_lock, never the reverse; the
// metadata allocator is called only after reserve_lock has been released.
unsafe impl Sync for ProcessArenaBacking {}

impl ProcessArenaBacking {
    pub(crate) const fn new() -> Self {
        Self {
            reserve_lock: PrivateLock::new(),
            huge_reservation_lock: PrivateLock::new(),
            huge_cleanup_retained: AtomicBool::new(false),
            huge_cleanup: UnsafeCell::new(None),
            registry: ArenaRegistry::new(core::ptr::null_mut()),
            slots: [const { ArenaAllocationSlot::new() }; MAX_ARENAS],
            purge_expire: crate::atomic::AtomicI64Value::new(0),
            arena_purges: crate::statistics::StatCounter::new(),
        }
    }

    #[inline]
    pub(crate) fn registry(&self) -> &ArenaRegistry { &self.registry }

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
        if extra != 0 { owner.process.subprocess().vm_statistics().committed_decrease(extra); }
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
            if !core::ptr::eq(owner.process.policy(), process.policy())
                || !core::ptr::eq(owner.process.subprocess(), process.subprocess())
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
        &'static self, search: ArenaSearch, slice_count: usize, alignment: usize, commit: bool,
    ) -> Option<ArenaSliceClaim<'static>> {
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
    ) -> Result<ManagedExternalRegion, ProcessArenaInstallFailure> {
        let _guard = match self.reserve_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(ProcessArenaInstallFailure {
                error: ManageArenaError::RegistryFull, mapping, memory, process,
            }),
        };
        unsafe { self.install_owned_os_mapping_locked(process, config, managed_size, mapping, memory, numa_node, exclusive) }
    }

    /// The caller holds reserve_lock through every slot and registry write.
    unsafe fn install_owned_os_mapping_locked(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        managed_size: usize, mapping: Mapping, memory: MemoryId, numa_node: i32, exclusive: bool,
    ) -> Result<ManagedExternalRegion, ProcessArenaInstallFailure> {
        let result = unsafe { self.install_owned_allocation_locked(process, config, managed_size,
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
                process,
                config,
                release_error: None,
            });
        }
        slot.state.store(INITIALIZING, Ordering::Release);
        drop(guard);

        let numa_node = if numa_node < 0 && process.policy().arena_is_numa_local() {
            process.current_numa_node() as i32
        } else { numa_node };
        let result = unsafe {
            super::manage_in_place_with_publisher(
                &self.registry,
                start,
                managed_size,
                config.page_size(),
                memory.initially_committed(),
                numa_node,
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
        unsafe { self.install_owned_allocation_locked(process, config, size,
            ArenaBacking::Huge(allocation), memory, numa_node, exclusive) }
            .map_err(|(error, owner)| {
                let ArenaBacking::Huge(allocation) = owner else { unreachable!() };
                ProcessHugeArenaInstallFailure { error, allocation }
            })
    }

    /// Caller holds reserve_lock until slot publication or complete rollback.
    unsafe fn install_owned_allocation_locked(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        managed_size: usize, allocation: ArenaBacking, memory: MemoryId,
        numa_node: i32, exclusive: bool,
    ) -> Result<ManagedExternalRegion, (ManageArenaError, ArenaBacking)> {
        let fail = |error, allocation| (error, allocation);
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
        if !exact || !valid_kind || managed_size < ARENA_MIN_SIZE
            || managed_size > size || (start as usize) % ARENA_ALIGNMENT != 0 {
            return Err(fail(ManageArenaError::InvalidRegion, allocation));
        }
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) == EMPTY { continue; }
            let owner = unsafe { slot.initialized().unwrap() };
            if !core::ptr::eq(owner.process.policy(), process.policy())
                || !core::ptr::eq(owner.process.subprocess(), process.subprocess())
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
        unsafe { (*slot.value.get()).write(OwnedArenaAllocation { allocation, memory, process, config, release_error: None }); }
        slot.state.store(INITIALIZING, Ordering::Release);
        let hook = (memory.kind() == MemoryKind::Os).then(||
            CommitHook::new(commit_owned_arena, (slot as *const ArenaAllocationSlot).cast_mut().cast()));
        // The internal hook carries Rust ownership, not an externally supplied
        // source callback. Its zero-already-committed path is exactly the OS
        // commit used by source arena initialization and page metadata.
        let numa_node = if numa_node < 0 && process.policy().arena_is_numa_local() {
            process.current_numa_node() as i32
        } else { numa_node };
        let result = unsafe {
            super::manage_in_place(&self.registry, start, managed_size, config.page_size(),
                memory.initially_committed(), numa_node, exclusive, hook, memory)
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
            // SAFETY: a PUBLISHED slot is never moved, replaced or released.
            let owner = unsafe { slot.initialized()? };
            let stored = owner.memory.os_memory()?;
            (stored.base == base && stored.size == size).then_some(owner)
        })
    }

    /// Returns the source failed-cleanup owner without granting a second
    /// syscall attempt. C accounts a failed free once; silently retrying it
    /// would apply the same decrement twice. A retained failure therefore
    /// prevents further automatic reservations through this owner.
    pub(crate) fn retained_release_error(&self) -> Option<Errno> {
        self.slots.iter().find_map(|slot| {
            if slot.state.load(Ordering::Acquire) != RETAINED { return None; }
            unsafe { slot.initialized() }?.release_error
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
    /// configuration. `search`'s requested arena and Heap/thread inputs must
    /// describe live source owners. The returned claim retains its exact
    /// range until explicit release; no registry destruction may overlap.
    pub(crate) unsafe fn try_allocate_slices(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        search: ArenaSearch, slice_count: usize, alignment: usize, commit: bool,
    ) -> Option<ArenaSliceClaim<'static>> {
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
            if self.retained_release_error().is_some() { return None; }
            if observed_count == self.registry.count() {
                let _ = unsafe { self.reserve_locked(process, config, requested_size, search.allow_pinned) };
            }
        }
        unsafe { self.try_find_free(search, slice_count, alignment, commit) }
    }

    /// Source `mi_arena_reserve`, called only under the source reserve lock.
    unsafe fn reserve_locked(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        requested_size: usize, allow_large: bool,
    ) -> Option<ArenaId> {
        let policy = process.policy();
        let plan = ArenaReservationPlan::new(config, self.registry.count(), requested_size,
            policy.arena_reserve_bytes(), policy.arena_eager_commit(), policy.allow_large_os_pages())?;
        for size in [Some(plan.primary_size), plan.fallback_size].into_iter().flatten() {
            let stats = process.subprocess().vm_statistics();
            if plan.adjust_committed { stats.committed_adjust_decrease(size); }
            let result = unsafe { self.reserve_one_locked(process, config, size, plan.access, allow_large, None) };
            if let Some(id) = result { return Some(id); }
            if plan.adjust_committed { stats.committed_adjust_increase(size); }
            if self.retained_release_error().is_some() { return None; }
        }
        None
    }

    /// Explicit source regular reservation used after huge startup options.
    /// It may span multiple source arenas; the allocation owner retains any
    /// suffix after partial registry publication.
    ///
    /// # Safety
    /// This is the process's sole arena group with immutable configuration.
    /// Published ranges remain process-lived, and no teardown overlaps. Any
    /// random image is exclusively borrowed from the current default Theap.
    pub(crate) unsafe fn reserve_os_memory_for_process(
        &'static self, process: VmProcess<'static>, config: MemoryConfig, size: usize,
        access: MapAccess, allow_large: bool, random: Option<&mut crate::random::TheapRandomImage>,
    ) -> Result<ArenaId, Errno> {
        if size > crate::config::MAX_ALLOC_SIZE { return Err(Errno::NOMEM); }
        let size = size.checked_add(crate::config::ARENA_SLICE_SIZE - 1)
            .map(|size| size & !(crate::config::ARENA_SLICE_SIZE - 1))
            .filter(|size| *size <= crate::config::MAX_ALLOC_SIZE).ok_or(Errno::NOMEM)?;
        let _guard = self.reserve_lock.lock()?;
        if self.retained_release_error().is_some() { return Err(Errno::NOMEM); }
        unsafe { self.reserve_one_locked(process, config, size, access, allow_large, random) }.ok_or(Errno::NOMEM)
    }

    /// Source `mi_reserve_os_memory_ex2` regular aligned map/manage/free.
    /// A failed map trim or unpublished manage cleanup retains the exact
    /// still-active owner in a terminal slot, never an untracked raw address.
    unsafe fn reserve_one_locked(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        size: usize, access: MapAccess, allow_large: bool, random: Option<&mut crate::random::TheapRandomImage>,
    ) -> Option<ArenaId> {
        // Reserve a cleanup slot before acquiring any new OS ownership.
        let slot = self.slots.iter().find(|slot| slot.state.load(Ordering::Relaxed) == EMPTY)?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            size, ARENA_ALIGNMENT, access, allow_large, random);
        let (mut mapping, memory, already_failed_cleanup) = match allocation {
            Ok(allocation) => {
                let (mapping, memory) = allocation.into_mapping_and_memory();
                match unsafe { self.install_owned_os_mapping_locked(process, config, size, mapping, memory, -1, false) } {
                    Ok(managed) => return Some(managed.arena_id()),
                    Err(failure) => { let (mapping, memory, _) = failure.into_parts(); (mapping, memory, None) }
                }
            }
            Err(failure) => {
                let error = failure.error();
                let mapping = failure.into_mapping()?;
                let memory = MemoryId::os(mapping.base().expect("retained OS failure owns an active mapping"),
                    mapping.length().expect("retained OS failure owns its complete length"),
                    mapping.initially_committed(), mapping.initially_zero(), mapping.is_large());
                (mapping, memory, Some(error))
            }
        };
        let error = match already_failed_cleanup {
            Some(error) => error,
            None => {
                let commit_size = if memory.initially_committed() {
                    memory.os_memory().expect("unpublished arena failure retains OS provenance").size
                } else { 0 };
                match mapping.unmap_for_process(process, commit_size, false) {
                    Ok(()) => return None,
                    Err(error) => error,
                }
            }
        };
        unsafe { (*slot.value.get()).write(OwnedArenaAllocation {
            allocation: ArenaBacking::Regular(mapping), memory, process, config, release_error: Some(error),
        }); }
        slot.state.store(RETAINED, Ordering::Release);
        None
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
pub(crate) struct ProcessArenaInstallFailure {
    error: ManageArenaError,
    mapping: Mapping,
    memory: MemoryId,
    process: VmProcess<'static>,
}

impl ProcessArenaInstallFailure {
    pub(crate) const fn error(&self) -> ManageArenaError { self.error }

    pub(crate) fn into_parts(self) -> (Mapping, MemoryId, VmProcess<'static>) {
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
            mapping.commit_for_process(owner.process, offset, size, 0).is_ok())
    } else {
        // This arm's source result means "needs recommit", not syscall
        // success. Native Linux retains accessibility even when its advisory
        // discard reports an error. The complete policy purge caller also
        // supplies allow_reset and already-committed accounting separately.
        let Some(mapping) = owner.allocation.regular() else { return false; };
        let _ = mapping.decommit_for_process(owner.process, offset, size, size);
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
        let process = process();
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
        let lease = failure
            .into_returned_lease()
            .expect("the unpublished callback lease returns to its caller");
        assert_eq!(lease.base(), base);

        trace.commit_success.store(true, Ordering::Release);
        trace.commit_zero_output.store(true, Ordering::Release);
        install_external(backing, process, ARENA_MIN_SIZE, lease);
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
            .bind_detached_for_main_subprocess(process.subprocess())
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
            17 * crate::config::GIB, MapAccess::Committed, false, None) }.unwrap();
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

    #[test]
    fn failed_reservation_cleanup_is_retained_without_second_accounting_or_fallback() {
        let fault = fault::install(fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaEagerCommit, 0);
        let process = process_with_options(options);
        let backing = backing();
        fault.set(fault::Plan::at_pair(fault::Point::Commit, 1, fault::Point::Unmap, 1, Errno::NOMEM));
        assert!(unsafe { backing.try_allocate_slices(process, config(), search(ArenaId::none()),
            1, ARENA_SLICE_SIZE, true) }.is_none());
        assert_eq!(backing.registry().count(), 0);
        assert_eq!(backing.retained_release_error(), Some(Errno::NOMEM));
        let before = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::disabled());
        assert!(unsafe { backing.try_allocate_slices(process, config(), search(ArenaId::none()),
            1, ARENA_SLICE_SIZE, true) }.is_none());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
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
    fn source_purge_guard_excludes_collection_without_losing_scheduled_work() {
        let _fault = fault::install(fault::Plan::disabled());
        let backing = backing();
        let process = process();
        let id = install(backing, process, MapAccess::Reserved);
        let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, true) }.unwrap();
        assert!(claim.release());
        let before = process.subprocess().vm_statistics().snapshot();
        let guard = crate::atomic::try_atomic_guard(&purge::PURGE_GUARD).unwrap();
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
        assert_eq!(crate::atomic::i64_load_relaxed(&backing.arena_purges.total), 0);
        drop(guard);
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
        assert_eq!(process.subprocess().vm_statistics().snapshot().purge_calls, before.purge_calls + 1);
        assert_eq!(crate::atomic::i64_load_relaxed(&backing.arena_purges.total), 1);
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
        assert_eq!(crate::atomic::i64_load_relaxed(&backing.arena_purges.total), 1);
        assert!(unsafe { backing.collect_purge(process, config(), true, true, 2) });
        assert!(arenas.iter().all(|id| expiry(*id) == 0));
        assert_eq!(crate::atomic::i64_load_relaxed(&backing.arena_purges.total), 3);
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
            let id = install(backing, process, MapAccess::Reserved);
            let claim = unsafe { backing.try_find_free(search(id), 2, ARENA_SLICE_SIZE, !mixed) }.unwrap();
            let start = claim.slice_index();
            let view = unsafe { ArenaView::from_ptr(id.as_ptr()) }.unwrap();
            if mixed {
                let owner = unsafe { backing.allocation_for_arena(view.arena()) }.unwrap();
                assert!(owner.commit(claim.start(), ARENA_SLICE_SIZE, 0));
                unsafe { view.slices_committed() }.unwrap().set_range(start, 1).unwrap();
            }
            let before = process.subprocess().vm_statistics().snapshot();
            assert!(claim.release());
            assert!(unsafe { backing.collect_purge(process, config(), true, true, 0) });
            let after = process.subprocess().vm_statistics().snapshot();
            for value in [after.purge_calls - before.purge_calls, after.purged - before.purged,
                after.reset_calls - before.reset_calls, after.reset - before.reset,
                after.committed_current - before.committed_current,
                unsafe { view.slices_committed() }.unwrap().popcount_range(start, 2).unwrap() as i64,
                crate::atomic::i64_load_relaxed(&backing.arena_purges.total)] {
                std::println!("m2.arena.purge.{field}={value}"); field += 1;
            }
        }
        assert_eq!(field, 28);
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
}

#[cfg(test)]
pub(crate) use tests::m2_external_callback_trace;
