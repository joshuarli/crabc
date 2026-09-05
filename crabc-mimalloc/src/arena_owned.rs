// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: pinned mimalloc v3.5.0 src/arena.c:1573-1611,1676-1912.

//! Process-owned backing for the source arena registry.
//!
//! Unlike the historical one-arena `ProcessSharedArenaStorage` sidecar, this
//! is the arena group of one `MainSubprocess`: one reserve lock, one registry,
//! and the exact OS owners of its published arenas. This Rust ownership group
//! is not an assertion about the complete C `mi_subproc_t` layout. Publication
//! retains backing for process lifetime; quiescent subprocess destruction is
//! a separate caller and must not infer authority from an ordinary arena view.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crabc_core::Errno;

use super::{ArenaId, ArenaRegistry, ArenaReservationPlan, ArenaSearch, ArenaSliceClaim, CommitHook, ManageArenaError, ManagedExternalRegion};
use crate::config::{ARENA_ALIGNMENT, ARENA_MAX_SIZE, ARENA_MIN_SIZE, MAX_ARENAS};
use crate::lock::PrivateLock;
use crate::os::{MapAccess, Mapping, MemoryConfig, NormalOsAllocation, VmProcess};
use crate::types::{Arena, MemoryId, MemoryKind};

const EMPTY: u8 = 0;
const INITIALIZING: u8 = 1;
const PUBLISHED: u8 = 2;
const RETAINED: u8 = 3;

struct ArenaMappingSlot {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<OwnedArenaMapping>>,
    #[cfg(test)]
    initializing_reads: core::sync::atomic::AtomicUsize,
}

impl ArenaMappingSlot {
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
    unsafe fn initialized(&self) -> Option<&OwnedArenaMapping> {
        let state = self.state.load(Ordering::Acquire);
        if state == EMPTY { return None; }
        #[cfg(test)]
        if state == INITIALIZING { self.initializing_reads.fetch_add(1, Ordering::Relaxed); }
        Some(unsafe { (&*self.value.get()).assume_init_ref() })
    }
}

pub(super) struct OwnedArenaMapping {
    mapping: Mapping,
    memory: MemoryId,
    pub(super) process: VmProcess<'static>,
    pub(super) config: MemoryConfig,
    release_error: Option<Errno>,
}

impl OwnedArenaMapping {
    pub(super) fn commit(&self, start: *mut u8, size: usize, already_committed: usize) -> bool {
        let Ok(base) = self.mapping.base() else { return false; };
        let Some(offset) = (start as usize).checked_sub(base as usize) else { return false; };
        self.mapping.commit_for_process(self.process, offset, size, already_committed).is_ok()
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
    registry: ArenaRegistry,
    slots: [ArenaMappingSlot; MAX_ARENAS],
}

// SAFETY: the lock exclusively owns all unpublished slot transitions. Once
// published, slots and mappings are never moved or released. Their shared VM
// transitions touch only caller-owned source ranges and atomic statistics.
unsafe impl Sync for ProcessArenaBacking {}

impl ProcessArenaBacking {
    pub(crate) const fn new() -> Self {
        Self {
            reserve_lock: PrivateLock::new(),
            registry: ArenaRegistry::new(core::ptr::null_mut()),
            slots: [const { ArenaMappingSlot::new() }; MAX_ARENAS],
        }
    }

    #[inline]
    pub(crate) fn registry(&self) -> &ArenaRegistry { &self.registry }

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
                let owner = self.mapping_for_arena(view.arena())?;
                view.try_claim_slices_with_owner(search.requested, slice_count, commit,
                    search.thread_sequence, Some(owner))
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
        let fail = |error, mapping| ProcessArenaInstallFailure { error, mapping, memory, process };
        let start = match mapping.base() {
            Ok(start) => start,
            Err(_) => return Err(fail(ManageArenaError::InvalidRegion, mapping)),
        };
        let size = match mapping.length() {
            Ok(size) => size,
            Err(_) => return Err(fail(ManageArenaError::InvalidRegion, mapping)),
        };
        let exact = memory.os_memory().is_some_and(|os| os.base == start && os.size == size);
        if !exact || memory.kind() != MemoryKind::Os
            || memory.is_pinned() != mapping.is_large()
            || memory.initially_zero() != mapping.initially_zero()
            || memory.initially_committed() != mapping.initially_committed()
            || !(ARENA_MIN_SIZE..=ARENA_MAX_SIZE).contains(&managed_size)
            || managed_size > size || (start as usize) % ARENA_ALIGNMENT != 0
        {
            return Err(fail(ManageArenaError::InvalidRegion, mapping));
        }
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) == EMPTY { continue; }
            let owner = unsafe { slot.initialized().unwrap() };
            if !core::ptr::eq(owner.process.policy(), process.policy())
                || !core::ptr::eq(owner.process.subprocess(), process.subprocess())
                || owner.config != config
            {
                return Err(fail(ManageArenaError::InvalidRegion, mapping));
            }
            break;
        }
        if self.registry.count() == 0 {
            // SAFETY: this lock is the only normal registry publisher.
            if !unsafe { self.registry.bind_subprocess_before_publication(process.subprocess().as_ptr()) } {
                return Err(fail(ManageArenaError::InvalidRegion, mapping));
            }
        } else if !self.registry.is_bound_to_subprocess(process.subprocess().as_ptr()) {
            return Err(fail(ManageArenaError::InvalidRegion, mapping));
        }
        let Some(slot) = self.slots.iter().find(|slot| slot.state.load(Ordering::Relaxed) == EMPTY) else {
            return Err(fail(ManageArenaError::RegistryFull, mapping));
        };
        unsafe { (*slot.value.get()).write(OwnedArenaMapping { mapping, memory, process, config, release_error: None }); }
        slot.state.store(INITIALIZING, Ordering::Release);
        let hook = CommitHook::new(commit_owned_arena, (slot as *const ArenaMappingSlot).cast_mut().cast());
        // The internal hook carries Rust ownership, not an externally supplied
        // source callback. Its zero-already-committed path is exactly the OS
        // commit used by source arena initialization and page metadata.
        let result = unsafe {
            super::manage_in_place(&self.registry, start, managed_size, config.page_size(),
                memory.initially_committed(), numa_node, exclusive, Some(hook), memory)
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
                Err(fail(error, owner.mapping))
            }
        }
    }

    /// Retrieves only backing already published by this exact process owner.
    /// The arena must be live; this does not authorize access to arbitrary
    /// addresses or transfer the full mapping's destruction capability.
    unsafe fn mapping_for_arena(&self, arena: &Arena) -> Option<&OwnedArenaMapping> {
        if !self.registry.is_bound_to_subprocess(arena.subprocess) { return None; }
        let parent = if arena.parent.is_null() { arena } else { unsafe { &*arena.parent } };
        let memory = parent.memid.os_memory()?;
        if let Some(owner) = self.published_mapping(memory.base, memory.size) {
            return Some(owner);
        }
        // Source registry publication can precede this target slot's final
        // PUBLISHED store. On this miss only, wait for the one initializing
        // publisher to finish and recheck. Never borrow unrelated temporary
        // slots: their failed manage may move/drop/reuse the contained owner.
        let _guard = self.reserve_lock.lock().ok()?;
        self.published_mapping(memory.base, memory.size)
    }

    fn published_mapping(&self, base: *mut u8, size: usize) -> Option<&OwnedArenaMapping> {
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
            let result = unsafe { self.reserve_one_locked(process, config, size, plan.access, allow_large) };
            if let Some(id) = result { return Some(id); }
            if plan.adjust_committed { stats.committed_adjust_increase(size); }
            if self.retained_release_error().is_some() { return None; }
        }
        None
    }

    /// Source `mi_reserve_os_memory_ex2` regular aligned map/manage/free.
    /// A failed map trim or unpublished manage cleanup retains the exact
    /// still-active owner in a terminal slot, never an untracked raw address.
    unsafe fn reserve_one_locked(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        size: usize, access: MapAccess, allow_large: bool,
    ) -> Option<ArenaId> {
        // Reserve a cleanup slot before acquiring any new OS ownership.
        let slot = self.slots.iter().find(|slot| slot.state.load(Ordering::Relaxed) == EMPTY)?;
        let allocation = NormalOsAllocation::allocate_aligned_base_for_process(process, config,
            size, ARENA_ALIGNMENT, access, allow_large, None);
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
        unsafe { (*slot.value.get()).write(OwnedArenaMapping {
            mapping, memory, process, config, release_error: Some(error),
        }); }
        slot.state.store(RETAINED, Ordering::Release);
        None
    }
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
    let Some(slot) = (unsafe { argument.cast::<ArenaMappingSlot>().as_ref() }) else { return false; };
    let Some(owner) = (unsafe { slot.initialized() }) else { return false; };
    let Ok(base) = owner.mapping.base() else { return false; };
    let Some(offset) = (start as usize).checked_sub(base as usize) else { return false; };
    let Ok(length) = owner.mapping.length() else { return false; };
    if offset.checked_add(size).is_none_or(|end| end > length) { return false; }
    if !is_zero.is_null() { unsafe { is_zero.write(false); } }
    if commit {
        owner.mapping.commit_for_process(owner.process, offset, size, 0).is_ok()
    } else {
        // This arm's source result means "needs recommit", not syscall
        // success. Native Linux retains accessibility even when its advisory
        // discard reports an error. The complete policy purge caller also
        // supplies allow_reset and already-committed accounting separately.
        let _ = owner.mapping.decommit_for_process(owner.process, offset, size, size);
        false
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::{ArenaId, ArenaView};
    use crate::config::{ARENA_SLICE_SIZE, KIB, MIB, VmOption, VmOptions, VmOptionEnvironment};
    use crate::os::{MapAccess, NormalOsAllocation, PageSize, VmPolicy, fault};
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
        VmProcess::new(policy, MainSubprocess::test_static_owner())
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
        let owner = unsafe { backing.mapping_for_arena(view.arena()) }.unwrap();
        assert_eq!(owner.mapping.length(), Ok(64 * MIB));
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
        let found = unsafe { backing.mapping_for_arena(view.arena()) };
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
            unsafe { backing.mapping_for_arena(arena) }.map(|owner| owner.mapping.base().unwrap() as usize)
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

    #[test]
    fn failed_owned_metadata_commit_returns_the_unpublished_mapping() {
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
        let owner = unsafe { mixed.mapping_for_arena(view.arena()) }.unwrap();
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
