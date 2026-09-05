// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
// Source: pinned mimalloc v3.5.0 src/arena.c:2167-2222 and src/os.c:772-862.

//! Huge reservation, source cleanup, and retained failed primitive ownership.
//!
//! The source ignores individual huge-free failures; Rust preserves that full
//! pass but retains its failed page set in detached metadata. Tracking is
//! allocated only after an unpublished manage rejection, outside reserve_lock.
//! If tracking cannot be obtained, the complete allocation remains owned and
//! no primitive free has started. This is safety bookkeeping, not a new huge
//! allocation policy or a fixed limit on the number of requested pages.

use core::pin::Pin;
use core::sync::atomic::Ordering;

use crabc_core::Errno;

use super::ProcessArenaBacking;
use crate::arena::{ArenaId, ManageArenaError};
use crate::meta::{MetaAllocation, MetaAllocator, MetaError, MetaRelease, MetaReleaseFailure};
use crate::os::{HugeOsAllocation, HugeOsAllocationOutcome, HugeOsAllocationStop,
    HugeOsRawReleaseRetry, HugeOsRejectedPrimitive, HugeOsReleaseFailure, MemoryConfig, VmProcess};
use crate::random::TheapRandomImage;

/// Source startup ignores reservation errors and continues in huge-before-
/// regular order. Retain those outcomes without changing readiness policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartupArenaReservationOutcomes {
    pub(crate) huge: Option<Result<(), Errno>>,
    pub(crate) regular: Option<Result<(), Errno>>,
}

impl StartupArenaReservationOutcomes {
    pub(crate) const fn empty() -> Self { Self { huge: None, regular: None } }
}

/// Distinct source reservation result and Rust retained-cleanup diagnosis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HugeArenaReserveError {
    Lock(Errno),
    PendingCleanup,
    Unavailable(HugeOsAllocationStop),
    Manage(ManageArenaError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HugeArenaCleanupError {
    Lock(Errno),
    Metadata(MetaError),
    Primitive(Errno),
    TrackerCapacity,
}

/// Fresh detached metadata selected exclusively as huge-free tracking words.
/// Its only typed projections are transient, borrow this linear capability,
/// and never outlive a retry or storage-return transition.
struct HugeReleaseMetadata {
    allocation: MetaAllocation<'static>,
    words: usize,
}

impl HugeReleaseMetadata {
    fn allocate(metadata: Pin<&'static MetaAllocator>, process: VmProcess<'static>,
        config: MemoryConfig, words: usize) -> Result<Self, MetaError> {
        let bytes = words.checked_mul(core::mem::size_of::<usize>())
            .filter(|bytes| *bytes != 0).ok_or(MetaError::AllocationUnavailable)?;
        let allocation = metadata.zalloc_for_main_subprocess(config, process.subprocess(), bytes)?;
        // Ordinary metadata zalloc guarantees the allocator's word alignment;
        // the fresh capability has never been exposed as another typed role.
        debug_assert_eq!(allocation.pointer().as_ptr().addr() % core::mem::align_of::<usize>(), 0);
        Ok(Self { allocation, words })
    }

    fn release(self) -> Result<(), MetaReleaseFailure> {
        MetaRelease::Malloc(self.allocation).release()
    }
}

impl AsRef<[usize]> for HugeReleaseMetadata {
    fn as_ref(&self) -> &[usize] {
        // SAFETY: this private owner was built from an exact fresh zeroed
        // metadata request. Its live capability cannot be freed while borrowed.
        unsafe { core::slice::from_raw_parts(self.allocation.pointer().as_ptr().cast(), self.words) }
    }
}

impl AsMut<[usize]> for HugeReleaseMetadata {
    fn as_mut(&mut self) -> &mut [usize] {
        // SAFETY: only this unique capability can project these words; no raw
        // reference is stored by the retry token or exposed outside this module.
        unsafe { core::slice::from_raw_parts_mut(self.allocation.pointer().as_ptr().cast(), self.words) }
    }
}

enum HugePrefixCleanup {
    Unreleased { allocation: HugeOsAllocation<'static>, tracker: Option<HugeReleaseMetadata> },
    FailedPages(HugeOsRawReleaseRetry<'static, HugeReleaseMetadata>),
    TrackerRelease(MetaReleaseFailure),
}

pub(super) struct PendingHugeCleanup {
    prefix: Option<HugePrefixCleanup>,
    rejected: Option<HugeOsRejectedPrimitive>,
    metadata: Pin<&'static MetaAllocator>,
    config: MemoryConfig,
    error: HugeArenaCleanupError,
}

impl PendingHugeCleanup {
    fn retain_tracker_failure(&mut self, failure: MetaReleaseFailure) {
        self.error = match &failure {
            MetaReleaseFailure::MallocRetryable { error, .. }
            | MetaReleaseFailure::MallocTerminal { error, .. } => HugeArenaCleanupError::Metadata(*error),
            MetaReleaseFailure::RegularOs { error, .. } => HugeArenaCleanupError::Primitive(*error),
        };
        self.prefix = Some(HugePrefixCleanup::TrackerRelease(failure));
    }

    fn release_tracker(&mut self, tracker: HugeReleaseMetadata) {
        if let Err(failure) = tracker.release() { self.retain_tracker_failure(failure); }
    }

    /// An initial cleanup never repeats the rejected primitive's already
    /// attempted adjustment-free. An explicit retry may revisit retained raw
    /// owners, and continues to the independent prefix even after an error.
    fn advance(&mut self, retry_existing: bool) {
        if retry_existing {
            if let Some(rejected) = self.rejected.take() {
                if let Err(rejected) = rejected.retry_raw_release() {
                    self.error = HugeArenaCleanupError::Primitive(rejected.error());
                    self.rejected = Some(rejected);
                }
            }
        }
        let Some(prefix) = self.prefix.take() else { return; };
        match prefix {
            HugePrefixCleanup::Unreleased { allocation, tracker } => {
                let tracker = match tracker {
                    Some(tracker) => tracker,
                    None => match HugeReleaseMetadata::allocate(self.metadata, allocation.process(),
                        self.config, allocation.release_tracking_words()) {
                        Ok(tracker) => tracker,
                        Err(error) => {
                            self.error = HugeArenaCleanupError::Metadata(error);
                            self.prefix = Some(HugePrefixCleanup::Unreleased { allocation, tracker: None });
                            return;
                        }
                    },
                };
                // SAFETY: HugeReleaseMetadata owns the same live, exclusive
                // buffer through every move. Only retry operations mutate it.
                match unsafe { allocation.release_with_tracker(tracker) } {
                    Ok(tracker) => self.release_tracker(tracker),
                    Err(HugeOsReleaseFailure::FailedPages(retry)) => {
                        self.error = HugeArenaCleanupError::Primitive(retry.source_error());
                        self.prefix = Some(HugePrefixCleanup::FailedPages(retry));
                    }
                    Err(HugeOsReleaseFailure::Tracking(failure)) => {
                        let (allocation, tracker) = failure.into_parts();
                        self.error = HugeArenaCleanupError::TrackerCapacity;
                        self.prefix = Some(HugePrefixCleanup::Unreleased { allocation, tracker: Some(tracker) });
                    }
                }
            }
            HugePrefixCleanup::FailedPages(retry) => match retry.retry_raw() {
                Ok(tracker) => self.release_tracker(tracker),
                Err(failure) => {
                    self.error = HugeArenaCleanupError::Primitive(failure.error());
                    self.prefix = Some(HugePrefixCleanup::FailedPages(failure.into_retry()));
                }
            },
            HugePrefixCleanup::TrackerRelease(failure) => match failure {
                MetaReleaseFailure::MallocRetryable { allocation, .. } => {
                    if let Err(failure) = MetaRelease::Malloc(allocation).release() {
                        self.retain_tracker_failure(failure);
                    }
                }
                terminal => self.prefix = Some(HugePrefixCleanup::TrackerRelease(terminal)),
            },
        }
    }

    fn is_empty(&self) -> bool { self.prefix.is_none() && self.rejected.is_none() }
}

impl ProcessArenaBacking {
    /// Pinned init.c:566-579 invokes huge reservations before its explicit
    /// regular reservation. Each error is observed here but does not prevent
    /// the next source option or process readiness.
    ///
    /// # Safety
    /// The caller owns initial process startup after main-thread attachment;
    /// the default random image and metadata/process bindings are exclusive
    /// and valid, and this process has not yet been made ready to clients.
    pub(crate) unsafe fn reserve_startup_options(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, mut random: Option<&mut TheapRandomImage>,
    ) -> StartupArenaReservationOutcomes {
        let mut results = StartupArenaReservationOutcomes::empty();
        let pages_option = process.policy().reserve_huge_os_pages();
        if pages_option != 0 {
            let pages = pages_option.clamp(0, 128 * 1024) as usize;
            let node = process.policy().reserve_huge_os_pages_at().clamp(-1, i32::MAX as i64) as i32;
            let timeout = pages * 500;
            let result = if node != -1 {
                unsafe { self.reserve_huge_at(process, config, metadata, pages, node,
                    timeout, false, random.as_deref_mut()) }.map(|_| ())
            } else {
                unsafe { self.reserve_huge_interleaved(process, config, metadata, pages, 0,
                    timeout, random.as_deref_mut()) }
            };
            results.huge = Some(result.map_err(|_| Errno::NOMEM));
        }
        let regular_kib = process.policy().reserve_os_memory_kib();
        if regular_kib > 0 {
            let size = (regular_kib as usize).wrapping_mul(crate::config::KIB);
            results.regular = Some(unsafe { self.reserve_os_memory_for_process(process, config,
                size, crate::os::MapAccess::Committed, true, random.as_deref_mut()) }.map(|_| ()));
        }
        results
    }

    /// Reserves and installs pinned `mi_reserve_huge_os_pages_at_ex` backing.
    /// Zero pages succeeds without NUMA lookup or allocation. A nonempty
    /// partial primitive prefix is a successful reservation if manage accepts
    /// it, even if the primitive loop stopped early.
    ///
    /// # Safety
    /// This is the process's sole arena group; metadata is its bound detached
    /// owner, config is immutable, and any random image is exclusively owned
    /// by the calling current Theap for the duration of this operation.
    pub(crate) unsafe fn reserve_huge_at(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, pages: usize, numa_node: i32,
        timeout_milliseconds: usize, exclusive: bool, random: Option<&mut TheapRandomImage>,
    ) -> Result<Option<ArenaId>, HugeArenaReserveError> {
        if pages == 0 { return Ok(None); }
        let _guard = self.huge_reservation_lock.lock().map_err(HugeArenaReserveError::Lock)?;
        if self.huge_cleanup_retained.load(Ordering::Acquire) {
            return Err(HugeArenaReserveError::PendingCleanup);
        }
        let numa_node = if numa_node < -1 { -1 } else if numa_node >= 0 {
            (numa_node as usize % process.policy().numa_node_count()) as i32
        } else { numa_node };
        let outcome = HugeOsAllocation::allocate_for_process(process, config, pages,
            numa_node, timeout_milliseconds as i64, random);
        unsafe { self.finish_huge_reservation(config, metadata, numa_node, exclusive, outcome) }
    }

    /// Caller holds huge_reservation_lock. Registry installation takes the
    /// ordinary reserve lock only for its publication; metadata cleanup runs
    /// after that lock has been released, so it can safely allocate backing.
    unsafe fn finish_huge_reservation(
        &'static self, config: MemoryConfig, metadata: Pin<&'static MetaAllocator>,
        numa_node: i32, exclusive: bool, outcome: HugeOsAllocationOutcome<'static>,
    ) -> Result<Option<ArenaId>, HugeArenaReserveError> {
        let (allocation, rejected, unavailable) = match outcome {
            HugeOsAllocationOutcome::Unavailable(stop) => return Err(HugeArenaReserveError::Unavailable(stop)),
            HugeOsAllocationOutcome::Allocated(allocation) => (Some(allocation), None, None),
            HugeOsAllocationOutcome::AllocatedWithRejectedPrimitive { allocation, rejected } =>
                (Some(allocation), Some(rejected), None),
            HugeOsAllocationOutcome::RejectedPrimitive(rejected) =>
                (None, Some(rejected), Some(HugeOsAllocationStop::NoncontiguousPrimitive)),
        };
        let mut pending = PendingHugeCleanup { prefix: None, rejected, metadata, config,
            error: HugeArenaCleanupError::Primitive(Errno::NOMEM) };
        if let Some(rejected) = &pending.rejected {
            pending.error = HugeArenaCleanupError::Primitive(rejected.error());
        }
        let result = match allocation {
            None => Err(HugeArenaReserveError::Unavailable(unavailable.unwrap())),
            Some(allocation) => match unsafe { self.install_owned_huge_allocation(config, allocation, numa_node, exclusive) } {
                Ok(managed) => Ok(Some(managed.arena_id())),
                Err(failure) => {
                    let error = failure.error();
                    pending.prefix = Some(HugePrefixCleanup::Unreleased {
                        allocation: failure.into_allocation(), tracker: None,
                    });
                    pending.advance(false);
                    Err(HugeArenaReserveError::Manage(error))
                }
            },
        };
        if !pending.is_empty() {
            // SAFETY: the huge lock owns this empty final cleanup slot. No
            // caller can replace it until explicit retry has consumed it.
            unsafe { *self.huge_cleanup.get() = Some(pending) };
            self.huge_cleanup_retained.store(true, Ordering::Release);
        }
        result
    }

    pub(crate) fn huge_cleanup_pending(&self) -> bool {
        self.huge_cleanup_retained.load(Ordering::Acquire)
    }

    /// Retries only exact retained owners. Primitive statistics are never
    /// repeated; terminal metadata release remains diagnostic state.
    pub(crate) fn retry_huge_cleanup(&'static self) -> Result<(), HugeArenaCleanupError> {
        let _guard = self.huge_reservation_lock.lock().map_err(HugeArenaCleanupError::Lock)?;
        // SAFETY: the held huge lock excludes all other owners of this slot.
        let Some(mut pending) = (unsafe { &mut *self.huge_cleanup.get() }).take() else { return Ok(()); };
        pending.advance(true);
        if pending.is_empty() {
            self.huge_cleanup_retained.store(false, Ordering::Release);
            Ok(())
        } else {
            let error = pending.error;
            unsafe { *self.huge_cleanup.get() = Some(pending) };
            Err(error)
        }
    }

    /// Source interleave policy: distribute the remainder to the earliest
    /// nodes and stop at the first node reservation error. Successful partial
    /// primitive prefixes count as success for that node, as in pinned C.
    ///
    /// # Safety
    /// The same process, metadata, configuration, and random-owner contract
    /// as reserve_huge_at applies across this complete source loop.
    pub(crate) unsafe fn reserve_huge_interleaved(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, pages: usize, numa_nodes: usize,
        timeout_milliseconds: usize, mut random: Option<&mut TheapRandomImage>,
    ) -> Result<(), HugeArenaReserveError> {
        if pages == 0 { return Ok(()); }
        reserve_huge_interleaved_with(pages, numa_nodes, process.policy().numa_node_count(),
            timeout_milliseconds, |pages, node, timeout| unsafe {
                self.reserve_huge_at(process, config, metadata, pages, node, timeout, false,
                    random.as_deref_mut()).map(|_| ())
            })
    }
}

fn reserve_huge_interleaved_with<E>(pages: usize, numa_nodes: usize, detected_nodes: usize,
    timeout: usize, mut reserve: impl FnMut(usize, i32, usize) -> Result<(), E>) -> Result<(), E> {
    if pages == 0 { return Ok(()); }
    let nodes = if numa_nodes > 0 && numa_nodes <= i32::MAX as usize { numa_nodes }
        else { detected_nodes.max(1) };
    let per_node = pages / nodes;
    let remainder = pages % nodes;
    let timeout_per = if timeout == 0 { 0 } else { (timeout / nodes).wrapping_add(50) };
    let mut remaining = pages;
    for node in 0..nodes {
        if remaining == 0 { break; }
        let node_pages = per_node + usize::from(node < remainder);
        reserve(node_pages, node as i32, timeout_per)?;
        remaining = remaining.saturating_sub(node_pages);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::config::{GIB, MAX_ARENAS, VmOption, VmOptionEnvironment, VmOptions};
    use crate::os::{fault, PageSize};
    use crate::process_init::ProcessMainInitializationStorage;
    use crate::process_page_map::ProcessPageMapStorage;

    fn fixture() -> (MemoryConfig, VmProcess<'static>, Pin<&'static MetaAllocator>) {
        let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false);
        let metadata = MetaAllocator::test_static_owner();
        let subprocess = metadata.test_default_subprocess();
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaReserve, 64 * 1024);
        options.set(VmOption::PurgeDelay, -1);
        let storage = ProcessMainInitializationStorage::test_static_owner();
        let map = ProcessPageMapStorage::test_static_owner();
        let binding = unsafe { storage.test_prepare_vm_process_backing_binding(config, options, subprocess, map) }.unwrap();
        metadata.bind_process_backing(binding).unwrap();
        (config, binding.process(), metadata)
    }

    fn fill_registry(backing: &ProcessArenaBacking) -> usize {
        let count = backing.registry.count();
        let first = unsafe { backing.registry.arena_at(0) }.unwrap() as *const _ as *mut _;
        for slot in &backing.registry.arenas[count..] { slot.store(first, Ordering::Relaxed); }
        backing.registry.count.store(MAX_ARENAS, Ordering::Relaxed);
        count
    }

    fn restore_registry(backing: &ProcessArenaBacking, count: usize) {
        for slot in &backing.registry.arenas[count..] { slot.store(core::ptr::null_mut(), Ordering::Relaxed); }
        backing.registry.count.store(count, Ordering::Relaxed);
    }

    #[test]
    fn huge_cleanup_retains_metadata_and_only_failed_pages_until_raw_retry() {
        let fault = fault::install(fault::Plan::disabled());
        let (config, process, metadata) = fixture();
        let backing = process.subprocess().arena_backing();
        let mut warm = metadata.zalloc(config, 8).unwrap();
        let audit = metadata.test_allocation_audit();
        let allocation = HugeOsAllocation::test_registry_allocation(process, config, 3);
        let count = fill_registry(backing);
        let before = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Unmap, 2, Errno::NOMEM));
        {
            let _guard = backing.huge_reservation_lock.lock().unwrap();
            assert!(matches!(unsafe { backing.finish_huge_reservation(config, metadata, -1, false,
                HugeOsAllocationOutcome::Allocated(allocation)) },
                Err(HugeArenaReserveError::Manage(ManageArenaError::RegistryFull))));
        }
        restore_registry(backing, count);
        assert_eq!(fault.observed(), 3, "the source pass continues after its second free failed");
        assert!(backing.huge_cleanup_pending());
        assert_eq!(metadata.test_allocation_audit().live_capability_count, audit.live_capability_count + 1);
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.reserved_current, before.reserved_current - 3 * GIB as i64);
        assert_eq!(after.committed_current, before.committed_current - 3 * GIB as i64);
        {
            let pending = unsafe { &*backing.huge_cleanup.get() }.as_ref().unwrap();
            let Some(HugePrefixCleanup::FailedPages(retry)) = &pending.prefix else { panic!("failed page state"); };
            assert!(!retry.failed_page(0));
            assert!(retry.failed_page(1));
            assert!(!retry.failed_page(2));
        }
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        assert_eq!(backing.retry_huge_cleanup(), Err(HugeArenaCleanupError::Primitive(Errno::NOMEM)));
        assert_eq!(fault.observed(), 1, "raw retry touches only the one retained page");
        assert_eq!(process.subprocess().vm_statistics().snapshot(), after);
        fault.set(fault::Plan::disabled());
        let held = metadata.test_with_held_backing_entry(|| backing.retry_huge_cleanup()).unwrap();
        assert_eq!(held, Err(HugeArenaCleanupError::Metadata(MetaError::RecursiveEntry)),
            "the final raw unmap precedes a retryable metadata-entry rejection");
        assert!(backing.huge_cleanup_pending());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), after);
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        backing.retry_huge_cleanup().unwrap();
        assert_eq!(fault.observed(), 0, "tracker-only retry cannot touch already released huge pages");
        assert!(!backing.huge_cleanup_pending());
        assert_eq!(metadata.test_allocation_audit().live_capability_count, audit.live_capability_count);
        assert_eq!(process.subprocess().vm_statistics().snapshot(), after);
        metadata.free(&mut warm).unwrap();
    }

    #[test]
    fn huge_cleanup_metadata_failure_preserves_full_owner_before_any_free() {
        let fault = fault::install(fault::Plan::disabled());
        let (config, process, metadata) = fixture();
        let backing = process.subprocess().arena_backing();
        let mut warm = metadata.zalloc(config, 8).unwrap();
        let allocation = HugeOsAllocation::test_registry_allocation(process, config, 3);
        let base = allocation.base();
        let count = fill_registry(backing);
        let before = process.subprocess().vm_statistics().snapshot();
        metadata.test_fail_next_direct_zeroed_size(8);
        {
            let _guard = backing.huge_reservation_lock.lock().unwrap();
            assert!(matches!(unsafe { backing.finish_huge_reservation(config, metadata, -1, false,
                HugeOsAllocationOutcome::Allocated(allocation)) }, Err(HugeArenaReserveError::Manage(_))));
        }
        restore_registry(backing, count);
        assert!(backing.huge_cleanup_pending());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
        {
            let pending = unsafe { &*backing.huge_cleanup.get() }.as_ref().unwrap();
            let Some(HugePrefixCleanup::Unreleased { allocation, tracker: None }) = &pending.prefix
                else { panic!("the complete unreleased owner must remain live"); };
            assert_eq!(allocation.base(), base);
            assert_eq!(allocation.page_count(), 3);
        }
        // No fault is armed: this is the first source free pass, not a raw
        // retry, and it must account all three pages exactly once.
        fault.set(fault::Plan::disabled());
        backing.retry_huge_cleanup().unwrap();
        assert!(!backing.huge_cleanup_pending());
        let after = process.subprocess().vm_statistics().snapshot();
        assert_eq!(after.reserved_current, before.reserved_current - 3 * GIB as i64);
        metadata.free(&mut warm).unwrap();
    }

    #[test]
    fn huge_reservation_primitive_failure_needs_no_tracking_metadata() {
        let fault = fault::install(fault::Plan::disabled());
        let (config, process, metadata) = fixture();
        let backing = process.subprocess().arena_backing();
        let before = process.subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::HugeMap, 1, Errno::NOMEM));
        assert_eq!(unsafe { backing.reserve_huge_at(process, config, metadata, 5, -2, 0, false, None) },
            Err(HugeArenaReserveError::Unavailable(HugeOsAllocationStop::PrimitiveMapFailed(Errno::NOMEM))));
        assert_eq!(fault.observed(), 1);
        assert_eq!(backing.registry.count(), 0);
        assert!(!backing.huge_cleanup_pending());
        assert_eq!(metadata.test_allocation_audit().live_capability_count, 0);
        assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
    }

    #[test]
    fn huge_successful_reservation_keeps_metadata_tracking_unallocated() {
        let _fault = fault::install(fault::Plan::disabled());
        let (config, process, metadata) = fixture();
        let backing = process.subprocess().arena_backing();
        let allocation = HugeOsAllocation::test_registry_allocation(process, config, 1);
        let _guard = backing.huge_reservation_lock.lock().unwrap();
        let arena = unsafe { backing.finish_huge_reservation(config, metadata, -1, false,
            HugeOsAllocationOutcome::Allocated(allocation)) }.unwrap().unwrap();
        assert_eq!(backing.registry.count(), 1);
        assert_eq!(unsafe { &*arena.as_ptr() }.memid.kind(), crate::types::MemoryKind::OsHuge);
        assert_eq!(metadata.test_allocation_audit().live_capability_count, 0);
        assert!(!backing.huge_cleanup_pending());
    }

    #[test]
    fn huge_rejected_primitive_cleanup_never_consumes_the_published_prefix() {
        let fault = fault::install(fault::Plan::disabled());
        let (config, process, metadata) = fixture();
        let backing = process.subprocess().arena_backing();
        let allocation = HugeOsAllocation::test_registry_allocation(process, config, 1);
        let prefix = allocation.base();
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let rejected = HugeOsRejectedPrimitive::test_rejected_cleanup_for_process(process, config);
        let after_adjustment = process.subprocess().vm_statistics().snapshot();
        let arena = {
            let _guard = backing.huge_reservation_lock.lock().unwrap();
            unsafe { backing.finish_huge_reservation(config, metadata, -1, false,
                HugeOsAllocationOutcome::AllocatedWithRejectedPrimitive { allocation, rejected }) }.unwrap().unwrap()
        };
        assert_eq!(fault.observed(), 1, "initial reservation does not repeat the failed adjustment-free");
        assert!(backing.huge_cleanup_pending());
        assert_eq!(metadata.test_allocation_audit().live_capability_count, 0);
        assert_eq!(unsafe { backing.reserve_huge_at(process, config, metadata, 1, -1, 0, false, None) },
            Err(HugeArenaReserveError::PendingCleanup));
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        assert_eq!(backing.retry_huge_cleanup(), Err(HugeArenaCleanupError::Primitive(Errno::NOMEM)));
        fault.set(fault::Plan::disabled());
        backing.retry_huge_cleanup().unwrap();
        assert!(!backing.huge_cleanup_pending());
        assert_eq!(process.subprocess().vm_statistics().snapshot(), after_adjustment);
        let parent = unsafe { &*arena.as_ptr() };
        assert_eq!(parent.memid.os_memory().unwrap().base, prefix.as_ptr());
        assert_eq!(parent.memid.kind(), crate::types::MemoryKind::OsHuge);
        assert_eq!(backing.registry.count(), 1);
    }

    #[test]
    fn huge_interleave_preserves_source_distribution_timeout_and_first_error() {
        let mut field = 0;
        for (pages, nodes, detected, timeout, fail_at) in [
            (0, 0, 3, 0, 0), (1, 0, 3, 0, 0), (5, 3, 9, 100, 0),
            (5, 3, 9, 100, 2), (17, usize::MAX, 4, 1, 0), (5, 2, 1, usize::MAX, 0),
            (1, 1, 1, usize::MAX, 0), (2, i32::MAX as usize, 3, 0, 0), (2, 0, 0, 100, 0),
        ] {
            let mut calls = 0;
            let result = reserve_huge_interleaved_with(pages, nodes, detected, timeout,
                |pages, node, timeout| {
                    calls += 1;
                    for value in [pages, node as usize, timeout] {
                        std::println!("m2.huge.interleave.{field}={value}"); field += 1;
                    }
                    if fail_at != 0 && calls == fail_at { Err(Errno::NOMEM) } else { Ok(()) }
                });
            for value in [calls, usize::from(result.is_err())] {
                std::println!("m2.huge.interleave.{field}={value}"); field += 1;
            }
            if pages == 0 { assert_eq!(calls, 0); }
            if fail_at != 0 { assert_eq!(calls, fail_at); assert_eq!(result, Err(Errno::NOMEM)); }
        }
    }
}
