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
#[cfg(target_arch = "x86_64")]
use crate::diagnostic_output::MbindWarningRoute;
use crate::os::{HugeOsAllocation, HugeOsAllocationOutcome, HugeOsAllocationStop,
    HugeOsRawReleaseRetry, HugeOsRejectedPrimitive, HugeOsReleaseFailure, MemoryConfig, VmProcess};
use crate::random::TheapRandomImage;

/// Source startup ignores reservation errors and continues in huge-before-
/// regular order. Retain those outcomes without changing readiness policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartupArenaReservationOutcomes {
    pub(crate) huge: Option<Result<(), Errno>>,
    pub(crate) regular: Option<Result<(), Errno>>,
    // The public outcome stays scalar: source startup intentionally ignores a
    // regular-reservation failure and continues to READY.  The successful
    // parent ID is retained privately so the one ticket-zero consumer can
    // prove that it is using this source-start arena rather than reconstructing
    // an arena from an ambient policy or raw address.
    regular_arena: Option<ArenaId>,
}

impl StartupArenaReservationOutcomes {
    pub(crate) const fn empty() -> Self {
        Self { huge: None, regular: None, regular_arena: None }
    }

    /// Returns only the parent arena installed by a successful explicit
    /// regular startup reservation.  A failed or skipped option never grants
    /// a candidate identity.
    #[inline]
    pub(crate) const fn regular_arena(self) -> Option<ArenaId> {
        match self.regular {
            Some(Ok(())) => self.regular_arena,
            Some(Err(_)) | None => None,
        }
    }
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

/// The exact detached metadata issuer and the admission retaining any
/// unpublished child mapping. Successful arena publication transfers child
/// lifetime custody to that child's registry and teardown path.
enum HugeReservationOwner {
    Main(Pin<&'static MetaAllocator>),
    #[cfg(target_arch = "x86_64")]
    Child(crate::subproc::lifecycle::NativeChildArenaAdmission),
}

/// Fresh detached metadata selected exclusively as huge-free tracking words.
/// Its typed projections borrow this linear capability and never outlive a
/// retry or storage-return transition.
struct HugeReleaseMetadata {
    allocation: HugeTrackerAllocation,
    words: usize,
}

enum HugeTrackerAllocation {
    Main(MetaAllocation<'static>),
    #[cfg(target_arch = "x86_64")]
    Child(crate::subproc::lifecycle::NativeChildArenaMetadata),
}

enum HugeTrackerReleaseFailure {
    Main(MetaReleaseFailure),
    #[cfg(target_arch = "x86_64")]
    Child { tracker: crate::subproc::lifecycle::NativeChildArenaMetadata, error: MetaError },
}

impl HugeTrackerReleaseFailure {
    fn error(&self) -> HugeArenaCleanupError {
        match self {
            Self::Main(MetaReleaseFailure::MallocRetryable { error, .. }
                | MetaReleaseFailure::MallocTerminal { error, .. }) => HugeArenaCleanupError::Metadata(*error),
            Self::Main(MetaReleaseFailure::RegularOs { error, .. }) => HugeArenaCleanupError::Primitive(*error),
            #[cfg(target_arch = "x86_64")]
            Self::Child { error, .. } => HugeArenaCleanupError::Metadata(*error),
        }
    }

    fn retry(self) -> Result<(), Self> {
        match self {
            Self::Main(MetaReleaseFailure::MallocRetryable { allocation, .. }) =>
                MetaRelease::Malloc(allocation).release().map_err(Self::Main),
            Self::Main(terminal) => Err(Self::Main(terminal)),
            #[cfg(target_arch = "x86_64")]
            Self::Child { mut tracker, .. } => tracker.free()
                .map_err(|error| Self::Child { tracker, error }),
        }
    }
}

impl HugeReleaseMetadata {
    fn allocate(owner: &HugeReservationOwner, process: VmProcess<'static>,
        config: MemoryConfig, words: usize) -> Result<Self, MetaError> {
        let bytes = words.checked_mul(core::mem::size_of::<usize>())
            .filter(|bytes| *bytes != 0).ok_or(MetaError::AllocationUnavailable)?;
        let allocation = match owner {
            HugeReservationOwner::Main(metadata) => {
                let subprocess = process.main_subprocess().ok_or(MetaError::SubprocessMismatch)?;
                HugeTrackerAllocation::Main(metadata.zalloc_for_main_subprocess(config, subprocess, bytes)?)
            }
            #[cfg(target_arch = "x86_64")]
            HugeReservationOwner::Child(admission) => HugeTrackerAllocation::Child(admission.allocate_tracker(bytes)?),
        };
        let tracker = Self { allocation, words };
        debug_assert_eq!(tracker.pointer().as_ptr().addr() % core::mem::align_of::<usize>(), 0);
        Ok(tracker)
    }

    fn pointer(&self) -> core::ptr::NonNull<u8> {
        match &self.allocation {
            HugeTrackerAllocation::Main(allocation) => allocation.pointer(),
            #[cfg(target_arch = "x86_64")]
            HugeTrackerAllocation::Child(allocation) => allocation.pointer(),
        }
    }

    fn release(self) -> Result<(), HugeTrackerReleaseFailure> {
        match self.allocation {
            HugeTrackerAllocation::Main(allocation) => MetaRelease::Malloc(allocation).release()
                .map_err(HugeTrackerReleaseFailure::Main),
            #[cfg(target_arch = "x86_64")]
            HugeTrackerAllocation::Child(mut tracker) => tracker.free()
                .map_err(|error| HugeTrackerReleaseFailure::Child { tracker, error }),
        }
    }
}

impl AsRef<[usize]> for HugeReleaseMetadata {
    fn as_ref(&self) -> &[usize] {
        // SAFETY: this owner holds an exact fresh zeroed metadata request;
        // the live capability cannot be returned while these words are borrowed.
        unsafe { core::slice::from_raw_parts(self.pointer().as_ptr().cast(), self.words) }
    }
}

impl AsMut<[usize]> for HugeReleaseMetadata {
    fn as_mut(&mut self) -> &mut [usize] {
        // SAFETY: only this unique capability projects these words; no stored
        // reference outlives a retry or metadata storage-return transition.
        unsafe { core::slice::from_raw_parts_mut(self.pointer().as_ptr().cast(), self.words) }
    }
}

enum HugePrefixCleanup {
    Unreleased { allocation: HugeOsAllocation<'static>, tracker: Option<HugeReleaseMetadata> },
    FailedPages(HugeOsRawReleaseRetry<'static, HugeReleaseMetadata>),
    TrackerRelease(HugeTrackerReleaseFailure),
}

pub(super) struct PendingHugeCleanup {
    prefix: Option<HugePrefixCleanup>,
    rejected: Option<HugeOsRejectedPrimitive>,
    owner: HugeReservationOwner,
    error: HugeArenaCleanupError,
}

impl PendingHugeCleanup {
    fn retain_tracker_failure(&mut self, failure: HugeTrackerReleaseFailure) {
        self.error = failure.error();
        self.prefix = Some(HugePrefixCleanup::TrackerRelease(failure));
    }

    fn release_tracker(&mut self, tracker: HugeReleaseMetadata) {
        if let Err(failure) = tracker.release() { self.retain_tracker_failure(failure); }
    }

    /// An initial cleanup never repeats the rejected primitive's already
    /// attempted adjustment-free. An explicit retry may revisit retained raw
    /// owners, and continues to the independent prefix even after an error.
    fn advance(&mut self, config: MemoryConfig, retry_existing: bool) {
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
                    None => match HugeReleaseMetadata::allocate(&self.owner, allocation.process(),
                        config, allocation.release_tracking_words()) {
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
            HugePrefixCleanup::TrackerRelease(failure) => {
                if let Err(failure) = failure.retry() { self.retain_tracker_failure(failure); }
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
        metadata: Pin<&'static MetaAllocator>, mut random: crate::os::OsRandom<'_>,
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
            match unsafe {
                self.reserve_os_memory_for_process(process, config, size,
                    crate::os::MapAccess::Committed, true, false, random.as_deref_mut())
            } {
                Ok(arena) => {
                    results.regular = Some(Ok(()));
                    results.regular_arena = Some(arena);
                }
                Err(error) => results.regular = Some(Err(error)),
            }
        }
        results
    }

    #[cfg(target_arch = "x86_64")]
    /// Selected source startup with a mandatory borrowed failed-`mbind`
    /// receiver. Its regular reservation and outcome ownership are identical
    /// to [`Self::reserve_startup_options`].
    ///
    /// # Safety
    /// The ordinary startup requirements apply; `warning` remains borrowed
    /// from the retained process diagnostic owner through this full route.
    pub(crate) unsafe fn reserve_startup_options_with_mbind_warning(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, mut random: crate::os::OsRandom<'_>,
        warning: MbindWarningRoute<'_>,
    ) -> StartupArenaReservationOutcomes {
        let mut results = StartupArenaReservationOutcomes::empty();
        let pages_option = process.policy().reserve_huge_os_pages();
        if pages_option != 0 {
            let pages = pages_option.clamp(0, 128 * 1024) as usize;
            let node = process.policy().reserve_huge_os_pages_at().clamp(-1, i32::MAX as i64) as i32;
            let timeout = pages * 500;
            let result = if node != -1 {
                let result = unsafe { self.reserve_huge_at_with_mbind_warning(process, config, metadata, pages, node,
                    timeout, false, random.as_deref_mut(), warning) };
                result.map(|_| ())
            } else {
                unsafe { self.reserve_huge_interleaved_with_mbind_warning(process, config, metadata, pages, 0,
                    timeout, random.as_deref_mut(), warning) }
            };
            results.huge = Some(result.map_err(|_| Errno::NOMEM));
        }
        let regular_kib = process.policy().reserve_os_memory_kib();
        if regular_kib > 0 {
            let size = (regular_kib as usize).wrapping_mul(crate::config::KIB);
            match unsafe {
                self.reserve_os_memory_for_process(process, config, size,
                    crate::os::MapAccess::Committed, true, false, random.as_deref_mut())
            } {
                Ok(arena) => {
                    results.regular = Some(Ok(()));
                    results.regular_arena = Some(arena);
                }
                Err(error) => results.regular = Some(Err(error)),
            }
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
        timeout_milliseconds: usize, exclusive: bool, random: crate::os::OsRandom<'_>,
    ) -> Result<Option<ArenaId>, HugeArenaReserveError> {
        unsafe { self.reserve_huge_at_reporting_errno(process, config, metadata, pages,
            numa_node, timeout_milliseconds, exclusive, random,
            #[cfg(target_arch = "x86_64")] None).0 }
    }

    #[cfg(target_arch = "x86_64")]
    /// Reserve huge pages with the process-owned failed-mbind warning route.
    pub(crate) unsafe fn reserve_huge_at_with_mbind_warning(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, pages: usize, numa_node: i32,
        timeout_milliseconds: usize, exclusive: bool, random: crate::os::OsRandom<'_>,
        warning: MbindWarningRoute<'_>,
    ) -> Result<Option<ArenaId>, HugeArenaReserveError> {
        unsafe { self.reserve_huge_at_reporting_errno(process, config, metadata, pages,
            numa_node, timeout_milliseconds, exclusive, random, Some(warning)).0 }
    }

    /// Retain the last primitive errno effect even when a partial prefix is
    /// successfully installed. The C reservation return value and errno are
    /// independent: a failed later map does not discard earlier huge pages.
    ///
    /// # Safety
    /// The arena group, process, metadata, and random image meet the same
    /// ownership requirements as `reserve_huge_at`.
    pub(crate) unsafe fn reserve_huge_at_reporting_errno(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, pages: usize, numa_node: i32,
        timeout_milliseconds: usize, exclusive: bool, random: crate::os::OsRandom<'_>,
        #[cfg(target_arch = "x86_64")] warning: Option<MbindWarningRoute<'_>>,
    ) -> (Result<Option<ArenaId>, HugeArenaReserveError>, crate::source_api::SourceErrno) {
        unsafe { self.reserve_huge_at_with_owner(process, config, HugeReservationOwner::Main(metadata),
            pages, numa_node, timeout_milliseconds, exclusive, random,
            #[cfg(target_arch = "x86_64")] warning) }
    }

    /// Reserve under the admitted current child's exact VM and metadata owner.
    /// Unpublished mappings retain this admission in the cleanup slot; a
    /// published arena transfers custody to this child's registry.
    ///
    /// # Safety
    /// Any random image belongs exclusively to the calling Theap, and the
    /// caller ends all process/backing views before publication returns.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn reserve_huge_at_for_child(
        admission: crate::subproc::lifecycle::NativeChildArenaAdmission,
        pages: usize, numa_node: i32, timeout_milliseconds: usize,
        exclusive: bool, random: crate::os::OsRandom<'_>, warning: Option<MbindWarningRoute<'_>>,
    ) -> (Result<Option<ArenaId>, HugeArenaReserveError>, crate::source_api::SourceErrno) {
        let config = admission.config();
        // SAFETY: the admission moves into the reservation owner, remains
        // retained for unpublished cleanup, and transfers published custody
        // only to this exact child's arena registry.
        let process = unsafe { admission.process() };
        let backing = unsafe { admission.backing() };
        unsafe { backing.reserve_huge_at_with_owner(process, config, HugeReservationOwner::Child(admission),
            pages, numa_node, timeout_milliseconds, exclusive, random, warning) }
    }

    unsafe fn reserve_huge_at_with_owner(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        owner: HugeReservationOwner, pages: usize, numa_node: i32,
        timeout_milliseconds: usize, exclusive: bool, random: crate::os::OsRandom<'_>,
        #[cfg(target_arch = "x86_64")] warning: Option<MbindWarningRoute<'_>>,
    ) -> (Result<Option<ArenaId>, HugeArenaReserveError>, crate::source_api::SourceErrno) {
        use crate::source_api::SourceErrno;
        let mut errno = SourceErrno::Unchanged;
        let result = (|| {
            if pages == 0 { return Ok(None); }
            let _guard = self.huge_reservation_lock.lock().map_err(HugeArenaReserveError::Lock)?;
            if self.huge_cleanup_retained.load(Ordering::Acquire) {
                return Err(HugeArenaReserveError::PendingCleanup);
            }
            self.prepare_huge_reservation(process, config, matches!(&owner, HugeReservationOwner::Main(_)))?;
            let numa_node = if numa_node < -1 { -1 } else if numa_node >= 0 {
                (numa_node as usize % process.policy().numa_node_count()) as i32
            } else { numa_node };
            #[cfg(target_arch = "x86_64")]
            let outcome = if let Some(warning) = warning {
                HugeOsAllocation::allocate_for_process_with_mbind_warning(process, config,
                    pages, numa_node, timeout_milliseconds as i64, random, warning)
            } else {
                HugeOsAllocation::allocate_for_process(process, config, pages,
                    numa_node, timeout_milliseconds as i64, random)
            };
            #[cfg(not(target_arch = "x86_64"))]
            let outcome = HugeOsAllocation::allocate_for_process(process, config, pages,
                numa_node, timeout_milliseconds as i64, random);
            errno = match &outcome {
                HugeOsAllocationOutcome::Unavailable(HugeOsAllocationStop::PrimitiveMapFailed(error)) =>
                    SourceErrno::Store(*error),
                HugeOsAllocationOutcome::Allocated(allocation) => match allocation.stop() {
                    HugeOsAllocationStop::PrimitiveMapFailed(error) => SourceErrno::Store(error),
                    _ => SourceErrno::Unchanged,
                },
                HugeOsAllocationOutcome::AllocatedWithRejectedPrimitive { rejected, .. }
                | HugeOsAllocationOutcome::RejectedPrimitive(rejected) => SourceErrno::Store(rejected.error()),
                _ => SourceErrno::Unchanged,
            };
            if matches!(&outcome, HugeOsAllocationOutcome::Unavailable(_)
                | HugeOsAllocationOutcome::RejectedPrimitive(_)) {
                // The original child admission is still held across this
                // synchronous warning; no child record lock spans callbacks.
                let message = crate::diagnostic_output::SourceFormattedMessage::huge_reservation_failure(pages);
                #[cfg(target_arch = "x86_64")]
                if let Some(warning) = warning {
                    unsafe { warning.huge_warning(message) };
                } else { process.policy().source_warning(message); }
                #[cfg(not(target_arch = "x86_64"))]
                process.policy().source_warning(message);
            }
            let result = unsafe { self.finish_prepared_huge_reservation(config, owner, numa_node, exclusive, outcome) };
            // A manage rejection runs the source primitive free pass. Its
            // last failed free can replace a previous mapping errno even
            // though the reservation return remains ENOMEM.
            if let Some(pending) = unsafe { &*self.huge_cleanup.get() }.as_ref() {
                if matches!(&pending.prefix, Some(HugePrefixCleanup::FailedPages(_)))
                    || pending.rejected.is_some() {
                    if let HugeArenaCleanupError::Primitive(error) = pending.error {
                        errno = SourceErrno::Store(error);
                    }
                }
            }
            result
        })();
        (result, errno)
    }

    fn prepare_huge_reservation(&self, process: VmProcess<'static>, config: MemoryConfig, process_lived: bool)
        -> Result<(), HugeArenaReserveError> {
        let _guard = self.reserve_lock.lock().map_err(HugeArenaReserveError::Lock)?;
        let stored = if process_lived { super::StoredVmProcess::from_static_process(process) }
            else {
                // SAFETY: the reservation admission retains unpublished
                // mappings; publication transfers ownership to the same child
                // context, which retires arenas before releasing its image.
                unsafe { super::StoredVmProcess::from_retained_process(process) }
            };
        if !self.begin_preparation_locked(stored, config) {
            return Err(HugeArenaReserveError::Manage(ManageArenaError::InvalidRegion));
        }
        Ok(())
    }

    fn finish_huge_preparation(&self) -> Result<(), HugeArenaReserveError> {
        let _guard = self.reserve_lock.lock().map_err(HugeArenaReserveError::Lock)?;
        self.finish_preparation_locked();
        Ok(())
    }

    #[cfg(test)]
    unsafe fn finish_huge_reservation(&'static self, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, numa_node: i32, exclusive: bool,
        outcome: HugeOsAllocationOutcome<'static>) -> Result<Option<ArenaId>, HugeArenaReserveError> {
        let process = match &outcome {
            HugeOsAllocationOutcome::Allocated(allocation)
            | HugeOsAllocationOutcome::AllocatedWithRejectedPrimitive { allocation, .. } => allocation.process(),
            _ => return Err(HugeArenaReserveError::Manage(ManageArenaError::InvalidRegion)),
        };
        self.prepare_huge_reservation(process, config, true)?;
        unsafe { self.finish_prepared_huge_reservation(config, HugeReservationOwner::Main(metadata), numa_node, exclusive, outcome) }
    }

    /// Caller holds huge_reservation_lock. Registry installation takes the
    /// ordinary reserve lock only for its publication; metadata cleanup runs
    /// after that lock has been released, so it can safely allocate backing.
    unsafe fn finish_prepared_huge_reservation(
        &'static self, config: MemoryConfig, owner: HugeReservationOwner,
        numa_node: i32, exclusive: bool, outcome: HugeOsAllocationOutcome<'static>,
    ) -> Result<Option<ArenaId>, HugeArenaReserveError> {
        let (allocation, rejected, unavailable) = match outcome {
            HugeOsAllocationOutcome::Unavailable(stop) => {
                self.finish_huge_preparation()?;
                return Err(HugeArenaReserveError::Unavailable(stop));
            },
            HugeOsAllocationOutcome::Allocated(allocation) => (Some(allocation), None, None),
            HugeOsAllocationOutcome::AllocatedWithRejectedPrimitive { allocation, rejected } =>
                (Some(allocation), Some(rejected), None),
            HugeOsAllocationOutcome::RejectedPrimitive(rejected) =>
                (None, Some(rejected), Some(HugeOsAllocationStop::NoncontiguousPrimitive)),
        };
        #[cfg(target_arch = "x86_64")]
        let retained_child = matches!(&owner, HugeReservationOwner::Child(_));
        let mut pending = PendingHugeCleanup { prefix: None, rejected, owner,
            error: HugeArenaCleanupError::Primitive(Errno::NOMEM) };
        if let Some(rejected) = &pending.rejected {
            pending.error = HugeArenaCleanupError::Primitive(rejected.error());
        }
        let result = match allocation {
            None => Err(HugeArenaReserveError::Unavailable(unavailable.unwrap())),
            Some(allocation) => match {
                #[cfg(target_arch = "x86_64")]
                let installed = if retained_child {
                    // SAFETY: the pending owner retains the original child
                    // admission through rejection; publication transfers only
                    // to its child context's eventual arena teardown.
                    unsafe { self.install_owned_huge_allocation_for_retained_process(config, allocation, numa_node, exclusive) }
                } else {
                    unsafe { self.install_owned_huge_allocation(config, allocation, numa_node, exclusive) }
                };
                #[cfg(not(target_arch = "x86_64"))]
                let installed = unsafe { self.install_owned_huge_allocation(config, allocation, numa_node, exclusive) };
                installed
            } {
                Ok(managed) => Ok(Some(managed.arena_id())),
                Err(failure) => {
                    let error = failure.error();
                    pending.prefix = Some(HugePrefixCleanup::Unreleased {
                        allocation: failure.into_allocation(), tracker: None,
                    });
                    pending.advance(config, false);
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
        self.finish_huge_preparation()?;
        result
    }

    pub(crate) fn huge_cleanup_pending(&self) -> bool {
        self.huge_cleanup_retained.load(Ordering::Acquire)
    }

    /// Retries only exact retained owners. Primitive statistics are never
    /// repeated; terminal metadata release remains diagnostic state.
    pub(crate) fn retry_huge_cleanup(&'static self) -> Result<(), HugeArenaCleanupError> {
        let _guard = self.huge_reservation_lock.lock().map_err(HugeArenaCleanupError::Lock)?;
        // Inspect without transferring custody: a failed configuration-lock
        // acquisition must leave every retained allocation available to retry.
        // SAFETY: the held huge lock excludes all other owners of this slot.
        if unsafe { &*self.huge_cleanup.get() }.is_none() { return Ok(()); }
        // The retained preparation pins the original complete configuration;
        // metadata allocation/retry never follows a later caller's policy.
        let config = {
            let _guard = self.reserve_lock.lock().map_err(HugeArenaCleanupError::Lock)?;
            // SAFETY: huge_cleanup_retained prevents binding reset, and this
            // guard excludes a new publisher. Only the immutable copy escapes.
            unsafe { &*self.binding.get() }.as_ref()
                .map(|binding| binding.config)
                .ok_or(HugeArenaCleanupError::Metadata(MetaError::InitializationRetained))?
        };
        // SAFETY: the huge lock is still held and no path above removed the
        // pending owner. All fallible prerequisites precede this transfer.
        let mut pending = unsafe { &mut *self.huge_cleanup.get() }.take().unwrap();
        pending.advance(config, true);
        if pending.is_empty() {
            self.huge_cleanup_retained.store(false, Ordering::Release);
            let _guard = self.reserve_lock.lock().map_err(HugeArenaCleanupError::Lock)?;
            self.clear_unused_binding_locked();
            Ok(())
        } else {
            let error = pending.error;
            unsafe { *self.huge_cleanup.get() = Some(pending) };
            Err(error)
        }
    }

    /// Shared node distribution and timeout arithmetic for public reservations
    /// and startup. Each successful node remains published after a later error.
    pub(crate) fn interleave_huge_reservations<E>(
        pages: usize, numa_nodes: usize, detected_nodes: usize, timeout: usize,
        reserve: impl FnMut(usize, i32, usize) -> Result<(), E>,
    ) -> Result<(), E> {
        reserve_huge_interleaved_with(pages, numa_nodes, detected_nodes, timeout, reserve)
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
        timeout_milliseconds: usize, mut random: crate::os::OsRandom<'_>,
    ) -> Result<(), HugeArenaReserveError> {
        if pages == 0 { return Ok(()); }
        reserve_huge_interleaved_with(pages, numa_nodes, process.policy().numa_node_count(),
            timeout_milliseconds, |pages, node, timeout| unsafe {
                self.reserve_huge_at(process, config, metadata, pages, node, timeout, false,
                    random.as_deref_mut()).map(|_| ())
            })
    }

    #[cfg(target_arch = "x86_64")]
    /// Same interleave policy as [`Self::reserve_huge_interleaved`] with the
    /// mandatory startup warning route carried to every selected node attempt.
    pub(crate) unsafe fn reserve_huge_interleaved_with_mbind_warning(
        &'static self, process: VmProcess<'static>, config: MemoryConfig,
        metadata: Pin<&'static MetaAllocator>, pages: usize, numa_nodes: usize,
        timeout_milliseconds: usize, mut random: crate::os::OsRandom<'_>,
        warning: MbindWarningRoute<'_>,
    ) -> Result<(), HugeArenaReserveError> {
        if pages == 0 { return Ok(()); }
        reserve_huge_interleaved_with(pages, numa_nodes, process.policy().numa_node_count(),
            timeout_milliseconds, |pages, node, timeout| unsafe {
                let result = self.reserve_huge_at_with_mbind_warning(process, config, metadata, pages, node,
                    timeout, false, random.as_deref_mut(), warning);
                result.map(|_| ())
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
    use crate::config::{GIB, MAX_ARENAS, SourceOption, VmOption, VmOptionEnvironment, VmOptions};
    use crate::diagnostic_output::{OutputCallback, OutputOwner};
    use crate::os::{fault, PageSize};
    use crate::process_init::ProcessMainInitializationStorage;
    use crate::process_page_map::ProcessPageMapStorage;
    use core::ffi::{c_char, c_void, CStr};
    use core::sync::atomic::AtomicUsize;

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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn failed_startup_huge_reservation_reports_the_source_failure_warning() {
        unsafe fn empty_environment() -> *const *const c_char {
            static END: usize = 0;
            (&END as *const usize).cast()
        }
        unsafe extern "C" fn unused_output(_: *const c_char) {}
        unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
            let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
            if bytes == b"failed to reserve 1 GiB huge pages\n" {
                let count = unsafe { &*(argument.cast::<AtomicUsize>()) };
                count.fetch_add(1, Ordering::AcqRel);
            }
        }

        let fault = fault::install(fault::Plan::disabled());
        for (node_option, field) in [(0, "explicit_warnings"), (-1, "interleaved_warnings")] {
            let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false);
            let metadata = MetaAllocator::test_static_owner();
            let subprocess = metadata.test_default_subprocess();
            let mut options = VmOptions::uninitialized();
            options.initialize_all(|_| VmOptionEnvironment::Absent);
            options.set(VmOption::ReserveHugeOsPages, 1);
            options.set(VmOption::ReserveHugeOsPagesAt, node_option);
            let storage = ProcessMainInitializationStorage::test_static_owner();
            let map = ProcessPageMapStorage::test_static_owner();
            let binding = unsafe { storage.test_prepare_vm_process_backing_binding(config, options, subprocess, map) }.unwrap();
            metadata.bind_process_backing(binding).unwrap();
            let output = OutputOwner::new(unused_output);
            unsafe { output.initialize_source_options(empty_environment) };
            unsafe { output.option_set(SourceOption::ShowErrors, 1) }.unwrap();
            unsafe { output.option_set(SourceOption::MaxWarnings, 100) }.unwrap();
            let warnings = AtomicUsize::new(0);
            unsafe { output.register_output(Some(capture as OutputCallback),
                (&warnings as *const AtomicUsize).cast_mut().cast()) };
            fault.set(fault::Plan::at(fault::Point::HugeMap, 1, Errno::NOMEM));
            let result = unsafe { subprocess.arena_backing().reserve_startup_options_with_mbind_warning(
                binding.process(), config, metadata, None, MbindWarningRoute::new(&output)) };
            assert_eq!(result.huge, Some(Err(Errno::NOMEM)));
            std::println!("m2.startup_huge_failure.{field}={}", warnings.load(Ordering::Acquire));
            assert_eq!(warnings.load(Ordering::Acquire), 1);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn process_option_startup_delivers_one_public_huge_failure_warning() {
        unsafe fn environment() -> *const *const c_char {
            static END: usize = 0;
            (&END as *const usize).cast()
        }
        unsafe extern "C" fn discard(_: *const c_char) {}
        unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
            if unsafe { CStr::from_ptr(message) }.to_bytes() == b"failed to reserve 1 GiB huge pages\n" {
                unsafe { &*argument.cast::<AtomicUsize>() }.fetch_add(1, Ordering::Relaxed);
            }
        }
        let fault = fault::install(fault::Plan::every(fault::Point::HugeMap, Errno::IO));
        for node in [0, -1] {
            let output = std::boxed::Box::leak(std::boxed::Box::new(OutputOwner::new(discard)));
            unsafe { output.initialize_source_options(environment) };
            for (option, value) in [(SourceOption::ShowErrors, 1), (SourceOption::MaxWarnings, 100),
                (SourceOption::ReserveHugeOsPages, 1), (SourceOption::ReserveHugeOsPagesAt, node),
                (SourceOption::UseNumaNodes, 1)] {
                unsafe { output.option_set(option, value) }.unwrap();
            }
            let warnings = AtomicUsize::new(0);
            unsafe { output.register_output(Some(capture), (&warnings as *const AtomicUsize).cast_mut().cast()) };
            let policy = std::boxed::Box::leak(std::boxed::Box::new(unsafe { crate::os::VmPolicy::from_process_options(output) }));
            let subprocess = crate::subproc::MainSubprocess::test_static_owner();
            let process = VmProcess::new_main(policy, subprocess);
            let metadata = MetaAllocator::test_static_owner();
            let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1 << 20, true, false);
            let result = unsafe { subprocess.arena_backing().reserve_startup_options_with_mbind_warning(
                process, config, metadata, None, MbindWarningRoute::new(output)) };
            unsafe { output.register_output(None, core::ptr::null_mut()) };
            assert_eq!(result.huge, Some(Err(Errno::NOMEM)));
            assert_eq!(warnings.load(Ordering::Relaxed), 1);
        }
        drop(fault);
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

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn child_huge_manage_rejection_retains_its_vm_and_metadata_until_raw_retry() {
        use crate::subproc::lifecycle::{NativeChildArenaAdmission, NativeChildThreadAdd,
            NativeSubprocessError, native_subproc_new, native_subproc_add_current_thread,
            native_child_thread_done, native_subproc_destroy};
        unsafe extern "C" fn no_output(_: *const c_char) {}
        crate::test_process::run_in_fresh_process(
            "arena::owned::huge::tests::child_huge_manage_rejection_retains_its_vm_and_metadata_until_raw_retry",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let id = native_subproc_new().expect("child");
                std::thread::spawn(move || {
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let admission = NativeChildArenaAdmission::acquire_current().unwrap().unwrap();
                    let backing = unsafe { admission.backing() };
                    let mut warm = admission.allocate_tracker(64).expect("warm child detached metadata");
                    warm.free().expect("return original warm tracker");
                    assert!(backing.process_lived_projection().is_none());
                    let count = fill_registry(backing);
                    let fault = fault::install(fault::Plan::every(fault::Point::Unmap, Errno::IO));
                    fault.enable_one_synthetic_huge_map();
                    let result = crate::source_heap_api::reserve_huge_os_pages_at(1, -1, 0);
                    assert_eq!(result.value, Errno::NOMEM.raw());
                    assert_eq!(result.errno, crate::source_api::SourceErrno::Store(Errno::IO));
                    assert!(backing.process_lived_projection().is_none(), "child admission cannot publish permanent VM lifetime");
                    restore_registry(backing, count);
                    assert!(backing.huge_cleanup_pending());
                    {
                        let pending = unsafe { &*backing.huge_cleanup.get() }.as_ref().unwrap();
                        let HugeReservationOwner::Child(owner) = &pending.owner else { panic!("original child reservation owner"); };
                        assert!(core::ptr::eq(unsafe { owner.backing() }, backing));
                        assert!(matches!(&pending.prefix, Some(HugePrefixCleanup::FailedPages(_))));
                    }
                    drop(admission);
                    assert!(matches!(unsafe { native_subproc_destroy(id) }, Err(NativeSubprocessError::DestroyRefused(_))));
                    assert_eq!(backing.retry_huge_cleanup(), Err(HugeArenaCleanupError::Primitive(Errno::IO)));
                    fault.set(fault::Plan::disabled());
                    backing.retry_huge_cleanup().expect("same child raw mapping and tracker return");
                    assert!(!backing.huge_cleanup_pending());
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                }).join().expect("retained child huge cleanup");
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn huge_partial_reservation_publishes_claims_and_releases_the_source_arena() {
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::LargeMap, 1, fault::Point::LargeMap, 1, Errno::NOMEM));
        let (config, process, metadata) = fixture();
        let backing = process.subprocess().arena_backing();
        let before = process.subprocess().vm_statistics().snapshot();
        let arena_before = process.subprocess().arena_statistics().snapshot().arena_count;
        fault.enable_one_synthetic_huge_map();
        // SAFETY: this fixture retains its process and bound metadata through
        // the complete sole-owner reservation, claim, and terminal release.
        let id = unsafe { backing.reserve_huge_at(process, config, metadata,
            3, -1, 0, false, None) }.unwrap().unwrap();
        let hint = fault.synthetic_huge_hint();
        let arena = unsafe { &*id.as_ptr() };
        let parent = arena.memid;
        let span = parent.os_memory().unwrap();
        let after = process.subprocess().vm_statistics().snapshot();
        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!(concat!("m2.huge_reservation_progress.arena_", $name, "={}"), $value);
            };
        }
        emit!("published", usize::from(backing.registry.count() == 1));
        emit!("partial", usize::from(span.size == GIB));
        emit!("base_exact", usize::from(span.base.addr() == hint));
        emit!("memory_huge", usize::from(parent.kind() == crate::types::MemoryKind::OsHuge));
        emit!("memory_pinned", usize::from(parent.is_pinned()));
        emit!("reserved_after", (after.reserved_current - before.reserved_current) / GIB as i64);
        emit!("committed_after", (after.committed_current - before.committed_current) / GIB as i64);
        emit!("count_after", process.subprocess().arena_statistics().snapshot().arena_count - arena_before);
        let claim = unsafe { backing.registry.try_find_free(crate::arena::ArenaSearch {
            heap_sequence: 0, heap_count: 1, thread_sequence: 0, numa_node: -1,
            requested: id, allow_pinned: true,
        }, 2, crate::config::ARENA_SLICE_SIZE, true) }.unwrap();
        let start = claim.start();
        let memory = claim.memory_id();
        let length = 2 * crate::config::ARENA_SLICE_SIZE;
        // SAFETY: the source claim owns both committed slices exclusively.
        let writable = unsafe {
            start.write_volatile(0x3c);
            start.add(length - 1).write_volatile(0x6d);
            start.read_volatile() == 0x3c && start.add(length - 1).read_volatile() == 0x6d
        };
        emit!("claim_writable", usize::from(writable));
        emit!("claim_pinned", usize::from(memory.is_pinned()));
        emit!("claim_committed", usize::from(memory.initially_committed()));
        emit!("claim_released", usize::from(claim.release()));
        fault.set(fault::Plan::disabled());
        let mut tracking = [0usize; 1];
        // SAFETY: no claim, view, callback or allocation survives destruction;
        // tracking is separate from the retiring one-GiB mapping.
        let destroyed = unsafe { backing.destroy_all(&mut tracking) }.unwrap();
        emit!("terminal_released", usize::from(destroyed.is_released()));
        emit!("terminal_registry", backing.registry.count());
        let terminal = process.subprocess().vm_statistics().snapshot();
        emit!("reserved_terminal", terminal.reserved_current - before.reserved_current);
        emit!("committed_terminal", terminal.committed_current - before.committed_current);
        let mut residence = 0u8;
        // SAFETY: residency tests the former address without dereferencing it.
        emit!("terminal_absent", usize::from(unsafe {
            crabc_core::mm::mincore_raw(span.base, 4096, &mut residence)
        }.is_err()));
        assert!(writable && destroyed.is_released());
        assert_eq!(terminal.reserved_current, before.reserved_current);
        assert_eq!(terminal.committed_current, before.committed_current);
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
