// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/theap.c:381-412, src/heap.c:162-224,241-251.

//! Quiescent main-Heap destruction after explicit metadata-owner transfer.
//! The source main Heap skips `_mi_heap_destroy_pages` (arena.c:2640-2643):
//! its pages are released later with the subprocess arenas. TLDs are detached,
//! not freed by this transition. Their exact Rust capabilities remain in
//! external tracking storage until the enclosing arena-destruction owner
//! consumes that backing. Failed Theap frees also remain represented there.
//! The current Theap prefix omits source statistics, so the source per-Theap
//! statistics merge remains unimplemented. Main-Heap unlink/count bookkeeping,
//! the detached metadata bootstrap Heap, arena release, and global PageMap
//! destruction are separate required predecessors/successors of full teardown.

use super::{Heap, MemoryKind, Theap, ThreadLocalData};
use crate::meta::{MetaAllocation, MetaAllocator, MetaError, MetaRelease, MetaReleaseFailure};
use crate::subproc::ThreadRegistrationLease;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use crabc_core::Errno;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapDestroyError {
    Inactive,
    NotMainHeap,
    TrackingOccupied,
    TrackingCapacity { required: usize },
    InvalidOwnership,
    Busy,
    Lock(Errno),
    Metadata(MetaError),
}

enum TrackedTheap {
    /// Recovered before source list mutation/refcount decrement.
    Recovered(MetaAllocation<'static>),
    /// Source still has a cached reference after dropping its Heap reference.
    Cached(MetaAllocation<'static>),
    /// Source reference reached zero; entry refusal made no allocator mutation.
    Retryable(MetaAllocation<'static>),
    /// A release was claimed before failure; retain diagnostic ownership only.
    Terminal { allocation: MetaAllocation<'static>, error: MetaError },
}

/// External ownership storage for one source Theap and its detached TLD.
/// A successful main-Heap destruction deliberately retains the TLD: source
/// `mi_heap_free_theaps` does not call `mi_tld_free`. Never release this
/// storage or its remaining capabilities while their backing remains live.
#[must_use = "retain detached TLD and failed/cached Theap owners through backing destruction"]
pub(crate) struct MainHeapDestroyTracking {
    pointer: Option<NonNull<Theap>>,
    tld_pointer: Option<NonNull<ThreadLocalData>>,
    theap: Option<TrackedTheap>,
    tld: Option<MetaAllocation<'static>>,
    registration: Option<ThreadRegistrationLease>,
}

impl MainHeapDestroyTracking {
    pub(crate) const fn empty() -> Self {
        Self { pointer: None, tld_pointer: None, theap: None, tld: None, registration: None }
    }

    pub(crate) fn retains_theap(&self) -> bool { self.theap.is_some() }
    pub(crate) fn retains_tld(&self) -> bool { self.tld.is_some() }

    /// Retries only the exact metadata free whose source reference already
    /// reached zero. A cached-reference owner is never eligible, and this
    /// never repeats list mutation or a source reference decrement.
    pub(crate) fn retry_theap_metadata_release(
        &mut self,
    ) -> Result<(), MetaError> {
        match self.theap.take() {
            Some(TrackedTheap::Retryable(allocation)) => self.release_theap(allocation),
            other => {
                self.theap = other;
                Err(MetaError::ReleasedOrStale)
            }
        }
    }

    fn release_theap(&mut self, allocation: MetaAllocation<'static>) -> Result<(), MetaError> {
        match MetaRelease::Malloc(allocation).release() {
            Ok(()) => Ok(()),
            Err(MetaReleaseFailure::MallocRetryable { error, allocation }) => {
                self.theap = Some(TrackedTheap::Retryable(allocation));
                Err(error)
            }
            Err(MetaReleaseFailure::MallocTerminal { error, allocation }) => {
                self.theap = Some(TrackedTheap::Terminal { allocation, error });
                Err(error)
            }
            Err(MetaReleaseFailure::RegularOs { .. }) => unreachable!("a Malloc capability cannot select OS release"),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_retained_tld_is_detached(&mut self) -> bool {
        self.tld.as_mut().and_then(MetaAllocation::thread_local_data_mut)
            .is_some_and(|tld| tld.is_subprocess_attached_no_theap())
    }
}

impl Heap {
    #[cfg(test)]
    pub(crate) fn test_destroy_graph_counts(&self) -> (usize, usize) {
        let guard = self.theaps_lock.lock().expect("source graph audit lock");
        let mut dynamic = 0;
        let mut attached = 0;
        let mut current = self.theaps;
        while let Some(pointer) = NonNull::new(current) {
            // The held source lock protects each valid intrusive-list member.
            let theap = unsafe { pointer.as_ref() };
            if theap.memid.kind() == MemoryKind::Malloc {
                dynamic += 1;
                attached += usize::from(!theap.tld.is_null());
            }
            current = unsafe { *theap.hnext.get() };
        }
        guard.unlock().expect("source graph audit unlock");
        (dynamic, attached)
    }

    /// Applies the source main-Heap Theap-list destruction with exact dynamic
    /// metadata ownership. Static images remain allocated and unchanged
    /// except for their list links, as source `_mi_theap_decref` requires.
    ///
    /// Every dynamic member must have crossed the explicit source-retention
    /// transfer. Tracking capacity is checked before any owner recovery. Once
    /// recovery begins, an error is terminal: tracking owns recovered images,
    /// and not-yet-recovered images remain owned by the source graph. No error
    /// permits releasing arenas or retrying this complete transition.
    ///
    /// # Safety
    /// The process has permanently stopped all Heap/TLD/Theap, allocation,
    /// cache, metadata, and remote-producer access except this transition's
    /// metadata frees. All source lists and pointers are valid and exclusively
    /// accessible. Every dynamic member and its distinct TLD were explicitly
    /// transferred by their old Rust wrappers, with no recovery or surviving
    /// wrapper; `metadata` is their original allocator. No Heap/TLD lock
    /// guard/waiter remains. Source TLS/cache roots have been retired in source order.
    /// Tracking, this Heap, and metadata control storage live outside arenas
    /// which the subsequent subprocess transition may release. The caller
    /// retains tracking on success and failure and never reopens this Heap.
    pub(crate) unsafe fn force_destroy_main_heap_theaps_quiescent(
        &mut self,
        metadata: Pin<&'static MetaAllocator>,
        tracking: &mut [MainHeapDestroyTracking],
    ) -> Result<(), MainHeapDestroyError> {
        if !self.is_main_static() { return Err(MainHeapDestroyError::NotMainHeap); }
        if tracking.iter().any(|slot| slot.pointer.is_some() || slot.theap.is_some() || slot.tld.is_some()) {
            return Err(MainHeapDestroyError::TrackingOccupied);
        }
        let mut count = 0usize;
        let mut current = self.theaps;
        // SAFETY: the caller owns the complete valid, quiescent source list.
        while let Some(theap) = NonNull::new(current) {
            count = count.checked_add(1).ok_or(MainHeapDestroyError::InvalidOwnership)?;
            current = unsafe { *(*theap.as_ptr()).hnext.get() };
        }
        if tracking.len() < count {
            return Err(MainHeapDestroyError::TrackingCapacity { required: count });
        }
        current = self.theaps;
        for index in 0..count {
            let pointer = NonNull::new(current).ok_or(MainHeapDestroyError::InvalidOwnership)?;
            let theap = unsafe { pointer.as_ref() };
            if !core::ptr::eq(theap.heap.load(Ordering::Acquire), self)
                || !matches!(theap.memid.kind(), MemoryKind::Static | MemoryKind::Malloc)
                || (theap.memid.kind() == MemoryKind::Malloc && theap.refcount.load(Ordering::Acquire) == 0)
            {
                return Err(MainHeapDestroyError::InvalidOwnership);
            }
            let tld_pointer = NonNull::new(theap.tld);
            if theap.memid.kind() == MemoryKind::Malloc {
                let tld = tld_pointer.ok_or(MainHeapDestroyError::InvalidOwnership)?;
                if tracking[..index].iter().any(|slot| slot.tld_pointer == Some(tld)) {
                    return Err(MainHeapDestroyError::InvalidOwnership);
                }
                // SAFETY: whole-process quiescence and prior explicit
                // transfer are caller obligations; each graph member is
                // recovered only once into its external tracking slot.
                tracking[index].theap = Some(TrackedTheap::Recovered(unsafe {
                    MetaAllocation::recover_source_retained_theap(metadata, pointer)
                }.ok_or(MainHeapDestroyError::InvalidOwnership)?));
                tracking[index].tld = Some(unsafe {
                    MetaAllocation::recover_source_retained_tld(metadata, tld)
                }.ok_or(MainHeapDestroyError::InvalidOwnership)?);
                tracking[index].registration = Some(unsafe {
                    ThreadRegistrationLease::recover_source_retained(&*self.subprocess, tld.as_ref())
                }.ok_or(MainHeapDestroyError::InvalidOwnership)?);
            }
            tracking[index].pointer = Some(pointer);
            tracking[index].tld_pointer = tld_pointer;
            current = unsafe { *theap.hnext.get() };
        }

        // Source first detaches *all* TLD relations, then frees the Heap list.
        // Quiescence removes the source contention/backoff case; a busy lock
        // contradicts admission and therefore preserves all remaining owners.
        let heap_guard = self.theaps_lock.try_lock().ok_or(MainHeapDestroyError::Busy)?;
        for slot in &tracking[..count] {
            let mut pointer = slot.pointer.expect("recovered list member");
            let theap = unsafe { pointer.as_mut() };
            if let Some(mut tld_pointer) = NonNull::new(theap.tld) {
                let tld = unsafe { tld_pointer.as_mut() };
                let guard = tld.theaps_lock.try_lock().ok_or(MainHeapDestroyError::Busy)?;
                unsafe {
                    if !theap.tnext.is_null() { (*theap.tnext).tprev = theap.tprev; }
                    if !theap.tprev.is_null() { (*theap.tprev).tnext = theap.tnext; }
                    else { tld.theaps = theap.tnext; }
                }
                theap.tnext = core::ptr::null_mut();
                theap.tprev = core::ptr::null_mut();
                theap.tld = core::ptr::null_mut();
                guard.unlock().map_err(MainHeapDestroyError::Lock)?;
            }
        }
        heap_guard.unlock().map_err(MainHeapDestroyError::Lock)?;
        let heap_guard = self.theaps_lock.try_lock().ok_or(MainHeapDestroyError::Busy)?;
        self.theaps = core::ptr::null_mut();
        let mut first_error = None;
        for slot in &mut tracking[..count] {
            let mut pointer = slot.pointer.expect("recovered list member");
            let theap = unsafe { pointer.as_mut() };
            *theap.hnext.get_mut() = core::ptr::null_mut();
            *theap.hprev.get_mut() = core::ptr::null_mut();
            if let Some(TrackedTheap::Recovered(allocation)) = slot.theap.take() {
                let previous = theap.refcount.fetch_sub(1, Ordering::AcqRel);
                if previous == 0 {
                    slot.theap = Some(TrackedTheap::Terminal { allocation, error: MetaError::ReleasedOrStale });
                    first_error.get_or_insert(MainHeapDestroyError::InvalidOwnership);
                } else if previous == 1 {
                    if let Err(error) = slot.release_theap(allocation) {
                        first_error.get_or_insert(MainHeapDestroyError::Metadata(error));
                    }
                } else {
                    slot.theap = Some(TrackedTheap::Cached(allocation));
                }
            }
        }
        if let Err(error) = heap_guard.unlock() {
            first_error.get_or_insert(MainHeapDestroyError::Lock(error));
        }
        first_error.map_or(Ok(()), Err)
    }
}
