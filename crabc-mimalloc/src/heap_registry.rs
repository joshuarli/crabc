// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/heap.c:102-125,188-225.

//! Source subprocess Heap membership for the canonical process main Heap.
//! This group owns the source head, lock, live count and sequence counter.
//! It exposes no general Heap projection or non-main Heap constructor.

use super::Heap;
use crate::lock::PrivateLock;
use crate::subproc::MainSubprocess;
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use crabc_core::Errno;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceHeapRegistryError {
    InvalidImage,
    ListLockAcquire(Errno),
    ListLockRelease(Errno),
}

pub(crate) struct SubprocessHeapList {
    head: UnsafeCell<*mut Heap>,
    lock: PrivateLock,
    live: AtomicUsize,
    total: AtomicUsize,
}

// SAFETY: head is accessed only with lock held. Counters are atomic. Raw
// identities grant no projection; the canonical pinned owner governs access.
unsafe impl Sync for SubprocessHeapList {}

impl SubprocessHeapList {
    pub(crate) const fn new() -> Self {
        Self { head: UnsafeCell::new(null_mut()), lock: PrivateLock::new(),
            live: AtomicUsize::new(0), total: AtomicUsize::new(0) }
    }

    pub(super) fn next_sequence(&self) -> usize { self.total.fetch_add(1, Ordering::Relaxed) }

    /// # Safety
    /// `heap` is the uniquely initialized, permanently pinned canonical main
    /// Heap. No prior publication can project it. Failure retains its image
    /// and subprocess permanently; an unlock error may follow list insertion.
    pub(super) unsafe fn link_main(&self, heap: &mut Heap, subprocess: &MainSubprocess) -> Result<(), SourceHeapRegistryError> {
        let guard = self.lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
        if unsafe { !(*self.head.get()).is_null() } || self.live.load(Ordering::Relaxed) != 0 {
            drop(guard);
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        // This selected source branch has no predecessor Heap; non-main Heap
        // publication needs its own owner and neighbouring-link authority.
        heap.prev = null_mut();
        heap.next = unsafe { *self.head.get() };
        unsafe { *self.head.get() = core::ptr::from_mut(heap); }
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
        self.live.fetch_add(1, Ordering::Relaxed);
        subprocess.record_statistics_heap_linked();
        Ok(())
    }

    /// # Safety
    /// All Heap/Theap consumers are permanently quiescent and safe projection
    /// entries are sealed. The complete source Theap pass succeeded. `heap`
    /// remains pinned on every result; failures are terminal, never retried.
    pub(crate) unsafe fn free_main(&self, heap: &mut Heap, subprocess: &MainSubprocess) -> Result<(), SourceHeapRegistryError> {
        // Preflight only: actual source merge/decrement precedes unlink lock.
        let guard = self.lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
        let valid = unsafe { *self.head.get() == core::ptr::from_mut(heap) }
            && heap.next.is_null() && heap.prev.is_null() && heap.theaps.is_null()
            && self.live.load(Ordering::Relaxed) == 1;
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
        if !valid { return Err(SourceHeapRegistryError::InvalidImage); }
        if !heap.merge_main_heap_statistics_into_owning_subprocess_before_unlink() {
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        self.live.fetch_sub(1, Ordering::Relaxed);
        subprocess.record_statistics_heap_unlinked();
        let guard = self.lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
        unsafe { *self.head.get() = heap.next; }
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
        // Source lock_done has no external resource counterpart for these
        // private futex words. Permanent owner revocation excludes every
        // future lock operation; the process-static Heap itself is retained.
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_counts(&self) -> (usize, usize, bool) {
        let guard = self.lock.lock().expect("source Heap audit lock");
        let counts = (self.live.load(Ordering::Relaxed), self.total.load(Ordering::Relaxed), unsafe { (*self.head.get()).is_null() });
        guard.unlock().expect("source Heap audit unlock");
        counts
    }
}
