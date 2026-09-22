// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/subproc.c:14-15,141-156,202-212,316-325.

//! The source subprocess list surrounding canonical native main initialization.
//! Only main is constructible in this staged runtime. Its actual source links,
//! static MemoryId, and sequence are retained; no non-main API is synthesized.

use super::*;

pub(crate) struct SourceSubprocessRegistry {
    head: UnsafeCell<*mut MainSubprocess>,
    lock: PrivateLock,
    total_count: AtomicUsize,
}

// SAFETY: list reads/writes require the source list lock. Initialization and
// terminal removal additionally require the process coordinator's authority.
unsafe impl Sync for SourceSubprocessRegistry {}

pub(super) struct SourceSubprocessMembership {
    registry: AtomicPtr<SourceSubprocessRegistry>,
    previous: UnsafeCell<*mut MainSubprocess>,
    next: UnsafeCell<*mut MainSubprocess>,
    parent: UnsafeCell<*mut MainSubprocess>,
    sequence: UnsafeCell<usize>,
    memory: UnsafeCell<MemoryId>,
}

impl SourceSubprocessMembership {
    pub(super) const fn new() -> Self {
        Self {
            registry: AtomicPtr::new(core::ptr::null_mut()),
            previous: UnsafeCell::new(core::ptr::null_mut()),
            next: UnsafeCell::new(core::ptr::null_mut()),
            parent: UnsafeCell::new(core::ptr::null_mut()),
            sequence: UnsafeCell::new(0),
            memory: UnsafeCell::new(MemoryId::none()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceSubprocessRegistryError {
    InvalidMembership,
    Lock(crabc_core::Errno),
}

impl SourceSubprocessRegistry {
    pub(crate) const fn new() -> Self {
        Self { head: UnsafeCell::new(core::ptr::null_mut()), lock: PrivateLock::new(), total_count: AtomicUsize::new(0) }
    }

    /// Source `_mi_subproc_main_init` before main-Heap initialization.
    ///
    /// # Safety
    /// The process initializer exclusively owns this never-linked static main
    /// image. Registry and subprocess remain pinned for the complete process;
    /// failure retains that once-only image and cannot restart initialization.
    pub(crate) unsafe fn initialize_main(
        &'static self, subprocess: &'static MainSubprocess,
    ) -> Result<(), SourceSubprocessRegistryError> {
        let member = &subprocess.source_membership;
        member.registry.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(self).cast_mut(), Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SourceSubprocessRegistryError::InvalidMembership)?;
        // Source assigns static memid/parent/sequence before list locking.
        unsafe {
            *member.memory.get() = MemoryId::static_allocation(NonNull::from(subprocess).cast(), size_of::<MainSubprocess>());
            *member.parent.get() = core::ptr::null_mut();
            *member.sequence.get() = self.total_count.fetch_add(1, Ordering::Relaxed);
        }
        let guard = self.lock.lock().map_err(SourceSubprocessRegistryError::Lock)?;
        if !unsafe { *self.head.get() }.is_null() {
            let _ = guard.unlock();
            return Err(SourceSubprocessRegistryError::InvalidMembership);
        }
        // Source's prepend has no former head in the supported main-only
        // graph. The actual null links remain represented for source unlink.
        unsafe {
            *member.previous.get() = core::ptr::null_mut();
            *member.next.get() = *self.head.get();
            *self.head.get() = core::ptr::from_ref(subprocess).cast_mut();
        }
        guard.unlock().map_err(SourceSubprocessRegistryError::Lock)
    }

    /// Removes source subprocess membership before any Heap is destroyed.
    ///
    /// # Safety
    /// Permanent terminal admission excludes all initializer/list/Heap users.
    /// The exact static subprocess and registry remain pinned through the
    /// subsequent heap, arena, metadata and PageMap retirement sequence.
    pub(crate) unsafe fn unlink_main_terminal(
        &self, subprocess: &MainSubprocess,
    ) -> Result<(), SourceSubprocessRegistryError> {
        let guard = self.lock.lock().map_err(SourceSubprocessRegistryError::Lock)?;
        let member = &subprocess.source_membership;
        let valid = core::ptr::eq(member.registry.load(Ordering::Acquire), self)
            && core::ptr::eq(unsafe { *self.head.get() }, subprocess)
            && unsafe { (*member.previous.get()).is_null() && (*member.next.get()).is_null() };
        if !valid {
            let _ = guard.unlock();
            return Err(SourceSubprocessRegistryError::InvalidMembership);
        }
        // Pinned source removes links from the list without rewriting the
        // retired node's own links or making the subprocess reusable.
        unsafe { *self.head.get() = *member.next.get(); }
        guard.unlock().map_err(SourceSubprocessRegistryError::Lock)
    }
}
