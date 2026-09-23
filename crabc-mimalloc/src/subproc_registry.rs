// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/subproc.c:14-15,141-156,202-212,316-325.

//! Source subprocess list ownership for process-main initialization and child
//! membership. Main still uses its canonical static image; child registration
//! records its parent-issued Malloc provenance and source sequence.

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
    /// Reads the immutable sequence assigned before main publication.
    ///
    /// # Safety
    /// The exact subprocess completed initialization in this registry. Its
    /// process-lifetime storage remains live; terminal unlink never rewrites
    /// this scalar. No initializer can run again.
    pub(crate) unsafe fn initialized_main_sequence(&self, subprocess: &MainSubprocess) -> usize {
        unsafe { *subprocess.source_membership.sequence.get() }
    }

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
            *member.memory.get() = MemoryId::static_allocation(NonNull::from(subprocess).cast().as_ptr(), size_of::<MainSubprocess>());
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

    /// Source `mi_subproc_init`'s non-main membership transition after the
    /// caller has allocated and initialized the exact child context image.
    ///
    /// # Safety
    /// `subprocess` is pinned in a live allocation owned by `parent`, and
    /// `memory` is the exact Malloc MemoryId returned for that whole image.
    /// The parent is already a member of this registry. The caller retains
    /// the allocation and excludes child teardown until every Heap, metadata
    /// owner, thread, and list consumer has completed.
    pub(crate) unsafe fn initialize_child(
        &'static self,
        subprocess: &'static MainSubprocess,
        parent: &'static MainSubprocess,
        memory: MemoryId,
    ) -> Result<(), SourceSubprocessRegistryError> {
        let member = &subprocess.source_membership;
        if subprocess.is_process_main()
            || memory.kind() != crate::types::MemoryKind::Malloc
            || !core::ptr::eq(
                parent.source_membership.registry.load(Ordering::Acquire),
                self,
            )
        {
            return Err(SourceSubprocessRegistryError::InvalidMembership);
        }
        member
            .registry
            .compare_exchange(
                core::ptr::null_mut(),
                core::ptr::from_ref(self).cast_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| SourceSubprocessRegistryError::InvalidMembership)?;
        // Pinned `mi_subproc_init` assigns parent and sequence before taking
        // the process-list lock. The source relaxed total is monotonic even
        // if a later lock boundary must retain the partially initialized node.
        unsafe {
            *member.memory.get() = memory;
            *member.parent.get() = core::ptr::from_ref(parent).cast_mut();
            *member.sequence.get() = self.total_count.fetch_add(1, Ordering::Relaxed);
        }
        let guard = self.lock.lock().map_err(SourceSubprocessRegistryError::Lock)?;
        let head = unsafe { *self.head.get() };
        if head.is_null() {
            let _ = guard.unlock();
            return Err(SourceSubprocessRegistryError::InvalidMembership);
        }
        unsafe {
            *member.previous.get() = core::ptr::null_mut();
            *member.next.get() = head;
            (*head).source_membership.previous
                .get()
                .write(core::ptr::from_ref(subprocess).cast_mut());
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

    /// Removes one non-main subprocess at the source's first destroy step.
    ///
    /// # Safety
    /// Terminal child admission excludes every list, Heap, metadata, thread,
    /// and arena user. Its owner retains the exact context allocation until
    /// all later source destroy steps finish, and must free it only afterward.
    pub(crate) unsafe fn unlink_child_terminal(
        &self,
        subprocess: &MainSubprocess,
    ) -> Result<(), SourceSubprocessRegistryError> {
        let guard = self.lock.lock().map_err(SourceSubprocessRegistryError::Lock)?;
        let member = &subprocess.source_membership;
        let previous = unsafe { *member.previous.get() };
        let next = unsafe { *member.next.get() };
        let valid = !subprocess.is_process_main()
            && core::ptr::eq(member.registry.load(Ordering::Acquire), self)
            && (previous.is_null() || unsafe { (*previous).source_membership.registry.load(Ordering::Acquire) == core::ptr::from_ref(self).cast_mut() })
            && (next.is_null() || unsafe { (*next).source_membership.registry.load(Ordering::Acquire) == core::ptr::from_ref(self).cast_mut() })
            && (if previous.is_null() {
                unsafe { *self.head.get() == core::ptr::from_ref(subprocess).cast_mut() }
            } else {
                unsafe { (*previous).source_membership.next.get().read() == core::ptr::from_ref(subprocess).cast_mut() }
            });
        if !valid {
            let _ = guard.unlock();
            return Err(SourceSubprocessRegistryError::InvalidMembership);
        }
        unsafe {
            if previous.is_null() {
                *self.head.get() = next;
            } else {
                *(*previous).source_membership.next.get() = next;
            }
            if !next.is_null() {
                *(*next).source_membership.previous.get() = previous;
            }
        }
        // Preserve the retired node's own links and identity as pinned C does.
        guard.unlock().map_err(SourceSubprocessRegistryError::Lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_registration_prepends_and_terminal_unlink_preserves_owner_image() {
        let registry = std::boxed::Box::leak(std::boxed::Box::new(SourceSubprocessRegistry::new()));
        let main: &'static MainSubprocess =
            std::boxed::Box::leak(std::boxed::Box::new(MainSubprocess::new()));
        let child: &'static MainSubprocess =
            std::boxed::Box::leak(std::boxed::Box::new(MainSubprocess::new_child()));
        // SAFETY: the isolated process fixture exclusively owns the static
        // main image and its one-time source-list transition.
        unsafe { registry.initialize_main(main) }.unwrap();
        let memory = MemoryId {
            info: crate::types::MemoryInfo {
                malloc: crate::types::MallocMemory {
                    base: core::ptr::from_ref(child).cast_mut().cast(),
                    size: size_of::<MainSubprocess>(),
                },
            },
            kind: crate::types::MemoryKind::Malloc,
            is_pinned: true,
            initially_committed: true,
            initially_zero: true,
        };
        // SAFETY: child is pinned in the exact Malloc-shaped test image;
        // main is already a member, and this fixture has no concurrent users.
        unsafe { registry.initialize_child(child, main, memory) }.unwrap();

        assert!(core::ptr::eq(unsafe { *registry.head.get() }, child));
        assert!(core::ptr::eq(
            unsafe { *child.source_membership.parent.get() },
            main
        ));
        assert_eq!(unsafe { *child.source_membership.sequence.get() }, 1);
        assert!(unsafe { *child.source_membership.previous.get() }.is_null());
        assert!(core::ptr::eq(
            unsafe { *child.source_membership.next.get() },
            main
        ));
        assert!(core::ptr::eq(
            unsafe { *main.source_membership.previous.get() },
            child
        ));
        assert_eq!(
            unsafe { *child.source_membership.memory.get() }.kind(),
            crate::types::MemoryKind::Malloc
        );

        // SAFETY: this isolated child has no Heap, thread, metadata, or arena
        // users; the exact child image remains allocated through unlink.
        unsafe { registry.unlink_child_terminal(child) }.unwrap();
        assert!(core::ptr::eq(unsafe { *registry.head.get() }, main));
        assert!(unsafe { *main.source_membership.previous.get() }.is_null());
        assert_eq!(unsafe { *child.source_membership.previous.get() }, core::ptr::null_mut());
        assert!(core::ptr::eq(
            unsafe { *child.source_membership.next.get() },
            main
        ));
        assert_eq!(registry.total_count.load(Ordering::Relaxed), 2);
    }
}
