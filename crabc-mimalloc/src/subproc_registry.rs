// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/subproc.c:14-15,141-156,202-212,316-325.

//! Source subprocess list ownership for process-main initialization and child
//! membership. Main still uses its canonical static image; child registration
//! records its parent-issued Malloc provenance and source sequence.

use super::*;

pub(crate) struct SourceSubprocessRegistry {
    head: UnsafeCell<*mut SubprocessIdentity>,
    lock: PrivateLock,
    total_count: AtomicUsize,
}

// SAFETY: list reads/writes require the source list lock. Initialization and
// terminal removal additionally require the process coordinator's authority.
unsafe impl Sync for SourceSubprocessRegistry {}

pub(super) struct SourceSubprocessMembership {
    registry: AtomicPtr<SourceSubprocessRegistry>,
    initialized: AtomicBool,
    previous: UnsafeCell<*mut SubprocessIdentity>,
    next: UnsafeCell<*mut SubprocessIdentity>,
    parent: UnsafeCell<*mut SubprocessIdentity>,
    sequence: UnsafeCell<usize>,
    memory: UnsafeCell<MemoryId>,
}

impl SourceSubprocessMembership {
    pub(super) const fn new() -> Self {
        Self {
            registry: AtomicPtr::new(core::ptr::null_mut()),
            initialized: AtomicBool::new(false),
            previous: UnsafeCell::new(core::ptr::null_mut()),
            next: UnsafeCell::new(core::ptr::null_mut()),
            parent: UnsafeCell::new(core::ptr::null_mut()),
            sequence: UnsafeCell::new(0),
            memory: UnsafeCell::new(MemoryId::none()),
        }
    }

    pub(super) fn is_child_of(
        &self,
        parent: &SubprocessIdentity,
        child_is_main: bool,
    ) -> bool {
        let parent_membership = &parent.source_membership;
        self.initialized.load(Ordering::Acquire)
            && parent_membership.initialized.load(Ordering::Acquire)
            && !child_is_main
            && core::ptr::eq(
                self.registry.load(Ordering::Acquire),
                parent_membership.registry.load(Ordering::Acquire),
            )
            && core::ptr::eq(
                // SAFETY: initialization publishes this immutable parent
                // write with `initialized`'s Release store.
                unsafe { *self.parent.get() },
                parent.as_ptr(),
            )
    }

    pub(super) fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
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
        let identity = &subprocess.identity;
        let member = &identity.source_membership;
        member.registry.compare_exchange(core::ptr::null_mut(), core::ptr::from_ref(self).cast_mut(), Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SourceSubprocessRegistryError::InvalidMembership)?;
        // Source assigns static memid/parent/sequence before list locking.
        unsafe {
            *member.memory.get() = MemoryId::static_allocation(identity.as_ptr().cast(), size_of::<MainSubprocess>());
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
            *self.head.get() = identity.as_ptr();
        }
        member.initialized.store(true, Ordering::Release);
        guard.unlock().map_err(SourceSubprocessRegistryError::Lock)
    }

    /// Source `mi_subproc_init`'s non-main membership transition after the
    /// caller has allocated and initialized the exact child context image.
    ///
    /// # Safety
    /// `subprocess` is pinned in a live allocation owned by `parent`, and
    /// `memory` is the exact Malloc MemoryId returned for that whole image.
    /// The parent is already a member of this process-lifetime registry. The
    /// caller retains both subprocess allocations and excludes child teardown
    /// until every Heap, metadata owner, thread, and list consumer has
    /// completed. Child and parent references need remain valid only for this
    /// transition; the retained allocation is the authority for later raw
    /// membership projections.
    pub(crate) unsafe fn initialize_child(
        &'static self,
        subprocess: &ChildSubprocessImage,
        parent: &MainSubprocess,
        memory: MemoryId,
    ) -> Result<(), SourceSubprocessRegistryError> {
        let identity = subprocess.identity();
        let member = &identity.source_membership;
        if identity.is_process_main()
            || memory.kind() != crate::types::MemoryKind::Malloc
        {
            return Err(SourceSubprocessRegistryError::InvalidMembership);
        }
        // SAFETY: the kind check above validates which MemoryId union member
        // is active before its exact allocation identity is inspected.
        let malloc = unsafe { memory.info.malloc };
        if malloc.base != core::ptr::from_ref(subprocess).cast_mut().cast()
            || malloc.size != size_of::<ChildSubprocessImage>()
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
            *member.parent.get() = parent.identity_ptr();
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
                .write(identity.as_ptr());
            *self.head.get() = identity.as_ptr();
        }
        member.initialized.store(true, Ordering::Release);
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
        let member = &subprocess.identity.source_membership;
        let valid = core::ptr::eq(member.registry.load(Ordering::Acquire), self)
            && core::ptr::eq(unsafe { *self.head.get() }, subprocess.identity_ptr())
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
    /// The caller has exclusive terminal child teardown: no concurrent
    /// subprocess-list operation can inspect this child, and no concurrent
    /// child operation can race its nested destruction. The source unlink is
    /// the first destroy step; the caller must keep the child image live while
    /// Heap, metadata-Theap, thread, arena, and lock teardown follows, then
    /// release the exact context allocation only after those steps complete.
    pub(crate) unsafe fn unlink_child_terminal(
        &self,
        subprocess: &ChildSubprocessImage,
    ) -> Result<(), SourceSubprocessRegistryError> {
        let guard = self.lock.lock().map_err(SourceSubprocessRegistryError::Lock)?;
        let identity = subprocess.identity();
        let member = &identity.source_membership;
        let previous = unsafe { *member.previous.get() };
        let next = unsafe { *member.next.get() };
        let valid = !identity.is_process_main()
            && core::ptr::eq(member.registry.load(Ordering::Acquire), self)
            && (previous.is_null() || unsafe { (*previous).source_membership.registry.load(Ordering::Acquire) == core::ptr::from_ref(self).cast_mut() })
            && (next.is_null() || unsafe { (*next).source_membership.registry.load(Ordering::Acquire) == core::ptr::from_ref(self).cast_mut() })
            && (if previous.is_null() {
                unsafe { *self.head.get() == identity.as_ptr() }
            } else {
                unsafe { (*previous).source_membership.next.get().read() == identity.as_ptr() }
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
        member.initialized.store(false, Ordering::Release);
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
        let child: &'static ChildSubprocessImage =
            std::boxed::Box::leak(std::boxed::Box::new(ChildSubprocessImage::new()));
        // SAFETY: the isolated process fixture exclusively owns the static
        // main image and its one-time source-list transition.
        unsafe { registry.initialize_main(main) }.unwrap();
        let memory = MemoryId {
            info: crate::types::MemoryInfo {
                malloc: crate::types::MallocMemory {
                    base: core::ptr::from_ref(child).cast_mut().cast(),
                    size: size_of::<ChildSubprocessImage>(),
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

        let mut options = crate::config::VmOptions::uninitialized();
        options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        let policy = crate::os::VmPolicy::new(options).unwrap();
        // SAFETY: `child` is the exact stable allocation retained by this
        // fixture and remains pinned through the registration/unlink checks.
        let child_pin = unsafe { core::pin::Pin::new_unchecked(child) };
        let target = crate::os::ChildVmProcess::new(&policy, child_pin, main.identity())
            .expect("a registered child borrows the process policy with its own identity");
        assert!(core::ptr::eq(target.identity(), child.identity()));
        assert!(!core::ptr::eq(target.identity(), main.identity()));
        assert!(core::ptr::eq(target.process().subprocess(), child.identity()));

        assert!(core::ptr::eq(unsafe { *registry.head.get() }, child.identity()));
        assert!(core::ptr::eq(
            unsafe { *child.source_membership.parent.get() },
            main.identity()
        ));
        assert_eq!(unsafe { *child.source_membership.sequence.get() }, 1);
        assert!(unsafe { *child.source_membership.previous.get() }.is_null());
        assert!(core::ptr::eq(
            unsafe { *child.source_membership.next.get() },
            main.identity()
        ));
        assert!(core::ptr::eq(
            unsafe { *main.source_membership.previous.get() },
            child.identity()
        ));
        assert_eq!(
            unsafe { *child.source_membership.memory.get() }.kind(),
            crate::types::MemoryKind::Malloc
        );

        // SAFETY: this isolated child has no Heap, thread, metadata, or arena
        // users; the exact child image remains allocated through unlink.
        unsafe { registry.unlink_child_terminal(child) }.unwrap();
        assert!(core::ptr::eq(unsafe { *registry.head.get() }, main.identity()));
        assert!(unsafe { *main.source_membership.previous.get() }.is_null());
        assert_eq!(unsafe { *child.source_membership.previous.get() }, core::ptr::null_mut());
        assert!(core::ptr::eq(
            unsafe { *child.source_membership.next.get() },
            main.identity()
        ));
        assert_eq!(registry.total_count.load(Ordering::Relaxed), 2);
    }
}
