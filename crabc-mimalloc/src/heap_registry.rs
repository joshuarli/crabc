// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/heap.c:30-33,102-125,188-225.

//! Source subprocess Heap membership: the head, lock, live count, and
//! sequence counter of one subprocess's Heap list, for main Heaps and for
//! non-main Heaps from `mi_heap_new` (see [`lifecycle`]).

use super::Heap;
use crate::lock::PrivateLock;
use crate::subproc::SubprocessIdentity;
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
    pub(super) unsafe fn link_main(&self, heap: &mut Heap, subprocess: &SubprocessIdentity) -> Result<(), SourceHeapRegistryError> {
        if !subprocess.is_process_main() {
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        unsafe { self.link_first_main_heap(heap, subprocess) }
    }

    /// Shared first-main-Heap list insertion after role-specific identity
    /// publication. The caller's role-specific owner retains both images.
    ///
    /// # Safety
    /// `heap` is uniquely initialized and pinned for its owning subprocess's
    /// lifetime. No prior Heap list member exists and no concurrent list
    /// operation can race this insertion; failures after mutation retain both
    /// images and the owning subprocess.
    unsafe fn link_first_main_heap(
        &self,
        heap: &mut Heap,
        subprocess: &SubprocessIdentity,
    ) -> Result<(), SourceHeapRegistryError> {
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

    /// Source `_mi_heap_init` admission for one already published child main
    /// Heap. This is only the subprocess-list transition; it does not prove
    /// the Heap's page destruction or parent heap-allocation release.
    ///
    /// # Safety
    /// `heap` and the child image stay pinned through terminal unlink. The
    /// child identity was already published in its parent registry, its
    /// `heap_main` identity is in its `Publishing` interval and names this Heap, and no other child
    /// Heap-list operation can race this first insertion.
    pub(crate) unsafe fn link_child_main(
        &self,
        heap: &mut Heap,
        subprocess: &SubprocessIdentity,
    ) -> Result<(), SourceHeapRegistryError> {
        if subprocess.is_process_main()
            || !subprocess.is_registered()
            || !subprocess.matches_publishing_main_heap(core::ptr::NonNull::from(&mut *heap))
        {
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        unsafe { self.link_first_main_heap(heap, subprocess) }
    }

    /// # Safety
    /// All Heap/Theap consumers are permanently quiescent and safe projection
    /// entries are sealed. The complete source Theap pass succeeded. `heap`
    /// remains pinned on every result; failures are terminal, never retried.
    pub(crate) unsafe fn free_main(&self, heap: &mut Heap, subprocess: &SubprocessIdentity) -> Result<(), SourceHeapRegistryError> {
        if !subprocess.is_process_main() {
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        unsafe { self.free_linked_main_heap(heap, subprocess) }
    }

    /// Shared Heap-list removal. This does not release Heap storage or
    /// destroy pages; the role-specific owner controls those later steps.
    ///
    /// # Safety
    /// The owning subprocess is already unlinked or permanently quiescent,
    /// every Theap edge is gone, and `heap` remains pinned until the external
    /// owner handles its backing allocation.
    unsafe fn free_linked_main_heap(
        &self,
        heap: &mut Heap,
        subprocess: &SubprocessIdentity,
    ) -> Result<(), SourceHeapRegistryError> {
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
        // private futex words. The role-specific owner excludes any future
        // operation before it releases the Heap backing.
        Ok(())
    }

    /// Source child main-Heap list removal after subprocess unlink and all
    /// Theap-list edges are clear. Page destruction remains a separate
    /// unimplemented transition.
    ///
    /// # Safety
    /// The child registry edge is already removed, the Heap remains pinned,
    /// its Theap list is empty, and no Heap-list consumer can race this
    /// terminal removal. The caller retains the child context until return.
    pub(crate) unsafe fn free_child_main(
        &self,
        heap: &mut Heap,
        subprocess: &SubprocessIdentity,
    ) -> Result<(), SourceHeapRegistryError> {
        if subprocess.is_process_main() || subprocess.is_registered() {
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        unsafe { self.free_linked_main_heap(heap, subprocess) }
    }

    /// Source `mi_subproc_visit_heaps` (subproc.c:303-313): calls `visitor`
    /// for each list member in list order while the Heap-list lock is held,
    /// stopping at the first `false`. It returns whether every visited call
    /// returned `true`, so an empty list returns `true`.
    ///
    /// The visitor receives only a Heap identity. It must not take this
    /// list's lock or link or unlink a Heap of this subprocess; source has
    /// the same non-reentrant lock requirement.
    pub(crate) fn visit_heaps(
        &self,
        mut visitor: impl FnMut(core::ptr::NonNull<Heap>) -> bool,
    ) -> Result<bool, SourceHeapRegistryError> {
        let guard = self.lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
        let mut ok = true;
        // SAFETY: the held list lock excludes every link/unlink, and each
        // linked member stays pinned until its own locked removal.
        let mut current = unsafe { *self.head.get() };
        while ok {
            let Some(heap) = core::ptr::NonNull::new(current) else { break; };
            // Source reads `heap->next` after the visitor returns; the lock
            // keeps it stable either way. Read it first so no projection of
            // the visited Heap overlaps the visitor call.
            current = unsafe { (*heap.as_ptr()).next };
            ok = visitor(heap);
        }
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
        Ok(ok)
    }

    /// Source `_mi_heap_init`'s list push (`heap.c:115-124`) for one
    /// non-main Heap: push at the head under the list lock, then the
    /// `heap_count` increment and the `heaps` statistic.
    ///
    /// # Safety
    /// `heap` was just initialized by [`Heap::initialize_non_main`] for this
    /// list's subprocess and is pinned until its [`Self::unlink_non_main`].
    /// Every linked member stays pinned until its own unlink; this writes the
    /// current head's `prev` link while holding the list lock.
    pub(crate) unsafe fn link_non_main(
        &self,
        heap: &mut Heap,
        subprocess: &SubprocessIdentity,
    ) -> Result<(), SourceHeapRegistryError> {
        if !core::ptr::eq(heap.subprocess, subprocess.as_ptr()) || heap.theap_slot <= 1 {
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        let guard = self.lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
        let heap_pointer = core::ptr::from_mut(heap);
        // SAFETY: the held lock excludes every other link/unlink, and the
        // current head stays pinned until its own locked removal.
        unsafe {
            let head = *self.head.get();
            heap.prev = null_mut();
            heap.next = head;
            if !head.is_null() {
                (*head).prev = heap_pointer;
            }
            *self.head.get() = heap_pointer;
        }
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
        self.live.fetch_add(1, Ordering::Relaxed);
        subprocess.record_statistics_heap_linked();
        Ok(())
    }

    /// Source `mi_heap_free`'s count, statistic, and list removal
    /// (`heap.c:205-219`) for one non-main Heap. The caller has already merged
    /// the Heap's statistics into its main Heap.
    ///
    /// # Safety
    /// `heap` is a member of this list with no Theap left, it stays pinned
    /// until return, and its neighbours stay pinned until their own unlink.
    pub(crate) unsafe fn unlink_non_main(
        &self,
        heap: &mut Heap,
        subprocess: &SubprocessIdentity,
    ) -> Result<(), SourceHeapRegistryError> {
        if !core::ptr::eq(heap.subprocess, subprocess.as_ptr()) || !heap.theaps.is_null() {
            return Err(SourceHeapRegistryError::InvalidImage);
        }
        self.live.fetch_sub(1, Ordering::Relaxed);
        subprocess.record_statistics_heap_unlinked();
        let guard = self.lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
        // SAFETY: the held lock excludes every other link/unlink, and both
        // neighbours stay pinned until their own locked removal.
        unsafe {
            if !heap.next.is_null() {
                (*heap.next).prev = heap.prev;
            }
            if !heap.prev.is_null() {
                (*heap.prev).next = heap.next;
            } else {
                *self.head.get() = heap.next;
            }
        }
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)
    }

    #[cfg(test)]
    pub(crate) fn test_counts(&self) -> (usize, usize, bool) {
        let guard = self.lock.lock().expect("source Heap audit lock");
        let counts = (self.live.load(Ordering::Relaxed), self.total.load(Ordering::Relaxed), unsafe { (*self.head.get()).is_null() });
        guard.unlock().expect("source Heap audit unlock");
        counts
    }
}

impl Heap {
    /// Source `_mi_heap_init`'s field initialization (`heap.c:103-114`) for
    /// one non-main Heap: its dynamic thread-local slot, subprocess, the next
    /// Heap sequence, exclusive arena, no NUMA affinity, fresh statistics, and
    /// fresh locks. List membership follows in
    /// [`SubprocessHeapList::link_non_main`].
    pub(crate) fn initialize_non_main(
        &mut self,
        subprocess: &SubprocessIdentity,
        theap_slot: u64,
        exclusive_arena: *mut super::Arena,
        memory: super::MemoryId,
    ) {
        *self = Heap::bootstrap_empty();
        self.theap_slot = theap_slot as usize;
        self.subprocess = subprocess.as_ptr();
        self.heap_seq = subprocess.heap_list().next_sequence();
        self.exclusive_arena = exclusive_arena;
        self.numa_node = -1;
        self.memid = memory;
    }

    /// Whether this non-main Heap owns no Theap and no page: the state in
    /// which `mi_heap_free_theaps`, `_mi_heap_move_pages`, and
    /// `_mi_heap_destroy_pages` have nothing to do.
    pub(crate) fn is_without_theaps_or_pages(&self) -> bool {
        self.theaps.is_null()
            && self.os_abandoned_pages.is_null()
            && self.abandoned_count.iter().all(|count| count.load(Ordering::Relaxed) == 0)
            && self.arena_pages.iter().all(|pages| pages.load(Ordering::Relaxed).is_null())
    }

    /// Source `mi_heap_stats_merge_to_main` (`heap.c:30-33`): merge this
    /// Heap's statistics into its subprocess main Heap and reset them.
    ///
    /// # Safety
    /// `main` is this Heap's live subprocess main Heap. Only its statistics
    /// field is accessed, and those counters are relaxed atomics.
    pub(crate) unsafe fn merge_statistics_to_main(&self, main: core::ptr::NonNull<Heap>) {
        // SAFETY: forwarded liveness; no reference to the whole main Heap is
        // formed, only to its internally synchronized statistics field.
        let target = unsafe { &*core::ptr::addr_of!((*main.as_ptr()).statistics) };
        target.merge_from_and_reset(&self.statistics);
    }

    /// Source-visible fields of a non-main Heap image for the pinned-C
    /// differential: sequence, subprocess, no exclusive arena, NUMA node, no
    /// Theap, and its thread-local slot key.
    #[cfg(test)]
    pub(crate) fn test_non_main_facts(&self) -> (usize, *mut SubprocessIdentity, bool, i32, bool, u64) {
        (self.heap_seq, self.subprocess, self.exclusive_arena.is_null(), self.numa_node,
            self.theaps.is_null(), self.theap_slot as u64)
    }

    /// This Heap's list neighbours, for the pinned-C list-order checks.
    ///
    /// # Safety
    /// No list operation runs during the read.
    #[cfg(test)]
    pub(crate) unsafe fn test_links(heap: core::ptr::NonNull<Heap>) -> (*mut Heap, *mut Heap) {
        unsafe { ((*heap.as_ptr()).prev, (*heap.as_ptr()).next) }
    }
}

#[cfg(test)]
impl SubprocessHeapList {
    /// The list head, for the pinned-C list-order checks.
    pub(crate) fn test_head(&self) -> *mut Heap {
        let guard = self.lock.lock().expect("source Heap audit lock");
        let head = unsafe { *self.head.get() };
        guard.unlock().expect("source Heap audit unlock");
        head
    }
}

/// Child main-Heap image facts that pinned C exposes after `mi_subproc_new`.
#[cfg(test)]
pub(crate) struct ChildMainHeapImageFacts {
    pub(crate) heap_sequence: usize,
    pub(crate) subprocess: *mut SubprocessIdentity,
    pub(crate) metadata_theap_is_only_member: bool,
    pub(crate) metadata_theap_on_parent_tld: bool,
}

#[cfg(test)]
impl Heap {
    /// # Safety
    /// This Heap, `metadata_theap`, and `parent_metadata_theap` are live and
    /// no Heap/Theap list operation runs during the read.
    pub(crate) unsafe fn test_child_main_image_facts(
        &self,
        metadata_theap: core::ptr::NonNull<super::Theap>,
        parent_metadata_theap: core::ptr::NonNull<super::Theap>,
    ) -> ChildMainHeapImageFacts {
        let theap = metadata_theap.as_ptr();
        let parent = parent_metadata_theap.as_ptr();
        // SAFETY: forwarded liveness and list-quiescence obligations.
        unsafe {
            ChildMainHeapImageFacts {
                heap_sequence: self.heap_seq,
                subprocess: self.subprocess,
                metadata_theap_is_only_member: self.theaps == theap
                    && (*(*theap).hnext.get()).is_null()
                    && (*(*theap).hprev.get()).is_null()
                    && core::ptr::eq((*theap).heap.load(Ordering::Acquire), self),
                metadata_theap_on_parent_tld: (*theap).is_detached
                    && !(*theap).tld.is_null()
                    && (*theap).tld == (*parent).tld,
            }
        }
    }
}

#[path = "heap_lifecycle.rs"]
pub(crate) mod lifecycle;
