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

    /// Whether this is the main Heap of its subprocess: the Heap whose Theaps
    /// use the fast thread-local key (`heap.c:136`), for the process main
    /// subprocess or a child.
    #[inline]
    pub(crate) fn is_subprocess_main(&self) -> bool {
        self.theap_slot == crate::thread_local::TLS_FAST_KEY_RAW as usize && !self.subprocess.is_null()
    }

    /// Source `mi_heap_ensure_arena_pages` (`arena.c:699-723`) for the main
    /// Heap of a child subprocess: point its slot for `arena_index` at that
    /// arena's in-place `pages_main`, which the Heap's page, abandoned-page,
    /// and visit transitions read. An already identical slot is the normal
    /// fast path; a different image is refused.
    ///
    /// # Safety
    /// `pages` is the `pages_main` image of the live arena with that index in
    /// this Heap's subprocess, and the Heap stays live for the call.
    pub(crate) unsafe fn ensure_child_main_arena_pages(
        &self,
        arena_index: usize,
        pages: core::ptr::NonNull<super::ArenaPages>,
    ) -> bool {
        if arena_index >= self.arena_pages.len() || !self.is_subprocess_main() || self.memid.kind() == super::MemoryKind::Static {
            return false;
        }
        let current = self.arena_pages[arena_index].load(Ordering::Acquire);
        if current == pages.as_ptr() {
            return true;
        }
        if !current.is_null() {
            return false;
        }
        let Ok(guard) = self.arena_pages_lock.lock() else { return false };
        let current = self.arena_pages[arena_index].load(Ordering::Acquire);
        let installed = if current.is_null() {
            self.arena_pages[arena_index].store(pages.as_ptr(), Ordering::Release);
            true
        } else {
            current == pages.as_ptr()
        };
        guard.unlock().is_ok() && installed
    }

    /// The Heap of `page` and its child subprocess, or `None` for a page of
    /// the process main subprocess. Only the page's `heap` identity and that
    /// Heap's immutable subprocess identity are read.
    ///
    /// # Safety
    /// `page` is live page metadata (for example, the page of a live block),
    /// and its Heap stays live for the call.
    pub(crate) unsafe fn child_heap_of_page(
        page: core::ptr::NonNull<super::Page>,
    ) -> Option<(core::ptr::NonNull<Heap>, core::ptr::NonNull<SubprocessIdentity>)> {
        // SAFETY: a raw field read; the page's Heap identity is immutable
        // while one of its blocks is live.
        let heap = core::ptr::NonNull::new(unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).heap)) })?;
        // SAFETY: forwarded Heap liveness; immutable after initialization.
        let heap_ref = unsafe { heap.as_ref() };
        let subprocess = core::ptr::NonNull::new(heap_ref.subprocess)?;
        // SAFETY: a Heap's subprocess outlives the Heap.
        if unsafe { subprocess.as_ref() }.is_process_main() {
            return None;
        }
        Some((heap, subprocess))
    }

    /// The first Theap on this Heap's list other than `except`, with the TLD
    /// it names: one step of source `_mi_heap_detach_theaps`
    /// (`theap.c:381-411`) at process destruction, where the caller detaches
    /// each returned Theap before asking again.
    ///
    /// # Safety
    /// Permanent terminal quiescence: no Theap or Heap list operation runs
    /// concurrently, and every listed Theap and its TLD stay allocated until
    /// the caller's subprocess destruction releases their arenas.
    pub(crate) unsafe fn first_theap_other_than_quiescent(
        &self,
        except: Option<core::ptr::NonNull<super::Theap>>,
    ) -> Option<(core::ptr::NonNull<super::Theap>, *mut super::ThreadLocalData)> {
        let mut current = self.theaps;
        while let Some(theap) = core::ptr::NonNull::new(current) {
            if Some(theap) != except {
                // SAFETY: a listed Theap is allocated (caller contract).
                return Some((theap, unsafe { (*theap.as_ptr()).tld }));
            }
            // SAFETY: as above.
            current = unsafe { *(*theap.as_ptr()).hnext.get() };
        }
        None
    }

    /// Visits this Heap's Theaps in list order with their TLDs until `visit`
    /// returns `false`; `visit` must not change either list.
    ///
    /// # Safety
    /// As for [`Self::first_theap_other_than_quiescent`].
    pub(crate) unsafe fn visit_theaps_quiescent(
        &self,
        mut visit: impl FnMut(core::ptr::NonNull<super::Theap>, *mut super::ThreadLocalData) -> bool,
    ) -> bool {
        let mut current = self.theaps;
        while let Some(theap) = core::ptr::NonNull::new(current) {
            // SAFETY: a listed Theap is allocated (caller contract).
            let (tld, next) = unsafe { ((*theap.as_ptr()).tld, *(*theap.as_ptr()).hnext.get()) };
            if !visit(theap, tld) {
                return false;
            }
            current = next;
        }
        true
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

/// Raw source transitions on the Theap, TLD, Heap, and Page images used by the
/// per-thread Theaps of non-main child Heaps and by `mi_heap_destroy`
/// (`src/theap.c:236-412`, `src/heap.c:162-251`, `src/arena.c:677-723,
/// 1216-1298, 2531-2644`, `src/prim/prim-tls.c:211-229`). Each operates on
/// individual fields; callers own the list or page state they change.
impl super::Theap {
    /// `_mi_theap_incref` (`theap.c:357-362`): a Theap with a freeable
    /// image counts each cached reference.
    ///
    /// # Safety
    /// `theap` is a live Theap image.
    pub(crate) unsafe fn incref_at(theap: core::ptr::NonNull<Self>) {
        // SAFETY: forwarded liveness; `refcount` and `memid` are read or
        // updated field by field.
        unsafe {
            if (*theap.as_ptr()).memid.kind() == super::MemoryKind::Malloc {
                (*theap.as_ptr()).refcount.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    /// `_mi_theap_decref` (`theap.c:364-370`) up to `mi_theap_free_mem`:
    /// `true` when this dropped the last reference, so the caller must free
    /// the image (and count it out of `theaps` unless it is detached).
    ///
    /// # Safety
    /// `theap` is a live Theap image holding the reference being dropped.
    pub(crate) unsafe fn decref_at(theap: core::ptr::NonNull<Self>) -> bool {
        // SAFETY: as for `incref_at`.
        unsafe {
            (*theap.as_ptr()).memid.kind() == super::MemoryKind::Malloc
                && (*theap.as_ptr()).refcount.fetch_sub(1, Ordering::AcqRel) == 1
        }
    }

    /// The Heap this Theap names (`_mi_theap_heap_peek`), or null.
    ///
    /// # Safety
    /// `theap` is a live Theap image or the static empty Theap.
    #[inline]
    pub(crate) unsafe fn heap_at(theap: core::ptr::NonNull<Self>) -> *mut Heap {
        // SAFETY: forwarded; an atomic field load.
        unsafe { (*theap.as_ptr()).heap.load(Ordering::Acquire) }
    }

    /// The TLD this Theap names, or null once detached.
    ///
    /// # Safety
    /// `theap` is a live Theap image.
    #[inline]
    pub(crate) unsafe fn tld_at(theap: core::ptr::NonNull<Self>) -> *mut super::ThreadLocalData {
        // SAFETY: forwarded; a field read by the owning thread or under
        // the caller's list exclusion.
        unsafe { core::ptr::read(core::ptr::addr_of!((*theap.as_ptr()).tld)) }
    }

    /// Whether this Theap is a detached (metadata) Theap, which the
    /// `theaps` statistic does not count (`theap.c:290-292,350-352`).
    ///
    /// # Safety
    /// `theap` is a live Theap image.
    #[inline]
    pub(crate) unsafe fn is_detached_at(theap: core::ptr::NonNull<Self>) -> bool {
        // SAFETY: forwarded; immutable after initialization.
        unsafe { core::ptr::read(core::ptr::addr_of!((*theap.as_ptr()).is_detached)) }
    }

    /// The next Theap on this Theap's TLD list.
    ///
    /// # Safety
    /// `theap` is a live Theap image and the caller excludes TLD-list changes.
    #[inline]
    pub(crate) unsafe fn tld_next_at(theap: core::ptr::NonNull<Self>) -> *mut Self {
        // SAFETY: forwarded.
        unsafe { core::ptr::read(core::ptr::addr_of!((*theap.as_ptr()).tnext)) }
    }
}

impl super::ThreadLocalData {
    /// Source `_mi_tld_detach_theaps` (`theap.c:414-445`) and the list pass
    /// of `mi_thread_theaps_done` (`init.c:401-415`) for one Theap of a
    /// finishing thread: its statistics merge into its Heap and it leaves the
    /// Heap's list (try-locking the Heap and backing off, counting
    /// `heaps_delete_wait`, while a Heap operation holds it), its Heap
    /// identity is cleared, then it leaves this TLD's list. The caller drops
    /// its Heap reference next.
    ///
    /// # Safety
    /// `tld` is the finishing thread's live TLD, `theap` a live member of its
    /// list, and the Theap owns no page.
    pub(crate) unsafe fn detach_theap_for_thread_done(
        tld: core::ptr::NonNull<Self>,
        theap: core::ptr::NonNull<super::Theap>,
        subprocess: &SubprocessIdentity,
    ) -> Result<(), SourceHeapRegistryError> {
        let theap = theap.as_ptr();
        loop {
            // SAFETY: forwarded liveness; the Heap stays live while a Theap
            // names it (a Heap free first detaches its Theaps).
            let heap = unsafe { (*theap).heap.load(Ordering::Acquire) };
            if heap.is_null() {
                break;
            }
            let heap = unsafe { &*heap };
            match heap.theaps_lock.try_lock() {
                Some(guard) => {
                    // SAFETY: the held Heap lock serializes its list.
                    unsafe {
                        heap.statistics.merge_from_and_reset(&(*theap).statistics);
                        let (hnext, hprev) = (*(*theap).hnext.get(), *(*theap).hprev.get());
                        if !hnext.is_null() { *(*hnext).hprev.get() = hprev; }
                        if !hprev.is_null() {
                            *(*hprev).hnext.get() = hnext;
                        } else {
                            core::ptr::addr_of!(heap.theaps).cast_mut().write(hnext);
                        }
                        *(*theap).hnext.get() = core::ptr::null_mut();
                        *(*theap).hprev.get() = core::ptr::null_mut();
                        (*theap).heap.store(core::ptr::null_mut(), Ordering::Release);
                    }
                    guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
                    break;
                }
                None => {
                    subprocess.record_statistics_heap_delete_wait();
                    let _ = crate::os::thread_yield();
                }
            }
        }
        // SAFETY: the TLD lock serializes this thread's list.
        let guard = unsafe { (*tld.as_ptr()).theaps_lock.lock() }.map_err(SourceHeapRegistryError::ListLockAcquire)?;
        unsafe {
            let tld = tld.as_ptr();
            let (tnext, tprev) = ((*theap).tnext, (*theap).tprev);
            if !tnext.is_null() { (*tnext).tprev = tprev; }
            if !tprev.is_null() { (*tprev).tnext = tnext; } else { (*tld).theaps = tnext; }
            (*theap).tnext = core::ptr::null_mut();
            (*theap).tprev = core::ptr::null_mut();
            (*theap).tld = core::ptr::null_mut();
        }
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)
    }

    /// The first Theap on this TLD's list.
    ///
    /// # Safety
    /// `tld` is live and the caller excludes TLD-list changes.
    #[inline]
    pub(crate) unsafe fn theaps_head_at(tld: core::ptr::NonNull<Self>) -> *mut super::Theap {
        // SAFETY: forwarded.
        unsafe { core::ptr::read(core::ptr::addr_of!((*tld.as_ptr()).theaps)) }
    }
}

impl Heap {
    /// Source `_mi_heap_detach_theaps` (`theap.c:381-412`) then the list
    /// hand-off of `mi_heap_free_theaps` (`heap.c:162-172`): every Theap of
    /// this Heap leaves its TLD's list, taking that TLD's lock with a
    /// try-lock and backing off (counting `heaps_delete_wait`) while a
    /// finishing thread holds it; then the Heap list is emptied and returned
    /// through `visit` in list order, with each Theap's Heap links cleared.
    /// `visit` merges statistics and drops the Heap's reference.
    ///
    /// # Safety
    /// The Heap and every listed Theap and TLD are live; the caller excludes
    /// other Heap-list operations on this Heap. A thread that finishes
    /// concurrently changes its TLD list only under that TLD's lock.
    pub(crate) unsafe fn detach_and_take_theaps(
        &self,
        subprocess: &SubprocessIdentity,
        mut visit: impl FnMut(core::ptr::NonNull<super::Theap>),
    ) -> Result<(), SourceHeapRegistryError> {
        loop {
            let guard = self.theaps_lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
            let mut all_detached = true;
            let mut current = self.theaps;
            while let Some(theap) = core::ptr::NonNull::new(current) {
                // SAFETY: the held Heap lock keeps the list and its members.
                let theap = theap.as_ptr();
                let next = unsafe { *(*theap).hnext.get() };
                let tld = unsafe { (*theap).tld };
                if !tld.is_null() {
                    // SAFETY: a listed Theap's TLD is live while it names it.
                    match unsafe { (*tld).theaps_lock.try_lock() } {
                        Some(tld_guard) => {
                            // SAFETY: the TLD lock serializes its list.
                            unsafe {
                                let (tnext, tprev) = ((*theap).tnext, (*theap).tprev);
                                if !tnext.is_null() { (*tnext).tprev = tprev; }
                                if !tprev.is_null() { (*tprev).tnext = tnext; } else { (*tld).theaps = tnext; }
                                (*theap).tnext = core::ptr::null_mut();
                                (*theap).tprev = core::ptr::null_mut();
                                (*theap).tld = core::ptr::null_mut();
                            }
                            tld_guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
                        }
                        None => all_detached = false,
                    }
                }
                current = next;
            }
            guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)?;
            if all_detached {
                break;
            }
            subprocess.record_statistics_heap_delete_wait();
            let _ = crate::os::thread_yield();
        }
        let guard = self.theaps_lock.lock().map_err(SourceHeapRegistryError::ListLockAcquire)?;
        // SAFETY: the held lock serializes the Heap list; no TLD names these
        // Theaps any longer.
        let mut current = unsafe {
            let head = self.theaps;
            core::ptr::addr_of!(self.theaps).cast_mut().write(core::ptr::null_mut());
            head
        };
        while let Some(theap) = core::ptr::NonNull::new(current) {
            // SAFETY: as above.
            unsafe {
                current = *(*theap.as_ptr()).hnext.get();
                *(*theap.as_ptr()).hnext.get() = core::ptr::null_mut();
                *(*theap.as_ptr()).hprev.get() = core::ptr::null_mut();
            }
            visit(theap);
        }
        guard.unlock().map_err(SourceHeapRegistryError::ListLockRelease)
    }

    /// This Heap's subprocess identity (immutable after initialization).
    #[inline]
    pub(crate) fn subprocess_pointer(&self) -> *mut SubprocessIdentity { self.subprocess }

    /// The Heap's slot for arena `arena_index` (`mi_heap_arena_pages`).
    #[inline]
    pub(crate) fn arena_pages_slot(&self, arena_index: usize) -> Option<core::ptr::NonNull<super::ArenaPages>> {
        core::ptr::NonNull::new(self.arena_pages.get(arena_index)?.load(Ordering::Acquire))
    }

    /// One bitmap of this non-main Heap's `mi_arena_pages_t` for `arena`:
    /// index 0 is `pages`, `1 + bin` is `pages_abandoned[bin]`.
    ///
    /// # Safety
    /// The Heap's image for this arena, if any, stays live while the view is
    /// used.
    pub(crate) unsafe fn non_main_arena_pages_bitmap<'a>(
        &self,
        arena: &crate::arena::ArenaView<'a>,
        bitmap: usize,
    ) -> Option<crate::bitmap::BitmapView<'a>> {
        if self.is_subprocess_main() {
            return None;
        }
        let pages = self.arena_pages_slot(arena.arena().arena_index)?;
        let layout = crate::arena::ArenaPagesLayout::for_slice_count(arena.arena().slice_count)?;
        // SAFETY: an installed image was initialized with this exact layout
        // before its Release publication.
        let pointer = unsafe {
            if bitmap == 0 { (*pages.as_ptr()).pages } else { *(*pages.as_ptr()).pages_abandoned.get(bitmap - 1)? }
        };
        // SAFETY: as above.
        unsafe { crate::bitmap::BitmapView::attach(pointer, layout.bitmap_layout().byte_size(), layout.bitmap_layout()) }
    }

    /// Source `mi_heap_ensure_arena_pages` (`arena.c:699-723`) for a non-main
    /// Heap: under the Heap's `arena_pages_lock`, `allocate` supplies a
    /// zeroed, `BCHUNK_SIZE`-aligned block of the source `mi_arena_pages_t`
    /// size for `arena` (source allocates it with `mi_heap_zalloc_aligned`
    /// from the subprocess main Heap, `arena.c:1661-1672`), whose bitmaps are
    /// initialized and whose header is Release-published into the slot.
    ///
    /// # Safety
    /// `arena` is a live arena of this Heap's subprocess; `allocate` returns
    /// an exclusively owned block of at least the requested size.
    pub(crate) unsafe fn ensure_non_main_arena_pages(
        &self,
        arena: &crate::arena::ArenaView<'_>,
        allocate: impl FnOnce(usize, usize) -> Option<core::ptr::NonNull<u8>>,
    ) -> bool {
        let index = arena.arena().arena_index;
        if self.is_subprocess_main() || index >= self.arena_pages.len() {
            return false;
        }
        if self.arena_pages_slot(index).is_some() {
            return true;
        }
        let Some(layout) = crate::arena::ArenaPagesLayout::for_slice_count(arena.arena().slice_count) else {
            return false;
        };
        let Ok(guard) = self.arena_pages_lock.lock() else { return false };
        let installed = self.arena_pages_slot(index).is_some() || 'image: {
            let Some(block) = allocate(layout.byte_size(), crate::bitmap::BCHUNK_SIZE) else { break 'image false };
            let mut pointers = [core::ptr::null_mut(); crate::config::ARENA_BIN_COUNT + 1];
            for (bitmap, slot) in pointers.iter_mut().enumerate() {
                let Some(offset) = layout.bitmap_offset(bitmap) else { break 'image false };
                // SAFETY: the block holds the complete layout.
                let pointer = unsafe { block.as_ptr().add(offset) };
                // SAFETY: a zeroed, exclusively owned bitmap image.
                if unsafe {
                    crate::bitmap::BitmapView::initialize_zeroed(pointer, layout.bitmap_layout().byte_size(), layout.bitmap_layout())
                }.is_none() {
                    break 'image false;
                }
                *slot = pointer;
            }
            // SAFETY: the header lies at the block start, written before
            // the Release publication below.
            unsafe {
                block.as_ptr().cast::<super::ArenaPages>().write(super::ArenaPages {
                    pages: pointers[0],
                    pages_abandoned: core::array::from_fn(|bin| pointers[bin + 1]),
                });
            }
            self.arena_pages[index].store(block.as_ptr().cast(), Ordering::Release);
            true
        };
        guard.unlock().is_ok() && installed
    }

    /// Clears every `mi_arena_pages_t` slot of this non-main Heap and
    /// returns each image through `free`, in arena order (`heap.c:185-194`).
    pub(crate) fn take_non_main_arena_pages(&self, mut free: impl FnMut(core::ptr::NonNull<u8>) -> bool) -> bool {
        if self.is_subprocess_main() {
            return false;
        }
        let Ok(guard) = self.arena_pages_lock.lock() else { return false };
        let mut freed = true;
        for slot in &self.arena_pages {
            let pages = slot.load(Ordering::Relaxed);
            if let Some(pages) = core::ptr::NonNull::new(pages) {
                slot.store(core::ptr::null_mut(), Ordering::Relaxed);
                freed &= free(pages.cast());
            }
        }
        guard.unlock().is_ok() && freed
    }

    /// The OS-abandoned push of `_mi_arenas_page_abandon`
    /// (`arena.c:1340-1353`) for a child subprocess Heap: under the Heap's
    /// `os_abandoned_pages_lock`, `page` goes to the front of the list.
    ///
    /// # Safety
    /// `heap` is live; the caller holds `page`'s low owner bit after its
    /// abandoned identity is set, and `page` is in no list. Only this lock's
    /// holders touch the list and the pages' list links.
    pub(crate) unsafe fn push_os_abandoned_page_at(heap: core::ptr::NonNull<Heap>, page: core::ptr::NonNull<super::Page>) -> bool {
        let heap = heap.as_ptr();
        // SAFETY: forwarded; the list fields are written only under the lock.
        unsafe {
            let Ok(guard) = (*heap).os_abandoned_pages_lock.lock() else { return false };
            let page = page.as_ptr();
            let head = core::ptr::read(core::ptr::addr_of!((*heap).os_abandoned_pages));
            (*page).prev = core::ptr::null_mut();
            (*page).next = head;
            if !head.is_null() {
                (*head).prev = page;
            }
            core::ptr::addr_of_mut!((*heap).os_abandoned_pages).write(page);
            guard.unlock().is_ok()
        }
    }

    /// The OS-abandoned removal of `_mi_arenas_page_unabandon`
    /// (`arena.c:1410-1419`) for a child subprocess Heap.
    ///
    /// # Safety
    /// As for [`Self::push_os_abandoned_page_at`], with `page` on the list.
    pub(crate) unsafe fn remove_os_abandoned_page_at(heap: core::ptr::NonNull<Heap>, page: core::ptr::NonNull<super::Page>) -> bool {
        let heap = heap.as_ptr();
        // SAFETY: as above.
        unsafe {
            let Ok(guard) = (*heap).os_abandoned_pages_lock.lock() else { return false };
            let page = page.as_ptr();
            let (prev, next) = ((*page).prev, (*page).next);
            if !prev.is_null() { (*prev).next = next; }
            if !next.is_null() { (*next).prev = prev; }
            if core::ptr::read(core::ptr::addr_of!((*heap).os_abandoned_pages)) == page {
                core::ptr::addr_of_mut!((*heap).os_abandoned_pages).write(next);
            }
            (*page).next = core::ptr::null_mut();
            (*page).prev = core::ptr::null_mut();
            guard.unlock().is_ok()
        }
    }

    /// The first page on this Heap's OS-abandoned list.
    ///
    /// # Safety
    /// The caller excludes list changes (a Heap free with detached Theaps).
    pub(crate) unsafe fn os_abandoned_head_at(heap: core::ptr::NonNull<Heap>) -> *mut super::Page {
        // SAFETY: forwarded.
        unsafe { core::ptr::read(core::ptr::addr_of!((*heap.as_ptr()).os_abandoned_pages)) }
    }

    /// Records one page leaving this Heap without a Theap
    /// (`mi_heap_stat_decrease` of `page_bins[bin]` and `pages`).
    #[inline]
    pub(crate) fn record_page_released(&self, statistics_bin: usize) -> bool {
        self.statistics.page_released(statistics_bin)
    }
}

/// The mapped-abandoned capability of one arena page of a non-main Heap:
/// that Heap's `mi_arena_pages_t.pages_abandoned[bin]` for the arena, paired
/// with the Heap's `abandoned_count[bin]` (`arena.c:1304-1337,1383-1409`).
/// Every access requires the Heap's ordinary `pages` bit for the slice, as
/// `mi_page_arena_pages` asserts.
pub(crate) struct NonMainArenaMappedAbandonedPage {
    heap: core::ptr::NonNull<Heap>,
    arena: core::ptr::NonNull<super::Arena>,
    bin: usize,
}

impl NonMainArenaMappedAbandonedPage {
    fn view(&self) -> Option<crate::arena::ArenaView<'_>> {
        // SAFETY: construction proved a live arena of the Heap's subprocess,
        // which outlives every page of the Heap.
        unsafe { crate::arena::ArenaView::from_ptr(self.arena.as_ptr()) }
    }

    fn with_bitmap<R>(&self, bitmap: usize, operation: impl FnOnce(&crate::bitmap::BitmapView<'_>) -> R) -> Option<R> {
        let view = self.view()?;
        // SAFETY: the Heap's record for this arena stays installed while
        // the Heap owns a page in it.
        let pages = unsafe { self.heap.as_ref().non_main_arena_pages_bitmap(&view, bitmap) }?;
        Some(operation(&pages))
    }

    fn ordinary_is_set(&self, slice_index: usize) -> bool {
        self.with_bitmap(0, |pages| pages.is_set_range(slice_index, 1) == Some(true)) == Some(true)
    }
}

impl crate::abandoned::MappedAbandonedPages for NonMainArenaMappedAbandonedPage {
    fn bin(&self) -> usize { self.bin }

    fn page_slice_index(&self, memory: super::MemoryId) -> Option<usize> {
        let memory = memory.arena_memory()?;
        if memory.arena != self.arena.as_ptr() {
            return None;
        }
        // SAFETY: the live arena of this capability.
        let slice_count = unsafe { self.arena.as_ref() }.slice_count;
        let index = memory.slice_index as usize;
        (index < slice_count).then_some(index)
    }

    fn is_clear(&self, slice_index: usize) -> bool {
        self.ordinary_is_set(slice_index)
            && self.with_bitmap(1 + self.bin, |pages| pages.is_clear_range(slice_index, 1) == Some(true)) == Some(true)
    }

    fn publish(&self, slice_index: usize) -> bool {
        if !self.ordinary_is_set(slice_index) {
            return false;
        }
        let published = self.with_bitmap(1 + self.bin, |pages| {
            pages.set_range(slice_index, 1).is_some_and(|transition| transition.all_transitioned())
        }) == Some(true);
        if published {
            // SAFETY: the live Heap; an atomic counter.
            unsafe { self.heap.as_ref() }.increment_abandoned_count(self.bin);
        }
        published
    }

    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> crate::abandoned::MappedAbandonedClaim
    where
        F: FnMut(usize) -> crate::bitmap::AbandonedBitmapClaim,
    {
        let mut claim = claim;
        let claimed = self.with_bitmap(1 + self.bin, |pages| {
            pages.try_find_and_claim_abandoned(thread_sequence, |slice_index| {
                if self.ordinary_is_set(slice_index) {
                    claim(slice_index)
                } else {
                    crate::bitmap::AbandonedBitmapClaim::KeepSet
                }
            })
        });
        let Some(Some(slice_index)) = claimed else {
            return crate::abandoned::MappedAbandonedClaim::None;
        };
        // SAFETY: as in `publish`.
        if unsafe { self.heap.as_ref() }.decrement_abandoned_count(self.bin) {
            crate::abandoned::MappedAbandonedClaim::Claimed(slice_index)
        } else {
            crate::abandoned::MappedAbandonedClaim::CountDecrementFailed(slice_index)
        }
    }

    fn clear_once_set(&self, slice_index: usize) -> bool {
        // SAFETY: the Heap's subprocess outlives it.
        let Some(subprocess) = (unsafe { self.heap.as_ref().subprocess.as_ref() }) else { return false };
        self.with_bitmap(1 + self.bin, |pages| pages.clear_once_set(subprocess, slice_index) == Some(())) == Some(true)
    }

    fn decrement_after_identity_clear(&self) -> bool {
        // SAFETY: as in `publish`.
        unsafe { self.heap.as_ref() }.decrement_abandoned_count(self.bin)
    }
}

impl Heap {
    /// The mapped-abandoned capability for `bin` of this non-main Heap's
    /// record for `arena`, if the Heap has one.
    pub(crate) fn non_main_abandoned_page(
        heap: core::ptr::NonNull<Heap>,
        arena: &crate::arena::ArenaView<'_>,
        bin: usize,
    ) -> Option<NonMainArenaMappedAbandonedPage> {
        // SAFETY: the caller's live Heap.
        let heap_ref = unsafe { heap.as_ref() };
        if heap_ref.is_subprocess_main()
            || bin >= crate::config::ARENA_BIN_COUNT
            || heap_ref.arena_pages_slot(arena.arena().arena_index).is_none()
        {
            return None;
        }
        Some(NonMainArenaMappedAbandonedPage {
            heap,
            arena: core::ptr::NonNull::from(arena.arena()),
            bin,
        })
    }
}

impl super::Page {
    /// The Theap this page names (`page->theap`).
    ///
    /// # Safety
    /// `page` is live page metadata whose owner does not change during the
    /// read (for example, the page of a live block of the calling thread).
    #[inline]
    pub(crate) unsafe fn theap_at(page: core::ptr::NonNull<Self>) -> *mut super::Theap {
        // SAFETY: forwarded; a raw field read.
        unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).theap)) }
    }

    /// `mi_heap_delete_page`'s first steps (`arena.c:2531-2546`): claim the
    /// page's low owner bit; a page that is not abandoned then has its queue
    /// links and Theap identity cleared (`mi_page_set_theap(page, NULL)`).
    /// Returns whether the page was already abandoned, which the caller then
    /// unabandons.
    ///
    /// # Safety
    /// `page` is live page metadata of a Heap whose Theaps are all detached,
    /// so no thread operates on the page, and it stays live until the caller
    /// frees or moves it.
    pub(crate) unsafe fn claim_for_heap_delete(page: core::ptr::NonNull<Self>) -> bool {
        let page = page.as_ptr();
        // SAFETY: forwarded; atomic fields, then fields no thread uses.
        unsafe {
            (*page).xthread_free.fetch_or(1, Ordering::AcqRel);
            let thread = (*page).xthread_id.load(Ordering::Relaxed) & !(super::PAGE_FLAG_MASK as usize);
            if thread <= super::THREAD_ID_ABANDONED_MAPPED {
                return true;
            }
            (*page).next = core::ptr::null_mut();
            (*page).prev = core::ptr::null_mut();
            (*page).theap = core::ptr::null_mut();
            let mut old = (*page).xthread_id.load(Ordering::Relaxed);
            loop {
                let new = super::THREAD_ID_ABANDONED | (old & super::PAGE_FLAG_MASK as usize);
                match (*page).xthread_id.compare_exchange_weak(old, new, Ordering::Release, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(current) => old = current,
                }
            }
        }
        false
    }

    /// The next page on the list this page is linked in.
    ///
    /// # Safety
    /// The caller excludes changes to that list.
    pub(crate) unsafe fn next_at(page: core::ptr::NonNull<Self>) -> *mut Self {
        // SAFETY: forwarded.
        unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).next)) }
    }

    /// Whether the page has the mapped-abandoned identity.
    ///
    /// # Safety
    /// `page` is live page metadata.
    pub(crate) unsafe fn is_abandoned_mapped_at(page: core::ptr::NonNull<Self>) -> bool {
        // SAFETY: an atomic field load.
        let thread = unsafe { (*page.as_ptr()).xthread_id.load(Ordering::Relaxed) };
        thread & !(super::PAGE_FLAG_MASK as usize) == super::THREAD_ID_ABANDONED_MAPPED
    }

    /// `mi_page_clear_abandoned_mapped` (`internal.h:1036-1039`).
    ///
    /// # Safety
    /// The caller holds the page's low owner bit and removed its bitmap bit.
    pub(crate) unsafe fn clear_abandoned_mapped_at(page: core::ptr::NonNull<Self>) {
        // SAFETY: an atomic field update.
        unsafe { (*page.as_ptr()).xthread_id.fetch_and(super::PAGE_FLAG_MASK as usize, Ordering::Relaxed) };
    }

    /// Destroy arm of `mi_heap_delete_page`: `page->used = 0`.
    ///
    /// # Safety
    /// The caller holds the page's low owner bit and no block is used again.
    pub(crate) unsafe fn discard_used_for_heap_destroy(page: core::ptr::NonNull<Self>) {
        // SAFETY: forwarded.
        unsafe { (*page.as_ptr()).used = 0 };
    }

    /// Move arm of `mi_heap_delete_page`: `page->heap = heap_target`.
    ///
    /// # Safety
    /// The caller holds the page's low owner bit; `heap` is live.
    pub(crate) unsafe fn set_heap_for_move(page: core::ptr::NonNull<Self>, heap: core::ptr::NonNull<Heap>) {
        // SAFETY: forwarded.
        unsafe { (*page.as_ptr()).heap = heap.as_ptr() };
    }

    /// The number of live blocks of a page whose low owner bit the caller
    /// holds.
    ///
    /// # Safety
    /// As above.
    pub(crate) unsafe fn used_at_claimed(page: core::ptr::NonNull<Self>) -> usize {
        // SAFETY: forwarded.
        unsafe { (*page.as_ptr()).used }
    }
}

#[cfg(test)]
impl super::Theap {
    /// `(hnext, hprev, tnext, tprev, tld)` of a live Theap, for the pinned-C
    /// list checks.
    ///
    /// # Safety
    /// No list operation runs during the read.
    pub(crate) unsafe fn test_list_links(
        theap: core::ptr::NonNull<Self>,
    ) -> (*mut Self, *mut Self, *mut Self, *mut Self, *mut super::ThreadLocalData) {
        let theap = theap.as_ptr();
        unsafe { (*(*theap).hnext.get(), *(*theap).hprev.get(), (*theap).tnext, (*theap).tprev, (*theap).tld) }
    }
}

#[cfg(test)]
impl super::Page {
    /// `(next, prev)` of a page.
    ///
    /// # Safety
    /// No list operation runs during the read.
    pub(crate) unsafe fn test_list_links(page: core::ptr::NonNull<Self>) -> (*mut Self, *mut Self) {
        unsafe { ((*page.as_ptr()).next, (*page.as_ptr()).prev) }
    }
}

#[cfg(test)]
impl Heap {
    /// The head of this Heap's Theap list.
    pub(crate) fn test_theaps_head(&self) -> *mut super::Theap { self.theaps }

    /// How many per-arena page records this Heap has.
    pub(crate) fn test_arena_page_record_count(&self) -> usize {
        self.arena_pages.iter().filter(|slot| !slot.load(Ordering::Relaxed).is_null()).count()
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
