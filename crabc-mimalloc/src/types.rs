// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h:288-456`
// (`MemoryKind`, memory-ID layout, `Block`, page flags, and `Page`),
// `include/mimalloc/types.h:499-598` (the default-theap prefix, including
// `mi_page_queue_t`, `mi_random_ctx_t`, and `mi_theap_t` through `memid`),
// `include/mimalloc/types.h:618-680` (the heap prefix),
// `include/mimalloc/types.h:690-701` (complete source-ordered TLD fields),
// `include/mimalloc/types.h:608-758`
// (arena-page and arena metadata layouts), `src/init.c:15-145` (the
// empty-page, direct-page table, all 75 default queues, detached TLD, and
// empty-theap initializers), `src/theap.c:228-306,357-369,414-449` (dynamic
// Theap initialization, canonical cached reference pair, and list detach),
// `src/arena.c:674-723,870-1037,1240-1282` (per-heap arena-pages
// acquisition/publication and fresh/release page metadata
// publication), `src/page.c:214-243,574-644,708-757` (false-force owner-local
// collection and fresh-page local-state invariants),
// and `src/arena.c:199-219` (arena memory-ID construction and projection).
// The intrusive membership operations from `src/page-queue.c:40-55,126-423`
// are isolated in the `page_queue` child module below.
// `Heap` and `Theap` below are exact source-layout *prefixes* only.
// `ThreadLocalData` preserves all source field ordering and meaning, but its
// lock is the documented private-futex boundary rather than a pthread ABI
// object. The bounded process-main identity and its TLD ticket/count contract
// are represented separately in `subproc.rs`. `main_theap.rs` attaches the
// ticket-zero static TLD to one static main heap/default Theap, while
// `dynamic_theap.rs` owns one private later-ticket metadata TLD/Theap over a
// caller-pinned Heap. Complete subprocess/list/lock/statistics lifecycle and
// all C ABI-size claims remain absent. No code may treat a Rust type here as
// `sizeof(mi_heap_t)`, `sizeof(mi_tld_t)`, or `sizeof(mi_theap_t)`.

use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::num::NonZeroUsize;
use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicI64, AtomicPtr, AtomicUsize, Ordering};

use crate::config::{
    BIN_COUNT, BIN_FULL, LARGE_MAX_OBJ_WSIZE, MAX_ARENAS, PAGES_DIRECT,
    WORD_SIZE,
};
use crate::lock::PrivateLock;
use crate::random::TheapRandomImage;
use crate::subproc::MainSubprocess;

pub(crate) type ThreadId = usize;
pub(crate) type ThreadFree = usize;
pub(crate) type PageFlags = usize;
/// Compatibility spelling for source fields that carry the bounded
/// process-main identity. This is deliberately not a complete `mi_subproc_t`
/// layout; see [`MainSubprocess`] for the represented fields.
pub(crate) type Subprocess = MainSubprocess;

pub(crate) const PAGE_IN_FULL_QUEUE: PageFlags = 0x01;
pub(crate) const PAGE_HAS_INTERIOR_POINTERS: PageFlags = 0x02;
pub(crate) const PAGE_FLAG_MASK: PageFlags = 0x03;
pub(crate) const PAGE_FLAG_BITS: usize = 2;
pub(crate) const THREAD_ID_ABANDONED: ThreadId = 0;
pub(crate) const THREAD_ID_ABANDONED_MAPPED: ThreadId = 1 << PAGE_FLAG_BITS;
pub(crate) const THREAD_ID_DETACHED: ThreadId = 2 << PAGE_FLAG_BITS;

/// One valid non-detached `mi_threadid_t` for the exclusive bootstrap slice.
///
/// `src/prim/prim-tls.c:_mi_thread_id` reserves the low two bits for page
/// flags. The source's detached and abandoned encodings occupy the other
/// values below `3 << MI_PAGE_FLAG_BITS`; an attached default theap must not
/// use any of them. This is an input contract supplied by the integrating
/// runtime, not a thread-ID syscall or TLS mechanism.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveThreadId(NonZeroUsize);

impl LiveThreadId {
    #[inline]
    pub(crate) const fn new(raw: ThreadId) -> Option<Self> {
        if raw == THREAD_ID_ABANDONED
            || raw == THREAD_ID_ABANDONED_MAPPED
            || raw == THREAD_ID_DETACHED
            || raw & PAGE_FLAG_MASK != 0
        {
            return None;
        }

        match NonZeroUsize::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub(crate) const fn get(self) -> ThreadId {
        self.0.get()
    }
}

/// One source-issued `mi_tld_t::thread_seq` value.
///
/// `src/init.c:mi_tld_create` obtains this value from the previous result of
/// its relaxed `subproc->thread_total_count` increment. The bounded
/// [`crate::subproc::MainSubprocess`] owns that increment and turns the old
/// value into a linear registration ticket; this transparent value type
/// records the source field inside `ThreadLocalData` without becoming a second
/// sequence source.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadSequence(usize);

impl ThreadSequence {
    /// Records the old value returned by the source relaxed total-thread
    /// counter increment.
    #[inline]
    pub(crate) const fn from_previous_total_count(previous: usize) -> Self {
        Self(previous)
    }

    /// Returns the source sequence value stored in `mi_tld_t`.
    #[inline]
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

/// The exact source identity attached to one exclusively mutated theap.
///
/// Ordinary default theaps carry a valid running-thread identity. The
/// process metadata theap is different: `src/init.c` intentionally keeps its
/// TLD detached and serializes all of its access through
/// `theap_meta_lock`. Keeping that distinction in the type prevents the
/// metadata owner from pretending it is a thread-local cache belonging to
/// whichever thread initialized it first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TheapOwner {
    Live(LiveThreadId),
    Detached,
}

impl TheapOwner {
    #[inline]
    pub(crate) const fn thread_id(self) -> ThreadId {
        match self {
            Self::Live(thread_id) => thread_id.get(),
            Self::Detached => THREAD_ID_DETACHED,
        }
    }

    #[inline]
    const fn is_detached(self) -> bool {
        matches!(self, Self::Detached)
    }
}

/// Source-ordered prefix of `mi_heap_t` through `memid`.
///
/// The process-static main attachment needs the selected normal-release heap
/// fields through its theap list lock.  The source abandoned-page, arena-page,
/// and lock regions are kept as valid zero/deferred state so their later
/// lifecycle can extend this one image without reordering the prefix.  The
/// trailing `mi_stats_t` is deliberately absent: statistics needs its own
/// source merge and subprocess accounting contract, so this remains neither a
/// complete `mi_heap_t` layout claim nor a first-class heap API.
#[repr(C)]
pub(crate) struct Heap {
    subprocess: *mut MainSubprocess,
    heap_seq: usize,
    next: *mut Heap,
    prev: *mut Heap,
    theap_slot: usize,
    exclusive_arena: *mut Arena,
    numa_node: i32,
    theaps: *mut Theap,
    theaps_lock: PrivateLock,
    abandoned_count: [AtomicUsize; BIN_COUNT],
    os_abandoned_pages: *mut Page,
    os_abandoned_pages_lock: PrivateLock,
    arena_pages: [AtomicPtr<ArenaPages>; MAX_ARENAS],
    arena_pages_lock: PrivateLock,
    memid: MemoryId,
}

impl Heap {
    #[inline]
    pub(crate) const fn bootstrap_empty() -> Self {
        Self {
            subprocess: null_mut(),
            heap_seq: 0,
            next: null_mut(),
            prev: null_mut(),
            theap_slot: 0,
            exclusive_arena: null_mut(),
            numa_node: 0,
            theaps: null_mut(),
            theaps_lock: PrivateLock::new(),
            abandoned_count: [const { AtomicUsize::new(0) }; BIN_COUNT],
            os_abandoned_pages: null_mut(),
            os_abandoned_pages_lock: PrivateLock::new(),
            arena_pages: [const { AtomicPtr::new(null_mut()) }; MAX_ARENAS],
            arena_pages_lock: PrivateLock::new(),
            memid: MemoryId::none(),
        }
    }

    /// Initializes the statically allocated main heap fields used before the
    /// future heap/subprocess list and arena lifecycle exists.
    ///
    /// This is the selected source `_mi_heap_init` main-heap shape: fast key
    /// one, main subprocess, first (zero) heap sequence, no exclusive arena,
    /// no NUMA affinity, empty theap list, and valid private list locks.  The
    /// source's abandoned-page and arena-page regions stay zeroed and are not
    /// a claim that their routing/lifetime protocols are implemented.
    #[inline]
    pub(crate) fn initialize_main_static(
        &mut self,
        subprocess: &'static MainSubprocess,
        memid: MemoryId,
    ) {
        debug_assert!(self.subprocess.is_null());
        debug_assert!(self.theaps.is_null());
        self.subprocess = subprocess.as_ptr();
        // `mi_atomic_increment_relaxed` returns the previous source count;
        // the one process-static main heap observes its initial value zero.
        self.heap_seq = 0;
        self.next = null_mut();
        self.prev = null_mut();
        // `internal.h:mi_thread_local_key_fast` is the fixed key value one.
        self.theap_slot = 1;
        self.exclusive_arena = null_mut();
        self.numa_node = -1;
        self.theaps = null_mut();
        self.theaps_lock = PrivateLock::new();
        self.abandoned_count = [const { AtomicUsize::new(0) }; BIN_COUNT];
        self.os_abandoned_pages = null_mut();
        self.os_abandoned_pages_lock = PrivateLock::new();
        self.arena_pages = [const { AtomicPtr::new(null_mut()) }; MAX_ARENAS];
        self.arena_pages_lock = PrivateLock::new();
        self.memid = memid;
    }

    /// Initializes a caller-pinned first-class heap image for one regular
    /// dynamic Theap binding.
    ///
    /// The caller retains the address-stable `Pin<&mut Heap>` for the entire
    /// attachment; this method neither allocates the heap nor claims the C
    /// `mi_heap_t` allocation size. Its `MemoryId::None` records precisely
    /// that caller storage remains externally owned. Heap/subprocess list
    /// counters and full `mi_heap_new/delete/destroy` are deferred.
    ///
    /// # Safety
    ///
    /// `self` must be the unique address-stable `Heap::bootstrap_empty()`
    /// image for this attachment, with no page state, aliases, private-lock
    /// guards, or waiters. The source has a separately allocated first-class
    /// heap; this bounded caller-storage substitute cannot reconstruct that
    /// stronger allocation ownership from its prefix fields.
    #[inline]
    pub(crate) unsafe fn initialize_dynamic_binding(
        &mut self,
        subprocess: &'static MainSubprocess,
        regular_theap_key: usize,
    ) -> bool {
        if regular_theap_key == 0
            || regular_theap_key == 1
            || !self.subprocess.is_null()
            || !self.theaps.is_null()
            || self.memid.kind() != MemoryKind::None
        {
            return false;
        }
        // SAFETY: the private dynamic attachment proves that this exact
        // caller-pinned image is a unique `Heap::bootstrap_empty()` value with
        // no guards, waiters, page state, or aliases. The small observable
        // checks above reject obvious reuse, while the complete pristine-image
        // proof remains the unsafe caller obligation because private locks and
        // atomics are intentionally not comparable/reconstructable here.
        self.subprocess = subprocess.as_ptr();
        // The real first-class heap sequence comes from deferred subprocess
        // counters. This caller-owned binding has no heap-list insertion and
        // therefore records only the source-valid initial field value.
        self.heap_seq = 0;
        self.next = null_mut();
        self.prev = null_mut();
        self.theap_slot = regular_theap_key;
        self.exclusive_arena = null_mut();
        self.numa_node = -1;
        self.theaps = null_mut();
        self.theaps_lock = PrivateLock::new();
        self.abandoned_count = [const { AtomicUsize::new(0) }; BIN_COUNT];
        self.os_abandoned_pages = null_mut();
        self.os_abandoned_pages_lock = PrivateLock::new();
        self.arena_pages = [const { AtomicPtr::new(null_mut()) }; MAX_ARENAS];
        self.arena_pages_lock = PrivateLock::new();
        self.memid = MemoryId::none();
        true
    }

    #[inline]
    pub(crate) fn matches_dynamic_binding(
        &self,
        subprocess: &MainSubprocess,
        regular_theap_key: usize,
    ) -> bool {
        regular_theap_key != 0
            && regular_theap_key != 1
            && core::ptr::eq(self.subprocess, subprocess.as_ptr())
            && self.theap_slot == regular_theap_key
            && self.memid.kind() == MemoryKind::None
    }

    /// Exact Relaxed source `heap->abandoned_count[bin]` increment after a
    /// dynamic mapped-abandoned bit becomes visible.
    #[inline]
    pub(crate) fn increment_abandoned_count(&self, bin: usize) {
        if bin < BIN_COUNT {
            self.abandoned_count[bin].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Exact Relaxed mapped-bit claim/unabandon decrement. A zero counter is
    /// an invalid owner pairing and remains untouched rather than wrapping.
    #[inline]
    pub(crate) fn decrement_abandoned_count(&self, bin: usize) -> bool {
        if bin >= BIN_COUNT {
            return false;
        }
        let count = &self.abandoned_count[bin];
        let mut current = count.load(Ordering::Relaxed);
        while current != 0 {
            match count.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
        false
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn abandoned_count(&self, bin: usize) -> Option<usize> {
        (bin < BIN_COUNT).then(|| self.abandoned_count[bin].load(Ordering::Relaxed))
    }

    /// Acquire-loads one source `heap->arena_pages[arena]` slot.
    ///
    /// Callers must retain the matching main in-place or dynamic heap-local
    /// owner; this raw table observation does not select a bitmap policy.
    #[inline]
    pub(crate) fn arena_pages_at(&self, arena_index: usize) -> Option<NonNull<ArenaPages>> {
        if arena_index >= MAX_ARENAS {
            return None;
        }
        NonNull::new(self.arena_pages[arena_index].load(Ordering::Acquire))
    }

    /// Backward-compatible spelling for the existing non-main owner paths.
    #[inline]
    pub(crate) fn dynamic_arena_pages_at(&self, arena_index: usize) -> Option<NonNull<ArenaPages>> {
        self.arena_pages_at(arena_index)
    }

    /// Installs the source main arena's embedded `pages_main` image into the
    /// static main Heap's arena slot.
    ///
    /// Pinned `mi_heap_ensure_arena_pages` does not allocate a dynamic
    /// `mi_arena_pages_t` for `mi_heap_main()`: it points the main Heap at the
    /// selected arena's in-place `pages_main` instead. An already identical
    /// installation is the normal later-allocation fast path; any different
    /// non-null image is an invalid-owner boundary rather than a fallback to
    /// a dynamic image.
    #[inline]
    pub(crate) fn install_main_arena_pages(
        &self,
        subprocess: &MainSubprocess,
        arena_index: usize,
        pages: NonNull<ArenaPages>,
    ) -> Result<(), HeapArenaPagesError> {
        if arena_index >= MAX_ARENAS {
            return Err(HeapArenaPagesError::ArenaIndex);
        }
        if self.theap_slot != 1
            || self.memid.kind() != MemoryKind::Static
            || !core::ptr::eq(self.subprocess, subprocess.as_ptr())
        {
            return Err(HeapArenaPagesError::NotMainStatic);
        }
        let guard = self
            .arena_pages_lock
            .lock()
            .map_err(HeapArenaPagesError::Lock)?;
        let current = self.arena_pages[arena_index].load(Ordering::Acquire);
        let result = if current.is_null() {
            self.arena_pages[arena_index].store(pages.as_ptr(), Ordering::Release);
            Ok(())
        } else if current == pages.as_ptr() {
            Ok(())
        } else {
            Err(HeapArenaPagesError::Occupied)
        };
        let unlock = guard.unlock();
        match (result, unlock) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(error)) => Err(HeapArenaPagesError::Lock(error)),
            (Err(error), _) => Err(error),
        }
    }

    /// Release-publishes one freshly initialized private dynamic
    /// `mi_arena_pages_t` image under the source heap lock.
    ///
    /// This is intentionally a one-image bounded operation: the dynamic
    /// attachment owns the exact arena identity and keeps the matching typed
    /// metadata capability alive. A non-null slot or busy lock is an
    /// invalid-owner boundary, never a fallback to main-heap `pages_main`.
    #[inline]
    pub(crate) fn publish_dynamic_arena_pages(
        &self,
        arena_index: usize,
        pages: NonNull<ArenaPages>,
    ) -> Result<(), HeapArenaPagesError> {
        if arena_index >= MAX_ARENAS {
            return Err(HeapArenaPagesError::ArenaIndex);
        }
        let guard = self
            .arena_pages_lock
            .try_lock()
            .ok_or(HeapArenaPagesError::Busy)?;
        if !self.arena_pages[arena_index].load(Ordering::Acquire).is_null() {
            let _ = guard.unlock();
            return Err(HeapArenaPagesError::Occupied);
        }
        self.arena_pages[arena_index].store(pages.as_ptr(), Ordering::Release);
        guard.unlock().map_err(HeapArenaPagesError::Lock)
    }

    /// Removes precisely the prior private dynamic arena-pages image before
    /// its retained metadata capability is freed.
    #[inline]
    pub(crate) fn remove_dynamic_arena_pages(
        &self,
        arena_index: usize,
        expected: NonNull<ArenaPages>,
    ) -> Result<(), HeapArenaPagesError> {
        if arena_index >= MAX_ARENAS {
            return Err(HeapArenaPagesError::ArenaIndex);
        }
        let guard = self
            .arena_pages_lock
            .try_lock()
            .ok_or(HeapArenaPagesError::Busy)?;
        if self.arena_pages[arena_index].load(Ordering::Acquire) != expected.as_ptr() {
            let _ = guard.unlock();
            return Err(HeapArenaPagesError::Mismatch);
        }
        self.arena_pages[arena_index].store(null_mut(), Ordering::Release);
        guard.unlock().map_err(HeapArenaPagesError::Lock)
    }

    /// Retires only the bounded caller-storage dynamic-binding fields after
    /// the exact Theap was detached from this heap list. This is neither
    /// `_mi_heap_delete` nor a general caller-heap reset: the caller retains
    /// its storage and every deferred heap/page/arena region stays untouched.
    ///
    /// # Safety
    ///
    /// The private attachment must have detached the sole Theap, established
    /// that the heap-list lock has no guards or waiters, and retained exclusive
    /// address-stable authority for this caller image.
    #[inline]
    pub(crate) unsafe fn retire_dynamic_binding_after_detach(&mut self) -> bool {
        if !self.theaps.is_null()
            || self
                .arena_pages
                .iter()
                .any(|slot| !slot.load(Ordering::Acquire).is_null())
        {
            return false;
        }
        let guard = match self.theaps_lock.try_lock() {
            Some(guard) => guard,
            None => return false,
        };
        if guard.unlock().is_err() {
            return false;
        }
        self.subprocess = null_mut();
        self.heap_seq = 0;
        self.next = null_mut();
        self.prev = null_mut();
        self.theap_slot = 0;
        self.exclusive_arena = null_mut();
        self.numa_node = 0;
        self.memid = MemoryId::none();
        true
    }

    /// Binds this source prefix to the one bounded process-main identity.
    ///
    /// Only `ExclusiveTheapBootstrap` calls this while its heap is still
    /// inactive and address-stable; no heap-list or subprocess API follows
    /// from the stored pointer.
    #[inline]
    pub(crate) fn bind_main_subprocess(&mut self, subprocess: &'static MainSubprocess) {
        debug_assert!(self.subprocess.is_null());
        self.subprocess = subprocess.as_ptr();
    }

    #[inline]
    fn attach_theap_after_heap_publication(
        &mut self,
        theap: *mut Theap,
    ) -> Result<(), HeapTheapListError> {
        self.attach_theap_after_heap_publication_with_lock(theap, false)
    }

    /// Performs the same source heap-list publication using the normal
    /// blocking private-lock path.  Later-thread attachments to the shared
    /// process-static main heap use this variant: routine lock contention is
    /// not an invalid owner state merely because another thread is attaching
    /// or detaching its own Theap.
    #[inline]
    pub(crate) fn attach_theap_after_heap_publication_blocking(
        &mut self,
        theap: *mut Theap,
    ) -> Result<(), HeapTheapListError> {
        self.attach_theap_after_heap_publication_with_lock(theap, true)
    }

    fn attach_theap_after_heap_publication_with_lock(
        &mut self,
        theap: *mut Theap,
        blocking: bool,
    ) -> Result<(), HeapTheapListError> {
        // The bounded static or dynamic attachment owns an otherwise-
        // uncontended heap list. A busy result is therefore an invalid-owner
        // initialization boundary, not a reason to block while an unexplained
        // alias exists.
        let guard = if blocking {
            self.theaps_lock.lock().map_err(HeapTheapListError::Lock)?
        } else {
            self.theaps_lock
                .try_lock()
                .ok_or(HeapTheapListError::Busy)?
        };
        // SAFETY: the attachment owns `theap`, keeps it address-stable, and
        // invokes this only after its Release heap publication. The lock
        // serializes the source intrusive heap-list update.
        unsafe {
            let head = self.theaps;
            (*theap).hprev = null_mut();
            (*theap).hnext = head;
            if !head.is_null() {
                (*head).hprev = theap;
            }
            self.theaps = theap;
        }
        guard.unlock().map_err(HeapTheapListError::Lock)
    }

    #[inline]
    pub(crate) fn has_exact_theap_member(&self, theap: *mut Theap) -> bool {
        // SAFETY: the caller retains the typed Theap capability and uses this
        // only as a pre-mutation ownership witness; the pointer is not an
        // externally supplied raw alias.
        unsafe {
            self.theaps == theap
                && !theap.is_null()
                && (*theap).hprev.is_null()
                && (*theap).hnext.is_null()
                && core::ptr::eq((*theap).heap.load(Ordering::Acquire), core::ptr::from_ref(self).cast_mut())
        }
    }

    /// Validates one member of a potentially multi-Theap shared main heap.
    ///
    /// Unlike [`Self::has_exact_theap_member`], this accepts either a head or
    /// an interior entry.  The caller retains the typed Theap allocation and
    /// holds the process-level projection guard; this method additionally
    /// takes the source heap-list lock so concurrent normal attachment or
    /// detachment cannot make the local link witness transient.
    #[inline]
    pub(crate) fn has_shared_theap_member_blocking(
        &self,
        theap: *mut Theap,
    ) -> Result<bool, HeapTheapListError> {
        if theap.is_null() {
            return Ok(false);
        }
        let guard = self.theaps_lock.lock().map_err(HeapTheapListError::Lock)?;
        // SAFETY: the caller owns the typed Theap allocation and this lock
        // serializes the source hnext/hprev relations for this Heap.  The
        // adjacent links, if non-null, were inserted through the same list.
        let is_member = unsafe {
            if !core::ptr::eq(
                (*theap).heap.load(Ordering::Acquire),
                core::ptr::from_ref(self).cast_mut(),
            ) {
                false
            } else if (*theap).hprev.is_null() {
                self.theaps == theap
            } else {
                (*(*theap).hprev).hnext == theap
                    && ((*theap).hnext.is_null() || (*(*theap).hnext).hprev == theap)
            }
        };
        guard.unlock().map_err(HeapTheapListError::Lock)?;
        Ok(is_member)
    }

    #[inline]
    fn detach_one_theap_under_tld_lock(
        &mut self,
        theap: *mut Theap,
    ) -> Result<(), HeapTheapListError> {
        self.detach_one_theap_under_tld_lock_with_lock(theap, false)
    }

    /// Removes one shared-main-heap list member while its source TLD list
    /// lock is already held.  Unlike the bounded one-Theap owners, ordinary
    /// contention on the process heap is resolved by waiting on the private
    /// lock, matching `_mi_tld_detach_theaps` rather than terminally poisoning
    /// an otherwise valid later-thread owner.
    #[inline]
    pub(crate) fn detach_one_theap_under_tld_lock_blocking(
        &mut self,
        theap: *mut Theap,
    ) -> Result<(), HeapTheapListError> {
        self.detach_one_theap_under_tld_lock_with_lock(theap, true)
    }

    fn detach_one_theap_under_tld_lock_with_lock(
        &mut self,
        theap: *mut Theap,
        blocking: bool,
    ) -> Result<(), HeapTheapListError> {
        // The attachment owner has already cleared its owned TLS publication
        // in source teardown order. A busy/private-lock or membership failure
        // is therefore an invalid-owner terminal state: do not retry, steal
        // the lock, or imply that its retained storage was retired.
        let guard = if blocking {
            self.theaps_lock.lock().map_err(HeapTheapListError::Lock)?
        } else {
            self.theaps_lock.try_lock().ok_or(HeapTheapListError::Busy)?
        };
        // SAFETY: the caller holds the associated TLD list lock and owns the
        // one exact bounded theap. The heap lock completes the source two-list
        // detachment discipline before this method clears the Release heap
        // publication.
        unsafe {
            if (*theap).hprev.is_null() && self.theaps != theap {
                let _ = guard.unlock();
                return Err(HeapTheapListError::Membership);
            }
            if !(*theap).hnext.is_null() {
                (*(*theap).hnext).hprev = (*theap).hprev;
            }
            if !(*theap).hprev.is_null() {
                (*(*theap).hprev).hnext = (*theap).hnext;
            } else {
                self.theaps = (*theap).hnext;
            }
            (*theap).hnext = null_mut();
            (*theap).hprev = null_mut();
            (*theap).heap.store(null_mut(), Ordering::Release);
        }
        guard.unlock().map_err(HeapTheapListError::Lock)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_main_static_fields(&self) -> HeapMainStaticFields {
        HeapMainStaticFields {
            heap_seq: self.heap_seq,
            theap_slot: self.theap_slot,
            numa_node: self.numa_node,
            has_exclusive_arena: !self.exclusive_arena.is_null(),
            theaps_empty: self.theaps.is_null(),
            memid: self.memid,
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_theap_head_is(&self, theap: *mut Theap) -> bool {
        self.theaps == theap
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_inject_busy_theaps_lock(&self) {
        self.theaps_lock.test_inject_busy();
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_inject_busy_arena_pages_lock(&self) {
        self.arena_pages_lock.test_inject_busy();
    }

    #[inline]
    pub(crate) fn is_bound_to_main_subprocess(&self, subprocess: &MainSubprocess) -> bool {
        core::ptr::eq(self.subprocess, subprocess.as_ptr())
    }

    /// Identifies the source process-static main Heap image. This is narrower
    /// than a generic heap identity: only this Heap may pair an arena's
    /// in-place `pages_main` abandoned bitmap with `abandoned_count[bin]`.
    #[inline]
    pub(crate) fn is_main_static(&self) -> bool {
        self.theap_slot == 1
            && self.memid.kind() == MemoryKind::Static
            && !self.subprocess.is_null()
    }
}

/// A failure while manipulating the private source heap-theap list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapTheapListError {
    Busy,
    Membership,
    Lock(crabc_core::Errno),
}

/// One failure manipulating the source-private `heap->arena_pages` table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapArenaPagesError {
    ArenaIndex,
    NotMainStatic,
    Busy,
    Occupied,
    Mismatch,
    Lock(crabc_core::Errno),
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct HeapMainStaticFields {
    pub(crate) heap_seq: usize,
    pub(crate) theap_slot: usize,
    pub(crate) numa_node: i32,
    pub(crate) has_exclusive_arena: bool,
    pub(crate) theaps_empty: bool,
    pub(crate) memid: MemoryId,
}

/// Source-ordered `mi_tld_t` fields.
///
/// The field order and meanings match pinned `include/mimalloc/types.h`, but
/// this is not a byte-for-byte C ABI claim: [`PrivateLock`] is the allocator's
/// audited Linux futex boundary, not the upstream pthread-mutex object. The
/// detached bootstrap and bounded current-thread metadata owner initialize its
/// generic states. `main_theap.rs` consumes the first static owner for one
/// static Theap/list/compiler-TLS attachment; `dynamic_theap.rs` consumes a
/// later metadata owner for one regular-slot attachment. None is a complete
/// public `mi_tld_create`/thread lifecycle.
#[repr(C)]
pub(crate) struct ThreadLocalData {
    thread_id: ThreadId,
    thread_seq: usize,
    numa_node: i32,
    subprocess: *mut MainSubprocess,
    theaps: *mut Theap,
    theaps_lock: PrivateLock,
    recurse: bool,
    is_in_threadpool: bool,
    memid: MemoryId,
}

impl ThreadLocalData {
    #[inline]
    pub(crate) const fn detached() -> Self {
        Self {
            thread_id: THREAD_ID_DETACHED,
            thread_seq: 0,
            numa_node: 0,
            subprocess: null_mut(),
            theaps: null_mut(),
            theaps_lock: PrivateLock::new(),
            recurse: false,
            is_in_threadpool: false,
            memid: MemoryId::static_empty(),
        }
    }

    #[inline]
    pub(crate) const fn thread_id(&self) -> ThreadId {
        self.thread_id
    }

    /// Returns the source sequence previously issued by the process owner.
    #[inline]
    pub(crate) const fn thread_sequence(&self) -> ThreadSequence {
        ThreadSequence(self.thread_seq)
    }

    /// Returns the NUMA node selected by the pinned Unix primitive.
    #[inline]
    pub(crate) const fn numa_node(&self) -> i32 {
        self.numa_node
    }

    /// Returns whether this bounded TLD names a subprocess but no theap list.
    ///
    /// This is the precise checkpoint after `mi_tld_init`: its source
    /// subprocess pointer and live-count lease exist, but theap allocation,
    /// list attachment, and compiler-TLS publication are deliberately absent.
    #[inline]
    pub(crate) const fn is_subprocess_attached_no_theap(&self) -> bool {
        !self.subprocess.is_null() && self.theaps.is_null()
    }

    #[inline]
    pub(crate) fn is_attached_to_main_subprocess(&self, subprocess: &MainSubprocess) -> bool {
        core::ptr::eq(self.subprocess, subprocess.as_ptr())
    }

    /// Returns whether a deferred callback is currently recursing.
    #[inline]
    pub(crate) const fn recursing(&self) -> bool {
        self.recurse
    }

    /// Returns the pinned Unix thread-pool observation.
    #[inline]
    pub(crate) const fn is_in_threadpool(&self) -> bool {
        self.is_in_threadpool
    }

    /// Returns the metadata provenance of this exact TLD allocation.
    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.memid
    }

    /// Test-only witness that `mi_tld_init`'s private theap-list lock starts
    /// unlocked in the complete metadata image.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_theaps_lock_is_unlocked(&self) -> bool {
        self.theaps_lock.try_lock().is_some()
    }

    /// Injects a private theap-list lock violation without retaining a guard
    /// or TLD reference across `ThreadLocalDataOwner::teardown`.
    ///
    /// Normal lifecycle tests must never use this: a valid owner reaches
    /// teardown with no guards or waiters.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_inject_busy_theaps_lock(&self) {
        self.theaps_lock.test_inject_busy();
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_theap_head_is(&self, theap: *mut Theap) -> bool {
        self.theaps == theap
    }

    #[inline]
    pub(crate) fn has_exact_theap_member(&self, theap: *mut Theap) -> bool {
        // SAFETY: this is the same private typed pointer check used by the
        // list-detach path before it mutates either intrusive list.
        unsafe {
            self.theaps == theap
                && !theap.is_null()
                && (*theap).tprev.is_null()
                && (*theap).tnext.is_null()
                && core::ptr::eq((*theap).tld, core::ptr::from_ref(self).cast_mut())
        }
    }

    /// Records a live identity on caller-pinned/static bootstrap storage.
    ///
    /// This is the allocation-free bootstrap-only identity update used by
    /// [`crate::bootstrap::ExclusiveTheapBootstrap`]. It neither initializes
    /// a dynamic metadata TLD nor attaches it to a subprocess or theap list;
    /// `ThreadLocalDataOwner` owns that distinct future lifecycle boundary.
    #[inline]
    pub(crate) fn attach_bootstrap_exclusive(&mut self, thread_id: LiveThreadId) {
        self.thread_id = thread_id.get();
    }

    /// Initializes the source detached metadata-TLD portion after the bounded
    /// main subprocess identity exists.
    ///
    /// This is `mi_tld_init`'s detached branch: it names the same main
    /// subprocess as the process heap and metadata theap, retains sequence
    /// zero, and stores the source detached NUMA sentinel. It is not a live
    /// thread registration and therefore does not affect either counter.
    #[inline]
    pub(crate) fn attach_detached_main_subprocess(&mut self, subprocess: &'static MainSubprocess) {
        debug_assert_eq!(self.thread_id, THREAD_ID_DETACHED);
        self.thread_seq = 0;
        self.numa_node = -1;
        self.subprocess = subprocess.as_ptr();
        self.theaps = null_mut();
        self.theaps_lock = PrivateLock::new();
        self.recurse = false;
        self.is_in_threadpool = false;
        self.memid = MemoryId::static_empty();
    }

    /// Initializes the complete subprocess-attached/no-theap result of the
    /// bounded `mi_tld_create` adaptation.
    ///
    /// # Safety
    ///
    /// `self` must name the unique fresh-zeroed, properly aligned valid image
    /// for one `ThreadLocalData` metadata request. No concurrent observer may
    /// exist there. `memid` must describe that exact allocation. The caller
    /// must keep the allocation live until the source-ordered invalidation and
    /// metadata release transition completes.
    pub(crate) unsafe fn initialize_subprocess_attached_no_theap(
        &mut self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node: i32,
        subprocess: &'static MainSubprocess,
        memid: MemoryId,
    ) {
        // SAFETY: forwarded unchanged; `self` is the caller's exclusive
        // valid image and receives a complete source-ordered replacement.
        unsafe {
            Self::write_subprocess_attached_no_theap_at(
                core::ptr::from_mut(self),
                thread_id,
                thread_sequence,
                numa_node,
                subprocess,
                memid,
            );
        }
    }

    /// Writes one complete subprocess-attached/no-theap TLD image into raw
    /// storage without first forming a reference to that storage.
    ///
    /// The process-static main-TLD branch begins as `MaybeUninit`, unlike the
    /// metadata branch's known valid all-zero representation. Keeping this
    /// raw initialization boundary avoids manufacturing `&mut ThreadLocalData`
    /// before every field has been initialized.
    ///
    /// # Safety
    ///
    /// `destination` must be aligned writable storage for exactly one TLD and
    /// exclusively available. If it already contains a TLD value, its owner
    /// must permit replacement without running `Drop` (the represented TLD is
    /// intentionally non-dropping). No observer may access the destination
    /// until this complete image has been published by its owner.
    #[inline]
    pub(crate) unsafe fn write_subprocess_attached_no_theap_at(
        destination: *mut Self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node: i32,
        subprocess: &'static MainSubprocess,
        memid: MemoryId,
    ) {
        // SAFETY: the caller proves exclusive aligned storage and no observer
        // can reach it before the complete image is installed.
        unsafe {
            destination.write(Self {
                thread_id: thread_id.get(),
                thread_seq: thread_sequence.get(),
                numa_node,
                subprocess: subprocess.as_ptr(),
                theaps: null_mut(),
                theaps_lock: PrivateLock::new(),
                recurse: false,
                // `src/prim/unix/prim.c` returns false exactly.
                is_in_threadpool: false,
                memid,
            });
        }
    }

    /// Checks the complete bounded TLD invariant before its owner exposes it.
    #[inline]
    pub(crate) fn matches_subprocess_attached_no_theap_lifecycle(
        &self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        subprocess: &MainSubprocess,
    ) -> bool {
        self.matches_subprocess_attached_lifecycle(thread_id, thread_sequence, subprocess)
            && self.theaps.is_null()
    }

    /// Checks the initialized TLD prefix shared by no-theap construction and
    /// a later private dynamic-Theap attachment.
    ///
    /// The list itself is intentionally excluded: `ThreadLocalDataOwner`
    /// uses the stricter no-theap predicate above, while the dynamic owner
    /// separately proves its one exact intrusive-list member before teardown.
    /// This does not broaden the generic no-theap projection contract.
    #[inline]
    pub(crate) fn matches_subprocess_attached_lifecycle(
        &self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        subprocess: &MainSubprocess,
    ) -> bool {
        self.thread_id == thread_id.get()
            && self.thread_seq == thread_sequence.get()
            && !self.subprocess.is_null()
            && self.is_attached_to_main_subprocess(subprocess)
            && !self.recurse
            // This is the pinned Unix primitive result, not a guessed policy.
            && !self.is_in_threadpool
    }

    /// Executes the `mi_tld_free` identity invalidation after its owner has
    /// released the corresponding subprocess live-count lease.
    ///
    /// The source next destroys the TLD lock. The project-private futex lock
    /// has no destructor, so its owner proves quiescence separately before a
    /// metadata image is released or the static image is retired.
    #[inline]
    pub(crate) fn invalidate_subprocess_attached_no_theap_for_teardown(&mut self) {
        debug_assert!(self.is_subprocess_attached_no_theap());
        self.thread_id = usize::MAX;
    }

    /// Establishes the private-lock quiescence required before source-static
    /// retirement or metadata release.
    ///
    /// Every owning TLD/static/dynamic attachment is `!Send`. The ordinary path
    /// has no published Theap list; both attachment paths reach this point only
    /// after detaching their exact list member. All require no concurrent raw
    /// references, guards, or waiters. A busy lock therefore records a violated
    /// owner contract rather than waiting during teardown and pretending to
    /// provide pthread destruction.
    #[inline]
    pub(crate) fn quiesce_theap_list_lock_for_teardown(
        &self,
    ) -> Result<(), ThreadLocalDataQuiesceError> {
        let guard = self
            .theaps_lock
            .try_lock()
            .ok_or(ThreadLocalDataQuiesceError::Busy)?;
        guard.unlock().map_err(ThreadLocalDataQuiesceError::Lock)
    }

    /// Pushes one fully prepared theap on the source current-TLD list.
    ///
    /// `Theap::initialize_main_static` and
    /// `Theap::initialize_dynamic_metadata` own the complete bounded
    /// `_mi_theap_init` sequences. They call this after installing the
    /// TLD/subprocess fields but before random/cookie generation and Release
    /// heap publication. If there is an existing head, this returns the local
    /// random-image snapshot made *while the list lock is held*, exactly as
    /// the C `head_random` local does.
    #[inline]
    fn attach_one_theap(
        &mut self,
        theap: *mut Theap,
    ) -> Result<Option<TheapRandomImage>, ThreadLocalTheapListError> {
        // Both bounded attachment paths require exclusive control of this TLD
        // list. A busy lock is invalid-owner initialization state rather than
        // a waitable source condition; the static path retains its process
        // storage, while the dynamic path returns its concrete terminal owner.
        let guard = self
            .theaps_lock
            .try_lock()
            .ok_or(ThreadLocalTheapListError::Busy)?;
        let head = self.theaps;
        // SAFETY: the caller retains the only mutable authority for an
        // address-stable theap. The lock serializes this source intrusive
        // list update with later heap/TLD lifecycle work.
        let head_random = unsafe {
            (*theap).tprev = null_mut();
            (*theap).tnext = head;
            let head_random = if !head.is_null() {
                (*head).tprev = theap;
                Some((*head).random.snapshot_for_split())
            } else {
                None
            };
            self.theaps = theap;
            head_random
        };
        guard.unlock().map_err(ThreadLocalTheapListError::Lock)?;
        Ok(head_random)
    }

    /// Performs the source `_mi_tld_detach_theaps` heap-list half for the
    /// one exact bounded theap. The outer TLD lock is held first; the owned
    /// Heap must be immediately try-lockable or the owner becomes terminally
    /// poisoned rather than waiting while a violated alias exists. The caller
    /// has already cleared its owned TLS publication in source order, so a
    /// later lock/list error is explicitly not retryable or a completed
    /// teardown claim.
    #[inline]
    pub(crate) fn detach_one_theap_from_heap(
        &mut self,
        heap: &mut Heap,
        theap: *mut Theap,
    ) -> Result<(), ThreadLocalTheapListError> {
        let self_pointer = core::ptr::from_mut(self);
        let guard = self
            .theaps_lock
            .lock()
            .map_err(ThreadLocalTheapListError::Lock)?;
        // SAFETY: the attachment owner has verified the exact current TLD
        // identity. This check precedes the heap mutation so a corrupt or
        // aliased list never receives a partial detach transition.
        let valid_member = unsafe {
            self.theaps == theap
                && (*theap).tprev.is_null()
                && core::ptr::eq((*theap).tld, self_pointer)
        };
        if !valid_member {
            let _ = guard.unlock();
            return Err(ThreadLocalTheapListError::Membership);
        }
        heap.detach_one_theap_under_tld_lock(theap)
            .map_err(ThreadLocalTheapListError::Heap)?;
        guard.unlock().map_err(ThreadLocalTheapListError::Lock)
    }

    /// Performs the same heap-list half for a later thread attached to the
    /// shared process-static main Heap.
    ///
    /// The TLD still has exactly one owner, but the Heap can contain other
    /// live threads' Theaps.  Its private list lock therefore waits for
    /// ordinary contention instead of treating a concurrent valid detach as
    /// a terminal aliasing violation.  The caller's process heap lease keeps
    /// the static image live while this operation runs.
    #[inline]
    pub(crate) fn detach_one_theap_from_shared_main_heap(
        &mut self,
        heap: &mut Heap,
        theap: *mut Theap,
    ) -> Result<(), ThreadLocalTheapListError> {
        let self_pointer = core::ptr::from_mut(self);
        let guard = self
            .theaps_lock
            .lock()
            .map_err(ThreadLocalTheapListError::Lock)?;
        let valid_member = unsafe {
            self.theaps == theap
                && (*theap).tprev.is_null()
                && core::ptr::eq((*theap).tld, self_pointer)
        };
        if !valid_member {
            let _ = guard.unlock();
            return Err(ThreadLocalTheapListError::Membership);
        }
        heap.detach_one_theap_under_tld_lock_blocking(theap)
            .map_err(ThreadLocalTheapListError::Heap)?;
        guard.unlock().map_err(ThreadLocalTheapListError::Lock)
    }

    /// Clears the source TLD-list links after the heap-list pass has
    /// Release-cleared `theap->heap`.
    #[inline]
    pub(crate) fn detach_one_theap_from_tld(
        &mut self,
        theap: *mut Theap,
    ) -> Result<(), ThreadLocalTheapListError> {
        let self_pointer = core::ptr::from_mut(self);
        let guard = self
            .theaps_lock
            .lock()
            .map_err(ThreadLocalTheapListError::Lock)?;
        // SAFETY: the source heap-list pass has detached the exact bounded
        // theap and cleared its initialized predicate. This second
        // TLD-locked pass mirrors `mi_thread_theaps_done` before TLD release.
        let valid_member = unsafe {
            self.theaps == theap
                && (*theap).tprev.is_null()
                && (*theap).heap.load(Ordering::Acquire).is_null()
                && core::ptr::eq((*theap).tld, self_pointer)
        };
        if !valid_member {
            let _ = guard.unlock();
            return Err(ThreadLocalTheapListError::Membership);
        }
        unsafe {
            self.theaps = (*theap).tnext;
            if !(*theap).tnext.is_null() {
                (*(*theap).tnext).tprev = null_mut();
            }
            (*theap).tnext = null_mut();
            (*theap).tprev = null_mut();
            (*theap).tld = null_mut();
        }
        guard.unlock().map_err(ThreadLocalTheapListError::Lock)
    }

    /// Invalidates a fully detached live TLD after its registration is
    /// released and before its static or metadata storage is terminally
    /// retired.
    #[inline]
    pub(crate) fn invalidate_attached_theap_for_teardown(&mut self) {
        debug_assert!(self.theaps.is_null());
        self.thread_id = usize::MAX;
    }

    #[inline]
    fn matches_owner(&self, owner: TheapOwner) -> bool {
        self.thread_id == owner.thread_id()
    }
}

/// A failure while manipulating one source `mi_tld_t::theaps` list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadLocalTheapListError {
    Busy,
    Membership,
    Heap(HeapTheapListError),
    Lock(crabc_core::Errno),
}

/// A private TLD lock was not quiescent at its explicit lifecycle boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadLocalDataQuiesceError {
    Busy,
    Lock(crabc_core::Errno),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryKind {
    None,
    External,
    Static,
    Os,
    OsHuge,
    OsRemap,
    Arena,
    Malloc,
}

impl MemoryKind {
    #[inline]
    pub(crate) const fn is_os(self) -> bool {
        matches!(self, Self::Os | Self::OsHuge | Self::OsRemap)
    }

    #[inline]
    pub(crate) const fn needs_no_free(self) -> bool {
        matches!(self, Self::None | Self::External | Self::Static)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OsMemory {
    pub(crate) base: *mut u8,
    pub(crate) size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ArenaMemory {
    pub(crate) arena: *mut Arena,
    pub(crate) slice_index: u32,
    pub(crate) slice_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MallocMemory {
    pub(crate) base: *mut u8,
    pub(crate) size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union MemoryInfo {
    pub(crate) os: OsMemory,
    pub(crate) arena: ArenaMemory,
    pub(crate) malloc: MallocMemory,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MemoryId {
    pub(crate) info: MemoryInfo,
    pub(crate) kind: MemoryKind,
    pub(crate) is_pinned: bool,
    pub(crate) initially_committed: bool,
    pub(crate) initially_zero: bool,
}

impl MemoryId {
    #[inline]
    const fn empty_with_kind(kind: MemoryKind) -> Self {
        Self {
            info: MemoryInfo {
                os: OsMemory {
                    base: null_mut(),
                    size: 0,
                },
            },
            kind,
            is_pinned: false,
            initially_committed: false,
            initially_zero: false,
        }
    }

    #[inline]
    pub(crate) const fn none() -> Self {
        Self::empty_with_kind(MemoryKind::None)
    }

    /// Relinquishes ownership while preserving the source memory attributes.
    ///
    /// `mi_manage_os_memory_ex2` changes only `memkind` after publishing the
    /// parent arena. Sub-arenas must therefore retain the original committed,
    /// pinned, and zero-state observations even though they do not own the
    /// external allocation.
    #[inline]
    pub(crate) fn relinquish_ownership(&mut self) {
        self.kind = MemoryKind::None;
    }

    #[inline]
    pub(crate) const fn external(
        base: *mut u8,
        size: usize,
        initially_committed: bool,
        is_pinned: bool,
        initially_zero: bool,
    ) -> Self {
        Self {
            info: MemoryInfo {
                // `_mi_memid_create_static` deliberately records concrete
                // static-image extent through the source `mem.malloc` union
                // member, even though its memory kind is `MI_MEM_STATIC`.
                malloc: MallocMemory { base, size },
            },
            kind: MemoryKind::External,
            is_pinned,
            initially_committed,
            initially_zero,
        }
    }

    #[inline]
    /// Constructs arena provenance after checking the source's slice bounds.
    ///
    /// # Safety
    ///
    /// `arena` must point to a live initialized arena for the duration of this
    /// check and every later operation that projects the stored pointer.
    pub(crate) unsafe fn from_arena(
        arena: *mut Arena,
        slice_index: usize,
        slice_count: usize,
    ) -> Option<Self> {
        if arena.is_null()
            || slice_count == 0
            || slice_index >= u32::MAX as usize
            || slice_count >= u32::MAX as usize
        {
            return None;
        }
        if slice_index >= unsafe { (*arena).slice_count } {
            return None;
        }
        Some(Self {
            info: MemoryInfo {
                arena: ArenaMemory {
                    arena,
                    slice_index: slice_index as u32,
                    slice_count: slice_count as u32,
                },
            },
            kind: MemoryKind::Arena,
            is_pinned: false,
            initially_committed: false,
            initially_zero: false,
        })
    }

    /// Records `MI_MEM_STATIC` provenance for one concrete static image.
    ///
    /// `internal.h:_mi_memid_create_static` preserves the image's actual base
    /// and size while marking it pinned and committed. This is distinct from
    /// [`Self::static_empty`], which remains the source's reusable null/zero
    /// static initializer for unrelated empty images.
    #[inline]
    pub(crate) const fn static_allocation(base: *mut u8, size: usize) -> Self {
        Self {
            info: MemoryInfo {
                // `_mi_memid_create_static` records its provenance in the
                // `mem.malloc` union arm even though `MI_MEM_STATIC` is
                // pinned/committed and `_mi_memid_size` deliberately reports
                // zero for it.
                malloc: MallocMemory { base, size },
            },
            kind: MemoryKind::Static,
            is_pinned: true,
            initially_committed: true,
            initially_zero: false,
        }
    }

    /// Creates exactly `_mi_memid_create(MI_MEM_STATIC)`: a zero union and
    /// zero flags with only the source memory kind set.
    ///
    /// `mi_heap_main_init_once` uses this kind-only provenance for the static
    /// process heap. It deliberately does not claim concrete image extent,
    /// pinning, or initial commitment; `_mi_memid_create_static` is separate.
    #[inline]
    pub(crate) const fn static_kind_only() -> Self {
        Self::empty_with_kind(MemoryKind::Static)
    }

    /// The static null/zero-extent source image used by unrelated empty images.
    ///
    /// This intentionally remains the kind-only null/zero image; concrete
    /// static allocations such as `mi_process_tld_main` must use
    /// [`Self::static_allocation`].
    #[inline]
    pub(crate) const fn static_empty() -> Self {
        Self::static_kind_only()
    }

    #[inline]
    pub(crate) const fn kind(&self) -> MemoryKind {
        self.kind
    }

    #[inline]
    pub(crate) const fn is_os(&self) -> bool {
        self.kind.is_os()
    }

    #[inline]
    pub(crate) const fn needs_no_free(&self) -> bool {
        self.kind.needs_no_free()
    }

    #[inline]
    pub(crate) const fn is_pinned(&self) -> bool {
        self.is_pinned
    }

    #[inline]
    pub(crate) const fn initially_committed(&self) -> bool {
        self.initially_committed
    }

    #[inline]
    pub(crate) const fn initially_zero(&self) -> bool {
        self.initially_zero
    }

    #[inline]
    pub(crate) fn os_memory(&self) -> Option<OsMemory> {
        if matches!(
            self.kind,
            MemoryKind::External
                | MemoryKind::Os
                | MemoryKind::OsHuge
                | MemoryKind::OsRemap
        ) {
            Some(unsafe { self.info.os })
        } else {
            None
        }
    }

    /// Returns the `mem.malloc` base/size union arm for `MI_MEM_STATIC`.
    ///
    /// A kind-only `_mi_memid_create(MI_MEM_STATIC)` image returns its zero
    /// union, while `_mi_memid_create_static` records concrete image extent.
    #[inline]
    pub(crate) fn static_memory(&self) -> Option<MallocMemory> {
        if self.kind == MemoryKind::Static {
            // SAFETY: a zero `os` union arm has the same all-zero bit pattern
            // as `MallocMemory { null, 0 }`; concrete static allocation uses
            // the malloc arm directly.
            Some(unsafe { self.info.malloc })
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn arena_memory(&self) -> Option<ArenaMemory> {
        if self.kind == MemoryKind::Arena {
            Some(unsafe { self.info.arena })
        } else {
            None
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct Encoded(pub(crate) usize);

#[repr(C)]
pub(crate) struct Block {
    next: Encoded,
}

/// Narrow mutable projection for the exclusive local free-list algorithms.
///
/// It deliberately omits ownership, queue links, thread-free state, and heap
/// pointers. `free_list.rs` may update only the fields that the source local
/// free-list routines own; queue and direct-cache transitions stay with the
/// default-theap lifecycle.
pub(super) struct PageFreeListState<'a> {
    pub(super) area: NonNull<u8>,
    pub(super) area_bytes: usize,
    pub(super) block_size: usize,
    pub(super) capacity: &'a mut u16,
    pub(super) reserved: u16,
    pub(super) free: &'a mut *mut Block,
    pub(super) local_free: &'a mut *mut Block,
    pub(super) used: &'a mut usize,
    pub(super) free_is_zero: &'a mut bool,
}

/// Narrow producer projection for the source remote-free protocol.
///
/// The pointers name precisely the two atomic source fields a remote producer
/// may inspect. No `Page` reference is retained or manufactured: a producer
/// has no permission to read `theap`, `local_free`, `used`, or any other
/// non-atomic field. The associated-page [`crate::remote_free::push`] path
/// preserves the low owner bit, while the abandoned-page
/// [`crate::remote_free::push_abandoned`] path may claim it. In either case,
/// the surrounding caller retains the stable live page lifetime; only the
/// abandoned path may use its acquired bit to enter owner-only collection.
pub(super) struct PageRemoteFreeProducerState {
    pub(super) xthread_id: NonNull<AtomicUsize>,
    pub(super) xthread_free: NonNull<AtomicUsize>,
}

/// Narrow owner-only projection for remote-list collection.
///
/// The owner may touch `free`, `local_free`, `used`, and `free_is_zero` only
/// while it holds the source low owner bit. Ordinary collection obtains that
/// state through an AcqRel CAS that detaches the remote head; the abandoned
/// small-page partial path instead keeps its just-published head atomic while
/// the claimed owner moves only its predecessor list. These are raw field
/// pointers rather than a `&mut Page`, so producers can retain disjoint
/// atomic-field pointers without creating a concurrent whole-page alias. The
/// caller supplies the lifetime, non-abandonment, and no-release proof for
/// every pointer.
#[derive(Clone, Copy)]
pub(super) struct PageRemoteFreeOwnerState {
    pub(super) xthread_free: NonNull<AtomicUsize>,
    pub(super) free: NonNull<*mut Block>,
    pub(super) local_free: NonNull<*mut Block>,
    pub(super) used: NonNull<usize>,
    pub(super) free_is_zero: NonNull<bool>,
    pub(super) capacity: u16,
}

/// Narrow owner-only projection for the local half of `_mi_page_free_collect`.
///
/// Unlike [`PageFreeListState`], this carries raw field pointers and never
/// creates a whole-page mutable reference. The bounded full-page collector is
/// nevertheless a caller-proved joined/quiescent lifecycle: later queue
/// transitions still use existing queue helpers that borrow page metadata.
/// The test-only scoped producer models that proof but is not a production
/// lifetime capability. The caller remains responsible for the live-page,
/// owner-associated, non-abandoning, and no-release proof; this state grants
/// no queue or lifetime transition.
pub(super) struct PageLocalCollectState {
    pub(super) area: NonNull<u8>,
    pub(super) area_bytes: usize,
    pub(super) block_size: usize,
    pub(super) capacity: u16,
    pub(super) reserved: u16,
    pub(super) free: NonNull<*mut Block>,
    pub(super) local_free: NonNull<*mut Block>,
    pub(super) used: NonNull<usize>,
    pub(super) free_is_zero: NonNull<bool>,
}

/// Raw field projection for the bounded abandoned-page state machine.
///
/// This is deliberately not a `&mut Page`: an abandoned-page producer may
/// retain only the disjoint atomic `xthread_free` field while the owner moves
/// the page between associated, mapped-abandoned, and unowned states. The
/// abandonment module must validate the source state encoded in these fields
/// before it mutates any ordinary member.
pub(super) struct PageAbandonmentState {
    pub(super) xthread_id: NonNull<AtomicUsize>,
    pub(super) xthread_free: NonNull<AtomicUsize>,
    pub(super) theap: NonNull<*mut Theap>,
    pub(super) used: NonNull<usize>,
    pub(super) reserved: u16,
    pub(super) block_size: usize,
    pub(super) memid: MemoryId,
}

/// Atomic-only abandoned-page projection available before low-bit ownership.
///
/// A bitmap reader may use this to perform `mi_page_claim_ownership`, but it
/// has no permission to inspect page identity, arena provenance, or any other
/// ordinary page member until that AcqRel claim succeeds.
pub(super) struct PageAbandonmentAtomicState {
    pub(super) xthread_free: NonNull<AtomicUsize>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageKind {
    Small,
    Medium,
    Large,
    Singleton,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PageQueue {
    first: *mut Page,
    last: *mut Page,
    count: usize,
    block_size: usize,
}

impl PageQueue {
    pub(crate) const fn empty(block_size: usize) -> Self {
        Self {
            first: null_mut(),
            last: null_mut(),
            count: 0,
            block_size,
        }
    }

    #[inline]
    pub(crate) const fn block_size(&self) -> usize {
        self.block_size
    }

    #[inline]
    pub(crate) const fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.first.is_null() && self.last.is_null() && self.count == 0
    }

    #[inline]
    pub(crate) const fn first(&self) -> *mut Page {
        self.first
    }

    #[inline]
    pub(crate) const fn last(&self) -> *mut Page {
        self.last
    }
}

// `src/init.c:MI_PAGE_QUEUES_EMPTY`; all source values are machine-word
// counts, so multiplying by `WORD_SIZE` is the direct language adaptation.
pub(crate) const BIN_BLOCK_SIZES: [usize; BIN_COUNT] = [
    1 * WORD_SIZE,
    1 * WORD_SIZE, 2 * WORD_SIZE, 3 * WORD_SIZE, 4 * WORD_SIZE,
    5 * WORD_SIZE, 6 * WORD_SIZE, 7 * WORD_SIZE, 8 * WORD_SIZE,
    10 * WORD_SIZE, 12 * WORD_SIZE, 14 * WORD_SIZE, 16 * WORD_SIZE,
    20 * WORD_SIZE, 24 * WORD_SIZE, 28 * WORD_SIZE, 32 * WORD_SIZE,
    40 * WORD_SIZE, 48 * WORD_SIZE, 56 * WORD_SIZE, 64 * WORD_SIZE,
    80 * WORD_SIZE, 96 * WORD_SIZE, 112 * WORD_SIZE, 128 * WORD_SIZE,
    160 * WORD_SIZE, 192 * WORD_SIZE, 224 * WORD_SIZE, 256 * WORD_SIZE,
    320 * WORD_SIZE, 384 * WORD_SIZE, 448 * WORD_SIZE, 512 * WORD_SIZE,
    640 * WORD_SIZE, 768 * WORD_SIZE, 896 * WORD_SIZE, 1024 * WORD_SIZE,
    1280 * WORD_SIZE, 1536 * WORD_SIZE, 1792 * WORD_SIZE, 2048 * WORD_SIZE,
    2560 * WORD_SIZE, 3072 * WORD_SIZE, 3584 * WORD_SIZE, 4096 * WORD_SIZE,
    5120 * WORD_SIZE, 6144 * WORD_SIZE, 7168 * WORD_SIZE, 8192 * WORD_SIZE,
    10_240 * WORD_SIZE, 12_288 * WORD_SIZE, 14_336 * WORD_SIZE, 16_384 * WORD_SIZE,
    20_480 * WORD_SIZE, 24_576 * WORD_SIZE, 28_672 * WORD_SIZE, 32_768 * WORD_SIZE,
    40_960 * WORD_SIZE, 49_152 * WORD_SIZE, 57_344 * WORD_SIZE, 65_536 * WORD_SIZE,
    81_920 * WORD_SIZE, 98_304 * WORD_SIZE, 114_688 * WORD_SIZE, 131_072 * WORD_SIZE,
    163_840 * WORD_SIZE, 196_608 * WORD_SIZE, 229_376 * WORD_SIZE, 262_144 * WORD_SIZE,
    327_680 * WORD_SIZE, 393_216 * WORD_SIZE, 458_752 * WORD_SIZE, 524_288 * WORD_SIZE,
    (LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE,
    (LARGE_MAX_OBJ_WSIZE + 2) * WORD_SIZE,
];

const fn empty_page_queues() -> [PageQueue; BIN_COUNT] {
    let mut queues = [PageQueue::empty(0); BIN_COUNT];
    let mut index = 0;
    while index < BIN_COUNT {
        queues[index] = PageQueue::empty(BIN_BLOCK_SIZES[index]);
        index += 1;
    }
    queues
}

pub(crate) const EMPTY_PAGE_QUEUES: [PageQueue; BIN_COUNT] = empty_page_queues();

// `keys` is absent exactly as in the default C layout: both `MI_PADDING` and
// `MI_ENCODE_FREELIST` resolve to zero for this profile.
#[repr(C)]
pub(crate) struct Page {
    self_: AtomicPtr<Page>,
    xthread_id: AtomicUsize,
    free: *mut Block,
    used: usize,
    local_free: *mut Block,
    block_size: usize,
    page_offset: usize,
    capacity: u16,
    reserved: u16,
    slice_pcommitted: u16,
    retire_expire: u8,
    free_is_zero: bool,
    xthread_free: AtomicUsize,
    theap: *mut Theap,
    heap: *mut Heap,
    next: *mut Page,
    prev: *mut Page,
    memid: MemoryId,
}

/// Public-source custom commit/decommit hook retained by externally managed
/// arenas. The function pointer is nullable in [`Arena`].
pub(crate) type CommitFunction = unsafe extern "C" fn(
    commit: bool,
    start: *mut u8,
    size: usize,
    is_zero: *mut bool,
    user_argument: *mut c_void,
) -> bool;

/// C-shaped `mi_arena_pages_t` header. Its variable-size ordinary bitmaps live
/// in caller-owned storage immediately after this fixed pointer table.
#[repr(C)]
pub(crate) struct ArenaPages {
    pub(crate) pages: *mut u8,
    pub(crate) pages_abandoned: [*mut u8; crate::config::ARENA_BIN_COUNT],
}

/// The fixed `mi_arena_t` metadata image for the frozen default profile.
///
/// Bitmap pointers name atomically accessed caller-owned images in the arena's
/// reserved prefix. All non-atomic fields are initialized before registry
/// publication and remain immutable in the current substrate, except for the
/// source-defined partial-split adjustment of a parent `total_size`.
#[repr(C)]
pub(crate) struct Arena {
    pub(crate) memid: MemoryId,
    pub(crate) subprocess: *mut Subprocess,
    pub(crate) arena_index: usize,
    pub(crate) start: *mut u8,
    pub(crate) slice_count: usize,
    pub(crate) info_slices: usize,
    pub(crate) numa_node: i32,
    pub(crate) is_exclusive: bool,
    pub(crate) purge_expire: AtomicI64,
    pub(crate) commit_function: Option<CommitFunction>,
    pub(crate) commit_function_argument: *mut c_void,
    pub(crate) total_size: usize,
    pub(crate) parent: *mut Arena,
    pub(crate) slices_free: *mut u8,
    pub(crate) slices_committed: *mut u8,
    pub(crate) slices_dirty: *mut u8,
    pub(crate) slices_purge: *mut u8,
    pub(crate) pages_meta: *mut Page,
    pub(crate) pages_main: ArenaPages,
}

// SAFETY: registry publication gives shared access only after every ordinary
// field and bitmap pointer is initialized. Concurrent bitmap state is atomic;
// later lifecycle slices must preserve this publication/quiescence contract.
unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

impl Page {
    const fn empty() -> Self {
        Self {
            self_: AtomicPtr::new(null_mut()),
            xthread_id: AtomicUsize::new(THREAD_ID_ABANDONED),
            free: null_mut(),
            used: 0,
            local_free: null_mut(),
            block_size: 0,
            page_offset: 0,
            capacity: 0,
            reserved: 0,
            slice_pcommitted: 0,
            retire_expire: 0,
            free_is_zero: false,
            xthread_free: AtomicUsize::new(0),
            theap: null_mut(),
            heap: null_mut(),
            next: null_mut(),
            prev: null_mut(),
            memid: MemoryId::static_empty(),
        }
    }

    /// Creates the zero page image used only for secondary aligned-metadata
    /// lookup slots.
    ///
    /// Pinned `arena.c` zeroes the metadata prefix and initializes only the
    /// `self` atomic in these aliases. Every zero bit-pattern below is a valid
    /// Rust field value, including `MemoryKind::None`; spelling out the image
    /// avoids treating arbitrary bytes as an initialized `Page`.
    const fn empty_aligned_alias() -> Self {
        Self {
            self_: AtomicPtr::new(null_mut()),
            xthread_id: AtomicUsize::new(0),
            free: null_mut(),
            used: 0,
            local_free: null_mut(),
            block_size: 0,
            page_offset: 0,
            capacity: 0,
            reserved: 0,
            slice_pcommitted: 0,
            retire_expire: 0,
            free_is_zero: false,
            xthread_free: AtomicUsize::new(0),
            theap: null_mut(),
            heap: null_mut(),
            next: null_mut(),
            prev: null_mut(),
            memid: MemoryId::none(),
        }
    }

    /// Initializes one secondary `_mi_aligned_ptr_page0` metadata slot.
    ///
    /// The slot is a lookup alias, not an allocator page: every field remains
    /// at the source zero image except `self`, which publishes the primary
    /// page with Release ordering.
    ///
    /// # Safety
    ///
    /// `slot` must be aligned writable storage for one `Page` in the committed
    /// metadata prefix belonging to `owner`. It must not contain a live Rust
    /// value or be visible to a concurrent lookup until this call returns.
    /// `owner` must remain address-stable and live until this exact slot is
    /// cleared or its entire mapping is released after reader quiescence.
    pub(crate) unsafe fn publish_aligned_alias_at(
        slot: NonNull<Page>,
        owner: NonNull<Page>,
    ) {
        // SAFETY: the caller supplies uninitialized/exclusively reusable slot
        // storage; writing a complete valid image precedes all observation.
        unsafe { slot.as_ptr().write(Self::empty_aligned_alias()) };
        // SAFETY: the preceding write initialized the complete `Page` image
        // and the caller retains exclusive publication rights to its atomic.
        unsafe { &*core::ptr::addr_of!((*slot.as_ptr()).self_) }
            .store(owner.as_ptr(), core::sync::atomic::Ordering::Release);
    }

    /// Clears one secondary aligned-metadata alias before mapping release.
    ///
    /// A false result means the slot did not name `owner`; the caller must not
    /// unmap on that ownership mismatch.
    ///
    /// # Safety
    ///
    /// `slot` must name a live initialized alias slot created by
    /// [`Self::publish_aligned_alias_at`]. The caller must serialize this
    /// transition with other writers and establish lookup quiescence before
    /// releasing the containing mapping.
    pub(crate) unsafe fn clear_aligned_alias_at(
        slot: NonNull<Page>,
        owner: NonNull<Page>,
    ) -> bool {
        // SAFETY: the caller proves the alias slot is initialized and live.
        unsafe { &*core::ptr::addr_of!((*slot.as_ptr()).self_) }
            .compare_exchange(
                owner.as_ptr(),
                null_mut(),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    /// Reads the aligned metadata owner published in this slot.
    #[inline]
    pub(crate) fn aligned_alias_owner(&self) -> *mut Page {
        self.self_.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Associates a newly initialized page with the caller's exclusive
    /// default theap.
    ///
    /// This is the single-thread subset of
    /// `internal.h:mi_page_set_theap`: the page has no remote-free producer,
    /// so no flags need to survive a compare/exchange loop. `theap` and
    /// `heap` must remain address-stable while the page can be observed; the
    /// bootstrap owner enforces that by requiring pinning before it exposes
    /// either address. The page metadata itself must likewise remain live and
    /// exclusively mutable for the complete association.
    pub(crate) fn associate_exclusive(
        &mut self,
        theap: &mut Theap,
        heap: &mut Heap,
        thread_id: LiveThreadId,
    ) {
        self.associate_exclusive_owner(theap, heap, TheapOwner::Live(thread_id));
    }

    /// Associates a page with either a live-thread or detached exclusive
    /// theap. Detached ownership is valid only for the process metadata
    /// theap, whose callers serialize every operation with its private lock;
    /// it is never a remote-free or abandonment owner.
    pub(crate) fn associate_exclusive_owner(
        &mut self,
        theap: &mut Theap,
        heap: &mut Heap,
        owner: TheapOwner,
    ) {
        debug_assert!(theap.matches_owner(owner));
        self.theap = core::ptr::from_mut(theap);
        self.heap = core::ptr::from_mut(heap);
        self.xthread_id
            .store(owner.thread_id(), core::sync::atomic::Ordering::Release);
        // The source's owner bit permits access to the non-atomic page fields.
        // This exclusive slice has no remote-free transitions but begins with
        // the same owned empty-list state.
        self.xthread_free.store(1, core::sync::atomic::Ordering::Release);
    }

    /// Publishes a freshly acquired page into the exclusive local lifecycle.
    ///
    /// This is the source-defined partial initialization from
    /// `arena.c:mi_arenas_page_alloc_fresh` followed by the reset invariants
    /// checked in `page.c:_mi_page_init`; extending the local free list is a
    /// separate operation. The pointed theap and heap must be the stable
    /// fields of a pinned [`crate::bootstrap::ExclusiveTheapBootstrap`].
    /// `reserved` is the complete source-reserved block count and must be
    /// nonzero. `page_offset` identifies the already-provisioned live block
    /// area; this routine deliberately does not allocate, map, or validate it.
    pub(crate) fn publish_fresh_exclusive(
        &mut self,
        theap: &mut Theap,
        heap: &mut Heap,
        thread_id: LiveThreadId,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> bool {
        self.publish_fresh_exclusive_owner(
            theap,
            heap,
            TheapOwner::Live(thread_id),
            block_size,
            page_offset,
            reserved,
            slice_pcommitted,
            free_is_zero,
            memid,
        )
    }

    /// Owner-typed source fresh-page publication shared by the live default
    /// and detached metadata theaps. The caller's external synchronization
    /// is what makes either path exclusive; this routine itself introduces no
    /// remote-free capability.
    pub(crate) fn publish_fresh_exclusive_owner(
        &mut self,
        theap: &mut Theap,
        heap: &mut Heap,
        owner: TheapOwner,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> bool {
        if !Self::fresh_parameters_are_valid(block_size, page_offset, reserved) {
            return false;
        }

        self.free = null_mut();
        self.used = 0;
        self.local_free = null_mut();
        self.block_size = block_size;
        self.page_offset = page_offset;
        self.capacity = 0;
        self.reserved = reserved;
        self.slice_pcommitted = slice_pcommitted;
        self.retire_expire = 0;
        self.free_is_zero = free_is_zero;
        self.next = null_mut();
        self.prev = null_mut();
        self.memid = memid;
        self.associate_exclusive_owner(theap, heap, owner);
        // `MI_PAGE_META_IS_ALIGNED` is enabled in the frozen profile. As in
        // `arena.c`, publish the self map only after every ordinary page field
        // and exclusive owner record is ready.
        let self_pointer = core::ptr::from_mut(self);
        self.self_
            .store(self_pointer, core::sync::atomic::Ordering::Release);
        true
    }

    #[inline]
    const fn fresh_parameters_are_valid(block_size: usize, page_offset: usize, reserved: u16) -> bool {
        block_size != 0 && page_offset != 0 && reserved != 0
    }

    /// Initializes potentially nonzero raw metadata and publishes a fresh
    /// page into the exclusive local lifecycle.
    ///
    /// This is the only fresh-page entry point for newly committed arena
    /// metadata. It writes [`Self::empty`] before creating a Rust reference,
    /// matching `arena.c`'s explicit metadata zeroing rather than assuming the
    /// OS mapping happened to contain a valid `Page` value.
    ///
    /// # Safety
    ///
    /// `metadata` must be aligned writable storage for exactly one `Page` and
    /// must not currently hold a live Rust `Page`; no alias or page-map entry
    /// may observe it while this method initializes it. The storage, the
    /// supplied pinned theap/heap, and the complete page block area described
    /// by `page_offset` and `reserved * block_size` must remain live and
    /// exclusively owned through the local page lifecycle. All source page
    /// geometry/provenance inputs must describe that existing memory. This
    /// method maps no memory and does not validate a virtual-memory range.
    pub(crate) unsafe fn publish_fresh_exclusive_at(
        metadata: NonNull<Self>,
        theap: &mut Theap,
        heap: &mut Heap,
        thread_id: LiveThreadId,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> Option<NonNull<Self>> {
        unsafe {
            Self::publish_fresh_exclusive_owner_at(
                metadata,
                theap,
                heap,
                TheapOwner::Live(thread_id),
                block_size,
                page_offset,
                reserved,
                slice_pcommitted,
                free_is_zero,
                memid,
            )
        }
    }

    /// Raw owner-typed fresh-page publication for the detached metadata
    /// theap and ordinary live theaps. See
    /// [`Self::publish_fresh_exclusive_at`] for the storage obligations.
    pub(crate) unsafe fn publish_fresh_exclusive_owner_at(
        mut metadata: NonNull<Self>,
        theap: &mut Theap,
        heap: &mut Heap,
        owner: TheapOwner,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> Option<NonNull<Self>> {
        if !Self::fresh_parameters_are_valid(block_size, page_offset, reserved) {
            return None;
        }
        // SAFETY: the caller proves that this aligned writable metadata does
        // not contain a live `Page`, so initialization by raw write is valid.
        unsafe { metadata.as_ptr().write(Self::empty()) };
        // SAFETY: the preceding raw write initialized a valid Page value at
        // `metadata`; exclusive caller ownership permits this mutable borrow.
        let page = unsafe { metadata.as_mut() };
        // This publication mutates every fresh-page field and is therefore a
        // required release transition, not a debug-only invariant check.
        // Keeping its boolean result explicit also preserves the raw entry
        // point's checked failure boundary in every optimization profile.
        if !page.publish_fresh_exclusive_owner(
            theap,
            heap,
            owner,
            block_size,
            page_offset,
            reserved,
            slice_pcommitted,
            free_is_zero,
            memid,
        ) {
            return None;
        }
        Some(metadata)
    }

    /// Removes an exclusive-theap association before the page metadata is
    /// reused. No remote free may be in flight.
    pub(crate) fn disassociate_exclusive(&mut self) {
        self.theap = null_mut();
        self.xthread_id
            .store(THREAD_ID_ABANDONED, core::sync::atomic::Ordering::Release);
        self.xthread_free.store(0, core::sync::atomic::Ordering::Release);
    }

    /// Retires a fully free, queue-detached page before its mapping/provenance
    /// is released, returning the source memory ID needed for that release.
    ///
    /// The caller must already have removed the page from its queue and direct
    /// cache, decremented the owning theap page count, and established that no
    /// remote free or observer exists. The caller must use the returned
    /// provenance to unregister the raw page address before it releases the
    /// backing mapping. This is the exclusive single-thread subset of
    /// `page.c:_mi_page_free` plus the metadata reset performed by its arena
    /// release path; it is not abandonment or cross-thread reclamation.
    #[inline]
    pub(crate) fn retire_exclusive(&mut self) -> Option<MemoryId> {
        if self.used != 0 || !self.next.is_null() || !self.prev.is_null() {
            return None;
        }

        let memid = self.memid;
        self.self_
            .store(null_mut(), core::sync::atomic::Ordering::Release);
        self.xthread_id
            .store(THREAD_ID_ABANDONED, core::sync::atomic::Ordering::Release);
        self.xthread_free.store(0, core::sync::atomic::Ordering::Release);
        self.free = null_mut();
        self.local_free = null_mut();
        self.block_size = 0;
        self.page_offset = 0;
        self.capacity = 0;
        self.reserved = 0;
        self.slice_pcommitted = 0;
        self.retire_expire = 0;
        self.free_is_zero = false;
        self.theap = null_mut();
        self.heap = null_mut();
        self.next = null_mut();
        self.prev = null_mut();
        self.memid = MemoryId::none();
        Some(memid)
    }

    #[inline]
    pub(crate) const fn free_list_head(&self) -> *mut Block {
        self.free
    }

    /// Replaces the ordinary free-list head while this page is exclusively
    /// owned by its associated single-thread theap.
    ///
    /// `head` must be null or the first valid block of this page's unencoded
    /// free list. Encoded and remote free-list protocols remain out of scope.
    #[inline]
    pub(crate) fn set_exclusive_free_list_head(&mut self, head: *mut Block) {
        self.free = head;
    }

    #[inline]
    pub(crate) const fn used(&self) -> usize {
        self.used
    }

    /// Changes `used` only for the exclusive local lifecycle. The caller must
    /// preserve the source page equation relative to the free list and
    /// capacity; remote-free collection is not implemented in this slice.
    #[inline]
    pub(crate) fn set_exclusive_used(&mut self, used: usize) {
        self.used = used;
    }

    #[inline]
    pub(crate) const fn reserved(&self) -> u16 {
        self.reserved
    }

    #[inline]
    pub(crate) const fn capacity(&self) -> u16 {
        self.capacity
    }

    /// Returns the source count of committed OS pages for an on-demand page.
    /// Zero is the fully committed sentinel used by ordinary committed pages
    /// and OS-aligned singleton pages in the frozen profile.
    #[inline]
    pub(crate) const fn slice_pcommitted(&self) -> u16 {
        self.slice_pcommitted
    }

    /// Records the successfully committed on-demand prefix of this page.
    ///
    /// The caller must own this live associated page exclusively, have just
    /// completed the direct OS commit for every byte between the old and new
    /// prefix, and preserve the source page-area geometry. Zero remains the
    /// distinct fully-committed sentinel, so this rejects transitions from or
    /// back to zero and any decreasing count.
    #[inline]
    pub(crate) fn set_slice_pcommitted_after_commit(&mut self, next: u16) -> bool {
        if self.slice_pcommitted == 0 || next == 0 || next < self.slice_pcommitted {
            return false;
        }
        self.slice_pcommitted = next;
        true
    }

    /// Sets the local page capacity record before the page is published into
    /// an exclusive theap queue. `capacity` must not exceed `reserved`.
    #[inline]
    pub(crate) fn set_capacity_reserved(&mut self, capacity: u16, reserved: u16) -> bool {
        if capacity > reserved {
            return false;
        }
        self.capacity = capacity;
        self.reserved = reserved;
        true
    }

    #[inline]
    pub(crate) const fn block_size(&self) -> usize {
        self.block_size
    }

    /// Reads the source `MI_PAGE_HAS_INTERIOR_POINTERS` flag.
    ///
    /// A live aligned allocation may begin after its source free-list block;
    /// this page-wide flag tells free and usable-size lookup to recover the
    /// block base before applying ordinary block invariants. The flag shares
    /// the low bits of `xthread_id`, exactly as in
    /// `internal.h:mi_page_has_interior_pointers`.
    #[inline]
    pub(crate) fn has_interior_pointers(&self) -> bool {
        self.xthread_id.load(core::sync::atomic::Ordering::Relaxed)
            & PAGE_HAS_INTERIOR_POINTERS
            != 0
    }

    /// Applies `internal.h:mi_page_set_has_interior_pointers` without changing
    /// the page's owner identity or full-queue membership flag.
    #[inline]
    pub(crate) fn set_has_interior_pointers(&self, has_interior_pointers: bool) {
        if has_interior_pointers {
            self.xthread_id.fetch_or(
                PAGE_HAS_INTERIOR_POINTERS,
                core::sync::atomic::Ordering::Relaxed,
            );
        } else {
            self.xthread_id.fetch_and(
                !PAGE_HAS_INTERIOR_POINTERS,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    #[inline]
    pub(crate) fn set_block_size(&mut self, block_size: usize) {
        self.block_size = block_size;
    }

    /// Returns the source `mi_page_start` address.
    ///
    /// # Safety
    ///
    /// The metadata must describe a live page whose block area starts exactly
    /// `page_offset` bytes after this `Page`; the resulting pointer range must
    /// remain in the same allocated object. The return value carries no access
    /// permission by itself.
    #[inline]
    pub(crate) unsafe fn start(&self) -> *mut u8 {
        // SAFETY: the caller proves the source page-area layout and bounds.
        unsafe { (self as *const Self).cast_mut().cast::<u8>().add(self.page_offset) }
    }

    #[inline]
    pub(crate) const fn page_offset(&self) -> usize {
        self.page_offset
    }

    #[inline]
    pub(crate) const fn memid(&self) -> MemoryId {
        self.memid
    }

    #[inline]
    pub(crate) const fn retire_expire(&self) -> u8 {
        self.retire_expire
    }

    #[inline]
    pub(crate) const fn free_is_zero(&self) -> bool {
        self.free_is_zero
    }

    /// Sets the source retirement countdown while the caller exclusively owns
    /// this page and its queue membership.
    #[inline]
    pub(crate) fn set_retire_expire(&mut self, retire_expire: u8) {
        self.retire_expire = retire_expire;
    }

    /// Projects only the source atomic fields that a remote producer may use.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized metadata that remains live while a
    /// returned producer state can be used. The caller must prohibit page
    /// abandonment, detachment, retirement, reuse, and release, but remote
    /// producer code itself must not inspect any non-atomic page field.
    #[inline]
    pub(super) unsafe fn remote_free_producer_state_at(
        page: NonNull<Self>,
    ) -> PageRemoteFreeProducerState {
        let page = page.as_ptr();
        // SAFETY: the caller proves initialized stable page metadata. These
        // derive raw pointers to the exact atomic subobjects without creating
        // a `Page` reference or reading a non-atomic field.
        let xthread_id = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).xthread_id)) };
        let xthread_free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).xthread_free)) };
        PageRemoteFreeProducerState {
            xthread_id,
            xthread_free,
        }
    }

    /// Projects the source fields used by the owner after remote-list detach.
    ///
    /// # Safety
    ///
    /// `page` must name one live initialized page. The caller must be its
    /// sole owner for every non-atomic field and must keep it associated with
    /// a live theap, without abandonment, detachment, retirement, reuse, or
    /// release, until this owner operation completes. Other threads may hold
    /// only the disjoint atomic producer state from
    /// [`Self::remote_free_producer_state_at`]. In particular, the page's
    /// `xthread_free` low owner bit must currently be set; this method
    /// acquire-validates it before reading any owner-only ordinary field.
    #[inline]
    pub(super) unsafe fn remote_free_owner_state_at(
        page: NonNull<Self>,
    ) -> Option<PageRemoteFreeOwnerState> {
        let page = page.as_ptr();
        // SAFETY: the caller proves initialized stable metadata. This creates
        // a direct reference to the atomic subobject only, before inspecting
        // an owner-only ordinary field.
        let xthread_free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).xthread_free)) };
        // SAFETY: `xthread_free` names the initialized atomic field above.
        if unsafe { xthread_free.as_ref() }
            .load(core::sync::atomic::Ordering::Acquire)
            & 1
            == 0
        {
            return None;
        }
        // SAFETY: the caller proves the page is initialized and the owner has
        // exclusive permission for ordinary fields after the acquire owner-bit
        // validation above. This reads the owner-only `theap` field; producer
        // code never performs this access.
        if unsafe { (*page).theap }.is_null() {
            return None;
        }
        // SAFETY: as above, these are direct pointers to initialized page
        // fields; no whole-page reference is formed.
        let xthread_id = unsafe { &*core::ptr::addr_of!((*page).xthread_id) };
        let thread_id = xthread_id.load(core::sync::atomic::Ordering::Acquire) & !PAGE_FLAG_MASK;
        if thread_id == THREAD_ID_ABANDONED
            || thread_id == THREAD_ID_ABANDONED_MAPPED
            || thread_id == THREAD_ID_DETACHED
        {
            return None;
        }
        // SAFETY: the same initialized-page proof allows these owner-only
        // field pointers. They are not dereferenced until after list detach.
        let free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free)) };
        let local_free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).local_free)) };
        let used = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).used)) };
        let free_is_zero = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free_is_zero)) };
        Some(PageRemoteFreeOwnerState {
            xthread_free,
            free,
            local_free,
            used,
            free_is_zero,
            // SAFETY: capacity is immutable while the page is live in this
            // bounded slice and belongs to the exclusive owner contract.
            capacity: unsafe { (*page).capacity },
        })
    }

    /// Checks the exact live-owner identity needed before a scoped remote
    /// producer can retain this page's raw atomic projection.
    ///
    /// This reads only initialized atomic fields plus the source `theap`
    /// pointer and forms no whole-page reference. It is narrower than the
    /// collection projections: a caller uses it before publication to reject
    /// an invalid, detached, abandoned, or stale live owner without touching
    /// a page/list/block field.
    ///
    /// # Safety
    ///
    /// `page` must name live initialized page metadata for the duration of
    /// these atomic reads. The caller must prevent concurrent page retirement,
    /// reuse, registration, or unregistration.
    #[inline]
    pub(super) unsafe fn is_live_owner_for_thread_at(
        page: NonNull<Self>,
        expected_thread: LiveThreadId,
    ) -> bool {
        let page = page.as_ptr();
        // SAFETY: caller supplies stable initialized page metadata; this is
        // the source remote head's atomic owner bit.
        let xthread_free = unsafe { &*core::ptr::addr_of!((*page).xthread_free) };
        if xthread_free.load(Ordering::Acquire) & 1 == 0 {
            return false;
        }
        // SAFETY: the pointer is initialized with the page; null cannot name
        // a live associated owner.
        if unsafe { (*page).theap }.is_null() {
            return false;
        }
        // SAFETY: the source identity word is an initialized atomic field.
        let thread_id = unsafe { &*core::ptr::addr_of!((*page).xthread_id) }
            .load(Ordering::Acquire)
            & !PAGE_FLAG_MASK;
        thread_id == expected_thread.get()
    }

    /// Projects the raw owner fields used after remote detach by the
    /// false-force local half of `_mi_page_free_collect`.
    ///
    /// This is deliberately separate from [`Self::local_free_list_state`]: a
    /// `PageFreeListState` borrows the local fields through a `&mut Page`,
    /// while this narrow collection step does not manufacture a whole-page
    /// mutable reference. The surrounding full-page lifecycle still requires
    /// caller-proved joined/quiescent producers before its later queue
    /// transition helpers. The raw free-list boundary can select either the
    /// false-force transfer or the force-only local-list append; no projection
    /// itself grants a queue, abandonment, or owner-exit transition.
    ///
    /// # Safety
    ///
    /// `page` must be live initialized metadata for an owner matching
    /// `expected_thread`: `Some` requires that exact live thread identity,
    /// while `None` requires the explicit detached owner. The caller must
    /// exclusively own the ordinary fields below and keep the page plus its
    /// complete block area live until the collection completes; it must not
    /// detach, retire, reuse, or release the page. A live owner may have
    /// other threads retaining only [`Self::remote_free_producer_state_at`]
    /// and may not touch the ordinary fields. The detached branch instead
    /// has the bootstrap/session's externally serialized no-remote-producer
    /// contract. The caller must prove that `page_offset` and
    /// `reserved * block_size` describe the same live writable area as the
    /// page's local lists.
    #[inline]
    pub(super) unsafe fn local_collect_state_for_owner_at(
        page: NonNull<Self>,
        expected_thread: Option<LiveThreadId>,
    ) -> Option<PageLocalCollectState> {
        let page = page.as_ptr();
        // SAFETY: caller supplies initialized stable metadata; read only the
        // atomic owner word before any ordinary-field projection.
        let xthread_free = unsafe { &*core::ptr::addr_of!((*page).xthread_free) };
        if xthread_free.load(Ordering::Acquire) & 1 == 0 {
            return None;
        }
        // SAFETY: the caller supplies the owner proof for these ordinary
        // fields; producers retain only atomic field pointers.
        if unsafe { (*page).theap }.is_null() {
            return None;
        }
        // SAFETY: the xthread identity is an initialized atomic field.
        let thread_id = unsafe { &*core::ptr::addr_of!((*page).xthread_id) }
            .load(Ordering::Acquire)
            & !PAGE_FLAG_MASK;
        match expected_thread {
            Some(expected) if thread_id == expected.get() => {}
            None if thread_id == THREAD_ID_DETACHED => {}
            _ => return None,
        }

        // SAFETY: the stated caller proof permits these owner-only geometry
        // reads without manufacturing a `Page` reference.
        let block_size = unsafe { (*page).block_size };
        let reserved = unsafe { (*page).reserved };
        let capacity = unsafe { (*page).capacity };
        let used = unsafe { (*page).used };
        let page_offset = unsafe { (*page).page_offset };
        if block_size == 0
            || reserved == 0
            || capacity > reserved
            || used > capacity as usize
            || page_offset == 0
        {
            return None;
        }
        let area_bytes = usize::from(reserved).checked_mul(block_size)?;
        // SAFETY: the caller proves the exact described area is live; this is
        // raw address derivation only and does not create a whole-page borrow.
        let area = unsafe { NonNull::new_unchecked(page.cast::<u8>().add(page_offset)) };
        Some(PageLocalCollectState {
            area,
            area_bytes,
            block_size,
            capacity,
            reserved,
            // SAFETY: these are initialized owner-only subobjects; the
            // returned raw pointers are not dereferenced until the caller
            // performs its source-ordered local collection.
            free: unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free)) },
            local_free: unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).local_free))
            },
            used: unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).used)) },
            free_is_zero: unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free_is_zero))
            },
        })
    }

    /// Projects exactly the state needed by the abandoned-page protocol.
    ///
    /// # Safety
    ///
    /// `page` must name initialized metadata that remains live until the
    /// caller completes its source ownership transition. The caller must own
    /// the non-atomic fields represented here whenever it reads or writes
    /// them. Other threads may retain only the atomic remote-free projection;
    /// the caller must not release or reuse this metadata until no producer,
    /// map reader, or owning transition can observe it.
    #[inline]
    pub(super) unsafe fn abandonment_state_at(page: NonNull<Self>) -> PageAbandonmentState {
        let page = page.as_ptr();
        // SAFETY: caller supplies initialized stable metadata. These are only
        // raw subobject pointers and do not manufacture a whole-page borrow.
        let xthread_id = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).xthread_id)) };
        let xthread_free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).xthread_free)) };
        // SAFETY: caller's owner/lifetime proof permits projections of these
        // exact initialized ordinary fields without creating `&mut Page`.
        let theap = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).theap)) };
        let used = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).used)) };
        PageAbandonmentState {
            xthread_id,
            xthread_free,
            theap,
            used,
            reserved: unsafe { (*page).reserved },
            block_size: unsafe { (*page).block_size },
            memid: unsafe { (*page).memid },
        }
    }

    /// Projects only the atomic low-owner word required to claim an abandoned
    /// page from its bitmap candidate.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized metadata that remains live while
    /// the returned atomic field can be used. The projection grants no access
    /// to any ordinary page field; a caller must first acquire the low owner
    /// bit before it calls [`Self::abandonment_state_at`] and reads identity or
    /// provenance.
    #[inline]
    pub(super) unsafe fn abandonment_atomic_state_at(
        page: NonNull<Self>,
    ) -> PageAbandonmentAtomicState {
        let page = page.as_ptr();
        PageAbandonmentAtomicState {
            // SAFETY: caller proves stable initialized metadata; derive one
            // raw atomic subobject pointer without a whole-page borrow.
            xthread_free: unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).xthread_free))
            },
        }
    }

    /// Projects the owner collection fields only after an abandoned page has
    /// been claimed. Unlike [`Self::remote_free_owner_state_at`], this accepts
    /// the two source abandoned identities and deliberately does not inspect
    /// the stale `theap` pointer.
    ///
    /// # Safety
    ///
    /// `page` must be a live abandoned page whose `xthread_free` owner bit is
    /// held by this caller. The caller must retain the metadata and every
    /// remote block until collection completes, and must be the sole writer of
    /// `free`, `local_free`, `used`, and `free_is_zero`.
    #[inline]
    pub(super) unsafe fn abandoned_remote_free_owner_state_at(
        page: NonNull<Self>,
    ) -> Option<PageRemoteFreeOwnerState> {
        let page = page.as_ptr();
        let xthread_free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).xthread_free)) };
        if unsafe { xthread_free.as_ref() }
            .load(core::sync::atomic::Ordering::Acquire)
            & 1
            == 0
        {
            return None;
        }
        let xthread_id = unsafe { &*core::ptr::addr_of!((*page).xthread_id) };
        let thread_id = xthread_id.load(core::sync::atomic::Ordering::Acquire) & !PAGE_FLAG_MASK;
        if thread_id != THREAD_ID_ABANDONED && thread_id != THREAD_ID_ABANDONED_MAPPED {
            return None;
        }
        let free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free)) };
        let local_free = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).local_free)) };
        let used = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).used)) };
        let free_is_zero = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free_is_zero)) };
        Some(PageRemoteFreeOwnerState {
            xthread_free,
            free,
            local_free,
            used,
            free_is_zero,
            capacity: unsafe { (*page).capacity },
        })
    }

    /// Projects exactly the local free-list fields used by the single-thread
    /// source path.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own this live page and its entire block
    /// area: `page_offset` bytes from this metadata address must begin a
    /// writable allocation of exactly `reserved * block_size` bytes, with
    /// nonzero `block_size` and `reserved`. The multiplication and resulting
    /// pointer range must not overflow. The page must be associated with the
    /// caller's live exclusive theap, and no remote-free, page-map,
    /// queue-retirement, or other access may observe or mutate the projected
    /// fields for the lifetime of the returned projection. Each free-list
    /// pointer written through it must be null or an aligned block inside this
    /// area. These are the source `mi_page_t` local-list invariants; this
    /// bootstrap slice intentionally does not supply their concurrent form.
    #[inline]
    pub(super) unsafe fn local_free_list_state(&mut self) -> PageFreeListState<'_> {
        debug_assert!(self.block_size != 0);
        debug_assert!(self.reserved != 0);
        // SAFETY: the caller's live-area contract proves that advancing from
        // this page metadata address by `page_offset` remains in bounds and
        // produces the beginning of its writable block area.
        let area = unsafe { (self as *mut Self).cast::<u8>().add(self.page_offset) };
        // SAFETY: the live-area contract also proves the returned area pointer
        // is non-null and valid for the derived byte count.
        let area = unsafe { NonNull::new_unchecked(area) };
        // SAFETY: the same caller contract proves this source field product
        // does not overflow and identifies the complete page block area.
        let area_bytes = unsafe { usize::from(self.reserved).unchecked_mul(self.block_size) };

        PageFreeListState {
            area,
            area_bytes,
            block_size: self.block_size,
            capacity: &mut self.capacity,
            reserved: self.reserved,
            free: &mut self.free,
            local_free: &mut self.local_free,
            used: &mut self.used,
            free_is_zero: &mut self.free_is_zero,
        }
    }

    #[cfg(test)]
    pub(crate) fn remote_free_test_page(capacity: u16, used: usize) -> Self {
        assert!(used <= capacity as usize);
        let mut page = Self::empty();
        page.capacity = capacity;
        page.reserved = capacity;
        page.block_size = core::mem::size_of::<Block>();
        // This is an address sentinel used only by remote-free protocol unit
        // tests. It is never dereferenced: production association must use a
        // pinned live `Theap` through `associate_exclusive`.
        page.theap = NonNull::<Theap>::dangling().as_ptr();
        page.xthread_id.store(12, core::sync::atomic::Ordering::Relaxed);
        page.xthread_free.store(1, core::sync::atomic::Ordering::Release);
        page.used = used;
        page
    }

    #[cfg(test)]
    pub(crate) fn remote_free_test_unassociated() -> Self {
        Self::empty()
    }

    #[cfg(test)]
    pub(crate) fn remote_free_test_mark_abandoned(&mut self) {
        // `src/page.c:_mi_page_abandon` can retain the old theap pointer for
        // later reclaim, so this test changes only the atomic page identity.
        // A bounded owner-associated remote free must still reject it.
        self.xthread_id
            .store(THREAD_ID_ABANDONED, core::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) unsafe fn abandoned_test_set_arena_memory(
        &mut self,
        arena: *mut Arena,
        slice_index: usize,
        slice_count: usize,
    ) -> bool {
        let Some(memory) = (unsafe { MemoryId::from_arena(arena, slice_index, slice_count) }) else {
            return false;
        };
        self.memid = memory;
        true
    }

    #[cfg(test)]
    pub(crate) fn abandoned_test_thread_id(&self) -> ThreadId {
        self.xthread_id.load(core::sync::atomic::Ordering::Acquire) & !PAGE_FLAG_MASK
    }

    #[cfg(test)]
    pub(crate) fn abandoned_test_set_theap(&mut self, theap: *mut Theap) {
        self.theap = theap;
    }

    #[cfg(test)]
    pub(crate) fn remote_free_test_set_local_free(&mut self, local_free: *mut Block) {
        self.local_free = local_free;
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn remote_free_test_free(&self) -> *mut Block {
        self.free
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn remote_free_test_local_free(&self) -> *mut Block {
        self.local_free
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn remote_free_test_free_is_zero(&self) -> bool {
        self.free_is_zero
    }

    #[cfg(test)]
    pub(crate) fn remote_free_test_head(&self) -> ThreadFree {
        self.xthread_free.load(core::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) const fn remote_free_test_used(&self) -> usize {
        self.used
    }

    #[cfg(test)]
    pub(crate) fn remote_free_test_local_chain(&self) -> [*mut u8; 3] {
        // SAFETY: the remote-free test fixture writes these exact three
        // unencoded links before inspecting them under sole ownership.
        unsafe {
            let first = self.local_free.cast::<u8>();
            let second = core::ptr::read(first.cast::<*mut u8>());
            let third = core::ptr::read(second.cast::<*mut u8>());
            [first, second, third]
        }
    }

    #[cfg(test)]
    pub(crate) fn remote_free_test_local_chain_len(&self, maximum: usize) -> usize {
        let mut count = 0;
        let mut current = self.local_free.cast::<u8>();
        while !current.is_null() && count < maximum {
            count += 1;
            // SAFETY: callers use this only after a successful collection of
            // test-owned unencoded blocks, each of which initialized its link.
            current = unsafe { core::ptr::read(current.cast::<*mut u8>()) };
        }
        count
    }

    #[inline]
    pub(crate) const fn theap(&self) -> *mut Theap {
        self.theap
    }

    #[inline]
    pub(crate) const fn heap(&self) -> *mut Heap {
        self.heap
    }

    /// Returns the next raw queue link for exclusive retired-page traversal.
    ///
    /// Queue mutation remains confined to `page_queue`; callers may only
    /// follow this pointer while the owning single-thread session guarantees
    /// that the page stays queue-linked and live.
    #[inline]
    pub(crate) const fn next(&self) -> *mut Page {
        self.next
    }

    /// Returns the predecessor raw queue link for exclusive queue validation.
    ///
    /// Queue mutation remains confined to `page_queue`; callers may only
    /// inspect this pointer while the owning single-thread session guarantees
    /// that the page stays queue-linked and live.
    #[inline]
    pub(crate) const fn prev(&self) -> *mut Page {
        self.prev
    }

    /// Corrupts one intrusive predecessor link for an isolated queue-boundary
    /// regression. Production queue mutations remain confined to
    /// `page_queue`.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_set_queue_prev(&mut self, prev: *mut Page) {
        self.prev = prev;
    }

    /// Whether neither intrusive queue link names this page.
    ///
    /// Terminal release validates this before it clears map/arena metadata:
    /// the ordinary local path detaches immediately before release, while an
    /// abandoned-free path has already detached it before publishing its
    /// abandoned identity.
    #[inline]
    pub(crate) const fn is_queue_detached(&self) -> bool {
        self.next.is_null() && self.prev.is_null()
    }
}

// This is the immutable `src/init.c:mi_page_empty` prototype. `Page` contains
// raw pointers and is therefore not auto-`Sync`; the wrapper exposes only a
// shared reference and never permits mutation of this static prototype.
#[repr(transparent)]
pub(crate) struct BootstrapPage(Page);

// SAFETY: `BootstrapPage` only exposes `&Page`; its non-atomic fields are an
// immutable zero-state prototype and no safe API exposes mutable access.
unsafe impl Sync for BootstrapPage {}

impl BootstrapPage {
    #[inline]
    pub(crate) const fn as_ref(&self) -> &Page {
        &self.0
    }

    /// Returns the source-shaped direct-cache sentinel pointer.
    ///
    /// The pointed page is immutable bootstrap metadata. A direct-cache slot
    /// may compare against it, but it must never mutate it or enqueue it.
    #[inline]
    pub(crate) const fn as_ptr(&self) -> *mut Page {
        core::ptr::addr_of!(self.0).cast_mut()
    }
}

pub(crate) static EMPTY_PAGE: BootstrapPage = BootstrapPage(Page::empty());

// `src/init.c:mi_tld_detached`. It is immutable: the live default-theap
// bootstrap owns a separate TLD after pinning. Dynamic TLD fields contain raw
// pointers and therefore must not grant a blanket `Sync` implementation to
// `ThreadLocalData`; this wrapper grants it only to this never-mutated static
// source image. Keeping it separate is what lets the initial empty theap
// avoid any TLS access.
#[repr(transparent)]
struct DetachedThreadLocal(ThreadLocalData);

// SAFETY: no public API yields a reference or mutable pointer to the wrapped
// TLD. The empty static theap stores its address only as an immutable source
// sentinel; a live bootstrap replaces that pointer with its own pinned TLD
// before it can publish a mutable theap.
unsafe impl Sync for DetachedThreadLocal {}

static DETACHED_THREAD_LOCAL: DetachedThreadLocal = DetachedThreadLocal(ThreadLocalData::detached());

#[inline]
const fn detached_thread_local_ptr() -> *mut ThreadLocalData {
    core::ptr::addr_of!(DETACHED_THREAD_LOCAL.0).cast_mut()
}

/// Source-layout prefix of `mi_theap_t` through `memid`.
///
/// This prefix contains every field required by the default direct-page
/// cache, page queues, and exclusive local page accounting. `mi_stats_t`
/// follows `memid` in C but is not represented: statistics require their own
/// lifecycle and merge contract. Consequently this Rust type intentionally
/// has no complete-`mi_theap_t` size claim.
#[repr(C)]
pub(crate) struct Theap {
    // Keep first for `internal.h:_mi_theap_get_free_small_page`.
    pages_free_direct: [*mut Page; PAGES_DIRECT],
    tld: *mut ThreadLocalData,
    heap: AtomicPtr<Heap>,
    subproc: AtomicPtr<Subprocess>,
    refcount: AtomicUsize,
    heartbeat: u64,
    cookie: usize,
    random: TheapRandomImage,
    page_count: usize,
    page_retired_min: usize,
    page_retired_max: usize,
    pages_full_size: usize,
    generic_count: isize,
    generic_collect_count: isize,
    tnext: *mut Theap,
    tprev: *mut Theap,
    hnext: *mut Theap,
    hprev: *mut Theap,
    page_full_retain: isize,
    allow_page_reclaim: bool,
    allow_page_abandon: bool,
    is_detached: bool,
    pages: [PageQueue; BIN_COUNT],
    memid: MemoryId,
}

impl Theap {
    /// `src/init.c:_mi_theap_empty` through its `memid` prefix.
    ///
    /// No heap is published, so `is_initialized` remains false exactly as in
    /// `internal.h:mi_theap_is_initialized`. The direct table is deliberately
    /// populated with the immutable empty-page sentinel rather than null.
    pub(crate) const fn empty() -> Self {
        Self {
            pages_free_direct: [EMPTY_PAGE.as_ptr(); PAGES_DIRECT],
            tld: detached_thread_local_ptr(),
            heap: AtomicPtr::new(null_mut()),
            subproc: AtomicPtr::new(null_mut()),
            refcount: AtomicUsize::new(1),
            heartbeat: 0,
            cookie: 0,
            random: TheapRandomImage::empty_weak(),
            page_count: 0,
            page_retired_min: BIN_FULL,
            page_retired_max: 0,
            pages_full_size: 0,
            generic_count: 0,
            generic_collect_count: 0,
            tnext: null_mut(),
            tprev: null_mut(),
            hnext: null_mut(),
            hprev: null_mut(),
            page_full_retain: 0,
            allow_page_reclaim: false,
            allow_page_abandon: true,
            is_detached: true,
            pages: EMPTY_PAGE_QUEUES,
            memid: MemoryId::static_empty(),
        }
    }

    /// Installs the concrete static allocation provenance that source
    /// `_mi_thread_init_with_heap` records before `_mi_theap_init` copies the
    /// empty image. The following initializer saves and restores this value.
    #[inline]
    pub(crate) fn set_main_static_memid(&mut self, memid: MemoryId) -> bool {
        if self.is_initialized()
            || memid.kind() != MemoryKind::Static
            || !memid.is_pinned()
            || !memid.initially_committed()
        {
            return false;
        }
        self.memid = memid;
        true
    }

    /// Records the exact direct-zeroed metadata allocation provenance for a
    /// dynamic Theap image. This is deliberately separate from the concrete
    /// static-image setter: a caller-owned heap is not a claim about the
    /// dynamically allocated Theap's Malloc ownership.
    #[inline]
    pub(crate) fn set_dynamic_metadata_memid(&mut self, memid: MemoryId) -> bool {
        if self.is_initialized()
            || memid.kind() != MemoryKind::Malloc
            || !memid.is_pinned()
            || !memid.initially_committed()
        {
            return false;
        }
        self.memid = memid;
        true
    }

    /// Initializes the process-static first live theap with the exact
    /// `_mi_theap_init` publication ordering relevant to this bounded slice.
    ///
    /// The caller gives this final address-stable source static image its
    /// concrete `MI_MEM_STATIC` provenance before entering. The method saves
    /// that provenance, copies the immutable empty image, restores `memid`,
    /// links the TLD list, initializes RustCrypto-backed random/cookie state,
    /// and only then Release-publishes `heap` before linking the heap list.
    /// The absent stats/guarded/options framework is intentionally not
    /// fabricated: the frozen normal-release option values below are the
    /// exact live values reached by this source path. A busy fresh-list lock
    /// or a post-mutation unlock/heap-list error has no valid source recovery:
    /// the caller records terminal initialization-invalid-owner state with the
    /// static TLD/live registration retained and no returned teardown owner.
    #[inline]
    pub(crate) fn initialize_main_static(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
    ) -> Result<(), TheapMainStaticInitError> {
        if self.is_initialized()
            || !tld.is_subprocess_attached_no_theap()
            || !tld.matches_owner(TheapOwner::Live(
                LiveThreadId::new(tld.thread_id()).ok_or(TheapMainStaticInitError::InvalidInput)?,
            ))
            || heap.subprocess.is_null()
            || !core::ptr::eq(heap.subprocess, tld.subprocess)
        {
            return Err(TheapMainStaticInitError::InvalidInput);
        }

        // `_mi_theap_init` first preserves the concrete allocation provenance
        // supplied by `_mi_theap_alloc`, copies `_mi_theap_empty`, then puts
        // that provenance back. `replace` is the Rust ownership equivalent of
        // the aligned source copy; the old inert random image is zeroized by
        // its bounded Drop rather than silently retained in static storage.
        let memid = self.memid;
        let replaced = core::mem::replace(self, Self::empty());
        drop(replaced);
        self.memid = memid;
        self.tld = core::ptr::from_mut(tld);
        self.refcount.store(1, Ordering::Release);
        self.subproc.store(heap.subprocess, Ordering::Release);

        // `mi_theap_options_init` under the frozen default-release profile:
        // `page_reclaim_on_free >= 0`, `page_full_retain == 2`, and a live
        // TLD rather than the detached metadata identity.
        self.allow_page_reclaim = true;
        self.allow_page_abandon = true;
        self.page_full_retain = 2;
        self.is_detached = false;

        let self_pointer = core::ptr::from_mut(self);
        let head_random = tld
            .attach_one_theap(self_pointer)
            .map_err(TheapMainStaticInitError::ThreadList)?;
        if let Some(mut head_random) = head_random {
            head_random.split_into(&mut self.random);
        } else {
            self.random.initialize();
        }
        self.cookie = self.random.next() as usize | 1;

        // This Release write is the exact initialized predicate. It must stay
        // after list/random/cookie setup and before the heap-list operation.
        self.heap.store(core::ptr::from_mut(heap), Ordering::Release);
        heap.attach_theap_after_heap_publication(self_pointer)
            .map_err(TheapMainStaticInitError::HeapList)
    }

    /// Initializes one direct-zeroed metadata Theap for a caller-pinned heap.
    ///
    /// This preserves the `_mi_theap_init` sequence independently of the
    /// process-static branch: concrete Malloc `memid`, empty image, TLD,
    /// Release refcount/subprocess, normal option image, locked TLD list,
    /// random/cookie, Release heap publication, then locked heap list. A
    /// fallible private-list boundary has no rollback in this bounded owner;
    /// its caller retains every live capability in a terminal attachment.
    ///
    /// # Safety
    ///
    /// `heap` and `tld` must remain live, uniquely owned, and address-stable
    /// until this Theap has been detached from both intrusive lists and its
    /// Release heap publication is cleared. No other thread may mutate either
    /// list or their private locks. This method stores both raw pointers as
    /// part of the source Theap image, so ordinary `&mut` argument lifetimes
    /// alone do not encode the full list-residency obligation.
    #[inline]
    pub(crate) unsafe fn initialize_dynamic_metadata(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
        page_mode: DynamicTheapPageMode,
    ) -> Result<(), TheapDynamicInitError> {
        if self.is_initialized()
            || self.memid.kind() != MemoryKind::Malloc
            || !tld.is_subprocess_attached_no_theap()
            || !tld.matches_owner(TheapOwner::Live(
                LiveThreadId::new(tld.thread_id()).ok_or(TheapDynamicInitError::InvalidInput)?,
            ))
            || heap.subprocess.is_null()
            || !core::ptr::eq(heap.subprocess, tld.subprocess)
        {
            return Err(TheapDynamicInitError::InvalidInput);
        }

        let memid = self.memid;
        let replaced = core::mem::replace(self, Self::empty());
        drop(replaced);
        self.memid = memid;
        self.tld = core::ptr::from_mut(tld);
        self.refcount.store(1, Ordering::Release);
        self.subproc.store(heap.subprocess, Ordering::Release);
        self.allow_page_reclaim = true;
        // This source option image must be selected before the Release heap
        // publication. Ordinary dynamic attachment keeps the normal abandon
        // setting; the only alternate private mode is a non-abandoning page
        // session whose bounded collector can drain every admitted route.
        self.allow_page_abandon = page_mode.allows_page_abandon();
        self.page_full_retain = page_mode.page_full_retain();
        self.is_detached = false;

        let self_pointer = core::ptr::from_mut(self);
        let head_random = tld
            .attach_one_theap(self_pointer)
            .map_err(TheapDynamicInitError::ThreadList)?;
        if let Some(mut head_random) = head_random {
            head_random.split_into(&mut self.random);
        } else {
            self.random.initialize();
        }
        self.cookie = self.random.next() as usize | 1;
        self.heap.store(core::ptr::from_mut(heap), Ordering::Release);
        heap.attach_theap_after_heap_publication(self_pointer)
            .map_err(TheapDynamicInitError::HeapList)
    }

    /// Initializes one metadata Theap for a later thread using the shared
    /// process-static main Heap.
    ///
    /// This is the normal `src/init.c:_mi_thread_init_with_heap` later-ticket
    /// branch, not the caller-pinned first-class-heap substitute above.  Its
    /// typed metadata image and current-thread TLD remain exclusive to the
    /// caller, while the supplied main Heap is projected only under a
    /// [`crate::main_theap::MainStaticHeapLease`] guard.  The final
    /// heap-list operation waits for normal source lock contention; all
    /// source publication ordering before that point is identical to
    /// [`Self::initialize_dynamic_metadata`].
    ///
    /// # Safety
    ///
    /// `heap` must be the initialized process-static main Heap selected by
    /// the same `MainSubprocess` as `tld`, and the caller must hold the
    /// lease's temporary projection guard for this entire call.  `tld` and
    /// this exact direct-zeroed metadata allocation must remain live and
    /// address-stable until both intrusive lists are detached.  No raw alias
    /// may mutate this Theap outside its current-thread lifecycle owner.
    #[inline]
    pub(crate) unsafe fn initialize_shared_main_metadata(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
    ) -> Result<(), TheapDynamicInitError> {
        if self.is_initialized()
            || self.memid.kind() != MemoryKind::Malloc
            || !tld.is_subprocess_attached_no_theap()
            || !tld.matches_owner(TheapOwner::Live(
                LiveThreadId::new(tld.thread_id()).ok_or(TheapDynamicInitError::InvalidInput)?,
            ))
            || heap.subprocess.is_null()
            || !core::ptr::eq(heap.subprocess, tld.subprocess)
            // A later `_mi_thread_init_with_heap(mi_heap_main())` uses the
            // process main Heap's fixed fast key, not a regular dynamic slot.
            || heap.theap_slot != 1
            || heap.memid.kind() != MemoryKind::Static
        {
            return Err(TheapDynamicInitError::InvalidInput);
        }

        let memid = self.memid;
        let replaced = core::mem::replace(self, Self::empty());
        drop(replaced);
        self.memid = memid;
        self.tld = core::ptr::from_mut(tld);
        self.refcount.store(1, Ordering::Release);
        self.subproc.store(heap.subprocess, Ordering::Release);
        // This is the ordinary source option image.  A shared-main later
        // thread cannot select the private non-abandoning page-session mode.
        self.allow_page_reclaim = true;
        self.allow_page_abandon = true;
        self.page_full_retain = 2;
        self.is_detached = false;

        let self_pointer = core::ptr::from_mut(self);
        let head_random = tld
            .attach_one_theap(self_pointer)
            .map_err(TheapDynamicInitError::ThreadList)?;
        if let Some(mut head_random) = head_random {
            head_random.split_into(&mut self.random);
        } else {
            self.random.initialize();
        }
        self.cookie = self.random.next() as usize | 1;
        // The initialized predicate remains the Release heap pointer store;
        // only the heap-list lock behavior differs from the private binding.
        self.heap.store(core::ptr::from_mut(heap), Ordering::Release);
        heap.attach_theap_after_heap_publication_blocking(self_pointer)
            .map_err(TheapDynamicInitError::HeapList)
    }

    /// Clears the remaining terminal static-theap state after both intrusive
    /// lists are detached. Static provenance suppresses source metadata free,
    /// but Rust's manual static-storage lifecycle must still clear the random
    /// image because no `Drop` runs when the static slot is retired.
    #[inline]
    pub(crate) fn clear_main_static_after_detach(&mut self) -> bool {
        if !self.heap.load(Ordering::Acquire).is_null()
            || !self.tld.is_null()
            || !self.tnext.is_null()
            || !self.tprev.is_null()
            || !self.hnext.is_null()
            || !self.hprev.is_null()
        {
            return false;
        }
        self.random.clear();
        self.cookie = 0;
        self.subproc.store(null_mut(), Ordering::Release);
        true
    }

    /// Clears the final live dynamic-Theap image before its exact retained
    /// Malloc capability is released. The regular slot and owner-only cached
    /// reference were already cleared/released, and both list links must be
    /// detached before the refcount reaches its final zero.
    #[inline]
    pub(crate) fn clear_dynamic_metadata_after_detach(&mut self) -> bool {
        if !self.heap.load(Ordering::Acquire).is_null()
            || !self.tld.is_null()
            || !self.tnext.is_null()
            || !self.tprev.is_null()
            || !self.hnext.is_null()
            || !self.hprev.is_null()
            || self.refcount.load(Ordering::Acquire) != 1
        {
            return false;
        }
        self.random.clear();
        self.cookie = 0;
        self.subproc.store(null_mut(), Ordering::Release);
        self.refcount
            .fetch_sub(1, Ordering::AcqRel)
            == 1
    }

    /// Acquires the one cached-root reference for a live dynamic attachment.
    ///
    /// This is deliberately not a general Theap refcount API. The sole
    /// `DynamicTheapAttachment` caller has just source-ordered the compiler
    /// TLS cached-root store from the canonical empty Theap to this exact
    /// Malloc-backed image, and retains exclusive current-thread/lifecycle
    /// ownership until it reverses that store. The exact 1 -> 2 CAS turns a
    /// violated owner/refcount invariant into a retained terminal state rather
    /// than silently composing with an unknown reference.
    #[inline]
    pub(crate) fn acquire_dynamic_cached_reference(&self) -> bool {
        self.memid.kind() == MemoryKind::Malloc
            && self.is_initialized()
            && self
                .refcount
                .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    /// Releases the one cached-root reference of a dynamic attachment after
    /// its source-ordered cached-root reset to the canonical static empty
    /// image. This exact 2 -> 1 transition is the inverse of
    /// [`Self::acquire_dynamic_cached_reference`]; any other count is an
    /// invalid-owner state and must retain the allocated image terminally.
    #[inline]
    pub(crate) fn release_dynamic_cached_reference(&self) -> bool {
        self.memid.kind() == MemoryKind::Malloc
            && self.is_initialized()
            && self
                .refcount
                .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    /// Binds the empty source image to the one pinned default heap/TLD pair.
    ///
    /// The caller must first attach `tld` to a valid [`LiveThreadId`] and must
    /// ensure both input addresses remain stable for every associated page.
    /// `ExclusiveTheapBootstrap` is the only owner in this slice and
    /// makes that condition explicit with `Pin`. Publishing `heap` last is
    /// source order from `src/theap.c:_mi_theap_init`: it is the initialized
    /// predicate and must not become non-null before the preceding fields are
    /// ready.
    pub(crate) fn bind_exclusive_single_thread(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
    ) -> bool {
        let Some(thread_id) = LiveThreadId::new(tld.thread_id()) else {
            return false;
        };
        self.bind_exclusive_owner(heap, tld, TheapOwner::Live(thread_id))
    }

    /// Binds the empty source image to one process-lived detached metadata
    /// theap. It deliberately accepts only the source detached TLD identity;
    /// callers serialize every mutation with the metadata private lock and
    /// must never route remote frees or abandonment through this theap.
    pub(crate) fn bind_exclusive_detached(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
    ) -> bool {
        self.bind_exclusive_owner(heap, tld, TheapOwner::Detached)
    }

    fn bind_exclusive_owner(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
        owner: TheapOwner,
    ) -> bool {
        if !tld.matches_owner(owner) {
            return false;
        }
        if self.is_initialized() {
            return false;
        }

        self.tld = core::ptr::from_mut(tld);
        self.refcount.store(1, core::sync::atomic::Ordering::Release);
        self.subproc
            .store(heap.subprocess, core::sync::atomic::Ordering::Release);
        self.is_detached = owner.is_detached();
        // `theap.c:mi_theap_options_init` snapshots the default
        // `mi_option_page_full_retain == 2` into each initialized theap. This
        // bounded lifecycle freezes that normal-release value rather than
        // introducing mutable option state.
        self.page_full_retain = 2;
        // The normal source default permits abandonment. This detached
        // bootstrap is separately source-special-cased as non-abandoning with
        // retain two; it supports only the bounded owner-local collector,
        // never a remote producer, abandonment/adoption, or a live dynamic
        // attachment session.
        self.allow_page_abandon = false;
        debug_assert!(self.matches_owner(owner));
        self.heap.store(
            core::ptr::from_mut(heap),
            core::sync::atomic::Ordering::Release,
        );
        true
    }

    #[inline]
    pub(crate) fn is_initialized(&self) -> bool {
        !self.heap.load(core::sync::atomic::Ordering::Relaxed).is_null()
    }

    #[inline]
    pub(crate) fn matches_thread(&self, thread_id: LiveThreadId) -> bool {
        self.matches_owner(TheapOwner::Live(thread_id))
    }

    #[inline]
    fn matches_owner(&self, owner: TheapOwner) -> bool {
        // The only constructors use `DETACHED_THREAD_LOCAL` or a pinned
        // exclusive bootstrap field, both live for this reference.
        let tld = unsafe { self.tld.as_ref() };
        matches!(tld, Some(tld) if tld.matches_owner(owner))
    }

    #[inline]
    pub(crate) const fn is_detached(&self) -> bool {
        self.is_detached
    }

    #[inline]
    pub(crate) fn refcount(&self) -> usize {
        self.refcount.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn heap(&self) -> *mut Heap {
        self.heap.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_main_static_fields(&self) -> TheapMainStaticFields {
        TheapMainStaticFields {
            initialized: self.is_initialized(),
            refcount: self.refcount(),
            cookie_is_odd: self.cookie & 1 == 1,
            random_initialized: self.random.is_initialized(),
            random_weak: self.random.is_weak(),
            page_full_retain: self.page_full_retain,
            allows_page_reclaim: self.allow_page_reclaim,
            allows_page_abandon: self.allow_page_abandon,
            detached: self.is_detached,
            memid: self.memid,
        }
    }

    #[inline]
    pub(crate) fn is_bound_to_main_subprocess(&self, subprocess: &MainSubprocess) -> bool {
        core::ptr::eq(
            self.subproc.load(core::sync::atomic::Ordering::Acquire),
            subprocess.as_ptr(),
        )
    }

    #[inline]
    pub(crate) const fn page_count(&self) -> usize {
        self.page_count
    }

    #[inline]
    pub(crate) const fn page_full_retain(&self) -> isize {
        self.page_full_retain
    }

    /// Reports the frozen source `page_reclaim_on_free >= 0` option image.
    /// A mapped abandoned free may reassociate only with a live Theap that
    /// retained this permission during initialization.
    #[inline]
    pub(crate) const fn allows_page_reclaim(&self) -> bool {
        self.allow_page_reclaim
    }

    #[inline]
    pub(crate) const fn allows_page_abandon(&self) -> bool {
        self.allow_page_abandon
    }

    #[inline]
    pub(crate) const fn retired_bounds(&self) -> (usize, usize) {
        (self.page_retired_min, self.page_retired_max)
    }

    /// Includes one source regular-bin retirement in the bounded collection
    /// range. Full and huge queues are never retired through this mechanism.
    #[inline]
    pub(crate) fn note_retired_bin(&mut self, bin: usize) -> bool {
        if bin >= BIN_FULL {
            return false;
        }
        if bin < self.page_retired_min {
            self.page_retired_min = bin;
        }
        if bin > self.page_retired_max {
            self.page_retired_max = bin;
        }
        true
    }

    /// Restores the empty `src/init.c:_mi_theap_empty` retirement range after
    /// a collection pass has found no remaining retired regular-bin page.
    #[inline]
    pub(crate) fn reset_retired_bounds(&mut self) {
        self.page_retired_min = BIN_FULL;
        self.page_retired_max = 0;
    }

    #[inline]
    pub(crate) fn queue(&self, bin: usize) -> Option<&PageQueue> {
        self.pages.get(bin)
    }

    /// Grants the single-thread lifecycle code mutable access to one exact
    /// source queue. It must maintain `page_count` through
    /// [`Self::note_page_added`] and [`Self::note_page_removed`] alongside the
    /// intrusive `page_queue` transitions.
    #[inline]
    pub(crate) fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        self.pages.get_mut(bin)
    }

    #[inline]
    pub(crate) fn direct_page(&self, index: usize) -> Option<*mut Page> {
        match self.pages_free_direct.get(index) {
            Some(page) => Some(*page),
            None => None,
        }
    }

    /// Replaces one direct-cache entry under the exclusive local lifecycle.
    ///
    /// `page` must be [`EMPTY_PAGE`] or a live page owned by this exact theap;
    /// callers must clear the slot before retiring or reusing that live page.
    #[inline]
    pub(crate) fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        let Some(slot) = self.pages_free_direct.get_mut(index) else {
            return false;
        };
        *slot = page;
        true
    }

    #[inline]
    pub(crate) fn clear_direct_page(&mut self, index: usize) -> bool {
        self.set_direct_page(index, EMPTY_PAGE.as_ptr())
    }

    /// Mirrors the owning-theap count update performed around the source's
    /// queue insertion helpers. The caller must have exclusively inserted one
    /// page into a queue first.
    #[inline]
    pub(crate) fn note_page_added(&mut self) {
        self.page_count += 1;
    }

    /// Mirrors the owning-theap count update performed around the source's
    /// queue removal helpers. Returns `false` rather than underflowing when a
    /// caller violates the queue/page-count pairing contract.
    #[inline]
    pub(crate) fn note_page_removed(&mut self) -> bool {
        let Some(next) = self.page_count.checked_sub(1) else {
            return false;
        };
        self.page_count = next;
        true
    }
}

/// A failed bounded `_mi_theap_init` transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TheapMainStaticInitError {
    InvalidInput,
    ThreadList(ThreadLocalTheapListError),
    HeapList(HeapTheapListError),
}

/// The only dynamic-Theap option images represented before `_mi_theap_init`
/// Release-publishes its heap pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicTheapPageMode {
    /// Ordinary source mode: page abandonment remains enabled, so no bounded
    /// local page session may be constructed over this attachment.
    OrdinaryAbandoning,
    /// Private bounded mode: abandonment is disabled before publication and
    /// the shared non-abandoning page engine may drain its page lifecycle.
    NonAbandoningPageSession,
}

impl DynamicTheapPageMode {
    #[inline]
    pub(crate) const fn allows_page_abandon(self) -> bool {
        matches!(self, Self::OrdinaryAbandoning)
    }

    /// `mi_theap_options_init` derives both fields from
    /// `mi_option_page_full_retain`: the source-reachable non-abandoning
    /// profile is `-1`, not an invented `allow=false, retain=2` image.
    #[inline]
    pub(crate) const fn page_full_retain(self) -> isize {
        match self {
            Self::OrdinaryAbandoning => 2,
            Self::NonAbandoningPageSession => -1,
        }
    }
}

/// A failed bounded dynamic `_mi_theap_init` transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TheapDynamicInitError {
    InvalidInput,
    ThreadList(ThreadLocalTheapListError),
    HeapList(HeapTheapListError),
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct TheapMainStaticFields {
    pub(crate) initialized: bool,
    pub(crate) refcount: usize,
    pub(crate) cookie_is_odd: bool,
    pub(crate) random_initialized: bool,
    pub(crate) random_weak: bool,
    pub(crate) page_full_retain: isize,
    pub(crate) allows_page_reclaim: bool,
    pub(crate) allows_page_abandon: bool,
    pub(crate) detached: bool,
    pub(crate) memid: MemoryId,
}

const _: [(); 4] = [(); size_of::<MemoryKind>()];
const _: [(); 16] = [(); size_of::<MemoryInfo>()];
const _: [(); 8] = [(); align_of::<MemoryInfo>()];
const _: [(); 24] = [(); size_of::<MemoryId>()];
const _: [(); 8] = [(); align_of::<MemoryId>()];
const _: [(); 496] = [(); size_of::<ArenaPages>()];
const _: [(); 8] = [(); align_of::<ArenaPages>()];
const _: [(); 648] = [(); size_of::<Arena>()];
const _: [(); 8] = [(); align_of::<Arena>()];
const _: [(); 8] = [(); size_of::<Block>()];
const _: [(); 32] = [(); size_of::<PageQueue>()];
const _: [(); 128] = [(); size_of::<Page>()];
const _: [(); 8] = [(); align_of::<Page>()];
// `Heap` stops at the source `memid` field and uses allocator-private futex
// locks in place of pthread ABI objects. Its size is intentionally not a C
// layout assertion.
const _: [(); 136] = [(); size_of::<TheapRandomImage>()];
const _: [(); 4] = [(); align_of::<TheapRandomImage>()];
const _: [(); 3736] = [(); size_of::<Theap>()];
const _: [(); 8] = [(); align_of::<Theap>()];
const _: [(); 129] = [(); PAGES_DIRECT];
const _: [(); 74] = [(); BIN_FULL];

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::{align_of, offset_of, size_of, MaybeUninit};

    #[test]
    fn oracle_layout_probe_emits_machine_record() {
        macro_rules! record {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value);
            };
        }

        std::println!("CRABC_MI_LAYOUT_BEGIN");
        record!("pointer.size", size_of::<*const ()>());
        record!("sizeof.mi_memkind_t", size_of::<MemoryKind>());
        record!("alignof.mi_memkind_t", align_of::<MemoryKind>());
        record!("value.MI_MEM_NONE", MemoryKind::None as usize);
        record!("value.MI_MEM_EXTERNAL", MemoryKind::External as usize);
        record!("value.MI_MEM_STATIC", MemoryKind::Static as usize);
        record!("value.MI_MEM_OS", MemoryKind::Os as usize);
        record!("value.MI_MEM_OS_HUGE", MemoryKind::OsHuge as usize);
        record!("value.MI_MEM_OS_REMAP", MemoryKind::OsRemap as usize);
        record!("value.MI_MEM_ARENA", MemoryKind::Arena as usize);
        record!("value.MI_MEM_MALLOC", MemoryKind::Malloc as usize);
        record!("sizeof.mi_memid_t", size_of::<MemoryId>());
        record!("alignof.mi_memid_t", align_of::<MemoryId>());
        record!("offsetof.mi_memid_t.mem", offset_of!(MemoryId, info));
        record!("offsetof.mi_memid_t.memkind", offset_of!(MemoryId, kind));
        record!("offsetof.mi_memid_t.is_pinned", offset_of!(MemoryId, is_pinned));
        record!(
            "offsetof.mi_memid_t.initially_committed",
            offset_of!(MemoryId, initially_committed)
        );
        record!(
            "offsetof.mi_memid_t.initially_zero",
            offset_of!(MemoryId, initially_zero)
        );
        record!("sizeof.mi_page_t", size_of::<Page>());
        record!("alignof.mi_page_t", align_of::<Page>());
        record!("offsetof.mi_page_t.xthread_free", offset_of!(Page, xthread_free));
        record!("offsetof.mi_page_t.theap", offset_of!(Page, theap));
        record!("offsetof.mi_page_t.memid", offset_of!(Page, memid));
        record!("sizeof.mi_page_kind_t", size_of::<PageKind>());
        record!("alignof.mi_page_kind_t", align_of::<PageKind>());
        record!("value.MI_PAGE_SMALL", PageKind::Small as usize);
        record!("value.MI_PAGE_MEDIUM", PageKind::Medium as usize);
        record!("value.MI_PAGE_LARGE", PageKind::Large as usize);
        record!("value.MI_PAGE_SINGLETON", PageKind::Singleton as usize);
        record!("sizeof.mi_page_queue_t", size_of::<PageQueue>());
        record!("alignof.mi_page_queue_t", align_of::<PageQueue>());
        record!("offsetof.mi_page_queue_t.first", offset_of!(PageQueue, first));
        record!("offsetof.mi_page_queue_t.last", offset_of!(PageQueue, last));
        record!("offsetof.mi_page_queue_t.count", offset_of!(PageQueue, count));
        record!(
            "offsetof.mi_page_queue_t.block_size",
            offset_of!(PageQueue, block_size)
        );
        record!("alignof.mi_theap_t", align_of::<Theap>());
        record!(
            "offsetof.mi_theap_t.pages_free_direct",
            offset_of!(Theap, pages_free_direct)
        );
        record!("offsetof.mi_theap_t.page_count", offset_of!(Theap, page_count));
        record!("offsetof.mi_theap_t.pages", offset_of!(Theap, pages));
        record!("offsetof.mi_theap_t.memid", offset_of!(Theap, memid));
        // This exact prefix ends where the intentionally absent C `stats`
        // field begins; it is not a complete `sizeof(mi_theap_t)` claim.
        record!("offsetof.mi_theap_t.stats", size_of::<Theap>());
        record!("sizeof.mi_arena_t", size_of::<Arena>());
        record!("alignof.mi_arena_t", align_of::<Arena>());
        record!("offsetof.mi_arena_t.memid", offset_of!(Arena, memid));
        record!("offsetof.mi_arena_t.subproc", offset_of!(Arena, subprocess));
        record!("offsetof.mi_arena_t.arena_idx", offset_of!(Arena, arena_index));
        record!("offsetof.mi_arena_t.start", offset_of!(Arena, start));
        record!("offsetof.mi_arena_t.slice_count", offset_of!(Arena, slice_count));
        record!("offsetof.mi_arena_t.info_slices", offset_of!(Arena, info_slices));
        record!("offsetof.mi_arena_t.numa_node", offset_of!(Arena, numa_node));
        record!("offsetof.mi_arena_t.is_exclusive", offset_of!(Arena, is_exclusive));
        record!("offsetof.mi_arena_t.purge_expire", offset_of!(Arena, purge_expire));
        record!("offsetof.mi_arena_t.commit_fun", offset_of!(Arena, commit_function));
        record!(
            "offsetof.mi_arena_t.commit_fun_arg",
            offset_of!(Arena, commit_function_argument)
        );
        record!("offsetof.mi_arena_t.total_size", offset_of!(Arena, total_size));
        record!("offsetof.mi_arena_t.parent", offset_of!(Arena, parent));
        record!("offsetof.mi_arena_t.slices_free", offset_of!(Arena, slices_free));
        record!(
            "offsetof.mi_arena_t.slices_committed",
            offset_of!(Arena, slices_committed)
        );
        record!("offsetof.mi_arena_t.slices_dirty", offset_of!(Arena, slices_dirty));
        record!("offsetof.mi_arena_t.slices_purge", offset_of!(Arena, slices_purge));
        record!("offsetof.mi_arena_t.pages_meta", offset_of!(Arena, pages_meta));
        record!("offsetof.mi_arena_t.pages_main", offset_of!(Arena, pages_main));
        record!("sizeof.mi_arena_pages_t", size_of::<ArenaPages>());
        record!("alignof.mi_arena_pages_t", align_of::<ArenaPages>());
        record!("offsetof.mi_arena_pages_t.pages", offset_of!(ArenaPages, pages));
        record!(
            "offsetof.mi_arena_pages_t.pages_abandoned",
            offset_of!(ArenaPages, pages_abandoned)
        );
        record!("MI_DEBUG", crate::config::DEBUG_LEVEL);
        record!("MI_SECURE", crate::config::SECURE_LEVEL);
        record!("MI_STAT", crate::config::STAT_LEVEL);
        record!("MI_GUARDED", crate::config::GUARDED as usize);
        record!("MI_PADDING", (crate::config::PADDING_SIZE != 0) as usize);
        record!("MI_ENCODE_FREELIST", crate::config::ENCODE_FREELIST as usize);
        record!("MI_FREE_IS_CHECKED", crate::config::FREE_IS_CHECKED as usize);
        record!("MI_BIN_COUNT", crate::config::BIN_COUNT);
        record!("MI_BIN_HUGE", crate::config::BIN_HUGE);
        record!("MI_ARENA_SLICE_SIZE", crate::config::ARENA_SLICE_SIZE);
        record!("MI_ARENA_CHUNK_SIZE", crate::config::ARENA_CHUNK_SIZE);
        record!("MI_SMALL_PAGE_SIZE", crate::config::SMALL_PAGE_SIZE);
        record!("MI_MEDIUM_PAGE_SIZE", crate::config::MEDIUM_PAGE_SIZE);
        record!("MI_LARGE_PAGE_SIZE", crate::config::LARGE_PAGE_SIZE);
        record!("MI_SMALL_MAX_OBJ_SIZE", crate::config::SMALL_MAX_OBJ_SIZE);
        record!("MI_MEDIUM_MAX_OBJ_SIZE", crate::config::MEDIUM_MAX_OBJ_SIZE);
        record!("MI_LARGE_MAX_OBJ_SIZE", crate::config::LARGE_MAX_OBJ_SIZE);
        record!("MI_MAX_ARENAS", crate::config::MAX_ARENAS);

        // Keep one machine record for every source-derived production
        // constant in `config.rs`; the runner compares these values directly
        // with the pinned v3.5.0 C expressions in `LAYOUT_PROBE`.
        record!("config.WORD_SIZE", crate::config::WORD_SIZE);
        record!("config.MAX_ALIGN_SIZE", crate::config::MAX_ALIGN_SIZE);
        record!("config.SECURE_LEVEL", crate::config::SECURE_LEVEL);
        record!("config.DEBUG_LEVEL", crate::config::DEBUG_LEVEL);
        record!("config.STAT_LEVEL", crate::config::STAT_LEVEL);
        record!(
            "config.FREE_IS_CHECKED",
            crate::config::FREE_IS_CHECKED as usize
        );
        record!(
            "config.FREE_USE_PAGEMAP",
            crate::config::FREE_USE_PAGEMAP as usize
        );
        record!(
            "config.OPT_FREE_SMALL",
            crate::config::OPT_FREE_SMALL as usize
        );
        record!(
            "config.ENABLE_LARGE_PAGES",
            crate::config::ENABLE_LARGE_PAGES as usize
        );
        record!(
            "config.ENCODE_FREELIST",
            crate::config::ENCODE_FREELIST as usize
        );
        record!("config.GUARDED", crate::config::GUARDED as usize);
        record!("config.OPT_SIMD", crate::config::OPT_SIMD as usize);
        record!("config.PADDING_SIZE", crate::config::PADDING_SIZE);
        record!("config.PADDING_WSIZE", crate::config::PADDING_WSIZE);
        record!("config.PAGE_KEY_COUNT", crate::config::PAGE_KEY_COUNT);
        record!("config.ARENA_SLICE_SHIFT", crate::config::ARENA_SLICE_SHIFT);
        record!("config.BCHUNK_BITS_SHIFT", crate::config::BCHUNK_BITS_SHIFT);
        record!("config.BCHUNK_BITS", crate::config::BCHUNK_BITS);
        record!("config.ARENA_SLICE_SIZE", crate::config::ARENA_SLICE_SIZE);
        record!("config.ARENA_SLICE_ALIGN", crate::config::ARENA_SLICE_ALIGN);
        record!("config.ARENA_CHUNK_SIZE", crate::config::ARENA_CHUNK_SIZE);
        record!(
            "config.ARENA_MIN_OBJ_SLICES",
            crate::config::ARENA_MIN_OBJ_SLICES
        );
        record!(
            "config.ARENA_MAX_CHUNK_OBJ_SLICES",
            crate::config::ARENA_MAX_CHUNK_OBJ_SLICES
        );
        record!("config.ARENA_MIN_OBJ_SIZE", crate::config::ARENA_MIN_OBJ_SIZE);
        record!(
            "config.ARENA_MAX_CHUNK_OBJ_SIZE",
            crate::config::ARENA_MAX_CHUNK_OBJ_SIZE
        );
        record!("config.SMALL_PAGE_SIZE", crate::config::SMALL_PAGE_SIZE);
        record!("config.MEDIUM_PAGE_SIZE", crate::config::MEDIUM_PAGE_SIZE);
        record!("config.LARGE_PAGE_SIZE", crate::config::LARGE_PAGE_SIZE);
        record!("config.BIN_HUGE", crate::config::BIN_HUGE);
        record!("config.BIN_FULL", crate::config::BIN_FULL);
        record!("config.BIN_COUNT", crate::config::BIN_COUNT);
        record!("config.MAX_ALLOC_SIZE", crate::config::MAX_ALLOC_SIZE);
        record!(
            "config.PAGE_MIN_COMMIT_SIZE",
            crate::config::PAGE_MIN_COMMIT_SIZE
        );
        record!(
            "config.PAGE_META_IS_SEPARATED",
            crate::config::PAGE_META_IS_SEPARATED as usize
        );
        record!(
            "config.PAGE_META_IS_ALIGNED",
            crate::config::PAGE_META_IS_ALIGNED as usize
        );
        record!(
            "config.PAGE_META_ALIGNED_CHUNKS",
            crate::config::PAGE_META_ALIGNED_CHUNKS
        );
        record!(
            "config.PAGE_META_ALIGNED_COUNT",
            crate::config::PAGE_META_ALIGNED_COUNT
        );
        record!(
            "config.PAGE_META_ALIGNMENT",
            crate::config::PAGE_META_ALIGNMENT
        );
        record!("config.ARENA_ALIGNMENT", crate::config::ARENA_ALIGNMENT);
        record!("config.PAGE_ALIGN", crate::config::PAGE_ALIGN);
        record!(
            "config.PAGE_MIN_START_BLOCK_ALIGN",
            crate::config::PAGE_MIN_START_BLOCK_ALIGN
        );
        record!(
            "config.PAGE_MAX_START_BLOCK_ALIGN2",
            crate::config::PAGE_MAX_START_BLOCK_ALIGN2
        );
        record!(
            "config.PAGE_OSPAGE_BLOCK_ALIGN2",
            crate::config::PAGE_OSPAGE_BLOCK_ALIGN2
        );
        record!(
            "config.PAGE_MAX_OVERALLOC_ALIGN",
            crate::config::PAGE_MAX_OVERALLOC_ALIGN
        );
        record!("config.SMALL_WSIZE_MAX", crate::config::SMALL_WSIZE_MAX);
        record!("config.SMALL_SIZE_MAX", crate::config::SMALL_SIZE_MAX);
        record!(
            "config.SMALL_MAX_OBJ_SIZE",
            crate::config::SMALL_MAX_OBJ_SIZE
        );
        record!(
            "config.MEDIUM_MAX_OBJ_SIZE",
            crate::config::MEDIUM_MAX_OBJ_SIZE
        );
        record!(
            "config.LARGE_MAX_OBJ_SIZE",
            crate::config::LARGE_MAX_OBJ_SIZE
        );
        record!(
            "config.LARGE_MAX_OBJ_WSIZE",
            crate::config::LARGE_MAX_OBJ_WSIZE
        );
        record!(
            "config.MAX_SINGLETON_BIN",
            crate::config::MAX_SINGLETON_BIN
        );
        record!("config.PAGES_DIRECT", crate::config::PAGES_DIRECT);
        record!("config.MAX_ARENAS", crate::config::MAX_ARENAS);
        record!("config.ARENA_BIN_COUNT", crate::config::ARENA_BIN_COUNT);
        record!(
            "config.BITMAP_MAX_BIT_COUNT",
            crate::config::BITMAP_MAX_BIT_COUNT
        );
        record!("config.ARENA_MIN_SIZE", crate::config::ARENA_MIN_SIZE);
        record!("config.ARENA_MAX_SIZE", crate::config::ARENA_MAX_SIZE);
        record!("config.MAX_VABITS", crate::config::MAX_VABITS);
        record!("config.MIN_VABITS", crate::config::MIN_VABITS);
        record!("config.PAGE_MAP_FLAT", crate::config::PAGE_MAP_FLAT as usize);
        record!(
            "config.PAGE_MAP_SUB_SHIFT",
            crate::config::PAGE_MAP_SUB_SHIFT
        );
        record!(
            "config.PAGE_MAP_SUB_COUNT",
            crate::config::PAGE_MAP_SUB_COUNT
        );
        record!("config.PAGE_MAP_SHIFT", crate::config::PAGE_MAP_SHIFT);
        for (bin_index, block_size) in BIN_BLOCK_SIZES.iter().copied().enumerate() {
            std::println!("bin.block_size.{bin_index}={block_size}");
            for (label, size) in [
                ("minus", block_size - 1),
                ("at", block_size),
                ("plus", block_size + 1),
            ] {
                let selected = crate::size_class::bin(size)
                    .expect("every queue boundary is below the size-overflow limit");
                std::println!("bin.index.{bin_index}.{label}={selected}");
            }
        }
        std::println!("CRABC_MI_LAYOUT_END");
    }

    #[test]
    fn metadata_layout_matches_the_default_release_c_contract() {
        assert_eq!(size_of::<MemoryKind>(), 4);
        assert_eq!(size_of::<MemoryInfo>(), 16);
        assert_eq!(align_of::<MemoryInfo>(), 8);
        assert_eq!(size_of::<MemoryId>(), 24);
        assert_eq!(align_of::<MemoryId>(), 8);
        assert_eq!(offset_of!(MemoryId, info), 0);
        assert_eq!(offset_of!(MemoryId, kind), 16);
        assert_eq!(offset_of!(MemoryId, is_pinned), 20);
        assert_eq!(offset_of!(MemoryId, initially_committed), 21);
        assert_eq!(offset_of!(MemoryId, initially_zero), 22);

        assert_eq!(size_of::<Block>(), 8);
        assert_eq!(size_of::<PageQueue>(), 32);
        assert_eq!(align_of::<PageQueue>(), 8);
        assert_eq!(size_of::<Page>(), 128);
        assert_eq!(align_of::<Page>(), 8);
        assert_eq!(offset_of!(Page, self_), 0);
        assert_eq!(offset_of!(Page, xthread_id), 8);
        assert_eq!(offset_of!(Page, xthread_free), 64);
        assert_eq!(offset_of!(Page, memid), 104);
    }

    #[test]
    fn represented_theap_prefix_keeps_the_pinned_field_offsets() {
        // These are offsets in the actual C `mi_theap_t`; this Rust prefix
        // stops at the same `memid` end boundary before absent `mi_stats_t`.
        assert_eq!(size_of::<TheapRandomImage>(), 136);
        assert_eq!(offset_of!(Theap, pages_free_direct), 0);
        assert_eq!(offset_of!(Theap, tld), PAGES_DIRECT * size_of::<*mut Page>());
        assert_eq!(offset_of!(Theap, heap), 1_040);
        assert_eq!(offset_of!(Theap, random), 1_080);
        assert_eq!(offset_of!(Theap, pages), 1_312);
        assert_eq!(offset_of!(Theap, memid), 3_712);
        assert_eq!(size_of::<Theap>(), 3_736);
        assert_eq!(align_of::<Theap>(), 8);
    }

    #[test]
    fn fresh_page_publication_resets_every_local_lifecycle_field() {
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_bootstrap_exclusive(thread_id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));
        assert_eq!(theap.page_full_retain(), 2);

        let mut page = Page::empty();
        page.used = 7;
        page.local_free = core::ptr::without_provenance_mut::<Block>(0x1000);
        page.capacity = 7;
        page.retire_expire = 3;
        page.free_is_zero = true;
        page.next = core::ptr::without_provenance_mut::<Page>(0x1000);
        page.prev = core::ptr::without_provenance_mut::<Page>(0x2000);

        let memid = MemoryId::none();
        assert!(page.publish_fresh_exclusive(
            &mut theap,
            &mut heap,
            thread_id,
            16,
            128,
            32,
            0,
            false,
            memid,
        ));

        assert_eq!(page.self_.load(core::sync::atomic::Ordering::Acquire), core::ptr::from_mut(&mut page));
        assert_eq!(page.theap(), core::ptr::from_mut(&mut theap));
        assert_eq!(page.heap(), core::ptr::from_mut(&mut heap));
        assert_eq!(page.xthread_id.load(core::sync::atomic::Ordering::Acquire), thread_id.get());
        assert_eq!(page.xthread_free.load(core::sync::atomic::Ordering::Acquire), 1);
        assert!(page.free.is_null());
        assert!(page.local_free.is_null());
        assert_eq!(page.used(), 0);
        assert_eq!(page.capacity(), 0);
        assert_eq!(page.reserved(), 32);
        assert_eq!(page.block_size(), 16);
        assert!(!page.has_interior_pointers());
        page.set_has_interior_pointers(true);
        assert!(page.has_interior_pointers());
        assert_eq!(
            page.xthread_id.load(core::sync::atomic::Ordering::Relaxed),
            thread_id.get() | PAGE_HAS_INTERIOR_POINTERS,
        );
        page.set_has_interior_pointers(false);
        assert!(!page.has_interior_pointers());
        assert_eq!(
            page.xthread_id.load(core::sync::atomic::Ordering::Relaxed),
            thread_id.get(),
        );
        page.xthread_id.fetch_or(
            PAGE_IN_FULL_QUEUE,
            core::sync::atomic::Ordering::Relaxed,
        );
        page.set_has_interior_pointers(true);
        page.set_has_interior_pointers(false);
        assert_eq!(
            page.xthread_id.load(core::sync::atomic::Ordering::Relaxed),
            thread_id.get() | PAGE_IN_FULL_QUEUE,
        );
        page.xthread_id.fetch_and(
            !PAGE_IN_FULL_QUEUE,
            core::sync::atomic::Ordering::Relaxed,
        );
        assert_eq!(page.page_offset(), 128);
        assert_eq!(page.slice_pcommitted, 0);
        assert!(!page.free_is_zero);
        assert_eq!(page.retire_expire(), 0);
        assert!(page.next.is_null());
        assert!(page.prev.is_null());
        assert_eq!(page.memid().kind(), MemoryKind::None);
    }

    #[test]
    fn raw_fresh_page_publication_performs_its_transition_in_every_profile() {
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_bootstrap_exclusive(thread_id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));

        let mut storage = MaybeUninit::<Page>::uninit();
        let metadata = NonNull::from(&mut storage).cast::<Page>();
        // SAFETY: `storage` is aligned, writable raw page metadata with no
        // observer. The tested boundary initializes its full Page image.
        let page = unsafe {
            Page::publish_fresh_exclusive_at(
                metadata,
                &mut theap,
                &mut heap,
                thread_id,
                16,
                128,
                32,
                0,
                false,
                MemoryId::none(),
            )
        }
        .expect("valid raw metadata publication");
        // SAFETY: successful publication initialized this exact Page image.
        let page = unsafe { page.as_ref() };
        assert_eq!(page.block_size(), 16);
        assert_eq!(page.page_offset(), 128);
        assert_eq!(page.reserved(), 32);
        assert_eq!(page.theap(), core::ptr::from_mut(&mut theap));
        assert_eq!(page.heap(), core::ptr::from_mut(&mut heap));
        assert_eq!(
            page.xthread_id.load(core::sync::atomic::Ordering::Acquire),
            thread_id.get(),
        );
    }

    #[test]
    fn aligned_metadata_alias_publishes_only_its_primary_owner() {
        let mut primary = Page::empty();
        let mut alias = Page::empty();
        alias.block_size = 73;
        alias.used = 9;
        alias.memid = MemoryId::static_empty();
        let primary = NonNull::from(&mut primary);
        let alias = NonNull::from(&mut alias);

        // SAFETY: both test pages are exclusive, address-stable stack values;
        // the alias is not observed until publication returns.
        unsafe { Page::publish_aligned_alias_at(alias, primary) };
        // SAFETY: publication initialized the complete alias Page image.
        let alias_ref = unsafe { alias.as_ref() };
        assert_eq!(alias_ref.aligned_alias_owner(), primary.as_ptr());
        assert_eq!(alias_ref.block_size(), 0);
        assert_eq!(alias_ref.used(), 0);
        assert_eq!(alias_ref.memid().kind(), MemoryKind::None);

        // SAFETY: this test serializes the matching alias transition and does
        // not access it after the clear except to inspect its atomic owner.
        assert!(unsafe { Page::clear_aligned_alias_at(alias, primary) });
        assert!(alias_ref.aligned_alias_owner().is_null());
        // SAFETY: the alias no longer names the primary, so a second clear is
        // rejected without changing any ownership state.
        assert!(!unsafe { Page::clear_aligned_alias_at(alias, primary) });
    }

    #[test]
    fn free_detached_page_retirement_clears_owner_and_returns_provenance() {
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_bootstrap_exclusive(thread_id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));

        let source_memid = MemoryId::external(
            core::ptr::without_provenance_mut::<u8>(0x1000),
            4096,
            true,
            false,
            true,
        );
        let mut page = Page::empty();
        assert!(page.publish_fresh_exclusive(
            &mut theap,
            &mut heap,
            thread_id,
            16,
            128,
            32,
            1,
            true,
            source_memid,
        ));

        let released = page
            .retire_exclusive()
            .expect("fresh page is free and queue-detached");
        assert_eq!(released.kind(), MemoryKind::External);
        assert!(page.self_.load(core::sync::atomic::Ordering::Acquire).is_null());
        assert_eq!(
            page.xthread_id.load(core::sync::atomic::Ordering::Acquire),
            THREAD_ID_ABANDONED
        );
        assert_eq!(page.xthread_free.load(core::sync::atomic::Ordering::Acquire), 0);
        assert!(page.free.is_null());
        assert!(page.local_free.is_null());
        assert_eq!(page.used(), 0);
        assert_eq!(page.block_size(), 0);
        assert_eq!(page.page_offset(), 0);
        assert_eq!(page.capacity(), 0);
        assert_eq!(page.reserved(), 0);
        assert_eq!(page.slice_pcommitted, 0);
        assert_eq!(page.retire_expire(), 0);
        assert!(!page.free_is_zero());
        assert!(page.theap().is_null());
        assert!(page.heap().is_null());
        assert!(page.next().is_null());
        assert!(page.prev.is_null());
        assert_eq!(page.memid().kind(), MemoryKind::None);
    }

    #[test]
    fn empty_page_is_static_and_has_no_allocator_owned_state() {
        let page = EMPTY_PAGE.as_ref();
        assert_eq!(page.xthread_id.load(core::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(page.xthread_free.load(core::sync::atomic::Ordering::Relaxed), 0);
        assert!(page.memid.needs_no_free());
        assert_eq!(page.memid.kind(), MemoryKind::Static);
        assert_eq!(page.block_size, 0);
        assert_eq!(page.capacity, 0);
        assert_eq!(page.reserved, 0);
    }

    #[test]
    fn relinquishing_parent_memory_ownership_preserves_subarena_observations() {
        let base = core::ptr::without_provenance_mut::<u8>(0x1_0000);
        let mut memory = MemoryId::external(base, 32 * 1024 * 1024, true, true, true);

        memory.relinquish_ownership();

        assert_eq!(memory.kind(), MemoryKind::None);
        assert!(memory.is_pinned());
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        assert!(memory.os_memory().is_none(), "a subarena does not own the parent mapping");
    }

    #[test]
    fn page_queue_initializers_match_all_pinned_bin_sizes() {
        assert_eq!(BIN_BLOCK_SIZES.len(), crate::config::BIN_COUNT);
        assert_eq!(BIN_BLOCK_SIZES[0], 8);
        assert_eq!(BIN_BLOCK_SIZES[1], 8);
        assert_eq!(BIN_BLOCK_SIZES[8], 64);
        assert_eq!(BIN_BLOCK_SIZES[9], 80);
        assert_eq!(BIN_BLOCK_SIZES[72], 4 * 1024 * 1024);
        assert_eq!(BIN_BLOCK_SIZES[73], 524_296);
        assert_eq!(BIN_BLOCK_SIZES[74], 524_304);
        for (queue, size) in EMPTY_PAGE_QUEUES.iter().zip(BIN_BLOCK_SIZES) {
            assert!(queue.first.is_null());
            assert!(queue.last.is_null());
            assert_eq!(queue.count, 0);
            assert_eq!(queue.block_size, size);
        }
    }
}

#[path = "page_queue.rs"]
pub(crate) mod page_queue;
