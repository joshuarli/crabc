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
// (arena-page and arena metadata layouts), `src/init.c:15-145,184-193,
// 195-198,236-250` (the empty-page, direct-page table, all 75 default queues,
// detached TLD and empty-theap initializers, detached TLD's kind-only memid
// predecessor / detached helper order, and main-Heap `memid` / Release
// identity / heap initialization order), `src/theap.c:228-306,357-369,414-449` (dynamic
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

    /// Records just the kind-only `memid_static` image that pinned
    /// `mi_heap_main_init_once` assigns at `src/init.c:196` before its
    /// Release publication of `subproc->heap_main` at line 197.
    ///
    /// This is deliberately narrower than `_mi_heap_init`: it neither binds
    /// a subprocess nor initializes a Heap field, lock, list, arena, or
    /// thread-local key.  The exclusive mutable borrow prevents safe aliases,
    /// while the observable bootstrap checks reject an obvious reused Heap
    /// image without changing it.  The process-static foundation alone owns
    /// the matching later `initialize_main_static_after_kind_only_memid`.
    #[must_use = "a refused main-Heap memid preparation must retain the source-static transition"]
    #[inline]
    pub(crate) fn prepare_main_static_kind_only_memid(&mut self) -> bool {
        if !self.is_uninitialized_main_static_image()
            || self.memid.kind() != MemoryKind::None
            || self.memid.is_pinned()
            || self.memid.initially_committed()
            || self.memid.initially_zero()
        {
            return false;
        }
        self.memid = MemoryId::static_kind_only();
        true
    }

    /// Completes the bounded `_mi_heap_init` shape after
    /// [`Self::prepare_main_static_kind_only_memid`] has established the
    /// source `memid_static` image and the owner has Release-published the
    /// opaque main-Heap identity.
    ///
    /// A non-kind-only or reused image is refused without mutation.  This
    /// method intentionally has no pointer-returning companion: Heap access
    /// remains owned by the enclosing process-static attachment capability.
    #[must_use = "a refused main-Heap field initialization must retain the source-static transition"]
    #[inline]
    pub(crate) fn initialize_main_static_after_kind_only_memid(
        &mut self,
        subprocess: &'static MainSubprocess,
    ) -> bool {
        if !self.is_uninitialized_main_static_image()
            || !self.has_kind_only_static_memid()
        {
            return false;
        }
        self.initialize_main_static_fields(subprocess);
        true
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
        self.memid = memid;
        self.initialize_main_static_fields(subprocess);
    }

    #[inline]
    fn initialize_main_static_fields(&mut self, subprocess: &'static MainSubprocess) {
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
    }

    #[inline]
    fn is_uninitialized_main_static_image(&self) -> bool {
        self.subprocess.is_null()
            && self.heap_seq == 0
            && self.next.is_null()
            && self.prev.is_null()
            && self.theap_slot == 0
            && self.exclusive_arena.is_null()
            && self.numa_node == 0
            && self.theaps.is_null()
            && self
                .abandoned_count
                .iter()
                .all(|count| count.load(Ordering::Relaxed) == 0)
            && self.os_abandoned_pages.is_null()
            && self
                .arena_pages
                .iter()
                .all(|pages| pages.load(Ordering::Relaxed).is_null())
    }

    #[inline]
    fn has_kind_only_static_memid(&self) -> bool {
        let Some(memory) = self.memid.static_memory() else {
            return false;
        };
        !self.memid.is_pinned()
            && !self.memid.initially_committed()
            && !self.memid.initially_zero()
            && memory.base.is_null()
            && memory.size == 0
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
        self.initialize_dynamic_binding_with_selected_arena(
            subprocess,
            regular_theap_key,
            null_mut(),
        )
    }

    /// Initializes a caller-pinned first-class Heap image whose source
    /// `exclusive_arena` field selects one already-live direct parent arena.
    ///
    /// This is the `mi_heap_init` input used by `heap.c:mi_heap_init_theap`
    /// before its `_mi_theap_create(heap, mi_theap_get_default()->tld)` call.
    /// It records only the selected parent identity in the bounded caller
    /// image: it does not publish a regular TLS slot, create a heap list
    /// entry, or claim the full source Heap allocation/lifetime.
    ///
    /// # Safety
    ///
    /// The caller must uphold [`Self::initialize_dynamic_binding`]'s fresh,
    /// address-stable caller-storage obligation and additionally prove that
    /// `requested_parent` is the live direct parent selected for this Heap,
    /// belongs to `subprocess`, and remains live until the matching arena
    /// Theap has detached and this Heap is retired.
    #[inline]
    pub(crate) unsafe fn initialize_dynamic_binding_for_requested_arena(
        &mut self,
        subprocess: &'static MainSubprocess,
        regular_theap_key: usize,
        requested_parent: *mut Arena,
    ) -> bool {
        if requested_parent.is_null() {
            return false;
        }
        self.initialize_dynamic_binding_with_selected_arena(
            subprocess,
            regular_theap_key,
            requested_parent,
        )
    }

    #[inline]
    fn initialize_dynamic_binding_with_selected_arena(
        &mut self,
        subprocess: &'static MainSubprocess,
        regular_theap_key: usize,
        selected_arena: *mut Arena,
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
        self.exclusive_arena = selected_arena;
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
            && self.exclusive_arena.is_null()
            && self.memid.kind() == MemoryKind::None
    }

    /// Verifies the bounded caller Heap image remains bound to this exact
    /// selected requested parent. It deliberately validates no generic heap
    /// list or TLS state: those are separate source owners and must not be
    /// inferred from the stored raw arena identity.
    #[inline]
    pub(crate) fn matches_dynamic_binding_for_requested_arena(
        &self,
        subprocess: &MainSubprocess,
        requested_parent: *mut Arena,
    ) -> bool {
        !requested_parent.is_null()
            && self.theap_slot != 0
            && self.theap_slot != 1
            && core::ptr::eq(self.subprocess, subprocess.as_ptr())
            && self.exclusive_arena == requested_parent
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

    /// Returns C `heap->abandoned_count[bin] != 0` for the relaxed
    /// allocation-time early skip in `arena.c:mi_arenas_page_try_find_abandoned`.
    ///
    /// This is only a search hint: the matching arena bitmap plus its low
    /// page-owner claim remains the authority for reclamation. In particular,
    /// a `true` result never identifies or reserves a page.
    #[inline]
    pub(crate) fn has_abandoned_page_in_bin(&self, bin: usize) -> bool {
        bin < BIN_COUNT && self.abandoned_count[bin].load(Ordering::Relaxed) != 0
    }

    #[cfg(any(test, feature = "native-runtime-test-audit"))]
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

    /// Checks the one-member Heap-list shape used by bounded owners.
    ///
    /// # Safety
    ///
    /// `theap` must be a live, address-stable typed image owned by the caller.
    /// The caller must serialize the observed Heap-list links for this
    /// complete observation.
    #[inline]
    pub(crate) unsafe fn has_exact_theap_member(&self, theap: *mut Theap) -> bool {
        // SAFETY: forwarded from the caller; the raw image is live and its
        // list links are serialized for this exact observation.
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

    /// Observes the exact finite Heap-list shape admitted by the M1
    /// compiler-TLS same-TLD terminal fixture.
    ///
    /// This is intentionally narrower than a general Heap traversal. The
    /// caller supplies the complete fixture-local member count, so a null
    /// link, extra member, cycle, mismatched Heap publication, or failed lock
    /// is a failed observation rather than an unbounded walk. `contains`
    /// selects whether the named Theap must occur in that exact list shape.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_m1_has_bounded_theap_member(
        &self,
        target: *mut Theap,
        member_count: usize,
        contains: bool,
    ) -> bool {
        // The Rust fixture's main Heap has only D before the selected detach
        // and no members afterwards. Pinned C also retains a metadata member,
        // but that source-private image is outside this Rust representation;
        // do not silently broaden this seam into a generic traversal.
        if target.is_null() || member_count > 1 {
            return false;
        }
        let Ok(guard) = self.theaps_lock.lock() else {
            return false;
        };
        let self_pointer = core::ptr::from_ref(self).cast_mut();
        let mut current = self.theaps;
        let mut found = false;
        let mut valid = true;
        for _ in 0..member_count {
            if current.is_null() {
                valid = false;
                break;
            }
            // SAFETY: the fixture retains every admitted Theap and the
            // source Heap-list lock serializes the hnext/hprev image.
            unsafe {
                if !core::ptr::eq((*current).heap.load(Ordering::Acquire), self_pointer) {
                    valid = false;
                    break;
                }
                found |= current == target;
                current = (*current).hnext;
            }
        }
        if !current.is_null() {
            valid = false;
        }
        guard.unlock().is_ok() && valid && found == contains
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

    /// Returns the private non-arena abandoned-list head while a test holds
    /// the source Heap projection or otherwise proves that no concurrent
    /// private-list mutation can occur.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_os_abandoned_page_head(&self) -> *mut Page {
        self.os_abandoned_pages
    }

    /// Reports whether this Heap's private non-arena abandoned-page list has
    /// no current members.
    ///
    /// A bounded owner-exit route may use this only as an entry witness: it
    /// proves that every later list member was inserted by that same route.
    /// It deliberately exposes no traversal, claim, or removal capability.
    #[inline]
    pub(crate) fn os_abandoned_pages_are_empty(
        &self,
    ) -> Result<bool, HeapOsAbandonedPageListError> {
        let guard = self
            .os_abandoned_pages_lock
            .lock()
            .map_err(HeapOsAbandonedPageListError::Lock)?;
        let is_empty = self.os_abandoned_pages.is_null();
        match guard.unlock() {
            Ok(()) => Ok(is_empty),
            Err(error) => Err(HeapOsAbandonedPageListError::Lock(error)),
        }
    }

    /// Links one non-arena abandoned page at this Heap's private OS-list
    /// head.
    ///
    /// This is the insertion half of pinned mimalloc v3.5.0
    /// `src/arena.c:_mi_arenas_page_abandon`'s non-arena branch.  The paired
    /// removal below is the same source's `_mi_arenas_page_unabandon` branch.
    /// The caller must retain the live page metadata for `page`, every page
    /// already linked from this Heap's head, and this Heap for the whole call.
    /// It must also have selected the non-arena abandonment branch; this
    /// intrusive-list primitive neither classifies pages nor changes their
    /// abandoned identity.
    ///
    /// Unlike the unchecked C link writes, this bounded Rust boundary rejects
    /// a linked candidate, a foreign page, or a malformed current head before
    /// making any change. It deliberately does not search for or repair a
    /// separately registered page owner.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized metadata owned by this Heap with
    /// clear intrusive links. The caller must keep it and every current list
    /// neighbor live, and must exclusively own the page's ordinary link
    /// fields through the call. Concurrent live clients may access their
    /// distinct current blocks and only their disjoint remote-free atomic
    /// projections within Page metadata.
    #[inline]
    pub(crate) unsafe fn push_os_abandoned_page(
        &mut self,
        page: NonNull<Page>,
    ) -> Result<(), HeapOsAbandonedPageListError> {
        let guard = self
            .os_abandoned_pages_lock
            .lock()
            .map_err(HeapOsAbandonedPageListError::Lock)?;
        let heap = core::ptr::from_ref(self).cast_mut();
        let page_pointer = page.as_ptr();

        // SAFETY: the caller retains live metadata and owns the ordinary
        // intrusive links. Raw field operations avoid borrowing whole pages
        // while clients may retain disjoint remote-free atomics.
        let result = unsafe {
            if core::ptr::read::<*mut Heap>(core::ptr::addr_of!((*page_pointer).heap)) != heap {
                Err(HeapOsAbandonedPageListError::HeapMismatch)
            } else if !core::ptr::read(core::ptr::addr_of!((*page_pointer).prev)).is_null()
                || !core::ptr::read(core::ptr::addr_of!((*page_pointer).next)).is_null()
            {
                Err(HeapOsAbandonedPageListError::NodeLinked)
            } else {
                let head = self.os_abandoned_pages;
                if head.is_null() {
                    core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).prev), null_mut());
                    core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).next), null_mut());
                    self.os_abandoned_pages = page_pointer;
                    Ok(())
                } else if head == page_pointer
                    || !core::ptr::eq((*head).heap, heap)
                    || !(*head).prev.is_null()
                {
                    Err(HeapOsAbandonedPageListError::Head)
                } else {
                    let head_next = (*head).next;
                    if !head_next.is_null()
                        && (!core::ptr::eq((*head_next).heap, heap)
                            || (*head_next).prev != head)
                    {
                        Err(HeapOsAbandonedPageListError::Head)
                    } else {
                        // Preserve the source link order after every local
                        // ownership relation has been validated.
                        core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).prev), null_mut());
                        core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).next), head);
                        core::ptr::write(core::ptr::addr_of_mut!((*head).prev), page_pointer);
                        self.os_abandoned_pages = page_pointer;
                        Ok(())
                    }
                }
            }
        };

        match (result, guard.unlock()) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(error)) | (Err(_), Err(error)) => {
                Err(HeapOsAbandonedPageListError::Lock(error))
            }
            (Err(error), Ok(())) => Err(error),
        }
    }

    /// Unlinks one exact member from this Heap's private OS-abandoned-page
    /// list.
    ///
    /// This is the removal half of pinned mimalloc v3.5.0
    /// `src/arena.c:_mi_arenas_page_unabandon`'s non-arena branch. The caller
    /// retains live metadata for `page`, this Heap, and all already-linked
    /// adjacent pages. It must hold the page's higher-level abandonment owner
    /// transition; this method only performs the locked list mutation and
    /// clears the removed page's two intrusive links.
    ///
    /// The direct predecessor/successor and current-head relations are all
    /// validated before writes. A foreign, absent, or malformed member is
    /// rejected with every existing link preserved rather than being silently
    /// spliced into a different list.
    ///
    /// # Safety
    ///
    /// `page` must name one stable initialized member of this Heap's private
    /// list. The caller must retain it and every direct neighbor and must
    /// exclusively own their ordinary link fields through the call.
    /// Concurrent live clients may access their distinct current blocks and
    /// only their disjoint remote-free atomic projections within Page
    /// metadata.
    #[inline]
    pub(crate) unsafe fn remove_os_abandoned_page_with_outcome(
        &mut self,
        page: NonNull<Page>,
    ) -> HeapOsAbandonedPageRemovalOutcome {
        let guard = match self.os_abandoned_pages_lock.lock() {
            Ok(guard) => guard,
            Err(error) => {
                return HeapOsAbandonedPageRemovalOutcome::NotRemoved(
                    HeapOsAbandonedPageListError::Lock(error),
                );
            }
        };
        let heap = core::ptr::from_ref(self).cast_mut();
        let page_pointer = page.as_ptr();

        // SAFETY: caller retains every direct neighbor and owns the ordinary
        // link fields; the private lock serializes all list mutations. Raw
        // subobject operations manufacture no whole-page mutable reference.
        let result = unsafe {
            if core::ptr::read::<*mut Heap>(core::ptr::addr_of!((*page_pointer).heap)) != heap {
                Err(HeapOsAbandonedPageListError::HeapMismatch)
            } else {
                let head = self.os_abandoned_pages;
                if head.is_null()
                    || !core::ptr::eq((*head).heap, heap)
                    || !(*head).prev.is_null()
                {
                    Err(HeapOsAbandonedPageListError::Membership)
                } else {
                    let head_next = (*head).next;
                    if !head_next.is_null()
                        && (!core::ptr::eq((*head_next).heap, heap)
                            || (*head_next).prev != head)
                    {
                        Err(HeapOsAbandonedPageListError::Head)
                    } else {
                        let previous = core::ptr::read(core::ptr::addr_of!((*page_pointer).prev));
                        let next = core::ptr::read(core::ptr::addr_of!((*page_pointer).next));
                        if previous.is_null() {
                            if head != page_pointer {
                                Err(HeapOsAbandonedPageListError::Membership)
                            } else if !next.is_null()
                                && (!core::ptr::eq((*next).heap, heap)
                                    || (*next).prev != page_pointer)
                            {
                                Err(HeapOsAbandonedPageListError::Successor)
                            } else {
                                self.os_abandoned_pages = next;
                                if !next.is_null() {
                                    core::ptr::write(core::ptr::addr_of_mut!((*next).prev), null_mut());
                                }
                                core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).next), null_mut());
                                core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).prev), null_mut());
                                Ok(())
                            }
                        } else if previous == page_pointer
                            || !core::ptr::eq((*previous).heap, heap)
                            || (*previous).next != page_pointer
                        {
                            Err(HeapOsAbandonedPageListError::Predecessor)
                        } else if !next.is_null()
                            && (next == page_pointer
                                || !core::ptr::eq((*next).heap, heap)
                                || (*next).prev != page_pointer)
                        {
                            Err(HeapOsAbandonedPageListError::Successor)
                        } else {
                            core::ptr::write(core::ptr::addr_of_mut!((*previous).next), next);
                            if !next.is_null() {
                                core::ptr::write(core::ptr::addr_of_mut!((*next).prev), previous);
                            }
                            core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).next), null_mut());
                            core::ptr::write(core::ptr::addr_of_mut!((*page_pointer).prev), null_mut());
                            Ok(())
                        }
                    }
                }
            }
        };

        match (result, guard.unlock()) {
            (Ok(()), Ok(())) => HeapOsAbandonedPageRemovalOutcome::Removed,
            // The source splice and link clearing completed before the private
            // lock's wake/error boundary. Preserve that irreversible fact so
            // a terminal caller never treats this as a still-linked page.
            (Ok(()), Err(error)) => {
                HeapOsAbandonedPageRemovalOutcome::RemovedUnlockFailed(error)
            }
            (Err(_), Err(error)) => HeapOsAbandonedPageRemovalOutcome::NotRemoved(
                HeapOsAbandonedPageListError::Lock(error),
            ),
            (Err(error), Ok(())) => HeapOsAbandonedPageRemovalOutcome::NotRemoved(error),
        }
    }

    /// Removes one OS-abandoned list member while preserving the historic
    /// `Result` boundary for callers that do not own a later irreversible
    /// terminal transition.
    ///
    /// A new post-list terminal owner must instead call
    /// [`Self::remove_os_abandoned_page_with_outcome`] and retain
    /// [`HeapOsAbandonedPageRemovalOutcome::RemovedUnlockFailed`] as a
    /// completed splice.
    ///
    /// # Safety
    ///
    /// Same as [`Self::remove_os_abandoned_page_with_outcome`].
    #[inline]
    pub(crate) unsafe fn remove_os_abandoned_page(
        &mut self,
        page: NonNull<Page>,
    ) -> Result<(), HeapOsAbandonedPageListError> {
        match unsafe { self.remove_os_abandoned_page_with_outcome(page) } {
            HeapOsAbandonedPageRemovalOutcome::Removed => Ok(()),
            HeapOsAbandonedPageRemovalOutcome::RemovedUnlockFailed(error) => {
                Err(HeapOsAbandonedPageListError::Lock(error))
            }
            HeapOsAbandonedPageRemovalOutcome::NotRemoved(error) => Err(error),
        }
    }
}

/// A failure while manipulating the private source heap-theap list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapTheapListError {
    Busy,
    Membership,
    Lock(crabc_core::Errno),
}

/// A rejected mutation of the private `heap->os_abandoned_pages` list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapOsAbandonedPageListError {
    /// The supplied live page belongs to another Heap.
    HeapMismatch,
    /// Insertion requires both intrusive page links to be clear.
    NodeLinked,
    /// Removal did not name this Heap's head or a locally linked member.
    Membership,
    /// The current head has foreign or inconsistent local links.
    Head,
    /// The candidate's predecessor is foreign, self-referential, or does not
    /// name the candidate as its successor.
    Predecessor,
    /// The candidate's successor is foreign, self-referential, or does not
    /// name the candidate as its predecessor.
    Successor,
    /// The allocator-private lock acquisition or release failed.
    Lock(crabc_core::Errno),
}

/// Mutation-aware result of removing one source OS-abandoned-list member.
///
/// A lock wake may fail after the list splice and link clearing completed.
/// This type makes that ordering explicit for terminal source paths while the
/// older `Result` wrapper remains available to bounded callers that treat any
/// lock error as terminal at their own higher boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapOsAbandonedPageRemovalOutcome {
    /// The list splice completed and its lock guard reported normal release.
    Removed,
    /// The list splice completed, but the internal private-lock release
    /// reported an error after it made its source Release transition.
    RemovedUnlockFailed(crabc_core::Errno),
    /// No splice occurred; the page remains subject to its prior list owner.
    NotRemoved(HeapOsAbandonedPageListError),
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

/// Test-only event witness for the exact modeled write order of the normal
/// `mi_tld_init` arm. Its events are emitted by the production helper's
/// shared implementation; this contains no substitute initialization logic.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct NormalTldInitWriteTrace {
    next: usize,
    subprocess: usize,
    theap_head: usize,
    lock: usize,
    numa_node: usize,
    thread_id: usize,
    threadpool: usize,
    thread_sequence: usize,
    live_registration: usize,
}

#[cfg(test)]
impl NormalTldInitWriteTrace {
    #[inline]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn record_next(&mut self) -> usize {
        self.next += 1;
        self.next
    }

    #[inline]
    fn record_subprocess(&mut self) {
        self.subprocess = self.record_next();
    }

    #[inline]
    fn record_theap_head(&mut self) {
        self.theap_head = self.record_next();
    }

    #[inline]
    fn record_lock(&mut self) {
        self.lock = self.record_next();
    }

    #[inline]
    fn record_numa_node(&mut self) {
        self.numa_node = self.record_next();
    }

    #[inline]
    fn record_thread_id(&mut self) {
        self.thread_id = self.record_next();
    }

    #[inline]
    fn record_threadpool(&mut self) {
        self.threadpool = self.record_next();
    }

    #[inline]
    fn record_thread_sequence(&mut self) {
        self.thread_sequence = self.record_next();
    }

    /// Records the final modeled `mi_tld_init` `thread_count` increment. The
    /// linear Rust ticket owns this effect immediately after the field prefix
    /// and before a static owner Release-publishes its image.
    #[inline]
    pub(crate) fn record_live_registration(&mut self) {
        self.live_registration = self.record_next();
    }

    #[inline]
    pub(crate) fn has_exact_source_order(&self) -> bool {
        self.subprocess == 1
            && self.theap_head == 2
            && self.lock == 3
            && self.numa_node == 4
            && self.thread_id == 5
            && self.threadpool == 6
            && self.thread_sequence == 7
            && self.live_registration == 8
            && self.next == 8
    }

    #[inline]
    pub(crate) fn modeled_field_writes_are_ordered(&self) -> bool {
        self.numa_node < self.thread_id
            && self.thread_id < self.threadpool
            && self.threadpool < self.thread_sequence
    }

    /// Checks the five effects C can hook in this body against the complete
    /// eight-event Rust field trace. C observes five primitive/counter calls;
    /// Rust observes their corresponding modeled field/counter positions, not
    /// a claim that Rust acquires its already-validated identity at that spot.
    #[inline]
    pub(crate) fn has_modeled_observable_source_effect_order(&self) -> bool {
        self.lock == 3
            && self.numa_node == 4
            && self.thread_id == 5
            && self.threadpool == 6
            && self.live_registration == 8
            && self.next == 8
    }
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

    /// Forms the valid all-zero-shaped TLD image consumed by the selected
    /// normal arm of pinned `src/init.c:236-250`.
    ///
    /// This represents only the direct helper's read/write preimage: an
    /// abandoned zero thread identity, no subprocess or Theap head, an
    /// unlocked private list lock, and zero scalar fields.  It deliberately
    /// does not stand for `mi_tld_create`, static-main storage selection, or
    /// a `MemoryId` predecessor; those outer source callers install their own
    /// provenance before they invoke the normal helper.
    #[inline]
    pub(crate) const fn normal_tld_init_preimage() -> Self {
        Self {
            thread_id: THREAD_ID_ABANDONED,
            thread_seq: 0,
            numa_node: 0,
            subprocess: null_mut(),
            theaps: null_mut(),
            theaps_lock: PrivateLock::new(),
            recurse: false,
            is_in_threadpool: false,
            memid: MemoryId::none(),
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
    /// This is a shape predicate shared by two intentionally distinct source
    /// checkpoints. The detached `src/init.c:236-250` branch names its main
    /// subprocess without changing either thread counter; a non-detached TLD
    /// reaches the same no-Theap shape only after its separate registration
    /// path has acquired a live-count lease. Theap allocation, list
    /// attachment, and compiler-TLS publication are deliberately absent from
    /// both observations.
    #[inline]
    pub(crate) const fn is_subprocess_attached_no_theap(&self) -> bool {
        !self.subprocess.is_null() && self.theaps.is_null()
    }

    /// Checks the exact page-free two-member default-TLD shape used by the
    /// bounded auxiliary-Theap owners: an auxiliary head followed by the
    /// live static default tail. It is not a general list traversal or a
    /// multi-Theap admission API.
    ///
    /// # Safety
    ///
    /// Both raw Theap images must be live and address-stable, and the caller
    /// must exclusively own this TLD's list for the complete observation.
    #[inline]
    pub(crate) unsafe fn has_exact_auxiliary_and_default_pair(
        &self,
        auxiliary: *mut Theap,
        main_default: *mut Theap,
    ) -> bool {
        let self_pointer = core::ptr::from_ref(self).cast_mut();
        // SAFETY: the caller proves both raw images are live, address-stable,
        // and exclusively protected by this TLD's list owner.
        unsafe {
            !auxiliary.is_null()
                && !main_default.is_null()
                && self.theaps == auxiliary
                && (*auxiliary).tprev.is_null()
                && (*auxiliary).tnext == main_default
                && (*main_default).tprev == auxiliary
                && (*main_default).tnext.is_null()
                && core::ptr::eq((*auxiliary).tld, self_pointer)
                && core::ptr::eq((*main_default).tld, self_pointer)
        }
    }

    /// Backward-compatible test spelling for the M1 differential fixture.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_m1_cached_aux_and_main_pair(
        &self,
        cached_aux: *mut Theap,
        main_default: *mut Theap,
    ) -> bool {
        // SAFETY: the finite M1 fixture owns both typed images and invokes
        // this observation while it exclusively owns the TLD list.
        unsafe { self.has_exact_auxiliary_and_default_pair(cached_aux, main_default) }
    }

    /// Counts at most the two list entries admitted by the M1 terminal
    /// fixture. Returning `3` means the fixture is malformed; it never
    /// traverses an unbounded production list.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_m1_theap_count(&self) -> usize {
        let mut count = 0;
        let mut theap = self.theaps;
        while !theap.is_null() && count < 3 {
            count += 1;
            // SAFETY: this finite test-only observation is guarded by the
            // owning M1 fixture, which retains each permitted node.
            theap = unsafe { (*theap).tnext };
        }
        count
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

    /// Enters the source `_mi_deferred_free` callback recursion boundary.
    ///
    /// The caller must retain this exact live TLD for one synchronous callback
    /// and must pair a successful entry with [`Self::end_deferred_callback`]
    /// before any TLD teardown. Returning `false` preserves the source nested
    /// callback skip rather than attempting recursive allocator entry.
    #[inline]
    pub(crate) fn begin_deferred_callback(&mut self) -> bool {
        if self.recurse {
            return false;
        }
        self.recurse = true;
        true
    }

    /// Leaves the source `_mi_deferred_free` callback recursion boundary.
    #[inline]
    pub(crate) fn end_deferred_callback(&mut self) {
        debug_assert!(self.recurse, "a deferred callback must own the recursion marker");
        self.recurse = false;
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
    /// unlocked and returns to that operational state after release.
    ///
    /// This deliberately proves acquire/release behavior rather than a
    /// byte-for-byte `pthread_mutex_t` initializer claim.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_theaps_lock_starts_and_restores_unlocked(&self) -> bool {
        let Some(first) = self.theaps_lock.try_lock() else {
            return false;
        };
        if first.unlock().is_err() {
            return false;
        }
        let Some(second) = self.theaps_lock.try_lock() else {
            return false;
        };
        second.unlock().is_ok()
    }

    /// Checks the direct C fixture's all-zero normal-helper preimage except
    /// for the private lock state. The production predicate deliberately
    /// leaves `memid` caller-owned so static and metadata callers can install
    /// concrete provenance first; this witness instead proves the minimal
    /// `MemoryId::none()` seam used only by the seq=7 direct differential.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_matches_normal_tld_init_minimal_preimage_except_lock(&self) -> bool {
        self.matches_normal_tld_init_direct_preimage() && self.test_memory_id_is_none()
    }

    /// Tests the complete semantic `MemoryId::none()` tuple without exposing
    /// its address-bearing union contents. This is only a local fixture
    /// witness; normal `mi_tld_init` itself leaves caller provenance alone.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_memory_id_is_none(&self) -> bool {
        if self.memid.kind() != MemoryKind::None {
            return false;
        }
        // SAFETY: `MemoryKind::None` is constructed through `empty_with_kind`
        // with this null/zero `os` view. The direct fixture rejects every
        // other discriminant before inspecting that representation.
        let memory = unsafe { self.memid.info.os };
        memory.base.is_null()
            && memory.size == 0
            && !self.memid.is_pinned()
            && !self.memid.initially_committed()
            && !self.memid.initially_zero()
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
    pub(crate) fn test_subprocess_is_null(&self) -> bool {
        self.subprocess.is_null()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_theap_head_is(&self, theap: *mut Theap) -> bool {
        self.theaps == theap
    }

    /// Checks the one-member TLD-list shape used by bounded owners.
    ///
    /// # Safety
    ///
    /// `theap` must be a live, address-stable typed image owned by the caller.
    /// The caller must serialize the observed TLD-list links for this complete
    /// observation.
    #[inline]
    pub(crate) unsafe fn has_exact_theap_member(&self, theap: *mut Theap) -> bool {
        // SAFETY: forwarded from the caller; the raw image is live and its
        // list links are serialized for this exact observation.
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

    /// Applies only `mi_heap_main_init_once`'s detached-TLD `memid` predecessor.
    ///
    /// Pinned `src/init.c:184-193` first replaces the exact
    /// `mi_tld_detached` `MI_MEMID_STATIC` image with
    /// `_mi_memid_create(MI_MEM_STATIC)`, then calls file-static
    /// `mi_tld_init`. Keeping this write separate makes the following helper
    /// a direct representation of the detached `mi_tld_init` body rather
    /// than a broader complete-image replacement.
    ///
    /// Returns `false` without mutation unless `self` is the selected
    /// detached static preimage and its private list lock is quiescent. The
    /// source static image is a valid initializer input; Rust additionally
    /// refuses a busy private futex rather than reusing that poisoned image.
    /// It never names a subprocess, changes a counter, resets the lock, or
    /// adjusts a TLD field other than `memid`.
    #[must_use = "a refused detached static-memid predecessor leaves the source image unchanged"]
    #[inline]
    pub(crate) fn prepare_detached_static_memid(&mut self) -> bool {
        if !self.matches_detached_static_preimage()
            || !self.tld_init_preimage_lock_is_quiescent()
        {
            return false;
        }
        self.memid = MemoryId::static_kind_only();
        true
    }

    /// Applies only the detached branch of pinned `mi_tld_init`.
    ///
    /// This is source-ordered `src/init.c:236-250` after
    /// [`Self::prepare_detached_static_memid`]: write the subprocess, clear
    /// the Theap head, reset its private lock, then write the detached
    /// `numa_node = -1` sentinel. It intentionally does not rewrite the
    /// static predecessor's `memid`, sequence, recursion, or thread-pool
    /// fields, and it does not register a live thread or change either source
    /// counter. The normal `mi_tld_init` branch and `mi_tld_create` remain
    /// separate lifecycle boundaries.
    ///
    /// Returns `false` without mutation unless `self` still has the exact
    /// detached static image after the predecessor step and its private list
    /// lock is quiescent. The exclusive `&mut self` boundary rules out safe
    /// aliases, guards, and waiters; the nonblocking probe additionally
    /// refuses an already-busy lock instead of overwriting it with a new
    /// initializer image.
    #[must_use = "a refused detached mi_tld_init step leaves the source image unchanged"]
    #[inline]
    pub(crate) fn initialize_detached_after_static_memid(
        &mut self,
        subprocess: &'static MainSubprocess,
    ) -> bool {
        if !self.matches_detached_static_memid_preimage() {
            return false;
        }
        if !self.tld_init_preimage_lock_is_quiescent() {
            return false;
        }
        self.subprocess = subprocess.as_ptr();
        self.theaps = null_mut();
        self.theaps_lock = PrivateLock::new();
        self.numa_node = -1;
        true
    }

    /// Applies only the non-detached arm of pinned `mi_tld_init`.
    ///
    /// The modeled body begins after Rust's outer owner has already validated
    /// its live thread identity. It writes the source fields in their exact
    /// body order: subprocess, null Theap head, fresh private lock, NUMA
    /// node, live thread identity, thread-pool result, and source-issued
    /// sequence. The matching [`crate::subproc::ThreadRegistrationTicket`]
    /// owns the
    /// final modeled `thread_count` increment; its full-operation wrapper
    /// runs that effect immediately after this field prefix succeeds.
    ///
    /// `mi_tld_init` neither reads nor writes `memid`; its enclosing source
    /// caller provides that provenance.  This helper therefore accepts the
    /// deliberately minimal direct-helper preimage used by the differential
    /// fixture as well as the concrete static or metadata provenance installed
    /// by bounded Rust callers.  It is not `mi_tld_create`, storage selection,
    /// TLS/list/root publication, or a general TLD lifecycle.
    ///
    /// Returns `false` without mutation unless the selected direct preimage
    /// still exists and its private list lock is quiescent.  The latter is a
    /// Rust safety strengthening: an invalid busy futex must not be replaced
    /// by a fresh lock image.
    #[must_use = "a refused normal mi_tld_init body leaves the source image unchanged"]
    #[inline]
    pub(crate) fn initialize_normal_tld_field_prefix_after_direct_preimage(
        &mut self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node: i32,
        subprocess: &'static MainSubprocess,
    ) -> bool {
        self.initialize_normal_tld_field_prefix_after_direct_preimage_with_numa_source(
            thread_id,
            thread_sequence,
            move || numa_node,
            subprocess,
        )
    }

    /// Applies the normal helper body with its NUMA input obtained exactly at
    /// the source `tld->numa_node` write.  The validated thread identity is
    /// intentionally an already-acquired outer Rust safety input: delaying
    /// that validation would change ticket/slot failure semantics.
    #[inline]
    pub(crate) fn initialize_normal_tld_field_prefix_after_direct_preimage_with_numa_source(
        &mut self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node_source: impl FnOnce() -> i32,
        subprocess: &'static MainSubprocess,
    ) -> bool {
        self.initialize_normal_tld_field_prefix_after_direct_preimage_impl(
            thread_id,
            thread_sequence,
            numa_node_source,
            subprocess,
            #[cfg(test)]
            None,
        )
    }

    /// Executes the selected normal helper body while recording each modeled
    /// source write.  This is test-only instrumentation around the same
    /// production implementation used by
    /// [`Self::initialize_normal_tld_field_prefix_after_direct_preimage`]; it neither supplies
    /// a test implementation nor adds a lifecycle route.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_initialize_normal_tld_field_prefix_after_direct_preimage(
        &mut self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node: i32,
        subprocess: &'static MainSubprocess,
        trace: &mut NormalTldInitWriteTrace,
    ) -> bool {
        self.initialize_normal_tld_field_prefix_after_direct_preimage_impl(
            thread_id,
            thread_sequence,
            move || numa_node,
            subprocess,
            Some(trace),
        )
    }

    #[inline]
    fn initialize_normal_tld_field_prefix_after_direct_preimage_impl(
        &mut self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node_source: impl FnOnce() -> i32,
        subprocess: &'static MainSubprocess,
        #[cfg(test)] mut trace: Option<&mut NormalTldInitWriteTrace>,
    ) -> bool {
        if !self.matches_normal_tld_init_direct_preimage()
            || !self.tld_init_preimage_lock_is_quiescent()
        {
            return false;
        }

        self.subprocess = subprocess.as_ptr();
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.record_subprocess();
        }

        self.theaps = null_mut();
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.record_theap_head();
        }

        self.theaps_lock = PrivateLock::new();
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.record_lock();
        }

        self.numa_node = numa_node_source();
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.record_numa_node();
        }

        self.thread_id = thread_id.get();
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.record_thread_id();
        }

        // `src/prim/unix/prim.c` returns false exactly.  The source helper
        // invokes that primitive here after its thread-ID write; Rust's
        // validated outer boundary carries the resulting fixed value.
        self.is_in_threadpool = false;
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.record_threadpool();
        }

        self.thread_seq = thread_sequence.get();
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.record_thread_sequence();
        }
        true
    }

    #[inline]
    fn matches_detached_static_preimage(&self) -> bool {
        self.matches_detached_static_fields()
            && self.matches_zero_static_memid(true, true)
    }

    #[inline]
    fn matches_detached_static_memid_preimage(&self) -> bool {
        self.matches_detached_static_fields()
            && self.matches_zero_static_memid(false, false)
    }

    #[inline]
    fn matches_normal_tld_init_direct_preimage(&self) -> bool {
        self.thread_id == THREAD_ID_ABANDONED
            && self.thread_seq == 0
            && self.numa_node == 0
            && self.subprocess.is_null()
            && self.theaps.is_null()
            && !self.recurse
            && !self.is_in_threadpool
    }

    /// Probes the initializer-only private lock and restores its unlocked
    /// state before either ordered detached or normal helper writes a field.
    ///
    /// This is intentionally a Rust safety strengthening outside C's valid
    /// static-preimage contract: a test-only or otherwise invalid Rust image
    /// can carry a busy private futex, which neither source helper may safely
    /// reclaim. The exclusive `&mut self` boundary rules out safe aliases,
    /// guards, and waiters while the short probe is held.
    #[inline]
    fn tld_init_preimage_lock_is_quiescent(&self) -> bool {
        let Some(quiescent_lock) = self.theaps_lock.try_lock() else {
            return false;
        };
        // Drop deliberately restores the probe's unlocked state before the
        // caller replaces any source-modeled field. Under the exclusive owner
        // boundary it cannot need a futex wake.
        drop(quiescent_lock);
        true
    }

    #[inline]
    fn matches_detached_static_fields(&self) -> bool {
        self.thread_id == THREAD_ID_DETACHED
            && self.thread_seq == 0
            && self.numa_node == 0
            && self.subprocess.is_null()
            && self.theaps.is_null()
            && !self.recurse
            && !self.is_in_threadpool
    }

    #[inline]
    fn matches_zero_static_memid(&self, pinned: bool, committed: bool) -> bool {
        let Some(memory) = self.memid.static_memory() else {
            return false;
        };
        self.memid.is_pinned() == pinned
            && self.memid.initially_committed() == committed
            && !self.memid.initially_zero()
            && memory.base.is_null()
            && memory.size == 0
    }

    /// Initializes the complete subprocess-attached/no-theap result of the
    /// bounded `mi_tld_create` adaptation.
    ///
    /// # Safety
    ///
    /// `self` must name the unique fresh-zeroed, properly aligned valid image
    /// for one `ThreadLocalData` metadata request: in particular it must have
    /// the normal direct-helper preimage's abandoned identity, zero sequence
    /// and NUMA node, null pointers, false flags, `MemoryId::none()`, and an
    /// unlocked private list lock. No concurrent observer, lock guard, or
    /// waiter may exist there. `memid` must describe that exact allocation.
    /// The caller must keep the allocation live until the source-ordered
    /// invalidation and metadata release transition completes. This method
    /// installs `memid` before checking that preimage, so those conditions are
    /// a release precondition rather than a debug-only convenience.
    pub(crate) unsafe fn initialize_subprocess_attached_no_theap(
        &mut self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node: i32,
        subprocess: &'static MainSubprocess,
        memid: MemoryId,
    ) {
        // `mi_tld_create` writes this caller-owned provenance before entering
        // the selected normal helper body.  The direct helper deliberately
        // leaves it untouched.
        self.memid = memid;
        let initialized = self.initialize_normal_tld_field_prefix_after_direct_preimage(
            thread_id,
            thread_sequence,
            numa_node,
            subprocess,
        );
        debug_assert!(
            initialized,
            "the unsafe fresh-zeroed TLD contract must satisfy normal mi_tld_init's preimage"
        );
    }

    /// Writes one source-ordered subprocess-attached/no-theap TLD image into
    /// raw storage without first forming a reference to that storage.
    ///
    /// The process-static main-TLD branch begins as `MaybeUninit`, unlike the
    /// metadata branch's known valid all-zero representation. Keeping this
    /// raw initialization boundary avoids manufacturing `&mut ThreadLocalData`
    /// before every field has been initialized.
    ///
    /// # Safety
    ///
    /// `destination` must be fresh uninitialized storage for exactly one TLD,
    /// aligned, writable, and exclusively available. It must not name a prior
    /// TLD image, including an image with a busy private lock: this routine
    /// first overwrites the storage with the direct preimage and therefore
    /// cannot safely preserve or probe a prior lock. No observer may access
    /// the destination until this complete image has been published by its
    /// owner. It first materializes a valid source-zero-shaped static TLD,
    /// installs the outer concrete static `MemoryId` predecessor, and then
    /// invokes the normal `mi_tld_init` body in field order. Its caller
    /// performs the final source live-count registration before that owner
    /// publishes the image.
    #[inline]
    pub(crate) unsafe fn write_subprocess_attached_no_theap_at(
        destination: *mut Self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node_source: impl FnOnce() -> i32,
        subprocess: &'static MainSubprocess,
        memid: MemoryId,
    ) {
        // SAFETY: the caller proves exclusive aligned storage and no observer
        // can reach it before the complete image is installed. The first
        // write constructs a valid Rust object before its ordered field body
        // forms `&mut` storage.
        unsafe {
            destination.write(Self::normal_tld_init_preimage());
            let tld = &mut *destination;
            // This is `mi_tld_create`'s outer provenance predecessor, not a
            // field touched by `mi_tld_init` itself.
            tld.memid = memid;
            let initialized = tld
                .initialize_normal_tld_field_prefix_after_direct_preimage_with_numa_source(
                    thread_id,
                    thread_sequence,
                    numa_node_source,
                    subprocess,
                );
            debug_assert!(
                initialized,
                "fresh raw TLD storage must satisfy the normal mi_tld_init preimage"
            );
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

    /// Detaches one exact auxiliary Theap while deleting its owning
    /// first-class Heap, leaving the current default Theap on this TLD.
    ///
    /// This is the selected single-member form of
    /// `theap.c:_mi_heap_detach_theaps` followed by
    /// `heap.c:mi_heap_free_theaps`: the Heap lock is outermost, the TLD link
    /// is removed first, and the now-TLD-detached member is then removed from
    /// its sole Heap list. Rust Release-clears `theap->heap` after that final
    /// list removal so its typed prefix has no live initialized predicate
    /// before its arena storage is returned; pinned C immediately frees the
    /// raw image at that point and therefore does not need that extra safe-Rust
    /// observation.
    ///
    /// # Safety
    ///
    /// `theap` and `main_default` must be live, address-stable typed Theaps.
    /// `theap` must be owned exclusively by `heap`, be the head of this
    /// TLD's exact auxiliary/default pair, and be the sole member of `heap`'s
    /// Theap list. No concurrent list mutation, guard, or raw alias may exist
    /// for the complete transition.
    #[inline]
    pub(crate) unsafe fn detach_one_auxiliary_theap_for_heap_delete(
        &mut self,
        heap: &mut Heap,
        theap: *mut Theap,
        main_default: *mut Theap,
    ) -> Result<(), ThreadLocalTheapListError> {
        let self_pointer = core::ptr::from_mut(self);
        let heap_pointer = core::ptr::from_mut(heap);
        let heap_guard = heap
            .theaps_lock
            .lock()
            .map_err(|error| ThreadLocalTheapListError::Heap(HeapTheapListError::Lock(error)))?;
        let tld_guard = match self.theaps_lock.try_lock() {
            Some(guard) => guard,
            None => {
                let _ = heap_guard.unlock();
                return Err(ThreadLocalTheapListError::Busy);
            }
        };
        // SAFETY: forwarded from this method's caller. The exact bounded
        // shape is validated before either intrusive list is mutated.
        let valid_member = unsafe {
            !theap.is_null()
                && !main_default.is_null()
                && self.theaps == theap
                && (*theap).tprev.is_null()
                && (*theap).tnext == main_default
                && core::ptr::eq((*theap).tld, self_pointer)
                && (*main_default).tprev == theap
                && (*main_default).tnext.is_null()
                && core::ptr::eq((*main_default).tld, self_pointer)
                && heap.theaps == theap
                && (*theap).hprev.is_null()
                && (*theap).hnext.is_null()
                && core::ptr::eq((*theap).heap.load(Ordering::Acquire), heap_pointer)
        };
        if !valid_member {
            let _ = tld_guard.unlock();
            let _ = heap_guard.unlock();
            return Err(ThreadLocalTheapListError::Membership);
        }

        // SAFETY: the validated member is the current TLD head. This is the
        // source heap-delete ordering: erase the TLD relation before the
        // enclosing Heap's final list removal.
        unsafe {
            self.theaps = (*theap).tnext;
            if !(*theap).tnext.is_null() {
                (*(*theap).tnext).tprev = null_mut();
            }
            (*theap).tnext = null_mut();
            (*theap).tprev = null_mut();
            (*theap).tld = null_mut();
        }
        tld_guard.unlock().map_err(ThreadLocalTheapListError::Lock)?;

        // SAFETY: the held Heap lock and preceding exact-member check prove
        // this is the only Heap-list member. The Release clear is the
        // explicit Rust typed-prefix retirement noted above.
        unsafe {
            heap.theaps = null_mut();
            (*theap).hnext = null_mut();
            (*theap).hprev = null_mut();
            (*theap).heap.store(null_mut(), Ordering::Release);
        }
        heap_guard
            .unlock()
            .map_err(|error| ThreadLocalTheapListError::Heap(HeapTheapListError::Lock(error)))
    }

    /// Performs the finite two-member heap-list pass used only by the M1
    /// compiler-TLS terminal differential fixture.
    ///
    /// The pinned `mi_thread_theaps_done` path first leaves its TLD list
    /// intact, then `_mi_tld_detach_theaps` walks each member and
    /// Release-clears its owning Heap pointer.  The normal one-Theap owners
    /// above intentionally cannot express that intermediate `aux -> main`
    /// TLD list.  This test-only helper accepts exactly that page-free pair:
    /// the Malloc auxiliary cached Theap is the head and the process-static
    /// default Theap is its sole tail.  It is not a general multi-Theap API
    /// or a claim about source contention/retry behavior.
    #[cfg(test)]
    #[inline]
    pub(crate) fn m1_detach_cached_aux_and_main_from_heaps(
        &mut self,
        cached_aux: *mut Theap,
        cached_aux_heap: &mut Heap,
        main_default: *mut Theap,
        main_heap: &mut Heap,
    ) -> Result<(), ThreadLocalTheapListError> {
        if cached_aux.is_null()
            || main_default.is_null()
            || core::ptr::eq(cached_aux, main_default)
            || core::ptr::eq(cached_aux_heap, main_heap)
        {
            return Err(ThreadLocalTheapListError::Membership);
        }
        let self_pointer = core::ptr::from_mut(self);
        let guard = self
            .theaps_lock
            .lock()
            .map_err(ThreadLocalTheapListError::Lock)?;
        // SAFETY: the M1 composite retains the two typed Theap allocations
        // and both address-stable Heap images. The exact list shape is
        // checked before either Heap list is changed, mirroring the saved
        // `tnext` traversal in `_mi_tld_detach_theaps`.
        let valid_pair = unsafe {
            self.theaps == cached_aux
                && (*cached_aux).tprev.is_null()
                && (*cached_aux).tnext == main_default
                && (*main_default).tprev == cached_aux
                && (*main_default).tnext.is_null()
                && core::ptr::eq((*cached_aux).tld, self_pointer)
                && core::ptr::eq((*main_default).tld, self_pointer)
                && core::ptr::eq(
                    (*cached_aux).heap.load(Ordering::Acquire),
                    core::ptr::from_mut(cached_aux_heap),
                )
                && core::ptr::eq(
                    (*main_default).heap.load(Ordering::Acquire),
                    core::ptr::from_mut(main_heap),
                )
        };
        if !valid_pair {
            let _ = guard.unlock();
            return Err(ThreadLocalTheapListError::Membership);
        }
        // The source takes each Heap lock while the TLD list is still live.
        // This fixture has no competing owner, so the blocking form supplies
        // the same successful lock order without inventing retry coverage.
        cached_aux_heap
            .detach_one_theap_under_tld_lock_blocking(cached_aux)
            .map_err(ThreadLocalTheapListError::Heap)?;
        main_heap
            .detach_one_theap_under_tld_lock_blocking(main_default)
            .map_err(ThreadLocalTheapListError::Heap)?;
        guard.unlock().map_err(ThreadLocalTheapListError::Lock)
    }

    /// Completes the finite M1 fixture's TLD-list/final-reference pass only
    /// after its complete heap-list pass.
    ///
    /// This mirrors `mi_thread_theaps_done`'s terminal loop precisely enough
    /// for the selected two-node trace: take the list head, publish
    /// `tld->theaps = NULL`, clear and observe/decref cached auxiliary A,
    /// then clear and observe/decref static default D. The observers run just
    /// before their respective Rust final-reference operations, corresponding
    /// to the C wrapper immediately before `_mi_theap_decref`. The Malloc
    /// metadata capability itself is released by the owning fixture after
    /// this source-shaped list pass, not under this list lock.
    #[cfg(test)]
    #[inline]
    pub(crate) fn m1_finish_cached_aux_and_main_tld(
        &mut self,
        cached_aux: *mut Theap,
        main_default: *mut Theap,
        before_cached_aux_decref: impl FnOnce(&Theap),
        before_main_default_decref: impl FnOnce(&Theap),
    ) -> Result<(bool, bool), ThreadLocalTheapListError> {
        if cached_aux.is_null()
            || main_default.is_null()
            || core::ptr::eq(cached_aux, main_default)
        {
            return Err(ThreadLocalTheapListError::Membership);
        }
        let self_pointer = core::ptr::from_mut(self);
        let guard = self
            .theaps_lock
            .lock()
            .map_err(ThreadLocalTheapListError::Lock)?;
        // SAFETY: the preceding exact heap pass Release-cleared both heap
        // pointers while retaining this unchanged two-member TLD list.
        let valid_pair = unsafe {
            self.theaps == cached_aux
                && (*cached_aux).tprev.is_null()
                && (*cached_aux).tnext == main_default
                && (*main_default).tprev == cached_aux
                && (*main_default).tnext.is_null()
                && (*cached_aux).heap.load(Ordering::Acquire).is_null()
                && (*main_default).heap.load(Ordering::Acquire).is_null()
                && core::ptr::eq((*cached_aux).tld, self_pointer)
                && core::ptr::eq((*main_default).tld, self_pointer)
        };
        if !valid_pair {
            let _ = guard.unlock();
            return Err(ThreadLocalTheapListError::Membership);
        }
        // SAFETY: `valid_pair` proves both raw nodes stay live and have no
        // other neighbors. Source clears the list head before its saved-next
        // traversal; preserve the separate A then D link-clear/final-release
        // order rather than coalescing both nodes into one Rust operation.
        unsafe {
            self.theaps = null_mut();
            (*cached_aux).tld = null_mut();
            (*cached_aux).tnext = null_mut();
            (*cached_aux).tprev = null_mut();
        }
        // SAFETY: A remains owned by the M1 fixture. Its TLD/heap/list links
        // now exactly match the source pre-decref assertion state.
        let cached_cleared = unsafe {
            before_cached_aux_decref(&*cached_aux);
            (&mut *cached_aux).clear_dynamic_metadata_after_detach()
        };
        // SAFETY: D remains the static fixture image; A's former pointer in
        // D's tprev is cleared before D is observed/released just as in the
        // source saved-next loop.
        let main_cleared = unsafe {
            (*main_default).tld = null_mut();
            (*main_default).tnext = null_mut();
            (*main_default).tprev = null_mut();
            before_main_default_decref(&*main_default);
            (&mut *main_default).clear_main_static_after_detach()
        };
        guard.unlock().map_err(ThreadLocalTheapListError::Lock)?;
        Ok((cached_cleared, main_cleared))
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
    /// `mi_heap_main_init_once` uses this kind-only provenance for its static
    /// detached TLD, process heap, and detached metadata Theap. It
    /// deliberately does not claim concrete image extent, pinning, or initial
    /// commitment; `_mi_memid_create_static` is separate.
    #[inline]
    pub(crate) const fn static_kind_only() -> Self {
        Self::empty_with_kind(MemoryKind::Static)
    }

    /// Creates the exact null/zero-extent `MI_MEMID_STATIC` initializer.
    ///
    /// The pinned macro records immutable static storage as pinned and
    /// initially committed even when its union is null and its extent is zero.
    /// `src/init.c` uses this image for `mi_page_empty`, `mi_tld_detached`, and
    /// `_mi_theap_empty`. It is intentionally distinct from
    /// `_mi_memid_create(MI_MEM_STATIC)` ([`Self::static_kind_only`]) and from
    /// concrete `_mi_memid_create_static` storage ([`Self::static_allocation`]).
    #[inline]
    pub(crate) const fn static_empty() -> Self {
        Self {
            info: MemoryInfo {
                os: OsMemory {
                    base: null_mut(),
                    size: 0,
                },
            },
            kind: MemoryKind::Static,
            is_pinned: true,
            initially_committed: true,
            initially_zero: false,
        }
    }

    /// Reads the selected `MI_MEMID_STATIC` union image for the static-image
    /// C/Rust oracle. The source macro initializes its union as `{ NULL, 0 }`;
    /// this Rust constructor deliberately uses the matching `os` arm. Keep
    /// the union projection test-only so production provenance APIs remain
    /// kind-specific rather than exposing raw union state.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_static_empty_info(&self) -> (bool, usize) {
        // SAFETY: `static_empty` initializes this union through the `os` arm,
        // and the only callers are the immutable static-image witnesses.
        let os = unsafe { self.info.os };
        (os.base.is_null(), os.size)
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
pub(super) struct PageFreeListState {
    pub(super) area: NonNull<u8>,
    pub(super) area_bytes: usize,
    pub(super) block_size: usize,
    pub(super) capacity: NonNull<u16>,
    pub(super) reserved: u16,
    pub(super) free: NonNull<*mut Block>,
    pub(super) local_free: NonNull<*mut Block>,
    pub(super) used: NonNull<usize>,
    pub(super) free_is_zero: NonNull<bool>,
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
#[derive(Clone, Copy)]
pub(super) struct PageRemoteFreeProducerState {
    pub(super) xthread_id: NonNull<AtomicUsize>,
    pub(super) xthread_free: NonNull<AtomicUsize>,
}

// SAFETY: this projection grants access only to two initialized atomic
// subobjects of one stable live `Page`. Constructing it is unsafe and carries
// the page-lifetime obligation documented by
// `Page::remote_free_producer_state_at`; moving a copy to a producer thread
// grants no access to any owner-only ordinary field.
unsafe impl Send for PageRemoteFreeProducerState {}

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
/// Unlike [`PageFreeListState`], this projects initialized capacity by value.
/// Both forms carry raw field pointers and never create a whole-page mutable
/// reference. Later queue transitions likewise use raw intrusive-link
/// subobject operations. The caller remains responsible for the live-page,
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
        heap: &Heap,
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
        heap: &Heap,
        owner: TheapOwner,
    ) {
        debug_assert!(theap.matches_owner(owner));
        self.theap = core::ptr::from_mut(theap);
        // A fresh page records this address but does not mutate its Heap.
        // Heap-list and arena-pages changes retain their own synchronized
        // source boundaries, so this association must not manufacture an
        // exclusive Rust projection of the process-static main Heap.
        self.heap = core::ptr::from_ref(heap).cast_mut();
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
        heap: &Heap,
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
        heap: &Heap,
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
        heap: &Heap,
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
        heap: &Heap,
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

    /// Whether the source owner-exit force collector can leave this page with
    /// an immediately reusable local free block.
    ///
    /// Normal local frees first enter `local_free`; `_mi_theap_collect_abandon`
    /// force-collects that list into `free` before it decides whether a live
    /// page can be abandoned. This boolean is therefore meaningful only while
    /// the caller still owns the page's exclusive source lifecycle. It does
    /// not expose either list address or grant post-exit reclamation authority.
    #[inline]
    pub(crate) const fn has_owner_exit_collectable_local_free(&self) -> bool {
        !self.free.is_null() || !self.local_free.is_null()
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

    /// Records a committed on-demand prefix through only its owner field.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized live metadata. The caller must own
    /// `slice_pcommitted`, have committed the complete old-to-new prefix, and
    /// preserve immutable page geometry. Concurrent live clients may access
    /// their distinct current blocks and only their disjoint remote-free
    /// atomic projection within Page metadata.
    #[inline]
    pub(super) unsafe fn set_slice_pcommitted_after_commit_at(
        page: NonNull<Self>,
        next: u16,
    ) -> bool {
        // SAFETY: caller proves `page` names stable initialized metadata; this
        // derives only the ordinary prefix-count subobject address.
        let field = unsafe {
            core::ptr::addr_of_mut!((*page.as_ptr()).slice_pcommitted)
        };
        // SAFETY: caller proves this initialized owner-only subobject remains
        // stable and grants exclusive access for the transition.
        let current = unsafe { core::ptr::read(field) };
        if current == 0 || next == 0 || next < current {
            return false;
        }
        // SAFETY: same caller proof grants the exact ordinary-field write.
        unsafe { core::ptr::write(field, next) };
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

    /// Writes the owner-only retirement countdown without borrowing the
    /// complete live page.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized metadata whose owning theap grants
    /// the caller exclusive access to `retire_expire`. The page may have live
    /// clients retaining only the disjoint remote-free atomic projection; no
    /// other access to this ordinary byte may overlap the write.
    #[inline]
    pub(super) unsafe fn set_retire_expire_at(page: NonNull<Self>, retire_expire: u8) {
        // SAFETY: the caller owns this exact ordinary subobject and the raw
        // projection creates no whole-page mutable reference.
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!((*page.as_ptr()).retire_expire),
                retire_expire,
            )
        };
    }

    /// Reads the owner-only live allocation count without borrowing the
    /// complete page.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized metadata whose current source owner
    /// exclusively controls `used`. A valid remote producer may concurrently
    /// retain only its disjoint atomic projection; it must not read or write
    /// this ordinary field. The caller must not use a zero result to retire or
    /// reuse metadata until it has completed the matching source collection
    /// and queue-detach proof.
    #[inline]
    pub(super) unsafe fn owner_used_at(page: NonNull<Self>) -> usize {
        // SAFETY: the caller supplies the exact ordinary-field ownership and
        // lifetime proof; this raw read creates no whole-page reference.
        unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).used)) }
    }

    /// Reads the owner-only retirement countdown without borrowing a whole
    /// live page.
    ///
    /// # Safety
    ///
    /// `page` must be stable initialized metadata whose owner exclusively
    /// controls the ordinary retirement byte. Concurrent remote producers may
    /// retain only the page's atomic producer projection.
    #[inline]
    pub(super) unsafe fn retire_expire_at(page: NonNull<Self>) -> u8 {
        // SAFETY: same caller proof as `owner_used_at`; this is a raw
        // subobject projection rather than an immutable page borrow.
        unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).retire_expire)) }
    }

    /// Reads one queue successor through its raw intrusive-link subobject.
    ///
    /// # Safety
    ///
    /// `page` must be a stable initialized member of a queue whose links the
    /// caller exclusively owns. A remote producer may retain only disjoint
    /// page atomics and must never access queue links.
    #[inline]
    pub(super) unsafe fn queue_next_at(page: NonNull<Self>) -> *mut Self {
        // SAFETY: the caller owns this exact intrusive-link subobject.
        unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).next)) }
    }

    /// Reads one queue predecessor through its raw intrusive-link subobject.
    ///
    /// # Safety
    ///
    /// Same as [`Self::queue_next_at`].
    #[inline]
    pub(super) unsafe fn queue_prev_at(page: NonNull<Self>) -> *mut Self {
        // SAFETY: the caller owns this exact intrusive-link subobject.
        unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).prev)) }
    }

    /// Projects only the source atomic fields that a remote producer may use.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized metadata that remains live while a
    /// returned producer state can be used. A current allocation may provide
    /// that lifetime: its still-counted source `used` contribution prevents
    /// final page release until its remote publication reaches
    /// `xthread_free`. Page abandonment may race that publication, but reuse
    /// and final release may not. Remote producer code itself must not inspect
    /// any non-atomic page field, and a producer that claims an abandoned low
    /// owner bit must complete the corresponding source owner protocol.
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

    /// Returns whether the remote-free atomic is in the exact live-owner,
    /// empty-list state used by a sealed owner-exit preflight.
    ///
    /// This is an observation only: it neither claims the source owner bit nor
    /// detaches a remote list. The caller must keep the page metadata live and
    /// exclude a concurrent producer for the complete transition that follows.
    #[inline]
    pub(crate) fn remote_free_head_is_owner_only(&self) -> bool {
        self.xthread_free.load(Ordering::Acquire) == 1
    }

    /// Recovers the source free-list block for one exact live client held by
    /// a remote producer.
    ///
    /// Pinned `mi_free_generic_mt` makes this same distinction before it
    /// calls `mi_free_block_mt`: a page-wide atomic flag says whether a
    /// client may begin inside its source block, while `page_offset` and
    /// `block_size` remain fixed for the whole lifetime of that page. This
    /// raw projection deliberately creates no `Page` reference, so it can be
    /// used beside an owning thread's ordinary-page mutation and the remote
    /// producer subsequently retains only the atomic free-head capability.
    ///
    /// # Safety
    ///
    /// `page` must name initialized metadata for the live page containing
    /// `client`. `client` must be an exact current allocation from that page,
    /// and its allocation lifetime must keep the page registered, associated,
    /// and unreused through the returned block's eventual remote publication.
    /// The caller may not use this to inspect an arbitrary pointer or a
    /// detached/abandoned page.
    #[inline]
    pub(super) unsafe fn canonical_remote_block_for_live_client_at(
        page: NonNull<Self>,
        client: NonNull<u8>,
    ) -> Option<NonNull<u8>> {
        let page = page.as_ptr();
        // SAFETY: the caller keeps the initialized live page stable. This
        // forms a reference only to the source atomic flag, never to `Page`.
        let xthread_id = unsafe { &*core::ptr::addr_of!((*page).xthread_id) };
        if xthread_id.load(Ordering::Relaxed) & PAGE_HAS_INTERIOR_POINTERS == 0 {
            return Some(client);
        }

        // SAFETY: source `mi_free_generic_mt` relies on these immutable page
        // geometry fields while the exact live client keeps the page from
        // release or reuse. Derive only the source block-area address and do
        // not manufacture a shared `Page` reference.
        let page_offset = unsafe { (*page).page_offset };
        let block_size = unsafe { (*page).block_size };
        let page_start = unsafe { page.cast::<u8>().add(page_offset) };
        let base_address = crate::aligned::recover_block_start(
            client.as_ptr().addr(),
            page_start.addr(),
            block_size,
        )?;
        let adjustment = client.as_ptr().addr().checked_sub(base_address)?;
        NonNull::new(client.as_ptr().wrapping_sub(adjustment))
    }

    /// Projects the raw owner fields used after remote detach by the
    /// false-force local half of `_mi_page_free_collect`.
    ///
    /// This is deliberately separate from [`Self::local_free_list_state_at`]:
    /// the latter includes mutable capacity, while this narrow collection
    /// step projects the already-initialized capacity by value. Neither
    /// projection manufactures a whole-page reference. Later queue transitions
    /// likewise project only owner-controlled intrusive links, so valid live
    /// clients may retain or use only the disjoint producer atomics. The raw
    /// free-list boundary can select either the false-force transfer or the
    /// force-only local-list append; no projection itself grants a queue,
    /// abandonment, or owner-exit transition.
    ///
    /// # Safety
    ///
    /// `page` must be live initialized metadata for an owner matching
    /// `expected_thread`: `Some` requires that exact live thread identity,
    /// while `None` requires the explicit detached owner. The caller must
    /// exclusively own the ordinary fields below and keep the page plus its
    /// complete block area live until the collection completes; it must not
    /// detach, retire, reuse, or release the page. A live owner may have
    /// other threads accessing distinct current blocks and retaining only
    /// [`Self::remote_free_producer_state_at`] within Page metadata; those
    /// threads may not touch the ordinary fields. The detached branch instead
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

    /// Projects the false-force local-list state after an abandoned-page
    /// remote publication has claimed the source low bit.
    ///
    /// This is deliberately distinct from
    /// [`Self::local_collect_state_for_owner_at`]: thread exit may retain a
    /// raw former `theap` pointer for source comparison, but no post-exit path
    /// may read or dereference it. The held low bit and either abandoned
    /// identity are the complete authority for this narrow local-list phase.
    ///
    /// # Safety
    ///
    /// `page` must be initialized abandoned metadata whose `xthread_free`
    /// owner bit is held by the caller. The caller must own the ordinary
    /// free/local-free/used fields and retain the complete page area through
    /// the following `collect_local_false` operation. It must not retire,
    /// reuse, or release the page during that operation.
    #[inline]
    pub(super) unsafe fn abandoned_local_collect_state_at(
        page: NonNull<Self>,
    ) -> Option<PageLocalCollectState> {
        let page = page.as_ptr();
        // SAFETY: the caller retains the initialized atomic remote-head field
        // until this post-claim local collection has finished.
        let xthread_free = unsafe { &*core::ptr::addr_of!((*page).xthread_free) };
        if xthread_free.load(Ordering::Acquire) & 1 == 0 {
            return None;
        }
        // SAFETY: read only the atomic source identity. No former Theap is
        // projected here, even as a null/equality check.
        let thread_id = unsafe { &*core::ptr::addr_of!((*page).xthread_id) }
            .load(Ordering::Acquire)
            & !PAGE_FLAG_MASK;
        if !matches!(thread_id, THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED) {
            return None;
        }

        // SAFETY: the held source owner bit gives the caller the exact
        // ordinary-field authority for the false-force local transfer.
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
        // SAFETY: the caller's complete-page-area proof makes this exact
        // source start address valid for the local-list transfer.
        let area = unsafe { NonNull::new_unchecked(page.cast::<u8>().add(page_offset)) };
        Some(PageLocalCollectState {
            area,
            area_bytes,
            block_size,
            capacity,
            reserved,
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

    /// Projects exactly the local free-list fields used by the source owner.
    ///
    /// # Safety
    ///
    /// `page` must name stable initialized metadata. The caller must
    /// exclusively own its ordinary local-list fields. `page_offset` bytes
    /// from this metadata address must begin a live writable allocation of
    /// exactly `reserved * block_size` bytes, with nonzero `block_size` and
    /// `reserved`; the multiplication and resulting pointer range must not
    /// overflow. The page must be associated with the caller's live theap.
    ///
    /// Block-area access follows the source allocation partition rather than
    /// granting exclusivity over the entire area: the owner may access link
    /// words only in blocks already on its local lists, newly extended
    /// unallocated blocks, the exact block being freed locally, or the exact
    /// block selected until `pop` returns it to the client. A remote producer
    /// may concurrently write the link word of its own distinct current
    /// allocation and access only [`Self::remote_free_producer_state_at`]. No
    /// page-map, queue-retirement, or other owner operation may mutate the
    /// projected ordinary fields while this state is used, and no whole
    /// mutable `Page` reference may coexist with either projection's access.
    /// Every list pointer must remain null or name an aligned owner-accessible
    /// block inside the area.
    #[inline]
    pub(super) unsafe fn local_free_list_state_at(
        page: NonNull<Self>,
    ) -> PageFreeListState {
        let page = page.as_ptr();
        // SAFETY: the caller proves initialized stable metadata and immutable
        // live-page geometry for this owner operation.
        let block_size = unsafe { (*page).block_size };
        let reserved = unsafe { (*page).reserved };
        let page_offset = unsafe { (*page).page_offset };
        debug_assert!(block_size != 0);
        debug_assert!(reserved != 0);
        // SAFETY: the caller's live-area contract proves that advancing from
        // this page metadata address by `page_offset` remains in bounds and
        // produces the beginning of its writable block area.
        let area = unsafe { page.cast::<u8>().add(page_offset) };
        // SAFETY: the live-area contract also proves the returned area pointer
        // is non-null and valid for the derived byte count.
        let area = unsafe { NonNull::new_unchecked(area) };
        // SAFETY: the same caller contract proves this source field product
        // does not overflow and identifies the complete page block area.
        let area_bytes = unsafe { usize::from(reserved).unchecked_mul(block_size) };

        PageFreeListState {
            area,
            area_bytes,
            block_size,
            // SAFETY: these raw pointers name only the caller-owned ordinary
            // subobjects and manufacture no whole-page reference.
            capacity: unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).capacity))
            },
            reserved,
            free: unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free)) },
            local_free: unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).local_free))
            },
            used: unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).used)) },
            free_is_zero: unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*page).free_is_zero))
            },
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

    /// Returns the fixed synthetic page reservation used by the abandoned
    /// free protocol tests. This exposes no production allocator state: the
    /// test fixture owns the page metadata exclusively.
    #[cfg(test)]
    #[inline]
    pub(crate) const fn remote_free_test_reserved(&self) -> u16 {
        self.reserved
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

    /// Whether a joined producer has published at least one remote block to
    /// this live page's source `mi_thread_free_t` head.
    ///
    /// This reads only the atomic head representation. Callers that use it to
    /// select an owner-side collection transition must separately prove that
    /// the page remains live and that no producer can publish concurrently
    /// with the following non-atomic queue/page mutation.
    #[inline]
    pub(crate) fn has_published_remote_free(&self) -> bool {
        // `mi_thread_free_t` reserves its low bit for ownership; every other
        // bit is the aligned remote-block address.
        self.xthread_free.load(Ordering::Acquire) & !1 != 0
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

// `src/init.c:mi_tld_detached`'s pre-process-initialization source image. C
// later mutates that object in `mi_heap_main_init_once`; the Rust bootstrap
// instead owns a separate live TLD after pinning. Dynamic TLD fields contain
// raw pointers and therefore must not grant a blanket `Sync` implementation
// to `ThreadLocalData`; this wrapper grants it only to this never-mutated
// source-image witness. Keeping it separate is what lets the initial empty
// theap avoid any TLS access.
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

    /// Records the kind-only static provenance that
    /// `mi_heap_main_init_once` assigns to `mi_process_theap_meta` before
    /// `_mi_theap_init` copies the immutable empty image.
    ///
    /// This is deliberately distinct from [`Self::set_main_static_memid`]:
    /// the source uses `_mi_memid_create(MI_MEM_STATIC)`, not the pinned,
    /// initially-committed concrete-static-image provenance. It accepts only
    /// the untouched `Theap::empty` static image before heap publication.
    #[inline]
    fn set_detached_main_metadata_static_memid(&mut self) -> bool {
        let Some(static_memory) = self.memid.static_memory() else {
            return false;
        };
        if self.is_initialized()
            || !self.memid.is_pinned()
            || !self.memid.initially_committed()
            || self.memid.initially_zero()
            || !static_memory.base.is_null()
            || static_memory.size != 0
        {
            return false;
        }
        self.memid = MemoryId::static_kind_only();
        true
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

    /// Records the exact requested-parent `MI_MEM_ARENA` provenance returned
    /// by `_mi_theap_alloc` before `_mi_theap_init` copies the empty image.
    ///
    /// This deliberately accepts either source pin observation and either
    /// zero observation: an external parent arena may be pinned, and a
    /// previously returned slice is expected to be dirty. The exact live
    /// arena/slice identity remains in `memid`; only committed arena storage
    /// can hold this typed Rust prefix.
    #[inline]
    pub(crate) fn set_requested_arena_metadata_memid(&mut self, memid: MemoryId) -> bool {
        let Some(arena) = memid.arena_memory() else {
            return false;
        };
        if self.is_initialized()
            || memid.kind() != MemoryKind::Arena
            || !memid.initially_committed()
            || arena.arena.is_null()
            || arena.slice_count as usize != crate::config::ARENA_MIN_OBJ_SLICES
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
            || tld.is_in_threadpool()
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

    /// Initializes the one Malloc-backed cached Theap in the finite M1
    /// same-TLD terminal fixture.
    ///
    /// Pinned `mi_heap_new` can attach an auxiliary Theap to the current
    /// thread's already-live process TLD.  In the selected fixture that TLD
    /// has exactly one existing member: the process-static default Theap.
    /// The normal dynamic initializer deliberately rejects that shape so its
    /// ordinary owner cannot accidentally form a multi-Theap list.  Keep this
    /// test-only entry narrow instead of weakening that production boundary.
    /// It preserves `_mi_theap_init`'s ordering for the auxiliary image:
    /// Malloc provenance, empty image, TLD/subprocess/refcount, TLD-list
    /// head insertion and random split, Release heap publication, then the
    /// auxiliary Heap list.
    ///
    /// # Safety
    ///
    /// `heap`, `tld`, and `main_default` must be the exact address-stable
    /// page-free fixture images. The caller retains the Malloc metadata
    /// capability for `self`, owns both list mutations, and must tear the
    /// pair down through the matching M1 helper before releasing either
    /// image.
    #[cfg(test)]
    #[inline]
    pub(crate) unsafe fn initialize_m1_cached_aux_on_main_tld(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
        main_default: *mut Theap,
    ) -> Result<(), TheapDynamicInitError> {
        // SAFETY: forwarded unchanged to the shared selected-default-TLD
        // initializer. This test-only caller retains the Malloc capability.
        unsafe {
            self.initialize_auxiliary_on_main_tld(
                heap,
                tld,
                main_default,
                MemoryKind::Malloc,
            )
        }
    }

    /// Initializes the selected requested-parent Arena Theap prefix on the
    /// already-live default TLD used by `heap.c:mi_heap_init_theap`.
    ///
    /// This is the `_mi_theap_create(heap, mi_theap_get_default()->tld)`
    /// prefix through TLD-list insertion, random split, Release heap
    /// publication, and Heap-list insertion. The outer caller's regular TLS
    /// slot and cached-root update happen later in `heap.c` and intentionally
    /// remain outside this owner. The Rust type is only the source prefix;
    /// this method makes no claim about the C statistics tail.
    ///
    /// # Safety
    ///
    /// `heap`, `tld`, and `main_default` must be the exact address-stable,
    /// current-thread source images. `self` must occupy the selected Arena
    /// slice named by its `MemoryId`, and its linear owner must detach both
    /// lists, clear the prefix, and return that exact slice through the
    /// selected subprocess before any image is retired.
    #[inline]
    pub(crate) unsafe fn initialize_requested_arena_on_main_tld(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
        main_default: *mut Theap,
    ) -> Result<(), TheapDynamicInitError> {
        let Some(arena) = self.memid.arena_memory() else {
            return Err(TheapDynamicInitError::InvalidInput);
        };
        if self.memid.kind() != MemoryKind::Arena
            || !self.memid.initially_committed()
            || arena.arena.is_null()
            || heap.exclusive_arena != arena.arena
        {
            return Err(TheapDynamicInitError::InvalidInput);
        }
        // SAFETY: forwarded unchanged; the arena-specific precondition above
        // keeps the Malloc-only dynamic route separate from this source arm.
        unsafe {
            self.initialize_auxiliary_on_main_tld(heap, tld, main_default, MemoryKind::Arena)
        }
    }

    /// Shared `_mi_theap_init` prefix for the two deliberately bounded
    /// existing-default-TLD auxiliary owners. Callers select a concrete
    /// provenance kind before entry; this helper never broadens the normal
    /// Malloc dynamic API into generic metadata ownership.
    unsafe fn initialize_auxiliary_on_main_tld(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
        main_default: *mut Theap,
        memory_kind: MemoryKind,
    ) -> Result<(), TheapDynamicInitError> {
        let tld_pointer = core::ptr::from_mut(tld);
        // SAFETY: this is only an entry witness; no field is mutated until
        // every relation of the existing static one-member list is checked.
        let valid_main_tail = unsafe {
            !main_default.is_null()
                && tld.theaps == main_default
                && (*main_default).tprev.is_null()
                && (*main_default).tnext.is_null()
                && core::ptr::eq((*main_default).tld, tld_pointer)
                && !(*main_default).heap.load(Ordering::Acquire).is_null()
                && (*main_default).memid.kind() == MemoryKind::Static
                && (*main_default).refcount.load(Ordering::Acquire) == 1
                && core::ptr::eq(
                    (*main_default).subproc.load(Ordering::Acquire),
                    tld.subprocess,
                )
        };
        if self.is_initialized()
            || self.memid.kind() != memory_kind
            || !valid_main_tail
            || !tld.matches_owner(TheapOwner::Live(
                LiveThreadId::new(tld.thread_id()).ok_or(TheapDynamicInitError::InvalidInput)?,
            ))
            || tld.is_in_threadpool()
            || heap.subprocess.is_null()
            || !core::ptr::eq(heap.subprocess, tld.subprocess)
        {
            return Err(TheapDynamicInitError::InvalidInput);
        }

        let memid = self.memid;
        let replaced = core::mem::replace(self, Self::empty());
        drop(replaced);
        self.memid = memid;
        self.tld = tld_pointer;
        self.refcount.store(1, Ordering::Release);
        self.subproc.store(heap.subprocess, Ordering::Release);
        self.allow_page_reclaim = true;
        self.allow_page_abandon = true;
        self.page_full_retain = 2;
        self.is_detached = false;

        let self_pointer = core::ptr::from_mut(self);
        let head_random = tld
            .attach_one_theap(self_pointer)
            .map_err(TheapDynamicInitError::ThreadList)?;
        let Some(mut head_random) = head_random else {
            // The validated main tail is a member, so source must split its
            // initialized random image into the new head. Treat an impossible
            // empty result as an invalid fixture rather than silently making
            // this a second independent initialization path.
            return Err(TheapDynamicInitError::InvalidInput);
        };
        head_random.split_into(&mut self.random);
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
        self.clear_metadata_after_detach(MemoryKind::Malloc)
    }

    /// Clears the final requested-parent Arena Theap prefix after both
    /// intrusive lists detached. Its linear arena owner then drops this Rust
    /// prefix and returns the exact selected slice; there is no generic
    /// `MetaAllocator` or `_mi_meta_free` dispatcher claim here.
    #[inline]
    pub(crate) fn clear_requested_arena_after_detach(&mut self) -> bool {
        if !self.metadata_prefix_is_detached(MemoryKind::Arena) {
            return false;
        }
        // `_mi_theap_decref` first performs the final 1 -> 0 transition and
        // only then enters `_mi_theap_free_mem`, which still reads `subproc`
        // to account for/free the raw image. `mi_heap_free_theaps` also merges
        // the complete C statistics tail before that call. Rust has neither
        // those statistics transitions nor a generic metadata dispatcher in
        // this narrow prefix owner, but retains `subproc` through its
        // equivalent final transition rather than clearing it early as the
        // Malloc-specific typed-release route does.
        if self.refcount.fetch_sub(1, Ordering::AcqRel) != 1 {
            return false;
        }
        // Manual raw-slice release does not invoke Rust Drop until after this
        // method, so zeroize the prefix-local random state now. The subsequent
        // `TheapRandomImage::Drop` is deliberately idempotent.
        self.random.clear();
        self.cookie = 0;
        true
    }

    /// Common final prefix clear for ownership-specific metadata routes.
    /// Keeping the expected kind explicit ensures a Malloc caller cannot
    /// accidentally release an Arena slice, or vice versa.
    #[inline]
    fn clear_metadata_after_detach(&mut self, memory_kind: MemoryKind) -> bool {
        if !self.metadata_prefix_is_detached(memory_kind) {
            return false;
        }
        self.random.clear();
        self.cookie = 0;
        self.subproc.store(null_mut(), Ordering::Release);
        self.refcount
            .fetch_sub(1, Ordering::AcqRel)
            == 1
    }

    #[inline]
    fn metadata_prefix_is_detached(&self, memory_kind: MemoryKind) -> bool {
        self.heap.load(Ordering::Acquire).is_null()
            && self.tld.is_null()
            && self.tnext.is_null()
            && self.tprev.is_null()
            && self.hnext.is_null()
            && self.hprev.is_null()
            && self.memid.kind() == memory_kind
            && self.refcount.load(Ordering::Acquire) == 1
    }

    /// Acquires the one cached-root reference for a live dynamic attachment.
    ///
    /// This is deliberately not a general Theap refcount API. Its sole
    /// production caller, `DynamicTheapAttachment`, and the exact `cfg(test)`
    /// M1 same-TLD fixture each source-order the compiler-TLS cached-root
    /// store from the canonical empty Theap to this exact Malloc-backed image
    /// and retain exclusive current-thread/lifecycle ownership until they
    /// reverse that store. The exact 1 -> 2 CAS turns a violated
    /// owner/refcount invariant into a retained terminal state rather than
    /// silently composing with an unknown reference.
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
    /// [`Self::acquire_dynamic_cached_reference`] for the production dynamic
    /// owner and the exact `cfg(test)` M1 fixture; any other count is an
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
    /// theap. It accepts only the source-state subset required for this
    /// bounded Linux/AArch64 first-head branch: a matching subprocess
    /// identity, an empty theap head, and no thread-pool option adjustment.
    /// [`crate::bootstrap::ExclusiveTheapBootstrap`] establishes the fuller
    /// detached `mi_tld_init` image. A nonempty source head takes
    /// `_mi_random_split`; that unported list/split path is rejected before
    /// any field mutation rather than being misrepresented as first-head
    /// initialization. The pinned bootstrap owns this Theap's stable address
    /// while its random image is initialized. Callers serialize every mutation
    /// with the metadata private lock and must never route remote frees or
    /// abandonment through this theap.
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
        if owner.is_detached()
            && (!tld.is_subprocess_attached_no_theap()
                || !core::ptr::eq(heap.subprocess, tld.subprocess)
                || tld.is_in_threadpool())
        {
            // `theap.c:_mi_theap_init` initializes a new random image only
            // for `head == NULL`; a nonempty head is a distinct, locked
            // snapshot-and-split route. This bounded bootstrap additionally
            // pairs the detached TLD with its same-subprocess private Heap
            // and excludes the source thread-pool retain adjustment. It
            // models only that fresh `mi_tld_init` checkpoint, so reject
            // instead of inventing a split or mutating provenance before an
            // incompatible bounded owner can publish it.
            return false;
        }

        if owner.is_detached() && !self.set_detached_main_metadata_static_memid() {
            return false;
        }

        self.tld = core::ptr::from_mut(tld);
        self.refcount.store(1, core::sync::atomic::Ordering::Release);
        self.subproc
            .store(heap.subprocess, core::sync::atomic::Ordering::Release);
        // `theap.c:mi_theap_options_init` snapshots the frozen normal-release
        // `mi_option_page_reclaim_on_free == 0` as enabled before the heap
        // Release publication. The detached metadata special case changes
        // abandonment below, not this reclaim option image.
        self.allow_page_reclaim = true;
        self.is_detached = owner.is_detached();
        // `theap.c:mi_theap_options_init` snapshots the default
        // `mi_option_page_full_retain == 2` into each initialized theap. This
        // bounded lifecycle freezes that normal-release value rather than
        // introducing mutable option state.
        self.page_full_retain = 2;
        if owner.is_detached() {
            // The preceding fresh-TLD guard proves `mi_tld_init`'s null
            // detached head before `mi_process_theap_meta` enters
            // `_mi_theap_init`, so this is precisely its normal first-head
            // random branch. The private bootstrap intentionally does not
            // model TLD-list insertion or the nonempty-head split route.
            self.random.initialize();
            self.cookie = self.random.next() as usize | 1;
        }
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

    /// Returns the concrete source allocation provenance retained across
    /// `_mi_theap_init`'s empty-image copy. This is an observation only; it
    /// does not transfer the matching Malloc/Arena release capability.
    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.memid
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

    /// Checks the exact TLD pointer saved by source `_mi_theap_init`.
    ///
    /// This is intentionally narrower than owner identity matching: the
    /// deferred-free boundary must not cross a stale Theap/TLD pairing during
    /// post-exit teardown.
    #[inline]
    pub(crate) fn matches_tld_pointer(&self, tld: *mut ThreadLocalData) -> bool {
        core::ptr::eq(self.tld, tld) && !tld.is_null()
    }

    /// Advances source `mi_theap_t::heartbeat` for one collector entry.
    ///
    /// Pinned C uses an unsigned counter, so overflow is defined modulo the
    /// field width rather than a debug-only failure.
    #[inline]
    pub(crate) fn advance_heartbeat(&mut self) -> u64 {
        self.heartbeat = self.heartbeat.wrapping_add(1);
        self.heartbeat
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

    /// Address-free terminal-link observation for the finite M1 compiler-TLS
    /// same-TLD differential. It intentionally exposes only relations that
    /// the pinned C fixture records before final metadata release.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_m1_terminal_fields(&self) -> M1TerminalTheapFields {
        M1TerminalTheapFields {
            heap_is_null: self.heap.load(Ordering::Acquire).is_null(),
            tld_is_null: self.tld.is_null(),
            tnext_is_null: self.tnext.is_null(),
            tprev_is_null: self.tprev.is_null(),
            hnext_is_null: self.hnext.is_null(),
            hprev_is_null: self.hprev.is_null(),
            subproc_is_nonnull: !self.subproc.load(Ordering::Acquire).is_null(),
            refcount: self.refcount(),
            page_count: self.page_count,
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

/// The source-visible terminal Theap relations observed before its final
/// `_mi_theap_decref` in the M1 same-TLD differential fixture.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct M1TerminalTheapFields {
    pub(crate) heap_is_null: bool,
    pub(crate) tld_is_null: bool,
    pub(crate) tnext_is_null: bool,
    pub(crate) tprev_is_null: bool,
    pub(crate) hnext_is_null: bool,
    pub(crate) hprev_is_null: bool,
    pub(crate) subproc_is_nonnull: bool,
    pub(crate) refcount: usize,
    pub(crate) page_count: usize,
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
    use crate::free_list::LocalFreeList;
    use crate::remote_free;
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
        record!("sizeof.mi_memid_t.mem", size_of::<MemoryInfo>());
        record!("alignof.mi_memid_t.mem", align_of::<MemoryInfo>());
        record!("sizeof.mi_memid_os_info_t", size_of::<OsMemory>());
        record!("alignof.mi_memid_os_info_t", align_of::<OsMemory>());
        record!(
            "offsetof.mi_memid_os_info_t.base",
            offset_of!(OsMemory, base)
        );
        record!(
            "offsetof.mi_memid_os_info_t.size",
            offset_of!(OsMemory, size)
        );
        record!("sizeof.mi_memid_arena_info_t", size_of::<ArenaMemory>());
        record!("alignof.mi_memid_arena_info_t", align_of::<ArenaMemory>());
        record!(
            "offsetof.mi_memid_arena_info_t.arena",
            offset_of!(ArenaMemory, arena)
        );
        record!(
            "offsetof.mi_memid_arena_info_t.slice_index",
            offset_of!(ArenaMemory, slice_index)
        );
        record!(
            "offsetof.mi_memid_arena_info_t.slice_count",
            offset_of!(ArenaMemory, slice_count)
        );
        record!("sizeof.mi_memid_malloc_info_t", size_of::<MallocMemory>());
        record!(
            "alignof.mi_memid_malloc_info_t",
            align_of::<MallocMemory>()
        );
        record!(
            "offsetof.mi_memid_malloc_info_t.base",
            offset_of!(MallocMemory, base)
        );
        record!(
            "offsetof.mi_memid_malloc_info_t.size",
            offset_of!(MallocMemory, size)
        );
        record!("sizeof.mi_memid_t", size_of::<MemoryId>());
        record!("alignof.mi_memid_t", align_of::<MemoryId>());
        record!("offsetof.mi_memid_t.mem", offset_of!(MemoryId, info));
        record!(
            "offsetof.mi_memid_t.mem.os.base",
            offset_of!(MemoryId, info) + offset_of!(OsMemory, base)
        );
        record!(
            "offsetof.mi_memid_t.mem.os.size",
            offset_of!(MemoryId, info) + offset_of!(OsMemory, size)
        );
        record!(
            "offsetof.mi_memid_t.mem.arena.arena",
            offset_of!(MemoryId, info) + offset_of!(ArenaMemory, arena)
        );
        record!(
            "offsetof.mi_memid_t.mem.arena.slice_index",
            offset_of!(MemoryId, info) + offset_of!(ArenaMemory, slice_index)
        );
        record!(
            "offsetof.mi_memid_t.mem.arena.slice_count",
            offset_of!(MemoryId, info) + offset_of!(ArenaMemory, slice_count)
        );
        record!(
            "offsetof.mi_memid_t.mem.malloc.base",
            offset_of!(MemoryId, info) + offset_of!(MallocMemory, base)
        );
        record!(
            "offsetof.mi_memid_t.mem.malloc.size",
            offset_of!(MemoryId, info) + offset_of!(MallocMemory, size)
        );
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
        let memory_kinds = [
            MemoryKind::None,
            MemoryKind::External,
            MemoryKind::Static,
            MemoryKind::Os,
            MemoryKind::OsHuge,
            MemoryKind::OsRemap,
            MemoryKind::Arena,
            MemoryKind::Malloc,
        ];
        let mut memory_kind_is_os_mask = 0usize;
        let mut memory_kind_needs_no_free_mask = 0usize;
        for (index, kind) in memory_kinds.iter().copied().enumerate() {
            if kind.is_os() {
                memory_kind_is_os_mask |= 1usize << index;
            }
            if kind.needs_no_free() {
                memory_kind_needs_no_free_mask |= 1usize << index;
            }
        }
        record!("m1.provenance.memkind.is_os.mask", memory_kind_is_os_mask);
        record!(
            "m1.provenance.memkind.needs_no_free.mask",
            memory_kind_needs_no_free_mask
        );
        let mut m1_memid_anchor = 0_u8;
        let m1_memid_anchor = core::ptr::from_mut(&mut m1_memid_anchor);
        let m1_memid_none = MemoryId::none();
        let m1_memid_static = MemoryId::static_kind_only();
        let m1_memid_static_allocation = MemoryId::static_allocation(m1_memid_anchor, 37);
        let m1_memid_malloc = MemoryId::malloc(m1_memid_anchor, 41, true);
        let m1_memid_os = MemoryId::os(m1_memid_anchor, 43, false, true, true);
        record!("m1.provenance.create.none.kind", m1_memid_none.kind as usize);
        record!(
            "m1.provenance.create.none.pinned",
            m1_memid_none.is_pinned as usize
        );
        record!(
            "m1.provenance.create.none.committed",
            m1_memid_none.initially_committed as usize
        );
        record!(
            "m1.provenance.create.none.zero",
            m1_memid_none.initially_zero as usize
        );
        record!(
            "m1.provenance.create.none.memid_size",
            m1_memid_none.size().expect("none has a source size")
        );
        let m1_static_memory = m1_memid_static
            .static_memory()
            .expect("kind-only static memory projects its zero union");
        record!(
            "m1.provenance.create.static.kind",
            m1_memid_static.kind as usize
        );
        record!(
            "m1.provenance.create.static.pinned",
            m1_memid_static.is_pinned as usize
        );
        record!(
            "m1.provenance.create.static.committed",
            m1_memid_static.initially_committed as usize
        );
        record!(
            "m1.provenance.create.static.zero",
            m1_memid_static.initially_zero as usize
        );
        record!(
            "m1.provenance.create.static.base_is_null",
            m1_static_memory.base.is_null() as usize
        );
        record!(
            "m1.provenance.create.static.stored_size",
            m1_static_memory.size
        );
        record!(
            "m1.provenance.create.static.memid_size",
            m1_memid_static.size().expect("static has a source size")
        );
        let m1_static_allocation_memory = m1_memid_static_allocation
            .static_memory()
            .expect("concrete static memory projects the malloc union");
        record!(
            "m1.provenance.create.static_allocation.kind",
            m1_memid_static_allocation.kind as usize
        );
        record!(
            "m1.provenance.create.static_allocation.pinned",
            m1_memid_static_allocation.is_pinned as usize
        );
        record!(
            "m1.provenance.create.static_allocation.committed",
            m1_memid_static_allocation.initially_committed as usize
        );
        record!(
            "m1.provenance.create.static_allocation.zero",
            m1_memid_static_allocation.initially_zero as usize
        );
        record!(
            "m1.provenance.create.static_allocation.base_is_input",
            (m1_static_allocation_memory.base == m1_memid_anchor) as usize
        );
        record!(
            "m1.provenance.create.static_allocation.stored_size",
            m1_static_allocation_memory.size
        );
        record!(
            "m1.provenance.create.static_allocation.memid_size",
            m1_memid_static_allocation
                .size()
                .expect("static allocation has a source size")
        );
        let m1_malloc_memory = m1_memid_malloc
            .malloc_memory()
            .expect("malloc memory projects its source union");
        record!(
            "m1.provenance.create.malloc.kind",
            m1_memid_malloc.kind as usize
        );
        record!(
            "m1.provenance.create.malloc.pinned",
            m1_memid_malloc.is_pinned as usize
        );
        record!(
            "m1.provenance.create.malloc.committed",
            m1_memid_malloc.initially_committed as usize
        );
        record!(
            "m1.provenance.create.malloc.zero",
            m1_memid_malloc.initially_zero as usize
        );
        record!(
            "m1.provenance.create.malloc.base_is_input",
            (m1_malloc_memory.base == m1_memid_anchor) as usize
        );
        record!(
            "m1.provenance.create.malloc.stored_size",
            m1_malloc_memory.size
        );
        record!(
            "m1.provenance.create.malloc.memid_size",
            m1_memid_malloc.size().expect("malloc has a source size")
        );
        let m1_os_memory = m1_memid_os
            .os_memory()
            .expect("OS memory projects its source union");
        record!("m1.provenance.create.os.kind", m1_memid_os.kind as usize);
        record!(
            "m1.provenance.create.os.pinned",
            m1_memid_os.is_pinned as usize
        );
        record!(
            "m1.provenance.create.os.committed",
            m1_memid_os.initially_committed as usize
        );
        record!("m1.provenance.create.os.zero", m1_memid_os.initially_zero as usize);
        record!(
            "m1.provenance.create.os.base_is_input",
            (m1_os_memory.base == m1_memid_anchor) as usize
        );
        record!("m1.provenance.create.os.stored_size", m1_os_memory.size);
        record!(
            "m1.provenance.create.os.memid_size",
            m1_memid_os.size().expect("OS memory has a source size")
        );
        // These are the actual static source images, rather than fresh
        // temporary values. C initializes them through `MI_MEMID_STATIC` in
        // `src/init.c`; only the detached TLD becomes mutable after process
        // initialization, which the dedicated C reader suppresses.
        let empty_page = EMPTY_PAGE.as_ref();
        let empty_theap = crate::bootstrap::empty_default_theap();
        let detached_tld = &DETACHED_THREAD_LOCAL.0;
        let empty_page_memid = &empty_page.memid;
        let empty_theap_memid = &empty_theap.memid;
        record!(
            "m1.bootstrap.empty_page.memid.kind",
            empty_page_memid.kind as usize
        );
        record!(
            "m1.bootstrap.empty_page.memid.pinned",
            empty_page_memid.is_pinned as usize
        );
        record!(
            "m1.bootstrap.empty_page.memid.committed",
            empty_page_memid.initially_committed as usize
        );
        record!(
            "m1.bootstrap.empty_page.memid.zero",
            empty_page_memid.initially_zero as usize
        );
        record!(
            "m1.bootstrap.empty_theap.memid.kind",
            empty_theap_memid.kind as usize
        );
        record!(
            "m1.bootstrap.empty_theap.memid.pinned",
            empty_theap_memid.is_pinned as usize
        );
        record!(
            "m1.bootstrap.empty_theap.memid.committed",
            empty_theap_memid.initially_committed as usize
        );
        record!(
            "m1.bootstrap.empty_theap.memid.zero",
            empty_theap_memid.initially_zero as usize
        );
        // The immutable `src/init.c` images have pointer fields, so the
        // release oracle records source relationships instead of unstable
        // process addresses. The detached TLD lock is intentionally checked
        // only by acquire/release behavior: `PrivateLock` is a Linux futex
        // boundary, not a byte-layout claim about `pthread_mutex_t`.
        let (empty_page_memid_base_is_null, empty_page_memid_size) =
            empty_page_memid.test_static_empty_info();
        record!(
            "m1.bootstrap.empty_page.self_is_null",
            empty_page.self_.load(Ordering::Relaxed).is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_page.xthread_id",
            empty_page.xthread_id.load(Ordering::Relaxed)
        );
        record!(
            "m1.bootstrap.empty_page.free_is_null",
            empty_page.free.is_null() as usize
        );
        record!("m1.bootstrap.empty_page.used", empty_page.used);
        record!(
            "m1.bootstrap.empty_page.local_free_is_null",
            empty_page.local_free.is_null() as usize
        );
        record!("m1.bootstrap.empty_page.block_size", empty_page.block_size);
        record!("m1.bootstrap.empty_page.page_offset", empty_page.page_offset);
        record!("m1.bootstrap.empty_page.capacity", empty_page.capacity);
        record!("m1.bootstrap.empty_page.reserved", empty_page.reserved);
        record!(
            "m1.bootstrap.empty_page.slice_pcommitted",
            empty_page.slice_pcommitted
        );
        record!(
            "m1.bootstrap.empty_page.retire_expire",
            empty_page.retire_expire
        );
        record!(
            "m1.bootstrap.empty_page.free_is_zero",
            empty_page.free_is_zero as usize
        );
        record!(
            "m1.bootstrap.empty_page.xthread_free",
            empty_page.xthread_free.load(Ordering::Relaxed)
        );
        record!(
            "m1.bootstrap.empty_page.theap_is_null",
            empty_page.theap.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_page.heap_is_null",
            empty_page.heap.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_page.next_is_null",
            empty_page.next.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_page.prev_is_null",
            empty_page.prev.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_page.memid.base_is_null",
            empty_page_memid_base_is_null as usize
        );
        record!("m1.bootstrap.empty_page.memid.size", empty_page_memid_size);

        record!(
            "m1.bootstrap.empty_theap.pages_free_direct.count",
            empty_theap.pages_free_direct.len()
        );
        record!(
            "m1.bootstrap.empty_theap.pages_free_direct.all_empty_page",
            empty_theap
                .pages_free_direct
                .iter()
                .all(|page| core::ptr::eq(*page, EMPTY_PAGE.as_ptr())) as usize
        );

        let (detached_tld_memid_base_is_null, detached_tld_memid_size) =
            detached_tld.memid.test_static_empty_info();
        record!(
            "m1.bootstrap.detached_tld.thread_id",
            detached_tld.thread_id
        );
        record!(
            "m1.bootstrap.detached_tld.thread_seq",
            detached_tld.thread_seq
        );
        record!(
            "m1.bootstrap.detached_tld.numa_node",
            detached_tld.numa_node
        );
        record!(
            "m1.bootstrap.detached_tld.subproc_is_null",
            detached_tld.subprocess.is_null() as usize
        );
        record!(
            "m1.bootstrap.detached_tld.theaps_is_null",
            detached_tld.theaps.is_null() as usize
        );
        record!(
            "m1.bootstrap.detached_tld.lock_is_initially_acquirable",
            detached_tld.test_theaps_lock_starts_and_restores_unlocked() as usize
        );
        record!("m1.bootstrap.detached_tld.recurse", detached_tld.recurse as usize);
        record!(
            "m1.bootstrap.detached_tld.is_in_threadpool",
            detached_tld.is_in_threadpool as usize
        );
        record!(
            "m1.bootstrap.detached_tld.memid.base_is_null",
            detached_tld_memid_base_is_null as usize
        );
        record!(
            "m1.bootstrap.detached_tld.memid.size",
            detached_tld_memid_size
        );
        record!(
            "m1.bootstrap.detached_tld.memid.kind",
            detached_tld.memid.kind as usize
        );
        record!(
            "m1.bootstrap.detached_tld.memid.pinned",
            detached_tld.memid.is_pinned as usize
        );
        record!(
            "m1.bootstrap.detached_tld.memid.committed",
            detached_tld.memid.initially_committed as usize
        );
        record!(
            "m1.bootstrap.detached_tld.memid.zero",
            detached_tld.memid.initially_zero as usize
        );

        let (random_input_all_zero, random_output_all_zero, random_output_available, random_weak) =
            empty_theap.random.test_static_empty_shape();
        let queues_all_first_null = empty_theap.pages.iter().all(|queue| queue.first.is_null());
        let queues_all_last_null = empty_theap.pages.iter().all(|queue| queue.last.is_null());
        let queues_all_count_zero = empty_theap.pages.iter().all(|queue| queue.count == 0);
        let (empty_theap_memid_base_is_null, empty_theap_memid_size) =
            empty_theap_memid.test_static_empty_info();
        record!(
            "m1.bootstrap.empty_theap.tld_is_detached_tld",
            core::ptr::eq(empty_theap.tld, detached_thread_local_ptr()) as usize
        );
        record!(
            "m1.bootstrap.empty_theap.heap_is_null",
            empty_theap.heap.load(Ordering::Relaxed).is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_theap.subproc_is_null",
            empty_theap.subproc.load(Ordering::Relaxed).is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_theap.refcount",
            empty_theap.refcount.load(Ordering::Relaxed)
        );
        record!("m1.bootstrap.empty_theap.heartbeat", empty_theap.heartbeat);
        record!("m1.bootstrap.empty_theap.cookie", empty_theap.cookie);
        record!(
            "m1.bootstrap.empty_theap.random.input_all_zero",
            random_input_all_zero as usize
        );
        record!(
            "m1.bootstrap.empty_theap.random.output_all_zero",
            random_output_all_zero as usize
        );
        record!(
            "m1.bootstrap.empty_theap.random.output_available",
            random_output_available
        );
        record!("m1.bootstrap.empty_theap.random.weak", random_weak as usize);
        record!("m1.bootstrap.empty_theap.page_count", empty_theap.page_count);
        record!(
            "m1.bootstrap.empty_theap.page_retired_min",
            empty_theap.page_retired_min
        );
        record!(
            "m1.bootstrap.empty_theap.page_retired_max",
            empty_theap.page_retired_max
        );
        record!(
            "m1.bootstrap.empty_theap.pages_full_size",
            empty_theap.pages_full_size
        );
        record!(
            "m1.bootstrap.empty_theap.generic_count",
            empty_theap.generic_count as usize
        );
        record!(
            "m1.bootstrap.empty_theap.generic_collect_count",
            empty_theap.generic_collect_count as usize
        );
        record!(
            "m1.bootstrap.empty_theap.tnext_is_null",
            empty_theap.tnext.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_theap.tprev_is_null",
            empty_theap.tprev.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_theap.hnext_is_null",
            empty_theap.hnext.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_theap.hprev_is_null",
            empty_theap.hprev.is_null() as usize
        );
        record!(
            "m1.bootstrap.empty_theap.page_full_retain",
            empty_theap.page_full_retain as usize
        );
        record!(
            "m1.bootstrap.empty_theap.allow_page_reclaim",
            empty_theap.allow_page_reclaim as usize
        );
        record!(
            "m1.bootstrap.empty_theap.allow_page_abandon",
            empty_theap.allow_page_abandon as usize
        );
        record!(
            "m1.bootstrap.empty_theap.is_detached",
            empty_theap.is_detached as usize
        );
        record!(
            "m1.bootstrap.empty_theap.page_queues.count",
            empty_theap.pages.len()
        );
        record!(
            "m1.bootstrap.empty_theap.page_queues.all_first_null",
            queues_all_first_null as usize
        );
        record!(
            "m1.bootstrap.empty_theap.page_queues.all_last_null",
            queues_all_last_null as usize
        );
        record!(
            "m1.bootstrap.empty_theap.page_queues.all_count_zero",
            queues_all_count_zero as usize
        );
        for (index, queue) in empty_theap.pages.iter().enumerate() {
            std::println!(
                "m1.bootstrap.empty_theap.page_queues.block_size.{index}={}",
                queue.block_size
            );
        }
        record!(
            "m1.bootstrap.empty_theap.memid.base_is_null",
            empty_theap_memid_base_is_null as usize
        );
        record!("m1.bootstrap.empty_theap.memid.size", empty_theap_memid_size);
        // `LAYOUT_PROBE` has always emitted this complete C image. Keep the
        // Rust record equally complete so the release-oracle comparison owns
        // the random-context ABI rather than relying only on local asserts.
        record!("sizeof.mi_random_ctx_t", size_of::<TheapRandomImage>());
        record!("alignof.mi_random_ctx_t", align_of::<TheapRandomImage>());
        record!(
            "offsetof.mi_random_ctx_t.input",
            TheapRandomImage::INPUT_OFFSET
        );
        record!(
            "offsetof.mi_random_ctx_t.output",
            TheapRandomImage::OUTPUT_OFFSET
        );
        record!(
            "offsetof.mi_random_ctx_t.output_available",
            TheapRandomImage::OUTPUT_AVAILABLE_OFFSET
        );
        record!(
            "offsetof.mi_random_ctx_t.weak",
            TheapRandomImage::WEAK_OFFSET
        );
        // The M1 record is a selected address-independent state trace from
        // pinned `src/random.c`, not an extra layout claim. It pairs the
        // source's split and no-op reinitialization branches with the weak
        // initializer and 64-bit zero-result retry without leaking a random
        // key, generated child output, or raw address into evidence.
        let random_trace = TheapRandomImage::m1_source_state_trace();
        record!(
            "m1.random.split.parent.output_available",
            random_trace.split_parent_output_available as usize
        );
        record!(
            "m1.random.split.parent.consumed_words_cleared",
            random_trace.split_parent_consumed_words_cleared as usize
        );
        record!(
            "m1.random.split.parent.counter_low",
            random_trace.split_parent_counter_low as usize
        );
        record!(
            "m1.random.split.parent.counter_high",
            random_trace.split_parent_counter_high as usize
        );
        record!(
            "m1.random.split.child.output_available",
            random_trace.split_child_output_available as usize
        );
        record!(
            "m1.random.split.child.counter_low",
            random_trace.split_child_counter_low as usize
        );
        record!(
            "m1.random.split.child.counter_high",
            random_trace.split_child_counter_high as usize
        );
        record!(
            "m1.random.split.child.weak",
            random_trace.split_child_weak as usize
        );
        record!(
            "m1.random.split.child.nonce_xor_destination",
            random_trace.split_child_nonce_xor_destination as usize
        );
        record!(
            "m1.random.next.zero_retry.result",
            random_trace.zero_retry_result as usize
        );
        record!(
            "m1.random.next.zero_retry.output_available",
            random_trace.zero_retry_output_available as usize
        );
        record!(
            "m1.random.next.zero_retry.consumed_words_cleared",
            random_trace.zero_retry_consumed_words_cleared as usize
        );
        record!(
            "m1.random.forced_weak.initialized",
            random_trace.forced_weak_initialized as usize
        );
        record!("m1.random.forced_weak.weak", random_trace.forced_weak as usize);
        record!(
            "m1.random.forced_weak.output_available",
            random_trace.forced_weak_output_available as usize
        );
        record!(
            "m1.random.forced_weak.counter_low",
            random_trace.forced_weak_counter_low as usize
        );
        record!(
            "m1.random.forced_weak.counter_high",
            random_trace.forced_weak_counter_high as usize
        );
        record!(
            "m1.random.forced_weak.nonce_xor_destination",
            random_trace.forced_weak_nonce_xor_destination as usize
        );
        record!(
            "m1.random.reinit.strong.attempted",
            random_trace.strong_reinit_attempted as usize
        );
        record!(
            "m1.random.reinit.strong.state_preserved",
            random_trace.strong_reinit_state_preserved as usize
        );
        record!(
            "m1.random.reinit.strong.fingerprint",
            random_trace.strong_reinit_fingerprint as usize
        );
        record!("sizeof.mi_encoded_t", size_of::<Encoded>());
        record!("alignof.mi_encoded_t", align_of::<Encoded>());
        record!("sizeof.mi_threadid_t", size_of::<ThreadId>());
        record!("alignof.mi_threadid_t", align_of::<ThreadId>());
        record!("sizeof.mi_thread_free_t", size_of::<ThreadFree>());
        record!("alignof.mi_thread_free_t", align_of::<ThreadFree>());
        record!("sizeof.mi_used_t", size_of::<usize>());
        record!("alignof.mi_used_t", align_of::<usize>());
        record!("sizeof.mi_page_flags_t", size_of::<PageFlags>());
        record!("alignof.mi_page_flags_t", align_of::<PageFlags>());
        record!("value.MI_PAGE_IN_FULL_QUEUE", PAGE_IN_FULL_QUEUE);
        record!(
            "value.MI_PAGE_HAS_INTERIOR_POINTERS",
            PAGE_HAS_INTERIOR_POINTERS
        );
        record!("value.MI_PAGE_FLAG_MASK", PAGE_FLAG_MASK);
        record!("value.MI_PAGE_FLAG_BITS", PAGE_FLAG_BITS);
        record!("value.MI_THREADID_ABANDONED", THREAD_ID_ABANDONED);
        record!(
            "value.MI_THREADID_ABANDONED_MAPPED",
            THREAD_ID_ABANDONED_MAPPED
        );
        record!("value.MI_THREADID_DETACHED", THREAD_ID_DETACHED);
        record!("sizeof.mi_block_t", size_of::<Block>());
        record!("alignof.mi_block_t", align_of::<Block>());
        record!("offsetof.mi_block_t.next", offset_of!(Block, next));
        record!("sizeof.mi_page_t", size_of::<Page>());
        record!("alignof.mi_page_t", align_of::<Page>());
        record!("offsetof.mi_page_t.self", offset_of!(Page, self_));
        record!("offsetof.mi_page_t.xthread_id", offset_of!(Page, xthread_id));
        record!("offsetof.mi_page_t.free", offset_of!(Page, free));
        record!("offsetof.mi_page_t.used", offset_of!(Page, used));
        record!("offsetof.mi_page_t.local_free", offset_of!(Page, local_free));
        record!("offsetof.mi_page_t.block_size", offset_of!(Page, block_size));
        record!("offsetof.mi_page_t.page_offset", offset_of!(Page, page_offset));
        record!("offsetof.mi_page_t.capacity", offset_of!(Page, capacity));
        record!("offsetof.mi_page_t.reserved", offset_of!(Page, reserved));
        record!(
            "offsetof.mi_page_t.slice_pcommitted",
            offset_of!(Page, slice_pcommitted)
        );
        record!(
            "offsetof.mi_page_t.retire_expire",
            offset_of!(Page, retire_expire)
        );
        record!("offsetof.mi_page_t.free_is_zero", offset_of!(Page, free_is_zero));
        record!("offsetof.mi_page_t.xthread_free", offset_of!(Page, xthread_free));
        record!("offsetof.mi_page_t.theap", offset_of!(Page, theap));
        record!("offsetof.mi_page_t.heap", offset_of!(Page, heap));
        record!("offsetof.mi_page_t.next", offset_of!(Page, next));
        record!("offsetof.mi_page_t.prev", offset_of!(Page, prev));
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

        // Keep the selected scalar M1 vector in the release C/Rust record,
        // rather than relying on a Rust-only assertion. The operands are
        // intentionally representable before rounding: `Option::None` still
        // represents the separate explicit Rust overflow boundary.
        record!(
            "m1.scalar.is_power_of_two.zero",
            crate::invariants::is_power_of_two(0) as usize
        );
        record!(
            "m1.scalar.is_aligned.zero",
            crate::provenance::Address::new(0x1234_5678).is_aligned_to(0) as usize
        );
        record!(
            "m1.scalar.align_down.generic.101_by_24",
            crate::invariants::align_down(101, 24)
                .expect("selected M1 scalar vector is representable")
        );
        record!(
            "m1.scalar.align_up.generic.101_by_24",
            crate::invariants::align_up(101, 24)
                .expect("selected M1 scalar vector is representable")
        );
        record!(
            "m1.scalar.divide_up.17_by_6",
            crate::invariants::divide_up(17, 6)
                .expect("selected M1 scalar vector is representable")
        );
        record!(
            "m1.scalar.wsize_from_size.17",
            crate::invariants::word_count(17)
                .expect("selected M1 scalar vector is representable")
        );
        record!(
            "m1.scalar.slice_count.one_past_slice",
            crate::invariants::slice_count_of_size(crate::config::ARENA_SLICE_SIZE + 1)
                .expect("selected M1 scalar vector is representable")
        );
        record!(
            "m1.scalar.size_of_slices.3",
            crate::invariants::size_of_slices(3)
                .expect("selected M1 scalar vector is representable")
        );

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
    fn static_empty_bootstrap_images_keep_the_pinned_static_memid_flags() {
        // Pinned `MI_MEMID_STATIC` is not `_mi_memid_create(MI_MEM_STATIC)`:
        // its null/zero union still records immutable static storage as
        // pinned and initially committed. `src/init.c` uses that exact image
        // for mi_page_empty, the initial mi_tld_detached image, and
        // _mi_theap_empty.
        let static_empty = MemoryId::static_empty();
        assert_eq!(static_empty.kind(), MemoryKind::Static);
        assert!(static_empty.is_pinned());
        assert!(static_empty.initially_committed());
        assert!(!static_empty.initially_zero());

        let page = Page::empty();
        assert!(page.memid.is_pinned());
        assert!(page.memid.initially_committed());
        assert!(!page.memid.initially_zero());

        let detached = ThreadLocalData::detached();
        assert!(detached.memid.is_pinned());
        assert!(detached.memid.initially_committed());
        assert!(!detached.memid.initially_zero());

        // `mi_heap_main_init_once` replaces the initial detached-TLD image
        // with `_mi_memid_create(MI_MEM_STATIC)` before `mi_tld_init` binds
        // the main subprocess. Do not preserve the initializer flags across
        // that source transition.
        let mut attached_detached = ThreadLocalData::detached();
        assert!(attached_detached.prepare_detached_static_memid());
        assert!(attached_detached.initialize_detached_after_static_memid(MainSubprocess::global()));
        assert_eq!(attached_detached.memid.kind(), MemoryKind::Static);
        assert!(!attached_detached.memid.is_pinned());
        assert!(!attached_detached.memid.initially_committed());
        assert!(!attached_detached.memid.initially_zero());

        let theap = Theap::empty();
        assert!(theap.memid.is_pinned());
        assert!(theap.memid.initially_committed());
        assert!(!theap.memid.initially_zero());

        // `_mi_memid_create(MI_MEM_STATIC)` remains a separate kind-only
        // source path; collapsing it into the initializer would hide this
        // distinction again.
        let kind_only = MemoryId::static_kind_only();
        assert!(!kind_only.is_pinned());
        assert!(!kind_only.initially_committed());
        assert!(!kind_only.initially_zero());
    }

    #[derive(Debug, PartialEq)]
    struct DetachedStaticPreimageSnapshot {
        thread_id: ThreadId,
        thread_seq: usize,
        numa_node: i32,
        subprocess: *mut MainSubprocess,
        theap_head: *mut Theap,
        recurse: bool,
        in_threadpool: bool,
        memid_kind: MemoryKind,
        memid_static_base: *mut u8,
        memid_static_size: usize,
        memid_pinned: bool,
        memid_initially_committed: bool,
        memid_initially_zero: bool,
    }

    fn detached_static_preimage_snapshot(
        tld: &ThreadLocalData,
    ) -> DetachedStaticPreimageSnapshot {
        let static_memory = tld
            .memid
            .static_memory()
            .expect("the selected detached image has static provenance");
        DetachedStaticPreimageSnapshot {
            thread_id: tld.thread_id,
            thread_seq: tld.thread_seq,
            numa_node: tld.numa_node,
            subprocess: tld.subprocess,
            theap_head: tld.theaps,
            recurse: tld.recurse,
            in_threadpool: tld.is_in_threadpool,
            memid_kind: tld.memid.kind(),
            memid_static_base: static_memory.base,
            memid_static_size: static_memory.size,
            memid_pinned: tld.memid.is_pinned(),
            memid_initially_committed: tld.memid.initially_committed(),
            memid_initially_zero: tld.memid.initially_zero(),
        }
    }

    #[test]
    fn detached_static_preimage_steps_refuse_out_of_order_without_mutation() {
        let subprocess = MainSubprocess::test_static_owner();
        let mut tld = ThreadLocalData::detached();
        let static_preimage = detached_static_preimage_snapshot(&tld);
        assert!(
            !tld.initialize_detached_after_static_memid(subprocess),
            "the helper must not absorb src/init.c:192's separate predecessor"
        );
        assert_eq!(detached_static_preimage_snapshot(&tld), static_preimage);
        assert!(tld.test_theaps_lock_starts_and_restores_unlocked());

        assert!(tld.prepare_detached_static_memid());
        let kind_only_preimage = detached_static_preimage_snapshot(&tld);
        assert!(
            !tld.prepare_detached_static_memid(),
            "the predecessor accepts only MI_MEMID_STATIC, not its own result"
        );
        assert_eq!(detached_static_preimage_snapshot(&tld), kind_only_preimage);
        assert!(tld.test_theaps_lock_starts_and_restores_unlocked());

        assert!(tld.initialize_detached_after_static_memid(subprocess));
        let initialized = detached_static_preimage_snapshot(&tld);
        assert!(
            !tld.initialize_detached_after_static_memid(subprocess),
            "the detached helper accepts only its source-order predecessor"
        );
        assert!(!tld.prepare_detached_static_memid());
        assert_eq!(detached_static_preimage_snapshot(&tld), initialized);
        assert!(tld.test_theaps_lock_starts_and_restores_unlocked());
        assert_eq!(subprocess.total_thread_count(), 0);
        assert_eq!(subprocess.live_thread_count(), 0);
    }

    #[test]
    fn detached_static_preimage_steps_refuse_busy_lock_without_mutation() {
        let subprocess = MainSubprocess::test_static_owner();
        let counters_before = (
            subprocess.total_thread_count(),
            subprocess.live_thread_count(),
        );
        assert_eq!(counters_before, (0, 0));

        let mut before_predecessor = ThreadLocalData::detached();
        let static_preimage = detached_static_preimage_snapshot(&before_predecessor);
        before_predecessor.test_inject_busy_theaps_lock();
        assert!(
            !before_predecessor.prepare_detached_static_memid(),
            "a busy private lock must not be reused by the static-memid predecessor"
        );
        assert_eq!(
            detached_static_preimage_snapshot(&before_predecessor),
            static_preimage
        );
        assert_eq!(
            (
                subprocess.total_thread_count(),
                subprocess.live_thread_count(),
            ),
            counters_before
        );
        assert!(
            !before_predecessor.test_theaps_lock_starts_and_restores_unlocked(),
            "predecessor refusal retains the injected busy lock"
        );

        let mut between_stages = ThreadLocalData::detached();
        assert!(between_stages.prepare_detached_static_memid());
        let static_memid_preimage = detached_static_preimage_snapshot(&between_stages);
        between_stages.test_inject_busy_theaps_lock();

        assert!(
            !between_stages.initialize_detached_after_static_memid(subprocess),
            "a busy private lock must not be overwritten by the detached helper"
        );
        assert_eq!(
            detached_static_preimage_snapshot(&between_stages),
            static_memid_preimage
        );
        assert_eq!(
            (
                subprocess.total_thread_count(),
                subprocess.live_thread_count(),
            ),
            counters_before
        );
        assert!(
            !between_stages.test_theaps_lock_starts_and_restores_unlocked(),
            "initializer refusal retains the injected busy lock rather than replacing it"
        );
    }

    #[test]
    fn emit_m2_detached_tld_static_preimage_c_rust_trace() {
        // This is deliberately the exact detached source slice, not the
        // broader bootstrap/Theap lifecycle. It starts with src/init.c's
        // static `mi_tld_detached` image, applies only its line-192 memid
        // predecessor, then applies only the file-static mi_tld_init
        // detached branch. Its zeroed test-local subprocess is an
        // address-only fixture valid only for this helper; it is not
        // `_mi_subproc_main_init()` or the complete line-193 caller. Both
        // counters begin at zero so the trace can prove that this branch
        // never registers a live thread.
        fn memory_id_trace(memid: MemoryId) -> (bool, bool, bool, bool, bool, bool) {
            let static_memory = memid
                .static_memory()
                .expect("the selected detached trace has static provenance");
            (
                memid.kind() == MemoryKind::Static,
                static_memory.base.is_null(),
                static_memory.size == 0,
                memid.is_pinned(),
                memid.initially_committed(),
                !memid.initially_zero(),
            )
        }

        macro_rules! record {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }

        let subprocess = MainSubprocess::test_static_owner();
        let mut tld = ThreadLocalData::detached();
        let pre_memid = memory_id_trace(tld.memid);
        let pre_total_thread_count = subprocess.total_thread_count();
        let pre_live_thread_count = subprocess.live_thread_count();
        let pre_thread_id_detached = tld.thread_id == THREAD_ID_DETACHED;
        let pre_thread_sequence_zero = tld.thread_seq == 0;
        let pre_numa_node_zero = tld.numa_node == 0;
        let pre_subprocess_null = tld.subprocess.is_null();
        let pre_theap_head_null = tld.theaps.is_null();
        let pre_lock_roundtrip = tld.test_theaps_lock_starts_and_restores_unlocked();
        let pre_recurse_false = !tld.recurse;
        let pre_threadpool_false = !tld.is_in_threadpool;

        assert!(pre_thread_id_detached);
        assert!(pre_thread_sequence_zero);
        assert!(pre_numa_node_zero);
        assert!(pre_subprocess_null);
        assert!(pre_theap_head_null);
        assert!(pre_lock_roundtrip);
        assert!(pre_recurse_false);
        assert!(pre_threadpool_false);
        assert_eq!(pre_memid, (true, true, true, true, true, true));
        assert_eq!(pre_total_thread_count, 0);
        assert_eq!(pre_live_thread_count, 0);

        assert!(tld.prepare_detached_static_memid());
        let predecessor_memid = memory_id_trace(tld.memid);
        assert_eq!(predecessor_memid, (true, true, true, false, false, true));

        assert!(tld.initialize_detached_after_static_memid(subprocess));
        let post_memid = memory_id_trace(tld.memid);
        let post_total_thread_count = subprocess.total_thread_count();
        let post_live_thread_count = subprocess.live_thread_count();
        let post_thread_id_detached = tld.thread_id == THREAD_ID_DETACHED;
        let post_thread_sequence_zero = tld.thread_seq == 0;
        let post_numa_node_minus_one = tld.numa_node == -1;
        let post_subprocess_matches_input = core::ptr::eq(tld.subprocess, subprocess.as_ptr());
        let post_theap_head_null = tld.theaps.is_null();
        let post_lock_roundtrip = tld.test_theaps_lock_starts_and_restores_unlocked();
        let post_recurse_false = !tld.recurse;
        let post_threadpool_false = !tld.is_in_threadpool;

        assert!(post_thread_id_detached);
        assert!(post_thread_sequence_zero);
        assert!(post_numa_node_minus_one);
        assert!(post_subprocess_matches_input);
        assert!(post_theap_head_null);
        assert!(post_lock_roundtrip);
        assert!(post_recurse_false);
        assert!(post_threadpool_false);
        assert_eq!(post_memid, predecessor_memid);
        assert_eq!(post_total_thread_count, 0);
        assert_eq!(post_live_thread_count, 0);
        assert_eq!(post_total_thread_count, pre_total_thread_count);
        assert_eq!(post_live_thread_count, pre_live_thread_count);

        std::println!("CRABC_MI_M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_BEGIN");
        record!(
            "m2.initialization.detached_tld.pre.thread_id_detached",
            pre_thread_id_detached
        );
        record!(
            "m2.initialization.detached_tld.pre.thread_sequence_zero",
            pre_thread_sequence_zero
        );
        record!(
            "m2.initialization.detached_tld.pre.numa_node_zero",
            pre_numa_node_zero
        );
        record!(
            "m2.initialization.detached_tld.pre.subprocess_null",
            pre_subprocess_null
        );
        record!(
            "m2.initialization.detached_tld.pre.theap_head_null",
            pre_theap_head_null
        );
        record!(
            "m2.initialization.detached_tld.pre.lock_roundtrip",
            pre_lock_roundtrip
        );
        record!(
            "m2.initialization.detached_tld.pre.recurse_false",
            pre_recurse_false
        );
        record!(
            "m2.initialization.detached_tld.pre.threadpool_false",
            pre_threadpool_false
        );
        record!(
            "m2.initialization.detached_tld.pre.memid_static",
            pre_memid.0
        );
        record!(
            "m2.initialization.detached_tld.pre.memid_base_null",
            pre_memid.1
        );
        record!(
            "m2.initialization.detached_tld.pre.memid_size_zero",
            pre_memid.2
        );
        record!(
            "m2.initialization.detached_tld.pre.memid_pinned",
            pre_memid.3
        );
        record!(
            "m2.initialization.detached_tld.pre.memid_committed",
            pre_memid.4
        );
        record!(
            "m2.initialization.detached_tld.pre.memid_zero_false",
            pre_memid.5
        );
        record!(
            "m2.initialization.detached_tld.pre.total_thread_count_zero",
            pre_total_thread_count == 0
        );
        record!(
            "m2.initialization.detached_tld.pre.live_thread_count_zero",
            pre_live_thread_count == 0
        );
        record!(
            "m2.initialization.detached_tld.predecessor.memid_static",
            predecessor_memid.0
        );
        record!(
            "m2.initialization.detached_tld.predecessor.memid_base_null",
            predecessor_memid.1
        );
        record!(
            "m2.initialization.detached_tld.predecessor.memid_size_zero",
            predecessor_memid.2
        );
        record!(
            "m2.initialization.detached_tld.predecessor.memid_unpinned",
            !predecessor_memid.3
        );
        record!(
            "m2.initialization.detached_tld.predecessor.memid_uncommitted",
            !predecessor_memid.4
        );
        record!(
            "m2.initialization.detached_tld.predecessor.memid_zero_false",
            predecessor_memid.5
        );
        record!(
            "m2.initialization.detached_tld.post.thread_id_detached",
            post_thread_id_detached
        );
        record!(
            "m2.initialization.detached_tld.post.thread_sequence_zero",
            post_thread_sequence_zero
        );
        record!(
            "m2.initialization.detached_tld.post.numa_node_minus_one",
            post_numa_node_minus_one
        );
        record!(
            "m2.initialization.detached_tld.post.subprocess_matches_input",
            post_subprocess_matches_input
        );
        record!(
            "m2.initialization.detached_tld.post.theap_head_null",
            post_theap_head_null
        );
        record!(
            "m2.initialization.detached_tld.post.lock_roundtrip",
            post_lock_roundtrip
        );
        record!(
            "m2.initialization.detached_tld.post.recurse_false",
            post_recurse_false
        );
        record!(
            "m2.initialization.detached_tld.post.threadpool_false",
            post_threadpool_false
        );
        record!(
            "m2.initialization.detached_tld.post.memid_static",
            post_memid.0
        );
        record!(
            "m2.initialization.detached_tld.post.memid_base_null",
            post_memid.1
        );
        record!(
            "m2.initialization.detached_tld.post.memid_size_zero",
            post_memid.2
        );
        record!(
            "m2.initialization.detached_tld.post.memid_unpinned",
            !post_memid.3
        );
        record!(
            "m2.initialization.detached_tld.post.memid_uncommitted",
            !post_memid.4
        );
        record!(
            "m2.initialization.detached_tld.post.memid_zero_false",
            post_memid.5
        );
        record!(
            "m2.initialization.detached_tld.post.total_thread_count_zero",
            post_total_thread_count == 0
        );
        record!(
            "m2.initialization.detached_tld.post.total_thread_count_unchanged",
            post_total_thread_count == pre_total_thread_count
        );
        record!(
            "m2.initialization.detached_tld.post.live_thread_count_zero",
            post_live_thread_count == 0
        );
        record!(
            "m2.initialization.detached_tld.post.live_thread_count_unchanged",
            post_live_thread_count == pre_live_thread_count
        );
        std::println!("CRABC_MI_M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_END");
    }

    #[test]
    fn static_bootstrap_images_keep_the_complete_pinned_relational_shape() {
        // This is the Rust half of the release C/Rust static-image vector.
        // It intentionally owns only `src/init.c`'s pre-process-initialization
        // images through the represented `Theap::memid` prefix. C later
        // mutates the detached TLD; `mi_stats_t`, guarded fields, alternate
        // page key/padding tails, and mutable process-main storage are not
        // silently folded into this witness.
        fn assert_static_empty_memory_id(memid: &MemoryId) {
            let (base_is_null, size) = memid.test_static_empty_info();
            assert!(base_is_null);
            assert_eq!(size, 0);
            assert_eq!(memid.kind(), MemoryKind::Static);
            assert!(memid.is_pinned());
            assert!(memid.initially_committed());
            assert!(!memid.initially_zero());
        }

        let empty_page = EMPTY_PAGE.as_ref();
        assert!(empty_page.self_.load(Ordering::Relaxed).is_null());
        assert_eq!(empty_page.xthread_id.load(Ordering::Relaxed), 0);
        assert!(empty_page.free.is_null());
        assert_eq!(empty_page.used, 0);
        assert!(empty_page.local_free.is_null());
        assert_eq!(empty_page.block_size, 0);
        assert_eq!(empty_page.page_offset, 0);
        assert_eq!(empty_page.capacity, 0);
        assert_eq!(empty_page.reserved, 0);
        assert_eq!(empty_page.slice_pcommitted, 0);
        assert_eq!(empty_page.retire_expire, 0);
        assert!(!empty_page.free_is_zero);
        assert_eq!(empty_page.xthread_free.load(Ordering::Relaxed), 0);
        assert!(empty_page.theap.is_null());
        assert!(empty_page.heap.is_null());
        assert!(empty_page.next.is_null());
        assert!(empty_page.prev.is_null());
        assert_static_empty_memory_id(&empty_page.memid);

        let detached_tld = &DETACHED_THREAD_LOCAL.0;
        assert_eq!(detached_tld.thread_id, THREAD_ID_DETACHED);
        assert_eq!(detached_tld.thread_seq, 0);
        assert_eq!(detached_tld.numa_node, 0);
        assert!(detached_tld.subprocess.is_null());
        assert!(detached_tld.theaps.is_null());
        // The actual static lock is acquired/released by the layout vector.
        // This fresh source-equivalent image keeps this unit regression from
        // racing that probe while proving the same static initializer state.
        assert!(
            ThreadLocalData::detached().test_theaps_lock_starts_and_restores_unlocked()
        );
        assert!(!detached_tld.recurse);
        assert!(!detached_tld.is_in_threadpool);
        assert_static_empty_memory_id(&detached_tld.memid);

        let empty_theap = crate::bootstrap::empty_default_theap();
        assert_eq!(empty_theap.pages_free_direct.len(), PAGES_DIRECT);
        assert!(empty_theap
            .pages_free_direct
            .iter()
            .all(|page| core::ptr::eq(*page, EMPTY_PAGE.as_ptr())));
        assert!(core::ptr::eq(empty_theap.tld, detached_thread_local_ptr()));
        assert!(empty_theap.heap.load(Ordering::Relaxed).is_null());
        assert!(empty_theap.subproc.load(Ordering::Relaxed).is_null());
        assert_eq!(empty_theap.refcount.load(Ordering::Relaxed), 1);
        assert_eq!(empty_theap.heartbeat, 0);
        assert_eq!(empty_theap.cookie, 0);
        assert_eq!(empty_theap.random.test_static_empty_shape(), (true, true, 0, true));
        assert_eq!(empty_theap.page_count, 0);
        assert_eq!(empty_theap.page_retired_min, BIN_FULL);
        assert_eq!(empty_theap.page_retired_max, 0);
        assert_eq!(empty_theap.pages_full_size, 0);
        assert_eq!(empty_theap.generic_count, 0);
        assert_eq!(empty_theap.generic_collect_count, 0);
        assert!(empty_theap.tnext.is_null());
        assert!(empty_theap.tprev.is_null());
        assert!(empty_theap.hnext.is_null());
        assert!(empty_theap.hprev.is_null());
        assert_eq!(empty_theap.page_full_retain, 0);
        assert!(!empty_theap.allow_page_reclaim);
        assert!(empty_theap.allow_page_abandon);
        assert!(empty_theap.is_detached);
        assert_eq!(empty_theap.pages.len(), BIN_COUNT);
        for (index, queue) in empty_theap.pages.iter().enumerate() {
            assert!(queue.first.is_null(), "queue {index} first link must be null");
            assert!(queue.last.is_null(), "queue {index} last link must be null");
            assert_eq!(queue.count, 0, "queue {index} count must be zero");
            assert_eq!(
                queue.block_size, BIN_BLOCK_SIZES[index],
                "queue {index} block size must retain the source initializer"
            );
        }
        assert_static_empty_memory_id(&empty_theap.memid);
    }

    #[test]
    fn detached_exclusive_binding_rejects_an_invalid_fresh_tld_checkpoint_before_mutation() {
        fn assert_unchanged_static_source_image(candidate: &Theap) {
            assert!(!candidate.is_initialized());
            assert!(candidate.subproc.load(Ordering::Relaxed).is_null());
            assert_eq!(candidate.tld, detached_thread_local_ptr());
            assert_eq!(candidate.refcount(), 1);
            assert!(!candidate.random.is_initialized());
            assert_eq!(candidate.cookie, 0);
            assert_eq!(candidate.page_full_retain, 0);
            assert!(candidate.allows_page_abandon());
            assert!(!candidate.allows_page_reclaim());
            assert!(candidate.is_detached());
            assert_eq!(candidate.memid.kind(), MemoryKind::Static);
            assert!(candidate.memid.is_pinned());
            assert!(candidate.memid.initially_committed());
            assert!(!candidate.memid.initially_zero());
            let static_memory = candidate
                .memid
                .static_memory()
                .expect("the unchanged static source image projects its zero union");
            assert!(static_memory.base.is_null());
            assert_eq!(static_memory.size, 0);
        }

        let subprocess = MainSubprocess::test_static_owner();
        let foreign_subprocess = MainSubprocess::test_static_owner();

        let mut nonempty_heap = Heap::bootstrap_empty();
        nonempty_heap.bind_main_subprocess(subprocess);
        let mut nonempty_tld = ThreadLocalData::detached();
        assert!(nonempty_tld.prepare_detached_static_memid());
        assert!(nonempty_tld.initialize_detached_after_static_memid(subprocess));
        assert!(nonempty_tld.is_subprocess_attached_no_theap());
        let mut existing_head = Theap::empty();
        let existing_head = core::ptr::from_mut(&mut existing_head);
        nonempty_tld.theaps = existing_head;
        let mut nonempty_candidate = Theap::empty();

        assert!(
            !nonempty_candidate.bind_exclusive_detached(&mut nonempty_heap, &mut nonempty_tld),
            "the bounded detached bootstrap must reject the unported source random-split path"
        );
        assert_eq!(
            nonempty_tld.theaps, existing_head,
            "rejection must not repair, relink, or replace the caller's TLD head"
        );
        assert_unchanged_static_source_image(&nonempty_candidate);

        let mut mismatched_heap = Heap::bootstrap_empty();
        mismatched_heap.bind_main_subprocess(foreign_subprocess);
        let mut empty_tld = ThreadLocalData::detached();
        assert!(empty_tld.prepare_detached_static_memid());
        assert!(empty_tld.initialize_detached_after_static_memid(subprocess));
        assert!(empty_tld.is_subprocess_attached_no_theap());
        let mut mismatched_candidate = Theap::empty();

        assert!(
            !mismatched_candidate.bind_exclusive_detached(&mut mismatched_heap, &mut empty_tld),
            "the bounded detached bootstrap must reject mismatched Heap/TLD subprocess identities"
        );
        assert!(
            empty_tld.is_subprocess_attached_no_theap(),
            "rejection must leave the fresh detached-TLD checkpoint unchanged"
        );
        assert_unchanged_static_source_image(&mismatched_candidate);

        let mut threadpool_heap = Heap::bootstrap_empty();
        threadpool_heap.bind_main_subprocess(subprocess);
        let mut threadpool_tld = ThreadLocalData::detached();
        assert!(threadpool_tld.prepare_detached_static_memid());
        assert!(threadpool_tld.initialize_detached_after_static_memid(subprocess));
        threadpool_tld.is_in_threadpool = true;
        let mut threadpool_candidate = Theap::empty();

        assert!(
            !threadpool_candidate.bind_exclusive_detached(&mut threadpool_heap, &mut threadpool_tld),
            "the bounded detached bootstrap must reject the source thread-pool option adjustment"
        );
        assert!(
            threadpool_tld.is_subprocess_attached_no_theap() && threadpool_tld.is_in_threadpool(),
            "rejection must not normalize the caller's thread-pool checkpoint"
        );
        assert_unchanged_static_source_image(&threadpool_candidate);
    }

    #[test]
    fn metadata_layout_matches_the_default_release_c_contract() {
        assert_eq!(size_of::<MemoryKind>(), 4);
        assert_eq!(align_of::<MemoryKind>(), 4);
        assert_eq!(size_of::<MemoryInfo>(), 16);
        assert_eq!(align_of::<MemoryInfo>(), 8);
        assert_eq!(size_of::<OsMemory>(), 16);
        assert_eq!(align_of::<OsMemory>(), 8);
        assert_eq!(offset_of!(OsMemory, base), 0);
        assert_eq!(offset_of!(OsMemory, size), 8);
        assert_eq!(size_of::<ArenaMemory>(), 16);
        assert_eq!(align_of::<ArenaMemory>(), 8);
        assert_eq!(offset_of!(ArenaMemory, arena), 0);
        assert_eq!(offset_of!(ArenaMemory, slice_index), 8);
        assert_eq!(offset_of!(ArenaMemory, slice_count), 12);
        assert_eq!(size_of::<MallocMemory>(), 16);
        assert_eq!(align_of::<MallocMemory>(), 8);
        assert_eq!(offset_of!(MallocMemory, base), 0);
        assert_eq!(offset_of!(MallocMemory, size), 8);
        assert_eq!(size_of::<MemoryId>(), 24);
        assert_eq!(align_of::<MemoryId>(), 8);
        assert_eq!(offset_of!(MemoryId, info), 0);
        assert_eq!(offset_of!(MemoryId, kind), 16);
        assert_eq!(offset_of!(MemoryId, is_pinned), 20);
        assert_eq!(offset_of!(MemoryId, initially_committed), 21);
        assert_eq!(offset_of!(MemoryId, initially_zero), 22);

        assert_eq!(size_of::<Block>(), 8);
        assert_eq!(align_of::<Block>(), 8);
        assert_eq!(offset_of!(Block, next), 0);
        assert_eq!(size_of::<ThreadId>(), 8);
        assert_eq!(align_of::<ThreadId>(), 8);
        assert_eq!(size_of::<ThreadFree>(), 8);
        assert_eq!(align_of::<ThreadFree>(), 8);
        assert_eq!(size_of::<PageFlags>(), 8);
        assert_eq!(align_of::<PageFlags>(), 8);
        assert_eq!(size_of::<Encoded>(), 8);
        assert_eq!(align_of::<Encoded>(), 8);
        assert_eq!(PAGE_IN_FULL_QUEUE, 1);
        assert_eq!(PAGE_HAS_INTERIOR_POINTERS, 2);
        assert_eq!(PAGE_FLAG_MASK, 3);
        assert_eq!(PAGE_FLAG_BITS, 2);
        assert_eq!(THREAD_ID_ABANDONED, 0);
        assert_eq!(THREAD_ID_ABANDONED_MAPPED, 4);
        assert_eq!(THREAD_ID_DETACHED, 8);
        assert_eq!(size_of::<PageKind>(), 4);
        assert_eq!(align_of::<PageKind>(), 4);
        assert_eq!(PageKind::Small as usize, 0);
        assert_eq!(PageKind::Medium as usize, 1);
        assert_eq!(PageKind::Large as usize, 2);
        assert_eq!(PageKind::Singleton as usize, 3);
        assert_eq!(size_of::<PageQueue>(), 32);
        assert_eq!(align_of::<PageQueue>(), 8);
        assert_eq!(offset_of!(PageQueue, first), 0);
        assert_eq!(offset_of!(PageQueue, last), 8);
        assert_eq!(offset_of!(PageQueue, count), 16);
        assert_eq!(offset_of!(PageQueue, block_size), 24);
        assert_eq!(size_of::<Page>(), 128);
        assert_eq!(align_of::<Page>(), 8);
        assert_eq!(offset_of!(Page, self_), 0);
        assert_eq!(offset_of!(Page, xthread_id), 8);
        assert_eq!(offset_of!(Page, free), 16);
        assert_eq!(offset_of!(Page, used), 24);
        assert_eq!(offset_of!(Page, local_free), 32);
        assert_eq!(offset_of!(Page, block_size), 40);
        assert_eq!(offset_of!(Page, page_offset), 48);
        assert_eq!(offset_of!(Page, capacity), 56);
        assert_eq!(offset_of!(Page, reserved), 58);
        assert_eq!(offset_of!(Page, slice_pcommitted), 60);
        assert_eq!(offset_of!(Page, retire_expire), 62);
        assert_eq!(offset_of!(Page, free_is_zero), 63);
        assert_eq!(offset_of!(Page, xthread_free), 64);
        assert_eq!(offset_of!(Page, theap), 72);
        assert_eq!(offset_of!(Page, heap), 80);
        assert_eq!(offset_of!(Page, next), 88);
        assert_eq!(offset_of!(Page, prev), 96);
        assert_eq!(offset_of!(Page, memid), 104);
    }

    #[test]
    fn remote_free_projection_and_live_client_geometry_coexist_with_owner_mutation() {
        const BLOCK_SIZE: usize = 64;
        const PAGE_OFFSET: usize = size_of::<Page>();
        const STORAGE_WORDS: usize = (PAGE_OFFSET + 2 * BLOCK_SIZE) / size_of::<usize>();
        const LIVE_THREAD_ID: usize = 12;

        assert_eq!(PAGE_OFFSET, 128);
        assert_eq!(STORAGE_WORDS * size_of::<usize>(), 256);

        // This address-stable backing contains one source-stride `Page`
        // followed by its two-block area. It adds no metadata wrapper or
        // sidecar: `page_offset` names the actual live block area just as in
        // `free.c:_mi_page_ptr_unalign`.
        let mut storage = [core::mem::MaybeUninit::<usize>::uninit(); STORAGE_WORDS];
        let page_pointer = storage.as_mut_ptr().cast::<Page>();
        let mut initial = Page::remote_free_test_page(2, 1);
        initial.block_size = BLOCK_SIZE;
        initial.page_offset = PAGE_OFFSET;
        initial.xthread_id.store(
            LIVE_THREAD_ID | PAGE_HAS_INTERIOR_POINTERS,
            core::sync::atomic::Ordering::Relaxed,
        );
        // SAFETY: the word-aligned storage is large enough for the complete
        // 128-byte `Page`; it is uninitialized and written exactly once.
        unsafe { page_pointer.write(initial) };
        // SAFETY: `page_pointer` comes from the live backing allocation and
        // cannot be null.
        let page = unsafe { NonNull::new_unchecked(page_pointer) };
        // SAFETY: the initialized geometry above places this two-block area
        // immediately after the page metadata inside the same live storage.
        let first_block = unsafe {
            NonNull::new_unchecked(page_pointer.cast::<u8>().add(PAGE_OFFSET))
        };
        // This interior address represents a still-live aligned client whose
        // allocation keeps both metadata and block storage live through the
        // complete scoped producer operation.
        let client = unsafe { NonNull::new_unchecked(first_block.as_ptr().add(17)) };
        // SAFETY: the fixture is owner-associated, remains initialized and
        // address-stable, and this test never abandons, retires, or releases
        // it. The returned state is used only for its owner-only `used` field.
        let owner = unsafe { Page::remote_free_owner_state_at(page) }
            .expect("the test page begins owner-associated");
        // SAFETY: the same stable fixture permits the producer's atomic-only
        // projection. Keeping this value while `owner` exists must not create
        // a whole-page alias.
        let producer = unsafe { Page::remote_free_producer_state_at(page) };
        let page_address = page.as_ptr().cast::<u8>().addr();
        let xthread_id_address = producer.xthread_id.as_ptr().cast::<u8>().addr();
        let xthread_free_address = producer.xthread_free.as_ptr().cast::<u8>().addr();
        let used_address = owner.used.as_ptr().cast::<u8>().addr();

        assert_eq!(
            xthread_id_address.wrapping_sub(page_address),
            offset_of!(Page, xthread_id),
        );
        assert_eq!(
            xthread_free_address.wrapping_sub(page_address),
            offset_of!(Page, xthread_free),
        );
        assert_eq!(
            used_address.wrapping_sub(page_address),
            offset_of!(Page, used),
        );
        assert_eq!(owner.xthread_free, producer.xthread_free);
        assert_eq!(
            offset_of!(Page, xthread_id) + size_of::<core::sync::atomic::AtomicUsize>(),
            offset_of!(Page, free),
        );
        assert_eq!(
            offset_of!(Page, used) + size_of::<usize>(),
            offset_of!(Page, local_free),
        );
        assert_eq!(
            offset_of!(Page, block_size) + size_of::<usize>(),
            offset_of!(Page, page_offset),
        );
        assert!(
            offset_of!(Page, page_offset) + size_of::<usize>()
                <= offset_of!(Page, xthread_free),
        );
        assert_eq!(
            offset_of!(Page, xthread_free) + size_of::<core::sync::atomic::AtomicUsize>(),
            offset_of!(Page, theap),
        );
        assert!(used_address + size_of::<usize>() <= xthread_free_address);
        assert!(xthread_id_address + size_of::<core::sync::atomic::AtomicUsize>() <= used_address);

        let published_page = std::sync::atomic::AtomicPtr::new(page.as_ptr());
        let published_client = std::sync::atomic::AtomicPtr::new(client.as_ptr());
        let producer_ready = std::sync::Barrier::new(2);
        let owner_finished = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let published_page = &published_page;
            let published_client = &published_client;
            let producer_ready = &producer_ready;
            let owner_finished = &owner_finished;
            scope.spawn(move || {
                let page = NonNull::new(
                    published_page.load(core::sync::atomic::Ordering::Acquire),
                )
                .expect("the scoped page publication remains live");
                let client = NonNull::new(
                    published_client.load(core::sync::atomic::Ordering::Acquire),
                )
                .expect("the scoped live client publication remains live");
                // SAFETY: the scoped storage and exact live client remain
                // valid. This worker retains only raw atomic subobject
                // pointers plus the source-permitted immutable geometry.
                let producer = unsafe { Page::remote_free_producer_state_at(page) };
                producer_ready.wait();
                // SAFETY: the live interior client keeps the page and its
                // fixed `block_size`/`page_offset` geometry alive and
                // unchanged while the owner mutates only `used` below.
                let expected_block = NonNull::new(
                    page.as_ptr().cast::<u8>().wrapping_add(PAGE_OFFSET),
                )
                .expect("the live block area follows its page metadata");
                assert_eq!(
                    unsafe { Page::canonical_remote_block_for_live_client_at(page, client) },
                    Some(expected_block),
                );
                // SAFETY: the projection names initialized atomic source
                // fields. These loads intentionally form no `Page` borrow.
                assert_eq!(
                    unsafe { producer.xthread_id.as_ref() }
                        .load(core::sync::atomic::Ordering::Acquire),
                    LIVE_THREAD_ID | PAGE_HAS_INTERIOR_POINTERS,
                );
                assert_eq!(
                    unsafe { producer.xthread_free.as_ref() }
                        .load(core::sync::atomic::Ordering::Acquire),
                    1,
                );
                owner_finished.wait();
            });

            producer_ready.wait();
            // SAFETY: this test thread is the sole source owner of ordinary
            // mutable page fields. Advancing `used` from one to two models an
            // owner-local allocation while the first live client continues
            // to justify the producer's immutable geometry access.
            unsafe { owner.used.as_ptr().write(2) };
            owner_finished.wait();
        });

        // SAFETY: the scoped producer has joined, and this raw field belongs
        // to the owner-only projection used above.
        assert_eq!(unsafe { owner.used.as_ptr().read() }, 2);
        // SAFETY: all concurrent access has joined; these initialized source
        // geometry fields were immutable throughout the live page lifetime.
        assert_eq!(unsafe { (*page.as_ptr()).block_size }, BLOCK_SIZE);
        assert_eq!(unsafe { (*page.as_ptr()).page_offset }, PAGE_OFFSET);
    }

    fn producer_count_coexists_with_owner_local_alloc_free_and_quick_collect(
        producer_count: usize,
    ) {
        const BLOCK_SIZE: usize = 64;
        const PAGE_OFFSET: usize = size_of::<Page>();
        const MAX_PRODUCERS: usize = 8;
        const MAX_BLOCKS: usize = MAX_PRODUCERS + 1;
        const STORAGE_WORDS: usize =
            (PAGE_OFFSET + MAX_BLOCKS * BLOCK_SIZE) / size_of::<usize>();

        assert!(matches!(producer_count, 1 | 2 | 4 | 8));
        let reserved = u16::try_from(producer_count + 1).expect("bounded block count");
        let mut storage = [MaybeUninit::<usize>::uninit(); STORAGE_WORDS];
        let page_pointer = storage.as_mut_ptr().cast::<Page>();
        let mut initial = Page::remote_free_test_page(reserved, 0);
        initial.capacity = 0;
        initial.block_size = BLOCK_SIZE;
        initial.page_offset = PAGE_OFFSET;
        // SAFETY: the aligned backing has room for the exact source-stride
        // metadata followed by every reserved block and is initialized once.
        unsafe { page_pointer.write(initial) };
        // SAFETY: the backing pointer is non-null and remains stable through
        // all scoped owner and producer operations below.
        let page = unsafe { NonNull::new_unchecked(page_pointer) };
        // SAFETY: this test owner controls the ordinary local-list fields and
        // initially every block. After allocation, the owner keeps only
        // `local_block`; each producer receives one distinct current block and
        // the disjoint atomic projection.
        let mut local = unsafe { LocalFreeList::from_page_at(page) }
            .expect("valid source-stride local-list projection");
        assert_eq!(local.extend().expect("initial source extension"), reserved);

        let published: [std::sync::atomic::AtomicPtr<u8>; MAX_PRODUCERS] =
            std::array::from_fn(|_| std::sync::atomic::AtomicPtr::new(null_mut()));
        for slot in published.iter().take(producer_count) {
            let block = local
                .pop(false)
                .expect("valid remote allocation pop")
                .expect("reserved remote block");
            slot.store(block.as_ptr(), Ordering::Release);
        }
        let local_block = local
            .pop(false)
            .expect("valid owner allocation pop")
            .expect("reserved owner block");
        assert_eq!(local.used(), producer_count + 1);

        // SAFETY: the page is live, associated, and address-stable. Each copy
        // permits only source atomic remote publication for one exact block.
        let producer = unsafe { Page::remote_free_producer_state_at(page) };
        let start = std::sync::Barrier::new(producer_count + 1);
        let producer_fields_ready = std::sync::Barrier::new(producer_count + 1);
        let owner_finished = std::sync::Barrier::new(producer_count + 1);
        std::thread::scope(|scope| {
            for slot in published.iter().take(producer_count) {
                let start = &start;
                let producer_fields_ready = &producer_fields_ready;
                let owner_finished = &owner_finished;
                scope.spawn(move || {
                    let block = NonNull::new(slot.load(Ordering::Acquire))
                        .expect("published exact remote block");
                    start.wait();
                    // SAFETY: these are the initialized atomic subobjects of
                    // the stable source page. Keeping the references live
                    // across the owner's disjoint local-list writes makes the
                    // intended subobject coexistence deterministic.
                    let xthread_id = unsafe { producer.xthread_id.as_ref() };
                    let xthread_free = unsafe { producer.xthread_free.as_ref() };
                    producer_fields_ready.wait();
                    // SAFETY: every worker owns one distinct current block;
                    // the scoped backing remains live and owner-associated.
                    unsafe { remote_free::push(producer, block) }
                        .expect("source remote publication");
                    owner_finished.wait();
                    assert_eq!(
                        xthread_id.load(Ordering::Acquire) & !PAGE_FLAG_MASK,
                        12,
                    );
                    assert_eq!(xthread_free.load(Ordering::Acquire) & 1, 1);
                });
            }

            start.wait();
            producer_fields_ready.wait();
            // Exercise all three owner-local operations while each producer
            // atomic reference is live. The empty immediate list makes every
            // quick collection select exactly the just-freed owner block.
            for _ in 0..(producer_count * 64) {
                // SAFETY: the owner alone controls this exact allocated block
                // and the ordinary `used`/`local_free` fields.
                unsafe { local.push_local(local_block) }
                    .expect("owner local free");
                assert!(local.quick_collect().expect("owner quick collect"));
                assert_eq!(
                    local.pop(false).expect("owner local allocation"),
                    Some(local_block),
                );
            }
            owner_finished.wait();
        });
        drop(local);

        // SAFETY: all producer threads joined; this owner projection now
        // exclusively collects ordinary fields while retaining the owned bit.
        let owner = unsafe { Page::remote_free_owner_state_at(page) }
            .expect("live associated owner state");
        assert_eq!(
            unsafe { remote_free::collect(owner) }.expect("owner remote collection"),
            producer_count,
        );
        // SAFETY: collection and all producer access have ended.
        assert_eq!(unsafe { core::ptr::read(core::ptr::addr_of!((*page.as_ptr()).used)) }, 1);
    }

    #[test]
    fn one_producer_coexists_with_owner_local_alloc_free_and_quick_collect() {
        producer_count_coexists_with_owner_local_alloc_free_and_quick_collect(1);
    }

    #[test]
    fn two_producers_coexist_with_owner_local_alloc_free_and_quick_collect() {
        producer_count_coexists_with_owner_local_alloc_free_and_quick_collect(2);
    }

    #[test]
    fn four_producers_coexist_with_owner_local_alloc_free_and_quick_collect() {
        producer_count_coexists_with_owner_local_alloc_free_and_quick_collect(4);
    }

    #[test]
    fn eight_producers_coexist_with_owner_local_alloc_free_and_quick_collect() {
        producer_count_coexists_with_owner_local_alloc_free_and_quick_collect(8);
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

    fn os_abandoned_test_page(heap: &Heap) -> Page {
        let mut page = Page::empty();
        page.heap = core::ptr::from_ref(heap).cast_mut();
        page
    }

    #[test]
    fn os_abandoned_page_list_inserts_empty_page_at_head() {
        let mut heap = Heap::bootstrap_empty();
        let mut page = os_abandoned_test_page(&heap);
        let page_pointer = core::ptr::addr_of_mut!(page);

        assert_eq!(heap.os_abandoned_pages_are_empty(), Ok(true));
        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut page)) }, Ok(()));
        assert_eq!(heap.os_abandoned_pages_are_empty(), Ok(false));
        assert_eq!(heap.os_abandoned_pages, page_pointer);
        assert!(page.prev.is_null());
        assert!(page.next.is_null());
    }

    #[test]
    fn os_abandoned_page_list_keeps_two_node_order_and_clears_removed_links() {
        let mut heap = Heap::bootstrap_empty();
        let mut first = os_abandoned_test_page(&heap);
        let mut second = os_abandoned_test_page(&heap);
        let first_pointer = core::ptr::addr_of_mut!(first);
        let second_pointer = core::ptr::addr_of_mut!(second);

        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut first)) }, Ok(()));
        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut second)) }, Ok(()));
        assert_eq!(heap.os_abandoned_pages, second_pointer);
        assert!(second.prev.is_null());
        assert_eq!(second.next, first_pointer);
        assert_eq!(first.prev, second_pointer);
        assert!(first.next.is_null());

        assert_eq!(unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut first)) }, Ok(()));
        assert_eq!(heap.os_abandoned_pages, second_pointer);
        assert!(second.prev.is_null());
        assert!(second.next.is_null());
        assert!(first.prev.is_null());
        assert!(first.next.is_null());

        assert_eq!(unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut second)) }, Ok(()));
        assert_eq!(heap.os_abandoned_pages_are_empty(), Ok(true));
        assert!(heap.os_abandoned_pages.is_null());
        assert!(second.prev.is_null());
        assert!(second.next.is_null());
    }

    #[test]
    fn os_abandoned_page_list_rejects_foreign_and_absent_nodes_without_repair() {
        let mut heap = Heap::bootstrap_empty();
        let mut foreign_heap = Heap::bootstrap_empty();
        let mut member = os_abandoned_test_page(&heap);
        let mut foreign = os_abandoned_test_page(&foreign_heap);
        let mut absent = os_abandoned_test_page(&heap);
        let member_pointer = core::ptr::addr_of_mut!(member);

        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut member)) }, Ok(()));
        assert_eq!(
            unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut foreign)) },
            Err(HeapOsAbandonedPageListError::HeapMismatch)
        );
        assert_eq!(
            unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut absent)) },
            Err(HeapOsAbandonedPageListError::Membership)
        );
        assert_eq!(heap.os_abandoned_pages, member_pointer);
        assert!(member.prev.is_null());
        assert!(member.next.is_null());

        assert_eq!(unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut member)) }, Ok(()));
        assert_eq!(
            unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut member)) },
            Err(HeapOsAbandonedPageListError::Membership)
        );
        assert!(heap.os_abandoned_pages.is_null());
        assert!(member.prev.is_null());
        assert!(member.next.is_null());
    }

    #[test]
    fn os_abandoned_page_list_rejects_malformed_predecessor_without_repair() {
        let mut heap = Heap::bootstrap_empty();
        let mut tail = os_abandoned_test_page(&heap);
        let mut middle = os_abandoned_test_page(&heap);
        let mut head = os_abandoned_test_page(&heap);
        let mut forged_predecessor = os_abandoned_test_page(&heap);
        let tail_pointer = core::ptr::addr_of_mut!(tail);
        let middle_pointer = core::ptr::addr_of_mut!(middle);
        let head_pointer = core::ptr::addr_of_mut!(head);
        let forged_pointer = core::ptr::addr_of_mut!(forged_predecessor);

        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut tail)) }, Ok(()));
        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut middle)) }, Ok(()));
        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut head)) }, Ok(()));
        tail.prev = forged_pointer;

        assert_eq!(
            unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut tail)) },
            Err(HeapOsAbandonedPageListError::Predecessor)
        );
        assert_eq!(heap.os_abandoned_pages, head_pointer);
        assert_eq!(head.next, middle_pointer);
        assert_eq!(middle.next, tail_pointer);
        assert_eq!(tail.prev, forged_pointer);
        assert!(forged_predecessor.next.is_null());
    }

    #[test]
    fn os_abandoned_page_list_rejects_malformed_successor_without_repair() {
        let mut heap = Heap::bootstrap_empty();
        let mut tail = os_abandoned_test_page(&heap);
        let mut head = os_abandoned_test_page(&heap);
        let mut forged_successor = os_abandoned_test_page(&heap);
        let tail_pointer = core::ptr::addr_of_mut!(tail);
        let head_pointer = core::ptr::addr_of_mut!(head);
        let forged_pointer = core::ptr::addr_of_mut!(forged_successor);

        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut tail)) }, Ok(()));
        assert_eq!(unsafe { heap.push_os_abandoned_page(NonNull::from(&mut head)) }, Ok(()));
        tail.next = forged_pointer;

        assert_eq!(
            unsafe { heap.remove_os_abandoned_page(NonNull::from(&mut tail)) },
            Err(HeapOsAbandonedPageListError::Successor)
        );
        assert_eq!(heap.os_abandoned_pages, head_pointer);
        assert_eq!(head.next, tail_pointer);
        assert_eq!(tail.next, forged_pointer);
        assert!(forged_successor.prev.is_null());
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
        alias.memid = MemoryId::static_kind_only();
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
