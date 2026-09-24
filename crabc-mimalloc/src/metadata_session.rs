// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/init.c:200-205, src/subproc.c:29-67.

//! Detached metadata page ownership on the canonical process main Heap.
//! The session retains raw process-static authority, not a mutable reference
//! spanning source list links. Local mutations project only their own fields.

use super::{Heap, LiveThreadId, MemoryId, Page, PageQueue, Theap, TheapOwner, ThreadLocalData};
use crate::arena::ArenaView;
use crate::bootstrap::{TheapPageSession, theap_page_session_sealed};
use crate::main_theap::MainStaticMetadataHeapLease;
use crate::os::MemoryConfig;
use crate::os_page::OsAlignedPageOwner;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

pub(crate) struct CanonicalMetadataTheapSession {
    theap: NonNull<Theap>,
    /// Identity of the detached parent TLD in the same pinned bootstrap.
    /// This stays raw so the session retains no mutable/shared TLD borrow
    /// across page operations.
    parent_tld: NonNull<ThreadLocalData>,
    heap: MainStaticMetadataHeapLease,
}

impl CanonicalMetadataTheapSession {
    /// # Safety
    /// This is the sole metadata page session for the initialized pinned
    /// detached Theap linked to `heap`. The process metadata entry serializes
    /// every operation. Source list mutation uses its own locks; ordinary
    /// Theap fields have no other reader/writer while projected here. The
    /// process retains the image until this authority is consumed under
    /// permanent quiescence. No whole-image mutable reference may survive.
    pub(crate) unsafe fn new(
        theap: NonNull<Theap>,
        parent_tld: NonNull<ThreadLocalData>,
        heap: MainStaticMetadataHeapLease,
    ) -> Self {
        Self { theap, parent_tld, heap }
    }

    /// # Safety
    /// The metadata engine entry exclusively owns this session and the child
    /// Heap/Theap remain pinned until their memberships are removed.
    /// An error may follow TLD-list attachment and Release publication, so
    /// retain the child owner and do not retry from the error alone.
    pub(crate) unsafe fn initialize_child_metadata_theap(
        &mut self,
        child_heap: &mut Heap,
        child_theap: &mut Theap,
    ) -> Result<(), crate::types::TheapMainStaticInitError> {
        // SAFETY: construction captured this exact TLD from the initialized
        // pinned bootstrap; MetadataEngine serializes every projection, and
        // this method retains no reference after the source operation.
        let parent_tld = unsafe { &mut *self.parent_tld.as_ptr() };
        // SAFETY: construction captured the stable bootstrap TLD, and the
        // caller retains the pinned child Heap/metadata capability through
        // teardown without concurrent list mutation.
        unsafe { child_theap.initialize_child_metadata(child_heap, parent_tld) }
    }

    /// # Safety
    /// The metadata engine entry is exclusive, the child has no clients or
    /// producers, and the exact child Theap allocation remains live. Any
    /// error may follow a list mutation; retain the child owner and do not
    /// retry or release based on this result alone. No Rust reference or
    /// typed projection to the child Theap may remain live during the raw
    /// mutation; reborrow from its capability only after return.
    pub(crate) unsafe fn detach_child_metadata_theap(
        &mut self,
        child_heap: &mut Heap,
        child_theap: NonNull<Theap>,
    ) -> Result<(), crate::types::ChildTheapDetachError> {
        // SAFETY: as above, this is a short local projection guarded by the
        // owning metadata engine entry; no session method stores the borrow.
        let parent_tld = unsafe { &mut *self.parent_tld.as_ptr() };
        // SAFETY: forwarded child image pinning, producer quiescence, and
        // exact-allocation liveness obligations.
        unsafe {
            parent_tld.detach_one_child_theap_for_heap_destroy(
                child_heap,
                child_theap.as_ptr(),
            )
        }
    }
}

impl theap_page_session_sealed::Sealed for CanonicalMetadataTheapSession {}

// SAFETY: construction transfers the sole metadata-local field authority;
// metadata entry serializes all projections and source Heap links have their
// separate interior-mutability/lock boundary. References are scoped to a
// session borrow, so local mutation cannot overlap a returned observation.
unsafe impl TheapPageSession for CanonicalMetadataTheapSession {
    fn theap(&self) -> &Theap { unsafe { self.theap.as_ref() } }
    fn thread_id(&self) -> Option<LiveThreadId> { None }
    fn with_os_random_source<R>(
        &mut self,
        operation: impl FnOnce(&mut (dyn crate::os::OsRandomSource + 'static)) -> R,
    ) -> R {
        // SAFETY: this canonical metadata session is entered only under its
        // serialized MetadataEngine entry and retains this exact initialized
        // Theap through the operation; the adapter projects one field per draw.
        let mut random = unsafe { crate::os::CurrentTheapRandom::new(self.theap) };
        operation(&mut random)
    }
    fn queue(&self, bin: usize) -> Option<&PageQueue> { self.theap().queue(bin) }
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        unsafe { Theap::local_queue_mut_at(self.theap, bin) }
    }
    fn direct_page(&self, index: usize) -> Option<*mut Page> { self.theap().direct_page(index) }
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        unsafe { Theap::set_local_direct_page_at(self.theap, index, page) }
    }
    fn note_page_added(&mut self) { unsafe { Theap::note_local_page_added_at(self.theap); } }
    fn note_page_removed(&mut self) -> bool {
        unsafe { Theap::note_local_page_removed_at(self.theap) }
    }

    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        unsafe { arena.pages().is_some() }
    }
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        if memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() { return false; }
        unsafe { arena.pages() }
            .and_then(|pages| pages.set_range(memory.slice_index as usize, 1))
            .is_some_and(|transition| transition.all_transitioned())
    }
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        if memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() { return false; }
        unsafe { arena.pages() }.and_then(|pages| pages.clear_range(memory.slice_index as usize, 1))
            == Some(true)
    }
    unsafe fn publish_fresh_page(
        &mut self, metadata: NonNull<Page>, block_size: usize, page_offset: usize,
        reserved: u16, slice_pcommitted: u16, free_is_zero: bool, memid: MemoryId,
    ) -> Option<NonNull<Page>> {
        let pointer = self.theap.as_ptr();
        self.heap.with_heap(|heap| unsafe {
            // The whole-Theap borrow lasts only while the shared Heap guard
            // excludes link mutations; no local session observation survives.
            Page::publish_fresh_exclusive_owner_at(metadata, &mut *pointer, heap,
                TheapOwner::Detached, block_size, page_offset, reserved,
                slice_pcommitted, free_is_zero, memid)
        }).ok().flatten()
    }
    fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId> { page.retire_exclusive() }
    fn retired_bounds(&self) -> (usize, usize) { self.theap().retired_bounds() }
    fn note_retired_bin(&mut self, bin: usize) -> bool {
        unsafe { Theap::note_local_retired_bin_at(self.theap, bin) }
    }
    fn reset_retired_bounds(&mut self) {
        unsafe { Theap::reset_local_retired_bounds_at(self.theap); }
    }
    fn retain_unfinished_os_release(&mut self, owner: OsAlignedPageOwner) -> Result<(), OsAlignedPageOwner> {
        Err(owner)
    }
    fn latch_unfinished_page_engine(&mut self) {}
}

/// One child metadata page operation. The caller holds the child's
/// `theap_meta_lock` for this session and keeps the context, metadata-Theap,
/// parent-allocated child Heap, PageMap root, and child arena backing alive.
/// The Heap is retained as a raw identity only: fresh-page association stores
/// its address and must not create `&mut Heap` while child threads may use it.
pub(crate) struct ChildMetadataTheapPageSession<'session, 'image> {
    theap: NonNull<Theap>,
    heap: NonNull<Heap>,
    child: NonNull<crate::subproc::SubprocessIdentity>,
    pending_os_release: &'session mut Option<OsAlignedPageOwner>,
    page_engine: &'session mut crate::meta::ChildPageEngineState,
    metadata_pages_may_exist: &'session mut bool,
    _image: PhantomData<&'image crate::subproc::ChildSubprocessImage>,
}

/// One child thread's ordinary Theap page authority. Unlike
/// `ChildMetadataTheapPageSession`, this page owner has a live child TLD and
/// publishes pages as `TheapOwner::Live`; only the child context owner can
/// retain its exact TLD/Theap metadata blocks through the operation.
pub(crate) struct ChildOrdinaryTheapPageSession<'session, 'image> {
    theap: NonNull<Theap>,
    heap: NonNull<Heap>,
    child: NonNull<crate::subproc::SubprocessIdentity>,
    thread: LiveThreadId,
    pending_os_release: &'session mut Option<OsAlignedPageOwner>,
    page_engine: &'session mut crate::meta::ChildPageEngineState,
    _image: PhantomData<&'image crate::subproc::ChildSubprocessImage>,
}

impl<'session, 'image> ChildOrdinaryTheapPageSession<'session, 'image> {
    /// # Safety
    /// The caller retains the exact child image, ordinary TLD/Theap blocks,
    /// parent-allocated Heap, and mutable lifecycle fields for the operation.
    /// The calling thread is the sole owner of this live Theap, and the child
    /// pair's PageMap lifecycle lease excludes all other map/page writers.
    pub(crate) unsafe fn new(
        child: core::pin::Pin<&'image crate::subproc::ChildSubprocessImage>,
        tld: NonNull<ThreadLocalData>,
        theap: NonNull<Theap>,
        heap: NonNull<Heap>,
        thread: LiveThreadId,
        sequence: crate::types::ThreadSequence,
        pending_os_release: &'session mut Option<OsAlignedPageOwner>,
        page_engine: &'session mut crate::meta::ChildPageEngineState,
    ) -> Option<Self> {
        let identity = child.get_ref().identity();
        // SAFETY: caller's block owners retain both exact images for this
        // bounded projection, and no image reference escapes the session.
        let (tld_ref, theap_ref) = unsafe { (tld.as_ref(), theap.as_ref()) };
        if !identity.is_registered()
            || !identity.matches_ready_main_heap(heap)
            || !tld_ref.matches_subprocess_attached_lifecycle(thread, sequence, identity)
            || !core::ptr::eq(theap_ref.heap.load(Ordering::Acquire), heap.as_ptr())
            || !core::ptr::eq(theap_ref.tld, tld.as_ptr())
            || theap_ref.is_detached()
            || !theap_ref.is_initialized()
            || pending_os_release.is_some()
            || *page_engine != crate::meta::ChildPageEngineState::Active
        {
            return None;
        }
        Some(Self {
            theap,
            heap,
            child: NonNull::from(identity),
            thread,
            pending_os_release,
            page_engine,
            _image: PhantomData,
        })
    }

    #[inline]
    fn theap(&self) -> &Theap {
        // SAFETY: the child-thread owner retains the exact stable Theap and
        // grants this operation exclusive local-field authority.
        unsafe { self.theap.as_ref() }
    }

    /// The Theap this session owns, as an address for field-scoped source
    /// traversals that must not form a whole-Theap borrow.
    #[inline]
    pub(crate) fn theap_pointer(&self) -> NonNull<Theap> { self.theap }
}

impl<'session, 'image> ChildMetadataTheapPageSession<'session, 'image> {
    /// # Safety
    /// The caller owns the exact child metadata lock and projects the pinned
    /// child image, Theap capability, and Heap allocation from one live
    /// `ChildMainHeapContextOwner`. Those owners and both mutable state
    /// references remain exclusive until the session is consumed. No other
    /// operation may project this detached Theap while the lock is held.
    pub(crate) unsafe fn new(
        child: core::pin::Pin<&'image crate::subproc::ChildSubprocessImage>,
        theap: &'session mut Theap,
        heap: NonNull<Heap>,
        pending_os_release: &'session mut Option<OsAlignedPageOwner>,
        page_engine: &'session mut crate::meta::ChildPageEngineState,
        metadata_pages_may_exist: &'session mut bool,
    ) -> Option<Self> {
        let identity = child.get_ref().identity();
        if !identity.matches_ready_main_heap(heap)
            || !identity.matches_published_detached_metadata_theap(NonNull::from(&mut *theap))
            || !theap.is_detached()
            || pending_os_release.is_some()
            || *page_engine != crate::meta::ChildPageEngineState::Active
        {
            return None;
        }
        Some(Self {
            theap: NonNull::from(theap),
            heap,
            child: NonNull::from(identity),
            pending_os_release,
            page_engine,
            metadata_pages_may_exist,
            _image: PhantomData,
        })
    }

    #[inline]
    fn theap(&self) -> &Theap {
        // SAFETY: the child metadata lock and exclusive owner retain this
        // exact initialized image for the complete session operation.
        unsafe { self.theap.as_ref() }
    }
}

impl theap_page_session_sealed::Sealed for ChildMetadataTheapPageSession<'_, '_> {}
impl theap_page_session_sealed::Sealed for ChildOrdinaryTheapPageSession<'_, '_> {}

// SAFETY: the constructor takes the exact child metadata lock and transfers
// unique local-field authority for its detached Theap. Child page backing and
// Heap addresses remain retained by the external owner for the operation.
unsafe impl TheapPageSession for ChildMetadataTheapPageSession<'_, '_> {
    fn theap(&self) -> &Theap { self.theap() }
    fn thread_id(&self) -> Option<LiveThreadId> { None }

    fn with_os_random_source<R>(
        &mut self,
        operation: impl FnOnce(&mut (dyn crate::os::OsRandomSource + 'static)) -> R,
    ) -> R {
        // SAFETY: detached metadata operations serialize this exact Theap;
        // only its initialized random field is projected for each draw.
        let mut random = unsafe { crate::os::CurrentTheapRandom::new(self.theap) };
        operation(&mut random)
    }

    fn queue(&self, bin: usize) -> Option<&PageQueue> { self.theap().queue(bin) }
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        unsafe { Theap::local_queue_mut_at(self.theap, bin) }
    }
    fn direct_page(&self, index: usize) -> Option<*mut Page> { self.theap().direct_page(index) }
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        unsafe { Theap::set_local_direct_page_at(self.theap, index, page) }
    }
    fn note_page_added(&mut self) {
        unsafe { Theap::note_local_page_added_at(self.theap); }
        *self.metadata_pages_may_exist = true;
    }
    fn note_page_removed(&mut self) -> bool {
        let removed = unsafe { Theap::note_local_page_removed_at(self.theap) };
        if removed && self.theap().page_count() == 0 {
            *self.metadata_pages_may_exist = false;
        }
        removed
    }

    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        // `mi_heap_ensure_arena_pages` points the child main Heap at the
        // arena's in-place `pages_main` (`arena.c:699-723`).
        // SAFETY: the session retains the child Heap and the claimed arena.
        unsafe {
            arena.pages().is_some()
                && self.heap.as_ref().ensure_child_main_arena_pages(
                    arena.arena().arena_index,
                    NonNull::from(&arena.arena().pages_main),
                )
        }
    }
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        if memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() { return false; }
        unsafe { arena.pages() }
            .and_then(|pages| pages.set_range(memory.slice_index as usize, 1))
            .is_some_and(|transition| transition.all_transitioned())
    }
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        if memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() { return false; }
        unsafe { arena.pages() }
            .and_then(|pages| pages.clear_range(memory.slice_index as usize, 1))
            == Some(true)
    }

    unsafe fn publish_fresh_page(
        &mut self, metadata: NonNull<Page>, block_size: usize, page_offset: usize,
        reserved: u16, slice_pcommitted: u16, free_is_zero: bool, memid: MemoryId,
    ) -> Option<NonNull<Page>> {
        // SAFETY: page metadata is exclusively held by the fresh claim; the
        // metadata lock grants this Theap, and the child owner retains the
        // stable Heap address without forming an overlapping Heap reference.
        unsafe { Page::publish_fresh_exclusive_owner_at_with_heap_pointer(
            metadata, &mut *self.theap.as_ptr(), self.heap, TheapOwner::Detached,
            block_size, page_offset, reserved, slice_pcommitted, free_is_zero, memid,
        ) }
    }

    fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId> { page.retire_exclusive() }
    fn retired_bounds(&self) -> (usize, usize) { self.theap().retired_bounds() }
    fn note_retired_bin(&mut self, bin: usize) -> bool {
        unsafe { Theap::note_local_retired_bin_at(self.theap, bin) }
    }
    fn reset_retired_bounds(&mut self) {
        unsafe { Theap::reset_local_retired_bounds_at(self.theap); }
    }
    fn retain_unfinished_os_release(
        &mut self,
        owner: OsAlignedPageOwner,
    ) -> Result<(), OsAlignedPageOwner> {
        if self.pending_os_release.is_some()
            || !owner.belongs_to_subprocess(unsafe { self.child.as_ref() })
        {
            return Err(owner);
        }
        let Some(next) = self.page_engine.with_retained_release(owner.raw_retry_ready()) else {
            return Err(owner);
        };
        *self.pending_os_release = Some(owner);
        *self.page_engine = next;
        Ok(())
    }
    fn latch_unfinished_page_engine(&mut self) {
        *self.page_engine = self.page_engine.latch_unfinished();
    }
}

// SAFETY: construction validates the live child TLD/Theap pair and the
// enclosing child-thread owner retains both exact metadata blocks for the
// operation. Only this OS thread mutates the ordinary Theap's local fields.
unsafe impl TheapPageSession for ChildOrdinaryTheapPageSession<'_, '_> {
    fn theap(&self) -> &Theap { self.theap() }
    fn thread_id(&self) -> Option<LiveThreadId> { Some(self.thread) }

    fn with_os_random_source<R>(
        &mut self,
        operation: impl FnOnce(&mut (dyn crate::os::OsRandomSource + 'static)) -> R,
    ) -> R {
        // SAFETY: the live child thread owner uniquely owns this Theap's
        // local random state for the duration of the page operation.
        let mut random = unsafe { crate::os::CurrentTheapRandom::new(self.theap) };
        operation(&mut random)
    }

    fn queue(&self, bin: usize) -> Option<&PageQueue> { self.theap().queue(bin) }
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        unsafe { Theap::local_queue_mut_at(self.theap, bin) }
    }
    fn direct_page(&self, index: usize) -> Option<*mut Page> { self.theap().direct_page(index) }
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        unsafe { Theap::set_local_direct_page_at(self.theap, index, page) }
    }
    fn note_page_added(&mut self) { unsafe { Theap::note_local_page_added_at(self.theap); } }
    fn note_page_removed(&mut self) -> bool {
        unsafe { Theap::note_local_page_removed_at(self.theap) }
    }

    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        // `mi_heap_ensure_arena_pages` points the child main Heap at the
        // arena's in-place `pages_main` (`arena.c:699-723`).
        // SAFETY: the session retains the child Heap and the claimed arena.
        unsafe {
            arena.pages().is_some()
                && self.heap.as_ref().ensure_child_main_arena_pages(
                    arena.arena().arena_index,
                    NonNull::from(&arena.arena().pages_main),
                )
        }
    }
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        if memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() { return false; }
        unsafe { arena.pages() }
            .and_then(|pages| pages.set_range(memory.slice_index as usize, 1))
            .is_some_and(|transition| transition.all_transitioned())
    }
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        if memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() { return false; }
        unsafe { arena.pages() }
            .and_then(|pages| pages.clear_range(memory.slice_index as usize, 1))
            == Some(true)
    }

    unsafe fn publish_fresh_page(
        &mut self,
        metadata: NonNull<Page>,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> Option<NonNull<Page>> {
        // SAFETY: the metadata is exclusively owned by the fresh claim. The
        // child owner retains the stable Heap and live Theap images, and this
        // session publishes the ordinary source owner identity.
        unsafe {
            Page::publish_fresh_exclusive_owner_at_with_heap_pointer(
                metadata,
                &mut *self.theap.as_ptr(),
                self.heap,
                TheapOwner::Live(self.thread),
                block_size,
                page_offset,
                reserved,
                slice_pcommitted,
                free_is_zero,
                memid,
            )
        }
    }

    fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId> { page.retire_exclusive() }
    fn retired_bounds(&self) -> (usize, usize) { self.theap().retired_bounds() }
    fn note_retired_bin(&mut self, bin: usize) -> bool {
        unsafe { Theap::note_local_retired_bin_at(self.theap, bin) }
    }
    fn reset_retired_bounds(&mut self) { unsafe { Theap::reset_local_retired_bounds_at(self.theap); } }

    fn retain_unfinished_os_release(
        &mut self,
        owner: OsAlignedPageOwner,
    ) -> Result<(), OsAlignedPageOwner> {
        if self.pending_os_release.is_some()
            || !owner.belongs_to_subprocess(unsafe { self.child.as_ref() })
        {
            return Err(owner);
        }
        let Some(next) = self.page_engine.with_retained_release(owner.raw_retry_ready()) else {
            return Err(owner);
        };
        *self.pending_os_release = Some(owner);
        *self.page_engine = next;
        Ok(())
    }
    fn latch_unfinished_page_engine(&mut self) {
        *self.page_engine = self.page_engine.latch_unfinished();
    }
}
