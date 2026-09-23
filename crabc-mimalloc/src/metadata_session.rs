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
use core::ptr::NonNull;

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
        child_theap.initialize_child_metadata(child_heap, parent_tld)
    }

    /// # Safety
    /// The metadata engine entry is exclusive, the child has no clients or
    /// producers, and the exact child Theap allocation remains live. Any
    /// error may follow a list mutation; retain the child owner and do not
    /// retry or release based on this result alone.
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
