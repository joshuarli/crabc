// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:151-157,305-360,377-421`
// (including `mi_thread_theaps_done`) and `src/init.c:448-481`
// (`_mi_thread_done` root/teardown call order), `src/theap.c:228-306,414-449`
// (including `_mi_tld_detach_theaps`), `src/heap.c:37-42,103-126`,
// `src/threadlocal.c:205-214`, and `include/mimalloc/types.h:560-639,690-701`.

//! Process-static first-thread main heap and default-theap attachment.
//!
//! This is intentionally one narrow source branch: the unique ticket-zero
//! `mi_process_tld_main` receives the process-static `mi_process_theap_main`
//! belonging to the process-static main heap. It is neither dynamic TLD/Theap
//! allocation, first-class heap attachment, a subprocess API, nor a pthread
//! hook. The owner is current-thread-only and terminal after teardown or an
//! ambiguous failed lifecycle transition.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::arena::ArenaView;
use crate::bootstrap::{TheapPageSession, theap_page_session_sealed};
use crate::compiler_tls::{
    cached_theap, clear_main_static_attachment_roots, current_thread_identity,
    default_theap, dynamic_backing_peek, fast_slot_peek,
    is_empty_dynamic_backing,
    roots_are_pristine_for_main_static_attachment, set_default_theap,
    set_fast_slot,
};
use crate::subproc::{
    MainStaticBootstrapSelection, MainStaticBootstrapSelectionError,
    MainStaticTldError, MainStaticThreadLocalData, MainSubprocess,
    ThreadRegistrationLease,
};
use crate::lock::{PrivateLock, PrivateLockGuard};
use crate::os::MemoryConfig;
use crate::os_page::OsAlignedPageOwner;
use crate::types::{
    Heap, MemoryId, Page, PageQueue, Theap, TheapMainStaticInitError, TheapOwner,
    ThreadLocalData,
    ThreadLocalDataQuiesceError, ThreadLocalTheapListError,
};

const COLD: u8 = 0;
const HEAP_INITIALIZING: u8 = 1;
const HEAP_READY: u8 = 2;
const THREAD_INITIALIZING: u8 = 3;
const THREAD_READY: u8 = 4;
const TORN_DOWN: u8 = 5;
const POISONED: u8 = 6;

// This is separate from `state`: it records whether a process-lifetime page
// session has made main-image teardown permanently unavailable.  The source
// static images themselves remain process-static, but safe Rust must also
// preserve that logical lifetime when a later thread holds a shared-main Heap
// lease while ticket zero owns page state.
const PROCESS_PAGE_SESSION_COLD: u8 = 0;
const PROCESS_PAGE_SESSION_ACTIVE: u8 = 1;
const PROCESS_PAGE_SESSION_RETAINED: u8 = 2;

/// One cache-aligned heap field slot within the process-static owner.
#[repr(align(64))]
struct MainStaticHeapSlot {
    image: UnsafeCell<Heap>,
}

impl MainStaticHeapSlot {
    const fn new() -> Self {
        Self {
            image: UnsafeCell::new(Heap::bootstrap_empty()),
        }
    }
}

/// One cache-aligned main-theap field slot within the process-static owner.
#[repr(align(64))]
struct MainStaticTheapSlot {
    image: UnsafeCell<Theap>,
}

impl MainStaticTheapSlot {
    const fn new() -> Self {
        Self {
            image: UnsafeCell::new(Theap::empty()),
        }
    }
}

/// Address-stable state for the one process-static main heap/theap pair.
///
/// Its two independently cache-aligned image fields are slots within this one
/// Rust process-static owner, rather than separate Rust/source statics. The
/// atomic state first publishes the static Heap alone, then admits the unique
/// non-Send ticket-zero thread attachment. This preserves the source order in
/// which `mi_heap_main_init_once` precedes `_mi_page_map_init` and only then
/// `_mi_thread_init_with_heap` projects the static TLD/Theap images.
pub(crate) struct MainStaticAttachmentStorage {
    state: AtomicU8,
    heap: MainStaticHeapSlot,
    theap: MainStaticTheapSlot,
    /// Serializes short mutable projections of the process-static main Heap
    /// made by later-thread attachments.  The main attachment itself mutates
    /// the image only after the ticket-zero attachment publishes it or after
    /// every such lease has been relinquished through Rust's borrow boundary.
    ///
    /// This is not a replacement for the source `heap->theaps_lock`: that
    /// lock still owns the intrusive-list publication.  It is the Rust
    /// aliasing boundary that lets later attachments use the source static
    /// Heap without retaining an invalid `&mut Heap` for their lifetime.
    shared_heap_projection_lock: PrivateLock,
    /// Number of fully published later-thread Theaps using the static main
    /// Heap.  It prevents main-image retirement while a live source list
    /// member still points at that image.  Preparation failures which have no
    /// attached Theap never increment this count.
    shared_later_theap_count: AtomicUsize,
    /// A process-lifetime ticket-zero page session has been issued.  It
    /// makes the main static attachment non-tear-downable even after the
    /// session is consumed by an empty engine: copied shared-Heap leases are
    /// then no longer tied to a Rust borrow of the attachment itself.
    process_page_session: AtomicU8,
    #[cfg(test)]
    inject_busy_tld_list_before_initial_attachment: AtomicU8,
}

// SAFETY: `state` serializes the unique Cold -> HeapInitializing -> HeapReady
// -> ThreadInitializing claim. The ticket-zero `!Send` owner projects the
// Theap and attached Heap only during initial setup and terminal teardown. A
// live later-thread attachment can project only `heap`, only while it retains
// `shared_heap_projection_lock` plus a borrow tied to that main owner; source
// heap-list mutation remains under `theaps_lock`. Neither slot is reused
// after teardown or poison. Read-only test observations occur only under the
// same owner or one of those explicit synchronization boundaries.
unsafe impl Sync for MainStaticAttachmentStorage {}

impl MainStaticAttachmentStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(COLD),
            heap: MainStaticHeapSlot::new(),
            theap: MainStaticTheapSlot::new(),
            shared_heap_projection_lock: PrivateLock::new(),
            shared_later_theap_count: AtomicUsize::new(0),
            process_page_session: AtomicU8::new(PROCESS_PAGE_SESSION_COLD),
            #[cfg(test)]
            inject_busy_tld_list_before_initial_attachment: AtomicU8::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_MAIN_STATIC_ATTACHMENT
    }

    #[inline]
    fn claim_cold_for_heap_foundation(&self) -> Result<(), MainStaticHeapFoundationError> {
        self.state
            .compare_exchange(COLD, HEAP_INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| match state {
                HEAP_INITIALIZING | THREAD_INITIALIZING => {
                    MainStaticHeapFoundationError::Initializing
                }
                HEAP_READY | THREAD_READY => MainStaticHeapFoundationError::AlreadyInitialized,
                TORN_DOWN => MainStaticHeapFoundationError::TornDown,
                POISONED | _ => MainStaticHeapFoundationError::Poisoned,
            })
    }

    #[inline]
    fn claim_ready_heap_for_initial_thread(&self) -> Result<(), MainStaticTheapError> {
        self.state
            .compare_exchange(
                HEAP_READY,
                THREAD_INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|state| match state {
                COLD => MainStaticTheapError::HeapNotInitialized,
                HEAP_INITIALIZING | THREAD_INITIALIZING => MainStaticTheapError::Initializing,
                THREAD_READY => MainStaticTheapError::AlreadyAttached,
                HEAP_READY => MainStaticTheapError::Initializing,
                TORN_DOWN => MainStaticTheapError::TornDown,
                POISONED | _ => MainStaticTheapError::Poisoned,
            })
    }

    #[inline]
    fn mark_heap_ready(&self) {
        self.state.store(HEAP_READY, Ordering::Release);
    }

    #[inline]
    fn mark_thread_ready(&self) {
        self.state.store(THREAD_READY, Ordering::Release);
    }

    #[inline]
    fn state_is_heap_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == HEAP_READY
    }

    #[inline]
    fn mark_torn_down(&self) {
        self.state.store(TORN_DOWN, Ordering::Release);
    }

    #[inline]
    fn mark_poisoned(&self) {
        self.state.store(POISONED, Ordering::Release);
    }

    #[inline]
    fn process_page_session_is_cold(&self) -> bool {
        self.process_page_session.load(Ordering::Acquire) == PROCESS_PAGE_SESSION_COLD
    }

    #[inline]
    fn claim_process_page_session(&self) -> bool {
        self.process_page_session
            .compare_exchange(
                PROCESS_PAGE_SESSION_COLD,
                PROCESS_PAGE_SESSION_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    fn retain_process_page_session(&self) {
        self.process_page_session
            .store(PROCESS_PAGE_SESSION_RETAINED, Ordering::Release);
    }

    #[inline]
    unsafe fn heap_mut_for_foundation(&self) -> &mut Heap {
        // SAFETY: the caller owns the sole COLD -> HEAP_INITIALIZING
        // transition and has not yet exposed any static-Heap projection.
        unsafe { &mut *self.heap.image.get() }
    }

    #[inline]
    unsafe fn images_mut(&self) -> (&mut Heap, &mut Theap) {
        // SAFETY: the caller owns the ticket-zero current-thread attachment
        // while it is initializing or doing terminal teardown. Both slots
        // have distinct storage and the Heap foundation was published before
        // this transition.
        unsafe { (&mut *self.heap.image.get(), &mut *self.theap.image.get()) }
    }

    #[cfg(test)]
    #[inline]
    fn heap_address(&self) -> usize {
        self.heap.image.get().addr()
    }

    #[cfg(test)]
    #[inline]
    fn theap_address(&self) -> usize {
        self.theap.image.get().addr()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_shared_later_theap_count(&self) -> usize {
        self.shared_later_theap_count.load(Ordering::Acquire)
    }

    #[cfg(test)]
    #[inline]
    fn test_inject_busy_tld_list_before_initial_attachment(&self) {
        self.inject_busy_tld_list_before_initial_attachment
            .store(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    #[inline]
    fn take_test_busy_tld_list_before_initial_attachment(&self) -> bool {
        self.inject_busy_tld_list_before_initial_attachment
            .swap(0, Ordering::Relaxed)
            != 0
    }
}

/// A failure while publishing the source-static main Heap before PageMap or
/// ticket-zero thread initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticHeapFoundationError {
    /// The selected static bootstrap belongs to another subprocess identity.
    SubprocessMismatch,
    Initializing,
    AlreadyInitialized,
    TornDown,
    Poisoned,
}

/// A stable proof that the static source main Heap exists, but no thread TLD,
/// Theap, compiler-TLS root, process PageMap, or arena has been published by
/// this object alone.
#[derive(Clone, Copy)]
pub(crate) struct MainStaticHeapFoundation {
    storage: &'static MainStaticAttachmentStorage,
    subprocess: &'static MainSubprocess,
}

impl MainStaticHeapFoundation {
    /// Initializes only source `mi_process_heap_main` in its final static
    /// slot. The mutable selection remains live so any later process-init
    /// failure becomes terminal instead of reopening ticket zero.
    pub(crate) fn initialize(
        storage: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        selection: &mut MainStaticBootstrapSelection,
    ) -> Result<Self, MainStaticHeapFoundationError> {
        if !core::ptr::eq(selection.subprocess().as_ptr(), subprocess.as_ptr()) {
            return Err(MainStaticHeapFoundationError::SubprocessMismatch);
        }
        storage.claim_cold_for_heap_foundation()?;
        // SAFETY: the successful state transition grants the sole mutable
        // projection of the final static Heap before any root or TLD exists.
        let heap = unsafe { storage.heap_mut_for_foundation() };
        // `mi_heap_main_init_once` uses `_mi_memid_create(MI_MEM_STATIC)`,
        // not `_mi_memid_create_static`: source heap provenance is kind-only
        // with a zero union/flags.
        heap.initialize_main_static(subprocess, MemoryId::static_kind_only());
        storage.mark_heap_ready();
        selection.commit_heap_foundation();
        Ok(Self { storage, subprocess })
    }

    #[inline]
    pub(crate) const fn subprocess(self) -> &'static MainSubprocess {
        self.subprocess
    }

    #[inline]
    fn storage(self) -> &'static MainStaticAttachmentStorage {
        self.storage
    }

    #[inline]
    fn matches_selection(self, selection: &MainStaticBootstrapSelection) -> bool {
        core::ptr::eq(self.subprocess.as_ptr(), selection.subprocess().as_ptr())
    }

    #[cfg(test)]
    #[inline]
    fn test_heap_is_initialized(self) -> bool {
        self.storage.state_is_heap_ready()
    }
}

/// A borrow-tied capability to make a short synchronized mutable projection
/// of the process-static main heap for one later-thread attachment.
///
/// The capability deliberately carries no raw heap pointer and does not
/// expose a general heap API.  Its lifetime is tied to a live
/// [`MainStaticTheapAttachment`], so safe code cannot begin main-image
/// teardown while a worker can still attach, detach, or retain a Theap that
/// points into that image.  It is Send/Sync only as this narrow process
/// lifetime witness; each caller must still establish a separate current
/// thread/TLD owner before it can mutate the heap.
#[derive(Clone, Copy)]
pub(crate) struct MainStaticHeapLease<'main> {
    storage: &'static MainStaticAttachmentStorage,
    subprocess: &'static MainSubprocess,
    _main_attachment: PhantomData<&'main MainStaticTheapAttachment>,
}

// SAFETY: the lease contains only process-static addresses.  All mutable
// projection of `storage.heap` is serialized by `shared_heap_projection_lock`;
// source intrusive-list mutation remains serialized independently by
// `Heap::theaps_lock`.  Its lifetime borrow prevents safe main attachment
// teardown while another thread retains this capability.
unsafe impl Send for MainStaticHeapLease<'_> {}
// SAFETY: see the Send justification above.  Sharing the capability only
// permits independently synchronized short projections.
unsafe impl Sync for MainStaticHeapLease<'_> {}

/// A temporary mutable view of the static main heap.
///
/// References returned by [`Self::heap_mut`] cannot outlive this guard, and
/// the guard is intentionally !Send through `PrivateLockGuard`.
pub(crate) struct MainStaticHeapGuard<'main> {
    storage: &'static MainStaticAttachmentStorage,
    lock: PrivateLockGuard<'static>,
    // The raw static image remains allocated forever, but this logical
    // borrow is what prevents safe main-image teardown while a caller can
    // still project or release the heap through this guard.
    _main_attachment: PhantomData<&'main MainStaticTheapAttachment>,
}

impl<'main> MainStaticHeapLease<'main> {
    /// Returns the main subprocess identity selected by the ticket-zero
    /// attachment.  Later-thread TLD construction must use this exact
    /// identity rather than a separately chosen process counter.
    #[inline]
    pub(crate) const fn subprocess(self) -> &'static MainSubprocess {
        self.subprocess
    }

    /// Acquires the Rust aliasing guard for one short source heap operation.
    ///
    /// The underlying source heap remains thread-ready for the complete lease
    /// lifetime. The atomic check is retained so unsafe/manual lifecycle
    /// integrations fail closed instead of projecting a retired image.
    pub(crate) fn lock_heap(self) -> Result<MainStaticHeapGuard<'main>, MainStaticHeapLeaseError> {
        let lock = self
            .storage
            .shared_heap_projection_lock
            .lock()
            .map_err(MainStaticHeapLeaseError::Lock)?;
        if self.storage.state.load(Ordering::Acquire) != THREAD_READY {
            drop(lock);
            return Err(MainStaticHeapLeaseError::Inactive);
        }
        Ok(MainStaticHeapGuard {
            storage: self.storage,
            lock,
            _main_attachment: PhantomData,
        })
    }

    /// Records a completed source heap-list publication.  The caller holds
    /// the temporary heap guard and retains the typed Theap/TLD capability;
    /// this counter is therefore only a main-teardown gate, never a second
    /// list or ownership registry.
    #[inline]
    pub(crate) fn note_later_theap_attached(self) -> Result<(), MainStaticHeapLeaseError> {
        if self.storage.state.load(Ordering::Acquire) != THREAD_READY {
            return Err(MainStaticHeapLeaseError::Inactive);
        }
        self.storage
            .shared_later_theap_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| count.checked_add(1))
            .map(|_| ())
            .map_err(|_| MainStaticHeapLeaseError::CountOverflow)
    }

    /// Removes one completed source heap-list member after it has been fully
    /// detached and its metadata/TLD release is no longer observable through
    /// the main Heap.
    #[inline]
    pub(crate) fn note_later_theap_detached(self) -> bool {
        let mut current = self.storage.shared_later_theap_count.load(Ordering::Acquire);
        while current != 0 {
            match self.storage.shared_later_theap_count.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
        false
    }
}

impl MainStaticHeapGuard<'_> {
    /// Projects the stable static main Heap while this guard is held.
    #[inline]
    pub(crate) fn heap_mut(&mut self) -> &mut Heap {
        // SAFETY: `shared_heap_projection_lock` serializes all projections
        // made through a `MainStaticHeapLease`.  The borrow carried by that
        // lease prevents the main attachment from independently projecting
        // or retiring this image in safe code.
        unsafe { &mut *self.storage.heap.image.get() }
    }

    /// Releases the aliasing guard and exposes an unexpected private-futex
    /// wake failure to the lifecycle owner.
    #[inline]
    pub(crate) fn unlock(self) -> Result<(), crabc_core::Errno> {
        self.lock.unlock()
    }
}

/// A failure at the shared process-static heap projection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticHeapLeaseError {
    Inactive,
    CountOverflow,
    Lock(crabc_core::Errno),
}

static PROCESS_MAIN_STATIC_ATTACHMENT: MainStaticAttachmentStorage =
    MainStaticAttachmentStorage::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachmentState {
    Attached,
    TornDown,
    Poisoned,
}

/// One bounded first-thread main static-attachment error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticTheapError {
    InvalidCurrentThread,
    /// The dynamic, fast, default, or cached root was already changed. This
    /// is checked before state claim and before the source ticket is issued.
    RootsNotPristine,
    /// The source static Heap foundation has not been initialized. A
    /// ticket-zero TLD/Theap cannot cross this process-startup boundary.
    HeapNotInitialized,
    Initializing,
    AlreadyAttached,
    TornDown,
    Poisoned,
    HeapFoundation(MainStaticHeapFoundationError),
    BootstrapSelection(MainStaticBootstrapSelectionError),
    /// Default and fast TLS roots were published, but the Rust first-ticket
    /// selector could not publish completion. The static image is retained.
    BootstrapPublication,
    NotFirstTicket,
    MainStaticTld(MainStaticTldError),
    TheapInit(TheapMainStaticInitError),
    /// A later-thread source Theap remains linked to the process-static main
    /// Heap.  Main-image retirement would leave that live list member with a
    /// dangling heap pointer, so this is a non-mutating refusal.
    SharedTheapsLive,
    /// A process-lifetime ticket-zero page session issued one or more
    /// shared-main Heap leases without retaining a Rust borrow of this
    /// attachment.  Its static images must never be torn down or reused.
    ProcessPageSessionLive,
    PageCountNonZero,
    RootOwnership,
    TldOwnership,
    TheapList(ThreadLocalTheapListError),
    TheapClear,
    TldQuiesce(ThreadLocalDataQuiesceError),
}

/// The exact owner of the static main heap/default-theap attachment.
///
/// It owns the consuming ticket-zero TLD projection and its live registration
/// lease. Its raw image addresses are kept only inside private static slots;
/// callers get no independent raw ownership or general heap API. The raw
/// marker makes both the owner and every mutable projection current-thread
/// only.
#[must_use = "the static main default-theap attachment must explicitly tear down"]
pub(crate) struct MainStaticTheapAttachment {
    storage: &'static MainStaticAttachmentStorage,
    subprocess: &'static MainSubprocess,
    thread: crate::types::LiveThreadId,
    tld: Option<MainStaticThreadLocalData>,
    registration: Option<ThreadRegistrationLease>,
    /// One detached OS-aligned singleton release owner retained only when an
    /// unfinished bounded main-static page engine cannot complete its final
    /// unmap. It is intentionally terminal: this attachment has no general
    /// page teardown or OS-release retry entry point yet.
    terminal_os_release: Option<OsAlignedPageOwner>,
    state: AttachmentState,
    _not_send_or_sync: PhantomData<*mut ()>,
    #[cfg(test)]
    inject_busy_before_quiesce: bool,
    #[cfg(test)]
    inject_busy_heap_before_detach: bool,
}

impl MainStaticTheapAttachment {
    /// Validates the current-thread and compiler-TLS conditions which must
    /// hold before process initialization reserves the source ticket-zero
    /// branch. This deliberately changes no source storage or ticket count.
    pub(crate) fn preflight_current_roots() -> Result<(), MainStaticTheapError> {
        current_thread_identity().ok_or(MainStaticTheapError::InvalidCurrentThread)?;
        if !roots_are_pristine_for_main_static_attachment() {
            return Err(MainStaticTheapError::RootsNotPristine);
        }
        i32::try_from(crate::os::numa_node())
            .map_err(|_| MainStaticTheapError::InvalidCurrentThread)?;
        Ok(())
    }

    /// Builds the historical test-only direct transition over isolated
    /// process-lifetime statics. Production code must instead use
    /// `process_init::ProcessMainInitializationStorage`, which inserts the
    /// process PageMap publication between the Heap foundation and this
    /// ticket-zero TLD/Theap attachment.
    #[cfg(test)]
    pub(crate) unsafe fn begin_with_test_storage(
        storage: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
    ) -> Result<Self, MainStaticTheapError> {
        Self::preflight_current_roots()?;
        let mut selection = subprocess.reserve_static_bootstrap().map_err(|error| match error {
            MainStaticBootstrapSelectionError::FirstTicketAlreadyIssued => {
                MainStaticTheapError::NotFirstTicket
            }
            other => MainStaticTheapError::BootstrapSelection(other),
        })?;
        let foundation = MainStaticHeapFoundation::initialize(storage, subprocess, &mut selection)
            .map_err(MainStaticTheapError::HeapFoundation)?;
        // SAFETY: the test owns the current-thread lifecycle and retains all
        // leaked source-image fixtures for the attachment's whole lifetime.
        unsafe { Self::begin_after_heap_foundation(foundation, selection) }
    }

    /// Attaches the source-static ticket-zero TLD/Theap only after a selected
    /// main Heap foundation and the process coordinator's intervening work.
    ///
    /// # Safety
    ///
    /// The caller must own this thread's allocator lifecycle, retain the
    /// returned owner until `teardown`, and establish all source process-init
    /// stages between `foundation` and this attachment. In particular, it
    /// must have either published the selected process PageMap or retained an
    /// explicit initialization failure; it must not create a competing TLD,
    /// mutate compiler-TLS roots, move the returned owner, or retain raw
    /// aliases to the static images.
    pub(crate) unsafe fn begin_after_heap_foundation(
        foundation: MainStaticHeapFoundation,
        mut selection: MainStaticBootstrapSelection,
    ) -> Result<Self, MainStaticTheapError> {
        if !foundation.matches_selection(&selection) {
            return Err(MainStaticTheapError::BootstrapSelection(
                MainStaticBootstrapSelectionError::Retained,
            ));
        }
        Self::preflight_current_roots()?;
        let storage = foundation.storage();
        let subprocess = foundation.subprocess();
        let thread = current_thread_identity().ok_or(MainStaticTheapError::InvalidCurrentThread)?;
        let numa = i32::try_from(crate::os::numa_node())
            .map_err(|_| MainStaticTheapError::InvalidCurrentThread)?;
        storage.claim_ready_heap_for_initial_thread()?;

        let ticket = selection.issue_first_ticket().map_err(|error| {
            storage.mark_poisoned();
            match error {
                MainStaticBootstrapSelectionError::FirstTicketAlreadyIssued => {
                    MainStaticTheapError::NotFirstTicket
                }
                other => MainStaticTheapError::BootstrapSelection(other),
            }
        })?;
        let (mut tld, registration) = ticket
            .initialize_and_activate_first_main_tld(thread, numa)
            .map_err(|error| {
                storage.mark_poisoned();
                MainStaticTheapError::MainStaticTld(error)
            })?;

        #[cfg(test)]
        if storage.take_test_busy_tld_list_before_initial_attachment() {
            // The registration above is intentionally already live. This
            // non-aliasing fixture makes the otherwise-fresh list lock busy
            // immediately before `_mi_theap_init` would attach it.
            tld.current_mut().test_inject_busy_theaps_lock();
        }

        // SAFETY: the static state is THREAD_INITIALIZING, the Heap foundation
        // was initialized in its final slot, and this function has not exposed
        // a TLD/Theap capability or TLS root. The owner fields have distinct,
        // independently cache-aligned final static addresses.
        let (heap, theap) = unsafe { storage.images_mut() };
        let theap_memid = MemoryId::static_allocation(
            core::ptr::from_mut(theap).cast(),
            size_of::<Theap>(),
        );
        if !theap.set_main_static_memid(theap_memid) {
            storage.mark_poisoned();
            return Err(MainStaticTheapError::TheapInit(
                TheapMainStaticInitError::InvalidInput,
            ));
        }
        if let Err(error) = theap.initialize_main_static(heap, tld.current_mut()) {
            // Initialization has already created the source-static TLD and
            // live registration, but has no returned attachment capability
            // that can safely tear either down. A busy fresh list lock, a
            // post-mutation unlock error, or a later heap-list error requires
            // invalid concurrency/kernel failure outside the source contract.
            // This is terminal initialization-invalid-owner state: leave the
            // TLD/static storage and live count retained, do not invent
            // rollback, and reject every retry.
            storage.mark_poisoned();
            return Err(MainStaticTheapError::TheapInit(error));
        }

        let theap_pointer = NonNull::from(&mut *theap);
        // Source `_mi_thread_init_with_heap` writes the default root first and
        // only then writes the main heap's fixed fast-key root. Cached remains
        // the empty static theap and dynamic TLS remains its empty image.
        set_default_theap(theap_pointer);
        set_fast_slot(Some(theap_pointer.cast()));
        storage.mark_thread_ready();
        if !selection.complete_initial_thread() {
            storage.mark_poisoned();
            return Err(MainStaticTheapError::BootstrapPublication);
        }

        Ok(Self {
            storage,
            subprocess,
            thread,
            tld: Some(tld),
            registration: Some(registration),
            terminal_os_release: None,
            state: AttachmentState::Attached,
            _not_send_or_sync: PhantomData,
            #[cfg(test)]
            inject_busy_before_quiesce: false,
            #[cfg(test)]
            inject_busy_heap_before_detach: false,
        })
    }

    /// Returns the live main TLD only while all source ownership and current
    /// thread checks still hold.
    pub(crate) fn tld(&mut self) -> Result<&ThreadLocalData, MainStaticTheapError> {
        self.ensure_current()?;
        if !self.tld_matches_subprocess() {
            self.poison();
            return Err(MainStaticTheapError::TldOwnership);
        }
        let tld = self
            .tld
            .as_mut()
            .ok_or(MainStaticTheapError::Poisoned)?
            .current_mut();
        Ok(tld)
    }

    /// Returns the selected process-main identity while the ticket-zero
    /// attachment remains current and live. Page-bearing callers use this
    /// only to reject a mismatched process map/arena pair before borrowing
    /// any static image.
    #[inline]
    pub(crate) fn subprocess(&self) -> Result<&'static MainSubprocess, MainStaticTheapError> {
        self.ensure_current()?;
        if self.storage.state.load(Ordering::Acquire) != THREAD_READY {
            return Err(MainStaticTheapError::Poisoned);
        }
        Ok(self.subprocess)
    }

    /// Borrows the live process-static main Heap for source-shaped
    /// later-thread attachment work.
    ///
    /// The returned capability is deliberately narrower than a heap pointer:
    /// it grants only short locked mutable projections and keeps this main
    /// attachment immutably borrowed.  That makes a later thread's
    /// `theap->heap` lifetime explicit without giving it permission to alter
    /// ticket-zero roots, the main TLD, or process-static image ownership.
    pub(crate) fn shared_main_heap_lease(
        &self,
    ) -> Result<MainStaticHeapLease<'_>, MainStaticTheapError> {
        self.ensure_current()?;
        if self.storage.state.load(Ordering::Acquire) != THREAD_READY {
            return Err(MainStaticTheapError::Poisoned);
        }
        Ok(MainStaticHeapLease {
            storage: self.storage,
            subprocess: self.subprocess,
            _main_attachment: PhantomData,
        })
    }

    /// Borrows this exact ticket-zero owner as the bounded static page
    /// session. The mutable borrow keeps the TLD, static Heap/Theap images,
    /// compiler-TLS roots, and main teardown authority alive for every page
    /// and scoped remote producer admitted by the shared page engine.
    pub(crate) fn page_session(
        &mut self,
    ) -> Result<MainStaticPageSession<'_>, MainStaticPageSessionError> {
        MainStaticPageSession::begin(self)
    }

    /// Converts the ticket-zero page authority into one permanent
    /// process-lifetime session.
    ///
    /// Unlike [`Self::page_session`], the returned session does not retain a
    /// Rust borrow of this attachment. It instead permanently closes this
    /// attachment's teardown boundary, allowing its explicitly derived
    /// shared-main Heap lease to outlive the call and serve later no-page
    /// thread attachments. Every Heap projection made by the session remains
    /// under `shared_heap_projection_lock`; it never permits a second plain
    /// PageMap lifecycle or a second ticket-zero Theap.
    pub(crate) fn begin_process_lifetime_page_session(
        &self,
    ) -> Result<MainStaticProcessPageSession, MainStaticProcessPageSessionError> {
        self.ensure_current()
            .map_err(|error| MainStaticProcessPageSessionError::Session(
                MainStaticPageSessionError::Attachment(error),
            ))?;
        if !self.storage.process_page_session_is_cold() {
            return Err(MainStaticProcessPageSessionError::AlreadyStarted);
        }
        if self
            .storage
            .shared_later_theap_count
            .load(Ordering::Acquire)
            != 0
        {
            return Err(MainStaticProcessPageSessionError::Session(
                MainStaticPageSessionError::SharedTheapsLive,
            ));
        }
        let theap_pointer = self.storage.theap.image.get();
        if !core::ptr::eq(default_theap().as_ptr(), theap_pointer)
            || fast_slot_peek().map_or(true, |fast| fast.as_ptr().cast::<Theap>() != theap_pointer)
            || !core::ptr::eq(cached_theap().as_ptr(), crate::bootstrap::empty_default_theap_ptr())
            || !matches!(dynamic_backing_peek(), Some(backing) if is_empty_dynamic_backing(backing))
        {
            self.storage.mark_poisoned();
            return Err(MainStaticProcessPageSessionError::Session(
                MainStaticPageSessionError::RootOwnership,
            ));
        }
        // SAFETY: this path provides neither a mutable page-session borrow
        // nor a mutable Heap projection. It checks the immutable ticket-zero
        // images before atomically claiming the permanent page authority, so
        // the already-issued shared-main Heap lease remains a valid witness.
        let heap = unsafe { &*self.storage.heap.image.get() };
        let theap = unsafe { &*self.storage.theap.image.get() };
        if !heap.is_bound_to_main_subprocess(self.subprocess)
            || !theap.is_initialized()
            || !theap.matches_thread(self.thread)
            || !theap.is_bound_to_main_subprocess(self.subprocess)
            || !core::ptr::eq(theap.heap(), self.storage.heap.image.get())
            || theap.page_count() != 0
        {
            self.storage.mark_poisoned();
            return Err(MainStaticProcessPageSessionError::Session(
                MainStaticPageSessionError::ImageOwnership,
            ));
        }
        if !self.storage.claim_process_page_session() {
            return Err(MainStaticProcessPageSessionError::AlreadyStarted);
        }
        Ok(MainStaticProcessPageSession {
            storage: self.storage,
            subprocess: self.subprocess,
            thread: self.thread,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Validates that this ticket-zero attachment can begin a fresh page
    /// session without retaining that borrow.
    ///
    /// A source fresh-arena owner needs this before it maps its first arena:
    /// if the current roots, static images, or zero-page precondition are not
    /// valid, it must reject without publishing a new process arena. The
    /// returned unit capability deliberately carries no mutable image or page
    /// access; the caller must acquire its matching PageMap lifecycle and then
    /// call [`Self::page_session`] again to form the actual engine.
    #[inline]
    pub(crate) fn preflight_fresh_page_session(
        &mut self,
    ) -> Result<(), MainStaticPageSessionError> {
        MainStaticPageSession::begin(self).map(|_| ())
    }

    /// Performs the bounded source teardown order for the one static main
    /// theap: require no pages, clear only owned TLS roots, detach heap then
    /// TLD lists, clear terminal theap links/random state, invalidate TLD,
    /// prove its now-empty private lock quiescent, release its live
    /// registration, and retire the source-static TLD slot.  Quiescence comes
    /// first so a poisoned busy-lock boundary cannot decrement the live count
    /// while the static TLD storage remains unretired.
    pub(crate) fn teardown(&mut self) -> Result<(), MainStaticTheapError> {
        self.ensure_current()?;
        if !self.tld_matches_subprocess() {
            self.poison();
            return Err(MainStaticTheapError::TldOwnership);
        }
        if self
            .storage
            .shared_later_theap_count
            .load(Ordering::Acquire)
            != 0
        {
            // This is deliberately pre-root and pre-list mutation. A shared
            // heap lease can only exist while this owner is immutably
            // borrowed in safe Rust, but retain the runtime counter as the
            // final guard for future pthread-owned storage.
            return Err(MainStaticTheapError::SharedTheapsLive);
        }
        if !self.storage.process_page_session_is_cold() {
            return Err(MainStaticTheapError::ProcessPageSessionLive);
        }

        // SAFETY: the attached capability is unique and current-thread-only.
        // Both static images remain valid for the whole process.
        let (heap, theap) = unsafe { self.storage.images_mut() };
        let theap_pointer = core::ptr::from_mut(theap);
        if !core::ptr::eq(default_theap().as_ptr(), theap_pointer)
            || fast_slot_peek().map_or(true, |fast| fast.as_ptr().cast::<Theap>() != theap_pointer)
            || !core::ptr::eq(cached_theap().as_ptr(), crate::bootstrap::empty_default_theap_ptr())
            || !matches!(dynamic_backing_peek(), Some(backing) if is_empty_dynamic_backing(backing))
        {
            self.poison();
            return Err(MainStaticTheapError::RootOwnership);
        }

        if theap.page_count() != 0 {
            // This pre-root rejection preserves every live root/list/image
            // and registration exactly. It is terminal because page routing
            // is absent, but it must not imitate any teardown publication.
            self.poison();
            return Err(MainStaticTheapError::PageCountNonZero);
        }

        // This helper intentionally leaves the immutable count-zero dynamic
        // backing untouched; see `threadlocal.c:205-214`.
        clear_main_static_attachment_roots();

        #[cfg(test)]
        let inject_busy_heap_before_detach = self.inject_busy_heap_before_detach;
        let heap_detach = {
            let tld = self
                .tld
                .as_mut()
                .ok_or(MainStaticTheapError::Poisoned)?
                .current_mut();
            #[cfg(test)]
            if inject_busy_heap_before_detach {
                heap.test_inject_busy_theaps_lock();
            }
            tld.detach_one_theap_from_heap(heap, theap_pointer)
        };
        if let Err(error) = heap_detach {
            // The source roots are already reset. A fallible private lock or
            // list boundary cannot occur in C and is a terminal invalid-owner
            // state here; static images and their live registration remain.
            self.poison();
            return Err(MainStaticTheapError::TheapList(error));
        }
        let tld_detach = {
            let tld = self
                .tld
                .as_mut()
                .ok_or(MainStaticTheapError::Poisoned)?
                .current_mut();
            tld.detach_one_theap_from_tld(theap_pointer)
        };
        if let Err(error) = tld_detach {
            // As above, this is post-root-reset terminal invalid-owner state.
            self.poison();
            return Err(MainStaticTheapError::TheapList(error));
        }
        if !theap.clear_main_static_after_detach() {
            self.poison();
            return Err(MainStaticTheapError::TheapClear);
        }

        let quiesce = {
            let tld = self
                .tld
                .as_mut()
                .ok_or(MainStaticTheapError::Poisoned)?
                .current_mut();
            tld.invalidate_attached_theap_for_teardown();
            #[cfg(test)]
            if self.inject_busy_before_quiesce {
                tld.test_inject_busy_theaps_lock();
            }
            tld.quiesce_theap_list_lock_for_teardown()
        };
        if let Err(error) = quiesce {
            self.poison();
            return Err(MainStaticTheapError::TldQuiesce(error));
        }
        let registration = self
            .registration
            .take()
            .ok_or(MainStaticTheapError::Poisoned)?;
        registration.release();
        let tld = self.tld.take().ok_or(MainStaticTheapError::Poisoned)?;
        tld.retire();
        self.state = AttachmentState::TornDown;
        self.storage.mark_torn_down();
        Ok(())
    }

    #[inline]
    fn ensure_current(&self) -> Result<(), MainStaticTheapError> {
        match self.state {
            AttachmentState::Attached => {
                if self.storage.state.load(Ordering::Acquire) != THREAD_READY {
                    return Err(MainStaticTheapError::Poisoned);
                }
                match current_thread_identity() {
                    Some(thread) if thread == self.thread => Ok(()),
                    Some(_) | None => Err(MainStaticTheapError::InvalidCurrentThread),
                }
            }
            AttachmentState::TornDown => Err(MainStaticTheapError::TornDown),
            AttachmentState::Poisoned => Err(MainStaticTheapError::Poisoned),
        }
    }

    #[inline]
    fn poison(&mut self) {
        self.state = AttachmentState::Poisoned;
        self.storage.mark_poisoned();
    }

    #[inline]
    fn tld_matches_subprocess(&mut self) -> bool {
        self.tld.as_mut().is_some_and(|storage| {
            storage
                .current_mut()
                .is_attached_to_main_subprocess(self.subprocess)
        })
    }

    #[cfg(test)]
    pub(crate) fn test_theap_pointer(&self) -> *mut Theap {
        self.storage.theap.image.get()
    }

    #[cfg(test)]
    pub(crate) fn test_heap_pointer(&self) -> *mut Heap {
        self.storage.heap.image.get()
    }

    #[cfg(test)]
    pub(crate) fn test_images(&mut self) -> (&Heap, &Theap) {
        // SAFETY: test callers retain the unique attached owner and request
        // only shared observations of its address-stable static images.
        let (heap, theap) = unsafe { self.storage.images_mut() };
        (&*heap, &*theap)
    }

    #[cfg(test)]
    fn test_add_page_for_teardown_failure(&mut self) {
        // SAFETY: exact test-only violated teardown fixture; no page metadata
        // or queue is created, so the resulting terminal poison leaks nothing
        // beyond its isolated static test image.
        let (_, theap) = unsafe { self.storage.images_mut() };
        theap.note_page_added();
    }

    #[cfg(test)]
    fn test_tld_has_theap_head(&mut self, theap: *mut Theap) -> bool {
        self.tld
            .as_mut()
            .expect("the injected page-count failure retains the live TLD")
            .current_mut()
            .test_theap_head_is(theap)
    }

    #[cfg(test)]
    fn test_inject_busy_before_quiesce(&mut self) {
        self.inject_busy_before_quiesce = true;
    }

    #[cfg(test)]
    fn test_inject_busy_heap_before_detach(&mut self) {
        self.inject_busy_heap_before_detach = true;
    }
}

/// A rejection while borrowing the ticket-zero static owner for one complete
/// process-page lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticPageSessionError {
    Attachment(MainStaticTheapError),
    /// Compiler-TLS roots no longer name the exact static Theap/default
    /// image. This is terminal because a page engine could otherwise publish
    /// a page owned by a stale root.
    RootOwnership,
    /// The static Heap, Theap, or TLD no longer form the source main-thread
    /// image expected by `mi_heap_ensure_arena_pages`.
    ImageOwnership,
    /// A later shared-main Theap remains linked. This is a non-mutating
    /// refusal: source main-page mutation cannot safely overlap that broader
    /// unfinished lifecycle in this bounded port.
    SharedTheapsLive,
    /// A process-lifetime ticket-zero page session already owns the static
    /// page authority. A borrowed session must not recreate a competing
    /// mutable view even after its engine becomes empty.
    ProcessPageSessionLive,
}

/// Borrowed page-owner view of the static ticket-zero Theap.
///
/// It is intentionally constructed only by [`MainStaticTheapAttachment`]. A
/// typed process page/arena pair separately proves the selected PageMap and
/// arena identity; this session supplies the source main Heap distinction:
/// fresh pages install the arena's embedded `pages_main`, never a dynamic
/// `mi_arena_pages_t` image.
pub(crate) struct MainStaticPageSession<'main> {
    attachment: &'main mut MainStaticTheapAttachment,
}

impl<'main> MainStaticPageSession<'main> {
    fn begin(
        attachment: &'main mut MainStaticTheapAttachment,
    ) -> Result<Self, MainStaticPageSessionError> {
        attachment
            .ensure_current()
            .map_err(MainStaticPageSessionError::Attachment)?;
        if !attachment.storage.process_page_session_is_cold() {
            return Err(MainStaticPageSessionError::ProcessPageSessionLive);
        }
        if attachment
            .storage
            .shared_later_theap_count
            .load(Ordering::Acquire)
            != 0
        {
            return Err(MainStaticPageSessionError::SharedTheapsLive);
        }
        if !attachment.tld_matches_subprocess() {
            attachment.poison();
            return Err(MainStaticPageSessionError::ImageOwnership);
        }

        let theap_pointer = attachment.storage.theap.image.get();
        if !core::ptr::eq(default_theap().as_ptr(), theap_pointer)
            || fast_slot_peek().map_or(true, |fast| fast.as_ptr().cast::<Theap>() != theap_pointer)
            || !core::ptr::eq(cached_theap().as_ptr(), crate::bootstrap::empty_default_theap_ptr())
            || !matches!(dynamic_backing_peek(), Some(backing) if is_empty_dynamic_backing(backing))
        {
            attachment.poison();
            return Err(MainStaticPageSessionError::RootOwnership);
        }

        // SAFETY: the unique mutable attachment borrow excludes a safe shared
        // main-heap lease or a second page session. The images remain static
        // for the process lifetime and are initialized before attachment
        // READY publication.
        let (heap, theap) = unsafe { attachment.storage.images_mut() };
        if !heap.is_bound_to_main_subprocess(attachment.subprocess)
            || !theap.is_initialized()
            || !theap.matches_thread(attachment.thread)
            || !theap.is_bound_to_main_subprocess(attachment.subprocess)
            || !core::ptr::eq(theap.heap(), core::ptr::from_mut(heap))
            || theap.page_count() != 0
        {
            attachment.poison();
            return Err(MainStaticPageSessionError::ImageOwnership);
        }
        Ok(Self { attachment })
    }

    /// The source static main TLD consumes the old total-thread count zero.
    #[inline]
    pub(crate) const fn thread_sequence(&self) -> usize { 0 }

    #[inline]
    fn theap(&self) -> &Theap {
        // SAFETY: session construction took the attachment's unique mutable
        // borrow; the static image is initialized and cannot move.
        unsafe { &*self.attachment.storage.theap.image.get() }
    }

    #[inline]
    fn theap_mut(&mut self) -> &mut Theap {
        // SAFETY: see `Self::theap`; all page/queue mutation remains inside
        // this one page-session lifetime.
        unsafe { &mut *self.attachment.storage.theap.image.get() }
    }

    #[inline]
    fn heap(&self) -> &Heap {
        // SAFETY: the static Heap shares the same session exclusivity proof.
        unsafe { &*self.attachment.storage.heap.image.get() }
    }

}

impl theap_page_session_sealed::Sealed for MainStaticPageSession<'_> {}

/// A failure while converting ticket zero into its permanent page owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticProcessPageSessionError {
    /// The normal borrowed-session preconditions did not hold before the
    /// irreversible process-lifetime claim.
    Session(MainStaticPageSessionError),
    /// A process-lifetime static page session was already issued. Reusing the
    /// source static Theap would create a competing mutable owner.
    AlreadyStarted,
}

/// A process-lifetime, ticket-zero page owner which can coexist with copied
/// shared-main Heap leases.
///
/// This is not a second main attachment and it is not a general concurrent
/// page allocator. It owns only the static main Theap on its original thread.
/// Its claim permanently closes main-image teardown, while each Heap touch is
/// reduced to a short `shared_heap_projection_lock` critical section. That
/// distinction permits later *no-page* TLD/Theap lifecycle work to retain its
/// source list member without handing either owner an aliased `&mut Heap`.
#[must_use = "a process-lifetime static page session permanently closes main-image teardown"]
pub(crate) struct MainStaticProcessPageSession {
    storage: &'static MainStaticAttachmentStorage,
    subprocess: &'static MainSubprocess,
    thread: crate::types::LiveThreadId,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl MainStaticProcessPageSession {
    /// The source static main TLD consumes the old total-thread count zero.
    #[inline]
    pub(crate) const fn thread_sequence(&self) -> usize { 0 }

    /// Returns a permanently valid shared-main Heap lease.
    ///
    /// The session's irreversible storage claim makes this lifetime honest:
    /// `MainStaticTheapAttachment::teardown` now rejects before changing any
    /// root, list, or image, and a dropped/unfinished session remains
    /// terminally retained rather than reopening the static slot.
    #[inline]
    pub(crate) fn shared_main_heap_lease(&self) -> MainStaticHeapLease<'static> {
        debug_assert_eq!(
            self.storage.process_page_session.load(Ordering::Acquire),
            PROCESS_PAGE_SESSION_ACTIVE
        );
        MainStaticHeapLease {
            storage: self.storage,
            subprocess: self.subprocess,
            _main_attachment: PhantomData,
        }
    }

    /// Returns the exact process identity validated before this permanent
    /// session claimed the ticket-zero static image.
    #[inline]
    pub(crate) const fn subprocess(&self) -> &'static MainSubprocess {
        self.subprocess
    }

    /// Rechecks the narrow empty-ticket-zero precondition immediately before
    /// a lazy first-arena owner maps memory.
    ///
    /// A later no-page attachment has disjoint TLS/Theap state and may have
    /// linked and detached in the interim. It cannot change these ticket-zero
    /// roots, images, or page count. Any contrary observation is terminal:
    /// the permanent session must not reserve a process arena around a stale
    /// static image.
    pub(crate) fn preflight_fresh_page_session(&self) -> bool {
        if !self.is_current() {
            self.latch();
            return false;
        }
        let theap_pointer = self.storage.theap.image.get();
        if !core::ptr::eq(default_theap().as_ptr(), theap_pointer)
            || fast_slot_peek().map_or(true, |fast| fast.as_ptr().cast::<Theap>() != theap_pointer)
            || !core::ptr::eq(cached_theap().as_ptr(), crate::bootstrap::empty_default_theap_ptr())
            || !matches!(dynamic_backing_peek(), Some(backing) if is_empty_dynamic_backing(backing))
        {
            self.latch();
            return false;
        }
        // SAFETY: this session is the sole ticket-zero static-Theap owner,
        // and every shared Heap operation is separately short-locked.
        let heap = unsafe { &*self.storage.heap.image.get() };
        let theap = self.theap();
        if !heap.is_bound_to_main_subprocess(self.subprocess)
            || !theap.is_initialized()
            || !theap.matches_thread(self.thread)
            || !theap.is_bound_to_main_subprocess(self.subprocess)
            || !core::ptr::eq(theap.heap(), self.storage.heap.image.get())
            || theap.page_count() != 0
        {
            self.latch();
            return false;
        }
        true
    }

    /// Leaves the permanent static-image owner terminally retained without
    /// dropping its source state. Runtime startup uses this when a failed
    /// first-arena transition cannot safely be retried.
    #[inline]
    pub(crate) fn retain_terminal(&self) { self.latch() }

    #[inline]
    fn is_current(&self) -> bool {
        current_thread_identity().is_some_and(|current| current == self.thread)
            && self.storage.state.load(Ordering::Acquire) == THREAD_READY
            && self.storage.process_page_session.load(Ordering::Acquire)
                == PROCESS_PAGE_SESSION_ACTIVE
    }

    #[inline]
    fn theap(&self) -> &Theap {
        // SAFETY: construction proves this is the unique ticket-zero page
        // owner. Main teardown is permanently closed before the session is
        // exposed, and later attachments never project this static Theap.
        unsafe { &*self.storage.theap.image.get() }
    }

    #[inline]
    fn theap_mut(&mut self) -> &mut Theap {
        // SAFETY: see `Self::theap`; the !Send session remains on the exact
        // ticket-zero thread and is the only page owner of this Theap.
        unsafe { &mut *self.storage.theap.image.get() }
    }

    /// Runs one short static-Heap operation while no later thread can create
    /// an aliased mutable projection. The returned result includes the lock's
    /// post-release wake outcome because a visible source mutation cannot be
    /// rolled back after that boundary.
    fn with_heap<R>(&self, operation: impl FnOnce(&Heap) -> R) -> Result<R, crabc_core::Errno> {
        let guard = self.storage.shared_heap_projection_lock.lock()?;
        if self.storage.state.load(Ordering::Acquire) != THREAD_READY
            || self.storage.process_page_session.load(Ordering::Acquire)
                != PROCESS_PAGE_SESSION_ACTIVE
        {
            drop(guard);
            return Err(crabc_core::Errno::INVAL);
        }
        // SAFETY: the projection lock excludes every `MainStaticHeapLease`
        // mutable view. This operation receives only `&Heap`, so it cannot
        // modify the heap outside source-owned interior locks.
        let heap = unsafe { &*self.storage.heap.image.get() };
        let result = operation(heap);
        guard.unlock().map(|_| result)
    }

    #[inline]
    fn latch(&self) {
        self.storage.retain_process_page_session();
    }
}

impl Drop for MainStaticProcessPageSession {
    fn drop(&mut self) {
        // A session can be consumed by a page engine. If that engine is
        // dropped unfinished, retain the logical process-static owner rather
        // than permitting a later safe teardown to mistake its images for an
        // empty borrowed attachment.
        self.storage.retain_process_page_session();
    }
}

impl theap_page_session_sealed::Sealed for MainStaticProcessPageSession {}

/// Marker for the two exact ticket-zero sessions that select the source main
/// Heap's in-place arena bitmap. It keeps the page engine constructor closed
/// to dynamic and bootstrap Theaps while allowing the process-lifetime owner
/// to use the same source allocation mechanics as the borrowed owner.
pub(crate) trait MainStaticTheapPageSession: TheapPageSession {}

impl MainStaticTheapPageSession for MainStaticPageSession<'_> {}
impl MainStaticTheapPageSession for MainStaticProcessPageSession {}

// SAFETY: construction verifies the exact current ticket-zero roots and the
// static TLD/Theap/Heap relation, then retains `&mut MainStaticTheapAttachment`
// for the complete page engine/remote-producer lifetime. The paired process
// map mutation lease supplies the separate exclusion required for PageMap
// plain entries; this session selects only the arena's embedded main bitmap.
unsafe impl TheapPageSession for MainStaticPageSession<'_> {
    #[inline]
    fn theap(&self) -> &Theap { Self::theap(self) }

    #[inline]
    fn thread_id(&self) -> Option<crate::types::LiveThreadId> {
        Some(self.attachment.thread)
    }

    #[inline]
    fn queue(&self, bin: usize) -> Option<&PageQueue> { self.theap().queue(bin) }

    #[inline]
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        self.theap_mut().queue_mut(bin)
    }

    #[inline]
    fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.theap().direct_page(index)
    }

    #[inline]
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        self.theap_mut().set_direct_page(index, page)
    }

    #[inline]
    fn note_page_added(&mut self) { self.theap_mut().note_page_added() }

    #[inline]
    fn note_page_removed(&mut self) -> bool { self.theap_mut().note_page_removed() }

    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        let pages = NonNull::from(&arena.arena().pages_main);
        match self.heap().install_main_arena_pages(
            self.attachment.subprocess,
            arena.arena().arena_index,
            pages,
        ) {
            Ok(()) => true,
            Err(_) => {
                // A failed static slot installation can follow a visible
                // Release store or reveal a foreign main bitmap. The bounded
                // static owner has no rollback/rebinding protocol.
                self.attachment.poison();
                false
            }
        }
    }

    #[inline]
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if arena_memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() {
            return false;
        }
        // SAFETY: this static session owns the matching fresh-page lifecycle
        // and has installed exactly the arena's embedded `pages_main` slot.
        unsafe { arena.pages() }
            .and_then(|pages| pages.set_range(arena_memory.slice_index as usize, 1))
            .is_some_and(|transition| transition.all_transitioned())
    }

    #[inline]
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if arena_memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() {
            return false;
        }
        // The generic engine unregisters the complete map span before this
        // matching source main-bitmap clear and arena-slice release.
        unsafe { arena.pages() }
            .and_then(|pages| pages.clear_range(arena_memory.slice_index as usize, 1))
            == Some(true)
    }

    #[inline]
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
        let thread = self.attachment.thread;
        let (heap, theap) = unsafe { self.attachment.storage.images_mut() };
        // SAFETY: the caller retains the page-engine raw metadata/area proof;
        // this session owns the exact static live Theap/Heap pair for its
        // complete source page lifecycle.
        unsafe {
            Page::publish_fresh_exclusive_owner_at(
                metadata,
                theap,
                heap,
                TheapOwner::Live(thread),
                block_size,
                page_offset,
                reserved,
                slice_pcommitted,
                free_is_zero,
                memid,
            )
        }
    }

    #[inline]
    fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId> { page.retire_exclusive() }

    #[inline]
    fn retired_bounds(&self) -> (usize, usize) { self.theap().retired_bounds() }

    #[inline]
    fn note_retired_bin(&mut self, bin: usize) -> bool {
        self.theap_mut().note_retired_bin(bin)
    }

    #[inline]
    fn reset_retired_bounds(&mut self) { self.theap_mut().reset_retired_bounds() }

    fn retain_unfinished_os_release(
        &mut self,
        owner: OsAlignedPageOwner,
    ) -> Result<(), OsAlignedPageOwner> {
        if self.attachment.terminal_os_release.is_some() {
            return Err(owner);
        }
        self.attachment.terminal_os_release = Some(owner);
        Ok(())
    }

    #[inline]
    fn latch_unfinished_page_engine(&mut self) {
        self.attachment.poison();
    }
}

// SAFETY: construction first runs the ordinary ticket-zero root/image/page
// checks, then atomically and irreversibly closes main-image teardown. The
// session is !Send and current-thread checked for every Heap operation. Its
// static Theap is never projected by a later attachment; every shared static
// Heap access is serialized through `shared_heap_projection_lock`, while the
// paired process map lease remains the separate plain PageMap exclusion.
unsafe impl TheapPageSession for MainStaticProcessPageSession {
    #[inline]
    fn theap(&self) -> &Theap { Self::theap(self) }

    #[inline]
    fn thread_id(&self) -> Option<crate::types::LiveThreadId> {
        self.is_current().then_some(self.thread)
    }

    #[inline]
    fn queue(&self, bin: usize) -> Option<&PageQueue> {
        self.is_current().then(|| self.theap().queue(bin)).flatten()
    }

    #[inline]
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        self.is_current().then(|| self.theap_mut().queue_mut(bin)).flatten()
    }

    #[inline]
    fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.is_current().then(|| self.theap().direct_page(index)).flatten()
    }

    #[inline]
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        self.is_current()
            && self
                .theap_mut()
                .set_direct_page(index, page)
    }

    #[inline]
    fn note_page_added(&mut self) {
        if self.is_current() {
            self.theap_mut().note_page_added();
        }
    }

    #[inline]
    fn note_page_removed(&mut self) -> bool {
        self.is_current() && self.theap_mut().note_page_removed()
    }

    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        if !self.is_current() {
            self.latch();
            return false;
        }
        let pages = NonNull::from(&arena.arena().pages_main);
        let installed = self.with_heap(|heap| {
            heap.install_main_arena_pages(self.subprocess, arena.arena().arena_index, pages)
        });
        match installed {
            Ok(Ok(())) => true,
            Ok(Err(_)) | Err(_) => {
                // The source in-place bitmap slot can have become visible
                // before a lock wake error or a foreign-image refusal. This
                // permanent session has no rebind/rollback transition.
                self.latch();
                false
            }
        }
    }

    #[inline]
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if !self.is_current()
            || arena_memory.arena != core::ptr::from_ref(arena.arena()).cast_mut()
        {
            return false;
        }
        // SAFETY: this exact process-lifetime session owns the static main
        // Theap and the outer engine owns the matching PageMap lifecycle.
        unsafe { arena.pages() }
            .and_then(|pages| pages.set_range(arena_memory.slice_index as usize, 1))
            .is_some_and(|transition| transition.all_transitioned())
    }

    #[inline]
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if !self.is_current()
            || arena_memory.arena != core::ptr::from_ref(arena.arena()).cast_mut()
        {
            return false;
        }
        // The generic engine unregisters the complete map span before this
        // matching source main-bitmap clear and arena-slice release.
        unsafe { arena.pages() }
            .and_then(|pages| pages.clear_range(arena_memory.slice_index as usize, 1))
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
        if !self.is_current() {
            self.latch();
            return None;
        }
        let thread = self.thread;
        let theap = self.storage.theap.image.get();
        let published = self.with_heap(|heap| {
            // SAFETY: this process-lifetime session is the sole mutable
            // projection of the static ticket-zero Theap. The raw pointer is
            // formed before the independent short Heap-lock borrow so the
            // closure never aliases `self` itself.
            let theap = unsafe { &mut *theap };
            // SAFETY: the engine forwarded the raw metadata/block-area proof;
            // this session owns the matching static Theap, and the short heap
            // lock permits only this shared address association.
            unsafe {
                Page::publish_fresh_exclusive_owner_at(
                    metadata,
                    theap,
                    heap,
                    TheapOwner::Live(thread),
                    block_size,
                    page_offset,
                    reserved,
                    slice_pcommitted,
                    free_is_zero,
                    memid,
                )
            }
        });
        match published {
            Ok(page) => page,
            Err(_) => {
                self.latch();
                None
            }
        }
    }

    #[inline]
    fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId> { page.retire_exclusive() }

    #[inline]
    fn retired_bounds(&self) -> (usize, usize) {
        if self.is_current() {
            self.theap().retired_bounds()
        } else {
            (0, 0)
        }
    }

    #[inline]
    fn note_retired_bin(&mut self, bin: usize) -> bool {
        self.is_current() && self.theap_mut().note_retired_bin(bin)
    }

    #[inline]
    fn reset_retired_bounds(&mut self) {
        if self.is_current() {
            self.theap_mut().reset_retired_bounds();
        }
    }

    #[inline]
    fn retain_unfinished_os_release(
        &mut self,
        owner: OsAlignedPageOwner,
    ) -> Result<(), OsAlignedPageOwner> {
        // The generic engine retains its exact pending OS owner in the
        // terminal wrapper returned to the caller. This permanent session has
        // no independent retry registry and must not drop or duplicate it.
        Err(owner)
    }

    #[inline]
    fn latch_unfinished_page_engine(&mut self) { self.latch() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::empty_default_theap_ptr;
    use crate::compiler_tls::{
        is_empty_dynamic_backing, roots_are_pristine_for_main_static_attachment,
        set_cached_theap, set_default_theap,
    };
    use crate::meta::MetaAllocator;
    use crate::os::{MemoryConfig, PageSize, fault, numa_node};
    use crate::tld::ThreadLocalDataOwner;
    use crate::types::{HeapTheapListError, MemoryKind};
    use std::thread;

    fn fixture() -> (&'static MainStaticAttachmentStorage, &'static MainSubprocess) {
        (
            MainStaticAttachmentStorage::test_static_owner(),
            MainSubprocess::test_static_owner(),
        )
    }

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the pinned native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    #[test]
    fn static_heap_foundation_precedes_ticket_zero_tld_theap_and_tls_roots() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            MainStaticTheapAttachment::preflight_current_roots()
                .expect("a fresh test thread has pristine static roots");
            let mut selection = subprocess
                .reserve_static_bootstrap()
                .expect("the cold subprocess selects the static source branch");
            let foundation = MainStaticHeapFoundation::initialize(storage, subprocess, &mut selection)
                .expect("the source main Heap initializes before PageMap/thread setup");

            assert!(foundation.test_heap_is_initialized());
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(roots_are_pristine_for_main_static_attachment());
            let (heap, theap) = unsafe { storage.images_mut() };
            assert!(heap.is_bound_to_main_subprocess(subprocess));
            assert!(!theap.is_initialized());
            assert!(theap.heap().is_null());

            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_after_heap_foundation(foundation, selection)
            }
            .expect("the delayed ticket-zero source attachment succeeds");
            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
            owner.teardown().expect("the static owner tears down normally");
        })
        .join()
        .expect("heap-foundation test thread completes");
    }

    #[test]
    fn ticket_zero_static_attachment_keeps_source_images_lists_roots_and_release_witness() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            assert_eq!(storage.heap_address() & 63, 0);
            assert_eq!(storage.theap_address() & 63, 0);
            let identity = current_thread_identity().expect("native TPIDR_EL0 identity");
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the first ticket attaches process-static images");

            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
            {
                let tld = owner.tld().expect("main TLD remains current");
                assert_eq!(tld.thread_id(), identity.get());
                assert_eq!(tld.thread_sequence().get(), 0);
                assert_eq!(tld.numa_node(), i32::try_from(numa_node()).unwrap());
                assert_eq!(tld.memory_id().kind(), MemoryKind::Static);
                assert!(tld.memory_id().is_pinned());
            }

            let theap_pointer = owner.test_theap_pointer();
            let heap_pointer = owner.test_heap_pointer();
            let (heap, theap) = owner.test_images();
            let heap_fields = heap.test_main_static_fields();
            assert_eq!(heap_fields.heap_seq, 0);
            assert_eq!(heap_fields.theap_slot, 1);
            assert_eq!(heap_fields.numa_node, -1);
            assert!(!heap_fields.has_exclusive_arena);
            assert!(!heap_fields.theaps_empty);
            assert_eq!(heap_fields.memid.kind(), MemoryKind::Static);
            let heap_memory = heap_fields.memid.static_memory().unwrap();
            assert_eq!(heap_memory.base, core::ptr::null_mut());
            assert_eq!(heap_memory.size, 0);
            assert!(!heap_fields.memid.is_pinned());
            assert!(!heap_fields.memid.initially_committed());
            assert!(!heap_fields.memid.initially_zero());
            assert!(heap.test_theap_head_is(theap_pointer));
            let theap_fields = theap.test_main_static_fields();
            // A non-null heap is the source initialized predicate. These
            // observations therefore witness every preceding field before its
            // Release publication, including random/cookie/list state.
            assert!(theap_fields.initialized);
            assert_eq!(theap.heap(), heap_pointer);
            assert_eq!(theap_fields.refcount, 1);
            assert!(theap_fields.cookie_is_odd);
            assert!(theap_fields.random_initialized);
            assert!(!theap_fields.random_weak);
            assert_eq!(theap_fields.page_full_retain, 2);
            assert!(theap_fields.allows_page_reclaim);
            assert!(theap_fields.allows_page_abandon);
            assert!(!theap_fields.detached);
            assert_eq!(theap_fields.memid.kind(), MemoryKind::Static);
            assert!(theap_fields.memid.is_pinned());
            assert!(theap_fields.memid.initially_committed());
            assert!(!theap_fields.memid.initially_zero());
            assert_eq!(theap_fields.memid.static_memory().unwrap().base, theap_pointer.cast());
            assert!(owner
                .tld()
                .expect("main TLD remains current for list witness")
                .test_theap_head_is(theap_pointer));
            assert_eq!(default_theap().as_ptr(), theap_pointer);
            assert_eq!(fast_slot_peek().unwrap().as_ptr().cast::<Theap>(), theap_pointer);
            assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));

            owner.teardown().expect("static attachment tears down exactly once");
            assert_eq!(subprocess.live_thread_count(), 0);
            assert_eq!(default_theap().as_ptr(), empty_default_theap_ptr());
            assert!(fast_slot_peek().is_none());
            assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            assert_eq!(owner.teardown(), Err(MainStaticTheapError::TornDown));
        })
        .join()
        .expect("static attachment test thread completes");
    }

    #[test]
    fn wrong_roots_reject_before_ticket_and_repeat_observes_published_roots() {
        thread::spawn(|| {
            let (wrong_storage, wrong_subprocess) = fixture();
            let mut foreign = Theap::empty();
            set_default_theap(NonNull::from(&mut foreign));
            assert!(matches!(
                unsafe {
                    MainStaticTheapAttachment::begin_with_test_storage(
                        wrong_storage,
                        wrong_subprocess,
                    )
                },
                Err(MainStaticTheapError::RootsNotPristine)
            ));
            assert_eq!(wrong_subprocess.total_thread_count(), 0);
            assert_eq!(wrong_subprocess.live_thread_count(), 0);
            set_default_theap(NonNull::new(empty_default_theap_ptr()).unwrap());

            let (storage, subprocess) = fixture();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("first attachment succeeds");
            assert!(matches!(
                unsafe { MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess) },
                Err(MainStaticTheapError::RootsNotPristine)
            ));
            assert_eq!(subprocess.total_thread_count(), 1);
            owner.teardown().expect("first owner remains the sole teardown authority");
        })
        .join()
        .expect("root-rejection test thread completes");
    }

    #[test]
    fn generic_first_ticket_rejects_static_selection_without_aliasing_or_live_count_error() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut generic = unsafe {
                ThreadLocalDataOwner::begin_with_test_metadata(
                    subprocess,
                    metadata,
                    memory_config(),
                )
            }
            .expect("the generic owner can consume process ticket zero");
            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
            assert!(roots_are_pristine_for_main_static_attachment());

            assert!(matches!(
                unsafe { MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess) },
                Err(MainStaticTheapError::NotFirstTicket)
            ));
            assert_eq!(
                subprocess.total_thread_count(),
                1,
                "the selector rejects static startup before it can consume a second ticket"
            );
            assert_eq!(
                subprocess.live_thread_count(),
                1,
                "the rejected static path never manufactures a registration"
            );
            assert!(roots_are_pristine_for_main_static_attachment());
            let (heap, theap) = unsafe { storage.images_mut() };
            assert_eq!(heap.test_main_static_fields().memid.kind(), MemoryKind::None);
            assert!(!theap.is_initialized());

            generic
                .teardown()
                .expect("the actual generic ticket-zero owner remains responsible");
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join()
        .expect("generic-first ticket conflict test completes");
    }

    #[test]
    fn busy_tld_list_during_initial_attachment_poison_retains_static_tld_registration() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            storage.test_inject_busy_tld_list_before_initial_attachment();

            assert!(matches!(
                unsafe { MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess) },
                Err(MainStaticTheapError::TheapInit(
                    TheapMainStaticInitError::ThreadList(ThreadLocalTheapListError::Busy)
                ))
            ));
            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(
                subprocess.live_thread_count(),
                1,
                "the initialized static TLD keeps its source registration"
            );
            assert!(roots_are_pristine_for_main_static_attachment());
            let (heap, theap) = unsafe { storage.images_mut() };
            assert!(
                heap.test_main_static_fields().theaps_empty,
                "the heap list was not published"
            );
            assert!(!theap.is_initialized());
            assert!(theap.heap().is_null());
            assert!(matches!(
                unsafe { MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess) },
                Err(MainStaticTheapError::BootstrapSelection(
                    MainStaticBootstrapSelectionError::Retained
                ))
            ));
            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
        })
        .join()
        .expect("initial-attachment terminal poison test completes");
    }

    #[test]
    fn ticket_zero_static_path_touches_neither_metadata_mapping_nor_dynamic_backing() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero uses only process-static storage");
            assert_eq!(fault.observed(), 0, "no metadata/page-map path is reached");
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            owner.teardown().expect("static owner tears down after map seam check");
        })
        .join()
        .expect("metadata-free static path test completes");
    }

    #[test]
    fn entropy_failure_keeps_the_static_attachment_live_with_weak_random() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let fault = fault::install(fault::Plan::at(
                fault::Point::Entropy,
                1,
                crabc_core::Errno::NOMEM,
            ));
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("weak entropy remains a live source-compatible attachment");
            assert_eq!(fault.observed(), 1);
            assert!(owner.test_images().1.test_main_static_fields().random_weak);
            owner.teardown().expect("weak attachment tears down normally");
        })
        .join()
        .expect("weak entropy attachment test completes");
    }

    #[test]
    fn nonzero_page_count_poison_does_not_lie_about_live_static_storage() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("static attachment succeeds before injected page count");
            let heap_pointer = owner.test_heap_pointer();
            let theap_pointer = owner.test_theap_pointer();
            owner.test_add_page_for_teardown_failure();
            assert_eq!(owner.teardown(), Err(MainStaticTheapError::PageCountNonZero));
            assert_eq!(default_theap().as_ptr(), theap_pointer);
            assert_eq!(fast_slot_peek().unwrap().as_ptr().cast::<Theap>(), theap_pointer);
            assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            let (heap, theap) = owner.test_images();
            assert!(heap.test_theap_head_is(theap_pointer));
            assert!(theap.test_main_static_fields().initialized);
            assert_eq!(theap.heap(), heap_pointer);
            assert!(owner.test_tld_has_theap_head(theap_pointer));
            assert_eq!(subprocess.live_thread_count(), 1);
            assert_eq!(owner.teardown(), Err(MainStaticTheapError::Poisoned));
        })
        .join()
        .expect("terminal poison preserves live registration test completes");
    }

    #[test]
    fn root_ownership_mismatch_poison_retains_foreign_root_and_live_registration() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("static attachment succeeds before external cached-root mutation");
            let theap_pointer = owner.test_theap_pointer();
            let mut foreign = Theap::empty();
            let foreign_pointer = NonNull::from(&mut foreign);
            set_cached_theap(foreign_pointer);

            assert_eq!(owner.teardown(), Err(MainStaticTheapError::RootOwnership));
            assert_eq!(cached_theap(), foreign_pointer);
            assert_eq!(default_theap().as_ptr(), theap_pointer);
            assert_eq!(fast_slot_peek().unwrap().as_ptr().cast::<Theap>(), theap_pointer);
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            let (heap, theap) = owner.test_images();
            assert!(heap.test_theap_head_is(theap_pointer));
            assert!(theap.test_main_static_fields().initialized);
            assert!(owner.test_tld_has_theap_head(theap_pointer));
            assert_eq!(subprocess.live_thread_count(), 1);
            assert_eq!(owner.teardown(), Err(MainStaticTheapError::Poisoned));
            // The preceding assertion proves teardown did not overwrite the
            // foreign root. Restore this test thread's immutable empty root
            // before `foreign` leaves scope, without making the poisoned
            // owner reusable or changing its retained registration.
            set_cached_theap(NonNull::new(empty_default_theap_ptr()).unwrap());
        })
        .join()
        .expect("foreign-root ownership failure test completes");
    }

    #[test]
    fn busy_heap_lock_after_root_reset_poison_retains_lists_and_live_registration() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("static attachment succeeds before a terminal heap-lock violation");
            let theap_pointer = owner.test_theap_pointer();
            let heap_pointer = owner.test_heap_pointer();
            owner.test_inject_busy_heap_before_detach();
            assert_eq!(
                owner.teardown(),
                Err(MainStaticTheapError::TheapList(
                    ThreadLocalTheapListError::Heap(HeapTheapListError::Busy)
                ))
            );
            assert_eq!(default_theap().as_ptr(), empty_default_theap_ptr());
            assert!(fast_slot_peek().is_none());
            assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            let (heap, theap) = owner.test_images();
            assert!(heap.test_theap_head_is(theap_pointer));
            assert!(theap.test_main_static_fields().initialized);
            assert_eq!(theap.heap(), heap_pointer);
            assert!(owner.test_tld_has_theap_head(theap_pointer));
            assert_eq!(subprocess.live_thread_count(), 1);
            assert_eq!(owner.teardown(), Err(MainStaticTheapError::Poisoned));
        })
        .join()
        .expect("busy heap-lock terminal-poison test completes");
    }

    #[test]
    fn post_detach_busy_tld_lock_poison_retains_the_live_registration() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("static attachment succeeds before a terminal lock violation");
            owner.test_inject_busy_before_quiesce();
            assert_eq!(
                owner.teardown(),
                Err(MainStaticTheapError::TldQuiesce(
                    ThreadLocalDataQuiesceError::Busy
                ))
            );
            assert_eq!(
                subprocess.live_thread_count(),
                1,
                "unretired static TLD retains its live source registration"
            );
            assert_eq!(owner.teardown(), Err(MainStaticTheapError::Poisoned));
        })
        .join()
        .expect("busy-lock terminal-poison test completes");
    }
}
