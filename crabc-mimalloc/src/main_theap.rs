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
use core::sync::atomic::{AtomicU8, Ordering};

use crate::compiler_tls::{
    cached_theap, clear_main_static_attachment_roots, current_thread_identity,
    default_theap, dynamic_backing_peek, fast_slot_peek,
    is_empty_dynamic_backing,
    roots_are_pristine_for_main_static_attachment, set_default_theap,
    set_fast_slot,
};
use crate::subproc::{
    MainStaticTldError, MainStaticThreadLocalData, MainSubprocess,
    ThreadRegistrationLease,
};
use crate::types::{
    Heap, MemoryId, Theap, TheapMainStaticInitError, ThreadLocalData,
    ThreadLocalDataQuiesceError, ThreadLocalTheapListError,
};

const COLD: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const TORN_DOWN: u8 = 3;
const POISONED: u8 = 4;

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
/// atomic state is the only shared entry path; a successful caller obtains the
/// unique non-Send attachment capability before either `UnsafeCell` is
/// projected mutably.
struct MainStaticAttachmentStorage {
    state: AtomicU8,
    heap: MainStaticHeapSlot,
    theap: MainStaticTheapSlot,
    #[cfg(test)]
    inject_busy_tld_list_before_initial_attachment: AtomicU8,
}

// SAFETY: `state` serializes the unique Cold -> Initializing claim. Only the
// resulting `!Send` current-thread owner projects either image mutably; after
// teardown or poison neither slot is reused. Read-only test observations occur
// only under that same owner or after terminal completion.
unsafe impl Sync for MainStaticAttachmentStorage {}

impl MainStaticAttachmentStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(COLD),
            heap: MainStaticHeapSlot::new(),
            theap: MainStaticTheapSlot::new(),
            #[cfg(test)]
            inject_busy_tld_list_before_initial_attachment: AtomicU8::new(0),
        }
    }

    #[cfg(test)]
    fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    #[inline]
    fn claim_cold(&self) -> Result<(), MainStaticTheapError> {
        self.state
            .compare_exchange(COLD, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| match state {
                INITIALIZING => MainStaticTheapError::Initializing,
                READY => MainStaticTheapError::AlreadyAttached,
                TORN_DOWN => MainStaticTheapError::TornDown,
                POISONED => MainStaticTheapError::Poisoned,
                _ => MainStaticTheapError::Poisoned,
            })
    }

    #[inline]
    fn reject_non_cold_before_root_read(&self) -> Result<(), MainStaticTheapError> {
        match self.state.load(Ordering::Acquire) {
            COLD => Ok(()),
            INITIALIZING => Err(MainStaticTheapError::Initializing),
            READY => Err(MainStaticTheapError::AlreadyAttached),
            TORN_DOWN => Err(MainStaticTheapError::TornDown),
            POISONED | _ => Err(MainStaticTheapError::Poisoned),
        }
    }

    #[inline]
    fn mark_ready(&self) {
        self.state.store(READY, Ordering::Release);
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
    unsafe fn images_mut(&self) -> (&mut Heap, &mut Theap) {
        // SAFETY: the caller owns the one current-thread attachment capability
        // created after `claim_cold`, or it is performing its sole setup before
        // that capability escapes. Both slots have distinct storage.
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
    Initializing,
    AlreadyAttached,
    TornDown,
    Poisoned,
    NotFirstTicket,
    MainStaticTld(MainStaticTldError),
    TheapInit(TheapMainStaticInitError),
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
    state: AttachmentState,
    _not_send_or_sync: PhantomData<*mut ()>,
    #[cfg(test)]
    inject_busy_before_quiesce: bool,
    #[cfg(test)]
    inject_busy_heap_before_detach: bool,
}

impl MainStaticTheapAttachment {
    /// Attaches the actual process-static main TLD to the process-static main
    /// heap/theap pair.
    ///
    /// # Safety
    ///
    /// The caller must own this thread's allocator lifecycle and the
    /// process-bootstrap selection of this `MainSubprocess`'s sole ticket
    /// zero. In particular, it must call this path before any generic
    /// [`crate::tld::ThreadLocalDataOwner`] could consume that ticket. No
    /// shared process-init authority arbitrates those generic and static
    /// choices in this slice. It must not create a competing TLD or mutate any
    /// compiler-TLS root while this capability is live, move the capability to
    /// another thread, retain raw aliases to its static images, or skip
    /// [`Self::teardown`]. This is a bounded first-ticket path, not a
    /// replacement for later dynamic TLD and first-class heap attachment.
    pub(crate) unsafe fn begin() -> Result<Self, MainStaticTheapError> {
        // SAFETY: forwarded to the common static-store constructor. The
        // process singleton and process-main identity have matching lifetime.
        unsafe {
            Self::begin_with_storage(
                &PROCESS_MAIN_STATIC_ATTACHMENT,
                MainSubprocess::global(),
            )
        }
    }

    /// Builds the same source transition over isolated leaked test statics.
    #[cfg(test)]
    unsafe fn begin_with_test_storage(
        storage: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
    ) -> Result<Self, MainStaticTheapError> {
        // SAFETY: test callers carry the same current-thread exclusivity
        // contract as production and retain both leaked fixtures indefinitely.
        unsafe { Self::begin_with_storage(storage, subprocess) }
    }

    unsafe fn begin_with_storage(
        storage: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
    ) -> Result<Self, MainStaticTheapError> {
        let thread = current_thread_identity().ok_or(MainStaticTheapError::InvalidCurrentThread)?;
        // A repeat or terminal process-static image is rejected before reading
        // the live roots. That leaves a ready attachment distinguishable from
        // a cold store with foreign roots, and neither case consumes a ticket.
        storage.reject_non_cold_before_root_read()?;
        // This root check deliberately precedes both static state claim and
        // `thread_total_count` ticket issuance. A wrong root is a pure
        // rejection: it cannot consume the source sequence or static storage.
        if !roots_are_pristine_for_main_static_attachment() {
            return Err(MainStaticTheapError::RootsNotPristine);
        }
        // The source observes NUMA during TLD initialization, but this pure
        // range validation has no allocation or source state effect. Keeping
        // it before the state claim/ticket makes an impossible out-of-range
        // observation a true pre-ticket rejection instead of stranding the
        // static owner in INITIALIZING.
        let numa = i32::try_from(crate::os::numa_node())
            .map_err(|_| MainStaticTheapError::InvalidCurrentThread)?;
        storage.claim_cold()?;

        let ticket = subprocess.issue_thread_ticket();
        if !ticket.is_first_main_tld() {
            storage.mark_poisoned();
            return Err(MainStaticTheapError::NotFirstTicket);
        }
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

        // SAFETY: the static state is INITIALIZING and this function has not
        // exposed a capability or TLS root. The owner fields have distinct,
        // independently cache-aligned final static addresses.
        let (heap, theap) = unsafe { storage.images_mut() };
        // `mi_heap_main_init_once` uses `_mi_memid_create(MI_MEM_STATIC)`,
        // not `_mi_memid_create_static`: heap provenance is kind-only with a
        // zero union/flags. The source TLD and Theap keep their concrete
        // static image memids below/inside their respective initializers.
        let heap_memid = MemoryId::static_kind_only();
        heap.initialize_main_static(subprocess, heap_memid);
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
        storage.mark_ready();

        Ok(Self {
            storage,
            subprocess,
            thread,
            tld: Some(tld),
            registration: Some(registration),
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
            AttachmentState::Attached => match current_thread_identity() {
                Some(thread) if thread == self.thread => Ok(()),
                Some(_) | None => Err(MainStaticTheapError::InvalidCurrentThread),
            },
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
    fn test_theap_pointer(&self) -> *mut Theap {
        self.storage.theap.image.get()
    }

    #[cfg(test)]
    fn test_heap_pointer(&self) -> *mut Heap {
        self.storage.heap.image.get()
    }

    #[cfg(test)]
    fn test_images(&mut self) -> (&Heap, &Theap) {
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
    fn wrong_roots_reject_before_ticket_and_repeat_rejects_after_ready() {
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
                Err(MainStaticTheapError::AlreadyAttached)
            ));
            assert_eq!(subprocess.total_thread_count(), 1);
            owner.teardown().expect("first owner remains the sole teardown authority");
        })
        .join()
        .expect("root-rejection test thread completes");
    }

    #[test]
    fn generic_first_ticket_poison_static_attachment_without_aliasing_or_live_count_error() {
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
            assert_eq!(subprocess.total_thread_count(), 2);
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
                Err(MainStaticTheapError::Poisoned)
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
