// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:236-282,305-360,377-421,
// 448-481`, `src/theap.c:89-152,228-306,414-449`, `src/page.c:214-243`,
// `src/threadlocal.c:205-214`, and `src/heap.c:103-126`.

//! Later-thread attachment to the process-static main heap.
//!
//! This module is the first shared owner boundary for the normal
//! `_mi_thread_init_with_heap(mi_heap_main())` path.  A
//! [`MainHeapThreadAttachment`] owns a metadata TLD and metadata Theap for one
//! later thread, but borrows the ticket-zero static main heap through
//! [`MainStaticHeapLease`].  It publishes the ordinary default root followed
//! by the main heap's fixed fast root, and its no-page teardown follows
//! `_mi_thread_done`: dynamic/fast TLS phase, default/cached reset, heap-list
//! detach, Theap release, then TLD release. A separate bounded page session
//! can borrow this same owner only with the process PageMap/arena pair; it
//! selects the static main Heap's in-place `pages_main` image, not a dynamic
//! heap-local arena-pages allocation.
//!
//! Its direct finish intentionally stops at the no-page lifecycle. The paired
//! process PageMap/arena and scoped-producer lifetime are represented only by
//! `main_heap_page.rs`'s separate bounded session, which can consume this
//! owner into one all-free source `_mi_theap_collect_abandon` drain. A
//! remaining live page, a nonempty dynamic backing, or an unexpected root is
//! retained as a terminal owner instead of being mistaken for completed
//! pthread teardown.

#[cfg(test)]
extern crate std;

use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::NonNull;

#[cfg(test)]
use core::ffi::c_void;

use crate::arena::ArenaView;
use crate::bootstrap::{TheapPageSession, empty_default_theap_ptr, theap_page_session_sealed};
use crate::compiler_tls::{
    cached_theap, current_thread_identity, default_theap, dynamic_backing_peek,
    fast_slot_peek, is_empty_dynamic_backing, set_cached_theap, set_default_theap,
    set_fast_slot,
};
use crate::deferred_free::DeferredFreeInvocationError;
#[cfg(test)]
use crate::deferred_free::{DeferredFreeTestCallback, DeferredFreeTestObserver};
use crate::main_theap::{
    MainStaticHeapLease, MainStaticHeapLeaseError,
};
use crate::meta::{MetaAllocation, MetaAllocator, MetaError};
use crate::os::MemoryConfig;
use crate::os_page::OsAlignedPageOwner;
use crate::tld::{DynamicAttachedThreadLocalData, ThreadLocalDataError, ThreadLocalDataOwner};
use crate::types::{
    MemoryId, Page, PageQueue, Theap, TheapDynamicInitError, TheapOwner,
    ThreadLocalTheapListError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MainHeapThreadAttachmentState {
    Preparing,
    Attached,
    /// The main Heap's fixed compiler-TLS slot has been cleared for source
    /// `_mi_thread_done`, but this exact later Theap, its TLD/list links, and
    /// any process page lifecycle are still retained until an explicit page
    /// drain has released every page.
    DrainingPages,
    TornDown,
    Poisoned,
}

/// One source-boundary failure while attaching or retiring a later thread's
/// metadata Theap on the process-static main heap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadAttachmentError {
    InvalidCurrentThread,
    /// A later-thread attachment begins only from the normal fresh compiler
    /// TLS roots.  In particular, a null dynamic root is post-teardown, not a
    /// replacement for the source's immutable count-zero backing.
    RootsNotPristine,
    ThreadLocalData(ThreadLocalDataError),
    TheapMetadata(MetaError),
    TheapProjection,
    TheapInit(TheapDynamicInitError),
    MainHeap(MainStaticHeapLeaseError),
    /// The default, fast, cached, or dynamic root ceased to name this exact
    /// no-page owner before the source teardown transition.
    RootOwnership,
    /// The bounded all-free exit drain cannot abandon a remaining live page,
    /// so it remains with this retained owner rather than crossing a fake
    /// release.
    PageCountNonZero,
    /// A caller attempted a pre- or post-fast-slot operation in the wrong
    /// side of the explicit source thread-exit page-drain transition.
    PageDrainState,
    /// A Rust-owned persistent page-engine state token has temporarily
    /// suspended this attachment's borrowed page session.  The attachment
    /// cannot begin a second page engine, enter source thread teardown, or
    /// be treated as no-page until that exact token resumes its session or is
    /// explicitly retained terminally.
    PersistentPageEngineSuspended,
    /// A persistent page-engine state token was offered to an attachment that
    /// did not record its matching suspended session.  This is a rejected
    /// capability mismatch; no page, root, or TLD state has changed.
    PersistentPageEngineMissing,
    ListOwnership,
    TheapList(ThreadLocalTheapListError),
    TheapClear,
    /// The retained Theap no longer named its live callback TLD at the
    /// source deferred-free boundary. The attachment is kept terminal rather
    /// than allowing an old metadata pointer to cross teardown.
    DeferredFree(DeferredFreeInvocationError),
    SharedCount,
    TornDown,
    Poisoned,
}

/// A refusal to borrow a later main-heap attachment as the bounded shared
/// page engine's source Theap session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadPageSessionError {
    Attachment(MainHeapThreadAttachmentError),
    /// A later-thread metadata TLD must never claim ticket zero, which belongs
    /// to the source-static main TLD.
    FirstTicket,
}

/// A failed later-thread construction that either made no retained source
/// state or must preserve its exact partial owner.
#[must_use = "a retained later-thread attachment error owns live source state"]
pub(crate) enum MainHeapThreadAttachmentBeginError<'main> {
    Rejected(MainHeapThreadAttachmentError),
    Retained {
        error: MainHeapThreadAttachmentError,
        attachment: MainHeapThreadAttachment<'main>,
    },
}

/// The current-thread owner of a source later-ticket metadata TLD/Theap
/// attached to the process-static main Heap.
///
/// It is `!Send` and `!Sync`; the process heap lease is shareable only so a
/// worker can construct its own such owner.  Dropping this value deliberately
/// does not clear compiler TLS, detach raw list links, or free metadata.
#[must_use = "a later main-heap thread attachment must explicitly finish after user destructors"]
pub(crate) struct MainHeapThreadAttachment<'main> {
    main_heap: MainStaticHeapLease<'main>,
    metadata: core::pin::Pin<&'static MetaAllocator>,
    config: MemoryConfig,
    tld: Option<DynamicAttachedThreadLocalData>,
    theap: Option<MetaAllocation<'static>>,
    thread: crate::types::LiveThreadId,
    counted_in_main_heap: bool,
    /// A detached OS-aligned singleton mapping which a failed bounded page
    /// engine could not release. No later-thread owner-exit traversal exists
    /// yet, so retaining this token is terminal and poisons the attachment.
    terminal_os_release: Option<OsAlignedPageOwner>,
    /// The page engine itself may be stored separately from this attachment
    /// between allocator calls so TLS can own both without a self-reference.
    /// While true, the detached engine-state token is the only authority that
    /// may resume a normal page session.  Direct no-page teardown and a fresh
    /// page session reject rather than losing its PageMap/arena/OS state.
    page_engine_suspended: bool,
    /// A private source-order observer used only by focused lifecycle tests.
    /// It is deliberately attachment-local: the production public callback
    /// registration ABI requires a future whole-process pointer-domain and
    /// re-entry contract.
    #[cfg(test)]
    deferred_free_test_observer: Option<DeferredFreeTestObserver>,
    state: MainHeapThreadAttachmentState,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl<'main> MainHeapThreadAttachment<'main> {
    /// Starts the ordinary later-thread branch against the selected process
    /// main Heap using the process-global detached metadata owner.
    ///
    /// # Safety
    ///
    /// `main_heap` must have been obtained from the live ticket-zero main
    /// attachment and must remain borrowed for this complete owner lifetime.
    /// The caller owns this current thread's allocator lifecycle, invokes this
    /// before user allocation, retains the returned owner until
    /// [`Self::finish_after_user_destructors`], and does not mutate the
    /// allocator compiler-TLS roots or construct a competing TLD/Theap.  This
    /// is not a general page-bearing allocator or a pthread hook yet.
    pub(crate) unsafe fn begin(
        main_heap: MainStaticHeapLease<'main>,
        config: MemoryConfig,
    ) -> Result<Self, MainHeapThreadAttachmentBeginError<'main>> {
        // SAFETY: the process-global metadata owner has process lifetime; all
        // remaining lifecycle obligations are forwarded to the shared helper.
        unsafe { Self::begin_with_metadata(main_heap, MetaAllocator::global(), config) }
    }

    /// Builds the same owner over an explicit process-lived metadata fixture.
    ///
    /// # Safety
    ///
    /// This has the same obligations as [`Self::begin`].  `metadata` must
    /// remain the sole process-lived detached metadata owner for every TLD and
    /// Theap allocation returned through it.
    #[cfg(test)]
    pub(crate) unsafe fn begin_with_test_metadata(
        main_heap: MainStaticHeapLease<'main>,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        config: MemoryConfig,
    ) -> Result<Self, MainHeapThreadAttachmentBeginError<'main>> {
        // SAFETY: test callers carry the same root/current-thread ownership
        // proof and retain the leaked metadata fixture for the full lifetime.
        unsafe { Self::begin_with_metadata(main_heap, metadata, config) }
    }

    unsafe fn begin_with_metadata(
        main_heap: MainStaticHeapLease<'main>,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        config: MemoryConfig,
    ) -> Result<Self, MainHeapThreadAttachmentBeginError<'main>> {
        let thread = current_thread_identity().ok_or(
            MainHeapThreadAttachmentBeginError::Rejected(
                MainHeapThreadAttachmentError::InvalidCurrentThread,
            ),
        )?;
        if !roots_are_pristine_for_later_main_attachment() {
            return Err(MainHeapThreadAttachmentBeginError::Rejected(
                MainHeapThreadAttachmentError::RootsNotPristine,
            ));
        }

        let tld = match unsafe {
            ThreadLocalDataOwner::begin_later_main_heap_attachment_with_metadata(
                main_heap.subprocess(),
                metadata,
                config,
            )
        } {
            Ok(tld) => tld,
            Err(error) => {
                return Err(MainHeapThreadAttachmentBeginError::Rejected(
                    MainHeapThreadAttachmentError::ThreadLocalData(error),
                ));
            }
        };
        let mut attachment = Self {
            main_heap,
            metadata,
            config,
            tld: Some(tld),
            theap: None,
            thread,
            counted_in_main_heap: false,
            terminal_os_release: None,
            page_engine_suspended: false,
            #[cfg(test)]
            deferred_free_test_observer: None,
            state: MainHeapThreadAttachmentState::Preparing,
            _not_send_or_sync: PhantomData,
        };

        let allocation = match metadata.zalloc_for_main_subprocess(
            config,
            attachment.main_heap.subprocess(),
            size_of::<Theap>(),
        ) {
            Ok(allocation) => allocation,
            Err(error) => {
                return match attachment.cancel_before_theap_publication() {
                    Ok(()) => Err(MainHeapThreadAttachmentBeginError::Rejected(
                        MainHeapThreadAttachmentError::TheapMetadata(error),
                    )),
                    Err(cleanup) => Err(attachment.into_retained_begin_failure(cleanup)),
                };
            }
        };
        attachment.theap = Some(allocation);

        let initialize = attachment.initialize_and_publish();
        match initialize {
            Ok(()) => {
                attachment.state = MainHeapThreadAttachmentState::Attached;
                Ok(attachment)
            }
            Err(error) => Err(attachment.into_retained_begin_failure(error)),
        }
    }

    /// Returns the exact process-main identity while this later-thread owner
    /// remains current and attached. A page-bearing wrapper uses it to reject
    /// a foreign process PageMap/arena pair before acquiring its map lease.
    #[inline]
    pub(crate) fn subprocess(
        &self,
    ) -> Result<&'static crate::subproc::MainSubprocess, MainHeapThreadAttachmentError> {
        self.ensure_attached_current()?;
        Ok(self.main_heap.subprocess())
    }

    /// Returns the frozen configuration used for this TLD/Theap metadata
    /// image. The process PageMap/arena pair must match it exactly.
    #[inline]
    pub(crate) fn memory_config(
        &self,
    ) -> Result<MemoryConfig, MainHeapThreadAttachmentError> {
        self.ensure_attached_current()?;
        Ok(self.config)
    }

    /// Borrows this exact later-thread attachment as one bounded page
    /// session. The mutable borrow prevents its root/list/TLD teardown while
    /// the page engine or scoped remote producer can retain raw page state.
    #[inline]
    pub(crate) fn page_session(
        &mut self,
    ) -> Result<MainHeapThreadPageSession<'_, 'main>, MainHeapThreadPageSessionError> {
        MainHeapThreadPageSession::begin(self)
    }

    /// Revalidates this already-attached source owner for one short operation
    /// of its continuously stored owner-local page engine.
    ///
    /// Unlike [`Self::page_session`], this projection accepts pages already
    /// owned by the attachment. It neither suspends the source owner nor
    /// changes its fast-slot, list, or page-count state; the caller must keep
    /// the matching engine continuously alive and bind this view only for the
    /// duration of one synchronous local operation.
    #[inline]
    pub(crate) fn owner_local_page_session(
        &mut self,
    ) -> Result<MainHeapThreadPageSession<'_, 'main>, MainHeapThreadPageSessionError> {
        MainHeapThreadPageSession::begin_owner_local(self)
    }

    /// Installs one attachment-local deferred-free observer for a focused
    /// source-order regression.
    ///
    /// # Safety
    ///
    /// `context` and every value it reaches must remain valid until this
    /// attachment finishes or is intentionally retained terminally. The
    /// callback is observational only: it must not retain metadata pointers,
    /// mutate allocator state, or unwind across the invocation boundary.
    #[cfg(test)]
    pub(crate) unsafe fn test_install_deferred_free_observer(
        &mut self,
        callback: DeferredFreeTestCallback,
        context: NonNull<c_void>,
    ) -> bool {
        if self.ensure_attached_current().is_err() || self.deferred_free_test_observer.is_some() {
            return false;
        }
        // SAFETY: the caller supplies the synchronous callback/context
        // lifetime proof documented above. This field remains private to the
        // exact attachment and is consumed before its TLD can tear down.
        self.deferred_free_test_observer = Some(unsafe {
            DeferredFreeTestObserver::new(callback, context)
        });
        true
    }

    /// Finishes source `_mi_thread_done` after the pthread runtime has run all
    /// user cleanup handlers and public TSD destructors.
    ///
    /// This direct entry remains the no-page form. A page-bearing later owner
    /// must first consume its engine into `MainHeapThreadPageDrainSession`,
    /// which clears the fast slot, force-collects/release-drains only pages
    /// that become all-free, and then returns here through
    /// [`Self::finish_after_page_drain`]. It deliberately does not pretend to
    /// abandon a remaining live page.
    pub(crate) fn finish_after_user_destructors(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        self.prevalidate_attached_no_pages()?;

        self.begin_page_drain()?;
        self.finish_after_page_drain()
    }

    /// Completes the root/list/TLD portion of source `_mi_thread_done` after
    /// a bounded page drain has proved that this later Theap has no page,
    /// queue, direct-cache, PageMap, or arena-bitmap state left to release.
    ///
    /// It is intentionally separate from the all-free drain. A retained
    /// nonempty page has no general abandonment route yet, so it cannot cross
    /// this boundary or be reclassified as a normal no-page attachment.
    pub(crate) fn finish_after_page_drain(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        self.prevalidate_draining_page_teardown()?;

        // `_mi_thread_locals_thread_done` already cleared the fixed main Heap
        // slot before the bounded page drain. Source then resets default and
        // cached only after `mi_thread_theaps_done` has finished draining the
        // owner-local page queues.
        set_default_theap(empty_default_theap());
        set_cached_theap(empty_default_theap());

        let theap_pointer = self.theap_pointer()?;
        let main_heap = self.main_heap;
        let detach_heap = {
            let tld = self.current_tld_mut()?;
            let mut heap = main_heap
                .lock_heap()
                .map_err(MainHeapThreadAttachmentError::MainHeap)?;
            let detach = tld.detach_one_theap_from_shared_main_heap(
                heap.heap_mut(),
                theap_pointer,
            );
            let unlock = heap.unlock();
            match (detach, unlock) {
                (Err(error), _) => Err(MainHeapThreadAttachmentError::TheapList(error)),
                (Ok(()), Err(error)) => Err(MainHeapThreadAttachmentError::MainHeap(
                    MainStaticHeapLeaseError::Lock(error),
                )),
                (Ok(()), Ok(())) => Ok(()),
            }
        };
        if let Err(error) = detach_heap {
            return Err(self.poison(error));
        }

        let detach_tld = self
            .current_tld_mut()?
            .detach_one_theap_from_tld(theap_pointer)
            .map_err(MainHeapThreadAttachmentError::TheapList);
        if let Err(error) = detach_tld {
            return Err(self.poison(error));
        }

        let clear_theap = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .map(Theap::clear_dynamic_metadata_after_detach);
        match clear_theap {
            Some(true) => {}
            Some(false) => return Err(self.poison(MainHeapThreadAttachmentError::TheapClear)),
            None => return Err(self.poison(MainHeapThreadAttachmentError::TheapProjection)),
        }

        let mut theap = self
            .theap
            .take()
            .ok_or_else(|| self.poison(MainHeapThreadAttachmentError::Poisoned))?;
        if let Err(error) = self.metadata.free(&mut theap) {
            return Err(self.poison(MainHeapThreadAttachmentError::TheapMetadata(error)));
        }

        let tld_teardown = match self.tld.as_mut() {
            Some(tld) => tld
                .teardown_after_theap_detached()
                .map_err(MainHeapThreadAttachmentError::ThreadLocalData),
            None => return Err(self.poison(MainHeapThreadAttachmentError::Poisoned)),
        };
        if let Err(error) = tld_teardown {
            return Err(self.poison(error));
        }
        self.tld = None;

        if !self.counted_in_main_heap || !self.main_heap.note_later_theap_detached() {
            return Err(self.poison(MainHeapThreadAttachmentError::SharedCount));
        }
        self.counted_in_main_heap = false;
        self.state = MainHeapThreadAttachmentState::TornDown;
        Ok(())
    }

    /// Completes the old Theap/TLD half of `_mi_thread_done` after a typed
    /// process-lived abandoned-page route has detached every remaining page.
    ///
    /// # Safety
    ///
    /// Every source-live page formerly counted by this Theap must already be
    /// queue/direct-cache detached and represented by one typed process route
    /// that retains its PageMap registration, matching arena bitmap/count
    /// pair, metadata, backing slices, and final-release authority. No route
    /// may dereference this attachment's Theap or TLD after this call. The
    /// caller must retain every such route until its final release or an
    /// explicit terminal state. This method intentionally cannot discover
    /// that external route from the now-empty Theap page count.
    pub(crate) unsafe fn finish_after_detached_process_page_route(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        self.finish_after_page_drain()
    }

    fn initialize_and_publish(&mut self) -> Result<(), MainHeapThreadAttachmentError> {
        let main_heap = self.main_heap;
        let theap_pointer = {
            let (tld_slot, theap_slot) = (&mut self.tld, &mut self.theap);
            let tld = tld_slot
                .as_mut()
                .ok_or(MainHeapThreadAttachmentError::Poisoned)?
                .current_mut()
                .map_err(MainHeapThreadAttachmentError::ThreadLocalData)?;
            let theap = theap_slot
                .as_mut()
                .and_then(MetaAllocation::initialize_dynamic_theap_metadata)
                .ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
            let mut heap = main_heap
                .lock_heap()
                .map_err(MainHeapThreadAttachmentError::MainHeap)?;
            let initialize = unsafe { theap.initialize_shared_main_metadata(heap.heap_mut(), tld) };
            let unlock = heap.unlock();
            match (initialize, unlock) {
                (Err(error), _) => return Err(MainHeapThreadAttachmentError::TheapInit(error)),
                (Ok(()), Err(error)) => {
                    return Err(MainHeapThreadAttachmentError::MainHeap(
                        MainStaticHeapLeaseError::Lock(error),
                    ));
                }
                (Ok(()), Ok(())) => {}
            }
            NonNull::from(theap)
        };

        // The counter is a Rust lifetime gate only.  It comes after source
        // list publication and before roots become reachable, so main-image
        // retirement cannot race a returned attached capability.
        self.main_heap
            .note_later_theap_attached()
            .map_err(MainHeapThreadAttachmentError::MainHeap)?;
        self.counted_in_main_heap = true;

        // `_mi_thread_init_with_heap` makes the default root live before it
        // stores the current thread's Theap in the main heap's fixed fast
        // slot.  Cached stays the canonical empty source image.
        set_default_theap(theap_pointer);
        set_fast_slot(Some(theap_pointer.cast()));
        Ok(())
    }

    fn cancel_before_theap_publication(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if let Some(mut theap) = self.theap.take() {
            self.metadata
                .free(&mut theap)
                .map_err(MainHeapThreadAttachmentError::TheapMetadata)?;
        }
        self.tld
            .as_mut()
            .ok_or(MainHeapThreadAttachmentError::Poisoned)?
            .teardown_after_theap_detached()
            .map_err(MainHeapThreadAttachmentError::ThreadLocalData)?;
        self.tld = None;
        self.state = MainHeapThreadAttachmentState::TornDown;
        Ok(())
    }

    /// Validates an attached later owner before it clears the static-main fast
    /// slot. `require_empty` distinguishes the direct no-page teardown and
    /// fresh page-session entry from the page-bearing source drain transition.
    fn prevalidate_attached_page_drain(
        &mut self,
        require_empty: bool,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if self.page_engine_suspended {
            return Err(MainHeapThreadAttachmentError::PersistentPageEngineSuspended);
        }
        self.ensure_attached_current()?;
        self.prevalidate_page_drain_common(require_empty, true)
    }

    /// Validates the exact opposite half of the persistent-engine handoff.
    ///
    /// A suspended state token deliberately leaves the attachment's source
    /// roots, Theap, TLD, and any live pages in place, but releases the Rust
    /// borrow that would otherwise make TLS storage self-referential.  Only
    /// that token may call this path to re-form one ordinary page session.
    /// The marker is cleared only after every fallible preflight has passed,
    /// so a rejected resume leaves the old token and attachment unchanged.
    fn resume_persistent_page_engine(&mut self) -> Result<(), MainHeapThreadAttachmentError> {
        if !self.page_engine_suspended {
            return Err(MainHeapThreadAttachmentError::PersistentPageEngineMissing);
        }
        self.ensure_attached_current()?;
        self.prevalidate_page_drain_common(false, true)?;
        if self.terminal_os_release.is_some() {
            return Err(MainHeapThreadAttachmentError::Poisoned);
        }
        if self
            .tld
            .as_ref()
            .ok_or(MainHeapThreadAttachmentError::Poisoned)?
            .sequence()
            .get()
            == 0
        {
            return Err(MainHeapThreadAttachmentError::PersistentPageEngineMissing);
        }
        self.page_engine_suspended = false;
        Ok(())
    }

    /// Records that the current normal page session has moved its engine
    /// state into a separate typed owner.  This is not source allocator
    /// behavior; it is the Rust storage boundary which makes a persistent
    /// TLS-owned page engine possible without manufacturing a second mutable
    /// borrow of the attachment.
    fn suspend_persistent_page_engine(&mut self) -> Result<(), MainHeapThreadAttachmentError> {
        self.ensure_attached_current()?;
        if self.page_engine_suspended {
            return Err(MainHeapThreadAttachmentError::PersistentPageEngineSuspended);
        }
        self.page_engine_suspended = true;
        Ok(())
    }

    #[inline]
    fn prevalidate_attached_no_pages(&mut self) -> Result<(), MainHeapThreadAttachmentError> {
        self.prevalidate_attached_page_drain(true)
    }

    /// Validates the post-fast-slot, pre-list-detach source state. The default
    /// root still owns this exact Theap until the page drain and list teardown
    /// are complete; only the fixed fast slot is gone.
    fn prevalidate_draining_page_teardown(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        self.ensure_draining_current()?;
        self.prevalidate_page_drain_common(true, false)
    }

    fn prevalidate_page_drain_common(
        &mut self,
        require_empty: bool,
        expect_fast_owner: bool,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if self.terminal_os_release.is_some() {
            return Err(MainHeapThreadAttachmentError::Poisoned);
        }
        let theap_pointer = self.theap_pointer()?;
        let (page_count, refcount, matches_thread, bound_to_main_subprocess) = {
            let theap = self
                .theap
                .as_mut()
                .and_then(MetaAllocation::dynamic_theap_mut)
                .ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
            (
                theap.page_count(),
                theap.refcount(),
                theap.matches_thread(self.thread),
                theap.is_bound_to_main_subprocess(self.main_heap.subprocess()),
            )
        };
        if require_empty && page_count != 0 {
            return Err(MainHeapThreadAttachmentError::PageCountNonZero);
        }
        if refcount != 1 || !matches_thread || !bound_to_main_subprocess
        {
            return Err(MainHeapThreadAttachmentError::ListOwnership);
        }
        let fast_matches = if expect_fast_owner {
            fast_slot_peek()
                .is_some_and(|fast| fast.as_ptr().cast::<Theap>() == theap_pointer)
        } else {
            fast_slot_peek().is_none()
        };
        if !matches!(dynamic_backing_peek(), Some(backing) if is_empty_dynamic_backing(backing))
            || !fast_matches
            || !core::ptr::eq(default_theap().as_ptr(), theap_pointer)
            || !core::ptr::eq(cached_theap().as_ptr(), empty_default_theap_ptr())
        {
            return Err(MainHeapThreadAttachmentError::RootOwnership);
        }
        if !self
            .current_tld_mut()?
            .has_exact_theap_member(theap_pointer)
        {
            return Err(MainHeapThreadAttachmentError::ListOwnership);
        }
        let mut heap = self
            .main_heap
            .lock_heap()
            .map_err(MainHeapThreadAttachmentError::MainHeap)?;
        let member = heap
            .heap_mut()
            .has_shared_theap_member_blocking(theap_pointer)
            .map_err(|error| MainHeapThreadAttachmentError::TheapList(
                ThreadLocalTheapListError::Heap(error),
            ));
        let unlock = heap.unlock();
        if let Err(error) = unlock {
            return Err(MainHeapThreadAttachmentError::MainHeap(
                MainStaticHeapLeaseError::Lock(error),
            ));
        }
        let member = member?;
        if !member {
            return Err(MainHeapThreadAttachmentError::ListOwnership);
        }
        Ok(())
    }

    /// Clears the source main Heap's fixed compiler-TLS slot before the
    /// bounded later-owner page drain. There is no fallible operation after
    /// the clear: once it becomes visible, only the draining capability may
    /// release pages or finish root/list/TLD teardown.
    fn begin_page_drain(&mut self) -> Result<(), MainHeapThreadAttachmentError> {
        self.prevalidate_attached_page_drain(false)?;
        if self.terminal_os_release.is_some() {
            return Err(MainHeapThreadAttachmentError::Poisoned);
        }
        set_fast_slot(None);
        self.state = MainHeapThreadAttachmentState::DrainingPages;
        Ok(())
    }

    /// Clears one exact shared-main ordinary bitmap bit after PageMap
    /// unregistration while the fixed fast slot is already clear. Keeping
    /// this stage-specific helper distinct prevents a drain from accidentally
    /// reusing a normal attached-owner transition.
    fn clear_main_arena_page_during_drain(
        &mut self,
        arena: &ArenaView<'_>,
        memory: MemoryId,
    ) -> bool {
        if self.ensure_draining_current().is_err() {
            return false;
        }
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if arena_memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() {
            return false;
        }
        // The all-free drain has already unregistered the exact PageMap span;
        // it now performs the matching `pages_main` clear before slice return.
        unsafe { arena.pages() }
            .and_then(|pages| pages.clear_range(arena_memory.slice_index as usize, 1))
            == Some(true)
    }

    #[inline]
    fn ensure_attached_current(&self) -> Result<(), MainHeapThreadAttachmentError> {
        match self.state {
            MainHeapThreadAttachmentState::Attached => match current_thread_identity() {
                Some(thread) if thread == self.thread => Ok(()),
                Some(_) | None => Err(MainHeapThreadAttachmentError::InvalidCurrentThread),
            },
            MainHeapThreadAttachmentState::TornDown => Err(MainHeapThreadAttachmentError::TornDown),
            MainHeapThreadAttachmentState::DrainingPages => {
                Err(MainHeapThreadAttachmentError::PageDrainState)
            }
            MainHeapThreadAttachmentState::Preparing | MainHeapThreadAttachmentState::Poisoned => {
                Err(MainHeapThreadAttachmentError::Poisoned)
            }
        }
    }

    #[inline]
    fn ensure_draining_current(&self) -> Result<(), MainHeapThreadAttachmentError> {
        match self.state {
            MainHeapThreadAttachmentState::DrainingPages => match current_thread_identity() {
                Some(thread) if thread == self.thread => Ok(()),
                Some(_) | None => Err(MainHeapThreadAttachmentError::InvalidCurrentThread),
            },
            MainHeapThreadAttachmentState::TornDown => Err(MainHeapThreadAttachmentError::TornDown),
            MainHeapThreadAttachmentState::Attached => {
                Err(MainHeapThreadAttachmentError::PageDrainState)
            }
            MainHeapThreadAttachmentState::Preparing | MainHeapThreadAttachmentState::Poisoned => {
                Err(MainHeapThreadAttachmentError::Poisoned)
            }
        }
    }

    fn current_tld_mut(
        &mut self,
    ) -> Result<&mut crate::types::ThreadLocalData, MainHeapThreadAttachmentError> {
        self.tld
            .as_mut()
            .ok_or(MainHeapThreadAttachmentError::Poisoned)?
            .current_mut()
            .map_err(MainHeapThreadAttachmentError::ThreadLocalData)
    }

    fn theap_pointer(&mut self) -> Result<*mut Theap, MainHeapThreadAttachmentError> {
        let theap = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
        Ok(core::ptr::from_mut(theap))
    }

    /// Exposes the retained metadata Theap address only to sibling focused
    /// regressions which still hold this current-thread owner.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_theap_pointer(
        &mut self,
    ) -> Result<*mut Theap, MainHeapThreadAttachmentError> {
        self.theap_pointer()
    }

    fn into_retained_begin_failure(
        mut self,
        error: MainHeapThreadAttachmentError,
    ) -> MainHeapThreadAttachmentBeginError<'main> {
        self.state = MainHeapThreadAttachmentState::Poisoned;
        MainHeapThreadAttachmentBeginError::Retained {
            error,
            attachment: self,
        }
    }

    #[inline]
    fn poison(&mut self, error: MainHeapThreadAttachmentError) -> MainHeapThreadAttachmentError {
        self.state = MainHeapThreadAttachmentState::Poisoned;
        error
    }
}

/// One borrowed page-owner view of a later metadata Theap linked to the
/// source-static main Heap.
///
/// The TLD and Theap are private metadata images, while the Heap is borrowed
/// through its short `MainStaticHeapLease` projection.  This is therefore
/// deliberately distinct from `DynamicTheapPageSession`: source
/// `mi_heap_ensure_arena_pages` selects the selected arena's embedded
/// `pages_main` image for `mi_heap_main()`, rather than allocating a
/// heap-local image for this later Theap.
pub(crate) struct MainHeapThreadPageSession<'attachment, 'main> {
    attachment: &'attachment mut MainHeapThreadAttachment<'main>,
}

impl<'attachment, 'main> MainHeapThreadPageSession<'attachment, 'main> {
    fn begin(
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<Self, MainHeapThreadPageSessionError> {
        attachment
            .prevalidate_attached_no_pages()
            .map_err(MainHeapThreadPageSessionError::Attachment)?;
        if attachment.terminal_os_release.is_some() {
            return Err(MainHeapThreadPageSessionError::Attachment(
                MainHeapThreadAttachmentError::Poisoned,
            ));
        }
        if attachment
            .tld
            .as_ref()
            .ok_or(MainHeapThreadPageSessionError::Attachment(
                MainHeapThreadAttachmentError::Poisoned,
            ))?
            .sequence()
            .get()
            == 0
        {
            return Err(MainHeapThreadPageSessionError::FirstTicket);
        }
        Ok(Self { attachment })
    }

    fn begin_owner_local(
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<Self, MainHeapThreadPageSessionError> {
        attachment
            .prevalidate_attached_page_drain(false)
            .map_err(MainHeapThreadPageSessionError::Attachment)?;
        if attachment.terminal_os_release.is_some() {
            return Err(MainHeapThreadPageSessionError::Attachment(
                MainHeapThreadAttachmentError::Poisoned,
            ));
        }
        if attachment
            .tld
            .as_ref()
            .ok_or(MainHeapThreadPageSessionError::Attachment(
                MainHeapThreadAttachmentError::Poisoned,
            ))?
            .sequence()
            .get()
            == 0
        {
            return Err(MainHeapThreadPageSessionError::FirstTicket);
        }
        Ok(Self { attachment })
    }

    /// Re-forms one normal page session from the only suspended persistent
    /// engine-state token for `attachment`.
    ///
    /// This intentionally differs from [`Self::begin`]: a persistent engine
    /// may still own live pages, so requiring an empty Theap here would make
    /// TLS storage impossible.  The attachment-local suspended marker is the
    /// missing uniqueness proof.  It is set only while the exact engine state
    /// is held by `MainHeapThreadPausedProcessPageAllocator`, and is cleared
    /// only after all current-thread/root/list checks succeed.
    pub(crate) fn resume_persistent(
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<Self, MainHeapThreadPageSessionError> {
        attachment
            .resume_persistent_page_engine()
            .map_err(MainHeapThreadPageSessionError::Attachment)?;
        Ok(Self { attachment })
    }

    /// Detaches this Rust borrow while retaining the source page owner in the
    /// attachment and moving the matching engine state into a typed external
    /// token.  A second normal session or no-page teardown now rejects until
    /// that token resumes, so this cannot silently become a no-page
    /// attachment merely because its engine is no longer on the stack.
    pub(crate) fn suspend_persistent(&mut self) -> Result<(), MainHeapThreadAttachmentError> {
        self.attachment.suspend_persistent_page_engine()
    }

    /// The source old `thread_total_count` value belongs to the retained
    /// metadata TLD. It is never supplied independently by a page wrapper.
    #[inline]
    pub(crate) fn thread_sequence(&self) -> usize {
        self.attachment
            .tld
            .as_ref()
            .expect("a validated later-thread page session retains its TLD")
            .sequence()
            .get()
    }

    /// Returns the process-static main Heap witness retained by this normal
    /// later-thread page session. A consuming post-exit adoption uses it only
    /// to prove that its source route and fresh target share the same static
    /// main image before the mapped page's low owner bit is claimed.
    #[inline]
    pub(crate) fn main_heap_lease(&self) -> MainStaticHeapLease<'main> {
        self.attachment.main_heap
    }

    /// Forwards the private attachment-local deferred-free observer while the
    /// normal page engine still owns the live source Theap/TLD pair.
    #[cfg(test)]
    pub(crate) unsafe fn test_install_deferred_free_observer(
        &mut self,
        callback: DeferredFreeTestCallback,
        context: NonNull<c_void>,
    ) -> bool {
        // SAFETY: forwarded unchanged to the attachment-local test boundary.
        unsafe {
            self.attachment
                .test_install_deferred_free_observer(callback, context)
        }
    }

    #[inline]
    fn theap(&self) -> &Theap {
        self.attachment
            .theap
            .as_ref()
            .and_then(MetaAllocation::dynamic_theap)
            .expect("a validated later-thread page session retains its typed Theap")
    }

    #[inline]
    fn theap_mut(&mut self) -> &mut Theap {
        self.attachment
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .expect("a validated later-thread page session retains its typed Theap")
    }

    /// Consumes the normal later-thread page session into the post-fast-slot
    /// source drain. A failure retains the original session because any
    /// future post-clear error would already leave the attachment terminal.
    pub(crate) fn begin_thread_exit_drain(
        self,
    ) -> Result<
        MainHeapThreadPageDrainSession<'attachment, 'main>,
        (Self, MainHeapThreadAttachmentError),
    > {
        match self.attachment.begin_page_drain() {
            Ok(()) => Ok(MainHeapThreadPageDrainSession {
                attachment: self.attachment,
            }),
            Err(error) => Err((self, error)),
        }
    }
}

/// A post-fast-slot, pre-list-detach page owner for one later metadata Theap
/// linked to the static main Heap.
///
/// This session is deliberately not an allocator. It retains the same
/// queue/direct/page metadata and process map/arena borrow as the consumed
/// live session, but rejects every fresh-publication operation. Its only
/// caller is the bounded all-free owner-exit drain in `single_thread.rs`.
pub(crate) struct MainHeapThreadPageDrainSession<'attachment, 'main> {
    attachment: &'attachment mut MainHeapThreadAttachment<'main>,
}

impl<'attachment, 'main> MainHeapThreadPageDrainSession<'attachment, 'main> {
    /// Returns the process-static main Heap lifetime witness retained by this
    /// still-linked later Theap. A post-exit route may keep this copy after
    /// the Theap/TLD are detached so it can preserve the static-main
    /// `pages_abandoned[bin]`/`abandoned_count[bin]` pairing.
    #[inline]
    pub(crate) fn main_heap_lease(&self) -> MainStaticHeapLease<'main> {
        self.attachment.main_heap
    }

    /// Returns whether a source owner-exit traversal has already retained an
    /// ambiguous post-fast-slot state. Such a drain can no longer enter the
    /// ordinary all-free/no-page finalizer merely because some queue/count
    /// fields were detached before the failure.
    #[inline]
    pub(crate) fn owner_exit_is_terminal(&self) -> bool {
        self.attachment.state == MainHeapThreadAttachmentState::Poisoned
    }

    /// Records a failed source owner-exit traversal after its route may have
    /// detached queue/count state without completing a typed process route.
    ///
    /// This is deliberately attachment-local: it keeps the original Theap,
    /// TLD, and worker lifecycle from being finalized through the normal
    /// no-page path while the retained engine/lease remains the only exact
    /// owner of the ambiguous page state.
    #[inline]
    pub(crate) fn retain_terminal_owner_exit(&mut self) {
        self.attachment.state = MainHeapThreadAttachmentState::Poisoned;
    }

    /// Executes the source `_mi_deferred_free` phase while both metadata
    /// images remain live, after the fixed fast slot has cleared and before a
    /// page collector can retire, release, or queue-detach a page.
    ///
    /// The callback registration ABI remains absent. Production still takes
    /// the source heartbeat step; a private test observer proves the exact
    /// ordering without giving arbitrary code allocator mutation authority.
    pub(crate) fn collect_deferred_free_before_page_collection(
        &mut self,
        force: bool,
    ) -> Result<u64, MainHeapThreadAttachmentError> {
        self.attachment.ensure_draining_current()?;
        #[cfg(test)]
        let observer = self.attachment.deferred_free_test_observer;
        let theap = NonNull::new(self.attachment.theap_pointer()?)
            .ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
        let tld = {
            let tld = self.attachment.current_tld_mut()?;
            NonNull::from(tld)
        };
        #[cfg(test)]
        let collect = crate::deferred_free::collect_with_test_observer(
            theap, tld, force, observer,
        );
        #[cfg(not(test))]
        let collect = crate::deferred_free::collect(theap, tld, force);
        collect.map_err(MainHeapThreadAttachmentError::DeferredFree)
    }

    /// Consumes this empty post-fast-slot session into its underlying later
    /// attachment after source-live pages crossed into typed process routes.
    ///
    /// # Safety
    ///
    /// The caller must prove the Theap's page count, every queue, and every
    /// direct cache are empty, and that all formerly live page state is held
    /// by typed process routes. It must next call
    /// [`MainHeapThreadAttachment::finish_after_detached_process_page_route`]
    /// or retain the returned attachment terminally. No surviving route may
    /// access this session's Theap/TLD after the conversion.
    #[inline]
    pub(crate) unsafe fn into_attachment_after_process_page_route(
        self,
    ) -> &'attachment mut MainHeapThreadAttachment<'main> {
        self.attachment
    }

    #[inline]
    fn theap(&self) -> &Theap {
        self.attachment
            .theap
            .as_ref()
            .and_then(MetaAllocation::dynamic_theap)
            .expect("a draining later-thread page session retains its typed Theap")
    }

    #[inline]
    fn theap_mut(&mut self) -> &mut Theap {
        self.attachment
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .expect("a draining later-thread page session retains its typed Theap")
    }
}

impl theap_page_session_sealed::Sealed for MainHeapThreadPageSession<'_, '_> {}
impl theap_page_session_sealed::Sealed for MainHeapThreadPageDrainSession<'_, '_> {}

// SAFETY: construction revalidates the current-thread TLD/Theap/root/list
// state while taking `&mut MainHeapThreadAttachment`. That borrow retains the
// metadata Theap and TLD for the complete page/producer lifetime. Short
// mutable projections of the static main Heap remain serialized by
// `MainStaticHeapLease`, while the paired process PageMap lease serializes the
// source-plain map entries outside this session.
unsafe impl TheapPageSession for MainHeapThreadPageSession<'_, '_> {
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
        let main_heap = self.attachment.main_heap;
        let subprocess = main_heap.subprocess();
        let arena_index = arena.arena().arena_index;
        let pages = NonNull::from(&arena.arena().pages_main);
        let installed = match main_heap.lock_heap() {
            Ok(mut heap) => {
                let install = heap
                    .heap_mut()
                    .install_main_arena_pages(subprocess, arena_index, pages);
                let unlock = heap.unlock();
                install.is_ok() && unlock.is_ok()
            }
            Err(_) => false,
        };
        if !installed {
            // A failed main-bitmap installation can follow a visible store or
            // reveal a foreign slot. This bounded page session has no source
            // rebinding or retry protocol, so keep the later owner terminal.
            self.attachment.state = MainHeapThreadAttachmentState::Poisoned;
        }
        installed
    }

    #[inline]
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if arena_memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() {
            return false;
        }
        // SAFETY: the outer process-map lifecycle lease admits only this
        // page engine, and `ensure_arena_pages` installed this exact embedded
        // main bitmap before the fresh PageMap publication.
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
        // The generic engine unregisters the complete PageMap span before
        // this matching source `pages_main` clear and arena-slice release.
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
        let main_heap = self.attachment.main_heap;
        let thread = self.attachment.thread;
        let (page, unlock_ok) = match main_heap.lock_heap() {
            Ok(mut heap) => {
                let page = {
                    let theap = self.theap_mut();
                    // SAFETY: this session retains the exact metadata Theap
                    // and its current-thread TLD. The held heap guard is the
                    // sole mutable projection of the same static main Heap.
                    unsafe {
                        Page::publish_fresh_exclusive_owner_at(
                            metadata,
                            theap,
                            heap.heap_mut(),
                            TheapOwner::Live(thread),
                            block_size,
                            page_offset,
                            reserved,
                            slice_pcommitted,
                            free_is_zero,
                            memid,
                        )
                    }
                };
                let unlock_ok = heap.unlock().is_ok();
                (page, unlock_ok)
            }
            Err(_) => (None, false),
        };
        if !unlock_ok {
            // A post-publication wake error cannot be rolled back without
            // guessing whether another observer saw this Theap/Heap pair.
            // Return the initialized page to the engine so it can preserve
            // normal map/bitmap ordering, but make the attachment terminal.
            self.attachment.state = MainHeapThreadAttachmentState::Poisoned;
        }
        page
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
        self.attachment.state = MainHeapThreadAttachmentState::Poisoned;
    }
}

// SAFETY: this session is created only by consuming an attached later-main
// page session after `_mi_thread_locals_thread_done` cleared the fixed fast
// slot. It retains the exact typed Theap/TLD/list membership, static-main Heap
// lease, PageMap/arena borrow, and current live owner identity needed for the
// source force collection that precedes all-free release. Its only wrapper
// exposes draining, not ordinary allocation or fresh publication.
unsafe impl TheapPageSession for MainHeapThreadPageDrainSession<'_, '_> {
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

    // Fresh publication after source fast-slot teardown would recreate a
    // normal later-thread allocator owner. The drain wrapper has no such API;
    // these defensive trait paths reject it even if generic internals change.
    #[inline]
    fn ensure_arena_pages(&mut self, _arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        false
    }

    #[inline]
    fn set_arena_page(&mut self, _arena: &ArenaView<'_>, _memory: MemoryId) -> bool { false }

    #[inline]
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        self.attachment.clear_main_arena_page_during_drain(arena, memory)
    }

    #[inline]
    unsafe fn publish_fresh_page(
        &mut self,
        _metadata: NonNull<Page>,
        _block_size: usize,
        _page_offset: usize,
        _reserved: u16,
        _slice_pcommitted: u16,
        _free_is_zero: bool,
        _memid: MemoryId,
    ) -> Option<NonNull<Page>> {
        None
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
        self.attachment.state = MainHeapThreadAttachmentState::Poisoned;
    }
}

#[inline]
fn empty_default_theap() -> NonNull<Theap> {
    // SAFETY: the immutable source empty Theap is process-static and non-null.
    unsafe { NonNull::new_unchecked(empty_default_theap_ptr()) }
}

#[inline]
fn roots_are_pristine_for_later_main_attachment() -> bool {
    matches!(dynamic_backing_peek(), Some(backing) if is_empty_dynamic_backing(backing))
        && fast_slot_peek().is_none()
        && core::ptr::eq(default_theap().as_ptr(), empty_default_theap_ptr())
        && core::ptr::eq(cached_theap().as_ptr(), empty_default_theap_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_theap::{MainStaticAttachmentStorage, MainStaticTheapAttachment};
    use crate::os::{MemoryConfig, PageSize};
    use crate::subproc::MainSubprocess;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn fixture() -> (&'static MainStaticAttachmentStorage, &'static MainSubprocess) {
        (
            MainStaticAttachmentStorage::test_static_owner(),
            MainSubprocess::test_static_owner(),
        )
    }

    #[test]
    fn later_thread_uses_main_fast_slot_and_retires_before_main_storage() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the process main images");
            let main_heap = main
                .shared_main_heap_lease()
                .expect("the live main attachment lends its heap");

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the later ticket should attach, got rejection: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the later ticket should not retain a terminal owner: {error:?}")
                        }
                    };

                    let theap_pointer = owner.theap_pointer().expect("typed Theap remains live");
                    assert_eq!(default_theap().as_ptr(), theap_pointer);
                    assert_eq!(
                        fast_slot_peek().map(NonNull::as_ptr),
                        Some(theap_pointer.cast()),
                        "the shared main heap uses its fixed fast TLS slot"
                    );
                    assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
                    assert!(matches!(
                        dynamic_backing_peek(),
                        Some(backing) if is_empty_dynamic_backing(backing)
                    ));
                    assert_eq!(
                        owner
                            .current_tld_mut()
                            .expect("the attached TLD is current")
                            .thread_sequence()
                            .get(),
                        1,
                        "the source static main ticket remains sequence zero"
                    );
                    let mut heap = owner.main_heap.lock_heap().expect("shared heap is live");
                    assert!(
                        heap
                            .heap_mut()
                            .has_shared_theap_member_blocking(theap_pointer)
                            .expect("the source heap list stays valid")
                    );
                    heap.unlock().expect("shared heap guard releases");

                    owner
                        .finish_after_user_destructors()
                        .expect("the no-page source thread exit completes");
                    assert!(fast_slot_peek().is_none());
                    assert_eq!(default_theap().as_ptr(), empty_default_theap_ptr());
                    assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
                    assert!(matches!(
                        dynamic_backing_peek(),
                        Some(backing) if is_empty_dynamic_backing(backing)
                    ));
                    assert_eq!(
                        owner.finish_after_user_destructors(),
                        Err(MainHeapThreadAttachmentError::TornDown)
                    );
                });
                worker.join().expect("later attachment worker completes");
            });

            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 1);
            main.teardown()
                .expect("the main images retire after every later Theap detached");
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join()
        .expect("main-heap later-thread lifecycle completes");
    }

    #[test]
    fn later_thread_rejects_a_foreign_root_before_consuming_a_ticket() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the process main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut foreign = Theap::empty();
                    set_default_theap(NonNull::from(&mut foreign));
                    assert!(matches!(
                        unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap,
                                metadata,
                                memory_config(),
                            )
                        },
                        Err(MainHeapThreadAttachmentBeginError::Rejected(
                            MainHeapThreadAttachmentError::RootsNotPristine
                        ))
                    ));
                    assert_eq!(subprocess.total_thread_count(), 1);
                    assert_eq!(subprocess.live_thread_count(), 1);
                    set_default_theap(empty_default_theap());
                });
                worker.join().expect("root-rejection worker completes");
            });

            main.teardown().expect("foreign-root rejection changed no main state");
        })
        .join()
        .expect("root-rejection lifecycle completes");
    }

    #[test]
    fn overlapping_later_threads_link_distinct_metadata_theaps_to_one_main_heap() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the process main images");
            let main_heap = main.shared_main_heap_lease().unwrap();
            let ready = Arc::new(Barrier::new(3));
            let release = Arc::new(Barrier::new(3));
            let (sender, receiver) = mpsc::channel();

            thread::scope(|scope| {
                let mut workers = std::vec::Vec::new();
                for _ in 0..2 {
                    let ready = Arc::clone(&ready);
                    let release = Arc::clone(&release);
                    let sender = sender.clone();
                    workers.push(scope.spawn(move || {
                        let mut owner = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap,
                                metadata,
                                memory_config(),
                            )
                        } {
                            Ok(owner) => owner,
                            Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                panic!("overlapping later attach rejected: {error:?}")
                            }
                            Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                                panic!("overlapping later attach retained: {error:?}")
                            }
                        };
                        sender
                            .send(owner.theap_pointer().unwrap() as usize)
                            .expect("main inspector remains live");
                        ready.wait();
                        release.wait();
                        owner
                            .finish_after_user_destructors()
                            .expect("each shared main-heap owner retires");
                    }));
                }
                drop(sender);

                let first = receiver.recv().expect("first later Theap publishes");
                let second = receiver.recv().expect("second later Theap publishes");
                assert_ne!(first, second);
                ready.wait();
                assert_eq!(
                    storage.test_shared_later_theap_count(),
                    2,
                    "main-image teardown is gated while both shared list members are live"
                );
                let mut heap = main_heap.lock_heap().expect("shared heap remains live");
                for pointer in [first, second] {
                    assert!(
                        heap
                            .heap_mut()
                            .has_shared_theap_member_blocking(pointer as *mut Theap)
                            .expect("each published source list link is valid")
                    );
                }
                heap.unlock().expect("shared heap inspection unlocks");
                release.wait();
                for worker in workers {
                    worker.join().expect("overlapping worker completes");
                }
            });

            assert_eq!(
                storage.test_shared_later_theap_count(),
                0,
                "the main teardown gate clears only after both owner exits complete"
            );
            assert_eq!(subprocess.total_thread_count(), 3);
            assert_eq!(subprocess.live_thread_count(), 1);
            main.teardown()
                .expect("main storage retires only after both later owners detach");
        })
        .join()
        .expect("overlapping shared-main lifecycle completes");
    }
}
