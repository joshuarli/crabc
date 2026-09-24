// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:236-282,305-360,377-421,
// 448-481`, `src/theap.c:89-152,228-306,414-449`, `src/page.c:214-243`,
// `src/threadlocal.c:205-214`, `src/page.c:1021-1043`, `src/options.c:160`,
// `src/prim/prim-tls.c:25-34,211-252`, and
// `src/heap.c:103-126`.

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
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
use core::ffi::c_void;

use crate::arena::ArenaView;
use crate::bootstrap::{TheapPageSession, empty_default_theap_ptr, theap_page_session_sealed};
use crate::compiler_tls::{
    cached_theap, clear_dynamic_backing, current_thread_identity, default_theap,
    dynamic_backing_peek, fast_slot_peek, is_empty_dynamic_backing, set_cached_theap,
    set_default_theap, set_fast_slot,
};
#[cfg(test)]
use crate::compiler_tls::{DynamicThreadLocalBacking, install_dynamic_backing};
use crate::deferred_free::{self, DeferredFreeInvocation, DeferredFreeInvocationError};
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
    LiveThreadId, MemoryId, Page, PageQueue, Theap, TheapDynamicInitError, TheapOwner,
    TheapPageMode, ThreadLocalTheapListError,
};

/// Whether one attachment prevalidation re-observes this Theap's membership
/// in the process-shared main Heap list.
///
/// Membership can change only through this attachment's own source teardown
/// (`TLD::detach_one_theap_from_shared_main_heap` requires the owner's
/// exclusive TLD) or through quiescent process destruction, which closes
/// native admission before any operation could observe the result. The
/// locked observation therefore belongs at the transitions that change or
/// consume that list, not on every ordinary allocation: pinned
/// `mi_malloc`/`mi_free` take no Heap lock on the local path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SharedHeapMembership {
    /// Take the main Heap projection and list locks and re-check membership.
    /// Drain, teardown, resume, and deferred-callback selection use this.
    Observe,
    /// Rely on the attachment invariant above. Only ordinary owner-local
    /// page-session admission uses this, so independent owners never contend
    /// on a process-global lock per operation.
    AttachedInvariant,
}

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
    SourceRetained,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MainHeapThreadOwnerLocalPageEngineState {
    Missing,
    Idle,
    Borrowed,
    Terminal,
}

// This marker belongs to the one source attachment permitted by the current
// thread's compiler-TLS roots. It carries no pointer or registry identity: the
// attachment's root/list validation supplies that proof, while this linear
// state alone prevents a second persistent engine and makes unfinished Drop
// permanently ineligible for fresh begin or attachment teardown.
#[thread_local]
static mut OWNER_LOCAL_PAGE_ENGINE_STATE: MainHeapThreadOwnerLocalPageEngineState =
    MainHeapThreadOwnerLocalPageEngineState::Missing;

#[inline]
fn owner_local_page_engine_state() -> MainHeapThreadOwnerLocalPageEngineState {
    // SAFETY: the current thread alone reads its compiler-TLS lifecycle byte.
    unsafe { OWNER_LOCAL_PAGE_ENGINE_STATE }
}

#[inline]
fn set_owner_local_page_engine_state(state: MainHeapThreadOwnerLocalPageEngineState) {
    // SAFETY: the current thread alone writes its compiler-TLS lifecycle byte.
    unsafe { OWNER_LOCAL_PAGE_ENGINE_STATE = state };
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
    /// This attachment already has one continuously stored owner-local page
    /// engine. Neither a duplicate engine nor direct attachment teardown may
    /// cross that linear ownership boundary.
    OwnerLocalPageEngineActive,
    /// An owner-local allocator callback tried to enter another page operation
    /// before the first short source projection returned.
    OwnerLocalPageEngineReentrant,
    /// No owner-local engine is currently claimed by this attachment.
    OwnerLocalPageEngineMissing,
    /// An unfinished owner-local engine was dropped or its lifecycle otherwise
    /// lost a safe retry boundary. The attachment and its page state remain
    /// terminally retained.
    OwnerLocalPageEngineTerminal,
    ListOwnership,
    TheapList(ThreadLocalTheapListError),
    TheapClear,
    /// The retained Theap no longer named its live callback TLD at the
    /// source deferred-free boundary. The attachment is kept terminal rather
    /// than allowing an old metadata pointer to cross teardown.
    DeferredFree(DeferredFreeInvocationError),
    /// A selected deferred-free callback has returned through neither its
    /// caller-stack completion token nor its attachment identity check. The
    /// attachment cannot enter teardown or process-done retention while that
    /// callback may still reenter ordinary allocation.
    DeferredFreeCallbackActive,
    /// A live callback marker did not name this attachment's current caller-
    /// stack generation. It cannot authorize callback allocation reentry.
    DeferredFreeCallbackGeneration,
    /// The attachment named a live generation, but the current source TLD no
    /// longer carried that callback's recurse marker.
    DeferredFreeCallbackNotRecursing,
    /// The callback completion did not name the current active attachment
    /// generation. This rejects a stale or duplicate continuation before it
    /// can resume source collection.
    DeferredFreeCallbackLease,
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

/// Linear compiler-TLS claim for one continuously stored later-main page
/// engine. It owns no attachment reference, so the TLS payload can store the
/// attachment and engine in sibling fields without a self-reference.
#[must_use = "an owner-local page-engine claim must finish or retain its attachment terminally"]
pub(crate) struct MainHeapThreadOwnerLocalPageEngineLease {
    thread: crate::types::LiveThreadId,
    thread_sequence: usize,
    finished: bool,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// One caller-stack proof that an attached source callback is in flight.
///
/// It has no attachment reference and no saved allocator continuation. The
/// attachment retains only the active generation for teardown/fork admission;
/// a normal later owner projection must consume this lease and revalidate the
/// exact source roots before it resumes collection or allocation.
#[must_use = "a deferred-free callback lease must be completed through its current attachment"]
pub(crate) struct MainHeapThreadDeferredFreeCallbackLease {
    theap: NonNull<Theap>,
    tld: NonNull<crate::types::ThreadLocalData>,
    /// `mi_tld_t::thread_seq` identifies this source TLD lifetime. A later
    /// attachment can reuse storage addresses only with a new source-issued
    /// sequence, so phase C rejects it before it resumes this continuation.
    source_thread_sequence: usize,
    /// The same attachment's live source thread identity. This prevents an
    /// address-stable source slot from standing in for a different owner.
    source_thread: crate::types::LiveThreadId,
    generation: usize,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// A deferred-free source selection whose user call is outside attachment and
/// page-engine borrows.
#[must_use = "a selected deferred-free callback must return through the attachment completion boundary"]
pub(crate) enum MainHeapThreadDeferredFreeCall {
    Complete(u64),
    Callback {
        invocation: DeferredFreeInvocation,
        lease: MainHeapThreadDeferredFreeCallbackLease,
    },
}

impl MainHeapThreadDeferredFreeCall {
    /// Whether phase B will cross into the registered foreign callback.
    /// Nested source recursion returns `Complete` and must not publish a
    /// process-global callback admission for its heartbeat-only boundary.
    #[inline]
    pub(crate) const fn invokes_user_callback(&self) -> bool {
        matches!(self, Self::Callback { .. })
    }

    /// Delivers selected user code after the outer persistent owner has
    /// returned to its idle compiler-TLS cell.
    ///
    /// # Safety
    ///
    /// The caller must have released every mutable attachment, page-engine,
    /// session, Theap, and TLD projection before this call. It must then pass
    /// the returned lease to the same attachment's completion boundary.
    #[inline]
    pub(crate) unsafe fn invoke(self) -> (u64, Option<MainHeapThreadDeferredFreeCallbackLease>) {
        match self {
            Self::Complete(heartbeat) => (heartbeat, None),
            Self::Callback { invocation, lease } => {
                // SAFETY: forwarded from this method's caller-stack contract.
                (unsafe { invocation.invoke() }, Some(lease))
            }
        }
    }
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
    /// The source `mi_option_page_full_retain` image frozen before this
    /// later Theap Release-publishes its heap pointer.
    page_mode: TheapPageMode,
    /// Source generic collection option retained by the real process path;
    /// detached fixtures keep the pinned 10,000 default.
    generic_collect_policy: Option<&'static crate::os::VmPolicy>,
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
    /// The one source callback currently selected for this attachment. The
    /// continuation stays on the caller stack; this field only blocks
    /// teardown/process-done/fork admission until normal phase-C identity
    /// validation consumes its matching lease.
    deferred_free_callback_generation: usize,
    /// This is deliberately an acquire/release publication instead of a
    /// thread-local lifecycle byte. Fork admission takes a registry snapshot
    /// without borrowing this attachment, and must reject an in-flight user
    /// callback instead of waiting while that callback can reenter allocation.
    /// Zero is not a generation and means that no callback lease is active.
    deferred_free_callback_active: AtomicUsize,
    /// A private source-order observer used only by focused lifecycle tests.
    /// It is deliberately attachment-local: the production public callback
    /// registration ABI requires a future whole-process pointer-domain and
    /// re-entry contract.
    #[cfg(test)]
    deferred_free_test_observer: Option<DeferredFreeTestObserver>,
    /// One focused test-only fault at the final attachment boundary after a
    /// successful page drain. It never models a production fallback or route;
    /// it proves that the outer persistent owner retains `AttachmentOnly`
    /// rather than reconstructing a drained page engine.
    #[cfg(test)]
    detached_process_page_finish_failures: usize,
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
        unsafe {
            Self::begin_with_metadata(
                main_heap,
                MetaAllocator::global(),
                config,
                TheapPageMode::OrdinaryAbandoning,
            )
        }
    }

    /// Starts the production later-main owner with the selected process
    /// option image used at each generic administration boundary.
    ///
    /// # Safety
    ///
    /// This has [`Self::begin`]'s caller obligations. `process` must be the
    /// process-lived policy for this exact main Heap and remain valid through
    /// the attachment's final teardown.
    pub(crate) unsafe fn begin_with_vm_process(
        main_heap: MainStaticHeapLease<'main>,
        config: MemoryConfig,
        process: crate::os::VmProcess<'static>,
    ) -> Result<Self, MainHeapThreadAttachmentBeginError<'main>> {
        // SAFETY: the caller supplies the same source attachment inputs and
        // exact retained process identity required by this boundary.
        let mut attachment = unsafe { Self::begin(main_heap, config) }?;
        attachment.generic_collect_policy = Some(process.policy());
        Ok(attachment)
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
        // SAFETY: this fixture preserves the ordinary source option image.
        unsafe {
            Self::begin_with_test_metadata_mode(
                main_heap,
                metadata,
                config,
                TheapPageMode::OrdinaryAbandoning,
            )
        }
    }

    /// Builds a focused later-thread fixture whose source
    /// `mi_option_page_full_retain = -1` image keeps full pages in `BIN_FULL`.
    ///
    /// This is only for fixtures that exercise source full-queue collection.
    /// Production later-thread attachment keeps the ordinary option image.
    #[cfg(test)]
    pub(crate) unsafe fn begin_with_test_metadata_non_abandoning_full_queue(
        main_heap: MainStaticHeapLease<'main>,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        config: MemoryConfig,
    ) -> Result<Self, MainHeapThreadAttachmentBeginError<'main>> {
        // SAFETY: the full-queue fixture differs only in the frozen source
        // option image selected before heap publication.
        unsafe {
            Self::begin_with_test_metadata_mode(
                main_heap,
                metadata,
                config,
                TheapPageMode::NonAbandoningPageSession,
            )
        }
    }

    /// Shared test-fixture admission and source option selection.
    ///
    /// # Safety
    ///
    /// The caller upholds [`Self::begin_with_test_metadata`]'s complete
    /// current-thread/root/metadata lifetime contract.
    #[cfg(test)]
    unsafe fn begin_with_test_metadata_mode(
        main_heap: MainStaticHeapLease<'main>,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        config: MemoryConfig,
        page_mode: TheapPageMode,
    ) -> Result<Self, MainHeapThreadAttachmentBeginError<'main>> {
        // Preserve the common constructor's no-side-effect admission checks:
        // a rejected current-thread/root image must not even publish the
        // test fixture's metadata identity.
        if current_thread_identity().is_none() {
            return Err(MainHeapThreadAttachmentBeginError::Rejected(
                MainHeapThreadAttachmentError::InvalidCurrentThread,
            ));
        }
        if !roots_are_pristine_for_later_main_attachment() {
            return Err(MainHeapThreadAttachmentBeginError::Rejected(
                MainHeapThreadAttachmentError::RootsNotPristine,
            ));
        }
        // The test-only fixture establishes the same process preparation
        // edge that production completes before it admits later threads. The
        // main-heap lease carries the exact selected source-main identity;
        // this is identity-only and cannot take metadata backing.
        metadata
            .prepare_for_main_subprocess(config, main_heap.subprocess())
            .map_err(|error| {
                MainHeapThreadAttachmentBeginError::Rejected(
                    MainHeapThreadAttachmentError::TheapMetadata(error),
                )
            })?;
        // SAFETY: test callers carry the same root/current-thread ownership
        // proof and retain the leaked metadata fixture for the full lifetime.
        unsafe { Self::begin_with_metadata(main_heap, metadata, config, page_mode) }
    }

    unsafe fn begin_with_metadata(
        main_heap: MainStaticHeapLease<'main>,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        config: MemoryConfig,
        page_mode: TheapPageMode,
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
            page_mode,
            generic_collect_policy: None,
            tld: Some(tld),
            theap: None,
            thread,
            counted_in_main_heap: false,
            terminal_os_release: None,
            page_engine_suspended: false,
            deferred_free_callback_generation: 0,
            deferred_free_callback_active: AtomicUsize::new(0),
            #[cfg(test)]
            deferred_free_test_observer: None,
            #[cfg(test)]
            detached_process_page_finish_failures: 0,
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

    /// Exposes the exact process metadata owner selected by this attachment
    /// to parent-issued capabilities such as child-subprocess creation.
    #[inline]
    pub(crate) fn parent_metadata_allocator(&self) -> core::pin::Pin<&'static MetaAllocator> {
        self.metadata
    }

    /// Returns the current parent allocation-owner identity retained by this
    /// exact later-thread TLD. The sequence distinguishes a later attachment
    /// on a reused thread from the one that issued an outstanding child Heap
    /// allocation token.
    #[inline]
    pub(crate) fn allocation_owner_identity(
        &self,
    ) -> Result<(crate::types::LiveThreadId, usize), MainHeapThreadAttachmentError> {
        self.ensure_attached_current()?;
        let sequence = self
            .tld
            .as_ref()
            .ok_or(MainHeapThreadAttachmentError::Poisoned)?
            .sequence()
            .get();
        Ok((self.thread, sequence))
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

    /// Checks the attachment half of the selected post-process-done retain
    /// boundary. It performs no source teardown: the pinned Unix automatic
    /// thread-done key has already been deleted, so a nonfinal worker may
    /// leave its TLD/Theap/list membership live. A suspended engine or pending
    /// OS release has an independent Rust owner and remains fail-closed.
    #[inline]
    pub(crate) fn permits_process_done_source_retention(&self) -> bool {
        let tld_matches = self
            .tld
            .as_ref()
            .is_some_and(|tld| tld.thread() == self.thread);
        let theap_matches = self
            .theap
            .as_ref()
            .and_then(MetaAllocation::dynamic_theap)
            .is_some_and(|theap| theap.is_initialized() && theap.matches_thread(self.thread));
        self.ensure_attached_current().is_ok()
            && self.terminal_os_release.is_none()
            && !self.page_engine_suspended
            && !self.has_active_deferred_free_callback()
            && tld_matches
            && theap_matches
    }

    /// Exact source image for a vanished worker's child-only page drain.
    /// This never reads or rewrites the survivor's compiler-TLS roots.
    ///
    /// # Safety
    /// The child continuation keeps native entry closed and retains this
    /// copied owner, with no old observations or callbacks. The source thread
    /// vanished, and all copied libc outer locks have been released.
    pub(crate) unsafe fn vanished_child_source(
        &mut self,
    ) -> Result<(NonNull<Theap>, LiveThreadId, MainStaticHeapLease<'main>), MainHeapThreadAttachmentError> {
        if self.state != MainHeapThreadAttachmentState::Attached
            || self.has_active_deferred_free_callback()
            || self.terminal_os_release.is_some() || self.page_engine_suspended
            || !self.counted_in_main_heap
            || !matches!(current_thread_identity(), Some(thread) if thread != self.thread)
        { return Err(MainHeapThreadAttachmentError::PageDrainState); }
        let allocation = self.theap.as_ref().ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
        let valid = allocation.dynamic_theap().is_some_and(|theap| {
            theap.is_initialized() && theap.matches_thread(self.thread)
                && theap.is_bound_to_main_subprocess(self.main_heap.subprocess())
                && theap.refcount() == 1 && theap.allows_page_abandon()
        });
        if !valid { return Err(MainHeapThreadAttachmentError::ListOwnership); }
        let pointer = allocation.pointer().cast::<Theap>();
        let tld = unsafe {
            self.tld.as_mut().ok_or(MainHeapThreadAttachmentError::Poisoned)?
                .vanished_child_mut()
        }.map_err(MainHeapThreadAttachmentError::ThreadLocalData)?;
        if !unsafe { tld.has_exact_theap_member(pointer.as_ptr()) } {
            return Err(MainHeapThreadAttachmentError::ListOwnership);
        }
        Ok((pointer, self.thread, self.main_heap))
    }

    /// Retires one vanished worker after its child-only source collect-abandon.
    /// The remaining process graph owns every inherited live client page.
    ///
    /// # Safety
    /// `vanished_child_source`'s obligations apply. The engine and all page
    /// sessions have ended, every queue/direct entry is empty, and the earlier
    /// child thread-done prefix accounted for thread statistics exactly once.
    /// Failure retains this wrapper and requires child fail-stop; no retry or
    /// survivor TLS publication is permitted.
    pub(crate) unsafe fn retire_vanished_child_after_page_drain(&mut self)
        -> Result<(), MainHeapThreadAttachmentError> {
        let (pointer, _, main_heap) = unsafe { self.vanished_child_source()? };
        if unsafe { pointer.as_ref().page_count() } != 0 {
            return Err(MainHeapThreadAttachmentError::PageCountNonZero);
        }
        let result = (|| {
            let mut heap = main_heap.lock_heap().map_err(MainHeapThreadAttachmentError::MainHeap)?;
            // Source merge precedes the TLD-locked Heap unlink. The shared
            // observation ends before either intrusive link can be changed.
            heap.heap_mut().merge_detached_theap_statistics(unsafe { pointer.as_ref() });
            let tld = unsafe { self.tld.as_mut().ok_or(MainHeapThreadAttachmentError::Poisoned)?
                .vanished_child_mut() }.map_err(MainHeapThreadAttachmentError::ThreadLocalData)?;
            let detach = tld.detach_one_theap_from_heap(heap.heap_mut(), pointer.as_ptr())
                .map_err(MainHeapThreadAttachmentError::TheapList);
            let unlock = heap.unlock().map_err(|error| MainHeapThreadAttachmentError::MainHeap(
                MainStaticHeapLeaseError::Lock(error)));
            detach.and(unlock)?;
            tld.detach_one_theap_from_tld(pointer.as_ptr()).map_err(MainHeapThreadAttachmentError::TheapList)?;
            if !self.theap.as_mut().and_then(MetaAllocation::dynamic_theap_mut)
                .is_some_and(Theap::clear_dynamic_metadata_after_detach)
            { return Err(MainHeapThreadAttachmentError::TheapClear); }
            let mut allocation = self.theap.take().ok_or(MainHeapThreadAttachmentError::Poisoned)?;
            if let Err(error) = self.metadata.free(&mut allocation) {
                self.theap = Some(allocation);
                return Err(MainHeapThreadAttachmentError::TheapMetadata(error));
            }
            unsafe { self.tld.as_mut().ok_or(MainHeapThreadAttachmentError::Poisoned)?
                .retire_vanished_child_after_theap_detached() }
                .map_err(MainHeapThreadAttachmentError::ThreadLocalData)?;
            self.tld = None;
            if !self.main_heap.note_later_theap_detached() {
                return Err(MainHeapThreadAttachmentError::SharedCount);
            }
            self.counted_in_main_heap = false;
            self.state = MainHeapThreadAttachmentState::TornDown;
            Ok(())
        })();
        result.map_err(|error| self.poison(error))
    }

    /// Validates a remote terminal transfer without treating the terminal
    /// writer as this source attachment's originating thread.
    ///
    /// # Safety
    /// Native admission excludes all source entries and callbacks for this
    /// read-only observation; this exact attachment/TLS mapping and metadata
    /// are pinned. The actual consuming transfer requires permanent exclusion.
    pub(crate) unsafe fn permits_terminal_source_transfer(&self) -> bool {
        self.state == MainHeapThreadAttachmentState::Attached
            && !self.has_active_deferred_free_callback()
            && self.terminal_os_release.is_none() && !self.page_engine_suspended
            && self.theap.as_ref().is_some_and(|allocation| {
                allocation.can_transfer_source_retained_theap()
                    && allocation.dynamic_theap().is_some_and(|theap| {
                        theap.is_initialized() && theap.matches_thread(self.thread)
                    })
            })
            && self.tld.as_ref().is_some_and(|tld| {
                tld.thread() == self.thread
                    && unsafe { tld.can_transfer_source_state_terminal_quiescent() }
            })
    }

    /// Read-only preflight before copying a source owner which child repair
    /// may need to retire. No current-thread TLS identity is adopted.
    ///
    /// # Safety
    /// The prepared fork epoch excludes every source entry/callback for this
    /// scoped observation and its registry pins this exact owner/metadata.
    pub(crate) unsafe fn permits_child_source_retirement(&self) -> bool {
        (unsafe { self.permits_terminal_source_transfer() })
            && self.theap.as_ref().and_then(MetaAllocation::dynamic_theap)
                .is_some_and(|theap| theap.refcount() == 1 && theap.allows_page_abandon())
    }

    /// Transfers both exact metadata capabilities after the terminal engine
    /// retirement. It changes no source list, page or refcount; the following
    /// force-destruction pass is the sole owner of those source transitions.
    ///
    /// # Safety
    /// `permits_terminal_source_transfer`'s obligations apply permanently:
    /// originating-thread entry and every other observer can never resume.
    /// Every engine borrowing this attachment has already been consumed, and this wrapper
    /// is made permanently inaccessible before any backing retirement.
    pub(crate) unsafe fn transfer_source_state_terminal_quiescent(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if !unsafe { self.permits_terminal_source_transfer() } {
            return Err(MainHeapThreadAttachmentError::PageDrainState);
        }
        self.transfer_prevalidated_source_state(|tld| {
            // SAFETY: the enclosing permanent terminal capability supplies
            // the exact remote TLD authority checked above.
            unsafe { tld.transfer_source_state_terminal_quiescent() }
        })
    }

    /// Hands the metadata release rights to the persistent source Heap/Theap
    /// graph before libc releases this worker's TLS mapping. This changes no
    /// source roots, lists, reference counts, live-thread count, or pages.
    ///
    /// # Safety
    /// The caller has selected the nonfinal post-process-done exit and must
    /// permanently disable this wrapper and its page engine before TLS is
    /// released. The process graph must remain live until a quiescent source
    /// heap destruction recovers each transferred metadata owner once.
    pub(crate) unsafe fn transfer_source_state_after_process_done(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if !self.permits_process_done_source_retention() {
            return Err(MainHeapThreadAttachmentError::PageDrainState);
        }
        if !self.theap.as_ref().is_some_and(MetaAllocation::can_transfer_source_retained_theap)
            || !self.tld.as_mut().is_some_and(DynamicAttachedThreadLocalData::can_transfer_source_state_after_process_done)
        {
            return Err(MainHeapThreadAttachmentError::TheapProjection);
        }
        self.transfer_prevalidated_source_state(|tld| {
            // SAFETY: forwarded from this nonfinal process-done transfer.
            unsafe { tld.transfer_source_state_after_process_done() }
        })
    }

    fn transfer_prevalidated_source_state(
        &mut self,
        transfer_tld: impl FnOnce(&mut DynamicAttachedThreadLocalData) -> Result<NonNull<crate::types::ThreadLocalData>, crate::tld::ThreadLocalDataError>,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        let allocation = self.theap.take().ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
        match allocation.into_source_retained_theap() {
            Ok(_theap) => {}
            Err(allocation) => {
                self.theap = Some(allocation);
                return Err(MainHeapThreadAttachmentError::TheapProjection);
            }
        }
        let result = transfer_tld(self.tld.as_mut().expect("retention preflight validated TLD"));
        if let Err(error) = result {
            // Both exact capabilities were preflighted without intervening
            // source mutation. An inconsistent second transfer is terminal:
            // the Heap still owns the source Theap, while this wrapper keeps
            // the refused TLD capability. Do not recover a raw owner before
            // whole-process quiescence or allow libc to release this TLS.
            self.state = MainHeapThreadAttachmentState::Poisoned;
            return Err(MainHeapThreadAttachmentError::ThreadLocalData(error));
        }
        self.tld = None;
        self.state = MainHeapThreadAttachmentState::SourceRetained;
        Ok(())
    }

    /// Reports whether a selected source deferred-free callback has not yet
    /// passed its normal attachment completion boundary.
    ///
    /// This is an admission predicate only. The callback continuation itself
    /// remains a non-Send caller-stack value, so nested allocation cannot
    /// overwrite one mutable attachment slot.
    #[inline]
    pub(crate) fn has_active_deferred_free_callback(&self) -> bool {
        self.deferred_free_callback_active.load(Ordering::Acquire) != 0
    }

    /// Reports that the source collector and the final attachment boundary
    /// have both completed.  This is intentionally narrower than a generic
    /// attachment-state accessor: the persistent TLS cell uses it only before
    /// dropping the already-drained owner shell after owner-exit phase C.
    #[inline]
    pub(crate) fn is_torn_down_after_owner_exit(&self) -> bool {
        self.state == MainHeapThreadAttachmentState::TornDown
    }

    /// Selects the source `_mi_deferred_free` callback after the allocator's
    /// phase-A counter decision and before its corresponding mini, full, or
    /// forced collector. It performs no user callback while borrowing this
    /// attachment.
    pub(crate) fn begin_deferred_free_callback(
        &mut self,
        force: bool,
    ) -> Result<MainHeapThreadDeferredFreeCall, MainHeapThreadAttachmentError> {
        // Preserve the same root/list/TLD identity that an ordinary source
        // collector requires, but do not clear a fast slot or begin teardown.
        // Pinned `_mi_deferred_free` may itself run during the selected user
        // callback: its exact active generation and source `recurse` marker
        // prove that nested entry, which advances heartbeat then returns
        // `Complete` without selecting user code a second time.
        let callback_reentry = self.has_active_deferred_free_callback();
        if callback_reentry {
            self.prevalidate_owner_local_callback_reentry()?;
        } else {
            self.prevalidate_page_drain_common(false, true)?;
        }
        self.select_deferred_free_callback(force, callback_reentry)
    }

    /// Selects the source `_mi_deferred_free` callback after the thread-exit
    /// transition cleared only the fixed fast root.  Pinned
    /// `threadlocal.c:_mi_thread_locals_thread_done` clears that fast slot,
    /// while `alloc.c:mi_malloc` still selects `_mi_theap_default()` and
    /// `init.c:mi_thread_theaps_done` resets default only after every
    /// `_mi_theap_collect_abandon` call returned. The callback therefore
    /// makes a normal nested allocation through this same old default owner;
    /// it must nevertheless return its invocation token before any drain
    /// session or queue collector is formed.
    pub(crate) fn begin_thread_exit_deferred_free_callback(
        &mut self,
        force: bool,
    ) -> Result<MainHeapThreadDeferredFreeCall, MainHeapThreadAttachmentError> {
        if self.has_active_deferred_free_callback() {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackActive);
        }
        self.ensure_draining_current()?;
        self.prevalidate_page_drain_common(false, false)?;
        self.select_deferred_free_callback(force, false)
    }

    /// Selects one deferred-free source boundary after its caller proved the
    /// attached or post-fast-slot root image.  This performs only the source
    /// heartbeat, registration load, and recurse-marker selection; it never
    /// invokes foreign code while borrowing this attachment.
    fn select_deferred_free_callback(
        &mut self,
        force: bool,
        callback_reentry: bool,
    ) -> Result<MainHeapThreadDeferredFreeCall, MainHeapThreadAttachmentError> {
        let theap = NonNull::new(self.theap_pointer()?)
            .ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
        let tld = if callback_reentry {
            NonNull::from(self.current_deferred_callback_tld_mut()?)
        } else {
            NonNull::from(self.current_tld_mut()?)
        };
        let source_thread_sequence = unsafe { theap.as_ref() }
            .thread_sequence()
            .ok_or(MainHeapThreadAttachmentError::DeferredFreeCallbackLease)?;
        if unsafe { tld.as_ref() }.thread_sequence().get() != source_thread_sequence {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackLease);
        }
        match deferred_free::begin_process(theap, tld, force)
            .map_err(MainHeapThreadAttachmentError::DeferredFree)?
        {
            DeferredFreeInvocation::Complete(heartbeat) => {
                Ok(MainHeapThreadDeferredFreeCall::Complete(heartbeat))
            }
            invocation @ DeferredFreeInvocation::Callback(_) => {
                // A nested `_mi_deferred_free` increments the heartbeat then
                // observes the live TLD recurse marker above, so it reaches
                // `Complete` and does not take this branch. A second selected
                // callback would instead be a broken owner transition; drop
                // its token to restore the just-set recurse marker and retain
                // the outer caller-stack lease as the sole active callback.
                if self.has_active_deferred_free_callback() {
                    drop(invocation);
                    return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackActive);
                }
                let mut generation = self.deferred_free_callback_generation.wrapping_add(1);
                if generation == 0 {
                    generation = 1;
                }
                self.deferred_free_callback_generation = generation;
                self.deferred_free_callback_active
                    .store(generation, Ordering::Release);
                Ok(MainHeapThreadDeferredFreeCall::Callback {
                    invocation,
                    lease: MainHeapThreadDeferredFreeCallbackLease {
                        theap,
                        tld,
                        source_thread_sequence,
                        source_thread: self.thread,
                        generation,
                        _not_send_or_sync: PhantomData,
                    },
                })
            }
        }
    }

    /// Consumes the caller-stack callback lease after its user function has
    /// returned, then revalidates the current source attachment before the
    /// caller resumes its saved collection or allocation transition.
    pub(crate) fn complete_deferred_free_callback(
        &mut self,
        lease: MainHeapThreadDeferredFreeCallbackLease,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if self.deferred_free_callback_active.load(Ordering::Acquire) != lease.generation {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackLease);
        }
        // Do not clear the activity marker until every scalar source identity
        // check succeeds. A stale completion can name the current generation
        // while carrying a reused Theap/TLD address or another source thread;
        // clearing it first would reopen teardown and ordinary admission while
        // the actual callback's caller-stack lease may still be live. Every
        // error below deliberately retains this fail-closed marker.
        match self.state {
            MainHeapThreadAttachmentState::Attached => {
                self.prevalidate_page_drain_common(false, true)?;
            }
            MainHeapThreadAttachmentState::DrainingPages => {
                self.ensure_draining_current()?;
                self.prevalidate_page_drain_common(false, false)?;
            }
            MainHeapThreadAttachmentState::TornDown => {
                return Err(MainHeapThreadAttachmentError::TornDown);
            }
            MainHeapThreadAttachmentState::Preparing
            | MainHeapThreadAttachmentState::SourceRetained
            | MainHeapThreadAttachmentState::Poisoned => {
                return Err(MainHeapThreadAttachmentError::Poisoned);
            }
        }
        // Capture the attachment thread identity before projecting its TLD.
        // The callback boundary must not retain an outer attachment borrow
        // while user code runs, and phase C checks the saved scalar identity
        // only after that projection has been reacquired.
        let current_source_thread = self.thread;
        let current_theap = self.theap_pointer()?;
        let current_theap_sequence = unsafe { (&*current_theap).thread_sequence() };
        let current_tld = self.current_tld_mut()?;
        if current_theap != lease.theap.as_ptr()
            || !core::ptr::eq(current_tld, lease.tld.as_ptr())
            || current_source_thread != lease.source_thread
            || current_theap_sequence != Some(lease.source_thread_sequence)
            || current_tld.thread_sequence().get() != lease.source_thread_sequence
        {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackLease);
        }
        // This exact lease proved the current source generation, TLD lifetime,
        // and owner thread. Its foreign callback has returned, so phase C may
        // now reopen only to resume the caller-stack continuation below.
        self.deferred_free_callback_active.store(0, Ordering::Release);
        Ok(())
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

    /// Resets only the source generic counters after a focused test seeded
    /// its direct-small page. The pinned C deferred-free fixture performs the
    /// same reset before it measures 1k/10k administration timing.
    #[cfg(test)]
    pub(crate) fn test_reset_generic_allocation_administration(
        &self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        let theap = self.local_theap_pointer()?;
        // SAFETY: this attachment retains the exact current source Theap and
        // the test invokes it outside any allocation/session projection. The
        // helper writes only the two source-local generic counters.
        unsafe { Theap::test_reset_generic_allocation_administration_at(theap) };
        Ok(())
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
        #[cfg(test)]
        if self.detached_process_page_finish_failures != 0 {
            self.detached_process_page_finish_failures -= 1;
            return Err(MainHeapThreadAttachmentError::TheapProjection);
        }
        self.finish_after_page_drain()
    }

    /// Makes the next selected final attachment-boundary attempts fail before
    /// any root/list/TLD mutation.
    ///
    /// This is test-only evidence for the consuming collect-abandon wrapper.
    /// It deliberately cannot select production cleanup, a scheduler, a
    /// registry, or a page route.
    #[cfg(test)]
    pub(crate) fn test_fail_detached_process_page_finish_times(&mut self, failures: usize) {
        assert_ne!(failures, 0, "the focused post-drain fault has one selected attempt");
        assert_eq!(
            self.detached_process_page_finish_failures, 0,
            "one attachment owns at most one focused post-drain fault plan"
        );
        self.detached_process_page_finish_failures = failures;
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
            let initialize = unsafe {
                theap.initialize_shared_main_metadata(heap.heap_mut(), tld, self.page_mode)
            };
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
        // `init.c:358` records the source thread only after both default and
        // fast roots publish the initialized Theap.
        self.main_heap
            .subprocess()
            .record_statistics_thread_attached();
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
        if self.has_active_deferred_free_callback() {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackActive);
        }
        match owner_local_page_engine_state() {
            MainHeapThreadOwnerLocalPageEngineState::Missing => {}
            MainHeapThreadOwnerLocalPageEngineState::Idle => {
                return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineActive);
            }
            MainHeapThreadOwnerLocalPageEngineState::Borrowed => {
                return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineReentrant);
            }
            MainHeapThreadOwnerLocalPageEngineState::Terminal => {
                return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineTerminal);
            }
        }
        self.prevalidate_attached_page_drain_without_owner_local(require_empty)
    }

    fn prevalidate_attached_page_drain_without_owner_local(
        &mut self,
        require_empty: bool,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if self.has_active_deferred_free_callback() {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackActive);
        }
        if self.page_engine_suspended {
            return Err(MainHeapThreadAttachmentError::PersistentPageEngineSuspended);
        }
        self.ensure_attached_current()?;
        self.prevalidate_page_drain_common(require_empty, true)
    }

    /// Validates one ordinary local allocation entered from the selected
    /// deferred-free callback.  The source keeps `TLD::recurse` set for the
    /// whole foreign call, and the active attachment generation prevents
    /// teardown, fork preservation, or a second selected callback while the
    /// caller-stack continuation is outstanding.  That exact combination is
    /// the one exception to the normal active-callback refusal: pinned
    /// `_mi_deferred_free` permits allocator reentry, and the nested source
    /// prefix observes `recurse` and skips user callback recursion.
    ///
    /// This deliberately does not make `has_active_deferred_free_callback`
    /// a general allocation permission.  A live callback lease without the
    /// current TLD recursion marker remains an incomplete or stale phase and
    /// is rejected as before.
    fn prevalidate_owner_local_callback_reentry(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        let active_generation = self.deferred_free_callback_active.load(Ordering::Acquire);
        if active_generation == 0 {
            return self.prevalidate_attached_page_drain_without_owner_local(false);
        }
        // A stale publication cannot confer allocation permission.  The
        // attachment's scalar generation is advanced only when it mints the
        // matching caller-stack lease, and `ensure_attached_current` below
        // ties that lease to this current-thread attachment.
        if active_generation != self.deferred_free_callback_generation {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackGeneration);
        }
        let expect_fast_owner = match self.state {
            MainHeapThreadAttachmentState::Attached => {
                self.ensure_attached_current()?;
                true
            }
            // `mi_thread_theaps_done` clears the fixed fast root before it
            // enters `_mi_theap_collect_abandon`. The selected callback still
            // owns the default root/TLD/list and may allocate through the
            // exact persistent engine until phase C resumes that drain.
            MainHeapThreadAttachmentState::DrainingPages => {
                self.ensure_draining_current()?;
                false
            }
            MainHeapThreadAttachmentState::TornDown => {
                return Err(MainHeapThreadAttachmentError::TornDown);
            }
            MainHeapThreadAttachmentState::Preparing
            | MainHeapThreadAttachmentState::SourceRetained
            | MainHeapThreadAttachmentState::Poisoned => {
                return Err(MainHeapThreadAttachmentError::Poisoned);
            }
        };
        // A projection failure is not equivalent to a non-recursing TLD.
        // Preserve its exact attached-owner error for the caller's retained
        // boundary; otherwise a poisoned/replaced TLD could be misreported as
        // an ordinary callback that merely cannot reenter.
        let current_callback_reentry = self.current_deferred_callback_recurse()?;
        if !current_callback_reentry {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackNotRecursing);
        }
        if self.page_engine_suspended {
            return Err(MainHeapThreadAttachmentError::PersistentPageEngineSuspended);
        }
        self.prevalidate_page_drain_common_callback_reentry(false, expect_fast_owner)
    }

    /// Validates one ordinary owner-local page operation on the persistent
    /// engine.
    ///
    /// Outside a selected deferred-free callback this performs every check of
    /// the non-callback path of
    /// [`Self::prevalidate_owner_local_callback_reentry`] (attachment state,
    /// suspension, current identity, Theap refcount/thread/subprocess, TLS
    /// roots, and TLD-list membership) except the locked re-observation of
    /// the shared main Heap list; see [`SharedHeapMembership`]. The rare
    /// callback-reentry path keeps its complete observation.
    fn prevalidate_owner_local_operation(
        &mut self,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if self.has_active_deferred_free_callback() {
            return self.prevalidate_owner_local_callback_reentry();
        }
        if self.page_engine_suspended {
            return Err(MainHeapThreadAttachmentError::PersistentPageEngineSuspended);
        }
        self.ensure_attached_current()?;
        self.prevalidate_page_drain_common_with_tld_projection(
            false,
            true,
            false,
            SharedHeapMembership::AttachedInvariant,
        )
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
        self.prevalidate_page_drain_common_with_tld_projection(
            require_empty,
            expect_fast_owner,
            false,
            SharedHeapMembership::Observe,
        )
    }

    /// Validates the same root/list image for a nested allocation during the
    /// caller-stack deferred-free callback. The special TLD projection admits
    /// only the live recurse marker that phase A already selected.
    fn prevalidate_page_drain_common_callback_reentry(
        &mut self,
        require_empty: bool,
        expect_fast_owner: bool,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        self.prevalidate_page_drain_common_with_tld_projection(
            require_empty,
            expect_fast_owner,
            true,
            SharedHeapMembership::Observe,
        )
    }

    fn prevalidate_page_drain_common_with_tld_projection(
        &mut self,
        require_empty: bool,
        expect_fast_owner: bool,
        callback_reentry: bool,
        membership: SharedHeapMembership,
    ) -> Result<(), MainHeapThreadAttachmentError> {
        if self.terminal_os_release.is_some() {
            return Err(MainHeapThreadAttachmentError::Poisoned);
        }
        let theap_pointer = self.theap_pointer()?;
        let (page_count, refcount, matches_thread, bound_to_main_subprocess) = {
            let theap = self
                .theap
                .as_ref()
                .and_then(MetaAllocation::dynamic_theap)
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
        let has_exact_theap_member = if callback_reentry {
            // SAFETY: the callback-only projection revalidated this exact
            // source TLD and its published recurse marker. This reads its
            // retained intrusive-list identity without carrying a TLD borrow
            // into the following shared-Heap observation.
            unsafe {
                self.current_deferred_callback_tld_mut()?
                    .has_exact_theap_member(theap_pointer)
            }
        } else {
            // SAFETY: ordinary callers use the non-recursing current TLD
            // projection before inspecting the retained list identity.
            unsafe { self.current_tld_mut()?.has_exact_theap_member(theap_pointer) }
        };
        if !has_exact_theap_member {
            return Err(MainHeapThreadAttachmentError::ListOwnership);
        }
        if membership == SharedHeapMembership::AttachedInvariant {
            return Ok(());
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
        // `init.c:471` adjusts `stats.threads` after the source fast/TLS
        // clear and before the later Theap/page-drain work begins.
        self.main_heap
            .subprocess()
            .record_statistics_thread_detached();
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
            MainHeapThreadAttachmentState::Preparing | MainHeapThreadAttachmentState::SourceRetained | MainHeapThreadAttachmentState::Poisoned => {
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
            MainHeapThreadAttachmentState::Preparing | MainHeapThreadAttachmentState::SourceRetained | MainHeapThreadAttachmentState::Poisoned => {
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

    /// Projects the current TLD only while its exact selected deferred-free
    /// callback owns the source recurse marker. Ordinary attachment paths use
    /// [`Self::current_tld_mut`] and therefore continue to reject recursion.
    #[inline]
    fn current_deferred_callback_tld_mut(
        &mut self,
    ) -> Result<&mut crate::types::ThreadLocalData, MainHeapThreadAttachmentError> {
        self.tld
            .as_mut()
            .ok_or(MainHeapThreadAttachmentError::Poisoned)?
            .current_deferred_callback_mut()
            .map_err(MainHeapThreadAttachmentError::ThreadLocalData)
    }

    /// Observes the recurse marker after validating the exact current callback
    /// TLD identity. This leaves callback allocation itself behind
    /// `current_deferred_callback_tld_mut`, which still requires `recurse`.
    #[inline]
    fn current_deferred_callback_recurse(
        &mut self,
    ) -> Result<bool, MainHeapThreadAttachmentError> {
        self.tld
            .as_mut()
            .ok_or(MainHeapThreadAttachmentError::Poisoned)?
            .current_deferred_callback_recurse()
            .map_err(MainHeapThreadAttachmentError::ThreadLocalData)
    }

    /// Returns the validated dynamic metadata Theap address for a field-level
    /// session operation. A transient `dynamic_theap` read proves liveness and
    /// the dynamic-Theap role, then ends before this returns the original
    /// metadata capability's writable raw storage address. It never casts a
    /// shared `&Theap` into mutation authority or forms a whole mutable Theap
    /// projection.
    #[inline]
    fn local_theap_pointer(&self) -> Result<NonNull<Theap>, MainHeapThreadAttachmentError> {
        let allocation = self
            .theap
            .as_ref()
            .ok_or(MainHeapThreadAttachmentError::TheapProjection)?;
        if allocation.dynamic_theap().is_none() {
            return Err(MainHeapThreadAttachmentError::TheapProjection);
        }
        // The validation view ended above. `pointer` is the original pinned
        // metadata capability, whose exact live dynamic-Theap layout was just
        // checked; field helpers receive no whole-image reference.
        Ok(allocation.pointer().cast())
    }

    #[inline]
    fn theap_pointer(&self) -> Result<*mut Theap, MainHeapThreadAttachmentError> {
        Ok(self.local_theap_pointer()?.as_ptr())
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
        match owner_local_page_engine_state() {
            MainHeapThreadOwnerLocalPageEngineState::Idle => {}
            MainHeapThreadOwnerLocalPageEngineState::Borrowed => {
                return Err(MainHeapThreadPageSessionError::Attachment(
                    MainHeapThreadAttachmentError::OwnerLocalPageEngineReentrant,
                ));
            }
            MainHeapThreadOwnerLocalPageEngineState::Terminal => {
                return Err(MainHeapThreadPageSessionError::Attachment(
                    MainHeapThreadAttachmentError::OwnerLocalPageEngineTerminal,
                ));
            }
            MainHeapThreadOwnerLocalPageEngineState::Missing => {
                return Err(MainHeapThreadPageSessionError::Attachment(
                    MainHeapThreadAttachmentError::OwnerLocalPageEngineMissing,
                ));
            }
        }
        attachment
            .prevalidate_owner_local_operation()
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
        // Every attachment/root/list check has succeeded and no fallible step
        // remains. Publish the synchronous borrow only now, so a rejection
        // leaves the persistent engine idle and retryable.
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Borrowed);
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
    fn local_theap_pointer(&self) -> NonNull<Theap> {
        self.attachment
            .local_theap_pointer()
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

impl MainHeapThreadOwnerLocalPageEngineLease {
    /// Reads only the retained claim/attachment identity. Permanent terminal
    /// exclusion supplies the proof that no originating-thread borrow remains.
    pub(crate) fn matches_terminal_attachment(&self, attachment: &MainHeapThreadAttachment<'_>) -> bool {
        !self.finished && self.thread_sequence != 0 && self.thread == attachment.thread
            && attachment.tld.as_ref().is_some_and(|tld| tld.sequence().get() == self.thread_sequence)
    }

    /// Ends this wrapper's Drop obligation without writing the terminally
    /// excluded originating thread's independent compiler-TLS engine flag.
    ///
    /// # Safety
    /// The engine has consumed every session/backing borrow, native terminal
    /// admission permanently forbids future source access, and the exact
    /// descriptor/TLS image remains pinned through this operation.
    pub(crate) unsafe fn finish_terminal_quiescent(&mut self) { self.finished = true; }

    /// Disarms only the vanished thread's local-engine lease after child
    /// collection consumed that engine. Survivor compiler TLS is untouched.
    ///
    /// # Safety
    /// The sole-child continuation excludes source entry and retains this
    /// vanished owner. Its engine/session has ended and it can never resume.
    pub(crate) unsafe fn finish_vanished_child(&mut self) { self.finished = true; }

    /// Claims the current attachment's compiler-TLS owner after an ordinary
    /// empty page session has established its exact root/list/thread identity.
    pub(crate) fn claim(
        session: &MainHeapThreadPageSession<'_, '_>,
    ) -> Result<Self, MainHeapThreadAttachmentError> {
        match owner_local_page_engine_state() {
            MainHeapThreadOwnerLocalPageEngineState::Missing => {}
            MainHeapThreadOwnerLocalPageEngineState::Idle => {
                return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineActive);
            }
            MainHeapThreadOwnerLocalPageEngineState::Borrowed => {
                return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineReentrant);
            }
            MainHeapThreadOwnerLocalPageEngineState::Terminal => {
                return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineTerminal);
            }
        }
        let thread = session
            .thread_id()
            .ok_or(MainHeapThreadAttachmentError::InvalidCurrentThread)?;
        if current_thread_identity() != Some(thread) {
            return Err(MainHeapThreadAttachmentError::InvalidCurrentThread);
        }
        let thread_sequence = session.thread_sequence();
        if thread_sequence == 0 {
            return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineMissing);
        }
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Idle);
        Ok(Self {
            thread,
            thread_sequence,
            finished: false,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Consumes the continuously stored owner-local claim into the one-way
    /// source owner-exit drain. Every fallible attachment preflight completes
    /// before the fixed fast slot or compiler-TLS owner state changes.
    pub(crate) fn begin_thread_exit_drain<'attachment, 'main>(
        &mut self,
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<MainHeapThreadPageDrainSession<'attachment, 'main>, MainHeapThreadAttachmentError> {
        self.precheck_access()?;
        attachment.prevalidate_attached_page_drain_without_owner_local(false)?;
        if attachment.terminal_os_release.is_some() {
            return Err(MainHeapThreadAttachmentError::Poisoned);
        }
        set_fast_slot(None);
        attachment.state = MainHeapThreadAttachmentState::DrainingPages;
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Missing);
        self.finished = true;
        Ok(MainHeapThreadPageDrainSession { attachment })
    }

    /// Starts the source thread-exit deferred-free phase without forming a
    /// draining session.  The fixed fast root is cleared first, exactly as
    /// `mi_thread_theaps_done` does before `_mi_theap_collect_abandon`; the
    /// owner-local claim stays idle so the selected callback can reenter the
    /// same default Theap.  Only phase C may later consume this claim into
    /// the non-allocating page-drain session.
    pub(crate) fn begin_thread_exit_deferred_free_phase(
        &mut self,
        attachment: &mut MainHeapThreadAttachment<'_>,
    ) -> Result<MainHeapThreadDeferredFreeCall, MainHeapThreadAttachmentError> {
        self.precheck_access()?;
        attachment.prevalidate_attached_page_drain_without_owner_local(false)?;
        if attachment.terminal_os_release.is_some() {
            return Err(MainHeapThreadAttachmentError::Poisoned);
        }
        set_fast_slot(None);
        // This normal A/B/C route has the same `init.c:471` source event as
        // the no-page drain, but reaches its callback before phase C consumes
        // the attachment. Neither route can enter the other's clear prefix.
        attachment
            .main_heap
            .subprocess()
            .record_statistics_thread_detached();
        attachment.state = MainHeapThreadAttachmentState::DrainingPages;
        match attachment.begin_thread_exit_deferred_free_callback(true) {
            Ok(call) => Ok(call),
            Err(error) => {
                // Fast-slot removal is a one-way source transition.  The
                // caller must retain the exact engine instead of recreating
                // an attached owner after a failed phase-A selection.
                self.retain_terminal_after_thread_exit_failure();
                attachment.state = MainHeapThreadAttachmentState::Poisoned;
                Err(error)
            }
        }
    }

    /// Consumes the idle claim into the page-drain session after the
    /// caller-stack deferred-free invocation completed and phase C cleared
    /// the matching attachment generation.  No callback token, TLD, engine,
    /// or attachment borrow crosses the foreign call.
    pub(crate) fn finish_thread_exit_deferred_free_phase<'attachment, 'main>(
        &mut self,
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<MainHeapThreadPageDrainSession<'attachment, 'main>, MainHeapThreadAttachmentError> {
        self.precheck_access()?;
        if attachment.has_active_deferred_free_callback() {
            return Err(MainHeapThreadAttachmentError::DeferredFreeCallbackActive);
        }
        attachment.ensure_draining_current()?;
        attachment.prevalidate_page_drain_common(false, false)?;
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Missing);
        self.finished = true;
        Ok(MainHeapThreadPageDrainSession { attachment })
    }

    /// Checks the compiler-TLS linear/reentry state before the caller forms a
    /// new mutable attachment or page-session projection.
    pub(crate) fn precheck_access(&self) -> Result<(), MainHeapThreadAttachmentError> {
        if self.finished {
            return Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineMissing);
        }
        if current_thread_identity() != Some(self.thread) || self.thread_sequence == 0 {
            return Err(MainHeapThreadAttachmentError::InvalidCurrentThread);
        }
        match owner_local_page_engine_state() {
            MainHeapThreadOwnerLocalPageEngineState::Idle => Ok(()),
            MainHeapThreadOwnerLocalPageEngineState::Borrowed => {
                Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineReentrant)
            }
            MainHeapThreadOwnerLocalPageEngineState::Terminal => {
                Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineTerminal)
            }
            MainHeapThreadOwnerLocalPageEngineState::Missing => {
                Err(MainHeapThreadAttachmentError::OwnerLocalPageEngineMissing)
            }
        }
    }

    /// Releases the linear compiler-TLS claim only after the page engine has
    /// proved quiescent and disarmed its own conservative Drop.
    pub(crate) fn finish(&mut self) -> Result<(), MainHeapThreadAttachmentError> {
        self.precheck_access()?;
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Missing);
        self.finished = true;
        Ok(())
    }

    /// Marks the consumed owner claim terminal after the fast slot changed
    /// but a source queue transition could not complete. The outer owner
    /// retains the exact engine only for fail-closed lifetime accounting; it
    /// must not form another drain from this claim.
    #[inline]
    pub(crate) fn retain_terminal_after_thread_exit_failure(&mut self) {
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Terminal);
        self.finished = true;
    }

    #[cfg(test)]
    pub(crate) fn test_begin_borrowed_state(&mut self) {
        self.precheck_access()
            .expect("the test reentry marker starts from one idle owner");
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Borrowed);
    }

    #[cfg(test)]
    pub(crate) fn test_end_borrowed_state(&mut self) {
        MainHeapThreadAttachment::end_owner_local_page_engine_access();
        self.precheck_access()
            .expect("the test reentry marker restores the idle owner");
    }
}

impl Drop for MainHeapThreadOwnerLocalPageEngineLease {
    fn drop(&mut self) {
        if !self.finished {
            MainHeapThreadAttachment::latch_unfinished_owner_local_page_engine();
        }
    }
}

impl MainHeapThreadAttachment<'_> {
    /// Restores the persistent owner to idle after one synchronous short
    /// source projection, including panic unwinding.
    pub(crate) fn end_owner_local_page_engine_access() {
        match owner_local_page_engine_state() {
            MainHeapThreadOwnerLocalPageEngineState::Borrowed => {
                set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Idle);
            }
            MainHeapThreadOwnerLocalPageEngineState::Terminal => {}
            MainHeapThreadOwnerLocalPageEngineState::Missing
            | MainHeapThreadOwnerLocalPageEngineState::Idle => {
                set_owner_local_page_engine_state(
                    MainHeapThreadOwnerLocalPageEngineState::Terminal,
                );
            }
        }
    }

    /// Permanently prevents fresh page-engine entry and attachment teardown
    /// after an unfinished owner lost its explicit consuming finish boundary.
    pub(crate) fn latch_unfinished_owner_local_page_engine() {
        set_owner_local_page_engine_state(MainHeapThreadOwnerLocalPageEngineState::Terminal);
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
    /// This legacy direct-drain helper is valid only while the process
    /// registration is inert. The doc-hidden native registration adapter uses
    /// the normal A/B/C continuation before it creates a drain session; this
    /// helper still holds its source session and must never dispatch an
    /// arbitrary registered callback. Its test observer proves only the local
    /// heartbeat/recursion order and is not a registration substitute.
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

    /// Returns the exact live Theap address for the post-callback owner-exit
    /// collector. The deferred-free phase has already completed through its
    /// caller-stack continuation before this draining session exists, so this
    /// accessor deliberately carries no TLD or callback authority.
    pub(crate) fn owner_exit_theap_pointer(
        &mut self,
    ) -> Result<NonNull<Theap>, MainHeapThreadAttachmentError> {
        self.attachment.ensure_draining_current()?;
        NonNull::new(self.attachment.theap_pointer()?)
            .ok_or(MainHeapThreadAttachmentError::TheapProjection)
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
    fn local_theap_pointer(&self) -> NonNull<Theap> {
        self.attachment
            .local_theap_pointer()
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
    fn advance_generic_allocation_administration(
        &mut self,
    ) -> crate::types::GenericAllocationAdministration {
        // SAFETY: this validated session owns only the two generic source
        // counters; no whole-Theap mutable projection overlaps Heap links.
        unsafe {
            Theap::advance_generic_allocation_administration_at(
                self.local_theap_pointer(),
                || self.attachment.generic_collect_policy
                    .map_or(10_000, crate::os::VmPolicy::generic_collect_frequency),
            )
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn selects_selected_main_arena_source_full_abandonment(&self) -> bool {
        self.theap().allows_page_abandon()
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn permits_selected_main_arena_ordinary_full_abandonment(&self) -> bool {
        self.attachment.ensure_attached_current().is_ok()
    }

    fn push_selected_main_os_abandoned_page(&mut self, page: NonNull<Page>) -> bool {
        let main_heap = self.attachment.main_heap;
        let linked = match main_heap.lock_heap() {
            Ok(mut heap) => {
                // SAFETY: the ordinary full-page transition has detached this
                // exact page from its local queue after false collection, and
                // the main Heap guard serializes the source private list.
                let linked = unsafe { heap.heap_mut().push_os_abandoned_page(page) };
                let unlocked = heap.unlock();
                linked.is_ok() && unlocked.is_ok()
            }
            Err(_) => false,
        };
        if !linked {
            // A list splice may have become visible before its wake failure.
            // The current page transition must therefore stay terminally
            // retained instead of trying an arena or full-queue fallback.
            self.attachment.state = MainHeapThreadAttachmentState::Poisoned;
        }
        linked
    }

    fn remove_selected_main_os_abandoned_page(&mut self, page: NonNull<Page>) -> bool {
        let main_heap = self.attachment.main_heap;
        let removed = match main_heap.lock_heap() {
            Ok(mut heap) => {
                // SAFETY: the caller has the all-free low-owner result for
                // this exact list member; no queue owner remains and the
                // main Heap guard serializes source list removal.
                let removed = unsafe { heap.heap_mut().remove_os_abandoned_page(page) };
                let unlocked = heap.unlock();
                removed.is_ok() && unlocked.is_ok()
            }
            Err(_) => false,
        };
        if !removed {
            // Removal may have spliced before a post-mutation wake failure,
            // so retain this transition rather than guessing a second owner.
            self.attachment.state = MainHeapThreadAttachmentState::Poisoned;
        }
        removed
    }

    #[inline]
    fn queue(&self, bin: usize) -> Option<&PageQueue> { self.theap().queue(bin) }

    #[inline]
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        // SAFETY: the current page session exclusively owns this ordinary
        // queue; the raw helper never aliases source Heap link fields.
        unsafe { Theap::local_queue_mut_at(self.local_theap_pointer(), bin) }
    }

    #[inline]
    fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.theap().direct_page(index)
    }

    #[inline]
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        // SAFETY: the current page session exclusively owns this direct slot.
        unsafe { Theap::set_local_direct_page_at(self.local_theap_pointer(), index, page) }
    }

    #[inline]
    fn note_page_added(&mut self) {
        // SAFETY: the current page session owns the source page count field.
        unsafe { Theap::note_local_page_added_at(self.local_theap_pointer()) }
    }

    #[inline]
    fn note_page_removed(&mut self) -> bool {
        // SAFETY: the current page session owns the source page count field.
        unsafe { Theap::note_local_page_removed_at(self.local_theap_pointer()) }
    }

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
                    // The common main-Heap guard excludes the source hprev
                    // mutation that otherwise forbids a whole-Theap mutable
                    // projection. Publication is the sole session operation
                    // that requires that complete source image.
                    let theap = self
                        .attachment
                        .theap
                        .as_mut()
                        .and_then(MetaAllocation::dynamic_theap_mut)
                        .expect("the guarded page session retains its typed Theap");
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
        // SAFETY: the current page session owns the retirement bounds.
        unsafe { Theap::note_local_retired_bin_at(self.local_theap_pointer(), bin) }
    }

    #[inline]
    fn reset_retired_bounds(&mut self) {
        // SAFETY: the current page session owns the retirement bounds.
        unsafe { Theap::reset_local_retired_bounds_at(self.local_theap_pointer()) }
    }

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
        // SAFETY: the current page session exclusively owns this ordinary
        // queue; the raw helper never aliases source Heap link fields.
        unsafe { Theap::local_queue_mut_at(self.local_theap_pointer(), bin) }
    }

    #[inline]
    fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.theap().direct_page(index)
    }

    #[inline]
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        // SAFETY: the current page session exclusively owns this direct slot.
        unsafe { Theap::set_local_direct_page_at(self.local_theap_pointer(), index, page) }
    }

    #[inline]
    fn note_page_added(&mut self) {
        // SAFETY: the current page session owns the source page count field.
        unsafe { Theap::note_local_page_added_at(self.local_theap_pointer()) }
    }

    #[inline]
    fn note_page_removed(&mut self) -> bool {
        // SAFETY: the current page session owns the source page count field.
        unsafe { Theap::note_local_page_removed_at(self.local_theap_pointer()) }
    }

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
        // SAFETY: the current page session owns the retirement bounds.
        unsafe { Theap::note_local_retired_bin_at(self.local_theap_pointer(), bin) }
    }

    #[inline]
    fn reset_retired_bounds(&mut self) {
        // SAFETY: the current page session owns the retirement bounds.
        unsafe { Theap::reset_local_retired_bounds_at(self.local_theap_pointer()) }
    }

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
    fn source_retained_workers_transfer_before_tls_exit_and_force_destroy_reclaims_all_theaps() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let process = crate::process_init::ProcessMainInitializationStorage::test_static_owner();
            let page_map = crate::process_page_map::ProcessPageMapStorage::test_static_owner();
            let mut options = crate::config::VmOptions::uninitialized();
            options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
            options.set(crate::config::VmOption::ArenaReserve, 64 * 1024);
            let mut main = unsafe {
                process.initialize_with_test_components_and_vm_options(memory_config(), options,
                    storage, subprocess, metadata, page_map)
            }.expect("canonical source process owner");
            assert!(metadata.test_canonical_metadata_heap_membership());
            let heap = main.attachment_mut().unwrap().shared_main_heap_lease().expect("main Heap");
            thread::scope(|scope| {
                for _ in 0..3 {
                    scope.spawn(move || {
                        let mut owner = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(heap, metadata, memory_config())
                        } {
                            Ok(owner) => owner,
                            Err(_) => panic!("later source owner"),
                        };
                        let pointer = owner.theap_pointer().expect("live Theap");
                        let thread = owner.thread;
                        assert!(owner.permits_process_done_source_retention());
                        unsafe { owner.transfer_source_state_after_process_done() }
                            .expect("explicit metadata transfer precedes TLS loss");
                        assert!(owner.theap.is_none());
                        assert!(owner.tld.is_none());
                        assert!(!owner.permits_process_done_source_retention());
                        assert!(owner.finish_after_user_destructors().is_err());
                        // The transfer does not impersonate thread_done: the
                        // source image and TLS roots remain usable until this
                        // worker exits. No wrapper retains its release right.
                        assert_eq!(default_theap().as_ptr(), pointer);
                        assert!(unsafe { &*pointer }.matches_thread(thread));
                    }).join().expect("source-retained worker exits");
                }
            });
            assert_eq!(metadata.test_allocation_audit().live_capability_count, 6);
            assert_eq!(subprocess.live_thread_count(), 4);
            let before_live = subprocess.live_thread_count();
            let heap_before = subprocess.heap_list().test_counts();
            assert_eq!(heap_before, (1, 1, false));
            let (dynamic_members, attached_tlds, total_members) = {
                let mut guard = heap.lock_heap().expect("quiescent main Heap audit");
                let counts = guard.heap_mut().test_destroy_graph_counts();
                guard.unlock().expect("main Heap audit releases");
                counts
            };
            crate::compiler_tls::clear_main_static_attachment_roots();
            let tracking = std::boxed::Box::leak(std::boxed::Box::new([
                const { crate::types::heap_destroy::MainHeapDestroyTracking::empty() }; 5
            ]));
            // SAFETY: all workers joined after transferring their owners;
            // the remaining initial roots are clear, and this test never
            // accesses the old main attachment or any earlier Heap projection.
            unsafe { heap.force_destroy_source_owned_main_heap(metadata, tracking) }
                .expect("the complete main Heap list is destroyed");
            assert!(heap.lock_heap().is_err(), "copied leases cannot reopen a retired Heap");
            assert_eq!(tracking.iter().filter(|slot| slot.retains_theap()).count(), 0);
            assert_eq!(tracking.iter().filter(|slot| slot.retains_tld()).count(), 3);
            assert_eq!(metadata.test_allocation_audit().live_capability_count, 3);
            assert_eq!(subprocess.live_thread_count(), 4, "source Heap destruction does not free TLDs");
            let detached = tracking.iter_mut().map(|slot| slot.test_retained_tld_is_detached()).filter(|detached| *detached).count();
            assert_eq!(detached, 3);
            for (index, value) in [before_live, dynamic_members, attached_tlds,
                usize::from(heap.test_destroyed_heap_list_empty()), detached, subprocess.live_thread_count(), total_members, heap_before.0,
                subprocess.heap_list().test_counts().0, subprocess.heap_list().test_counts().1,
                usize::from(subprocess.heap_list().test_counts().2)].into_iter().enumerate() {
                std::println!("m2.heap.destroy.{index}={value}");
            }
            // Source static metadata is now detached along with the ordinary
            // static and dynamic members. All dynamic metadata releases above
            // ran through its canonical raw field session after TLD detachment.
            unsafe { metadata.close_process_engine_quiescent() }.expect("metadata session retires");
            // The fixture retains the detached TLD owners in external leaked
            // storage; arena/process destruction is a separate transition.
        }).join().expect("quiescent Heap destruction lifecycle");
    }

    #[test]
    fn source_retained_main_heap_destruction_preserves_owners_on_capacity_and_metadata_refusal() {
        for refuse_metadata in [false, true] {
            thread::spawn(move || {
                use crate::types::heap_destroy::{MainHeapDestroyError, MainHeapDestroyTracking};
                let (storage, subprocess) = fixture();
                let metadata = MetaAllocator::test_static_owner();
                let main = unsafe {
                    MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
                }.expect("main source owner");
                let heap = main.shared_main_heap_lease().expect("main Heap");
                thread::scope(|scope| {
                    scope.spawn(move || {
                        let mut owner = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(heap, metadata, memory_config())
                        } {
                            Ok(owner) => owner,
                            Err(_) => panic!("later source owner"),
                        };
                        unsafe { owner.transfer_source_state_after_process_done() }
                            .expect("explicit source transfer");
                    }).join().expect("transferred worker joins");
                });
                crate::compiler_tls::clear_main_static_attachment_roots();
                let tracking = std::boxed::Box::leak(std::boxed::Box::new([
                    const { MainHeapDestroyTracking::empty() }; 2
                ]));
                if refuse_metadata {
                    // The test holds only metadata's private entry gate, not
                    // a Heap/TLD projection or metadata image. The actual
                    // free receiver refuses before accessing backing state.
                    let result = metadata.test_with_held_backing_entry(|| unsafe {
                        heap.force_destroy_source_owned_theaps(metadata, tracking)
                    }).expect("held metadata entry fixture");
                    assert_eq!(result, Err(MainHeapDestroyError::Metadata(MetaError::RecursiveEntry)));
                    assert_eq!(tracking.iter().filter(|slot| slot.retains_theap()).count(), 1);
                    assert_eq!(tracking.iter().filter(|slot| slot.retains_tld()).count(), 1);
                    assert_eq!(metadata.test_allocation_audit().live_capability_count, 2);
                    let failed = tracking.iter_mut().find(|slot| slot.retains_theap()).unwrap();
                    failed.retry_theap_metadata_release().expect("exact owner retry after entry release");
                    assert_eq!(failed.retry_theap_metadata_release(), Err(MetaError::ReleasedOrStale));
                    assert_eq!(metadata.test_allocation_audit().live_capability_count, 1);
                } else {
                    let result = unsafe { heap.force_destroy_source_owned_theaps(metadata, &mut tracking[..1]) };
                    assert_eq!(result, Err(MainHeapDestroyError::TrackingCapacity { required: 2 }));
                    assert!(tracking.iter().all(|slot| !slot.retains_theap() && !slot.retains_tld()));
                    assert_eq!(metadata.test_allocation_audit().live_capability_count, 2);
                }
                assert!(heap.lock_heap().is_err(), "neither failure reopens the source Heap");
                assert_eq!(subprocess.live_thread_count(), 2);
                // External tracking and the leaked fixture retain every
                // outstanding owner; neither error authorizes arena release.
            }).join().expect("destruction refusal preserves ownership");
        }
    }

    #[test]
    fn deferred_free_callback_reentry_requires_current_generation_recurse_and_source_identity() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main
                .shared_main_heap_lease()
                .expect("the live main attachment lends its static heap");

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut attachment = unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    }
                    .unwrap_or_else(|_| {
                        panic!("the focused attachment publishes its current source pair")
                    });

                    attachment.deferred_free_callback_generation = 7;
                    attachment
                        .deferred_free_callback_active
                        .store(7, Ordering::Release);
                    assert_eq!(
                        attachment.prevalidate_owner_local_callback_reentry(),
                        Err(MainHeapThreadAttachmentError::DeferredFreeCallbackNotRecursing),
                        "an unfinished callback lease without the source recurse marker cannot enter allocation"
                    );

                    assert!(
                        attachment
                            .current_tld_mut()
                            .expect("the attached source TLD remains current")
                            .begin_deferred_callback(),
                        "the focused source TLD begins its one synthetic callback interval"
                    );
                    attachment
                        .deferred_free_callback_active
                        .store(6, Ordering::Release);
                    assert_eq!(
                        attachment.prevalidate_owner_local_callback_reentry(),
                        Err(MainHeapThreadAttachmentError::DeferredFreeCallbackGeneration),
                        "a stale active generation cannot inherit the current TLD recurse permission"
                    );
                    attachment
                        .deferred_free_callback_active
                        .store(7, Ordering::Release);
                    assert!(
                        attachment.prevalidate_owner_local_callback_reentry().is_ok(),
                        "only the current attached source generation with its live recurse marker may reenter"
                    );
                    assert!(matches!(
                        attachment.current_tld_mut(),
                        Err(MainHeapThreadAttachmentError::ThreadLocalData(
                            crate::tld::ThreadLocalDataError::Projection
                        ))
                    ),
                        "ordinary TLD projection stays unavailable while the callback owns recurse"
                    );
                    attachment
                        .current_deferred_callback_tld_mut()
                        .expect("the callback projection retains its source TLD")
                        .end_deferred_callback();

                    let theap = NonNull::new(
                        attachment
                            .theap_pointer()
                            .expect("the focused attachment retains its Theap"),
                    )
                    .expect("the focused Theap address is non-null");
                    let tld = NonNull::from(
                        attachment
                            .current_tld_mut()
                            .expect("the focused attachment retains its TLD"),
                    );
                    let sequence = unsafe { theap.as_ref() }
                        .thread_sequence()
                        .expect("the focused Theap records the live source sequence");
                    let wrong_thread = crate::types::LiveThreadId::new(
                        attachment.thread.get().checked_add(4).unwrap_or(12),
                    )
                    .filter(|thread| *thread != attachment.thread)
                    .or_else(|| crate::types::LiveThreadId::new(12).filter(|thread| *thread != attachment.thread))
                    .expect("the test can name a distinct valid source thread identity");
                    attachment.deferred_free_callback_generation = 8;
                    attachment
                        .deferred_free_callback_active
                        .store(8, Ordering::Release);
                    assert_eq!(
                        attachment.complete_deferred_free_callback(
                            MainHeapThreadDeferredFreeCallbackLease {
                                theap,
                                tld,
                                source_thread_sequence: sequence,
                                source_thread: wrong_thread,
                                generation: 8,
                                _not_send_or_sync: PhantomData,
                            },
                        ),
                        Err(MainHeapThreadAttachmentError::DeferredFreeCallbackLease),
                        "phase C rejects a same-address callback lease from another source thread"
                    );
                    assert!(
                        attachment.has_active_deferred_free_callback(),
                        "a rejected stale lease keeps the active marker fail-closed instead of reopening teardown"
                    );
                    // This test manufactured the active generation without a
                    // real caller-stack callback token. Restore that private
                    // fixture state only after asserting the production
                    // fail-closed postcondition, so normal no-page cleanup
                    // can prove no other source state was changed.
                    attachment
                        .deferred_free_callback_active
                        .store(0, Ordering::Release);
                    attachment
                        .finish_after_user_destructors()
                        .expect("the rejected stale callback lease leaves the no-page source attachment drainable");
                });
                worker
                    .join()
                    .expect("the focused deferred callback attachment stays on its source thread");
            });
            main.teardown()
                .expect("ticket zero retires after the focused callback admission test");
        })
        .join()
        .expect("the focused callback admission test completes");
    }

    #[test]
    fn owner_local_operation_admission_takes_no_shared_main_heap_lock() {
        // Pinned `mi_malloc`/`mi_free` take no Heap lock on the local path.
        // An attached owner's ordinary page-session admission must therefore
        // complete while another thread holds the shared main Heap projection
        // lock; only drain/teardown/resume transitions re-observe the list.
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main
                .shared_main_heap_lease()
                .expect("the live main attachment lends its static heap");
            let (attached_sender, attached_receiver) = mpsc::channel();
            let (go_sender, go_receiver) = mpsc::channel::<()>();
            let (result_sender, result_receiver) = mpsc::channel();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut attachment = unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    }
                    .unwrap_or_else(|_| panic!("the focused attachment publishes its source pair"));
                    attached_sender.send(()).expect("the coordinator observes attachment");
                    go_receiver.recv().expect("the coordinator holds the Heap lock");
                    result_sender
                        .send(attachment.prevalidate_owner_local_operation())
                        .expect("the coordinator receives the admission result");
                    attachment
                        .finish_after_user_destructors()
                        .expect("the no-page attachment drains after the lock is released");
                });
                attached_receiver.recv().expect("the worker attached");
                let held = main_heap
                    .lock_heap()
                    .expect("the coordinator holds the shared main Heap projection lock");
                go_sender.send(()).expect("the worker waits for the held lock");
                let observed = result_receiver.recv_timeout(std::time::Duration::from_secs(10));
                held.unlock().expect("the coordinator releases the shared main Heap lock");
                assert_eq!(
                    observed,
                    Ok(Ok(())),
                    "ordinary owner-local admission completes without the process-global Heap lock"
                );
                worker.join().expect("the focused worker stays on its source thread");
            });
            main.teardown()
                .expect("ticket zero retires after the focused owner-local admission test");
        })
        .join()
        .expect("the focused owner-local admission test completes");
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
                    let ordinary = unsafe {
                        owner
                            .test_theap_pointer()
                            .expect("the attached ordinary Theap remains projected")
                            .as_ref()
                            .expect("the attached ordinary Theap pointer remains non-null")
                    };
                    assert!(ordinary.allows_page_abandon());
                    assert_eq!(ordinary.page_full_retain(), 2);
                    let session = owner
                        .page_session()
                        .expect("the ordinary source Theap opens its page session");
                    assert!(
                        session.selects_selected_main_arena_source_full_abandonment(),
                        "the ordinary source image selects page.c full-page abandonment"
                    );
                    drop(session);
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
    fn later_thread_no_page_statistics_follow_source_attach_and_direct_finish() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the focused main image");
            // This direct test fixture deliberately bypasses process_init's
            // existing initial attachment event. Establish that process-main
            // baseline before the real later attachment below.
            subprocess.record_statistics_thread_attached();
            let main_heap = main
                .shared_main_heap_lease()
                .expect("the focused later worker borrows the static Heap");

            thread::scope(|scope| {
                scope.spawn(move || {
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(_)) => {
                            panic!("the focused later thread is not rejected")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { .. }) => {
                            panic!("the focused later thread does not retain a terminal attachment")
                        }
                    };
                    let attached = subprocess.statistics().source_snapshot();
                    assert_eq!(
                        (attached.threads_total, attached.threads_peak, attached.threads_current),
                        (2, 2, 2),
                        "the initial and later source attachment events share one subprocess statistics image"
                    );

                    attachment
                        .finish_after_user_destructors()
                        .expect("the no-page direct source finish clears the later attachment");
                    let detached = subprocess.statistics().source_snapshot();
                    assert_eq!(
                        (detached.threads_total, detached.threads_peak, detached.threads_current),
                        (2, 2, 1),
                        "the no-page source clear balances only the later attachment before its drain"
                    );
                })
                .join()
                .expect("the focused later worker remains current-thread local");
            });
            main.teardown()
                .expect("the ticket-zero owner retires after the later source drain");
        })
        .join()
        .expect("the focused no-page thread-statistics lifecycle completes");
    }

    #[test]
    fn later_thread_full_queue_fixture_selects_source_option_before_heap_publication() {
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
                        MainHeapThreadAttachment::begin_with_test_metadata_non_abandoning_full_queue(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the full-queue fixture rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the full-queue fixture retained: {error:?}")
                        }
                    };
                    let theap = unsafe {
                        owner
                            .test_theap_pointer()
                            .expect("the attached Theap remains projected")
                            .as_ref()
                            .expect("the attached full-queue Theap pointer remains non-null")
                    };
                    assert!(!theap.allows_page_abandon());
                    assert_eq!(
                        theap.page_full_retain(),
                        -1,
                        "the fixture selects the source non-abandoning option before heap publication"
                    );
                    let session = owner
                        .page_session()
                        .expect("the full-queue source Theap opens its page session");
                    assert!(
                        !session.selects_selected_main_arena_source_full_abandonment(),
                        "the -1 source image leaves full pages in BIN_FULL"
                    );
                    drop(session);
                    owner
                        .finish_after_user_destructors()
                        .expect("the no-page fixture retires normally");
                });
                worker.join().expect("the full-queue worker remains current");
            });

            main.teardown()
                .expect("the main images retire after the fixture");
        })
        .join()
        .expect("the source full-queue option fixture remains thread local");
    }

    /// Pinned `_mi_thread_init_with_heap` allocates the later TLD before its
    /// metadata Theap.  If the latter allocation fails, `src/init.c` frees
    /// that just-created TLD and returns before publishing the default or
    /// fixed main-Heap root.  The failed source ticket remains consumed, but
    /// no live registration or metadata capability may survive it.
    #[test]
    fn later_theap_metadata_failure_releases_its_tld_before_root_publication() {
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
                    assert_ne!(
                        size_of::<Theap>(),
                        size_of::<crate::types::ThreadLocalData>(),
                        "the focused fault selects the second metadata allocation rather than TLD creation"
                    );
                    metadata
                        .get_ref()
                        .test_fail_next_direct_zeroed_size(size_of::<Theap>());

                    assert!(matches!(
                        unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap,
                                metadata,
                                memory_config(),
                            )
                        },
                        Err(MainHeapThreadAttachmentBeginError::Rejected(
                            MainHeapThreadAttachmentError::TheapMetadata(
                                MetaError::AllocationUnavailable
                            )
                        ))
                    ));
                    assert_eq!(
                        subprocess.total_thread_count(),
                        2,
                        "the failed later source ticket remains consumed after its TLD cleanup"
                    );
                    assert_eq!(
                        subprocess.live_thread_count(),
                        1,
                        "only ticket zero remains registered after the failed later Theap allocation"
                    );
                    assert_eq!(
                        storage.test_shared_later_theap_count(),
                        0,
                        "the failed Theap never reaches the source shared-main list"
                    );
                    assert_eq!(
                        metadata.test_allocation_audit().live_capability_count,
                        0,
                        "the failed attachment releases its exact TLD metadata capability"
                    );
                    assert!(
                        roots_are_pristine_for_later_main_attachment(),
                        "the failed Theap allocation leaves every worker root at its source empty image"
                    );

                    let mut recovered = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the later source retry rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the later source retry retained: {error:?}")
                        }
                    };
                    assert_eq!(
                        recovered
                            .current_tld_mut()
                            .expect("the recovered TLD is current")
                            .thread_sequence()
                            .get(),
                        2,
                        "the retry receives the source sequence after the failed TLD/Theap pair"
                    );
                    recovered
                        .finish_after_user_destructors()
                        .expect("the recovered no-page attachment tears down normally");
                    assert!(
                        roots_are_pristine_for_later_main_attachment(),
                        "the successful subsequent attachment restores the same empty worker roots"
                    );
                });
                worker.join().expect("the failed-then-recovered worker completes");
            });

            assert_eq!(subprocess.total_thread_count(), 3);
            assert_eq!(subprocess.live_thread_count(), 1);
            main.teardown()
                .expect("ticket zero retires after the failed and recovered later paths");
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join()
        .expect("the later-Theap allocation failure lifecycle completes");
    }

    /// Emits the failure post-state for the second metadata request in the
    /// ordinary later-main attachment. Pinned C injects the selected
    /// `_mi_theap_alloc` failure at the direct caller and verifies its own
    /// TLD-cleanup order. Rust observes only the retained source facts after
    /// the typed allocator rejects the exact Theap-size request; it does not
    /// claim C event ordering or infer an allocation attempt from a ticket.
    #[test]
    fn emit_m2_later_main_theap_metadata_failure_c_rust_trace() {
        macro_rules! record {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }

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
                    let pre_total_thread_count_one = subprocess.total_thread_count() == 1;
                    let pre_live_thread_count_one = subprocess.live_thread_count() == 1;
                    assert!(pre_total_thread_count_one);
                    assert!(pre_live_thread_count_one);
                    assert!(roots_are_pristine_for_later_main_attachment());
                    assert_ne!(
                        core::mem::size_of::<Theap>(),
                        core::mem::size_of::<crate::types::ThreadLocalData>(),
                        "the selected fault must follow the successful later TLD allocation"
                    );

                    metadata
                        .get_ref()
                        .test_fail_next_direct_zeroed_size(core::mem::size_of::<Theap>());
                    let rejected = unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    };
                    let result_unavailable = matches!(
                        rejected,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(
                            MainHeapThreadAttachmentError::TheapMetadata(
                                MetaError::AllocationUnavailable
                            )
                        ))
                    );
                    let total_thread_count_two = subprocess.total_thread_count() == 2;
                    let live_thread_count_one = subprocess.live_thread_count() == 1;
                    let no_shared_theap_list_member = storage.test_shared_later_theap_count() == 0;
                    let roots_remain_empty = roots_are_pristine_for_later_main_attachment();
                    let tld_metadata_released_before_root_publication =
                        metadata.test_allocation_audit().live_capability_count == 0;

                    assert!(result_unavailable);
                    assert!(total_thread_count_two);
                    assert!(live_thread_count_one);
                    assert!(no_shared_theap_list_member);
                    assert!(roots_remain_empty);
                    assert!(tld_metadata_released_before_root_publication);

                    std::println!(
                        "CRABC_MI_M2_LATER_MAIN_THEAP_METADATA_FAILURE_TRACE_BEGIN"
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.pre.total_thread_count_one",
                        pre_total_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.pre.live_thread_count_one",
                        pre_live_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.post.result_unavailable",
                        result_unavailable
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.post.total_thread_count_two",
                        total_thread_count_two
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.post.live_thread_count_one",
                        live_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.post.no_shared_theap_list_member",
                        no_shared_theap_list_member
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.post.roots_remain_empty",
                        roots_remain_empty
                    );
                    record!(
                        "m2.initialization.later_main_theap_failure.post.tld_metadata_released_before_root_publication",
                        tld_metadata_released_before_root_publication
                    );
                    std::println!(
                        "CRABC_MI_M2_LATER_MAIN_THEAP_METADATA_FAILURE_TRACE_END"
                    );
                });
                worker
                    .join()
                    .expect("the ordinary later Theap failure trace completes");
            });

            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 1);
            main.teardown()
                .expect("the ticket-zero main owner retires after the failed later attachment");
        })
        .join()
        .expect("the ordinary later Theap failure trace finishes");
    }

    /// Emits independently observed state for the complete ordinary
    /// `_mi_thread_init_with_heap(mi_heap_main())` later-thread transaction.
    ///
    /// The paired pinned-C fixture invokes that exact source caller on a
    /// later pthread and checks its own call order through TLD allocation,
    /// Theap allocation/initialization, default-root publication, and the
    /// fixed main-Heap TLS store. This typed test records only the resulting
    /// metadata, list, root, counter, and explicit-finish state; it has no
    /// C-call hooks and must not present those facts as order equivalence.
    /// Its finish is an explicit owner call after the attached post-state was
    /// observed. It does not claim automatic pthread destruction, process
    /// shutdown, fork, or recursion behavior.
    #[test]
    fn emit_m2_later_main_theap_publication_success_c_rust_trace() {
        macro_rules! record {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }

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
                    let pre_total_thread_count_one = subprocess.total_thread_count() == 1;
                    let pre_live_thread_count_one = subprocess.live_thread_count() == 1;
                    assert!(pre_total_thread_count_one);
                    assert!(pre_live_thread_count_one);
                    assert!(roots_are_pristine_for_later_main_attachment());

                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the ordinary later attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the ordinary later attachment retained: {error:?}")
                        }
                    };
                    let theap_pointer = owner
                        .theap_pointer()
                        .expect("the metadata Theap remains owned while attached");
                    let result_available = true;
                    let tld_metadata_malloc = {
                        let tld = owner
                            .current_tld_mut()
                            .expect("the later metadata TLD remains current");
                        let memory = tld.memory_id();
                        memory.kind() == crate::types::MemoryKind::Malloc
                            && memory.malloc_memory().is_some_and(|allocation| {
                                allocation.base
                                    == (tld as *const crate::types::ThreadLocalData)
                                        .cast_mut()
                                        .cast()
                                    && allocation.size
                                        == core::mem::size_of::<crate::types::ThreadLocalData>()
                            })
                    };
                    let (theap_metadata_malloc, theap_initialized) = {
                        let allocation = owner
                            .theap
                            .as_ref()
                            .expect("the attached owner retains its metadata capability");
                        let memory = allocation.memory_id();
                        (
                            memory.kind() == crate::types::MemoryKind::Malloc
                                && memory.malloc_memory().is_some_and(|allocation_memory| {
                                    allocation_memory.base == allocation.pointer().as_ptr().cast()
                                        && allocation_memory.size == core::mem::size_of::<Theap>()
                                }),
                            allocation
                                .dynamic_theap()
                                .is_some_and(Theap::is_initialized),
                        )
                    };
                    let tld_list_contains_theap = unsafe {
                        owner
                            .current_tld_mut()
                            .expect("the attached TLD remains current")
                            .has_exact_theap_member(theap_pointer)
                    };
                    let heap_list_contains_theap = {
                        let mut heap = main_heap
                            .lock_heap()
                            .expect("the source main heap remains live");
                        let member = heap
                            .heap_mut()
                            .has_shared_theap_member_blocking(theap_pointer)
                            .expect("the source shared heap list stays valid");
                        heap.unlock().expect("shared heap inspection unlocks");
                        member
                    };
                    let default_root_matches_theap =
                        core::ptr::eq(default_theap().as_ptr(), theap_pointer);
                    let fast_root_matches_theap = fast_slot_peek()
                        .is_some_and(|fast| fast.as_ptr().cast::<Theap>() == theap_pointer);
                    let total_thread_count_two = subprocess.total_thread_count() == 2;
                    let live_thread_count_two = subprocess.live_thread_count() == 2;
                    let attached_metadata_capabilities_two =
                        metadata.test_allocation_audit().live_capability_count == 2;

                    assert!(result_available);
                    assert!(tld_metadata_malloc);
                    assert!(theap_metadata_malloc);
                    assert!(theap_initialized);
                    assert!(tld_list_contains_theap);
                    assert!(heap_list_contains_theap);
                    assert!(default_root_matches_theap);
                    assert!(fast_root_matches_theap);
                    assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
                    assert!(total_thread_count_two);
                    assert!(live_thread_count_two);
                    assert!(attached_metadata_capabilities_two);

                    owner
                        .finish_after_user_destructors()
                        .expect("the explicit ordinary no-page finish releases the later owner");
                    let finish_default_root_empty =
                        core::ptr::eq(default_theap().as_ptr(), empty_default_theap_ptr());
                    let finish_fast_root_empty = fast_slot_peek().is_none();
                    let finish_live_thread_count_one = subprocess.live_thread_count() == 1;
                    let finish_heap_list_released = storage.test_shared_later_theap_count() == 0;
                    let finish_metadata_capabilities_released =
                        metadata.test_allocation_audit().live_capability_count == 0;

                    assert!(finish_default_root_empty);
                    assert!(finish_fast_root_empty);
                    assert!(finish_live_thread_count_one);
                    assert!(finish_heap_list_released);
                    assert!(finish_metadata_capabilities_released);

                    std::println!(
                        "CRABC_MI_M2_LATER_MAIN_THEAP_PUBLICATION_SUCCESS_TRACE_BEGIN"
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.pre.total_thread_count_one",
                        pre_total_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.pre.live_thread_count_one",
                        pre_live_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.result_available",
                        result_available
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.tld_metadata_malloc",
                        tld_metadata_malloc
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.theap_metadata_malloc",
                        theap_metadata_malloc
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.theap_initialized",
                        theap_initialized
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.tld_list_contains_theap",
                        tld_list_contains_theap
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.heap_list_contains_theap",
                        heap_list_contains_theap
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.default_root_matches_theap",
                        default_root_matches_theap
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.fast_root_matches_theap",
                        fast_root_matches_theap
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.total_thread_count_two",
                        total_thread_count_two
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.post.live_thread_count_two",
                        live_thread_count_two
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.finish.default_root_empty",
                        finish_default_root_empty
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.finish.fast_root_empty",
                        finish_fast_root_empty
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.finish.live_thread_count_one",
                        finish_live_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_main_theap_success.finish.heap_list_released",
                        finish_heap_list_released
                    );
                    std::println!(
                        "CRABC_MI_M2_LATER_MAIN_THEAP_PUBLICATION_SUCCESS_TRACE_END"
                    );
                });
                worker
                    .join()
                    .expect("the ordinary later attachment trace completes");
            });

            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 1);
            main.teardown()
                .expect("the ticket-zero main owner retires after the explicit later finish");
        })
        .join()
        .expect("the ordinary later attachment trace finishes");
    }

    /// Pinned `_mi_thread_init_with_heap` first creates its later TLD through
    /// `mi_tld_create`.  A failed metadata allocation at that first step has
    /// no TLD capability to clean up, so it must return before either Theap
    /// allocation or any shared-main root/list publication.  As in the C
    /// branch, the old `thread_total_count` value remains consumed while the
    /// live count stays at the ticket-zero owner.
    #[test]
    fn later_tld_metadata_failure_precedes_theap_allocation_and_root_publication() {
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
                    assert_ne!(
                        size_of::<crate::types::ThreadLocalData>(),
                        size_of::<Theap>(),
                        "the focused fault selects the first metadata allocation rather than Theap creation"
                    );
                    metadata
                        .get_ref()
                        .test_fail_next_direct_zeroed_size(size_of::<crate::types::ThreadLocalData>());

                    assert!(matches!(
                        unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap,
                                metadata,
                                memory_config(),
                            )
                        },
                        Err(MainHeapThreadAttachmentBeginError::Rejected(
                            MainHeapThreadAttachmentError::ThreadLocalData(
                                ThreadLocalDataError::Metadata(MetaError::AllocationUnavailable)
                            )
                        ))
                    ));
                    assert_eq!(
                        subprocess.total_thread_count(),
                        2,
                        "the rejected later-TLD source ticket remains consumed"
                    );
                    assert_eq!(
                        subprocess.live_thread_count(),
                        1,
                        "the failed TLD never becomes a live registration"
                    );
                    assert_eq!(
                        storage.test_shared_later_theap_count(),
                        0,
                        "the later Theap cannot exist when TLD construction fails first"
                    );
                    assert_eq!(
                        metadata.test_allocation_audit().live_capability_count,
                        0,
                        "a rejected TLD request leaves no metadata capability to release"
                    );
                    assert!(
                        roots_are_pristine_for_later_main_attachment(),
                        "the rejected TLD leaves the default, fast, cached, and dynamic roots untouched"
                    );

                    let mut recovered = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the later TLD retry rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the later TLD retry retained: {error:?}")
                        }
                    };
                    assert_eq!(
                        recovered
                            .current_tld_mut()
                            .expect("the recovered TLD is current")
                            .thread_sequence()
                            .get(),
                        2,
                        "the recovery receives the source sequence after the rejected TLD"
                    );
                    recovered
                        .finish_after_user_destructors()
                        .expect("the recovered no-page attachment tears down normally");
                    assert!(
                        roots_are_pristine_for_later_main_attachment(),
                        "the recovered attachment restores the empty worker roots"
                    );
                });
                worker.join().expect("the rejected-then-recovered worker completes");
            });

            assert_eq!(subprocess.total_thread_count(), 3);
            assert_eq!(subprocess.live_thread_count(), 1);
            main.teardown()
                .expect("ticket zero retires after the rejected and recovered later paths");
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join()
        .expect("the later-TLD allocation failure lifecycle completes");
    }

    /// Emits the common address-independent relations for the pinned
    /// `mi_tld_create` generic/later metadata-allocation failure arm.
    ///
    /// The paired C fixture selects ticket one on the source main subprocess,
    /// intercepts exactly its `_mi_meta_zalloc` call, and records the source
    /// ENOMEM diagnostic before result visibility. Rust's fixed exact-size
    /// seam is narrower than a production fault policy: it proves that the
    /// typed owner consumes the same source ticket, does not register a TLD,
    /// and leaves no Theap or metadata capability to publish. Successful
    /// generic/later construction and all metadata publication receivers stay
    /// outside this trace.
    #[test]
    fn emit_m2_later_tld_metadata_failure_c_rust_trace() {
        macro_rules! record {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }

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
                    assert_ne!(
                        size_of::<crate::types::ThreadLocalData>(),
                        size_of::<Theap>(),
                        "the fault must select the preceding TLD metadata request"
                    );
                    let pre_main_subprocess_selected =
                        core::ptr::eq(main_heap.subprocess(), subprocess);
                    let pre_metadata_owner_ready = metadata
                        .prepare_for_main_subprocess(memory_config(), subprocess)
                        .is_ok();
                    let pre_total_thread_count_one = subprocess.total_thread_count() == 1;
                    let pre_live_thread_count_one = subprocess.live_thread_count() == 1;
                    assert!(pre_main_subprocess_selected);
                    assert!(pre_metadata_owner_ready);
                    assert!(pre_total_thread_count_one);
                    assert!(pre_live_thread_count_one);

                    metadata
                        .get_ref()
                        .test_fail_next_direct_zeroed_size(size_of::<crate::types::ThreadLocalData>());
                    let rejected = unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    };
                    let result_unavailable = matches!(
                        rejected,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(
                            MainHeapThreadAttachmentError::ThreadLocalData(
                                ThreadLocalDataError::Metadata(MetaError::AllocationUnavailable)
                            )
                        ))
                    );
                    let post_total_thread_count_two = subprocess.total_thread_count() == 2;
                    let post_total_thread_count_incremented = post_total_thread_count_two;
                    let post_live_thread_count_one = subprocess.live_thread_count() == 1;
                    let post_live_thread_count_unchanged = post_live_thread_count_one;
                    let post_no_normal_tld_registration = post_live_thread_count_unchanged;
                    let allocation_failure_reported = result_unavailable;
                    assert!(result_unavailable);
                    assert!(post_total_thread_count_two);
                    assert!(post_live_thread_count_one);
                    assert_eq!(
                        storage.test_shared_later_theap_count(),
                        0,
                        "the rejected source TLD has not begun Theap publication"
                    );
                    assert_eq!(
                        metadata.test_allocation_audit().live_capability_count,
                        0,
                        "the failed source allocation has no capability to retain"
                    );
                    assert!(roots_are_pristine_for_later_main_attachment());

                    // This successful next request consumes the one exact
                    // test seam. Its sequence proves that the failed source
                    // ticket was not rolled back or registered; it is test
                    // cleanup only and does not enter the printed poststate.
                    let mut recovered = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the later-TLD recovery rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the later-TLD recovery retained: {error:?}")
                        }
                    };
                    let recovery_uses_second_ticket = recovered
                        .current_tld_mut()
                        .expect("the recovered TLD is current")
                        .thread_sequence()
                        .get()
                        == 2;
                    assert!(recovery_uses_second_ticket);
                    recovered
                        .finish_after_user_destructors()
                        .expect("the recovery tears down normally");

                    // The C fixture records its own source-call order. This
                    // Rust seam observes the resulting typed state only: it
                    // has no hooks at the ticket, metadata, and return events,
                    // so it must not present terminal booleans as event-order
                    // parity.

                    std::println!("CRABC_MI_M2_LATER_TLD_METADATA_FAILURE_TRACE_BEGIN");
                    record!(
                        "m2.initialization.later_tld_metadata_failure.pre.main_subprocess_selected",
                        pre_main_subprocess_selected
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.pre.metadata_owner_ready",
                        pre_metadata_owner_ready
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.pre.total_thread_count_one",
                        pre_total_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.pre.live_thread_count_one",
                        pre_live_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.result_unavailable",
                        result_unavailable
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.metadata_request_is_tld",
                        true
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.total_thread_count_two",
                        post_total_thread_count_two
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.total_thread_count_incremented",
                        post_total_thread_count_incremented
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.live_thread_count_one",
                        post_live_thread_count_one
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.live_thread_count_unchanged",
                        post_live_thread_count_unchanged
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.no_normal_tld_registration",
                        post_no_normal_tld_registration
                    );
                    record!(
                        "m2.initialization.later_tld_metadata_failure.post.allocation_failure_reported",
                        allocation_failure_reported
                    );
                    std::println!("CRABC_MI_M2_LATER_TLD_METADATA_FAILURE_TRACE_END");
                });
                worker.join().expect("the later-TLD failure worker completes");
            });

            assert_eq!(subprocess.total_thread_count(), 3);
            assert_eq!(subprocess.live_thread_count(), 1);
            main.teardown()
                .expect("ticket zero retires after the failure trace");
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join()
        .expect("the later-TLD metadata failure trace completes");
    }

    /// Emits the normalized source-owner transitions for the native C/Rust
    /// initialization, reentry, teardown, and recovery witness.
    ///
    /// Pinned `src/init.c:_mi_thread_init_with_heap` returns the existing
    /// default Theap when it is already initialized.  This typed Rust layer
    /// cannot return a second mutable owner for the same TLD/Theap, so a
    /// direct second constructor instead refuses before any ticket, metadata,
    /// list, or root mutation.  Both outcomes establish the shared source
    /// invariant recorded below: reentry creates no second current owner.
    /// The runtime's `AlreadyAttached` result owns the public worker-wrapper
    /// form of that distinction; this test stays at the source attachment
    /// boundary and does not claim its callback or runtime integration.
    #[test]
    fn emit_x86_64_init_recursion_teardown_c_rust_trace() {
        thread::spawn(|| {
            let (storage, subprocess) = fixture();
            let metadata = MetaAllocator::test_static_owner();
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the source-main owner remains live while its worker recovers");
            let main_heap = main
                .shared_main_heap_lease()
                .expect("the source-main owner lends one immutable Heap identity");

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut first = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the first source worker attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the first source worker attachment retained: {error:?}")
                        }
                    };
                    let first_theap = first
                        .theap_pointer()
                        .expect("the first source worker publishes its default Theap");
                    let first_default_initialized =
                        core::ptr::eq(default_theap().as_ptr(), first_theap);

                    let reentrant_constructor_refused = matches!(
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
                    ) && core::ptr::eq(default_theap().as_ptr(), first_theap)
                        && fast_slot_peek().map(NonNull::as_ptr)
                            == Some(first_theap.cast::<()>());

                    first
                        .finish_after_user_destructors()
                        .expect("the first source worker clears its roots before TLD release");
                    let first_teardown_clears_default = roots_are_pristine_for_later_main_attachment();
                    let repeated_teardown_keeps_default_empty = first
                        .finish_after_user_destructors()
                        == Err(MainHeapThreadAttachmentError::TornDown)
                        && roots_are_pristine_for_later_main_attachment();

                    let mut recovered = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            memory_config(),
                        )
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("the recovered source worker attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("the recovered source worker attachment retained: {error:?}")
                        }
                    };
                    let recovery_default_initialized = recovered
                        .theap_pointer()
                        .map(|theap| core::ptr::eq(default_theap().as_ptr(), theap))
                        .unwrap_or(false);
                    recovered
                        .finish_after_user_destructors()
                        .expect("the recovered source worker clears its roots before final release");
                    let final_teardown_clears_default = roots_are_pristine_for_later_main_attachment();

                    assert!(first_default_initialized);
                    assert!(reentrant_constructor_refused);
                    assert!(first_teardown_clears_default);
                    assert!(repeated_teardown_keeps_default_empty);
                    assert!(recovery_default_initialized);
                    assert!(final_teardown_clears_default);

                    std::println!("CRABC_MI_INIT_RECURSION_TRACE_BEGIN");
                    std::println!(
                        "trace.init_recursion.first_default_initialized={}",
                        usize::from(first_default_initialized)
                    );
                    std::println!(
                        "trace.init_recursion.reentrant_entry_preserves_one_owner={}",
                        usize::from(reentrant_constructor_refused)
                    );
                    std::println!(
                        "trace.init_recursion.first_teardown_clears_default={}",
                        usize::from(first_teardown_clears_default)
                    );
                    std::println!(
                        "trace.init_recursion.repeated_teardown_keeps_default_empty={}",
                        usize::from(repeated_teardown_keeps_default_empty)
                    );
                    std::println!(
                        "trace.init_recursion.recovery_default_initialized={}",
                        usize::from(recovery_default_initialized)
                    );
                    std::println!(
                        "trace.init_recursion.final_teardown_clears_default={}",
                        usize::from(final_teardown_clears_default)
                    );
                    std::println!("trace.init_recursion.valid=1");
                    std::println!("CRABC_MI_INIT_RECURSION_TRACE_END");
                });
                worker
                    .join()
                    .expect("the selected source worker lifecycle completes");
            });

            main.teardown()
                .expect("the source-main owner retires after both worker attachments finish");
        })
        .join()
        .expect("the C/Rust source lifecycle trace completes");
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

    /// The later-thread constructor may consume a generic TLD ticket only
    /// from the complete source empty-root image.  A stale root can name a
    /// different lifecycle, so every root variant must refuse before it can
    /// prepare metadata, link a Theap, increment either thread count, or
    /// overwrite the caller's diagnostic root.  This is the Rust ownership
    /// boundary corresponding to `src/init.c`'s warning that TLS access can
    /// recursively allocate during thread initialization.
    #[test]
    fn later_thread_rejects_every_nonpristine_source_root_before_ticket_or_metadata_mutation() {
        #[derive(Clone, Copy)]
        enum ForeignRoot {
            DynamicBackingAbsent,
            DynamicBackingNonempty,
            FastSlot,
            DefaultTheap,
            CachedTheap,
        }

        for root in [
            ForeignRoot::DynamicBackingAbsent,
            ForeignRoot::DynamicBackingNonempty,
            ForeignRoot::FastSlot,
            ForeignRoot::DefaultTheap,
            ForeignRoot::CachedTheap,
        ] {
            thread::spawn(move || {
                let (storage, subprocess) = fixture();
                let metadata = MetaAllocator::test_static_owner();
                let mut main = unsafe {
                    MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
                }
                .expect("ticket zero attaches the process main images");
                let main_heap = main.shared_main_heap_lease().unwrap();

                thread::scope(|scope| {
                    let worker = scope.spawn(move || {
                        let mut foreign_dynamic = DynamicThreadLocalBacking::test_image(1);
                        let mut foreign_fast = 0xfeed_faceusize;
                        let mut foreign_default = Theap::empty();
                        let mut foreign_cached = Theap::empty();
                        match root {
                            ForeignRoot::DynamicBackingAbsent => clear_dynamic_backing(),
                            ForeignRoot::DynamicBackingNonempty => {
                                install_dynamic_backing(NonNull::from(&mut foreign_dynamic))
                            }
                            ForeignRoot::FastSlot => {
                                set_fast_slot(Some(NonNull::from(&mut foreign_fast).cast()))
                            }
                            ForeignRoot::DefaultTheap => {
                                set_default_theap(NonNull::from(&mut foreign_default))
                            }
                            ForeignRoot::CachedTheap => {
                                set_cached_theap(NonNull::from(&mut foreign_cached))
                            }
                        }

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
                        assert_eq!(storage.test_shared_later_theap_count(), 0);
                        assert!(
                            !metadata.test_is_bound_for(memory_config(), subprocess),
                            "root rejection must precede detached-metadata preparation"
                        );

                        match root {
                            ForeignRoot::DynamicBackingAbsent => {
                                assert!(dynamic_backing_peek().is_none());
                            }
                            ForeignRoot::DynamicBackingNonempty => {
                                assert_eq!(
                                    dynamic_backing_peek().map(NonNull::as_ptr),
                                    Some(NonNull::from(&mut foreign_dynamic).as_ptr()),
                                );
                                // The one-slot image remains live on this
                                // stack; the rejected constructor observed
                                // its root identity without dereferencing it.
                                assert_eq!(
                                    foreign_dynamic.count(),
                                    1,
                                );
                                clear_dynamic_backing();
                            }
                            ForeignRoot::FastSlot => {
                                assert_eq!(
                                    fast_slot_peek().map(NonNull::as_ptr),
                                    Some(NonNull::from(&mut foreign_fast).as_ptr().cast()),
                                );
                                set_fast_slot(None);
                            }
                            ForeignRoot::DefaultTheap => {
                                assert_eq!(
                                    default_theap().as_ptr(),
                                    NonNull::from(&mut foreign_default).as_ptr(),
                                );
                                set_default_theap(empty_default_theap());
                            }
                            ForeignRoot::CachedTheap => {
                                assert_eq!(
                                    cached_theap().as_ptr(),
                                    NonNull::from(&mut foreign_cached).as_ptr(),
                                );
                                set_cached_theap(empty_default_theap());
                            }
                        }
                    });
                    worker.join().expect("foreign-root worker completes");
                });

                main.teardown().expect("foreign roots changed no main state");
            })
            .join()
            .expect("each root-rejection lifecycle completes");
        }
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
