// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:99-173`
// (`_mi_theap_empty`, the detached TLD relationship, and empty-theap
// predicate), `src/init.c:184-205` (the kind-only static provenance and
// detached-metadata special case in `mi_heap_main_init_once`),
// `src/init.c:305-360` (main default-theap wiring order),
// `src/theap.c:228-306` (`_mi_theap_init`'s initialized-predicate publication
// order and option image), `src/options.c:161-162` (frozen normal defaults),
// and `include/mimalloc/internal.h:626-664` (theap initialized and
// thread-identity predicates).
//
// This is deliberately only an allocation-free, exclusive single-thread
// bootstrap. It has no compiler TLS slot, pthread key, first-class heap,
// general random reinitialization/split, remote-free, teardown, or
// concurrent-init lifecycle. Its detached metadata image records one bounded
// first-head random/cookie initialization and main-subprocess identity only;
// this remains distinct from a live TLD/theap attachment or subprocess
// lifecycle.

use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::ptr::NonNull;

use crate::arena::ArenaView;
use crate::os::MemoryConfig;
use crate::os_page::OsAlignedPageOwner;
use crate::single_thread::{
    StaticMainMappedRegularClaimSource,
    StaticMainMappedRegularClaimSourceHookOutcome,
};
use crate::types::{
    Heap, LiveThreadId, MemoryId, Page, PageQueue, Theap, TheapOwner,
    ThreadLocalData,
};
use crate::subproc::MainSubprocess;

// `Theap` contains raw pointers and must not be shared for mutation. This
// wrapper exposes only `&Theap` for the immutable source `_mi_theap_empty`
// prototype, matching `src/init.c`'s `const mi_theap_t` contract.
#[repr(transparent)]
struct EmptyDefaultTheap(Theap);

// SAFETY: no API exposes a mutable reference or mutable raw pointer derived
// from this wrapper. The atomics have their source initializer values and are
// never modified; all ordinary fields are immutable bootstrap metadata.
unsafe impl Sync for EmptyDefaultTheap {}

static EMPTY_DEFAULT_THEAP: EmptyDefaultTheap = EmptyDefaultTheap(Theap::empty());

/// Returns the immutable source equivalent of `_mi_theap_empty`.
///
/// The caller may inspect its direct-page sentinel table and queues only. It
/// is not an initialized allocator theap and must never be used as a live
/// page owner.
#[inline]
pub(crate) fn empty_default_theap() -> &'static Theap {
    &EMPTY_DEFAULT_THEAP.0
}

/// Returns the source empty-theap address for compiler-TLS initialization.
///
/// The pointer is mutable only because the pinned C TLS roots have mutable
/// pointer type. The static image itself remains immutable and no caller may
/// use this address to mutate it.
#[inline]
pub(crate) const fn empty_default_theap_ptr() -> *mut Theap {
    core::ptr::addr_of!(EMPTY_DEFAULT_THEAP.0).cast_mut()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapError {
    /// This caller-owned image has already published its exclusive theap.
    AlreadyInitialized,
    /// The supplied state violated the source thread-identity predicate.
    InvalidThreadState,
}

/// Caller-owned backing storage for one exclusive heap/theap bootstrap.
///
/// It may be constructed allocation-free and moved while inactive. Before
/// an activation method can wire `Theap` and `Page` raw pointers, the caller
/// must place it in address-stable storage and pass `Pin<&mut Self>`. The
/// active session exposes only controlled queue/direct-cache/page operations;
/// it never exposes a mutable whole `Theap` or `Heap` that could invalidate
/// those stored raw pointers by replacement.
///
/// This type is private allocator state, is intentionally `!Unpin`, and makes
/// no Send, Sync, TLS, or concurrency claim. One exclusive caller supplies a
/// source-valid [`LiveThreadId`] for an ordinary session, or a process owner
/// supplies the source detached identity for metadata allocation.
pub(crate) struct ExclusiveTheapBootstrap {
    heap: Heap,
    tld: ThreadLocalData,
    theap: Theap,
    /// The one owner whose source image has been initialized in this pinned
    /// storage. A detached metadata image may be bound during process startup
    /// before it has an arena/PageMap backing or an allocator session.
    bound_owner: Option<TheapOwner>,
    /// A source image may lend exactly one mutable allocator session. Binding
    /// the detached static image is deliberately separate from issuing that
    /// session so `mi_heap_main_init_once` can precede first metadata demand.
    session_issued: bool,
    canonical_heap: Option<crate::main_theap::MainStaticMetadataHeapLease>,
    // Raw-pointer marker prevents accidental Send/Sync claims for this
    // exclusive mutable state; `PhantomPinned` makes pointer wiring durable.
    _not_send_or_sync: PhantomData<*mut ()>,
    _pin: PhantomPinned,
}

impl ExclusiveTheapBootstrap {
    /// Creates an inert, allocation-free bootstrap image.
    ///
    /// It has the source empty-theap contents but still points at the static
    /// detached TLD and has no published heap. Pin it before activating one
    /// live or detached owner.
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            heap: Heap::bootstrap_empty(),
            tld: ThreadLocalData::detached(),
            theap: Theap::empty(),
            bound_owner: None,
            session_issued: false,
            canonical_heap: None,
            _not_send_or_sync: PhantomData,
            _pin: PhantomPinned,
        }
    }

    /// Checks that a detached bootstrap image names one selected bounded
    /// process-main subprocess identity.
    pub(crate) fn is_detached_for_main_subprocess(
        &self,
        subprocess: &MainSubprocess,
    ) -> bool {
        (self.canonical_heap.is_some_and(|heap| core::ptr::eq(heap.subprocess(), subprocess))
            || self.heap.is_bound_to_main_subprocess(subprocess))
            && self.tld.is_attached_to_main_subprocess(subprocess)
            && self.tld.numa_node() == -1
            && self.theap.is_bound_to_main_subprocess(subprocess)
    }

    /// Returns the exact pinned detached metadata-Theap identity after its
    /// bounded detached-metadata image is initialized.
    ///
    /// This returns an identity only: it cannot start a session, expose the
    /// Theap, or mutate it. `MetaAllocator` uses it to make the source
    /// `subproc->theap_meta = &mi_process_theap_meta` assignment one-way after
    /// `mi_theap_init` has completed the represented detached fields. It does
    /// not claim the actual source main-Heap linkage or metadata lock.
    #[inline]
    pub(crate) fn detached_metadata_theap_identity(
        self: Pin<&Self>,
        subprocess: &'static MainSubprocess,
    ) -> Option<NonNull<Theap>> {
        let state = self.get_ref();
        (state.bound_owner == Some(TheapOwner::Detached)
            && state.is_detached_for_main_subprocess(subprocess))
            .then(|| NonNull::from(&state.theap))
    }

    /// Attaches and publishes a live-thread theap after this image is pinned.
    ///
    /// This is the bounded source order from `_mi_thread_init_with_heap` and
    /// `_mi_theap_init`: record the caller identity in the TLD, complete the
    /// ordinary theap fields, then publish the heap pointer last. The returned
    /// session is the sole local owner; it neither installs nor reads TLS.
    pub(crate) fn activate_live(
        mut self: Pin<&mut Self>,
        thread_id: LiveThreadId,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        self.as_mut().bind_owner(TheapOwner::Live(thread_id), None, false)?;
        self.begin_bound_session(TheapOwner::Live(thread_id))
    }

    /// Attaches the live Theap with the source non-abandoning option image.
    ///
    /// `src/theap.c:229-231` selects `allow_page_abandon == false` only with
    /// `mi_option_page_full_retain == -1`, so every exhausted page enters
    /// `BIN_FULL`. [`Self::activate_live`] keeps the historical retain-two
    /// fixture image that existing focused tests depend on; this is the
    /// source-reachable local profile compared with pinned C.
    #[cfg(test)]
    pub(crate) fn activate_live_non_abandoning(
        mut self: Pin<&mut Self>,
        thread_id: LiveThreadId,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        self.as_mut().bind_owner(TheapOwner::Live(thread_id), None, true)?;
        self.begin_bound_session(TheapOwner::Live(thread_id))
    }

    /// Activates the source detached metadata-theap form.
    ///
    /// The resulting session is not thread-local: a process owner must hold
    /// its private lock around every operation. It deliberately has no
    /// thread identity, TLS access, remote-free path, or abandonment path.
    pub(crate) fn activate_detached(
        self: Pin<&mut Self>,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        self.activate_detached_for_main_subprocess(MainSubprocess::global())
    }

    /// Activates a detached metadata-theap form tied to one process-main
    /// identity. `MetaAllocator` chooses this identity before it publishes
    /// detached allocator state, so its heap, TLD, and theap agree on the
    /// same bounded source `subproc` pointer.
    pub(crate) fn activate_detached_for_main_subprocess(
        mut self: Pin<&mut Self>,
        subprocess: &'static MainSubprocess,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        self.as_mut().bind_detached_for_main_subprocess(subprocess)?;
        self.begin_bound_detached_session(subprocess)
    }

    /// Initializes the process-static detached metadata image without issuing
    /// an allocator session or allocating backing storage.
    ///
    /// This is the bounded source `mi_process_theap_meta` portion of
    /// `mi_heap_main_init_once`: the represented Heap/TLD/Theap fields name
    /// the selected main subprocess. `MetaAllocator` later publishes this
    /// fully formed image identity; the first `_mi_meta_zalloc` remains
    /// responsible for acquiring a page.
    pub(crate) fn bind_detached_for_main_subprocess(
        self: Pin<&mut Self>,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), BootstrapError> {
        self.bind_owner(TheapOwner::Detached, Some(subprocess), false)
    }

    /// Lends the one mutable session for an already bound detached metadata
    /// image.
    ///
    /// The caller must name the same source main subprocess used at binding.
    /// This is intentionally unavailable for an unbound image and cannot
    /// reissue a session after an earlier caller retained it.
    pub(crate) fn begin_bound_detached_session(
        mut self: Pin<&mut Self>,
        subprocess: &'static MainSubprocess,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        let state = self.as_ref().get_ref();
        if state.bound_owner != Some(TheapOwner::Detached)
            || !state.is_detached_for_main_subprocess(subprocess)
        {
            return Err(BootstrapError::InvalidThreadState);
        }
        self.begin_bound_session(TheapOwner::Detached)
    }

    /// Initializes the source metadata Theap on the canonical Heap rather
    /// than the legacy isolated fixture Heap. This is startup-only, before
    /// any page session or other Theap observer may exist.
    pub(crate) fn bind_detached_for_main_heap(
        self: Pin<&mut Self>, heap: crate::main_theap::MainStaticMetadataHeapLease,
    ) -> Result<(), BootstrapError> {
        let state = unsafe { self.get_unchecked_mut() };
        if state.bound_owner.is_some() { return Err(BootstrapError::AlreadyInitialized); }
        if !state.tld.prepare_detached_static_memid()
            || !state.tld.initialize_detached_after_static_memid(heap.subprocess())
            || !state.theap.set_detached_main_metadata_static_memid()
        {
            return Err(BootstrapError::InvalidThreadState);
        }
        heap.with_heap(|canonical| state.theap.initialize_metadata_static(canonical, &mut state.tld))
            .map_err(|_| BootstrapError::InvalidThreadState)?
            .map_err(|_| BootstrapError::InvalidThreadState)?;
        state.canonical_heap = Some(heap);
        state.bound_owner = Some(TheapOwner::Detached);
        Ok(())
    }

    /// # Safety
    /// The pointer is this process's pinned initialized canonical metadata
    /// bootstrap. The metadata entry grants unique session issuance and
    /// serializes every subsequent session operation. No whole-bootstrap
    /// reference or mutable Theap borrow may survive canonical publication.
    pub(crate) unsafe fn begin_canonical_metadata_session_at(
        pointer: NonNull<Self>,
    ) -> Result<crate::types::metadata_session::CanonicalMetadataTheapSession, BootstrapError> {
        let state = pointer.as_ptr();
        let Some(heap) = (unsafe { (*state).canonical_heap }) else {
            return Err(BootstrapError::InvalidThreadState);
        };
        if unsafe { (*state).session_issued } { return Err(BootstrapError::AlreadyInitialized); }
        unsafe { (*state).session_issued = true; }
        let theap = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*state).theap)) };
        let parent_tld = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*state).tld)) };
        Ok(unsafe {
            crate::types::metadata_session::CanonicalMetadataTheapSession::new(
                theap,
                parent_tld,
                heap,
            )
        })
    }

    fn bind_owner(
        self: Pin<&mut Self>,
        owner: TheapOwner,
        detached_subprocess: Option<&'static MainSubprocess>,
        live_non_abandoning: bool,
    ) -> Result<(), BootstrapError> {
        // SAFETY: `Self` is !Unpin and this method never moves a field. The
        // newly stored self-referential raw pointers target the pinned `heap`
        // and `tld` fields and remain valid while this pinned image exists.
        let state = unsafe { self.get_unchecked_mut() };
        if state.bound_owner.is_some() {
            return Err(BootstrapError::AlreadyInitialized);
        }

        if let TheapOwner::Live(thread_id) = owner {
            state.tld.attach_bootstrap_exclusive(thread_id);
        } else if let Some(subprocess) = detached_subprocess {
            // Preserve src/init.c:184-193's detached-TLD sequence: form
            // only its kind-only static memid predecessor, then run the
            // detached mi_tld_init fields before binding the later Heap.
            // Neither TLD step registers a live thread or changes either
            // subprocess counter.
            if !state.tld.prepare_detached_static_memid()
                || !state.tld.initialize_detached_after_static_memid(subprocess)
            {
                return Err(BootstrapError::InvalidThreadState);
            }
            state.heap.bind_main_subprocess(subprocess);
        }
        let bound = match owner {
            TheapOwner::Live(_) if live_non_abandoning => state
                .theap
                .bind_exclusive_single_thread_non_abandoning(&mut state.heap, &mut state.tld),
            TheapOwner::Live(_) => state
                .theap
                .bind_exclusive_single_thread(&mut state.heap, &mut state.tld),
            TheapOwner::Detached => state
                .theap
                .bind_exclusive_detached(&mut state.heap, &mut state.tld),
        };
        if !bound {
            return Err(BootstrapError::InvalidThreadState);
        }
        state.bound_owner = Some(owner);
        Ok(())
    }

    fn begin_bound_session(
        self: Pin<&mut Self>,
        owner: TheapOwner,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        let state = unsafe { self.get_unchecked_mut() };
        if state.bound_owner != Some(owner) {
            return Err(BootstrapError::InvalidThreadState);
        }
        if state.session_issued {
            return Err(BootstrapError::AlreadyInitialized);
        }
        state.session_issued = true;
        Ok(ExclusiveTheapSession {
            // `state` came from the pinned receiver and remains in place for
            // the session lifetime; the session never moves the image.
            state: NonNull::from(state),
            owner,
            _pinned: PhantomData,
        })
    }

    #[inline]
    pub(crate) const fn active_thread(&self) -> Option<LiveThreadId> {
        match self.bound_owner {
            Some(TheapOwner::Live(thread_id)) => Some(thread_id),
            Some(TheapOwner::Detached) | None => None,
        }
    }
}

/// Exclusive capability for one activated live or detached theap.
///
/// It deliberately offers only the state transitions required by the bounded
/// exclusive page lifecycle. Dropping it does not detach, abandon, or free
/// anything; live-thread teardown and lock-free remote-free protocols remain
/// later work.
pub(crate) struct ExclusiveTheapSession<'a> {
    /// Address of the pinned bootstrap, derived once from its exclusive
    /// pinned borrow. Every access projects from this one raw capability:
    /// re-deriving a whole `&mut ExclusiveTheapBootstrap` or `&mut Theap` per
    /// queue access would retag the complete image and invalidate a disjoint
    /// queue projection that the page engine still holds (for example the
    /// source and destination of `mi_page_queue_enqueue_from`).
    state: NonNull<ExclusiveTheapBootstrap>,
    owner: TheapOwner,
    _pinned: PhantomData<Pin<&'a mut ExclusiveTheapBootstrap>>,
}

/// Narrow private page-owner interface shared by the static bootstrap and the
/// bounded dynamic-Theap page session.
///
/// It deliberately exposes queue/direct/page-accounting transitions rather
/// than a mutable whole Heap or Theap. Each implementation holds the one
/// address-stable source image and its exact owner/thread proof for the
/// duration of a page lifecycle; `single_thread.rs` remains the sole page
/// algorithm engine.
pub(crate) mod theap_page_session_sealed {
    pub(crate) trait Sealed {}
}

/// # Safety
///
/// An implementation must retain one stable initialized Theap, Heap, and TLD;
/// prove the exact live owner/thread identity for every published page; keep
/// ordinary page fields, queue links, and source queue/direct state under the
/// one owner while clients use only distinct current blocks and atomic Page
/// projections; select the exact main or heap-local arena-pages bitmap for
/// fresh, rollback, and release transitions; and prevent
/// attachment/metadata/list teardown while the engine or a scoped producer
/// may hold raw page state. The canonical detached metadata session has one
/// explicit source exception: after permanent process quiescence and with no
/// outstanding observations, main-Heap destruction may detach its TLD/Heap
/// links while retaining its static identities/backing and exclusive local
/// field authority solely for that pass's metadata frees. No fresh allocation,
/// producer admission, or physical backing retirement overlaps this phase;
/// terminal metadata close consumes the session before backing destruction.
/// `publish_fresh_page` must wire only that
/// exact stable Theap/Heap pair.
pub(crate) unsafe trait TheapPageSession: theap_page_session_sealed::Sealed {
    fn theap(&self) -> &Theap;
    fn thread_id(&self) -> Option<LiveThreadId>;
    /// Runs OS placement draws against this session's source random image.
    /// Ordinary sessions use current compiler TLS; detached child metadata
    /// sessions override this to draw from their owned metadata Theap.
    #[inline]
    fn with_os_random_source<R>(
        &mut self,
        operation: impl FnOnce(&mut (dyn crate::os::OsRandomSource + 'static)) -> R,
    ) -> R {
        // SAFETY: ordinary source sessions retain the current default Theap
        // for the operation; child metadata sessions provide their own image.
        let mut random = unsafe { crate::os::CurrentDefaultTheapRandom::new() };
        operation(&mut random)
    }
    /// Advances the source generic-allocation administration counters for an
    /// ordinary allocation boundary. Only a session that owns the exact
    /// mutable Theap overrides this hook; read-only or deliberately narrowed
    /// sessions retain their existing no-allocation behavior.
    #[inline]
    fn advance_generic_allocation_administration(
        &mut self,
    ) -> crate::types::GenericAllocationAdministration {
        crate::types::GenericAllocationAdministration::None
    }
    /// Copies the current source identity for a caller-stack deferred-free
    /// phase. The default deliberately grants no raw source identity to
    /// narrowed, teardown, or fixture sessions.
    #[inline]
    fn deferred_free_source(&self) -> Option<crate::deferred_free::DeferredFreeSource> {
        None
    }
    /// Reports whether this session still authorizes ordinary page-engine
    /// operations. A typed teardown continuation can retain the backing page
    /// image solely to resume its own source boundary; it must not thereby
    /// re-enable allocation, free, collection, or remote-producer entry.
    /// Static and completed drain sessions remain ordinary engine owners.
    #[inline]
    fn permits_ordinary_page_operations(&self) -> bool { true }

    /// Native terminal retirement is separately opt-in. A session must prove
    /// no bound local projection or retained selector owner remains, without
    /// consulting the calling thread's TLS identity. This grants no source
    /// access; the consuming engine still requires permanent quiescence.
    fn permits_terminal_process_retirement(&self) -> bool { false }
    /// Authorizes only a captured pointer-first local free over a source
    /// Theap retained after process shutdown. This does not authorize fresh
    /// allocation, collection, attachment, or a general ordinary engine
    /// operation. The sealed default is false so a session must opt in to
    /// that one narrowed source transition explicitly.
    #[inline]
    fn permits_retained_source_local_free(&self) -> bool { false }
    /// Selects the pinned selected-x86 static-main source full-page branch.
    ///
    /// This is policy, not a safety proof: once selected, an invalid page or
    /// unavailable static-main capability must terminally retain the current
    /// transition instead of silently taking the non-abandoning `BIN_FULL`
    /// algorithm. The sealed default keeps paused and intentionally
    /// non-abandoning sessions on their existing source transition.
    #[inline]
    fn selects_selected_main_arena_source_full_abandonment(&self) -> bool { false }
    /// Authorizes mutation of the selected x86 static-main source
    /// full-page-abandonment branch after it was selected by
    /// [`Self::selects_selected_main_arena_source_full_abandonment`].
    ///
    /// The caller still validates the pinned default-release Theap options,
    /// regular arena page shape, and matching static-main bitmap/count
    /// capability. A false result is a terminal retained failure, never an
    /// alternate source policy.
    #[inline]
    fn permits_selected_main_arena_ordinary_full_abandonment(&self) -> bool { false }
    /// Links one non-arena full page into the selected source Heap's private
    /// `os_abandoned_pages` list after its abandoned identity is visible and
    /// before the common low-owner-bit release. The sealed default refuses:
    /// an unavailable source list is a retained transition, never permission
    /// to use the arena bitmap or the non-abandoning full queue.
    #[inline]
    fn push_selected_main_os_abandoned_page(&mut self, _page: NonNull<Page>) -> bool { false }
    /// Removes the exact all-free non-arena page from the selected source
    /// Heap's private abandoned list before its PageMap/metadata/mapping
    /// terminal release. The default has no list authority.
    #[inline]
    fn remove_selected_main_os_abandoned_page(&mut self, _page: NonNull<Page>) -> bool { false }
    fn queue(&self, bin: usize) -> Option<&PageQueue>;
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue>;
    fn direct_page(&self, index: usize) -> Option<*mut Page>;
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool;
    fn note_page_added(&mut self);
    fn note_page_removed(&mut self) -> bool;
    /// Ensures the source-selected ordinary arena-pages bitmap exists before
    /// fresh page metadata can be published. The static session selects the
    /// arena's `pages_main`; a dynamic session lazily owns one heap-local
    /// `mi_arena_pages_t` image.
    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, config: MemoryConfig) -> bool;
    /// Sets one ordinary arena-pages bit after fresh metadata exists and
    /// before page-map registration.
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool;
    /// Clears one ordinary arena-pages bit after page-map unregistration and
    /// before returning the source arena slice claim.
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool;
    unsafe fn publish_fresh_page(
        &mut self,
        metadata: NonNull<Page>,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> Option<NonNull<Page>>;
    /// Performs the terminal whole-page reset.
    ///
    /// The caller must first prove the source `used == 0` no-live-client
    /// condition and remove every queue, direct-cache, PageMap, bitmap, and
    /// aligned alias that could retain or reach this metadata. Fresh rollback
    /// may call this before any client or producer projection is published.
    /// Only those two states permit manufacturing the supplied `&mut Page`.
    fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId>;
    fn retired_bounds(&self) -> (usize, usize);
    fn note_retired_bin(&mut self, bin: usize) -> bool;
    fn reset_retired_bounds(&mut self);
    /// Transfers a detached OS mapping owner into session-specific terminal
    /// storage before an unfinished engine disappears. Implementations that
    /// have no retained attachment return the unchanged owner to the caller.
    fn retain_unfinished_os_release(
        &mut self,
        owner: OsAlignedPageOwner,
    ) -> Result<(), OsAlignedPageOwner>;
    /// Latches an unfinished engine without freeing or detaching page state.
    /// Static bootstrap sessions are inert; dynamic sessions poison their
    /// retained attachment so later teardown/re-entry cannot lie.
    fn latch_unfinished_page_engine(&mut self);

    /// Runs the selected static-main mapped-regular source only while its
    /// persistent owner selector is synchronously bound to this session.
    ///
    /// The higher-ranked callback makes the non-Copy source unrepresentable
    /// in `R`: a caller cannot retain the pair, static-Heap lease, or scoped
    /// PageMap claim capability after this bound session ends. The sealed
    /// default is deliberately unavailable and accepts no linear token, so a
    /// generic session cannot accidentally consume/forget one.
    #[inline]
    unsafe fn with_static_main_mapped_regular_claim_source<R>(
        _session: NonNull<Self>,
        _operation: impl for<'source> FnOnce(StaticMainMappedRegularClaimSource<'source>) -> R,
    ) -> StaticMainMappedRegularClaimSourceHookOutcome<R>
    where
        Self: Sized,
    {
        StaticMainMappedRegularClaimSourceHookOutcome::Unavailable
    }

    /// Reports the persistent selected-source terminal latch without exposing
    /// any source capability. Allocation entry gates include this predicate so
    /// a second allocation in one bound user callback cannot bypass a first
    /// regular-page claim failure through an unrelated size class.
    #[inline]
    fn is_static_main_mapped_regular_claim_terminal(&self) -> bool { false }
}

impl ExclusiveTheapSession<'_> {
    #[inline]
    fn state_mut(&mut self) -> &mut ExclusiveTheapBootstrap {
        // SAFETY: session construction consumed the sole mutable pinned
        // borrow for `'a`, and `&mut self` excludes every other projection
        // made through this session. Callers never move a pinned field.
        unsafe { &mut *self.state.as_ptr() }
    }

    /// The pinned Theap address, projected without forming a whole-image
    /// reference.
    #[inline]
    fn theap_pointer(&self) -> NonNull<Theap> {
        // SAFETY: `state` is the live pinned bootstrap for `'a`; this only
        // computes a field address.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.state.as_ptr()).theap)) }
    }

    /// Initializes one child metadata Theap against this session's actual
    /// detached parent TLD.
    ///
    /// # Safety
    /// The child Heap and Theap must remain pinned in stable storage until
    /// both source list memberships are removed. `child_theap` must be the
    /// still-live exact parent metadata allocation, and the caller must
    /// exclude concurrent child lifecycle operations.
    /// An error may follow TLD-list attachment and Release publication; in
    /// that case the caller must retain the child owner and not retry.
    pub(crate) unsafe fn initialize_child_metadata_theap(
        &mut self,
        parent: &'static MainSubprocess,
        child_heap: &mut Heap,
        child_theap: &mut Theap,
    ) -> Result<(), crate::types::TheapMainStaticInitError> {
        let owner = self.owner;
        let state = self.state_mut();
        if owner != TheapOwner::Detached
            || !state.is_detached_for_main_subprocess(parent)
        {
            return Err(crate::types::TheapMainStaticInitError::InvalidInput);
        }
        // SAFETY: this session pins the parent bootstrap; the caller promises
        // stable child images and exclusive lifecycle authority through detach.
        unsafe { child_theap.initialize_child_metadata(child_heap, &mut state.tld) }
    }

    /// Detaches a child metadata Theap in the source TLD-then-Heap order.
    ///
    /// # Safety
    /// The caller has exclusive teardown authority over the pinned child Heap
    /// and Theap, no child clients or producers remain, and the exact
    /// metadata allocation stays live. Errors distinguish failure before the
    /// TLD unlink, after it, before the Heap unlink, or after both list edges
    /// were removed; unlock failures may follow mutation. Retain the complete
    /// child owner and do not retry or release from the error alone. No Rust
    /// reference to `child_theap` may remain live during this raw-pointer
    /// transition; reacquire a projection from its capability afterward.
    pub(crate) unsafe fn detach_child_metadata_theap(
        &mut self,
        parent: &'static MainSubprocess,
        child_heap: &mut Heap,
        child_theap: NonNull<Theap>,
    ) -> Result<(), crate::types::ChildTheapDetachError> {
        let owner = self.owner;
        let state = self.state_mut();
        if owner != TheapOwner::Detached
            || !state.is_detached_for_main_subprocess(parent)
        {
            return Err(crate::types::ChildTheapDetachError::BeforeTldUnlink(
                crate::types::ThreadLocalTheapListError::Membership,
            ));
        }
        // SAFETY: forwarded child image pinning, producer quiescence, and
        // exact-allocation liveness obligations.
        unsafe {
            state
                .tld
                .detach_one_child_theap_for_heap_destroy(child_heap, child_theap.as_ptr())
        }
    }

    /// Inspects the initialized exclusive theap without permitting replacement
    /// of its address-stable backing field.
    #[inline]
    pub(crate) fn theap(&self) -> &Theap {
        // SAFETY: the session exclusively owns the pinned image for `'a`;
        // `&self` excludes a concurrent mutable projection through it.
        unsafe { self.theap_pointer().as_ref() }
    }

    #[inline]
    pub(crate) const fn thread_id(&self) -> Option<LiveThreadId> {
        match self.owner {
            TheapOwner::Live(thread_id) => Some(thread_id),
            TheapOwner::Detached => None,
        }
    }

    /// Returns one source `mi_page_queue_t` under the exclusive session.
    #[inline]
    pub(crate) fn queue(&self, bin: usize) -> Option<&PageQueue> {
        // SAFETY: `&self` excludes a mutable projection of this queue made
        // through the session for the returned lifetime.
        unsafe { Theap::local_queue_at(self.theap_pointer(), bin) }
    }

    /// Grants local lifecycle code one queue record while retaining ownership
    /// of the pinned theap itself. Queue insertion/removal must pair with the
    /// respective page-count method below.
    #[inline]
    pub(crate) fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        // SAFETY: `&mut self` makes this the only live projection of the
        // selected queue made through the session. It retags only that
        // queue, so a raw pointer the engine retains to another queue stays
        // valid across this call.
        unsafe { Theap::local_queue_mut_at(self.theap_pointer(), bin) }
    }

    #[inline]
    pub(crate) fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.theap().direct_page(index)
    }

    #[inline]
    pub(crate) fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        // SAFETY: this exclusive session owns the direct slot.
        unsafe { Theap::set_local_direct_page_at(self.theap_pointer(), index, page) }
    }

    #[inline]
    pub(crate) fn clear_direct_page(&mut self, index: usize) -> bool {
        // SAFETY: this exclusive session owns the direct slot.
        unsafe { Theap::set_local_direct_page_at(self.theap_pointer(), index, crate::types::EMPTY_PAGE.as_ptr()) }
    }

    #[inline]
    pub(crate) fn note_page_added(&mut self) {
        // SAFETY: this exclusive session owns the source page count.
        unsafe { Theap::note_local_page_added_at(self.theap_pointer()) }
    }

    #[inline]
    pub(crate) fn note_page_removed(&mut self) -> bool {
        // SAFETY: this exclusive session owns the source page count.
        unsafe { Theap::note_local_page_removed_at(self.theap_pointer()) }
    }

    /// Initializes raw, potentially nonzero arena metadata as a fresh page.
    ///
    /// This is the session-level entry point for source
    /// `mi_arenas_page_alloc_fresh` metadata: it writes a valid empty `Page`
    /// image before forming a Rust reference, then wires that page to the
    /// stable pinned heap/theap fields. It does not insert the page into a
    /// queue or direct cache; local lifecycle code performs those transitions
    /// only after this method returns the now-valid metadata pointer.
    ///
    /// # Safety
    ///
    /// `metadata` must be writable, suitably aligned storage for one `Page`
    /// and must not currently hold a live Rust `Page`. No page-map, queue, or
    /// other observer may access it during initialization. The metadata and
    /// its live block area (`page_offset` followed by `reserved * block_size`
    /// bytes) must remain exclusively owned and valid for the resulting
    /// page's complete local lifecycle. The supplied geometry and `memid`
    /// must faithfully describe that pre-existing mapping; this method neither
    /// maps nor validates virtual memory.
    #[inline]
    pub(crate) unsafe fn publish_fresh_page(
        &mut self,
        metadata: NonNull<Page>,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> Option<NonNull<Page>> {
        let owner = self.owner;
        let theap = self.theap_pointer();
        // SAFETY: `state` is the live pinned bootstrap; this only computes
        // the Heap field address.
        let heap = unsafe {
            NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.state.as_ptr()).heap))
        };
        // SAFETY: this method forwards its raw-metadata and live-area
        // obligations unchanged; the session owns the stable pinned
        // Theap/Heap, whose raw projections the page records as its owner.
        unsafe {
            Page::publish_fresh_exclusive_owner_at_with_pointers(
                metadata,
                theap,
                heap,
                owner,
                block_size,
                page_offset,
                reserved,
                slice_pcommitted,
                free_is_zero,
                memid,
            )
        }
    }

    /// Associates `page` with this stable exclusive theap and heap.
    ///
    /// The page metadata and its described block area must remain stable and
    /// exclusively owned for as long as it remains associated. In particular,
    /// callers must not use the static [`EMPTY_PAGE`] sentinel here.
    #[inline]
    pub(crate) fn associate_page(&mut self, page: &mut Page) {
        let owner = self.owner;
        let state = self.state_mut();
        page.associate_exclusive_owner(&mut state.theap, &state.heap, owner);
    }

    /// Clears a local-page association before metadata reuse.
    ///
    /// No queue or direct-cache slot may still point at `page`, and no remote
    /// free or observer may exist; this is not thread teardown or abandonment.
    #[inline]
    pub(crate) fn disassociate_page(&mut self, page: &mut Page) {
        page.disassociate_exclusive();
    }

    /// Resets a fully free, detached page and returns its release provenance.
    ///
    /// The caller must first clear every direct-cache slot, remove queue
    /// membership, update theap page accounting, and establish the exclusive
    /// no-remote-free contract. Before releasing its backing mapping, the
    /// caller must unregister the returned provenance's raw page address.
    #[inline]
    pub(crate) fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId> {
        page.retire_exclusive()
    }

    /// Reports the bounded source collection range for retired regular bins.
    #[inline]
    pub(crate) fn retired_bounds(&self) -> (usize, usize) {
        self.theap().retired_bounds()
    }

    /// Includes one retired regular-bin page in the next local collection
    /// range. Full and huge bins are rejected, matching the source contract.
    #[inline]
    pub(crate) fn note_retired_bin(&mut self, bin: usize) -> bool {
        // SAFETY: this exclusive session owns the retired bounds.
        unsafe { Theap::note_local_retired_bin_at(self.theap_pointer(), bin) }
    }

    /// Resets retirement bounds after a local collection pass empties them.
    #[inline]
    pub(crate) fn reset_retired_bounds(&mut self) {
        // SAFETY: this exclusive session owns the retired bounds.
        unsafe { Theap::reset_local_retired_bounds_at(self.theap_pointer()) }
    }

    /// Runs the source `_mi_deferred_free` scalar prefix for one collection
    /// phase of a phased allocation: advance this Theap's heartbeat and
    /// select from a fixture-local registration that has no callback.
    ///
    /// Runtime owners perform this phase B through their caller-stack
    /// `DeferredFreeSource`; this exclusive fixture session has no process
    /// callback boundary, so a test driver stands in for that runtime step.
    #[cfg(test)]
    pub(crate) fn test_run_empty_deferred_free_phase(&mut self, force: bool) -> u64 {
        static EMPTY_REGISTRATION: crate::deferred_free::DeferredFreeRegistration =
            crate::deferred_free::DeferredFreeRegistration::new();
        let theap = self.theap_pointer();
        // SAFETY: `state` is the live pinned bootstrap; this only computes
        // the TLD field address.
        let tld = unsafe {
            NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.state.as_ptr()).tld))
        };
        let invocation = crate::deferred_free::begin(&EMPTY_REGISTRATION, theap, tld, force)
            .expect("the exclusive Theap records its own TLD");
        // SAFETY: the empty registration never selects user code, so no
        // callback can observe or reenter this exclusive session.
        unsafe { invocation.invoke() }
    }
}

impl theap_page_session_sealed::Sealed for ExclusiveTheapSession<'_> {}

unsafe impl TheapPageSession for ExclusiveTheapSession<'_> {
    #[inline]
    fn theap(&self) -> &Theap { Self::theap(self) }
    #[inline]
    fn thread_id(&self) -> Option<LiveThreadId> { Self::thread_id(self) }
    /// This session exclusively owns its whole pinned Theap, so it keeps the
    /// source `_mi_malloc_generic` counters. It has no process option owner
    /// and therefore uses the frozen `mi_option_generic_collect` default.
    #[inline]
    fn advance_generic_allocation_administration(
        &mut self,
    ) -> crate::types::GenericAllocationAdministration {
        // SAFETY: this exclusive session owns both counters, and the frozen
        // default option read inspects no Theap state.
        unsafe { Theap::advance_generic_allocation_administration_at(self.theap_pointer(), || 10_000) }
    }
    #[inline]
    fn queue(&self, bin: usize) -> Option<&PageQueue> { Self::queue(self, bin) }
    #[inline]
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> { Self::queue_mut(self, bin) }
    #[inline]
    fn direct_page(&self, index: usize) -> Option<*mut Page> { Self::direct_page(self, index) }
    #[inline]
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        Self::set_direct_page(self, index, page)
    }
    #[inline]
    fn note_page_added(&mut self) { Self::note_page_added(self) }
    #[inline]
    fn note_page_removed(&mut self) -> bool { Self::note_page_removed(self) }
    #[inline]
    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        // SAFETY: static bootstrap owns the same source arena lifecycle and
        // `pages_main` is in-place initialized before the ArenaView exists.
        unsafe { arena.pages().is_some() }
    }
    #[inline]
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        let Some(arena_memory) = memory.arena_memory() else {
            return false;
        };
        if arena_memory.arena != core::ptr::from_ref(arena.arena()).cast_mut() {
            return false;
        }
        // SAFETY: the fresh-page lifecycle owns this exact in-place main
        // bitmap transition before page-map publication.
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
        // SAFETY: the matching page-map entry is gone in source release
        // order, so the static session may clear its exact main bitmap bit.
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
        unsafe {
            Self::publish_fresh_page(
                self, metadata, block_size, page_offset, reserved, slice_pcommitted,
                free_is_zero, memid,
            )
        }
    }
    #[inline]
    fn retire_page(&mut self, page: &mut Page) -> Option<MemoryId> { Self::retire_page(self, page) }
    #[inline]
    fn retired_bounds(&self) -> (usize, usize) { Self::retired_bounds(self) }
    #[inline]
    fn note_retired_bin(&mut self, bin: usize) -> bool { Self::note_retired_bin(self, bin) }
    #[inline]
    fn reset_retired_bounds(&mut self) { Self::reset_retired_bounds(self) }
    #[inline]
    fn retain_unfinished_os_release(
        &mut self,
        owner: OsAlignedPageOwner,
    ) -> Result<(), OsAlignedPageOwner> {
        Err(owner)
    }
    #[inline]
    fn latch_unfinished_page_engine(&mut self) {}
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::MaybeUninit;
    use crate::config::{BIN_COUNT, BIN_FULL, PAGES_DIRECT};
    use crate::types::{
        MemoryKind, BIN_BLOCK_SIZES, EMPTY_PAGE, EMPTY_PAGE_QUEUES, THREAD_ID_ABANDONED,
        THREAD_ID_ABANDONED_MAPPED, THREAD_ID_DETACHED,
    };

    #[test]
    fn live_thread_identity_reserves_page_flags_and_special_source_values() {
        for invalid in [
            THREAD_ID_ABANDONED,
            1,
            2,
            3,
            THREAD_ID_ABANDONED_MAPPED,
            THREAD_ID_DETACHED,
        ] {
            assert!(LiveThreadId::new(invalid).is_none(), "{invalid:#x} is reserved");
        }
        assert_eq!(LiveThreadId::new(12).map(LiveThreadId::get), Some(12));
        assert_eq!(LiveThreadId::new(16).map(LiveThreadId::get), Some(16));
    }

    #[test]
    fn source_empty_theap_initializes_every_direct_slot_and_queue() {
        let theap = empty_default_theap();

        assert!(!theap.is_initialized());
        assert!(theap.is_detached());
        assert_eq!(theap.refcount(), 1);
        assert_eq!(theap.page_count(), 0);
        for index in 0..PAGES_DIRECT {
            assert_eq!(theap.direct_page(index), Some(EMPTY_PAGE.as_ptr()), "slot {index}");
        }
        assert!(theap.direct_page(PAGES_DIRECT).is_none());

        for (index, (queue, expected)) in (0..BIN_COUNT)
            .map(|index| (theap.queue(index).expect("source queue exists"), BIN_BLOCK_SIZES[index]))
            .enumerate()
        {
            assert_eq!(queue.block_size(), expected, "queue {index}");
            assert!(queue.is_empty(), "queue {index}");
            assert_eq!(queue.count(), 0, "queue {index}");
        }
        assert!(theap.queue(BIN_COUNT).is_none());
        assert_eq!(BIN_FULL, BIN_COUNT - 1);
        assert_eq!(EMPTY_PAGE_QUEUES.len(), BIN_COUNT);
    }

    #[test]
    fn pinned_activation_binds_stable_owner_addresses_and_publishes_heap_last() {
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let thread_id = LiveThreadId::new(12).expect("valid source-shaped id");

        let session = bootstrap
            .as_mut()
            .activate_live(thread_id)
            .expect("first pinned activation succeeds");
        // SAFETY: the live session keeps its pinned image for this read.
        let state = unsafe { session.state.as_ref() };
        let theap = session.theap();

        assert_eq!(state.active_thread(), Some(thread_id));
        assert!(theap.is_initialized());
        assert!(!theap.is_detached());
        assert!(
            !theap.allows_page_abandon(),
            "the bounded local lifecycle uses source non-abandoning mode"
        );
        assert!(theap.matches_thread(thread_id));
        assert_eq!(
            theap.heap(),
            core::ptr::addr_of!(state.heap).cast_mut(),
            "theap stores the pinned heap field address"
        );
        assert_eq!(theap.refcount(), 1);
        assert_eq!(session.retired_bounds(), (BIN_FULL, 0));

        drop(session);
        assert!(matches!(
            bootstrap.as_mut().activate_live(thread_id),
            Err(BootstrapError::AlreadyInitialized)
        ), "this bounded slice has no detach/reinitialize lifecycle");
    }

    #[test]
    fn detached_activation_keeps_the_source_detached_identity_and_forbids_abandonment() {
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let subprocess = MainSubprocess::test_static_owner();
        let session = bootstrap
            .as_mut()
            .activate_detached_for_main_subprocess(subprocess)
            .expect("a detached source bootstrap activates once");
        // SAFETY: the live session keeps its pinned image for this read.
        let state = unsafe { session.state.as_ref() };
        let theap = session.theap();

        assert_eq!(session.thread_id(), None);
        assert_eq!(state.active_thread(), None);
        assert!(theap.is_initialized());
        assert!(theap.is_detached());
        assert!(state.heap.is_bound_to_main_subprocess(subprocess));
        assert!(state.tld.is_attached_to_main_subprocess(subprocess));
        assert!(theap.is_bound_to_main_subprocess(subprocess));
        assert_eq!(state.tld.numa_node(), -1);
        assert_eq!(theap.refcount(), 1);
        assert_eq!(theap.page_full_retain(), 2);
        assert!(!theap.allows_page_abandon());
        assert_eq!(
            theap.heap(),
            core::ptr::addr_of!(state.heap).cast_mut(),
            "the detached theap publishes its address-stable heap last"
        );

        drop(session);
        assert!(matches!(
            bootstrap.as_mut().activate_detached(),
            Err(BootstrapError::AlreadyInitialized)
        ));
    }

    #[test]
    fn detached_binding_initializes_the_static_image_before_issuing_its_one_session() {
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let subprocess = MainSubprocess::test_static_owner();
        let foreign = MainSubprocess::test_static_owner();

        bootstrap
            .as_mut()
            .bind_detached_for_main_subprocess(subprocess)
            .expect("the static detached image binds without an allocator session");
        {
            let state = bootstrap.as_ref().get_ref();
            assert!(state.is_detached_for_main_subprocess(subprocess));
            assert!(state.theap.is_initialized());
            assert_eq!(state.active_thread(), None);
            assert!(
                state.theap.allows_page_reclaim(),
                "the frozen source page-reclaim default is present before first metadata demand"
            );
            let fields = state.theap.test_main_static_fields();
            assert_eq!(fields.memid.kind(), MemoryKind::Static);
            assert!(
                fields.random_initialized,
                "the detached metadata Theap initializes its first-head random image before demand"
            );
            assert!(
                fields.cookie_is_odd,
                "the detached metadata Theap derives its source cookie before publication"
            );
            let static_memory = fields
                .memid
                .static_memory()
                .expect("the static source image projects its zero union");
            assert!(
                !fields.memid.is_pinned()
                    && !fields.memid.initially_committed()
                    && !fields.memid.initially_zero(),
                "the detached metadata Theap preserves init.c's kind-only \
                 _mi_memid_create(MI_MEM_STATIC) provenance before first demand"
            );
            assert!(
                static_memory.base.is_null() && static_memory.size == 0,
                "the detached metadata Theap preserves _mi_memid_create's zero union"
            );
            assert!(!state.session_issued);
        }
        assert!(matches!(
            bootstrap.as_mut().begin_bound_detached_session(foreign),
            Err(BootstrapError::InvalidThreadState)
        ));

        let session = bootstrap
            .as_mut()
            .begin_bound_detached_session(subprocess)
            .expect("the first demand lends the one already bound detached session");
        assert_eq!(session.thread_id(), None);
        drop(session);

        assert!(matches!(
            bootstrap.as_mut().begin_bound_detached_session(subprocess),
            Err(BootstrapError::AlreadyInitialized)
        ));
    }

    #[repr(C, align(8))]
    struct FreshPageBacking {
        page: MaybeUninit<Page>,
        area: [u8; 8],
    }

    #[test]
    fn pinned_session_raw_publication_initializes_metadata_before_page_access() {
        let bootstrap = ExclusiveTheapBootstrap::new();
        let mut bootstrap = core::pin::pin!(bootstrap);
        let thread_id = LiveThreadId::new(12).expect("valid source-shaped id");
        let mut session = bootstrap
            .as_mut()
            .activate_live(thread_id)
            .expect("pinned bootstrap activates");
        let mut backing = FreshPageBacking {
            page: MaybeUninit::uninit(),
            area: [0; 8],
        };
        let raw_page = NonNull::from(&mut backing.page).cast::<Page>();

        // SAFETY: this aligned backing begins with uninitialized Page metadata
        // followed by the described, exclusive eight-byte page area.
        let page = unsafe {
            session
                .publish_fresh_page(
                    raw_page,
                    8,
                    core::mem::size_of::<Page>(),
                    1,
                    0,
                    true,
                    MemoryId::none(),
                )
                .expect("valid fresh-page geometry")
        };
        // SAFETY: `publish_fresh_page` has just initialized this metadata.
        let page_ref = unsafe { page.as_ref() };
        assert_eq!(page_ref.theap(), session.theap() as *const Theap as *mut Theap);
        assert_eq!(page_ref.reserved(), 1);
        assert_eq!(page_ref.block_size(), 8);
        assert!(page_ref.free_is_zero());
        assert_eq!(
            // SAFETY: the backing includes the full recorded page area.
            unsafe { page_ref.start() },
            backing.area.as_mut_ptr()
        );

        assert!(session.set_direct_page(0, page.as_ptr()));
        assert_eq!(session.direct_page(0), Some(page.as_ptr()));
        assert!(session.clear_direct_page(0));
        assert_eq!(session.direct_page(0), Some(EMPTY_PAGE.as_ptr()));

        assert!(session.note_retired_bin(3));
        assert!(session.note_retired_bin(1));
        assert!(session.note_retired_bin(8));
        assert_eq!(session.retired_bounds(), (1, 8));
        assert!(!session.note_retired_bin(BIN_FULL));
        session.reset_retired_bounds();
        assert_eq!(session.retired_bounds(), (BIN_FULL, 0));

        // SAFETY: the sole session still exclusively owns the initialized page.
        let page_mut = unsafe { &mut *page.as_ptr() };
        assert_eq!(
            session
                .retire_page(page_mut)
                .expect("the fresh page is free and queue-detached")
                .kind(),
            MemoryKind::None
        );
    }
}
