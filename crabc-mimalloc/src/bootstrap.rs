// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:99-173`
// (`_mi_theap_empty`, the detached TLD relationship, and empty-theap
// predicate), `src/init.c:305-360` (main default-theap wiring order),
// `src/theap.c:228-306` (`_mi_theap_init`'s initialized-predicate publication
// order), and `include/mimalloc/internal.h:626-664` (theap initialized and
// thread-identity predicates).
//
// This is deliberately only an allocation-free, exclusive single-thread
// bootstrap. It has no compiler TLS slot, pthread key, first-class heap,
// subprocess, random, remote-free, teardown, or concurrent-init lifecycle.

use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::ptr::NonNull;

use crate::types::{
    Heap, LiveThreadId, MemoryId, Page, PageQueue, Theap, TheapOwner,
    ThreadLocalData,
};

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
    active_owner: Option<TheapOwner>,
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
            active_owner: None,
            _not_send_or_sync: PhantomData,
            _pin: PhantomPinned,
        }
    }

    /// Attaches and publishes a live-thread theap after this image is pinned.
    ///
    /// This is the bounded source order from `_mi_thread_init_with_heap` and
    /// `_mi_theap_init`: record the caller identity in the TLD, complete the
    /// ordinary theap fields, then publish the heap pointer last. The returned
    /// session is the sole local owner; it neither installs nor reads TLS.
    pub(crate) fn activate_live(
        self: Pin<&mut Self>,
        thread_id: LiveThreadId,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        self.activate_owner(TheapOwner::Live(thread_id))
    }

    /// Activates the source detached metadata-theap form.
    ///
    /// The resulting session is not thread-local: a process owner must hold
    /// its private lock around every operation. It deliberately has no
    /// thread identity, TLS access, remote-free path, or abandonment path.
    pub(crate) fn activate_detached(
        self: Pin<&mut Self>,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        self.activate_owner(TheapOwner::Detached)
    }

    fn activate_owner(
        self: Pin<&mut Self>,
        owner: TheapOwner,
    ) -> Result<ExclusiveTheapSession<'_>, BootstrapError> {
        // SAFETY: `Self` is !Unpin and this method never moves a field. The
        // newly stored self-referential raw pointers target the pinned `heap`
        // and `tld` fields and remain valid while the returned session borrows
        // this Pin.
        let state = unsafe { self.get_unchecked_mut() };
        if state.active_owner.is_some() {
            return Err(BootstrapError::AlreadyInitialized);
        }

        if let TheapOwner::Live(thread_id) = owner {
            state.tld.attach_bootstrap_exclusive(thread_id);
        }
        let bound = match owner {
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
        state.active_owner = Some(owner);

        Ok(ExclusiveTheapSession {
            // SAFETY: `state` came from the pinned receiver and remains in
            // place for the session lifetime. Reborrowing it restores the
            // pin rather than moving the bootstrap image.
            state: unsafe { Pin::new_unchecked(state) },
            owner,
        })
    }

    #[inline]
    pub(crate) const fn active_thread(&self) -> Option<LiveThreadId> {
        match self.active_owner {
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
    state: Pin<&'a mut ExclusiveTheapBootstrap>,
    owner: TheapOwner,
}

impl ExclusiveTheapSession<'_> {
    #[inline]
    fn state_mut(&mut self) -> &mut ExclusiveTheapBootstrap {
        // SAFETY: session construction holds the sole mutable borrow of the
        // pinned bootstrap. This helper does not move any pinned field.
        unsafe { self.state.as_mut().get_unchecked_mut() }
    }

    /// Inspects the initialized exclusive theap without permitting replacement
    /// of its address-stable backing field.
    #[inline]
    pub(crate) fn theap(&self) -> &Theap {
        &self.state.as_ref().get_ref().theap
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
        self.theap().queue(bin)
    }

    /// Grants local lifecycle code one queue record while retaining ownership
    /// of the pinned theap itself. Queue insertion/removal must pair with the
    /// respective page-count method below.
    #[inline]
    pub(crate) fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        self.state_mut().theap.queue_mut(bin)
    }

    #[inline]
    pub(crate) fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.theap().direct_page(index)
    }

    #[inline]
    pub(crate) fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        self.state_mut().theap.set_direct_page(index, page)
    }

    #[inline]
    pub(crate) fn clear_direct_page(&mut self, index: usize) -> bool {
        self.state_mut().theap.clear_direct_page(index)
    }

    #[inline]
    pub(crate) fn note_page_added(&mut self) {
        self.state_mut().theap.note_page_added();
    }

    #[inline]
    pub(crate) fn note_page_removed(&mut self) -> bool {
        self.state_mut().theap.note_page_removed()
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
        let state = self.state_mut();
        // SAFETY: this method forwards its raw-metadata and live-area
        // obligations unchanged; `state` owns the stable pinned theap/heap.
        unsafe {
            Page::publish_fresh_exclusive_owner_at(
                metadata,
                &mut state.theap,
                &mut state.heap,
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
        page.associate_exclusive_owner(&mut state.theap, &mut state.heap, owner);
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
        self.state_mut().theap.note_retired_bin(bin)
    }

    /// Resets retirement bounds after a local collection pass empties them.
    #[inline]
    pub(crate) fn reset_retired_bounds(&mut self) {
        self.state_mut().theap.reset_retired_bounds();
    }
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
        let state = session.state.as_ref().get_ref();
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
        let session = bootstrap
            .as_mut()
            .activate_detached()
            .expect("a detached source bootstrap activates once");
        let state = session.state.as_ref().get_ref();
        let theap = session.theap();

        assert_eq!(session.thread_id(), None);
        assert_eq!(state.active_thread(), None);
        assert!(theap.is_initialized());
        assert!(theap.is_detached());
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
