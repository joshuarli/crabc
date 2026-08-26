// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/arena.c:674-723,1101-1114,1240-1282`,
// `src/page.c:214-302`, `src/free.c:371-515`,
// `src/threadlocal.c:23-214`,
// `src/init.c:236-360,377-421,448-481`, `src/theap.c:228-306,357-369,414-449`,
// `src/heap.c:60-100`, and `src/prim/prim-tls.c:211-229`.

//! Private current-thread dynamic Theap attachment.
//!
//! This is a deliberately narrow first-class-heap binding: a caller provides
//! one address-stable `Heap::bootstrap_empty()` image, this owner claims one
//! regular TLS key, and it attaches one direct-zeroed metadata Theap to one
//! later-ticket metadata TLD. It does not implement `mi_heap_new/delete`,
//! subprocess heap lists/counters, general cached-root switching, pthread
//! hooks, or public allocation APIs. Ordinary dynamic begin uses the source
//! abandoning `true`/`2` option image and rejects a page session. The private
//! unsafe non-abandoning begin selects source-reachable `false`/`-1` before
//! Release heap publication; its exclusive borrowed `DynamicTheapPageSession`
//! alone reaches the shared private page engine. Its first dynamic arena page
//! lazily receives one exact heap-local `mi_arena_pages_t` metadata image;
//! fresh/rollback/release use that image rather than `Arena::pages_main`. Its
//! post-TLS `DynamicTheapPageDrainSession` first force-collects already-retired
//! all-free pages, then has one further source-shaped live owner exit: a full
//! one-block arena or OS-aligned singleton can be queue-detached, abandoned,
//! and released only when its later client free sees the cleared regular slot
//! and takes the failed-reclaim all-free tail. The OS branch links the exact
//! page through this dynamic Heap's private `os_abandoned_pages` list before
//! common unown, then removes it before clipped map/metadata/mapping release.
//! Four separate full regular handoffs remain initially unmapped after source
//! force then false collection: medium and large detach from `BIN_FULL`;
//! non-direct small requires `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`
//! and detaches from its ordinary bin with every direct-cache slot empty; and
//! direct small requires `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and
//! its complete rounded direct-cache range, which clears before count detach.
//! Each accepts sequential failed-reclaim frees only, publishing its exact
//! dynamic bitmap/count pair only after the source mostly-used boundary. The
//! direct-small partial collector retains its just-published head, so its
//! transition occurs one free later than the normal classes. Three bounded
//! post-TLS mapped two-block handoff operations remain separate from those
//! full routes: medium and non-direct small use their normal collector's
//! `UnownedMapped` then `Empty` transition, while direct small requires its
//! complete rounded cache image and keeps the first partial head atomic, so
//! observed `used` remains two until the final free. Each admits one sole
//! nonfull dynamic arena page only; it is not a general owner-exit traversal.
//! Five bounded homogeneous full aggregates also preserve `MI_ABANDON`
//! traversal only for
//! two-or-more source members with one sealed class/size/bin image: singleton
//! members take only raw empty failed-reclaim release; medium members
//! re-resolve their own dynamic bitmap/count capability after their later
//! low-owner claim; large members preserve their exact 64-slice arena span;
//! non-direct-small members retain the source ordinary `true`/`2` option
//! image, one ordinary bin, and no direct-cache state; and direct-small
//! members retain that same ordinary image plus their complete rounded
//! direct-cache queue-head range and partial-collector head lag. The latter
//! two are exercised only through a test fixture: production ordinary dynamic
//! attachments still seal the generic page-session boundary. None keeps a raw
//! page list or adds a general full-queue policy. Separately, one
//! full medium or large `BIN_FULL` page, or a full non-direct-small ordinary-
//! bin page with every direct slot empty, with exactly one joined remote free
//! becomes nonfull during source force collection and publishes its matching
//! dynamic bitmap/count pair immediately after queue detachment; each returned
//! handoff starts mapped and remains client-free-only, while large retains its
//! complete 64-slice terminal span. All general dynamic owner-exit traversal
//! remains outside this module.
//! It does implement the one
//! owner-only cached-Theap root/reference pair which follows regular-slot
//! publication in `src/heap.c:_mi_heap_theap_get_or_init`.

#[cfg(test)]
extern crate std;

use core::marker::PhantomData;
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::NonNull;

use crate::compiler_tls::{
    cached_theap, current_thread_identity, default_theap, fast_slot_peek, set_cached_theap,
};
use crate::arena::{
    ArenaView, DynamicArenaMappedAbandonedPage,
    DynamicArenaPagesOwner, DynamicArenaPagesOwnerCreateError,
    DynamicArenaPagesOwnerError,
};
use crate::bootstrap::{TheapPageSession, theap_page_session_sealed};
use crate::meta::{MetaAllocation, MetaAllocator, MetaError};
use crate::owned_tls_key_registry::{
    OwnedThreadLocalKeyError, OwnedThreadLocalKeyLease, OwnedThreadLocalKeyRegistry,
};
use crate::os::MemoryConfig;
use crate::os_page::OsAlignedPageOwner;
use crate::subproc::MainSubprocess;
use crate::thread_local::{ThreadLocalBackingError, ThreadLocalBackingOwner, ThreadLocalKey};
use crate::tld::{DynamicAttachedThreadLocalData, ThreadLocalDataError, ThreadLocalDataOwner};
use crate::types::{
    DynamicTheapPageMode, Heap, HeapOsAbandonedPageListError, MemoryId, Page, PageQueue,
    Theap, TheapDynamicInitError, TheapOwner, ThreadLocalTheapListError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicAttachmentState {
    Preparing,
    Attached,
    /// The source regular TLS slot is cleared, so an abandoned-page free can
    /// no longer reclaim this Theap. The page-map/arena/Theap/TLD ownership
    /// stays live until the dedicated page-drain owner has released or
    /// retained every page, after which ordinary attachment teardown resumes.
    DrainingPages,
    AwaitingKeyRelease,
    TornDown,
    Poisoned,
}

/// One current-thread dynamic attachment failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicTheapError {
    InvalidCurrentThread,
    HeapBinding,
    FirstTicketReserved,
    ThreadLocalData(ThreadLocalDataError),
    Key(OwnedThreadLocalKeyError),
    Backing(ThreadLocalBackingError),
    TheapMetadata(MetaError),
    TheapProjection,
    TheapInit(TheapDynamicInitError),
    RootOwnership,
    CachedReference,
    SlotOwnership,
    ListOwnership,
    PageCountNonZero,
    ArenaPages(DynamicArenaPagesOwnerError),
    TheapList(ThreadLocalTheapListError),
    TheapClear,
    HeapRetire,
    TornDown,
    Poisoned,
}

/// A non-mutating refusal to borrow a dynamic attachment as the shared
/// production non-abandoning page engine's Theap session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicTheapPageSessionError {
    Attachment(DynamicTheapError),
    AbandoningMode,
}

/// A dynamic begin either rejects after complete pre-publication cleanup or
/// returns the concrete retained owner for a terminal/awaiting-release state.
///
/// A post-registration allocation/list/backing failure must not silently drop
/// a TLD registration, typed metadata capability, or regular-key lease. The
/// caller receives that owner to account for an invalid-owner state or retry
/// the one pre-mutation key-release lock failure; this slice intentionally
/// invents no rollback after Theap/list publication.
#[must_use = "a retained dynamic attachment error carries live ownership that must be handled explicitly"]
pub(crate) enum DynamicTheapBeginError<'heap> {
    Rejected(DynamicTheapError),
    Retained {
        error: DynamicTheapError,
        attachment: DynamicTheapAttachment<'heap>,
    },
}

/// The regular-key portion of one caller-owned dynamic Heap binding.
///
/// `slot_bound` is separate from the lease itself: it makes releasing a key
/// while any dynamic backing slot can still name it structurally impossible
/// through this owner.
struct DynamicHeapBinding {
    lease: OwnedThreadLocalKeyLease,
    slot_bound: bool,
}

impl DynamicHeapBinding {
    #[inline]
    const fn key(&self) -> ThreadLocalKey {
        self.lease.key()
    }

    #[inline]
    fn mark_slot_bound_after_publication(&mut self) {
        debug_assert!(!self.slot_bound);
        self.slot_bound = true;
    }

    #[inline]
    fn clear_slot_bound(&mut self) -> bool {
        if !self.slot_bound {
            return false;
        }
        self.slot_bound = false;
        true
    }

    #[inline]
    fn release_after_slot_clear(&mut self) -> Result<(), DynamicTheapError> {
        if self.slot_bound {
            return Err(DynamicTheapError::SlotOwnership);
        }
        self.lease.release().map_err(DynamicTheapError::Key)
    }
}

#[derive(Clone, Copy)]
struct UnrelatedRoots {
    default: NonNull<Theap>,
    fast: Option<NonNull<()>>,
    cached: NonNull<Theap>,
}

impl UnrelatedRoots {
    #[inline]
    fn capture() -> Self {
        Self {
            default: default_theap(),
            fast: fast_slot_peek(),
            cached: cached_theap(),
        }
    }

    #[inline]
    fn still_matches(self) -> bool {
        core::ptr::eq(default_theap().as_ptr(), self.default.as_ptr())
            && fast_slot_peek() == self.fast
            && core::ptr::eq(cached_theap().as_ptr(), self.cached.as_ptr())
    }

    /// The caller may not adopt an arbitrary cached predecessor. This narrow
    /// slice begins only from the canonical empty source Theap, whose static
    /// reference needs no paired metadata transition.
    #[inline]
    fn cached_is_canonical_empty(self) -> bool {
        core::ptr::eq(
            self.cached.as_ptr(),
            crate::bootstrap::empty_default_theap() as *const Theap,
        )
    }

    /// Default and fast remain unrelated roots throughout this dynamic
    /// attachment. Cached changes are instead validated as this owner's
    /// explicit store/refcount pair.
    #[inline]
    fn default_and_fast_still_match(self) -> bool {
        core::ptr::eq(default_theap().as_ptr(), self.default.as_ptr())
            && fast_slot_peek() == self.fast
    }
}

/// The exact private owner of one current-thread regular-key Theap.
///
/// The caller's `Pin<&mut Heap>` proves the heap address stays stable while
/// the intrusive Theap lists contain it. The key lease, backing, TLD
/// registration/allocation, and Theap allocation are all retained as fields.
/// The raw marker makes this owner `!Send` and `!Sync`; every live operation
/// also rechecks the captured AArch64 `TPIDR_EL0` identity.
#[must_use = "a dynamic Theap attachment must explicitly tear down or remain terminally retained"]
pub(crate) struct DynamicTheapAttachment<'heap> {
    heap: Pin<&'heap mut Heap>,
    binding: Option<DynamicHeapBinding>,
    backing: Option<ThreadLocalBackingOwner>,
    tld: Option<DynamicAttachedThreadLocalData>,
    theap: Option<MetaAllocation<'static>>,
    roots: UnrelatedRoots,
    cached_root_bound: bool,
    page_mode: DynamicTheapPageMode,
    terminal_os_release: Option<OsAlignedPageOwner>,
    arena_pages: Option<DynamicArenaPagesOwner>,
    thread: crate::types::LiveThreadId,
    state: DynamicAttachmentState,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl<'heap> DynamicTheapAttachment<'heap> {
    /// Begins one later-ticket dynamic Theap binding using the process-global
    /// regular-key registry and metadata owner.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own this exact current thread's allocator
    /// lifecycle and process-selection decision. `heap` must be the unique,
    /// address-stable `Heap::bootstrap_empty()` caller image with no aliases,
    /// private-lock guards/waiters, pages, or prior binding. The caller must
    /// not create a second TLD/backing owner, mutate compiler-TLS roots, move
    /// this `!Send` owner to another thread, or release the regular key outside
    /// this capability. It must drive a returned attachment through successful
    /// teardown before allowing it to drop or reusing `heap`. A retained
    /// terminal owner that cannot finish teardown must stay alive (or be
    /// deliberately leaked) for as long as its thread/TLS/process state and
    /// heap storage can be observed; dropping it must not manufacture cleanup.
    /// Ticket zero is explicitly reserved for `MainStaticTheapAttachment`;
    /// this method returns `FirstTicketReserved` without consuming it.
    pub(crate) unsafe fn begin(
        config: MemoryConfig,
        heap: Pin<&'heap mut Heap>,
    ) -> Result<Self, DynamicTheapBeginError<'heap>> {
        // SAFETY: the process-global identity/capabilities have process
        // lifetime, and the caller upholds the documented current-thread
        // ownership condition.
        unsafe {
            Self::begin_with_components_mode(
                config,
                heap,
                MainSubprocess::global(),
                MetaAllocator::global(),
                OwnedThreadLocalKeyRegistry::global(),
                DynamicTheapPageMode::OrdinaryAbandoning,
            )
        }
    }

    /// Begins the one private production-shaped dynamic attachment whose
    /// Theap option image disables abandonment before its Release heap
    /// publication. This is the only dynamic mode that can borrow the shared
    /// bounded page engine; callers may never toggle an already live Theap.
    ///
    /// # Safety
    ///
    /// The caller upholds every [`Self::begin`] ownership and current-thread
    /// obligation, and additionally retains the returned attachment until a
    /// page engine has either consumed `finish` successfully or latched a
    /// terminal retained owner. This is crate-private integration structure,
    /// not a public first-class heap constructor.
    pub(crate) unsafe fn begin_non_abandoning(
        config: MemoryConfig,
        heap: Pin<&'heap mut Heap>,
    ) -> Result<Self, DynamicTheapBeginError<'heap>> {
        // SAFETY: as `begin`, with the source-reachable non-abandoning option
        // selected before `_mi_theap_init` publishes `heap`.
        unsafe {
            Self::begin_with_components_mode(
                config,
                heap,
                MainSubprocess::global(),
                MetaAllocator::global(),
                OwnedThreadLocalKeyRegistry::global(),
                DynamicTheapPageMode::NonAbandoningPageSession,
            )
        }
    }

    /// Builds the same private owner over explicit process-lived components.
    /// This supports isolated lifecycle tests without creating a second public
    /// attachment API.
    ///
    /// # Safety
    ///
    /// The obligations are identical to [`Self::begin`], and all components
    /// must name the same selected main-subprocess identity.
    unsafe fn begin_with_components(
        config: MemoryConfig,
        heap: Pin<&'heap mut Heap>,
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        registry: &'static OwnedThreadLocalKeyRegistry,
    ) -> Result<Self, DynamicTheapBeginError<'heap>> {
        unsafe {
            Self::begin_with_components_mode(
                config,
                heap,
                subprocess,
                metadata,
                registry,
                DynamicTheapPageMode::OrdinaryAbandoning,
            )
        }
    }

    /// Test-capable private entry for the one non-abandoning page-session
    /// owner. The selection is made before `_mi_theap_init` publishes its
    /// heap pointer; callers may never toggle a live Theap.
    #[cfg(test)]
    pub(crate) unsafe fn begin_non_abandoning_with_components(
        config: MemoryConfig,
        heap: Pin<&'heap mut Heap>,
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        registry: &'static OwnedThreadLocalKeyRegistry,
    ) -> Result<Self, DynamicTheapBeginError<'heap>> {
        unsafe {
            Self::begin_with_components_mode(
                config,
                heap,
                subprocess,
                metadata,
                registry,
                DynamicTheapPageMode::NonAbandoningPageSession,
            )
        }
    }

    unsafe fn begin_with_components_mode(
        config: MemoryConfig,
        heap: Pin<&'heap mut Heap>,
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        registry: &'static OwnedThreadLocalKeyRegistry,
        page_mode: DynamicTheapPageMode,
    ) -> Result<Self, DynamicTheapBeginError<'heap>> {
        let thread = current_thread_identity()
            .ok_or(DynamicTheapBeginError::Rejected(DynamicTheapError::InvalidCurrentThread))?;
        let roots = UnrelatedRoots::capture();
        // Source `_mi_heap_theap_get_or_init` may replace the cached root only
        // after a regular slot exists. This bounded owner intentionally has no
        // generic predecessor/ref API, so a foreign—even empty-looking—root is
        // rejected before the later-ticket TLD sequence or metadata backing
        // can be consumed.
        if !roots.cached_is_canonical_empty() {
            return Err(DynamicTheapBeginError::Rejected(
                DynamicTheapError::RootOwnership,
            ));
        }
        let tld = match unsafe {
            ThreadLocalDataOwner::begin_later_dynamic_attachment_with_metadata(
                subprocess, metadata, config,
            )
        } {
            Ok(tld) => tld,
            Err(ThreadLocalDataError::FirstTicketReserved) => {
                return Err(DynamicTheapBeginError::Rejected(
                    DynamicTheapError::FirstTicketReserved,
                ));
            }
            Err(error) => {
                return Err(DynamicTheapBeginError::Rejected(
                    DynamicTheapError::ThreadLocalData(error),
                ));
            }
        };
        let mut attachment = Self {
            heap,
            binding: None,
            backing: None,
            tld: Some(tld),
            theap: None,
            roots,
            cached_root_bound: false,
            page_mode,
            terminal_os_release: None,
            arena_pages: None,
            thread,
            state: DynamicAttachmentState::Preparing,
            _not_send_or_sync: PhantomData,
        };

        let backing = match unsafe {
            ThreadLocalBackingOwner::begin_with_metadata(metadata, subprocess, config)
        } {
            Ok(backing) => backing,
            Err(error) => {
                return match attachment.cancel_before_heap_binding() {
                    Ok(()) => Err(DynamicTheapBeginError::Rejected(
                        DynamicTheapError::Backing(error),
                    )),
                    Err(cleanup) => Err(attachment.into_retained_begin_failure(cleanup)),
                };
            }
        };
        attachment.backing = Some(backing);

        let lease = match registry.claim_for_main_subprocess(config, subprocess, metadata) {
            Ok(lease) => lease,
            Err(error) => {
                return match attachment.cancel_before_heap_binding() {
                    Ok(()) => Err(DynamicTheapBeginError::Rejected(DynamicTheapError::Key(error))),
                    Err(cleanup) => Err(attachment.into_retained_begin_failure(cleanup)),
                };
            }
        };
        let key = lease.key();
        attachment.binding = Some(DynamicHeapBinding {
            lease,
            slot_bound: false,
        });
        let heap_initialized = {
            let heap = attachment.heap_mut();
            // SAFETY: the outer unsafe constructor carries the unique pristine
            // caller-heap image proof required by this narrow initializer.
            unsafe { heap.initialize_dynamic_binding(subprocess, key.raw() as usize) }
        };
        if !heap_initialized {
            return Err(attachment.into_retained_begin_failure(DynamicTheapError::HeapBinding));
        }

        let allocation = match metadata.zalloc_for_main_subprocess(config, subprocess, size_of::<Theap>()) {
            Ok(allocation) => allocation,
            Err(error) => {
                return match attachment.cancel_before_theap_publication() {
                    Ok(()) => Err(DynamicTheapBeginError::Rejected(
                        DynamicTheapError::TheapMetadata(error),
                    )),
                    Err(cleanup) => Err(attachment.into_retained_begin_failure(cleanup)),
                };
            }
        };
        attachment.theap = Some(allocation);
        let initialized = attachment.initialize_and_publish_theap();
        match initialized {
            Ok(()) => {
                attachment.state = DynamicAttachmentState::Attached;
                Ok(attachment)
            }
            Err(error) => Err(attachment.into_retained_begin_failure(error)),
        }
    }

    /// Returns the bound regular key while the attachment retains its lease.
    #[inline]
    pub(crate) fn key(&self) -> Result<ThreadLocalKey, DynamicTheapError> {
        self.ensure_attached_current()?;
        self.binding
            .as_ref()
            .map(DynamicHeapBinding::key)
            .ok_or(DynamicTheapError::Poisoned)
    }

    /// Borrows this exact attachment as one non-abandoning page lifecycle.
    ///
    /// The returned session holds `&mut self`, so safe code cannot clear the
    /// regular key/backing, cached root/ref, intrusive lists, typed metadata,
    /// or caller-pinned Heap while the shared allocation engine (or its
    /// scoped remote producer) exists.
    pub(crate) fn page_session(
        &mut self,
    ) -> Result<DynamicTheapPageSession<'_, 'heap>, DynamicTheapPageSessionError> {
        DynamicTheapPageSession::begin(self)
    }

    /// Creates the source-default dynamic page owner only for a focused
    /// thread-exit fixture. Production ordinary dynamic attachments continue
    /// to reject [`Self::page_session`]: this test-only seam proves the
    /// `allow_page_abandon=true` / `page_full_retain=2` queue image that
    /// `mi_thread_theaps_done` receives, without exposing a general ordinary
    /// dynamic allocation API.
    #[cfg(test)]
    pub(crate) fn page_session_for_ordinary_thread_exit_fixture(
        &mut self,
    ) -> Result<DynamicTheapPageSession<'_, 'heap>, DynamicTheapPageSessionError> {
        DynamicTheapPageSession::begin_ordinary_thread_exit_fixture(self)
    }

    /// Lazily forms the one non-main source `mi_arena_pages_t` image selected
    /// by this dynamic Heap and arena. A metadata-allocation failure occurs
    /// before publication and leaves the attached owner retryable; any typed
    /// image or Heap-slot failure retains the exact allocation and terminally
    /// poisons this attachment rather than falling back to `pages_main`.
    fn ensure_dynamic_arena_pages(
        &mut self,
        arena: &ArenaView<'_>,
        config: MemoryConfig,
    ) -> Result<(), DynamicTheapError> {
        self.ensure_attached_current()?;
        if let Some(owner) = self.arena_pages.as_ref() {
            return if owner.is_for_arena(arena) && owner.is_published_for(self.heap.as_ref().get_ref()) {
                Ok(())
            } else {
                Err(self.poison(DynamicTheapError::ArenaPages(
                    DynamicArenaPagesOwnerError::ForeignArena,
                )))
            };
        }
        let (metadata, subprocess) = match self.tld.as_ref() {
            Some(tld) => (tld.metadata(), tld.subprocess()),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        let mut owner = match DynamicArenaPagesOwner::create(
            metadata,
            config,
            subprocess,
            self.heap.as_ref().get_ref(),
            arena,
        ) {
            Ok(owner) => owner,
            Err(DynamicArenaPagesOwnerCreateError::Error(error)) => {
                return Err(DynamicTheapError::ArenaPages(error));
            }
            Err(DynamicArenaPagesOwnerCreateError::Retained(owner)) => {
                self.arena_pages = Some(owner);
                return Err(self.poison(DynamicTheapError::ArenaPages(
                    DynamicArenaPagesOwnerError::Image,
                )));
            }
        };
        if let Err(error) = owner.publish(self.heap.as_ref().get_ref()) {
            self.arena_pages = Some(owner);
            return Err(self.poison(DynamicTheapError::ArenaPages(error)));
        }
        self.arena_pages = Some(owner);
        Ok(())
    }

    fn set_dynamic_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        if self.ensure_attached_current().is_err() {
            return false;
        }
        let Some(owner) = self.arena_pages.as_ref() else {
            self.state = DynamicAttachmentState::Poisoned;
            return false;
        };
        if !owner.is_for_arena(arena) || !owner.set_page(memory) {
            self.state = DynamicAttachmentState::Poisoned;
            return false;
        }
        true
    }

    fn clear_dynamic_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        if self.ensure_attached_current().is_err() {
            return false;
        }
        let Some(owner) = self.arena_pages.as_ref() else {
            self.state = DynamicAttachmentState::Poisoned;
            return false;
        };
        if !owner.is_for_arena(arena) || !owner.clear_page(memory) {
            self.state = DynamicAttachmentState::Poisoned;
            return false;
        }
        true
    }

    /// Clears one exact dynamic ordinary-page bit while the regular TLS slot
    /// has already been removed for thread exit. The page-drain owner retains
    /// the same Heap-local arena-pages image; using the normal attached-path
    /// helper here would incorrectly require a still-live reclaim slot.
    fn clear_dynamic_arena_page_during_drain(
        &mut self,
        arena: &ArenaView<'_>,
        memory: MemoryId,
    ) -> bool {
        if self.ensure_draining_current().is_err() {
            return false;
        }
        let Some(owner) = self.arena_pages.as_ref() else {
            self.state = DynamicAttachmentState::Poisoned;
            return false;
        };
        if !owner.is_for_arena(arena) || !owner.clear_page(memory) {
            self.state = DynamicAttachmentState::Poisoned;
            return false;
        }
        true
    }

    /// Clears the dynamic regular TLS backing before thread-exit page
    /// abandonment, matching `_mi_thread_locals_thread_done` before
    /// `mi_thread_theaps_done`. The resulting [`DynamicAttachmentState::DrainingPages`]
    /// retains the page map, arena image, Theap, Heap, and TLD until a narrow
    /// page-drain owner has accounted for every page.
    fn begin_page_drain(&mut self) -> Result<(), DynamicTheapError> {
        self.prevalidate_attached_page_drain(false)?;
        let key = self.binding()?.key();
        let clear_slot = {
            let backing = self.backing.as_mut().ok_or(DynamicTheapError::Poisoned)?;
            backing.set(key, core::ptr::null_mut())
        };
        if let Err(error) = clear_slot {
            return Err(self.poison(DynamicTheapError::Backing(error)));
        }
        let slot_cleared = match self.binding.as_mut() {
            Some(binding) => binding.clear_slot_bound(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if !slot_cleared {
            return Err(self.poison(DynamicTheapError::SlotOwnership));
        }
        let backing_teardown = match self.backing.as_mut() {
            Some(backing) => backing.teardown(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = backing_teardown {
            return Err(self.poison(DynamicTheapError::Backing(error)));
        }
        self.backing = None;
        self.state = DynamicAttachmentState::DrainingPages;
        Ok(())
    }

    /// Performs the bounded no-page teardown sequence. A direct no-page
    /// teardown enters and completes the same page-drain state in one call;
    /// a previously returned drain owner completes it only after its exact
    /// abandoned pages have been released or deliberately retained.
    pub(crate) fn teardown(&mut self) -> Result<(), DynamicTheapError> {
        if self.state == DynamicAttachmentState::AwaitingKeyRelease {
            return self.finish_key_release();
        }
        match self.state {
            DynamicAttachmentState::Attached => {
                self.prevalidate_attached_page_drain(true)?;
                self.begin_page_drain()?;
            }
            DynamicAttachmentState::DrainingPages => self.prevalidate_draining_page_teardown()?,
            DynamicAttachmentState::TornDown => return Err(DynamicTheapError::TornDown),
            DynamicAttachmentState::Preparing | DynamicAttachmentState::Poisoned => {
                return Err(DynamicTheapError::Poisoned);
            }
            DynamicAttachmentState::AwaitingKeyRelease => unreachable!(),
        }
        let theap_pointer = self.theap_pointer()?;
        self.complete_page_drain_teardown(theap_pointer)
    }

    /// Completes the part of `mi_thread_theaps_done` that follows successful
    /// page drain: restore the cached root, detach the exact Theap from the
    /// Heap and TLD lists, then release typed metadata and the key lease.
    fn complete_page_drain_teardown(
        &mut self,
        theap_pointer: *mut Theap,
    ) -> Result<(), DynamicTheapError> {
        if let Err(error) = self.restore_empty_cached_root_and_release(theap_pointer) {
            return Err(self.poison(error));
        }

        let detach_heap = match self.heap_and_tld_mut() {
            Ok((heap, tld)) => tld.detach_one_theap_from_heap(heap, theap_pointer),
            Err(error) => return Err(self.poison(error)),
        };
        if let Err(error) = detach_heap {
            return Err(self.poison(DynamicTheapError::TheapList(error)));
        }
        let detach_tld = match self.tld.as_mut() {
            Some(tld) => match tld.current_mut() {
                Ok(tld) => tld.detach_one_theap_from_tld(theap_pointer),
                Err(error) => return Err(self.poison(DynamicTheapError::ThreadLocalData(error))),
            },
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = detach_tld {
            return Err(self.poison(DynamicTheapError::TheapList(error)));
        }
        let clear_theap = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .map(Theap::clear_dynamic_metadata_after_detach);
        match clear_theap {
            Some(true) => {}
            Some(false) => return Err(self.poison(DynamicTheapError::TheapClear)),
            None => return Err(self.poison(DynamicTheapError::TheapProjection)),
        }
        if let Some(owner) = self.arena_pages.as_mut() {
            if let Err(error) = owner.unpublish_and_free(self.heap.as_ref().get_ref()) {
                return Err(self.poison(DynamicTheapError::ArenaPages(error)));
            }
        }
        self.arena_pages = None;
        let mut theap = match self.theap.take() {
            Some(theap) => theap,
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        let metadata = match self.tld.as_ref() {
            Some(tld) => tld.metadata(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = metadata.free(&mut theap) {
            return Err(self.poison(DynamicTheapError::TheapMetadata(error)));
        }

        let tld_teardown = match self.tld.as_mut() {
            Some(tld) => tld.teardown_after_theap_detached(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = tld_teardown {
            return Err(self.poison(DynamicTheapError::ThreadLocalData(error)));
        }
        self.tld = None;
        let heap_retired = {
            let heap = self.heap_mut();
            // SAFETY: both lists are detached and the owner has exclusive
            // caller-storage authority through the held Pin.
            unsafe { heap.retire_dynamic_binding_after_detach() }
        };
        if !heap_retired {
            return Err(self.poison(DynamicTheapError::HeapRetire));
        }
        self.state = DynamicAttachmentState::AwaitingKeyRelease;
        self.finish_key_release()
    }

    fn initialize_and_publish_theap(&mut self) -> Result<(), DynamicTheapError> {
        let key = self.binding()?.key();
        let page_mode = self.page_mode;
        let theap_pointer = {
            let (heap, tld, allocation) = self.heap_tld_theap_mut()?;
            let theap = allocation
                .initialize_dynamic_theap_metadata()
                .ok_or(DynamicTheapError::TheapProjection)?;
            // SAFETY: this attachment retains the caller's pinned Heap, the
            // exact metadata TLD capability, and the Theap allocation through
            // both list lifetimes; its `!Send`/TPIDR proof excludes a second
            // thread or list mutator until source-ordered detachment.
            unsafe { theap.initialize_dynamic_metadata(heap, tld, page_mode) }
                .map_err(DynamicTheapError::TheapInit)?;
            core::ptr::from_mut(theap).cast::<()>()
        };
        let published = match self.backing.as_mut() {
            Some(backing) => backing.set(key, theap_pointer),
            None => return Err(DynamicTheapError::Poisoned),
        };
        if let Err(error) = published {
            return Err(DynamicTheapError::Backing(error));
        }
        // This is infallible by construction: it records only the successful
        // source publication immediately above, so no retained owner can
        // carry a live regular slot while claiming it is unbound.
        self.binding
            .as_mut()
            .expect("a successful regular-slot publication retains its key binding")
            .mark_slot_bound_after_publication();
        let cached_theap = NonNull::new(theap_pointer.cast::<Theap>())
            .ok_or(DynamicTheapError::TheapProjection)?;
        self.publish_cached_root(cached_theap)?;
        Ok(())
    }

    /// Validates the still-attached source ownership required before the
    /// regular TLS slot is cleared. `require_empty` is true for direct
    /// teardown and false for the intermediate thread-exit page-drain state.
    fn prevalidate_attached_page_drain(
        &mut self,
        require_empty: bool,
    ) -> Result<(), DynamicTheapError> {
        self.ensure_attached_current()?;
        if !self.roots.default_and_fast_still_match() {
            return Err(DynamicTheapError::RootOwnership);
        }
        let key = self.binding()?.key();
        if !self.binding()?.slot_bound {
            return Err(DynamicTheapError::SlotOwnership);
        }
        let theap_pointer = self.theap_pointer()?;
        let subprocess = self
            .tld
            .as_ref()
            .ok_or(DynamicTheapError::Poisoned)?
            .subprocess();
        let (page_count, refcount, matches_thread, bound_to_subprocess) = {
            let theap = self
                .theap
                .as_mut()
                .and_then(MetaAllocation::dynamic_theap_mut)
                .ok_or(DynamicTheapError::TheapProjection)?;
            (
                theap.page_count(),
                theap.refcount(),
                theap.matches_thread(self.thread),
                theap.is_bound_to_main_subprocess(subprocess),
            )
        };
        if require_empty && page_count != 0 {
            return Err(DynamicTheapError::PageCountNonZero);
        }
        if require_empty {
            if let Some(owner) = self.arena_pages.as_ref() {
                if !owner.is_published_for(self.heap.as_ref().get_ref())
                    || !owner.is_empty_published()
                {
                    return Err(DynamicTheapError::ArenaPages(
                        DynamicArenaPagesOwnerError::NonEmpty,
                    ));
                }
            }
        }
        if !self.cached_root_bound || !core::ptr::eq(cached_theap().as_ptr(), theap_pointer) {
            return Err(DynamicTheapError::RootOwnership);
        }
        if refcount != 2 {
            return Err(DynamicTheapError::CachedReference);
        }
        let tld_member = match self.tld.as_mut() {
            Some(tld) => tld
                .current_mut()
                .map_err(DynamicTheapError::ThreadLocalData)?
                .has_exact_theap_member(theap_pointer),
            None => return Err(DynamicTheapError::Poisoned),
        };
        let heap = self.heap.as_ref().get_ref();
        if !matches_thread
            || !bound_to_subprocess
            || !tld_member
            || !heap.has_exact_theap_member(theap_pointer)
            || !heap.matches_dynamic_binding(
                subprocess,
                key.raw() as usize,
            )
        {
            return Err(DynamicTheapError::ListOwnership);
        }
        let value = self
            .backing
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .get(key)
            .map_err(DynamicTheapError::Backing)?;
        if value != theap_pointer.cast() {
            return Err(DynamicTheapError::SlotOwnership);
        }
        Ok(())
    }

    /// Validates the post-TLS, pre-list-detach side of the source thread-exit
    /// sequence. No dynamic regular backing may remain, while the cached
    /// root and both intrusive list memberships still retain the exact Theap
    /// until every page has drained.
    fn prevalidate_draining_page_teardown(&mut self) -> Result<(), DynamicTheapError> {
        self.ensure_draining_current()?;
        if !self.roots.default_and_fast_still_match() {
            return Err(DynamicTheapError::RootOwnership);
        }
        let key = self.binding()?.key();
        if self.binding()?.slot_bound || self.backing.is_some() {
            return Err(DynamicTheapError::SlotOwnership);
        }
        let theap_pointer = self.theap_pointer()?;
        let subprocess = self
            .tld
            .as_ref()
            .ok_or(DynamicTheapError::Poisoned)?
            .subprocess();
        let (page_count, refcount, matches_thread, bound_to_subprocess) = {
            let theap = self
                .theap
                .as_mut()
                .and_then(MetaAllocation::dynamic_theap_mut)
                .ok_or(DynamicTheapError::TheapProjection)?;
            (
                theap.page_count(),
                theap.refcount(),
                theap.matches_thread(self.thread),
                theap.is_bound_to_main_subprocess(subprocess),
            )
        };
        if page_count != 0 {
            return Err(DynamicTheapError::PageCountNonZero);
        }
        if let Some(owner) = self.arena_pages.as_ref() {
            if !owner.is_published_for(self.heap.as_ref().get_ref())
                || !owner.is_empty_published()
            {
                return Err(DynamicTheapError::ArenaPages(
                    DynamicArenaPagesOwnerError::NonEmpty,
                ));
            }
        }
        if !self.cached_root_bound || !core::ptr::eq(cached_theap().as_ptr(), theap_pointer) {
            return Err(DynamicTheapError::RootOwnership);
        }
        if refcount != 2 {
            return Err(DynamicTheapError::CachedReference);
        }
        let tld_member = match self.tld.as_mut() {
            Some(tld) => tld
                .current_mut()
                .map_err(DynamicTheapError::ThreadLocalData)?
                .has_exact_theap_member(theap_pointer),
            None => return Err(DynamicTheapError::Poisoned),
        };
        let heap = self.heap.as_ref().get_ref();
        if !matches_thread
            || !bound_to_subprocess
            || !tld_member
            || !heap.has_exact_theap_member(theap_pointer)
            || !heap.matches_dynamic_binding(
                subprocess,
                key.raw() as usize,
            )
        {
            return Err(DynamicTheapError::ListOwnership);
        }
        Ok(())
    }

    /// Stores this dynamically allocated Theap in the cached compiler-TLS
    /// root and then acquires its owner-only reference, exactly as
    /// `_mi_theap_cached_set` does. The only supported previous root is the
    /// canonical empty source image captured before ticket issuance.
    fn publish_cached_root(&mut self, theap: NonNull<Theap>) -> Result<(), DynamicTheapError> {
        if self.cached_root_bound
            || !self.roots.cached_is_canonical_empty()
            || !core::ptr::eq(cached_theap().as_ptr(), self.roots.cached.as_ptr())
        {
            return Err(DynamicTheapError::RootOwnership);
        }
        let theap_image = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .ok_or(DynamicTheapError::TheapProjection)?;
        if !core::ptr::eq(core::ptr::from_mut(theap_image), theap.as_ptr()) {
            return Err(DynamicTheapError::TheapProjection);
        }

        // `_mi_theap_cached_set` stores the pointer before changing either
        // reference count. The empty static predecessor has source no-free
        // provenance, so its corresponding decrement is intentionally a no-op.
        set_cached_theap(theap);
        // This records pointer-root ownership, not a successful reference
        // transition. A failed 1 -> 2 CAS has already left the raw root
        // pointing at this retained terminal image and must never be described
        // as an unbound cached root.
        self.cached_root_bound = true;
        if !theap_image.acquire_dynamic_cached_reference() {
            return Err(DynamicTheapError::CachedReference);
        }
        Ok(())
    }

    /// Restores exactly the canonical empty cached root and releases this
    /// attachment's paired cached reference. It runs after regular backing
    /// teardown but before either source list detach, matching
    /// `_mi_thread_locals_thread_done` followed by `mi_thread_theaps_done`.
    fn restore_empty_cached_root_and_release(
        &mut self,
        theap_pointer: *mut Theap,
    ) -> Result<(), DynamicTheapError> {
        if !self.cached_root_bound
            || !self.roots.cached_is_canonical_empty()
            || !core::ptr::eq(cached_theap().as_ptr(), theap_pointer)
        {
            return Err(DynamicTheapError::RootOwnership);
        }
        let theap = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .ok_or(DynamicTheapError::TheapProjection)?;
        if !core::ptr::eq(core::ptr::from_mut(theap), theap_pointer) {
            return Err(DynamicTheapError::TheapProjection);
        }

        // This is the source cached-set store first, followed by the exact
        // dynamic 2 -> 1 reference release. The static empty predecessor is
        // never dynamically referenced by this owner.
        set_cached_theap(self.roots.cached);
        // As above, this tracks the raw pointer root. If the post-store CAS
        // fails, the terminal attachment retains a detached cached reference,
        // not a cached pointer to itself.
        self.cached_root_bound = false;
        if !theap.release_dynamic_cached_reference() {
            return Err(DynamicTheapError::CachedReference);
        }
        Ok(())
    }

    fn cancel_before_theap_publication(&mut self) -> Result<(), DynamicTheapError> {
        if let Some(backing) = self.backing.as_mut() {
            backing.teardown().map_err(DynamicTheapError::Backing)?;
        }
        self.backing = None;
        let retired = {
            let heap = self.heap_mut();
            // SAFETY: no Theap/list entry has been published on this path.
            unsafe { heap.retire_dynamic_binding_after_detach() }
        };
        if !retired {
            return Err(DynamicTheapError::HeapRetire);
        }
        self.tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .teardown_after_theap_detached()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        self.tld = None;
        self.state = DynamicAttachmentState::AwaitingKeyRelease;
        self.finish_key_release()
    }

    /// Cleans up the empty TLD/backing pair before any heap/key/Theap state
    /// exists. This is the recoverable path for a backing or regular-registry
    /// allocation failure after a later TLD ticket has activated its live
    /// registration: successful cleanup must not manufacture a retained live
    /// owner merely because its source sequence was consumed.
    fn cancel_before_heap_binding(&mut self) -> Result<(), DynamicTheapError> {
        if let Some(backing) = self.backing.as_mut() {
            backing.teardown().map_err(DynamicTheapError::Backing)?;
        }
        self.backing = None;
        self.tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .teardown_after_theap_detached()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        self.tld = None;
        Ok(())
    }

    fn into_retained_begin_failure(
        mut self,
        error: DynamicTheapError,
    ) -> DynamicTheapBeginError<'heap> {
        if self.state != DynamicAttachmentState::AwaitingKeyRelease {
            self.state = DynamicAttachmentState::Poisoned;
        }
        DynamicTheapBeginError::Retained {
            error,
            attachment: self,
        }
    }

    #[inline]
    fn poison(&mut self, error: DynamicTheapError) -> DynamicTheapError {
        self.state = DynamicAttachmentState::Poisoned;
        error
    }

    #[inline]
    fn ensure_attached_current(&self) -> Result<(), DynamicTheapError> {
        match self.state {
            DynamicAttachmentState::Attached => match current_thread_identity() {
                Some(thread) if thread == self.thread => Ok(()),
                Some(_) => Err(DynamicTheapError::InvalidCurrentThread),
                None => Err(DynamicTheapError::InvalidCurrentThread),
            },
            DynamicAttachmentState::TornDown => Err(DynamicTheapError::TornDown),
            DynamicAttachmentState::Preparing
            | DynamicAttachmentState::DrainingPages
            | DynamicAttachmentState::AwaitingKeyRelease
            | DynamicAttachmentState::Poisoned => {
                Err(DynamicTheapError::Poisoned)
            }
        }
    }

    #[inline]
    fn ensure_draining_current(&self) -> Result<(), DynamicTheapError> {
        match self.state {
            DynamicAttachmentState::DrainingPages => match current_thread_identity() {
                Some(thread) if thread == self.thread => Ok(()),
                Some(_) | None => Err(DynamicTheapError::InvalidCurrentThread),
            },
            DynamicAttachmentState::TornDown => Err(DynamicTheapError::TornDown),
            DynamicAttachmentState::Preparing
            | DynamicAttachmentState::Attached
            | DynamicAttachmentState::AwaitingKeyRelease
            | DynamicAttachmentState::Poisoned => Err(DynamicTheapError::Poisoned),
        }
    }

    /// Completes only the retained linear regular-key release after every
    /// backing/TLD/Theap/Heap capability has already been retired. A key-lock
    /// error is guaranteed by the lease API to be pre-mutation, so it keeps
    /// this exact owner in `AwaitingKeyRelease` for a later retry. Any other
    /// release failure terminalizes the owner rather than claiming a retry
    /// over ambiguous registry state.
    fn finish_key_release(&mut self) -> Result<(), DynamicTheapError> {
        match current_thread_identity() {
            Some(thread) if thread == self.thread => {}
            Some(_) | None => return Err(DynamicTheapError::InvalidCurrentThread),
        }
        let release = match self.binding.as_mut() {
            Some(binding) => binding.release_after_slot_clear(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        match release {
            Ok(()) => {
                self.binding = None;
                self.state = DynamicAttachmentState::TornDown;
                Ok(())
            }
            Err(error @ DynamicTheapError::Key(OwnedThreadLocalKeyError::Lock(_))) => Err(error),
            Err(error) => Err(self.poison(error)),
        }
    }

    #[inline]
    fn binding(&self) -> Result<&DynamicHeapBinding, DynamicTheapError> {
        self.binding.as_ref().ok_or(DynamicTheapError::Poisoned)
    }

    #[inline]
    fn heap_mut(&mut self) -> &mut Heap {
        // SAFETY: the attachment exclusively owns the caller's pinned mutable
        // heap borrow for its whole lifetime.
        unsafe { Pin::get_unchecked_mut(self.heap.as_mut()) }
    }

    fn heap_and_tld_mut(&mut self) -> Result<(&mut Heap, &mut crate::types::ThreadLocalData), DynamicTheapError> {
        let DynamicTheapAttachment { heap, tld, .. } = self;
        // SAFETY: this owner retains the sole pinned mutable heap borrow.
        let heap = unsafe { Pin::get_unchecked_mut(heap.as_mut()) };
        let tld = tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .current_mut()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        Ok((heap, tld))
    }

    fn heap_tld_theap_mut(
        &mut self,
    ) -> Result<
        (
            &mut Heap,
            &mut crate::types::ThreadLocalData,
            &mut MetaAllocation<'static>,
        ),
        DynamicTheapError,
    > {
        let DynamicTheapAttachment {
            heap, tld, theap, ..
        } = self;
        // SAFETY: this owner retains the sole pinned mutable heap borrow.
        let heap = unsafe { Pin::get_unchecked_mut(heap.as_mut()) };
        let tld = tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .current_mut()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        let theap = theap.as_mut().ok_or(DynamicTheapError::Poisoned)?;
        Ok((heap, tld, theap))
    }

    fn theap_pointer(&mut self) -> Result<*mut Theap, DynamicTheapError> {
        // The address is derived only from the retained typed dynamic-Theap
        // metadata capability. It is used as an intrusive-list witness while
        // that capability remains exclusively owned by this attachment; no
        // externally supplied pointer is dereferenced through this path.
        let theap = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .ok_or(DynamicTheapError::TheapProjection)?;
        Ok(core::ptr::from_mut(theap))
    }
}

/// One borrowed page-owner view of a private dynamic Theap attachment.
///
/// This is deliberately not a general heap API. Its constructor validates the
/// full attached/root/slot/list/refcount state and, through its production
/// constructor, accepts only the typed mode that disabled abandonment before
/// `_mi_theap_init` published `heap`. A separately documented `cfg(test)`
/// constructor admits the frozen ordinary source image only for thread-exit
/// fixture setup; it does not widen that production boundary.
pub(crate) struct DynamicTheapPageSession<'attach, 'heap> {
    attachment: &'attach mut DynamicTheapAttachment<'heap>,
}

impl<'attach, 'heap> DynamicTheapPageSession<'attach, 'heap> {
    fn begin(
        attachment: &'attach mut DynamicTheapAttachment<'heap>,
    ) -> Result<Self, DynamicTheapPageSessionError> {
        attachment
            .prevalidate_attached_page_drain(true)
            .map_err(DynamicTheapPageSessionError::Attachment)?;
        let theap = attachment
            .theap
            .as_ref()
            .and_then(MetaAllocation::dynamic_theap)
            .ok_or(DynamicTheapPageSessionError::Attachment(
                DynamicTheapError::TheapProjection,
            ))?;
        if attachment.page_mode != DynamicTheapPageMode::NonAbandoningPageSession
            || theap.allows_page_abandon()
            || theap.page_full_retain() != -1
        {
            return Err(DynamicTheapPageSessionError::AbandoningMode);
        }
        Ok(Self { attachment })
    }

    /// Admits only the frozen ordinary dynamic option image for focused
    /// `MI_ABANDON` fixture setup. Unlike [`Self::begin`], this is test-only:
    /// the public crate-private dynamic page session remains restricted to
    /// the non-abandoning `false`/`-1` image, while this exact source-default
    /// `true`/`2` image is necessary to retain full ordinary small pages for
    /// a later thread-exit traversal proof.
    #[cfg(test)]
    fn begin_ordinary_thread_exit_fixture(
        attachment: &'attach mut DynamicTheapAttachment<'heap>,
    ) -> Result<Self, DynamicTheapPageSessionError> {
        attachment
            .prevalidate_attached_page_drain(true)
            .map_err(DynamicTheapPageSessionError::Attachment)?;
        let theap = attachment
            .theap
            .as_ref()
            .and_then(MetaAllocation::dynamic_theap)
            .ok_or(DynamicTheapPageSessionError::Attachment(
                DynamicTheapError::TheapProjection,
            ))?;
        if attachment.page_mode != DynamicTheapPageMode::OrdinaryAbandoning
            || !theap.allows_page_abandon()
            || theap.page_full_retain() != 2
        {
            return Err(DynamicTheapPageSessionError::AbandoningMode);
        }
        Ok(Self { attachment })
    }

    #[inline]
    pub(crate) fn thread_sequence(&self) -> usize {
        self.attachment
            .tld
            .as_ref()
            .expect("a validated dynamic page session retains its TLD")
            .sequence()
            .get()
    }

    #[inline]
    fn dynamic_theap(&self) -> &Theap {
        self.attachment
            .theap
            .as_ref()
            .and_then(MetaAllocation::dynamic_theap)
            .expect("a validated borrowed dynamic page session retains its typed Theap")
    }

    #[inline]
    fn dynamic_theap_mut(&mut self) -> &mut Theap {
        self.attachment
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .expect("a validated borrowed dynamic page session retains its typed Theap")
    }

    /// Selects exactly one heap-local dynamic abandoned-map slot only while
    /// this borrowed session still proves its attached current-thread state.
    /// The returned capability cannot name a different Heap, arena, bin, or
    /// ordinary slice.
    pub(crate) fn mapped_abandoned_page(
        &self,
        arena: &ArenaView<'_>,
        bin: usize,
        memory: MemoryId,
    ) -> Option<DynamicArenaMappedAbandonedPage<'_>> {
        matches!(self.attachment.state, DynamicAttachmentState::Attached)
            .then(|| self.attachment.arena_pages.as_ref())
            .flatten()?
            .mapped_abandoned_page(arena, bin, memory)
    }

    /// Consumes this live page-session borrow into the source thread-exit
    /// page-drain state. The attachment clears its regular TLS backing first,
    /// so later abandoned frees cannot reclaim this Theap through its dynamic
    /// heap key. On error the caller retains this exact session/engine; a
    /// post-mutation error has already poisoned the attachment.
    pub(crate) fn begin_thread_exit_drain(
        self,
    ) -> Result<DynamicTheapPageDrainSession<'attach, 'heap>, (Self, DynamicTheapError)> {
        match self.attachment.begin_page_drain() {
            Ok(()) => Ok(DynamicTheapPageDrainSession {
                attachment: self.attachment,
            }),
            Err(error) => Err((self, error)),
        }
    }

    /// Test-only non-mutating view of the attachment's teardown preflight.
    /// It never invokes teardown, clears a root, or detaches a list while the
    /// session owns the attachment borrow.
    #[cfg(test)]
    pub(crate) fn test_teardown_preflight(&mut self) -> Result<(), DynamicTheapError> {
        self.attachment.prevalidate_attached_page_drain(true)
    }

    #[cfg(test)]
    pub(crate) fn test_arena_pages_image(
        &self,
        memory: MemoryId,
    ) -> Option<(NonNull<crate::types::ArenaPages>, crate::arena::ArenaPagesLayout, MemoryId, bool)> {
        let owner = self.attachment.arena_pages.as_ref()?;
        let (header, layout, image_memory) = owner.test_image()?;
        Some((header, layout, image_memory, owner.page_is_set(memory)))
    }

}

/// A post-TLS, pre-list-detach page owner used only by the bounded
/// thread-exit handoff. It deliberately has no public allocation interface:
/// it can force-collect existing retired pages and drain exact queue-detached
/// abandoned pages while retaining the dynamic Heap's arena-page image and
/// PageMap authority.
pub(crate) struct DynamicTheapPageDrainSession<'attach, 'heap> {
    attachment: &'attach mut DynamicTheapAttachment<'heap>,
}

impl<'attach, 'heap> DynamicTheapPageDrainSession<'attach, 'heap> {
    #[inline]
    fn dynamic_theap(&self) -> &Theap {
        self.attachment
            .theap
            .as_ref()
            .and_then(MetaAllocation::dynamic_theap)
            .expect("a draining dynamic page session retains its typed Theap")
    }

    #[inline]
    fn dynamic_theap_mut(&mut self) -> &mut Theap {
        self.attachment
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .expect("a draining dynamic page session retains its typed Theap")
    }

    /// Selects exactly one heap-local dynamic abandoned-map slot while this
    /// session proves the post-TLS, pre-teardown thread-exit state.
    ///
    /// This is intentionally separate from
    /// [`DynamicTheapPageSession::mapped_abandoned_page`]: the ordinary live
    /// session requires an attached regular TLS slot, while this drain exists
    /// only after source thread exit cleared that slot. It exposes no general
    /// reclaim or allocation capability; its caller still has to prove the
    /// exact live page, arena span, regular bin, queue-detach order, and final
    /// release lifecycle.
    pub(crate) fn mapped_abandoned_page_during_drain(
        &self,
        arena: &ArenaView<'_>,
        bin: usize,
        memory: MemoryId,
    ) -> Option<DynamicArenaMappedAbandonedPage<'_>> {
        self.attachment.ensure_draining_current().ok()?;
        self.attachment
            .arena_pages
            .as_ref()?
            .mapped_abandoned_page(arena, bin, memory)
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_regular_slot_is_clear(&self) -> bool {
        self.attachment.backing.is_none()
            && self
                .attachment
                .binding
                .as_ref()
                .is_some_and(|binding| !binding.slot_bound)
            && crate::compiler_tls::dynamic_backing_peek().is_none()
    }

    #[cfg(test)]
    pub(crate) fn test_cached_root_still_names_the_draining_theap(&self) -> bool {
        self.attachment.cached_root_bound
            && core::ptr::eq(
                cached_theap().as_ptr(),
                self.dynamic_theap() as *const Theap as *mut Theap,
            )
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_arena_page_is_clear(&self, memory: MemoryId) -> bool {
        self.attachment
            .arena_pages
            .as_ref()
            .is_some_and(|owner| !owner.page_is_set(memory))
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_dynamic_abandoned_page_is_clear(
        &self,
        bin: usize,
        memory: MemoryId,
    ) -> bool {
        self.attachment
            .arena_pages
            .as_ref()
            .is_some_and(|owner| owner.test_abandoned_page_is_clear(bin, memory))
    }

    /// Links one queue-detached OS-aligned singleton into this dynamic
    /// attachment's source Heap before common abandonment clears its low
    /// owner state.
    ///
    /// The page-drain session retains the unique pinned Heap borrow and the
    /// source Theap/TLD/page-map owner. Its caller has already proved that
    /// `page` is this Heap's live full singleton, so this narrow boundary
    /// delegates only the private intrusive-list mutation and its lock to
    /// [`Heap::push_os_abandoned_page`].
    ///
    /// # Safety
    ///
    /// `page` must be live dynamic metadata owned by this exact pinned Heap,
    /// with both intrusive OS-list links clear. The caller must retain that
    /// metadata through the paired removal or terminal retained owner.
    pub(crate) unsafe fn push_os_abandoned_singleton(
        &mut self,
        page: NonNull<Page>,
    ) -> Result<(), HeapOsAbandonedPageListError> {
        // SAFETY: the dynamic attachment retains this unique, address-stable
        // Heap borrow for the whole page-drain session. The caller's source
        // preflight retains the exact live page metadata until its terminal
        // handoff completes.
        let heap = unsafe { Pin::get_unchecked_mut(self.attachment.heap.as_mut()) };
        // SAFETY: forwarded from this method's dynamic page-drain ownership
        // proof; Heap serializes its private OS-list mutation internally.
        unsafe { heap.push_os_abandoned_page(&mut *page.as_ptr()) }
    }

    /// Proves that a bounded OS-singleton aggregate starts from the empty
    /// private list, without exposing the list as a general abandoned-page
    /// registry.
    pub(crate) fn os_abandoned_pages_are_empty(
        &self,
    ) -> Result<bool, HeapOsAbandonedPageListError> {
        self.attachment
            .heap
            .as_ref()
            .get_ref()
            .os_abandoned_pages_are_empty()
    }

    /// Removes one exact all-free OS-aligned singleton from this dynamic
    /// attachment's private Heap list before the terminal mapping release.
    ///
    /// The consuming owner-exit handoff retains the live metadata and has
    /// already claimed its sole final free. This method deliberately performs
    /// no traversal or reclamation beyond the source list removal.
    ///
    /// # Safety
    ///
    /// `page` must be the exact live member of this dynamic Heap's private
    /// OS-abandoned list, retained through the following terminal release.
    pub(crate) unsafe fn remove_os_abandoned_singleton(
        &mut self,
        page: NonNull<Page>,
    ) -> Result<(), HeapOsAbandonedPageListError> {
        // SAFETY: the attachment's pinned Heap and the exact live page remain
        // retained by the consuming page-drain handoff through this removal.
        let heap = unsafe { Pin::get_unchecked_mut(self.attachment.heap.as_mut()) };
        // SAFETY: forwarded from this method's all-free handoff proof; Heap
        // serializes its private OS-list mutation internally.
        unsafe { heap.remove_os_abandoned_page(&mut *page.as_ptr()) }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_os_abandoned_page_head(&self) -> *mut Page {
        // The dynamic fixture holds this attachment exclusively and creates
        // no concurrent OS-list mutation path while it observes a handoff.
        self.attachment
            .heap
            .as_ref()
            .get_ref()
            .test_os_abandoned_page_head()
    }
}

impl theap_page_session_sealed::Sealed for DynamicTheapPageSession<'_, '_> {}
impl theap_page_session_sealed::Sealed for DynamicTheapPageDrainSession<'_, '_> {}

// SAFETY: construction revalidates the exact attached current-thread
// TLD/Theap/Heap/list/root/refcount state while taking `&mut attachment`.
// That borrow retains the typed metadata, regular key/backing, cached ref,
// and pinned Heap for every engine/producers' raw page lifetime.
unsafe impl TheapPageSession for DynamicTheapPageSession<'_, '_> {
    #[inline]
    fn theap(&self) -> &Theap { self.dynamic_theap() }

    #[inline]
    fn thread_id(&self) -> Option<crate::types::LiveThreadId> {
        Some(self.attachment.thread)
    }

    #[inline]
    fn queue(&self, bin: usize) -> Option<&PageQueue> { self.dynamic_theap().queue(bin) }

    #[inline]
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        self.dynamic_theap_mut().queue_mut(bin)
    }

    #[inline]
    fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.dynamic_theap().direct_page(index)
    }

    #[inline]
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        self.dynamic_theap_mut().set_direct_page(index, page)
    }

    #[inline]
    fn note_page_added(&mut self) { self.dynamic_theap_mut().note_page_added() }

    #[inline]
    fn note_page_removed(&mut self) -> bool { self.dynamic_theap_mut().note_page_removed() }

    #[inline]
    fn ensure_arena_pages(&mut self, arena: &ArenaView<'_>, config: MemoryConfig) -> bool {
        self.attachment.ensure_dynamic_arena_pages(arena, config).is_ok()
    }

    #[inline]
    fn set_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        self.attachment.set_dynamic_arena_page(arena, memory)
    }

    #[inline]
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        self.attachment.clear_dynamic_arena_page(arena, memory)
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
        let DynamicTheapAttachment { heap, theap, .. } = self.attachment;
        // SAFETY: `DynamicTheapPageSession` retains the attachment's unique
        // pinned Heap borrow, and its constructor proved the typed Theap/list
        // binding. The returned engine keeps this borrow for the complete
        // page lifecycle.
        let heap = unsafe { Pin::get_unchecked_mut(heap.as_mut()) };
        let theap = theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)?;
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
    fn retired_bounds(&self) -> (usize, usize) { self.dynamic_theap().retired_bounds() }

    #[inline]
    fn note_retired_bin(&mut self, bin: usize) -> bool {
        self.dynamic_theap_mut().note_retired_bin(bin)
    }

    #[inline]
    fn reset_retired_bounds(&mut self) { self.dynamic_theap_mut().reset_retired_bounds() }

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
        self.attachment.state = DynamicAttachmentState::Poisoned;
    }
}

// SAFETY: `DynamicTheapPageDrainSession` is constructed only by consuming an
// attached dynamic page session after its regular TLS slot has been cleared.
// It retains the same pinned Heap, typed Theap/TLD metadata, exact queue
// records, PageMap borrow, and heap-local arena image, but is exposed only
// through the thread-exit drain wrapper in `single_thread.rs`. Its live thread
// identity remains available solely for the source false-force collection that
// precedes abandonment; no ordinary allocation entry point receives this
// session type.
unsafe impl TheapPageSession for DynamicTheapPageDrainSession<'_, '_> {
    #[inline]
    fn theap(&self) -> &Theap { self.dynamic_theap() }

    #[inline]
    fn thread_id(&self) -> Option<crate::types::LiveThreadId> {
        Some(self.attachment.thread)
    }

    #[inline]
    fn queue(&self, bin: usize) -> Option<&PageQueue> { self.dynamic_theap().queue(bin) }

    #[inline]
    fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        self.dynamic_theap_mut().queue_mut(bin)
    }

    #[inline]
    fn direct_page(&self, index: usize) -> Option<*mut Page> {
        self.dynamic_theap().direct_page(index)
    }

    #[inline]
    fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        self.dynamic_theap_mut().set_direct_page(index, page)
    }

    #[inline]
    fn note_page_added(&mut self) { self.dynamic_theap_mut().note_page_added() }

    #[inline]
    fn note_page_removed(&mut self) -> bool { self.dynamic_theap_mut().note_page_removed() }

    // Fresh publication during page drain would recreate a regular TLS owner
    // after source thread-local teardown. The thread-exit wrapper has no such
    // operation, and these defensive trait implementations refuse it.
    #[inline]
    fn ensure_arena_pages(&mut self, _arena: &ArenaView<'_>, _config: MemoryConfig) -> bool {
        false
    }

    #[inline]
    fn set_arena_page(&mut self, _arena: &ArenaView<'_>, _memory: MemoryId) -> bool { false }

    #[inline]
    fn clear_arena_page(&mut self, arena: &ArenaView<'_>, memory: MemoryId) -> bool {
        self.attachment.clear_dynamic_arena_page_during_drain(arena, memory)
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
    fn retired_bounds(&self) -> (usize, usize) { self.dynamic_theap().retired_bounds() }

    #[inline]
    fn note_retired_bin(&mut self, bin: usize) -> bool {
        self.dynamic_theap_mut().note_retired_bin(bin)
    }

    #[inline]
    fn reset_retired_bounds(&mut self) { self.dynamic_theap_mut().reset_retired_bounds() }

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
        self.attachment.state = DynamicAttachmentState::Poisoned;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::{
        ArenaId, ArenaPagesLayout, ArenaRegistry, ArenaView, manage_external_in_place,
    };
    use crate::config::{
        ARENA_ALIGNMENT, ARENA_MIN_SIZE, ARENA_SLICE_SIZE, BIN_FULL, LARGE_MAX_OBJ_SIZE,
        MEDIUM_MAX_OBJ_SIZE, PAGES_DIRECT, SMALL_MAX_OBJ_SIZE, SMALL_SIZE_MAX, WORD_SIZE,
    };
    use crate::compiler_tls::{
        dynamic_backing_peek, is_empty_dynamic_backing, set_cached_theap,
    };
    use crate::os::{PageSize, fault};
    use crate::os_page::PublishedOsAlignedPage;
    use crate::page_map::PageMap;
    use crate::single_thread::{
        DynamicMappedAbandonError, DynamicMappedAbandonFailure,
        DynamicMappedRemoteFreeFailure,
        DynamicTheapAllocator, DynamicThreadExitDrainFailure,
        DynamicThreadExitFullMediumPagesAbandonError,
        DynamicThreadExitFullMediumPagesAbandonFailure,
        DynamicThreadExitFullMediumPagesFreeResult,
        DynamicThreadExitFullMediumPagesRemoteFreeFailure,
        DynamicThreadExitFullMediumAbandonError,
        DynamicThreadExitFullMediumAbandonFailure,
        DynamicThreadExitFullMediumFreeResult,
        DynamicThreadExitFullMediumRemoteFreeFailure,
        DynamicThreadExitFullSingletonPagesAbandonError,
        DynamicThreadExitFullSingletonPagesAbandonFailure,
        DynamicThreadExitFullSingletonPagesFreeResult,
        DynamicThreadExitFullSingletonPagesRemoteFreeFailure,
        DynamicThreadExitFullOsSingletonPagesAbandonFailure,
        DynamicThreadExitFullOsSingletonPagesAbandonError,
        DynamicThreadExitFullOsSingletonPagesFreeResult,
        DynamicThreadExitFullOsSingletonPagesRemoteFreeError,
        DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure,
        DynamicThreadExitFullLargePagesAbandonError,
        DynamicThreadExitFullLargeAbandonError,
        DynamicThreadExitFullLargeAbandonFailure,
        DynamicThreadExitFullLargeFreeResult,
        DynamicThreadExitFullLargeRemoteFreeFailure,
        DynamicThreadExitFullLargePagesAbandonFailure,
        DynamicThreadExitFullLargePagesFreeResult,
        DynamicThreadExitFullLargePagesRemoteFreeFailure,
        DynamicThreadExitFullNonDirectSmallPagesAbandonError,
        DynamicThreadExitFullNonDirectSmallPagesAbandonFailure,
        DynamicThreadExitFullNonDirectSmallPagesFreeResult,
        DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure,
        DynamicThreadExitFullDirectSmallPagesAbandonError,
        DynamicThreadExitFullDirectSmallPagesAbandonFailure,
        DynamicThreadExitFullDirectSmallPagesFreeResult,
        DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure,
        DynamicThreadExitFullDirectSmallAbandonError,
        DynamicThreadExitFullDirectSmallAbandonFailure,
        DynamicThreadExitFullDirectSmallFreeResult,
        DynamicThreadExitFullDirectSmallRemoteFreeFailure,
        DynamicThreadExitFullNonDirectSmallAbandonError,
        DynamicThreadExitFullNonDirectSmallAbandonFailure,
        DynamicThreadExitFullNonDirectSmallFreeResult,
        DynamicThreadExitFullNonDirectSmallRemoteFreeFailure,
        DynamicThreadExitMappedOneBlockAbandonError,
        DynamicThreadExitMappedOneBlockAbandonFailure,
        DynamicThreadExitMappedOneBlockRemoteFreeFailure,
        DynamicThreadExitMappedTwoBlockMediumAbandonError,
        DynamicThreadExitMappedTwoBlockMediumAbandonFailure,
        DynamicThreadExitMappedTwoBlockMediumFreeResult,
        DynamicThreadExitMappedTwoBlockMediumRemoteFreeFailure,
        DynamicThreadExitMappedTwoBlockLargeAbandonFailure,
        DynamicThreadExitMappedTwoBlockLargeAbandonError,
        DynamicThreadExitMappedTwoBlockLargeFreeResult,
        DynamicThreadExitMappedTwoBlockLargeRemoteFreeFailure,
        DynamicThreadExitMappedTwoBlockDirectSmallAbandonError,
        DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure,
        DynamicThreadExitMappedTwoBlockDirectSmallFreeResult,
        DynamicThreadExitMappedTwoBlockDirectSmallRemoteFreeFailure,
        DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonError,
        DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure,
        DynamicThreadExitMappedTwoBlockNonDirectSmallFreeResult,
        DynamicThreadExitMappedTwoBlockNonDirectSmallRemoteFreeFailure,
        DynamicThreadExitSingletonAbandonError,
        DynamicThreadExitSingletonAbandonFailure,
        DynamicThreadExitSingletonRemoteFreeError,
        DynamicThreadExitSingletonRemoteFreeFailure,
    };
    use crate::tld::ThreadLocalDataOwner;
    use crate::types::{BIN_BLOCK_SIZES, MemoryKind};
    use core::ptr::null_mut;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::boxed::Box;
    use std::thread;
    use std::vec::Vec;

    struct DynamicArenaRegion {
        pointer: NonNull<u8>,
        layout: Layout,
    }

    impl DynamicArenaRegion {
        fn zeroed() -> Self {
            let layout = Layout::from_size_align(ARENA_MIN_SIZE, ARENA_ALIGNMENT)
                .expect("the pinned arena alignment is a valid test layout");
            // SAFETY: the fixture owns this one external arena allocation and
            // destroys every page-map entry before this region is dropped.
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
                .expect("the dynamic page fixture allocates its arena");
            Self { pointer, layout }
        }

        #[inline]
        fn as_ptr(&mut self) -> *mut u8 {
            self.pointer.as_ptr()
        }
    }

    impl Drop for DynamicArenaRegion {
        fn drop(&mut self) {
            // SAFETY: `pointer` was allocated exactly once with `layout` and
            // the fixture's explicit engine shutdown removed all page users.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    /// The real page fixture either completes its explicit shutdown or models
    /// one deliberately retained terminal owner. A boolean would make that
    /// ownership choice too easy to invert at a call site.
    enum DynamicPageFixtureOutcome {
        TearDown,
        RetainTerminal,
    }

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the pinned native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn fixture() -> (
        &'static MainSubprocess,
        Pin<&'static MetaAllocator>,
        &'static OwnedThreadLocalKeyRegistry,
    ) {
        (
            MainSubprocess::test_static_owner(),
            MetaAllocator::test_static_owner(),
            OwnedThreadLocalKeyRegistry::test_static_owner(),
        )
    }

    fn pinned_empty_heap() -> Pin<&'static mut Heap> {
        let heap: &'static mut Heap = Box::leak(Box::new(Heap::bootstrap_empty()));
        // SAFETY: the deliberately leaked test heap has one stable address;
        // each test creates only one attachment over its unique mutable ref.
        unsafe { Pin::new_unchecked(heap) }
    }

    fn consume_static_ticket(
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
    ) {
        let mut generic = unsafe {
            ThreadLocalDataOwner::begin_with_test_metadata(subprocess, metadata, memory_config())
        }
        .expect("the isolated fixture begins with its ticket-zero generic TLD");
        generic
            .teardown()
            .expect("the generic ticket-zero owner retires before dynamic selection");
    }

    fn attach(
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        registry: &'static OwnedThreadLocalKeyRegistry,
        heap: Pin<&'static mut Heap>,
    ) -> DynamicTheapAttachment<'static> {
        match unsafe {
            DynamicTheapAttachment::begin_with_components(
                memory_config(),
                heap,
                subprocess,
                metadata,
                registry,
            )
        } {
            Ok(owner) => owner,
            Err(DynamicTheapBeginError::Rejected(error)) => {
                panic!("the prepared later-ticket dynamic attachment succeeds: {error:?}")
            }
            Err(DynamicTheapBeginError::Retained { error, .. }) => {
                panic!("the prepared later-ticket dynamic attachment did not enter terminal state: {error:?}")
            }
        }
    }

    /// Runs a real caller-managed arena/page-map through the private dynamic
    /// non-abandoning page session. The callback must consume its engine with
    /// `finish`; only then can this helper run attachment and map teardown.
    fn with_non_abandoning_dynamic_page_fixture(
        test: impl FnOnce(
                &mut DynamicTheapAttachment<'static>,
                ArenaView<'_>,
                &mut PageMap,
            ) -> DynamicPageFixtureOutcome
            + Send
            + 'static,
    ) {
        thread::spawn(move || {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = match unsafe {
                DynamicTheapAttachment::begin_non_abandoning_with_components(
                    memory_config(),
                    pinned_empty_heap(),
                    subprocess,
                    metadata,
                    registry,
                )
            } {
                Ok(owner) => owner,
                Err(DynamicTheapBeginError::Rejected(error)) => {
                    panic!("the prepared dynamic non-abandoning attachment succeeds: {error:?}")
                }
                Err(DynamicTheapBeginError::Retained { error, .. }) => {
                    panic!("the prepared dynamic non-abandoning attachment is not terminal: {error:?}")
                }
            };
            let mut region = DynamicArenaRegion::zeroed();
            let registry = ArenaRegistry::new(null_mut());
            assert!(unsafe { registry.bind_subprocess_before_publication(subprocess.as_ptr()) });
            let managed = unsafe {
                manage_external_in_place(
                    &registry,
                    region.as_ptr(),
                    ARENA_MIN_SIZE,
                    PageSize::new(4096).expect("pinned page size"),
                    true,
                    true,
                    true,
                    -1,
                    false,
                    None,
                )
            }
            .expect("the dynamic fixture registers its external arena");
            let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }
                .expect("registered arena has a view");
            let mut page_map = PageMap::initialize(memory_config(), 0, true)
                .expect("the dynamic fixture initializes one page map");

            if matches!(
                test(&mut owner, arena, &mut page_map),
                DynamicPageFixtureOutcome::TearDown
            ) {
                owner
                    .teardown()
                    .expect("an explicitly finished dynamic page engine leaves a tear-downable attachment");
                // SAFETY: successful `finish` has collected/released every
                // page before this explicit source-plain page-map destruction
                // point.
                unsafe { page_map.destroy() }
                    .expect("the dynamic fixture has no remaining page-map entries");
            } else {
                // A terminal dynamic poison intentionally retains the page
                // engine's attachment plus its live map/arena/resource state. This
                // isolated fixture models that production state by leaking
                // all mutually linked storage after its assertions.
                core::mem::forget(owner);
                core::mem::forget(page_map);
                core::mem::forget(region);
                core::mem::forget(registry);
            }
        })
        .join()
        .expect("the dynamic page fixture remains on one current thread");
    }

    /// Runs the exact source-default ordinary dynamic option image through a
    /// private fixture-only page session. This does not widen the production
    /// page-session boundary: ordinary dynamic attachments still reject
    /// [`DynamicTheapAttachment::page_session`]. It exists solely to form the
    /// `allow_page_abandon=true` / `page_full_retain=2` regular-bin image
    /// consumed by `mi_thread_theaps_done`.
    fn with_ordinary_dynamic_page_fixture(
        test: impl FnOnce(
                &mut DynamicTheapAttachment<'static>,
                ArenaView<'_>,
                &mut PageMap,
            ) -> DynamicPageFixtureOutcome
            + Send
            + 'static,
    ) {
        thread::spawn(move || {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let fields = owner
                .theap
                .as_mut()
                .and_then(MetaAllocation::dynamic_theap_mut)
                .expect("the ordinary dynamic fixture retains its typed Theap")
                .test_main_static_fields();
            assert!(fields.allows_page_abandon);
            assert_eq!(fields.page_full_retain, 2);

            let mut region = DynamicArenaRegion::zeroed();
            let registry = ArenaRegistry::new(null_mut());
            assert!(unsafe { registry.bind_subprocess_before_publication(subprocess.as_ptr()) });
            let managed = unsafe {
                manage_external_in_place(
                    &registry,
                    region.as_ptr(),
                    ARENA_MIN_SIZE,
                    PageSize::new(4096).expect("pinned page size"),
                    true,
                    true,
                    true,
                    -1,
                    false,
                    None,
                )
            }
            .expect("the ordinary dynamic fixture registers its external arena");
            let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }
                .expect("registered arena has a view");
            let mut page_map = PageMap::initialize(memory_config(), 0, true)
                .expect("the ordinary dynamic fixture initializes one page map");

            if matches!(
                test(&mut owner, arena, &mut page_map),
                DynamicPageFixtureOutcome::TearDown
            ) {
                owner
                    .teardown()
                    .expect("an explicitly finished ordinary dynamic page engine leaves a tear-downable attachment");
                // SAFETY: successful `finish` has collected/released every
                // page before this explicit source-plain page-map destruction
                // point.
                unsafe { page_map.destroy() }
                    .expect("the ordinary dynamic fixture has no remaining page-map entries");
            } else {
                // A terminal dynamic poison intentionally retains the page
                // engine's attachment plus its live map/arena/resource state. This
                // isolated fixture models that production state by leaking
                // all mutually linked storage after its assertions.
                core::mem::forget(owner);
                core::mem::forget(page_map);
                core::mem::forget(region);
                core::mem::forget(registry);
            }
        })
        .join()
        .expect("the ordinary dynamic page fixture remains on one current thread");
    }

    /// Independent source model of `mi_theap_queue_first_update`'s rounded
    /// direct-cache range. It intentionally uses the frozen queue table
    /// rather than `PageAllocatorEngine`'s implementation so the aggregate
    /// fixtures catch a shared cache-range translation error.
    fn source_direct_cache_range(block_size: usize) -> (usize, usize) {
        let index = crate::invariants::word_count(block_size)
            .expect("the rounded source block size has a direct-cache index");
        assert!(index < PAGES_DIRECT, "the direct range stays in source bounds");
        if index <= 1 {
            return (0, index);
        }

        let bin = crate::size_class::bin(block_size)
            .expect("the direct source block size has one regular queue bin");
        assert!(bin > 0, "a direct cache index above one has a predecessor bin");
        let mut previous = bin - 1;
        while previous > 0
            && crate::size_class::bin(BIN_BLOCK_SIZES[previous]) == Some(bin)
        {
            previous -= 1;
        }
        let start = crate::invariants::word_count(BIN_BLOCK_SIZES[previous])
            .expect("the source predecessor block size has a word count")
            .checked_add(1)
            .expect("the direct range start cannot overflow")
            .min(index);
        (start, index)
    }

    #[test]
    fn ordinary_dynamic_attachment_rejects_page_session_without_arena_or_map_mutation() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            assert!(matches!(
                owner.page_session(),
                Err(DynamicTheapPageSessionError::AbandoningMode)
            ));
            owner
                .teardown()
                .expect("the refusing ordinary attachment has not created pages");
        })
        .join()
        .expect("ordinary dynamic session refusal stays current-thread local");
    }

    #[test]
    fn non_abandoning_dynamic_page_session_allocates_on_its_exact_theap_and_pinned_heap() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let heap = owner.heap.as_ref().get_ref() as *const Heap as *mut Heap;
            let fields = owner
                .theap
                .as_mut()
                .and_then(MetaAllocation::dynamic_theap_mut)
                .expect("the attached dynamic owner retains its typed Theap")
                .test_main_static_fields();
            assert_eq!(fields.page_full_retain, -1);
            assert!(!fields.allows_page_abandon);
            let session = owner
                .page_session()
                .expect("the selected non-abandoning image admits the page engine");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(37, false)
                .expect("the dynamic engine allocates a real regular page block");
            let page = unsafe { allocator.page_for_block(block) };
            assert!(!page.is_null());
            // SAFETY: the current allocation keeps this dynamic page-map
            // entry and its source page fields live until its matching free.
            assert_eq!(unsafe { (*page).theap() }, allocator.theap_identity());
            assert_eq!(unsafe { (*page).heap() }, heap);
            let memory = unsafe { (*page).memid() };
            let (header, layout, image_memory, dynamic_bit_set) = allocator
                .test_dynamic_arena_pages_image(memory)
                .expect("fresh dynamic page lazily creates heap-local arena pages");
            assert_eq!(header.as_ptr().addr() % crate::bitmap::BCHUNK_SIZE, 0);
            assert_eq!(layout.byte_size(), 12_416);
            assert_eq!(image_memory.kind(), MemoryKind::Malloc);
            let malloc = image_memory
                .malloc_memory()
                .expect("typed arena-pages metadata retains Malloc provenance");
            assert_eq!(malloc.base, header.as_ptr().cast());
            assert_eq!(malloc.size, layout.byte_size());
            assert!(image_memory.initially_zero());
            assert!(image_memory.initially_committed());
            assert!(dynamic_bit_set);
            assert!(
                allocator.test_dynamic_main_arena_page_is_clear(memory),
                "dynamic page registration must not masquerade as pages_main"
            );
            assert_eq!(
                allocator.test_attachment_teardown_preflight(),
                Err(DynamicTheapError::PageCountNonZero),
                "a live dynamic page rejects attachment teardown before root/key/list mutation"
            );
            // SAFETY: `block` is this test's sole current allocation.
            unsafe { allocator.free(block) }.expect("the dynamic block frees locally");
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_mapped_regular_page_handoff_publishes_then_reclaims_its_exact_heap_image() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(37, false)
                .expect("real dynamic regular page allocation");
            let page = unsafe { allocator.page_for_block(block) };
            assert!(!page.is_null());
            let original_theap = unsafe { (*page).theap() };

            // SAFETY: `block` is the fixture's only current allocation and
            // no producer token exists while the consuming handoff runs.
            let handoff = match unsafe { allocator.abandon_mapped_regular(block) } {
                Ok(handoff) => handoff,
                Err(failure) => {
                    // The regression must not drop an unexpected retained
                    // owner and pretend fixture cleanup can safely continue.
                    core::mem::forget(failure);
                    panic!("a mapped regular dynamic page hands off source ownership");
                }
            };
            let bin = handoff.test_bin();
            assert_eq!(handoff.page().as_ptr(), page);
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            assert!(handoff.test_main_arena_page_is_clear());
            assert_eq!(unsafe { (*page).theap() }, original_theap);

            let mut allocator = match handoff.adopt() {
                Ok(allocator) => allocator,
                Err(failure) => {
                    core::mem::forget(failure);
                    panic!("the exact heap-local abandoned bit reclaims to the same Theap");
                }
            };
            assert_eq!(unsafe { (*page).theap() }, allocator.theap_identity());
            // The bitmap claim decremented before the two source adoption
            // collections, and push-at-end restored the source page count.
            let heap = unsafe { &*allocator.theap_identity().cast::<Theap>() }.heap();
            assert_eq!(
                unsafe { heap.as_ref() }.and_then(|heap| heap.abandoned_count(bin)),
                Some(0)
            );
            let memory = unsafe { (*page).memid() };
            assert!(allocator.test_dynamic_abandoned_page_is_clear(bin, memory));

            // SAFETY: adoption restored this exact original live allocation
            // to the ordinary local-free lifecycle.
            unsafe { allocator.free(block) }
                .expect("the reclaimed dynamic page accepts its original local free");
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_mapped_regular_remote_free_reclaims_to_its_same_origin() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(37, false)
                .expect("first dynamic regular page allocation");
            let second = allocator
                .allocate(37, false)
                .expect("second allocation shares the regular page");
            let page = unsafe { allocator.page_for_block(first) };
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            let memory = unsafe { (*page).memid() };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the dynamic fixture allocated a regular size class");

            // SAFETY: both client blocks are live allocations of the exact
            // active regular page, and this consuming handoff admits no
            // scoped producer while it changes page ownership.
            let handoff = match unsafe { allocator.abandon_mapped_regular(first) } {
                Ok(handoff) => handoff,
                Err(failure) => {
                    core::mem::forget(failure);
                    panic!("a partially used dynamic regular page enters the mapped handoff");
                }
            };
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            // SAFETY: `first` is still exactly once live in this handoff's
            // page; this method models the source allow-collect remote-free
            // branch and consumes that client ownership.
            let mut allocator = match unsafe { handoff.remote_free_and_reclaim(first) } {
                Ok(allocator) => allocator,
                Err(DynamicMappedRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicMappedRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("same-origin mapped remote free reclaims the page: {error:?}");
                }
            };
            assert_eq!(unsafe { (*page).theap() }, allocator.theap_identity());
            assert!(allocator.test_dynamic_abandoned_page_is_clear(bin, memory));

            // SAFETY: `second` remains the one live client allocation after
            // the source remote free was collected into owner-local state.
            unsafe { allocator.free(second) }
                .expect("the reclaimed page accepts its remaining local allocation");
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_mapped_regular_remote_free_empty_releases_the_queue_detached_arena_page() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(37, false)
                .expect("one dynamic regular page allocation");
            let page = unsafe { allocator.page_for_block(block) };
            let memory = unsafe { (*page).memid() };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the dynamic fixture allocated a regular size class");
            let handoff = match unsafe { allocator.abandon_mapped_regular(block) } {
                Ok(handoff) => handoff,
                Err(failure) => {
                    core::mem::forget(failure);
                    panic!("the one live regular block enters the mapped handoff");
                }
            };

            // SAFETY: this is the handoff's only current client allocation.
            // The source makes its page all-free, clears its mapped-abandoned
            // entry, and then releases the already queue-detached arena span.
            let allocator = match unsafe { handoff.remote_free_and_reclaim(block) } {
                Ok(allocator) => allocator,
                Err(DynamicMappedRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicMappedRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("an empty mapped free releases its exact arena span: {error:?}");
                }
            };
            assert_eq!(unsafe { allocator.page_for_block(block) }, core::ptr::null_mut());
            let heap = unsafe { &*allocator.theap_identity().cast::<Theap>() }.heap();
            assert_eq!(
                unsafe { heap.as_ref() }.and_then(|heap| heap.abandoned_count(bin)),
                Some(0),
                "unabandoning consumes the exact dynamic abandoned-map count before release"
            );
            let (_, _, _, dynamic_page_is_set) = allocator
                .test_dynamic_arena_pages_image(memory)
                .expect("the dynamic image remains available after its page bit clears");
            assert!(!dynamic_page_is_set);
            assert!(allocator.test_dynamic_main_arena_page_is_clear(memory));
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_singleton_remote_free_clears_tls_then_releases_its_arena_page() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the dynamic fixture allocates one arena singleton");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the singleton remains page-map published before thread exit");
            let memory = unsafe { page.as_ref().memid() };
            assert_eq!(unsafe { page.as_ref().reserved() }, 1);
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // The source clears the dynamic regular TLS backing before it
            // abandons pages during `mi_thread_theaps_done`. That makes this
            // page's later free fail the one reclaim attempt without
            // pretending that its original Theap is still live.
            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());
            assert!(drain.test_cached_root_still_names_the_draining_theap());

            // SAFETY: `block` is the singleton's one current allocation.
            // Thread-exit drain owns its queue, page map, dynamic arena image,
            // and the exact source TLS-detach proof until the result is
            // terminally released or retained.
            let handoff = match unsafe { drain.abandon_full_singleton(block) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitSingletonAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitSingletonAbandonFailure::RetainedDrain { drain, error }) => {
                    core::mem::forget(drain);
                    panic!("the live full singleton enters the owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitSingletonAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("singleton abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert!(handoff.test_dynamic_regular_slot_is_clear());

            // SAFETY: this is the handoff's exact once-live client block.
            // The singleton cannot reabandon to an arena bitmap, so its
            // source failed-reclaim tail must take the all-free terminal
            // release rather than route through the mapped handoff.
            let drain = match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
                Ok(drain) => drain,
                Err(DynamicThreadExitSingletonRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitSingletonRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the final singleton free releases its queue-detached arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(block) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_singleton_pages_route_releases_each_same_size_page() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = LARGE_MAX_OBJ_SIZE + 1;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic arena singleton");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first singleton remains PageMap-published before thread exit");
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic arena singleton");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second singleton remains PageMap-published before thread exit");
            assert_ne!(
                first_page,
                second_page,
                "each oversized dynamic allocation has its own singleton metadata page"
            );
            assert_eq!(unsafe { first_page.as_ref().reserved() }, 1);
            assert_eq!(unsafe { first_page.as_ref().used() }, 1);
            assert_eq!(unsafe { second_page.as_ref().reserved() }, 1);
            assert_eq!(unsafe { second_page.as_ref().used() }, 1);
            assert_eq!(
                unsafe { first_page.as_ref().block_size() },
                unsafe { second_page.as_ref().block_size() },
                "the bounded aggregate seals one rounded singleton size"
            );
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));
            let first_memory = unsafe { first_page.as_ref().memid() };
            let second_memory = unsafe { second_page.as_ref().memid() };

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());
            // SAFETY: the dynamic drain owns the complete two-member source
            // full queue, the PageMap, dynamic arena image, and both current
            // client blocks through the returned linear aggregate route.
            let route = match unsafe { drain.abandon_full_singleton_pages() } {
                Ok(route) => route,
                Err(DynamicThreadExitFullSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("same-size full singletons enter the dynamic aggregate route: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 2);
            assert_eq!(route.test_page_count(), 0);
            assert_eq!(unsafe { route.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { route.test_page_for_block(second) }, second_page.as_ptr());

            // SAFETY: `first` is the route's exact once-live canonical block.
            let route = match unsafe { route.remote_free_after_thread_exit(first) } {
                Ok(DynamicThreadExitFullSingletonPagesFreeResult::ReleasedPage(route)) => route,
                Ok(_) => panic!("the first singleton free leaves one aggregate member"),
                Err(DynamicThreadExitFullSingletonPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullSingletonPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the first singleton free releases its exact dynamic member: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 1);
            assert!(unsafe { route.test_page_for_block(first) }.is_null());
            assert_eq!(unsafe { route.test_page_for_block(second) }, second_page.as_ptr());
            assert!(route.test_dynamic_arena_page_is_clear(first_memory));

            // SAFETY: `second` is the final route-owned client block.
            let drain = match unsafe { route.remote_free_after_thread_exit(second) } {
                Ok(DynamicThreadExitFullSingletonPagesFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullSingletonPagesFreeResult::ReleasedPage(route)) => {
                    core::mem::forget(route);
                    panic!("the second singleton free releases the final aggregate member");
                }
                Err(DynamicThreadExitFullSingletonPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullSingletonPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the second singleton free releases the final dynamic member: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert!(drain.test_dynamic_arena_page_is_clear(second_memory));
            assert_eq!(drain.test_page_count(), 0);
            assert!(drain.finish());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_singleton_pages_route_rejects_a_sole_singleton_before_mutation() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates one full dynamic arena singleton");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the singleton remains PageMap-published before thread exit");
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the one current allocation is deliberately supplied to
            // exercise aggregate admission only; the sole singleton handoff
            // remains a separate source boundary.
            let drain = match unsafe { drain.abandon_full_singleton_pages() } {
                Err(DynamicThreadExitFullSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullSingletonPagesAbandonError::NotMultiplePages,
                }) => drain,
                Err(DynamicThreadExitFullSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole-page proof rejects before source collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("one singleton cannot enter the dynamic aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_singleton_pages_route_rejects_mixed_sizes_before_mutation() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its first dynamic arena singleton");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first singleton remains PageMap-published before thread exit");
            let second = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 64 * 1024 + 1, false)
                .expect("the fixture creates its second distinct dynamic arena singleton");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second singleton remains PageMap-published before thread exit");
            assert_ne!(
                unsafe { first_page.as_ref().block_size() },
                unsafe { second_page.as_ref().block_size() },
                "the source full queue deliberately contains heterogeneous singleton sizes"
            );
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: both current allocations remain live solely to prove
            // this heterogeneous full queue rejects before collection.
            let drain = match unsafe { drain.abandon_full_singleton_pages() } {
                Err(DynamicThreadExitFullSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullSingletonPagesAbandonError::NotFullSingleton,
                }) => drain,
                Err(DynamicThreadExitFullSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("mixed-size singleton proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("mixed singleton sizes cannot enter the dynamic aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_singleton_pages_route_retains_a_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = LARGE_MAX_OBJ_SIZE + 1;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic arena singleton");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first singleton remains PageMap-published before thread exit");
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic arena singleton");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second singleton remains PageMap-published before thread exit");

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the injected force collector fails only after complete
            // aggregate preflight and before any queue detachment.
            let drain = match unsafe { drain.abandon_full_singleton_pages() } {
                Err(DynamicThreadExitFullSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullSingletonPagesAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected singleton collection failure retains the dynamic drain: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("the injected collection failure cannot create a dynamic aggregate route");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() }, 1);
            assert_eq!(unsafe { second_page.as_ref().used() }, 1);

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_pages_route_reabandons_each_same_bin_page_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;

            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic medium page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first medium page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            assert!(
                capacity >= 16,
                "the selected medium geometry exposes the source mostly-used prefix"
            );
            let mut first_blocks = Vec::with_capacity(capacity);
            first_blocks.push(first);
            while first_blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its first dynamic medium page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
                first_blocks.push(block);
            }

            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic medium page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second medium page remains PageMap-published");
            assert_ne!(
                first_page, second_page,
                "the bounded aggregate keeps distinct source medium pages"
            );
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            let mut second_blocks = Vec::with_capacity(second_capacity);
            second_blocks.push(second);
            while second_blocks.len() < second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its second dynamic medium page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
                second_blocks.push(block);
            }

            let first_ref = unsafe { first_page.as_ref() };
            let second_ref = unsafe { second_page.as_ref() };
            assert_eq!(
                crate::size_class::page_kind_for_block_size(first_ref.block_size()),
                Some(crate::types::PageKind::Medium)
            );
            assert_eq!(first_ref.block_size(), second_ref.block_size());
            let bin = crate::size_class::bin(first_ref.block_size())
                .expect("the homogeneous medium pages retain one source bin");
            let first_memory = first_ref.memid();
            let second_memory = second_ref.memid();
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the drain retains the complete two-page full queue,
            // PageMap, dynamic arena image, and every live client allocation.
            let mut route = match unsafe { drain.abandon_full_medium_pages() } {
                Ok(route) => route,
                Err(DynamicThreadExitFullMediumPagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("same-bin full medium pages enter the dynamic aggregate route: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 2);
            assert_eq!(route.test_page_count(), 0);
            assert_eq!(unsafe { route.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { route.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));

            let unmapped_frees = capacity / 8;
            assert!(unmapped_frees > 0);
            for block in first_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each block is still live and belongs to the linear
                // first aggregate member.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullMediumPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used first medium page remains live"),
                    Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("the mostly-used first medium free remains source-unmapped: {error:?}");
                    }
                };
            }
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));

            // SAFETY: this exact next free crosses the first member's source
            // mostly-used threshold and must publish only its bitmap/count.
            route = match unsafe {
                route.remote_free_after_thread_exit(first_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullMediumPagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the first reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the first medium reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));

            for block in first_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected first-page
                // client allocation through its mapped failed-reclaim tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullMediumPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped first-page free remains live"),
                    Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("a mapped first-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let first_last = *first_blocks.last().expect("the first full page has one final block");
            // SAFETY: this is the first member's final route-owned allocation.
            route = match unsafe { route.remote_free_after_thread_exit(first_last) } {
                Ok(DynamicThreadExitFullMediumPagesFreeResult::ReleasedPage(route)) => route,
                Ok(_) => panic!("the first final free releases exactly one aggregate member"),
                Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the first final free completes its mapped release: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 1);
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(unsafe { route.test_page_for_block(first) }.is_null());
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_arena_page_is_clear(first_memory));

            for block in second_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: the second page remains independently live and
                // source-unmapped through its own threshold prefix.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullMediumPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used second medium page remains live"),
                    Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("the mostly-used second medium free remains source-unmapped: {error:?}");
                    }
                };
            }
            // SAFETY: this exact next free crosses only the second member's
            // source mostly-used threshold.
            route = match unsafe {
                route.remote_free_after_thread_exit(second_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullMediumPagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the second reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the second medium reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, second_memory));

            for block in second_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(second_capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected second-page
                // allocation through its mapped failed-reclaim tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullMediumPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped second-page free remains live"),
                    Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("a mapped second-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let second_last = *second_blocks.last().expect("the second full page has one final block");
            // SAFETY: this is the route's final aggregate-owned allocation.
            let drain = match unsafe { route.remote_free_after_thread_exit(second_last) } {
                Ok(DynamicThreadExitFullMediumPagesFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullMediumPagesFreeResult::StillLive(route))
                | Ok(DynamicThreadExitFullMediumPagesFreeResult::ReleasedPage(route)) => {
                    core::mem::forget(route);
                    panic!("the final medium free releases the complete aggregate route");
                }
                Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullMediumPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the final medium free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, second_memory));
            assert!(drain.test_dynamic_arena_page_is_clear(second_memory));
            assert_eq!(drain.test_page_count(), 0);
            assert!(drain.finish());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_pages_route_rejects_a_sole_full_medium_before_mutation() {
        with_non_abandoning_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains PageMap-published before thread exit");
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(capacity);
            blocks.push(first);
            while blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its sole dynamic medium page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the sole full medium page is deliberately supplied only
            // to prove aggregate admission rejects before source collection.
            let drain = match unsafe { drain.abandon_full_medium_pages() } {
                Err(DynamicThreadExitFullMediumPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullMediumPagesAbandonError::NotMultiplePages,
                }) => drain,
                Err(DynamicThreadExitFullMediumPagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole-page proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("one full medium page cannot enter the dynamic aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, capacity);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_pages_route_rejects_mixed_full_classes_before_mutation() {
        with_non_abandoning_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its dynamic medium member");
            let medium_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium member remains PageMap-published");
            let capacity = unsafe { medium_page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(capacity);
            blocks.push(first);
            while blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills its medium member before adding a mixed class");
                assert_eq!(unsafe { allocator.page_for_block(block) }, medium_page.as_ptr());
                blocks.push(block);
            }
            let singleton = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture adds a full singleton to the mixed source queue");
            let singleton_page = NonNull::new(unsafe { allocator.page_for_block(singleton) })
                .expect("the singleton remains PageMap-published");
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the live medium and singleton allocations exist only to
            // prove mixed `BIN_FULL` classes reject before collection.
            let drain = match unsafe { drain.abandon_full_medium_pages() } {
                Err(DynamicThreadExitFullMediumPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullMediumPagesAbandonError::NotFullMedium,
                }) => drain,
                Err(DynamicThreadExitFullMediumPagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the mixed class proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("a mixed full queue cannot enter the dynamic medium aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, medium_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(singleton) }, singleton_page.as_ptr());
            assert_eq!(unsafe { medium_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { singleton_page.as_ref().used() }, 1);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_pages_route_retains_a_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic medium page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first medium page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            let mut first_blocks = Vec::with_capacity(capacity);
            first_blocks.push(first);
            while first_blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its first dynamic medium page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
                first_blocks.push(block);
            }
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic medium page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second medium page remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            let mut second_blocks = Vec::with_capacity(second_capacity);
            second_blocks.push(second);
            while second_blocks.len() < second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its second dynamic medium page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
                second_blocks.push(block);
            }

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the injected force collector fails only after complete
            // aggregate preflight and before any full-queue detachment.
            let drain = match unsafe { drain.abandon_full_medium_pages() } {
                Err(DynamicThreadExitFullMediumPagesAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullMediumPagesAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullMediumPagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the injected aggregate collection failure retains the dynamic drain: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("the injected collection failure cannot create a dynamic medium aggregate route");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { second_page.as_ref().used() as usize }, second_capacity);

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_pages_route_reabandons_each_same_bin_page_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;

            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic large page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first large page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            assert!(
                capacity > 8,
                "the selected large geometry exposes the source mostly-used prefix"
            );
            let mut first_blocks = Vec::with_capacity(capacity);
            first_blocks.push(first);
            while first_blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its first dynamic large page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
                first_blocks.push(block);
            }

            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic large page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second large page remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            let mut second_blocks = Vec::with_capacity(second_capacity);
            second_blocks.push(second);
            while second_blocks.len() < second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its second dynamic large page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
                second_blocks.push(block);
            }

            let first_ref = unsafe { first_page.as_ref() };
            let second_ref = unsafe { second_page.as_ref() };
            assert_ne!(
                first_page, second_page,
                "the bounded aggregate keeps distinct source large pages"
            );
            assert_eq!(
                crate::size_class::page_kind_for_block_size(first_ref.block_size()),
                Some(crate::types::PageKind::Large)
            );
            assert_eq!(first_ref.block_size(), second_ref.block_size());
            let bin = crate::size_class::bin(first_ref.block_size())
                .expect("the homogeneous large pages retain one source bin");
            let first_memory = first_ref.memid();
            let second_memory = second_ref.memid();
            let first_arena_memory = first_memory
                .arena_memory()
                .expect("the first large page retains arena provenance");
            let first_slice_start = unsafe { ArenaView::from_ptr(first_arena_memory.arena) }
                .and_then(|arena| arena.slice_start(first_arena_memory.slice_index as usize))
                .expect("the first large span begins in its published arena");
            let first_span_size = first_arena_memory.slice_count as usize * ARENA_SLICE_SIZE;
            let second_arena_memory = second_memory
                .arena_memory()
                .expect("the second large page retains arena provenance");
            let second_slice_start = unsafe { ArenaView::from_ptr(second_arena_memory.arena) }
                .and_then(|arena| arena.slice_start(second_arena_memory.slice_index as usize))
                .expect("the second large span begins in its published arena");
            let second_span_size = second_arena_memory.slice_count as usize * ARENA_SLICE_SIZE;
            assert_eq!(first_memory.kind(), MemoryKind::Arena);
            assert_eq!(second_memory.kind(), MemoryKind::Arena);
            assert_eq!(
                first_span_size / ARENA_SLICE_SIZE,
                64,
                "the first aggregate member retains every source arena slice"
            );
            assert_eq!(
                second_span_size / ARENA_SLICE_SIZE,
                64,
                "the second aggregate member retains every source arena slice"
            );
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));
            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: both vectors retain every live canonical allocation in
            // the complete same-bin full-large source queue.
            let mut route = match unsafe { drain.abandon_full_large_pages() } {
                Ok(route) => route,
                Err(DynamicThreadExitFullLargePagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargePagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("same-bin full large pages enter the dynamic aggregate route: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 2);
            assert_eq!(route.test_page_count(), 0);
            assert_eq!(unsafe { route.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { route.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));

            let unmapped_frees = capacity / 8;
            assert!(unmapped_frees > 0);
            for block in first_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each block is still live and belongs to the linear
                // first aggregate member.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullLargePagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used first large page remains live"),
                    Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("the mostly-used first large free remains source-unmapped: {error:?}");
                    }
                };
            }
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));

            // SAFETY: this exact next free crosses the first member's source
            // mostly-used threshold and must publish only its bitmap/count.
            route = match unsafe {
                route.remote_free_after_thread_exit(first_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullLargePagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the first reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the first large reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));

            for block in first_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected first-page
                // client allocation through its mapped failed-reclaim tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullLargePagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped first-page free remains live"),
                    Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("a mapped first-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let first_last = *first_blocks.last().expect("the first full page has one final block");
            // SAFETY: this is the first member's final route-owned allocation.
            route = match unsafe { route.remote_free_after_thread_exit(first_last) } {
                Ok(DynamicThreadExitFullLargePagesFreeResult::ReleasedPage(route)) => route,
                Ok(_) => panic!("the first final free releases exactly one aggregate member"),
                Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the first final free completes its mapped release: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 1);
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(unsafe { route.test_page_for_block(first) }.is_null());
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_arena_page_is_clear(first_memory));

            for block in second_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: the second page remains independently live and
                // source-unmapped through its own threshold prefix.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullLargePagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used second large page remains live"),
                    Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("the mostly-used second large free remains source-unmapped: {error:?}");
                    }
                };
            }
            // SAFETY: this exact next free crosses only the second member's
            // source mostly-used threshold.
            route = match unsafe {
                route.remote_free_after_thread_exit(second_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullLargePagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the second reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the second large reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, second_memory));

            for block in second_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(second_capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected second-page
                // allocation through its mapped failed-reclaim tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullLargePagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped second-page free remains live"),
                    Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    }) => {
                        core::mem::forget(route);
                        panic!("a mapped second-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let second_last = *second_blocks.last().expect("the second full page has one final block");
            // SAFETY: this is the route's final aggregate-owned allocation.
            let drain = match unsafe { route.remote_free_after_thread_exit(second_last) } {
                Ok(DynamicThreadExitFullLargePagesFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullLargePagesFreeResult::StillLive(route))
                | Ok(DynamicThreadExitFullLargePagesFreeResult::ReleasedPage(route)) => {
                    core::mem::forget(route);
                    panic!("the final large free releases the complete aggregate route");
                }
                Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullLargePagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the final large free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, second_memory));
            assert!(drain.test_dynamic_arena_page_is_clear(second_memory));
            assert_eq!(drain.test_page_count(), 0);
            assert!(drain.finish());
            for offset in (0..first_span_size).step_by(ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(first_slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            for offset in (0..second_span_size).step_by(ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(second_slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_pages_route_rejects_a_sole_full_large_before_mutation() {
        with_non_abandoning_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic large page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published before thread exit");
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(capacity);
            blocks.push(first);
            while blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its sole dynamic large page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the sole full large page is deliberately supplied only
            // to prove aggregate admission rejects before source collection.
            let drain = match unsafe { drain.abandon_full_large_pages() } {
                Err(DynamicThreadExitFullLargePagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullLargePagesAbandonError::NotMultiplePages,
                }) => drain,
                Err(DynamicThreadExitFullLargePagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargePagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole-page proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("one full large page cannot enter the dynamic aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, capacity);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_pages_route_rejects_mixed_full_classes_before_mutation() {
        with_non_abandoning_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let large_request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(large_request, false)
                .expect("the fixture creates its dynamic large member");
            let large_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large member remains PageMap-published");
            let capacity = unsafe { large_page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(capacity);
            blocks.push(first);
            while blocks.len() < capacity {
                let block = allocator
                    .allocate(large_request, false)
                    .expect("the fixture fills its large member before adding a mixed class");
                assert_eq!(unsafe { allocator.page_for_block(block) }, large_page.as_ptr());
                blocks.push(block);
            }
            let medium = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture adds a full medium page to the mixed source queue");
            let medium_page = NonNull::new(unsafe { allocator.page_for_block(medium) })
                .expect("the medium page remains PageMap-published");
            let medium_capacity = unsafe { medium_page.as_ref().reserved() as usize };
            let mut medium_blocks = Vec::with_capacity(medium_capacity);
            medium_blocks.push(medium);
            while medium_blocks.len() < medium_capacity {
                let block = allocator
                    .allocate(SMALL_MAX_OBJ_SIZE + WORD_SIZE, false)
                    .expect("the fixture fills its mixed medium member");
                assert_eq!(unsafe { allocator.page_for_block(block) }, medium_page.as_ptr());
                medium_blocks.push(block);
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the live large and medium allocations exist only to
            // prove mixed `BIN_FULL` classes reject before collection.
            let drain = match unsafe { drain.abandon_full_large_pages() } {
                Err(DynamicThreadExitFullLargePagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullLargePagesAbandonError::NotFullLarge,
                }) => drain,
                Err(DynamicThreadExitFullLargePagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargePagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the mixed class proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("a mixed full queue cannot enter the dynamic large aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, large_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(medium) }, medium_page.as_ptr());
            assert_eq!(unsafe { large_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { medium_page.as_ref().used() as usize }, medium_capacity);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_pages_route_retains_a_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic large page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first large page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            let mut first_blocks = Vec::with_capacity(capacity);
            first_blocks.push(first);
            while first_blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its first dynamic large page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
                first_blocks.push(block);
            }
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic large page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second large page remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            let mut second_blocks = Vec::with_capacity(second_capacity);
            second_blocks.push(second);
            while second_blocks.len() < second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its second dynamic large page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
                second_blocks.push(block);
            }

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the injected force collector fails only after complete
            // aggregate preflight and before any full-queue detachment.
            let drain = match unsafe { drain.abandon_full_large_pages() } {
                Err(DynamicThreadExitFullLargePagesAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullLargePagesAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullLargePagesAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargePagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the injected aggregate collection failure retains the dynamic drain: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("the injected collection failure cannot create a dynamic large aggregate route");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { second_page.as_ref().used() as usize }, second_capacity);

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_pages_route_reabandons_each_same_bin_page_then_releases() {
        with_ordinary_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;

            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic non-direct-small page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first non-direct-small page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            assert!(
                capacity > 8,
                "the selected non-direct-small geometry exposes the source mostly-used prefix"
            );
            let mut first_blocks = Vec::with_capacity(capacity);
            first_blocks.push(first);
            while first_blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its first dynamic non-direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
                first_blocks.push(block);
            }

            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic non-direct-small page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second non-direct-small page remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            let mut second_blocks = Vec::with_capacity(second_capacity);
            second_blocks.push(second);
            while second_blocks.len() < second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its second dynamic non-direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
                second_blocks.push(block);
            }

            let first_ref = unsafe { first_page.as_ref() };
            let second_ref = unsafe { second_page.as_ref() };
            assert_ne!(
                first_page, second_page,
                "the bounded aggregate keeps distinct ordinary-bin source pages"
            );
            assert_eq!(
                crate::size_class::page_kind_for_block_size(first_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(
                first_ref.block_size() > SMALL_SIZE_MAX
                    && first_ref.block_size() <= SMALL_MAX_OBJ_SIZE
                    && !crate::types::page_queue::page_is_in_full(first_ref),
                "the first member has the ordinary non-direct-small source shape"
            );
            assert_eq!(first_ref.block_size(), second_ref.block_size());
            assert!(
                !crate::types::page_queue::page_is_in_full(second_ref),
                "the second member remains in the same ordinary source bin"
            );
            let bin = crate::size_class::bin(first_ref.block_size())
                .expect("the homogeneous non-direct-small pages retain one source bin");
            let first_memory = first_ref.memid();
            let second_memory = second_ref.memid();
            let first_arena_memory = first_memory
                .arena_memory()
                .expect("the first non-direct-small page retains arena provenance");
            let first_slice_start = unsafe { ArenaView::from_ptr(first_arena_memory.arena) }
                .and_then(|arena| arena.slice_start(first_arena_memory.slice_index as usize))
                .expect("the first non-direct-small span begins in its published arena");
            let second_arena_memory = second_memory
                .arena_memory()
                .expect("the second non-direct-small page retains arena provenance");
            let second_slice_start = unsafe { ArenaView::from_ptr(second_arena_memory.arena) }
                .and_then(|arena| arena.slice_start(second_arena_memory.slice_index as usize))
                .expect("the second non-direct-small span begins in its published arena");
            assert_eq!(first_memory.kind(), MemoryKind::Arena);
            assert_eq!(second_memory.kind(), MemoryKind::Arena);
            assert_eq!(
                first_arena_memory.slice_count, 1,
                "the first aggregate member retains one exact source arena slice"
            );
            assert_eq!(
                second_arena_memory.slice_count, 1,
                "the second aggregate member retains one exact source arena slice"
            );
            assert_eq!(allocator.queue_count(bin), Some(2));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the non-direct-small aggregate has no source direct-cache image"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: both vectors retain every live canonical allocation in
            // the complete same-bin full non-direct-small source queue.
            let mut route = match unsafe { drain.abandon_full_non_direct_small_pages() } {
                Ok(route) => route,
                Err(DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("same-bin full non-direct-small pages enter the dynamic aggregate route: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 2);
            assert_eq!(route.test_page_count(), 0);
            assert_eq!(unsafe { route.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { route.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));

            let unmapped_frees = capacity / 8;
            assert!(unmapped_frees > 0);
            for block in first_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each block is still live and belongs to the linear
                // first aggregate member.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used first non-direct-small page remains live"),
                    Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("the mostly-used first non-direct-small free remains source-unmapped: {error:?}");
                    }
                };
            }
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));

            // SAFETY: this exact next free crosses the first member's source
            // mostly-used threshold and publishes only its dynamic bitmap/count.
            route = match unsafe {
                route.remote_free_after_thread_exit(first_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the first reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the first non-direct-small reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));

            for block in first_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected first-page
                // allocation through its mapped failed-reclaim tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped first-page free remains live"),
                    Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("a mapped first-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let first_last = *first_blocks.last().expect("the first full page has one final block");
            // SAFETY: this is the first member's final route-owned allocation.
            route = match unsafe { route.remote_free_after_thread_exit(first_last) } {
                Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::ReleasedPage(route)) => route,
                Ok(_) => panic!("the first final free releases exactly one aggregate member"),
                Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the first final free completes its mapped release: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 1);
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(unsafe { route.test_page_for_block(first) }.is_null());
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_arena_page_is_clear(first_memory));

            for block in second_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: the second page remains independently live and
                // source-unmapped through its own threshold prefix.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used second non-direct-small page remains live"),
                    Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("the mostly-used second non-direct-small free remains source-unmapped: {error:?}");
                    }
                };
            }
            // SAFETY: this exact next free crosses only the second member's
            // source mostly-used threshold.
            route = match unsafe {
                route.remote_free_after_thread_exit(second_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the second reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the second non-direct-small reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, second_memory));

            for block in second_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(second_capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected second-page
                // allocation through its mapped failed-reclaim tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped second-page free remains live"),
                    Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("a mapped second-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let second_last = *second_blocks.last().expect("the second full page has one final block");
            // SAFETY: this is the route's final aggregate-owned allocation.
            let drain = match unsafe { route.remote_free_after_thread_exit(second_last) } {
                Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::StillLive(route))
                | Ok(DynamicThreadExitFullNonDirectSmallPagesFreeResult::ReleasedPage(route)) => {
                    core::mem::forget(route);
                    panic!("the final non-direct-small free releases the complete aggregate route");
                }
                Err(DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the final non-direct-small free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, second_memory));
            assert!(drain.test_dynamic_arena_page_is_clear(second_memory));
            assert_eq!(drain.test_page_count(), 0);
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first_slice_start) }.is_null());
            assert!(unsafe { page_map.checked_lookup(second_slice_start) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_pages_route_rejects_a_sole_full_page_before_mutation() {
        with_ordinary_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the non-direct-small page remains PageMap-published before thread exit");
            let capacity = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(capacity);
            blocks.push(first);
            while blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its sole dynamic non-direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let page_ref = unsafe { page.as_ref() };
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the sole non-direct-small page retains one source bin");
            assert!(
                page_ref.block_size() > SMALL_SIZE_MAX
                    && page_ref.block_size() <= SMALL_MAX_OBJ_SIZE
                    && !crate::types::page_queue::page_is_in_full(page_ref),
                "the sole page has the ordinary non-direct-small source shape"
            );
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the sole full page is supplied only to prove aggregate
            // admission rejects before source collection.
            let drain = match unsafe { drain.abandon_full_non_direct_small_pages() } {
                Err(DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallPagesAbandonError::NotMultiplePages,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the sole-page proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("one full non-direct-small page cannot enter the dynamic aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(bin), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, capacity);
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the rejected preflight leaves the empty direct-cache image untouched"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_pages_route_rejects_mixed_full_classes_before_mutation() {
        with_ordinary_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let non_direct_request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(non_direct_request, false)
                .expect("the fixture creates its first non-direct-small aggregate member");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first non-direct-small member remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            for _ in 1..capacity {
                let block = allocator
                    .allocate(non_direct_request, false)
                    .expect("the fixture fills its first non-direct-small member");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
            }
            let second = allocator
                .allocate(non_direct_request, false)
                .expect("the fixture creates its second non-direct-small aggregate member");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second non-direct-small member remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            for _ in 1..second_capacity {
                let block = allocator
                    .allocate(non_direct_request, false)
                    .expect("the fixture fills its second non-direct-small member");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
            }
            let medium = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture adds a full medium page to the mixed source image");
            let medium_page = NonNull::new(unsafe { allocator.page_for_block(medium) })
                .expect("the medium member remains PageMap-published");
            let medium_capacity = unsafe { medium_page.as_ref().reserved() as usize };
            for _ in 1..medium_capacity {
                let block = allocator
                    .allocate(SMALL_MAX_OBJ_SIZE + WORD_SIZE, false)
                    .expect("the fixture fills its mixed medium member");
                assert_eq!(unsafe { allocator.page_for_block(block) }, medium_page.as_ptr());
            }
            let bin = crate::size_class::bin(unsafe { first_page.as_ref().block_size() })
                .expect("the non-direct-small members retain one ordinary bin");
            assert_eq!(allocator.queue_count(bin), Some(2));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            assert_eq!(
                crate::size_class::page_kind_for_block_size(unsafe { medium_page.as_ref().block_size() }),
                Some(crate::types::PageKind::Medium),
                "the foreign full member gives the aggregate a distinct source class"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the live ordinary-bin small and `BIN_FULL` medium pages
            // exist only to prove mixed full classes reject before collection.
            let drain = match unsafe { drain.abandon_full_non_direct_small_pages() } {
                Err(DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallPagesAbandonError::Queue,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the mixed class proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("a mixed full source image cannot enter the dynamic non-direct-small aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(bin), Some(2));
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(medium) }, medium_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { second_page.as_ref().used() as usize }, second_capacity);
            assert_eq!(unsafe { medium_page.as_ref().used() as usize }, medium_capacity);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_pages_route_retains_a_collection_failure() {
        with_ordinary_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic non-direct-small page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first non-direct-small page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            for _ in 1..capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its first dynamic non-direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
            }
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic non-direct-small page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second non-direct-small page remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            for _ in 1..second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its second dynamic non-direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
            }
            let bin = crate::size_class::bin(unsafe { first_page.as_ref().block_size() })
                .expect("the non-direct-small aggregate has one ordinary source bin");

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the injected force collector fails only after complete
            // aggregate preflight and before ordinary-bin detachment.
            let drain = match unsafe { drain.abandon_full_non_direct_small_pages() } {
                Err(
                    DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error: DynamicThreadExitFullNonDirectSmallPagesAbandonError::Collection,
                    },
                ) => drain,
                Err(DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullNonDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the injected aggregate collection failure retains the dynamic drain: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("the injected collection failure cannot create a dynamic non-direct-small aggregate route");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(drain.test_queue_count(bin), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { second_page.as_ref().used() as usize }, second_capacity);
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the retained collection failure leaves the direct-cache image untouched"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_pages_route_preserves_partial_head_then_releases_each_member() {
        with_ordinary_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;

            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic direct-small page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first direct-small page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            assert!(
                capacity >= 16,
                "the source direct partial collector requires the pinned reserved floor"
            );
            let mut first_blocks = Vec::with_capacity(capacity);
            first_blocks.push(first);
            while first_blocks.len() < capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its first dynamic direct-small page");
                assert_eq!(
                    unsafe { allocator.page_for_block(block) },
                    first_page.as_ptr(),
                    "the first source page fills in its ordinary bin before a second page is created"
                );
                first_blocks.push(block);
            }

            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic direct-small page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second direct-small page remains PageMap-published");
            assert_ne!(
                second_page, first_page,
                "the aggregate route receives two distinct ordinary-bin source pages"
            );
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(
                second_capacity, capacity,
                "one request class gives both aggregate members the same full-page geometry"
            );
            let mut second_blocks = Vec::with_capacity(second_capacity);
            second_blocks.push(second);
            while second_blocks.len() < second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its second dynamic direct-small page");
                assert_eq!(
                    unsafe { allocator.page_for_block(block) },
                    second_page.as_ptr(),
                    "the second source page fills without creating a third member"
                );
                second_blocks.push(block);
            }

            let first_ref = unsafe { first_page.as_ref() };
            let second_ref = unsafe { second_page.as_ref() };
            assert_eq!(
                crate::size_class::page_kind_for_block_size(first_ref.block_size()),
                Some(crate::types::PageKind::Small),
                "the first aggregate member stays in the ordinary small class"
            );
            assert!(
                first_ref.block_size() <= SMALL_SIZE_MAX,
                "the aggregate owns only the direct-small source interval"
            );
            assert_eq!(first_ref.block_size(), second_ref.block_size());
            assert_eq!(first_ref.used() as usize, capacity);
            assert_eq!(second_ref.used() as usize, second_capacity);
            assert!(
                !crate::types::page_queue::page_is_in_full(first_ref)
                    && !crate::types::page_queue::page_is_in_full(second_ref),
                "full direct-small pages remain in their ordinary source bin"
            );
            let bin = crate::size_class::bin(first_ref.block_size())
                .expect("the homogeneous direct-small pages retain one source bin");
            let first_memory = first_ref.memid();
            let second_memory = second_ref.memid();
            let first_slice_start = first_memory
                .arena_memory()
                .and_then(|memory| unsafe {
                    ArenaView::from_ptr(memory.arena)
                        .and_then(|arena| arena.slice_start(memory.slice_index as usize))
                })
                .expect("the first direct-small span begins in its published arena");
            let second_slice_start = second_memory
                .arena_memory()
                .and_then(|memory| unsafe {
                    ArenaView::from_ptr(memory.arena)
                        .and_then(|arena| arena.slice_start(memory.slice_index as usize))
                })
                .expect("the second direct-small span begins in its published arena");
            assert_eq!(first_memory.kind(), MemoryKind::Arena);
            assert_eq!(second_memory.kind(), MemoryKind::Arena);
            assert_eq!(
                first_memory
                    .arena_memory()
                    .expect("the first member retains arena provenance")
                    .slice_count,
                1,
                "the first aggregate member retains one exact source arena slice"
            );
            assert_eq!(
                second_memory
                    .arena_memory()
                    .expect("the second member retains arena provenance")
                    .slice_count,
                1,
                "the second aggregate member retains one exact source arena slice"
            );
            assert_eq!(allocator.queue_count(bin), Some(2));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            let (direct_start, direct_end) = source_direct_cache_range(first_ref.block_size());
            let direct_head = allocator
                .direct_page(direct_start)
                .expect("the source direct cache remains addressable");
            assert!(
                direct_head == first_page.as_ptr() || direct_head == second_page.as_ptr(),
                "the source direct cache names the ordinary queue head"
            );
            for index in 0..PAGES_DIRECT {
                let expected = if index >= direct_start && index <= direct_end {
                    direct_head
                } else {
                    crate::types::EMPTY_PAGE.as_ptr()
                };
                assert_eq!(
                    allocator.direct_page(index),
                    Some(expected),
                    "the aggregate preserves the complete rounded source direct-cache image"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: both vectors retain every live canonical allocation in
            // the complete same-bin full direct-small source queue.
            let mut route = match unsafe { drain.abandon_full_direct_small_pages() } {
                Ok(route) => route,
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("same-bin full direct-small pages enter the dynamic aggregate route: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 2);
            assert_eq!(route.test_page_count(), 0);
            assert_eq!(unsafe { route.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { route.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    route.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "each source removal clears its complete rounded direct-cache range before count detach"
                );
            }

            // `_mi_page_free_collect_partly` deliberately retains the just-
            // published head. Each direct-small member therefore remains
            // unmapped for one free beyond the normal collector's threshold.
            let unmapped_frees = capacity / 8 + 1;
            assert!(unmapped_frees + 1 < capacity);
            for block in first_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each selected block is still live in the linear
                // first aggregate member's partial-collector tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used first direct-small page remains live"),
                    Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("the partial-head first direct-small prefix remains source-unmapped: {error:?}");
                    }
                };
            }
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));

            // SAFETY: this exact next free crosses the first member's delayed
            // source mostly-used threshold and publishes only its dynamic
            // bitmap/count pair.
            route = match unsafe {
                route.remote_free_after_thread_exit(first_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the first reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the first direct-small reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, first_memory));
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, second_memory));

            for block in first_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected first-page
                // allocation through its mapped partial-collector tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped first-page free remains live"),
                    Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("a mapped first-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let first_last = *first_blocks.last().expect("the first full page has one final block");
            // SAFETY: this is the first member's final route-owned allocation.
            route = match unsafe { route.remote_free_after_thread_exit(first_last) } {
                Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::ReleasedPage(route)) => route,
                Ok(_) => panic!("the first final free releases exactly one aggregate member"),
                Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the first final free completes its mapped release: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 1);
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(0));
            assert!(unsafe { route.test_page_for_block(first) }.is_null());
            assert!(route.test_dynamic_abandoned_page_is_clear(bin, first_memory));
            assert!(route.test_dynamic_arena_page_is_clear(first_memory));

            for block in second_blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: the second page remains independently live and
                // source-unmapped through its own partial-head prefix.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("the mostly-used second direct-small page remains live"),
                    Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("the partial-head second direct-small prefix remains source-unmapped: {error:?}");
                    }
                };
            }
            // SAFETY: this exact next free crosses only the second member's
            // delayed source mostly-used threshold.
            route = match unsafe {
                route.remote_free_after_thread_exit(second_blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::StillLive(route)) => route,
                Ok(_) => panic!("the second reabandon boundary leaves live blocks"),
                Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the second direct-small reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(route.test_dynamic_abandoned_count(bin), Some(1));
            assert!(route.test_dynamic_abandoned_page_is_set(bin, second_memory));

            for block in second_blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(second_capacity - unmapped_frees - 2)
            {
                // SAFETY: this linear route still owns the selected second-
                // page allocation through its mapped partial-collector tail.
                route = match unsafe { route.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::StillLive(route)) => route,
                    Ok(_) => panic!("a nonfinal mapped second-page free remains live"),
                    Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                        route,
                        error,
                    })
                    | Err(
                        DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                            route,
                            error,
                        },
                    ) => {
                        core::mem::forget(route);
                        panic!("a mapped second-page free stays in the aggregate route: {error:?}");
                    }
                };
            }
            let second_last = *second_blocks.last().expect("the second full page has one final block");
            // SAFETY: this is the route's final aggregate-owned allocation.
            let drain = match unsafe { route.remote_free_after_thread_exit(second_last) } {
                Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::StillLive(route))
                | Ok(DynamicThreadExitFullDirectSmallPagesFreeResult::ReleasedPage(route)) => {
                    core::mem::forget(route);
                    panic!("the final direct-small free releases the complete aggregate route");
                }
                Err(DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesRemoteFreeFailure::Terminal {
                        route,
                        error,
                    },
                ) => {
                    core::mem::forget(route);
                    panic!("the final direct-small free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, second_memory));
            assert!(drain.test_dynamic_arena_page_is_clear(second_memory));
            assert_eq!(drain.test_page_count(), 0);
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first_slice_start) }.is_null());
            assert!(unsafe { page_map.checked_lookup(second_slice_start) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_pages_route_rejects_a_sole_full_page_before_mutation() {
        with_ordinary_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let capacity = unsafe { page.as_ref().reserved() as usize };
            for _ in 1..capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills only its sole dynamic direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            let page_ref = unsafe { page.as_ref() };
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the sole direct-small page retains one source bin");
            let (direct_start, direct_end) = source_direct_cache_range(page_ref.block_size());
            let direct_head = allocator
                .direct_page(direct_start)
                .expect("the direct cache remains addressable");
            assert_eq!(direct_head, page.as_ptr());
            assert!(
                page_ref.block_size() <= SMALL_SIZE_MAX
                    && page_ref.reserved() >= 16
                    && !crate::types::page_queue::page_is_in_full(page_ref),
                "the sole page has the complete full direct-small source shape except multiplicity"
            );
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the sole full page exists only to prove aggregate
            // admission rejects before force collection or queue mutation.
            let drain = match unsafe { drain.abandon_full_direct_small_pages() } {
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallPagesAbandonError::NotMultiplePages,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the sole-page proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("one full direct-small page cannot enter the dynamic aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(bin), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, capacity);
            for index in 0..PAGES_DIRECT {
                let expected = if index >= direct_start && index <= direct_end {
                    direct_head
                } else {
                    crate::types::EMPTY_PAGE.as_ptr()
                };
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(expected),
                    "the rejected preflight leaves the complete rounded direct-cache image untouched"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_pages_route_refuses_stale_rounded_direct_cache_before_detach() {
        with_ordinary_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic direct-small page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first direct-small page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            for _ in 1..capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills exactly its first direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
            }
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic direct-small page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second direct-small page remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            for _ in 1..second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills exactly its second direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
            }
            let first_ref = unsafe { first_page.as_ref() };
            let bin = crate::size_class::bin(first_ref.block_size())
                .expect("the direct-small aggregate has one ordinary source bin");
            let (_direct_start, direct_end) = source_direct_cache_range(first_ref.block_size());
            assert_ne!(
                allocator.direct_page(direct_end),
                Some(crate::types::EMPTY_PAGE.as_ptr()),
                "the source image initially names its ordinary direct queue head"
            );
            assert!(
                allocator.set_direct_page_for_test(direct_end, crate::types::EMPTY_PAGE.as_ptr()),
                "the fixture can model one stale rounded direct-cache slot"
            );
            let mut stale_image = [core::ptr::null_mut::<Page>(); PAGES_DIRECT];
            for (index, slot) in stale_image.iter_mut().enumerate() {
                *slot = allocator
                    .direct_page(index)
                    .expect("the direct cache remains addressable while stale");
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the complete full source queue is present but one
            // rounded direct-cache slot is intentionally stale before exit.
            let drain = match unsafe { drain.abandon_full_direct_small_pages() } {
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallPagesAbandonError::Queue,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the stale direct image rejects before collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("a stale rounded direct-cache image cannot enter the aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(bin), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { second_page.as_ref().used() as usize }, second_capacity);
            for (index, expected) in stale_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(expected),
                    "the stale preflight refusal does not repair or otherwise mutate direct-cache state"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_pages_route_rejects_mixed_full_classes_before_mutation() {
        with_ordinary_dynamic_page_fixture(|_owner, arena, page_map| {
            let session = _owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let direct_request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(direct_request, false)
                .expect("the fixture creates its first direct-small aggregate member");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first direct-small member remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            for _ in 1..capacity {
                let block = allocator
                    .allocate(direct_request, false)
                    .expect("the fixture fills its first direct-small aggregate member");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
            }
            let second = allocator
                .allocate(direct_request, false)
                .expect("the fixture creates its second direct-small aggregate member");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second direct-small member remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            for _ in 1..second_capacity {
                let block = allocator
                    .allocate(direct_request, false)
                    .expect("the fixture fills its second direct-small aggregate member");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
            }
            let medium_request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let medium = allocator
                .allocate(medium_request, false)
                .expect("the fixture adds one full medium page to the mixed source image");
            let medium_page = NonNull::new(unsafe { allocator.page_for_block(medium) })
                .expect("the mixed medium page remains PageMap-published");
            let medium_capacity = unsafe { medium_page.as_ref().reserved() as usize };
            for _ in 1..medium_capacity {
                let block = allocator
                    .allocate(medium_request, false)
                    .expect("the fixture fills its mixed medium member");
                assert_eq!(unsafe { allocator.page_for_block(block) }, medium_page.as_ptr());
            }
            let first_ref = unsafe { first_page.as_ref() };
            let bin = crate::size_class::bin(first_ref.block_size())
                .expect("the direct-small members retain one ordinary bin");
            let mut direct_image = [core::ptr::null_mut::<Page>(); PAGES_DIRECT];
            for (index, slot) in direct_image.iter_mut().enumerate() {
                *slot = allocator
                    .direct_page(index)
                    .expect("the direct cache remains addressable for the mixed source image");
            }
            assert_eq!(allocator.queue_count(bin), Some(2));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            assert_eq!(
                crate::size_class::page_kind_for_block_size(unsafe { medium_page.as_ref().block_size() }),
                Some(crate::types::PageKind::Medium),
                "the foreign full member gives the direct aggregate a distinct source class"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: live direct-small ordinary-bin and medium `BIN_FULL`
            // pages exist only to prove mixed source classes reject before
            // collection or queue mutation.
            let drain = match unsafe { drain.abandon_full_direct_small_pages() } {
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallPagesAbandonError::Queue,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the mixed class proof is pre-collection: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("a mixed full source image cannot enter the dynamic direct-small aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(bin), Some(2));
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(medium) }, medium_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { second_page.as_ref().used() as usize }, second_capacity);
            assert_eq!(unsafe { medium_page.as_ref().used() as usize }, medium_capacity);
            for (index, expected) in direct_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(expected),
                    "the mixed-class preflight refusal leaves the complete direct-cache image untouched"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_pages_route_retains_a_collection_failure() {
        with_ordinary_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session_for_ordinary_thread_exit_fixture()
                .expect("the ordinary dynamic fixture admits its exact source page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first dynamic direct-small page");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first direct-small page remains PageMap-published");
            let capacity = unsafe { first_page.as_ref().reserved() as usize };
            for _ in 1..capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills exactly its first direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, first_page.as_ptr());
            }
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second dynamic direct-small page");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second direct-small page remains PageMap-published");
            let second_capacity = unsafe { second_page.as_ref().reserved() as usize };
            assert_eq!(second_capacity, capacity);
            for _ in 1..second_capacity {
                let block = allocator
                    .allocate(request, false)
                    .expect("the fixture fills exactly its second direct-small page");
                assert_eq!(unsafe { allocator.page_for_block(block) }, second_page.as_ptr());
            }
            let first_ref = unsafe { first_page.as_ref() };
            let bin = crate::size_class::bin(first_ref.block_size())
                .expect("the direct-small aggregate has one ordinary source bin");
            let mut direct_image = [core::ptr::null_mut::<Page>(); PAGES_DIRECT];
            for (index, slot) in direct_image.iter_mut().enumerate() {
                *slot = allocator
                    .direct_page(index)
                    .expect("the direct cache remains addressable before collection");
            }

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the injected force collector fails only after complete
            // aggregate and rounded direct-cache preflight, before detachment.
            let drain = match unsafe { drain.abandon_full_direct_small_pages() } {
                Err(
                    DynamicThreadExitFullDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error: DynamicThreadExitFullDirectSmallPagesAbandonError::Collection,
                    },
                ) => drain,
                Err(DynamicThreadExitFullDirectSmallPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitFullDirectSmallPagesAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the injected aggregate collection failure retains the dynamic drain: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("the injected collection failure cannot create a dynamic direct-small aggregate route");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(drain.test_queue_count(bin), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert_eq!(unsafe { first_page.as_ref().used() as usize }, capacity);
            assert_eq!(unsafe { second_page.as_ref().used() as usize }, second_capacity);
            for (index, expected) in direct_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(expected),
                    "the retained collection failure leaves the complete rounded direct-cache image untouched"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_os_aligned_singleton_handoff_releases_after_its_final_free() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the dynamic fixture allocates one OS-aligned singleton");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the OS singleton remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            assert_eq!(page_ref.reserved(), 1);
            assert_eq!(page_ref.used(), 1);
            assert!(page_ref.memid().is_os());
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));
            let published = unsafe { PublishedOsAlignedPage::from_page(memory_config(), page) }
                .expect("the OS singleton retains its complete terminal-release token");
            assert!(allocator.test_os_page_map_entries_match(&published));

            // The source clears the dynamic regular TLS backing before it
            // abandons pages during `mi_thread_theaps_done`. That makes this
            // page's later free fail the one reclaim attempt without
            // pretending that its original Theap is still live.
            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());
            assert!(drain.test_cached_root_still_names_the_draining_theap());

            // SAFETY: `block` is the sole current allocation in the exact
            // full OS-aligned singleton retained by this post-TLS dynamic
            // page-drain lifecycle.
            let handoff = match unsafe { drain.abandon_full_singleton(block) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitSingletonAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitSingletonAbandonFailure::RetainedDrain { drain, error }) => {
                    core::mem::forget(drain);
                    panic!("the OS-aligned singleton enters the owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitSingletonAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("OS-singleton abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert!(handoff.test_os_page_map_entries_match(&published));
            assert_eq!(
                handoff.test_os_abandoned_page_head(),
                page.as_ptr(),
                "source OS abandonment links the detached singleton before it clears the low owner"
            );

            // SAFETY: this is the handoff's exact once-live client
            // allocation. The cleared regular TLS slot is the bounded source
            // proof that the one reclaim attempt must fail.
            let drain = match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
                Ok(drain) => drain,
                Err(DynamicThreadExitSingletonRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitSingletonRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the OS-singleton final free releases its sole page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(block) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert!(
                drain.test_os_abandoned_page_head().is_null(),
                "source OS release removes the all-free singleton from the private list before unmap"
            );
            assert!(drain.finish());
            for offset in (0..published.layout().page_map_size())
                .step_by(crate::config::ARENA_SLICE_SIZE)
            {
                assert!(unsafe {
                    page_map.checked_lookup(published.slice_start().as_ptr().wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_os_aligned_singleton_handoff_rejects_unmapped_pointer_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the dynamic fixture allocates one OS-aligned singleton");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the OS singleton remains PageMap-published before thread exit");
            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the regular TLS slot before OS preflight: {error:?}");
                }
            };

            // SAFETY: this deliberately unmapped non-null pointer is only a
            // pre-detach error witness; the drain must preserve the actual
            // OS singleton and return its complete source owner unchanged.
            let drain = match unsafe { drain.abandon_full_singleton(NonNull::dangling()) } {
                Err(DynamicThreadExitSingletonAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitSingletonAbandonError::Unmapped,
                }) => drain,
                Err(DynamicThreadExitSingletonAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitSingletonAbandonFailure::RetainedDrain { drain, error }) => {
                    core::mem::forget(drain);
                    panic!("an unmapped pointer is rejected before dynamic OS detachment: {error:?}");
                }
                Err(DynamicThreadExitSingletonAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("an unmapped pointer cannot create a terminal OS handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("an unmapped pointer cannot enter the OS singleton handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page.as_ptr());
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));
            let page_ref = unsafe { page.as_ref() };
            assert_eq!(page_ref.reserved(), 1);
            assert_eq!(page_ref.used(), 1);

            // SAFETY: the actual client allocation remains live and exactly
            // once-owned after the rejected pre-detach observation.
            let handoff = match unsafe { drain.abandon_full_singleton(block) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitSingletonAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitSingletonAbandonFailure::RetainedDrain { drain, error }) => {
                    core::mem::forget(drain);
                    panic!("the preserved OS singleton still enters its handoff: {error:?}");
                }
                Err(DynamicThreadExitSingletonAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the preserved OS singleton does not retain terminal ownership: {error:?}");
                }
            };
            // SAFETY: this is the exact client allocation transferred by the
            // valid handoff immediately after its rejected preflight attempt.
            let drain = match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
                Ok(drain) => drain,
                Err(DynamicThreadExitSingletonRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitSingletonRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the preserved OS singleton still releases after its final free: {error:?}");
                }
            };
            assert!(drain.finish());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_os_aligned_singleton_handoff_retains_failed_unmap_terminally() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let fault = fault::install(fault::Plan::disabled());
            let block = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the dynamic fixture allocates one OS-aligned singleton");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the OS singleton remains PageMap-published before thread exit");
            let published = unsafe { PublishedOsAlignedPage::from_page(memory_config(), page) }
                .expect("the OS singleton retains its complete terminal-release token");
            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the regular TLS slot before failed OS release: {error:?}");
                }
            };
            let handoff = match unsafe { drain.abandon_full_singleton(block) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitSingletonAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitSingletonAbandonFailure::RetainedDrain { drain, error }) => {
                    core::mem::forget(drain);
                    panic!("the OS singleton enters the failed-unmap handoff: {error:?}");
                }
                Err(DynamicThreadExitSingletonAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("OS abandonment unexpectedly retained terminal ownership: {error:?}");
                }
            };

            fault.set(fault::Plan::at(
                fault::Point::Unmap,
                1,
                crabc_core::Errno::NOMEM,
            ));
            // SAFETY: this remains the handoff's exact once-live client
            // block. The source TLS-detach proof still makes the one reclaim
            // attempt fail before terminal release.
            let handoff = match unsafe { handoff.remote_free_after_failed_reclaim(block) } {
                Err(DynamicThreadExitSingletonRemoteFreeFailure::Terminal {
                    handoff,
                    error: DynamicThreadExitSingletonRemoteFreeError::Release,
                }) => handoff,
                Err(DynamicThreadExitSingletonRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("failed OS unmap retains the exact release terminal: {error:?}");
                }
                Err(DynamicThreadExitSingletonRemoteFreeFailure::Rejected { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the exact OS singleton final free is not rejected: {error:?}");
                }
                Ok(drain) => {
                    core::mem::forget(drain);
                    panic!("the configured OS unmap failure must retain its handoff");
                }
            };
            assert_eq!(
                fault.observed(),
                1,
                "the terminal OS release attempts exactly one source unmap"
            );
            fault.set(fault::Plan::disabled());
            assert!(
                handoff.test_has_pending_os_release(),
                "failed unmap retains the unique published mapping owner in the handoff engine"
            );
            assert!(
                handoff.test_os_abandoned_page_head().is_null(),
                "the source list removal precedes the failed terminal unmap"
            );
            assert!(handoff.test_os_page_map_entries_are_clear(&published));

            // Dropping the terminal handoff moves the raw published mapping
            // owner into the dynamic attachment and latches it. This slice
            // deliberately exposes no retry lifecycle for that owner.
            drop(handoff);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            assert!(
                owner.terminal_os_release.is_some(),
                "terminal Drop transfers the unique OS release owner into the retained attachment"
            );
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_os_singleton_pages_route_releases_each_clipped_map() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the fixture creates its first OS-aligned singleton");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first OS singleton is PageMap-published");
            let second = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the fixture creates its second OS-aligned singleton");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second OS singleton is PageMap-published");
            let first_ref = unsafe { first_page.as_ref() };
            let second_ref = unsafe { second_page.as_ref() };
            assert!(first_ref.memid().is_os());
            assert!(second_ref.memid().is_os());
            assert_eq!(first_ref.block_size(), second_ref.block_size());
            assert_eq!(first_ref.reserved(), 1);
            assert_eq!(first_ref.used(), 1);
            assert_eq!(second_ref.reserved(), 1);
            assert_eq!(second_ref.used(), 1);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(2));
            let first_published = unsafe { PublishedOsAlignedPage::from_page(memory_config(), first_page) }
                .expect("the first singleton retains its clipped release token");
            let second_published = unsafe { PublishedOsAlignedPage::from_page(memory_config(), second_page) }
                .expect("the second singleton retains its clipped release token");
            assert!(allocator.test_os_page_map_entries_match(&first_published));
            assert!(allocator.test_os_page_map_entries_match(&second_published));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the regular TLS slot before OS aggregate abandonment: {error:?}");
                }
            };
            // SAFETY: both exact OS-aligned singleton allocations remain live
            // in the complete homogeneous full source queue. The route owns
            // their sequential failed-reclaim frees after source detachment.
            let route = match unsafe { drain.abandon_full_os_singleton_pages() } {
                Ok(route) => route,
                Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the two OS singletons enter their aggregate route: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 2);
            assert_eq!(route.test_page_count(), 0);
            let head = route.test_os_abandoned_page_head();
            let head_page = NonNull::new(head)
                .expect("source OS abandonment links a nonempty private list");
            let tail = unsafe { head_page.as_ref().next() };
            assert!(!tail.is_null(), "both aggregate members stay linked in the private list");
            assert!(unsafe { (*tail).next() }.is_null());
            assert!(
                (head == first_page.as_ptr() && tail == second_page.as_ptr())
                    || (head == second_page.as_ptr() && tail == first_page.as_ptr()),
                "the private list contains exactly the two detached OS aggregate members"
            );

            let tail_block = if tail == first_page.as_ptr() { first } else { second };
            let head_block = if head == first_page.as_ptr() { first } else { second };
            // SAFETY: `tail_block` names the exact non-head member of the
            // source-owned list. Its terminal release must unlink only that
            // member and leave the other clipped mapping routable.
            let route = match unsafe { route.remote_free_after_thread_exit(tail_block) } {
                Ok(DynamicThreadExitFullOsSingletonPagesFreeResult::ReleasedPage(route)) => route,
                Ok(DynamicThreadExitFullOsSingletonPagesFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("one of two OS aggregate members cannot finish the route");
                }
                Err(DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the exact non-head OS aggregate member releases: {error:?}");
                }
            };
            assert_eq!(route.test_remaining_pages(), 1);
            assert_eq!(route.test_os_abandoned_page_head(), head);
            assert!(unsafe { route.test_page_for_block(tail_block) }.is_null());
            assert_eq!(
                unsafe { route.test_page_for_block(head_block) },
                head,
                "releasing one OS aggregate member leaves the other clipped map registered"
            );

            // SAFETY: `head_block` is the remaining exact aggregate client
            // allocation after the earlier interior-list removal.
            let drain = match unsafe { route.remote_free_after_thread_exit(head_block) } {
                Ok(DynamicThreadExitFullOsSingletonPagesFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullOsSingletonPagesFreeResult::ReleasedPage(route)) => {
                    core::mem::forget(route);
                    panic!("the final OS aggregate member must finish the route");
                }
                Err(DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                })
                | Err(DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the remaining OS aggregate member releases its clipped map: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert!(drain.test_os_abandoned_page_head().is_null());
            assert!(drain.finish());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_os_singleton_pages_route_rejects_a_sole_page_before_mutation() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the fixture creates one OS-aligned singleton");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the OS singleton remains PageMap-published");
            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the regular TLS slot before sole aggregate refusal: {error:?}");
                }
            };
            // SAFETY: the one live OS singleton is supplied only to prove the
            // aggregate boundary remains disjoint from the established sole
            // singleton handoff and rejects before collection or list insert.
            let drain = match unsafe { drain.abandon_full_os_singleton_pages() } {
                Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullOsSingletonPagesAbandonError::NotMultiplePages,
                }) => drain,
                Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("sole OS aggregate refusal remains pre-mutation: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("one OS singleton cannot enter the aggregate route");
                }
            };
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page.as_ptr());
            assert!(drain.test_os_abandoned_page_head().is_null());

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_os_singleton_pages_route_retains_a_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the fixture creates its first OS singleton");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first OS singleton remains PageMap-published");
            let second = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the fixture creates its second OS singleton");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second OS singleton remains PageMap-published");
            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the regular TLS slot before OS aggregate collection: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the injected force collector fails only after complete
            // OS queue/list preflight and before queue detachment or list
            // insertion, so source state must remain intact.
            let drain = match unsafe { drain.abandon_full_os_singleton_pages() } {
                Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullOsSingletonPagesAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the injected OS aggregate collection failure retains its drain: {error:?}");
                }
                Ok(route) => {
                    core::mem::forget(route);
                    panic!("the injected collection failure cannot create an OS aggregate route");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(2));
            assert_eq!(unsafe { drain.test_page_for_block(first) }, first_page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, second_page.as_ptr());
            assert!(drain.test_os_abandoned_page_head().is_null());

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_os_singleton_pages_route_retains_failed_unmap_terminally() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let fault = fault::install(fault::Plan::disabled());
            let first = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the fixture creates its first OS singleton");
            let first_page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first OS singleton remains PageMap-published");
            let first_published = unsafe { PublishedOsAlignedPage::from_page(memory_config(), first_page) }
                .expect("the first OS singleton retains its clipped release token");
            let second = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("the fixture creates its second OS singleton");
            let second_page = NonNull::new(unsafe { allocator.page_for_block(second) })
                .expect("the second OS singleton remains PageMap-published");
            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the regular TLS slot before failed OS aggregate release: {error:?}");
                }
            };
            let route = match unsafe { drain.abandon_full_os_singleton_pages() } {
                Ok(route) => route,
                Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullOsSingletonPagesAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the OS aggregate enters its failed-unmap route: {error:?}");
                }
            };
            fault.set(fault::Plan::at(
                fault::Point::Unmap,
                1,
                crabc_core::Errno::NOMEM,
            ));
            // SAFETY: `first` remains one exact aggregate allocation. Its
            // failed mapping reclaim must terminalize the whole linear route
            // before the second member can be released.
            let route = match unsafe { route.remote_free_after_thread_exit(first) } {
                Err(DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure::Terminal {
                    route,
                    error: DynamicThreadExitFullOsSingletonPagesRemoteFreeError::Release,
                }) => route,
                Err(DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure::Terminal {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("failed OS aggregate unmap retains its release terminal: {error:?}");
                }
                Err(DynamicThreadExitFullOsSingletonPagesRemoteFreeFailure::Rejected {
                    route,
                    error,
                }) => {
                    core::mem::forget(route);
                    panic!("the exact first OS aggregate member is not rejected: {error:?}");
                }
                Ok(DynamicThreadExitFullOsSingletonPagesFreeResult::ReleasedPage(route)) => {
                    core::mem::forget(route);
                    panic!("the configured first OS aggregate unmap must not release a route");
                }
                Ok(DynamicThreadExitFullOsSingletonPagesFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the configured first OS aggregate unmap must not finish the route");
                }
            };
            assert_eq!(fault.observed(), 1);
            fault.set(fault::Plan::disabled());
            assert!(route.test_has_pending_os_release());
            assert_eq!(
                route.test_os_abandoned_page_head(),
                second_page.as_ptr(),
                "the failed first release unlinks only its exact member before parking the mapping owner"
            );
            assert!(route.test_os_page_map_entries_are_clear(&first_published));
            assert!(unsafe { route.test_page_for_block(first) }.is_null());
            assert_eq!(
                unsafe { route.test_page_for_block(second) },
                second_page.as_ptr(),
                "the second aggregate member remains PageMap-routable after the first terminal failure"
            );

            drop(route);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            assert!(owner.terminal_os_release.is_some());
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_handoff_releases_after_its_final_free() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the dynamic fixture allocates one regular medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the regular page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the regular medium page has one source bin");
            assert_eq!(memory.kind(), MemoryKind::Arena);
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Medium)
            );
            assert!(page_ref.reserved() > 1);
            assert_eq!(page_ref.used(), 1);
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `block` is the exact sole live allocation in this sole
            // nonfull medium page. The dynamic drain retains its source
            // post-TLS map/image/page authority through the final free.
            let handoff = match unsafe { drain.abandon_mapped_one_block(block) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the one-block medium page enters the dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("mapped abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(block), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            // SAFETY: this is the handoff's exact once-live client block. Its
            // source mapped-free path reaches all-free before reclaim and
            // releases the complete queue-detached arena span.
            let drain = match unsafe { handoff.remote_free_to_empty(block) } {
                Ok(drain) => drain,
                Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the mapped one-block final free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(block) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(block.as_ptr()) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_medium_handoff_keeps_first_free_mapped_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the dynamic fixture allocates its first regular medium block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first regular medium block remains PageMap-published");
            let second = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the dynamic fixture allocates its second regular medium block");
            assert_eq!(
                unsafe { allocator.page_for_block(second) },
                page.as_ptr(),
                "the two-block route starts from one shared medium page"
            );
            let (memory, bin) = {
                // SAFETY: both client blocks are live and the source page has
                // not crossed its dynamic thread-exit owner boundary.
                let page_ref = unsafe { page.as_ref() };
                let memory = page_ref.memid();
                let bin = crate::size_class::bin(page_ref.block_size())
                    .expect("the regular medium page has one source bin");
                assert_eq!(memory.kind(), MemoryKind::Arena);
                assert_eq!(
                    crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                    Some(crate::types::PageKind::Medium)
                );
                assert!(page_ref.reserved() > 2);
                assert_eq!(page_ref.used(), 2);
                (memory, bin)
            };
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `first` and `second` are the exact two current client
            // allocations in this sole nonfull medium source page. The
            // returned handoff serializes their distinct source free tails.
            let handoff = match unsafe { drain.abandon_mapped_two_block_medium(first) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the two-block medium page enters its dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("two-block mapped abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(unsafe { handoff.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            // SAFETY: this exact first live block leaves one client block in
            // the source page, so the failed-reclaim tail must re-unown its
            // mapped abandoned identity without terminal release.
            let handoff = match unsafe { handoff.remote_free_after_thread_exit(first) } {
                Ok(DynamicThreadExitMappedTwoBlockMediumFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitMappedTwoBlockMediumFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the first of two medium frees must not release the page");
                }
                Err(DynamicThreadExitMappedTwoBlockMediumRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockMediumRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the first two-block medium free preserves the mapped handoff: {error:?}");
                }
            };
            assert_eq!(unsafe { handoff.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            // SAFETY: `second` is now the handoff's exact final live client
            // block, so the source mapped tail clears the dynamic bit/count
            // before the queue-detached PageMap/arena release.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(second) } {
                Ok(DynamicThreadExitMappedTwoBlockMediumFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitMappedTwoBlockMediumFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final two-block medium free must release the page");
                }
                Err(DynamicThreadExitMappedTwoBlockMediumRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockMediumRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the final two-block medium free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first.as_ptr()) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_medium_handoff_rejects_one_live_block_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates one medium live block");
            let page = unsafe { allocator.page_for_block(block) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the medium page has one source bin");

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: this medium page has only one live allocation. The
            // two-block endpoint must refuse before source collection, queue
            // detachment, or dynamic bitmap/count publication.
            let drain = match unsafe { drain.abandon_mapped_two_block_medium(block) } {
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockMediumAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the one-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the one-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("one live medium block must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(unsafe { (*page).used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_medium_handoff_rejects_three_live_blocks_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its first medium live block");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its second medium live block");
            let third = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its third medium live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            assert_eq!(unsafe { allocator.page_for_block(third) }, page);
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the medium page has one source bin");
            assert_eq!(unsafe { (*page).used() }, 3);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: three exact live client blocks remain in the one source
            // medium page. The two-block endpoint cannot silently turn into a
            // general multi-free route.
            let drain = match unsafe { drain.abandon_mapped_two_block_medium(first) } {
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockMediumAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the three-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the three-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("three live medium blocks must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(third) }, page);
            assert_eq!(unsafe { (*page).used() }, 3);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_medium_handoff_rejects_another_page_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its first two-block-medium member");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its second two-block-medium member");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates a second live source page");
            let other_page = unsafe { allocator.page_for_block(other) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the medium page has one source bin");
            assert_eq!(unsafe { (*page).used() }, 2);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the selected page has exactly two live medium blocks,
            // but the extra live page proves this endpoint cannot skip the
            // rest of the source `MI_ABANDON` traversal.
            let drain = match unsafe { drain.abandon_mapped_two_block_medium(first) } {
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockMediumAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the extra-page refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the extra-page refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("another live source page must block the two-block medium handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { (*page).used() }, 2);
            assert_eq!(drain.test_page_count(), 2);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_medium_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its first medium block for source collection");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its second medium block for source collection");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the medium page has one source bin");

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the exact two-block source image remains queue-linked;
            // the one-shot seam fails force collection before source detach,
            // retaining the poisoned post-TLS drain as the only owner.
            let drain = match unsafe { drain.abandon_mapped_two_block_medium(first) } {
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockMediumAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockMediumAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal two-block mapped handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the two-block medium page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { (*page).used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_keeps_first_free_mapped_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the dynamic fixture allocates its first non-direct small block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first non-direct small block remains PageMap-published");
            let second = allocator
                .allocate(request, false)
                .expect("the dynamic fixture allocates its second non-direct small block");
            assert_eq!(
                unsafe { allocator.page_for_block(second) },
                page.as_ptr(),
                "the two-block route starts from one shared non-direct small page"
            );
            let (memory, bin) = {
                // SAFETY: both client blocks are live and the source page has
                // not crossed its dynamic thread-exit owner boundary.
                let page_ref = unsafe { page.as_ref() };
                let memory = page_ref.memid();
                let bin = crate::size_class::bin(page_ref.block_size())
                    .expect("the regular non-direct small page has one source bin");
                assert_eq!(memory.kind(), MemoryKind::Arena);
                assert_eq!(
                    crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                    Some(crate::types::PageKind::Small)
                );
                assert!(page_ref.block_size() > SMALL_SIZE_MAX);
                assert!(page_ref.block_size() <= SMALL_MAX_OBJ_SIZE);
                assert_eq!(memory.arena_memory().map(|memory| memory.slice_count), Some(1));
                assert!(page_ref.reserved() > 2);
                assert_eq!(page_ref.used(), 2);
                (memory, bin)
            };
            assert_eq!(allocator.queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the non-direct small source class starts with an empty direct image"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `first` and `second` are the exact two current client
            // allocations in this sole nonfull non-direct-small source page.
            let handoff = match unsafe {
                drain.abandon_mapped_two_block_non_direct_small(first)
            } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the two-block non-direct small page enters its dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("two-block non-direct-small abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(unsafe { handoff.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the non-direct queue removal preserves its source no-op direct update"
                );
            }

            // SAFETY: the first free leaves exactly one client block, so the
            // failed-reclaim tail must preserve the mapped bit/count pair.
            let handoff = match unsafe { handoff.remote_free_after_thread_exit(first) } {
                Ok(DynamicThreadExitMappedTwoBlockNonDirectSmallFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitMappedTwoBlockNonDirectSmallFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the first of two non-direct-small frees must not release the page");
                }
                Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    },
                )
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    },
                ) => {
                    core::mem::forget(handoff);
                    panic!("the first two-block non-direct-small free preserves the mapped handoff: {error:?}");
                }
            };
            assert_eq!(unsafe { handoff.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            // SAFETY: `second` is the handoff's final exact client block, so
            // only this free may clear the dynamic pair and release the page.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(second) } {
                Ok(DynamicThreadExitMappedTwoBlockNonDirectSmallFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitMappedTwoBlockNonDirectSmallFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final two-block non-direct-small free must release the page");
                }
                Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    },
                )
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    },
                ) => {
                    core::mem::forget(handoff);
                    panic!("the final two-block non-direct-small free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "terminal release does not manufacture a direct-small cache entry"
                );
            }
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first.as_ptr()) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_one_live_block_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let block = allocator
                .allocate(request, false)
                .expect("the fixture creates one non-direct-small live block");
            let page = unsafe { allocator.page_for_block(block) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the non-direct-small page has one source bin");
            assert!(unsafe { (*page).block_size() } > SMALL_SIZE_MAX);
            assert!(unsafe { (*page).block_size() } <= SMALL_MAX_OBJ_SIZE);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: this ordinary small page has only one live allocation.
            // The two-block endpoint must refuse before source collection,
            // queue detachment, or dynamic bitmap/count publication.
            let drain = match unsafe { drain.abandon_mapped_two_block_non_direct_small(block) } {
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the one-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the one-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("one live non-direct-small block must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(unsafe { (*page).used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the pre-detach refusal preserves the ordinary small empty direct image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_three_live_blocks_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first non-direct-small live block");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second non-direct-small live block");
            let third = allocator
                .allocate(request, false)
                .expect("the fixture creates its third non-direct-small live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            assert_eq!(unsafe { allocator.page_for_block(third) }, page);
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the non-direct-small page has one source bin");
            assert_eq!(unsafe { (*page).used() }, 3);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: three exact live client blocks remain in the one source
            // ordinary-small page. The endpoint cannot silently turn into a
            // generic multi-free route.
            let drain = match unsafe { drain.abandon_mapped_two_block_non_direct_small(first) } {
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the three-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the three-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("three live non-direct-small blocks must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(third) }, page);
            assert_eq!(unsafe { (*page).used() }, 3);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_another_page_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first two-block ordinary-small member");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second two-block ordinary-small member");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates a second live source page");
            let other_page = unsafe { allocator.page_for_block(other) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the non-direct-small page has one source bin");
            assert_eq!(unsafe { (*page).used() }, 2);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the selected page has exactly two live ordinary-small
            // blocks, but the extra live page proves this endpoint cannot skip
            // the rest of the source `MI_ABANDON` traversal.
            let drain = match unsafe { drain.abandon_mapped_two_block_non_direct_small(first) } {
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the extra-page refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the extra-page refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("another live source page must block the two-block non-direct-small handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { (*page).used() }, 2);
            assert_eq!(drain.test_page_count(), 2);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its first direct-small live block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let second = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its second direct-small live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            assert!(unsafe { page.as_ref().block_size() } <= SMALL_SIZE_MAX);
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the direct-small source page owns a rounded cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: this is a two-live-block direct-small page. The normal
            // small endpoint must reject its distinct partial collector and
            // rounded direct-cache image before any source mutation.
            let drain = match unsafe { drain.abandon_mapped_two_block_non_direct_small(first) } {
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the direct-small refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the direct-small refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a direct-small page must not enter the non-direct-small handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "the class refusal preserves the complete direct-small source cache"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first ordinary-small block for source collection");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second ordinary-small block for source collection");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the non-direct-small page has one source bin");

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the exact two-block ordinary-small source image remains
            // queue-linked; the one-shot seam fails force collection before
            // source detach, retaining the poisoned post-TLS drain as the only
            // owner.
            let drain = match unsafe { drain.abandon_mapped_two_block_non_direct_small(first) } {
                Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error: DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonError::Collection,
                    },
                ) => drain,
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal two-block ordinary-small handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the two-block ordinary-small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { (*page).used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "collection failure preserves the ordinary small empty direct image"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_direct_small_handoff_keeps_partial_head_mapped_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the dynamic fixture allocates its first direct-small block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let second = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the dynamic fixture allocates its second direct-small block");
            assert_eq!(
                unsafe { allocator.page_for_block(second) },
                page.as_ptr(),
                "the two-block route starts from one shared direct-small page"
            );
            let (memory, bin) = {
                // SAFETY: both client blocks are live and the source page has
                // not crossed its dynamic thread-exit owner boundary.
                let page_ref = unsafe { page.as_ref() };
                let memory = page_ref.memid();
                let bin = crate::size_class::bin(page_ref.block_size())
                    .expect("the direct-small page has one source bin");
                assert_eq!(memory.kind(), MemoryKind::Arena);
                assert_eq!(
                    crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                    Some(crate::types::PageKind::Small)
                );
                assert!(page_ref.block_size() <= SMALL_SIZE_MAX);
                assert!(page_ref.reserved() >= 16);
                assert_eq!(memory.arena_memory().map(|memory| memory.slice_count), Some(1));
                assert_eq!(page_ref.used(), 2);
                (memory, bin)
            };
            assert_eq!(allocator.queue_count(bin), Some(1));
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the direct-small source page owns its complete rounded direct-cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `first` and `second` are the exact two current client
            // allocations in this sole nonfull direct-small source page. Its
            // complete rounded cache image and partial collector remain fixed
            // through the returned linear handoff.
            let handoff = match unsafe { drain.abandon_mapped_two_block_direct_small(first) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the two-block direct-small page enters its dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("two-block direct-small abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(unsafe { handoff.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "direct-small queue removal clears its complete source cache range before count removal"
                );
            }

            // SAFETY: source partial collection leaves `first` as the owned
            // atomic head, so this first client free preserves the mapped
            // identity and the observed used count until `second` reaches the
            // final collector path.
            let handoff = match unsafe { handoff.remote_free_after_thread_exit(first) } {
                Ok(DynamicThreadExitMappedTwoBlockDirectSmallFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitMappedTwoBlockDirectSmallFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the first direct-small partial free must not release the page");
                }
                Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    },
                )
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    },
                ) => {
                    core::mem::forget(handoff);
                    panic!("the first direct-small partial free preserves the mapped handoff: {error:?}");
                }
            };
            assert_eq!(unsafe { handoff.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(
                unsafe { page.as_ref().used() },
                2,
                "the direct-small partial collector leaves its first published head uncollected"
            );
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            // SAFETY: `second` is the handoff's final exact client block. Its
            // partial collector consumes the retained first head and then the
            // current head, so only this free clears the dynamic pair and
            // releases the page.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(second) } {
                Ok(DynamicThreadExitMappedTwoBlockDirectSmallFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitMappedTwoBlockDirectSmallFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final direct-small partial free must release the page");
                }
                Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    },
                )
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    },
                ) => {
                    core::mem::forget(handoff);
                    panic!("the final direct-small partial free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "terminal release cannot manufacture a direct-cache entry"
                );
            }
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first.as_ptr()) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_direct_small_handoff_refuses_stale_direct_cache_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its first direct-small live block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let second = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its second direct-small live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            let stale_index = direct_before
                .iter()
                .position(|direct| *direct == Some(page.as_ptr()))
                .expect("the direct-small page owns at least one rounded direct-cache entry");
            assert!(
                allocator.set_direct_page_for_test(stale_index, crate::types::EMPTY_PAGE.as_ptr()),
                "the focused corruption seam changes one rounded direct-cache slot"
            );
            let stale_image = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_ne!(stale_image, direct_before);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: both allocations remain current in the exact source
            // page, but the stale rounded cache image must reject before
            // collection, queue removal, or page-count mutation.
            let drain = match unsafe { drain.abandon_mapped_two_block_direct_small(first) } {
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("stale direct-cache refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("stale direct-cache refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a stale rounded direct-cache image must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in stale_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "stale direct-cache refusal preserves the complete source cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_one_live_block_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one direct-small live block");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the direct-small page remains PageMap-published");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: this direct-small page has only one live allocation.
            // The two-block endpoint must refuse before source collection,
            // cache mutation, queue detachment, or bitmap/count publication.
            let drain = match unsafe { drain.abandon_mapped_two_block_direct_small(block) } {
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockDirectSmallAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the one-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the one-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("one live direct-small block must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "the pre-detach refusal preserves the rounded direct-cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_three_live_blocks_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its first direct-small live block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let second = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its second direct-small live block");
            let third = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its third direct-small live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { allocator.page_for_block(third) }, page.as_ptr());
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_eq!(unsafe { page.as_ref().used() }, 3);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: three exact client blocks remain in the one source
            // direct-small page. The endpoint cannot silently become a
            // generic multi-free partial-collector route.
            let drain = match unsafe { drain.abandon_mapped_two_block_direct_small(first) } {
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockDirectSmallAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the three-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the three-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("three live direct-small blocks must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(third) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 3);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "the three-block refusal preserves the rounded direct-cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_non_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates its first non-direct-small live block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the non-direct-small page remains PageMap-published");
            let second = allocator
                .allocate(request, false)
                .expect("the fixture creates its second non-direct-small live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the non-direct-small page has one source bin");
            assert!(unsafe { page.as_ref().block_size() } > SMALL_SIZE_MAX);
            assert!(unsafe { page.as_ref().block_size() } <= SMALL_MAX_OBJ_SIZE);
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(direct_before.iter().all(|direct| {
                *direct == Some(crate::types::EMPTY_PAGE.as_ptr())
            }));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: this is a two-live-block non-direct small page. The
            // direct endpoint must reject its normal collector and empty
            // direct-cache image before any source mutation.
            let drain = match unsafe { drain.abandon_mapped_two_block_direct_small(first) } {
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockDirectSmallAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the non-direct-small refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the non-direct-small refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a non-direct-small page must not enter the direct-small handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "the class refusal preserves the ordinary-small empty direct-cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_another_page_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its first direct-small two-block member");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let second = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its second direct-small two-block member");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates a second live source page");
            let other_page = unsafe { allocator.page_for_block(other) };
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_eq!(unsafe { page.as_ref().used() }, 2);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the selected page has exactly two live direct-small
            // blocks, but the extra live page proves this endpoint cannot skip
            // the rest of source `MI_ABANDON` traversal.
            let drain = match unsafe { drain.abandon_mapped_two_block_direct_small(first) } {
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("the extra-page refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the extra-page refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("another live source page must block the direct-small two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 2);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "the extra-page refusal preserves the rounded direct-cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_direct_small_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its first direct-small block for source collection");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let second = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates its second direct-small block for source collection");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the exact direct-small two-block source image remains
            // queue-linked; the one-shot seam fails force collection before
            // direct-cache, queue, or count mutation and retains the poisoned
            // post-TLS drain as the only owner.
            let drain = match unsafe { drain.abandon_mapped_two_block_direct_small(first) } {
                Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error: DynamicThreadExitMappedTwoBlockDirectSmallAbandonError::Collection,
                    },
                ) => drain,
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(
                    DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::RetainedDrain {
                        drain,
                        error,
                    },
                ) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal two-block direct-small handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the two-block direct-small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "collection failure preserves the complete rounded direct-cache image"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_keeps_first_free_mapped_then_releases_complete_span() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the dynamic fixture allocates its first regular large block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the first regular large block remains PageMap-published");
            let second = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the dynamic fixture allocates its second regular large block");
            assert_eq!(
                unsafe { allocator.page_for_block(second) },
                page.as_ptr(),
                "the two-block route starts from one shared large page"
            );
            let (memory, bin, slice_start, span_size, slice_index, arena_ptr) = {
                // SAFETY: both client blocks are live and the source page has
                // not crossed its dynamic thread-exit owner boundary.
                let page_ref = unsafe { page.as_ref() };
                let memory = page_ref.memid();
                let arena_memory = memory
                    .arena_memory()
                    .expect("the dynamic large page retains arena provenance");
                let slice_start = unsafe { ArenaView::from_ptr(arena_memory.arena) }
                    .and_then(|arena| arena.slice_start(arena_memory.slice_index as usize))
                    .expect("the dynamic large span begins in its published arena");
                let span_size = arena_memory.slice_count as usize * ARENA_SLICE_SIZE;
                let bin = crate::size_class::bin(page_ref.block_size())
                    .expect("the regular large page has one source bin");
                assert_eq!(memory.kind(), MemoryKind::Arena);
                assert_eq!(
                    crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                    Some(crate::types::PageKind::Large)
                );
                assert_eq!(
                    span_size / ARENA_SLICE_SIZE,
                    64,
                    "the two-block large handoff retains its complete source span"
                );
                assert!(page_ref.reserved() > 2);
                assert_eq!(page_ref.used(), 2);
                (
                    memory,
                    bin,
                    slice_start,
                    span_size,
                    arena_memory.slice_index as usize,
                    arena_memory.arena,
                )
            };
            assert_eq!(allocator.queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "a large source page has no direct-cache image"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `first` and `second` are the exact two current client
            // allocations in this sole nonfull large source page. The
            // returned handoff serializes their distinct normal free tails.
            let handoff = match unsafe { drain.abandon_mapped_two_block_large(first) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the two-block large page enters its dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("two-block mapped abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(unsafe { handoff.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            let (handoff_slice_start, handoff_span_size) = handoff
                .test_arena_span()
                .expect("the two-block large handoff retains its complete arena span");
            assert_eq!(handoff_slice_start, slice_start);
            assert_eq!(handoff_span_size, span_size);
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "large queue removal leaves the no-op direct-cache image empty"
                );
            }
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert_eq!(
                    handoff.test_page_map_entry(slice_start.wrapping_add(offset)),
                    page.as_ptr(),
                    "mapped abandonment retains every large-span PageMap entry"
                );
            }

            // SAFETY: this exact first live block leaves one client block in
            // the source page, so the normal failed-reclaim tail must
            // re-unown the mapped identity without terminal release.
            let handoff = match unsafe { handoff.remote_free_after_thread_exit(first) } {
                Ok(DynamicThreadExitMappedTwoBlockLargeFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitMappedTwoBlockLargeFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the first of two large frees must not release the page");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the first two-block large free preserves the mapped handoff: {error:?}");
                }
            };
            assert_eq!(unsafe { handoff.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert_eq!(
                    handoff.test_page_map_entry(slice_start.wrapping_add(offset)),
                    page.as_ptr(),
                    "the first normal free preserves every large-span PageMap entry"
                );
            }

            // SAFETY: `second` is now the handoff's exact final live client
            // block, so the source mapped tail clears the dynamic bit/count
            // before the queue-detached PageMap/arena release.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(second) } {
                Ok(DynamicThreadExitMappedTwoBlockLargeFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitMappedTwoBlockLargeFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final two-block large free must release the page");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the final two-block large free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert!(unsafe { drain.test_page_for_block(second) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "terminal release cannot manufacture a direct-cache entry"
                );
            }
            assert!(drain.finish());
            let arena_view = unsafe { ArenaView::from_ptr(arena_ptr) }
                .expect("the released large span remains in its external arena");
            assert_eq!(
                unsafe { arena_view.slices_free() }
                    .expect("the external arena retains its free-slice bitmap")
                    .is_set_range(slice_index, span_size / ARENA_SLICE_SIZE),
                Some(true),
                "the final large free returns every arena slice to the source free bitmap"
            );
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_rejects_one_live_block_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates one large live block");
            let page = unsafe { allocator.page_for_block(block) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the large page has one source bin");

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: this large page has only one live allocation. The
            // two-block endpoint must refuse before source collection, queue
            // detachment, or dynamic bitmap/count publication.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(block) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the one-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the one-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("one live large block must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(unsafe { (*page).used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_rejects_three_live_blocks_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its first large live block");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its second large live block");
            let third = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its third large live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            assert_eq!(unsafe { allocator.page_for_block(third) }, page);
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the large page has one source bin");
            assert_eq!(unsafe { (*page).used() }, 3);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: three exact live client blocks remain in the one source
            // large page. The two-block endpoint cannot silently turn into a
            // general multi-free route.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(first) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the three-block refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the three-block refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("three live large blocks must not enter the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(third) }, page);
            assert_eq!(unsafe { (*page).used() }, 3);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_rejects_another_page_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its first two-block-large member");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its second two-block-large member");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates a second live source page");
            let other_page = unsafe { allocator.page_for_block(other) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the large page has one source bin");
            assert_eq!(unsafe { (*page).used() }, 2);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: the selected page has exactly two live large blocks,
            // but the extra live page proves this endpoint cannot skip the
            // rest of the source `MI_ABANDON` traversal.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(first) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the extra-page refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the extra-page refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("another live source page must block the two-block large handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { (*page).used() }, 2);
            assert_eq!(drain.test_page_count(), 2);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_rejects_medium_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its first medium boundary block");
            let page = unsafe { allocator.page_for_block(first) };
            let second = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates its second medium boundary block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page);
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the medium page has one source bin");
            assert_eq!(
                crate::size_class::page_kind_for_block_size(unsafe { (*page).block_size() }),
                Some(crate::types::PageKind::Medium)
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: both allocations are live in one medium page. The
            // large-only route must refuse them before source collection,
            // queue detachment, or dynamic bitmap/count publication.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(first) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("medium refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("medium refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a medium page must not enter the two-block large handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page);
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page);
            assert_eq!(unsafe { (*page).used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_rejects_singleton_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates a singleton class boundary page");
            let page = unsafe { allocator.page_for_block(block) };
            assert_eq!(
                crate::size_class::page_kind_for_block_size(unsafe { (*page).block_size() }),
                Some(crate::types::PageKind::Singleton)
            );
            assert_eq!(unsafe { (*page).used() }, 1);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: this live singleton crosses the large size boundary but
            // is not a regular `PageKind::Large` page. The two-block large
            // route must reject before source collection or queue detachment.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(block) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("singleton refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("singleton refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a singleton page must not enter the two-block large handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(unsafe { (*page).used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_refuses_stale_direct_cache_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its first large live block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published");
            let second = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its second large live block");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the large page has one source bin");
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert!(
                allocator.set_direct_page_for_test(0, page.as_ptr()),
                "the focused corruption seam writes one forbidden large direct-cache entry"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: both allocations remain current in the exact source
            // page, but a large page must never carry a direct-cache image.
            // The route must refuse before collection, queue removal, or
            // page-count mutation rather than repairing the stale state.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(first) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the stale direct-cache refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the stale direct-cache refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a stale large direct-cache entry must block the two-block handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            assert_eq!(drain.test_direct_page(0), Some(page.as_ptr()));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its first large block for source collection");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published");
            let second = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its second large block for source collection");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let page_ref = unsafe { page.as_ref() };
            let arena_memory = page_ref
                .memid()
                .arena_memory()
                .expect("the large source page retains arena provenance");
            let slice_start = unsafe { ArenaView::from_ptr(arena_memory.arena) }
                .and_then(|arena| arena.slice_start(arena_memory.slice_index as usize))
                .expect("the complete large source span begins in its arena");
            let span_size = arena_memory.slice_count as usize * ARENA_SLICE_SIZE;
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the large page has one source bin");
            assert_eq!(span_size / ARENA_SLICE_SIZE, 64);

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the exact two-block large source image remains queue-
            // linked; the one-shot seam fails force collection before source
            // detach and retains the poisoned post-TLS drain as the only
            // owner of its full PageMap span.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(first) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal two-block large handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the two-block large page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "collection failure preserves the large no-op direct-cache image"
                );
            }
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert_eq!(
                    drain.test_page_map_entry(slice_start.wrapping_add(offset)),
                    page.as_ptr(),
                    "collection failure preserves every large-span PageMap entry"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_retains_false_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its first large block for false collection");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published");
            let second = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its second large block for false collection");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let page_ref = unsafe { page.as_ref() };
            let arena_memory = page_ref
                .memid()
                .arena_memory()
                .expect("the large source page retains arena provenance");
            let slice_start = unsafe { ArenaView::from_ptr(arena_memory.arena) }
                .and_then(|arena| arena.slice_start(arena_memory.slice_index as usize))
                .expect("the complete large source span begins in its arena");
            let span_size = arena_memory.slice_count as usize * ARENA_SLICE_SIZE;
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the large page has one source bin");

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_false_failure_once();
            // SAFETY: force collection completes over the unchanged exact
            // two-block source image, then the test-only false-force seam
            // fails before remote detach, queue mutation, or publication.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(first) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected false collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("false collection fails before a terminal two-block large handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected false collection failure cannot abandon the large page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 2);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "false collection failure preserves the large no-op direct-cache image"
                );
            }
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert_eq!(
                    drain.test_page_map_entry(slice_start.wrapping_add(offset)),
                    page.as_ptr(),
                    "false collection failure preserves every large-span PageMap entry"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_two_block_large_handoff_retains_post_force_shape_mismatch() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its first large block for force collection");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published");
            let second = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates its second large block for force collection");
            assert_eq!(unsafe { allocator.page_for_block(second) }, page.as_ptr());
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the large page has one source bin");

            // SAFETY: `first` is a live same-Theap allocation. The scoped
            // producer transfers that exact client alias into the source
            // remote head before post-TLS force collection; `second` remains
            // the handoff's only current caller alias.
            let producer = unsafe { allocator.begin_remote_free(first) }
                .expect("the large page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote large block publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });
            assert_eq!(unsafe { page.as_ref().used() }, 2);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: source force collection consumes the published remote
            // block, so the post-force page no longer satisfies the exact
            // two-client handoff shape. This is past the collection boundary:
            // it must retain a poisoned drain rather than expose a retryable
            // differently-classified page owner.
            let drain = match unsafe { drain.abandon_mapped_two_block_large(second) } {
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedTwoBlockLargeAbandonError::NotMappedTwoBlock,
                }) => drain,
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("post-force shape mismatch retains the source drain: {error:?}");
                }
                Err(DynamicThreadExitMappedTwoBlockLargeAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("post-force shape mismatch does not detach the large page: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a post-force one-block large page must not enter the two-block handoff");
                }
            };
            assert!(
                drain.test_has_collection_poison(),
                "a post-collection shape mismatch cannot expose a retryable drain"
            );
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(second) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_large_handoff_releases_its_complete_span_after_final_free() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the dynamic fixture allocates one regular large page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the regular large page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let arena_memory = memory
                .arena_memory()
                .expect("the dynamic large page retains arena provenance");
            let slice_start = unsafe { ArenaView::from_ptr(arena_memory.arena) }
                .and_then(|arena| arena.slice_start(arena_memory.slice_index as usize))
                .expect("the dynamic large span begins in its published arena");
            let span_size = arena_memory.slice_count as usize * ARENA_SLICE_SIZE;
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the regular large page has one source bin");
            assert_eq!(memory.kind(), MemoryKind::Arena);
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Large)
            );
            assert_eq!(
                span_size / ARENA_SLICE_SIZE,
                64,
                "the large handoff retains its complete source span"
            );
            assert!(page_ref.reserved() > 1);
            assert_eq!(page_ref.used(), 1);
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `block` is the exact sole live allocation in this sole
            // nonfull large page. The dynamic drain retains its source
            // post-TLS map/image/page authority through the final free.
            let handoff = match unsafe { drain.abandon_mapped_one_block_large(block) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the one-block large page enters the dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("mapped abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(block), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            // SAFETY: this is the handoff's exact once-live client block. Its
            // normal mapped-free path reaches all-free before reclaim and
            // releases every PageMap entry in the 64-slice large span.
            let drain = match unsafe { handoff.remote_free_to_empty(block) } {
                Ok(drain) => drain,
                Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the mapped one-block large final free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(block) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_large_handoff_rejects_medium_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates the medium boundary page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the medium page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the medium page has one source bin");
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Medium)
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `block` is a live medium allocation. The large-only
            // route must refuse it before force collection, queue detach, or
            // dynamic bitmap/count publication.
            let drain = match unsafe { drain.abandon_mapped_one_block_large(block) } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::NotMappedOneBlock,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("medium refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("medium refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a medium page must not enter the large handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            // General dynamic post-TLS traversal remains outside this slice.
            // Retain the unchanged owner after proving class refusal did not
            // detach or abandon the medium page.
            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_large_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(MEDIUM_MAX_OBJ_SIZE + WORD_SIZE, false)
                .expect("the fixture creates one large page for source collection");
            let page = unsafe { allocator.page_for_block(block) };
            let page_ref = unsafe { &*page };
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the large page has one source bin");
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Large)
            );

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `block` remains the sole live large allocation. The
            // one-shot seam fails source force collection before queue
            // detachment, so the post-TLS drain—not a retryable live
            // allocator—must retain it.
            let drain = match unsafe { drain.abandon_mapped_one_block_large(block) } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal mapped handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the large page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_handoff_rejects_before_detach_when_another_page_is_live() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let regular = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates the medium one-block page");
            let regular_page = unsafe { allocator.page_for_block(regular) };
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates another live arena page");
            let other_page = unsafe { allocator.page_for_block(other) };

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `regular` names the live medium page, but the second
            // live page proves this narrow handoff must not skip source
            // traversal order.
            let drain = match unsafe { drain.abandon_mapped_one_block(regular) } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole-page check is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the sole-page check is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a second live page must block the dynamic mapped handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(regular) }, regular_page);
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { (*regular_page).used() }, 1);
            assert_eq!(drain.test_page_count(), 2);

            // General dynamic post-TLS traversal remains deliberately outside
            // this slice. Retain this unchanged source image after proving the
            // refusal did not detach either page.
            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates one medium page for source collection");
            let page = unsafe { allocator.page_for_block(block) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the medium page has one source bin");

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `block` remains the sole live allocation. The one-shot
            // seam fails source force collection before queue detachment, so
            // the post-TLS drain—not a retryable live allocator—must retain it.
            let drain = match unsafe { drain.abandon_mapped_one_block(block) } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal mapped handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the medium page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_handoff_reabandons_after_mostly_used_frees_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic large page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full large page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Large)
            );
            assert!(reserved > 8, "the source mostly-used boundary has a nonzero prefix");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the large page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: the vector holds every live allocation in this one full
            // large page. The post-TLS drain must retain the exact source map,
            // Theap, dynamic arena image, and all 64 registered slices through
            // the sequential failed-reclaim frees below.
            let mut handoff = match unsafe { drain.abandon_full_large(blocks[0]) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole full large page enters its dynamic unmapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullLargeAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("full-large abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[0]), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the full-large handoff retains its complete arena span");
            assert_eq!(
                span_size / ARENA_SLICE_SIZE,
                64,
                "the full-large handoff retains every source arena slice"
            );
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "full-large abandonment cannot leave a direct-cache entry"
                );
            }

            let unmapped_frees = reserved / 8;
            for block in blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each loop iteration transfers one still-live
                // canonical client allocation exactly once to its linear
                // failed-reclaim handoff.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullLargeFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullLargeFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the mostly-used prefix cannot release the full large page");
                    }
                    Err(DynamicThreadExitFullLargeRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullLargeRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the unmapped full-large free remains source-shaped: {error:?}");
                    }
                };
            }
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());

            // The first free beyond reserved / 8 is the exact source
            // unmapped-to-mapped reabandon boundary.
            handoff = match unsafe {
                handoff.remote_free_after_thread_exit(blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullLargeFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitFullLargeFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the reabandon boundary leaves live large blocks");
                }
                Err(DynamicThreadExitFullLargeRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitFullLargeRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the full-large reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            for block in blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(reserved - unmapped_frees - 2)
            {
                // SAFETY: the handoff remains linear and each selected block
                // is still live until this source-shaped remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullLargeFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullLargeFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the penultimate full-large frees leave one block live");
                    }
                    Err(DynamicThreadExitFullLargeRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullLargeRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full-large free remains source-shaped: {error:?}");
                    }
                };
            }
            let last = *blocks.last().expect("the full page has one final allocation");
            // SAFETY: last is now the handoff's exact final live client
            // allocation, so the mapped tail must clear its paired dynamic
            // bit/count and release the complete arena span.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullLargeFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullLargeFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final full-large free releases its arena span");
                }
                Err(DynamicThreadExitFullLargeRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitFullLargeRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the final full-large free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_handoff_rejects_a_full_medium_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the medium page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` remains a current allocation in a full medium
            // page. Full-large admission is wholly pre-collection and must
            // preserve the source full queue and PageMap entry.
            let drain = match unsafe { drain.abandon_full_large(first) } {
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullLargeAbandonError::NotFullLarge,
                }) => drain,
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("full-large class admission rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullLargeAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("full-large class admission rejects before detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a full medium page cannot enter the full-large handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic large page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the large page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `first` remains one current allocation in the full
            // large page. The deterministic source collection failure occurs
            // before queue detachment and retains the poisoned post-TLS drain.
            let drain = match unsafe { drain.abandon_full_large(first) } {
                Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullLargeAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected full-large collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullLargeAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal full-large handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full large page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_one_remote_force_collects_to_mapped_handoff_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic large page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full large page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Large)
            );
            assert!(reserved > 1, "the large source page has a joined-free predecessor");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the large page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // Preserve one source remote free until `MI_ABANDON` force
            // collection. `blocks[0]` is no longer a client alias after
            // publication; `blocks[1]` remains the exact live witness for
            // the source page-abandon call.
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full large page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: force collection consumes the one already joined remote
            // block. The other entries remain the exact live client set of
            // this sole full large page and are transferred linearly below.
            let mut handoff = match unsafe {
                drain.abandon_full_large_after_force_collect_to_mapped(blocks[1])
            } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("one joined remote large free enters the dynamic mapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullLargeAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("one joined remote large free does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[1]), page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, reserved - 1);
            assert!(
                !crate::types::page_queue::page_is_in_full(unsafe { page.as_ref() }),
                "full-queue removal clears the source full flag after force collection"
            );
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the mapped full-large handoff retains its complete arena span");
            assert_eq!(
                span_size / ARENA_SLICE_SIZE,
                64,
                "the mapped full-large handoff retains every source arena slice"
            );
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert_eq!(
                    handoff.test_page_map_entry(slice_start.wrapping_add(offset)),
                    page.as_ptr(),
                    "mapped abandonment retains every large PageMap slice"
                );
            }

            for block in blocks.iter().copied().skip(1).take(reserved - 2) {
                // SAFETY: the handoff remains linear and each selected block
                // remains live after the one force-collected remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullLargeFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullLargeFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("a nonfinal mapped large free cannot release the page");
                    }
                    Err(DynamicThreadExitFullLargeRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullLargeRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full-large free remains source-shaped: {error:?}");
                    }
                };
                assert_eq!(handoff.test_abandoned_count(), Some(1));
            }
            let last = *blocks.last().expect("the full large page has a last live block");
            // SAFETY: the remote source block was force-collected, so `last`
            // is now the final live client and must clear the exact mapped
            // bitmap/count pair before the complete 64-slice release.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullLargeFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullLargeFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped large free releases the arena span");
                }
                Err(DynamicThreadExitFullLargeRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitFullLargeRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped large free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert!(unsafe { page_map.checked_lookup(slice_start.wrapping_add(offset)) }.is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_one_remote_force_collect_route_rejects_full_medium_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the medium page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` remains a current allocation in a full medium
            // page. The force-collected large admission must reject before it
            // observes or mutates any source remote-free state.
            let drain = match unsafe {
                drain.abandon_full_large_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullLargeAbandonError::NotFullLarge,
                }) => drain,
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("full-large class admission rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullLargeAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("full-large class admission rejects before detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a full medium page cannot enter the force-collected large handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_large_one_remote_force_collect_route_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic large page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the large page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full large page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the seam fails source force collection before it can
            // consume the already joined remote block or detach BIN_FULL.
            let drain = match unsafe {
                drain.abandon_full_large_after_force_collect_to_mapped(blocks[1])
            } {
                Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullLargeAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullLargeAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullLargeAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected force-collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullLargeAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal force-collected handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full large page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(blocks[1]) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_one_remote_force_collects_to_mapped_handoff_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full medium page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Medium)
            );
            assert!(reserved > 1, "the medium source page has a joined-free predecessor");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the medium page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            // Preserve one source remote free until `MI_ABANDON` force
            // collection. `blocks[0]` is no longer a client alias after
            // publication; `blocks[1]` remains the exact live witness for
            // the source page-abandon call.
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full medium page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: force collection consumes the one already joined remote
            // block. The other entries remain the exact live client set of
            // this sole full medium page and are transferred linearly below.
            let mut handoff = match unsafe {
                drain.abandon_full_medium_after_force_collect_to_mapped(blocks[1])
            } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("one joined remote medium free enters the dynamic mapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullMediumAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("one joined remote medium free does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[1]), page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, reserved - 1);
            assert!(
                !crate::types::page_queue::page_is_in_full(unsafe { page.as_ref() }),
                "full-queue removal clears the source full flag after force collection"
            );
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the mapped full-medium handoff retains its complete arena span");
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert_eq!(
                    handoff.test_page_map_entry(slice_start.wrapping_add(offset)),
                    page.as_ptr(),
                    "mapped abandonment retains every medium PageMap slice"
                );
            }

            for block in blocks.iter().copied().skip(1).take(reserved - 2) {
                // SAFETY: the handoff remains linear and each selected block
                // remains live after the one force-collected remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullMediumFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullMediumFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("a nonfinal mapped medium free cannot release the page");
                    }
                    Err(DynamicThreadExitFullMediumRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullMediumRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full-medium free remains source-shaped: {error:?}");
                    }
                };
                assert_eq!(handoff.test_abandoned_count(), Some(1));
            }
            let last = *blocks.last().expect("the full medium page has a last live block");
            // SAFETY: the remote source block was force-collected, so `last`
            // is now the final live client and must clear the exact mapped
            // bitmap/count pair before the complete arena release.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullMediumFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullMediumFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped medium free releases the arena page");
                }
                Err(DynamicThreadExitFullMediumRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitFullMediumRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped medium free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            for offset in (0..span_size).step_by(ARENA_SLICE_SIZE) {
                assert!(unsafe { page_map.checked_lookup(slice_start.wrapping_add(offset)) }.is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_one_remote_force_collect_route_rejects_regular_medium_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one regular dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the regular medium page remains PageMap-published before thread exit");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the regular medium page has one source bin");
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` remains a current allocation in a nonfull
            // regular medium page. The full-origin force-collected route must
            // reject before it sees any source remote-free state or detaches
            // the ordinary queue member.
            let drain = match unsafe {
                drain.abandon_full_medium_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullMediumAbandonError::NotFullMedium,
                }) => drain,
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("regular-medium admission rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullMediumAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("regular-medium admission rejects before detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a regular medium page cannot enter the force-collected handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_one_remote_force_collect_route_rejects_full_large_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = MEDIUM_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic large page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the large page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the large page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` remains a current allocation in a full large
            // page. The force-collected medium admission must reject before it
            // observes or mutates any source remote-free state.
            let drain = match unsafe {
                drain.abandon_full_medium_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullMediumAbandonError::NotFullMedium,
                }) => drain,
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("full-medium class admission rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullMediumAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("full-medium class admission rejects before detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a full large page cannot enter the force-collected medium handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_one_remote_force_collect_route_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the medium page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full medium page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the seam fails source force collection before it can
            // consume the already joined remote block or detach BIN_FULL.
            let drain = match unsafe {
                drain.abandon_full_medium_after_force_collect_to_mapped(blocks[1])
            } {
                Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullMediumAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected force-collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullMediumAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal force-collected handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full medium page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(blocks[1]) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_handoff_reabandons_after_mostly_used_frees_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full medium page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Medium)
            );
            assert!(reserved > 8, "the source mostly-used boundary has a nonzero prefix");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the medium page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(BIN_FULL), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: the vector holds every live allocation in this one full
            // medium page. The post-TLS drain retains the exact source map,
            // Theap, dynamic arena image, and page ownership through the
            // sequential failed-reclaim frees below.
            let mut handoff = match unsafe { drain.abandon_full_medium(blocks[0]) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole full medium page enters its dynamic unmapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullMediumAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("full medium abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[0]), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the full-medium handoff retains its complete arena span");
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "full-medium abandonment cannot leave a direct-cache entry"
                );
            }

            let unmapped_frees = reserved / 8;
            for block in blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each loop iteration transfers one still-live
                // canonical client allocation exactly once to its linear
                // failed-reclaim handoff.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullMediumFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullMediumFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the mostly-used prefix cannot release the full medium page");
                    }
                    Err(DynamicThreadExitFullMediumRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullMediumRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the unmapped full-medium free remains source-shaped: {error:?}");
                    }
                };
            }
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());

            // The first free beyond `reserved / 8` is the exact source
            // unmapped-to-mapped reabandon boundary.
            handoff = match unsafe {
                handoff.remote_free_after_thread_exit(blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullMediumFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitFullMediumFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the reabandon boundary leaves live medium blocks");
                }
                Err(DynamicThreadExitFullMediumRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitFullMediumRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the full-medium reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            for block in blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(reserved - unmapped_frees - 2)
            {
                // SAFETY: the handoff remains linear and each selected block
                // is still live until this source-shaped remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullMediumFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullMediumFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the penultimate full-medium frees leave one block live");
                    }
                    Err(DynamicThreadExitFullMediumRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullMediumRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full-medium free remains source-shaped: {error:?}");
                    }
                };
            }
            let last = *blocks.last().expect("the full page has one final allocation");
            // SAFETY: `last` is now the handoff's exact final live client
            // allocation, so the mapped tail must clear its paired dynamic
            // bit/count and release the complete arena span.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullMediumFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullMediumFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final full-medium free releases its arena span");
                }
                Err(DynamicThreadExitFullMediumRemoteFreeFailure::Rejected { handoff, error })
                | Err(DynamicThreadExitFullMediumRemoteFreeFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the final full-medium free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first.as_ptr()) }.is_null());
            for offset in (0..span_size).step_by(crate::config::ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_handoff_rejects_before_detach_when_another_page_is_live() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains page-map published");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the medium page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates another live arena page");
            let other_page = unsafe { allocator.page_for_block(other) };

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `blocks[0]` names a full medium page, but `other`
            // proves this bounded source traversal cannot detach it early.
            let drain = match unsafe { drain.abandon_full_medium(blocks[0]) } {
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullMediumAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the full-medium sole-page check is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullMediumAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("the full-medium sole-page check is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a second live page must block the dynamic full-medium handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(blocks[0]) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 2);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_medium_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_MAX_OBJ_SIZE + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the medium page remains page-map published");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the medium page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `first` remains one current allocation in the full
            // page. The deterministic source collection failure occurs before
            // queue detachment and must retain the poisoned post-TLS drain.
            let drain = match unsafe { drain.abandon_full_medium(first) } {
                Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullMediumAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullMediumAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitFullMediumAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected full-medium collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullMediumAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal full-medium handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full medium page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(BIN_FULL), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_one_remote_force_collects_to_mapped_handoff_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the non-direct small page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full non-direct small page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(
                page_ref.block_size() > SMALL_SIZE_MAX
                    && page_ref.block_size() <= SMALL_MAX_OBJ_SIZE,
                "the source branch is the non-direct small class"
            );
            assert!(reserved > 1, "the source branch has a joined-free predecessor");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            assert!(
                !crate::types::page_queue::page_is_in_full(unsafe { page.as_ref() }),
                "a full non-direct small page remains in its ordinary source bin"
            );
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the non-direct source class has no direct-cache image"
                );
            }

            // Preserve exactly one source remote free until `MI_ABANDON`
            // force collection. `blocks[0]` is no longer a client alias
            // after publication; `blocks[1]` remains the exact live witness
            // for source page abandonment.
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full non-direct small page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: force collection consumes the one already joined remote
            // block. The remaining entries are the exact live client set of
            // this sole full non-direct small page and are transferred
            // linearly below.
            let mut handoff = match unsafe {
                drain.abandon_full_non_direct_small_after_force_collect_to_mapped(blocks[1])
            } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("one joined remote non-direct-small free enters the dynamic mapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("one joined remote non-direct-small free does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[1]), page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, reserved - 1);
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the mapped full non-direct-small handoff retains its complete arena span");
            assert_eq!(span_size, ARENA_SLICE_SIZE);
            assert_eq!(
                handoff.test_page_map_entry(slice_start),
                page.as_ptr(),
                "immediate mapped abandonment retains the complete non-direct-small PageMap span"
            );

            for block in blocks.iter().copied().skip(1).take(reserved - 2) {
                // SAFETY: the handoff remains linear and each selected block
                // remains live after the one force-collected remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullNonDirectSmallFreeResult::StillLive(handoff)) => {
                        handoff
                    }
                    Ok(DynamicThreadExitFullNonDirectSmallFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("a nonfinal mapped non-direct-small free cannot release the page");
                    }
                    Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full non-direct-small free remains source-shaped: {error:?}");
                    }
                };
                assert_eq!(handoff.test_abandoned_count(), Some(1));
            }
            let last = *blocks
                .last()
                .expect("the full non-direct small page has a last live block");
            // SAFETY: the remote source block was force-collected, so `last`
            // is now the final live client and must clear the exact mapped
            // bitmap/count pair before the arena release.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullNonDirectSmallFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullNonDirectSmallFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped non-direct-small free releases the arena page");
                }
                Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped non-direct-small free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(slice_start) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_rejects_regular_non_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one regular dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the regular non-direct small page remains PageMap-published before thread exit");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the regular non-direct small page has one source bin");
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` remains a current allocation in a nonfull
            // regular non-direct small page. The full-origin force-collected
            // route must reject before it sees source remote-free state or
            // detaches the ordinary queue member.
            let drain = match unsafe {
                drain.abandon_full_non_direct_small_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::NotFullNonDirectSmall,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("regular non-direct-small admission rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("regular non-direct-small admission rejects before detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a regular non-direct small page cannot enter the force-collected handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_rejects_full_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the direct-small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the full direct-small page retains its rounded source direct-cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` names a full direct-small page. This route must
            // reject it before source collection so its partial collector and
            // rounded direct-cache contract cannot be silently bypassed.
            let drain = match unsafe {
                drain.abandon_full_non_direct_small_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::NotFullNonDirectSmall,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("full direct-small class rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("full direct-small class rejects before queue detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a full direct-small page cannot enter the force-collected non-direct handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "direct-small preflight rejection preserves the complete rounded source cache"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_refuses_stale_direct_cache_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the non-direct small page remains PageMap-published before thread exit");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full non-direct small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            assert!(
                allocator.set_direct_page_for_test(0, page.as_ptr()),
                "the focused corruption seam writes one forbidden direct-cache entry"
            );
            let stale_image = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_eq!(stale_image[0], Some(page.as_ptr()));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` names a full non-direct small page, but the
            // corrupted direct image proves this bounded route cannot conceal
            // malformed source cache state by queue detachment.
            let drain = match unsafe {
                drain.abandon_full_non_direct_small_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("stale non-direct-cache refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("stale non-direct-cache refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a stale non-direct cache image must not enter the force-collected handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in stale_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "stale non-direct-cache refusal preserves the complete source cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the non-direct small page remains PageMap-published before thread exit");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full non-direct small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full non-direct small page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the seam fails source force collection before it can
            // consume the already joined remote block or detach the ordinary
            // non-direct-small queue member.
            let drain = match unsafe {
                drain.abandon_full_non_direct_small_after_force_collect_to_mapped(blocks[1])
            } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected force-collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal force-collected handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full non-direct small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(blocks[1]) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_handoff_reabandons_after_mostly_used_frees_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the small page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full non-direct small page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(memory.kind(), MemoryKind::Arena);
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(page_ref.block_size() > SMALL_SIZE_MAX);
            assert!(page_ref.block_size() <= SMALL_MAX_OBJ_SIZE);
            assert!(reserved > 8, "the source mostly-used boundary has a nonzero prefix");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "a non-direct small page leaves every source direct slot empty"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: the vector holds every live allocation in this one full
            // ordinary-bin non-direct small page. The post-TLS drain retains
            // the exact source map, Theap, dynamic arena image, and page
            // ownership through the sequential failed-reclaim frees below.
            let mut handoff = match unsafe { drain.abandon_full_non_direct_small(blocks[0]) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole full non-direct small page enters its dynamic unmapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("full non-direct small abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[0]), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the full non-direct small handoff retains its complete arena span");
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "non-direct small abandonment cannot leave a direct-cache entry"
                );
            }

            let unmapped_frees = reserved / 8;
            for block in blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each loop iteration transfers one still-live
                // canonical client allocation exactly once to its linear
                // failed-reclaim handoff.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullNonDirectSmallFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullNonDirectSmallFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the mostly-used prefix cannot release the full non-direct small page");
                    }
                    Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the unmapped full non-direct small free remains source-shaped: {error:?}");
                    }
                };
            }
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());

            // The first free beyond `reserved / 8` is the exact source
            // unmapped-to-mapped reabandon boundary.
            handoff = match unsafe {
                handoff.remote_free_after_thread_exit(blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullNonDirectSmallFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitFullNonDirectSmallFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the reabandon boundary leaves live non-direct small blocks");
                }
                Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the full non-direct small reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            for block in blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(reserved - unmapped_frees - 2)
            {
                // SAFETY: the handoff remains linear and each selected block
                // is still live until this source-shaped remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullNonDirectSmallFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullNonDirectSmallFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the penultimate full non-direct small frees leave one block live");
                    }
                    Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full non-direct small free remains source-shaped: {error:?}");
                    }
                };
            }
            let last = *blocks.last().expect("the full page has one final allocation");
            // SAFETY: `last` is now the handoff's exact final live client
            // allocation, so the mapped tail must clear its paired dynamic
            // bit/count and release the complete arena span.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullNonDirectSmallFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullNonDirectSmallFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final full non-direct small free releases its arena span");
                }
                Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the final full non-direct small free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first.as_ptr()) }.is_null());
            for offset in (0..span_size).step_by(crate::config::ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_handoff_rejects_before_detach_when_another_page_is_live() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the small page remains PageMap-published");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates another live arena page");
            let other_page = unsafe { allocator.page_for_block(other) };

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `blocks[0]` names a full non-direct small page, but
            // `other` proves this bounded source traversal cannot detach it
            // early.
            let drain = match unsafe { drain.abandon_full_non_direct_small(blocks[0]) } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the full non-direct small sole-page check is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the full non-direct small sole-page check is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a second live page must block the dynamic full non-direct small handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(blocks[0]) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 2);

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_handoff_rejects_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            assert!(reserved >= 16);
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the direct-small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the full direct-small page retains its rounded source direct-cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `blocks[0]` names a full direct-small page. This route
            // must reject it before source collection so its partial collector
            // and rounded direct-cache contract cannot be silently bypassed.
            let drain = match unsafe { drain.abandon_full_non_direct_small(blocks[0]) } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::NotFullNonDirectSmall,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the direct-small class rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the direct-small class rejects before queue detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the non-direct full route must not accept direct-small geometry");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "direct-small preflight rejection preserves the complete rounded source cache"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_handoff_refuses_stale_direct_cache_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the small page remains PageMap-published");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full non-direct small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            assert!(
                allocator.set_direct_page_for_test(0, page.as_ptr()),
                "the focused corruption seam writes one forbidden direct-cache entry"
            );
            let stale_image = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_eq!(stale_image[0], Some(page.as_ptr()));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` names a full non-direct small page, but the
            // corrupted direct image proves this bounded route cannot conceal
            // malformed source cache state by queue detachment.
            let drain = match unsafe { drain.abandon_full_non_direct_small(first) } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("stale non-direct-cache refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("stale non-direct-cache refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a stale non-direct cache image must not enter the full handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in stale_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "stale non-direct-cache refusal preserves the complete source cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_non_direct_small_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the small page remains PageMap-published");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full non-direct small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `first` remains one current allocation in the full
            // ordinary-bin page. The deterministic source collection failure
            // occurs before queue detachment and retains the poisoned post-TLS
            // drain.
            let drain = match unsafe { drain.abandon_full_non_direct_small(first) } {
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullNonDirectSmallAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected full non-direct small collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullNonDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal full non-direct small handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full non-direct small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "non-direct small collection failure preserves the empty source direct-cache image"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_one_remote_force_collects_to_mapped_handoff_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full direct-small page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(memory.kind(), MemoryKind::Arena);
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(page_ref.block_size() <= SMALL_SIZE_MAX);
            assert!(reserved >= 16, "the partial collector keeps its source floor");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the direct-small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            assert!(
                !crate::types::page_queue::page_is_in_full(unsafe { page.as_ref() }),
                "a full direct-small page remains in its ordinary source bin"
            );
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the full direct-small page retains its rounded source direct-cache range"
            );

            // Preserve exactly one source remote free until `MI_ABANDON`
            // force collection. `blocks[0]` is no longer a client alias
            // after publication; `blocks[1]` remains the exact live witness
            // for the ordinary-bin owner-exit transition.
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full direct-small page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(bin), Some(1));

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: force collection consumes the one already joined remote
            // block. The remaining entries are the exact live client set of
            // this sole full direct-small page and are transferred linearly
            // through the mapped partial-collector tail below.
            let mut handoff = match unsafe {
                drain.abandon_full_direct_small_after_force_collect_to_mapped(blocks[1])
            } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("one joined remote direct-small free enters the dynamic mapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("one joined remote direct-small free does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[1]), page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, reserved - 1);
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the mapped full direct-small handoff retains its complete arena span");
            assert_eq!(span_size, ARENA_SLICE_SIZE);
            assert_eq!(
                handoff.test_page_map_entry(slice_start),
                page.as_ptr(),
                "immediate mapped abandonment retains the complete direct-small PageMap span"
            );
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "force-collected direct-small abandonment clears its rounded cache before page-count detach"
                );
            }

            for block in blocks.iter().copied().skip(1).take(reserved - 2) {
                // SAFETY: the handoff remains linear and each selected block
                // remains live after the one force-collected remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullDirectSmallFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullDirectSmallFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("a nonfinal mapped direct-small free cannot release the page");
                    }
                    Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full direct-small free remains source-shaped: {error:?}");
                    }
                };
                assert_eq!(handoff.test_abandoned_count(), Some(1));
            }
            let last = *blocks
                .last()
                .expect("the full direct-small page has a last live block");
            // SAFETY: the remote source block was force-collected, so `last`
            // is now the final live client. The partial collector must consume
            // its retained head and clear the exact mapped pair before release.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullDirectSmallFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullDirectSmallFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped direct-small free releases the arena page");
                }
                Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the final mapped direct-small free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "terminal release cannot manufacture a direct-cache entry"
                );
            }
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(slice_start) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_rejects_regular_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one regular dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the regular direct-small page remains PageMap-published before thread exit");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the regular direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the regular direct-small page retains its rounded source direct-cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` remains a current allocation in a nonfull
            // direct-small page. The full-origin force-collected route must
            // reject before it sees source remote-free state or changes the
            // rounded direct-cache image.
            let drain = match unsafe {
                drain.abandon_full_direct_small_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::NotFullDirectSmall,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("regular direct-small admission rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("regular direct-small admission rejects before detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a regular direct-small page cannot enter the force-collected handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "regular direct-small rejection preserves the complete rounded source cache"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_rejects_full_non_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the non-direct-small page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct-small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the non-direct-small page has one source bin");
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the non-direct-small page leaves every direct-cache slot empty"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` is live in a full non-direct-small page. The
            // direct route must reject that class before collection or detach.
            let drain = match unsafe {
                drain.abandon_full_direct_small_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::NotFullDirectSmall,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("full non-direct-small class rejects before collection: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("full non-direct-small class rejects before queue detachment: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a full non-direct-small page cannot enter the force-collected direct handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "non-direct-small rejection preserves the empty source direct-cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_refuses_stale_direct_cache_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(SMALL_SIZE_MAX, false)
                    .expect("the direct-small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            let stale_index = direct_before
                .iter()
                .position(|direct| *direct == Some(page.as_ptr()))
                .expect("the direct-small page owns at least one rounded direct-cache entry");
            assert!(
                allocator.set_direct_page_for_test(stale_index, crate::types::EMPTY_PAGE.as_ptr()),
                "the focused corruption seam changes one rounded direct-cache slot"
            );
            let stale_image = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_ne!(stale_image, direct_before);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` names a full direct-small page, but its stale
            // rounded image proves this route cannot repair source cache state
            // by queue detachment.
            let drain = match unsafe {
                drain.abandon_full_direct_small_after_force_collect_to_mapped(first)
            } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("stale direct-cache refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("stale direct-cache refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a stale direct-cache image must not enter the force-collected direct handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in stale_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "stale direct-cache refusal preserves the complete malformed source image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full direct-small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(SMALL_SIZE_MAX, false)
                    .expect("the direct-small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the full direct-small page admits one joined remote producer");
            thread::scope(|scope| {
                let publisher = scope.spawn(move || producer.publish());
                match publisher.join().expect("the remote producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("the remote client publishes before owner exit {original:?}: {error:?}");
                    }
                }
            });

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: the seam fails source force collection before it can
            // consume the already joined remote block or clear the rounded
            // direct cache and detach the ordinary-bin member.
            let drain = match unsafe {
                drain.abandon_full_direct_small_after_force_collect_to_mapped(blocks[1])
            } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected force-collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal force-collected handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full direct-small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(blocks[1]) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "direct-small collection failure preserves the complete rounded source cache"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_handoff_reabandons_after_partial_head_lag_then_releases() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the full direct-small page has one source bin");
            let reserved = page_ref.reserved() as usize;
            assert_eq!(memory.kind(), MemoryKind::Arena);
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(page_ref.block_size() <= SMALL_SIZE_MAX);
            assert!(reserved >= 16, "the partial collector keeps its source floor");
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the direct-small page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
                blocks.push(block);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(bin), Some(1));
            assert_eq!(allocator.queue_count(BIN_FULL), Some(0));
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the full direct-small page retains its rounded source direct-cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: the vector holds every live allocation in this one full
            // direct-small page. The post-TLS drain retains the exact source
            // map, rounded cache image, dynamic arena image, and page
            // ownership through the sequential failed-reclaim frees below.
            let mut handoff = match unsafe { drain.abandon_full_direct_small(blocks[0]) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the sole full direct-small page enters its dynamic unmapped handoff: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("full direct-small abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(blocks[0]), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());
            let (slice_start, span_size) = handoff
                .test_arena_span()
                .expect("the full direct-small handoff retains its complete arena span");
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "direct-small queue detachment clears its complete rounded cache before page-count removal"
                );
            }

            // The partial collector deliberately retains its just-published
            // head. Therefore the source remains unmapped for one additional
            // free relative to the normal full-page collector.
            let unmapped_frees = reserved / 8 + 1;
            assert!(unmapped_frees + 1 < reserved);
            for block in blocks.iter().copied().take(unmapped_frees) {
                // SAFETY: each loop iteration transfers one still-live
                // canonical client allocation exactly once to its linear
                // failed-reclaim handoff.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullDirectSmallFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullDirectSmallFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the partial-head mostly-used prefix cannot release the full direct-small page");
                    }
                    Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the unmapped full direct-small free remains source-shaped: {error:?}");
                    }
                };
            }
            assert_eq!(handoff.test_abandoned_count(), Some(0));
            assert!(handoff.test_dynamic_abandoned_page_is_clear());

            // This next free consumes past the retained partial head and is
            // the exact source unmapped-to-mapped reabandon boundary.
            handoff = match unsafe {
                handoff.remote_free_after_thread_exit(blocks[unmapped_frees])
            } {
                Ok(DynamicThreadExitFullDirectSmallFreeResult::StillLive(handoff)) => handoff,
                Ok(DynamicThreadExitFullDirectSmallFreeResult::Released(drain)) => {
                    core::mem::forget(drain);
                    panic!("the direct-small reabandon boundary leaves live client blocks");
                }
                Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the full direct-small reabandon boundary succeeds: {error:?}");
                }
            };
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());

            for block in blocks
                .iter()
                .copied()
                .skip(unmapped_frees + 1)
                .take(reserved - unmapped_frees - 2)
            {
                // SAFETY: the handoff remains linear and each selected block
                // is still live until this source-shaped remote free.
                handoff = match unsafe { handoff.remote_free_after_thread_exit(block) } {
                    Ok(DynamicThreadExitFullDirectSmallFreeResult::StillLive(handoff)) => handoff,
                    Ok(DynamicThreadExitFullDirectSmallFreeResult::Released(drain)) => {
                        core::mem::forget(drain);
                        panic!("the penultimate full direct-small frees leave one block live");
                    }
                    Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Rejected {
                        handoff,
                        error,
                    })
                    | Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Terminal {
                        handoff,
                        error,
                    }) => {
                        core::mem::forget(handoff);
                        panic!("the mapped full direct-small free remains source-shaped: {error:?}");
                    }
                };
            }
            let last = *blocks.last().expect("the full page has one final allocation");
            // SAFETY: `last` is now the handoff's exact final live client
            // allocation, so the mapped tail must clear its paired dynamic
            // bit/count and release the complete arena span.
            let drain = match unsafe { handoff.remote_free_after_thread_exit(last) } {
                Ok(DynamicThreadExitFullDirectSmallFreeResult::Released(drain)) => drain,
                Ok(DynamicThreadExitFullDirectSmallFreeResult::StillLive(handoff)) => {
                    core::mem::forget(handoff);
                    panic!("the final full direct-small free releases its arena span");
                }
                Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the final full direct-small free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(first) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "terminal release cannot manufacture a direct-cache entry"
                );
            }
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(first.as_ptr()) }.is_null());
            for offset in (0..span_size).step_by(crate::config::ARENA_SLICE_SIZE) {
                assert!(unsafe {
                    page_map.checked_lookup(slice_start.wrapping_add(offset))
                }
                .is_null());
            }
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_handoff_refuses_stale_rounded_direct_cache_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full direct-small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(SMALL_SIZE_MAX, false)
                    .expect("the direct-small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            let stale_index = direct_before
                .iter()
                .position(|direct| *direct == Some(page.as_ptr()))
                .expect("the direct-small page owns at least one rounded direct-cache entry");
            assert!(
                allocator.set_direct_page_for_test(stale_index, crate::types::EMPTY_PAGE.as_ptr()),
                "the focused corruption seam changes one rounded direct-cache slot"
            );
            let stale_image = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_ne!(stale_image, direct_before);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` remains live in the full direct-small page, but
            // its deliberately stale rounded cache image must reject before
            // source collection, queue removal, or page-count mutation.
            let drain = match unsafe { drain.abandon_full_direct_small(first) } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("stale direct-cache refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("stale direct-cache refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a stale rounded direct-cache image must not enter the full handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in stale_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "stale direct-cache refusal preserves the complete source cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_handoff_rejects_non_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = SMALL_SIZE_MAX + WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("the fixture creates one dynamic non-direct small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the non-direct small page remains PageMap-published");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full non-direct small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(request, false)
                    .expect("the non-direct small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the non-direct small page leaves every direct-cache slot empty"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` is live in a full non-direct small page. The
            // direct route must reject that class before collection or detach.
            let drain = match unsafe { drain.abandon_full_direct_small(first) } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::NotFullDirectSmall,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("non-direct class rejection is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("non-direct class rejection is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a non-direct small page must not enter the direct full handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "non-direct class rejection preserves the empty direct-cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_handoff_rejects_before_detach_when_another_page_is_live() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(SMALL_SIZE_MAX, false)
                    .expect("the direct-small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            let other = allocator
                .allocate(LARGE_MAX_OBJ_SIZE + 1, false)
                .expect("the fixture creates another live arena page");
            let other_page = unsafe { allocator.page_for_block(other) };

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `first` names a full direct-small page, but `other`
            // proves this bounded source traversal cannot detach it early.
            let drain = match unsafe { drain.abandon_full_direct_small(first) } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the full direct-small sole-page check is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the full direct-small sole-page check is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a second live page must block the dynamic full direct-small handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { drain.test_page_for_block(other) }, other_page);
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 2);
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "the sole-page refusal preserves the complete rounded direct-cache image"
                );
            }

            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_full_direct_small_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one dynamic direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the direct-small page remains PageMap-published");
            let bin = crate::size_class::bin(unsafe { page.as_ref().block_size() })
                .expect("the full direct-small page has one source bin");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            while unsafe { page.as_ref().used() } < reserved {
                let block = allocator
                    .allocate(SMALL_SIZE_MAX, false)
                    .expect("the direct-small page reaches its full source state");
                assert_eq!(unsafe { allocator.page_for_block(block) }, page.as_ptr());
            }
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `first` remains current in the full direct-small page.
            // The deterministic source force-collection failure occurs before
            // direct-cache, queue, or count mutation and retains the poisoned
            // post-TLS drain rather than offering an ordinary retry.
            let drain = match unsafe { drain.abandon_full_direct_small(first) } {
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitFullDirectSmallAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Rejected {
                    drain,
                    error,
                })
                | Err(DynamicThreadExitFullDirectSmallAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected full direct-small collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitFullDirectSmallAbandonFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal full direct-small handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the full direct-small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(first) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() as usize }, reserved);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "direct-small collection failure preserves the complete source cache image"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_direct_small_handoff_releases_after_its_final_free() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the dynamic fixture allocates one direct-small regular page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the direct-small page has one source bin");
            assert_eq!(memory.kind(), MemoryKind::Arena);
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(page_ref.block_size() <= SMALL_SIZE_MAX);
            assert!(page_ref.reserved() >= 16);
            assert_eq!(page_ref.used(), 1);
            assert_eq!(allocator.queue_count(bin), Some(1));
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the direct-small page owns its complete rounded source direct-cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `block` is the exact sole live allocation in this sole
            // nonfull direct-small page. Its rounded direct-cache image and
            // partial-collection geometry remain coupled to the drain until
            // the final free releases the page.
            let handoff = match unsafe { drain.abandon_mapped_one_block_direct_small(block) } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the one-block direct-small page enters the dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("mapped abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(block), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "direct-small detachment clears its complete source direct-cache image before page-count removal"
                );
            }

            // SAFETY: this is the handoff's exact once-live client block. The
            // source direct-small partial collector consumes its final remote
            // head, reaches all-free before reclaim, and releases the complete
            // queue-detached arena span.
            let drain = match unsafe { handoff.remote_free_to_empty(block) } {
                Ok(drain) => drain,
                Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the mapped direct-small final free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(block) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "terminal direct-small release cannot manufacture a direct-cache entry"
                );
            }
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(block.as_ptr()) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_direct_small_handoff_refuses_stale_direct_cache_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates the boundary direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the direct-small page has one source bin");
            assert!(page_ref.block_size() <= SMALL_SIZE_MAX);
            assert!(page_ref.reserved() >= 16);
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            let stale_index = direct_before
                .iter()
                .position(|direct| *direct == Some(page.as_ptr()))
                .expect("the direct-small page owns at least one rounded direct-cache entry");
            assert!(
                allocator.set_direct_page_for_test(stale_index, crate::types::EMPTY_PAGE.as_ptr()),
                "the focused corruption seam changes one direct-cache slot"
            );
            let stale_image = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert_ne!(stale_image, direct_before);

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `block` remains the one live direct-small allocation,
            // but the deliberately stale rounded cache image must reject the
            // route before collection, queue mutation, or count removal.
            let drain = match unsafe { drain.abandon_mapped_one_block_direct_small(block) } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::NotOnlyPage,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("stale direct-cache refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("stale direct-cache refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a stale direct-cache image must not enter the dynamic handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in stale_image.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "direct-small preflight refusal preserves the complete stale source cache image"
                );
            }

            // General dynamic post-TLS traversal remains outside this slice.
            // Retain the unchanged source owner after proving the cache
            // mismatch cannot be silently repaired by detaching the page.
            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_direct_small_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates one direct-small page for source collection");
            let page = unsafe { allocator.page_for_block(block) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the direct-small page has one source bin");
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `block` remains the sole live direct-small allocation.
            // The one-shot seam fails source force collection before its
            // direct-cache or queue ownership can change, so the post-TLS
            // drain must remain retained and poisoned.
            let drain = match unsafe { drain.abandon_mapped_one_block_direct_small(block) } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal direct-small handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the direct-small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "direct-small collection failure preserves the complete source direct-cache image"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_non_direct_small_handoff_releases_after_its_final_free() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_SIZE_MAX + WORD_SIZE, false)
                .expect("the dynamic fixture allocates one non-direct small regular page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the regular page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let memory = page_ref.memid();
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the regular non-direct small page has one source bin");
            assert_eq!(memory.kind(), MemoryKind::Arena);
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(page_ref.block_size() > SMALL_SIZE_MAX);
            assert!(page_ref.block_size() <= SMALL_MAX_OBJ_SIZE);
            assert!(page_ref.reserved() > 1);
            assert_eq!(page_ref.used(), 1);
            assert_eq!(allocator.queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    allocator.direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "a non-direct small page leaves every source direct slot empty"
                );
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());

            // SAFETY: `block` is the exact sole live allocation in this sole
            // nonfull non-direct small page. The dynamic drain retains its
            // source post-TLS map/image/page authority through the final free.
            let handoff = match unsafe {
                drain.abandon_mapped_one_block_non_direct_small(block)
            } {
                Ok(handoff) => handoff,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("the one-block non-direct small page enters the dynamic owner-exit handoff: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("mapped abandonment does not retain a terminal owner: {error:?}");
                }
            };
            assert_eq!(handoff.test_page_count(), 0);
            assert_eq!(handoff.test_page_for_block(block), page.as_ptr());
            assert_eq!(handoff.test_abandoned_count(), Some(1));
            assert!(handoff.test_dynamic_abandoned_page_is_set());
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    handoff.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "the non-direct small source queue removal leaves direct slots untouched"
                );
            }

            // SAFETY: this is the handoff's exact once-live client block. Its
            // source normal collection reaches all-free before reclaim and
            // releases the complete queue-detached arena span.
            let drain = match unsafe { handoff.remote_free_to_empty(block) } {
                Ok(drain) => drain,
                Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Rejected {
                    handoff,
                    error,
                })
                | Err(DynamicThreadExitMappedOneBlockRemoteFreeFailure::Terminal {
                    handoff,
                    error,
                }) => {
                    core::mem::forget(handoff);
                    panic!("the mapped one-block final free releases its dynamic arena page: {error:?}");
                }
            };
            assert!(unsafe { drain.test_page_for_block(block) }.is_null());
            assert_eq!(drain.test_page_count(), 0);
            assert_eq!(drain.test_dynamic_abandoned_count(bin), Some(0));
            assert!(drain.test_dynamic_abandoned_page_is_clear(bin, memory));
            assert!(drain.test_dynamic_arena_page_is_clear(memory));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "terminal release does not manufacture a direct-small cache entry"
                );
            }
            assert!(drain.finish());
            assert!(unsafe { page_map.checked_lookup(block.as_ptr()) }.is_null());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_non_direct_small_handoff_rejects_direct_small_before_detach() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_SIZE_MAX, false)
                .expect("the fixture creates the boundary direct-small page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the direct-small page remains PageMap-published before thread exit");
            let page_ref = unsafe { page.as_ref() };
            let bin = crate::size_class::bin(page_ref.block_size())
                .expect("the boundary small page has one source bin");
            assert_eq!(
                crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                Some(crate::types::PageKind::Small)
            );
            assert!(page_ref.block_size() <= SMALL_SIZE_MAX);
            let direct_before = (0..PAGES_DIRECT)
                .map(|index| allocator.direct_page(index))
                .collect::<Vec<_>>();
            assert!(
                direct_before.iter().any(|direct| *direct == Some(page.as_ptr())),
                "the boundary small page owns its source direct-cache range"
            );

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            // SAFETY: `block` is a live direct-small allocation. This route
            // must refuse it before force collection, queue detach, or a
            // direct-cache update because its source class is deliberately
            // non-direct small only.
            let drain = match unsafe {
                drain.abandon_mapped_one_block_non_direct_small(block)
            } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::NotMappedOneBlock,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("direct-small refusal is wholly pre-collection: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("direct-small refusal is pre-detach: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("a direct-small page must not enter the non-direct handoff");
                }
            };
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page.as_ptr());
            assert_eq!(unsafe { page.as_ref().used() }, 1);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for (index, expected) in direct_before.into_iter().enumerate() {
                assert_eq!(
                    drain.test_direct_page(index),
                    expected,
                    "direct-small refusal preserves the complete source direct-cache image"
                );
            }

            // General dynamic post-TLS traversal of direct-small pages stays
            // deliberately outside this slice. Retain the unchanged source
            // owner after proving that the refusal did not detach it.
            core::mem::forget(drain);
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_mapped_one_block_non_direct_small_handoff_retains_collection_failure() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_SIZE_MAX + WORD_SIZE, false)
                .expect("the fixture creates one non-direct small page for source collection");
            let page = unsafe { allocator.page_for_block(block) };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the non-direct small page has one source bin");

            let mut drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread exit clears the dynamic regular TLS slot: {error:?}");
                }
            };
            drain.inject_page_free_collect_failure_once();
            // SAFETY: `block` remains the sole live allocation. The one-shot
            // seam fails source force collection before queue detachment, so
            // the post-TLS drain—not a retryable live allocator—must retain it.
            let drain = match unsafe {
                drain.abandon_mapped_one_block_non_direct_small(block)
            } {
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error: DynamicThreadExitMappedOneBlockAbandonError::Collection,
                }) => drain,
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Rejected { drain, error })
                | Err(DynamicThreadExitMappedOneBlockAbandonFailure::RetainedDrain {
                    drain,
                    error,
                }) => {
                    core::mem::forget(drain);
                    panic!("injected source collection failure retains the dynamic drain: {error:?}");
                }
                Err(DynamicThreadExitMappedOneBlockAbandonFailure::Terminal { handoff, error }) => {
                    core::mem::forget(handoff);
                    panic!("collection fails before a terminal mapped handoff: {error:?}");
                }
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("the injected collection failure cannot abandon the non-direct small page");
                }
            };
            assert!(drain.test_has_collection_poison());
            assert_eq!(unsafe { drain.test_page_for_block(block) }, page);
            assert_eq!(drain.test_page_count(), 1);
            assert_eq!(drain.test_queue_count(bin), Some(1));
            for index in 0..PAGES_DIRECT {
                assert_eq!(
                    drain.test_direct_page(index),
                    Some(crate::types::EMPTY_PAGE.as_ptr()),
                    "non-direct small collection failure preserves its empty direct-cache image"
                );
            }

            drop(drain);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_thread_exit_force_collects_a_retired_regular_page_after_tls_clear() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                .expect("the dynamic fixture allocates one regular medium page");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the regular page remains page-map published");
            assert!(unsafe { page.as_ref().reserved() } > 1);

            // SAFETY: this is the page's only current local allocation. Its
            // normal free leaves a retired regular page so thread exit must
            // take `_mi_theap_collect_retired(theap, true)` after clearing the
            // regular TLS backing, rather than treating no-page teardown as a
            // substitute for the source force-collection boundary.
            unsafe { allocator.free(block) }
                .expect("one non-full regular page enters retirement before thread exit");
            assert!(!unsafe { allocator.page_for_block(block) }.is_null());

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(DynamicThreadExitDrainFailure::Retained { engine, error }) => {
                    core::mem::forget(engine);
                    panic!("thread-exit drain clears the dynamic regular TLS slot: {error:?}");
                }
            };
            assert!(drain.test_dynamic_regular_slot_is_clear());
            assert_eq!(drain.test_page_count(), 1);

            // `finish` first force-collects retirement before it can establish
            // the empty-page precondition for cached-root/list/key teardown.
            assert!(drain.finish());
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_mapped_handoff_rejects_an_unmapped_pointer_before_state_mutation() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner
                .page_session()
                .expect("non-abandoning dynamic attachment admits its page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(37, false)
                .expect("real dynamic regular page allocation");
            let page = unsafe { allocator.page_for_block(block) };
            assert!(!page.is_null());
            let memory = unsafe { (*page).memid() };
            let bin = crate::size_class::bin(unsafe { (*page).block_size() })
                .expect("the dynamic fixture allocated a regular size class");

            // SAFETY: the deliberately unmapped dangling address is not
            // dereferenced; the consuming API must reject it at PageMap
            // lookup and return the unchanged engine.
            allocator = match unsafe {
                allocator.abandon_mapped_regular(NonNull::<u8>::dangling())
            } {
                Err(DynamicMappedAbandonFailure::Rejected {
                    engine,
                    error: DynamicMappedAbandonError::Unmapped,
                }) => engine,
                Ok(handoff) => {
                    core::mem::forget(handoff);
                    panic!("an unmapped pointer cannot form an abandoned-page handoff");
                }
                Err(failure) => {
                    core::mem::forget(failure);
                    panic!("an unmapped pointer must be a wholly pre-mutation rejection");
                }
            };
            assert_eq!(unsafe { (*page).theap() }, allocator.theap_identity());
            assert!(allocator.test_dynamic_abandoned_page_is_clear(bin, memory));

            // SAFETY: rejection left the one real allocation live and owned
            // by the ordinary dynamic engine.
            unsafe { allocator.free(block) }
                .expect("the pre-mutation rejection preserves normal local free");
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_arena_pages_nonempty_teardown_rejects_without_root_or_slot_mutation() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let key = owner.key().expect("attached owner keeps its regular key");
            let cached_before = cached_theap();
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator.allocate(37, false).expect("dynamic page block");
            let page = unsafe { allocator.page_for_block(block) };
            let memory = unsafe { (*page).memid() };
            unsafe { allocator.free(block) }.expect("local dynamic block frees");
            assert!(matches!(allocator.finish(), Ok(())));

            let arena_pages = owner
                .arena_pages
                .as_ref()
                .expect("finished engine retains the empty heap-local image");
            assert!(arena_pages.set_page(memory));
            assert_eq!(
                owner.teardown(),
                Err(DynamicTheapError::ArenaPages(DynamicArenaPagesOwnerError::NonEmpty))
            );
            assert_eq!(cached_theap(), cached_before);
            assert!(!owner
                .backing
                .as_mut()
                .expect("pre-mutation rejection retains backing")
                .get(key)
                .expect("slot lookup remains valid")
                .is_null());
            assert!(owner
                .arena_pages
                .as_ref()
                .expect("pre-mutation rejection retains owner")
                .clear_page(memory));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_arena_pages_rejects_cross_heap_removal_and_retains_exact_slot() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator.allocate(37, false).expect("dynamic page block");
            unsafe { allocator.free(block) }.expect("local dynamic block frees");
            assert!(matches!(allocator.finish(), Ok(())));

            let foreign = Heap::bootstrap_empty();
            let arena_pages = owner
                .arena_pages
                .as_mut()
                .expect("dynamic page engine retained its exact Heap owner");
            assert_eq!(
                arena_pages.unpublish_and_free(&foreign),
                Err(DynamicArenaPagesOwnerError::ForeignHeap)
            );
            assert!(arena_pages.is_published_for(owner.heap.as_ref().get_ref()));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_arena_pages_aligned_metadata_failure_leaves_slot_null_and_retries() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = match unsafe {
                DynamicTheapAttachment::begin_non_abandoning_with_components(
                    memory_config(),
                    pinned_empty_heap(),
                    subprocess,
                    metadata,
                    registry,
                )
            } {
                Ok(owner) => owner,
                Err(DynamicTheapBeginError::Rejected(error)) => panic!("attach: {error:?}"),
                Err(DynamicTheapBeginError::Retained { error, .. }) => panic!("retained: {error:?}"),
            };
            let mut region = DynamicArenaRegion::zeroed();
            let registry = ArenaRegistry::new(null_mut());
            assert!(unsafe { registry.bind_subprocess_before_publication(subprocess.as_ptr()) });
            let managed = unsafe {
                manage_external_in_place(
                    &registry,
                    region.as_ptr(),
                    ARENA_MIN_SIZE,
                    PageSize::new(4096).expect("pinned page size"),
                    true,
                    true,
                    true,
                    -1,
                    false,
                    None,
                )
            }
            .expect("external arena");
            let arena_pointer = managed.arena_id().as_ptr();
            let arena = unsafe { ArenaView::from_ptr(arena_pointer) }
                .expect("arena view");
            let arena_index = arena.arena().arena_index;
            let mut page_map = PageMap::initialize(memory_config(), 0, true).expect("page map");
            let layout = ArenaPagesLayout::for_slice_count(arena.arena().slice_count)
                .expect("source arena bitmap layout");
            metadata.test_fail_next_aligned_zeroed_size(layout.byte_size());
            let session = owner.page_session().expect("page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                &mut page_map,
            );
            assert!(allocator.allocate(37, false).is_none());
            assert!(matches!(allocator.finish(), Ok(())));
            assert!(owner.arena_pages.is_none());
            assert!(owner.heap.as_ref().get_ref().dynamic_arena_pages_at(
                arena_index
            ).is_none());
            let retry_arena = unsafe { ArenaView::from_ptr(arena_pointer) }
                .expect("arena stays registered for retry");
            let retry_session = owner.page_session().expect("retry page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                retry_session,
                retry_arena,
                ArenaId::none(),
                &mut page_map,
            );
            let block = allocator.allocate(37, false).expect("retry allocates after pre-publication failure");
            unsafe { allocator.free(block) }.expect("retry allocation frees");
            assert!(matches!(allocator.finish(), Ok(())));
            owner.teardown().expect("empty retry owner tears down");
            unsafe { page_map.destroy() }.expect("no retry map entries remain");
        })
        .join()
        .expect("aligned metadata failure fixture stays current-thread local");
    }

    #[test]
    fn dynamic_arena_pages_reject_unbound_or_foreign_arena_subprocess_before_allocation() {
        thread::spawn(|| {
            let (subprocess, metadata, _) = fixture();
            let foreign = MainSubprocess::test_static_owner();
            let reject = |registry, expected| {
                let mut region = DynamicArenaRegion::zeroed();
                let managed = unsafe {
                    manage_external_in_place(
                        &registry,
                        region.as_ptr(),
                        ARENA_MIN_SIZE,
                        PageSize::new(4096).expect("pinned page size"),
                        true,
                        true,
                        true,
                        -1,
                        false,
                        None,
                    )
                }
                .expect("the isolated external arena publishes");
                let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }
                    .expect("the published arena has a view");
                let heap = Heap::bootstrap_empty();
                assert!(matches!(
                    DynamicArenaPagesOwner::create(
                        metadata,
                        memory_config(),
                        subprocess,
                        &heap,
                        &arena,
                    ),
                    Err(DynamicArenaPagesOwnerCreateError::Error(error)) if error == expected
                ));
                assert!(
                    heap.dynamic_arena_pages_at(arena.arena().arena_index).is_none(),
                    "the source-identity preflight rejects before any Heap-slot or metadata publication"
                );
            };

            reject(
                ArenaRegistry::new(null_mut()),
                DynamicArenaPagesOwnerError::UnboundArenaSubprocess,
            );
            reject(
                ArenaRegistry::new(foreign.as_ptr()),
                DynamicArenaPagesOwnerError::ForeignArenaSubprocess,
            );
        })
        .join()
        .expect("the source-identity rejection fixture stays current-thread local");
    }

    #[test]
    fn dynamic_arena_pages_slot_publish_failure_retains_typed_owner_terminally() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let arena_index = arena.arena().arena_index;
            owner
                .heap
                .as_ref()
                .get_ref()
                .test_inject_busy_arena_pages_lock();
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            assert!(allocator.allocate(37, false).is_none());
            assert!(matches!(allocator.finish(), Ok(())));
            assert!(owner.arena_pages.is_some());
            assert!(owner
                .heap
                .as_ref()
                .get_ref()
                .dynamic_arena_pages_at(arena_index)
                .is_none());
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_non_abandoning_full_page_collects_joined_remote_block_and_unfulls() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let request = crate::config::SMALL_MAX_OBJ_SIZE + crate::config::WORD_SIZE;
            let first = allocator
                .allocate(request, false)
                .expect("dynamic medium block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the dynamic medium block has a page");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let next = allocator
                    .allocate(request, false)
                    .expect("the dynamic medium page reaches its source full state");
                assert_eq!(unsafe { allocator.page_for_block(next) }, page.as_ptr());
                blocks.push(next);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            assert_eq!(allocator.queue_count(crate::config::BIN_FULL), Some(1));

            let producer = unsafe { allocator.begin_remote_free(blocks[0]) }
                .expect("the dynamic full page admits the joined producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined.join().expect("dynamic full producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("dynamic full remote publication rejected {original:?}: {error:?}");
                    }
                }
            });

            assert!(allocator.collect_retired(false));
            assert_eq!(unsafe { page.as_ref().used() }, reserved - 1);
            assert_eq!(allocator.queue_count(crate::config::BIN_FULL), Some(0));
            let reused = allocator
                .allocate(request, false)
                .expect("the non-abandoning full collector restores the remote block");
            assert_eq!(reused, blocks[0]);
            blocks[0] = reused;
            for block in blocks {
                // SAFETY: the full collector returned the transferred block
                // once and all sibling blocks remained local throughout.
                unsafe { allocator.free(block) }.expect("the dynamic full block frees");
            }
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn failed_dynamic_engine_finish_retains_the_engine_then_drop_latches_attachment_terminal() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator
                .allocate(37, false)
                .expect("a live page makes explicit finish fail without consuming authority");
            let page = unsafe { allocator.page_for_block(block) };
            let allocator = match allocator.finish() {
                Ok(()) => panic!("a live dynamic page cannot finish"),
                Err(allocator) => allocator,
            };
            // `finish(self)` has returned the sole live engine, so no caller
            // can use a successfully finished value. Dropping this failed
            // engine is deliberately non-destructive but latches attachment
            // teardown instead of losing the live page/map ownership.
            drop(allocator);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            assert!(!page.is_null());
            assert_eq!(
                unsafe { page_map.checked_lookup(block.as_ptr()) },
                page,
                "terminal dynamic attachment keeps its page-map entry rather than faking teardown"
            );
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_pending_os_release_makes_finish_retain_then_drop_latch_attachment() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let fault = fault::install(fault::Plan::disabled());
            let block = allocator
                .allocate_aligned(7, 128 * crate::config::KIB)
                .expect("dynamic OS-aligned singleton");
            fault.set(fault::Plan::at(
                fault::Point::Unmap,
                1,
                crabc_core::Errno::NOMEM,
            ));
            // SAFETY: `block` is the singleton's sole live allocation; the
            // injected unmap failure clears its page metadata but retains the
            // unique mapping owner in the engine.
            unsafe { allocator.free(block) }.expect("semantic free parks its OS owner");
            assert!(allocator.has_pending_os_release());
            let allocator = match allocator.finish() {
                Ok(()) => panic!("a pending OS release cannot finish"),
                Err(allocator) => allocator,
            };
            drop(allocator);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            assert!(
                owner.terminal_os_release.is_some(),
                "terminal Drop transfers the unique OS release owner into the retained attachment"
            );
            assert_eq!(
                owner
                    .theap
                    .as_mut()
                    .and_then(MetaAllocation::dynamic_theap_mut)
                    .unwrap()
                    .page_count(),
                0,
                "the retained terminal state is the engine's pending OS owner, not a live page"
            );
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn dynamic_regular_remote_free_is_joined_collected_and_reused() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator.allocate(37, false).expect("dynamic regular block");
            let page = NonNull::new(unsafe { allocator.page_for_block(block) })
                .expect("the current dynamic block has a page-map entry");
            let capacity = unsafe { page.as_ref().capacity() as usize };
            let mut local_blocks = Vec::with_capacity(capacity);
            local_blocks.push(block);
            while unsafe { page.as_ref().used() } < capacity {
                let next = allocator
                    .allocate(37, false)
                    .expect("the dynamic direct page supplies its initialized capacity");
                assert_eq!(unsafe { allocator.page_for_block(next) }, page.as_ptr());
                local_blocks.push(next);
            }
            assert!(capacity < unsafe { page.as_ref().reserved() as usize });
            let producer = unsafe { allocator.begin_remote_free(block) }
                .expect("the real dynamic regular page has an owner collection route");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined.join().expect("scoped producer remains live") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("dynamic remote publication rejected {original:?}: {error:?}");
                    }
                }
            });
            let reused = allocator
                .allocate(37, false)
                .expect("the regular search false-collects the joined remote block");
            assert_eq!(reused, block);
            // SAFETY: collection returned this exact formerly remote block to
            // local ownership once.
            unsafe { allocator.free(reused) }.expect("the reused dynamic block frees");
            for local in local_blocks.into_iter().skip(1) {
                // SAFETY: these sibling allocations were never transferred
                // and remain exact current blocks from this dynamic page.
                unsafe { allocator.free(local) }.expect("the dynamic sibling frees");
            }
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_non_abandoning_small_page_uses_the_stored_minus_one_full_profile() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let first = allocator.allocate(37, false).expect("dynamic small block");
            let page = NonNull::new(unsafe { allocator.page_for_block(first) })
                .expect("the dynamic small block has a page");
            let reserved = unsafe { page.as_ref().reserved() as usize };
            let mut blocks = Vec::with_capacity(reserved);
            blocks.push(first);
            while unsafe { page.as_ref().used() } < reserved {
                let next = allocator
                    .allocate(37, false)
                    .expect("the small page extends then exhausts through the shared engine");
                assert_eq!(unsafe { allocator.page_for_block(next) }, page.as_ptr());
                blocks.push(next);
            }
            assert_eq!(unsafe { page.as_ref().used() }, reserved);
            let successor = allocator
                .allocate(37, false)
                .expect("the direct miss enters generic small-page search");
            assert_ne!(
                unsafe { allocator.page_for_block(successor) },
                page.as_ptr(),
                "the exhausted page is classified before a fresh successor is used"
            );
            // `_mi_page_to_full` immediately performs the second
            // false-force collection. With no remote or local frees that
            // collection unfulls this page again, so assert the exact
            // transition witness rather than its transient queue position.
            assert_eq!(
                allocator.test_last_page_to_full(),
                Some(page),
                "the stored -1 profile routes an exhausted small page through BIN_FULL"
            );
            for block in blocks {
                // SAFETY: all blocks remain exact local allocations; this
                // only demonstrates immediate full routing, not remote flow.
                unsafe { allocator.free(block) }.expect("the dynamic small block frees");
            }
            // SAFETY: this successor is a distinct, still-local allocation
            // from the generic fallback that forced the source queue scan.
            unsafe { allocator.free(successor) }.expect("the successor frees");
            assert!(matches!(allocator.finish(), Ok(())));
            DynamicPageFixtureOutcome::TearDown
        });
    }

    #[test]
    fn dynamic_collection_poison_retains_attachment_map_roots_and_key_authority() {
        with_non_abandoning_dynamic_page_fixture(|owner, arena, page_map| {
            let key = owner.key().expect("attached dynamic owner retains its key");
            let theap = owner.theap_pointer().expect("typed dynamic Theap pointer");
            let session = owner.page_session().expect("non-abandoning page session");
            let mut allocator = DynamicTheapAllocator::activate_dynamic(
                session,
                arena,
                ArenaId::none(),
                page_map,
            );
            let block = allocator.allocate(37, false).expect("dynamic regular block");
            let page = unsafe { allocator.page_for_block(block) };
            let page_ref = NonNull::new(page).expect("the current dynamic block has a page");
            let capacity = unsafe { page_ref.as_ref().capacity() as usize };
            let mut locals = Vec::with_capacity(capacity);
            locals.push(block);
            while unsafe { page_ref.as_ref().used() } < capacity {
                let next = allocator.allocate(37, false).expect("dynamic page capacity");
                assert_eq!(unsafe { allocator.page_for_block(next) }, page);
                locals.push(next);
            }
            let producer = unsafe { allocator.begin_remote_free(block) }
                .expect("the active dynamic regular page admits its producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined.join().expect("dynamic poison producer joins") {
                    Ok(()) => {}
                    Err((producer, error)) => {
                        let original = producer.cancel();
                        panic!("dynamic poison publication rejected {original:?}: {error:?}");
                    }
                }
            });

            allocator.inject_page_free_collect_failure_once();
            assert_eq!(allocator.allocate(37, false), None);
            assert!(allocator.test_has_collection_poison());
            // The failure is before remote detachment, but production cannot
            // clear its poison. Dropping this unfinished engine latches the
            // dynamic attachment without releasing any related capability.
            drop(allocator);

            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            assert_eq!(cached_theap().as_ptr(), theap);
            assert_eq!(
                owner.backing.as_mut().unwrap().get(key).unwrap(),
                theap.cast(),
                "terminal collection poison keeps the regular key slot live"
            );
            assert!(dynamic_backing_peek().is_some());
            assert_eq!(
                unsafe { page_map.checked_lookup(block.as_ptr()) },
                page,
                "terminal collection poison retains the real dynamic map entry"
            );
            assert_eq!(
                owner
                    .theap
                    .as_mut()
                    .and_then(MetaAllocation::dynamic_theap_mut)
                    .unwrap()
                    .page_count(),
                1
            );
            DynamicPageFixtureOutcome::RetainTerminal
        });
    }

    #[test]
    fn regular_slot_then_cached_publication_increments_the_dynamic_theap_reference() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let dynamic_before = dynamic_backing_peek();
            let roots_before = UnrelatedRoots::capture();
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let key = owner.key().expect("attached owner retains its regular key");
            assert_ne!(key.raw(), 0);
            assert_ne!(key.raw(), crate::thread_local::TLS_FAST_KEY_RAW);
            assert_eq!(key.index().get(), 0);
            assert_eq!(key.version(), 1);
            assert_ne!(dynamic_backing_peek(), dynamic_before);

            let theap_pointer = owner.theap_pointer().unwrap();
            let slot = owner
                .backing
                .as_mut()
                .unwrap()
                .get(key)
                .expect("the retained backing projects its own regular slot");
            assert_eq!(slot, theap_pointer.cast());
            assert_eq!(default_theap(), roots_before.default);
            assert_eq!(fast_slot_peek(), roots_before.fast);
            assert_eq!(cached_theap().as_ptr(), theap_pointer);
            assert!(owner.binding.as_ref().unwrap().slot_bound);
            assert_eq!(
                owner
                    .binding
                    .as_mut()
                    .unwrap()
                    .release_after_slot_clear(),
                Err(DynamicTheapError::SlotOwnership),
                "a live backing slot keeps the linear key lease unreleasable"
            );
            assert_eq!(
                owner.backing.as_mut().unwrap().get(key).unwrap(),
                theap_pointer.cast(),
                "a rejected key release cannot clear or stale the live slot"
            );
            let heap = owner.heap.as_ref().get_ref();
            assert!(heap.has_exact_theap_member(theap_pointer));
            assert!(heap.matches_dynamic_binding(subprocess, key.raw() as usize));
            let heap_fields = heap.test_main_static_fields();
            assert_eq!(heap_fields.memid.kind(), MemoryKind::None);
            assert_eq!(heap_fields.theap_slot, key.raw() as usize);
            assert_eq!(heap_fields.numa_node, -1);
            let tld = owner.tld.as_mut().unwrap().current_mut().unwrap();
            assert!(tld.has_exact_theap_member(theap_pointer));
            assert!(tld.test_theap_head_is(theap_pointer));
            let fields = owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .test_main_static_fields();
            // The non-null heap is the source initialized predicate, so this
            // observes every preceding TLD/list/random/cookie field before
            // the Release heap publication.
            assert!(fields.initialized);
            assert_eq!(fields.refcount, 2);
            assert!(fields.cookie_is_odd);
            assert!(fields.random_initialized);
            assert!(!fields.random_weak);
            assert_eq!(fields.page_full_retain, 2);
            assert!(fields.allows_page_reclaim);
            assert!(fields.allows_page_abandon);
            assert!(!fields.detached);
            assert_eq!(fields.memid.kind(), MemoryKind::Malloc);
            assert!(fields.memid.is_pinned());
            assert!(fields.memid.initially_committed());

            owner.teardown().expect("the no-page regular attachment tears down");
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(dynamic_backing_peek().is_none());
            assert_eq!(default_theap(), roots_before.default);
            assert_eq!(fast_slot_peek(), roots_before.fast);
            assert_eq!(cached_theap(), roots_before.cached);
            assert!(owner.heap.as_ref().get_ref().test_main_static_fields().theaps_empty);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::TornDown));
        })
        .join()
        .expect("the current-thread attachment test completes");
    }

    #[test]
    fn nonzero_page_rejection_is_wholly_pre_mutation_and_recovery_detaches_after_page_removal() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let key = owner.key().unwrap();
            let theap_pointer = owner.theap_pointer().unwrap();
            owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .note_page_added();
            assert_eq!(owner.teardown(), Err(DynamicTheapError::PageCountNonZero));
            assert_eq!(owner.state, DynamicAttachmentState::Attached);
            assert_eq!(default_theap(), roots.default);
            assert_eq!(fast_slot_peek(), roots.fast);
            assert_eq!(cached_theap().as_ptr(), theap_pointer);
            assert_eq!(
                owner.backing.as_mut().unwrap().get(key).unwrap(),
                theap_pointer.cast(),
                "the regular slot is untouched before the page-count rejection"
            );
            assert!(owner.heap.as_ref().get_ref().has_exact_theap_member(theap_pointer));
            assert!(owner
                .tld
                .as_mut()
                .unwrap()
                .current_mut()
                .unwrap()
                .has_exact_theap_member(theap_pointer));
            assert_eq!(subprocess.live_thread_count(), 1);
            assert!(owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .note_page_removed());
            owner.teardown().unwrap();
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join()
        .expect("the pre-mutation page-count test completes");
    }

    #[test]
    fn root_mismatch_preserves_the_foreign_root_and_retains_attachment_authority() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let key = owner.key().unwrap();
            let slot = owner.backing.as_mut().unwrap().get(key).unwrap();
            let theap_pointer = owner.theap_pointer().unwrap();
            let mut foreign = Theap::empty();
            let foreign_pointer = NonNull::from(&mut foreign);
            set_cached_theap(foreign_pointer);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::RootOwnership));
            assert_eq!(cached_theap(), foreign_pointer);
            assert_eq!(owner.state, DynamicAttachmentState::Attached);
            assert_eq!(owner.backing.as_mut().unwrap().get(key).unwrap(), slot);
            assert_eq!(
                owner
                    .theap
                    .as_mut()
                    .unwrap()
                    .dynamic_theap_mut()
                    .unwrap()
                    .refcount(),
                2,
                "a foreign cached root must not consume the attachment reference"
            );
            assert_eq!(subprocess.live_thread_count(), 1);
            // Restore precisely this attachment's cached root after proving
            // prevalidation did not overwrite the foreign pointer.
            set_cached_theap(NonNull::new(theap_pointer).unwrap());
            owner.teardown().unwrap();
        })
        .join()
        .expect("foreign-root preflight test completes");
    }

    #[test]
    fn cached_root_is_empty_and_reference_is_one_before_a_terminal_heap_detach_failure() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots_before = UnrelatedRoots::capture();
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let theap_pointer = owner.theap_pointer().unwrap();
            owner.heap_mut().test_inject_busy_theaps_lock();

            assert_eq!(
                owner.teardown(),
                Err(DynamicTheapError::TheapList(ThreadLocalTheapListError::Heap(
                    crate::types::HeapTheapListError::Busy
                )))
            );

            assert_eq!(owner.state, DynamicAttachmentState::Poisoned);
            assert!(owner.backing.is_none(), "backing/root teardown precedes list detach");
            assert!(!owner.binding.as_ref().unwrap().slot_bound);
            assert!(!owner.cached_root_bound);
            assert_eq!(registry.test_live_lease_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
            assert!(dynamic_backing_peek().is_none());
            assert_eq!(default_theap(), roots_before.default);
            assert_eq!(fast_slot_peek(), roots_before.fast);
            assert_eq!(
                cached_theap(),
                NonNull::from(crate::bootstrap::empty_default_theap()),
                "cached reset happens before the failing source list detach"
            );
            assert_eq!(
                owner
                    .theap
                    .as_mut()
                    .unwrap()
                    .dynamic_theap_mut()
                    .unwrap()
                    .refcount(),
                1,
                "the paired cached reference was released before detach"
            );
            assert!(owner.heap.as_ref().get_ref().has_exact_theap_member(theap_pointer));
            assert!(owner
                .tld
                .as_mut()
                .unwrap()
                .current_mut()
                .unwrap()
                .has_exact_theap_member(theap_pointer));
            assert!(owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .is_initialized());
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));

            // This injected invalid-owner state follows the root mutation and
            // therefore has no source-valid recovery path. Keep all known
            // capabilities alive for the isolated fixture.
            core::mem::forget(owner);
        })
        .join()
        .expect("cached reset precedes terminal detach failure");
    }

    #[test]
    fn tld_and_theap_allocation_failures_consume_only_total_sequence_and_leave_roots_pristine() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            let dynamic_before = dynamic_backing_peek();
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::ThreadLocalData(
                    ThreadLocalDataError::Metadata(MetaError::InitializationFailed)
                )))
            ));
            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert!(roots.still_matches());
            fault.set(fault::Plan::disabled());

            metadata
                .get_ref()
                .test_fail_next_direct_zeroed_size(size_of::<Theap>());
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::TheapMetadata(
                    MetaError::AllocationUnavailable
                )))
            ));
            assert_eq!(subprocess.total_thread_count(), 3);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            assert!(roots.still_matches());
        })
        .join()
        .expect("allocation failures leave no live dynamic attachment");
    }

    #[test]
    fn foreign_cached_root_rejects_before_later_ticket_or_backing_allocation() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let dynamic_before = dynamic_backing_peek();
            let total_before = subprocess.total_thread_count();
            let live_before = subprocess.live_thread_count();
            let mut foreign = Theap::empty();
            let foreign_pointer = NonNull::from(&mut foreign);
            set_cached_theap(foreign_pointer);

            let result = unsafe {
                DynamicTheapAttachment::begin_with_components(
                    memory_config(),
                    pinned_empty_heap(),
                    subprocess,
                    metadata,
                    registry,
                )
            };
            let total_after = subprocess.total_thread_count();
            let live_after = subprocess.live_thread_count();
            let rejected = match result {
                Ok(mut owner) => {
                    owner
                        .teardown()
                        .expect("the old behavior must clean its isolated fixture");
                    false
                }
                Err(DynamicTheapBeginError::Retained { attachment, .. }) => {
                    core::mem::forget(attachment);
                    false
                }
                Err(DynamicTheapBeginError::Rejected(error)) => {
                    error == DynamicTheapError::RootOwnership
                }
            };

            assert!(rejected);
            assert_eq!(total_after, total_before);
            assert_eq!(live_after, live_before);
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert_eq!(cached_theap(), foreign_pointer);
            set_cached_theap(NonNull::from(crate::bootstrap::empty_default_theap()));
        })
        .join()
        .expect("foreign cached-root preflight stays allocation-free");
    }

    #[test]
    fn foreign_cached_root_rejects_before_ticket_zero_selection_or_allocation() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            let dynamic_before = dynamic_backing_peek();
            let fault = fault::install(fault::Plan::any_nth(
                1,
                crabc_core::Errno::NOMEM,
            ));
            let mut foreign = Theap::empty();
            let foreign_pointer = NonNull::from(&mut foreign);
            set_cached_theap(foreign_pointer);

            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::RootOwnership))
            ));
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert_eq!(registry.test_live_lease_count(), 0);
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert_eq!(cached_theap(), foreign_pointer);
            assert_eq!(
                fault.observed(),
                0,
                "the foreign cached-root gate precedes all OS-backed metadata work"
            );

            fault.set(fault::Plan::disabled());
            set_cached_theap(NonNull::from(crate::bootstrap::empty_default_theap()));
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(
                    DynamicTheapError::FirstTicketReserved
                ))
            ));
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert_eq!(registry.test_live_lease_count(), 0);
            assert_eq!(dynamic_backing_peek(), dynamic_before);
        })
        .join()
        .expect("foreign cached-root ownership wins before ticket-zero selection");
    }

    #[test]
    fn registry_claim_failure_after_tld_registration_cleans_up_without_retaining_live_count() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            registry.test_fail_next_bitmap_allocation();
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::Key(_)))
            ));
            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            assert!(roots.still_matches());
        })
        .join()
        .expect("recoverable registry OOM cleans up the activated TLD");
    }

    #[test]
    fn post_list_publication_backing_failure_returns_a_retained_poisoned_owner() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            let backing_size = crate::compiler_tls::DynamicThreadLocalBacking::allocation_size(16)
                .expect("the first source backing request is representable");
            assert_ne!(backing_size, size_of::<Theap>());
            metadata
                .get_ref()
                .test_fail_next_direct_zeroed_size(backing_size);
            let retained = match unsafe {
                DynamicTheapAttachment::begin_with_components(
                    memory_config(),
                    pinned_empty_heap(),
                    subprocess,
                    metadata,
                    registry,
                )
            } {
                Err(DynamicTheapBeginError::Retained { error, attachment }) => {
                    assert_eq!(
                        error,
                        DynamicTheapError::Backing(ThreadLocalBackingError::Metadata(
                            MetaError::AllocationUnavailable
                        ))
                    );
                    attachment
                }
                Ok(_) | Err(DynamicTheapBeginError::Rejected(_)) => {
                    panic!("a post-list backing allocation failure retains its concrete owner")
                }
            };
            let mut owner = retained;
            let theap_pointer = owner.theap_pointer().unwrap();
            assert_eq!(owner.state, DynamicAttachmentState::Poisoned);
            assert!(owner.backing.is_some());
            assert!(owner.tld.is_some());
            assert!(owner.theap.is_some());
            assert!(owner.binding.as_ref().is_some_and(|binding| !binding.slot_bound));
            assert_eq!(
                registry.test_live_lease_count(),
                1,
                "the unbound key lease stays live"
            );
            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 1);
            assert!(roots.still_matches());
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            assert!(owner.heap.as_ref().get_ref().has_exact_theap_member(theap_pointer));
            assert!(owner
                .tld
                .as_mut()
                .unwrap()
                .current_mut()
                .unwrap()
                .has_exact_theap_member(theap_pointer));
            assert!(owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .is_initialized());
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            assert_eq!(
                registry.test_live_lease_count(),
                1,
                "poisoning cannot release the key"
            );
            assert_eq!(subprocess.live_thread_count(), 1);
            // This isolated invalid-owner fixture deliberately retains every
            // terminal capability. Dropping the token would falsely model a
            // completed cleanup without a source-ordered release path.
            core::mem::forget(owner);
        })
        .join()
        .expect("retained post-publication owner test completes");
    }

    #[test]
    fn stale_regular_generation_is_null_after_teardown_and_slot_reclaim() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut first = attach(subprocess, metadata, registry, pinned_empty_heap());
            let stale = first.key().unwrap();
            first.teardown().unwrap();
            // `_mi_thread_locals_thread_done` leaves the old thread's backing
            // null. A later attachment therefore belongs to a fresh native
            // thread, while the process registry still reclaims the key.
            thread::spawn(move || {
                let mut second = attach(subprocess, metadata, registry, pinned_empty_heap());
                let current = second.key().unwrap();
                assert_eq!(current.index(), stale.index());
                assert_ne!(current.version(), stale.version());
                assert!(second.backing.as_mut().unwrap().get(stale).unwrap().is_null());
                assert!(!second.backing.as_mut().unwrap().get(current).unwrap().is_null());
                second.teardown().unwrap();
            })
            .join()
            .expect("a fresh native thread receives the reclaimed regular key");
        })
        .join()
        .expect("generation reuse remains source-stale-safe");
    }

    #[test]
    fn key_release_lock_failure_keeps_only_the_linear_lease_for_retry() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            registry.test_fail_next_release_lock();
            assert_eq!(
                owner.teardown(),
                Err(DynamicTheapError::Key(OwnedThreadLocalKeyError::Lock(
                    crabc_core::Errno::INTR
                )))
            );
            assert_eq!(owner.state, DynamicAttachmentState::AwaitingKeyRelease);
            assert!(owner.backing.is_none());
            assert!(owner.tld.is_none());
            assert!(owner.theap.is_none());
            assert!(owner.binding.as_ref().is_some_and(|binding| !binding.slot_bound));
            assert!(owner.heap.as_ref().get_ref().test_main_static_fields().theaps_empty);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(dynamic_backing_peek().is_none());
            owner
                .teardown()
                .expect("the exact retained lease retries its pre-mutation release");
            assert_eq!(owner.state, DynamicAttachmentState::TornDown);
        })
        .join()
        .expect("the key-release retry test completes");
    }

    #[test]
    fn dynamic_selection_never_seizes_ticket_zero_and_generic_zero_can_precede_a_later_attachment() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            let roots = UnrelatedRoots::capture();
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::FirstTicketReserved))
            ));
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(roots.still_matches());
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            assert_eq!(owner.tld.as_ref().unwrap().sequence().get(), 1);
            owner.teardown().unwrap();
        })
        .join()
        .expect("dynamic selection observes generic ticket-zero ownership exactly");
    }
}
