// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/arena.c:674-723,1101-1114,1240-1282`,
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
//! fresh/rollback/release use that image rather than `Arena::pages_main`.
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
    DynamicTheapPageMode, Heap, MemoryId, Page, PageQueue, Theap, TheapDynamicInitError,
    TheapOwner, ThreadLocalTheapListError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicAttachmentState {
    Preparing,
    Attached,
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
/// non-abandoning page engine's Theap session.
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

    /// Performs the bounded no-page teardown sequence.
    pub(crate) fn teardown(&mut self) -> Result<(), DynamicTheapError> {
        if self.state == DynamicAttachmentState::AwaitingKeyRelease {
            return self.finish_key_release();
        }
        self.prevalidate_teardown()?;

        let key = self.binding()?.key();
        let theap_pointer = self.theap_pointer()?;
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

    fn prevalidate_teardown(&mut self) -> Result<(), DynamicTheapError> {
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
            | DynamicAttachmentState::AwaitingKeyRelease
            | DynamicAttachmentState::Poisoned => {
                Err(DynamicTheapError::Poisoned)
            }
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
/// full attached/root/slot/list/refcount state and accepts only the typed mode
/// that disabled abandonment before `_mi_theap_init` published `heap`.
pub(crate) struct DynamicTheapPageSession<'attach, 'heap> {
    attachment: &'attach mut DynamicTheapAttachment<'heap>,
}

impl<'attach, 'heap> DynamicTheapPageSession<'attach, 'heap> {
    fn begin(
        attachment: &'attach mut DynamicTheapAttachment<'heap>,
    ) -> Result<Self, DynamicTheapPageSessionError> {
        attachment
            .prevalidate_teardown()
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

    /// Test-only non-mutating view of the attachment's teardown preflight.
    /// It never invokes teardown, clears a root, or detaches a list while the
    /// session owns the attachment borrow.
    #[cfg(test)]
    pub(crate) fn test_teardown_preflight(&mut self) -> Result<(), DynamicTheapError> {
        self.attachment.prevalidate_teardown()
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

impl theap_page_session_sealed::Sealed for DynamicTheapPageSession<'_, '_> {}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::{
        ArenaId, ArenaPagesLayout, ArenaRegistry, ArenaView, manage_external_in_place,
    };
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
    use crate::compiler_tls::{
        dynamic_backing_peek, is_empty_dynamic_backing, set_cached_theap,
    };
    use crate::os::{PageSize, fault};
    use crate::page_map::PageMap;
    use crate::single_thread::{
        DynamicMappedAbandonError, DynamicMappedAbandonFailure, DynamicTheapAllocator,
    };
    use crate::tld::ThreadLocalDataOwner;
    use crate::types::MemoryKind;
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
