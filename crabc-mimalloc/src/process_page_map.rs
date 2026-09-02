// Copyright (c) 2023-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h:371-386`
// (the `xthread_id` flag and special ownership encodings),
// `include/mimalloc/internal.h:753-769,960-1025,1112-1128` (checked two-level
// lookup, source page-state predicates, interior-pointer flag, and usable-block
// geometry), `src/page-map.c:468-511` (range registration and checked pointer
// lookup), `src/free.c:93-248` (atomic `xthread_id` snapshot, canonical
// aligned-block recovery, and free pointer dispatch), `src/alloc.c:364-439`
// (usable-size plus realloc's exact old-client copy prefix), `src/page-map.c:228-365`
// (`mi_page_map_init_once` and `_mi_page_map_init`), and
// `src/subproc.c:253-255` (the main-subprocess process-lifetime ownership of
// the global page map).

//! Process-owned publication of the global source page map.
//!
//! The mapped [`PageMap`] mechanics deliberately live in `page_map.rs`; this
//! module owns the missing process-wide state around them.  It initializes one
//! source-shaped global map from a frozen [`MemoryConfig`], binds it to one
//! selected [`MainSubprocess`], and Release-publishes its header through a
//! [`PageMapRoot`].  The returned lease is only a stable-root witness.  It
//! gives no page lifetime, arena, producer, or thread-exit authority, and the
//! map is process-lived until a future complete main-subprocess shutdown can
//! clear readers and destroy it.  The C static `mi_page_map_empty` pre-root is
//! deliberately not exposed yet: no Rust runtime lookup/free path may enter
//! this owner while it is cold.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use crabc_core::Errno;

use crate::abandoned::{AdoptedPage, RetainedAdoptFailure};
use crate::lock::{PrivateLock, PrivateLockGuard};
use crate::os::{Mapping, MemoryConfig};
use crate::page_map::{PageMap, PageMapHeader, PageMapInitializationError, PageMapRoot};
use crate::subproc::MainSubprocess;
use crate::types::{
    PAGE_FLAG_MASK, PAGE_HAS_INTERIOR_POINTERS, LiveThreadId, Page, PageFlags, ThreadId,
    THREAD_ID_ABANDONED, THREAD_ID_ABANDONED_MAPPED, THREAD_ID_DETACHED,
};

const COLD: u8 = 0;
const READY: u8 = 1;
const POISONED: u8 = 2;

/// The `mi_page_t` prefix read by the pointer-only source boundary.
///
/// `Page` is `repr(C)` and its source-compatible definition owns these first
/// fields in this order. This private prefix deliberately uses raw fields
/// instead of forming `&Page`: a foreign free, usable-size query, or realloc
/// lookup may run while the owning thread changes disjoint ordinary page
/// fields. `block_size` and `page_offset` are immutable from page publication
/// through final unregistration, while `xthread_id` is the source atomic flag
/// word. If the source `Page` prefix changes, this projection must change in
/// the same commit.
#[repr(C)]
struct PagePointerGeometry {
    _self: AtomicPtr<Page>,
    xthread_id: AtomicUsize,
    _free: *mut (),
    _used: usize,
    _local_free: *mut (),
    block_size: usize,
    page_offset: usize,
}

/// Source ownership state captured from a `mi_page_t::xthread_id` snapshot.
///
/// This is exactly the source identity after masking its two low flag bits:
/// `types.h` reserves zero for an ordinary abandoned page, four for an
/// abandoned page that remains mapped in its arena's abandoned bitmap, and
/// eight for the detached source identity. Every other source identity names
/// a currently associated owner. The observation neither validates that owner
/// nor selects a local-versus-remote free path; pinned `free.c` performs that
/// separate comparison against the caller's thread identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveAllocationPageState {
    /// A non-special source identity currently associates the page with an
    /// owner. The raw identity remains available on [`LiveAllocationPointer`].
    LiveOwnerAssociated,
    /// The source ordinary-abandoned identity (`MI_THREADID_ABANDONED`).
    Abandoned,
    /// The source abandoned-and-arena-mapped identity
    /// (`MI_THREADID_ABANDONED_MAPPED`).
    AbandonedMapped,
    /// The source detached identity (`MI_THREADID_DETACHED`).
    Detached,
}

#[inline]
const fn source_page_state(xthread_id: ThreadId) -> LiveAllocationPageState {
    match xthread_id & !PAGE_FLAG_MASK {
        THREAD_ID_ABANDONED => LiveAllocationPageState::Abandoned,
        THREAD_ID_ABANDONED_MAPPED => LiveAllocationPageState::AbandonedMapped,
        THREAD_ID_DETACHED => LiveAllocationPageState::Detached,
        _ => LiveAllocationPageState::LiveOwnerAssociated,
    }
}

/// Pointer-derived facts for one current native allocation.
///
/// This is a one-operation observation, not page ownership. The exact source
/// block remains live while this value is valid; pinned `free.c` relies on
/// that block to keep the PageMap registration and page metadata alive through
/// canonical-block recovery and local or atomic remote-free publication.
/// Normal-build [`crate::remote_free::push_live_allocation`] accepts this
/// concrete token rather than an independently supplied page/block pair, so
/// the checked lookup is the only production route into live remote
/// publication. A winning abandoned-page publication transfers this exact
/// observation into its linear claim until the source collection tail has
/// finished; an ordinary publication to an existing owner consumes it at the
/// CAS. Carrying this value does not permit ordinary page mutation, PageMap
/// registration, or final release, and it must not be retained after the
/// consuming source operation makes the client no longer live.
#[must_use = "live allocation facts must be consumed by one source operation"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LiveAllocationPointer {
    page: NonNull<Page>,
    client: NonNull<u8>,
    canonical_block: NonNull<u8>,
    block_size: usize,
    usable_size: usize,
    xthread_id: ThreadId,
    page_flags: PageFlags,
    page_state: LiveAllocationPageState,
    has_interior_pointers: bool,
}

/// One nonlocal-reallocation source derived from a current live allocation.
///
/// Pinned `mi_theap_realloc_zero_ex` copies from the exact old client, not
/// from its canonical free-list block. For an adjusted aligned allocation the
/// former starts after the latter, so the readable old extent is only the
/// client-relative usable prefix. This token keeps all three facts from one
/// PageMap observation together until the caller either releases the old
/// allocation through the normal pointer-centered path or returns it intact
/// after replacement allocation failure.
///
/// The token deliberately has no `Clone` or `Copy` implementation. Its
/// `copy_prefix_len` is frozen when it is formed, before replacement
/// allocation or old-block release, and it cannot be recomputed from a
/// replacement pointer or a later page lookup. It grants no page,
/// PageMap, owner, replacement-allocation, or release authority.
#[must_use = "the old live allocation must remain held through its replacement copy or failure path"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LiveAllocationReallocationSource {
    allocation: LiveAllocationPointer,
    copy_prefix_len: usize,
}

impl LiveAllocationReallocationSource {
    /// Returns the exact old client pointer that starts the readable prefix.
    ///
    /// This is the source address for replacement copying. In particular, it
    /// is not interchangeable with [`Self::canonical_block_for_release`] when
    /// the source page permits interior allocation pointers.
    #[inline]
    pub(crate) const fn copy_client(&self) -> NonNull<u8> { self.allocation.client }

    /// Returns the source free-list block recovered for the old client.
    ///
    /// This is retained for the later pointer-centered release operation. It
    /// is never the start of the replacement copy for an interior client.
    #[inline]
    pub(crate) const fn canonical_block_for_release(&self) -> NonNull<u8> {
        self.allocation.canonical_block
    }

    /// Returns the complete readable prefix that begins at [`Self::copy_client`].
    ///
    /// This is the PageMap observation's client-relative usable extent, not
    /// the page block size. It excludes aligned-allocation adjustment bytes
    /// before the client pointer.
    #[inline]
    pub(crate) const fn usable_prefix_len(&self) -> usize { self.allocation.usable_size }

    /// Returns the exact prefix length a replacement may copy.
    ///
    /// This equals `min(replacement_request, usable_prefix_len())`, captured
    /// with the old allocation before replacement allocation and old-block
    /// release. It is therefore safe from both an interior-pointer over-copy
    /// and accidental reuse of a replacement allocation's extent.
    #[inline]
    pub(crate) const fn copy_prefix_len(&self) -> usize { self.copy_prefix_len }

    /// Returns the original one-operation PageMap observation.
    ///
    /// Call this only after replacement copying has completed or replacement
    /// allocation has failed. The returned observation must then follow its
    /// own existing general-free or failure-preservation contract.
    #[inline]
    pub(crate) fn into_live_allocation(self) -> LiveAllocationPointer { self.allocation }
}

impl LiveAllocationPointer {
    /// Returns the source page selected by the two-level PageMap.
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> { self.page }

    /// Returns the exact client pointer supplied to the lookup.
    #[inline]
    pub(crate) const fn client(&self) -> NonNull<u8> { self.client }

    /// Returns the source free-list block for `client`.
    ///
    /// This equals [`Self::client`] for normal pages and is the aligned block
    /// base for pages whose source flag permits interior allocation pointers.
    #[inline]
    pub(crate) const fn canonical_block(&self) -> NonNull<u8> { self.canonical_block }

    /// Returns the fixed source block size captured during classification.
    #[inline]
    pub(crate) const fn block_size(&self) -> usize { self.block_size }

    /// Returns the source usable extent beginning at the exact client pointer.
    #[inline]
    pub(crate) const fn usable_size(&self) -> usize { self.usable_size }

    /// Consumes this observation into a bounded source for one replacement.
    ///
    /// The returned token fixes the exact old client, canonical release block,
    /// and `min(replacement_request, usable_size)` copy prefix from this one
    /// observation. This preserves the old allocation's one-operation
    /// lifetime boundary across a nonlocal replacement: callers cannot copy
    /// from a canonical aligned block by accident or derive the old extent
    /// from a later replacement allocation.
    #[inline]
    pub(crate) fn into_reallocation_copy_source(
        self,
        replacement_request: usize,
    ) -> LiveAllocationReallocationSource {
        let copy_prefix_len = core::cmp::min(replacement_request, self.usable_size);
        LiveAllocationReallocationSource { allocation: self, copy_prefix_len }
    }

    /// Returns the raw source `mi_page_t::xthread_id` atomic snapshot.
    ///
    /// The low two bits are the source page flags; use [`Self::page_flags`]
    /// and [`Self::page_state`] for their decoded observational forms. This is
    /// not a caller-relative local/remote decision and must not be retained as
    /// page ownership.
    #[inline]
    pub(crate) const fn xthread_id(&self) -> ThreadId { self.xthread_id }

    /// Returns the two source page-flag bits captured with `xthread_id`.
    #[inline]
    pub(crate) const fn page_flags(&self) -> PageFlags { self.page_flags }

    /// Returns the source ownership state decoded from the same atomic
    /// `xthread_id` snapshot.
    #[inline]
    pub(crate) const fn page_state(&self) -> LiveAllocationPageState { self.page_state }

    /// Reports whether the captured source identity names `owner`.
    ///
    /// This is the caller-relative comparison performed after pointer lookup
    /// by pinned `mi_free_nonnull`; page flags remain a separate dispatch
    /// input. A false result covers both another live owner and every special
    /// abandoned/detached source identity.
    #[inline]
    pub(crate) const fn is_associated_with(&self, owner: LiveThreadId) -> bool {
        self.xthread_id & !PAGE_FLAG_MASK == owner.get()
    }

    /// Reports the source page-wide interior-pointer flag.
    #[inline]
    pub(crate) const fn has_interior_pointers(&self) -> bool { self.has_interior_pointers }

}

/// Classifies one current allocation after its source PageMap lookup.
///
/// # Safety
///
/// `page` must be initialized, registered for `client`, and remain address
/// stable through the returned observation's last use. `client` must be a
/// current native allocation from that page. Its allocation lifetime must
/// prevent source retirement, PageMap unregistration, metadata reuse, and
/// mapping release until any subsequent free publication, usable-size read, or
/// realloc decision consumes the returned facts. The caller may not treat
/// `None` as validation of an arbitrary C pointer.
#[inline]
unsafe fn classify_live_allocation_in_page(
    page: NonNull<Page>,
    client: NonNull<u8>,
) -> Option<LiveAllocationPointer> {
    let geometry = page.as_ptr().cast::<PagePointerGeometry>();
    // SAFETY: the caller proves this initialized page remains stable. This is
    // a reference to the one atomic source field only; it never creates a
    // shared `Page` reference beside the owner's ordinary field mutation.
    let xthread_id = unsafe { &*core::ptr::addr_of!((*geometry).xthread_id) };
    // Pinned `mi_free_nonnull` takes this same relaxed atomic word once before
    // it derives caller-relative dispatch. Keep the complete raw snapshot so
    // later source dispatch can use it without dereferencing `theap` or
    // acquiring a structural PageMap mutation lease.
    let xthread_id = xthread_id.load(Ordering::Relaxed);
    let page_flags = xthread_id & PAGE_FLAG_MASK;
    let page_state = source_page_state(xthread_id);
    let has_interior_pointers = page_flags & PAGE_HAS_INTERIOR_POINTERS != 0;
    // SAFETY: source page publication fixes these geometry fields before the
    // allocation becomes visible. The caller's live-client proof keeps the
    // page from reuse or final release, so raw reads do not overlap a write.
    let block_size = unsafe { (*geometry).block_size };
    let page_offset = unsafe { (*geometry).page_offset };
    if block_size == 0 {
        return None;
    }
    let page_start = page.as_ptr().addr().checked_add(page_offset)?;
    let client_address = client.as_ptr().addr();
    let canonical_block = if has_interior_pointers {
        let block_address = crate::aligned::recover_block_start(
            client_address,
            page_start,
            block_size,
        )?;
        let adjustment = client_address.checked_sub(block_address)?;
        // SAFETY: the source recovery rounds an exact live client down within
        // its same source block. Retaining `client` provenance while subtracting
        // the checked adjustment avoids manufacturing a pointer from an integer.
        NonNull::new(client.as_ptr().wrapping_sub(adjustment))?
    } else {
        client
    };
    let usable_size = crate::aligned::usable_size(
        block_size,
        client_address,
        canonical_block.as_ptr().addr(),
    )?;

    Some(LiveAllocationPointer {
        page,
        client,
        canonical_block,
        block_size,
        usable_size,
        xthread_id,
        page_flags,
        page_state,
        has_interior_pointers,
    })
}

/// Process-static storage for the one main-subprocess global page map.
///
/// The `PageMap` lives in its final slot before its root is published.  The
/// storage has no destruction entry point: `src/subproc.c` may destroy the
/// global map only as part of main-subprocess destruction, which is not yet a
/// completed lifecycle in this port.  That deliberate process lifetime makes
/// a published lease safe to copy without turning a raw page pointer into an
/// owner.
pub(crate) struct ProcessPageMapStorage {
    state: AtomicU8,
    initialization_lock: PrivateLock,
    /// Rust-side exclusion boundary for the source page map's plain entry
    /// reads and writes. This is deliberately separate from initialization
    /// and from the source map's individual submap locks. A normal bounded
    /// engine holds it for its complete owner/producer lifetime. A future
    /// source-shaped thread-exit handoff may instead transfer it to a
    /// process-lived route which reacquires it around each complete
    /// lookup/free/release decision; it never leaves a plain entry access
    /// unguarded between those two forms.
    page_lifecycle_lock: PrivateLock,
    /// Number of separately typed post-exit continuations whose source pages
    /// still use short PageMap access. It is not a lock and never names a
    /// client or page; it prevents one route from consuming into a long
    /// engine while a sibling detached route remains.
    post_exit_route_count: AtomicUsize,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    subprocess: AtomicPtr<MainSubprocess>,
    page_map: UnsafeCell<MaybeUninit<PageMap>>,
    /// The exact unpublished mapping retained when PageMap bootstrap's
    /// cleanup `munmap` fails. It is distinct from `page_map`: no PageMap was
    /// formed on this branch, and overwriting this slot would lose a live VM
    /// owner. Process lifetime is the production terminal owner until the
    /// source main-subprocess destruction lifecycle is ported.
    retained_initialization_mapping: UnsafeCell<MaybeUninit<Mapping>>,
    has_retained_initialization_mapping: AtomicBool,
    root: PageMapRoot,
}

// SAFETY: `initialization_lock` serializes every write to the final slots.
// READY is Release-published only after the initialized map/header/config and
// root are all valid.  The `PageMap` itself retains its documented source
// plain-entry synchronization contract; this storage does not claim to
// serialize registration or lookup.  The process lifetime forbids a safe
// concurrent destroy while a lease or root reader can exist.
unsafe impl Sync for ProcessPageMapStorage {}

impl ProcessPageMapStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(COLD),
            initialization_lock: PrivateLock::new(),
            page_lifecycle_lock: PrivateLock::new(),
            post_exit_route_count: AtomicUsize::new(0),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            subprocess: AtomicPtr::new(core::ptr::null_mut()),
            page_map: UnsafeCell::new(MaybeUninit::uninit()),
            retained_initialization_mapping: UnsafeCell::new(MaybeUninit::uninit()),
            has_retained_initialization_mapping: AtomicBool::new(false),
            root: PageMapRoot::empty(),
        }
    }

    /// Returns the process-static source owner.  It stays cold until a future
    /// runtime startup path supplies its frozen memory configuration and
    /// selected main-subprocess identity.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_PAGE_MAP
    }

    /// Builds a deliberately leaked process-lifetime storage fixture.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    /// Test-only observation of pre-publication state. It exposes no map
    /// reference and is used by source-order regressions to prove that a
    /// process preflight rejection never manufactures a global root.
    #[cfg(test)]
    pub(crate) fn test_has_published_root(&self) -> bool {
        self.root.load().is_some()
    }

    /// Test-only observation of the retained private bootstrap owner. It
    /// grants neither a mapping reference nor a retry path.
    #[cfg(test)]
    pub(crate) fn test_has_retained_initialization_mapping(&self) -> bool {
        self.has_retained_initialization_mapping.load(Ordering::Acquire)
    }

    /// Releases the exact retained bootstrap mapping after a test removes its
    /// injected cleanup fault. A failed retry writes the same owner back into
    /// the final slot before returning.
    #[cfg(test)]
    pub(crate) fn test_release_retained_initialization_mapping(
        &'static self,
    ) -> Result<(), Errno> {
        let guard = self.initialization_lock.lock()?;
        if !self.has_retained_initialization_mapping.load(Ordering::Acquire) {
            return match guard.unlock() {
                Ok(()) => Err(Errno::INVAL),
                Err(error) => Err(error),
            };
        }
        // SAFETY: the initialization lock excludes every other slot access,
        // and the Acquire flag proves the initialization path wrote one live
        // mapping before it poisoned this storage.
        let mut mapping = unsafe {
            (*self.retained_initialization_mapping.get()).assume_init_read()
        };
        let release = match mapping.unmap() {
            Ok(()) => {
                self.has_retained_initialization_mapping
                    .store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                // SAFETY: the same lock still excludes another owner, and
                // failed `unmap` leaves this exact Mapping live.
                unsafe { self.write_retained_initialization_mapping(mapping) };
                Err(error)
            }
        };
        let unlock = guard.unlock();
        match (release, unlock) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Initializes or obtains the process-global map for `subprocess`.
    ///
    /// The source default `mi_option_max_vabits == 0` is passed as the
    /// configured value, so [`PageMap::initialize`] observes the frozen
    /// selected Linux-profile virtual-address width. Option parsing and process
    /// shutdown are intentionally separate future boundaries.
    pub(crate) fn initialize(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessPageMapLease, ProcessPageMapError> {
        // Source `_mi_atomic_once_enter` has a completed fast path.  Preserve
        // that no-lock read for the common process-ready case; a cold caller
        // still takes the private lock so only one final slot can be formed.
        if self.state.load(Ordering::Acquire) == READY {
            return self.lease_if_matches(config, subprocess);
        }
        let guard = self
            .initialization_lock
            .lock()
            .map_err(ProcessPageMapError::Lock)?;

        let result = match self.state.load(Ordering::Acquire) {
            COLD => self.initialize_cold(config, subprocess),
            READY => self.lease_if_matches(config, subprocess),
            POISONED | _ => Err(ProcessPageMapError::Poisoned),
        };
        let unlock = guard.unlock();

        match (result, unlock) {
            (Ok(lease), Ok(())) => Ok(lease),
            (Ok(_), Err(error)) => {
                // The map/root are already published.  A private-futex wake
                // failure has no source equivalent and cannot safely be
                // retried as if initialization had remained private.
                self.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
            (Err(error), Err(_)) => {
                // The source-shaped map attempt determines the observable
                // outcome before a later private-futex wake failure. The
                // atomic unlock has already occurred either way, and no root
                // was published on this branch.
                Err(error)
            }
            (Err(error), Ok(())) => Err(error),
        }
    }

    fn initialize_cold(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessPageMapLease, ProcessPageMapError> {
        let page_map = match PageMap::initialize(config, 0, false) {
            Ok(page_map) => page_map,
            Err(PageMapInitializationError::Failed { error }) => {
                // `_mi_page_map_init` runs its body through source
                // `mi_atomic_do_once`: an initialization attempt is never
                // replayed.  We retain that once-only transition but report a
                // durable explicit error instead of letting a later caller
                // mistake an unpublished Rust root for C's static empty map.
                self.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Initialization(error));
            }
            Err(PageMapInitializationError::Retained {
                initialization,
                cleanup,
                mapping,
            }) => {
                // SAFETY: the initialization lock is held, COLD excludes all
                // readers, and no PageMap/root was formed. The failed cleanup
                // left this exact mapping live, so it must enter its final
                // terminal owner before POISONED is published.
                unsafe { self.write_retained_initialization_mapping(mapping) };
                self.has_retained_initialization_mapping
                    .store(true, Ordering::Release);
                self.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::InitializationRetained {
                    initialization,
                    cleanup,
                });
            }
        };
        // SAFETY: the initialization lock is held, COLD excludes every
        // reader, and this process-static slot is the page map's final
        // address.  `page_map` has not yet been published through `root`.
        unsafe { (*self.page_map.get()).write(page_map) };
        // SAFETY: same exclusive COLD-state publication proof as the map.
        unsafe { (*self.config.get()).write(config) };
        self.subprocess.store(subprocess.as_ptr(), Ordering::Release);

        // SAFETY: the map was fully initialized in its final slot and is
        // process-lived.  The Release root publication makes its initialized
        // header visible to later Acquire readers.
        unsafe { self.root.publish(self.page_map_ref()) };
        self.state.store(READY, Ordering::Release);
        Ok(ProcessPageMapLease { storage: self })
    }

    /// Writes the exact private PageMap bootstrap mapping into its terminal
    /// process-static owner.
    ///
    /// # Safety
    ///
    /// The caller holds `initialization_lock`, the state is COLD, no root was
    /// published, and the slot has not previously been initialized.
    #[inline]
    unsafe fn write_retained_initialization_mapping(&self, mapping: Mapping) {
        unsafe { (*self.retained_initialization_mapping.get()).write(mapping) };
    }

    fn lease_if_matches(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessPageMapLease, ProcessPageMapError> {
        let stored_config = self.config();
        if stored_config != config {
            return Err(ProcessPageMapError::ConfigurationMismatch);
        }
        if !core::ptr::eq(self.subprocess.load(Ordering::Acquire), subprocess.as_ptr()) {
            return Err(ProcessPageMapError::SubprocessMismatch);
        }
        if self.root.load().is_none() {
            self.state.store(POISONED, Ordering::Release);
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(ProcessPageMapLease { storage: self })
    }

    #[inline]
    fn config(&self) -> MemoryConfig {
        // SAFETY: callers reach this only in READY state, whose Release store
        // follows the final-slot write and is observed under the
        // initialization lock or with an Acquire state check.
        unsafe { *(*self.config.get()).assume_init_ref() }
    }

    #[inline]
    fn page_map_ref(&'static self) -> &'static PageMap {
        // SAFETY: the page-map slot is initialized before root/READY
        // publication and is never destroyed by this bounded process owner.
        unsafe { (*self.page_map.get()).assume_init_ref() }
    }

    /// Registers one detached source continuation before its old long lease
    /// becomes short post-exit access. A count overflow is not recoverable:
    /// the current engine has already reached a one-way owner-exit boundary,
    /// so preserve the process root instead of wrapping to a false quiescent
    /// image.
    fn begin_post_exit_route(&self) -> Result<(), ProcessPageMapError> {
        loop {
            let observed = self.post_exit_route_count.load(Ordering::Acquire);
            let Some(next) = observed.checked_add(1) else {
                self.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Poisoned);
            };
            if self
                .post_exit_route_count
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Removes one completed detached continuation. The caller's typed route
    /// proves it had terminally released every source page before this count
    /// changes; a zero or failed transition keeps the process root terminal
    /// rather than letting a sibling route look alone and adoptable.
    fn finish_post_exit_route(&self) -> Result<(), ProcessPageMapError> {
        loop {
            let observed = self.post_exit_route_count.load(Ordering::Acquire);
            let Some(next) = observed.checked_sub(1) else {
                self.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Poisoned);
            };
            if self
                .post_exit_route_count
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    #[cfg(test)]
    #[inline]
    fn test_post_exit_route_count(&self) -> usize {
        self.post_exit_route_count.load(Ordering::Acquire)
    }
}

/// A stable process-global page-map root witness.
///
/// This capability is Send/Sync because it only names process-static storage;
/// callers must separately uphold [`PageMap`]'s explicit synchronization and
/// page-lifetime requirements before registering, unregistering, or looking
/// up a page.
#[derive(Clone, Copy)]
pub(crate) struct ProcessPageMapLease {
    storage: &'static ProcessPageMapStorage,
}

// SAFETY: the lease contains one process-static address. It cannot mutate the
// map or bypass PageMap's own unsafe range and lifetime contracts.
unsafe impl Send for ProcessPageMapLease {}
// SAFETY: see the Send justification above.
unsafe impl Sync for ProcessPageMapLease {}

/// The only completed operation states for one mapped-abandoned claim.
///
/// `AdoptedPage` is deliberately not exposed directly: it predates the final
/// complete-span proof. The closure can return [`Self::Claimed`] only through
/// [`MappedAbandonedClaimAccess::claim_after_full_span_validation`], which
/// consumes the scoped PageMap capability after source reassociation and the
/// target owner's exact `release_span` / all-PageMap-entry validation. The
/// resulting linear token then names the A-to-B range transfer.
#[must_use = "a completed mapped-abandoned claim must be consumed as a no-candidate, claimed range, or terminal retained range"]
pub(crate) enum MappedAbandonedClaimCompletion {
    /// The selected source bitmap search completed without an adopted page.
    /// No low-owner claim remains with this operation, so a caller may resume
    /// the pinned ordinary fresh-page path after the outer lock releases.
    NoCandidate(MappedAbandonedClaimNoCandidate),
    /// The source bitmap/low-owner operation reassociated one page with the
    /// target and the complete arena/PageMap span was validated before this
    /// token left the short closure.
    Claimed(MappedAbandonedClaimedRange),
    /// A low-owner claim already occurred but the source adoption or target
    /// span validation could not complete. This retains the exact page and a
    /// source-specific reason; constructing it terminally poisons the root.
    Retained(MappedAbandonedClaimRetainedRange),
}

/// Proof that this scoped source attempt completed before a low-owner claim.
///
/// Its field is private so only [`MappedAbandonedClaimAccess::no_candidate`]
/// can construct the clean completion.  In particular, safe crate code cannot
/// cross the low-owner boundary and then forge a `NoCandidate` return that
/// would reopen the root.
#[must_use = "the no-candidate proof completes exactly one claim access"]
pub(crate) struct MappedAbandonedClaimNoCandidate {
    _scoped: (),
}

/// The outer state of one nonblocking mapped-abandoned claim access.
///
/// [`Self::Busy`] is the only clean retry result: its closure did not run and
/// the map root remains reusable. Every other non-success result either names
/// an invalid paired root or a terminal root, and must not turn into a fresh
/// allocation fallback. In particular, [`Self::UnlockFailed`] returns the
/// completed claim token because the source operation happened before the
/// private futex wake failed.
#[must_use = "a mapped-abandoned claim outcome must preserve its exact source ownership state"]
pub(crate) enum MappedAbandonedClaimOutcome {
    /// A normal page lifecycle currently owns the source-plain map. The
    /// closure did not run and no candidate state changed.
    Busy,
    /// The supplied map lease and validated process-page-arena lease name
    /// different immutable PageMap roots. No lock was acquired and no source
    /// state changed.
    PairMismatch,
    /// This root was already terminal, became terminal before the closure
    /// could run. The closure did not run.
    RootTerminal,
    /// The closure did not run, but releasing the pre-closure short lock
    /// reported a private-futex wake failure. The root is poisoned and the
    /// error remains distinct from a prior terminal state.
    RootTerminalLock(Errno),
    /// The closure completed and the short PageMap exclusion boundary released
    /// normally.
    Completed(MappedAbandonedClaimCompletion),
    /// The closure completed, then the private lock's Release transition
    /// reported a wake failure. The root is already poisoned. `completion`
    /// preserves a claimed or retained exact range so the target owner can be
    /// latched terminally instead of forgetting the source transfer.
    UnlockFailed {
        completion: MappedAbandonedClaimCompletion,
        error: Errno,
    },
}

/// One PageMap borrow scoped to exactly one mapped-abandoned source attempt.
///
/// This is constructed only by
/// [`ProcessPageMapLease::try_with_validated_mapped_abandoned_claim`]. It can
/// expose the map only during that closure, and its consuming constructors are
/// the only normal way to turn a source `AdoptedPage` or
/// `RetainedAdoptFailure` into an outer completion state.
pub(crate) struct MappedAbandonedClaimAccess<'map> {
    page_map: &'map PageMap,
    storage: &'static ProcessPageMapStorage,
    completed: bool,
}

impl<'map> MappedAbandonedClaimAccess<'map> {
    /// Borrows the map only for the current selected bitmap/low-owner claim
    /// sequence. The higher-ranked outer closure prevents a normal reference
    /// escape; callers must not manufacture a raw PageMap escape.
    #[inline]
    pub(crate) fn page_map(&self) -> &'map PageMap { self.page_map }

    /// Completes the scoped attempt before any source low-owner claim won.
    #[inline]
    pub(crate) fn no_candidate(mut self) -> MappedAbandonedClaimCompletion {
        self.completed = true;
        MappedAbandonedClaimCompletion::NoCandidate(MappedAbandonedClaimNoCandidate {
            _scoped: (),
        })
    }

    /// Transfers one adopted page into the target-owned exact-range token.
    ///
    /// # Safety
    ///
    /// `adopted` must be the result of this closure's one
    /// `abandoned::try_adopt_retained` call. Before calling this method, the
    /// closure must have validated the target Theap/Heap association and its
    /// complete `ReleaseSpan::Arena` shape, including every matching PageMap
    /// entry, while this access remains live. It must perform no later source
    /// PageMap operation or second bitmap search. The returned token may be
    /// consumed only after the outer outcome reports a normal completion (or
    /// an explicitly latched terminal unlock failure).
    pub(crate) unsafe fn claim_after_full_span_validation(
        self,
        adopted: AdoptedPage,
    ) -> MappedAbandonedClaimCompletion {
        self.claim(adopted.page())
    }

    #[cfg(test)]
    /// Builds a claimed completion from a non-dereferenced fixture page.
    ///
    /// This exists only to test this scope's completion and linear-handoff
    /// state mechanics. It does not model bitmap selection, source adoption,
    /// or the required production full-span validation.
    ///
    /// # Safety
    ///
    /// The test must treat `page` only as an opaque, non-dereferenced page
    /// identity and model a completed exact-range transfer.
    pub(crate) unsafe fn test_claim_after_full_span_validation(
        self,
        page: NonNull<Page>,
    ) -> MappedAbandonedClaimCompletion {
        self.claim(page)
    }

    #[inline]
    fn claim(mut self, page: NonNull<Page>) -> MappedAbandonedClaimCompletion {
        self.completed = true;
        MappedAbandonedClaimCompletion::Claimed(MappedAbandonedClaimedRange {
            storage: self.storage,
            page,
            handed_off: false,
        })
    }

    /// Retains a source adoption failure after its low-owner claim.
    ///
    /// # Safety
    ///
    /// `failure` must be this closure's `try_adopt_retained` failure. Its
    /// exact page remains live with the low owner held; no fresh fallback,
    /// unowned retry, or PageMap operation may follow this transition.
    pub(crate) unsafe fn retain_after_adopt_failure(
        self,
        failure: RetainedAdoptFailure,
    ) -> MappedAbandonedClaimCompletion {
        self.retain(
            failure.page(),
            MappedAbandonedClaimRetainedReason::Adoption(failure),
        )
    }

    /// Retains an adopted page whose target-owned exact span did not validate.
    ///
    /// # Safety
    ///
    /// `adopted` must be this closure's successfully low-owner-claimed source
    /// adoption. The failed validation means its page remains a terminal
    /// target owner; it cannot be reabandoned or replaced with a fresh page
    /// through this access.
    pub(crate) unsafe fn retain_after_span_validation_failure(
        self,
        adopted: AdoptedPage,
    ) -> MappedAbandonedClaimCompletion {
        self.retain(
            adopted.page(),
            MappedAbandonedClaimRetainedReason::SpanValidation,
        )
    }

    #[cfg(test)]
    /// Builds a terminal retained completion from a fixture page.
    ///
    /// This checks the claim scope's terminal state mechanics only; it does
    /// not model the production low-owner or span-validation transition.
    ///
    /// # Safety
    ///
    /// The test must treat `page` as an opaque, non-dereferenced page and
    /// retain the returned terminal token through its assertion.
    pub(crate) unsafe fn test_retain_after_span_validation_failure(
        self,
        page: NonNull<Page>,
    ) -> MappedAbandonedClaimCompletion {
        self.retain(page, MappedAbandonedClaimRetainedReason::SpanValidation)
    }

    #[inline]
    fn retain(
        mut self,
        page: NonNull<Page>,
        reason: MappedAbandonedClaimRetainedReason,
    ) -> MappedAbandonedClaimCompletion {
        self.completed = true;
        MappedAbandonedClaimCompletion::Retained(MappedAbandonedClaimRetainedRange::terminal(
            self.storage,
            page,
            reason,
        ))
    }
}

impl Drop for MappedAbandonedClaimAccess<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // The closure neither proved a clean no-candidate search nor
            // handed a low-owner result to an explicit token.  This includes
            // unwinding before its terminal completion constructor, so do not
            // release the short exclusion boundary into a reusable root.
            self.storage.state.store(POISONED, Ordering::Release);
        }
    }
}

/// The exact target-owned page range after source adoption and full span
/// validation.
///
/// Dropping this token means the caller lost an A-to-B ownership transfer.
/// Conservatively poison the process root rather than reopen a map whose
/// source low owner may still name this page.
#[must_use = "a claimed mapped-abandoned range must transfer to its target owner or terminally retain the root"]
pub(crate) struct MappedAbandonedClaimedRange {
    storage: &'static ProcessPageMapStorage,
    page: NonNull<Page>,
    handed_off: bool,
}

impl MappedAbandonedClaimedRange {
    /// Consumes the validated transfer token into the target owner's page.
    ///
    /// # Safety
    ///
    /// Call this only after matching an outer
    /// [`MappedAbandonedClaimOutcome::Completed`] result, or after explicitly
    /// latching the target owner terminally for
    /// [`MappedAbandonedClaimOutcome::UnlockFailed`]. The target must retain
    /// the page through its complete queue/reclaim/reabandon/release tail and
    /// must not fresh-fallback while that range remains live.
    pub(crate) unsafe fn into_page(mut self) -> NonNull<Page> {
        self.handed_off = true;
        self.page
    }
}

impl Drop for MappedAbandonedClaimedRange {
    fn drop(&mut self) {
        if !self.handed_off {
            self.storage.state.store(POISONED, Ordering::Release);
        }
    }
}

/// The reason a low-owner-claimed page became a terminal retained range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappedAbandonedClaimRetainedReason {
    /// `try_adopt_retained` failed after its bitmap/low-owner transition.
    Adoption(RetainedAdoptFailure),
    /// The target-owned complete arena/PageMap span did not validate after
    /// successful source adoption.
    SpanValidation,
}

/// One terminal retained source page after a low-owner claim.
///
/// Its constructor poisons the root immediately. The page and reason remain
/// available only to the caller's explicit terminal owner; ordinary allocation
/// cannot resume through this map root.
#[must_use = "a retained mapped-abandoned range must remain with an explicit terminal owner"]
pub(crate) struct MappedAbandonedClaimRetainedRange {
    storage: &'static ProcessPageMapStorage,
    page: NonNull<Page>,
    reason: MappedAbandonedClaimRetainedReason,
}

impl MappedAbandonedClaimRetainedRange {
    #[inline]
    fn terminal(
        storage: &'static ProcessPageMapStorage,
        page: NonNull<Page>,
        reason: MappedAbandonedClaimRetainedReason,
    ) -> Self {
        storage.state.store(POISONED, Ordering::Release);
        Self {
            storage,
            page,
            reason,
        }
    }

    /// Returns the terminal source reason while retaining the range token.
    #[inline]
    pub(crate) const fn reason(&self) -> MappedAbandonedClaimRetainedReason { self.reason }

    /// Borrows the terminally retained raw page for an explicit terminal
    /// owner transition.
    ///
    /// # Safety
    ///
    /// The caller must keep this range terminally retained and must not use
    /// the pointer to resume normal allocation, a fresh fallback, or an
    /// unowned source retry. The root is already poisoned.
    #[inline]
    pub(crate) unsafe fn page(&self) -> NonNull<Page> { self.page }
}

impl Drop for MappedAbandonedClaimRetainedRange {
    fn drop(&mut self) {
        self.storage.state.store(POISONED, Ordering::Release);
    }
}

/// Poisons the root before releasing a short claim lock if its closure does
/// not return normally. This prevents unwinding from exposing a successful
/// bitmap/low-owner transition as a fresh reusable PageMap lifecycle.
struct MappedAbandonedClaimScope {
    storage: &'static ProcessPageMapStorage,
    guard: Option<PrivateLockGuard<'static>>,
    completed: bool,
}

impl MappedAbandonedClaimScope {
    #[inline]
    fn new(storage: &'static ProcessPageMapStorage, guard: PrivateLockGuard<'static>) -> Self {
        Self {
            storage,
            guard: Some(guard),
            completed: false,
        }
    }

    #[inline]
    fn complete(&mut self) {
        self.completed = true;
    }

    fn unlock(mut self) -> Result<(), Errno> {
        let Some(guard) = self.guard.take() else {
            // This scope is normally constructed with exactly one guard. If
            // an internal future change violates that invariant after the
            // closure completed, do not let the completed Drop path reopen
            // the root as though it had released normally.
            self.storage.state.store(POISONED, Ordering::Release);
            return Err(Errno::INVAL);
        };
        let result = guard.unlock();
        if result.is_err() {
            // `PrivateLockGuard::unlock` already made the Release visible.
            // Its guard is consumed, so this scope's Drop cannot observe it;
            // record terminal state here before the caller sees the error.
            self.storage.state.store(POISONED, Ordering::Release);
        }
        result
    }
}

impl Drop for MappedAbandonedClaimScope {
    fn drop(&mut self) {
        if !self.completed && self.guard.is_some() {
            // Store before `guard` drops so a waiter cannot observe an
            // unlocked-but-healthy root after a panic or early path that may
            // have crossed the low-owner boundary.
            self.storage.state.store(POISONED, Ordering::Release);
        }
    }
}

impl ProcessPageMapLease {
    /// Returns the published source root after confirming the process owner
    /// remains live.
    pub(crate) fn root(self) -> Result<NonNull<PageMapHeader>, ProcessPageMapError> {
        self.ensure_ready()?;
        self.storage.root.load().ok_or(ProcessPageMapError::Poisoned)
    }

    /// Returns the frozen memory configuration of the process page map.
    #[inline]
    pub(crate) fn memory_config(self) -> Result<MemoryConfig, ProcessPageMapError> {
        self.ensure_ready()?;
        if self.storage.root.load().is_none() {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.config())
    }

    /// Runs one complete selected mapped-abandoned claim attempt while holding
    /// the PageMap's plain-entry exclusion boundary.
    ///
    /// The paired lease is rechecked against this map's immutable root before
    /// the nonblocking `try_lock`. A bare map lease therefore cannot enter the
    /// short claim path without an independently validated
    /// [`crate::process_arena::ProcessPageArenaLease`] witness. This does not
    /// construct a [`ProcessPageMapMutationLease`] or enter W03's blocking
    /// post-owner-exit mutation path.
    ///
    /// # Safety
    ///
    /// `paired` must remain the selected process map/arena pair, and the
    /// caller must retain the selected static-main arena, target Theap/Heap,
    /// page metadata, and complete candidate PageMap span for the call. The
    /// closure may perform only one pinned source sequence: resolver lookup,
    /// matching bitmap/low-owner claim, `try_adopt_retained`, and full target
    /// `release_span`/all-PageMap-span validation. It must then finish through
    /// one [`MappedAbandonedClaimAccess`] constructor. It must not retain a
    /// raw PageMap access, perform another candidate search, register or
    /// unregister a range, use W03, or call
    /// [`MappedAbandonedClaimedRange::into_page`] inside the closure.
    ///
    /// Any successful claim must return `Claimed`; any post-low-owner failure
    /// must return `Retained`. The caller owns the resulting target page only
    /// after it matches the outer outcome and consumes the linear range token
    /// under that token's contract. A closure that panics or unwinds is
    /// terminally retained before its lock releases.
    pub(crate) unsafe fn try_with_validated_mapped_abandoned_claim(
        self,
        paired: crate::process_arena::ProcessPageArenaLease,
        operation: impl for<'map> FnOnce(
            MappedAbandonedClaimAccess<'map>,
        ) -> MappedAbandonedClaimCompletion,
    ) -> MappedAbandonedClaimOutcome {
        let root = match self.root() {
            Ok(root) => root,
            Err(_) => return MappedAbandonedClaimOutcome::RootTerminal,
        };
        let paired_root = match paired.page_map_root() {
            Ok(root) => root,
            Err(_) => return MappedAbandonedClaimOutcome::RootTerminal,
        };
        if root != paired_root {
            return MappedAbandonedClaimOutcome::PairMismatch;
        }

        let guard = match self.storage.page_lifecycle_lock.try_lock() {
            Some(guard) => guard,
            None => return MappedAbandonedClaimOutcome::Busy,
        };
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            return match guard.unlock() {
                Ok(()) => MappedAbandonedClaimOutcome::RootTerminal,
                Err(error) => {
                    // The closure did not run, but a visible Release followed by
                    // a failed wake means no later lifecycle may trust this root.
                    self.storage.state.store(POISONED, Ordering::Release);
                    MappedAbandonedClaimOutcome::RootTerminalLock(error)
                }
            };
        }

        let mut scope = MappedAbandonedClaimScope::new(self.storage, guard);
        let completion = operation(MappedAbandonedClaimAccess {
            page_map: self.storage.page_map_ref(),
            storage: self.storage,
            completed: false,
        });
        if matches!(&completion, MappedAbandonedClaimCompletion::Retained(_)) {
            // A retained range crossed the low-owner boundary. The token
            // itself already terminalizes the root, and repeating the store
            // here makes the outer transition independent of its constructor.
            self.storage.state.store(POISONED, Ordering::Release);
        }
        // The closure returned normally and its completion now owns any
        // claimed/retained page token. A later unlock failure stays visible in
        // the distinct outer outcome below.
        scope.complete();
        match scope.unlock() {
            Ok(()) => MappedAbandonedClaimOutcome::Completed(completion),
            Err(error) => {
                // The atomic Release occurred before this wake failure. The
                // completion remains the sole evidence of a possible range
                // transfer, but the root cannot return to normal admission.
                self.storage.state.store(POISONED, Ordering::Release);
                MappedAbandonedClaimOutcome::UnlockFailed { completion, error }
            }
        }
    }

    /// Looks up the page containing one exact live native allocation without
    /// acquiring the long ordinary-page mutation lease.
    ///
    /// This is the source `mi_free` lookup boundary for a remote producer,
    /// not a general concurrent PageMap read. A current allocation keeps its
    /// containing page registered: its owner cannot retire, unregister,
    /// reuse, or release that page while the allocation remains live. That
    /// lifetime fact excludes a plain read/write overlap for this exact arena
    /// slice, while independent source operations may still mutate unrelated
    /// slices. The returned raw page pointer carries no ordinary-page or
    /// PageMap mutation authority.
    ///
    /// # Safety
    ///
    /// `client` must be an exact current allocation of the native runtime.
    /// The caller must retain its allocation lifetime through every use of
    /// the returned pointer, and must use only source-permitted remote
    /// producer fields unless it separately owns the page's ordinary
    /// lifecycle. Passing an arbitrary C pointer is not a way to validate a
    /// PageMap entry: as with pinned `mi_free`, invalid-pointer behavior is
    /// outside this boundary's contract.
    pub(crate) unsafe fn lookup_page_for_live_client(
        self,
        client: NonNull<u8>,
    ) -> Result<Option<NonNull<Page>>, ProcessPageMapError> {
        self.ensure_ready()?;
        if self.storage.root.load().is_none() {
            return Err(ProcessPageMapError::Poisoned);
        }
        // SAFETY: the caller's exact-live-client proof excludes a register or
        // unregister write to this allocation's arena slice for the duration
        // of this source-plain lookup.
        let page = unsafe { self.storage.page_map_ref().checked_lookup(client.as_ptr()) };
        Ok(NonNull::new(page))
    }

    /// Looks up one exact live allocation and copies its source dispatch facts.
    ///
    /// This is the source-shaped shared front edge for general `free`,
    /// usable-size, and realloc: it performs the checked two-level PageMap
    /// lookup and captures canonical block geometry plus the one raw
    /// `xthread_id` snapshot. It deliberately does not compare that snapshot
    /// with a caller identity. The next free-path layer makes that source
    /// local/remote/abandoned dispatch decision.
    ///
    /// A normal lookup deliberately does not acquire `page_lifecycle_lock` or
    /// invent a Rust generation sidecar. Pinned `free.c` makes the live source
    /// block itself the lifetime proof: until the consuming operation frees
    /// that block locally or completes atomic remote publication, the page
    /// cannot become all-free, unregister its PageMap entry, retire/reuse its
    /// metadata, or release its mapping. The lookup is therefore constant-time
    /// in PageMap geometry and independent of owner, route, and client counts.
    ///
    /// # Safety
    ///
    /// `client` must be an exact current allocation of the native runtime.
    /// The caller must retain that allocation lifetime through the complete
    /// consuming source operation. That proof keeps the containing page
    /// registered, initialized, mapped, and unreused, and excludes an
    /// overlapping plain PageMap entry mutation for the exact client slice.
    /// The returned value must not be retained after local free, completed
    /// remote publication/collection, realloc release, or any other operation
    /// that ends the client's lifetime. The sole internal exception is a
    /// winning `allow_collect=true` publication, which moves this exact
    /// observation into its linear source-tail claim until that tail has
    /// completed. This boundary does not validate arbitrary C pointers and
    /// grants no ordinary page, PageMap mutation, or final-release authority.
    pub(crate) unsafe fn lookup_live_allocation(
        self,
        client: NonNull<u8>,
    ) -> Result<Option<LiveAllocationPointer>, ProcessPageMapError> {
        self.ensure_ready()?;
        if self.storage.root.load().is_none() {
            return Err(ProcessPageMapError::Poisoned);
        }
        // SAFETY: the exact-live-client caller proof excludes an overlapping
        // source-plain register/unregister write for this arena slice.
        let page = unsafe { self.storage.page_map_ref().checked_lookup(client.as_ptr()) };
        let Some(page) = NonNull::new(page) else {
            return Ok(None);
        };
        // SAFETY: the same live source block keeps the selected PageMap entry
        // and metadata stable while immutable geometry plus the source atomic
        // ownership word are copied without forming `&Page`.
        Ok(unsafe { classify_live_allocation_in_page(page, client) })
    }

    /// Starts the one explicit mutable PageMap lifecycle for this process
    /// root.
    ///
    /// The returned capability owns the Rust aliasing/quiescence boundary for
    /// the source map's plain entries. It is intentionally nonblocking: a
    /// second page-bearing owner, including accidental same-thread reentry,
    /// is an unsupported lifecycle conflict rather than a new recursive map
    /// protocol. A caller that drops this capability before finishing its page
    /// engine poisons the bounded process owner so no later route can mistake
    /// retained entries for an empty map.
    pub(crate) fn begin_page_lifecycle(
        self,
    ) -> Result<ProcessPageMapMutationLease, ProcessPageMapError> {
        self.ensure_ready()?;
        let guard = self
            .storage
            .page_lifecycle_lock
            .try_lock()
            .ok_or(ProcessPageMapError::LifecycleBusy)?;
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                self.storage.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Lock(error));
            }
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(ProcessPageMapMutationLease {
            storage: self.storage,
            guard: Some(guard),
        })
    }

    /// Blocks for one short, exact W03 post-owner-exit PageMap mutation.
    ///
    /// This is deliberately separate from [`Self::begin_page_lifecycle`].
    /// Normal page-engine admission remains nonblocking so a second owner is
    /// rejected as [`ProcessPageMapError::LifecycleBusy`] instead of becoming
    /// an implicit recursive or scheduled lifecycle. Only W03's terminal
    /// callbacks may wait here after W07 has claimed the exact abandoned page
    /// and immediately before that source tail mutates its PageMap range.
    ///
    /// # Safety
    ///
    /// The caller must hold W07's unique low-bit claim for one exact
    /// post-owner-exit terminal source continuation. It must use the returned
    /// mutation lease only for that page's bounded map/list/metadata/backing
    /// release, then call
    /// [`ProcessPageMapMutationLease::finish_after_exact_post_owner_exit_operation`]
    /// or retain the lease with that exact terminal owner after partial
    /// progress. It must not use this blocking boundary for normal lifecycle
    /// admission, a lookup, a route/registry, or a new scheduler policy.
    pub(crate) unsafe fn begin_blocking_exact_post_owner_exit_mutation(
        self,
    ) -> Result<ProcessPageMapMutationLease, ProcessPageMapError> {
        self.ensure_ready()?;
        let guard = self
            .storage
            .page_lifecycle_lock
            .lock()
            .map_err(ProcessPageMapError::Lock)?;
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                self.storage.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Lock(error));
            }
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(ProcessPageMapMutationLease {
            storage: self.storage,
            guard: Some(guard),
        })
    }

    /// Borrows the process-stable PageMap for source structural operations on
    /// ranges whose complete lifetime the caller owns.
    ///
    /// This replaces no PageMap synchronization with an implicit global
    /// lease. The source map's lazy submap publication retains its own lock;
    /// once a submap exists, individual entries are deliberately plain. Two
    /// owners may mutate disjoint ranges independently, while each owner must
    /// serialize every lookup/register/unregister touching its own entries.
    ///
    /// # Safety
    ///
    /// For every operation through the returned map, the caller must own the
    /// exact affected ranges and page lifetimes, prevent overlapping plain
    /// entry read/write or write/write access, keep registered page metadata
    /// mapped and initialized until lookup users are quiescent and the range
    /// is unregistered, and unregister before releasing or reusing metadata.
    /// This borrow grants no global PageMap mutation, page ownership,
    /// cross-range exclusion, or terminal-release authority.
    pub(crate) unsafe fn page_map_for_owned_ranges(
        self,
    ) -> Result<&'static PageMap, ProcessPageMapError> {
        self.ensure_ready()?;
        if self.storage.root.load().is_none() {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.page_map_ref())
    }

    /// Borrows the process-lived page map for isolated crate tests.
    ///
    /// This does not give ownership of any entry or page.  All `PageMap`
    /// caller obligations remain in force, including synchronization of plain
    /// overlapping entry accesses and retaining a registered page until its
    /// matching unregister operation.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    pub(crate) fn page_map(self) -> Result<&'static PageMap, ProcessPageMapError> {
        self.ensure_ready()?;
        if self.storage.root.load().is_none() {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.page_map_ref())
    }

    /// Returns the final map only for an isolated terminal-owner regression.
    ///
    /// Unlike [`Self::page_map`], this may inspect a Release-published map
    /// after an unfinished page lifecycle poisoned the outer owner. It never
    /// makes that map reusable: test callers must retain the same exclusive
    /// fixture and use it only to prove that the terminal path did not erase
    /// a still-live registration.
    #[cfg(test)]
    pub(crate) fn test_retained_page_map(self) -> Option<&'static PageMap> {
        match self.storage.state.load(Ordering::Acquire) {
            READY | POISONED if self.storage.root.load().is_some() => {
                Some(self.storage.page_map_ref())
            }
            _ => None,
        }
    }

    /// Returns the exact process-main identity which owns this global map.
    #[inline]
    pub(crate) fn subprocess(self) -> Result<&'static MainSubprocess, ProcessPageMapError> {
        self.ensure_ready()?;
        let pointer = self.storage.subprocess.load(Ordering::Acquire);
        NonNull::new(pointer)
            .map(|pointer| {
                // SAFETY: READY publication stores exactly the process-static
                // subprocess supplied to initialization; it has process
                // lifetime and is never replaced by this owner.
                unsafe { pointer.as_ref() }
            })
            .ok_or(ProcessPageMapError::Poisoned)
    }

    #[inline]
    fn ensure_ready(self) -> Result<(), ProcessPageMapError> {
        if self.storage.state.load(Ordering::Acquire) == READY {
            Ok(())
        } else {
            Err(ProcessPageMapError::Poisoned)
        }
    }
}

/// One exclusive, process-root PageMap mutation lifetime.
///
/// The capability deliberately exposes only the shared `PageMap` view needed
/// by the existing source page engine. Its held private lock is the proof that
/// engine-internal unsafe registration, lookup, and unregistration have no
/// competing plain-entry access. A scoped remote producer may outlive an
/// individual engine call, but the owning engine retains this capability until
/// that producer joins and the complete lifecycle finishes.
#[must_use = "a process PageMap mutation lease must finish or retain its owner explicitly"]
pub(crate) struct ProcessPageMapMutationLease {
    storage: &'static ProcessPageMapStorage,
    guard: Option<PrivateLockGuard<'static>>,
}

impl ProcessPageMapMutationLease {
    /// Borrows the final process-static map while this exclusive lifecycle is
    /// held. It is not a general PageMap escape hatch: the only current
    /// consumer is the typed page owner that also retains this lease.
    #[inline]
    pub(crate) fn page_map(&self) -> Result<&'static PageMap, ProcessPageMapError> {
        if self.guard.is_none() || self.storage.state.load(Ordering::Acquire) != READY {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.page_map_ref())
    }

    /// Releases the lifecycle boundary after a completely quiesced page
    /// engine has cleared every map entry and source page owner.
    pub(crate) fn finish(mut self) -> Result<(), ProcessPageMapError> {
        let guard = self.guard.take().ok_or(ProcessPageMapError::Poisoned)?;
        match guard.unlock() {
            Ok(()) => Ok(()),
            Err(error) => {
                // The atomic release already occurred. A later wake failure
                // cannot make this map safely reusable as if the bounded
                // lifecycle had remained private.
                self.storage.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
        }
    }

    /// Releases one short, exact post-owner-exit PageMap mutation boundary.
    ///
    /// Unlike [`Self::finish`], this does not claim that the whole process
    /// PageMap is empty. It is deliberately unsafe and narrowly intended for
    /// a source post-owner-exit continuation which has already proved all of
    /// the following: it held W07's unique page claim, serialized every plain
    /// PageMap operation on that exact page through this lease, and either
    /// removed that exact registration before releasing its metadata or left
    /// it untouched under another still-live source owner. Other entries must
    /// have disjoint source lifetime proofs; this operation is neither a
    /// general short map lock nor a route/access registry.
    ///
    /// An unlock failure follows the normal mutation-lease rule and poisons
    /// the root after the visible release, so the caller must retain a
    /// terminal process outcome rather than retrying it as a fresh lifecycle.
    pub(crate) unsafe fn finish_after_exact_post_owner_exit_operation(
        mut self,
    ) -> Result<(), ProcessPageMapError> {
        let guard = self.guard.take().ok_or(ProcessPageMapError::Poisoned)?;
        match guard.unlock() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.storage.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
        }
    }

    /// Transfers the long engine guard to one process-lived post-exit page
    /// route.
    ///
    /// This is intentionally unsafe even though it performs only a private
    /// lock release. The caller must already own a source-valid live-page
    /// continuation that retains every registered page selected by this owner
    /// exit: its metadata, arena backing, matching Heap arena-pages image,
    /// and final release authority. That continuation must use the returned
    /// access capability for every plain PageMap lookup, registration, and
    /// unregistration, and must call
    /// [`ProcessPageMapPostExitAccess::finish_after_all_pages_released`] only
    /// after all of those pages are gone. A higher-level bounded lifecycle
    /// may retain another independently detached route for disjoint pages;
    /// each access reacquires this root's same short exclusion per operation.
    /// Dropping either capability before its explicit completion poisons this
    /// process root rather than reopening it over a possibly live map entry.
    ///
    /// The transfer itself is the Rust ownership bridge required after
    /// upstream has detached and freed the old Theap/TLD: source PageMap
    /// entries remain plain, but their process-lifetime owner no longer keeps
    /// an arbitrary-length engine borrow or its former thread metadata alive.
    /// It is not a general PageMap escape hatch or a substitute for
    /// `xthread_free`, abandoned-bitmap, Heap, or arena synchronization.
    pub(crate) unsafe fn into_post_exit_access(
        mut self,
    ) -> Result<ProcessPageMapPostExitAccess, ProcessPageMapError> {
        let guard = self.guard.take().ok_or(ProcessPageMapError::Poisoned)?;
        if let Err(error) = self.storage.begin_post_exit_route() {
            let unlock = guard.unlock();
            if unlock.is_err() {
                self.storage.state.store(POISONED, Ordering::Release);
            }
            return Err(error);
        }
        match guard.unlock() {
            Ok(()) => Ok(ProcessPageMapPostExitAccess {
                storage: self.storage,
                completed: false,
                route_registered: true,
            }),
            Err(error) => {
                // The Release transition occurred before the wake failure.
                // The former engine cannot safely retain its long guard, and
                // a later route cannot treat the map as normal after an
                // unreported handoff wake failure.
                self.storage.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
        }
    }

    /// Transfers this long plain-PageMap guard to one suspended normal-engine
    /// state token.
    ///
    /// Unlike [`Self::into_post_exit_access`], this transition is for an
    /// attachment that remains live and may later reassemble its same normal
    /// page engine.  The caller must move every engine-owned fact—its arena,
    /// PageMap reference, collector state, pending OS release, and the
    /// attachment's suspended-session marker—into one typed token beside the
    /// returned access capability.  That token may re-acquire a long lease
    /// only through [`ProcessPageMapSuspendedEngineAccess::into_mutation_lease`].
    ///
    /// It is not an escape hatch for page-map lookup or a replacement for
    /// source page ownership.  The released guard merely lets another fully
    /// bounded engine operation serialize its own plain entries while this
    /// normal engine is between calls.  Dropping the returned access before
    /// reassembly or terminal retention poisons the process root.
    ///
    /// # Safety
    ///
    /// The caller must retain the sole matching live normal-engine state and
    /// attachment marker for the complete returned access lifetime.  No raw
    /// PageMap pointer or engine operation may survive this transfer.
    pub(crate) unsafe fn into_suspended_engine_access(
        mut self,
    ) -> Result<ProcessPageMapSuspendedEngineAccess, ProcessPageMapError> {
        let guard = self.guard.take().ok_or(ProcessPageMapError::Poisoned)?;
        match guard.unlock() {
            Ok(()) => Ok(ProcessPageMapSuspendedEngineAccess {
                storage: self.storage,
                resumed: false,
                _not_send_or_sync: PhantomData,
            }),
            Err(error) => {
                // The atomic Release happened before the failed wake. The
                // normal engine cannot safely claim it still owns a long
                // guard, and no later suspended token may treat the root as
                // healthy after that unreported handoff boundary.
                self.storage.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
        }
    }
}

impl Drop for ProcessPageMapMutationLease {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            // An unfinished owner can retain live map entries, arena bits, or
            // a page/producer relation. Do not unlock and silently let a
            // later caller treat the root as a fresh allocation route.
            self.storage.state.store(POISONED, Ordering::Release);
            drop(guard);
        }
    }
}

/// One process-root capability held while a live normal page engine is
/// suspended between operations.
///
/// This value exposes no PageMap reference or short lookup/free operation.
/// Its only successful transition reclaims the long
/// [`ProcessPageMapMutationLease`] needed to reassemble that same engine.
/// Keeping the capability separate from post-exit access prevents a normal
/// attachment from being finalized through a route meant for an already
/// detached Theap/TLD.
#[must_use = "a suspended normal-engine PageMap access must resume its engine or remain terminally retained"]
pub(crate) struct ProcessPageMapSuspendedEngineAccess {
    storage: &'static ProcessPageMapStorage,
    resumed: bool,
    // This capability is paired with one current-thread attachment's
    // separated normal-engine state. Unlike a post-exit route it must never
    // cross to another worker, even though it contains only a process-static
    // address at runtime.
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ProcessPageMapSuspendedEngineAccess {
    /// Reclaims the long source-plain PageMap exclusion for the exact normal
    /// engine state that created this suspended token.
    ///
    /// # Safety
    ///
    /// The caller must immediately couple the returned lease to that unique
    /// engine state and its matching current-thread attachment session.  It
    /// must not construct a fresh engine, retain a second suspended token, or
    /// leave a raw PageMap access alive.  A failed return preserves this token
    /// unchanged so the caller can retain the same terminal owner.
    pub(crate) unsafe fn into_mutation_lease(
        mut self,
    ) -> Result<ProcessPageMapMutationLease, (Self, ProcessPageMapError)> {
        if self.resumed
            || self.storage.state.load(Ordering::Acquire) != READY
            || self.storage.root.load().is_none()
        {
            return Err((self, ProcessPageMapError::Poisoned));
        }
        let guard = match self.storage.page_lifecycle_lock.try_lock() {
            Some(guard) => guard,
            None => return Err((self, ProcessPageMapError::LifecycleBusy)),
        };
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                // As with every other handoff, an atomic Release followed by
                // a failed wake is terminal rather than retryable.
                self.storage.state.store(POISONED, Ordering::Release);
                return Err((self, ProcessPageMapError::Lock(error)));
            }
            return Err((self, ProcessPageMapError::Poisoned));
        }
        // The returned long lease is the sole page-map owner for the resumed
        // engine. Mark this source token complete before it drops so its
        // conservative Drop cannot poison that valid transfer.
        self.resumed = true;
        Ok(ProcessPageMapMutationLease {
            storage: self.storage,
            guard: Some(guard),
        })
    }
}

impl Drop for ProcessPageMapSuspendedEngineAccess {
    fn drop(&mut self) {
        if !self.resumed {
            // A live normal attachment may still hold registered entries or a
            // pending OS-release token in its separated engine state. Do not
            // reopen the root as though a paused engine had become quiescent.
            self.storage.state.store(POISONED, Ordering::Release);
        }
    }
}

/// One process-lived route for page-map access after a thread owner detached.
///
/// Upstream abandoned pages keep their PageMap registration after their old
/// Theap and TLD have gone away. The route therefore cannot retain
/// [`ProcessPageMapMutationLease`]: that guard is deliberately an
/// engine-lifetime aliasing boundary. Instead, this capability reacquires the
/// same guard for each complete plain-entry operation. It carries no raw page
/// pointer, arena, Heap, or free-list right by itself; its one valid consumer
/// must retain those in a separate typed post-exit owner.
///
/// Separate typed post-exit routes may retain disjoint source-page sets at
/// once under a higher-level bounded router. They serialize every operation
/// through this one root's lock, and none may consume into a long mutation
/// lease while another short route survives. The explicit
/// `finish_after_all_pages_released` transition is deliberately unsafe
/// because the process map cannot inspect whether every page belonging to
/// this route has truly completed its final release. An unfinished drop is
/// terminal, matching the existing long-lifecycle lease policy.
#[must_use = "a post-exit PageMap access route must finish after every retained page is released"]
pub(crate) struct ProcessPageMapPostExitAccess {
    storage: &'static ProcessPageMapStorage,
    completed: bool,
    /// Set exactly when `ProcessPageMapMutationLease::into_post_exit_access`
    /// registered this continuation. It clears only after explicit terminal
    /// completion or a consuming sole-route long-lease handoff.
    route_registered: bool,
}

impl ProcessPageMapPostExitAccess {
    /// Reclaims the long source-plain PageMap exclusion boundary for one
    /// newly attached page engine.
    ///
    /// # Safety
    ///
    /// The caller must consume the only process-exit route that owns every
    /// still-registered page and immediately couple the returned lease to one
    /// typed engine that assumes every later plain PageMap lookup,
    /// registration, and unregistration responsibility. It must not leave a
    /// second short-access route, a concurrent post-exit client-free route,
    /// or an unowned registered page behind. Dropping the returned lease
    /// before that engine finishes remains terminal, just like a normal
    /// mutation lease.
    ///
    /// This is the inverse of
    /// [`ProcessPageMapMutationLease::into_post_exit_access`], but it is not
    /// a general route upgrade: only an explicit consuming handoff may turn
    /// the short post-exit access capability back into a long engine
    /// lifecycle.
    pub(crate) unsafe fn into_mutation_lease(
        mut self,
    ) -> Result<ProcessPageMapMutationLease, (Self, ProcessPageMapError)> {
        if self.completed
            || !self.route_registered
            || self.storage.state.load(Ordering::Acquire) != READY
            || self.storage.root.load().is_none()
        {
            return Err((self, ProcessPageMapError::Poisoned));
        }
        let guard = match self.storage.page_lifecycle_lock.try_lock() {
            Some(guard) => guard,
            None => return Err((self, ProcessPageMapError::LifecycleBusy)),
        };
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                // The lock became externally visible before its wake failed.
                // This route cannot retry as though it still owned a clean
                // short-access capability.
                self.storage.state.store(POISONED, Ordering::Release);
                return Err((self, ProcessPageMapError::Lock(error)));
            }
            return Err((self, ProcessPageMapError::Poisoned));
        }
        if self.storage.post_exit_route_count.load(Ordering::Acquire) != 1 {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                self.storage.state.store(POISONED, Ordering::Release);
                return Err((self, ProcessPageMapError::Lock(error)));
            }
            // This route remains intact and retryable after a sibling route
            // completes. Converting it now would split the one long engine
            // lifecycle from the sibling's short post-exit ownership.
            return Err((self, ProcessPageMapError::LifecycleBusy));
        }
        if let Err(error) = self.storage.finish_post_exit_route() {
            let unlock = guard.unlock();
            if let Err(unlock_error) = unlock {
                self.storage.state.store(POISONED, Ordering::Release);
                return Err((self, ProcessPageMapError::Lock(unlock_error)));
            }
            return Err((self, error));
        }
        // The returned long lease is now the sole owner responsible for the
        // post-exit entries. Mark this source capability complete before it
        // drops so its conservative Drop cannot poison that valid transfer.
        self.completed = true;
        self.route_registered = false;
        Ok(ProcessPageMapMutationLease {
            storage: self.storage,
            guard: Some(guard),
        })
    }

    /// Checks whether this post-exit route belongs to one stable
    /// process-page-map root.
    ///
    /// This is only an identity witness. It neither borrows the map nor
    /// grants entry access; callers still need the consuming transition above
    /// before they may form a normal page engine.
    #[inline]
    pub(crate) fn matches_root(
        &self,
        root: NonNull<PageMapHeader>,
    ) -> Result<bool, ProcessPageMapError> {
        if self.completed || !self.route_registered || self.storage.state.load(Ordering::Acquire) != READY {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.root.load() == Some(root))
    }

    /// Runs one complete operation while holding the source-plain PageMap
    /// entry exclusion boundary.
    ///
    /// A closure that obtains a page from a lookup must complete its atomic
    /// abandoned-free/release decision before it returns. It must not leak a
    /// raw page reference, pointer-based owner right, or a future plain map
    /// access beyond this closure. Stable page and arena lifetime remain the
    /// enclosing post-exit owner's separate responsibility.
    pub(crate) fn with_page_map<R>(
        &self,
        operation: impl for<'map> FnOnce(&'map PageMap) -> R,
    ) -> Result<R, ProcessPageMapError> {
        if self.completed
            || !self.route_registered
            || self.storage.state.load(Ordering::Acquire) != READY
            || self.storage.root.load().is_none()
        {
            return Err(ProcessPageMapError::Poisoned);
        }
        let guard = self
            .storage
            .page_lifecycle_lock
            .lock()
            .map_err(ProcessPageMapError::Lock)?;
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                self.storage.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Lock(error));
            }
            return Err(ProcessPageMapError::Poisoned);
        }

        let result = operation(self.storage.page_map_ref());
        match guard.unlock() {
            Ok(()) => Ok(result),
            Err(error) => {
                // The closure's source operation completed before this
                // post-Release wake failure. Its caller receives no result
                // that could be used to continue an apparently healthy route.
                self.storage.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
        }
    }

    /// Completes the process-page-map half of a post-exit route.
    ///
    /// # Safety
    ///
    /// Every page in this route's selected source continuation whose live
    /// registration depended on this capability must have completed its
    /// source terminal release: mapped identity/bitmap removal where
    /// applicable, PageMap unregister, ordinary arena-page clear, metadata
    /// retirement, and backing-slice/mapping release. No `with_page_map`
    /// operation or raw page/producer relation may remain. A distinct typed
    /// route may still own disjoint registered pages and its own short access.
    pub(crate) unsafe fn finish_after_all_pages_released(
        mut self,
    ) -> Result<(), ProcessPageMapError> {
        // Acquire/release the same exclusion boundary once more so a safe
        // caller cannot mark this route complete while one of its own prior
        // map closures still holds a plain entry access.
        self.with_page_map(|_| ())?;
        self.storage.finish_post_exit_route()?;
        self.completed = true;
        self.route_registered = false;
        Ok(())
    }
}

impl Drop for ProcessPageMapPostExitAccess {
    fn drop(&mut self) {
        if !self.completed || self.route_registered {
            // A detached Theap/TLD may already be gone while its pages stay
            // registered. Never allow another route to interpret that as a
            // clean PageMap lifecycle.
            self.storage.state.store(POISONED, Ordering::Release);
        }
    }
}

/// A process-global page-map initialization or publication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessPageMapError {
    Lock(Errno),
    /// A different bounded page lifecycle still owns the source-plain map
    /// entries. This is a non-mutating rejection rather than a recursive
    /// lock acquisition.
    LifecycleBusy,
    Initialization(Errno),
    /// Bootstrap failed and its private PageMap mapping could not be released.
    /// The process-static owner retains that exact mapping terminally.
    InitializationRetained { initialization: Errno, cleanup: Errno },
    ConfigurationMismatch,
    SubprocessMismatch,
    Poisoned,
}

static PROCESS_PAGE_MAP: ProcessPageMapStorage = ProcessPageMapStorage::new();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ARENA_SLICE_SIZE;
    use crate::os::{PageSize, fault};
    use crate::remote_free::{
        self, AbandonedOwnerHeadTransition, LiveRemoteFreePublish,
    };
    use crate::types::{
        Heap, LiveThreadId, MemoryId, Theap, ThreadLocalData, PAGE_FLAG_MASK,
        PAGE_HAS_INTERIOR_POINTERS, PAGE_IN_FULL_QUEUE, THREAD_ID_ABANDONED,
        THREAD_ID_ABANDONED_MAPPED, THREAD_ID_DETACHED,
    };
    use core::alloc::Layout;
    use core::mem::{align_of, size_of};
    use core::ptr::NonNull;
    use std::alloc::{alloc_zeroed, dealloc};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn store_source_xthread_id_for_pointer_test(page: NonNull<Page>, xthread_id: usize) {
        let geometry = page.as_ptr().cast::<PagePointerGeometry>();
        // SAFETY: the fixture owns its initialized page metadata exclusively
        // through PageMap unregistration. This names only the source atomic
        // identity field and never accesses the potentially stale `theap`.
        let field = unsafe { &*core::ptr::addr_of!((*geometry).xthread_id) };
        field.store(xthread_id, Ordering::Relaxed);
    }

    /// Runs one real PageMap-derived pointer fixture through a consuming
    /// source remote-free operation before unregistering its exact range.
    ///
    /// The closure receives no raw page/block constructor: it must obtain a
    /// [`LiveAllocationPointer`] through `lookup_live_allocation`, just as the
    /// production pointer dispatcher does.
    fn with_live_pointer_remote_fixture(
        operation: impl FnOnce(ProcessPageMapLease, NonNull<Page>, NonNull<u8>),
    ) {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage
            .initialize(memory_config(), subprocess)
            .expect("the fixture process map initializes");

        let thread_id = LiveThreadId::new(16).expect("the fixture owner is source-valid");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_bootstrap_exclusive(thread_id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));

        const BLOCK_SIZE: usize = 48;
        const RESERVED: u16 = 4;
        let metadata_size =
            (size_of::<Page>() + align_of::<usize>() - 1) & !(align_of::<usize>() - 1);
        let page_offset = ARENA_SLICE_SIZE + metadata_size;
        let layout = Layout::from_size_align(2 * ARENA_SLICE_SIZE, ARENA_SLICE_SIZE)
            .expect("the separated-metadata fixture layout is valid");
        // SAFETY: the matching exact-range unregistration and deallocation
        // happen after the consuming pointer operation returns.
        let base = NonNull::new(unsafe { alloc_zeroed(layout) })
            .expect("the focused pointer fixture allocates two arena slices");
        let page = base.cast::<Page>();
        // SAFETY: this fixture owns the metadata, complete block range, and
        // bound source owner through its one pointer operation.
        let mut page = unsafe {
            Page::publish_fresh_exclusive_at(
                page,
                &mut theap,
                &heap,
                thread_id,
                BLOCK_SIZE,
                page_offset,
                RESERVED,
                0,
                false,
                MemoryId::external(base.as_ptr(), 2 * ARENA_SLICE_SIZE, true, false, true),
            )
        }
        .expect("the live pointer fixture page is source-valid");
        // A fresh page begins with zero committed block capacity. Model the
        // source page-extension step before handing out its first client:
        // remote collection bounds its detached list by `capacity`, so a
        // still-counted client on a zero-capacity page is not a valid source
        // state and would correctly reject its one published block.
        // SAFETY: this fixture still exclusively owns every ordinary page
        // field before it exposes the current client to its PageMap lookup.
        assert!(unsafe { page.as_mut() }.set_capacity_reserved(RESERVED, RESERVED));
        // The fixture hands out exactly its first block, so its still-counted
        // `used` value supplies the source PageMap lifetime proof through the
        // later remote publication.
        unsafe { page.as_mut() }.set_exclusive_used(1);
        let block = NonNull::new(unsafe { base.as_ptr().add(page_offset) })
            .expect("the fixture canonical block is non-null");
        // SAFETY: this fixture owns the one registered block area and has no
        // concurrent PageMap writer or reader.
        let page_map = unsafe { lease.page_map_for_owned_ranges() }
            .expect("the process map serves the fixture range");
        unsafe {
            page_map
                .register_range(block.as_ptr(), usize::from(RESERVED) * BLOCK_SIZE, page)
                .expect("the fixture block range registers before lookup");
        }

        operation(lease, page, block);

        // SAFETY: the operation consumed or rejected its one pointer and has
        // discharged any source low-bit ownership before this exact clear.
        unsafe {
            page_map
                .unregister_range(block.as_ptr(), usize::from(RESERVED) * BLOCK_SIZE)
                .expect("the fixture registration clears before metadata release");
            core::ptr::drop_in_place(page.as_ptr());
            dealloc(base.as_ptr(), layout);
        }
    }

    #[test]
    fn live_reallocation_copy_source_keeps_an_interior_client_prefix_bounded() {
        with_live_pointer_remote_fixture(|lease, mut page, block| {
            const INTERIOR_ADJUSTMENT: usize = 5;
            const BLOCK_SIZE: usize = 48;
            const SHORT_REPLACEMENT_REQUEST: usize = 17;
            // SAFETY: this fixture owns the page exclusively through its
            // final source remote-free collection. The adjusted client below
            // models one aligned allocation within its canonical source block.
            unsafe { page.as_mut() }.set_has_interior_pointers(true);
            // SAFETY: this remains inside the exact current source block and
            // the fixture's still-counted allocation keeps its PageMap entry
            // and metadata live through the complete operation.
            let client = NonNull::new(unsafe { block.as_ptr().add(INTERIOR_ADJUSTMENT) })
                .expect("the interior client remains non-null");

            // SAFETY: `client` is the fixture's exact live adjusted client;
            // no PageMap writer overlaps this source observation.
            let source = unsafe { lease.lookup_live_allocation(client) }
                .expect("the fixture map remains ready")
                .expect("the live interior client resolves")
                .into_reallocation_copy_source(usize::MAX);

            // A replacement copies from the client pointer, never from the
            // preceding canonical block base. Its maximum copy is only the
            // prefix that starts at that exact adjusted client.
            assert_eq!(source.copy_client(), client);
            assert_eq!(source.canonical_block_for_release(), block);
            assert_eq!(source.usable_prefix_len(), BLOCK_SIZE - INTERIOR_ADJUSTMENT);
            assert_eq!(source.copy_prefix_len(), BLOCK_SIZE - INTERIOR_ADJUSTMENT);

            // A failed replacement leaves the old client live, so it returns
            // the non-Copy observation and a later operation may form one new
            // bounded source. That second request proves the token freezes
            // `min(request, usable-prefix)`, not merely the old usable extent.
            let source = source
                .into_live_allocation()
                .into_reallocation_copy_source(SHORT_REPLACEMENT_REQUEST);
            assert_eq!(source.copy_client(), client);
            assert_eq!(source.canonical_block_for_release(), block);
            assert_eq!(source.usable_prefix_len(), BLOCK_SIZE - INTERIOR_ADJUSTMENT);
            assert_eq!(source.copy_prefix_len(), SHORT_REPLACEMENT_REQUEST);

            // The non-Copy source token returns the original observation only
            // after the caller has finished the replacement copy phase. The
            // normal pointer-centered free path then consumes that observation
            // and its canonical block.
            let live = source.into_live_allocation();
            assert_eq!(live.client(), client);
            assert_eq!(live.canonical_block(), block);
            assert_eq!(
                unsafe { remote_free::push_live_allocation(live) },
                Ok(LiveRemoteFreePublish::PublishedToOwner),
            );
            let owner = unsafe { Page::remote_free_owner_state_at(page) }
                .expect("the fixture owner stays source-associated");
            assert_eq!(unsafe { remote_free::collect_live_page(owner) }, Ok(1));
        });
    }

    #[test]
    fn live_allocation_pointer_post_exit_publication_handles_stale_source_snapshots() {
        // A lookup that was live before owner exit must still use the exact
        // allow-collect CAS. If exit clears the head first, the source result
        // is the W07 claim—not a re-read or a former-owner route.
        with_live_pointer_remote_fixture(|lease, page, block| {
            let live = unsafe { lease.lookup_live_allocation(block) }
                .expect("the fixture map remains ready")
                .expect("the current fixture allocation resolves");
            assert_eq!(live.page_state(), LiveAllocationPageState::LiveOwnerAssociated);
            store_source_xthread_id_for_pointer_test(page, THREAD_ID_ABANDONED);
            // SAFETY: this fixture exclusively models the source exit's
            // identity/unown boundary before the stale pointer's CAS.
            // SAFETY: this fixture retains the initialized atomic remote-head
            // projection through the exact source unown model below.
            unsafe {
                Page::remote_free_producer_state_at(page)
                    .xthread_free
                    .as_ref()
                    .store(0, Ordering::Release);
            }

            let claim = match unsafe { remote_free::push_post_owner_exit_live_allocation(live) } {
                Ok(LiveRemoteFreePublish::ClaimedAbandonedPage(claim)) => claim,
                outcome => panic!("stale live lookup must retain its exact claim: {outcome:?}"),
            };
            assert_eq!(claim.page(), page);
            assert_eq!(claim.published_block(), block);
            // SAFETY: the exact claim owns the abandoned low bit. Finish the
            // test's source collection/unown before PageMap cleanup.
            assert_eq!(unsafe { remote_free::collect_abandoned(page) }, Ok(1));
            let producer = unsafe { Page::remote_free_producer_state_at(page) };
            let mut no_hook = None::<fn()>;
            assert_eq!(
                remote_free::try_unown_abandoned_head(
                    unsafe { producer.xthread_free.as_ref() },
                    &mut no_hook,
                ),
                AbandonedOwnerHeadTransition::Released,
            );
            drop(claim);
        });

        // A lookup already classified as mapped-abandoned may become live
        // again before its CAS. It must publish to that reclaimed owner rather
        // than reject the stale snapshot or construct a second claim.
        with_live_pointer_remote_fixture(|lease, page, block| {
            store_source_xthread_id_for_pointer_test(page, THREAD_ID_ABANDONED_MAPPED);
            let producer = unsafe { Page::remote_free_producer_state_at(page) };
            unsafe { producer.xthread_free.as_ref() }.store(0, Ordering::Release);
            let mapped = unsafe { lease.lookup_live_allocation(block) }
                .expect("the fixture map remains ready")
                .expect("the mapped-abandoned allocation resolves");
            assert_eq!(mapped.page_state(), LiveAllocationPageState::AbandonedMapped);

            // A different source claimant wins first and reclaims the page.
            assert_eq!(
                remote_free::claim_abandoned_owner(unsafe { producer.xthread_free.as_ref() }),
                remote_free::AbandonedOwnerClaim::ClaimedUnowned,
            );
            store_source_xthread_id_for_pointer_test(page, 16);
            assert_eq!(
                unsafe { remote_free::push_post_owner_exit_live_allocation(mapped) },
                Ok(LiveRemoteFreePublish::PublishedToOwner),
            );
            let owner = unsafe { Page::remote_free_owner_state_at(page) }
                .expect("the reclaim installed the live owner projection");
            assert_eq!(unsafe { remote_free::collect_live_page(owner) }, Ok(1));
        });

        // Detached source identity remains a hard dispatch boundary: it must
        // not publish through an exited owner or an abandoned-page tail.
        with_live_pointer_remote_fixture(|lease, page, block| {
            store_source_xthread_id_for_pointer_test(page, THREAD_ID_DETACHED);
            let detached = unsafe { lease.lookup_live_allocation(block) }
                .expect("the fixture map remains ready")
                .expect("the detached allocation remains lookup-visible");
            assert_eq!(detached.page_state(), LiveAllocationPageState::Detached);
            assert_eq!(
                unsafe { remote_free::push_post_owner_exit_live_allocation(detached) },
                Err(remote_free::RemoteFreeError::NotOwnerAssociated),
            );
            // SAFETY: detached rejection leaves this fixture's initialized
            // remote-head atomic untouched until its exact test teardown.
            assert_eq!(
                unsafe {
                    Page::remote_free_producer_state_at(page)
                        .xthread_free
                        .as_ref()
                        .load(Ordering::Acquire)
                },
                1,
            );
        });
    }

    #[test]
    fn live_pointer_lookup_copies_dispatch_facts_without_a_mutation_lease_or_adjacent_metadata() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let thread_id = LiveThreadId::new(16).expect("the fixture owner is source-valid");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_bootstrap_exclusive(thread_id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));

        const BLOCK_SIZE: usize = 48;
        const RESERVED: u16 = 4;
        let metadata_size =
            (size_of::<Page>() + align_of::<usize>() - 1) & !(align_of::<usize>() - 1);
        let page_offset = ARENA_SLICE_SIZE + metadata_size;
        let layout = Layout::from_size_align(2 * ARENA_SLICE_SIZE, ARENA_SLICE_SIZE)
            .expect("the separated-metadata fixture layout is valid");
        // SAFETY: `layout` has nonzero size and valid alignment. The matching
        // deallocation follows page-map unregistration below.
        let base = NonNull::new(unsafe { alloc_zeroed(layout) })
            .expect("the focused pointer fixture allocates two arena slices");
        let page = base.cast::<Page>();
        // SAFETY: the aligned fixture owns both arena slices. Page metadata is
        // in the first and the complete block area starts in the second, so
        // pointer classification can succeed only through the PageMap result;
        // it cannot align to an adjacent metadata sidecar. No PageMap entry
        // observes either region before publication.
        let mut page = unsafe {
            Page::publish_fresh_exclusive_at(
                page,
                &mut theap,
                &mut heap,
                thread_id,
                BLOCK_SIZE,
                page_offset,
                RESERVED,
                0,
                false,
                MemoryId::external(base.as_ptr(), 2 * ARENA_SLICE_SIZE, true, false, true),
            )
        }
        .expect("the fixture page geometry is source-valid");
        // SAFETY: the page's complete block area is inside the live fixture
        // allocation and starts at the source page offset.
        let block = NonNull::new(unsafe { base.as_ptr().add(page_offset + BLOCK_SIZE) })
            .expect("the fixture block address is non-null");
        // SAFETY: the interior client remains inside the second exact source
        // block and its lifetime pins the registered page for this test.
        let client = NonNull::new(unsafe { block.as_ptr().add(5) })
            .expect("the fixture interior client address is non-null");

        // SAFETY: this fixture exclusively owns the one registered range and
        // its separated page metadata until the matching unregister. No
        // overlapping entry reader or writer exists during either mutation.
        let page_map = unsafe { lease.page_map_for_owned_ranges() }
            .expect("the process-stable PageMap serves the owned range");
        // SAFETY: the fixture's exact-range ownership serializes this entry
        // write, and the page metadata stays valid until unregister below.
        unsafe {
            page_map
                .register_range(block.as_ptr(), usize::from(RESERVED) * BLOCK_SIZE, page)
                .expect("the live block area is registered before client publication");
        }

        // SAFETY: `block` is an exact current normal allocation from the
        // registered source page. No long mutation lease exists; the source
        // live block itself pins the PageMap entry and separated metadata.
        let normal = unsafe { lease.lookup_live_allocation(block) }
            .expect("the process root stays ready")
            .expect("the exact normal client resolves through the source page map");
        assert_eq!(normal.page(), page);
        assert_eq!(normal.client(), block);
        assert_eq!(normal.canonical_block(), block);
        assert_eq!(normal.xthread_id(), thread_id.get());
        assert_eq!(normal.page_flags(), 0);
        assert_eq!(normal.page_state(), LiveAllocationPageState::LiveOwnerAssociated);
        assert!(normal.is_associated_with(thread_id));
        assert!(!normal.is_associated_with(
            LiveThreadId::new(32).expect("the other source identity is valid")
        ));
        assert!(!normal.has_interior_pointers());
        assert_eq!(normal.block_size(), BLOCK_SIZE);
        assert_eq!(normal.usable_size(), BLOCK_SIZE);

        // SAFETY: the fixture owns the page exclusively until map
        // unregistration, so this source flag can be published before the
        // read-only interior-client operation below.
        unsafe { page.as_mut() }.set_has_interior_pointers(true);
        // SAFETY: `client` is an exact current interior allocation from this
        // registered page, and the same live-block invariant spans lookup.
        let pointer = unsafe { lease.lookup_live_allocation(client) }
            .expect("the process root stays ready")
            .expect("the exact live client resolves through the source page map");
        assert_eq!(pointer.page(), page);
        assert_eq!(pointer.client(), client);
        assert_eq!(pointer.canonical_block(), block);
        assert_eq!(
            pointer.xthread_id(),
            thread_id.get() | PAGE_HAS_INTERIOR_POINTERS
        );
        assert_eq!(pointer.page_flags(), PAGE_HAS_INTERIOR_POINTERS);
        assert_eq!(pointer.page_state(), LiveAllocationPageState::LiveOwnerAssociated);
        assert!(pointer.has_interior_pointers());
        assert_eq!(pointer.block_size(), BLOCK_SIZE);
        assert_eq!(pointer.usable_size(), BLOCK_SIZE - 5);

        store_source_xthread_id_for_pointer_test(page, THREAD_ID_ABANDONED | PAGE_IN_FULL_QUEUE);
        // SAFETY: `block` remains an exact live allocation. The source state
        // snapshot is deliberately abandoned but still PageMap-published.
        let abandoned = unsafe { lease.lookup_live_allocation(block) }
            .expect("the process root stays ready")
            .expect("the abandoned source page stays registered");
        assert_eq!(
            abandoned.xthread_id(),
            THREAD_ID_ABANDONED | PAGE_IN_FULL_QUEUE
        );
        assert_eq!(abandoned.page_flags(), PAGE_IN_FULL_QUEUE);
        assert_eq!(abandoned.page_state(), LiveAllocationPageState::Abandoned);
        assert!(!abandoned.is_associated_with(thread_id));

        store_source_xthread_id_for_pointer_test(
            page,
            THREAD_ID_ABANDONED_MAPPED | PAGE_HAS_INTERIOR_POINTERS,
        );
        // SAFETY: `client` remains a live interior allocation whose source
        // page map lifetime still pins the mapped-abandoned metadata.
        let abandoned_mapped = unsafe { lease.lookup_live_allocation(client) }
            .expect("the process root stays ready")
            .expect("the mapped-abandoned source page stays registered");
        assert_eq!(
            abandoned_mapped.xthread_id(),
            THREAD_ID_ABANDONED_MAPPED | PAGE_HAS_INTERIOR_POINTERS
        );
        assert_eq!(abandoned_mapped.page_flags(), PAGE_HAS_INTERIOR_POINTERS);
        assert_eq!(
            abandoned_mapped.page_state(),
            LiveAllocationPageState::AbandonedMapped
        );
        assert_eq!(abandoned_mapped.canonical_block(), block);

        store_source_xthread_id_for_pointer_test(
            page,
            THREAD_ID_DETACHED | PAGE_FLAG_MASK,
        );
        // SAFETY: `client` and the registered fixture page remain live. The
        // detached identity is only observed; this boundary makes no caller
        // ownership decision and does not access the page's `theap` field.
        let detached = unsafe { lease.lookup_live_allocation(client) }
            .expect("the process root stays ready")
            .expect("the detached source page stays registered");
        assert_eq!(detached.xthread_id(), THREAD_ID_DETACHED | PAGE_FLAG_MASK);
        assert_eq!(detached.page_flags(), PAGE_FLAG_MASK);
        assert_eq!(detached.page_state(), LiveAllocationPageState::Detached);
        assert_eq!(detached.canonical_block(), block);

        // SAFETY: every pointer observation is finished, no producer can use
        // this test-only page, and exact-range ownership serializes the clear.
        unsafe {
            page_map
                .unregister_range(block.as_ptr(), usize::from(RESERVED) * BLOCK_SIZE)
                .expect("the fixture registration clears before metadata release");
        }
        // SAFETY: the Page was initialized in the fixture allocation and no
        // PageMap lookup remains after unregistration; the layout exactly
        // matches the allocation above.
        unsafe {
            core::ptr::drop_in_place(page.as_ptr());
            dealloc(base.as_ptr(), layout);
        }
    }

    #[test]
    fn process_map_publishes_one_stable_root_for_its_selected_main_subprocess() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let first = storage
            .initialize(memory_config(), subprocess)
            .expect("the source page map initializes");
        let second = storage
            .initialize(memory_config(), subprocess)
            .expect("same frozen process inputs reuse the root");

        assert_eq!(first.root().unwrap(), second.root().unwrap());
        assert_eq!(first.subprocess().unwrap().as_ptr(), subprocess.as_ptr());
        assert_eq!(first.memory_config().unwrap(), memory_config());
    }

    #[test]
    fn process_map_rejects_changed_config_or_main_identity_without_replacing_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let first = storage.initialize(memory_config(), subprocess).unwrap();
        let root = first.root().unwrap();
        let different_config = MemoryConfig::from_observations(
            PageSize::new(4_096).expect("the selected native page size is valid"),
            1024 * 1024 + 1,
            false,
            false,
        );
        assert!(matches!(
            storage.initialize(different_config, subprocess),
            Err(ProcessPageMapError::ConfigurationMismatch)
        ));
        assert!(matches!(
            storage.initialize(memory_config(), MainSubprocess::test_static_owner()),
            Err(ProcessPageMapError::SubprocessMismatch)
        ));
        assert_eq!(first.root().unwrap(), root);
    }

    #[test]
    fn page_lifecycle_is_exclusive_and_an_unfinished_owner_poisoned_the_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let lifecycle = lease
            .begin_page_lifecycle()
            .expect("the ready process root admits its first page owner");
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::LifecycleBusy)
        ));
        lifecycle
            .finish()
            .expect("a quiesced page owner releases the process lifecycle");

        let unfinished = lease
            .begin_page_lifecycle()
            .expect("the completed lifecycle leaves the root reusable");
        drop(unfinished);
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::Poisoned)
        ));
        assert!(
            lease.test_retained_page_map().is_some(),
            "terminal poisoning retains the final map slot rather than exposing a new cold root"
        );
    }

    #[test]
    fn exact_post_owner_exit_mutation_waits_without_changing_normal_lifecycle_rejection() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();
        let held = lease
            .begin_page_lifecycle()
            .expect("the fixture's normal lifecycle holds the shared map boundary");
        let barrier = Arc::new(Barrier::new(2));
        let (completion_send, completion_receive) = mpsc::channel();
        let waiter_barrier = Arc::clone(&barrier);

        let waiter = thread::spawn(move || {
            waiter_barrier.wait();
            // SAFETY: this empty isolated fixture models one already-claimed
            // W03 final callback. It has no raw PageMap access or page state,
            // and it releases the returned short boundary before returning.
            let completion = unsafe { lease.begin_blocking_exact_post_owner_exit_mutation() }
                .and_then(|mutation| unsafe {
                    mutation.finish_after_exact_post_owner_exit_operation()
                });
            completion_send
                .send(completion)
                .expect("the fixture receives the W03 terminal completion");
        });

        barrier.wait();
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::LifecycleBusy)
        ), "ordinary lifecycle admission remains immediately nonblocking while W03 waits");
        assert!(
            completion_receive
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "the W03-only terminal acquisition waits instead of converting held-map contention into retention"
        );

        held
            .finish()
            .expect("releasing the normal lifecycle wakes the exact W03 terminal acquisition");
        match completion_receive.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(())) => {}
            completion => panic!("the waiting W03 terminal acquisition releases safely: {completion:?}"),
        }
        waiter
            .join()
            .expect("the W03 waiter completes after the normal lifecycle releases");
        lease
            .begin_page_lifecycle()
            .expect("the completed short W03 mutation leaves ordinary lifecycle semantics unchanged")
            .finish()
            .expect("the final normal lifecycle releases the reusable root");
    }

    #[test]
    fn suspended_normal_engine_releases_only_its_map_guard_between_operations() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let lifecycle = lease
            .begin_page_lifecycle()
            .expect("the first normal engine owns the source-plain entries");
        // SAFETY: this isolated regression retains no raw PageMap access or
        // page state; it proves only the long-guard-to-suspended-engine
        // transfer before a future persistent engine uses it with live state.
        let suspended = unsafe { lifecycle.into_suspended_engine_access() }
            .expect("the suspended engine releases its long map guard");
        let independent = lease
            .begin_page_lifecycle()
            .expect("another complete engine operation may serialize while the first is paused");
        independent
            .finish()
            .expect("the independent empty operation releases the map guard");

        // SAFETY: `suspended` is still the unique token from the original
        // long lease and the isolated fixture has no competing source state.
        let resumed = match unsafe { suspended.into_mutation_lease() } {
            Ok(lifecycle) => lifecycle,
            Err((suspended, error)) => {
                core::mem::forget(suspended);
                panic!("the same suspended engine reclaims its long map guard: {error:?}");
            }
        };
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::LifecycleBusy)
        ));
        // SAFETY: this repeats the exact no-page transfer solely to verify
        // that an unfinished suspended engine remains a terminal root owner.
        let suspended = unsafe { resumed.into_suspended_engine_access() }
            .expect("the resumed engine can pause again after its operation");
        drop(suspended);
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::Poisoned)
        ));
    }

    #[test]
    fn independently_suspended_normal_engines_resume_in_either_serial_order() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let first = lease
            .begin_page_lifecycle()
            .expect("the first normal engine owns the plain map entries");
        // SAFETY: this isolated regression holds the exact first suspended
        // token and no page state. It exercises only the PageMap long-guard
        // split used by the runtime's independently parked engine scheduler.
        let first = unsafe { first.into_suspended_engine_access() }
            .expect("the first suspended engine releases its long map guard");

        let second = lease
            .begin_page_lifecycle()
            .expect("the second normal engine may begin after the first parks");
        // SAFETY: `second` is a distinct complete lifecycle that retains its
        // own sole suspended token before another operation can begin.
        let second = unsafe { second.into_suspended_engine_access() }
            .expect("the second suspended engine releases its long map guard");

        let second = match unsafe { second.into_mutation_lease() } {
            Ok(lifecycle) => lifecycle,
            Err((suspended, error)) => {
                core::mem::forget(suspended);
                panic!("the second suspended token reacquires the serialized lease: {error:?}");
            }
        };
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::LifecycleBusy)
        ));
        second
            .finish()
            .expect("the second empty engine releases only its own mutation lease");

        let first = match unsafe { first.into_mutation_lease() } {
            Ok(lifecycle) => lifecycle,
            Err((suspended, error)) => {
                core::mem::forget(suspended);
                panic!("the first suspended token reacquires the serialized lease after the second: {error:?}");
            }
        };
        first
            .finish()
            .expect("the first empty engine releases the final serialized mutation lease");
        lease
            .begin_page_lifecycle()
            .expect("both independently suspended engines leave the root reusable")
            .finish()
            .expect("the final empty lifecycle releases normally");
    }

    #[test]
    fn post_exit_access_releases_the_engine_guard_but_requires_explicit_page_completion() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let lifecycle = lease
            .begin_page_lifecycle()
            .expect("the exiting engine initially owns every plain map entry");
        // SAFETY: this regression models the later owner-exit handoff. No
        // page exists in this isolated fixture, so the explicit completion
        // below proves the transfer does not reopen a retained route.
        let access = unsafe { lifecycle.into_post_exit_access() }
            .expect("the map guard transfers to the process-lived route");

        assert_eq!(
            access
                .with_page_map(|page_map| page_map.memory_config())
                .expect("the short access guard observes the final map"),
            memory_config()
        );
        let next = lease
            .begin_page_lifecycle()
            .expect("the transfer releases the long engine guard between accesses");
        next.finish()
            .expect("the independent empty engine returns the shared guard");

        // SAFETY: the fixture has no registered page or in-flight access.
        unsafe { access.finish_after_all_pages_released() }
            .expect("explicit all-page completion keeps the process root ready");
        lease
            .begin_page_lifecycle()
            .expect("a completed post-exit route leaves the map reusable")
            .finish()
            .expect("the final empty lifecycle releases normally");
    }

    #[test]
    fn post_exit_access_can_transfer_to_one_new_long_page_lifecycle() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();
        let lifecycle = lease
            .begin_page_lifecycle()
            .expect("the exiting engine initially owns every plain map entry");
        // SAFETY: this isolated fixture models the consuming route handoff;
        // no registered page exists, so the follow-on long lifecycle owns the
        // complete empty map boundary.
        let access = unsafe { lifecycle.into_post_exit_access() }
            .expect("the old engine transfers into its process-lived route");
        let reclaimed = match unsafe { access.into_mutation_lease() } {
            Ok(lifecycle) => lifecycle,
            Err((_access, error)) => {
                panic!("the explicit route reclaims its one long lifecycle: {error:?}")
            }
        };
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::LifecycleBusy)
        ));
        assert_eq!(
            reclaimed
                .page_map()
                .expect("the reclaimed lifecycle retains the final map")
                .memory_config(),
            memory_config()
        );
        reclaimed
            .finish()
            .expect("the empty adopted engine releases the long lifecycle");
        lease
            .begin_page_lifecycle()
            .expect("the completed adopted lifecycle leaves the map reusable")
            .finish()
            .expect("the final empty lifecycle releases normally");
    }

    #[test]
    fn independent_post_exit_routes_share_short_access_but_block_long_adoption() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let first = lease
            .begin_page_lifecycle()
            .expect("the first owner begins its source lifecycle");
        // SAFETY: this isolated regression models the first detached owner
        // with no raw page retained outside its typed short route.
        let first = unsafe { first.into_post_exit_access() }
            .expect("the first owner transfers to short post-exit access");
        let second = lease
            .begin_page_lifecycle()
            .expect("the released long guard admits an independent second owner");
        // SAFETY: as above, this models a distinct source owner-exit route.
        let second = unsafe { second.into_post_exit_access() }
            .expect("the second owner also transfers to short post-exit access");
        assert_eq!(
            storage.test_post_exit_route_count(),
            2,
            "each detached route remains individually represented before either completes"
        );

        let first = match unsafe { first.into_mutation_lease() } {
            Ok(lifecycle) => {
                drop(lifecycle);
                panic!("a route cannot consume to a long engine while its sibling survives")
            }
            Err((route, ProcessPageMapError::LifecycleBusy)) => route,
            Err((route, error)) => {
                core::mem::forget(route);
                panic!("the sibling route remains a normal bounded blocker: {error:?}")
            }
        };
        assert_eq!(
            storage.test_post_exit_route_count(),
            2,
            "the rejected long adoption preserves both independently detached routes"
        );

        // SAFETY: the isolated first route has no registered pages and has
        // completed every short access before its explicit completion.
        unsafe { first.finish_after_all_pages_released() }
            .expect("the first detached route releases only its own count");
        assert_eq!(
            storage.test_post_exit_route_count(),
            1,
            "the second short route remains represented after its sibling completes"
        );

        let reclaimed = match unsafe { second.into_mutation_lease() } {
            Ok(lifecycle) => lifecycle,
            Err((_route, error)) => {
                panic!("the remaining sole route can consume to a long engine: {error:?}")
            }
        };
        assert_eq!(
            storage.test_post_exit_route_count(),
            0,
            "the consuming sole-route handoff removes its short-route count"
        );
        reclaimed
            .finish()
            .expect("the empty adopted engine releases the final long lifecycle");
        lease
            .begin_page_lifecycle()
            .expect("both completed routes leave the shared root reusable")
            .finish()
            .expect("the final empty lifecycle releases normally");
    }

    #[test]
    fn dropping_unfinished_post_exit_access_poisoned_the_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();
        let lifecycle = lease.begin_page_lifecycle().unwrap();
        // SAFETY: this test intentionally abandons the returned process page
        // route to prove the conservative terminal-drop policy.
        let access = unsafe { lifecycle.into_post_exit_access() }.unwrap();
        drop(access);

        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::Poisoned)
        ));
        assert!(lease.test_retained_page_map().is_some());
    }

    #[test]
    fn concurrent_process_map_initializers_share_the_one_release_published_root() {
        const THREADS: usize = 4;

        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        // A second source-map reservation would fail.  Every worker must
        // instead observe the first initializer's release-published final
        // slot, proving the process owner does not leak a competing map.
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 2, Errno::NOMEM));
        let ready = Arc::new(Barrier::new(THREADS));
        let mut workers = std::vec::Vec::new();
        for _ in 0..THREADS {
            let ready = Arc::clone(&ready);
            workers.push(thread::spawn(move || {
                ready.wait();
                storage
                    .initialize(memory_config(), subprocess)
                    .expect("the serialized once path succeeds")
                    .root()
                    .unwrap()
                    .as_ptr()
                    .addr()
            }));
        }

        let first = workers.remove(0).join().unwrap();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), first);
        }
        fault.set(fault::Plan::disabled());
    }

    #[test]
    fn unpublished_mapping_failure_consumes_the_once_owner_without_publishing_a_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Initialization(Errno::NOMEM))
        ));
        assert_eq!(storage.state.load(Ordering::Acquire), POISONED);
        assert!(storage.root.load().is_none());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        ));
    }

    /// Emits the Rust half of the failed-first PageMap initialization record.
    ///
    /// Pinned C retains its `mi_page_map_empty` sentinel after the once body
    /// fails and lets a later call report success without replaying that body.
    /// This typed owner intentionally does not expose a sentinel as a live
    /// [`PageMap`]: the failed map allocation leaves no owned map, no root is
    /// published, and every later initialization request is terminally
    /// rejected. The trace proves the shared single-attempt/no-dynamic-root
    /// facts while making the differing cold-lookup-route policy explicit.
    #[test]
    fn emit_m2_page_map_cold_init_failure_rust_trace() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));

        let first_init_failed = matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Initialization(Errno::NOMEM))
        );
        let root_absent_after_first = storage.root.load().is_none();
        let first_attempt_count = fault.observed();
        let second_call_returns_poisoned = matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        );
        let init_body_attempt_count = fault.observed();
        let absent_root = storage.root.load().is_none();
        let dynamic_root_unpublished = root_absent_after_first && absent_root;
        // There is deliberately no lookup operation to invoke while cold: a
        // poisoned owner with no published root cannot yield a valid lease.
        let cold_lookup_route_unavailable =
            storage.state.load(Ordering::Acquire) == POISONED && absent_root;

        assert!(first_init_failed);
        assert!(dynamic_root_unpublished);
        assert_eq!(first_attempt_count, 1);
        assert_eq!(init_body_attempt_count, 1);
        assert!(second_call_returns_poisoned);
        assert!(cold_lookup_route_unavailable);

        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }
        std::println!("CRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_BEGIN");
        emit!("m2.page_map.cold.first_init_failed", first_init_failed);
        emit!(
            "m2.page_map.cold.dynamic_root_unpublished",
            dynamic_root_unpublished
        );
        emit!(
            "m2.page_map.cold.init_body_attempt_count",
            init_body_attempt_count
        );
        emit!("m2.page_map.cold.static_empty_root", false);
        emit!("m2.page_map.cold.absent_root", absent_root);
        emit!("m2.page_map.cold.second_call_returns_success", false);
        emit!(
            "m2.page_map.cold.second_call_returns_poisoned",
            second_call_returns_poisoned
        );
        // The C-only null-lookup observation has no Rust operation to run;
        // the paired route field records that it is unavailable by state.
        emit!("m2.page_map.cold.null_lookup_returns_null", false);
        emit!(
            "m2.page_map.cold.cold_lookup_route_unavailable",
            cold_lookup_route_unavailable
        );
        std::println!("CRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_END");
    }

    #[test]
    fn unpublished_top_level_commit_failure_consumes_the_once_owner_without_a_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        // With this non-overcommit fixture, `PageMap::initialize` first
        // commits the minimum top-level header before it can write a root.
        let fault = fault::install(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Initialization(Errno::NOMEM))
        ));
        assert_eq!(storage.state.load(Ordering::Acquire), POISONED);
        assert!(storage.root.load().is_none());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        ));
    }

    #[test]
    fn paired_initial_commit_and_cleanup_unmap_failure_retains_the_exact_mapping() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit,
            1,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));

        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::InitializationRetained {
                initialization: Errno::NOMEM,
                cleanup: Errno::NOMEM,
            })
        ));
        assert!(storage.test_has_retained_initialization_mapping());
        assert!(!storage.test_has_published_root());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        ));
        storage
            .test_release_retained_initialization_mapping()
            .expect("the retained exact mapping releases after the injected fault is removed");
        assert!(!storage.test_has_retained_initialization_mapping());
    }

    #[test]
    fn paired_initial_trailing_submap_commit_and_cleanup_unmap_failure_retains_the_exact_mapping() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit,
            2,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));

        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::InitializationRetained {
                initialization: Errno::NOMEM,
                cleanup: Errno::NOMEM,
            })
        ));
        assert!(storage.test_has_retained_initialization_mapping());
        assert!(!storage.test_has_published_root());

        fault.set(fault::Plan::disabled());
        storage
            .test_release_retained_initialization_mapping()
            .expect("the retained trailing-submap mapping releases after the injected fault is removed");
        assert!(!storage.test_has_retained_initialization_mapping());
    }

    #[test]
    fn unpublished_trailing_submap_commit_failure_consumes_the_once_owner_without_a_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        // The second commit makes the trailing source submap available. It
        // must fail before header/root publication just like the first one.
        let fault = fault::install(fault::Plan::at(fault::Point::Commit, 2, Errno::NOMEM));
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Initialization(Errno::NOMEM))
        ));
        assert_eq!(storage.state.load(Ordering::Acquire), POISONED);
        assert!(storage.root.load().is_none());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        ));
    }
}
