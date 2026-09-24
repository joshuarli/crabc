// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/subproc.c:12-70,84-101`
// (`mi_process_subproc_main`, `_mi_meta_zalloc`, `_mi_meta_zalloc_aligned`,
// `_mi_meta_rezalloc`, and `_mi_meta_is_meta_page`), `include/mimalloc/types.h:651-680`
// (the bounded `mi_subproc_t` fields), `include/mimalloc/types.h:690-701`
// (`mi_tld_t`), and `src/init.c:155-157,184-208,216-229,236-282`
// (`mi_process_tld_main`, the main-Heap `memid` / Release identity /
// `_mi_heap_init` order, the detached metadata-Theap publication,
// `_mi_subproc_heap_main`, `mi_tld_create`, and `mi_tld_free`).

//! Bounded main-subprocess thread-registration ownership.
//!
//! Upstream places a complete `mi_subproc_t` in static storage. This module
//! intentionally represents only the process-main identity, the detached
//! metadata-Theap identity needed before `_mi_meta_zalloc`, the source-owned
//! direct-allocation lock beside that identity, its selected lock-free
//! metadata-page equality query, and the two counters directly required by
//! `mi_tld_create`/`mi_tld_free`: the relaxed total-thread sequence and the
//! relaxed current-thread count. It is not a Rust layout claim for
//! `mi_subproc_t`: `theap_meta` and `theap_meta_lock` are one-way
//! identity/private-futex capabilities, not C byte-layout or normal C backing
//! routes. Its `registry` child module owns source main-subprocess list
//! publication and terminal unlink; non-main creation and a public subprocess
//! API remain absent. It owns one source-shaped process arena-backing registry,
//! one complete private `mi_stats_t` image, and the bitmap statistics that its
//! staged source paths actually mutate.
//! Its main-Heap slot retains only the canonical
//! static identity publication from `mi_subproc_t::heap_main`; it is never a
//! Rust heap accessor.
//!
//! A [`ThreadRegistrationTicket`] is the old result of the source relaxed
//! `thread_total_count` increment. Tickets are consumed even when a later
//! metadata allocation fails. Only a ticket that successfully forms a TLD can
//! become a [`ThreadRegistrationLease`], which owns exactly one corresponding
//! `thread_count` increment and decrement. The first ticket owns the real
//! process-static main-TLD storage; all later tickets must use metadata.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::{MaybeUninit, size_of};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use crabc_core::Result as CoreResult;

use crate::lock::{PrivateLock, PrivateLockGuard};
use crate::types::{Heap, LiveThreadId, MemoryId, Page, Theap, ThreadLocalData, ThreadSequence};
#[cfg(test)]
use crate::types::{NormalTldInitWriteTrace, StaticFirstTldCreateTrace};

const MAIN_TLD_COLD: u8 = 0;
const MAIN_TLD_CLAIMED: u8 = 1;
const MAIN_TLD_LIVE: u8 = 2;
const MAIN_TLD_RETIRED: u8 = 3;

// The source relaxed `thread_total_count` is deliberately kept separate from
// this Rust-only first-ticket selector.  Source process initialization owns
// the startup ordering; without a selector, a generic Rust TLD constructor
// could race the selected ticket-zero static-main path and consume its
// immutable source storage before the process PageMap exists.
const BOOTSTRAP_OPEN: u8 = 0;
const BOOTSTRAP_STATIC_SELECTING: u8 = 1;
const BOOTSTRAP_STATIC_TICKET_ISSUED: u8 = 2;
const BOOTSTRAP_STATIC_READY: u8 = 3;
const BOOTSTRAP_GENERIC_READY: u8 = 4;
const BOOTSTRAP_RETAINED: u8 = 5;

// `src/init.c:196` assigns the kind-only static memory ID, line 197
// Release-stores `mi_process_heap_main` in `subproc->heap_main`, and line 198
// runs `_mi_heap_init`. The C once envelope keeps callers from treating that
// early pointer as generally usable. Rust first reserves an unpublished
// `RESERVED` state that privately binds the candidate but leaves the
// subprocess atomic null, so a rejected stale owner cannot mutate a candidate
// Heap image; it Release-stores the identity and then makes it `PUBLISHING`
// only after the line-196 memid transition. A finished foundation alone makes
// that identity ready for comparison.
const MAIN_HEAP_ABSENT: u8 = 0;
const MAIN_HEAP_RESERVED: u8 = 1;
const MAIN_HEAP_PUBLISHING: u8 = 2;
const MAIN_HEAP_READY: u8 = 3;

/// Cache-aligned backing for source-static `mi_process_tld_main`.
///
/// `mi_decl_cache_align` gives this source object the normal 64-byte cache
/// alignment. The inner image remains `MaybeUninit` until the unique
/// ticket-zero transition writes every TLD field.
#[repr(align(64))]
struct MainStaticTldSlot {
    image: MaybeUninit<ThreadLocalData>,
}

impl MainStaticTldSlot {
    const fn new() -> Self {
        Self {
            image: MaybeUninit::uninit(),
        }
    }
}

/// Shared address-stable identity embedded in either the process-main owner
/// or one parent-allocated child image. Intrusive Heap/TLD/Theap links point
/// at this field, never at either surrounding role-specific image; the
/// `repr(transparent)` child wrapper preserves the identity at allocation
/// base for the exact source `mi_memid_t` membership check.
pub(crate) struct SubprocessIdentity {
    role: SubprocessRole,
    source_membership: registry::SourceSubprocessMembership,
    /// This identity's source `arenas` array, reserve lock, and exact OS
    /// backing slots. The `ProcessArenaBacking` Rust name describes the
    /// existing process path; it is a per-subprocess owner, not shared state
    /// or a complete `mi_subproc_t` layout projection.
    arena_backing: crate::arena::ProcessArenaBacking,
    /// The complete source-ordered statistics image shares the subprocess
    /// lifetime with VM, arena, and Heap producers. This is private state,
    /// not a public `mi_stats_t` layout, reporting API, or generic sink.
    statistics: crate::statistics::SubprocessStatistics,
    heap_list: crate::types::heap_registry::SubprocessHeapList,
    thread_count: AtomicUsize,
    thread_total_count: AtomicUsize,
    /// The one source `subproc->heap_main` identity selected for this
    /// subprocess (the process-static image for main, parent-owned for child).
    ///
    /// The pointer is never projected as `&Heap` or `&mut Heap`.  It exists
    /// solely so the source-static foundation can publish and later compare
    /// its address-stable canonical Heap slot without creating a general
    /// subprocess heap API.
    main_heap: AtomicPtr<Heap>,
    /// Rust's ready boundary around the source pointer publication above.
    /// `RESERVED` admits the one-way process owner before it can mutate a
    /// candidate Heap; `PUBLISHING` preserves C's store-before-initialize
    /// order while preventing an acquire lookup from treating that early
    /// identity as a usable ready result.
    main_heap_state: AtomicU8,
    /// The one source `subproc->theap_meta` identity selected during process
    /// initialization.
    ///
    /// Pinned C writes this non-atomic field once after it initializes the
    /// detached static Theap, then asserts it is non-null before taking the
    /// metadata lock. Rust retains only an identity pointer and uses a
    /// Release/Acquire one-way publication to make a stale or second static
    /// image fail closed. It grants neither dereference authority nor a
    /// general subprocess-Theap API.
    theap_meta: AtomicPtr<Theap>,
    /// Rust's bounded private-futex representation of source
    /// `subproc->theap_meta_lock`.
    ///
    /// It serializes only the selected direct allocation phase from
    /// `_mi_meta_zalloc`, `_mi_meta_zalloc_aligned`, and `_mi_meta_rezalloc`.
    /// `MetaAllocator` retains its separate outer lock for its Rust-only
    /// process-lifetime backing slots and bootstrap state. This is neither a
    /// `mi_subproc_t` byte-layout claim nor pthread-mutex equivalence.
    theap_meta_lock: PrivateLock,
}

/// Process-main-only owner. The detached metadata engine and immutable
/// ticket-zero TLD slot never occupy reclaimable child context storage.
#[repr(C)]
pub(crate) struct MainSubprocess {
    identity: SubprocessIdentity,
    metadata_allocator: crate::meta::MetaAllocator,
    main_tld: UnsafeCell<MainStaticTldSlot>,
    /// Rust-side selection of the source sequence-zero TLD branch. This selector
    /// belongs only to process main; child sequence zero always uses metadata.
    bootstrap_selection: AtomicU8,
    main_tld_state: AtomicU8,
    #[cfg(test)]
    main_tld_post_registration_state: AtomicU8,
    #[cfg(test)]
    main_tld_post_registration_total: AtomicUsize,
    #[cfg(test)]
    main_tld_post_registration_live: AtomicUsize,
}

impl core::ops::Deref for MainSubprocess {
    type Target = SubprocessIdentity;

    fn deref(&self) -> &Self::Target { &self.identity }
}

// SAFETY: common subprocess state is synchronized by its atomics/private
// locks. The process-only TLD slot is initialized by its one-way ticket-zero
// protocol and metadata-engine mutation is serialized by that engine's lock.
unsafe impl Sync for MainSubprocess {}

/// The exact parent-allocated child source image. Its shared identity starts
/// at allocation offset zero, while its pinned role wrapper prevents safe
/// movement after the source registry or intrusive Heap/Theap lists publish
/// this address. Child metadata capabilities remain in its external owner.
///
/// `native_record` is Rust state with no source counterpart: the production
/// [`lifecycle::NativeChildSubprocess`] record that owns this child, set once
/// by `lifecycle::native_subproc_new`, so that process destruction can reach
/// each child's owner from the source subprocess list as
/// `_mi_subprocs_unsafe_destroy_all` reaches each `mi_subproc_t`.
#[repr(C)]
pub(crate) struct ChildSubprocessImage {
    identity: SubprocessIdentity,
    native_record: core::sync::atomic::AtomicPtr<lifecycle::NativeChildSubprocess>,
    _pin: PhantomPinned,
}

impl core::ops::Deref for ChildSubprocessImage {
    type Target = SubprocessIdentity;

    fn deref(&self) -> &Self::Target { &self.identity }
}

impl ChildSubprocessImage {
    pub(crate) const fn new() -> Self {
        Self {
            identity: SubprocessIdentity::new_with_role(SubprocessRole::Child),
            native_record: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            _pin: PhantomPinned,
        }
    }

    #[inline]
    pub(crate) fn identity(&self) -> &SubprocessIdentity { &self.identity }

    /// Publishes the production record that owns this child. Only the first
    /// publication succeeds.
    pub(crate) fn publish_native_record(
        &self,
        record: core::ptr::NonNull<lifecycle::NativeChildSubprocess>,
    ) -> bool {
        self.native_record
            .compare_exchange(core::ptr::null_mut(), record.as_ptr(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// The production record published for this child, if any.
    #[inline]
    pub(crate) fn native_record(&self) -> Option<core::ptr::NonNull<lifecycle::NativeChildSubprocess>> {
        core::ptr::NonNull::new(self.native_record.load(Ordering::Acquire))
    }

    /// Issues the exact old source child `thread_total_count` value. Child
    /// sequence zero is always metadata-backed; only `MainSubprocess` owns
    /// the ticket-zero static TLD image.
    #[inline]
    pub(crate) fn issue_metadata_thread_ticket<'ctx>(
        self: core::pin::Pin<&'ctx Self>,
    ) -> Result<ChildThreadRegistrationTicket<'ctx>, ChildThreadTicketError> {
        let identity: &'ctx SubprocessIdentity = &self.get_ref().identity;
        if !identity.is_registered()
            || identity.main_heap_publication_state() != MainHeapPublicationState::Ready
            || !identity.has_published_metadata_theap()
        {
            return Err(ChildThreadTicketError::ChildNotReady);
        }
        let old = identity.thread_total_count.fetch_add(1, Ordering::Relaxed);
        Ok(ChildThreadRegistrationTicket {
            subprocess: identity,
            sequence: ThreadSequence::from_previous_total_count(old),
            _not_send_or_sync: PhantomData,
        })
    }
}

/// The source child thread sequence reserved before child metadata TLD
/// allocation. Its borrow keeps the child image projection alive; dropping
/// the ticket records the source monotonic failed-creation result and never
/// decrements the live-thread count.
#[must_use = "a child thread ticket must initialize one metadata TLD or record a failed creation"]
pub(crate) struct ChildThreadRegistrationTicket<'ctx> {
    subprocess: &'ctx SubprocessIdentity,
    sequence: ThreadSequence,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ChildThreadRegistrationTicket<'_> {
    #[inline]
    pub(crate) const fn sequence(&self) -> ThreadSequence { self.sequence }

    #[inline]
    pub(crate) fn subprocess(&self) -> &SubprocessIdentity { self.subprocess }

    /// Consumes this exact source sequence after its complete child TLD image
    /// has been initialized. Sequence zero is ordinary metadata storage for
    /// children; only process main can select the static TLD image.
    ///
    /// # Safety
    /// The returned lease outlives this ticket's borrow and owns no part of
    /// the child image. The caller stores it beside the matching TLD in the
    /// `ChildMainHeapContextOwner` route that issued this ticket and keeps
    /// that owner borrowed or projected until the lease is released, so the
    /// parent-metadata allocation holding the pinned child image cannot be
    /// released first. Release obligations are on
    /// `ChildThreadRegistrationLease::release`.
    #[inline]
    pub(crate) unsafe fn activate_after_initialized_tld(
        self,
        tld: &ThreadLocalData,
        thread: LiveThreadId,
    ) -> Result<ChildThreadRegistrationLease, ChildThreadTicketError> {
        if !tld.matches_subprocess_attached_no_theap_lifecycle(
            thread,
            self.sequence,
            self.subprocess,
        ) {
            return Err(ChildThreadTicketError::TldMismatch);
        }
        self.subprocess.increment_live_thread_count();
        Ok(ChildThreadRegistrationLease {
            subprocess: NonNull::from(self.subprocess),
            _not_send_or_sync: PhantomData,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildThreadTicketError {
    ChildNotReady,
    TldMismatch,
}

/// Source `thread_count` ownership for one completed child TLD.
///
/// This is the child counterpart of `ThreadRegistrationLease`, but the child
/// identity is not `'static`: it is the offset-zero identity of a pinned
/// `ChildSubprocessImage` inside a parent-metadata allocation owned by one
/// `ChildMainHeapContextOwner`. The lease records only that address, like the
/// source `tld->subproc`, and never keeps the image alive by itself.
/// `release` consumes the lease, so one TLD teardown has exactly one relaxed
/// decrement. Dropping an unreleased lease deliberately does nothing: the
/// count stays raised rather than reporting a possibly live TLD as gone.
#[must_use = "a child TLD registration must be released exactly once"]
pub(crate) struct ChildThreadRegistrationLease {
    subprocess: NonNull<SubprocessIdentity>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ChildThreadRegistrationLease {
    #[inline]
    pub(crate) fn belongs_to(&self, subprocess: &SubprocessIdentity) -> bool {
        self.subprocess == NonNull::from(subprocess)
    }

    /// Performs `mi_tld_free`'s first transition: the relaxed decrement of
    /// the child `thread_count` raised by `activate_after_initialized_tld`.
    ///
    /// # Safety
    /// - Lifetime: the `ChildMainHeapContextOwner` that issued this lease's
    ///   ticket still owns the parent-metadata allocation holding the pinned
    ///   child image, and stays borrowed (or has its image projected) for this
    ///   whole call so it cannot free, move, or reinitialize that image. The
    ///   lease's own address is not evidence of liveness.
    /// - Order: the matching TLD has no attached Theap, either because none
    ///   was ever attached or because both intrusive Heap/TLD edges are
    ///   removed, and its thread identity is still valid: this call precedes
    ///   that TLD's identity invalidation, lock teardown, and metadata free.
    #[inline]
    pub(crate) unsafe fn release(self) {
        // SAFETY: the caller keeps the issuing context owner, and therefore
        // the pinned image allocation, live for this call. Only a short shared
        // reference is formed: the identity is never projected mutably and
        // this is one atomic RMW. Consuming `self` pairs it with exactly one
        // prior increment, so the count cannot underflow.
        unsafe { self.subprocess.as_ref() }.decrement_live_thread_count();
    }
}

/// Which source subprocess path may consume the process-static TLD image.
/// Every other subprocess starts its own relaxed TLD sequence at zero but
/// must route that first TLD through its metadata-Theap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubprocessRole {
    ProcessMain,
    Child,
}

// SAFETY: the counters and one-way metadata-Theap identity are atomic; the
// private metadata lock serializes only its bounded direct-allocation callers.
// The sole UnsafeCell is initialized only by the unique sequence-zero ticket,
// then reached exclusively through its `!Send` TLD owner; it is never reused
// after retirement.
unsafe impl Sync for SubprocessIdentity {}

/// The bounded visibility of the source process-main Heap identity.
///
/// This is an identity-state observation only. It does not expose a Heap
/// reference, allocation authority, or a replacement for source process-once
/// policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapPublicationState {
    Absent,
    /// An owner has privately bound one candidate Heap, but has not published
    /// it in the subprocess atomic. No pointer is observable through this
    /// state.
    Reserved,
    Publishing,
    Ready,
    /// An invalid atomic image is retained rather than being normalized or
    /// overwritten by a later initializer.
    Retained,
}

/// Why an acquire-only main-Heap identity lookup did not produce a ready
/// opaque identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapReadyLookupError {
    Absent,
    Reserved,
    Publishing,
    Retained,
}

/// A refused source main-Heap identity transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapPublicationError {
    Reserved,
    Publishing,
    AlreadyReady,
    ForeignSubprocess,
    StalePublication,
}

/// An opaque exact identity for the initialized canonical source main Heap.
///
/// It intentionally provides equality comparison only. In particular, this
/// type exposes neither a raw-pointer getter nor a Heap reference, so it
/// cannot become a general Rust equivalent of `_mi_subproc_heap_main`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MainHeapReadyIdentity {
    heap: NonNull<Heap>,
}

impl MainHeapReadyIdentity {
    /// Checks an internally held candidate against this opaque source-main
    /// identity without granting dereference authority for either pointer.
    #[inline]
    pub(crate) fn matches(self, heap: NonNull<Heap>) -> bool {
        core::ptr::eq(self.heap.as_ptr(), heap.as_ptr())
    }
}

/// The unpublished, current-thread-only `Absent -> Reserved` admission for
/// one source main-Heap transition.
///
/// The token privately binds the final Heap identity, but `MainSubprocess`
/// stores no pointer until the owner records `src/init.c:196`'s kind-only
/// `memid` and consumes this token through `publish_main_heap_identity` for
/// line 197's Release pointer store. Dropping it deliberately leaves the
/// process image `Reserved`: Rust must not silently reopen a source-static
/// Heap transition or substitute a different candidate after mutation begins.
#[must_use = "a reserved source main-Heap transition must publish or retain the process image"]
pub(crate) struct MainHeapPublicationReservation<'subprocess> {
    subprocess: &'subprocess SubprocessIdentity,
    heap: NonNull<Heap>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// The pointer-bearing `Publishing -> Ready` portion of one source main-Heap
/// transition.
///
/// Dropping an unfinished token deliberately leaves the process image in
/// `Publishing`: Rust must not silently reopen or overwrite the
/// Release-published source-static Heap identity.
#[must_use = "a published source main-Heap identity must become ready or retain the process image"]
pub(crate) struct MainHeapPublication<'subprocess> {
    subprocess: &'subprocess SubprocessIdentity,
    heap: NonNull<Heap>,
    completed: bool,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl MainSubprocess {
    pub(crate) const fn new() -> Self {
        Self {
            identity: SubprocessIdentity::new_with_role(SubprocessRole::ProcessMain),
            metadata_allocator: crate::meta::MetaAllocator::new(),
            main_tld: UnsafeCell::new(MainStaticTldSlot::new()),
            bootstrap_selection: AtomicU8::new(BOOTSTRAP_OPEN),
            main_tld_state: AtomicU8::new(MAIN_TLD_COLD),
            #[cfg(test)]
            main_tld_post_registration_state: AtomicU8::new(MAIN_TLD_COLD),
            #[cfg(test)]
            main_tld_post_registration_total: AtomicUsize::new(0),
            #[cfg(test)]
            main_tld_post_registration_live: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_MAIN_SUBPROCESS
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut SubprocessIdentity {
        self.identity.as_ptr()
    }

    #[inline]
    pub(crate) fn owner_ptr(&self) -> *mut Self {
        core::ptr::from_ref(self).cast_mut()
    }

    #[inline]
    pub(crate) fn identity_ptr(&self) -> *mut SubprocessIdentity {
        self.identity.as_ptr()
    }

    #[inline]
    pub(crate) fn identity(&self) -> &SubprocessIdentity {
        &self.identity
    }
}

const _: [(); 0] = [(); core::mem::offset_of!(MainSubprocess, identity)];

impl SubprocessIdentity {
    const fn new_with_role(role: SubprocessRole) -> Self {
        Self {
            role,
            source_membership: registry::SourceSubprocessMembership::new(),
            arena_backing: crate::arena::ProcessArenaBacking::new(),
            statistics: crate::statistics::SubprocessStatistics::new(),
            heap_list: crate::types::heap_registry::SubprocessHeapList::new(),
            thread_count: AtomicUsize::new(0),
            thread_total_count: AtomicUsize::new(0),
            main_heap: AtomicPtr::new(core::ptr::null_mut()),
            main_heap_state: AtomicU8::new(MAIN_HEAP_ABSENT),
            theap_meta: AtomicPtr::new(core::ptr::null_mut()),
            theap_meta_lock: PrivateLock::new(),
        }
    }

    pub(crate) fn heap_list(&self) -> &crate::types::heap_registry::SubprocessHeapList {
        &self.heap_list
    }

    /// Returns this subprocess's pinned detached metadata owner.
    ///
    /// The global main owner is permanently static. Later child construction
    /// must tie this pin to the parent metadata allocation that owns the child
    /// context rather than lengthening a borrow to process lifetime.
    #[inline]
    pub(crate) const fn is_process_main(&self) -> bool {
        matches!(self.role, SubprocessRole::ProcessMain)
    }

    /// Checks the source child-parent edge after list membership publication.
    #[inline]
    pub(crate) fn is_registered_child_of(&self, parent: &SubprocessIdentity) -> bool {
        self.source_membership
            .is_child_of(parent, self.is_process_main())
    }

    #[inline]
    pub(crate) fn is_registered(&self) -> bool {
        self.source_membership.is_initialized()
    }

    /// Returns the one process-static main-subprocess identity.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_MAIN_SUBPROCESS.identity
    }

    /// Returns bitmap producers' view into this subprocess's one source
    /// statistics image. This owns no duplicate bitmap counters.
    #[inline]
    pub(crate) fn bitmap_statistics(&self) -> crate::statistics::BitmapStatistics<'_> {
        self.statistics.bitmap()
    }

    /// Returns this subprocess's only source normal-arena backing owner.
    /// Arena publication is still gated by its own reserve lock and the
    /// process-ready VM pair; this accessor grants neither either capability.
    #[inline]
    pub(crate) fn arena_backing(&self) -> &crate::arena::ProcessArenaBacking {
        &self.arena_backing
    }

    /// Returns the selected private source statistics owner. Its snapshots
    /// and aggregation have relaxed source semantics; this grants neither a
    /// public `mi_stats_t` projection nor an event-adjustment capability.
    #[inline]
    pub(crate) fn statistics(&self) -> &crate::statistics::SubprocessStatistics {
        &self.statistics
    }

    /// Returns the VM producer view of this subprocess's one statistics
    /// owner. Kept as a typed source-event boundary for existing OS paths.
    #[inline]
    pub(crate) fn vm_statistics(&self) -> crate::statistics::VmStatistics<'_> {
        self.statistics.vm()
    }

    /// Returns the arena producer view of this subprocess's one statistics
    /// owner. Kept as a typed source-event boundary for arena publication and
    /// delayed-purge paths.
    #[inline]
    pub(crate) fn arena_statistics(&self) -> crate::statistics::ArenaStatistics<'_> {
        self.statistics.arena()
    }

    /// Records the completed source `init.c` default-Theap attachment.
    /// This is separate from the Rust TLD registration count: source updates
    /// `stats.threads` only after the initialized default Theap is installed.
    #[inline]
    pub(crate) fn record_statistics_thread_attached(&self) {
        self.statistics.thread_attached();
    }

    /// Records `init.c`'s source thread-exit statistics transition.
    #[inline]
    pub(crate) fn record_statistics_thread_detached(&self) {
        self.statistics.thread_detached();
    }

    /// Records source Heap list publication/removal after its corresponding
    /// list/count transition has succeeded.
    #[inline]
    pub(crate) fn record_statistics_heap_linked(&self) {
        self.statistics.heap_linked();
    }

    #[inline]
    pub(crate) fn record_statistics_heap_unlinked(&self) {
        self.statistics.heap_unlinked();
    }

    /// Records source non-detached Theap publication/release.
    #[inline]
    pub(crate) fn record_statistics_theap_linked(&self) {
        self.statistics.theap_linked();
    }

    #[inline]
    pub(crate) fn record_statistics_theap_unlinked(&self) {
        self.statistics.theap_unlinked();
    }

    /// Records one source `theaps_lock` teardown retry before its yield.
    #[inline]
    pub(crate) fn record_statistics_heap_delete_wait(&self) {
        self.statistics.heap_delete_waited();
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *mut Self {
        core::ptr::from_ref(self).cast_mut()
    }

    /// Observes whether the canonical source main-Heap identity is absent,
    /// privately reserved but unpublished, being published, or ready. It
    /// never returns a Heap pointer.
    #[inline]
    pub(crate) fn main_heap_publication_state(&self) -> MainHeapPublicationState {
        match self.main_heap_state.load(Ordering::Acquire) {
            MAIN_HEAP_ABSENT => MainHeapPublicationState::Absent,
            MAIN_HEAP_RESERVED => MainHeapPublicationState::Reserved,
            MAIN_HEAP_PUBLISHING => MainHeapPublicationState::Publishing,
            MAIN_HEAP_READY => MainHeapPublicationState::Ready,
            _ => MainHeapPublicationState::Retained,
        }
    }

    /// Acquire-loads the ready source main-Heap identity without exposing a
    /// dereferenceable Heap capability.
    #[inline]
    pub(crate) fn ready_main_heap_identity(
        &self,
    ) -> Result<MainHeapReadyIdentity, MainHeapReadyLookupError> {
        match self.main_heap_publication_state() {
            MainHeapPublicationState::Absent => Err(MainHeapReadyLookupError::Absent),
            MainHeapPublicationState::Reserved => Err(MainHeapReadyLookupError::Reserved),
            MainHeapPublicationState::Publishing => Err(MainHeapReadyLookupError::Publishing),
            MainHeapPublicationState::Retained => Err(MainHeapReadyLookupError::Retained),
            MainHeapPublicationState::Ready => {
                let heap = NonNull::new(self.main_heap.load(Ordering::Acquire))
                    .ok_or(MainHeapReadyLookupError::Retained)?;
                Ok(MainHeapReadyIdentity { heap })
            }
        }
    }

    /// Checks whether `heap` is exactly the ready canonical source main-Heap
    /// image. This is comparison-only and grants no Heap projection.
    #[inline]
    pub(crate) fn matches_ready_main_heap(&self, heap: NonNull<Heap>) -> bool {
        match self.ready_main_heap_identity() {
            Ok(identity) => identity.matches(heap),
            Err(_) => false,
        }
    }

    #[inline]
    pub(crate) fn matches_publishing_main_heap(&self, heap: NonNull<Heap>) -> bool {
        self.main_heap_state.load(Ordering::Acquire) == MAIN_HEAP_PUBLISHING
            && core::ptr::eq(self.main_heap.load(Ordering::Acquire), heap.as_ptr())
    }

    /// Reserves this subprocess's one `Absent -> Reserved` main-Heap
    /// transition before the source-adjacent Heap image writes occur.
    ///
    /// The subprocess atomic deliberately has no pointer yet, while the
    /// returned private token binds `heap` as the only candidate that may
    /// later publish. This lets a stale owner fail before it can alter a
    /// candidate static Heap, while a valid owner can still preserve the
    /// pinned `src/init.c:196` -> `197` order by recording the kind-only
    /// static `memid` before calling [`Self::publish_main_heap_identity`].
    ///
    /// # Safety
    ///
    /// The caller must own this exact subprocess's selected main-Heap
    /// initialization branch and final stable Heap slot. For `ProcessMain`,
    /// that is the process-static slot and remains valid for process lifetime.
    /// For `Child`, the external context owner must retain the parent-issued
    /// context allocation through terminal registry, Theap, and Heap-list
    /// teardown; this token's borrow alone is not that owner. In either role,
    /// the caller must complete or deliberately retain the transition.
    /// Dropping the reservation leaves `Reserved` permanently set, so it is
    /// not a probe or retry mechanism.
    #[inline]
    pub(crate) unsafe fn begin_main_heap_publication(
        &self,
        heap: NonNull<Heap>,
    ) -> Result<MainHeapPublicationReservation<'_>, MainHeapPublicationError> {
        match self.main_heap_state.compare_exchange(
            MAIN_HEAP_ABSENT,
            MAIN_HEAP_RESERVED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(MainHeapPublicationReservation {
                subprocess: self,
                heap,
                _not_send_or_sync: PhantomData,
            }),
            Err(MAIN_HEAP_RESERVED) => Err(MainHeapPublicationError::Reserved),
            Err(MAIN_HEAP_PUBLISHING) => Err(MainHeapPublicationError::Publishing),
            Err(MAIN_HEAP_READY) => Err(MainHeapPublicationError::AlreadyReady),
            Err(_) => Err(MainHeapPublicationError::StalePublication),
        }
    }

    /// Release-publishes this subprocess's main-Heap identity after the exact
    /// role-specific memory ID has been recorded, but before the owner
    /// completes `_mi_heap_init`'s remaining Heap fields.
    ///
    /// This is exactly the `src/init.c:196` -> `197` boundary. The process
    /// main branch records its kind-only static memory ID; the child branch
    /// records the exact parent-issued Malloc ID. The returned
    /// pointer-bearing token is `Publishing`; callers must not expose a ready
    /// lookup until `finish_main_heap_publication` follows complete
    /// `Heap::initialize_main_static_after_kind_only_memid` work.
    ///
    /// # Safety
    ///
    /// `reservation` must be the one current transition for this exact
    /// subprocess and already privately binds its final role-specific main
    /// Heap image. Its source memory ID must already be installed. For a
    /// process-main identity the image is process-static; for a child the
    /// external child owner retains the exact context allocation until all
    /// Heap identity observers are quiescent after teardown. The caller
    /// exclusively owns the remaining initialization transition. This method never
    /// dereferences the bound Heap and provides no Heap projection; an
    /// incorrect reservation would nevertheless permanently bind the
    /// subprocess to a foreign or stale static slot.
    #[inline]
    pub(crate) unsafe fn publish_main_heap_identity(
        &self,
        reservation: MainHeapPublicationReservation<'_>,
    ) -> Result<MainHeapPublication<'_>, MainHeapPublicationError> {
        if !core::ptr::eq(reservation.subprocess.as_ptr(), self.as_ptr()) {
            return Err(MainHeapPublicationError::ForeignSubprocess);
        }
        let heap = reservation.heap;
        if self.main_heap_state.load(Ordering::Acquire) != MAIN_HEAP_RESERVED
            || !self.main_heap.load(Ordering::Acquire).is_null()
        {
            return Err(MainHeapPublicationError::StalePublication);
        }
        // Pinned `src/init.c:197` is the first pointer publication. Keep the
        // Rust-only state in Reserved until this Release store has made the
        // kind-only line-196 Heap image visible; no ready lookup can project
        // either state as a Heap reference.
        self.main_heap.store(heap.as_ptr(), Ordering::Release);
        self.main_heap_state
            .store(MAIN_HEAP_PUBLISHING, Ordering::Release);
        Ok(MainHeapPublication {
            subprocess: self,
            heap,
            completed: false,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Marks a previously published source main-Heap identity ready after its
    /// full static initialization completes.
    ///
    /// # Safety
    ///
    /// The token must have come from this exact subprocess, and its Heap must
    /// be completely initialized in its final stable slot before this call.
    /// The main image remains process-static. A child owner must retain its
    /// context allocation until every ready-identity observer has ended and
    /// the child Heap list is unlinked. The resulting identity is
    /// comparison-only, but a premature ready mark would falsely report the
    /// source `heap_main` image as initialized.
    #[inline]
    pub(crate) unsafe fn finish_main_heap_publication(
        &self,
        publication: &mut MainHeapPublication<'_>,
    ) -> Result<MainHeapReadyIdentity, MainHeapPublicationError> {
        if publication.completed {
            return Err(MainHeapPublicationError::StalePublication);
        }
        if !core::ptr::eq(publication.subprocess.as_ptr(), self.as_ptr()) {
            return Err(MainHeapPublicationError::ForeignSubprocess);
        }
        let heap = publication.heap;
        if !core::ptr::eq(
            self.main_heap.load(Ordering::Acquire),
            heap.as_ptr(),
        ) {
            return Err(MainHeapPublicationError::StalePublication);
        }
        match self.main_heap_state.compare_exchange(
            MAIN_HEAP_PUBLISHING,
            MAIN_HEAP_READY,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                publication.completed = true;
                Ok(MainHeapReadyIdentity { heap })
            }
            Err(_) => Err(MainHeapPublicationError::StalePublication),
        }
    }

    /// Release-publishes this process's one static detached metadata-Theap
    /// identity exactly once.
    ///
    /// # Safety
    ///
    /// `theap` must be the fully initialized detached metadata image selected
    /// for this exact subprocess. Process main retains it at a pinned static
    /// address; a child owner retains its exact metadata capability until
    /// terminal teardown and no longer permits identity observation.
    /// This method never dereferences it, but publishing a stale, incomplete,
    /// or cross-subprocess image would let a later metadata route mistake it
    /// for the source process owner. A failed publication never overwrites the
    /// prior slot. The caller retains the subprocess image and Theap owner
    /// through the complete publication lifetime.
    #[inline]
    pub(crate) unsafe fn publish_detached_metadata_theap(
        &self,
        theap: NonNull<Theap>,
    ) -> bool {
        self.theap_meta
            .compare_exchange(
                core::ptr::null_mut(),
                theap.as_ptr(),
                Ordering::Release,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub(crate) fn has_published_metadata_theap(&self) -> bool {
        !self.theap_meta.load(Ordering::Acquire).is_null()
    }

    /// The published detached metadata Theap address, for fixture checks.
    #[cfg(test)]
    pub(crate) fn test_published_metadata_theap(&self) -> *mut Theap {
        self.theap_meta.load(Ordering::Acquire)
    }

    /// Source `subproc.c:232` clears metadata identity after Heap destruction
    /// and before arena release. A child engine must be absent or terminally
    /// closed; a parent metadata engine may still own the detached storage.
    ///
    /// # Safety
    /// Permanent terminal admission excludes every source observer and the
    /// no child metadata engine can allocate or retain pages through this
    /// subprocess. If a child engine was initialized, its exact owner has
    /// consumed it. No old metadata Page may subsequently be classified
    /// through this subprocess.
    pub(crate) unsafe fn clear_metadata_identity_terminal(&self) {
        self.theap_meta.store(core::ptr::null_mut(), Ordering::Release);
    }

    /// Checks only whether `theap` is the exact previously published detached
    /// metadata image. It does not dereference the slot or grant allocation
    /// authority.
    #[inline]
    pub(crate) fn matches_published_detached_metadata_theap(&self, theap: NonNull<Theap>) -> bool {
        core::ptr::eq(self.theap_meta.load(Ordering::Acquire), theap.as_ptr())
    }

    /// Acquires the bounded Rust representation of source
    /// `subproc->theap_meta_lock`.
    ///
    /// Production callers must first prove the existing `theap_meta` identity
    /// admission. Only `MetaAllocator`'s selected direct allocation phase may
    /// retain this guard; it releases the guard before `_mi_meta_rezalloc`'s
    /// Rust copy and exact-owner free work. The source Malloc branch of
    /// `_mi_meta_free` does not take this lock, so Rust's separate backing
    /// lock remains responsible for its private allocator mutation.
    #[inline]
    pub(crate) fn lock_metadata_theap(&self) -> CoreResult<PrivateLockGuard<'_>> {
        self.theap_meta_lock.lock()
    }

    /// Test-only observation of a selected direct metadata caller waiting on
    /// this source-owned lock. It grants neither lock ownership nor a Theap
    /// capability.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_metadata_theap_lock_is_contended(&self) -> bool {
        self.theap_meta_lock.test_is_contended()
    }

    /// Holds the selected source-owned metadata lock for one ordering test.
    /// This is test-only and grants no metadata allocation or Theap
    /// capability.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_hold_metadata_theap_lock(&self) -> CoreResult<PrivateLockGuard<'_>> {
        self.lock_metadata_theap()
    }

    /// Implements the selected read-only `_mi_meta_is_meta_page` predicate.
    ///
    /// `None` represents C's null `mi_page_t*` input. A Rust `&Page` proves
    /// that the page image is readable for the field load; this method grants
    /// neither a Theap reference nor authority to change the page or
    /// subprocess. It deliberately takes no metadata or subprocess lock,
    /// does not inspect COLD/BOUND/READY state, and does not start backing or
    /// a detached session.
    #[inline]
    pub(crate) fn is_metadata_page(&self, page: Option<&Page>) -> bool {
        let Some(page) = page else {
            return false;
        };
        let theap = page.theap();
        !theap.is_null() && core::ptr::eq(theap, self.theap_meta.load(Ordering::Acquire))
    }

    /// Test-only observation of whether the source metadata-Theap identity is
    /// non-null. This deliberately reveals neither its address nor a usable
    /// Theap reference.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_has_published_metadata_theap(&self) -> bool {
        !self.theap_meta.load(Ordering::Acquire).is_null()
    }

    /// Source `thread_count`: TLDs registered and not yet freed. Child
    /// destruction reads it under the operation that excludes admission.
    #[inline]
    pub(crate) fn live_thread_count(&self) -> usize {
        self.thread_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn total_thread_count(&self) -> usize {
        self.thread_total_count.load(Ordering::Relaxed)
    }

    #[inline]
    fn increment_live_thread_count(&self) {
        self.thread_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn decrement_live_thread_count(&self) {
        let prior = self.thread_count.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(prior > 0, "a thread-registration lease cannot underflow");
    }


}


impl MainSubprocess {
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_static_owner() -> &'static Self {
        // Each fixture owns its isolated source-main image so tests cannot
        // depend on the process singleton's first-ticket history.
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    /// Reserves the unique source-static ticket-zero path for a process
    /// coordinator.
    ///
    /// The returned linear selector prevents generic TLD construction while
    /// source main-heap/map initialization is in progress. Dropping it before
    /// the static heap changes returns the process to `OPEN`; every later
    /// drop is terminal so a partial source image cannot be mistaken for an
    /// unselected process.
    pub(crate) fn reserve_static_bootstrap(
        &'static self,
    ) -> Result<MainStaticBootstrapSelection, MainStaticBootstrapSelectionError> {
        if !self.is_process_main() {
            return Err(MainStaticBootstrapSelectionError::NotProcessMain);
        }
        let observed = self.bootstrap_selection.compare_exchange(
            BOOTSTRAP_OPEN,
            BOOTSTRAP_STATIC_SELECTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        match observed {
            Ok(_) => {
                // Every supported ticket issuer first claims the selector
                // before it can increment the source relaxed counter. Keep a
                // defensive check here so a future raw issuer fails closed
                // instead of stealing a nonzero static branch.
                if self.thread_total_count.load(Ordering::Relaxed) != 0 {
                    self.bootstrap_selection
                        .store(BOOTSTRAP_RETAINED, Ordering::Release);
                    return Err(MainStaticBootstrapSelectionError::FirstTicketAlreadyIssued);
                }
                Ok(MainStaticBootstrapSelection {
                    subprocess: self,
                    heap_foundation_committed: false,
                    completed: false,
                    _not_send_or_sync: PhantomData,
                })
            }
            Err(BOOTSTRAP_GENERIC_READY) => {
                Err(MainStaticBootstrapSelectionError::FirstTicketAlreadyIssued)
            }
            Err(BOOTSTRAP_STATIC_SELECTING | BOOTSTRAP_STATIC_TICKET_ISSUED) => {
                Err(MainStaticBootstrapSelectionError::Selecting)
            }
            Err(BOOTSTRAP_STATIC_READY | BOOTSTRAP_RETAINED | _) => {
                Err(MainStaticBootstrapSelectionError::Retained)
            }
        }
    }

    /// Issues the exact old value of source `thread_total_count.fetch_add`
    /// for a generic TLD constructor.
    ///
    /// This happens before any metadata allocation attempt. Dropping the
    /// resulting ticket intentionally does not roll the total count back:
    /// upstream total-thread sequencing is monotonic even when TLD creation
    /// later fails.
    pub(crate) fn issue_generic_thread_ticket(
        &'static self,
    ) -> Result<ThreadRegistrationTicket, GenericThreadTicketError> {
        loop {
            match self.bootstrap_selection.load(Ordering::Acquire) {
                BOOTSTRAP_OPEN => {
                    // Taking sequence zero requires a selector transition
                    // first. If a source static coordinator wins instead,
                    // this generic path observes its explicit rejection
                    // before it can mutate the relaxed sequence.
                    if self.thread_total_count.load(Ordering::Relaxed) == 0 {
                        if self
                            .bootstrap_selection
                            .compare_exchange(
                                BOOTSTRAP_OPEN,
                                BOOTSTRAP_GENERIC_READY,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_err()
                        {
                            continue;
                        }
                        let ticket = self.issue_thread_ticket_unchecked();
                        debug_assert_eq!(ticket.is_first_main_tld(), self.is_process_main());
                        return Ok(ticket);
                    }

                    // A nonzero sequence with an open selector can only
                    // arise through a future raw issuer that bypassed this
                    // module. Preserve the static slots and reject it rather
                    // than guessing which branch owns ticket zero.
                    self.bootstrap_selection
                        .store(BOOTSTRAP_RETAINED, Ordering::Release);
                    return Err(GenericThreadTicketError::BootstrapRetained);
                }
                BOOTSTRAP_GENERIC_READY | BOOTSTRAP_STATIC_READY => {
                    return Ok(self.issue_thread_ticket_unchecked());
                }
                BOOTSTRAP_STATIC_SELECTING | BOOTSTRAP_STATIC_TICKET_ISSUED => {
                    return Err(GenericThreadTicketError::StaticBootstrapSelecting);
                }
                BOOTSTRAP_RETAINED | _ => {
                    return Err(GenericThreadTicketError::BootstrapRetained);
                }
            }
        }
    }

    /// Reserves exactly one nonzero source sequence for the bounded dynamic
    /// Theap path without consuming ticket zero.
    ///
    /// This is an intentional Rust process-selection gate, not a replacement
    /// for `mi_tld_create`'s unconditional `fetch_add`: ticket zero belongs to
    /// the separately selected static-main path in this milestone. The CAS
    /// loop is Relaxed like the source counter and prevents a read-then-add
    /// race from accidentally seizing that static ticket. Once a nonzero old
    /// value is reserved it is a normal source ticket; later TLD allocation
    /// failure still consumes it and leaves the live count unchanged.
    #[inline]
    pub(crate) fn issue_later_thread_ticket(
        &'static self,
    ) -> Result<ThreadRegistrationTicket, LaterThreadTicketError> {
        let mut observed = self.thread_total_count.load(Ordering::Relaxed);
        loop {
            match self.bootstrap_selection.load(Ordering::Acquire) {
                BOOTSTRAP_STATIC_SELECTING | BOOTSTRAP_STATIC_TICKET_ISSUED => {
                    return Err(LaterThreadTicketError::StaticBootstrapSelecting);
                }
                BOOTSTRAP_RETAINED => return Err(LaterThreadTicketError::BootstrapRetained),
                _ => {}
            }
            if observed == 0 {
                return Err(LaterThreadTicketError::FirstTicketReserved);
            }
            match self.thread_total_count.compare_exchange_weak(
                observed,
                observed.wrapping_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(old) => {
                    return Ok(ThreadRegistrationTicket {
                        subprocess: self,
                        sequence: ThreadSequence::from_previous_total_count(old),
                        _not_send_or_sync: PhantomData,
                    });
                }
                Err(current) => observed = current,
            }
        }
    }

    /// Proves the fresh static slot is still cold before the selected
    /// ticket-zero attachment begins its claim/provenance transition.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_main_tld_is_cold(&self) -> bool {
        self.main_tld_state.load(Ordering::Acquire) == MAIN_TLD_COLD
    }

    /// Observes the test-only state between static-provenance formation and
    /// complete image publication without exposing the partial TLD image.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_main_tld_is_claimed(&self) -> bool {
        self.main_tld_state.load(Ordering::Acquire) == MAIN_TLD_CLAIMED
    }

    /// Proves that the static normal-arm registration was recorded while its
    /// source slot was still claimed, before its later Release publication.
    /// It deliberately exposes only scalar ordering evidence, never the
    /// unpublished TLD image.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_main_tld_registered_while_claimed(&self) -> bool {
        self.main_tld_post_registration_state.load(Ordering::Acquire) == MAIN_TLD_CLAIMED
            && self
                .main_tld_post_registration_total
                .load(Ordering::Relaxed)
                == 1
            && self
                .main_tld_post_registration_live
                .load(Ordering::Relaxed)
                == 1
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_main_tld_is_live(&self) -> bool {
        self.main_tld_state.load(Ordering::Acquire) == MAIN_TLD_LIVE
    }

    /// Initializes the static TLD image after its concrete static provenance
    /// exists, but before its normal-arm registration and Release
    /// publication.
    ///
    /// The source's `mi_tld_create` constructs `MI_MEM_STATIC` provenance
    /// before `mi_tld_init` obtains the live NUMA node. Rust first materializes
    /// the selected zero-shaped source preimage, then runs the modeled normal
    /// helper body in field order. The returned unpublished token keeps the
    /// final source `thread_count` increment inseparable from publication.
    fn initialize_main_tld_unpublished_with_numa_source(
        &'static self,
        sequence: ThreadSequence,
        thread: LiveThreadId,
        numa_node_source: impl FnOnce(MemoryId) -> i32,
    ) -> Result<PendingMainStaticThreadLocalData, MainStaticTldError> {
        self.initialize_main_tld_unpublished_with_numa_source_impl(
            sequence,
            thread,
            numa_node_source,
            #[cfg(test)]
            None,
        )
    }

    /// Test-only trace entry for the same unpublished static-TLD transition.
    ///
    /// The trace is a stack borrow owned by the private attachment path; this
    /// method returns only the same private pending token as production and
    /// never grants an unpublished TLD projection.
    #[cfg(test)]
    #[inline]
    fn test_initialize_main_tld_unpublished_with_numa_source(
        &'static self,
        sequence: ThreadSequence,
        thread: LiveThreadId,
        numa_node_source: impl FnOnce(MemoryId) -> i32,
        trace: &mut StaticFirstTldCreateTrace,
    ) -> Result<PendingMainStaticThreadLocalData, MainStaticTldError> {
        self.initialize_main_tld_unpublished_with_numa_source_impl(
            sequence,
            thread,
            numa_node_source,
            Some(trace),
        )
    }

    #[inline]
    fn initialize_main_tld_unpublished_with_numa_source_impl(
        &'static self,
        sequence: ThreadSequence,
        thread: LiveThreadId,
        numa_node_source: impl FnOnce(MemoryId) -> i32,
        #[cfg(test)] trace: Option<&mut StaticFirstTldCreateTrace>,
    ) -> Result<PendingMainStaticThreadLocalData, MainStaticTldError> {
        if sequence.get() != 0 {
            return Err(MainStaticTldError::NotFirstTicket);
        }
        if self
            .main_tld_state
            .compare_exchange(
                MAIN_TLD_COLD,
                MAIN_TLD_CLAIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(MainStaticTldError::AlreadyUsed);
        }

        let tld = self.main_tld_ptr();
        let memid = MemoryId::static_allocation(tld.cast(), size_of::<ThreadLocalData>());
        // SAFETY: sequence zero is unique for this process-main identity and
        // the state transition above grants the only mutable initialization
        // authority over this final static slot. The raw helper first writes
        // a valid zero-shaped image, then forms a mutable reference only for
        // the selected source-order normal arm.
        #[cfg(test)]
        match trace {
            Some(trace) => {
                // SAFETY: the unique claimed source-static slot remains
                // unobservable until the private pending token completes its
                // live registration and Release publication.
                unsafe {
                    ThreadLocalData::test_write_subprocess_attached_no_theap_at_with_static_first_trace(
                        tld,
                        thread,
                        sequence,
                        move || numa_node_source(memid),
                        self,
                        memid,
                        trace,
                    )
                };
            }
            None => {
                // SAFETY: as above, this is the production half of the
                // shared source-static transition in a test build.
                unsafe {
                    ThreadLocalData::write_subprocess_attached_no_theap_at(
                        tld,
                        thread,
                        sequence,
                        move || numa_node_source(memid),
                        self,
                        memid,
                    )
                };
            }
        }
        #[cfg(not(test))]
        unsafe {
            ThreadLocalData::write_subprocess_attached_no_theap_at(
                tld,
                thread,
                sequence,
                move || numa_node_source(memid),
                self,
                memid,
            )
        }

        Ok(PendingMainStaticThreadLocalData {
            subprocess: self,
            // SAFETY: `main_tld` is an aligned static `ThreadLocalData` image
            // initialized immediately above and cannot be null. The pending
            // token retains the only projection until count registration and
            // Release publication complete.
            pointer: unsafe { NonNull::new_unchecked(tld) },
        })
    }

    #[cfg(test)]
    #[inline]
    fn record_main_tld_post_registration_snapshot(&self) {
        self.main_tld_post_registration_total.store(
            self.thread_total_count.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.main_tld_post_registration_live.store(
            self.thread_count.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.main_tld_post_registration_state.store(
            self.main_tld_state.load(Ordering::Acquire),
            Ordering::Release,
        );
    }

    fn retire_main_tld(&self, pointer: NonNull<ThreadLocalData>) {
        debug_assert_eq!(pointer.as_ptr(), self.main_tld_ptr());
        let retired = self
            .main_tld_state
            .compare_exchange(
                MAIN_TLD_LIVE,
                MAIN_TLD_RETIRED,
                Ordering::Release,
                Ordering::Acquire,
            )
            .is_ok();
        // The static projection is private to the ticket-zero owner. Once
        // its complete image was Release-published, no other transition can
        // race or legally precede this retirement; keep that proof boundary
        // structurally infallible instead of dropping a static owner on an
        // recoverable-looking error path.
        debug_assert!(retired);
    }

    #[inline]
    fn main_tld_ptr(&self) -> *mut ThreadLocalData {
        // SAFETY: taking a raw field address through the `UnsafeCell` does
        // not form a reference to the uninitialized TLD. Every later write or
        // projection is separately gated by the static-slot state machine.
        debug_assert!(self.is_process_main());
        unsafe { core::ptr::addr_of_mut!((*self.main_tld.get()).image).cast() }
    }

    #[inline]
    fn issue_thread_ticket_unchecked(&'static self) -> ThreadRegistrationTicket {
        let old = self.identity.thread_total_count.fetch_add(1, Ordering::Relaxed);
        ThreadRegistrationTicket {
            subprocess: self,
            sequence: ThreadSequence::from_previous_total_count(old),
            _not_send_or_sync: PhantomData,
        }
    }
}

static PROCESS_MAIN_SUBPROCESS: MainSubprocess = MainSubprocess::new();

impl MainSubprocess {
    pub(crate) fn metadata_allocator(&'static self) -> core::pin::Pin<&'static crate::meta::MetaAllocator> {
        // SAFETY: this wrapper is the process-static owner; child images do
        // not contain or project a process metadata engine.
        unsafe { core::pin::Pin::new_unchecked(&self.metadata_allocator) }
    }
}

/// A selected source-static ticket-zero bootstrap path.
///
/// It is intentionally `!Send`/`!Sync`: the coordinator performs the
/// static-main source transition on one current thread and must either finish
/// its TLD/Theap publication or retain the incomplete process image.
#[must_use = "a selected static bootstrap must finish its ticket-zero attachment or retain the process image"]
pub(crate) struct MainStaticBootstrapSelection {
    subprocess: &'static MainSubprocess,
    heap_foundation_committed: bool,
    completed: bool,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl MainStaticBootstrapSelection {
    #[inline]
    pub(crate) const fn subprocess(&self) -> &'static MainSubprocess {
        self.subprocess
    }

    /// Marks the source main-heap static slot as initialized. From this point
    /// a failed process-map or ticket-zero attachment is process-terminal.
    #[inline]
    pub(crate) fn commit_heap_foundation(&mut self) {
        self.heap_foundation_committed = true;
    }

    /// Retains the selected static branch after it has irreversibly reserved
    /// the source main-Heap transition but before a complete foundation
    /// exists. This is deliberately not `commit_heap_foundation`: no caller
    /// may issue ticket zero from this failed image, yet Drop must not reopen
    /// the selector while `heap_main` remains Reserved or Publishing.
    #[inline]
    pub(crate) fn retain_after_main_heap_reservation(&mut self) {
        self.subprocess
            .bootstrap_selection
            .store(BOOTSTRAP_RETAINED, Ordering::Release);
        self.completed = true;
    }

    /// Consumes source sequence zero only after the static Heap foundation
    /// exists and before the static TLD/Theap attachment is initialized.
    pub(crate) fn issue_first_ticket(
        &mut self,
    ) -> Result<ThreadRegistrationTicket, MainStaticBootstrapSelectionError> {
        self.issue_first_ticket_impl(
            #[cfg(test)]
            None,
        )
    }

    /// Test-only recording entry used only by the private static attachment
    /// trace. It returns the ordinary linear ticket; no test gains a
    /// standalone static-TLD or lease construction route.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_issue_first_ticket_with_static_first_trace(
        &mut self,
        trace: &mut StaticFirstTldCreateTrace,
    ) -> Result<ThreadRegistrationTicket, MainStaticBootstrapSelectionError> {
        self.issue_first_ticket_impl(Some(trace))
    }

    #[inline]
    fn issue_first_ticket_impl(
        &mut self,
        #[cfg(test)] mut trace: Option<&mut StaticFirstTldCreateTrace>,
    ) -> Result<ThreadRegistrationTicket, MainStaticBootstrapSelectionError> {
        if !self.heap_foundation_committed {
            return Err(MainStaticBootstrapSelectionError::HeapFoundationNotCommitted);
        }
        if self
            .subprocess
            .bootstrap_selection
            .load(Ordering::Acquire)
            != BOOTSTRAP_STATIC_SELECTING
        {
            return Err(MainStaticBootstrapSelectionError::Retained);
        }
        let ticket = self.subprocess.issue_thread_ticket_unchecked();
        if !ticket.is_first_main_tld() {
            self.subprocess
                .bootstrap_selection
                .store(BOOTSTRAP_RETAINED, Ordering::Release);
            return Err(MainStaticBootstrapSelectionError::FirstTicketAlreadyIssued);
        }
        self.subprocess
            .bootstrap_selection
            .store(BOOTSTRAP_STATIC_TICKET_ISSUED, Ordering::Release);
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            // This records the actual existing total-count ticket only after
            // its sequence-zero branch has been accepted. The selector's
            // earlier foundation preparation is deliberately not recorded as
            // C caller-order parity.
            trace.record_ticket_zero_issued();
        }
        Ok(ticket)
    }

    /// Publishes that the static TLD/Theap branch completed. Generic later
    /// TLD construction may now issue nonzero source tickets.
    pub(crate) fn complete_initial_thread(&mut self) -> bool {
        let result = self.subprocess.bootstrap_selection.compare_exchange(
            BOOTSTRAP_STATIC_TICKET_ISSUED,
            BOOTSTRAP_STATIC_READY,
            Ordering::Release,
            Ordering::Acquire,
        );
        if result.is_ok() {
            self.completed = true;
            true
        } else {
            self.subprocess
                .bootstrap_selection
                .store(BOOTSTRAP_RETAINED, Ordering::Release);
            false
        }
    }

    /// Records an explicit retained process image before normal completion.
    #[inline]
    pub(crate) fn retain(mut self) {
        self.subprocess
            .bootstrap_selection
            .store(BOOTSTRAP_RETAINED, Ordering::Release);
        self.completed = true;
    }
}

impl Drop for MainStaticBootstrapSelection {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.heap_foundation_committed {
            self.subprocess
                .bootstrap_selection
                .store(BOOTSTRAP_RETAINED, Ordering::Release);
        } else {
            // A pre-foundation selection failure is still a pure preflight
            // outcome. Restore OPEN only if this token still owns it; a
            // foreign state is itself terminal rather than an excuse to
            // overwrite another selector's decision.
            let _ = self.subprocess.bootstrap_selection.compare_exchange(
                BOOTSTRAP_STATIC_SELECTING,
                BOOTSTRAP_OPEN,
                Ordering::Release,
                Ordering::Acquire,
            );
        }
    }
}

/// A refused static-main selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticBootstrapSelectionError {
    NotProcessMain,
    /// The static Heap must occupy its final source slot before ticket zero
    /// can make the static TLD image observable.
    HeapFoundationNotCommitted,
    FirstTicketAlreadyIssued,
    Selecting,
    Retained,
}

/// A generic ticket cannot cross an active or retained static-main bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenericThreadTicketError {
    StaticBootstrapSelecting,
    BootstrapRetained,
}

/// The source-issued old `thread_total_count` result for one TLD attempt.
///
/// It is deliberately not `Copy`: one ticket can create at most one static
/// source image or one metadata image, and only then can it be consumed into a
/// live-count lease. Its drop is an explicit failed-creation outcome, not a
/// rollback of the total-thread sequence.
#[must_use = "a source thread-registration ticket must become one TLD lease, record a failed creation, or be returned from a pre-body direct-preimage refusal"]
pub(crate) struct ThreadRegistrationTicket {
    subprocess: &'static MainSubprocess,
    sequence: ThreadSequence,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// Dynamic attachment deliberately leaves the process-main static ticket for
/// `MainStaticTheapAttachment`; this is the explicit outcome when it has not
/// yet been consumed by the selected bootstrap owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaterThreadTicketError {
    FirstTicketReserved,
    StaticBootstrapSelecting,
    BootstrapRetained,
}

impl ThreadRegistrationTicket {
    #[inline]
    pub(crate) const fn sequence(&self) -> ThreadSequence {
        self.sequence
    }

    #[inline]
    pub(crate) const fn is_first_main_tld(&self) -> bool {
        self.subprocess.identity.is_process_main() && self.sequence.get() == 0
    }

    /// Initializes and registers the actual static `mi_process_tld_main`
    /// branch as one consuming ticket transition.
    ///
    /// No metadata allocator is touched here. The source performs this branch
    /// after issuing ticket zero, and its static `MI_MEM_STATIC` provenance is
    /// later a deliberate no-op release. The ticket is consumed only after
    /// the complete image exists; its live publication cannot escape as a
    /// separate unregistered static-storage capability.
    #[inline]
    pub(crate) fn initialize_and_activate_first_main_tld(
        self,
        thread: LiveThreadId,
        numa_node: i32,
    ) -> Result<(MainStaticThreadLocalData, ThreadRegistrationLease), MainStaticTldError> {
        self.initialize_and_activate_first_main_tld_with_numa_source(thread, move |_| numa_node)
    }

    /// Initializes ticket zero from a private NUMA source after static
    /// provenance is available and before the final TLD image is published.
    ///
    /// The source is invoked synchronously and is never retained as allocator
    /// policy or caller-configurable state. The existing numeric entry point
    /// remains the raw-input route used by generic/later TLD construction.
    #[inline]
    pub(crate) fn initialize_and_activate_first_main_tld_with_numa_source(
        self,
        thread: LiveThreadId,
        numa_node_source: impl FnOnce(MemoryId) -> i32,
    ) -> Result<(MainStaticThreadLocalData, ThreadRegistrationLease), MainStaticTldError> {
        let storage = self
            .subprocess
            .initialize_main_tld_unpublished_with_numa_source(
                self.sequence,
                thread,
                numa_node_source,
            )?;
        debug_assert!(storage
            .current()
            .matches_subprocess_attached_no_theap_lifecycle(
                thread,
                self.sequence,
                self.subprocess,
            ));
        let subprocess = self.subprocess;
        let registration = self.consume_after_normal_tld_body(storage.current(), thread);
        #[cfg(test)]
        subprocess.record_main_tld_post_registration_snapshot();
        #[cfg(not(test))]
        let _ = subprocess;
        // No fallible operation or callback may intervene between the source
        // live-count increment above and this publication. The lease is an
        // already-constructed linear record; the Release store makes the
        // complete, registered static image observable only afterward.
        let storage = storage.publish();
        Ok((storage, registration))
    }

    /// Test-only recording entry for the existing ticket-zero static owner.
    ///
    /// Only `main_theap`'s private attachment transition calls this method;
    /// its stack-borrowed trace is never retained by, or allowed to escape
    /// through, the pending token or returned owner, so it cannot become a
    /// standalone TLD/lease API. Unlike the ordinary test-build path, this
    /// deliberately bypasses the legacy scalar post-registration snapshot:
    /// the trace records the one live increment and then the sole Release
    /// store with no unrelated observation, callback, fallible operation, or
    /// owner exposure in between.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_initialize_and_activate_first_main_tld_with_static_first_trace(
        self,
        thread: LiveThreadId,
        numa_node_source: impl FnOnce(MemoryId) -> i32,
        trace: &mut StaticFirstTldCreateTrace,
    ) -> Result<(MainStaticThreadLocalData, ThreadRegistrationLease), MainStaticTldError> {
        let storage = self
            .subprocess
            .test_initialize_main_tld_unpublished_with_numa_source(
                self.sequence,
                thread,
                numa_node_source,
                trace,
            )?;
        debug_assert!(storage
            .current()
            .matches_subprocess_attached_no_theap_lifecycle(
                thread,
                self.sequence,
                self.subprocess,
            ));
        let registration = self.consume_after_normal_tld_body_with_static_first_trace(
            storage.current(),
            thread,
            trace,
        );
        // The trace records the just-completed relaxed live increment. Its
        // next operation is the one real `MAIN_TLD_LIVE` Release store; no
        // Result/Option branch, callback, allocation, or owner projection is
        // permitted in this gap.
        let storage = storage.publish_with_static_first_trace(trace);
        Ok((storage, registration))
    }

    /// Test-only direct model of the entire selected normal `mi_tld_init`
    /// operation for one minimal helper preimage. The production static and
    /// metadata routes use the source-ordered field prefix with their owned
    /// lifecycle capabilities; this fixture must not become a standalone
    /// live-TLD construction API. The ticket supplies the caller-owned source
    /// sequence and is consumed only after every body field succeeds; its
    /// single live-count increment is therefore the final modeled helper
    /// event. A rejected preimage or busy-lock safety check returns the exact
    /// ticket unchanged: this narrow Rust strengthening occurs before any
    /// modeled source field or counter mutation, unlike ordinary source
    /// ticketed allocation failure, which still consumes its sequence.
    #[cfg(test)]
    #[inline]
    pub(crate) fn initialize_normal_tld_after_direct_preimage(
        self,
        tld: &mut ThreadLocalData,
        thread: LiveThreadId,
        numa_node: i32,
    ) -> Result<ThreadRegistrationLease, Self> {
        self.initialize_normal_tld_after_direct_preimage_with_numa_source(
            tld,
            thread,
            move || numa_node,
        )
    }

    /// As above, but obtains the bounded NUMA value at the source body write.
    #[cfg(test)]
    #[inline]
    pub(crate) fn initialize_normal_tld_after_direct_preimage_with_numa_source(
        self,
        tld: &mut ThreadLocalData,
        thread: LiveThreadId,
        numa_node_source: impl FnOnce() -> i32,
    ) -> Result<ThreadRegistrationLease, Self> {
        if !tld.initialize_normal_tld_field_prefix_after_direct_preimage_with_numa_source(
            thread,
            self.sequence,
            numa_node_source,
            self.subprocess,
        ) {
            return Err(self);
        }
        Ok(self.consume_after_normal_tld_body(tld, thread))
    }

    /// Test-only recording wrapper around the same full normal-operation
    /// implementation. It exists solely to prove the source write and live
    /// registration order; it does not replace production initialization.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_initialize_normal_tld_after_direct_preimage(
        self,
        tld: &mut ThreadLocalData,
        thread: LiveThreadId,
        numa_node: i32,
        trace: &mut NormalTldInitWriteTrace,
    ) -> Result<ThreadRegistrationLease, Self> {
        if !tld.test_initialize_normal_tld_field_prefix_after_direct_preimage(
            thread,
            self.sequence,
            numa_node,
            self.subprocess,
            trace,
        ) {
            return Err(self);
        }
        Ok(self.consume_after_normal_tld_body_with_trace(tld, thread, trace))
    }

    #[inline]
    fn consume_after_normal_tld_body(
        self,
        tld: &ThreadLocalData,
        thread: LiveThreadId,
    ) -> ThreadRegistrationLease {
        debug_assert!(tld.matches_subprocess_attached_no_theap_lifecycle(
            thread,
            self.sequence,
            self.subprocess,
        ));
        self.subprocess.increment_live_thread_count();
        ThreadRegistrationLease {
        subprocess: self.subprocess.identity(),
            _not_send_or_sync: PhantomData,
        }
    }

    #[cfg(test)]
    #[inline]
    fn consume_after_normal_tld_body_with_trace(
        self,
        tld: &ThreadLocalData,
        thread: LiveThreadId,
        trace: &mut NormalTldInitWriteTrace,
    ) -> ThreadRegistrationLease {
        let registration = self.consume_after_normal_tld_body(tld, thread);
        trace.record_live_registration();
        registration
    }

    /// Fixed scalar test witness for the static ticket-zero path. Unlike a
    /// trait-object hook, this exact trace has no caller-provided dispatch in
    /// the critical live-registration to Release-publication gap.
    #[cfg(test)]
    #[inline]
    fn consume_after_normal_tld_body_with_static_first_trace(
        self,
        tld: &ThreadLocalData,
        thread: LiveThreadId,
        trace: &mut StaticFirstTldCreateTrace,
    ) -> ThreadRegistrationLease {
        let registration = self.consume_after_normal_tld_body(tld, thread);
        trace.record_live_registration();
        registration
    }

    /// Consumes this ticket after its complete TLD image exists.
    ///
    /// # Safety
    ///
    /// `tld` must be the completed source-shaped
    /// subprocess-attached/no-theap image initialized by this exact ticket:
    /// it must carry `thread`, this ticket's old total-count sequence, and
    /// this ticket's process-main pointer. The only caller is the private TLD
    /// constructor immediately after its static or direct-zeroed metadata
    /// initialization; this keeps a live-count increment inseparable from a
    /// matching TLD. The debug assertion remains a focused proof witness.
    #[inline]
    pub(crate) unsafe fn activate_after_initialized_tld(
        self,
        tld: &ThreadLocalData,
        thread: LiveThreadId,
    ) -> ThreadRegistrationLease {
        debug_assert!(tld.matches_subprocess_attached_no_theap_lifecycle(
            thread,
            self.sequence,
            self.subprocess,
        ));
        self.subprocess.increment_live_thread_count();
        ThreadRegistrationLease {
            subprocess: self.subprocess.identity(),
            _not_send_or_sync: PhantomData,
        }
    }
}

/// The sole ownership record for source `thread_count` after TLD creation.
///
/// `release` consumes the lease, so one normal teardown has exactly one
/// relaxed decrement. Dropping a lease deliberately does nothing: the unsafe
/// explicit-teardown contract was violated, and silently decrementing would
/// falsely report that its still-live TLD is no longer registered.
#[must_use = "a live subprocess registration must be released exactly once"]
pub(crate) struct ThreadRegistrationLease {
    subprocess: &'static SubprocessIdentity,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ThreadRegistrationLease {
    /// Moves the registration's release obligation into the live source TLD.
    /// The matching metadata transfer preserves that TLD's identity and
    /// subprocess fields; no thread-count decrement happens here.
    pub(crate) fn into_source_retained(self) {}

    /// Recovers the registration paired with an explicitly transferred TLD.
    ///
    /// # Safety
    /// The caller has exclusive process quiescence, recovered this exact TLD
    /// metadata once, and proves its original lease crossed
    /// `into_source_retained` without release or prior recovery. The source
    /// TLD and subprocess must remain live for the returned lease.
    pub(crate) unsafe fn recover_source_retained(
        subprocess: &'static SubprocessIdentity,
        tld: &ThreadLocalData,
    ) -> Option<Self> {
        let thread = LiveThreadId::new(tld.thread_id())?;
        if !tld.matches_subprocess_attached_lifecycle(thread, tld.thread_sequence(), subprocess) {
            return None;
        }
        Some(Self { subprocess, _not_send_or_sync: PhantomData })
    }

    #[inline]
    pub(crate) fn release(self) {
        self.subprocess.decrement_live_thread_count();
    }
}

/// A unique projection of source-static `mi_process_tld_main` storage.
pub(crate) struct MainStaticThreadLocalData {
    subprocess: &'static MainSubprocess,
    pointer: NonNull<ThreadLocalData>,
}

/// The fully initialized but not yet registered/published static TLD image.
///
/// This private token is deliberately not a public TLD projection. It holds
/// the exact source-order gap between normal-arm field writes and the final
/// `thread_count` increment, so the latter must happen before the owner can
/// Release-publish `MAIN_TLD_LIVE`.
struct PendingMainStaticThreadLocalData {
    subprocess: &'static MainSubprocess,
    pointer: NonNull<ThreadLocalData>,
}

impl PendingMainStaticThreadLocalData {
    #[inline]
    fn current(&self) -> &ThreadLocalData {
        // SAFETY: only the sequence-zero transition constructs this pending
        // token. Its image was fully initialized before the token exists and
        // remains unobservable until `publish` consumes this token.
        unsafe { self.pointer.as_ref() }
    }

    #[inline]
    fn publish(self) -> MainStaticThreadLocalData {
        self.publish_impl(
            #[cfg(test)]
            None,
        )
    }

    /// Records the actual Release-publication boundary around the same
    /// private pending token. The trace remains a caller-stack borrow and is
    /// never retained in this token or the returned owner.
    #[cfg(test)]
    #[inline]
    fn publish_with_static_first_trace(
        self,
        trace: &mut StaticFirstTldCreateTrace,
    ) -> MainStaticThreadLocalData {
        self.publish_impl(Some(trace))
    }

    #[inline]
    fn publish_impl(
        self,
        #[cfg(test)] mut trace: Option<&mut StaticFirstTldCreateTrace>,
    ) -> MainStaticThreadLocalData {
        // This final Release store is deliberately after the caller has
        // consumed its ticket into the one live-count lease.
        self.subprocess
            .main_tld_state
            .store(MAIN_TLD_LIVE, Ordering::Release);
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            // Keep the test-only scalar event immediately adjacent to the
            // one production Release store above. It has no callback,
            // allocation, fallible path, or ownership effect.
            trace.record_release_publication();
        }
        MainStaticThreadLocalData {
            subprocess: self.subprocess,
            pointer: self.pointer,
        }
    }
}

impl MainStaticThreadLocalData {
    /// Projects the vanished initial TLD under sole-child source authority.
    ///
    /// # Safety
    /// The initial thread cannot resume, every old TLD observation has ended,
    /// and the exact static storage remains pinned. This does not claim the
    /// caller has the initial thread's TLS identity or change survivor roots.
    pub(crate) unsafe fn vanished_initial_mut(&mut self) -> &mut ThreadLocalData {
        unsafe { self.pointer.as_mut() }
    }

    #[inline]
    pub(crate) fn current_mut(&mut self) -> &mut ThreadLocalData {
        // SAFETY: only the ticket-zero owner constructs this projection. Its
        // `!Send` parent owner keeps all access current-thread exclusive until
        // the source-ordered teardown retires this static slot.
        unsafe { self.pointer.as_mut() }
    }

    #[inline]
    pub(crate) fn retire(self) {
        self.subprocess.retire_main_tld(self.pointer);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticTldError {
    NotFirstTicket,
    AlreadyUsed,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn process_metadata_allocator_is_owned_by_the_static_main_subprocess() {
        let subprocess = MainSubprocess::global();
        let owned = subprocess.metadata_allocator();
        let global = crate::meta::MetaAllocator::global();
        assert!(core::ptr::eq(owned.get_ref(), global.get_ref()));
    }

    #[test]
    fn ticket_issues_old_relaxed_sequence_and_only_a_lease_changes_live_count() {
        let main = MainSubprocess::test_static_owner();
        let first = main.issue_generic_thread_ticket().unwrap();
        let second = main.issue_generic_thread_ticket().unwrap();

        assert_eq!(first.sequence().get(), 0);
        assert_eq!(second.sequence().get(), 1);
        assert_eq!(main.total_thread_count(), 2);
        assert_eq!(main.live_thread_count(), 0);

        let ticket = main.issue_generic_thread_ticket().unwrap();
        let mut image = ThreadLocalData::normal_tld_init_preimage();
        // SAFETY: this test owns a fresh local TLD image and names the exact
        // fixture subprocess/ticket before it becomes observable.
        unsafe {
            image.initialize_subprocess_attached_no_theap(
                LiveThreadId::new(12).unwrap(),
                ticket.sequence(),
                0,
                main,
                MemoryId::static_kind_only(),
            );
        }
        // SAFETY: `image` was initialized immediately above from this exact
        // ticket, thread identity, sequence, and subprocess fixture.
        let lease = unsafe {
            ticket.activate_after_initialized_tld(&image, LiveThreadId::new(12).unwrap())
        };
        assert_eq!(main.live_thread_count(), 1);
        lease.release();
        assert_eq!(main.live_thread_count(), 0);
    }

    #[test]
    fn normal_tld_init_direct_preimage_refuses_busy_lock_then_registers_sequence_seven() {
        let direct = MainSubprocess::test_static_owner();
        for expected_sequence in 0..7 {
            let prior = direct
                .issue_generic_thread_ticket()
                .expect("the direct helper fixture seeds prior source tickets");
            assert_eq!(prior.sequence().get(), expected_sequence);
            drop(prior);
        }
        let ticket = direct
            .issue_generic_thread_ticket()
            .expect("the eighth source-style ticket has sequence seven");
        assert_eq!(ticket.sequence().get(), 7);
        assert_eq!(direct.total_thread_count(), 8);
        assert_eq!(direct.live_thread_count(), 0);

        let thread = LiveThreadId::new(0x40).expect("the fixture uses a live aligned identity");
        let mut busy = ThreadLocalData::normal_tld_init_preimage();
        assert!(busy.test_matches_normal_tld_init_minimal_preimage_except_lock());
        busy.test_inject_busy_theaps_lock();
        let ticket = match ticket.initialize_normal_tld_after_direct_preimage(
            &mut busy,
            thread,
            3,
        ) {
            Ok(_) => panic!("a busy normal TLD lock must refuse before registration"),
            Err(ticket) => ticket,
        };
        assert!(
            busy.test_matches_normal_tld_init_minimal_preimage_except_lock(),
            "the busy preflight leaves every non-lock direct-preimage field unchanged"
        );
        assert!(busy.test_theap_head_is(core::ptr::null_mut()));
        assert!(
            !busy.test_theaps_lock_starts_and_restores_unlocked(),
            "refusal retains the injected busy lock rather than resetting it"
        );
        assert_eq!(direct.total_thread_count(), 8);
        assert_eq!(direct.live_thread_count(), 0);

        // `MemoryId::none()` is the deliberately minimal direct-helper seam:
        // this seq=7 fixture proves `mi_tld_init` leaves caller-owned
        // provenance unchanged, not a static/main caller predecessor.
        let mut accepted = ThreadLocalData::normal_tld_init_preimage();
        let mut trace = NormalTldInitWriteTrace::new();
        let registration = match ticket.test_initialize_normal_tld_after_direct_preimage(
            &mut accepted,
            thread,
            3,
            &mut trace,
        ) {
            Ok(registration) => registration,
            Err(_) => panic!("the fresh direct normal TLD preimage must initialize"),
        };
        assert!(trace.has_exact_source_order());
        assert!(trace.modeled_field_writes_are_ordered());
        assert_eq!(accepted.thread_id(), thread.get());
        assert_eq!(accepted.thread_sequence().get(), 7);
        assert_eq!(accepted.numa_node(), 3);
        assert!(accepted.is_attached_to_main_subprocess(direct));
        assert!(accepted.is_subprocess_attached_no_theap());
        assert!(!accepted.is_in_threadpool());
        assert!(accepted.test_theaps_lock_starts_and_restores_unlocked());
        assert!(accepted.test_memory_id_is_none());
        assert_eq!(direct.total_thread_count(), 8);
        assert_eq!(direct.live_thread_count(), 1);
        registration.release();
        assert_eq!(direct.live_thread_count(), 0);
    }

    #[test]
    fn emit_m2_normal_tld_direct_c_rust_trace() {
        // This is one direct normal `mi_tld_init` helper fixture for pinned
        // `src/init.c:236-250`: a fresh all-zero-shaped TLD/subprocess
        // preimage plus a caller-owned post-ticket context (total=8, seq=7).
        // It is not `mi_tld_create`, static-main construction, metadata
        // allocation, `_mi_subproc_main_init`, Theap/list/TLS/root
        // publication, or teardown. `MemoryId::none()` is deliberately left
        // unchanged because this helper neither reads nor writes provenance.
        // Rust receives an already-validated `LiveThreadId` at its outer
        // safety boundary; its event trace proves modeled field/counter order,
        // not literal timing parity for C's thread-ID primitive invocation.
        macro_rules! record {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value as usize);
            };
        }

        let subprocess = MainSubprocess::test_static_owner();
        let mut tld = ThreadLocalData::normal_tld_init_preimage();
        for expected_sequence in 0..7 {
            let prior = subprocess
                .issue_generic_thread_ticket()
                .expect("the direct fixture seeds source tickets zero through six");
            assert_eq!(prior.sequence().get(), expected_sequence);
            drop(prior);
        }
        let ticket = subprocess
            .issue_generic_thread_ticket()
            .expect("the direct fixture retains source ticket sequence seven");
        assert_eq!(ticket.sequence().get(), 7);

        let thread = LiveThreadId::new(0x40).expect("the fixture uses one live identity");
        let threadpool_source = false;
        let pre_thread_id_abandoned = tld.thread_id() == crate::types::THREAD_ID_ABANDONED;
        let pre_thread_sequence_zero = tld.thread_sequence().get() == 0;
        let pre_numa_node_zero = tld.numa_node() == 0;
        let pre_subprocess_null = tld.test_subprocess_is_null();
        let pre_theap_head_null = tld.test_theap_head_is(core::ptr::null_mut());
        let pre_recurse_false = !tld.recursing();
        let pre_threadpool_false = !tld.is_in_threadpool();
        let pre_memid_none = tld.test_memory_id_is_none();
        let pre_total_thread_count_eight = subprocess.total_thread_count() == 8;
        let pre_live_thread_count_zero = subprocess.live_thread_count() == 0;

        assert!(pre_thread_id_abandoned);
        assert!(pre_thread_sequence_zero);
        assert!(pre_numa_node_zero);
        assert!(pre_subprocess_null);
        assert!(pre_theap_head_null);
        assert!(pre_recurse_false);
        assert!(pre_threadpool_false);
        assert!(pre_memid_none);
        assert!(pre_total_thread_count_eight);
        assert!(pre_live_thread_count_zero);

        let mut trace = NormalTldInitWriteTrace::new();
        let input_tld = core::ptr::from_mut(&mut tld);
        let registration = match ticket.test_initialize_normal_tld_after_direct_preimage(
            &mut tld,
            thread,
            3,
            &mut trace,
        ) {
            Ok(registration) => registration,
            Err(_) => panic!("the fresh direct normal preimage accepts the retained ticket"),
        };

        // C checks `mi_tld_init` returned its input; the Rust operation returns
        // a lease, so this neutral relation instead proves its same in-place
        // input identity without claiming a Rust TLD-reference return value.
        let post_input_identity_preserved = core::ptr::eq(input_tld, core::ptr::from_mut(&mut tld));
        let post_subprocess_matches_input = tld.is_attached_to_main_subprocess(subprocess);
        let post_theap_head_null = tld.test_theap_head_is(core::ptr::null_mut());
        let post_lock_roundtrip = tld.test_theaps_lock_starts_and_restores_unlocked();
        let post_numa_node_injected_three = tld.numa_node() == 3;
        let post_thread_id_matches_input = tld.thread_id() == thread.get();
        let post_thread_id_live = LiveThreadId::new(tld.thread_id()).is_some();
        let post_threadpool_matches_input = tld.is_in_threadpool() == threadpool_source;
        let post_threadpool_false = !tld.is_in_threadpool();
        let post_thread_sequence_matches_input = tld.thread_sequence().get() == 7;
        let post_recurse_false = !tld.recursing();
        let post_memid_none = tld.test_memory_id_is_none();
        let post_total_thread_count_eight = subprocess.total_thread_count() == 8;
        let post_total_thread_count_unchanged = subprocess.total_thread_count() == 8;
        let post_live_thread_count_one = subprocess.live_thread_count() == 1;
        let post_live_thread_count_incremented = subprocess.live_thread_count() == 1;
        let modeled_source_order = trace.has_exact_source_order();
        let modeled_observable_effect_order = trace.has_modeled_observable_source_effect_order();

        assert!(post_input_identity_preserved);
        assert!(post_subprocess_matches_input);
        assert!(post_theap_head_null);
        assert!(post_lock_roundtrip);
        assert!(post_numa_node_injected_three);
        assert!(post_thread_id_matches_input);
        assert!(post_thread_id_live);
        assert!(post_threadpool_matches_input);
        assert!(post_threadpool_false);
        assert!(post_thread_sequence_matches_input);
        assert!(post_recurse_false);
        assert!(post_memid_none);
        assert!(post_total_thread_count_eight);
        assert!(post_total_thread_count_unchanged);
        assert!(post_live_thread_count_one);
        assert!(post_live_thread_count_incremented);
        assert!(modeled_source_order);
        assert!(modeled_observable_effect_order);

        std::println!("CRABC_MI_M2_NORMAL_TLD_DIRECT_TRACE_BEGIN");
        record!(
            "m2.initialization.normal_tld.pre.thread_id_abandoned",
            pre_thread_id_abandoned
        );
        record!(
            "m2.initialization.normal_tld.pre.thread_sequence_zero",
            pre_thread_sequence_zero
        );
        record!(
            "m2.initialization.normal_tld.pre.numa_node_zero",
            pre_numa_node_zero
        );
        record!(
            "m2.initialization.normal_tld.pre.subprocess_null",
            pre_subprocess_null
        );
        record!(
            "m2.initialization.normal_tld.pre.theap_head_null",
            pre_theap_head_null
        );
        record!(
            "m2.initialization.normal_tld.pre.recurse_false",
            pre_recurse_false
        );
        record!(
            "m2.initialization.normal_tld.pre.threadpool_false",
            pre_threadpool_false
        );
        record!("m2.initialization.normal_tld.pre.memid_none", pre_memid_none);
        record!(
            "m2.initialization.normal_tld.pre.total_thread_count_eight",
            pre_total_thread_count_eight
        );
        record!(
            "m2.initialization.normal_tld.pre.live_thread_count_zero",
            pre_live_thread_count_zero
        );
        record!(
            "m2.initialization.normal_tld.post.input_identity_preserved",
            post_input_identity_preserved
        );
        record!(
            "m2.initialization.normal_tld.post.subprocess_matches_input",
            post_subprocess_matches_input
        );
        record!(
            "m2.initialization.normal_tld.post.theap_head_null",
            post_theap_head_null
        );
        record!(
            "m2.initialization.normal_tld.post.lock_roundtrip",
            post_lock_roundtrip
        );
        record!(
            "m2.initialization.normal_tld.post.numa_node_injected_three",
            post_numa_node_injected_three
        );
        record!(
            "m2.initialization.normal_tld.post.thread_id_matches_input",
            post_thread_id_matches_input
        );
        record!(
            "m2.initialization.normal_tld.post.thread_id_live",
            post_thread_id_live
        );
        record!(
            "m2.initialization.normal_tld.post.threadpool_matches_input",
            post_threadpool_matches_input
        );
        record!(
            "m2.initialization.normal_tld.post.threadpool_false",
            post_threadpool_false
        );
        record!(
            "m2.initialization.normal_tld.post.thread_sequence_matches_input",
            post_thread_sequence_matches_input
        );
        record!(
            "m2.initialization.normal_tld.post.recurse_false",
            post_recurse_false
        );
        record!("m2.initialization.normal_tld.post.memid_none", post_memid_none);
        record!(
            "m2.initialization.normal_tld.post.total_thread_count_eight",
            post_total_thread_count_eight
        );
        record!(
            "m2.initialization.normal_tld.post.total_thread_count_unchanged",
            post_total_thread_count_unchanged
        );
        record!(
            "m2.initialization.normal_tld.post.live_thread_count_one",
            post_live_thread_count_one
        );
        record!(
            "m2.initialization.normal_tld.post.live_thread_count_incremented",
            post_live_thread_count_incremented
        );
        record!(
            "m2.initialization.normal_tld.order.lock_before_numa",
            modeled_observable_effect_order
        );
        record!(
            "m2.initialization.normal_tld.order.numa_before_thread_id",
            modeled_observable_effect_order
        );
        record!(
            "m2.initialization.normal_tld.order.thread_id_before_threadpool",
            modeled_observable_effect_order
        );
        record!(
            "m2.initialization.normal_tld.order.threadpool_before_live_increment",
            modeled_observable_effect_order
        );
        record!(
            "m2.initialization.normal_tld.order.exactly_five_observable_effects",
            modeled_observable_effect_order
        );
        std::println!("CRABC_MI_M2_NORMAL_TLD_DIRECT_TRACE_END");

        registration.release();
        assert_eq!(subprocess.live_thread_count(), 0);
    }

    #[test]
    fn later_ticket_gate_never_consumes_the_reserved_static_zero_sequence() {
        let main = MainSubprocess::test_static_owner();
        assert!(matches!(
            main.issue_later_thread_ticket(),
            Err(LaterThreadTicketError::FirstTicketReserved)
        ));
        assert_eq!(main.total_thread_count(), 0);

        let first = main.issue_generic_thread_ticket().unwrap();
        assert_eq!(first.sequence().get(), 0);
        let later = main
            .issue_later_thread_ticket()
            .expect("a consumed static ticket permits exactly the next later sequence");
        assert_eq!(later.sequence().get(), 1);
        assert_eq!(main.total_thread_count(), 2);
        assert_eq!(main.live_thread_count(), 0);
    }

    #[test]
    fn selected_static_bootstrap_blocks_generic_ticket_zero_until_it_completes_or_retains() {
        let main = MainSubprocess::test_static_owner();
        let mut selection = main
            .reserve_static_bootstrap()
            .expect("the cold subprocess selects its static branch");
        assert!(matches!(
            main.issue_generic_thread_ticket(),
            Err(GenericThreadTicketError::StaticBootstrapSelecting)
        ));
        assert_eq!(main.total_thread_count(), 0);

        selection.commit_heap_foundation();
        let ticket = selection
            .issue_first_ticket()
            .expect("the selected branch alone consumes sequence zero");
        assert_eq!(ticket.sequence().get(), 0);
        assert!(matches!(
            main.issue_generic_thread_ticket(),
            Err(GenericThreadTicketError::StaticBootstrapSelecting)
        ));
        drop(selection);
        assert!(matches!(
            main.issue_generic_thread_ticket(),
            Err(GenericThreadTicketError::BootstrapRetained)
        ));
        assert_eq!(main.total_thread_count(), 1);
    }

    #[test]
    fn selected_static_bootstrap_cannot_issue_ticket_zero_before_heap_foundation() {
        let main = MainSubprocess::test_static_owner();
        let mut selection = main
            .reserve_static_bootstrap()
            .expect("the cold subprocess selects its static branch");

        assert!(
            matches!(
                selection.issue_first_ticket(),
                Err(MainStaticBootstrapSelectionError::HeapFoundationNotCommitted)
            ),
            "ticket zero remains behind the source static-Heap foundation"
        );
        assert_eq!(main.total_thread_count(), 0);
        drop(selection);

        let generic = main
            .issue_generic_thread_ticket()
            .expect("a pre-foundation selection failure leaves the subprocess cold");
        assert_eq!(generic.sequence().get(), 0);
    }

    #[test]
    fn main_heap_reservation_retains_static_selection_before_foundation_commit() {
        let main = MainSubprocess::test_static_owner();
        let mut selection = main
            .reserve_static_bootstrap()
            .expect("the cold subprocess selects its static branch");
        let heap = std::boxed::Box::leak(std::boxed::Box::new(Heap::bootstrap_empty()));
        let heap_identity = NonNull::from(&mut *heap);

        // SAFETY: this test owns the selected branch and deliberately keeps
        // its incomplete source main-Heap transition retained. The leaked
        // image stands in for the final process-static candidate bound by the
        // reservation before any Heap mutation.
        let reservation = unsafe { main.begin_main_heap_publication(heap_identity) }
            .expect("the selected branch reserves its only main-Heap transition");
        drop(reservation);
        selection.retain_after_main_heap_reservation();
        drop(selection);

        assert_eq!(
            main.main_heap_publication_state(),
            MainHeapPublicationState::Reserved
        );
        assert!(matches!(
            unsafe { main.begin_main_heap_publication(heap_identity) },
            Err(MainHeapPublicationError::Reserved)
        ));
        assert!(matches!(
            main.issue_generic_thread_ticket(),
            Err(GenericThreadTicketError::BootstrapRetained)
        ));
        assert_eq!(main.total_thread_count(), 0);
    }

    #[test]
    fn main_heap_identity_publication_is_one_way_and_owner_bound() {
        let main = MainSubprocess::test_static_owner();
        let foreign = MainSubprocess::test_static_owner();
        let heap = std::boxed::Box::leak(std::boxed::Box::new(Heap::bootstrap_empty()));

        assert_eq!(
            main.main_heap_publication_state(),
            MainHeapPublicationState::Absent
        );
        assert_eq!(
            main.ready_main_heap_identity(),
            Err(MainHeapReadyLookupError::Absent)
        );

        // SAFETY: this test owns the selected source-main transition and
        // keeps the process image retained if it does not complete it.
        let heap_identity = NonNull::from(&mut *heap);
        let reservation = unsafe { main.begin_main_heap_publication(heap_identity) }
            .expect("the cold source subprocess admits its canonical heap transition");
        assert_eq!(
            main.main_heap_publication_state(),
            MainHeapPublicationState::Reserved
        );
        assert_eq!(
            main.ready_main_heap_identity(),
            Err(MainHeapReadyLookupError::Reserved)
        );
        assert!(
            heap.prepare_main_static_kind_only_memid(),
            "the final bootstrap Heap accepts only source kind-only provenance"
        );
        let prepared_fields = heap.test_main_static_fields();
        assert_eq!(prepared_fields.memid.kind(), crate::types::MemoryKind::Static);
        let prepared_memory = prepared_fields
            .memid
            .static_memory()
            .expect("kind-only static provenance selects the static union");
        assert!(prepared_memory.base.is_null());
        assert_eq!(prepared_memory.size, 0);
        assert!(!prepared_fields.memid.is_pinned());
        assert!(!prepared_fields.memid.initially_committed());
        assert!(!prepared_fields.memid.initially_zero());
        assert_eq!(prepared_fields.heap_seq, 0);
        assert_eq!(prepared_fields.theap_slot, 0);

        // SAFETY: this leaked test slot represents a process-lifetime static
        // address. Its previously bound identity has line-196 kind-only
        // provenance and remains exclusive until the remaining source
        // initialization completes.
        let mut publication = unsafe { main.publish_main_heap_identity(reservation) }
        .expect("the reserved subprocess releases its exact canonical Heap identity");
        assert_eq!(
            main.main_heap_publication_state(),
            MainHeapPublicationState::Publishing
        );
        assert_eq!(
            main.ready_main_heap_identity(),
            Err(MainHeapReadyLookupError::Publishing)
        );

        // SAFETY: the foreign-owner call is intentionally invalid only at
        // the identity boundary; it cannot dereference either heap slot.
        assert_eq!(
            unsafe { foreign.finish_main_heap_publication(&mut publication) },
            Err(MainHeapPublicationError::ForeignSubprocess)
        );
        assert_eq!(
            foreign.main_heap_publication_state(),
            MainHeapPublicationState::Absent,
            "a foreign completion cannot claim or overwrite its own slot"
        );
        assert_eq!(
            main.main_heap_publication_state(),
            MainHeapPublicationState::Publishing,
            "a foreign completion cannot change the source publication"
        );

        assert!(
            unsafe { heap.initialize_main_static_after_kind_only_memid(main) }.is_ok(),
            "the remaining source heap initializer preserves prepared provenance"
        );
        // SAFETY: the leaked static test image is initialized before the
        // ready identity becomes visible.
        let ready = unsafe { main.finish_main_heap_publication(&mut publication) }
            .expect("the owning subprocess completes its publication");
        assert!(ready.matches(heap_identity));
        assert_eq!(
            main.main_heap_publication_state(),
            MainHeapPublicationState::Ready
        );
        assert_eq!(
            main.ready_main_heap_identity(),
            Ok(ready),
            "an Acquire lookup retains the exact ready identity"
        );

        // SAFETY: this is a deliberately stale completion token. It owns no
        // dereference capability and must not alter the ready publication.
        assert_eq!(
            unsafe { main.finish_main_heap_publication(&mut publication) },
            Err(MainHeapPublicationError::StalePublication)
        );
        // SAFETY: a second reservation must not overwrite the already-ready
        // source identity.
        assert!(matches!(
            unsafe { main.begin_main_heap_publication(heap_identity) },
            Err(MainHeapPublicationError::AlreadyReady)
        ));
        assert_eq!(main.ready_main_heap_identity(), Ok(ready));
    }

    #[test]
    fn dropping_unfinished_main_heap_publication_retains_publishing() {
        let main = MainSubprocess::test_static_owner();
        let heap = std::boxed::Box::leak(std::boxed::Box::new(Heap::bootstrap_empty()));

        // SAFETY: this test exclusively owns the selected main-Heap branch
        // and deliberately verifies its retained incomplete outcome.
        let heap_identity = NonNull::from(&mut *heap);
        let reservation = unsafe { main.begin_main_heap_publication(heap_identity) }
            .expect("the cold subprocess reserves its only main-Heap transition");
        assert!(heap.prepare_main_static_kind_only_memid());
        // SAFETY: the leaked process-lifetime test slot has the required
        // kind-only memid before its bound exact identity is Release-published.
        let publication = unsafe { main.publish_main_heap_identity(reservation) }
            .expect("the reserved subprocess publishes the exact test identity");
        drop(publication);

        assert_eq!(
            main.main_heap_publication_state(),
            MainHeapPublicationState::Publishing,
            "dropping a pointer-bearing publication cannot reopen or erase it"
        );
        assert_eq!(
            main.ready_main_heap_identity(),
            Err(MainHeapReadyLookupError::Publishing),
            "an unfinished published identity never becomes a ready Heap capability"
        );
        // SAFETY: this is deliberately a second source-main admission attempt
        // after the original token was dropped retained.
        assert!(
            matches!(
                unsafe { main.begin_main_heap_publication(heap_identity) },
                Err(MainHeapPublicationError::Publishing)
            ),
            "a retained publication rejects a second owner without mutation"
        );
    }
}

#[path = "subproc_registry.rs"]
pub(crate) mod registry;
#[path = "subproc_lifecycle.rs"]
pub(crate) mod lifecycle;
