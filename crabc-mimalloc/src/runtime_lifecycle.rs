// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license is included in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:236-282,305-360,377-421,
// 448-481`, `src/theap.c:228-306,414-449`, `src/threadlocal.c:205-214`,
// `src/free.c:152-233,372-418,479-515`, and `src/prim/unix/prim.c:943-974`; the
// direct libc fork placement follows pinned musl 1.2.6 `src/process/fork.c`.

//! Private crabc-runtime lifecycle bridge.
//!
//! This module is the one direct Rust boundary used by `crabc-libc` while the
//! C mimalloc backend remains the production allocator. It retains the
//! source-shaped ticket-zero `ProcessMainThread` and the main-thread-minted
//! `MainStaticHeapLease` for the process lifetime, then places one no-page
//! `MainHeapThreadAttachment` in compiler TLS for each pthread worker that
//! successfully enters through the runtime. An ordinary later-thread native
//! allocation promotes that attachment once into an inline compiler-TLS owner
//! containing the attachment and continuously stored owner-local page engine;
//! later local calls use short in-place borrows and never park or resume it.
//! The worker consumes that owner only after libc has run user cleanup handlers
//! and pthread TSD destructors. Older typed post-exit fixtures retain their
//! bounded dormant ticket-zero scheduler routes until pointer-first abandoned
//! dispatch owns the complete replacement capability.
//!
//! It exposes no C symbol, does not select a backend, creates no public pthread
//! key, and claims no general fork recovery. A failed process setup leaves
//! this shadow lifecycle unavailable and preserves the C backend. A failed
//! worker attachment prevents that
//! worker's start routine from running; libc performs the parent/child startup
//! handshake. On libc's prepared `fork` path, only the original ticket-zero
//! TLS image with no live or retained later bridge owner preserves the copied
//! no-page process owner. Every other child disables this incomplete lifecycle
//! without traversing inherited locks, roots, or page state.

use core::cell::UnsafeCell;
use core::convert::Infallible;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use crate::compiler_tls::current_thread_identity;
use crate::config::{
    LARGE_MAX_OBJ_SIZE, MEDIUM_MAX_OBJ_SIZE, MEDIUM_PAGE_SIZE, SMALL_MAX_OBJ_SIZE,
    SMALL_PAGE_SIZE, SMALL_SIZE_MAX,
};
use crate::main_heap_thread::{
    MainHeapThreadAttachment, MainHeapThreadAttachmentBeginError,
    MainHeapThreadAttachmentError, MainHeapThreadPageSessionError,
};
use crate::main_heap_page::{
    MainHeapThreadOwnerLocalAllocator, MainHeapThreadOwnerLocalPageEngine,
    MainHeapThreadOwnerLocalPageEngineBeginError,
    MainHeapThreadPausedProcessPageAllocator,
    MainHeapThreadPausedProcessPageAllocatorResumeFailure,
    MainHeapThreadPersistentPageEngineTerminal,
    MainHeapThreadProcessPageAllocator,
    MainHeapThreadProcessPageAllocatorBeginError,
    MainHeapThreadProcessPageExitDrainFailure,
    MainHeapThreadProcessPageAllocatorFinishError,
    MainHeapThreadProcessPageAllocatorSuspendFailure,
    MainHeapThreadProcessPageExitMappedRegularAdoptFailure,
    MainHeapThreadProcessPageExitMappedRegularFreeFailure,
    MainHeapThreadProcessPageExitMappedRegularFreeResult,
    MainHeapThreadProcessPageExitMappedRegularRoute,
    MainHeapThreadProcessPageExitMappedRegularPagesAdoptFailure,
    MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure,
    MainHeapThreadProcessPageExitMappedRegularPagesFreeResult,
    MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin,
    MainHeapThreadProcessPageExitMappedRegularPagesRoute,
};
use crate::main_static_page::MainStaticRuntimeFirstArenaPageAllocator;
use crate::main_theap::MainStaticHeapLease;
use crate::meta::{MetaAllocation, MetaAllocator};
use crate::os::{MemoryConfig, PageSize, StartupInput};
use crate::process_init::{ProcessMainInitializationStorage, ProcessMainThread};
use crate::process_arena::{
    ProcessPageArenaLease, ProcessPageArenaLeaseError, ProcessSharedArenaStorage,
};
use crate::process_page_map::{
    LiveAllocationPageState, LiveAllocationPointer, ProcessPageMapError, ProcessPageMapLease,
};
use crate::remote_free;
use crate::single_thread::{
    ProcessPostOwnerExitPointerFreeDisposition, ProcessPostOwnerExitPointerFreeRejection,
    RemoteFreeProducer, RemoteFreeProducerPair,
    ThreadExitKnownPostExitOsAbandonedList,
    ThreadExitMappedRegularPagesPostExitRemoteFreeProducer,
    ThreadExitMappedRegularPagesPostExitRemoteFreeProducerPair,
};
use crate::thread_local::{
    PersistentCompilerTlsOwnerCell, PersistentCompilerTlsOwnerError,
    PersistentCompilerTlsOwnerInitializeError, PersistentCompilerTlsOwnerTeardownError,
};
use crate::types::{LiveThreadId, Page};

const PROCESS_COLD: u8 = 0;
const PROCESS_INITIALIZING: u8 = 1;
const PROCESS_ACTIVE: u8 = 2;
const PROCESS_RETAINED: u8 = 3;

// A separate process-long owner state keeps the original no-page lifecycle
// intact until an internal ticket-zero request needs the first native page.
// `BUSY` closes one complete source PageMap mutation operation; it is not a
// general allocator lock. Every parked count represents that many distinct
// current-thread-only suspended engines, each of which released its long
// PageMap guard. The scheduler permits another complete operation only by
// claiming the one `BUSY` state, so multiple parked owners never imply
// concurrent mutation of plain PageMap entries.
const PAGE_OWNER_COLD: usize = 0;
const PAGE_OWNER_STARTING: usize = 1;
const PAGE_OWNER_READY: usize = 2;
const PAGE_OWNER_BUSY: usize = 3;
/// The process-static ticket-zero slot was moved into the initial thread's
/// compiler-TLS owner cell.  This is an ownership publication used only at
/// the one-time promotion boundary; ordinary initial local operations never
/// inspect or transition this word.
const PAGE_OWNER_INITIAL_PERSISTENT: usize = 4;
const PAGE_OWNER_PARKED_BASE: usize = 5;
/// Compatibility spelling for the first parked owner. Callers that need the
/// number of independently suspended engines use
/// [`page_owner_parked_count`] instead of treating this as one global route.
const PAGE_OWNER_PARKED: usize = PAGE_OWNER_PARKED_BASE;
const PAGE_OWNER_RETAINED: usize = usize::MAX;

/// Encodes a nonzero number of independently suspended normal engines.
///
/// Zero parked engines use the distinct `READY` state so ticket zero can
/// claim its permanent owner without a count conversion. `RETAINED` stays
/// outside the representable parked range, ensuring no arithmetic overflow
/// can make a terminal process look quiescent.
#[inline]
const fn page_owner_parked_state(count: usize) -> Option<usize> {
    if count == 0 {
        return Some(PAGE_OWNER_READY);
    }
    match PAGE_OWNER_PARKED_BASE.checked_add(count - 1) {
        Some(state) if state != PAGE_OWNER_RETAINED => Some(state),
        Some(_) | None => None,
    }
}

/// Decodes the quiescent or parked portion of the runtime scheduler.
///
/// `COLD`, `STARTING`, `BUSY`, `INITIAL_PERSISTENT`, and `RETAINED`
/// deliberately have no count: none represents a retryable collection of
/// suspended owner tokens.  In particular, the initial persistent owner is
/// not a parked compatibility engine that another thread may borrow.
#[inline]
const fn page_owner_parked_count(state: usize) -> Option<usize> {
    if state == PAGE_OWNER_READY {
        Some(0)
    } else if state >= PAGE_OWNER_PARKED_BASE && state != PAGE_OWNER_RETAINED {
        Some(state - PAGE_OWNER_PARKED_BASE + 1)
    } else {
        None
    }
}

/// A parked engine may lose the scheduler CAS because a peer just completed
/// or re-parked.  Both `BUSY` and any nonzero parked count still represent a
/// live, typed runtime transition; callers that retain their own parked token
/// may retry rather than treating that ordinary count change as terminal.
#[inline]
const fn page_owner_transition_is_retryable(state: usize) -> bool {
    state == PAGE_OWNER_BUSY
        || matches!(page_owner_parked_count(state), Some(parked_count) if parked_count > 0)
}

/// A worker creating its first session has not yet contributed a parked token.
/// If it misses the scheduler CAS while a peer completes, the next stable
/// observation may therefore be `READY`: that is an admission state for a
/// new engine, not evidence that this worker's ownership was lost. Existing
/// parked-session callers must continue to use
/// [`page_owner_transition_is_retryable`], which deliberately excludes
/// `READY` because their own token must remain represented by a nonzero count.
#[inline]
const fn page_owner_session_begin_is_retryable(state: usize) -> bool {
    state == PAGE_OWNER_BUSY || page_owner_parked_count(state).is_some()
}

// The native libc shadow keeps detached post-exit routes in a metadata-backed
// process registry. It is not a general allocator lock: each active entry
// owns one already-detached A route and serializes only that route's private
// ledger. The lower source `ProcessPageMapPostExitAccess` takes the shared
// PageMap exclusion around each complete exact free, while this private router
// never exposes a client or a page selection capability.
const NATIVE_POST_EXIT_ROUTE_EMPTY: u8 = 0;
const NATIVE_POST_EXIT_ROUTE_ACTIVE: u8 = 1;
const NATIVE_POST_EXIT_ROUTE_BUSY: u8 = 2;
const NATIVE_POST_EXIT_ROUTE_RETAINED: u8 = 3;
// A terminal source route has no remaining C client, but it still owns its
// exact parked scheduler token and A's worker-admission proof until the
// matched B attachment has completed its own normal teardown. Keeping that
// completion in the stable private registry lets one B carry more than one
// such boundary without turning client addresses into a cross-thread API.
const NATIVE_POST_EXIT_ROUTE_COMPLETED: u8 = 4;

// Appending one permanent metadata-backed registry entry is separate from an
// entry's own `ACTIVE -> BUSY` route serialization. Nodes never move or leave
// the list, so a reader that acquired the list head may inspect a stable entry
// without a raw-pointer lifetime race. An entry is reusable only after its
// active route or completed B lifecycle has fully released. The short registry
// mutation word serializes installation with terminal closure: once any route
// is retained, a later detached A may not publish beside it.
const NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE: u8 = 0;
const NATIVE_POST_EXIT_ROUTE_REGISTRY_MUTATING: u8 = 1;
const NATIVE_POST_EXIT_ROUTE_REGISTRY_RETAINED: u8 = 2;

// Native live-owner remote frees use metadata-backed entries, not a
// process-wide client table. Every entry stores only one A compiler-TLS slot
// and generation; an exact C address remains private in that A session ledger
// until B has atomically published it to the source page. Empty entries are
// reusable while their backing metadata stays process-lived, so concurrent A
// owners have no fixed cardinality cap and sequential workers reuse the
// observed high-water instead of accumulating a new raw-TLS handoff each time.
const NATIVE_LIVE_REMOTE_OWNER_EMPTY: u8 = 0;
const NATIVE_LIVE_REMOTE_OWNER_ACTIVE: u8 = 1;
const NATIVE_LIVE_REMOTE_OWNER_BUSY: u8 = 2;
const NATIVE_LIVE_REMOTE_OWNER_RETAINED: u8 = 3;

// Appending one stable live-owner entry is separate from claiming that entry
// for a source-shaped B operation. Readers may scan the append-only list
// without exposing a client or node identity. The short registry mutation word
// serializes installation with terminal closure, while ordinary PageMap work
// and a different entry's `ACTIVE -> BUSY` transition stay independent.
const NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE: u8 = 0;
const NATIVE_LIVE_REMOTE_OWNER_REGISTRY_MUTATING: u8 = 1;
const NATIVE_LIVE_REMOTE_OWNER_REGISTRY_RETAINED: u8 = 2;

// Linux/AArch64's public C allocation ABI guarantees 16-byte natural malloc
// alignment. A request at or below this boundary remains an ordinary native
// allocation in the private ledger; only a wider request takes the aligned
// path, whose interior/base geometry cannot safely name a later normal queue.
const NATIVE_C_MALLOC_ALIGNMENT: usize = 16;

// The source full-medium witness uses the established 64 KiB regular-medium
// request from the source-shaped full-page fixtures. Its rounded block stays
// below `MEDIUM_MAX_OBJ_SIZE` and its fixed page has only a small bounded
// number of clients. `good_size` may round the request upward, never
// downward, so this is a conservative stack-only bound rather than a second
// page-shape policy.
// Keep both source small-page classes in the one mixed Theap: 37 lands in
// the direct cache range, while `SMALL_SIZE_MAX + 1` remains a small page but
// has no direct-cache slot. Neither class gets its own owner-exit entry.
// The existing direct-small member supplies the one direct post-exit source
// free plus two same-page atomic publishers. Keeping all three clients in the
// already-covered direct-cache source page exercises the upstream multi-push
// remote-head transition without introducing a new page geometry.
const OWNER_EXIT_DIRECT_SMALL_CLIENT_SLOTS: usize = 3;
const OWNER_EXIT_NON_DIRECT_SMALL_CLIENT_SLOTS: usize = 1;
const OWNER_EXIT_NON_DIRECT_SMALL_REQUEST: usize = SMALL_SIZE_MAX + 1;
const OWNER_EXIT_FULL_MEDIUM_REQUEST: usize = 64 * 1024;
const OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS: usize =
    MEDIUM_PAGE_SIZE / OWNER_EXIT_FULL_MEDIUM_REQUEST;
// Keep the force-empty large page in a distinct source bin from the live
// large member below. Its one remote client lets the existing aggregate
// traversal prove the required page-empty-during-exit branch without turning
// this runtime witness into a separate geometry-specific route.
const OWNER_EXIT_FORCE_EMPTY_LARGE_REQUEST: usize = MEDIUM_MAX_OBJ_SIZE + 1;
const OWNER_EXIT_PRE_EXIT_REMOTE_CLIENT_SLOTS: usize = 2;
const OWNER_EXIT_LIVE_LARGE_REQUEST: usize = MEDIUM_MAX_OBJ_SIZE + 64 * 1024;
const OWNER_EXIT_LIVE_LARGE_CLIENT_SLOTS: usize = 2;
// Keep one live arena singleton in the same aggregate coordinator. This is
// deliberately a normal unaligned request just above the regular-large range:
// source owner exit must retain its PageMap-only terminal tail until B frees
// its one opaque client, unlike the force-empty large member above.
const OWNER_EXIT_ARENA_SINGLETON_REQUEST: usize = LARGE_MAX_OBJ_SIZE + 1;
// This stays inside the source's OS-aligned singleton profile while crossing
// the `MI_SMALL_MAX_OBJ_SIZE` boundary that moves a full singleton from
// `BIN_HUGE` to `BIN_FULL`. Its 128 KiB alignment exceeds the in-arena path
// and remains below the 256 MiB metadata-alignment ceiling.
const OWNER_EXIT_OS_SINGLETON_REQUEST: usize = SMALL_MAX_OBJ_SIZE + 1;
const OWNER_EXIT_OS_SINGLETON_ALIGNMENT: usize = 128 * 1024;
// This has the same source-rounded medium geometry as the mixed owner-exit
// witness, but it returns one local free after two live clients. The source
// owner-exit collector transfers that deferred block into the immediate head
// required by the existing sole-medium adoption route.
const OWNER_EXIT_RECLAIM_MEDIUM_REQUEST: usize = OWNER_EXIT_FULL_MEDIUM_REQUEST;
// This request stays inside the source direct-cache range. The direct-small
// predecessor below validates its complete rounded cache image through the
// existing specialized source drain; it is deliberately not reclassified as
// a `SoleImmediateMedium` aggregate result.
const OWNER_EXIT_RECLAIM_DIRECT_SMALL_REQUEST: usize = 37;
const OWNER_EXIT_RECLAIM_CLIENT_SLOTS: usize = 2;
const OWNER_EXIT_NON_DIRECT_SMALL_START: usize = OWNER_EXIT_DIRECT_SMALL_CLIENT_SLOTS;
const OWNER_EXIT_LIVE_LARGE_START: usize =
    OWNER_EXIT_NON_DIRECT_SMALL_START + OWNER_EXIT_NON_DIRECT_SMALL_CLIENT_SLOTS;
const OWNER_EXIT_MAPPED_MEDIUM_START: usize =
    OWNER_EXIT_LIVE_LARGE_START + OWNER_EXIT_LIVE_LARGE_CLIENT_SLOTS;
const OWNER_EXIT_UNMAPPED_FULL_MEDIUM_START: usize =
    OWNER_EXIT_MAPPED_MEDIUM_START + (OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS - 1);
// The third medium begins full, then A locally frees one exact client before
// owner exit. Its remaining clients therefore reach the general aggregate as
// an initially mapped, non-full regular member, distinct from both the
// pre-exit-normalized and source-unmapped full-medium members above.
const OWNER_EXIT_INITIAL_MAPPED_MEDIUM_START: usize =
    OWNER_EXIT_UNMAPPED_FULL_MEDIUM_START + OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS;
const OWNER_EXIT_ARENA_SINGLETON_INDEX: usize =
    OWNER_EXIT_INITIAL_MAPPED_MEDIUM_START + (OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS - 1);
const OWNER_EXIT_OS_SINGLETON_INDEX: usize = OWNER_EXIT_ARENA_SINGLETON_INDEX + 1;
// This is the inline portion of the private client registry for the internal
// generic page-bearing TLS owner. It covers the largest source aggregate used
// by the focused owner-exit fixtures. Ordinary native sessions may grow a
// private metadata-backed overflow beyond it; client identity remains inside
// the session and never becomes a public registry or a routing capability.
const RUNTIME_PAGE_OWNER_PRIVATE_CLIENT_SLOTS: usize = OWNER_EXIT_OS_SINGLETON_INDEX + 1;
// Preparation sees the two pre-exit source clients before their joined remote
// publications. They are deliberately absent from the post-exit route after
// source collection, but the inline ledger must still account for them while
// A owns the live engine. Keep that source-fixture capacity separate from the
// B-side opaque-client array so neither identity can be forgotten nor
// accidentally handed to B twice.
const RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS: usize =
    RUNTIME_PAGE_OWNER_PRIVATE_CLIENT_SLOTS + OWNER_EXIT_PRE_EXIT_REMOTE_CLIENT_SLOTS;

// The production route has no branch-reporting surface: its only observable
// result is a terminal proof or retained owner. This test-only counter lets
// the mixed lifecycle regression prove it reached the aggregate final-member
// adoption transition rather than merely freeing its final page sequentially.
#[cfg(test)]
static AGGREGATE_LAST_MAPPED_REGULAR_ADOPTION_COUNT: AtomicUsize = AtomicUsize::new(0);

// This default-off counter is an execution witness for the Phase-B native
// owner-local seam.  It counts only successful operations that ran through
// the retained current-thread owner, after its initial attachment/setup
// transition; it is not a client ledger, scheduler, or routing capability.
#[cfg(feature = "native-runtime-test-audit")]
static NATIVE_OWNER_LOCAL_OPERATION_COUNT: AtomicUsize = AtomicUsize::new(0);

// This separate counter makes the Phase-B regression reject an implementation
// that merely renames the old parked-session bridge. It contains no pointer or
// owner identity and is sampled only after the participating worker joins.
#[cfg(feature = "native-runtime-test-audit")]
static NATIVE_PARKED_COMPATIBILITY_OPERATION_COUNT: AtomicUsize = AtomicUsize::new(0);

// This default-off monotonic audit records every successful entry into the
// legacy process page-owner scheduler (`COLD -> STARTING` or `* -> BUSY`). It
// exposes no state, token, or owner identity. A direct persistent worker owns
// its independently copied PageMap/arena pair and therefore must leave this
// count unchanged after ticket-zero preparation has established the baseline.
#[cfg(feature = "native-runtime-test-audit")]
static NATIVE_SCHEDULER_TRANSITION_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "native-runtime-test-audit")]
#[inline]
fn note_native_scheduler_transition() {
    NATIVE_SCHEDULER_TRANSITION_COUNT.fetch_add(1, Ordering::AcqRel);
}

/// Result of one private ticket-zero native allocation operation.
///
/// This is a Rust-only friend interface for future bounded integration tests;
/// it has no C ABI and does not select the libc allocation backend.
#[doc(hidden)]
pub enum TicketZeroPageAllocationResult {
    Allocated(core::ptr::NonNull<u8>),
    Unavailable,
    AllocationFailed,
    Retained,
}

/// Result of returning one exact private ticket-zero native allocation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketZeroPageFreeResult {
    Freed,
    Unavailable,
    InvalidPointer,
    Retained,
}

/// Result of one private native allocator operation selected by the
/// nondefault crabc-libc shadow backend.
///
/// The result deliberately names neither the ticket-zero implementation nor
/// a worker session. A returned block remains in the one current native owner
/// and must later re-enter this same friend boundary; it is never eligible for
/// C-mimalloc fallback. The current worker branch is intentionally bounded to
/// the existing parked TLS owner and its explicit client ledger while the
/// general M5 allocation/remote-free/owner-exit router is completed.
#[doc(hidden)]
pub enum NativePageAllocationResult {
    Allocated(core::ptr::NonNull<u8>),
    Unavailable,
    AllocationFailed,
    Retained,
}

/// Result of returning one private native-shadow allocation.
///
/// An invalid or foreign pointer stays distinct from an unavailable native
/// owner so the libc boundary can fail-stop rather than accidentally pass a
/// Rust-engine pointer to C mimalloc.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePageFreeResult {
    Freed,
    Unavailable,
    InvalidPointer,
    Retained,
}

/// Result of one private scoped later-worker page-engine round trip.
///
/// The operation is intentionally narrower than allocation routing: it
/// attaches the current worker, uses the ticket-zero owner's already-published
/// pair only while ticket zero is dormant, returns that engine empty, and
/// finishes the worker attachment. No pointer crosses the boundary.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketZeroLaterThreadPageResult {
    Completed,
    Unavailable,
    AllocationFailed,
    Retained,
}

/// One private, linear remote-free publication capability for a live later
/// worker page. It is only a friend-boundary wrapper around the source-shaped
/// engine token: it accepts no client pointer and exposes no allocator state.
///
/// The adapter may move it to exactly one joined pthread and call
/// [`Self::publish`]. If that operation cannot publish, it must return this
/// value to the runtime callback so the owner can cancel the transfer while it
/// still holds the exclusive engine lifecycle.
#[doc(hidden)]
#[must_use = "the remote-free publication must be published or returned to its runtime callback"]
pub struct TicketZeroRemoteFreeProducer<'owner> {
    producer: RemoteFreeProducer<'owner>,
}

impl<'owner> TicketZeroRemoteFreeProducer<'owner> {
    /// Publishes this one logical handoff to the live owner page's source
    /// remote-free head. It never exposes the transferred client pointer.
    #[inline]
    pub fn publish(self) -> Result<(), Self> {
        match self.producer.publish() {
            Ok(()) => Ok(()),
            Err((producer, _)) => Err(Self { producer }),
        }
    }

    #[inline]
    fn cancel(self) -> core::ptr::NonNull<u8> {
        self.producer.cancel()
    }

}

/// One opaque post-exit publication capability issued only after B has
/// claimed the source abandoned-page owner bit for its direct client free.
///
/// The runtime keeps every client identity private. A joined publisher receives
/// only this single-use producer, which may publish into B's already-owned
/// remote head; it cannot collect, reclaim, adopt, release, or retain the page
/// route.
#[doc(hidden)]
#[must_use = "the post-exit remote publication must publish or return its opaque producer"]
pub struct TicketZeroOwnerExitRemoteFreeProducer<'route> {
    producer: ThreadExitMappedRegularPagesPostExitRemoteFreeProducer<'route>,
}

// SAFETY: the wrapped source producer is Send and carries only the one
// already-proved private client plus the callback-local lifetime boundary.
// Moving it transfers no PageMap, route, or terminal-release authority.
unsafe impl Send for TicketZeroOwnerExitRemoteFreeProducer<'_> {}

impl<'route> TicketZeroOwnerExitRemoteFreeProducer<'route> {
    /// Atomically publishes one private client to B's held source remote
    /// head. A failure returns the same opaque capability, allowing the
    /// direct route to become terminal rather than pretending it published.
    #[inline]
    pub fn publish(self) -> Result<(), Self> {
        match self.producer.publish() {
            Ok(()) => Ok(()),
            Err(producer) => Err(Self { producer }),
        }
    }
}

/// Two opaque C/D-side publication capabilities issued only after B has
/// claimed the source abandoned-page owner bit for its direct client free.
///
/// Splitting this value transfers exactly two atomic-only appends. It cannot
/// reveal a client address, construct a collector, or outlive B's
/// higher-ranked synchronous callback.
#[doc(hidden)]
#[must_use = "both post-exit remote publications must publish or the opaque pair must return to the runtime callback"]
pub struct TicketZeroOwnerExitRemoteFreeProducerPair<'route> {
    producers: ThreadExitMappedRegularPagesPostExitRemoteFreeProducerPair<'route>,
}

// SAFETY: each component is Send and carries only one exact private client
// plus the callback-local lifetime boundary. The pair gives no route,
// PageMap, collector, or terminal-release authority to its receiver.
unsafe impl Send for TicketZeroOwnerExitRemoteFreeProducerPair<'_> {}

impl<'route> TicketZeroOwnerExitRemoteFreeProducerPair<'route> {
    /// Separates C and D's opaque atomic-only source publications. Both
    /// tokens remain bounded by B's direct source transition.
    #[inline]
    pub fn split(
        self,
    ) -> (
        TicketZeroOwnerExitRemoteFreeProducer<'route>,
        TicketZeroOwnerExitRemoteFreeProducer<'route>,
    ) {
        let (first, second) = self.producers.split();
        (
            TicketZeroOwnerExitRemoteFreeProducer { producer: first },
            TicketZeroOwnerExitRemoteFreeProducer { producer: second },
        )
    }

    #[inline]
    fn into_source_pair(self) -> ThreadExitMappedRegularPagesPostExitRemoteFreeProducerPair<'route> {
        self.producers
    }
}

/// The one callback shape admitted between B's direct source low-bit claim
/// and its existing collector. Its higher-ranked pair cannot outlive the
/// synchronous callback that the aggregate route joins before it resumes.
#[doc(hidden)]
pub type TicketZeroOwnerExitRemoteFreePublisher = for<'route> fn(
    TicketZeroOwnerExitRemoteFreeProducerPair<'route>,
) -> Result<(), TicketZeroOwnerExitRemoteFreeProducerPair<'route>>;

/// One opaque post-exit publication capability for a source-mapped, non-full
/// medium page. B mints it only after claiming that page's source low owner
/// bit for its direct client free.
///
/// This is intentionally a nominally distinct capability from
/// [`TicketZeroOwnerExitRemoteFreeProducer`]. The callback cannot reinterpret
/// a direct-small witness as a mapped-medium route, and still receives no
/// address, PageMap, collector, reclaim, or terminal-release authority.
#[doc(hidden)]
#[must_use = "the mapped-medium post-exit publication must publish or return its opaque producer"]
pub struct TicketZeroOwnerExitMappedMediumRemoteFreeProducer<'route> {
    producer: ThreadExitMappedRegularPagesPostExitRemoteFreeProducer<'route>,
}

// SAFETY: the wrapped source producer is Send and carries only one exact
// private client plus its callback-local lifetime boundary. Moving it exposes
// no route, map, collector, or terminal-release capability.
unsafe impl Send for TicketZeroOwnerExitMappedMediumRemoteFreeProducer<'_> {}

impl<'route> TicketZeroOwnerExitMappedMediumRemoteFreeProducer<'route> {
    /// Atomically publishes one private mapped-medium client to B's held
    /// source remote head. Failure returns the same opaque capability so the
    /// route remains terminal instead of claiming a publication happened.
    #[inline]
    pub fn publish(self) -> Result<(), Self> {
        match self.producer.publish() {
            Ok(()) => Ok(()),
            Err(producer) => Err(Self { producer }),
        }
    }
}

/// Two opaque C/D-side mapped-medium publication capabilities issued only
/// after B has claimed the source low owner bit for its direct medium free.
#[doc(hidden)]
#[must_use = "both mapped-medium post-exit publications must publish or the opaque pair must return to the runtime callback"]
pub struct TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'route> {
    producers: ThreadExitMappedRegularPagesPostExitRemoteFreeProducerPair<'route>,
}

// SAFETY: each component is Send and carries only one exact private client
// plus the callback-local lifetime boundary. The pair transfers no route,
// PageMap, collector, or terminal-release authority.
unsafe impl Send for TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'_> {}

impl<'route> TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'route> {
    /// Separates C and D's opaque mapped-medium atomic-only publications.
    /// Both remain bounded by B's one direct source transition.
    #[inline]
    pub fn split(
        self,
    ) -> (
        TicketZeroOwnerExitMappedMediumRemoteFreeProducer<'route>,
        TicketZeroOwnerExitMappedMediumRemoteFreeProducer<'route>,
    ) {
        let (first, second) = self.producers.split();
        (
            TicketZeroOwnerExitMappedMediumRemoteFreeProducer { producer: first },
            TicketZeroOwnerExitMappedMediumRemoteFreeProducer { producer: second },
        )
    }

    #[inline]
    fn into_source_pair(self) -> ThreadExitMappedRegularPagesPostExitRemoteFreeProducerPair<'route> {
        self.producers
    }
}

/// The one callback shape admitted between B's mapped-medium direct source
/// low-bit claim and its existing collector. Its higher-ranked pair cannot
/// outlive the synchronous callback that B joins before it resumes.
#[doc(hidden)]
pub type TicketZeroOwnerExitMappedMediumRemoteFreePublisher = for<'route> fn(
    TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'route>,
) -> Result<(), TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'route>>;

/// One opaque client identity after A has detached its Theap/TLD.
///
/// The key is not a pointer-domain capability: it only lets the detached
/// owner name one already-accounted client while it still keeps the address
/// private. In particular, direct-small's source drain may identify its
/// exact first client without turning the route into a block-list API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DetachedOwnerExitClientKey {
    slot: usize,
    generation: usize,
}

/// The one source page shape selected for a bounded post-exit B/C/D
/// publication. This stays wholly inside the runtime ledger: it is not a
/// selector exposed to the consumer callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetachedOwnerExitRemotePublicationKind {
    DirectSmall,
    MappedMedium,
}

/// Three opaque ledger identities together with the source shape that proved
/// their shared-page relation while A still owned the live engine.
#[derive(Clone, Copy)]
struct DetachedOwnerExitRemotePublicationSelection {
    kind: DetachedOwnerExitRemotePublicationKind,
    clients: [DetachedOwnerExitClientKey; 3],
}

/// The private callback identity carried to B's one bounded source
/// interleaving. It is checked against the opaque ledger selection before B
/// removes any client from that selection, so a callback for one source shape
/// cannot consume the other shape's route.
enum TicketZeroOwnerExitPostExitPublisher {
    DirectSmall(TicketZeroOwnerExitRemoteFreePublisher),
    MappedMedium(TicketZeroOwnerExitMappedMediumRemoteFreePublisher),
}

impl TicketZeroOwnerExitPostExitPublisher {
    #[inline]
    fn accepts(&self, kind: DetachedOwnerExitRemotePublicationKind) -> bool {
        matches!(
            (self, kind),
            (
                Self::DirectSmall(_),
                DetachedOwnerExitRemotePublicationKind::DirectSmall
            ) | (
                Self::MappedMedium(_),
                DetachedOwnerExitRemotePublicationKind::MappedMedium
            )
        )
    }
}

/// One private entry in the detached owner's client ledger.
///
/// The ledger is deliberately a coarse ownership fact, not the mixed witness'
/// historical layout. The source-shaped traversal owns page classification;
/// this object only proves that every live client has exactly one eventual
/// post-exit consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DetachedOwnerExitClient {
    key: DetachedOwnerExitClientKey,
    block: core::ptr::NonNull<u8>,
    /// The exact source usable extent recorded while A still owned the live
    /// page engine. The bounded native post-exit route may answer an exact
    /// C `malloc_usable_size` query from this immutable fact; it must not
    /// reopen the detached page map merely to inspect a client.
    usable_size: usize,
    /// `Some` records the ordinary request that selected this regular-page
    /// client. `None` is an aligned allocation, which cannot name the normal
    /// small/medium/large queue required by aggregate last-member adoption.
    /// This remains private route accounting, never a pointer or page
    /// identity capability.
    normal_request: Option<usize>,
    /// A observed that source owner-exit force collection will leave this
    /// exact still-live ordinary page with an immediate local head before it
    /// suspended. This is the conservative authority needed to attempt the
    /// aggregate's consuming final-member reclaim later: a page without that
    /// source fact must use ordinary sequential free, because a failed reclaim
    /// after its long PageMap claim cannot reconstruct the short route. The
    /// field keeps the fact private to the opaque route and never exposes an
    /// address or page identity to B's callback.
    has_pre_exit_owner_exit_collectable_local_free: bool,
}

impl DetachedOwnerExitClient {
    #[inline]
    fn can_attempt_final_member_adoption(self) -> bool {
        self.normal_request.is_some() && self.has_pre_exit_owner_exit_collectable_local_free
    }
}

/// The private client ledger carried across A's detached owner exit.
///
/// Fixed preparation witnesses remain inline because their caller-owned
/// selection arrays are deliberately small. A real parked session, however,
/// moves its own metadata-backed registry wholesale after it has transformed
/// every live entry into a detached-only client fact. That preserves the
/// allocation capability all the way through B's terminal exact-free route:
/// C still cannot enumerate an entry or obtain a client address from it.
enum DetachedOwnerExitClientLedger {
    Inline {
        entries: [
            Option<DetachedOwnerExitClient>;
            RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS
        ],
    },
    Session(PreparedOwnerExitClients),
}

impl DetachedOwnerExitClientLedger {
    fn empty() -> Self {
        Self::Inline {
            entries: core::array::from_fn(|_| None),
        }
    }

    #[inline]
    fn from_inline_entries(
        entries: [
            Option<DetachedOwnerExitClient>;
            RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS
        ],
    ) -> Self {
        Self::Inline { entries }
    }

    #[inline]
    fn from_session(clients: PreparedOwnerExitClients) -> Self {
        Self::Session(clients)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        match self {
            Self::Inline { entries } => entries.iter().all(Option::is_none),
            Self::Session(clients) => !clients.has_detached_client(),
        }
    }

    #[inline]
    fn block_for(&self, key: DetachedOwnerExitClientKey) -> Option<core::ptr::NonNull<u8>> {
        match self {
            Self::Inline { entries } => entries.iter().find_map(|entry| match entry {
                Some(client) if client.key == key => Some(client.block),
                _ => None,
            }),
            Self::Session(clients) => clients.detached_block_for(key),
        }
    }

    #[inline]
    fn next(&self) -> Option<DetachedOwnerExitClient> {
        match self {
            Self::Inline { entries } => entries.iter().flatten().copied().next(),
            Self::Session(clients) => clients.next_detached_client(),
        }
    }

    #[inline]
    fn take_next(&mut self) -> Option<DetachedOwnerExitClient> {
        match self {
            Self::Inline { entries } => entries.iter_mut().find_map(Option::take),
            Self::Session(clients) => clients.take_next_detached_client(),
        }
    }

    /// Removes one exact client only while the opaque post-exit route holds
    /// the aggregate owner. This is intentionally a private lookup by the C
    /// boundary's input address, not an iterable pointer registry: the route
    /// never returns a stored address or lets a caller select a page.
    #[inline]
    fn take_for_native_free(
        &mut self,
        block: core::ptr::NonNull<u8>,
    ) -> Option<DetachedOwnerExitClient> {
        match self {
            Self::Inline { entries } => entries.iter_mut().find_map(|entry| match entry {
                Some(client) if client.block == block => entry.take(),
                Some(_) | None => None,
            }),
            Self::Session(clients) => clients.take_detached_client_for_native_free(block),
        }
    }

    /// Returns an exact native C client only when it is the ledger's last
    /// remaining entry.  The opaque route may consume the existing aggregate
    /// final-member adoption only at that point: the C boundary must first
    /// terminally release every sibling, and it never receives a page or a
    /// client-selection capability.
    #[inline]
    fn only_client_for_native_free(
        &self,
        block: core::ptr::NonNull<u8>,
    ) -> Option<DetachedOwnerExitClient> {
        match self {
            Self::Inline { entries } => {
                let mut only = None;
                for client in entries.iter().flatten().copied() {
                    if only.replace(client).is_some() {
                        return None;
                    }
                }
                only.filter(|client| client.block == block)
            }
            Self::Session(clients) => clients.only_detached_client_for_native_free(block),
        }
    }

    /// Returns the source-recorded usable extent for one exact native C
    /// client without transferring or exposing the client entry. The route
    /// still owns the address and every page-lifecycle capability; this is a
    /// read-only C ABI query rather than a pointer registry operation.
    #[inline]
    fn usable_size_for_native_block(&self, block: core::ptr::NonNull<u8>) -> Option<usize> {
        match self {
            Self::Inline { entries } => entries.iter().find_map(|entry| match entry {
                Some(client) if client.block == block => Some(client.usable_size),
                Some(_) | None => None,
            }),
            Self::Session(clients) => clients.detached_usable_size_for_native_block(block),
        }
    }

    fn take_remote_publication_group(
        &mut self,
        selection: DetachedOwnerExitRemotePublicationSelection,
    ) -> Option<DetachedOwnerExitRemotePublicationGroup> {
        let [direct, first_published, second_published] = selection.clients;
        if direct == first_published
            || direct == second_published
            || first_published == second_published
        {
            return None;
        }
        match self {
            Self::Inline { entries } => {
                let direct_index = entries.iter().position(|entry| {
                    matches!(entry, Some(client) if client.key == direct)
                })?;
                let first_published_index = entries.iter().position(|entry| {
                    matches!(entry, Some(client) if client.key == first_published)
                })?;
                let second_published_index = entries.iter().position(|entry| {
                    matches!(entry, Some(client) if client.key == second_published)
                })?;
                let direct = entries[direct_index]
                    .take()
                    .expect("the located detached client remains present");
                let first_published = entries[first_published_index]
                    .take()
                    .expect("the distinct located detached client remains present");
                let second_published = entries[second_published_index]
                    .take()
                    .expect("the distinct located detached client remains present");
                Some(DetachedOwnerExitRemotePublicationGroup {
                    kind: selection.kind,
                    direct: Some(direct.block),
                    first_published: Some(first_published.block),
                    second_published: Some(second_published.block),
                })
            }
            Self::Session(clients) => clients.take_detached_remote_publication_group(selection),
        }
    }

    /// Releases the session's metadata extension only after every detached
    /// client has terminally left the route. Inline preparation ledgers have
    /// no separate storage capability to return.
    fn release_overflow_when_empty(
        &mut self,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        match self {
            Self::Inline { .. } => Ok(()),
            Self::Session(clients) => clients.release_overflow_without_detached_clients(),
        }
    }

    fn free_locals(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    ) -> Result<(), ()> {
        while let Some(client) = self.take_next() {
            // SAFETY: this ledger is only freed before A suspends, or after
            // B has adopted the exact page engine. Its entry names one
            // current client owned exclusively by that engine.
            unsafe { allocator.free(client.block) }.map_err(|_| ())?;
        }
        self.release_overflow_when_empty().map_err(|_| ())
    }
}

/// The one source-faithful B/C/D interleaving retained only by the bounded
/// runtime witness. The group is selected by opaque ledger keys during A's
/// preparation; the generic sequential route never indexes a fixture layout.
/// Its explicit kind keeps the direct-small and mapped-medium source proofs
/// nominally separate. B directly claims the source low bit, then C and D
/// each atomically append one same-page client before B's collector resumes.
struct DetachedOwnerExitRemotePublicationGroup {
    kind: DetachedOwnerExitRemotePublicationKind,
    direct: Option<core::ptr::NonNull<u8>>,
    first_published: Option<core::ptr::NonNull<u8>>,
    second_published: Option<core::ptr::NonNull<u8>>,
}

impl DetachedOwnerExitRemotePublicationGroup {
    #[inline]
    fn is_empty(&self) -> bool {
        self.direct.is_none()
            && self.first_published.is_none()
            && self.second_published.is_none()
    }

    #[inline]
    fn take_next(&mut self) -> Option<core::ptr::NonNull<u8>> {
        self.direct
            .take()
            .or_else(|| self.first_published.take())
            .or_else(|| self.second_published.take())
    }

    #[inline]
    fn take_for_publishers(
        &mut self,
    ) -> Option<(
        core::ptr::NonNull<u8>,
        core::ptr::NonNull<u8>,
        core::ptr::NonNull<u8>,
    )> {
        if self.direct.is_none()
            || self.first_published.is_none()
            || self.second_published.is_none()
        {
            return None;
        }
        Some((
            self.direct
                .take()
                .expect("the checked direct private client remains present"),
            self.first_published
                .take()
                .expect("the checked first published private client remains present"),
            self.second_published
                .take()
                .expect("the checked second published private client remains present"),
        ))
    }

    fn free_locals(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    ) -> Result<(), ()> {
        while let Some(block) = self.take_next() {
            // SAFETY: this group remains A-local until preparation either
            // suspends its exact source engine or aborts it normally.
            unsafe { allocator.free(block) }.map_err(|_| ())?;
        }
        Ok(())
    }
}

/// One private, linear source post-exit route whose client addresses remain
/// inside the runtime witness. It is the only capability that may complete
/// one detached source owner after A has torn down its Theap/TLD.
///
/// The adapter may move it to exactly one joined pthread B and call
/// [`Self::free_remaining_in_fresh_runtime_worker`]. It neither exposes a
/// client address nor creates an allocation, reclaim, or page-shape-specific
/// owner-exit API. Internally, the same route may take the already-proven
/// aggregate-last-member handoff only after its private sequential ledger has
/// terminally released every sibling; B still receives no client or page
/// selection capability.
#[doc(hidden)]
#[must_use = "the post-exit route must release every private client or remain terminally retained"]
pub struct TicketZeroOwnerExitFreeRoute<'main> {
    // Every production route originates from `ThreadLifecycleSlot`, whose
    // attachment and process-main roots are compiler-TLS/process-static.
    // Keep that concrete ownership here so B can borrow its own static
    // attachment for a source-valid final-member adoption. The phantom
    // lifetime preserves the higher-ranked consumer boundary: a callback
    // cannot safely retain this opaque route beyond its synchronous handoff.
    route: MainHeapThreadProcessPageExitMappedRegularPagesRoute<'static>,
    clients: DetachedOwnerExitClientLedger,
    post_exit_remote_publication_group: Option<DetachedOwnerExitRemotePublicationGroup>,
    /// The immutable process map/arena identity remains private to this route
    /// so a final mapped regular member can enter B only through the existing
    /// source-shaped short-to-long adoption transition. It is not an exposed
    /// scheduler or allocation capability.
    pair: ProcessPageArenaLease,
    admission: LaterThreadAdmissionClaim,
    _consumer: PhantomData<&'main mut ()>,
}

// SAFETY: this private capability contains neither an old TLD nor a Theap.
// Its only `NonNull` values are exact one-shot client identities that remain
// inaccessible to its receiver. The underlying aggregate route is Send but
// deliberately !Sync, so moving this value transfers its unique linear
// source release authority to one joined consumer.
unsafe impl Send for TicketZeroOwnerExitFreeRoute<'_> {}

/// A proof that a private owner-exit route reached `ReleasedAll` and finished
/// its PageMap lifecycle. The private drain inside
/// [`TicketZeroOwnerExitFreeRoute::free_remaining_in_fresh_runtime_worker`]
/// mints it only after B has entered its own fresh runtime lifecycle; the
/// runtime consumes it before releasing A's admission claim.
#[doc(hidden)]
#[must_use = "this proof must immediately complete the detached worker lifecycle"]
pub struct TicketZeroOwnerExitRouteFinished {
    admission: LaterThreadAdmissionClaim,
}

impl TicketZeroOwnerExitRouteFinished {
    #[inline]
    fn into_admission(self) -> LaterThreadAdmissionClaim {
        self.admission
    }

    /// Consumes the only post-exit terminal proof to release its matching
    /// worker admission. A failed count transition returns the same proof so
    /// the runtime can retain its exact claim rather than decrementing some
    /// unrelated worker or reopening fork preservation.
    #[inline]
    fn release_worker_admission(
        self,
        admissions: &RuntimeForkAdmission,
    ) -> Result<(), Self> {
        match admissions.release_later_thread(self.admission) {
            Ok(()) => Ok(()),
            Err(admission) => Err(Self { admission }),
        }
    }
}

/// A terminal post-exit result whose final PageMap wake poisoned after every
/// page had released. It cannot authorize normal worker completion, but it
/// retains the exact admission claim so the fork boundary remains explicit.
#[doc(hidden)]
#[must_use = "a poisoned owner-exit result must retain its exact worker admission claim"]
pub struct TicketZeroOwnerExitRoutePoisoned {
    admission: LaterThreadAdmissionClaim,
}

impl TicketZeroOwnerExitRoutePoisoned {
    #[inline]
    fn into_admission(self) -> LaterThreadAdmissionClaim {
        self.admission
    }
}

/// One private, linear post-exit route that may reclaim exactly one
/// source-approved mapped regular page into one fresh later worker.
///
/// The former owner A's client identities, process pair, allocation request,
/// and admission claim remain private to this capability. Its receiver can
/// only run the already-proven source adoption, use and drain the reclaimed
/// page, and return a typed proof to A. It cannot obtain an allocation-time
/// scan, a raw client pointer, or a general PageMap scheduler capability.
#[doc(hidden)]
#[must_use = "the post-exit reclaim route must finish its exact later owner or remain terminally retained"]
pub struct TicketZeroOwnerExitReclaimRoute {
    route: MainHeapThreadProcessPageExitMappedRegularRoute<'static>,
    clients: DetachedOwnerExitClientLedger,
    request: usize,
    pair: ProcessPageArenaLease,
    admission: LaterThreadAdmissionClaim,
}

// SAFETY: this contains no former TLD/Theap borrow. The sole mapped route is
// Send and serializes its short-to-long PageMap transition, while the opaque
// client identities remain inaccessible to the receiving worker. Moving it
// transfers one linear source reclamation decision; it grants neither
// concurrent reclamation nor generic allocation authority.
unsafe impl Send for TicketZeroOwnerExitReclaimRoute {}

/// Outcome of one joined B-side source reclamation operation.
#[doc(hidden)]
#[must_use = "a failed post-exit reclamation retains the exact admission and page owner"]
pub enum TicketZeroOwnerExitReclaimOutcome {
    /// B reclaimed the exact page, returned its engine empty, and completed
    /// its own attachment before returning A's terminal admission proof.
    Finished(TicketZeroOwnerExitRouteFinished),
    /// Reclamation rejected before transferring the short route, so A still
    /// owns the exact route and admission claim.
    Retained(TicketZeroOwnerExitReclaimRoute),
    /// The route transferred or B began a lifecycle whose source ownership is
    /// no longer retryable. The exact A admission remains terminally visible.
    Poisoned(TicketZeroOwnerExitRoutePoisoned),
}

/// A terminal outcome from the opaque B-side owner-exit consumer.
#[doc(hidden)]
#[must_use = "a retained route or poisoned outcome must retain the runtime boundary"]
pub enum TicketZeroOwnerExitFreeOutcome<'main> {
    /// B released every exact client and the last PageMap lifecycle completed.
    Finished(TicketZeroOwnerExitRouteFinished),
    /// A source release error left the still-owning route retained exactly as
    /// returned by the aggregate path. The runtime must become retained.
    Retained(TicketZeroOwnerExitFreeRoute<'main>),
    /// The last page release completed but PageMap quiescence poisoned its
    /// wake boundary, leaving no route to retry. The runtime retains its
    /// exact admission claim instead of making the worker fork-quiescent.
    Poisoned(TicketZeroOwnerExitRoutePoisoned),
}

/// One result from consuming a private client through the aggregate source
/// route. Keeping this classification separate lets both the ordinary ledger
/// drain and the test-only B/C pair use the exact same terminal accounting.
enum DetachedOwnerExitFreeStep<'main> {
    Continue(MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main>),
    ReleasedAll,
    Retained(MainHeapThreadProcessPageExitMappedRegularPagesRoute<'main>),
    Poisoned,
}

/// One private result from looking up a raw C free in a detached native
/// owner-exit route. The route remains opaque to the caller throughout: the
/// only observable success is that this exact free completed; page state,
/// client identities, and A's admission claim stay internal.
enum NativePostExitFreeStep {
    NotOwned(NativePostExitFreeRoute),
    Freed(NativePostExitFreeRoute),
    Finished(TicketZeroOwnerExitRouteFinished),
    Retained(NativePostExitFreeRoute),
    Poisoned(TicketZeroOwnerExitRoutePoisoned),
}

/// The aggregate route's private result before the C-facing native dispatcher
/// erases its source branch.  The aggregate remains reusable by the existing
/// typed runtime consumers with their original non-`'static` lifetimes;
/// only the process-static native slot converts it into
/// [`NativePostExitFreeRoute`].
enum AggregateNativePostExitFreeStep<'main> {
    NotOwned(TicketZeroOwnerExitFreeRoute<'main>),
    Freed(TicketZeroOwnerExitFreeRoute<'main>),
    Finished(TicketZeroOwnerExitRouteFinished),
    Retained(TicketZeroOwnerExitFreeRoute<'main>),
    Poisoned(TicketZeroOwnerExitRoutePoisoned),
}

/// The C-facing post-exit router owns one already-detached source route.  The
/// variants are source control-flow results, not a C-visible page geometry:
/// the aggregate traversal has its process registry, while the older
/// source-proved sole mapped regular result already has one exact
/// failed-reclaim free primitive.  Both retain the same private ledger and
/// admission until a final native `free` produces a typed proof.
#[must_use = "a native post-exit route must release every private client or remain terminally retained"]
enum NativePostExitFreeRoute {
    Aggregate(TicketZeroOwnerExitFreeRoute<'static>),
    SoleMappedRegular(NativeSoleMappedRegularPostExitRoute),
}

/// One source-proved sole mapped regular page after A's Theap/TLD teardown.
///
/// This is deliberately a client-free route, not an adoption route.  A fresh
/// C worker B offers one exact address already recorded by A's private
/// ledger; the lower route performs the existing source failed-reclaim free
/// and terminal release.  B receives no page, client, or reclaim capability,
/// and cannot turn a C free into allocation-time adoption.
#[must_use = "a sole mapped regular native route must release its exact client or remain terminally retained"]
struct NativeSoleMappedRegularPostExitRoute {
    route: MainHeapThreadProcessPageExitMappedRegularRoute<'static>,
    clients: DetachedOwnerExitClientLedger,
    /// The immutable process pair selected before A suspended.  The sole
    /// client-free path does not consume this copyable identity witness, but
    /// it stays coupled to the route just as the aggregate native route does
    /// so a future source transition cannot substitute another process pair.
    _pair: ProcessPageArenaLease,
    admission: LaterThreadAdmissionClaim,
}

impl NativePostExitFreeRoute {
    fn free_exact_native_block(
        self,
        attachment: &mut MainHeapThreadAttachment<'static>,
        block: core::ptr::NonNull<u8>,
    ) -> NativePostExitFreeStep {
        match self {
            Self::Aggregate(route) => match route.free_exact_native_block(attachment, block) {
                AggregateNativePostExitFreeStep::NotOwned(route) => {
                    NativePostExitFreeStep::NotOwned(Self::Aggregate(route))
                }
                AggregateNativePostExitFreeStep::Freed(route) => {
                    NativePostExitFreeStep::Freed(Self::Aggregate(route))
                }
                AggregateNativePostExitFreeStep::Finished(proof) => {
                    NativePostExitFreeStep::Finished(proof)
                }
                AggregateNativePostExitFreeStep::Retained(route) => {
                    NativePostExitFreeStep::Retained(Self::Aggregate(route))
                }
                AggregateNativePostExitFreeStep::Poisoned(proof) => {
                    NativePostExitFreeStep::Poisoned(proof)
                }
            },
            Self::SoleMappedRegular(route) => route.free_exact_native_block(block),
        }
    }

    #[inline]
    fn native_usable_size(&self, block: core::ptr::NonNull<u8>) -> Option<usize> {
        match self {
            Self::Aggregate(route) => route.native_usable_size(block),
            Self::SoleMappedRegular(route) => route.native_usable_size(block),
        }
    }

    #[inline]
    fn admission_ptr(&self) -> *const LaterThreadAdmissionClaim {
        match self {
            Self::Aggregate(route) => core::ptr::addr_of!(route.admission),
            Self::SoleMappedRegular(route) => core::ptr::addr_of!(route.admission),
        }
    }
}

impl NativeSoleMappedRegularPostExitRoute {
    /// Consumes one exact native C client through the already source-proved
    /// mapped regular post-exit free path.  The private ledger is the raw-C
    /// validation boundary; it is not a general PageMap lookup or pointer
    /// registry.
    fn free_exact_native_block(
        mut self,
        block: core::ptr::NonNull<u8>,
    ) -> NativePostExitFreeStep {
        let Some(client) = self.clients.take_for_native_free(block) else {
            return NativePostExitFreeStep::NotOwned(
                NativePostExitFreeRoute::SoleMappedRegular(self),
            );
        };

        // SAFETY: the opaque route owns this exact once-live client and the
        // sole source page selected by A's completed `MI_ABANDON` traversal.
        // No former Theap/TLD or second post-exit route can access it.
        match unsafe { self.route.remote_free_after_thread_exit(client.block) } {
            Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::StillLive(route)) => {
                self.route = route;
                NativePostExitFreeStep::Freed(NativePostExitFreeRoute::SoleMappedRegular(self))
            }
            Ok(MainHeapThreadProcessPageExitMappedRegularFreeResult::Released) => {
                if self.clients.is_empty() {
                    match self.clients.release_overflow_when_empty() {
                        Ok(()) => NativePostExitFreeStep::Finished(
                            TicketZeroOwnerExitRouteFinished {
                                admission: self.admission,
                            },
                        ),
                        Err(_) => NativePostExitFreeStep::Poisoned(
                            TicketZeroOwnerExitRoutePoisoned {
                                admission: self.admission,
                            },
                        ),
                    }
                } else {
                    // The lower route has terminally released. Any remaining
                    // client identity would be an impossible alias with no
                    // source owner left to receive it.
                    NativePostExitFreeStep::Poisoned(TicketZeroOwnerExitRoutePoisoned {
                        admission: self.admission,
                    })
                }
            }
            Err(MainHeapThreadProcessPageExitMappedRegularFreeFailure::Rejected {
                route,
                ..
            })
            | Err(MainHeapThreadProcessPageExitMappedRegularFreeFailure::Terminal {
                route,
                ..
            }) => {
                self.route = route;
                NativePostExitFreeStep::Retained(NativePostExitFreeRoute::SoleMappedRegular(
                    self,
                ))
            }
            Err(
                MainHeapThreadProcessPageExitMappedRegularFreeFailure::ReleasedPageMapPoisoned {
                    ..
                },
            ) => NativePostExitFreeStep::Poisoned(TicketZeroOwnerExitRoutePoisoned {
                admission: self.admission,
            }),
        }
    }

    #[inline]
    fn native_usable_size(&self, block: core::ptr::NonNull<u8>) -> Option<usize> {
        self.clients.usable_size_for_native_block(block)
    }
}

fn classify_detached_owner_exit_free<'main>(
    free: Result<
        MainHeapThreadProcessPageExitMappedRegularPagesFreeResult<'main>,
        MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure<'main>,
    >,
) -> DetachedOwnerExitFreeStep<'main> {
    match free {
        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::StillLive(route))
        | Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedPage(route)) => {
            DetachedOwnerExitFreeStep::Continue(route)
        }
        Ok(MainHeapThreadProcessPageExitMappedRegularPagesFreeResult::ReleasedAll) => {
            DetachedOwnerExitFreeStep::ReleasedAll
        }
        Err(MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure::Rejected {
            route,
            ..
        })
        | Err(MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure::Terminal {
            route,
            ..
        }) => DetachedOwnerExitFreeStep::Retained(route),
        Err(
            MainHeapThreadProcessPageExitMappedRegularPagesFreeFailure::ReleasedAllPageMapPoisoned {
                ..
            },
        ) => DetachedOwnerExitFreeStep::Poisoned,
    }
}

fn detached_owner_exit_released_all<'main>(
    clients: &mut DetachedOwnerExitClientLedger,
    has_remaining_clients: bool,
    admission: LaterThreadAdmissionClaim,
) -> TicketZeroOwnerExitFreeOutcome<'main> {
    if has_remaining_clients {
        // A completed route cannot have an unconsumed private alias. The
        // lower source route no longer exists to retain, so keep the exact
        // admission terminal rather than minting a false completion proof.
        TicketZeroOwnerExitFreeOutcome::Poisoned(TicketZeroOwnerExitRoutePoisoned {
            admission,
        })
    } else if clients.release_overflow_when_empty().is_ok() {
        TicketZeroOwnerExitFreeOutcome::Finished(TicketZeroOwnerExitRouteFinished { admission })
    } else {
        TicketZeroOwnerExitFreeOutcome::Poisoned(TicketZeroOwnerExitRoutePoisoned { admission })
    }
}

impl<'main> TicketZeroOwnerExitFreeRoute<'main> {
    /// Releases the detached owner's private remaining clients through the
    /// single general aggregate route. The ledger is populated by ordinary
    /// A-side activity, not by a source-page-shape layout; its deterministic
    /// insertion order merely makes this private witness reproducible. At a
    /// normal final client it may ask the lower aggregate whether the source
    /// state permits its existing consuming mapped-regular handoff; a
    /// rejection leaves this same route on the ordinary sequential free path.
    // Keep the raw source-route drain inside this runtime module.  Once A has
    // detached, an external consumer must use
    // `free_remaining_in_fresh_runtime_worker`: exposing this lower-level
    // step would let a callback manufacture A's terminal proof without first
    // completing B's separately admitted no-page lifecycle.
    fn free_remaining(
        self,
        attachment: &mut MainHeapThreadAttachment<'static>,
    ) -> TicketZeroOwnerExitFreeOutcome<'main> {
        if self.post_exit_remote_publication_group.is_some() {
            // A bounded B/C/D source interleaving is not a generic
            // sequential-free fallback. The caller must select the matching
            // typed publisher route so B can lend the atomic-only producers
            // only after its source low-bit claim; otherwise its normal
            // no-page finish could falsely stand in for that terminal route.
            return TicketZeroOwnerExitFreeOutcome::Retained(self);
        }
        self.free_remaining_clients(attachment)
    }

    /// Consumes one exact C-facing client from the generic aggregate route.
    ///
    /// The native shadow calls this only after the original owner A has
    /// detached and a fresh attached worker B has presented the address to
    /// the private router. Unlike the test-only `free_remaining` helper, it
    /// does not expose the remaining ledger or select an allocation order.
    /// Every nonterminal outcome returns the same linear route for the
    /// router to retain; a terminal proof remains unavailable until the last
    /// source page and PageMap state have released.
    fn free_exact_native_block(
        self,
        attachment: &mut MainHeapThreadAttachment<'static>,
        block: core::ptr::NonNull<u8>,
    ) -> AggregateNativePostExitFreeStep<'main> {
        // The scoped B/C/D publishers are a distinct source-test
        // interleaving. A C free may not accidentally reinterpret that
        // bounded group as a general pointer-routing route.
        if self.post_exit_remote_publication_group.is_some() {
            return AggregateNativePostExitFreeStep::Retained(self);
        }

        // B has supplied only this raw C address.  It may consume the
        // established aggregate last-member adoption transition only after
        // prior exact frees left this one private ledger entry, and only when
        // A recorded the source force-collectable local-head fact before
        // suspension.
        // The route still validates membership and makes the pinned bitmap
        // claim below; this is not a client- or page-selection API.
        if let Some(candidate) = self
            .clients
            .only_client_for_native_free(block)
            .filter(|client| client.can_attempt_final_member_adoption())
        {
            return self.adopt_last_native_mapped_regular_member(attachment, candidate, block);
        }

        self.free_exact_native_block_sequential(block)
    }

    /// Keeps the established exact-free tail for every native route that has
    /// not reached the one final mapped regular member.  A failed adoption
    /// preflight returns here with the same route, so a short-access refusal
    /// never turns an otherwise valid C free into a retained process owner.
    fn free_exact_native_block_sequential(
        mut self,
        block: core::ptr::NonNull<u8>,
    ) -> AggregateNativePostExitFreeStep<'main> {
        let Some(client) = self.clients.take_for_native_free(block) else {
            return AggregateNativePostExitFreeStep::NotOwned(self);
        };

        // SAFETY: the opaque route owns the selected exact client and the
        // aggregate source transition. No live source TLD can still access
        // this block after A's detached owner exit.
        let free = unsafe { self.route.remote_free_after_thread_exit(client.block) };
        match classify_detached_owner_exit_free(free) {
            DetachedOwnerExitFreeStep::Continue(route) => {
                self.route = route;
                AggregateNativePostExitFreeStep::Freed(self)
            }
            DetachedOwnerExitFreeStep::ReleasedAll => {
                if self.clients.is_empty() {
                    match self.clients.release_overflow_when_empty() {
                        Ok(()) => AggregateNativePostExitFreeStep::Finished(
                            TicketZeroOwnerExitRouteFinished {
                                admission: self.admission,
                            },
                        ),
                        Err(_) => AggregateNativePostExitFreeStep::Poisoned(
                            TicketZeroOwnerExitRoutePoisoned {
                                admission: self.admission,
                            },
                        ),
                    }
                } else {
                    // The source route no longer exists, so unconsumed
                    // client identities cannot be returned to an ordinary
                    // allocator. Retain A's exact admission rather than
                    // minting a false terminal proof.
                    AggregateNativePostExitFreeStep::Poisoned(TicketZeroOwnerExitRoutePoisoned {
                        admission: self.admission,
                    })
                }
            }
            DetachedOwnerExitFreeStep::Retained(route) => {
                self.route = route;
                AggregateNativePostExitFreeStep::Retained(self)
            }
            DetachedOwnerExitFreeStep::Poisoned => {
                AggregateNativePostExitFreeStep::Poisoned(TicketZeroOwnerExitRoutePoisoned {
                    admission: self.admission,
                })
            }
        }
    }

    /// Consumes the already-proven aggregate final-member adoption transition
    /// through the native opaque route.
    ///
    /// B has already released every sibling through exact C frees.  Its last
    /// address remains private in this route, while the lower transition
    /// claims the source bitmap, creates B's real page engine, reuses the
    /// source page, drains both the inherited client and B's temporary
    /// allocation, and finishes that engine before minting A's terminal
    /// proof.  A source rejection restores the ordinary exact-free route;
    /// every post-claim failure is terminally retained rather than falling
    /// back to a fresh allocation or a normal no-page finalizer.
    fn adopt_last_native_mapped_regular_member(
        self,
        attachment: &mut MainHeapThreadAttachment<'static>,
        candidate: DetachedOwnerExitClient,
        block: core::ptr::NonNull<u8>,
    ) -> AggregateNativePostExitFreeStep<'main> {
        debug_assert_eq!(candidate.block, block);
        debug_assert!(candidate.can_attempt_final_member_adoption());
        let request = candidate
            .normal_request
            .expect("the final native adoption candidate keeps its normal request");
        let Self {
            route,
            mut clients,
            post_exit_remote_publication_group,
            pair,
            admission,
            _consumer: _,
        } = self;
        debug_assert!(post_exit_remote_publication_group.is_none());

        // SAFETY: the native route owns its last exact once-live client and
        // its aggregate short PageMap capability. `candidate` was observed
        // force-collectable before A suspended, so source owner exit leaves
        // an immediately reusable local head; the lower bridge rechecks the
        // source page identity and all lifecycle roots before it consumes
        // short access into B's long mutation lease.
        match unsafe {
            route.adopt_remaining_mapped_regular_into_later_main(
                attachment,
                pair,
                candidate.block,
                request,
            )
        } {
            Ok(mut allocator) => {
                #[cfg(test)]
                AGGREGATE_LAST_MAPPED_REGULAR_ADOPTION_COUNT.fetch_add(1, Ordering::Relaxed);

                // The source page must do useful B-side work before it can
                // return A's terminal proof.  The allocator has only the
                // adopted source member, so this normal request proves reuse
                // rather than authorizing a fresh page search.
                let Some(reclaimed_allocation) = allocator.allocate(request, false) else {
                    core::mem::forget(allocator);
                    return AggregateNativePostExitFreeStep::Poisoned(
                        TicketZeroOwnerExitRoutePoisoned { admission },
                    );
                };
                let mut reclaimed_allocation = Some(reclaimed_allocation);
                if clients.free_locals(&mut allocator).is_err()
                    || free_owner_exit_locals(
                        &mut allocator,
                        core::slice::from_mut(&mut reclaimed_allocation),
                    )
                    .is_err()
                {
                    core::mem::forget(allocator);
                    return AggregateNativePostExitFreeStep::Poisoned(
                        TicketZeroOwnerExitRoutePoisoned { admission },
                    );
                }
                if let Err(failure) = allocator.finish() {
                    core::mem::forget(failure);
                    return AggregateNativePostExitFreeStep::Poisoned(
                        TicketZeroOwnerExitRoutePoisoned { admission },
                    );
                }
                if clients.is_empty() && clients.release_overflow_when_empty().is_ok() {
                    AggregateNativePostExitFreeStep::Finished(TicketZeroOwnerExitRouteFinished {
                        admission,
                    })
                } else {
                    // The lower route has completed, so a residual private
                    // client would have no source owner left to consume it.
                    AggregateNativePostExitFreeStep::Poisoned(
                        TicketZeroOwnerExitRoutePoisoned { admission },
                    )
                }
            }
            Err(
                MainHeapThreadProcessPageExitMappedRegularPagesAdoptFailure::Rejected {
                    route,
                    ..
                },
            ) => {
                Self {
                    route,
                    clients,
                    post_exit_remote_publication_group,
                    pair,
                    admission,
                    _consumer: PhantomData,
                }
                .free_exact_native_block_sequential(block)
            }
            Err(
                MainHeapThreadProcessPageExitMappedRegularPagesAdoptFailure::Retained {
                    adoption,
                    ..
                },
            ) => {
                // The source route became B's long lifecycle.  It cannot
                // safely return to the raw-C dispatcher or imitate a normal
                // no-page finisher after this point.
                core::mem::forget(adoption);
                AggregateNativePostExitFreeStep::Poisoned(TicketZeroOwnerExitRoutePoisoned {
                    admission,
                })
            }
        }
    }

    /// Looks up one exact native C client without changing the detached
    /// route. The source engine recorded this extent before it tore down A's
    /// Theap/TLD, so B need not reopen the PageMap or receive a client handle
    /// merely to answer `malloc_usable_size` before a later exact `free`.
    #[inline]
    fn native_usable_size(&self, block: core::ptr::NonNull<u8>) -> Option<usize> {
        // The scoped B/C/D producer group is a test-only source interleaving and
        // intentionally has no raw-C lookup surface.
        if self.post_exit_remote_publication_group.is_some() {
            return None;
        }
        self.clients.usable_size_for_native_block(block)
    }

    /// Runs one test-only B/C/D interleaving for the opaque group selected by
    /// the mixed regression builder, then resumes the generic ledger drain.
    ///
    /// The callback is present only in the Gate 5C adapter witness. Its three
    /// slots were allocated from either the covered direct-small page or the
    /// separately selected mapped, non-full medium page while A owned the
    /// live engine. B directly frees one; C and D receive only the two opaque
    /// producers constructed after B has claimed the source low owner bit.
    fn free_remaining_with_post_exit_publisher(
        mut self,
        attachment: &mut MainHeapThreadAttachment<'static>,
        publisher: TicketZeroOwnerExitPostExitPublisher,
    ) -> TicketZeroOwnerExitFreeOutcome<'main> {
        let Some(mut group) = self.post_exit_remote_publication_group.take() else {
            // The bounded B/C/D witness has no valid three-client same-page
            // shape. It must not silently fall back to a linear drain, which
            // would claim a concurrent source protocol had been exercised.
            return TicketZeroOwnerExitFreeOutcome::Retained(self);
        };
        if !publisher.accepts(group.kind) {
            // A nominally different opaque producer must not be treated as a
            // fallback for this source page. Keep the private selection and
            // route intact so neither ordinary nor mismatched finalization
            // can claim the bounded interleaving completed.
            self.post_exit_remote_publication_group = Some(group);
            return TicketZeroOwnerExitFreeOutcome::Retained(self);
        }
        let Some((block, first_published_block, second_published_block)) =
            group.take_for_publishers()
        else {
            self.post_exit_remote_publication_group = Some(group);
            return TicketZeroOwnerExitFreeOutcome::Retained(self);
        };
        // SAFETY: the regression builder selected three distinct current
        // clients from one source page by their private ledger keys. The
        // lower route validates that same-page image again under its short
        // PageMap access before B lends C and D the atomic-only producers.
        let has_remaining_clients = self.has_remaining_clients();
        let free = match publisher {
            TicketZeroOwnerExitPostExitPublisher::DirectSmall(publisher) => unsafe {
                self.route
                    .remote_free_after_thread_exit_with_direct_small_publishers(
                        block,
                        first_published_block,
                        second_published_block,
                        |producers| {
                            match publisher(TicketZeroOwnerExitRemoteFreeProducerPair {
                                producers,
                            }) {
                                Ok(()) => Ok(()),
                                Err(producers) => Err(producers.into_source_pair()),
                            }
                        },
                    )
            },
            TicketZeroOwnerExitPostExitPublisher::MappedMedium(publisher) => unsafe {
                self.route
                    .remote_free_after_thread_exit_with_mapped_medium_publishers(
                        block,
                        first_published_block,
                        second_published_block,
                        |producers| {
                            match publisher(
                                TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair { producers },
                            ) {
                                Ok(()) => Ok(()),
                                Err(producers) => Err(producers.into_source_pair()),
                            }
                        },
                    )
            },
        };
        match classify_detached_owner_exit_free(free) {
            DetachedOwnerExitFreeStep::Continue(route) => {
                self.route = route;
                self.free_remaining_clients(attachment)
            }
            DetachedOwnerExitFreeStep::ReleasedAll => detached_owner_exit_released_all(
                &mut self.clients,
                has_remaining_clients,
                self.admission,
            ),
            DetachedOwnerExitFreeStep::Retained(route) => {
                self.route = route;
                TicketZeroOwnerExitFreeOutcome::Retained(self)
            }
            DetachedOwnerExitFreeStep::Poisoned => {
                TicketZeroOwnerExitFreeOutcome::Poisoned(TicketZeroOwnerExitRoutePoisoned {
                    admission: self.admission,
                })
            }
        }
    }

    #[inline]
    fn has_remaining_clients(&self) -> bool {
        !self.clients.is_empty()
            || self
                .post_exit_remote_publication_group
                .as_ref()
                .is_some_and(|group| !group.is_empty())
    }

    fn free_remaining_clients(
        self,
        attachment: &mut MainHeapThreadAttachment<'static>,
    ) -> TicketZeroOwnerExitFreeOutcome<'main> {
        let Self {
            mut route,
            mut clients,
            mut post_exit_remote_publication_group,
            pair,
            admission,
            ..
        } = self;

        loop {
            // Do not skip the bounded B/C/D publisher group: both
            // source-shaped publications must run before any later-main
            // adoption attempt. Once that group is gone, only an A-side prevalidated immediate
            // local head may attempt the consuming final-member reclaim. A
            // normal ledger entry without that fact is still fully routable,
            // but must remain on sequential free: the lower long-lifecycle
            // claim is intentionally irreversible after it observes a missing
            // head. This scheduler never derives or stores a page identity.
            if post_exit_remote_publication_group.is_none() {
                if let Some(candidate) = clients
                    .next()
                    .filter(|client| client.can_attempt_final_member_adoption())
                {
                    let request = candidate
                        .normal_request
                        .expect("the filtered normal route client keeps its request");
                    // SAFETY: the private ledger owns this exact once-live
                    // client, and its normal request came from the ordinary
                    // A-side allocation that minted it. The lower transition
                    // retains every target state after it consumes short map
                    // access; a pre-transfer refusal returns the same route.
                    match unsafe {
                        route.adopt_remaining_mapped_regular_into_later_main(
                            attachment,
                            pair,
                            candidate.block,
                            request,
                        )
                    } {
                        Ok(mut allocator) => {
                            #[cfg(test)]
                            AGGREGATE_LAST_MAPPED_REGULAR_ADOPTION_COUNT
                                .fetch_add(1, Ordering::Relaxed);
                            // Reuse one source-free block before draining the
                            // inherited private clients. This keeps the
                            // aggregate edge aligned with the established
                            // sole-page route: B must actually use and finish
                            // the adopted engine, rather than merely claiming
                            // it before A's admission is released.
                            let Some(reclaimed_allocation) = allocator.allocate(request, false)
                            else {
                                core::mem::forget(allocator);
                                retain_current_thread_detached_owner_exit();
                                return TicketZeroOwnerExitFreeOutcome::Poisoned(
                                    TicketZeroOwnerExitRoutePoisoned { admission },
                                );
                            };
                            let mut reclaimed_allocation = Some(reclaimed_allocation);
                            if clients.free_locals(&mut allocator).is_err()
                                || free_owner_exit_locals(
                                    &mut allocator,
                                    core::slice::from_mut(&mut reclaimed_allocation),
                                )
                                .is_err()
                            {
                                core::mem::forget(allocator);
                                retain_current_thread_detached_owner_exit();
                                return TicketZeroOwnerExitFreeOutcome::Poisoned(
                                    TicketZeroOwnerExitRoutePoisoned { admission },
                                );
                            }
                            if let Err(failure) = allocator.finish() {
                                core::mem::forget(failure);
                                retain_current_thread_detached_owner_exit();
                                return TicketZeroOwnerExitFreeOutcome::Poisoned(
                                    TicketZeroOwnerExitRoutePoisoned { admission },
                                );
                            }
                            let has_remaining_clients = !clients.is_empty();
                            return detached_owner_exit_released_all(
                                &mut clients,
                                has_remaining_clients,
                                admission,
                            );
                        }
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularPagesAdoptFailure::Rejected {
                                route: returned,
                                ..
                            },
                        ) => route = returned,
                        Err(
                            MainHeapThreadProcessPageExitMappedRegularPagesAdoptFailure::Retained {
                                adoption,
                                ..
                            },
                        ) => {
                            // The short route became B's long map lifecycle.
                            // It cannot resume ordinary aggregate freeing or
                            // B's no-page finalizer, so retain both workers.
                            core::mem::forget(adoption);
                            retain_current_thread_detached_owner_exit();
                            return TicketZeroOwnerExitFreeOutcome::Poisoned(
                                TicketZeroOwnerExitRoutePoisoned { admission },
                            );
                        }
                    }
                }
            }

            let block = if let Some(mut remote_group) = post_exit_remote_publication_group.take() {
                let block = remote_group.take_next();
                if !remote_group.is_empty() {
                    post_exit_remote_publication_group = Some(remote_group);
                }
                block
            } else {
                clients.take_next().map(|client| client.block)
            };
            let Some(block) = block else {
                // A complete route must report `ReleasedAll` while consuming
                // one ledger entry. Retain an impossible residual source
                // route rather than turning an empty client set into a forged
                // completion proof.
                return TicketZeroOwnerExitFreeOutcome::Retained(Self {
                    route,
                    clients,
                    post_exit_remote_publication_group,
                    pair,
                    admission,
                    _consumer: PhantomData,
                });
            };
            // SAFETY: this opaque route owns the exact current private client
            // and the only aggregate post-exit route that can consume it.
            let has_remaining_clients = !clients.is_empty()
                || post_exit_remote_publication_group
                    .as_ref()
                    .is_some_and(|remote_group| !remote_group.is_empty());
            let free = unsafe { route.remote_free_after_thread_exit(block) };
            match classify_detached_owner_exit_free(free) {
                DetachedOwnerExitFreeStep::Continue(returned) => route = returned,
                DetachedOwnerExitFreeStep::ReleasedAll => {
                    return detached_owner_exit_released_all(
                        &mut clients,
                        has_remaining_clients,
                        admission,
                    );
                }
                DetachedOwnerExitFreeStep::Retained(returned) => {
                    return TicketZeroOwnerExitFreeOutcome::Retained(Self {
                        route: returned,
                        clients,
                        post_exit_remote_publication_group,
                        pair,
                        admission,
                        _consumer: PhantomData,
                    });
                }
                DetachedOwnerExitFreeStep::Poisoned => {
                    return TicketZeroOwnerExitFreeOutcome::Poisoned(
                        TicketZeroOwnerExitRoutePoisoned {
                            admission,
                        },
                    );
                }
            }
        }
    }

    /// Consumes this opaque A-side route from one fresh joined B worker and
    /// completes B's independent no-page runtime lifecycle before returning
    /// A's terminal result.
    ///
    /// B receives neither an A client address nor A's detached attachment. It
    /// may use [`finish_current_thread_after_user_destructors`] only for the
    /// new B attachment that this method creates. A's admission remains in
    /// this route until its private drain has terminally released every page,
    /// either through aggregate `ReleasedAll` or a consumed final-member
    /// target engine. Only the caller that receives the returned typed proof
    /// may then finish A's already-detached lifecycle. If B cannot complete
    /// its own lifecycle after A's route released, the A proof is converted
    /// into a terminal poisoned outcome so neither admission is made
    /// fork-quiescent by an unrelated normal finalizer.
    ///
    /// The receiver must run on one fresh joined worker. An existing attached
    /// worker has its own caller-owned lifecycle and is rejected without
    /// consuming the route.
    pub fn free_remaining_in_fresh_runtime_worker(
        self,
    ) -> TicketZeroOwnerExitFreeOutcome<'main> {
        self.free_remaining_in_fresh_runtime_worker_with_publisher(None)
    }

    /// Consumes this opaque A-side route from fresh joined B while scoped C/D
    /// workers publish two direct-small private clients after B's direct
    /// source claim.
    ///
    /// This bounded adapter seam is intentionally narrower than a general
    /// concurrent free entry point. C receives no client address, route,
    /// PageMap, or collector capability; the callback must publish and join
    /// before B resumes its existing source collector. B still completes its
    /// own no-page lifecycle before the returned terminal proof can release
    /// A's admission claim.
    pub fn free_remaining_in_fresh_runtime_worker_with_post_exit_publisher(
        self,
        publisher: TicketZeroOwnerExitRemoteFreePublisher,
    ) -> TicketZeroOwnerExitFreeOutcome<'main> {
        self.free_remaining_in_fresh_runtime_worker_with_publisher(Some(
            TicketZeroOwnerExitPostExitPublisher::DirectSmall(publisher),
        ))
    }

    /// Consumes this opaque A-side route from fresh joined B while scoped C/D
    /// workers publish two private clients from the one source-mapped,
    /// non-full medium page selected during A's owner exit.
    ///
    /// The mapped-medium callback is nominally distinct from the direct-small
    /// callback. A mismatch retains this exact route without exposing a
    /// client address or falling through to ordinary no-page finalization.
    /// The callback remains synchronous: it can append only to B's held
    /// source remote head, and B remains the only collector and terminal
    /// release owner.
    pub fn free_remaining_in_fresh_runtime_worker_with_post_exit_mapped_medium_publisher(
        self,
        publisher: TicketZeroOwnerExitMappedMediumRemoteFreePublisher,
    ) -> TicketZeroOwnerExitFreeOutcome<'main> {
        self.free_remaining_in_fresh_runtime_worker_with_publisher(Some(
            TicketZeroOwnerExitPostExitPublisher::MappedMedium(publisher),
        ))
    }

    fn free_remaining_in_fresh_runtime_worker_with_publisher(
        self,
        publisher: Option<TicketZeroOwnerExitPostExitPublisher>,
    ) -> TicketZeroOwnerExitFreeOutcome<'main> {
        match attach_current_thread() {
            ThreadAttachResult::Attached => {}
            ThreadAttachResult::Inactive
            | ThreadAttachResult::AlreadyAttached
            | ThreadAttachResult::Finished
            | ThreadAttachResult::Retained => {
                return TicketZeroOwnerExitFreeOutcome::Retained(self);
            }
        }

        let outcome = {
            let slot = current_thread_slot();
            let Some(attachment) = slot.attachment.as_mut() else {
                return TicketZeroOwnerExitFreeOutcome::Retained(self);
            };
            match publisher {
                Some(publisher) => {
                    self.free_remaining_with_post_exit_publisher(attachment, publisher)
                }
                None => self.free_remaining(attachment),
            }
        };
        match finish_current_thread_after_user_destructors() {
            ThreadFinishResult::Finished => outcome,
            ThreadFinishResult::NotAttached
            | ThreadFinishResult::AlreadyFinished
            | ThreadFinishResult::Retained => match outcome {
                TicketZeroOwnerExitFreeOutcome::Finished(proof) => {
                    // The route is physically released, but B's new runtime
                    // attachment did not finish. Keep A's exact admission
                    // terminally represented alongside B's retained TLS
                    // admission instead of treating either worker as a
                    // completed owner.
                    TicketZeroOwnerExitFreeOutcome::Poisoned(
                        TicketZeroOwnerExitRoutePoisoned {
                            admission: proof.into_admission(),
                        },
                    )
                }
                TicketZeroOwnerExitFreeOutcome::Retained(route) => {
                    TicketZeroOwnerExitFreeOutcome::Retained(route)
                }
                TicketZeroOwnerExitFreeOutcome::Poisoned(poisoned) => {
                    TicketZeroOwnerExitFreeOutcome::Poisoned(poisoned)
                }
            },
        }
    }
}

impl TicketZeroOwnerExitReclaimRoute {
    /// Reclaims the one source-approved mapped regular page into this fresh B
    /// worker, proves a normal allocation of the same private request can use
    /// the reclaimed page, and drains that worker before returning A's
    /// terminal admission proof.
    ///
    /// A normal no-page finalizer is reached only for B, and only after B's
    /// reclaimed page engine has returned its PageMap lifecycle empty. A's
    /// admission is held in this route throughout; it can leave only in the
    /// returned [`TicketZeroOwnerExitRouteFinished`].
    pub fn reclaim_and_finish(self) -> TicketZeroOwnerExitReclaimOutcome {
        let Self {
            route,
            mut clients,
            request,
            pair,
            admission,
        } = self;
        match attach_current_thread() {
            ThreadAttachResult::Attached => {}
            ThreadAttachResult::Inactive
            | ThreadAttachResult::AlreadyAttached
            | ThreadAttachResult::Finished
            | ThreadAttachResult::Retained => {
                return TicketZeroOwnerExitReclaimOutcome::Retained(Self {
                    route,
                    clients,
                    request,
                    pair,
                    admission,
                });
            }
        }

        let slot = current_thread_slot();
        let Some(attachment) = slot.attachment.as_mut() else {
            // A successful admission without its corresponding attachment is
            // an impossible runtime image. B may not silently finish, and A
            // may not release its independent post-exit claim.
            retain_current_thread_detached_owner_exit();
            return TicketZeroOwnerExitReclaimOutcome::Poisoned(
                TicketZeroOwnerExitRoutePoisoned {
                    admission,
                },
            );
        };

        let mut allocator = match route.adopt_into_later_main(attachment, pair) {
            Ok(allocator) => allocator,
            Err(MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                route,
                ..
            }) => {
                // The source route was unchanged, but B's attached lifecycle
                // is now an opaque terminal witness. Do not run the generic
                // finish while a capability-bound reclaim operation has been
                // refused; retention keeps both admissions visible.
                retain_current_thread_detached_owner_exit();
                return TicketZeroOwnerExitReclaimOutcome::Retained(Self {
                    route,
                    clients,
                    request,
                    pair,
                    admission,
                });
            }
            Err(MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                adoption,
                ..
            }) => {
                // The short route already transferred to B's long mutation
                // lifecycle. It has no safe reverse conversion, so preserve
                // both the source page owner and B's admission terminally.
                core::mem::forget(adoption);
                retain_current_thread_detached_owner_exit();
                return TicketZeroOwnerExitReclaimOutcome::Poisoned(
                    TicketZeroOwnerExitRoutePoisoned {
                        admission,
                    },
                );
            }
            Err(MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                adoption,
                ..
            }) => {
                // A direct page-area commit failure has already reabandoned
                // the exact source page under B's long same-candidate owner.
                // This bounded runtime witness does not expose retry through
                // its opaque C callback boundary.
                core::mem::forget(adoption);
                retain_current_thread_detached_owner_exit();
                return TicketZeroOwnerExitReclaimOutcome::Poisoned(
                    TicketZeroOwnerExitRoutePoisoned {
                        admission,
                    },
                );
            }
        };

        // The source adoption returned a page with an immediate local head.
        // One allocation proves that B actually uses this reclaimed engine
        // before it consumes every inherited private client.
        let Some(reclaimed_allocation) = allocator.allocate(request, false)
        else {
            core::mem::forget(allocator);
            retain_current_thread_detached_owner_exit();
            return TicketZeroOwnerExitReclaimOutcome::Poisoned(
                TicketZeroOwnerExitRoutePoisoned {
                    admission,
                },
            );
        };
        let mut reclaimed_allocation = Some(reclaimed_allocation);
        if clients.free_locals(&mut allocator).is_err()
            || free_owner_exit_locals(
                &mut allocator,
                core::slice::from_mut(&mut reclaimed_allocation),
            )
            .is_err()
        {
            core::mem::forget(allocator);
            retain_current_thread_detached_owner_exit();
            return TicketZeroOwnerExitReclaimOutcome::Poisoned(
                TicketZeroOwnerExitRoutePoisoned {
                    admission,
                },
            );
        }
        if let Err(failure) = allocator.finish() {
            // A retained allocator still owns B's PageMap lifecycle. Neither
            // B's normal finalizer nor A's typed admission completion is
            // legal after this ambiguity.
            core::mem::forget(failure);
            retain_current_thread_detached_owner_exit();
            return TicketZeroOwnerExitReclaimOutcome::Poisoned(
                TicketZeroOwnerExitRoutePoisoned {
                    admission,
                },
            );
        }

        match finish_current_thread_after_user_destructors() {
            ThreadFinishResult::Finished => {
                TicketZeroOwnerExitReclaimOutcome::Finished(TicketZeroOwnerExitRouteFinished {
                    admission,
                })
            }
            ThreadFinishResult::NotAttached
            | ThreadFinishResult::AlreadyFinished
            | ThreadFinishResult::Retained => {
                TicketZeroOwnerExitReclaimOutcome::Poisoned(
                    TicketZeroOwnerExitRoutePoisoned {
                        admission,
                    },
                )
            }
        }
    }
}

/// The adapter-supplied, joined B-side consumer for the private Gate 5C
/// witness. Outside this module, the route exposes only
/// [`TicketZeroOwnerExitFreeRoute::free_remaining_in_fresh_runtime_worker`],
/// which creates and finishes only B's new no-page attachment. The
/// higher-ranked function pointer prevents retaining the route beyond the
/// source owner's completed lifecycle boundary.
#[doc(hidden)]
pub type TicketZeroOwnerExitFreeConsumer = for<'owner> fn(
    TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner>;

/// The adapter-supplied, joined B-side consumer for the source-valid
/// owner-exit reclamation witness. It receives no client address, PageMap
/// lease, or admission token beyond the opaque linear route itself.
#[doc(hidden)]
pub type TicketZeroOwnerExitReclaimConsumer = fn(
    TicketZeroOwnerExitReclaimRoute,
) -> TicketZeroOwnerExitReclaimOutcome;

/// Two opaque source remote-free capabilities for the same stopped worker A.
/// The adapter may split and move them to two joined publisher pthreads B/C;
/// neither receiver obtains a client pointer or an owner capability.
#[doc(hidden)]
#[must_use = "both remote-free publications must be published or returned to the runtime callback"]
pub struct TicketZeroRemoteFreeProducerPair<'owner> {
    producers: RemoteFreeProducerPair<'owner>,
}

impl<'owner> TicketZeroRemoteFreeProducerPair<'owner> {
    #[inline]
    pub fn split(
        self,
    ) -> (
        TicketZeroRemoteFreeProducer<'owner>,
        TicketZeroRemoteFreeProducer<'owner>,
    ) {
        let (first, second) = self.producers.split();
        (
            TicketZeroRemoteFreeProducer { producer: first },
            TicketZeroRemoteFreeProducer { producer: second },
        )
    }

    #[inline]
    fn cancel(self) -> (core::ptr::NonNull<u8>, core::ptr::NonNull<u8>) {
        self.producers.cancel()
    }
}

/// The adapter-supplied, joined two-publisher operation for the private Gate
/// 5B witness. A higher-ranked function pointer proves the adapter cannot
/// retain either capability beyond the owner's scoped engine lifetime.
#[doc(hidden)]
pub type TicketZeroRemoteFreePublisher = for<'owner> fn(
    TicketZeroRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>>;

/// The adapter-supplied, joined one-publisher operation for one source client
/// in an active parked TLS session. The producer remains pointer-private and
/// its higher-ranked lifetime prevents the publisher from retaining it after
/// the owner has resumed.
#[doc(hidden)]
pub type TicketZeroSingleRemoteFreePublisher = for<'owner> fn(
    TicketZeroRemoteFreeProducer<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducer<'owner>>;

// The high two bits are an allocation-free fork admission gate. The low bits
// count every current later-thread attachment, including one still between its
// pre-user-code attach and post-destructor finish transitions. A fork may
// preserve the copied quiescent ticket-zero process owner only if it first
// publishes the gate, observes this count at zero, and the private predicate
// finds no active page engine or live client. The second high bit records that
// complete precondition for the raw-fork child; it is never exposed while the
// parent is allowed to admit a later owner.
const FORK_GATE_HELD: usize = 1usize << (usize::BITS - 1);
const FORK_GATE_PRESERVE: usize = 1usize << (usize::BITS - 2);
const FORK_GATE_COUNT_MASK: usize = FORK_GATE_PRESERVE - 1;

/// Result of attempting the private worker-entry lifecycle transition.
///
/// This is Rust-only control flow for `crabc-libc`; it is not a stable public
/// allocator interface and has no C ABI representation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadAttachResult {
    /// The current pthread worker owns a live no-page metadata TLD/Theap.
    Attached,
    /// The process shadow lifecycle was never activated or was retained.
    Inactive,
    /// The current thread had already published an attachment.
    AlreadyAttached,
    /// A prior terminal transition leaves this thread's retained owner live.
    Retained,
    /// A completed worker lifecycle cannot be reattached on the same thread.
    Finished,
}

/// Result of attempting the private worker-exit lifecycle transition.
///
/// This is Rust-only control flow for `crabc-libc`; it is not a stable public
/// allocator interface and has no C ABI representation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadFinishResult {
    /// The no-page source `_mi_thread_done` sequence completed exactly once.
    Finished,
    /// This thread was never attached by crabc's pthread runtime.
    NotAttached,
    /// A second finish attempt was rejected after the completed first finish.
    AlreadyFinished,
    /// An incomplete owner remains retained; no completed teardown is claimed.
    Retained,
}

/// Process-lifetime slots for the ticket-zero owner and its Heap witness.
///
/// Both values are written once before `PROCESS_ACTIVE` is Release-published
/// and are never moved, mutated, or dropped by this slice. The heap witness
/// must be minted by the ticket-zero thread before workers exist; worker TPIDR
/// identities may use only the already-published copy. The separate page-owner
/// staging slot moves exactly once, under a zero-admission gate, into the
/// initial thread's pinned compiler-TLS owner; it is unavailable afterward
/// and every legacy access is guarded by `page_owner_state`. Main-thread
/// teardown needs a complete process-exit/fork contract and remains
/// deliberately out of scope while later workers can still carry source list
/// members.
struct RuntimeProcessStorage {
    state: AtomicU8,
    /// The ticket-zero Linux/AArch64 TPIDR_EL0 identity. A copied process
    /// foundation can be preserved only when `fork` runs on this same TLS
    /// image; a foreign caller has no authority to treat the static TLD as
    /// its current-thread owner.
    initial_thread_identity: AtomicUsize,
    owner: UnsafeCell<MaybeUninit<ProcessMainThread>>,
    main_heap: UnsafeCell<MaybeUninit<MainStaticHeapLease<'static>>>,
    /// The ticket-zero staging owner is absent until the private native seam
    /// asks it for a valid allocation. It stays here only until the one-time
    /// zero-admission promotion into pinned initial TLS; afterward
    /// `PAGE_OWNER_INITIAL_PERSISTENT` keeps legacy static-slot access closed.
    page_owner_state: AtomicUsize,
    /// Counts only detached routes whose source aggregate still owns live
    /// page clients. This is deliberately narrower than `page_owner_state`'s
    /// parked-token count: a terminal route has moved its token into B's
    /// no-page completion, and ticket zero must remain unavailable until that
    /// B lifecycle consumes the token. A source-active route, by contrast,
    /// lets ticket zero run a private operation beside its separate token.
    active_post_exit_route_count: AtomicUsize,
    /// Counts terminal source routes that have moved their parked scheduler
    /// token into a matched B worker's no-page completion. This is separate
    /// from source-active routes: even another live route must not reopen
    /// ticket zero while any B still owes the terminal lifecycle that releases
    /// its exact A-side worker-admission claim.
    pending_post_exit_completion_count: AtomicUsize,
    /// Counts routes whose source transition has become terminally retained.
    /// Such a route keeps its scheduler token and A-side admission forever,
    /// but has no matched B completion that could consume it. It must stop
    /// ticket zero even if a separate route remains source-active; otherwise
    /// that live sibling would accidentally turn a retained terminal owner
    /// back into a private-operation admission.
    retained_post_exit_route_count: AtomicUsize,
    page_owner: UnsafeCell<MaybeUninit<MainStaticRuntimeFirstArenaPageAllocator>>,
}

/// One runtime-owned claim that ticket zero has lent its dormant process pair
/// to exactly one *active* normal page-engine operation.
///
/// The pair itself remains private to the transition into
/// [`MainHeapThreadProcessPageAllocator`]. A completed operation restores the
/// exact prior parked-owner count, while a normal suspension publishes that
/// count plus itself. Multiple suspended engines therefore remain distinct
/// current-thread tokens even though the runtime admits only one active PageMap
/// mutation at once. Dropping an unfinished claim retains the process instead
/// of reopening ticket zero over a possibly live map entry.
#[must_use = "a runtime dormant-pair operation must finish, park, or retain its page owner"]
struct RuntimeDormantPageOperation {
    runtime: &'static RuntimeProcessStorage,
    pair: Option<ProcessPageArenaLease>,
    /// Scheduler state to restore when this engine completely finishes. A
    /// fresh engine preserves every pre-existing parked owner, while a
    /// resumed parked engine removes only itself.
    finish_state: usize,
    /// Scheduler state to restore when this engine releases just its long
    /// PageMap guard into a current-thread suspended token. This includes the
    /// engine itself and every independently parked peer.
    park_state: usize,
    may_park: bool,
    active: bool,
}

/// One detached post-exit owner represented in the runtime scheduler's
/// parked-owner count.
///
/// The source route itself owns the `ProcessPageMapPostExitAccess` that
/// serializes each exact free. This token represents only its outstanding
/// ticket-zero exclusion: it remains parked while the route has live clients
/// and through the fresh B worker's ordinary no-page finish. It may decrement
/// exactly one parked owner only after that B lifecycle has detached.
#[must_use = "a parked detached post-exit token must finish with B or remain terminally retained"]
struct RuntimeParkedPostExitRoute {
    runtime: &'static RuntimeProcessStorage,
    /// The source route still owns at least one exact client. Once its final
    /// exact free produces B's typed completion, this becomes false before
    /// the scheduler token can wait for B's ordinary no-page finish.
    source_route_active: bool,
    /// The source route has terminally released and this still-parked token
    /// now belongs to a matched B no-page completion. Ticket zero remains
    /// unavailable until that B finishes and consumes this exact token.
    terminal_completion_pending: bool,
    /// The source route has reached an unrecoverable terminal state instead
    /// of minting a B completion. Its scheduler token remains permanently
    /// represented, so ticket zero cannot borrow beside a live sibling route.
    terminal_retained: bool,
    active: bool,
}

/// One live normal later-main engine while the runtime has its `BUSY` page
/// owner claim.
///
/// It exposes only the existing ordinary allocation/free operations and the
/// typed persistent split. It deliberately has no detached-owner finalizer,
/// raw process-pair accessor, or remote-producer escape hatch. A normal
/// operation may park as its own current-thread token; a scoped interleaving
/// operation remains non-parkable and must finish empty before any parked
/// owner resumes.
#[must_use = "a runtime persistent page engine must finish, park, or retain its page owner"]
struct RuntimePersistentPageEngine<'attachment, 'main> {
    allocator: Option<MainHeapThreadProcessPageAllocator<'attachment, 'main>>,
    operation: Option<RuntimeDormantPageOperation>,
    // `ProcessPageArenaLease` is an immutable, identity-checked view. Keep
    // the exact pair alongside the live engine so a source post-exit route
    // that permits later-main adoption can carry that same checked identity
    // to its fresh consumer after the old allocator drains.
    pair: ProcessPageArenaLease,
}

/// One current-thread-only persistent engine state after its normal PageMap
/// guard has been released between complete operations.
///
/// This is not an abandoned/post-exit route. Its only successful transition
/// reacquires `BUSY` for this same owner and resumes against that attachment's
/// explicit suspended-session marker. Other parked owners remain represented
/// only by their own typed tokens while the current token holds the serialized
/// mutation operation. A drop makes both the map and the runtime page owner
/// terminal.
#[must_use = "a runtime parked engine must resume or retain its exact live state"]
struct RuntimeParkedPersistentPageEngine {
    runtime: &'static RuntimeProcessStorage,
    paused: Option<MainHeapThreadPausedProcessPageAllocator>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePersistentPageEngineBeginError {
    Unavailable,
    /// A separately typed bounded operation currently owns the lower
    /// PageMap mutation lease. The runtime scheduler claim was restored to
    /// its exact prior parked state, so a session start may retry after that
    /// operation completes.
    PageMapBusy,
    Attachment(MainHeapThreadProcessPageAllocatorBeginError),
}

#[must_use = "a failed runtime persistent-engine suspension retains its exact owner"]
enum RuntimePersistentPageEngineSuspendFailure<'attachment, 'main> {
    /// The live engine was unchanged; only its original A-side runtime claim
    /// may retry the split.
    Rejected {
        engine: RuntimePersistentPageEngine<'attachment, 'main>,
        error: MainHeapThreadAttachmentError,
    },
    /// A scoped interleaving operation runs while one or more normal engines
    /// are parked. It must complete rather than becoming another suspended
    /// current-thread owner.
    InterleavingOperation {
        engine: RuntimePersistentPageEngine<'attachment, 'main>,
    },
    /// The PageMap wake boundary failed after releasing the long guard. The
    /// separated state and runtime page owner are terminal.
    Retained {
        terminal: MainHeapThreadPersistentPageEngineTerminal,
        error: ProcessPageMapError,
    },
    /// The runtime state no longer named this exact active operation.
    PageOwnerRetained,
}

#[must_use = "a failed runtime persistent-engine resume retains its exact state token"]
enum RuntimePersistentPageEngineResumeFailure {
    /// Another complete operation currently owns the runtime's `BUSY` claim.
    /// The A-side token remains intact and may retry after that operation.
    Unavailable {
        parked: RuntimeParkedPersistentPageEngine,
    },
    /// The matching attachment rejected before its suspended marker changed.
    Rejected {
        parked: RuntimeParkedPersistentPageEngine,
        error: MainHeapThreadPageSessionError,
    },
    /// A non-runtime page lifecycle temporarily owns the plain PageMap guard.
    /// The A-side token remains intact and may retry once it finishes.
    PageMapBusy {
        parked: RuntimeParkedPersistentPageEngine,
        error: ProcessPageMapError,
    },
    /// The lower PageMap handoff became terminal and retained the separated
    /// normal engine state.
    Retained {
        terminal: MainHeapThreadPersistentPageEngineTerminal,
        error: ProcessPageMapError,
    },
    PageOwnerRetained,
}

#[must_use = "a failed runtime persistent-engine finish retains its exact source owner"]
enum RuntimePersistentPageEngineFinishFailure<'attachment, 'main> {
    Allocator(MainHeapThreadProcessPageAllocatorFinishError<'attachment, 'main>),
    PageOwnerRetained,
}

// SAFETY: the COLD -> INITIALIZING CAS gives one writer exclusive access to
// `owner`; the final owner is written before PROCESS_ACTIVE's Release store
// and is thereafter read immutably. The independent page-owner scheduler
// admits ticket zero only from READY and one complete later-main mutation at
// a time; parked engines hold only current-thread typed tokens. Terminal
// retention never mutates either owner.
unsafe impl Sync for RuntimeProcessStorage {}

impl RuntimeDormantPageOperation {
    /// Restores this scheduler operation after a lower PageMap `try_lock`
    /// refusal that happened before it borrowed a session or mutated an
    /// engine. The process pair is immutable and Copy, but placing it back in
    /// the linear operation documents that this exact active claim—not a
    /// reconstructed substitute—returns to its prior scheduler state.
    fn restore_after_page_map_busy(
        mut self,
        pair: ProcessPageArenaLease,
    ) -> Result<(), Self> {
        debug_assert!(self.pair.is_none());
        self.pair = Some(pair);
        let finish_state = self.finish_state;
        self.settle(finish_state)
    }

    fn begin_engine<'attachment, 'main>(
        mut self,
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<
        RuntimePersistentPageEngine<'attachment, 'main>,
        RuntimePersistentPageEngineBeginError,
    > {
        let pair = self
            .pair
            .take()
            .expect("a runtime dormant-pair operation retains its one private pair");
        match MainHeapThreadProcessPageAllocator::begin(attachment, pair) {
            Ok(allocator) => Ok(RuntimePersistentPageEngine {
                allocator: Some(allocator),
                operation: Some(self),
                pair,
            }),
            // `MainHeapThreadProcessPageAllocator::begin` reaches this exact
            // error only when `begin_page_lifecycle`'s nonblocking lock
            // refuses before it can construct a mutable page engine. Its
            // temporary page-session borrow has already ended, the immutable
            // pair is still valid, and another bounded operation (commonly a
            // post-exit exact free) merely owns the lower map boundary. Put
            // the runtime claim back before retrying; dropping it would turn
            // ordinary concurrency into terminal retention.
            Err(
                error @ MainHeapThreadProcessPageAllocatorBeginError::Pair(
                    ProcessPageArenaLeaseError::PageMap(ProcessPageMapError::LifecycleBusy),
                ),
            ) => match self.restore_after_page_map_busy(pair) {
                Ok(()) => Err(RuntimePersistentPageEngineBeginError::PageMapBusy),
                Err(operation) => {
                    // The lower refusal itself was replayable, but the
                    // scheduler no longer recognizes this exact BUSY claim.
                    // `Drop` keeps that ambiguous state terminal instead of
                    // reopening the pair under a reconstructed state.
                    drop(operation);
                    Err(RuntimePersistentPageEngineBeginError::Attachment(error))
                }
            },
            // The PageMap/attachment constructor does not return a safely
            // replayable post-mutation capability. Let this operation's Drop
            // retain the runtime rather than attempting to infer which lower
            // preflight, lease, or source-session state may be retried.
            Err(error) => Err(RuntimePersistentPageEngineBeginError::Attachment(error)),
        }
    }

    #[inline]
    fn finish_state(&self) -> usize {
        self.finish_state
    }

    /// Converts this active normal-engine scheduler claim into one parked
    /// detached-route token after source owner exit released the long
    /// PageMap lease into `ProcessPageMapPostExitAccess`.
    ///
    /// The route remains unable to reopen ticket zero because its token adds
    /// one parked owner. Unlike a suspended normal engine, it has no
    /// attachment-bound allocator state to resume: its already-detached
    /// source route acquires the PageMap boundary independently for each
    /// exact free.
    fn park_detached_post_exit(self) -> Result<RuntimeParkedPostExitRoute, Self> {
        if !self.may_park {
            self.runtime.retain_page_owner();
            return Err(self);
        }
        let runtime = self.runtime;
        let park_state = self.park_state;
        if !runtime.register_active_post_exit_route() {
            return Err(self);
        }
        match self.settle(park_state) {
            Ok(()) => Ok(RuntimeParkedPostExitRoute {
                runtime,
                source_route_active: true,
                terminal_completion_pending: false,
                terminal_retained: false,
                active: true,
            }),
            Err(operation) => {
                // `settle` has already made the scheduler terminal. Restore
                // the narrower source-route count nevertheless so no
                // diagnostic/audit path can mistake a failed publication for
                // a live source route.
                let _ = runtime.unregister_active_post_exit_route();
                Err(operation)
            }
        }
    }

    fn settle(mut self, next_state: usize) -> Result<(), Self> {
        if self.active
            && self
                .runtime
                .page_owner_state
                .compare_exchange(
                    PAGE_OWNER_BUSY,
                    next_state,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            self.active = false;
            return Ok(());
        }
        self.runtime.retain_page_owner();
        Err(self)
    }
}

impl Drop for RuntimeDormantPageOperation {
    fn drop(&mut self) {
        if self.active {
            // An active engine may still own PageMap entries or a paired
            // source attachment. Never convert an abandoned runtime claim
            // into `READY` or a parked-owner count merely because its Rust
            // wrapper fell out of scope.
            self.runtime.retain_page_owner();
        }
    }
}

impl RuntimeParkedPostExitRoute {
    /// Converts this token from a source-active detached route into B's
    /// terminal no-page completion. The token itself stays parked until B
    /// detaches, but ticket zero may no longer borrow beside it because no
    /// source route remains to justify that narrower exception.
    fn finish_source_route(mut self) -> Result<Self, Self> {
        if !self.source_route_active
            || self.terminal_retained
            || !self.runtime.register_pending_post_exit_completion()
            || !self.runtime.unregister_active_post_exit_route()
        {
            self.runtime.retain_page_owner();
            return Err(self);
        }
        self.source_route_active = false;
        self.terminal_completion_pending = true;
        Ok(self)
    }

    /// Converts a source-active route into a permanent terminal blocker when
    /// its exact source transition cannot be retried or completed. This is
    /// distinct from [`Self::finish_source_route`]: there is no B completion
    /// capable of consuming this token, but a still-live sibling route must
    /// not make ticket zero treat it as an ordinary source-active token.
    fn retain_source_route(mut self) -> Result<Self, Self> {
        if !self.source_route_active
            || self.terminal_completion_pending
            || self.terminal_retained
            || !self.runtime.register_retained_post_exit_route()
            || !self.runtime.unregister_active_post_exit_route()
        {
            self.runtime.retain_page_owner();
            return Err(self);
        }
        self.source_route_active = false;
        self.terminal_retained = true;
        Ok(self)
    }

    /// Removes this exact detached route from the scheduler only after its
    /// matched B worker has completed ordinary no-page teardown.
    ///
    /// No PageMap mutation occurs here: the terminal exact free completed
    /// that source lifecycle under its route-owned short access before it
    /// created the B-side completion. A direct parked-count transition keeps
    /// other detached routes and independently parked normal engines intact.
    fn finish_after_b(mut self) -> Result<(), Self> {
        if self.source_route_active || self.terminal_retained || !self.terminal_completion_pending {
            // Only a terminal exact free can convert a source route into a
            // B completion. Removing the scheduler token before that proof
            // would make ticket zero appear reusable over live A clients.
            self.runtime.retain_page_owner();
            return Err(self);
        }
        loop {
            let observed = self.runtime.page_owner_state.load(Ordering::Acquire);
            if observed == PAGE_OWNER_BUSY {
                // A distinct normal engine or exact detached-route free is
                // completing its serialized PageMap operation. This B-side
                // no-page finish owns no map state, so wait for the scheduler
                // to republish the parked-owner count instead of treating
                // ordinary cross-route activity as terminal corruption.
                core::hint::spin_loop();
                continue;
            }
            let Some(parked_count) = page_owner_parked_count(observed).filter(|count| *count > 0)
            else {
                self.runtime.retain_page_owner();
                return Err(self);
            };
            let Some(next_state) = page_owner_parked_state(parked_count - 1) else {
                self.runtime.retain_page_owner();
                return Err(self);
            };
            if self
                .runtime
                .page_owner_state
                .compare_exchange_weak(observed, next_state, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if !self.runtime.finish_pending_post_exit_completion() {
                    // The scheduler token already left its parked count, but
                    // the matching B completion accounting disagreed. The
                    // process is terminal; keep this concrete capability
                    // alive rather than reporting an ordinary finish.
                    self.runtime.retain_page_owner();
                    return Err(self);
                }
                self.terminal_completion_pending = false;
                self.active = false;
                return Ok(());
            }
        }
    }
}

impl Drop for RuntimeParkedPostExitRoute {
    fn drop(&mut self) {
        if self.active {
            // A detached route still owns source page state or an unconsumed
            // B-side completion. It must never vanish from the parked count
            // and make ticket zero look reusable.
            self.runtime.retain_page_owner();
        }
    }
}

impl<'attachment, 'main> RuntimePersistentPageEngine<'attachment, 'main> {
    #[inline]
    fn allocate(&mut self, request: usize, zero: bool) -> Option<core::ptr::NonNull<u8>> {
        self.allocator
            .as_mut()
            .expect("a runtime persistent engine retains its normal allocator")
            .allocate(request, zero)
    }

    /// # Safety
    ///
    /// `block` must remain a current local allocation of this exact live
    /// engine. It may not have crossed a producer, post-exit route, or any
    /// foreign pointer domain.
    #[inline]
    unsafe fn free(
        &mut self,
        block: core::ptr::NonNull<u8>,
    ) -> Result<(), crate::single_thread::FreeError> {
        // SAFETY: forwarded unchanged from this wrapper's exact local-block
        // contract.
        unsafe {
            self.allocator
                .as_mut()
                .expect("a runtime persistent engine retains its normal allocator")
                .free(block)
        }
    }

    /// Publishes one exact block to a separately parked live owner's source
    /// remote head. A complete B operation may be a fresh scoped
    /// interleaving or the temporary resume of B's already parked session;
    /// either way this wrapper exposes neither the allocator nor its PageMap
    /// lease to the native libc boundary.
    ///
    /// # Safety
    ///
    /// `block` must be a current C-facing client recorded in the parked A
    /// session whose exact registry entry admitted this B operation.
    #[inline]
    unsafe fn publish_remote_free_to_parked_live_owner(
        &mut self,
        block: core::ptr::NonNull<u8>,
    ) -> Result<(), crate::single_thread::RemoteFreePreparationError> {
        unsafe {
            self.allocator
                .as_mut()
                .expect("a runtime persistent engine retains its normal allocator")
                .publish_remote_free_to_parked_live_owner(block)
        }
    }

    /// Runs the one fixed Gate 5A mixed-local workload through this exact
    /// runtime-owned engine. This is intentionally not an allocator escape
    /// hatch: the workload keeps every client private and uses only ordinary
    /// local allocation/free before the operation's typed finish.
    #[inline]
    fn run_persistent_local_workload(&mut self) -> Result<(), PersistentLocalWorkerError> {
        run_persistent_local_worker_workload(
            self.allocator
                .as_mut()
                .expect("a runtime persistent engine retains its normal allocator"),
        )
    }

    /// Runs the one fixed Gate 5B live-owner remote-free workload through
    /// this exact runtime-owned engine. The publisher receives only the two
    /// opaque remote-free capabilities; it cannot borrow this engine, its
    /// PageMap lease, or any client address.
    #[inline]
    fn run_persistent_remote_workload(
        &mut self,
        publish: TicketZeroRemoteFreePublisher,
    ) -> Result<(), PersistentRemoteWorkerError> {
        run_persistent_remote_worker_workload(
            self.allocator
                .as_mut()
                .expect("a runtime persistent engine retains its normal allocator"),
            publish,
        )
    }

    fn suspend(
        mut self,
    ) -> Result<
        RuntimeParkedPersistentPageEngine,
        RuntimePersistentPageEngineSuspendFailure<'attachment, 'main>,
    > {
        let allocator = self
            .allocator
            .take()
            .expect("a runtime persistent engine retains its normal allocator");
        let operation = self
            .operation
            .take()
            .expect("a runtime persistent engine retains its page-owner claim");
        if !operation.may_park {
            self.allocator = Some(allocator);
            self.operation = Some(operation);
            return Err(
                RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine: self },
            );
        }

        let runtime = operation.runtime;
        let park_state = operation.park_state;
        match allocator.suspend_persistent() {
            Ok(paused) => match operation.settle(park_state) {
                Ok(()) => Ok(RuntimeParkedPersistentPageEngine {
                    runtime,
                    paused: Some(paused),
                }),
                Err(operation) => {
                    // The lower token owns a live engine and its map access;
                    // both drops deliberately retain/poison rather than
                    // manufacturing a state repair after an impossible
                    // runtime-state mismatch.
                    drop(paused);
                    drop(operation);
                    Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained)
                }
            },
            Err(MainHeapThreadProcessPageAllocatorSuspendFailure::Rejected {
                allocator,
                error,
            }) => {
                self.allocator = Some(allocator);
                self.operation = Some(operation);
                Err(RuntimePersistentPageEngineSuspendFailure::Rejected {
                    engine: self,
                    error,
                })
            }
            Err(MainHeapThreadProcessPageAllocatorSuspendFailure::Retained { terminal, error }) => {
                drop(operation);
                Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, error })
            }
        }
    }

    fn finish(
        mut self,
    ) -> Result<(), RuntimePersistentPageEngineFinishFailure<'attachment, 'main>> {
        let allocator = self
            .allocator
            .take()
            .expect("a runtime persistent engine retains its normal allocator");
        let operation = self
            .operation
            .take()
            .expect("a runtime persistent engine retains its page-owner claim");
        let finish_state = operation.finish_state;
        match allocator.finish() {
            Ok(()) => match operation.settle(finish_state) {
                Ok(()) => Ok(()),
                Err(operation) => {
                    drop(operation);
                    Err(RuntimePersistentPageEngineFinishFailure::PageOwnerRetained)
                }
            },
            Err(error) => {
                drop(operation);
                Err(RuntimePersistentPageEngineFinishFailure::Allocator(error))
            }
        }
    }

    /// Consumes this live runtime engine into the source post-fast-slot
    /// owner-exit drain while retaining the exact dormant-pair scheduler
    /// claim.  The claim cannot return ticket zero to `READY` yet: a
    /// successful drain may move live client pages into a typed post-exit
    /// route, whose terminal proof is the only later authority to settle it.
    ///
    /// A lower drain refusal still owns a live allocator and the runtime
    /// operation, so it returns this exact wrapper for terminal retention
    /// rather than letting the caller fall through to no-page teardown.
    fn begin_thread_exit_drain(
        mut self,
    ) -> Result<
        (
            crate::main_heap_page::MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
            RuntimeDormantPageOperation,
            ProcessPageArenaLease,
        ),
        Self,
    > {
        let allocator = self
            .allocator
            .take()
            .expect("a runtime persistent engine retains its normal allocator");
        let operation = self
            .operation
            .take()
            .expect("a runtime persistent engine retains its page-owner claim");
        match allocator.begin_thread_exit_drain() {
            Ok(drain) => Ok((drain, operation, self.pair)),
            Err(MainHeapThreadProcessPageExitDrainFailure::Retained { allocator, .. }) => {
                self.allocator = Some(allocator);
                self.operation = Some(operation);
                Err(self)
            }
        }
    }
}

impl RuntimeParkedPersistentPageEngine {
    fn resume<'attachment, 'main>(
        mut self,
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<
        RuntimePersistentPageEngine<'attachment, 'main>,
        RuntimePersistentPageEngineResumeFailure,
    > {
        let paused = self
            .paused
            .take()
            .expect("a runtime parked engine retains its normal-engine token");
        let observed_state = self.runtime.page_owner_state.load(Ordering::Acquire);
        let Some(parked_count) = page_owner_parked_count(observed_state).filter(|count| *count > 0)
        else {
            self.paused = Some(paused);
            return Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked: self });
        };
        let Some(finish_state) = page_owner_parked_state(parked_count - 1) else {
            self.paused = Some(paused);
            self.runtime.retain_page_owner();
            return Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained);
        };
        let Some(operation) = self.runtime.begin_dormant_page_operation(
            observed_state,
            finish_state,
            observed_state,
            true,
        ) else {
            self.paused = Some(paused);
            return Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked: self });
        };
        let pair = operation
            .pair
            .expect("a resumed runtime operation retains its checked process pair");

        match paused.resume(attachment) {
            Ok(allocator) => Ok(RuntimePersistentPageEngine {
                allocator: Some(allocator),
                operation: Some(operation),
                pair,
            }),
            Err(MainHeapThreadPausedProcessPageAllocatorResumeFailure::Rejected {
                paused,
                error,
            }) => match operation.settle(observed_state) {
                Ok(()) => {
                    self.paused = Some(paused);
                    Err(RuntimePersistentPageEngineResumeFailure::Rejected {
                        parked: self,
                        error,
                    })
                }
                Err(operation) => {
                    drop(paused);
                    drop(operation);
                    Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained)
                }
            },
            Err(MainHeapThreadPausedProcessPageAllocatorResumeFailure::PageMapBusy {
                paused,
                error,
            }) => match operation.settle(observed_state) {
                Ok(()) => {
                    self.paused = Some(paused);
                    Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy {
                        parked: self,
                        error,
                    })
                }
                Err(operation) => {
                    drop(paused);
                    drop(operation);
                    Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained)
                }
            },
            Err(MainHeapThreadPausedProcessPageAllocatorResumeFailure::Retained {
                terminal,
                error,
            }) => {
                drop(operation);
                Err(RuntimePersistentPageEngineResumeFailure::Retained { terminal, error })
            }
        }
    }
}

impl Drop for RuntimeParkedPersistentPageEngine {
    fn drop(&mut self) {
        if self.paused.is_some() {
            // The lower token's Drop poisons the map. Pair it with the outer
            // page-owner state so ticket zero cannot reactivate over an
            // abandoned current-thread engine state.
            self.runtime.retain_page_owner();
        }
    }
}

impl RuntimeProcessStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(PROCESS_COLD),
            initial_thread_identity: AtomicUsize::new(0),
            owner: UnsafeCell::new(MaybeUninit::uninit()),
            main_heap: UnsafeCell::new(MaybeUninit::uninit()),
            page_owner_state: AtomicUsize::new(PAGE_OWNER_COLD),
            active_post_exit_route_count: AtomicUsize::new(0),
            pending_post_exit_completion_count: AtomicUsize::new(0),
            retained_post_exit_route_count: AtomicUsize::new(0),
            page_owner: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Registers one typed route while its source aggregate is still live.
    /// The route increments this narrower count before publishing its parked
    /// scheduler token, so ticket zero cannot observe a route token without
    /// the capability that permits its private interleaving.
    fn register_active_post_exit_route(&self) -> bool {
        let mut observed = self.active_post_exit_route_count.load(Ordering::Acquire);
        loop {
            let Some(next) = observed.checked_add(1) else {
                self.retain_page_owner();
                return false;
            };
            match self.active_post_exit_route_count.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next_observed) => observed = next_observed,
            }
        }
    }

    /// Removes one source-active route after its terminal exact free has
    /// created B's typed completion. The remaining parked scheduler token is
    /// intentionally not represented here: it blocks ticket zero until B
    /// completes ordinary no-page teardown.
    fn unregister_active_post_exit_route(&self) -> bool {
        let mut observed = self.active_post_exit_route_count.load(Ordering::Acquire);
        loop {
            let Some(next) = observed.checked_sub(1) else {
                self.retain_page_owner();
                return false;
            };
            match self.active_post_exit_route_count.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next_observed) => observed = next_observed,
            }
        }
    }

    #[inline]
    fn has_active_post_exit_route(&self) -> bool {
        self.active_post_exit_route_count.load(Ordering::Acquire) != 0
    }

    /// Registers one source-terminal route before it drops its source-active
    /// capability. This ordering leaves no interval in which another live
    /// route could make ticket zero appear available while B still owes a
    /// normal no-page lifecycle.
    fn register_pending_post_exit_completion(&self) -> bool {
        let mut observed = self
            .pending_post_exit_completion_count
            .load(Ordering::Acquire);
        loop {
            let Some(next) = observed.checked_add(1) else {
                self.retain_page_owner();
                return false;
            };
            match self.pending_post_exit_completion_count.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next_observed) => observed = next_observed,
            }
        }
    }

    /// Removes one B completion only after its exact parked scheduler token
    /// has left the count during B's ordinary no-page finish.
    fn finish_pending_post_exit_completion(&self) -> bool {
        let mut observed = self
            .pending_post_exit_completion_count
            .load(Ordering::Acquire);
        loop {
            let Some(next) = observed.checked_sub(1) else {
                self.retain_page_owner();
                return false;
            };
            match self.pending_post_exit_completion_count.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next_observed) => observed = next_observed,
            }
        }
    }

    #[inline]
    fn has_pending_post_exit_completion(&self) -> bool {
        self.pending_post_exit_completion_count.load(Ordering::Acquire) != 0
    }

    /// Registers one terminally retained route before it drops its
    /// source-active capability. There is deliberately no matching decrement:
    /// the route owns source state that no normal B finalizer may release.
    fn register_retained_post_exit_route(&self) -> bool {
        let mut observed = self.retained_post_exit_route_count.load(Ordering::Acquire);
        loop {
            let Some(next) = observed.checked_add(1) else {
                self.retain_page_owner();
                return false;
            };
            match self.retained_post_exit_route_count.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next_observed) => observed = next_observed,
            }
        }
    }

    #[inline]
    fn has_retained_post_exit_route(&self) -> bool {
        self.retained_post_exit_route_count.load(Ordering::Acquire) != 0
    }

    #[inline]
    fn is_active(&self) -> bool {
        self.state.load(Ordering::Acquire) == PROCESS_ACTIVE
    }

    /// Whether the process is active on the same TPIDR_EL0 image that minted
    /// ticket zero. Linux preserves that TLS image through `fork`; a newly
    /// created pthread receives a different one and cannot preserve the
    /// process-static attachment as though it owned ticket zero.
    #[inline]
    fn is_on_initial_thread(&self) -> bool {
        if !self.is_active() {
            return false;
        }
        let expected = self.initial_thread_identity.load(Ordering::Acquire);
        expected != 0
            && current_thread_identity().is_some_and(|current| current.get() == expected)
    }

    #[inline]
    fn is_quiescent_on_initial_thread_for_fork(&self) -> bool {
        if !self.is_on_initial_thread() {
            return false;
        }

        match self.page_owner_state.load(Ordering::Acquire) {
            // The historical no-page case remains valid.
            PAGE_OWNER_COLD => true,
            // The caller invokes this only after `RuntimeForkAdmission` has
            // installed its held gate while its count is zero.  That excludes
            // every later owner which could otherwise change READY into BUSY
            // and mutably borrow this final slot.  The initial thread itself
            // is crossing `fork` with signals held, so this immutable view is
            // the one safe quiescent ticket-zero inspection.
            PAGE_OWNER_READY => {
                // SAFETY: `start_ticket_zero_page_owner_with_storage` wrote
                // this final slot before its Release READY publication.  The
                // gate precondition above excludes a concurrent later-engine
                // transition, and the current initial thread owns the only
                // ticket-zero operation.
                let page_owner = unsafe { (&*self.page_owner.get()).assume_init_ref() };
                page_owner.is_quiescent_for_fork()
            }
            // The static staging slot is vacant after W01's one-time
            // ticket-zero promotion. Do not read it here: the source owner
            // now lives only in the original thread's pinned compiler-TLS
            // cell. `before_fork_with` invokes this predicate while the
            // admission gate is held at count zero, so no later owner can
            // borrow or transition that direct initial engine during this
            // temporary source-state inspection.
            PAGE_OWNER_INITIAL_PERSISTENT => {
                current_thread_initial_persistent_owner_is_quiescent_for_held_fork_gate()
            }
            // Starting, a current operation, any parked page engine, and
            // retained source state all remain outside the child contract.
            PAGE_OWNER_STARTING | PAGE_OWNER_BUSY | PAGE_OWNER_RETAINED | _ => false,
        }
    }

    /// Reconstructs the immutable source owner identity used by a remote
    /// producer targeting the permanent ticket-zero page owner.
    ///
    /// The initial thread recorded this value only after `LiveThreadId`
    /// validation during process startup. Revalidating it here keeps a
    /// malformed retained process state from being treated as a foreign
    /// page's owner identity.
    #[inline]
    fn initial_live_thread_identity(&self) -> Option<LiveThreadId> {
        LiveThreadId::new(self.initial_thread_identity.load(Ordering::Acquire))
    }

    /// Returns the process-static PageMap witness for one exact live native
    /// allocation lookup.
    ///
    /// This intentionally shares only the immutable root witness, never the
    /// permanent owner, its page lifecycle lock, or an ordinary `&mut`
    /// engine. A live allocation itself supplies the same-slice lifetime
    /// proof consumed by `ProcessPageMapLease::lookup_page_for_live_client`.
    #[inline]
    fn page_map_for_live_native_allocation(&'static self) -> Option<ProcessPageMapLease> {
        // SAFETY: the process owner is written before PROCESS_ACTIVE and is
        // never torn down by this bounded runtime. This takes only its
        // immutable ready witness; it never borrows the permanent page owner.
        let owner = unsafe { self.active_owner() }?;
        owner.ready().ok()?.page_map().ok()
    }

    /// Returns the durable ticket-zero owner after its Release publication.
    ///
    /// # Safety
    ///
    /// The storage is process-static. This slice never calls `teardown` or
    /// drops its stored owner, so a caller receiving this reference may retain
    /// a borrow-tied main-Heap lease through a worker's complete lifecycle.
    unsafe fn active_owner(&'static self) -> Option<&'static ProcessMainThread> {
        if !self.is_active() {
            return None;
        }
        // SAFETY: PROCESS_ACTIVE is stored only after this exact static slot
        // is initialized. No path overwrites or drops it thereafter.
        Some(unsafe { (&*self.owner.get()).assume_init_ref() })
    }

    /// Returns the main-thread-minted shared-Heap lease after publication.
    ///
    /// # Safety
    ///
    /// The lease is created while the ticket-zero owner is current, then
    /// stored beside that never-dropped owner before PROCESS_ACTIVE is
    /// Release-published. It is Copy and contains only process-static
    /// addresses plus the owner's lifetime witness.
    unsafe fn active_main_heap(&'static self) -> Option<MainStaticHeapLease<'static>> {
        if !self.is_active() {
            return None;
        }
        // SAFETY: PROCESS_ACTIVE follows the one write to this static slot;
        // no path overwrites or drops the stored lease.
        Some(*unsafe { (&*self.main_heap.get()).assume_init_ref() })
    }

    fn retain(&self) {
        self.state.store(PROCESS_RETAINED, Ordering::Release);
    }

    /// Makes the permanent native page owner terminal together with the
    /// runtime bridge. This is the only fallback for a runtime scheduler
    /// claim that can no longer prove whether its live engine, PageMap lease,
    /// or current-thread attachment still owns source state.
    #[inline]
    fn retain_page_owner(&self) {
        self.retain();
        self.page_owner_state
            .store(PAGE_OWNER_RETAINED, Ordering::Release);
    }

    /// Starts the hidden ticket-zero native owner without reserving an arena.
    ///
    /// This uses only the immutable process coordinator: the permanent
    /// session itself is designed to coexist with the copied shared-main Heap
    /// witness already held by pthread lifecycle code. Any startup failure is
    /// terminal, because retrying could reuse a partially claimed ticket-zero
    /// page image under a different process/lifecycle observation.
    fn start_ticket_zero_page_owner(&'static self) -> bool {
        self.start_ticket_zero_page_owner_with_storage(ProcessSharedArenaStorage::global())
    }

    fn start_ticket_zero_page_owner_with_storage(
        &'static self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> bool {
        if !self.is_on_initial_thread() {
            return false;
        }
        match self.page_owner_state.compare_exchange(
            PAGE_OWNER_COLD,
            PAGE_OWNER_STARTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                #[cfg(feature = "native-runtime-test-audit")]
                note_native_scheduler_transition();
            }
            Err(PAGE_OWNER_READY) => return true,
            Err(observed) if page_owner_parked_count(observed).is_some() => return true,
            Err(PAGE_OWNER_STARTING | PAGE_OWNER_BUSY | PAGE_OWNER_RETAINED | _) => return false,
        }

        // SAFETY: PROCESS_ACTIVE follows the final owner write. This only
        // takes its shared immutable view; `ProcessMainThread` converts the
        // static attachment through its shared permanent-session transition,
        // so it never conflicts with the stored main-Heap lease.
        let Some(owner) = (unsafe { self.active_owner() }) else {
            self.retain();
            self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
            return false;
        };
        let page_map = match owner.ready().and_then(|ready| ready.page_map()) {
            Ok(page_map) => page_map,
            Err(_) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                return false;
            }
        };
        let session = match owner.begin_process_lifetime_page_session() {
            Ok(session) => session,
            Err(_) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                return false;
            }
        };
        let page_owner = match MainStaticRuntimeFirstArenaPageAllocator::begin(
            session,
            page_map,
            arena_storage,
        ) {
            Ok(owner) => owner,
            Err(_) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                return false;
            }
        };
        // SAFETY: this COLD -> STARTING winner remains the sole writer until
        // the READY publication below. The stored owner is process-lifetime
        // and no path drops or replaces it.
        unsafe { (*self.page_owner.get()).write(page_owner) };
        self.page_owner_state.store(PAGE_OWNER_READY, Ordering::Release);
        true
    }

    /// Runs one non-reentrant operation on the ticket-zero native owner.
    ///
    /// Ticket zero may temporarily resume its *own* parked engine while one
    /// or more typed later-owner routes remain parked. Its operation still
    /// claims the one `BUSY` mutation slot, and on return it restores every
    /// other parked token exactly. If the operation becomes all-free, only
    /// ticket zero's own token disappears; a detached route remains parked
    /// until its matched B-side terminal finish proves it may release.
    ///
    /// Returning `None` means this private route is inactive or recursively
    /// busy; it never asks the C allocator to interpret a native pointer.
    fn with_ticket_zero_page_owner<R>(
        &'static self,
        operation: impl FnOnce(&mut MainStaticRuntimeFirstArenaPageAllocator) -> R,
    ) -> Option<R> {
        self.with_ticket_zero_page_owner_with_storage(ProcessSharedArenaStorage::global(), operation)
    }

    fn with_ticket_zero_page_owner_with_storage<R>(
        &'static self,
        arena_storage: &'static ProcessSharedArenaStorage,
        operation: impl FnOnce(&mut MainStaticRuntimeFirstArenaPageAllocator) -> R,
    ) -> Option<R> {
        if !self.start_ticket_zero_page_owner_with_storage(arena_storage) {
            return None;
        }
        let observed = loop {
            let observed = self.page_owner_state.load(Ordering::Acquire);
            if page_owner_parked_count(observed).is_none() {
                return None;
            }
            if self
                .page_owner_state
                .compare_exchange_weak(
                    observed,
                    PAGE_OWNER_BUSY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                #[cfg(feature = "native-runtime-test-audit")]
                note_native_scheduler_transition();
                break observed;
            }
        };
        // SAFETY: READY/PARKED -> BUSY serializes every mutable engine
        // operation; `start_ticket_zero_page_owner` wrote this final slot
        // before its first Release publication, and the current TPIDR check
        // prevents a pthread worker from borrowing the ticket-zero engine.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        let parked_count = page_owner_parked_count(observed)
            .expect("the ticket-zero scheduler admitted only ready or parked states");
        let ticket_zero_was_parked = owner.has_parked_live_engine();
        if self.has_pending_post_exit_completion()
            || self.has_retained_post_exit_route()
            || (observed != PAGE_OWNER_READY
                && !ticket_zero_was_parked
                && !self.has_active_post_exit_route())
        {
            // A pending B completion always wins, even beside another live
            // source route. Otherwise a normal parked engine owns the only
            // token. Neither condition lets ticket zero borrow the dormant
            // pair, so restore the exact state rather than treating every
            // parked count alike.
            self.page_owner_state.store(observed, Ordering::Release);
            return None;
        }
        let result = operation(owner);
        if owner.is_retained() {
            self.retain();
            self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
        } else {
            let ticket_zero_is_parked = owner.has_parked_live_engine();
            let next_state = match (ticket_zero_was_parked, ticket_zero_is_parked) {
                // A dormant ticket zero has explicitly parked a fresh private
                // source engine while one or more detached routes retain
                // their own admission claims. That new parked engine adds
                // exactly one token; it never reuses or releases a route
                // token.
                (false, true) => page_owner_parked_state(parked_count + 1)
                    .expect("adding ticket zero to the representable parked count stays representable"),
                // A normal ticket-zero operation runs only under this call's
                // transient BUSY state and leaves no separately parked source
                // engine. It may allocate and free its own permanent-owner
                // clients, but every foreign parked route remains unchanged.
                (false, false) => observed,
                // Ticket zero resumed and re-parked its already-counted
                // engine, restoring the exact foreign/peer count it found.
                (true, true) => observed,
                // Ticket zero's own parked engine became all-free. Keep every
                // foreign route/engine represented until its matched typed
                // terminal finish releases that separate admission token.
                (true, false) => page_owner_parked_state(parked_count - 1)
                    .expect("removing ticket zero from a nonzero parked count stays representable"),
            };
            self.page_owner_state.store(next_state, Ordering::Release);
        }
        Some(result)
    }

    /// Gives one attached later worker the permanent owner's already-published
    /// process pair only while ticket zero has no live native pages.
    ///
    /// This is a scoped handoff, not a concurrent page engine or a generic
    /// map scheduler. `READY -> BUSY` excludes ticket-zero reactivation while
    /// the worker holds the source map lifecycle lease. The callback must
    /// finish its own page engine empty; an error retains both permanent
    /// owners instead of manufacturing a second page lifecycle.
    fn with_dormant_page_pair<R>(
        &'static self,
        operation: impl FnOnce(ProcessPageArenaLease) -> Result<R, ()>,
    ) -> Option<R> {
        if !self.is_active()
            || self
                .page_owner_state
                .compare_exchange(
                    PAGE_OWNER_READY,
                    PAGE_OWNER_BUSY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return None;
        }
        #[cfg(feature = "native-runtime-test-audit")]
        note_native_scheduler_transition();

        // SAFETY: READY -> BUSY serializes this mutable permanent owner with
        // ticket zero. The final slot was written before READY's Release
        // publication and is never moved or replaced.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        match owner.with_later_thread_page_pair(operation) {
            Ok(result) => {
                self.page_owner_state.store(PAGE_OWNER_READY, Ordering::Release);
                Some(result)
            }
            Err(()) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                None
            }
        }
    }

    /// Claims the permanent owner's dormant process pair for one normal page
    /// engine operation without exposing that pair outside the typed runtime
    /// transition. The permanent owner remains source-dormant while the
    /// returned operation owns only the runtime's `BUSY` scheduling state.
    ///
    /// `expected_state` names the exact previously published parked-owner
    /// count. `finish_state` and `park_state` are carried inside the linear
    /// result so a completing or re-parking engine changes only its own
    /// membership; no operation can reopen ticket zero while another
    /// suspended engine remains live.
    fn begin_dormant_page_operation(
        &'static self,
        expected_state: usize,
        finish_state: usize,
        park_state: usize,
        may_park: bool,
    ) -> Option<RuntimeDormantPageOperation> {
        if !self.is_active()
            || self
                .page_owner_state
                .compare_exchange(
                    expected_state,
                    PAGE_OWNER_BUSY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return None;
        }

        #[cfg(feature = "native-runtime-test-audit")]
        note_native_scheduler_transition();

        // SAFETY: expected -> BUSY serializes every mutable access to the
        // final permanent owner. `with_later_thread_page_pair` restores the
        // exact dormant or ticket-zero-parked source state before this method
        // returns; the operation below owns only whether ticket zero may
        // enter again.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        match owner.with_later_thread_page_pair(Ok) {
            Ok(pair) => Some(RuntimeDormantPageOperation {
                runtime: self,
                pair: Some(pair),
                finish_state,
                park_state,
                may_park,
                active: true,
            }),
            Err(()) => {
                self.retain_page_owner();
                None
            }
        }
    }

    /// Starts one new persistent later-main engine while zero or more other
    /// engines are parked. A successful suspension increments the parked
    /// count; an empty finish restores exactly the count observed before this
    /// engine began. Each complete engine operation remains serialized by the
    /// one `BUSY` transition and the lower PageMap mutation lease.
    fn begin_persistent_later_engine<'attachment, 'main>(
        &'static self,
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<
        RuntimePersistentPageEngine<'attachment, 'main>,
        RuntimePersistentPageEngineBeginError,
    > {
        let observed_state = self.page_owner_state.load(Ordering::Acquire);
        let Some(parked_count) = page_owner_parked_count(observed_state) else {
            return Err(RuntimePersistentPageEngineBeginError::Unavailable);
        };
        let Some(park_state) = parked_count
            .checked_add(1)
            .and_then(page_owner_parked_state)
        else {
            return Err(RuntimePersistentPageEngineBeginError::Unavailable);
        };
        let Some(operation) = self.begin_dormant_page_operation(
            observed_state,
            observed_state,
            park_state,
            true,
        ) else {
            return Err(RuntimePersistentPageEngineBeginError::Unavailable);
        };
        operation.begin_engine(attachment)
    }

    /// Starts one whole B-side operation while one or more distinct persistent
    /// engines are parked. It must finish empty and restores that exact
    /// parked-owner count. It remains deliberately non-parkable: this path is
    /// for scoped interleavings such as a remote publication, not for creating
    /// another current-thread session.
    fn begin_interleaving_persistent_later_engine<'attachment, 'main>(
        &'static self,
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    ) -> Result<
        RuntimePersistentPageEngine<'attachment, 'main>,
        RuntimePersistentPageEngineBeginError,
    > {
        let observed_state = self.page_owner_state.load(Ordering::Acquire);
        if !page_owner_parked_count(observed_state).is_some_and(|count| count > 0) {
            return Err(RuntimePersistentPageEngineBeginError::Unavailable);
        }
        let Some(operation) = self.begin_dormant_page_operation(
            observed_state,
            observed_state,
            observed_state,
            false,
        ) else {
            return Err(RuntimePersistentPageEngineBeginError::Unavailable);
        };
        operation.begin_engine(attachment)
    }

    #[inline]
    fn page_owner_has_started(&self) -> bool {
        self.page_owner_state.load(Ordering::Acquire) != PAGE_OWNER_COLD
    }

    #[inline]
    fn page_owner_unavailable_result(&self) -> TicketZeroPageAllocationResult {
        if self.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || self.state.load(Ordering::Acquire) == PROCESS_RETAINED
        {
            TicketZeroPageAllocationResult::Retained
        } else {
            TicketZeroPageAllocationResult::Unavailable
        }
    }

    fn initialize(&'static self, page_size_bytes: usize) -> bool {
        match self.state.compare_exchange(
            PROCESS_COLD,
            PROCESS_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(PROCESS_ACTIVE) => return true,
            Err(_) => return false,
        }

        let Some(page_size) = PageSize::new(page_size_bytes) else {
            self.retain();
            return false;
        };
        let config = MemoryConfig::detect(StartupInput::new(page_size));
        // SAFETY: libc calls this only after initial TLS exists and before
        // application constructors. This static owner retains ticket zero for
        // the process lifetime, and no competing runtime lifecycle call can
        // pass the INITIALIZING state above.
        let owner = unsafe { ProcessMainInitializationStorage::global().initialize(config) };
        let Ok(owner) = owner else {
            self.retain();
            return false;
        };

        // SAFETY: this successful COLD -> INITIALIZING winner is the sole
        // writer, and `owner` is moved into its final static process slot
        // before PROCESS_ACTIVE makes it visible to worker threads.
        unsafe { (*self.owner.get()).write(owner) };
        // A shared main-Heap lease may only be minted by the ticket-zero
        // owner on its own thread. Store that immutable process witness now;
        // later pthread workers may copy it but must never try to mint it
        // while their TPIDR identity differs from the initial attachment.
        let owner = unsafe { (&*self.owner.get()).assume_init_ref() };
        let Ok(main_heap) = owner.shared_main_heap_lease() else {
            self.retain();
            return false;
        };
        let Some(initial_thread) = current_thread_identity() else {
            self.retain();
            return false;
        };
        // SAFETY: the same sole initializer writes this second final slot
        // before the Release publication below.
        unsafe { (*self.main_heap.get()).write(main_heap) };
        // The initial thread identity is written before PROCESS_ACTIVE's
        // Release publication. It is an immutable witness: a quiescent child
        // retains the copied TPIDR_EL0 image, while every fresh pthread gets a
        // distinct image and cannot pass the fork-preservation check.
        self.initial_thread_identity
            .store(initial_thread.get(), Ordering::Release);
        self.state.store(PROCESS_ACTIVE, Ordering::Release);
        true
    }
}

static RUNTIME_PROCESS: RuntimeProcessStorage = RuntimeProcessStorage::new();

/// Allocation-free admission accounting around the incomplete runtime
/// lifecycle.
///
/// This is deliberately not a general allocator lock or source fork repair.
/// It records only whether the bridge itself has a later TLD/Theap transition
/// in flight or retained. Holding `FORK_GATE_HELD` prevents a new attachment
/// from beginning while libc crosses raw `fork`; an already live owner is
/// conservatively carried into the non-preserving child case rather than
/// traversed, unlocked, or repaired there.
struct RuntimeForkAdmission {
    state: AtomicUsize,
}

/// One linear claim in the runtime's later-worker admission count.
///
/// A normal worker keeps this in its TLS slot. A worker that has detached its
/// Theap/TLD transfers it into the opaque post-exit route, which can return it
/// only in [`TicketZeroOwnerExitRouteFinished`] after terminal PageMap
/// release. This prevents an ordinary no-page finalizer from decrementing the
/// admission count while a process route still owns client-visible pages.
#[must_use = "a later-worker admission claim must finish normally or remain terminally retained"]
struct LaterThreadAdmissionClaim {
    _private: (),
}

impl RuntimeForkAdmission {
    const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
        }
    }

    /// Claims one later-thread lifecycle admission. A concurrent fork waits
    /// only while it crosses the raw kernel boundary; it never observes a
    /// half-published attachment as absent.
    fn claim_later_thread(&self) -> Option<LaterThreadAdmissionClaim> {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & FORK_GATE_HELD != 0 {
                core::hint::spin_loop();
                continue;
            }
            let count = observed & FORK_GATE_COUNT_MASK;
            if count == FORK_GATE_COUNT_MASK {
                return None;
            }
            let next = observed + 1;
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(LaterThreadAdmissionClaim { _private: () });
            }
        }
    }

    /// Releases one fully finished later-thread owner. The count remains
    /// visible while a fork gate is held, so a finish racing a fork can only
    /// make that fork more conservative; it can never retroactively turn an
    /// unsafe child into a preserving one.
    fn release_later_thread(
        &self,
        claim: LaterThreadAdmissionClaim,
    ) -> Result<(), LaterThreadAdmissionClaim> {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            let count = observed & FORK_GATE_COUNT_MASK;
            if count == 0 {
                return Err(claim);
            }
            let next = observed - 1;
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Runs one initial-thread-only ownership publication while no later
    /// attachment can begin.
    ///
    /// This reuses the existing short admission gate solely for the one-time
    /// ticket-zero -> compiler-TLS promotion.  It is not an allocator
    /// scheduler: normal initial local calls happen after this closure has
    /// released the gate, and no page or PageMap operation is represented by
    /// the admission word.  A nonzero existing count refuses the transfer so
    /// a waiting worker can never revive or alias the moved static owner.
    fn with_no_later_thread_admissions<R>(&self, operation: impl FnOnce() -> R) -> Option<R> {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & FORK_GATE_HELD != 0 {
                core::hint::spin_loop();
                continue;
            }
            // A preserved fork image is valid only while `HELD` is set. Do
            // not clear or reinterpret any unexpected non-count flag here:
            // promotion has no fork-preservation authority and may proceed
            // only from the exact ordinary idle word.
            if observed != 0 {
                return None;
            }
            let held = FORK_GATE_HELD;
            if self
                .state
                .compare_exchange_weak(observed, held, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let result = operation();
                // The successful publication began from the exact zero word,
                // so it owns only this temporary HELD flag. Release that same
                // flag before ordinary lifecycle code resumes; no fork
                // preservation bit is created, consumed, or overwritten.
                self.state.store(0, Ordering::Release);
                return Some(result);
            }
        }
    }

    /// Holds the direct internal fork boundary and records whether the copied
    /// child may preserve its quiescent ticket-zero image. No allocation,
    /// lock traversal, page operation, or public pthread-atfork slot is
    /// involved.
    fn before_fork(&self, can_preserve_process_owner: bool) {
        self.before_fork_with(|| can_preserve_process_owner);
    }

    /// Holds the gate before inspecting a potentially permanent page owner.
    ///
    /// The callback executes only after the gate has observed zero later
    /// attachments. That ordering matters: a READY static ticket-zero owner
    /// or INITIAL_PERSISTENT initial TLS owner may otherwise be mutably
    /// borrowed by a source operation, so inspecting its dormant image before
    /// worker admission is closed would be an unsound concurrent view. The
    /// callback is an allocation-free private predicate for the direct libc
    /// fork path; it never exposes a page or fork capability.
    fn before_fork_with(&self, can_preserve_process_owner: impl FnOnce() -> bool) {
        let mut can_preserve_process_owner = Some(can_preserve_process_owner);
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & FORK_GATE_HELD != 0 {
                core::hint::spin_loop();
                continue;
            }
            let count = observed & FORK_GATE_COUNT_MASK;
            let next = observed | FORK_GATE_HELD;
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // A zero count under HELD excludes every later attachment:
                // `claim_later_thread` spins until the parent clears HELD.
                // Therefore the predicate may safely inspect a quiescent
                // static or pinned-initial ticket-zero owner before this raw
                // fork.
                if count == 0
                    && can_preserve_process_owner
                        .take()
                        .is_some_and(|predicate| predicate())
                {
                    self.state
                        .store(next | FORK_GATE_PRESERVE, Ordering::Release);
                }
                return;
            }
        }
    }

    /// Releases the parent's fork admission boundary while retaining the
    /// exact number of still-live later owners. This is called before public
    /// parent handlers, so a handler can create a pthread only after the
    /// runtime has restored normal admission.
    fn after_fork_parent(&self) {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & FORK_GATE_HELD == 0 {
                return;
            }
            let next = observed & FORK_GATE_COUNT_MASK;
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Resets the copied admission word without acquiring an inherited lock.
    /// The return value is true only when this exact fork path presented its
    /// prepared token and the gate recorded ticket zero with no bridge-owned
    /// later attachment. The source image may be the static dormant owner or
    /// the original initial thread's pinned TLS owner. The explicit token
    /// prevents an unprepared raw fork on another thread from mistaking
    /// copied gate bits for its own proof.
    fn after_fork_child(&self, fork_was_prepared: bool) -> bool {
        let observed = self.state.swap(0, Ordering::AcqRel);
        fork_was_prepared
            && (observed & (FORK_GATE_HELD | FORK_GATE_PRESERVE))
            == (FORK_GATE_HELD | FORK_GATE_PRESERVE)
            && observed & FORK_GATE_COUNT_MASK == 0
    }
}

static RUNTIME_FORK_ADMISSION: RuntimeForkAdmission = RuntimeForkAdmission::new();

/// Mints a process-unique nonzero identity for one B attachment that may own
/// terminal post-exit completions. The identity is metadata only: it grants no
/// access to a TLS slot, route, page, client, allocator, or admission proof.
/// Exhaustion closes the incomplete native lifecycle rather than allowing a
/// wrapped identity to match a stale process-lifetime registry entry.
static NEXT_NATIVE_POST_EXIT_COMPLETION_OWNER_GENERATION: AtomicUsize = AtomicUsize::new(1);

fn claim_native_post_exit_completion_owner_generation() -> Option<usize> {
    let mut observed = NEXT_NATIVE_POST_EXIT_COMPLETION_OWNER_GENERATION.load(Ordering::Acquire);
    loop {
        if observed == 0 {
            return None;
        }
        let next = observed.checked_add(1).unwrap_or(0);
        match NEXT_NATIVE_POST_EXIT_COMPLETION_OWNER_GENERATION.compare_exchange_weak(
            observed,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return next.checked_sub(1),
            Err(actual) => observed = actual,
        }
    }
}

/// A detached native-shadow route paired with its exact parked runtime
/// scheduler token.
///
/// The source route owns A's admission claim. Its own short PageMap access
/// serializes each exact C free, while `parked` keeps ticket zero out of
/// `READY` until the route returns a typed terminal proof and B completes its
/// normal finish. Keeping both fields in one linear entry prevents a raw C
/// free from reopening ticket zero before all source pages have released.
#[must_use = "a native post-exit route must reach B's terminal proof or remain retained"]
struct NativePostExitRoute {
    parked: RuntimeParkedPostExitRoute,
    route: NativePostExitFreeRoute,
}

/// The opaque lifecycle identity of a B attachment that has received one or
/// more terminal native post-exit route completions.
///
/// This is a private registry matching key, not a route, allocator, client,
/// page, or release capability. The compiler-TLS address stays internal and
/// the nonzero lifecycle generation prevents an old completed entry from
/// matching a later attachment in the same TLS slot.
#[derive(Clone, Copy, Eq, PartialEq)]
struct NativePostExitRouteCompletionOwner {
    slot: core::ptr::NonNull<ThreadLifecycleSlot>,
    generation: usize,
}

/// A terminal native post-exit route paired with its still-parked
/// detached-route scheduler token and matched B lifecycle identity.
///
/// A route may return its typed PageMap/admission proof after B's final C
/// `free`, but B's no-page TLD/Theap is still live until its normal pthread
/// finish. Keeping the parked token beside that proof prevents ticket zero
/// from borrowing the dormant pair during this final B-only interval. The
/// completion may remove only its route's parked token after B has detached
/// its own attachment, then releases A's admission proof.
#[must_use = "a terminal native route completion must finish B or remain retained"]
struct NativePostExitRouteCompletion {
    owner: NativePostExitRouteCompletionOwner,
    parked: RuntimeParkedPostExitRoute,
    proof: TicketZeroOwnerExitRouteFinished,
}

/// A terminal route storage image. Retained entries intentionally keep every
/// exact ownership capability alive for the process lifetime rather than
/// dropping an ambiguous route and making the fork-admission count appear
/// quiescent.
#[must_use = "a retained native post-exit entry must stay process-terminal"]
enum NativePostExitRouteEntry {
    Active(NativePostExitRoute),
    /// A completed source route has released every C client but remains live
    /// in the registry until its exact B attachment has torn down. It cannot
    /// answer an address lookup or be reused by a later A owner.
    Completed(NativePostExitRouteCompletion),
    RetainedRoute(NativePostExitRoute),
    RetainedFinished {
        parked: RuntimeParkedPostExitRoute,
        proof: TicketZeroOwnerExitRouteFinished,
    },
    /// The matching parked token was removed, but releasing A's admission
    /// proof failed. Preserve that exact proof in the terminal entry rather
    /// than dropping it after the scheduler became ready.
    RetainedAdmission {
        proof: TicketZeroOwnerExitRouteFinished,
    },
    RetainedPoisoned {
        parked: RuntimeParkedPostExitRoute,
        proof: TicketZeroOwnerExitRoutePoisoned,
    },
}

/// Result visible to the native libc friend boundary after it offers one raw
/// C address to the opaque post-exit route. No variant exposes a client,
/// PageMap lease, or allocator authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePostExitRouteFreeResult {
    NotOwned,
    Freed,
    Finished,
    Retained,
}

/// Result visible to the native libc friend boundary after it asks a private
/// detached route to replace one exact A-owned client in B's parked session.
///
/// The successful block is already recorded in B's private ledger.  This is
/// deliberately not a route/client/page capability: callers may only return
/// the replacement through the normal C `realloc` boundary, then later offer
/// that address back to B's ordinary local `free` or `realloc` path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePostExitRouteReallocateResult {
    NotOwned,
    Allocated(core::ptr::NonNull<u8>),
    AllocationFailed,
    Unavailable,
    Retained,
}

#[inline]
fn native_post_exit_reallocate_session_failure(
    error: CurrentThreadPageOwnerSessionError,
) -> NativePostExitRouteReallocateResult {
    match error {
        CurrentThreadPageOwnerSessionError::Preparation(
            CurrentThreadPageOwnerPreparationError::AllocationFailed
            | CurrentThreadPageOwnerPreparationError::OverCapacity,
        ) => NativePostExitRouteReallocateResult::AllocationFailed,
        CurrentThreadPageOwnerSessionError::Retained => NativePostExitRouteReallocateResult::Retained,
        CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale
        | CurrentThreadPageOwnerSessionError::Preparation(_) => {
            NativePostExitRouteReallocateResult::Unavailable
        }
    }
}

/// Private result of probing one detached route for an exact usable-size
/// query. It keeps a retained registry entry from being mistaken for an
/// ordinary address miss while the private router considers another entry.
enum NativePostExitRouteUsableSizeResult {
    NotOwned,
    Owned(usize),
    Retained,
}

/// Private result of asking one stable entry to settle a completion for the
/// current B attachment after that attachment's own source teardown.
enum NativePostExitRouteCompletionFinishResult {
    NotOwned,
    Finished,
    Retained,
}

/// Aggregate result of finishing every completed route matched to one B
/// attachment. The registry never returns an entry, route, client, page, or
/// admission capability to its caller.
enum NativePostExitRouteCompletionsFinishResult {
    Finished,
    Retained,
}

/// One registry entry's observable ownership state.
///
/// `Live` includes the brief private `BUSY` move while its exact B-side
/// operation runs and the post-terminal `COMPLETED` image that still owns a
/// parked token and A admission. A retained entry closes the whole process
/// runtime, so a later source owner may not use it as evidence that another
/// route can safely append an OS-abandoned-list member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePostExitRouteStorageState {
    Empty,
    Live,
    Retained,
}

/// Read-only scalar accounting for the private native post-exit registry.
///
/// This exists only in the default-off direct-test feature. It deliberately
/// reports aggregate counts rather than a node address, route, client, page,
/// allocator, or release capability. `published_entry_count` is also the
/// registry's retained metadata high-water: nodes are append-only and an
/// emptied node is the only reusable storage for a later detached owner.
/// The direct regression samples it only after all participating workers have
/// joined; a contemporaneous `BUSY` entry is conservatively reported live.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePostExitRouteRegistryAudit {
    pub published_entry_count: usize,
    pub live_entry_count: usize,
    pub retained_entry_count: usize,
}

/// Read-only scalar accounting for the private native live-owner registry.
///
/// This exists only in the default-off direct-test feature. It reports the
/// stable metadata-node high-water and aggregate entry states, never an entry
/// identity, raw TLS slot, client address, page, allocator, or release
/// capability. Nodes are append-only and an emptied entry is the only
/// reusable storage for a later parked A. Callers must sample only after all
/// participating workers have joined; a contemporaneous `BUSY` entry is
/// conservatively reported as live.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveRemoteOwnerRegistryAudit {
    pub published_entry_count: usize,
    pub live_entry_count: usize,
    pub retained_entry_count: usize,
}

/// Read-only scalar accounting for one quiescent native runtime process.
///
/// This is deliberately a default-off evidence hook. It reports lifecycle
/// counts and readiness bits only; it does not reveal a route, client address,
/// PageMap root, arena address, allocator, or release capability. Callers
/// must sample only after every participating worker has joined, so no normal
/// engine or detached route is concurrently mutating the source-owned state.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRuntimeLifecycleAudit {
    pub process_active: usize,
    pub page_owner_ready: usize,
    pub page_map_registered_entry_count: usize,
    pub page_map_published_submap_count: usize,
    pub page_map_lazy_submap_allocation_count: usize,
    pub arena_registry_count: usize,
    pub live_thread_count: usize,
    pub metadata_live_capability_count: usize,
    pub metadata_high_water_capability_count: usize,
    pub shared_later_theap_count: usize,
    pub main_heap_abandoned_page_count: usize,
    pub main_heap_os_abandoned_pages_empty: usize,
    pub native_owner_local_operation_count: usize,
    pub native_parked_compatibility_operation_count: usize,
    pub native_scheduler_transition_count: usize,
}

/// Read-only scalar accounting for the runtime's fork-admission gate.
///
/// This is deliberately a default-off direct-test hook. It reports only the
/// current number of attached later-thread claims. It neither claims,
/// releases, nor preserves an admission, and it exposes no route, client
/// address, page, allocator, or fork capability. Unlike the quiescent
/// lifecycle audit, a direct regression may sample this scalar while its exact
/// B worker is still attached.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRuntimeForkAdmissionAudit {
    pub active_later_thread_count: usize,
}

/// One metadata-backed entry in the private native-shadow post-exit registry.
/// The atomic word protects only moves through the `UnsafeCell`; no lock
/// guards general allocation. The route's own `ProcessPageMapPostExitAccess`
/// serializes each exact free, while its parked runtime token keeps ticket
/// zero unavailable without preventing a distinct normal engine from using
/// the shared process pair between route operations.
struct NativePostExitRouteStorage {
    state: AtomicU8,
    entry: UnsafeCell<MaybeUninit<NativePostExitRouteEntry>>,
}

// SAFETY: all access to `entry` first claims either `ACTIVE -> BUSY` or
// `COMPLETED -> BUSY` with AcqRel. The static has one writer while installing
// and one mutable route/completion consumer at a time; retained entries are
// never read as active again.
unsafe impl Sync for NativePostExitRouteStorage {}

impl NativePostExitRouteStorage {
    /// Reserves a not-yet-published detached route while its A-side runtime
    /// operation still owns the scheduler's `BUSY` state.  Readers classify
    /// this `BUSY` entry as live for source preflight, but cannot borrow its
    /// uninitialized route image before the reserving owner publishes the
    /// matching parked scheduler token.
    #[inline]
    fn reserved() -> Self {
        Self {
            state: AtomicU8::new(NATIVE_POST_EXIT_ROUTE_BUSY),
            entry: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Classifies one stable metadata entry without exposing its route,
    /// clients, PageMap access, or admission capability.
    #[inline]
    fn registry_state(&self) -> NativePostExitRouteStorageState {
        match self.state.load(Ordering::Acquire) {
            NATIVE_POST_EXIT_ROUTE_EMPTY => NativePostExitRouteStorageState::Empty,
            NATIVE_POST_EXIT_ROUTE_ACTIVE
            | NATIVE_POST_EXIT_ROUTE_BUSY
            | NATIVE_POST_EXIT_ROUTE_COMPLETED => {
                NativePostExitRouteStorageState::Live
            }
            NATIVE_POST_EXIT_ROUTE_RETAINED => NativePostExitRouteStorageState::Retained,
            _ => {
                // An invalid state cannot name a route whose source PageMap
                // and admission ownership can be reconstructed. Preserve the
                // registry entry and close the runtime rather than treating a
                // corrupt word as an empty reusable slot.
                RUNTIME_PROCESS.retain_page_owner();
                self.state
                    .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
                NativePostExitRouteStorageState::Retained
            }
        }
    }

    /// Reserves a reusable empty entry while the registry mutation guard is
    /// held. The route image remains in the caller until its A-side operation
    /// can publish the matching parked scheduler token; this prevents another
    /// concurrent A from observing an empty source-list proof in that gap.
    fn reserve(&self) -> bool {
        self.state
            .compare_exchange(
                NATIVE_POST_EXIT_ROUTE_EMPTY,
                NATIVE_POST_EXIT_ROUTE_BUSY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Completes a previously reserved entry after the A-side operation has
    /// converted its `BUSY` scheduler claim into the exact parked route token.
    #[inline]
    fn publish_reserved(&self, route: NativePostExitRoute) {
        // SAFETY: the reservation owns this entry's BUSY state. No reader
        // accesses `entry` until this Release publication makes it ACTIVE.
        unsafe { (*self.entry.get()).write(NativePostExitRouteEntry::Active(route)) };
        self.state
            .store(NATIVE_POST_EXIT_ROUTE_ACTIVE, Ordering::Release);
    }

    /// Closes a reservation that could not obtain a matching parked token.
    /// Its route stays with the caller, which retains its exact admission and
    /// client facts; readers must nevertheless treat this static registry
    /// entry as terminal rather than read its deliberately uninitialized
    /// image.
    #[inline]
    fn retain_reserved(&self) {
        self.state
            .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
    }

    /// Restores one unchanged or still-live route after this entry's private
    /// operation has completed. The route and its parked scheduler token move
    /// together so an address miss or a nonterminal exact free cannot make
    /// ticket zero observe a false quiescent state.
    #[inline]
    fn restore_active(&self, parked: RuntimeParkedPostExitRoute, route: NativePostExitFreeRoute) {
        // SAFETY: this storage operation owns the entry after its successful
        // `ACTIVE -> BUSY` claim and writes the next complete linear image
        // before publishing ACTIVE again.
        unsafe {
            (*self.entry.get()).write(NativePostExitRouteEntry::Active(
                NativePostExitRoute { parked, route },
            ))
        };
        self.state
            .store(NATIVE_POST_EXIT_ROUTE_ACTIVE, Ordering::Release);
    }

    /// Publishes a terminal entry only after the private registry has closed
    /// future detached-owner installation. The closure names no route or
    /// client: it is solely the process-lifetime fact that a retained source
    /// owner prevents another A from appending beside it.
    #[inline]
    fn publish_retained(&self) {
        NATIVE_POST_EXIT_ROUTE.close_for_retained_entry();
        self.state
            .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
    }

    /// Keeps a concrete route and its scheduler token process-terminal after
    /// an operation can no longer prove a retryable source state.
    #[inline]
    fn retain_route(&self, parked: RuntimeParkedPostExitRoute, route: NativePostExitFreeRoute) {
        let parked = match parked.retain_source_route() {
            Ok(parked) => parked,
            Err(parked) => {
                // The failed conversion has already retained the page-owner
                // scheduler. Keep the exact source route in the terminal
                // registry image as well; no later normal finalizer may
                // reconstruct or release its admission.
                parked
            }
        };
        // SAFETY: see `restore_active`; retained entries are never moved back
        // through an active route operation.
        unsafe {
            (*self.entry.get()).write(NativePostExitRouteEntry::RetainedRoute(
                NativePostExitRoute { parked, route },
            ))
        };
        self.publish_retained();
    }

    /// Commits a consumed exact-source free into this storage entry.
    ///
    /// A route may mint its terminal proof only after it has released every
    /// A-owned client. This helper is shared by C `free` and the detached
    /// B-side `realloc` transaction, so both paths preserve the same rule:
    /// B's attachment and any independently parked B session must finish
    /// before A's parked token and worker-admission claim can be released.
    fn settle_exact_free(
        &self,
        parked: RuntimeParkedPostExitRoute,
        free: NativePostExitFreeStep,
    ) -> NativePostExitRouteFreeResult {
        match free {
            NativePostExitFreeStep::NotOwned(route) => {
                self.restore_active(parked, route);
                NativePostExitRouteFreeResult::NotOwned
            }
            NativePostExitFreeStep::Freed(route) => {
                self.restore_active(parked, route);
                NativePostExitRouteFreeResult::Freed
            }
            NativePostExitFreeStep::Finished(proof) => {
                // The detached source route has terminally released, but B is still
                // an attached worker. B may already have its own *parked*
                // local native session: that engine is independent of A's
                // route and its eventual source finish is the concrete B
                // lifecycle boundary we need. Transfer both the terminal
                // proof and this route's still-parked scheduler token into
                // the stable opaque registry only when B's own engine is
                // parked. The registry records B's private lifecycle identity
                // and TLS retains only its completion count, so one B may
                // carry several terminal routes without exposing a client or
                // making any completion reusable before B's required finish.
                let parked = match parked.finish_source_route() {
                    Ok(parked) => parked,
                    Err(parked) => {
                        // The scheduler token cannot become a B completion
                        // unless this exact source route first released its
                        // narrower ticket-zero interleaving capability.
                        // Preserve both terminally rather than making the
                        // registry slot look empty with an unbalanced count.
                        unsafe {
                            (*self.entry.get()).write(NativePostExitRouteEntry::RetainedFinished {
                                parked,
                                proof,
                            })
                        };
                        self.publish_retained();
                        return NativePostExitRouteFreeResult::Retained;
                    }
                };
                let slot_pointer = current_thread_slot_pointer();
                // SAFETY: this running B worker owns its compiler-TLS slot.
                // The entry receives only the opaque identity below, never a
                // route/client/page authority or a dereference capability.
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                let b_session_is_parked = match slot.page_owner.as_ref() {
                    None => true,
                    Some(ThreadLifecyclePageOwner::Session(session)) => session.parked.is_some(),
                    Some(ThreadLifecyclePageOwner::PreparedExit(_)) => false,
                };
                let completion_owner = if b_session_is_parked {
                    slot.record_post_exit_route_completion(slot_pointer)
                } else {
                    None
                };
                let Some(owner) = completion_owner else {
                    // A complete route without its matching B lifecycle has
                    // no legal scheduler settle or admission release. Keep
                    // both typed capabilities terminally represented instead
                    // of converting the static route back into an empty slot.
                    unsafe {
                        (*self.entry.get()).write(NativePostExitRouteEntry::RetainedFinished {
                            parked,
                            proof,
                        })
                    };
                    RUNTIME_PROCESS.retain_page_owner();
                    self.publish_retained();
                    return NativePostExitRouteFreeResult::Retained;
                };
                unsafe {
                    (*self.entry.get()).write(NativePostExitRouteEntry::Completed(
                        NativePostExitRouteCompletion {
                            owner,
                            parked,
                            proof,
                        },
                    ))
                };
                self.state
                    .store(NATIVE_POST_EXIT_ROUTE_COMPLETED, Ordering::Release);
                NativePostExitRouteFreeResult::Finished
            }
            NativePostExitFreeStep::Retained(route) => {
                self.retain_route(parked, route);
                NativePostExitRouteFreeResult::Retained
            }
            NativePostExitFreeStep::Poisoned(proof) => {
                // SAFETY: the lower route has no retryable source state, but
                // its scheduler claim and exact admission must remain owned.
                // Remove its source-active interleaving capability before
                // publishing the retained entry, so a live sibling cannot
                // reopen ticket zero over this terminal owner.
                let parked = match parked.retain_source_route() {
                    Ok(parked) => parked,
                    Err(parked) => parked,
                };
                unsafe {
                    (*self.entry.get()).write(NativePostExitRouteEntry::RetainedPoisoned {
                        parked,
                        proof,
                    })
                };
                self.publish_retained();
                NativePostExitRouteFreeResult::Retained
            }
        }
    }

    /// Applies one exact C free to the current detached route. A route that
    /// does not own the address is restored unchanged, allowing ordinary
    /// current-owner lookup to continue without ever observing its clients.
    fn free_exact(&self, block: core::ptr::NonNull<u8>) -> NativePostExitRouteFreeResult {
        loop {
            match self.state.load(Ordering::Acquire) {
                NATIVE_POST_EXIT_ROUTE_EMPTY | NATIVE_POST_EXIT_ROUTE_COMPLETED => {
                    // A completed entry has no C client left. Its parked token
                    // and admission proof remain private in the registry, so
                    // the router may continue scanning a distinct live route.
                    return NativePostExitRouteFreeResult::NotOwned;
                }
                NATIVE_POST_EXIT_ROUTE_RETAINED => {
                    return NativePostExitRouteFreeResult::Retained;
                }
                NATIVE_POST_EXIT_ROUTE_BUSY => core::hint::spin_loop(),
                NATIVE_POST_EXIT_ROUTE_ACTIVE => {
                    if self
                        .state
                        .compare_exchange(
                            NATIVE_POST_EXIT_ROUTE_ACTIVE,
                            NATIVE_POST_EXIT_ROUTE_BUSY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    self.publish_retained();
                    return NativePostExitRouteFreeResult::Retained;
                }
            }
        }

        // SAFETY: this thread exclusively owns the Active -> BUSY route
        // transition. Every nonterminal arm below writes a new initialized
        // entry before publishing a non-BUSY state.
        let entry = unsafe { (*self.entry.get()).assume_init_read() };
        let NativePostExitRouteEntry::Active(NativePostExitRoute { parked, route }) = entry
        else {
            // The atomic state and entry discriminant disagreed. Preserve the
            // actual value and close the runtime rather than inferring which
            // detached owner owns the source map.
            core::mem::forget(entry);
            RUNTIME_PROCESS.retain_page_owner();
            self.publish_retained();
            return NativePostExitRouteFreeResult::Retained;
        };

        let free = {
            let slot = current_thread_slot();
            let Some(attachment) = slot.attachment.as_mut() else {
                // The route is still live, but this caller has no matched B
                // attachment in which a final member could become a real
                // later-main engine. Restore the route unchanged and fail
                // closed rather than letting an exact raw C address advance
                // source state without B's lifecycle boundary.
                unsafe {
                    (*self.entry.get()).write(NativePostExitRouteEntry::Active(
                        NativePostExitRoute { parked, route },
                    ))
                };
                self.state
                    .store(NATIVE_POST_EXIT_ROUTE_ACTIVE, Ordering::Release);
                return NativePostExitRouteFreeResult::Retained;
            };
            route.free_exact_native_block(attachment, block)
        };

        self.settle_exact_free(parked, free)
    }

    /// Replaces one exact detached A client through one private B-side
    /// allocate/copy/free transaction.
    ///
    /// The entry stays `BUSY` across B's parked-session allocation. That is
    /// longer than a normal post-exit exact free, but it does not borrow a
    /// source PageMap lease: B's session operation resumes and re-parks its
    /// own engine before this route consumes A's block through the existing
    /// source free transition. Keeping the opaque route claimed for the full
    /// transaction prevents another exact free from removing A's client after
    /// the replacement copy but before the old client is terminally released.
    fn reallocate_exact(
        &self,
        block: core::ptr::NonNull<u8>,
        new_size: usize,
    ) -> NativePostExitRouteReallocateResult {
        loop {
            match self.state.load(Ordering::Acquire) {
                NATIVE_POST_EXIT_ROUTE_EMPTY | NATIVE_POST_EXIT_ROUTE_COMPLETED => {
                    // See `free_exact`: a terminal completion cannot own a
                    // replacement input, but it must remain non-reusable
                    // until the matching B lifecycle finishes.
                    return NativePostExitRouteReallocateResult::NotOwned;
                }
                NATIVE_POST_EXIT_ROUTE_RETAINED => {
                    return NativePostExitRouteReallocateResult::Retained;
                }
                NATIVE_POST_EXIT_ROUTE_BUSY => core::hint::spin_loop(),
                NATIVE_POST_EXIT_ROUTE_ACTIVE => {
                    if self
                        .state
                        .compare_exchange(
                            NATIVE_POST_EXIT_ROUTE_ACTIVE,
                            NATIVE_POST_EXIT_ROUTE_BUSY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    self.publish_retained();
                    return NativePostExitRouteReallocateResult::Retained;
                }
            }
        }

        // SAFETY: this thread exclusively claimed the initialized active
        // entry. Every return below restores a complete active image or keeps
        // the exact route process-terminal before publishing another state.
        let entry = unsafe { (*self.entry.get()).assume_init_read() };
        let NativePostExitRouteEntry::Active(NativePostExitRoute { parked, route }) = entry
        else {
            // The atomic state and entry discriminant disagreed. Preserve the
            // concrete value and close the runtime rather than guessing which
            // detached owner owns the old C client.
            core::mem::forget(entry);
            RUNTIME_PROCESS.retain_page_owner();
            self.publish_retained();
            return NativePostExitRouteReallocateResult::Retained;
        };

        let Some(old_usable_size) = route.native_usable_size(block) else {
            self.restore_active(parked, route);
            return NativePostExitRouteReallocateResult::NotOwned;
        };

        // The B allocation is made and recorded before A's exact route may
        // consume the old client. This is the source `malloc -> memcpy ->
        // free` ordering: every allocation refusal restores the untouched A
        // route so C still owns `block` and may later free it normally.
        let replacement = match current_thread_native_session_handle(true) {
            Ok(mut session) => match session.native_allocate_aligned(
                new_size,
                NATIVE_C_MALLOC_ALIGNMENT,
                false,
            ) {
                Ok(replacement) => match session.enable_native_live_remote() {
                    Ok(()) => replacement,
                    Err(error) => {
                        let result = native_post_exit_reallocate_session_failure(error);
                        // `native_allocate_aligned` recorded the exact client
                        // before publication. Remove it again before the old
                        // source route is touched; a failed cleanup has an
                        // unobservable native allocation, so retain both
                        // owners rather than claim ordinary realloc failure.
                        if session.native_free(replacement).is_err()
                            || result == NativePostExitRouteReallocateResult::Retained
                        {
                            self.retain_route(parked, route);
                            RUNTIME_PROCESS.retain_page_owner();
                            return NativePostExitRouteReallocateResult::Retained;
                        }
                        self.restore_active(parked, route);
                        return result;
                    }
                },
                Err(error) => {
                    let result = native_post_exit_reallocate_session_failure(error);
                    if result == NativePostExitRouteReallocateResult::Retained {
                        self.retain_route(parked, route);
                        RUNTIME_PROCESS.retain_page_owner();
                        return NativePostExitRouteReallocateResult::Retained;
                    }
                    self.restore_active(parked, route);
                    return result;
                }
            },
            Err(error) => {
                let result = native_post_exit_reallocate_session_failure(error);
                if result == NativePostExitRouteReallocateResult::Retained {
                    self.retain_route(parked, route);
                    RUNTIME_PROCESS.retain_page_owner();
                    return NativePostExitRouteReallocateResult::Retained;
                }
                self.restore_active(parked, route);
                return result;
            }
        };

        let copy_size = core::cmp::min(old_usable_size, new_size);
        if new_size == 0 {
            // Pinned `mi_theap_realloc_zero_ex` gives a successful zero-size
            // replacement a defined first byte even though ordinary malloc(0)
            // is otherwise uninitialized. The successful native allocation
            // has at least one writable byte.
            unsafe { replacement.as_ptr().write(0) };
        }
        if copy_size != 0 {
            // SAFETY: the private route still proves that `block` is live and
            // readable through `old_usable_size`; the B session has recorded
            // a distinct live normal-alignment replacement. The bounded copy
            // extent is exactly the pinned source overlap before old-client
            // release, and C's realloc contract excludes concurrent access.
            unsafe {
                crate::support::copy_bytes_aligned(
                    replacement.as_ptr(),
                    block.as_ptr(),
                    copy_size,
                )
            };
        }

        let free = {
            let slot = current_thread_slot();
            let Some(attachment) = slot.attachment.as_mut() else {
                // A successful B allocation without its matched attachment
                // cannot safely advance A's source route or hand its terminal
                // proof to a normal B finish. Preserve both linear owners.
                self.retain_route(parked, route);
                RUNTIME_PROCESS.retain_page_owner();
                return NativePostExitRouteReallocateResult::Retained;
            };
            route.free_exact_native_block(attachment, block)
        };

        match free {
            NativePostExitFreeStep::NotOwned(route) => {
                // The immutable exact lookup above and the still-claimed
                // entry make this impossible without a lower ownership
                // disagreement. Cleanly remove B's private replacement only
                // if that local ledger remains coherent; otherwise retain
                // rather than returning a hidden allocation to C.
                match current_thread_native_session_handle(false)
                    .and_then(|mut session| session.native_free(replacement))
                {
                    Ok(()) => {
                        self.restore_active(parked, route);
                        NativePostExitRouteReallocateResult::Unavailable
                    }
                    Err(_) => {
                        self.retain_route(parked, route);
                        RUNTIME_PROCESS.retain_page_owner();
                        NativePostExitRouteReallocateResult::Retained
                    }
                }
            }
            free => match self.settle_exact_free(parked, free) {
                NativePostExitRouteFreeResult::Freed
                | NativePostExitRouteFreeResult::Finished => {
                    NativePostExitRouteReallocateResult::Allocated(replacement)
                }
                NativePostExitRouteFreeResult::Retained => {
                    NativePostExitRouteReallocateResult::Retained
                }
                NativePostExitRouteFreeResult::NotOwned => {
                    // The `NotOwned` source result is handled above while it
                    // still carries the route. Reaching it here would lose a
                    // proven B replacement, so make the runtime terminal.
                    RUNTIME_PROCESS.retain_page_owner();
                    NativePostExitRouteReallocateResult::Retained
                }
            },
        }
    }

    /// Returns the already-recorded usable extent for one exact detached C
    /// client while preserving the active route unchanged. The short
    /// `ACTIVE -> BUSY -> ACTIVE` ownership move serializes this read with a
    /// later terminal `free`, but it deliberately does not touch source page
    /// state, the parked scheduler token, or A's admission proof.
    fn usable_size_exact(
        &self,
        block: core::ptr::NonNull<u8>,
    ) -> NativePostExitRouteUsableSizeResult {
        loop {
            match self.state.load(Ordering::Acquire) {
                NATIVE_POST_EXIT_ROUTE_EMPTY | NATIVE_POST_EXIT_ROUTE_COMPLETED => {
                    // Completed routes retain only lifecycle facts, never a
                    // C client that could answer a usable-size query.
                    return NativePostExitRouteUsableSizeResult::NotOwned;
                }
                NATIVE_POST_EXIT_ROUTE_RETAINED => {
                    return NativePostExitRouteUsableSizeResult::Retained;
                }
                NATIVE_POST_EXIT_ROUTE_BUSY => core::hint::spin_loop(),
                NATIVE_POST_EXIT_ROUTE_ACTIVE => {
                    if self
                        .state
                        .compare_exchange(
                            NATIVE_POST_EXIT_ROUTE_ACTIVE,
                            NATIVE_POST_EXIT_ROUTE_BUSY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    self.publish_retained();
                    return NativePostExitRouteUsableSizeResult::Retained;
                }
            }
        }

        // SAFETY: this thread exclusively claimed the initialized active
        // entry. The read-only result below writes that same exact route back
        // before it makes the slot observable again.
        let entry = unsafe { (*self.entry.get()).assume_init_read() };
        let NativePostExitRouteEntry::Active(NativePostExitRoute { parked, route }) = entry
        else {
            // The entry discriminant cannot disagree with ACTIVE without an
            // ownership violation. Preserve its concrete value and keep the
            // process terminal instead of guessing a client/page owner.
            core::mem::forget(entry);
            RUNTIME_PROCESS.retain_page_owner();
            self.publish_retained();
            return NativePostExitRouteUsableSizeResult::Retained;
        };

        let usable_size = route.native_usable_size(block);
        // SAFETY: this same writer took the initialized active entry above;
        // the query retained the exact route and every linear capability.
        unsafe {
            (*self.entry.get()).write(NativePostExitRouteEntry::Active(
                NativePostExitRoute { parked, route },
            ))
        };
        self.state
            .store(NATIVE_POST_EXIT_ROUTE_ACTIVE, Ordering::Release);
        match usable_size {
            Some(usable_size) => NativePostExitRouteUsableSizeResult::Owned(usable_size),
            None => NativePostExitRouteUsableSizeResult::NotOwned,
        }
    }

    /// Settles one terminal A route only when this entry's opaque B identity
    /// matches the attachment that has already completed its own ordinary
    /// teardown. A completed entry has no client-facing operation left: this
    /// is the sole internal transition that may remove its parked scheduler
    /// token and release its exact A admission.
    fn finish_completion_for_owner(
        &self,
        owner: NativePostExitRouteCompletionOwner,
    ) -> NativePostExitRouteCompletionFinishResult {
        loop {
            match self.state.load(Ordering::Acquire) {
                NATIVE_POST_EXIT_ROUTE_EMPTY | NATIVE_POST_EXIT_ROUTE_ACTIVE => {
                    return NativePostExitRouteCompletionFinishResult::NotOwned;
                }
                NATIVE_POST_EXIT_ROUTE_RETAINED => {
                    return NativePostExitRouteCompletionFinishResult::Retained;
                }
                NATIVE_POST_EXIT_ROUTE_BUSY => core::hint::spin_loop(),
                NATIVE_POST_EXIT_ROUTE_COMPLETED => {
                    if self
                        .state
                        .compare_exchange(
                            NATIVE_POST_EXIT_ROUTE_COMPLETED,
                            NATIVE_POST_EXIT_ROUTE_BUSY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    self.publish_retained();
                    return NativePostExitRouteCompletionFinishResult::Retained;
                }
            }
        }

        // SAFETY: this finisher exclusively claimed the initialized
        // `COMPLETED -> BUSY` entry. Every nonterminal path below restores its
        // complete image before the entry becomes observable again.
        let entry = unsafe { (*self.entry.get()).assume_init_read() };
        let NativePostExitRouteEntry::Completed(completion) = entry else {
            // A mismatched atomic state and entry discriminant can no longer
            // identify which exact route owns the scheduler/admission facts.
            core::mem::forget(entry);
            RUNTIME_PROCESS.retain_page_owner();
            self.publish_retained();
            return NativePostExitRouteCompletionFinishResult::Retained;
        };
        if completion.owner != owner {
            // This is another B's completion. Restore it without exposing a
            // capability, then let the stable registry scan continue.
            unsafe {
                (*self.entry.get()).write(NativePostExitRouteEntry::Completed(completion))
            };
            self.state
                .store(NATIVE_POST_EXIT_ROUTE_COMPLETED, Ordering::Release);
            return NativePostExitRouteCompletionFinishResult::NotOwned;
        }

        let NativePostExitRouteCompletion {
            owner: _,
            parked,
            proof,
        } = completion;
        match parked.finish_after_b() {
            Ok(()) => match proof.release_worker_admission(&RUNTIME_FORK_ADMISSION) {
                Ok(()) => {
                    self.state
                        .store(NATIVE_POST_EXIT_ROUTE_EMPTY, Ordering::Release);
                    NativePostExitRouteCompletionFinishResult::Finished
                }
                Err(proof) => {
                    // The scheduler token has already left its parked count,
                    // but A's exact fork-admission proof still has to remain
                    // represented. Preserve it in this terminal entry and
                    // close the full process boundary.
                    unsafe {
                        (*self.entry.get()).write(NativePostExitRouteEntry::RetainedAdmission {
                            proof,
                        })
                    };
                    RUNTIME_PROCESS.retain();
                    self.publish_retained();
                    NativePostExitRouteCompletionFinishResult::Retained
                }
            },
            Err(parked) => {
                // `finish_after_b` already retained the scheduler on failure.
                // Keep both exact linear capabilities process-terminal instead
                // of making the completion appear consumed.
                unsafe {
                    (*self.entry.get()).write(NativePostExitRouteEntry::RetainedFinished {
                        parked,
                        proof,
                    })
                };
                self.publish_retained();
                NativePostExitRouteCompletionFinishResult::Retained
            }
        }
    }

}

/// One permanent node in the metadata-backed detached-route registry.
///
/// The metadata capability intentionally remains in the same process-lifetime
/// allocation as this node. It is never released or moved: a concurrent raw
/// C free may have acquired the node from the registry head, so reclaiming
/// node storage would require an unrelated hazard-pointer or epoch protocol.
/// Empty entries are reused only after their matching B lifecycle released
/// every terminal completion. This bounds retained metadata by the high-water
/// of simultaneously detached routes and completed B-owned routes rather than
/// by the number of sequential worker exits.
struct NativePostExitRouteRegistryNode {
    next: AtomicPtr<NativePostExitRouteRegistryNode>,
    storage: NativePostExitRouteStorage,
    /// Keeps the exact metadata backing capability live for this stable node.
    /// It is deliberately not exposed or freed independently of the node.
    _backing: MetaAllocation<'static>,
}

// Metadata's ordinary source allocation is naturally aligned to the native
// malloc boundary. Keep this node's typed image within that established
// guarantee before projecting its bytes as a registry entry.
const _: [(); 1] = [();
    (core::mem::align_of::<NativePostExitRouteRegistryNode>() <= NATIVE_C_MALLOC_ALIGNMENT)
        as usize
];

impl NativePostExitRouteRegistryNode {
    #[inline]
    fn new_reserved(
        next: *mut NativePostExitRouteRegistryNode,
        backing: MetaAllocation<'static>,
    ) -> Self {
        Self {
            next: AtomicPtr::new(next),
            storage: NativePostExitRouteStorage::reserved(),
            _backing: backing,
        }
    }
}

// SAFETY: `next` is initialized before this node is Release-published and is
// never changed. The only mutable route state is inside `storage`, whose own
// `ACTIVE -> BUSY` protocol already provides the required exclusion. The
// metadata capability is process-lived and never accessed through this shared
// reference after initialization.
unsafe impl Sync for NativePostExitRouteRegistryNode {}

/// Result of looking for a reusable detached-route registry entry while the
/// registry's short mutation guard is held.
enum NativePostExitRouteRegistryReservationLookup {
    Reserved(&'static NativePostExitRouteStorage),
    NeedsEntry,
    Retained,
}

/// Private state of the complete registry view used before another A may
/// begin its source owner-exit traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePostExitRouteRegistryView {
    Empty,
    Live,
    Retained,
}

/// The private metadata-backed native post-exit router.
///
/// Nodes have a stable process-lifetime address and the list only grows under
/// the short registry mutation word. That word also closes future
/// installation once any entry becomes terminally retained. Scanning never
/// returns a route, raw client, or PageMap fact to the caller. A foreign
/// address restores the claimed entry before the next node is considered, so
/// exact C frees remain serialized per route and source PageMap access remains
/// route-local.
struct NativePostExitRouteRegistry {
    mutation: AtomicU8,
    head: AtomicPtr<NativePostExitRouteRegistryNode>,
}

/// One short registry reservation held while an A-side operation is still
/// `BUSY`. Its storage entry is visible as live to a concurrent source drain,
/// but no raw-C route operation can read the uninitialized image until
/// [`Self::publish`] installs the matching parked scheduler token.
#[must_use = "a detached-route registry reservation must publish or retain its exact source route"]
struct NativePostExitRouteRegistryReservation {
    registry: &'static NativePostExitRouteRegistry,
    storage: &'static NativePostExitRouteStorage,
    active: bool,
}

impl NativePostExitRouteRegistryReservation {
    /// Publishes the complete route before allowing another installer to use
    /// the registry mutation boundary. `route` already contains the exact
    /// parked token produced while this reservation kept the new node busy.
    fn publish(mut self, route: NativePostExitRoute) {
        self.storage.publish_reserved(route);
        self.registry.release_mutation();
        self.active = false;
    }

    /// Closes this reserved node after the matching page-owner operation
    /// failed before it could produce a parked token. The caller retains the
    /// separate route/admission image terminally; this storage has never
    /// initialized its route cell and must not become reusable.
    fn retain(mut self) {
        self.storage.retain_reserved();
        self.registry.retain_held_mutation();
        self.active = false;
    }
}

impl Drop for NativePostExitRouteRegistryReservation {
    fn drop(&mut self) {
        if self.active {
            // A dropped reservation has a source route or scheduler claim
            // whose complete relationship can no longer be proven. Keep the
            // uninitialized entry non-reusable and close future route
            // installation before the surrounding owner is retained.
            self.storage.retain_reserved();
            self.registry.retain_held_mutation();
            RUNTIME_PROCESS.retain_page_owner();
        }
    }
}

impl NativePostExitRouteRegistry {
    const fn new() -> Self {
        Self {
            mutation: AtomicU8::new(NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE),
            head: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Scans the stable list once while the short registry mutation boundary
    /// is held. A retained node wins over a reusable empty node: once source
    /// ownership is terminal, another detached A may not publish a route
    /// beside it.
    fn try_reserve_existing(&'static self) -> NativePostExitRouteRegistryReservationLookup {
        let mut candidate: *mut NativePostExitRouteRegistryNode = core::ptr::null_mut();
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: every node is fully initialized before the Release store
            // that links it from `head`, and nodes are never removed or moved.
            let node = unsafe { &*current };
            match node.storage.registry_state() {
                NativePostExitRouteStorageState::Empty if candidate.is_null() => {
                    candidate = current;
                }
                NativePostExitRouteStorageState::Empty | NativePostExitRouteStorageState::Live => {}
                NativePostExitRouteStorageState::Retained => {
                    return NativePostExitRouteRegistryReservationLookup::Retained;
                }
            }
            current = node.next.load(Ordering::Acquire);
        }
        if candidate.is_null() {
            return NativePostExitRouteRegistryReservationLookup::NeedsEntry;
        }
        // SAFETY: `candidate` was read from the stable registry list above.
        // The registry mutation word serializes another installer and a
        // terminal close, while the entry CAS remains the local proof that a
        // route never overwrites a nonempty stable node.
        let storage = unsafe { &(*candidate).storage };
        if storage.reserve() {
            NativePostExitRouteRegistryReservationLookup::Reserved(storage)
        } else {
            NativePostExitRouteRegistryReservationLookup::NeedsEntry
        }
    }

    /// Acquires the registry-only transition that installs a new detached
    /// owner. It never covers ordinary exact frees or usable-size queries;
    /// those retain their existing per-entry `ACTIVE -> BUSY` serialization.
    /// A retained registry is process-terminal for future detached-owner
    /// installation, so this reports false without reopening it.
    fn acquire_mutation(&self) -> bool {
        loop {
            match self.mutation.load(Ordering::Acquire) {
                NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE => {
                    if self
                        .mutation
                        .compare_exchange(
                            NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE,
                            NATIVE_POST_EXIT_ROUTE_REGISTRY_MUTATING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                NATIVE_POST_EXIT_ROUTE_REGISTRY_MUTATING => core::hint::spin_loop(),
                NATIVE_POST_EXIT_ROUTE_REGISTRY_RETAINED => return false,
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    return false;
                }
            }
        }
    }

    #[inline]
    fn release_mutation(&self) {
        self.mutation
            .store(NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE, Ordering::Release);
    }

    /// Completes a reservation that failed before publishing a route. The
    /// caller already owns the mutation state, so it must not call the normal
    /// close helper, which waits for that very state to become idle.
    #[inline]
    fn retain_held_mutation(&self) {
        self.mutation
            .store(NATIVE_POST_EXIT_ROUTE_REGISTRY_RETAINED, Ordering::Release);
    }

    /// Tries to close the registry for one already-retained route. A concurrent
    /// installer owns the short mutation word until it has either published
    /// its whole route or retained that exact source owner, so closing must
    /// wait instead of overwriting its state back to idle.
    #[inline]
    fn try_close_for_retained_entry(&self) -> bool {
        loop {
            match self.mutation.load(Ordering::Acquire) {
                NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE => {
                    if self
                        .mutation
                        .compare_exchange(
                            NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE,
                            NATIVE_POST_EXIT_ROUTE_REGISTRY_RETAINED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                NATIVE_POST_EXIT_ROUTE_REGISTRY_MUTATING => return false,
                NATIVE_POST_EXIT_ROUTE_REGISTRY_RETAINED => return true,
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    return true;
                }
            }
        }
    }

    /// Closes future detached-route installation after a route becomes
    /// terminally retained. It exposes no entry, client, PageMap, or allocator
    /// capability; it is only the private registry-wide closure fact.
    fn close_for_retained_entry(&self) {
        while !self.try_close_for_retained_entry() {
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn is_closed_for_retained_entry(&self) -> bool {
        match self.mutation.load(Ordering::Acquire) {
            NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE
            | NATIVE_POST_EXIT_ROUTE_REGISTRY_MUTATING => false,
            NATIVE_POST_EXIT_ROUTE_REGISTRY_RETAINED => true,
            _ => {
                RUNTIME_PROCESS.retain_page_owner();
                true
            }
        }
    }

    /// Reserves the next detached-route entry while A still owns its complete
    /// runtime page operation. The reservation is already visible as `Live`
    /// to a concurrent A's source-list preflight, but remains `BUSY` to raw-C
    /// readers until A has converted its own operation into the route's
    /// parked scheduler token and calls [`NativePostExitRouteRegistryReservation::publish`].
    ///
    /// This closes the publication gap between source abandonment and typed
    /// route registration: another owner may no longer see an empty registry
    /// after the first owner has detached its Theap/TLD.
    fn reserve(
        &'static self,
        config: MemoryConfig,
    ) -> Result<NativePostExitRouteRegistryReservation, ()> {
        if !self.acquire_mutation() {
            return Err(());
        }

        // This whole reservation shares one linearization boundary with
        // terminal closure. A retained route therefore cannot appear after
        // this A has selected an empty node but before that node becomes a
        // visible busy source-list member.
        match self.try_reserve_existing() {
            NativePostExitRouteRegistryReservationLookup::Reserved(storage) => {
                return Ok(NativePostExitRouteRegistryReservation {
                    registry: self,
                    storage,
                    active: true,
                });
            }
            NativePostExitRouteRegistryReservationLookup::NeedsEntry => {}
            NativePostExitRouteRegistryReservationLookup::Retained => {
                self.release_mutation();
                return Err(());
            }
        }

        let backing = match MetaAllocator::global().zalloc(
            config,
            core::mem::size_of::<NativePostExitRouteRegistryNode>(),
        ) {
            Ok(backing) => backing,
            Err(_) => {
                self.release_mutation();
                return Err(());
            }
        };
        let next = self.head.load(Ordering::Acquire);
        let node = backing
            .pointer()
            .as_ptr()
            .cast::<NativePostExitRouteRegistryNode>();
        // SAFETY: `backing` is a fresh zeroed metadata allocation with the
        // compile-time-checked alignment above. This is its one typed node
        // initialization, before any registry reader can acquire `head`. Its
        // storage stays BUSY until the caller publishes a complete route.
        unsafe { node.write(NativePostExitRouteRegistryNode::new_reserved(next, backing)) };
        self.head.store(node, Ordering::Release);
        // SAFETY: the new node has a process-lifetime metadata backing and
        // was fully initialized before its Release publication above.
        let storage = unsafe { &(*node).storage };
        Ok(NativePostExitRouteRegistryReservation {
            registry: self,
            storage,
            active: true,
        })
    }

    /// Reports whether every currently published detached route or completed
    /// B lifecycle entry remains live. The caller receives no entry identity
    /// or list access. A `Live` answer means every pre-existing private OS-list
    /// member is still owned by one typed route whose terminal exact free
    /// unlinks only its own member, or by one completion that still owns a
    /// parked token and admission proof.
    fn view(&self) -> NativePostExitRouteRegistryView {
        if self.is_closed_for_retained_entry() {
            return NativePostExitRouteRegistryView::Retained;
        }
        let mut live = false;
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: see `try_install_existing`; the append-only node chain
            // makes this exact entry stable for the complete inspection.
            let node = unsafe { &*current };
            match node.storage.registry_state() {
                NativePostExitRouteStorageState::Empty => {}
                NativePostExitRouteStorageState::Live => live = true,
                NativePostExitRouteStorageState::Retained => {
                    return NativePostExitRouteRegistryView::Retained;
                }
            }
            current = node.next.load(Ordering::Acquire);
        }
        if live {
            NativePostExitRouteRegistryView::Live
        } else {
            NativePostExitRouteRegistryView::Empty
        }
    }

    /// Offers one raw C address to the private detached routes. A retained
    /// entry has already made the shared runtime terminal, so no later node
    /// may safely answer a free after that point.
    fn free_exact(&self, block: core::ptr::NonNull<u8>) -> NativePostExitRouteFreeResult {
        if self.is_closed_for_retained_entry() {
            return NativePostExitRouteFreeResult::Retained;
        }
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: nodes stay linked and stable for the process lifetime.
            let node = unsafe { &*current };
            match node.storage.free_exact(block) {
                NativePostExitRouteFreeResult::NotOwned => {
                    current = node.next.load(Ordering::Acquire);
                }
                result => return result,
            }
        }
        NativePostExitRouteFreeResult::NotOwned
    }

    /// Offers one raw C address to the private detached routes for the one
    /// source-shaped B allocation/copy/free transition. Each entry decides
    /// membership under its own `ACTIVE -> BUSY` move; the registry never
    /// returns a route, a client identity, or a page capability while it
    /// continues its stable-node scan after an address miss.
    fn reallocate_exact(
        &self,
        block: core::ptr::NonNull<u8>,
        new_size: usize,
    ) -> NativePostExitRouteReallocateResult {
        if self.is_closed_for_retained_entry() {
            return NativePostExitRouteReallocateResult::Retained;
        }
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: nodes stay linked and stable for the process lifetime.
            let node = unsafe { &*current };
            match node.storage.reallocate_exact(block, new_size) {
                NativePostExitRouteReallocateResult::NotOwned => {
                    current = node.next.load(Ordering::Acquire);
                }
                result => return result,
            }
        }
        NativePostExitRouteReallocateResult::NotOwned
    }

    /// Looks up one source-recorded extent without exposing which private
    /// route owns it. A failed node lookup restores that entry before the next
    /// stable node is considered.
    fn usable_size_exact(&self, block: core::ptr::NonNull<u8>) -> Option<usize> {
        if self.is_closed_for_retained_entry() {
            return None;
        }
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: nodes stay linked and stable for the process lifetime.
            let node = unsafe { &*current };
            match node.storage.usable_size_exact(block) {
                NativePostExitRouteUsableSizeResult::Owned(usable_size) => return Some(usable_size),
                NativePostExitRouteUsableSizeResult::Retained => return None,
                NativePostExitRouteUsableSizeResult::NotOwned => {
                    current = node.next.load(Ordering::Acquire);
                }
            }
        }
        None
    }

    /// Finishes exactly the completed routes assigned to one B attachment
    /// after that attachment has already crossed its ordinary source teardown.
    /// The caller supplies only an opaque compiler-TLS identity and a scalar
    /// count; this scan exposes no stable node, route, C client, page, or
    /// admission proof. Every matched entry performs its own
    /// `COMPLETED -> BUSY` claim before it can remove a parked token.
    fn finish_completions_for_owner(
        &self,
        owner: NativePostExitRouteCompletionOwner,
        expected_count: usize,
    ) -> NativePostExitRouteCompletionsFinishResult {
        if expected_count == 0 {
            return NativePostExitRouteCompletionsFinishResult::Finished;
        }

        let mut completed_count = 0usize;
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: nodes are fully initialized before their Release
            // publication and never leave the append-only registry list.
            let node = unsafe { &*current };
            match node.storage.finish_completion_for_owner(owner) {
                NativePostExitRouteCompletionFinishResult::NotOwned => {}
                NativePostExitRouteCompletionFinishResult::Finished => {
                    let Some(next_count) = completed_count.checked_add(1) else {
                        RUNTIME_PROCESS.retain_page_owner();
                        self.close_for_retained_entry();
                        return NativePostExitRouteCompletionsFinishResult::Retained;
                    };
                    completed_count = next_count;
                    if completed_count > expected_count {
                        // The scalar TLS count and stable entry ownership
                        // disagree. Do not release another admission based on
                        // a guessed attachment boundary.
                        RUNTIME_PROCESS.retain_page_owner();
                        self.close_for_retained_entry();
                        return NativePostExitRouteCompletionsFinishResult::Retained;
                    }
                }
                NativePostExitRouteCompletionFinishResult::Retained => {
                    return NativePostExitRouteCompletionsFinishResult::Retained;
                }
            }
            current = node.next.load(Ordering::Acquire);
        }

        if completed_count == expected_count {
            NativePostExitRouteCompletionsFinishResult::Finished
        } else {
            // An attachment count that cannot find every exact completed
            // entry is never retryable: a missing parked token/proof must
            // keep the process terminal rather than look quiescent.
            RUNTIME_PROCESS.retain_page_owner();
            self.close_for_retained_entry();
            NativePostExitRouteCompletionsFinishResult::Retained
        }
    }

    /// Counts only stable entry states for the direct high-water regression.
    /// It returns no route identity or capability, and it must be sampled
    /// after the test's participating workers have joined. A transient busy
    /// state is intentionally counted as live by `registry_state`.
    #[cfg(feature = "native-runtime-test-audit")]
    fn test_audit(&self) -> NativePostExitRouteRegistryAudit {
        let mut audit = NativePostExitRouteRegistryAudit {
            published_entry_count: 0,
            live_entry_count: 0,
            retained_entry_count: 0,
        };
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: every node is fully initialized before its Release
            // publication, and append-only links keep the node address valid
            // for this diagnostic-only traversal.
            let node = unsafe { &*current };
            audit.published_entry_count += 1;
            match node.storage.registry_state() {
                NativePostExitRouteStorageState::Empty => {}
                NativePostExitRouteStorageState::Live => audit.live_entry_count += 1,
                NativePostExitRouteStorageState::Retained => audit.retained_entry_count += 1,
            }
            current = node.next.load(Ordering::Acquire);
        }
        audit
    }
}

// SAFETY: the registry publishes only fully initialized immutable node links.
// Each node's mutable route state is independently protected by its storage
// protocol, and the mutation word serializes installation with terminal
// closure.
unsafe impl Sync for NativePostExitRouteRegistry {}

static NATIVE_POST_EXIT_ROUTE: NativePostExitRouteRegistry = NativePostExitRouteRegistry::new();

/// Returns scalar-only accounting for the private native post-exit registry.
///
/// This direct-test hook is feature-gated and deliberately cannot identify,
/// operate on, or release any registry entry. See
/// [`NativePostExitRouteRegistryAudit`] for the quiescent-sampling contract.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
pub fn native_post_exit_registry_test_audit() -> NativePostExitRouteRegistryAudit {
    NATIVE_POST_EXIT_ROUTE.test_audit()
}

/// Returns scalar-only lifecycle accounting for the process-global runtime.
///
/// A `None` result means the source process image is not active and quiescent
/// enough to produce an auditable snapshot. It intentionally does not turn an
/// audit request into a scheduler claim or a PageMap operation.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
pub fn native_runtime_lifecycle_test_audit() -> Option<NativeRuntimeLifecycleAudit> {
    let process_active = RUNTIME_PROCESS.is_active();
    if !process_active {
        return None;
    }
    // SAFETY: PROCESS_ACTIVE follows the one process-lifetime owner and main
    // Heap publication. This diagnostic takes only their immutable witnesses.
    let owner = unsafe { RUNTIME_PROCESS.active_owner() }?;
    let ready = owner.ready().ok()?;
    let process_page_map = ready.page_map().ok()?;
    let page_map = process_page_map.page_map().ok()?;
    let arena = ProcessSharedArenaStorage::global().ready_lease().ok()?;
    let subprocess = ready.subprocess().ok()?;
    // SAFETY: see the owner access above. The copied lease permits one short
    // serialized read-only Heap projection and carries no allocator authority.
    let main_heap = unsafe { RUNTIME_PROCESS.active_main_heap() }?;
    let (main_heap_abandoned_page_count, main_heap_os_abandoned_pages_empty) =
        native_runtime_main_heap_lifecycle_audit(main_heap)?;
    let metadata = MetaAllocator::global().test_allocation_audit();

    Some(NativeRuntimeLifecycleAudit {
        process_active: usize::from(process_active),
        // The audit's scalar "ready" means the initial source owner can
        // accept its ordinary current-thread operation. Once W01 has moved
        // the static staging image into compiler TLS, that direct owner has
        // the same externally observable readiness without being a legacy
        // scheduler `READY` slot.
        page_owner_ready: usize::from(matches!(
            RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire),
            PAGE_OWNER_READY | PAGE_OWNER_INITIAL_PERSISTENT
        )),
        page_map_registered_entry_count: page_map.test_registered_entry_count().ok()?,
        page_map_published_submap_count: page_map.test_published_submap_count().ok()?,
        page_map_lazy_submap_allocation_count: page_map.test_lazy_submap_allocation_count(),
        arena_registry_count: arena.test_registry_count().ok()?,
        live_thread_count: subprocess.live_thread_count(),
        metadata_live_capability_count: metadata.live_capability_count,
        metadata_high_water_capability_count: metadata.high_water_capability_count,
        shared_later_theap_count: main_heap.test_shared_later_theap_count(),
        main_heap_abandoned_page_count,
        main_heap_os_abandoned_pages_empty: usize::from(main_heap_os_abandoned_pages_empty),
        native_owner_local_operation_count: NATIVE_OWNER_LOCAL_OPERATION_COUNT
            .load(Ordering::Acquire),
        native_parked_compatibility_operation_count:
            NATIVE_PARKED_COMPATIBILITY_OPERATION_COUNT.load(Ordering::Acquire),
        native_scheduler_transition_count: NATIVE_SCHEDULER_TRANSITION_COUNT
            .load(Ordering::Acquire),
    })
}

/// Returns scalar-only accounting for the private fork-admission gate.
///
/// This direct-test hook intentionally reads one atomic word and cannot turn
/// that read into an admission claim, a fork preparation, or any allocator
/// operation. It exists so a terminal post-exit regression can distinguish
/// A's still-retained worker admission from the independent parked page-owner
/// token after B has completed its own ordinary finish.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
pub fn native_runtime_fork_admission_test_audit() -> NativeRuntimeForkAdmissionAudit {
    let state = RUNTIME_FORK_ADMISSION.state.load(Ordering::Acquire);
    NativeRuntimeForkAdmissionAudit {
        active_later_thread_count: state & FORK_GATE_COUNT_MASK,
    }
}

/// One direct-test-only guard that makes the next allocator `munmap` fail.
///
/// This deliberately exposes neither a generic fault plan nor any allocator
/// route, page, client, scheduler, or PageMap capability. The sole native
/// post-exit regression uses it after A's aggregate route has detached and
/// immediately before B offers the exact OS-aligned client to that opaque
/// route. Dropping the guard clears the one test process's injection.
#[cfg(feature = "native-runtime-test-fault")]
#[doc(hidden)]
pub struct NativeRuntimeTestUnmapFailure {
    guard: crate::os::fault::Guard,
}

#[cfg(feature = "native-runtime-test-fault")]
impl NativeRuntimeTestUnmapFailure {
    /// Returns the number of selected `munmap` attempts observed while this
    /// serial direct-test guard was installed.
    #[doc(hidden)]
    #[inline]
    pub fn observed(&self) -> usize {
        self.guard.observed()
    }
}

/// Installs the one direct-test `munmap` failure used at the native post-exit
/// terminal-release boundary.
///
/// The default-off feature keeps this hook out of normal allocator and libc
/// builds. It never exposes the fault subsystem's general plan or any source
/// route capability to a caller.
#[cfg(feature = "native-runtime-test-fault")]
#[doc(hidden)]
pub fn native_runtime_test_fail_next_unmap() -> NativeRuntimeTestUnmapFailure {
    NativeRuntimeTestUnmapFailure {
        guard: crate::os::fault::install(crate::os::fault::Plan::at(
            crate::os::fault::Point::Unmap,
            1,
            crabc_core::Errno::NOMEM,
        )),
    }
}

/// Reads the scalar static-Heap state while holding exactly the established
/// short projection guard. The explicit unlock is part of this diagnostic's
/// contract: an audit failure must not leave an evidence-only lock held.
#[cfg(feature = "native-runtime-test-audit")]
fn native_runtime_main_heap_lifecycle_audit(
    main_heap: MainStaticHeapLease<'static>,
) -> Option<(usize, bool)> {
    let mut heap = main_heap.lock_heap().ok()?;
    let result = (|| {
        let heap = heap.heap_mut();
        let abandoned_page_count = (0..crate::config::BIN_COUNT)
            .try_fold(0usize, |total, bin| total.checked_add(heap.abandoned_count(bin)?))?;
        let os_abandoned_pages_empty = heap.os_abandoned_pages_are_empty().ok()?;
        Some((abandoned_page_count, os_abandoned_pages_empty))
    })();
    match (result, heap.unlock()) {
        (Some(snapshot), Ok(())) => Some(snapshot),
        (Some(_) | None, Err(_)) | (None, Ok(())) => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadLifecycleState {
    Fresh,
    Attached,
    Finished,
    Retained,
}

/// The source-shaped owner retained for ordinary later-thread native calls.
///
/// The attachment and continuously stored page engine are co-located values,
/// not a self-reference. Each C operation temporarily splits one mutable
/// borrow into the lower engine's short attachment/session projection. Source
/// Page and PageMap state is the allocation record; this owner deliberately
/// contains no client ledger, scheduler token, or process registry entry.
#[must_use = "a persistent native thread owner must finish or remain retained in compiler TLS"]
struct NativePersistentThreadOwner {
    attachment: MainHeapThreadAttachment<'static>,
    state: NativePersistentThreadOwnerExitState,
}

/// The only persistent-owner states accepted at its one-way exit boundary.
///
/// The split prevents a terminal post-drain engine from being mistaken for a
/// retryable pre-drain engine when compiler TLS retains the outer owner after
/// an error. No variant carries a scheduler token, registry entry, route, or
/// raw pointer capability.
enum NativePersistentThreadOwnerExitState {
    PreDrain(MainHeapThreadOwnerLocalPageEngine),
    RetainedTerminalEngine(MainHeapThreadOwnerLocalPageEngine),
    AttachmentOnly,
}

impl NativePersistentThreadOwner {
    /// Binds one short attachment view to the continuously stored engine.
    /// The scalar audit advances only after both the compiler-TLS projection
    /// and this source-engine projection succeeded.
    fn with_local_allocator<R>(
        &mut self,
        operation: impl FnOnce(&mut MainHeapThreadOwnerLocalAllocator<'_>) -> R,
    ) -> Result<R, ()> {
        let NativePersistentThreadOwnerExitState::PreDrain(engine) = &mut self.state else {
            return Err(());
        };
        let result = engine
            .with_local_allocator(&mut self.attachment, operation)
            .map_err(|_| ())?;
        #[cfg(feature = "native-runtime-test-audit")]
        NATIVE_OWNER_LOCAL_OPERATION_COUNT.fetch_add(1, Ordering::AcqRel);
        Ok(result)
    }

    /// Completes source collect-abandon then the final attachment boundary.
    ///
    /// Only `PreDrain` may enter the source queue traversal. A terminal
    /// retained engine is deliberately returned untouched, while an
    /// attachment-only continuation retries no allocator work.
    fn teardown(&mut self) -> Result<(), ()> {
        let state = core::mem::replace(
            &mut self.state,
            NativePersistentThreadOwnerExitState::AttachmentOnly,
        );
        match state {
            NativePersistentThreadOwnerExitState::PreDrain(engine) => {
                match engine.finish_after_collect_abandon(&mut self.attachment) {
                    Ok(()) => return Ok(()),
                    Err(
                        crate::main_heap_page::MainHeapThreadOwnerLocalPageEngineCollectAbandonFailure::PreDrain(
                            engine,
                        ),
                    ) => {
                        self.state = NativePersistentThreadOwnerExitState::PreDrain(engine);
                        return Err(());
                    }
                    Err(
                        crate::main_heap_page::MainHeapThreadOwnerLocalPageEngineCollectAbandonFailure::RetainedTerminalEngine(
                            engine,
                        ),
                    ) => {
                        self.state =
                            NativePersistentThreadOwnerExitState::RetainedTerminalEngine(engine);
                        return Err(());
                    }
                    Err(
                        crate::main_heap_page::MainHeapThreadOwnerLocalPageEngineCollectAbandonFailure::AttachmentOnly,
                    ) => {}
                }
            }
            NativePersistentThreadOwnerExitState::RetainedTerminalEngine(engine) => {
                self.state = NativePersistentThreadOwnerExitState::RetainedTerminalEngine(engine);
                return Err(());
            }
            NativePersistentThreadOwnerExitState::AttachmentOnly => {}
        }

        self.attachment
            .finish_after_user_destructors()
            .or_else(|error| match error {
                // This exact refusal proves the page engine already completed
                // its source drain. No engine can be reconstructed; only the
                // remaining root/list/TLD boundary may retry.
                MainHeapThreadAttachmentError::PageDrainState => {
                    // SAFETY: `AttachmentOnly` is minted only after the drain
                    // proved queues/direct cache/page count empty and
                    // released or abandoned every former page.
                    unsafe { self.attachment.finish_after_detached_process_page_route() }
                }
                error => Err(error),
            })
            .map_err(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePersistentThreadOwnerAccessError {
    NotInstalled,
    Unavailable,
    Retained,
}

/// The initial thread's continuously owned source page engine.
///
/// Pinned initialization gives ticket zero static storage, but that storage
/// does not require an ordinary operation to pass through the historical
/// process scheduler.  At one explicit promotion boundary the complete
/// `MainStaticRuntimeFirstArenaPageAllocator` moves from its process-static
/// staging slot into this compiler-TLS cell.  The cell then owns the exact
/// session, active engine, and any long PageMap lifecycle for the initial
/// thread's lifetime.  It contains no route, registry, client ledger, or
/// scheduler token.
#[must_use = "the initial persistent owner remains in compiler TLS for the process lifetime"]
struct NativeInitialPersistentThreadOwner {
    allocator: MainStaticRuntimeFirstArenaPageAllocator,
}

impl NativeInitialPersistentThreadOwner {
    #[inline]
    fn allocate(&mut self, request: usize, zero: bool) -> Option<core::ptr::NonNull<u8>> {
        self.allocator
            .allocate_current_initial_thread_local(request, zero)
    }

    #[inline]
    fn allocate_aligned(
        &mut self,
        request: usize,
        alignment: usize,
        zero: bool,
    ) -> Option<core::ptr::NonNull<u8>> {
        self.allocator
            .allocate_aligned_current_initial_thread_local(request, alignment, zero)
    }

    /// Reallocates one exact current initial-thread client without entering a
    /// parked compatibility engine.
    ///
    /// # Safety
    ///
    /// `block` must remain a live local allocation of this exact persistent
    /// owner and must not have been remotely published or freed.
    #[inline]
    unsafe fn reallocate(
        &mut self,
        block: core::ptr::NonNull<u8>,
        new_size: usize,
    ) -> Option<core::ptr::NonNull<u8>> {
        // SAFETY: forwarded unchanged from this owner-local boundary.
        unsafe {
            self.allocator
                .reallocate_current_initial_thread_local(Some(block), new_size)
        }
    }

    /// Frees one exact current initial-thread client without a scheduler
    /// claim, park, or resume.
    ///
    /// # Safety
    ///
    /// `block` must remain a live local allocation of this exact persistent
    /// owner and must not have been remotely published or freed.
    #[inline]
    unsafe fn free(
        &mut self,
        block: core::ptr::NonNull<u8>,
    ) -> Result<(), crate::main_static_page::MainStaticRuntimeFirstArenaPageAllocatorFreeError>
    {
        // SAFETY: forwarded unchanged from this owner-local boundary.
        unsafe {
            self.allocator
                .free_current_initial_thread_local(block)
        }
    }

    /// Queries a live initial-thread client directly from its current engine.
    ///
    /// # Safety
    ///
    /// `block` must remain current in this exact local owner.
    #[inline]
    unsafe fn usable_size(&mut self, block: core::ptr::NonNull<u8>) -> Option<usize> {
        // SAFETY: forwarded unchanged from this owner-local boundary.
        unsafe {
            self.allocator
                .usable_size_current_initial_thread_local(block)
        }
    }

    /// Establishes or confirms the dormant first-arena state before a later
    /// worker starts. A live initial engine is deliberately rejected instead
    /// of being parked or lent through the former static owner.
    #[inline]
    fn prepare_dormant_page_pair_for_later_thread(&mut self) -> bool {
        self.allocator
            .prepare_dormant_page_pair_current_initial_thread_local()
    }

    #[inline]
    fn is_retained(&self) -> bool {
        self.allocator.is_retained()
    }

    /// Reports whether this direct initial source owner is safe to copy into
    /// the prepared raw-fork child.
    ///
    /// The caller must have already held the fork-admission gate with zero
    /// later admissions. That gate excludes the only other runtime owners;
    /// the current initial thread then uses its pinned TLS cell rather than
    /// the vacated process-static staging slot to inspect the source state.
    #[inline]
    fn is_quiescent_for_held_fork_gate(&self) -> bool {
        self.allocator.is_quiescent_for_fork()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeInitialPersistentThreadOwnerAccessError {
    NotInstalled,
    Unavailable,
    Retained,
}

/// Per-pthread compiler-TLS storage for the explicit later-thread owner.
///
/// It intentionally has no destructor: libc calls the source-ordered finish
/// explicitly. Dropping an attached owner at ELF TLS teardown would hide a
/// failed lifecycle transition and could free state before the main Heap list
/// had been detached.
struct ThreadLifecycleSlot {
    state: ThreadLifecycleState,
    /// A successful admission remains claimed from child attach through the
    /// complete post-destructor finish. Retained states intentionally keep
    /// their claim in the parent, making later fork preservation reject
    /// rather than treating ambiguous source ownership as quiescent.
    admission: Option<LaterThreadAdmissionClaim>,
    /// The opaque per-attachment generation matched by completed registry
    /// entries. It is never exposed beyond this module and makes an old
    /// completion unable to match a later attachment that reuses this TLS
    /// address.
    post_exit_route_completion_generation: usize,
    /// Counts terminal native post-exit completions assigned to this B
    /// attachment. The entries retain their typed parked tokens and proofs in
    /// the stable private registry until this attachment's ordinary finish;
    /// TLS carries only scalar lifecycle accounting, never a route or client.
    pending_post_exit_route_completion_count: usize,
    attachment: Option<MainHeapThreadAttachment<'static>>,
    /// Ordinary C-shaped later-thread operations promote `attachment` into
    /// this address-stable cell once, then use only in-place scoped borrows.
    /// Legacy typed owner-exit fixtures continue to use `attachment` plus
    /// `page_owner` until their separate migration lands.
    native_persistent_owner: PersistentCompilerTlsOwnerCell<NativePersistentThreadOwner>,
    /// Distinguishes the cell's installed/retained payload from the other
    /// lifecycle shapes whose attachment and page-owner fields are empty.
    /// This is current-thread scalar state, not allocation or route metadata.
    native_persistent_owner_installed: bool,
    /// The initial thread has a distinct static-storage source owner.  It
    /// moves here once and remains in this same compiler-TLS cell for the
    /// process lifetime, so ordinary initial local operations do not claim
    /// the legacy ticket-zero scheduler.
    initial_native_persistent_owner:
        PersistentCompilerTlsOwnerCell<NativeInitialPersistentThreadOwner>,
    /// Distinguishes an installed initial persistent source owner from the
    /// untouched process-static staging slot.  This is current-thread state,
    /// never a pointer lookup or process routing record.
    initial_native_persistent_owner_installed: bool,
    /// A current-thread-only page engine that deliberately released its Rust
    /// borrow before it entered compiler TLS.  A normal no-page finalizer
    /// must never cross this state: it has to resume the matching engine and
    /// drive the source owner-exit coordinator first.
    page_owner: Option<ThreadLifecyclePageOwner>,
    /// A private current-thread session handle carries this generation while
    /// ordinary page operations repeatedly park and resume the same source
    /// engine.  Keeping it in TLS prevents a stale, dropped handle from
    /// operating a later session that happens to reuse the slot.
    next_page_owner_session_generation: usize,
}

impl ThreadLifecycleSlot {
    const fn new() -> Self {
        Self {
            state: ThreadLifecycleState::Fresh,
            admission: None,
            post_exit_route_completion_generation: 0,
            pending_post_exit_route_completion_count: 0,
            attachment: None,
            native_persistent_owner: PersistentCompilerTlsOwnerCell::new(),
            native_persistent_owner_installed: false,
            initial_native_persistent_owner: PersistentCompilerTlsOwnerCell::new(),
            initial_native_persistent_owner_installed: false,
            page_owner: None,
            next_page_owner_session_generation: 0,
        }
    }

    #[inline]
    fn next_page_owner_session_generation(&mut self) -> usize {
        self.next_page_owner_session_generation = self
            .next_page_owner_session_generation
            .wrapping_add(1);
        if self.next_page_owner_session_generation == 0 {
            // Zero remains an impossible session generation so a stale
            // private handle cannot name a newly installed TLS session after
            // counter wraparound.
            self.next_page_owner_session_generation = 1;
        }
        self.next_page_owner_session_generation
    }

    /// Starts the one process-unique opaque completion identity for this
    /// attachment. No completion can be assigned before this happens.
    #[inline]
    fn begin_post_exit_route_completion_lifecycle(&mut self, generation: usize) {
        debug_assert_ne!(generation, 0);
        self.post_exit_route_completion_generation = generation;
        self.pending_post_exit_route_completion_count = 0;
    }

    /// Records one completed A route against this still-attached B lifecycle.
    /// The caller owns this compiler-TLS slot and publishes the matching
    /// registry entry before exposing success to the C free boundary.
    #[inline]
    fn record_post_exit_route_completion(
        &mut self,
        slot: core::ptr::NonNull<ThreadLifecycleSlot>,
    ) -> Option<NativePostExitRouteCompletionOwner> {
        if self.state != ThreadLifecycleState::Attached
            || self.post_exit_route_completion_generation == 0
        {
            return None;
        }
        self.pending_post_exit_route_completion_count = self
            .pending_post_exit_route_completion_count
            .checked_add(1)?;
        Some(NativePostExitRouteCompletionOwner {
            slot,
            generation: self.post_exit_route_completion_generation,
        })
    }

    /// Returns the current attachment's exact completion identity and scalar
    /// count after its ordinary source teardown. The registry still owns every
    /// linear parked token/proof; the count merely detects a missing or stale
    /// entry before any later attachment could be admitted as quiescent.
    #[inline]
    fn post_exit_route_completion_owner_after_finish(
        &self,
        slot: core::ptr::NonNull<ThreadLifecycleSlot>,
    ) -> Option<(NativePostExitRouteCompletionOwner, usize)> {
        if self.state != ThreadLifecycleState::Finished
            || self.post_exit_route_completion_generation == 0
        {
            return None;
        }
        Some((
            NativePostExitRouteCompletionOwner {
                slot,
                generation: self.post_exit_route_completion_generation,
            },
            self.pending_post_exit_route_completion_count,
        ))
    }

    #[inline]
    fn has_pending_post_exit_route_completions(&self) -> bool {
        self.pending_post_exit_route_completion_count != 0
    }

    #[inline]
    fn finish_post_exit_route_completions(
        &mut self,
        owner: NativePostExitRouteCompletionOwner,
        expected_count: usize,
    ) -> bool {
        if self.state != ThreadLifecycleState::Finished
            || self.post_exit_route_completion_generation != owner.generation
            || self.pending_post_exit_route_completion_count != expected_count
        {
            return false;
        }
        self.pending_post_exit_route_completion_count = 0;
        true
    }

    /// Keeps one post-exit admission claim terminally visible in this thread's
    /// TLS state. An existing claim is an impossible double-owner image; keep
    /// both claims nonreleasable rather than dropping either count silently.
    #[inline]
    fn retain_terminal_admission(&mut self, admission: LaterThreadAdmissionClaim) {
        if let Some(previous) = self.admission.replace(admission) {
            core::mem::forget(previous);
        }
    }
}

/// One private page-bearing state retained by the real per-pthread runtime
/// slot between ordinary allocator activity and source-ordered thread exit.
///
/// This deliberately stores a suspended engine rather than an allocator that
/// borrows `attachment`: compiler TLS owns both fields, so the split avoids a
/// self-reference while the lower token preserves its exact PageMap and
/// attachment-session authority. An active session owns its private live
/// client ledger across ordinary operations; only a separately prepared exit
/// may enter the source owner-exit dispatcher. This prevents an active
/// allocator session from being mistaken for a no-page finalizer input.
#[must_use = "a page-bearing runtime slot must resume into owner exit or remain terminally retained"]
enum ThreadLifecyclePageOwner {
    /// The current worker may resume this exact parked engine for another
    /// bounded ordinary operation. It has not yet selected a post-exit route;
    /// on normal finish it may instead enter the typed all-free drain only
    /// when its private ledger has no local live client.
    Session(CurrentThreadPageOwnerSession),
    /// The active session has consumed every local client into a typed route.
    /// This state crosses `finish_current_thread_after_user_destructors` only
    /// through its typed post-exit route.
    PreparedExit(ThreadLifecyclePreparedPageOwner),
}

/// A fully prepared page-bearing owner whose old allocator borrow is parked
/// in compiler TLS until the source-ordered destructor boundary resumes it.
struct ThreadLifecyclePreparedPageOwner {
    parked: RuntimeParkedPersistentPageEngine,
    exit: DetachedOwnerExit,
    /// A native deferred exit keeps its former live-owner entry `BUSY` until
    /// the replacement post-exit route publishes its private ledger. This
    /// prevents an exact foreign `free` from observing an empty gap between
    /// the raw-TLS handoff and the detached route.
    native_live_remote_handoff: Option<NativeLiveRemoteOwnerGuard>,
}

/// The typed post-exit half of a generic page-bearing TLS owner.
///
/// A detached owner retains one coarse client ledger plus only the source
/// disposition that changes lower control flow. It is deliberately not a
/// sum type over test workloads, page kinds, or exact block counts.
#[must_use = "a page-bearing owner exit must reach its typed post-exit route or remain terminally retained"]
struct DetachedOwnerExit {
    clients: DetachedOwnerExitClientLedger,
    disposition: DetachedOwnerExitDisposition,
}

/// The only post-exit choices that alter the source control flow after A has
/// suspended. `SequentialFree` is the general aggregate route. The other
/// branch names the one source-proved immediate mapped regular handoff; its
/// direct-small entrance remains distinct solely because upstream validates a
/// complete rounded direct-cache image before it can produce that same route.
enum DetachedOwnerExitDisposition {
    SequentialFree {
        free_after_exit: TicketZeroOwnerExitFreeConsumer,
        post_exit_remote_publication_group: Option<DetachedOwnerExitRemotePublicationGroup>,
    },
    SoleImmediateMappedRegularReclaim {
        source: DetachedOwnerExitReclaimSource,
        request: usize,
        reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
    },
    /// The nondefault native libc shadow moves this opaque route into one
    /// stable metadata-backed private post-exit registry entry. The scheduler
    /// still retains the same client ledger and A admission, but C presents
    /// later frees one address at a time rather than receiving a route
    /// callback or client identity.
    NativeDeferred,
}

enum DetachedOwnerExitReclaimSource {
    AggregateTraversal,
    DirectSmall {
        first: DetachedOwnerExitClientKey,
    },
}

impl DetachedOwnerExit {
    fn free_locals(
        mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    ) -> Result<(), ()> {
        if let DetachedOwnerExitDisposition::SequentialFree {
            post_exit_remote_publication_group,
            ..
        } = &mut self.disposition
        {
            if let Some(group) = post_exit_remote_publication_group {
                group.free_locals(allocator)?;
            }
        }
        self.clients.free_locals(allocator)
    }
}

#[thread_local]
static THREAD_LIFECYCLE: UnsafeCell<ThreadLifecycleSlot> =
    UnsafeCell::new(ThreadLifecycleSlot::new());

/// One parked native A session eligible for a C-shaped live-owner remote
/// publication.
///
/// The entry deliberately stores the compiler-TLS slot and session generation
/// only. It never stores a client address, a PageMap lease, or an allocator;
/// B must still present an exact address to A's private ledger while holding
/// the source-shaped interleaving scheduler operation.
#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeLiveRemoteOwner {
    slot: core::ptr::NonNull<ThreadLifecycleSlot>,
    generation: usize,
}

/// One entry's state while a B-side native query or free asks whether its A
/// still owns the supplied C address.
enum NativeLiveRemoteOwnerClaim {
    Empty,
    Retained,
    Claimed(NativeLiveRemoteOwnerGuard),
}

/// One nonblocking attempt to claim a live-owner handoff.
///
/// This is deliberately separate from [`NativeLiveRemoteOwnerClaim`]: a
/// caller that owns no other route uses the blocking claim and cannot receive
/// `Busy`, while a caller already holding a foreign route must receive that
/// state and release before retrying. Keeping the two result types distinct
/// prevents an ordinary live-owner scan from accidentally adopting the
/// no-wait protocol.
enum NativeLiveRemoteOwnerTryClaim {
    Empty,
    Busy,
    Retained,
    Claimed(NativeLiveRemoteOwnerGuard),
}

/// Result of looking up the running thread's exact registry entry before it
/// borrows its compiler-TLS session. `Claimed` deliberately keeps that entry
/// `BUSY`: it is the exclusive handoff that makes a cross-thread raw TLS
/// borrow sound. A foreign entry is restored before this value escapes, so it
/// never grants access to another worker's session.
enum NativeLiveRemoteOwnerCurrentClaim {
    Empty,
    Foreign,
    /// A distinct entry is temporarily borrowed while this caller already
    /// owns another live route. The caller must release that route before it
    /// retries its current-slot claim, preserving a no-wait-with-a-guard rule.
    Busy,
    Retained,
    Claimed(NativeLiveRemoteOwnerGuard),
}

/// A private result of scanning stable live-owner entries for one exact C
/// address. The returned client is still module-private and exists only while
/// the accompanying guard excludes A's TLS session from resuming.
enum NativeLiveRemoteOwnerExactClaim {
    NotOwned,
    Retained,
    Claimed {
        route: NativeLiveRemoteOwnerGuard,
        client: PreparedOwnerExitClient,
    },
}

/// A private scalar result of asking live-owner entries for an exact C
/// allocation's source-recorded usable extent.
enum NativeLiveRemoteOwnerUsableSizeResult {
    NotOwned,
    Retained,
    Owned(usize),
}

/// The stable classification used only while installing or scanning a
/// metadata-backed live-owner entry. A `BUSY` entry remains live: a B-side
/// operation temporarily owns its raw TLS handoff but has not removed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeLiveRemoteOwnerStorageState {
    Empty,
    Live,
    Retained,
}

/// One metadata-backed handoff to a parked native A session. The atomic state
/// serializes only moves through `entry`; the runtime page-owner scheduler
/// separately serializes every PageMap and ordinary-page operation.
struct NativeLiveRemoteOwnerStorage {
    state: AtomicU8,
    entry: UnsafeCell<MaybeUninit<NativeLiveRemoteOwner>>,
}

// SAFETY: `ACTIVE -> BUSY` grants one caller exclusive access to `entry`.
// That caller may access A's TLS only while it retains the matching registry
// handoff. A likewise claims it into `BUSY` before moving its session out of
// TLS, then either restores the complete parked image or explicitly removes
// its own publication for terminal source exit.
unsafe impl Sync for NativeLiveRemoteOwnerStorage {}

/// One claimed A-side parked-session publication. Dropping an unresolved claim
/// is terminal: retaining this entry is safer than exposing a raw TLS pointer
/// after an incomplete B-side source transition.
#[must_use = "a native live-owner publication claim must restore A or remain retained"]
struct NativeLiveRemoteOwnerGuard {
    storage: &'static NativeLiveRemoteOwnerStorage,
    owner: Option<NativeLiveRemoteOwner>,
}

impl NativeLiveRemoteOwnerStorage {
    #[inline]
    fn from_active(owner: NativeLiveRemoteOwner) -> Self {
        Self {
            state: AtomicU8::new(NATIVE_LIVE_REMOTE_OWNER_ACTIVE),
            entry: UnsafeCell::new(MaybeUninit::new(owner)),
        }
    }

    /// Publishes a terminal raw-TLS handoff only after the private registry
    /// has closed future live-owner installation. The closure contains no TLS
    /// identity, client, page, or allocator capability; it records only that
    /// a discarded source handoff has made the process terminal.
    #[inline]
    fn publish_retained(&self) {
        NATIVE_LIVE_REMOTE_OWNER.close_for_retained_entry();
        self.state
            .store(NATIVE_LIVE_REMOTE_OWNER_RETAINED, Ordering::Release);
    }

    /// Classifies one stable entry without exposing its raw TLS identity. A
    /// malformed state has no reconstructible source owner, so it becomes
    /// terminal rather than reusable.
    #[inline]
    fn registry_state(&self) -> NativeLiveRemoteOwnerStorageState {
        match self.state.load(Ordering::Acquire) {
            NATIVE_LIVE_REMOTE_OWNER_EMPTY => NativeLiveRemoteOwnerStorageState::Empty,
            NATIVE_LIVE_REMOTE_OWNER_ACTIVE | NATIVE_LIVE_REMOTE_OWNER_BUSY => {
                NativeLiveRemoteOwnerStorageState::Live
            }
            NATIVE_LIVE_REMOTE_OWNER_RETAINED => NativeLiveRemoteOwnerStorageState::Retained,
            _ => {
                RUNTIME_PROCESS.retain_page_owner();
                self.state
                    .store(NATIVE_LIVE_REMOTE_OWNER_RETAINED, Ordering::Release);
                NativeLiveRemoteOwnerStorageState::Retained
            }
        }
    }

    /// Installs one current A session after its first C-facing allocation has
    /// returned to compiler TLS. The caller owns that TLS slot exclusively;
    /// the entry is published only after the full session image is present.
    fn install(&self, owner: NativeLiveRemoteOwner) -> Result<(), NativeLiveRemoteOwner> {
        if self
            .state
            .compare_exchange(
                NATIVE_LIVE_REMOTE_OWNER_EMPTY,
                NATIVE_LIVE_REMOTE_OWNER_BUSY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(owner);
        }
        // SAFETY: the successful EMPTY -> BUSY transition is this entry's
        // unique initialization, and the Release store below publishes it.
        unsafe { (*self.entry.get()).write(owner) };
        self.state
            .store(NATIVE_LIVE_REMOTE_OWNER_ACTIVE, Ordering::Release);
        Ok(())
    }

    /// Claims this active publication for a B-side C query or `free`. The
    /// guard keeps the entry `BUSY`, so A cannot resume or end its page owner
    /// until the guard restores it or terminally retains the process.
    fn claim(&'static self) -> NativeLiveRemoteOwnerClaim {
        loop {
            match self.try_claim() {
                NativeLiveRemoteOwnerTryClaim::Busy => core::hint::spin_loop(),
                NativeLiveRemoteOwnerTryClaim::Empty => {
                    return NativeLiveRemoteOwnerClaim::Empty;
                }
                NativeLiveRemoteOwnerTryClaim::Retained => {
                    return NativeLiveRemoteOwnerClaim::Retained;
                }
                NativeLiveRemoteOwnerTryClaim::Claimed(route) => {
                    return NativeLiveRemoteOwnerClaim::Claimed(route);
                }
            }
        }
    }

    /// Attempts one exact raw-TLS handoff without waiting. This is used only
    /// while a B already holds a different live route: retaining both guards
    /// while waiting could cycle between two source transfers. Other callers
    /// use [`Self::claim`] and preserve its ordinary bounded wait.
    fn try_claim(&'static self) -> NativeLiveRemoteOwnerTryClaim {
        loop {
            match self.state.load(Ordering::Acquire) {
                NATIVE_LIVE_REMOTE_OWNER_EMPTY => return NativeLiveRemoteOwnerTryClaim::Empty,
                NATIVE_LIVE_REMOTE_OWNER_RETAINED => {
                    return NativeLiveRemoteOwnerTryClaim::Retained;
                }
                NATIVE_LIVE_REMOTE_OWNER_BUSY => return NativeLiveRemoteOwnerTryClaim::Busy,
                NATIVE_LIVE_REMOTE_OWNER_ACTIVE => {
                    if self
                        .state
                        .compare_exchange(
                            NATIVE_LIVE_REMOTE_OWNER_ACTIVE,
                            NATIVE_LIVE_REMOTE_OWNER_BUSY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // SAFETY: this unique ACTIVE -> BUSY claimant owns
                        // the initialized entry until its guard resolves it.
                        let owner = unsafe { (*self.entry.get()).assume_init_read() };
                        return NativeLiveRemoteOwnerTryClaim::Claimed(
                            NativeLiveRemoteOwnerGuard {
                                storage: self,
                                owner: Some(owner),
                            },
                        );
                    }
                }
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    self.state
                        .store(NATIVE_LIVE_REMOTE_OWNER_RETAINED, Ordering::Release);
                    return NativeLiveRemoteOwnerTryClaim::Retained;
                }
            }
        }
    }

}

impl NativeLiveRemoteOwnerGuard {
    #[inline]
    fn owner(&self) -> NativeLiveRemoteOwner {
        self.owner
            .expect("a live-owner guard retains its entry until it resolves")
    }

    /// Identifies only the stable private entry held by this guard. This is
    /// not an owner, client, page, or allocator capability. It lets the
    /// current B route skip precisely its already-claimed foreign entry while
    /// it claims its own distinct parked session.
    #[inline]
    fn storage(&self) -> &'static NativeLiveRemoteOwnerStorage {
        self.storage
    }

    /// Borrows A's parked native session while its registry entry is BUSY.
    ///
    /// # Safety
    ///
    /// The caller must hold the complete B-side scheduler operation before it
    /// reads or writes source page state. This guard alone serializes A's TLS
    /// ownership; it does not grant PageMap or page mutation authority.
    unsafe fn session_mut(&mut self) -> Option<&mut CurrentThreadPageOwnerSession> {
        let owner = self.owner?;
        // SAFETY: the active publication was installed only after this exact
        // session entered A's TLS. A's take path waits for this BUSY guard to
        // resolve before it can mutate, move, or tear down that session.
        let slot = unsafe { &mut *owner.slot.as_ptr() };
        if slot.state != ThreadLifecycleState::Attached {
            return None;
        }
        let Some(ThreadLifecyclePageOwner::Session(session)) = slot.page_owner.as_mut() else {
            return None;
        };
        if session.generation != owner.generation || !session.native_live_remote {
            return None;
        }
        Some(session)
    }

    /// Returns the exact A publication to its registry entry after B has either
    /// completed a read-only exact query, rejected an unrelated C pointer, or
    /// completely published and finished its source interleaving operation.
    fn restore(mut self) {
        let owner = self
            .owner
            .take()
            .expect("a live-owner guard retains its entry until it resolves");
        // SAFETY: this guard claimed the entry and is its only writer until
        // the Release store below makes the restored A session visible.
        unsafe { (*self.storage.entry.get()).write(owner) };
        self.storage
            .state
            .store(NATIVE_LIVE_REMOTE_OWNER_ACTIVE, Ordering::Release);
    }

    /// Consumes A's registry publication before A moves or tears down its
    /// parked session. The raw TLS identity is discarded, so another B can
    /// no longer borrow it while A holds the session locally.
    fn remove(mut self) -> NativeLiveRemoteOwner {
        let owner = self
            .owner
            .take()
            .expect("a live-owner guard retains its entry until it resolves");
        self.storage
            .state
            .store(NATIVE_LIVE_REMOTE_OWNER_EMPTY, Ordering::Release);
        owner
    }

    /// Makes an incomplete A/B handoff permanently non-routable. The entry's
    /// raw TLS pointer is discarded rather than retained after a terminal
    /// source transition; the runtime page-owner state keeps its exact page
    /// ownership closed instead.
    fn retain(mut self) {
        self.owner.take();
        RUNTIME_PROCESS.retain_page_owner();
        self.storage.publish_retained();
    }
}

impl Drop for NativeLiveRemoteOwnerGuard {
    fn drop(&mut self) {
        if self.owner.take().is_some() {
            RUNTIME_PROCESS.retain_page_owner();
            self.storage.publish_retained();
        }
    }
}

/// One permanent metadata-backed entry in the private live-owner registry.
///
/// The backing capability remains in the same process-lifetime allocation as
/// the entry. A raw C free may already have reached the node from the registry
/// head, so removing or moving it would require a separate reclamation
/// protocol. Empty storage is reused instead, bounding metadata by concurrent
/// live-owner high-water rather than the number of sequential workers.
struct NativeLiveRemoteOwnerRegistryNode {
    next: AtomicPtr<NativeLiveRemoteOwnerRegistryNode>,
    storage: NativeLiveRemoteOwnerStorage,
    _backing: MetaAllocation<'static>,
}

const _: [(); 1] = [();
    (core::mem::align_of::<NativeLiveRemoteOwnerRegistryNode>()
        <= NATIVE_C_MALLOC_ALIGNMENT) as usize
];

impl NativeLiveRemoteOwnerRegistryNode {
    #[inline]
    fn new(
        owner: NativeLiveRemoteOwner,
        next: *mut NativeLiveRemoteOwnerRegistryNode,
        backing: MetaAllocation<'static>,
    ) -> Self {
        Self {
            next: AtomicPtr::new(next),
            storage: NativeLiveRemoteOwnerStorage::from_active(owner),
            _backing: backing,
        }
    }
}

// SAFETY: a node is fully initialized before the Release publication from
// `head`; its next link never changes and its mutable entry uses the separate
// `ACTIVE -> BUSY` protocol above. The backing capability keeps this address
// valid until process termination.
unsafe impl Sync for NativeLiveRemoteOwnerRegistryNode {}

enum NativeLiveRemoteOwnerRegistryExistingInstall {
    Installed,
    NeedsEntry(NativeLiveRemoteOwner),
    Retained(NativeLiveRemoteOwner),
}

enum NativeLiveRemoteOwnerRegistryInstall {
    Installed,
    Unavailable(NativeLiveRemoteOwner),
    Retained(NativeLiveRemoteOwner),
}

/// The private append-only registry of independently parked live A sessions.
///
/// Scanning never returns a node, raw address, page, or allocator capability.
/// A foreign address restores each claimed entry before the next stable node is
/// considered. The only value that leaves this registry internally is an
/// opaque guard paired with an already-validated private client fact.
struct NativeLiveRemoteOwnerRegistry {
    mutation: AtomicU8,
    head: AtomicPtr<NativeLiveRemoteOwnerRegistryNode>,
}

impl NativeLiveRemoteOwnerRegistry {
    const fn new() -> Self {
        Self {
            mutation: AtomicU8::new(NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE),
            head: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Finds a reusable entry without exposing its identity. A retained entry
    /// wins over a reusable one: a terminal raw-TLS handoff closes the runtime
    /// instead of allowing an unrelated A to publish beside it.
    fn try_install_existing(
        &self,
        owner: NativeLiveRemoteOwner,
    ) -> NativeLiveRemoteOwnerRegistryExistingInstall {
        let mut candidate: *mut NativeLiveRemoteOwnerRegistryNode = core::ptr::null_mut();
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: nodes are fully initialized before publication and stay
            // linked at this address for the process lifetime.
            let node = unsafe { &*current };
            match node.storage.registry_state() {
                NativeLiveRemoteOwnerStorageState::Empty if candidate.is_null() => {
                    candidate = current;
                }
                NativeLiveRemoteOwnerStorageState::Empty
                | NativeLiveRemoteOwnerStorageState::Live => {}
                NativeLiveRemoteOwnerStorageState::Retained => {
                    return NativeLiveRemoteOwnerRegistryExistingInstall::Retained(owner);
                }
            }
            current = node.next.load(Ordering::Acquire);
        }
        if candidate.is_null() {
            return NativeLiveRemoteOwnerRegistryExistingInstall::NeedsEntry(owner);
        }
        // SAFETY: the candidate is an append-only stable node. The registry
        // mutation word serializes another installer and terminal closure,
        // while this entry transition proves no route overwrites a nonempty
        // stable node.
        match unsafe { (&*candidate).storage.install(owner) } {
            Ok(()) => NativeLiveRemoteOwnerRegistryExistingInstall::Installed,
            Err(owner) => NativeLiveRemoteOwnerRegistryExistingInstall::NeedsEntry(owner),
        }
    }

    /// Acquires the registry-only transition that installs one parked live
    /// owner. It never covers a source operation, whose entry-level state
    /// retains the short serialization. A retained registry is terminal for
    /// future raw-TLS handoffs, so this reports false without reopening it.
    fn acquire_mutation(&self) -> bool {
        loop {
            match self.mutation.load(Ordering::Acquire) {
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE => {
                    if self
                        .mutation
                        .compare_exchange(
                            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE,
                            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_MUTATING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_MUTATING => core::hint::spin_loop(),
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_RETAINED => return false,
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    return false;
                }
            }
        }
    }

    #[inline]
    fn release_mutation(&self) {
        self.mutation
            .store(NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE, Ordering::Release);
    }

    /// Tries to close the registry after a raw-TLS handoff becomes terminal.
    /// An in-flight installer owns the mutation word until it has published a
    /// complete live owner or retained that exact source, so closure waits
    /// instead of overwriting its state back to idle.
    #[inline]
    fn try_close_for_retained_entry(&self) -> bool {
        loop {
            match self.mutation.load(Ordering::Acquire) {
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE => {
                    if self
                        .mutation
                        .compare_exchange(
                            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE,
                            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_RETAINED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_MUTATING => return false,
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_RETAINED => return true,
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    return true;
                }
            }
        }
    }

    /// Closes future live-owner installation after one raw-TLS handoff has
    /// become terminal. It is only a private process-lifetime closure fact;
    /// it does not expose or release an entry, client, page, or allocator.
    fn close_for_retained_entry(&self) {
        while !self.try_close_for_retained_entry() {
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn is_closed_for_retained_entry(&self) -> bool {
        match self.mutation.load(Ordering::Acquire) {
            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE
            | NATIVE_LIVE_REMOTE_OWNER_REGISTRY_MUTATING => false,
            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_RETAINED => true,
            _ => {
                RUNTIME_PROCESS.retain_page_owner();
                true
            }
        }
    }

    /// Installs a current A session into an empty stable entry or appends one
    /// new metadata-backed node. Allocation failure leaves the session local
    /// only; it never overwrites a peer route or makes the client address
    /// visible through a fallback table.
    fn install(
        &self,
        owner: NativeLiveRemoteOwner,
        config: MemoryConfig,
    ) -> NativeLiveRemoteOwnerRegistryInstall {
        if !self.acquire_mutation() {
            return NativeLiveRemoteOwnerRegistryInstall::Retained(owner);
        }

        // This whole decision shares one linearization boundary with terminal
        // closure. A retained raw-TLS handoff cannot appear after this A has
        // selected an empty node but before that node receives its complete
        // live image.
        let owner = match self.try_install_existing(owner) {
            NativeLiveRemoteOwnerRegistryExistingInstall::Installed => {
                self.release_mutation();
                return NativeLiveRemoteOwnerRegistryInstall::Installed;
            }
            NativeLiveRemoteOwnerRegistryExistingInstall::NeedsEntry(owner) => owner,
            NativeLiveRemoteOwnerRegistryExistingInstall::Retained(owner) => {
                self.release_mutation();
                return NativeLiveRemoteOwnerRegistryInstall::Retained(owner);
            }
        };

        let backing = match MetaAllocator::global().zalloc(
            config,
            core::mem::size_of::<NativeLiveRemoteOwnerRegistryNode>(),
        ) {
            Ok(backing) => backing,
            Err(_) => {
                self.release_mutation();
                return NativeLiveRemoteOwnerRegistryInstall::Unavailable(owner);
            }
        };
        let next = self.head.load(Ordering::Acquire);
        let node = backing
            .pointer()
            .as_ptr()
            .cast::<NativeLiveRemoteOwnerRegistryNode>();
        // SAFETY: the metadata allocation has the checked alignment and this
        // is its one typed initialization before the Release publication.
        unsafe { node.write(NativeLiveRemoteOwnerRegistryNode::new(owner, next, backing)) };
        self.head.store(node, Ordering::Release);
        self.release_mutation();
        NativeLiveRemoteOwnerRegistryInstall::Installed
    }

    /// Claims the running thread's exact entry before it reads compiler TLS.
    /// A running A must wait for a B-side guard that borrowed its raw slot, but
    /// all foreign entries are restored before A accesses its own TLS image.
    fn claim_current_slot(
        &'static self,
        slot: core::ptr::NonNull<ThreadLifecycleSlot>,
    ) -> NativeLiveRemoteOwnerCurrentClaim {
        self.claim_current_slot_excluding_held_route(slot, None)
    }

    /// Claims the running thread's exact entry while this B worker already
    /// holds one different A route. The excluded entry remains `BUSY` under
    /// that typed guard; visiting it again would self-deadlock before B could
    /// claim and resume its own parked session. This skips only the exact
    /// held storage, never an arbitrary busy owner, and never exposes its TLS
    /// identity or client ledger.
    fn claim_current_slot_while_holding_live_remote_owner(
        &'static self,
        slot: core::ptr::NonNull<ThreadLifecycleSlot>,
        held_route: &NativeLiveRemoteOwnerGuard,
    ) -> NativeLiveRemoteOwnerCurrentClaim {
        self.claim_current_slot_excluding_held_route(slot, Some(held_route))
    }

    fn claim_current_slot_excluding_held_route(
        &'static self,
        slot: core::ptr::NonNull<ThreadLifecycleSlot>,
        held_route: Option<&NativeLiveRemoteOwnerGuard>,
    ) -> NativeLiveRemoteOwnerCurrentClaim {
        if self.is_closed_for_retained_entry() {
            return NativeLiveRemoteOwnerCurrentClaim::Retained;
        }
        let held_storage = held_route.map(NativeLiveRemoteOwnerGuard::storage);
        let mut saw_foreign = false;
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: this append-only metadata node has process lifetime, so
            // a claimed guard may retain its storage reference after the scan
            // advances to another node.
            let node: &'static NativeLiveRemoteOwnerRegistryNode = unsafe { &*current };
            if held_storage.is_some_and(|storage| core::ptr::eq(storage, &node.storage)) {
                // This caller already owns the only BUSY handoff for the
                // foreign A. Its matching exact client is still private to
                // that guard, so this lookup must neither wait on nor inspect
                // it before it claims B's own separate registry entry.
                current = node.next.load(Ordering::Acquire);
                continue;
            }
            let claim = if held_storage.is_some() {
                match node.storage.try_claim() {
                    NativeLiveRemoteOwnerTryClaim::Empty => NativeLiveRemoteOwnerClaim::Empty,
                    NativeLiveRemoteOwnerTryClaim::Busy => {
                        // This path already holds one different exact foreign
                        // route. Do not wait while retaining it: an opposite
                        // source transfer may hold this entry and need its own
                        // current-slot claim. The caller restores its held
                        // route before retrying this scan.
                        return NativeLiveRemoteOwnerCurrentClaim::Busy;
                    }
                    NativeLiveRemoteOwnerTryClaim::Retained => {
                        NativeLiveRemoteOwnerClaim::Retained
                    }
                    NativeLiveRemoteOwnerTryClaim::Claimed(route) => {
                        NativeLiveRemoteOwnerClaim::Claimed(route)
                    }
                }
            } else {
                node.storage.claim()
            };
            match claim {
                NativeLiveRemoteOwnerClaim::Empty => {}
                NativeLiveRemoteOwnerClaim::Retained => {
                    return NativeLiveRemoteOwnerCurrentClaim::Retained;
                }
                NativeLiveRemoteOwnerClaim::Claimed(route) => {
                    if route.owner().slot == slot {
                        return NativeLiveRemoteOwnerCurrentClaim::Claimed(route);
                    }
                    route.restore();
                    saw_foreign = true;
                }
            }
            current = node.next.load(Ordering::Acquire);
        }
        if saw_foreign {
            NativeLiveRemoteOwnerCurrentClaim::Foreign
        } else {
            NativeLiveRemoteOwnerCurrentClaim::Empty
        }
    }

    /// Finds and claims the one live A ledger that proves `block` is current.
    /// Every address miss restores that exact entry before the scan continues;
    /// an inconsistent session is terminal rather than treated as a foreign
    /// pointer that could reach another A.
    fn claim_exact_client(
        &'static self,
        block: core::ptr::NonNull<u8>,
    ) -> NativeLiveRemoteOwnerExactClaim {
        if self.is_closed_for_retained_entry() {
            return NativeLiveRemoteOwnerExactClaim::Retained;
        }
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: see `claim_current_slot`; entries never move or leave
            // the list while a C free can still be scanning them.
            let node: &'static NativeLiveRemoteOwnerRegistryNode = unsafe { &*current };
            match node.storage.claim() {
                NativeLiveRemoteOwnerClaim::Empty => {}
                NativeLiveRemoteOwnerClaim::Retained => {
                    return NativeLiveRemoteOwnerExactClaim::Retained;
                }
                NativeLiveRemoteOwnerClaim::Claimed(mut route) => {
                    let client = {
                        // SAFETY: this guard excludes the matching A session
                        // from resume or source exit while B checks only its
                        // private ledger.
                        let Some(session) = (unsafe { route.session_mut() }) else {
                            route.retain();
                            return NativeLiveRemoteOwnerExactClaim::Retained;
                        };
                        session.clients.native_client_for_block(block)
                    };
                    match client {
                        Ok(client) => {
                            return NativeLiveRemoteOwnerExactClaim::Claimed { route, client };
                        }
                        Err(CurrentThreadPageOwnerPreparationError::UnknownClient) => {
                            route.restore();
                        }
                        Err(_) => {
                            route.retain();
                            return NativeLiveRemoteOwnerExactClaim::Retained;
                        }
                    }
                }
            }
            current = node.next.load(Ordering::Acquire);
        }
        NativeLiveRemoteOwnerExactClaim::NotOwned
    }

    /// Reads the source-recorded usable extent of one exact live client. The
    /// scan restores every nonmatching A before moving on and returns only a
    /// scalar, never a route or a client capability.
    fn usable_size_exact(
        &'static self,
        block: core::ptr::NonNull<u8>,
    ) -> NativeLiveRemoteOwnerUsableSizeResult {
        if self.is_closed_for_retained_entry() {
            return NativeLiveRemoteOwnerUsableSizeResult::Retained;
        }
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: see `claim_current_slot`; this stable node owns the
            // storage referenced by its temporary guard for process lifetime.
            let node: &'static NativeLiveRemoteOwnerRegistryNode = unsafe { &*current };
            match node.storage.claim() {
                NativeLiveRemoteOwnerClaim::Empty => {}
                NativeLiveRemoteOwnerClaim::Retained => {
                    return NativeLiveRemoteOwnerUsableSizeResult::Retained;
                }
                NativeLiveRemoteOwnerClaim::Claimed(mut route) => {
                    let usable_size = {
                        // SAFETY: the claimed entry is the only raw TLS alias
                        // until the exact result below restores it.
                        let Some(session) = (unsafe { route.session_mut() }) else {
                            route.retain();
                            return NativeLiveRemoteOwnerUsableSizeResult::Retained;
                        };
                        session.clients.recorded_native_usable_size(block)
                    };
                    match usable_size {
                        Ok(usable_size) => {
                            route.restore();
                            return NativeLiveRemoteOwnerUsableSizeResult::Owned(usable_size);
                        }
                        Err(CurrentThreadPageOwnerPreparationError::UnknownClient) => {
                            route.restore();
                        }
                        Err(_) => {
                            route.retain();
                            return NativeLiveRemoteOwnerUsableSizeResult::Retained;
                        }
                    }
                }
            }
            current = node.next.load(Ordering::Acquire);
        }
        NativeLiveRemoteOwnerUsableSizeResult::NotOwned
    }

    /// Counts only stable entry states for the direct live-owner high-water
    /// regression. It returns no raw TLS identity or route capability and
    /// must be sampled after the test's participating workers have joined.
    /// A transient busy entry is conservatively counted as live.
    #[cfg(feature = "native-runtime-test-audit")]
    fn test_audit(&self) -> NativeLiveRemoteOwnerRegistryAudit {
        let mut audit = NativeLiveRemoteOwnerRegistryAudit {
            published_entry_count: 0,
            live_entry_count: 0,
            retained_entry_count: 0,
        };
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: every node is fully initialized before its Release
            // publication, and append-only links keep its metadata address
            // valid for this diagnostic-only traversal.
            let node = unsafe { &*current };
            audit.published_entry_count += 1;
            match node.storage.registry_state() {
                NativeLiveRemoteOwnerStorageState::Empty => {}
                NativeLiveRemoteOwnerStorageState::Live => audit.live_entry_count += 1,
                NativeLiveRemoteOwnerStorageState::Retained => audit.retained_entry_count += 1,
            }
            current = node.next.load(Ordering::Acquire);
        }
        audit
    }
}

// SAFETY: nodes publish only complete immutable links, and every mutable
// entry operation owns its independent state word. The mutation word
// serializes installation with terminal closure, not live allocator work.
unsafe impl Sync for NativeLiveRemoteOwnerRegistry {}

static NATIVE_LIVE_REMOTE_OWNER: NativeLiveRemoteOwnerRegistry =
    NativeLiveRemoteOwnerRegistry::new();

/// Returns scalar-only accounting for the private native live-owner registry.
///
/// This direct-test hook is feature-gated and cannot identify, operate on, or
/// release a registry entry. See [`NativeLiveRemoteOwnerRegistryAudit`] for
/// the quiescent-sampling contract.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
pub fn native_live_remote_owner_registry_test_audit() -> NativeLiveRemoteOwnerRegistryAudit {
    NATIVE_LIVE_REMOTE_OWNER.test_audit()
}

#[inline]
fn current_thread_slot_pointer() -> core::ptr::NonNull<ThreadLifecycleSlot> {
    // SAFETY: compiler TLS gives this running thread the only normal Rust
    // access to its slot. The one native live-owner route transfers this raw
    // identity only under its explicit registry/scheduler protocol above.
    unsafe { core::ptr::NonNull::new_unchecked(THREAD_LIFECYCLE.get()) }
}

#[inline]
fn current_thread_slot() -> &'static mut ThreadLifecycleSlot {
    // SAFETY: this is compiler TLS. Only the running thread can reach its
    // slot, and libc invokes attach/finish serially on that thread.
    unsafe { &mut *current_thread_slot_pointer().as_ptr() }
}

/// Pins the initial thread's persistent static-owner cell at its compiler-TLS
/// address.
///
/// The initial thread shares the same statically allocated TLS record as the
/// later-thread lifecycle, but it deliberately uses a separate owner type:
/// it has source-required static ticket-zero storage rather than an attached
/// pthread `MainHeapThreadAttachment`.
#[inline]
fn current_thread_native_initial_persistent_owner_cell(
) -> Pin<&'static PersistentCompilerTlsOwnerCell<NativeInitialPersistentThreadOwner>> {
    let slot = current_thread_slot_pointer();
    // SAFETY: compiler TLS gives the record its final address before the
    // process enters the allocator. The cell never moves after installation.
    unsafe { Pin::new_unchecked(&(*slot.as_ptr()).initial_native_persistent_owner) }
}

#[inline]
fn current_thread_has_native_initial_persistent_owner() -> bool {
    RUNTIME_PROCESS.is_on_initial_thread()
        && current_thread_slot().initial_native_persistent_owner_installed
}

/// Inspects the promoted initial owner's source state during the held,
/// zero-admission fork boundary.
///
/// `RuntimeForkAdmission::before_fork_with` calls this only after it has
/// installed `FORK_GATE_HELD` while every later admission count is zero. The
/// direct owner was moved out of `RuntimeProcessStorage::page_owner` during
/// promotion, so this deliberately projects only the original thread's
/// pinned compiler-TLS cell and never reads that vacated static slot. A cell
/// state mismatch is conservative: it cannot preserve a copied child and it
/// must not terminalize or otherwise mutate the source owner while merely
/// answering the fork predicate.
#[inline]
fn current_thread_initial_persistent_owner_is_quiescent_for_held_fork_gate() -> bool {
    let gate = RUNTIME_FORK_ADMISSION.state.load(Ordering::Acquire);
    if gate & (FORK_GATE_HELD | FORK_GATE_COUNT_MASK) != FORK_GATE_HELD {
        return false;
    }
    if !current_thread_has_native_initial_persistent_owner() {
        return false;
    }
    debug_assert_eq!(
        gate & (FORK_GATE_HELD | FORK_GATE_COUNT_MASK),
        FORK_GATE_HELD,
        "the pinned initial-owner fork probe runs only under the held zero-admission gate"
    );
    current_thread_native_initial_persistent_owner_cell()
        .with_owner(|owner| owner.as_ref().get_ref().is_quiescent_for_held_fork_gate())
        .unwrap_or(false)
}

/// Uses the direct initial source owner after its one-time promotion.
///
/// This performs no `page_owner_state` read, scheduler claim, parked-engine
/// resume, route/registry lookup, or PageMap lease acquisition. The compiler
/// TLS cell itself is the reentrancy and exact-current-thread boundary.
fn with_current_thread_native_initial_persistent_owner<R>(
    operation: impl FnOnce(&mut NativeInitialPersistentThreadOwner) -> R,
) -> Result<R, NativeInitialPersistentThreadOwnerAccessError> {
    if !RUNTIME_PROCESS.is_on_initial_thread() {
        return Err(NativeInitialPersistentThreadOwnerAccessError::Unavailable);
    }
    if !current_thread_slot().initial_native_persistent_owner_installed {
        return Err(NativeInitialPersistentThreadOwnerAccessError::NotInstalled);
    }
    match current_thread_native_initial_persistent_owner_cell()
        .with_owner(|owner| operation(owner.get_mut()))
    {
        Ok(result) => Ok(result),
        Err(PersistentCompilerTlsOwnerError::NotAttached) => {
            Err(NativeInitialPersistentThreadOwnerAccessError::NotInstalled)
        }
        Err(
            PersistentCompilerTlsOwnerError::Initializing
            | PersistentCompilerTlsOwnerError::Reentrant,
        ) => {
            // A recursive initial local operation cannot safely borrow the
            // static engine a second time. It is a source-owner violation,
            // never an availability signal for a valid local free.
            RUNTIME_PROCESS.retain_page_owner();
            Err(NativeInitialPersistentThreadOwnerAccessError::Retained)
        }
        Err(
            PersistentCompilerTlsOwnerError::InvalidCurrentThread
            | PersistentCompilerTlsOwnerError::WrongThread
            | PersistentCompilerTlsOwnerError::AlreadyActive
            | PersistentCompilerTlsOwnerError::Exiting
            | PersistentCompilerTlsOwnerError::Retained
            | PersistentCompilerTlsOwnerError::TornDown,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            Err(NativeInitialPersistentThreadOwnerAccessError::Retained)
        }
    }
}

/// Moves the one initialized static ticket-zero engine into the initial
/// thread's persistent compiler-TLS owner cell.
///
/// The short admission gate is used only here, at startup/promotion, to
/// exclude a later attachment while the process-static staging slot is moved.
/// It is released before any ordinary allocation, free, realloc, or usable
/// size query. Once publication succeeds, later-worker preparation refuses to
/// borrow the vacated static slot rather than recreating a scheduler path.
fn begin_current_thread_native_initial_persistent_owner(
) -> Result<(), NativeInitialPersistentThreadOwnerAccessError> {
    if !RUNTIME_PROCESS.is_on_initial_thread() {
        return Err(NativeInitialPersistentThreadOwnerAccessError::Unavailable);
    }
    if current_thread_slot().initial_native_persistent_owner_installed {
        return Ok(());
    }

    let promoted = RUNTIME_FORK_ADMISSION.with_no_later_thread_admissions(|| {
        if !RUNTIME_PROCESS.start_ticket_zero_page_owner() {
            return Err(());
        }
        if RUNTIME_PROCESS
            .page_owner_state
            .compare_exchange(
                PAGE_OWNER_READY,
                PAGE_OWNER_BUSY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(());
        }
        #[cfg(feature = "native-runtime-test-audit")]
        note_native_scheduler_transition();

        // SAFETY: the temporary admission gate excludes every later
        // attachment, and READY -> BUSY excludes every legacy ticket-zero
        // operation. This is the sole move out of the initialized static
        // staging slot. No ordinary local operation can observe it there
        // again after the INITIAL_PERSISTENT publication below.
        let allocator = unsafe { (&*RUNTIME_PROCESS.page_owner.get()).assume_init_read() };
        let owner = NativeInitialPersistentThreadOwner { allocator };
        match current_thread_native_initial_persistent_owner_cell().initialize(
            owner,
            |_owner| -> Result<(), Infallible> { Ok(()) },
        ) {
            Ok(()) => {
                current_thread_slot().initial_native_persistent_owner_installed = true;
                RUNTIME_PROCESS
                    .page_owner_state
                    .store(PAGE_OWNER_INITIAL_PERSISTENT, Ordering::Release);
                Ok(())
            }
            Err(PersistentCompilerTlsOwnerInitializeError::State { owner, .. }) => {
                // The cell rejected the offered owner before consuming it;
                // restore exactly the same static image before terminalizing
                // the impossible transfer.
                unsafe { (*RUNTIME_PROCESS.page_owner.get()).write(owner.allocator) };
                RUNTIME_PROCESS
                    .page_owner_state
                    .store(PAGE_OWNER_READY, Ordering::Release);
                Err(())
            }
            Err(PersistentCompilerTlsOwnerInitializeError::Owner(never)) => match never {},
        }
    });

    match promoted {
        Some(Ok(())) => Ok(()),
        Some(Err(())) | None => {
            // An existing or racing worker can no longer be allowed to borrow
            // a static slot that this initial thread attempted to make
            // persistent. There is no safe scheduler-based recovery here.
            RUNTIME_PROCESS.retain_page_owner();
            Err(NativeInitialPersistentThreadOwnerAccessError::Retained)
        }
    }
}

/// Runs one ordinary initial local operation, promoting only before the first
/// such operation. Later iterations use the exact same pinned TLS owner.
fn with_current_thread_native_initial_persistent_allocator<R>(
    create_if_absent: bool,
    mut operation: impl FnMut(&mut NativeInitialPersistentThreadOwner) -> R,
) -> Result<R, NativeInitialPersistentThreadOwnerAccessError> {
    match with_current_thread_native_initial_persistent_owner(|owner| operation(owner)) {
        Ok(result) => Ok(result),
        Err(NativeInitialPersistentThreadOwnerAccessError::NotInstalled) if create_if_absent => {
            begin_current_thread_native_initial_persistent_owner()?;
            with_current_thread_native_initial_persistent_owner(|owner| operation(owner))
        }
        Err(error) => Err(error),
    }
}

/// Promotes the initial static owner before a later-thread preparation can
/// make an admission observable, then leaves only its source-dormant pair
/// available to that later owner.
///
/// This is the one preparation/clone boundary that may create the persistent
/// initial owner while the process is still cold. It is deliberately not a
/// steady allocation or free path: promotion holds the short fork-admission
/// gate exactly once, after which the owner remains pinned in initial-thread
/// compiler TLS. A live or terminal initial engine is retained rather than
/// being parked, lent, or reconstructed through the former static slot.
fn prepare_current_thread_native_initial_persistent_owner_for_later_thread() -> bool {
    let prepared = with_current_thread_native_initial_persistent_allocator(true, |owner| {
        (
            owner.prepare_dormant_page_pair_for_later_thread(),
            owner.is_retained(),
        )
    });
    match prepared {
        // The direct initial owner is source-dormant. A later worker may
        // construct an independent local engine from the immutable process
        // pair; it never borrows, parks, or revives the moved static staging
        // owner.
        Ok((true, false)) => true,
        // This is specifically an attempted live/terminal transfer. Do not
        // make all later workers unavailable merely because the initial owner
        // was promoted; fail closed only when its actual source state cannot
        // yield the dormant pair.
        Ok((true, true)) | Ok((false, _)) | Err(_) => {
            RUNTIME_PROCESS.retain_page_owner();
            false
        }
    }
}

/// Pins the inline native owner cell at its final compiler-TLS address.
///
/// The TLS slot is allocated by the runtime loader before this thread enters
/// the allocator bridge and is never moved during the thread lifetime. Only
/// the running thread can obtain this projection; the cell itself rejects
/// nested mutable owner access before dereferencing its payload.
#[inline]
fn current_thread_native_persistent_owner_cell(
) -> Pin<&'static PersistentCompilerTlsOwnerCell<NativePersistentThreadOwner>> {
    let slot = current_thread_slot_pointer();
    // SAFETY: the compiler-TLS slot has its final address for this native
    // thread, and no API moves the embedded `!Unpin` cell after publication.
    unsafe { Pin::new_unchecked(&(*slot.as_ptr()).native_persistent_owner) }
}

#[inline]
fn retain_current_thread_native_persistent_owner_for_teardown() {
    current_thread_slot().state = ThreadLifecycleState::Retained;
}

#[inline]
fn fail_stop_with_current_thread_native_owner() -> ! {
    retain_current_thread_native_persistent_owner_for_teardown();
    crabc_core::process::exit_immediately(134)
}

#[inline]
fn current_thread_has_native_persistent_owner() -> bool {
    let slot = current_thread_slot();
    slot.native_persistent_owner_installed
        && matches!(
            slot.state,
            ThreadLifecycleState::Attached | ThreadLifecycleState::Retained
        )
}

fn with_current_thread_native_persistent_owner<R>(
    operation: impl FnOnce(&mut NativePersistentThreadOwner) -> R,
) -> Result<R, NativePersistentThreadOwnerAccessError> {
    match current_thread_slot().state {
        ThreadLifecycleState::Attached => {}
        ThreadLifecycleState::Retained => {
            return Err(NativePersistentThreadOwnerAccessError::Retained);
        }
        ThreadLifecycleState::Fresh | ThreadLifecycleState::Finished => {
            return Err(NativePersistentThreadOwnerAccessError::Unavailable);
        }
    }
    match current_thread_native_persistent_owner_cell()
        .with_owner(|owner| operation(owner.get_mut()))
    {
        Ok(result) => Ok(result),
        Err(PersistentCompilerTlsOwnerError::NotAttached) => {
            Err(NativePersistentThreadOwnerAccessError::NotInstalled)
        }
        Err(
            PersistentCompilerTlsOwnerError::Initializing
            | PersistentCompilerTlsOwnerError::Reentrant,
        ) => Err(NativePersistentThreadOwnerAccessError::Unavailable),
        Err(
            PersistentCompilerTlsOwnerError::InvalidCurrentThread
            | PersistentCompilerTlsOwnerError::WrongThread
            | PersistentCompilerTlsOwnerError::AlreadyActive
            | PersistentCompilerTlsOwnerError::Exiting
            | PersistentCompilerTlsOwnerError::Retained
            | PersistentCompilerTlsOwnerError::TornDown,
        ) => {
            retain_current_thread_native_persistent_owner_for_teardown();
            Err(NativePersistentThreadOwnerAccessError::Retained)
        }
    }
}

/// Forms the immutable process pair used once during native-owner promotion.
/// It does not claim or inspect `RuntimeProcessStorage::page_owner_state`.
fn current_native_process_page_arena_pair() -> Option<ProcessPageArenaLease> {
    // SAFETY: an active process permanently publishes this owner before any
    // later thread is admitted.
    let owner = unsafe { RUNTIME_PROCESS.active_owner() }?;
    let page_map = owner.ready().ok()?.page_map().ok()?;
    let arena = ProcessSharedArenaStorage::global().ready_lease().ok()?;
    ProcessPageArenaLease::join(page_map, arena).ok()
}

/// Promotes the attached worker exactly once into its inline native owner.
///
/// The offered attachment is moved from the legacy slot only after the
/// process pair is ready. A lower initialization failure leaves that exact
/// attachment/engine payload pinned in the cell's retained state.
fn begin_current_thread_native_persistent_owner(
) -> Result<(), NativePersistentThreadOwnerAccessError> {
    let Some(pair) = current_native_process_page_arena_pair() else {
        return Err(NativePersistentThreadOwnerAccessError::Unavailable);
    };
    let slot = current_thread_slot();
    if slot.state != ThreadLifecycleState::Attached || slot.page_owner.is_some() {
        return Err(NativePersistentThreadOwnerAccessError::Unavailable);
    }
    let Some(attachment) = slot.attachment.take() else {
        retain_current_thread_native_persistent_owner_for_teardown();
        return Err(NativePersistentThreadOwnerAccessError::Retained);
    };
    let owner = NativePersistentThreadOwner {
        attachment,
        state: NativePersistentThreadOwnerExitState::AttachmentOnly,
    };
    let initialized = current_thread_native_persistent_owner_cell().initialize(
        owner,
        |mut owner| -> Result<(), MainHeapThreadOwnerLocalPageEngineBeginError> {
            let owner = owner.as_mut().get_mut();
            let engine = MainHeapThreadOwnerLocalPageEngine::begin(&mut owner.attachment, pair)?;
            owner.state = NativePersistentThreadOwnerExitState::PreDrain(engine);
            Ok(())
        },
    );
    match initialized {
        Ok(()) => {
            current_thread_slot().native_persistent_owner_installed = true;
            Ok(())
        }
        Err(PersistentCompilerTlsOwnerInitializeError::Owner(_)) => {
            current_thread_slot().native_persistent_owner_installed = true;
            retain_current_thread_native_persistent_owner_for_teardown();
            Err(NativePersistentThreadOwnerAccessError::Retained)
        }
        Err(PersistentCompilerTlsOwnerInitializeError::State { owner, .. }) => {
            // The cell rejected the offered owner before initialization, so
            // its owner state is still attachment-only and the original
            // attachment can be restored as the exact terminal diagnostic
            // owner.
            let NativePersistentThreadOwner { attachment, state } = owner;
            debug_assert!(matches!(
                state,
                NativePersistentThreadOwnerExitState::AttachmentOnly
            ));
            drop(state);
            let slot = current_thread_slot();
            debug_assert!(slot.attachment.is_none());
            slot.attachment = Some(attachment);
            fail_stop_with_current_thread_native_owner()
        }
    }
}

fn with_current_thread_native_persistent_allocator<R>(
    create_if_absent: bool,
    mut operation: impl FnMut(&mut MainHeapThreadOwnerLocalAllocator<'_>) -> R,
) -> Result<R, NativePersistentThreadOwnerAccessError> {
    let mut may_create = create_if_absent;
    loop {
        match with_current_thread_native_persistent_owner(|owner| {
            owner.with_local_allocator(|allocator| operation(allocator))
        }) {
            Ok(Ok(result)) => return Ok(result),
            Ok(Err(())) => {
                retain_current_thread_native_persistent_owner_for_teardown();
                return Err(NativePersistentThreadOwnerAccessError::Retained);
            }
            Err(NativePersistentThreadOwnerAccessError::NotInstalled) if may_create => {
                begin_current_thread_native_persistent_owner()?;
                may_create = false;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Applies one pointer-consuming operation only when PageMap source state
/// associates the exact live allocation with this persistent local owner.
fn with_current_thread_native_persistent_pointer<R>(
    block: core::ptr::NonNull<u8>,
    operation: impl FnOnce(&mut MainHeapThreadOwnerLocalAllocator<'_>) -> R,
) -> Result<Option<R>, NativePersistentThreadOwnerAccessError> {
    let Some(thread) = current_thread_identity() else {
        retain_current_thread_native_persistent_owner_for_teardown();
        return Err(NativePersistentThreadOwnerAccessError::Retained);
    };
    let Some(page_map) = (unsafe { RUNTIME_PROCESS.active_owner() })
        .and_then(|owner| owner.ready().ok())
        .and_then(|ready| ready.page_map().ok())
    else {
        return Err(NativePersistentThreadOwnerAccessError::Unavailable);
    };
    match with_current_thread_native_persistent_owner(|owner| {
        // SAFETY: this private boundary is reached only from the native C
        // operation's exact-live-allocation contract. The observation stays
        // in this closure through the consuming local operation.
        let pointer = unsafe { page_map.lookup_live_allocation(block) }.map_err(|_| ())?;
        let Some(pointer) = pointer else {
            return Ok(None);
        };
        if !pointer.is_associated_with(thread) {
            return Ok(None);
        }
        let result = owner
            .with_local_allocator(operation)
            .map(Some)
            .map_err(|_| ());
        drop(pointer);
        result
    }) {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(())) => {
            retain_current_thread_native_persistent_owner_for_teardown();
            Err(NativePersistentThreadOwnerAccessError::Retained)
        }
        Err(error) => Err(error),
    }
}

/// Initializes the retained ticket-zero process owner from libc's validated
/// `AT_PAGESZ` value. A false result means the shadow lifecycle is unavailable
/// for this process; the existing C mimalloc backend remains selected.
#[doc(hidden)]
#[inline]
pub fn initialize_process(page_size_bytes: usize) -> bool {
    RUNTIME_PROCESS.initialize(page_size_bytes)
}

/// Whether the private process lifecycle can admit a new pthread worker.
#[doc(hidden)]
#[inline]
pub fn process_is_active() -> bool {
    RUNTIME_PROCESS.is_active()
}

/// Attempts one ordinary allocation through the private permanent ticket-zero
/// page owner.
///
/// This does not call or replace libc's `malloc`: callers must retain and use
/// only the returned native pointer through the matching APIs below. An
/// invalid size fails before permanent page-session startup, preserving the
/// existing no-page runtime lifecycle.
#[doc(hidden)]
pub fn ticket_zero_allocate(request: usize, zero: bool) -> TicketZeroPageAllocationResult {
    if !crate::size_class::request_size_is_valid(request) {
        return TicketZeroPageAllocationResult::AllocationFailed;
    }
    if current_thread_has_native_initial_persistent_owner() {
        return ticket_zero_initial_persistent_allocate(request, None, zero);
    }
    ticket_zero_allocation_result(
        RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| owner.allocate(request, zero)),
    )
}

/// Attempts one aligned allocation through the private permanent ticket-zero
/// page owner.
///
/// This preserves the same process-static owner and first-arena lifecycle as
/// [`ticket_zero_allocate`]. The lower engine selects its pinned natural,
/// in-arena overallocated, or OS-aligned singleton path; this runtime seam
/// only rejects invalid request/alignment inputs before they can mutate that
/// owner. It remains a Rust-only friend boundary until the nondefault libc
/// shadow backend proves the corresponding C ABI route.
#[doc(hidden)]
pub fn ticket_zero_allocate_aligned(
    request: usize,
    alignment: usize,
    zero: bool,
) -> TicketZeroPageAllocationResult {
    if !crate::size_class::request_size_is_valid(request)
        || !crate::size_class::alignment_is_valid(alignment)
    {
        return TicketZeroPageAllocationResult::AllocationFailed;
    }
    if current_thread_has_native_initial_persistent_owner() {
        return ticket_zero_initial_persistent_allocate(request, Some(alignment), zero);
    }
    ticket_zero_allocation_result(RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| {
        owner.allocate_aligned(request, alignment, zero)
    }))
}

#[inline]
fn ticket_zero_allocation_result(
    result: Option<Option<core::ptr::NonNull<u8>>>,
) -> TicketZeroPageAllocationResult {
    match result {
        Some(Some(block)) => TicketZeroPageAllocationResult::Allocated(block),
        Some(None) => {
            if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
                || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED
            {
                TicketZeroPageAllocationResult::Retained
            } else {
                TicketZeroPageAllocationResult::AllocationFailed
            }
        }
        None => RUNTIME_PROCESS.page_owner_unavailable_result(),
    }
}

/// Preserves the old private ticket-zero test seam after native initial-owner
/// promotion without sending it back through the legacy scheduler.
///
/// This compatibility helper is not an alternative allocator owner: it merely
/// lets existing internal fixtures keep using their historical spelling once
/// the exact static engine has moved into the initial thread's TLS cell.
fn ticket_zero_initial_persistent_allocate(
    request: usize,
    alignment: Option<usize>,
    zero: bool,
) -> TicketZeroPageAllocationResult {
    let result = with_current_thread_native_initial_persistent_allocator(false, |owner| {
        let block = match alignment {
            Some(alignment) => owner.allocate_aligned(request, alignment, zero),
            None => owner.allocate(request, zero),
        };
        (block, owner.is_retained())
    });
    match result {
        Ok((Some(block), false)) => TicketZeroPageAllocationResult::Allocated(block),
        Ok((None, false)) => TicketZeroPageAllocationResult::AllocationFailed,
        Ok((Some(_) | None, true))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            TicketZeroPageAllocationResult::Retained
        }
    }
}

/// Preserves the private ticket-zero reallocation seam after the direct
/// initial owner has been installed.
unsafe fn ticket_zero_initial_persistent_reallocate(
    block: Option<core::ptr::NonNull<u8>>,
    new_size: usize,
) -> TicketZeroPageAllocationResult {
    let result = with_current_thread_native_initial_persistent_allocator(false, |owner| {
        let replacement = match block {
            Some(block) => {
                // SAFETY: forwarded from the private ticket-zero caller
                // contract while the direct initial owner is current.
                unsafe { owner.reallocate(block, new_size) }
            }
            None => owner.allocate(new_size, false),
        };
        (replacement, owner.is_retained())
    });
    match result {
        Ok((Some(block), false)) => TicketZeroPageAllocationResult::Allocated(block),
        Ok((None, false)) => TicketZeroPageAllocationResult::AllocationFailed,
        Ok((Some(_) | None, true))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            TicketZeroPageAllocationResult::Retained
        }
    }
}

/// Preserves the private ticket-zero free spelling after native promotion.
unsafe fn ticket_zero_initial_persistent_free(
    block: core::ptr::NonNull<u8>,
) -> TicketZeroPageFreeResult {
    let result = with_current_thread_native_initial_persistent_allocator(false, |owner| {
        // SAFETY: forwarded from the private ticket-zero current-block
        // contract while the direct initial owner is current.
        let free = unsafe { owner.free(block) };
        (free, owner.is_retained())
    });
    match result {
        Ok((Ok(()), false)) => TicketZeroPageFreeResult::Freed,
        Ok((Err(
            crate::main_static_page::MainStaticRuntimeFirstArenaPageAllocatorFreeError::Free(
                crate::single_thread::FreeError::Unmapped
                | crate::single_thread::FreeError::ForeignPage
                | crate::single_thread::FreeError::InvalidBlock(_),
            ),
        ), false)) => TicketZeroPageFreeResult::InvalidPointer,
        Ok((Ok(()) | Err(_), true))
        | Ok((Err(_), false))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            TicketZeroPageFreeResult::Retained
        }
    }
}

/// Preserves the private ticket-zero usable-size spelling after native
/// promotion without reopening the process-static owner staging slot.
unsafe fn ticket_zero_initial_persistent_usable_size(
    block: core::ptr::NonNull<u8>,
) -> Option<usize> {
    let result = with_current_thread_native_initial_persistent_allocator(false, |owner| {
        // SAFETY: forwarded from the private ticket-zero current-block
        // contract while the direct initial owner is current.
        let usable_size = unsafe { owner.usable_size(block) };
        (usable_size, owner.is_retained())
    });
    match result {
        Ok((usable_size, false)) => usable_size,
        Ok((_, true))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            None
        }
    }
}

/// Reallocates one current private ticket-zero native allocation.
///
/// # Safety
///
/// `block`, when present, must have been returned by this exact runtime owner,
/// remain live, and have no aliased or cross-thread access. A failed result
/// preserves a non-null old block. This is not valid for a libc/C-backend
/// pointer and does not select a C allocator route.
#[doc(hidden)]
pub unsafe fn ticket_zero_reallocate(
    block: Option<core::ptr::NonNull<u8>>,
    new_size: usize,
) -> TicketZeroPageAllocationResult {
    if !crate::size_class::request_size_is_valid(new_size) {
        return TicketZeroPageAllocationResult::AllocationFailed;
    }
    if current_thread_has_native_initial_persistent_owner() {
        // SAFETY: forwarded unchanged from this private current-block
        // contract to the direct persistent initial owner.
        return unsafe { ticket_zero_initial_persistent_reallocate(block, new_size) };
    }
    if block.is_some() && !RUNTIME_PROCESS.page_owner_has_started() {
        return RUNTIME_PROCESS.page_owner_unavailable_result();
    }
    match RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| {
        // SAFETY: forwarded unchanged from this function's exact native-block
        // caller contract.
        unsafe { owner.reallocate(block, new_size) }
    }) {
        Some(Some(replacement)) => TicketZeroPageAllocationResult::Allocated(replacement),
        Some(None) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroPageAllocationResult::Retained
        }
        Some(None) => TicketZeroPageAllocationResult::AllocationFailed,
        None => RUNTIME_PROCESS.page_owner_unavailable_result(),
    }
}

/// Frees one current private ticket-zero native allocation.
///
/// # Safety
///
/// `block` must be a current unique result of [`ticket_zero_allocate`] or
/// [`ticket_zero_reallocate`]. It must not be a libc/C-backend pointer.
#[doc(hidden)]
pub unsafe fn ticket_zero_free(block: core::ptr::NonNull<u8>) -> TicketZeroPageFreeResult {
    if current_thread_has_native_initial_persistent_owner() {
        // SAFETY: forwarded unchanged from this private current-block
        // contract to the direct persistent initial owner.
        return unsafe { ticket_zero_initial_persistent_free(block) };
    }
    if !RUNTIME_PROCESS.page_owner_has_started() {
        return match RUNTIME_PROCESS.page_owner_unavailable_result() {
            TicketZeroPageAllocationResult::Retained => TicketZeroPageFreeResult::Retained,
            TicketZeroPageAllocationResult::Allocated(_) | TicketZeroPageAllocationResult::Unavailable
            | TicketZeroPageAllocationResult::AllocationFailed => TicketZeroPageFreeResult::Unavailable,
        };
    }
    match RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| {
        // SAFETY: forwarded unchanged from this function's exact native-block
        // caller contract.
        unsafe { owner.free(block) }
    }) {
        Some(Ok(())) => TicketZeroPageFreeResult::Freed,
        Some(Err(
            crate::main_static_page::MainStaticRuntimeFirstArenaPageAllocatorFreeError::Busy,
        )) => TicketZeroPageFreeResult::Unavailable,
        Some(Err(crate::main_static_page::MainStaticRuntimeFirstArenaPageAllocatorFreeError::Free(
            crate::single_thread::FreeError::Unmapped
            | crate::single_thread::FreeError::ForeignPage
            | crate::single_thread::FreeError::InvalidBlock(_),
        ))) => TicketZeroPageFreeResult::InvalidPointer,
        Some(Err(_)) => {
            RUNTIME_PROCESS.retain();
            RUNTIME_PROCESS
                .page_owner_state
                .store(PAGE_OWNER_RETAINED, Ordering::Release);
            TicketZeroPageFreeResult::Retained
        }
        None if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroPageFreeResult::Retained
        }
        None => TicketZeroPageFreeResult::Unavailable,
    }
}

/// Returns the usable size of one current private ticket-zero allocation.
///
/// # Safety
///
/// `block` must have been returned by this exact ticket-zero owner, remain
/// current, and not be concurrently accessed or transitioned through another
/// allocator operation. A missing result means the owner is unavailable,
/// retained, or does not recognize the pointer; it deliberately does not
/// reinterpret a foreign C-backend allocation.
#[doc(hidden)]
pub unsafe fn ticket_zero_usable_size(block: core::ptr::NonNull<u8>) -> Option<usize> {
    if current_thread_has_native_initial_persistent_owner() {
        // SAFETY: forwarded unchanged from this private current-block
        // contract to the direct persistent initial owner.
        return unsafe { ticket_zero_initial_persistent_usable_size(block) };
    }
    if !RUNTIME_PROCESS.page_owner_has_started() {
        return None;
    }
    RUNTIME_PROCESS
        .with_ticket_zero_page_owner(|owner| {
            // SAFETY: forwarded unchanged from this function's current
            // ticket-zero allocation contract while the runtime guard owns
            // the permanent page owner exclusively.
            unsafe { owner.usable_size(block) }
        })
        .flatten()
}

/// Allocates through the initial thread's continuously stored source owner.
/// The promotion below is a one-time startup transition; once installed, an
/// active owner performs this local operation with no process scheduler or
/// parked-engine bridge.
fn native_initial_thread_allocate_aligned(
    request: usize,
    alignment: usize,
    zero: bool,
) -> NativePageAllocationResult {
    match with_current_thread_native_initial_persistent_allocator(true, |owner| {
        (
            owner.allocate_aligned(request, alignment, zero),
            owner.is_retained(),
        )
    }) {
        Ok((Some(block), false)) => NativePageAllocationResult::Allocated(block),
        Ok((None, false)) => NativePageAllocationResult::AllocationFailed,
        Ok((Some(_) | None, true))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            NativePageAllocationResult::Retained
        }
    }
}

/// Frees a PageMap-proven current initial-thread client through that owner's
/// direct engine. Unlike the legacy ticket-zero helper, this has no scheduler
/// miss to translate into an ordinary unavailable result.
fn native_initial_thread_free_pointer_first(
    block: core::ptr::NonNull<u8>,
) -> NativePageFreeResult {
    let result = with_current_thread_native_initial_persistent_allocator(true, |owner| {
        // SAFETY: the caller's one PageMap observation associated this exact
        // live client with the current initial owner for the complete local
        // source operation.
        let free = unsafe { owner.free(block) };
        (free, owner.is_retained())
    });
    match result {
        Ok((Ok(()), false)) => NativePageFreeResult::Freed,
        Ok((Ok(()) | Err(_), true))
        | Ok((Err(_), false))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            // PageMap already proved this is a valid current local block. A
            // failed source transition must retain rather than falling back to
            // a ticket-zero scheduler, route, or caller-selected owner.
            RUNTIME_PROCESS.retain_page_owner();
            NativePageFreeResult::Retained
        }
    }
}

/// Reallocates one documented current initial-thread client through the same
/// direct owner. This preserves the existing helper's scope; it adds no W02
/// cross-owner replacement policy.
unsafe fn native_initial_thread_reallocate(
    block: core::ptr::NonNull<u8>,
    new_size: usize,
) -> NativePageAllocationResult {
    let result = with_current_thread_native_initial_persistent_allocator(false, |owner| {
        // SAFETY: forwarded from `native_reallocate`'s exact-current initial
        // owner contract.
        let replacement = unsafe { owner.reallocate(block, new_size) };
        (replacement, owner.is_retained())
    });
    match result {
        Ok((Some(block), false)) => NativePageAllocationResult::Allocated(block),
        Ok((None, false)) => NativePageAllocationResult::AllocationFailed,
        Ok((Some(_) | None, true))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            NativePageAllocationResult::Retained
        }
    }
}

/// Returns the usable extent of one current initial-thread client directly
/// from its persistent source engine.
unsafe fn native_initial_thread_usable_size(block: core::ptr::NonNull<u8>) -> Option<usize> {
    let result = with_current_thread_native_initial_persistent_allocator(true, |owner| {
        // SAFETY: forwarded from the exact-current initial native query.
        let usable_size = unsafe { owner.usable_size(block) };
        (usable_size, owner.is_retained())
    });
    match result {
        Ok((usable_size, false)) => usable_size,
        Ok((_, true))
        | Err(
            NativeInitialPersistentThreadOwnerAccessError::NotInstalled
            | NativeInitialPersistentThreadOwnerAccessError::Unavailable
            | NativeInitialPersistentThreadOwnerAccessError::Retained,
        ) => {
            RUNTIME_PROCESS.retain_page_owner();
            None
        }
    }
}

/// Primes the one source first arena before a native-shadow worker can borrow
/// the existing dormant pair.
///
/// This is intentionally an initial-thread-only integration step. Before it
/// can expose a later-worker preparation, it promotes even a cold static
/// ticket-zero staging owner into the initial thread's persistent TLS cell
/// while the later-admission count is zero. It then creates and releases one
/// private word-sized block only if that owner has no live page engine,
/// leaving its established dormant first-arena pair available to the worker.
/// A live initial allocation or any terminal runtime state rejects rather
/// than borrowing a page image that already has a caller owner. The ordinary
/// C backend never calls this boundary.
#[doc(hidden)]
pub fn prepare_native_later_thread_arena() -> bool {
    if !RUNTIME_PROCESS.is_on_initial_thread() {
        return false;
    }
    prepare_current_thread_native_initial_persistent_owner_for_later_thread()
}

/// Prepares the persistent initial native owner before its creating initial
/// thread publishes a later pthread.
///
/// The creator first performs the one-time static-to-TLS promotion while no
/// later admission exists, including from `COLD`. It keeps every initial
/// client and source engine field private while making only the immutable
/// process pair available to one serialized worker operation. This does not
/// attach the child, route a pointer, or change the C backend. A dormant owner
/// stays on its direct pair path; a live/retained owner is unavailable rather
/// than manufacturing a lifecycle repair.
#[doc(hidden)]
pub fn prepare_native_initial_owner_for_later_thread() {
    if !RUNTIME_PROCESS.is_on_initial_thread() {
        return;
    }
    let _ = prepare_current_thread_native_initial_persistent_owner_for_later_thread();
}

/// Allocates one C-facing native-shadow block on the current thread.
///
/// The initial process thread uses its continuously stored static-source
/// owner. An attached later pthread uses its own continuously stored
/// compiler-TLS owner.
/// Natural C alignment remains an ordinary source allocation; only wider
/// alignment takes the distinct aligned path. The local allocation is
/// represented solely by source Page used/free state plus the process PageMap;
/// no client address is copied into the runtime owner.
#[doc(hidden)]
pub fn native_allocate_aligned(
    request: usize,
    alignment: usize,
    zero: bool,
) -> NativePageAllocationResult {
    if !crate::size_class::request_size_is_valid(request)
        || !crate::size_class::alignment_is_valid(alignment)
    {
        return NativePageAllocationResult::AllocationFailed;
    }
    if RUNTIME_PROCESS.is_on_initial_thread() {
        return native_initial_thread_allocate_aligned(request, alignment, zero);
    }
    // A final B-side free may already have recorded one or more A terminal
    // completions for this attachment. Those entries retain only A's parked
    // token and admission proof; they do not borrow B's independent inline
    // owner. B may therefore continue persistent local allocation while its
    // eventual source finish still precedes every completion release.
    native_later_thread_allocate_aligned(request, alignment, zero)
}

/// Constructs the one source-valid mixed native exit image for an isolated
/// lifecycle regression.
///
/// A joined producer first publishes a direct-small client to A's source
/// remote head, while a distinct medium client remains local in the same
/// native session. The returned address names only that still-live C-shaped
/// client; the published client remains private to source collection. This
/// setup exists solely to exercise the native destructor branch that must
/// collect the first client before it transfers the second through the typed
/// post-exit route. It is deliberately feature-gated instead of creating a
/// general native source-publication API.
#[cfg(feature = "native-runtime-test-published-source")]
#[doc(hidden)]
pub fn native_test_prepare_source_published_live_owner_exit(
    publish_before_exit: TicketZeroSingleRemoteFreePublisher,
) -> NativePageAllocationResult {
    let mut session = match current_thread_native_session_handle(true) {
        Ok(session) => session,
        Err(error) => return native_later_thread_allocation_result(Err(error)),
    };
    let published = match session.allocate(37, false) {
        Ok(client) => client,
        Err(error) => return native_later_thread_allocation_result(Err(error)),
    };
    let live = match session.native_allocate_aligned(
        OWNER_EXIT_RECLAIM_MEDIUM_REQUEST,
        NATIVE_C_MALLOC_ALIGNMENT,
        false,
    ) {
        Ok(block) => block,
        Err(error) => return native_later_thread_allocation_result(Err(error)),
    };
    if session.enable_native_live_remote().is_err() {
        retain_current_thread_live_page_owner();
        return NativePageAllocationResult::Retained;
    }
    if session
        .publish_remote_free(published, publish_before_exit)
        .is_err()
    {
        // The publication closure either left the source client live or
        // returned its exact producer to the source operation. This focused
        // setup has no retry policy, and it must never present the sibling as
        // a detached client after that incomplete source transition.
        retain_current_thread_live_page_owner();
        return NativePageAllocationResult::Retained;
    }
    NativePageAllocationResult::Allocated(live)
}

/// Looks up one exact native client before a pointer-first reallocation.
///
/// Once the caller's persistent target owner is established, pinned
/// `mi_usable_size` and `mi_theap_realloc_zero_ex` derive the page and
/// allocation geometry from the supplied client before consulting the target
/// Heap. This boundary keeps that source order: PageMap facts first, then the
/// caller compares the captured source owner with its own identity. The
/// observation gives no owner, route, registry, scheduler, or
/// lifetime-widening capability.
///
/// # Safety
///
/// `block` must be an exact live native-shadow allocation and remain live
/// through the caller's complete source operation. Its lifetime keeps the
/// selected PageMap slice and page metadata stable for this lookup.
unsafe fn native_live_allocation_for_pointer_reallocation(
    block: core::ptr::NonNull<u8>,
) -> Result<LiveAllocationPointer, NativePageAllocationResult> {
    let Some(page_map) = RUNTIME_PROCESS.page_map_for_live_native_allocation() else {
        // A caller-local engine cannot reconstruct source ownership when the
        // one immutable PageMap witness is unavailable.
        RUNTIME_PROCESS.retain_page_owner();
        return Err(NativePageAllocationResult::Retained);
    };
    // SAFETY: forwarded from this helper's exact-live native-client contract.
    let allocation = match unsafe { page_map.lookup_live_allocation(block) } {
        Ok(Some(allocation)) => allocation,
        Ok(None) => return Err(NativePageAllocationResult::Unavailable),
        Err(_) => {
            RUNTIME_PROCESS.retain_page_owner();
            return Err(NativePageAllocationResult::Retained);
        }
    };
    Ok(allocation)
}

/// Establishes the noninitial caller's persistent target owner before its
/// non-null pointer reallocation selects source facts.
///
/// A public `mi_realloc` reaches its current default Theap before the pinned
/// `mi_theap_realloc_zero_ex` source operation. The native equivalent is the
/// caller's continuously stored persistent owner. Establishing it here gives
/// a first allocation-family operation on B the same target-owner basis as a
/// later B operation, without allocating a client, borrowing A, opening a
/// session, or creating a route. The subsequent PageMap lookup remains the
/// first operation on the supplied source pointer.
fn native_reallocate_prepare_caller_persistent_owner() -> Result<(), NativePageAllocationResult> {
    if RUNTIME_PROCESS.is_on_initial_thread() {
        return Ok(());
    }

    match with_current_thread_native_persistent_allocator(true, |_| ()) {
        Ok(()) => Ok(()),
        Err(NativePersistentThreadOwnerAccessError::Retained) => {
            Err(NativePageAllocationResult::Retained)
        }
        Err(
            NativePersistentThreadOwnerAccessError::NotInstalled
            | NativePersistentThreadOwnerAccessError::Unavailable,
        ) => Err(NativePageAllocationResult::Unavailable),
    }
}

/// Reallocates one PageMap-proven current native client through its existing
/// direct owner.
///
/// The exact PageMap observation stays live through the local engine call so
/// the source allocation cannot retire its selected page while the engine
/// performs its pinned in-place/replacement decision. There is no second
/// lookup or fallback after the current-owner comparison.
fn native_reallocate_pointer_first_local(
    allocation: LiveAllocationPointer,
    new_size: usize,
) -> NativePageAllocationResult {
    let block = allocation.client();
    if RUNTIME_PROCESS.is_on_initial_thread() {
        // SAFETY: the preceding PageMap classification associated this exact
        // live client with the persistent current initial owner.
        let result = unsafe { native_initial_thread_reallocate(block, new_size) };
        drop(allocation);
        return result;
    }

    let result = with_current_thread_native_persistent_allocator(false, |allocator| {
        // SAFETY: the caller's PageMap observation associated this exact live
        // client with the current worker owner for this source operation.
        unsafe { allocator.reallocate(Some(block), new_size) }
    });
    drop(allocation);
    match result {
        Ok(Some(block)) => NativePageAllocationResult::Allocated(block),
        Ok(None) => NativePageAllocationResult::AllocationFailed,
        Err(
            NativePersistentThreadOwnerAccessError::NotInstalled
            | NativePersistentThreadOwnerAccessError::Unavailable
            | NativePersistentThreadOwnerAccessError::Retained,
        ) => {
            // PageMap already proved that a current owner exists. Losing its
            // direct persistent source state cannot safely select an older
            // session, route, or caller-local replacement owner.
            retain_current_thread_native_persistent_owner_for_teardown();
            NativePageAllocationResult::Retained
        }
    }
}

/// Releases a replacement that this caller just allocated for a nonlocal
/// reallocation which could not consume its old source.
///
/// The source `mi_theap_realloc_zero_ex` path treats successful allocation as
/// the point after which copy and old-pointer free cannot fail. Rust retains a
/// typed failure result from the generic nonlocal tail instead. This helper
/// attempts to release the known current replacement directly through the
/// caller's persistent owner without looking up its PageMap state again. It
/// is used only before that replacement has escaped, so its exact
/// current-owner proof is stronger than the public pointer boundary.
///
/// A failed direct release leaves that owner terminally retained with an
/// unreachable replacement. The caller must consequently fail closed; it
/// must not describe this fallback as a successful cleanup or return the
/// replacement while the old source remains live.
fn native_reallocate_release_unpublished_replacement(replacement: core::ptr::NonNull<u8>) {
    if RUNTIME_PROCESS.is_on_initial_thread() {
        let _ = native_initial_thread_free_pointer_first(replacement);
        return;
    }

    match with_current_thread_native_persistent_allocator(false, |allocator| {
        // SAFETY: `replacement` is the exact just-allocated result of this
        // caller's persistent native owner. It has not escaped, been
        // published, or been offered to any other pointer operation.
        unsafe { allocator.free(replacement) }
    }) {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => {
            retain_current_thread_native_persistent_owner_for_teardown();
        }
    }
}

/// Reallocates a PageMap-proven noncurrent source through the caller's own
/// persistent native owner.
///
/// Pinned `mi_theap_realloc_zero_ex` can reuse in place only when the source
/// page belongs to the target Theap. A noncurrent source therefore enters the
/// replacement transaction: allocate from the caller, copy the bounded prefix,
/// then offer the old source to the generic pointer-first nonlocal free tail.
/// The replacement becomes visible only when that tail reports `Freed`.
///
/// The generic tail currently has source-consuming transitions for the states
/// supplied by W03. A PageMap-proven state without such a transition (notably
/// detached until its own producer/continuation lands) rolls the unpublished
/// replacement back and fails closed. No former owner, route, client ledger,
/// scheduler, or synthetic target owner participates.
fn native_reallocate_pointer_first_nonlocal(
    allocation: LiveAllocationPointer,
    new_size: usize,
) -> NativePageAllocationResult {
    let source = allocation.into_reallocation_copy_source(new_size);
    let replacement = match native_allocate_aligned(new_size, NATIVE_C_MALLOC_ALIGNMENT, false) {
        NativePageAllocationResult::Allocated(replacement) => replacement,
        result @ (NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained) => {
            // The old allocation has not entered a consuming source path.
            // Recovering then dropping its immutable PageMap facts preserves
            // the exact old client for the caller, including allocation
            // failure.
            drop(source.into_live_allocation());
            return result;
        }
    };

    // SAFETY: `source` freezes the exact live client plus its client-relative
    // readable prefix before replacement allocation. `replacement` is a
    // distinct still-live allocation from the caller's persistent owner and
    // covers `new_size`. A live allocator allocation cannot overlap another
    // live allocation, so the source-shaped memcpy has nonoverlapping ranges.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source.copy_client().as_ptr(),
            replacement.as_ptr(),
            source.copy_prefix_len(),
        );
    }
    if new_size == 0 {
        // Pinned `mi_theap_realloc_zero_ex` initializes the first byte of a
        // successful zero-size replacement for callers that observe it before
        // free. The native zero-size allocation is likewise non-null here.
        unsafe { replacement.as_ptr().write(0) };
    }

    match native_free_pointer_first_nonlocal(source.into_live_allocation()) {
        NativePageFreeResult::Freed => NativePageAllocationResult::Allocated(replacement),
        NativePageFreeResult::Unavailable
        | NativePageFreeResult::InvalidPointer
        | NativePageFreeResult::Retained => {
            // The replacement is not published until the old source is
            // consumed. Return it to the caller's direct owner first. If that
            // direct free cannot be proved, its persistent owner remains
            // terminally retained with this unreachable replacement; never
            // claim that it was released or expose it beside the still-live
            // old source.
            native_reallocate_release_unpublished_replacement(replacement);
            RUNTIME_PROCESS.retain_page_owner();
            NativePageAllocationResult::Retained
        }
    }
}

/// Reallocates one C-facing native-shadow block through pointer-derived source
/// facts and the calling thread's persistent native owner.
///
/// # Safety
///
/// When present, `block` must be a live result from this native-shadow
/// allocator and must not be concurrently accessed, remotely published, or
/// already freed. The caller must not access `block` after an `Allocated`
/// result: a current source may have been reallocated in place or replaced,
/// while a noncurrent source has been copied then consumed through generic
/// pointer-first free. An `AllocationFailed` result leaves the old allocation
/// live and unchanged. `Retained` is terminal fail-closed: neither the old
/// input nor an unpublished replacement is returned for caller access. This
/// boundary never borrows a former owner or widens a source allocation
/// lifetime.
#[doc(hidden)]
pub unsafe fn native_reallocate(
    block: Option<core::ptr::NonNull<u8>>,
    new_size: usize,
) -> NativePageAllocationResult {
    if !crate::size_class::request_size_is_valid(new_size) {
        return NativePageAllocationResult::AllocationFailed;
    }
    let Some(block) = block else {
        return native_allocate_aligned(new_size, NATIVE_C_MALLOC_ALIGNMENT, false);
    };
    if let Err(result) = native_reallocate_prepare_caller_persistent_owner() {
        // The old source has not entered a lookup, copy, or consuming free
        // path. A target-owner setup failure leaves it exactly live.
        return result;
    }
    // SAFETY: forwarded from this boundary's exact-live native-client
    // contract. The returned observation remains live through one local or
    // nonlocal source operation below.
    let allocation = match unsafe { native_live_allocation_for_pointer_reallocation(block) } {
        Ok(allocation) => allocation,
        Err(result) => return result,
    };
    let Some(current) = current_thread_identity() else {
        drop(allocation);
        RUNTIME_PROCESS.retain_page_owner();
        return NativePageAllocationResult::Retained;
    };
    if allocation.is_associated_with(current) {
        native_reallocate_pointer_first_local(allocation, new_size)
    } else {
        native_reallocate_pointer_first_nonlocal(allocation, new_size)
    }
}

/// Frees one C-facing native-shadow block from its source page state.
///
/// This is the production pointer-first counterpart of pinned
/// `mi_free_nonnull`: it obtains one coherent PageMap observation before it
/// compares the captured source owner against the caller. A matching source
/// owner uses only its current local engine. Every other live, abandoned, or
/// mapped-abandoned source state moves directly into W03's process-page-facts
/// continuation, which consumes W07's exact claim internally. A detached
/// PageMap observation remains a typed source refusal and is fail-closed as
/// retained; it never revives a former owner through a route, registry,
/// client ledger, scheduler bridge, or geometry selector.
///
/// # Safety
///
/// `block` must be a live native-shadow allocation. A wrong-domain pointer
/// reports `InvalidPointer`. Callers must not route any native failure to the
/// C allocator as recovery.
#[doc(hidden)]
pub unsafe fn native_free(block: core::ptr::NonNull<u8>) -> NativePageFreeResult {
    let Some(page_map) = RUNTIME_PROCESS.page_map_for_live_native_allocation() else {
        // The pointer contract could not obtain its one process-published
        // PageMap witness. No caller-local fallback can establish a source
        // owner after that failure.
        RUNTIME_PROCESS.retain_page_owner();
        return NativePageFreeResult::Retained;
    };
    // SAFETY: `native_free` accepts only an exact current native allocation.
    // Its source lifetime keeps the selected registration and page metadata
    // stable until one branch below consumes the observation.
    let allocation = match unsafe { page_map.lookup_live_allocation(block) } {
        Ok(Some(allocation)) => allocation,
        Ok(None) => return NativePageFreeResult::InvalidPointer,
        Err(_) => {
            RUNTIME_PROCESS.retain_page_owner();
            return NativePageFreeResult::Retained;
        }
    };

    // Pinned `mi_free_nonnull` resolves the page before comparing the page's
    // captured owner identity against the caller. Do not select a former
    // owner, route, or current-thread ledger before this comparison.
    let Some(current) = current_thread_identity() else {
        drop(allocation);
        RUNTIME_PROCESS.retain_page_owner();
        return NativePageFreeResult::Retained;
    };
    if allocation.is_associated_with(current) {
        return native_free_pointer_first_local(allocation);
    }

    native_free_pointer_first_nonlocal(allocation)
}

/// Consumes one PageMap-derived allocation through its current source owner.
///
/// The caller already compared the captured `xthread_id` against its own
/// identity. This helper deliberately performs no second PageMap lookup and
/// never inspects a route, registry, or client ledger to recover local
/// ownership.
fn native_free_pointer_first_local(allocation: LiveAllocationPointer) -> NativePageFreeResult {
    let client = allocation.client();
    if RUNTIME_PROCESS.is_on_initial_thread() {
        // SAFETY: the preceding PageMap classification associated this exact
        // live allocation with the current initial source owner.
        let result = native_initial_thread_free_pointer_first(client);
        drop(allocation);
        return result;
    }

    // The worker's continuously stored owner is already current. Its short
    // local allocator borrow is the only local source operation; unlike the
    // historical helper it does not reclassify the pointer or consult a
    // session handle on a miss.
    let result = with_current_thread_native_persistent_allocator(false, |allocator| {
        // SAFETY: the caller's PageMap observation associated `client` with
        // this exact current owner, and the observation remains live through
        // this one consuming local source free.
        unsafe { allocator.free(client) }
    });
    drop(allocation);
    match result {
        Ok(Ok(())) => NativePageFreeResult::Freed,
        Ok(Err(_)) | Err(_) => {
            retain_current_thread_native_persistent_owner_for_teardown();
            NativePageFreeResult::Retained
        }
    }
}

/// Consumes one nonlocal PageMap observation through W03's source-state tail.
///
/// This is the only nonlocal free continuation. W03 invokes W07's linear
/// source claim internally and owns any post-CAS retained capability; this
/// dispatcher receives only scalar disposition/rejection values.
fn native_free_pointer_first_nonlocal(
    allocation: LiveAllocationPointer,
) -> NativePageFreeResult {
    let detached = allocation.page_state() == LiveAllocationPageState::Detached;
    let Some(process) = current_native_process_page_arena_pair() else {
        // The PageMap observation cannot safely continue without the paired
        // arena capability. This is not a temporary current-owner result.
        RUNTIME_PROCESS.retain_page_owner();
        return NativePageFreeResult::Retained;
    };
    // SAFETY: the active process owns this never-dropped main-Heap lease.
    // `process` was formed from the same active root immediately above.
    let Some(main_heap) = (unsafe { RUNTIME_PROCESS.active_main_heap() }) else {
        RUNTIME_PROCESS.retain_page_owner();
        return NativePageFreeResult::Retained;
    };
    // SAFETY: `allocation` is the exact current PageMap-derived source
    // pointer, while `process` and `main_heap` are the matching process-wide
    // PageMap/arena and static-Heap facts required by W03. W03 consumes any
    // W07 claim rather than exposing or rebuilding it here.
    match unsafe {
        crate::single_thread::continue_post_owner_exit_live_allocation_with_process_page_facts(
            allocation, process, main_heap,
        )
    } {
        Ok(
            ProcessPostOwnerExitPointerFreeDisposition::PublishedToOwner
            | ProcessPostOwnerExitPointerFreeDisposition::StillLive
            | ProcessPostOwnerExitPointerFreeDisposition::Released,
        ) => NativePageFreeResult::Freed,
        Ok(ProcessPostOwnerExitPointerFreeDisposition::Retained) => {
            // W03 already sealed the exact post-CAS source owner. Mark the
            // runtime terminal only after that consuming operation succeeds.
            RUNTIME_PROCESS.retain_page_owner();
            NativePageFreeResult::Retained
        }
        Err(ProcessPostOwnerExitPointerFreeRejection::Publication(
            crate::remote_free::RemoteFreeError::NotOwnerAssociated,
        )) if detached => {
            // Detached is a valid PageMap observation but has no source
            // producer. W03 rejected it before any CAS or terminal marker;
            // retain this scalar result without poisoning the process.
            NativePageFreeResult::Retained
        }
        Err(_) => {
            // Any other pre-CAS failure contradicts the valid PageMap source
            // operation. No legacy route can recover it safely.
            RUNTIME_PROCESS.retain_page_owner();
            NativePageFreeResult::Retained
        }
    }
}

/// Returns the PageMap-derived usable size of one live native allocation.
///
/// This follows pinned `mi_usable_size`'s pointer/page geometry calculation:
/// one immutable PageMap lookup captures the source extent, which this
/// boundary returns directly. Unlike realloc, usable-size has no current-owner
/// operation to select, so it performs no identity, TLS owner, route, registry,
/// scheduler, or page-engine query.
#[doc(hidden)]
pub unsafe fn native_usable_size(block: core::ptr::NonNull<u8>) -> Option<usize> {
    let Some(page_map) = RUNTIME_PROCESS.page_map_for_live_native_allocation() else {
        RUNTIME_PROCESS.retain_page_owner();
        return None;
    };
    // SAFETY: `native_usable_size` receives an exact live native client. Its
    // allocation lifetime keeps this one PageMap source observation stable
    // until the captured scalar has been copied below.
    let allocation = match unsafe { page_map.lookup_live_allocation(block) } {
        Ok(Some(allocation)) => allocation,
        Ok(None) => return None,
        Err(_) => {
            RUNTIME_PROCESS.retain_page_owner();
            return None;
        }
    };
    let usable_size = allocation.usable_size();
    drop(allocation);
    Some(usable_size)
}

/// The allocation vocabulary shared by the source-shaped owner-exit fixtures
/// and the generic TLS-owner preparation.  The latter implementation never
/// hands its underlying allocator to a caller: every successful allocation is
/// represented by one linear client capability first.
///
/// The raw allocator implementation remains for source-level state audits.
/// It does not install compiler-TLS state, while the preparation implementation
/// below records every live client before a worker may suspend.
trait OwnerExitClientAllocator {
    type Client;
    type AllocationError;

    fn allocate_client(
        &mut self,
        request: usize,
        zero: bool,
    ) -> Result<Self::Client, Self::AllocationError>;

    fn allocate_aligned_client(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<Self::Client, Self::AllocationError>;

    fn free_client(&mut self, client: Self::Client) -> Result<(), ()>;

    fn current_allocation_page_reserved_client(&self, client: &Self::Client) -> Option<usize>;
}

impl<'attachment, 'main> OwnerExitClientAllocator
    for MainHeapThreadProcessPageAllocator<'attachment, 'main>
{
    type Client = core::ptr::NonNull<u8>;
    type AllocationError = ();

    #[inline]
    fn allocate_client(
        &mut self,
        request: usize,
        zero: bool,
    ) -> Result<Self::Client, Self::AllocationError> {
        self.allocate(request, zero).ok_or(())
    }

    #[inline]
    fn allocate_aligned_client(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<Self::Client, Self::AllocationError> {
        self.allocate_aligned(request, alignment).ok_or(())
    }

    #[inline]
    fn free_client(&mut self, client: Self::Client) -> Result<(), ()> {
        // SAFETY: the generic source fixture moves each exact allocation
        // exactly once out of its private slot before calling this adapter.
        unsafe { self.free(client) }.map_err(|_| ())
    }

    #[inline]
    fn current_allocation_page_reserved_client(&self, client: &Self::Client) -> Option<usize> {
        // SAFETY: the source fixture asks only about a still-live exact
        // allocation and no producer is in flight through this adapter.
        unsafe { self.current_allocation_page_reserved(*client) }
    }
}

fn free_owner_exit_clients<A: OwnerExitClientAllocator>(
    allocator: &mut A,
    clients: &mut [Option<A::Client>],
) -> Result<(), ()> {
    for client in clients {
        if let Some(client) = client.take() {
            allocator.free_client(client)?;
        }
    }
    Ok(())
}

// This private witness enters one genuinely mixed departing Theap without
// choosing a special exit geometry. It keeps direct and non-direct small
// pages, fills two regular medium pages, gives exactly one client from the
// first to a joined remote publisher, and leaves the second unchanged. Its
// large member keeps two clients live so B must preserve its span through one
// sequential post-exit free before terminal release. It also retains one
// source arena singleton and one OS-aligned singleton. B receives every
// remaining small/medium/large/arena/OS client only through the opaque
// aggregate route. The first full page reaches the source `BIN_FULL`
// collector with a joined remote free; the second reaches the same traversal
// still source-unmapped, while the arena member uses its PageMap-only terminal
// tail and the OS member uses its private-list/clipped-map tail. Every request
// remains inside the existing general traversal profile.
struct OwnerExitMappedRegularWorkload<Client> {
    direct_small: [Option<Client>; OWNER_EXIT_DIRECT_SMALL_CLIENT_SLOTS],
    non_direct_small: [Option<Client>; OWNER_EXIT_NON_DIRECT_SMALL_CLIENT_SLOTS],
    full_medium: [Option<Client>; OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS],
    unmapped_full_medium: [Option<Client>; OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS],
    initially_mapped_medium: [Option<Client>; OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS],
    force_empty_large: Option<Client>,
    large: [Option<Client>; OWNER_EXIT_LIVE_LARGE_CLIENT_SLOTS],
    arena_singleton: Option<Client>,
    os_singleton: Option<Client>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerExitMappedRegularWorkloadError {
    DirectSmallAllocation,
    NonDirectSmallAllocation,
    FirstMediumAllocation,
    FullMediumCapacity,
    FullMediumAllocation,
    UnmappedFullMediumAllocation,
    UnmappedFullMediumCapacity,
    InitiallyMappedMediumAllocation,
    InitiallyMappedMediumCapacity,
    InitiallyMappedMediumLocalFree,
    ForceEmptyLargeAllocation,
    LargeAllocation,
    ArenaSingletonAllocation,
    OsSingletonAllocation,
}

impl<Client> OwnerExitMappedRegularWorkload<Client> {
    fn allocate<A>(allocator: &mut A) -> Result<Self, OwnerExitMappedRegularWorkloadError>
    where
        A: OwnerExitClientAllocator<Client = Client>,
    {
        let mut workload = Self {
            direct_small: core::array::from_fn(|_| None),
            non_direct_small: core::array::from_fn(|_| None),
            full_medium: core::array::from_fn(|_| None),
            unmapped_full_medium: core::array::from_fn(|_| None),
            initially_mapped_medium: core::array::from_fn(|_| None),
            force_empty_large: None,
            large: core::array::from_fn(|_| None),
            arena_singleton: None,
            os_singleton: None,
        };

        for slot in &mut workload.direct_small {
            let Ok(block) = allocator.allocate_client(37, false) else {
                let _ = workload.free_locals(allocator);
                return Err(OwnerExitMappedRegularWorkloadError::DirectSmallAllocation);
            };
            *slot = Some(block);
        }

        for slot in &mut workload.non_direct_small {
            let Ok(block) = allocator.allocate_client(OWNER_EXIT_NON_DIRECT_SMALL_REQUEST, false)
            else {
                let _ = workload.free_locals(allocator);
                return Err(OwnerExitMappedRegularWorkloadError::NonDirectSmallAllocation);
            };
            *slot = Some(block);
        }

        let Ok(first_medium) = allocator.allocate_client(OWNER_EXIT_FULL_MEDIUM_REQUEST, false) else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::FirstMediumAllocation);
        };
        workload.full_medium[0] = Some(first_medium);
        // The allocator vocabulary only exposes this observation for a live
        // exact client. Current committed capacity may still be one while
        // normal allocation grows the page.
        let Some(capacity) = allocator.current_allocation_page_reserved_client(
            workload.full_medium[0]
                .as_ref()
                .expect("the first medium remains in its private workload slot"),
        )
            .filter(|capacity| {
                *capacity >= 2 && *capacity <= OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS
            })
        else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::FullMediumCapacity);
        };
        for slot in workload.full_medium.iter_mut().take(capacity).skip(1) {
            let Ok(block) = allocator.allocate_client(OWNER_EXIT_FULL_MEDIUM_REQUEST, false) else {
                let _ = workload.free_locals(allocator);
                return Err(OwnerExitMappedRegularWorkloadError::FullMediumAllocation);
            };
            *slot = Some(block);
        }

        // The first full medium is now in BIN_FULL, so this exact same
        // request obtains a distinct second page. Leave every second-page
        // client local: it must enter the general aggregate source-unmapped
        // tail rather than being normalized by force collection.
        let Ok(first_unmapped_medium) = allocator.allocate_client(OWNER_EXIT_FULL_MEDIUM_REQUEST, false)
        else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::UnmappedFullMediumAllocation);
        };
        workload.unmapped_full_medium[0] = Some(first_unmapped_medium);
        let Some(unmapped_capacity) = allocator.current_allocation_page_reserved_client(
            workload.unmapped_full_medium[0]
                .as_ref()
                .expect("the first unchanged medium remains in its private workload slot"),
        )
        .filter(|capacity| {
            *capacity >= 2 && *capacity <= OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS
        })
        else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::UnmappedFullMediumCapacity);
        };
        for slot in workload
            .unmapped_full_medium
            .iter_mut()
            .take(unmapped_capacity)
            .skip(1)
        {
            let Ok(block) = allocator.allocate_client(OWNER_EXIT_FULL_MEDIUM_REQUEST, false) else {
                let _ = workload.free_locals(allocator);
                return Err(OwnerExitMappedRegularWorkloadError::UnmappedFullMediumAllocation);
            };
            *slot = Some(block);
        }

        // Fill a third regular medium page, then return one A-local client.
        // This is an ordinary source unfull transition before owner exit: the
        // remaining clients are already a mapped, non-full member when
        // `_mi_theap_collect_ex(MI_ABANDON)` begins. Keep it beside the
        // force-normalized and source-unmapped full members so the aggregate
        // coordinator—not a special page route—selects all three states.
        let Ok(first_initially_mapped_medium) =
            allocator.allocate_client(OWNER_EXIT_FULL_MEDIUM_REQUEST, false)
        else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::InitiallyMappedMediumAllocation);
        };
        workload.initially_mapped_medium[0] = Some(first_initially_mapped_medium);
        let Some(initially_mapped_capacity) = allocator
            .current_allocation_page_reserved_client(
                workload.initially_mapped_medium[0]
                    .as_ref()
                    .expect("the initially mapped medium remains in its private workload slot"),
            )
            .filter(|capacity| {
                *capacity >= 4 && *capacity <= OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS
            })
        else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::InitiallyMappedMediumCapacity);
        };
        for slot in workload
            .initially_mapped_medium
            .iter_mut()
            .take(initially_mapped_capacity)
            .skip(1)
        {
            let Ok(block) = allocator.allocate_client(OWNER_EXIT_FULL_MEDIUM_REQUEST, false) else {
                let _ = workload.free_locals(allocator);
                return Err(OwnerExitMappedRegularWorkloadError::InitiallyMappedMediumAllocation);
            };
            *slot = Some(block);
        }
        let initially_mapped_local_free = workload.initially_mapped_medium[0]
            .take()
            .expect("the full medium keeps the exact A-local client that makes it non-full");
        if allocator.free_client(initially_mapped_local_free).is_err() {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::InitiallyMappedMediumLocalFree);
        }

        let Ok(force_empty_large) = allocator.allocate_client(OWNER_EXIT_FORCE_EMPTY_LARGE_REQUEST, false) else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::ForceEmptyLargeAllocation);
        };
        workload.force_empty_large = Some(force_empty_large);

        for slot in &mut workload.large {
            let Ok(block) = allocator.allocate_client(OWNER_EXIT_LIVE_LARGE_REQUEST, false) else {
                let _ = workload.free_locals(allocator);
                return Err(OwnerExitMappedRegularWorkloadError::LargeAllocation);
            };
            *slot = Some(block);
        }

        let Ok(arena_singleton) =
            allocator.allocate_client(OWNER_EXIT_ARENA_SINGLETON_REQUEST, false)
        else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::ArenaSingletonAllocation);
        };
        workload.arena_singleton = Some(arena_singleton);

        let Ok(os_singleton) = allocator.allocate_aligned_client(
            OWNER_EXIT_OS_SINGLETON_REQUEST,
            OWNER_EXIT_OS_SINGLETON_ALIGNMENT,
        ) else {
            let _ = workload.free_locals(allocator);
            return Err(OwnerExitMappedRegularWorkloadError::OsSingletonAllocation);
        };
        workload.os_singleton = Some(os_singleton);
        Ok(workload)
    }

    #[inline]
    fn take_remote_clients(
        &mut self,
    ) -> Option<(Client, Client)> {
        let medium = self.full_medium[0].take()?;
        let Some(large) = self.force_empty_large.take() else {
            self.full_medium[0] = Some(medium);
            return None;
        };
        Some((medium, large))
    }

    #[inline]
    fn restore_remote_clients(
        &mut self,
        medium: Client,
        large: Client,
    ) {
        debug_assert!(self.full_medium[0].is_none());
        debug_assert!(self.force_empty_large.is_none());
        self.full_medium[0] = Some(medium);
        self.force_empty_large = Some(large);
    }

    fn into_post_exit_clients(
        mut self,
    ) -> Option<[Option<Client>; RUNTIME_PAGE_OWNER_PRIVATE_CLIENT_SLOTS]> {
        // The sole remote client must have left the private workload before
        // A detaches. Keeping it here would make B hold two aliases to the
        // same client identity after source collection.
        if self.full_medium[0].is_some()
            || self.force_empty_large.is_some()
            || !self.direct_small.iter().all(Option::is_some)
            || !self.non_direct_small.iter().all(Option::is_some)
            || !self.full_medium[1..].iter().all(Option::is_some)
            || !self.unmapped_full_medium.iter().all(Option::is_some)
            || !self.initially_mapped_medium[1..].iter().all(Option::is_some)
            || !self.large.iter().all(Option::is_some)
            || self.arena_singleton.is_none()
            || self.os_singleton.is_none()
        {
            return None;
        }

        let mut blocks = core::array::from_fn(|_| None);
        for (destination, source) in blocks[..OWNER_EXIT_DIRECT_SMALL_CLIENT_SLOTS]
            .iter_mut()
            .zip(&mut self.direct_small)
        {
            *destination = source.take();
        }
        for (destination, source) in blocks[OWNER_EXIT_NON_DIRECT_SMALL_START..OWNER_EXIT_LIVE_LARGE_START]
            .iter_mut()
            .zip(&mut self.non_direct_small)
        {
            *destination = source.take();
        }
        for (destination, source) in blocks[OWNER_EXIT_LIVE_LARGE_START..OWNER_EXIT_MAPPED_MEDIUM_START]
            .iter_mut()
            .zip(&mut self.large)
        {
            *destination = source.take();
        }
        for (destination, source) in blocks[OWNER_EXIT_MAPPED_MEDIUM_START..OWNER_EXIT_UNMAPPED_FULL_MEDIUM_START]
            .iter_mut()
            .zip(&mut self.full_medium[1..])
        {
            *destination = source.take();
        }
        for (destination, source) in blocks[OWNER_EXIT_UNMAPPED_FULL_MEDIUM_START..OWNER_EXIT_INITIAL_MAPPED_MEDIUM_START]
            .iter_mut()
            .zip(&mut self.unmapped_full_medium)
        {
            *destination = source.take();
        }
        for (destination, source) in blocks
            [OWNER_EXIT_INITIAL_MAPPED_MEDIUM_START..OWNER_EXIT_ARENA_SINGLETON_INDEX]
            .iter_mut()
            .zip(&mut self.initially_mapped_medium[1..])
        {
            *destination = source.take();
        }
        blocks[OWNER_EXIT_ARENA_SINGLETON_INDEX] = self.arena_singleton.take();
        blocks[OWNER_EXIT_OS_SINGLETON_INDEX] = self.os_singleton.take();
        Some(blocks)
    }

    fn free_locals(
        &mut self,
        allocator: &mut impl OwnerExitClientAllocator<Client = Client>,
    ) -> Result<(), ()> {
        free_owner_exit_clients(allocator, &mut self.direct_small)?;
        free_owner_exit_clients(allocator, &mut self.non_direct_small)?;
        free_owner_exit_clients(allocator, &mut self.full_medium)?;
        free_owner_exit_clients(allocator, &mut self.unmapped_full_medium)?;
        free_owner_exit_clients(allocator, &mut self.initially_mapped_medium)?;
        free_owner_exit_clients(allocator, core::slice::from_mut(&mut self.force_empty_large))?;
        free_owner_exit_clients(allocator, &mut self.large)?;
        free_owner_exit_clients(allocator, core::slice::from_mut(&mut self.arena_singleton))?;
        free_owner_exit_clients(allocator, core::slice::from_mut(&mut self.os_singleton))
    }
}

impl OwnerExitMappedRegularWorkload<core::ptr::NonNull<u8>> {
    /// The direct source-state audits predate the linear TLS preparation and
    /// inspect the same raw private array while A still owns its engine. They
    /// never install a compiler-TLS owner through this compatibility helper.
    #[inline]
    fn into_post_exit_blocks(
        self,
    ) -> Option<[Option<core::ptr::NonNull<u8>>; RUNTIME_PAGE_OWNER_PRIVATE_CLIENT_SLOTS]> {
        self.into_post_exit_clients()
    }
}

impl OwnerExitMappedRegularWorkload<PreparedOwnerExitClient> {
    /// Selects the three direct-small clients used only by the bounded B/C/D
    /// regression. The selection remains an opaque ledger-key fact: generic
    /// post-exit routing neither names these fixture positions nor exposes
    /// their addresses.
    #[inline]
    fn post_exit_remote_publication_group_keys(
        &self,
    ) -> Option<DetachedOwnerExitRemotePublicationSelection> {
        Some(DetachedOwnerExitRemotePublicationSelection {
            kind: DetachedOwnerExitRemotePublicationKind::DirectSmall,
            clients: [
                self.direct_small[0].as_ref()?.key(),
                self.direct_small[1].as_ref()?.key(),
                self.direct_small[2].as_ref()?.key(),
            ],
        })
    }

    /// Selects three still-live clients from the first full-medium member
    /// after its pre-exit remote free forced it into the mapped regular
    /// route. `full_medium[0]` has already left A through that pre-exit
    /// publication; the following three entries remain on the same now
    /// non-full medium page. Their identities stay private ledger facts, so
    /// this is a bounded source witness rather than a page selector or a
    /// general post-exit producer API.
    #[inline]
    fn post_exit_mapped_medium_remote_publication_group_keys(
        &self,
    ) -> Option<DetachedOwnerExitRemotePublicationSelection> {
        Some(DetachedOwnerExitRemotePublicationSelection {
            kind: DetachedOwnerExitRemotePublicationKind::MappedMedium,
            clients: [
                self.full_medium[1].as_ref()?.key(),
                self.full_medium[2].as_ref()?.key(),
                self.full_medium[3].as_ref()?.key(),
            ],
        })
    }

    /// Selects three remaining clients from the distinct medium page that A
    /// made non-full through one ordinary local free before owner exit. The
    /// lower aggregate route already owns every mapped regular member through
    /// the same source traversal; this selection proves that a pre-existing
    /// mapped medium can use the bounded B/C/D publication without being
    /// mistaken for the separate force-normalized source state.
    #[inline]
    fn post_exit_initial_mapped_medium_remote_publication_group_keys(
        &self,
    ) -> Option<DetachedOwnerExitRemotePublicationSelection> {
        Some(DetachedOwnerExitRemotePublicationSelection {
            kind: DetachedOwnerExitRemotePublicationKind::MappedMedium,
            clients: [
                self.initially_mapped_medium[1].as_ref()?.key(),
                self.initially_mapped_medium[2].as_ref()?.key(),
                self.initially_mapped_medium[3].as_ref()?.key(),
            ],
        })
    }

    /// Produces the same complete private ledger as `into_post_exit_clients`,
    /// but schedules one normal full-medium client after every other
    /// post-exit client. The runtime route still has no fixture layout or
    /// page identity: when this final opaque client is reached, the source
    /// aggregate decides whether it is the sole mapped regular member and
    /// otherwise rejects back to the ordinary sequential free.
    ///
    /// The mixed witness chooses this order to exercise the aggregate
    /// last-member handoff with an already-normalized medium page. Its
    /// pre-exit remote client supplies an immediate source free block, while
    /// all other source members are terminally released first.
    fn into_post_exit_clients_for_later_main_adoption(
        self,
    ) -> Option<[Option<PreparedOwnerExitClient>; RUNTIME_PAGE_OWNER_PRIVATE_CLIENT_SLOTS]> {
        let mut clients = self.into_post_exit_clients()?;
        clients.swap(
            OWNER_EXIT_MAPPED_MEDIUM_START,
            OWNER_EXIT_OS_SINGLETON_INDEX,
        );
        Some(clients)
    }
}

/// The source-valid reclamation predecessor: one nonfull medium page with
/// two private live clients and at least one immediate local free block. A's
/// general owner-exit traversal must therefore return the established sole
/// mapped-medium route rather than an aggregate registry.
struct OwnerExitReclaimWorkload<Client> {
    blocks: [Option<Client>; OWNER_EXIT_RECLAIM_CLIENT_SLOTS],
}

impl<Client> OwnerExitReclaimWorkload<Client> {
    fn allocate<A>(allocator: &mut A) -> Result<Self, ()>
    where
        A: OwnerExitClientAllocator<Client = Client>,
    {
        let mut workload = Self {
            blocks: core::array::from_fn(|_| None),
        };
        for slot in &mut workload.blocks {
            let Ok(block) = allocator.allocate_client(OWNER_EXIT_RECLAIM_MEDIUM_REQUEST, false) else {
                let _ = workload.free_locals(allocator);
                return Err(());
            };
            *slot = Some(block);
        }

        // The aggregate owner-exit traversal may expose the sole-medium
        // handoff only after source collection transfers a returned local
        // block into its immediate head. Do not infer that fact merely from
        // capacity: source page extension is lazy, so two live clients can
        // still sit at its current commit boundary. Allocate and return one
        // exact third client while A still owns the engine, matching the
        // source-shaped collector witness.
        let Ok(spare) = allocator.allocate_client(OWNER_EXIT_RECLAIM_MEDIUM_REQUEST, false) else {
            let _ = workload.free_locals(allocator);
            return Err(());
        };
        if allocator.free_client(spare).is_err() {
            let _ = workload.free_locals(allocator);
            return Err(());
        }

        let Some(reserved) = allocator.current_allocation_page_reserved_client(
            workload.blocks[0]
                .as_ref()
                .expect("the reclamation workload keeps its first medium client"),
        )
        .filter(|reserved| *reserved > OWNER_EXIT_RECLAIM_CLIENT_SLOTS)
        else {
            let _ = workload.free_locals(allocator);
            return Err(());
        };
        debug_assert!(reserved > OWNER_EXIT_RECLAIM_CLIENT_SLOTS);
        Ok(workload)
    }

    #[inline]
    fn into_clients(self) -> Option<[Client; OWNER_EXIT_RECLAIM_CLIENT_SLOTS]> {
        let [first, second] = self.blocks;
        Some([first?, second?])
    }

    fn free_locals(
        &mut self,
        allocator: &mut impl OwnerExitClientAllocator<Client = Client>,
    ) -> Result<(), ()> {
        free_owner_exit_clients(allocator, &mut self.blocks)
    }
}

impl OwnerExitReclaimWorkload<core::ptr::NonNull<u8>> {
    /// Raw source-state audits retain the historical optional-array shape;
    /// the TLS preparation consumes the stricter all-present linear array.
    #[inline]
    fn into_blocks(
        self,
    ) -> Option<[Option<core::ptr::NonNull<u8>>; OWNER_EXIT_RECLAIM_CLIENT_SLOTS]> {
        let [first, second] = self.into_clients()?;
        Some([Some(first), Some(second)])
    }
}

/// The source-valid direct-small reclamation predecessor: two opaque live
/// clients in one direct-cache page plus one exact local return. The latter
/// creates the immediate local head required by the existing specialized
/// `abandon_mapped_small_or_medium_to_process_route` boundary. That boundary,
/// rather than this fixed request, validates the complete rounded direct-cache
/// image and refuses every non-direct or malformed shape before A tears down.
struct OwnerExitDirectSmallReclaimWorkload<Client> {
    blocks: [Option<Client>; OWNER_EXIT_RECLAIM_CLIENT_SLOTS],
}

impl<Client> OwnerExitDirectSmallReclaimWorkload<Client> {
    fn allocate<A>(allocator: &mut A) -> Result<Self, ()>
    where
        A: OwnerExitClientAllocator<Client = Client>,
    {
        let mut workload = Self {
            blocks: core::array::from_fn(|_| None),
        };
        for slot in &mut workload.blocks {
            let Ok(block) = allocator.allocate_client(OWNER_EXIT_RECLAIM_DIRECT_SMALL_REQUEST, false)
            else {
                let _ = workload.free_locals(allocator);
                return Err(());
            };
            *slot = Some(block);
        }

        // A direct-small page may begin with a lazy scalar extension. Return
        // one exact third local client while A still has exclusive ownership,
        // so the specialized source drain receives the required immediate
        // head instead of inferring availability from reserved capacity.
        let Ok(spare) = allocator.allocate_client(OWNER_EXIT_RECLAIM_DIRECT_SMALL_REQUEST, false)
        else {
            let _ = workload.free_locals(allocator);
            return Err(());
        };
        if allocator.free_client(spare).is_err() {
            let _ = workload.free_locals(allocator);
            return Err(());
        }

        // Preserve a bounded source candidate before suspension. The typed
        // direct-small drain performs the authoritative direct-cache and
        // immediate-head validation while it still owns the active queue.
        let Some(reserved) = allocator.current_allocation_page_reserved_client(
            workload.blocks[0]
                .as_ref()
                .expect("the direct-small reclamation workload keeps its first client"),
        )
        .filter(|reserved| *reserved > OWNER_EXIT_RECLAIM_CLIENT_SLOTS)
        else {
            let _ = workload.free_locals(allocator);
            return Err(());
        };
        debug_assert!(reserved > OWNER_EXIT_RECLAIM_CLIENT_SLOTS);
        Ok(workload)
    }

    #[inline]
    fn into_clients(self) -> Option<[Client; OWNER_EXIT_RECLAIM_CLIENT_SLOTS]> {
        let [first, second] = self.blocks;
        Some([first?, second?])
    }

    fn free_locals(
        &mut self,
        allocator: &mut impl OwnerExitClientAllocator<Client = Client>,
    ) -> Result<(), ()> {
        free_owner_exit_clients(allocator, &mut self.blocks)
    }
}

impl OwnerExitDirectSmallReclaimWorkload<core::ptr::NonNull<u8>> {
    /// The direct-small state audit needs the first client separately because
    /// the source drain names it before validating the complete route image.
    #[inline]
    fn into_route_parts(
        self,
    ) -> Option<(
        core::ptr::NonNull<u8>,
        [Option<core::ptr::NonNull<u8>>; OWNER_EXIT_RECLAIM_CLIENT_SLOTS],
    )> {
        let [first, second] = self.into_clients()?;
        Some((first, [Some(first), Some(second)]))
    }
}

/// Selects one already-distinct source reclamation predecessor while keeping
/// its consumer and all client identities in the same private TLS owner.
#[derive(Clone, Copy)]
enum MappedRegularReclaimPredecessor {
    Medium,
    DirectSmall,
}

/// The result of preparing the private page-bearing TLS owner before the
/// ordinary post-destructor runtime finish dispatches it into source owner
/// exit. `Installed` moved the engine borrow into compiler TLS; the ordinary
/// failures returned their engine empty and may use the existing no-page
/// finish. Every other state remains terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerExitMappedRegularPageOwnerInstallResult {
    Installed,
    AllocationFailed,
    PublicationFailed,
    Retained,
}

#[inline]
fn retain_current_thread_detached_owner_exit() {
    let slot = current_thread_slot();
    // The old Theap/TLD has either already detached or its typed terminal
    // still owns it. In both cases a generic normal finish would be unsound;
    // retain the admission claim so fork preservation remains closed.
    slot.state = ThreadLifecycleState::Retained;
    RUNTIME_PROCESS.retain();
}

/// Retains an attachment whose page-bearing state has not safely crossed the
/// source owner-exit boundary.  Unlike the detached-route helper above, this
/// path still has a live or suspended engine and must also terminally close
/// ticket zero's dormant-pair scheduler.
#[inline]
fn retain_current_thread_live_page_owner() {
    let slot = current_thread_slot();
    slot.state = ThreadLifecycleState::Retained;
    RUNTIME_PROCESS.retain_page_owner();
}

#[inline]
fn retain_current_thread_detached_owner_exit_with_admission(
    admission: LaterThreadAdmissionClaim,
) {
    let slot = current_thread_slot();
    slot.retain_terminal_admission(admission);
    slot.state = ThreadLifecycleState::Retained;
    RUNTIME_PROCESS.retain();
}

/// Completes the runtime half of a source owner exit after a private typed
/// process route has proved `ReleasedAll`.
///
/// The proof can only come after the aggregate route's final PageMap release,
/// whether that release was a direct client-free tail or the consumed target
/// engine of its source-valid final-member handoff. In particular, this intentionally does not call
/// `finish_current_thread_after_user_destructors`: that no-page entry would
/// attempt to access an attachment whose Theap/TLD boundary was already
/// completed by `finish_after_detached_process_page_route`.
fn finish_current_thread_after_detached_process_page_route(
    proof: TicketZeroOwnerExitRouteFinished,
) -> ThreadFinishResult {
    let slot = current_thread_slot();
    match slot.state {
        ThreadLifecycleState::Fresh
        | ThreadLifecycleState::Finished
        | ThreadLifecycleState::Retained => {
            // A terminal proof on any other lifecycle state is an invalid
            // private transition. Preserve its exact claim rather than
            // dropping the proof and leaving an unrepresented gate count.
            retain_current_thread_detached_owner_exit_with_admission(proof.into_admission());
            return ThreadFinishResult::Retained;
        }
        ThreadLifecycleState::Attached => {}
    }
    if slot.admission.is_some() {
        // The only producer moves the TLS claim into the opaque route before
        // exposing it to B. A second TLS claim therefore indicates a broken
        // private lifecycle transition. Keep the route claim terminally
        // retained and never make this worker look fork-quiescent.
        retain_current_thread_detached_owner_exit_with_admission(proof.into_admission());
        return ThreadFinishResult::Retained;
    }

    // The proof is minted only after `finish_thread_owner` detached A's old
    // Theap/TLD and the last post-exit client free finished the PageMap
    // lifecycle. An implementation may retain the now-torn-down attachment
    // in TLS as a diagnostic witness, but the proof—not that storage detail—
    // is the authority to discard it and release admission.
    drop(slot.attachment.take());

    match proof.release_worker_admission(&RUNTIME_FORK_ADMISSION) {
        Ok(()) => {
            slot.state = ThreadLifecycleState::Finished;
            ThreadFinishResult::Finished
        }
        Err(TicketZeroOwnerExitRouteFinished { admission }) => {
            // The old attachment is already gone, but the admission count no
            // longer names this exact source transition. Preserve the exact
            // claim in TLS rather than making the post-exit route appear
            // fork-quiescent.
            slot.admission = Some(admission);
            retain_current_thread_detached_owner_exit();
            ThreadFinishResult::Retained
        }
    }
}

fn free_owner_exit_locals(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    blocks: &mut [Option<core::ptr::NonNull<u8>>],
) -> Result<(), ()> {
    for block in blocks {
        if let Some(block) = block.take() {
            // SAFETY: this cleanup remains in A before any producer publishes
            // or the engine enters the source owner-exit drain.
            unsafe { allocator.free(block) }.map_err(|_| ())?;
        }
    }
    Ok(())
}

/// One non-copyable exact client emitted by a page-owner preparation.  It is
/// deliberately neither a client pointer API nor a public allocation handle:
/// its only consumers record local free, pre-exit publication, or the one
/// typed post-exit route that will own it after A's engine suspends.
#[must_use = "every prepared owner-exit client must be locally freed, published before exit, or transferred into the typed post-exit route"]
struct PreparedOwnerExitClient {
    slot: usize,
    generation: usize,
    block: core::ptr::NonNull<u8>,
    usable_size: usize,
    normal_request: Option<usize>,
}

impl PreparedOwnerExitClient {
    #[inline]
    fn key(&self) -> DetachedOwnerExitClientKey {
        DetachedOwnerExitClientKey {
            slot: self.slot,
            generation: self.generation,
        }
    }
}

#[cfg(test)]
impl PreparedOwnerExitClient {
    /// Creates an intentionally forged second linear capability for the
    /// ledger regression below. Production code cannot duplicate this
    /// non-`Copy` capability.
    #[inline]
    fn duplicate_for_test(&self) -> Self {
        Self {
            slot: self.slot,
            generation: self.generation,
            block: self.block,
            usable_size: self.usable_size,
            normal_request: self.normal_request,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedOwnerExitClientState {
    Vacant,
    Live {
        generation: usize,
        block: core::ptr::NonNull<u8>,
        usable_size: usize,
        normal_request: Option<usize>,
    },
    /// The raw client address is now inside `DetachedOwnerExit`'s private
    /// ledger. The source engine has not suspended yet, so preparation abort
    /// may take that exit back and free these exact local clients. Keeping the
    /// full immutable client fact here lets a metadata-backed session move
    /// its private storage into the detached route without reconstructing an
    /// address from source page state after A's Theap has gone away.
    TransferredToExit(DetachedOwnerExitClient),
    /// A joined source remote producer owns the free. Its address never
    /// appears in the post-exit route and source collection consumes it before
    /// the engine can suspend.
    PublishedBeforeExit,
    /// A fresh B published this C-facing client while the original A session
    /// remains parked and live. A's next ordinary source operation may collect
    /// and reuse it, so unlike `PublishedBeforeExit` this state must not close
    /// the session to later allocations. It still cannot be locally freed,
    /// reallocated, or transferred to a post-exit route.
    PublishedToLiveOwner,
    Freed,
}

// The source ordinary allocator returns naturally aligned blocks. The
// metadata overflow stores only this private enum, whose alignment stays
// within that source guarantee. Keeping the assertion beside the raw
// projection below makes an accidental wider state fail at compile time
// instead of reinterpreting an under-aligned metadata allocation.
const _: [(); 1] = [(); (core::mem::align_of::<PreparedOwnerExitClientState>() <= 16) as usize];

/// One metadata-backed extension of the current thread's private client
/// ledger. The linear [`MetaAllocation`] stays with the session until every
/// local client has been freed or the typed exit route has terminally
/// completed. The raw slot bytes never leave this module.
struct PreparedOwnerExitClientOverflow {
    allocation: MetaAllocation<'static>,
    slot_count: usize,
}

/// The private linear registry for allocations made while preparing a
/// current-thread page owner. Its inline portion covers the focused source
/// aggregate, while a real native session may extend it through the detached
/// metadata allocator. This is storage for existing private client facts, not
/// a pointer registry: no caller can enumerate or obtain an entry from it.
///
/// A typed detached route may take this complete registry after it has
/// transformed every live entry into an immutable route-owned client fact.
/// That move keeps overflow storage and all C addresses private while A's
/// old Theap/TLD is torn down; B can only submit an exact C address to its
/// opaque route and cannot enumerate this registry.
struct PreparedOwnerExitClients {
    slots: [PreparedOwnerExitClientState; RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS],
    overflow: Option<PreparedOwnerExitClientOverflow>,
    /// `None` is used only by isolated ledger tests. Every runtime session
    /// records the frozen attachment configuration and can grow its private
    /// metadata storage before a C allocation escapes the source engine.
    metadata_config: Option<MemoryConfig>,
    next_generation: usize,
}

impl PreparedOwnerExitClients {
    const fn new(metadata_config: Option<MemoryConfig>) -> Self {
        Self {
            slots: [
                PreparedOwnerExitClientState::Vacant;
                RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS
            ],
            overflow: None,
            metadata_config,
            next_generation: 0,
        }
    }

    #[inline]
    fn overflow_slots(&self) -> &[PreparedOwnerExitClientState] {
        let Some(overflow) = self.overflow.as_ref() else {
            return &[];
        };
        // SAFETY: `grow_overflow` initializes every slot before publishing
        // this capability, and the metadata allocation remains owned by
        // `self` for the whole returned borrow. The compile-time alignment
        // assertion above matches the source ordinary-allocation guarantee.
        unsafe {
            core::slice::from_raw_parts(
                overflow
                    .allocation
                    .pointer()
                    .as_ptr()
                    .cast::<PreparedOwnerExitClientState>(),
                overflow.slot_count,
            )
        }
    }

    #[inline]
    fn overflow_slots_mut(&mut self) -> &mut [PreparedOwnerExitClientState] {
        let Some(overflow) = self.overflow.as_mut() else {
            return &mut [];
        };
        // SAFETY: see `overflow_slots`; this exclusive borrow also excludes
        // metadata resize or release until the returned slice ends.
        unsafe {
            core::slice::from_raw_parts_mut(
                overflow
                    .allocation
                    .pointer()
                    .as_ptr()
                    .cast::<PreparedOwnerExitClientState>(),
                overflow.slot_count,
            )
        }
    }

    /// Initializes a raw metadata range before any typed slice can observe
    /// it. `MetaAllocator::zalloc` gives bytes, not initialized Rust enum
    /// values, and `rezalloc` copies only the previous initialized prefix.
    /// Writing every new slot through a raw pointer keeps the later
    /// `from_raw_parts[_mut]` projections sound even if `Vacant` stops using
    /// an all-zero representation.
    fn initialize_overflow_slots(
        pointer: core::ptr::NonNull<u8>,
        start: usize,
        end: usize,
    ) {
        for slot in start..end {
            // SAFETY: the caller owns a metadata allocation large enough for
            // `end` client states, and each new slot is written exactly once
            // before any shared or mutable typed projection is created.
            unsafe {
                pointer
                    .as_ptr()
                    .cast::<PreparedOwnerExitClientState>()
                    .add(slot)
                    .write(PreparedOwnerExitClientState::Vacant);
            }
        }
    }

    #[inline]
    fn slot_count(&self) -> usize {
        RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS + self.overflow_slots().len()
    }

    #[inline]
    fn state(&self, slot: usize) -> Option<&PreparedOwnerExitClientState> {
        if slot < self.slots.len() {
            return self.slots.get(slot);
        }
        self.overflow_slots().get(slot - self.slots.len())
    }

    #[inline]
    fn state_mut(&mut self, slot: usize) -> Option<&mut PreparedOwnerExitClientState> {
        if slot < self.slots.len() {
            return self.slots.get_mut(slot);
        }
        let overflow_slot = slot.checked_sub(self.slots.len())?;
        self.overflow_slots_mut().get_mut(overflow_slot)
    }

    #[inline]
    fn any_state(
        &self,
        predicate: impl Fn(&PreparedOwnerExitClientState) -> bool,
    ) -> bool {
        self.slots.iter().any(&predicate) || self.overflow_slots().iter().any(predicate)
    }

    #[inline]
    fn all_states(
        &self,
        predicate: impl Fn(&PreparedOwnerExitClientState) -> bool,
    ) -> bool {
        self.slots.iter().all(&predicate) && self.overflow_slots().iter().all(predicate)
    }

    /// Extends the session-local ledger before the next C allocation can
    /// escape. A failed metadata request changes no source page allocation or
    /// client state; callers report the normal selected allocation failure.
    fn grow_overflow(&mut self) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        let Some(config) = self.metadata_config else {
            return Err(CurrentThreadPageOwnerPreparationError::OverCapacity);
        };
        let previous_slots = self.overflow_slots().len();
        let next_slots = if previous_slots == 0 {
            RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS
        } else {
            previous_slots
                .checked_mul(2)
                .ok_or(CurrentThreadPageOwnerPreparationError::AllocationFailed)?
        };
        let byte_count = next_slots
            .checked_mul(core::mem::size_of::<PreparedOwnerExitClientState>())
            .ok_or(CurrentThreadPageOwnerPreparationError::AllocationFailed)?;

        if let Some(overflow) = self.overflow.as_mut() {
            let replacement = MetaAllocator::global()
                .rezalloc(config, Some(&mut overflow.allocation), byte_count)
                .map_err(|_| CurrentThreadPageOwnerPreparationError::AllocationFailed)?;
            overflow.allocation = replacement;
            overflow.slot_count = next_slots;
            Self::initialize_overflow_slots(
                overflow.allocation.pointer(),
                previous_slots,
                next_slots,
            );
        } else {
            let allocation = MetaAllocator::global()
                .zalloc(config, byte_count)
                .map_err(|_| CurrentThreadPageOwnerPreparationError::AllocationFailed)?;
            Self::initialize_overflow_slots(allocation.pointer(), 0, next_slots);
            self.overflow = Some(PreparedOwnerExitClientOverflow {
                allocation,
                slot_count: next_slots,
            });
        }
        Ok(())
    }

    /// Releases private metadata only after no local client can still require
    /// the ledger. Fixed preparation routes copy their small selected set, so
    /// transferred and source-published states do not keep an otherwise idle
    /// overflow alive. A metadata-backed detached route uses the stricter
    /// `release_overflow_without_detached_clients` boundary below instead.
    /// The caller retains its owner if metadata release fails, so cleanup
    /// cannot make worker admission look quiescent.
    fn release_overflow_without_live_clients(
        &mut self,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        if self.has_live_client() {
            return Err(CurrentThreadPageOwnerPreparationError::OmittedClient);
        }
        let Some(mut overflow) = self.overflow.take() else {
            return Ok(());
        };
        match MetaAllocator::global().free(&mut overflow.allocation) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.overflow = Some(overflow);
                Err(CurrentThreadPageOwnerPreparationError::LocalFree)
            }
        }
    }

    #[inline]
    fn detached_client_at(&self, slot: usize) -> Option<DetachedOwnerExitClient> {
        match self.state(slot)? {
            PreparedOwnerExitClientState::TransferredToExit(client) => Some(*client),
            _ => None,
        }
    }

    #[inline]
    fn detached_client_for_key(
        &self,
        key: DetachedOwnerExitClientKey,
    ) -> Option<DetachedOwnerExitClient> {
        self.detached_client_at(key.slot)
            .filter(|client| client.key == key)
    }

    #[inline]
    fn has_detached_client(&self) -> bool {
        self.any_state(|state| {
            matches!(state, PreparedOwnerExitClientState::TransferredToExit(_))
        })
    }

    #[inline]
    fn detached_block_for(&self, key: DetachedOwnerExitClientKey) -> Option<core::ptr::NonNull<u8>> {
        self.detached_client_for_key(key).map(|client| client.block)
    }

    #[inline]
    fn next_detached_client(&self) -> Option<DetachedOwnerExitClient> {
        (0..self.slot_count()).find_map(|slot| self.detached_client_at(slot))
    }

    #[inline]
    fn take_detached_client_for_key(
        &mut self,
        key: DetachedOwnerExitClientKey,
    ) -> Option<DetachedOwnerExitClient> {
        let state = self.state_mut(key.slot)?;
        let PreparedOwnerExitClientState::TransferredToExit(client) = *state else {
            return None;
        };
        if client.key != key {
            return None;
        }
        *state = PreparedOwnerExitClientState::Freed;
        Some(client)
    }

    #[inline]
    fn take_next_detached_client(&mut self) -> Option<DetachedOwnerExitClient> {
        for slot in 0..self.slot_count() {
            let Some(client) = self.detached_client_at(slot) else {
                continue;
            };
            return self.take_detached_client_for_key(client.key);
        }
        None
    }

    #[inline]
    fn take_detached_client_for_native_free(
        &mut self,
        block: core::ptr::NonNull<u8>,
    ) -> Option<DetachedOwnerExitClient> {
        for slot in 0..self.slot_count() {
            let Some(client) = self.detached_client_at(slot) else {
                continue;
            };
            if client.block == block {
                return self.take_detached_client_for_key(client.key);
            }
        }
        None
    }

    #[inline]
    fn only_detached_client_for_native_free(
        &self,
        block: core::ptr::NonNull<u8>,
    ) -> Option<DetachedOwnerExitClient> {
        let mut only = None;
        for slot in 0..self.slot_count() {
            let Some(client) = self.detached_client_at(slot) else {
                continue;
            };
            if only.replace(client).is_some() {
                return None;
            }
        }
        only.filter(|client| client.block == block)
    }

    #[inline]
    fn detached_usable_size_for_native_block(
        &self,
        block: core::ptr::NonNull<u8>,
    ) -> Option<usize> {
        (0..self.slot_count()).find_map(|slot| {
            self.detached_client_at(slot)
                .filter(|client| client.block == block)
                .map(|client| client.usable_size)
        })
    }

    fn take_detached_remote_publication_group(
        &mut self,
        selection: DetachedOwnerExitRemotePublicationSelection,
    ) -> Option<DetachedOwnerExitRemotePublicationGroup> {
        let [direct, first_published, second_published] = selection.clients;
        if direct == first_published
            || direct == second_published
            || first_published == second_published
        {
            return None;
        }
        self.detached_client_for_key(direct)?;
        self.detached_client_for_key(first_published)?;
        self.detached_client_for_key(second_published)?;
        let direct = self
            .take_detached_client_for_key(direct)
            .expect("the prevalidated direct detached client remains present");
        let first_published = self
            .take_detached_client_for_key(first_published)
            .expect("the distinct first published detached client remains present");
        let second_published = self
            .take_detached_client_for_key(second_published)
            .expect("the distinct second published detached client remains present");
        Some(DetachedOwnerExitRemotePublicationGroup {
            kind: selection.kind,
            direct: Some(direct.block),
            first_published: Some(first_published.block),
            second_published: Some(second_published.block),
        })
    }

    /// Returns the metadata allocation only after the detached route has no
    /// still-routable client. A stale local `Live` state is also rejected:
    /// moving the registry is valid only when every such client crossed the
    /// same typed route exactly once.
    fn release_overflow_without_detached_clients(
        &mut self,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        if self.has_live_client() || self.has_detached_client() {
            return Err(CurrentThreadPageOwnerPreparationError::OmittedClient);
        }
        let Some(mut overflow) = self.overflow.take() else {
            return Ok(());
        };
        match MetaAllocator::global().free(&mut overflow.allocation) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.overflow = Some(overflow);
                Err(CurrentThreadPageOwnerPreparationError::LocalFree)
            }
        }
    }

    fn reserve_slot(&mut self) -> Result<(usize, usize), CurrentThreadPageOwnerPreparationError> {
        let mut slot = (0..self.slot_count()).find(|slot| {
            matches!(
                self.state(*slot),
                Some(PreparedOwnerExitClientState::Vacant | PreparedOwnerExitClientState::Freed)
            )
        });
        if slot.is_none() {
            self.grow_overflow()?;
            slot = (0..self.slot_count()).find(|slot| {
                matches!(
                    self.state(*slot),
                    Some(PreparedOwnerExitClientState::Vacant | PreparedOwnerExitClientState::Freed)
                )
            });
        }
        let Some(slot) = slot else {
            return Err(CurrentThreadPageOwnerPreparationError::OverCapacity);
        };
        self.next_generation = self.next_generation.wrapping_add(1);
        if self.next_generation == 0 {
            // Zero remains an impossible generation so a wrapped stale test
            // capability cannot name a fresh allocation slot.
            self.next_generation = 1;
        }
        Ok((slot, self.next_generation))
    }

    fn record_allocation(
        &mut self,
        slot: usize,
        generation: usize,
        block: core::ptr::NonNull<u8>,
        usable_size: usize,
        normal_request: Option<usize>,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerPreparationError> {
        if self.any_state(|state| {
            matches!(
                state,
                PreparedOwnerExitClientState::Live {
                    block: existing,
                    ..
                } if *existing == block
            )
        }) {
            return Err(CurrentThreadPageOwnerPreparationError::DuplicateClient);
        }
        let Some(state) = self.state_mut(slot) else {
            return Err(CurrentThreadPageOwnerPreparationError::OverCapacity);
        };
        *state = PreparedOwnerExitClientState::Live {
            generation,
            block,
            usable_size,
            normal_request,
        };
        Ok(PreparedOwnerExitClient {
            slot,
            generation,
            block,
            usable_size,
            normal_request,
        })
    }

    /// Records one ordinary allocation while the exact source engine is
    /// live. The private registry is the boundary: no allocation may survive
    /// a park without a corresponding linear client capability, whether that
    /// capability occupies inline storage or a session-private extension.
    fn allocate_client(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        request: usize,
        zero: bool,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerPreparationError> {
        if self.has_published_before_exit() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        let (slot, generation) = self.reserve_slot()?;
        let Some(block) = allocator.allocate(request, zero) else {
            return Err(CurrentThreadPageOwnerPreparationError::AllocationFailed);
        };
        // SAFETY: this exact block was just returned by the current exclusive
        // engine. A missing extent would violate the engine's allocation
        // contract before the block could reach the private ledger.
        let usable_size = unsafe { allocator.usable_size(block) }
            .expect("a freshly allocated owner-session block has a usable extent");
        match self.record_allocation(slot, generation, block, usable_size, Some(request)) {
            Ok(client) => Ok(client),
            Err(error) => {
                // SAFETY: a duplicate registry identity is impossible for a
                // correct exclusive allocator, but if it occurs the just-made
                // allocation must not escape this rejected source operation.
                let _ = unsafe { allocator.free(block) };
                Err(error)
            }
        }
    }

    /// Records one aligned allocation. The missing normal request is
    /// intentional: the aggregate final-member adoption edge is restricted
    /// to ordinary allocation clients and never guesses an aligned request.
    fn allocate_aligned_client(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        request: usize,
        alignment: usize,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerPreparationError> {
        if self.has_published_before_exit() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        let (slot, generation) = self.reserve_slot()?;
        let Some(block) = allocator.allocate_aligned(request, alignment) else {
            return Err(CurrentThreadPageOwnerPreparationError::AllocationFailed);
        };
        // SAFETY: see the ordinary allocation's exact-current query above.
        let usable_size = unsafe { allocator.usable_size(block) }
            .expect("a freshly aligned owner-session block has a usable extent");
        match self.record_allocation(slot, generation, block, usable_size, None) {
            Ok(client) => Ok(client),
            Err(error) => {
                // SAFETY: see the matching ordinary-allocation cleanup.
                let _ = unsafe { allocator.free(block) };
                Err(error)
            }
        }
    }

    /// Records one zeroed aligned allocation for the nondefault native libc
    /// shadow. As with the ordinary aligned path, the missing normal request
    /// deliberately keeps a later owner-exit traversal from guessing a
    /// final-member adoption request for an over-aligned C client.
    fn allocate_aligned_zeroed_client(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        request: usize,
        alignment: usize,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerPreparationError> {
        if self.has_published_before_exit() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        let (slot, generation) = self.reserve_slot()?;
        let Some(block) = allocator.allocate_aligned_zeroed(request, alignment) else {
            return Err(CurrentThreadPageOwnerPreparationError::AllocationFailed);
        };
        // SAFETY: see the ordinary allocation's exact-current query above.
        let usable_size = unsafe { allocator.usable_size(block) }
            .expect("a freshly zeroed aligned owner-session block has a usable extent");
        match self.record_allocation(slot, generation, block, usable_size, None) {
            Ok(client) => Ok(client),
            Err(error) => {
                // SAFETY: the just-created allocation has not escaped the
                // current exclusive engine when the private ledger rejects it.
                let _ = unsafe { allocator.free(block) };
                Err(error)
            }
        }
    }

    fn validate_live(
        &self,
        client: &PreparedOwnerExitClient,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        let Some(state) = self.state(client.slot) else {
            return Err(CurrentThreadPageOwnerPreparationError::UnknownClient);
        };
        match state {
            PreparedOwnerExitClientState::Live {
                generation,
                block,
                usable_size,
                normal_request,
            } if *generation == client.generation
                && *block == client.block
                && *usable_size == client.usable_size
                && *normal_request == client.normal_request =>
            {
                Ok(())
            }
            PreparedOwnerExitClientState::Live { .. } => {
                Err(CurrentThreadPageOwnerPreparationError::UnknownClient)
            }
            PreparedOwnerExitClientState::TransferredToExit(_)
            | PreparedOwnerExitClientState::PublishedBeforeExit
            | PreparedOwnerExitClientState::PublishedToLiveOwner
            | PreparedOwnerExitClientState::Freed => {
                Err(CurrentThreadPageOwnerPreparationError::DuplicateClient)
            }
            PreparedOwnerExitClientState::Vacant => {
                Err(CurrentThreadPageOwnerPreparationError::UnknownClient)
            }
        }
    }

    /// Validates one opaque client key while the source session still owns its
    /// complete live registry.  A post-exit B/C pair is selected by these
    /// keys—not by a raw address—and must be rejected before the transfer
    /// changes any registry state.
    fn validate_live_key(
        &self,
        key: DetachedOwnerExitClientKey,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        let Some(state) = self.state(key.slot) else {
            return Err(CurrentThreadPageOwnerPreparationError::UnknownClient);
        };
        match state {
            PreparedOwnerExitClientState::Live { generation, .. }
                if *generation == key.generation =>
            {
                Ok(())
            }
            PreparedOwnerExitClientState::Live { .. }
            | PreparedOwnerExitClientState::Vacant => {
                Err(CurrentThreadPageOwnerPreparationError::UnknownClient)
            }
            PreparedOwnerExitClientState::TransferredToExit(_)
            | PreparedOwnerExitClientState::PublishedBeforeExit
            | PreparedOwnerExitClientState::PublishedToLiveOwner
            | PreparedOwnerExitClientState::Freed => {
                Err(CurrentThreadPageOwnerPreparationError::DuplicateClient)
            }
        }
    }

    fn transfer_clients(
        &mut self,
        clients: &mut [Option<PreparedOwnerExitClient>],
    ) -> Result<DetachedOwnerExitClientLedger, CurrentThreadPageOwnerPreparationError> {
        self.transfer_clients_with_final_member_adoption(clients, |_| false)
    }

    /// Transfers a complete selected client set while recording the only
    /// pre-suspension fact that can authorize a later aggregate
    /// final-member reclaim attempt. The callback runs only after the linear
    /// registry has validated each client and must be conservative: `false`
    /// retains the ordinary sequential-free route, while a false positive
    /// could turn a reversible route into a post-claim retained owner.
    fn transfer_clients_with_final_member_adoption(
        &mut self,
        clients: &mut [Option<PreparedOwnerExitClient>],
        mut has_pre_exit_owner_exit_collectable_local_free: impl FnMut(&PreparedOwnerExitClient) -> bool,
    ) -> Result<DetachedOwnerExitClientLedger, CurrentThreadPageOwnerPreparationError> {
        // Fixed preparation callers still provide a fixed selected array.
        // The dynamic session path below moves its own whole registry instead
        // of silently truncating an overflow into this inline witness.
        if clients.len() > RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS {
            return Err(CurrentThreadPageOwnerPreparationError::OverCapacity);
        }
        let mut seen = [false; RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS];
        for client in clients.iter().flatten() {
            if client.slot >= seen.len() {
                return Err(CurrentThreadPageOwnerPreparationError::OverCapacity);
            }
            self.validate_live(client)?;
            if seen[client.slot] {
                return Err(CurrentThreadPageOwnerPreparationError::DuplicateClient);
            }
            seen[client.slot] = true;
        }
        for slot in 0..self.slot_count() {
            let state = self
                .state(slot)
                .expect("the private ledger range has a matching slot");
            if matches!(state, PreparedOwnerExitClientState::Live { .. })
                && (slot >= seen.len() || !seen[slot])
            {
                return Err(if slot >= seen.len() {
                    CurrentThreadPageOwnerPreparationError::OverCapacity
                } else {
                    CurrentThreadPageOwnerPreparationError::OmittedClient
                });
            }
        }

        let mut entries = core::array::from_fn(|_| None);
        for (entry, client) in entries.iter_mut().zip(clients.iter_mut()) {
            let Some(client) = client.take() else {
                continue;
            };
            let detached = DetachedOwnerExitClient {
                key: client.key(),
                block: client.block,
                usable_size: client.usable_size,
                normal_request: client.normal_request,
                has_pre_exit_owner_exit_collectable_local_free: client.normal_request.is_some()
                    && has_pre_exit_owner_exit_collectable_local_free(&client),
            };
            *entry = Some(detached);
            *self
                .state_mut(client.slot)
                .expect("the validated private client keeps its slot") =
                PreparedOwnerExitClientState::TransferredToExit(detached);
        }
        Ok(DetachedOwnerExitClientLedger::from_inline_entries(entries))
    }

    /// Transfers every still-local client into the private post-exit ledger
    /// without asking an ordinary session caller to enumerate raw client
    /// capabilities. A metadata-backed session moves that same private
    /// storage into the route after its live entries become detached facts;
    /// source-published clients remain outside the route for source
    /// collection before A detaches.
    fn transfer_all_live(
        &mut self,
    ) -> Result<DetachedOwnerExitClientLedger, CurrentThreadPageOwnerPreparationError> {
        self.transfer_all_live_with_final_member_adoption(|_| false)
    }

    /// Transfers every live client while preserving an A-side owner-exit
    /// force-collectable local-head fact for the opaque B route. As with the
    /// selected form, a missing or failed observation is deliberately
    /// conservative and leaves the client sequential-free-only after A
    /// detaches.
    fn transfer_all_live_with_final_member_adoption(
        &mut self,
        mut has_pre_exit_owner_exit_collectable_local_free: impl FnMut(&PreparedOwnerExitClient) -> bool,
    ) -> Result<DetachedOwnerExitClientLedger, CurrentThreadPageOwnerPreparationError> {
        let live_count = (0..self.slot_count())
            .filter(|slot| {
                matches!(
                    self.state(*slot),
                    Some(PreparedOwnerExitClientState::Live { .. })
                )
            })
            .count();
        if live_count == 0 {
            return Err(CurrentThreadPageOwnerPreparationError::OmittedClient);
        }
        if self.overflow.is_none() && live_count > RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS {
            return Err(CurrentThreadPageOwnerPreparationError::OverCapacity);
        }

        let has_overflow = self.overflow.is_some();
        let mut inline_entries = core::array::from_fn(|_| None);
        let mut entry = 0;
        for slot in 0..self.slot_count() {
            let state = *self
                .state(slot)
                .expect("the private ledger range has a matching slot");
            let PreparedOwnerExitClientState::Live {
                generation,
                block,
                usable_size,
                normal_request,
            } = state
            else {
                continue;
            };
            let detached = DetachedOwnerExitClient {
                key: DetachedOwnerExitClientKey {
                    slot,
                    generation,
                },
                block,
                usable_size,
                normal_request,
                has_pre_exit_owner_exit_collectable_local_free: normal_request.is_some()
                    && has_pre_exit_owner_exit_collectable_local_free(&PreparedOwnerExitClient {
                        slot,
                        generation,
                        block,
                        usable_size,
                        normal_request,
                    }),
            };
            if !has_overflow {
                inline_entries[entry] = Some(detached);
            }
            *self
                .state_mut(slot)
                .expect("the copied live client keeps its private slot") =
                PreparedOwnerExitClientState::TransferredToExit(detached);
            entry += 1;
        }
        if has_overflow {
            let metadata_config = self.metadata_config;
            let clients = core::mem::replace(self, Self::new(metadata_config));
            Ok(DetachedOwnerExitClientLedger::from_session(clients))
        } else {
            Ok(DetachedOwnerExitClientLedger::from_inline_entries(inline_entries))
        }
    }

    /// Transfers every live session client and, when requested by the one
    /// source-valid B/C/D witness, separates three prevalidated opaque entries
    /// into the scoped post-exit publication group. The keys are validated
    /// before the linear registry moves, so a stale, duplicate, freed, or
    /// pre-exit-published selection leaves the parked session recoverable.
    fn transfer_all_live_with_final_member_adoption_and_post_exit_remote_publication_group(
        &mut self,
        post_exit_remote_publication_group: Option<DetachedOwnerExitRemotePublicationSelection>,
        has_pre_exit_owner_exit_collectable_local_free: impl FnMut(&PreparedOwnerExitClient) -> bool,
    ) -> Result<
        (
            DetachedOwnerExitClientLedger,
            Option<DetachedOwnerExitRemotePublicationGroup>,
        ),
        CurrentThreadPageOwnerPreparationError,
    > {
        if let Some(selection) = post_exit_remote_publication_group {
            let [direct, first_published, second_published] = selection.clients;
            if direct == first_published
                || direct == second_published
                || first_published == second_published
            {
                return Err(CurrentThreadPageOwnerPreparationError::DuplicateClient);
            }
            self.validate_live_key(direct)?;
            self.validate_live_key(first_published)?;
            self.validate_live_key(second_published)?;
        }

        let mut clients = self
            .transfer_all_live_with_final_member_adoption(
                has_pre_exit_owner_exit_collectable_local_free,
            )?;
        let post_exit_remote_publication_group =
            post_exit_remote_publication_group.map(|selection| {
            clients
                .take_remote_publication_group(selection)
                .expect("the prevalidated live publication group remains in the just-transferred ledger")
        });
        Ok((clients, post_exit_remote_publication_group))
    }

    fn free_client(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        client: PreparedOwnerExitClient,
    ) -> Result<(), ()> {
        self.validate_live(&client).map_err(|_| ())?;
        // SAFETY: the registry proves this exact allocation is still local to
        // the active A-side engine and has not crossed a producer or route.
        unsafe { allocator.free(client.block) }.map_err(|_| ())?;
        *self
            .state_mut(client.slot)
            .expect("the validated local client keeps its private slot") =
            PreparedOwnerExitClientState::Freed;
        Ok(())
    }

    /// Reconstructs the private linear client for one exact C-facing address
    /// while the current session still owns it. The raw address enters only at
    /// the libc friend boundary; it is not an iterable or cross-thread
    /// registry surface.
    fn native_client_for_block(
        &self,
        block: core::ptr::NonNull<u8>,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerPreparationError> {
        for slot in 0..self.slot_count() {
            let state = self
                .state(slot)
                .expect("the private ledger range has a matching slot");
            let PreparedOwnerExitClientState::Live {
                generation,
                block: current,
                usable_size,
                normal_request,
            } = *state
            else {
                continue;
            };
            if current == block {
                return Ok(PreparedOwnerExitClient {
                    slot,
                    generation,
                    block,
                    usable_size,
                    normal_request,
                });
            }
        }
        Err(CurrentThreadPageOwnerPreparationError::UnknownClient)
    }

    /// Returns one exact live C client's source-recorded usable extent
    /// without resuming its owner engine. The only foreign caller is the
    /// bounded parked-A read-only route, which holds its registry publication
    /// exclusively while it proves this address; it never receives the
    /// client capability, a page, or a PageMap lease.
    fn recorded_native_usable_size(
        &self,
        block: core::ptr::NonNull<u8>,
    ) -> Result<usize, CurrentThreadPageOwnerPreparationError> {
        let client = self.native_client_for_block(block)?;
        self.validate_live(&client)?;
        Ok(client.usable_size)
    }

    /// Frees one exact C-facing local client after the native shadow has
    /// reconstructed its private ledger capability.
    fn free_native_block(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        block: core::ptr::NonNull<u8>,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        let client = self.native_client_for_block(block)?;
        self.free_client(allocator, client)
            .map_err(|_| CurrentThreadPageOwnerPreparationError::LocalFree)
    }

    /// Reallocates one exact local C-facing client and replaces the private
    /// ledger address only after the source engine has returned a current
    /// replacement. A failed replacement leaves the old ledger entry live.
    fn reallocate_native_block(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        block: core::ptr::NonNull<u8>,
        new_size: usize,
    ) -> Result<core::ptr::NonNull<u8>, CurrentThreadPageOwnerPreparationError> {
        let client = self.native_client_for_block(block)?;
        // SAFETY: `native_client_for_block` proved the exact block is live,
        // local, and not transferred; this current operation owns the sole
        // resumed source engine.
        let Some(replacement) = (unsafe { allocator.reallocate(Some(block), new_size) }) else {
            return Err(CurrentThreadPageOwnerPreparationError::AllocationFailed);
        };
        // SAFETY: successful reallocation returns the exact current
        // replacement while this source operation still owns the engine.
        let usable_size = unsafe { allocator.usable_size(replacement) }
            .expect("a freshly reallocated owner-session block has a usable extent");
        self.validate_live(&client)?;
        *self
            .state_mut(client.slot)
            .expect("the validated reallocation client keeps its private slot") =
            PreparedOwnerExitClientState::Live {
            generation: client.generation,
            block: replacement,
            usable_size,
            // `realloc` returns a normally aligned C allocation even when
            // the previous pointer entered through an aligned API. Do not
            // carry an old over-aligned final-member classification forward.
            normal_request: Some(new_size),
        };
        Ok(replacement)
    }

    /// Queries one exact local C-facing client while the runtime has resumed
    /// its owner engine. An untracked, transferred, or foreign address has no
    /// usable native extent.
    fn native_usable_size(
        &self,
        allocator: &MainHeapThreadProcessPageAllocator<'_, '_>,
        block: core::ptr::NonNull<u8>,
    ) -> Result<usize, CurrentThreadPageOwnerPreparationError> {
        let client = self.native_client_for_block(block)?;
        self.validate_live(&client)?;
        // SAFETY: the ledger proves this exact block is current in the
        // exclusive resumed engine and no producer can exist for this route.
        unsafe { allocator.usable_size(block) }
            .ok_or(CurrentThreadPageOwnerPreparationError::UnknownClient)
    }

    fn current_allocation_page_reserved(
        &self,
        allocator: &MainHeapThreadProcessPageAllocator<'_, '_>,
        client: &PreparedOwnerExitClient,
    ) -> Option<usize> {
        self.validate_live(client).ok()?;
        // SAFETY: registry validation proves this exact block is current in
        // the exclusive source engine; callers use this only outside a
        // scoped remote producer.
        unsafe { allocator.current_allocation_page_reserved(client.block) }
    }

    fn mark_published_before_exit(
        &mut self,
        client: &PreparedOwnerExitClient,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        self.validate_live(client)?;
        *self
            .state_mut(client.slot)
            .expect("the validated publication client keeps its private slot") =
            PreparedOwnerExitClientState::PublishedBeforeExit;
        Ok(())
    }

    /// Marks one exact C-facing client after B has successfully published it
    /// to A's live source remote head. This stays distinct from the older
    /// joined-before-exit state because A must remain able to resume, collect,
    /// and allocate before it begins any owner-exit transition.
    fn mark_published_to_live_owner(
        &mut self,
        client: &PreparedOwnerExitClient,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        self.validate_live(client)?;
        *self
            .state_mut(client.slot)
            .expect("the validated live publication client keeps its private slot") =
            PreparedOwnerExitClientState::PublishedToLiveOwner;
        Ok(())
    }

    /// Publishes one joined source remote free from an active TLS session.
    ///
    /// This is the same `RemoteFreeProducer` source primitive as the paired
    /// live-owner witness, but it deliberately has one producer and one
    /// ledger transition. It admits the source-valid one-client all-free
    /// drain without turning the session into a general concurrent-free API.
    fn publish_remote_free(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        client: PreparedOwnerExitClient,
        publish: TicketZeroSingleRemoteFreePublisher,
    ) -> Result<(), PreparedOwnerExitRemoteFreeFailure> {
        if self.has_published_before_exit() {
            return Err(PreparedOwnerExitRemoteFreeFailure {
                client,
                error: CurrentThreadPageOwnerPreparationError::Closed,
            });
        }
        if let Err(error) = self.validate_live(&client) {
            return Err(PreparedOwnerExitRemoteFreeFailure { client, error });
        }

        let producer = match unsafe { allocator.begin_remote_free(client.block) } {
            Ok(producer) => TicketZeroRemoteFreeProducer { producer },
            Err(_) => {
                return Err(PreparedOwnerExitRemoteFreeFailure {
                    client,
                    error: CurrentThreadPageOwnerPreparationError::RemotePreparation,
                });
            }
        };
        if let Err(producer) = publish(producer) {
            let returned = producer.cancel();
            // The source token is a linear handoff. If cancellation did not
            // recover its exact client, no local ledger or route can safely
            // describe the remaining ownership, so retain terminally.
            if returned != client.block {
                return Err(PreparedOwnerExitRemoteFreeFailure {
                    client,
                    error: CurrentThreadPageOwnerPreparationError::RemotePublication,
                });
            }
            return Err(PreparedOwnerExitRemoteFreeFailure {
                client,
                error: CurrentThreadPageOwnerPreparationError::RemotePublication,
            });
        }
        self.mark_published_before_exit(&client)
            .expect("the joined producer leaves its validated client live until publication completes");
        Ok(())
    }

    fn publish_remote_free_pair(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
        first: PreparedOwnerExitClient,
        second: PreparedOwnerExitClient,
        publish: TicketZeroRemoteFreePublisher,
    ) -> Result<(), PreparedOwnerExitRemotePairFailure> {
        let validate = || {
            if self.has_published_before_exit() || first.slot == second.slot {
                return Err(CurrentThreadPageOwnerPreparationError::Closed);
            }
            self.validate_live(&first)?;
            self.validate_live(&second)?;
            Ok(())
        };
        if let Err(error) = validate() {
            return Err(PreparedOwnerExitRemotePairFailure {
                first,
                second,
                error,
            });
        }

        let producers = match unsafe { allocator.begin_remote_free_pair(first.block, second.block) } {
            Ok(producers) => TicketZeroRemoteFreeProducerPair { producers },
            Err(_) => {
                return Err(PreparedOwnerExitRemotePairFailure {
                    first,
                    second,
                    error: CurrentThreadPageOwnerPreparationError::RemotePreparation,
                });
            }
        };
        if let Err(producers) = publish(producers) {
            let (returned_first, returned_second) = producers.cancel();
            if returned_first != first.block || returned_second != second.block {
                // The source pair promises exact cancellation. A violated
                // promise cannot be represented as a local client or a route,
                // so keep the owner terminal rather than guessing which block
                // remains live.
                return Err(PreparedOwnerExitRemotePairFailure {
                    first,
                    second,
                    error: CurrentThreadPageOwnerPreparationError::RemotePublication,
                });
            }
            return Err(PreparedOwnerExitRemotePairFailure {
                first,
                second,
                error: CurrentThreadPageOwnerPreparationError::RemotePublication,
            });
        }
        self.mark_published_before_exit(&first)
            .expect("the joined first producer leaves its validated client live until publication completes");
        self.mark_published_before_exit(&second)
            .expect("the joined second producer leaves its validated client live until publication completes");
        Ok(())
    }

    fn has_published_before_exit(&self) -> bool {
        self.any_state(|state| {
            matches!(state, PreparedOwnerExitClientState::PublishedBeforeExit)
        })
    }

    fn has_live_client(&self) -> bool {
        self.any_state(|state| matches!(state, PreparedOwnerExitClientState::Live { .. }))
    }

    /// Whether this active session can enter the all-free source thread-exit
    /// drain.
    ///
    /// A locally freed client has no remaining source ownership. A joined
    /// pre-exit publication remains on the source remote head, which
    /// `_mi_theap_collect_abandon` force-collects before it tests
    /// `mi_page_all_free`; it can therefore enter the same typed drain after
    /// its publisher has joined. A live or transferred client instead still
    /// requires its own typed owner-exit disposition.
    #[inline]
    fn can_enter_all_free_thread_exit_drain(&self) -> bool {
        self.all_states(|state| {
            matches!(
                state,
                PreparedOwnerExitClientState::Vacant
                    | PreparedOwnerExitClientState::Freed
                    | PreparedOwnerExitClientState::PublishedBeforeExit
                    | PreparedOwnerExitClientState::PublishedToLiveOwner
            )
        })
    }

    fn free_untransferred_locals(
        &mut self,
        allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    ) -> Result<(), ()> {
        for slot in 0..self.slot_count() {
            let PreparedOwnerExitClientState::Live { block, .. } = *self
                .state(slot)
                .expect("the private ledger range has a matching slot")
            else {
                continue;
            };
            // SAFETY: every `Live` registry member remains local to the
            // active preparation; no post-exit route or remote producer can
            // name it.
            unsafe { allocator.free(block) }.map_err(|_| ())?;
            *self
                .state_mut(slot)
                .expect("the local client keeps its private slot") =
                PreparedOwnerExitClientState::Freed;
        }
        Ok(())
    }
}

/// Why preparation did not yield a complete typed route.  These values stay
/// private to the runtime boundary; callers receive only the existing
/// installation result and no client pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentThreadPageOwnerPreparationError {
    AllocationFailed,
    OverCapacity,
    Closed,
    UnknownClient,
    DuplicateClient,
    OmittedClient,
    LocalFree,
    RemotePreparation,
    RemotePublication,
}

/// A recoverable returned client after an attempted one-client joined
/// publication. The source handoff either publishes the exact client or
/// cancels it back to the same active owner, allowing a caller that owns a
/// recovery policy to retain or locally free it without guessing identity.
struct PreparedOwnerExitRemoteFreeFailure {
    client: PreparedOwnerExitClient,
    error: CurrentThreadPageOwnerPreparationError,
}

impl PreparedOwnerExitRemoteFreeFailure {
    #[inline]
    fn into_parts(
        self,
    ) -> (
        PreparedOwnerExitClient,
        CurrentThreadPageOwnerPreparationError,
    ) {
        (self.client, self.error)
    }
}

/// A recoverable returned pair of linear clients after an attempted joined
/// pre-exit publication.  Source preparation keeps the same two clients
/// local when C did not publish, so the failure path can cleanly free them
/// before the engine finishes rather than suspending a half-described route.
struct PreparedOwnerExitRemotePairFailure {
    first: PreparedOwnerExitClient,
    second: PreparedOwnerExitClient,
    error: CurrentThreadPageOwnerPreparationError,
}

impl PreparedOwnerExitRemotePairFailure {
    #[inline]
    fn into_parts(
        self,
    ) -> (
        PreparedOwnerExitClient,
        PreparedOwnerExitClient,
        CurrentThreadPageOwnerPreparationError,
    ) {
        (self.first, self.second, self.error)
    }
}

/// A current-thread-only ordinary page-owner session.  The parked token is
/// absent only while one private handle has resumed it into a complete
/// operation; every successful operation restores it before returning to the
/// caller. The client ledger is the durable boundary across that park/resume
/// split, never a public pointer registry.
#[must_use = "an active page-owner session must prepare typed exit, enter its all-free drain, or remain terminally retained"]
struct CurrentThreadPageOwnerSession {
    parked: Option<RuntimeParkedPersistentPageEngine>,
    clients: PreparedOwnerExitClients,
    generation: usize,
    /// A C-facing native allocation has made this parked owner eligible for
    /// the source-shaped B-side remote publication route. Its metadata-backed
    /// registry entry stores this session's slot/generation only; it never
    /// receives a client address or a page capability.
    native_live_remote: bool,
    /// A native live-owner route stays `BUSY` while its A session is
    /// temporarily out of compiler TLS for one ordinary operation.  Keeping
    /// this guard beside the moved session reserves this exact registry entry
    /// through the brief interval between A's resume and re-park. Other
    /// parked A sessions retain independently published entries; parked TLS
    /// sessions hold `None` and are instead reachable through their own
    /// `ACTIVE` entry.
    native_live_remote_reservation: Option<NativeLiveRemoteOwnerGuard>,
}

impl CurrentThreadPageOwnerSession {
    /// Resolves a temporarily reserved native route as terminal before this
    /// session becomes a retained diagnostic owner.  A retained session may
    /// still keep its parked engine, but no later B may spin forever on a
    /// `BUSY` raw-TLS publication.
    fn retain_native_live_remote_reservation(&mut self) {
        if let Some(route) = self.native_live_remote_reservation.take() {
            route.retain();
        }
    }

    /// Takes A's live-owner reservation while it crosses into a prepared
    /// source exit. A native deferred caller keeps this guard `BUSY` until it
    /// has Release-published the replacement post-exit route; an ordinary
    /// source-only caller consumes it immediately because no C pointer route
    /// follows that exit.
    fn take_native_live_remote_reservation_for_exit(
        &mut self,
    ) -> Result<Option<NativeLiveRemoteOwnerGuard>, ()> {
        match (
            self.native_live_remote,
            self.native_live_remote_reservation.take(),
        ) {
            (false, None) => Ok(None),
            (true, Some(route)) => {
                let owner = route.owner();
                let slot = current_thread_slot_pointer();
                if owner.slot == slot && owner.generation == self.generation {
                    // The session is about to leave compiler TLS. Its
                    // reservation stays BUSY in the returned opaque guard,
                    // so no B can borrow the old TLS image during the route
                    // handoff.
                    self.native_live_remote = false;
                    Ok(Some(route))
                } else {
                    // Preserve the raw identity only in the terminal
                    // registry state. Reconstructing it from an ambiguous
                    // TLS slot could let a future B borrow the wrong owner.
                    route.retain();
                    Err(())
                }
            }
            (_, Some(route)) => {
                route.retain();
                Err(())
            }
            (true, None) => {
                RUNTIME_PROCESS.retain_page_owner();
                Err(())
            }
        }
    }

    /// Consumes a live-owner publication for a source-only prepared exit.
    /// Native deferred exits instead carry the returned guard in
    /// [`ThreadLifecyclePreparedPageOwner`] until their post-exit registry
    /// publication establishes the replacement route.
    fn remove_native_live_remote_reservation_for_exit(&mut self) -> Result<(), ()> {
        let Some(route) = self.take_native_live_remote_reservation_for_exit()? else {
            return Ok(());
        };
        let _ = route.remove();
        Ok(())
    }
}

/// One non-transferable private capability for the current TLS session.  It
/// contains neither a raw allocation address nor a page/process capability;
/// every operation looks up the matching session again in this thread's TLS.
#[must_use = "a current-thread page-owner session handle must prepare typed exit, leave its owner for all-free finish, or retain it"]
struct CurrentThreadPageOwnerSessionHandle {
    generation: usize,
    _current_thread_only: PhantomData<*mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentThreadPageOwnerSessionError {
    /// The current TLS image has no active session for this operation.
    Unavailable,
    /// Another bounded native page operation temporarily owns the serialized
    /// runtime/PageMap transition. The current session remains parked and may
    /// retry without changing its client ledger or lifecycle ownership.
    Busy,
    /// A consumed or stale private handle cannot name the current session.
    Stale,
    /// The exact source operation was rejected before it changed the parked
    /// session. The caller may retain or retry through its same handle.
    Preparation(CurrentThreadPageOwnerPreparationError),
    /// A lower lifecycle transition became terminal. No ordinary no-page
    /// finalizer may cross this state.
    Retained,
}

enum CurrentThreadPageOwnerSessionRemotePairFailure {
    Preparation(PreparedOwnerExitRemotePairFailure),
    Session(CurrentThreadPageOwnerSessionError),
}

enum CurrentThreadPageOwnerSessionRemoteFreeFailure {
    Preparation(PreparedOwnerExitRemoteFreeFailure),
    Session(CurrentThreadPageOwnerSessionError),
}

/// Failure of one exact source remote publication attempted while B retains
/// its own parked native session. The source publication error is distinct
/// from B's session transition: both remain private runtime facts, and the C
/// boundary retains the matched A route on either failure instead of treating
/// it as a foreign pointer or reopening either session.
enum CurrentThreadPageOwnerSessionLiveRemotePublicationFailure {
    Publication(crate::single_thread::RemoteFreePreparationError),
    Session(CurrentThreadPageOwnerSessionError),
}

/// The one stable choice made before a parked session is suspended into its
/// source owner-exit state. It names authority, not a page geometry: the
/// normal test seam transfers the route to its higher-ranked consumer, while
/// the native libc seam transfers the same opaque ledger to the bounded
/// post-exit scheduler.
enum CurrentThreadPageOwnerExitConsumer {
    Callback(TicketZeroOwnerExitFreeConsumer),
    NativeDeferred,
}

fn take_current_thread_page_owner_session(
    generation: usize,
) -> Result<CurrentThreadPageOwnerSession, CurrentThreadPageOwnerSessionError> {
    take_current_thread_page_owner_session_with_held_live_remote_owner(generation, None)
}

/// Takes B's own session while B holds an exact foreign A route. The held
/// route stays opaque and busy throughout the take; it merely prevents the
/// registry scan from recursively claiming the same foreign entry.
fn take_current_thread_page_owner_session_while_holding_live_remote_owner(
    generation: usize,
    held_route: &NativeLiveRemoteOwnerGuard,
) -> Result<CurrentThreadPageOwnerSession, CurrentThreadPageOwnerSessionError> {
    take_current_thread_page_owner_session_with_held_live_remote_owner(generation, Some(held_route))
}

fn take_current_thread_page_owner_session_with_held_live_remote_owner(
    generation: usize,
    held_route: Option<&NativeLiveRemoteOwnerGuard>,
) -> Result<CurrentThreadPageOwnerSession, CurrentThreadPageOwnerSessionError> {
    let slot_pointer = current_thread_slot_pointer();
    // Claim this slot's registry handoff *before* inspecting compiler TLS. A B-side
    // free owns a mutable reference to A's ledger while this state is BUSY;
    // even a generation read must therefore wait for it to resolve.
    let native_route_claim = match held_route {
        Some(route) => NATIVE_LIVE_REMOTE_OWNER
            .claim_current_slot_while_holding_live_remote_owner(slot_pointer, route),
        None => NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot_pointer),
    };
    let native_route = match native_route_claim {
        // Keep the exact raw-TLS handoff BUSY while the session is out of its
        // slot.  It becomes an active publication again only after the full
        // session image is restored, closing the A-resume/B-install race.
        NativeLiveRemoteOwnerCurrentClaim::Claimed(route) => Some(route),
        NativeLiveRemoteOwnerCurrentClaim::Empty | NativeLiveRemoteOwnerCurrentClaim::Foreign => {
            None
        }
        NativeLiveRemoteOwnerCurrentClaim::Busy => {
            // The held-route scanner never waits on a second raw-TLS entry:
            // its caller must restore the first route before this worker
            // retries its own session claim.
            return Err(CurrentThreadPageOwnerSessionError::Busy);
        }
        NativeLiveRemoteOwnerCurrentClaim::Retained => {
            // SAFETY: a retained registry entry has discarded its raw TLS
            // identity, so no B-side reference remains to this slot.
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return Err(CurrentThreadPageOwnerSessionError::Retained);
        }
    };

    // SAFETY: an exact native handoff, if present, remains BUSY in
    // `native_route`; a foreign handoff never names this compiler-TLS slot.
    // No B-side route can retain an alias while A moves its page-owner state
    // out of TLS.
    let slot = unsafe { &mut *slot_pointer.as_ptr() };
    if slot.state != ThreadLifecycleState::Attached {
        if let Some(route) = native_route {
            slot.state = ThreadLifecycleState::Retained;
            route.retain();
            return Err(CurrentThreadPageOwnerSessionError::Retained);
        }
        return Err(CurrentThreadPageOwnerSessionError::Unavailable);
    }
    let Some(owner) = slot.page_owner.take() else {
        if let Some(route) = native_route {
            slot.state = ThreadLifecycleState::Retained;
            route.retain();
            return Err(CurrentThreadPageOwnerSessionError::Retained);
        }
        return Err(CurrentThreadPageOwnerSessionError::Stale);
    };
    match owner {
        ThreadLifecyclePageOwner::Session(mut session) if session.generation == generation => {
            let exact_native_route = native_route.as_ref().is_some_and(|route| {
                let owner = route.owner();
                owner.slot == slot_pointer && owner.generation == generation
            });
            if session.native_live_remote == exact_native_route
                && session.native_live_remote_reservation.is_none()
            {
                session.native_live_remote_reservation = native_route;
                Ok(session)
            } else {
                // The registry entry and the in-TLS session disagree. Keep the
                // exact parked engine terminal instead of manufacturing a
                // second publication or exposing a raw TLS alias.
                slot.page_owner = Some(ThreadLifecyclePageOwner::Session(session));
                slot.state = ThreadLifecycleState::Retained;
                if let Some(route) = native_route {
                    route.retain();
                } else {
                    RUNTIME_PROCESS.retain_page_owner();
                }
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
        }
        owner => {
            slot.page_owner = Some(owner);
            if let Some(route) = native_route {
                slot.state = ThreadLifecycleState::Retained;
                route.retain();
                Err(CurrentThreadPageOwnerSessionError::Retained)
            } else {
                Err(CurrentThreadPageOwnerSessionError::Stale)
            }
        }
    }
}

fn restore_current_thread_page_owner_session(mut session: CurrentThreadPageOwnerSession) {
    let slot_pointer = current_thread_slot_pointer();
    let native_route = session.native_live_remote_reservation.take();
    let native_route_matches = match (session.native_live_remote, native_route.as_ref()) {
        (false, None) => true,
        (true, Some(route)) => {
            let owner = route.owner();
            owner.slot == slot_pointer && owner.generation == session.generation
        }
        _ => false,
    };
    // SAFETY: A owns its current TLS session while it restores the parked
    // engine. A matching native route remains BUSY until the complete session
    // image is back in TLS, so B cannot install or borrow another owner in
    // this restoration interval.
    let slot = unsafe { &mut *slot_pointer.as_ptr() };
    if slot.state == ThreadLifecycleState::Attached
        && slot.page_owner.is_none()
        && native_route_matches
    {
        slot.page_owner = Some(ThreadLifecyclePageOwner::Session(session));
        if let Some(route) = native_route {
            route.restore();
        }
        return;
    }

    // This can arise only from an impossible reentrant/private transition.
    // Do not drop a parked source token into an apparently fresh slot. Resolve
    // a held registry publication terminally so a future B cannot wait on it.
    if let Some(route) = native_route {
        route.retain();
    }
    drop(session);
    slot.state = ThreadLifecycleState::Retained;
    RUNTIME_PROCESS.retain_page_owner();
}

/// Preserves one session only as a terminal diagnostic owner after its native
/// live-owner publication has already been removed. This intentionally does
/// not call the ordinary restore helper: a retained A must not reinstall a
/// raw TLS route that a later B could mistake for a resumable source owner.
fn retain_current_thread_page_owner_session(mut session: CurrentThreadPageOwnerSession) {
    session.retain_native_live_remote_reservation();
    let slot = current_thread_slot();
    if slot.state == ThreadLifecycleState::Attached && slot.page_owner.is_none() {
        slot.page_owner = Some(ThreadLifecyclePageOwner::Session(session));
    } else {
        core::mem::forget(session);
    }
    retain_current_thread_live_page_owner();
}

/// Preserves a moved session as a terminal diagnostic owner without leaving a
/// live-route guard in `BUSY`.  Callers intentionally leak the source engine
/// after an irrecoverable lower transition, but the registry entry must still
/// become explicitly non-routable before that leak.
fn retain_forgotten_current_thread_page_owner_session(mut session: CurrentThreadPageOwnerSession) {
    session.retain_native_live_remote_reservation();
    core::mem::forget(session);
    retain_current_thread_live_page_owner();
}

impl CurrentThreadPageOwnerSessionHandle {
    /// Runs one bounded ordinary operation after resuming the exact parked
    /// source engine, then parks it again before any result becomes visible.
    /// The callback receives the allocator only alongside the private ledger,
    /// so it cannot manufacture an untracked client or retain the engine.
    fn with_active_operation<R>(
        &self,
        operation: impl FnOnce(
            &mut MainHeapThreadProcessPageAllocator<'_, '_>,
            &mut PreparedOwnerExitClients,
        ) -> R,
    ) -> Result<R, CurrentThreadPageOwnerSessionError> {
        self.with_active_operation_while_holding_live_remote_owner(None, operation)
    }

    /// Runs one bounded operation after claiming B's session while B already
    /// holds a distinct A live-owner route. The held route remains the sole
    /// authority over A's ledger; it only excludes its own `BUSY` storage from
    /// B's private current-slot lookup, preventing recursive self-claim.
    fn with_active_operation_while_holding_live_remote_owner<R>(
        &self,
        held_route: Option<&NativeLiveRemoteOwnerGuard>,
        operation: impl FnOnce(
            &mut MainHeapThreadProcessPageAllocator<'_, '_>,
            &mut PreparedOwnerExitClients,
        ) -> R,
    ) -> Result<R, CurrentThreadPageOwnerSessionError> {
        let mut session = match held_route {
            Some(route) => take_current_thread_page_owner_session_while_holding_live_remote_owner(
                self.generation,
                route,
            )?,
            None => take_current_thread_page_owner_session(self.generation)?,
        };
        let parked = session
            .parked
            .take()
            .expect("an active TLS session retains its one parked engine");
        let has_attachment = {
            let slot = current_thread_slot();
            slot.attachment.is_some()
        };
        if !has_attachment {
            session.parked = Some(parked);
            restore_current_thread_page_owner_session(session);
            let slot = current_thread_slot();
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return Err(CurrentThreadPageOwnerSessionError::Retained);
        }
        let resume = {
            let slot = current_thread_slot();
            let attachment = slot
                .attachment
                .as_mut()
                .expect("the checked current session attachment remains present");
            parked.resume(attachment)
        };
        let mut engine = match resume {
            Ok(engine) => engine,
            Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked }) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
                if page_owner_transition_is_retryable(
                    RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire),
                ) {
                    return Err(CurrentThreadPageOwnerSessionError::Busy);
                }
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            Err(RuntimePersistentPageEngineResumeFailure::Rejected {
                parked,
                ..
            }) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy {
                parked,
                ..
            }) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
                return Err(CurrentThreadPageOwnerSessionError::Busy);
            }
            Err(RuntimePersistentPageEngineResumeFailure::Retained { terminal, .. }) => {
                core::mem::forget(terminal);
                retain_forgotten_current_thread_page_owner_session(session);
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
                retain_forgotten_current_thread_page_owner_session(session);
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
        };

        let result = operation(
            engine
                .allocator
                .as_mut()
                .expect("a resumed session retains its ordinary allocator"),
            &mut session.clients,
        );
        match engine.suspend() {
            Ok(parked) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
                Ok(result)
            }
            Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, .. })
            | Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                core::mem::forget(engine);
                retain_forgotten_current_thread_page_owner_session(session);
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
            Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, .. }) => {
                core::mem::forget(terminal);
                retain_forgotten_current_thread_page_owner_session(session);
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
            Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                retain_forgotten_current_thread_page_owner_session(session);
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
        }
    }

    /// Runs one legacy session-local operation through the Phase-A parked
    /// compatibility bridge.
    ///
    /// Ordinary native free/realloc/usable dispatch first projects the inline
    /// persistent owner and reaches this method only when no such owner was
    /// installed (principally the older typed owner-exit fixtures). Keeping
    /// this spelling prevents those continuations from being mistaken for
    /// the owner-local fast path while their pointer-first exit migration is
    /// still incomplete.
    fn with_native_owner_local_operation<R>(
        &self,
        operation: impl FnMut(
            &mut MainHeapThreadProcessPageAllocator<'_, '_>,
            &mut PreparedOwnerExitClients,
        ) -> R,
    ) -> Result<R, CurrentThreadPageOwnerSessionError> {
        self.with_native_parked_compatibility_operation(operation)
    }

    /// Runs one C-facing operation through the temporary parked-session
    /// bridge after any competing native PageMap operation republished its
    /// state.
    ///
    /// This bridge is intentionally not the owner-local operation boundary.
    /// It preserves the existing retry semantics only while a session moves
    /// out of TLS and resumes its parked engine for every call. Persistent
    /// TLD/Theap storage removes this whole bridge from ordinary local calls.
    fn with_native_parked_compatibility_operation<R>(
        &self,
        mut operation: impl FnMut(
            &mut MainHeapThreadProcessPageAllocator<'_, '_>,
            &mut PreparedOwnerExitClients,
        ) -> R,
    ) -> Result<R, CurrentThreadPageOwnerSessionError> {
        #[cfg(feature = "native-runtime-test-audit")]
        NATIVE_PARKED_COMPATIBILITY_OPERATION_COUNT.fetch_add(1, Ordering::AcqRel);
        loop {
            match self.with_active_operation(|allocator, clients| operation(allocator, clients)) {
                Err(CurrentThreadPageOwnerSessionError::Busy) => core::hint::spin_loop(),
                result => return result,
            }
        }
    }

    /// Compatibility spelling for routes that have not yet reached the
    /// owner-local persistent-TLS seam.
    ///
    /// New ordinary local free/realloc callers must use
    /// [`Self::with_native_owner_local_operation`] instead. Existing
    /// allocation and scoped remote-publication routes stay here until their
    /// separate source ownership and pointer-dispatch transitions land.
    #[inline]
    fn with_native_active_operation<R>(
        &self,
        operation: impl FnMut(
            &mut MainHeapThreadProcessPageAllocator<'_, '_>,
            &mut PreparedOwnerExitClients,
        ) -> R,
    ) -> Result<R, CurrentThreadPageOwnerSessionError> {
        self.with_native_parked_compatibility_operation(operation)
    }

    /// Runs one C-facing B operation while the caller holds an exact foreign
    /// A route. A busy current-slot scan returns to the caller instead of
    /// waiting while it retains A: the caller restores A and retries its
    /// exact source lookup with no live-route guard held. Every other
    /// registry entry and scheduler transition keeps its normal ownership
    /// checks.
    fn with_native_active_operation_while_holding_live_remote_owner<R>(
        &self,
        held_route: &NativeLiveRemoteOwnerGuard,
        mut operation: impl FnMut(
            &mut MainHeapThreadProcessPageAllocator<'_, '_>,
            &mut PreparedOwnerExitClients,
        ) -> R,
    ) -> Result<R, CurrentThreadPageOwnerSessionError> {
        self.with_active_operation_while_holding_live_remote_owner(
            Some(held_route),
            |allocator, clients| operation(allocator, clients),
        )
    }

    fn allocate(
        &mut self,
        request: usize,
        zero: bool,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerSessionError> {
        match self.with_active_operation(|allocator, clients| {
            clients.allocate_client(allocator, request, zero)
        }) {
            Ok(result) => result.map_err(CurrentThreadPageOwnerSessionError::Preparation),
            Err(error) => Err(error),
        }
    }

    fn allocate_aligned(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerSessionError> {
        match self.with_active_operation(|allocator, clients| {
            clients.allocate_aligned_client(allocator, request, alignment)
        }) {
            Ok(result) => result.map_err(CurrentThreadPageOwnerSessionError::Preparation),
            Err(error) => Err(error),
        }
    }

    fn free(
        &mut self,
        client: PreparedOwnerExitClient,
    ) -> Result<(), CurrentThreadPageOwnerSessionError> {
        match self.with_active_operation(|allocator, clients| {
            clients.free_client(allocator, client)
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) => Err(CurrentThreadPageOwnerSessionError::Preparation(
                CurrentThreadPageOwnerPreparationError::LocalFree,
            )),
            Err(error) => Err(error),
        }
    }

    /// Records one C-facing local allocation in the current parked worker
    /// session and returns only its raw client address to the libc friend
    /// boundary. The ledger remains the owner-exit authority; this method is
    /// not a general pointer registry or a cross-thread handoff.
    fn native_allocate_aligned(
        &mut self,
        request: usize,
        alignment: usize,
        zero: bool,
    ) -> Result<core::ptr::NonNull<u8>, CurrentThreadPageOwnerSessionError> {
        if alignment <= NATIVE_C_MALLOC_ALIGNMENT {
            // C `malloc`/`calloc` and low-alignment `aligned_alloc` requests
            // all satisfy their ABI through the normal source queue. Preserve
            // that ordinary request in the private ledger so a later
            // aggregate route can prove exact queue geometry; a genuinely
            // over-aligned client remains intentionally ineligible below.
            match self.with_native_active_operation(|allocator, clients| {
                clients.allocate_client(allocator, request, zero)
            }) {
                Ok(result) => result
                    .map(|client| client.block)
                    .map_err(CurrentThreadPageOwnerSessionError::Preparation),
                Err(error) => Err(error),
            }
        } else if zero {
            match self.with_native_active_operation(|allocator, clients| {
                clients.allocate_aligned_zeroed_client(allocator, request, alignment)
            }) {
                Ok(result) => result
                    .map(|client| client.block)
                    .map_err(CurrentThreadPageOwnerSessionError::Preparation),
                Err(error) => Err(error),
            }
        } else {
            match self.with_native_active_operation(|allocator, clients| {
                clients.allocate_aligned_client(allocator, request, alignment)
            }) {
                Ok(result) => result
                    .map(|client| client.block)
                    .map_err(CurrentThreadPageOwnerSessionError::Preparation),
                Err(error) => Err(error),
            }
        }
    }

    /// Publishes this parked session as one native C live-owner source route
    /// after a successful C-facing allocation has been recorded in its private
    /// ledger. Its metadata-backed entry carries only this TLS slot and
    /// generation; B must still prove an exact address against that ledger.
    fn enable_native_live_remote(&self) -> Result<(), CurrentThreadPageOwnerSessionError> {
        let slot_pointer = current_thread_slot_pointer();
        match NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot_pointer) {
            NativeLiveRemoteOwnerCurrentClaim::Claimed(route) => {
                // SAFETY: the claimed route excludes B from this exact TLS
                // image until it is restored or terminally retained below.
                let valid_existing_publication = unsafe {
                    let slot = &mut *slot_pointer.as_ptr();
                    slot.state == ThreadLifecycleState::Attached
                        && matches!(
                            slot.page_owner.as_ref(),
                            Some(ThreadLifecyclePageOwner::Session(session))
                                if session.generation == self.generation
                                    && session.native_live_remote
                        )
                };
                if valid_existing_publication && route.owner().generation == self.generation {
                    route.restore();
                    return Ok(());
                }

                // A registry entry naming this TLS slot must agree with the
                // parked native session. Discard its raw address on any
                // mismatch rather than trying to repair a half-publication.
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                slot.state = ThreadLifecycleState::Retained;
                route.retain();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
            NativeLiveRemoteOwnerCurrentClaim::Retained => {
                // SAFETY: a retained registry entry has no TLS alias left.
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
            // `claim_current_slot` owns no foreign route and therefore uses
            // the blocking storage claim. Only the held-route variant may
            // return Busy to make its caller release and retry.
            NativeLiveRemoteOwnerCurrentClaim::Busy => {
                unreachable!("an unheld current-slot claim does not return busy")
            }
            NativeLiveRemoteOwnerCurrentClaim::Empty
            | NativeLiveRemoteOwnerCurrentClaim::Foreign => {}
        }

        // SAFETY: the current TLS slot has no B-side alias until its complete
        // native image is Release-published through the registry below.
        let (owner, config) = {
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            if slot.state != ThreadLifecycleState::Attached {
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            let Some(ThreadLifecyclePageOwner::Session(session)) = slot.page_owner.as_mut() else {
                return Err(CurrentThreadPageOwnerSessionError::Stale);
            };
            if session.generation != self.generation {
                return Err(CurrentThreadPageOwnerSessionError::Stale);
            }
            if session.native_live_remote {
                // An in-TLS bit without its exact registry entry would let A
                // and a future B disagree about who may borrow this session.
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
            let Some(config) = session.clients.metadata_config else {
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            };

            // Set the bit before publishing the entry so a B that claims it
            // immediately validates a complete A session image. End this raw
            // TLS borrow before metadata growth, which may wait on a distinct
            // registry append but never exposes this client address.
            session.native_live_remote = true;
            (
                NativeLiveRemoteOwner {
                    slot: slot_pointer,
                    generation: self.generation,
                },
                config,
            )
        };

        match NATIVE_LIVE_REMOTE_OWNER.install(owner, config) {
            NativeLiveRemoteOwnerRegistryInstall::Installed => Ok(()),
            NativeLiveRemoteOwnerRegistryInstall::Unavailable(owner) => {
                // Metadata exhaustion leaves this session safely local-only:
                // no entry was published, its exact clients remain private,
                // and future C frees cannot mistake another A for this one.
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                let Some(ThreadLifecyclePageOwner::Session(session)) = slot.page_owner.as_mut()
                else {
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain_page_owner();
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                };
                if slot.state != ThreadLifecycleState::Attached
                    || owner.slot != slot_pointer
                    || session.generation != owner.generation
                    || !session.native_live_remote
                {
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain_page_owner();
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                session.native_live_remote = false;
                Ok(())
            }
            NativeLiveRemoteOwnerRegistryInstall::Retained(_owner) => {
                // A retained registry entry has already discarded the raw TLS
                // identity that made its source route safe. Do not publish a
                // second route beside that terminal process state.
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
        }
    }

    /// Frees one raw C-facing client after the private ledger has proved that
    /// this exact current session still owns it locally.
    fn native_free(
        &mut self,
        block: core::ptr::NonNull<u8>,
    ) -> Result<(), CurrentThreadPageOwnerSessionError> {
        match self.with_native_owner_local_operation(|allocator, clients| {
            clients.free_native_block(allocator, block)
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(CurrentThreadPageOwnerSessionError::Preparation(error)),
            Err(error) => Err(error),
        }
    }

    /// Publishes one exact A-owned native client while this current B session
    /// is briefly active. The session immediately re-parks before this helper
    /// returns, so B never lends its allocator or client ledger to A's route.
    ///
    /// # Safety
    ///
    /// `block` must be the exact current client already proved against a
    /// separately parked A session whose registry entry remains `BUSY` for
    /// the full call. `held_route` must be that exact foreign A guard; it
    /// keeps the guarded entry private while B claims and resumes its own
    /// older parked session. The caller must mark A's ledger published only
    /// after this source push succeeds.
    unsafe fn native_publish_remote_free_to_parked_live_owner(
        &mut self,
        held_route: &NativeLiveRemoteOwnerGuard,
        block: core::ptr::NonNull<u8>,
    ) -> Result<(), CurrentThreadPageOwnerSessionLiveRemotePublicationFailure> {
        match self.with_native_active_operation_while_holding_live_remote_owner(
            held_route,
            |allocator, _clients| {
                // SAFETY: forwarded unchanged from this helper's exact
                // A-client, matched-route, and parked-owner contract above.
                unsafe { allocator.publish_remote_free_to_parked_live_owner(block) }
            },
        ) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                Err(CurrentThreadPageOwnerSessionLiveRemotePublicationFailure::Publication(error))
            }
            Err(error) => {
                Err(CurrentThreadPageOwnerSessionLiveRemotePublicationFailure::Session(error))
            }
        }
    }

    /// Reallocates one raw C-facing local client and atomically updates the
    /// matching private ledger slot if the source engine returns a replacement.
    fn native_reallocate(
        &mut self,
        block: core::ptr::NonNull<u8>,
        new_size: usize,
    ) -> Result<core::ptr::NonNull<u8>, CurrentThreadPageOwnerSessionError> {
        match self.with_native_owner_local_operation(|allocator, clients| {
            clients.reallocate_native_block(allocator, block, new_size)
        }) {
            Ok(result) => result.map_err(CurrentThreadPageOwnerSessionError::Preparation),
            Err(error) => Err(error),
        }
    }

    /// Queries one raw C-facing local client without exposing its owner or
    /// ledger slot beyond this private session.
    fn native_usable_size(
        &self,
        block: core::ptr::NonNull<u8>,
    ) -> Result<usize, CurrentThreadPageOwnerSessionError> {
        match self.with_native_active_operation(|allocator, clients| {
            clients.native_usable_size(allocator, block)
        }) {
            Ok(result) => result.map_err(CurrentThreadPageOwnerSessionError::Preparation),
            Err(error) => Err(error),
        }
    }

    fn current_allocation_page_reserved(&self, client: &PreparedOwnerExitClient) -> Option<usize> {
        self.with_active_operation(|allocator, clients| {
            clients.current_allocation_page_reserved(allocator, client)
        })
        .ok()
        .flatten()
    }

    fn publish_remote_free(
        &mut self,
        client: PreparedOwnerExitClient,
        publish: TicketZeroSingleRemoteFreePublisher,
    ) -> Result<(), CurrentThreadPageOwnerSessionRemoteFreeFailure> {
        match self.with_active_operation(|allocator, clients| {
            clients.publish_remote_free(allocator, client, publish)
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(failure)) => Err(CurrentThreadPageOwnerSessionRemoteFreeFailure::Preparation(
                failure,
            )),
            Err(error) => Err(CurrentThreadPageOwnerSessionRemoteFreeFailure::Session(error)),
        }
    }

    fn publish_remote_free_pair(
        &mut self,
        first: PreparedOwnerExitClient,
        second: PreparedOwnerExitClient,
        publish: TicketZeroRemoteFreePublisher,
    ) -> Result<(), CurrentThreadPageOwnerSessionRemotePairFailure> {
        match self.with_active_operation(|allocator, clients| {
            clients.publish_remote_free_pair(allocator, first, second, publish)
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(failure)) => Err(CurrentThreadPageOwnerSessionRemotePairFailure::Preparation(
                failure,
            )),
            Err(error) => Err(CurrentThreadPageOwnerSessionRemotePairFailure::Session(error)),
        }
    }

    /// Consumes this active ordinary session into the one general sequential
    /// source owner-exit disposition. The live registry, not a workload or
    /// caller-supplied pointer list, supplies every remaining client. A
    /// source-published pre-exit pair remains outside the post-exit ledger for
    /// the existing collector to consume before A detaches.
    fn prepare_sequential_exit(
        self,
        free_after_exit: TicketZeroOwnerExitFreeConsumer,
    ) -> Result<(), CurrentThreadPageOwnerSessionError> {
        self.prepare_sequential_exit_with_consumer(
            None,
            CurrentThreadPageOwnerExitConsumer::Callback(free_after_exit),
        )
    }

    /// Moves every live native-shadow client into the same typed source exit
    /// route, but defers its private C frees to the runtime-owned post-exit
    /// scheduler. This is the only native path that permits a live page
    /// session to cross pthread teardown; all-free sessions continue through
    /// their existing direct drain.
    fn prepare_native_deferred_exit(self) -> Result<(), CurrentThreadPageOwnerSessionError> {
        self.prepare_sequential_exit_with_consumer(
            None,
            CurrentThreadPageOwnerExitConsumer::NativeDeferred,
        )
    }

    /// Prepares the same generic sequential route while carrying the one
    /// source-valid scoped B/C/D publication group. The group contains only
    /// opaque registry keys selected before suspension; it grants neither a
    /// caller address nor a general post-exit producer route.
    fn prepare_sequential_exit_with_post_exit_remote_publication_group(
        self,
        post_exit_remote_publication_group: DetachedOwnerExitRemotePublicationSelection,
        free_after_exit: TicketZeroOwnerExitFreeConsumer,
    ) -> Result<(), CurrentThreadPageOwnerSessionError> {
        self.prepare_sequential_exit_with_consumer(
            Some(post_exit_remote_publication_group),
            CurrentThreadPageOwnerExitConsumer::Callback(free_after_exit),
        )
    }

    fn prepare_sequential_exit_with_consumer(
        self,
        post_exit_remote_publication_group: Option<DetachedOwnerExitRemotePublicationSelection>,
        consumer: CurrentThreadPageOwnerExitConsumer,
    ) -> Result<(), CurrentThreadPageOwnerSessionError> {
        let native_deferred = matches!(&consumer, CurrentThreadPageOwnerExitConsumer::NativeDeferred);
        let mut session = take_current_thread_page_owner_session(self.generation)?;
        let parked = session
            .parked
            .take()
            .expect("an active TLS session retains its one parked engine");
        let has_attachment = {
            let slot = current_thread_slot();
            slot.attachment.is_some()
        };
        if !has_attachment {
            session.parked = Some(parked);
            restore_current_thread_page_owner_session(session);
            let slot = current_thread_slot();
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return Err(CurrentThreadPageOwnerSessionError::Retained);
        }
        let resume = {
            let slot = current_thread_slot();
            let attachment = slot
                .attachment
                .as_mut()
                .expect("the checked current session attachment remains present");
            parked.resume(attachment)
        };
        let engine = match resume {
            Ok(engine) => engine,
            Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked }) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
                if page_owner_transition_is_retryable(
                    RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire),
                ) {
                    // A concurrent prepared exit owns the complete scheduler
                    // handoff, but this exact session is still parked and
                    // unchanged in TLS. Let the native destructor boundary
                    // retry that typed state instead of relabeling it as an
                    // owner-exit failure before its route exists.
                    return Err(CurrentThreadPageOwnerSessionError::Busy);
                }
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            Err(RuntimePersistentPageEngineResumeFailure::Rejected { parked, .. }) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy { parked, .. }) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
                if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) != PAGE_OWNER_RETAINED
                    && RUNTIME_PROCESS.state.load(Ordering::Acquire) != PROCESS_RETAINED
                {
                    // A detached route may transiently own its short map
                    // access after another A has republished the scheduler.
                    // This parked session has not changed, so its native
                    // owner-exit preparation may retry the map handoff.
                    return Err(CurrentThreadPageOwnerSessionError::Busy);
                }
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            Err(RuntimePersistentPageEngineResumeFailure::Retained { terminal, .. }) => {
                core::mem::forget(terminal);
                retain_forgotten_current_thread_page_owner_session(session);
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
                retain_forgotten_current_thread_page_owner_session(session);
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
        };

        let (clients, post_exit_remote_publication_group) = match {
            let allocator = engine
                .allocator
                .as_ref()
                .expect("a resumed session retains its ordinary allocator");
            session
                .clients
                .transfer_all_live_with_final_member_adoption_and_post_exit_remote_publication_group(
                    post_exit_remote_publication_group,
                    |client| {
                        // SAFETY: the session registry has already validated
                        // the client as live in this exclusive source engine,
                        // and no producer survives into its prepared exit.
                        unsafe {
                            allocator
                                .current_allocation_page_has_owner_exit_collectable_local_free(
                                    client.block,
                                )
                        }
                        .unwrap_or(false)
                    },
                )
        } {
            Ok(clients) => clients,
            Err(error) => match engine.suspend() {
                Ok(parked) => {
                    session.parked = Some(parked);
                    restore_current_thread_page_owner_session(session);
                    return Err(CurrentThreadPageOwnerSessionError::Preparation(error));
                }
                Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, .. })
                | Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation {
                    engine,
                }) => {
                    core::mem::forget(engine);
                    retain_forgotten_current_thread_page_owner_session(session);
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, .. }) => {
                    core::mem::forget(terminal);
                    retain_forgotten_current_thread_page_owner_session(session);
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                    retain_forgotten_current_thread_page_owner_session(session);
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
            },
        };
        let disposition = match consumer {
            CurrentThreadPageOwnerExitConsumer::Callback(free_after_exit) => {
                DetachedOwnerExitDisposition::SequentialFree {
                    free_after_exit,
                    post_exit_remote_publication_group,
                }
            }
            CurrentThreadPageOwnerExitConsumer::NativeDeferred => {
                // The only source-supported B/C/D group is a scoped test seam;
                // a C post-exit route has no such callback and must not carry
                // those three identities into a general pointer dispatcher.
                if post_exit_remote_publication_group.is_some() {
                    core::mem::forget(clients);
                    core::mem::forget(engine);
                    retain_forgotten_current_thread_page_owner_session(session);
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                DetachedOwnerExitDisposition::NativeDeferred
            }
        };
        let exit = DetachedOwnerExit { clients, disposition };

        match engine.suspend() {
            Ok(parked) => {
                let native_live_remote_handoff = if native_deferred {
                    match session.take_native_live_remote_reservation_for_exit() {
                        Ok(Some(handoff)) => Some(handoff),
                        // A native deferred exit is reachable only from the
                        // exact live-owner publication that made its C
                        // clients routable. A missing handoff would expose an
                        // unexplainable raw pointer lifetime.
                        Ok(None) | Err(()) => {
                            drop(parked);
                            core::mem::forget(exit);
                            retain_forgotten_current_thread_page_owner_session(session);
                            return Err(CurrentThreadPageOwnerSessionError::Retained);
                        }
                    }
                } else {
                    if session
                        .remove_native_live_remote_reservation_for_exit()
                        .is_err()
                    {
                        drop(parked);
                        core::mem::forget(exit);
                        retain_forgotten_current_thread_page_owner_session(session);
                        return Err(CurrentThreadPageOwnerSessionError::Retained);
                    }
                    None
                };
                // The old session's parked field is intentionally empty after
                // resume. Dropping it cannot run the parked-token retention
                // path. A native deferred publication remains `BUSY` in the
                // prepared owner until its replacement detached route has
                // published; source-only exits consumed their publication
                // above because no raw C route follows.
                drop(session);
                let slot = current_thread_slot();
                if slot.state != ThreadLifecycleState::Attached || slot.page_owner.is_some() {
                    drop(parked);
                    core::mem::forget(exit);
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain_page_owner();
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
                    ThreadLifecyclePreparedPageOwner {
                        parked,
                        exit,
                        native_live_remote_handoff,
                    },
                ));
                Ok(())
            }
            Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, .. })
            | Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                core::mem::forget(engine);
                core::mem::forget(exit);
                retain_forgotten_current_thread_page_owner_session(session);
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
            Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, .. }) => {
                core::mem::forget(terminal);
                core::mem::forget(exit);
                retain_forgotten_current_thread_page_owner_session(session);
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
            Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                core::mem::forget(exit);
                retain_forgotten_current_thread_page_owner_session(session);
                Err(CurrentThreadPageOwnerSessionError::Retained)
            }
        }
    }
}

/// Starts one private persistent page-owner session for an already attached
/// worker. It immediately parks the engine in compiler TLS, so ordinary
/// session operations must explicitly resume and re-park the same source
/// attachment before returning. This is internal runtime state, not an
/// allocator API or a raw-pointer escape hatch.
fn begin_current_thread_page_owner_session(
) -> Result<CurrentThreadPageOwnerSessionHandle, CurrentThreadPageOwnerSessionError> {
    let slot = current_thread_slot();
    if slot.state != ThreadLifecycleState::Attached || slot.page_owner.is_some() {
        return Err(CurrentThreadPageOwnerSessionError::Unavailable);
    }
    let (parked, metadata_config) = {
        let Some(attachment) = slot.attachment.as_mut() else {
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return Err(CurrentThreadPageOwnerSessionError::Retained);
        };
        let metadata_config = match attachment.memory_config() {
            Ok(config) => config,
            Err(_) => {
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
        };
        let engine = loop {
            match RUNTIME_PROCESS.begin_persistent_later_engine(attachment) {
                Ok(engine) => break engine,
                Err(
                    RuntimePersistentPageEngineBeginError::Unavailable
                    | RuntimePersistentPageEngineBeginError::PageMapBusy,
                )
                    if page_owner_session_begin_is_retryable(
                        RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire),
                    ) =>
                {
                    // A peer may hold the serialized PageMap operation while
                    // it creates or resumes its own ordinary native session.
                    // This first C allocation has no parked session of its
                    // own yet, but the source allocator's concurrent malloc
                    // path must wait for that bounded internal handoff rather
                    // than returning a spurious null to caller code that is
                    // about to establish its normal owner.
                    core::hint::spin_loop();
                }
                Err(
                    RuntimePersistentPageEngineBeginError::Unavailable
                    | RuntimePersistentPageEngineBeginError::PageMapBusy,
                ) => {
                    return Err(CurrentThreadPageOwnerSessionError::Unavailable);
                }
                Err(RuntimePersistentPageEngineBeginError::Attachment(_)) => {
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain_page_owner();
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
            }
        };
        match engine.suspend() {
            Ok(parked) => (parked, metadata_config),
            Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, .. })
            | Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                core::mem::forget(engine);
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
            Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, .. }) => {
                core::mem::forget(terminal);
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
            Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
        }
    };
    let generation = slot.next_page_owner_session_generation();
    slot.page_owner = Some(ThreadLifecyclePageOwner::Session(
        CurrentThreadPageOwnerSession {
            parked: Some(parked),
            clients: PreparedOwnerExitClients::new(Some(metadata_config)),
            generation,
            native_live_remote: false,
            native_live_remote_reservation: None,
        },
    ));
    Ok(CurrentThreadPageOwnerSessionHandle {
        generation,
        _current_thread_only: PhantomData,
    })
}

/// Returns the current worker's existing native-shadow session, optionally
/// creating its first parked page owner. The compiler-TLS slot keeps the
/// engine and its ledger private; this helper exports only a temporary
/// current-thread handle for one C ABI operation.
fn current_thread_native_session_handle(
    create_if_absent: bool,
) -> Result<CurrentThreadPageOwnerSessionHandle, CurrentThreadPageOwnerSessionError> {
    let slot_pointer = current_thread_slot_pointer();
    let existing_generation = match NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot_pointer) {
        NativeLiveRemoteOwnerCurrentClaim::Claimed(route) => {
            // SAFETY: this exact A-side registry handoff remains BUSY while the
            // running thread decides whether it already has a session.
            let matching_native_session = unsafe {
                let slot = &mut *slot_pointer.as_ptr();
                match (slot.state, slot.page_owner.as_ref()) {
                    (
                        ThreadLifecycleState::Attached,
                        Some(ThreadLifecyclePageOwner::Session(session)),
                    ) if session.native_live_remote
                        && session.generation == route.owner().generation =>
                    {
                        Some(session.generation)
                    }
                    _ => None,
                }
            };
            if let Some(generation) = matching_native_session {
                route.restore();
                Some(generation)
            } else {
                // A claimed TLS route without its matching native session is
                // not retryable: B may already have observed the raw owner.
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                slot.state = ThreadLifecycleState::Retained;
                route.retain();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
            }
        }
        NativeLiveRemoteOwnerCurrentClaim::Retained => {
            // SAFETY: retained static state has no raw TLS pointer left.
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return Err(CurrentThreadPageOwnerSessionError::Retained);
        }
        // This caller holds no foreign route, so `claim_current_slot` waits
        // rather than producing the no-wait Busy result.
        NativeLiveRemoteOwnerCurrentClaim::Busy => {
            unreachable!("an unheld current-slot claim does not return busy")
        }
        NativeLiveRemoteOwnerCurrentClaim::Empty
        | NativeLiveRemoteOwnerCurrentClaim::Foreign => {
            // SAFETY: there is no B-side alias to this worker's TLS session.
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            if slot.state != ThreadLifecycleState::Attached {
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            match slot.page_owner.as_ref() {
                Some(ThreadLifecyclePageOwner::Session(session))
                    if !session.native_live_remote =>
                {
                    Some(session.generation)
                }
                Some(ThreadLifecyclePageOwner::Session(_)) => {
                    // A native session without its own active registry entry
                    // cannot safely re-enter ordinary allocator code.
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain_page_owner();
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                Some(ThreadLifecyclePageOwner::PreparedExit(_)) => {
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                None => None,
            }
        }
    };
    if let Some(generation) = existing_generation {
        return Ok(CurrentThreadPageOwnerSessionHandle {
            generation,
            _current_thread_only: PhantomData,
        });
    }
    if !create_if_absent {
        return Err(CurrentThreadPageOwnerSessionError::Unavailable);
    }
    begin_current_thread_page_owner_session()
}

#[inline]
fn native_later_thread_allocation_result(
    result: Result<core::ptr::NonNull<u8>, CurrentThreadPageOwnerSessionError>,
) -> NativePageAllocationResult {
    match result {
        Ok(block) => NativePageAllocationResult::Allocated(block),
        Err(CurrentThreadPageOwnerSessionError::Preparation(
            CurrentThreadPageOwnerPreparationError::AllocationFailed
            | CurrentThreadPageOwnerPreparationError::OverCapacity,
        )) => NativePageAllocationResult::AllocationFailed,
        Err(CurrentThreadPageOwnerSessionError::Retained) => NativePageAllocationResult::Retained,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale
        | CurrentThreadPageOwnerSessionError::Preparation(_)) => {
            NativePageAllocationResult::Unavailable
        }
    }
}

fn native_later_thread_allocate_aligned(
    request: usize,
    alignment: usize,
    zero: bool,
) -> NativePageAllocationResult {
    let result = with_current_thread_native_persistent_allocator(true, |allocator| {
        if alignment <= NATIVE_C_MALLOC_ALIGNMENT {
            allocator.allocate(request, zero)
        } else if zero {
            allocator.allocate_aligned_zeroed(request, alignment)
        } else {
            allocator.allocate_aligned(request, alignment)
        }
    });
    match result {
        Ok(Some(block)) => NativePageAllocationResult::Allocated(block),
        Ok(None) => NativePageAllocationResult::AllocationFailed,
        Err(NativePersistentThreadOwnerAccessError::Retained) => {
            NativePageAllocationResult::Retained
        }
        Err(
            NativePersistentThreadOwnerAccessError::NotInstalled
            | NativePersistentThreadOwnerAccessError::Unavailable,
        ) => NativePageAllocationResult::Unavailable,
    }
}

unsafe fn native_later_thread_reallocate(
    block: core::ptr::NonNull<u8>,
    new_size: usize,
) -> NativePageAllocationResult {
    // SAFETY: forwarded unchanged from the exact-live native realloc
    // boundary. PageMap association is checked before the local engine sees
    // the pointer.
    let persistent = with_current_thread_native_persistent_pointer(block, |allocator| unsafe {
        allocator.reallocate(Some(block), new_size)
    });
    match persistent {
        Ok(Some(Some(replacement))) => NativePageAllocationResult::Allocated(replacement),
        Ok(Some(None)) => NativePageAllocationResult::AllocationFailed,
        Ok(None) => NativePageAllocationResult::Unavailable,
        Err(NativePersistentThreadOwnerAccessError::NotInstalled) => {
            let result = current_thread_native_session_handle(false)
                .and_then(|mut session| session.native_reallocate(block, new_size));
            native_later_thread_allocation_result(result)
        }
        Err(NativePersistentThreadOwnerAccessError::Retained) => {
            NativePageAllocationResult::Retained
        }
        Err(NativePersistentThreadOwnerAccessError::Unavailable) => {
            NativePageAllocationResult::Unavailable
        }
    }
}

unsafe fn native_later_thread_free(block: core::ptr::NonNull<u8>) -> NativePageFreeResult {
    // SAFETY: forwarded unchanged from the exact-live native free boundary.
    // PageMap association is checked before the local engine sees the pointer.
    let persistent = with_current_thread_native_persistent_pointer(block, |allocator| unsafe {
        allocator.free(block)
    });
    match persistent {
        Ok(Some(Ok(()))) => NativePageFreeResult::Freed,
        Ok(Some(Err(_))) => {
            retain_current_thread_native_persistent_owner_for_teardown();
            NativePageFreeResult::Retained
        }
        Ok(None) => NativePageFreeResult::InvalidPointer,
        Err(NativePersistentThreadOwnerAccessError::NotInstalled) => {
            match current_thread_native_session_handle(false)
                .and_then(|mut session| session.native_free(block))
            {
                Ok(()) => NativePageFreeResult::Freed,
                Err(CurrentThreadPageOwnerSessionError::Preparation(
                    CurrentThreadPageOwnerPreparationError::UnknownClient
                    | CurrentThreadPageOwnerPreparationError::DuplicateClient
                    | CurrentThreadPageOwnerPreparationError::LocalFree,
                )) => NativePageFreeResult::InvalidPointer,
                Err(CurrentThreadPageOwnerSessionError::Retained) => {
                    NativePageFreeResult::Retained
                }
                Err(
                    CurrentThreadPageOwnerSessionError::Busy
                    | CurrentThreadPageOwnerSessionError::Unavailable
                    | CurrentThreadPageOwnerSessionError::Stale
                    | CurrentThreadPageOwnerSessionError::Preparation(_),
                ) => NativePageFreeResult::Unavailable,
            }
        }
        Err(NativePersistentThreadOwnerAccessError::Retained) => {
            NativePageFreeResult::Retained
        }
        Err(NativePersistentThreadOwnerAccessError::Unavailable) => {
            NativePageFreeResult::Unavailable
        }
    }
}

/// Result of one B-side attempt to publish a C-shaped free to A's parked
/// native session. This remains private to the libc friend boundary: neither
/// outcome exposes a client, page, PageMap, or owner capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeLiveRemoteFreeResult {
    NotOwned,
    Freed,
    Unavailable,
    Retained,
}

/// Result of attempting the source remote producer path for one allocation
/// still owned by the permanent ticket-zero page engine.
///
/// Unlike the parked-A route below, ticket zero does not lend its engine or
/// scheduler admission to the freeing worker. A current client keeps its page
/// alive, so the worker needs only the exact source page-map lookup,
/// immutable aligned-block recovery, and `mi_free_block_mt` atomic push.
/// The main owner collects that head in its next ordinary operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeTicketZeroRemoteFreeResult {
    NotOwned,
    Freed,
    Unavailable,
    Retained,
}

/// Publishes one exact C pointer to the source remote head of the permanent
/// ticket-zero owner.
///
/// This is the normal `mi_free_nonnull -> mi_free_generic_mt ->
/// mi_free_block_mt` path for a page still owned by the initial thread. It
/// deliberately does not acquire the long `ProcessPageMapMutationLease`: the
/// exact live allocation keeps its page registered, so no registration or
/// unregistration of its page-map slice can overlap this one plain lookup.
/// After the lookup, the producer touches only the page's atomic owner/free
/// fields and the client block's source next word. The initial owner remains
/// free to run ordinary source collection concurrently.
///
/// # Safety
///
/// `block` must be a live exact native-shadow allocation. It may be owned by
/// the ticket-zero page engine or another supported native domain. A pointer
/// not owned by ticket zero returns `NotOwned` without publication; arbitrary
/// invalid C pointers remain outside the same `free` contract as pinned
/// mimalloc.
unsafe fn native_ticket_zero_live_remote_free(
    block: core::ptr::NonNull<u8>,
) -> NativeTicketZeroRemoteFreeResult {
    if current_thread_slot().state != ThreadLifecycleState::Attached {
        return NativeTicketZeroRemoteFreeResult::Unavailable;
    }
    let Some(initial_thread) = RUNTIME_PROCESS.initial_live_thread_identity() else {
        return if RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED {
            NativeTicketZeroRemoteFreeResult::Retained
        } else {
            NativeTicketZeroRemoteFreeResult::Unavailable
        };
    };
    let Some(page_map) = RUNTIME_PROCESS.page_map_for_live_native_allocation() else {
        return if RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED {
            NativeTicketZeroRemoteFreeResult::Retained
        } else {
            NativeTicketZeroRemoteFreeResult::Unavailable
        };
    };

    // SAFETY: this function's exact-live-native-client contract proves that
    // the allocation pins its page and rules out a plain PageMap write for
    // its slice throughout the lookup and source publication below.
    let page = match unsafe { page_map.lookup_page_for_live_client(block) } {
        Ok(Some(page)) => page,
        Ok(None) => return NativeTicketZeroRemoteFreeResult::NotOwned,
        Err(_) => {
            RUNTIME_PROCESS.retain_page_owner();
            return NativeTicketZeroRemoteFreeResult::Retained;
        }
    };

    // SAFETY: the exact live allocation keeps this registered page's metadata
    // initialized and unreused. A different owner is a normal dispatch miss;
    // only the matching ticket-zero identity may enter the atomic producer.
    if !unsafe { Page::is_live_owner_for_thread_at(page, initial_thread) } {
        return NativeTicketZeroRemoteFreeResult::NotOwned;
    }
    // SAFETY: the same live-client proof keeps the page geometry immutable.
    // This reproduces source aligned-pointer recovery without creating a
    // shared `Page` reference beside the initial owner's ordinary mutation.
    let Some(canonical_block) =
        (unsafe { Page::canonical_remote_block_for_live_client_at(page, block) })
    else {
        return NativeTicketZeroRemoteFreeResult::NotOwned;
    };

    // SAFETY: `page` is a live associated ticket-zero page and `block` is its
    // exact current source block. `remote_free::push` reads only the atomic
    // producer state and publishes the block before the initial owner can
    // collect or retire that page.
    // SAFETY: the exact live client pins initialized page metadata through
    // this publication. Only the two atomic producer fields are retained.
    let producer = unsafe { Page::remote_free_producer_state_at(page) };
    match unsafe { remote_free::push(producer, canonical_block) } {
        Ok(()) => NativeTicketZeroRemoteFreeResult::Freed,
        Err(crate::remote_free::RemoteFreeError::UnalignedBlock) => {
            NativeTicketZeroRemoteFreeResult::NotOwned
        }
        Err(_) => {
            RUNTIME_PROCESS.retain_page_owner();
            NativeTicketZeroRemoteFreeResult::Retained
        }
    }
}

/// Publishes one exact C pointer to the source remote head of a separately
/// parked native A session.
///
/// The metadata-backed registry contains no client address. B first proves its
/// raw input against one A's existing private C ledger. A fresh B borrows the
/// runtime pair for one complete non-parkable `PARKED -> BUSY -> PARKED`
/// operation; a B with its own parked session briefly resumes only that
/// session and re-parks it before the source publication returns. Either
/// complete operation serializes the PageMap preflight and atomic source push;
/// A cannot resume until B finishes it, at which point A's normal allocation
/// or page drain collects the remote head. This remains a bounded live-owner
/// route, not a general allocator or foreign-pointer registry.
///
/// # Safety
///
/// `block` must be a live native-shadow allocation. The caller has already
/// established that this B worker is attached and either has no local page
/// owner or one fully parked native session. B may also carry completed
/// post-exit routes: their stable parked tokens and admission proofs remain
/// opaque and independent while this operation resumes only B's session. The
/// latter re-parks before the result is visible. A wrong C pointer is rejected
/// before any source publication; an inconsistent source transition remains
/// terminal.
unsafe fn native_later_thread_live_remote_free(
    block: core::ptr::NonNull<u8>,
) -> NativeLiveRemoteFreeResult {
    loop {
    let (mut route, client) = match NATIVE_LIVE_REMOTE_OWNER.claim_exact_client(block) {
        NativeLiveRemoteOwnerExactClaim::NotOwned => {
            return NativeLiveRemoteFreeResult::NotOwned;
        }
        NativeLiveRemoteOwnerExactClaim::Retained => {
            return NativeLiveRemoteFreeResult::Retained;
        }
        NativeLiveRemoteOwnerExactClaim::Claimed { route, client } => (route, client),
    };

    let parked_local_session = {
        let slot = current_thread_slot();
        if slot.state != ThreadLifecycleState::Attached {
            route.restore();
            return NativeLiveRemoteFreeResult::Unavailable;
        }
        match slot.page_owner.as_ref() {
            None => None,
            Some(ThreadLifecyclePageOwner::Session(session)) if session.parked.is_some() => {
                Some(CurrentThreadPageOwnerSessionHandle {
                    generation: session.generation,
                    _current_thread_only: PhantomData,
                })
            }
            Some(ThreadLifecyclePageOwner::Session(_))
            | Some(ThreadLifecyclePageOwner::PreparedExit(_)) => {
                route.restore();
                return NativeLiveRemoteFreeResult::Unavailable;
            }
        }
    };

    if let Some(mut session) = parked_local_session {
        // SAFETY: B's current session is parked, and `route` keeps the exact
        // A ledger and source engine unavailable until the complete B session
        // operation re-parks. The lower source method receives only A's
        // already-validated client address.
        match unsafe {
            session.native_publish_remote_free_to_parked_live_owner(&route, client.block)
        } {
            Ok(()) => {}
            Err(CurrentThreadPageOwnerSessionLiveRemotePublicationFailure::Publication(error)) => {
                let _ = error;
                route.retain();
                return NativeLiveRemoteFreeResult::Retained;
            }
            Err(CurrentThreadPageOwnerSessionLiveRemotePublicationFailure::Session(
                CurrentThreadPageOwnerSessionError::Busy,
            )) => {
                // B's own session is temporarily borrowed through a second
                // live route. Retaining A while waiting can form an opposite
                // A/B source-transfer cycle, so restore A before retrying
                // the exact lookup. The next iteration revalidates the C
                // input against a still-live A ledger. If source exit has
                // instead Release-published A's post-exit successor, this
                // helper reports `NotOwned` and `native_free` performs that
                // successor lookup outside the live-route retry.
                route.restore();
                core::hint::spin_loop();
                continue;
            }
            Err(CurrentThreadPageOwnerSessionLiveRemotePublicationFailure::Session(error)) => {
                let _ = error;
                route.retain();
                return NativeLiveRemoteFreeResult::Retained;
            }
        }

        // The source push is visible only after B has re-parked its own
        // session. Change A's private ledger now, while `route` still makes
        // A unable to locally free, reallocate, or enter owner exit.
        let marked = match unsafe { route.session_mut() } {
            Some(session) => session.clients.mark_published_to_live_owner(&client).is_ok(),
            None => false,
        };
        if !marked {
            route.retain();
            return NativeLiveRemoteFreeResult::Retained;
        }
        route.restore();
        return NativeLiveRemoteFreeResult::Freed;
    }

    let engine = {
        let slot = current_thread_slot();
        let Some(attachment) = slot.attachment.as_mut() else {
            route.retain();
            return NativeLiveRemoteFreeResult::Retained;
        };
        loop {
            match RUNTIME_PROCESS.begin_interleaving_persistent_later_engine(attachment) {
                Ok(engine) => break engine,
                Err(
                    RuntimePersistentPageEngineBeginError::Unavailable
                    | RuntimePersistentPageEngineBeginError::PageMapBusy,
                ) if page_owner_transition_is_retryable(
                    RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire),
                ) => {
                    // A separately typed session start, resumed engine, or
                    // post-exit exact free owns the bounded scheduler/PageMap
                    // handoff. A's claimed registry entry remains live and
                    // unchanged, so wait for that complete operation instead
                    // of retaining an otherwise replayable C free.
                    core::hint::spin_loop();
                }
                Err(_) => {
                    // The exact registry entry proves A is parked. A failure
                    // other than an ordinary bounded handoff leaves an
                    // ambiguous scheduler/PageMap image rather than a
                    // retryable foreign-free miss.
                    route.retain();
                    return NativeLiveRemoteFreeResult::Retained;
                }
            }
        }
    };
    let mut engine = engine;

    // SAFETY: A's exact ledger entry stays live while `route` is BUSY, and B
    // holds the sole interleaving operation's long PageMap lifecycle. The
    // lower method validates the source page geometry before `mi_free_block_mt`
    // publishes only the canonical block to A's atomic remote head.
    if unsafe { engine.publish_remote_free_to_parked_live_owner(client.block) }.is_err() {
        core::mem::forget(engine);
        route.retain();
        return NativeLiveRemoteFreeResult::Retained;
    }

    // The source push is now visible to A's later collector. Change the
    // private ledger only after that success, so A cannot locally free,
    // reallocate, or transfer this client into a post-exit route.
    let marked = {
        // SAFETY: route still excludes A from its TLS session until this B
        // operation either returns A to PARKED or becomes terminal.
        match unsafe { route.session_mut() } {
            Some(session) => session.clients.mark_published_to_live_owner(&client).is_ok(),
            None => false,
        }
    };
    if !marked {
        core::mem::forget(engine);
        route.retain();
        return NativeLiveRemoteFreeResult::Retained;
    }

    return match engine.finish() {
        Ok(()) => {
            route.restore();
            NativeLiveRemoteFreeResult::Freed
        }
        Err(error) => {
            // The page-map or B attachment may already have crossed a source
            // teardown boundary. Keep both engines terminal rather than
            // returning A to PARKED after its client became remotely owned.
            core::mem::forget(error);
            route.retain();
            NativeLiveRemoteFreeResult::Retained
        }
    };
    }
}

/// Reads the source-recorded extent of one exact C pointer owned by a
/// separately parked native A session.
///
/// This is intentionally narrower than the source `mi_usable_size` page
/// lookup: B scans only private live-owner entries, proves its input against
/// one A ledger, and restores that same entry before returning a scalar. It
/// does not borrow A's page engine, acquire the persistent scheduler, or
/// change the remote-free/admission state. A later `free` still follows the
/// complete source-shaped interleaving above.
///
/// # Safety
///
/// `block` must be a non-null C pointer. The caller must have established
/// that the current B attachment has no page owner or terminal post-exit
/// proof. Unknown and unavailable pointers return `None`; a malformed registry
/// entry is terminally retained rather than exposing A's TLS.
unsafe fn native_later_thread_live_remote_usable_size(
    block: core::ptr::NonNull<u8>,
) -> Option<usize> {
    let slot = current_thread_slot();
    if slot.state != ThreadLifecycleState::Attached
        || slot.page_owner.is_some()
        || slot.has_pending_post_exit_route_completions()
    {
        return None;
    }
    match NATIVE_LIVE_REMOTE_OWNER.usable_size_exact(block) {
        NativeLiveRemoteOwnerUsableSizeResult::Owned(usable_size) => Some(usable_size),
        NativeLiveRemoteOwnerUsableSizeResult::NotOwned
        | NativeLiveRemoteOwnerUsableSizeResult::Retained => None,
    }
}

unsafe fn native_later_thread_usable_size(block: core::ptr::NonNull<u8>) -> Option<usize> {
    // SAFETY: forwarded unchanged from the exact-live native usable-size
    // boundary. PageMap association is checked before the local engine sees
    // the pointer.
    match with_current_thread_native_persistent_pointer(block, |allocator| unsafe {
        allocator.usable_size(block)
    }) {
        Ok(Some(Some(usable_size))) => Some(usable_size),
        Ok(Some(None)) => {
            retain_current_thread_native_persistent_owner_for_teardown();
            None
        }
        Ok(None) => None,
        Err(NativePersistentThreadOwnerAccessError::NotInstalled) => {
            current_thread_native_session_handle(false)
                .and_then(|session| session.native_usable_size(block))
                .ok()
        }
        Err(NativePersistentThreadOwnerAccessError::Unavailable) => None,
        Err(NativePersistentThreadOwnerAccessError::Retained) => None,
    }
}

/// Returns whether this attached worker can make one pointer-private native
/// post-exit route operation.
///
/// A fresh B has no page owner. A B that established its own native session
/// before seeing A's pointer is also admissible, but only while that session
/// is parked: the route's short PageMap operation then serializes with B's
/// future long engine operation through the existing scheduler. A prepared
/// exit has already consumed B's source clients into another typed route, so
/// it cannot advance an A route. A completed A route remains opaque and live
/// in the registry until B finishes, but B may continue to consume a distinct
/// still-active route through the same bounded pointer-private dispatcher.
#[inline]
fn current_thread_can_access_native_post_exit_route() -> bool {
    let slot = current_thread_slot();
    if slot.state != ThreadLifecycleState::Attached {
        return false;
    }
    match slot.page_owner.as_ref() {
        None => true,
        Some(ThreadLifecyclePageOwner::Session(session)) => session.parked.is_some(),
        Some(ThreadLifecyclePageOwner::PreparedExit(_)) => false,
    }
}

impl OwnerExitClientAllocator for CurrentThreadPageOwnerSessionHandle {
    type Client = PreparedOwnerExitClient;
    type AllocationError = CurrentThreadPageOwnerSessionError;

    #[inline]
    fn allocate_client(
        &mut self,
        request: usize,
        zero: bool,
    ) -> Result<Self::Client, Self::AllocationError> {
        self.allocate(request, zero)
    }

    #[inline]
    fn allocate_aligned_client(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<Self::Client, Self::AllocationError> {
        self.allocate_aligned(request, alignment)
    }

    #[inline]
    fn free_client(&mut self, client: Self::Client) -> Result<(), ()> {
        self.free(client).map_err(|_| ())
    }

    #[inline]
    fn current_allocation_page_reserved_client(&self, client: &Self::Client) -> Option<usize> {
        self.current_allocation_page_reserved(client)
    }
}

/// The only allocator surface available while a current thread prepares a
/// page-bearing TLS owner. It owns the linear client registry alongside the
/// live engine borrow, so a closure cannot manufacture a raw post-exit block
/// list or hide an ordinary allocation from the eventual typed route.
struct CurrentThreadPageOwnerPreparation<'allocator, 'attachment, 'main> {
    allocator: &'allocator mut MainHeapThreadProcessPageAllocator<'attachment, 'main>,
    clients: PreparedOwnerExitClients,
    exit: Option<DetachedOwnerExit>,
}

impl<'allocator, 'attachment, 'main>
    CurrentThreadPageOwnerPreparation<'allocator, 'attachment, 'main>
{
    #[inline]
    fn new(
        allocator: &'allocator mut MainHeapThreadProcessPageAllocator<'attachment, 'main>,
        metadata_config: MemoryConfig,
    ) -> Self {
        Self {
            allocator,
            clients: PreparedOwnerExitClients::new(Some(metadata_config)),
            exit: None,
        }
    }

    fn allocate(
        &mut self,
        request: usize,
        zero: bool,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerPreparationError> {
        if self.exit.is_some() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        self.clients.allocate_client(self.allocator, request, zero)
    }

    fn allocate_aligned(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<PreparedOwnerExitClient, CurrentThreadPageOwnerPreparationError> {
        if self.exit.is_some() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        self.clients
            .allocate_aligned_client(self.allocator, request, alignment)
    }

    fn free(
        &mut self,
        client: PreparedOwnerExitClient,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        if self.exit.is_some() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        self.clients
            .free_client(self.allocator, client)
            .map_err(|_| CurrentThreadPageOwnerPreparationError::LocalFree)
    }

    fn current_allocation_page_reserved(
        &self,
        client: &PreparedOwnerExitClient,
    ) -> Option<usize> {
        self.clients
            .current_allocation_page_reserved(self.allocator, client)
    }

    fn publish_remote_free_pair(
        &mut self,
        first: PreparedOwnerExitClient,
        second: PreparedOwnerExitClient,
        publish: TicketZeroRemoteFreePublisher,
    ) -> Result<(), PreparedOwnerExitRemotePairFailure> {
        if self.exit.is_some() {
            return Err(PreparedOwnerExitRemotePairFailure {
                first,
                second,
                error: CurrentThreadPageOwnerPreparationError::Closed,
            });
        }
        self.clients
            .publish_remote_free_pair(self.allocator, first, second, publish)
    }

    /// Transfers an arbitrary complete set of A-side live clients into the
    /// general sequential post-exit disposition. The caller supplies only
    /// linear capabilities; this preparation validates that they account for
    /// every live registry entry before the engine can suspend.
    fn finish_sequential(
        &mut self,
        clients: &mut [Option<PreparedOwnerExitClient>],
        post_exit_remote_publication_group: Option<DetachedOwnerExitRemotePublicationSelection>,
        free_after_exit: TicketZeroOwnerExitFreeConsumer,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        if self.exit.is_some() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        let allocator = &*self.allocator;
        let mut clients = self
            .clients
            .transfer_clients_with_final_member_adoption(clients, |client| {
                // SAFETY: this preparation validated the exact live client
                // while its source allocator still owns the exclusive page
                // lifecycle. A failed observation remains sequential-only.
                unsafe {
                    allocator.current_allocation_page_has_owner_exit_collectable_local_free(
                        client.block,
                    )
                }
                .unwrap_or(false)
            })?;
        let post_exit_remote_publication_group = match post_exit_remote_publication_group {
            Some(selection) => {
                let [direct, first_published, second_published] = selection.clients;
                if direct == first_published
                    || direct == second_published
                    || first_published == second_published
                {
                    return Err(CurrentThreadPageOwnerPreparationError::DuplicateClient);
                }
                Some(
                    clients
                        .take_remote_publication_group(selection)
                        .ok_or(CurrentThreadPageOwnerPreparationError::UnknownClient)?,
                )
            }
            None => None,
        };
        self.exit = Some(DetachedOwnerExit {
            clients,
            disposition: DetachedOwnerExitDisposition::SequentialFree {
                free_after_exit,
                post_exit_remote_publication_group,
            },
        });
        Ok(())
    }

    /// Transfers the source-proved sole immediate mapped regular outcome.
    /// `direct_small` changes only A's lower source drain; after that drain
    /// both source entrances expose the same later-owner adoption route.
    fn finish_sole_immediate_mapped_regular_reclaim(
        &mut self,
        clients: [PreparedOwnerExitClient; OWNER_EXIT_RECLAIM_CLIENT_SLOTS],
        direct_small: bool,
        request: usize,
        reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
    ) -> Result<(), CurrentThreadPageOwnerPreparationError> {
        if self.exit.is_some() {
            return Err(CurrentThreadPageOwnerPreparationError::Closed);
        }
        let [first, second] = clients;
        let first_key = first.key();
        let mut clients = [Some(first), Some(second)];
        let clients = self.clients.transfer_clients(&mut clients)?;
        let source = if direct_small {
            DetachedOwnerExitReclaimSource::DirectSmall { first: first_key }
        } else {
            DetachedOwnerExitReclaimSource::AggregateTraversal
        };
        self.exit = Some(DetachedOwnerExit {
            clients,
            disposition: DetachedOwnerExitDisposition::SoleImmediateMappedRegularReclaim {
                source,
                request,
                reclaim_after_exit,
            },
        });
        Ok(())
    }

    fn take_exit(
        &mut self,
    ) -> Result<DetachedOwnerExit, CurrentThreadPageOwnerPreparationError> {
        if self.clients.has_live_client() {
            return Err(CurrentThreadPageOwnerPreparationError::OmittedClient);
        }
        let exit = self
            .exit
            .take()
            .ok_or(CurrentThreadPageOwnerPreparationError::OmittedClient)?;
        if self.clients.release_overflow_without_live_clients().is_err() {
            self.exit = Some(exit);
            return Err(CurrentThreadPageOwnerPreparationError::LocalFree);
        }
        Ok(exit)
    }

    /// Returns every still-local allocation before an unsuccessful preparation
    /// asks the persistent engine to perform its normal all-free finish. A
    /// published pre-exit client is deliberately left to the joined source
    /// collector; it never became a post-exit route member.
    fn abort(&mut self) -> Result<(), ()> {
        if let Some(exit) = self.exit.take() {
            exit.free_locals(self.allocator)?;
        }
        self.clients.free_untransferred_locals(self.allocator)?;
        self.clients
            .release_overflow_without_live_clients()
            .map_err(|_| ())
    }
}

impl<'allocator, 'attachment, 'main> OwnerExitClientAllocator
    for CurrentThreadPageOwnerPreparation<'allocator, 'attachment, 'main>
{
    type Client = PreparedOwnerExitClient;
    type AllocationError = CurrentThreadPageOwnerPreparationError;

    #[inline]
    fn allocate_client(
        &mut self,
        request: usize,
        zero: bool,
    ) -> Result<Self::Client, Self::AllocationError> {
        self.allocate(request, zero)
    }

    #[inline]
    fn allocate_aligned_client(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<Self::Client, Self::AllocationError> {
        self.allocate_aligned(request, alignment)
    }

    #[inline]
    fn free_client(&mut self, client: Self::Client) -> Result<(), ()> {
        self.free(client).map_err(|_| ())
    }

    #[inline]
    fn current_allocation_page_reserved_client(&self, client: &Self::Client) -> Option<usize> {
        self.current_allocation_page_reserved(client)
    }
}

/// Moves any qualifying current-thread page engine into the one private
/// compiler-TLS owner state after ordinary source activity has prepared a
/// complete typed post-exit handoff.
///
/// The closure receives the linear preparation vocabulary rather than the
/// live allocator. It can allocate, locally free, publish the established
/// joined pre-exit pair, and finalize one typed route, but it cannot pack raw
/// client addresses or suspend an engine with a client omitted from that
/// route. The source fast-slot clear and Theap/TLD teardown remain solely in
/// [`finish_current_thread_after_user_destructors`]. A failed preparation
/// restores every local client before the ordinary all-free engine finish;
/// any unfinished engine remains terminal.
fn install_current_thread_page_owner(
    prepare: impl FnOnce(
        &mut CurrentThreadPageOwnerPreparation<'_, '_, '_>,
    ) -> Result<(), OwnerExitMappedRegularPageOwnerInstallResult>,
) -> OwnerExitMappedRegularPageOwnerInstallResult {
    let (parked, exit) = {
        let slot = current_thread_slot();
        if slot.page_owner.is_some() {
            return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
        }
        let Some(attachment) = slot.attachment.as_mut() else {
            return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
        };
        let metadata_config = match attachment.memory_config() {
            Ok(config) => config,
            Err(_) => return OwnerExitMappedRegularPageOwnerInstallResult::Retained,
        };
        let mut engine = match RUNTIME_PROCESS.begin_persistent_later_engine(attachment) {
            Ok(engine) => engine,
            Err(_) => return OwnerExitMappedRegularPageOwnerInstallResult::Retained,
        };
        let mut preparation = CurrentThreadPageOwnerPreparation::new(
            engine
                .allocator
                .as_mut()
                .expect("a runtime persistent engine retains its normal allocator"),
            metadata_config,
        );
        let exit = match prepare(&mut preparation) {
            Ok(()) => match preparation.take_exit() {
                Ok(exit) => exit,
                Err(_) => {
                    if preparation.abort().is_err() {
                        core::mem::forget(engine);
                        return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
                    }
                    return match engine.finish() {
                        Ok(()) => OwnerExitMappedRegularPageOwnerInstallResult::Retained,
                        Err(failure) => {
                            core::mem::forget(failure);
                            OwnerExitMappedRegularPageOwnerInstallResult::Retained
                        }
                    };
                }
            },
            Err(result) => {
                if preparation.abort().is_err() {
                    core::mem::forget(engine);
                    return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
                }
                return match engine.finish() {
                    Ok(()) => result,
                    Err(failure) => {
                        core::mem::forget(failure);
                        OwnerExitMappedRegularPageOwnerInstallResult::Retained
                    }
                };
            }
        };
        drop(preparation);

        match engine.suspend() {
            Ok(parked) => (parked, exit),
            Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, .. })
            | Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                core::mem::forget(engine);
                return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
            }
            Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, .. }) => {
                core::mem::forget(terminal);
                return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
            }
            Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
            }
        }
    };

    let slot = current_thread_slot();
    if slot.page_owner.is_some() {
        // A second suspended engine in one compiler-TLS slot would erase the
        // matching attachment marker. Dropping the new token makes the
        // runtime/page-map terminal; the caller records that state below.
        drop(parked);
        return OwnerExitMappedRegularPageOwnerInstallResult::Retained;
    }
    slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
        ThreadLifecyclePreparedPageOwner {
            parked,
            exit,
            native_live_remote_handoff: None,
        },
    ));
    OwnerExitMappedRegularPageOwnerInstallResult::Installed
}

/// Builds the mixed Gate 5C source image through
/// [`install_current_thread_page_owner`]. The workload remains a regression
/// fixture; it is not the runtime's page-owner state.
fn install_mapped_regular_owner_exit_page_owner(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> OwnerExitMappedRegularPageOwnerInstallResult {
    install_current_thread_page_owner(|preparation| {
        let mut workload = OwnerExitMappedRegularWorkload::allocate(preparation)
            .map_err(|_| OwnerExitMappedRegularPageOwnerInstallResult::AllocationFailed)?;
        let (medium, large) = workload
            .take_remote_clients()
            .expect("the bounded owner-exit workload allocated both remote clients");
        if let Err(failure) =
            preparation.publish_remote_free_pair(medium, large, publish_before_exit)
        {
            let (medium, large, _) = failure.into_parts();
            workload.restore_remote_clients(medium, large);
            let _ = workload.free_locals(preparation);
            return Err(OwnerExitMappedRegularPageOwnerInstallResult::PublicationFailed);
        }
        let post_exit_remote_publication_group = workload.post_exit_remote_publication_group_keys();
        let Some(mut clients) = workload.into_post_exit_clients_for_later_main_adoption() else {
            return Err(OwnerExitMappedRegularPageOwnerInstallResult::Retained);
        };
        preparation
            .finish_sequential(
                &mut clients,
                post_exit_remote_publication_group,
                free_after_exit,
            )
            .map_err(|_| OwnerExitMappedRegularPageOwnerInstallResult::Retained)
    })
}

/// Creates one source-valid reclaim predecessor through the same suspended
/// compiler-TLS owner transition as the mixed aggregate witness. Medium
/// enters the shared aggregate traversal; direct small enters its existing
/// specialized cache-validating source drain. Both transfer only the same
/// typed mapped regular route to B, which must adopt and drain the exact
/// page. The predecessor workload is consumed before suspension, so it is
/// never a property of the TLS lifecycle state.
fn install_mapped_regular_owner_exit_reclaim_page_owner(
    predecessor: MappedRegularReclaimPredecessor,
    reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
) -> OwnerExitMappedRegularPageOwnerInstallResult {
    install_current_thread_page_owner(|preparation| match predecessor {
        MappedRegularReclaimPredecessor::Medium => {
            let workload = OwnerExitReclaimWorkload::allocate(preparation)
                .map_err(|_| OwnerExitMappedRegularPageOwnerInstallResult::AllocationFailed)?;
            let Some(clients) = workload.into_clients() else {
                return Err(OwnerExitMappedRegularPageOwnerInstallResult::Retained);
            };
            preparation
                .finish_sole_immediate_mapped_regular_reclaim(
                    clients,
                    false,
                    OWNER_EXIT_RECLAIM_MEDIUM_REQUEST,
                    reclaim_after_exit,
                )
                .map_err(|_| OwnerExitMappedRegularPageOwnerInstallResult::Retained)
        }
        MappedRegularReclaimPredecessor::DirectSmall => {
            let workload = OwnerExitDirectSmallReclaimWorkload::allocate(preparation)
                .map_err(|_| OwnerExitMappedRegularPageOwnerInstallResult::AllocationFailed)?;
            let Some(clients) = workload.into_clients() else {
                return Err(OwnerExitMappedRegularPageOwnerInstallResult::Retained);
            };
            preparation
                .finish_sole_immediate_mapped_regular_reclaim(
                    clients,
                    true,
                    OWNER_EXIT_RECLAIM_DIRECT_SMALL_REQUEST,
                    reclaim_after_exit,
                )
                .map_err(|_| OwnerExitMappedRegularPageOwnerInstallResult::Retained)
        }
    })
}

// This fixed, pointer-private test workload deliberately crosses the source
// small, medium, large, and singleton allocation branches. Two small and two
// medium blocks remain live while their siblings are freed and reacquired, so
// the reuse check observes local page ownership rather than a freshly released
// page or a ticket-zero handoff. The final singleton is larger than one large
// page to require a multi-page source singleton span.
const PERSISTENT_WORKER_LOCAL_REQUESTS: [(usize, u8); 7] = [
    (37, 0x11),
    (37, 0x22),
    (SMALL_MAX_OBJ_SIZE + 1, 0x33),
    (SMALL_MAX_OBJ_SIZE + 1, 0x44),
    (MEDIUM_MAX_OBJ_SIZE + 1, 0x55),
    (LARGE_MAX_OBJ_SIZE + 1, 0x66),
    (LARGE_MAX_OBJ_SIZE + 64 * 1024 + 1, 0x77),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentLocalWorkerError {
    AllocationFailed,
    PatternMismatch,
    Free,
}

#[inline]
unsafe fn fill_worker_pattern(block: core::ptr::NonNull<u8>, size: usize, seed: u8) {
    for offset in 0..size {
        // SAFETY: the caller proves this exact current allocation has at
        // least `size` writable bytes and no concurrent or aliased access.
        unsafe {
            block
                .as_ptr()
                .add(offset)
                .write(seed.wrapping_add(offset as u8));
        }
    }
}

#[inline]
unsafe fn worker_pattern_matches(block: core::ptr::NonNull<u8>, size: usize, seed: u8) -> bool {
    for offset in 0..size {
        // SAFETY: the caller proves this exact current allocation has at
        // least `size` readable bytes and no concurrent or aliased access.
        let observed = unsafe { block.as_ptr().add(offset).read() };
        if observed != seed.wrapping_add(offset as u8) {
            return false;
        }
    }
    true
}

#[inline]
fn free_persistent_worker_block(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    block: &mut Option<core::ptr::NonNull<u8>>,
) -> Result<(), PersistentLocalWorkerError> {
    let block = block.take().ok_or(PersistentLocalWorkerError::Free)?;
    // SAFETY: this helper consumes exactly one current local allocation and
    // never publishes it outside the persistent worker engine.
    unsafe { allocator.free(block) }.map_err(|_| PersistentLocalWorkerError::Free)
}

fn free_remaining_persistent_worker_blocks(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    blocks: &mut [Option<core::ptr::NonNull<u8>>; PERSISTENT_WORKER_LOCAL_REQUESTS.len()],
) -> Result<(), PersistentLocalWorkerError> {
    for block in blocks {
        if block.is_some() {
            free_persistent_worker_block(allocator, block)?;
        }
    }
    Ok(())
}

/// Exercises one worker-owned page engine for the complete local Gate 5A
/// witness. It has no transfer, remote-free, abandonment, or owner-exit
/// operation: every pointer stays private to this thread and is freed before
/// its enclosing engine can finish.
fn run_persistent_local_worker_workload(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
) -> Result<(), PersistentLocalWorkerError> {
    let mut blocks = [None; PERSISTENT_WORKER_LOCAL_REQUESTS.len()];

    for (slot, (request, seed)) in blocks.iter_mut().zip(PERSISTENT_WORKER_LOCAL_REQUESTS) {
        let Some(block) = allocator.allocate(request, false) else {
            free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
            return Err(PersistentLocalWorkerError::AllocationFailed);
        };
        // SAFETY: `block` is the exact newly allocated, local block and the
        // request is the checked allocation length for this workload.
        unsafe { fill_worker_pattern(block, request, seed) };
        *slot = Some(block);
    }

    for (block, (request, seed)) in blocks.iter().zip(PERSISTENT_WORKER_LOCAL_REQUESTS) {
        let block = block.ok_or(PersistentLocalWorkerError::PatternMismatch)?;
        // SAFETY: each allocation remains current and exclusively local until
        // the mixed free sequence below consumes it.
        if !unsafe { worker_pattern_matches(block, request, seed) } {
            free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
            return Err(PersistentLocalWorkerError::PatternMismatch);
        }
    }

    free_persistent_worker_block(allocator, &mut blocks[0])?;
    let Some(reused_small) = allocator.allocate(PERSISTENT_WORKER_LOCAL_REQUESTS[0].0, false)
    else {
        free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentLocalWorkerError::AllocationFailed);
    };
    blocks[0] = Some(reused_small);
    // SAFETY: this post-free allocation is current and private to this worker.
    unsafe {
        fill_worker_pattern(
            reused_small,
            PERSISTENT_WORKER_LOCAL_REQUESTS[0].0,
            PERSISTENT_WORKER_LOCAL_REQUESTS[0].1,
        )
    };

    free_persistent_worker_block(allocator, &mut blocks[2])?;
    let Some(reused_medium) = allocator.allocate(PERSISTENT_WORKER_LOCAL_REQUESTS[2].0, false)
    else {
        free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentLocalWorkerError::AllocationFailed);
    };
    blocks[2] = Some(reused_medium);
    // SAFETY: this post-free allocation is current and private to this worker.
    unsafe {
        fill_worker_pattern(
            reused_medium,
            PERSISTENT_WORKER_LOCAL_REQUESTS[2].0,
            PERSISTENT_WORKER_LOCAL_REQUESTS[2].1,
        )
    };

    // Deliberately free across page kinds rather than in allocation order.
    for index in [4, 1, 6, 5, 3, 2, 0] {
        free_persistent_worker_block(allocator, &mut blocks[index])?;
    }
    Ok(())
}

/// Runs the fixed mixed-local witness through the runtime's typed persistent
/// operation rather than the older closure-shaped dormant-pair handoff.
///
/// The operation owns the `READY -> BUSY -> READY` scheduler transition and
/// can therefore be the same A-side capability that a separate focused test
/// parks before one bounded B-side operation. This local witness does not
/// park, transfer a client, or admit B; it proves that the prefixed C fixture
/// exercises the typed scheduler without widening its ABI.
fn run_runtime_persistent_local_worker_lifecycle<'attachment, 'main>(
    runtime: &'static RuntimeProcessStorage,
    attachment: &'attachment mut MainHeapThreadAttachment<'main>,
) -> Result<PersistentLocalWorkerResult, ()> {
    let mut engine = runtime
        .begin_persistent_later_engine(attachment)
        .map_err(|_| ())?;
    let workload = engine.run_persistent_local_workload();
    match (workload, engine.finish()) {
        (Ok(()), Ok(())) => Ok(PersistentLocalWorkerResult::Completed),
        (Err(PersistentLocalWorkerError::AllocationFailed), Ok(())) => {
            Ok(PersistentLocalWorkerResult::AllocationFailed)
        }
        (
            Err(PersistentLocalWorkerError::PatternMismatch | PersistentLocalWorkerError::Free),
            Ok(()),
        ) => {
            // The lower engine did reach its all-free finish, but this witness
            // observed a broken local invariant. Match the former
            // closure-shaped route: preserve a terminal process outcome rather
            // than reopening ticket zero after an unaccounted test failure.
            runtime.retain_page_owner();
            Err(())
        }
        (_, Err(_)) => Err(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentLocalWorkerResult {
    Completed,
    AllocationFailed,
}

// A regular small page has at most this many exact 37-byte requests: source
// block rounding and page metadata can only decrease the capacity. The
// read-only engine observation below supplies the exact current capacity, so
// the owner fills one page without crossing into a successor before B publishes
// the remote free.
const PERSISTENT_REMOTE_REQUEST: usize = 37;
const PERSISTENT_REMOTE_BLOCK_SLOTS: usize = SMALL_PAGE_SIZE / PERSISTENT_REMOTE_REQUEST;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentRemoteWorkerError {
    AllocationFailed,
    PublicationFailed,
    PageCapacityInvalid,
    ReuseFailed,
    Free,
}

#[inline]
fn free_persistent_remote_worker_block(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    block: &mut Option<core::ptr::NonNull<u8>>,
) -> Result<(), PersistentRemoteWorkerError> {
    let block = block.take().ok_or(PersistentRemoteWorkerError::Free)?;
    // SAFETY: the helper consumes one current block that the remote handoff
    // never received, or that owner collection returned to this exact engine.
    unsafe { allocator.free(block) }.map_err(|_| PersistentRemoteWorkerError::Free)
}

fn free_remaining_persistent_remote_worker_blocks(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    blocks: &mut [Option<core::ptr::NonNull<u8>>; PERSISTENT_REMOTE_BLOCK_SLOTS],
) -> Result<(), PersistentRemoteWorkerError> {
    for block in blocks {
        if block.is_some() {
            free_persistent_remote_worker_block(allocator, block)?;
        }
    }
    Ok(())
}

/// Exercises the live-owner half of Gate 5B. The first small page becomes full
/// before two exact blocks transfer as logical remote publications; the
/// joined owner's next ordinary allocations perform the source false
/// collection, receive both exact blocks back, and finish with no client
/// allocation.
///
/// `publish` owns only the two source remote-free capabilities. It cannot
/// access the worker attachment, page engine, PageMap lease, arena, or client
/// pointers. The owner remains stopped until the callback returns both tokens
/// as published or not-published, so this is not an owner-exit or general
/// asynchronous path.
fn run_persistent_remote_worker_workload(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    publish: TicketZeroRemoteFreePublisher,
) -> Result<(), PersistentRemoteWorkerError> {
    let mut blocks = [None; PERSISTENT_REMOTE_BLOCK_SLOTS];
    let Some(first) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
        return Err(PersistentRemoteWorkerError::AllocationFailed);
    };
    // SAFETY: `first` is the exact current allocation and no remote producer
    // exists while the owner observes its page's fixed source capacity.
    let capacity = unsafe { allocator.current_allocation_page_capacity(first) }
        .filter(|capacity| *capacity >= 2 && *capacity <= PERSISTENT_REMOTE_BLOCK_SLOTS)
        .ok_or(PersistentRemoteWorkerError::PageCapacityInvalid)?;
    blocks[0] = Some(first);
    for slot in blocks.iter_mut().take(capacity).skip(1) {
        let Some(block) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
            free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
            return Err(PersistentRemoteWorkerError::AllocationFailed);
        };
        *slot = Some(block);
    }

    let first_transferred = blocks[0]
        .take()
        .ok_or(PersistentRemoteWorkerError::Free)?;
    let second_transferred = blocks[1]
        .take()
        .ok_or(PersistentRemoteWorkerError::Free)?;
    // SAFETY: the bounded fixed request filled the target's first small page
    // before these transfers. Both blocks are current, distinct, and remain
    // PageMap-published until B/C join and owner A collects them.
    let producers = unsafe {
        allocator.begin_remote_free_pair(first_transferred, second_transferred)
    }
        .map_err(|_| PersistentRemoteWorkerError::PublicationFailed)?;
    let producers = TicketZeroRemoteFreeProducerPair { producers };
    if let Err(producers) = publish(producers) {
        let (first, second) = producers.cancel();
        blocks[0] = Some(first);
        blocks[1] = Some(second);
        free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentRemoteWorkerError::PublicationFailed);
    }

    let Some(reused) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
        free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentRemoteWorkerError::AllocationFailed);
    };
    let Some(second_reused) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
        blocks[0] = Some(reused);
        free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentRemoteWorkerError::AllocationFailed);
    };
    blocks[0] = Some(reused);
    blocks[1] = Some(second_reused);
    free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
    if (reused == first_transferred && second_reused == second_transferred)
        || (reused == second_transferred && second_reused == first_transferred)
    {
        Ok(())
    } else {
        Err(PersistentRemoteWorkerError::ReuseFailed)
    }
}

/// Runs the fixed live-owner remote-free witness through the runtime's typed
/// persistent operation rather than the older closure-shaped dormant-pair
/// handoff.
///
/// The worker remains the sole A-side engine owner throughout the scoped B
/// publication and join. Its `READY -> BUSY -> READY` transition therefore
/// stays coupled to the exact engine that collects the remote frees, while
/// the publisher remains unable to obtain a general page operation.
fn run_runtime_persistent_remote_worker_lifecycle<'attachment, 'main>(
    runtime: &'static RuntimeProcessStorage,
    attachment: &'attachment mut MainHeapThreadAttachment<'main>,
    publish: TicketZeroRemoteFreePublisher,
) -> Result<PersistentRemoteWorkerResult, ()> {
    let mut engine = runtime
        .begin_persistent_later_engine(attachment)
        .map_err(|_| ())?;
    let workload = engine.run_persistent_remote_workload(publish);
    match (workload, engine.finish()) {
        (Ok(()), Ok(())) => Ok(PersistentRemoteWorkerResult::Completed),
        (Err(PersistentRemoteWorkerError::AllocationFailed), Ok(())) => {
            Ok(PersistentRemoteWorkerResult::AllocationFailed)
        }
        (Err(PersistentRemoteWorkerError::PublicationFailed), Ok(())) => {
            Ok(PersistentRemoteWorkerResult::PublicationFailed)
        }
        (Err(PersistentRemoteWorkerError::ReuseFailed), Ok(())) => {
            Ok(PersistentRemoteWorkerResult::ReuseFailed)
        }
        (
            Err(PersistentRemoteWorkerError::PageCapacityInvalid | PersistentRemoteWorkerError::Free),
            Ok(()),
        ) => {
            // As with the former closure-shaped handoff, an unaccounted
            // source invariant failure must not reopen ticket zero merely
            // because the lower engine happened to become all-free.
            runtime.retain_page_owner();
            Err(())
        }
        (_, Err(_)) => Err(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentRemoteWorkerResult {
    Completed,
    AllocationFailed,
    PublicationFailed,
    ReuseFailed,
}

/// Runs the bounded mixed owner-exit witness through the real normal
/// post-destructor runtime finish dispatch.
///
/// This stores A's page-bearing owner in the current thread's compiler TLS
/// before it invokes [`finish_current_thread_after_user_destructors`]. The
/// normal finish must therefore resume the typed engine, run the general
/// aggregate coordinator, and wait for B's opaque terminal proof before it
/// may release A's worker admission. It remains a pointer-private test seam,
/// not a libc backend or a general post-exit free API.
#[doc(hidden)]
pub fn ticket_zero_later_thread_mapped_regular_owner_exit_through_normal_finish(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    match install_mapped_regular_owner_exit_page_owner(publish_before_exit, free_after_exit) {
        OwnerExitMappedRegularPageOwnerInstallResult::Installed => {
            match finish_current_thread_after_user_destructors() {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        OwnerExitMappedRegularPageOwnerInstallResult::AllocationFailed => {
            match finish_current_thread_after_user_destructors() {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::AllocationFailed,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        OwnerExitMappedRegularPageOwnerInstallResult::PublicationFailed => {
            match finish_current_thread_after_user_destructors() {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Unavailable,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        OwnerExitMappedRegularPageOwnerInstallResult::Retained => {
            retain_current_thread_live_page_owner();
            TicketZeroLaterThreadPageResult::Retained
        }
    }
}

/// The source choice that changes a parked session's post-exit consumer
/// preparation. Every case retains the same generic aggregate route and its
/// private client ledger; a scoped source interleaving moves two opaque client
/// keys outside that ledger only for B to hand C/D their bounded producers.
#[derive(Clone, Copy)]
enum ParkedSessionPostExitPublication {
    Ordinary,
    ScopedDirectSmallRemoteFree,
    ScopedMappedMediumRemoteFree,
    ScopedInitiallyMappedMediumRemoteFree,
}

/// Exercises the ordinary owner-exit dispatcher from a real parked TLS
/// session rather than from the one-shot preparation closure used by the
/// historical fixed workload witness.
///
/// The session performs ordinary allocation, local free/reuse, a joined
/// source remote publication, and further allocations across separate
/// park/resume operations before it consumes its own private ledger into the
/// general sequential route. No raw client address, allocator, page identity,
/// or general post-exit selector crosses this Rust-only test seam.
#[doc(hidden)]
pub fn ticket_zero_later_thread_session_owner_exit_through_normal_finish(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> TicketZeroLaterThreadPageResult {
    ticket_zero_later_thread_session_owner_exit_through_normal_finish_with_post_exit_publication(
        publish_before_exit,
        free_after_exit,
        ParkedSessionPostExitPublication::Ordinary,
    )
}

/// Exercises the source-valid direct-small B/C/D post-exit publication from
/// the same parked TLS session lifecycle. A selects three still-live clients
/// only by private ledger key before it suspends; fresh B receives the opaque
/// route and may lend C/D scoped atomic producers only after B has the source
/// low-bit claim. This is not a public producer or pointer-handoff API.
#[doc(hidden)]
pub fn ticket_zero_later_thread_session_owner_exit_with_post_exit_publisher_through_normal_finish(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> TicketZeroLaterThreadPageResult {
    ticket_zero_later_thread_session_owner_exit_through_normal_finish_with_post_exit_publication(
        publish_before_exit,
        free_after_exit,
        ParkedSessionPostExitPublication::ScopedDirectSmallRemoteFree,
    )
}

/// Exercises the separately bounded mapped-medium B/C/D publication from the
/// same parked TLS session lifecycle. A selects three remaining medium
/// clients only by private ledger key after the page's pre-exit source remote
/// free has normalized it into the mapped regular route. Fresh B can lend C/D
/// the nominally mapped-medium producers only after B holds the source low
/// owner bit. This is neither a general concurrent free route nor a public
/// pointer-handoff API.
#[doc(hidden)]
pub fn ticket_zero_later_thread_session_owner_exit_with_post_exit_mapped_medium_publisher_through_normal_finish(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> TicketZeroLaterThreadPageResult {
    ticket_zero_later_thread_session_owner_exit_through_normal_finish_with_post_exit_publication(
        publish_before_exit,
        free_after_exit,
        ParkedSessionPostExitPublication::ScopedMappedMediumRemoteFree,
    )
}

/// Exercises the same bounded B/C/D publication from a medium member that
/// was already mapped and non-full when A entered the general owner-exit
/// traversal. A reaches that source state through one ordinary local free;
/// the aggregate route still chooses and owns the member, while fresh B may
/// lend C/D the nominally mapped-medium producers only after B has claimed
/// the page's source low owner bit. This remains neither a general concurrent
/// free route nor a public pointer-handoff API.
#[doc(hidden)]
pub fn ticket_zero_later_thread_session_owner_exit_with_initial_mapped_medium_post_exit_publisher_through_normal_finish(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> TicketZeroLaterThreadPageResult {
    ticket_zero_later_thread_session_owner_exit_through_normal_finish_with_post_exit_publication(
        publish_before_exit,
        free_after_exit,
        ParkedSessionPostExitPublication::ScopedInitiallyMappedMediumRemoteFree,
    )
}

fn ticket_zero_later_thread_session_owner_exit_through_normal_finish_with_post_exit_publication(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
    post_exit_publication: ParkedSessionPostExitPublication,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let mut session = match begin_current_thread_page_owner_session() {
        Ok(session) => session,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Unavailable;
        }
        Err(CurrentThreadPageOwnerSessionError::Preparation(_) | CurrentThreadPageOwnerSessionError::Retained) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };

    // The one source operation proves that a local free can immediately feed
    // another same-class allocation. The allocator need not return the exact
    // same address: its source free-list policy may choose another local
    // block. The following workload operations each cross the parked-session
    // boundary, so the session still proves durable ordinary state.
    let local_reuse = session.with_active_operation(|allocator, clients| {
        let first = clients.allocate_client(allocator, 37, false)?;
        clients
            .free_client(allocator, first)
            .map_err(|_| CurrentThreadPageOwnerPreparationError::LocalFree)?;
        let reused = clients.allocate_client(allocator, 37, false)?;
        clients
            .free_client(allocator, reused)
            .map_err(|_| CurrentThreadPageOwnerPreparationError::LocalFree)?;
        Ok::<(), CurrentThreadPageOwnerPreparationError>(())
    });
    match local_reuse {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    }

    // This remains a source-state fixture, but every allocation now goes
    // through the live TLS session's ordinary operation boundary. The active
    // session—not this local workload value—owns the durable client ledger.
    let mut workload = match OwnerExitMappedRegularWorkload::allocate(&mut session) {
        Ok(workload) => workload,
        Err(_) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    let Some((medium, large)) = workload.take_remote_clients() else {
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    };
    if let Err(failure) = session.publish_remote_free_pair(medium, large, publish_before_exit) {
        match failure {
            CurrentThreadPageOwnerSessionRemotePairFailure::Preparation(failure) => {
                let (medium, large, _) = failure.into_parts();
                workload.restore_remote_clients(medium, large);
                let _ = workload.free_locals(&mut session);
            }
            CurrentThreadPageOwnerSessionRemotePairFailure::Session(error) => {
                // The source session already owns the terminal state for this
                // failed operation. Keep the exact error consumed here so the
                // outer boundary cannot mistake it for a recoverable pair.
                let _ = error;
            }
        }
        // A session-level failure may have retained the exact parked/live
        // source state already. Neither branch may call the no-page finalizer
        // while this unfinished session still owns its client ledger.
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    }
    let post_exit_remote_publication_group = match post_exit_publication {
        ParkedSessionPostExitPublication::Ordinary => None,
        ParkedSessionPostExitPublication::ScopedDirectSmallRemoteFree => {
            match workload.post_exit_remote_publication_group_keys() {
                Some(group) => Some(group),
                None => {
                    retain_current_thread_live_page_owner();
                    return TicketZeroLaterThreadPageResult::Retained;
                }
            }
        }
        ParkedSessionPostExitPublication::ScopedMappedMediumRemoteFree => {
            match workload.post_exit_mapped_medium_remote_publication_group_keys() {
                Some(group) => Some(group),
                None => {
                    retain_current_thread_live_page_owner();
                    return TicketZeroLaterThreadPageResult::Retained;
                }
            }
        }
        ParkedSessionPostExitPublication::ScopedInitiallyMappedMediumRemoteFree => {
            match workload.post_exit_initial_mapped_medium_remote_publication_group_keys() {
                Some(group) => Some(group),
                None => {
                    retain_current_thread_live_page_owner();
                    return TicketZeroLaterThreadPageResult::Retained;
                }
            }
        }
    };
    drop(workload);

    let prepare_exit = match post_exit_remote_publication_group {
        Some(group) => session
            .prepare_sequential_exit_with_post_exit_remote_publication_group(group, free_after_exit),
        None => session.prepare_sequential_exit(free_after_exit),
    };
    match prepare_exit {
        Ok(()) => match finish_current_thread_after_user_destructors() {
            ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
            ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
            ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                TicketZeroLaterThreadPageResult::Unavailable
            }
        },
        Err(_) => {
            retain_current_thread_live_page_owner();
            TicketZeroLaterThreadPageResult::Retained
        }
    }
}

/// Exercises the source retired-page prepass through an actual parked TLS
/// session before that session transfers its one surviving client into the
/// ordinary aggregate owner-exit route.
///
/// The first allocation is a direct-small page that a normal local free leaves
/// queued with a nonzero source retirement countdown. The second is a distinct
/// medium page with one live client. At normal finish,
/// `_mi_theap_collect_abandon` must release the retired direct-small span
/// before it traverses and publishes the live medium into B's opaque route.
/// A still owns its worker admission until that route terminally releases and
/// B completes its own attachment; this seam never supplies an address to the
/// caller or substitutes the no-page finalizer after abandonment.
#[doc(hidden)]
pub fn ticket_zero_later_thread_retired_then_live_session_owner_exit_through_normal_finish(
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let mut session = match begin_current_thread_page_owner_session() {
        Ok(session) => session,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Unavailable;
        }
        Err(CurrentThreadPageOwnerSessionError::Preparation(_) | CurrentThreadPageOwnerSessionError::Retained) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };

    let retired = match session.allocate(37, false) {
        Ok(block) => block,
        Err(_) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    if session.free(retired).is_err() {
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    }

    // This request occupies a distinct medium page, so the direct-small
    // source cache remains retired instead of being revived by the live
    // session client. The lower coordinator validates and releases that
    // cache image during its retired-page prepass before it publishes this
    // surviving client into the general route.
    if session.allocate(SMALL_MAX_OBJ_SIZE + 1, false).is_err() {
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    }

    match session.prepare_sequential_exit(free_after_exit) {
        Ok(()) => match finish_current_thread_after_user_destructors() {
            ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
            ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
            ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                TicketZeroLaterThreadPageResult::Unavailable
            }
        },
        Err(_) => {
            retain_current_thread_live_page_owner();
            TicketZeroLaterThreadPageResult::Retained
        }
    }
}

/// Exercises the all-free side of the active parked-session lifecycle through
/// the ordinary post-destructor finish entry.
///
/// Every session allocation is locally freed before the finish boundary. The
/// session therefore has no client that could require the typed post-exit
/// route, but it still owns a suspended page engine and cannot be treated as
/// a no-page attachment. The normal dispatcher must resume that exact engine,
/// run the all-free page drain, then finish the old Theap/TLD before releasing
/// this worker's admission. This is a Rust-only regression seam, not allocator
/// routing or a permission to finalize a live session through the no-page
/// path.
#[doc(hidden)]
pub fn ticket_zero_later_thread_all_free_session_through_normal_finish(
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let mut session = match begin_current_thread_page_owner_session() {
        Ok(session) => session,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Unavailable;
        }
        Err(CurrentThreadPageOwnerSessionError::Preparation(_) | CurrentThreadPageOwnerSessionError::Retained) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    let block = match session.allocate(37, false) {
        Ok(block) => block,
        Err(_) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    if session.free(block).is_err() {
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    }
    drop(session);

    match finish_current_thread_after_user_destructors() {
        ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
        ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
        ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
            TicketZeroLaterThreadPageResult::Unavailable
        }
    }
}

/// Exercises the source-published all-free side of the active parked-session
/// boundary.
///
/// Both clients have crossed the joined source remote-free protocol before the
/// destructor boundary, so neither is a locally live ledger entry. They still
/// remain page-bearing until source collection force-collects their remote
/// heads. The normal finish must therefore use the typed all-free page drain,
/// not the no-page finalizer; only after that drain and A's attachment teardown
/// may it release this worker's admission. This is a Rust-only regression
/// seam, not allocator routing.
#[doc(hidden)]
pub fn ticket_zero_later_thread_source_published_session_through_normal_finish(
    publish_before_exit: TicketZeroRemoteFreePublisher,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let mut session = match begin_current_thread_page_owner_session() {
        Ok(session) => session,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Unavailable;
        }
        Err(CurrentThreadPageOwnerSessionError::Preparation(_) | CurrentThreadPageOwnerSessionError::Retained) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    let first = match session.allocate(37, false) {
        Ok(block) => block,
        Err(_) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    let second = match session.allocate(37, false) {
        Ok(block) => block,
        Err(_) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    if session
        .publish_remote_free_pair(first, second, publish_before_exit)
        .is_err()
    {
        // A failed publication may leave the exact live source session in
        // TLS. The test seam has no recovery route for that state and must
        // never invoke the no-page finalizer merely to report a result.
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    }
    drop(session);

    match finish_current_thread_after_user_destructors() {
        ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
        ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
        ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
            TicketZeroLaterThreadPageResult::Unavailable
        }
    }
}

/// Exercises the one-client source-published all-free side of the active
/// parked-session boundary.
///
/// The client crosses one joined source remote-free handoff before the
/// destructor boundary. It is still page-bearing until the source
/// `_mi_theap_collect_abandon` pass force-collects the remote head, so normal
/// finish must run the typed all-free page drain and attachment teardown before
/// releasing this worker's admission. This remains a pointer-private Rust-only
/// regression seam, not allocator routing or a general remote-free API.
#[doc(hidden)]
pub fn ticket_zero_later_thread_single_source_published_session_through_normal_finish(
    publish_before_exit: TicketZeroSingleRemoteFreePublisher,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let mut session = match begin_current_thread_page_owner_session() {
        Ok(session) => session,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Unavailable;
        }
        Err(CurrentThreadPageOwnerSessionError::Preparation(_) | CurrentThreadPageOwnerSessionError::Retained) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    let client = match session.allocate(37, false) {
        Ok(block) => block,
        Err(_) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    if let Err(failure) = session.publish_remote_free(client, publish_before_exit) {
        match failure {
            CurrentThreadPageOwnerSessionRemoteFreeFailure::Preparation(failure) => {
                let _ = failure.into_parts();
            }
            CurrentThreadPageOwnerSessionRemoteFreeFailure::Session(error) => {
                let _ = error;
            }
        }
        // The failed handoff leaves its exact source client/session in TLS.
        // This seam has no recovery policy, and must not invoke the no-page
        // finalizer merely to convert that state into a result code.
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    }
    drop(session);

    match finish_current_thread_after_user_destructors() {
        ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
        ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
        ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
            TicketZeroLaterThreadPageResult::Unavailable
        }
    }
}

/// Exercises the negative lifecycle boundary for an active parked TLS page
/// owner. The session deliberately retains one live private client but does
/// not select a typed post-exit route before it invokes the ordinary finish
/// entry. That entry must retain the exact active owner; it must not mistake
/// the parked engine for a no-page attachment and release this worker's
/// admission. This is a Rust-only regression seam, not allocator routing.
#[doc(hidden)]
pub fn ticket_zero_later_thread_active_session_rejects_normal_finish(
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let mut session = match begin_current_thread_page_owner_session() {
        Ok(session) => session,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Unavailable;
        }
        Err(CurrentThreadPageOwnerSessionError::Preparation(_) | CurrentThreadPageOwnerSessionError::Retained) => {
            retain_current_thread_live_page_owner();
            return TicketZeroLaterThreadPageResult::Retained;
        }
    };
    if session.allocate(37, false).is_err() {
        // The active session remains in TLS on an ordinary source allocation
        // refusal. Preserve it terminally rather than attempting the old
        // no-page fallback merely to classify this test-only seam.
        retain_current_thread_live_page_owner();
        return TicketZeroLaterThreadPageResult::Retained;
    }
    drop(session);

    match finish_current_thread_after_user_destructors() {
        ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
        ThreadFinishResult::Finished
        | ThreadFinishResult::NotAttached
        | ThreadFinishResult::AlreadyFinished => TicketZeroLaterThreadPageResult::Unavailable,
    }
}

/// Runs the bounded sole-medium reclamation witness through the real normal
/// post-destructor runtime finish dispatch.
///
/// A's page-bearing state is suspended into compiler TLS before ordinary
/// finish resumes it and runs the same aggregate source traversal as the
/// mixed witness. The sole route keeps A's admission until B has adopted,
/// used, drained, and terminally finished it. This remains a pointer-private
/// test seam, not a general reclamation or libc allocator interface.
#[doc(hidden)]
pub fn ticket_zero_later_thread_mapped_regular_owner_exit_reclaim_through_normal_finish(
    reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
) -> TicketZeroLaterThreadPageResult {
    ticket_zero_later_thread_owner_exit_reclaim_through_normal_finish(
        MappedRegularReclaimPredecessor::Medium,
        reclaim_after_exit,
    )
}

/// Runs the bounded direct-small reclamation witness through the same real
/// normal post-destructor runtime finish dispatch.
///
/// A's page-bearing state suspends into compiler TLS before ordinary finish
/// enters the existing direct-small cache-validating source drain. B receives
/// only the resulting opaque regular-page adoption capability; it must use,
/// drain, and finish the reclaimed page before the common typed proof releases
/// A's admission. This is private lifecycle evidence, not an aggregate-route
/// claim, a public reclamation API, or a libc allocator interface.
#[doc(hidden)]
pub fn ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish(
    reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
) -> TicketZeroLaterThreadPageResult {
    ticket_zero_later_thread_owner_exit_reclaim_through_normal_finish(
        MappedRegularReclaimPredecessor::DirectSmall,
        reclaim_after_exit,
    )
}

fn ticket_zero_later_thread_owner_exit_reclaim_through_normal_finish(
    predecessor: MappedRegularReclaimPredecessor,
    reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    match install_mapped_regular_owner_exit_reclaim_page_owner(predecessor, reclaim_after_exit) {
        OwnerExitMappedRegularPageOwnerInstallResult::Installed => {
            match finish_current_thread_after_user_destructors() {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        OwnerExitMappedRegularPageOwnerInstallResult::AllocationFailed => {
            match finish_current_thread_after_user_destructors() {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::AllocationFailed,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        OwnerExitMappedRegularPageOwnerInstallResult::PublicationFailed => {
            // The reclaim predecessor publishes no remote client before A
            // exits. Keep this exhaustive result mapping explicit so a later
            // shared installer cannot accidentally reinterpret it as success.
            match finish_current_thread_after_user_destructors() {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Unavailable,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        OwnerExitMappedRegularPageOwnerInstallResult::Retained => {
            retain_current_thread_live_page_owner();
            TicketZeroLaterThreadPageResult::Retained
        }
    }
}

/// Runs the bounded real-lifecycle Gate 5C witness against the dormant
/// ticket-zero process pair.
///
/// A publishes two clients to joined B/C before it crosses the existing
/// general regular-page owner-exit traversal: one from a full medium page and
/// one from a distinct large page. The traversal force-collects both, moving
/// the medium out of `BIN_FULL` while immediately releasing the now-empty
/// large page; a second full medium remains source-unmapped. It then detaches
/// A's Theap/TLD and returns one opaque aggregate route. A second fresh joined
/// B receives that route, frees every remaining private small/medium/large/
/// arena-singleton/OS-singleton client, and completes only B's own no-page
/// attachment before returning the proof of the final PageMap lifecycle. This
/// test-only seam accepts no raw pointer, does not route libc allocation, and
/// does not create a new page-shape-specific owner-exit entry point.
//
// Kept out of the compiled crate only while this source file is being
// consolidated: the normal-finish witnesses above now provide the one active
// lifecycle route for the same fixed workload. It is not an alternate API or
// fallback path.
#[cfg(any())]
#[doc(hidden)]
pub fn ticket_zero_later_thread_mapped_regular_owner_exit(
    publish_before_exit: TicketZeroRemoteFreePublisher,
    free_after_exit: TicketZeroOwnerExitFreeConsumer,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let page_result = RUNTIME_PROCESS.with_dormant_page_pair(|pair| {
        let lifecycle_slot = current_thread_slot();
        let Some(attachment) = lifecycle_slot.attachment.as_mut() else {
            return Err(());
        };
        let owner_exit_result = {
            let mut allocator = match MainHeapThreadProcessPageAllocator::begin(attachment, pair) {
                Ok(allocator) => allocator,
                Err(_) => return Err(()),
            };
            let mut workload = match OwnerExitMappedRegularWorkload::allocate(&mut allocator) {
                Ok(workload) => workload,
                Err(_) => {
                    return match allocator.finish() {
                        Ok(()) => Ok(OwnerExitMappedRegularWorkerResult::AllocationFailed),
                        Err(failure) => {
                            core::mem::forget(failure);
                            Ok(OwnerExitMappedRegularWorkerResult::Retained)
                        }
                    };
                }
            };

            let (medium, large) = workload
                .take_remote_clients()
                .expect("the bounded owner-exit witness allocated both remote clients");
            // SAFETY: `medium` and `large` are distinct exact current
            // clients. The first belongs to a source-full regular medium page
            // and the second is the sole client of a separate regular large
            // page. B/C receive only logical remote-free producers; A remains
            // alive until both have published or returned.
            let producers = match unsafe { allocator.begin_remote_free_pair(medium, large) } {
                Ok(producers) => TicketZeroRemoteFreeProducerPair { producers },
                Err(_) => {
                    workload.restore_remote_clients(medium, large);
                    let _ = workload.free_locals(&mut allocator);
                    return match allocator.finish() {
                        Ok(()) => Ok(OwnerExitMappedRegularWorkerResult::PublicationFailed),
                        Err(failure) => {
                            core::mem::forget(failure);
                            Ok(OwnerExitMappedRegularWorkerResult::Retained)
                        }
                    };
                }
            };
            if let Err(producers) = publish_before_exit(producers) {
                let (medium, large) = producers.cancel();
                workload.restore_remote_clients(medium, large);
                let _ = workload.free_locals(&mut allocator);
                return match allocator.finish() {
                    Ok(()) => Ok(OwnerExitMappedRegularWorkerResult::PublicationFailed),
                    Err(failure) => {
                        core::mem::forget(failure);
                        Ok(OwnerExitMappedRegularWorkerResult::Retained)
                    }
                };
            }

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(crate::main_heap_page::MainHeapThreadProcessPageExitDrainFailure::Retained {
                    allocator,
                    ..
                }) => {
                    core::mem::forget(allocator);
                    return Ok(OwnerExitMappedRegularWorkerResult::Retained);
                }
            };
            match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => {
                    // The aggregate route has already detached every source page
                    // and completed the old Theap/TLD boundary. The retired
                    // attachment remains in TLS until the final release proof
                    // lets the runtime atomically complete its admission.
                    let Some(blocks) = workload.into_post_exit_blocks() else {
                        // The route has detached A already. Retaining it keeps
                        // both the source route and its worker admission closed
                        // if a private workload invariant ever regresses.
                        core::mem::forget(route);
                        return Ok(OwnerExitMappedRegularWorkerResult::Retained);
                    };
                    let Some(admission) = lifecycle_slot.admission.take() else {
                        // The route has detached A already. Without the exact
                        // linear admission token it must remain terminal; a
                        // generic no-page finalizer may not decrement the
                        // count for this post-exit owner.
                        core::mem::forget(route);
                        return Ok(OwnerExitMappedRegularWorkerResult::Retained);
                    };
                    match free_after_exit(TicketZeroOwnerExitFreeRoute {
                        route,
                        blocks,
                        pair,
                        admission,
                        _consumer: PhantomData,
                    }) {
                        TicketZeroOwnerExitFreeOutcome::Finished(proof) => {
                            Ok(OwnerExitMappedRegularWorkerResult::Completed(proof))
                        }
                        TicketZeroOwnerExitFreeOutcome::Retained(route) => {
                            core::mem::forget(route);
                            Ok(OwnerExitMappedRegularWorkerResult::Retained)
                        }
                        TicketZeroOwnerExitFreeOutcome::Poisoned(poisoned) => {
                            Ok(OwnerExitMappedRegularWorkerResult::Poisoned(poisoned))
                        }
                    }
                }
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::SoleImmediateMedium(route)) => {
                    // The fixed workload retains multiple pages; a special
                    // one-page result means its source invariant no longer holds.
                    core::mem::forget(route);
                    Ok(OwnerExitMappedRegularWorkerResult::Retained)
                }
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
                    core::mem::forget(drain);
                    Ok(OwnerExitMappedRegularWorkerResult::Retained)
                }
                Err(failure) => {
                    core::mem::forget(failure);
                    Ok(OwnerExitMappedRegularWorkerResult::Retained)
                }
            }
        };
        owner_exit_result
    });

    match page_result {
        Some(OwnerExitMappedRegularWorkerResult::Completed(proof)) => {
            match finish_current_thread_after_detached_process_page_route(proof) {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        Some(
            OwnerExitMappedRegularWorkerResult::AllocationFailed
            | OwnerExitMappedRegularWorkerResult::PublicationFailed,
        ) => match finish_current_thread_after_user_destructors() {
            ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::AllocationFailed,
            ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
            ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                TicketZeroLaterThreadPageResult::Unavailable
            }
        },
        Some(OwnerExitMappedRegularWorkerResult::Retained) => {
            retain_current_thread_detached_owner_exit();
            TicketZeroLaterThreadPageResult::Retained
        }
        Some(OwnerExitMappedRegularWorkerResult::Poisoned(poisoned)) => {
            retain_current_thread_detached_owner_exit_with_admission(poisoned.into_admission());
            TicketZeroLaterThreadPageResult::Retained
        }
        None => {
            retain_current_thread_detached_owner_exit();
            TicketZeroLaterThreadPageResult::Retained
        }
    }
}

#[cfg(any())]
enum OwnerExitReclaimWorkerResult {
    Completed(TicketZeroOwnerExitRouteFinished),
    AllocationFailed,
    Retained,
    Poisoned(TicketZeroOwnerExitRoutePoisoned),
}

/// Runs the source-valid post-exit reclamation half of Gate 5C against the
/// dormant ticket-zero process pair.
///
/// A owns one initially-nonfull medium page with a returned local free that
/// source exit collection turns into the immediate head. It crosses the same
/// source-shaped aggregate owner-exit traversal as the mixed witness and
/// receives only its typed sole-medium route. Joined B gets that opaque route,
/// attaches through the normal runtime boundary, reclaims the exact page, uses
/// it once, frees every private A/B client, and completes its own page-bearing
/// lifecycle. Only then can B return the proof that releases A's original
/// admission claim. No client pointer, PageMap lease, or generic normal
/// finalizer crosses the A/B boundary.
#[cfg(any())]
#[doc(hidden)]
pub fn ticket_zero_later_thread_mapped_regular_owner_exit_reclaim(
    reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let page_result = RUNTIME_PROCESS.with_dormant_page_pair(|pair| {
        let lifecycle_slot = current_thread_slot();
        let Some(attachment) = lifecycle_slot.attachment.as_mut() else {
            return Err(());
        };
        let owner_exit_result = {
            let mut allocator = match MainHeapThreadProcessPageAllocator::begin(attachment, pair) {
                Ok(allocator) => allocator,
                Err(_) => return Err(()),
            };
            let workload = match OwnerExitReclaimWorkload::allocate(&mut allocator) {
                Ok(workload) => workload,
                Err(()) => {
                    return match allocator.finish() {
                        Ok(()) => Ok(OwnerExitReclaimWorkerResult::AllocationFailed),
                        Err(failure) => {
                            core::mem::forget(failure);
                            Ok(OwnerExitReclaimWorkerResult::Retained)
                        }
                    };
                }
            };

            let drain = match allocator.begin_thread_exit_drain() {
                Ok(drain) => drain,
                Err(crate::main_heap_page::MainHeapThreadProcessPageExitDrainFailure::Retained {
                    allocator,
                    ..
                }) => {
                    core::mem::forget(allocator);
                    return Ok(OwnerExitReclaimWorkerResult::Retained);
                }
            };
            match unsafe { drain.abandon_mapped_regular_pages_to_process_route() } {
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::SoleImmediateMedium(
                    route,
                )) => {
                    // The completed source traversal already tore down A's
                    // Theap/TLD. Transfer A's admission into the only route
                    // that can cause B's reclaim/drain to return completion.
                    let Some(blocks) = workload.into_blocks() else {
                        core::mem::forget(route);
                        return Ok(OwnerExitReclaimWorkerResult::Retained);
                    };
                    let Some(admission) = lifecycle_slot.admission.take() else {
                        core::mem::forget(route);
                        return Ok(OwnerExitReclaimWorkerResult::Retained);
                    };
                    match reclaim_after_exit(TicketZeroOwnerExitReclaimRoute {
                        route,
                        blocks,
                        request: OWNER_EXIT_RECLAIM_MEDIUM_REQUEST,
                        pair,
                        admission,
                    }) {
                        TicketZeroOwnerExitReclaimOutcome::Finished(proof) => {
                            Ok(OwnerExitReclaimWorkerResult::Completed(proof))
                        }
                        TicketZeroOwnerExitReclaimOutcome::Retained(route) => {
                            core::mem::forget(route);
                            Ok(OwnerExitReclaimWorkerResult::Retained)
                        }
                        TicketZeroOwnerExitReclaimOutcome::Poisoned(poisoned) => {
                            Ok(OwnerExitReclaimWorkerResult::Poisoned(poisoned))
                        }
                    }
                }
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => {
                    // Exactly one initially nonfull medium predecessor must
                    // not silently fall back to the aggregate free-only path.
                    core::mem::forget(route);
                    Ok(OwnerExitReclaimWorkerResult::Retained)
                }
                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
                    core::mem::forget(drain);
                    Ok(OwnerExitReclaimWorkerResult::Retained)
                }
                Err(failure) => {
                    core::mem::forget(failure);
                    Ok(OwnerExitReclaimWorkerResult::Retained)
                }
            }
        };
        owner_exit_result
    });

    match page_result {
        Some(OwnerExitReclaimWorkerResult::Completed(proof)) => {
            match finish_current_thread_after_detached_process_page_route(proof) {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::Completed,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        Some(OwnerExitReclaimWorkerResult::AllocationFailed) => {
            match finish_current_thread_after_user_destructors() {
                ThreadFinishResult::Finished => TicketZeroLaterThreadPageResult::AllocationFailed,
                ThreadFinishResult::Retained => TicketZeroLaterThreadPageResult::Retained,
                ThreadFinishResult::NotAttached | ThreadFinishResult::AlreadyFinished => {
                    TicketZeroLaterThreadPageResult::Unavailable
                }
            }
        }
        Some(OwnerExitReclaimWorkerResult::Retained) => {
            retain_current_thread_detached_owner_exit();
            TicketZeroLaterThreadPageResult::Retained
        }
        Some(OwnerExitReclaimWorkerResult::Poisoned(poisoned)) => {
            retain_current_thread_detached_owner_exit_with_admission(poisoned.into_admission());
            TicketZeroLaterThreadPageResult::Retained
        }
        None => {
            retain_current_thread_detached_owner_exit();
            TicketZeroLaterThreadPageResult::Retained
        }
    }
}

/// Runs one complete persistent later-worker page-engine lifecycle against
/// the dormant ticket-zero process pair.
///
/// This private evidence/control seam attaches a fresh worker exactly once,
/// retains one page engine through a fixed mixed local workload, returns that
/// engine empty, and only then completes normal worker attachment teardown.
/// It enters through the runtime's typed A-side scheduler operation, but never
/// parks or grants any B-side operation. It accepts and returns no allocation
/// pointer, does not route libc allocation, and is deliberately not a
/// concurrent or general worker-owner API.
#[doc(hidden)]
pub fn ticket_zero_later_thread_persistent_local_workload() -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let page_result = (|| {
        let slot = current_thread_slot();
        let attachment = slot.attachment.as_mut().ok_or(())?;
        run_runtime_persistent_local_worker_lifecycle(&RUNTIME_PROCESS, attachment)
    })()
    .ok();
    let finish = finish_current_thread_after_user_destructors();
    match (page_result, finish) {
        (Some(PersistentLocalWorkerResult::Completed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::Completed
        }
        (Some(PersistentLocalWorkerResult::AllocationFailed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::AllocationFailed
        }
        (_, ThreadFinishResult::Retained)
        | (_, _) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroLaterThreadPageResult::Retained
        }
        _ => TicketZeroLaterThreadPageResult::Unavailable,
    }
}

/// Runs one complete live-owner remote-free lifecycle against the dormant
/// ticket-zero process pair.
///
/// The current fresh worker is owner A. It retains one ordinary page engine,
/// gives the supplied joined publisher the one opaque source remote-free
/// capability for B, then collects and reuses the returned block while A is
/// still alive. The typed A-side operation carries the runtime's
/// `READY -> BUSY -> READY` transition; the publisher carries no client
/// pointer and the caller must return it only after B has published or failed
/// without publication. This remains a test-only bounded witness: it does not
/// create concurrent page engines, owner-exit handling, or a libc allocation
/// route.
#[doc(hidden)]
pub fn ticket_zero_later_thread_remote_free_roundtrip(
    publish: TicketZeroRemoteFreePublisher,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    let page_result = (|| {
        let slot = current_thread_slot();
        let attachment = slot.attachment.as_mut().ok_or(())?;
        run_runtime_persistent_remote_worker_lifecycle(&RUNTIME_PROCESS, attachment, publish)
    })()
    .ok();
    let finish = finish_current_thread_after_user_destructors();
    match (page_result, finish) {
        (Some(PersistentRemoteWorkerResult::Completed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::Completed
        }
        (Some(PersistentRemoteWorkerResult::AllocationFailed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::AllocationFailed
        }
        (
            Some(
                PersistentRemoteWorkerResult::PublicationFailed
                | PersistentRemoteWorkerResult::ReuseFailed,
            ),
            ThreadFinishResult::Finished,
        ) => {
            TicketZeroLaterThreadPageResult::Unavailable
        }
        (_, ThreadFinishResult::Retained)
        | (_, _) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroLaterThreadPageResult::Retained
        }
        _ => TicketZeroLaterThreadPageResult::Unavailable,
    }
}

/// Runs one complete later-worker page-engine lifecycle against the dormant
/// ticket-zero process pair.
///
/// This is a private evidence/control seam. It does not route a libc
/// allocation or make a worker a concurrent allocator owner: it accepts no
/// pointer, allocates and frees one local block before returning, and then
/// completes the already-existing worker attachment teardown. The request
/// must be valid for the native engine.
#[doc(hidden)]
pub fn ticket_zero_later_thread_page_roundtrip(
    request: usize,
    zero: bool,
) -> TicketZeroLaterThreadPageResult {
    if !crate::size_class::request_size_is_valid(request) {
        return TicketZeroLaterThreadPageResult::AllocationFailed;
    }
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    enum ScopedPageResult {
        Completed,
        AllocationFailed,
    }

    let page_result = RUNTIME_PROCESS.with_dormant_page_pair(|pair| {
        let slot = current_thread_slot();
        let attachment = slot.attachment.as_mut().ok_or(())?;
        let mut allocator = MainHeapThreadProcessPageAllocator::begin(attachment, pair)
            .map_err(|_| ())?;
        let Some(block) = allocator.allocate(request, zero) else {
            return allocator
                .finish()
                .map(|()| ScopedPageResult::AllocationFailed)
                .map_err(|_| ());
        };
        // SAFETY: `block` is current in this scoped engine and has not left
        // the current worker before its matching free.
        unsafe { allocator.free(block) }.map_err(|_| ())?;
        allocator
            .finish()
            .map(|()| ScopedPageResult::Completed)
            .map_err(|_| ())
    });
    let finish = finish_current_thread_after_user_destructors();
    match (page_result, finish) {
        (Some(ScopedPageResult::Completed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::Completed
        }
        (Some(ScopedPageResult::AllocationFailed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::AllocationFailed
        }
        (_, ThreadFinishResult::Retained)
        | (_, _) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroLaterThreadPageResult::Retained
        }
        _ => TicketZeroLaterThreadPageResult::Unavailable,
    }
}

/// Prevents a later attachment from beginning across libc's direct raw-fork
/// boundary and snapshots whether its narrow quiescent ticket-zero image can
/// survive in the child.
///
/// Libc invokes this after public prepare handlers and before the raw Linux
/// fork-equivalent syscall. It has no C ABI, does not allocate, and does not
/// consume a public `pthread_atfork` registration slot. The child is eligible
/// for preservation only when the caller is the original ticket-zero
/// TPIDR_EL0 image, no later bridge attachment is live or retained, and its
/// ticket-zero source owner is either unmapped or has returned to its source
/// all-free dormant image. That owner may remain in the static staging slot
/// or, after one-time promotion, in the initial thread's pinned compiler-TLS
/// cell. It does not repair a live page engine or client.
#[doc(hidden)]
#[inline]
pub fn before_fork() {
    RUNTIME_FORK_ADMISSION.before_fork_with(|| {
        RUNTIME_PROCESS.is_quiescent_on_initial_thread_for_fork()
    });
}

/// Releases the parent's direct fork admission boundary before public parent
/// handlers run. It preserves any real later-owner count observed while the
/// raw fork was in progress.
#[doc(hidden)]
#[inline]
pub fn after_fork_parent() {
    RUNTIME_FORK_ADMISSION.after_fork_parent();
}

/// Attaches the current pthread worker before its user start routine.
///
/// Libc must call this only for a child whose parent observed
/// [`process_is_active`] and must use its startup handshake to prevent a user
/// start routine from running when this returns anything other than
/// [`ThreadAttachResult::Attached`].
#[doc(hidden)]
pub fn attach_current_thread() -> ThreadAttachResult {
    let slot = current_thread_slot();
    match slot.state {
        ThreadLifecycleState::Attached => return ThreadAttachResult::AlreadyAttached,
        ThreadLifecycleState::Finished => return ThreadAttachResult::Finished,
        ThreadLifecycleState::Retained => return ThreadAttachResult::Retained,
        ThreadLifecycleState::Fresh => {}
    }

    if !RUNTIME_PROCESS.is_active() {
        return ThreadAttachResult::Inactive;
    }
    let Some(admission) = RUNTIME_FORK_ADMISSION.claim_later_thread() else {
        // A count overflow cannot be mistaken for a fresh process state. It
        // is not a practical capacity policy; it is a terminal failure of the
        // bridge's precise fork-admission accounting.
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadAttachResult::Retained;
    };
    slot.admission = Some(admission);

    // SAFETY: a published process owner and its main-thread-minted immutable
    // Heap lease stay in final static slots for the process lifetime.
    let Some(process_owner) = (unsafe { RUNTIME_PROCESS.active_owner() }) else {
        let admission = slot
            .admission
            .take()
            .expect("a claimed worker admission remains in its fresh TLS slot");
        match RUNTIME_FORK_ADMISSION.release_later_thread(admission) {
            Ok(()) => return ThreadAttachResult::Inactive,
            Err(admission) => {
                slot.admission = Some(admission);
            }
        }
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadAttachResult::Retained;
    };
    let ready = match process_owner.ready() {
        Ok(ready) => ready,
        Err(_) => {
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            return ThreadAttachResult::Retained;
        }
    };
    let config = match ready.memory_config() {
        Ok(config) => config,
        Err(_) => {
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            return ThreadAttachResult::Retained;
        }
    };
    let Some(main_heap) = (unsafe { RUNTIME_PROCESS.active_main_heap() }) else {
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadAttachResult::Retained;
    };
    let Some(completion_generation) = claim_native_post_exit_completion_owner_generation() else {
        // A wrapped completion identity could make a process-lifetime
        // completed registry entry appear to belong to this new B. Preserve
        // the claimed admission and close the native lifecycle instead.
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadAttachResult::Retained;
    };

    // SAFETY: libc installed this child TLS image and calls before user code;
    // `slot` retains the returned current-thread owner until its explicit
    // post-destructor finish. The static process owner is never torn down by
    // this slice, and no other code may mutate the allocator TLS roots.
    match unsafe { MainHeapThreadAttachment::begin(main_heap, config) } {
        Ok(attachment) => {
            slot.attachment = Some(attachment);
            slot.begin_post_exit_route_completion_lifecycle(completion_generation);
            slot.state = ThreadLifecycleState::Attached;
            ThreadAttachResult::Attached
        }
        Err(MainHeapThreadAttachmentBeginError::Rejected(_)) => {
            // A foreign root or pre-publication failure cannot safely become
            // an invisible lifecycle skip. Retain the process boundary so no
            // later worker receives a fresh-looking capability.
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            ThreadAttachResult::Retained
        }
        Err(MainHeapThreadAttachmentBeginError::Retained { attachment, .. }) => {
            // Preserve the exact partial owner in this thread's TLS instead
            // of dropping it. The parent handshake will reject this worker.
            slot.attachment = Some(attachment);
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            ThreadAttachResult::Retained
        }
    }
}

/// Finishes one attached worker after libc's cleanup-handler and TSD phases.
#[doc(hidden)]
pub fn finish_current_thread_after_user_destructors() -> ThreadFinishResult {
    // The persistent owner never publishes itself through the Phase-A raw-TLS
    // route registry. Finish it directly so an unrelated retained registry
    // entry cannot strand this exact inline payload at ELF TLS reclamation.
    if current_thread_has_native_persistent_owner() {
        let result = finish_current_thread_native_persistent_owner_after_user_destructors();
        if result != ThreadFinishResult::Finished {
            return result;
        }
        return finish_current_thread_post_exit_route_completions_after_user_destructors();
    }

    let page_owner = {
        let slot_pointer = current_thread_slot_pointer();
        // A native A may not even inspect its TLS slot while B owns the raw
        // handoff. Remove the exact registry entry first, then make the normal
        // page-owner finish decision with no B-side alias remaining.
        let native_owner = match NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot_pointer) {
            NativeLiveRemoteOwnerCurrentClaim::Claimed(route) => Some(route.remove()),
            NativeLiveRemoteOwnerCurrentClaim::Empty
            | NativeLiveRemoteOwnerCurrentClaim::Foreign => None,
            // This source finalizer takes no foreign route, so its current
            // slot lookup retains the normal blocking claim behavior.
            NativeLiveRemoteOwnerCurrentClaim::Busy => {
                unreachable!("an unheld current-slot claim does not return busy")
            }
            NativeLiveRemoteOwnerCurrentClaim::Retained => {
                // SAFETY: retained static state has discarded the raw slot.
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
        };

        // SAFETY: an exact native publication is now gone; a foreign static
        // entry cannot name this compiler-TLS slot.
        let slot = unsafe { &mut *slot_pointer.as_ptr() };
        match slot.state {
            ThreadLifecycleState::Fresh => {
                if native_owner.is_some() {
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain_page_owner();
                    return ThreadFinishResult::Retained;
                }
                return ThreadFinishResult::NotAttached;
            }
            ThreadLifecycleState::Finished => {
                if native_owner.is_some() {
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain_page_owner();
                    return ThreadFinishResult::Retained;
                }
                return ThreadFinishResult::AlreadyFinished;
            }
            ThreadLifecycleState::Retained => return ThreadFinishResult::Retained,
            ThreadLifecycleState::Attached => {}
        }

        let native_route_matches = match slot.page_owner.as_ref() {
            Some(ThreadLifecyclePageOwner::Session(session)) if session.native_live_remote => {
                native_owner.is_some_and(|owner| {
                    owner.slot == slot_pointer && owner.generation == session.generation
                })
            }
            _ => native_owner.is_none(),
        };
        if !native_route_matches {
            // A normal pthread finisher must not move a live native owner out
            // of TLS when its registry entry does not prove it owns the same
            // session. Keep the exact page owner terminal instead.
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return ThreadFinishResult::Retained;
        }
        slot.page_owner.take()
    };

    let result = match page_owner {
        Some(owner) => finish_current_thread_page_owner_after_user_destructors(owner),
        None => finish_current_thread_no_page_after_user_destructors(),
    };
    if result != ThreadFinishResult::Finished {
        return result;
    }

    finish_current_thread_post_exit_route_completions_after_user_destructors()
}

/// Finishes a native prepared exit that already holds its own live-owner
/// handoff `BUSY` in compiler TLS.
///
/// This is deliberately separate from
/// [`finish_current_thread_after_user_destructors`]. The ordinary finisher
/// first claims the current raw-TLS registry entry before it reads the slot,
/// because a foreign B may own that entry. A native deferred exit instead
/// carries its own exact guard from preparation through detached-route
/// publication. Reclaiming that same guard through the ordinary scan would
/// wait on itself forever; the prepared state is the typed proof that no B
/// can borrow the old TLS image while this current A takes it directly.
fn finish_current_thread_prepared_native_after_user_destructors() -> ThreadFinishResult {
    let page_owner = {
        let slot = current_thread_slot();
        match slot.state {
            ThreadLifecycleState::Fresh => return ThreadFinishResult::NotAttached,
            ThreadLifecycleState::Finished => return ThreadFinishResult::AlreadyFinished,
            ThreadLifecycleState::Retained => return ThreadFinishResult::Retained,
            ThreadLifecycleState::Attached => {}
        }
        let owns_native_handoff = matches!(
            slot.page_owner.as_ref(),
            Some(ThreadLifecyclePageOwner::PreparedExit(prepared))
                if prepared.native_live_remote_handoff.is_some()
        );
        if !owns_native_handoff {
            // This helper is reachable only after the native preparation
            // retained the exact raw-TLS guard. Without it, treating a
            // prepared owner as self-owned would bypass the normal B-side
            // exclusion protocol.
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return ThreadFinishResult::Retained;
        }
        slot.page_owner
            .take()
            .expect("the checked native prepared owner remains in current TLS")
    };

    let result = finish_current_thread_page_owner_after_user_destructors(page_owner);
    if result != ThreadFinishResult::Finished {
        return result;
    }
    finish_current_thread_post_exit_route_completions_after_user_destructors()
}

/// Removes every detached-route scheduler token and releases every matched A
/// admission only after this current B worker has completed its own attachment
/// lifecycle.
///
/// Each completion is written by the native post-exit route only after its
/// final PageMap release. Its stable entry carries the parked token and A-side
/// proof, while B's compiler TLS carries only the opaque owner identity and
/// scalar count. That keeps client addresses private and prevents a normal
/// no-page finalizer from consuming an abandoned source route. B may receive
/// several such completions, but neither the dormant pair nor any A admission
/// becomes quiescent until this ordinary B teardown has succeeded.
fn finish_current_thread_post_exit_route_completions_after_user_destructors() -> ThreadFinishResult {
    let slot_pointer = current_thread_slot_pointer();
    let (owner, expected_count) = {
        // SAFETY: this function runs on the same B thread that has just
        // completed the ordinary attachment finish. No registry entry may
        // dereference this opaque identity; it is used only for equality.
        let slot = unsafe { &mut *slot_pointer.as_ptr() };
        let Some(completion) = slot.post_exit_route_completion_owner_after_finish(slot_pointer)
        else {
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return ThreadFinishResult::Retained;
        };
        completion
    };

    match NATIVE_POST_EXIT_ROUTE.finish_completions_for_owner(owner, expected_count) {
        NativePostExitRouteCompletionsFinishResult::Finished => {
            // SAFETY: only this current B can change its TLS scalar after the
            // source finish. The registry already consumed exactly the count
            // it observed above; a mismatch is terminal rather than a reason
            // to replay a completed route.
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            if slot.finish_post_exit_route_completions(owner, expected_count) {
                ThreadFinishResult::Finished
            } else {
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                ThreadFinishResult::Retained
            }
        }
        NativePostExitRouteCompletionsFinishResult::Retained => {
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            slot.state = ThreadLifecycleState::Retained;
            ThreadFinishResult::Retained
        }
    }
}

/// Selects the native-shadow owner-exit route for a current worker with live
/// C allocations. This is a compile-time libc friend boundary, not a public
/// allocator API: it is the only path that turns a parked native session into
/// the bounded process-static post-exit route. Ordinary runtime callers keep
/// using [`finish_current_thread_after_user_destructors`], whose live session
/// rejection remains the guard against accidentally finalizing an abandoned
/// engine as no-page state.
#[doc(hidden)]
pub fn finish_current_thread_native_after_user_destructors() -> ThreadFinishResult {
    // This source shape has no raw-TLS registry entry or client ledger to
    // claim. Its exact compiler-TLS payload must be consumed before this
    // function is allowed to return to libc's thread-exit path.
    if current_thread_has_native_persistent_owner() {
        return finish_current_thread_after_user_destructors();
    }

    let slot_pointer = current_thread_slot_pointer();
    let native_session_generation = match NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot_pointer)
    {
        NativeLiveRemoteOwnerCurrentClaim::Claimed(route) => {
            // SAFETY: B cannot borrow this native A session until this guard
            // restores it. That makes the ledger decision below a real
            // exclusive decision rather than an unsynchronized TLS read.
            let deferred_exit = unsafe {
                let slot = &mut *slot_pointer.as_ptr();
                match (slot.state, slot.page_owner.as_ref()) {
                    (
                        ThreadLifecycleState::Attached,
                        Some(ThreadLifecyclePageOwner::Session(session)),
                    ) if session.native_live_remote
                        && session.generation == route.owner().generation =>
                    {
                        // A joined pre-exit publication stays solely on A's
                        // source remote head; the source drain force-collects
                        // it before this session's parked engine detaches.
                        // Its presence cannot turn a distinct local client
                        // into an all-free session. That client still needs
                        // the typed native route, whose terminal B proof owns
                        // A's admission release.
                        Some(session.clients.has_live_client())
                    }
                    _ => None,
                }
            };
            let Some(needs_deferred_exit) = deferred_exit else {
                let slot = unsafe { &mut *slot_pointer.as_ptr() };
                slot.state = ThreadLifecycleState::Retained;
                route.retain();
                return ThreadFinishResult::Retained;
            };
            let generation = route.owner().generation;
            route.restore();
            needs_deferred_exit.then_some(generation)
        }
        NativeLiveRemoteOwnerCurrentClaim::Retained => {
            // SAFETY: retained static state has no raw TLS alias left.
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return ThreadFinishResult::Retained;
        }
        // The typed native finish route begins without a foreign handoff, so
        // it uses the blocking current-slot claim rather than a retry result.
        NativeLiveRemoteOwnerCurrentClaim::Busy => {
            unreachable!("an unheld current-slot claim does not return busy")
        }
        NativeLiveRemoteOwnerCurrentClaim::Empty
        | NativeLiveRemoteOwnerCurrentClaim::Foreign => {
            // SAFETY: the current slot has no B-side native handoff. A
            // foreign registry entry was restored before this branch.
            let slot = unsafe { &mut *slot_pointer.as_ptr() };
            match slot.state {
                ThreadLifecycleState::Fresh => return ThreadFinishResult::NotAttached,
                ThreadLifecycleState::Finished => return ThreadFinishResult::AlreadyFinished,
                ThreadLifecycleState::Retained => return ThreadFinishResult::Retained,
                ThreadLifecycleState::Attached => {}
            }
            if matches!(
                slot.page_owner.as_ref(),
                Some(ThreadLifecyclePageOwner::Session(session)) if session.native_live_remote
            ) {
                // A C-visible session may only be finished through its exact
                // registry entry; without it neither A nor B has a valid owner
                // handoff to explain the raw pointer lifetime.
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
            None
        }
    };

    if let Some(generation) = native_session_generation {
        loop {
            let session = CurrentThreadPageOwnerSessionHandle {
                generation,
                _current_thread_only: PhantomData,
            };
            match session.prepare_native_deferred_exit() {
                Ok(()) => break,
                Err(CurrentThreadPageOwnerSessionError::Busy) => {
                    // The session restored its exact parked token before
                    // returning. A peer owns only a bounded scheduler or
                    // PageMap handoff, so wait rather than prematurely
                    // retaining A after its user destructors have run.
                    core::hint::spin_loop();
                }
                Err(_) => {
                    // Every non-busy error leaves a source owner, attachment,
                    // or ledger whose post-destructor route cannot be
                    // replayed. Preserve that concrete state terminally;
                    // returning `Retained` alone would incorrectly leave the
                    // process scheduler and worker admission looking live.
                    retain_current_thread_live_page_owner();
                    return ThreadFinishResult::Retained;
                }
            }
        }
        // Preparation retained A's own raw-TLS publication `BUSY` through
        // replacement-route publication. Do not enter the ordinary finisher,
        // which correctly waits on a foreign `BUSY` handoff but would wait on
        // this current A forever.
        return finish_current_thread_prepared_native_after_user_destructors();
    }
    finish_current_thread_after_user_destructors()
}

/// Consumes the continuously stored native owner at the source destructor
/// boundary. No client ledger participates: the lower engine follows source
/// collect-abandon, releasing all-free pages and abandoning surviving live
/// pages before its Theap/TLD boundary. A pre-drain refusal restores the exact
/// engine; a failure after source queue state changed retains the terminal
/// engine and must fail-stop rather than reach native thread return. Since libc
/// reclaims the ELF TLS image immediately after this boundary, an unresolved
/// retained payload cannot become a normal thread-return result.
fn finish_current_thread_native_persistent_owner_after_user_destructors(
) -> ThreadFinishResult {
    let teardown = current_thread_native_persistent_owner_cell()
        .teardown(|mut owner| owner.as_mut().get_mut().teardown());
    match teardown {
        Ok(()) => {}
        Err(
            PersistentCompilerTlsOwnerTeardownError::Owner(())
            | PersistentCompilerTlsOwnerTeardownError::State(_),
        ) => {
            fail_stop_with_current_thread_native_owner();
        }
    }
    current_thread_slot().native_persistent_owner_installed = false;

    let slot = current_thread_slot();
    let Some(admission) = slot.admission.take() else {
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadFinishResult::Retained;
    };
    match RUNTIME_FORK_ADMISSION.release_later_thread(admission) {
        Ok(()) => {
            slot.state = ThreadLifecycleState::Finished;
            ThreadFinishResult::Finished
        }
        Err(admission) => {
            slot.admission = Some(admission);
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            ThreadFinishResult::Retained
        }
    }
}

/// The ordinary no-page half of the runtime finish boundary.  It is separate
/// from [`finish_current_thread_after_user_destructors`] so a page-bearing TLS
/// owner cannot accidentally become a no-page attachment merely because its
/// allocator borrow was suspended into a typed token.
fn finish_current_thread_no_page_after_user_destructors() -> ThreadFinishResult {
    let slot = current_thread_slot();
    match slot.state {
        ThreadLifecycleState::Fresh => return ThreadFinishResult::NotAttached,
        ThreadLifecycleState::Finished => return ThreadFinishResult::AlreadyFinished,
        ThreadLifecycleState::Retained => return ThreadFinishResult::Retained,
        ThreadLifecycleState::Attached => {}
    }
    let Some(admission) = slot.admission.take() else {
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadFinishResult::Retained;
    };

    let Some(mut attachment) = slot.attachment.take() else {
        slot.admission = Some(admission);
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadFinishResult::Retained;
    };
    match attachment.finish_after_user_destructors() {
        Ok(()) => {
            match RUNTIME_FORK_ADMISSION.release_later_thread(admission) {
                Ok(()) => {
                    slot.state = ThreadLifecycleState::Finished;
                    ThreadFinishResult::Finished
                }
                Err(admission) => {
                    // The source owner is already torn down, but its fork
                    // accounting no longer names this transition. Keep the
                    // exact claim terminally retained rather than claiming a
                    // child-preserving boundary from an inconsistent count.
                    slot.admission = Some(admission);
                    slot.state = ThreadLifecycleState::Retained;
                    RUNTIME_PROCESS.retain();
                    ThreadFinishResult::Retained
                }
            }
        }
        Err(_) => {
            // The `must_use` owner still carries concrete roots/list/metadata
            // state. Retain it in TLS and stop admitting new workers rather
            // than claiming that `_mi_thread_done` completed.
            slot.attachment = Some(attachment);
            slot.admission = Some(admission);
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            ThreadFinishResult::Retained
        }
    }
}

/// Returns the dormant-pair scheduler to `READY` only after a typed post-exit
/// route has terminally released, then consumes that route's matching A-side
/// admission proof. Both aggregate-free and sole-page-reclaim outcomes use
/// this one boundary; neither may invoke the ordinary no-page finalizer for
/// A after its source traversal already tore down the old Theap/TLD.
fn finish_current_thread_page_owner_after_post_exit_route(
    operation: RuntimeDormantPageOperation,
    proof: TicketZeroOwnerExitRouteFinished,
) -> ThreadFinishResult {
    let finish_state = operation.finish_state();
    match operation.settle(finish_state) {
        Ok(()) => finish_current_thread_after_detached_process_page_route(proof),
        Err(operation) => {
            // The route did physically finish, but ticket zero's scheduler
            // no longer recognizes the matching current owner. Keep A's
            // exact admission terminally represented instead of making
            // either boundary look quiescent.
            drop(operation);
            retain_current_thread_detached_owner_exit_with_admission(proof.into_admission());
            ThreadFinishResult::Retained
        }
    }
}

/// Transfers a fully detached native-shadow route out of A's compiler TLS
/// into the private metadata-backed C free registry.
///
/// This is deliberately after the source aggregate has torn down A's
/// Theap/TLD and after its long PageMap lease has become route-owned short
/// access. Before the scheduler releases A's active `BUSY` claim, the route
/// reserves a `BUSY` registry entry that concurrent source exits classify as
/// live but raw-C consumers cannot read. The matching parked route token and
/// complete entry then publish together. The prior live-owner handoff remains
/// `BUSY` until after that publication; its later `EMPTY` Release store gives
/// a B that waited on the old handoff a happens-before edge to retry the new
/// route. That token may leave the parked count only after a B free returns
/// the exact typed terminal proof and B finishes its own no-page lifecycle.
/// A's TLS becomes finished because it owns no remaining route or admission
/// capability, not because the global worker-admission count has been
/// released.
fn defer_current_thread_native_post_exit_route(
    operation: RuntimeDormantPageOperation,
    registry_config: MemoryConfig,
    native_live_remote_handoff: NativeLiveRemoteOwnerGuard,
    build_route: impl FnOnce(LaterThreadAdmissionClaim) -> NativePostExitFreeRoute,
) -> ThreadFinishResult {
    let admission = {
        let slot = current_thread_slot();
        let Some(admission) = slot.admission.take() else {
            // The closure still owns the exact detached source route and its
            // private client ledger. Do not let a missing admission drop that
            // route while the scheduler operation becomes terminal.
            core::mem::forget(build_route);
            drop(operation);
            retain_current_thread_detached_owner_exit();
            return ThreadFinishResult::Retained;
        };
        admission
    };
    let route = build_route(admission);
    let reservation = match NATIVE_POST_EXIT_ROUTE.reserve(registry_config) {
        Ok(reservation) => reservation,
        Err(()) => {
            // Registry growth failed or a prior terminal entry closed future
            // publication before this source owner could release `BUSY`.
            // Preserve the exact detached route and admission rather than
            // reopening the scheduler over an unregistered Theap/TLD exit.
            let route = core::mem::ManuallyDrop::new(route);
            // SAFETY: this retained route will never be dropped. Reading its
            // exact non-Copy admission transfers the one fork-count claim
            // into A's terminal TLS slot without exposing a client or route.
            let admission = unsafe { core::ptr::read(route.admission_ptr()) };
            drop(operation);
            retain_current_thread_detached_owner_exit_with_admission(admission);
            return ThreadFinishResult::Retained;
        }
    };
    let parked = match operation.park_detached_post_exit() {
        Ok(parked) => parked,
        Err(operation) => {
            // The source route has already detached A. Preserve its exact
            // admission and page facts while the failed scheduler conversion
            // keeps the process terminal; no normal finalizer can repair
            // that one-way boundary.
            reservation.retain();
            let route = core::mem::ManuallyDrop::new(route);
            // SAFETY: this retained route will never be dropped. Reading its
            // exact non-Copy admission transfers the only fork-count claim
            // into A's terminal TLS slot without exposing a client or route.
            let admission = unsafe { core::ptr::read(route.admission_ptr()) };
            drop(operation);
            retain_current_thread_detached_owner_exit_with_admission(admission);
            return ThreadFinishResult::Retained;
        }
    };
    reservation.publish(NativePostExitRoute { parked, route });
    // Publish the replacement route before making the raw-TLS entry empty.
    // A B that first missed the detached registry, then waited for this
    // `BUSY` handoff and observes `EMPTY`, must retry the detached lookup;
    // the two Release publications make that retry observe the exact route
    // rather than treating its valid C client as foreign.
    let _ = native_live_remote_handoff.remove();
    let slot = current_thread_slot();
    // The source aggregate completed the old Theap/TLD boundary. Its
    // detached route—not this attachment—now owns every page client and A
    // admission, so a later normal finalizer cannot touch this historical
    // attachment.
    drop(slot.attachment.take());
    slot.state = ThreadLifecycleState::Finished;
    ThreadFinishResult::Finished
}

/// Moves one typed mapped-regular reclamation route into its private fresh-B
/// consumer. The route retains A's admission until that consumer has adopted,
/// used, drained, and finished B; both source-valid medium and direct-small
/// predecessors converge here after their distinct A-side source drains.
fn finish_current_thread_page_owner_reclaim_route(
    operation: RuntimeDormantPageOperation,
    route: MainHeapThreadProcessPageExitMappedRegularRoute<'static>,
    clients: DetachedOwnerExitClientLedger,
    request: usize,
    pair: ProcessPageArenaLease,
    reclaim_after_exit: TicketZeroOwnerExitReclaimConsumer,
) -> ThreadFinishResult {
    let admission = {
        let slot = current_thread_slot();
        let Some(admission) = slot.admission.take() else {
            core::mem::forget(route);
            drop(operation);
            retain_current_thread_detached_owner_exit();
            return ThreadFinishResult::Retained;
        };
        admission
    };
    match reclaim_after_exit(TicketZeroOwnerExitReclaimRoute {
        route,
        clients,
        request,
        pair,
        admission,
    }) {
        TicketZeroOwnerExitReclaimOutcome::Finished(proof) => {
            finish_current_thread_page_owner_after_post_exit_route(operation, proof)
        }
        TicketZeroOwnerExitReclaimOutcome::Retained(route) => {
            core::mem::forget(route);
            drop(operation);
            retain_current_thread_detached_owner_exit();
            ThreadFinishResult::Retained
        }
        TicketZeroOwnerExitReclaimOutcome::Poisoned(poisoned) => {
            drop(operation);
            retain_current_thread_detached_owner_exit_with_admission(poisoned.into_admission());
            ThreadFinishResult::Retained
        }
    }
}

/// Completes the all-free side of an active parked TLS page-owner session.
///
/// Unlike a prepared exit, this path has no detached post-exit client route
/// and may finish only when the session has no locally live client. It still
/// does *not* use the no-page finalizer: the parked engine must resume, clear
/// the source fast slot, force-collect joined source-published heads, release
/// pages that then become all-free, and complete the attachment's page-drain
/// teardown before its worker-admission claim can leave the runtime. Only a
/// live or transferred client stays terminally retained for the typed
/// owner-exit path instead.
fn finish_current_thread_all_free_page_owner_after_user_destructors(
    mut session: CurrentThreadPageOwnerSession,
) -> ThreadFinishResult {
    if !session.clients.can_enter_all_free_thread_exit_drain() {
        retain_current_thread_page_owner_session(session);
        return ThreadFinishResult::Retained;
    }
    if session
        .clients
        .release_overflow_without_live_clients()
        .is_err()
    {
        retain_current_thread_page_owner_session(session);
        return ThreadFinishResult::Retained;
    }

    let Some(mut parked) = session.parked.take() else {
        retain_current_thread_live_page_owner();
        return ThreadFinishResult::Retained;
    };
    let engine = loop {
        let resume = {
            let slot = current_thread_slot();
            let Some(attachment) = slot.attachment.as_mut() else {
                session.parked = Some(parked);
                retain_current_thread_page_owner_session(session);
                return ThreadFinishResult::Retained;
            };
            parked.resume(attachment)
        };
        match resume {
            Ok(engine) => break engine,
            Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked: retry }) => {
                parked = retry;
                if page_owner_transition_is_retryable(
                    RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire),
                ) {
                    // An independently parked native session is completing a
                    // bounded operation, or just changed the parked count
                    // between this token's load and CAS. Its scheduler token
                    // still represents this worker's parked owner, so this
                    // all-free destructor finish may retry rather than
                    // retaining a valid local owner.
                    core::hint::spin_loop();
                    continue;
                }
                session.parked = Some(parked);
                retain_current_thread_page_owner_session(session);
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy { parked: retry, .. }) => {
                parked = retry;
                if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) != PAGE_OWNER_RETAINED
                    && RUNTIME_PROCESS.state.load(Ordering::Acquire) != PROCESS_RETAINED
                {
                    // A short post-exit route can transiently hold the map
                    // while the scheduler still names parked normal engines.
                    // It owns no B attachment, so wait for its exact free to
                    // restore the map instead of poisoning this all-free B.
                    core::hint::spin_loop();
                    continue;
                }
                session.parked = Some(parked);
                retain_current_thread_page_owner_session(session);
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::Rejected {
                parked: retry,
                ..
            }) => {
                session.parked = Some(retry);
                retain_current_thread_page_owner_session(session);
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::Retained { terminal, .. }) => {
                core::mem::forget(terminal);
                retain_current_thread_live_page_owner();
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
                retain_current_thread_live_page_owner();
                return ThreadFinishResult::Retained;
            }
        }
    };
    // The resumed engine now owns the only parked token. Dropping the empty
    // session cannot invoke the parked-token retention path.
    drop(session);

    let (drain, operation, pair) = match engine.begin_thread_exit_drain() {
        Ok(parts) => parts,
        Err(engine) => {
            core::mem::forget(engine);
            retain_current_thread_live_page_owner();
            return ThreadFinishResult::Retained;
        }
    };
    // The all-free path has no post-exit consumer. The pair remains an
    // identity witness for the engine transition only and cannot authorize a
    // second page lifecycle once the drain begins.
    drop(pair);

    if let Err(failure) = drain.finish() {
        core::mem::forget(failure);
        drop(operation);
        retain_current_thread_live_page_owner();
        return ThreadFinishResult::Retained;
    }

    let attachment_finished = {
        let slot = current_thread_slot();
        match slot.attachment.as_mut() {
            Some(attachment) => attachment.finish_after_page_drain().is_ok(),
            None => false,
        }
    };
    if !attachment_finished {
        drop(operation);
        retain_current_thread_live_page_owner();
        return ThreadFinishResult::Retained;
    }

    let admission = {
        let slot = current_thread_slot();
        let Some(admission) = slot.admission.take() else {
            drop(operation);
            retain_current_thread_live_page_owner();
            return ThreadFinishResult::Retained;
        };
        admission
    };
    // The page drain already completed the old Theap/TLD transition. Remove
    // the torn-down diagnostic owner before a successful scheduler settle can
    // make the dormant ticket-zero pair available again.
    drop(current_thread_slot().attachment.take());

    let finish_state = operation.finish_state();
    match operation.settle(finish_state) {
        Ok(()) => match RUNTIME_FORK_ADMISSION.release_later_thread(admission) {
            Ok(()) => {
                current_thread_slot().state = ThreadLifecycleState::Finished;
                ThreadFinishResult::Finished
            }
            Err(admission) => {
                let slot = current_thread_slot();
                slot.admission = Some(admission);
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain();
                ThreadFinishResult::Retained
            }
        },
        Err(operation) => {
            let slot = current_thread_slot();
            slot.admission = Some(admission);
            drop(operation);
            retain_current_thread_live_page_owner();
            ThreadFinishResult::Retained
        }
    }
}

/// Completes the page-bearing half of the ordinary runtime finish boundary.
///
/// The suspended owner is current-thread compiler-TLS state, not an
/// externally callable allocator route.  It resumes only against the exact
/// attachment that recorded its suspended marker, clears the source fast
/// slot through `begin_thread_exit_drain`, and enters the one aggregate
/// `MI_ABANDON` coordinator.  A live post-exit route remains the sole owner
/// of A's client identities and admission claim until B returns its typed
/// terminal proof.  Every failure stays terminal; this function must never
/// fall back to [`finish_current_thread_no_page_after_user_destructors`].
fn finish_current_thread_page_owner_after_user_destructors(
    owner: ThreadLifecyclePageOwner,
) -> ThreadFinishResult {
    let ThreadLifecyclePageOwner::PreparedExit(ThreadLifecyclePreparedPageOwner {
        parked,
        exit,
        native_live_remote_handoff,
    }) = owner
    else {
        let ThreadLifecyclePageOwner::Session(session) = owner else {
            unreachable!("the page-owner state has exactly active and prepared variants");
        };
        return finish_current_thread_all_free_page_owner_after_user_destructors(session);
    };

    let mut parked = parked;
    let mut native_live_remote_handoff = native_live_remote_handoff;
    let engine = loop {
        let resume = {
            let slot = current_thread_slot();
            let Some(attachment) = slot.attachment.as_mut() else {
                slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
                    ThreadLifecyclePreparedPageOwner {
                        parked,
                        exit,
                        native_live_remote_handoff,
                    },
                ));
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            };
            parked.resume(attachment)
        };
        match resume {
            Ok(engine) => break engine,
            Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked: retry }) => {
                parked = retry;
                if page_owner_transition_is_retryable(
                    RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire),
                ) {
                    // A peer's deferred owner exit temporarily owns the one
                    // scheduler/PageMap mutation slot. This worker still owns
                    // its separate parked token and complete deferred route,
                    // so it must wait for the peer to republish the parked
                    // count rather than retaining a valid source exit.
                    core::hint::spin_loop();
                    continue;
                }
                let slot = current_thread_slot();
                slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
                    ThreadLifecyclePreparedPageOwner {
                        parked,
                        exit,
                        native_live_remote_handoff,
                    },
                ));
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy {
                parked: retry,
                ..
            }) => {
                parked = retry;
                if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) != PAGE_OWNER_RETAINED
                    && RUNTIME_PROCESS.state.load(Ordering::Acquire) != PROCESS_RETAINED
                {
                    // A peer may have republished the scheduler while its
                    // detached route completes one short PageMap operation.
                    // The current prepared exit has not crossed its own drain
                    // boundary yet, so retry against the same parked token.
                    core::hint::spin_loop();
                    continue;
                }
                let slot = current_thread_slot();
                slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
                    ThreadLifecyclePreparedPageOwner {
                        parked,
                        exit,
                        native_live_remote_handoff,
                    },
                ));
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::Rejected {
                parked: retry,
                ..
            }) => {
                let slot = current_thread_slot();
                slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
                    ThreadLifecyclePreparedPageOwner {
                        parked: retry,
                        exit,
                        native_live_remote_handoff,
                    },
                ));
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::Retained {
                terminal,
                ..
            }) => {
                core::mem::forget(terminal);
                let slot = current_thread_slot();
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
                let slot = current_thread_slot();
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
        }
    };

    let (drain, operation, pair) = match engine.begin_thread_exit_drain() {
        Ok(parts) => parts,
        Err(engine) => {
            // The engine still owns its attachment borrow and PageMap lease.
            // It cannot be returned to compiler TLS as a self-reference, so
            // retain that exact source owner rather than dropping into a
            // no-page finalizer.
            core::mem::forget(engine);
            retain_current_thread_live_page_owner();
            return ThreadFinishResult::Retained;
        }
    };
    let DetachedOwnerExit {
        clients,
        disposition,
    } = exit;
    // `pair` remains a copyable, identity-checked process view after the old
    // attachment tears down, unlike `MainHeapThreadAttachment::memory_config`,
    // which intentionally rejects that post-Theap boundary. Capture the
    // immutable configuration before source abandonment so metadata registry
    // growth never needs to reopen A's attachment.
    let native_registry_config = if matches!(&disposition, DetachedOwnerExitDisposition::NativeDeferred) {
        match pair.memory_config() {
            Ok(config) => Some(config),
            Err(_) => {
                core::mem::forget(drain);
                drop(operation);
                retain_current_thread_live_page_owner();
                return ThreadFinishResult::Retained;
            }
        }
    } else {
        None
    };

    // Direct small has a distinct source entrance because its owner exit must
    // prove and clear the exact rounded direct-cache image before the page
    // can cross into a regular post-exit route. It nevertheless converges on
    // the same opaque B-side adoption capability and admission proof as the
    // aggregate predecessor below. The disposition names its first source
    // client only by an opaque ledger key; the raw address stays private here.
    if let DetachedOwnerExitDisposition::SoleImmediateMappedRegularReclaim {
        source: DetachedOwnerExitReclaimSource::DirectSmall { first },
        request,
        reclaim_after_exit,
    } = &disposition
    {
        let Some(first_block) = clients.block_for(*first) else {
            drop(operation);
            retain_current_thread_detached_owner_exit();
            return ThreadFinishResult::Retained;
        };
        // SAFETY: preparation recorded this exact live client in the detached
        // ledger and no producer survives. The lower source boundary validates
        // the direct-cache and immediate-head image while it owns A's drain.
        match unsafe { drain.abandon_mapped_small_or_medium_to_process_route(first_block) } {
            Ok(route) => {
                return finish_current_thread_page_owner_reclaim_route(
                    operation,
                    route,
                    clients,
                    *request,
                    pair,
                    *reclaim_after_exit,
                );
            }
            Err(failure) => {
                core::mem::forget(failure);
                drop(operation);
                retain_current_thread_detached_owner_exit();
                return ThreadFinishResult::Retained;
            }
        }
    }

    // SAFETY: `ThreadLifecyclePageOwner` was installed only after the current
    // attachment's matching persistent engine had suspended. It owns every
    // remaining client identity in `exit`, no scoped pre-exit producer
    // survives, and this normal finish is the source fast-slot-clear boundary.
    let route_begin = if matches!(&disposition, DetachedOwnerExitDisposition::NativeDeferred) {
        match NATIVE_POST_EXIT_ROUTE.view() {
            NativePostExitRouteRegistryView::Live => {
                // SAFETY: the metadata-backed registry proved every prior
                // private OS-list member remains owned by one live typed
                // route. This source drain can append only its own exact
                // member; it receives neither a list traversal nor another
                // route's client address.
                let known_os_abandoned_members = unsafe {
                    ThreadExitKnownPostExitOsAbandonedList::from_native_post_exit_route_registry()
                };
                unsafe {
                drain.abandon_mapped_regular_pages_to_process_route_with_known_os_abandoned_members(
                    known_os_abandoned_members,
                )
                }
            }
            // SAFETY: no live native route exists, so the standard source
            // preflight retains its conservative empty-list requirement.
            NativePostExitRouteRegistryView::Empty => unsafe {
                drain.abandon_mapped_regular_pages_to_process_route()
            },
            NativePostExitRouteRegistryView::Retained => {
                // A prior detached route no longer has retryable source
                // ownership. Do not use its former list membership as a
                // preflight proof or run another A through normal teardown.
                core::mem::forget(drain);
                drop(operation);
                retain_current_thread_detached_owner_exit();
                return ThreadFinishResult::Retained;
            }
        }
    } else {
        // SAFETY: non-native routes never receive the private registry proof
        // and therefore keep the ordinary empty-list source entrance.
        unsafe { drain.abandon_mapped_regular_pages_to_process_route() }
    };
    match route_begin {
        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => {
            match disposition {
                DetachedOwnerExitDisposition::SequentialFree {
                    free_after_exit,
                    post_exit_remote_publication_group,
                } => {
                let admission = {
                    let slot = current_thread_slot();
                    let Some(admission) = slot.admission.take() else {
                        core::mem::forget(route);
                        drop(operation);
                        retain_current_thread_detached_owner_exit();
                        return ThreadFinishResult::Retained;
                    };
                    admission
                };
                match free_after_exit(TicketZeroOwnerExitFreeRoute {
                    route,
                    clients,
                    post_exit_remote_publication_group,
                    pair,
                    admission,
                    _consumer: PhantomData,
                }) {
                    TicketZeroOwnerExitFreeOutcome::Finished(proof) => {
                        finish_current_thread_page_owner_after_post_exit_route(operation, proof)
                    }
                    TicketZeroOwnerExitFreeOutcome::Retained(route) => {
                        core::mem::forget(route);
                        drop(operation);
                        retain_current_thread_detached_owner_exit();
                        ThreadFinishResult::Retained
                    }
                    TicketZeroOwnerExitFreeOutcome::Poisoned(poisoned) => {
                        drop(operation);
                        retain_current_thread_detached_owner_exit_with_admission(
                            poisoned.into_admission(),
                        );
                        ThreadFinishResult::Retained
                    }
                }
                }
                DetachedOwnerExitDisposition::NativeDeferred => {
                    let registry_config = native_registry_config
                        .expect("the native deferred route captured its immutable process config");
                    let Some(handoff) = native_live_remote_handoff.take() else {
                        // The detached route is ready, but its matching
                        // raw-TLS publication vanished before the replacement
                        // C route could publish. Keep the source route
                        // terminal rather than exposing an ownership gap.
                        core::mem::forget(route);
                        drop(operation);
                        retain_current_thread_detached_owner_exit();
                        return ThreadFinishResult::Retained;
                    };
                    defer_current_thread_native_post_exit_route(operation, registry_config, handoff, |admission| {
                        NativePostExitFreeRoute::Aggregate(TicketZeroOwnerExitFreeRoute {
                            route,
                            clients,
                            post_exit_remote_publication_group: None,
                            pair,
                            admission,
                            _consumer: PhantomData,
                        })
                    })
                }
                DetachedOwnerExitDisposition::SoleImmediateMappedRegularReclaim { .. } => {
                    // A source-proved sole-page reclamation must not silently
                    // use the aggregate release route. Retain the exact source
                    // result rather than broadening a mismatched lifecycle
                    // transition.
                    core::mem::forget(route);
                    drop(operation);
                    retain_current_thread_detached_owner_exit();
                    ThreadFinishResult::Retained
                }
            }
        }
        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::SoleImmediateMedium(
            route,
        )) => {
            match disposition {
                DetachedOwnerExitDisposition::SequentialFree { .. } => {
                    // A sequential detached ledger can describe several live
                    // pages, so a sole adoption result cannot name its private
                    // source image.
                    core::mem::forget(route);
                    drop(operation);
                    retain_current_thread_detached_owner_exit();
                    ThreadFinishResult::Retained
                }
                DetachedOwnerExitDisposition::SoleImmediateMappedRegularReclaim {
                    source: DetachedOwnerExitReclaimSource::AggregateTraversal,
                    request,
                    reclaim_after_exit,
                } => finish_current_thread_page_owner_reclaim_route(
                    operation,
                    route,
                    clients,
                    request,
                    pair,
                    reclaim_after_exit,
                ),
                DetachedOwnerExitDisposition::SoleImmediateMappedRegularReclaim {
                    source: DetachedOwnerExitReclaimSource::DirectSmall { .. },
                    ..
                } => {
                    // Direct-small returned above through its own cache-
                    // validating source drain. It must not appear as an
                    // aggregate `SoleImmediateMedium` result.
                    core::mem::forget(route);
                    drop(operation);
                    retain_current_thread_detached_owner_exit();
                    ThreadFinishResult::Retained
                }
                DetachedOwnerExitDisposition::NativeDeferred => {
                    // The source traversal already proved this exact sole
                    // initially-nonfull medium page. C does not receive an
                    // adoption capability: its later raw free is accepted
                    // only after the opaque route proves the exact address
                    // against A's private ledger, then uses the existing
                    // source failed-reclaim terminal-free path.
                    let registry_config = native_registry_config
                        .expect("the native deferred route captured its immutable process config");
                    let Some(handoff) = native_live_remote_handoff.take() else {
                        // See the aggregate route above: the source route
                        // cannot safely become C-routable without the exact
                        // live-owner handoff that kept foreign frees waiting.
                        core::mem::forget(route);
                        drop(operation);
                        retain_current_thread_detached_owner_exit();
                        return ThreadFinishResult::Retained;
                    };
                    defer_current_thread_native_post_exit_route(operation, registry_config, handoff, |admission| {
                        NativePostExitFreeRoute::SoleMappedRegular(
                            NativeSoleMappedRegularPostExitRoute {
                                route,
                                clients,
                                _pair: pair,
                                admission,
                            },
                        )
                    })
                }
            }
        }
        Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
            // Neither private workload can become all-free without losing the
            // client accounting held by its suspended TLS owner. Preserve the
            // lower drain and scheduler state terminally.
            core::mem::forget(drain);
            drop(operation);
            retain_current_thread_detached_owner_exit();
            ThreadFinishResult::Retained
        }
        Err(failure) => {
            core::mem::forget(failure);
            drop(operation);
            retain_current_thread_detached_owner_exit();
            ThreadFinishResult::Retained
        }
    }
}

/// Preserves only a quiescent ticket-zero image in the post-fork child,
/// otherwise disables this incomplete lifecycle without acquiring an
/// inherited allocator lock or walking inherited thread/page ownership.
///
/// The caller is libc's raw-fork child path. `fork_was_prepared` is true only
/// for the direct public `fork` path that just called [`before_fork`]. That
/// explicit token, plus the gate, preserves the copied process owner only when
/// no later bridge attachment was live or retained, the raw fork ran on the
/// original ticket-zero TLS image, and its source owner was unmapped or
/// all-free dormant in either the static staging slot or pinned initial TLS
/// cell. It prevents another raw-fork caller from borrowing a concurrently
/// copied gate. A preserving child may reactivate that dormant ticket-zero
/// owner or attach a fresh pthread through the existing no-page path. Every
/// other child remains disabled: this is intentionally not a general fork
/// repair and never traverses inherited locks, roots, lists, or page
/// ownership.
#[doc(hidden)]
pub fn after_fork_child(fork_was_prepared: bool) {
    if RUNTIME_FORK_ADMISSION.after_fork_child(fork_was_prepared) {
        return;
    }
    RUNTIME_PROCESS.retain();
    let slot = current_thread_slot();
    if slot.state == ThreadLifecycleState::Attached {
        slot.state = ThreadLifecycleState::Retained;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
    use crate::main_heap_page::MainHeapThreadOwnerLocalPageEngine;
    use crate::main_heap_thread::{
        MainHeapThreadAttachment, MainHeapThreadAttachmentBeginError,
    };
    use crate::main_theap::{MainStaticAttachmentStorage, MainStaticTheapAttachment};
    use crate::meta::MetaAllocator;
    use crate::os::{MapAccess, Mapping};
    use crate::process_arena::ProcessSharedArenaStorage;
    use crate::process_page_map::ProcessPageMapStorage;
    use crate::subproc::MainSubprocess;
    use std::sync::mpsc;
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn native_persistent_owner_process_pair(
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> ProcessPageArenaLease {
        let page_map = ProcessPageMapStorage::test_static_owner()
            .initialize(config, subprocess)
            .expect("the focused persistent-owner test initializes one process PageMap");
        let mapping = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        )
        .expect("the focused persistent-owner test owns one complete arena mapping");
        let arena = match ProcessSharedArenaStorage::test_static_owner()
            .install_one_owned_external_arena(page_map, mapping)
        {
            Ok(arena) => arena,
            Err(_) => panic!("the focused persistent-owner test installs its paired process arena"),
        };
        ProcessPageArenaLease::join(page_map, arena)
            .expect("the focused persistent-owner test joins its matching PageMap and arena")
    }

    fn with_native_persistent_owner_fixture(
        operation: impl FnOnce(&mut NativePersistentThreadOwner) + Send + 'static,
    ) {
        thread::spawn(move || {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let pair = native_persistent_owner_process_pair(config, subprocess);
            // The real compiler-TLS owner stores its attachment with a static
            // process-main lease. Keep this isolated test root alive for the
            // worker's complete terminal-state observation rather than
            // shortening that production lifetime in a fixture.
            let main = std::boxed::Box::leak(std::boxed::Box::new(unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
                .expect("ticket zero attaches the focused source-static main image")
            }));
            let main_heap = main
                .shared_main_heap_lease()
                .expect("the focused persistent worker borrows the static main Heap");

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(
                            main_heap,
                            metadata,
                            config,
                        )
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("focused persistent attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("focused persistent attachment retained: {error:?}")
                        }
                    };
                    let engine = MainHeapThreadOwnerLocalPageEngine::begin(&mut attachment, pair)
                        .expect("the focused attachment creates one persistent owner engine");
                    let mut owner = NativePersistentThreadOwner {
                        attachment,
                        state: NativePersistentThreadOwnerExitState::PreDrain(engine),
                    };
                    operation(&mut owner);
                });
                worker
                    .join()
                    .expect("the focused persistent owner remains current-thread local");
            });
        })
        .join()
        .expect("the focused persistent-owner fixture remains current-thread local");
    }

    #[test]
    fn native_persistent_owner_collect_abandon_predrain_retains_the_exact_engine() {
        with_native_persistent_owner_fixture(|owner| {
            let NativePersistentThreadOwner { attachment: _, state } = owner;
            let NativePersistentThreadOwnerExitState::PreDrain(engine) = state else {
                panic!("the focused persistent owner starts before its drain boundary");
            };
            engine.test_begin_borrowed_state();

            assert_eq!(
                owner.teardown(),
                Err(()),
                "a preflight failure remains retryable before the fast slot or engine changes"
            );
            assert!(matches!(
                owner.state,
                NativePersistentThreadOwnerExitState::PreDrain(_)
            ));

            let NativePersistentThreadOwner { attachment, state } = owner;
            let NativePersistentThreadOwnerExitState::PreDrain(engine) = state else {
                panic!("the preflight failure restores its exact persistent engine");
            };
            engine.test_end_borrowed_state();
            engine
                .with_local_allocator(attachment, |allocator| {
                    let block = allocator
                        .allocate(73, false)
                        .expect("the restored engine still performs a normal local allocation");
                    // SAFETY: this block is current in the exact engine which
                    // the pre-drain failure returned unchanged.
                    unsafe { allocator.free(block) }
                        .expect("the restored engine still performs its normal local free");
                })
                .expect("the exact pre-drain engine is usable after its rejected teardown");

            assert_eq!(
                owner.teardown(),
                Ok(()),
                "the restored engine later enters the normal collect-abandon finish once"
            );
        });
    }

    #[test]
    fn native_persistent_owner_collect_abandon_failure_is_terminal_without_retry_or_allocation() {
        with_native_persistent_owner_fixture(|owner| {
            let NativePersistentThreadOwner { attachment, state } = owner;
            let NativePersistentThreadOwnerExitState::PreDrain(engine) = state else {
                panic!("the focused persistent owner starts before its drain boundary");
            };
            engine
                .with_local_allocator(attachment, |allocator| {
                    let _live = allocator
                        .allocate(81, false)
                        .expect("the focused worker creates one source-live page");
                    allocator.inject_page_free_collect_failure_once();
                })
                .expect("the focused collection injection stays on the exact local owner");

            assert_eq!(
                owner.teardown(),
                Err(()),
                "an injected source collection failure retains the changed drain terminally"
            );
            assert!(matches!(
                owner.state,
                NativePersistentThreadOwnerExitState::RetainedTerminalEngine(_)
            ));

            let allocation_entered = core::cell::Cell::new(false);
            assert_eq!(
                owner.with_local_allocator(|_| allocation_entered.set(true)),
                Err(()),
                "the terminal owner never reopens allocation authority"
            );
            assert!(
                !allocation_entered.get(),
                "the rejected terminal owner never forms a local allocator view"
            );
            assert_eq!(
                owner.teardown(),
                Err(()),
                "a retained terminal engine never re-enters source queue collection"
            );
            assert!(matches!(
                owner.state,
                NativePersistentThreadOwnerExitState::RetainedTerminalEngine(_)
            ));
        });
    }

    #[test]
    fn native_persistent_owner_collect_abandon_attachment_only_retries_no_page_boundary() {
        with_native_persistent_owner_fixture(|owner| {
            // The first fault is observed by the lower consumed drain; the
            // second is observed by this call's attachment-only retry. The
            // next teardown must then finish only the no-page boundary.
            owner
                .attachment
                .test_fail_detached_process_page_finish_times(2);
            assert_eq!(
                owner.teardown(),
                Err(()),
                "a post-drain attachment failure consumes the page engine without recreating it"
            );
            assert!(matches!(
                owner.state,
                NativePersistentThreadOwnerExitState::AttachmentOnly
            ));

            let allocation_entered = core::cell::Cell::new(false);
            assert_eq!(
                owner.with_local_allocator(|_| allocation_entered.set(true)),
                Err(()),
                "attachment-only continuation has no page engine to borrow"
            );
            assert!(
                !allocation_entered.get(),
                "attachment-only continuation never recreates allocation authority"
            );
            assert_eq!(
                owner.teardown(),
                Ok(()),
                "the next attempt retries only the already-drained attachment boundary"
            );
            assert!(matches!(
                owner.state,
                NativePersistentThreadOwnerExitState::AttachmentOnly
            ));
        });
    }

    // Keep this deterministic audit materially longer than the one-cycle
    // owner-exit route regressions while leaving the 128-cycle C lane as the
    // watchdog-bound soak witness. Each cycle constructs fresh A and B
    // threads: A detaches its old owner, B terminally releases the opaque
    // route and finishes its own no-page attachment, and only then may the
    // next worker begin.
    const OWNER_EXIT_STATE_AUDIT_CYCLES: usize = 8;

    #[test]
    fn native_post_exit_registry_terminal_close_waits_for_an_inflight_installation() {
        let registry = NativePostExitRouteRegistry::new();

        assert!(
            registry.acquire_mutation(),
            "the first detached-owner installer holds the registry-only mutation word"
        );
        assert!(
            !registry.try_close_for_retained_entry(),
            "a terminal route waits rather than overwriting an in-flight installation back to idle"
        );
        assert_eq!(
            registry.mutation.load(Ordering::Acquire),
            NATIVE_POST_EXIT_ROUTE_REGISTRY_MUTATING,
            "the terminal close leaves the complete in-flight installation authoritative"
        );

        registry.release_mutation();
        assert!(
            registry.try_close_for_retained_entry(),
            "the retained route closes future installation after the current source owner publishes"
        );
        assert!(
            registry.is_closed_for_retained_entry(),
            "the terminal registry latch remains visible without exposing a route or client"
        );
        assert!(
            !registry.acquire_mutation(),
            "a later detached owner cannot install beside a retained route"
        );
    }

    #[test]
    fn native_live_owner_registry_terminal_close_waits_for_an_inflight_installation() {
        let registry = NativeLiveRemoteOwnerRegistry::new();

        assert!(
            registry.acquire_mutation(),
            "the first parked-live-owner installer holds the registry-only mutation word"
        );
        assert!(
            !registry.try_close_for_retained_entry(),
            "a terminal raw-TLS handoff waits rather than overwriting an in-flight installation back to idle"
        );
        assert_eq!(
            registry.mutation.load(Ordering::Acquire),
            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_MUTATING,
            "the terminal close leaves the complete in-flight live-owner installation authoritative"
        );

        registry.release_mutation();
        assert!(
            registry.try_close_for_retained_entry(),
            "the terminal raw-TLS handoff closes future installation after the current owner publishes"
        );
        assert!(
            registry.is_closed_for_retained_entry(),
            "the terminal live-owner latch remains private and visible without exposing TLS state"
        );
        assert!(
            !registry.acquire_mutation(),
            "a later parked live owner cannot publish beside the retained handoff"
        );
    }

    #[test]
    fn native_prepared_exit_keeps_live_owner_handoff_busy_until_post_exit_publication() {
        // A native C client may already have crossed to B when A starts its
        // source exit.  The raw-TLS registry may therefore not become empty
        // until the replacement post-exit registry has published the same
        // private client ledger.  Otherwise B can observe neither route and
        // incorrectly reject a valid transferred C pointer as foreign.
        let generation = 17;
        let storage = std::boxed::Box::leak(std::boxed::Box::new(
            NativeLiveRemoteOwnerStorage::from_active(NativeLiveRemoteOwner {
                slot: current_thread_slot_pointer(),
                generation,
            }),
        ));
        let reservation = match storage.claim() {
            NativeLiveRemoteOwnerClaim::Claimed(route) => route,
            NativeLiveRemoteOwnerClaim::Empty
            | NativeLiveRemoteOwnerClaim::Retained => {
                panic!("the synthetic native A publication remains claimable")
            }
        };
        let mut session = CurrentThreadPageOwnerSession {
            parked: None,
            clients: PreparedOwnerExitClients::new(None),
            generation,
            native_live_remote: true,
            native_live_remote_reservation: Some(reservation),
        };

        let handoff = session
            .take_native_live_remote_reservation_for_exit()
            .expect("the matching current native session enters its prepared-exit boundary")
            .expect("a native prepared exit retains its exact live-owner handoff");
        assert_eq!(
            storage.state.load(Ordering::Acquire),
            NATIVE_LIVE_REMOTE_OWNER_BUSY,
            "the prepared exit retains its live-owner handoff until its post-exit route publishes"
        );
        let _ = handoff.remove();
        assert_eq!(
            storage.state.load(Ordering::Acquire),
            NATIVE_LIVE_REMOTE_OWNER_EMPTY,
            "the old raw-TLS entry becomes reusable only after the replacement route publishes"
        );
    }

    #[test]
    fn native_live_owner_try_claim_reports_busy_without_waiting() {
        // A B that already holds one exact foreign route must never spin
        // while it probes another busy entry for B's own parked session: two
        // opposite source transfers would otherwise wait on each other's
        // held raw-TLS handoffs. The caller needs a typed Busy result so it
        // can restore its foreign route and retry the exact lookup with no
        // registry guard held.
        let storage = std::boxed::Box::leak(std::boxed::Box::new(
            NativeLiveRemoteOwnerStorage::from_active(NativeLiveRemoteOwner {
                slot: current_thread_slot_pointer(),
                generation: 23,
            }),
        ));
        let held = match storage.claim() {
            NativeLiveRemoteOwnerClaim::Claimed(route) => route,
            _ => panic!("an active storage gives its first claimant the exact guard"),
        };
        assert!(matches!(
            storage.try_claim(),
            NativeLiveRemoteOwnerTryClaim::Busy
        ));
        held.restore();
        match storage.try_claim() {
            NativeLiveRemoteOwnerTryClaim::Claimed(route) => route.restore(),
            _ => panic!("a restored storage is claimable again"),
        }
    }

    /// Publishes C and D's two private post-exit clients only while B holds
    /// the source low owner bit for its direct free. Each scoped join is part
    /// of the test contract: it proves both producers complete before B's
    /// exact `mi_free_block_mt` -> `mi_free_try_collect_mt` collector resumes.
    fn publish_post_exit_remote_free_from_scoped_workers<'route>(
        producers: TicketZeroOwnerExitRemoteFreeProducerPair<'route>,
    ) -> Result<(), TicketZeroOwnerExitRemoteFreeProducerPair<'route>> {
        let (first, second) = producers.split();
        thread::scope(|scope| {
            assert!(
                scope
                    .spawn(move || first.publish())
                    .join()
                    .expect("the first scoped post-exit publisher joins before B resumes collection")
                    .is_ok(),
                "the first post-exit publisher reaches B's held source remote head"
            );
        });
        thread::scope(|scope| {
            assert!(
                scope
                    .spawn(move || second.publish())
                    .join()
                    .expect("the second scoped post-exit publisher joins before B resumes collection")
                    .is_ok(),
                "the second post-exit publisher appends before B resumes collection"
            );
        });
        Ok(())
    }

    fn ledger_test_client(
        clients: &mut PreparedOwnerExitClients,
        address: usize,
    ) -> PreparedOwnerExitClient {
        let (slot, generation) = clients
            .reserve_slot()
            .expect("the bounded ledger accepts its next synthetic client");
        clients
            .record_allocation(
                slot,
                generation,
                core::ptr::NonNull::new(address as *mut u8)
                    .expect("the synthetic client address is non-null"),
                1,
                Some(1),
            )
            .expect("each synthetic live client occupies one distinct ledger slot")
    }

    #[test]
    fn prepared_owner_exit_ledger_rejects_omission_duplicate_and_over_capacity_before_transfer() {
        // `transfer_clients` is called by every typed finalizer immediately
        // before `CurrentThreadPageOwnerPreparation` stores its exit. The
        // engine cannot suspend until it succeeds, so these isolated checks
        // prove an incomplete registry cannot become compiler-TLS state.
        let mut omitted = PreparedOwnerExitClients::new(None);
        let first = ledger_test_client(&mut omitted, 0x1000);
        let second = ledger_test_client(&mut omitted, 0x2000);
        let mut omitted_route: [
            Option<PreparedOwnerExitClient>;
            RUNTIME_PAGE_OWNER_PRIVATE_CLIENT_SLOTS
        ] = core::array::from_fn(|_| None);
        omitted_route[0] = Some(first);
        assert!(matches!(
            omitted.transfer_clients(&mut omitted_route),
            Err(CurrentThreadPageOwnerPreparationError::OmittedClient)
        ), "every live A client must be selected before the post-exit route exists");
        assert!(matches!(
            omitted.slots[second.slot],
            PreparedOwnerExitClientState::Live { .. }
        ));

        let mut duplicate = PreparedOwnerExitClients::new(None);
        let first = ledger_test_client(&mut duplicate, 0x3000);
        let copied = first.duplicate_for_test();
        let mut duplicate_route: [
            Option<PreparedOwnerExitClient>;
            RUNTIME_PAGE_OWNER_PRIVATE_CLIENT_SLOTS
        ] = core::array::from_fn(|_| None);
        duplicate_route[0] = Some(first);
        duplicate_route[1] = Some(copied);
        assert!(matches!(
            duplicate.transfer_clients(&mut duplicate_route),
            Err(CurrentThreadPageOwnerPreparationError::DuplicateClient)
        ), "the one test-only forged duplicate cannot create two route aliases");

        let mut full = PreparedOwnerExitClients::new(None);
        for slot in 0..RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS {
            let _ = ledger_test_client(&mut full, 0x4000 + slot * 0x1000);
        }
        assert_eq!(
            full.reserve_slot(),
            Err(CurrentThreadPageOwnerPreparationError::OverCapacity),
            "capacity rejects before a caller can allocate an untracked client"
        );
    }

    #[test]
    fn prepared_owner_exit_ledger_transfers_all_live_session_clients_without_client_enumeration() {
        // An active TLS session does not hand a workload-shaped pointer list
        // back into the runtime when it prepares exit. Its fixed private
        // ledger alone selects every still-local client, while a source
        // publication remains outside the post-exit ledger for collection.
        let mut clients = PreparedOwnerExitClients::new(None);
        let first = ledger_test_client(&mut clients, 0x1000);
        let published = ledger_test_client(&mut clients, 0x2000);
        let second = ledger_test_client(&mut clients, 0x3000);
        clients
            .mark_published_before_exit(&published)
            .expect("the synthetic source publication starts from one live client");

        let ledger = clients
            .transfer_all_live()
            .expect("the session moves every remaining live client without a caller list");
        assert_eq!(
            ledger.block_for(first.key()),
            Some(first.block),
            "the first live client keeps its exact opaque identity"
        );
        assert_eq!(
            ledger.block_for(second.key()),
            Some(second.block),
            "the later live client keeps its exact opaque identity"
        );
        assert_eq!(
            ledger.block_for(published.key()),
            None,
            "the source-published client never aliases the post-exit ledger"
        );
        assert!(matches!(
            clients.slots[first.slot],
            PreparedOwnerExitClientState::TransferredToExit(_)
        ));
        assert!(matches!(
            clients.slots[second.slot],
            PreparedOwnerExitClientState::TransferredToExit(_)
        ));
        assert!(matches!(
            clients.slots[published.slot],
            PreparedOwnerExitClientState::PublishedBeforeExit
        ));
        assert!(matches!(
            clients.transfer_all_live(),
            Err(CurrentThreadPageOwnerPreparationError::OmittedClient)
        ), "a prepared session cannot transfer the same live client set twice");
    }

    #[test]
    fn dynamic_session_exit_ledger_keeps_metadata_until_its_last_detached_client() {
        // The normal native session must not inherit the fixed-preparation
        // client ceiling. Once it grows past the inline source witness, its
        // exact client facts move as one typed route-owned registry. Releasing
        // that metadata before the final exact post-exit free would destroy
        // the only private membership proof while A's admission remains live.
        let mut clients = PreparedOwnerExitClients::new(Some(memory_config()));
        let client_count = RUNTIME_PAGE_OWNER_PREPARATION_CLIENT_SLOTS + 3;
        for index in 0..client_count {
            let _ = ledger_test_client(&mut clients, 0x10_000 + index * 0x100);
        }

        let mut ledger = clients
            .transfer_all_live()
            .expect("the session moves every inline and overflow client into its typed route");
        assert!(matches!(
            &ledger,
            DetachedOwnerExitClientLedger::Session(_)
        ), "an overflow-backed session moves its storage instead of truncating to the fixed preparation array");

        for _ in 1..client_count {
            assert!(
                ledger.take_next().is_some(),
                "each nonfinal detached client remains privately routable"
            );
        }
        assert!(
            matches!(
                ledger.release_overflow_when_empty(),
                Err(CurrentThreadPageOwnerPreparationError::OmittedClient)
            ),
            "the metadata capability cannot release while one typed route client remains"
        );
        assert!(ledger.take_next().is_some(), "the final private client remains available");
        assert!(ledger.is_empty());
        assert_eq!(
            ledger.release_overflow_when_empty(),
            Ok(()),
            "only the terminal empty route may return its metadata capability"
        );
    }

    #[test]
    fn live_remote_publication_stays_with_source_when_other_clients_exit() {
        // B's live-owner push has already changed the source atomic head, so
        // only A's later source collection may consume this client. A distinct
        // local client can still cross the typed exit route; treating the
        // published client as route-owned would permit B to free it twice.
        let mut clients = PreparedOwnerExitClients::new(None);
        let published = ledger_test_client(&mut clients, 0x1000);
        let local = ledger_test_client(&mut clients, 0x2000);
        clients
            .mark_published_to_live_owner(&published)
            .expect("a live native source publication starts from one local client");

        let ledger = clients
            .transfer_all_live()
            .expect("the later live client moves while the source publication stays private");
        assert_eq!(
            ledger.block_for(local.key()),
            Some(local.block),
            "the still-local client keeps its exact opaque exit identity"
        );
        assert_eq!(
            ledger.block_for(published.key()),
            None,
            "the B-published source client never aliases the post-exit route"
        );
        assert!(matches!(
            clients.slots[published.slot],
            PreparedOwnerExitClientState::PublishedToLiveOwner
        ));
        assert!(matches!(
            clients.slots[local.slot],
            PreparedOwnerExitClientState::TransferredToExit(_)
        ));
    }

    #[test]
    fn parked_session_post_exit_publication_group_validates_before_moving_the_ledger() {
        // The active-session B/C/D route names its direct source client and
        // two prospective publishers only by private generation-checked keys.
        // A bad selection must reject while the session is still fully parked
        // and recoverable; it may not first transfer a partial ledger and then
        // discover a stale publication group.
        let mut clients = PreparedOwnerExitClients::new(None);
        let first = ledger_test_client(&mut clients, 0x1000);
        let second = ledger_test_client(&mut clients, 0x2000);
        let third = ledger_test_client(&mut clients, 0x3000);
        let fourth = ledger_test_client(&mut clients, 0x4000);

        assert!(matches!(
            clients.transfer_all_live_with_final_member_adoption_and_post_exit_remote_publication_group(
                Some(DetachedOwnerExitRemotePublicationSelection {
                    kind: DetachedOwnerExitRemotePublicationKind::DirectSmall,
                    clients: [first.key(), first.key(), second.key()],
                }),
                |_| false,
            ),
            Err(CurrentThreadPageOwnerPreparationError::DuplicateClient)
        ), "a duplicate opaque publication group rejects before the session registry moves");
        assert!(matches!(
            clients.slots[first.slot],
            PreparedOwnerExitClientState::Live { .. }
        ));
        assert!(matches!(
            clients.slots[second.slot],
            PreparedOwnerExitClientState::Live { .. }
        ));

        let stale = DetachedOwnerExitClientKey {
            slot: third.slot,
            generation: third.generation.wrapping_add(1),
        };
        assert!(matches!(
            clients.transfer_all_live_with_final_member_adoption_and_post_exit_remote_publication_group(
                Some(DetachedOwnerExitRemotePublicationSelection {
                    kind: DetachedOwnerExitRemotePublicationKind::DirectSmall,
                    clients: [first.key(), stale, third.key()],
                }),
                |_| false,
            ),
            Err(CurrentThreadPageOwnerPreparationError::UnknownClient)
        ), "a stale opaque key rejects before it can turn a parked session terminal");
        assert!(matches!(
            clients.slots[third.slot],
            PreparedOwnerExitClientState::Live { .. }
        ));

        let (ledger, mut group) = clients
            .transfer_all_live_with_final_member_adoption_and_post_exit_remote_publication_group(
                Some(DetachedOwnerExitRemotePublicationSelection {
                    kind: DetachedOwnerExitRemotePublicationKind::DirectSmall,
                    clients: [first.key(), second.key(), third.key()],
                }),
                |_| false,
            )
            .expect("three validated live keys move only into the scoped post-exit publication group");
        assert_eq!(
            ledger.block_for(first.key()),
            None,
            "the direct scoped source client leaves the ordinary B ledger"
        );
        assert_eq!(
            ledger.block_for(second.key()),
            None,
            "the first publisher source client leaves the ordinary B ledger"
        );
        assert_eq!(
            ledger.block_for(third.key()),
            None,
            "the second publisher source client leaves the ordinary B ledger"
        );
        assert_eq!(
            ledger.block_for(fourth.key()),
            Some(fourth.block),
            "unselected live clients remain in the ordinary opaque ledger"
        );
        let group = group
            .as_mut()
            .expect("the validated group retains all three source client identities");
        assert_eq!(
            group.kind,
            DetachedOwnerExitRemotePublicationKind::DirectSmall,
            "the opaque ledger retains the source page-shape proof with its clients"
        );
        assert_eq!(group.take_next(), Some(first.block));
        assert_eq!(group.take_next(), Some(second.block));
        assert_eq!(group.take_next(), Some(third.block));
        assert!(group.is_empty());
    }

    #[test]
    fn detached_owner_exit_keeps_admission_until_typed_route_proof() {
        let admissions = RuntimeForkAdmission::new();
        let claim = admissions
            .claim_later_thread()
            .expect("the isolated admission word accepts one worker");
        assert_eq!(
            admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
            1,
            "A remains admitted while the detached post-exit route owns its clients"
        );

        // Only the private final route result can package this linear claim
        // for release. Construct it directly here because this module owns
        // both sides of the capability boundary; the aggregate-route tests
        // separately prove that production code creates this result only at
        // `ReleasedAll` after PageMap quiescence.
        let finished = TicketZeroOwnerExitRouteFinished { admission: claim };
        assert_eq!(
            admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
            1,
            "constructing a terminal proof does not itself reopen fork admission"
        );
        assert!(
            finished.release_worker_admission(&admissions).is_ok(),
            "consuming the typed proof releases its exact worker claim"
        );
        assert_eq!(
            admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
            0,
            "only the terminal proof makes the worker fork-quiescent"
        );
    }

    #[test]
    fn poisoned_owner_exit_keeps_its_admission_claim_terminally_visible() {
        let admissions = RuntimeForkAdmission::new();
        let claim = admissions
            .claim_later_thread()
            .expect("the isolated admission word accepts one worker");
        let poisoned = TicketZeroOwnerExitRoutePoisoned { admission: claim };
        let mut slot = ThreadLifecycleSlot::new();
        slot.retain_terminal_admission(poisoned.into_admission());
        assert_eq!(
            admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
            1,
            "a poisoned final PageMap wake cannot make the detached worker fork-quiescent"
        );
        admissions.before_fork(true);
        assert_eq!(
            admissions.state.load(Ordering::Acquire) & FORK_GATE_PRESERVE,
            0,
            "a fork while the poisoned claim remains retained cannot preserve the runtime image"
        );
        admissions.after_fork_parent();
        let claim = slot
            .admission
            .take()
            .expect("the poisoned result retains its exact linear claim");
        assert!(
            admissions.release_later_thread(claim).is_ok(),
            "the retained value remains the exact claim that would otherwise release"
        );
    }

    #[test]
    fn fork_predicate_runs_only_after_gate_excludes_every_later_admission() {
        let admissions = RuntimeForkAdmission::new();
        let claim = admissions
            .claim_later_thread()
            .expect("the isolated admission word accepts one worker");
        let inspected = std::sync::atomic::AtomicBool::new(false);

        admissions.before_fork_with(|| {
            inspected.store(true, Ordering::Release);
            true
        });
        assert!(
            !inspected.load(Ordering::Acquire),
            "a live later admission prevents the fork predicate from borrowing the permanent owner"
        );
        assert_eq!(
            admissions.state.load(Ordering::Acquire) & FORK_GATE_PRESERVE,
            0,
            "a nonzero admission count cannot preserve a copied runtime image"
        );
        admissions.after_fork_parent();
        assert!(
            admissions.release_later_thread(claim).is_ok(),
            "the isolated worker releases before the quiescent fork boundary"
        );

        admissions.before_fork_with(|| {
            assert_eq!(
                admissions.state.load(Ordering::Acquire),
                FORK_GATE_HELD,
                "the predicate observes the gate held with every later admission excluded"
            );
            inspected.store(true, Ordering::Release);
            true
        });
        assert!(
            inspected.load(Ordering::Acquire),
            "the quiescent gate invokes its private preservation predicate"
        );
        assert_ne!(
            admissions.state.load(Ordering::Acquire) & FORK_GATE_PRESERVE,
            0,
            "only the held zero-count boundary records a preserving child image"
        );
        assert!(
            admissions.after_fork_child(true),
            "the prepared child consumes exactly the preserving gate record"
        );
    }

    /// A read-only audit of the process-long objects that a completed Gate 5A
    /// worker must return to their pre-worker state. `total_thread_count` is
    /// intentionally separate: mimalloc's source sequence is monotonic, while
    /// live TLD, metadata-capability, and shared-later-Theap counts must be
    /// restored.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PersistentWorkerStateAudit {
        runtime_process_state: u8,
        page_owner_state: usize,
        page_map_root: usize,
        page_map_committed_count: usize,
        page_map_reserved_count: usize,
        page_map_registered_entry_count: usize,
        page_map_published_submap_count: usize,
        page_map_lazy_submap_allocation_count: usize,
        arena_address: usize,
        arena_registry_count: usize,
        total_thread_count: usize,
        live_thread_count: usize,
        metadata_live_capability_count: usize,
        shared_later_theap_count: usize,
        main_heap_abandoned_counts: [usize; crate::config::BIN_COUNT],
        main_heap_os_abandoned_page: usize,
    }

    fn persistent_worker_state_audit(
        runtime: &'static RuntimeProcessStorage,
        arena_storage: &'static ProcessSharedArenaStorage,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
    ) -> PersistentWorkerStateAudit {
        // SAFETY: this fixture leaked the one permanent process owner before
        // starting its workers, and this audit runs only after a worker join.
        let owner = unsafe { runtime.active_owner() }
            .expect("the isolated runtime keeps its process owner published");
        let ready = owner
            .ready()
            .expect("the permanent ticket-zero owner remains process-ready");
        let process_page_map = ready
            .page_map()
            .expect("the process-ready owner retains its PageMap lease");
        let page_map = process_page_map
            .page_map()
            .expect("the initialized PageMap root remains auditably published");
        let arena = arena_storage
            .ready_lease()
            .expect("the first ticket-zero request published one retained arena");
        let main_heap = owner
            .shared_main_heap_lease()
            .expect("the permanent ticket-zero owner retains its static main Heap witness");
        let (main_heap_abandoned_counts, main_heap_os_abandoned_page) = {
            let mut heap = main_heap
                .lock_heap()
                .expect("the retained static main Heap remains auditable after worker join");
            let abandoned_counts = core::array::from_fn(|bin| {
                heap.heap_mut()
                    .abandoned_count(bin)
                    .expect("every static-main abandoned-count slot remains addressable")
            });
            let os_abandoned_page = heap.heap_mut().test_os_abandoned_page_head().addr();
            heap.unlock()
                .expect("the retained static main Heap unlocks after its audit");
            (abandoned_counts, os_abandoned_page)
        };
        PersistentWorkerStateAudit {
            runtime_process_state: runtime.state.load(Ordering::Acquire),
            page_owner_state: runtime.page_owner_state.load(Ordering::Acquire),
            page_map_root: process_page_map
                .root()
                .expect("the PageMap root remains stable")
                .as_ptr()
                .addr(),
            page_map_committed_count: page_map
                .committed_count()
                .expect("the PageMap committed extent remains readable"),
            page_map_reserved_count: page_map.reserved_count(),
            page_map_registered_entry_count: page_map
                .test_registered_entry_count()
                .expect("the finished worker leaves only stable PageMap entries"),
            page_map_published_submap_count: page_map
                .test_published_submap_count()
                .expect("the PageMap published-submap audit remains readable"),
            page_map_lazy_submap_allocation_count: page_map.test_lazy_submap_allocation_count(),
            arena_address: core::ptr::from_ref(
                arena
                    .arena()
                    .expect("the process arena remains registry-published")
                    .arena(),
            )
            .addr(),
            arena_registry_count: arena
                .test_registry_count()
                .expect("the process arena registry remains readable"),
            total_thread_count: subprocess.total_thread_count(),
            live_thread_count: subprocess.live_thread_count(),
            metadata_live_capability_count: metadata
                .test_allocation_audit()
                .live_capability_count,
            shared_later_theap_count: main_static.test_shared_later_theap_count(),
            main_heap_abandoned_counts,
            main_heap_os_abandoned_page,
        }
    }

    /// Publishes a fully constructed isolated source ticket-zero owner into
    /// a fresh runtime slot. The test owns this one thread, has no worker
    /// admission, and deliberately leaks the final process lifetime state.
    unsafe fn publish_test_owner(
        runtime: &'static RuntimeProcessStorage,
        owner: ProcessMainThread,
    ) {
        assert_eq!(
            runtime.state.compare_exchange(
                PROCESS_COLD,
                PROCESS_INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(PROCESS_COLD),
            "the isolated runtime slot begins cold"
        );
        // SAFETY: the successful test-only initialization claim above grants
        // the sole final-slot write, exactly as production initialization.
        unsafe { (*runtime.owner.get()).write(owner) };
        // SAFETY: the final owner is present before its Release publication;
        // this is the ticket-zero thread that constructed it.
        let owner = unsafe { (&*runtime.owner.get()).assume_init_ref() };
        let main_heap = owner
            .shared_main_heap_lease()
            .expect("ticket zero mints the immutable later-thread witness");
        let initial_thread = current_thread_identity()
            .expect("the isolated runtime fixture has its current thread identity");
        // SAFETY: the same initialization winner writes the last immutable
        // witness before PROCESS_ACTIVE makes either slot observable.
        unsafe { (*runtime.main_heap.get()).write(main_heap) };
        runtime
            .initial_thread_identity
            .store(initial_thread.get(), Ordering::Release);
        runtime.state.store(PROCESS_ACTIVE, Ordering::Release);
    }

    #[test]
    fn runtime_ticket_zero_page_owner_is_lazy_and_preserves_only_a_quiescent_fork_image() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let admissions = RuntimeForkAdmission::new();
            let is_preserved_at_quiescent_fork_boundary = || {
                admissions.before_fork_with(|| runtime.is_quiescent_on_initial_thread_for_fork());
                let preserves = admissions.state.load(Ordering::Acquire) & FORK_GATE_PRESERVE != 0;
                admissions.after_fork_parent();
                preserves
            };

            assert!(is_preserved_at_quiescent_fork_boundary());
            assert!(
                runtime.start_ticket_zero_page_owner_with_storage(arena_storage),
                "the runtime creates its permanent owner without an arena reservation"
            );
            assert!(
                arena_storage.test_is_cold(),
                "the runtime page owner remains mapping-free until its first valid request"
            );
            assert!(
                is_preserved_at_quiescent_fork_boundary(),
                "an unmapped permanent ticket-zero owner remains quiescent for fork"
            );

            let block = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .flatten()
                .expect("the first ordinary runtime request activates the source default arena");
            assert!(
                !is_preserved_at_quiescent_fork_boundary(),
                "a live ticket-zero client keeps the copied child outside the narrow fork contract"
            );
            assert!(
                !arena_storage.test_is_cold(),
                "only the valid first miss publishes the default arena"
            );
            let free = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `block` is the exact live allocation returned
                    // by this runtime's sole ticket-zero page owner.
                    unsafe { owner.free(block) }
            })
                .expect("the permanent owner remains callable after activation");
            assert!(free.is_ok(), "the exact ticket-zero allocation frees normally");
            assert!(
                is_preserved_at_quiescent_fork_boundary(),
                "the all-free source finish restores the permanent owner to the quiescent fork image"
            );

            let aligned = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate_aligned(65, 64, true)
                })
                .flatten()
                .expect("the dormant owner reactivates its first arena for aligned allocation");
            assert_eq!(
                aligned.as_ptr().addr() % 64,
                0,
                "the permanent runtime owner preserves the requested source alignment"
            );
            // SAFETY: `aligned` is still the exact current allocation from
            // this runtime owner, whose operation guard remains exclusive.
            let usable = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| unsafe {
                    owner.usable_size(aligned)
                })
                .flatten()
                .expect("the aligned ticket-zero allocation remains inspectable");
            assert!(
                usable >= 65,
                "the native usable-size query reports space the caller may use"
            );
            // SAFETY: `aligned` remains current and is consumed exactly once
            // by this permanent owner before the next reactivation.
            let aligned_free = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| unsafe {
                    owner.free(aligned)
                })
                .expect("the permanent owner remains callable for aligned free");
            assert!(
                aligned_free.is_ok(),
                "the aligned ticket-zero allocation returns to the dormant state"
            );

            let reused = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .flatten()
                .expect("the quiescent runtime owner reactivates through its existing first arena");
            let free_reused = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `reused` is the exact current allocation from
                    // the reactivated permanent ticket-zero owner.
                    unsafe { owner.free(reused) }
                })
                .expect("the reactivated permanent owner remains callable");
            assert!(
                free_reused.is_ok(),
                "the reactivated ticket-zero allocation frees normally"
            );
            assert_eq!(
                runtime.page_owner_state.load(Ordering::Acquire),
                PAGE_OWNER_READY,
                "an all-free runtime owner remains process-owned rather than reopening the no-page state"
            );
        })
        .join()
        .expect("the isolated runtime page-owner fixture remains ticket-zero local");
    }

    #[test]
    fn ticket_zero_starts_private_operation_while_detached_routes_remain_parked() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            // SAFETY: this test supplies the one final runtime publication and
            // keeps every source/process owner alive through its assertions.
            unsafe { publish_test_owner(runtime, owner) };

            let initial = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(79, false)
                })
                .flatten()
                .expect("ticket zero creates its live client before A exits");
            assert!(
                runtime
                    .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                        owner.prepare_live_engine_for_later_thread()
                    })
                    .is_some_and(|prepared| prepared),
                "ticket zero parks only its own live engine before the later owner starts"
            );
            assert_eq!(
                runtime.page_owner_state.load(Ordering::Acquire),
                PAGE_OWNER_PARKED,
                "ticket zero contributes the first parked scheduler token"
            );

            // This models two typed A routes after source teardown has
            // converted each active operation into a detached parked token.
            // The test intentionally holds no route client address: only the
            // tokens' lifecycle effect is relevant to ticket-zero scheduling.
            assert_eq!(
                runtime.page_owner_state.compare_exchange(
                    PAGE_OWNER_PARKED,
                    page_owner_parked_state(3)
                        .expect("three parked owners remain representable"),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(PAGE_OWNER_PARKED),
                "two synthetic detached routes join ticket zero's parked token"
            );
            assert!(
                runtime.register_active_post_exit_route()
                    && runtime.register_active_post_exit_route(),
                "each synthetic detached route publishes its source-active capability before its parked token"
            );
            let first_route = RuntimeParkedPostExitRoute {
                runtime,
                source_route_active: true,
                terminal_completion_pending: false,
                terminal_retained: false,
                active: true,
            };
            let second_route = RuntimeParkedPostExitRoute {
                runtime,
                source_route_active: true,
                terminal_completion_pending: false,
                terminal_retained: false,
                active: true,
            };

            let usable = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| unsafe {
                    // SAFETY: `initial` is ticket zero's exact still-live client.
                    owner.usable_size(initial)
                })
                .flatten()
                .expect("ticket zero may inspect its own client while A remains parked");
            assert!(usable >= 79);
            let initial_free = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `initial` remains the exact ticket-zero client
                    // and is consumed once by this operation.
                    unsafe { owner.free(initial) }
                })
                .expect("ticket zero keeps its own parked engine callable beside A's route");
            assert!(
                initial_free.is_ok(),
                "ticket zero frees its own client without taking A's route"
            );
            assert_eq!(
                page_owner_parked_count(runtime.page_owner_state.load(Ordering::Acquire)),
                Some(2),
                "ticket zero's all-free transition removes only its own token"
            );
            let bookkeeping = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(97, true)
                })
                .flatten()
                .expect(
                    "ticket zero starts its next private source operation while detached routes retain admission",
                );
            assert_eq!(
                page_owner_parked_count(runtime.page_owner_state.load(Ordering::Acquire)),
                Some(2),
                "ticket zero's ordinary private operation leaves both detached tokens intact"
            );
            assert!(
                runtime
                    .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                        // SAFETY: `bookkeeping` is ticket zero's exact fresh client.
                        unsafe { owner.free(bookkeeping) }
                    })
                    .expect("ticket zero keeps its new private engine callable beside detached routes")
                    .is_ok(),
                "ticket zero settles only its own renewed engine"
            );
            assert_eq!(
                page_owner_parked_count(runtime.page_owner_state.load(Ordering::Acquire)),
                Some(2),
                "both detached route claims remain after ticket zero finishes its private operation"
            );

            let first_route = match first_route.finish_source_route() {
                Ok(route) => route,
                Err(_) => panic!("the first synthetic route converts into B's terminal completion"),
            };
            let second_route = match second_route.finish_source_route() {
                Ok(route) => route,
                Err(_) => panic!("the second synthetic route converts into B's terminal completion"),
            };
            assert!(
                runtime
                    .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                        owner.allocate(61, false)
                    })
                    .is_none(),
                "terminal B completions keep ticket zero unavailable after every source route released"
            );
            assert!(
                first_route.finish_after_b().is_ok(),
                "the first B terminal finish removes only its matching detached token"
            );
            assert_eq!(
                page_owner_parked_count(runtime.page_owner_state.load(Ordering::Acquire)),
                Some(1),
                "the second detached route retains its worker-admission claim"
            );
            assert!(
                second_route.finish_after_b().is_ok(),
                "only the second matched B terminal finish releases the final detached token"
            );
            assert_eq!(
                runtime.page_owner_state.load(Ordering::Acquire),
                PAGE_OWNER_READY,
                "both terminal proofs restore the dormant scheduler"
            );

            let after = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(53, false)
                })
                .flatten()
                .expect("ticket zero remains usable after both terminal route releases");
            assert!(
                runtime
                    .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                        // SAFETY: `after` is ticket zero's exact fresh client.
                        unsafe { owner.free(after) }
                    })
                    .expect("ticket zero remains callable after A's route release")
                    .is_ok(),
                "the resumed initial owner returns to its dormant state"
            );
        })
        .join()
        .expect("the isolated runtime keeps ticket zero and detached routes distinct");
    }

    #[test]
    fn dormant_ticket_zero_page_owner_lends_persistent_mixed_local_worker_engine() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .flatten()
                .expect("the ticket-zero owner activates its first arena");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `first` is the exact current ticket-zero block.
                    unsafe { owner.free(first) }
                })
                .expect("the ticket-zero owner remains callable")
                .expect("the first ticket-zero block frees into the dormant state");

            let baseline =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);
            assert_eq!(baseline.shared_later_theap_count, 0);

            for worker_number in 1..=3 {
                thread::spawn(move || {
                    // SAFETY: the test's permanent process owner and copied
                    // main Heap lease remain in final runtime storage for this
                    // worker.
                    let process_owner = unsafe { runtime.active_owner() }
                        .expect("the process owner stays published for the worker");
                    let config = process_owner
                        .ready()
                        .and_then(|ready| ready.memory_config())
                        .expect("the worker observes the frozen process config");
                    let main_heap = unsafe { runtime.active_main_heap() }
                        .expect("the worker copies the ticket-zero main Heap witness");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(_) => panic!("the worker begins its normal shared-main attachment"),
                    };

                    let completed = run_runtime_persistent_local_worker_lifecycle(
                        runtime,
                        &mut attachment,
                    )
                    .ok();
                    assert_eq!(
                        completed,
                        Some(PersistentLocalWorkerResult::Completed),
                        "the typed runtime operation lends its published pair to persistent local worker {worker_number}"
                    );
                    assert_eq!(
                        runtime.page_owner_state.load(Ordering::Acquire),
                        PAGE_OWNER_READY,
                        "worker {worker_number} returns ticket zero only after its typed engine finishes"
                    );
                    attachment
                        .finish_after_user_destructors()
                        .expect("the empty persistent worker engine restores normal worker teardown");
                })
                .join()
                .expect("each later-main page engine stays on its worker thread");

                let after_worker = persistent_worker_state_audit(
                    runtime,
                    arena_storage,
                    metadata,
                    main_static,
                    subprocess,
                );
                assert_eq!(
                    after_worker.page_map_root,
                    baseline.page_map_root,
                    "worker {worker_number} retains the one process PageMap root"
                );
                assert_eq!(
                    after_worker.page_map_committed_count,
                    baseline.page_map_committed_count,
                    "worker {worker_number} returns the PageMap commitment boundary"
                );
                assert_eq!(
                    after_worker.page_map_reserved_count,
                    baseline.page_map_reserved_count,
                    "worker {worker_number} does not change PageMap reservation ownership"
                );
                assert_eq!(
                    after_worker.page_map_registered_entry_count,
                    baseline.page_map_registered_entry_count,
                    "worker {worker_number} leaves no PageMap registrations"
                );
                assert_eq!(
                    after_worker.page_map_published_submap_count,
                    baseline.page_map_published_submap_count,
                    "worker {worker_number} leaves no additional published PageMap submap"
                );
                assert_eq!(
                    after_worker.page_map_lazy_submap_allocation_count,
                    baseline.page_map_lazy_submap_allocation_count,
                    "worker {worker_number} leaves no lazy PageMap allocation"
                );
                assert_eq!(
                    after_worker.arena_address,
                    baseline.arena_address,
                    "worker {worker_number} retains the one process arena identity"
                );
                assert_eq!(
                    after_worker.arena_registry_count,
                    baseline.arena_registry_count,
                    "worker {worker_number} leaves no arena registry ownership"
                );
                assert_eq!(
                    after_worker.live_thread_count,
                    baseline.live_thread_count,
                    "worker {worker_number} restores the source live-TLD count"
                );
                assert_eq!(
                    after_worker.shared_later_theap_count,
                    baseline.shared_later_theap_count,
                    "worker {worker_number} restores the shared-later-Theap count"
                );
                assert_eq!(
                    after_worker.total_thread_count,
                    baseline.total_thread_count + worker_number,
                    "worker {worker_number} consumes exactly one monotonic source thread sequence"
                );
            }

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(101, false)
                })
                .flatten()
                .expect("the dormant ticket-zero owner reactivates after the worker returns its map lease");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `resumed` is the exact current ticket-zero block.
                    unsafe { owner.free(resumed) }
                })
                .expect("ticket zero remains callable after the worker engine")
                .expect("the resumed ticket-zero block frees normally");
        })
        .join()
        .expect("the runtime alternates the one process pair between ticket zero and one persistent worker");
    }

    #[test]
    fn dormant_ticket_zero_page_owner_parks_live_engine_until_interleaving_worker_finishes() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            // SAFETY: this fixture owns the one final runtime publication and
            // keeps every source process object alive for both joined workers.
            unsafe { publish_test_owner(runtime, owner) };

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .flatten()
                .expect("ticket zero activates the first arena before it lends the dormant pair");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `first` is the exact current ticket-zero client.
                    unsafe { owner.free(first) }
                })
                .expect("the permanent owner remains callable after first activation")
                .expect("ticket zero returns to the dormant existing-arena state");

            let baseline =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(baseline.runtime_process_state, PROCESS_ACTIVE);
            assert_eq!(baseline.page_owner_state, PAGE_OWNER_READY);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);
            assert_eq!(baseline.shared_later_theap_count, 0);

            // SAFETY: the process owner and its heap lease are final static
            // runtime values. Each worker constructs its own current-thread
            // TLD/Theap attachment over this immutable witness.
            let process_owner = unsafe { runtime.active_owner() }
                .expect("the permanent process owner stays published");
            let config = process_owner
                .ready()
                .and_then(|ready| ready.memory_config())
                .expect("workers observe the frozen process configuration");
            let main_heap = unsafe { runtime.active_main_heap() }
                .expect("workers copy the ticket-zero static heap witness");

            let (a_parked_tx, a_parked_rx) = mpsc::sync_channel::<()>(0);
            let (start_b_tx, start_b_rx) = mpsc::sync_channel::<()>(0);
            let (b_finished_tx, b_finished_rx) = mpsc::sync_channel::<()>(0);
            let (resume_a_tx, resume_a_rx) = mpsc::sync_channel::<()>(0);

            thread::scope(|scope| {
                let a = scope.spawn(move || {
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("A attaches before its persistent operation: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { attachment, error }) => {
                            core::mem::forget(attachment);
                            panic!("A attachment remains healthy: {error:?}")
                        }
                    };
                    let mut engine = match runtime.begin_persistent_later_engine(&mut attachment) {
                        Ok(engine) => engine,
                        Err(error) => panic!("A acquires the dormant runtime pair: {error:?}"),
                    };
                    let first = engine
                        .allocate(37, false)
                        .expect("A keeps one live client across its persistent pause");
                    let parked = match engine.suspend() {
                        Ok(parked) => parked,
                        Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, error }) => {
                            core::mem::forget(engine);
                            panic!("A records its suspended attachment marker: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                            core::mem::forget(engine);
                            panic!("the original A operation alone may park")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, error }) => {
                            core::mem::forget(terminal);
                            panic!("A's PageMap pause handoff remains healthy: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                            panic!("A's runtime page-owner claim remains exact while it parks")
                        }
                    };

                    a_parked_tx
                        .send(())
                        .expect("the parent observes A's parked live engine");
                    resume_a_rx
                        .recv()
                        .expect("A waits until B's complete operation returns the parked state");

                    let mut engine = match parked.resume(&mut attachment) {
                        Ok(engine) => engine,
                        Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked }) => {
                            core::mem::forget(parked);
                            panic!("B released the runtime busy claim before A resumes")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::Rejected { parked, error }) => {
                            core::mem::forget(parked);
                            panic!("A retains the matching suspended attachment marker: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy { parked, error }) => {
                            core::mem::forget(parked);
                            panic!("B completed its whole PageMap operation before A resumes: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::Retained { terminal, error }) => {
                            core::mem::forget(terminal);
                            panic!("A's resumed PageMap handoff remains healthy: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
                            panic!("A's parked runtime claim remains exact on resume")
                        }
                    };
                    // SAFETY: `first` never crossed a producer or post-exit
                    // route, and A recovered its unique normal engine first.
                    unsafe { engine.free(first) }
                        .expect("A frees its pre-pause local client only after resume");
                    match engine.finish() {
                        Ok(()) => {}
                        Err(RuntimePersistentPageEngineFinishFailure::Allocator(error)) => {
                            core::mem::forget(error);
                            panic!("A becomes all-free before it returns ticket zero to ready")
                        }
                        Err(RuntimePersistentPageEngineFinishFailure::PageOwnerRetained) => {
                            panic!("A owns the matching runtime busy claim through its all-free finish")
                        }
                    }
                    attachment
                        .finish_after_user_destructors()
                        .expect("A tears down only after its resumed engine is empty");
                });

                let b = scope.spawn(move || {
                    start_b_rx
                        .recv()
                        .expect("B starts only after A has parked its live engine");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("B attaches for its interleaving operation: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { attachment, error }) => {
                            core::mem::forget(attachment);
                            panic!("B attachment remains healthy: {error:?}")
                        }
                    };
                    let engine = match runtime.begin_interleaving_persistent_later_engine(&mut attachment) {
                        Ok(engine) => engine,
                        Err(error) => panic!("B acquires the parked runtime pair for one complete operation: {error:?}"),
                    };
                    let mut engine = match engine.suspend() {
                        Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                            engine
                        }
                        Ok(parked) => {
                            core::mem::forget(parked);
                            panic!("B cannot create a second parked live engine beside A")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, error }) => {
                            core::mem::forget(engine);
                            panic!("B's non-parkable operation does not touch its attachment: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, error }) => {
                            core::mem::forget(terminal);
                            panic!("B's non-parkable operation does not transfer its PageMap state: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                            panic!("B's non-parkable operation preserves A's parked runtime claim")
                        }
                    };
                    let block = engine
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("B owns an independent ordinary medium allocation while A is parked");
                    // SAFETY: `block` belongs only to B's current complete
                    // operation and never crosses A's private paused token.
                    unsafe { engine.free(block) }
                        .expect("B frees its own local client before returning the parked state");
                    match engine.finish() {
                        Ok(()) => {}
                        Err(RuntimePersistentPageEngineFinishFailure::Allocator(error)) => {
                            core::mem::forget(error);
                            panic!("B becomes all-free before it restores A's parked state")
                        }
                        Err(RuntimePersistentPageEngineFinishFailure::PageOwnerRetained) => {
                            panic!("B restores exactly the prior parked runtime state")
                        }
                    }
                    attachment
                        .finish_after_user_destructors()
                        .expect("B tears down after its complete empty engine operation");
                    b_finished_tx
                        .send(())
                        .expect("the parent observes B's complete operation before A resumes");
                });

                a_parked_rx
                    .recv()
                    .expect("A publishes its typed parked engine state");
                assert_eq!(
                    runtime.page_owner_state.load(Ordering::Acquire),
                    PAGE_OWNER_PARKED,
                    "A's live separated engine keeps ticket zero outside the runtime scheduler"
                );
                assert!(
                    runtime
                        .with_ticket_zero_page_owner_with_storage(arena_storage, |_| ())
                        .is_none(),
                    "ticket zero cannot reactivate while A owns a parked live engine"
                );
                assert_eq!(
                    runtime.page_owner_state.load(Ordering::Acquire),
                    PAGE_OWNER_PARKED,
                    "the rejected ticket-zero attempt leaves A's exact parked claim intact"
                );

                start_b_tx
                    .send(())
                    .expect("the parent admits B's one complete interleaving operation");
                b_finished_rx
                    .recv()
                    .expect("B returns A's parked state before A resumes");
                assert_eq!(
                    runtime.page_owner_state.load(Ordering::Acquire),
                    PAGE_OWNER_PARKED,
                    "B's empty engine restores the same parked A-side runtime state"
                );
                resume_a_tx
                    .send(())
                    .expect("the parent permits A to reclaim its typed normal engine");

                a.join()
                    .expect("A resumes and tears down after B's complete operation");
                b.join()
                    .expect("B remains a separate later-thread lifecycle owner");
            });

            let after =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(after.runtime_process_state, PROCESS_ACTIVE);
            assert_eq!(after.page_owner_state, PAGE_OWNER_READY);
            assert_eq!(after.page_map_root, baseline.page_map_root);
            assert_eq!(after.page_map_committed_count, baseline.page_map_committed_count);
            assert_eq!(after.page_map_reserved_count, baseline.page_map_reserved_count);
            assert_eq!(after.page_map_registered_entry_count, 0);
            assert_eq!(after.arena_address, baseline.arena_address);
            assert_eq!(after.arena_registry_count, baseline.arena_registry_count);
            assert_eq!(after.live_thread_count, baseline.live_thread_count);
            assert_eq!(
                after.total_thread_count,
                baseline.total_thread_count + 2,
                "A and B each consume one monotonic source later-thread ticket"
            );
            assert_eq!(
                after.metadata_live_capability_count,
                baseline.metadata_live_capability_count,
                "both complete worker attachments release their TLD/Theap metadata"
            );
            assert_eq!(after.shared_later_theap_count, baseline.shared_later_theap_count);
            assert_eq!(after.main_heap_abandoned_counts, baseline.main_heap_abandoned_counts);
            assert_eq!(after.main_heap_os_abandoned_page, baseline.main_heap_os_abandoned_page);

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .flatten()
                .expect("ticket zero reactivates only after A returns its exact engine empty");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `resumed` is the exact fresh ticket-zero client.
                    unsafe { owner.free(resumed) }
                })
                .expect("ticket zero is callable after the A/B persistent lifecycle")
                .expect("ticket zero frees after the parked engine fully returns to ready");
        })
        .join()
        .expect("the runtime scheduler keeps each persistent engine current-thread local");
    }

    #[test]
    fn dormant_ticket_zero_page_owner_keeps_two_parked_engines_distinct_until_each_finishes() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            // SAFETY: the fixture retains every process-static component
            // through both independently attached worker lifecycles.
            unsafe { publish_test_owner(runtime, owner) };

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .expect("ticket zero starts its first native page engine")
                .expect("the first ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `first` is the exact current ticket-zero client.
                    unsafe { owner.free(first) }
                })
                .expect("ticket zero remains callable after first activation")
                .expect("ticket zero returns its first native page engine dormant");

            let baseline =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(baseline.page_owner_state, PAGE_OWNER_READY);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);

            // SAFETY: the published process owner and shared Heap lease have
            // process lifetime throughout this scoped two-worker fixture.
            let process_owner = unsafe { runtime.active_owner() }
                .expect("the permanent process owner stays published");
            let config = process_owner
                .ready()
                .and_then(|ready| ready.memory_config())
                .expect("both workers observe the frozen process configuration");
            let main_heap = unsafe { runtime.active_main_heap() }
                .expect("both workers copy the ticket-zero static Heap witness");

            let (a_parked_tx, a_parked_rx) = mpsc::sync_channel::<()>(0);
            let (start_b_tx, start_b_rx) = mpsc::sync_channel::<()>(0);
            let (b_started_tx, b_started_rx) = mpsc::sync_channel::<bool>(0);
            let (b_parked_tx, b_parked_rx) = mpsc::sync_channel::<()>(0);
            let (resume_b_tx, resume_b_rx) = mpsc::sync_channel::<()>(0);
            let (b_finished_tx, b_finished_rx) = mpsc::sync_channel::<()>(0);
            let (resume_a_tx, resume_a_rx) = mpsc::sync_channel::<()>(0);
            let (a_finished_tx, a_finished_rx) = mpsc::sync_channel::<()>(0);

            thread::scope(|scope| {
                let a = scope.spawn(move || {
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("A attaches before its persistent operation: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { attachment, error }) => {
                            core::mem::forget(attachment);
                            panic!("A attachment remains healthy: {error:?}")
                        }
                    };
                    let mut engine = match runtime.begin_persistent_later_engine(&mut attachment) {
                        Ok(engine) => engine,
                        Err(error) => panic!("A acquires the dormant runtime pair: {error:?}"),
                    };
                    let block = engine
                        .allocate(37, false)
                        .expect("A keeps one live local allocation while parked");
                    let parked = match engine.suspend() {
                        Ok(parked) => parked,
                        Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, error }) => {
                            core::mem::forget(engine);
                            panic!("A records its suspended attachment marker: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                            core::mem::forget(engine);
                            panic!("A's ordinary persistent operation may park")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, error }) => {
                            core::mem::forget(terminal);
                            panic!("A's PageMap pause handoff remains healthy: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                            panic!("A's runtime owner claim remains exact while it parks")
                        }
                    };
                    a_parked_tx
                        .send(())
                        .expect("the parent observes A's parked engine");
                    resume_a_rx
                        .recv()
                        .expect("A waits until B has completed its own lifecycle");
                    let mut engine = match parked.resume(&mut attachment) {
                        Ok(engine) => engine,
                        Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked }) => {
                            core::mem::forget(parked);
                            panic!("A resumes after B released its independent parked owner")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::Rejected { parked, error }) => {
                            core::mem::forget(parked);
                            panic!("A retains its matching suspended attachment marker: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy { parked, error }) => {
                            core::mem::forget(parked);
                            panic!("A resumes only after B has released the PageMap mutation lease: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::Retained { terminal, error }) => {
                            core::mem::forget(terminal);
                            panic!("A's resumed PageMap handoff remains healthy: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
                            panic!("A's parked runtime claim remains exact on resume")
                        }
                    };
                    // SAFETY: `block` stayed local to A's exact paused engine.
                    unsafe { engine.free(block) }
                        .expect("A frees its live allocation only after its own resume");
                    match engine.finish() {
                        Ok(()) => {}
                        Err(RuntimePersistentPageEngineFinishFailure::Allocator(error)) => {
                            core::mem::forget(error);
                            panic!("A becomes all-free before it returns its runtime claim")
                        }
                        Err(RuntimePersistentPageEngineFinishFailure::PageOwnerRetained) => {
                            panic!("A finishes against its exact runtime scheduler claim")
                        }
                    }
                    attachment
                        .finish_after_user_destructors()
                        .expect("A tears down only after its empty engine finishes");
                    a_finished_tx
                        .send(())
                        .expect("the parent observes A's complete lifecycle");
                });

                let b = scope.spawn(move || {
                    start_b_rx
                        .recv()
                        .expect("B starts only after A has parked its live engine");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("B attaches for its independent persistent operation: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { attachment, error }) => {
                            core::mem::forget(attachment);
                            panic!("B attachment remains healthy: {error:?}")
                        }
                    };
                    let mut engine = match runtime.begin_persistent_later_engine(&mut attachment) {
                        Ok(engine) => {
                            b_started_tx
                                .send(true)
                                .expect("the parent observes B's second persistent engine");
                            engine
                        }
                        Err(_) => {
                            b_started_tx
                                .send(false)
                                .expect("the parent observes B's rejected second persistent engine");
                            return;
                        }
                    };
                    let block = engine
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("B keeps an independent medium allocation while A remains parked");
                    let parked = match engine.suspend() {
                        Ok(parked) => parked,
                        Err(RuntimePersistentPageEngineSuspendFailure::Rejected { engine, error }) => {
                            core::mem::forget(engine);
                            panic!("B records its own suspended attachment marker: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::InterleavingOperation { engine }) => {
                            core::mem::forget(engine);
                            panic!("B's ordinary persistent operation may park beside A")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::Retained { terminal, error }) => {
                            core::mem::forget(terminal);
                            panic!("B's PageMap pause handoff remains healthy: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineSuspendFailure::PageOwnerRetained) => {
                            panic!("B's runtime owner claim remains exact while it parks")
                        }
                    };
                    b_parked_tx
                        .send(())
                        .expect("the parent observes B's independent parked engine");
                    resume_b_rx
                        .recv()
                        .expect("B waits for the parent to choose its resume order");
                    let mut engine = match parked.resume(&mut attachment) {
                        Ok(engine) => engine,
                        Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked }) => {
                            core::mem::forget(parked);
                            panic!("B resumes while A remains parked")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::Rejected { parked, error }) => {
                            core::mem::forget(parked);
                            panic!("B retains its matching suspended attachment marker: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy { parked, error }) => {
                            core::mem::forget(parked);
                            panic!("B owns the one serialized PageMap mutation lease: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::Retained { terminal, error }) => {
                            core::mem::forget(terminal);
                            panic!("B's resumed PageMap handoff remains healthy: {error:?}")
                        }
                        Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
                            panic!("B's parked runtime claim remains exact on resume")
                        }
                    };
                    // SAFETY: `block` stayed local to B's exact paused engine.
                    unsafe { engine.free(block) }
                        .expect("B frees its live allocation only after its own resume");
                    match engine.finish() {
                        Ok(()) => {}
                        Err(RuntimePersistentPageEngineFinishFailure::Allocator(error)) => {
                            core::mem::forget(error);
                            panic!("B becomes all-free before it returns its runtime claim")
                        }
                        Err(RuntimePersistentPageEngineFinishFailure::PageOwnerRetained) => {
                            panic!("B finishes against its exact runtime scheduler claim")
                        }
                    }
                    attachment
                        .finish_after_user_destructors()
                        .expect("B tears down only after its empty engine finishes");
                    b_finished_tx
                        .send(())
                        .expect("the parent observes B's complete lifecycle");
                });

                a_parked_rx
                    .recv()
                    .expect("A publishes its typed parked engine state");
                assert_eq!(
                    runtime.page_owner_state.load(Ordering::Acquire),
                    PAGE_OWNER_PARKED,
                    "one parked owner keeps ticket zero outside the runtime scheduler"
                );
                assert_eq!(
                    page_owner_parked_count(runtime.page_owner_state.load(Ordering::Acquire)),
                    Some(1),
                    "A's suspended token is the one counted parked owner"
                );
                start_b_tx
                    .send(())
                    .expect("the parent permits B to create its independent parked engine");
                if !b_started_rx
                    .recv()
                    .expect("B reports whether the scheduler admitted its independent engine")
                {
                    resume_a_tx
                        .send(())
                        .expect("the parent releases A after B's rejected second engine");
                    a_finished_rx
                        .recv()
                        .expect("A completes after B's rejected second engine");
                    a.join()
                        .expect("A still owns its exact current-thread paused engine");
                    b.join()
                        .expect("B tears down its no-page attachment after the scheduler rejection");
                    panic!("the scheduler must admit B's independent parked engine while A remains parked");
                }
                b_parked_rx
                    .recv()
                    .expect("B publishes its independent typed parked engine state");
                assert_eq!(
                    page_owner_parked_count(runtime.page_owner_state.load(Ordering::Acquire)),
                    Some(2),
                    "A and B each retain an independent suspended engine token"
                );
                assert!(
                    runtime
                        .with_ticket_zero_page_owner_with_storage(arena_storage, |_| ())
                        .is_none(),
                    "ticket zero cannot reactivate while either parked engine remains live"
                );

                resume_b_tx
                    .send(())
                    .expect("the parent resumes B before A");
                b_finished_rx
                    .recv()
                    .expect("B completes without resuming A");
                assert_eq!(
                    page_owner_parked_count(runtime.page_owner_state.load(Ordering::Acquire)),
                    Some(1),
                    "A's parked engine remains the sole scheduler claim after B finishes"
                );
                assert!(
                    runtime
                        .with_ticket_zero_page_owner_with_storage(arena_storage, |_| ())
                        .is_none(),
                    "ticket zero remains blocked until A also finishes"
                );

                resume_a_tx
                    .send(())
                    .expect("the parent resumes the remaining parked A engine");
                a_finished_rx
                    .recv()
                    .expect("A completes after B has already torn down");
                a.join()
                    .expect("A retains its exact current-thread paused engine");
                b.join()
                    .expect("B retains its independent current-thread paused engine");
            });

            let after =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(after.runtime_process_state, PROCESS_ACTIVE);
            assert_eq!(after.page_owner_state, PAGE_OWNER_READY);
            assert_eq!(after.page_map_root, baseline.page_map_root);
            assert_eq!(after.page_map_registered_entry_count, 0);
            assert_eq!(after.live_thread_count, baseline.live_thread_count);
            assert_eq!(after.shared_later_theap_count, baseline.shared_later_theap_count);
            assert_eq!(
                after.total_thread_count,
                baseline.total_thread_count + 2,
                "two independently attached workers consume two source later-thread tickets"
            );

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .flatten()
                .expect("ticket zero reactivates only after both parked engines finish");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `resumed` is the exact fresh ticket-zero client.
                    unsafe { owner.free(resumed) }
                })
                .expect("ticket zero remains callable after both independent worker lifecycles")
                .expect("the reactivated ticket-zero client frees normally");
        })
        .join()
        .expect("the runtime scheduler serializes mutations while retaining multiple paused owners");
    }

    fn publish_remote_from_scoped_test_thread<'owner>(
        producers: TicketZeroRemoteFreeProducerPair<'owner>,
    ) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>> {
        let (first, second) = producers.split();
        thread::scope(|scope| {
            let first = scope.spawn(move || first.publish());
            let second = scope.spawn(move || second.publish());
            match first
                .join()
                .expect("the first remote publisher remains bounded by its owner join")
            {
                Ok(()) => {}
                Err(_) => panic!("the first remote publisher accepts its exact source block"),
            }
            match second
                .join()
                .expect("the second remote publisher remains bounded by its owner join")
            {
                Ok(()) => {}
                Err(_) => panic!("the second remote publisher accepts its exact source block"),
            }
            Ok(())
        })
    }

    fn reject_remote_publication<'owner>(
        producers: TicketZeroRemoteFreeProducerPair<'owner>,
    ) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>> {
        Err(producers)
    }

    #[test]
    fn dormant_ticket_zero_page_owner_reuses_remote_frees_and_cleans_failed_publication() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .expect("the ticket-zero owner starts its first page engine")
                .expect("the first ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    unsafe { owner.free(first) }
                })
                .expect("the ticket-zero owner remains callable")
                .expect("the first ticket-zero block frees into the dormant state");

            let baseline =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);
            assert_eq!(baseline.shared_later_theap_count, 0);

            let cases: [(TicketZeroRemoteFreePublisher, PersistentRemoteWorkerResult); 4] = [
                (
                    publish_remote_from_scoped_test_thread,
                    PersistentRemoteWorkerResult::Completed,
                ),
                (
                    publish_remote_from_scoped_test_thread,
                    PersistentRemoteWorkerResult::Completed,
                ),
                (
                    publish_remote_from_scoped_test_thread,
                    PersistentRemoteWorkerResult::Completed,
                ),
                (
                    reject_remote_publication,
                    PersistentRemoteWorkerResult::PublicationFailed,
                ),
            ];
            for (worker_index, (publish, expected_result)) in cases.into_iter().enumerate() {
                let worker_number = worker_index + 1;
                thread::spawn(move || {
                    // SAFETY: this fixture keeps the permanent process owner
                    // and its shared main Heap lease process-static while A
                    // owns one engine and its scoped B publisher joins.
                    let process_owner = unsafe { runtime.active_owner() }
                        .expect("the process owner stays published for remote owner A");
                    let config = process_owner
                        .ready()
                        .and_then(|ready| ready.memory_config())
                        .expect("remote owner A observes the frozen process config");
                    let main_heap = unsafe { runtime.active_main_heap() }
                        .expect("remote owner A copies the ticket-zero main Heap witness");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(_) => panic!("remote owner A begins its normal shared-main attachment"),
                    };

                    let completed = run_runtime_persistent_remote_worker_lifecycle(
                        runtime,
                        &mut attachment,
                        publish,
                    )
                    .ok();
                    assert_eq!(
                        completed,
                        Some(expected_result),
                        "the typed runtime operation preserves its bounded remote outcome for owner A {worker_number}"
                    );
                    assert_eq!(
                        runtime.page_owner_state.load(Ordering::Acquire),
                        PAGE_OWNER_READY,
                        "remote owner A {worker_number} returns ticket zero after its joined B publication or canceled opaque route"
                    );
                    attachment
                        .finish_after_user_destructors()
                        .expect("remote owner A tears down after B has joined and all pages are empty");
                })
                .join()
                .expect("each live remote-free owner remains on its fresh worker thread");

                let after_worker = persistent_worker_state_audit(
                    runtime,
                    arena_storage,
                    metadata,
                    main_static,
                    subprocess,
                );
                let expected = PersistentWorkerStateAudit {
                    total_thread_count: baseline.total_thread_count + worker_number,
                    ..baseline
                };
                assert_eq!(
                    after_worker, expected,
                    "remote owner A {worker_number} leaves no PageMap, arena, TLD, or Theap residue"
                );
            }

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .expect("ticket zero reactivates after every remote owner joins")
                .expect("the reactivated ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    unsafe { owner.free(resumed) }
                })
                .expect("the resumed ticket-zero owner stays callable")
                .expect("the reactivated ticket-zero block frees normally");
        })
        .join()
        .expect("the isolated runtime restores its retained baseline after repeated live remote frees");
    }

    #[test]
    fn dormant_ticket_zero_page_owner_repeats_mixed_owner_exit_without_state_growth() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .expect("ticket zero starts its first page engine")
                .expect("the first ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `first` is the exact current ticket-zero block.
                    unsafe { owner.free(first) }
                })
                .expect("ticket zero remains callable after its first allocation")
                .expect("the first ticket-zero block frees into the dormant state");

            let baseline =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(baseline.runtime_process_state, PROCESS_ACTIVE);
            assert_eq!(baseline.page_owner_state, PAGE_OWNER_READY);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);
            assert_eq!(
                baseline.metadata_live_capability_count, 0,
                "the dormant ticket-zero owner retains no worker metadata capability"
            );
            assert_eq!(baseline.shared_later_theap_count, 0);
            assert_eq!(
                baseline.main_heap_abandoned_counts,
                [0; crate::config::BIN_COUNT],
                "the dormant ticket-zero owner has no leaked static-main abandoned bitmap/count pairing"
            );
            assert_eq!(
                baseline.main_heap_os_abandoned_page,
                0,
                "the dormant ticket-zero owner has no leaked private OS-abandoned list member"
            );
            // The first OS-aligned singleton route may lazily allocate the
            // PageMap submaps that cover its clipped alias/mapping range.
            // Those process-owned submaps are intentionally retained after
            // terminal release, so require the complete state to plateau
            // after one warmup cycle rather than falsely treating this first
            // immutable publication as a per-worker leak.
            let mut warmed_owner_exit_state = None;
            let mut warmed_metadata_high_water = None;

            for worker_number in 1..=OWNER_EXIT_STATE_AUDIT_CYCLES {
                thread::spawn(move || {
                    // SAFETY: the fixture keeps the permanent process owner
                    // and its immutable shared main Heap witness alive while
                    // A detaches and its joined B consumes only the opaque
                    // post-exit route.
                    let process_owner = unsafe { runtime.active_owner() }
                        .expect("the process owner stays published for owner-exit A");
                    let config = process_owner
                        .ready()
                        .and_then(|ready| ready.memory_config())
                        .expect("owner-exit A observes the frozen process config");
                    let main_heap = unsafe { runtime.active_main_heap() }
                        .expect("owner-exit A copies the ticket-zero main Heap witness");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("owner-exit A begins its shared-main attachment: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("owner-exit A cannot retain during attachment: {error:?}")
                        }
                    };
                    let admissions = RuntimeForkAdmission::new();

                    let completed = runtime.with_dormant_page_pair(|pair| {
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut attachment, pair)
                            .expect("the dormant ticket-zero pair admits the mixed owner-exit worker");
                        let mut workload = OwnerExitMappedRegularWorkload::allocate(&mut allocator)
                            .expect("the mixed owner-exit worker allocates its bounded source workload");

                        let direct_small_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload.direct_small[0]
                                    .expect("the owner-exit workload has a direct-small client"),
                            )
                        })
                        .expect("the direct-small page stays PageMap-published before exit");
                        let direct_small_page = unsafe { direct_small_page_pointer.as_ref() };
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(
                                direct_small_page.block_size(),
                            ),
                            Some(crate::types::PageKind::Small),
                            "the mixed source image retains a direct small page"
                        );
                        assert!(
                            direct_small_page.block_size() <= SMALL_SIZE_MAX,
                            "the direct-small page remains inside the source direct-cache range"
                        );
                        assert_eq!(
                            direct_small_page.used(),
                            OWNER_EXIT_DIRECT_SMALL_CLIENT_SLOTS,
                            "both direct-small clients remain live through A's aggregate exit"
                        );
                        for (index, block) in workload.direct_small.iter().enumerate() {
                            let block = block
                                .expect("the owner-exit workload retains each direct-small client");
                            assert_eq!(
                                unsafe { allocator.test_page_for_block(block) },
                                direct_small_page_pointer.as_ptr(),
                                "direct-small client {index} stays in its exact source page"
                            );
                        }

                        let non_direct_small_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload.non_direct_small[0]
                                    .expect("the owner-exit workload has a non-direct-small client"),
                            )
                        })
                        .expect("the non-direct-small page stays PageMap-published before exit");
                        let non_direct_small_page = unsafe { non_direct_small_page_pointer.as_ref() };
                        assert_ne!(
                            non_direct_small_page_pointer,
                            direct_small_page_pointer,
                            "the two source small classes stay in independently classified pages"
                        );
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(
                                non_direct_small_page.block_size(),
                            ),
                            Some(crate::types::PageKind::Small),
                            "the mixed source image retains a non-direct small page"
                        );
                        assert!(
                            non_direct_small_page.block_size() > SMALL_SIZE_MAX,
                            "the non-direct small page does not borrow a source direct-cache slot"
                        );
                        assert_eq!(
                            non_direct_small_page.used(),
                            OWNER_EXIT_NON_DIRECT_SMALL_CLIENT_SLOTS,
                            "the non-direct-small client remains live through A's aggregate exit"
                        );

                        let medium_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload.full_medium[0]
                                    .expect("the owner-exit workload has a medium client"),
                            )
                        })
                        .expect("the owner-exit medium page stays PageMap-published before exit");
                        let medium_page = unsafe { medium_page_pointer.as_ref() };
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(medium_page.block_size()),
                            Some(crate::types::PageKind::Medium),
                            "the post-exit coordinator sees the source medium class"
                        );
                        assert_eq!(
                            medium_page.used(),
                            usize::from(medium_page.reserved()),
                            "the joined remote publication starts from a full source medium page"
                        );
                        assert!(
                            crate::types::page_queue::page_is_in_full(medium_page),
                            "the full source medium remains in BIN_FULL until force collection"
                        );
                        for (index, block) in workload.full_medium.iter().enumerate() {
                            let Some(block) = *block else {
                                continue;
                            };
                            assert_eq!(
                                unsafe { allocator.test_page_for_block(block) },
                                medium_page_pointer.as_ptr(),
                                "full-medium client {index} stays in the exact source BIN_FULL page"
                            );
                        }

                        let unmapped_medium_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload.unmapped_full_medium[0]
                                    .expect("the owner-exit workload has an unchanged medium client"),
                            )
                        })
                        .expect("the unchanged owner-exit medium page stays PageMap-published before exit");
                        assert_ne!(
                            unmapped_medium_page_pointer,
                            medium_page_pointer,
                            "the source-unmapped witness occupies a distinct full medium page"
                        );
                        let unmapped_medium_page = unsafe { unmapped_medium_page_pointer.as_ref() };
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(
                                unmapped_medium_page.block_size(),
                            ),
                            Some(crate::types::PageKind::Medium),
                            "the unchanged source member remains a regular medium page"
                        );
                        assert_eq!(
                            unmapped_medium_page.used(),
                            usize::from(unmapped_medium_page.reserved()),
                            "the second full medium remains live without a joined remote free"
                        );
                        assert!(
                            crate::types::page_queue::page_is_in_full(unmapped_medium_page)
                                && !unmapped_medium_page.has_published_remote_free(),
                            "the second source member stays full and source-unmapped before A exits"
                        );
                        let full_medium_bin = crate::size_class::bin(medium_page.block_size())
                            .expect("both full medium pages use one regular bitmap bin");
                        assert_eq!(
                            crate::size_class::bin(unmapped_medium_page.block_size()),
                            Some(full_medium_bin),
                            "the paired medium witnesses share the same static-main bitmap class"
                        );
                        for (index, block) in workload.unmapped_full_medium.iter().enumerate() {
                            let Some(block) = *block else {
                                continue;
                            };
                            assert_eq!(
                                unsafe { allocator.test_page_for_block(block) },
                                unmapped_medium_page_pointer.as_ptr(),
                                "source-unmapped full-medium client {index} stays in its exact BIN_FULL page"
                            );
                        }

                        let initially_mapped_medium_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload.initially_mapped_medium[1].expect(
                                    "the owner-exit workload retains an initially mapped medium client",
                                ),
                            )
                        })
                        .expect("the initially mapped medium page stays PageMap-published before exit");
                        assert_ne!(
                            initially_mapped_medium_page_pointer,
                            medium_page_pointer,
                            "the initially mapped source member is distinct from the force-normalized medium"
                        );
                        assert_ne!(
                            initially_mapped_medium_page_pointer,
                            unmapped_medium_page_pointer,
                            "the initially mapped source member is distinct from the source-unmapped full medium"
                        );
                        let initially_mapped_medium_page =
                            unsafe { initially_mapped_medium_page_pointer.as_ref() };
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(
                                initially_mapped_medium_page.block_size(),
                            ),
                            Some(crate::types::PageKind::Medium),
                            "the local-free source member remains a regular medium page"
                        );
                        assert_eq!(
                            initially_mapped_medium_page.used() + 1,
                            usize::from(initially_mapped_medium_page.reserved()),
                            "A's one ordinary local free makes the third medium non-full before owner exit"
                        );
                        assert!(
                            !crate::types::page_queue::page_is_in_full(initially_mapped_medium_page)
                                && !initially_mapped_medium_page.has_published_remote_free(),
                            "the third medium reaches owner exit as an already-mapped, local-free regular member"
                        );
                        assert_eq!(
                            crate::size_class::bin(initially_mapped_medium_page.block_size()),
                            Some(full_medium_bin),
                            "all three medium members retain their one regular static-main bitmap class"
                        );
                        assert!(
                            workload.initially_mapped_medium[0].is_none(),
                            "the A-local medium client has left the private ledger before owner exit"
                        );
                        for (index, block) in workload.initially_mapped_medium[1..].iter().enumerate() {
                            let block = block.expect(
                                "the owner-exit workload retains every remaining initially mapped medium client",
                            );
                            assert_eq!(
                                unsafe { allocator.test_page_for_block(block) },
                                initially_mapped_medium_page_pointer.as_ptr(),
                                "initially mapped medium client {} stays in its exact regular page",
                                index + 1,
                            );
                        }

                        let force_empty_large_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload.force_empty_large.expect(
                                    "the owner-exit workload has its force-empty large client",
                                ),
                            )
                        })
                        .expect("the force-empty large page stays PageMap-published before exit");
                        let force_empty_large_page = unsafe { force_empty_large_page_pointer.as_ref() };
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(
                                force_empty_large_page.block_size(),
                            ),
                            Some(crate::types::PageKind::Large),
                            "the source traversal receives a regular large page that can become empty"
                        );
                        assert_eq!(
                            force_empty_large_page.used(),
                            1,
                            "the joined remote free is the large page's sole live client"
                        );
                        assert!(
                            !crate::types::page_queue::page_is_in_full(force_empty_large_page),
                            "the force-empty large page reaches the ordinary source queue before collection"
                        );
                        let live_large_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload
                                    .large
                                    [0]
                                    .expect("the owner-exit workload has its first surviving large client"),
                            )
                        })
                        .expect("the live large page stays PageMap-published before exit");
                        let live_large_page = unsafe { live_large_page_pointer.as_ref() };
                        assert_ne!(
                            force_empty_large_page_pointer,
                            live_large_page_pointer,
                            "distinct large bins keep the force-empty and abandoned branches independent"
                        );
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(live_large_page.block_size()),
                            Some(crate::types::PageKind::Large),
                            "the mixed departing Theap retains a second live large member"
                        );
                        assert_eq!(
                            live_large_page.used(),
                            OWNER_EXIT_LIVE_LARGE_CLIENT_SLOTS,
                            "both large clients remain live for B's sequential post-exit route"
                        );
                        for (index, block) in workload.large.iter().enumerate() {
                            let block = block
                                .expect("the owner-exit workload retains each live large client");
                            assert_eq!(
                                unsafe { allocator.test_page_for_block(block) },
                                live_large_page_pointer.as_ptr(),
                                "live large client {index} stays in one source page through owner exit"
                            );
                        }

                        let arena_singleton_page_pointer = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(
                                workload
                                    .arena_singleton
                                    .expect("the owner-exit workload has its live arena singleton"),
                            )
                        })
                        .expect("the live arena singleton stays PageMap-published before exit");
                        assert_ne!(
                            arena_singleton_page_pointer,
                            live_large_page_pointer,
                            "the source singleton remains distinct from the regular large member"
                        );
                        let arena_singleton_page = unsafe { arena_singleton_page_pointer.as_ref() };
                        assert_eq!(
                            arena_singleton_page.memid().kind(),
                            crate::types::MemoryKind::Arena,
                            "the bounded singleton follows the arena terminal-release branch"
                        );
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(
                                arena_singleton_page.block_size(),
                            ),
                            Some(crate::types::PageKind::Singleton),
                            "the bounded request crosses the source singleton page class"
                        );
                        assert_eq!(arena_singleton_page.reserved(), 1);
                        assert_eq!(arena_singleton_page.used(), 1);
                        assert!(
                            crate::types::page_queue::page_is_in_full(arena_singleton_page)
                                && !arena_singleton_page.has_published_remote_free(),
                            "the live arena singleton reaches source owner exit without a force-empty remote free"
                        );

                        let (medium, force_empty_large) = workload
                            .take_remote_clients()
                            .expect("the mixed owner-exit witness has both pre-exit remote clients");
                        // SAFETY: the medium and large clients are distinct,
                        // exact current allocations. B/C receive only their
                        // joined logical publication capabilities before A
                        // starts source collection.
                        let producers = TicketZeroRemoteFreeProducerPair {
                            producers: unsafe {
                                allocator.begin_remote_free_pair(medium, force_empty_large)
                            }
                            .expect(
                                "the full medium and force-empty large admit joined remote publication",
                            ),
                        };
                        let (medium_producer, large_producer) = producers.split();
                        let (medium_publication, large_publication) = thread::scope(|scope| {
                            let medium_publisher = scope.spawn(move || medium_producer.publish());
                            let large_publisher = scope.spawn(move || large_producer.publish());
                            (
                                medium_publisher
                                    .join()
                                    .expect("the medium publisher remains bounded by its join"),
                                large_publisher
                                    .join()
                                    .expect("the large publisher remains bounded by its join"),
                            )
                        });
                        if let Err(producer) = medium_publication {
                            let _ = producer.cancel();
                            panic!("the full source medium publishes its joined remote client");
                        }
                        if let Err(producer) = large_publication {
                            let _ = producer.cancel();
                            panic!("the sole source large page publishes its joined remote client");
                        }

                        let drain = match allocator.begin_thread_exit_drain() {
                            Ok(drain) => drain,
                            Err(crate::main_heap_page::MainHeapThreadProcessPageExitDrainFailure::Retained {
                                allocator,
                                error,
                            }) => {
                                core::mem::forget(allocator);
                                panic!(
                                    "the mixed full-medium worker enters its source exit drain: {error:?}"
                                );
                            }
                        };
                        let route = match unsafe {
                            drain.abandon_mapped_regular_pages_to_process_route()
                        } {
                            Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(
                                route,
                            )) => route,
                            Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::SoleImmediateMedium(
                                route,
                            )) => {
                                core::mem::forget(route);
                                return Err(());
                            }
                            Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(
                                drain,
                            )) => {
                                core::mem::forget(drain);
                                return Err(());
                            }
                            Err(
                                crate::main_heap_page::MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::Rejected {
                                    drain,
                                    error,
                                },
                            ) => {
                                core::mem::forget(drain);
                                panic!(
                                    "the mixed full-medium owner-exit source is rejected before collection: {error:?}"
                                );
                            }
                            Err(
                                crate::main_heap_page::MainHeapThreadProcessPageExitMappedRegularPagesRouteBeginFailure::RetainedDrain {
                                    drain,
                                    error,
                                },
                            ) => {
                                core::mem::forget(drain);
                                panic!(
                                    "the mixed full-medium owner-exit source is retained after collection: {error:?}"
                                );
                            }
                            Err(failure) => {
                                core::mem::forget(failure);
                                panic!(
                                    "the mixed full-medium owner-exit source cannot fail after route teardown"
                                );
                            }
                        };
                        assert_eq!(
                            route.test_remaining_pages(),
                            8,
                            "the aggregate releases the force-empty large during collection and retains direct-small, non-direct-small, live-large, force-normalized-medium, source-unmapped-full-medium, initially-mapped-medium, live-arena-singleton, and private-OS-singleton members"
                        );
                        assert_eq!(
                            route.test_abandoned_count_for_bin(full_medium_bin),
                            Some(2),
                            "the force-normalized and initially mapped mediums enter the static-main mapped bitmap at owner exit"
                        );
                        assert_eq!(
                            unmapped_medium_page.used(),
                            usize::from(unmapped_medium_page.reserved()),
                            "the unchanged full medium reaches B with every client still live"
                        );
                        assert!(
                            !crate::types::page_queue::page_is_in_full(unmapped_medium_page),
                            "A clears the old full-queue link before the source-unmapped aggregate tail begins"
                        );
                        let admission = admissions
                            .claim_later_thread()
                            .expect("the isolated admission word accepts owner-exit A");
                        let Some(mut blocks) = workload.into_post_exit_blocks() else {
                            core::mem::forget(route);
                            panic!("the remote medium client leaves the private workload before A exits");
                        };
                        // This direct lower-level test intentionally retains
                        // the historical direct-small witness positions solely
                        // to select the B/C/D publication group. The runtime
                        // owner path converts the same selection into opaque
                        // ledger keys before it suspends A;
                        // `TicketZeroOwnerExitFreeRoute` itself has no
                        // fixture-shaped indexing.
                        let Some(direct) = blocks[0].take() else {
                            core::mem::forget(route);
                            panic!("the post-exit B/C/D witness keeps its direct same-page client");
                        };
                        let Some(first_published) = blocks[1].take() else {
                            core::mem::forget(route);
                            panic!("the post-exit B/C/D witness keeps its first publisher same-page client");
                        };
                        let Some(second_published) = blocks[2].take() else {
                            core::mem::forget(route);
                            panic!("the post-exit B/C/D witness keeps its second publisher same-page client");
                        };
                        let mut entries = core::array::from_fn(|slot| {
                                blocks.get(slot).copied().flatten().map(|block| DetachedOwnerExitClient {
                                    key: DetachedOwnerExitClientKey {
                                        slot,
                                        generation: 1,
                                    },
                                    block,
                                    // This direct source-state fixture
                                    // retains the B/C/D group and therefore
                                    // deliberately has no raw-C
                                    // `malloc_usable_size` surface (see
                                    // `TicketZeroOwnerExitFreeRoute::native_usable_size`).
                                    // Keep a nonzero synthetic extent solely
                                    // so its private ledger still satisfies
                                    // the concrete detached-client shape; the
                                    // value is never observable outside this
                                    // lower-level witness.
                                    usable_size: 1,
                                    normal_request: match slot {
                                        0..OWNER_EXIT_DIRECT_SMALL_CLIENT_SLOTS => Some(37),
                                        OWNER_EXIT_NON_DIRECT_SMALL_START..OWNER_EXIT_LIVE_LARGE_START => {
                                            Some(OWNER_EXIT_NON_DIRECT_SMALL_REQUEST)
                                        }
                                        OWNER_EXIT_LIVE_LARGE_START..OWNER_EXIT_MAPPED_MEDIUM_START => {
                                            Some(OWNER_EXIT_LIVE_LARGE_REQUEST)
                                        }
                                        OWNER_EXIT_MAPPED_MEDIUM_START..OWNER_EXIT_ARENA_SINGLETON_INDEX => {
                                            Some(OWNER_EXIT_FULL_MEDIUM_REQUEST)
                                        }
                                        OWNER_EXIT_ARENA_SINGLETON_INDEX => {
                                            Some(OWNER_EXIT_ARENA_SINGLETON_REQUEST)
                                        }
                                        OWNER_EXIT_OS_SINGLETON_INDEX => None,
                                        _ => None,
                                    },
                                    // This direct lower-level fixture has
                                    // already proven the force-normalized
                                    // mapped medium's immediate source head.
                                    // Preserve that one fact when it builds a
                                    // private ledger without an A-side
                                    // preparation object; every other member
                                    // remains sequential-only.
                                    has_pre_exit_owner_exit_collectable_local_free:
                                        slot == OWNER_EXIT_MAPPED_MEDIUM_START,
                                })
                            });
                        // The private ledger schedules the force-normalized
                        // medium's last live client after every other member.
                        // Its address remains inside the ledger; when B
                        // reaches it, the aggregate route must make the
                        // source bitmap claim rather than fall through to a
                        // final sequential free.
                        entries.swap(
                            OWNER_EXIT_MAPPED_MEDIUM_START,
                            OWNER_EXIT_OS_SINGLETON_INDEX,
                        );
                        let clients = DetachedOwnerExitClientLedger::from_inline_entries(entries);
                        let adoption_count_before =
                            AGGREGATE_LAST_MAPPED_REGULAR_ADOPTION_COUNT.load(Ordering::Relaxed);
                        let post_exit = TicketZeroOwnerExitFreeRoute {
                            route,
                            clients,
                            post_exit_remote_publication_group: Some(
                                DetachedOwnerExitRemotePublicationGroup {
                                    kind: DetachedOwnerExitRemotePublicationKind::DirectSmall,
                                    direct: Some(direct),
                                    first_published: Some(first_published),
                                    second_published: Some(second_published),
                                },
                            ),
                            pair,
                            admission,
                            _consumer: PhantomData,
                        };
                        assert_eq!(
                            admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
                            1,
                            "A stays admitted until B proves the aggregate route terminally released"
                        );
                        assert_eq!(
                            attachment.finish_after_page_drain(),
                            Err(crate::main_heap_thread::MainHeapThreadAttachmentError::TornDown),
                            "A's old Theap/TLD is gone before B receives the private route"
                        );

                        let outcome = thread::scope(|scope| {
                            let admissions = &admissions;
                            let consumer = scope.spawn(move || {
                                // B owns neither A's detached attachment nor
                                // any of A's private client identities. It
                                // first creates its own independent no-page
                                // attachment, consumes only the opaque route,
                                // and proves that its ordinary finish leaves
                                // no shared-main/TLD metadata residue.
                                let b_admission = admissions
                                    .claim_later_thread()
                                    .expect("the fresh post-exit consumer B receives its own admission");
                                assert_eq!(
                                    admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
                                    2,
                                    "A's detached route and B's new attachment remain independently admitted"
                                );
                                let mut b_attachment = match unsafe {
                                    MainHeapThreadAttachment::begin_with_test_metadata(
                                        main_heap,
                                        metadata,
                                        config,
                                    )
                                } {
                                    Ok(attachment) => attachment,
                                    Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                        panic!(
                                            "the fresh post-exit consumer B begins its no-page attachment: {error:?}"
                                        )
                                    }
                                    Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                                        panic!(
                                            "the fresh post-exit consumer B cannot retain during attachment: {error:?}"
                                        )
                                    }
                                };
                                let outcome = post_exit.free_remaining_with_post_exit_publisher(
                                    &mut b_attachment,
                                    TicketZeroOwnerExitPostExitPublisher::DirectSmall(
                                        publish_post_exit_remote_free_from_scoped_workers,
                                    ),
                                );
                                b_attachment
                                    .finish_after_user_destructors()
                                    .expect(
                                        "the route-consuming B finishes only its own no-page attachment",
                                    );
                                match admissions.release_later_thread(b_admission) {
                                    Ok(()) => {}
                                    Err(admission) => {
                                        core::mem::forget(admission);
                                        panic!(
                                            "B releases its own admission before returning A's terminal proof"
                                        );
                                    }
                                }
                                assert_eq!(
                                    admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
                                    1,
                                    "B's normal finalizer cannot release A's detached-route admission"
                                );
                                outcome
                            });
                            consumer
                                .join()
                                .expect("the post-exit consumer remains bounded by its join")
                        });
                        match outcome {
                            TicketZeroOwnerExitFreeOutcome::Finished(proof) => {
                                assert!(
                                    AGGREGATE_LAST_MAPPED_REGULAR_ADOPTION_COUNT
                                        .load(Ordering::Relaxed)
                                        > adoption_count_before,
                                    "the final force-normalized medium crosses the aggregate last-member adoption boundary"
                                );
                                match proof.release_worker_admission(&admissions) {
                                    Ok(()) => {}
                                    Err(proof) => {
                                        core::mem::forget(proof);
                                        panic!(
                                            "the terminal route proof releases its exact worker admission"
                                        );
                                    }
                                }
                            }
                            TicketZeroOwnerExitFreeOutcome::Retained(route) => {
                                core::mem::forget(route);
                                panic!("the private full-medium owner-exit route terminally releases");
                            }
                            TicketZeroOwnerExitFreeOutcome::Poisoned(poisoned) => {
                                core::mem::forget(poisoned);
                                panic!("the private full-medium owner-exit route avoids PageMap poisoning");
                            }
                        }
                        assert_eq!(
                            admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
                            0,
                            "B's terminal proof is the only transition that makes A fork-quiescent"
                        );
                        Ok(())
                    });
                    assert_eq!(
                        completed,
                        Some(()),
                        "the dormant ticket-zero pair completes mixed owner-exit cycle {worker_number}"
                    );
                })
                .join()
                .expect("each mixed owner-exit A remains on a fresh worker thread");

                let after_worker = persistent_worker_state_audit(
                    runtime,
                    arena_storage,
                    metadata,
                    main_static,
                    subprocess,
                );
                let expected_total_thread_count = baseline.total_thread_count + worker_number * 2;
                match warmed_owner_exit_state {
                    Some(warmed) => {
                        let expected = PersistentWorkerStateAudit {
                            total_thread_count: expected_total_thread_count,
                            ..warmed
                        };
                        assert_eq!(
                            after_worker, expected,
                            "mixed owner-exit cycle {worker_number} leaves no PageMap, arena, TLD, or Theap residue after warmup"
                        );
                    }
                    None => {
                        assert!(
                            after_worker.page_map_published_submap_count
                                >= baseline.page_map_published_submap_count
                                && after_worker.page_map_lazy_submap_allocation_count
                                    >= baseline.page_map_lazy_submap_allocation_count,
                            "the first OS owner-exit cycle may publish, but never discard, its process PageMap submaps"
                        );
                        let expected = PersistentWorkerStateAudit {
                            total_thread_count: expected_total_thread_count,
                            page_map_published_submap_count: after_worker
                                .page_map_published_submap_count,
                            page_map_lazy_submap_allocation_count: after_worker
                                .page_map_lazy_submap_allocation_count,
                            ..baseline
                        };
                        assert_eq!(
                            after_worker, expected,
                            "the first mixed owner-exit warmup leaves only the retained process PageMap submaps"
                        );
                        warmed_owner_exit_state = Some(after_worker);
                    }
                }
                let metadata_audit = metadata.test_allocation_audit();
                assert_eq!(
                    metadata_audit.live_capability_count,
                    baseline.metadata_live_capability_count,
                    "mixed owner-exit cycle {worker_number} releases every TLD/Theap metadata capability"
                );
                match warmed_metadata_high_water {
                    Some(high_water) => assert_eq!(
                        metadata_audit.high_water_capability_count,
                        high_water,
                        "mixed owner-exit cycle {worker_number} does not raise metadata capability high-water after warmup"
                    ),
                    None => {
                        warmed_metadata_high_water =
                            Some(metadata_audit.high_water_capability_count);
                    }
                }
            }

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .expect("ticket zero reactivates after every owner-exit cycle")
                .expect("the resumed ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `resumed` is the exact current ticket-zero block.
                    unsafe { owner.free(resumed) }
                })
                .expect("the resumed ticket-zero owner stays callable")
                .expect("the resumed ticket-zero block frees normally");
        })
        .join()
        .expect("the isolated runtime restores its retained baseline after repeated mixed owner exits");
    }

    #[test]
    fn dormant_ticket_zero_page_owner_repeats_mapped_regular_reclamation_without_state_growth() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .expect("ticket zero starts its first page engine")
                .expect("the first ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `first` is the exact current ticket-zero block.
                    unsafe { owner.free(first) }
                })
                .expect("ticket zero remains callable after its first allocation")
                .expect("the first ticket-zero block frees into the dormant state");

            let baseline =
                persistent_worker_state_audit(runtime, arena_storage, metadata, main_static, subprocess);
            assert_eq!(baseline.runtime_process_state, PROCESS_ACTIVE);
            assert_eq!(baseline.page_owner_state, PAGE_OWNER_READY);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);
            assert_eq!(baseline.metadata_live_capability_count, 0);
            assert_eq!(baseline.shared_later_theap_count, 0);
            assert_eq!(
                baseline.main_heap_abandoned_counts,
                [0; crate::config::BIN_COUNT],
                "the dormant ticket-zero owner has no leaked static-main abandoned bitmap/count pairing"
            );
            assert_eq!(
                baseline.main_heap_os_abandoned_page,
                0,
                "the dormant ticket-zero owner has no leaked private OS-abandoned list member"
            );

            // A medium span may be the first source user of its PageMap
            // submap. That immutable process allocation is not a worker leak,
            // but every subsequent A -> B reclamation cycle must plateau. The
            // test alternates the aggregate sole-medium result and the distinct
            // direct-small drain: these are source-specific lower boundaries,
            // while their B adoption/drain and terminal accounting are one
            // common mapped-regular lifecycle.
            let mut warmed_reclaim_state = None;
            let mut warmed_metadata_high_water = None;

            for worker_number in 1..=OWNER_EXIT_STATE_AUDIT_CYCLES {
                let predecessor = if worker_number % 2 == 0 {
                    MappedRegularReclaimPredecessor::DirectSmall
                } else {
                    MappedRegularReclaimPredecessor::Medium
                };
                thread::spawn(move || {
                    // SAFETY: the test keeps the permanent process owner and
                    // copied shared-main Heap witness alive through both A's
                    // source exit and B's exact reclaim/drain lifecycle.
                    let process_owner = unsafe { runtime.active_owner() }
                        .expect("the process owner stays published for reclaim A");
                    let config = process_owner
                        .ready()
                        .and_then(|ready| ready.memory_config())
                        .expect("reclaim A observes the frozen process config");
                    let main_heap = unsafe { runtime.active_main_heap() }
                        .expect("reclaim A copies the ticket-zero main Heap witness");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("reclaim A begins its shared-main attachment: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("reclaim A cannot retain during attachment: {error:?}")
                        }
                    };
                    let admissions = RuntimeForkAdmission::new();

                    let completed = runtime.with_dormant_page_pair(|pair| {
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut attachment, pair)
                            .expect("the dormant ticket-zero pair admits reclaim A");
                        let (first, blocks, request, expected_kind, source_name) = match predecessor {
                            MappedRegularReclaimPredecessor::Medium => {
                                let workload = OwnerExitReclaimWorkload::allocate(&mut allocator)
                                    .expect("reclaim A establishes the sole immediate-medium source image");
                                let blocks = workload
                                    .into_blocks()
                                    .expect("the medium reclamation workload retains both opaque A clients");
                                (
                                    blocks[0].expect("the first medium reclamation client remains live"),
                                    blocks,
                                    OWNER_EXIT_RECLAIM_MEDIUM_REQUEST,
                                    crate::types::PageKind::Medium,
                                    "sole-medium aggregate",
                                )
                            }
                            MappedRegularReclaimPredecessor::DirectSmall => {
                                let workload = OwnerExitDirectSmallReclaimWorkload::allocate(&mut allocator)
                                    .expect("reclaim A establishes the direct-small source image");
                                let (first, blocks) = workload
                                    .into_route_parts()
                                    .expect("the direct-small workload retains both opaque A clients");
                                (
                                    first,
                                    blocks,
                                    OWNER_EXIT_RECLAIM_DIRECT_SMALL_REQUEST,
                                    crate::types::PageKind::Small,
                                    "direct-small source drain",
                                )
                            }
                        };
                        let second = blocks[1]
                            .expect("the second opaque reclamation client remains live");
                        let page = core::ptr::NonNull::new(unsafe {
                            allocator.test_page_for_block(first)
                        })
                        .expect("the source reclamation page remains PageMap-published before exit");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(second) },
                            page.as_ptr(),
                            "both inherited reclamation clients occupy the one {source_name} page"
                        );
                        let page_ref = unsafe { page.as_ref() };
                        assert_eq!(
                            crate::size_class::page_kind_for_block_size(page_ref.block_size()),
                            Some(expected_kind),
                            "the runtime reclamation witness starts from the {source_name} class"
                        );
                        assert_eq!(
                            page_ref.used(),
                            OWNER_EXIT_RECLAIM_CLIENT_SLOTS,
                            "only the two opaque inherited clients remain live when A exits"
                        );
                        let page_address = page.as_ptr().expose_provenance();
                        let block_addresses = blocks.map(|block| {
                            block
                                .expect("each opaque source client remains live")
                                .as_ptr()
                                .expose_provenance()
                        });

                        let drain = match allocator.begin_thread_exit_drain() {
                            Ok(drain) => drain,
                            Err(crate::main_heap_page::MainHeapThreadProcessPageExitDrainFailure::Retained {
                                allocator,
                                error,
                            }) => {
                                core::mem::forget(allocator);
                                panic!("reclaim A enters its source exit drain: {error:?}");
                            }
                        };
                        let route = match predecessor {
                            MappedRegularReclaimPredecessor::Medium => match unsafe {
                                drain.abandon_mapped_regular_pages_to_process_route()
                            } {
                                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::SoleImmediateMedium(
                                    route,
                                )) => route,
                                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Route(route)) => {
                                    core::mem::forget(route);
                                    panic!("the sole source medium must not broaden into an aggregate registry");
                                }
                                Ok(MainHeapThreadProcessPageExitMappedRegularPagesRouteBegin::Drained(drain)) => {
                                    core::mem::forget(drain);
                                    panic!("two live inherited clients cannot become an empty source drain");
                                }
                                Err(failure) => {
                                    core::mem::forget(failure);
                                    panic!("the source-shaped sole medium completes A's owner exit");
                                }
                            },
                            MappedRegularReclaimPredecessor::DirectSmall => match unsafe {
                                drain.abandon_mapped_small_or_medium_to_process_route(first)
                            } {
                                Ok(route) => route,
                                Err(failure) => {
                                    core::mem::forget(failure);
                                    panic!("the direct-small source drain completes A's owner exit");
                                }
                            },
                        };
                        assert!(
                            !unsafe { page.as_ref().free_list_head() }.is_null(),
                            "A's {source_name} owner exit transfers the returned spare into the source route's required immediate head"
                        );
                        assert_eq!(
                            route.test_abandoned_count(),
                            Some(1),
                            "A publishes exactly its one {source_name} page to the static-main abandoned count"
                        );
                        let admission = admissions
                            .claim_later_thread()
                            .expect("the isolated admission word accepts reclaim A");
                        assert_eq!(
                            attachment.finish_after_page_drain(),
                            Err(crate::main_heap_thread::MainHeapThreadAttachmentError::TornDown),
                            "A's old Theap/TLD is gone before B receives the reclaim route"
                        );

                        let proof = thread::scope(|scope| {
                            let admissions = &admissions;
                            let target = scope.spawn(move || {
                                let target_admission = admissions
                                    .claim_later_thread()
                                    .expect("the isolated admission word accepts reclaim B");
                                let mut target_attachment = match unsafe {
                                    MainHeapThreadAttachment::begin_with_test_metadata(
                                        main_heap,
                                        metadata,
                                        config,
                                    )
                                } {
                                    Ok(attachment) => attachment,
                                    Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                        panic!("reclaim B begins its shared-main attachment: {error:?}")
                                    }
                                    Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                                        panic!("reclaim B cannot retain during attachment: {error:?}")
                                    }
                                };
                                let mut target_allocator = match route
                                    .adopt_into_later_main(&mut target_attachment, pair)
                                {
                                    Ok(allocator) => allocator,
                                    Err(
                                        MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Rejected {
                                            route,
                                            error,
                                        },
                                    ) => {
                                        core::mem::forget(route);
                                        panic!("reclaim B adopts A's exact source route: {error:?}");
                                    }
                                    Err(
                                        MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Retained {
                                            adoption,
                                            error,
                                        },
                                    ) => {
                                        core::mem::forget(adoption);
                                        panic!("reclaim B cannot retain its source-valid adoption: {error:?}");
                                    }
                                    Err(
                                        MainHeapThreadProcessPageExitMappedRegularAdoptFailure::Reabandoned {
                                            adoption,
                                            error,
                                        },
                                    ) => {
                                        core::mem::forget(adoption);
                                        panic!("the immediate-head reclaim cannot reabandon: {error:?}");
                                    }
                                };
                                let reused = target_allocator
                                    .allocate(request, false)
                                    .expect("reclaim B consumes A's immediate source head");
                                assert_eq!(
                                    unsafe { target_allocator.test_page_for_block(reused) },
                                    core::ptr::with_exposed_provenance_mut(page_address),
                                    "B's first allocation reuses A's exact PageMap identity"
                                );
                                for address in block_addresses {
                                    let block = core::ptr::NonNull::new(
                                        core::ptr::with_exposed_provenance_mut(address),
                                    )
                                    .expect("the inherited A client address remains non-null");
                                    // SAFETY: A transferred this exact once-live client only through
                                    // the joined typed source route; B now owns its normal engine.
                                    unsafe { target_allocator.free(block) }
                                        .expect("B frees each inherited A client through its reclaimed page");
                                }
                                // SAFETY: `reused` is B's exact current allocation in the same
                                // reclaimed engine and has no external alias.
                                unsafe { target_allocator.free(reused) }
                                    .expect("B frees its reclaimed-page allocation");
                                match target_allocator.finish() {
                                    Ok(()) => {}
                                    Err(allocator) => {
                                        core::mem::forget(allocator);
                                        panic!("B's page engine finishes only after all reclaimed clients free");
                                    }
                                }
                                target_attachment
                                    .finish_after_user_destructors()
                                    .expect("B completes ordinary later-thread teardown after its engine drains");
                                match admissions.release_later_thread(target_admission) {
                                    Ok(()) => {}
                                    Err(admission) => {
                                        core::mem::forget(admission);
                                        panic!("B releases its own completed admission before returning A's proof");
                                    }
                                }
                                TicketZeroOwnerExitRouteFinished { admission }
                            });
                            target
                                .join()
                                .expect("the distinct reclaim B remains bounded by its join")
                        });
                        match proof.release_worker_admission(&admissions) {
                            Ok(()) => {}
                            Err(proof) => {
                                core::mem::forget(proof);
                                panic!(
                                    "only B's terminal reclaim/drain proof releases A's admission"
                                );
                            }
                        }
                        assert_eq!(
                            admissions.state.load(Ordering::Acquire) & FORK_GATE_COUNT_MASK,
                            0,
                            "both A and B admissions complete only after the reclaimed page terminally drains"
                        );
                        Ok(())
                    });
                    assert_eq!(
                        completed,
                        Some(()),
                        "the dormant ticket-zero pair completes mapped-regular reclamation cycle {worker_number}"
                    );
                })
                .join()
                .expect("each mapped-regular reclamation A remains on a fresh worker thread");

                let after_worker = persistent_worker_state_audit(
                    runtime,
                    arena_storage,
                    metadata,
                    main_static,
                    subprocess,
                );
                let expected_total_thread_count = baseline.total_thread_count + worker_number * 2;
                match warmed_reclaim_state {
                    Some(warmed) => {
                        let expected = PersistentWorkerStateAudit {
                            total_thread_count: expected_total_thread_count,
                            ..warmed
                        };
                        assert_eq!(
                            after_worker, expected,
                            "mapped-regular reclamation cycle {worker_number} leaves no PageMap, arena, TLD, Theap, or abandoned-page residue after warmup"
                        );
                    }
                    None => {
                        assert!(
                            after_worker.page_map_published_submap_count
                                >= baseline.page_map_published_submap_count
                                && after_worker.page_map_lazy_submap_allocation_count
                                    >= baseline.page_map_lazy_submap_allocation_count,
                            "the first mapped-regular reclamation cycle may publish, but never discard, process PageMap submaps"
                        );
                        let expected = PersistentWorkerStateAudit {
                            total_thread_count: expected_total_thread_count,
                            page_map_published_submap_count: after_worker
                                .page_map_published_submap_count,
                            page_map_lazy_submap_allocation_count: after_worker
                                .page_map_lazy_submap_allocation_count,
                            ..baseline
                        };
                        assert_eq!(
                            after_worker, expected,
                            "the first mapped-regular reclamation warmup leaves only retained process PageMap submaps"
                        );
                        warmed_reclaim_state = Some(after_worker);
                    }
                }
                let metadata_audit = metadata.test_allocation_audit();
                assert_eq!(
                    metadata_audit.live_capability_count,
                    baseline.metadata_live_capability_count,
                    "mapped-regular reclamation cycle {worker_number} releases every A/B TLD and Theap metadata capability"
                );
                match warmed_metadata_high_water {
                    Some(high_water) => assert_eq!(
                        metadata_audit.high_water_capability_count,
                        high_water,
                        "mapped-regular reclamation cycle {worker_number} does not raise metadata capability high-water after warmup"
                    ),
                    None => {
                        warmed_metadata_high_water =
                            Some(metadata_audit.high_water_capability_count);
                    }
                }
            }

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .expect("ticket zero reactivates after every mapped-regular reclamation cycle")
                .expect("the resumed ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `resumed` is the exact current ticket-zero block.
                    unsafe { owner.free(resumed) }
                })
                .expect("the resumed ticket-zero owner stays callable")
                .expect("the resumed ticket-zero block frees normally");
        })
        .join()
        .expect("the isolated runtime restores its retained baseline after repeated mapped-regular reclamation");
    }

    /// A short post-exit route operation and a fresh persistent session both
    /// take the lower PageMap mutation lease, while only the latter holds the
    /// runtime scheduler claim. The lower `LifecycleBusy` refusal is therefore
    /// a normal bounded interleaving: it must restore that scheduler claim so
    /// the fresh worker can retry once the route operation returns.
    #[test]
    fn persistent_engine_begin_restores_scheduler_after_page_map_contention() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            // SAFETY: this test publishes one permanent owner into its fresh
            // isolated runtime before any worker observes the scheduler.
            unsafe { publish_test_owner(runtime, owner) };

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .flatten()
                .expect("ticket zero activates the shared first arena");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `first` is still the exact current ticket-zero
                    // client and this exclusive operation consumes it once.
                    unsafe { owner.free(first) }
                })
                .expect("ticket zero remains callable after the first allocation")
                .expect("ticket zero returns the first arena to its dormant pair");

            assert!(
                runtime.register_active_post_exit_route(),
                "the synthetic source route records its narrower active capability before it parks"
            );
            assert_eq!(
                runtime.page_owner_state.compare_exchange(
                    PAGE_OWNER_READY,
                    PAGE_OWNER_PARKED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(PAGE_OWNER_READY),
                "the synthetic source route contributes the one parked scheduler token"
            );
            let parked_route = RuntimeParkedPostExitRoute {
                runtime,
                source_route_active: true,
                terminal_completion_pending: false,
                terminal_retained: false,
                active: true,
            };

            let process_owner = unsafe { runtime.active_owner() }
                .expect("the permanent process owner stays published");
            let config = process_owner
                .ready()
                .and_then(|ready| ready.memory_config())
                .expect("the worker observes the process-frozen configuration");
            let main_heap = unsafe { runtime.active_main_heap() }
                .expect("the worker copies the permanent main-heap witness");
            let page_map = process_owner
                .ready()
                .and_then(|ready| ready.page_map())
                .expect("the permanent owner retains its PageMap lease");
            let contention = page_map
                .begin_page_lifecycle()
                .expect("the test owns one complete lower PageMap operation");

            thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut attachment = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap, metadata, config,
                            )
                        } {
                            Ok(attachment) => attachment,
                            Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                panic!("the contender attaches before it asks for a page engine: {error:?}")
                            }
                            Err(MainHeapThreadAttachmentBeginError::Retained {
                                attachment,
                                error,
                            }) => {
                                core::mem::forget(attachment);
                                panic!("the contender attachment stays healthy: {error:?}")
                            }
                        };
                        assert!(
                            matches!(
                                runtime.begin_persistent_later_engine(&mut attachment),
                                Err(RuntimePersistentPageEngineBeginError::PageMapBusy)
                            ),
                            "a lower PageMap contention restores the scheduler instead of retaining the runtime"
                        );
                        attachment
                            .finish_after_user_destructors()
                            .expect("the rejected contender still has its ordinary no-page teardown");
                    })
                    .join()
                    .expect("the contending worker returns from its retryable begin refusal");
            });

            assert_eq!(
                runtime.state.load(Ordering::Acquire),
                PROCESS_ACTIVE,
                "a retryable PageMap contention leaves the process runtime active"
            );
            assert_eq!(
                runtime.page_owner_state.load(Ordering::Acquire),
                PAGE_OWNER_PARKED,
                "the rejected fresh session restores exactly the scheduler state it claimed"
            );
            contention
                .finish()
                .expect("the independently held lower PageMap operation completes normally");

            thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut attachment = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap, metadata, config,
                            )
                        } {
                            Ok(attachment) => attachment,
                            Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                panic!("the retry worker attaches after contention clears: {error:?}")
                            }
                            Err(MainHeapThreadAttachmentBeginError::Retained {
                                attachment,
                                error,
                            }) => {
                                core::mem::forget(attachment);
                                panic!("the retry worker attachment stays healthy: {error:?}")
                            }
                        };
                        let engine = runtime
                            .begin_persistent_later_engine(&mut attachment)
                            .expect("the same fresh session begins after the lower operation returns");
                        match engine.finish() {
                            Ok(()) => {}
                            Err(error) => {
                                core::mem::forget(error);
                                panic!("the empty retry engine restores the dormant scheduler")
                            }
                        }
                        attachment
                            .finish_after_user_destructors()
                            .expect("the successful retry worker completes normal teardown");
                    })
                    .join()
                    .expect("the retry worker completes after PageMap contention clears");
            });

            assert_eq!(
                runtime.page_owner_state.load(Ordering::Acquire),
                PAGE_OWNER_PARKED,
                "the successful retry retains the detached route's one parked scheduler token"
            );
            let terminal_route = match parked_route.finish_source_route() {
                Ok(route) => route,
                Err(route) => {
                    core::mem::forget(route);
                    panic!("the synthetic source route becomes a terminal B completion")
                }
            };
            match terminal_route.finish_after_b() {
                Ok(()) => {}
                Err(route) => {
                    core::mem::forget(route);
                    panic!("the synthetic B completion releases its one parked route token")
                }
            }
            assert_eq!(
                runtime.page_owner_state.load(Ordering::Acquire),
                PAGE_OWNER_READY,
                "the terminal source route finally returns ticket zero to its dormant state"
            );
        })
        .join()
        .expect("the isolated retryable-contention runtime remains thread-local");
    }
}
