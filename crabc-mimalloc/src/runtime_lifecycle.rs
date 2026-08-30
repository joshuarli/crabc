// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license is included in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:236-282,305-360,377-421,
// 448-481`, `src/theap.c:228-306,414-449`, `src/threadlocal.c:205-214`,
// `src/free.c:372-418,479-515`, and `src/prim/unix/prim.c:943-974`; the
// direct libc fork placement follows pinned musl 1.2.6 `src/process/fork.c`.

//! Private crabc-runtime lifecycle bridge.
//!
//! This module is the one direct Rust boundary used by `crabc-libc` while the
//! C mimalloc backend remains the production allocator. It retains the
//! source-shaped ticket-zero `ProcessMainThread` and the main-thread-minted
//! `MainStaticHeapLease` for the process lifetime, then places one no-page
//! `MainHeapThreadAttachment` in compiler TLS for each pthread worker that
//! successfully enters through the runtime. A dormant ticket-zero native page
//! owner may lend its already-published pair to one such worker for a bounded
//! local or joined remote-free page-engine round trip; the worker finishes
//! only after libc has run user cleanup handlers and pthread TSD destructors.
//!
//! It deliberately does not route any `malloc`/`free` call, expose a C symbol,
//! select a backend, create a public pthread key, or claim general fork
//! recovery. A failed process setup leaves this shadow lifecycle unavailable
//! and preserves the C backend. A failed worker attachment prevents that
//! worker's start routine from running; libc performs the parent/child startup
//! handshake. On libc's prepared `fork` path, only the original ticket-zero
//! TLS image with no live or retained later bridge owner preserves the copied
//! no-page process owner. Every other child disables this incomplete lifecycle
//! without traversing inherited locks, roots, or page state.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
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
use crate::process_arena::{ProcessPageArenaLease, ProcessSharedArenaStorage};
use crate::process_page_map::{ProcessPageMapError, ProcessPageMapLease};
use crate::remote_free;
use crate::single_thread::{
    RemoteFreeProducer, RemoteFreeProducerPair,
    ThreadExitKnownPostExitOsAbandonedList,
    ThreadExitMappedRegularPagesPostExitRemoteFreeProducer,
    ThreadExitMappedRegularPagesPostExitRemoteFreeProducerPair,
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
const PAGE_OWNER_PARKED_BASE: usize = 4;
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
/// `COLD`, `STARTING`, `BUSY`, and `RETAINED` deliberately have no count:
/// none represents a retryable collection of suspended owner tokens.
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

// Appending one permanent metadata-backed registry entry is separate from an
// entry's own `ACTIVE -> BUSY` route serialization. Nodes never move or leave
// the list, so a reader that acquired the list head may inspect a stable entry
// without a raw-pointer lifetime race. Empty entries are reused; growth only
// records the process high-water of concurrently detached source owners.
const NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE: u8 = 0;
const NATIVE_POST_EXIT_ROUTE_REGISTRY_GROWING: u8 = 1;
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
// without exposing a client or node identity; growth never serializes ordinary
// PageMap work or a different entry's `ACTIVE -> BUSY` transition.
const NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE: u8 = 0;
const NATIVE_LIVE_REMOTE_OWNER_REGISTRY_GROWING: u8 = 1;
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
// This stays inside the source's OS-aligned singleton profile: the block is
// small, while its 128 KiB alignment exceeds the in-arena path and remains
// below the 256 MiB metadata-alignment ceiling.
const OWNER_EXIT_OS_SINGLETON_REQUEST: usize = 7;
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
const OWNER_EXIT_ARENA_SINGLETON_INDEX: usize =
    OWNER_EXIT_UNMAPPED_FULL_MEDIUM_START + OWNER_EXIT_FULL_MEDIUM_MAX_CLIENT_SLOTS;
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
/// identities may use only the already-published copy. Main-thread teardown
/// needs a complete process-exit/fork contract and remains deliberately out
/// of scope while later workers can still carry source list members.
struct RuntimeProcessStorage {
    state: AtomicU8,
    /// The ticket-zero Linux/AArch64 TPIDR_EL0 identity. A copied process
    /// foundation can be preserved only when `fork` runs on this same TLS
    /// image; a foreign caller has no authority to treat the static TLD as
    /// its current-thread owner.
    initial_thread_identity: AtomicUsize,
    owner: UnsafeCell<MaybeUninit<ProcessMainThread>>,
    main_heap: UnsafeCell<MaybeUninit<MainStaticHeapLease<'static>>>,
    /// The permanent ticket-zero page owner is absent until the private
    /// native seam asks it for a valid allocation. It stays in this final
    /// slot afterward: source-shaped process exit is still out of scope.
    page_owner_state: AtomicUsize,
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
        match self.settle(park_state) {
            Ok(()) => Ok(RuntimeParkedPostExitRoute {
                runtime,
                active: true,
            }),
            Err(operation) => Err(operation),
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
    /// Removes this exact detached route from the scheduler only after its
    /// matched B worker has completed ordinary no-page teardown.
    ///
    /// No PageMap mutation occurs here: the terminal exact free completed
    /// that source lifecycle under its route-owned short access before it
    /// created the B-side completion. A direct parked-count transition keeps
    /// other detached routes and independently parked normal engines intact.
    fn finish_after_b(mut self) -> Result<(), Self> {
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
    /// remote head. This wrapper exists only for the complete non-parkable B
    /// operation; it exposes neither the allocator nor its PageMap lease to
    /// the native libc boundary.
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
            page_owner: UnsafeCell::new(MaybeUninit::uninit()),
        }
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

    /// Returns the process-static PageMap witness for the narrow source
    /// remote-free lookup of an exact ticket-zero client.
    ///
    /// This intentionally shares only the immutable root witness, never the
    /// permanent owner, its page lifecycle lock, or an ordinary `&mut`
    /// engine. A live allocation itself supplies the same-slice lifetime
    /// proof consumed by `ProcessPageMapLease::lookup_page_for_live_client`.
    #[inline]
    fn page_map_for_live_ticket_zero_client(&'static self) -> Option<ProcessPageMapLease> {
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
            Ok(_) => {}
            Err(PAGE_OWNER_READY) => return true,
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
        if self
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
        // SAFETY: READY -> BUSY serializes every mutable engine operation;
        // `start_ticket_zero_page_owner` wrote this final slot before its
        // READY Release publication, and the current TPIDR check prevents a
        // pthread worker from borrowing the ticket-zero engine.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        let result = operation(owner);
        if owner.is_retained() {
            self.retain();
            self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
        } else {
            self.page_owner_state.store(PAGE_OWNER_READY, Ordering::Release);
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
        // SAFETY: READY -> BUSY serializes this mutable permanent owner with
        // ticket zero. The final slot was written before READY's Release
        // publication and is never moved or replaced.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        match owner.with_dormant_page_pair(operation) {
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

        // SAFETY: expected -> BUSY serializes every mutable access to the
        // final permanent owner. `with_dormant_page_pair` itself restores its
        // immutable dormant source state before this method returns; the
        // operation below owns only whether ticket zero may enter again.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        match owner.with_dormant_page_pair(Ok) {
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
    /// attachments.  That ordering matters: a READY ticket-zero owner may be
    /// mutably borrowed by a later engine, so reading its dormant source image
    /// before worker admission is closed would be an unsound concurrent view.
    /// The callback is an allocation-free private predicate for the direct
    /// libc fork path; it never exposes a page or fork capability.
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
                // Therefore the predicate may safely inspect a READY
                // permanent ticket-zero owner before this raw fork.
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
    /// later attachment. The explicit token prevents an unprepared raw fork
    /// on another thread from mistaking copied gate bits for its own proof.
    fn after_fork_child(&self, fork_was_prepared: bool) -> bool {
        let observed = self.state.swap(0, Ordering::AcqRel);
        fork_was_prepared
            && (observed & (FORK_GATE_HELD | FORK_GATE_PRESERVE))
            == (FORK_GATE_HELD | FORK_GATE_PRESERVE)
            && observed & FORK_GATE_COUNT_MASK == 0
    }
}

static RUNTIME_FORK_ADMISSION: RuntimeForkAdmission = RuntimeForkAdmission::new();

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

/// A terminal native post-exit route paired with its still-parked
/// detached-route scheduler token.
///
/// A route may return its typed PageMap/admission proof after B's final C
/// `free`, but B's no-page TLD/Theap is still live until its normal pthread
/// finish. Keeping the parked token beside that proof prevents ticket zero
/// from borrowing the dormant pair during this final B-only interval. The
/// completion may remove only its route's parked token after B has detached
/// its own attachment, then releases A's admission proof.
#[must_use = "a terminal native route completion must finish B or remain retained"]
struct NativePostExitRouteCompletion {
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
    RetainedRoute(NativePostExitRoute),
    RetainedFinished {
        parked: RuntimeParkedPostExitRoute,
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

/// One registry entry's observable ownership state.
///
/// `Live` includes the brief private `BUSY` move while its exact B-side
/// operation runs. A retained entry closes the whole process runtime, so a
/// later source owner may not use it as evidence that another route can
/// safely append an OS-abandoned-list member.
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

// SAFETY: all access to `entry` first claims `ACTIVE -> BUSY` with AcqRel.
// The static has one writer while installing and one mutable route consumer
// at a time; retained entries are never read as active again.
unsafe impl Sync for NativePostExitRouteStorage {}

impl NativePostExitRouteStorage {
    #[inline]
    fn from_active(route: NativePostExitRoute) -> Self {
        Self {
            state: AtomicU8::new(NATIVE_POST_EXIT_ROUTE_ACTIVE),
            entry: UnsafeCell::new(MaybeUninit::new(NativePostExitRouteEntry::Active(route))),
        }
    }

    /// Classifies one stable metadata entry without exposing its route,
    /// clients, PageMap access, or admission capability.
    #[inline]
    fn registry_state(&self) -> NativePostExitRouteStorageState {
        match self.state.load(Ordering::Acquire) {
            NATIVE_POST_EXIT_ROUTE_EMPTY => NativePostExitRouteStorageState::Empty,
            NATIVE_POST_EXIT_ROUTE_ACTIVE | NATIVE_POST_EXIT_ROUTE_BUSY => {
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

    /// Installs one fully detached route into a previously allocated metadata
    /// entry. An unexpected `EMPTY -> BUSY` race returns the original exact
    /// route so the caller can retry another entry or retain it rather than
    /// overwrite an independently parked owner.
    fn install(&self, route: NativePostExitRoute) -> Result<(), NativePostExitRoute> {
        if self
            .state
            .compare_exchange(
                NATIVE_POST_EXIT_ROUTE_EMPTY,
                NATIVE_POST_EXIT_ROUTE_BUSY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(route);
        }
        // SAFETY: the successful EMPTY -> BUSY transition is the unique
        // writer. The Active value is published before its Release store.
        unsafe { (*self.entry.get()).write(NativePostExitRouteEntry::Active(route)) };
        self.state
            .store(NATIVE_POST_EXIT_ROUTE_ACTIVE, Ordering::Release);
        Ok(())
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

    /// Keeps a concrete route and its scheduler token process-terminal after
    /// an operation can no longer prove a retryable source state.
    #[inline]
    fn retain_route(&self, parked: RuntimeParkedPostExitRoute, route: NativePostExitFreeRoute) {
        // SAFETY: see `restore_active`; retained entries are never moved back
        // through an active route operation.
        unsafe {
            (*self.entry.get()).write(NativePostExitRouteEntry::RetainedRoute(
                NativePostExitRoute { parked, route },
            ))
        };
        self.state
            .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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
                // proof and this route's still-parked scheduler token into B
                // TLS only when no engine is active and B has not already
                // received another route completion. Other owners may
                // continue their separately serialized PageMap operations,
                // but ticket zero cannot reopen until B has crossed its
                // required finish boundary.
                let slot = current_thread_slot();
                let b_session_is_parked = match slot.page_owner.as_ref() {
                    None => true,
                    Some(ThreadLifecyclePageOwner::Session(session)) => session.parked.is_some(),
                    Some(ThreadLifecyclePageOwner::PreparedExit(_)) => false,
                };
                if slot.state != ThreadLifecycleState::Attached
                    || !b_session_is_parked
                    || slot.post_exit_route_proof.is_some()
                {
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
                    self.state
                        .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
                    NativePostExitRouteFreeResult::Retained
                } else {
                    slot.post_exit_route_proof = Some(NativePostExitRouteCompletion {
                        parked,
                        proof,
                    });
                    self.state
                        .store(NATIVE_POST_EXIT_ROUTE_EMPTY, Ordering::Release);
                    NativePostExitRouteFreeResult::Finished
                }
            }
            NativePostExitFreeStep::Retained(route) => {
                self.retain_route(parked, route);
                NativePostExitRouteFreeResult::Retained
            }
            NativePostExitFreeStep::Poisoned(proof) => {
                // SAFETY: the lower route has no retryable source state, but
                // its scheduler claim and exact admission must remain owned.
                unsafe {
                    (*self.entry.get()).write(NativePostExitRouteEntry::RetainedPoisoned {
                        parked,
                        proof,
                    })
                };
                self.state
                    .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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
                NATIVE_POST_EXIT_ROUTE_EMPTY => return NativePostExitRouteFreeResult::NotOwned,
                NATIVE_POST_EXIT_ROUTE_RETAINED => {
                    return NativePostExitRouteFreeResult::Retained;
                }
                NATIVE_POST_EXIT_ROUTE_BUSY => {
                    core::hint::spin_loop();
                }
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
                    self.state
                        .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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
            self.state
                .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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
                NATIVE_POST_EXIT_ROUTE_EMPTY => {
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
                    self.state
                        .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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
            self.state
                .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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
                NATIVE_POST_EXIT_ROUTE_EMPTY => {
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
                    self.state
                        .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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
            self.state
                .store(NATIVE_POST_EXIT_ROUTE_RETAINED, Ordering::Release);
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

}

/// One permanent node in the metadata-backed detached-route registry.
///
/// The metadata capability intentionally remains in the same process-lifetime
/// allocation as this node. It is never released or moved: a concurrent raw
/// C free may have acquired the node from the registry head, so reclaiming
/// node storage would require an unrelated hazard-pointer or epoch protocol.
/// Empty entries are reused instead. This bounds retained metadata by the
/// high-water of simultaneously detached owners rather than by the number of
/// sequential worker exits.
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
    fn new(
        route: NativePostExitRoute,
        next: *mut NativePostExitRouteRegistryNode,
        backing: MetaAllocation<'static>,
    ) -> Self {
        Self {
            next: AtomicPtr::new(next),
            storage: NativePostExitRouteStorage::from_active(route),
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

/// Result of looking for a reusable detached-route registry entry.
enum NativePostExitRouteRegistryInstall {
    Installed,
    NeedsEntry(NativePostExitRoute),
    Retained(NativePostExitRoute),
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
/// the small append word. Scanning never returns a route, raw client, or
/// PageMap fact to the caller. A foreign address restores the claimed entry
/// before the next node is considered, so exact C frees remain serialized per
/// route and source PageMap access remains route-local.
struct NativePostExitRouteRegistry {
    growth: AtomicU8,
    head: AtomicPtr<NativePostExitRouteRegistryNode>,
}

impl NativePostExitRouteRegistry {
    const fn new() -> Self {
        Self {
            growth: AtomicU8::new(NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE),
            head: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Scans the stable list once without exposing an entry. A retained node
    /// wins over a reusable empty node: once source ownership is terminal,
    /// another detached A may not publish a route beside it.
    fn try_install_existing(
        &self,
        route: NativePostExitRoute,
    ) -> NativePostExitRouteRegistryInstall {
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
                    return NativePostExitRouteRegistryInstall::Retained(route);
                }
            }
            current = node.next.load(Ordering::Acquire);
        }
        if candidate.is_null() {
            return NativePostExitRouteRegistryInstall::NeedsEntry(route);
        }
        // SAFETY: `candidate` was read from the stable registry list above.
        // A concurrent installer can only win the entry's own EMPTY -> BUSY
        // transition; in that case this returns the unchanged linear route so
        // the caller can rescan or grow without overwriting it.
        match unsafe { (&*candidate).storage.install(route) } {
            Ok(()) => NativePostExitRouteRegistryInstall::Installed,
            Err(route) => NativePostExitRouteRegistryInstall::NeedsEntry(route),
        }
    }

    /// Acquires only the list-growth word. It never covers a route's source
    /// free or usable-size operation; those retain their existing per-entry
    /// short `ACTIVE -> BUSY` serialization.
    fn acquire_growth(&self) -> bool {
        loop {
            match self.growth.load(Ordering::Acquire) {
                NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE => {
                    if self
                        .growth
                        .compare_exchange(
                            NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE,
                            NATIVE_POST_EXIT_ROUTE_REGISTRY_GROWING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                NATIVE_POST_EXIT_ROUTE_REGISTRY_GROWING => core::hint::spin_loop(),
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    return false;
                }
            }
        }
    }

    #[inline]
    fn release_growth(&self) {
        self.growth
            .store(NATIVE_POST_EXIT_ROUTE_REGISTRY_IDLE, Ordering::Release);
    }

    /// Installs one fully detached route. Existing empty metadata entries are
    /// reused first; if every live entry is occupied, one new process-lived
    /// metadata node is initialized and published. An allocation failure
    /// returns the exact route for terminal retention rather than adding a
    /// cardinality cap or overwriting another A owner.
    fn install(
        &self,
        route: NativePostExitRoute,
        config: MemoryConfig,
    ) -> Result<(), NativePostExitRoute> {
        let route = match self.try_install_existing(route) {
            NativePostExitRouteRegistryInstall::Installed => return Ok(()),
            NativePostExitRouteRegistryInstall::NeedsEntry(route) => route,
            NativePostExitRouteRegistryInstall::Retained(route) => return Err(route),
        };
        if !self.acquire_growth() {
            return Err(route);
        }

        // A prior grower may have published a reusable node while this thread
        // waited. Recheck under the append word before asking metadata for a
        // new process-lifetime entry.
        let route = match self.try_install_existing(route) {
            NativePostExitRouteRegistryInstall::Installed => {
                self.release_growth();
                return Ok(());
            }
            NativePostExitRouteRegistryInstall::NeedsEntry(route) => route,
            NativePostExitRouteRegistryInstall::Retained(route) => {
                self.release_growth();
                return Err(route);
            }
        };

        let backing = match MetaAllocator::global().zalloc(
            config,
            core::mem::size_of::<NativePostExitRouteRegistryNode>(),
        ) {
            Ok(backing) => backing,
            Err(_) => {
                self.release_growth();
                return Err(route);
            }
        };
        let next = self.head.load(Ordering::Acquire);
        let node = backing
            .pointer()
            .as_ptr()
            .cast::<NativePostExitRouteRegistryNode>();
        // SAFETY: `backing` is a fresh zeroed metadata allocation with the
        // compile-time-checked alignment above. This is its one typed node
        // initialization, before any registry reader can acquire `head`.
        unsafe { node.write(NativePostExitRouteRegistryNode::new(route, next, backing)) };
        self.head.store(node, Ordering::Release);
        self.release_growth();
        Ok(())
    }

    /// Reports whether every currently published detached route remains live.
    /// The caller receives no entry identity or list access. A `Live` answer
    /// means every pre-existing private OS-list member is still owned by one
    /// typed route whose terminal exact free unlinks only its own member.
    fn view(&self) -> NativePostExitRouteRegistryView {
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
// protocol, and the append word serializes only list growth.
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
        page_owner_ready: usize::from(
            RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_READY,
        ),
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
    /// A terminal route proof plus its still-parked detached-route token. It
    /// belongs to the current B worker until B has completed its own
    /// attachment teardown; only then may it remove that route's one parked
    /// count and release A's admission. Keeping this completion in compiler
    /// TLS prevents route completion alone from reactivating ticket zero or a
    /// second worker.
    post_exit_route_proof: Option<NativePostExitRouteCompletion>,
    attachment: Option<MainHeapThreadAttachment<'static>>,
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
            post_exit_route_proof: None,
            attachment: None,
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

/// Result of looking up the running thread's exact registry entry before it
/// borrows its compiler-TLS session. `Claimed` deliberately keeps that entry
/// `BUSY`: it is the exclusive handoff that makes a cross-thread raw TLS
/// borrow sound. A foreign entry is restored before this value escapes, so it
/// never grants access to another worker's session.
enum NativeLiveRemoteOwnerCurrentClaim {
    Empty,
    Foreign,
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
            match self.state.load(Ordering::Acquire) {
                NATIVE_LIVE_REMOTE_OWNER_EMPTY => return NativeLiveRemoteOwnerClaim::Empty,
                NATIVE_LIVE_REMOTE_OWNER_RETAINED => {
                    return NativeLiveRemoteOwnerClaim::Retained;
                }
                NATIVE_LIVE_REMOTE_OWNER_BUSY => core::hint::spin_loop(),
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
                        return NativeLiveRemoteOwnerClaim::Claimed(
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
                    return NativeLiveRemoteOwnerClaim::Retained;
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
        self.storage
            .state
            .store(NATIVE_LIVE_REMOTE_OWNER_RETAINED, Ordering::Release);
        RUNTIME_PROCESS.retain_page_owner();
    }
}

impl Drop for NativeLiveRemoteOwnerGuard {
    fn drop(&mut self) {
        if self.owner.take().is_some() {
            self.storage
                .state
                .store(NATIVE_LIVE_REMOTE_OWNER_RETAINED, Ordering::Release);
            RUNTIME_PROCESS.retain_page_owner();
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
    growth: AtomicU8,
    head: AtomicPtr<NativeLiveRemoteOwnerRegistryNode>,
}

impl NativeLiveRemoteOwnerRegistry {
    const fn new() -> Self {
        Self {
            growth: AtomicU8::new(NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE),
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
        // SAFETY: the candidate is an append-only stable node. A concurrent
        // installer may win its EMPTY -> BUSY transition; in that case this
        // returns the unchanged owner for a rescan rather than overwriting it.
        match unsafe { (&*candidate).storage.install(owner) } {
            Ok(()) => NativeLiveRemoteOwnerRegistryExistingInstall::Installed,
            Err(owner) => NativeLiveRemoteOwnerRegistryExistingInstall::NeedsEntry(owner),
        }
    }

    /// Acquires only the append word. It never covers a live-owner source
    /// operation, whose entry-level state retains the short serialization.
    fn acquire_growth(&self) -> bool {
        loop {
            match self.growth.load(Ordering::Acquire) {
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE => {
                    if self
                        .growth
                        .compare_exchange(
                            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE,
                            NATIVE_LIVE_REMOTE_OWNER_REGISTRY_GROWING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                NATIVE_LIVE_REMOTE_OWNER_REGISTRY_GROWING => core::hint::spin_loop(),
                _ => {
                    RUNTIME_PROCESS.retain_page_owner();
                    return false;
                }
            }
        }
    }

    #[inline]
    fn release_growth(&self) {
        self.growth
            .store(NATIVE_LIVE_REMOTE_OWNER_REGISTRY_IDLE, Ordering::Release);
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
        let owner = match self.try_install_existing(owner) {
            NativeLiveRemoteOwnerRegistryExistingInstall::Installed => {
                return NativeLiveRemoteOwnerRegistryInstall::Installed;
            }
            NativeLiveRemoteOwnerRegistryExistingInstall::NeedsEntry(owner) => owner,
            NativeLiveRemoteOwnerRegistryExistingInstall::Retained(owner) => {
                return NativeLiveRemoteOwnerRegistryInstall::Retained(owner);
            }
        };
        if !self.acquire_growth() {
            return NativeLiveRemoteOwnerRegistryInstall::Retained(owner);
        }

        // A prior grower may have made an empty entry reusable while this
        // caller waited. Recheck under the append word before allocating.
        let owner = match self.try_install_existing(owner) {
            NativeLiveRemoteOwnerRegistryExistingInstall::Installed => {
                self.release_growth();
                return NativeLiveRemoteOwnerRegistryInstall::Installed;
            }
            NativeLiveRemoteOwnerRegistryExistingInstall::NeedsEntry(owner) => owner,
            NativeLiveRemoteOwnerRegistryExistingInstall::Retained(owner) => {
                self.release_growth();
                return NativeLiveRemoteOwnerRegistryInstall::Retained(owner);
            }
        };

        let backing = match MetaAllocator::global().zalloc(
            config,
            core::mem::size_of::<NativeLiveRemoteOwnerRegistryNode>(),
        ) {
            Ok(backing) => backing,
            Err(_) => {
                self.release_growth();
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
        self.release_growth();
        NativeLiveRemoteOwnerRegistryInstall::Installed
    }

    /// Claims the running thread's exact entry before it reads compiler TLS.
    /// A running A must wait for a B-side guard that borrowed its raw slot, but
    /// all foreign entries are restored before A accesses its own TLS image.
    fn claim_current_slot(
        &'static self,
        slot: core::ptr::NonNull<ThreadLifecycleSlot>,
    ) -> NativeLiveRemoteOwnerCurrentClaim {
        let mut saw_foreign = false;
        let mut current = self.head.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: this append-only metadata node has process lifetime, so
            // a claimed guard may retain its storage reference after the scan
            // advances to another node.
            let node: &'static NativeLiveRemoteOwnerRegistryNode = unsafe { &*current };
            match node.storage.claim() {
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
// entry operation owns its independent state word. The append word serializes
// only metadata growth, not live allocator work.
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

#[inline]
fn native_allocation_from_ticket_zero(
    result: TicketZeroPageAllocationResult,
) -> NativePageAllocationResult {
    match result {
        TicketZeroPageAllocationResult::Allocated(block) => NativePageAllocationResult::Allocated(block),
        TicketZeroPageAllocationResult::Unavailable => NativePageAllocationResult::Unavailable,
        TicketZeroPageAllocationResult::AllocationFailed => NativePageAllocationResult::AllocationFailed,
        TicketZeroPageAllocationResult::Retained => NativePageAllocationResult::Retained,
    }
}

#[inline]
fn native_free_from_ticket_zero(result: TicketZeroPageFreeResult) -> NativePageFreeResult {
    match result {
        TicketZeroPageFreeResult::Freed => NativePageFreeResult::Freed,
        TicketZeroPageFreeResult::Unavailable => NativePageFreeResult::Unavailable,
        TicketZeroPageFreeResult::InvalidPointer => NativePageFreeResult::InvalidPointer,
        TicketZeroPageFreeResult::Retained => NativePageFreeResult::Retained,
    }
}

/// Primes the one source first arena before a native-shadow worker can borrow
/// the existing dormant pair.
///
/// This is intentionally an initial-thread-only integration step. It creates
/// and releases one private word-sized block only if the permanent owner has
/// never entered a page engine, leaving the owner in its established dormant
/// first-arena state. A live ticket-zero allocation or any terminal runtime
/// state rejects rather than borrowing a page image that already has a caller
/// owner. The ordinary C backend never calls this boundary.
#[doc(hidden)]
pub fn prepare_native_later_thread_arena() -> bool {
    if !RUNTIME_PROCESS.is_on_initial_thread() {
        return false;
    }
    matches!(
        RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| owner.prepare_dormant_page_pair()),
        Some(true)
    ) && RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_READY
}

/// Allocates one C-facing native-shadow block on the current thread.
///
/// The initial process thread uses its permanent ticket-zero owner. An
/// attached later pthread uses its current-thread parked owner session and
/// records the returned block before the engine parks again. Natural C
/// alignment remains an ordinary source allocation; only wider alignment
/// takes the distinct aligned path. The latter is a deliberately bounded
/// early-shadow route: it permits local allocation, local free, and all-free
/// normal pthread finish, but has no cross-thread pointer dispatch or
/// live-owner-exit handoff yet.
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
        return native_allocation_from_ticket_zero(ticket_zero_allocate_aligned(
            request,
            alignment,
            zero,
        ));
    }
    // A final B-side free may already hold A's terminal admission proof in
    // this thread's TLS. Keep B no-page until its destructor finish consumes
    // that proof; otherwise a second parked engine could obscure the required
    // "route released, then B finished" lifecycle ordering.
    if current_thread_slot().post_exit_route_proof.is_some() {
        return NativePageAllocationResult::Unavailable;
    }
    native_later_thread_allocate_aligned(request, alignment, zero)
}

/// Reallocates one current C-facing native-shadow block on its owning thread.
///
/// # Safety
///
/// When present, `block` must be a live result from this same native-shadow
/// owner and must not be concurrently accessed, remotely published, or
/// already freed. One joined B may instead present an exact client held by a
/// typed detached-owner route. That route privately records a normal B
/// replacement, copies the source-defined prefix, and only then consumes A's
/// old client through its existing terminal-free path; it does not expose an
/// in-place, page, or general pointer-routing capability. In pinned v3.5.0,
/// `mi_theap_realloc_zero_ex` reuses an allocation in place only when its
/// page still belongs to the current Theap, which cannot hold after A's owner
/// exit.
#[doc(hidden)]
pub unsafe fn native_reallocate(
    block: Option<core::ptr::NonNull<u8>>,
    new_size: usize,
) -> NativePageAllocationResult {
    if !crate::size_class::request_size_is_valid(new_size) {
        return NativePageAllocationResult::AllocationFailed;
    }
    let Some(block) = block else {
        return native_allocate_aligned(new_size, 16, false);
    };
    if RUNTIME_PROCESS.is_on_initial_thread() {
        // SAFETY: forwarded unchanged from this boundary's exact-current
        // native block contract.
        return native_allocation_from_ticket_zero(unsafe {
            ticket_zero_reallocate(Some(block), new_size)
        });
    }
    if current_thread_can_access_native_post_exit_route() {
        match NATIVE_POST_EXIT_ROUTE.reallocate_exact(block, new_size) {
            NativePostExitRouteReallocateResult::Allocated(block) => {
                return NativePageAllocationResult::Allocated(block);
            }
            NativePostExitRouteReallocateResult::AllocationFailed => {
                return NativePageAllocationResult::AllocationFailed;
            }
            NativePostExitRouteReallocateResult::Unavailable => {
                return NativePageAllocationResult::Unavailable;
            }
            NativePostExitRouteReallocateResult::Retained => {
                return NativePageAllocationResult::Retained;
            }
            NativePostExitRouteReallocateResult::NotOwned => {}
        }
    }
    // SAFETY: forwarded unchanged from this boundary's exact-current native
    // block contract to the current attached worker's parked session.
    unsafe { native_later_thread_reallocate(block, new_size) }
}

/// Frees one current C-facing native-shadow block on its owning thread.
///
/// # Safety
///
/// `block` must be a live native-shadow allocation. A wrong-domain pointer
/// reports `InvalidPointer`. An attached later worker may either use its own
/// local ledger, consume the one typed detached-owner route, or atomically
/// source-publish an exact still-live ticket-zero client; it receives no
/// general pointer registry, page engine, or scheduler authority. Callers
/// must not route any native failure to the C allocator as recovery.
#[doc(hidden)]
pub unsafe fn native_free(block: core::ptr::NonNull<u8>) -> NativePageFreeResult {
    if RUNTIME_PROCESS.is_on_initial_thread() {
        // SAFETY: forwarded unchanged from this boundary's exact-current
        // native block contract.
        return native_free_from_ticket_zero(unsafe { ticket_zero_free(block) });
    }
    if current_thread_can_access_native_post_exit_route() {
        match NATIVE_POST_EXIT_ROUTE.free_exact(block) {
            NativePostExitRouteFreeResult::Freed | NativePostExitRouteFreeResult::Finished => {
                return NativePageFreeResult::Freed;
            }
            NativePostExitRouteFreeResult::Retained => return NativePageFreeResult::Retained,
            NativePostExitRouteFreeResult::NotOwned => {}
        }
    }
    // SAFETY: forwarded unchanged from this boundary's exact-current native
    // block contract to the current attached worker's parked session.
    let local = unsafe { native_later_thread_free(block) };
    match local {
        NativePageFreeResult::Freed | NativePageFreeResult::Retained => return local,
        NativePageFreeResult::InvalidPointer | NativePageFreeResult::Unavailable => {}
    }

    // A ticket-zero allocation may legitimately cross to a later pthread
    // while the permanent initial owner remains active. Unlike a parked
    // worker route, the exact live allocation itself pins the source page;
    // the remote producer needs no borrowed engine, client ledger, or
    // scheduler transition. Try this owner domain after the local ledger
    // rejects the address, so a worker that owns unrelated native pages can
    // still free an initial-thread client through `mi_free_block_mt`.
    match unsafe { native_ticket_zero_live_remote_free(block) } {
        NativeTicketZeroRemoteFreeResult::Freed => return NativePageFreeResult::Freed,
        NativeTicketZeroRemoteFreeResult::Retained => return NativePageFreeResult::Retained,
        NativeTicketZeroRemoteFreeResult::NotOwned
        | NativeTicketZeroRemoteFreeResult::Unavailable => {}
    }

    if local != NativePageFreeResult::Unavailable
        || !current_thread_can_access_native_post_exit_route()
    {
        return local;
    }
    match unsafe { native_later_thread_live_remote_free(block) } {
        NativeLiveRemoteFreeResult::Freed => NativePageFreeResult::Freed,
        NativeLiveRemoteFreeResult::NotOwned => NativePageFreeResult::InvalidPointer,
        NativeLiveRemoteFreeResult::Unavailable => NativePageFreeResult::Unavailable,
        NativeLiveRemoteFreeResult::Retained => NativePageFreeResult::Retained,
    }
}

/// Returns the usable size of one current native-shadow allocation.
///
/// A current owner uses its own live engine. A fresh no-page B may also query
/// one exact live client held by either bounded pointer-private route: the
/// detached aggregate or one parked live A. Each returns only A's
/// source-recorded extent and remains active for a later exact `free`; the
/// query itself does not touch a page engine, scheduler, or admission claim.
/// An unavailable or foreign pointer returns no size rather than consulting
/// the C allocator.
#[doc(hidden)]
pub unsafe fn native_usable_size(block: core::ptr::NonNull<u8>) -> Option<usize> {
    if RUNTIME_PROCESS.is_on_initial_thread() {
        // SAFETY: forwarded unchanged from this boundary's exact-current
        // native block contract.
        return unsafe { ticket_zero_usable_size(block) };
    }
    if current_thread_can_access_native_post_exit_route() {
        if let Some(usable_size) = NATIVE_POST_EXIT_ROUTE.usable_size_exact(block) {
            return Some(usable_size);
        }
        // SAFETY: the same fresh no-page B-state check prevents this
        // read-only route from borrowing a local engine or terminal proof.
        if let Some(usable_size) = unsafe { native_later_thread_live_remote_usable_size(block) } {
            return Some(usable_size);
        }
    }
    // SAFETY: forwarded unchanged from this boundary's exact-current native
    // block contract to the current attached worker's parked session.
    unsafe { native_later_thread_usable_size(block) }
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
        for (destination, source) in blocks[OWNER_EXIT_UNMAPPED_FULL_MEDIUM_START..OWNER_EXIT_ARENA_SINGLETON_INDEX]
            .iter_mut()
            .zip(&mut self.unmapped_full_medium)
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

    /// Removes A's registry publication only when this parked session is
    /// permanently leaving the live-owner state for a typed exit route.  The
    /// source exit no longer permits B to borrow A's ledger, so `EMPTY` is
    /// correct only after the parked engine has been transferred into the
    /// prepared source owner.
    fn remove_native_live_remote_reservation_for_exit(&mut self) -> Result<(), ()> {
        match (
            self.native_live_remote,
            self.native_live_remote_reservation.take(),
        ) {
            (false, None) => Ok(()),
            (true, Some(route)) => {
                let owner = route.remove();
                let slot = current_thread_slot_pointer();
                if owner.slot == slot && owner.generation == self.generation {
                    Ok(())
                } else {
                    // `remove` deliberately discarded the raw identity, so
                    // the only safe response to an impossible mismatch is to
                    // make the process terminal rather than reconstructing a
                    // route from an ambiguous TLS slot.
                    RUNTIME_PROCESS.retain_page_owner();
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
    let slot_pointer = current_thread_slot_pointer();
    // Claim this slot's registry handoff *before* inspecting compiler TLS. A B-side
    // free owns a mutable reference to A's ledger while this state is BUSY;
    // even a generation read must therefore wait for it to resolve.
    let native_route = match NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot_pointer) {
        // Keep the exact raw-TLS handoff BUSY while the session is out of its
        // slot.  It becomes an active publication again only after the full
        // session image is restored, closing the A-resume/B-install race.
        NativeLiveRemoteOwnerCurrentClaim::Claimed(route) => Some(route),
        NativeLiveRemoteOwnerCurrentClaim::Empty | NativeLiveRemoteOwnerCurrentClaim::Foreign => {
            None
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

    /// Runs one C-facing local operation after any bounded competing native
    /// PageMap operation has republished its parked state.
    ///
    /// The retry is deliberately internal to one current-thread session. It
    /// does not retry rejected source transitions, stale handles, allocation
    /// failures, or terminal ownership; it only waits through the short
    /// scheduler/map handoff that another already-admitted native worker is
    /// completing. This lets an A local `free` and B's all-free pthread exit
    /// serialize instead of turning their valid order into a C fail-stop.
    fn with_native_active_operation<R>(
        &self,
        mut operation: impl FnMut(
            &mut MainHeapThreadProcessPageAllocator<'_, '_>,
            &mut PreparedOwnerExitClients,
        ) -> R,
    ) -> Result<R, CurrentThreadPageOwnerSessionError> {
        loop {
            match self.with_active_operation(|allocator, clients| operation(allocator, clients)) {
                Err(CurrentThreadPageOwnerSessionError::Busy) => core::hint::spin_loop(),
                result => return result,
            }
        }
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
        match self.with_native_active_operation(|allocator, clients| {
            clients.free_native_block(allocator, block)
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(CurrentThreadPageOwnerSessionError::Preparation(error)),
            Err(error) => Err(error),
        }
    }

    /// Reallocates one raw C-facing local client and atomically updates the
    /// matching private ledger slot if the source engine returns a replacement.
    fn native_reallocate(
        &mut self,
        block: core::ptr::NonNull<u8>,
        new_size: usize,
    ) -> Result<core::ptr::NonNull<u8>, CurrentThreadPageOwnerSessionError> {
        match self.with_native_active_operation(|allocator, clients| {
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
            Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked })
            | Err(RuntimePersistentPageEngineResumeFailure::Rejected {
                parked,
                ..
            })
            | Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy {
                parked,
                ..
            }) => {
                session.parked = Some(parked);
                restore_current_thread_page_owner_session(session);
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
                if session
                    .remove_native_live_remote_reservation_for_exit()
                    .is_err()
                {
                    drop(parked);
                    core::mem::forget(exit);
                    retain_forgotten_current_thread_page_owner_session(session);
                    return Err(CurrentThreadPageOwnerSessionError::Retained);
                }
                // The old session's parked field is intentionally empty after
                // resume. Dropping it cannot run the parked-token retention
                // path; its native publication was intentionally removed
                // above because the new token belongs solely to the prepared
                // source exit.
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
                    ThreadLifecyclePreparedPageOwner { parked, exit },
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
        let engine = match RUNTIME_PROCESS.begin_persistent_later_engine(attachment) {
            Ok(engine) => engine,
            Err(RuntimePersistentPageEngineBeginError::Unavailable) => {
                return Err(CurrentThreadPageOwnerSessionError::Unavailable);
            }
            Err(RuntimePersistentPageEngineBeginError::Attachment(_)) => {
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return Err(CurrentThreadPageOwnerSessionError::Retained);
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
    let result = current_thread_native_session_handle(true).and_then(|mut session| {
        let block = session.native_allocate_aligned(request, alignment, zero)?;
        session.enable_native_live_remote()?;
        Ok(block)
    });
    native_later_thread_allocation_result(result)
}

unsafe fn native_later_thread_reallocate(
    block: core::ptr::NonNull<u8>,
    new_size: usize,
) -> NativePageAllocationResult {
    let result = current_thread_native_session_handle(false)
        .and_then(|mut session| session.native_reallocate(block, new_size));
    native_later_thread_allocation_result(result)
}

unsafe fn native_later_thread_free(block: core::ptr::NonNull<u8>) -> NativePageFreeResult {
    match current_thread_native_session_handle(false).and_then(|mut session| session.native_free(block)) {
        Ok(()) => NativePageFreeResult::Freed,
        Err(CurrentThreadPageOwnerSessionError::Preparation(
            CurrentThreadPageOwnerPreparationError::UnknownClient
            | CurrentThreadPageOwnerPreparationError::DuplicateClient
            | CurrentThreadPageOwnerPreparationError::LocalFree,
        )) => NativePageFreeResult::InvalidPointer,
        Err(CurrentThreadPageOwnerSessionError::Retained) => NativePageFreeResult::Retained,
        Err(CurrentThreadPageOwnerSessionError::Busy
        | CurrentThreadPageOwnerSessionError::Unavailable
        | CurrentThreadPageOwnerSessionError::Stale
        | CurrentThreadPageOwnerSessionError::Preparation(_)) => {
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
    let Some(page_map) = RUNTIME_PROCESS.page_map_for_live_ticket_zero_client() else {
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
    match unsafe { remote_free::push(page, canonical_block) } {
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
/// raw input against one A's existing private C ledger, then borrows the
/// runtime pair only for one complete non-parkable `PARKED -> BUSY -> PARKED`
/// operation. That operation serializes the PageMap preflight and atomic
/// source push; A cannot resume until B finishes it, at which point A's normal
/// allocation or page drain collects the remote head. This remains a bounded
/// live-owner route, not a general allocator or foreign-pointer registry.
///
/// # Safety
///
/// `block` must be a live native-shadow allocation. The caller has already
/// established that this B worker is attached, has no local page owner, and
/// has no terminal post-exit proof. A wrong C pointer is rejected before any
/// source publication; an inconsistent source transition remains terminal.
unsafe fn native_later_thread_live_remote_free(
    block: core::ptr::NonNull<u8>,
) -> NativeLiveRemoteFreeResult {
    let (mut route, client) = match NATIVE_LIVE_REMOTE_OWNER.claim_exact_client(block) {
        NativeLiveRemoteOwnerExactClaim::NotOwned => {
            return NativeLiveRemoteFreeResult::NotOwned;
        }
        NativeLiveRemoteOwnerExactClaim::Retained => {
            return NativeLiveRemoteFreeResult::Retained;
        }
        NativeLiveRemoteOwnerExactClaim::Claimed { route, client } => (route, client),
    };

    let engine = {
        let slot = current_thread_slot();
        if slot.state != ThreadLifecycleState::Attached
            || slot.page_owner.is_some()
            || slot.post_exit_route_proof.is_some()
        {
            route.restore();
            return NativeLiveRemoteFreeResult::Unavailable;
        }
        let Some(attachment) = slot.attachment.as_mut() else {
            route.retain();
            return NativeLiveRemoteFreeResult::Retained;
        };
        match RUNTIME_PROCESS.begin_interleaving_persistent_later_engine(attachment) {
            Ok(engine) => engine,
            Err(_) => {
                // The exact registry entry proves A is parked. Failing to
                // acquire the matching source interleaving operation therefore
                // leaves an ambiguous scheduler/PageMap image rather than a
                // retryable foreign-free miss.
                route.retain();
                return NativeLiveRemoteFreeResult::Retained;
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

    match engine.finish() {
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
        || slot.post_exit_route_proof.is_some()
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
    current_thread_native_session_handle(false)
        .and_then(|session| session.native_usable_size(block))
        .ok()
}

/// Returns whether this attached worker can make one pointer-private native
/// post-exit route operation.
///
/// A fresh B has no page owner. A B that established its own native session
/// before seeing A's pointer is also admissible, but only while that session
/// is parked: the route's short PageMap operation then serializes with B's
/// future long engine operation through the existing scheduler. A prepared
/// exit has already consumed B's source clients into another typed route, so
/// it cannot accept a second terminal proof or advance A's route. Once B has
/// received A's terminal proof it likewise remains out of the dispatcher
/// until its ordinary finish settles that proof.
#[inline]
fn current_thread_can_access_native_post_exit_route() -> bool {
    let slot = current_thread_slot();
    if slot.state != ThreadLifecycleState::Attached || slot.post_exit_route_proof.is_some() {
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
        ThreadLifecyclePreparedPageOwner { parked, exit },
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
/// permanent page owner is either unmapped or has returned to its source
/// all-free dormant image. It does not repair a live page engine or client.
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

    // SAFETY: libc installed this child TLS image and calls before user code;
    // `slot` retains the returned current-thread owner until its explicit
    // post-destructor finish. The static process owner is never torn down by
    // this slice, and no other code may mutate the allocator TLS roots.
    match unsafe { MainHeapThreadAttachment::begin(main_heap, config) } {
        Ok(attachment) => {
            slot.attachment = Some(attachment);
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
    let page_owner = {
        let slot_pointer = current_thread_slot_pointer();
        // A native A may not even inspect its TLS slot while B owns the raw
        // handoff. Remove the exact registry entry first, then make the normal
        // page-owner finish decision with no B-side alias remaining.
        let native_owner = match NATIVE_LIVE_REMOTE_OWNER.claim_current_slot(slot_pointer) {
            NativeLiveRemoteOwnerCurrentClaim::Claimed(route) => Some(route.remove()),
            NativeLiveRemoteOwnerCurrentClaim::Empty
            | NativeLiveRemoteOwnerCurrentClaim::Foreign => None,
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

    finish_current_thread_post_exit_route_proof_after_user_destructors()
}

/// Removes one detached-route scheduler token and releases A's admission
/// only after this current B worker has completed its own attachment
/// lifecycle.
///
/// The completion is written by the native post-exit route only after its
/// final PageMap release. Keeping its still-parked scheduler token beside
/// the A-side proof means B may release several of A's clients while it
/// remains attached, but cannot make either the dormant pair or A's fork
/// admission quiescent until B's no-page finish has actually detached its own
/// TLD/Theap. Other independently parked routes remain represented by their
/// own tokens throughout this transition.
fn finish_current_thread_post_exit_route_proof_after_user_destructors() -> ThreadFinishResult {
    let completion = current_thread_slot().post_exit_route_proof.take();
    let Some(NativePostExitRouteCompletion { parked, proof }) = completion else {
        return ThreadFinishResult::Finished;
    };
    match parked.finish_after_b() {
        Ok(()) => match proof.release_worker_admission(&RUNTIME_FORK_ADMISSION) {
            Ok(()) => ThreadFinishResult::Finished,
            Err(proof) => {
                // B already detached and the scheduler settled, but A's exact
                // admission no longer matches the fork counter. Preserve that
                // claim terminally rather than letting the ready scheduler
                // make the retained process appear quiescent.
                retain_current_thread_detached_owner_exit_with_admission(proof.into_admission());
                ThreadFinishResult::Retained
            }
        },
        Err(parked) => {
            let slot = current_thread_slot();
            // A failed parked-token removal has already made the page owner
            // terminally retained; keep the exact completion in B TLS as the
            // matching diagnostic capability rather than dropping either
            // half of the boundary.
            slot.post_exit_route_proof = Some(NativePostExitRouteCompletion { parked, proof });
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
                        Some(
                            session.clients.has_live_client()
                                && !session.clients.has_published_before_exit(),
                        )
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
        let session = CurrentThreadPageOwnerSessionHandle {
            generation,
            _current_thread_only: PhantomData,
        };
        if session.prepare_native_deferred_exit().is_err() {
            return ThreadFinishResult::Retained;
        }
    }
    finish_current_thread_after_user_destructors()
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
/// access. The scheduler converts A's active operation into one parked route
/// token, so a distinct normal engine may run between exact frees while
/// ticket zero remains unavailable. That token may leave the parked count
/// only after a B free returns the exact typed terminal proof and B finishes
/// its own no-page lifecycle. A's TLS becomes finished because it owns no
/// remaining route or admission capability, not because the global
/// worker-admission count has been released.
fn defer_current_thread_native_post_exit_route(
    operation: RuntimeDormantPageOperation,
    registry_config: MemoryConfig,
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
    let parked = match operation.park_detached_post_exit() {
        Ok(parked) => parked,
        Err(operation) => {
            // The source route has already detached A. Preserve its exact
            // admission and page facts while the failed scheduler conversion
            // keeps the process terminal; no normal finalizer can repair
            // that one-way boundary.
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
    let deferred = NativePostExitRoute {
        parked,
        route,
    };
    let installed = NATIVE_POST_EXIT_ROUTE.install(deferred, registry_config);
    match installed {
        Ok(()) => {
            let slot = current_thread_slot();
            // The source aggregate completed the old Theap/TLD boundary.
            // Its detached route—not this attachment—now owns every page
            // client and A admission, so a later normal finalizer cannot
            // touch this historical attachment.
            drop(slot.attachment.take());
            slot.state = ThreadLifecycleState::Finished;
            ThreadFinishResult::Finished
        }
        Err(deferred) => {
            // Registry growth failed or observed a terminal entry after A's
            // source teardown. Preserve both exact capabilities rather than
            // overwriting an independently parked owner or manufacturing a
            // normal no-page finalizer.
            let deferred = core::mem::ManuallyDrop::new(deferred);
            // SAFETY: `deferred` is intentionally never dropped after this
            // ownership mismatch. Reading its non-Copy admission transfers
            // that one claim into the terminal A TLS slot while the leaked
            // route retains all page/process state.
            let admission = unsafe { core::ptr::read(deferred.route.admission_ptr()) };
            RUNTIME_PROCESS.retain_page_owner();
            retain_current_thread_detached_owner_exit_with_admission(admission);
            ThreadFinishResult::Retained
        }
    }
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
    }) = owner
    else {
        let ThreadLifecyclePageOwner::Session(session) = owner else {
            unreachable!("the page-owner state has exactly active and prepared variants");
        };
        return finish_current_thread_all_free_page_owner_after_user_destructors(session);
    };

    let engine = {
        let slot = current_thread_slot();
        let Some(attachment) = slot.attachment.as_mut() else {
            slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
                ThreadLifecyclePreparedPageOwner { parked, exit },
            ));
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain_page_owner();
            return ThreadFinishResult::Retained;
        };
        match parked.resume(attachment) {
            Ok(engine) => engine,
            Err(RuntimePersistentPageEngineResumeFailure::Unavailable { parked })
            | Err(RuntimePersistentPageEngineResumeFailure::Rejected {
                parked,
                ..
            })
            | Err(RuntimePersistentPageEngineResumeFailure::PageMapBusy {
                parked,
                ..
            }) => {
                slot.page_owner = Some(ThreadLifecyclePageOwner::PreparedExit(
                    ThreadLifecyclePreparedPageOwner { parked, exit },
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
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain_page_owner();
                return ThreadFinishResult::Retained;
            }
            Err(RuntimePersistentPageEngineResumeFailure::PageOwnerRetained) => {
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
                    defer_current_thread_native_post_exit_route(operation, registry_config, |admission| {
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
                    defer_current_thread_native_post_exit_route(operation, registry_config, |admission| {
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
/// original ticket-zero TLS image, and its permanent page owner was unmapped
/// or all-free dormant. It prevents another raw-fork caller from borrowing a
/// concurrently copied gate. A preserving child may reactivate that dormant
/// ticket-zero owner or attach a fresh pthread through the existing no-page
/// path. Every other child remains disabled: this is intentionally not a
/// general fork repair and never traverses inherited locks, roots, lists, or
/// page ownership.
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
    use crate::main_theap::MainStaticAttachmentStorage;
    use crate::meta::MetaAllocator;
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

    // Keep this deterministic audit materially longer than the one-cycle
    // owner-exit route regressions while leaving the 128-cycle C lane as the
    // watchdog-bound soak witness. Each cycle constructs fresh A and B
    // threads: A detaches its old owner, B terminally releases the opaque
    // route and finishes its own no-page attachment, and only then may the
    // next worker begin.
    const OWNER_EXIT_STATE_AUDIT_CYCLES: usize = 8;

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
                            7,
                            "the aggregate releases the force-empty large during collection and retains direct-small, non-direct-small, live-large, force-normalized-medium, unchanged-full-medium, live-arena-singleton, and private-OS-singleton members"
                        );
                        assert_eq!(
                            route.test_abandoned_count_for_bin(full_medium_bin),
                            Some(1),
                            "only the medium with a joined remote free enters the static-main mapped bitmap at owner exit"
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
}
