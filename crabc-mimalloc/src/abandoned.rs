// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page.c:245-302`,
// `src/arena.c:631-671,725-778,1304-1409`, `src/free.c:372-514`, and
// `include/mimalloc/internal.h:1008-1039,1111-1119`.
//
// This Milestone 5 substrate models one page's abandoned-owner decisions.
// It deliberately excludes general allocation/free routing, queues, and
// TLS/theap registration. It does not itself own raw page-map/span release:
// `single_thread.rs` supplies that distinct authority for a bounded mapped
// regular handoff, a sole mapped one-block later-main owner-exit handoff, one
// sole full-medium later-main route that first remains unmapped and then may
// reabandon into the static-main bitmap, one sole small-or-medium later-main
// process route and one aggregate regular-pages process registry after their
// Theap/TLD tears down, and one post-TLS full singleton owner-exit handoff.
// Metadata reuse and every general terminal-release route remain outside this
// substrate.

use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;

#[cfg(test)]
use crate::arena::ArenaAbandonedPages;
use crate::atomic::{word_cas_weak_release, word_load_relaxed};
use crate::bitmap::AbandonedBitmapClaim;
use crate::config::{ARENA_BIN_COUNT, BIN_FULL, SMALL_SIZE_MAX};
use crate::free_list::{self, FreeListError};
use crate::process_page_map::LiveAllocationPageState;
use crate::remote_free::{
    self, AbandonedOwnerClaim, AbandonedOwnerHeadTransition, RemoteFreeError,
};
use crate::size_class;
use crate::types::{
    LiveThreadId, MemoryId, MemoryKind, Page, PageAbandonmentState, PageKind, Theap,
    PAGE_FLAG_MASK, THREAD_ID_ABANDONED, THREAD_ID_ABANDONED_MAPPED,
};

const THREAD_FREE_OWNED: usize = 1;

/// One exact `pages_abandoned[bin]` image selected by its owning arena-page
/// lifecycle.
///
/// The source protocol is indifferent to whether the image lives in an
/// arena's main pages record or in a non-main Heap's `mi_arena_pages_t`. This
/// deliberately small capability keeps that choice at the owner boundary:
/// callers can publish, claim, and quiescently clear only the bin and arena
/// slice the capability already proved. It is not a general bitmap view.
pub(crate) trait MappedAbandonedPages {
    fn bin(&self) -> usize;
    fn page_slice_index(&self, memory: MemoryId) -> Option<usize>;
    /// Checks the one source bit before identity publication. A false result
    /// is a pre-mutation invalid-owner state, never permission to overwrite a
    /// concurrent abandoned page.
    fn is_clear(&self, slice_index: usize) -> bool;
    fn publish(&self, slice_index: usize) -> bool;
    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim;
    fn clear_once_set(&self, slice_index: usize) -> bool;
    /// Completes `arena.c:1295-1297` after the caller has cleared the page's
    /// mapped-abandoned identity. Production static-main and dynamic
    /// capabilities each consume their paired `heap->abandoned_count[bin]`
    /// here, rather than while the bit is still visible.
    fn decrement_after_identity_clear(&self) -> bool;
}

// A route that must acquire the abandoned low owner bit before it can inspect
// ordinary page metadata can construct its exact bitmap/count capability only
// after that claim. The shared collector below owns such a capability by
// value; forwarding through a reference lets the established one-page callers
// keep their preselected capability without duplicating the source tail.
impl<M: MappedAbandonedPages + ?Sized> MappedAbandonedPages for &M {
    #[inline]
    fn bin(&self) -> usize { (**self).bin() }

    #[inline]
    fn page_slice_index(&self, memory: MemoryId) -> Option<usize> {
        (**self).page_slice_index(memory)
    }

    #[inline]
    fn is_clear(&self, slice_index: usize) -> bool { (**self).is_clear(slice_index) }

    #[inline]
    fn publish(&self, slice_index: usize) -> bool { (**self).publish(slice_index) }

    #[inline]
    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        (**self).try_claim(thread_sequence, claim)
    }

    #[inline]
    fn clear_once_set(&self, slice_index: usize) -> bool {
        (**self).clear_once_set(slice_index)
    }

    #[inline]
    fn decrement_after_identity_clear(&self) -> bool {
        (**self).decrement_after_identity_clear()
    }
}

/// Result of the bitmap-low-bit part of mapped abandonment adoption.
///
/// A dynamic owner can clear the source bit but fail to consume its exact
/// paired Heap counter. That is already a post-claim state: callers must keep
/// the claimed page terminally rather than treat it as an ordinary miss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappedAbandonedClaim {
    None,
    Claimed(usize),
    CountDecrementFailed(usize),
}

/// Private capability for a source page that cannot ever enter an arena
/// `pages_abandoned` bitmap: its size-class bin is at or beyond
/// `ARENA_BIN_COUNT` (the bounded thread-exit singleton case), or a caller
/// has otherwise proved the source reabandon branch is unreachable. It never
/// publishes a bit. Supplying it to the common protocol makes an accidental
/// attempt to map an eligible regular page fail closed before publication.
struct UnmappableAbandonedPages;

impl MappedAbandonedPages for UnmappableAbandonedPages {
    #[inline]
    fn bin(&self) -> usize { ARENA_BIN_COUNT }

    #[inline]
    fn page_slice_index(&self, _memory: MemoryId) -> Option<usize> { None }

    #[inline]
    fn is_clear(&self, _slice_index: usize) -> bool { false }

    #[inline]
    fn publish(&self, _slice_index: usize) -> bool { false }

    #[inline]
    fn try_claim<F>(&self, _thread_sequence: usize, _claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        MappedAbandonedClaim::None
    }

    #[inline]
    fn clear_once_set(&self, _slice_index: usize) -> bool { false }

    #[inline]
    fn decrement_after_identity_clear(&self) -> bool { false }
}

static UNMAPPABLE_ABANDONED_PAGES: UnmappableAbandonedPages = UnmappableAbandonedPages;

// The bare main-arena bitmap is a source-state unit-test fixture only. Every
// production page owner must use `MainArenaMappedAbandonedPage`, which binds
// the same bit to its static-main `Heap::abandoned_count[bin]` transition.
#[cfg(test)]
impl MappedAbandonedPages for ArenaAbandonedPages<'_> {
    #[inline]
    fn bin(&self) -> usize { self.bin() }

    #[inline]
    fn page_slice_index(&self, memory: MemoryId) -> Option<usize> {
        self.page_slice_index(memory)
    }

    #[inline]
    fn is_clear(&self, slice_index: usize) -> bool {
        self.bitmap_is_clear(slice_index)
    }

    #[inline]
    fn publish(&self, slice_index: usize) -> bool { self.publish(slice_index) }

    #[inline]
    fn try_claim<F>(&self, thread_sequence: usize, claim: F) -> MappedAbandonedClaim
    where
        F: FnMut(usize) -> AbandonedBitmapClaim,
    {
        match self.try_claim(thread_sequence, claim) {
            Some(slice_index) => MappedAbandonedClaim::Claimed(slice_index),
            None => MappedAbandonedClaim::None,
        }
    }

    #[inline]
    fn clear_once_set(&self, slice_index: usize) -> bool {
        self.clear_once_set(slice_index)
    }

    #[inline]
    fn decrement_after_identity_clear(&self) -> bool { true }
}

/// The bounded abandonment protocol refused an invalid source-state handoff.
///
/// Every error leaves page lifetime with its caller; none invents a fallback
/// that would release or reuse metadata while a producer or bitmap reader can
/// still reach it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbandonError {
    NotOwnedAssociated,
    NotAbandoned,
    MissingMappedArenaBitmap,
    ArenaBitmapDoesNotMatchPage,
    BitmapQuiescenceFailed,
    MappedBitAlreadyPublished,
    MappedPublicationFailed,
    /// Source-specific abandoned publication did not complete between the
    /// abandoned identity/map transition and the common unown loop. The
    /// caller still owns the low bit and must retain its exact terminal
    /// transition rather than exposing an ordinary-associated page.
    PreUnownPublication,
    AbandonedCountDecrementFailed,
    InvalidPageGeometry,
    /// A bounded mapped one-block owner-exit handoff acquired its source low
    /// owner bit, but source collection left the page live. Reclaim/requeue is
    /// outside that handoff's contract, so it must remain terminally retained.
    MappedPageNotEmpty,
    RemoteFree(RemoteFreeError),
    /// A reclaimed page passed its atomic remote-free collection but rejected
    /// the source false-force local-list transfer. The low owner, target
    /// association, and consumed bitmap/count state remain with the caller's
    /// retained adoption owner.
    LocalFree(FreeListError),
    /// A bounded post-exit publisher did not complete while the direct
    /// freeing thread held the source low owner bit. The page remains owned
    /// and the caller must retain its enclosing post-exit route; it must not
    /// unown the page as though the requested remote client had published.
    PostExitRemotePublisher,
}

/// Result of abandoning one page without performing terminal page release.
///
/// `Empty` retains the low owner bit exactly until a later page-release slice
/// consumes the page. This makes the current absence of metadata reuse
/// explicit instead of treating an empty page as safely reusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbandonResult {
    Empty,
    UnownedMapped,
    UnownedUnmapped,
}

/// One successfully claimed mapped-abandoned page reassociated with a new
/// owner. It carries no destructor: queue insertion and page lifetime remain
/// later source slices.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AdoptedPage {
    page: NonNull<Page>,
    collected_remote_blocks: usize,
}

/// A source bitmap claim that crossed the low-owner boundary but could not
/// finish reassociation. Its raw page stays with the caller's consuming
/// terminal owner; the bitmap bit is intentionally still clear and retrying
/// would fabricate a second owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetainedAdoptFailure {
    page: NonNull<Page>,
    error: AbandonError,
}

/// Result of one `allow_collect=true` remote free on a mapped abandoned page.
///
/// This is the mapped same-origin portion of
/// `free.c:mi_free_try_collect_mt`: a producer can either find another
/// abandoned-free owner already responsible for the decision, reclaim the
/// page into its original live Theap, or make the page empty. Empty remains a
/// terminal result here because `_mi_arenas_page_free` needs the separate
/// page-map/span release authority that this bounded handoff deliberately
/// does not own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappedAbandonedFreeResult {
    PublishedToExistingOwner,
    Reclaimed { collected_remote_blocks: usize },
    Empty,
}

/// Result of the mapped-abandoned prefix of `mi_free_try_collect_mt` when a
/// bounded owner-exit handoff admits only the source all-free outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappedAbandonedFreeToEmptyResult {
    PublishedToExistingOwner,
    Empty,
}

/// Result of the mapped abandoned-page tail after source reclaim has already
/// been declined.
///
/// `mi_free_try_collect_mt` first checks the all-free result, then attempts
/// to reclaim only when the freeing thread has a suitable current Theap. A
/// post-thread-exit caller with no such Theap must preserve the remaining
/// mapped page and release the low owner bit again; it must not dereference
/// the departed `page->theap` association or manufacture a requeue. This
/// result keeps that source decision separate from a later process-owned
/// PageMap/span terminal release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappedAbandonedFreeAfterFailedReclaimResult {
    PublishedToExistingOwner,
    Empty,
    UnownedMapped,
}

/// Result of the unreclaimed, initially-unmapped part of
/// `free.c:mi_free_try_collect_mt`.
///
/// This capability begins only after the source reclaim decision has already
/// failed. It does not retry reclamation after a concurrent publication: the
/// source instead collects that publication, then selects terminal release,
/// reabandonment to the exact arena bitmap, or unownership. [`Self::Empty`]
/// retains the low owner bit and page metadata for a separate page-map/span
/// terminal-release capability; it does not claim that raw storage is safe to
/// reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnmappedAbandonedFreeResult {
    PublishedToExistingOwner,
    Empty,
    ReabandonedMapped,
    UnownedUnmapped,
}

/// Result of one bounded full-medium aggregate free tail.
///
/// A member starts as a full source-unmapped page. Its first below-mostly-used
/// client free can publish that member's exact bitmap/count pair; later frees
/// use the mapped half of the same source tail. The caller owns the registry
/// count and terminal PageMap/span release, so this result intentionally does
/// not expose a reusable page or a reclaim/requeue edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FullMediumAbandonedFreeAfterFailedReclaimResult {
    PublishedToExistingOwner,
    StillLive,
    Empty,
}

/// Result of one bounded per-member full-large aggregate free tail.
///
/// A member starts as a full source-unmapped page. Its first below-mostly-used
/// client free can publish that member's exact static-main bitmap/count pair;
/// later frees use the mapped half of the same source tail. The caller owns
/// the registry count and terminal 64-slice PageMap/span release, so this
/// result intentionally does not expose a reusable page or a reclaim/requeue
/// edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FullLargeAbandonedFreeAfterFailedReclaimResult {
    PublishedToExistingOwner,
    StillLive,
    Empty,
}

/// Result of the narrow failed-reclaim tail shared by one bounded mixed
/// full-medium/full-large aggregate.
///
/// The source `BIN_FULL` queue may contain both regular kinds, but neither
/// member enters small's partial collector or an allocation-time reclaim path.
/// This helper therefore keeps the common normal-collector tail explicit while
/// leaving queue traversal, per-member span release, and the eventual mixed
/// aggregate registry to a separately typed owner-exit boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult {
    PublishedToExistingOwner,
    StillLive,
    Empty,
}

/// Result of the one bounded full non-direct-small aggregate free
/// tail.
///
/// This is deliberately distinct from direct small: every member began above
/// `SMALL_SIZE_MAX`, has no direct-cache image, and therefore takes free.c's
/// ordinary collector. It starts source-unmapped and can publish its exact
/// static-main bitmap/count pair only after the mostly-used boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult {
    PublishedToExistingOwner,
    StillLive,
    Empty,
}

/// Result of the one bounded per-member full direct-small aggregate free
/// tail.
///
/// This is deliberately distinct from non-direct small: every member began at
/// or below `SMALL_SIZE_MAX`, retained one exact rounded direct-cache image at
/// owner exit, and therefore takes free.c's partial collector. The partial
/// head makes the source mostly-used transition lag one client free behind the
/// normal collector path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FullDirectSmallAbandonedFreeAfterFailedReclaimResult {
    PublishedToExistingOwner,
    StillLive,
    Empty,
}

/// Result of the source failed-reclaim tail shared by the general owner-exit
/// regular-page route.
///
/// A member may have entered owner exit already mapped because it was nonfull,
/// or may have begun full and still carry ordinary unmapped abandonment until
/// a later client free crosses the mostly-used boundary. The caller owns the
/// complete PageMap/span terminal release and keeps this result deliberately
/// free of reclaim, requeue, or fresh-allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegularAbandonedFreeAfterFailedReclaimResult {
    PublishedToExistingOwner,
    StillLive,
    Empty,
}

/// The PageMap/span owner's final disposition after an abandoned regular
/// page became all-free.
///
/// This is deliberately not an ordinary success/error result. Once
/// `free.c:mi_abandoned_page_try_free` has made the page all-free, cleared a
/// mapped identity when present, and retained the low owner bit, the terminal
/// PageMap/span release owns the only remaining lifetime decision. A failed
/// unregister, arena release, or `munmap` must retain that one owner; it must
/// not recreate the exited Theap or a client route in order to retry later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "the terminal release disposition determines whether the abandoned page remains owned"]
pub(crate) enum PostOwnerExitTerminalRelease {
    /// The caller finished source-ordered PageMap/span/metadata release. It
    /// may have invalidated `page`, so the free primitive performs no further
    /// access after receiving this disposition.
    Released,
    /// Release could not complete after ownership became terminal. The caller
    /// retains the page, its low owner bit, and all PageMap/span state as one
    /// auditable terminal owner. A later producer can only publish to that
    /// retained atomic owner; it cannot re-enter this page's normal
    /// reabandon or terminal-release tail.
    Retained,
}

/// Result of one pointer-centered post-owner-exit free for a regular arena
/// page.
///
/// The result deliberately names only the source page state. It contains no
/// old owner admission, Theap, route, or exact-client identifier: the caller
/// derives `page` and the canonical `block` from its pointer lookup, then
/// this source tail determines the next action from the page's atomics and
/// abandoned identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostOwnerExitRegularFreeResult {
    /// Another producer already owns this page's atomic abandoned-free head
    /// and is responsible for the source collection decision.
    PublishedToExistingOwner,
    /// The page remains live and abandoned. It is either mapped/unowned or
    /// still source-unmapped because it remains mostly used.
    StillLive,
    /// The final free ran the supplied source-ordered terminal release.
    Released,
    /// The final free reached terminal release, but the caller retained the
    /// unique final owner after its release attempt failed.
    TerminalReleaseRetained,
}

/// Exact terminal release authority for one all-free regular arena page.
///
/// The source page metadata can be retired before returning its arena slices.
/// Keep the copied `MemoryId` with the original remote-free claim so a failed
/// slice return still has one mechanically auditable owner after retirement
/// clears the page's own `memid`. This is not a page lookup, route, or retry
/// handle: terminal callers may only release or retain this exact value.
#[must_use = "an all-free regular claim must be released or retained terminally"]
pub(crate) struct ClaimedPostOwnerExitRegularRelease {
    owner: remote_free::ClaimedAbandonedRemoteFree,
    memory: MemoryId,
}

impl ClaimedPostOwnerExitRegularRelease {
    /// Returns the exact all-free page held by this terminal owner.
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> { self.owner.page() }

    /// Returns the copied source arena provenance retained across metadata
    /// retirement and a possible failed slice release.
    #[inline]
    pub(crate) const fn memory(&self) -> MemoryId { self.memory }
}

/// Result of a claimed regular page's terminal callback.
///
/// Unlike the older scalar terminal disposition, the retained form returns
/// the same exact owner that entered the callback. This makes it impossible
/// to report a failed post-retirement slice release with only a raw page
/// pointer whose provenance has already been cleared.
#[must_use = "a regular terminal callback must release or retain its exact owner"]
pub(crate) enum ClaimedPostOwnerExitRegularTerminalRelease {
    Released,
    Retained(ClaimedPostOwnerExitRegularRelease),
}

/// Disposition after consuming an already-published remote-free owner claim.
///
/// Unlike [`PostOwnerExitRegularFreeResult`], the terminal-retention branch
/// carries the same non-copyable source owner capability and copied backing
/// provenance forward. Successful release or an unown/reabandon transition
/// discharges it; no fieldless result permits a caller to return while
/// silently retaining `xthread_free`'s low owner bit.
#[must_use = "a post-claim result may retain the unique abandoned-page owner"]
pub(crate) enum ClaimedPostOwnerExitRegularFreeResult {
    /// A racing producer became responsible after the continuation transferred
    /// the low bit through the source unown loop.
    PublishedToExistingOwner,
    /// The continuation legally reabandoned or unowned a still-live page.
    StillLive,
    /// The supplied terminal owner completed PageMap/span/metadata release.
    Released,
    /// Terminal release retained the unique low-bit owner and exact backing
    /// provenance, including after metadata retirement.
    TerminalReleaseRetained(ClaimedPostOwnerExitRegularRelease),
}

/// A post-claim continuation error with its unique page owner preserved.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a failed post-claim tail still owns the abandoned page"]
pub(crate) struct ClaimedPostOwnerExitRegularFreeFailure {
    owner: remote_free::ClaimedAbandonedRemoteFree,
    error: AbandonError,
}

/// Source backing selected for an all-free singleton's terminal tail.
///
/// Arena singletons skip the mapped-abandoned bitmap but still return their
/// exact slices through `_mi_arenas_page_free`. OS and externally supplied
/// singleton mappings first leave `heap->os_abandoned_pages` and then run the
/// same source terminal page release with their original memory provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaimedPostOwnerExitSingletonBacking {
    Arena,
    OsOrExternal,
}

/// Linear terminal owner of an already-collected all-free singleton.
///
/// This contains the original remote-publication claim, not a reconstructed
/// page handle. Only the terminal callback receives it, so arena slice return
/// or OS/external list removal and mapping release consumes the exact owner
/// that published the final block. A failed terminal operation returns this
/// same value intact.
#[must_use = "an all-free singleton claim must be released or retained terminally"]
pub(crate) struct ClaimedPostOwnerExitSingletonRelease {
    owner: remote_free::ClaimedAbandonedRemoteFree,
    memory: MemoryId,
    backing: ClaimedPostOwnerExitSingletonBacking,
}

impl ClaimedPostOwnerExitSingletonRelease {
    /// Returns the exact all-free page held by this terminal owner.
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> { self.owner.page() }

    /// Returns the block whose publication acquired this owner.
    #[inline]
    pub(crate) const fn published_block(&self) -> NonNull<u8> {
        self.owner.published_block()
    }

    /// Returns the copied source memory provenance for terminal release.
    #[inline]
    pub(crate) const fn memory(&self) -> MemoryId { self.memory }

    /// Selects the source arena or OS/external terminal release route.
    #[inline]
    pub(crate) const fn backing(&self) -> ClaimedPostOwnerExitSingletonBacking {
        self.backing
    }
}

/// Disposition returned by the singleton terminal release callback.
///
/// `Released` proves the callback consumed the capability through source
/// list/bitmap, PageMap, metadata, and memory release. `Retained` carries the
/// exact same non-copyable owner after any fail-stop terminal outcome.
#[must_use = "a singleton terminal release may retain its exact page owner"]
pub(crate) enum ClaimedPostOwnerExitSingletonFreeResult {
    Released,
    TerminalReleaseRetained(ClaimedPostOwnerExitSingletonRelease),
}

/// A pre-terminal singleton continuation error with its original claim.
#[must_use = "a failed singleton post-claim tail still owns the abandoned page"]
pub(crate) struct ClaimedPostOwnerExitSingletonFreeFailure {
    owner: remote_free::ClaimedAbandonedRemoteFree,
    error: AbandonError,
}

impl ClaimedPostOwnerExitSingletonFreeFailure {
    /// Returns the retained exact claim and the reason collection stopped.
    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (remote_free::ClaimedAbandonedRemoteFree, AbandonError) {
        (self.owner, self.error)
    }
}

impl ClaimedPostOwnerExitRegularFreeFailure {
    /// Returns the retained owner and the reason its source tail stopped.
    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (remote_free::ClaimedAbandonedRemoteFree, AbandonError) {
        (self.owner, self.error)
    }
}

impl RetainedAdoptFailure {
    #[inline]
    pub(crate) const fn page(self) -> NonNull<Page> { self.page }

    #[inline]
    pub(crate) const fn error(self) -> AbandonError { self.error }
}

impl AdoptedPage {
    #[inline]
    pub(crate) const fn page(&self) -> NonNull<Page> {
        self.page
    }

    #[inline]
    pub(crate) const fn collected_remote_blocks(&self) -> usize {
        self.collected_remote_blocks
    }
}

/// Ports the mapped same-origin reclaim branch of
/// `free.c:mi_free_try_collect_mt` for one `allow_collect=true` remote free.
///
/// The existing consuming dynamic handoff is the only production caller. It
/// supplies its original live Theap as `target_theap`; after abandoning, that
/// is still the page's source-associated Theap and its empty regular queue is
/// within the frozen default reclaim limit. True reabandon is intentionally
/// absent here: upstream reaches it only from an *unmapped* abandoned page,
/// whereas this capability proves the page is presently mapped.
///
/// # Safety
///
/// `page` must be a stable mapped abandoned page for `map`; `block` must be
/// one exact current canonical allocation of that page. `target_theap` and
/// `target_thread` must name the current same-origin live Theap and remain
/// valid until the caller requeues a successful reclaim. The caller retains
/// the page-map, arena image, and terminal release authority throughout. A
/// result of `Empty` retains the owned page for that terminal authority. A
/// direct-sized small page (`block_size <= SMALL_SIZE_MAX`) must satisfy the
/// pinned source `reserved >= 16` invariant; an invalid page is retained as a
/// terminal error instead of entering partial collection.
pub(crate) unsafe fn free_mapped_and_reclaim<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
    target_theap: NonNull<Theap>,
    target_thread: LiveThreadId,
) -> Result<MappedAbandonedFreeResult, AbandonError> {
    // SAFETY: the caller supplies the stable abandoned-page/block proof. The
    // producer reads only atomic page fields and its own block link.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(MappedAbandonedFreeResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // A successful `allow_collect` push acquired the source low owner bit;
    // only now may this path inspect ordinary page state.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED_MAPPED {
        return Err(AbandonError::NotAbandoned);
    }
    // `mi_free_try_collect_mt` reaches the partial small-page collector only
    // under this source invariant. Reject an invalid synthetic/foreign page
    // after retaining its claimed owner state rather than using the optimized
    // path without its required geometry.
    if state.block_size <= crate::config::SMALL_SIZE_MAX && state.reserved < 16 {
        return Err(AbandonError::InvalidPageGeometry);
    }

    // The frozen normal-release small-page path avoids an atomic detach of
    // its just-published head. Larger pages use the ordinary full collection.
    // Both source paths run before the empty/reclaim decision.
    let collected_remote_blocks = if state.block_size <= crate::config::SMALL_SIZE_MAX {
        unsafe { remote_free::collect_abandoned_partly(page, block) }
    } else {
        unsafe { remote_free::collect_abandoned(page) }
    }
    .map_err(AbandonError::RemoteFree)?;

    if page_is_empty(&state) {
        unabandon_mapped(&state, Some(map))?;
        return Ok(MappedAbandonedFreeResult::Empty);
    }

    // `page_reclaim_on_free == 0` reclaims only into the originating Theap.
    // The consuming dynamic handoff validates that source condition before it
    // enters here. Preserve the source order: clear the mapped entry before
    // live reassociation, then run the second normal owner collection.
    if state.block_size > crate::config::MEDIUM_MAX_OBJ_SIZE
        || unsafe { ptr::read(state.theap.as_ptr()) } != target_theap.as_ptr()
    {
        // A mapped page that cannot use the same-origin reclaim branch stays
        // owned for a later generalized abandoned-free policy. Do not invent
        // the unmapped reabandon route in this mapped-only handoff.
        return Err(AbandonError::NotAbandoned);
    }
    unabandon_mapped(&state, Some(map))?;
    unsafe { ptr::write(state.theap.as_ptr(), target_theap.as_ptr()) };
    set_thread_identity(&state, target_thread.get());
    // SAFETY: reassociation installed a live owner and this caller retains
    // sole ordinary-field authority.
    let owner = unsafe { Page::remote_free_owner_state_at(page) }
        .ok_or(AbandonError::NotAbandoned)?;
    let collected_after_reassociation = unsafe { remote_free::collect(owner) }
        .map_err(AbandonError::RemoteFree)?;
    Ok(MappedAbandonedFreeResult::Reclaimed {
        collected_remote_blocks: collected_remote_blocks + collected_after_reassociation,
    })
}

/// The source collector selected by one mapped one-block owner-exit endpoint.
///
/// Keeping the direct-small partial collector distinct from the normal
/// collector prevents callers from treating a rounded direct-cache page as a
/// non-direct small page merely because both have [`PageKind::Small`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MappedOneBlockOwnerExitCollector {
    Normal,
    DirectSmall,
}

/// Ports only the mapped-abandoned all-free prefix of
/// `free.c:mi_free_try_collect_mt` for one final normal-collector client free
/// at owner exit.
///
/// The source checks whether the page is empty immediately after ordinary
/// collection and before it enters the reclaim branch. A sole non-direct
/// small, medium, or large page with one current client block must therefore
/// reach `Empty`. If it does not, this narrow helper retains the acquired low
/// owner bit and returns [`AbandonError::MappedPageNotEmpty`] rather than
/// manufacturing a reclaim, requeue, or general abandoned-page policy.
///
/// # Safety
///
/// `page` must be stable mapped-abandoned metadata for `map`; `block` must be
/// its exact one current canonical allocation. The caller retains the PageMap,
/// arena bitmap image, and terminal page-map/span release authority throughout.
/// A result of `Empty` retains the owned page for that terminal authority.
pub(crate) unsafe fn free_mapped_one_block_to_empty<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
) -> Result<MappedAbandonedFreeToEmptyResult, AbandonError> {
    // SAFETY: the normal endpoint's caller provides the stable mapped-page,
    // exact-block, bitmap, and terminal-release proof required by the shared
    // source all-free prefix.
    unsafe {
        free_mapped_one_block_to_empty_with_collector(
            page,
            block,
            map,
            MappedOneBlockOwnerExitCollector::Normal,
        )
    }
}

/// Ports only the mapped-abandoned all-free prefix of
/// `free.c:mi_free_try_collect_mt` for one final direct-small client free at
/// owner exit.
///
/// The direct-small source branch uses `_mi_page_free_collect_partly` with the
/// just-published remote head, and therefore requires the pinned
/// `reserved >= 16` geometry. Its one-live-block owner proves that partial
/// collection reaches all-free before the source reclaim branch. Any other
/// outcome remains terminally retained rather than becoming a general direct
/// cache or multi-free lifecycle.
///
/// # Safety
///
/// `page` must be stable mapped-abandoned direct-small metadata for `map`;
/// `block` must be its exact one current canonical allocation. The caller
/// retains the PageMap, exact direct-cache-detached arena image, and terminal
/// page-map/span release authority throughout. A result of `Empty` retains
/// the owned page for that terminal authority.
pub(crate) unsafe fn free_mapped_direct_one_block_to_empty<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
) -> Result<MappedAbandonedFreeToEmptyResult, AbandonError> {
    // SAFETY: the direct-small endpoint's caller additionally proves the
    // exact rounded cache image was detached and `block` is its sole live
    // direct-small allocation through this partial-collector transition.
    unsafe {
        free_mapped_one_block_to_empty_with_collector(
            page,
            block,
            map,
            MappedOneBlockOwnerExitCollector::DirectSmall,
        )
    }
}

/// Shared source all-free prefix after a public boundary fixed the only valid
/// one-block collection class.
///
/// # Safety
///
/// See the public normal/direct-small entry points. `collector` must match
/// the exact page class established by the caller before it invokes this raw
/// source tail.
unsafe fn free_mapped_one_block_to_empty_with_collector<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
    collector: MappedOneBlockOwnerExitCollector,
) -> Result<MappedAbandonedFreeToEmptyResult, AbandonError> {
    // SAFETY: the caller supplies the stable abandoned-page/block proof. The
    // producer reads only atomic page fields and its own block link.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(MappedAbandonedFreeToEmptyResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // A successful `allow_collect` push acquired the source low owner bit;
    // only now may this path inspect ordinary page state.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED_MAPPED {
        return Err(AbandonError::NotAbandoned);
    }
    // Select only the exact source branch proved by the higher-level handoff.
    // Normal one-block endpoints remain strictly above the direct-cache
    // boundary, with their caller retaining the source-specific small,
    // medium, or large span proof. The direct-small endpoint retains the
    // partial collector and its `reserved >= 16` precondition as a separately
    // named contract.
    let geometry_matches_collector = match collector {
        MappedOneBlockOwnerExitCollector::Normal => {
            matches!(
                size_class::page_kind_for_block_size(state.block_size),
                Some(
                    crate::types::PageKind::Small
                        | crate::types::PageKind::Medium
                        | crate::types::PageKind::Large
                )
            ) && state.block_size > crate::config::SMALL_SIZE_MAX
                && state.reserved > 1
        }
        MappedOneBlockOwnerExitCollector::DirectSmall => {
            size_class::page_kind_for_block_size(state.block_size)
                == Some(crate::types::PageKind::Small)
                && state.block_size <= crate::config::SMALL_SIZE_MAX
                && state.reserved >= 16
        }
    };
    if !geometry_matches_collector {
        return Err(AbandonError::InvalidPageGeometry);
    }

    // Both exact source collectors run before the all-free decision and before
    // any source reclaim branch. The direct-sized path consumes its exact
    // just-published head; normal pages detach the full remote list.
    match collector {
        MappedOneBlockOwnerExitCollector::Normal => unsafe { remote_free::collect_abandoned(page) },
        MappedOneBlockOwnerExitCollector::DirectSmall => unsafe {
            remote_free::collect_abandoned_partly(page, block)
        },
    }
    .map_err(AbandonError::RemoteFree)?;

    if !page_is_empty(&state) {
        return Err(AbandonError::MappedPageNotEmpty);
    }
    unabandon_mapped(&state, Some(map))?;
    Ok(MappedAbandonedFreeToEmptyResult::Empty)
}

/// Ports the mapped abandoned-page tail of `mi_free_try_collect_mt` after a
/// caller has established that source free-triggered reclamation is not
/// available.
///
/// This is deliberately distinct from [`free_mapped_and_reclaim`]: it never
/// inspects or dereferences the page's stale origin Theap. It first performs
/// the exact small partial or normal collection, frees an all-free page after
/// mapped identity removal, and otherwise uses
/// `mi_abandoned_page_unown_from_free`'s expected-head loop. A live result
/// remains mapped and unowned for a later free or allocation-time claim.
///
/// # Safety
///
/// `page` must be stable initialized mapped-abandoned metadata for `map` and
/// `block` must be one exact current canonical allocation of that page. The
/// caller must have already determined that its current thread cannot reclaim
/// the page, and must retain the PageMap, matching Heap/arena bitmap-count
/// pair, metadata, and final span-release authority through every returned
/// state. `Empty` retains the low owner bit and requires that separate final
/// release before the page can be reused. For a direct-sized small page
/// (`block_size <= SMALL_SIZE_MAX`), the pinned source `reserved >= 16`
/// invariant is required.
pub(crate) unsafe fn free_mapped_after_failed_reclaim<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
) -> Result<MappedAbandonedFreeAfterFailedReclaimResult, AbandonError> {
    // SAFETY: the caller's preselected capability names this exact page. The
    // selector is intentionally deferred until after the common helper has
    // acquired the low owner bit, but this established route needs no such
    // deferral and simply returns its borrowed map.
    unsafe {
        free_mapped_after_failed_reclaim_select_map(page, block, |_memory, _block_size| Ok(map))
    }
}

/// The mapped failed-reclaim tail with a bitmap/count capability selected
/// only after the source low owner bit has been acquired.
///
/// A post-thread-exit aggregate route cannot safely read a Page's ordinary
/// `memid` or `block_size` merely to choose its static-main bitmap: those
/// fields become readable only after `push_abandoned` wins the low owner bit.
/// This helper preserves the same `free.c:mi_free_try_collect_mt` tail as
/// [`free_mapped_after_failed_reclaim`], but supplies the validated arena
/// memory and block size to `select_map` at exactly that point. The returned
/// capability remains owned locally through identity/bit/count removal or
/// exact expected-head unownership; it is not a general map lookup API.
///
/// # Safety
///
/// `page` and `block` have the same stable mapped-abandoned lifetime
/// requirements as [`free_mapped_after_failed_reclaim`]. `select_map` must
/// return the exact bitmap/count capability for the supplied page memory and
/// size class, and its enclosing caller must retain that capability's arena
/// and Heap lifetime until this operation completes.
pub(crate) unsafe fn free_mapped_after_failed_reclaim_select_map<M, F>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
) -> Result<MappedAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
{
    // SAFETY: the caller supplies the stable abandoned-page/block proof. The
    // atomic source publication itself does not create a Rust page reference.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // A successful low-bit claim is the sole permission to observe ordinary
    // page state. The mapped capability must name this exact arena/bin/slice
    // before source collection can clear or unown it.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED_MAPPED {
        return Err(AbandonError::NotAbandoned);
    }
    if state.reserved == 0 || state.block_size == 0 || state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::InvalidPageGeometry);
    }
    // The low owner bit above is the first point at which it is legal to
    // observe the ordinary page fields needed to select the static-main
    // bitmap/count pair. Keep the selected value through the complete source
    // tail so identity, bit, and count cannot be split across capabilities.
    let map = select_map(state.memid, state.block_size)?;
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT
        || bin != map.bin()
        || map.page_slice_index(state.memid).is_none()
        || page_is_full(&state)
    {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    if state.block_size <= crate::config::SMALL_SIZE_MAX && state.reserved < 16 {
        return Err(AbandonError::InvalidPageGeometry);
    }

    // `_mi_page_free_collect_partly` retains the just-published small head,
    // whereas the normal collector leaves an owned empty head. Carry that
    // exact expected value into `mi_abandoned_page_unown_from_free` below.
    let expected_head = if state.block_size <= crate::config::SMALL_SIZE_MAX {
        block.as_ptr().expose_provenance()
    } else {
        0
    };
    if state.block_size <= crate::config::SMALL_SIZE_MAX {
        unsafe { remote_free::collect_abandoned_partly(page, block) }
    } else {
        unsafe { remote_free::collect_abandoned(page) }
    }
    .map_err(AbandonError::RemoteFree)?;

    if page_is_empty(&state) {
        unabandon_mapped(&state, Some(&map))?;
        return Ok(MappedAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    unown_mapped_from_free(page, &state, &map, expected_head)
}

/// Ports the failed-reclaim tail of `free.c:mi_free_try_collect_mt` for one
/// initially-unmapped abandoned page.
///
/// The source has already completed (or deliberately declined) its one
/// reclaim attempt before this point. This helper performs the matching
/// `allow_collect=true` push, the small partial or ordinary collection, then
/// chooses in source order: terminal all-free, unmapped-to-mapped reabandon,
/// or `mi_abandoned_page_unown_from_free`. If a concurrent publication makes
/// the expected-head CAS fail, it collects and repeats only the terminal and
/// reabandon decisions; it intentionally never calls reclamation again.
///
/// # Safety
///
/// `page` must be stable initialized metadata for an unowned
/// `THREAD_ID_ABANDONED` page whose source reclaim attempt has failed. `block`
/// must be one exact current canonical allocation of that page and no page-map
/// entry, bitmap reader, producer, or terminal release may outlive this call
/// except under the result's retained owner state. `map` must be the exact
/// arena/bin/slice capability that would receive this page if it becomes
/// reusable. A direct-sized small page (`block_size <= SMALL_SIZE_MAX`) must
/// satisfy the pinned source `reserved >= 16` invariant. `Empty` retains the
/// owned abandoned page for a distinct terminal page-map/span release authority.
pub(crate) unsafe fn free_unmapped_after_failed_reclaim<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
) -> Result<UnmappedAbandonedFreeResult, AbandonError> {
    let mut before_expected_cas: Option<fn()> = None;
    // SAFETY: this public boundary supplies the caller's complete abandoned
    // page/block/map lifetime proof to the source-shaped inner protocol. This
    // older raw boundary has no owner-local collection capability; the
    // claim-bearing continuation below supplies the source false phase.
    unsafe {
        free_unmapped_after_failed_reclaim_inner(
            page,
            block,
            map,
            &mut before_expected_cas,
            |_page| Ok(()),
        )
    }
}

/// Ports the post-reclaim free tail for one regular page in the general
/// owner-exit aggregate.
///
/// Unlike the older mapped-only and full-only helpers, this boundary admits
/// the two source identities one regular page can have after owner exit:
/// initially nonfull pages already carry `ABANDONED_MAPPED`, while initially
/// full pages retain `ABANDONED` until a later free crosses the source
/// mostly-used predicate. The selector therefore runs only after
/// `push_abandoned` has acquired the low owner bit, and its exact map remains
/// coupled to every mapped identity/count transition. This helper does not
/// reclaim, requeue, retain a former Theap address, or release a page span.
///
/// # Safety
///
/// `page` and `block` must be one exact current regular Small, Medium, or
/// Large arena-page allocation in a serial post-owner-exit route. The source
/// page must be queue-detached and have either `THREAD_ID_ABANDONED` or
/// `THREAD_ID_ABANDONED_MAPPED` identity after the successful low-owner
/// claim. `select_map` must return the exact static-main bitmap/count pair
/// for the supplied arena memory and size class. The caller retains PageMap,
/// metadata, arena, and terminal span-release authority through every result.
/// `Empty` retains the low owner bit for that separate terminal release.
pub(crate) unsafe fn free_regular_after_failed_reclaim_select_map<M, F>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
) -> Result<RegularAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
{
    // SAFETY: this ordinary linear route has no nested post-exit publisher.
    // The source low-owner claim may proceed directly into collection.
    unsafe {
        free_regular_after_failed_reclaim_select_map_with_after_claim(
            page,
            block,
            select_map,
            || true,
        )
    }
}

/// Ports the same regular post-thread-exit failed-reclaim tail as
/// [`free_regular_after_failed_reclaim_select_map`], but gives one bounded
/// caller a synchronous source interleaving immediately after it has claimed
/// the abandoned low owner bit and before it reads ordinary page fields or
/// detaches the remote list.
///
/// The callback may only publish a bounded set of already-proved distinct
/// clients through this page's atomic abandoned remote-free head and must
/// return before this function continues. It cannot inspect or mutate ordinary
/// page state, map membership, a bitmap, or a former Theap. A false result
/// keeps the claimed low owner bit terminally held: pretending a missing
/// publication never existed would let the caller unown a page with an
/// unresolved client.
///
/// # Safety
///
/// `page`, `block`, and `select_map` have the exact contract of
/// [`free_regular_after_failed_reclaim_select_map`]. `after_claim` must run
/// synchronously, may publish only the caller's bounded distinct exact current
/// clients from the same stable page, and must return true only after every
/// such publication has completed. It must not retain aliases past its return.
pub(crate) unsafe fn free_regular_after_failed_reclaim_select_map_with_after_claim<M, F, H>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
    after_claim: H,
) -> Result<RegularAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
    H: FnOnce() -> bool,
{
    // SAFETY: the established bounded callers already own their complete
    // source collection protocol. Preserve their existing raw tail while the
    // generic post-owner-exit entry below supplies its explicit local-list
    // collection seam.
    unsafe {
        free_regular_after_failed_reclaim_select_map_with_after_claim_and_owner_deferred_collection(
            page,
            block,
            select_map,
            after_claim,
            |_page| Ok(()),
        )
    }
}

/// Shared regular post-owner-exit tail with the owner-side local-free phase
/// made explicit.
///
/// `page.c:_mi_page_free_collect` always drains the atomic remote list and
/// then transfers the owner-local `local_free` list before `free.c` decides
/// whether to release, reabandon, or unown the page. The existing raw remote
/// helpers model the first half; this callback is the second half. It is not
/// mimalloc's unrelated `_mi_deferred_free` user callback, and it receives no
/// former Theap, client route, PageMap, or arena authority.
///
/// # Safety
///
/// This has the same stable page/block/bitmap requirements as
/// [`free_regular_after_failed_reclaim_select_map`]. After *each* source
/// remote-list collection, `collect_owner_deferred_frees` must perform only
/// the false-force owner-local collection for this exact page while the caller
/// holds its low owner bit. The expected-head unown loop can observe a later
/// remote publication and collect again, so the callback must remain valid for
/// every such source collection. It must not release, unown, reabandon, or
/// retain aliases to the page. An error leaves that low bit with the caller as
/// the one terminal owner and prevents every later state transition in this
/// tail.
unsafe fn free_regular_after_failed_reclaim_select_map_with_after_claim_and_owner_deferred_collection<
    M,
    F,
    H,
    C,
>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
    after_claim: H,
    collect_owner_deferred_frees: C,
) -> Result<RegularAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
    H: FnOnce() -> bool,
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
{
    // SAFETY: the route holds the stable abandoned-page/client allocation
    // proof through this source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(RegularAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {
            if !after_claim() {
                return Err(AbandonError::PostExitRemotePublisher);
            }
        }
    }

    // SAFETY: the source publication above changed an unowned remote head
    // into an owned head and retained the exact page/block lifetime. The
    // continuation begins after that publication and must not link `block`
    // into `xthread_free` a second time.
    unsafe {
        finish_regular_after_remote_claim(
            page,
            block,
            select_map,
            collect_owner_deferred_frees,
        )
    }
}

/// Continues the regular post-owner-exit source tail after remote publication
/// has already claimed the abandoned low owner bit.
///
/// This begins at `mi_free_try_collect_mt`'s post-CAS ownership assertion. It
/// deliberately contains no call to `push_abandoned`: `block` is already the
/// published head (or remains reachable through a later racing head), and a
/// second publication would create a duplicate/self-referential free-list
/// entry.
///
/// # Safety
///
/// The caller must own the low `xthread_free` bit acquired by publication of
/// this exact `block`, retain the complete initialized page/block area, and
/// satisfy the bitmap and owner-local callback obligations documented by
/// `free_regular_after_failed_reclaim_select_map_with_after_claim_and_owner_deferred_collection`.
unsafe fn finish_regular_after_remote_claim<M, F, C>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
    mut collect_owner_deferred_frees: C,
) -> Result<RegularAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
{
    // A successful low-bit claim is the first legal point to inspect ordinary
    // page fields. Source collection must finish before this tail acquires a
    // PageMap capability for its later reabandon/unown/release decisions.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state)
        || !matches!(
            source_identity,
            THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED
        )
    {
        return Err(AbandonError::NotAbandoned);
    }
    if state.reserved <= 1 || state.block_size == 0 || state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::InvalidPageGeometry);
    }
    let kind = size_class::page_kind_for_block_size(state.block_size);
    if !matches!(kind, Some(PageKind::Small | PageKind::Medium | PageKind::Large)) {
        return Err(AbandonError::InvalidPageGeometry);
    }
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT || bin == BIN_FULL {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    if state.block_size <= SMALL_SIZE_MAX && state.reserved < 16 {
        return Err(AbandonError::InvalidPageGeometry);
    }
    // An already-mapped page must have been published by the source's
    // nonfull branch. A full page starts unmapped and may become mapped only
    // below through `terminal_or_reabandon_unmapped`.
    if source_identity == THREAD_ID_ABANDONED_MAPPED && page_is_full(&state) {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    // `_mi_page_free_collect_partly` retains the just-published direct-small
    // head. Its exact address remains the first expected owner-word image;
    // normal collection detaches the list and expects zero instead.
    let expected_head = if state.block_size <= SMALL_SIZE_MAX {
        block.as_ptr().expose_provenance()
    } else {
        0
    };
    if state.block_size <= SMALL_SIZE_MAX {
        // SAFETY: the direct-small geometry and published client head were
        // validated above while this route owns the low bit.
        unsafe { remote_free::collect_abandoned_partly(page, block) }
    } else {
        // SAFETY: this route owns the low bit and all normal collector state.
        unsafe { remote_free::collect_abandoned(page) }
    }
    .map_err(AbandonError::RemoteFree)?;

    // `page.c:_mi_page_free_collect` transfers owner-local deferred frees
    // only after it detached/merged the atomic remote list and before every
    // free/reclaim/reabandon/unown decision. The callback is deliberately
    // positioned before the all-free test so a failure retains the low owner
    // bit with no PageMap or terminal-release mutation.
    collect_owner_deferred_frees(page)?;

    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            let map = select_map(state.memid, state.block_size)?;
            if map.bin() != bin || map.page_slice_index(state.memid).is_none() {
                return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
            }
            unabandon_mapped(&state, Some(&map))?;
        }
        return Ok(RegularAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    let map = select_map(state.memid, state.block_size)?;
    if map.bin() != bin || map.page_slice_index(state.memid).is_none() {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, &map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    RegularAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    RegularAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    RegularAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free_with_owner_deferred_collection(
            page,
            &state,
            &map,
            expected_head,
            &mut no_test_hook,
            &mut collect_owner_deferred_frees,
        )? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => Ok(
                RegularAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner,
            ),
            UnmappedAbandonedFreeResult::Empty => {
                Ok(RegularAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(RegularAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free_with_owner_deferred_collection(
        page,
        &state,
        &map,
        expected_head,
        &mut collect_owner_deferred_frees,
    )? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => Ok(
            RegularAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner,
        ),
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(RegularAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(RegularAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Performs the false-force owner-local phase after a post-exit CAS claim.
///
/// The outer W08 owner-exit coordinator already runs force then false
/// collection before it establishes an abandoned identity. A pointer lookup
/// can, however, observe a page that was abandoned by another valid source
/// path. Repeating this exact false-force phase under the newly claimed low
/// bit keeps that front edge source-faithful without consulting or
/// dereferencing a departed `theap`; it is a no-op for the coordinator-drained
/// case and consumes a remaining `local_free` list for the direct case.
///
/// # Safety
///
/// `page` must be the exact abandoned page whose remote-head low bit is held
/// by the caller after a successful `allow_collect=true` publication. The
/// page metadata and complete local-list area must remain live and exclusively
/// owned through this one local-list transfer.
pub(crate) unsafe fn collect_post_owner_exit_local_free_false(
    page: NonNull<Page>,
) -> Result<(), AbandonError> {
    // SAFETY: the caller supplies the exact post-CAS low-bit and page-area
    // proof. This projection reads only the abandoned identities and raw
    // local-list fields; it never reads `page->theap`.
    let state = unsafe { Page::abandoned_local_collect_state_at(page) }
        .ok_or(AbandonError::InvalidPageGeometry)?;
    // SAFETY: `state` is the one abandoned page's held-owner local-list
    // projection. `force == false` matches the post-remote source phase.
    unsafe { free_list::collect_local_false(state) }
        .map(|_| ())
        .map_err(AbandonError::LocalFree)
}

/// Frees one canonical block from an exited owner's regular arena page and,
/// if that was the final block, hands the page directly to its terminal
/// PageMap/span owner.
///
/// This is the pointer/page-state portion of
/// `free.c:mi_free_try_collect_mt`,
/// `page.c:_mi_page_free_collect`, and
/// `mi_abandoned_page_try_free`. It intentionally composes only the regular
/// Small/Medium/Large arena-page branch already shared by mapped and
/// source-unmapped abandonment. The caller recovers `page` and `block` from
/// the allocation pointer; `select_map` runs only after the source low-owner
/// claim makes ordinary page fields readable and only after source collection
/// completes does it acquire the PageMap capability for the release tail. No
/// input identifies the former thread, an owner admission, or an exact client
/// route, and this function never reads or dereferences `page->theap`.
///
/// The final release is deliberately injected at the PageMap boundary rather
/// than guessed from page geometry. On [`PostOwnerExitTerminalRelease::Released`]
/// the closure has completed source-ordered PageMap unregister, arena/bitmap
/// cleanup, metadata release, and mapping release, so it may invalidate
/// `page`. On [`PostOwnerExitTerminalRelease::Retained`] the closure keeps the
/// low owner bit, PageMap entry, metadata, and mapping together as the one
/// terminal owner after a failure. In either case this function makes no page
/// access after the closure returns.
///
/// # Safety
///
/// `page` must be the still-registered initialized regular arena page
/// recovered for `block`, and `block` must be exactly the current canonical
/// live allocation. The PageMap entry and page metadata must remain valid
/// through the atomic publication and source collection. `select_map` must
/// return the exact mapped-abandoned bitmap/count capability for the selected
/// page identity, only for the duration of this call.
/// `collect_owner_deferred_frees` must perform the source false-force
/// owner-local `local_free` collection after every remote-list detach and
/// before any empty/reabandon/unown decision; it has no PageMap or terminal
/// release authority. An error retains the claimed low owner bit and prevents
/// the terminal callback. `terminal_release` runs only with that bit retained
/// after all-free collection; it must either release PageMap/span/metadata in
/// source order or retain all of them under that bit. Callers must not use
/// either pointer after reporting `Released`.
pub(crate) unsafe fn free_post_owner_exit_regular_page<M, F, C, R>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
    collect_owner_deferred_frees: C,
    terminal_release: R,
) -> Result<PostOwnerExitRegularFreeResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
    R: FnOnce(NonNull<Page>) -> PostOwnerExitTerminalRelease,
{
    // SAFETY: the caller supplies the stable pointer-to-page, canonical-block,
    // PageMap, and terminal-owner proof. The shared tail publishes through
    // only the page's atomic remote-free word before it wins the low bit.
    match unsafe {
        free_regular_after_failed_reclaim_select_map_with_after_claim_and_owner_deferred_collection(
            page,
            block,
            select_map,
            || true,
            collect_owner_deferred_frees,
        )
    }? {
        RegularAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(PostOwnerExitRegularFreeResult::PublishedToExistingOwner)
        }
        RegularAbandonedFreeAfterFailedReclaimResult::StillLive => {
            Ok(PostOwnerExitRegularFreeResult::StillLive)
        }
        RegularAbandonedFreeAfterFailedReclaimResult::Empty => {
            // The shared source tail has already cleared a mapped identity,
            // when applicable. It deliberately leaves the low owner bit held
            // so the terminal PageMap/span owner is unique through release.
            match terminal_release(page) {
                PostOwnerExitTerminalRelease::Released => {
                    Ok(PostOwnerExitRegularFreeResult::Released)
                }
                PostOwnerExitTerminalRelease::Retained => {
                    Ok(PostOwnerExitRegularFreeResult::TerminalReleaseRetained)
                }
            }
        }
    }
}

/// Continues W09's regular post-owner-exit free after a live publication
/// already changed an unowned remote head into an owned head.
///
/// `claim` contains the exact page and canonical block published by
/// [`remote_free::push_live_allocation`]. This function starts after that CAS:
/// it never calls `push_abandoned` and therefore cannot link the same block a
/// second time. A legal release, reabandon, or unown consumes the capability.
/// Every error and terminal-retention result returns it to the caller as the
/// unique auditable owner of the page, PageMap entry, metadata, and backing.
/// The terminal callback receives a typed wrapper with copied arena
/// provenance, so a failure after `retire_exclusive` cannot lose the source
/// slice claim when the page's own `memid` becomes empty.
///
/// # Safety
///
/// `claim` must come directly from the current free's
/// `LiveRemoteFreePublish::ClaimedAbandonedPage` result. `select_map` and
/// `collect_owner_deferred_frees` satisfy the corresponding obligations of
/// [`free_post_owner_exit_regular_page`]. `terminal_release` receives the
/// exact typed terminal owner and must return it intact on failure. On a
/// `Released` result, it may have invalidated the page and block, and this
/// function performs no later access.
pub(crate) unsafe fn continue_post_owner_exit_remote_claim<M, F, C, R>(
    claim: remote_free::ClaimedAbandonedRemoteFree,
    select_map: F,
    collect_owner_deferred_frees: C,
    terminal_release: R,
) -> Result<
    ClaimedPostOwnerExitRegularFreeResult,
    ClaimedPostOwnerExitRegularFreeFailure,
>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
    R: FnOnce(ClaimedPostOwnerExitRegularRelease) -> ClaimedPostOwnerExitRegularTerminalRelease,
{
    let page = claim.page();
    let block = claim.published_block();
    // SAFETY: the capability proves this exact block was already published
    // by the CAS that acquired the page's low owner bit. The continuation
    // consumes only its post-publication source authority.
    let result = unsafe {
        finish_regular_after_remote_claim(
            page,
            block,
            select_map,
            collect_owner_deferred_frees,
        )
    };
    match result {
        Err(error) => Err(ClaimedPostOwnerExitRegularFreeFailure {
            owner: claim,
            error,
        }),
        Ok(RegularAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner) => {
            Ok(ClaimedPostOwnerExitRegularFreeResult::PublishedToExistingOwner)
        }
        Ok(RegularAbandonedFreeAfterFailedReclaimResult::StillLive) => {
            Ok(ClaimedPostOwnerExitRegularFreeResult::StillLive)
        }
        Ok(RegularAbandonedFreeAfterFailedReclaimResult::Empty) => {
            // Source all-free collection leaves this exact low-bit owner in
            // place. Copy its backing before the callback because terminal
            // metadata retirement may clear `page.memid`; no page access
            // follows the callback.
            let release = ClaimedPostOwnerExitRegularRelease {
                owner: claim,
                memory: unsafe { Page::abandonment_state_at(page) }.memid,
            };
            match terminal_release(release) {
                ClaimedPostOwnerExitRegularTerminalRelease::Released => {
                    Ok(ClaimedPostOwnerExitRegularFreeResult::Released)
                }
                ClaimedPostOwnerExitRegularTerminalRelease::Retained(release) => Ok(
                    ClaimedPostOwnerExitRegularFreeResult::TerminalReleaseRetained(release),
                ),
            }
        }
    }
}

/// Tests the source singleton shape after an abandoned remote-free claim.
///
/// Pinned `internal.h:mi_page_is_huge` recognizes the usual size-forced
/// singleton and the aligned normal-OS variant: `reserved == 1` with the
/// mapping base below its metadata. The latter is only an admission fact here;
/// the W03 terminal callback must still reconstruct
/// [`crate::os_page::OsAlignedPageLayout`] before it changes the OS list or
/// PageMap. Arena and external pages retain the size-forced requirement.
#[inline]
fn is_source_singleton_claim_geometry(
    page: NonNull<Page>,
    state: &PageAbandonmentState,
) -> bool {
    if state.reserved != 1 {
        return false;
    }
    if matches!(
        size_class::page_kind_for_block_size(state.block_size),
        Some(PageKind::Singleton)
    ) {
        return true;
    }
    state.memid.kind() == MemoryKind::Os
        && state.memid.os_memory().is_some_and(|memory| {
            !memory.base.is_null()
                && memory.size != 0
                && memory.base.addr() < page.as_ptr().addr()
        })
}

/// Continues an already-published singleton claim through the source
/// all-free and terminal arena/OS release tail.
///
/// Pinned `free.c:mi_free_try_collect_mt` always runs
/// `mi_abandoned_page_try_free` after an `allow_collect=true` publication
/// claims an unowned page. A singleton has exactly one live block, so the
/// published block must make it all-free. This continuation starts after the
/// publication CAS, performs that source collection without republishing,
/// and then moves the exact non-copyable claim into `terminal_release`.
///
/// The callback receives copied `MemoryId` provenance with the claim and must
/// execute the two source terminal calls in this exact order, exactly once:
/// first `_mi_arenas_page_unabandon(page, NULL)`, then
/// `_mi_arenas_page_free(page, NULL)`. For an arena singleton, the first call
/// discharges the ordinary abandoned-page accounting before the second call
/// unregisters PageMap state and returns the arena slices. For OS/external
/// memory, it first removes the page from `heap->os_abandoned_pages`, then
/// the same second call unregisters PageMap state and releases the mapping.
/// It must return `Released` only after completing that full
/// unabandon-then-free list-or-bitmap/PageMap/metadata/memory tail. Any failure
/// returns the same [`ClaimedPostOwnerExitSingletonRelease`] through
/// `TerminalReleaseRetained`; this function performs no page access after the
/// callback begins.
///
/// # Safety
///
/// `claim` must come directly from the current singleton free's
/// `LiveRemoteFreePublish::ClaimedAbandonedPage` result. The PageMap entry,
/// page metadata, complete one-block area, source arena or OS-list owner, and
/// memory release authority must remain valid through this call.
/// `terminal_release` must consume only the supplied exact capability and
/// obey the release/retention contract above.
pub(crate) unsafe fn continue_post_owner_exit_singleton_remote_claim<R>(
    claim: remote_free::ClaimedAbandonedRemoteFree,
    terminal_release: R,
) -> Result<
    ClaimedPostOwnerExitSingletonFreeResult,
    ClaimedPostOwnerExitSingletonFreeFailure,
>
where
    R: FnOnce(
        ClaimedPostOwnerExitSingletonRelease,
    ) -> ClaimedPostOwnerExitSingletonFreeResult,
{
    let page = claim.page();
    let block = claim.published_block();
    // The claiming CAS is the first legal point to copy ordinary singleton
    // geometry. No producer can mutate these fields while this low bit stays
    // held; the copied provenance accompanies the exact terminal owner.
    let state = unsafe { Page::abandonment_state_at(page) };
    let memory_kind = state.memid.kind();
    let backing = if memory_kind == MemoryKind::Arena {
        ClaimedPostOwnerExitSingletonBacking::Arena
    } else if memory_kind == MemoryKind::External || memory_kind.is_os() {
        ClaimedPostOwnerExitSingletonBacking::OsOrExternal
    } else {
        return Err(ClaimedPostOwnerExitSingletonFreeFailure {
            owner: claim,
            error: AbandonError::InvalidPageGeometry,
        });
    };
    // `internal.h:mi_page_is_huge` treats a singleton as either the usual
    // size-forced large block or a normal OS mapping whose aligned metadata
    // lies after the mapping base.  The latter is how
    // `aligned_alloc(128 KiB, 7)` reaches `reserved == 1` even though its
    // rounded internal block remains `PageKind::Small`. W03's terminal
    // callback reconstructs `OsAlignedPageLayout` before it mutates the OS
    // list or PageMap. The rounded 4 KiB block already takes the existing
    // full collector (`> SMALL_SIZE_MAX`), so this admission does not widen
    // the direct-small partial collector.
    if !is_owned(&state)
        || source_thread_identity(&state) != THREAD_ID_ABANDONED
        || !is_source_singleton_claim_geometry(page, &state)
    {
        return Err(ClaimedPostOwnerExitSingletonFreeFailure {
            owner: claim,
            error: AbandonError::InvalidPageGeometry,
        });
    }

    let memory = state.memid;
    let mut no_test_hook: Option<fn()> = None;
    // SAFETY: `claim` proves that this exact block is already the published
    // owner head. The unmappable source tail starts after that CAS and cannot
    // enter the arena bitmap branch for singleton geometry.
    let result = unsafe {
        finish_unmapped_after_remote_claim(
            page,
            block,
            &UNMAPPABLE_ABANDONED_PAGES,
            &mut no_test_hook,
            // After the source atomic detach, `_mi_page_free_collect(page,
            // false)` must transfer any owner-local deferred list before the
            // all-free/unabandon decision. The W07 claim still owns the low
            // bit, so this neither consults a departed Theap nor rebuilds
            // page/block authority.
            |page| collect_post_owner_exit_local_free_false(page),
        )
    };
    match result {
        Err(error) => Err(ClaimedPostOwnerExitSingletonFreeFailure {
            owner: claim,
            error,
        }),
        Ok(UnmappedAbandonedFreeResult::Empty) => {
            let release = ClaimedPostOwnerExitSingletonRelease {
                owner: claim,
                memory,
                backing,
            };
            Ok(terminal_release(release))
        }
        Ok(
            UnmappedAbandonedFreeResult::PublishedToExistingOwner
            | UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped,
        ) => Err(ClaimedPostOwnerExitSingletonFreeFailure {
            owner: claim,
            error: AbandonError::MappedPageNotEmpty,
        }),
    }
}

/// Dispatches one pointer-derived free after its source owner has exited.
///
/// `page_state` is the copied ownership classification from the same
/// pointer-to-page lookup that produced `page` and `block`. It is an admission
/// fact, not page ownership: the atomic abandoned-free publication never
/// rejects a stale identity if another source path already owns the low bit.
/// Only a publisher that changes unowned to owned then validates and reads
/// ordinary page state while it holds that bit. Both
/// source abandoned identities enter the same regular-page protocol so a
/// page that changed between ordinary and mapped abandonment after the lookup
/// is governed by its current claimed state rather than by stale geometry.
///
/// A live-owner or detached observation is deliberately rejected before any
/// publication. This mirrors `free.c:mi_free_block_mt`'s
/// `mi_page_is_abandoned` guard: its source identity range ends at
/// `THREAD_ID_ABANDONED_MAPPED`, so `THREAD_ID_DETACHED` is not a legal
/// abandoned-claim input. Its caller must use the corresponding live-owner or
/// detached source path; this boundary never searches an owner registry or
/// exact-client ledger and never guesses a former Theap from `page`.
///
/// # Safety
///
/// `page_state`, `page`, and `block` must come from one current live-allocation
/// observation. The allocation must keep its PageMap entry and page metadata
/// valid until this call has published or completed its claimed collection.
/// The remaining callback obligations are exactly those of
/// [`free_post_owner_exit_regular_page`]. In particular, `terminal_release`
/// may invalidate `page` after returning [`PostOwnerExitTerminalRelease::Released`],
/// and this function performs no later access.
pub(crate) unsafe fn free_post_owner_exit_from_page_state<M, F, C, R>(
    page: NonNull<Page>,
    page_state: LiveAllocationPageState,
    block: NonNull<u8>,
    select_map: F,
    collect_owner_deferred_frees: C,
    terminal_release: R,
) -> Result<PostOwnerExitRegularFreeResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
    R: FnOnce(NonNull<Page>) -> PostOwnerExitTerminalRelease,
{
    if !matches!(
        page_state,
        LiveAllocationPageState::Abandoned | LiveAllocationPageState::AbandonedMapped
    ) {
        return Err(AbandonError::NotAbandoned);
    }

    // SAFETY: the caller supplies the single live-allocation observation and
    // all callback-scoped source authorities required by the regular tail.
    // The inner atomic publication uses only the current head low bit. If it
    // wins that bit, the shared tail validates abandoned identity before it
    // can inspect any ordinary page field.
    unsafe {
        free_post_owner_exit_regular_page(
            page,
            block,
            select_map,
            collect_owner_deferred_frees,
            terminal_release,
        )
    }
}

/// Ports the common normal-collector failed-reclaim tail for one member of a
/// bounded mixed full-medium/full-large aggregate route.
///
/// The pinned source's `BIN_FULL` queue mixes regular page kinds. This helper
/// admits exactly Medium and Large arena members after `push_abandoned` claims
/// the low owner bit. It deliberately does not own the queue traversal, a raw
/// page registry, a terminal release, small/direct-small collection,
/// allocation-time reclaim, or requeue.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of a sequential
/// owner-exit route. `select_map` runs only after the source low-owner claim
/// and must return the exact member's arena/bin capability. The caller retains
/// PageMap, metadata, arena, and terminal span-release ownership across every
/// result; `Empty` retains the page low owner bit for that release.
pub(crate) unsafe fn free_full_medium_or_large_after_failed_reclaim_select_map<M, F>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
) -> Result<FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
{
    // SAFETY: the route owns this stable abandoned page and exact client
    // block through the source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // The successful low-bit claim is the first legal point to select the
    // member's exact bitmap/count capability from its ordinary state.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved <= 1
        || !matches!(
            size_class::page_kind_for_block_size(state.block_size),
            Some(PageKind::Medium | PageKind::Large)
        )
    {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let map = select_map(state.memid, state.block_size)?;
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT || map.bin() != bin || map.page_slice_index(state.memid).is_none() {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    // The source identity, rather than a fresh `used == reserved` check,
    // selects the tail. `MI_ABANDON` proved the aggregate began full before it
    // dropped the old owner; a serial client-free route can move unmapped to
    // mapped once, but never in reverse.
    match source_identity {
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED => {}
        _ => return Err(AbandonError::NotAbandoned),
    }

    // Both regular kinds use the ordinary collector. In particular, this
    // source-shaped shared tail deliberately excludes direct small's retained
    // partial head and its distinct cache image.
    unsafe { remote_free::collect_abandoned(page) }.map_err(AbandonError::RemoteFree)?;
    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            unabandon_mapped(&state, Some(&map))?;
        }
        return Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, &map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free(page, &state, &map, 0, &mut no_test_hook)? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
            }
            UnmappedAbandonedFreeResult::Empty => {
                Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free(page, &state, &map, 0)? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Ports the failed-reclaim tail for one member of a bounded full-medium
/// aggregate route.
///
/// Unlike the sole full-medium route, the aggregate owns no per-page mutable
/// unmapped/mapped state. It uses the abandoned identity held after its
/// low-bit claim to choose the exact source unmapped or mapped tail. The
/// selector receives that now-readable member's arena memory and rounded block
/// size, and must return its exact dynamic-Heap or static-main bitmap/count
/// capability. This does not generalize to another page class, direct small,
/// allocation-time reclaim, or requeue.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of the
/// aggregate route. `select_map` runs only after the source low-owner claim,
/// and must return the exact member's arena/bin capability. The caller must
/// retain PageMap, metadata, arena, and terminal span-release ownership across
/// every result; `Empty` retains the page low owner bit for that release.
pub(crate) unsafe fn free_full_medium_after_failed_reclaim_select_map<M, F>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
) -> Result<FullMediumAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
{
    // SAFETY: the route owns this stable abandoned page and exact client
    // block through the source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // The successful low-bit claim is the first legal point to select the
    // member's exact bitmap/count capability from its ordinary state.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved <= 1
        || size_class::page_kind_for_block_size(state.block_size) != Some(PageKind::Medium)
    {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let map = select_map(state.memid, state.block_size)?;
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT
        || map.bin() != bin
        || map.page_slice_index(state.memid).is_none()
    {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    // The source identity, rather than a fresh `used == reserved` check,
    // selects the tail. `MI_ABANDON` proved the aggregate began full before
    // it dropped the old owner; once a client free has entered the tail, this
    // identity is the route-state discriminator. A serial route can cross
    // from unmapped to mapped once, but never in reverse.
    match source_identity {
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED => {}
        _ => return Err(AbandonError::NotAbandoned),
    }

    // Medium pages use the ordinary collector: direct-small's retained
    // partial head is intentionally out of this source class.
    unsafe { remote_free::collect_abandoned(page) }.map_err(AbandonError::RemoteFree)?;
    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            unabandon_mapped(&state, Some(&map))?;
        }
        return Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, &map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    FullMediumAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    FullMediumAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    FullMediumAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free(page, &state, &map, 0, &mut no_test_hook)? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
            }
            UnmappedAbandonedFreeResult::Empty => {
                Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free(page, &state, &map, 0)? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(FullMediumAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Ports the failed-reclaim tail for one member of the bounded per-member
/// full-large aggregate route.
///
/// Like the per-member full-medium route, this aggregate retains no mutable
/// source bin or mapped/unmapped state for a former-Theap member. It claims
/// the source low owner bit first, then derives that exact large member's
/// arena bitmap/count capability from its now-readable memory and rounded
/// block size. Large blocks remain outside `free.c`'s reclaim-on-free branch;
/// this adds no allocation-time reclaim or requeue authority.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of the
/// aggregate route. `select_map` runs only after the source low-owner claim,
/// and must return that member's exact arena/bin capability. The caller must
/// retain PageMap, metadata, arena, and terminal span-release ownership across
/// every result; `Empty` retains the page low owner bit for that release.
pub(crate) unsafe fn free_full_large_after_failed_reclaim_select_map<M, F>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
) -> Result<FullLargeAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
{
    // SAFETY: the route owns this stable abandoned page and exact client
    // block through the source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // The successful low-bit claim is the first legal point to select the
    // member's exact bitmap/count capability from its ordinary state.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved <= 1
        || size_class::page_kind_for_block_size(state.block_size) != Some(PageKind::Large)
    {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let map = select_map(state.memid, state.block_size)?;
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT
        || map.bin() != bin
        || map.page_slice_index(state.memid).is_none()
    {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    match source_identity {
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED => {}
        _ => return Err(AbandonError::NotAbandoned),
    }

    // Large pages use the ordinary collector. Source `free.c` does not enter
    // its reclaim-on-free branch for blocks above `MI_MEDIUM_MAX_OBJ_SIZE`.
    unsafe { remote_free::collect_abandoned(page) }.map_err(AbandonError::RemoteFree)?;
    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            unabandon_mapped(&state, Some(&map))?;
        }
        return Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, &map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    FullLargeAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free(page, &state, &map, 0, &mut no_test_hook)? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
            }
            UnmappedAbandonedFreeResult::Empty => {
                Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free(page, &state, &map, 0)? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Ports the fixed-geometry failed-reclaim tail retained for one large-page
/// source substrate test or future homogeneous route.
///
/// Like the full-medium aggregate, this route retains no per-page
/// unmapped/mapped state. It uses the abandoned identity held after its
/// low-bit claim to select the exact source tail. Unlike medium, the pinned
/// `free.c` reclaim branch is inapplicable to a large block, so this boundary
/// has no allocation-time reclaim or requeue edge.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of the fixed
/// geometry source substrate. `expected_block_size` and `map` must be its
/// exact large size/bin/arena capability. The caller must retain PageMap,
/// metadata, arena, and terminal span-release ownership across every result;
/// `Empty` retains the page low owner bit for that release. The current
/// per-member aggregate route uses
/// [`free_full_large_after_failed_reclaim_select_map`] instead.
pub(crate) unsafe fn free_full_large_after_failed_reclaim<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    expected_block_size: usize,
    map: &M,
) -> Result<FullLargeAbandonedFreeAfterFailedReclaimResult, AbandonError> {
    // SAFETY: the route owns this stable abandoned page and exact client
    // block through the source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // The successful low-bit claim is the first legal point to read the
    // member's ordinary state. Keep the fixed-geometry source proof explicit so
    // an unrelated PageMap entry cannot silently enter this route.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved <= 1
        || state.block_size != expected_block_size
        || size_class::page_kind_for_block_size(state.block_size) != Some(PageKind::Large)
    {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT
        || map.bin() != bin
        || map.page_slice_index(state.memid).is_none()
    {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    // The source identity, rather than a fresh `used == reserved` check,
    // selects the tail. `MI_ABANDON` proved the aggregate began full before
    // it dropped the old owner; once a client free has entered the tail, this
    // identity is the route-state discriminator. A serial route can cross
    // from unmapped to mapped once, but never in reverse.
    match source_identity {
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED => {}
        _ => return Err(AbandonError::NotAbandoned),
    }

    // Large pages use the ordinary collector. Source `free.c` does not enter
    // its reclaim-on-free branch for blocks above `MI_MEDIUM_MAX_OBJ_SIZE`.
    unsafe { remote_free::collect_abandoned(page) }.map_err(AbandonError::RemoteFree)?;
    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            unabandon_mapped(&state, Some(map))?;
        }
        return Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    FullLargeAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free(page, &state, map, 0, &mut no_test_hook)? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
            }
            UnmappedAbandonedFreeResult::Empty => {
                Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free(page, &state, map, 0)? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Ports the failed-reclaim tail for one member of the bounded per-member
/// full non-direct-small aggregate route.
///
/// This is the normal-collector counterpart to the per-member medium and
/// large routes. A successful low-owner claim is the first legal point to
/// derive the member's ordinary bin and exact abandoned-pages capability;
/// direct small remains excluded by the strict `SMALL_SIZE_MAX` boundary.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of the
/// aggregate route. `select_map` runs only after the source low-owner claim,
/// and must return that member's exact arena/bin capability. The caller must
/// retain PageMap, metadata, arena, and terminal span-release ownership across
/// every result; `Empty` retains the page low owner bit for that release.
pub(crate) unsafe fn free_full_non_direct_small_after_failed_reclaim_select_map<M, F>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
) -> Result<FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
{
    // SAFETY: the aggregate route owns this stable abandoned page and exact
    // client block through the source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(
                FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner,
            );
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // The successful low-bit claim is the first legal point to inspect the
    // member and select its per-member ordinary-bin map.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved <= 1
        || state.block_size <= crate::config::SMALL_SIZE_MAX
        || state.block_size > crate::config::SMALL_MAX_OBJ_SIZE
        || size_class::page_kind_for_block_size(state.block_size) != Some(PageKind::Small)
    {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let map = select_map(state.memid, state.block_size)?;
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT
        || bin == BIN_FULL
        || map.bin() != bin
        || map.page_slice_index(state.memid).is_none()
    {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    match source_identity {
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED => {}
        _ => return Err(AbandonError::NotAbandoned),
    }

    // The source free.c branch is selected by `block_size <=
    // MI_SMALL_SIZE_MAX`, not by PageKind. This class lies above that direct
    // threshold and must not retain a partial collector head.
    unsafe { remote_free::collect_abandoned(page) }.map_err(AbandonError::RemoteFree)?;
    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            unabandon_mapped(&state, Some(&map))?;
        }
        return Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, &map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free(page, &state, &map, 0, &mut no_test_hook)? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
            }
            UnmappedAbandonedFreeResult::Empty => {
                Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free(page, &state, &map, 0)? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Ports the failed-reclaim tail for one member of the bounded homogeneous
/// full non-direct-small aggregate route.
///
/// Its small `PageKind` alone is deliberately insufficient: direct small
/// pages retain a rounded direct-cache image and free.c's partial collector.
/// This helper admits only the complementary ordinary-bin class above
/// `SMALL_SIZE_MAX`, validates that sealed boundary after it claims the source
/// low owner bit, and uses the normal collector through its unmapped/mapped
/// tails.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of the
/// aggregate route. `expected_block_size` and `map` must be the homogeneous
/// source preflight's exact non-direct-small size/bin/arena capability. The
/// caller retains PageMap, metadata, arena, and terminal span-release
/// ownership through every result; `Empty` retains the page low owner bit for
/// that release. This grants no direct-small, allocation-time reclaim, or
/// requeue authority.
pub(crate) unsafe fn free_full_non_direct_small_after_failed_reclaim<
    M: MappedAbandonedPages + ?Sized,
>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    expected_block_size: usize,
    map: &M,
) -> Result<FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult, AbandonError> {
    // SAFETY: the aggregate route owns this stable abandoned page and exact
    // client block through the source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(
                FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner,
            );
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // A successful low-bit claim is the first legal point to inspect ordinary
    // state. Preserve the sealed ordinary-bin/source-size proof here so no
    // direct-small member can silently take the normal collector.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved <= 1
        || state.block_size != expected_block_size
        || state.block_size <= crate::config::SMALL_SIZE_MAX
        || state.block_size > crate::config::SMALL_MAX_OBJ_SIZE
        || size_class::page_kind_for_block_size(state.block_size) != Some(PageKind::Small)
    {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT
        || map.bin() != bin
        || map.page_slice_index(state.memid).is_none()
    {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    match source_identity {
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED => {}
        _ => return Err(AbandonError::NotAbandoned),
    }

    // The source free.c branch is selected by `block_size <=
    // MI_SMALL_SIZE_MAX`, not by PageKind. This class lies above that direct
    // threshold and must not retain a partial collector head.
    unsafe { remote_free::collect_abandoned(page) }.map_err(AbandonError::RemoteFree)?;
    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            unabandon_mapped(&state, Some(map))?;
        }
        return Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free(page, &state, map, 0, &mut no_test_hook)? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
            }
            UnmappedAbandonedFreeResult::Empty => {
                Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free(page, &state, map, 0)? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Ports the failed-reclaim tail for one member of the bounded per-member
/// full direct-small aggregate route.
///
/// Its small `PageKind` alone is deliberately insufficient: this sealed class
/// retains its exact rounded direct-cache image during source owner exit and
/// takes `_mi_page_free_collect_partly` after a later free claims the low owner
/// bit. The retained partial head is carried into both unmapped and mapped
/// unown transitions, preserving free.c's one-free mostly-used lag.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of the
/// aggregate route. `select_map` runs only after the source low-owner claim,
/// and must return that member's exact direct-small arena/bin capability. The
/// caller retains PageMap, metadata, arena, and terminal span-release
/// ownership through every result; `Empty` retains the page low owner bit for
/// that release. This grants no allocation-time reclaim, requeue, or
/// direct-cache ownership.
pub(crate) unsafe fn free_full_direct_small_after_failed_reclaim_select_map<M, F>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    select_map: F,
) -> Result<FullDirectSmallAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages,
    F: FnOnce(MemoryId, usize) -> Result<M, AbandonError>,
{
    // SAFETY: the aggregate route owns this stable abandoned page and exact
    // client block through the source `allow_collect=true` publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // A successful low-bit claim is the first legal point to inspect ordinary
    // state and select that direct-small member's exact bitmap/count
    // capability. Keep the class proof here so a non-direct member cannot
    // silently take free.c's partial collector.
    let state = unsafe { Page::abandonment_state_at(page) };
    let source_identity = source_thread_identity(&state);
    if !is_owned(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved < 16
        || state.block_size > crate::config::SMALL_SIZE_MAX
        || size_class::page_kind_for_block_size(state.block_size) != Some(PageKind::Small)
    {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.memid.kind() != MemoryKind::Arena {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let map = select_map(state.memid, state.block_size)?;
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT
        || bin == BIN_FULL
        || map.bin() != bin
        || map.page_slice_index(state.memid).is_none()
    {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    match source_identity {
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED => {}
        _ => return Err(AbandonError::NotAbandoned),
    }

    // `_mi_page_free_collect_partly` leaves the just-pushed head atomically
    // visible. `mi_abandoned_page_unown_from_free` must therefore use that
    // exact pointer rather than the normal collector's zero head.
    let expected_head = block.as_ptr().expose_provenance();
    unsafe { remote_free::collect_abandoned_partly(page, block) }
        .map_err(AbandonError::RemoteFree)?;
    if page_is_empty(&state) {
        if source_identity == THREAD_ID_ABANDONED_MAPPED {
            unabandon_mapped(&state, Some(&map))?;
        }
        return Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty);
    }

    if source_identity == THREAD_ID_ABANDONED {
        if let Some(result) = terminal_or_reabandon_unmapped(page, &state, &map)? {
            return Ok(match result {
                UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                    FullDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner
                }
                UnmappedAbandonedFreeResult::Empty => {
                    FullDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty
                }
                UnmappedAbandonedFreeResult::ReabandonedMapped
                | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                    FullDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive
                }
            });
        }
        let mut no_test_hook: Option<fn()> = None;
        return match unown_unmapped_from_free(page, &state, &map, expected_head, &mut no_test_hook)? {
            UnmappedAbandonedFreeResult::PublishedToExistingOwner => {
                Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
            }
            UnmappedAbandonedFreeResult::Empty => {
                Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty)
            }
            UnmappedAbandonedFreeResult::ReabandonedMapped
            | UnmappedAbandonedFreeResult::UnownedUnmapped => {
                Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
            }
        };
    }

    match unown_mapped_from_free(page, &state, &map, expected_head)? {
        MappedAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner => {
            Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::PublishedToExistingOwner)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::Empty => {
            Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty)
        }
        MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped => {
            Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
        }
    }
}

/// Ports the failed-reclaim tail for one member of the bounded homogeneous
/// full direct-small substrate route.
///
/// The aggregate route uses
/// [`free_full_direct_small_after_failed_reclaim_select_map`] so it can select
/// each member's exact map after its low-owner claim. This fixed-geometry
/// wrapper preserves the existing sole-page callers and focused substrate
/// tests without widening their source boundary.
///
/// # Safety
///
/// `page` and `block` must be one exact live member/allocation of the fixed
/// source geometry. `expected_block_size` and `map` must be that geometry's
/// exact direct-small size/bin/arena capability. The caller retains PageMap,
/// metadata, arena, and terminal span-release ownership through every result.
pub(crate) unsafe fn free_full_direct_small_after_failed_reclaim<
    M: MappedAbandonedPages + ?Sized,
>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    expected_block_size: usize,
    map: &M,
) -> Result<FullDirectSmallAbandonedFreeAfterFailedReclaimResult, AbandonError> {
    // SAFETY: this wrapper preserves the fixed source proof and delegates the
    // shared low-owner/partial-collector tail to the per-member selector.
    unsafe {
        free_full_direct_small_after_failed_reclaim_select_map(page, block, |_, block_size| {
            if block_size == expected_block_size {
                Ok(map)
            } else {
                Err(AbandonError::InvalidPageGeometry)
            }
        })
    }
}

/// Ports the failed-reclaim tail for a source-unmappable abandoned page, such
/// as the one-block singleton used by the bounded thread-exit lifecycle.
///
/// Unlike [`free_unmapped_after_failed_reclaim`], this boundary has no
/// arena-bitmap capability because source `bin >= ARENA_BIN_COUNT` makes
/// reabandonment impossible. The private sentinel makes any accidental
/// attempt to use it for a mappable regular arena page fail before it can
/// publish a substitute bitmap bit.
///
/// # Safety
///
/// The caller must meet [`free_unmapped_after_failed_reclaim`]'s page/block
/// lifetime and failed-reclaim obligations, and additionally prove that this
/// page is not eligible for `pages_abandoned[bin]` publication.
pub(crate) unsafe fn free_unmappable_after_failed_reclaim(
    page: NonNull<Page>,
    block: NonNull<u8>,
) -> Result<UnmappedAbandonedFreeResult, AbandonError> {
    // SAFETY: the caller supplies the same stable source abandoned-page proof;
    // the private marker rejects any unexpected mapped-publication branch.
    unsafe {
        free_unmapped_after_failed_reclaim(page, block, &UNMAPPABLE_ABANDONED_PAGES)
    }
}

/// Testable inner form of [`free_unmapped_after_failed_reclaim`]. The hook is
/// a deterministic source interleaving point after its expected small-page
/// head is captured and before the AcqRel unown CAS. Production supplies no
/// hook; this exists only to prove the failed-CAS collection tail.
#[cfg(test)]
unsafe fn free_unmapped_after_failed_reclaim_with<M, F, C>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
    before_expected_cas: F,
    collect_owner_deferred_frees: C,
) -> Result<UnmappedAbandonedFreeResult, AbandonError>
where
    M: MappedAbandonedPages + ?Sized,
    F: FnOnce(),
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
{
    let mut before_expected_cas = Some(before_expected_cas);
    // SAFETY: the test fixture provides the same stable page/block/map proof
    // as the production entry and publishes only at this exact atomic point.
    unsafe {
        free_unmapped_after_failed_reclaim_inner(
            page,
            block,
            map,
            &mut before_expected_cas,
            collect_owner_deferred_frees,
        )
    }
}

unsafe fn free_unmapped_after_failed_reclaim_inner<M, F, C>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
    before_expected_cas: &mut Option<F>,
    collect_owner_deferred_frees: C,
) -> Result<UnmappedAbandonedFreeResult, AbandonError>
where
    M: MappedAbandonedPages + ?Sized,
    F: FnOnce(),
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
{
    // SAFETY: the caller retains the initialized abandoned page and exact
    // client block through the source atomic publication.
    match unsafe { remote_free::push_abandoned(page, block) }.map_err(AbandonError::RemoteFree)? {
        remote_free::AbandonedRemotePush::PublishedToExistingOwner => {
            return Ok(UnmappedAbandonedFreeResult::PublishedToExistingOwner);
        }
        remote_free::AbandonedRemotePush::ClaimedUnownedPage => {}
    }

    // SAFETY: the source publication above changed an unowned remote head
    // into an owned head. Continue after that CAS without linking `block` a
    // second time.
    unsafe {
        finish_unmapped_after_remote_claim(
            page,
            block,
            map,
            before_expected_cas,
            collect_owner_deferred_frees,
        )
    }
}

/// Continues the source-unmapped post-owner-exit tail after a remote
/// publication already acquired the abandoned low owner bit.
///
/// This is exactly the post-CAS portion of
/// [`free_unmapped_after_failed_reclaim_inner`]. Keeping it separate lets the
/// pointer-first live-free path move its linear claim directly into the
/// singleton terminal tail without republishing the same block.
///
/// # Safety
///
/// The caller must own the low `xthread_free` bit acquired by publication of
/// this exact `block`, retain the complete initialized page/block area, and
/// satisfy the map and test-hook obligations of
/// [`free_unmapped_after_failed_reclaim_inner`].
unsafe fn finish_unmapped_after_remote_claim<M, F, C>(
    page: NonNull<Page>,
    block: NonNull<u8>,
    map: &M,
    before_expected_cas: &mut Option<F>,
    mut collect_owner_deferred_frees: C,
) -> Result<UnmappedAbandonedFreeResult, AbandonError>
where
    M: MappedAbandonedPages + ?Sized,
    F: FnOnce(),
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
{

    // A successful `allow_collect` publication owns the low bit. Validate the
    // unmapped source identity before any ordinary page state is observed.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED {
        return Err(AbandonError::NotAbandoned);
    }
    if state.reserved == 0 || state.block_size == 0 {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if state.block_size <= crate::config::SMALL_SIZE_MAX && state.reserved < 16 {
        return Err(AbandonError::InvalidPageGeometry);
    }

    // `_mi_page_free_collect_partly` leaves its just-published head in the
    // atomic list. The expected-head CAS below must use that exact address;
    // the full collector has detached the list and therefore expects zero.
    let expected_head = if state.block_size <= crate::config::SMALL_SIZE_MAX {
        block.as_ptr().expose_provenance()
    } else {
        0
    };
    if state.block_size <= crate::config::SMALL_SIZE_MAX {
        // SAFETY: the source small-page geometry and just-published head were
        // validated above; the caller retains all predecessor block lifetime.
        unsafe { remote_free::collect_abandoned_partly(page, block) }
    } else {
        // SAFETY: this caller owns the abandoned low bit and stable metadata.
        unsafe { remote_free::collect_abandoned(page) }
    }
    .map_err(AbandonError::RemoteFree)?;

    // The atomic collector transfers its detached head into `local_free`.
    // Before source empty/reabandon/unown selection,
    // `_mi_page_free_collect(page, false)` performs the owner-local half.
    // The claim-bearing singleton continuation supplies that exact false
    // transfer; legacy raw callers make their preserved no-op explicit.
    collect_owner_deferred_frees(page)?;

    if let Some(result) = terminal_or_reabandon_unmapped(page, &state, map)? {
        return Ok(result);
    }
    unown_unmapped_from_free_with_owner_deferred_collection(
        page,
        &state,
        map,
        expected_head,
        before_expected_cas,
        &mut collect_owner_deferred_frees,
    )
}

/// Ports `page.c:_mi_page_abandon` and the mapped/unmapped publication half
/// of `arena.c:_mi_arenas_page_abandon` for one already queue-detached page.
///
/// A regular arena page becomes `ABANDONED_MAPPED`, publishes exactly one bit,
/// and only then releases the low `xthread_free` ownership bit. Full,
/// singleton, and non-arena pages retain the ordinary `ABANDONED` identity and
/// are not published into an arena bitmap. Empty pages are deliberately
/// returned as [`AbandonResult::Empty`] rather than released because terminal
/// free/reuse is outside this bounded slice.
///
/// # Safety
///
/// `page` must be initialized, live, queue-detached, and uniquely owned by
/// this caller through entry. Its `theap` pointer, memory provenance, and all
/// block metadata must remain live through the transition. Remote producers
/// may retain only their atomic source projection and each must eventually be
/// collected or become the next low-bit owner. When `map` is supplied, it must
/// be the initialized source `pages_abandoned[bin]` map capability for this
/// page's exact live arena, whether it is the arena main image or one bound
/// non-main Heap image; no page metadata may be released or reused while the
/// returned state can be observed.
pub(crate) unsafe fn abandon<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    map: Option<&M>,
) -> Result<AbandonResult, AbandonError> {
    // SAFETY: caller supplies the owner/lifetime proof for the pre-abandon
    // collection. It validates the live associated identity before ordinary
    // local state is touched.
    let owner = unsafe { Page::remote_free_owner_state_at(page) }
        .ok_or(AbandonError::NotAbandoned)?;
    unsafe { remote_free::collect(owner) }.map_err(AbandonError::RemoteFree)?;
    // SAFETY: caller retains the page lifecycle proof and has collected the
    // pre-abandon remote list. This projects raw fields only.
    unsafe { abandon_after_collect(page, map) }
}

/// The identity/publication half of [`abandon`] after the caller has already
/// performed exact false-force collection.
///
/// This lets the page engine retain source order (`remote` then `local`, then
/// queue detach, then arena-map publication) without re-running the remote
/// detach through the older stand-alone substrate.
///
/// # Safety
///
/// `page` has the same stable, uniquely owned, queue-detached lifecycle proof
/// as [`abandon`], and the caller has just completed the false-force local
/// collection. No raw page lease may be released or repurposed through this
/// transition.
pub(crate) unsafe fn abandon_after_collect<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    map: Option<&M>,
) -> Result<AbandonResult, AbandonError> {
    // SAFETY: this plain form has no source-specific publication between
    // identity/map publication and the shared abandoned-owner unown loop.
    unsafe { abandon_after_collect_with_before_unown(page, map, || Ok(())) }
}

/// The identity/publication half of [`abandon`] with one source-specific
/// publication boundary before the common abandoned-owner unown loop.
///
/// Pinned `page.c:_mi_page_abandon` establishes abandoned identity before it
/// delegates to `arena.c:_mi_arenas_page_abandon`. That branch may publish the
/// mapped bitmap/count pair or an exact non-arena OS-list member, and only
/// then may `mi_abandoned_page_unown` clear the owner bit. `before_unown`
/// models the latter publication and must not release, reuse, or reclassify
/// the page while it still owns the source low bit.
///
/// # Safety
///
/// `page` has the same proof as [`abandon_after_collect`]. In addition,
/// `before_unown` must preserve initialized metadata and the raw originating
/// Theap identity through its return. It may expose the page only through the
/// matching source process structure once the abandoned identity and low owner
/// bit are both established.
pub(crate) unsafe fn abandon_after_collect_with_before_unown<
    M: MappedAbandonedPages + ?Sized,
    F: FnOnce() -> Result<(), AbandonError>,
>(
    page: NonNull<Page>,
    map: Option<&M>,
    before_unown: F,
) -> Result<AbandonResult, AbandonError> {
    // SAFETY: caller retains the page lifecycle proof and has collected the
    // pre-abandon remote list. This projects raw fields only.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || !is_live_associated(&state) {
        return Err(AbandonError::NotOwnedAssociated);
    }
    if state.reserved == 0 || state.block_size == 0 {
        return Err(AbandonError::InvalidPageGeometry);
    }
    if page_is_empty(&state) {
        return Ok(AbandonResult::Empty);
    }

    // `arena.c` computes a size-class bin before it publishes. The main
    // abandoned map deliberately ends at `MI_MAX_SINGLETON_BIN`: partially
    // used arena singleton/huge-bin pages are left unmapped for a free to
    // reclaim, just like non-arena and full pages.
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    let mapped_bin = (!page_is_full(&state) && state.memid.kind() == MemoryKind::Arena)
        .then_some(bin)
        .filter(|&bin| bin < ARENA_BIN_COUNT);
    let mapped_slice = if let Some(bin) = mapped_bin {
        let map = map.ok_or(AbandonError::MissingMappedArenaBitmap)?;
        if bin != map.bin() {
            return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
        }
        let slice_index = map
            .page_slice_index(state.memid)
            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)?;
        if !map.is_clear(slice_index) {
            return Err(AbandonError::MappedBitAlreadyPublished);
        }
        Some((map, slice_index))
    } else {
        None
    };

    set_abandoned_identity(&state);
    if let Some((map, slice_index)) = mapped_slice {
        // Source order is significant: readers can only use a published bit
        // after the mapped abandoned identity exists.
        unsafe { state.xthread_id.as_ref() }
            .fetch_or(THREAD_ID_ABANDONED_MAPPED, Ordering::Relaxed);
        if !map.publish(slice_index) {
            // The identity has already changed. Callers must retain this as
            // terminal rather than retrying from a fictionally live page.
            return Err(AbandonError::MappedPublicationFailed);
        }
    }
    before_unown()?;
    unown(page, map)
}

/// Abandons a source-unmappable page after its owner has completed the exact
/// false-force collection and queue detach. This is the companion to
/// [`free_unmappable_after_failed_reclaim`] for source-currently-unmappable
/// thread-exit pages. That includes full regular pages: even when their
/// size-class bin could later be mapped, `arena.c` deliberately leaves them
/// unmapped until a failed-reclaim free crosses the mostly-used predicate. A
/// nonfull mappable regular arena page is rejected rather than silently
/// skipping its required bitmap publication.
///
/// # Safety
///
/// The caller must meet [`abandon_after_collect`]'s detached-page and stable
/// metadata obligations, and prove that the page is currently source-unmappable
/// (for example, because it is full) rather than a nonfull mappable regular
/// arena page.
pub(crate) unsafe fn abandon_unmappable_after_collect(
    page: NonNull<Page>,
) -> Result<AbandonResult, AbandonError> {
    // SAFETY: this plain source-unmappable form has no OS-list publication
    // boundary to preserve.
    unsafe { abandon_unmappable_after_collect_with_before_unown(page, || Ok(())) }
}

/// Source-unmappable [`abandon_after_collect_with_before_unown`] form for an
/// exact non-arena publication such as `heap->os_abandoned_pages`.
///
/// # Safety
///
/// The caller must meet [`abandon_unmappable_after_collect`]'s source-state
/// proof and the additional pre-unown publication obligations above.
pub(crate) unsafe fn abandon_unmappable_after_collect_with_before_unown<
    F: FnOnce() -> Result<(), AbandonError>,
>(
    page: NonNull<Page>,
    before_unown: F,
) -> Result<AbandonResult, AbandonError> {
    // SAFETY: the caller provides the queue-detached, false-force-collected
    // source state; the private marker blocks an accidental mapped route.
    unsafe {
        abandon_after_collect_with_before_unown(
            page,
            Some(&UNMAPPABLE_ABANDONED_PAGES),
            before_unown,
        )
    }
}

/// Searches one source `pages_abandoned[bin]` map and claims/reassociates the
/// first resolver-provided page that remains mapped-abandoned and unowned.
///
/// The resolver is intentionally explicit so each arena-page owner supplies
/// its own exact slice-to-metadata boundary. It must resolve an exact bitmap
/// slice to its stable `Page` metadata. On a failed low-bit ownership claim,
/// the shared bitmap primitive restores the bit before returning, which is
/// the required `arena.c:655-671` quiescence handoff to a concurrent
/// `unabandon`.
///
/// # Safety
///
/// `target_theap` and every page yielded by `resolve` must remain initialized
/// and address-stable. `target_thread` must be the live identity of
/// `target_theap`. Each resolved page must be live mapped-abandoned metadata
/// for that exact map slice; the caller must ensure it cannot be released or
/// reused while the map reader or returned [`AdoptedPage`] exists. No resolver
/// may create a `&mut Page` concurrent with a producer atomic projection.
#[cfg(test)]
unsafe fn try_adopt<M: MappedAbandonedPages + ?Sized, F>(
    map: &M,
    thread_sequence: usize,
    target_theap: NonNull<Theap>,
    target_thread: LiveThreadId,
    resolve: F,
) -> Result<Option<AdoptedPage>, AbandonError>
where
    F: FnMut(usize) -> Option<NonNull<Page>>,
{
    unsafe {
        try_adopt_with(
            map,
            thread_sequence,
            target_theap,
            target_thread,
            resolve,
            || {},
            || {},
        )
    }
}

/// Retained-error form of [`try_adopt`] for a consuming page-engine handoff.
///
/// Unlike the earlier substrate helper, a failure after successful bitmap/low
/// owner claim is not compressed into a bare error: its caller must retain the
/// exact page until an explicit later terminal policy exists.
///
/// # Safety
///
/// `target_theap` and every page yielded by `resolve` must remain initialized
/// and address-stable. `target_thread` must be the live identity of
/// `target_theap`. Each resolved page must be live mapped-abandoned metadata
/// for that exact map slice. The caller must keep its complete
/// `reserved * block_size` area writable and unreleased through the source
/// false-force collection below; no producer may mutate ordinary page fields
/// during that transfer. It must likewise prevent page reuse or release while
/// the returned [`AdoptedPage`] exists.
pub(crate) unsafe fn try_adopt_retained<M: MappedAbandonedPages + ?Sized, F>(
    map: &M,
    thread_sequence: usize,
    target_theap: NonNull<Theap>,
    target_thread: LiveThreadId,
    mut resolve: F,
) -> Result<Option<AdoptedPage>, RetainedAdoptFailure>
where
    F: FnMut(usize) -> Option<NonNull<Page>>,
{
    let mut claimed_page = None;
    let claimed = map.try_claim(thread_sequence, |slice_index| {
        let Some(page) = resolve(slice_index) else {
            return AbandonedBitmapClaim::KeepSet;
        };
        // SAFETY: resolver proves the atomic abandoned owner field is live;
        // no ordinary state is inspected before the AcqRel owner claim.
        let state = unsafe { Page::abandonment_atomic_state_at(page) };
        if remote_free::claim_abandoned_owner(unsafe { state.xthread_free.as_ref() })
            == AbandonedOwnerClaim::AlreadyOwned
        {
            return AbandonedBitmapClaim::KeepSet;
        }
        claimed_page = Some(page);
        AbandonedBitmapClaim::Claimed
    });
    let page = match claimed {
        MappedAbandonedClaim::None => return Ok(None),
        MappedAbandonedClaim::Claimed(_) => {
            claimed_page.expect("a claimed abandoned bitmap bit records its page")
        }
        MappedAbandonedClaim::CountDecrementFailed(_) => {
            return Err(RetainedAdoptFailure {
                page: claimed_page.expect("a claimed bitmap bit records its page before counting"),
                error: AbandonError::AbandonedCountDecrementFailed,
            });
        }
    };
    let fail = |error| RetainedAdoptFailure { page, error };

    // Source arena claim first drains while the page retains its abandoned
    // identity, then page reclaim reassociates and completes its live
    // false-force collection before queue insertion.
    let abandoned_collected = match unsafe { remote_free::collect_abandoned(page) } {
        Ok(collected) => collected,
        Err(error) => return Err(fail(AbandonError::RemoteFree(error))),
    };
    // SAFETY: the successful low-bit claim permits ordinary-state projection.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED_MAPPED {
        return Err(fail(AbandonError::NotAbandoned));
    }
    // SAFETY: source `_mi_theap_page_reclaim` writes the target before its
    // second collection; caller's consuming handoff keeps both owners live.
    unsafe { ptr::write(state.theap.as_ptr(), target_theap.as_ptr()) };
    set_thread_identity(&state, target_thread.get());
    let owner = unsafe { Page::remote_free_owner_state_at(page) }
        .ok_or_else(|| fail(AbandonError::NotAbandoned))?;
    let collected = match unsafe { remote_free::collect(owner) } {
        Ok(collected) => collected,
        Err(error) => return Err(fail(AbandonError::RemoteFree(error))),
    };
    // `_mi_page_free_collect(page, false)` completes the remote detach with
    // the non-forcing local transfer. The target thread identity and held low
    // owner bit prove this narrow raw projection without manufacturing a
    // whole-page mutable borrow.
    let local = match unsafe { Page::local_collect_state_for_owner_at(page, Some(target_thread)) }
    {
        Some(local) => local,
        None => return Err(fail(AbandonError::InvalidPageGeometry)),
    };
    // SAFETY: `local` describes the same live target-owned page after source
    // remote collection. The consuming adoption retains its complete page
    // area and all ordinary-field mutation authority through this transfer.
    if let Err(error) = unsafe { free_list::collect_local_false(local) } {
        return Err(fail(AbandonError::LocalFree(error)));
    }
    Ok(Some(AdoptedPage {
        page,
        collected_remote_blocks: abandoned_collected + collected,
    }))
}

/// Testable inner form of [`try_adopt`]. The source algorithm has no callback;
/// this private one-shot hook exists only to deterministically publish a
/// remote free at each source interleaving: after the low ownership claim,
/// and after abandoned-owner collection but before reassociation.
#[cfg(test)]
unsafe fn try_adopt_with<M: MappedAbandonedPages + ?Sized, F, H, I>(
    map: &M,
    thread_sequence: usize,
    target_theap: NonNull<Theap>,
    target_thread: LiveThreadId,
    mut resolve: F,
    after_claim: H,
    after_abandoned_collection: I,
) -> Result<Option<AdoptedPage>, AbandonError>
where
    F: FnMut(usize) -> Option<NonNull<Page>>,
    H: FnOnce(),
    I: FnOnce(),
{
    let mut claimed_page = None;
    let claimed = map.try_claim(thread_sequence, |slice_index| {
        let Some(page) = resolve(slice_index) else {
            return AbandonedBitmapClaim::KeepSet;
        };
        // SAFETY: resolver/caller prove stable initialized metadata. Before
        // the low-bit OR succeeds, this deliberately projects only that one
        // atomic word and reads no identity/provenance/ordinary state.
        let state = unsafe { Page::abandonment_atomic_state_at(page) };
        // `mi_page_claim_ownership`: the old value identifies whether a
        // concurrent free won. The AcqRel operation is the sole ownership
        // claim; ordinary fields remain untouched on failure.
        let claim = remote_free::claim_abandoned_owner(unsafe { state.xthread_free.as_ref() });
        if claim == AbandonedOwnerClaim::AlreadyOwned {
            return AbandonedBitmapClaim::KeepSet;
        }
        // SAFETY: success acquired the source owner bit. The resolver's
        // unsafe contract guarantees this exact bitmap slice/page relation;
        // use debug assertions for source-internal consistency only after
        // ownership makes ordinary fields readable.
        let state = unsafe { Page::abandonment_state_at(page) };
        debug_assert_eq!(map.page_slice_index(state.memid), Some(slice_index));
        debug_assert_eq!(source_thread_identity(&state), THREAD_ID_ABANDONED_MAPPED);
        claimed_page = Some(page);
        AbandonedBitmapClaim::Claimed
    });

    let page = match claimed {
        MappedAbandonedClaim::None => return Ok(None),
        MappedAbandonedClaim::Claimed(_) => {
            claimed_page.expect("a claimed abandoned bitmap bit records its page")
        }
        MappedAbandonedClaim::CountDecrementFailed(_) => {
            return Err(AbandonError::AbandonedCountDecrementFailed);
        }
    };
    after_claim();
    // `arena.c:_mi_arenas_try_find_abandoned` first drains an abandoned
    // owner's remote list while it still carries the abandoned identity.
    // A later `_mi_theap_page_reclaim` installs the target Theap and performs
    // the normal live-owner collection again before queue insertion.
    let abandoned_collected = unsafe { remote_free::collect_abandoned(page) }
        .map_err(AbandonError::RemoteFree)?;
    after_abandoned_collection();
    // SAFETY: the successful AcqRel OR acquired the only source owner bit;
    // map success retained the bit clear, so no alternate reader can adopt it.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || source_thread_identity(&state) != THREAD_ID_ABANDONED_MAPPED {
        return Err(AbandonError::NotAbandoned);
    }
    // `_mi_theap_page_reclaim` calls `mi_page_set_theap` before collection.
    // It retains all low page flags through the Release weak-CAS loop.
    unsafe { ptr::write(state.theap.as_ptr(), target_theap.as_ptr()) };
    set_thread_identity(&state, target_thread.get());
    // SAFETY: reassociation installs a live owner identity and the caller's
    // page lifetime proof still covers every published remote block.
    let owner = unsafe { Page::remote_free_owner_state_at(page) }
        .ok_or(AbandonError::NotAbandoned)?;
    let collected = unsafe { remote_free::collect(owner) }.map_err(AbandonError::RemoteFree)?;
    Ok(Some(AdoptedPage {
        page,
        collected_remote_blocks: abandoned_collected + collected,
    }))
}

fn unown<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    map: Option<&M>,
) -> Result<AbandonResult, AbandonError> {
    unown_with(page, map, || {
        #[cfg(test)]
        test_publish_owner_exit_remote_free_before_unown(page);
    })
}

#[cfg(test)]
struct OwnerExitLateRemoteFreeInjection {
    producer: remote_free::OwnerExitUnownRemoteFreeInjection,
}

#[cfg(test)]
#[thread_local]
static mut OWNER_EXIT_LATE_REMOTE_FREE_INJECTION: Option<OwnerExitLateRemoteFreeInjection> = None;

/// Installs the deterministic producer interleaving used by the production
/// owner-exit regression. The callback fires after source unown observed an
/// empty remote head and before its weak release CAS.
///
/// # Safety
///
/// `producer` must come from one exact still-live owner-scoped client and
/// remain pending only until the current thread consumes it during
/// abandonment.
#[cfg(test)]
pub(crate) unsafe fn test_inject_owner_exit_remote_free_before_unown(
    producer: remote_free::OwnerExitUnownRemoteFreeInjection,
) -> bool {
    // SAFETY: this compiler-TLS slot is reachable only by the current test
    // thread, which retains the page engine until the injection is consumed.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(OWNER_EXIT_LATE_REMOTE_FREE_INJECTION) };
    if slot.is_some() {
        return false;
    }
    *slot = Some(OwnerExitLateRemoteFreeInjection { producer });
    true
}

#[cfg(test)]
fn test_publish_owner_exit_remote_free_before_unown(page: NonNull<Page>) {
    // SAFETY: this compiler-TLS slot is reachable only by the current test
    // thread. A nonmatching abandonment leaves the injection for its exact
    // page later in the same generic queue traversal.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(OWNER_EXIT_LATE_REMOTE_FREE_INJECTION) };
    let Some(injection) = slot.take() else { return };
    // SAFETY: the matching unown caller retains its initialized page while
    // the test token retains only the disjoint producer projection.
    if !unsafe { injection.producer.matches_page(page) } {
        *slot = Some(injection);
        return;
    }
    assert_eq!(
        unsafe { injection.producer.publish_after_unown_observation() },
        Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner),
        "the deterministic late producer observes the source owner bit",
    );
}

/// Source `mi_abandoned_page_unown` loop with its sole interleaving point
/// factored for a deterministic protocol regression. The production caller
/// supplies no hook; it exists only so the test can publish exactly between
/// the empty-head observation and the weak CAS.
fn unown_with<M: MappedAbandonedPages + ?Sized, F>(
    page: NonNull<Page>,
    map: Option<&M>,
    before_release_cas: F,
) -> Result<AbandonResult, AbandonError>
where
    F: FnOnce(),
{
    // SAFETY: callers preserve page lifetime; this produces raw field pointers
    // only and the low owner bit below authorizes ordinary-state access.
    let state = unsafe { Page::abandonment_state_at(page) };
    if !is_owned(&state) || !is_abandoned(&state) {
        return Err(AbandonError::NotAbandoned);
    }
    let xthread_free = unsafe { state.xthread_free.as_ref() };
    let mut before_release_cas = Some(before_release_cas);
    loop {
        match remote_free::try_unown_abandoned_head(xthread_free, &mut before_release_cas) {
            AbandonedOwnerHeadTransition::Released => return Ok(if source_thread_identity(&state) == THREAD_ID_ABANDONED_MAPPED {
                AbandonResult::UnownedMapped
            } else {
                AbandonResult::UnownedUnmapped
            }),
            AbandonedOwnerHeadTransition::RemotePublished(_) => {
                // SAFETY: this caller still holds the owner bit and the
                // abandoned-page lifetime proof; collection touches only
                // owner fields.
                unsafe { remote_free::collect_abandoned(page) }
                    .map_err(AbandonError::RemoteFree)?;
                if page_is_empty(&state) {
                    unabandon_mapped(&state, map)?;
                    return Ok(AbandonResult::Empty);
                }
            }
            AbandonedOwnerHeadTransition::NotOwned => {
                return Err(AbandonError::NotOwnedAssociated);
            }
        }
    }
}

/// The mapped-page form of `mi_abandoned_page_unown_from_free` after source
/// free-triggered reclaim has failed. It intentionally has no reabandon arm:
/// this page already owns its exact `pages_abandoned[bin]` publication.
fn unown_mapped_from_free<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    state: &PageAbandonmentState,
    map: &M,
    expected_head: usize,
) -> Result<MappedAbandonedFreeAfterFailedReclaimResult, AbandonError> {
    // Older raw failed-reclaim helpers preserve their existing bounded
    // collection contract. The claim-bearing pointer continuation below
    // supplies the source false-force owner-local phase after every remote
    // detach.
    let mut no_owner_deferred_collection = |_page| Ok(());
    unown_mapped_from_free_with_owner_deferred_collection(
        page,
        state,
        map,
        expected_head,
        &mut no_owner_deferred_collection,
    )
}

/// The mapped `mi_abandoned_page_unown_from_free` loop for a continuation
/// that owns the false-force local collection capability.
///
/// A failed expected-head CAS can reveal another producer's remote list. The
/// source calls `_mi_page_free_collect(page, false)` after *each* such
/// observation, so this helper makes the local half explicit before it may
/// test all-free or transfer the mapped abandoned owner bit again.
fn unown_mapped_from_free_with_owner_deferred_collection<M, C>(
    page: NonNull<Page>,
    state: &PageAbandonmentState,
    map: &M,
    mut expected_head: usize,
    collect_owner_deferred_frees: &mut C,
) -> Result<MappedAbandonedFreeAfterFailedReclaimResult, AbandonError>
where
    M: MappedAbandonedPages + ?Sized,
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
{
    let xthread_free = unsafe { state.xthread_free.as_ref() };
    let mut no_test_hook: Option<fn()> = None;
    loop {
        match remote_free::try_unown_abandoned_expected_head(
            xthread_free,
            expected_head,
            &mut no_test_hook,
        )
        .map_err(AbandonError::RemoteFree)?
        {
            remote_free::AbandonedExpectedHeadTransition::Released => {
                return Ok(MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped);
            }
            remote_free::AbandonedExpectedHeadTransition::OwnedEmpty => {
                // A weak CAS may fail spuriously, or a concurrent collector
                // can leave the source-owned empty word. The source retries
                // against its ordinary null expected head.
                expected_head = 0;
            }
            remote_free::AbandonedExpectedHeadTransition::RemotePublished => {
                // SAFETY: the failed expected-head CAS still observed the
                // held source owner bit. The mapped page remains stable and
                // its producer list is the only permitted concurrent input.
                unsafe { remote_free::collect_abandoned(page) }
                    .map_err(AbandonError::RemoteFree)?;
                // `mi_abandoned_page_unown_from_free` returns through
                // `_mi_page_free_collect(page, false)`, not through a remote
                // detach alone. Keep the source local phase before the
                // all-free decision so a later publication cannot bypass it.
                collect_owner_deferred_frees(page)?;
                if page_is_empty(state) {
                    unabandon_mapped(state, Some(map))?;
                    return Ok(MappedAbandonedFreeAfterFailedReclaimResult::Empty);
                }
                // Pinned source does not retry reclamation after this
                // conflict; it only retries ownership release.
                expected_head = 0;
            }
            remote_free::AbandonedExpectedHeadTransition::NotOwned => {
                return Err(AbandonError::NotOwnedAssociated);
            }
        }
    }
}

/// Ports `mi_abandoned_page_unown_from_free` after its one reclaim attempt
/// has already failed. Its first CAS preserves the small partial collector's
/// head; only a failed CAS takes the source full-collection decision loop.
fn unown_unmapped_from_free<M, F>(
    page: NonNull<Page>,
    state: &PageAbandonmentState,
    map: &M,
    expected_head: usize,
    before_expected_cas: &mut Option<F>,
) -> Result<UnmappedAbandonedFreeResult, AbandonError>
where
    M: MappedAbandonedPages + ?Sized,
    F: FnOnce(),
{
    // Keep older raw helpers source-compatible without widening their caller
    // contracts. Claim-bearing pointer continuations use the sibling below,
    // which cannot omit the false-force local phase after a raced detach.
    let mut no_owner_deferred_collection = |_page| Ok(());
    unown_unmapped_from_free_with_owner_deferred_collection(
        page,
        state,
        map,
        expected_head,
        before_expected_cas,
        &mut no_owner_deferred_collection,
    )
}

/// The source-unmapped expected-head unown loop with its reusable
/// false-force owner-local collection capability.
fn unown_unmapped_from_free_with_owner_deferred_collection<M, F, C>(
    page: NonNull<Page>,
    state: &PageAbandonmentState,
    map: &M,
    mut expected_head: usize,
    before_expected_cas: &mut Option<F>,
    collect_owner_deferred_frees: &mut C,
) -> Result<UnmappedAbandonedFreeResult, AbandonError>
where
    M: MappedAbandonedPages + ?Sized,
    F: FnOnce(),
    C: FnMut(NonNull<Page>) -> Result<(), AbandonError>,
{
    let xthread_free = unsafe { state.xthread_free.as_ref() };
    loop {
        match remote_free::try_unown_abandoned_expected_head(
            xthread_free,
            expected_head,
            before_expected_cas,
        )
        .map_err(AbandonError::RemoteFree)?
        {
            remote_free::AbandonedExpectedHeadTransition::Released => {
                return Ok(UnmappedAbandonedFreeResult::UnownedUnmapped);
            }
            remote_free::AbandonedExpectedHeadTransition::OwnedEmpty => {
                // A weak CAS may fail spuriously, or a concurrent collector
                // may have left the source-owned empty word. `free.c` retries
                // with a null expected head in either case.
                expected_head = 0;
            }
            remote_free::AbandonedExpectedHeadTransition::RemotePublished => {
                // SAFETY: the failed CAS still observed the source owner bit;
                // this caller owns ordinary fields until it transfers that
                // bit through the next decision below.
                unsafe { remote_free::collect_abandoned(page) }
                    .map_err(AbandonError::RemoteFree)?;
                // Source `_mi_page_free_collect(page, false)` repeats its
                // local half after every raced remote detach before it can
                // free, reabandon, or retry unownership.
                collect_owner_deferred_frees(page)?;
                if let Some(result) = terminal_or_reabandon_unmapped(page, state, map)? {
                    return Ok(result);
                }
                // The source reloads its now-empty owned head before retrying
                // and never revisits reclaim after this conflict path.
                expected_head = 0;
            }
            remote_free::AbandonedExpectedHeadTransition::NotOwned => {
                return Err(AbandonError::NotOwnedAssociated);
            }
        }
    }
}

/// Chooses the source terminal/reabandon alternatives after a failed reclaim
/// attempt. `None` deliberately means the caller must run the expected-head
/// unown path rather than invent another reclaim attempt.
fn terminal_or_reabandon_unmapped<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    state: &PageAbandonmentState,
    map: &M,
) -> Result<Option<UnmappedAbandonedFreeResult>, AbandonError> {
    if page_is_empty(state) {
        return Ok(Some(UnmappedAbandonedFreeResult::Empty));
    }
    try_reabandon_unmapped_to_mapped(page, state, map)
}

/// Ports `mi_abandoned_page_try_reabandon_to_mapped` and its
/// `_mi_arenas_page_try_reabandon_to_mapped` success transition for the
/// already-abandoned, still-owned unmapped page.
fn try_reabandon_unmapped_to_mapped<M: MappedAbandonedPages + ?Sized>(
    page: NonNull<Page>,
    state: &PageAbandonmentState,
    map: &M,
) -> Result<Option<UnmappedAbandonedFreeResult>, AbandonError> {
    // The exact pinned source predicate is integer arithmetic: reabandon only
    // after the page has more than its final eighth free. Invalid synthetic or
    // foreign geometry is retained instead of being interpreted as reusable.
    if page_is_mostly_used(state)?
        || state.memid.kind() != MemoryKind::Arena
        || source_thread_identity(state) != THREAD_ID_ABANDONED
        || page_is_full(state)
    {
        return Ok(None);
    }
    let bin = size_class::bin(state.block_size).ok_or(AbandonError::InvalidPageGeometry)?;
    if bin >= ARENA_BIN_COUNT {
        // Pinned source excludes singleton/huge-bin pages from the mapped
        // abandoned bitmap. They remain unowned unmapped pages for a later
        // terminal/general lifecycle owner.
        return Ok(None);
    }
    if map.bin() != bin {
        return Err(AbandonError::ArenaBitmapDoesNotMatchPage);
    }
    let slice_index = map
        .page_slice_index(state.memid)
        .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)?;
    if !map.is_clear(slice_index) {
        return Err(AbandonError::MappedBitAlreadyPublished);
    }

    // `_mi_arenas_page_abandon` first installs the mapped identity, then
    // publishes its exact bit/count before the generic abandoned unown loop.
    set_thread_identity(state, THREAD_ID_ABANDONED_MAPPED);
    if !map.publish(slice_index) {
        // Identity has crossed the source visibility boundary; callers retain
        // this terminal owner rather than pretending the page stayed unmapped.
        return Err(AbandonError::MappedPublicationFailed);
    }
    match unown(page, Some(map))? {
        AbandonResult::UnownedMapped => Ok(Some(UnmappedAbandonedFreeResult::ReabandonedMapped)),
        AbandonResult::Empty => Ok(Some(UnmappedAbandonedFreeResult::Empty)),
        AbandonResult::UnownedUnmapped => Err(AbandonError::NotAbandoned),
    }
}

fn unabandon_mapped<M: MappedAbandonedPages + ?Sized>(
    state: &PageAbandonmentState,
    map: Option<&M>,
) -> Result<(), AbandonError> {
    if source_thread_identity(state) != THREAD_ID_ABANDONED_MAPPED {
        return Ok(());
    }
    let map = map.ok_or(AbandonError::MissingMappedArenaBitmap)?;
    let slice_index = map
        .page_slice_index(state.memid)
        .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)?;
    if !map.clear_once_set(slice_index) {
        return Err(AbandonError::BitmapQuiescenceFailed);
    }
    // `mi_page_clear_abandoned_mapped` preserves only page flags.
    unsafe { state.xthread_id.as_ref() }.fetch_and(PAGE_FLAG_MASK, Ordering::Relaxed);
    if !map.decrement_after_identity_clear() {
        // The bitmap and page identity are already clear, so this cannot be
        // represented as a recoverable pre-mutation failure.
        return Err(AbandonError::AbandonedCountDecrementFailed);
    }
    Ok(())
}

fn set_abandoned_identity(state: &PageAbandonmentState) {
    // `mi_page_set_theap(page, NULL)` briefly clears the ordinary pointer,
    // publishes the abandoned identity with Release CAS while preserving page
    // flags, then `page.c:_mi_page_abandon` restores the old pointer so a
    // same-theap free can reclaim it later.
    let stale_theap = unsafe { ptr::read(state.theap.as_ptr()) };
    unsafe { ptr::write(state.theap.as_ptr(), ptr::null_mut()) };
    set_thread_identity(state, THREAD_ID_ABANDONED);
    unsafe { ptr::write(state.theap.as_ptr(), stale_theap) };
}

fn set_thread_identity(state: &PageAbandonmentState, thread_id: usize) {
    debug_assert_eq!(thread_id & PAGE_FLAG_MASK, 0);
    let xthread_id = unsafe { state.xthread_id.as_ref() };
    let mut previous = xthread_id.load(Ordering::Relaxed);
    loop {
        let replacement = thread_id | (previous & PAGE_FLAG_MASK);
        if word_cas_weak_release(xthread_id, &mut previous, replacement) {
            return;
        }
    }
}

#[inline]
fn source_thread_identity(state: &PageAbandonmentState) -> usize {
    unsafe { state.xthread_id.as_ref() }.load(Ordering::Acquire) & !PAGE_FLAG_MASK
}

#[inline]
fn is_live_associated(state: &PageAbandonmentState) -> bool {
    let thread_id = source_thread_identity(state);
    thread_id != THREAD_ID_ABANDONED && thread_id != THREAD_ID_ABANDONED_MAPPED
}

#[inline]
fn is_abandoned(state: &PageAbandonmentState) -> bool {
    matches!(source_thread_identity(state), THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED)
}

#[inline]
fn is_owned(state: &PageAbandonmentState) -> bool {
    is_owned_word(word_load_relaxed(unsafe { state.xthread_free.as_ref() }))
}

#[inline]
const fn is_owned_word(word: usize) -> bool {
    word & THREAD_FREE_OWNED != 0
}

#[inline]
fn page_is_empty(state: &PageAbandonmentState) -> bool {
    // SAFETY: caller holds the source owner bit whenever it observes `used`.
    unsafe { *state.used.as_ptr() == 0 }
}

#[inline]
fn page_is_full(state: &PageAbandonmentState) -> bool {
    // SAFETY: same owner-bit proof as `page_is_empty`.
    unsafe { *state.used.as_ptr() == usize::from(state.reserved) }
}

/// Exact `mi_page_is_mostly_used`: more than seven eighths in use remains too
/// full to republish into `pages_abandoned`; the boundary itself stays
/// unmapped. Do not substitute a percentage calculation, which could alter
/// the pinned integer-rounding behavior.
fn page_is_mostly_used(state: &PageAbandonmentState) -> Result<bool, AbandonError> {
    // SAFETY: callers hold the source low owner bit while reading `used`.
    let used = unsafe { *state.used.as_ptr() };
    let reserved = usize::from(state.reserved);
    let free = reserved.checked_sub(used).ok_or(AbandonError::InvalidPageGeometry)?;
    Ok(free <= reserved / 8)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::cell::Cell;
    use core::mem::{MaybeUninit, size_of};
    use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::arena::ArenaView;
    use crate::bitmap::{BitmapLayout, BitmapView};
    use crate::config::{ARENA_BIN_COUNT, BCHUNK_BITS, LARGE_MAX_OBJ_SIZE, MAX_ALIGN_SIZE};
    use crate::types::{
        Arena, ArenaPages, Block, Heap, MemoryId, PageRemoteFreeProducerState,
        ThreadLocalData,
    };

    #[repr(align(64))]
    struct BitmapStorage {
        bytes: [MaybeUninit<u8>; 192],
    }

    impl BitmapStorage {
        const fn uninit() -> Self {
            Self {
                bytes: [const { MaybeUninit::uninit() }; 192],
            }
        }
    }

    #[repr(align(16))]
    struct TestBlock([u8; 16]);

    impl TestBlock {
        fn pointer(&mut self) -> NonNull<u8> {
            NonNull::from(&mut self.0).cast()
        }
    }

    // The singleton post-claim continuation now performs the source false
    // local-free transfer.  These tests therefore need a real source-stride
    // `Page` followed by its exact canonical block area, not the older
    // `remote_free_test_page` plus unrelated `TestBlock` protocol fixture.
    const SOURCE_SINGLETON_BLOCK_SIZE: usize =
        (LARGE_MAX_OBJ_SIZE + 1 + MAX_ALIGN_SIZE - 1) & !(MAX_ALIGN_SIZE - 1);
    const SOURCE_SINGLETON_PAGE_OFFSET: usize = size_of::<Page>();
    const SOURCE_SINGLETON_STORAGE_WORDS: usize =
        (SOURCE_SINGLETON_PAGE_OFFSET + SOURCE_SINGLETON_BLOCK_SIZE) / size_of::<usize>();

    #[repr(align(16))]
    struct SourceSingletonStorage {
        words: [MaybeUninit<usize>; SOURCE_SINGLETON_STORAGE_WORDS],
    }

    impl SourceSingletonStorage {
        fn uninit() -> Self {
            Self {
                words: [const { MaybeUninit::uninit() }; SOURCE_SINGLETON_STORAGE_WORDS],
            }
        }

        fn page_and_block(&mut self) -> (NonNull<Page>, NonNull<u8>) {
            let page = NonNull::new(self.words.as_mut_ptr().cast::<Page>())
                .expect("the source-stride singleton metadata is non-null");
            // SAFETY: the aligned backing reserves one complete page block
            // immediately after its as-yet uninitialized metadata slot.
            let block = unsafe {
                NonNull::new_unchecked(
                    page.as_ptr()
                        .cast::<u8>()
                        .add(SOURCE_SINGLETON_PAGE_OFFSET),
                )
            };
            (page, block)
        }
    }

    fn publish_source_singleton(
        storage: &mut SourceSingletonStorage,
        heap: &Heap,
        theap: &mut Theap,
        thread_id: LiveThreadId,
        memory: MemoryId,
    ) -> (NonNull<Page>, NonNull<u8>) {
        let (metadata, block) = storage.page_and_block();
        // SAFETY: `storage` holds exactly one aligned metadata image followed
        // by its complete, aligned one-block area. The bound live Theap/Heap
        // own the source association until `abandon` below.
        let mut page = unsafe {
            Page::publish_fresh_exclusive_at(
                metadata,
                theap,
                heap,
                thread_id,
                SOURCE_SINGLETON_BLOCK_SIZE,
                SOURCE_SINGLETON_PAGE_OFFSET,
                1,
                0,
                true,
                memory,
            )
        }
        .expect("the source-stride singleton metadata initializes");
        assert!(unsafe { page.as_mut() }.set_capacity_reserved(1, 1));
        unsafe { page.as_mut() }.set_exclusive_used(1);
        (page, block)
    }

    /// Raw-backed stand-in for one coherent W02 live-allocation observation.
    struct TestLiveRemoteAllocation {
        page: NonNull<Page>,
        producer: PageRemoteFreeProducerState,
        canonical_block: NonNull<u8>,
    }

    // SAFETY: each test constructs this only after fixing the address of one
    // initialized page and one exact current block. The block's `used`
    // contribution retains the page until the consuming source tail finishes;
    // only the narrow atomic producer projection survives owner exit.
    unsafe impl remote_free::LiveRemoteFreeAllocation for TestLiveRemoteAllocation {
        fn live_remote_free_allocation(
            &self,
        ) -> (
            NonNull<Page>,
            PageRemoteFreeProducerState,
            NonNull<u8>,
            LiveAllocationPageState,
        ) {
            (
                self.page,
                self.producer,
                self.canonical_block,
                LiveAllocationPageState::LiveOwnerAssociated,
            )
        }
    }

    /// Test-only sharing proof: scoped producers use only raw atomic page
    /// fields, while ordinary page state remains owner-only through each
    /// collection loop. `Page` itself intentionally remains non-`Sync`.
    #[repr(transparent)]
    struct ConcurrentPage(Page);

    unsafe impl Sync for ConcurrentPage {}

    impl ConcurrentPage {
        fn pointer(&self) -> NonNull<Page> {
            unsafe { NonNull::new_unchecked(core::ptr::addr_of!(self.0).cast_mut()) }
        }
    }

    fn map_fixture(storage: &mut BitmapStorage) -> Arena {
        map_fixture_for_bin(storage, 1)
    }

    fn map_fixture_for_bin(storage: &mut BitmapStorage, bin: usize) -> Arena {
        assert!(bin < ARENA_BIN_COUNT);
        let layout = BitmapLayout::for_bit_count(BCHUNK_BITS).unwrap();
        unsafe {
            BitmapView::initialize(
                storage.bytes.as_mut_ptr().cast(),
                storage.bytes.len(),
                layout,
                false,
            )
            .unwrap();
        }
        let bitmap = storage.bytes.as_mut_ptr().cast::<u8>();
        let mut maps = [core::ptr::null_mut(); ARENA_BIN_COUNT];
        maps[bin] = bitmap;
        Arena {
            memid: MemoryId::none(),
            subprocess: core::ptr::null_mut(),
            arena_index: 0,
            start: core::ptr::null_mut(),
            slice_count: BCHUNK_BITS,
            info_slices: 0,
            numa_node: -1,
            is_exclusive: false,
            purge_expire: AtomicI64::new(0),
            commit_function: None,
            commit_function_argument: core::ptr::null_mut(),
            total_size: 0,
            parent: core::ptr::null_mut(),
            slices_free: core::ptr::null_mut(),
            slices_committed: core::ptr::null_mut(),
            slices_dirty: core::ptr::null_mut(),
            slices_purge: core::ptr::null_mut(),
            pages_meta: core::ptr::null_mut(),
            pages_main: ArenaPages {
                pages: core::ptr::null_mut(),
                pages_abandoned: maps,
            },
        }
    }

    fn mapped_page(arena: &mut Arena, used: usize) -> Page {
        // The pinned small-page partial collector requires the source's
        // `reserved >= 16` invariant before it can leave its just-published
        // remote head in place.
        let mut page = Page::remote_free_test_page(16, used);
        assert!(unsafe { page.abandoned_test_set_arena_memory(arena, 17, 1) });
        page
    }

    fn bind_adopting_theap(
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
        theap: &mut Theap,
        thread_id: LiveThreadId,
    ) -> NonNull<Theap> {
        tld.attach_bootstrap_exclusive(thread_id);
        assert!(theap.bind_exclusive_single_thread(heap, tld));
        NonNull::from(theap)
    }

    fn abandon_full_unmapped(page: &mut Page) -> NonNull<Page> {
        let page = NonNull::from(page);
        assert_eq!(
            unsafe { abandon(page, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::UnownedUnmapped)
        );
        page
    }

    #[test]
    fn abandoned_post_exit_free_uses_page_state_then_releases_the_terminal_page() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let mut page = Page::remote_free_test_page(2, 2);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        // An exited owner can leave its source association address in the
        // page, but this post-exit path must never dereference it.
        page.abandoned_test_set_theap(NonNull::<Theap>::dangling().as_ptr());
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);

        let mut terminal_called = false;
        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    first.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| Ok(()),
                    |_page| {
                        terminal_called = true;
                        PostOwnerExitTerminalRelease::Released
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::StillLive)
        );
        assert!(!terminal_called, "a live page cannot enter terminal release");
        assert!(view.abandoned_pages(bin).unwrap().is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 1);

        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    second.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| Ok(()),
                    |_page| {
                        assert!(
                            !view.abandoned_pages(bin).unwrap().is_published(17),
                            "mapped identity must clear before terminal PageMap/span release"
                        );
                        terminal_called = true;
                        PostOwnerExitTerminalRelease::Released
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::Released)
        );
        assert!(terminal_called, "only the final free invokes the release seam");
        assert!(!view.abandoned_pages(bin).unwrap().is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn abandoned_post_exit_free_retains_one_terminal_owner_when_release_fails() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(2, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        let mut block = TestBlock([0; 16]);
        let mut terminal_calls = 0usize;

        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    block.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| Ok(()),
                    |_page| {
                        assert!(
                            !view.abandoned_pages(bin).unwrap().is_published(17),
                            "a failed terminal release still follows mapped identity removal"
                        );
                        terminal_calls += 1;
                        PostOwnerExitTerminalRelease::Retained
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::TerminalReleaseRetained)
        );
        assert_eq!(terminal_calls, 1, "the unique final owner receives one release attempt");
        assert!(!view.abandoned_pages(bin).unwrap().is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn abandoned_post_exit_deferred_collection_terminal_failure_keeps_one_owner() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(2, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        let mut first = TestBlock([0; 16]);
        let first = first.pointer();
        let collection_changed_page = Cell::new(false);
        let mut terminal_calls = 0usize;

        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    first,
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |collected_page| {
                        // The normal remote collector has already decremented
                        // `used` and installed its block in `local_free`.
                        // Model the source false-force local transfer before
                        // terminal release reports a failure.
                        let collected_page = unsafe { &mut *collected_page.as_ptr() };
                        assert_eq!(collected_page.remote_free_test_used(), 0);
                        assert_eq!(
                            collected_page.remote_free_test_local_free(),
                            first.cast::<Block>().as_ptr()
                        );
                        collected_page
                            .set_exclusive_free_list_head(collected_page.remote_free_test_local_free());
                        collected_page.remote_free_test_set_local_free(core::ptr::null_mut());
                        collection_changed_page.set(true);
                        Ok(())
                    },
                    |terminal_page| {
                        assert!(collection_changed_page.get());
                        let terminal_page = unsafe { terminal_page.as_ref() };
                        assert_eq!(
                            terminal_page.remote_free_test_free(),
                            first.cast::<Block>().as_ptr(),
                            "the terminal owner observes the completed local transfer"
                        );
                        assert!(terminal_page.remote_free_test_local_free().is_null());
                        assert!(
                            !view.abandoned_pages(bin).unwrap().is_published(17),
                            "mapped identity clears before terminal ownership is retained"
                        );
                        terminal_calls += 1;
                        PostOwnerExitTerminalRelease::Retained
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::TerminalReleaseRetained)
        );
        assert!(collection_changed_page.get());
        assert_eq!(terminal_calls, 1);
        assert_eq!(page.remote_free_test_free(), first.cast::<Block>().as_ptr());
        assert!(page.remote_free_test_local_free().is_null());
        assert_eq!(page.remote_free_test_used(), 0);
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);

        // A later pointer route reaches the still-owned atomic head, so it
        // cannot re-select the map, collect ordinary state, or retry terminal
        // release. TestBlock is this unit fixture's canonical synthetic page
        // allocation, as in the other abandoned remote-free route tests.
        let mut later = TestBlock([0; 16]);
        let later = later.pointer();
        let retry_selected_map = Cell::new(false);
        let retry_collected = Cell::new(false);
        let retry_terminal = Cell::new(false);
        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    later,
                    |_memory, _selected_block_size| {
                        retry_selected_map.set(true);
                        Ok(map)
                    },
                    |_page| {
                        retry_collected.set(true);
                        Ok(())
                    },
                    |_page| {
                        retry_terminal.set(true);
                        PostOwnerExitTerminalRelease::Released
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::PublishedToExistingOwner)
        );
        assert!(!retry_selected_map.get());
        assert!(!retry_collected.get());
        assert!(!retry_terminal.get());
        assert_eq!(terminal_calls, 1, "only the retained terminal owner may release");
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn abandoned_post_exit_free_does_not_select_a_page_map_for_an_existing_owner() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(2, 2);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        assert_eq!(
            unsafe { remote_free::push_abandoned(page_raw, first.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );

        let mut selected_map = false;
        let mut terminal_called = false;
        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    second.pointer(),
                    |_memory, _selected_block_size| {
                        selected_map = true;
                        Ok(map)
                    },
                    |_page| Ok(()),
                    |_page| {
                        terminal_called = true;
                        PostOwnerExitTerminalRelease::Released
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::PublishedToExistingOwner)
        );
        assert!(!selected_map, "an atomic producer owns the collection decision");
        assert!(!terminal_called, "the losing producer cannot release the page");
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);
    }

    #[test]
    fn abandoned_post_exit_deferred_collection_precedes_reabandon_and_terminal_release() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let mut page = Page::remote_free_test_page(2, 2);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let phase = Cell::new(0u8);

        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    first.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        assert_eq!(
                            phase.get(),
                            1,
                            "PageMap selection follows owner deferred collection"
                        );
                        phase.set(2);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| {
                        assert_eq!(phase.get(), 0);
                        assert!(
                            !view.abandoned_pages(bin).unwrap().is_published(17),
                            "owner collection runs before an unmapped page reabandonment"
                        );
                        phase.set(1);
                        Ok(())
                    },
                    |_page| panic!("a still-live page cannot enter terminal release"),
                )
            },
            Ok(PostOwnerExitRegularFreeResult::StillLive)
        );
        assert_eq!(phase.get(), 2);
        assert!(view.abandoned_pages(bin).unwrap().is_published(17));

        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    second.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        assert_eq!(
                            phase.get(),
                            3,
                            "PageMap selection follows the second owner collection"
                        );
                        phase.set(4);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| {
                        assert_eq!(phase.get(), 2);
                        assert!(view.abandoned_pages(bin).unwrap().is_published(17));
                        phase.set(3);
                        Ok(())
                    },
                    |_page| {
                        assert_eq!(phase.get(), 4);
                        assert!(
                            !view.abandoned_pages(bin).unwrap().is_published(17),
                            "terminal release follows mapped identity removal"
                        );
                        phase.set(5);
                        PostOwnerExitTerminalRelease::Released
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::Released)
        );
        assert_eq!(phase.get(), 5);
    }

    #[test]
    fn abandoned_post_exit_deferred_collection_failure_retains_before_terminal_release() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(2, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        let mut block = TestBlock([0; 16]);
        let map_selected = Cell::new(false);
        let mut terminal_called = false;

        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    block.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        map_selected.set(true);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| {
                        assert!(
                            !map_selected.get(),
                            "a collection failure cannot acquire PageMap release state"
                        );
                        assert!(
                            view.abandoned_pages(bin).unwrap().is_published(17),
                            "owner deferred collection precedes mapped identity removal"
                        );
                        Err(AbandonError::LocalFree(FreeListError::InvalidPage))
                    },
                    |_page| {
                        terminal_called = true;
                        PostOwnerExitTerminalRelease::Released
                    },
                )
            },
            Err(AbandonError::LocalFree(FreeListError::InvalidPage))
        );
        assert!(!terminal_called);
        assert!(!map_selected.get());
        assert!(view.abandoned_pages(bin).unwrap().is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn live_remote_claim_continues_to_terminal_release_without_republication() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(2, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page = NonNull::from(&mut page);
        let mut block = TestBlock([0; 16]);
        let block = block.pointer();
        // SAFETY: this exact live client pins the raw-backed page. Only the
        // two atomic producer fields survive the source owner-exit transition.
        let allocation = TestLiveRemoteAllocation {
            page,
            producer: unsafe { Page::remote_free_producer_state_at(page) },
            canonical_block: block,
        };

        // The lookup above copied a live owner identity. Before publication,
        // owner exit publishes the mapped-abandoned identity and unowns the
        // empty remote head while this client's `used` contribution keeps the
        // page registered and initialized.
        assert_eq!(
            unsafe { abandon(page, Some(&map)) },
            Ok(AbandonResult::UnownedMapped)
        );
        assert!(map.is_published(17));

        let claim = match unsafe { remote_free::push_live_allocation(allocation) } {
            Ok(remote_free::LiveRemoteFreePublish::ClaimedAbandonedPage(claim)) => claim,
            _ => panic!("the stale live observation must return its exact page owner"),
        };
        assert_eq!(claim.page(), page);
        assert_eq!(claim.published_block(), block);

        let selected_map = Cell::new(0usize);
        let owner_local_collections = Cell::new(0usize);
        let terminal_releases = Cell::new(0usize);
        // SAFETY: `claim` is the unique low-bit owner produced by the source
        // CAS above. Each callback retains only its documented phase and the
        // terminal callback performs the test's source release boundary.
        assert!(matches!(
            unsafe {
                continue_post_owner_exit_remote_claim(
                    claim,
                    |memory, selected_block_size| {
                        selected_map.set(selected_map.get() + 1);
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| {
                        owner_local_collections.set(owner_local_collections.get() + 1);
                        Ok(())
                    },
                    |release| {
                        assert_eq!(release.page(), page);
                        assert_eq!(release.memory().kind(), MemoryKind::Arena);
                        terminal_releases.set(terminal_releases.get() + 1);
                        ClaimedPostOwnerExitRegularTerminalRelease::Released
                    },
                )
            },
            Ok(ClaimedPostOwnerExitRegularFreeResult::Released)
        ));
        assert_eq!(selected_map.get(), 1);
        assert_eq!(owner_local_collections.get(), 1);
        assert_eq!(terminal_releases.get(), 1);
        assert!(
            !map.is_published(17),
            "the claimed continuation clears mapped identity before release"
        );
    }

    fn claim_live_singleton_after_owner_exit(
        page: NonNull<Page>,
        block: NonNull<u8>,
    ) -> remote_free::ClaimedAbandonedRemoteFree {
        // SAFETY: the fixture fixes this page and exact current block before
        // copying the producer projection. The live block keeps both valid
        // across the immediately following owner-exit transition.
        let allocation = TestLiveRemoteAllocation {
            page,
            producer: unsafe { Page::remote_free_producer_state_at(page) },
            canonical_block: block,
        };
        assert_eq!(
            unsafe { abandon(page, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::UnownedUnmapped)
        );
        match unsafe { remote_free::push_live_allocation(allocation) } {
            Ok(remote_free::LiveRemoteFreePublish::ClaimedAbandonedPage(claim)) => claim,
            _ => panic!("the stale live singleton observation must return its exact owner"),
        }
    }

    #[test]
    fn live_remote_singleton_claim_consumes_the_arena_terminal_tail() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let mut theap = Theap::empty();
        bind_adopting_theap(&mut heap, &mut tld, &mut theap, thread_id);
        let mut page_storage = SourceSingletonStorage::uninit();
        let (mut page_pointer, block) = publish_source_singleton(
            &mut page_storage,
            &heap,
            &mut theap,
            thread_id,
            MemoryId::none(),
        );
        assert!(unsafe { page_pointer.as_mut().abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let claim = claim_live_singleton_after_owner_exit(page_pointer, block);

        let mut unabandon_calls = 0usize;
        let mut terminal_free_calls = 0usize;
        // SAFETY: `claim` is the exact post-CAS singleton owner. The callback
        // models the exact source `_mi_arenas_page_unabandon` then
        // `_mi_arenas_page_free` order. It consumes the terminal capability
        // only after both terminal phases have run once.
        let result = unsafe {
            continue_post_owner_exit_singleton_remote_claim(claim, |release| {
                assert_eq!(release.page(), page_pointer);
                assert_eq!(release.published_block(), block);
                assert_eq!(release.memory().kind(), MemoryKind::Arena);
                assert_eq!(
                    release.backing(),
                    ClaimedPostOwnerExitSingletonBacking::Arena
                );
                let page = release.page().as_ref();
                assert_eq!(
                    page.remote_free_test_free(),
                    block.cast::<Block>().as_ptr(),
                    "the claimed remote block reached local_free before the source false collection"
                );
                assert!(
                    page.remote_free_test_local_free().is_null(),
                    "the singleton terminal tail observes the completed false-force local transfer"
                );
                assert_eq!(unabandon_calls, 0);
                unabandon_calls += 1;
                assert_eq!(terminal_free_calls, 0);
                terminal_free_calls += 1;
                ClaimedPostOwnerExitSingletonFreeResult::Released
            })
        };
        assert!(matches!(
            result,
            Ok(ClaimedPostOwnerExitSingletonFreeResult::Released)
        ));
        assert_eq!(unabandon_calls, 1);
        assert_eq!(terminal_free_calls, 1);
        assert_eq!(unsafe { page_pointer.as_ref() }.remote_free_test_used(), 0);
    }

    #[test]
    fn live_remote_singleton_claim_consumes_the_external_terminal_tail() {
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let mut theap = Theap::empty();
        bind_adopting_theap(&mut heap, &mut tld, &mut theap, thread_id);
        let mut page_storage = SourceSingletonStorage::uninit();
        let (_, block) = page_storage.page_and_block();
        let memory = MemoryId::external(
            block.as_ptr(),
            SOURCE_SINGLETON_BLOCK_SIZE,
            true,
            false,
            true,
        );
        let (mut page_pointer, block) = publish_source_singleton(
            &mut page_storage,
            &heap,
            &mut theap,
            thread_id,
            memory,
        );
        // Source `_mi_arenas_page_abandon` links a non-arena abandoned page
        // before it later unowns the remote head. The bounded substrate leaves
        // that private-list owner to this terminal fixture, so install the
        // exact single member after the source identity transition and before
        // the stale-live publication claims it.
        let allocation = TestLiveRemoteAllocation {
            page: page_pointer,
            producer: unsafe { Page::remote_free_producer_state_at(page_pointer) },
            canonical_block: block,
        };
        assert_eq!(
            unsafe { abandon(page_pointer, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::UnownedUnmapped)
        );
        assert_eq!(
            unsafe { heap.push_os_abandoned_page(page_pointer) },
            Ok(())
        );
        assert_eq!(heap.test_os_abandoned_page_head(), page_pointer.as_ptr());
        let claim = match unsafe { remote_free::push_live_allocation(allocation) } {
            Ok(remote_free::LiveRemoteFreePublish::ClaimedAbandonedPage(claim)) => claim,
            _ => panic!("the stale live singleton observation must return its exact owner"),
        };

        let mut unabandon_calls = 0usize;
        let mut terminal_free_calls = 0usize;
        // SAFETY: `claim` is the exact post-CAS singleton owner. The callback
        // runs the actual source OS-list-unabandon primitive before modeling
        // its one PageMap/metadata/external-memory release tail.
        let result = unsafe {
            continue_post_owner_exit_singleton_remote_claim(claim, |release| {
                assert_eq!(release.page(), page_pointer);
                assert_eq!(release.published_block(), block);
                assert_eq!(release.memory().kind(), MemoryKind::External);
                assert_eq!(
                    release.backing(),
                    ClaimedPostOwnerExitSingletonBacking::OsOrExternal
                );
                let page = release.page().as_ref();
                assert_eq!(
                    page.remote_free_test_free(),
                    block.cast::<Block>().as_ptr(),
                    "the external singleton sees the remote block after the source false collection"
                );
                assert!(
                    page.remote_free_test_local_free().is_null(),
                    "the external singleton terminal tail cannot skip local_free -> free"
                );
                assert_eq!(unabandon_calls, 0);
                unabandon_calls += 1;
                assert_eq!(heap.remove_os_abandoned_page(release.page()), Ok(()));
                assert!(heap.test_os_abandoned_page_head().is_null());
                assert_eq!(terminal_free_calls, 0);
                terminal_free_calls += 1;
                ClaimedPostOwnerExitSingletonFreeResult::Released
            })
        };
        assert!(matches!(
            result,
            Ok(ClaimedPostOwnerExitSingletonFreeResult::Released)
        ));
        assert_eq!(unabandon_calls, 1);
        assert_eq!(terminal_free_calls, 1);
        assert!(heap.test_os_abandoned_page_head().is_null());
        assert_eq!(unsafe { page_pointer.as_ref() }.remote_free_test_used(), 0);
    }

    #[test]
    fn live_remote_singleton_terminal_failure_retains_the_exact_claim() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let mut theap = Theap::empty();
        bind_adopting_theap(&mut heap, &mut tld, &mut theap, thread_id);
        let mut page_storage = SourceSingletonStorage::uninit();
        let (mut page_pointer, block) = publish_source_singleton(
            &mut page_storage,
            &heap,
            &mut theap,
            thread_id,
            MemoryId::none(),
        );
        assert!(unsafe { page_pointer.as_mut().abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let claim = claim_live_singleton_after_owner_exit(page_pointer, block);

        // SAFETY: the fixture intentionally models a failed terminal release;
        // it returns the exact capability it received instead of dropping the
        // already-collected page owner.
        let result = unsafe {
            continue_post_owner_exit_singleton_remote_claim(claim, |release| {
                ClaimedPostOwnerExitSingletonFreeResult::TerminalReleaseRetained(release)
            })
        };
        let retained = match result {
            Ok(ClaimedPostOwnerExitSingletonFreeResult::TerminalReleaseRetained(retained)) => {
                retained
            }
            _ => panic!("terminal failure must retain the exact singleton owner"),
        };
        assert_eq!(retained.page(), page_pointer);
        assert_eq!(retained.published_block(), block);
        assert_eq!(retained.memory().kind(), MemoryKind::Arena);
        assert_eq!(
            retained.backing(),
            ClaimedPostOwnerExitSingletonBacking::Arena
        );
        assert_eq!(unsafe { page_pointer.as_ref() }.remote_free_test_used(), 0);
        assert_ne!(unsafe { page_pointer.as_ref() }.remote_free_test_head() & THREAD_FREE_OWNED, 0);
    }

    #[test]
    fn post_owner_exit_page_state_dispatch_rejects_nonabandoned_states_before_publication() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(2, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        let mut block = TestBlock([0; 16]);

        for page_state in [
            LiveAllocationPageState::LiveOwnerAssociated,
            LiveAllocationPageState::Detached,
        ] {
            let selected_map = Cell::new(false);
            let collected = Cell::new(false);
            let terminal = Cell::new(false);
            assert_eq!(
                unsafe {
                    free_post_owner_exit_from_page_state(
                        page_raw,
                        page_state,
                        block.pointer(),
                        |memory, selected_block_size| {
                            selected_map.set(true);
                            assert_eq!(memory.kind(), MemoryKind::Arena);
                            assert_eq!(selected_block_size, block_size);
                            view.abandoned_pages(bin)
                                .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                        },
                        |_page| {
                            collected.set(true);
                            Ok(())
                        },
                        |_page| {
                            terminal.set(true);
                            PostOwnerExitTerminalRelease::Released
                        },
                    )
                },
                Err(AbandonError::NotAbandoned)
            );
            assert!(!selected_map.get());
            assert!(!collected.get());
            assert!(!terminal.get());
            assert_eq!(page.remote_free_test_head(), 0);
            assert_eq!(page.remote_free_test_used(), 1);
            assert!(view.abandoned_pages(bin).unwrap().is_published(17));
        }
    }

    #[test]
    fn post_owner_exit_page_state_dispatch_reabandons_then_retains_the_terminal_owner() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let mut page = Page::remote_free_test_page(2, 2);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        // The old association may remain as a source reclaim hint, but this
        // pointer/page-state free seam must never dereference it.
        page.abandoned_test_set_theap(NonNull::<Theap>::dangling().as_ptr());
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let owner_local_false_force_calls = Cell::new(0usize);
        let phase = Cell::new(0u8);
        let terminal_calls = Cell::new(0usize);

        assert_eq!(
            unsafe {
                free_post_owner_exit_from_page_state(
                    page_raw,
                    LiveAllocationPageState::Abandoned,
                    first.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        assert_eq!(
                            phase.get(),
                            1,
                            "the source local false-force phase precedes reabandon selection"
                        );
                        phase.set(2);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| {
                        assert_eq!(phase.get(), 0);
                        owner_local_false_force_calls.set(
                            owner_local_false_force_calls.get().saturating_add(1),
                        );
                        phase.set(1);
                        Ok(())
                    },
                    |_page| panic!("a still-live ordinary abandoned page cannot release"),
                )
            },
            Ok(PostOwnerExitRegularFreeResult::StillLive)
        );
        assert_eq!(owner_local_false_force_calls.get(), 1);
        assert_eq!(phase.get(), 2);
        assert!(view.abandoned_pages(bin).unwrap().is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 1);

        assert_eq!(
            unsafe {
                free_post_owner_exit_from_page_state(
                    page_raw,
                    LiveAllocationPageState::AbandonedMapped,
                    second.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        assert_eq!(
                            phase.get(),
                            3,
                            "the mapped identity also selects its map after local collection"
                        );
                        phase.set(4);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| {
                        assert_eq!(phase.get(), 2);
                        assert!(view.abandoned_pages(bin).unwrap().is_published(17));
                        owner_local_false_force_calls.set(
                            owner_local_false_force_calls.get().saturating_add(1),
                        );
                        phase.set(3);
                        Ok(())
                    },
                    |_page| {
                        assert_eq!(phase.get(), 4);
                        assert!(
                            !view.abandoned_pages(bin).unwrap().is_published(17),
                            "terminal retention follows mapped identity removal"
                        );
                        terminal_calls.set(terminal_calls.get().saturating_add(1));
                        PostOwnerExitTerminalRelease::Retained
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::TerminalReleaseRetained)
        );
        assert_eq!(owner_local_false_force_calls.get(), 2);
        assert_eq!(terminal_calls.get(), 1);
        assert_eq!(phase.get(), 4);
        assert!(!view.abandoned_pages(bin).unwrap().is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn post_owner_exit_page_state_dispatch_runs_false_collection_after_each_remote_detach() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut source_page = Page::remote_free_test_page(3, 2);
        source_page.set_block_size(block_size);
        assert!(unsafe { source_page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        source_page.abandoned_test_set_theap(NonNull::<Theap>::dangling().as_ptr());
        let page = ConcurrentPage(source_page);
        let page_raw = page.pointer();
        assert_eq!(
            unsafe { abandon(page_raw, Some(&map)) },
            Ok(AbandonResult::UnownedMapped)
        );
        assert!(map.is_published(17));

        let mut first = TestBlock([0; 16]);
        let first = first.pointer();
        let mut second = TestBlock([0; 16]);
        let second_pointer = second.pointer();
        let owner_collected_remote = Arc::new(Barrier::new(2));
        let publisher_finished = Arc::new(Barrier::new(2));
        let owner_local_false_force_calls = AtomicUsize::new(0);
        let terminal_calls = AtomicUsize::new(0);
        let producer_selected_map = AtomicBool::new(false);
        let page_for_producer = &page;
        let second_for_producer = &mut second;

        thread::scope(|scope| {
            let owner_collected_remote_for_producer = Arc::clone(&owner_collected_remote);
            let publisher_finished_for_producer = Arc::clone(&publisher_finished);
            let producer_selected_map_for_producer = &producer_selected_map;
            scope.spawn(move || {
                owner_collected_remote_for_producer.wait();
                assert_eq!(
                    unsafe {
                        free_post_owner_exit_from_page_state(
                            page_for_producer.pointer(),
                            LiveAllocationPageState::AbandonedMapped,
                            second_for_producer.pointer(),
                            |_memory, _selected_block_size| {
                                producer_selected_map_for_producer.store(true, Ordering::Release);
                                Ok(UnmappableAbandonedPages)
                            },
                            |_page| panic!("the losing producer cannot collect ordinary page state"),
                            |_page| panic!("the losing producer cannot release the page"),
                        )
                    },
                    Ok(PostOwnerExitRegularFreeResult::PublishedToExistingOwner)
                );
                publisher_finished_for_producer.wait();
            });

            assert_eq!(
                unsafe {
                    free_post_owner_exit_from_page_state(
                        page_raw,
                        LiveAllocationPageState::AbandonedMapped,
                        first,
                        |memory, selected_block_size| {
                            assert_eq!(memory.kind(), MemoryKind::Arena);
                            assert_eq!(selected_block_size, block_size);
                            Ok(&map)
                        },
                        |collected_page| {
                            // The winning source owner must complete the
                            // false-force local phase after both the initial
                            // detach and the raced expected-head detach.
                            let collected_page = &mut *collected_page.as_ptr();
                            match owner_local_false_force_calls.fetch_add(1, Ordering::AcqRel) {
                                0 => {
                                    assert_eq!(collected_page.remote_free_test_used(), 1);
                                    assert_eq!(
                                        collected_page.remote_free_test_local_free(),
                                        first.cast::<Block>().as_ptr()
                                    );
                                    assert!(collected_page.remote_free_test_free().is_null());
                                    collected_page.set_exclusive_free_list_head(
                                        collected_page.remote_free_test_local_free(),
                                    );
                                    collected_page
                                        .remote_free_test_set_local_free(core::ptr::null_mut());
                                    owner_collected_remote.wait();
                                    publisher_finished.wait();
                                }
                                1 => {
                                    assert_eq!(collected_page.remote_free_test_used(), 0);
                                    assert_eq!(
                                        collected_page.remote_free_test_local_free(),
                                        second_pointer.cast::<Block>().as_ptr(),
                                    );
                                    assert_eq!(
                                        collected_page.remote_free_test_free(),
                                        first.cast::<Block>().as_ptr(),
                                    );
                                    // `force == false` leaves a newly
                                    // detached local list in place when the
                                    // ordinary free list is already nonempty.
                                }
                                _ => panic!("the source tail has exactly two remote detaches"),
                            }
                            Ok(())
                        },
                        |_page| {
                            assert_eq!(owner_local_false_force_calls.load(Ordering::Acquire), 2);
                            assert!(
                                !map.is_published(17),
                                "the second remote client is collected before mapped terminal release"
                            );
                            terminal_calls.fetch_add(1, Ordering::AcqRel);
                            PostOwnerExitTerminalRelease::Released
                        },
                    )
                },
                Ok(PostOwnerExitRegularFreeResult::Released)
            );
        });

        assert!(!producer_selected_map.load(Ordering::Acquire));
        assert_eq!(owner_local_false_force_calls.load(Ordering::Acquire), 2);
        assert_eq!(terminal_calls.load(Ordering::Acquire), 1);
        assert!(!map.is_published(17));
        assert_eq!(page.0.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.0.remote_free_test_head() & THREAD_FREE_OWNED, 0);
        assert_eq!(page.0.remote_free_test_used(), 0);
    }

    #[test]
    fn unmapped_small_free_preserves_its_expected_partial_head_while_mostly_used() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 16);
        let page_raw = abandon_full_unmapped(&mut page);
        let mut block = TestBlock([0; 16]);
        let expected_head = block.pointer().as_ptr().expose_provenance();

        assert_eq!(
            unsafe { free_unmapped_after_failed_reclaim(page_raw, block.pointer(), &map) },
            Ok(UnmappedAbandonedFreeResult::UnownedUnmapped)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), expected_head);
        assert_eq!(page.remote_free_test_used(), 16);
    }

    #[test]
    fn unmapped_abandoned_free_leaves_the_existing_owner_responsible() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 16);
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);

        assert_eq!(
            unsafe { remote_free::push_abandoned(page_raw, first.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );
        assert_eq!(
            unsafe { free_unmapped_after_failed_reclaim(page_raw, second.pointer(), &map) },
            Ok(UnmappedAbandonedFreeResult::PublishedToExistingOwner)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.remote_free_test_head() & 1, 0);
        assert_eq!(page.remote_free_test_used(), 16);
    }

    #[test]
    fn unmapped_small_free_reabandons_only_after_the_partial_head_lag() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 16);
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let mut third = TestBlock([0; 16]);
        let mut fourth = TestBlock([0; 16]);

        for block in [first.pointer(), second.pointer(), third.pointer()] {
            assert_eq!(
                unsafe { free_unmapped_after_failed_reclaim(page_raw, block, &map) },
                Ok(UnmappedAbandonedFreeResult::UnownedUnmapped)
            );
            assert!(!map.is_published(17));
            assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        }

        assert_eq!(
            unsafe { free_unmapped_after_failed_reclaim(page_raw, fourth.pointer(), &map) },
            Ok(UnmappedAbandonedFreeResult::ReabandonedMapped)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 12);
        assert_eq!(page.remote_free_test_free_is_zero(), false);
        assert!(!page.remote_free_test_free().is_null());
        assert_eq!(page.remote_free_test_local_chain_len(4), 3);
    }

    #[test]
    fn unmapped_medium_free_reabandons_after_three_full_collections() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(16, 16);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let mut third = TestBlock([0; 16]);

        for block in [first.pointer(), second.pointer()] {
            assert_eq!(
                unsafe { free_unmapped_after_failed_reclaim(page_raw, block, &map) },
                Ok(UnmappedAbandonedFreeResult::UnownedUnmapped)
            );
            assert!(!map.is_published(17));
        }
        assert_eq!(
            unsafe { free_unmapped_after_failed_reclaim(page_raw, third.pointer(), &map) },
            Ok(UnmappedAbandonedFreeResult::ReabandonedMapped)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 13);
    }

    /// Keeps the raw `free.c` failed-reclaim tail independently regression-
    /// tested on synthetic metadata. The native x86 differential selects the
    /// real full-medium post-Theap-teardown route in `main_heap_page`; this
    /// unit test is deliberately only a low-level tail invariant.
    #[test]
    fn unmapped_reabandon_failed_reclaim_tail_crosses_source_threshold() {
        let block_size = crate::config::SMALL_MAX_OBJ_SIZE + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(16, 16);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });

        let reserved_before_free = usize::from(page.remote_free_test_reserved());
        let arena_backed = page.memid().kind() == MemoryKind::Arena;
        let medium_page = page.block_size() > crate::config::SMALL_MAX_OBJ_SIZE
            && page.block_size() <= crate::config::MEDIUM_MAX_OBJ_SIZE;
        let initially_full = page.remote_free_test_used() == reserved_before_free;
        let page_raw = abandon_full_unmapped(&mut page);
        let initially_unmapped = page.abandoned_test_thread_id() == THREAD_ID_ABANDONED;
        let abandoned_before_free = initially_unmapped;

        let free_count_to_reabandon = reserved_before_free / 8 + 1;
        let mut blocks = [TestBlock([0; 16]), TestBlock([0; 16]), TestBlock([0; 16])];
        assert_eq!(free_count_to_reabandon, blocks.len());

        for block in blocks.iter_mut().take(free_count_to_reabandon - 1) {
            assert_eq!(
                unsafe { free_unmapped_after_failed_reclaim(page_raw, block.pointer(), &map) },
                Ok(UnmappedAbandonedFreeResult::UnownedUnmapped)
            );
        }
        let pretransition_remained_unmapped = page.abandoned_test_thread_id() == THREAD_ID_ABANDONED
            && !map.is_published(17)
            && page.remote_free_test_head() & THREAD_FREE_OWNED == 0;

        assert_eq!(
            unsafe {
                free_unmapped_after_failed_reclaim(
                    page_raw,
                    blocks[free_count_to_reabandon - 1].pointer(),
                    &map,
                )
            },
            Ok(UnmappedAbandonedFreeResult::ReabandonedMapped)
        );

        // This is the exact source threshold, derived from the original
        // fixed reservation and the number of fully collected medium frees.
        // It intentionally does not inspect unowned ordinary page fields.
        let reabandon_threshold_crossed = free_count_to_reabandon > reserved_before_free / 8;
        let reabandoned_mapped_after_free = page.abandoned_test_thread_id()
            == THREAD_ID_ABANDONED_MAPPED;
        let abandoned_after_free = matches!(
            page.abandoned_test_thread_id(),
            THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED
        );
        let bitmap_published_after = map.is_published(17);
        let page_still_live = reserved_before_free > free_count_to_reabandon;
        let unowned_after_free = page.remote_free_test_head() & THREAD_FREE_OWNED == 0;
        let valid = arena_backed
            && medium_page
            && initially_full
            && initially_unmapped
            && abandoned_before_free
            && pretransition_remained_unmapped
            && reabandon_threshold_crossed
            && reabandoned_mapped_after_free
            && abandoned_after_free
            && bitmap_published_after
            && page_still_live
            && unowned_after_free;

        assert!(valid, "synthetic failed-reclaim tail violates the source threshold");
    }

    #[test]
    fn full_medium_or_large_aggregate_tail_accepts_each_regular_page_kind_after_the_owner_claim() {
        let medium_block_size =
            crate::config::SMALL_MAX_OBJ_SIZE + core::mem::size_of::<Block>();
        let large_block_size =
            crate::config::MEDIUM_MAX_OBJ_SIZE + core::mem::size_of::<Block>();
        assert_eq!(
            size_class::page_kind_for_block_size(medium_block_size),
            Some(PageKind::Medium),
            "the first aggregate member has the regular medium source kind"
        );
        assert_eq!(
            size_class::page_kind_for_block_size(large_block_size),
            Some(PageKind::Large),
            "the second aggregate member has the regular large source kind"
        );

        for (block_size, slice_count) in [
            (medium_block_size, 1usize),
            (
                large_block_size,
                crate::page::regular_page_slice_count(PageKind::Large)
                    .expect("large pages have their fixed source slice count"),
            ),
        ] {
            let bin = size_class::bin(block_size).expect("the regular member has an arena bin");
            assert!(bin < ARENA_BIN_COUNT);
            let mut storage = BitmapStorage::uninit();
            let mut arena = map_fixture_for_bin(&mut storage, bin);
            let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
            let mut page = Page::remote_free_test_page(4, 4);
            page.set_block_size(block_size);
            assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, slice_count) });
            let page_raw = abandon_full_unmapped(&mut page);
            let mut block = TestBlock([0; 16]);

            assert_eq!(
                unsafe {
                    free_full_medium_or_large_after_failed_reclaim_select_map(
                        page_raw,
                        block.pointer(),
                        |memory, selected_block_size| {
                            assert_eq!(memory.kind(), MemoryKind::Arena);
                            assert_eq!(selected_block_size, block_size);
                            view.abandoned_pages(bin)
                                .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                        },
                    )
                },
                Ok(FullMediumOrLargeAbandonedFreeAfterFailedReclaimResult::StillLive),
                "each member starts source-unmapped then follows free.c's normal collector"
            );
            assert!(view.abandoned_pages(bin).unwrap().is_published(17));
            assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
            assert_eq!(page.remote_free_test_head(), 0);
            assert_eq!(page.remote_free_test_used(), 3);
        }
    }

    #[test]
    fn full_large_aggregate_tail_uses_the_identity_selected_unmapped_and_mapped_paths() {
        let block_size = crate::config::MEDIUM_MAX_OBJ_SIZE + core::mem::size_of::<Block>();
        assert_eq!(
            size_class::page_kind_for_block_size(block_size),
            Some(PageKind::Large),
            "the aggregate helper owns only the regular large source class"
        );
        let bin = size_class::bin(block_size).expect("the large size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(4, 4);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 64) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let mut third = TestBlock([0; 16]);
        let mut fourth = TestBlock([0; 16]);

        assert_eq!(
            unsafe {
                free_full_large_after_failed_reclaim(page_raw, first.pointer(), block_size, &map)
            },
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(
            page.remote_free_test_head(),
            0,
            "large pages take free.c's ordinary collector rather than the small partial path"
        );
        assert_eq!(page.remote_free_test_used(), 3);

        for block in [second.pointer(), third.pointer()] {
            assert_eq!(
                unsafe { free_full_large_after_failed_reclaim(page_raw, block, block_size, &map) },
                Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::StillLive)
            );
            assert!(map.is_published(17));
            assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        }

        assert_eq!(
            unsafe {
                free_full_large_after_failed_reclaim(page_raw, fourth.pointer(), block_size, &map)
            },
            Ok(FullLargeAbandonedFreeAfterFailedReclaimResult::Empty)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn full_large_aggregate_tail_rejects_nonlarge_geometry_after_the_owner_claim() {
        let block_size = crate::config::SMALL_MAX_OBJ_SIZE + core::mem::size_of::<Block>();
        assert_eq!(
            size_class::page_kind_for_block_size(block_size),
            Some(PageKind::Medium),
            "the negative fixture must not enter the large source class"
        );
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(4, 4);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut block = TestBlock([0; 16]);

        assert_eq!(
            unsafe { free_full_large_after_failed_reclaim(page_raw, block.pointer(), block_size, &map) },
            Err(AbandonError::InvalidPageGeometry)
        );
        assert!(!map.is_published(17));
        assert_ne!(
            page.remote_free_test_head() & 1,
            0,
            "the source-shaped helper claims before it can validate ordinary metadata"
        );
    }

    #[test]
    fn full_non_direct_small_aggregate_tail_uses_normal_collection_after_its_unmapped_start() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        assert!(block_size <= crate::config::SMALL_MAX_OBJ_SIZE);
        assert_eq!(
            size_class::page_kind_for_block_size(block_size),
            Some(PageKind::Small),
            "the aggregate helper owns only the non-direct regular small source class"
        );
        let bin = size_class::bin(block_size).expect("the non-direct small size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(4, 4);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let mut third = TestBlock([0; 16]);
        let mut fourth = TestBlock([0; 16]);

        assert_eq!(
            unsafe {
                free_full_non_direct_small_after_failed_reclaim(
                    page_raw,
                    first.pointer(),
                    block_size,
                    &map,
                )
            },
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(
            page.remote_free_test_head(),
            0,
            "non-direct small must take free.c's normal collector, never the direct-small partial head"
        );

        for block in [second.pointer(), third.pointer()] {
            assert_eq!(
                unsafe {
                    free_full_non_direct_small_after_failed_reclaim(page_raw, block, block_size, &map)
                },
                Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
            );
            assert!(map.is_published(17));
        }

        assert_eq!(
            unsafe {
                free_full_non_direct_small_after_failed_reclaim(
                    page_raw,
                    fourth.pointer(),
                    block_size,
                    &map,
                )
            },
            Ok(FullNonDirectSmallAbandonedFreeAfterFailedReclaimResult::Empty)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn full_non_direct_small_aggregate_tail_rejects_direct_small_geometry_after_owner_claim() {
        let block_size = crate::config::SMALL_SIZE_MAX;
        assert_eq!(
            size_class::page_kind_for_block_size(block_size),
            Some(PageKind::Small),
            "the negative fixture stays in the broad small kind but is direct-sized"
        );
        let bin = size_class::bin(block_size).expect("the direct-small size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(4, 4);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut block = TestBlock([0; 16]);

        assert_eq!(
            unsafe {
                free_full_non_direct_small_after_failed_reclaim(
                    page_raw,
                    block.pointer(),
                    block_size,
                    &map,
                )
            },
            Err(AbandonError::InvalidPageGeometry)
        );
        assert!(!map.is_published(17));
        assert_ne!(
            page.remote_free_test_head() & 1,
            0,
            "the helper must claim before validating the sealed non-direct-small class"
        );
    }

    #[test]
    fn full_direct_small_aggregate_tail_preserves_partial_head_and_delays_mapping() {
        let block_size = crate::config::SMALL_SIZE_MAX;
        assert_eq!(
            size_class::page_kind_for_block_size(block_size),
            Some(PageKind::Small),
            "the aggregate helper owns the direct regular small source class"
        );
        let bin = size_class::bin(block_size).expect("the direct-small size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(16, 16);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let mut third = TestBlock([0; 16]);
        let mut fourth = TestBlock([0; 16]);

        assert_eq!(
            unsafe {
                free_full_direct_small_after_failed_reclaim(
                    page_raw,
                    first.pointer(),
                    block_size,
                    &map,
                )
            },
            Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(
            page.remote_free_test_head(),
            first.pointer().as_ptr().expose_provenance(),
            "the direct aggregate keeps its just-published partial head"
        );
        assert_eq!(page.remote_free_test_used(), 16);

        for block in [second.pointer(), third.pointer()] {
            assert_eq!(
                unsafe {
                    free_full_direct_small_after_failed_reclaim(page_raw, block, block_size, &map)
                },
                Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
            );
            assert!(!map.is_published(17));
            assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        }

        assert_eq!(
            unsafe {
                free_full_direct_small_after_failed_reclaim(
                    page_raw,
                    fourth.pointer(),
                    block_size,
                    &map,
                )
            },
            Ok(FullDirectSmallAbandonedFreeAfterFailedReclaimResult::StillLive)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 12);
    }

    #[test]
    fn full_direct_small_aggregate_tail_rejects_non_direct_geometry_after_owner_claim() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        assert_eq!(
            size_class::page_kind_for_block_size(block_size),
            Some(PageKind::Small),
            "the negative fixture stays in the broad small kind but is non-direct"
        );
        let bin = size_class::bin(block_size).expect("the non-direct-small size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(16, 16);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut block = TestBlock([0; 16]);

        assert_eq!(
            unsafe {
                free_full_direct_small_after_failed_reclaim(
                    page_raw,
                    block.pointer(),
                    block_size,
                    &map,
                )
            },
            Err(AbandonError::InvalidPageGeometry)
        );
        assert!(!map.is_published(17));
        assert_ne!(
            page.remote_free_test_head() & 1,
            0,
            "the helper must claim before validating the sealed direct-small class"
        );
    }

    #[test]
    fn unmapped_abandoned_free_selects_terminal_empty_without_releasing_metadata() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(1, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = abandon_full_unmapped(&mut page);
        let mut block = TestBlock([0; 16]);

        assert_eq!(
            unsafe { free_unmapped_after_failed_reclaim(page_raw, block.pointer(), &map) },
            Ok(UnmappedAbandonedFreeResult::Empty)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn failed_expected_head_unown_collects_new_publication_without_a_second_reclaim() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 16);
        let page_raw = abandon_full_unmapped(&mut page);
        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        let mut owner_local_collections = 0;

        assert_eq!(
            unsafe {
                free_unmapped_after_failed_reclaim_with(
                    page_raw,
                    first.pointer(),
                    &map,
                    || {
                        assert_eq!(
                            remote_free::push_abandoned(page_raw, second.pointer()),
                            Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner)
                        );
                    },
                    |_page| {
                        owner_local_collections += 1;
                        Ok(())
                    },
                )
            },
            Ok(UnmappedAbandonedFreeResult::UnownedUnmapped)
        );
        assert_eq!(
            owner_local_collections, 2,
            "each remote-list collection must complete free.c's false local phase before the next unown decision"
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 14);
        assert_eq!(page.remote_free_test_local_chain_len(3), 2);
    }

    #[test]
    fn mapped_expected_head_unown_recollects_the_owner_local_phase_before_release() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(16, 2);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut raced_block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { remote_free::push_abandoned(page_raw, raced_block.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );
        let state = unsafe { Page::abandonment_state_at(page_raw) };
        let mut owner_local_collections = 0;
        let mut collect_owner_deferred_frees = |_page| {
            owner_local_collections += 1;
            Ok(())
        };

        assert_eq!(
            unown_mapped_from_free_with_owner_deferred_collection(
                page_raw,
                &state,
                &map,
                0,
                &mut collect_owner_deferred_frees,
            ),
            Ok(MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped)
        );
        assert_eq!(
            owner_local_collections, 1,
            "a raced mapped publication must run free.c's false local phase before its owner bit is released"
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 1);
    }

    #[test]
    fn mapped_abandoned_free_reclaims_to_its_same_origin_after_collection() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let mut theap = Theap::empty();
        let target = bind_adopting_theap(&mut heap, &mut tld, &mut theap, thread_id);
        let mut page = mapped_page(&mut arena, 3);
        page.abandoned_test_set_theap(target.as_ptr());
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_and_reclaim(page_raw, block.pointer(), &map, target, thread_id) },
            Ok(MappedAbandonedFreeResult::Reclaimed {
                collected_remote_blocks: 1,
            })
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), thread_id.get());
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.remote_free_test_used(), 2);
    }

    #[test]
    fn mapped_abandoned_free_leaves_a_block_with_the_existing_owner() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let mut theap = Theap::empty();
        let target = bind_adopting_theap(&mut heap, &mut tld, &mut theap, thread_id);
        let mut page = mapped_page(&mut arena, 3);
        page.abandoned_test_set_theap(target.as_ptr());
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        assert_eq!(
            unsafe { remote_free::push_abandoned(page_raw, first.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );
        assert_eq!(
            unsafe {
                free_mapped_and_reclaim(page_raw, second.pointer(), &map, target, thread_id)
            },
            Ok(MappedAbandonedFreeResult::PublishedToExistingOwner)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head() & 1, 1);
    }

    #[test]
    fn mapped_abandoned_free_reports_empty_with_terminal_owner_retained() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let mut theap = Theap::empty();
        let target = bind_adopting_theap(&mut heap, &mut tld, &mut theap, thread_id);
        let mut page = mapped_page(&mut arena, 1);
        page.abandoned_test_set_theap(target.as_ptr());
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_and_reclaim(page_raw, block.pointer(), &map, target, thread_id) },
            Ok(MappedAbandonedFreeResult::Empty)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), 0);
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn mapped_medium_free_after_failed_reclaim_preserves_then_releases_the_route() {
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(16, 2);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        assert!(map.is_published(17));

        let mut first = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_after_failed_reclaim(page_raw, first.pointer(), &map) },
            Ok(MappedAbandonedFreeAfterFailedReclaimResult::UnownedMapped)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
        assert_eq!(page.remote_free_test_used(), 1);

        let mut second = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_after_failed_reclaim(page_raw, second.pointer(), &map) },
            Ok(MappedAbandonedFreeAfterFailedReclaimResult::Empty)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn mapped_one_block_owner_exit_free_retains_a_nonempty_medium_page() {
        let block_size = crate::config::SMALL_MAX_OBJ_SIZE + 1;
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(3, 2);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_one_block_to_empty(page_raw, block.pointer(), &map) },
            Err(AbandonError::MappedPageNotEmpty)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head() & 1, 1);
        assert_eq!(page.remote_free_test_used(), 1);
    }

    #[test]
    fn mapped_direct_one_block_owner_exit_free_collects_its_final_head_then_releases() {
        let block_size = crate::config::SMALL_SIZE_MAX;
        let bin = size_class::bin(block_size).expect("the direct-small size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(16, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        assert!(map.is_published(17));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_direct_one_block_to_empty(page_raw, block.pointer(), &map) },
            Ok(MappedAbandonedFreeToEmptyResult::Empty)
        );
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn mapped_direct_one_block_owner_exit_free_rejects_small_geometry_without_source_reserve() {
        let block_size = crate::config::SMALL_SIZE_MAX;
        let bin = size_class::bin(block_size).expect("the direct-small size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(15, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        assert!(map.is_published(17));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_direct_one_block_to_empty(page_raw, block.pointer(), &map) },
            Err(AbandonError::InvalidPageGeometry)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head() & 1, 1);
        assert_eq!(page.remote_free_test_used(), 1);
    }

    #[test]
    fn mapped_abandoned_free_rejects_a_small_page_without_the_source_reserve() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let mut theap = Theap::empty();
        let target = bind_adopting_theap(&mut heap, &mut tld, &mut theap, thread_id);
        let mut page = Page::remote_free_test_page(4, 3);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        page.abandoned_test_set_theap(target.as_ptr());
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { free_mapped_and_reclaim(page_raw, block.pointer(), &map, target, thread_id) },
            Err(AbandonError::InvalidPageGeometry)
        );
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head() & 1, 1);
    }

    #[test]
    fn abandoned_arena_page_is_published_before_it_becomes_unowned() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 3);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
        assert!(map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED_MAPPED);
        assert_eq!(page.remote_free_test_head(), 0);
    }

    #[test]
    fn full_or_non_arena_pages_abandon_unmapped() {
        let mut page = Page::remote_free_test_page(3, 3);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(
            unsafe { abandon(page_raw, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::UnownedUnmapped)
        );
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), 0);
    }

    #[test]
    fn partial_arena_singleton_bin_abandons_unmapped() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let mut page = mapped_page(&mut arena, 1);
        // `MI_BIN_HUGE` is outside `pages_abandoned[0..ARENA_BIN_COUNT]`.
        // The page remains partial, but `arena.c` must leave it unmapped.
        page.set_block_size(crate::config::LARGE_MAX_OBJ_SIZE + 1);
        assert!(size_class::bin(page.block_size()).unwrap() >= ARENA_BIN_COUNT);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(
            unsafe { abandon(page_raw, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::UnownedUnmapped)
        );
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_eq!(page.remote_free_test_head(), 0);
    }

    #[test]
    fn empty_page_reports_terminal_release_without_reusing_metadata() {
        let mut page = Page::remote_free_test_page(2, 0);
        let page_raw = NonNull::from(&mut page);

        assert_eq!(
            unsafe { abandon(page_raw, None::<&ArenaAbandonedPages<'_>>) },
            Ok(AbandonResult::Empty)
        );
        assert_eq!(page.remote_free_test_head(), 1);
        assert_eq!(page.abandoned_test_thread_id(), 12);
    }

    #[test]
    fn failed_adoption_republishes_the_bitmap_before_the_reader_returns() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let mut page = mapped_page(&mut arena, 3);
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        assert_eq!(
            unsafe { remote_free::push_abandoned(page_raw, block.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut target_heap = Heap::bootstrap_empty();
        let mut target_tld = ThreadLocalData::detached();
        let mut target_theap = Theap::empty();
        let target = bind_adopting_theap(
            &mut target_heap,
            &mut target_tld,
            &mut target_theap,
            thread_id,
        );
        assert_eq!(
            unsafe { try_adopt(&map, 0, target, thread_id, |_| Some(page_raw)) },
            Ok(None)
        );
        assert!(map.is_published(17));
        assert_eq!(page.remote_free_test_head() & 1, 1);
    }

    #[test]
    fn rejected_adoption_republishes_before_terminal_release_retains_its_owner() {
        // Deterministically schedule the source race from
        // `arena.c:655-671` against `free.c:487-514`: the terminal free has
        // acquired the abandoned low bit, an allocation-side bitmap reader
        // observes that ownership and restores its claimed bit, and only then
        // may `mi_abandoned_page_try_free` unabandon and hand the unique
        // owner to its terminal release policy.
        let block_size = crate::config::SMALL_SIZE_MAX + core::mem::size_of::<Block>();
        let bin = size_class::bin(block_size).expect("the medium size has an arena bin");
        assert!(bin < ARENA_BIN_COUNT);
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture_for_bin(&mut storage, bin);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(bin).unwrap();
        let mut page = Page::remote_free_test_page(2, 1);
        page.set_block_size(block_size);
        assert!(unsafe { page.abandoned_test_set_arena_memory(&mut arena, 17, 1) });
        let page_raw = NonNull::from(&mut page);
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let thread_id = LiveThreadId::new(16).unwrap();
        let mut target_heap = Heap::bootstrap_empty();
        let mut target_tld = ThreadLocalData::detached();
        let mut target_theap = Theap::empty();
        let target = bind_adopting_theap(
            &mut target_heap,
            &mut target_tld,
            &mut target_theap,
            thread_id,
        );
        let mut block = TestBlock([0; 16]);
        let reclaim_resolver_calls = Cell::new(0usize);
        let reclaim_rejected = Cell::new(false);
        let terminal_calls = Cell::new(0usize);

        assert_eq!(
            unsafe {
                free_post_owner_exit_regular_page(
                    page_raw,
                    block.pointer(),
                    |memory, selected_block_size| {
                        assert_eq!(memory.kind(), MemoryKind::Arena);
                        assert_eq!(selected_block_size, block_size);
                        view.abandoned_pages(bin)
                            .ok_or(AbandonError::ArenaBitmapDoesNotMatchPage)
                    },
                    |_page| {
                        // This callback is after the winning AcqRel
                        // publication and source collection, but before the
                        // all-free `unabandon` transition. The competing
                        // reclaim may inspect only the atomic owner word; a
                        // rejected claim must restore the bitmap for the
                        // terminal reader/quiescence handoff.
                        match try_adopt_retained(&map, 0, target, thread_id, |slice_index| {
                            assert_eq!(slice_index, 17);
                            reclaim_resolver_calls
                                .set(reclaim_resolver_calls.get() + 1);
                            Some(page_raw)
                        }) {
                            Ok(None) => reclaim_rejected.set(true),
                            Ok(Some(_)) => panic!(
                                "a terminal-free owner must reject concurrent abandoned-page adoption"
                            ),
                            Err(failure) => panic!(
                                "a rejected adoption must restore the bitmap, not retain a second owner: {:?}",
                                failure.error()
                            ),
                        }
                        assert!(
                            map.is_published(17),
                            "the rejected arena claim restores its bit before terminal unabandon"
                        );
                        assert_ne!(
                            page_raw.as_ref().remote_free_test_head() & THREAD_FREE_OWNED,
                            0,
                            "the terminal free keeps the sole abandoned owner through the reader race"
                        );
                        Ok(())
                    },
                    |_page| {
                        assert!(reclaim_rejected.get());
                        assert_eq!(reclaim_resolver_calls.get(), 1);
                        assert!(
                            !map.is_published(17),
                            "terminal release clears the republished bit only after the rejecting reader returns"
                        );
                        assert_ne!(
                            page_raw.as_ref().remote_free_test_head() & THREAD_FREE_OWNED,
                            0,
                            "the terminal policy receives the same unique low-bit owner"
                        );
                        terminal_calls.set(terminal_calls.get() + 1);
                        // Model an OS/PageMap terminal failure: the source
                        // low-bit owner remains intact rather than becoming a
                        // reusable page after the rejected reclaim.
                        PostOwnerExitTerminalRelease::Retained
                    },
                )
            },
            Ok(PostOwnerExitRegularFreeResult::TerminalReleaseRetained)
        );
        assert!(reclaim_rejected.get());
        assert_eq!(reclaim_resolver_calls.get(), 1);
        assert_eq!(terminal_calls.get(), 1);
        assert!(!map.is_published(17));
        assert_eq!(page.abandoned_test_thread_id(), THREAD_ID_ABANDONED);
        assert_ne!(page.remote_free_test_head() & THREAD_FREE_OWNED, 0);
        assert_eq!(page.remote_free_test_used(), 0);
    }

    #[test]
    fn successful_adoption_reassociates_and_collects_remote_frees() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let page = ConcurrentPage(mapped_page(&mut arena, 3));
        let page_raw = page.pointer();
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut target_heap = Heap::bootstrap_empty();
        let mut target_tld = ThreadLocalData::detached();
        let mut target_theap = Theap::empty();
        let target = bind_adopting_theap(
            &mut target_heap,
            &mut target_tld,
            &mut target_theap,
            thread_id,
        );
        let adopter_claimed = Arc::new(Barrier::new(2));
        let producer_published = Arc::new(Barrier::new(2));
        let page_for_producer = &page;
        let map_for_adopter = &map;
        let block_for_producer = &mut block;
        let adopted = thread::scope(|scope| {
            let claim_for_producer = Arc::clone(&adopter_claimed);
            let published_for_producer = Arc::clone(&producer_published);
            scope.spawn(move || {
                claim_for_producer.wait();
                assert_eq!(
                    unsafe {
                        remote_free::push_abandoned(
                            page_for_producer.pointer(),
                            block_for_producer.pointer(),
                        )
                    },
                    Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner)
                );
                published_for_producer.wait();
            });
            unsafe {
                try_adopt_with(
                    map_for_adopter,
                    0,
                    target,
                    thread_id,
                    |_| Some(page_raw),
                    || {
                        adopter_claimed.wait();
                        producer_published.wait();
                    },
                    || {},
                )
            }
            .unwrap()
            .expect("the mapped unowned page is adoptable")
        });

        assert_eq!(adopted.page(), page_raw);
        assert_eq!(adopted.collected_remote_blocks(), 1);
        assert_eq!(page.0.abandoned_test_thread_id(), thread_id.get());
        assert_eq!(page.0.remote_free_test_head(), 1);
        assert_eq!(page.0.remote_free_test_used(), 2);
        assert!(!map.is_published(17));
    }

    #[test]
    fn producer_between_abandoned_and_live_adoption_collections_is_drained_live() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let page = ConcurrentPage(mapped_page(&mut arena, 3));
        let page_raw = page.pointer();
        assert_eq!(unsafe { abandon(page_raw, Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut block = TestBlock([0; 16]);
        let thread_id = LiveThreadId::new(16).unwrap();
        let mut target_heap = Heap::bootstrap_empty();
        let mut target_tld = ThreadLocalData::detached();
        let mut target_theap = Theap::empty();
        let target = bind_adopting_theap(
            &mut target_heap,
            &mut target_tld,
            &mut target_theap,
            thread_id,
        );
        let abandoned_collected = Arc::new(Barrier::new(2));
        let producer_published = Arc::new(Barrier::new(2));
        let page_for_producer = &page;
        let map_for_adopter = &map;
        let block_for_producer = &mut block;
        let adopted = thread::scope(|scope| {
            let collected_for_producer = Arc::clone(&abandoned_collected);
            let published_for_producer = Arc::clone(&producer_published);
            scope.spawn(move || {
                collected_for_producer.wait();
                assert_eq!(
                    unsafe {
                        remote_free::push_abandoned(
                            page_for_producer.pointer(),
                            block_for_producer.pointer(),
                        )
                    },
                    Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner)
                );
                published_for_producer.wait();
            });
            unsafe {
                try_adopt_with(
                    map_for_adopter,
                    0,
                    target,
                    thread_id,
                    |_| Some(page_raw),
                    || {},
                    || {
                        abandoned_collected.wait();
                        producer_published.wait();
                    },
                )
            }
            .unwrap()
            .expect("the mapped unowned page is adoptable")
        });

        assert_eq!(adopted.page(), page_raw);
        assert_eq!(adopted.collected_remote_blocks(), 1);
        assert_eq!(page.0.abandoned_test_thread_id(), thread_id.get());
        assert_eq!(page.0.remote_free_test_head(), 1);
        assert_eq!(page.0.remote_free_test_used(), 2);
        assert!(!map.is_published(17));
    }

    #[test]
    fn producer_between_unown_observation_and_cas_is_collected_before_release() {
        let mut storage = BitmapStorage::uninit();
        let mut arena = map_fixture(&mut storage);
        let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
        let map = view.abandoned_pages(1).unwrap();
        let page = ConcurrentPage(mapped_page(&mut arena, 3));
        assert_eq!(unsafe { abandon(page.pointer(), Some(&map)) }, Ok(AbandonResult::UnownedMapped));

        let mut first = TestBlock([0; 16]);
        let mut second = TestBlock([0; 16]);
        assert_eq!(
            unsafe { remote_free::push_abandoned(page.pointer(), first.pointer()) },
            Ok(remote_free::AbandonedRemotePush::ClaimedUnownedPage)
        );
        let owner_observed_empty = Arc::new(Barrier::new(2));
        let producer_published = Arc::new(Barrier::new(2));
        let page = &page;
        let map = &map;
        let second_for_producer = &mut second;

        thread::scope(|scope| {
            let owner_for_producer = Arc::clone(&owner_observed_empty);
            let published_for_producer = Arc::clone(&producer_published);
            scope.spawn(move || {
                owner_for_producer.wait();
                assert_eq!(
                    unsafe {
                        remote_free::push_abandoned(page.pointer(), second_for_producer.pointer())
                    },
                    Ok(remote_free::AbandonedRemotePush::PublishedToExistingOwner)
                );
                published_for_producer.wait();
            });
            assert_eq!(
                unown_with(page.pointer(), Some(map), || {
                    owner_observed_empty.wait();
                    producer_published.wait();
                }),
                Ok(AbandonResult::UnownedMapped)
            );
        });

        assert_eq!(page.0.remote_free_test_head(), 0);
        assert_eq!(page.0.remote_free_test_used(), 1);
        assert_eq!(page.0.remote_free_test_local_chain_len(3), 2);
    }
}
