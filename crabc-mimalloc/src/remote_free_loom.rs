//! Finite Loom evidence for the source-shaped `mi_thread_free_t` atomic head.
//!
//! The production remote list stores native block pointers, and the owner
//! mutates `used`/`local_free` after detaching it. Those raw-pointer lifetime
//! and owner-only fields are outside Loom's address-free scheduler model.
//! This module instead gives each producer-owned block one unique aligned
//! integer identity and a modeled `next` word. It executes
//! [`super::publish_to_head`], [`super::detach_from_head`],
//! [`super::claim_abandoned_owner_with`], and
//! [`super::try_unown_abandoned_head_with`], and
//! [`super::try_unown_abandoned_expected_head_with`] directly, so the production
//! Relaxed load, AcqRel OR, and AcqRel/Acquire weak-CAS transitions cannot
//! drift from this evidence. The compact lifetime-word models likewise call
//! [`super::begin_live_remote_page_publication_with`],
//! [`super::finish_live_remote_page_publication_with`],
//! [`super::begin_live_remote_page_owner_collection_with`],
//! [`super::retain_live_remote_page_terminal_with`],
//! [`super::begin_live_remote_page_retirement_with`], and
//! [`super::reinitialize_live_remote_page_with`] directly. This keeps their
//! acquire/AcqRel publication, owner-close, and generation transitions tied to
//! the production boundary rather than to a geometry-specific free route.
//!
//! It proves the low-bit head races for live-owner collection and bounded
//! abandoned-page claim/unown. The lifetime model below also mirrors the
//! external proof required by `PageMap::checked_lookup`/
//! `PageMap::unregister_range`, `PageMapRoot::clear`,
//! `abandoned::abandon_after_collect`, and the terminal `release_page` fault
//! seam: a source publisher lease prevents owner exit and final release; an
//! owner exit first collects, publishes the abandoned identity, and unowns;
//! a final release first unregisters the page and then either releases once
//! or retains one terminal owner after the injected failure.
//! A separate two-producer witness composes those transitions with a terminal
//! consumer low-bit claim. Its deliberately fixed terminal shape has no
//! client-count ledger or owner registry: the two address-free source blocks,
//! one page-local publication word, and the source head are sufficient to
//! establish the owner-exit and terminal-claim ordering.
//!
//! These are intentionally page-geometry-free models. They neither select a
//! bin nor an arena/OS route, and they do not pretend that `PageMap`'s plain
//! entries are atomics. Instead, `PageMapLifetimeModel` is the explicit
//! external lifetime/exclusion obligation those plain entries require. Run
//! this module with:
//!
//! `./scripts/dev.sh test -p crabc-mimalloc --lib --features loom loom_ -- --test-threads=1`

use super::{
    AbandonedExpectedHeadTransition, AbandonedOwnerClaim, AbandonedOwnerHeadTransition,
    LiveRemoteFreePageOwnerCollectionError,
    LiveRemoteFreePagePublicationError, LiveRemoteFreePageReinitializeError,
    LiveRemoteFreePageRetirementError, RemoteFreeError, ThreadFree, THREAD_FREE_OWNED,
    begin_live_remote_page_owner_collection_with,
    begin_live_remote_page_publication_with,
    begin_live_remote_page_retirement_with, claim_abandoned_owner_with,
    detach_from_head, finish_live_remote_page_publication_with, live_remote_page_word,
    publish_to_head, publish_to_head_with_owner, reinitialize_live_remote_page_with,
    retain_live_remote_page_terminal_with,
    thread_free_block_address,
    try_unown_abandoned_expected_head_with, try_unown_abandoned_head_with,
};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::mpsc;
use loom::thread;

const PRODUCER_COUNT: usize = 2;
const OWNER_EMPTY_HEAD: ThreadFree = THREAD_FREE_OWNED;

/// Test-only adapter for the narrow production `ThreadFreeHead` boundary.
/// The orderings match `crate::atomic::word_load_relaxed` and
/// `word_cas_weak_acq_rel` exactly.
impl super::ThreadFreeHead for AtomicUsize {
    #[inline]
    fn load_relaxed(&self) -> ThreadFree {
        self.load(Ordering::Relaxed)
    }

    #[inline]
    fn cas_weak_acq_rel(&self, expected: &mut ThreadFree, replacement: ThreadFree) -> bool {
        self.compare_exchange_weak(
            *expected,
            replacement,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
    }

    #[inline]
    fn fetch_or_acq_rel(&self, value: ThreadFree) -> ThreadFree {
        self.fetch_or(value, Ordering::AcqRel)
    }
}

/// Test-only adapter for the compact production lifetime word. Its ordering
/// surface exactly mirrors `LiveRemoteFreePageLifetimeWord` on `AtomicWord`.
impl super::LiveRemoteFreePageLifetimeWord for AtomicUsize {
    #[inline]
    fn load_acquire(&self) -> usize {
        self.load(Ordering::Acquire)
    }

    #[inline]
    fn cas_weak_acq_rel(&self, expected: &mut usize, replacement: usize) -> bool {
        self.compare_exchange_weak(
            *expected,
            replacement,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
    }

    #[inline]
    fn fetch_sub_acq_rel(&self, value: usize) -> usize {
        self.fetch_sub(value, Ordering::AcqRel)
    }
}

struct ModelBlocks {
    /// Each producer owns exactly one link slot. It is initialized before the
    /// producer's release half of the shared-head compare/exchange, matching
    /// the source block first-word store.
    next: [AtomicUsize; PRODUCER_COUNT],
    published: [AtomicBool; PRODUCER_COUNT],
    collected: [AtomicBool; PRODUCER_COUNT],
}

impl ModelBlocks {
    fn new() -> Self {
        Self {
            next: core::array::from_fn(|_| AtomicUsize::new(0)),
            published: core::array::from_fn(|_| AtomicBool::new(false)),
            collected: core::array::from_fn(|_| AtomicBool::new(false)),
        }
    }

    /// Models the aligned pointer bit pattern of a distinct block. Zero is
    /// the empty-list terminator and bit zero remains available for ownership.
    const fn address(index: usize) -> ThreadFree {
        (index + 1) << 1
    }

    fn index(address: ThreadFree) -> usize {
        assert_ne!(address, 0, "the source list terminator is not a block");
        assert_eq!(address & THREAD_FREE_OWNED, 0, "model block remains aligned");
        let index = (address >> 1) - 1;
        assert!(index < PRODUCER_COUNT, "detached list has a known producer block");
        index
    }

    fn publish(&self, head: &AtomicUsize, index: usize) {
        let block = Self::address(index);
        publish_to_head(head, block, |previous_block| {
            self.next[index].store(previous_block, Ordering::Relaxed);
        })
        .expect("the model keeps the page owner-associated");
        self.published[index].store(true, Ordering::Release);
    }

    /// Executes the production `allow_collect=true` publication policy and
    /// returns whether the successfully replaced word already had an owner.
    fn publish_abandoned(&self, head: &AtomicUsize, index: usize) -> bool {
        let block = Self::address(index);
        let was_owned = publish_to_head_with_owner(
            head,
            block,
            |_| true,
            |previous_block| {
                self.next[index].store(previous_block, Ordering::Relaxed);
            },
        )
        .expect("the abandoned publisher may claim an unowned page");
        self.published[index].store(true, Ordering::Release);
        was_owned
    }

    fn collect_once(&self, head: &AtomicUsize) -> usize {
        let detached = detach_from_head(head).expect("the model preserves ownership");
        assert_eq!(
            detached & THREAD_FREE_OWNED,
            THREAD_FREE_OWNED,
            "every detached source head retains its low owner bit"
        );

        let mut count = 0;
        let mut block = thread_free_block_address(detached);
        while block != 0 {
            let index = Self::index(block);
            assert!(
                !self.collected[index].swap(true, Ordering::AcqRel),
                "each remote block is detached and collected at most once"
            );
            count += 1;
            block = self.next[index].load(Ordering::Relaxed);
        }
        count
    }

    fn assert_all_collected(&self) {
        for index in 0..PRODUCER_COUNT {
            assert!(
                self.published[index].load(Ordering::Acquire),
                "the producer completed its source publication"
            );
            assert!(
                self.collected[index].load(Ordering::Acquire),
                "the owner collected that remote block exactly once"
            );
        }
    }

    fn assert_collected(&self, index: usize) {
        assert!(
            self.published[index].load(Ordering::Acquire),
            "the producer completed its source publication"
        );
        assert!(
            self.collected[index].load(Ordering::Acquire),
            "the owner collected that remote block exactly once"
        );
    }
}

// The low two bits identify the abstract PageMap/page lifecycle phase. Every
// live source publisher owns one `LIFETIME_PUBLISHER` unit until it has made
// its `mi_free_block_mt` publication and finished every PageMap/metadata
// access. This is an intentionally small model of the *external* exclusion
// contract documented on `PageMap::checked_lookup` and
// `PageMap::unregister_range`; production PageMap entries remain source-plain.
const LIFETIME_PHASE_MASK: usize = 0b11;
const LIFETIME_LIVE: usize = 0;
const LIFETIME_ABANDONED: usize = 1;
const LIFETIME_RELEASING: usize = 2;
const LIFETIME_PUBLISHER: usize = 1 << 2;

const MODEL_ROOT_PUBLISHED: usize = 1;
const MODEL_ENTRY_PUBLISHED: usize = 1;
const MODEL_ENTRY_UNREGISTERED: usize = 0;
const MODEL_METADATA_LIVE: usize = 0;
const MODEL_METADATA_RELEASED: usize = 1;
const MODEL_OWNER_LIVE: usize = 2;
const MODEL_OWNER_ABANDONED: usize = 4;
const MODEL_TERMINAL_READY: usize = 0;
const MODEL_TERMINAL_RELEASING: usize = 1;
const MODEL_TERMINAL_RELEASED: usize = 2;
const MODEL_TERMINAL_RETAINED: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelTerminalRelease {
    /// One client is still live, or a publisher still owns the PageMap proof.
    NotReady,
    /// Another source-equivalent terminal path already owns the transition.
    AlreadyClaimed,
    /// The last page entry, page metadata, and PageMap root released in order.
    Released,
    /// The injected failure occurred after PageMap unregistration; one
    /// terminal owner retains the remaining metadata/mapping obligation.
    RetainedAfterUnregister,
}

/// A finite abstraction of the page/client lifetime relation from
/// `native-mimalloc.md` §4.5. It is not a production allocator state machine:
/// it states the cross-module proof that lets the real source-shaped atomics
/// below operate on plain PageMap entries without a dangling producer.
///
/// `begin_live_remote_publication` and `begin_post_exit_publication` model
/// the caller's PageMap lookup-to-atomic-publication lifetime. `begin_owner_exit`
/// models the point before `abandoned::abandon_after_collect`, while
/// `try_terminal_release` mirrors the `release_page` order after an exact
/// final free: unregister first, retain on a post-unregister fault, otherwise
/// clear the root and release the metadata exactly once.
struct PageMapLifetimeModel {
    phase_and_publishers: AtomicUsize,
    page_map_root: AtomicUsize,
    page_map_entry: AtomicUsize,
    metadata: AtomicUsize,
    owner_identity: AtomicUsize,
    live_clients: AtomicUsize,
    terminal_state: AtomicUsize,
    terminal_release_count: AtomicUsize,
    retained_owner_count: AtomicUsize,
}

impl PageMapLifetimeModel {
    fn new(live_clients: usize) -> Self {
        Self {
            phase_and_publishers: AtomicUsize::new(LIFETIME_LIVE),
            // This symbolic non-null value models `PageMapRoot::publish`.
            // The model starts after the source page map is fully initialized
            // and published, because page-map construction is not a
            // remote-free protocol.
            page_map_root: AtomicUsize::new(MODEL_ROOT_PUBLISHED),
            page_map_entry: AtomicUsize::new(MODEL_ENTRY_PUBLISHED),
            metadata: AtomicUsize::new(MODEL_METADATA_LIVE),
            owner_identity: AtomicUsize::new(MODEL_OWNER_LIVE),
            live_clients: AtomicUsize::new(live_clients),
            terminal_state: AtomicUsize::new(MODEL_TERMINAL_READY),
            terminal_release_count: AtomicUsize::new(0),
            retained_owner_count: AtomicUsize::new(0),
        }
    }

    fn begin_live_remote_publication(&self) -> bool {
        self.begin_publication(LIFETIME_LIVE)
    }

    fn begin_post_exit_publication(&self) -> bool {
        self.begin_publication(LIFETIME_ABANDONED)
    }

    fn begin_publication(&self, expected_phase: usize) -> bool {
        let mut observed = self.phase_and_publishers.load(Ordering::Acquire);
        loop {
            if observed & LIFETIME_PHASE_MASK != expected_phase {
                return false;
            }
            match self.phase_and_publishers.compare_exchange_weak(
                observed,
                observed + LIFETIME_PUBLISHER,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // A release transition cannot start while this lease is
                    // represented in the same word. These are the exact
                    // observations a caller needs before it invokes
                    // `PageMap::checked_lookup` and `mi_free_block_mt`.
                    assert_eq!(
                        self.page_map_root.load(Ordering::Acquire),
                        MODEL_ROOT_PUBLISHED,
                        "a source publisher never observes a cleared PageMap root"
                    );
                    assert_eq!(
                        self.page_map_entry.load(Ordering::Acquire),
                        MODEL_ENTRY_PUBLISHED,
                        "a source publisher never observes an unregistered page"
                    );
                    assert_eq!(
                        self.metadata.load(Ordering::Acquire),
                        MODEL_METADATA_LIVE,
                        "a source publisher never observes released page metadata"
                    );
                    return true;
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn finish_publication(&self) {
        let previous = self
            .phase_and_publishers
            .fetch_sub(LIFETIME_PUBLISHER, Ordering::Release);
        assert!(
            previous & !LIFETIME_PHASE_MASK >= LIFETIME_PUBLISHER,
            "only a publisher lease may finish a publication"
        );
        assert_ne!(
            previous & LIFETIME_PHASE_MASK,
            LIFETIME_RELEASING,
            "a terminal release cannot overlap a source publisher"
        );
    }

    /// The owner may begin `_mi_theap_collect_abandon` only after every live
    /// source publisher has completed its atomic publication and stopped
    /// touching the PageMap entry. A successful transition retains the exact
    /// page lifetime for `collect` and `abandon_after_collect` below.
    fn begin_owner_exit(&self) -> bool {
        self.phase_and_publishers
            .compare_exchange(
                LIFETIME_LIVE,
                LIFETIME_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Mirrors `abandoned::set_thread_identity`'s Release CAS after the
    /// owner has run `mi_page_thread_free_collect`, then executes the exact
    /// production `mi_abandoned_page_unown` atomic transition.
    fn abandon_after_collect(&self, head: &AtomicUsize) {
        assert_eq!(
            self.phase_and_publishers.load(Ordering::Acquire),
            LIFETIME_ABANDONED,
            "only the exclusive owner-exit phase may publish an abandoned identity"
        );
        assert_eq!(
            head.load(Ordering::Acquire),
            OWNER_EMPTY_HEAD,
            "owner exit collects every remote list before it abandons the page"
        );

        let mut previous = self.owner_identity.load(Ordering::Relaxed);
        loop {
            assert_eq!(
                previous, MODEL_OWNER_LIVE,
                "the identity is changed exactly once from live to abandoned"
            );
            match self.owner_identity.compare_exchange_weak(
                previous,
                MODEL_OWNER_ABANDONED,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => previous = actual,
            }
        }

        let mut no_hook: Option<fn()> = None;
        assert_eq!(
            try_unown_abandoned_head_with(head, &mut no_hook),
            AbandonedOwnerHeadTransition::Released,
            "an empty abandoned page transfers its low owner bit before a future free"
        );
        assert_eq!(
            head.load(Ordering::Acquire),
            0,
            "the abandoned page is unowned only after its remote list is empty"
        );
    }

    /// Marks one exact client free complete only after its source publication
    /// and owner-side collection have made the block unreachable from the
    /// PageMap page. The model has a one-client page because geometry and
    /// count arithmetic are tested deterministically elsewhere.
    fn finish_one_client_free(&self) {
        assert_eq!(
            self.live_clients.fetch_sub(1, Ordering::Release),
            1,
            "the modeled client is freed exactly once"
        );
    }

    /// Models the terminal portion of `release_page`. A failure after
    /// `PageMap::unregister_range` may not recreate a map entry or retry the
    /// prior traversal: the source path retains exactly one terminal owner.
    fn try_terminal_release(
        &self,
        head: &AtomicUsize,
        fail_after_page_map_unregister: bool,
    ) -> ModelTerminalRelease {
        if self.live_clients.load(Ordering::Acquire) != 0 {
            return ModelTerminalRelease::NotReady;
        }
        if self
            .phase_and_publishers
            .compare_exchange(
                LIFETIME_ABANDONED,
                LIFETIME_RELEASING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return ModelTerminalRelease::AlreadyClaimed;
        }

        assert_eq!(
            head.load(Ordering::Acquire),
            0,
            "final release begins only after the abandoned owner bit and list are gone"
        );
        assert_eq!(
            self.owner_identity.load(Ordering::Acquire),
            MODEL_OWNER_ABANDONED,
            "final release follows the source abandoned identity publication"
        );
        assert!(
            self.terminal_state
                .compare_exchange(
                    MODEL_TERMINAL_READY,
                    MODEL_TERMINAL_RELEASING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok(),
            "the lifecycle transition grants exactly one terminal owner"
        );
        assert_eq!(
            self.page_map_entry.swap(MODEL_ENTRY_UNREGISTERED, Ordering::AcqRel),
            MODEL_ENTRY_PUBLISHED,
            "PageMap unregister runs once before metadata/mapping release"
        );

        if fail_after_page_map_unregister {
            assert_eq!(
                self.retained_owner_count
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire),
                Ok(0),
                "a post-unregister fault retains exactly one terminal owner"
            );
            self.terminal_state
                .store(MODEL_TERMINAL_RETAINED, Ordering::Release);
            return ModelTerminalRelease::RetainedAfterUnregister;
        }

        // This is the one-page equivalent of
        // `ProcessPageMapPostExitAccess::finish_after_all_pages_released`:
        // every publisher has left, the last entry is unregistered, so the
        // root may clear before the final metadata/mapping release.
        assert_eq!(
            self.page_map_root.swap(0, Ordering::AcqRel),
            MODEL_ROOT_PUBLISHED,
            "PageMapRoot::clear runs only after the last entry is unregistered"
        );
        assert_eq!(
            self.metadata
                .swap(MODEL_METADATA_RELEASED, Ordering::AcqRel),
            MODEL_METADATA_LIVE,
            "page metadata/mapping release runs once after PageMap unregister"
        );
        assert_eq!(
            self.terminal_release_count.fetch_add(1, Ordering::AcqRel),
            0,
            "the final physical release occurs exactly once"
        );
        self.terminal_state
            .store(MODEL_TERMINAL_RELEASED, Ordering::Release);
        ModelTerminalRelease::Released
    }

    fn assert_released_once(&self) {
        assert_eq!(
            self.phase_and_publishers.load(Ordering::Acquire),
            LIFETIME_RELEASING
        );
        assert_eq!(self.page_map_entry.load(Ordering::Acquire), MODEL_ENTRY_UNREGISTERED);
        assert_eq!(self.page_map_root.load(Ordering::Acquire), 0);
        assert_eq!(self.metadata.load(Ordering::Acquire), MODEL_METADATA_RELEASED);
        assert_eq!(self.terminal_state.load(Ordering::Acquire), MODEL_TERMINAL_RELEASED);
        assert_eq!(self.terminal_release_count.load(Ordering::Acquire), 1);
        assert_eq!(self.retained_owner_count.load(Ordering::Acquire), 0);
    }

    fn assert_retained_after_unregister(&self) {
        assert_eq!(
            self.phase_and_publishers.load(Ordering::Acquire),
            LIFETIME_RELEASING
        );
        assert_eq!(self.page_map_entry.load(Ordering::Acquire), MODEL_ENTRY_UNREGISTERED);
        assert_eq!(
            self.page_map_root.load(Ordering::Acquire),
            MODEL_ROOT_PUBLISHED,
            "an unfinished post-exit route must not clear its process PageMap root"
        );
        assert_eq!(
            self.metadata.load(Ordering::Acquire),
            MODEL_METADATA_LIVE,
            "the terminal owner retains metadata after the irreversible fault"
        );
        assert_eq!(self.terminal_state.load(Ordering::Acquire), MODEL_TERMINAL_RETAINED);
        assert_eq!(self.terminal_release_count.load(Ordering::Acquire), 0);
        assert_eq!(self.retained_owner_count.load(Ordering::Acquire), 1);
    }
}

/// Outcome of a terminal consumer racing to claim one already-unowned,
/// source-empty abandoned page.
///
/// The claim is the pinned `mi_page_claim_ownership` low-bit transition, not
/// an entry in an owner table. Only its winner may perform the terminal
/// PageMap/metadata release below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalConsumerClaimOutcome {
    Released,
    AlreadyClaimed,
}

/// Finite composed lifetime witness for two final live remote publications,
/// owner exit, and a competing terminal consumer claim.
///
/// This intentionally has no live-client count and no owner registry. The
/// test fixes the two modeled source blocks as the page's final clients; the
/// `phase_and_publishers` word is only the page-local lookup-to-publication
/// exclusion required before owner exit. Once the owner has collected those
/// exact blocks and unowned the source head, `claim_abandoned_owner_with`
/// alone chooses the sole terminal consumer. Page geometry and the production
/// `used` count remain outside this address-free Loom proof.
struct MultiProducerOwnerExitTerminalModel {
    phase_and_publishers: AtomicUsize,
    page_map_root: AtomicUsize,
    page_map_entry: AtomicUsize,
    metadata: AtomicUsize,
    owner_identity: AtomicUsize,
    terminal_release_count: AtomicUsize,
}

impl MultiProducerOwnerExitTerminalModel {
    fn new() -> Self {
        Self {
            phase_and_publishers: AtomicUsize::new(LIFETIME_LIVE),
            page_map_root: AtomicUsize::new(MODEL_ROOT_PUBLISHED),
            page_map_entry: AtomicUsize::new(MODEL_ENTRY_PUBLISHED),
            metadata: AtomicUsize::new(MODEL_METADATA_LIVE),
            owner_identity: AtomicUsize::new(MODEL_OWNER_LIVE),
            terminal_release_count: AtomicUsize::new(0),
        }
    }

    /// Acquires the one page-local lifetime pin required between a successful
    /// PageMap lookup and the source `mi_free_block_mt` publication.
    fn begin_live_remote_publication(&self) -> bool {
        let mut observed = self.phase_and_publishers.load(Ordering::Acquire);
        loop {
            if observed & LIFETIME_PHASE_MASK != LIFETIME_LIVE {
                return false;
            }
            match self.phase_and_publishers.compare_exchange_weak(
                observed,
                observed + LIFETIME_PUBLISHER,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    assert_eq!(
                        self.page_map_root.load(Ordering::Acquire),
                        MODEL_ROOT_PUBLISHED,
                        "a live producer observes the published PageMap root"
                    );
                    assert_eq!(
                        self.page_map_entry.load(Ordering::Acquire),
                        MODEL_ENTRY_PUBLISHED,
                        "a live producer observes its registered page"
                    );
                    assert_eq!(
                        self.metadata.load(Ordering::Acquire),
                        MODEL_METADATA_LIVE,
                        "a live producer observes live page metadata"
                    );
                    return true;
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn finish_live_remote_publication(&self) {
        let previous = self
            .phase_and_publishers
            .fetch_sub(LIFETIME_PUBLISHER, Ordering::Release);
        assert_eq!(
            previous & LIFETIME_PHASE_MASK,
            LIFETIME_LIVE,
            "the owner cannot begin exit while a source publisher is still pinned"
        );
        assert!(
            previous & !LIFETIME_PHASE_MASK >= LIFETIME_PUBLISHER,
            "only an admitted source producer releases one page-local pin"
        );
    }

    /// The source owner can leave only after every page-local publisher has
    /// completed. A failed first attempt is the important composed race: it
    /// proves no registry lookup or client-ledger scan is necessary to find
    /// the two in-flight producers.
    fn begin_owner_exit(&self) -> bool {
        self.phase_and_publishers
            .compare_exchange(
                LIFETIME_LIVE,
                LIFETIME_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Publishes the abandoned identity only after the real source head has
    /// detached every final remote block, then runs the exact source unown
    /// transition to transfer the low-bit claim to a future consumer.
    fn abandon_after_remote_collection(&self, head: &AtomicUsize) {
        assert_eq!(
            self.phase_and_publishers.load(Ordering::Acquire),
            LIFETIME_ABANDONED,
            "only the exclusive owner-exit phase may abandon this page"
        );
        assert_eq!(
            head.load(Ordering::Acquire),
            OWNER_EMPTY_HEAD,
            "owner exit unowns only after its source collection emptied the head"
        );
        assert_eq!(
            self.owner_identity.compare_exchange(
                MODEL_OWNER_LIVE,
                MODEL_OWNER_ABANDONED,
                Ordering::Release,
                Ordering::Acquire,
            ),
            Ok(MODEL_OWNER_LIVE),
            "owner exit publishes the abandoned identity exactly once"
        );

        let mut no_hook: Option<fn()> = None;
        assert_eq!(
            try_unown_abandoned_head_with(head, &mut no_hook),
            AbandonedOwnerHeadTransition::Released,
            "the empty source head transfers its low owner bit to a consumer"
        );
        assert_eq!(
            head.load(Ordering::Acquire),
            0,
            "owner exit leaves one unowned empty page for the terminal claim"
        );
    }

    /// Claims and releases the selected terminal-empty page.
    ///
    /// A losing consumer sees the source low bit already set and never reads
    /// PageMap or metadata state. The winner alone converts the abandoned
    /// page-local phase into the irreversible terminal release.
    fn terminal_consumer_claim_and_release(
        &self,
        head: &AtomicUsize,
    ) -> TerminalConsumerClaimOutcome {
        if claim_abandoned_owner_with(head) == AbandonedOwnerClaim::AlreadyOwned {
            return TerminalConsumerClaimOutcome::AlreadyClaimed;
        }

        assert_eq!(
            head.load(Ordering::Acquire),
            OWNER_EMPTY_HEAD,
            "the winning consumer retains the source low-bit claim through release"
        );
        assert_eq!(
            self.owner_identity.load(Ordering::Acquire),
            MODEL_OWNER_ABANDONED,
            "the terminal consumer follows owner-exit's abandoned identity"
        );
        assert_eq!(
            self.phase_and_publishers.compare_exchange(
                LIFETIME_ABANDONED,
                LIFETIME_RELEASING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(LIFETIME_ABANDONED),
            "the unique low-bit claimant owns the only terminal release transition"
        );
        assert_eq!(
            self.page_map_entry.swap(MODEL_ENTRY_UNREGISTERED, Ordering::AcqRel),
            MODEL_ENTRY_PUBLISHED,
            "terminal release unregisters the page before metadata retirement"
        );
        assert_eq!(
            self.page_map_root.swap(0, Ordering::AcqRel),
            MODEL_ROOT_PUBLISHED,
            "the sole page entry lets terminal release clear the PageMap root"
        );
        assert_eq!(
            self.metadata
                .swap(MODEL_METADATA_RELEASED, Ordering::AcqRel),
            MODEL_METADATA_LIVE,
            "terminal release retires metadata after PageMap removal"
        );
        assert_eq!(
            self.terminal_release_count.fetch_add(1, Ordering::AcqRel),
            0,
            "exactly one terminal consumer reaches physical release"
        );
        TerminalConsumerClaimOutcome::Released
    }

    fn assert_terminal_release_once(&self, head: &AtomicUsize) {
        assert_eq!(
            self.phase_and_publishers.load(Ordering::Acquire),
            LIFETIME_RELEASING
        );
        assert_eq!(
            self.owner_identity.load(Ordering::Acquire),
            MODEL_OWNER_ABANDONED
        );
        assert_eq!(
            head.load(Ordering::Acquire),
            OWNER_EMPTY_HEAD,
            "the terminal owner still holds the sole source low-bit claim"
        );
        assert_eq!(self.page_map_entry.load(Ordering::Acquire), MODEL_ENTRY_UNREGISTERED);
        assert_eq!(self.page_map_root.load(Ordering::Acquire), 0);
        assert_eq!(self.metadata.load(Ordering::Acquire), MODEL_METADATA_RELEASED);
        assert_eq!(self.terminal_release_count.load(Ordering::Acquire), 1);
    }
}

// This bounded model covers the atomic half of W07's
// `ClaimedAbandonedRemoteFree` boundary. The concrete non-`Copy` production
// capability is constructed by `push_live_allocation` and consumed by the
// post-owner-exit continuation; its raw `Page` and block projections are
// exercised by their deterministic fixture tests. Loom must stay at the
// address-free atomic-helper boundary, so it deliberately does not fabricate
// a production claim. Instead, the move-only witness below records the same
// single successful CAS and the same move into either the terminal tail or an
// error. Its publication, unown, and detach calls all go through the existing
// source-shaped helpers.
const STALE_SNAPSHOT_CLAIM_TOKEN: usize = 1;
const STALE_SNAPSHOT_CONTINUATION_PENDING: usize = 0;
const STALE_SNAPSHOT_CONTINUATION_RUNNING: usize = 1;
const STALE_SNAPSHOT_CONTINUATION_FINISHED: usize = 2;
const STALE_SNAPSHOT_CONTINUATION_RETAINED: usize = 3;

/// The one coherent live-owner observation. It is intentionally move-only:
/// one pointer-dispatched client reaches exactly one `allow_collect` CAS.
struct StaleLiveRemoteFreeSnapshot {
    block_index: usize,
}

/// Fault injected after source detach, where a terminal retry would be
/// invalid because the list operation is already irreversible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaleSnapshotContinuationError {
    InjectedAfterDetach,
}

/// Test-only move witness for the real `ClaimedAbandonedRemoteFree` value.
///
/// This is not a second production token: it is the smallest representation
/// Loom can use without inventing a raw page or block pointer. Like the real
/// type, it has no `Copy` or `Clone`; terminal continuation consumes it and a
/// fault returns this same witness intact.
#[must_use = "a stale-snapshot claim must complete or retain its continuation"]
struct ClaimedAbandonedContinuationWitness {
    model: Arc<StaleSnapshotClaimModel>,
    token_id: usize,
    published_block: ThreadFree,
}

/// Retains the exact move witness after a post-detach fault.
#[must_use = "a post-detach fault retains the source claim"]
struct RetainedClaimedAbandonedContinuationWitness {
    claim: ClaimedAbandonedContinuationWitness,
    error: StaleSnapshotContinuationError,
}

impl ClaimedAbandonedContinuationWitness {
    fn finish_terminal_continuation(
        self,
        fail_after_detach: bool,
    ) -> Result<(), RetainedClaimedAbandonedContinuationWitness> {
        match self
            .model
            .finish_claimed_continuation(self.token_id, self.published_block, fail_after_detach)
        {
            Ok(()) => Ok(()),
            Err(error) => Err(RetainedClaimedAbandonedContinuationWitness { claim: self, error }),
        }
    }
}

/// Finite source-shaped state for one stale live-owner free.
///
/// The pointer dispatcher first observes a live identity. The source owner
/// then publishes abandonment and unowns its empty head. Only after that
/// handoff does the stale observation call `publish_to_head_with_owner`; the
/// winning CAS supplies one move-only continuation witness. The model selects
/// no geometry, PageMap implementation, arena, or release route.
struct StaleSnapshotClaimModel {
    head: AtomicUsize,
    blocks: ModelBlocks,
    used: AtomicUsize,
    owner_identity: AtomicUsize,
    snapshot_issued: AtomicUsize,
    claimed_token: AtomicUsize,
    source_publication_count: AtomicUsize,
    continuation_state: AtomicUsize,
    continuation_attempt_count: AtomicUsize,
    terminal_release_count: AtomicUsize,
    page_map_registered: AtomicBool,
    metadata_released: AtomicBool,
}

impl StaleSnapshotClaimModel {
    fn new() -> Self {
        Self {
            head: AtomicUsize::new(OWNER_EMPTY_HEAD),
            blocks: ModelBlocks::new(),
            used: AtomicUsize::new(1),
            owner_identity: AtomicUsize::new(MODEL_OWNER_LIVE),
            snapshot_issued: AtomicUsize::new(0),
            claimed_token: AtomicUsize::new(0),
            source_publication_count: AtomicUsize::new(0),
            continuation_state: AtomicUsize::new(STALE_SNAPSHOT_CONTINUATION_PENDING),
            continuation_attempt_count: AtomicUsize::new(0),
            terminal_release_count: AtomicUsize::new(0),
            page_map_registered: AtomicBool::new(true),
            metadata_released: AtomicBool::new(false),
        }
    }

    /// Captures the live identity before owner exit. This does not pin that
    /// identity; the `allow_collect=true` source CAS must close the gap.
    fn snapshot_live_owner(&self) -> StaleLiveRemoteFreeSnapshot {
        assert_eq!(
            self.owner_identity.load(Ordering::Acquire),
            MODEL_OWNER_LIVE,
            "pointer dispatch snapshots the page before owner exit"
        );
        assert_eq!(
            self.snapshot_issued.fetch_add(1, Ordering::AcqRel),
            0,
            "the bounded model owns one exact client observation"
        );
        StaleLiveRemoteFreeSnapshot { block_index: 0 }
    }

    /// Models source owner exit after the live observation, including the
    /// release of the empty low-bit head that the stale producer will claim.
    fn abandon_after_stale_snapshot(&self) {
        assert_eq!(
            self.snapshot_issued.load(Ordering::Acquire),
            1,
            "owner exit follows the one stale live observation"
        );
        assert_eq!(
            self.owner_identity.compare_exchange(
                MODEL_OWNER_LIVE,
                MODEL_OWNER_ABANDONED,
                Ordering::Release,
                Ordering::Relaxed,
            ),
            Ok(MODEL_OWNER_LIVE),
            "source owner publishes abandonment once"
        );
        let mut no_hook: Option<fn()> = None;
        assert_eq!(
            try_unown_abandoned_head_with(&self.head, &mut no_hook),
            AbandonedOwnerHeadTransition::Released,
            "owner exit releases its empty low-bit head"
        );
        assert_eq!(self.head.load(Ordering::Acquire), 0);
    }

    /// Executes the production-shaped stale `allow_collect` publication and
    /// creates one continuation witness only when it acquires the unowned
    /// abandoned head.
    fn claim_from_stale_snapshot(
        model: &Arc<Self>,
        snapshot: StaleLiveRemoteFreeSnapshot,
    ) -> ClaimedAbandonedContinuationWitness {
        assert_eq!(snapshot.block_index, 0);
        assert_eq!(
            model.owner_identity.load(Ordering::Acquire),
            MODEL_OWNER_ABANDONED,
            "the stale observation reaches the abandoned owner identity"
        );
        assert!(
            !model.blocks.publish_abandoned(&model.head, snapshot.block_index),
            "the unowned head makes this source publication the unique owner"
        );
        assert_eq!(
            model.source_publication_count.fetch_add(1, Ordering::AcqRel),
            0,
            "one client reaches one source publication"
        );
        assert_eq!(
            model.claimed_token.compare_exchange(
                0,
                STALE_SNAPSHOT_CLAIM_TOKEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(0),
            "the successful CAS yields one continuation witness"
        );
        ClaimedAbandonedContinuationWitness {
            model: Arc::clone(model),
            token_id: STALE_SNAPSHOT_CLAIM_TOKEN,
            published_block: ModelBlocks::address(snapshot.block_index),
        }
    }

    /// Runs the post-publication terminal tail without another publish. The
    /// injected error is after detach; returning the moved witness is the only
    /// valid way to retain the low-bit owner and its page lifetime.
    fn finish_claimed_continuation(
        &self,
        token_id: usize,
        published_block: ThreadFree,
        fail_after_detach: bool,
    ) -> Result<(), StaleSnapshotContinuationError> {
        assert_eq!(token_id, STALE_SNAPSHOT_CLAIM_TOKEN);
        assert_eq!(published_block, ModelBlocks::address(0));
        assert_eq!(
            self.claimed_token.load(Ordering::Acquire),
            token_id,
            "the terminal tail receives the exact successful claim"
        );
        assert_eq!(
            self.continuation_state.compare_exchange(
                STALE_SNAPSHOT_CONTINUATION_PENDING,
                STALE_SNAPSHOT_CONTINUATION_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(STALE_SNAPSHOT_CONTINUATION_PENDING),
            "one claim enters one terminal continuation"
        );
        assert_eq!(
            self.continuation_attempt_count.fetch_add(1, Ordering::AcqRel),
            0,
            "the terminal continuation starts once"
        );
        assert_eq!(self.blocks.collect_once(&self.head), 1);
        assert_eq!(
            self.used.fetch_sub(1, Ordering::Relaxed),
            1,
            "the terminal collector consumes the one still-counted client"
        );
        assert_eq!(self.head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);

        if fail_after_detach {
            self.continuation_state
                .store(STALE_SNAPSHOT_CONTINUATION_RETAINED, Ordering::Release);
            return Err(StaleSnapshotContinuationError::InjectedAfterDetach);
        }

        assert!(
            self.page_map_registered.swap(false, Ordering::AcqRel),
            "one successful continuation unregisters the page once"
        );
        assert!(
            !self.metadata_released.swap(true, Ordering::AcqRel),
            "metadata release follows that one unregister"
        );
        assert_eq!(
            self.terminal_release_count.fetch_add(1, Ordering::AcqRel),
            0,
            "the claimed continuation reaches one terminal release"
        );
        self.continuation_state
            .store(STALE_SNAPSHOT_CONTINUATION_FINISHED, Ordering::Release);
        Ok(())
    }

    fn assert_completed_once(&self) {
        assert_eq!(self.used.load(Ordering::Relaxed), 0);
        assert_eq!(self.head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        assert_eq!(
            self.source_publication_count.load(Ordering::Acquire),
            1,
            "the terminal tail never republishes its already-linked block"
        );
        assert_eq!(
            self.continuation_state.load(Ordering::Acquire),
            STALE_SNAPSHOT_CONTINUATION_FINISHED
        );
        assert_eq!(self.continuation_attempt_count.load(Ordering::Acquire), 1);
        assert_eq!(self.terminal_release_count.load(Ordering::Acquire), 1);
        assert!(!self.page_map_registered.load(Ordering::Acquire));
        assert!(self.metadata_released.load(Ordering::Acquire));
        self.blocks.assert_collected(0);
    }

    fn assert_retained_after_detach(&self) {
        assert_eq!(self.used.load(Ordering::Relaxed), 0);
        assert_eq!(self.head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        assert_eq!(
            self.source_publication_count.load(Ordering::Acquire),
            1,
            "a retained claim cannot publish its client a second time"
        );
        assert_eq!(
            self.continuation_state.load(Ordering::Acquire),
            STALE_SNAPSHOT_CONTINUATION_RETAINED
        );
        assert_eq!(self.continuation_attempt_count.load(Ordering::Acquire), 1);
        assert_eq!(self.terminal_release_count.load(Ordering::Acquire), 0);
        assert!(self.page_map_registered.load(Ordering::Acquire));
        assert!(!self.metadata_released.load(Ordering::Acquire));
        self.blocks.assert_collected(0);
    }
}

/// Forces the pointer-dispatch observation to become stale before its source
/// CAS, while preserving the modeled move-only ownership of that observation.
fn claim_after_stale_live_snapshot(
) -> (Arc<StaleSnapshotClaimModel>, ClaimedAbandonedContinuationWitness) {
    let model = Arc::new(StaleSnapshotClaimModel::new());
    let producer_model = Arc::clone(&model);
    let (snapshot_ready_send, snapshot_ready_receive) = mpsc::channel();
    let (abandoned_send, abandoned_receive) = mpsc::channel();
    let producer = thread::spawn(move || {
        let snapshot = producer_model.snapshot_live_owner();
        snapshot_ready_send
            .send(())
            .expect("owner keeps the stale-observation receiver");
        abandoned_receive
            .recv()
            .expect("stale publisher waits for owner abandonment");
        StaleSnapshotClaimModel::claim_from_stale_snapshot(&producer_model, snapshot)
    });

    snapshot_ready_receive
        .recv()
        .expect("producer records its live-owner observation");
    model.abandon_after_stale_snapshot();
    abandoned_send
        .send(())
        .expect("stale publisher remains available after owner exit");
    let claim = producer
        .join()
        .expect("stale publisher completes its source claim");
    (model, claim)
}

// This is the atomic source tail of one hypothetical pointer-centered
// replacement realloc, not a model of a supported nonlocal-realloc route.
// Pinned `alloc.c:379-451` makes the replacement/copy decision before it
// routes the old pointer through `mi_free`; the old pointer then reaches the
// `free.c:62-97` `allow_collect=true` publication and the `arena.c` unown
// loop mapped above. The current direct native boundary intentionally rejects
// foreign and detached replacement reallocs. This witness only records the
// source property a future pointer-first route would have to preserve: a
// separately allocated replacement never substitutes for, republishes, or
// loses the old allocation's canonical block.
const NONLOCAL_REALLOC_OLD_SOURCE_BLOCK: ThreadFree = ModelBlocks::address(0);
const NONLOCAL_REALLOC_REPLACEMENT_BLOCK: ThreadFree = ModelBlocks::address(1);

/// One coherent old-pointer observation retained across replacement work.
/// It intentionally carries only the canonical source-block identity: PageMap
/// lookup, allocation, copy extent, and byte preservation are outside this
/// source-head model and have their own deterministic evidence.
struct NonlocalReallocOldSourceSnapshot {
    canonical_block: ThreadFree,
}

/// The old pointer's one source `mi_free_block_mt(..., true)` outcome after a
/// replacement allocation. `ClaimedAbandoned` carries the exact canonical
/// block that changed an unowned head back to owned; it is not a reconstructed
/// page/block capability.
enum NonlocalReallocOldSourcePublication {
    PublishedToSourceOwner,
    ClaimedAbandoned(NonlocalReallocClaimedAbandonedContinuation),
}

/// The exiting source owner either collected the old canonical block itself,
/// or released its empty abandoned head before the producer's old-pointer CAS.
/// In the latter case, that CAS must return the claimed continuation above.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NonlocalReallocOwnerExitOutcome {
    CollectedOldSource,
    UnownedBeforeOldSourcePublication,
}

/// Test-only move witness for the old source block after its publication won
/// the abandoned unowned head. It is deliberately non-`Copy` and has no
/// replacement-block projection, mirroring the production W07 rule that the
/// successful CAS—not a later lookup—selects the source continuation.
#[must_use = "a claimed nonlocal-realloc old source must finish its abandoned continuation"]
struct NonlocalReallocClaimedAbandonedContinuation {
    model: Arc<NonlocalReallocSourceTailModel>,
    canonical_block: ThreadFree,
}

impl NonlocalReallocClaimedAbandonedContinuation {
    /// Runs only the source atomic tail of the claimed abandoned continuation:
    /// detach the already-published old canonical block, then unown its empty
    /// head. Geometry, PageMap teardown, and replacement lifetime are not
    /// inferred from this finite witness.
    fn finish_source_tail(self) {
        assert_eq!(self.canonical_block, NONLOCAL_REALLOC_OLD_SOURCE_BLOCK);
        assert_eq!(
            self.model.owner_identity.load(Ordering::Acquire),
            MODEL_OWNER_ABANDONED,
            "only the owner-exit unowned state may produce this continuation"
        );
        assert_eq!(
            self.model.head.load(Ordering::Acquire),
            self.canonical_block | THREAD_FREE_OWNED,
            "the continuation retains the exact old canonical block in the source head"
        );
        assert_eq!(
            self.model.claimed_continuation_finished.fetch_add(1, Ordering::AcqRel),
            0,
            "the claimed old source has one continuation tail"
        );
        assert_eq!(
            self.model.collect_old_source_once(),
            1,
            "the claimed continuation detaches its old canonical block once"
        );
        self.model.release_empty_abandoned_head();
    }
}

/// Finite identity and source-head evidence for the tail after one replacement
/// allocation has succeeded. It deliberately executes the production
/// `publish_to_head_with_owner`, `detach_from_head`, and
/// `try_unown_abandoned_head_with` transitions. The scalar replacement field
/// is only an ordering/distinctness witness; this is not a replacement
/// allocator, copy model, PageMap implementation, or general correctness
/// claim for cross-thread realloc.
struct NonlocalReallocSourceTailModel {
    head: AtomicUsize,
    blocks: ModelBlocks,
    owner_identity: AtomicUsize,
    owner_exit_started: AtomicBool,
    old_source_snapshot_count: AtomicUsize,
    replacement_block: AtomicUsize,
    old_source_publication_count: AtomicUsize,
    old_client_count: AtomicUsize,
    owner_collection_count: AtomicUsize,
    claimed_continuation_count: AtomicUsize,
    claimed_continuation_finished: AtomicUsize,
}

impl NonlocalReallocSourceTailModel {
    fn new() -> Self {
        Self {
            head: AtomicUsize::new(OWNER_EMPTY_HEAD),
            blocks: ModelBlocks::new(),
            owner_identity: AtomicUsize::new(MODEL_OWNER_LIVE),
            owner_exit_started: AtomicBool::new(false),
            old_source_snapshot_count: AtomicUsize::new(0),
            replacement_block: AtomicUsize::new(0),
            old_source_publication_count: AtomicUsize::new(0),
            // The old client stays counted until the real source head is
            // detached by either the exiting owner or its claimed tail.
            old_client_count: AtomicUsize::new(1),
            owner_collection_count: AtomicUsize::new(0),
            claimed_continuation_count: AtomicUsize::new(0),
            claimed_continuation_finished: AtomicUsize::new(0),
        }
    }

    /// Pointer dispatch has recovered the old allocation's canonical block
    /// while its source owner is still live. Owner exit may make this identity
    /// stale before the later source publication, exactly as `allow_collect`
    /// is intended to handle.
    fn snapshot_live_old_source(&self) -> NonlocalReallocOldSourceSnapshot {
        assert_eq!(
            self.owner_identity.load(Ordering::Acquire),
            MODEL_OWNER_LIVE,
            "the bounded old-pointer observation starts before source owner exit"
        );
        assert_eq!(
            self.old_source_snapshot_count.fetch_add(1, Ordering::AcqRel),
            0,
            "one nonlocal replacement owns one old-pointer observation"
        );
        NonlocalReallocOldSourceSnapshot {
            canonical_block: NONLOCAL_REALLOC_OLD_SOURCE_BLOCK,
        }
    }

    /// Represents a successful replacement allocation on a distinct target.
    /// It intentionally touches no old-page state: only the later old-pointer
    /// free is allowed to use the old source head.
    fn allocate_replacement_before_old_source_publication(&self) {
        assert_eq!(
            self.old_source_snapshot_count.load(Ordering::Acquire),
            1,
            "replacement starts from the one retained old-pointer observation"
        );
        assert_eq!(
            self.replacement_block.compare_exchange(
                0,
                NONLOCAL_REALLOC_REPLACEMENT_BLOCK,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(0),
            "the bounded replacement allocation occurs once"
        );
        assert_ne!(
            NONLOCAL_REALLOC_REPLACEMENT_BLOCK,
            NONLOCAL_REALLOC_OLD_SOURCE_BLOCK,
            "a replacement allocation cannot reuse the still-live old canonical block"
        );
    }

    /// Executes the production `allow_collect=true` old-pointer publication
    /// only after replacement allocation. Returning `false` from the helper
    /// means this exact old canonical block claimed an abandoned unowned head.
    fn publish_old_source_after_replacement(
        model: &Arc<Self>,
        snapshot: NonlocalReallocOldSourceSnapshot,
    ) -> NonlocalReallocOldSourcePublication {
        assert_eq!(snapshot.canonical_block, NONLOCAL_REALLOC_OLD_SOURCE_BLOCK);
        assert_eq!(
            model.replacement_block.load(Ordering::Acquire),
            NONLOCAL_REALLOC_REPLACEMENT_BLOCK,
            "the replacement allocation completes before old-source publication"
        );
        assert_eq!(
            model.old_source_publication_count.fetch_add(1, Ordering::AcqRel),
            0,
            "the old canonical block reaches one source publication attempt"
        );
        let was_owned = model
            .blocks
            .publish_abandoned(&model.head, 0);
        if was_owned {
            NonlocalReallocOldSourcePublication::PublishedToSourceOwner
        } else {
            assert_eq!(
                model.owner_identity.load(Ordering::Acquire),
                MODEL_OWNER_ABANDONED,
                "only the owner's released abandoned head yields the W07 continuation"
            );
            assert_eq!(
                model.claimed_continuation_count.fetch_add(1, Ordering::AcqRel),
                0,
                "the unowned-head CAS creates one claimed continuation"
            );
            NonlocalReallocOldSourcePublication::ClaimedAbandoned(
                NonlocalReallocClaimedAbandonedContinuation {
                    model: Arc::clone(model),
                    canonical_block: snapshot.canonical_block,
                },
            )
        }
    }

    /// Uses the real owner-side detach and verifies that its one old canonical
    /// client is neither lost nor replaced by the new allocation identity.
    fn collect_old_source_once(&self) -> usize {
        let collected = self.blocks.collect_once(&self.head);
        assert!(
            collected <= 1,
            "the replacement identity never enters the old source remote list"
        );
        if collected != 0 {
            assert_eq!(collected, 1);
            assert_eq!(
                self.old_client_count.fetch_sub(1, Ordering::AcqRel),
                1,
                "one source collection consumes the still-counted old client"
            );
        }
        collected
    }

    fn release_empty_abandoned_head(&self) {
        let mut no_hook: Option<fn()> = None;
        assert_eq!(
            try_unown_abandoned_head_with(&self.head, &mut no_hook),
            AbandonedOwnerHeadTransition::Released,
            "only an owned empty head may transfer the source owner bit"
        );
        assert_eq!(self.head.load(Ordering::Acquire), 0);
    }

    /// Models source owner exit after the old-pointer snapshot. It first uses
    /// the production detach; if that finds no block, the production unown CAS
    /// races the producer's later old-pointer publication. A failed unown CAS
    /// must make this owner collect the exact old block instead of dropping it.
    fn exit_collect_and_unown(&self) -> NonlocalReallocOwnerExitOutcome {
        assert!(
            !self.owner_exit_started.swap(true, Ordering::AcqRel),
            "one source owner performs the exit transition"
        );

        // `theap.c` collects the live owner's remote head before `arena.c`
        // publishes the abandoned identity and enters its common unown loop.
        // Keeping that scalar order visible prevents this atomic-tail witness
        // from silently treating an abandoned identity as authority for the
        // live owner collection.
        let initially_collected = self.collect_old_source_once();
        assert_eq!(
            self.owner_identity.compare_exchange(
                MODEL_OWNER_LIVE,
                MODEL_OWNER_ABANDONED,
                Ordering::Release,
                Ordering::Acquire,
            ),
            Ok(MODEL_OWNER_LIVE),
            "owner exit publishes the abandoned identity after source collection"
        );

        if initially_collected == 1 {
            assert_eq!(
                self.owner_collection_count.fetch_add(1, Ordering::AcqRel),
                0,
                "the exiting owner collects the old block once"
            );
            self.release_empty_abandoned_head();
            return NonlocalReallocOwnerExitOutcome::CollectedOldSource;
        }

        let mut no_hook: Option<fn()> = None;
        match try_unown_abandoned_head_with(&self.head, &mut no_hook) {
            AbandonedOwnerHeadTransition::Released => {
                assert_eq!(
                    self.old_client_count.load(Ordering::Acquire),
                    1,
                    "unown does not release the still-live old client before its source publication"
                );
                NonlocalReallocOwnerExitOutcome::UnownedBeforeOldSourcePublication
            }
            AbandonedOwnerHeadTransition::RemotePublished(observed) => {
                assert_eq!(
                    thread_free_block_address(observed),
                    NONLOCAL_REALLOC_OLD_SOURCE_BLOCK,
                    "a failed unown CAS observes the old canonical block, not the replacement"
                );
                assert_eq!(
                    self.collect_old_source_once(),
                    1,
                    "the owner retries through source collection after a late old-pointer publication"
                );
                assert_eq!(
                    self.owner_collection_count.fetch_add(1, Ordering::AcqRel),
                    0,
                    "the owner has one collection responsibility after the failed unown"
                );
                self.release_empty_abandoned_head();
                NonlocalReallocOwnerExitOutcome::CollectedOldSource
            }
            AbandonedOwnerHeadTransition::NotOwned => {
                panic!("no other transition may release the exiting owner's source head")
            }
        }
    }

    fn assert_owner_collected_old_source(&self) {
        self.assert_common_old_source_tail();
        assert_eq!(self.owner_collection_count.load(Ordering::Acquire), 1);
        assert_eq!(self.claimed_continuation_count.load(Ordering::Acquire), 0);
        assert_eq!(self.claimed_continuation_finished.load(Ordering::Acquire), 0);
    }

    fn assert_claimed_continuation_finished(&self) {
        self.assert_common_old_source_tail();
        assert_eq!(self.owner_collection_count.load(Ordering::Acquire), 0);
        assert_eq!(self.claimed_continuation_count.load(Ordering::Acquire), 1);
        assert_eq!(self.claimed_continuation_finished.load(Ordering::Acquire), 1);
    }

    fn assert_common_old_source_tail(&self) {
        assert!(self.owner_exit_started.load(Ordering::Acquire));
        assert_eq!(self.old_source_snapshot_count.load(Ordering::Acquire), 1);
        assert_eq!(
            self.replacement_block.load(Ordering::Acquire),
            NONLOCAL_REALLOC_REPLACEMENT_BLOCK
        );
        assert_eq!(self.old_source_publication_count.load(Ordering::Acquire), 1);
        assert_eq!(self.old_client_count.load(Ordering::Acquire), 0);
        assert_eq!(self.head.load(Ordering::Acquire), 0);
        assert_eq!(
            self.blocks.next[0].load(Ordering::Relaxed),
            0,
            "the old canonical block never links to the replacement identity"
        );
        assert!(self.blocks.published[0].load(Ordering::Acquire));
        assert!(self.blocks.collected[0].load(Ordering::Acquire));
        assert!(
            !self.blocks.published[1].load(Ordering::Acquire),
            "the replacement allocation is never published to the old source head"
        );
        assert!(
            !self.blocks.collected[1].load(Ordering::Acquire),
            "owner collection never reuses the replacement identity as the old block"
        );
    }
}

/// Compile-time guard for the concrete W07 boundary that this address-free
/// model represents. Either `Copy` or `Clone` would make the implementation
/// choice below ambiguous, so this test stops compiling if the real claim can
/// be duplicated instead of moved into its continuation.
#[test]
fn claimed_abandoned_remote_free_stays_linear_at_the_loom_boundary() {
    trait AmbiguousIfCopy<Marker> {
        fn assertion() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: ?Sized + Copy> AmbiguousIfCopy<u8> for T {}

    trait AmbiguousIfClone<Marker> {
        fn assertion() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}

    let _ = <super::ClaimedAbandonedRemoteFree as AmbiguousIfCopy<_>>::assertion;
    let _ = <super::ClaimedAbandonedRemoteFree as AmbiguousIfClone<_>>::assertion;
}

#[test]
fn loom_stale_live_snapshot_claimed_abandoned_remote_free_has_one_terminal_continuation() {
    loom::model(|| {
        let (model, claim) = claim_after_stale_live_snapshot();
        assert_eq!(claim.token_id, STALE_SNAPSHOT_CLAIM_TOKEN);
        assert_eq!(claim.published_block, ModelBlocks::address(0));
        assert_eq!(
            model.head.load(Ordering::Acquire),
            ModelBlocks::address(0) | THREAD_FREE_OWNED,
            "the stale observation claims the unowned head with its exact block"
        );

        match claim.finish_terminal_continuation(false) {
            Ok(()) => {}
            Err(_) => panic!("the non-faulting claimed continuation completes once"),
        }
        model.assert_completed_once();
    });
}

#[test]
fn loom_claimed_abandoned_remote_free_fault_retains_the_exact_token_without_republication() {
    loom::model(|| {
        let (model, claim) = claim_after_stale_live_snapshot();
        let token_id = claim.token_id;
        let published_block = claim.published_block;
        let retained = match claim.finish_terminal_continuation(true) {
            Ok(()) => panic!("the injected post-detach fault retains the continuation"),
            Err(retained) => retained,
        };

        assert_eq!(retained.error, StaleSnapshotContinuationError::InjectedAfterDetach);
        assert_eq!(
            retained.claim.token_id, token_id,
            "the error carries the exact successful claim rather than a replacement"
        );
        assert_eq!(
            retained.claim.published_block, published_block,
            "the retained claim still names the stale-snapshot client"
        );
        model.assert_retained_after_detach();
    });
}

#[test]
fn loom_nonlocal_realloc_replacement_precedes_one_old_source_tail() {
    loom::model(|| {
        let model = Arc::new(NonlocalReallocSourceTailModel::new());
        let producer_model = Arc::clone(&model);
        let (snapshot_ready_send, snapshot_ready_receive) = mpsc::channel();

        // The old pointer is resolved first. The producer then allocates a
        // distinct replacement before it can execute the source `mi_free` CAS
        // for that old pointer. The send makes the snapshot's stale-owner gap
        // explicit without ordering either later replacement work or the CAS
        // against the owner-exit thread.
        let producer = thread::spawn(move || {
            let snapshot = producer_model.snapshot_live_old_source();
            snapshot_ready_send
                .send(())
                .expect("owner exit waits for the old-pointer snapshot");
            producer_model.allocate_replacement_before_old_source_publication();
            NonlocalReallocSourceTailModel::publish_old_source_after_replacement(
                &producer_model,
                snapshot,
            )
        });

        snapshot_ready_receive
            .recv()
            .expect("the producer retains its old-pointer observation");

        // This is the exiting source owner: collection may see the old block
        // before the common unown loop, or it may observe an empty head and
        // race the producer's source CAS while trying to unown. Loom explores
        // both without replacing any production atomic transition.
        let owner_model = Arc::clone(&model);
        let owner = thread::spawn(move || owner_model.exit_collect_and_unown());

        let publication = producer.join().expect("old-source producer completes");
        let owner_outcome = owner.join().expect("source owner exit completes");

        match (owner_outcome, publication) {
            (
                NonlocalReallocOwnerExitOutcome::CollectedOldSource,
                NonlocalReallocOldSourcePublication::PublishedToSourceOwner,
            ) => model.assert_owner_collected_old_source(),
            (
                NonlocalReallocOwnerExitOutcome::UnownedBeforeOldSourcePublication,
                NonlocalReallocOldSourcePublication::ClaimedAbandoned(continuation),
            ) => {
                // The unowned-head winner owns the exact old block and must
                // take a W07-style continuation rather than retrying the
                // publication or treating the new replacement as that block.
                continuation.finish_source_tail();
                model.assert_claimed_continuation_finished();
            }
            _ => panic!(
                "an old-pointer source CAS either hands its exact block to the exiting owner or claims its abandoned continuation"
            ),
        }
    });
}

#[test]
fn loom_multiple_remote_publishers_preserve_owner_bit_and_collect_every_block_once() {
    loom::model(|| {
        let head = Arc::new(AtomicUsize::new(OWNER_EMPTY_HEAD));
        let blocks = Arc::new(ModelBlocks::new());

        let first_head = Arc::clone(&head);
        let first_blocks = Arc::clone(&blocks);
        let first = thread::spawn(move || first_blocks.publish(&first_head, 0));

        let second_head = Arc::clone(&head);
        let second_blocks = Arc::clone(&blocks);
        let second = thread::spawn(move || second_blocks.publish(&second_head, 1));

        first.join().expect("first publisher completes");
        second.join().expect("second publisher completes");

        assert_eq!(blocks.collect_once(&head), PRODUCER_COUNT);
        assert_eq!(head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        blocks.assert_all_collected();
    });
}

#[test]
fn loom_owner_collection_racing_publication_loses_no_block_and_keeps_owner_bit() {
    loom::model(|| {
        let head = Arc::new(AtomicUsize::new(OWNER_EMPTY_HEAD));
        let blocks = Arc::new(ModelBlocks::new());

        let first_head = Arc::clone(&head);
        let first_blocks = Arc::clone(&blocks);
        let (first_ready_send, first_ready_receive) = mpsc::channel();
        let first = thread::spawn(move || {
            first_blocks.publish(&first_head, 0);
            first_ready_send
                .send(())
                .expect("the modeled owner retains the readiness receiver");
        });

        // The owner waits only until one source publication is complete. The
        // second producer is then concurrent with the first owner detach.
        // A modeled channel avoids an unbounded polling schedule here.
        first_ready_receive
            .recv()
            .expect("the first publisher announces its completed publication");

        let second_head = Arc::clone(&head);
        let second_blocks = Arc::clone(&blocks);
        let second = thread::spawn(move || second_blocks.publish(&second_head, 1));

        let collected_before_joins = blocks.collect_once(&head);
        first.join().expect("first publisher completes");
        second.join().expect("second publisher completes");
        let collected_after_joins = blocks.collect_once(&head);

        assert_eq!(collected_before_joins + collected_after_joins, PRODUCER_COUNT);
        assert_eq!(head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        blocks.assert_all_collected();
    });
}

#[test]
fn loom_bitmap_adopter_racing_abandoned_publisher_has_one_owner_and_correct_bitmap_responsibility() {
    loom::model(|| {
        let head = Arc::new(AtomicUsize::new(0));
        let bitmap_published = Arc::new(AtomicBool::new(true));
        let blocks = Arc::new(ModelBlocks::new());

        let adopter_head = Arc::clone(&head);
        let adopter_bitmap = Arc::clone(&bitmap_published);
        let adopter = thread::spawn(move || {
            assert!(
                adopter_bitmap.swap(false, Ordering::AcqRel),
                "the modeled bitmap reader temporarily owns the published bit"
            );
            let claim = claim_abandoned_owner_with(&*adopter_head);
            if claim == AbandonedOwnerClaim::AlreadyOwned {
                // This is the source `keep_abandoned=true` obligation: a
                // producer that won ownership will later wait for this bit.
                adopter_bitmap.store(true, Ordering::Release);
            }
            claim
        });

        let publisher_head = Arc::clone(&head);
        let publisher_blocks = Arc::clone(&blocks);
        let publisher = thread::spawn(move || {
            publisher_blocks.publish_abandoned(&publisher_head, 0)
        });

        let adopter_claim = adopter.join().expect("bitmap adopter completes");
        let publisher_found_owner = publisher.join().expect("abandoned publisher completes");
        let adopter_found_unowned = adopter_claim == AbandonedOwnerClaim::ClaimedUnowned;
        let publisher_found_unowned = !publisher_found_owner;

        assert_ne!(
            adopter_found_unowned, publisher_found_unowned,
            "exactly one competing transition observes the old unowned word"
        );
        assert_eq!(
            bitmap_published.load(Ordering::Acquire),
            publisher_found_unowned,
            "a producer winner keeps bitmap responsibility; an adopter winner consumes it"
        );
        assert_eq!(
            head.load(Ordering::Acquire),
            ModelBlocks::address(0) | THREAD_FREE_OWNED,
            "the producer block and the unique owner bit remain published"
        );

        assert_eq!(blocks.collect_once(&head), 1);
        assert_eq!(head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        blocks.assert_collected(0);
    });
}

#[test]
fn loom_abandoned_unown_racing_publisher_either_transfers_or_retains_collection_obligation() {
    loom::model(|| {
        let head = Arc::new(AtomicUsize::new(OWNER_EMPTY_HEAD));
        let blocks = Arc::new(ModelBlocks::new());

        let owner_head = Arc::clone(&head);
        let owner = thread::spawn(move || {
            let mut no_hook: Option<fn()> = None;
            try_unown_abandoned_head_with(&*owner_head, &mut no_hook)
        });

        let publisher_head = Arc::clone(&head);
        let publisher_blocks = Arc::clone(&blocks);
        let publisher = thread::spawn(move || {
            publisher_blocks.publish_abandoned(&publisher_head, 0)
        });

        let owner_transition = owner.join().expect("abandoned owner completes its head transition");
        let publisher_found_owner = publisher.join().expect("abandoned publisher completes");

        match owner_transition {
            AbandonedOwnerHeadTransition::Released => assert!(
                !publisher_found_owner,
                "after unown wins, the producer must claim the unowned word"
            ),
            AbandonedOwnerHeadTransition::RemotePublished(observed) => {
                assert!(
                    publisher_found_owner,
                    "when publication wins, the old owner keeps collection responsibility"
                );
                assert_eq!(
                    thread_free_block_address(observed),
                    ModelBlocks::address(0),
                    "the failed unown observes the producer block"
                );
            }
            AbandonedOwnerHeadTransition::NotOwned => {
                panic!("the model begins with the abandoned owner bit held")
            }
        }
        assert_eq!(
            head.load(Ordering::Acquire),
            ModelBlocks::address(0) | THREAD_FREE_OWNED,
            "both legal outcomes retain one owner and the published block"
        );

        assert_eq!(blocks.collect_once(&head), 1);
        assert_eq!(head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        blocks.assert_collected(0);
    });
}

#[test]
fn loom_expected_head_unown_racing_allow_collect_publisher_preserves_the_head_or_collection() {
    loom::model(|| {
        // The small partial collector leaves block zero in the owned head.
        // The expected-head CAS may transfer that exact block unowned, but it
        // must never drop it while a new allow-collect producer races.
        let head = Arc::new(AtomicUsize::new(
            ModelBlocks::address(0) | THREAD_FREE_OWNED,
        ));
        let blocks = Arc::new(ModelBlocks::new());
        blocks.next[0].store(0, Ordering::Relaxed);
        blocks.published[0].store(true, Ordering::Release);

        let owner_head = Arc::clone(&head);
        let owner = thread::spawn(move || {
            let mut no_hook: Option<fn()> = None;
            try_unown_abandoned_expected_head_with(
                &*owner_head,
                ModelBlocks::address(0),
                &mut no_hook,
            )
            .expect("the modeled expected block remains low-bit aligned")
        });

        let publisher_head = Arc::clone(&head);
        let publisher_blocks = Arc::clone(&blocks);
        let publisher = thread::spawn(move || {
            publisher_blocks.publish_abandoned(&publisher_head, 1)
        });

        let transition = owner.join().expect("expected-head owner completes");
        let publisher_found_owner = publisher.join().expect("publisher completes");
        match transition {
            AbandonedExpectedHeadTransition::Released => assert!(
                !publisher_found_owner,
                "a successful expected-head unown lets the producer claim responsibility"
            ),
            AbandonedExpectedHeadTransition::RemotePublished => assert!(
                publisher_found_owner,
                "a failed expected-head CAS retains owner-side collection responsibility"
            ),
            AbandonedExpectedHeadTransition::OwnedEmpty => {
                panic!("the model's expected small-page head is never empty")
            }
            AbandonedExpectedHeadTransition::NotOwned => {
                panic!("the model begins with the abandoned owner bit held")
            }
        }
        assert_eq!(
            head.load(Ordering::Acquire),
            ModelBlocks::address(1) | THREAD_FREE_OWNED,
            "the racing producer retains both the new block and one owner bit"
        );

        assert_eq!(blocks.collect_once(&head), PRODUCER_COUNT);
        assert_eq!(head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        blocks.assert_all_collected();
    });
}

#[test]
fn loom_live_remote_publication_and_owner_exit_keep_the_pagemap_valid_until_one_final_release() {
    loom::model(|| {
        // This one-client page is deliberately independent of size class,
        // queue, arena, or mapping geometry. It forces the live remote-free
        // publication race against the owner-exit admission transition.
        let model = Arc::new(PageMapLifetimeModel::new(1));
        let head = Arc::new(AtomicUsize::new(OWNER_EMPTY_HEAD));
        let blocks = Arc::new(ModelBlocks::new());
        let live_publication = Arc::new(AtomicBool::new(false));
        let (publication_done_send, publication_done_receive) = mpsc::channel();

        let owner_model = Arc::clone(&model);
        let owner = thread::spawn(move || {
            if !owner_model.begin_owner_exit() {
                // A producer which won the lifetime lease must finish its
                // source publication before the exit starts collection.
                publication_done_receive
                    .recv()
                    .expect("the live producer retains its completion sender");
                assert!(
                    owner_model.begin_owner_exit(),
                    "once the only publisher has left, owner exit acquires the page"
                );
            }
        });

        let producer_model = Arc::clone(&model);
        let producer_head = Arc::clone(&head);
        let producer_blocks = Arc::clone(&blocks);
        let producer_publication = Arc::clone(&live_publication);
        let producer = thread::spawn(move || {
            let published = producer_model.begin_live_remote_publication();
            if published {
                producer_blocks.publish(&producer_head, 0);
                // The block is no longer a live client only after the source
                // atomic publication can be collected by its owner.
                producer_model.finish_one_client_free();
                producer_model.finish_publication();
            }
            producer_publication.store(published, Ordering::Release);
            // If owner exit won before this thread acquired its lease, the
            // owner has no reason to wait and may already have dropped the
            // receiver. That is the valid rejected-live-publication branch.
            let _ = publication_done_send.send(());
        });

        owner.join().expect("owner exit admission completes");
        producer.join().expect("live producer completes or is rejected by exit");

        let published_live = live_publication.load(Ordering::Acquire);
        let collected = blocks.collect_once(&head);
        assert_eq!(collected, usize::from(published_live));
        if published_live {
            blocks.assert_collected(0);
        }
        model.abandon_after_collect(&head);

        if !published_live {
            // The exit won before a live publisher acquired the PageMap
            // lifetime. The client remains valid on the abandoned page, so a
            // terminal release is forbidden until its post-exit free claims
            // the low owner bit and is collected.
            assert_eq!(
                model.try_terminal_release(&head, false),
                ModelTerminalRelease::NotReady
            );
            assert!(
                model.begin_post_exit_publication(),
                "an abandoned page retains its PageMap/metadata through a later free"
            );
            assert!(
                !blocks.publish_abandoned(&head, 0),
                "the post-exit publisher claims the unowned abandoned page"
            );
            assert_eq!(blocks.collect_once(&head), 1);
            blocks.assert_collected(0);
            model.finish_one_client_free();
            model.finish_publication();
        }

        assert_eq!(
            model.try_terminal_release(&head, false),
            ModelTerminalRelease::Released,
            "the source order releases only after every client and publisher is gone"
        );
        model.assert_released_once();
    });
}

#[test]
fn loom_two_remote_publishers_owner_exit_and_terminal_consumer_claim_need_no_ledger_or_registry() {
    loom::model(|| {
        // The test fixes two exact final source blocks. Each producer obtains
        // only the page-local lookup-to-publication pin; there is no client
        // record to scan and no global owner identity to resolve. Holding both
        // pins before the owner attempts exit forces the relevant source
        // interleaving: exit must wait for the raw remote-head publications,
        // then the next phase is chosen solely by the page-local words.
        let model = Arc::new(MultiProducerOwnerExitTerminalModel::new());
        let head = Arc::new(AtomicUsize::new(OWNER_EMPTY_HEAD));
        let blocks = Arc::new(ModelBlocks::new());

        let (first_ready_send, first_ready_receive) = mpsc::channel();
        let (second_ready_send, second_ready_receive) = mpsc::channel();
        let (first_publish_send, first_publish_receive) = mpsc::channel();
        let (second_publish_send, second_publish_receive) = mpsc::channel();
        let (first_done_send, first_done_receive) = mpsc::channel();
        let (second_done_send, second_done_receive) = mpsc::channel();
        let (first_terminal_claim_send, first_terminal_claim_receive) = mpsc::channel();
        let (second_terminal_claim_send, second_terminal_claim_receive) = mpsc::channel();
        let (first_terminal_outcome_send, first_terminal_outcome_receive) = mpsc::channel();
        let (second_terminal_outcome_send, second_terminal_outcome_receive) = mpsc::channel();

        let first_model = Arc::clone(&model);
        let first_head = Arc::clone(&head);
        let first_blocks = Arc::clone(&blocks);
        let first = thread::spawn(move || {
            assert!(
                first_model.begin_live_remote_publication(),
                "the first producer pins the still-live page"
            );
            first_ready_send
                .send(())
                .expect("the owner retains the first producer's readiness receiver");
            first_publish_receive
                .recv()
                .expect("the owner lets the first producer enter the source head");
            first_blocks.publish(&first_head, 0);
            first_model.finish_live_remote_publication();
            first_done_send
                .send(())
                .expect("the owner retains the first producer's completion receiver");
            first_terminal_claim_receive
                .recv()
                .expect("the owner releases the first terminal-consumer gate");
            first_terminal_outcome_send
                .send(first_model.terminal_consumer_claim_and_release(&first_head))
                .expect("the owner retains the first terminal outcome receiver");
        });

        let second_model = Arc::clone(&model);
        let second_head = Arc::clone(&head);
        let second_blocks = Arc::clone(&blocks);
        let second = thread::spawn(move || {
            assert!(
                second_model.begin_live_remote_publication(),
                "the second producer pins the still-live page"
            );
            second_ready_send
                .send(())
                .expect("the owner retains the second producer's readiness receiver");
            second_publish_receive
                .recv()
                .expect("the owner lets the second producer enter the source head");
            second_blocks.publish(&second_head, 1);
            second_model.finish_live_remote_publication();
            second_done_send
                .send(())
                .expect("the owner retains the second producer's completion receiver");
            second_terminal_claim_receive
                .recv()
                .expect("the owner releases the second terminal-consumer gate");
            second_terminal_outcome_send
                .send(second_model.terminal_consumer_claim_and_release(&second_head))
                .expect("the owner retains the second terminal outcome receiver");
        });

        // The model thread is the source owner. Keeping it here avoids an
        // artificial fifth worker while Loom still schedules both producers'
        // source atomic publications around the owner-exit admission.
        first_ready_receive
            .recv()
            .expect("the first producer retains its readiness sender");
        second_ready_receive
            .recv()
            .expect("the second producer retains its readiness sender");
        assert!(
            !model.begin_owner_exit(),
            "two page-local publication pins reject owner exit without an owner registry"
        );

        first_publish_send
            .send(())
            .expect("the first producer retains its source-publication receiver");
        second_publish_send
            .send(())
            .expect("the second producer retains its source-publication receiver");
        first_done_receive
            .recv()
            .expect("the first producer completes its source publication");
        second_done_receive
            .recv()
            .expect("the second producer completes its source publication");

        assert!(
            model.begin_owner_exit(),
            "the owner exits once both page-local publications have left"
        );
        assert_eq!(blocks.collect_once(&head), PRODUCER_COUNT);
        blocks.assert_all_collected();
        model.abandon_after_remote_collection(&head);

        // The completed producers no longer hold PageMap pins, so they may
        // now act as two independent terminal consumers. Reusing those
        // actors keeps the model finite while Loom still schedules their
        // competing source low-bit claims.
        first_terminal_claim_send
            .send(())
            .expect("the first producer retains its terminal-consumer receiver");
        second_terminal_claim_send
            .send(())
            .expect("the second producer retains its terminal-consumer receiver");
        let first_outcome = first_terminal_outcome_receive
            .recv()
            .expect("the first terminal consumer completes");
        let second_outcome = second_terminal_outcome_receive
            .recv()
            .expect("the second terminal consumer completes");
        first.join().expect("first producer completes its terminal claim");
        second.join().expect("second producer completes its terminal claim");
        assert!(
            matches!(
                (first_outcome, second_outcome),
                (
                    TerminalConsumerClaimOutcome::Released,
                    TerminalConsumerClaimOutcome::AlreadyClaimed
                ) | (
                    TerminalConsumerClaimOutcome::AlreadyClaimed,
                    TerminalConsumerClaimOutcome::Released
                )
            ),
            "the source low bit leaves exactly one terminal claimant without a client ledger or owner registry"
        );
        model.assert_terminal_release_once(&head);
    });
}

#[test]
fn loom_final_release_has_one_winner_after_owner_exit_and_abandonment() {
    loom::model(|| {
        // No clients remain, so this isolates final-release ownership from
        // geometry and count arithmetic. Two accidental callers are allowed
        // to contend only to prove that exactly one can cross the irreversible
        // unregister/release transition.
        let model = Arc::new(PageMapLifetimeModel::new(0));
        let head = Arc::new(AtomicUsize::new(OWNER_EMPTY_HEAD));
        let blocks = ModelBlocks::new();

        assert!(model.begin_owner_exit());
        assert_eq!(blocks.collect_once(&head), 0);
        model.abandon_after_collect(&head);

        let first_model = Arc::clone(&model);
        let first_head = Arc::clone(&head);
        let first = thread::spawn(move || first_model.try_terminal_release(&first_head, false));

        let second_model = Arc::clone(&model);
        let second_head = Arc::clone(&head);
        let second = thread::spawn(move || second_model.try_terminal_release(&second_head, false));

        let first = first.join().expect("first terminal claimant completes");
        let second = second.join().expect("second terminal claimant completes");
        assert!(
            matches!(
                (first, second),
                (ModelTerminalRelease::Released, ModelTerminalRelease::AlreadyClaimed)
                    | (ModelTerminalRelease::AlreadyClaimed, ModelTerminalRelease::Released)
            ),
            "one and only one final claimant releases the PageMap and metadata"
        );
        model.assert_released_once();
    });
}

#[test]
fn loom_post_unregister_release_fault_retains_one_auditable_terminal_owner() {
    loom::model(|| {
        // This mirrors the deterministic
        // `inject_page_release_after_page_map_unregister_failure_once` seam:
        // source queue/count and the PageMap entry have already changed, so
        // the old traversal cannot be recreated or retried.
        let model = PageMapLifetimeModel::new(0);
        let head = AtomicUsize::new(OWNER_EMPTY_HEAD);
        let blocks = ModelBlocks::new();

        assert!(model.begin_owner_exit());
        assert_eq!(blocks.collect_once(&head), 0);
        model.abandon_after_collect(&head);
        assert_eq!(
            model.try_terminal_release(&head, true),
            ModelTerminalRelease::RetainedAfterUnregister
        );
        assert_eq!(
            model.try_terminal_release(&head, false),
            ModelTerminalRelease::AlreadyClaimed,
            "the retained terminal owner prevents a guessed retry"
        );
        model.assert_retained_after_unregister();
    });
}

#[test]
fn loom_lifetime_word_owner_collection_after_publication_allows_retirement() {
    loom::model(|| {
        // This starts after PageMap lookup selected generation one. The
        // lifetime word is intentionally independent of bin, arena, and page
        // geometry; the modeled head only records the source remote block
        // that the owner must collect before closing the lifetime.
        let generation = 1;
        let lifetime = AtomicUsize::new(live_remote_page_word(generation, true, 0));
        let head = AtomicUsize::new(OWNER_EMPTY_HEAD);
        let blocks = ModelBlocks::new();

        begin_live_remote_page_publication_with(&lifetime, generation)
            .expect("the active PageMap generation admits one producer");
        blocks.publish(&head, 0);
        finish_live_remote_page_publication_with(&lifetime, generation);

        // `collect_once` stands for the owner-side
        // `mi_page_thread_free_collect`: after the final producer has
        // completed its source publication, it detaches the block exactly
        // once before the owner closes the lifetime for unregistration.
        assert_eq!(blocks.collect_once(&head), 1);
        blocks.assert_collected(0);
        assert_eq!(
            begin_live_remote_page_retirement_with(&lifetime, generation),
            Ok(())
        );
        assert_eq!(
            lifetime.load(Ordering::Acquire),
            live_remote_page_word(generation, false, 0),
            "retirement preserves the generation and leaves no publisher pin"
        );
    });
}

#[test]
fn loom_lifetime_word_retirement_racing_final_producer_admits_or_rejects_once() {
    loom::model(|| {
        let generation = 1;
        let lifetime = Arc::new(AtomicUsize::new(live_remote_page_word(
            generation, true, 0,
        )));
        let (finish_send, finish_receive) = mpsc::channel();
        let (producer_done_send, producer_done_receive) = mpsc::channel();

        // The owner either closes before this final producer's admission, or
        // observes the producer's publication pin and retries after it has
        // completed. The producer is held between its named begin/finish
        // transitions so Loom must explore the owner CAS racing that final
        // admission rather than only an already-finished publication.
        let producer_lifetime = Arc::clone(&lifetime);
        let producer = thread::spawn(move || {
            match begin_live_remote_page_publication_with(&*producer_lifetime, generation) {
                Ok(()) => {
                    finish_receive
                        .recv()
                        .expect("an in-flight producer makes the owner retry");
                    finish_live_remote_page_publication_with(&*producer_lifetime, generation);
                    let _ = producer_done_send.send(true);
                    true
                }
                Err(LiveRemoteFreePagePublicationError::Retired) => {
                    let _ = producer_done_send.send(false);
                    false
                }
                Err(error) => panic!("initial generation has no other producer outcome: {error:?}"),
            }
        });

        let owner_lifetime = Arc::clone(&lifetime);
        let owner = thread::spawn(move || {
            match begin_live_remote_page_retirement_with(&*owner_lifetime, generation) {
                Ok(()) => false,
                Err(LiveRemoteFreePageRetirementError::PublishersInFlight) => {
                    finish_send
                        .send(())
                        .expect("the admitted producer retains its finish receiver");
                    assert!(
                        producer_done_receive
                            .recv()
                            .expect("the admitted producer completes its publication"),
                        "the owner only waits after observing an admitted producer"
                    );
                    assert_eq!(
                        begin_live_remote_page_retirement_with(&*owner_lifetime, generation),
                        Ok(()),
                        "the final publisher leaves exactly one retryable close"
                    );
                    true
                }
                Err(error) => panic!("initial active generation has no other owner outcome: {error:?}"),
            }
        });

        let producer_published = producer.join().expect("producer completes or is rejected");
        let owner_waited_for_producer = owner.join().expect("owner retirement completes");

        assert_eq!(
            producer_published, owner_waited_for_producer,
            "the final producer is either pinned and observed by retirement, or rejected after close"
        );
        assert_eq!(
            lifetime.load(Ordering::Acquire),
            live_remote_page_word(generation, false, 0),
            "all schedules end with one closed generation and no lost publisher pin"
        );
        assert_eq!(
            begin_live_remote_page_publication_with(&*lifetime, generation),
            Err(LiveRemoteFreePagePublicationError::Retired),
            "a producer that loses retirement cannot repin the closed lifetime"
        );
    });
}

#[test]
fn loom_lifetime_word_reinitialize_rejects_stale_generation() {
    loom::model(|| {
        let first_generation = 1;
        let lifetime = AtomicUsize::new(live_remote_page_word(first_generation, true, 0));

        assert_eq!(
            begin_live_remote_page_retirement_with(&lifetime, first_generation),
            Ok(())
        );
        let next_generation = reinitialize_live_remote_page_with(&lifetime, first_generation)
            .expect("a closed zero-publisher generation can be reused exactly once");
        assert_ne!(
            next_generation, first_generation,
            "reuse changes the PageMap generation even at the same metadata address"
        );
        assert_eq!(
            lifetime.load(Ordering::Acquire),
            live_remote_page_word(next_generation, true, 0),
            "reinitialization admits only the distinct current generation"
        );

        assert_eq!(
            begin_live_remote_page_publication_with(&lifetime, first_generation),
            Err(LiveRemoteFreePagePublicationError::StaleGeneration),
            "a stale PageMap lookup cannot pin the later page lifetime"
        );
        assert_eq!(
            begin_live_remote_page_retirement_with(&lifetime, first_generation),
            Err(LiveRemoteFreePageRetirementError::StaleGeneration),
            "a former owner cannot close a later page lifetime"
        );
        assert_eq!(
            reinitialize_live_remote_page_with(&lifetime, first_generation),
            Err(LiveRemoteFreePageReinitializeError::StaleGeneration),
            "a stale reinitializer cannot recreate an earlier generation"
        );

        begin_live_remote_page_publication_with(&lifetime, next_generation)
            .expect("the current generation remains publishable after reuse");
        finish_live_remote_page_publication_with(&lifetime, next_generation);
        assert_eq!(
            begin_live_remote_page_retirement_with(&lifetime, next_generation),
            Ok(()),
            "the current generation still has one terminal owner-close transition"
        );
    });
}

#[test]
fn loom_lifetime_word_post_detach_collection_failure_retains_the_terminal_lifetime() {
    loom::model(|| {
        let generation = 1;
        let lifetime = AtomicUsize::new(live_remote_page_word(generation, true, 0));
        let head = AtomicUsize::new(OWNER_EMPTY_HEAD);
        let blocks = ModelBlocks::new();

        // The source producer finishes its compact publication before the
        // owner starts collection. This isolates the post-detach source
        // failure from the ordinary publisher/owner race.
        begin_live_remote_page_publication_with(&lifetime, generation)
            .expect("the active lifetime admits the source producer");
        blocks.publish(&head, 0);
        finish_live_remote_page_publication_with(&lifetime, generation);
        assert_eq!(
            begin_live_remote_page_owner_collection_with(&lifetime, generation),
            Ok(())
        );

        // This is the successful source `detach_from_head` inside
        // `collect_state`. `UsedCountUnderflow` is detected only later by
        // `collect_detached_to_local`, so the remote list cannot be treated as
        // a normal, completed owner drain or reconstructed for another pass.
        let detached = detach_from_head(&head)
            .expect("the modeled source owner still holds the low-bit head");
        assert_eq!(thread_free_block_address(detached), ModelBlocks::address(0));
        assert_eq!(head.load(Ordering::Acquire), OWNER_EMPTY_HEAD);
        assert!(
            !blocks.collected[0].load(Ordering::Acquire),
            "the post-detach fault occurs before normal local-list accounting"
        );
        let source = RemoteFreeError::UsedCountUnderflow;
        assert!(
            super::collection_error_is_post_detach(source),
            "the modeled source failure belongs to the irreversible post-detach class"
        );

        // This production transition replaces normal owner-collection finish:
        // it clears the collection slot only while recording the durable
        // terminal owner, preventing the detached list from becoming eligible
        // for retirement or metadata reuse.
        retain_live_remote_page_terminal_with(&lifetime, generation);

        assert_eq!(
            begin_live_remote_page_publication_with(&lifetime, generation),
            Err(LiveRemoteFreePagePublicationError::TerminallyRetained),
            "terminal retention rejects a guessed later producer"
        );
        assert_eq!(
            begin_live_remote_page_owner_collection_with(&lifetime, generation),
            Err(LiveRemoteFreePageOwnerCollectionError::TerminallyRetained),
            "terminal retention does not turn the detached fault into a new drain"
        );
        assert_eq!(
            begin_live_remote_page_retirement_with(&lifetime, generation),
            Err(LiveRemoteFreePageRetirementError::TerminallyRetained),
            "the detached collection fault cannot be retired as a completed drain"
        );
        assert_eq!(
            reinitialize_live_remote_page_with(&lifetime, generation),
            Err(LiveRemoteFreePageReinitializeError::TerminallyRetained),
            "the retained lifetime cannot reuse the same page metadata"
        );
    });
}
