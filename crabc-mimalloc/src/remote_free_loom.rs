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
    LiveRemoteFreePagePublicationError, LiveRemoteFreePageReinitializeError,
    LiveRemoteFreePageRetirementError,
    THREAD_FREE_OWNED,
    ThreadFree, begin_live_remote_page_publication_with,
    begin_live_remote_page_retirement_with, claim_abandoned_owner_with,
    detach_from_head, finish_live_remote_page_publication_with, live_remote_page_word,
    publish_to_head, publish_to_head_with_owner, reinitialize_live_remote_page_with,
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
