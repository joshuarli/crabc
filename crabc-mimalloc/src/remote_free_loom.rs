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
//! drift from this evidence.
//!
//! It proves the low-bit head races for live-owner collection and bounded
//! abandoned-page claim/unown. It does not model page identity, arena lookup,
//! bitmap field atomics, retirement/release, TLS, or owner-local
//! `used`/`local_free` mutation.

use super::{
    AbandonedExpectedHeadTransition, AbandonedOwnerClaim, AbandonedOwnerHeadTransition,
    THREAD_FREE_OWNED,
    ThreadFree, claim_abandoned_owner_with, detach_from_head, publish_to_head,
    publish_to_head_with_owner, thread_free_block_address,
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
