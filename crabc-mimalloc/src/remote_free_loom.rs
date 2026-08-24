//! Finite Loom evidence for the source-shaped `mi_thread_free_t` atomic head.
//!
//! The production remote list stores native block pointers, and the owner
//! mutates `used`/`local_free` after detaching it. Those raw-pointer lifetime
//! and owner-only fields are outside Loom's address-free scheduler model.
//! This module instead gives each producer-owned block one unique aligned
//! integer identity and a modeled `next` word. It executes
//! [`super::publish_to_head`] and [`super::detach_from_head`] directly, so the
//! production Relaxed load plus AcqRel/Acquire weak-CAS transitions cannot
//! drift from this evidence.
//!
//! It proves only live-page remote publication and collection. It does not
//! model page association, abandonment/adoption, retirement/release, TLS, or
//! owner-local `used`/`local_free` mutation.

use super::{
    THREAD_FREE_OWNED, ThreadFree, detach_from_head, publish_to_head,
    thread_free_block_address,
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
