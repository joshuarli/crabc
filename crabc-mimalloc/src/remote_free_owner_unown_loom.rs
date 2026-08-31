//! Finite owner-unown-window evidence for pinned mimalloc v3.5.0.
//!
//! This is deliberately separate from `remote_free_loom.rs`'s broad head and
//! lifetime-word claims. It models one source-specific branch only:
//! `theap.c:97-115` has collected the exiting owner's queue, `arena.c:1304-
//! 1355` has published one mapped-abandoned page, and a remote free arrives
//! after `arena.c:mi_abandoned_page_unown` observed the owned empty head but
//! before its release CAS. `arena.c:630-651` then requires collection of that
//! exact block; if it is the final client, `_mi_arenas_page_unabandon` must
//! precede `_mi_arenas_page_free`.
//!
//! The harness executes the production `mi_thread_free_t` publication,
//! unown, and detach helpers directly. Its small PageMap/backing record is an
//! external lifetime proof only: it has no page geometry, queue traversal,
//! allocator API, reclaim, or generic retained-route behavior.

use super::{
    AbandonedOwnerHeadTransition, THREAD_FREE_OWNED, ThreadFreeHead, detach_from_head,
    publish_to_head_with_owner, thread_free_block_address, try_unown_abandoned_head_with,
};
use crate::types::ThreadFree;
use loom::sync::atomic::{AtomicUsize, Ordering};

const OWNER_EMPTY_HEAD: ThreadFree = THREAD_FREE_OWNED;
const REMOTE_BLOCK: ThreadFree = 2;

const OWNER_LIVE: usize = 0;
const OWNER_ABANDONED_MAPPED: usize = 1;
const OWNER_UNABANDONED: usize = 2;

const MAPPED_ABANDONED_CLEAR: usize = 0;
const MAPPED_ABANDONED_PUBLISHED: usize = 1;
const PAGE_MAP_ROOT_PUBLISHED: usize = 1;
const PAGE_MAP_ENTRY_REGISTERED: usize = 1;
const PAGE_MAP_ENTRY_UNREGISTERED: usize = 0;
const METADATA_LIVE: usize = 0;
const METADATA_RELEASED: usize = 1;
const BACKING_LIVE: usize = 0;
const BACKING_RELEASED: usize = 1;
const TERMINAL_READY: usize = 0;
const TERMINAL_RELEASING: usize = 1;
const TERMINAL_RELEASED: usize = 2;
const TERMINAL_RETAINED: usize = 3;

/// A local Loom adapter for the exact production `ThreadFreeHead` boundary.
/// It intentionally does not share an implementation with the independent
/// claim-linearization model, so this regression's only common code is the
/// production atomic transition itself.
struct LoomHead(AtomicUsize);

impl LoomHead {
    fn owned_empty() -> Self { Self(AtomicUsize::new(OWNER_EMPTY_HEAD)) }

    fn load_acquire(&self) -> ThreadFree { self.0.load(Ordering::Acquire) }
}

impl ThreadFreeHead for LoomHead {
    fn load_relaxed(&self) -> ThreadFree { self.0.load(Ordering::Relaxed) }

    fn cas_weak_acq_rel(&self, expected: &mut ThreadFree, replacement: ThreadFree) -> bool {
        self.0
            .compare_exchange_weak(*expected, replacement, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|actual| *expected = actual)
            .is_ok()
    }

    fn fetch_or_acq_rel(&self, value: ThreadFree) -> ThreadFree {
        self.0.fetch_or(value, Ordering::AcqRel)
    }
}

/// The one non-geometric lifetime record necessary to make the source branch
/// auditable. The mapped-abandoned bit is intentionally distinct from the
/// PageMap entry: source `unabandon` clears the former, whereas terminal
/// release owns the latter and the backing lifetime.
struct OwnerUnownWindowModel {
    owner: AtomicUsize,
    mapped_abandoned: AtomicUsize,
    page_map_root: AtomicUsize,
    page_map_entry: AtomicUsize,
    metadata: AtomicUsize,
    backing: AtomicUsize,
    live_clients: AtomicUsize,
    publishers: AtomicUsize,
    terminal: AtomicUsize,
    retained_routes: AtomicUsize,
}

impl OwnerUnownWindowModel {
    fn one_live_client() -> Self {
        Self {
            owner: AtomicUsize::new(OWNER_LIVE),
            mapped_abandoned: AtomicUsize::new(MAPPED_ABANDONED_CLEAR),
            page_map_root: AtomicUsize::new(PAGE_MAP_ROOT_PUBLISHED),
            page_map_entry: AtomicUsize::new(PAGE_MAP_ENTRY_REGISTERED),
            metadata: AtomicUsize::new(METADATA_LIVE),
            backing: AtomicUsize::new(BACKING_LIVE),
            live_clients: AtomicUsize::new(1),
            publishers: AtomicUsize::new(0),
            terminal: AtomicUsize::new(TERMINAL_READY),
            retained_routes: AtomicUsize::new(0),
        }
    }

    /// `arena.c:_mi_arenas_page_abandon` publishes the mapped identity and
    /// bitmap before it calls `mi_abandoned_page_unown`.
    fn publish_mapped_abandon(&self, head: &LoomHead) {
        assert_eq!(head.load_acquire(), OWNER_EMPTY_HEAD);
        assert_eq!(
            self.owner.compare_exchange(
                OWNER_LIVE,
                OWNER_ABANDONED_MAPPED,
                Ordering::Release,
                Ordering::Acquire,
            ),
            Ok(OWNER_LIVE),
            "the source owner publishes one abandoned identity"
        );
        assert_eq!(
            self.mapped_abandoned.compare_exchange(
                MAPPED_ABANDONED_CLEAR,
                MAPPED_ABANDONED_PUBLISHED,
                Ordering::Release,
                Ordering::Acquire,
            ),
            Ok(MAPPED_ABANDONED_CLEAR),
            "mapped abandonment publishes once before the unown loop"
        );
    }

    /// Models the PageMap lifetime lease held by the exact remote producer.
    fn begin_remote_publication(&self) {
        assert_eq!(
            self.owner.load(Ordering::Acquire),
            OWNER_ABANDONED_MAPPED,
            "the in-window producer sees the already-published abandoned identity"
        );
        assert_eq!(
            self.mapped_abandoned.load(Ordering::Acquire),
            MAPPED_ABANDONED_PUBLISHED,
            "the producer sees the mapped-abandoned record before its atomic head publication"
        );
        assert_eq!(
            self.page_map_entry.load(Ordering::Acquire),
            PAGE_MAP_ENTRY_REGISTERED,
            "the producer cannot publish through an unregistered PageMap entry"
        );
        assert_eq!(
            self.metadata.load(Ordering::Acquire),
            METADATA_LIVE,
            "the producer cannot access released metadata"
        );
        assert_eq!(
            self.backing.load(Ordering::Acquire),
            BACKING_LIVE,
            "the producer cannot access released backing"
        );
        assert_eq!(
            self.publishers.fetch_add(1, Ordering::AcqRel),
            0,
            "the bounded witness has exactly one in-window producer"
        );
    }

    fn finish_final_client_publication(&self) {
        assert_eq!(
            self.live_clients.fetch_sub(1, Ordering::Release),
            1,
            "the injected remote free is the exact final client"
        );
        assert_eq!(
            self.publishers.fetch_sub(1, Ordering::Release),
            1,
            "the producer releases its PageMap lifetime before owner collection"
        );
    }

    /// `mi_abandoned_page_unown` reaches this only after source collection
    /// re-established an owned empty remote list. It must clear mapped state,
    /// retain the low owner bit, and select backing release without retrying
    /// the ordinary unown CAS.
    fn unabandon_after_empty_remote_collection(&self, head: &LoomHead) {
        assert_eq!(head.load_acquire(), OWNER_EMPTY_HEAD);
        assert_eq!(self.live_clients.load(Ordering::Acquire), 0);
        assert_eq!(self.publishers.load(Ordering::Acquire), 0);
        assert_eq!(
            self.mapped_abandoned
                .swap(MAPPED_ABANDONED_CLEAR, Ordering::AcqRel),
            MAPPED_ABANDONED_PUBLISHED,
            "_mi_arenas_page_unabandon clears the mapped state before page release"
        );
        assert_eq!(
            self.owner.compare_exchange(
                OWNER_ABANDONED_MAPPED,
                OWNER_UNABANDONED,
                Ordering::Release,
                Ordering::Acquire,
            ),
            Ok(OWNER_ABANDONED_MAPPED),
            "unabandon consumes the abandoned identity without relinquishing the low owner bit"
        );
    }

    /// The source's terminal backing owner. This models PageMap removal,
    /// metadata retirement, then backing release; no error or retained branch
    /// is selected by this successful owner-unown-window witness.
    fn release_backing_after_unabandon(&self, head: &LoomHead) {
        assert_eq!(head.load_acquire(), OWNER_EMPTY_HEAD);
        assert_eq!(
            self.owner.load(Ordering::Acquire),
            OWNER_UNABANDONED,
            "terminal release starts only after source unabandon"
        );
        assert_eq!(
            self.mapped_abandoned.load(Ordering::Acquire),
            MAPPED_ABANDONED_CLEAR,
            "terminal release cannot retain a mapped-abandoned record"
        );
        assert_eq!(
            self.terminal.compare_exchange(
                TERMINAL_READY,
                TERMINAL_RELEASING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(TERMINAL_READY),
            "the owned empty page has exactly one terminal backing owner"
        );
        assert_eq!(
            self.page_map_entry
                .swap(PAGE_MAP_ENTRY_UNREGISTERED, Ordering::AcqRel),
            PAGE_MAP_ENTRY_REGISTERED,
            "terminal release unregisters the page before metadata or backing release"
        );
        assert_eq!(
            self.page_map_root.swap(0, Ordering::AcqRel),
            PAGE_MAP_ROOT_PUBLISHED,
            "the sole entry lets the terminal route clear its PageMap root"
        );
        assert_eq!(
            self.metadata.swap(METADATA_RELEASED, Ordering::AcqRel),
            METADATA_LIVE,
            "metadata retires exactly once after PageMap removal"
        );
        assert_eq!(
            self.backing.swap(BACKING_RELEASED, Ordering::AcqRel),
            BACKING_LIVE,
            "backing releases exactly once after metadata retirement"
        );
        self.terminal.store(TERMINAL_RELEASED, Ordering::Release);
    }

    fn assert_released_without_retention(&self) {
        assert_eq!(self.owner.load(Ordering::Acquire), OWNER_UNABANDONED);
        assert_eq!(
            self.mapped_abandoned.load(Ordering::Acquire),
            MAPPED_ABANDONED_CLEAR
        );
        assert_eq!(self.page_map_entry.load(Ordering::Acquire), PAGE_MAP_ENTRY_UNREGISTERED);
        assert_eq!(self.page_map_root.load(Ordering::Acquire), 0);
        assert_eq!(self.metadata.load(Ordering::Acquire), METADATA_RELEASED);
        assert_eq!(self.backing.load(Ordering::Acquire), BACKING_RELEASED);
        assert_eq!(self.terminal.load(Ordering::Acquire), TERMINAL_RELEASED);
        assert_ne!(
            self.terminal.load(Ordering::Acquire),
            TERMINAL_RETAINED,
            "the successful source empty branch is never a retained route"
        );
        assert_eq!(
            self.retained_routes.load(Ordering::Acquire),
            0,
            "the owner-unown witness never records an error or retained route"
        );
    }
}

#[test]
fn loom_owner_unown_window_remote_empty_unabandons_then_releases_backing() {
    loom::model(|| {
        let model = OwnerUnownWindowModel::one_live_client();
        let head = LoomHead::owned_empty();
        let next = AtomicUsize::new(0);
        let collected = AtomicUsize::new(0);

        // `theap.c:mi_theap_page_collect` has already chosen the live-page
        // abandonment arm. This is the source identity/map publication just
        // before the common owner-unown loop.
        model.publish_mapped_abandon(&head);

        // The hook is the exact `arena.c:mi_abandoned_page_unown` point after
        // it saw `xthread_free == owned | NULL` but before its weak release
        // CAS. It exercises the real publication and unown atomics rather
        // than a parallel hand-written CAS model.
        let mut publish_before_unown_cas = Some(|| {
            model.begin_remote_publication();
            assert!(
                publish_to_head_with_owner(
                    &head,
                    REMOTE_BLOCK,
                    |_| true,
                    |previous_block| next.store(previous_block, Ordering::Relaxed),
                )
                .expect("the focused low-bit word stays source-valid"),
                "the in-window remote free observes the current owner bit"
            );
            model.finish_final_client_publication();
        });
        let transition = try_unown_abandoned_head_with(&head, &mut publish_before_unown_cas);
        let observed = match transition {
            AbandonedOwnerHeadTransition::RemotePublished(observed) => observed,
            AbandonedOwnerHeadTransition::Released | AbandonedOwnerHeadTransition::NotOwned => {
                panic!("the late producer must retain the owner and hand its exact block to collection")
            }
        };
        assert_eq!(
            observed & THREAD_FREE_OWNED,
            THREAD_FREE_OWNED,
            "the failed unown CAS keeps ownership on the exact remote block"
        );
        assert_eq!(thread_free_block_address(observed), REMOTE_BLOCK);

        let detached = detach_from_head(&head)
            .expect("the source owner keeps its low-bit proof through remote collection");
        assert_eq!(
            detached & THREAD_FREE_OWNED,
            THREAD_FREE_OWNED,
            "collection preserves the owner bit while it clears the remote head"
        );
        assert_eq!(thread_free_block_address(detached), REMOTE_BLOCK);
        assert_eq!(next.load(Ordering::Relaxed), 0);
        assert_eq!(
            collected.fetch_add(1, Ordering::AcqRel),
            0,
            "the final remote block is collected exactly once"
        );
        assert_eq!(head.load_acquire(), OWNER_EMPTY_HEAD);

        model.unabandon_after_empty_remote_collection(&head);
        model.release_backing_after_unabandon(&head);
        model.assert_released_without_retention();
    });
}
