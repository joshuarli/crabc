//! Loom model of the pinned mimalloc v3.5.0 page-local remote-free protocol.
//!
//! Source map: `src/free.c:62-97` (`mi_free_block_mt`), `src/free.c:368-515`
//! (`mi_free_try_collect_mt` with its try-free, reabandon, and
//! unown-from-free helpers), `src/page.c:150-269`
//! (`mi_page_thread_free_collect`, `_mi_page_free_collect`, and
//! `_mi_page_free_collect_partly`), `src/page.c:277-304,393-410`
//! (`_mi_theap_page_reclaim`, `_mi_page_abandon`, `_mi_page_free`),
//! `src/arena.c:631-680,725-770,1285-1420` (`mi_abandoned_page_unown`,
//! `mi_arena_try_claim_abandoned`, `mi_arenas_page_try_find_abandoned`,
//! `_mi_arenas_page_free`, `_mi_arenas_page_abandon`,
//! `_mi_arenas_page_try_reabandon_to_mapped`, `_mi_arenas_page_unabandon`),
//! `src/bitmap.c:90-130,1340-1370` (`mi_bfield_atomic_set`,
//! `mi_bfield_atomic_clear_once_set`, `mi_bitmap_try_find_and_claim_visit`),
//! and `include/mimalloc/internal.h:898-929,1008-1037,1089-1120` (page
//! predicates, `mi_page_set_theap`, abandoned identities, and the
//! `mi_thread_free_t` helpers).
//!
//! # Production transitions
//!
//! Every `xthread_free` transition executes this crate's implementation
//! through the private `ThreadFreeHead` boundary: `publish_to_head_with_owner`
//! (the `mi_free_block_mt` CAS loop, here always `allow_collect=true` as in
//! `mi_free`), `detach_from_head` (`mi_page_thread_free_collect`),
//! `claim_abandoned_owner_with` (`mi_page_claim_ownership`),
//! `try_unown_abandoned_head_with` (`mi_abandoned_page_unown`), and
//! `try_unown_abandoned_expected_head_with`
//! (`mi_abandoned_page_unown_from_free`). The `xthread_id` identity CAS and the
//! page's one `pages_abandoned` bitmap bit follow `abandoned::set_thread_identity`
//! and the `bitmap.rs` bfield operations with the exact source orderings;
//! those production functions act on core atomics that Loom cannot schedule.
//!
//! # Checked lifetime contract
//!
//! Pinned source keeps a page's PageMap entry and metadata alive without a
//! lease or publication counter. A live client block stays counted in `used`
//! until an owner collects its publication, and only the current owner (a
//! live Theap or the holder of the low `xthread_free` bit) may observe
//! `used == 0` and release the page. The model keeps every source-plain field
//! in a Loom `UnsafeCell`: the PageMap entry, page metadata, the owner-only
//! `used` and free lists, and each block's first word. A client reads its
//! PageMap entry, page geometry, and block before it publishes; the release
//! writes the entry and metadata. Loom rejects every interleaving in which
//! the production atomics fail to order those plain accesses, and the model
//! assertions reject a release before a legal client finishes, a block
//! collected twice, a second release, a live page without its owner bit, or an
//! abandoned page left all-free without its release.
//!
//! The scenarios compose generic source roles on one page: foreign
//! `mi_free`, live-owner local free and collection, owner exit
//! (`_mi_page_abandon`), and an arena reader claiming a mapped abandoned page.
//! No scenario selects a Rust geometry route, owner registry, client ledger,
//! PageMap lease, or publication counter. Block size and `reserved` only
//! select the source's own branches: `MI_SMALL_SIZE_MAX` partial collection,
//! `mi_page_is_full` mapping, and `mi_page_is_mostly_used` reabandonment.
//!
//! Every modeled producer is a foreign thread without a Theap for the page's
//! Heap, so `_mi_page_associated_theap_peek` returns `NULL` and
//! `mi_abandoned_page_try_reclaim` returns before any state change; it is not
//! modeled. Fault injection after an irreversible transition is not an atomic
//! interleaving; the deterministic unit and native tests keep that evidence.
//!
//! The model is only evidence if its plain cells can observe a missing
//! ordering. [`loom_model_rejects_a_head_without_source_acq_rel_ordering`]
//! reruns the live-owner schedule with every head operation weakened to
//! `Relaxed` and requires Loom to report the resulting causality violation;
//! [`loom_model_rejects_a_client_read_after_its_publication`] requires the
//! same report for a page release that is not ordered after a client's read.
//!
//! Each model runs under `LOOM_MAX_PREEMPTIONS` when it is set, and otherwise
//! under [`DEFAULT_PREEMPTION_BOUND`]. The x86-64 lifecycle judge runs this
//! module as its `remote-free-finite-loom-page-protocol` lane:
//! `./compat/allocator/run-x86_64.sh allocator-lifecycle`.

use super::{
    AbandonedExpectedHeadTransition, AbandonedOwnerClaim, AbandonedOwnerHeadTransition,
    THREAD_FREE_OWNED, ThreadFree, ThreadFreeHead, claim_abandoned_owner_with, detach_from_head,
    is_owned, publish_to_head_with_owner, thread_free_block_address,
    try_unown_abandoned_expected_head_with, try_unown_abandoned_head_with,
};
use crate::config::SMALL_SIZE_MAX;
use crate::types::{PAGE_FLAG_MASK, THREAD_ID_ABANDONED, THREAD_ID_ABANDONED_MAPPED};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;
use std::vec::Vec;

/// Bounded schedule exploration used when `LOOM_MAX_PREEMPTIONS` is unset.
const DEFAULT_PREEMPTION_BOUND: usize = 3;

const BLOCK_COUNT: usize = 3;

/// Live source thread identities: nonzero, flag bits clear, and distinct from
/// the special abandoned (0), abandoned-mapped (4), and detached (8) ids.
const OWNER_THREAD_ID: usize = 1 << 8;
const READER_THREAD_ID: usize = 2 << 8;

/// A `MI_SMALL_SIZE_MAX` page takes the partial collector in
/// `mi_free_try_collect_mt`; every larger page uses ordinary collection.
const SMALL_BLOCK_SIZE: usize = 16;
const REGULAR_BLOCK_SIZE: usize = SMALL_SIZE_MAX + 16;

/// A live owner's head: its low owner bit over an empty remote list.
const OWNED_EMPTY: ThreadFree = THREAD_FREE_OWNED;

/// The page's slice bit in its arena's `pages_abandoned[bin]` bitmap.
const ABANDONED_BIT: usize = 1;

/// A Loom word that can stand in for a page's `xthread_free` field.
trait ModelHead: ThreadFreeHead + Send + Sync + 'static {
    fn new(word: ThreadFree) -> Self;
}

/// Test-only adapter for the production `ThreadFreeHead` boundary. The
/// orderings match `crate::atomic::word_load_relaxed`,
/// `word_cas_weak_acq_rel`, and `word_or_acq_rel` exactly.
impl ThreadFreeHead for AtomicUsize {
    #[inline]
    fn load_relaxed(&self) -> ThreadFree {
        self.load(Ordering::Relaxed)
    }

    #[inline]
    fn cas_weak_acq_rel(&self, expected: &mut ThreadFree, replacement: ThreadFree) -> bool {
        self.compare_exchange_weak(*expected, replacement, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|actual| *expected = actual)
            .is_ok()
    }

    #[inline]
    fn fetch_or_acq_rel(&self, value: ThreadFree) -> ThreadFree {
        self.fetch_or(value, Ordering::AcqRel)
    }
}

impl ModelHead for AtomicUsize {
    fn new(word: ThreadFree) -> Self {
        AtomicUsize::new(word)
    }
}

/// Negative control: the production head transitions with the source
/// AcqRel/Acquire orderings removed. Nothing but the model's plain cells can
/// then notice that a release is no longer ordered after a client's reads.
struct UnorderedHead(AtomicUsize);

impl ThreadFreeHead for UnorderedHead {
    fn load_relaxed(&self) -> ThreadFree {
        self.0.load(Ordering::Relaxed)
    }

    fn cas_weak_acq_rel(&self, expected: &mut ThreadFree, replacement: ThreadFree) -> bool {
        self.0
            .compare_exchange_weak(*expected, replacement, Ordering::Relaxed, Ordering::Relaxed)
            .map_err(|actual| *expected = actual)
            .is_ok()
    }

    fn fetch_or_acq_rel(&self, value: ThreadFree) -> ThreadFree {
        self.0.fetch_or(value, Ordering::Relaxed)
    }
}

impl ModelHead for UnorderedHead {
    fn new(word: ThreadFree) -> Self {
        Self(AtomicUsize::new(word))
    }
}

/// An aligned, nonzero block address whose low owner bit stays clear.
const fn block_address(index: usize) -> ThreadFree {
    (index + 1) << 4
}

fn block_index(address: ThreadFree) -> usize {
    assert!(address != 0 && address & 0xf == 0, "a remote list names only model blocks");
    let index = (address >> 4) - 1;
    assert!(index < BLOCK_COUNT, "a remote list names only model blocks");
    index
}

#[inline]
const fn is_abandoned(xthread_id: usize) -> bool {
    matches!(
        xthread_id & !PAGE_FLAG_MASK,
        THREAD_ID_ABANDONED | THREAD_ID_ABANDONED_MAPPED
    )
}

/// Page geometry fixed at page publication, plus the terminal release mark.
struct PageMetadata {
    block_size: usize,
    reserved: usize,
    released: bool,
}

/// Ordinary page fields that only the current source owner may access.
struct OwnerFields {
    used: usize,
    free: ThreadFree,
    local_free: ThreadFree,
    /// Model-only record of each remote block's one collection.
    collected: [bool; BLOCK_COUNT],
}

/// The source state a scenario starts from.
struct PageImage {
    block_size: usize,
    reserved: usize,
    used: usize,
    xthread_id: usize,
    xthread_free: ThreadFree,
    abandoned_bitmap: usize,
}

impl PageImage {
    /// A page owned by a live Theap whose first `used` blocks are live.
    const fn live(block_size: usize, reserved: usize, used: usize) -> Self {
        Self {
            block_size,
            reserved,
            used,
            xthread_id: OWNER_THREAD_ID,
            xthread_free: OWNED_EMPTY,
            abandoned_bitmap: 0,
        }
    }

    /// A page that `_mi_arenas_page_abandon` published to its arena bitmap and
    /// then unowned, with its first `used` blocks still live.
    const fn abandoned_mapped(block_size: usize, reserved: usize, used: usize) -> Self {
        Self {
            block_size,
            reserved,
            used,
            xthread_id: THREAD_ID_ABANDONED_MAPPED,
            xthread_free: 0,
            abandoned_bitmap: ABANDONED_BIT,
        }
    }
}

/// A model page whose head uses the exact production orderings.
type SourcePage = ModelPage<AtomicUsize>;

/// One arena page and its PageMap entry.
struct ModelPage<H: ModelHead = AtomicUsize> {
    xthread_id: AtomicUsize,
    xthread_free: H,
    abandoned_bitmap: AtomicUsize,
    page_map_entry: UnsafeCell<bool>,
    metadata: UnsafeCell<PageMetadata>,
    owner: UnsafeCell<OwnerFields>,
    block_next: [UnsafeCell<ThreadFree>; BLOCK_COUNT],
    releases: AtomicUsize,
}

// SAFETY: this is the claim under test. Loom's `UnsafeCell` checks every
// plain access against the happens-before order its atomics establish and
// fails the model on any unsynchronized conflicting access.
unsafe impl<H: ModelHead> Sync for ModelPage<H> {}

impl<H: ModelHead> ModelPage<H> {
    fn new(image: PageImage) -> Self {
        assert!(image.used <= BLOCK_COUNT && image.used <= image.reserved);
        Self {
            xthread_id: AtomicUsize::new(image.xthread_id),
            xthread_free: H::new(image.xthread_free),
            abandoned_bitmap: AtomicUsize::new(image.abandoned_bitmap),
            page_map_entry: UnsafeCell::new(true),
            metadata: UnsafeCell::new(PageMetadata {
                block_size: image.block_size,
                reserved: image.reserved,
                released: false,
            }),
            owner: UnsafeCell::new(OwnerFields {
                used: image.used,
                free: 0,
                local_free: 0,
                collected: [false; BLOCK_COUNT],
            }),
            block_next: core::array::from_fn(|_| UnsafeCell::new(0)),
            releases: AtomicUsize::new(0),
        }
    }

    // ----- client front edge ------------------------------------------------

    /// `mi_validate_ptr_page` plus the geometry and client reads of
    /// usable-size and realloc's bounded copy, for one exact live client.
    fn read_live_client(&self, block: usize) -> usize {
        assert!(
            self.page_map_entry.with(|entry| unsafe { *entry }),
            "a live client's PageMap entry stays registered"
        );
        let block_size = self.metadata.with(|metadata| {
            let metadata = unsafe { &*metadata };
            assert!(!metadata.released, "a live client's page metadata stays live");
            metadata.block_size
        });
        self.block_next[block].with(|_| ());
        block_size
    }

    /// `mi_free` from a foreign thread: `mi_free_block_mt(page, block,
    /// allow_collect=true)` and, after a claiming CAS, its source tail.
    fn remote_free(&self, block: usize) {
        let block_size = self.read_live_client(block);
        let was_owned = publish_to_head_with_owner(
            &self.xthread_free,
            block_address(block),
            |_| true,
            |previous_block| {
                self.block_next[block].with_mut(|next| unsafe { *next = previous_block });
            },
        )
        .expect("model blocks keep the low owner bit clear");
        if !was_owned {
            assert!(
                is_abandoned(self.xthread_id.load(Ordering::Relaxed)),
                "only an abandoned page has an unowned head to claim"
            );
            self.free_try_collect_mt(block, block_size);
        }
    }

    /// `mi_free_try_collect_mt` under the low owner bit this free claimed.
    fn free_try_collect_mt(&self, block: usize, block_size: usize) {
        let expected_head = if block_size <= SMALL_SIZE_MAX {
            self.page_free_collect_partly(block);
            block_address(block)
        } else {
            self.page_free_collect();
            0
        };
        if self.abandoned_page_try_free() {
            return;
        }
        if self.abandoned_page_try_reabandon_to_mapped() {
            return;
        }
        self.abandoned_page_unown_from_free(expected_head);
    }

    // ----- owner-side collection -------------------------------------------

    /// `mi_page_thread_free_collect`: the production detach, then
    /// `mi_page_thread_collect_to_local`.
    fn thread_free_collect(&self) {
        let detached =
            detach_from_head(&self.xthread_free).expect("only the source owner collects");
        let head = thread_free_block_address(detached);
        if head != 0 {
            self.collect_to_local(head);
        }
    }

    /// `mi_page_thread_collect_to_local` for a list detached from the head.
    fn collect_to_local(&self, head: ThreadFree) {
        self.owner.with_mut(|owner| {
            let owner = unsafe { &mut *owner };
            let mut count = 0;
            let mut last = head;
            loop {
                let index = block_index(last);
                assert!(!owner.collected[index], "a remote block is collected at most once");
                owner.collected[index] = true;
                count += 1;
                let next = self.block_next[index].with(|next| unsafe { *next });
                if next == 0 {
                    break;
                }
                last = next;
            }
            assert!(count <= owner.used, "a remote list never exceeds the used count");
            self.block_next[block_index(last)]
                .with_mut(|next| unsafe { *next = owner.local_free });
            owner.local_free = head;
            owner.used -= count;
        });
    }

    /// The non-force local-list half of `_mi_page_free_collect`.
    fn move_local_to_free_if_empty(&self) {
        self.owner.with_mut(|owner| {
            let owner = unsafe { &mut *owner };
            if owner.local_free != 0 && owner.free == 0 {
                owner.free = owner.local_free;
                owner.local_free = 0;
            }
        });
    }

    /// `_mi_page_free_collect(page, false)`.
    fn page_free_collect(&self) {
        self.thread_free_collect();
        self.move_local_to_free_if_empty();
    }

    /// `_mi_page_free_collect_partly(page, head)`: collect the list behind
    /// the just-published `head` without an atomic operation, and the head
    /// itself only when it is the last used block.
    fn page_free_collect_partly(&self, head: usize) {
        let next = self.block_next[head].with(|next| unsafe { *next });
        if next != 0 {
            self.block_next[head].with_mut(|link| unsafe { *link = 0 });
            self.collect_to_local(next);
            self.move_local_to_free_if_empty();
        }
        if self.used() == 1 {
            assert_eq!(
                thread_free_block_address(self.xthread_free.load_relaxed()),
                block_address(head),
                "the last used block is still the published head"
            );
            self.page_free_collect();
        }
    }

    // ----- source predicates -------------------------------------------------

    fn used(&self) -> usize {
        self.owner.with(|owner| unsafe { (*owner).used })
    }

    fn reserved(&self) -> usize {
        self.metadata.with(|metadata| unsafe { (*metadata).reserved })
    }

    /// `mi_page_is_full`.
    fn is_full(&self) -> bool {
        self.used() == self.reserved()
    }

    /// `mi_page_is_mostly_used`: at most one eighth of `reserved` is free.
    fn is_mostly_used(&self) -> bool {
        let reserved = self.reserved();
        reserved - self.used() <= reserved / 8
    }

    fn identity(&self) -> usize {
        self.xthread_id.load(Ordering::Relaxed) & !PAGE_FLAG_MASK
    }

    /// `mi_page_set_theap`: a Release CAS that preserves the two flag bits.
    fn set_thread_identity(&self, thread_id: usize) {
        let mut previous = self.xthread_id.load(Ordering::Relaxed);
        loop {
            let replacement = thread_id | (previous & PAGE_FLAG_MASK);
            match self.xthread_id.compare_exchange_weak(
                previous,
                replacement,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => previous = actual,
            }
        }
    }

    // ----- abandoned-page tail ----------------------------------------------

    /// `mi_abandoned_page_try_free`.
    fn abandoned_page_try_free(&self) -> bool {
        if self.used() != 0 {
            return false;
        }
        self.arenas_page_unabandon();
        self.arenas_page_free();
        true
    }

    /// `mi_abandoned_page_try_reabandon_to_mapped` and
    /// `_mi_arenas_page_try_reabandon_to_mapped` for an arena page.
    fn abandoned_page_try_reabandon_to_mapped(&self) -> bool {
        if self.is_mostly_used() || self.identity() == THREAD_ID_ABANDONED_MAPPED {
            return false;
        }
        assert!(!self.is_full(), "a page that is not mostly used is not full");
        self.arenas_page_abandon();
        true
    }

    /// `mi_abandoned_page_unown_from_free`, including its expected-head
    /// release of a small page's retained published head.
    fn abandoned_page_unown_from_free(&self, mut expected_head: ThreadFree) {
        loop {
            let transition = try_unown_abandoned_expected_head_with(
                &self.xthread_free,
                expected_head,
                &mut None::<fn()>,
            )
            .expect("model blocks keep the low owner bit clear");
            match transition {
                AbandonedExpectedHeadTransition::Released => return,
                AbandonedExpectedHeadTransition::OwnedEmpty => {}
                AbandonedExpectedHeadTransition::RemotePublished => loop {
                    self.page_free_collect();
                    if self.abandoned_page_try_free() {
                        return;
                    }
                    if self.abandoned_page_try_reabandon_to_mapped() {
                        return;
                    }
                    let observed = self.xthread_free.load_relaxed();
                    if thread_free_block_address(observed) == 0 {
                        break;
                    }
                },
                AbandonedExpectedHeadTransition::NotOwned => {
                    panic!("only the owner-bit holder unowns an abandoned page")
                }
            }
            expected_head = 0;
        }
    }

    /// `_mi_arenas_page_abandon` for an arena page after its identity became
    /// abandoned: publish a non-full page to the arena bitmap, then unown.
    fn arenas_page_abandon(&self) {
        if !self.is_full() {
            self.xthread_id
                .fetch_or(THREAD_ID_ABANDONED_MAPPED, Ordering::Relaxed);
            let previous = self.abandoned_bitmap.fetch_or(ABANDONED_BIT, Ordering::AcqRel);
            assert_eq!(previous & ABANDONED_BIT, 0, "a page is mapped once at a time");
        }
        self.abandoned_page_unown();
    }

    /// `mi_abandoned_page_unown`. A publication raced after abandonment may
    /// make the page all free; its collector then releases the page.
    fn abandoned_page_unown(&self) {
        loop {
            match try_unown_abandoned_head_with(&self.xthread_free, &mut None::<fn()>) {
                AbandonedOwnerHeadTransition::Released => return,
                AbandonedOwnerHeadTransition::RemotePublished(_) => {
                    self.page_free_collect();
                    if self.used() == 0 {
                        self.arenas_page_unabandon();
                        self.arenas_page_free();
                        return;
                    }
                }
                AbandonedOwnerHeadTransition::NotOwned => {
                    panic!("only the owner-bit holder unowns an abandoned page")
                }
            }
        }
    }

    /// `_mi_arenas_page_unabandon`: a mapped page waits for any arena reader
    /// that cleared its bit to restore it, then clears it once.
    fn arenas_page_unabandon(&self) {
        if self.identity() == THREAD_ID_ABANDONED_MAPPED {
            self.abandoned_bitmap_clear_once_set();
            self.xthread_id.fetch_and(PAGE_FLAG_MASK, Ordering::Relaxed);
        }
    }

    /// `mi_bfield_atomic_clear_once_set` for the page's bitmap bit.
    fn abandoned_bitmap_clear_once_set(&self) {
        let mut observed = self.abandoned_bitmap.load(Ordering::Relaxed);
        loop {
            if observed & ABANDONED_BIT == 0 {
                observed = self.abandoned_bitmap.load(Ordering::Acquire);
                while observed & ABANDONED_BIT == 0 {
                    thread::yield_now();
                    observed = self.abandoned_bitmap.load(Ordering::Acquire);
                }
            }
            match self.abandoned_bitmap.compare_exchange_weak(
                observed,
                observed & !ABANDONED_BIT,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => observed = actual,
            }
        }
    }

    /// `_mi_arenas_page_free`: PageMap unregistration, then metadata and
    /// slice release, by the page's one owner once it is all free.
    fn arenas_page_free(&self) {
        assert!(
            is_owned(self.xthread_free.load_relaxed()),
            "only the source owner releases a page"
        );
        assert!(
            is_abandoned(self.xthread_id.load(Ordering::Relaxed)),
            "release follows the abandoned identity"
        );
        assert_eq!(self.used(), 0, "release requires an all-free page");
        self.page_map_entry.with_mut(|entry| unsafe {
            assert!(*entry, "the PageMap range is unregistered once");
            *entry = false;
        });
        self.metadata.with_mut(|metadata| unsafe {
            assert!(!(*metadata).released, "page metadata is released once");
            (*metadata).released = true;
        });
        assert_eq!(
            self.releases.fetch_add(1, Ordering::Relaxed),
            0,
            "a page reaches one terminal release"
        );
    }

    // ----- live owner ---------------------------------------------------------

    /// `mi_free_block_local` by the page's live owner.
    fn owner_local_free(&self, block: usize) {
        self.read_live_client(block);
        self.owner.with_mut(|owner| {
            let owner = unsafe { &mut *owner };
            self.block_next[block].with_mut(|next| unsafe { *next = owner.local_free });
            owner.local_free = block_address(block);
            owner.used -= 1;
        });
    }

    /// `_mi_page_free` for a live owner's all-free page.
    fn owner_page_free(&self) {
        assert_eq!(self.used(), 0, "a live owner frees only an all-free page");
        self.set_thread_identity(THREAD_ID_ABANDONED);
        self.arenas_page_free();
    }

    /// A live owner keeps collecting its page until every client is freed,
    /// then retires and frees it.
    fn owner_collect_until_all_free_then_free(&self) {
        loop {
            self.page_free_collect();
            if self.used() == 0 {
                break;
            }
            thread::yield_now();
        }
        self.owner_page_free();
    }

    /// `_mi_page_abandon` from `_mi_theap_collect_abandon` at owner exit.
    fn owner_exit(&self) {
        self.page_free_collect();
        if self.used() == 0 {
            self.owner_page_free();
            return;
        }
        self.set_thread_identity(THREAD_ID_ABANDONED);
        self.arenas_page_abandon();
    }

    // ----- arena reader -------------------------------------------------------

    /// `mi_bitmap_try_find_and_claim_visit` with `mi_arena_try_claim_abandoned`
    /// for the page's bit. Returns whether this reader claimed the page.
    fn arena_try_find_and_claim(&self) -> bool {
        // `mi_bchunk_try_find_and_clear`: relaxed scan, then the optimistic
        // AcqRel single-bit clear.
        if self.abandoned_bitmap.load(Ordering::Relaxed) & ABANDONED_BIT == 0 {
            return false;
        }
        if self.abandoned_bitmap.fetch_and(!ABANDONED_BIT, Ordering::AcqRel) & ABANDONED_BIT == 0 {
            return false;
        }
        // `mi_arena_page_at_slice`: the cleared bit names this page.
        self.metadata.with(|metadata| {
            assert!(!unsafe { (*metadata).released }, "a mapped bit names live metadata");
        });
        match claim_abandoned_owner_with(&self.xthread_free) {
            AbandonedOwnerClaim::ClaimedUnowned => true,
            AbandonedOwnerClaim::AlreadyOwned => {
                // `keep_abandoned`: restore the bit so a concurrent
                // `_mi_arenas_page_unabandon` can finish.
                let previous = self.abandoned_bitmap.fetch_or(ABANDONED_BIT, Ordering::AcqRel);
                assert_eq!(previous & ABANDONED_BIT, 0, "only this reader cleared the bit");
                false
            }
        }
    }

    /// The claimed page's `_mi_page_free_collect` in
    /// `mi_arenas_page_try_find_abandoned`, then `_mi_theap_page_reclaim`.
    fn arena_reclaim(&self, thread_id: usize) {
        assert_eq!(
            self.identity(),
            THREAD_ID_ABANDONED_MAPPED,
            "a claimed bitmap page carries the mapped identity"
        );
        self.page_free_collect();
        self.set_thread_identity(thread_id);
        self.page_free_collect();
    }

    // ----- quiescent audit ----------------------------------------------------

    /// Audits the page after every model thread joined. `remote` names the
    /// blocks freed by foreign threads and `live_clients` the blocks that
    /// remain allocated.
    fn assert_quiescent(&self, remote: &[usize], live_clients: usize) {
        let releases = self.releases.load(Ordering::Relaxed);
        let registered = self.page_map_entry.with(|entry| unsafe { *entry });
        let metadata_released = self.metadata.with(|metadata| unsafe { (*metadata).released });
        assert_eq!(registered, releases == 0, "PageMap registration matches the release");
        assert_eq!(metadata_released, releases == 1, "metadata release matches the release");
        let collected = self.owner.with(|owner| unsafe { (*owner).collected });
        if releases == 1 {
            assert_eq!(live_clients, 0, "a page with a live client is never released");
            for &block in remote {
                assert!(collected[block], "a released page collected every remote block");
            }
            return;
        }

        // Joining every model thread already ordered all head updates.
        let head = self.xthread_free.load_relaxed();
        let mut pending = Vec::new();
        let mut address = thread_free_block_address(head);
        while address != 0 {
            let index = block_index(address);
            pending.push(index);
            address = self.block_next[index].with(|next| unsafe { *next });
        }
        for &block in remote {
            assert!(
                collected[block] != pending.contains(&block),
                "each remote block is collected or still published, never both"
            );
        }
        let used = self.used();
        assert_eq!(
            used,
            live_clients + pending.len(),
            "every uncollected publication remains counted in used"
        );
        let identity = self.identity();
        if is_abandoned(identity) {
            assert!(!is_owned(head), "an abandoned page is left without an owner");
            assert!(used > 0, "an all-free abandoned page is always released");
            assert_eq!(
                self.abandoned_bitmap.load(Ordering::Relaxed) & ABANDONED_BIT != 0,
                identity == THREAD_ID_ABANDONED_MAPPED,
                "the arena bitmap bit tracks the mapped identity"
            );
        } else {
            assert!(is_owned(head), "a live owner keeps the low owner bit");
        }
    }
}

fn model<F>(scenario: F)
where
    F: Fn() + Sync + Send + 'static,
{
    let mut builder = loom::model::Builder::new();
    if builder.preemption_bound.is_none() {
        builder.preemption_bound = Some(DEFAULT_PREEMPTION_BOUND);
    }
    builder.check(scenario);
}

fn spawn_remote_free<H: ModelHead>(
    page: &Arc<ModelPage<H>>,
    block: usize,
) -> thread::JoinHandle<()> {
    let page = Arc::clone(page);
    thread::spawn(move || page.remote_free(block))
}

/// The claim linearity that the source tail relies on is a type property:
/// the production claim cannot be duplicated instead of moved into its
/// continuation. Either `Copy` or `Clone` would make the implementation
/// choice below ambiguous and stop this test from compiling.
#[test]
fn claimed_abandoned_remote_free_stays_linear() {
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

/// Two foreign frees publish to a live owner that concurrently collects and
/// frees its own client. The owner releases its page as soon as it has
/// collected both publications, while the producers may still be finishing.
fn live_owner_collects_remote_frees_before_its_page_release<H: ModelHead>() {
    let page = Arc::new(ModelPage::<H>::new(PageImage::live(REGULAR_BLOCK_SIZE, 4, 3)));
    let producers = [spawn_remote_free(&page, 0), spawn_remote_free(&page, 1)];
    page.owner_local_free(2);
    page.owner_collect_until_all_free_then_free();
    for producer in producers {
        producer.join().expect("remote free completes");
    }
    page.assert_quiescent(&[0, 1], 0);
}

#[test]
fn loom_live_owner_collects_remote_frees_before_its_page_release() {
    model(live_owner_collects_remote_frees_before_its_page_release::<AtomicUsize>);
}

/// The same schedule without the source head orderings must fail: a
/// producer's client reads and block link are then unordered with the
/// owner's collection and page release.
#[test]
#[should_panic(expected = "Causality violation")]
fn loom_model_rejects_a_head_without_source_acq_rel_ordering() {
    model(live_owner_collects_remote_frees_before_its_page_release::<UnorderedHead>);
}

/// A producer that reads its page geometry after its publication is no longer
/// a legal client: the owner may collect that block and release the page
/// concurrently. Even with the source orderings, the model must reject the
/// release as unordered with that late read.
#[test]
#[should_panic(expected = "Causality violation")]
fn loom_model_rejects_a_client_read_after_its_publication() {
    model(|| {
        let page = Arc::new(SourcePage::new(PageImage::live(REGULAR_BLOCK_SIZE, 4, 2)));
        let producer_page = Arc::clone(&page);
        let producer = thread::spawn(move || {
            producer_page.remote_free(0);
            producer_page.metadata.with(|metadata| unsafe { (*metadata).block_size });
        });
        page.owner_local_free(1);
        page.owner_collect_until_all_free_then_free();
        producer.join().expect("remote free completes");
    });
}

/// Owner exit collects, abandons a non-full page to its arena bitmap, and
/// unowns it while both final clients are freed remotely. Whichever of the
/// exiting owner or a claiming producer observes the page all free releases
/// it exactly once, after every client's PageMap and metadata reads.
#[test]
fn loom_owner_exit_racing_final_remote_frees_releases_the_page_once() {
    model(|| {
        let page = Arc::new(SourcePage::new(PageImage::live(REGULAR_BLOCK_SIZE, 4, 2)));
        let producers = [spawn_remote_free(&page, 0), spawn_remote_free(&page, 1)];
        page.owner_exit();
        for producer in producers {
            producer.join().expect("remote free completes");
        }
        page.assert_quiescent(&[0, 1], 0);
    });
}

/// A full page is abandoned unmapped. The first claiming producer finds it no
/// longer mostly used and reabandons it to the arena bitmap; the final free
/// then clears that bit before the one release.
#[test]
fn loom_full_page_owner_exit_reabandons_to_mapped_then_releases_once() {
    model(|| {
        let page = Arc::new(SourcePage::new(PageImage::live(REGULAR_BLOCK_SIZE, 2, 2)));
        let producers = [spawn_remote_free(&page, 0), spawn_remote_free(&page, 1)];
        page.owner_exit();
        for producer in producers {
            producer.join().expect("remote free completes");
        }
        page.assert_quiescent(&[0, 1], 0);
    });
}

/// An arena reader clears a mapped page's bit and claims its low owner bit
/// while the page's last client is freed remotely. Exactly one of them owns
/// the page: a failed reader restores the bit for the producer's unabandon,
/// and a successful reader reclaims the page and later frees it.
#[test]
fn loom_arena_reader_racing_final_remote_free_has_one_owner_and_one_release() {
    model(|| {
        let page = Arc::new(SourcePage::new(PageImage::abandoned_mapped(REGULAR_BLOCK_SIZE, 4, 1)));
        let producer = spawn_remote_free(&page, 0);
        let reader_page = Arc::clone(&page);
        let reader = thread::spawn(move || {
            if reader_page.arena_try_find_and_claim() {
                reader_page.arena_reclaim(READER_THREAD_ID);
                reader_page.owner_collect_until_all_free_then_free();
            }
        });
        producer.join().expect("remote free completes");
        reader.join().expect("arena reader completes");
        page.assert_quiescent(&[0], 0);
    });
}

/// On a small page, a claiming free collects only the list behind its own
/// head and may unown the page with that head still published. The next
/// claiming free collects the retained head as the page's last used block.
#[test]
fn loom_small_page_partial_collection_retains_its_head_until_the_final_free() {
    model(|| {
        let page = Arc::new(SourcePage::new(PageImage::abandoned_mapped(SMALL_BLOCK_SIZE, 16, 2)));
        let producer = spawn_remote_free(&page, 0);
        page.remote_free(1);
        producer.join().expect("remote free completes");
        page.assert_quiescent(&[0, 1], 0);
    });
}

/// A small-page free that leaves one client live: the claiming producer
/// unowns the page with its published head retained in `xthread_free`.
#[test]
fn loom_small_page_unown_from_free_keeps_the_page_mapped_with_its_client() {
    model(|| {
        let page = Arc::new(SourcePage::new(PageImage::abandoned_mapped(SMALL_BLOCK_SIZE, 16, 3)));
        let producer = spawn_remote_free(&page, 0);
        page.remote_free(1);
        producer.join().expect("remote free completes");
        page.assert_quiescent(&[0, 1], 1);
    });
}

/// Every role on one page: the owner exits and maps the page while both final
/// clients are freed remotely and an arena reader searches the bitmap. The
/// reader may lose to an owner bit and restore the bit, or reclaim the page
/// and free it as its new live owner; either way the page is released once.
#[test]
fn loom_owner_exit_remote_frees_and_arena_reader_compose_to_one_release() {
    model(|| {
        let page = Arc::new(SourcePage::new(PageImage::live(REGULAR_BLOCK_SIZE, 4, 2)));
        let producers = [spawn_remote_free(&page, 0), spawn_remote_free(&page, 1)];
        let reader_page = Arc::clone(&page);
        let reader = thread::spawn(move || {
            if reader_page.arena_try_find_and_claim() {
                reader_page.arena_reclaim(READER_THREAD_ID);
                reader_page.owner_collect_until_all_free_then_free();
            }
        });
        page.owner_exit();
        for producer in producers {
            producer.join().expect("remote free completes");
        }
        reader.join().expect("arena reader completes");
        page.assert_quiescent(&[0, 1], 0);
    });
}
