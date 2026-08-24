// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/threadlocal.c:18-315` and
// `include/mimalloc/prim-tls.h:41-50,193-229`. This slice preserves the
// AArch64 key encoding, caller-owned slot semantics, and the global
// free-index claim/release protocol. The source's allocator-backed metadata
// growth is represented by a caller-owned fixed sequence of exact 1024-bit
// growth blocks. Compiler TLS access, process initialization, backing-slot
// allocation, and thread teardown remain separate lifecycle work.

//! Dynamic versioned-thread-local slot and global-key substrate.

use core::cell::UnsafeCell;

use crabc_core::Result as CoreResult;

use crate::lock::PrivateLock;

/// The low key-field width used by pinned mimalloc on 64-bit targets.
///
/// The sole production target is AArch64, so a key is one 64-bit word with a
/// 16-bit index and a 48-bit version. This is an encoding fact, not a chosen
/// limit for a future registry's metadata allocation strategy.
const TLS_INDEX_BITS: u32 = 16;
const TLS_VERSION_BITS: u32 = 64 - TLS_INDEX_BITS;
const TLS_INDEX_MASK: u64 = (1_u64 << TLS_INDEX_BITS) - 1;
const TLS_VERSION_MAX: u64 = (1_u64 << TLS_VERSION_BITS) - 1;

const _: [(); 64] = [(); usize::BITS as usize];

/// A slot index that can be represented in a pinned AArch64 TLS key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadLocalSlotIndex(u16);

impl ThreadLocalSlotIndex {
    /// Validates an index before it is packed into the low 16 key bits.
    #[inline]
    pub(crate) const fn new(index: usize) -> Option<Self> {
        if index <= TLS_INDEX_MASK as usize {
            Some(Self(index as u16))
        } else {
            None
        }
    }

    /// Returns the index used to address caller-owned slot storage.
    #[inline]
    pub(crate) const fn get(self) -> usize {
        self.0 as usize
    }
}

/// A dynamic TLS key with one index field and one reuse-generation field.
///
/// Key value zero is impossible: version zero is reserved to make an empty
/// caller-owned [`ThreadLocalSlot`] reject every valid key. The source key
/// constructor accepts the complete nonzero 48-bit range; only a registry
/// claim advances versions according to the source's wrap rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadLocalKey(u64);

impl ThreadLocalKey {
    /// Forms one key from a representable slot index and a nonzero version.
    #[inline]
    pub(crate) const fn from_parts(index: ThreadLocalSlotIndex, version: u64) -> Option<Self> {
        if version == 0 || version > TLS_VERSION_MAX {
            return None;
        }

        Some(Self((version << TLS_INDEX_BITS) | index.get() as u64))
    }

    /// Returns the source-compatible packed 64-bit representation.
    #[inline]
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the low 16-bit caller-owned slot index.
    #[inline]
    pub(crate) const fn index(self) -> ThreadLocalSlotIndex {
        ThreadLocalSlotIndex((self.0 & TLS_INDEX_MASK) as u16)
    }

    /// Returns the high 48-bit reuse generation.
    #[inline]
    pub(crate) const fn version(self) -> u64 {
        self.0 >> TLS_INDEX_BITS
    }
}

/// Source-compatible generation state owned by the global key registry.
///
/// The registry holds its private lock while it advances this state. Keeping
/// the transition separate makes the source's process-global generation rule
/// auditable independently of the caller-owned bitmap storage.
struct ThreadLocalKeyVersions {
    last_claimed: u64,
}

impl ThreadLocalKeyVersions {
    /// Creates the source's initially zero global version state.
    #[inline]
    const fn new() -> Self {
        Self { last_claimed: 0 }
    }

    /// Issues the next generation for one index selected by the registry.
    ///
    /// This is exactly `src/threadlocal.c:249-256`: increment first, then
    /// replace a value greater than or equal to the 48-bit maximum with one.
    /// Version zero therefore remains reserved. As in the source, the maximum
    /// encodable version can be decoded and constructed but is not issued by
    /// this advancement path.
    #[inline]
    fn claim(&mut self, index: ThreadLocalSlotIndex) -> ThreadLocalKey {
        self.last_claimed += 1;
        if self.last_claimed >= TLS_VERSION_MAX {
            self.last_claimed = 1;
        }

        // `last_claimed` is initialized to zero and the source transition
        // above keeps it in 1..TLS_VERSION_MAX, so this cannot fail.
        match ThreadLocalKey::from_parts(index, self.last_claimed) {
            Some(key) => key,
            None => unreachable!("the source version transition always forms a valid key"),
        }
    }
}

// `mi_thread_local_create_expand` grows the source free-key bitmap by 1024
// bits at a time. The bitmap itself uses 512-bit cache-aligned chunks, so one
// expansion has sixteen 64-bit fields and spans two source bitmap chunks.
const TLS_REGISTRY_EXPANSION_BITS: usize = 1024;
const TLS_REGISTRY_WORD_BITS: usize = usize::BITS as usize;
const TLS_REGISTRY_WORDS_PER_BLOCK: usize =
    TLS_REGISTRY_EXPANSION_BITS / TLS_REGISTRY_WORD_BITS;
// The source rejects a 64th expansion because 64 * 1024 is greater than the
// 16-bit `MI_TLS_IDX_MAX` (65,535). Its largest reachable bitmap is 64,512.
const TLS_REGISTRY_MAX_BLOCKS: usize = TLS_INDEX_MASK as usize / TLS_REGISTRY_EXPANSION_BITS;

const _: [(); 64] = [(); TLS_REGISTRY_WORD_BITS];
const _: [(); 16] = [(); TLS_REGISTRY_WORDS_PER_BLOCK];
const _: [(); 63] = [(); TLS_REGISTRY_MAX_BLOCKS];

/// One caller-owned source-sized free-index bitmap growth block.
///
/// A block represents exactly the 1024 slots appended by one successful
/// `mi_thread_local_create_expand` call. `EMPTY` deliberately contains no
/// free bits: [`ThreadLocalKeyRegistry::claim`] alone publishes a block's
/// all-free image when it reaches that source growth edge.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub(crate) struct ThreadLocalKeyRegistryBlock {
    free: [usize; TLS_REGISTRY_WORDS_PER_BLOCK],
}

impl ThreadLocalKeyRegistryBlock {
    /// Caller-owned storage before registry initialization.
    pub(crate) const EMPTY: Self = Self {
        free: [0; TLS_REGISTRY_WORDS_PER_BLOCK],
    };

    #[inline]
    const fn all_free() -> Self {
        Self {
            free: [usize::MAX; TLS_REGISTRY_WORDS_PER_BLOCK],
        }
    }
}

/// The mutable global state protected by [`ThreadLocalKeyRegistry::lock`].
///
/// The caller transfers exclusive access to `blocks` into the registry at
/// construction. Each later mutation is serialized by the private lock, so
/// the non-atomic bit fields retain the source's locked-bitmap representation
/// without creating a public pthread dependency or pretending they are an
/// independently lock-free allocator structure.
struct ThreadLocalKeyRegistryState<'storage> {
    blocks: &'storage mut [ThreadLocalKeyRegistryBlock],
    active_block_count: usize,
    versions: ThreadLocalKeyVersions,
}

impl ThreadLocalKeyRegistryState<'_> {
    #[inline]
    fn claim(&mut self) -> Option<ThreadLocalKey> {
        if let Some(index) = self.claim_available_index() {
            return Some(self.versions.claim(index));
        }

        if !self.expand() {
            return None;
        }

        // Expansion initializes exactly one all-free 1024-bit block, so its
        // lowest bit must be immediately claimable. Retain an explicit branch
        // rather than manufacturing a key if a future representation change
        // breaks that source invariant.
        self.claim_available_index()
            .map(|index| self.versions.claim(index))
    }

    #[inline]
    fn release(&mut self, key: ThreadLocalKey) {
        let index = key.index().get();
        let active_slots = self.active_block_count * TLS_REGISTRY_EXPANSION_BITS;
        if index >= active_slots {
            // `_mi_thread_local_free` ignores a nonzero key whose index is not
            // in the current free bitmap. A safe lease normally makes this
            // unreachable, but retaining the source edge avoids inventing a
            // second global-key state machine here.
            return;
        }

        let block_index = index / TLS_REGISTRY_EXPANSION_BITS;
        let index_in_block = index % TLS_REGISTRY_EXPANSION_BITS;
        let word_index = index_in_block / TLS_REGISTRY_WORD_BITS;
        let bit_index = index_in_block % TLS_REGISTRY_WORD_BITS;
        self.blocks[block_index].free[word_index] |= 1usize << bit_index;
    }

    #[inline]
    fn claim_available_index(&mut self) -> Option<ThreadLocalSlotIndex> {
        for (block_index, block) in self.blocks[..self.active_block_count]
            .iter_mut()
            .enumerate()
        {
            for (word_index, free) in block.free.iter_mut().enumerate() {
                if *free == 0 {
                    continue;
                }

                let bit_index = free.trailing_zeros() as usize;
                *free &= !(1usize << bit_index);
                let index = block_index * TLS_REGISTRY_EXPANSION_BITS
                    + word_index * TLS_REGISTRY_WORD_BITS
                    + bit_index;
                // Each active source block is below the 65,535-index ceiling
                // proved by construction and `TLS_REGISTRY_MAX_BLOCKS`.
                return ThreadLocalSlotIndex::new(index);
            }
        }
        None
    }

    #[inline]
    fn expand(&mut self) -> bool {
        if self.active_block_count == self.blocks.len()
            || self.active_block_count == TLS_REGISTRY_MAX_BLOCKS
        {
            return false;
        }

        self.blocks[self.active_block_count] = ThreadLocalKeyRegistryBlock::all_free();
        self.active_block_count += 1;
        true
    }
}

/// Fixed-storage owner of mimalloc's global dynamic TLS-key registry.
///
/// Constructing this object transfers exclusive access to `blocks` for its
/// entire lifetime. Its private lock serializes the exact source operations:
/// find and clear the lowest free bit, advance one global generation, and set
/// an explicitly released index. This is global key bookkeeping only; it does
/// not install compiler TLS, allocate per-thread slots, initialize a process,
/// or tear a thread down.
pub(crate) struct ThreadLocalKeyRegistry<'storage> {
    lock: PrivateLock,
    state: UnsafeCell<ThreadLocalKeyRegistryState<'storage>>,
}

// SAFETY: `new` captures caller-owned blocks exclusively, and every later
// access to the non-atomic state occurs while `lock` is held. The returned
// key leases retain a shared reference to the registry, so the registry and
// its metadata cannot be dropped while a live lease could release an index.
unsafe impl Send for ThreadLocalKeyRegistry<'_> {}
unsafe impl Sync for ThreadLocalKeyRegistry<'_> {}

impl<'storage> ThreadLocalKeyRegistry<'storage> {
    /// Initializes one bounded global registry over caller-owned metadata.
    ///
    /// The source grows by complete 1024-bit units and never reaches a 64th
    /// unit: that would exceed the 16-bit maximum key index. Consequently a
    /// larger fixed backing is rejected instead of silently truncating its
    /// ownership. An empty slice is valid and represents a registry whose
    /// source metadata allocation cannot grow.
    pub(crate) fn new(blocks: &'storage mut [ThreadLocalKeyRegistryBlock]) -> Option<Self> {
        if blocks.len() > TLS_REGISTRY_MAX_BLOCKS {
            return None;
        }

        // `mi_thread_local_create_expand` receives zeroed metadata from the
        // source meta allocator. Clear all caller-owned blocks now so reuse of
        // previously owned storage cannot publish stale free bits later.
        for block in blocks.iter_mut() {
            *block = ThreadLocalKeyRegistryBlock::EMPTY;
        }

        Some(Self {
            lock: PrivateLock::new(),
            state: UnsafeCell::new(ThreadLocalKeyRegistryState {
                blocks,
                active_block_count: 0,
                versions: ThreadLocalKeyVersions::new(),
            }),
        })
    }

    /// Claims one global key, expanding by exactly one source-sized block
    /// only after every active bit is in use.
    ///
    /// This may return `Ok(None)` when caller-owned metadata has no remaining
    /// source-sized block. A private-lock acquisition error happens before
    /// metadata mutation and is returned unchanged. Once the source bitmap or
    /// generation changes, the guard's Drop path performs the corresponding
    /// Release unlock so this API never reports a half-completed claim.
    pub(crate) fn claim(&self) -> CoreResult<Option<ThreadLocalKeyLease<'_, 'storage>>> {
        let guard = self.lock.lock()?;
        // SAFETY: the guard gives this operation the sole mutable access to
        // `state`; `state` and its caller-owned blocks remain live for the
        // registry lifetime.
        let key = unsafe { (&mut *self.state.get()).claim() };
        // Keep the source operation atomic from the caller's perspective:
        // `PrivateLockGuard::drop` always performs its Release transition,
        // while its impossible post-transition wake error has no recoverable
        // source analogue and cannot invalidate the claimed key.
        drop(guard);
        Ok(key.map(|key| ThreadLocalKeyLease {
            registry: self,
            key,
        }))
    }

    #[inline]
    fn release_claimed(&self, key: ThreadLocalKey) -> CoreResult<()> {
        let guard = self.lock.lock()?;
        // SAFETY: as in `claim`, the held private lock gives this operation
        // exclusive mutable access to every non-atomic registry field.
        unsafe { (&mut *self.state.get()).release(key) };
        // As for `claim`, a Drop unlock publishes the complete source
        // transition without returning an impossible post-commit error.
        drop(guard);
        Ok(())
    }
}

/// Linear ownership of one claimed global TLS key.
///
/// The source expects callers to invoke `_mi_thread_local_free` exactly once
/// after every thread has stopped using the key. This Rust token makes that
/// lifecycle explicit: it is neither `Copy` nor `Clone`, and only consuming
/// [`Self::release`] can return its index to the global bitmap. Dropping it
/// intentionally leaves the index claimed, matching a missed source free;
/// callers must not rely on drop for process or thread teardown.
#[must_use = "a claimed TLS key must be explicitly released or remains globally claimed"]
pub(crate) struct ThreadLocalKeyLease<'registry, 'storage> {
    registry: &'registry ThreadLocalKeyRegistry<'storage>,
    key: ThreadLocalKey,
}

impl ThreadLocalKeyLease<'_, '_> {
    /// Returns the packed key for regular caller-owned per-thread slots.
    #[inline]
    pub(crate) const fn key(&self) -> ThreadLocalKey {
        self.key
    }

    /// Returns this key's index to the global locked bitmap.
    ///
    /// The caller must first ensure that no per-thread slot still contains or
    /// will access this key. A private-lock acquisition error is returned
    /// before the bitmap changes; after that transition commits this method
    /// succeeds rather than exposing a spurious post-commit wake error.
    #[inline]
    pub(crate) fn release(self) -> CoreResult<()> {
        self.registry.release_claimed(self.key)
    }
}

/// One caller-owned per-thread dynamic-TLS slot.
///
/// This mirrors the source's `(version, value)` pair. It is not compiler TLS:
/// the integrating thread/runtime retains its backing storage, presents it to
/// [`ThreadLocalSlots`], and owns its allocation and teardown.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ThreadLocalSlot {
    version: u64,
    value: *mut (),
}

impl ThreadLocalSlot {
    /// The source's all-zero initial slot image.
    pub(crate) const EMPTY: Self = Self {
        version: 0,
        value: core::ptr::null_mut(),
    };
}

/// A caller-owned per-thread view of dynamic TLS slot storage.
///
/// The caller must retain exclusive mutable access while using this view.
/// Cross-thread synchronization, compiler TLS access, storage allocation, and
/// thread teardown remain outside this type. A failed non-null set names the
/// exact index whose backing storage must be provided before retrying.
pub(crate) struct ThreadLocalSlots<'slots> {
    slots: &'slots mut [ThreadLocalSlot],
}

/// The caller must grow its per-thread backing storage before retrying a set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadLocalSlotExpansion {
    least_index: ThreadLocalSlotIndex,
}

impl ThreadLocalSlotExpansion {
    /// The least caller-owned slot count needed to address the pending key.
    #[inline]
    pub(crate) const fn required_slot_count(self) -> usize {
        self.least_index.get() + 1
    }

    /// The key index that triggered the storage-growth request.
    #[inline]
    pub(crate) const fn least_index(self) -> ThreadLocalSlotIndex {
        self.least_index
    }
}

impl ThreadLocalSlots<'_> {
    /// Binds an existing per-thread slot slice without allocating or
    /// installing compiler TLS state.
    #[inline]
    pub(crate) fn new(slots: &mut [ThreadLocalSlot]) -> ThreadLocalSlots<'_> {
        ThreadLocalSlots { slots }
    }

    /// Looks up one value only when its slot contains the key's generation.
    ///
    /// A missing slot, an uninitialized slot, and a stale generation all
    /// return null, exactly matching `_mi_thread_local_get`'s regular path.
    #[inline]
    pub(crate) fn get(&self, key: ThreadLocalKey) -> *mut () {
        match self.slots.get(key.index().get()) {
            Some(slot) if slot.version == key.version() => slot.value,
            Some(_) | None => core::ptr::null_mut(),
        }
    }

    /// Writes a value and generation into caller-owned storage.
    ///
    /// An out-of-range null write succeeds without growing storage, matching
    /// `mi_thread_local_set_expand`'s early null return. A non-null write
    /// reports the exact missing capacity instead of allocating: later
    /// allocator-metadata-backed per-thread growth owns the source's
    /// reallocation policy and may retry this operation after replacing its
    /// caller-owned backing storage.
    #[inline]
    pub(crate) fn set(
        &mut self,
        key: ThreadLocalKey,
        value: *mut (),
    ) -> Result<(), ThreadLocalSlotExpansion> {
        match self.slots.get_mut(key.index().get()) {
            Some(slot) => {
                slot.value = value;
                slot.version = key.version();
                Ok(())
            }
            None if value.is_null() => Ok(()),
            None => Err(ThreadLocalSlotExpansion {
                least_index: key.index(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{mpsc, Barrier};
    use std::thread;

    #[test]
    fn reused_index_rejects_the_previous_generation_until_rewritten() {
        let mut registry_metadata = [ThreadLocalKeyRegistryBlock::EMPTY; 1];
        let registry = ThreadLocalKeyRegistry::new(&mut registry_metadata)
            .expect("one source-sized growth block is representable");
        let old_lease = registry
            .claim()
            .expect("the private registry lock acquires")
            .expect("the first index is initially free");
        let old_key = old_lease.key();
        old_lease
            .release()
            .expect("the original key explicitly returns its index");
        let replacement_lease = registry
            .claim()
            .expect("the private registry lock acquires")
            .expect("the released index is available again");
        let replacement_key = replacement_lease.key();
        assert_eq!(old_key.index(), replacement_key.index());
        assert_ne!(old_key.version(), replacement_key.version());
        let mut backing = [ThreadLocalSlot::EMPTY; 4];
        let mut slots = ThreadLocalSlots::new(&mut backing);
        let mut old_payload = 0x1111usize;
        let mut replacement_payload = 0x2222usize;
        let old_value = (&mut old_payload as *mut usize).cast();
        let replacement_value = (&mut replacement_payload as *mut usize).cast();

        slots
            .set(old_key, old_value)
            .expect("the supplied caller storage covers the key");
        assert_eq!(slots.get(old_key), old_value);

        assert_eq!(
            slots.get(replacement_key),
            core::ptr::null_mut(),
            "a reused index must not expose the previous key generation's value"
        );
        slots
            .set(replacement_key, replacement_value)
            .expect("the replacement generation uses the same caller slot");
        assert_eq!(slots.get(old_key), core::ptr::null_mut());
        assert_eq!(slots.get(replacement_key), replacement_value);
    }

    #[test]
    fn packed_key_uses_the_complete_aarch64_16_bit_index_and_48_bit_version_fields() {
        let first_index = ThreadLocalSlotIndex::new(0).expect("zero is a valid index");
        let first = ThreadLocalKey::from_parts(first_index, 1).expect("one is the first valid version");
        assert_eq!(first.raw(), 1_u64 << TLS_INDEX_BITS);
        assert_eq!(first.index(), first_index);
        assert_eq!(first.version(), 1);

        let final_index = ThreadLocalSlotIndex::new(TLS_INDEX_MASK as usize)
            .expect("the complete 16-bit index field is valid");
        let final_key = ThreadLocalKey::from_parts(final_index, TLS_VERSION_MAX)
            .expect("the complete nonzero 48-bit version field decodes");
        assert_eq!(final_key.raw(), u64::MAX);
        assert_eq!(final_key.index(), final_index);
        assert_eq!(final_key.version(), TLS_VERSION_MAX);

        assert!(ThreadLocalKey::from_parts(first_index, 0).is_none());
        assert!(ThreadLocalSlotIndex::new(TLS_INDEX_MASK as usize + 1).is_none());
    }

    #[test]
    fn source_version_wrap_reserves_zero_and_restarts_at_one() {
        let index = ThreadLocalSlotIndex::new(7).expect("the index is representable");
        let mut versions = ThreadLocalKeyVersions {
            last_claimed: TLS_VERSION_MAX - 1,
        };

        let wrapped = versions.claim(index);
        assert_eq!(wrapped.version(), 1);
        assert_eq!(wrapped.raw(), (1_u64 << TLS_INDEX_BITS) | index.get() as u64);

        let following = versions.claim(index);
        assert_eq!(following.version(), 2);
        assert_ne!(following, wrapped);
    }

    #[test]
    fn out_of_range_null_set_needs_no_storage_but_nonnull_set_reports_the_exact_retry_capacity() {
        let index = ThreadLocalSlotIndex::new(6).expect("the index is representable");
        let key = ThreadLocalKey::from_parts(index, 1).expect("the key is valid");
        let mut backing = [ThreadLocalSlot::EMPTY; 2];
        let mut slots = ThreadLocalSlots::new(&mut backing);
        let mut payload = 0xfeed_faceusize;
        let value = (&mut payload as *mut usize).cast();

        assert_eq!(slots.set(key, core::ptr::null_mut()), Ok(()));
        assert_eq!(slots.get(key), core::ptr::null_mut());

        let expansion = slots
            .set(key, value)
            .expect_err("the caller must provide backing storage for a non-null value");
        assert_eq!(expansion.least_index(), index);
        assert_eq!(expansion.required_slot_count(), 7);
        assert_eq!(slots.get(key), core::ptr::null_mut());
    }

    #[test]
    fn registry_claims_every_slot_in_one_source_growth_before_expanding() {
        let mut metadata = [ThreadLocalKeyRegistryBlock::EMPTY; 2];
        let registry = ThreadLocalKeyRegistry::new(&mut metadata)
            .expect("two source-sized growth blocks are representable");
        let mut claims = std::vec::Vec::new();

        for expected_index in 0..TLS_REGISTRY_EXPANSION_BITS {
            let claim = registry
                .claim()
                .expect("the private registry lock acquires")
                .expect("the first source growth block has a free slot");
            assert_eq!(claim.key().index().get(), expected_index);
            claims.push(claim);
        }

        let first_expanded = registry
            .claim()
            .expect("the private registry lock acquires")
            .expect("a second caller-owned growth block permits expansion");
        assert_eq!(first_expanded.key().index().get(), TLS_REGISTRY_EXPANSION_BITS);
        assert_eq!(first_expanded.key().version(), TLS_REGISTRY_EXPANSION_BITS as u64 + 1);
    }

    #[test]
    fn registry_exhaustion_then_explicit_release_reuses_an_index_with_a_new_generation() {
        let mut metadata = [ThreadLocalKeyRegistryBlock::EMPTY; 1];
        let registry = ThreadLocalKeyRegistry::new(&mut metadata)
            .expect("one source-sized growth block is representable");
        let mut claims = std::vec::Vec::new();

        for _ in 0..TLS_REGISTRY_EXPANSION_BITS {
            claims.push(
                registry
                    .claim()
                    .expect("the private registry lock acquires")
                    .expect("each source-growth slot is initially free"),
            );
        }
        assert!(
            registry
                .claim()
                .expect("the private registry lock acquires")
                .is_none(),
            "fixed caller metadata makes source expansion exhaustion explicit"
        );

        for claim in claims {
            claim
                .release()
                .expect("an explicit release returns the index to the locked bitmap");
        }
        let reused = registry
            .claim()
            .expect("the private registry lock acquires")
            .expect("the released lowest index is available again");
        assert_eq!(reused.key().index().get(), 0);
        assert_eq!(
            reused.key().version(),
            TLS_REGISTRY_EXPANSION_BITS as u64 + 1,
            "a reused index receives the next process-global source generation"
        );
    }

    #[test]
    fn registry_rejects_metadata_that_cannot_follow_the_source_expansion_ceiling() {
        let mut metadata = [ThreadLocalKeyRegistryBlock::EMPTY; TLS_REGISTRY_MAX_BLOCKS + 1];
        assert!(
            ThreadLocalKeyRegistry::new(&mut metadata).is_none(),
            "the source never grows from 64,512 to 65,536 slots because that exceeds MI_TLS_IDX_MAX"
        );
    }

    #[test]
    fn registry_reaches_the_source_64_512_slot_ceiling_but_never_the_nominal_16_bit_maximum() {
        let mut metadata = [ThreadLocalKeyRegistryBlock::EMPTY; TLS_REGISTRY_MAX_BLOCKS];
        let registry = ThreadLocalKeyRegistry::new(&mut metadata)
            .expect("all 63 source-sized growth blocks are representable");
        let mut final_key = None;

        for _ in 0..TLS_REGISTRY_MAX_BLOCKS * TLS_REGISTRY_EXPANSION_BITS {
            let claim = registry
                .claim()
                .expect("the private registry lock acquires")
                .expect("the source ceiling still has one free index");
            final_key = Some(claim.key());
            // A missing source free leaves a key claimed. Deliberately model
            // that here so the bounded registry reaches its exhaustion edge
            // without allocating a test-only vector of leases.
            drop(claim);
        }

        let final_key = final_key.expect("the source ceiling is nonempty");
        assert_eq!(final_key.index().get(), 64_511);
        assert_eq!(
            final_key.version(),
            64_512,
            "the global generation advances once for every successful claim"
        );
        assert!(
            registry
                .claim()
                .expect("the private registry lock acquires")
                .is_none(),
            "the source cannot grow a 64th 1024-slot block to reach index 65,535"
        );
    }

    #[test]
    fn registry_lock_keeps_parallel_live_claims_unique_then_allows_reuse() {
        const THREADS: usize = 4;
        const CLAIMS_PER_THREAD: usize = 64;

        let mut metadata = [ThreadLocalKeyRegistryBlock::EMPTY; 1];
        let registry = ThreadLocalKeyRegistry::new(&mut metadata)
            .expect("one source-sized growth block is representable");
        let start = Barrier::new(THREADS + 1);
        let claimed = Barrier::new(THREADS + 1);
        let release = Barrier::new(THREADS + 1);
        let (key_sender, key_receiver) = mpsc::channel();

        thread::scope(|scope| {
            for _ in 0..THREADS {
                let worker_sender = key_sender.clone();
                let worker_registry = &registry;
                let worker_start = &start;
                let worker_claimed = &claimed;
                let worker_release = &release;
                scope.spawn(move || {
                    worker_start.wait();
                    let mut leases = std::vec::Vec::new();
                    let mut raw_keys = std::vec::Vec::new();
                    for _ in 0..CLAIMS_PER_THREAD {
                        let lease = worker_registry
                            .claim()
                            .expect("the private registry lock acquires")
                            .expect("the fixed registry has enough simultaneous capacity");
                        raw_keys.push(lease.key().raw());
                        leases.push(lease);
                    }
                    worker_sender
                        .send(raw_keys)
                        .expect("the test collector remains live");
                    worker_claimed.wait();
                    worker_release.wait();
                    for lease in leases {
                        lease
                            .release()
                            .expect("each owner explicitly returns its claimed key");
                    }
                });
            }
            drop(key_sender);

            start.wait();
            let mut raw_keys = std::vec::Vec::new();
            for _ in 0..THREADS {
                raw_keys.extend(
                    key_receiver
                        .recv()
                        .expect("each worker reports its still-live key set"),
                );
            }
            claimed.wait();
            raw_keys.sort_unstable();
            assert_eq!(raw_keys.len(), THREADS * CLAIMS_PER_THREAD);
            assert!(
                raw_keys.windows(2).all(|pair| pair[0] != pair[1]),
                "the private lock cannot issue the same live key to parallel claimers"
            );
            let mut live_indices = raw_keys
                .iter()
                .map(|raw| raw & TLS_INDEX_MASK)
                .collect::<std::vec::Vec<_>>();
            live_indices.sort_unstable();
            assert!(
                live_indices.windows(2).all(|pair| pair[0] != pair[1]),
                "a live source index is unique even before its generation is considered"
            );

            release.wait();
        });

        let reused = registry
            .claim()
            .expect("the private registry lock acquires")
            .expect("all explicit releases restore one available index");
        assert_eq!(reused.key().index().get(), 0);
        assert_eq!(
            reused.key().version(),
            (THREADS * CLAIMS_PER_THREAD + 1) as u64,
            "reuse remains governed by one global source generation stream"
        );
    }

    #[test]
    fn dropping_a_key_lease_does_not_silently_release_a_global_key() {
        let mut metadata = [ThreadLocalKeyRegistryBlock::EMPTY; 1];
        let registry = ThreadLocalKeyRegistry::new(&mut metadata)
            .expect("one source-sized growth block is representable");
        let leaked = registry
            .claim()
            .expect("the private registry lock acquires")
            .expect("the first slot is initially free");
        let first_key = leaked.key();

        drop(leaked);

        let next = registry
            .claim()
            .expect("the private registry lock acquires")
            .expect("the next slot remains available");
        assert_eq!(first_key.index().get(), 0);
        assert_eq!(
            next.key().index().get(),
            1,
            "only the explicit release lifecycle operation may make a key reusable"
        );
    }
}
