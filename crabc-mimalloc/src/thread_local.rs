// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/threadlocal.c:23-315` and
// `include/mimalloc/prim-tls.h:41-50,193-229`. This slice preserves the
// 64-bit Linux key encoding, caller-owned slot semantics, and the global
// free-index claim/release protocol. A current-thread lifecycle owner now
// uses the process-static metadata allocator for the source-shaped regular
// flexible backing, exact expansion, root publication, and bounded regular
// teardown. The registry here remains caller-owned substrate; the distinct
// process-global allocator-owned source bitmap and linear lease live in
// `owned_tls_key_registry`. Process initialization, TLD/theap attachment, and
// actual libc/pthread lifecycle hooks remain separate work.

//! Dynamic versioned-thread-local slot and global-key substrate.

use core::cell::{Cell, UnsafeCell};
use core::marker::{PhantomData, PhantomPinned};
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr::NonNull;

use crabc_core::Result as CoreResult;

use crate::compiler_tls::{
    DynamicThreadLocalBacking, clear_dynamic_backing, current_thread_identity,
    dynamic_backing_peek, install_dynamic_backing, is_empty_dynamic_backing,
    PersistentCompilerTlsOwnerState,
};
use crate::lock::PrivateLock;
use crate::meta::{
    MetaAllocation, MetaAllocator, MetaError, MetaRelease, MetaReleaseFailure,
};
use crate::os::MemoryConfig;
use crate::subproc::MainSubprocess;
use crate::types::LiveThreadId;

/// The low key-field width used by pinned mimalloc on 64-bit targets.
///
/// Both production target profiles use one 64-bit key word with a 16-bit index
/// and a 48-bit version. This is an encoding fact, not a chosen limit for a
/// future registry's metadata allocation strategy.
pub(crate) const TLS_INDEX_BITS: u32 = 16;
const TLS_VERSION_BITS: u32 = 64 - TLS_INDEX_BITS;
pub(crate) const TLS_INDEX_MASK: u64 = (1_u64 << TLS_INDEX_BITS) - 1;
pub(crate) const TLS_VERSION_MAX: u64 = (1_u64 << TLS_VERSION_BITS) - 1;
/// `mi_thread_local_key_fast`: reserved outside the regular key registry.
pub(crate) const TLS_FAST_KEY_RAW: u64 = 1;

const _: [(); 64] = [(); usize::BITS as usize];

/// A slot index that can be represented in a pinned 64-bit Linux TLS key.
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
pub(crate) struct ThreadLocalKeyVersions {
    last_claimed: u64,
}

impl ThreadLocalKeyVersions {
    /// Creates the source's initially zero global version state.
    #[inline]
    pub(crate) const fn new() -> Self {
        Self { last_claimed: 0 }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) const fn last_claimed(&self) -> u64 {
        self.last_claimed
    }

    /// Test-only seam for the source's exact pre-increment wrap boundary.
    #[cfg(test)]
    #[inline]
    pub(crate) fn set_last_claimed_for_test(&mut self, version: u64) {
        debug_assert!(version < TLS_VERSION_MAX);
        self.last_claimed = version;
    }

    /// Issues the next generation for one index selected by the registry.
    ///
    /// This is exactly `src/threadlocal.c:249-256`: increment first, then
    /// replace a value greater than or equal to the 48-bit maximum with one.
    /// Version zero therefore remains reserved. As in the source, the maximum
    /// encodable version can be decoded and constructed but is not issued by
    /// this advancement path.
    #[inline]
    pub(crate) fn claim(&mut self, index: ThreadLocalSlotIndex) -> ThreadLocalKey {
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
pub(crate) const TLS_REGISTRY_EXPANSION_BITS: usize = 1024;
const TLS_REGISTRY_WORD_BITS: usize = usize::BITS as usize;
const TLS_REGISTRY_WORDS_PER_BLOCK: usize =
    TLS_REGISTRY_EXPANSION_BITS / TLS_REGISTRY_WORD_BITS;
// The source rejects a 64th expansion because 64 * 1024 is greater than the
// 16-bit `MI_TLS_IDX_MAX` (65,535). Its largest reachable bitmap is 64,512.
pub(crate) const TLS_REGISTRY_MAX_BLOCKS: usize =
    TLS_INDEX_MASK as usize / TLS_REGISTRY_EXPANSION_BITS;

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

    /// Returns the source `(version, value-is-null)` image only for the
    /// finite M1 compiler-TLS differential. Production callers must use the
    /// typed key lookup rather than inspect a raw slot image.
    #[cfg(test)]
    #[inline]
    pub(crate) const fn m1_compiler_tls_image_fields(&self) -> (usize, bool) {
        (self.version as usize, self.value.is_null())
    }
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

/// A current-thread compiler-TLS owner transition could not preserve the
/// source-shaped persistent allocator lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PersistentCompilerTlsOwnerError {
    /// The direct target TLS register did not encode a live source thread identity.
    InvalidCurrentThread,
    /// This typed owner was used from a different native thread.
    WrongThread,
    /// The compiler-TLS owner cell has no installed owner.
    NotAttached,
    /// The current native thread already published a complete persistent owner.
    AlreadyActive,
    /// The inline payload is pinned but its source initialization is incomplete.
    Initializing,
    /// A local owner borrow is already active on this native thread.
    Reentrant,
    /// Source owner exit owns the only in-place payload projection.
    Exiting,
    /// Failed or unwinding initialization, local work, or exit retained the payload.
    Retained,
    /// The owner completed its one-way compiler-TLS teardown transition.
    TornDown,
}

/// Failure to install and initialize one inline compiler-TLS owner payload.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PersistentCompilerTlsOwnerInitializeError<T, E> {
    /// The cell rejected installation before consuming the offered payload.
    State {
        error: PersistentCompilerTlsOwnerError,
        owner: T,
    },
    /// Initialization failed after the payload became pinned in the cell.
    ///
    /// The cell retains that exact payload and rejects ordinary local work.
    Owner(E),
}

/// Failure of one source-ordered consuming owner teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PersistentCompilerTlsOwnerTeardownError<E> {
    /// The cell could not begin teardown from its current lifecycle state.
    State(PersistentCompilerTlsOwnerError),
    /// The source teardown refused or failed while retaining the exact payload.
    Owner(E),
}

/// Inline pinned storage for one persistent compiler-TLS allocator owner.
///
/// Pinned `_mi_thread_init_with_heap` creates a TLD/Theap once and leaves it
/// installed for arbitrary local operations. This cell gives Rust the same
/// persistent shape without moving the owner out for each operation: the
/// runtime embeds the cell directly in its compiler-TLS record, and
/// [`Self::with_owner`] temporarily projects its one exclusive pinned borrow.
/// A nested projection is rejected before it can create a second `&mut`
/// reference.
///
/// This generic cell is not itself a concrete ELF-TLS owner, scheduler,
/// process registry, page owner, or generic TLS-key mechanism. The integrating
/// runtime must embed it in a concrete compiler-TLS record, initialize the
/// complete co-located attachment and allocator state inside `T`, drive page
/// exit, and supply its consuming source teardown closure. `MaybeUninit`
/// deliberately has no implicit drop path: an active or retained payload must
/// stay mechanically owned by this cell instead of being destroyed at ELF TLS
/// reclamation without source teardown. The runtime must therefore resolve a
/// retained payload through teardown before the native thread returns; this
/// generic cell cannot make thread return safe by itself.
#[must_use = "a persistent compiler-TLS owner cell must complete source teardown or retain its exact payload"]
pub(crate) struct PersistentCompilerTlsOwnerCell<T> {
    state: Cell<PersistentCompilerTlsOwnerState>,
    thread: Cell<Option<LiveThreadId>>,
    owner: UnsafeCell<MaybeUninit<T>>,
    #[cfg(test)]
    completed_operation_count: Cell<usize>,
    _pinned: PhantomPinned,
    _not_send_sync: PhantomData<*mut ()>,
}

/// Publishes the conservative state if a transition closure unwinds.
struct PersistentCompilerTlsOwnerTransition<'cell, T> {
    cell: &'cell PersistentCompilerTlsOwnerCell<T>,
    unwind_state: PersistentCompilerTlsOwnerState,
    armed: bool,
}

impl<T> PersistentCompilerTlsOwnerCell<T> {
    /// Creates one vacant inline owner cell for a runtime compiler-TLS record.
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            state: Cell::new(PersistentCompilerTlsOwnerState::Vacant),
            thread: Cell::new(None),
            owner: UnsafeCell::new(MaybeUninit::uninit()),
            #[cfg(test)]
            completed_operation_count: Cell::new(0),
            _pinned: PhantomPinned,
            _not_send_sync: PhantomData,
        }
    }

    /// Installs and initializes one owner directly in this pinned cell.
    ///
    /// The cell records `Initializing` before invoking `initialize` and
    /// publishes `Active` only after that closure succeeds. A failed or
    /// unwinding initializer retains the exact payload in place; it never
    /// returns a possibly source-mutated owner or resets the cell to vacant.
    ///
    /// The runtime must pin the containing compiler-TLS record before calling
    /// this method and keep it pinned for the native thread's complete
    /// allocator lifetime. The cell is `!Send`, `!Sync`, and `!Unpin`; every
    /// later operation also verifies the captured direct TLS identity.
    pub(crate) fn initialize<E>(
        self: Pin<&Self>,
        owner: T,
        initialize: impl for<'owner> FnOnce(Pin<&'owner mut T>) -> Result<(), E>,
    ) -> Result<(), PersistentCompilerTlsOwnerInitializeError<T, E>> {
        let cell = self.get_ref();
        if cell.state.get() != PersistentCompilerTlsOwnerState::Vacant {
            return Err(PersistentCompilerTlsOwnerInitializeError::State {
                error: cell.state_error_for_initialization(),
                owner,
            });
        }
        let Some(thread) = current_thread_identity() else {
            return Err(PersistentCompilerTlsOwnerInitializeError::State {
                error: PersistentCompilerTlsOwnerError::InvalidCurrentThread,
                owner,
            });
        };

        cell.thread.set(Some(thread));
        // SAFETY: `Vacant` proves no initialized payload exists. `self` is
        // pinned before this write, and the cell never moves or exposes this
        // payload except through the scoped pinned projections below.
        unsafe { (&mut *cell.owner.get()).write(owner) };
        cell.state
            .set(PersistentCompilerTlsOwnerState::Initializing);
        let mut transition = PersistentCompilerTlsOwnerTransition::new(
            cell,
            PersistentCompilerTlsOwnerState::Retained,
        );
        // SAFETY: the just-written payload remains initialized and pinned.
        // `Initializing` rejects every recursive projection before it can
        // dereference this address.
        let result = initialize(unsafe { Pin::new_unchecked(&mut *cell.owner_pointer()) });
        match result {
            Ok(()) => {
                cell.state.set(PersistentCompilerTlsOwnerState::Active);
                transition.disarm();
                Ok(())
            }
            Err(error) => {
                cell.state.set(PersistentCompilerTlsOwnerState::Retained);
                transition.disarm();
                Err(PersistentCompilerTlsOwnerInitializeError::Owner(error))
            }
        }
    }

    /// Runs one direct local operation through the same in-place owner.
    ///
    /// The closure is synchronous. On normal return, the temporary exclusive
    /// borrow ends and the compiler-TLS owner becomes active again, so later
    /// operations observe the same TLD/Theap image and never park, resume, or
    /// move it. If the closure unwinds after a one-way source mutation, the
    /// guard conservatively retains the exact payload and refuses ordinary
    /// reentry; only source teardown may inspect it again.
    pub(crate) fn with_owner<R>(
        self: Pin<&Self>,
        operation: impl for<'owner> FnOnce(Pin<&'owner mut T>) -> R,
    ) -> Result<R, PersistentCompilerTlsOwnerError> {
        let cell = self.get_ref();
        match cell.state.get() {
            PersistentCompilerTlsOwnerState::Active => {}
            state => return Err(Self::access_error_for_state(state)),
        }
        cell.ensure_current_thread()?;
        cell.state.set(PersistentCompilerTlsOwnerState::Borrowed);
        let mut transition = PersistentCompilerTlsOwnerTransition::new(
            cell,
            PersistentCompilerTlsOwnerState::Retained,
        );
        // SAFETY: `Active -> Borrowed` grants this closure the only mutable
        // projection. Recursive access sees `Borrowed` and returns before
        // dereferencing the payload, and the higher-ranked closure result
        // cannot retain the projection lifetime.
        let result = operation(unsafe { Pin::new_unchecked(&mut *cell.owner_pointer()) });
        #[cfg(test)]
        cell.completed_operation_count
            .set(cell.completed_operation_count.get().wrapping_add(1));
        cell.state.set(PersistentCompilerTlsOwnerState::Active);
        transition.disarm();
        Ok(result)
    }

    /// Runs source-ordered consuming teardown and terminalizes the cell.
    ///
    /// `teardown` receives the same pinned payload after every ordinary
    /// operation has ended. It must release or transfer every page authority,
    /// detach the source Theap/TLD in source order, and return success only
    /// when dropping the now-torn-down shell is valid. Success first publishes
    /// `TornDown` and then drops `T` in place. Failure or unwind publishes
    /// `Retained`, keeps the exact payload pinned, and permits only a later
    /// teardown retry—not ordinary allocator work.
    pub(crate) fn teardown<E>(
        self: Pin<&Self>,
        teardown: impl for<'owner> FnOnce(Pin<&'owner mut T>) -> Result<(), E>,
    ) -> Result<(), PersistentCompilerTlsOwnerTeardownError<E>> {
        let cell = self.get_ref();
        match cell.state.get() {
            PersistentCompilerTlsOwnerState::Active
            | PersistentCompilerTlsOwnerState::Retained => {}
            state => {
                return Err(PersistentCompilerTlsOwnerTeardownError::State(
                    Self::access_error_for_state(state),
                ));
            }
        }
        cell.ensure_current_thread()
            .map_err(PersistentCompilerTlsOwnerTeardownError::State)?;
        cell.state.set(PersistentCompilerTlsOwnerState::Exiting);
        let mut transition = PersistentCompilerTlsOwnerTransition::new(
            cell,
            PersistentCompilerTlsOwnerState::Retained,
        );
        // SAFETY: `Exiting` rejects ordinary, initialization, and recursive
        // teardown entry before dereferencing the initialized payload. The
        // closure result cannot retain this projection lifetime.
        match teardown(unsafe { Pin::new_unchecked(&mut *cell.owner_pointer()) }) {
            Ok(()) => {
                // Publish the terminal state before Drop so a destructor that
                // reenters this cell cannot project the payload being dropped.
                cell.state.set(PersistentCompilerTlsOwnerState::TornDown);
                cell.thread.set(None);
                transition.disarm();
                // SAFETY: successful source teardown guarantees the pinned
                // payload may now be destroyed. It is dropped at its stable
                // address exactly once; `TornDown` forbids every later access.
                unsafe { core::ptr::drop_in_place(cell.owner_pointer()) };
                Ok(())
            }
            Err(error) => {
                cell.state.set(PersistentCompilerTlsOwnerState::Retained);
                transition.disarm();
                Err(PersistentCompilerTlsOwnerTeardownError::Owner(error))
            }
        }
    }

    #[inline]
    fn ensure_current_thread(&self) -> Result<(), PersistentCompilerTlsOwnerError> {
        match (self.thread.get(), current_thread_identity()) {
            (Some(expected), Some(thread)) if thread == expected => Ok(()),
            (None, _) => Err(PersistentCompilerTlsOwnerError::NotAttached),
            (Some(_), Some(_)) => Err(PersistentCompilerTlsOwnerError::WrongThread),
            (_, None) => Err(PersistentCompilerTlsOwnerError::InvalidCurrentThread),
        }
    }

    #[inline]
    fn state_error_for_initialization(&self) -> PersistentCompilerTlsOwnerError {
        match self.state.get() {
            PersistentCompilerTlsOwnerState::Vacant => {
                PersistentCompilerTlsOwnerError::NotAttached
            }
            PersistentCompilerTlsOwnerState::Initializing => {
                PersistentCompilerTlsOwnerError::Initializing
            }
            PersistentCompilerTlsOwnerState::Active => {
                PersistentCompilerTlsOwnerError::AlreadyActive
            }
            PersistentCompilerTlsOwnerState::Borrowed => {
                PersistentCompilerTlsOwnerError::Reentrant
            }
            PersistentCompilerTlsOwnerState::Exiting => {
                PersistentCompilerTlsOwnerError::Exiting
            }
            PersistentCompilerTlsOwnerState::Retained => {
                PersistentCompilerTlsOwnerError::Retained
            }
            PersistentCompilerTlsOwnerState::TornDown => {
                PersistentCompilerTlsOwnerError::TornDown
            }
        }
    }

    #[inline]
    fn access_error_for_state(
        state: PersistentCompilerTlsOwnerState,
    ) -> PersistentCompilerTlsOwnerError {
        match state {
            PersistentCompilerTlsOwnerState::Vacant => {
                PersistentCompilerTlsOwnerError::NotAttached
            }
            PersistentCompilerTlsOwnerState::Initializing => {
                PersistentCompilerTlsOwnerError::Initializing
            }
            PersistentCompilerTlsOwnerState::Active => {
                PersistentCompilerTlsOwnerError::AlreadyActive
            }
            PersistentCompilerTlsOwnerState::Borrowed => {
                PersistentCompilerTlsOwnerError::Reentrant
            }
            PersistentCompilerTlsOwnerState::Exiting => {
                PersistentCompilerTlsOwnerError::Exiting
            }
            PersistentCompilerTlsOwnerState::Retained => {
                PersistentCompilerTlsOwnerError::Retained
            }
            PersistentCompilerTlsOwnerState::TornDown => {
                PersistentCompilerTlsOwnerError::TornDown
            }
        }
    }

    /// Returns the initialized payload address after a state transition has
    /// granted one exclusive projection.
    ///
    /// # Safety
    ///
    /// The state must be `Initializing`, `Borrowed`, or `Exiting`, and the
    /// caller must own that transition's unique projection capability.
    #[inline(always)]
    unsafe fn owner_pointer(&self) -> *mut T {
        // SAFETY: the caller's transition proof gives exclusive access to the
        // initialized `MaybeUninit<T>` payload for this synchronous scope.
        unsafe { (&mut *self.owner.get()).as_mut_ptr() }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn completed_operation_count_for_test(&self) -> usize {
        self.completed_operation_count.get()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn state_for_test(&self) -> PersistentCompilerTlsOwnerState {
        self.state.get()
    }
}

impl<'cell, T> PersistentCompilerTlsOwnerTransition<'cell, T> {
    #[inline]
    fn new(
        cell: &'cell PersistentCompilerTlsOwnerCell<T>,
        unwind_state: PersistentCompilerTlsOwnerState,
    ) -> Self {
        Self {
            cell,
            unwind_state,
            armed: true,
        }
    }

    #[inline]
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<T> Drop for PersistentCompilerTlsOwnerTransition<'_, T> {
    fn drop(&mut self) {
        if self.armed {
            self.cell.state.set(self.unwind_state);
        }
    }
}

/// The regular current-thread compiler-TLS backing cannot service this
/// operation without violating its source lifecycle contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadLocalBackingError {
    /// The direct target TLS register did not encode a valid live source thread identity.
    InvalidCurrentThread,
    /// A current-thread owner was used from a different native thread.
    WrongThread,
    /// The current root already names a live dynamically owned image.
    RootAlreadyOwned,
    /// The dynamic root is null after thread teardown.
    RootTornDown,
    /// The root no longer names this owner's exact metadata capability.
    RootChanged,
    /// The owner has completed teardown and cannot be reused.
    TornDown,
    /// An internal metadata-free/replacement failure made this owner terminal.
    Poisoned,
    /// The source growth rule would require more than 65,535 slots.
    SlotCountLimit,
    /// A checked source flexible-allocation size overflowed `usize`.
    AllocationSizeOverflow,
    /// The one allowed typed projection no longer matched its allocation.
    BackingProjection,
    /// The process metadata owner rejected or could not complete the request.
    Metadata(MetaError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadLocalBackingState {
    Active,
    TornDown,
    Poisoned,
}

/// One current-thread owner of mimalloc's regular dynamic TLS image.
///
/// This is the lifecycle-side owner of the raw compiler-TLS pointer in
/// `compiler_tls`; it is intentionally not another TLS root. It retains the
/// exact `MetaAllocation` capability so a growth replacement cannot publish
/// a raw pointer without matching metadata provenance. The private marker
/// makes this type `!Send` and `!Sync`: its every operation validates the
/// captured direct TLS identity, but the type system also prevents a
/// safe move to a second thread.
///
/// The constructor is `unsafe` because the source's initially immutable
/// count-zero root cannot distinguish two idle Rust owners. The integrating
/// TLD/thread lifecycle must provide exclusive ownership of this current
/// thread's regular backing for the entire value lifetime; no other owner may
/// begin, access, reset, or replace this root until this owner tears it down.
/// It must also call [`Self::teardown`] before discarding a live owner.
#[must_use = "a live current-thread TLS backing owner must be torn down explicitly"]
pub(crate) struct ThreadLocalBackingOwner {
    metadata: Pin<&'static MetaAllocator>,
    subprocess: &'static MainSubprocess,
    config: MemoryConfig,
    thread: LiveThreadId,
    allocation: Option<MetaAllocation<'static>>,
    count: usize,
    state: ThreadLocalBackingState,
    _not_send_sync: PhantomData<*mut ()>,
}

impl ThreadLocalBackingOwner {
    /// Begins one source-shaped owner using the process metadata singleton.
    ///
    /// # Safety
    ///
    /// The caller must own the current thread's regular mimalloc TLS lifecycle
    /// exclusively. In particular, no second `ThreadLocalBackingOwner` may
    /// exist for this thread, and no other code may mutate the dynamic root
    /// until this owner tears it down. The caller must eventually call
    /// [`Self::teardown`] while still on this exact direct TLS identity.
    /// Process initialization must already have bound and published the
    /// process metadata image; this entry does not establish that edge.
    pub(crate) unsafe fn begin(config: MemoryConfig) -> Result<Self, ThreadLocalBackingError> {
        // SAFETY: forwarded unchanged to the common constructor; production
        // always binds the committed process-static metadata owner.
        unsafe {
            Self::begin_with_metadata(MetaAllocator::global(), MainSubprocess::global(), config)
        }
    }

    /// Binds the current thread to one already-selected process-lived metadata
    /// owner.
    ///
    /// The private dynamic-Theap attachment uses this to retain one exact
    /// selected owner for its TLD, Theap, and backing capabilities. Production
    /// [`Self::begin`] always uses `MetaAllocator::global`; tests may supply
    /// an isolated process-lifetime fixture.
    ///
    /// # Safety
    ///
    /// Identical to [`Self::begin`], plus `metadata`/`subprocess` must be the
    /// selected process-lived pair that releases every returned allocation.
    /// That pair must already have completed
    /// [`MetaAllocator::prepare_for_main_subprocess`]; this constructor does
    /// not convert a cold backing request into process initialization.
    pub(crate) unsafe fn begin_with_metadata(
        metadata: Pin<&'static MetaAllocator>,
        subprocess: &'static MainSubprocess,
        config: MemoryConfig,
    ) -> Result<Self, ThreadLocalBackingError> {
        let thread = current_thread_identity().ok_or(ThreadLocalBackingError::InvalidCurrentThread)?;
        let root = dynamic_backing_peek().ok_or(ThreadLocalBackingError::RootTornDown)?;
        if !is_empty_dynamic_backing(root) {
            return Err(ThreadLocalBackingError::RootAlreadyOwned);
        }
        Ok(Self {
            metadata,
            subprocess,
            config,
            thread,
            allocation: None,
            count: 0,
            state: ThreadLocalBackingState::Active,
            _not_send_sync: PhantomData,
        })
    }

    /// Gets one regular TLS value only when the backing slot generation
    /// matches `key`. The empty image, a stale generation, and a null value
    /// all produce null, exactly as `_mi_thread_local_get_regular` does.
    pub(crate) fn get(
        &mut self,
        key: ThreadLocalKey,
    ) -> Result<*mut (), ThreadLocalBackingError> {
        let Some(backing) = self.current_backing_mut()? else {
            return Ok(core::ptr::null_mut());
        };
        // SAFETY: `current_backing_mut` proved this owner retains the exact
        // flexible allocation and is the unique current-thread mutator.
        let slots = ThreadLocalSlots::new(unsafe { backing.slots_mut() });
        Ok(slots.get(key))
    }

    /// Sets one regular TLS value, growing the allocator-owned flexible image
    /// by the exact `threadlocal.c` rule when a non-null out-of-range value
    /// needs capacity. A null out-of-range write succeeds without growth.
    pub(crate) fn set(
        &mut self,
        key: ThreadLocalKey,
        value: *mut (),
    ) -> Result<(), ThreadLocalBackingError> {
        let index = key.index().get();
        self.ensure_active_current()?;

        if index >= self.count {
            // `mi_thread_local_set_expand` returns before it looks at or
            // grows the image for this source null edge.
            if value.is_null() {
                self.ensure_current_root()?;
                return Ok(());
            }
            self.expand(index)?;
        }

        let backing = self
            .current_backing_mut()?
            .ok_or(ThreadLocalBackingError::BackingProjection)?;
        // SAFETY: `index < self.count` after `expand`, and the backing was
        // projected from its exact flexible request under this owner.
        let mut slots = ThreadLocalSlots::new(unsafe { backing.slots_mut() });
        match slots.set(key, value) {
            Ok(()) => Ok(()),
            Err(_) => Err(ThreadLocalBackingError::BackingProjection),
        }
    }

    /// Releases a live dynamic backing, then makes only its compiler-TLS root
    /// null. This is the source order in `_mi_thread_locals_thread_done`.
    ///
    /// This direct [`ThreadLocalBackingOwner`] boundary retains its exact
    /// Malloc capability when `MetaRelease` proves the failure occurred before
    /// the metadata entry claimed it. In that one case the root, count, and
    /// active state remain unchanged for a direct caller retry. A terminal
    /// failure remains conservative: the root is cleared and the owner is
    /// poisoned because local release may already have mutated the backing.
    /// This does not make an enclosing attachment lifecycle retryable; that
    /// owner has its own state transition before it calls this method.
    pub(crate) fn teardown(&mut self) -> Result<(), ThreadLocalBackingError> {
        self.ensure_active_current()?;
        if self.count == 0 {
            // The source keeps the shared empty image installed because it
            // owns no allocation to release. Still verify no foreign root was
            // installed through an unsafe lifecycle violation.
            self.ensure_current_root()?;
            self.state = ThreadLocalBackingState::TornDown;
            return Ok(());
        }

        // Check identity before taking the capability. A foreign root must
        // not be cleared or freed through this owner.
        let _ = self
            .current_backing_mut()?
            .ok_or(ThreadLocalBackingError::BackingProjection)?;
        let allocation = self
            .allocation
            .take()
            .ok_or(ThreadLocalBackingError::BackingProjection)?;

        match MetaRelease::Malloc(allocation).release() {
            Ok(()) => {
                clear_dynamic_backing();
                self.count = 0;
                self.state = ThreadLocalBackingState::TornDown;
                Ok(())
            }
            Err(MetaReleaseFailure::MallocRetryable { error, allocation }) => {
                // This error occurred before `release_selected_malloc` claimed
                // the exact Malloc capability. Preserve the source root and
                // flexible-image count alongside that live value so this
                // direct owner can retry the same release later.
                self.allocation = Some(allocation);
                Err(ThreadLocalBackingError::Metadata(error))
            }
            Err(MetaReleaseFailure::MallocTerminal {
                error,
                allocation: _,
            }) => {
                // Once the exact Malloc capability has been claimed, local
                // free may already have changed its queues or page state.
                // Keep the old conservative terminal transition rather than
                // exposing a false retry path.
                clear_dynamic_backing();
                self.count = 0;
                self.state = ThreadLocalBackingState::Poisoned;
                Err(ThreadLocalBackingError::Metadata(error))
            }
            Err(MetaReleaseFailure::RegularOs { .. }) => unreachable!(
                "a selected Malloc release cannot report a regular-OS failure"
            ),
        }
    }

    #[inline]
    fn ensure_active_current(&self) -> Result<(), ThreadLocalBackingError> {
        match self.state {
            ThreadLocalBackingState::Active => self.ensure_current_thread(),
            ThreadLocalBackingState::TornDown => Err(ThreadLocalBackingError::TornDown),
            ThreadLocalBackingState::Poisoned => Err(ThreadLocalBackingError::Poisoned),
        }
    }

    #[inline]
    fn ensure_current_thread(&self) -> Result<(), ThreadLocalBackingError> {
        match current_thread_identity() {
            Some(thread) if thread == self.thread => Ok(()),
            Some(_) => Err(ThreadLocalBackingError::WrongThread),
            None => Err(ThreadLocalBackingError::InvalidCurrentThread),
        }
    }

    fn ensure_current_root(&self) -> Result<(), ThreadLocalBackingError> {
        self.ensure_active_current()?;
        let root = dynamic_backing_peek().ok_or(ThreadLocalBackingError::RootTornDown)?;
        if self.count == 0 {
            return if self.allocation.is_none() && is_empty_dynamic_backing(root) {
                Ok(())
            } else {
                Err(ThreadLocalBackingError::RootChanged)
            };
        }

        let allocation = self
            .allocation
            .as_ref()
            .ok_or(ThreadLocalBackingError::BackingProjection)?;
        // A shared exact-size proof is enough for the pointer comparison; the
        // mutable projection remains private to the current-thread owner.
        let expected = allocation.pointer();
        if root.as_ptr().cast::<u8>() != expected.as_ptr() {
            return Err(ThreadLocalBackingError::RootChanged);
        }
        Ok(())
    }

    fn current_backing_mut(
        &mut self,
    ) -> Result<Option<&mut DynamicThreadLocalBacking>, ThreadLocalBackingError> {
        self.ensure_current_root()?;
        if self.count == 0 {
            return Ok(None);
        }
        let allocation = self
            .allocation
            .as_mut()
            .ok_or(ThreadLocalBackingError::BackingProjection)?;
        let (header_count, header_memory) = {
            let backing = allocation
                .dynamic_thread_local_backing_mut(self.count)
                .ok_or(ThreadLocalBackingError::BackingProjection)?;
            (backing.count(), backing.memory_id())
        };
        if header_count != self.count || !allocation.matches_memory_id(header_memory) {
            return Err(ThreadLocalBackingError::BackingProjection);
        }
        let backing = allocation
            .dynamic_thread_local_backing_mut(self.count)
            .ok_or(ThreadLocalBackingError::BackingProjection)?;
        Ok(Some(backing))
    }

    fn expand(&mut self, least_index: usize) -> Result<(), ThreadLocalBackingError> {
        self.ensure_current_root()?;
        let old_count = self.count;
        let count = expanded_slot_count(old_count, least_index)?;
        let size = DynamicThreadLocalBacking::allocation_size(count)
            .ok_or(ThreadLocalBackingError::AllocationSizeOverflow)?;

        let replacement = if old_count == 0 {
            self.metadata
                .zalloc_for_main_subprocess(self.config, self.subprocess, size)
        } else {
            let old = self
                .allocation
                .as_mut()
                .ok_or(ThreadLocalBackingError::BackingProjection)?;
            self.metadata.rezalloc_for_main_subprocess(
                self.config,
                self.subprocess,
                Some(old),
                size,
            )
        };
        let replacement = match replacement {
            Ok(replacement) => replacement,
            Err(error @ MetaError::Free(_) | error @ MetaError::ReleasedOrStale) => {
                // A successful replacement may already have consumed the old
                // backing before reporting this internal lifecycle failure.
                // Do not leave its old root live or offer a false retry.
                self.poison_root();
                return Err(ThreadLocalBackingError::Metadata(error));
            }
            Err(error) => return Err(ThreadLocalBackingError::Metadata(error)),
        };

        // Keep the new provenance capability in this owner before its raw
        // address becomes reachable through compiler TLS. Replacing the old
        // capability after successful rezalloc drops only its explicitly
        // rejected/released Rust token; the source free already ran.
        self.allocation = Some(replacement);
        self.count = count;
        let allocation = self
            .allocation
            .as_mut()
            .ok_or(ThreadLocalBackingError::BackingProjection)?;
        let memid = allocation.memory_id();
        let backing = match allocation.dynamic_thread_local_backing_mut(count) {
            Some(backing) => backing,
            None => {
                self.poison_root();
                return Err(ThreadLocalBackingError::BackingProjection);
            }
        };
        // SAFETY: this is the exact flexible metadata allocation for `count`.
        // It is either fresh zeroed storage or the source-order copied old
        // image. The fixed header is initialized before root publication.
        unsafe { backing.initialize_owned_header(memid, count) };
        let backing = NonNull::from(backing);
        install_dynamic_backing(backing);
        Ok(())
    }

    fn poison_root(&mut self) {
        clear_dynamic_backing();
        self.allocation = None;
        self.count = 0;
        self.state = ThreadLocalBackingState::Poisoned;
    }
}

/// Implements `mi_thread_locals_expand`'s count transition before metadata
/// allocation. `least_index` is an index, not a requested count.
#[inline]
fn expanded_slot_count(
    old_count: usize,
    least_index: usize,
) -> Result<usize, ThreadLocalBackingError> {
    let mut count = if old_count == 0 {
        16
    } else if old_count >= 1024 {
        old_count
            .checked_add(1024)
            .ok_or(ThreadLocalBackingError::AllocationSizeOverflow)?
    } else {
        old_count
            .checked_mul(2)
            .ok_or(ThreadLocalBackingError::AllocationSizeOverflow)?
    };
    if count <= least_index {
        count = least_index
            .checked_add(1)
            .ok_or(ThreadLocalBackingError::SlotCountLimit)?;
    }
    if count > u16::MAX as usize {
        return Err(ThreadLocalBackingError::SlotCountLimit);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::os::{PageSize, fault};
    use crate::types::MemoryKind;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the pinned native test page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn key(index: usize, version: u64) -> ThreadLocalKey {
        ThreadLocalKey::from_parts(
            ThreadLocalSlotIndex::new(index).expect("the test index fits the source key"),
            version,
        )
        .expect("the test version is source-valid")
    }

    /// Builds a test-only current-thread backing owner after the exact
    /// isolated process pair has completed the identity-only metadata
    /// preparation edge. Production must prepare its global pair during
    /// process startup before it uses [`ThreadLocalBackingOwner::begin`].
    unsafe fn begin_with_prepared_test_metadata(
    ) -> Result<ThreadLocalBackingOwner, ThreadLocalBackingError> {
        let metadata = MetaAllocator::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        metadata
            .prepare_for_main_subprocess(memory_config(), subprocess)
            .map_err(ThreadLocalBackingError::Metadata)?;
        // SAFETY: the test caller owns this current thread's isolated backing
        // lifecycle and tears it down before the thread exits.
        unsafe {
            ThreadLocalBackingOwner::begin_with_metadata(metadata, subprocess, memory_config())
        }
    }

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
    fn packed_key_uses_the_complete_linux_64_16_bit_index_and_48_bit_version_fields() {
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

    #[test]
    fn current_thread_backing_first_allocates_the_exact_flexible_image_and_leaves_other_roots_alone() {
        thread::spawn(|| {
            let identity = current_thread_identity().expect("the native TLS identity is live");
            let fast_before = crate::compiler_tls::fast_slot_peek();
            let default_before = crate::compiler_tls::default_theap();
            let cached_before = crate::compiler_tls::cached_theap();
            let mut owner = unsafe { begin_with_prepared_test_metadata() }
                .expect("the fresh child root is the immutable empty image");
            let mut payload = 0x41usize;
            let value = (&mut payload as *mut usize).cast();

            owner.set(key(15, 1), value).unwrap();
            assert_eq!(owner.count, 16, "the source starts at sixteen slots");
            let root = dynamic_backing_peek().expect("the initialized image is published");
            assert!(!is_empty_dynamic_backing(root));
            // SAFETY: `owner` retains the exact metadata capability until its
            // teardown below, and the compiler root is checked against it.
            let backing = unsafe { root.as_ref() };
            assert_eq!(backing.count(), 16);
            assert_eq!(backing.memory_id().kind(), MemoryKind::Malloc);
            assert!(backing.memory_id().is_pinned());
            assert!(backing.memory_id().initially_committed());
            assert!(backing.memory_id().initially_zero());
            assert!(owner
                .allocation
                .as_ref()
                .expect("root publication retains its capability")
                .matches_memory_id(backing.memory_id()));
            assert_eq!(owner.get(key(15, 1)).unwrap(), value);
            assert_eq!(current_thread_identity(), Some(identity));
            assert_eq!(crate::compiler_tls::fast_slot_peek(), fast_before);
            assert_eq!(crate::compiler_tls::default_theap(), default_before);
            assert_eq!(crate::compiler_tls::cached_theap(), cached_before);

            owner.teardown().unwrap();
            assert!(dynamic_backing_peek().is_none());
            assert!(matches!(
                owner.get(key(15, 1)),
                Err(ThreadLocalBackingError::TornDown)
            ));
            assert_eq!(crate::compiler_tls::fast_slot_peek(), fast_before);
            assert_eq!(crate::compiler_tls::default_theap(), default_before);
            assert_eq!(crate::compiler_tls::cached_theap(), cached_before);
        })
        .join()
        .expect("the isolated native TLS lifecycle completes");
    }

    #[test]
    fn current_thread_backing_teardown_retains_the_live_malloc_capability_before_root_clear_on_recursive_entry() {
        let metadata = MetaAllocator::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        metadata
            .prepare_for_main_subprocess(memory_config(), subprocess)
            .expect("the isolated source pair publishes metadata before TLS teardown");

        thread::spawn(move || {
            let mut owner = unsafe {
                ThreadLocalBackingOwner::begin_with_metadata(
                    metadata,
                    subprocess,
                    memory_config(),
                )
            }
            .expect("the isolated child begins at the immutable empty root");
            let live_key = key(15, 1);
            let mut payload = 0x5ausize;
            let value = (&mut payload as *mut usize).cast();
            owner
                .set(live_key, value)
                .expect("the source first expansion publishes one 16-slot Malloc image");

            let root_before = dynamic_backing_peek().expect("the live image is installed");
            // SAFETY: `owner` retains the exact live metadata capability and
            // the test has not begun a successful teardown.
            let memory_before = unsafe { root_before.as_ref() }.memory_id();
            let audit_before = metadata.test_allocation_audit();
            assert_eq!(audit_before.live_capability_count, 1);
            assert_eq!(audit_before.high_water_capability_count, 1);

            // This intentionally witnesses the direct owner boundary only.
            // An enclosing dynamic-Theap attachment has already changed its
            // own binding state before it delegates teardown and is outside
            // this retry contract.
            assert_eq!(
                metadata.test_with_held_backing_entry(|| owner.teardown()),
                Ok(Err(ThreadLocalBackingError::Metadata(MetaError::RecursiveEntry))),
                "the direct owner sees a selected Malloc rejection before it can consume the TLS capability"
            );
            assert_eq!(
                dynamic_backing_peek(),
                Some(root_before),
                "the direct owner cannot clear the regular TLS root before a retryable free succeeds"
            );
            assert_eq!(owner.count, 16, "the failed pre-claim free retains the image count");
            assert_eq!(owner.state, ThreadLocalBackingState::Active);
            assert!(
                owner
                    .allocation
                    .as_ref()
                    .is_some_and(|allocation| allocation.matches_memory_id(memory_before)),
                "the owner retains the exact Malloc capability returned by the pre-claim boundary"
            );
            assert_eq!(owner.get(live_key), Ok(value));
            assert_eq!(
                metadata.test_allocation_audit(),
                audit_before,
                "same-thread rejection leaves the live capability audit unchanged"
            );

            owner
                .teardown()
                .expect("the exact retained TLS capability releases after the backing entry drops");
            assert!(dynamic_backing_peek().is_none());
            assert_eq!(owner.count, 0);
            assert_eq!(owner.state, ThreadLocalBackingState::TornDown);
            assert_eq!(
                metadata.test_allocation_audit().live_capability_count,
                0,
                "the successful retry consumes the retained Malloc capability exactly once"
            );
        })
        .join()
        .expect("the selected recursive teardown/retry lifecycle completes");
    }

    #[test]
    fn current_thread_backing_preserves_slots_across_exact_source_growth_edges() {
        thread::spawn(|| {
            assert_eq!(
                DynamicThreadLocalBacking::allocation_size(16),
                Some(
                    core::mem::size_of::<DynamicThreadLocalBacking>()
                        + 16 * core::mem::size_of::<ThreadLocalSlot>()
                ),
                "the flexible source request includes the declared slots[1] prefix"
            );
            assert_eq!(DynamicThreadLocalBacking::allocation_size(0), None);
            let mut owner = unsafe { begin_with_prepared_test_metadata() }.unwrap();
            let mut first_payload = 0x11usize;
            let mut second_payload = 0x22usize;
            let mut third_payload = 0x33usize;
            let mut fourth_payload = 0x44usize;
            let mut fifth_payload = 0x55usize;
            let first = (&mut first_payload as *mut usize).cast();
            let second = (&mut second_payload as *mut usize).cast();
            let third = (&mut third_payload as *mut usize).cast();
            let fourth = (&mut fourth_payload as *mut usize).cast();
            let fifth = (&mut fifth_payload as *mut usize).cast();

            owner.set(key(15, 1), first).unwrap();
            assert_eq!(owner.count, 16);
            owner.set(key(16, 1), second).unwrap();
            assert_eq!(owner.count, 32, "below 1024 the source doubles");
            assert_eq!(owner.get(key(15, 1)).unwrap(), first);
            owner.set(key(1023, 1), third).unwrap();
            assert_eq!(
                owner.count, 1024,
                "least-index override wins over the interim 64-slot doubling result"
            );
            assert_eq!(owner.get(key(15, 1)).unwrap(), first);
            assert_eq!(owner.get(key(16, 1)).unwrap(), second);
            owner.set(key(1024, 1), fourth).unwrap();
            assert_eq!(owner.count, 2048, "at 1024 the source grows by 1024");
            owner.set(key(1025, 1), fifth).unwrap();
            assert_eq!(owner.count, 2048, "an in-range source set does not grow again");
            assert_eq!(owner.get(key(1023, 1)).unwrap(), third);
            assert_eq!(owner.get(key(1024, 1)).unwrap(), fourth);
            assert_eq!(owner.get(key(1025, 1)).unwrap(), fifth);

            owner.teardown().unwrap();
        })
        .join()
        .expect("the isolated growth lifecycle completes");
    }

    /// Covers the real `mi_thread_locals_expand` replacement route: after a
    /// live 16-slot image, a non-null index 16 set must retain the old Malloc
    /// capability on allocation failure, then copy that image and consume the
    /// old capability only after a successful 16-to-32 replacement.
    #[test]
    fn current_thread_backing_rezalloc_failure_preserves_the_old_malloc_capability_then_retries() {
        let metadata = MetaAllocator::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        metadata
            .prepare_for_main_subprocess(memory_config(), subprocess)
            .expect("the isolated source pair publishes metadata before resize demand");
        thread::spawn(move || {
            let mut owner = unsafe {
                ThreadLocalBackingOwner::begin_with_metadata(
                    metadata,
                    subprocess,
                    memory_config(),
                )
            }
            .expect("the isolated child begins at the immutable empty root");
            let original_key = key(15, 1);
            let growth_key = key(16, 1);
            let mut original_payload = 0x51usize;
            let mut grown_payload = 0x52usize;
            let original_value = (&mut original_payload as *mut usize).cast();
            let grown_value = (&mut grown_payload as *mut usize).cast();

            owner
                .set(original_key, original_value)
                .expect("the source starts with one 16-slot Malloc image");
            let root_before = dynamic_backing_peek().expect("the first image is published");
            // SAFETY: the live current-thread owner still retains the exact
            // first metadata capability and has just verified its TLS root.
            let backing_before = unsafe { root_before.as_ref() };
            assert_eq!(backing_before.memory_id().kind(), MemoryKind::Malloc);
            assert_eq!(backing_before.count(), 16);
            let before_failure = metadata.test_allocation_audit();
            assert_eq!(before_failure.live_capability_count, 1);
            assert_eq!(before_failure.high_water_capability_count, 1);
            let replacement_size = DynamicThreadLocalBacking::allocation_size(32)
                .expect("the exact source 16-to-32 request is representable");
            metadata
                .get_ref()
                .test_fail_next_rezalloc_size(replacement_size);

            assert_eq!(
                owner.set(growth_key, grown_value),
                Err(ThreadLocalBackingError::Metadata(MetaError::AllocationUnavailable))
            );
            assert_eq!(owner.count, 16);
            assert_eq!(dynamic_backing_peek(), Some(root_before));
            assert_eq!(owner.get(original_key).unwrap(), original_value);
            assert_eq!(owner.get(growth_key).unwrap(), core::ptr::null_mut());
            assert!(owner.allocation.is_some(), "the old capability remains live on failure");
            let after_failure = metadata.test_allocation_audit();
            assert_eq!(after_failure.live_capability_count, 1);
            assert_eq!(after_failure.high_water_capability_count, 1);

            owner
                .set(growth_key, grown_value)
                .expect("the next source replacement retries the exact old image");
            let root_after = dynamic_backing_peek().expect("the replacement is published");
            assert_ne!(root_after, root_before, "the live old image cannot alias its replacement");
            assert_eq!(owner.count, 32);
            // SAFETY: the current-thread owner retains the exact replacement
            // capability and verifies the compiler-TLS root before access.
            let backing = unsafe { root_after.as_ref() };
            assert_eq!(backing.memory_id().kind(), MemoryKind::Malloc);
            assert_eq!(backing.count(), 32);
            assert_eq!(owner.get(original_key).unwrap(), original_value);
            assert_eq!(owner.get(growth_key).unwrap(), grown_value);
            let after_retry = metadata.test_allocation_audit();
            assert_eq!(after_retry.live_capability_count, 1);
            assert_eq!(after_retry.high_water_capability_count, 2);

            owner
                .teardown()
                .expect("the replacement capability releases through source teardown");
            assert!(dynamic_backing_peek().is_none());
            let after_teardown = metadata.test_allocation_audit();
            assert_eq!(after_teardown.live_capability_count, 0);
            assert_eq!(after_teardown.high_water_capability_count, 2);
        })
        .join()
        .expect("the exact resize failure/retry lifecycle completes");
    }

    #[test]
    fn current_thread_backing_rejects_stale_generation_and_null_out_of_range_needs_no_growth() {
        thread::spawn(|| {
            let mut owner = unsafe { begin_with_prepared_test_metadata() }.unwrap();
            let stale = key(4, 1);
            let replacement = key(4, 2);
            let missing = key(512, 1);
            let mut old_payload = 0x71usize;
            let mut new_payload = 0x72usize;
            let old_value = (&mut old_payload as *mut usize).cast();
            let new_value = (&mut new_payload as *mut usize).cast();

            owner.set(missing, core::ptr::null_mut()).unwrap();
            assert_eq!(owner.count, 0);
            assert!(is_empty_dynamic_backing(
                dynamic_backing_peek().expect("the empty image stays installed")
            ));
            owner.set(stale, old_value).unwrap();
            assert_eq!(owner.get(stale).unwrap(), old_value);
            assert_eq!(
                owner.get(replacement).unwrap(),
                core::ptr::null_mut(),
                "a reused key index must not observe its stale generation"
            );
            owner.set(replacement, new_value).unwrap();
            assert_eq!(owner.get(stale).unwrap(), core::ptr::null_mut());
            assert_eq!(owner.get(replacement).unwrap(), new_value);

            owner.teardown().unwrap();
        })
        .join()
        .expect("the isolated stale-generation lifecycle completes");
    }

    #[test]
    fn current_thread_backing_rejects_the_source_count_above_the_16_bit_ceiling() {
        thread::spawn(|| {
            let mut owner = unsafe { begin_with_prepared_test_metadata() }.unwrap();
            let mut payload = 0x99usize;
            let value = (&mut payload as *mut usize).cast();
            assert_eq!(expanded_slot_count(0, 65_534), Ok(65_535));
            assert_eq!(
                expanded_slot_count(0, 65_535),
                Err(ThreadLocalBackingError::SlotCountLimit)
            );
            assert_eq!(
                owner.set(key(65_535, 1), value),
                Err(ThreadLocalBackingError::SlotCountLimit)
            );
            assert_eq!(owner.count, 0);
            assert!(is_empty_dynamic_backing(
                dynamic_backing_peek().expect("a rejected first growth leaves the empty root")
            ));
            owner.teardown().unwrap();
        })
        .join()
        .expect("the isolated source-limit lifecycle completes");
    }

    #[test]
    fn current_thread_backing_allocation_failure_keeps_the_empty_root_and_retries() {
        let metadata = MetaAllocator::test_static_owner();
        let subprocess = metadata.test_default_subprocess();
        metadata
            .prepare_for_main_subprocess(memory_config(), subprocess)
            .expect("the isolated source pair publishes metadata before faulted backing demand");
        thread::spawn(move || {
            let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, crabc_core::Errno::NOMEM));
            let mut owner = unsafe {
                ThreadLocalBackingOwner::begin_with_metadata(
                    metadata,
                    subprocess,
                    memory_config(),
                )
            }
            .unwrap();
            let mut payload = 0xabusize;
            let value = (&mut payload as *mut usize).cast();

            assert!(matches!(
                owner.set(key(0, 1), value),
                Err(ThreadLocalBackingError::Metadata(MetaError::InitializationFailed))
            ));
            assert_eq!(owner.count, 0);
            assert!(owner.allocation.is_none());
            assert!(is_empty_dynamic_backing(
                dynamic_backing_peek().expect("failed first allocation cannot publish a root")
            ));

            fault.set(fault::Plan::disabled());
            owner.set(key(0, 1), value).unwrap();
            assert_eq!(owner.get(key(0, 1)).unwrap(), value);
            owner.teardown().unwrap();
        })
        .join()
        .expect("the isolated injected-allocation-failure lifecycle completes");
    }

    #[test]
    fn current_thread_backing_failed_live_growth_preserves_root_value_and_capability() {
        const FILLER_SIZE: usize = 1024 * 1024;
        const MAX_FILLERS: usize = 128;
        const MAX_TAIL_FILLERS: usize = 8192;

        let metadata = MetaAllocator::test_static_owner();
        let subprocess = metadata.test_default_subprocess();
        metadata
            .prepare_for_main_subprocess(memory_config(), subprocess)
            .expect("the isolated source pair publishes metadata before growth demand");
        thread::spawn(move || {
            let mut owner = unsafe {
                ThreadLocalBackingOwner::begin_with_metadata(
                    metadata,
                    subprocess,
                    memory_config(),
                )
            }
            .unwrap();
            let original_key = key(15, 1);
            let growth_key = key(16, 1);
            let mut original_payload = 0xdead_beefusize;
            let mut grown_payload = 0xbeef_deadusize;
            let original_value = (&mut original_payload as *mut usize).cast();
            let grown_value = (&mut grown_payload as *mut usize).cast();
            owner.set(original_key, original_value).unwrap();
            let root_before = dynamic_backing_peek().expect("the first live image is published");
            let growth_size = DynamicThreadLocalBacking::allocation_size(32)
                .expect("the 16-to-32 source replacement request is representable");

            let mut fillers = std::vec::Vec::new();
            for _ in 0..MAX_FILLERS {
                match metadata.zalloc(memory_config(), FILLER_SIZE) {
                    Ok(filler) => fillers.push(filler),
                    Err(MetaError::AllocationUnavailable) => break,
                    Err(error) => panic!("unexpected metadata-fill failure: {error:?}"),
                }
            }
            assert!(
                fillers.len() < MAX_FILLERS,
                "the fixed detached metadata arena must eventually reject retained 1 MiB requests"
            );
            let mut tail_exhausted = false;
            for _ in 0..MAX_TAIL_FILLERS {
                match metadata.zalloc(memory_config(), growth_size) {
                    Ok(filler) => fillers.push(filler),
                    Err(MetaError::AllocationUnavailable) => {
                        tail_exhausted = true;
                        break;
                    }
                    Err(error) => panic!("unexpected tail-fill failure: {error:?}"),
                }
            }
            assert!(
                tail_exhausted,
                "retained target-size pages must consume the last metadata arena capacity"
            );

            assert_eq!(
                owner.set(growth_key, grown_value),
                Err(ThreadLocalBackingError::Metadata(MetaError::AllocationUnavailable))
            );
            assert_eq!(owner.count, 16);
            assert_eq!(dynamic_backing_peek(), Some(root_before));
            assert_eq!(owner.get(original_key).unwrap(), original_value);
            assert!(owner.allocation.is_some(), "the old release capability remains live");

            for filler in &mut fillers {
                metadata.free(filler).unwrap();
            }
            owner.set(growth_key, grown_value).unwrap();
            assert_eq!(owner.count, 32);
            assert_eq!(owner.get(original_key).unwrap(), original_value);
            assert_eq!(owner.get(growth_key).unwrap(), grown_value);
            owner.teardown().unwrap();
        })
        .join()
        .expect("the isolated live-growth failure lifecycle completes");
    }

    #[test]
    fn current_thread_backings_are_isolated_across_overlapping_native_threads() {
        const THREADS: usize = 2;
        let start = std::sync::Arc::new(Barrier::new(THREADS + 1));
        let (sender, receiver) = mpsc::channel();
        let mut workers = std::vec::Vec::new();

        for payload in [0x101usize, 0x202usize] {
            let worker_start = std::sync::Arc::clone(&start);
            let worker_sender = sender.clone();
            workers.push(thread::spawn(move || {
                let mut owner = unsafe { begin_with_prepared_test_metadata() }.unwrap();
                let identity = current_thread_identity().expect("the worker has a native TLS identity");
                let fast_before = crate::compiler_tls::fast_slot_peek();
                let default_before = crate::compiler_tls::default_theap();
                let cached_before = crate::compiler_tls::cached_theap();
                let mut payload = payload;
                let value = (&mut payload as *mut usize).cast();
                owner.set(key(3, 1), value).unwrap();
                let root = dynamic_backing_peek().expect("the worker published its own root");
                worker_start.wait();
                let observed = owner.get(key(3, 1)).unwrap();
                worker_sender
                    .send((
                        identity.get(),
                        root.as_ptr() as usize,
                        observed as usize,
                        value as usize,
                        crate::compiler_tls::fast_slot_peek()
                            .map_or(0, |pointer| pointer.as_ptr() as usize),
                        fast_before.map_or(0, |pointer| pointer.as_ptr() as usize),
                        crate::compiler_tls::default_theap().as_ptr() as usize,
                        default_before.as_ptr() as usize,
                        crate::compiler_tls::cached_theap().as_ptr() as usize,
                        cached_before.as_ptr() as usize,
                    ))
                    .unwrap();
                owner.teardown().unwrap();
                assert!(dynamic_backing_peek().is_none());
            }));
        }
        drop(sender);
        start.wait();

        let results = (0..THREADS)
            .map(|_| receiver.recv().expect("every worker reports before teardown"))
            .collect::<std::vec::Vec<_>>();
        for worker in workers {
            worker.join().expect("the worker TLS lifecycle completes");
        }
        assert_ne!(results[0].0, results[1].0, "native TLS identities are distinct");
        assert_ne!(results[0].1, results[1].1, "each worker owns a separate backing");
        for result in &results {
            assert_eq!(result.2, result.3, "each worker retrieves only its own value");
            assert_eq!(result.4, result.5, "regular backing leaves the fast root alone");
            assert_eq!(result.6, result.7, "regular backing leaves default-theap alone");
            assert_eq!(result.8, result.9, "regular backing leaves cached-theap alone");
        }
    }

    #[test]
    fn persistent_compiler_tls_owner_keeps_one_inline_owner_pinned_across_local_borrows() {
        struct Owner {
            operations: usize,
            torn_down: bool,
            drops: Arc<AtomicUsize>,
            _pinned: core::marker::PhantomPinned,
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                assert!(self.torn_down, "the owner drops only after source teardown");
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        thread::spawn(|| {
            let drops = Arc::new(AtomicUsize::new(0));
            let expected_address = core::cell::Cell::new(0);
            let cell = core::pin::pin!(PersistentCompilerTlsOwnerCell::new());
            let cell = cell.as_ref();
            assert!(cell
                .initialize(
                    Owner {
                        operations: 0,
                        torn_down: false,
                        drops: Arc::clone(&drops),
                        _pinned: core::marker::PhantomPinned,
                    },
                    |owner| {
                        expected_address.set(owner.as_ref().get_ref() as *const Owner as usize);
                        assert_eq!(
                            cell.with_owner(|_| ()),
                            Err(PersistentCompilerTlsOwnerError::Initializing),
                            "the owner is not published active during in-place initialization"
                        );
                        Ok::<(), ()>(())
                    },
                )
                .is_ok());

            let first_address = cell
                .with_owner(|owner| {
                    let address = owner.as_ref().get_ref() as *const Owner as usize;
                    // SAFETY: the TLS cell lends this pinned owner exclusively
                    // for the closure and this mutation does not move it.
                    unsafe { owner.get_unchecked_mut() }.operations += 1;
                    address
                })
                .expect("the attached owner permits its first local borrow");
            let second_address = cell
                .with_owner(|owner| {
                    let address = owner.as_ref().get_ref() as *const Owner as usize;
                    // SAFETY: as above, only a field changes in place.
                    unsafe { owner.get_unchecked_mut() }.operations += 1;
                    address
                })
                .expect("the same attached owner permits another local borrow");

            assert_eq!(first_address, expected_address.get());
            assert_eq!(second_address, expected_address.get());
            assert_eq!(cell.completed_operation_count_for_test(), 2);

            assert!(cell
                .teardown(|owner| {
                    assert_eq!(owner.as_ref().get_ref().operations, 2);
                    // SAFETY: source teardown mutates the pinned owner in
                    // place and consumes no address-stability invariant.
                    unsafe { owner.get_unchecked_mut() }.torn_down = true;
                    Ok::<(), ()>(())
                })
                .is_ok());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(
                cell.with_owner(|_| ()),
                Err(PersistentCompilerTlsOwnerError::TornDown)
            );
        })
        .join()
        .expect("the persistent compiler-TLS owner test completes");
    }

    #[test]
    fn persistent_compiler_tls_owner_refuses_reentry_before_projecting_a_second_borrow() {
        struct Owner;

        thread::spawn(|| {
            let cell = core::pin::pin!(PersistentCompilerTlsOwnerCell::new());
            let cell = cell.as_ref();
            assert!(cell.initialize(Owner, |_| Ok::<(), ()>(())).is_ok());
            cell.with_owner(|_| {
                assert_eq!(
                    cell.with_owner(|_| ()),
                    Err(PersistentCompilerTlsOwnerError::Reentrant),
                    "a nested local operation must not form a second mutable owner borrow"
                );
            })
            .expect("the original local borrow remains valid after the rejected recursion");
            assert!(matches!(
                cell.initialize(Owner, |_| Ok::<(), ()>(())),
                Err(PersistentCompilerTlsOwnerInitializeError::State {
                    error: PersistentCompilerTlsOwnerError::AlreadyActive,
                    owner: Owner,
                })
            ));
            assert!(cell.teardown(|_| Ok::<(), ()>(())).is_ok());
        })
        .join()
        .expect("the compiler-TLS recursion test completes");
    }

    #[test]
    fn persistent_compiler_tls_owner_retains_one_way_operation_mutation_after_unwind() {
        struct Owner {
            one_way_source_mutation: bool,
            torn_down: bool,
            drops: Arc<AtomicUsize>,
            _pinned: core::marker::PhantomPinned,
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                assert!(self.torn_down, "the retained owner drops only after teardown");
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        thread::spawn(|| {
            let drops = Arc::new(AtomicUsize::new(0));
            let operation_address = core::cell::Cell::new(0);
            let cell = core::pin::pin!(PersistentCompilerTlsOwnerCell::new());
            let cell = cell.as_ref();
            assert!(cell
                .initialize(
                    Owner {
                        one_way_source_mutation: false,
                        torn_down: false,
                        drops: Arc::clone(&drops),
                        _pinned: core::marker::PhantomPinned,
                    },
                    |_| Ok::<(), ()>(()),
                )
                .is_ok());

            let unwind = catch_unwind(AssertUnwindSafe(|| {
                let _: Result<(), PersistentCompilerTlsOwnerError> = cell.with_owner(|owner| {
                    operation_address
                        .set(owner.as_ref().get_ref() as *const Owner as usize);
                    // SAFETY: the cell grants this closure the only pinned
                    // mutable projection; the mutation does not move `Owner`.
                    unsafe { owner.get_unchecked_mut() }.one_way_source_mutation = true;
                    panic!("operation unwinds after mutating source state");
                });
            }));
            assert!(unwind.is_err());
            assert_eq!(cell.completed_operation_count_for_test(), 0);
            assert_eq!(cell.state_for_test(), PersistentCompilerTlsOwnerState::Retained);
            assert_eq!(
                cell.with_owner(|_| ()),
                Err(PersistentCompilerTlsOwnerError::Retained),
                "an unwinding operation must not republish one-way source state as active"
            );
            assert_eq!(drops.load(Ordering::Relaxed), 0);

            assert!(cell
                .teardown(|owner| {
                    assert_eq!(
                        owner.as_ref().get_ref() as *const Owner as usize,
                        operation_address.get(),
                        "teardown receives the exact payload retained after unwind"
                    );
                    assert!(owner.as_ref().get_ref().one_way_source_mutation);
                    // SAFETY: teardown mutates the retained pinned shell in
                    // place before authorizing its terminal drop.
                    unsafe { owner.get_unchecked_mut() }.torn_down = true;
                    Ok::<(), ()>(())
                })
                .is_ok());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        })
        .join()
        .expect("the compiler-TLS operation-unwind test completes");
    }

    #[test]
    fn persistent_compiler_tls_owner_retains_failed_exit_for_one_source_ordered_retry() {
        struct Owner {
            drops: Arc<AtomicUsize>,
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        thread::spawn(|| {
            let drops = Arc::new(AtomicUsize::new(0));
            let cell = core::pin::pin!(PersistentCompilerTlsOwnerCell::new());
            let cell = cell.as_ref();
            assert!(cell
                .initialize(
                    Owner {
                        drops: Arc::clone(&drops),
                    },
                    |_| Ok::<(), ()>(()),
                )
                .is_ok());
            let address = core::cell::Cell::new(0);
            assert_eq!(
                cell.teardown(|owner| {
                    address.set(owner.as_ref().get_ref() as *const Owner as usize);
                    Err("pages remain live")
                }),
                Err(PersistentCompilerTlsOwnerTeardownError::Owner(
                    "pages remain live"
                ))
            );
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(
                cell.with_owner(|_| ()),
                Err(PersistentCompilerTlsOwnerError::Retained),
                "ordinary work cannot reenter an owner retained during exit"
            );
            assert!(cell
                .teardown(|owner| {
                    assert_eq!(
                        owner.as_ref().get_ref() as *const Owner as usize,
                        address.get(),
                        "retry receives the exact retained pinned payload"
                    );
                    Ok::<(), &str>(())
                })
                .is_ok());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(cell.state_for_test(), PersistentCompilerTlsOwnerState::TornDown);
        })
        .join()
        .expect("the retained-exit compiler-TLS owner test completes");
    }

    #[test]
    fn persistent_compiler_tls_owner_retains_an_initialization_failure_in_place() {
        struct Owner {
            drops: Arc<AtomicUsize>,
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        thread::spawn(|| {
            let drops = Arc::new(AtomicUsize::new(0));
            let address = core::cell::Cell::new(0);
            let cell = core::pin::pin!(PersistentCompilerTlsOwnerCell::new());
            let cell = cell.as_ref();
            assert!(matches!(
                cell.initialize(
                    Owner {
                        drops: Arc::clone(&drops),
                    },
                    |owner| {
                        address.set(owner.as_ref().get_ref() as *const Owner as usize);
                        Err("attachment retained source state")
                    },
                ),
                Err(PersistentCompilerTlsOwnerInitializeError::Owner(
                    "attachment retained source state"
                ))
            ));
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(cell.state_for_test(), PersistentCompilerTlsOwnerState::Retained);
            assert!(cell
                .teardown(|owner| {
                    assert_eq!(
                        owner.as_ref().get_ref() as *const Owner as usize,
                        address.get()
                    );
                    Ok::<(), ()>(())
                })
                .is_ok());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        })
        .join()
        .expect("the retained-initialization compiler-TLS owner test completes");
    }
}
