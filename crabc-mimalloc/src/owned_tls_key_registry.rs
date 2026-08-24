// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/threadlocal.c:221-315` and
// `src/bitmap.c:594-705,1297-1380`.

//! Allocator-owned process-global dynamic TLS-key registry.
//!
//! This is intentionally distinct from `thread_local::ThreadLocalKeyRegistry`:
//! that earlier type remains a bounded caller-storage substrate. This owner
//! retains the source bitmap as one linear `MetaAllocation` capability and
//! projects a `BitmapView` only inside its locked operations. The lock order
//! is always this registry's `PrivateLock` followed by `MetaAllocator`; no
//! caller may enter this registry while holding the metadata allocator lock.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::pin::Pin;
#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_core::Errno;

use crate::bitmap::{BCHUNK_SIZE, BitmapLayout};
use crate::lock::PrivateLock;
use crate::meta::{MetaAllocation, MetaAllocator, MetaBitmapProjectionError, MetaError};
use crate::os::MemoryConfig;
use crate::subproc::MainSubprocess;
use crate::thread_local::{
    TLS_FAST_KEY_RAW, TLS_INDEX_MASK, TLS_REGISTRY_EXPANSION_BITS,
    ThreadLocalKey, ThreadLocalKeyVersions, ThreadLocalSlotIndex,
};

/// The lifecycle state of the one process-global regular-key registry.
///
/// `ReadyWithoutBitmap` is observable after construction or a recoverable
/// first allocation failure. `Exhausted` retains its final bitmap and accepts
/// releases, which return it to `ReadyWithBitmap`. `Poisoned` retains any
/// previously published or committed typed image after an ownership-ambiguous
/// transition; `Shutdown` has no image and touches no bitmap again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedRegistryPhase {
    Cold,
    ReadyWithoutBitmap,
    ReadyWithBitmap,
    Exhausted,
    Poisoned,
    Shutdown,
}

struct RegistryBitmap {
    layout: BitmapLayout,
    allocation: MetaAllocation<'static>,
}

struct OwnedRegistryState {
    phase: OwnedRegistryPhase,
    bitmap: Option<RegistryBitmap>,
    versions: ThreadLocalKeyVersions,
    live_leases: usize,
    subprocess: Option<&'static MainSubprocess>,
    metadata: Option<Pin<&'static MetaAllocator>>,
}

impl OwnedRegistryState {
    const fn new() -> Self {
        Self {
            phase: OwnedRegistryPhase::Cold,
            bitmap: None,
            versions: ThreadLocalKeyVersions::new(),
            live_leases: 0,
            subprocess: None,
            metadata: None,
        }
    }

    #[inline]
    fn selected_metadata(&self) -> Result<Pin<&'static MetaAllocator>, OwnedThreadLocalKeyError> {
        self.metadata.ok_or(OwnedThreadLocalKeyError::Poisoned)
    }

    #[inline]
    fn select_main(
        &mut self,
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
    ) -> Result<(), OwnedThreadLocalKeyError> {
        match self.phase {
            OwnedRegistryPhase::Cold => {
                self.subprocess = Some(subprocess);
                self.metadata = Some(metadata);
                self.phase = OwnedRegistryPhase::ReadyWithoutBitmap;
                Ok(())
            }
            OwnedRegistryPhase::ReadyWithoutBitmap
            | OwnedRegistryPhase::ReadyWithBitmap
            | OwnedRegistryPhase::Exhausted => {
                if self.subprocess.is_some_and(|selected| core::ptr::eq(selected, subprocess))
                    && self.metadata.is_some_and(|selected| {
                        core::ptr::eq(selected.get_ref(), metadata.get_ref())
                    })
                {
                    Ok(())
                } else {
                    Err(OwnedThreadLocalKeyError::SubprocessMismatch)
                }
            }
            OwnedRegistryPhase::Poisoned => Err(OwnedThreadLocalKeyError::Poisoned),
            OwnedRegistryPhase::Shutdown => Err(OwnedThreadLocalKeyError::Shutdown),
        }
    }
}

/// One private process-global regular TLS-key registry error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnedThreadLocalKeyError {
    Lock(Errno),
    Meta(MetaError),
    Bitmap(MetaBitmapProjectionError),
    SubprocessMismatch,
    Exhausted,
    Poisoned,
    Shutdown,
    ShutdownLiveLeases,
    InvalidRelease,
}

/// Static owner of mimalloc's regular dynamic TLS-key bitmap and version.
///
/// The source's `mi_thread_locals_free`, `mi_thread_locals_memid`, and
/// `mi_thread_locals_version` become the typed state behind this lock. The
/// bitmap starts lazy; it is process metadata rather than compiler TLS and is
/// never installed in `DYNAMIC_BACKING_ROOT`.
pub(crate) struct OwnedThreadLocalKeyRegistry {
    lock: PrivateLock,
    state: UnsafeCell<OwnedRegistryState>,
    #[cfg(test)]
    fail_next_bitmap_allocation: AtomicUsize,
    #[cfg(test)]
    bitmap_allocation_attempts: AtomicUsize,
}

// SAFETY: all mutable state, including the linear metadata capability, is
// reached only while `lock` is held. The registry and its selected metadata
// owner are process-lived; leases retain a shared registry reference.
unsafe impl Sync for OwnedThreadLocalKeyRegistry {}

impl OwnedThreadLocalKeyRegistry {
    const fn new() -> Self {
        Self {
            lock: PrivateLock::new(),
            state: UnsafeCell::new(OwnedRegistryState::new()),
            #[cfg(test)]
            fail_next_bitmap_allocation: AtomicUsize::new(0),
            #[cfg(test)]
            bitmap_allocation_attempts: AtomicUsize::new(0),
        }
    }

    /// Returns the one process-global registry.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_OWNED_THREAD_LOCAL_KEYS
    }

    /// Claims one regular source key using the process-main metadata owner.
    ///
    /// This does not consume a thread-registration ticket, touch compiler TLS,
    /// or attach a TLD/theap. The selected main subprocess is fixed on the
    /// first claim and every future registry bitmap allocation keeps using it.
    pub(crate) fn claim(
        &'static self,
        config: MemoryConfig,
    ) -> Result<OwnedThreadLocalKeyLease, OwnedThreadLocalKeyError> {
        self.claim_selected(config, MainSubprocess::global(), MetaAllocator::global())
    }

    fn claim_selected(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
    ) -> Result<OwnedThreadLocalKeyLease, OwnedThreadLocalKeyError> {
        let guard = self.lock.lock().map_err(OwnedThreadLocalKeyError::Lock)?;
        // SAFETY: the held registry lock is the only mutable access to its
        // typed state and retained bitmap capability.
        let state = unsafe { &mut *self.state.get() };
        state.select_main(subprocess, metadata)?;

        loop {
            match state.phase {
                OwnedRegistryPhase::ReadyWithBitmap | OwnedRegistryPhase::Exhausted => {
                    let Some(bitmap) = state.bitmap.as_ref() else {
                        state.phase = OwnedRegistryPhase::Poisoned;
                        return Err(OwnedThreadLocalKeyError::Poisoned);
                    };
                    let selected_metadata = match state.selected_metadata() {
                        Ok(metadata) => metadata,
                        Err(_) => {
                            state.phase = OwnedRegistryPhase::Poisoned;
                            return Err(OwnedThreadLocalKeyError::Poisoned);
                        }
                    };
                    let index = match bitmap
                        .allocation
                        .with_bitmap_view(selected_metadata, bitmap.layout, |view| {
                            view.try_find_and_claim_lowest()
                        })
                    {
                        Ok(index) => index,
                        Err(error) => {
                            // A published image that cannot be projected by
                            // its retained typed capability violates an owner
                            // invariant. Do not offer another claim over an
                            // uncertain bitmap representation.
                            state.phase = OwnedRegistryPhase::Poisoned;
                            return Err(OwnedThreadLocalKeyError::Bitmap(error));
                        }
                    };
                    if let Some(index) = index {
                        let Some(index) = ThreadLocalSlotIndex::new(index) else {
                            state.phase = OwnedRegistryPhase::Poisoned;
                            return Err(OwnedThreadLocalKeyError::Poisoned);
                        };
                        let key = state.versions.claim(index);
                        debug_assert_ne!(key.raw(), TLS_FAST_KEY_RAW);
                        state.live_leases += 1;
                        state.phase = OwnedRegistryPhase::ReadyWithBitmap;
                        drop(guard);
                        return Ok(OwnedThreadLocalKeyLease {
                            registry: self,
                            key,
                        });
                    }
                    self.expand_locked(state, config)?;
                }
                OwnedRegistryPhase::ReadyWithoutBitmap => self.expand_locked(state, config)?,
                OwnedRegistryPhase::Poisoned => return Err(OwnedThreadLocalKeyError::Poisoned),
                OwnedRegistryPhase::Shutdown => return Err(OwnedThreadLocalKeyError::Shutdown),
                OwnedRegistryPhase::Cold => return Err(OwnedThreadLocalKeyError::Poisoned),
            }
        }
    }

    /// Holds the registry lock while it allocates/copies/publishes one exact
    /// +1024-bit source image. The lock order is registry then metadata.
    fn expand_locked(
        &self,
        state: &mut OwnedRegistryState,
        config: MemoryConfig,
    ) -> Result<(), OwnedThreadLocalKeyError> {
        debug_assert!(matches!(
            state.phase,
            OwnedRegistryPhase::ReadyWithoutBitmap
                | OwnedRegistryPhase::ReadyWithBitmap
                | OwnedRegistryPhase::Exhausted
        ));
        let old_bits = state.bitmap.as_ref().map_or(0, |bitmap| bitmap.layout.max_bits());
        let new_bits = old_bits + TLS_REGISTRY_EXPANSION_BITS;
        if new_bits > TLS_INDEX_MASK as usize {
            state.phase = OwnedRegistryPhase::Exhausted;
            return Err(OwnedThreadLocalKeyError::Exhausted);
        }
        let Some(new_layout) = BitmapLayout::for_bit_count(new_bits) else {
            state.phase = OwnedRegistryPhase::Poisoned;
            return Err(OwnedThreadLocalKeyError::Poisoned);
        };
        let metadata = match state.selected_metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                state.phase = OwnedRegistryPhase::Poisoned;
                return Err(OwnedThreadLocalKeyError::Poisoned);
            }
        };
        let Some(subprocess) = state.subprocess else {
            state.phase = OwnedRegistryPhase::Poisoned;
            return Err(OwnedThreadLocalKeyError::Poisoned);
        };

        #[cfg(test)]
        {
            self.bitmap_allocation_attempts.fetch_add(1, Ordering::Relaxed);
            if self.fail_next_bitmap_allocation.swap(0, Ordering::Relaxed) != 0 {
                return Err(OwnedThreadLocalKeyError::Meta(MetaError::AllocationUnavailable));
            }
        }

        let mut replacement = metadata
            .zalloc_aligned_for_main_subprocess(config, subprocess, new_layout.byte_size(), BCHUNK_SIZE)
            .map_err(OwnedThreadLocalKeyError::Meta)?;

        let initialized = if let Some(old) = state.bitmap.as_ref() {
            replacement
                .copy_bitmap_image_from(metadata, new_layout, &old.allocation, old.layout)
                .and_then(|()| {
                    replacement.publish_preserved_bitmap(metadata, new_layout, |view| {
                        // SAFETY: the outer registry lock keeps the replacement
                        // private through copied-image publication; exactly the
                        // appended source range becomes free.
                        unsafe { view.unsafe_set_range_local(old_bits, TLS_REGISTRY_EXPANSION_BITS) }
                    })
                })
        } else {
            replacement.initialize_zeroed_bitmap(metadata, new_layout, |view| {
                // SAFETY: this first fresh bitmap remains registry-private;
                // exactly its initial source block becomes free.
                unsafe { view.unsafe_set_range_local(0, TLS_REGISTRY_EXPANSION_BITS) }
            })
        };
        match initialized {
            Ok(Some(())) => {}
            Ok(None) => {
                // The old image was never consumed or replaced. A cleanup
                // failure would itself make the new capability ambiguous. An
                // absent appended-range result is likewise a construction
                // invariant failure, so retain the old owner terminally.
                if metadata.free(&mut replacement).is_err() {
                    state.phase = OwnedRegistryPhase::Poisoned;
                    return Err(OwnedThreadLocalKeyError::Poisoned);
                }
                state.phase = OwnedRegistryPhase::Poisoned;
                return Err(OwnedThreadLocalKeyError::Poisoned);
            }
            Err(error) => {
                // A typed-projection error after fresh allocation means the
                // process-owned image/provenance contract was broken. The
                // old image remains retained, but no retry may reinterpret it.
                if metadata.free(&mut replacement).is_err() {
                    state.phase = OwnedRegistryPhase::Poisoned;
                    return Err(OwnedThreadLocalKeyError::Poisoned);
                }
                state.phase = OwnedRegistryPhase::Poisoned;
                return Err(OwnedThreadLocalKeyError::Bitmap(error));
            }
        }

        // Commit the new typed capability before consuming the old one. A
        // later free error is ownership-ambiguous and therefore terminal, but
        // the committed image remains retained rather than dangling.
        let old = state.bitmap.replace(RegistryBitmap {
            layout: new_layout,
            allocation: replacement,
        });
        state.phase = OwnedRegistryPhase::ReadyWithBitmap;
        if let Some(mut old) = old {
            if metadata.free(&mut old.allocation).is_err() {
                state.phase = OwnedRegistryPhase::Poisoned;
                return Err(OwnedThreadLocalKeyError::Poisoned);
            }
        }
        Ok(())
    }

    #[inline]
    fn release_claimed(&self, key: ThreadLocalKey) -> Result<(), OwnedThreadLocalKeyError> {
        let guard = self.lock.lock().map_err(OwnedThreadLocalKeyError::Lock)?;
        // SAFETY: the lock serializes bitmap and live-lease state.
        let state = unsafe { &mut *self.state.get() };
        match state.phase {
            OwnedRegistryPhase::ReadyWithBitmap | OwnedRegistryPhase::Exhausted => {}
            OwnedRegistryPhase::Poisoned => return Err(OwnedThreadLocalKeyError::Poisoned),
            OwnedRegistryPhase::Shutdown => return Err(OwnedThreadLocalKeyError::Shutdown),
            _ => return Err(OwnedThreadLocalKeyError::InvalidRelease),
        }
        let Some(bitmap) = state.bitmap.as_ref() else {
            state.phase = OwnedRegistryPhase::Poisoned;
            return Err(OwnedThreadLocalKeyError::Poisoned);
        };
        let index = key.index().get();
        if index >= bitmap.layout.max_bits() || state.live_leases == 0 {
            return Err(OwnedThreadLocalKeyError::InvalidRelease);
        }
        let metadata = match state.selected_metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                state.phase = OwnedRegistryPhase::Poisoned;
                return Err(OwnedThreadLocalKeyError::Poisoned);
            }
        };
        let released = match bitmap
            .allocation
            .with_bitmap_view(metadata, bitmap.layout, |view| view.set_range(index, 1))
        {
            Ok(released) => released,
            Err(error) => {
                state.phase = OwnedRegistryPhase::Poisoned;
                return Err(OwnedThreadLocalKeyError::Bitmap(error));
            }
        };
        if released.is_none() {
            state.phase = OwnedRegistryPhase::Poisoned;
            return Err(OwnedThreadLocalKeyError::Poisoned);
        }
        // The pinned source intentionally ignores the key generation here.
        state.live_leases -= 1;
        state.phase = OwnedRegistryPhase::ReadyWithBitmap;
        drop(guard);
        Ok(())
    }

    /// Stops claims and frees the retained bitmap only after every explicit
    /// lease has been released. The private lock remains process-static and is
    /// not destroyed, matching its no-destruction contract.
    pub(crate) fn shutdown(&'static self) -> Result<(), OwnedThreadLocalKeyError> {
        let guard = self.lock.lock().map_err(OwnedThreadLocalKeyError::Lock)?;
        // SAFETY: the registry lock excludes claim/release/replacement while
        // shutdown checks liveness and moves its sole typed capability.
        let state = unsafe { &mut *self.state.get() };
        match state.phase {
            OwnedRegistryPhase::Shutdown => return Err(OwnedThreadLocalKeyError::Shutdown),
            OwnedRegistryPhase::Poisoned => return Err(OwnedThreadLocalKeyError::Poisoned),
            _ => {}
        }
        if state.live_leases != 0 {
            return Err(OwnedThreadLocalKeyError::ShutdownLiveLeases);
        }
        let bitmap = state.bitmap.take();
        state.phase = OwnedRegistryPhase::Shutdown;
        if let Some(mut bitmap) = bitmap {
            let metadata = match state.selected_metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    state.bitmap = Some(bitmap);
                    state.phase = OwnedRegistryPhase::Poisoned;
                    return Err(OwnedThreadLocalKeyError::Poisoned);
                }
            };
            if metadata.free(&mut bitmap.allocation).is_err() {
                state.bitmap = Some(bitmap);
                state.phase = OwnedRegistryPhase::Poisoned;
                return Err(OwnedThreadLocalKeyError::Poisoned);
            }
        }
        drop(guard);
        Ok(())
    }

    #[cfg(test)]
    fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    #[cfg(test)]
    fn test_claim_selected(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
    ) -> Result<OwnedThreadLocalKeyLease, OwnedThreadLocalKeyError> {
        self.claim_selected(config, subprocess, metadata)
    }

    #[cfg(test)]
    fn test_fail_next_bitmap_allocation(&self) {
        self.fail_next_bitmap_allocation.store(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn test_bitmap_allocation_attempts(&self) -> usize {
        self.bitmap_allocation_attempts.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn test_state(&self) -> (OwnedRegistryPhase, usize, u64, Option<(usize, usize, usize)>) {
        let guard = self.lock.lock().expect("test registry lock acquires");
        // SAFETY: the held test lock gives read-only access to its state.
        let state = unsafe { &*self.state.get() };
        let bitmap = state.bitmap.as_ref().map(|bitmap| {
            (
                bitmap.layout.max_bits(),
                bitmap.layout.byte_size(),
                bitmap.allocation.pointer().as_ptr().addr(),
            )
        });
        let result = (
            state.phase,
            state.live_leases,
            state.versions.last_claimed(),
            bitmap,
        );
        drop(guard);
        result
    }

    #[cfg(test)]
    fn test_release_raw_after_shutdown(&self, key: ThreadLocalKey) -> Result<(), OwnedThreadLocalKeyError> {
        self.release_claimed(key)
    }

    #[cfg(test)]
    fn test_bitmap_image(&self) -> Option<(BitmapLayout, crate::types::MemoryId, usize)> {
        let guard = self.lock.lock().expect("test registry lock acquires");
        // SAFETY: the held test lock provides a read-only snapshot of the
        // capability without forming a persistent bitmap projection.
        let state = unsafe { &*self.state.get() };
        let image = state.bitmap.as_ref().map(|bitmap| {
            (
                bitmap.layout,
                bitmap.allocation.memory_id(),
                bitmap.allocation.pointer().as_ptr().addr(),
            )
        });
        drop(guard);
        image
    }

    #[cfg(test)]
    fn test_set_last_claimed(&self, version: u64) {
        let guard = self.lock.lock().expect("test registry lock acquires");
        // SAFETY: the test lock provides the same exclusive transition
        // boundary as a source registry claim.
        let state = unsafe { &mut *self.state.get() };
        state.versions.set_last_claimed_for_test(version);
        drop(guard);
    }
}

static PROCESS_OWNED_THREAD_LOCAL_KEYS: OwnedThreadLocalKeyRegistry =
    OwnedThreadLocalKeyRegistry::new();

/// Linear lease for one regular process-global dynamic TLS key.
///
/// It is intentionally neither `Copy` nor `Clone`. Dropping it does not free
/// the index, matching a missed source `_mi_thread_local_free`; only consuming
/// [`Self::release`] records the exact bitmap release transition.
#[must_use = "a claimed regular TLS key must be explicitly released"]
pub(crate) struct OwnedThreadLocalKeyLease {
    registry: &'static OwnedThreadLocalKeyRegistry,
    key: ThreadLocalKey,
}

impl OwnedThreadLocalKeyLease {
    #[inline]
    pub(crate) const fn key(&self) -> ThreadLocalKey {
        self.key
    }

    /// Returns this key's index under the registry lock.
    ///
    /// The caller must first make every dynamic TLS slot quiescent. The source
    /// release ignores the generation and sets only the decoded index; this
    /// linear token prevents a second safe release of the same live claim.
    #[inline]
    pub(crate) fn release(self) -> Result<(), OwnedThreadLocalKeyError> {
        self.registry.release_claimed(self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::PageSize;
    use crate::thread_local::{
        TLS_REGISTRY_MAX_BLOCKS, TLS_VERSION_MAX, ThreadLocalSlot, ThreadLocalSlots,
    };
    use crate::types::MemoryKind;
    use std::sync::{mpsc, Barrier};
    use std::thread;

    fn config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the pinned native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn fixture() -> (
        &'static OwnedThreadLocalKeyRegistry,
        Pin<&'static MetaAllocator>,
        &'static MainSubprocess,
    ) {
        (
            OwnedThreadLocalKeyRegistry::test_static_owner(),
            MetaAllocator::test_static_owner(),
            MainSubprocess::test_static_owner(),
        )
    }

    #[test]
    fn first_regular_key_uses_index_zero_version_one_and_never_fast_raw_one() {
        let (registry, metadata, subprocess) = fixture();
        let lease = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the first registry image allocates");

        assert_eq!(lease.key().index().get(), 0);
        assert_eq!(lease.key().version(), 1);
        assert_ne!(lease.key().raw(), TLS_FAST_KEY_RAW, "raw one is the reserved fast key");
        assert_eq!(TLS_FAST_KEY_RAW, 1);
        lease.release().expect("the first explicit release succeeds");
        registry.shutdown().expect("a quiescent image shuts down");
    }

    #[test]
    fn first_image_is_exact_aligned_malloc_metadata_for_the_selected_main_subprocess() {
        let (registry, metadata, subprocess) = fixture();
        let lease = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the first registry image allocates");
        let (layout, memory, address) = registry
            .test_bitmap_image()
            .expect("the first claim retains its typed bitmap capability");

        assert_eq!(layout.max_bits(), TLS_REGISTRY_EXPANSION_BITS);
        assert_eq!(layout.byte_size(), 256, "two source chunks follow the 128-byte prefix");
        assert_eq!(address % BCHUNK_SIZE, 0);
        assert_eq!(memory.kind(), MemoryKind::Malloc);
        assert!(memory.is_pinned());
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        let malloc = memory
            .malloc_memory()
            .expect("a metadata bitmap has Malloc union provenance");
        assert_eq!(malloc.base.addr(), address);
        assert_eq!(malloc.size, layout.byte_size());

        lease.release().expect("the explicit lease release succeeds");
        registry.shutdown().expect("the exact typed image can be freed quiescently");
    }

    #[test]
    fn expansion_copies_claims_and_makes_only_the_appended_source_range_available() {
        let (registry, metadata, subprocess) = fixture();
        let mut leases = std::vec::Vec::with_capacity(TLS_REGISTRY_EXPANSION_BITS);
        for expected in 0..TLS_REGISTRY_EXPANSION_BITS {
            let lease = registry
                .test_claim_selected(config(), subprocess, metadata)
                .expect("every initial source index is claimable");
            assert_eq!(lease.key().index().get(), expected);
            leases.push(lease);
        }
        let (_, _, old_address) = registry
            .test_bitmap_image()
            .expect("the first image remains retained while full");

        let appended = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the full first image expands by exactly one block");
        assert_eq!(appended.key().index().get(), TLS_REGISTRY_EXPANSION_BITS);
        let (layout, _, new_address) = registry
            .test_bitmap_image()
            .expect("the replacement image is now the retained capability");
        assert_eq!(layout.max_bits(), TLS_REGISTRY_EXPANSION_BITS * 2);
        assert_eq!(layout.byte_size(), 384);
        assert_ne!(new_address, old_address, "the aligned replacement is a distinct typed image");

        let released_old = leases.swap_remove(17);
        released_old
            .release()
            .expect("an old-prefix index remains explicitly releasable after copy");
        let reclaimed = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the copied old prefix retains its released free bit");
        assert_eq!(reclaimed.key().index().get(), 17);

        reclaimed.release().unwrap();
        appended.release().unwrap();
        for lease in leases {
            lease.release().unwrap();
        }
        registry.shutdown().expect("no live lease remains after explicit cleanup");
    }

    #[test]
    fn failed_first_or_expansion_allocation_preserves_bitmap_and_generation() {
        let (registry, metadata, subprocess) = fixture();
        registry.test_fail_next_bitmap_allocation();
        assert!(matches!(
            registry.test_claim_selected(config(), subprocess, metadata),
            Err(OwnedThreadLocalKeyError::Meta(MetaError::AllocationUnavailable))
        ));
        assert_eq!(
            registry.test_state(),
            (OwnedRegistryPhase::ReadyWithoutBitmap, 0, 0, None),
            "a failed first allocation neither publishes an image nor advances generation"
        );

        let mut leases = std::vec::Vec::with_capacity(TLS_REGISTRY_EXPANSION_BITS);
        for _ in 0..TLS_REGISTRY_EXPANSION_BITS {
            leases.push(
                registry
                    .test_claim_selected(config(), subprocess, metadata)
                    .expect("the retry claims the original first image"),
            );
        }
        let before = registry.test_state();
        registry.test_fail_next_bitmap_allocation();
        assert!(matches!(
            registry.test_claim_selected(config(), subprocess, metadata),
            Err(OwnedThreadLocalKeyError::Meta(MetaError::AllocationUnavailable))
        ));
        assert_eq!(
            registry.test_state(),
            before,
            "a failed expansion preserves every prior claim, image, and generation"
        );

        let released = leases.swap_remove(9);
        released.release().unwrap();
        let retry = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the retained image stays usable after failed expansion");
        assert_eq!(retry.key().index().get(), 9);
        assert_eq!(retry.key().version(), TLS_REGISTRY_EXPANSION_BITS as u64 + 1);
        retry.release().unwrap();
        for lease in leases {
            lease.release().unwrap();
        }
        registry.shutdown().unwrap();
    }

    #[test]
    fn explicit_release_reclaims_an_index_with_a_new_generation_and_stale_slot_is_null() {
        let (registry, metadata, subprocess) = fixture();
        let first = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the first key allocates");
        let first_key = first.key();
        let mut storage = [ThreadLocalSlot::EMPTY; 1];
        let mut slots = ThreadLocalSlots::new(&mut storage);
        let value = core::ptr::dangling_mut::<()>();
        slots.set(first_key, value).unwrap();
        first.release().unwrap();

        let reused = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the released lowest index is reclaimed");
        assert_eq!(reused.key().index(), first_key.index());
        assert_ne!(reused.key().version(), first_key.version());
        assert!(slots.get(reused.key()).is_null(), "a previous slot generation is stale");
        slots.set(reused.key(), value).unwrap();
        assert_eq!(slots.get(reused.key()), value);

        reused.release().unwrap();
        registry.shutdown().unwrap();
    }

    #[test]
    fn source_generation_wrap_skips_zero_exactly_at_the_48_bit_ceiling() {
        let (registry, metadata, subprocess) = fixture();
        let first = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the first bitmap initializes");
        first.release().unwrap();
        registry.test_set_last_claimed(TLS_VERSION_MAX - 1);

        let wrapped = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the released source index is reusable at the wrap edge");
        assert_eq!(wrapped.key().index().get(), 0);
        assert_eq!(wrapped.key().version(), 1);
        assert_ne!(wrapped.key().raw(), TLS_FAST_KEY_RAW);
        wrapped.release().unwrap();
        registry.shutdown().unwrap();
    }

    #[test]
    fn sixty_three_source_blocks_are_the_ceiling_and_never_attempt_a_sixty_fourth_image() {
        let (registry, metadata, subprocess) = fixture();
        let maximum = TLS_REGISTRY_MAX_BLOCKS * TLS_REGISTRY_EXPANSION_BITS;
        for expected in 0..maximum {
            let lease = registry
                .test_claim_selected(config(), subprocess, metadata)
                .expect("every representable source index is claimable once");
            assert_eq!(lease.key().index().get(), expected);
            // Model an unreleased source key without retaining a huge test
            // vector. Drop intentionally does not alter live-lease state.
            drop(lease);
        }
        assert!(matches!(
            registry.test_claim_selected(config(), subprocess, metadata),
            Err(OwnedThreadLocalKeyError::Exhausted)
        ));
        let (phase, live, version, image) = registry.test_state();
        assert_eq!(phase, OwnedRegistryPhase::Exhausted);
        assert_eq!(live, maximum);
        assert_eq!(version, maximum as u64);
        assert_eq!(image.map(|image| image.0), Some(maximum));
        assert_eq!(registry.test_bitmap_allocation_attempts(), TLS_REGISTRY_MAX_BLOCKS);
    }

    #[test]
    fn concurrent_claims_are_unique_and_explicit_releases_restore_lowest_order() {
        const THREADS: usize = 4;
        const CLAIMS_PER_THREAD: usize = 32;

        let (registry, metadata, subprocess) = fixture();
        let start = Barrier::new(THREADS + 1);
        let claimed = Barrier::new(THREADS + 1);
        let release = Barrier::new(THREADS + 1);
        let (sender, receiver) = mpsc::channel();

        thread::scope(|scope| {
            for _ in 0..THREADS {
                let worker_start = &start;
                let worker_claimed = &claimed;
                let worker_release = &release;
                let worker_sender = sender.clone();
                scope.spawn(move || {
                    worker_start.wait();
                    let mut leases = std::vec::Vec::new();
                    let mut raw = std::vec::Vec::new();
                    for _ in 0..CLAIMS_PER_THREAD {
                        let lease = registry
                            .test_claim_selected(config(), subprocess, metadata)
                            .expect("the serialized owner issues one distinct live key");
                        raw.push(lease.key().raw());
                        leases.push(lease);
                    }
                    worker_sender.send(raw).unwrap();
                    worker_claimed.wait();
                    worker_release.wait();
                    for lease in leases {
                        lease.release().unwrap();
                    }
                });
            }
            drop(sender);
            start.wait();
            let mut raw = std::vec::Vec::new();
            for _ in 0..THREADS {
                raw.extend(receiver.recv().expect("each worker reports its live keys"));
            }
            claimed.wait();
            raw.sort_unstable();
            assert!(raw.windows(2).all(|pair| pair[0] != pair[1]));
            let mut indices = raw
                .iter()
                .map(|key| key & TLS_INDEX_MASK)
                .collect::<std::vec::Vec<_>>();
            indices.sort_unstable();
            assert!(indices.windows(2).all(|pair| pair[0] != pair[1]));
            release.wait();
        });

        let reused = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("all explicit worker releases restore the bitmap");
        assert_eq!(reused.key().index().get(), 0);
        assert_eq!(
            reused.key().version(),
            (THREADS * CLAIMS_PER_THREAD + 1) as u64
        );
        reused.release().unwrap();
        registry.shutdown().unwrap();
    }

    #[test]
    fn dropping_a_lease_does_not_silently_return_its_index() {
        let (registry, metadata, subprocess) = fixture();
        let dropped = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the first key is live");
        assert_eq!(dropped.key().index().get(), 0);
        drop(dropped);
        let next = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("only a distinct available index can be claimed");
        assert_eq!(next.key().index().get(), 1);
        assert_eq!(registry.test_state().1, 2, "drop leaves both source claims live");
        drop(next);
    }

    #[test]
    fn shutdown_requires_quiescence_then_rejects_late_claim_and_release_without_bitmap_access() {
        let (registry, metadata, subprocess) = fixture();
        let lease = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("the first source key is live");
        let key = lease.key();
        assert_eq!(
            registry.shutdown(),
            Err(OwnedThreadLocalKeyError::ShutdownLiveLeases)
        );
        assert_eq!(registry.test_state().0, OwnedRegistryPhase::ReadyWithBitmap);

        lease.release().unwrap();
        registry.shutdown().expect("a quiescent registry releases its sole image");
        assert_eq!(registry.test_state(), (OwnedRegistryPhase::Shutdown, 0, 1, None));
        assert!(matches!(
            registry.test_claim_selected(config(), subprocess, metadata),
            Err(OwnedThreadLocalKeyError::Shutdown)
        ));
        assert_eq!(
            registry.test_release_raw_after_shutdown(key),
            Err(OwnedThreadLocalKeyError::Shutdown)
        );
    }

    #[test]
    fn allocator_owned_registry_does_not_install_or_export_compiler_tls_roots() {
        let (registry, metadata, subprocess) = fixture();
        let dynamic_before = crate::compiler_tls::dynamic_backing_peek();
        let fast_before = crate::compiler_tls::fast_slot_peek();
        let default_before = crate::compiler_tls::default_theap();
        let cached_before = crate::compiler_tls::cached_theap();
        let registry_address = registry as *const OwnedThreadLocalKeyRegistry as usize;

        let lease = registry
            .test_claim_selected(config(), subprocess, metadata)
            .expect("registry metadata is process-global, not compiler TLS");
        assert_ne!(registry_address, 0);
        assert_eq!(crate::compiler_tls::dynamic_backing_peek(), dynamic_before);
        assert_eq!(crate::compiler_tls::fast_slot_peek(), fast_before);
        assert_eq!(crate::compiler_tls::default_theap(), default_before);
        assert_eq!(crate::compiler_tls::cached_theap(), cached_before);

        lease.release().unwrap();
        registry.shutdown().unwrap();
    }
}
