// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/subproc.c:19-88`
// (`_mi_meta_zalloc`, `_mi_meta_zalloc_aligned`, `_mi_meta_rezalloc`,
// `_mi_meta_free`, and `_mi_meta_is_meta_page`) with bootstrap ordering from
// `src/init.c:15-145,184-208`. The detached owner uses the already-portioned
// `src/arena.c`/`src/page-map.c`/`src/page.c` ordinary page lifecycle rather
// than a bespoke metadata allocator.

//! Process-lived detached metadata-theap ownership.
//!
//! Pinned mimalloc uses a statically allocated detached theap for allocator
//! control objects because normal thread initialization may itself require
//! metadata allocation. This bounded port preserves that shape: the control
//! fields and private lock are static, while the first ordinary pages come
//! from the existing direct Linux mapping, page-map, arena, and page-lifecycle
//! substrate. It does not use `alloc`, libc, public pthread APIs, compiler TLS,
//! or a separate slab/mmap-per-block algorithm.
//!
//! The metadata theap is not a thread cache. Every operation is serialized by
//! [`PrivateLock`], its source TLD identity stays `THREAD_ID_DETACHED`, and
//! its pages never enter abandonment or remote-free routing. The mapping,
//! page map, arena, bootstrap, and allocator all reside in final static slots
//! before the initialized state is Release-published; none is destroyed or
//! moved for the process lifetime.

use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crabc_core::Errno;

use crate::arena::{manage_external_in_place, ArenaId, ArenaRegistry, ArenaView};
use crate::bootstrap::{BootstrapError, ExclusiveTheapBootstrap};
use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE, MAX_VABITS};
use crate::lock::{PrivateLock, PrivateLockGuard};
use crate::os::{MapAccess, Mapping, MemoryConfig};
use crate::page_map::PageMap;
use crate::single_thread::{FreeError, SingleThreadAllocator};
use crate::size_class;
use crate::types::{LiveThreadId, MemoryId, Page};

const COLD: u8 = 0;
const READY: u8 = 1;
const FAILED: u8 = 2;

const ALLOCATION_LIVE: u8 = 0;
const ALLOCATION_MOVING: u8 = 1;
const ALLOCATION_RELEASING: u8 = 2;
const ALLOCATION_RELEASED: u8 = 3;
const ALLOCATION_REJECTED: u8 = 4;

/// One private metadata allocation error.
///
/// The engine has no `errno` policy. Callers receive a precise internal
/// outcome and must translate it at a later public boundary if one exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetaError {
    /// The direct AArch64 thread pointer was zero or not a valid live source
    /// identity, so entering the process lock would not be recursion-safe.
    InvalidEntryThread,
    /// This thread already owns the metadata lock; waiting would deadlock the
    /// source nonrecursive lock.
    RecursiveEntry,
    /// The private futex operation itself failed unexpectedly.
    Lock(Errno),
    /// The supplied immutable OS-memory observations differ from the values
    /// that created the process-lived metadata arena and page map.
    ConfigurationMismatch,
    /// A prior initialization cleanup could not release a partially owned
    /// mapping, so retrying would overwrite live process state.
    InitializationRetained,
    /// Direct OS/page-map/arena bootstrap could not complete but left no
    /// published metadata owner. A later call may retry.
    InitializationFailed,
    /// The source allocation route returned null for this request.
    AllocationUnavailable,
    /// The source alignment contract rejected this request before it reached
    /// an allocation or page publication path.
    InvalidAlignment,
    /// The allocation capability belongs to a different detached metadata
    /// owner. The capability remains live and may be retried through its
    /// recorded owner.
    ForeignOwner,
    /// A consumed or stale metadata capability was used again.
    ReleasedOrStale,
    /// The already-validated detached local free could not preserve a source
    /// page lifecycle invariant. This is not a public invalid-free policy.
    Free(FreeError),
}

/// One non-Copy, provenance-bearing metadata allocation capability.
///
/// Moving this value transfers its one private release capability. It may be
/// freed on another thread through [`MetaAllocator::free`], but callers must
/// not dereference the raw bytes concurrently with that operation. The state
/// atomically rejects a second release or a release while rezalloc owns the
/// source replacement transition. Its lifetime and recorded process-owner
/// address prevent it being released through a different detached metadata
/// theap. A later TLD/theap lifecycle owner that needs to retain metadata
/// must store and move this exact capability with its owner; it must not
/// reconstruct ownership from the raw pointer. There is deliberately no
/// raw-parts escape hatch before that lifecycle exists.
#[must_use = "metadata allocation capabilities must be released through their owning MetaAllocator"]
pub(crate) struct MetaAllocation<'owner> {
    pointer: NonNull<u8>,
    memory: MemoryId,
    requested_size: usize,
    owner: NonNull<MetaAllocator>,
    state: AtomicU8,
    _owner: PhantomData<Pin<&'owner MetaAllocator>>,
}

// SAFETY: the capability is linear and all allocator mutation is serialized
// by `MetaAllocator::lock`. Moving it to another thread transfers, rather
// than aliases, the release right. Byte access remains the caller's separate
// raw-pointer synchronization obligation.
unsafe impl Send for MetaAllocation<'_> {}

impl<'owner> MetaAllocation<'owner> {
    #[inline]
    fn new(
        owner: Pin<&'owner MetaAllocator>,
        pointer: NonNull<u8>,
        requested_size: usize,
    ) -> Self {
        Self {
            pointer,
            memory: MemoryId::malloc(pointer.as_ptr(), requested_size, true),
            requested_size,
            owner: NonNull::from(owner.get_ref()),
            state: AtomicU8::new(ALLOCATION_LIVE),
            _owner: PhantomData,
        }
    }

    #[inline]
    pub(crate) const fn pointer(&self) -> NonNull<u8> {
        self.pointer
    }

    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.memory
    }

    #[inline]
    fn claim(&self, expected: u8, next: u8) -> bool {
        self.state
            .compare_exchange(expected, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[inline]
    fn restore_live(&self) {
        self.state.store(ALLOCATION_LIVE, Ordering::Release);
    }

    #[inline]
    fn reject(&self) {
        self.state.store(ALLOCATION_REJECTED, Ordering::Release);
    }

    #[inline]
    fn release(&self) {
        self.state.store(ALLOCATION_RELEASED, Ordering::Release);
    }

    #[inline]
    fn belongs_to(&self, owner: Pin<&MetaAllocator>) -> bool {
        core::ptr::eq(self.owner.as_ptr(), owner.get_ref())
    }

    #[inline]
    fn has_consistent_malloc_provenance(&self) -> bool {
        let Some(memory) = self.memory.malloc_memory() else {
            return false;
        };
        memory.base == self.pointer.as_ptr()
            && memory.size == self.requested_size
            && self.memory.size() == Some(self.requested_size)
    }
}

/// One statically bootstrappable, process-lived metadata owner.
///
/// `Self` is `!Unpin`: after initialization, `SingleThreadAllocator` contains
/// references to the final `PageMap` and `ExclusiveTheapBootstrap` slots. Its
/// safe operations require `Pin<&'static Self>`. Pin alone only prevents a
/// move, not a destructor; the `SingleThreadAllocator` holds references to
/// these final slots and therefore needs a process-lived static address. The
/// process singleton satisfies that condition by construction.
pub(crate) struct MetaAllocator {
    lock: PrivateLock,
    active_entry_thread: AtomicUsize,
    status: AtomicU8,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    mapping: UnsafeCell<MaybeUninit<Mapping>>,
    page_map: UnsafeCell<MaybeUninit<PageMap>>,
    bootstrap: UnsafeCell<MaybeUninit<ExclusiveTheapBootstrap>>,
    allocator: UnsafeCell<MaybeUninit<SingleThreadAllocator<'static, 'static, 'static>>>,
    registry: ArenaRegistry,
    _pin: PhantomPinned,
}

// SAFETY: no safe method exposes a reference into an uninitialized slot. Once
// ready, every mutable access to the allocator/page-map/theap happens under
// `lock`; the process-lived mapping pins all raw targets. `registry` uses its
// own source atomics but is initialized and thereafter reached only beneath
// this same metadata lock in this bounded owner.
unsafe impl Sync for MetaAllocator {}

impl MetaAllocator {
    const fn new() -> Self {
        Self {
            lock: PrivateLock::new(),
            active_entry_thread: AtomicUsize::new(0),
            status: AtomicU8::new(COLD),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            mapping: UnsafeCell::new(MaybeUninit::uninit()),
            page_map: UnsafeCell::new(MaybeUninit::uninit()),
            bootstrap: UnsafeCell::new(MaybeUninit::uninit()),
            allocator: UnsafeCell::new(MaybeUninit::uninit()),
            registry: ArenaRegistry::new(core::ptr::null_mut()),
            _pin: PhantomPinned,
        }
    }

    /// Returns the one process metadata owner. Runtime integration supplies a
    /// frozen [`MemoryConfig`] before its first allocation; this accessor does
    /// not itself discover a page size or touch TLS.
    #[inline]
    pub(crate) fn global() -> Pin<&'static Self> {
        // SAFETY: this object is a process static and cannot move.
        unsafe { Pin::new_unchecked(&PROCESS_METADATA_ALLOCATOR) }
    }

    /// Allocates zeroed metadata through the detached source theap.
    pub(crate) fn zalloc(
        self: Pin<&'static Self>,
        config: MemoryConfig,
        size: usize,
    ) -> Result<MetaAllocation<'static>, MetaError> {
        let mut entry = self.enter()?;
        entry.ensure_ready(config)?;
        let pointer = entry
            .allocator()
            .allocate_zeroed(size)
            .ok_or(MetaError::AllocationUnavailable)?;
        Ok(MetaAllocation::new(self, pointer, size))
    }

    /// Allocates zeroed metadata with the source alignment contract.
    pub(crate) fn zalloc_aligned(
        self: Pin<&'static Self>,
        config: MemoryConfig,
        size: usize,
        alignment: usize,
    ) -> Result<MetaAllocation<'static>, MetaError> {
        if !size_class::alignment_is_valid(alignment) {
            return Err(MetaError::InvalidAlignment);
        }
        let mut entry = self.enter()?;
        entry.ensure_ready(config)?;
        let pointer = entry
            .allocator()
            .allocate_aligned_zeroed(size, alignment)
            .ok_or(MetaError::AllocationUnavailable)?;
        Ok(MetaAllocation::new(self, pointer, size))
    }

    /// Replaces a metadata allocation with a zeroed one.
    ///
    /// The replacement is allocated while holding the metadata lock. On
    /// allocation failure `old` remains live and is returned unchanged through
    /// its mutable capability. On success this method drops the lock before
    /// copying and before freeing `old`, exactly avoiding the source's
    /// `_mi_meta_rezalloc` recursive-lock hazard.
    pub(crate) fn rezalloc(
        self: Pin<&'static Self>,
        config: MemoryConfig,
        old: Option<&mut MetaAllocation<'static>>,
        new_size: usize,
    ) -> Result<MetaAllocation<'static>, MetaError> {
        let Some(old) = old else {
            return self.zalloc(config, new_size);
        };
        if !old.belongs_to(self) {
            return Err(MetaError::ForeignOwner);
        }

        let (replacement, copy_size) = {
            let mut entry = self.enter()?;
            entry.ensure_ready(config)?;
            if !old.claim(ALLOCATION_LIVE, ALLOCATION_MOVING)
                || !old.has_consistent_malloc_provenance()
            {
                old.reject();
                return Err(MetaError::ReleasedOrStale);
            }
            let old_usable = match unsafe { entry.allocator().usable_size(old.pointer) } {
                Some(size) => size,
                None => {
                    old.reject();
                    return Err(MetaError::ReleasedOrStale);
                }
            };
            let Some(pointer) = entry.allocator().allocate_zeroed(new_size) else {
                old.restore_live();
                return Err(MetaError::AllocationUnavailable);
            };
            (MetaAllocation::new(self, pointer, new_size), new_size.min(old_usable))
        };

        // SAFETY: `old` is in MOVING state under its exclusive mutable
        // capability; no safe metadata operation can free it. `replacement`
        // has not escaped this method. The source copy extent is bounded by
        // the validated old usable size and requested replacement size.
        unsafe {
            core::ptr::copy_nonoverlapping(
                old.pointer.as_ptr(),
                replacement.pointer.as_ptr(),
                copy_size,
            );
        }

        old.state.store(ALLOCATION_RELEASING, Ordering::Release);
        if let Err(error) = self.release_claimed(old) {
            // The old block was fully validated while held exclusively, so a
            // free failure is an internal lifecycle fault. Retire the private
            // replacement before reporting it rather than leaking an
            // unpublishable allocation; both operations remain serialized.
            let mut replacement = replacement;
            replacement.state.store(ALLOCATION_RELEASING, Ordering::Release);
            let _cleanup = self.release_claimed(&mut replacement);
            old.reject();
            return Err(error);
        }
        old.release();
        Ok(replacement)
    }

    /// Releases one metadata allocation under the detached owner lock.
    pub(crate) fn free(
        self: Pin<&'static Self>,
        allocation: &mut MetaAllocation<'static>,
    ) -> Result<(), MetaError> {
        if !allocation.belongs_to(self) {
            return Err(MetaError::ForeignOwner);
        }
        if !allocation.claim(ALLOCATION_LIVE, ALLOCATION_RELEASING)
            || !allocation.has_consistent_malloc_provenance()
        {
            allocation.reject();
            return Err(MetaError::ReleasedOrStale);
        }
        match self.release_claimed(allocation) {
            Ok(()) => {
                allocation.release();
                Ok(())
            }
            Err(error) => {
                allocation.reject();
                Err(error)
            }
        }
    }

    /// Implements the source `_mi_meta_is_meta_page` identity check.
    ///
    /// Like the source, this is only a raw comparison of the readable
    /// `page->theap` field against the process-stable metadata-theap address.
    /// It neither dereferences that target nor proves an abandoned page's
    /// lifetime; callers retain the normal readable-page precondition.
    pub(crate) fn is_metadata_page(
        self: Pin<&'static Self>,
        page: &Page,
    ) -> Result<bool, MetaError> {
        let entry = self.enter()?;
        if entry.status() != READY {
            return Ok(false);
        }
        Ok(page.theap() == entry.allocator_ref().theap_identity())
    }

    fn enter(self: Pin<&'static Self>) -> Result<MetaEntry, MetaError> {
        let thread = current_entry_thread()?;
        let this = self.get_ref();
        if this.active_entry_thread.load(Ordering::Acquire) == thread {
            return Err(MetaError::RecursiveEntry);
        }
        let guard = this.lock.lock().map_err(MetaError::Lock)?;
        if this.active_entry_thread.load(Ordering::Acquire) == thread {
            drop(guard);
            return Err(MetaError::RecursiveEntry);
        }
        this.active_entry_thread.store(thread, Ordering::Release);
        Ok(MetaEntry {
            owner: self,
            entry_thread: thread,
            guard: Some(guard),
        })
    }

    fn release_claimed(
        self: Pin<&'static Self>,
        allocation: &mut MetaAllocation<'static>,
    ) -> Result<(), MetaError> {
        let mut entry = self.enter()?;
        if entry.status() != READY || !allocation.has_consistent_malloc_provenance() {
            return Err(MetaError::ReleasedOrStale);
        }
        // SAFETY: the allocation capability is RELEASING or MOVING and the
        // metadata lock excludes every other allocator/page-map mutation.
        unsafe { entry.allocator().free(allocation.pointer) }.map_err(MetaError::Free)
    }

    fn initialize(
        self: Pin<&'static Self>,
        entry: &mut MetaEntry,
        config: MemoryConfig,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        let page_map = match PageMap::initialize(config, MAX_VABITS, false) {
            Ok(page_map) => page_map,
            Err(_) => return Err(MetaError::InitializationFailed),
        };
        // SAFETY: `entry` owns the sole initialization lock and COLD prevents
        // any reader from projecting this final static slot.
        unsafe { (*this.page_map.get()).write(page_map) };

        let mapping = match Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        ) {
            Ok(mapping) => mapping,
            Err(_) => return self.cleanup_page_map_after_failed_init(),
        };
        // SAFETY: same COLD/lock proof as the page-map slot above.
        unsafe { (*this.mapping.get()).write(mapping) };
        // SAFETY: the preceding in-place write initialized this unique mapping
        // owner and the metadata lock excludes all other projection.
        let mapping = unsafe { (&mut *this.mapping.get()).assume_init_mut() };
        let base = match mapping.base() {
            Ok(base) => base,
            Err(_) => return self.cleanup_mapping_and_page_map_after_failed_init(),
        };
        let length = match mapping.length() {
            Ok(length) => length,
            Err(_) => return self.cleanup_mapping_and_page_map_after_failed_init(),
        };
        let managed = unsafe {
            manage_external_in_place(
                &this.registry,
                base,
                length,
                config.page_size(),
                mapping.initially_committed(),
                false,
                mapping.initially_zero(),
                -1,
                false,
                None,
            )
        };
        let managed = match managed {
            Ok(managed) => managed,
            Err(_) => return self.cleanup_mapping_and_page_map_after_failed_init(),
        };
        let arena = match unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) } {
            Some(arena) if managed.is_complete() => arena,
            _ => {
                this.status.store(FAILED, Ordering::Release);
                return Err(MetaError::InitializationRetained);
            }
        };

        // SAFETY: the static slot is the final address used by the detached
        // theap's self references. It cannot move because callers hold Pin.
        unsafe { (*this.bootstrap.get()).write(ExclusiveTheapBootstrap::new()) };
        let bootstrap = unsafe { Pin::new_unchecked((&mut *this.bootstrap.get()).assume_init_mut()) };
        let page_map = unsafe { (&mut *this.page_map.get()).assume_init_mut() };
        let allocator = match SingleThreadAllocator::activate_detached(
            bootstrap,
            arena,
            ArenaId::none(),
            page_map,
            0,
        ) {
            Ok(allocator) => allocator,
            Err(BootstrapError::AlreadyInitialized | BootstrapError::InvalidThreadState) => {
                this.status.store(FAILED, Ordering::Release);
                return Err(MetaError::InitializationRetained);
            }
        };
        // SAFETY: every reference captured by `allocator` names one prior
        // final static slot. No operation can observe it before READY.
        unsafe { (*this.allocator.get()).write(allocator) };
        unsafe { (*this.config.get()).write(config) };
        this.status.store(READY, Ordering::Release);
        let _ = entry;
        Ok(())
    }

    fn cleanup_page_map_after_failed_init(self: Pin<&'static Self>) -> Result<(), MetaError> {
        let this = self.get_ref();
        // SAFETY: the unshared page map was written in COLD state and no root
        // or allocator can reach it. Successful destroy releases all direct
        // mappings before a retry may overwrite this inert slot.
        match unsafe { (&mut *this.page_map.get()).assume_init_mut().destroy() } {
            Ok(()) => Err(MetaError::InitializationFailed),
            Err(_) => {
                this.status.store(FAILED, Ordering::Release);
                Err(MetaError::InitializationRetained)
            }
        }
    }

    fn cleanup_mapping_and_page_map_after_failed_init(
        self: Pin<&'static Self>,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        // SAFETY: failure happened before the arena was registry-published;
        // the mapping is private to this COLD initialization attempt.
        let mapping_result = unsafe { (&mut *this.mapping.get()).assume_init_mut().unmap() };
        let page_map_result = unsafe { (&mut *this.page_map.get()).assume_init_mut().destroy() };
        if mapping_result.is_ok() && page_map_result.is_ok() {
            Err(MetaError::InitializationFailed)
        } else {
            this.status.store(FAILED, Ordering::Release);
            Err(MetaError::InitializationRetained)
        }
    }
}

/// A held metadata private lock and its exclusive initialized-state access.
struct MetaEntry {
    owner: Pin<&'static MetaAllocator>,
    entry_thread: usize,
    guard: Option<PrivateLockGuard<'static>>,
}

impl MetaEntry {
    fn ensure_ready(&mut self, config: MemoryConfig) -> Result<(), MetaError> {
        match self.status() {
            READY => {
                // SAFETY: READY release-publishes this initialized immutable
                // configuration before any later lock holder can read it.
                let stored = unsafe { self.owner.get_ref().config.get().read().assume_init() };
                if stored == config {
                    Ok(())
                } else {
                    Err(MetaError::ConfigurationMismatch)
                }
            }
            COLD => self.owner.initialize(self, config),
            FAILED => Err(MetaError::InitializationRetained),
            _ => Err(MetaError::InitializationRetained),
        }
    }

    #[inline]
    fn status(&self) -> u8 {
        self.owner.get_ref().status.load(Ordering::Acquire)
    }

    #[inline]
    fn allocator(&mut self) -> &mut SingleThreadAllocator<'static, 'static, 'static> {
        // SAFETY: READY plus this held private lock gives exclusive mutation
        // of the final static allocator slot.
        unsafe { (&mut *self.owner.get_ref().allocator.get()).assume_init_mut() }
    }

    #[inline]
    fn allocator_ref(&self) -> &SingleThreadAllocator<'static, 'static, 'static> {
        // SAFETY: see `allocator`; this shared projection is used only for
        // source pointer identity while the same metadata lock is held.
        unsafe { (&*self.owner.get_ref().allocator.get()).assume_init_ref() }
    }
}

impl Drop for MetaEntry {
    fn drop(&mut self) {
        // Unlock before clearing the recursion marker. Clearing first would
        // let same-thread signal reentry miss the marker and wait forever on
        // this still-held nonrecursive lock. A different thread may acquire
        // and replace the marker between these operations, so cleanup uses a
        // compare-exchange and must not erase that successor's ownership.
        drop(self.guard.take());
        clear_entry_thread_after_unlock(
            &self.owner.get_ref().active_entry_thread,
            self.entry_thread,
        );
    }
}

#[inline]
fn clear_entry_thread_after_unlock(active: &AtomicUsize, entry_thread: usize) {
    let _ = active.compare_exchange(
        entry_thread,
        0,
        Ordering::Release,
        Ordering::Relaxed,
    );
}

#[inline]
fn current_entry_thread() -> Result<usize, MetaError> {
    let thread = crate::os::thread_pointer_identity();
    LiveThreadId::new(thread)
        .map(LiveThreadId::get)
        .ok_or(MetaError::InvalidEntryThread)
}

static PROCESS_METADATA_ALLOCATOR: MetaAllocator = MetaAllocator::new();

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::os::{fault, PageSize};
    use crate::types::MemoryKind;

    fn config() -> MemoryConfig {
        let page_size = PageSize::new(4096).unwrap();
        MemoryConfig::from_observations(page_size, 1024 * 1024, false, false)
    }

    /// Test-only process lifetime mirrors the production static singleton:
    /// the detached engine stores `'static` references into its final slots.
    fn static_allocator() -> Pin<&'static MetaAllocator> {
        let allocator: &'static MetaAllocator =
            std::boxed::Box::leak(std::boxed::Box::new(MetaAllocator::new()));
        // SAFETY: `Box::leak` gives this test fixture a true process-lifetime
        // address, and `MetaAllocator` is never moved after construction.
        unsafe { Pin::new_unchecked(allocator) }
    }

    #[test]
    fn zero_and_aligned_zero_metadata_has_malloc_provenance() {
        let allocator = static_allocator();
        let mut block = allocator.zalloc(config(), 91).unwrap();
        let aligned = allocator.zalloc_aligned(config(), 47, 4096).unwrap();

        assert_eq!(block.memory_id().kind(), MemoryKind::Malloc);
        assert!(block.memory_id().is_pinned());
        assert!(block.memory_id().initially_committed());
        assert!(block.memory_id().initially_zero());
        assert_eq!(block.memory_id().size(), Some(91));
        assert_eq!(aligned.pointer().as_ptr().addr() & 4095, 0);
        // SAFETY: this fresh metadata capability owns 91 initialized bytes.
        assert!(unsafe { core::slice::from_raw_parts(block.pointer().as_ptr(), 91) }
            .iter()
            .all(|byte| *byte == 0));
        assert!(allocator.free(&mut block).is_ok());
        let mut aligned = aligned;
        assert!(allocator.free(&mut aligned).is_ok());
    }

    #[test]
    fn invalid_alignment_does_not_initialize_or_publish_metadata_state() {
        let allocator = static_allocator();
        assert!(matches!(
            allocator.zalloc_aligned(config(), 8, 3),
            Err(MetaError::InvalidAlignment)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), COLD);
    }

    #[test]
    fn map_and_commit_failure_leave_the_owner_retryable_and_unpublished() {
        let allocator = static_allocator();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), COLD);
        fault.set(fault::Plan::at(fault::Point::Map, 2, Errno::NOMEM));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        assert_eq!(fault.observed(), 2, "the second map is the metadata arena");
        assert_eq!(allocator.status.load(Ordering::Acquire), COLD);
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), COLD);
        fault.set(fault::Plan::disabled());
        let mut retry = allocator.zalloc(config(), 8).unwrap();
        allocator.free(&mut retry).unwrap();
    }

    #[test]
    fn failed_arena_cleanup_retains_the_static_owner_and_rejects_retry() {
        let allocator = static_allocator();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Map,
            2,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationRetained)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), FAILED);
        fault.set(fault::Plan::disabled());
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationRetained)
        ));
    }

    #[test]
    fn rezalloc_failure_preserves_old_and_success_copies_then_releases_it() {
        let allocator = static_allocator();
        let mut old = allocator.zalloc(config(), 32).unwrap();
        // SAFETY: `old` is a current exclusive metadata capability.
        unsafe { core::ptr::write_bytes(old.pointer().as_ptr(), 0x5a, 32) };
        assert!(matches!(
            allocator.rezalloc(config(), Some(&mut old), usize::MAX),
            Err(MetaError::AllocationUnavailable)
        ));
        // SAFETY: the failed replacement retained the old current block.
        assert!(unsafe { core::slice::from_raw_parts(old.pointer().as_ptr(), 32) }
            .iter()
            .all(|byte| *byte == 0x5a));

        let mut replacement = allocator.rezalloc(config(), Some(&mut old), 96).unwrap();
        // SAFETY: replacement owns 96 requested bytes, and the source copy
        // preserves the old 32-byte initialized prefix.
        assert!(unsafe { core::slice::from_raw_parts(replacement.pointer().as_ptr(), 32) }
            .iter()
            .all(|byte| *byte == 0x5a));
        assert_eq!(allocator.free(&mut old), Err(MetaError::ReleasedOrStale));
        allocator.free(&mut replacement).unwrap();
    }

    #[test]
    fn released_capability_rejects_double_release_and_metadata_page_identity() {
        let allocator = static_allocator();
        let mut block = allocator.zalloc(config(), 8).unwrap();
        let page = {
            let entry = allocator.enter().unwrap();
            // SAFETY: the held private lock excludes page-map mutation and
            // block is a current allocation from this exact metadata owner.
            unsafe { entry.allocator_ref().page_for_block(block.pointer()) }
        };
        let page = unsafe { page.as_ref() }.unwrap();
        assert!(allocator.is_metadata_page(page).unwrap());
        allocator.free(&mut block).unwrap();
        assert_eq!(allocator.free(&mut block), Err(MetaError::ReleasedOrStale));
    }

    #[test]
    fn foreign_owner_rejection_preserves_the_live_metadata_capability() {
        let owner = static_allocator();
        let foreign = static_allocator();
        let mut block = owner.zalloc(config(), 32).unwrap();

        assert_eq!(foreign.free(&mut block), Err(MetaError::ForeignOwner));
        assert!(matches!(
            foreign.rezalloc(config(), Some(&mut block), 64),
            Err(MetaError::ForeignOwner)
        ));
        // The foreign owner did not claim or retire `block`; its actual owner
        // can still replace and then release it.
        let mut replacement = owner.rezalloc(config(), Some(&mut block), 64).unwrap();
        owner.free(&mut replacement).unwrap();
    }

    #[test]
    fn configuration_mismatch_does_not_disturb_ready_metadata_state() {
        let allocator = static_allocator();
        let mut block = allocator.zalloc(config(), 8).unwrap();
        let different_page_size = PageSize::new(16 * 1024).unwrap();
        let different = MemoryConfig::from_observations(
            different_page_size,
            1024 * 1024,
            false,
            false,
        );
        assert!(matches!(
            allocator.zalloc(different, 8),
            Err(MetaError::ConfigurationMismatch)
        ));
        allocator.free(&mut block).unwrap();
    }

    #[test]
    fn recursive_metadata_entry_is_rejected_without_waiting() {
        let allocator = static_allocator();
        let entry = allocator.enter().unwrap();
        assert!(matches!(
            allocator.enter(),
            Err(MetaError::RecursiveEntry)
        ));
        drop(entry);
    }

    #[test]
    fn entry_cleanup_does_not_erase_a_successor_marker() {
        let marker = AtomicUsize::new(24);
        clear_entry_thread_after_unlock(&marker, 12);
        assert_eq!(marker.load(Ordering::Acquire), 24);
        clear_entry_thread_after_unlock(&marker, 24);
        assert_eq!(marker.load(Ordering::Acquire), 0);
    }

    #[test]
    fn private_lock_serializes_concurrent_detached_allocations() {
        let allocator = static_allocator();
        let barrier = Arc::new(Barrier::new(5));
        let completed = Arc::new(AtomicUsize::new(0));
        thread::scope(|scope| {
            for _ in 0..4 {
                let barrier = Arc::clone(&barrier);
                let completed = Arc::clone(&completed);
                scope.spawn(move || {
                    barrier.wait();
                    let mut block = allocator.zalloc(config(), 64).unwrap();
                    allocator.free(&mut block).unwrap();
                    completed.fetch_add(1, Ordering::Release);
                });
            }
            barrier.wait();
        });
        assert_eq!(completed.load(Ordering::Acquire), 4);
    }

    #[test]
    fn cross_thread_free_uses_the_private_metadata_lock() {
        let allocator = static_allocator();
        let block = allocator.zalloc(config(), 64).unwrap();
        thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let mut block = block;
                allocator.free(&mut block)
            });
            assert!(worker.join().unwrap().is_ok());
        });
    }

    #[test]
    fn static_global_metadata_allocation_leaves_compiler_tls_roots_unchanged() {
        let dynamic_before = crate::compiler_tls::dynamic_backing_peek();
        let fast_before = crate::compiler_tls::fast_slot_peek();
        let default_before = crate::compiler_tls::default_theap();
        let cached_before = crate::compiler_tls::cached_theap();

        let allocator = MetaAllocator::global();
        let mut block = allocator.zalloc(config(), 8).unwrap();
        allocator.free(&mut block).unwrap();

        assert_eq!(crate::compiler_tls::dynamic_backing_peek(), dynamic_before);
        assert_eq!(crate::compiler_tls::fast_slot_peek(), fast_before);
        assert_eq!(crate::compiler_tls::default_theap(), default_before);
        assert_eq!(crate::compiler_tls::cached_theap(), cached_before);
    }
}
