// Copyright (c) 2023-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/arena.c:1573-1611,
// 1676-1791,1794-1871` (`mi_arenas_add`, `mi_arena_initialize`, and
// `mi_manage_os_memory_ex2`). The later automatic arena-reserve policy in
// `src/arena.c:341-406,525-569` remains intentionally absent: it needs the
// source option and fresh-page routing owners rather than a fixed substitute.

//! One process-shared, caller-selected arena backing.
//!
//! The global [`ProcessPageMapLease`] is a source root/publication owner, not
//! an arena allocator. This sidecar starts the separate source
//! `mi_manage_os_memory_ex2` boundary: it binds one caller-selected, already
//! mapped single arena to that exact map root and main-subprocess identity,
//! then retains the mapping, registry slot, and in-place metadata for process
//! lifetime. It deliberately does not reserve a mapping itself or expose a
//! general page engine. `ProcessPageArenaLease` can instead prove this exact
//! pairing for the separately bounded ticket-zero static page owner; that
//! owner alone attaches the main Heap, registers pages, and retains a scoped
//! producer lifetime.
//!
//! On a pre-publication rejection, the caller receives its [`Mapping`] back
//! through [`ProcessSharedArenaInstallFailure`]. That is deliberate: this is
//! the lower `mi_manage_os_memory_ex2` layer, whose source caller owns the
//! backing-release decision. A later `mi_reserve_os_memory_ex2` port can make
//! the source's map-then-unmap-on-manage-failure policy explicit without
//! burying it in this sidecar.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use crabc_core::Errno;

use crate::arena::{
    ArenaRegistry, ArenaView, ExternalArenaPlan, ManageArenaError, ManagedExternalRegion,
    manage_external_in_place,
};
use crate::lock::PrivateLock;
use crate::os::{Mapping, MemoryConfig};
use crate::page_map::PageMapHeader;
use crate::process_page_map::{
    ProcessPageMapError, ProcessPageMapLease, ProcessPageMapMutationLease,
};
use crate::subproc::MainSubprocess;

const COLD: u8 = 0;
const READY: u8 = 1;
const RETAINED: u8 = 2;

const PAIR_UNSET: u8 = 0;
const PAIR_SET: u8 = 1;

/// Process-static sidecar for one source-managed external arena.
///
/// `MainSubprocess` currently models only the bounded thread/static-TLD
/// fields needed by prior slices. Keeping its arena-registry group here
/// avoids claiming that it is already a full Rust layout of `mi_subproc_t`.
/// The initialization lock serializes pair selection and the one registry
/// insertion. Once READY is Release-published, the final mapping, managed
/// arena metadata, exact root identity, and registry publication are all
/// stable until a future process-shutdown/quiescence owner exists.
pub(crate) struct ProcessSharedArenaStorage {
    state: AtomicU8,
    pair_state: AtomicU8,
    initialization_lock: PrivateLock,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    subprocess: AtomicPtr<MainSubprocess>,
    page_map_root: AtomicPtr<PageMapHeader>,
    registry: ArenaRegistry,
    mapping: UnsafeCell<MaybeUninit<Mapping>>,
    managed: UnsafeCell<MaybeUninit<ManagedExternalRegion>>,
}

// SAFETY: the initialization lock serializes final-slot writes. READY is
// Release-published only after every final slot and the registry's Release
// arena publication are valid. This owner intentionally supplies neither
// mutable page-map access nor arena teardown while a lease can exist.
unsafe impl Sync for ProcessSharedArenaStorage {}

impl ProcessSharedArenaStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(COLD),
            pair_state: AtomicU8::new(PAIR_UNSET),
            initialization_lock: PrivateLock::new(),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            subprocess: AtomicPtr::new(core::ptr::null_mut()),
            page_map_root: AtomicPtr::new(core::ptr::null_mut()),
            registry: ArenaRegistry::new(core::ptr::null_mut()),
            mapping: UnsafeCell::new(MaybeUninit::uninit()),
            managed: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Returns the one process-static shared-arena owner. It stays cold until
    /// a future source-shaped fresh-arena route provides a selected mapping.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_SHARED_ARENA
    }

    /// Builds an isolated deliberately leaked process-lifetime fixture.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    /// Installs one complete, aligned source arena into this process sidecar.
    ///
    /// The caller transfers one live mapping. On every pre-publication error,
    /// the returned failure still owns exactly that mapping; it must remain
    /// live or be explicitly unmapped by the caller. Success consumes it into
    /// this process-lifetime owner. A later source reserve policy must choose
    /// the mapping size/commit mode and decide whether to unmap on failure.
    pub(crate) fn install_one_owned_external_arena(
        &'static self,
        page_map: ProcessPageMapLease,
        mapping: Mapping,
    ) -> Result<ProcessSharedArenaLease, ProcessSharedArenaInstallFailure> {
        let candidate = match ProcessArenaCandidate::from_page_map_and_mapping(page_map, &mapping) {
            Ok(candidate) => candidate,
            Err(error) => return Err(ProcessSharedArenaInstallFailure::returned(error, mapping)),
        };

        let guard = match self.initialization_lock.lock() {
            Ok(guard) => guard,
            Err(error) => {
                return Err(ProcessSharedArenaInstallFailure::returned(
                    ProcessSharedArenaError::Lock(error),
                    mapping,
                ));
            }
        };

        let attempt = match self.state.load(Ordering::Acquire) {
            COLD => self.install_cold(candidate, mapping),
            READY => ProcessSharedArenaInstallAttempt::Returned {
                error: if self.pair_matches(candidate) {
                    ProcessSharedArenaError::AlreadyInstalled
                } else {
                    ProcessSharedArenaError::PairMismatch
                },
                mapping,
            },
            RETAINED | _ => ProcessSharedArenaInstallAttempt::Returned {
                error: ProcessSharedArenaError::Retained,
                mapping,
            },
        };
        let unlock = guard.unlock();

        match (attempt, unlock) {
            (ProcessSharedArenaInstallAttempt::Ready(lease), Ok(())) => Ok(lease),
            (ProcessSharedArenaInstallAttempt::Ready(_), Err(error)) => {
                // The mapping and registry are already published. The lock's
                // atomic Release occurred before the wake failure, so the
                // only sound result is a retained, non-retryable owner.
                self.state.store(RETAINED, Ordering::Release);
                Err(ProcessSharedArenaInstallFailure::retained(
                    ProcessSharedArenaError::Lock(error),
                ))
            }
            (ProcessSharedArenaInstallAttempt::Returned { error, mapping }, Err(_)) => {
                // This lower manage boundary made no arena publication. As in
                // the page-map owner, the concrete setup/rejection error has
                // precedence over a later private-futex wake failure.
                Err(ProcessSharedArenaInstallFailure::returned(error, mapping))
            }
            (ProcessSharedArenaInstallAttempt::Returned { error, mapping }, Ok(())) => {
                Err(ProcessSharedArenaInstallFailure::returned(error, mapping))
            }
            (ProcessSharedArenaInstallAttempt::Retained(error), _) => {
                Err(ProcessSharedArenaInstallFailure::retained(error))
            }
        }
    }

    fn install_cold(
        &'static self,
        candidate: ProcessArenaCandidate,
        mapping: Mapping,
    ) -> ProcessSharedArenaInstallAttempt {
        if let Err(error) = self.bind_or_match_pair(candidate) {
            // A foreign candidate has not changed this process sidecar and
            // must not consume the valid selected pair's future retry. A
            // registry-binding failure, by contrast, means the supposedly
            // private source registry no longer has a trustworthy state.
            if error == ProcessSharedArenaError::RegistryBinding {
                self.state.store(RETAINED, Ordering::Release);
            }
            return ProcessSharedArenaInstallAttempt::Returned { error, mapping };
        }

        // SAFETY: the candidate proves the live mapping is one complete,
        // aligned single arena using the same page size as the selected map.
        // The initialization lock excludes every registry reader/writer until
        // `manage_external_in_place` has fully initialized and published it.
        let managed = unsafe {
            manage_external_in_place(
                &self.registry,
                candidate.base,
                candidate.length,
                candidate.config.page_size(),
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
            Err(error) => {
                return ProcessSharedArenaInstallAttempt::Returned {
                    error: ProcessSharedArenaError::Arena(error),
                    mapping,
                };
            }
        };

        // A validated one-arena plan cannot partially manage its backing. If
        // this invariant is ever broken by a future lower arena change, keep
        // the escaped mapping and registry slot rather than pretending an
        // unpublish/retry protocol exists.
        if !managed.is_complete() {
            // SAFETY: this is the unique success path under the initialization
            // lock. The mapping must remain live because an arena slot escaped.
            unsafe { (*self.mapping.get()).write(mapping) };
            // SAFETY: same final-slot ownership proof as the mapping write.
            unsafe { (*self.managed.get()).write(managed) };
            self.state.store(RETAINED, Ordering::Release);
            return ProcessSharedArenaInstallAttempt::Retained(
                ProcessSharedArenaError::PartialManagement,
            );
        }

        // SAFETY: `manage_external_in_place` has fully initialized and
        // Release-published the sole arena. The mapping and region now move
        // into their final process-lifetime slots before READY publication.
        unsafe { (*self.mapping.get()).write(mapping) };
        // SAFETY: same final-slot ownership proof as the mapping write.
        unsafe { (*self.managed.get()).write(managed) };
        self.state.store(READY, Ordering::Release);
        ProcessSharedArenaInstallAttempt::Ready(ProcessSharedArenaLease { storage: self })
    }

    fn bind_or_match_pair(
        &self,
        candidate: ProcessArenaCandidate,
    ) -> Result<(), ProcessSharedArenaError> {
        if self.pair_state.load(Ordering::Acquire) == PAIR_SET {
            return if self.pair_matches(candidate) {
                Ok(())
            } else {
                Err(ProcessSharedArenaError::PairMismatch)
            };
        }

        // SAFETY: the caller holds `initialization_lock`; no arena has been
        // published through this new registry, and this process-static main
        // identity remains live for every future registry lookup.
        if !unsafe {
            self.registry
                .bind_subprocess_before_publication(candidate.subprocess.as_ptr())
        } {
            return Err(ProcessSharedArenaError::RegistryBinding);
        }
        // SAFETY: pair_state is still unset under the initialization lock, so
        // no reader can observe these final fields until its Release publish.
        unsafe { (*self.config.get()).write(candidate.config) };
        self.subprocess
            .store(candidate.subprocess.as_ptr(), Ordering::Release);
        self.page_map_root
            .store(candidate.root.as_ptr(), Ordering::Release);
        self.pair_state.store(PAIR_SET, Ordering::Release);
        Ok(())
    }

    #[inline]
    fn pair_matches(&self, candidate: ProcessArenaCandidate) -> bool {
        self.pair_state.load(Ordering::Acquire) == PAIR_SET
            && self.config() == candidate.config
            && core::ptr::eq(
                self.subprocess.load(Ordering::Acquire),
                candidate.subprocess.as_ptr(),
            )
            && core::ptr::eq(
                self.page_map_root.load(Ordering::Acquire),
                candidate.root.as_ptr(),
            )
    }

    #[inline]
    fn config(&self) -> MemoryConfig {
        // SAFETY: callers first observe PAIR_SET or READY with Acquire. Both
        // states are Release-published only after this final slot is written.
        unsafe { *(*self.config.get()).assume_init_ref() }
    }

    #[inline]
    fn managed(&self) -> ManagedExternalRegion {
        // SAFETY: callers reach this only after READY Acquire observes the
        // final mapping/managed writes. No shutdown path can destroy it yet.
        unsafe { *(*self.managed.get()).assume_init_ref() }
    }

    #[cfg(test)]
    #[inline]
    fn test_state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }
}

/// A stable lease for the paired process map and one registered arena.
///
/// It intentionally offers only immutable identity/configuration and a
/// lifetime-bound [`ArenaView`]. The lease does not yield a PageMap reference,
/// a mutable arena, a Page allocator, or a remote-free producer; those would
/// falsely claim the missing page/owner-exit synchronization protocol.
#[derive(Clone, Copy)]
pub(crate) struct ProcessSharedArenaLease {
    storage: &'static ProcessSharedArenaStorage,
}

// SAFETY: this is a copyable pointer to process-static storage. It cannot
// mutate its arena or page map; individual ArenaView/PageMap operations retain
// their explicit synchronization and page-lifetime contracts.
unsafe impl Send for ProcessSharedArenaLease {}
// SAFETY: see the Send justification above.
unsafe impl Sync for ProcessSharedArenaLease {}

impl ProcessSharedArenaLease {
    /// Returns the exact Release-published page-map root paired with this
    /// arena owner.
    pub(crate) fn root(self) -> Result<NonNull<PageMapHeader>, ProcessSharedArenaError> {
        self.ensure_ready()?;
        NonNull::new(self.storage.page_map_root.load(Ordering::Acquire))
            .ok_or(ProcessSharedArenaError::Retained)
    }

    /// Returns the one frozen memory configuration shared by the map and
    /// arena mapping.
    pub(crate) fn memory_config(self) -> Result<MemoryConfig, ProcessSharedArenaError> {
        self.ensure_ready()?;
        Ok(self.storage.config())
    }

    /// Returns the selected process-main identity for the paired owners.
    pub(crate) fn subprocess(self) -> Result<&'static MainSubprocess, ProcessSharedArenaError> {
        self.ensure_ready()?;
        NonNull::new(self.storage.subprocess.load(Ordering::Acquire))
            .map(|pointer| {
                // SAFETY: pair selection stores the exact process-static
                // main identity and there is no replacement/destruction path.
                unsafe { pointer.as_ref() }
            })
            .ok_or(ProcessSharedArenaError::Retained)
    }

    /// Borrows the one fully initialized, registry-published arena.
    pub(crate) fn arena(self) -> Result<ArenaView<'static>, ProcessSharedArenaError> {
        self.ensure_ready()?;
        let arena = self.storage.managed().arena_id().as_ptr();
        // SAFETY: READY retains the backing Mapping and the registry slot for
        // process lifetime. No safe API can unmap or unregister this arena.
        unsafe { ArenaView::from_ptr(arena) }.ok_or(ProcessSharedArenaError::Retained)
    }

    #[cfg(test)]
    #[inline]
    fn registry_count(self) -> Result<usize, ProcessSharedArenaError> {
        self.ensure_ready()?;
        Ok(self.storage.registry.count())
    }

    #[inline]
    fn ensure_ready(self) -> Result<(), ProcessSharedArenaError> {
        if self.storage.state.load(Ordering::Acquire) == READY {
            Ok(())
        } else {
            Err(ProcessSharedArenaError::Retained)
        }
    }
}

/// A typed pairing of the process-global PageMap and one process-owned arena.
///
/// A raw [`PageMapHeader`] cannot prove that a fresh page's map registration,
/// arena bitmap, static Heap, and selected main subprocess belong to the same
/// process image. This lease validates those immutable identities before a
/// page-bearing owner can acquire the PageMap lifecycle lock or inspect the
/// arena. It is still not a full process-initialization witness: CPU/options,
/// detached metadata, generic thread startup, and later arena routing remain
/// separate incomplete boundaries.
#[derive(Clone, Copy)]
pub(crate) struct ProcessPageArenaLease {
    page_map: ProcessPageMapLease,
    arena: ProcessSharedArenaLease,
}

impl ProcessPageArenaLease {
    /// Joins exactly matching Release-published process map and arena owners.
    pub(crate) fn join(
        page_map: ProcessPageMapLease,
        arena: ProcessSharedArenaLease,
    ) -> Result<Self, ProcessPageArenaLeaseError> {
        let map_root = page_map.root().map_err(ProcessPageArenaLeaseError::PageMap)?;
        let arena_root = arena.root().map_err(ProcessPageArenaLeaseError::Arena)?;
        if map_root != arena_root {
            return Err(ProcessPageArenaLeaseError::RootMismatch);
        }
        let map_config = page_map
            .memory_config()
            .map_err(ProcessPageArenaLeaseError::PageMap)?;
        let arena_config = arena
            .memory_config()
            .map_err(ProcessPageArenaLeaseError::Arena)?;
        if map_config != arena_config {
            return Err(ProcessPageArenaLeaseError::ConfigurationMismatch);
        }
        let map_subprocess = page_map
            .subprocess()
            .map_err(ProcessPageArenaLeaseError::PageMap)?;
        let arena_subprocess = arena
            .subprocess()
            .map_err(ProcessPageArenaLeaseError::Arena)?;
        if !core::ptr::eq(map_subprocess.as_ptr(), arena_subprocess.as_ptr()) {
            return Err(ProcessPageArenaLeaseError::SubprocessMismatch);
        }
        Ok(Self { page_map, arena })
    }

    /// Acquires the process map's one explicit page lifecycle guard after the
    /// paired identity has been proven.
    #[inline]
    pub(crate) fn begin_page_lifecycle(
        self,
    ) -> Result<ProcessPageMapMutationLease, ProcessPageArenaLeaseError> {
        self.page_map
            .begin_page_lifecycle()
            .map_err(ProcessPageArenaLeaseError::PageMap)
    }

    /// Borrows the exact registry-published arena after pairing validation.
    #[inline]
    pub(crate) fn arena(self) -> Result<ArenaView<'static>, ProcessPageArenaLeaseError> {
        self.arena.arena().map_err(ProcessPageArenaLeaseError::Arena)
    }

    #[inline]
    pub(crate) fn memory_config(self) -> Result<MemoryConfig, ProcessPageArenaLeaseError> {
        self.page_map
            .memory_config()
            .map_err(ProcessPageArenaLeaseError::PageMap)
    }

    #[inline]
    pub(crate) fn subprocess(
        self,
    ) -> Result<&'static MainSubprocess, ProcessPageArenaLeaseError> {
        self.page_map
            .subprocess()
            .map_err(ProcessPageArenaLeaseError::PageMap)
    }
}

/// A pre-mutation mismatch while forming one process page/arena owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessPageArenaLeaseError {
    PageMap(ProcessPageMapError),
    Arena(ProcessSharedArenaError),
    RootMismatch,
    ConfigurationMismatch,
    SubprocessMismatch,
}

/// A source-manage setup failure with no new arena publication.
///
/// The mapping is returned to make its release authority explicit. Callers
/// should normally call [`Mapping::unmap`] or pass it to a higher source
/// reserve-policy owner; dropping this failure does not implicitly unmap.
#[must_use = "an arena-install failure retains or returns an explicit mapping owner"]
pub(crate) enum ProcessSharedArenaInstallFailure {
    Returned {
        error: ProcessSharedArenaError,
        mapping: Mapping,
    },
    Retained {
        error: ProcessSharedArenaError,
    },
}

impl ProcessSharedArenaInstallFailure {
    #[inline]
    fn returned(error: ProcessSharedArenaError, mapping: Mapping) -> Self {
        Self::Returned { error, mapping }
    }

    #[inline]
    fn retained(error: ProcessSharedArenaError) -> Self {
        Self::Retained { error }
    }

    #[inline]
    pub(crate) const fn error(&self) -> ProcessSharedArenaError {
        match self {
            Self::Returned { error, .. } | Self::Retained { error } => *error,
        }
    }

    /// Returns the caller-owned unpublished mapping, if setup failed before
    /// this sidecar stored it in a final slot.
    #[inline]
    pub(crate) fn into_mapping(self) -> Option<Mapping> {
        match self {
            Self::Returned { mapping, .. } => Some(mapping),
            Self::Retained { .. } => None,
        }
    }
}

/// One concrete process-shared arena setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessSharedArenaError {
    PageMap(ProcessPageMapError),
    Mapping(Errno),
    MappingPageSizeMismatch,
    InvalidOneArena,
    PairMismatch,
    AlreadyInstalled,
    RegistryBinding,
    Arena(ManageArenaError),
    PartialManagement,
    Lock(Errno),
    Retained,
}

enum ProcessSharedArenaInstallAttempt {
    Ready(ProcessSharedArenaLease),
    Returned {
        error: ProcessSharedArenaError,
        mapping: Mapping,
    },
    Retained(ProcessSharedArenaError),
}

#[derive(Clone, Copy)]
struct ProcessArenaCandidate {
    root: NonNull<PageMapHeader>,
    config: MemoryConfig,
    subprocess: &'static MainSubprocess,
    base: *mut u8,
    length: usize,
}

impl ProcessArenaCandidate {
    fn from_page_map_and_mapping(
        page_map: ProcessPageMapLease,
        mapping: &Mapping,
    ) -> Result<Self, ProcessSharedArenaError> {
        let root = page_map.root().map_err(ProcessSharedArenaError::PageMap)?;
        let config = page_map
            .memory_config()
            .map_err(ProcessSharedArenaError::PageMap)?;
        let subprocess = page_map
            .subprocess()
            .map_err(ProcessSharedArenaError::PageMap)?;
        if mapping.page_size() != config.page_size() {
            return Err(ProcessSharedArenaError::MappingPageSizeMismatch);
        }
        let base = mapping.base().map_err(ProcessSharedArenaError::Mapping)?;
        let length = mapping.length().map_err(ProcessSharedArenaError::Mapping)?;
        let Some(plan) = ExternalArenaPlan::from_address(base.addr(), length) else {
            return Err(ProcessSharedArenaError::InvalidOneArena);
        };
        if plan.prefix_bytes() != 0 || plan.total_size() != length || plan.arena_count() != 1 {
            return Err(ProcessSharedArenaError::InvalidOneArena);
        }
        Ok(Self {
            root,
            config,
            subprocess,
            base,
            length,
        })
    }
}

static PROCESS_SHARED_ARENA: ProcessSharedArenaStorage = ProcessSharedArenaStorage::new();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
    use crate::os::{MapAccess, PageSize};
    use crate::process_page_map::ProcessPageMapStorage;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn initialized_map(
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> ProcessPageMapLease {
        ProcessPageMapStorage::test_static_owner()
            .initialize(config, subprocess)
            .expect("the isolated process map initializes")
    }

    fn one_arena_mapping(config: MemoryConfig) -> Mapping {
        Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        )
        .expect("map one source-sized arena backing")
    }

    fn take_returned_mapping(
        failure: ProcessSharedArenaInstallFailure,
    ) -> (ProcessSharedArenaError, Mapping) {
        let error = failure.error();
        let mapping = failure
            .into_mapping()
            .expect("pre-publication setup returns its caller-owned mapping");
        (error, mapping)
    }

    #[test]
    fn shared_owned_arena_binds_to_the_release_published_map_and_selected_subprocess() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let root = page_map.root().unwrap();
        let mapping = one_arena_mapping(config);
        let base = mapping.base().unwrap();
        let storage = ProcessSharedArenaStorage::test_static_owner();

        let lease = match storage.install_one_owned_external_arena(page_map, mapping) {
            Ok(lease) => lease,
            Err(_) => panic!("the selected one-arena backing becomes process-owned"),
        };

        assert_eq!(lease.root().unwrap(), root);
        assert_eq!(lease.memory_config().unwrap(), config);
        assert_eq!(lease.subprocess().unwrap().as_ptr(), subprocess.as_ptr());
        assert_eq!(lease.registry_count().unwrap(), 1);
        let arena = lease.arena().unwrap();
        assert_eq!(arena.slice_start(0), Some(base));
        assert_eq!(arena.size(), Some(ARENA_MIN_SIZE));
        let pages = unsafe { arena.pages() }.expect("the main pages bitmap exists");
        assert_eq!(pages.is_clear_range(0, pages.max_bits()), Some(true));
        assert!(unsafe { page_map.page_map().unwrap().checked_lookup(base) }.is_null());
    }

    #[test]
    fn arena_setup_failure_keeps_the_global_map_ready_and_returns_its_unpublished_backing() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let root = page_map.root().unwrap();
        let storage = ProcessSharedArenaStorage::test_static_owner();
        // This is a valid one-arena region but its source memory facts require
        // a metadata commit hook. The bounded sidecar deliberately has no
        // hidden hook or policy fallback, so `mi_manage_os_memory_ex2` fails
        // before registry publication and gives the caller its map back.
        let reserved = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Reserved,
        )
        .expect("map an intentionally inaccessible arena candidate");

        let failure = match storage.install_one_owned_external_arena(page_map, reserved) {
            Ok(_) => panic!("a missing commit hook cannot become an arena"),
            Err(failure) => failure,
        };
        let (error, mut returned) = take_returned_mapping(failure);
        assert_eq!(error, ProcessSharedArenaError::Arena(ManageArenaError::CommitRequired));
        assert_eq!(storage.test_state(), COLD);
        assert_eq!(storage.registry.count(), 0);
        assert_eq!(page_map.root().unwrap(), root);

        // Pairing is now frozen to this source map/subprocess, but a foreign
        // caller must not turn that still-cold retry state into a retained
        // owner. It simply receives its own unconsumed backing again.
        let foreign_map = initialized_map(config, MainSubprocess::test_static_owner());
        let foreign_failure = match storage.install_one_owned_external_arena(
            foreign_map,
            one_arena_mapping(config),
        ) {
            Ok(_) => panic!("a foreign map cannot replace the selected cold pair"),
            Err(failure) => failure,
        };
        let (foreign_error, mut foreign_backing) = take_returned_mapping(foreign_failure);
        assert_eq!(foreign_error, ProcessSharedArenaError::PairMismatch);
        assert_eq!(storage.test_state(), COLD);
        assert_eq!(storage.registry.count(), 0);
        foreign_backing
            .unmap()
            .expect("caller releases foreign unpublished backing");
        returned.unmap().expect("caller releases rejected backing");

        let lease = match storage.install_one_owned_external_arena(page_map, one_arena_mapping(config)) {
            Ok(lease) => lease,
            Err(_) => panic!("a later complete arena can install against the same map"),
        };
        assert_eq!(lease.root().unwrap(), root);
        assert_eq!(lease.registry_count().unwrap(), 1);
    }

    #[test]
    fn foreign_map_or_subprocess_rejects_before_mapping_or_registry_mutation() {
        let config = memory_config();
        let selected_subprocess = MainSubprocess::test_static_owner();
        let selected_map = initialized_map(config, selected_subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let selected = match storage
            .install_one_owned_external_arena(selected_map, one_arena_mapping(config))
        {
            Ok(lease) => lease,
            Err(_) => panic!("establish the selected process pair"),
        };
        let root = selected.root().unwrap();
        let arena_start = selected.arena().unwrap().slice_start(0).unwrap();

        let foreign_map = initialized_map(config, MainSubprocess::test_static_owner());
        let failure = match storage.install_one_owned_external_arena(
            foreign_map,
            one_arena_mapping(config),
        ) {
            Ok(_) => panic!("a foreign process map cannot reuse this arena owner"),
            Err(failure) => failure,
        };
        let (error, mut returned) = take_returned_mapping(failure);
        assert_eq!(error, ProcessSharedArenaError::PairMismatch);
        assert_eq!(storage.test_state(), READY);
        assert_eq!(selected.root().unwrap(), root);
        assert_eq!(selected.registry_count().unwrap(), 1);
        assert_eq!(selected.arena().unwrap().slice_start(0), Some(arena_start));
        returned.unmap().expect("caller releases foreign unpublished backing");
    }

    #[test]
    fn process_page_arena_pair_rejects_a_foreign_root_before_a_page_owner_can_begin() {
        let config = memory_config();
        let first_subprocess = MainSubprocess::test_static_owner();
        let first_map = initialized_map(config, first_subprocess);
        let first_arena = match ProcessSharedArenaStorage::test_static_owner()
            .install_one_owned_external_arena(first_map, one_arena_mapping(config))
        {
            Ok(lease) => lease,
            Err(_) => panic!("the first isolated process arena publishes"),
        };

        let second_subprocess = MainSubprocess::test_static_owner();
        let second_map = initialized_map(config, second_subprocess);
        let second_arena = match ProcessSharedArenaStorage::test_static_owner()
            .install_one_owned_external_arena(second_map, one_arena_mapping(config))
        {
            Ok(lease) => lease,
            Err(_) => panic!("the second isolated process arena publishes"),
        };

        assert!(matches!(
            ProcessPageArenaLease::join(first_map, second_arena),
            Err(ProcessPageArenaLeaseError::RootMismatch)
        ));
        let paired = ProcessPageArenaLease::join(first_map, first_arena)
            .expect("only identical release-published roots form a page owner pair");
        assert_eq!(paired.subprocess().unwrap().as_ptr(), first_subprocess.as_ptr());
        assert_eq!(paired.memory_config().unwrap(), config);
        assert_eq!(second_map.subprocess().unwrap().as_ptr(), second_subprocess.as_ptr());
    }
}
