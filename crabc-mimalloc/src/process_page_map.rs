// Copyright (c) 2023-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page-map.c:228-365`
// (`mi_page_map_init_once` and `_mi_page_map_init`) and
// `src/subproc.c:253-255` (the main-subprocess process-lifetime ownership of
// the global page map).

//! Process-owned publication of the global source page map.
//!
//! The mapped [`PageMap`] mechanics deliberately live in `page_map.rs`; this
//! module owns the missing process-wide state around them.  It initializes one
//! source-shaped global map from a frozen [`MemoryConfig`], binds it to one
//! selected [`MainSubprocess`], and Release-publishes its header through a
//! [`PageMapRoot`].  The returned lease is only a stable-root witness.  It
//! gives no page lifetime, arena, producer, or thread-exit authority, and the
//! map is process-lived until a future complete main-subprocess shutdown can
//! clear readers and destroy it.  The C static `mi_page_map_empty` pre-root is
//! deliberately not exposed yet: no Rust runtime lookup/free path may enter
//! this owner while it is cold.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use crabc_core::Errno;

use crate::lock::{PrivateLock, PrivateLockGuard};
use crate::os::MemoryConfig;
use crate::page_map::{PageMap, PageMapHeader, PageMapRoot};
use crate::subproc::MainSubprocess;

const COLD: u8 = 0;
const READY: u8 = 1;
const POISONED: u8 = 2;

/// Process-static storage for the one main-subprocess global page map.
///
/// The `PageMap` lives in its final slot before its root is published.  The
/// storage has no destruction entry point: `src/subproc.c` may destroy the
/// global map only as part of main-subprocess destruction, which is not yet a
/// completed lifecycle in this port.  That deliberate process lifetime makes
/// a published lease safe to copy without turning a raw page pointer into an
/// owner.
pub(crate) struct ProcessPageMapStorage {
    state: AtomicU8,
    initialization_lock: PrivateLock,
    /// Rust-side exclusive lifecycle boundary for the source page map's
    /// plain entry reads and writes. This is deliberately separate from
    /// initialization and from the source map's individual submap locks: one
    /// bounded page engine holds it for its complete owner/producer lifetime
    /// so it cannot manufacture a second mutable PageMap route.
    page_lifecycle_lock: PrivateLock,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    subprocess: AtomicPtr<MainSubprocess>,
    page_map: UnsafeCell<MaybeUninit<PageMap>>,
    root: PageMapRoot,
}

// SAFETY: `initialization_lock` serializes every write to the final slots.
// READY is Release-published only after the initialized map/header/config and
// root are all valid.  The `PageMap` itself retains its documented source
// plain-entry synchronization contract; this storage does not claim to
// serialize registration or lookup.  The process lifetime forbids a safe
// concurrent destroy while a lease or root reader can exist.
unsafe impl Sync for ProcessPageMapStorage {}

impl ProcessPageMapStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(COLD),
            initialization_lock: PrivateLock::new(),
            page_lifecycle_lock: PrivateLock::new(),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            subprocess: AtomicPtr::new(core::ptr::null_mut()),
            page_map: UnsafeCell::new(MaybeUninit::uninit()),
            root: PageMapRoot::empty(),
        }
    }

    /// Returns the process-static source owner.  It stays cold until a future
    /// runtime startup path supplies its frozen memory configuration and
    /// selected main-subprocess identity.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_PAGE_MAP
    }

    /// Builds a deliberately leaked process-lifetime storage fixture.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    /// Initializes or obtains the process-global map for `subprocess`.
    ///
    /// The source default `mi_option_max_vabits == 0` is passed as the
    /// configured value, so [`PageMap::initialize`] observes the frozen
    /// Linux/AArch64 virtual-address width.  Option parsing and process
    /// shutdown are intentionally separate future boundaries.
    pub(crate) fn initialize(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessPageMapLease, ProcessPageMapError> {
        // Source `_mi_atomic_once_enter` has a completed fast path.  Preserve
        // that no-lock read for the common process-ready case; a cold caller
        // still takes the private lock so only one final slot can be formed.
        if self.state.load(Ordering::Acquire) == READY {
            return self.lease_if_matches(config, subprocess);
        }
        let guard = self
            .initialization_lock
            .lock()
            .map_err(ProcessPageMapError::Lock)?;

        let result = match self.state.load(Ordering::Acquire) {
            COLD => self.initialize_cold(config, subprocess),
            READY => self.lease_if_matches(config, subprocess),
            POISONED | _ => Err(ProcessPageMapError::Poisoned),
        };
        let unlock = guard.unlock();

        match (result, unlock) {
            (Ok(lease), Ok(())) => Ok(lease),
            (Ok(_), Err(error)) => {
                // The map/root are already published.  A private-futex wake
                // failure has no source equivalent and cannot safely be
                // retried as if initialization had remained private.
                self.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
            (Err(error), Err(_)) => {
                // The source-shaped map attempt determines the observable
                // outcome before a later private-futex wake failure. The
                // atomic unlock has already occurred either way, and no root
                // was published on this branch.
                Err(error)
            }
            (Err(error), Ok(())) => Err(error),
        }
    }

    fn initialize_cold(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessPageMapLease, ProcessPageMapError> {
        let page_map = match PageMap::initialize(config, 0, false) {
            Ok(page_map) => page_map,
            Err(error) => {
                // `_mi_page_map_init` runs its body through source
                // `mi_atomic_do_once`: an initialization attempt is never
                // replayed.  We retain that once-only transition but report a
                // durable explicit error instead of letting a later caller
                // mistake an unpublished Rust root for C's static empty map.
                self.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Initialization(error));
            }
        };
        // SAFETY: the initialization lock is held, COLD excludes every
        // reader, and this process-static slot is the page map's final
        // address.  `page_map` has not yet been published through `root`.
        unsafe { (*self.page_map.get()).write(page_map) };
        // SAFETY: same exclusive COLD-state publication proof as the map.
        unsafe { (*self.config.get()).write(config) };
        self.subprocess.store(subprocess.as_ptr(), Ordering::Release);

        // SAFETY: the map was fully initialized in its final slot and is
        // process-lived.  The Release root publication makes its initialized
        // header visible to later Acquire readers.
        unsafe { self.root.publish(self.page_map_ref()) };
        self.state.store(READY, Ordering::Release);
        Ok(ProcessPageMapLease { storage: self })
    }

    fn lease_if_matches(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessPageMapLease, ProcessPageMapError> {
        let stored_config = self.config();
        if stored_config != config {
            return Err(ProcessPageMapError::ConfigurationMismatch);
        }
        if !core::ptr::eq(self.subprocess.load(Ordering::Acquire), subprocess.as_ptr()) {
            return Err(ProcessPageMapError::SubprocessMismatch);
        }
        if self.root.load().is_none() {
            self.state.store(POISONED, Ordering::Release);
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(ProcessPageMapLease { storage: self })
    }

    #[inline]
    fn config(&self) -> MemoryConfig {
        // SAFETY: callers reach this only in READY state, whose Release store
        // follows the final-slot write and is observed under the
        // initialization lock or with an Acquire state check.
        unsafe { *(*self.config.get()).assume_init_ref() }
    }

    #[inline]
    fn page_map_ref(&'static self) -> &'static PageMap {
        // SAFETY: the page-map slot is initialized before root/READY
        // publication and is never destroyed by this bounded process owner.
        unsafe { (*self.page_map.get()).assume_init_ref() }
    }
}

/// A stable process-global page-map root witness.
///
/// This capability is Send/Sync because it only names process-static storage;
/// callers must separately uphold [`PageMap`]'s explicit synchronization and
/// page-lifetime requirements before registering, unregistering, or looking
/// up a page.
#[derive(Clone, Copy)]
pub(crate) struct ProcessPageMapLease {
    storage: &'static ProcessPageMapStorage,
}

// SAFETY: the lease contains one process-static address. It cannot mutate the
// map or bypass PageMap's own unsafe range and lifetime contracts.
unsafe impl Send for ProcessPageMapLease {}
// SAFETY: see the Send justification above.
unsafe impl Sync for ProcessPageMapLease {}

impl ProcessPageMapLease {
    /// Returns the published source root after confirming the process owner
    /// remains live.
    pub(crate) fn root(self) -> Result<NonNull<PageMapHeader>, ProcessPageMapError> {
        self.ensure_ready()?;
        self.storage.root.load().ok_or(ProcessPageMapError::Poisoned)
    }

    /// Returns the frozen memory configuration of the process page map.
    #[inline]
    pub(crate) fn memory_config(self) -> Result<MemoryConfig, ProcessPageMapError> {
        self.ensure_ready()?;
        if self.storage.root.load().is_none() {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.config())
    }

    /// Starts the one explicit mutable PageMap lifecycle for this process
    /// root.
    ///
    /// The returned capability owns the Rust aliasing/quiescence boundary for
    /// the source map's plain entries. It is intentionally nonblocking: a
    /// second page-bearing owner, including accidental same-thread reentry,
    /// is an unsupported lifecycle conflict rather than a new recursive map
    /// protocol. A caller that drops this capability before finishing its page
    /// engine poisons the bounded process owner so no later route can mistake
    /// retained entries for an empty map.
    pub(crate) fn begin_page_lifecycle(
        self,
    ) -> Result<ProcessPageMapMutationLease, ProcessPageMapError> {
        self.ensure_ready()?;
        let guard = self
            .storage
            .page_lifecycle_lock
            .try_lock()
            .ok_or(ProcessPageMapError::LifecycleBusy)?;
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                self.storage.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Lock(error));
            }
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(ProcessPageMapMutationLease {
            storage: self.storage,
            guard: Some(guard),
        })
    }

    /// Borrows the process-lived page map for isolated crate tests.
    ///
    /// This does not give ownership of any entry or page.  All `PageMap`
    /// caller obligations remain in force, including synchronization of plain
    /// overlapping entry accesses and retaining a registered page until its
    /// matching unregister operation.
    #[cfg(test)]
    pub(crate) fn page_map(self) -> Result<&'static PageMap, ProcessPageMapError> {
        self.ensure_ready()?;
        if self.storage.root.load().is_none() {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.page_map_ref())
    }

    /// Returns the final map only for an isolated terminal-owner regression.
    ///
    /// Unlike [`Self::page_map`], this may inspect a Release-published map
    /// after an unfinished page lifecycle poisoned the outer owner. It never
    /// makes that map reusable: test callers must retain the same exclusive
    /// fixture and use it only to prove that the terminal path did not erase
    /// a still-live registration.
    #[cfg(test)]
    pub(crate) fn test_retained_page_map(self) -> Option<&'static PageMap> {
        match self.storage.state.load(Ordering::Acquire) {
            READY | POISONED if self.storage.root.load().is_some() => {
                Some(self.storage.page_map_ref())
            }
            _ => None,
        }
    }

    /// Returns the exact process-main identity which owns this global map.
    #[inline]
    pub(crate) fn subprocess(self) -> Result<&'static MainSubprocess, ProcessPageMapError> {
        self.ensure_ready()?;
        let pointer = self.storage.subprocess.load(Ordering::Acquire);
        NonNull::new(pointer)
            .map(|pointer| {
                // SAFETY: READY publication stores exactly the process-static
                // subprocess supplied to initialization; it has process
                // lifetime and is never replaced by this owner.
                unsafe { pointer.as_ref() }
            })
            .ok_or(ProcessPageMapError::Poisoned)
    }

    #[inline]
    fn ensure_ready(self) -> Result<(), ProcessPageMapError> {
        if self.storage.state.load(Ordering::Acquire) == READY {
            Ok(())
        } else {
            Err(ProcessPageMapError::Poisoned)
        }
    }
}

/// One exclusive, process-root PageMap mutation lifetime.
///
/// The capability deliberately exposes only the shared `PageMap` view needed
/// by the existing source page engine. Its held private lock is the proof that
/// engine-internal unsafe registration, lookup, and unregistration have no
/// competing plain-entry access. A scoped remote producer may outlive an
/// individual engine call, but the owning engine retains this capability until
/// that producer joins and the complete lifecycle finishes.
#[must_use = "a process PageMap mutation lease must finish or retain its owner explicitly"]
pub(crate) struct ProcessPageMapMutationLease {
    storage: &'static ProcessPageMapStorage,
    guard: Option<PrivateLockGuard<'static>>,
}

impl ProcessPageMapMutationLease {
    /// Borrows the final process-static map while this exclusive lifecycle is
    /// held. It is not a general PageMap escape hatch: the only current
    /// consumer is the typed page owner that also retains this lease.
    #[inline]
    pub(crate) fn page_map(&self) -> Result<&'static PageMap, ProcessPageMapError> {
        if self.guard.is_none() || self.storage.state.load(Ordering::Acquire) != READY {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.page_map_ref())
    }

    /// Releases the lifecycle boundary after a completely quiesced page
    /// engine has cleared every map entry and source page owner.
    pub(crate) fn finish(mut self) -> Result<(), ProcessPageMapError> {
        let guard = self.guard.take().ok_or(ProcessPageMapError::Poisoned)?;
        match guard.unlock() {
            Ok(()) => Ok(()),
            Err(error) => {
                // The atomic release already occurred. A later wake failure
                // cannot make this map safely reusable as if the bounded
                // lifecycle had remained private.
                self.storage.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
        }
    }
}

impl Drop for ProcessPageMapMutationLease {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            // An unfinished owner can retain live map entries, arena bits, or
            // a page/producer relation. Do not unlock and silently let a
            // later caller treat the root as a fresh allocation route.
            self.storage.state.store(POISONED, Ordering::Release);
            drop(guard);
        }
    }
}

/// A process-global page-map initialization or publication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessPageMapError {
    Lock(Errno),
    /// A different bounded page lifecycle still owns the source-plain map
    /// entries. This is a non-mutating rejection rather than a recursive
    /// lock acquisition.
    LifecycleBusy,
    Initialization(Errno),
    ConfigurationMismatch,
    SubprocessMismatch,
    Poisoned,
}

static PROCESS_PAGE_MAP: ProcessPageMapStorage = ProcessPageMapStorage::new();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::{PageSize, fault};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    #[test]
    fn process_map_publishes_one_stable_root_for_its_selected_main_subprocess() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let first = storage
            .initialize(memory_config(), subprocess)
            .expect("the source page map initializes");
        let second = storage
            .initialize(memory_config(), subprocess)
            .expect("same frozen process inputs reuse the root");

        assert_eq!(first.root().unwrap(), second.root().unwrap());
        assert_eq!(first.subprocess().unwrap().as_ptr(), subprocess.as_ptr());
        assert_eq!(first.memory_config().unwrap(), memory_config());
    }

    #[test]
    fn process_map_rejects_changed_config_or_main_identity_without_replacing_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let first = storage.initialize(memory_config(), subprocess).unwrap();
        let root = first.root().unwrap();
        let different_config = MemoryConfig::from_observations(
            PageSize::new(16_384).expect("Linux/AArch64 supports this page size"),
            1024 * 1024,
            false,
            false,
        );
        assert!(matches!(
            storage.initialize(different_config, subprocess),
            Err(ProcessPageMapError::ConfigurationMismatch)
        ));
        assert!(matches!(
            storage.initialize(memory_config(), MainSubprocess::test_static_owner()),
            Err(ProcessPageMapError::SubprocessMismatch)
        ));
        assert_eq!(first.root().unwrap(), root);
    }

    #[test]
    fn page_lifecycle_is_exclusive_and_an_unfinished_owner_poisoned_the_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let lifecycle = lease
            .begin_page_lifecycle()
            .expect("the ready process root admits its first page owner");
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::LifecycleBusy)
        ));
        lifecycle
            .finish()
            .expect("a quiesced page owner releases the process lifecycle");

        let unfinished = lease
            .begin_page_lifecycle()
            .expect("the completed lifecycle leaves the root reusable");
        drop(unfinished);
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::Poisoned)
        ));
        assert!(
            lease.test_retained_page_map().is_some(),
            "terminal poisoning retains the final map slot rather than exposing a new cold root"
        );
    }

    #[test]
    fn concurrent_process_map_initializers_share_the_one_release_published_root() {
        const THREADS: usize = 4;

        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        // A second source-map reservation would fail.  Every worker must
        // instead observe the first initializer's release-published final
        // slot, proving the process owner does not leak a competing map.
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 2, Errno::NOMEM));
        let ready = Arc::new(Barrier::new(THREADS));
        let mut workers = std::vec::Vec::new();
        for _ in 0..THREADS {
            let ready = Arc::clone(&ready);
            workers.push(thread::spawn(move || {
                ready.wait();
                storage
                    .initialize(memory_config(), subprocess)
                    .expect("the serialized once path succeeds")
                    .root()
                    .unwrap()
                    .as_ptr()
                    .addr()
            }));
        }

        let first = workers.remove(0).join().unwrap();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), first);
        }
        fault.set(fault::Plan::disabled());
    }

    #[test]
    fn unpublished_mapping_failure_consumes_the_once_owner_without_publishing_a_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Initialization(Errno::NOMEM))
        ));
        assert_eq!(storage.state.load(Ordering::Acquire), POISONED);
        assert!(storage.root.load().is_none());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        ));
    }

    #[test]
    fn unpublished_top_level_commit_failure_consumes_the_once_owner_without_a_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        // With this non-overcommit fixture, `PageMap::initialize` first
        // commits the minimum top-level header before it can write a root.
        let fault = fault::install(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Initialization(Errno::NOMEM))
        ));
        assert_eq!(storage.state.load(Ordering::Acquire), POISONED);
        assert!(storage.root.load().is_none());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        ));
    }

    #[test]
    fn unpublished_trailing_submap_commit_failure_consumes_the_once_owner_without_a_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        // The second commit makes the trailing source submap available. It
        // must fail before header/root publication just like the first one.
        let fault = fault::install(fault::Plan::at(fault::Point::Commit, 2, Errno::NOMEM));
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Initialization(Errno::NOMEM))
        ));
        assert_eq!(storage.state.load(Ordering::Acquire), POISONED);
        assert!(storage.root.load().is_none());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            storage.initialize(memory_config(), subprocess),
            Err(ProcessPageMapError::Poisoned)
        ));
    }
}
