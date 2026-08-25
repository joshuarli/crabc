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
    /// Rust-side exclusion boundary for the source page map's plain entry
    /// reads and writes. This is deliberately separate from initialization
    /// and from the source map's individual submap locks. A normal bounded
    /// engine holds it for its complete owner/producer lifetime. A future
    /// source-shaped thread-exit handoff may instead transfer it to a
    /// process-lived route which reacquires it around each complete
    /// lookup/free/release decision; it never leaves a plain entry access
    /// unguarded between those two forms.
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

    /// Test-only observation of pre-publication state. It exposes no map
    /// reference and is used by source-order regressions to prove that a
    /// process preflight rejection never manufactures a global root.
    #[cfg(test)]
    pub(crate) fn test_has_published_root(&self) -> bool {
        self.root.load().is_some()
    }

    /// Initializes or obtains the process-global map for `subprocess`.
    ///
    /// The source default `mi_option_max_vabits == 0` is passed as the
    /// configured value, so [`PageMap::initialize`] observes the frozen
    /// selected Linux-profile virtual-address width. Option parsing and process
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

    /// Transfers the long engine guard to one process-lived post-exit page
    /// route.
    ///
    /// This is intentionally unsafe even though it performs only a private
    /// lock release. The caller must already own a source-valid live-page
    /// continuation that retains every registered page's metadata, arena
    /// backing, matching Heap arena-pages image, and final release authority.
    /// That continuation must use the returned access capability for every
    /// plain PageMap lookup, registration, and unregistration, and must call
    /// [`ProcessPageMapPostExitAccess::finish_after_all_pages_released`] only
    /// after all of those pages are gone. Dropping the returned capability
    /// before that explicit completion poisons this process root rather than
    /// reopening it over a possibly live map entry.
    ///
    /// The transfer itself is the Rust ownership bridge required after
    /// upstream has detached and freed the old Theap/TLD: source PageMap
    /// entries remain plain, but their process-lifetime owner no longer keeps
    /// an arbitrary-length engine borrow or its former thread metadata alive.
    /// It is not a general PageMap escape hatch or a substitute for
    /// `xthread_free`, abandoned-bitmap, Heap, or arena synchronization.
    pub(crate) unsafe fn into_post_exit_access(
        mut self,
    ) -> Result<ProcessPageMapPostExitAccess, ProcessPageMapError> {
        let guard = self.guard.take().ok_or(ProcessPageMapError::Poisoned)?;
        match guard.unlock() {
            Ok(()) => Ok(ProcessPageMapPostExitAccess {
                storage: self.storage,
                completed: false,
            }),
            Err(error) => {
                // The Release transition occurred before the wake failure.
                // The former engine cannot safely retain its long guard, and
                // a later route cannot treat the map as normal after an
                // unreported handoff wake failure.
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

/// One process-lived route for page-map access after a thread owner detached.
///
/// Upstream abandoned pages keep their PageMap registration after their old
/// Theap and TLD have gone away. The route therefore cannot retain
/// [`ProcessPageMapMutationLease`]: that guard is deliberately an
/// engine-lifetime aliasing boundary. Instead, this capability reacquires the
/// same guard for each complete plain-entry operation. It carries no raw page
/// pointer, arena, Heap, or free-list right by itself; its one valid consumer
/// must retain those in a separate typed post-exit owner.
///
/// The explicit `finish_after_all_pages_released` transition is deliberately
/// unsafe because the process map cannot inspect whether every registered
/// post-exit page has truly completed its final release. An unfinished drop
/// is terminal, matching the existing long-lifecycle lease policy.
#[must_use = "a post-exit PageMap access route must finish after every retained page is released"]
pub(crate) struct ProcessPageMapPostExitAccess {
    storage: &'static ProcessPageMapStorage,
    completed: bool,
}

impl ProcessPageMapPostExitAccess {
    /// Reclaims the long source-plain PageMap exclusion boundary for one
    /// newly attached page engine.
    ///
    /// # Safety
    ///
    /// The caller must consume the only process-exit route that owns every
    /// still-registered page and immediately couple the returned lease to one
    /// typed engine that assumes every later plain PageMap lookup,
    /// registration, and unregistration responsibility. It must not leave a
    /// second short-access route, a concurrent post-exit client-free route,
    /// or an unowned registered page behind. Dropping the returned lease
    /// before that engine finishes remains terminal, just like a normal
    /// mutation lease.
    ///
    /// This is the inverse of
    /// [`ProcessPageMapMutationLease::into_post_exit_access`], but it is not
    /// a general route upgrade: only an explicit consuming handoff may turn
    /// the short post-exit access capability back into a long engine
    /// lifecycle.
    pub(crate) unsafe fn into_mutation_lease(
        mut self,
    ) -> Result<ProcessPageMapMutationLease, (Self, ProcessPageMapError)> {
        if self.completed
            || self.storage.state.load(Ordering::Acquire) != READY
            || self.storage.root.load().is_none()
        {
            return Err((self, ProcessPageMapError::Poisoned));
        }
        let guard = match self.storage.page_lifecycle_lock.try_lock() {
            Some(guard) => guard,
            None => return Err((self, ProcessPageMapError::LifecycleBusy)),
        };
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                // The lock became externally visible before its wake failed.
                // This route cannot retry as though it still owned a clean
                // short-access capability.
                self.storage.state.store(POISONED, Ordering::Release);
                return Err((self, ProcessPageMapError::Lock(error)));
            }
            return Err((self, ProcessPageMapError::Poisoned));
        }
        // The returned long lease is now the sole owner responsible for the
        // post-exit entries. Mark this source capability complete before it
        // drops so its conservative Drop cannot poison that valid transfer.
        self.completed = true;
        Ok(ProcessPageMapMutationLease {
            storage: self.storage,
            guard: Some(guard),
        })
    }

    /// Checks whether this post-exit route belongs to one stable
    /// process-page-map root.
    ///
    /// This is only an identity witness. It neither borrows the map nor
    /// grants entry access; callers still need the consuming transition above
    /// before they may form a normal page engine.
    #[inline]
    pub(crate) fn matches_root(
        &self,
        root: NonNull<PageMapHeader>,
    ) -> Result<bool, ProcessPageMapError> {
        if self.completed || self.storage.state.load(Ordering::Acquire) != READY {
            return Err(ProcessPageMapError::Poisoned);
        }
        Ok(self.storage.root.load() == Some(root))
    }

    /// Runs one complete operation while holding the source-plain PageMap
    /// entry exclusion boundary.
    ///
    /// A closure that obtains a page from a lookup must complete its atomic
    /// abandoned-free/release decision before it returns. It must not leak a
    /// raw page reference, pointer-based owner right, or a future plain map
    /// access beyond this closure. Stable page and arena lifetime remain the
    /// enclosing post-exit owner's separate responsibility.
    pub(crate) fn with_page_map<R>(
        &self,
        operation: impl for<'map> FnOnce(&'map PageMap) -> R,
    ) -> Result<R, ProcessPageMapError> {
        if self.completed
            || self.storage.state.load(Ordering::Acquire) != READY
            || self.storage.root.load().is_none()
        {
            return Err(ProcessPageMapError::Poisoned);
        }
        let guard = self
            .storage
            .page_lifecycle_lock
            .lock()
            .map_err(ProcessPageMapError::Lock)?;
        if self.storage.state.load(Ordering::Acquire) != READY || self.storage.root.load().is_none() {
            let unlock = guard.unlock();
            if let Err(error) = unlock {
                self.storage.state.store(POISONED, Ordering::Release);
                return Err(ProcessPageMapError::Lock(error));
            }
            return Err(ProcessPageMapError::Poisoned);
        }

        let result = operation(self.storage.page_map_ref());
        match guard.unlock() {
            Ok(()) => Ok(result),
            Err(error) => {
                // The closure's source operation completed before this
                // post-Release wake failure. Its caller receives no result
                // that could be used to continue an apparently healthy route.
                self.storage.state.store(POISONED, Ordering::Release);
                Err(ProcessPageMapError::Lock(error))
            }
        }
    }

    /// Completes the process-page-map half of a post-exit route.
    ///
    /// # Safety
    ///
    /// Every page whose live registration depended on this capability must
    /// have completed its source terminal release: mapped identity/bitmap
    /// removal where applicable, PageMap unregister, ordinary arena-page
    /// clear, metadata retirement, and backing-slice/mapping release. No
    /// `with_page_map` operation or raw page/producer relation may remain.
    pub(crate) unsafe fn finish_after_all_pages_released(
        mut self,
    ) -> Result<(), ProcessPageMapError> {
        // Acquire/release the same exclusion boundary once more so a safe
        // caller cannot mark this route complete while one of its own prior
        // map closures still holds a plain entry access.
        self.with_page_map(|_| ())?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for ProcessPageMapPostExitAccess {
    fn drop(&mut self) {
        if !self.completed {
            // A detached Theap/TLD may already be gone while its pages stay
            // registered. Never allow another route to interpret that as a
            // clean PageMap lifecycle.
            self.storage.state.store(POISONED, Ordering::Release);
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
            PageSize::new(4_096).expect("the selected native page size is valid"),
            1024 * 1024 + 1,
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
    fn post_exit_access_releases_the_engine_guard_but_requires_explicit_page_completion() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();

        let lifecycle = lease
            .begin_page_lifecycle()
            .expect("the exiting engine initially owns every plain map entry");
        // SAFETY: this regression models the later owner-exit handoff. No
        // page exists in this isolated fixture, so the explicit completion
        // below proves the transfer does not reopen a retained route.
        let access = unsafe { lifecycle.into_post_exit_access() }
            .expect("the map guard transfers to the process-lived route");

        assert_eq!(
            access
                .with_page_map(|page_map| page_map.memory_config())
                .expect("the short access guard observes the final map"),
            memory_config()
        );
        let next = lease
            .begin_page_lifecycle()
            .expect("the transfer releases the long engine guard between accesses");
        next.finish()
            .expect("the independent empty engine returns the shared guard");

        // SAFETY: the fixture has no registered page or in-flight access.
        unsafe { access.finish_after_all_pages_released() }
            .expect("explicit all-page completion keeps the process root ready");
        lease
            .begin_page_lifecycle()
            .expect("a completed post-exit route leaves the map reusable")
            .finish()
            .expect("the final empty lifecycle releases normally");
    }

    #[test]
    fn post_exit_access_can_transfer_to_one_new_long_page_lifecycle() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();
        let lifecycle = lease
            .begin_page_lifecycle()
            .expect("the exiting engine initially owns every plain map entry");
        // SAFETY: this isolated fixture models the consuming route handoff;
        // no registered page exists, so the follow-on long lifecycle owns the
        // complete empty map boundary.
        let access = unsafe { lifecycle.into_post_exit_access() }
            .expect("the old engine transfers into its process-lived route");
        let reclaimed = match unsafe { access.into_mutation_lease() } {
            Ok(lifecycle) => lifecycle,
            Err((_access, error)) => {
                panic!("the explicit route reclaims its one long lifecycle: {error:?}")
            }
        };
        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::LifecycleBusy)
        ));
        assert_eq!(
            reclaimed
                .page_map()
                .expect("the reclaimed lifecycle retains the final map")
                .memory_config(),
            memory_config()
        );
        reclaimed
            .finish()
            .expect("the empty adopted engine releases the long lifecycle");
        lease
            .begin_page_lifecycle()
            .expect("the completed adopted lifecycle leaves the map reusable")
            .finish()
            .expect("the final empty lifecycle releases normally");
    }

    #[test]
    fn dropping_unfinished_post_exit_access_poisoned_the_root() {
        let storage = ProcessPageMapStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let lease = storage.initialize(memory_config(), subprocess).unwrap();
        let lifecycle = lease.begin_page_lifecycle().unwrap();
        // SAFETY: this test intentionally abandons the returned process page
        // route to prove the conservative terminal-drop policy.
        let access = unsafe { lifecycle.into_post_exit_access() }.unwrap();
        drop(access);

        assert!(matches!(
            lease.begin_page_lifecycle(),
            Err(ProcessPageMapError::Poisoned)
        ));
        assert!(lease.test_retained_page_map().is_some());
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
