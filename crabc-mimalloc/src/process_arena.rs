// Copyright (c) 2023-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page.c:574-644`
// (`mi_page_extend_free`'s direct `_mi_os_commit`), and
// `src/arena.c:341-406,525-569,1573-1611,1676-1791,1794-1912`
// (`mi_arena_reserve`, the one-at-a-time fresh-arena retry point,
// `mi_arenas_add`, `mi_arena_initialize`, `mi_manage_os_memory_ex2`, and the
// regular `mi_reserve_os_memory_ex2` map path). The first-arena policy retains
// the pinned default options; general option mutation, later arena-count
// scaling, NUMA/exclusive selection, huge pages, and fresh-page routing remain
// separately incomplete.

//! One process-shared, caller-selected arena backing.
//!
//! The global [`ProcessPageMapLease`] is a source root/publication owner, not
//! an arena allocator. This sidecar starts the separate source
//! `mi_manage_os_memory_ex2` boundary: it binds one caller-selected, already
//! mapped single arena to that exact map root and main-subprocess identity,
//! then retains the mapping, registry slot, and in-place metadata for process
//! lifetime. Its explicit [`ProcessSharedArenaStorage::reserve_one_os_arena`]
//! entry ports one caller-selected regular `mi_reserve_os_memory_ex2` map. Its
//! separate [`ProcessSharedArenaStorage::reserve_default_os_arena`] entry
//! ports the first lazy `mi_arena_reserve` decision: the Linux/AArch64 default
//! 1-GiB reserve, normal default eager-commit choice, and 128-MiB retry after
//! a failed first reservation. The entry has no process-initialization caller;
//! `MainStaticFirstArenaPageAllocator` is its one current ticket-zero caller,
//! invoking it after an actual first fresh-page miss. Later arena-count scaling,
//! option mutation, huge pages,
//! exclusive/NUMA configuration, multiple sub-arenas, and general fresh-page
//! routing remain absent. `ProcessPageArenaLease` can instead prove this exact
//! pairing for the separately bounded ticket-zero static page owner; that
//! owner alone attaches the main Heap, registers pages, and retains a scoped
//! producer lifetime.
//!
//! A reserved selected mapping enters this sidecar's final slot before
//! `manage_external_in_place` initializes metadata. The retained arena callback
//! therefore reaches the exact process-owned [`Mapping`] for metadata, later
//! arena/page-metadata commitment, and the frozen Linux decommit request; it
//! never borrows a stack-local mapping owner. A paired page owner can also
//! request one range-checked direct page-area commit, mirroring
//! `mi_page_extend_free`'s `_mi_os_commit` rather than reusing the arena
//! callback. This boundary deliberately does not choose source
//! page-on-demand policy, track `slice_pcommitted`, or own a failed page-area
//! commit's `_mi_page_abandon` transition; the bounded page lifecycle does so
//! after this capability returns an error.
//!
//! On a pre-publication rejection from the lower external-manage entry, the
//! caller receives its [`Mapping`] back through
//! [`ProcessSharedArenaInstallFailure`]. The explicit regular-OS reservation
//! owns the contrasting source decision itself: it unmaps an unpublished
//! failed map before making the sidecar cold again, or retains the map and
//! terminal error when that release fails.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use crabc_core::Errno;

use crate::arena::{
    ArenaRegistry, ArenaView, CommitHook, ExternalArenaPlan, ManageArenaError,
    ManagedExternalRegion, manage_external_in_place, manage_os_in_place,
};
use crate::config::{
    ARENA_ALIGNMENT, ARENA_MAX_CHUNK_OBJ_SIZE, ARENA_MAX_SIZE, ARENA_MIN_SIZE,
    ARENA_SLICE_SIZE, GIB, MAX_ALLOC_SIZE,
};
use crate::invariants;
use crate::lock::PrivateLock;
use crate::os::{MapAccess, Mapping, MemoryConfig};
use crate::page_map::PageMapHeader;
use crate::process_page_map::{
    ProcessPageMapError, ProcessPageMapLease, ProcessPageMapMutationLease,
};
use crate::subproc::MainSubprocess;

const COLD: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const RETAINED: u8 = 3;

const PAIR_UNSET: u8 = 0;
const PAIR_SET: u8 = 1;

// `src/options.c:46-64` freezes these normal-release values for the only
// supported 64-bit Linux/AArch64 profile. The source stores `arena_reserve`
// in KiB; retain bytes here because every surrounding map/arena boundary is
// byte-based. This is not an options implementation or a mutable substitute
// for one.
const DEFAULT_ARENA_RESERVE: usize = GIB;
const DEFAULT_SMALL_ARENA_RESERVE: usize = 4 * ARENA_MIN_SIZE;

/// Process-static sidecar for one source-managed arena backing.
///
/// `MainSubprocess` currently models only the bounded thread/static-TLD
/// fields needed by prior slices. Keeping its arena-registry group here
/// avoids claiming that it is already a full Rust layout of `mi_subproc_t`.
/// The initialization lock serializes pair selection and the one registry
/// insertion. `INITIALIZING` makes the temporary final mapping-slot ownership
/// explicit while in-place metadata initialization invokes its callback. Once
/// READY is Release-published, the mapping, managed arena metadata, exact
/// root identity, and registry publication are all stable until a future
/// process-shutdown/quiescence owner exists.
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

// SAFETY: the initialization lock serializes final-slot writes and temporary
// `INITIALIZING` ownership. READY is Release-published only after every final
// slot and the registry's Release arena publication are valid. Once stored, a
// Mapping is never moved, replaced, or unmapped; its callback performs only
// raw range transitions whose conflicting ownership is serialized by Arena's
// source bitmap protocol. This owner intentionally supplies neither mutable
// page-map access nor arena teardown while a lease can exist.
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

    /// Returns an immutable lease for the one already-published shared arena.
    ///
    /// This is the read-only counterpart to the bounded reservation entries:
    /// it never reserves, searches, or mutates a map. A caller must still join
    /// it with an exact process PageMap lease before a page owner may use the
    /// arena, so an unrelated ready sidecar cannot be mistaken for the current
    /// process image.
    #[inline]
    pub(crate) fn ready_lease(
        &'static self,
    ) -> Result<ProcessSharedArenaLease, ProcessSharedArenaError> {
        if self.state.load(Ordering::Acquire) != READY {
            return Err(ProcessSharedArenaError::Retained);
        }
        Ok(ProcessSharedArenaLease { storage: self })
    }

    /// Builds an isolated deliberately leaked process-lifetime fixture.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    /// Test-only observation that the automatic-reserve policy remains absent
    /// from process initialization. A process coordinator must not touch this
    /// caller-managed sidecar merely by publishing a PageMap root.
    #[cfg(test)]
    pub(crate) fn test_is_cold(&self) -> bool {
        self.state.load(Ordering::Acquire) == COLD
    }

    /// Installs one complete, aligned source arena into this process sidecar.
    ///
    /// The caller transfers one live mapping. On every pre-publication error,
    /// the returned failure still owns exactly that mapping; it must remain
    /// live or be explicitly unmapped by the caller. Success consumes it into
    /// this process-lifetime owner. A reserved mapping commits only through
    /// the stable final-slot callback; a callback failure returns that same
    /// unpublished mapping while this sidecar returns to COLD. A later source
    /// reserve policy must choose the mapping size/commit mode and decide
    /// whether to unmap on failure.
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
            COLD => {
                // This state makes the temporary mapping-slot ownership
                // observable while `manage_external_in_place` invokes the
                // callback synchronously under this same lock.
                self.state.store(INITIALIZING, Ordering::Release);
                self.install_cold(candidate, mapping, ManagedArenaBacking::External)
            }
            READY => ProcessSharedArenaInstallAttempt::Returned {
                error: if self.pair_matches(candidate.pair) {
                    ProcessSharedArenaError::AlreadyInstalled
                } else {
                    ProcessSharedArenaError::PairMismatch
                },
                mapping,
            },
            INITIALIZING | RETAINED | _ => ProcessSharedArenaInstallAttempt::Returned {
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

    /// Reserves and publishes one caller-selected regular OS arena.
    ///
    /// This is the deliberately narrow `mi_reserve_os_memory_ex2` slice. The
    /// request is rounded only to source slice alignment and must then name
    /// exactly one complete arena; this boundary does not silently retain a
    /// tail, choose a multi-arena reservation, or infer any automatic policy.
    /// It uses the pinned normal mapping path only: `access` selects the
    /// source `commit` input, while huge pages, exclusive ownership, NUMA
    /// policy, and general allocation routing remain outside this capability.
    ///
    /// An unpublished metadata failure owns the source's matching release
    /// decision: it unmaps the exact regular mapping before returning a
    /// retryable rejection. If that unmap fails, the final mapping slot and a
    /// terminal retained result preserve the only live ownership proof.
    pub(crate) fn reserve_one_os_arena(
        &'static self,
        page_map: ProcessPageMapLease,
        requested_size: usize,
        access: MapAccess,
    ) -> Result<ProcessSharedArenaLease, ProcessSharedArenaReserveFailure> {
        let length = one_regular_os_arena_length(requested_size)
            .map_err(ProcessSharedArenaReserveFailure::rejected)?;
        let pair = ProcessArenaPair::from_page_map(page_map)
            .map_err(|error| ProcessSharedArenaReserveFailure::rejected(
                ProcessSharedArenaReserveError::PageMap(error),
            ))?;
        let guard = self
            .initialization_lock
            .lock()
            .map_err(|error| ProcessSharedArenaReserveFailure::rejected(
                ProcessSharedArenaReserveError::Lock(error),
            ))?;

        let attempt = match self.state.load(Ordering::Acquire) {
            READY => {
                if self.pair_matches(pair) {
                    ProcessSharedArenaReservationAttempt::Rejected(
                        ProcessSharedArenaReserveError::AlreadyInstalled,
                    )
                } else {
                    ProcessSharedArenaReservationAttempt::Rejected(
                        ProcessSharedArenaReserveError::PairMismatch,
                    )
                }
            }
            COLD if self.pair_state.load(Ordering::Acquire) == PAIR_SET
                && !self.pair_matches(pair) =>
            {
                ProcessSharedArenaReservationAttempt::Rejected(
                    ProcessSharedArenaReserveError::PairMismatch,
                )
            }
            COLD => self.reserve_cold_regular_os_arena(pair, length, access),
            INITIALIZING | RETAINED | _ => ProcessSharedArenaReservationAttempt::Retained(
                ProcessSharedArenaReserveError::Retained,
            ),
        };
        let unlock = guard.unlock();

        match (attempt, unlock) {
            (ProcessSharedArenaReservationAttempt::Ready(lease), Ok(())) => Ok(lease),
            (ProcessSharedArenaReservationAttempt::Ready(_), Err(error)) => {
                // The arena and its stable mapping callback were already
                // published before the wake failure. Preserve the only sound
                // terminal ownership state rather than offering a retry.
                self.state.store(RETAINED, Ordering::Release);
                Err(ProcessSharedArenaReserveFailure::retained(
                    ProcessSharedArenaReserveError::Lock(error),
                ))
            }
            (ProcessSharedArenaReservationAttempt::Rejected(error), Err(_))
            | (ProcessSharedArenaReservationAttempt::Rejected(error), Ok(())) => {
                // The source reservation/setup outcome takes precedence over
                // an unrelated post-Release private-futex wake failure.
                Err(ProcessSharedArenaReserveFailure::rejected(error))
            }
            (ProcessSharedArenaReservationAttempt::Retained(error), _) => {
                Err(ProcessSharedArenaReserveFailure::retained(error))
            }
        }
    }

    /// Reserves the first default arena after a source fresh-page miss.
    ///
    /// This is the bounded first-arena branch of `mi_arena_reserve`, not a
    /// process-start reservation. The caller supplies the current fresh page's
    /// already-rounded byte requirement; the frozen Linux/AArch64 profile
    /// first reserves 1 GiB and then retries 128 MiB only if the primary map
    /// or unpublished setup returned the sidecar to COLD. Later source arena
    /// count scaling, options, huge-page policy, and general fresh-page retry
    /// routing must be added with their owning source state machines.
    pub(crate) fn reserve_default_os_arena(
        &'static self,
        page_map: ProcessPageMapLease,
        requested_size: usize,
    ) -> Result<ProcessSharedArenaLease, ProcessSharedArenaReserveFailure> {
        let pair = ProcessArenaPair::from_page_map(page_map)
            .map_err(|error| ProcessSharedArenaReserveFailure::rejected(
                ProcessSharedArenaReserveError::PageMap(error),
            ))?;
        let plan = default_os_arena_reservation(pair.config, requested_size)
            .map_err(ProcessSharedArenaReserveFailure::rejected)?;
        let guard = self
            .initialization_lock
            .lock()
            .map_err(|error| ProcessSharedArenaReserveFailure::rejected(
                ProcessSharedArenaReserveError::Lock(error),
            ))?;

        let attempt = match self.state.load(Ordering::Acquire) {
            READY => {
                if self.pair_matches(pair) {
                    // The one-arena first-default policy cannot search or
                    // reuse this published arena. Returning a retryable
                    // rejection would let a caller mistake READY for COLD.
                    ProcessSharedArenaReservationAttempt::Retained(
                        ProcessSharedArenaReserveError::AlreadyInstalled,
                    )
                } else {
                    ProcessSharedArenaReservationAttempt::Retained(
                        ProcessSharedArenaReserveError::PairMismatch,
                    )
                }
            }
            COLD if self.pair_state.load(Ordering::Acquire) == PAIR_SET
                && !self.pair_matches(pair) =>
            {
                ProcessSharedArenaReservationAttempt::Retained(
                    ProcessSharedArenaReserveError::PairMismatch,
                )
            }
            COLD => self.reserve_cold_default_os_arena(pair, plan),
            INITIALIZING | RETAINED | _ => ProcessSharedArenaReservationAttempt::Retained(
                ProcessSharedArenaReserveError::Retained,
            ),
        };
        let unlock = guard.unlock();

        match (attempt, unlock) {
            (ProcessSharedArenaReservationAttempt::Ready(lease), Ok(())) => Ok(lease),
            (ProcessSharedArenaReservationAttempt::Ready(_), Err(error)) => {
                // The arena and its stable mapping callback were already
                // published before the wake failure. Preserve the only sound
                // terminal ownership state rather than offering a retry.
                self.state.store(RETAINED, Ordering::Release);
                Err(ProcessSharedArenaReserveFailure::retained(
                    ProcessSharedArenaReserveError::Lock(error),
                ))
            }
            (ProcessSharedArenaReservationAttempt::Rejected(error), Err(_))
            | (ProcessSharedArenaReservationAttempt::Rejected(error), Ok(())) => {
                // The source reservation/setup outcome takes precedence over
                // an unrelated post-Release private-futex wake failure.
                Err(ProcessSharedArenaReserveFailure::rejected(error))
            }
            (ProcessSharedArenaReservationAttempt::Retained(error), _) => {
                Err(ProcessSharedArenaReserveFailure::retained(error))
            }
        }
    }

    fn reserve_cold_regular_os_arena(
        &'static self,
        pair: ProcessArenaPair,
        length: usize,
        access: MapAccess,
    ) -> ProcessSharedArenaReservationAttempt {
        // `INITIALIZING` reserves this final mapping slot before the source
        // map call. No retry can observe COLD until either unpublished setup
        // released its map or a terminal retained owner records it.
        self.state.store(INITIALIZING, Ordering::Release);
        let mapping = match Mapping::map_aligned_for_allocator(
            pair.config,
            length,
            ARENA_ALIGNMENT,
            access,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                self.state.store(COLD, Ordering::Release);
                return ProcessSharedArenaReservationAttempt::Rejected(
                    ProcessSharedArenaReserveError::Mapping(error),
                );
            }
        };
        let candidate = match ProcessArenaCandidate::from_pair_and_mapping(pair, &mapping) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.state.store(COLD, Ordering::Release);
                return self.release_unpublished_os_reservation(mapping, error);
            }
        };

        match self.install_cold(candidate, mapping, ManagedArenaBacking::RegularOs) {
            ProcessSharedArenaInstallAttempt::Ready(lease) => {
                ProcessSharedArenaReservationAttempt::Ready(lease)
            }
            ProcessSharedArenaInstallAttempt::Retained(error) => {
                ProcessSharedArenaReservationAttempt::Retained(
                    ProcessSharedArenaReserveError::Manage(error),
                )
            }
            ProcessSharedArenaInstallAttempt::Returned { error, mapping } => {
                self.release_unpublished_os_reservation(mapping, error)
            }
        }
    }

    fn reserve_cold_default_os_arena(
        &'static self,
        pair: ProcessArenaPair,
        plan: DefaultOsArenaReservation,
    ) -> ProcessSharedArenaReservationAttempt {
        let primary = self.reserve_cold_regular_os_arena(pair, plan.primary_size, plan.access);
        if !matches!(&primary, ProcessSharedArenaReservationAttempt::Rejected(_)) {
            return primary;
        }

        let Some(fallback_size) = plan.fallback_size else {
            return primary;
        };
        // `reserve_cold_regular_os_arena` restores COLD only after it has
        // released the failed unpublished mapping. The source retry must not
        // manufacture a second reservation when any terminal owner remains.
        if self.state.load(Ordering::Acquire) != COLD {
            self.state.store(RETAINED, Ordering::Release);
            return ProcessSharedArenaReservationAttempt::Retained(
                ProcessSharedArenaReserveError::Retained,
            );
        }
        self.reserve_cold_regular_os_arena(pair, fallback_size, plan.access)
    }

    fn release_unpublished_os_reservation(
        &'static self,
        mut mapping: Mapping,
        manage: ProcessSharedArenaError,
    ) -> ProcessSharedArenaReservationAttempt {
        match mapping.unmap() {
            Ok(()) => match self.state.load(Ordering::Acquire) {
                COLD => ProcessSharedArenaReservationAttempt::Rejected(
                    ProcessSharedArenaReserveError::Manage(manage),
                ),
                RETAINED => ProcessSharedArenaReservationAttempt::Retained(
                    ProcessSharedArenaReserveError::Manage(manage),
                ),
                _ => {
                    // An unpublished mapping is gone, but an unexpected state
                    // cannot be made retryable without a stronger teardown
                    // proof for the shared registry/pair fields.
                    self.state.store(RETAINED, Ordering::Release);
                    ProcessSharedArenaReservationAttempt::Retained(
                        ProcessSharedArenaReserveError::Manage(manage),
                    )
                }
            },
            Err(unmap) => {
                // SAFETY: this exact mapping is still live after failed
                // `munmap`; the initialization lock is held, and no prior
                // successful publication can own this final slot.
                unsafe { self.write_retained_mapping(mapping) };
                self.state.store(RETAINED, Ordering::Release);
                ProcessSharedArenaReservationAttempt::Retained(
                    ProcessSharedArenaReserveError::Release { manage, unmap },
                )
            }
        }
    }

    fn install_cold(
        &'static self,
        candidate: ProcessArenaCandidate,
        mapping: Mapping,
        backing: ManagedArenaBacking,
    ) -> ProcessSharedArenaInstallAttempt {
        if let Err(error) = self.bind_or_match_pair(candidate) {
            // A foreign candidate has not changed this process sidecar and
            // must not consume the valid selected pair's future retry. A
            // registry-binding failure, by contrast, means the supposedly
            // private source registry no longer has a trustworthy state.
            if error == ProcessSharedArenaError::RegistryBinding {
                self.state.store(RETAINED, Ordering::Release);
            } else {
                self.state.store(COLD, Ordering::Release);
            }
            return ProcessSharedArenaInstallAttempt::Returned { error, mapping };
        }

        // The callback is retained by the in-place arena beyond this stack
        // frame. Store the mapping in its process-lifetime slot before the
        // source-shaped metadata commit call, rather than handing out a
        // pointer to this consuming local owner. An error below takes this
        // exact slot back before COLD is republished.
        //
        // SAFETY: `INITIALIZING` is held under `initialization_lock` and no
        // previous attempt can have initialized this final slot. The only
        // callback invocation before READY is synchronous below.
        unsafe { self.write_initializing_mapping(mapping) };
        let mapping = unsafe { self.mapping_for_commit() };
        let initially_committed = mapping.initially_committed();
        let initially_zero = mapping.initially_zero();
        let commit_hook = CommitHook::new(
            process_owned_mapping_commit,
            core::ptr::from_ref(self).cast_mut().cast::<c_void>(),
        );

        // SAFETY: the candidate proves the live mapping is one complete,
        // aligned single arena using the same page size as the selected map.
        // The final mapping slot is initialized for the stable hook before
        // this call, and the initialization lock excludes every registry
        // reader/writer until the selected source-shaped manager fully
        // publishes it.
        let managed = unsafe {
            match backing {
                ManagedArenaBacking::External => manage_external_in_place(
                    &self.registry,
                    candidate.base,
                    candidate.length,
                    candidate.pair.config.page_size(),
                    initially_committed,
                    false,
                    initially_zero,
                    -1,
                    false,
                    Some(commit_hook),
                ),
                ManagedArenaBacking::RegularOs => manage_os_in_place(
                    &self.registry,
                    candidate.base,
                    candidate.length,
                    candidate.pair.config.page_size(),
                    initially_committed,
                    initially_zero,
                    -1,
                    false,
                    Some(commit_hook),
                ),
            }
        };
        let managed = match managed {
            Ok(managed) => managed,
            Err(error) => {
                // SAFETY: the failed first-arena setup has not published a
                // registry entry or callback reachable by another caller.
                // The initialization lock still excludes another install.
                let mapping = unsafe { self.take_initializing_mapping() };
                self.state.store(COLD, Ordering::Release);
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
            // SAFETY: the managed slot joins the already-retained mapping.
            unsafe { (*self.managed.get()).write(managed) };
            self.state.store(RETAINED, Ordering::Release);
            return ProcessSharedArenaInstallAttempt::Retained(
                ProcessSharedArenaError::PartialManagement,
            );
        }

        // SAFETY: the selected in-place manager has fully initialized and
        // Release-published the sole arena. Its stable mapping callback is
        // already in the final slot; write the paired managed region before
        // READY publication.
        unsafe { (*self.managed.get()).write(managed) };
        self.state.store(READY, Ordering::Release);
        ProcessSharedArenaInstallAttempt::Ready(ProcessSharedArenaLease { storage: self })
    }

    /// Writes the mapping before synchronous in-place initialization can ask
    /// its callback to commit metadata.
    ///
    /// # Safety
    ///
    /// The caller holds `initialization_lock`, has changed the state from
    /// COLD to INITIALIZING, and knows this slot is uninitialized.
    #[inline]
    unsafe fn write_initializing_mapping(&self, mapping: Mapping) {
        unsafe { (*self.mapping.get()).write(mapping) };
    }

    /// Retains the one still-live mapping after a source reservation could not
    /// release an unpublished setup failure.
    ///
    /// # Safety
    ///
    /// The caller holds `initialization_lock`, knows that no successful arena
    /// publication owns this slot, and has either not initialized it or has
    /// already recovered it with [`Self::take_initializing_mapping`]. The
    /// mapping must still be live because its explicit `unmap` just failed.
    #[inline]
    unsafe fn write_retained_mapping(&self, mapping: Mapping) {
        unsafe { (*self.mapping.get()).write(mapping) };
    }

    /// Recovers the caller's mapping after first-arena initialization fails
    /// before registry publication.
    ///
    /// # Safety
    ///
    /// The caller holds `initialization_lock`, the state is INITIALIZING, and
    /// no arena callback escaped the failed first-arena setup.
    #[inline]
    unsafe fn take_initializing_mapping(&self) -> Mapping {
        unsafe { (*self.mapping.get()).assume_init_read() }
    }

    /// Borrows the stable mapping that owns an arena commit hook.
    ///
    /// # Safety
    ///
    /// The caller either holds `initialization_lock` during synchronous
    /// INITIALIZING metadata setup after `write_initializing_mapping`, or was
    /// reached through an arena that escaped management; its mapping slot is
    /// never moved or unmapped by this owner.
    #[inline]
    unsafe fn mapping_for_commit(&self) -> &Mapping {
        unsafe { (*self.mapping.get()).assume_init_ref() }
    }

    fn bind_or_match_pair(
        &self,
        candidate: ProcessArenaCandidate,
    ) -> Result<(), ProcessSharedArenaError> {
        if self.pair_state.load(Ordering::Acquire) == PAIR_SET {
            return if self.pair_matches(candidate.pair) {
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
                .bind_subprocess_before_publication(candidate.pair.subprocess.as_ptr())
        } {
            return Err(ProcessSharedArenaError::RegistryBinding);
        }
        // SAFETY: pair_state is still unset under the initialization lock, so
        // no reader can observe these final fields until its Release publish.
        unsafe { (*self.config.get()).write(candidate.pair.config) };
        self.subprocess
            .store(candidate.pair.subprocess.as_ptr(), Ordering::Release);
        self.page_map_root
            .store(candidate.pair.root.as_ptr(), Ordering::Release);
        self.pair_state.store(PAIR_SET, Ordering::Release);
        Ok(())
    }

    #[inline]
    fn pair_matches(&self, pair: ProcessArenaPair) -> bool {
        self.pair_state.load(Ordering::Acquire) == PAIR_SET
            && self.config() == pair.config
            && core::ptr::eq(
                self.subprocess.load(Ordering::Acquire),
                pair.subprocess.as_ptr(),
            )
            && core::ptr::eq(
                self.page_map_root.load(Ordering::Acquire),
                pair.root.as_ptr(),
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

/// Commits or purges a range through the exact mapping retained by the
/// process-owned arena.
///
/// This is the source `mi_manage_os_memory_ex2` callback boundary, not an
/// arena-reservation policy: the storage owns the selected map before this
/// callback can run, and it never releases or replaces that map while an arena
/// can retain the function pointer. A commit reports the conservative
/// `is_zero = false` observation because [`Mapping::commit`] cannot prove
/// zeroed bytes. A decommit callback's boolean instead means
/// `needs_recommit`; the frozen Linux `MADV_DONTNEED` path leaves a range
/// accessible, so both its successful outcome and its no-failure-channel
/// error case return false.
unsafe extern "C" fn process_owned_mapping_commit(
    commit: bool,
    start: *mut u8,
    size: usize,
    is_zero: *mut bool,
    user_argument: *mut c_void,
) -> bool {
    if user_argument.is_null() {
        return false;
    }
    // SAFETY: `install_cold` supplies only its process-static storage address
    // and stores its Mapping before `manage_external_in_place` can call this.
    // No successful path moves or unmapps that slot while an arena retains it.
    let storage = unsafe { &*user_argument.cast::<ProcessSharedArenaStorage>() };
    // SAFETY: the callback is synchronous under initialization_lock before
    // first publication, or comes from an arena whose retained mapping slot is
    // stable for the process lifetime.
    let mapping = unsafe { storage.mapping_for_commit() };
    let Ok(base) = mapping.base() else {
        return false;
    };
    let Some(offset) = start.addr().checked_sub(base.addr()) else {
        return false;
    };

    if commit {
        if mapping.commit(offset, size).is_err() {
            return false;
        }
        if !is_zero.is_null() {
            // SAFETY: the in-place arena API supplies either null or a valid
            // writable source `bool` output for this callback invocation.
            unsafe { is_zero.write(false) };
        }
        true
    } else {
        // The callback ABI has no decommit failure result: false specifically
        // says no recommit is needed. Mapping::decommit either preserves the
        // accessible default Linux mapping or leaves it untouched on error.
        let _ = mapping.decommit(offset, size);
        false
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

    /// Commits one validated page-area subrange through the retained mapping.
    ///
    /// This is intentionally narrower than the stable arena callback. Source
    /// `mi_page_extend_free` calls `_mi_os_commit` directly after a page has
    /// been selected, so it must neither update the arena's complete-slice
    /// commitment bitmap nor expose the mapping to page lifecycle policy.
    fn commit_page_area(
        self,
        memory: crate::types::MemoryId,
        offset: usize,
        size: usize,
    ) -> Result<(), ProcessSharedArenaError> {
        self.ensure_ready()?;
        if size == 0 {
            return Err(ProcessSharedArenaError::InvalidPageArea);
        }
        let arena_memory = memory
            .arena_memory()
            .ok_or(ProcessSharedArenaError::InvalidPageArea)?;
        let managed = self.storage.managed();
        if arena_memory.arena != managed.arena_id().as_ptr() {
            return Err(ProcessSharedArenaError::InvalidPageArea);
        }
        let arena = self.arena()?;
        let slice_index = arena_memory.slice_index as usize;
        let slice_count = arena_memory.slice_count as usize;
        let span_size = slice_count
            .checked_mul(crate::config::ARENA_SLICE_SIZE)
            .ok_or(ProcessSharedArenaError::InvalidPageArea)?;
        let span_end = offset
            .checked_add(size)
            .ok_or(ProcessSharedArenaError::InvalidPageArea)?;
        if slice_count == 0 || span_end > span_size {
            return Err(ProcessSharedArenaError::InvalidPageArea);
        }
        let slice_end = slice_index
            .checked_add(slice_count)
            .ok_or(ProcessSharedArenaError::InvalidPageArea)?;
        if slice_index >= arena.arena().slice_count || slice_end > arena.arena().slice_count {
            return Err(ProcessSharedArenaError::InvalidPageArea);
        }
        let span_start = arena
            .slice_start(slice_index)
            .ok_or(ProcessSharedArenaError::InvalidPageArea)?;
        // SAFETY: READY retains this exact Mapping in a final stable slot.
        let mapping = unsafe { self.storage.mapping_for_commit() };
        let mapping_base = mapping.base().map_err(ProcessSharedArenaError::Mapping)?;
        let mapping_length = mapping.length().map_err(ProcessSharedArenaError::Mapping)?;
        let mapping_offset = span_start
            .addr()
            .checked_sub(mapping_base.addr())
            .and_then(|start| start.checked_add(offset))
            .ok_or(ProcessSharedArenaError::InvalidPageArea)?;
        let mapping_end = mapping_offset
            .checked_add(size)
            .ok_or(ProcessSharedArenaError::InvalidPageArea)?;
        if mapping_end > mapping_length {
            return Err(ProcessSharedArenaError::InvalidPageArea);
        }
        mapping
            .commit(mapping_offset, size)
            .map_err(ProcessSharedArenaError::Mapping)?;
        Ok(())
    }

    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    #[inline]
    pub(crate) fn test_registry_count(self) -> Result<usize, ProcessSharedArenaError> {
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

    /// Blocks only for W03's one exact post-owner-exit terminal mutation
    /// after this pair's map/arena identity has already been proven.
    ///
    /// This delegates the PageMap's deliberately exceptional blocking
    /// boundary. It does not alter ordinary `begin_page_lifecycle` admission,
    /// create a general PageMap lock, or grant another page/route owner.
    ///
    /// # Safety
    ///
    /// The caller must satisfy
    /// [`ProcessPageMapLease::begin_blocking_exact_post_owner_exit_mutation`]'s
    /// W07-claim, exact-terminal-tail, and explicit-release-or-retention
    /// contract.
    #[inline]
    pub(crate) unsafe fn begin_blocking_exact_post_owner_exit_mutation(
        self,
    ) -> Result<ProcessPageMapMutationLease, ProcessPageArenaLeaseError> {
        // SAFETY: the caller supplies the delegated W03 exact-terminal
        // mutation contract; this pairing only preserves map/arena identity.
        unsafe { self.page_map.begin_blocking_exact_post_owner_exit_mutation() }
            .map_err(ProcessPageArenaLeaseError::PageMap)
    }

    /// Borrows the paired process PageMap for structural operations on exact
    /// ranges whose complete page lifetime the caller owns.
    ///
    /// # Safety
    ///
    /// The caller must satisfy
    /// [`ProcessPageMapLease::page_map_for_owned_ranges`]'s exact-range,
    /// no-overlap, metadata-lifetime, and unregister-before-release contract.
    /// The paired arena identity does not add global PageMap mutation or
    /// terminal-release authority.
    #[inline]
    pub(crate) unsafe fn page_map_for_owned_ranges(
        self,
    ) -> Result<&'static crate::page_map::PageMap, ProcessPageArenaLeaseError> {
        // SAFETY: the caller supplies the delegated exact-range PageMap
        // operation contract; this pairing only preserves map/arena identity.
        unsafe { self.page_map.page_map_for_owned_ranges() }
            .map_err(ProcessPageArenaLeaseError::PageMap)
    }

    /// Borrows the exact registry-published arena after pairing validation.
    #[inline]
    pub(crate) fn arena(self) -> Result<ArenaView<'static>, ProcessPageArenaLeaseError> {
        self.arena.arena().map_err(ProcessPageArenaLeaseError::Arena)
    }

    /// Returns the paired PageMap's stable root identity without borrowing
    /// any source-plain entry. A consuming post-exit handoff uses this only
    /// to reject a different test/process map before it transfers its short
    /// route into a long mutation lease.
    #[inline]
    pub(crate) fn page_map_root(
        self,
    ) -> Result<NonNull<crate::page_map::PageMapHeader>, ProcessPageArenaLeaseError> {
        self.page_map.root().map_err(ProcessPageArenaLeaseError::PageMap)
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

    /// Commits one selected on-demand page prefix or extension without
    /// yielding mapping ownership or altering the arena's complete-slice
    /// commitment accounting.
    #[inline]
    pub(crate) fn commit_page_area(
        self,
        memory: crate::types::MemoryId,
        offset: usize,
        size: usize,
    ) -> Result<(), ProcessPageArenaLeaseError> {
        self.arena
            .commit_page_area(memory, offset, size)
            .map_err(ProcessPageArenaLeaseError::Arena)
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
    /// A page lifecycle capability named a non-arena, foreign, overflowing,
    /// or out-of-span direct commitment range.
    InvalidPageArea,
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

/// A source-shaped explicit OS-reservation failure.
///
/// `Rejected` has released every unpublished mapping and leaves the selected
/// sidecar retryable when its state is COLD. `Retained` records that an arena,
/// registry, failed-release mapping, or already-selected incompatible process
/// identity prevents a caller from assuming a fresh reservation boundary.
#[must_use = "an OS-reservation failure records retryable or terminal mapping ownership"]
pub(crate) enum ProcessSharedArenaReserveFailure {
    Rejected {
        error: ProcessSharedArenaReserveError,
    },
    Retained {
        error: ProcessSharedArenaReserveError,
    },
}

impl ProcessSharedArenaReserveFailure {
    #[inline]
    fn rejected(error: ProcessSharedArenaReserveError) -> Self {
        Self::Rejected { error }
    }

    #[inline]
    fn retained(error: ProcessSharedArenaReserveError) -> Self {
        Self::Retained { error }
    }

}

/// One concrete regular-OS reservation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessSharedArenaReserveError {
    /// The source request was zero before slice rounding.
    InvalidRequest,
    /// The source request, including automatic reserve headroom when present,
    /// cannot fit the bounded regular one-arena path.
    RequestTooLarge,
    /// Slice rounding overflowed before any map was attempted.
    SizeOverflow,
    /// The rounded request would not become exactly one complete arena.
    InvalidOneArena,
    PageMap(ProcessPageMapError),
    Mapping(Errno),
    PairMismatch,
    AlreadyInstalled,
    /// In-place source management failed after the new regular map existed.
    Manage(ProcessSharedArenaError),
    /// Source management failed and the matching regular-map release failed.
    Release {
        manage: ProcessSharedArenaError,
        unmap: Errno,
    },
    Lock(Errno),
    Retained,
}

enum ProcessSharedArenaReservationAttempt {
    Ready(ProcessSharedArenaLease),
    Rejected(ProcessSharedArenaReserveError),
    Retained(ProcessSharedArenaReserveError),
}

/// The frozen first-arena result of `mi_arena_reserve` before a mapping exists.
///
/// The v3.5.0 source uses mutable option descriptors and the number of already
/// registered arenas. This bounded owner admits only the first automatic arena,
/// so this carries its exact default policy without inventing an option store
/// or claiming the later count-scaling branches.
#[derive(Clone, Copy)]
struct DefaultOsArenaReservation {
    primary_size: usize,
    fallback_size: Option<usize>,
    access: MapAccess,
}

#[derive(Clone, Copy)]
enum ManagedArenaBacking {
    External,
    RegularOs,
}

/// Immutable process-image identity selected before mapping a new arena.
#[derive(Clone, Copy)]
struct ProcessArenaPair {
    root: NonNull<PageMapHeader>,
    config: MemoryConfig,
    subprocess: &'static MainSubprocess,
}

impl ProcessArenaPair {
    fn from_page_map(page_map: ProcessPageMapLease) -> Result<Self, ProcessPageMapError> {
        Ok(Self {
            root: page_map.root()?,
            config: page_map.memory_config()?,
            subprocess: page_map.subprocess()?,
        })
    }
}

#[derive(Clone, Copy)]
struct ProcessArenaCandidate {
    pair: ProcessArenaPair,
    base: *mut u8,
    length: usize,
}

impl ProcessArenaCandidate {
    fn from_page_map_and_mapping(
        page_map: ProcessPageMapLease,
        mapping: &Mapping,
    ) -> Result<Self, ProcessSharedArenaError> {
        let pair = ProcessArenaPair::from_page_map(page_map)
            .map_err(ProcessSharedArenaError::PageMap)?;
        Self::from_pair_and_mapping(pair, mapping)
    }

    fn from_pair_and_mapping(
        pair: ProcessArenaPair,
        mapping: &Mapping,
    ) -> Result<Self, ProcessSharedArenaError> {
        if mapping.page_size() != pair.config.page_size() {
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
            pair,
            base,
            length,
        })
    }
}

fn one_regular_os_arena_length(
    requested_size: usize,
) -> Result<usize, ProcessSharedArenaReserveError> {
    if requested_size == 0 {
        return Err(ProcessSharedArenaReserveError::InvalidRequest);
    }
    if requested_size > MAX_ALLOC_SIZE {
        return Err(ProcessSharedArenaReserveError::RequestTooLarge);
    }
    let length = invariants::align_up(requested_size, ARENA_SLICE_SIZE)
        .ok_or(ProcessSharedArenaReserveError::SizeOverflow)?;
    let plan = ExternalArenaPlan::from_address(ARENA_ALIGNMENT, length)
        .ok_or(ProcessSharedArenaReserveError::InvalidOneArena)?;
    if plan.prefix_bytes() != 0 || plan.total_size() != length || plan.arena_count() != 1 {
        return Err(ProcessSharedArenaReserveError::InvalidOneArena);
    }
    Ok(length)
}

/// Selects the first regular source arena from `mi_arena_reserve`.
///
/// `requested_size` is the current fresh page's slice-rounded size before the
/// source adds `MI_ARENA_MAX_CHUNK_OBJ_SIZE` for metadata/headroom. On the
/// first arena, v3.5.0 does not apply its later `arena_count / 8` growth; it
/// starts with the 64-bit default 1 GiB, clamps it to one arena, and uses the
/// 128 MiB retry only when that retry can still contain the request. The
/// normal Linux default `arena_eager_commit == 2` commits the arena mapping on
/// an overcommit kernel; `allow_large_os_pages` is false in this frozen profile.
fn default_os_arena_reservation(
    config: MemoryConfig,
    requested_size: usize,
) -> Result<DefaultOsArenaReservation, ProcessSharedArenaReserveError> {
    if requested_size == 0 {
        return Err(ProcessSharedArenaReserveError::InvalidRequest);
    }
    if requested_size > MAX_ALLOC_SIZE {
        return Err(ProcessSharedArenaReserveError::RequestTooLarge);
    }
    let with_page_headroom = requested_size
        .checked_add(ARENA_MAX_CHUNK_OBJ_SIZE)
        .ok_or(ProcessSharedArenaReserveError::SizeOverflow)?;
    let required_size = invariants::align_up(with_page_headroom, ARENA_MAX_CHUNK_OBJ_SIZE)
        .ok_or(ProcessSharedArenaReserveError::SizeOverflow)?;

    // `src/arena.c` reduces the option before clamping only on targets that
    // cannot reserve virtual address space. Linux/AArch64 has that facility,
    // but retain the source decision so this policy has no hidden platform
    // assumption beyond the frozen `MemoryConfig` observation.
    let base_size = if config.has_virtual_reserve() {
        DEFAULT_ARENA_RESERVE
    } else {
        DEFAULT_ARENA_RESERVE / 4
    };
    let base_size = invariants::align_up(base_size, ARENA_SLICE_SIZE)
        .ok_or(ProcessSharedArenaReserveError::SizeOverflow)?;
    let primary_size = base_size
        .max(required_size)
        .max(ARENA_MIN_SIZE)
        .min(ARENA_MAX_SIZE);
    if primary_size < required_size {
        return Err(ProcessSharedArenaReserveError::RequestTooLarge);
    }
    // `MI_DEFAULT_ARENA_EAGER_COMMIT == 2` and
    // `MI_DEFAULT_ALLOW_LARGE_OS_PAGES == 0`: source eagerly maps only when
    // the live Linux configuration reports overcommit.
    let access = if config.has_overcommit() {
        MapAccess::Committed
    } else {
        MapAccess::Reserved
    };
    let fallback_size = (primary_size > DEFAULT_SMALL_ARENA_RESERVE
        && DEFAULT_SMALL_ARENA_RESERVE > required_size)
        .then_some(DEFAULT_SMALL_ARENA_RESERVE);

    // The ordinary reservation entry retains the one-arena structural proof,
    // including source slice rounding and the metadata-alignment requirement.
    one_regular_os_arena_length(primary_size)?;
    if let Some(fallback_size) = fallback_size {
        one_regular_os_arena_length(fallback_size)?;
    }
    Ok(DefaultOsArenaReservation {
        primary_size,
        fallback_size,
        access,
    })
}

static PROCESS_SHARED_ARENA: ProcessSharedArenaStorage = ProcessSharedArenaStorage::new();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::ArenaId;
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE, ARENA_SLICE_SIZE};
    use crate::os::{fault, MapAccess, PageSize};
    use crate::process_page_map::ProcessPageMapStorage;
    use crabc_core::Errno;

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

    #[test]
    fn explicit_os_reservation_publishes_one_os_arena_for_reserved_and_committed_requests() {
        for access in [MapAccess::Reserved, MapAccess::Committed] {
            let _fault = fault::install(fault::Plan::disabled());
            let config = memory_config();
            let subprocess = MainSubprocess::test_static_owner();
            let page_map = initialized_map(config, subprocess);
            let storage = ProcessSharedArenaStorage::test_static_owner();

            let lease = match storage.reserve_one_os_arena(page_map, ARENA_MIN_SIZE, access) {
                Ok(lease) => lease,
                Err(_) => panic!("one caller-selected regular OS arena reserves and publishes"),
            };
            let arena = lease.arena().expect("the reserved OS arena remains published");
            assert_eq!(arena.arena().memid.kind(), crate::types::MemoryKind::Os);
            assert_eq!(arena.arena().memid.initially_committed(), access == MapAccess::Committed);
            assert!(arena.arena().memid.initially_zero());
            assert_eq!(lease.test_registry_count().unwrap(), 1);
            assert_eq!(
                unsafe { page_map.page_map().unwrap().checked_lookup(arena.slice_start(0).unwrap()) },
                core::ptr::null_mut(),
                "reservation publishes no page before a typed page owner begins"
            );
        }
    }

    #[test]
    fn default_os_reservation_is_lazy_and_uses_the_pinned_first_arena_policy() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();

        assert!(storage.test_is_cold(), "process initialization does not pre-reserve an arena");
        let lease = match storage.reserve_default_os_arena(page_map, 1) {
            Ok(lease) => lease,
            Err(_) => panic!("the first source fresh-page miss reserves its default arena"),
        };
        let arena = lease.arena().expect("the default arena remains published");
        assert_eq!(arena.size(), Some(crate::config::GIB));
        assert!(
            !arena.arena().memid.initially_committed(),
            "the non-overcommit fixture preserves source lazy page commitment"
        );
        assert_eq!(lease.test_registry_count().unwrap(), 1);
        assert!(
            unsafe { page_map.page_map().unwrap().checked_lookup(arena.slice_start(0).unwrap()) }
                .is_null(),
            "reservation alone never manufactures a fresh page-map entry"
        );
    }

    #[test]
    fn default_os_reservation_retries_the_pinned_smaller_arena_after_its_first_map_failure() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));

        let lease = match storage.reserve_default_os_arena(page_map, ARENA_SLICE_SIZE) {
            Ok(lease) => lease,
            Err(_) => panic!("the source default-reserve fallback publishes its smaller arena"),
        };
        assert_eq!(
            lease.arena().unwrap().size(),
            Some(4 * ARENA_MIN_SIZE),
            "a failed 1 GiB first attempt retries the source 128 MiB arena"
        );
        assert!(fault.observed() >= 2, "the failed primary map is followed by a distinct fallback map");
    }

    #[test]
    fn default_os_reservation_releases_both_failed_attempts_before_retrying_from_cold() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Map,
            1,
            fault::Point::Map,
            2,
            Errno::NOMEM,
        ));

        match storage.reserve_default_os_arena(page_map, ARENA_SLICE_SIZE) {
            Err(ProcessSharedArenaReserveFailure::Rejected { .. }) => {}
            Err(ProcessSharedArenaReserveFailure::Retained { error }) => {
                panic!("a failed default reservation must not retain a map: {error:?}")
            }
            Ok(_) => panic!("the paired mapping failures cannot publish an arena"),
        }
        assert!(storage.test_is_cold());
        assert_eq!(storage.registry.count(), 0);
        assert!(
            fault.observed() >= 2,
            "the source fallback performs a distinct final reservation attempt"
        );

        fault.set(fault::Plan::disabled());
        let lease = match storage.reserve_default_os_arena(page_map, ARENA_SLICE_SIZE) {
            Ok(lease) => lease,
            Err(_) => panic!("a pair of map failures retains no owner and stays retryable"),
        };
        assert_eq!(lease.arena().unwrap().size(), Some(crate::config::GIB));
    }

    #[test]
    fn default_os_reservation_plan_preserves_headroom_commit_and_retry_boundaries() {
        let reserved = default_os_arena_reservation(memory_config(), ARENA_SLICE_SIZE)
            .expect("a small fresh page fits the first default arena");
        assert_eq!(reserved.primary_size, crate::config::GIB);
        assert_eq!(reserved.fallback_size, Some(4 * ARENA_MIN_SIZE));
        assert_eq!(reserved.access, MapAccess::Reserved);

        let overcommit = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(),
            1024 * 1024,
            true,
            false,
        );
        assert_eq!(
            default_os_arena_reservation(overcommit, ARENA_SLICE_SIZE)
                .expect("the overcommit profile remains a valid source default")
                .access,
            MapAccess::Committed,
            "arena_eager_commit == 2 commits only on an overcommit kernel"
        );

        let request = crate::config::GIB;
        let enlarged = default_os_arena_reservation(memory_config(), request)
            .expect("the source adds one max-page headroom chunk before reserving");
        assert_eq!(
            enlarged.primary_size,
            crate::config::GIB + ARENA_MAX_CHUNK_OBJ_SIZE
        );
        assert_eq!(enlarged.fallback_size, None);
        assert!(matches!(
            default_os_arena_reservation(memory_config(), ARENA_MAX_SIZE),
            Err(ProcessSharedArenaReserveError::RequestTooLarge)
        ), "a fresh page that cannot fit with its source headroom never maps a partial arena");
    }

    #[test]
    fn default_os_reservation_retains_an_already_published_first_arena() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();

        let first = match storage.reserve_default_os_arena(page_map, ARENA_SLICE_SIZE) {
            Ok(first) => first,
            Err(_) => panic!("the first default arena publishes"),
        };
        assert_eq!(first.arena().unwrap().size(), Some(crate::config::GIB));
        match storage.reserve_default_os_arena(page_map, ARENA_SLICE_SIZE) {
            Err(ProcessSharedArenaReserveFailure::Retained {
                error: ProcessSharedArenaReserveError::AlreadyInstalled,
            }) => {}
            Err(ProcessSharedArenaReserveFailure::Rejected { error }) => panic!(
                "an already-published first arena is not a retryable cold rejection: {error:?}"
            ),
            Err(ProcessSharedArenaReserveFailure::Retained { error }) => {
                panic!("the published first arena retains its exact ownership: {error:?}")
            }
            Ok(_) => panic!("the one-arena default policy cannot publish a second first arena"),
        }
    }

    #[test]
    fn explicit_os_reservation_rejects_invalid_or_second_requests_before_mapping() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));

        assert!(matches!(
            storage.reserve_one_os_arena(page_map, 0, MapAccess::Reserved),
            Err(ProcessSharedArenaReserveFailure::Rejected {
                error: ProcessSharedArenaReserveError::InvalidRequest,
            })
        ));
        assert_eq!(fault.observed(), 0, "an invalid request never reaches mmap");
        assert!(storage.test_is_cold());

        assert!(matches!(
            storage.reserve_one_os_arena(
                page_map,
                ARENA_MIN_SIZE + ARENA_SLICE_SIZE,
                MapAccess::Reserved,
            ),
            Err(ProcessSharedArenaReserveFailure::Rejected {
                error: ProcessSharedArenaReserveError::InvalidOneArena,
            })
        ));
        assert_eq!(
            fault.observed(),
            0,
            "a rounded request with an unmanaged tail never reaches mmap"
        );
        assert!(storage.test_is_cold());

        fault.set(fault::Plan::disabled());
        let selected = match storage.reserve_one_os_arena(page_map, ARENA_MIN_SIZE, MapAccess::Committed) {
            Ok(lease) => lease,
            Err(_) => panic!("the selected OS reservation publishes"),
        };
        let root = selected.root().unwrap();
        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            storage.reserve_one_os_arena(page_map, ARENA_MIN_SIZE, MapAccess::Committed),
            Err(ProcessSharedArenaReserveFailure::Rejected {
                error: ProcessSharedArenaReserveError::AlreadyInstalled,
            })
        ));
        assert_eq!(fault.observed(), 0, "a repeated reservation cannot create a second mapping");

        fault.set(fault::Plan::disabled());
        let foreign_map = initialized_map(config, MainSubprocess::test_static_owner());
        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            storage.reserve_one_os_arena(foreign_map, ARENA_MIN_SIZE, MapAccess::Committed),
            Err(ProcessSharedArenaReserveFailure::Rejected {
                error: ProcessSharedArenaReserveError::PairMismatch,
            })
        ));
        assert_eq!(fault.observed(), 0, "a foreign root rejects before mapping");
        assert_eq!(selected.root().unwrap(), root);
        assert_eq!(selected.test_registry_count().unwrap(), 1);
    }

    #[test]
    fn explicit_os_reservation_unmaps_a_failed_metadata_setup_and_allows_the_selected_retry() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let root = page_map.root().unwrap();
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let fault = fault::install(fault::Plan::at(
            fault::Point::Commit,
            1,
            Errno::NOMEM,
        ));

        assert!(matches!(
            storage.reserve_one_os_arena(page_map, ARENA_MIN_SIZE, MapAccess::Reserved),
            Err(ProcessSharedArenaReserveFailure::Rejected {
                error: ProcessSharedArenaReserveError::Manage(
                    ProcessSharedArenaError::Arena(ManageArenaError::CommitFailed),
                ),
            })
        ));
        assert!(storage.test_is_cold());
        assert_eq!(storage.registry.count(), 0);
        assert_eq!(page_map.root().unwrap(), root);

        fault.set(fault::Plan::disabled());
        let lease = match storage.reserve_one_os_arena(page_map, ARENA_MIN_SIZE, MapAccess::Reserved) {
            Ok(lease) => lease,
            Err(_) => panic!("the selected source pair retries after successful unmap"),
        };
        assert_eq!(lease.root().unwrap(), root);
        assert_eq!(lease.test_registry_count().unwrap(), 1);
        assert_eq!(lease.arena().unwrap().arena().memid.kind(), crate::types::MemoryKind::Os);
    }

    #[test]
    fn explicit_os_reservation_retains_the_mapping_when_failed_setup_cannot_unmap() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit,
            1,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));

        assert!(matches!(
            storage.reserve_one_os_arena(page_map, ARENA_MIN_SIZE, MapAccess::Reserved),
            Err(ProcessSharedArenaReserveFailure::Retained {
                error: ProcessSharedArenaReserveError::Release {
                    manage: ProcessSharedArenaError::Arena(ManageArenaError::CommitFailed),
                    unmap: Errno::NOMEM,
                },
            })
        ));
        assert_eq!(storage.test_state(), RETAINED);
        assert_eq!(storage.registry.count(), 0);

        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            storage.reserve_one_os_arena(page_map, ARENA_MIN_SIZE, MapAccess::Reserved),
            Err(ProcessSharedArenaReserveFailure::Retained {
                error: ProcessSharedArenaReserveError::Retained,
            })
        ));
        assert_eq!(fault.observed(), 0, "the retained reservation never loses its mapping to a retry");
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
        assert_eq!(lease.test_registry_count().unwrap(), 1);
        let arena = lease.arena().unwrap();
        assert_eq!(arena.slice_start(0), Some(base));
        assert_eq!(arena.size(), Some(ARENA_MIN_SIZE));
        let pages = unsafe { arena.pages() }.expect("the main pages bitmap exists");
        assert_eq!(pages.is_clear_range(0, pages.max_bits()), Some(true));
        assert!(unsafe { page_map.page_map().unwrap().checked_lookup(base) }.is_null());
    }

    #[test]
    fn reserved_owned_arena_commits_metadata_and_claims_slices_through_its_stable_mapping() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let root = page_map.root().unwrap();
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let reserved = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Reserved,
        )
        .expect("map one reserved source-sized arena backing");
        let base = reserved.base().expect("the caller still owns the reserved mapping");

        let lease = match storage.install_one_owned_external_arena(page_map, reserved) {
            Ok(lease) => lease,
            Err(_) => panic!("the process-owned mapping commits its arena metadata"),
        };
        assert_eq!(lease.root().unwrap(), root);
        assert_eq!(lease.test_registry_count().unwrap(), 1);
        let arena = lease.arena().expect("the committed reserved arena publishes");
        assert_eq!(arena.slice_start(0), Some(base));

        let claim = arena
            .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
            .expect("the same stable callback commits a selected arena slice");
        let slice = claim.slice_index();
        assert!(claim.memory_id().initially_committed());
        assert!(
            claim.page_metadata().is_some(),
            "page metadata commitment uses the same process-owned mapping callback"
        );
        assert_eq!(
            unsafe { arena.slices_committed() }
                .expect("the arena retains its source commitment bitmap")
                .is_set_range(slice, 1),
            Some(true),
            "the selected data slice becomes committed only through the callback"
        );
        assert!(claim.release(), "the one committed claim returns to its source free bitmap");
        assert!(
            arena.collect_scheduled_purge(config.page_size(), true),
            "the stable callback also owns the later source decommit request"
        );
        assert_eq!(
            unsafe { arena.slices_committed() }
                .expect("the source commitment bitmap remains readable")
                .is_set_range(slice, 1),
            Some(true),
            "the default Linux decommit callback reports that reuse needs no recommit"
        );
    }

    #[test]
    fn paired_page_lease_commits_one_page_area_without_marking_a_full_arena_slice() {
        let fault = fault::install(fault::Plan::disabled());
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let reserved = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Reserved,
        )
        .expect("map one reserved source-sized arena backing");
        let shared = match storage.install_one_owned_external_arena(page_map, reserved) {
            Ok(shared) => shared,
            Err(_) => panic!("the reserved backing publishes its stable callback owner"),
        };
        let pair = ProcessPageArenaLease::join(page_map, shared)
            .expect("the map and retained arena form one page-area capability");
        let arena = pair.arena().expect("the paired arena remains published");
        let claim = arena
            .try_claim_suitable_slices(ArenaId::none(), 1, false, 0)
            .expect("the fixture reserves one source on-demand slice");
        let memory = claim.memory_id();
        let slice = claim.slice_index();
        assert!(!memory.initially_committed());
        assert_eq!(
            unsafe { arena.slices_committed() }
                .expect("the full-slice accounting bitmap is readable")
                .is_clear_range(slice, 1),
            Some(true),
            "the reserved source page starts without a complete committed slice"
        );

        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        assert_eq!(
            pair.commit_page_area(memory, 0, config.page_size().bytes()),
            Err(ProcessPageArenaLeaseError::Arena(
                ProcessSharedArenaError::Mapping(Errno::NOMEM)
            )),
            "the narrow page-area capability reaches the retained mapping directly"
        );
        fault.set(fault::Plan::disabled());
        pair.commit_page_area(memory, 0, config.page_size().bytes())
            .expect("the exact failed page area remains retryable through the stable mapping");
        assert_eq!(
            unsafe { arena.slices_committed() }
                .expect("the source commitment bitmap remains readable")
                .is_clear_range(slice, 1),
            Some(true),
            "a partial page-area commit never manufactures complete-slice accounting"
        );
        assert_eq!(
            pair.commit_page_area(memory, ARENA_SLICE_SIZE, config.page_size().bytes()),
            Err(ProcessPageArenaLeaseError::Arena(
                ProcessSharedArenaError::InvalidPageArea
            )),
            "the capability rejects a range beyond the exact claimed page span"
        );
        assert!(claim.release(), "the isolated source claim returns to its free bitmap");
    }

    #[test]
    fn reserved_owned_arena_commit_failure_returns_the_unpublished_mapping_for_retry() {
        let config = memory_config();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map = initialized_map(config, subprocess);
        let root = page_map.root().unwrap();
        let storage = ProcessSharedArenaStorage::test_static_owner();
        let fault = fault::install(fault::Plan::at(
            fault::Point::Commit,
            1,
            Errno::NOMEM,
        ));
        let reserved = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Reserved,
        )
        .expect("map an intentionally inaccessible arena candidate");
        let base = reserved
            .base()
            .expect("the caller owns the candidate before installation");

        let failure = match storage.install_one_owned_external_arena(page_map, reserved) {
            Ok(_) => panic!("the injected owned-mapping commit failure cannot publish an arena"),
            Err(failure) => failure,
        };
        let (error, mut returned) = take_returned_mapping(failure);
        assert_eq!(error, ProcessSharedArenaError::Arena(ManageArenaError::CommitFailed));
        assert_eq!(storage.test_state(), COLD);
        assert_eq!(storage.registry.count(), 0);
        assert_eq!(page_map.root().unwrap(), root);
        assert_eq!(
            returned.base().expect("the returned mapping remains live"),
            base,
            "failed in-place metadata commitment returns the exact selected mapping"
        );
        fault.set(fault::Plan::disabled());
        assert!(
            returned
                .commit(0, config.page_size().bytes())
                .expect("the unpublished mapping remains live after commit failure")
                .is_some(),
            "the returned mapping retains its exact commit authority"
        );

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
        assert_eq!(lease.test_registry_count().unwrap(), 1);
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
        assert_eq!(selected.test_registry_count().unwrap(), 1);
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
