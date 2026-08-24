// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h:690-701` and
// `src/init.c:155-157,236-282` (`mi_process_tld_main`, `mi_tld_init`,
// `mi_tld_create`, and `mi_tld_free`).
// This is the bounded main-subprocess registration portion only: there is no
// theap list, default/cached/fast TLS publication, or pthread lifecycle
// integration.

//! Bounded current-thread `mi_tld_t` ownership.
//!
//! Pinned mimalloc allocates one full TLD from its detached metadata theap,
//! records the caller's thread identity, sequence and NUMA observation, and
//! then links it into a process/subprocess and theap lifecycle. This module
//! preserves the process-main ticket, static-first versus metadata-later
//! allocation, field initialization, current-`TPIDR_EL0` authority,
//! invalidation, and release portions without inventing a complete subprocess
//! implementation. The process-static [`MainSubprocess`] owns the source
//! relaxed sequencing and live-count state; callers cannot inject a sequence.

use core::marker::PhantomData;
use core::mem::size_of;
use core::pin::Pin;

use crate::compiler_tls::current_thread_identity;
use crate::meta::{MetaAllocation, MetaAllocator, MetaError};
use crate::os::{MemoryConfig, numa_node};
use crate::subproc::{
    MainStaticThreadLocalData, MainStaticTldError, MainSubprocess, ThreadRegistrationLease,
};
use crate::types::{
    LiveThreadId, MemoryKind, ThreadLocalData, ThreadLocalDataQuiesceError,
    ThreadSequence,
};

/// One bounded current-thread TLD lifecycle error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadLocalDataError {
    /// The calling AArch64 thread pointer did not encode a live source ID.
    InvalidCurrentThread,
    /// An owner was moved or otherwise invoked from a different thread.
    WrongThread,
    /// The caller's NUMA observation cannot fit the source's signed `int`
    /// field, so no metadata allocation was attempted.
    NumaNodeOutOfRange,
    /// The owner was explicitly torn down and cannot be reused.
    TornDown,
    /// Metadata release may have consumed the allocation before reporting an
    /// internal error, so retaining a retry capability would be unsound.
    Poisoned,
    /// An exact typed metadata allocation did not project to the full TLD
    /// layout or no longer matched its initialized bounded invariants.
    Projection,
    /// The actual source-static main-TLD branch could not establish its unique
    /// storage state.
    MainStatic(MainStaticTldError),
    /// The owner contract did not establish private theap-list lock
    /// quiescence before static retirement or metadata release.
    TheapListLock(ThreadLocalDataQuiesceError),
    /// The detached metadata owner could not allocate or release the TLD.
    Metadata(MetaError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadLocalDataState {
    Active,
    TornDown,
    Poisoned,
}

enum ThreadLocalDataStorage {
    MainStatic(MainStaticThreadLocalData),
    Metadata(MetaAllocation<'static>),
}

/// One owner-bound, source-shaped current-thread `mi_tld_t` allocation.
///
/// This owner intentionally has no compiler-TLS root. It does not make a
/// second process/TLD registry and cannot detect a duplicate inactive owner,
/// so construction is unsafe. It is `!Send` and `!Sync`; every operation
/// rechecks the exact direct `TPIDR_EL0` identity captured at construction.
/// This checkpoint is subprocess-attached with no theap: its TLD names the
/// source main subprocess and owns one current-thread registration lease, but
/// its theap-list remains null and it is not published to default/cached/fast
/// TLS roots. A later audited lifecycle may attach a theap; raw or external
/// publication remains outside this owner contract.
#[must_use = "current-thread TLD owners must explicitly tear down their metadata allocation"]
pub(crate) struct ThreadLocalDataOwner {
    metadata: Pin<&'static MetaAllocator>,
    subprocess: &'static MainSubprocess,
    thread: LiveThreadId,
    sequence: ThreadSequence,
    storage: Option<ThreadLocalDataStorage>,
    registration: Option<ThreadRegistrationLease>,
    state: ThreadLocalDataState,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ThreadLocalDataOwner {
    /// Creates one subprocess-attached/no-theap current-thread TLD.
    ///
    /// The bounded process-main owner issues the source relaxed old
    /// `thread_total_count` value itself. Ticket zero initializes the actual
    /// static `mi_process_tld_main` image without touching metadata; later
    /// tickets attempt the existing metadata route after their sequence has
    /// already been consumed.
    ///
    /// # Safety
    ///
    /// The caller must provide the exclusive lifecycle for this thread's
    /// TLD. In particular, it must not construct a second live
    /// `ThreadLocalDataOwner` for the same thread, move this owner to another
    /// thread, externally publish or retain a raw pointer to the returned
    /// TLD, or permit any concurrent reference while `teardown` may
    /// invalidate and release its metadata allocation. A future audited
    /// owner-controlled attachment transition is intentionally reserved. It
    /// must call [`Self::teardown`] exactly once while this checkpoint has no
    /// theap.
    pub(crate) unsafe fn begin(config: MemoryConfig) -> Result<Self, ThreadLocalDataError> {
        // SAFETY: forwarded unchanged to the common private constructor; the
        // process-static metadata owner has the required process lifetime.
        unsafe {
            Self::begin_with_main_and_metadata(
                MainSubprocess::global(),
                MetaAllocator::global(),
                config,
            )
        }
    }

    /// Returns the fully initialized, subprocess-attached/no-theap TLD after
    /// validating its current-thread and storage-provenance invariants.
    pub(crate) fn current(&mut self) -> Result<&ThreadLocalData, ThreadLocalDataError> {
        Ok(self.current_mut()?)
    }

    /// Runs the bounded source teardown order: decrement the live subprocess
    /// count, invalidate the thread ID, prove the private list lock quiescent,
    /// then retire static storage or attempt metadata release.
    ///
    /// The actual source-static first TLD has `MI_MEM_STATIC` provenance, so
    /// its final release is a no-op after retirement. Later metadata TLDs use
    /// the existing `MetaAllocator::free` route. A consumed/ambiguous metadata
    /// error or violated lock contract leaves this owner terminal rather than
    /// claiming a retryable raw allocation.
    pub(crate) fn teardown(&mut self) -> Result<(), ThreadLocalDataError> {
        self.ensure_active_current()?;
        // Validate the complete current image while its live-count lease is
        // still intact. A projection failure must not decrement the source
        // count and leave a valid-looking image behind.
        let _validated_tld = self.current_mut()?;
        let registration = self
            .registration
            .take()
            .ok_or(ThreadLocalDataError::Projection)?;
        registration.release();

        {
            let tld = self.current_mut()?;
            tld.invalidate_subprocess_attached_no_theap_for_teardown();
            if let Err(error) = tld.quiesce_theap_list_lock_for_teardown() {
                self.state = ThreadLocalDataState::Poisoned;
                return Err(ThreadLocalDataError::TheapListLock(error));
            }
        }

        let storage = self
            .storage
            .take()
            .ok_or(ThreadLocalDataError::Projection)?;
        match storage {
            ThreadLocalDataStorage::MainStatic(storage) => {
                storage.retire();
                self.state = ThreadLocalDataState::TornDown;
                Ok(())
            }
            ThreadLocalDataStorage::Metadata(mut allocation) => match self.metadata.free(&mut allocation) {
                Ok(()) => {
                    self.state = ThreadLocalDataState::TornDown;
                    Ok(())
                }
                Err(error) => {
                    // `MetaAllocator::free` can fail after its detached ordinary
                    // allocator consumed or linked the block. Do not retain a
                    // false capability or retry path after source invalidation.
                    self.state = ThreadLocalDataState::Poisoned;
                    Err(ThreadLocalDataError::Metadata(error))
                }
            },
        }
    }

    /// Builds an owner over an isolated process-lifetime metadata fixture for
    /// failure tests. Production code must use [`Self::begin`].
    ///
    /// # Safety
    ///
    /// This has exactly the same current-thread and exclusive-lifecycle
    /// obligations as [`Self::begin`]. `metadata` must remain a unique
    /// process-lived metadata owner for every allocation it returns.
    #[cfg(test)]
    unsafe fn begin_with_test_metadata(
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        config: MemoryConfig,
    ) -> Result<Self, ThreadLocalDataError> {
        // SAFETY: test callers uphold the same owner contract and the helper
        // has the identical implementation path as production construction.
        unsafe { Self::begin_with_main_and_metadata(subprocess, metadata, config) }
    }

    unsafe fn begin_with_main_and_metadata(
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        config: MemoryConfig,
    ) -> Result<Self, ThreadLocalDataError> {
        let thread = current_thread_identity().ok_or(ThreadLocalDataError::InvalidCurrentThread)?;
        let numa = i32::try_from(numa_node()).map_err(|_| ThreadLocalDataError::NumaNodeOutOfRange)?;
        // Source `mi_tld_create` obtains this old value before deciding
        // static-versus-metadata storage. A later allocation failure consumes
        // the total sequence but never reaches live-count registration.
        let ticket = subprocess.issue_thread_ticket();
        let sequence = ticket.sequence();

        let (storage, registration) = if ticket.is_first_main_tld() {
            let (storage, registration) = ticket
                .initialize_and_activate_first_main_tld(thread, numa)
                .map_err(ThreadLocalDataError::MainStatic)?;
            (ThreadLocalDataStorage::MainStatic(storage), registration)
        } else {
            let mut allocation = metadata
                .zalloc_for_main_subprocess(config, subprocess, size_of::<ThreadLocalData>())
                .map_err(ThreadLocalDataError::Metadata)?;
            let initialized = allocation
                .initialize_thread_local_data_subprocess_attached_no_theap(
                    thread,
                    sequence,
                    numa,
                    subprocess,
                );
            if !initialized {
                // This invariant failure has no owner to retain the capability.
                // The free result is authoritative: it may report after
                // consumption, so return that error if it does rather than
                // representing the allocation as retryable.
                return match metadata.free(&mut allocation) {
                    Ok(()) => Err(ThreadLocalDataError::Projection),
                    Err(error) => Err(ThreadLocalDataError::Metadata(error)),
                };
            }
            let registration = {
                // SAFETY: `initialized` was true for this exact exclusive
                // capability immediately above, after it wrote the complete
                // bounded TLD image; no operation intervened.
                let tld = unsafe { allocation.newly_initialized_thread_local_data_mut() };
                // SAFETY: the direct-zeroed capability was initialized above
                // with this ticket's exact thread, sequence, and subprocess.
                unsafe { ticket.activate_after_initialized_tld(tld, thread) }
            };
            (ThreadLocalDataStorage::Metadata(allocation), registration)
        };

        Ok(Self {
            metadata,
            subprocess,
            thread,
            sequence,
            storage: Some(storage),
            registration: Some(registration),
            state: ThreadLocalDataState::Active,
            _not_send_or_sync: PhantomData,
        })
    }

    #[inline]
    fn ensure_active_current(&self) -> Result<(), ThreadLocalDataError> {
        match self.state {
            ThreadLocalDataState::Active => self.ensure_current_thread(),
            ThreadLocalDataState::TornDown => Err(ThreadLocalDataError::TornDown),
            ThreadLocalDataState::Poisoned => Err(ThreadLocalDataError::Poisoned),
        }
    }

    #[inline]
    fn ensure_current_thread(&self) -> Result<(), ThreadLocalDataError> {
        match current_thread_identity() {
            Some(thread) if thread == self.thread => Ok(()),
            Some(_) => Err(ThreadLocalDataError::WrongThread),
            None => Err(ThreadLocalDataError::InvalidCurrentThread),
        }
    }

    fn current_mut(&mut self) -> Result<&mut ThreadLocalData, ThreadLocalDataError> {
        self.ensure_active_current()?;
        let storage = self
            .storage
            .as_mut()
            .ok_or(ThreadLocalDataError::Projection)?;
        match storage {
            ThreadLocalDataStorage::MainStatic(storage) => {
                let tld = storage.current_mut();
                if tld.matches_subprocess_attached_no_theap_lifecycle(
                    self.thread,
                    self.sequence,
                    self.subprocess,
                ) && tld.memory_id().kind() == MemoryKind::Static
                {
                    Ok(tld)
                } else {
                    Err(ThreadLocalDataError::Projection)
                }
            }
            ThreadLocalDataStorage::Metadata(allocation) => {
                let (matches_lifecycle, memory) = {
                    let tld = allocation
                        .thread_local_data_mut()
                        .ok_or(ThreadLocalDataError::Projection)?;
                    (
                        tld.matches_subprocess_attached_no_theap_lifecycle(
                            self.thread,
                            self.sequence,
                            self.subprocess,
                        ),
                        tld.memory_id(),
                    )
                };
                if !matches_lifecycle || !allocation.matches_memory_id(memory) {
                    return Err(ThreadLocalDataError::Projection);
                }
                allocation
                    .thread_local_data_mut()
                    .ok_or(ThreadLocalDataError::Projection)
            }
        }
    }

    #[cfg(test)]
    fn uses_main_static_storage(&self) -> bool {
        matches!(self.storage.as_ref(), Some(ThreadLocalDataStorage::MainStatic(_)))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::compiler_tls::{
        cached_theap, default_theap, dynamic_backing_peek, fast_slot_peek,
    };
    use crate::os::{PageSize, fault};
    use crate::subproc::MainSubprocess;
    use crate::types::MemoryKind;
    use std::sync::{Barrier, mpsc};
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the pinned native test page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn fixture() -> (&'static MainSubprocess, Pin<&'static MetaAllocator>) {
        (MainSubprocess::test_static_owner(), MetaAllocator::test_static_owner())
    }

    #[test]
    fn first_ticket_uses_the_real_static_main_tld_without_metadata_or_tls_publication() {
        thread::spawn(|| {
            let identity = current_thread_identity().expect("AArch64 TPIDR_EL0 is live");
            let (subprocess, metadata) = fixture();
            let dynamic_before = dynamic_backing_peek();
            let fast_before = fast_slot_peek();
            let default_before = default_theap();
            let cached_before = cached_theap();
            let mut owner = unsafe {
                ThreadLocalDataOwner::begin_with_test_metadata(
                    subprocess,
                    metadata,
                    memory_config(),
                )
            }
            .expect("ticket zero owns the source-static main TLD");
            assert!(owner.uses_main_static_storage());
            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
            {
                let tld = owner.current().expect("the metadata image is current and valid");

                assert_eq!(tld.thread_id(), identity.get());
                assert_eq!(tld.thread_sequence().get(), 0);
                assert_eq!(tld.numa_node(), i32::try_from(numa_node()).unwrap());
                assert!(tld.is_subprocess_attached_no_theap());
                assert!(tld.is_attached_to_main_subprocess(subprocess));
                assert!(!tld.recursing());
                assert!(
                    tld.test_theaps_lock_is_unlocked(),
                    "the source theap-list lock begins unlocked"
                );
                assert!(
                    !tld.is_in_threadpool(),
                    "the pinned Unix primitive has an exact false result"
                );
                assert_eq!(tld.memory_id().kind(), MemoryKind::Static);
                assert!(tld.memory_id().is_pinned());
                assert!(tld.memory_id().initially_committed());
                assert!(!tld.memory_id().initially_zero());
                assert_eq!(tld.memory_id().size(), Some(0));
                let static_memory = tld
                    .memory_id()
                    .static_memory()
                    .expect("the source static TLD records its own image");
                assert_eq!(static_memory.base, (tld as *const ThreadLocalData).cast_mut().cast());
                assert_eq!(static_memory.size, size_of::<ThreadLocalData>());
                assert_eq!(
                    (tld as *const ThreadLocalData).addr() % 64,
                    0,
                    "mi_process_tld_main retains source cache alignment"
                );
            }
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert_eq!(fast_slot_peek(), fast_before);
            assert_eq!(default_theap(), default_before);
            assert_eq!(cached_theap(), cached_before);

            owner.teardown().expect("the static TLD retires without a metadata free");
            assert!(matches!(owner.current(), Err(ThreadLocalDataError::TornDown)));
            assert_eq!(subprocess.live_thread_count(), 0);
            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert_eq!(fast_slot_peek(), fast_before);
            assert_eq!(default_theap(), default_before);
            assert_eq!(cached_theap(), cached_before);
        })
        .join()
        .expect("the bounded current-thread lifecycle completes");
    }

    #[test]
    fn later_ticket_uses_metadata_after_static_main_tld_retirement() {
        thread::spawn(move || {
            let (subprocess, metadata) = fixture();
            let mut first = unsafe {
                ThreadLocalDataOwner::begin_with_test_metadata(
                    subprocess,
                    metadata,
                    memory_config(),
                )
            }
            .unwrap();
            assert!(first.uses_main_static_storage());
            first.teardown().unwrap();

            let mut later = unsafe {
                ThreadLocalDataOwner::begin_with_test_metadata(
                    subprocess,
                    metadata,
                    memory_config(),
                )
            }
            .expect("the second ticket uses direct-zeroed metadata");
            assert!(!later.uses_main_static_storage());
            let tld = later.current().unwrap();
            assert_eq!(tld.thread_sequence().get(), 1);
            assert_eq!(tld.memory_id().kind(), MemoryKind::Malloc);
            assert!(tld.is_attached_to_main_subprocess(subprocess));
            assert_eq!(subprocess.live_thread_count(), 1);
            later.teardown().unwrap();
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join().unwrap();
    }

    #[test]
    fn metadata_allocation_failure_consumes_its_ticket_but_never_leaks_live_count() {
        let (subprocess, metadata) = fixture();
        thread::spawn(move || {
            let mut static_owner = unsafe {
                ThreadLocalDataOwner::begin_with_test_metadata(
                    subprocess,
                    metadata,
                    memory_config(),
                )
            }
            .unwrap();
            static_owner.teardown().unwrap();

            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            assert!(matches!(
                unsafe {
                    ThreadLocalDataOwner::begin_with_test_metadata(
                        subprocess,
                        metadata,
                        memory_config(),
                    )
                },
                Err(ThreadLocalDataError::Metadata(MetaError::InitializationFailed))
            ));
            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 0);

            fault.set(fault::Plan::disabled());
            let mut retry = unsafe {
                ThreadLocalDataOwner::begin_with_test_metadata(
                    subprocess,
                    metadata,
                    memory_config(),
                )
            }
            .expect("a failed metadata ticket stays consumed and later retry is sequence two");
            assert_eq!(retry.current().unwrap().thread_sequence().get(), 2);
            retry.teardown().unwrap();
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join().unwrap();
    }

    #[test]
    fn native_threads_receive_unique_source_sequences_and_exact_live_count() {
        const THREADS: usize = 3;
        let (subprocess, metadata) = fixture();
        let start = std::sync::Arc::new(Barrier::new(THREADS));
        let ready = std::sync::Arc::new(Barrier::new(THREADS + 1));
        let (sender, receiver) = mpsc::channel();
        thread::scope(|scope| {
            for _ in 0..THREADS {
                let start = start.clone();
                let ready = ready.clone();
                let sender = sender.clone();
                scope.spawn(move || {
                    let mut owner = unsafe {
                        ThreadLocalDataOwner::begin_with_test_metadata(
                            subprocess,
                            metadata,
                            memory_config(),
                        )
                    }
                    .expect("each native thread has a distinct current identity");
                    let tld = owner.current().unwrap();
                    sender
                        .send((
                            tld.thread_id(),
                            tld.thread_sequence().get(),
                            owner.uses_main_static_storage(),
                        ))
                        .expect("the collector remains live");
                    start.wait();
                    ready.wait();
                    owner.teardown().unwrap();
                });
            }

            let mut observed = [None; THREADS];
            let mut static_count = 0;
            for _ in 0..THREADS {
                let (thread, sequence, is_static) = receiver.recv().unwrap();
                assert!(thread != 0);
                observed[sequence] = Some(thread);
                static_count += usize::from(is_static);
            }
            assert!(observed.iter().all(Option::is_some));
            assert_eq!(static_count, 1);
            assert_eq!(subprocess.total_thread_count(), THREADS);
            assert_eq!(subprocess.live_thread_count(), THREADS);
            ready.wait();
        });
        assert_eq!(subprocess.live_thread_count(), 0);
    }

    struct ForeignOwner(*mut ThreadLocalDataOwner);

    // SAFETY: the focused wrong-thread test transfers sole access to a scoped
    // worker while the creating thread does not touch the owner.
    unsafe impl Send for ForeignOwner {}

    impl ForeignOwner {
        unsafe fn current(self) -> Result<(), ThreadLocalDataError> {
            // SAFETY: upheld by the scoped test's sole-access contract above.
            unsafe { (&mut *self.0).current().map(|_| ()) }
        }
    }

    #[test]
    fn owner_rejects_a_different_native_thread_before_touching_tld_state() {
        let (subprocess, metadata) = fixture();
        let mut owner = unsafe {
            ThreadLocalDataOwner::begin_with_test_metadata(subprocess, metadata, memory_config())
        }
        .unwrap();
        let foreign = ForeignOwner(core::ptr::from_mut(&mut owner));
        thread::scope(|scope| {
            let result = scope.spawn(move || unsafe { foreign.current() }).join().unwrap();
            assert_eq!(result, Err(ThreadLocalDataError::WrongThread));
        });
        assert_eq!(subprocess.live_thread_count(), 1);
        owner.teardown().unwrap();
    }

    #[test]
    fn teardown_busy_lock_poison_does_not_double_decrement_the_registration() {
        let (subprocess, metadata) = fixture();
        let mut owner = unsafe {
            ThreadLocalDataOwner::begin_with_test_metadata(subprocess, metadata, memory_config())
        }
        .unwrap();
        owner
            .current()
            .unwrap()
            .test_inject_busy_theaps_lock();
        assert_eq!(
            owner.teardown(),
            Err(ThreadLocalDataError::TheapListLock(
                ThreadLocalDataQuiesceError::Busy
            ))
        );
        assert_eq!(subprocess.live_thread_count(), 0);
        assert!(matches!(owner.current(), Err(ThreadLocalDataError::Poisoned)));
    }
}
