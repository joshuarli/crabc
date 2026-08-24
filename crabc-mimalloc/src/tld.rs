// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h:690-701` and
// `src/init.c:236-282` (`mi_tld_init`, `mi_tld_create`, and `mi_tld_free`).
// This is the deliberately unattached metadata allocation portion only:
// there is no subprocess counter, process-main static TLD, theap list,
// default/cached/fast TLS publication, or pthread lifecycle integration.

//! Bounded current-thread `mi_tld_t` ownership.
//!
//! Pinned mimalloc allocates one full TLD from its detached metadata theap,
//! records the caller's thread identity, sequence and NUMA observation, and
//! then links it into a process/subprocess and theap lifecycle. This module
//! preserves the allocation, field initialization, current-`TPIDR_EL0`
//! authority, invalidation, and metadata-release portions without inventing
//! the missing process state. The caller supplies the source-issued old
//! `thread_total_count` result explicitly; no global counter is introduced.

use core::marker::PhantomData;
use core::mem::size_of;
use core::pin::Pin;

use crate::compiler_tls::current_thread_identity;
use crate::meta::{MetaAllocation, MetaAllocator, MetaError};
use crate::os::{MemoryConfig, numa_node};
use crate::types::{LiveThreadId, ThreadLocalData, ThreadSequence};

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
    /// The detached metadata owner could not allocate or release the TLD.
    Metadata(MetaError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadLocalDataState {
    Active,
    TornDown,
    Poisoned,
}

/// One owner-bound, source-shaped current-thread `mi_tld_t` allocation.
///
/// This owner intentionally has no compiler-TLS root. It does not make a
/// second process/TLD registry and cannot detect a duplicate inactive owner,
/// so construction is unsafe. It is `!Send` and `!Sync`; every operation
/// rechecks the exact direct `TPIDR_EL0` identity captured at construction.
/// This checkpoint exposes only the explicitly unattached state: its
/// subprocess and theap-list fields remain null and it is not published to a
/// default or cached theap root. A later audited owner-controlled lifecycle
/// may add the source `Unattached -> Attached -> Detached` transition; raw or
/// external publication remains outside this owner contract.
#[must_use = "current-thread TLD owners must explicitly tear down their metadata allocation"]
pub(crate) struct ThreadLocalDataOwner {
    metadata: Pin<&'static MetaAllocator>,
    thread: LiveThreadId,
    sequence: ThreadSequence,
    allocation: Option<MetaAllocation<'static>>,
    state: ThreadLocalDataState,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ThreadLocalDataOwner {
    /// Creates one unattached current-thread TLD through the process metadata
    /// allocator.
    ///
    /// `sequence` must be the previous value returned by the future
    /// source-shaped relaxed `subproc->thread_total_count` increment. This
    /// method deliberately does not own or emulate that counter.
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
    /// must call [`Self::teardown`] exactly once while this checkpoint remains
    /// unattached.
    pub(crate) unsafe fn begin(
        config: MemoryConfig,
        sequence: ThreadSequence,
    ) -> Result<Self, ThreadLocalDataError> {
        // SAFETY: forwarded unchanged to the common private constructor; the
        // process-static metadata owner has the required process lifetime.
        unsafe { Self::begin_with_metadata(MetaAllocator::global(), config, sequence) }
    }

    /// Returns the fully initialized, still-unattached TLD after validating
    /// its current-thread and metadata-provenance invariants.
    pub(crate) fn current(&mut self) -> Result<&ThreadLocalData, ThreadLocalDataError> {
        Ok(self.current_mut()?)
    }

    /// Runs the bounded source teardown order: invalidate the thread ID, then
    /// attempt metadata release.
    ///
    /// Full `mi_tld_free` additionally decrements the subprocess thread count
    /// and calls the pthread-lock destructor. This owner has never attached a
    /// subprocess or a theap list, and its private lock has no waiters under
    /// the unsafe lifecycle contract, so it performs neither absent operation.
    /// If metadata release reports a consumption-ambiguous failure, the TLD
    /// was already invalidated and the owner becomes terminal rather than
    /// claiming a retryable raw allocation.
    pub(crate) fn teardown(&mut self) -> Result<(), ThreadLocalDataError> {
        self.ensure_active_current()?;
        self.current_mut()?.invalidate_unattached_for_teardown();
        let mut allocation = self
            .allocation
            .take()
            .ok_or(ThreadLocalDataError::Projection)?;
        match self.metadata.free(&mut allocation) {
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
        metadata: Pin<&'static MetaAllocator>,
        config: MemoryConfig,
        sequence: ThreadSequence,
    ) -> Result<Self, ThreadLocalDataError> {
        // SAFETY: test callers uphold the same owner contract and the helper
        // has the identical implementation path as production construction.
        unsafe { Self::begin_with_metadata(metadata, config, sequence) }
    }

    unsafe fn begin_with_metadata(
        metadata: Pin<&'static MetaAllocator>,
        config: MemoryConfig,
        sequence: ThreadSequence,
    ) -> Result<Self, ThreadLocalDataError> {
        let thread = current_thread_identity().ok_or(ThreadLocalDataError::InvalidCurrentThread)?;
        let numa = i32::try_from(numa_node()).map_err(|_| ThreadLocalDataError::NumaNodeOutOfRange)?;
        let mut allocation = metadata
            .zalloc(config, size_of::<ThreadLocalData>())
            .map_err(ThreadLocalDataError::Metadata)?;
        let initialized = allocation.initialize_thread_local_data_unattached(thread, sequence, numa);
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

        Ok(Self {
            metadata,
            thread,
            sequence,
            allocation: Some(allocation),
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
        let allocation = self
            .allocation
            .as_mut()
            .ok_or(ThreadLocalDataError::Projection)?;
        let (matches_lifecycle, memory) = {
            let tld = allocation
                .thread_local_data_mut()
                .ok_or(ThreadLocalDataError::Projection)?;
            (
                tld.matches_unattached_lifecycle(self.thread, self.sequence),
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::compiler_tls::{
        cached_theap, default_theap, dynamic_backing_peek, fast_slot_peek,
    };
    use crate::os::{PageSize, fault};
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

    fn sequence(value: usize) -> ThreadSequence {
        ThreadSequence::from_previous_total_count(value)
    }

    #[test]
    fn current_thread_tld_initializes_the_complete_unattached_source_image() {
        thread::spawn(|| {
            let identity = current_thread_identity().expect("AArch64 TPIDR_EL0 is live");
            let dynamic_before = dynamic_backing_peek();
            let fast_before = fast_slot_peek();
            let default_before = default_theap();
            let cached_before = cached_theap();
            let source_sequence = sequence(41);
            let mut owner = unsafe { ThreadLocalDataOwner::begin(memory_config(), source_sequence) }
                .expect("a fresh native thread can own one unattached TLD");
            let memory = {
                let tld = owner.current().expect("the metadata image is current and valid");

                assert_eq!(tld.thread_id(), identity.get());
                assert_eq!(tld.thread_sequence(), source_sequence);
                assert_eq!(tld.numa_node(), i32::try_from(numa_node()).unwrap());
                assert!(tld.is_unattached());
                assert!(!tld.recursing());
                assert!(
                    tld.test_theaps_lock_is_unlocked(),
                    "the source theap-list lock begins unlocked"
                );
                assert!(
                    !tld.is_in_threadpool(),
                    "the pinned Unix primitive has an exact false result"
                );
                assert_eq!(tld.memory_id().kind(), MemoryKind::Malloc);
                assert!(tld.memory_id().is_pinned());
                assert!(tld.memory_id().initially_committed());
                assert!(tld.memory_id().initially_zero());
                tld.memory_id()
            };
            assert!(owner
                .allocation
                .as_ref()
                .expect("the owner retains the TLD capability")
                .matches_memory_id(memory));
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert_eq!(fast_slot_peek(), fast_before);
            assert_eq!(default_theap(), default_before);
            assert_eq!(cached_theap(), cached_before);

            owner.teardown().expect("the isolated TLD metadata releases");
            assert!(matches!(owner.current(), Err(ThreadLocalDataError::TornDown)));
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert_eq!(fast_slot_peek(), fast_before);
            assert_eq!(default_theap(), default_before);
            assert_eq!(cached_theap(), cached_before);
        })
        .join()
        .expect("the bounded current-thread lifecycle completes");
    }

    #[test]
    fn current_thread_tld_failed_creation_stays_unpublished_and_retries() {
        let metadata = MetaAllocator::test_static_owner();
        thread::spawn(move || {
            let dynamic_before = dynamic_backing_peek();
            let fast_before = fast_slot_peek();
            let default_before = default_theap();
            let cached_before = cached_theap();
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));

            assert!(matches!(
                unsafe {
                    ThreadLocalDataOwner::begin_with_test_metadata(
                        metadata,
                        memory_config(),
                        sequence(0),
                    )
                },
                Err(ThreadLocalDataError::Metadata(MetaError::InitializationFailed))
            ));
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert_eq!(fast_slot_peek(), fast_before);
            assert_eq!(default_theap(), default_before);
            assert_eq!(cached_theap(), cached_before);

            fault.set(fault::Plan::disabled());
            let mut owner = unsafe {
                ThreadLocalDataOwner::begin_with_test_metadata(metadata, memory_config(), sequence(0))
            }
            .expect("the fresh metadata owner can retry after map failure");
            assert_eq!(owner.current().unwrap().thread_sequence(), sequence(0));
            owner.teardown().unwrap();
        })
        .join()
        .expect("the isolated metadata failure does not publish TLD state");
    }

    #[test]
    fn current_thread_tlds_are_isolated_and_sequences_remain_caller_owned() {
        const THREADS: usize = 2;
        let start = std::sync::Arc::new(Barrier::new(THREADS));
        let ready = std::sync::Arc::new(Barrier::new(THREADS + 1));
        let (sender, receiver) = mpsc::channel();
        thread::scope(|scope| {
            for sequence_value in [7usize, 99] {
                let start = start.clone();
                let ready = ready.clone();
                let sender = sender.clone();
                scope.spawn(move || {
                    let mut owner = unsafe {
                        ThreadLocalDataOwner::begin(memory_config(), sequence(sequence_value))
                    }
                    .expect("each native thread has a distinct current identity");
                    let tld = owner.current().unwrap();
                    sender
                        .send((
                            tld.thread_id(),
                            tld.thread_sequence().get(),
                            owner
                                .allocation
                                .as_ref()
                                .expect("the TLD remains capability-owned")
                                .pointer()
                                .as_ptr() as usize,
                        ))
                        .expect("the collector remains live");
                    start.wait();
                    assert_eq!(owner.current().unwrap().thread_sequence().get(), sequence_value);
                    ready.wait();
                    owner.teardown().unwrap();
                });
            }

            let first = receiver.recv().expect("first TLD reports its image");
            let second = receiver.recv().expect("second TLD reports its image");
            assert_ne!(first.0, second.0, "TPIDR_EL0 identities are per native thread");
            assert_eq!([first.1, second.1].into_iter().sum::<usize>(), 106);
            assert_ne!(first.2, second.2, "metadata capabilities own distinct TLD images");
            ready.wait();
        });
    }
}
