// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/subproc.c:12-15,95-101`
// (`mi_process_subproc_main`), `include/mimalloc/types.h:651-680`
// (`mi_subproc_t` counters), `include/mimalloc/types.h:690-701` (`mi_tld_t`),
// and `src/init.c:155-157,236-282`
// (`mi_process_tld_main`, `mi_tld_create`, and `mi_tld_free`).

//! Bounded main-subprocess thread-registration ownership.
//!
//! Upstream places a complete `mi_subproc_t` in static storage. This module
//! intentionally represents only the process-main identity plus the two
//! counters directly required by `mi_tld_create`/`mi_tld_free`: the relaxed
//! total-thread sequence and the relaxed current-thread count. It is not a
//! Rust layout claim for `mi_subproc_t`, and it supplies no subprocess list,
//! heap, arena, statistics, or public subprocess API.
//!
//! A [`ThreadRegistrationTicket`] is the old result of the source relaxed
//! `thread_total_count` increment. Tickets are consumed even when a later
//! metadata allocation fails. Only a ticket that successfully forms a TLD can
//! become a [`ThreadRegistrationLease`], which owns exactly one corresponding
//! `thread_count` increment and decrement. The first ticket owns the real
//! process-static main-TLD storage; all later tickets must use metadata.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::{MaybeUninit, size_of};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::types::{LiveThreadId, MemoryId, ThreadLocalData, ThreadSequence};

const MAIN_TLD_COLD: u8 = 0;
const MAIN_TLD_CLAIMED: u8 = 1;
const MAIN_TLD_LIVE: u8 = 2;
const MAIN_TLD_RETIRED: u8 = 3;

/// Cache-aligned backing for source-static `mi_process_tld_main`.
///
/// `mi_decl_cache_align` gives this source object the normal 64-byte cache
/// alignment. The inner image remains `MaybeUninit` until the unique
/// ticket-zero transition writes every TLD field.
#[repr(align(64))]
struct MainStaticTldSlot {
    image: MaybeUninit<ThreadLocalData>,
}

impl MainStaticTldSlot {
    const fn new() -> Self {
        Self {
            image: MaybeUninit::uninit(),
        }
    }
}

/// The deliberately bounded source identity of `mi_process_subproc_main`.
///
/// This type owns no general subprocess state. Its private static-TLD slot is
/// the actual source-shaped `mi_process_tld_main` branch selected only by
/// sequence zero; it is not a metadata allocation cache or a reusable TLD.
pub(crate) struct MainSubprocess {
    thread_count: AtomicUsize,
    thread_total_count: AtomicUsize,
    main_tld_state: AtomicU8,
    main_tld: UnsafeCell<MainStaticTldSlot>,
}

// SAFETY: the counter fields are atomic. The sole UnsafeCell is initialized
// only by the unique sequence-zero ticket, then reached exclusively through
// its `!Send` TLD owner; it is never reused after retirement.
unsafe impl Sync for MainSubprocess {}

impl MainSubprocess {
    pub(crate) const fn new() -> Self {
        Self {
            thread_count: AtomicUsize::new(0),
            thread_total_count: AtomicUsize::new(0),
            main_tld_state: AtomicU8::new(MAIN_TLD_COLD),
            main_tld: UnsafeCell::new(MainStaticTldSlot::new()),
        }
    }

    /// Returns the one process-static main-subprocess identity.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_MAIN_SUBPROCESS
    }

    /// Issues the exact old value of source `thread_total_count.fetch_add`.
    ///
    /// This happens before any metadata allocation attempt. Dropping the
    /// resulting ticket intentionally does not roll the total count back:
    /// upstream total-thread sequencing is monotonic even when TLD creation
    /// later fails.
    #[inline]
    pub(crate) fn issue_thread_ticket(&'static self) -> ThreadRegistrationTicket {
        let old = self.thread_total_count.fetch_add(1, Ordering::Relaxed);
        ThreadRegistrationTicket {
            subprocess: self,
            sequence: ThreadSequence::from_previous_total_count(old),
            _not_send_or_sync: PhantomData,
        }
    }

    /// Reserves exactly one nonzero source sequence for the bounded dynamic
    /// Theap path without consuming ticket zero.
    ///
    /// This is an intentional Rust process-selection gate, not a replacement
    /// for `mi_tld_create`'s unconditional `fetch_add`: ticket zero belongs to
    /// the separately selected static-main path in this milestone. The CAS
    /// loop is Relaxed like the source counter and prevents a read-then-add
    /// race from accidentally seizing that static ticket. Once a nonzero old
    /// value is reserved it is a normal source ticket; later TLD allocation
    /// failure still consumes it and leaves the live count unchanged.
    #[inline]
    pub(crate) fn issue_later_thread_ticket(
        &'static self,
    ) -> Result<ThreadRegistrationTicket, LaterThreadTicketError> {
        let mut observed = self.thread_total_count.load(Ordering::Relaxed);
        loop {
            if observed == 0 {
                return Err(LaterThreadTicketError::FirstTicketReserved);
            }
            match self.thread_total_count.compare_exchange_weak(
                observed,
                observed.wrapping_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(old) => {
                    return Ok(ThreadRegistrationTicket {
                        subprocess: self,
                        sequence: ThreadSequence::from_previous_total_count(old),
                        _not_send_or_sync: PhantomData,
                    });
                }
                Err(current) => observed = current,
            }
        }
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *mut Self {
        core::ptr::from_ref(self).cast_mut()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn live_thread_count(&self) -> usize {
        self.thread_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn total_thread_count(&self) -> usize {
        self.thread_total_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_static_owner() -> &'static Self {
        // Each fixture owns its isolated source-main image so tests cannot
        // depend on the process singleton's first-ticket history.
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    fn initialize_main_tld(
        &'static self,
        sequence: ThreadSequence,
        thread: LiveThreadId,
        numa_node: i32,
    ) -> Result<MainStaticThreadLocalData, MainStaticTldError> {
        if sequence.get() != 0 {
            return Err(MainStaticTldError::NotFirstTicket);
        }
        if self
            .main_tld_state
            .compare_exchange(
                MAIN_TLD_COLD,
                MAIN_TLD_CLAIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(MainStaticTldError::AlreadyUsed);
        }

        let tld = self.main_tld_ptr();
        let memid = MemoryId::static_allocation(tld.cast(), size_of::<ThreadLocalData>());
        // SAFETY: sequence zero is unique for this process-main identity and
        // the state transition above grants the only mutable initialization
        // authority over this final static slot. This writes the complete
        // image without first forming a reference to `MaybeUninit` storage.
        unsafe {
            ThreadLocalData::write_subprocess_attached_no_theap_at(
                tld,
                thread,
                sequence,
                numa_node,
                self,
                memid,
            );
        }
        // The static image is now fully initialized. Its Release publication
        // is distinct from the earlier exclusive COLD -> CLAIMED transition:
        // observers must never mistake a claimed raw slot for a live TLD.
        self.main_tld_state.store(MAIN_TLD_LIVE, Ordering::Release);

        Ok(MainStaticThreadLocalData {
            subprocess: self,
            // SAFETY: `main_tld` is an aligned static `ThreadLocalData` image
            // initialized immediately above and cannot be null.
            pointer: unsafe { NonNull::new_unchecked(tld) },
        })
    }

    fn retire_main_tld(&self, pointer: NonNull<ThreadLocalData>) {
        debug_assert_eq!(pointer.as_ptr(), self.main_tld_ptr());
        let retired = self
            .main_tld_state
            .compare_exchange(
                MAIN_TLD_LIVE,
                MAIN_TLD_RETIRED,
                Ordering::Release,
                Ordering::Acquire,
            )
            .is_ok();
        // The static projection is private to the ticket-zero owner. Once
        // its complete image was Release-published, no other transition can
        // race or legally precede this retirement; keep that proof boundary
        // structurally infallible instead of dropping a static owner on an
        // recoverable-looking error path.
        debug_assert!(retired);
    }

    #[inline]
    fn main_tld_ptr(&self) -> *mut ThreadLocalData {
        // SAFETY: taking a raw field address through the `UnsafeCell` does
        // not form a reference to the uninitialized TLD. Every later write or
        // projection is separately gated by the static-slot state machine.
        unsafe { core::ptr::addr_of_mut!((*self.main_tld.get()).image).cast() }
    }

    #[inline]
    fn increment_live_thread_count(&self) {
        self.thread_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn decrement_live_thread_count(&self) {
        let prior = self.thread_count.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(prior > 0, "a thread-registration lease cannot underflow");
    }
}

static PROCESS_MAIN_SUBPROCESS: MainSubprocess = MainSubprocess::new();

/// The source-issued old `thread_total_count` result for one TLD attempt.
///
/// It is deliberately not `Copy`: one ticket can create at most one static
/// source image or one metadata image, and only then can it be consumed into a
/// live-count lease. Its drop is an explicit failed-creation outcome, not a
/// rollback of the total-thread sequence.
#[must_use = "a source thread-registration ticket must become one TLD lease or record a failed creation"]
pub(crate) struct ThreadRegistrationTicket {
    subprocess: &'static MainSubprocess,
    sequence: ThreadSequence,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// Dynamic attachment deliberately leaves the process-main static ticket for
/// `MainStaticTheapAttachment`; this is the explicit outcome when it has not
/// yet been consumed by the selected bootstrap owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaterThreadTicketError {
    FirstTicketReserved,
}

impl ThreadRegistrationTicket {
    #[inline]
    pub(crate) const fn sequence(&self) -> ThreadSequence {
        self.sequence
    }

    #[inline]
    pub(crate) const fn is_first_main_tld(&self) -> bool {
        self.sequence.get() == 0
    }

    /// Initializes and registers the actual static `mi_process_tld_main`
    /// branch as one consuming ticket transition.
    ///
    /// No metadata allocator is touched here. The source performs this branch
    /// after issuing ticket zero, and its static `MI_MEM_STATIC` provenance is
    /// later a deliberate no-op release. The ticket is consumed only after
    /// the complete image exists; its live publication cannot escape as a
    /// separate unregistered static-storage capability.
    #[inline]
    pub(crate) fn initialize_and_activate_first_main_tld(
        self,
        thread: LiveThreadId,
        numa_node: i32,
    ) -> Result<(MainStaticThreadLocalData, ThreadRegistrationLease), MainStaticTldError> {
        let mut storage = self
            .subprocess
            .initialize_main_tld(self.sequence, thread, numa_node)?;
        debug_assert!(storage
            .current_mut()
            .matches_subprocess_attached_no_theap_lifecycle(
                thread,
                self.sequence,
                self.subprocess,
            ));
        self.subprocess.increment_live_thread_count();
        let registration = ThreadRegistrationLease {
            subprocess: self.subprocess,
            _not_send_or_sync: PhantomData,
        };
        Ok((storage, registration))
    }

    /// Consumes this ticket after its complete TLD image exists.
    ///
    /// # Safety
    ///
    /// `tld` must be the completed source-shaped
    /// subprocess-attached/no-theap image initialized by this exact ticket:
    /// it must carry `thread`, this ticket's old total-count sequence, and
    /// this ticket's process-main pointer. The only caller is the private TLD
    /// constructor immediately after its static or direct-zeroed metadata
    /// initialization; this keeps a live-count increment inseparable from a
    /// matching TLD. The debug assertion remains a focused proof witness.
    #[inline]
    pub(crate) unsafe fn activate_after_initialized_tld(
        self,
        tld: &ThreadLocalData,
        thread: LiveThreadId,
    ) -> ThreadRegistrationLease {
        debug_assert!(tld.matches_subprocess_attached_no_theap_lifecycle(
            thread,
            self.sequence,
            self.subprocess,
        ));
        self.subprocess.increment_live_thread_count();
        ThreadRegistrationLease {
            subprocess: self.subprocess,
            _not_send_or_sync: PhantomData,
        }
    }
}

/// The sole ownership record for source `thread_count` after TLD creation.
///
/// `release` consumes the lease, so one normal teardown has exactly one
/// relaxed decrement. Dropping a lease deliberately does nothing: the unsafe
/// explicit-teardown contract was violated, and silently decrementing would
/// falsely report that its still-live TLD is no longer registered.
#[must_use = "a live subprocess registration must be released exactly once"]
pub(crate) struct ThreadRegistrationLease {
    subprocess: &'static MainSubprocess,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ThreadRegistrationLease {
    #[inline]
    pub(crate) fn release(self) {
        self.subprocess.decrement_live_thread_count();
    }
}

/// A unique projection of source-static `mi_process_tld_main` storage.
pub(crate) struct MainStaticThreadLocalData {
    subprocess: &'static MainSubprocess,
    pointer: NonNull<ThreadLocalData>,
}

impl MainStaticThreadLocalData {
    #[inline]
    pub(crate) fn current_mut(&mut self) -> &mut ThreadLocalData {
        // SAFETY: only the ticket-zero owner constructs this projection. Its
        // `!Send` parent owner keeps all access current-thread exclusive until
        // the source-ordered teardown retires this static slot.
        unsafe { self.pointer.as_mut() }
    }

    #[inline]
    pub(crate) fn retire(self) {
        self.subprocess.retire_main_tld(self.pointer);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticTldError {
    NotFirstTicket,
    AlreadyUsed,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn ticket_issues_old_relaxed_sequence_and_only_a_lease_changes_live_count() {
        let main = MainSubprocess::test_static_owner();
        let first = main.issue_thread_ticket();
        let second = main.issue_thread_ticket();

        assert_eq!(first.sequence().get(), 0);
        assert_eq!(second.sequence().get(), 1);
        assert_eq!(main.total_thread_count(), 2);
        assert_eq!(main.live_thread_count(), 0);

        let ticket = main.issue_thread_ticket();
        let mut image = ThreadLocalData::detached();
        // SAFETY: this test owns a fresh local TLD image and names the exact
        // fixture subprocess/ticket before it becomes observable.
        unsafe {
            image.initialize_subprocess_attached_no_theap(
                LiveThreadId::new(12).unwrap(),
                ticket.sequence(),
                0,
                main,
                MemoryId::static_empty(),
            );
        }
        // SAFETY: `image` was initialized immediately above from this exact
        // ticket, thread identity, sequence, and subprocess fixture.
        let lease = unsafe {
            ticket.activate_after_initialized_tld(&image, LiveThreadId::new(12).unwrap())
        };
        assert_eq!(main.live_thread_count(), 1);
        lease.release();
        assert_eq!(main.live_thread_count(), 0);
    }

    #[test]
    fn later_ticket_gate_never_consumes_the_reserved_static_zero_sequence() {
        let main = MainSubprocess::test_static_owner();
        assert!(matches!(
            main.issue_later_thread_ticket(),
            Err(LaterThreadTicketError::FirstTicketReserved)
        ));
        assert_eq!(main.total_thread_count(), 0);

        let first = main.issue_thread_ticket();
        assert_eq!(first.sequence().get(), 0);
        let later = main
            .issue_later_thread_ticket()
            .expect("a consumed static ticket permits exactly the next later sequence");
        assert_eq!(later.sequence().get(), 1);
        assert_eq!(main.total_thread_count(), 2);
        assert_eq!(main.live_thread_count(), 0);
    }
}
