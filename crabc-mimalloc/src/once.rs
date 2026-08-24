// Copyright (c) 2018-2024 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/libc.c:112-140` and
// `include/mimalloc/atomic.h:544-557`. The C source obtains its current
// identity through `_mi_thread_id()`. This allocator-private Rust boundary
// instead requires the integrating runtime to pass a validated identity:
// that keeps the engine independent of public pthread/OS APIs and permits a
// host model to supply deterministic identities. Reserving 0 and 1 for the
// source state machine is a language-boundary representation requirement, not
// an algorithmic change.

//! Allocator-private initialization-once protocol.
//!
//! [`AllocatorOnce`] preserves mimalloc's three `tid` states: `0` is
//! unstarted, `1` is complete, and a value greater than `1` identifies the
//! current initializer. A successful [`AllocatorOnce::enter`] returns an
//! [`AllocatorOnceCompletion`] token, which retains the private lock across
//! the initializer. Explicitly completing that token publishes completion
//! with Release ordering before unlocking. Dropping an uncompleted token uses
//! the same completion transition as a safe Rust fallback, so safe callers
//! cannot accidentally leave the lock retained forever.
//!
//! This module only implements enter/release coordination. It does not invoke
//! an initializer callback, recover a dead owner, or provide fork repair.

use core::num::NonZeroUsize;

use crabc_core::Result;

use crate::atomic::{
    word_cas_strong_acq_rel, word_load_acquire, word_store_release, AtomicWord,
};
use crate::lock::{PrivateLock, PrivateLockGuard};

const UNSTARTED: usize = 0;
const COMPLETE: usize = 1;

/// A current-thread identity admitted to the once-state encoding.
///
/// The integrating runtime supplies this identity at the lifecycle boundary.
/// It must identify one live calling thread uniquely among concurrent calls;
/// it is compared only for recursive entry and is never dereferenced. Values
/// `0` and `1` are rejected because the pinned protocol reserves them for the
/// unstarted and complete states respectively.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OnceThreadId(NonZeroUsize);

impl OnceThreadId {
    /// Validates one identity for use with [`AllocatorOnce`].
    #[inline]
    pub(crate) const fn new(raw: usize) -> Option<Self> {
        match NonZeroUsize::new(raw) {
            Some(identity) if raw > COMPLETE => Some(Self(identity)),
            Some(_) | None => None,
        }
    }

    #[inline]
    const fn get(self) -> usize {
        self.0.get()
    }
}

/// An allocator-private equivalent of mimalloc's `mi_atomic_once_t`.
pub(crate) struct AllocatorOnce {
    tid: AtomicWord,
    lock: PrivateLock,
}

/// Proof that one caller owns an [`AllocatorOnce`] initialization.
///
/// The token is intentionally the only way to retain the once lock. Its
/// explicit [`Self::complete`] operation carries the possible private-lock
/// release error to the lifecycle caller. If that release reports an error,
/// the Release publication and atomic unlock already occurred, so callers
/// must record or escalate that error rather than retrying initialization.
#[must_use = "an initialization token must be completed or dropped"]
pub(crate) struct AllocatorOnceCompletion<'a> {
    once: &'a AllocatorOnce,
    lock: Option<PrivateLockGuard<'a>>,
}

impl AllocatorOnce {
    /// Creates an unstarted once object suitable for static storage.
    pub(crate) const fn new() -> Self {
        Self {
            tid: AtomicWord::new(UNSTARTED),
            lock: PrivateLock::new(),
        }
    }

    /// Enters the one-time initializer when this is the first caller.
    ///
    /// `Ok(Some(token))` grants the caller the initializer role and retains
    /// the private lock until the token completes. `Ok(None)` means the action
    /// is already complete, or that this identity recursively entered while it
    /// owns initialization; recursive entry never waits on itself. A private
    /// lock wait or unlock failure is returned unchanged.
    pub(crate) fn enter(
        &self,
        current_thread: OnceThreadId,
    ) -> Result<Option<AllocatorOnceCompletion<'_>>> {
        let observed = word_load_acquire(&self.tid);
        if observed == COMPLETE {
            return Ok(None);
        }
        if observed == current_thread.get() {
            return Ok(None);
        }

        // This guard stays inside the completion token on a successful CAS,
        // exactly retaining the source lock across the initializer.
        let lock = self.lock.lock()?;
        let mut expected = UNSTARTED;
        if word_cas_strong_acq_rel(&self.tid, &mut expected, current_thread.get()) {
            Ok(Some(AllocatorOnceCompletion {
                once: self,
                lock: Some(lock),
            }))
        } else {
            // Once we acquire the source lock, a failed 0 -> current-id CAS
            // means an initializer retained and released it first. Propagate
            // the private unlock result instead of hiding the boundary error.
            lock.unlock()?;
            Ok(None)
        }
    }
}

impl AllocatorOnceCompletion<'_> {
    /// Marks the action complete and releases the retained private lock.
    ///
    /// This is the typed equivalent of `_mi_atomic_once_release`: its Acquire
    /// load preserves the upstream paranoia check, its Release store publishes
    /// initializer writes as complete, and the guard then performs the lock's
    /// Release transition and possible wake.
    pub(crate) fn complete(mut self) -> Result<()> {
        self.complete_inner()
    }

    #[inline]
    fn complete_inner(&mut self) -> Result<()> {
        let Some(lock) = self.lock.take() else {
            return Ok(());
        };

        let initializing = word_load_acquire(&self.once.tid) > COMPLETE;
        debug_assert!(initializing, "a completion token owns an initializer state");
        if initializing {
            word_store_release(&self.once.tid, COMPLETE);
        }

        // `PrivateLockGuard::unlock` makes the private-futex error boundary
        // observable. Its atomic unlock has already occurred on an error.
        lock.unlock()
    }
}

impl Drop for AllocatorOnceCompletion<'_> {
    fn drop(&mut self) {
        if self.lock.is_some() {
            // The explicit method is the observable error boundary. Drop must
            // still publish completion and release the retained lock, but it
            // cannot return a private-futex wake error.
            let _completion_result = self.complete_inner();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    static STATIC_ONCE: AllocatorOnce = AllocatorOnce::new();

    fn thread_id(raw: usize) -> OnceThreadId {
        OnceThreadId::new(raw).expect("test identities avoid reserved states")
    }

    #[test]
    fn static_once_first_completion_publishes_and_stays_complete() {
        let payload = AtomicUsize::new(0);
        let completion = STATIC_ONCE
            .enter(thread_id(2))
            .expect("first static entry acquires the private lock")
            .expect("first static entry initializes");
        payload.store(0xfeed_face, Ordering::Relaxed);
        completion
            .complete()
            .expect("explicit completion releases the private lock");

        assert!(
            STATIC_ONCE
                .enter(thread_id(3))
                .expect("completed fast path has no lock error")
                .is_none(),
            "a completed once object never grants another initializer"
        );
        assert_eq!(payload.load(Ordering::Relaxed), 0xfeed_face);
    }

    #[test]
    fn current_thread_identity_reserves_once_state_values() {
        assert!(OnceThreadId::new(0).is_none());
        assert!(OnceThreadId::new(1).is_none());
        assert_eq!(thread_id(2).get(), 2);
    }

    #[test]
    fn recursive_entry_is_nonblocking_and_does_not_complete() {
        let once = AllocatorOnce::new();
        let current = thread_id(2);
        let completion = once
            .enter(current)
            .expect("first entry acquires the private lock")
            .expect("first entry initializes");

        assert!(
            once.enter(current)
                .expect("recursive entry never reaches the private lock")
                .is_none(),
            "the initializer identity observes recursive entry as already entered"
        );

        completion
            .complete()
            .expect("completion releases the retained private lock");
    }

    #[test]
    fn dropped_completion_releases_the_lock_and_marks_completion() {
        let once = AllocatorOnce::new();
        {
            let _completion = once
                .enter(thread_id(2))
                .expect("first entry acquires the private lock")
                .expect("first entry initializes");
        }

        assert!(
            once.enter(thread_id(3))
                .expect("drop released the private lock")
                .is_none(),
            "drop publishes completion rather than leaving another caller blocked"
        );
    }

    #[test]
    fn concurrent_entries_block_and_choose_one_initializer() {
        const THREADS: usize = 4;

        let once = Arc::new(AllocatorOnce::new());
        let start = Arc::new(Barrier::new(THREADS));
        let finish_initializer = Arc::new(Barrier::new(2));
        let winners = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(AtomicUsize::new(0));
        let (started_sender, started_receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::channel();
        let mut workers = std::vec::Vec::new();

        for index in 0..THREADS {
            let worker_once = Arc::clone(&once);
            let worker_start = Arc::clone(&start);
            let worker_finish = Arc::clone(&finish_initializer);
            let worker_winners = Arc::clone(&winners);
            let worker_published = Arc::clone(&published);
            let worker_started = started_sender.clone();
            let worker_done = done_sender.clone();
            workers.push(thread::spawn(move || {
                worker_start.wait();
                let initialized = match worker_once
                    .enter(thread_id(index + 2))
                    .expect("valid private lock protocol")
                {
                    Some(completion) => {
                        assert_eq!(worker_winners.fetch_add(1, Ordering::AcqRel), 0);
                        worker_started
                            .send(())
                            .expect("test receiver stays alive");
                        worker_finish.wait();
                        worker_published.store(0xabc, Ordering::Relaxed);
                        completion
                            .complete()
                            .expect("completion releases the blocked callers");
                        true
                    }
                    None => {
                        assert_eq!(
                            worker_published.load(Ordering::Relaxed),
                            0xabc,
                            "Acquire completion observation publishes initializer writes"
                        );
                        false
                    }
                };
                worker_done
                    .send(initialized)
                    .expect("test receiver stays alive");
            }));
        }
        drop(started_sender);
        drop(done_sender);

        started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("one worker becomes the initializer");
        assert!(
            done_receiver.recv_timeout(Duration::from_millis(50)).is_err(),
            "every losing caller remains blocked until the initializer completes"
        );

        finish_initializer.wait();

        let mut initialized = 0;
        for _ in 0..THREADS {
            if done_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("every worker finishes after completion")
            {
                initialized += 1;
            }
        }
        for worker in workers {
            worker.join().expect("once worker completes");
        }
        assert_eq!(initialized, 1);
        assert_eq!(winners.load(Ordering::Acquire), 1);
    }

    fn complete_through_result_boundary(once: &AllocatorOnce) -> Result<bool> {
        match once.enter(thread_id(2))? {
            Some(completion) => {
                completion.complete()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    #[test]
    fn entry_and_completion_keep_private_lock_errors_observable() {
        let once = AllocatorOnce::new();
        assert!(
            complete_through_result_boundary(&once)
                .expect("uncontended entry and release succeed")
        );
        assert!(
            !complete_through_result_boundary(&once)
                .expect("completed entry keeps the result boundary")
        );
    }
}
