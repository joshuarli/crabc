// Copyright (c) 2018-2024 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Boundary adaptation source: pinned mimalloc v3.5.0
// `include/mimalloc/atomic.h:405-472`. Its active `MI_USE_PTHREADS` branch
// delegates a private normal pthread mutex. This file preserves that narrow
// capability boundary without importing crabc-libc or its public pthread ABI.
// The 0/1/2 futex state machine below is crabc Linux/AArch64 boundary code,
// not a transliteration of upstream mimalloc code.

//! Allocator-private blocking lock boundary.
//!
//! `PrivateLock::new` is the complete initialization operation and may be
//! used in static storage. There is no destruction operation: before a
//! dynamically placed lock is dropped, unmapped, or reused, its owner must
//! establish quiescence—no guards, waiters, or concurrent attempts may
//! remain. The lock is process-private, nonrecursive, and nonrobust. It
//! records no owner, provides no owner-death recovery, and makes no fork
//! correctness or post-fork repair claim.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering};

use crabc_core::{Errno, Result};

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

/// A private normal allocator lock.
pub(crate) struct PrivateLock {
    state: AtomicU32,
}

/// Exclusive ownership of one [`PrivateLock`].
#[must_use = "dropping a lock guard releases the allocator-private lock"]
pub(crate) struct PrivateLockGuard<'a> {
    lock: &'a PrivateLock,
    released: bool,
    _not_send: PhantomData<*mut ()>,
}

impl PrivateLock {
    /// Creates an unlocked private lock.
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }

    /// Attempts to acquire the lock without blocking.
    pub(crate) fn try_lock(&self) -> Option<PrivateLockGuard<'_>> {
        self.state
            .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| self.guard())
    }

    /// Injects a held state without manufacturing a guard or borrowing the
    /// protected owner across its teardown transition.
    ///
    /// This is solely a lifecycle-failure test hook. It deliberately leaves
    /// the lock state busy so the terminally poisoned owner cannot reclaim or
    /// reuse the backing TLD image; production code cannot call it.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_inject_busy(&self) {
        self.state.store(LOCKED, Ordering::Relaxed);
    }

    /// Acquires the lock, blocking when another thread holds it.
    ///
    /// A successful acquire is an Acquire operation. The dropping guard's
    /// Release transition therefore publishes every preceding critical-section
    /// write to this holder. `EINTR` and `EAGAIN` are the only transient
    /// wait outcomes: both restart the protocol because a signal or an
    /// unlock-before-sleep race may have changed the state. Every other kernel
    /// error returns directly without granting ownership.
    pub(crate) fn lock(&self) -> Result<PrivateLockGuard<'_>> {
        if let Some(guard) = self.try_lock() {
            return Ok(guard);
        }

        loop {
            // Changing `LOCKED` to `CONTENDED` makes a subsequent release
            // issue one private futex wake. If release won before this RMW,
            // its returned zero atomically transfers ownership to this thread.
            if self.state.swap(CONTENDED, Ordering::Acquire) == UNLOCKED {
                return Ok(self.guard());
            }

            // SAFETY: `state` is a live four-byte-aligned atomic futex word
            // owned by this process-private lock. It remains valid because
            // the lock's documented quiescence rule prohibits destruction or
            // reuse while an acquisition may be waiting. A null timeout is an
            // unbounded wait.
            let wait = unsafe {
                crabc_core::thread::futex_wait(
                    (&self.state as *const AtomicU32).cast::<u32>(),
                    CONTENDED,
                    true,
                    core::ptr::null(),
                )
            };
            retry_wait_result(wait)?;
        }
    }

    #[inline]
    fn guard(&self) -> PrivateLockGuard<'_> {
        PrivateLockGuard {
            lock: self,
            released: false,
            // A raw mutable-pointer marker prevents sending this guard to a
            // different thread, which would turn a normal lock release into a
            // cross-thread unlock.
            _not_send: PhantomData,
        }
    }

    #[inline]
    fn release(&self) -> Result<()> {
        let previous = self.state.swap(UNLOCKED, Ordering::Release);
        if previous == CONTENDED {
            // SAFETY: The guard keeps this lock alive while it releases, and
            // `state` is its aligned process-private futex word. This is one
            // wake only: contenders restore `CONTENDED` before waiting, so a
            // waking thread either acquires or leaves the contended marker for
            // the next release.
            unsafe {
                crabc_core::thread::futex_wake(
                    (&self.state as *const AtomicU32).cast::<u32>(),
                    1,
                    true,
                )
            }
            .map(|_| ())
        } else {
            Ok(())
        }
    }
}

impl PrivateLockGuard<'_> {
    /// Releases the lock and reports an unexpected futex-wake failure.
    ///
    /// The atomic Release transition happens before a possible wake error, so
    /// an error means this guard no longer owns the lock but the caller has an
    /// explicit boundary for recording or escalating the impossible kernel
    /// result. `futex_wake` is not retried: its valid-word call has no source
    /// transient retry contract.
    pub(crate) fn unlock(mut self) -> Result<()> {
        // Mark the guard first so Drop cannot issue a second unlock if the
        // one wake reports an error after the state transition succeeded.
        self.released = true;
        self.lock.release()
    }
}

impl Drop for PrivateLockGuard<'_> {
    fn drop(&mut self) {
        if !self.released {
            // Drop cannot return a wake error. It still performs the Release
            // transition and deliberately does not panic on an otherwise
            // impossible valid-private-futex failure. Callers which require an
            // observable error boundary use `PrivateLockGuard::unlock`.
            let _release_result = self.lock.release();
        }
    }
}

/// Collapses only the documented transient wait outcomes into a retry.
///
/// Keeping this as a concrete result function makes the non-transient error
/// policy unit-testable without a production callback, trait, or test-only
/// futex dispatch path.
#[inline]
fn retry_wait_result(wait: Result<()>) -> Result<()> {
    match wait {
        Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) => Ok(()),
        Err(error) => Err(error),
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

    #[test]
    fn try_lock_is_uncontended_and_exclusive() {
        let lock = PrivateLock::new();

        let guard = lock.try_lock().expect("a new lock is unlocked");
        assert!(lock.try_lock().is_none(), "a held lock cannot be reacquired");
        guard.unlock().expect("an uncontended unlock succeeds");
        assert!(lock.try_lock().is_some(), "unlock restores acquisition");
    }

    #[test]
    fn blocked_waiter_handoffs_after_release() {
        let lock = Arc::new(PrivateLock::new());
        let held = lock.lock().expect("acquire before starting the waiter");
        let (started_sender, started_receiver) = mpsc::channel();
        let (acquired_sender, acquired_receiver) = mpsc::channel();
        let waiter_lock = Arc::clone(&lock);

        let waiter = thread::spawn(move || {
            started_sender.send(()).expect("test receiver remains live");
            let guard = waiter_lock.lock().expect("wake hands the lock to a waiter");
            acquired_sender.send(()).expect("test receiver remains live");
            drop(guard);
        });

        started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter begins while the lock is held");
        assert!(
            acquired_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "the waiter must not enter before the holder releases"
        );
        held.unlock().expect("release wakes one contended waiter");
        acquired_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the waiter acquires after release");
        waiter.join().expect("waiter completes");
    }

    #[test]
    fn contended_sections_exclude_one_another() {
        const THREADS: usize = 4;
        const ROUNDS: usize = 64;

        let lock = Arc::new(PrivateLock::new());
        let active = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(THREADS));
        let mut workers = std::vec::Vec::new();

        for _ in 0..THREADS {
            let worker_lock = Arc::clone(&lock);
            let worker_active = Arc::clone(&active);
            let worker_start = Arc::clone(&start);
            workers.push(thread::spawn(move || {
                worker_start.wait();
                for _ in 0..ROUNDS {
                    let guard = worker_lock.lock().expect("contended acquisition");
                    assert_eq!(worker_active.fetch_add(1, Ordering::AcqRel), 0);
                    thread::yield_now();
                    assert_eq!(worker_active.fetch_sub(1, Ordering::Release), 1);
                    drop(guard);
                }
            }));
        }

        for worker in workers {
            worker.join().expect("worker preserves exclusion");
        }
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn bounded_churn_does_not_lose_a_wake() {
        const THREADS: usize = 4;
        const ROUNDS: usize = 128;

        let lock = Arc::new(PrivateLock::new());
        let completed = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(THREADS));
        let (done_sender, done_receiver) = mpsc::channel();
        let mut workers = std::vec::Vec::new();

        for _ in 0..THREADS {
            let worker_lock = Arc::clone(&lock);
            let worker_completed = Arc::clone(&completed);
            let worker_start = Arc::clone(&start);
            let worker_done = done_sender.clone();
            workers.push(thread::spawn(move || {
                worker_start.wait();
                for _ in 0..ROUNDS {
                    let guard = worker_lock.lock().expect("bounded churn acquires");
                    worker_completed.fetch_add(1, Ordering::Relaxed);
                    thread::yield_now();
                    drop(guard);
                }
                worker_done.send(()).expect("test receiver remains live");
            }));
        }
        drop(done_sender);

        for _ in 0..THREADS {
            done_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("every bounded-churn worker completes");
        }
        for worker in workers {
            worker.join().expect("bounded-churn worker completes");
        }
        assert_eq!(completed.load(Ordering::Acquire), THREADS * ROUNDS);
    }

    #[test]
    fn only_transient_wait_errors_are_retried() {
        assert_eq!(retry_wait_result(Ok(())), Ok(()));
        assert_eq!(retry_wait_result(Err(Errno::INTR)), Ok(()));
        assert_eq!(retry_wait_result(Err(Errno::AGAIN)), Ok(()));
        assert_eq!(retry_wait_result(Err(Errno::INVAL)), Err(Errno::INVAL));
    }
}
