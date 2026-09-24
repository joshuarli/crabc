//! Pinned musl 1.2.6 `src/thread/__lock.c` over a caller-owned lock word.
//!
//! Translation provenance is musl release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license. The
//! word combines an ownership flag in the sign bit with a congestion count:
//! zero is unlocked and uncontended, a negative value is locked with
//! `value - INT_MIN` tasks inside the critical section, and a positive value is
//! unlocked with that many tasks still contending. Acquisition keeps the
//! source's fast compare-and-swap, ten-iteration medium-congestion spin, and
//! private futex wait; release wakes one waiter only when another task has
//! entered the critical section.
//!
//! Musl skips both operations while `libc.need_locks` is zero. This owner
//! always takes the lock instead, as the other native private musl lock owners
//! do: the elision has no observable effect for a single-threaded caller and
//! would add a process-global threading-state owner here.
//!
//! This is the per-object form of the static-word copies retained by other
//! owners (for example `owned_syslog.rs`); it adds no reusable mutex, fork
//! protocol, poisoning, or recursion. A word must be zero-initialized, stay at
//! one address while any task can reach it, and be released only by the task
//! that acquired it.

use core::sync::atomic::{AtomicI32, Ordering};

use super::raw_syscall;

const FUTEX_WAIT_PRIVATE: i64 = 128;
const FUTEX_WAKE_PRIVATE: i64 = 129;
const LOCK_FLAG: i32 = i32::MIN;
const LOCKED_ONE: i32 = LOCK_FLAG + 1;

#[inline]
fn futex_wait(word: &AtomicI32, value: i32) {
    // SAFETY: `word` is a live aligned process-private futex word. A signal,
    // mismatch, or spurious wake only returns to the source acquisition loop.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            word.as_ptr() as i64,
            FUTEX_WAIT_PRIVATE,
            i64::from(value),
            0,
        )
    };
}

#[inline]
fn futex_wake(word: &AtomicI32) {
    // SAFETY: this wakes at most one contender on the same private word.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FUTEX,
            word.as_ptr() as i64,
            FUTEX_WAKE_PRIVATE,
            1,
        )
    };
}

/// Acquire `word` as musl `__lock`.
#[inline]
pub(super) fn lock(word: &AtomicI32) {
    let mut current = word
        .compare_exchange(0, LOCKED_ONE, Ordering::Acquire, Ordering::Relaxed)
        .unwrap_or_else(|value| value);
    if current == 0 {
        return;
    }
    for _ in 0..10 {
        if current < 0 {
            current = current.wrapping_sub(LOCKED_ONE);
        }
        match word.compare_exchange(
            current,
            LOCK_FLAG.wrapping_add(current.wrapping_add(1)),
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(value) => current = value,
        }
    }
    // Spinning failed: count this task inside the critical section, then only
    // the acquiring compare-and-swap changes the word.
    current = word.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    loop {
        if current < 0 {
            futex_wait(word, current);
            current = current.wrapping_sub(LOCKED_ONE);
        }
        match word.compare_exchange(
            current,
            LOCK_FLAG.wrapping_add(current),
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(value) => current = value,
        }
    }
}

/// Release `word` as musl `__unlock`. The caller must hold it.
#[inline]
pub(super) fn unlock(word: &AtomicI32) {
    if word.load(Ordering::Relaxed) < 0
        && word.fetch_add(LOCKED_ONE.wrapping_neg(), Ordering::Release) != LOCKED_ONE
    {
        futex_wake(word);
    }
}
