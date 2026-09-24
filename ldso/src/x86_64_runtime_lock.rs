//! One mutation lock for runtime mapping, scope and worker TLS registration.
//!
//! No libc allocator or application callback is entered under the graph lock.
//! Ordinary TLS allocation/release occurs outside libc's pthread list lock.
//! Fork is the explicit outer transaction: graph -> callback -> libc internal
//! registries -> thread list -> process lock, released before user atfork hooks.
//! Initial publication remains single-threaded before application callbacks.

use super::*;
use core::sync::atomic::{AtomicI32, Ordering};

static LOCK: AtomicI32 = AtomicI32::new(0);
// Musl's init_fini_lock is separate from its graph lock: constructor bodies
// release it, finalizer bodies retain it, and fork acquires graph then callback.
static CALLBACK_LOCK: AtomicI32 = AtomicI32::new(0);

// Both locks use the three-state futex protocol: 0 is free, 1 is held with no
// sleeper, and 2 is held with a possible sleeper. A contended acquirer always
// publishes 2 before it sleeps, so an uncontended release (1 -> 0) needs no
// FUTEX_WAKE and an uncontended acquire/release pair issues no syscall. This
// is musl's `__lock`/`__unlock` waiter discipline for its loader locks.
const FREE: i32 = 0;
const HELD: i32 = 1;
const CONTENDED: i32 = 2;

fn acquire(lock: &AtomicI32) {
    if lock.compare_exchange(FREE, HELD, Ordering::Acquire, Ordering::Relaxed).is_ok() { return; }
    while lock.swap(CONTENDED, Ordering::Acquire) != FREE {
        unsafe { syscall6(202, lock as *const _ as i64, 128, CONTENDED as i64, 0, 0, 0); }
    }
}
fn release(lock: &AtomicI32) {
    if lock.swap(FREE, Ordering::Release) == CONTENDED {
        unsafe { syscall6(202, lock as *const _ as i64, 129, 1, 0, 0, 0); }
    }
}

pub(super) struct CallbackGuard(core::marker::PhantomData<*mut ()>);
impl CallbackGuard {
    pub(super) fn acquire() -> Self {
        acquire(&CALLBACK_LOCK);
        Self(core::marker::PhantomData)
    }
    /// Complete the callback lock retained across one private fork syscall.
    /// The caller owns the exact successful prepare/parent-or-child pair.
    pub(super) unsafe fn complete_fork() { release(&CALLBACK_LOCK); }

    /// Unit-test teardown only: production finalization retains this lock
    /// until exit_group, while an in-process fixture restores its saved graph.
    #[cfg(test)]
    pub(super) unsafe fn reset_finalized_fixture() { release(&CALLBACK_LOCK); }
}
impl Drop for CallbackGuard {
    fn drop(&mut self) { release(&CALLBACK_LOCK); }
}
pub(super) struct RuntimeGuard(core::marker::PhantomData<*mut ()>);
impl RuntimeGuard {
    pub(super) fn acquire() -> Self {
        acquire(&LOCK);
        Self(core::marker::PhantomData)
    }
    /// Complete the mutation lock retained across one private fork syscall.
    /// The caller releases the nested callback lock before this outer lock.
    pub(super) unsafe fn complete_fork() { release(&LOCK); }
}
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        release(&LOCK);
    }
}

pub(super) fn wait_initialization(state: &AtomicI32, expected: i32) {
    unsafe { syscall6(202, state as *const AtomicI32 as i64, 128, expected as i64, 0, 0, 0); }
}
pub(super) fn wake_initialization(state: &AtomicI32) {
    unsafe { syscall6(202, state as *const AtomicI32 as i64, 129, i32::MAX as i64, 0, 0, 0); }
}

/// Isolate mincore-after-unmap assertions from unrelated test threads that
/// can immediately reuse the freed virtual address. This is harness-only raw
/// process isolation; it does not enter the product's dynamic fork adapter.
/// The child probe may use only loader raw mappings and inherited immutable
/// inputs: no libc heap, pthread locks, callbacks, panics or inherited waiters.
#[cfg(test)]
pub(super) unsafe fn isolated_mapping_probe(probe: unsafe fn(&RuntimeGuard) -> bool) {
    let guard = RuntimeGuard::acquire();
    let pid = unsafe { syscall1(57, 0) };
    if pid == 0 {
        let result = unsafe { probe(&guard) };
        unsafe { syscall1(60, if result { 0 } else { 1 }); core::hint::unreachable_unchecked(); }
    }
    let mut status = -1i32;
    let waited = if pid > 0 {
        loop {
            let result = unsafe { syscall4(61, pid, core::ptr::addr_of_mut!(status) as i64, 0, 0) };
            if result != -4 { break result; }
        }
    } else { pid };
    drop(guard);
    assert!(pid > 0 && waited == pid && status == 0, "isolated mapping probe: pid={pid}, wait={waited}, status={status}");
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::AtomicUsize;

    // Contended acquirers must still exclude one another and wake after the
    // uncontended fast path stopped issuing an unconditional FUTEX_WAKE.
    #[test]
    fn three_state_lock_excludes_contended_workers_and_returns_free() {
        static TEST_LOCK: AtomicI32 = AtomicI32::new(FREE);
        static INSIDE: AtomicUsize = AtomicUsize::new(0);
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        const WORKERS: usize = 4;
        const ROUNDS: usize = 20_000;
        let workers: std::vec::Vec<_> = (0..WORKERS).map(|_| std::thread::spawn(|| {
            for round in 0..ROUNDS {
                acquire(&TEST_LOCK);
                assert_eq!(INSIDE.fetch_add(1, Ordering::Relaxed), 0, "two owners inside the lock");
                let value = COUNT.load(Ordering::Relaxed);
                if round % 64 == 0 { std::thread::yield_now(); }
                COUNT.store(value + 1, Ordering::Relaxed);
                INSIDE.fetch_sub(1, Ordering::Relaxed);
                release(&TEST_LOCK);
            }
        })).collect();
        for worker in workers { worker.join().unwrap(); }
        assert_eq!(COUNT.load(Ordering::Relaxed), WORKERS * ROUNDS);
        assert_eq!(TEST_LOCK.load(Ordering::Relaxed), FREE);
        acquire(&TEST_LOCK);
        assert_eq!(TEST_LOCK.load(Ordering::Relaxed), HELD, "an uncontended acquire records no sleeper");
        release(&TEST_LOCK);
    }
}
