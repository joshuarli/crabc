//! One mutation lock for runtime mapping, scope and worker TLS registration.
//!
//! No libc allocator, pthread list lock or application callback is acquired
//! while held. The pthread owner calls TLS allocation/release outside its list
//! lock; initial publication is single-threaded before any callback.

use super::*;
use core::sync::atomic::{AtomicI32, Ordering};

static LOCK: AtomicI32 = AtomicI32::new(0);
pub(super) struct RuntimeGuard(core::marker::PhantomData<*mut ()>);
impl RuntimeGuard {
    pub(super) fn acquire() -> Self {
        loop {
            if LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                return Self(core::marker::PhantomData);
            }
            unsafe { syscall6(202, core::ptr::addr_of!(LOCK) as i64, 128, 1, 0, 0, 0); }
        }
    }
}
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        LOCK.store(0, Ordering::Release);
        unsafe { syscall6(202, core::ptr::addr_of!(LOCK) as i64, 129, 1, 0, 0, 0); }
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
/// process isolation, not the product's unimplemented dynamic fork adapter.
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
