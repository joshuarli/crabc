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
