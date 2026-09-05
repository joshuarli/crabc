//! Shared Linux/x86-64 owner of musl's private `vmlock[2]` record.
//!
//! This module is a source-specific semantic port of pinned musl 1.2.6
//! `src/thread/vmlock.c`, under musl's MIT license recorded in `COPYRIGHT`.
//! Its one process-local pair synchronizes every selected process-shared
//! pthread object whose kernel-visible lifetime can overlap a destroy or a
//! robust-list pending-node transition. `pthread_barrier` and the selected
//! robust-mutex path deliberately share this one record; duplicate private
//! counters would not preserve musl's `__vm_wait` lifetime boundary.
//!
//! This is an internal synchronization seam, not a C ABI or a general
//! process-memory ownership facility. Callers must keep their caller-owned
//! public object live while they hold the paired guard, and must complete the
//! matching [`unlock`] even on an internal error path.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread vmlock leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;

use super::{atomic, raw_syscall};

const FUTEX_WAIT_PRIVATE: i64 = 128;
const FUTEX_WAKE_PRIVATE: i64 = 129;

/// Musl's one process-local `vmlock[2]`: active-holder count then wait hint.
///
/// Raw atomic helpers are the only concurrent accesses. Keeping it private
/// to this leaf prevents an accidental C data ABI while preserving the one
/// source-defined lifetime guard for every selected consumer.
static mut VMLOCK: [c_int; 2] = [0; 2];

/// Return one raw word from the complete static vmlock record.
///
/// # Safety
///
/// `index` must be zero or one. All access must use the helpers in this
/// module or an equivalent compatible raw-atomic protocol.
#[inline(always)]
unsafe fn word(index: usize) -> *mut c_int {
    debug_assert!(index < 2);
    // SAFETY: taking a raw address does not create a mutable Rust reference
    // to concurrently modified static storage.
    unsafe { core::ptr::addr_of_mut!(VMLOCK).cast::<c_int>().add(index) }
}

/// Enter musl's process-local virtual-memory lifetime guard.
///
/// # Safety
///
/// The caller must keep its protected public object alive until the matching
/// [`unlock`]. It may not hold this guard across user code or an operation
/// that can recursively destroy that object.
#[inline(always)]
pub(super) unsafe fn lock() {
    // SAFETY: word zero is the static active-holder count.
    let lock = unsafe { word(0) };
    // SAFETY: all selected holders use this same atomic increment/decrement
    // protocol on the live static word.
    unsafe { atomic::x86_64_fetch_add_acqrel_i32(lock, 1) };
}

/// Leave musl's process-local virtual-memory lifetime guard.
///
/// # Safety
///
/// The caller must hold exactly one matching [`lock`] acquisition and must
/// have completed its protected public-object transition before this call.
#[inline(always)]
pub(super) unsafe fn unlock() {
    // SAFETY: both words belong to the complete static vmlock record.
    let lock = unsafe { word(0) };
    // SAFETY: word one is the source-defined waiter hint.
    let waiters = unsafe { word(1) };
    // SAFETY: balances the caller's source-shaped holder acquisition.
    if unsafe { atomic::x86_64_fetch_sub_acqrel_i32(lock, 1) } == 1
        // SAFETY: the waiter hint is live static atomic storage.
        && unsafe { atomic::x86_64_load_relaxed_i32(waiters) } != 0
    {
        // SAFETY: publication of the zero holder count precedes this
        // best-effort private futex wake; an ignored raw error cannot revoke
        // the published lifetime transition.
        let _ = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                lock as usize as i64,
                FUTEX_WAKE_PRIVATE,
                i64::from(c_int::MAX),
                0,
            )
        };
    }
}

/// Wait until no selected process-shared object transition retains vmlock.
///
/// # Safety
///
/// The caller must preserve musl's object-destruction admission rule: no new
/// selected operation may begin on the caller-owned object after it starts
/// this wait. This function itself owns no object or C errno behavior.
pub(super) unsafe fn wait() {
    // SAFETY: both words belong to the complete static vmlock record.
    let lock = unsafe { word(0) };
    // SAFETY: word one is the source-defined waiter hint.
    let waiters = unsafe { word(1) };
    loop {
        // SAFETY: all selected users access the active count atomically.
        let expected = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        if expected == 0 {
            return;
        }
        // SAFETY: publish the waiter hint before a private futex wait.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiters, 1) };
        while unsafe { atomic::x86_64_load_acquire_i32(lock) } == expected {
            // SAFETY: both words remain static and aligned for this futex
            // wait; interruption/racing values merely request another load.
            let _ = unsafe {
                raw_syscall::syscall4(
                    raw_syscall::SYS_FUTEX,
                    lock as usize as i64,
                    FUTEX_WAIT_PRIVATE,
                    i64::from(expected),
                    0,
                )
            };
        }
        // SAFETY: balances the just-published waiter hint before retrying.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
    }
}
