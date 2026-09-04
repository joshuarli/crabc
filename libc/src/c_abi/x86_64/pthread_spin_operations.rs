//! Selected Linux/x86-64 `pthread_spin_lock` operations.
//!
//! This private opt-in block is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_spin_lock.c::pthread_spin_lock` retries a zero to
//!   `EBUSY` compare-and-exchange and executes the x86 `pause` instruction;
//! - `src/thread/pthread_spin_trylock.c::pthread_spin_trylock` returns the
//!   compare-and-exchange observation directly;
//! - `src/thread/pthread_spin_unlock.c::pthread_spin_unlock` atomically stores
//!   zero and returns success.
//!
//! The operations compose the existing four-byte `pthread_spinlock_t`
//! initialization/destruction records and the private x86 i32 atomic helper.
//! They do not select mutexes, condition variables, process sharing, thread
//! lifecycle, TLS, cancellation, allocation, errno, or a general pthread
//! runtime.

#![allow(clippy::missing_safety_doc)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread spin operations require little-endian Linux/x86-64");

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

use super::atomic;

const EBUSY: c_int = 16;

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::align_of::<c_int>() == 4);
};

/// Hint to an x86 processor that the current loop is a spin-wait.
#[inline(always)]
fn spin_pause() {
    // SAFETY: `pause` has no memory operands and is valid on the selected
    // Linux/x86-64 target. The compiler memory clobber preserves musl's
    // synchronization-loop boundary around the atomic helper.
    unsafe {
        core::arch::asm!("pause", options(nostack, preserves_flags));
    }
}

/// Acquire a caller-owned four-byte pthread spinlock.
///
/// # Safety
///
/// `spinlock` must point to live, writable, four-byte-aligned
/// `pthread_spinlock_t` storage. The object must be initialized or
/// statically zero-initialized, and all concurrent accesses must follow the
/// pthread spinlock synchronization contract.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_lock(spinlock: *mut c_int) -> c_int {
    loop {
        // The relaxed read mirrors musl's initial volatile observation and
        // avoids an unnecessary locked transaction while the object is held.
        // A successful CAS supplies the acquire operation that publishes the
        // preceding owner's release store.
        // SAFETY: forwarded from the exported function's caller contract.
        if unsafe { atomic::x86_64_load_relaxed_i32(spinlock) } == 0 {
            // SAFETY: forwarded from the exported function's caller contract.
            if unsafe {
                atomic::x86_64_compare_exchange_acqrel_i32(spinlock, 0, EBUSY)
            } == 0
            {
                return 0;
            }
        }
        spin_pause();
    }
}

/// Attempt to acquire a caller-owned four-byte pthread spinlock.
///
/// Returns zero on acquisition and the observed lock word (normally `EBUSY`)
/// when the compare-and-exchange cannot acquire it, matching musl's direct
/// `a_cas(s, 0, EBUSY)` result.
///
/// # Safety
///
/// `spinlock` must point to live, writable, four-byte-aligned
/// `pthread_spinlock_t` storage. All concurrent accesses must be atomic and
/// follow the pthread spinlock synchronization contract.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_trylock(spinlock: *mut c_int) -> c_int {
    // SAFETY: forwarded from the exported function's caller contract.
    unsafe { atomic::x86_64_compare_exchange_acqrel_i32(spinlock, 0, EBUSY) }
}

/// Release a caller-owned four-byte pthread spinlock.
///
/// # Safety
///
/// `spinlock` must point to live, four-byte-aligned `pthread_spinlock_t`
/// storage currently owned by the calling thread. All concurrent accesses
/// must follow the pthread spinlock synchronization contract.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_unlock(spinlock: *mut c_int) -> c_int {
    // `AtomicI32::from_ptr` retains the raw-pointer boundary and a release
    // store is sufficient for x86's TSO ordering, matching musl's a_store.
    // SAFETY: forwarded from the exported function's caller contract.
    unsafe { AtomicI32::from_ptr(spinlock) }.store(0, Ordering::Release);
    0
}
