//! Bounded Linux/x86-64 static `pthread_spin_init` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_spin_init.c::pthread_spin_init` is exactly
//!   `return *s = 0;`. The shared argument is deliberately ignored.
//!
//! The selected boundary is one valid caller-owned four-byte spinlock record
//! reset. It establishes neither spin acquisition/release, destruction,
//! process sharing, synchronization, thread lifecycle, nor general pthread
//! support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread spin-init leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;
use core::mem::{align_of, size_of};

const _: () = {
    assert!(size_of::<c_int>() == 4);
    assert!(align_of::<c_int>() == 4);
};

/// Reset one caller-owned musl `pthread_spinlock_t` record to its initial zero.
///
/// # Safety
///
/// `spinlock` must designate writable, properly aligned public
/// `pthread_spinlock_t` storage for the duration of this call. As in musl,
/// null, misaligned, and otherwise invalid pointers are outside the C caller
/// contract. `pshared` is accepted but deliberately ignored.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_init(spinlock: *mut c_int, _pshared: c_int) -> c_int {
    // SAFETY: the caller supplies one writable public spinlock record.
    unsafe { core::ptr::write(spinlock, 0) };
    0
}
