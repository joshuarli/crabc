//! Selected static Linux/x86-64 `pthread_spin_destroy` C ABI.
//!
//! This is a deliberately private compatibility leaf, translated from pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_spin_destroy.c::pthread_spin_destroy` has a
//!   source-closed successful return and neither reads nor writes its opaque
//!   `pthread_spinlock_t *` argument.
//!
//! The SysV AMD64 ABI passes that one pointer in `rdi` and returns the
//! successful `int` status in `eax`. This leaf does not establish spin-lock
//! initialization, lock/trylock/unlock, a lock state machine, synchronization,
//! atomics, threads, cancellation, errno, TLS, allocation, syscalls, or a
//! general pthread runtime.

use core::ffi::c_int;

/// Return musl's successful spin-destruction status without observing storage.
///
/// # Safety
///
/// The caller retains the C/POSIX lifetime and initialization contract for its
/// `pthread_spinlock_t` object. This source-closed compatibility leaf treats
/// the pointer as opaque: it does not dereference, retain, free, initialize,
/// lock, or otherwise modify it.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_destroy(_spinlock: *mut c_int) -> c_int {
    0
}
