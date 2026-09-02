//! Bounded Linux/x86-64 static pthread attribute lifecycle artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_mutexattr_init.c::pthread_mutexattr_init` and
//!   `src/thread/pthread_condattr_init.c::pthread_condattr_init` store zero
//!   in the caller-owned `__attr` word and return zero.
//! - `src/thread/pthread_mutexattr_destroy.c::pthread_mutexattr_destroy` and
//!   `src/thread/pthread_condattr_destroy.c::pthread_condattr_destroy` return
//!   zero without dereferencing their argument because these records own no
//!   resource.
//!
//! The admitted surface is deliberately only this stateless lifecycle record
//! quartet over the installed four-byte `pthread_mutexattr_t` and
//! `pthread_condattr_t` words. It has no attribute setter/getter, mutex or
//! condition initialization/operation, allocation, syscall, C-`errno`, TLS,
//! TCB, synchronization, cancellation, thread lifecycle, or pthread runtime
//! behavior. Initializing a record does not make any selected mutex or
//! condition initializer consume it; this is not pthread-family completion or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread attribute lifecycle leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

/// Exact public x86 `pthread_mutexattr_t` storage.
///
/// This private representation establishes only the caller-owned raw word
/// required by the lifecycle entries; it is not a Rust synchronization type.
#[repr(C)]
struct PublicPthreadMutexAttr {
    attr: c_uint,
}

/// Exact public x86 `pthread_condattr_t` storage.
///
/// This private representation establishes only the caller-owned raw word
/// required by the lifecycle entries; it is not a Rust condition type.
#[repr(C)]
struct PublicPthreadCondAttr {
    attr: c_uint,
}

const _: () = {
    assert!(size_of::<PublicPthreadMutexAttr>() == 4);
    assert!(align_of::<PublicPthreadMutexAttr>() == 4);
    assert!(offset_of!(PublicPthreadMutexAttr, attr) == 0);
    assert!(size_of::<PublicPthreadCondAttr>() == 4);
    assert!(align_of::<PublicPthreadCondAttr>() == 4);
    assert!(offset_of!(PublicPthreadCondAttr, attr) == 0);
};

/// Initialize one caller-owned mutex attribute record to musl's all-zero
/// default representation.
///
/// # Safety
///
/// `attribute` must designate writable, aligned x86 `pthread_mutexattr_t`
/// storage that is not concurrently accessed.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_init(attribute: *mut c_void) -> c_int {
    // SAFETY: the caller provides exactly one writable public record described
    // above; all-zero is musl's complete default representation.
    unsafe {
        core::ptr::write(
            attribute.cast::<PublicPthreadMutexAttr>(),
            PublicPthreadMutexAttr { attr: 0 },
        )
    };
    0
}

/// Destroy one mutex attribute record without observing it.
///
/// Musl's record owns no resource, so this intentionally neither dereferences
/// the caller pointer nor changes C errno.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_destroy(_attribute: *mut c_void) -> c_int {
    0
}

/// Initialize one caller-owned condition attribute record to musl's all-zero
/// default representation.
///
/// # Safety
///
/// `attribute` must designate writable, aligned x86 `pthread_condattr_t`
/// storage that is not concurrently accessed.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_init(attribute: *mut c_void) -> c_int {
    // SAFETY: the caller provides exactly one writable public record described
    // above; all-zero is musl's complete default representation.
    unsafe {
        core::ptr::write(
            attribute.cast::<PublicPthreadCondAttr>(),
            PublicPthreadCondAttr { attr: 0 },
        )
    };
    0
}

/// Destroy one condition attribute record without observing it.
///
/// Musl's record owns no resource, so this intentionally neither dereferences
/// the caller pointer nor changes C errno.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_destroy(_attribute: *mut c_void) -> c_int {
    0
}
