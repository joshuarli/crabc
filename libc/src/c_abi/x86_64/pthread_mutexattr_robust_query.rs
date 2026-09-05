//! Bounded Linux/x86-64 static `pthread_mutexattr_getrobust` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_attr_get.c::pthread_mutexattr_getrobust` assigns
//!   `*robust = a->__attr / 4U % 2` and returns zero.
//!
//! The admitted surface is deliberately only this raw robustness-bit query
//! over the installed four-byte `pthread_mutexattr_t` word. It has no allocation,
//! syscall, C-`errno`, TLS, TCB, attribute lifecycle, mutex
//! state-machine, synchronization, cancellation, or thread lifecycle
//! behavior. In particular, it does not select `pthread_mutexattr_setrobust`:
//! musl's setter probes and caches kernel robust-list support, which is outside
//! this direct record-query boundary. The adjacent selected robust-mutex
//! artifact separately performs that capability probe and consumes its
//! admitted normal/robust attribute records; this query does not do so. A raw
//! robust bit is not robust-mutex operation, general pthread support, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread mutex-attribute robust-query leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const ROBUST_BIT: c_uint = 4;

/// Exact public x86 `pthread_mutexattr_t` storage.
///
/// The installed C header makes the one unsigned word visible as `__attr`.
/// This private record establishes only that ABI representation; it is not a
/// Rust synchronization type and owns no mutex or robust-list behavior.
#[repr(C)]
struct PublicPthreadMutexAttr {
    attr: c_uint,
}

const _: () = {
    assert!(size_of::<PublicPthreadMutexAttr>() == 4);
    assert!(align_of::<PublicPthreadMutexAttr>() == 4);
    assert!(offset_of!(PublicPthreadMutexAttr, attr) == 0);
};

/// Read musl's raw public robustness bit from a mutex-attribute record.
///
/// # Safety
///
/// `attr` must designate readable, aligned public `pthread_mutexattr_t`
/// storage and `robust` must designate writable `int` storage. As in musl,
/// null and otherwise invalid object pointers are outside the C caller
/// contract. This entry only observes bit 2; it neither initializes nor
/// consumes the record and does not establish robust mutex behavior.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getrobust(
    attr: *const c_void,
    robust: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable public record and writable C
    // result slot described above.
    let record = unsafe { core::ptr::read(attr.cast::<PublicPthreadMutexAttr>()) };
    unsafe { core::ptr::write(robust, (record.attr / ROBUST_BIT % 2) as c_int) };
    0
}
