//! Bounded Linux/x86-64 static `pthread_mutexattr_gettype` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_attr_get.c::pthread_mutexattr_gettype` assigns
//!   `*type = a->__attr & 3` and returns zero.
//!
//! The admitted surface is deliberately only this raw low-two-bit query over
//! the installed four-byte `pthread_mutexattr_t` word. It has no allocation,
//! syscall, C-`errno`, TLS, TCB, attribute lifecycle, mutex state-machine,
//! synchronization, cancellation, or thread lifecycle behavior. In particular,
//! it does not select `pthread_mutexattr_settype`: the getter observes a
//! caller-owned record word only and does not construct or validate a mutex
//! type record. The adjacent selected normal-mutex artifact continues to reject
//! every non-null attribute rather than consume a record queried here. A raw
//! type value is not recursive or error-checking mutex operation, a mutex state
//! machine, general pthread support, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread mutex-attribute type-query leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const TYPE_MASK: c_uint = 3;

/// Exact public x86 `pthread_mutexattr_t` storage.
///
/// The installed C header makes the one unsigned word visible as `__attr`.
/// This private record establishes only that ABI representation; it is not a
/// Rust synchronization type and owns no mutex or type state.
#[repr(C)]
struct PublicPthreadMutexAttr {
    attr: c_uint,
}

const _: () = {
    assert!(size_of::<PublicPthreadMutexAttr>() == 4);
    assert!(align_of::<PublicPthreadMutexAttr>() == 4);
    assert!(offset_of!(PublicPthreadMutexAttr, attr) == 0);
};

/// Read musl's raw public mutex-type bits from a mutex-attribute record.
///
/// # Safety
///
/// `attr` must designate readable, aligned public `pthread_mutexattr_t`
/// storage and `mutex_type` must designate writable `int` storage. As in musl,
/// null and otherwise invalid object pointers are outside the C caller
/// contract. This entry only observes bits 0 and 1; it neither initializes nor
/// consumes the record and does not establish a mutex type or mutex behavior.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_gettype(
    attr: *const c_void,
    mutex_type: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable public record and writable C
    // result slot described above.
    let record = unsafe { core::ptr::read(attr.cast::<PublicPthreadMutexAttr>()) };
    unsafe { core::ptr::write(mutex_type, (record.attr & TYPE_MASK) as c_int) };
    0
}
