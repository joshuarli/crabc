//! Bounded Linux/x86-64 static `pthread_mutexattr_getpshared` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_attr_get.c::pthread_mutexattr_getpshared` assigns
//!   `*pshared = a->__attr / 128U % 2` and returns zero.
//!
//! The admitted surface is deliberately only this raw process-sharing-bit
//! query over the installed four-byte `pthread_mutexattr_t` word. It has no allocation,
//! syscall, C-`errno`, TLS, TCB, attribute lifecycle, mutex
//! state-machine, synchronization, cancellation, or thread lifecycle
//! behavior. In particular, it does not select `pthread_mutexattr_setpshared`:
//! the getter is evidence for a caller-owned record word only, not a record
//! construction or validation contract. The adjacent selected normal-mutex
//! artifact continues to reject every non-null attribute rather than consume a
//! record queried here. A raw process-sharing bit is not process-shared mutex
//! operation, a cross-process capability claim, general pthread support, or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread mutex-attribute pshared-query leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const PSHARED_BIT: c_uint = 128;

/// Exact public x86 `pthread_mutexattr_t` storage.
///
/// The installed C header makes the one unsigned word visible as `__attr`.
/// This private record establishes only that ABI representation; it is not a
/// Rust synchronization type and owns no mutex or process-sharing state.
#[repr(C)]
struct PublicPthreadMutexAttr {
    attr: c_uint,
}

const _: () = {
    assert!(size_of::<PublicPthreadMutexAttr>() == 4);
    assert!(align_of::<PublicPthreadMutexAttr>() == 4);
    assert!(offset_of!(PublicPthreadMutexAttr, attr) == 0);
};

/// Read musl's raw public process-sharing bit from a mutex-attribute record.
///
/// # Safety
///
/// `attr` must designate readable, aligned public `pthread_mutexattr_t`
/// storage and `pshared` must designate writable `int` storage. As in musl,
/// null and otherwise invalid object pointers are outside the C caller
/// contract. This entry only observes bit 7; it neither initializes nor
/// consumes the record and does not establish process-shared mutex behavior.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getpshared(
    attr: *const c_void,
    pshared: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable public record and writable C
    // result slot described above.
    let record = unsafe { core::ptr::read(attr.cast::<PublicPthreadMutexAttr>()) };
    unsafe { core::ptr::write(pshared, (record.attr / PSHARED_BIT % 2) as c_int) };
    0
}
