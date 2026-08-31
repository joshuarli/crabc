//! Bounded Linux/x86-64 static `pthread_mutexattr_settype` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_mutexattr_settype.c::pthread_mutexattr_settype`
//!   returns `EINVAL` unless `(unsigned)type <= 2`, then replaces only raw
//!   bits zero and one with `type`.
//!
//! The admitted surface is deliberately only that caller-owned four-byte
//! record update and its input-first `EINVAL` branch. It owns no attribute
//! lifecycle, mutex state, scheduler state, allocation, syscall, C errno/TLS,
//! TCB, synchronization, cancellation, or thread-lifecycle behavior. It is a
//! private selected static artifact, not a mutex-type operation, a mutex
//! capability claim, pthread-family completion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread mutex-attribute type setter requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const EINVAL: c_int = 22;
const TYPE_MASK: c_uint = 3;

/// Exact public x86 `pthread_mutexattr_t` storage.
///
/// This private representation establishes only the caller-owned raw record
/// word required by the selected setter; it is not a Rust synchronization type
/// and owns no mutex or attribute-lifecycle state.
#[repr(C)]
struct PublicPthreadMutexAttr {
    attr: c_uint,
}

const _: () = {
    assert!(size_of::<PublicPthreadMutexAttr>() == 4);
    assert!(align_of::<PublicPthreadMutexAttr>() == 4);
    assert!(offset_of!(PublicPthreadMutexAttr, attr) == 0);
};

/// Replace musl's raw public mutex-type bits after its input-first validation.
///
/// # Safety
///
/// For a valid type value `0`, `1`, or `2`, `attr` must designate writable,
/// aligned public `pthread_mutexattr_t` storage. Invalid type values return
/// `EINVAL` before reading or writing `attr`, exactly as musl does. This entry
/// neither initializes nor consumes the record and does not establish mutex
/// type or mutex-operation behavior.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_settype(
    attr: *mut c_void,
    mutex_type: c_int,
) -> c_int {
    if (mutex_type as c_uint) > 2 {
        return EINVAL;
    }

    // SAFETY: a valid type requires the caller-owned writable public record
    // described above. The source-specific update changes only raw bits 0..1.
    let mut record = unsafe { core::ptr::read(attr.cast::<PublicPthreadMutexAttr>()) };
    record.attr = (record.attr & !TYPE_MASK) | mutex_type as c_uint;
    unsafe { core::ptr::write(attr.cast::<PublicPthreadMutexAttr>(), record) };
    0
}
