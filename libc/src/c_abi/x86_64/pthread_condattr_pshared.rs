//! Bounded Linux/x86-64 static `pthread_condattr_*pshared` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_condattr_setpshared.c::pthread_condattr_setpshared`
//!   validates `pshared > 1U`, clears `a->__attr &= 0x7fffffff`, then sets
//!   `a->__attr |= (unsigned)pshared<<31`.
//! - `src/thread/pthread_attr_get.c::pthread_condattr_getpshared` assigns
//!   `*pshared = a->__attr>>31`, reading exactly the raw high bit.
//!
//! The admitted surface is deliberately only this raw process-sharing record
//! pair over the installed four-byte `pthread_condattr_t` word. It preserves
//! the unselected low thirty-one clock-record bits and has no allocation,
//! syscall, C-`errno`, TLS, TCB, attribute lifecycle, condition state-machine,
//! synchronization, cancellation, or thread lifecycle behavior. The selected
//! private-condition artifact continues to reject every non-null initialization
//! attribute, so no selected condition initializer consumes a record here. A
//! shared record bit is not condition initialization, condition waiting,
//! process-shared condition operation, general pthread support, or public x86
//! support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread condition-attribute pshared leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const EINVAL: c_int = 22;
const MAX_PSHARED: c_uint = 1;
const PROCESS_SHARED_BIT: c_uint = 1 << 31;
const CLOCK_RECORD_MASK: c_uint = !PROCESS_SHARED_BIT;

/// Exact public x86 `pthread_condattr_t` storage.
///
/// The installed C header makes the one unsigned word visible as `__attr`.
/// This private record establishes only that ABI representation; it is not a
/// Rust condition type and owns no condition or clock behavior.
#[repr(C)]
struct PublicPthreadCondAttr {
    attr: c_uint,
}

const _: () = {
    assert!(size_of::<PublicPthreadCondAttr>() == 4);
    assert!(align_of::<PublicPthreadCondAttr>() == 4);
    assert!(offset_of!(PublicPthreadCondAttr, attr) == 0);
};

/// Replace only one public condition-attribute process-sharing record bit.
///
/// # Safety
///
/// For accepted `pshared` values, `attr` must designate writable, aligned
/// public `pthread_condattr_t` storage. The caller owns its object-lifetime
/// contract; this entry neither initializes nor consumes a condition
/// attribute. As in musl, null or otherwise invalid object pointers are
/// outside the C caller contract. Invalid `pshared` values return `EINVAL`
/// before accessing the record and leave it unchanged.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_setpshared(attr: *mut c_void, pshared: c_int) -> c_int {
    if (pshared as c_uint) > MAX_PSHARED {
        return EINVAL;
    }

    // SAFETY: the caller supplies one writable public attribute record.
    let prior = unsafe { core::ptr::read(attr.cast::<PublicPthreadCondAttr>()) };
    let selected_bit = if pshared == 0 { 0 } else { PROCESS_SHARED_BIT };
    // SAFETY: the caller supplies the same writable public attribute record.
    unsafe {
        core::ptr::write(
            attr.cast::<PublicPthreadCondAttr>(),
            PublicPthreadCondAttr {
                attr: (prior.attr & CLOCK_RECORD_MASK) | selected_bit,
            },
        )
    };
    0
}

/// Read one public condition-attribute process-sharing record bit.
///
/// # Safety
///
/// `attr` must designate readable, aligned public `pthread_condattr_t`
/// storage and `pshared` must designate writable `int` storage. As in musl,
/// null and invalid object pointers are outside the C caller contract. This
/// observes only bit 31 and does not establish a condition, a condition clock,
/// or process-sharing operation.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_getpshared(
    attr: *const c_void,
    pshared: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable C result
    // slot described above.
    let record = unsafe { core::ptr::read(attr.cast::<PublicPthreadCondAttr>()) };
    unsafe { core::ptr::write(pshared, (record.attr >> 31) as c_int) };
    0
}
