//! Bounded Linux/x86-64 static `pthread_barrierattr_*pshared` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_barrierattr_setpshared.c::pthread_barrierattr_setpshared`
//!   validates `pshared > 1U`, then assigns
//!   `a->__attr = pshared ? INT_MIN : 0`.
//! - `src/thread/pthread_attr_get.c::pthread_barrierattr_getpshared` assigns
//!   `*pshared = !!a->__attr`, canonicalizing any nonzero public word to one.
//!
//! The admitted surface is deliberately only this raw process-sharing
//! record-pair over the installed four-byte `pthread_barrierattr_t` word. It
//! has no allocation, syscall, C-`errno`, TLS, TCB, attribute lifecycle,
//! barrier state-machine, synchronization, cancellation, or thread lifecycle
//! behavior. This standalone fixture does not invoke the separately selected
//! operational barrier block, and no init/destroy sibling is imported into
//! this module. Its raw record proof alone is not barrier initialization,
//! barrier waiting, process-shared barrier operation, general pthread support,
//! or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread barrier-attribute pshared leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const EINVAL: c_int = 22;
const MAX_PSHARED: c_uint = 1;
const SHARED_RECORD_WORD: c_uint = 1 << 31;

/// Exact public x86 `pthread_barrierattr_t` storage.
///
/// The installed C header makes the one unsigned word visible as `__attr`.
/// This private record establishes only that ABI representation; it is not a
/// Rust barrier type and owns no barrier behavior.
#[repr(C)]
struct PublicPthreadBarrierAttr {
    attr: c_uint,
}

const _: () = {
    assert!(size_of::<PublicPthreadBarrierAttr>() == 4);
    assert!(align_of::<PublicPthreadBarrierAttr>() == 4);
    assert!(offset_of!(PublicPthreadBarrierAttr, attr) == 0);
};

/// Replace one public barrier-attribute word with musl's pshared encoding.
///
/// # Safety
///
/// For accepted `pshared` values, `attr` must designate writable, aligned
/// public `pthread_barrierattr_t` storage. The caller owns its object-lifetime
/// contract; this entry neither initializes nor consumes a barrier attribute.
/// As in musl, null or otherwise invalid object pointers are outside the C
/// caller contract. Invalid `pshared` values return `EINVAL` before accessing
/// the record and leave it unchanged.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_setpshared(
    attr: *mut c_void,
    pshared: c_int,
) -> c_int {
    if (pshared as c_uint) > MAX_PSHARED {
        return EINVAL;
    }

    let attr_word = if pshared == 0 { 0 } else { SHARED_RECORD_WORD };
    // SAFETY: the caller supplies one writable public attribute record.
    unsafe {
        core::ptr::write(
            attr.cast::<PublicPthreadBarrierAttr>(),
            PublicPthreadBarrierAttr { attr: attr_word },
        )
    };
    0
}

/// Canonicalize one public barrier-attribute word to its pshared result.
///
/// # Safety
///
/// `attr` must designate readable, aligned public `pthread_barrierattr_t`
/// storage and `pshared` must designate writable `int` storage. As in musl,
/// null and invalid object pointers are outside the C caller contract. This
/// observes only the one record word and does not establish a barrier or its
/// process-sharing operation.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_getpshared(
    attr: *const c_void,
    pshared: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable C result
    // slot described above.
    let record = unsafe { core::ptr::read(attr.cast::<PublicPthreadBarrierAttr>()) };
    unsafe { core::ptr::write(pshared, (record.attr != 0) as c_int) };
    0
}
