//! Bounded Linux/x86-64 static `pthread_condattr_*clock` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_condattr_setclock.c::pthread_condattr_setclock`
//!   validates `if (clk < 0 || clk-2U < 2) return EINVAL`, then preserves
//!   `a->__attr &= 0x80000000` and sets `a->__attr |= clk`.
//! - `src/thread/pthread_attr_get.c::pthread_condattr_getclock` assigns
//!   `*clk = a->__attr & 0x7fffffff`, reading exactly the raw low clock bits.
//!
//! The admitted surface is deliberately only this raw clock-record pair over
//! the installed four-byte `pthread_condattr_t` word. It preserves the
//! separately selected high process-sharing bit and has no allocation,
//! syscall, C-`errno`, TLS, TCB, attribute lifecycle, condition state-machine,
//! synchronization, cancellation, or thread lifecycle behavior. The selected
//! private-condition artifact continues to reject every non-null initialization
//! attribute, so no selected condition initializer consumes a clock record. A
//! clock record is not condition initialization, timed waiting, or a clock
//! operation. It is not general pthread support or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread condition-attribute clock leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const EINVAL: c_int = 22;
const PROCESS_SHARED_BIT: c_uint = 1 << 31;
const CLOCK_RECORD_MASK: c_uint = !PROCESS_SHARED_BIT;
const FIRST_REJECTED_CPU_CLOCK: c_uint = 2;
const REJECTED_CPU_CLOCK_COUNT: c_uint = 2;

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

/// Replace the public condition-attribute raw low clock-record bits.
///
/// # Safety
///
/// For accepted `clock` values, `attr` must designate writable, aligned public
/// `pthread_condattr_t` storage. The caller owns its object-lifetime contract;
/// this entry neither initializes nor consumes a condition attribute. As in
/// musl, null or otherwise invalid object pointers are outside the C caller
/// contract. Negative clocks and the two CPU-clock IDs return `EINVAL` before
/// accessing the record and leave it unchanged.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_setclock(attr: *mut c_void, clock: c_int) -> c_int {
    let raw_clock = clock as c_uint;
    if clock < 0
        || raw_clock.wrapping_sub(FIRST_REJECTED_CPU_CLOCK) < REJECTED_CPU_CLOCK_COUNT
    {
        return EINVAL;
    }

    // SAFETY: the caller supplies one writable public attribute record.
    let prior = unsafe { core::ptr::read(attr.cast::<PublicPthreadCondAttr>()) };
    // SAFETY: the caller supplies the same writable public attribute record.
    unsafe {
        core::ptr::write(
            attr.cast::<PublicPthreadCondAttr>(),
            PublicPthreadCondAttr {
                attr: (prior.attr & PROCESS_SHARED_BIT) | raw_clock,
            },
        )
    };
    0
}

/// Read the public condition-attribute raw low clock-record bits.
///
/// # Safety
///
/// `attr` must designate readable, aligned public `pthread_condattr_t`
/// storage and `clock` must designate writable `clockid_t`/`int` storage. As
/// in musl, null and invalid object pointers are outside the C caller contract.
/// This observes only bits 0..30 and does not establish a condition, timed
/// wait, or clock operation.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_getclock(
    attr: *const c_void,
    clock: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable C result
    // slot described above.
    let record = unsafe { core::ptr::read(attr.cast::<PublicPthreadCondAttr>()) };
    unsafe { core::ptr::write(clock, (record.attr & CLOCK_RECORD_MASK) as c_int) };
    0
}
