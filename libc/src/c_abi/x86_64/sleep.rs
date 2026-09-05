//! Selected static Linux/x86-64 `sleep` C ABI boundary.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/sleep.c::sleep` builds one local `struct timespec`, calls
//! `nanosleep(&tv, &tv)`, and returns either zero after completion or the
//! whole-second portion of that same remaining record after interruption.
//!
//! The selected x86 `nanosleep` dependency is the existing direct Linux
//! `nanosleep=35` boundary, canceling in the owned runtime. It preserves musl's ordinary
//! single-call result and initial-TLS `errno` publication on EINTR, but does
//! not independently select `usleep`, clocks or timer control, signal
//! policy, libc.so, CRT, loader, sysroot, family completion, promotion, or
//! public x86 support.

use core::ffi::{c_long, c_uint, c_void};

use super::nanosleep;

/// Linux/x86-64 public `struct timespec` storage used only within [`sleep`].
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

const _: () = {
    assert!(core::mem::size_of::<Timespec>() == 16);
    assert!(core::mem::align_of::<Timespec>() == 8);
    assert!(core::mem::offset_of!(Timespec, seconds) == 0);
    assert!(core::mem::offset_of!(Timespec, nanoseconds) == 8);
};

/// Sleep once and return the whole seconds still unslept after interruption.
///
/// This is the complete musl wrapper shape: the same local record supplies
/// the request and, only when Linux interrupts it, the remaining interval.
/// A completion returns zero; the existing `nanosleep` boundary publishes
/// EINTR in the selected initial-TLS `errno` slot before this function returns
/// the record's truncated whole-second remainder. It neither retries nor
/// installs handlers, masks signals, creates timers, or promises wake timing.
#[no_mangle]
pub extern "C" fn sleep(seconds: c_uint) -> c_uint {
    let mut interval = Timespec {
        seconds: c_long::from(seconds),
        nanoseconds: 0,
    };
    let interval_pointer = core::ptr::addr_of_mut!(interval);

    // SAFETY: this local is one aligned initialized x86 `timespec`; musl
    // passes it as both the readable request and writable EINTR remainder.
    // The selected nanosleep call owns the raw Linux result and errno path.
    let result = unsafe {
        nanosleep::nanosleep(
            interval_pointer.cast::<c_void>().cast_const(),
            interval_pointer.cast::<c_void>(),
        )
    };

    if result == 0 {
        0
    } else {
        interval.seconds as c_uint
    }
}
