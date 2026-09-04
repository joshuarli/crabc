//! Selected static Linux/x86-64 interval-timer C ABI boundary.
//!
//! This leaf maps pinned musl 1.2.6 `src/signal/getitimer.c` and
//! `src/signal/setitimer.c` to the Linux x86-64 `getitimer=36` and
//! `setitimer=38` syscalls. On x86-64, `timeval` is two signed eight-byte
//! longs and `itimerval` is two adjacent `timeval` records; the kernel owns
//! validation of timer selectors, timeval ranges, and optional old-value
//! pointers. The shared `c_status` boundary translates only Linux's raw
//! negative errno range, preserving successful caller `errno`.
//!
//! The timer is process-global kernel state. This module does not install
//! signal handlers, alter masks, wait for delivery, or select a signal or
//! POSIX-timer policy. The separate `alarm` and `ualarm` adapters retain
//! their own source and evidence boundaries.

use core::ffi::{c_int, c_long};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

/// Exact public Linux/x86-64 `struct timeval` storage.
#[repr(C)]
struct Timeval {
    seconds: c_long,
    microseconds: c_long,
}

/// Exact public Linux/x86-64 `struct itimerval` storage.
#[repr(C)]
pub struct Itimerval {
    interval: Timeval,
    value: Timeval,
}

const _: () = {
    assert!(size_of::<Timeval>() == 16);
    assert!(align_of::<Timeval>() == 8);
    assert!(offset_of!(Timeval, seconds) == 0);
    assert!(offset_of!(Timeval, microseconds) == 8);
    assert!(size_of::<Itimerval>() == 32);
    assert!(align_of::<Itimerval>() == 8);
    assert!(offset_of!(Itimerval, interval) == 0);
    assert!(offset_of!(Itimerval, value) == 16);
};

/// Read one Linux process interval timer into caller-owned storage.
///
/// # Safety
///
/// `old` must be null only when intentionally testing Linux's pointer-error
/// behavior. Otherwise it must point to writable, properly aligned storage
/// for one complete x86-64 `struct itimerval` for the duration of the
/// syscall. `which` is passed to Linux unchanged; the caller owns the
/// process-global timer state and any concurrent access policy.
#[no_mangle]
pub unsafe extern "C" fn getitimer(which: c_int, old: *mut Itimerval) -> c_int {
    // SAFETY: the public C caller owns the selector and output-pointer
    // contract documented above; syscall2 supplies Linux rdi/rsi exactly.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_GETITIMER,
            i64::from(which),
            old as usize as i64,
        )
    };
    c_status(result)
}

/// Replace one Linux process interval timer and optionally return its old
/// setting.
///
/// # Safety
///
/// `new` must be non-null and point to readable, properly aligned storage for
/// one complete x86-64 `struct itimerval` for the duration of the syscall.
/// `old` may be null, or must point to writable storage for the same complete
/// record. `which` is passed to Linux unchanged; the caller owns the
/// process-global timer state and any concurrent access policy.
#[no_mangle]
pub unsafe extern "C" fn setitimer(
    which: c_int,
    new: *const Itimerval,
    old: *mut Itimerval,
) -> c_int {
    // SAFETY: the public C caller owns both record-pointer contracts
    // documented above; syscall3 supplies Linux rdi/rsi/rdx exactly.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SETITIMER,
            i64::from(which),
            new as usize as i64,
            old as usize as i64,
        )
    };
    c_status(result)
}
