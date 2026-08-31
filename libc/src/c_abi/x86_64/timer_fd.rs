//! Selected static Linux/x86-64 timer-descriptor C boundary.
//!
//! This is a bounded adaptation of pinned musl 1.2.6's
//! `src/linux/timerfd.c` at release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! It exposes the direct Linux/x86-64 `timerfd_create=283`,
//! `timerfd_settime=286`, and `timerfd_gettime=287` entry points. Linux 5.10
//! supplies all three modern syscalls, so musl's broader portability machinery
//! is neither needed nor selected here.
//!
//! The public timer record is the 32-byte LP64 `itimerspec`: two 16-byte
//! `timespec` values at offsets zero and sixteen. The kernel owns clock and
//! flag validation, descriptor lifetime, arming/disarming, expiration counts,
//! read readiness, and `TFD_TIMER_CANCEL_ON_SET` behavior. Raw Linux failures
//! become ordinary C `-1` plus the calling initial-TLS `errno` through the
//! shared selected-static result translator.
//!
//! This leaf is not a POSIX process-timer, signal, callback, timer registry,
//! event-loop, or readiness policy. It adds no pthread cancellation point,
//! dynamic runtime, loader/CRT/sysroot state, or public x86 support.

use core::ffi::{c_int, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

#[repr(C)]
struct PublicTimespec {
    seconds: i64,
    nanoseconds: i64,
}

/// Layout-only public x86 `struct itimerspec` record.
///
/// The wrappers do not dereference this Rust type; raw C pointers are passed
/// to Linux so the kernel preserves the caller's normal `EFAULT` behavior.
#[repr(C)]
struct PublicItimerspec {
    interval: PublicTimespec,
    value: PublicTimespec,
}

const _: () = {
    assert!(size_of::<PublicTimespec>() == 16);
    assert!(align_of::<PublicTimespec>() == 8);
    assert!(offset_of!(PublicTimespec, seconds) == 0);
    assert!(offset_of!(PublicTimespec, nanoseconds) == 8);
    assert!(size_of::<PublicItimerspec>() == 32);
    assert!(align_of::<PublicItimerspec>() == 8);
    assert!(offset_of!(PublicItimerspec, interval) == 0);
    assert!(offset_of!(PublicItimerspec, value) == 16);
};

/// Create one timer descriptor through Linux `timerfd_create(2)`.
///
/// Linux validates the clock and creation flags and owns the returned
/// descriptor's lifetime. This selected static C leaf does not add timer or
/// descriptor ownership policy.
#[no_mangle]
pub extern "C" fn timerfd_create(clock_id: c_int, flags: c_int) -> c_int {
    // SAFETY: both arguments are scalar Linux words; Linux validates their
    // values and allocates the descriptor only on success.
    c_status(unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_TIMERFD_CREATE,
            i64::from(clock_id),
            i64::from(flags),
        )
    })
}

/// Arm, disarm, or replace one timer descriptor setting.
///
/// # Safety
///
/// `new_value` must be null or point to readable x86 LP64 `struct itimerspec`
/// storage for the syscall duration. `old_value` must be null or point to
/// writable storage for the same record. The descriptor must remain open for
/// the syscall; its concurrent ownership, read, and timer policy stay with
/// the C caller. Null or inaccessible pointers reach Linux unchanged and use
/// its ordinary `EFAULT` result.
#[no_mangle]
pub unsafe extern "C" fn timerfd_settime(
    descriptor: c_int,
    flags: c_int,
    new_value: *const c_void,
    old_value: *mut c_void,
) -> c_int {
    // SAFETY: the caller owns both record-pointer and descriptor-lifetime
    // contracts. The helper maps C's fourth word to Linux x86-64 r10.
    c_status(unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_TIMERFD_SETTIME,
            i64::from(descriptor),
            i64::from(flags),
            new_value as usize as i64,
            old_value as usize as i64,
        )
    })
}

/// Query one timer descriptor's current setting.
///
/// # Safety
///
/// `current_value` must be null or point to writable x86 LP64 `struct
/// itimerspec` storage for the syscall duration. The descriptor must remain
/// open throughout the syscall. Null or inaccessible storage is deliberately
/// passed to Linux for its ordinary `EFAULT` result; this leaf adds no timer
/// ownership or synchronization policy.
#[no_mangle]
pub unsafe extern "C" fn timerfd_gettime(
    descriptor: c_int,
    current_value: *mut c_void,
) -> c_int {
    // SAFETY: the caller owns the output-record and descriptor-lifetime
    // contracts; Linux validates both the descriptor and output storage.
    c_status(unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_TIMERFD_GETTIME,
            i64::from(descriptor),
            current_value as usize as i64,
        )
    })
}
