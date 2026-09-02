//! Selected static Linux/x86-64 `ualarm` C boundary.
//!
//! This private one-symbol adaptation maps to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT
//! license: `src/unistd/ualarm.c` plus its complete x86 LP64 direct branch in
//! `src/signal/setitimer.c`. On this ABI `time_t` and `long` are both eight
//! bytes, so musl puts the supplied unsigned microsecond `value` and
//! `interval` directly into zero-second `ITIMER_REAL` fields, invokes
//! `setitimer`, and returns the previous remaining time as
//! `tv_sec * 1_000_000 + tv_usec` with C unsigned wrapping.
//!
//! Musl leaves its old record uninitialized before the nested `setitimer`
//! call, so an invalid microsecond field has no usable musl return-value
//! oracle. Rust necessarily uses a zero-initialized old record. This x86 leaf
//! deliberately matches the active AArch64 C ABI's safe fallback instead:
//! after publishing the ordinary Linux error in `errno`, it returns
//! `UINT_MAX`. The differential covers only valid return values; the invalid
//! `1_000_000` field is asserted solely through errno and unchanged timer
//! state.
//!
//! This boundary exports neither `alarm`, `getitimer`, nor `setitimer`; it
//! owns only the historical microsecond adapter. It does not install handlers,
//! alter masks, wait for, or deliver a signal. A caller retains all SIGALRM,
//! process-timer, and concurrency policy.

use core::ffi::{c_long, c_uint};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

const ITIMER_REAL: i64 = 0;
const MICROSECONDS_PER_SECOND: c_uint = 1_000_000;

/// Exact public Linux/x86-64 `struct timeval` storage.
#[repr(C)]
struct Timeval {
    seconds: c_long,
    microseconds: c_long,
}

/// Exact public Linux/x86-64 `struct itimerval` storage.
#[repr(C)]
struct Itimerval {
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

/// Replace `ITIMER_REAL` with microsecond fields and return its old value.
///
/// Linux accepts only canonical subsecond `tv_usec` values. For those inputs,
/// this preserves musl's historical `ualarm` rule: write zero-second interval
/// and value fields, then return the previous remaining interval in
/// microseconds with C unsigned wrapping. Successful calls leave caller
/// `errno` unchanged. Musl's failure return is indeterminate because its old
/// record is uninitialized; this zero-initialized Rust record instead returns
/// `UINT_MAX` after the normal C errno translation, matching the existing
/// AArch64 implementation. The caller owns process-global timer state and any
/// resulting SIGALRM disposition.
#[no_mangle]
pub extern "C" fn ualarm(value: c_uint, interval: c_uint) -> c_uint {
    let requested = Itimerval {
        interval: Timeval {
            seconds: 0,
            microseconds: interval as c_long,
        },
        value: Timeval {
            seconds: 0,
            microseconds: value as c_long,
        },
    };
    let mut old = Itimerval {
        interval: Timeval {
            seconds: 0,
            microseconds: 0,
        },
        value: Timeval {
            seconds: 0,
            microseconds: 0,
        },
    };

    // SAFETY: the fixed real-timer selector and two complete local records
    // match Linux/x86-64 `setitimer=38`.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SETITIMER,
            ITIMER_REAL,
            (&requested as *const Itimerval) as usize as i64,
            (&mut old as *mut Itimerval) as usize as i64,
        )
    };
    if c_status(result) < 0 {
        return c_uint::MAX;
    }

    (old.value.seconds as c_uint)
        .wrapping_mul(MICROSECONDS_PER_SECOND)
        .wrapping_add(old.value.microseconds as c_uint)
}
