//! Selected static Linux/x86-64 alarm C boundary.
//!
//! This private one-symbol adaptation maps to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT
//! license: `src/unistd/alarm.c` plus its complete x86 LP64
//! `src/signal/setitimer.c` direct branch. `time_t` and `long` are both
//! eight bytes here, so musl builds a zero-interval `ITIMER_REAL` record,
//! calls `setitimer`, and returns the previous remaining seconds rounded up
//! when its microsecond field is nonzero.
//!
//! The `setitimer=38` C return is intentionally discarded, exactly as in
//! musl's historical `alarm` wrapper; its ordinary errno side effect remains
//! observable if the fixed syscall somehow fails. This boundary exports neither
//! `setitimer` nor `ualarm`; it owns only the one replacement/disarm adapter.
//! It does not install handlers, alter masks, wait for, or deliver a signal.
//! A caller retains all SIGALRM disposition, process-timer, and concurrency
//! policy.

use core::ffi::{c_long, c_uint};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

const ITIMER_REAL: i64 = 0;

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

/// Replace the process's real-time interval timer and return its old remainder.
///
/// This is the historical C `alarm` contract: it writes a one-shot
/// `ITIMER_REAL` value in whole seconds, discards the `setitimer` C status
/// after preserving its ordinary failure-to-errno side effect, and rounds a
/// prior nonzero microsecond remainder upward. It has no error return and
/// leaves successful caller `errno` unchanged. The caller owns the
/// process-global timer and any resulting SIGALRM disposition.
#[no_mangle]
pub extern "C" fn alarm(seconds: c_uint) -> c_uint {
    let requested = Itimerval {
        interval: Timeval {
            seconds: 0,
            microseconds: 0,
        },
        value: Timeval {
            seconds: seconds as c_long,
            microseconds: 0,
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
    // Musl discards setitimer's C return value, but the nested wrapper still
    // translates a Linux failure into errno. Preserve that otherwise-unseen
    // side effect while retaining zero-initialized `old` as the return fallback.
    let _ = c_status(result);

    let fractional_remainder: c_uint = if old.value.microseconds != 0 { 1 } else { 0 };
    (old.value.seconds as c_uint).wrapping_add(fractional_remainder)
}
