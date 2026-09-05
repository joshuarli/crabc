//! Owned Linux/x86-64 legacy time and clock-adjustment C boundaries.
//!
//! This owned-product leaf maps pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/time/times.c::times` maps to [`times`].
//! - `src/linux/adjtimex.c::adjtimex` maps to [`adjtimex`].
//! - `src/linux/adjtime.c::adjtime` maps to [`adjtime`].
//! - `src/linux/settimeofday.c::settimeofday` maps to [`settimeofday`].
//! - `src/linux/stime.c::stime` maps to [`stime`].
//!
//! On Linux/x86-64, musl's `times` deliberately uses raw `__syscall` rather
//! than its ordinary errno translator. Its signed return therefore preserves
//! both the kernel's elapsed-tick bit pattern, including a wrapped negative
//! value, and a raw negative errno range. `adjtime` and `adjtimex` instead use
//! the existing owned [`super::clock_adjtime::clock_adjtime`] C boundary and
//! its ordinary `-1`/initial-TLS-`errno` convention. That source-shaped
//! composition leaves `clock_adjtime` as the sole owner of Linux's clock
//! adjustment syscall ABI.
//!
//! `adjtime(NULL, output)` and a zero-mode `adjtimex` record are observation
//! requests. A non-null `adjtime` input can discipline `CLOCK_REALTIME`; the
//! product qualification therefore blocks that syscall with a disposable
//! seccomp child before exercising its C error boundary. `settimeofday` and
//! `stime` are likewise only exercised as null, local-validation, or
//! seccomp-denied calls. `clock_settime` remains the sole owner of Linux's
//! realtime clock-setting syscall ABI.

use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{errno, raw_syscall};

const CLOCK_REALTIME: c_int = 0;
const EINVAL: c_int = 22;
const ADJ_OFFSET_SINGLESHOT: c_uint = 0x8001;
const MICROSECONDS_PER_SECOND: c_long = 1_000_000;

/// Exact Linux/x86-64 `struct timeval` storage used by musl `adjtime`.
#[repr(C)]
struct Timeval {
    seconds: c_long,
    microseconds: c_long,
}

/// Exact Linux/x86-64 `struct tms` storage used by musl `times`.
#[repr(C)]
struct Tms {
    user: c_long,
    system: c_long,
    children_user: c_long,
    children_system: c_long,
}

/// Exact Linux/x86-64 `struct timespec` storage used by `settimeofday`.
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

/// Exact Linux/x86-64 `struct timex` storage used by musl `adjtime`.
#[repr(C)]
struct Timex {
    modes: c_uint,
    offset: c_long,
    frequency: c_long,
    maximum_error: c_long,
    estimated_error: c_long,
    status: c_int,
    time_constant: c_long,
    precision: c_long,
    tolerance: c_long,
    time: Timeval,
    tick: c_long,
    pps_frequency: c_long,
    jitter: c_long,
    shift: c_int,
    stability: c_long,
    jitter_count: c_long,
    calibration_count: c_long,
    error_count: c_long,
    stability_count: c_long,
    tai: c_int,
    padding: [c_int; 11],
}

impl Timex {
    const fn zeroed() -> Self {
        Self {
            modes: 0,
            offset: 0,
            frequency: 0,
            maximum_error: 0,
            estimated_error: 0,
            status: 0,
            time_constant: 0,
            precision: 0,
            tolerance: 0,
            time: Timeval {
                seconds: 0,
                microseconds: 0,
            },
            tick: 0,
            pps_frequency: 0,
            jitter: 0,
            shift: 0,
            stability: 0,
            jitter_count: 0,
            calibration_count: 0,
            error_count: 0,
            stability_count: 0,
            tai: 0,
            padding: [0; 11],
        }
    }
}

const _: () = {
    assert!(size_of::<Timeval>() == 16);
    assert!(align_of::<Timeval>() == 8);
    assert!(offset_of!(Timeval, seconds) == 0);
    assert!(offset_of!(Timeval, microseconds) == 8);
    assert!(size_of::<Tms>() == 32);
    assert!(align_of::<Tms>() == 8);
    assert!(offset_of!(Tms, user) == 0);
    assert!(offset_of!(Tms, system) == 8);
    assert!(offset_of!(Tms, children_user) == 16);
    assert!(offset_of!(Tms, children_system) == 24);
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, seconds) == 0);
    assert!(offset_of!(Timespec, nanoseconds) == 8);
    assert!(size_of::<Timex>() == 208);
    assert!(align_of::<Timex>() == 8);
    assert!(offset_of!(Timex, modes) == 0);
    assert!(offset_of!(Timex, offset) == 8);
    assert!(offset_of!(Timex, time) == 72);
    assert!(offset_of!(Timex, tai) == 160);
};

/// Read the calling process's Linux accounting ticks without error decoding.
///
/// # Safety
///
/// `output` may be null, as Linux `times(2)` permits, or it must point to one
/// writable, aligned x86-64 `struct tms` record for the syscall duration. The
/// result deliberately remains raw: callers must not treat every negative
/// `clock_t` as an errno return because the elapsed kernel tick count can wrap
/// into that signed range.
#[no_mangle]
pub unsafe extern "C" fn times(output: *mut Tms) -> c_long {
    // SAFETY: the caller owns Linux's nullable-or-writable `times(2)` output
    // contract. Musl uses `__syscall`, so do not publish an errno or collapse
    // a valid wrapped tick count to C's ordinary error sentinel.
    unsafe { raw_syscall::syscall1(raw_syscall::SYS_TIMES, output as usize as i64) as c_long }
}

/// Forward musl's `adjtimex` spelling through the existing realtime owner.
///
/// # Safety
///
/// `state` must point to writable, aligned 208-byte x86-64 `struct timex`
/// storage for the call. Its modes and fields can request global clock state
/// mutation; callers own that authority and those consequences.
#[no_mangle]
pub unsafe extern "C" fn adjtimex(state: *mut Timex) -> c_int {
    // SAFETY: musl's x86-64 implementation calls `clock_adjtime` with the
    // fixed realtime ID and the same borrowed public timex storage.
    unsafe { super::clock_adjtime::clock_adjtime(CLOCK_REALTIME, state.cast::<c_void>()) }
}

/// Apply or query one legacy realtime clock adjustment through musl's rule.
///
/// # Safety
///
/// `increment`, when non-null, must point to one readable x86-64 `timeval`.
/// `remaining`, when non-null, must point to one writable record. A non-null
/// increment can change host clock discipline; callers own that authority and
/// process/system-wide consequence.
#[no_mangle]
pub unsafe extern "C" fn adjtime(
    increment: *const Timeval,
    remaining: *mut Timeval,
) -> c_int {
    let mut state = Timex::zeroed();
    if !increment.is_null() {
        // SAFETY: the C entry point documents one readable `timeval` record.
        let increment = unsafe { increment.read() };
        // Preserve musl's intentionally narrow upper-bound-only guard. Its
        // signed source expression has machine-word arithmetic on x86-64;
        // explicit wrapping preserves that result without debug-overflow
        // behavior becoming an ABI distinction.
        if increment.seconds > 1000 || increment.microseconds > 1_000_000_000 {
            // SAFETY: the local source-faithful validation failure belongs to
            // the calling thread's selected C ABI errno slot.
            unsafe { errno::set_errno(EINVAL) };
            return -1;
        }
        state.offset = increment
            .seconds
            .wrapping_mul(MICROSECONDS_PER_SECOND)
            .wrapping_add(increment.microseconds);
        state.modes = ADJ_OFFSET_SINGLESHOT;
    }

    // SAFETY: `state` is complete, writable exact x86 `struct timex` storage.
    if unsafe { adjtimex(&mut state) } < 0 {
        return -1;
    }

    if !remaining.is_null() {
        let mut seconds = state.offset / MICROSECONDS_PER_SECOND;
        let mut microseconds = state.offset % MICROSECONDS_PER_SECOND;
        if microseconds < 0 {
            seconds -= 1;
            microseconds += MICROSECONDS_PER_SECOND;
        }
        // SAFETY: the C entry point documents one writable `timeval` record.
        unsafe {
            remaining.write(Timeval {
                seconds,
                microseconds,
            });
        }
    }
    0
}

/// Apply musl's legacy `settimeofday` conversion through `clock_settime`.
///
/// # Safety
///
/// `value` may be null, which returns success without observing `timezone`.
/// Otherwise it must point to one readable, aligned x86-64 `timeval` record.
/// `timezone` is retained only for the public C ABI and is never read, as in
/// musl. A valid non-null value can discipline `CLOCK_REALTIME`; callers own
/// that authority and its system-wide consequence.
#[no_mangle]
pub unsafe extern "C" fn settimeofday(
    value: *const Timeval,
    timezone: *const c_void,
) -> c_int {
    let _ = timezone;
    if value.is_null() {
        return 0;
    }
    // SAFETY: the C entry point documents one readable `timeval` record.
    let value = unsafe { value.read() };
    // Musl compares against an unsigned 64-bit literal, so all negative
    // signed microsecond fields reject alongside values at or above one second.
    if (value.microseconds as u64) >= MICROSECONDS_PER_SECOND as u64 {
        // SAFETY: this source-local validation failure is a normal C errno
        // result in the selected initial-TLS errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }
    let request = Timespec {
        seconds: value.seconds,
        nanoseconds: value.microseconds * 1_000,
    };
    // SAFETY: the exact LP64 timespec is borrowed for the call, and the
    // source fixes the clock ID to realtime.
    unsafe {
        super::clock_settime::clock_settime(
            CLOCK_REALTIME,
            (&request as *const Timespec).cast::<c_void>(),
        )
    }
}

/// Apply musl's historical `time_t`-to-`timeval` `stime` adapter.
///
/// # Safety
///
/// `value` must point to one readable x86-64 LP64 `time_t` word. The selected
/// source always dereferences it. A successful call can alter `CLOCK_REALTIME`;
/// callers own that authority and its system-wide consequence.
#[no_mangle]
pub unsafe extern "C" fn stime(value: *const c_long) -> c_int {
    // SAFETY: the C entry point documents one readable LP64 `time_t` word.
    let seconds = unsafe { value.read() };
    let request = Timeval {
        seconds,
        microseconds: 0,
    };
    // SAFETY: musl calls settimeofday with this complete local timeval and an
    // ignored null timezone pointer.
    unsafe { settimeofday(&request, core::ptr::null()) }
}
