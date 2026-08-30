//! Selected static Linux/x86-64 C clock-observation boundary.
//!
//! This leaf owns one bounded direct C time-query block: `clock`, `time`,
//! `difftime`, C11 `timespec_get`, `clock_getres`, and `gettimeofday`. It
//! composes only the raw Linux x86-64 syscall ABI and the selected initial-TLS
//! `errno` writer. It is not calendar or timezone state, clock mutation,
//! POSIX timers, pthread cancellation, a vDSO resolver, libc.so, CRT,
//! dynamic TLS, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/time/clock.c` maps to [`clock`].
//! - `src/time/time.c` maps to [`time`].
//! - `src/time/difftime.c` maps to [`difftime`].
//! - `src/time/timespec_get.c` maps to [`timespec_get`].
//! - `src/time/clock_getres.c` maps to [`clock_getres`].
//! - `src/time/gettimeofday.c` maps to [`gettimeofday`].
//!
//! Musl may use its private vDSO resolver for the underlying clock calls.
//! This dependency-free static artifact instead issues the Linux 5.10
//! syscalls directly. That intentionally does not select a process-lifetime
//! vDSO state owner.

use core::ffi::{c_int, c_long, c_void};

use super::{c_status, raw_syscall};

const CLOCK_REALTIME: c_int = 0;
const CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
const CLOCKS_PER_SEC: c_long = 1_000_000;
const NANOSECONDS_PER_SECOND: c_long = 1_000_000_000;
const TIME_UTC: c_int = 1;

/// Exact Linux/x86-64 `struct timespec` wire storage.
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

/// Exact Linux/x86-64 `struct timeval` wire storage.
#[repr(C)]
struct Timeval {
    seconds: c_long,
    microseconds: c_long,
}

const _: () = {
    assert!(core::mem::size_of::<Timespec>() == 16);
    assert!(core::mem::align_of::<Timespec>() == 8);
    assert!(core::mem::offset_of!(Timespec, seconds) == 0);
    assert!(core::mem::offset_of!(Timespec, nanoseconds) == 8);
    assert!(core::mem::size_of::<Timeval>() == 16);
    assert!(core::mem::align_of::<Timeval>() == 8);
    assert!(core::mem::offset_of!(Timeval, seconds) == 0);
    assert!(core::mem::offset_of!(Timeval, microseconds) == 8);
};

/// Read one Linux clock using the ordinary C `0`/`-1` and `errno` boundary.
///
/// # Safety
///
/// `output` must be null only where the named Linux clock syscall permits it,
/// or otherwise point to writable 16-byte x86 `struct timespec` storage for
/// the call. The caller owns its lifetime and clock-ID policy.
#[inline]
unsafe fn clock_status(clock_id: c_int, output: *mut Timespec) -> c_int {
    // SAFETY: the caller owns the raw clock ID and output pointer contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_GETTIME,
            i64::from(clock_id),
            output as usize as i64,
        )
    };
    c_status(result)
}

/// Return CPU time consumed by the calling process in microseconds.
///
/// A failed underlying query returns `-1` after publishing the raw Linux
/// error in the selected initial-TLS `errno` slot.
#[no_mangle]
pub extern "C" fn clock() -> c_long {
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: `value` is writable exact timespec storage for this call.
    if unsafe { clock_status(CLOCK_PROCESS_CPUTIME_ID, &mut value) } != 0 {
        return -1;
    }
    value
        .seconds
        .wrapping_mul(CLOCKS_PER_SEC)
        .wrapping_add(value.nanoseconds / (NANOSECONDS_PER_SECOND / CLOCKS_PER_SEC))
}

/// Return the realtime clock's whole-second value and optionally store it.
///
/// # Safety
///
/// When non-null, `output` must point to writable LP64 `time_t` storage. The
/// caller owns its lifetime. This direct static leaf does not select calendar,
/// timezone, or vDSO runtime state.
#[no_mangle]
pub unsafe extern "C" fn time(output: *mut c_long) -> c_long {
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: `value` is writable exact timespec storage for this call.
    if unsafe { clock_status(CLOCK_REALTIME, &mut value) } != 0 {
        return -1;
    }
    if !output.is_null() {
        // SAFETY: the caller supplied writable `time_t` storage.
        unsafe { output.write(value.seconds) };
    }
    value.seconds
}

/// Compute a `double` difference without integer subtraction overflow.
#[no_mangle]
pub extern "C" fn difftime(left: c_long, right: c_long) -> f64 {
    (left as f64) - (right as f64)
}

/// Read realtime into one C11 `timespec_get` output record.
///
/// # Safety
///
/// When `base` is `TIME_UTC`, `output` must point to writable 16-byte x86
/// `struct timespec` storage for the call. Unsupported bases return zero
/// without inspecting the output pointer, matching musl's C11 boundary.
#[no_mangle]
pub unsafe extern "C" fn timespec_get(output: *mut c_void, base: c_int) -> c_int {
    if base != TIME_UTC {
        return 0;
    }
    // SAFETY: the caller owns the C11 output-record contract for TIME_UTC.
    if unsafe { clock_status(CLOCK_REALTIME, output.cast::<Timespec>()) } == 0 {
        TIME_UTC
    } else {
        0
    }
}

/// Query the resolution of one Linux clock.
///
/// # Safety
///
/// `output` must be null only where Linux permits it, or otherwise designate
/// writable 16-byte x86 `struct timespec` storage for the call. The caller
/// owns the clock-ID and output lifetime contract.
#[no_mangle]
pub unsafe extern "C" fn clock_getres(clock_id: c_int, output: *mut c_void) -> c_int {
    // SAFETY: the caller owns the raw clock ID and optional output contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_GETRES,
            i64::from(clock_id),
            output as usize as i64,
        )
    };
    c_status(result)
}

/// Store Linux realtime wall-clock parts while ignoring obsolete timezone
/// output.
///
/// # Safety
///
/// `output` must be null only where Linux permits it, or otherwise point to
/// writable 16-byte x86 `struct timeval` storage for the call. The second C
/// argument is deliberately ignored: this selected profile has no obsolete
/// timezone state or output contract.
#[no_mangle]
pub unsafe extern "C" fn gettimeofday(output: *mut c_void, _timezone: *mut c_void) -> c_int {
    // SAFETY: the caller owns the optional timeval pointer contract. A null
    // second word requests no obsolete timezone result from Linux.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_GETTIMEOFDAY,
            output as usize as i64,
            0,
        )
    };
    c_status(result)
}
