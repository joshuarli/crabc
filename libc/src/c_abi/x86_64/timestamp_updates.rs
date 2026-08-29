//! Selected static Linux/x86-64 C timestamp-update boundary.
//!
//! This leaf owns `utimensat`, `futimens`, the legacy timeval adapters
//! `futimes`, `futimesat`, `lutimes`, and `utimes`, plus `utime`. It composes
//! only the selected raw Linux syscall register boundary and the initial-TLS
//! C `errno` slot. It is not a general C runtime, cancellation-point layer,
//! libc.so, CRT, loader, sysroot, pathname layer, or timestamp policy.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/stat/utimensat.c` maps to [`utimensat`] and its all-`UTIME_NOW`
//!   null-times optimization.
//! - `src/stat/futimens.c` maps to [`futimens`].
//! - `src/stat/futimesat.c` maps to [`__futimesat`] and musl's weak,
//!   same-address `futimesat` alias.
//! - `src/legacy/futimes.c`, `src/legacy/lutimes.c`, and
//!   `src/linux/utimes.c` map to the legacy timeval adapters.
//! - `src/time/utime.c` maps to [`utime`].
//!
//! Linux 5.10 provides `utimensat=280`, so this bounded target deliberately
//! does not select musl's older `ENOSYS` fallback through `futimesat` or
//! `utimes`. As in musl, only `__futimesat` validates a timeval's
//! microseconds before conversion; `futimes` and `lutimes` retain the direct
//! conversion and Linux validates the resulting timespecs.

use core::ffi::{c_char, c_int};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, errno, raw_syscall};

const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const EINVAL: c_int = 22;
const UTIME_NOW: i64 = 0x3fff_ffff;

/// Private Linux/x86-64 `struct timespec` C ABI record.
#[repr(C)]
pub struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

/// Private Linux/x86-64 `struct timeval` C ABI record.
#[repr(C)]
pub struct Timeval {
    seconds: i64,
    microseconds: i64,
}

/// Private Linux/x86-64 `struct utimbuf` C ABI record.
#[repr(C)]
pub struct Utimbuf {
    access_time: i64,
    modification_time: i64,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, seconds) == 0);
    assert!(offset_of!(Timespec, nanoseconds) == 8);
    assert!(size_of::<Timeval>() == 16);
    assert!(align_of::<Timeval>() == 8);
    assert!(offset_of!(Timeval, seconds) == 0);
    assert!(offset_of!(Timeval, microseconds) == 8);
    assert!(size_of::<Utimbuf>() == 16);
    assert!(align_of::<Utimbuf>() == 8);
    assert!(offset_of!(Utimbuf, access_time) == 0);
    assert!(offset_of!(Utimbuf, modification_time) == 8);
};

/// Issue the Linux `utimensat` request after musl's all-now optimization.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timespec`
/// records. `path`, `directory_descriptor`, and `flags` must satisfy Linux
/// `utimensat(2)`'s complete raw syscall contract. A null `path` is permitted
/// only for the `futimens` descriptor form selected below.
#[inline]
unsafe fn utimensat_impl(
    directory_descriptor: c_int,
    path: *const c_char,
    times: *const Timespec,
    flags: c_int,
) -> c_int {
    let times = if !times.is_null()
        // SAFETY: the caller guarantees two readable `Timespec` records.
        && unsafe { (*times).nanoseconds == UTIME_NOW }
        // SAFETY: the caller guarantees two readable `Timespec` records.
        && unsafe { (*times.add(1)).nanoseconds == UTIME_NOW }
    {
        core::ptr::null()
    } else {
        times
    };

    // SAFETY: the caller owns the full raw Linux `utimensat` contract. The
    // x86 syscall wrapper moves `flags` from the C ABI's rcx into r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_UTIMENSAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            times as usize as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Convert a timeval pair exactly as musl's legacy `futimes` and `lutimes`
/// sources do, without user-space range validation.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timeval`
/// records. `converted` is private writable stack storage for the duration of
/// the following syscall.
#[inline]
unsafe fn legacy_timeval_pair(
    times: *const Timeval,
    converted: &mut [Timespec; 2],
) -> *const Timespec {
    if times.is_null() {
        return core::ptr::null();
    }

    // SAFETY: the caller guarantees two readable `Timeval` records.
    let first = unsafe { times.read() };
    // SAFETY: the caller guarantees two readable `Timeval` records.
    let second = unsafe { times.add(1).read() };
    converted[0] = Timespec {
        seconds: first.seconds,
        nanoseconds: first.microseconds.wrapping_mul(1_000),
    };
    converted[1] = Timespec {
        seconds: second.seconds,
        nanoseconds: second.microseconds.wrapping_mul(1_000),
    };
    converted.as_ptr()
}

/// Convert and validate one timeval pair for musl's `__futimesat` boundary.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timeval`
/// records. `converted` is private writable stack storage for the duration of
/// the following syscall.
#[inline]
unsafe fn futimesat_timeval_pair(
    times: *const Timeval,
    converted: &mut [Timespec; 2],
) -> Option<*const Timespec> {
    if times.is_null() {
        return Some(core::ptr::null());
    }

    // SAFETY: the caller guarantees two readable `Timeval` records.
    let first = unsafe { times.read() };
    // SAFETY: the caller guarantees two readable `Timeval` records.
    let second = unsafe { times.add(1).read() };
    if first.microseconds < 0
        || first.microseconds >= 1_000_000
        || second.microseconds < 0
        || second.microseconds >= 1_000_000
    {
        // SAFETY: this local musl-compatible validation failure belongs to
        // the calling thread's selected C ABI errno slot.
        unsafe { errno::set_errno(EINVAL) };
        return None;
    }

    converted[0] = Timespec {
        seconds: first.seconds,
        nanoseconds: first.microseconds * 1_000,
    };
    converted[1] = Timespec {
        seconds: second.seconds,
        nanoseconds: second.microseconds * 1_000,
    };
    Some(converted.as_ptr())
}

// Musl's `weak_alias(__futimesat, futimesat)` requires the two ELF names to
// identify one implementation. A Rust forwarding wrapper would have a
// distinct address and change that source-specific ABI contract.
core::arch::global_asm!(
    ".weak futimesat",
    ".set futimesat, __futimesat",
);

/// Update a pathname's timestamps through Linux `utimensat(2)`.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timespec`
/// records. `path`, `directory_descriptor`, and `flags` must satisfy Linux
/// `utimensat(2)`'s complete pointer, lifetime, and argument requirements.
#[no_mangle]
pub unsafe extern "C" fn utimensat(
    directory_descriptor: c_int,
    path: *const c_char,
    times: *const Timespec,
    flags: c_int,
) -> c_int {
    // SAFETY: this C entry point documents the raw `utimensat` requirements.
    unsafe { utimensat_impl(directory_descriptor, path, times, flags) }
}

/// Update an open file descriptor's timestamps through the null-path
/// `utimensat` form.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timespec`
/// records. `file_descriptor` must be suitable for Linux `futimens`-style
/// timestamp updates and remain valid for the syscall.
#[no_mangle]
pub unsafe extern "C" fn futimens(
    file_descriptor: c_int,
    times: *const Timespec,
) -> c_int {
    // SAFETY: the C entry point's descriptor and timespec requirements are
    // exactly those of the selected null-path `utimensat` form.
    unsafe { utimensat_impl(file_descriptor, core::ptr::null(), times, 0) }
}

/// Musl's strong implementation behind the weak `futimesat` C ABI alias.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timeval`
/// records. `path` and `directory_descriptor` must satisfy Linux
/// `utimensat(2)`'s pathname and descriptor requirements.
#[no_mangle]
pub unsafe extern "C" fn __futimesat(
    directory_descriptor: c_int,
    path: *const c_char,
    times: *const Timeval,
) -> c_int {
    let mut converted = [
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
    ];
    // SAFETY: the C entry point documents the input timeval pair requirement.
    let times = match unsafe { futimesat_timeval_pair(times, &mut converted) } {
        Some(times) => times,
        None => return -1,
    };
    // SAFETY: the converted pair is valid private stack storage for this call,
    // and the C entry point documents the pathname/descriptor requirements.
    unsafe { utimensat_impl(directory_descriptor, path, times, 0) }
}

/// Update an open file descriptor's timestamps from a legacy timeval pair.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timeval`
/// records. `file_descriptor` must be suitable for Linux timestamp updates
/// and remain valid for the syscall.
#[no_mangle]
pub unsafe extern "C" fn futimes(file_descriptor: c_int, times: *const Timeval) -> c_int {
    if times.is_null() {
        // SAFETY: a null pair selects Linux's current-time behavior.
        return unsafe { futimens(file_descriptor, core::ptr::null()) };
    }

    let mut converted = [
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
    ];
    // SAFETY: the C entry point documents the input timeval pair requirement.
    let times = unsafe { legacy_timeval_pair(times, &mut converted) };
    // SAFETY: the converted pair is valid private stack storage for this call.
    unsafe { futimens(file_descriptor, times) }
}

/// Update a pathname's timestamps from a legacy timeval pair without
/// following the final symbolic link.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timeval`
/// records. `path` must satisfy Linux `utimensat(2)`'s pathname, lifetime,
/// and accessibility requirements.
#[no_mangle]
pub unsafe extern "C" fn lutimes(path: *const c_char, times: *const Timeval) -> c_int {
    let mut converted = [
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
    ];
    // SAFETY: the C entry point documents the input timeval pair requirement.
    let times = unsafe { legacy_timeval_pair(times, &mut converted) };
    // SAFETY: the converted pair is valid private stack storage for this call,
    // and the C entry point documents the pathname requirement.
    unsafe { utimensat_impl(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW) }
}

/// Update a pathname's timestamps from a legacy timeval pair.
///
/// # Safety
///
/// If non-null, `times` must point to two readable x86 `struct timeval`
/// records. `path` must satisfy Linux `utimensat(2)`'s pathname, lifetime,
/// and accessibility requirements.
#[no_mangle]
pub unsafe extern "C" fn utimes(path: *const c_char, times: *const Timeval) -> c_int {
    // SAFETY: forwarded unchanged to musl's selected `__futimesat` boundary.
    unsafe { __futimesat(AT_FDCWD, path, times) }
}

/// Update a pathname's timestamps from a legacy seconds-only `utimbuf`.
///
/// # Safety
///
/// If non-null, `times` must point to one readable x86 `struct utimbuf`
/// record. `path` must satisfy Linux `utimensat(2)`'s pathname, lifetime,
/// and accessibility requirements.
#[no_mangle]
pub unsafe extern "C" fn utime(path: *const c_char, times: *const Utimbuf) -> c_int {
    let mut converted = [
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
        Timespec {
            seconds: 0,
            nanoseconds: 0,
        },
    ];
    let times = if times.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: the C entry point documents one readable `Utimbuf` record.
        let times = unsafe { times.read() };
        converted[0].seconds = times.access_time;
        converted[1].seconds = times.modification_time;
        converted.as_ptr()
    };

    // SAFETY: the converted pair is valid private stack storage for this call,
    // and the C entry point documents the pathname requirement.
    unsafe { utimensat_impl(AT_FDCWD, path, times, 0) }
}
