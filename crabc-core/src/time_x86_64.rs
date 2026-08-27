//! Bounded Linux/x86-64 clock and relative-sleep operations.
//!
//! This module owns the x86-64 `timespec`, `itimerspec`, and read-only legacy
//! `itimerval` wire records, clock query boundaries, timerfd operations, and
//! the direct `nanosleep` and private `clock_nanosleep` syscalls. Clock
//! mutation, process-owned time state, and the C ABI remain outside this staged
//! slice.

use core::mem::MaybeUninit;

use crate::syscall::{
    decode, syscall2, syscall4, SYS_CLOCK_GETRES, SYS_CLOCK_NANOSLEEP, SYS_GETITIMER, SYS_NANOSLEEP,
    SYS_TIMERFD_CREATE, SYS_TIMERFD_GETTIME, SYS_TIMERFD_SETTIME,
};
use crate::{RawFd, Result};

/// Linux/x86-64 `struct timespec` as written by the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KernelTimespec {
    /// Seconds in the selected Linux clock's epoch.
    pub tv_sec: i64,
    /// Nanoseconds within `tv_sec`.
    pub tv_nsec: i64,
}

const _: () = assert!(core::mem::size_of::<KernelTimespec>() == 16);
const _: () = assert!(core::mem::align_of::<KernelTimespec>() == 8);

/// Linux/x86-64 `struct timeval` nested in an interval-timer record.
///
/// This is a syscall wire type with two signed 64-bit words, not a public C
/// ABI alias. Linux normalizes a successful `getitimer` microsecond remainder
/// to `0..1_000_000`; the native facade validates it before constructing a
/// Rust duration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KernelItimervalTimeval {
    /// Whole seconds in the interval-timer value.
    pub tv_sec: i64,
    /// Microseconds within `tv_sec`.
    pub tv_usec: i64,
}

const _: () = assert!(core::mem::size_of::<KernelItimervalTimeval>() == 16);
const _: () = assert!(core::mem::align_of::<KernelItimervalTimeval>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelItimervalTimeval, tv_sec) == 0);
const _: () = assert!(core::mem::offset_of!(KernelItimervalTimeval, tv_usec) == 8);

/// Linux/x86-64 `struct itimerval` returned by `getitimer`.
///
/// The kernel writes the interval first and remaining value second. This
/// private wire record is deliberately distinct from a public C `itimerval`
/// declaration and from timerfd's nanosecond `itimerspec` record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KernelItimerval {
    /// Time between expirations, or zero for a one-shot timer.
    pub it_interval: KernelItimervalTimeval,
    /// Time remaining until the next expiration, or zero when disarmed.
    pub it_value: KernelItimervalTimeval,
}

const _: () = assert!(core::mem::size_of::<KernelItimerval>() == 32);
const _: () = assert!(core::mem::align_of::<KernelItimerval>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelItimerval, it_interval) == 0);
const _: () = assert!(core::mem::offset_of!(KernelItimerval, it_value) == 16);

/// Linux/x86-64 `struct itimerspec` used by the timerfd syscalls.
///
/// Both nested records are the exact 16-byte x86-64 kernel timespec layout;
/// this is a syscall wire type and is intentionally distinct from any public
/// Rust duration or C ABI representation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KernelItimerspec {
    /// Time between expirations, or zero for a one-shot timer.
    pub it_interval: KernelTimespec,
    /// Initial or absolute expiration, or zero when disarmed.
    pub it_value: KernelTimespec,
}

const _: () = assert!(core::mem::size_of::<KernelItimerspec>() == 32);
const _: () = assert!(core::mem::align_of::<KernelItimerspec>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelItimerspec, it_interval) == 0);
const _: () = assert!(core::mem::offset_of!(KernelItimerspec, it_value) == 16);

/// Sleeps for a relative Linux/x86-64 timespec without using libc or TLS
/// `errno`.
///
/// Linux initializes `remaining` only when the sleep is interrupted with
/// `EINTR`; callers must not read it for any other result.
///
/// # Safety
///
/// `request` must point to a readable Linux/x86-64 `struct timespec`.
/// `remaining` must point to writable storage for one such value.
#[inline]
pub unsafe fn nanosleep_raw(request: *const u8, remaining: *mut u8) -> Result<()> {
    // SAFETY: The caller owns both timespec pointer contracts; Linux
    // validates the requested range and writes `remaining` only on EINTR.
    decode(unsafe { syscall2(SYS_NANOSLEEP, request as usize, remaining as usize) }).map(|_| ())
}

/// Performs Linux/x86-64 `clock_nanosleep` through its native four-argument
/// syscall ABI, without using libc or TLS `errno`.
///
/// `flags` is zero for a relative request and `1` (`TIMER_ABSTIME`) for an
/// absolute request. Linux does not write `remaining` for an absolute
/// request; callers should pass null in that mode.
///
/// # Safety
///
/// `request` must point to a readable Linux/x86-64 `struct timespec`.
/// For a relative request, `remaining` must point to writable storage for one
/// such value. For an absolute request, `remaining` must be null.
#[inline]
pub unsafe fn clock_nanosleep_raw(
    clock_id: i32,
    flags: u32,
    request: *const u8,
    remaining: *mut u8,
) -> Result<()> {
    // SAFETY: The caller owns the timespec pointer contracts; Linux validates
    // the clock identifier, flags, and timespec fields.
    decode(unsafe {
        syscall4(
            SYS_CLOCK_NANOSLEEP,
            clock_id as usize,
            flags as usize,
            request as usize,
            remaining as usize,
        )
    })
    .map(|_| ())
}

/// Reads one Linux/x86-64 process interval timer without using libc or TLS
/// `errno`.
///
/// `which` is the raw Linux `ITIMER_*` selector. The native facade owns the
/// closed safe selector vocabulary, while this boundary preserves Linux's
/// `EINVAL` result for unsupported raw values.
///
/// # Safety
///
/// `value` must point to writable storage for one [`KernelItimerval`] value
/// that remains live for the syscall. Linux initializes the complete record on
/// success. An invalid pointer may be passed deliberately when testing the
/// kernel's pointer-validation behavior.
#[inline]
pub unsafe fn getitimer_raw(which: i32, value: *mut KernelItimerval) -> Result<()> {
    // SAFETY: The caller owns the exact output-pointer contract documented
    // above; Linux validates the selector and writes all four words on success.
    decode(unsafe { syscall2(SYS_GETITIMER, which as usize, value as usize) }).map(|_| ())
}

/// Reads one x86-64 Linux clock through the validated vDSO, with a direct
/// syscall fallback when the process vDSO is unavailable or malformed.
pub fn clock_gettime(clock_id: i32) -> Result<KernelTimespec> {
    let mut value = MaybeUninit::<KernelTimespec>::uninit();
    // SAFETY: `value` is writable storage for the exact x86-64 timespec
    // record and the dispatcher initializes both fields on success.
    unsafe { decode(crate::vdso::clock_gettime_status(clock_id, value.as_mut_ptr().cast()) as isize)? };
    // SAFETY: The successful kernel/vDSO result initialized `value`.
    Ok(unsafe { value.assume_init() })
}

/// Fills caller-owned x86-64 `struct timespec` storage from the validated
/// vDSO or direct syscall path.
///
/// # Safety
///
/// `timespec` must point to writable storage for one 16-byte x86-64 Linux
/// `struct timespec`; the storage must remain live for the duration of the
/// call. Linux initializes both signed 64-bit fields on success.
pub unsafe fn clock_gettime_raw(clock_id: i32, timespec: *mut u8) -> Result<()> {
    // SAFETY: The caller owns the exact output-pointer contract documented
    // above; the shared dispatcher performs the target syscall/vDSO call.
    unsafe { decode(crate::vdso::clock_gettime_status(clock_id, timespec) as isize) }.map(|_| ())
}

/// Creates a Linux/x86-64 timerfd descriptor without using libc or TLS
/// `errno`.
#[inline]
pub fn timerfd_create(clock_id: i32, flags: u32) -> Result<RawFd> {
    // SAFETY: Linux validates the clock identifier and descriptor flags; no
    // user memory is accessed by this operation.
    decode(unsafe { syscall2(SYS_TIMERFD_CREATE, clock_id as usize, flags as usize) })
        .map(|fd| fd as RawFd)
}

/// Arms or disarms a Linux/x86-64 timerfd descriptor without using libc or
/// TLS `errno`.
///
/// # Safety
///
/// `new_value` must be non-null and point to readable, initialized
/// [`KernelItimerspec`] storage for the duration of the syscall. `old_value`
/// must be null or point to writable storage for one [`KernelItimerspec`]; if
/// non-null, Linux initializes that record on success. The descriptor must
/// be a timerfd owned by the caller, and `flags` must contain only the Linux
/// timerfd settime flags.
#[inline]
pub unsafe fn timerfd_settime_raw(
    fd: RawFd,
    flags: u32,
    new_value: *const KernelItimerspec,
    old_value: *mut KernelItimerspec,
) -> Result<()> {
    // SAFETY: The caller owns both typed pointer contracts documented above;
    // Linux validates the descriptor and timer flags.
    decode(unsafe {
        syscall4(
            SYS_TIMERFD_SETTIME,
            fd as usize,
            flags as usize,
            new_value as usize,
            old_value as usize,
        )
    })
    .map(|_| ())
}

/// Reads a Linux/x86-64 timerfd descriptor's current setting without using
/// libc or TLS `errno`.
///
/// # Safety
///
/// `current_value` must be non-null and point to writable storage for one
/// [`KernelItimerspec`] for the duration of the syscall. Linux initializes the
/// complete record on success, and `fd` must be a timerfd owned by the caller.
#[inline]
pub unsafe fn timerfd_gettime_raw(
    fd: RawFd,
    current_value: *mut KernelItimerspec,
) -> Result<()> {
    // SAFETY: The caller owns the typed output-pointer contract documented
    // above; Linux validates the descriptor.
    decode(unsafe {
        syscall2(SYS_TIMERFD_GETTIME, fd as usize, current_value as usize)
    })
    .map(|_| ())
}

/// Reads the resolution of one x86-64 Linux clock through the direct syscall.
pub fn clock_getres(clock_id: i32) -> Result<KernelTimespec> {
    let mut value = MaybeUninit::<KernelTimespec>::uninit();
    // SAFETY: `value` is writable storage for the exact x86-64 timespec
    // record and Linux initializes it on success.
    unsafe {
        decode(syscall2(
            SYS_CLOCK_GETRES,
            clock_id as usize,
            value.as_mut_ptr() as usize,
        ))?
    };
    // SAFETY: The successful syscall initialized `value`.
    Ok(unsafe { value.assume_init() })
}
