//! Stateless Linux/AArch64 time operations.

use core::mem::MaybeUninit;

use crate::{RawFd, Result};
use crate::syscall::{decode, decode_i32, syscall1, syscall2, syscall3, syscall4, SYS_CLOCK_GETRES, SYS_CLOCK_NANOSLEEP, SYS_CLOCK_SETTIME, SYS_GETITIMER, SYS_GETTIMEOFDAY, SYS_NANOSLEEP, SYS_SETITIMER, SYS_TIMERFD_CREATE, SYS_TIMERFD_GETTIME, SYS_TIMERFD_SETTIME, SYS_TIMER_CREATE, SYS_TIMER_DELETE, SYS_TIMER_GETOVERRUN, SYS_TIMER_GETTIME, SYS_TIMER_SETTIME};

/// One signed timeval from Linux/AArch64's legacy `getitimer` result.
///
/// This is the exact kernel wire layout: both fields are signed 64-bit
/// words, with `tv_usec` normalized by Linux to `0..1_000_000`. It is not
/// a public C `timeval` alias; the native facade validates these fields
/// before exposing them as Rust [`core::time::Duration`] values.
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KernelItimervalTimeval {
    /// Whole seconds in the interval-timer value.
    pub tv_sec: i64,
    /// Microseconds within `tv_sec`.
    pub tv_usec: i64,
}

/// Linux/AArch64's four-word `struct __kernel_old_itimerval` result.
///
/// The kernel writes the interval first and the current value second.
/// This is a syscall wire record rather than a C ABI type; callers should
/// validate each nested timeval before converting it to a native value.
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KernelItimerval {
    /// Time between expirations, or zero for a one-shot timer.
    pub it_interval: KernelItimervalTimeval,
    /// Time remaining until the next expiration, or zero when disarmed.
    pub it_value: KernelItimervalTimeval,
}

/// One Linux/AArch64 POSIX-timer timespec.
///
/// This private wire record intentionally remains separate from the
/// public Rust `Timespec`: it exists only to make the timer syscalls'
/// pointer and layout contract explicit.
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KernelTimerTimespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds within the second.
    pub tv_nsec: i64,
}

/// Linux/AArch64's POSIX timer setting record.
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KernelItimerspec {
    /// Interval between expirations.
    pub it_interval: KernelTimerTimespec,
    /// Initial or absolute expiration.
    pub it_value: KernelTimerTimespec,
}

/// Kernel wall-clock fields returned by AArch64 `gettimeofday`.
///
/// This is a private wire contract for the native Rust facade, not a
/// public C `timeval` type. Linux reports signed Unix-epoch seconds and a
/// canonical microsecond remainder in the range `0..1_000_000`.
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KernelWallClockParts {
    /// Signed seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
    pub seconds: i64,
    /// Microseconds within `seconds`, as normalized by Linux.
    pub microseconds: i64,
}

/// Queries Linux's UTC wall clock without using libc, vDSO dispatch, or
/// TLS `errno`.
#[inline]
pub fn gettimeofday() -> Result<KernelWallClockParts> {
    let mut value = MaybeUninit::<KernelWallClockParts>::uninit();
    // SAFETY: `value` has the exact two-word AArch64 kernel layout, and a
    // successful syscall initializes both fields.
    unsafe { gettimeofday_raw(value.as_mut_ptr().cast())? };
    // SAFETY: Linux initialized `value` on the successful return above.
    Ok(unsafe { value.assume_init() })
}

/// Reads one Linux process interval timer without using libc or TLS
/// `errno`.
///
/// `which` is the Linux `ITIMER_*` selector (`0`, `1`, or `2`). The
/// selector remains raw at this syscall boundary so Linux can report
/// `EINVAL` for unsupported values; the Rust facade supplies the closed
/// interval-timer vocabulary.
///
/// # Safety
///
/// `value` must point to writable storage for one
/// [`KernelItimerval`] value. Linux initializes all four words on
/// success. An invalid pointer may be passed deliberately when testing
/// the kernel's pointer validation behavior.
#[inline]
pub unsafe fn getitimer_raw(which: i32, value: *mut u8) -> Result<()> {
    // SAFETY: The caller owns the result-pointer contract; Linux validates
    // the selector and writes the complete four-word record on success.
    decode(unsafe { syscall2(SYS_GETITIMER, which as usize, value as usize) }).map(|_| ())
}

/// Arms or disarms one Linux process interval timer and optionally
/// returns its previous setting without using libc or TLS `errno`.
///
/// # Safety
///
/// `new_value` must point to one Linux/AArch64 `__kernel_old_itimerval`;
/// `old_value` must be null or writable storage for the same record.
#[inline]
pub unsafe fn setitimer_raw(
    which: i32,
    new_value: *const u8,
    old_value: *mut u8,
) -> Result<()> {
    // SAFETY: The caller owns both timeval record pointer contracts;
    // Linux validates the selector and the timeval values.
    decode(unsafe {
        syscall3(
            SYS_SETITIMER,
            which as usize,
            new_value as usize,
            old_value as usize,
        )
    })
    .map(|_| ())
}

/// Creates one Linux POSIX timer with a private kernel `sigevent` record.
///
/// # Safety
///
/// `event` must be null or point to the exact 64-byte Linux/AArch64
/// `sigevent` layout. `timer_id` must point to writable `i32` storage.
#[inline]
pub unsafe fn timer_create_raw(
    clock_id: i32,
    event: *const u8,
    timer_id: *mut i32,
) -> Result<i32> {
    // SAFETY: The caller owns the event and result-pointer contracts;
    // Linux validates clock and notification values.
    decode_i32(unsafe {
        syscall3(
            SYS_TIMER_CREATE,
            clock_id as usize,
            event as usize,
            timer_id as usize,
        )
    })
}

/// Arms or disarms a Linux POSIX timer and optionally returns its old
/// setting without using libc or TLS `errno`.
///
/// # Safety
///
/// `new_value` must point to an initialized Linux/AArch64 `itimerspec`;
/// `old_value` must be null or writable storage for one such record.
#[inline]
pub unsafe fn timer_settime_raw(
    timer_id: i32,
    flags: i32,
    new_value: *const u8,
    old_value: *mut u8,
) -> Result<()> {
    // SAFETY: The caller owns both itimerspec pointer contracts; Linux
    // validates the timer ID, flags, and time values.
    decode(unsafe {
        syscall4(
            SYS_TIMER_SETTIME,
            timer_id as usize,
            flags as usize,
            new_value as usize,
            old_value as usize,
        )
    })
    .map(|_| ())
}

/// Reads one Linux POSIX timer's current setting without using libc or
/// TLS `errno`.
///
/// # Safety
///
/// `value` must point to writable storage for one Linux/AArch64
/// `itimerspec` record.
#[inline]
pub unsafe fn timer_gettime_raw(timer_id: i32, value: *mut u8) -> Result<()> {
    // SAFETY: The caller owns the output-memory contract; Linux validates
    // the timer ID and initializes the complete record on success.
    decode(unsafe { syscall2(SYS_TIMER_GETTIME, timer_id as usize, value as usize) })
        .map(|_| ())
}

/// Returns a Linux POSIX timer's overrun count without using libc or TLS
/// `errno`.
#[inline]
pub fn timer_getoverrun_raw(timer_id: i32) -> Result<i32> {
    // SAFETY: The timer ID is a scalar and Linux validates it.
    decode_i32(unsafe { syscall1(SYS_TIMER_GETOVERRUN, timer_id as usize) })
}

/// Deletes one Linux POSIX timer without using libc or TLS `errno`.
#[inline]
pub fn timer_delete_raw(timer_id: i32) -> Result<()> {
    // SAFETY: The timer ID is a scalar and Linux validates it.
    decode(unsafe { syscall1(SYS_TIMER_DELETE, timer_id as usize) }).map(|_| ())
}

/// Performs the Linux/AArch64 `gettimeofday` syscall.
///
/// The second syscall argument is deliberately null: timezone output is a
/// legacy C process-global concept and is not part of this native query.
///
/// # Safety
///
/// `parts` must point to writable storage for one
/// [`KernelWallClockParts`] value.
#[inline]
pub unsafe fn gettimeofday_raw(parts: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies storage for the kernel's two-word
    // result; the null timezone pointer requests no legacy timezone data.
    decode(unsafe { syscall2(SYS_GETTIMEOFDAY, parts as usize, 0) }).map(|_| ())
}

/// Queries Linux realtime through the validated vDSO when present, falling
/// back to the direct `gettimeofday` syscall with the raw kernel result.
///
/// # Safety
///
/// `timeval` must be null or writable for one Linux/AArch64 timeval; the
/// optional `timezone` pointer follows the same kernel ABI.
#[inline]
pub unsafe fn gettimeofday_status_raw(timeval: *mut u8, timezone: *mut u8) -> i32 {
    // SAFETY: The caller owns both kernel ABI pointers.
    unsafe { crate::vdso::gettimeofday_status(timeval, timezone) }
}

/// Sleeps for a relative Linux/AArch64 timespec without using libc or TLS
/// `errno`.
///
/// Linux initializes `remaining` only when the sleep is interrupted with
/// `EINTR`; callers must not read it for any other result.
///
/// # Safety
///
/// `request` must point to a readable Linux/AArch64 `struct timespec`.
/// `remaining` must point to writable storage for one such value.
#[inline]
pub unsafe fn nanosleep_raw(request: *const u8, remaining: *mut u8) -> Result<()> {
    // SAFETY: The caller owns both timespec pointer contracts; Linux
    // validates the requested range and writes `remaining` only on EINTR.
    decode(unsafe { syscall2(SYS_NANOSLEEP, request as usize, remaining as usize) }).map(|_| ())
}

/// Performs Linux/AArch64 `clock_nanosleep` with its native four-argument
/// syscall ABI, without using libc or TLS `errno`.
///
/// `flags` is zero for a relative request and `1` (`TIMER_ABSTIME`) for an
/// absolute request. Linux does not write `remaining` for an absolute
/// request; callers should pass null in that mode.
///
/// # Safety
///
/// `request` must point to a readable Linux/AArch64 `struct timespec`.
/// For a relative request, `remaining` must point to writable storage for
/// one such value. For an absolute request, `remaining` must be null.
#[inline]
pub unsafe fn clock_nanosleep_raw(
    clock_id: i32,
    flags: u32,
    request: *const u8,
    remaining: *mut u8,
) -> Result<()> {
    // SAFETY: The caller owns the timespec pointer contracts; Linux
    // validates the clock identifier, flags, and timespec fields.
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

/// Queries a Linux clock through the validated kernel vDSO when present,
/// otherwise through the direct syscall, without libc or TLS `errno`.
///
/// # Safety
///
/// `timespec` must be writable for one Linux/AArch64 `struct timespec`.
#[inline]
pub unsafe fn clock_gettime_raw(clock_id: i32, timespec: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies exact output storage for the vDSO or
    // direct Linux/AArch64 timespec ABI.
    decode(unsafe { clock_gettime_status_raw(clock_id, timespec) } as isize).map(|_| ())
}

/// Queries a Linux clock with the raw kernel success/negative-errno
/// convention used by the C ABI wrapper.
///
/// The route is the same validated vDSO dispatch and direct-syscall
/// fallback as [`clock_gettime_raw`], but it avoids constructing an
/// internal `Result` only to translate it immediately back to C's errno
/// convention.
///
/// # Safety
///
/// `timespec` must be writable for one Linux/AArch64 `struct timespec`.
#[inline]
pub unsafe fn clock_gettime_status_raw(clock_id: i32, timespec: *mut u8) -> i32 {
    // SAFETY: The caller owns the output-pointer contract.
    unsafe { crate::vdso::clock_gettime_status(clock_id, timespec) }
}

/// Sets a Linux clock without using libc, vDSO dispatch, or TLS `errno`.
///
/// Linux permits only settable clocks and requires the caller to have
/// permission to change them. The kernel therefore remains responsible
/// for returning `EINVAL` for a non-settable clock and `EPERM` when the
/// caller lacks the required privilege.
///
/// # Safety
///
/// `timespec` must point to a readable Linux/AArch64 `struct timespec`
/// whose `tv_nsec` field has already been validated as canonical.
#[inline]
pub unsafe fn clock_settime_raw(clock_id: i32, timespec: *const u8) -> Result<()> {
    // SAFETY: The caller owns the readable timespec pointer contract and
    // has validated its nanosecond field before crossing this boundary.
    decode(unsafe { syscall2(SYS_CLOCK_SETTIME, clock_id as usize, timespec as usize) })
        .map(|_| ())
}

/// Queries the resolution of a Linux clock without using libc, vDSO
/// dispatch, or TLS `errno`.
///
/// # Safety
///
/// `timespec` must be writable for one Linux/AArch64 `struct timespec`.
#[inline]
pub unsafe fn clock_getres_raw(clock_id: i32, timespec: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies exact output storage for the kernel
    // timespec layout; Linux validates the clock identifier.
    decode(unsafe { syscall2(SYS_CLOCK_GETRES, clock_id as usize, timespec as usize) })
        .map(|_| ())
}

/// Creates a Linux timer descriptor without using libc or TLS `errno`.
#[inline]
pub fn timerfd_create(clock_id: i32, flags: u32) -> Result<RawFd> {
    // SAFETY: Linux validates the clock identifier and timer descriptor
    // flags; no user memory is accessed by this operation.
    decode(unsafe { crate::syscall::syscall2(SYS_TIMERFD_CREATE, clock_id as usize, flags as usize) })
        .map(|fd| fd as RawFd)
}

/// Arms or disarms a Linux timer descriptor without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// `new_value` must point to one writable Linux/AArch64 `struct
/// itimerspec`, and `old_value` must be null or point to writable storage
/// for one such value.
#[inline]
pub unsafe fn timerfd_settime_raw(
    fd: RawFd,
    flags: u32,
    new_value: *const u8,
    old_value: *mut u8,
) -> Result<()> {
    // SAFETY: The caller owns the two `itimerspec` pointer contracts;
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

/// Reads a Linux timer descriptor's current setting without using libc or
/// TLS `errno`.
///
/// # Safety
///
/// `current_value` must point to writable storage for one Linux/AArch64
/// `struct itimerspec`.
#[inline]
pub unsafe fn timerfd_gettime_raw(fd: RawFd, current_value: *mut u8) -> Result<()> {
    // SAFETY: The caller owns the output-memory contract; Linux validates
    // the descriptor.
    decode(unsafe { crate::syscall::syscall2(SYS_TIMERFD_GETTIME, fd as usize, current_value as usize) })
        .map(|_| ())
}
