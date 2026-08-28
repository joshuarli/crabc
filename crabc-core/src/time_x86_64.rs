//! Bounded Linux/x86-64 clock and relative-sleep operations.
//!
//! This module owns the x86-64 `timespec`, `itimerspec`, read-only legacy
//! `itimerval`, `itimerspec`, and `gettimeofday` wire records; clock-query and
//! mutation boundaries; owned POSIX timer syscalls; timerfd operations; and
//! the direct `nanosleep` and typed `clock_nanosleep` syscalls. The C ABI
//! remains outside this staged slice.

use core::mem::MaybeUninit;

use crate::syscall::{
    decode, decode_i32, syscall1, syscall2, syscall3, syscall4, SYS_CLOCK_GETRES,
    SYS_CLOCK_NANOSLEEP, SYS_CLOCK_SETTIME, SYS_GETITIMER, SYS_GETTIMEOFDAY, SYS_NANOSLEEP,
    SYS_SETITIMER, SYS_TIMER_CREATE, SYS_TIMER_DELETE, SYS_TIMER_GETOVERRUN, SYS_TIMER_GETTIME,
    SYS_TIMER_SETTIME, SYS_TIMERFD_CREATE, SYS_TIMERFD_GETTIME, SYS_TIMERFD_SETTIME,
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
const _: () = assert!(core::mem::offset_of!(KernelTimespec, tv_sec) == 0);
const _: () = assert!(core::mem::offset_of!(KernelTimespec, tv_nsec) == 8);

/// Linux/x86-64 `struct timeval` returned by `gettimeofday`.
///
/// This is a private direct-syscall record, not a public C `timeval` alias.
/// Linux writes signed Unix-epoch seconds and a normalized microsecond
/// remainder; the native facade validates that remainder before exposing its
/// Rust-native wall-clock counterpart.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KernelWallClockParts {
    /// Signed seconds since 1970-01-01 00:00:00 UTC.
    pub seconds: i64,
    /// Microseconds within `seconds`, normalized by Linux on success.
    pub microseconds: i64,
}

const _: () = assert!(core::mem::size_of::<KernelWallClockParts>() == 16);
const _: () = assert!(core::mem::align_of::<KernelWallClockParts>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelWallClockParts, seconds) == 0);
const _: () = assert!(core::mem::offset_of!(KernelWallClockParts, microseconds) == 8);

/// Reads Linux/x86-64's UTC wall clock without libc, vDSO dispatch, timezone
/// output, or TLS `errno`.
#[inline]
pub fn gettimeofday() -> Result<KernelWallClockParts> {
    let mut value = MaybeUninit::<KernelWallClockParts>::uninit();
    // SAFETY: `value` is exact writable x86-64 `timeval` storage, and Linux
    // initializes both words on a successful direct syscall.
    unsafe { gettimeofday_raw(value.as_mut_ptr())? };
    // SAFETY: the successful syscall above initialized the full record.
    Ok(unsafe { value.assume_init() })
}

/// Performs the Linux/x86-64 `gettimeofday` syscall with a null legacy
/// timezone argument.
///
/// # Safety
///
/// `parts` must point to writable storage for one [`KernelWallClockParts`]
/// value that remains live for the syscall. The second syscall argument is
/// always null: C timezone state is deliberately outside this native query.
#[inline]
pub unsafe fn gettimeofday_raw(parts: *mut KernelWallClockParts) -> Result<()> {
    // SAFETY: the caller owns the exact output-record pointer contract; the
    // null second argument requests no obsolete timezone result.
    decode(unsafe { syscall2(SYS_GETTIMEOFDAY, parts as usize, 0) }).map(|_| ())
}

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

/// Arms or disarms one Linux/x86-64 process interval timer and returns its
/// previous setting without using libc or TLS `errno`.
///
/// `which` is the raw Linux `ITIMER_*` selector. The native facade owns the
/// closed safe selector vocabulary and validates the setting before reaching
/// this boundary.
///
/// # Safety
///
/// `new_value` must be non-null and point to initialized Linux/x86-64
/// [`KernelItimerval`] storage for the duration of the syscall. `old_value`
/// must be null or point to writable storage for one [`KernelItimerval`]
/// value; Linux initializes a non-null output on success.
#[inline]
pub unsafe fn setitimer_raw(
    which: i32,
    new_value: *const KernelItimerval,
    old_value: *mut KernelItimerval,
) -> Result<()> {
    // SAFETY: The caller owns both timeval record pointer contracts;
    // Linux validates the selector and timeval values.
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

/// Sets one Linux/x86-64 clock through the direct syscall, without vDSO,
/// libc, or TLS `errno`.
///
/// # Safety
///
/// `timespec` must be non-null and point to one initialized
/// [`KernelTimespec`] whose nanosecond field has already been validated as a
/// canonical Linux value. The caller is responsible for accepting the
/// selected clock's privilege and mutability result.
#[inline]
pub unsafe fn clock_settime_raw(clock_id: i32, timespec: *const KernelTimespec) -> Result<()> {
    // SAFETY: The caller owns the initialized x86-64 timespec input contract;
    // Linux validates clock mutability and permission.
    decode(unsafe { syscall2(SYS_CLOCK_SETTIME, clock_id as usize, timespec as usize) }).map(|_| ())
}

/// Fills one caller-owned x86-64 Linux `timespec` through direct
/// `clock_getres`.
///
/// # Safety
///
/// `timespec` must point to writable storage for one [`KernelTimespec`] that
/// remains live for the syscall. Linux initializes both signed words on
/// success.
#[inline]
pub unsafe fn clock_getres_raw(clock_id: i32, timespec: *mut KernelTimespec) -> Result<()> {
    // SAFETY: The caller owns the exact x86-64 output record; Linux validates
    // the clock identifier and initializes it on success.
    decode(unsafe { syscall2(SYS_CLOCK_GETRES, clock_id as usize, timespec as usize) }).map(|_| ())
}

/// Creates one Linux/x86-64 POSIX timer using a private `sigevent` record.
///
/// # Safety
///
/// `event` must be null or point to one initialized private 64-byte Linux
/// `sigevent` record. `timer_id` must point to writable `i32` storage that
/// remains live for the syscall. The returned raw value is syscall success;
/// Linux writes the timer identifier through `timer_id`.
#[inline]
pub unsafe fn timer_create_raw(
    clock_id: i32,
    event: *const u8,
    timer_id: *mut i32,
) -> Result<i32> {
    // SAFETY: The caller owns the event and timer-ID pointer contracts; Linux
    // validates the clock and notification values.
    decode_i32(unsafe {
        syscall3(
            SYS_TIMER_CREATE,
            clock_id as usize,
            event as usize,
            timer_id as usize,
        )
    })
}

/// Arms or disarms one Linux/x86-64 POSIX timer and optionally returns its
/// previous setting.
///
/// # Safety
///
/// `new_value` must point to initialized [`KernelItimerspec`] storage.
/// `old_value` must be null or point to writable storage for one such record.
/// Both records must remain live for the syscall; Linux initializes a
/// non-null old-value record on success.
#[inline]
pub unsafe fn timer_settime_raw(
    timer_id: i32,
    flags: i32,
    new_value: *const KernelItimerspec,
    old_value: *mut KernelItimerspec,
) -> Result<()> {
    // SAFETY: The caller owns both exact itimerspec pointer contracts. The
    // fourth x86-64 syscall argument carries `old_value` in r10.
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

/// Reads one Linux/x86-64 POSIX timer setting.
///
/// # Safety
///
/// `value` must point to writable storage for one [`KernelItimerspec`] that
/// remains live for the syscall. Linux initializes the complete record on
/// success.
#[inline]
pub unsafe fn timer_gettime_raw(timer_id: i32, value: *mut KernelItimerspec) -> Result<()> {
    // SAFETY: The caller owns the complete x86-64 output record contract.
    decode(unsafe { syscall2(SYS_TIMER_GETTIME, timer_id as usize, value as usize) }).map(|_| ())
}

/// Returns one Linux/x86-64 POSIX timer's overrun count.
#[inline]
pub fn timer_getoverrun_raw(timer_id: i32) -> Result<i32> {
    // SAFETY: The scalar timer ID is validated by Linux.
    decode_i32(unsafe { syscall1(SYS_TIMER_GETOVERRUN, timer_id as usize) })
}

/// Deletes one Linux/x86-64 POSIX timer.
#[inline]
pub fn timer_delete_raw(timer_id: i32) -> Result<()> {
    // SAFETY: The scalar timer ID is validated by Linux.
    decode(unsafe { syscall1(SYS_TIMER_DELETE, timer_id as usize) }).map(|_| ())
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
    unsafe { clock_getres_raw(clock_id, value.as_mut_ptr())? };
    // SAFETY: The successful syscall initialized `value`.
    Ok(unsafe { value.assume_init() })
}
