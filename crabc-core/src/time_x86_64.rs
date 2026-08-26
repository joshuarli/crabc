//! Bounded Linux/x86-64 clock and relative-sleep operations.
//!
//! This module owns only the x86-64 `timespec` wire record, clock query
//! boundaries, and the direct relative `nanosleep` syscall. Timers, clock
//! mutation, process-owned time state, and the C ABI remain outside this
//! staged slice.

use core::mem::MaybeUninit;

use crate::syscall::{decode, syscall2, SYS_CLOCK_GETRES, SYS_NANOSLEEP};
use crate::Result;

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
