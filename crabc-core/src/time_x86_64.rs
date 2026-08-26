//! Bounded Linux/x86-64 clock operations.
//!
//! This module owns only the x86-64 `clock_gettime` and `clock_getres` wire
//! records and their direct kernel/vDSO boundary. Timers, clock mutation, and
//! process-owned time state remain outside this staged slice.

use core::mem::MaybeUninit;

use crate::syscall::{decode, syscall2, SYS_CLOCK_GETRES};
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
