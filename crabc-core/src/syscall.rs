//! Linux syscall result decoding and architecture entry.

use crate::error::MAX_ERRNO;
use crate::{Errno, Result};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

#[inline]
pub(crate) fn decode(result: isize) -> Result<usize> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux syscall errors are in the inclusive `-4095..=-1` range.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as usize)
}

#[inline]
pub(crate) fn decode_i32(result: isize) -> Result<i32> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux syscall errors are in the inclusive `-4095..=-1` range.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as i32)
}

#[inline]
pub(crate) fn decode_i64(result: isize) -> Result<i64> {
    if result < 0 && result >= -(MAX_ERRNO as isize) {
        // SAFETY: Linux syscall errors are in the inclusive `-4095..=-1` range.
        return Err(Errno::from_raw_os_error((-result) as i32));
    }
    Ok(result as i64)
}


// Miri cannot execute `syscall`; these seams dispatch to the kernel model.
// Calls that return pointers or write through caller pointers never reach
// here: their typed wrappers call the model directly to keep provenance.
#[cfg(miri)]
#[inline(always)]
pub(crate) unsafe fn syscall0(number: usize) -> isize {
    crate::miri_model::syscall(number, [0; 6])
}

#[cfg(miri)]
#[inline(always)]
pub(crate) unsafe fn syscall1(number: usize, arg0: usize) -> isize {
    crate::miri_model::syscall(number, [arg0, 0, 0, 0, 0, 0])
}

#[cfg(miri)]
#[inline(always)]
pub(crate) unsafe fn syscall2(number: usize, arg0: usize, arg1: usize) -> isize {
    crate::miri_model::syscall(number, [arg0, arg1, 0, 0, 0, 0])
}

#[cfg(miri)]
#[inline(always)]
pub(crate) unsafe fn syscall3(number: usize, arg0: usize, arg1: usize, arg2: usize) -> isize {
    crate::miri_model::syscall(number, [arg0, arg1, arg2, 0, 0, 0])
}

#[cfg(miri)]
#[inline(always)]
pub(crate) unsafe fn syscall4(number: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    crate::miri_model::syscall(number, [arg0, arg1, arg2, arg3, 0, 0])
}

#[cfg(miri)]
#[inline(always)]
pub(crate) unsafe fn syscall5(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> isize {
    crate::miri_model::syscall(number, [arg0, arg1, arg2, arg3, arg4, 0])
}

#[cfg(miri)]
#[inline(always)]
pub(crate) unsafe fn syscall6(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> isize {
    crate::miri_model::syscall(number, [arg0, arg1, arg2, arg3, arg4, arg5])
}
