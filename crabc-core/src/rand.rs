//! Stateless Linux/AArch64 random-source operations.

use crate::Result;
use crate::syscall::{decode, syscall3, SYS_GETRANDOM};

/// Reads random bytes without using libc or TLS `errno`.
///
/// # Safety
///
/// `buffer` must be writable for `length` bytes unless `length` is zero.
#[inline]
pub unsafe fn getrandom_raw(buffer: *mut u8, length: usize, flags: u32) -> Result<usize> {
    // SAFETY: The caller supplies the output-memory contract; Linux
    // validates the random-source flags.
    decode(unsafe { syscall3(SYS_GETRANDOM, buffer as usize, length, flags as usize) })
}
