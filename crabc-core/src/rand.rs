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
    // Miri: a fixed test stream, never entropy; see `miri_model`.
    #[cfg(all(miri, target_arch = "x86_64"))]
    return unsafe { crate::miri_model::getrandom(buffer, length, flags) };
    // SAFETY: The caller supplies the output-memory contract; Linux
    // validates the random-source flags.
    decode(unsafe { syscall3(SYS_GETRANDOM, buffer as usize, length, flags as usize) })
}
