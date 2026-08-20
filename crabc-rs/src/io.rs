//! Direct descriptor I/O.
//!
//! These operations use the shared typed kernel seam in `crabc-core`; they do
//! not call crabc's public C ABI and never read or write TLS `errno`.

use core::mem::MaybeUninit;

use crate::{AsFd, Result};

pub use crate::Errno;

/// Reads bytes into potentially uninitialized storage.
///
/// Only the first returned number of elements are initialized by a successful
/// call. The descriptor remains borrowed for the duration of the operation.
#[inline]
pub fn read<Fd: AsFd>(fd: Fd, buffer: &mut [MaybeUninit<u8>]) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `MaybeUninit<u8>` has the same layout as `u8`, and the slice is
    // valid writable storage for its length. The API reports how many bytes the
    // kernel initialized.
    unsafe {
        crabc_core::io::read_raw(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    }
}

/// Writes the complete byte slice as far as the kernel accepts it.
///
/// A successful short write is reported as its actual byte count, matching the
/// Linux `write` contract.
#[inline]
pub fn write<Fd: AsFd>(fd: Fd, buffer: &[u8]) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `buffer` is valid immutable storage for its exact length.
    unsafe { crabc_core::io::write_raw(fd.as_raw_fd(), buffer.as_ptr(), buffer.len()) }
}
