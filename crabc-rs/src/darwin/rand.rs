//! Darwin entropy requests over libSystem `getentropy`.

use super::errno::{self, Errno, Result};
use super::sys;
use crate::buffer::Buffer;
use crate::rand::GETENTROPY_MAX_LENGTH;

/// Fills the whole buffer from libSystem `getentropy`.
///
/// Requests larger than [`GETENTROPY_MAX_LENGTH`] fail with [`Errno::IO`]
/// before the call, as libSystem would. A successful call initializes the
/// entire buffer: Darwin's `getentropy` never returns a short fill.
///
/// Initialized buffers return their byte count and `MaybeUninit` buffers
/// return the initialized and remaining uninitialized subslices.
#[inline]
#[allow(private_interfaces)]
pub fn getentropy<Buf: Buffer<u8>>(mut buffer: Buf) -> Result<Buf::Output> {
    let (pointer, length) = buffer.parts_mut();
    if length > GETENTROPY_MAX_LENGTH {
        return Err(Errno::IO);
    }
    // SAFETY: `Buffer` supplies writable storage for exactly `length` bytes.
    let result = unsafe { sys::getentropy(pointer.cast(), length) };
    errno::check(result)?;
    // SAFETY: a successful `getentropy` initialized all `length` bytes.
    Ok(unsafe { buffer.assume_init(length) })
}
