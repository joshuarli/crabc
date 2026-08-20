//! Direct Linux kernel random-source operations.
//!
//! This module intentionally exposes the kernel's short-read behavior. Code
//! needing an atomic all-or-error entropy request should use the C `getentropy`
//! boundary or explicitly loop over [`getrandom`].

use bitflags::bitflags;

use crate::buffer::Buffer;
use crate::Result;

bitflags! {
    /// Flags accepted by Linux `getrandom`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct GetRandomFlags: u32 {
        /// Return `EAGAIN` rather than waiting for the random pool.
        const NONBLOCK = 0x1;
        /// Draw from `/dev/random` semantics.
        const RANDOM = 0x2;
        /// Request a cryptographically secure but potentially early-boot
        /// source, where the kernel supports it.
        const INSECURE = 0x4;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

/// Obtains random bytes from the Linux kernel.
///
/// For initialized buffers the return value is the number of bytes received.
/// For `MaybeUninit` storage it separates the initialized prefix from the
/// remaining uninitialized suffix. A successful result may be short.
#[inline]
#[allow(private_interfaces)]
pub fn getrandom<Buf: Buffer<u8>>(mut buffer: Buf, flags: GetRandomFlags) -> Result<Buf::Output> {
    let (pointer, length) = buffer.parts_mut();
    // SAFETY: `Buffer` supplies writable storage for exactly `length` bytes.
    let initialized = unsafe { crabc_core::rand::getrandom_raw(pointer, length, flags.bits())? };
    // SAFETY: Linux initialized exactly its successful return prefix.
    unsafe { Ok(buffer.assume_init(initialized)) }
}
