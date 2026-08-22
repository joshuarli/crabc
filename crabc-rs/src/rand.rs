//! Direct Linux kernel random-source operations.
//!
//! This module intentionally exposes the kernel's short-read behavior. Code
//! needing an atomic all-or-error entropy request should use [`getentropy`]
//! or explicitly loop over [`getrandom`].

use bitflags::bitflags;

use crate::buffer::Buffer;
use crate::Result;

/// Maximum request size accepted by [`getentropy`], as required by musl's
/// Linux implementation and the C interface it mirrors.
pub const GETENTROPY_MAX_LENGTH: usize = 256;

/// An explicitly owned deterministic pseudo-random state.
///
/// This is a small, non-cryptographic generator for callers that need a
/// reproducible sequence. It does not borrow or modify any C `rand`/`random`
/// process-global state. Use [`Self::from_entropy`] when the initial seed
/// should come from the Linux kernel; the resulting sequence is still only as
/// strong as this generator, and must not be used for secrets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RandomState {
    state: u64,
}

impl RandomState {
    /// Creates a deterministic generator from an explicitly supplied seed.
    ///
    /// Every seed, including zero, is valid. The sequence is stable for this
    /// API's lifetime, but is not a cryptographic construction.
    #[inline]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Creates a generator seeded from Linux `getrandom`.
    ///
    /// This fills the seed completely, retrying short successful kernel reads.
    /// Kernel errors are returned as [`crate::Errno`] values; no C `errno` or
    /// libc random state is involved.
    #[inline]
    pub fn from_entropy() -> Result<Self> {
        let mut seed = [0_u8; core::mem::size_of::<u64>()];
        let mut offset = 0;
        while offset < seed.len() {
            let received = getrandom(&mut seed[offset..], GetRandomFlags::empty())?;
            if received == 0 {
                // Linux should not return a zero-length successful read for
                // this non-empty request. Avoid looping forever if that
                // contract is ever violated by a kernel or test double.
                return Err(crate::Errno::IO);
            }
            offset += received;
        }
        Ok(Self::new(u64::from_ne_bytes(seed)))
    }

    /// Returns the next 64-bit value and advances this owned state.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64 has one word of state, accepts every seed, and has no
        // forbidden all-zero state. Wrapping arithmetic is part of its
        // definition and is explicit here for debug-build portability.
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Returns the low 32 bits of the next 64-bit value.
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}

/// Draws one deterministic 32-bit value from explicitly owned state.
#[inline]
pub fn random_u32(state: &mut RandomState) -> u32 {
    state.next_u32()
}

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

/// Obtains a complete entropy request from Linux's random source.
///
/// This is the Rust-native equivalent of C `getentropy`: requests larger than
/// [`GETENTROPY_MAX_LENGTH`] fail with [`crate::Errno::IO`] before crossing the
/// kernel boundary, and a successful call always initializes the entire
/// caller-provided buffer. Linux may return short successful `getrandom`
/// reads, so this function keeps reading until the request is complete. An
/// interrupted read is retried; a zero-byte read is treated as [`crate::Errno::IO`]
/// rather than looping forever.
///
/// As with [`getrandom`], initialized buffers return their initialized byte
/// count and `MaybeUninit` buffers return the initialized and remaining
/// uninitialized subslices. An error may follow a partial kernel write, but
/// no uninitialized bytes are exposed as initialized in the result.
#[inline]
#[allow(private_interfaces)]
pub fn getentropy<Buf: Buffer<u8>>(mut buffer: Buf) -> Result<Buf::Output> {
    let (pointer, length) = buffer.parts_mut();
    if length > GETENTROPY_MAX_LENGTH {
        return Err(crate::Errno::IO);
    }

    let mut initialized = 0;
    while initialized < length {
        // SAFETY: `Buffer` supplies writable storage for `length` bytes, and
        // the initialized prefix keeps this pointer within that range.
        let received = match unsafe {
            crabc_core::rand::getrandom_raw(
                pointer.add(initialized),
                length - initialized,
                GetRandomFlags::empty().bits(),
            )
        } {
            Ok(received) if received != 0 && received <= length - initialized => received,
            Ok(_) => return Err(crate::Errno::IO),
            Err(error) if error == crate::Errno::INTR => continue,
            Err(error) => return Err(error),
        };
        initialized += received;
    }

    // SAFETY: The loop above proves that the kernel initialized exactly the
    // full caller-provided buffer before exposing the result.
    unsafe { Ok(buffer.assume_init(length)) }
}
