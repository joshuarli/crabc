//! Native byte operations whose C contracts are not ordinary slice methods.
//!
//! The APIs in [`ByteOps`] use borrowed slices to make the amount of memory
//! accessed explicit. They never call crabc's public C ABI, consult `errno`,
//! or permit the pointer aliasing which makes the corresponding C functions
//! unsafe. Operations which return a C pointer instead return either a
//! borrowed destination suffix or an explicit absence value.

use core::sync::atomic::{compiler_fence, Ordering};

/// Byte operations with contracts that need more than ordinary slice copying.
pub struct ByteOps;

impl ByteOps {
    /// Overwrites every byte in `buffer` with zero using volatile stores.
    ///
    /// The volatile stores and compiler fences are intentional: this is a
    /// secure-erasure boundary, so the compiler must not remove the writes as
    /// dead stores merely because the caller does not subsequently read the
    /// buffer. The exclusive borrow makes the complete byte range valid for
    /// the duration of the operation.
    #[inline]
    pub fn explicit_bzero(buffer: &mut [u8]) {
        compiler_fence(Ordering::SeqCst);
        for byte in buffer {
            // SAFETY: `byte` is a valid, uniquely borrowed element of
            // `buffer`, and volatile writes preserve that element's validity.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Copies `source` into the beginning of `destination`, stopping after
    /// and including the first `needle` byte.
    ///
    /// The source slice supplies the C `memccpy` count. On success, the
    /// returned mutable suffix begins immediately after the copied needle;
    /// `None` means all of `source` was copied and the needle was absent. This
    /// makes the C pointer return value useful without exposing a raw pointer.
    ///
    /// # Panics
    ///
    /// Panics if `destination` is shorter than `source`, just as the ordinary
    /// Rust slice-copying APIs reject an insufficient destination. Separate
    /// source and destination borrows also make overlapping `memccpy` calls
    /// unrepresentable in safe Rust.
    #[inline]
    pub fn memccpy<'a>(
        destination: &'a mut [u8],
        source: &[u8],
        needle: u8,
    ) -> Option<&'a mut [u8]> {
        assert!(
            destination.len() >= source.len(),
            "memccpy destination is shorter than source"
        );

        for (index, &byte) in source.iter().enumerate() {
            destination[index] = byte;
            if byte == needle {
                return Some(destination.split_at_mut(index + 1).1);
            }
        }
        None
    }

    /// Copies `source` into `destination` and returns the untouched suffix
    /// beginning immediately after the copied bytes.
    ///
    /// This is the typed equivalent of `mempcpy`'s one-past-the-copy pointer.
    /// The separate immutable and mutable borrows make the C non-overlap
    /// precondition explicit in safe Rust.
    ///
    /// # Panics
    ///
    /// Panics if `destination` is shorter than `source`.
    #[inline]
    pub fn mempcpy<'a>(destination: &'a mut [u8], source: &[u8]) -> &'a mut [u8] {
        assert!(
            destination.len() >= source.len(),
            "mempcpy destination is shorter than source"
        );
        let copied = source.len();
        for (index, &byte) in source.iter().enumerate() {
            destination[index] = byte;
        }
        destination.split_at_mut(copied).1
    }

    /// Swaps each adjacent byte pair from `source` into `destination`.
    ///
    /// If `source` has odd length, its final byte is not consumed and the
    /// corresponding final destination byte is left unchanged, matching
    /// `swab`'s pairwise contract. The source slice supplies the C byte count.
    ///
    /// # Panics
    ///
    /// Panics if `destination` is shorter than `source`.
    #[inline]
    pub fn swab(source: &[u8], destination: &mut [u8]) {
        assert!(
            destination.len() >= source.len(),
            "swab destination is shorter than source"
        );

        let pairs = source.len() / 2;
        for pair in 0..pairs {
            let index = pair * 2;
            destination[index] = source[index + 1];
            destination[index + 1] = source[index];
        }
    }
}
