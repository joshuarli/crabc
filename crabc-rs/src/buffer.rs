//! Receive buffers for direct kernel I/O.
//!
//! `read` accepts initialized and potentially uninitialized byte storage. The
//! return type makes the initialized portion explicit when the caller supplies
//! `MaybeUninit` storage, so safe callers cannot read bytes the kernel did not
//! write.

use core::mem::MaybeUninit;
use core::slice;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// A byte buffer accepted by an operation which initializes bytes.
///
/// This mirrors the useful Rustix distinction: initialized buffers return the
/// number of initialized bytes, while `MaybeUninit` buffers return the
/// initialized and uninitialized subslices. It is sealed so an implementation
/// cannot claim initialization for storage whose validity it cannot prove.
#[allow(private_bounds)]
pub trait Buffer<T>: private::Sealed<T> {
    /// The value returned after the kernel has initialized a buffer prefix.
    type Output;

    /// Returns writable storage as pointer and element count.
    #[doc(hidden)]
    fn parts_mut(&mut self) -> (*mut T, usize);

    /// Converts a successfully initialized prefix into the public result.
    ///
    /// # Safety
    ///
    /// The first `length` elements supplied by [`Self::parts_mut`] must have
    /// been initialized by the kernel operation.
    #[doc(hidden)]
    unsafe fn assume_init(self, length: usize) -> Self::Output;
}

impl<T> Buffer<T> for &mut [T] {
    type Output = usize;

    fn parts_mut(&mut self) -> (*mut T, usize) {
        (self.as_mut_ptr(), self.len())
    }

    unsafe fn assume_init(self, length: usize) -> Self::Output {
        length
    }
}

impl<T, const N: usize> Buffer<T> for &mut [T; N] {
    type Output = usize;

    fn parts_mut(&mut self) -> (*mut T, usize) {
        (self.as_mut_ptr(), N)
    }

    unsafe fn assume_init(self, length: usize) -> Self::Output {
        length
    }
}

impl<'a, T> Buffer<T> for &'a mut [MaybeUninit<T>] {
    type Output = (&'a mut [T], &'a mut [MaybeUninit<T>]);

    fn parts_mut(&mut self) -> (*mut T, usize) {
        (self.as_mut_ptr().cast(), self.len())
    }

    unsafe fn assume_init(self, length: usize) -> Self::Output {
        let (initialized, uninitialized) = self.split_at_mut(length);
        // SAFETY: The caller established that this prefix was initialized by
        // the kernel operation.
        let initialized = unsafe {
            slice::from_raw_parts_mut(initialized.as_mut_ptr().cast::<T>(), initialized.len())
        };
        (initialized, uninitialized)
    }
}

impl<'a, T, const N: usize> Buffer<T> for &'a mut [MaybeUninit<T>; N] {
    type Output = (&'a mut [T], &'a mut [MaybeUninit<T>]);

    fn parts_mut(&mut self) -> (*mut T, usize) {
        (self.as_mut_ptr().cast(), N)
    }

    unsafe fn assume_init(self, length: usize) -> Self::Output {
        let (initialized, uninitialized) = self.as_mut_slice().split_at_mut(length);
        // SAFETY: The caller established that this prefix was initialized by
        // the kernel operation.
        let initialized = unsafe {
            slice::from_raw_parts_mut(initialized.as_mut_ptr().cast::<T>(), initialized.len())
        };
        (initialized, uninitialized)
    }
}

#[cfg(feature = "alloc")]
impl<T> Buffer<T> for &mut Vec<T> {
    type Output = usize;

    fn parts_mut(&mut self) -> (*mut T, usize) {
        (self.as_mut_ptr(), self.len())
    }

    unsafe fn assume_init(self, length: usize) -> Self::Output {
        length
    }
}

#[cfg(feature = "alloc")]
impl<'a, T> Buffer<T> for &'a mut Vec<MaybeUninit<T>> {
    type Output = (&'a mut [T], &'a mut [MaybeUninit<T>]);

    fn parts_mut(&mut self) -> (*mut T, usize) {
        (self.as_mut_ptr().cast(), self.len())
    }

    unsafe fn assume_init(self, length: usize) -> Self::Output {
        let (initialized, uninitialized) = self.as_mut_slice().split_at_mut(length);
        // SAFETY: The caller established that this prefix was initialized by
        // the kernel operation.
        let initialized = unsafe {
            slice::from_raw_parts_mut(initialized.as_mut_ptr().cast::<T>(), initialized.len())
        };
        (initialized, uninitialized)
    }
}

/// Appends received elements to a vector's existing spare capacity.
///
/// Construct this with [`spare_capacity`]. It never reallocates.
#[cfg(feature = "alloc")]
pub struct SpareCapacity<'a, T>(&'a mut Vec<T>);

/// Borrows a vector's spare capacity as a receive buffer.
#[cfg(feature = "alloc")]
#[must_use]
pub fn spare_capacity<T>(vector: &mut Vec<T>) -> SpareCapacity<'_, T> {
    SpareCapacity(vector)
}

#[cfg(feature = "alloc")]
impl<T> Buffer<T> for SpareCapacity<'_, T> {
    type Output = usize;

    fn parts_mut(&mut self) -> (*mut T, usize) {
        let spare = self.0.spare_capacity_mut();
        (spare.as_mut_ptr().cast(), spare.len())
    }

    unsafe fn assume_init(self, length: usize) -> Self::Output {
        // SAFETY: The caller established that exactly this prefix was
        // initialized, and it cannot exceed the supplied spare capacity.
        unsafe { self.0.set_len(self.0.len() + length) };
        length
    }
}

mod private {
    use super::MaybeUninit;

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    pub(crate) trait Sealed<T> {}

    impl<T> Sealed<T> for &mut [T] {}
    impl<T, const N: usize> Sealed<T> for &mut [T; N] {}
    impl<T> Sealed<T> for &mut [MaybeUninit<T>] {}
    impl<T, const N: usize> Sealed<T> for &mut [MaybeUninit<T>; N] {}

    #[cfg(feature = "alloc")]
    impl<T> Sealed<T> for &mut Vec<T> {}
    #[cfg(feature = "alloc")]
    impl<T> Sealed<T> for &mut Vec<MaybeUninit<T>> {}
    #[cfg(feature = "alloc")]
    impl<T> Sealed<T> for super::SpareCapacity<'_, T> {}
}
