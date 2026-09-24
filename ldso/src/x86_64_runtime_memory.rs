//! Raw loader scratch with checked, resource-sized ownership; never libc heap.

use super::*;

pub(super) struct LoaderBuffer<T: Copy> { pointer: *mut T, length: usize, bytes: usize }
impl<T: Copy> LoaderBuffer<T> {
    pub(super) fn new(length: usize, value: T) -> Option<Self> {
        let bytes = length.checked_mul(core::mem::size_of::<T>())?.max(1);
        if bytes > isize::MAX as usize || core::mem::align_of::<T>() > PAGE as usize { return None; }
        let address = unsafe { syscall6(SYS_MMAP, 0, bytes as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if is_linux_error(address) { return None; }
        let pointer = address as *mut T;
        for index in 0..length { unsafe { core::ptr::write(pointer.add(index), value); } }
        Some(Self { pointer, length, bytes })
    }
    pub(super) fn as_slice(&self) -> &[T] { unsafe { core::slice::from_raw_parts(self.pointer, self.length) } }
    pub(super) fn as_mut_slice(&mut self) -> &mut [T] { unsafe { core::slice::from_raw_parts_mut(self.pointer, self.length) } }
}
impl<T: Copy> Drop for LoaderBuffer<T> {
    fn drop(&mut self) { unsafe { syscall2(SYS_MUNMAP, self.pointer as i64, self.bytes as i64); } }
}

/// A growable sequence in raw loader mappings; never libc heap.
///
/// The general loader must admit graphs of any size before libc (and its
/// allocator) can run, as musl's loader does with its own reclaimed memory.
/// Growth maps a larger span, moves the elements bitwise and unmaps the old
/// span, so callers never hold a reference across a `push` (the borrow rules
/// enforce this). An empty vector owns no mapping. Elements are dropped with
/// the vector.
pub(super) struct LoaderVec<T> { pointer: *mut T, length: usize, capacity: usize }

impl<T> LoaderVec<T> {
    pub(super) const fn new() -> Self { Self { pointer: core::ptr::null_mut(), length: 0, capacity: 0 } }

    pub(super) fn len(&self) -> usize { self.length }

    pub(super) fn is_empty(&self) -> bool { self.length == 0 }

    /// Append one element, returning `None` (with the vector unchanged) when
    /// the kernel refuses a larger mapping.
    pub(super) fn push(&mut self, value: T) -> Option<()> {
        if self.length == self.capacity { self.grow(self.length.checked_add(1)?)?; }
        unsafe { core::ptr::write(self.pointer.add(self.length), value); }
        self.length += 1;
        Some(())
    }

    /// Ensure room for `additional` more elements without another mapping.
    pub(super) fn reserve(&mut self, additional: usize) -> Option<()> {
        let required = self.length.checked_add(additional)?;
        if required > self.capacity { self.grow(required)?; }
        Some(())
    }

    /// Drop every element after the first `length`.
    pub(super) fn truncate(&mut self, length: usize) {
        while self.length > length {
            self.length -= 1;
            unsafe { core::ptr::drop_in_place(self.pointer.add(self.length)); }
        }
    }

    fn grow(&mut self, required: usize) -> Option<()> {
        let size = core::mem::size_of::<T>().max(1);
        if core::mem::align_of::<T>() > PAGE as usize { return None; }
        // At least one page, then doubling: amortized O(1) moves per element.
        let minimum = (PAGE as usize / size).max(1);
        let capacity = required.max(self.capacity.checked_mul(2)?).max(minimum);
        let bytes = capacity.checked_mul(size)?;
        if bytes > isize::MAX as usize { return None; }
        let address = unsafe { syscall6(SYS_MMAP, 0, bytes as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if is_linux_error(address) { return None; }
        let pointer = address as *mut T;
        if self.capacity != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(self.pointer, pointer, self.length);
                syscall2(SYS_MUNMAP, self.pointer as i64, (self.capacity * size) as i64);
            }
        }
        self.pointer = pointer;
        self.capacity = capacity;
        Some(())
    }
}

impl<T> core::ops::Deref for LoaderVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        if self.capacity == 0 { return &[]; }
        unsafe { core::slice::from_raw_parts(self.pointer, self.length) }
    }
}

impl<T> core::ops::DerefMut for LoaderVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        if self.capacity == 0 { return &mut []; }
        unsafe { core::slice::from_raw_parts_mut(self.pointer, self.length) }
    }
}

impl<T> Drop for LoaderVec<T> {
    fn drop(&mut self) {
        self.truncate(0);
        if self.capacity != 0 {
            let bytes = self.capacity * core::mem::size_of::<T>().max(1);
            unsafe { syscall2(SYS_MUNMAP, self.pointer as i64, bytes as i64); }
        }
    }
}

// SAFETY: the vector uniquely owns its elements, like `Vec<T>`.
unsafe impl<T: Send> Send for LoaderVec<T> {}
// SAFETY: shared access only yields `&[T]`, like `Vec<T>`.
unsafe impl<T: Sync> Sync for LoaderVec<T> {}
