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
