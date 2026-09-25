//! Raw loader scratch with checked, resource-sized ownership; never libc heap.
//!
//! Small blocks come from a loader-private pool rather than one anonymous
//! mapping each: the loader's names, scopes, orders and nodes are mostly tens
//! to a few thousand bytes, and a mapping per block cost two syscalls (and a
//! page fault) apiece at every startup, dlopen and dlsym. The pool is
//! power-of-two size classes up to [`LARGEST_CLASS`], carved from
//! [`CHUNK_BYTES`] mappings and recycled through per-class free lists, like
//! musl's loader reusing its own reclaimed memory before libc's allocator
//! exists. Pool memory is retained for the process; larger blocks keep their
//! own mapping. Every block is returned zeroed, as a fresh anonymous mapping
//! is.

use super::*;
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
use super::x86_64_runtime_lock::AllocationGuard;

/// Roots without the installed runtime have no loader lock module. Their
/// production use is the one-threaded initial transaction, but their source
/// tests allocate from concurrent harness threads, so the pool still takes a
/// short spin lock.
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
struct AllocationGuard;
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
static POOL_SPIN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
impl AllocationGuard {
    fn acquire() -> Self {
        use core::sync::atomic::Ordering;
        while POOL_SPIN.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        Self
    }
}
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
impl Drop for AllocationGuard {
    fn drop(&mut self) { POOL_SPIN.store(false, core::sync::atomic::Ordering::Release); }
}
use core::cell::UnsafeCell;

const SMALLEST_CLASS: usize = 16;
const LARGEST_CLASS: usize = 16 * 1024;
const CLASS_COUNT: usize = (LARGEST_CLASS / SMALLEST_CLASS).trailing_zeros() as usize + 1;
const CHUNK_BYTES: usize = 64 * 1024;

struct Pool {
    // Singly linked free blocks per class; the link is the block's first word.
    free: [*mut u8; CLASS_COUNT],
    // Unused tail of the current chunk.
    cursor: *mut u8,
    remaining: usize,
    // Whether the loader's static first chunk has been handed out.
    static_chunk_used: bool,
}

/// The first chunk is loader `.bss`, as musl's loader starts from its own
/// static memory: the kernel already maps it zero-filled with the loader, so
/// a startup that fits in it needs no pool mapping at all. Untouched pages
/// cost nothing.
#[repr(C, align(4096))]
struct StaticChunk(UnsafeCell<[u8; CHUNK_BYTES]>);
// SAFETY: the chunk is handed out once, under `AllocationGuard`, and each
// block of it is then owned exclusively like any mapped chunk's block.
unsafe impl Sync for StaticChunk {}
static STATIC_CHUNK: StaticChunk = StaticChunk(UnsafeCell::new([0; CHUNK_BYTES]));
struct PoolCell(UnsafeCell<Pool>);
// SAFETY: every access holds `AllocationGuard`.
unsafe impl Sync for PoolCell {}
static POOL: PoolCell = PoolCell(UnsafeCell::new(Pool {
    free: [core::ptr::null_mut(); CLASS_COUNT], cursor: core::ptr::null_mut(), remaining: 0,
    static_chunk_used: false,
}));

/// Class index and size for a pooled request, or `None` for its own mapping.
fn class(bytes: usize, align: usize) -> Option<(usize, usize)> {
    if align > SMALLEST_CLASS || bytes > LARGEST_CLASS { return None; }
    let size = bytes.max(SMALLEST_CLASS).next_power_of_two();
    Some(((size / SMALLEST_CLASS).trailing_zeros() as usize, size))
}

fn map(bytes: usize) -> Option<*mut u8> {
    let address = unsafe { syscall6(SYS_MMAP, 0, bytes as i64,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
    (!is_linux_error(address)).then_some(address as *mut u8)
}

/// Allocate `bytes` (at least one) zeroed bytes aligned to `align`.
pub(super) fn allocate(bytes: usize, align: usize) -> Option<*mut u8> {
    allocate_block(bytes, align, true)
}

/// [`allocate`] for a caller that writes every byte it later reads
/// (LoaderBuffer initializes each element; LoaderVec reads only pushed
/// ones): a recycled block keeps its stale bytes instead of being zeroed.
fn allocate_uninitialized(bytes: usize, align: usize) -> Option<*mut u8> {
    allocate_block(bytes, align, false)
}

fn allocate_block(bytes: usize, align: usize, zeroed: bool) -> Option<*mut u8> {
    let bytes = bytes.max(1);
    if bytes > isize::MAX as usize || align > PAGE as usize { return None; }
    let Some((index, size)) = class(bytes, align) else { return map(bytes); };
    let _guard = AllocationGuard::acquire();
    // SAFETY: the guard serializes every pool access.
    let pool = unsafe { &mut *POOL.0.get() };
    let block = if !pool.free[index].is_null() {
        let block = pool.free[index];
        // SAFETY: a free block stores its successor in its first word.
        pool.free[index] = unsafe { block.cast::<*mut u8>().read() };
        // SAFETY: the block is `size` bytes of pool memory owned by us now.
        if zeroed { unsafe { core::ptr::write_bytes(block, 0, size); } }
        block
    } else {
        // Carve the block at the next `size`-aligned address of the current
        // chunk; a chunk too full for it is abandoned (its tail stays mapped
        // and unused) for a fresh one.
        let mut padding = (pool.cursor as usize).wrapping_neg() % size;
        if pool.cursor.is_null() || pool.remaining < size + padding {
            pool.cursor = if pool.static_chunk_used {
                map(CHUNK_BYTES)?
            } else {
                pool.static_chunk_used = true;
                STATIC_CHUNK.0.get().cast::<u8>()
            };
            pool.remaining = CHUNK_BYTES;
            padding = (pool.cursor as usize).wrapping_neg() % size;
        }
        let block = pool.cursor.wrapping_add(padding);
        pool.cursor = block.wrapping_add(size);
        pool.remaining -= size + padding;
        // Never-used chunk memory is still the kernel's zero fill.
        block
    };
    Some(block)
}

/// Return a block from [`allocate`] with the same `bytes` and `align`.
///
/// # Safety
/// `block` came from `allocate(bytes, align)` and is not used afterwards.
pub(super) unsafe fn release(block: *mut u8, bytes: usize, align: usize) {
    let bytes = bytes.max(1);
    let Some((index, _)) = class(bytes, align) else {
        unsafe { syscall2(SYS_MUNMAP, block as i64, bytes as i64); }
        return;
    };
    let _guard = AllocationGuard::acquire();
    // SAFETY: the guard serializes every pool access; the caller transfers
    // ownership of a block of this class.
    let pool = unsafe { &mut *POOL.0.get() };
    unsafe { block.cast::<*mut u8>().write(pool.free[index]); }
    pool.free[index] = block;
}

pub(super) struct LoaderBuffer<T: Copy> { pointer: *mut T, length: usize, bytes: usize }
impl<T: Copy> LoaderBuffer<T> {
    pub(super) fn new(length: usize, value: T) -> Option<Self> {
        let bytes = length.checked_mul(core::mem::size_of::<T>())?.max(1);
        let pointer = allocate_uninitialized(bytes, core::mem::align_of::<T>())?.cast::<T>();
        for index in 0..length { unsafe { core::ptr::write(pointer.add(index), value); } }
        Some(Self { pointer, length, bytes })
    }
    pub(super) fn as_slice(&self) -> &[T] { unsafe { core::slice::from_raw_parts(self.pointer, self.length) } }
    pub(super) fn as_mut_slice(&mut self) -> &mut [T] { unsafe { core::slice::from_raw_parts_mut(self.pointer, self.length) } }
}
impl<T: Copy> Drop for LoaderBuffer<T> {
    fn drop(&mut self) {
        unsafe { release(self.pointer.cast(), self.bytes, core::mem::align_of::<T>()); }
    }
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
        // At least four elements, then doubling: amortized O(1) moves per
        // element, with small vectors drawn from the pool.
        let capacity = required.max(self.capacity.checked_mul(2)?).max(4);
        let bytes = capacity.checked_mul(size)?;
        let pointer = allocate_uninitialized(bytes, core::mem::align_of::<T>())?.cast::<T>();
        if self.capacity != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(self.pointer, pointer, self.length);
                release(self.pointer.cast(), self.capacity * size, core::mem::align_of::<T>());
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
            unsafe { release(self.pointer.cast(), bytes, core::mem::align_of::<T>()); }
        }
    }
}

// SAFETY: the vector uniquely owns its elements, like `Vec<T>`.
unsafe impl<T: Send> Send for LoaderVec<T> {}
// SAFETY: shared access only yields `&[T]`, like `Vec<T>`.
unsafe impl<T: Sync> Sync for LoaderVec<T> {}

#[cfg(test)]
mod pool_tests {
    extern crate std;
    use super::*;

    // Recycled blocks must come back zeroed and class-aligned, large blocks
    // keep their own mapping, and concurrent users never share a block.
    #[test]
    fn pooled_blocks_are_zeroed_aligned_reused_and_exclusive() {
        for bytes in [1usize, 16, 17, 100, 680, 2120, 4080, 14400, LARGEST_CLASS] {
            let first = allocate(bytes, 8).unwrap();
            assert_eq!(first as usize % bytes.max(SMALLEST_CLASS).next_power_of_two().min(PAGE as usize), 0);
            unsafe { core::ptr::write_bytes(first, 0xa5, bytes); release(first, bytes, 8); }
            // Usually the released block itself comes back (a concurrent
            // test thread may take it first); either way it is zeroed.
            let second = allocate(bytes, 8).unwrap();
            assert!(unsafe { core::slice::from_raw_parts(second, bytes) }.iter().all(|&byte| byte == 0));
            unsafe { release(second, bytes, 8); }
        }
        let large = allocate(LARGEST_CLASS + 1, 8).unwrap();
        assert_eq!(large as usize % PAGE as usize, 0, "an oversized block is its own mapping");
        unsafe { release(large, LARGEST_CLASS + 1, 8); }
        let workers: std::vec::Vec<_> = (0..4usize).map(|worker| std::thread::spawn(move || {
            for round in 0..2_000usize {
                let bytes = 16 << ((worker + round) % 6);
                let block = allocate(bytes, 8).unwrap();
                let tag = (worker as u8) ^ (round as u8) | 1;
                unsafe { core::ptr::write_bytes(block, tag, bytes); }
                std::thread::yield_now();
                assert!(unsafe { core::slice::from_raw_parts(block, bytes) }.iter().all(|&byte| byte == tag));
                unsafe { release(block, bytes, 8); }
            }
        })).collect();
        for worker in workers { worker.join().unwrap(); }
    }
}
