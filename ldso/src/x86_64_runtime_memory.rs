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
    // Next carve address and exclusive end of its current chunk.
    cursor: *mut u8,
    limit: usize,
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
    free: [core::ptr::null_mut(); CLASS_COUNT], cursor: core::ptr::null_mut(), limit: 0,
    static_chunk_used: false,
}));

/// Class index and size for a pooled request, or `None` for its own mapping.
fn class(bytes: usize, align: usize) -> Option<(usize, usize)> {
    if align > SMALLEST_CLASS || bytes > LARGEST_CLASS { return None; }
    // All sizes up to the smallest class share its exponent; above it, each
    // next power-of-two boundary selects the following class.
    let rounded_input = bytes.saturating_sub(1) | (SMALLEST_CLASS - 1);
    let exponent = usize::BITS - rounded_input.leading_zeros();
    let index = (exponent - SMALLEST_CLASS.trailing_zeros()) as usize;
    Some((index, SMALLEST_CLASS << index))
}

fn map(bytes: usize) -> Option<*mut u8> {
    let address = unsafe { syscall6(SYS_MMAP, 0, bytes as i64,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
    (!is_linux_error(address)).then_some(address as *mut u8)
}

/// Allocate `bytes` (at least one) zeroed bytes aligned to `align`.
pub(super) fn allocate(bytes: usize, align: usize) -> Option<*mut u8> {
    allocate_block::<true>(bytes, align)
}

/// [`allocate`] for a caller that writes every byte it later reads
/// (LoaderBuffer initializes each element; LoaderVec reads only pushed
/// ones): a recycled block keeps its stale bytes instead of being zeroed.
fn allocate_uninitialized(bytes: usize, align: usize) -> Option<*mut u8> {
    allocate_block::<false>(bytes, align)
}

fn allocate_block<const ZEROED: bool>(bytes: usize, align: usize) -> Option<*mut u8> {
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
        if ZEROED { unsafe { core::ptr::write_bytes(block, 0, size); } }
        block
    } else {
        // Carve the block at the next `size`-aligned address of the current
        // chunk; a chunk too full for it is abandoned (its tail stays mapped
        // and unused) for a fresh one.
        let mut padding = (pool.cursor as usize).wrapping_neg() % size;
        let mut block = pool.cursor.wrapping_add(padding);
        let mut end = block.wrapping_add(size);
        if pool.cursor.is_null() || end as usize > pool.limit {
            let cursor = if pool.static_chunk_used {
                map(CHUNK_BYTES)?
            } else {
                pool.static_chunk_used = true;
                STATIC_CHUNK.0.get().cast::<u8>()
            };
            pool.limit = cursor as usize + CHUNK_BYTES;
            padding = (cursor as usize).wrapping_neg() % size;
            block = cursor.wrapping_add(padding);
            end = block.wrapping_add(size);
        }
        pool.cursor = end;
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
    let Some((index, _)) = class(bytes, align) else {
        // A zero-length request with larger alignment mapped one byte.
        unsafe { syscall2(SYS_MUNMAP, block as i64, bytes.max(1) as i64); }
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
/// Growth allocates a larger block, moves the elements bitwise and releases
/// the old block: pooled blocks are recycled and larger mappings are unmapped.
/// Callers never hold a reference across a `push` (the borrow rules enforce
/// this). An empty vector owns no block. Elements are dropped with the vector.
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

    #[test]
    fn vector_growth_and_refusal_preserve_owned_elements_until_reverse_drop() {
        struct Element {
            index: usize,
            drops: std::sync::Arc<std::sync::Mutex<std::vec::Vec<usize>>>,
        }
        impl Drop for Element {
            fn drop(&mut self) {
                // Dropping an owned element may return another loader block.
                // Vector teardown must not retain the pool lock across it.
                let nested = allocate(97, 8).unwrap();
                unsafe { release(nested, 97, 8); }
                self.drops.lock().unwrap().push(self.index);
            }
        }
        let drops = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
        let mut values = LoaderVec::new();
        for index in 0..100 {
            values.push(Element { index, drops: drops.clone() }).unwrap();
        }
        let address = values.as_ptr();
        assert!(values.reserve(usize::MAX).is_none());
        assert_eq!(values.as_ptr(), address);
        assert_eq!(values.len(), 100);
        assert!(values.iter().enumerate().all(|(index, element)| index == element.index));
        assert!(drops.lock().unwrap().is_empty());
        values.truncate(3);
        assert_eq!(*drops.lock().unwrap(), (3..100).rev().collect::<std::vec::Vec<_>>());
        values.reserve(1000).unwrap();
        assert_eq!(values.iter().map(|element| element.index).collect::<std::vec::Vec<_>>(), [0, 1, 2]);
        assert_eq!(drops.lock().unwrap().len(), 97);
        drop(values);
        assert_eq!(*drops.lock().unwrap(), (0..100).rev().collect::<std::vec::Vec<_>>());
    }

    #[test]
    fn buffer_and_vector_refuse_unrepresentable_spans_without_consuming_live_storage() {
        assert!(LoaderBuffer::new(usize::MAX, 1usize).is_none());
        let buffer = LoaderBuffer::new(33, 71usize).unwrap();
        let address = buffer.as_slice().as_ptr();
        let mut values = LoaderVec::new();
        values.push(82usize).unwrap();
        assert!(values.reserve(isize::MAX as usize).is_none());
        assert_eq!(&*values, [82]);
        assert_eq!(buffer.as_slice().as_ptr(), address);
        assert!(buffer.as_slice().iter().all(|&value| value == 71));
    }

    #[test]
    fn class_rounding_keeps_pool_and_mapping_boundaries() {
        for (bytes, index, size) in [
            (0, 0, 16), (1, 0, 16), (16, 0, 16), (17, 1, 32),
            (31, 1, 32), (32, 1, 32), (33, 2, 64),
            (LARGEST_CLASS - 1, CLASS_COUNT - 1, LARGEST_CLASS),
            (LARGEST_CLASS, CLASS_COUNT - 1, LARGEST_CLASS),
        ] {
            assert_eq!(class(bytes, 16), Some((index, size)));
        }
        assert_eq!(class(LARGEST_CLASS + 1, 16), None);
        assert_eq!(class(16, 32), None);
    }

    #[test]
    fn every_class_edge_rounds_up_without_crossing_the_mapping_cutoff() {
        for index in 0..CLASS_COUNT {
            let size = SMALLEST_CLASS << index;
            assert_eq!(class(size, 16), Some((index, size)));
            if index > 0 {
                assert_eq!(class(size - 1, 16), Some((index, size)));
            }
            if index + 1 < CLASS_COUNT {
                assert_eq!(class(size + 1, 16), Some((index + 1, size * 2)));
            }
        }
        assert_eq!(class(LARGEST_CLASS + 1, 16), None);
    }

    #[test]
    fn zero_length_release_recycles_the_smallest_class_without_exposing_stale_bytes() {
        let first = allocate_block::<true>(0, 1).unwrap();
        let neighbor = allocate(1, 1).unwrap();
        assert_ne!(first, neighbor);
        unsafe { first.write(0xa5); neighbor.write(0x5a); release(first, 0, 1); }
        let recycled = allocate(1, 1).unwrap();
        assert_eq!(unsafe { recycled.read() }, 0);
        assert_eq!(unsafe { neighbor.read() }, 0x5a);
        unsafe { release(recycled, 1, 1); release(neighbor, 1, 1); }
    }

    // The process-isolated probe uses the installed runtime's fork lock. The
    // initial-only source root has its own pool lock and no runtime lock.
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    #[test]
    fn zero_length_with_large_alignment_releases_its_mapping() {
        use super::super::x86_64_runtime_lock::{isolated_mapping_probe, RuntimeGuard};
        unsafe fn probe(_: &RuntimeGuard) -> bool {
            let Some(block) = allocate_block::<true>(0, 32) else { return false; };
            let mut residency = 0u8;
            let before = unsafe { syscall3(27, block as i64, PAGE as i64,
                core::ptr::addr_of_mut!(residency) as i64) } == 0;
            unsafe { release(block, 0, 32); }
            let after = unsafe { syscall3(27, block as i64, PAGE as i64,
                core::ptr::addr_of_mut!(residency) as i64) } == -12;
            before && after
        }
        unsafe { isolated_mapping_probe(probe); }
    }

    #[test]
    fn mixed_class_blocks_remain_disjoint_across_chunk_refills() {
        let sizes = [16, 8192, 32, 16384, 64, 16384, 128, 16384,
            256, 16384, 512, 16384, 1024, 16384];
        let mut blocks = std::vec::Vec::new();
        for (index, bytes) in sizes.into_iter().enumerate() {
            let block = allocate(bytes, 16).unwrap();
            assert_eq!(block as usize % bytes.max(SMALLEST_CLASS).next_power_of_two(), 0);
            assert!(unsafe { core::slice::from_raw_parts(block, bytes) }.iter().all(|&byte| byte == 0));
            let tag = index as u8 + 1;
            unsafe { core::ptr::write_bytes(block, tag, bytes); }
            blocks.push((block, bytes, tag));
        }
        for (index, &(block, bytes, tag)) in blocks.iter().enumerate() {
            let start = block as usize;
            let end = start.checked_add(bytes).unwrap();
            assert!(unsafe { core::slice::from_raw_parts(block, bytes) }.iter().all(|&byte| byte == tag));
            for &(other, other_bytes, _) in &blocks[..index] {
                let other_start = other as usize;
                let other_end = other_start.checked_add(other_bytes).unwrap();
                assert!(end <= other_start || other_end <= start);
            }
        }
        for (block, bytes, _) in blocks.into_iter().rev() {
            unsafe { release(block, bytes, 16); }
        }
    }

    #[test]
    fn concurrent_chunk_refills_keep_live_blocks_exclusive() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers: std::vec::Vec<_> = (1..=4u8).map(|tag| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut blocks = std::vec::Vec::new();
                for _ in 0..6 {
                    let block = allocate(LARGEST_CLASS, 16).unwrap();
                    unsafe { core::ptr::write_bytes(block, tag, LARGEST_CLASS); }
                    blocks.push(block);
                }
                barrier.wait();
                for &block in &blocks {
                    assert!(unsafe { core::slice::from_raw_parts(block, LARGEST_CLASS) }
                        .iter().all(|&byte| byte == tag));
                }
                barrier.wait();
                for block in blocks { unsafe { release(block, LARGEST_CLASS, 16); } }
            })
        }).collect();
        for worker in workers { worker.join().unwrap(); }
    }

    #[test]
    fn recycled_class_blocks_zero_requested_bytes_across_size_changes() {
        // Both requests share one class, so a shorter reuse may leave bytes
        // that a later, longer request must clear before returning them.
        for &(first_size, second_size) in &[(127usize, 65usize), (65, 127)] {
            let first = allocate(first_size, 8).unwrap();
            unsafe { core::ptr::write_bytes(first, 0xa5, first_size); release(first, first_size, 8); }
            let second = allocate(second_size, 8).unwrap();
            assert!(unsafe { core::slice::from_raw_parts(second, second_size) }
                .iter().all(|&byte| byte == 0));
            unsafe { release(second, second_size, 8); }
        }
    }

    #[test]
    fn concurrent_mixed_requests_keep_zeroing_and_ownership() {
        let workers: std::vec::Vec<_> = (0..4usize).map(|worker| std::thread::spawn(move || {
            for round in 0..500usize {
                let bytes = if (worker + round) % 2 == 0 { 65 } else { 127 };
                let block = allocate(bytes, 8).unwrap();
                assert!(unsafe { core::slice::from_raw_parts(block, bytes) }
                    .iter().all(|&byte| byte == 0));
                let tag = (worker + 1) as u8;
                unsafe { core::ptr::write_bytes(block, tag, bytes); }
                std::thread::yield_now();
                assert!(unsafe { core::slice::from_raw_parts(block, bytes) }
                    .iter().all(|&byte| byte == tag));
                unsafe { release(block, bytes, 8); }
            }
        })).collect();
        for worker in workers { worker.join().unwrap(); }
    }

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
