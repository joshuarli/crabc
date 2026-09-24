#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_reallocate, prepare_native_later_thread_arena,
    register_current_native_allocator_worker_descriptor,
};

const SLOTS: usize = 64;
const WORKERS: usize = 8;
const ROUNDS: usize = 16;
const OPERATIONS: usize = 4000;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Mostly small blocks with some singletons in the 512 KiB .. 3.5 MiB range.
fn size(state: &mut u64) -> usize {
    if next(state) % 8 == 0 {
        512 * 1024 + (next(state) % (3 * 1024 * 1024)) as usize
    } else {
        16 + (next(state) % 2048) as usize
    }
}

/// Stores the block size in its first word and checks it back before use.
unsafe fn stamp(block: core::ptr::NonNull<u8>, size: usize) {
    unsafe {
        block.as_ptr().cast::<usize>().write(size);
        block.as_ptr().add(size - 1).write(size as u8);
    }
}

unsafe fn checked_size(block: core::ptr::NonNull<u8>) -> usize {
    let size = unsafe { block.as_ptr().cast::<usize>().read() };
    assert_eq!(unsafe { block.as_ptr().add(size - 1).read() }, size as u8, "block tail intact");
    size
}

fn allocate(state: &mut u64) -> core::ptr::NonNull<u8> {
    let size = size(state);
    match native_allocate_aligned(size, 16, false) {
        NativePageAllocationResult::Allocated(block) => {
            unsafe { stamp(block, size) };
            block
        }
        _ => panic!("allocation of {size} bytes failed"),
    }
}

fn worker(slots: &[AtomicUsize], seed: u64) {
    let mut state = seed;
    let mut local: Vec<Option<core::ptr::NonNull<u8>>> = vec![None; 32];
    for _ in 0..OPERATIONS {
        let index = (next(&mut state) % local.len() as u64) as usize;
        let choice = next(&mut state) % 100;
        match local[index] {
            None => local[index] = Some(allocate(&mut state)),
            Some(block) if choice < 30 => {
                unsafe { checked_size(block) };
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed, "free");
                local[index] = None;
            }
            Some(block) if choice < 60 => {
                let old = unsafe { checked_size(block) };
                let new = size(&mut state);
                match unsafe { native_reallocate(Some(block), new) } {
                    NativePageAllocationResult::Allocated(moved) => {
                        let kept = old.min(new);
                        if kept >= core::mem::size_of::<usize>() {
                            assert_eq!(unsafe { moved.as_ptr().cast::<usize>().read() }, old);
                        }
                        unsafe { stamp(moved, new) };
                        local[index] = Some(moved);
                    }
                    NativePageAllocationResult::AllocationFailed => {
                        panic!("realloc {old} -> {new} failed")
                    }
                    NativePageAllocationResult::Unavailable => {
                        panic!("realloc {old} -> {new} unavailable")
                    }
                    NativePageAllocationResult::Retained => {
                        panic!("realloc {old} -> {new} retained")
                    }
                }
            }
            Some(block) => {
                let slot = (next(&mut state) % SLOTS as u64) as usize;
                let previous = slots[slot].swap(block.as_ptr().addr(), Ordering::AcqRel);
                local[index] = core::ptr::NonNull::new(previous as *mut u8);
            }
        }
    }
    for block in local.into_iter().flatten() {
        let slot = (next(&mut state) % SLOTS as u64) as usize;
        let previous = slots[slot].swap(block.as_ptr().addr(), Ordering::AcqRel);
        if let Some(previous) = core::ptr::NonNull::new(previous as *mut u8) {
            unsafe { checked_size(previous) };
            assert_eq!(unsafe { native_free(previous) }, NativePageFreeResult::Freed, "exit free");
        }
    }
}

/// Owners transfer, reallocate, and free each other's small and singleton
/// blocks, including blocks whose owner already exited. While one thread
/// reallocates a transferred block, its owner concurrently moves that page
/// between the full and ordinary queues, exits and abandons it, or the
/// reallocating thread reclaims it; each changes the page's `xthread_id`.
/// Every legal reallocation and free must still succeed.
#[test]
fn owners_reallocate_and_free_transferred_blocks() {
    assert!(native_runtime_test_support::initialize(current_page_size()));
    assert!(prepare_native_later_thread_arena());
    let slots: Arc<Vec<AtomicUsize>> = Arc::new((0..SLOTS).map(|_| AtomicUsize::new(0)).collect());
    for round in 0..ROUNDS {
        let barrier = Arc::new(Barrier::new(WORKERS));
        let threads: Vec<_> = (0..WORKERS)
            .map(|index| {
                let slots = Arc::clone(&slots);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    // SAFETY: the TLS descriptor stays mapped through finish.
                    assert!(unsafe {
                        register_current_native_allocator_worker_descriptor(
                            current_native_allocator_thread_descriptor(),
                        )
                    });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    barrier.wait();
                    worker(&slots, 0x1234 ^ ((round as u64) << 32) ^ index as u64 * 0x2545_f491);
                    assert_eq!(
                        finish_current_thread_native_after_user_destructors(),
                        ThreadFinishResult::Finished
                    );
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("worker completes");
        }
    }
    for slot in slots.iter() {
        if let Some(block) = core::ptr::NonNull::new(slot.swap(0, Ordering::AcqRel) as *mut u8) {
            unsafe { checked_size(block) };
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed, "drain free");
        }
    }
}
