//! Active dynamic arena path from musl 1.2.6 `src/regex/tre-mem.c`.
//!
//! The pinned x86 source does not define `TRE_USE_ALLOCA`, so its live
//! `tre_mem_new`, `tre_mem_alloc`, and `tre_mem_calloc` macros always use the
//! heap-backed path below.  Every compiler and matcher temporary allocation
//! remains live until one `tre_mem_destroy`; no fixed capacity or individual
//! free operation is introduced.

use core::ffi::{c_int, c_void};
use core::mem::{align_of, size_of};
use core::ptr;

use super::types::{TreList, TreMem, TRE_MEM_BLOCK_SIZE};

unsafe extern "C" {
    #[link_name = "calloc"]
    fn cabi_calloc(count: usize, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn cabi_free(pointer: *mut c_void);
    #[link_name = "malloc"]
    fn cabi_malloc(size: usize) -> *mut c_void;
}

#[cfg(test)]
mod allocation_test_hook {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub(super) static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub(super) static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_AFTER_SUCCESSES: AtomicUsize = AtomicUsize::new(usize::MAX);
    static TEST_LOCK: AtomicBool = AtomicBool::new(false);

    pub(super) struct TestAllocationGuard;

    pub(super) fn lock() -> TestAllocationGuard {
        while TEST_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        TestAllocationGuard
    }

    impl Drop for TestAllocationGuard {
        fn drop(&mut self) {
            TEST_LOCK.store(false, Ordering::Release);
        }
    }

    pub(super) fn reset() {
        ALLOCATION_CALLS.store(0, Ordering::Relaxed);
        FREE_CALLS.store(0, Ordering::Relaxed);
        FAIL_AFTER_SUCCESSES.store(usize::MAX, Ordering::Relaxed);
    }

    pub(super) fn fail_after(successes: usize) {
        FAIL_AFTER_SUCCESSES.store(successes, Ordering::Relaxed);
    }

    pub(super) fn permit_allocation() -> bool {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        let mut remaining = FAIL_AFTER_SUCCESSES.load(Ordering::Relaxed);
        loop {
            if remaining == usize::MAX {
                return true;
            }
            if remaining == 0 {
                return false;
            }
            match FAIL_AFTER_SUCCESSES.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => remaining = observed,
            }
        }
    }

    pub(super) fn note_free() {
        FREE_CALLS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe fn owned_calloc(count: usize, size: usize) -> *mut c_void {
    #[cfg(test)]
    if !allocation_test_hook::permit_allocation() {
        return ptr::null_mut();
    }
    // SAFETY: caller preserves the selected C allocation ABI contract.
    unsafe { cabi_calloc(count, size) }
}

unsafe fn owned_malloc(size: usize) -> *mut c_void {
    #[cfg(test)]
    if !allocation_test_hook::permit_allocation() {
        return ptr::null_mut();
    }
    // SAFETY: caller preserves the selected C allocation ABI contract.
    unsafe { cabi_malloc(size) }
}

unsafe fn owned_free(pointer: *mut c_void) {
    #[cfg(test)]
    allocation_test_hook::note_free();
    // SAFETY: caller transfers one allocation from the selected C allocator.
    unsafe { cabi_free(pointer) };
}

/// `tre_mem_new()` through `tre_mem_new_impl(0, NULL)` in `tre.h`.
pub(crate) unsafe fn tre_mem_new() -> *mut TreMem {
    // SAFETY: the active source macro always selects the heap-backed form.
    unsafe { tre_mem_new_impl(false, ptr::null_mut()) }
}

/// Active `tre_mem_new_impl` body from `tre-mem.c:53-65`.
///
/// The `provided` branch is retained in the function shape for the source
/// mapping, but no active x86 caller can select it because `TRE_USE_ALLOCA`
/// is absent.  It is deliberately not exposed as a Rust stack-allocation API.
unsafe fn tre_mem_new_impl(provided: bool, provided_block: *mut TreMem) -> *mut TreMem {
    let memory = if provided {
        if provided_block.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: this is the exact source branch for a caller-provided
        // `struct tre_mem_struct`; it writes only that complete record.
        unsafe { ptr::write_bytes(provided_block, 0, 1) };
        provided_block
    } else {
        // SAFETY: `calloc(1, sizeof(*mem))` is the source allocation.
        unsafe { owned_calloc(1, size_of::<TreMem>()) }.cast::<TreMem>()
    };
    memory
}

/// `tre_mem_destroy` from `tre-mem.c:70-82` for the active heap path.
pub(crate) unsafe fn tre_mem_destroy(memory: *mut TreMem) {
    if memory.is_null() {
        return;
    }
    // SAFETY: `memory` is a live source arena whose lists are linked only by
    // this module's allocation function.
    let mut list = unsafe { (*memory).blocks };
    while !list.is_null() {
        // SAFETY: retain next before consuming the current list record.
        let next = unsafe { (*list).next };
        // SAFETY: every list data allocation was created by cabi_malloc.
        unsafe { owned_free((*list).data) };
        // SAFETY: each list record is likewise owned exactly once here.
        unsafe { owned_free(list.cast()) };
        list = next;
    }
    // SAFETY: the active `tre_mem_new` path allocated this record with calloc.
    unsafe { owned_free(memory.cast()) };
}

/// `tre_mem_alloc(mem, size)` from `tre.h`.
pub(crate) unsafe fn tre_mem_alloc(memory: *mut TreMem, size: usize) -> *mut c_void {
    // SAFETY: the active macro supplies `provided = 0`, `zero = 0`.
    unsafe { tre_mem_alloc_impl(memory, false, ptr::null_mut(), false, size) }
}

/// `tre_mem_calloc(mem, size)` from `tre.h`.
pub(crate) unsafe fn tre_mem_calloc(memory: *mut TreMem, size: usize) -> *mut c_void {
    // SAFETY: the active macro supplies `provided = 0`, `zero = 1`.
    unsafe { tre_mem_alloc_impl(memory, false, ptr::null_mut(), true, size) }
}

/// Active `tre_mem_alloc_impl` algorithm from `tre-mem.c:89-151`.
///
/// The checked arithmetic preserves the source's allocation-failure boundary
/// before pointer arithmetic could overflow in Rust. It does not impose a
/// pattern or state capacity. The source stores the block byte count in a C
/// `int`; an unrepresentable `size * 8` is a documented memory-safety
/// divergence: this port marks the arena failed and returns null before that
/// source conversion could create a too-small allocation.
unsafe fn tre_mem_alloc_impl(
    memory: *mut TreMem,
    provided: bool,
    provided_block: *mut u8,
    zero: bool,
    mut size: usize,
) -> *mut c_void {
    if memory.is_null() || unsafe { (*memory).failed } != 0 {
        return ptr::null_mut();
    }
    // Every active `regcomp.c`/`regexec.c` call site supplies a positive
    // record or positive-count array size. Reject a zero-sized foreign call
    // explicitly before the source expression `mem->ptr + size` could touch
    // a null initial cursor or Rust's zero-length write could receive null.
    if size == 0 {
        return ptr::null_mut();
    }

    if unsafe { (*memory).n } < size {
        if provided {
            if provided_block.is_null() {
                unsafe { (*memory).failed = 1 };
                return ptr::null_mut();
            }
            unsafe {
                (*memory).ptr = provided_block.cast();
                (*memory).n = TRE_MEM_BLOCK_SIZE;
            }
        } else {
            let Some(eightfold) = size.checked_mul(8) else {
                unsafe { (*memory).failed = 1 };
                return ptr::null_mut();
            };
            if eightfold > c_int::MAX as usize {
                unsafe { (*memory).failed = 1 };
                return ptr::null_mut();
            }
            // `tre-mem.c` declares this local as `int`, rather than size_t.
            let block_size: c_int = core::cmp::max(eightfold, TRE_MEM_BLOCK_SIZE) as c_int;
            // SAFETY: these mirror `xmalloc(sizeof(*l))` and
            // `xmalloc(block_size)` in source order.
            let list = unsafe { owned_malloc(size_of::<TreList>()) }.cast::<TreList>();
            if list.is_null() {
                unsafe { (*memory).failed = 1 };
                return ptr::null_mut();
            }
            let data = unsafe { owned_malloc(block_size as usize) };
            if data.is_null() {
                unsafe { owned_free(list.cast()) };
                unsafe { (*memory).failed = 1 };
                return ptr::null_mut();
            }
            unsafe {
                (*list).data = data;
                (*list).next = ptr::null_mut();
                if !(*memory).current.is_null() {
                    (*(*memory).current).next = list;
                }
                if (*memory).blocks.is_null() {
                    (*memory).blocks = list;
                }
                (*memory).current = list;
                (*memory).ptr = data.cast();
                (*memory).n = block_size as usize;
            }
        }
    }

    // C's `ALIGN(mem->ptr + size, long)` aligns the next pointer, not the
    // returned one.  Keep that order so all later source records receive the
    // same `long` alignment guarantee.
    let current = unsafe { (*memory).ptr }.cast::<u8>();
    let Some(end_address) = (current as usize).checked_add(size) else {
        unsafe { (*memory).failed = 1 };
        return ptr::null_mut();
    };
    let remainder = end_address % align_of::<core::ffi::c_long>();
    if remainder != 0 {
        let adjustment = align_of::<core::ffi::c_long>() - remainder;
        let Some(adjusted) = size.checked_add(adjustment) else {
            unsafe { (*memory).failed = 1 };
            return ptr::null_mut();
        };
        size = adjusted;
    }
    if unsafe { (*memory).n } < size {
        // The C source's normal callers request records whose aligned size
        // fits the just-reserved block.  Treat an impossible residual request
        // as the same sticky allocation failure rather than underflowing.
        unsafe { (*memory).failed = 1 };
        return ptr::null_mut();
    }

    let result = current;
    unsafe {
        (*memory).ptr = current.add(size).cast();
        (*memory).n -= size;
        if zero {
            ptr::write_bytes(result, 0, size);
        }
    }
    result.cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tre_mem_active_arena_grows_aligns_zeros_and_releases_all_blocks() {
        let _allocation_guard = allocation_test_hook::lock();
        allocation_test_hook::reset();
        // SAFETY: every pointer below comes from this test's source arena and
        // is consumed exactly once by tre_mem_destroy.
        unsafe {
            let memory = tre_mem_new();
            assert!(!memory.is_null());
            let first = tre_mem_alloc(memory, 1).cast::<u8>();
            assert!(!first.is_null());
            assert_eq!((first as usize) % align_of::<core::ffi::c_long>(), 0);
            first.write(0xa5);

            let zeroed = tre_mem_calloc(memory, 17).cast::<u8>();
            assert!(!zeroed.is_null());
            for index in 0..17 {
                assert_eq!(zeroed.add(index).read(), 0);
            }

            let next = tre_mem_alloc(memory, TRE_MEM_BLOCK_SIZE).cast::<u8>();
            assert!(!next.is_null());
            assert!(!(*memory).blocks.is_null());
            assert!(!(*(*memory).blocks).next.is_null());
            assert_eq!(first.read(), 0xa5);
            tre_mem_destroy(memory);
        }
    }

    #[test]
    fn tre_mem_rejects_zero_before_a_null_cursor_and_keeps_the_arena_usable() {
        let _allocation_guard = allocation_test_hook::lock();
        allocation_test_hook::reset();
        // SAFETY: the test owns this arena for the duration of the call.
        unsafe {
            let memory = tre_mem_new();
            assert!(!memory.is_null());
            assert!(tre_mem_calloc(memory, 0).is_null());
            assert!((*memory).blocks.is_null());
            assert_eq!((*memory).n, 0);
            assert!(!tre_mem_alloc(memory, 1).is_null());
            tre_mem_destroy(memory);
        }
    }

    #[test]
    fn tre_mem_list_allocation_failure_is_sticky_and_releases_prior_blocks() {
        let _allocation_guard = allocation_test_hook::lock();
        // SAFETY: all calls use one test-owned source arena.
        unsafe {
            allocation_test_hook::reset();
            let memory = tre_mem_new();
            assert!(!tre_mem_alloc(memory, 1).is_null());
            allocation_test_hook::fail_after(0);
            assert!(tre_mem_alloc(memory, TRE_MEM_BLOCK_SIZE).is_null());
            assert_eq!((*memory).failed, 1);
            let calls_after_failure = allocation_test_hook::ALLOCATION_CALLS.load(
                core::sync::atomic::Ordering::Relaxed,
            );
            assert!(tre_mem_alloc(memory, 1).is_null());
            assert_eq!(
                allocation_test_hook::ALLOCATION_CALLS.load(core::sync::atomic::Ordering::Relaxed),
                calls_after_failure,
            );
            let frees_before_destroy = allocation_test_hook::FREE_CALLS.load(
                core::sync::atomic::Ordering::Relaxed,
            );
            tre_mem_destroy(memory);
            assert_eq!(
                allocation_test_hook::FREE_CALLS.load(core::sync::atomic::Ordering::Relaxed),
                frees_before_destroy + 3,
            );
        }
    }

    #[test]
    fn tre_mem_data_allocation_failure_frees_the_list_then_releases_prior_blocks() {
        let _allocation_guard = allocation_test_hook::lock();
        // SAFETY: all calls use one test-owned source arena.
        unsafe {
            allocation_test_hook::reset();
            let memory = tre_mem_new();
            assert!(!tre_mem_alloc(memory, 1).is_null());
            allocation_test_hook::fail_after(1);
            assert!(tre_mem_alloc(memory, TRE_MEM_BLOCK_SIZE).is_null());
            assert_eq!((*memory).failed, 1);
            let frees_before_destroy = allocation_test_hook::FREE_CALLS.load(
                core::sync::atomic::Ordering::Relaxed,
            );
            // The failed data allocation consumes no data block, but its
            // freshly allocated list record is released immediately.
            assert_eq!(frees_before_destroy, 1);
            tre_mem_destroy(memory);
            assert_eq!(
                allocation_test_hook::FREE_CALLS.load(core::sync::atomic::Ordering::Relaxed),
                frees_before_destroy + 3,
            );
        }
    }

    #[test]
    fn tre_mem_marks_an_unrepresentable_c_int_block_size_sticky() {
        let _allocation_guard = allocation_test_hook::lock();
        // SAFETY: the request is rejected before it can allocate or dereference
        // a block; the test then consumes its sole arena allocation.
        unsafe {
            allocation_test_hook::reset();
            let memory = tre_mem_new();
            let unrepresentable_size = c_int::MAX as usize / 8 + 1;
            assert!(tre_mem_alloc(memory, unrepresentable_size).is_null());
            assert_eq!((*memory).failed, 1);
            let calls_after_failure = allocation_test_hook::ALLOCATION_CALLS.load(
                core::sync::atomic::Ordering::Relaxed,
            );
            assert!(tre_mem_alloc(memory, 1).is_null());
            assert_eq!(
                allocation_test_hook::ALLOCATION_CALLS.load(core::sync::atomic::Ordering::Relaxed),
                calls_after_failure,
            );
            tre_mem_destroy(memory);
        }
    }
}
