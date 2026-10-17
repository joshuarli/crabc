#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{c_int, c_void};
use crabc_mimalloc::__crabc_runtime::{
    ThreadAttachResult, ThreadFinishResult, finish_current_thread_native_after_user_destructors,
    prepare_native_later_thread_arena,
};
use crabc_mimalloc::source_api::{self as api, FreeOutcome};
use crabc_mimalloc::source_heap_api as heaps;

unsafe extern "C" {
    fn mincore(address: *mut c_void, length: usize, residency: *mut u8) -> c_int;
}

#[test]
fn dynamic_heap_os_singleton_survives_join_and_unmaps_on_consumer_free() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    let owner = std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let heap = heaps::heap_new();
        assert!(!heap.is_null());
        assert!(!unsafe { heaps::heap_theap(heap) }.is_null());
        let allocation = unsafe { heaps::heap_malloc_aligned_at(heap, 7, 128 * 1024, 0, false) };
        assert_eq!(allocation.errno.apply(37), 37);
        let block = allocation.value.expect("the source-aligned OS singleton");
        assert_eq!(block.as_ptr().addr() % (128 * 1024), 0);
        unsafe { block.as_ptr().write_bytes(0xa5, 7) };
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        (heap.addr(), block.as_ptr().addr())
    });
    let (heap, address) = owner.join().expect("the source owner completes thread teardown");
    let heap = heap as *mut c_void;
    let block = address as *mut u8;
    unsafe {
        assert_eq!(heaps::heap_of(block), heap);
        for index in 0..7 { assert_eq!(block.add(index).read(), 0xa5); }
        let mut residency = 0;
        assert_eq!(mincore(block.cast(), page_size, &mut residency), 0);
        assert_eq!(api::free(block), FreeOutcome::Freed);
        assert_eq!(mincore(block.cast(), page_size, &mut residency), -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(12));
        assert!(heaps::heap_release(heap, true));
    }
}
