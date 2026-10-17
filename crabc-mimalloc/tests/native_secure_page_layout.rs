#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{
    ThreadAttachResult, ThreadFinishResult, finish_current_thread_native_after_user_destructors,
    prepare_native_later_thread_arena,
};
use crabc_mimalloc::source_api::{self as api, FreeOutcome};
use crabc_mimalloc::source_heap_api as heaps;

unsafe extern "C" {
    fn mincore(address: *mut core::ffi::c_void, length: usize, residency: *mut u8) -> core::ffi::c_int;
}

#[test]
fn secure_checked_pages_preserve_inline_clients_and_offset_mapping_ownership() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let heap = heaps::heap_new();
        assert!(!heap.is_null());
        crabc_mimalloc::source_options_api::option_set(17, 1);
        for size in [16, 6464, 8192, 1024 * 1024] {
            let block = unsafe { heaps::heap_malloc_aligned_at(heap, size, 16, 0, true) }.value.unwrap();
            unsafe {
                assert!(api::usable_size(block.as_ptr()) >= size);
                assert_eq!(heaps::heap_of(block.as_ptr()), heap);
                assert!((0..size).all(|index| block.as_ptr().add(index).read() == 0));
                block.as_ptr().write_bytes(0x6b, size);
                assert_eq!(api::free(block.as_ptr()), FreeOutcome::Freed);
            }
        }
        crabc_mimalloc::source_options_api::option_set(17, 0);
        assert!(unsafe { heaps::heap_release(heap, true) });
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    }).join().unwrap();
    crabc_mimalloc::source_options_api::option_set(23, 0);
    crabc_mimalloc::source_options_api::option_set(26, 1);
    let owner = std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let heap = heaps::heap_new();
        assert!(!heap.is_null());
        for size in [16, 6464, 8192, 1024 * 1024] {
            let block = unsafe { heaps::heap_malloc_aligned_at(heap, size, 16, 0, true) }.value.unwrap();
            unsafe {
                assert!(api::usable_size(block.as_ptr()) >= size);
                assert_eq!(heaps::heap_of(block.as_ptr()), heap);
                assert!((0..size).all(|index| block.as_ptr().add(index).read() == 0));
                block.as_ptr().write_bytes(0x6b, size);
                assert_eq!(api::free(block.as_ptr()), FreeOutcome::Freed);
            }
        }
        let large_alignment = if cfg!(feature = "mi-secure-1") { 256 * 1024 * 1024 } else { 512 * 1024 };
        let clients = [128 * 1024, large_alignment].map(|alignment| {
            let block = unsafe { heaps::heap_malloc_aligned_at(heap, 7, alignment, 0, false) }.value.unwrap();
            assert_eq!(block.as_ptr().addr() % alignment, 0);
            unsafe { block.as_ptr().write_bytes(0xa5, 7) };
            (block.as_ptr().addr(), alignment)
        });
        crabc_mimalloc::source_options_api::option_set(17, 1);
        assert!(unsafe { heaps::heap_malloc_aligned_at(heap, 7, 1024 * 1024, 0, false) }.value.is_none());
        crabc_mimalloc::source_options_api::option_set(17, 0);
        let recovered = unsafe { heaps::heap_malloc_aligned_at(heap, 7, 1024 * 1024, 0, false) }.value.unwrap();
        assert_eq!(unsafe { api::free(recovered.as_ptr()) }, FreeOutcome::Freed);
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        (heap.addr(), clients)
    });
    let (heap, clients) = owner.join().unwrap();
    for (address, alignment) in clients {
        let block = address as *mut u8;
        unsafe {
            assert!(api::usable_size(block) >= 7);
            assert_eq!(heaps::heap_of(block).addr(), heap);
            assert!((0..7).all(|index| block.add(index).read() == 0xa5));
            let base = (address - alignment) as *mut core::ffi::c_void;
            let mut residency = 0;
            assert_eq!(mincore(base, page_size, &mut residency), 0);
            assert_eq!(mincore(block.cast(), page_size, &mut residency), 0);
            assert_eq!(api::free(block), FreeOutcome::Freed);
            for page in [base, block.cast()] {
                assert_eq!(mincore(page, page_size, &mut residency), -1);
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(12));
            }
        }
    }
    assert!(unsafe { heaps::heap_release(heap as *mut _, true) });
}
