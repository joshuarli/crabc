#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::CStr;
use crabc_mimalloc::{source_api as api, source_heap_api as heaps};

fn requested_total() -> i64 {
    let mut buffer = [0_i8; 65536];
    // SAFETY: this owner retains its main Heap; the fixed buffer is exclusive
    // and lives through the getter and subsequent zero-terminated projection.
    let json = unsafe {
        assert_eq!(heaps::heap_stats_json(heaps::heap_main(), buffer.len(), buffer.as_mut_ptr()), buffer.as_mut_ptr());
        CStr::from_ptr(buffer.as_ptr()).to_str().unwrap()
    };
    let value = json.split_once("\"malloc_requested\"").unwrap().1
        .split_once("\"total\":").unwrap().1.split(',').next().unwrap();
    value.trim().parse().unwrap()
}

fn observe_birth() {
    let warm = heaps::heap_new();
    assert!(!warm.is_null());
    // SAFETY: this sole owner holds the empty Heap and no client.
    assert!(unsafe { heaps::heap_release(warm, false) });
    let before = requested_total();
    let heap = heaps::heap_new();
    assert!(!heap.is_null());
    let requested = requested_total() - before;
    // The pinned x86 source Heap request is 6464 bytes in every selected
    // profile; requested-byte counters are enabled only at statistics level two.
    let expected = if cfg!(any(feature = "mi-debug-1", feature = "mi-stat-2")) { 6464 } else { 0 };
    assert_eq!(requested, expected);
    assert_eq!(heap.addr() % 32, 0);
    // SAFETY: the Heap itself is a live ordinary allocation from this owner's
    // main Heap. Its full image and the client remain live through deletion.
    unsafe {
        let usable = api::usable_size(heap.cast());
        let expected_usable = if cfg!(feature = "mi-debug-1") { 6464 } else { 7168 };
        assert_eq!(usable, expected_usable);
        println!("birth.requested={requested}\nbirth.usable={usable}\nbirth.aligned32=1");
        let client = heaps::heap_malloc(heap, 73).value.unwrap();
        client.as_ptr().write_bytes(0x73, 73);
        assert_eq!(heaps::heap_of(client.as_ptr()), heap);
        for index in 0..73 { assert_eq!(client.as_ptr().add(index).read(), 0x73); }
        assert_eq!(api::free(client.as_ptr()), api::FreeOutcome::Freed);
        assert!(heaps::heap_release(heap, false));
    }
}

#[test]
fn main_heap_birth_uses_source_sized_request_and_retains_aligned_image() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    observe_birth();
}

#[test]
fn heap_birth_uses_source_sized_request_and_retains_aligned_image() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    observe_birth();
    assert!(crabc_mimalloc::__crabc_runtime::prepare_native_later_thread_arena());
    let child = heaps::subproc_new() as usize;
    assert_ne!(child, 0);
    std::thread::spawn(move || {
        let descriptor = crabc_mimalloc::__crabc_runtime::current_native_allocator_thread_descriptor();
        // SAFETY: this fresh worker owns its TLS descriptor and joins the live
        // child before allocation. The caller retains the child until join.
        unsafe {
            assert!(crabc_mimalloc::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor));
            assert_eq!(heaps::subproc_add_current_thread(child as *mut core::ffi::c_void),
                       heaps::SubprocAddCurrentThread::Added);
            observe_birth();
            assert_eq!(crabc_mimalloc::__crabc_runtime::finish_current_thread_native_after_user_destructors(),
                       crabc_mimalloc::__crabc_runtime::ThreadFinishResult::Finished);
        }
    }).join().unwrap();
    // SAFETY: the joined worker freed its only client and auxiliary Heap.
    assert!(unsafe { heaps::subproc_destroy(child as *mut core::ffi::c_void) });
}
