#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::{source_api as api, source_heap_api as heaps};

#[test]
fn main_auxiliary_theap_birth_preserves_source_metadata_geometry_and_lifetime() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let heap = heaps::heap_new();
    assert!(!heap.is_null());
    // SAFETY: this sole owner retains the new Heap, its auxiliary Theap,
    // and its client until the final free and Heap deletion below.
    unsafe {
        let block = heaps::heap_malloc(heap, 73).value.unwrap();
        block.as_ptr().write_bytes(0x73, 73);
        let theap = heaps::heap_theap(heap);
        assert!(!theap.is_null());
        assert_eq!(api::usable_size(theap.cast()), if cfg!(feature = "mi-debug-1") { 8112 } else { 8192 });
        for offset in 0..73 { assert_eq!(block.as_ptr().add(offset).read(), 0x73); }
        assert_eq!(heaps::heap_of(block.as_ptr()), heap);
        println!("theap.usable={}\ntheap.client_preserved=1", api::usable_size(theap.cast()));
        assert_eq!(api::free(block.as_ptr()), api::FreeOutcome::Freed);
        assert!(heaps::heap_release(heap, false));
    }

    let heap = heaps::heap_new();
    assert!(!heap.is_null());
    let heap_address = heap as usize;
    let (theap_usable, client_address) = std::thread::spawn(move || {
        use crabc_mimalloc::__crabc_runtime::{
            ThreadAttachResult, ThreadFinishResult,
            finish_current_thread_native_after_user_destructors,
        };
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: the parent retains the Heap through the join. This worker
        // owns the new client until it hands the address to the joined parent.
        unsafe {
            let heap = heap_address as *mut core::ffi::c_void;
            let block = heaps::heap_malloc(heap, 73).value.unwrap();
            block.as_ptr().write_bytes(0x51, 73);
            let theap = heaps::heap_theap(heap);
            assert!(!theap.is_null());
            let result = (api::usable_size(theap.cast()), block.as_ptr() as usize);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            result
        }
    }).join().expect("the source owner finishes before the final Heap reference");
    // SAFETY: join ended the creator's allocator lifetime and freed its
    // Theap metadata. Only the observed size and a live client cross the join;
    // the Heap and abandoned client page remain owned until the free below.
    unsafe {
        let client = client_address as *mut u8;
        assert_eq!(theap_usable, if cfg!(feature = "mi-debug-1") { 8112 } else { 8192 });
        println!("theap.joined_usable={theap_usable}");
        for offset in 0..73 { assert_eq!(client.add(offset).read(), 0x51); }
        assert_eq!(heaps::heap_of(client), heap);
        assert_eq!(api::free(client), api::FreeOutcome::Freed);
        assert!(heaps::heap_release(heap, false));
        println!("theap.joined_client_preserved=1");
    }
}
