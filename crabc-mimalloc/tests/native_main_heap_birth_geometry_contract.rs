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
}
