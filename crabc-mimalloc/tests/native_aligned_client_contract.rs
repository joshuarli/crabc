#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::source_api::{self, FreeOutcome};

#[test]
fn aligned_offset_client_keeps_usable_reallocation_and_free_contract() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let original = source_api::zalloc_aligned_at(81, 128, 11).value.unwrap();
    assert_eq!((original.as_ptr().addr() + 11) % 128, 0);
    // SAFETY: this test exclusively owns the successful 81-byte allocation.
    unsafe {
        assert!(core::slice::from_raw_parts(original.as_ptr(), 81).iter().all(|byte| *byte == 0));
        original.as_ptr().write_bytes(0x63, 81);
        let usable = source_api::usable_size_sourced(original.as_ptr());
        assert!(usable.value >= 81, "a valid offset client must retain its usable extent");
        assert_eq!(usable.errno.apply(0), 0);
        let failed = source_api::realloc_aligned_at(original.as_ptr(), usize::MAX, 128, 11);
        assert!(failed.value.is_none());
        assert!(core::slice::from_raw_parts(original.as_ptr(), 81).iter().all(|byte| *byte == 0x63));
        let reused = source_api::realloc_aligned_at(original.as_ptr(), 81, 128, 11);
        assert_eq!(reused.value, Some(original));
        assert_eq!(reused.errno.apply(0), 0);
        let grown = source_api::realloc_aligned_at(original.as_ptr(), 257, 128, 11);
        assert_eq!(grown.errno.apply(0), 0);
        let grown = grown.value.unwrap();
        assert_eq!((grown.as_ptr().addr() + 11) % 128, 0);
        assert!(core::slice::from_raw_parts(grown.as_ptr(), 81).iter().all(|byte| *byte == 0x63));
        let freed = source_api::free_sourced(grown.as_ptr());
        assert_eq!(freed.value, FreeOutcome::Freed);
        assert_eq!(freed.errno.apply(0), 0);

        let offset_word = source_api::zalloc_aligned_at(64, 8, 7).value.unwrap();
        offset_word.as_ptr().write_bytes(0x41, 64);
        let grown = source_api::rezalloc(offset_word.as_ptr(), 201);
        assert_eq!(grown.errno.apply(0), 0);
        let grown = grown.value.unwrap();
        assert!(core::slice::from_raw_parts(grown.as_ptr(), 64).iter().all(|byte| *byte == 0x41));
        assert!(core::slice::from_raw_parts(grown.as_ptr().add(64), 137).iter().all(|byte| *byte == 0));
        assert_eq!(source_api::free(grown.as_ptr()), FreeOutcome::Freed);

        let sized = source_api::malloc_aligned_at(37, 64, 3).value.unwrap();
        let freed = source_api::ufree_sourced(sized.as_ptr());
        assert_eq!(freed.value.0, FreeOutcome::Freed);
        assert!(freed.value.1 >= 37);
        assert_eq!(freed.errno.apply(0), 0);

        let heap = crabc_mimalloc::source_heap_api::heap_new();
        assert!(!heap.is_null());
        let client = crabc_mimalloc::source_heap_api::heap_malloc_aligned_at(heap, 81, 128, 11, true).value.unwrap();
        client.as_ptr().write_bytes(0x27, 81);
        let replacement = crabc_mimalloc::source_heap_api::heap_realloc(heap, client.as_ptr(), 301, true);
        assert_eq!(replacement.errno.apply(0), 0);
        assert_eq!(replacement.value.1, FreeOutcome::Freed);
        let replacement = replacement.value.0.unwrap();
        assert!(core::slice::from_raw_parts(replacement.as_ptr(), 81).iter().all(|byte| *byte == 0x27));
        assert!(core::slice::from_raw_parts(replacement.as_ptr().add(81), 220).iter().all(|byte| *byte == 0));
        assert_eq!(source_api::free(replacement.as_ptr()), FreeOutcome::Freed);
        assert!(crabc_mimalloc::source_heap_api::heap_release(heap, true));
    }
}
