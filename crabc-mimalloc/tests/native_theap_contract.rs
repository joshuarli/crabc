#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use core::ptr::{NonNull, null_mut};
use crabc_mimalloc::__crabc_runtime::{source_api as api, source_heap_api as heaps};

unsafe fn owned_by(block: NonNull<u8>, heap: *mut c_void) {
    // SAFETY: each caller retains its exact live allocation through this query.
    assert_eq!(unsafe { heaps::heap_of(block.as_ptr()) }, heap);
}

unsafe fn zeroed(block: NonNull<u8>, length: usize) {
    // SAFETY: each caller supplies the initialized requested extent of its block.
    assert!(unsafe { core::slice::from_raw_parts(block.as_ptr(), length) }
        .iter().all(|byte| *byte == 0));
}

#[test]
fn public_theap_selection_allocation_collection_and_lifetime() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let base = heaps::theap_get_default();
    let main = heaps::heap_main();
    let heap = heaps::heap_new();
    assert!(!base.is_null() && !main.is_null() && !heap.is_null());

    // SAFETY: all Heap and Theap handles below come from this thread's public
    // selectors. They remain attached and live until their matching release;
    // every block stays exclusively owned until free or successful realloc.
    unsafe {
        let selected = heaps::heap_theap(heap);
        assert!(!selected.is_null() && selected != base);
        assert_eq!(heaps::heap_theap(main), base);
        assert_eq!(heaps::theap_set_default(null_mut()), base);
        assert_eq!(heaps::theap_get_default(), base);

        let before = heaps::theap_malloc(selected, 64, false).value.unwrap();
        owned_by(before, heap);
        assert_eq!(heaps::theap_get_default(), base);
        assert_eq!(heaps::theap_set_default(selected), base);
        let switched = api::malloc(80).value.unwrap();
        let explicit = heaps::theap_malloc(base, 96, false).value.unwrap();
        owned_by(switched, heap);
        owned_by(explicit, main);

        // Interleaving Heap selectors may update their lookup cache, but
        // cannot substitute either direct allocation's Theap or the default.
        for _ in 0..4 {
            assert_eq!(heaps::heap_theap(main), base);
            let from_selected = heaps::theap_malloc(selected, 33, false).value.unwrap();
            assert_eq!(heaps::heap_theap(heap), selected);
            let from_base = heaps::theap_malloc(base, 33, false).value.unwrap();
            owned_by(from_selected, heap);
            owned_by(from_base, main);
            assert_eq!(heaps::theap_get_default(), selected);
            api::free(from_selected.as_ptr());
            api::free(from_base.as_ptr());
        }

        let mut blocks = Vec::new();
        for size in [0, 32, 96, 128, 2048] {
            for zero in [false, true] {
                let block = heaps::theap_malloc(selected, size, zero).value.unwrap();
                owned_by(block, heap);
                if zero { zeroed(block, size); }
                blocks.push(block);
            }
        }
        let counted = api::theap_calloc(selected, 7, 13).value.unwrap();
        owned_by(counted, heap);
        zeroed(counted, 91);
        blocks.push(counted);
        for (size, alignment, zero) in [(73, 4096, false), (129, 1 << 20, true)] {
            let block = api::theap_malloc_aligned_at(selected, size, alignment, 0, zero).value.unwrap();
            assert_eq!(block.as_ptr() as usize % alignment, 0);
            owned_by(block, heap);
            if zero { zeroed(block, size); }
            blocks.push(block);
        }
        let overflow = api::theap_calloc(selected, usize::MAX, 2);
        assert!(overflow.value.is_none());
        #[cfg(not(feature = "mi-debug-1"))]
        assert_eq!(overflow.errno, api::SourceErrno::Unchanged);
        #[cfg(feature = "mi-debug-1")]
        assert_eq!(overflow.errno, api::SourceErrno::DefaultIfZero(crabc_core::Errno::NOMEM));
        assert!(api::theap_malloc_aligned_at(selected, 33, 3, 0, false).value.is_none());
        assert_eq!(heaps::theap_get_default(), selected);

        let original = heaps::theap_malloc(selected, 128, false).value.unwrap();
        let usable = api::usable_size(original.as_ptr());
        original.as_ptr().write_bytes(0x6b, usable);
        let reused = api::theap_realloc(selected, original.as_ptr(), 96, false).value.unwrap();
        assert_eq!(reused, original);
        let grown = api::theap_realloc(selected, reused.as_ptr(), 8192, true).value.unwrap();
        owned_by(grown, heap);
        assert!(core::slice::from_raw_parts(grown.as_ptr(), usable).iter().all(|byte| *byte == 0x6b));
        assert!(core::slice::from_raw_parts(grown.as_ptr().add(usable), 8192 - usable).iter().all(|byte| *byte == 0));
        let failed = api::theap_realloc(selected, grown.as_ptr(), usize::MAX, false);
        assert!(failed.value.is_none());
        owned_by(grown, heap);
        assert_eq!(grown.as_ptr().read(), 0x6b);
        let moved = api::theap_realloc(base, grown.as_ptr(), 16384, false).value.unwrap();
        owned_by(moved, main);
        assert_eq!(moved.as_ptr().read(), 0x6b);
        let empty = api::theap_realloc(selected, moved.as_ptr(), 0, false).value.unwrap();
        owned_by(empty, heap);
        assert_eq!(empty.as_ptr().read(), 0);
        blocks.push(empty);
        let null_zero = api::theap_realloc(selected, null_mut(), 32, true).value.unwrap();
        zeroed(null_zero, 32);
        blocks.push(null_zero);

        for block in blocks.into_iter().chain([before, switched, explicit]) {
            api::free(block.as_ptr());
        }
        api::theap_collect(selected, false);
        api::theap_collect(selected, true);
        api::theap_collect(base, true);
        assert_eq!(heaps::theap_get_default(), selected);
        assert_eq!(heaps::heap_theap(heap), selected);
        assert_eq!(heaps::theap_set_default(base), selected);

        // Deleting an auxiliary Heap transfers its live pages to the main
        // Heap. No deleted Heap or Theap handle is used after this boundary.
        let survivor = heaps::theap_malloc(selected, 57, false).value.unwrap();
        survivor.as_ptr().write_bytes(0x47, 57);
        assert!(heaps::heap_release(heap, false));
        owned_by(survivor, main);
        assert!(core::slice::from_raw_parts(survivor.as_ptr(), 57).iter().all(|byte| *byte == 0x47));
        assert_eq!(heaps::theap_get_default(), base);
        let after = api::malloc(48).value.unwrap();
        owned_by(after, main);
        api::free(survivor.as_ptr());
        api::free(after.as_ptr());
        api::theap_collect(base, true);
    }
}
