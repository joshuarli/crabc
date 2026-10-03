#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::source_api::{self, FreeOutcome};

#[test]
fn aligned_offset_client_keeps_usable_reallocation_and_free_contract() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    #[cfg(target_arch = "x86_64")]
    arbitrary_offset_clients_preserve_byte_extents_through_canonical_free();
    selected_theap_reallocation_preserves_source_extent();
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
        let half = usable.value - usable.value / 2;
        let reused = source_api::realloc_aligned_at(original.as_ptr(), half, 128, 11);
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

        let client = source_api::malloc_aligned_at(81, 128, 11).value.unwrap();
        let client_extent = source_api::usable_size(client.as_ptr());
        client.as_ptr().write_bytes(0x19, client_extent);
        let refused = source_api::urealloc(client.as_ptr(), usize::MAX);
        assert!(refused.value.0.is_none());
        let canonical_size = refused.value.1.unwrap();
        assert!(canonical_size > client_extent,
            "the offset client reports its complete canonical block size");
        assert_eq!(refused.value.2, None, "failure leaves the new block-size output untouched");
        assert_eq!(source_api::usable_size(client.as_ptr()), client_extent);
        let grown = source_api::urealloc(client.as_ptr(), 501);
        assert_eq!(grown.errno.apply(0), 0);
        assert_eq!(grown.value.1, Some(canonical_size));
        let grown_block_size = grown.value.2.unwrap();
        assert!(grown_block_size >= 501);
        let grown = grown.value.0.unwrap();
        assert!(core::slice::from_raw_parts(grown.as_ptr(), client_extent).iter().all(|byte| *byte == 0x19));
        assert_eq!(source_api::ufree(grown.as_ptr()), (FreeOutcome::Freed, grown_block_size));

        let zero = source_api::malloc_aligned_at(0, 128, 11).value.unwrap();
        let zero_usable = source_api::usable_size(zero.as_ptr());
        let reused = source_api::realloc_aligned_at(zero.as_ptr(), 0, 128, 11);
        assert_eq!(reused.errno.apply(0), 0);
        if zero_usable == 0 {
            assert_eq!(reused.value, Some(zero), "zero extent satisfies aligned reuse");
        } else {
            assert_ne!(reused.value, Some(zero), "nonzero extent fails zero-size ceil-half reuse");
        }
        let reused = reused.value.unwrap();
        assert_eq!((reused.as_ptr().addr() + 11) % 128, 0);
        assert_eq!(source_api::free(reused.as_ptr()), FreeOutcome::Freed);

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
        let client = crabc_mimalloc::source_heap_api::heap_malloc_aligned_at(heap, 81, 128, 11, true).value.unwrap();
        client.as_ptr().write_bytes(0x51, 81);
        let theap = crabc_mimalloc::source_heap_api::heap_theap(heap);
        let grown = source_api::theap_realloc(theap, client.as_ptr(), 401, true);
        assert_eq!(grown.errno.apply(0), 0);
        let grown = grown.value.unwrap();
        assert!(core::slice::from_raw_parts(grown.as_ptr(), 81).iter().all(|byte| *byte == 0x51));
        assert!(core::slice::from_raw_parts(grown.as_ptr().add(81), 320).iter().all(|byte| *byte == 0));
        assert_eq!(source_api::free(grown.as_ptr()), FreeOutcome::Freed);
        assert!(crabc_mimalloc::source_heap_api::heap_release(heap, true));

        let address = std::thread::spawn(|| {
            use crabc_mimalloc::__crabc_runtime::{ThreadAttachResult, ThreadFinishResult, finish_current_thread_native_after_user_destructors};
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            let client = source_api::zalloc_aligned_at(81, 128, 11).value.unwrap();
            // SAFETY: the worker exclusively owns the exact returned client
            // until its address is transferred after the worker has joined.
            client.as_ptr().write_bytes(0x74, 81);
            let address = client.as_ptr().expose_provenance();
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            address
        }).join().unwrap();
        // The joined worker transfers its still-live exact client; no other
        // thread retains access, and the allocation keeps its page registered.
        let client = core::ptr::with_exposed_provenance_mut::<u8>(address);
        assert!(source_api::usable_size(client) >= 81);
        assert!(core::slice::from_raw_parts(client, 81).iter().all(|byte| *byte == 0x74));
        assert_eq!(source_api::free(client), FreeOutcome::Freed);

        #[cfg(feature = "mi-debug-1")]
        {
            let client = source_api::malloc_aligned_at(81, 128, 11).value.unwrap();
            let usable = source_api::usable_size(client.as_ptr());
            assert!(usable >= 81);
            // The live canonical block also owns its reserved debug tail.
            // Deliberately change its first padding/record byte to verify
            // that accepting the exact offset client does not bypass the
            // existing padding refusal. The fresh test process retains this
            // refused allocation until exit, without retrying a rejected free.
            let tail = client.as_ptr().add(usable);
            tail.write(tail.read() ^ 0xff);
            let refused = source_api::free_sourced(client.as_ptr());
            assert_eq!(refused.value, FreeOutcome::RejectedCorruption);
            assert_eq!(refused.errno.apply(29), 29);
        }
    }
}

fn selected_theap_reallocation_preserves_source_extent() {
    use crabc_mimalloc::source_heap_api as heap_api;

    let source = heap_api::heap_new();
    let target = heap_api::heap_new();
    assert!(!source.is_null() && !target.is_null());
    let base = heap_api::theap_get_default();
    // SAFETY: this thread retains both Heaps and their initialized Theaps,
    // exclusively owns each returned client, restores its default Theap,
    // and frees every client before releasing either Heap.
    unsafe {
        let selected = heap_api::heap_theap(target);
        assert!(!selected.is_null());
        assert_eq!(heap_api::theap_set_default(selected), base);
        for alignment in [8, 128] {
            let offset = if alignment == 8 { 7 } else { 11 };
            let old = heap_api::heap_malloc_aligned_at(source, 81, alignment, offset, false)
                .value.unwrap();
            let extent = source_api::usable_size(old.as_ptr());
            assert!(extent >= 81);
            old.as_ptr().write_bytes(0x58, extent);
            let half = extent - extent / 2;
            let reused = source_api::rezalloc_aligned_at(old.as_ptr(), half, alignment, offset);
            assert_eq!(reused.value, Some(old), "aligned reuse omits the target Heap comparison");
            assert_eq!(heap_api::heap_of(old.as_ptr()), source);
            assert_eq!(source_api::usable_size(old.as_ptr()), extent,
                "reuse retains the original extent even after a smaller request");
            let failed = source_api::rezalloc_aligned_at(old.as_ptr(), usize::MAX, alignment, offset);
            assert!(failed.value.is_none());
            assert_eq!(source_api::usable_size(old.as_ptr()), extent);
            assert!(core::slice::from_raw_parts(old.as_ptr(), extent).iter().all(|byte| *byte == 0x58));

            let grown = source_api::rezalloc_aligned_at(old.as_ptr(), extent + 173, alignment, offset)
                .value.unwrap();
            assert_eq!((grown.as_ptr().addr() + offset) % alignment, 0);
            assert_eq!(heap_api::heap_of(grown.as_ptr()), target);
            let grown_extent = source_api::usable_size(grown.as_ptr());
            assert!(grown_extent >= extent + 173);
            assert!(core::slice::from_raw_parts(grown.as_ptr(), extent).iter().all(|byte| *byte == 0x58),
                "replacement copies the observed extent, including bytes beyond the smaller request");
            assert!(core::slice::from_raw_parts(grown.as_ptr().add(extent), grown_extent - extent)
                .iter().all(|byte| *byte == 0));
            assert_eq!(source_api::free(grown.as_ptr()), FreeOutcome::Freed);
        }
        assert_eq!(heap_api::theap_set_default(base), selected);

        for explicit in [false, true] {
            let old = heap_api::heap_malloc_aligned_at(source, 81, 128, 11, false).value.unwrap();
            let extent = source_api::usable_size(old.as_ptr());
            old.as_ptr().write_bytes(0x39, extent);
            let replacement = if explicit {
                source_api::theap_realloc(selected, old.as_ptr(), extent, true)
            } else {
                assert_eq!(heap_api::theap_set_default(selected), base);
                let result = source_api::rezalloc(old.as_ptr(), extent);
                assert_eq!(heap_api::theap_set_default(base), selected);
                result
            }.value.unwrap();
            assert_ne!(replacement, old, "ordinary reuse requires equality with the target Heap");
            assert_eq!(heap_api::heap_of(replacement.as_ptr()), target);
            assert!(core::slice::from_raw_parts(replacement.as_ptr(), extent).iter().all(|byte| *byte == 0x39));
            let replacement_extent = source_api::usable_size(replacement.as_ptr());
            assert!(core::slice::from_raw_parts(replacement.as_ptr().add(extent), replacement_extent - extent)
                .iter().all(|byte| *byte == 0));
            assert_eq!(heap_api::theap_get_default(), base,
                "an explicit Theap call retains the current default");
            assert_eq!(source_api::free(replacement.as_ptr()), FreeOutcome::Freed);
        }
        assert!(heap_api::heap_release(source, false));
        assert!(heap_api::heap_release(target, false));
        assert_eq!(heap_api::theap_get_default(), base);
    }
}

#[cfg(target_arch = "x86_64")]
fn arbitrary_offset_clients_preserve_byte_extents_through_canonical_free() {
    let word = core::mem::size_of::<usize>();
    for alignment in [2, 4, 8, 16, 128, 4096, 65_536] {
        for request in [1, 7, 8, 9, 15, 17, 50, 81] {
            for offset in [1, 7, request + 1, 65_537, usize::MAX] {
                let original = source_api::zalloc_aligned_at(request, alignment, offset)
                    .value.unwrap();
                assert_eq!(original.as_ptr().addr().wrapping_add(offset) % alignment, 0);
                if alignment >= word && offset % word != 0 {
                    assert_ne!(original.as_ptr().addr() % word, 0,
                        "an arbitrary-offset client may be unaligned independently of its canonical block");
                }
                // SAFETY: every pointer here is the exact live result of this
                // thread. Each byte access stays within the queried client
                // extent; no canonical prefix or freed storage is accessed.
                unsafe {
                    let extent = source_api::usable_size(original.as_ptr());
                    assert!(extent >= request);
                    assert!(core::slice::from_raw_parts(original.as_ptr(), extent)
                        .iter().all(|byte| *byte == 0));
                    original.as_ptr().write_bytes(0x6b, extent);
                    let half = extent - extent / 2;
                    let reused = source_api::rezalloc_aligned_at(
                        original.as_ptr(), half, alignment, offset).value.unwrap();
                    assert_eq!(reused, original);
                    assert_eq!(source_api::usable_size(reused.as_ptr()), extent);
                    assert!(core::slice::from_raw_parts(reused.as_ptr(), extent)
                        .iter().all(|byte| *byte == 0x6b));

                    let grown = source_api::rezalloc_aligned_at(
                        reused.as_ptr(), extent + 23, alignment, offset).value.unwrap();
                    assert_ne!(grown, reused);
                    assert_eq!(grown.as_ptr().addr().wrapping_add(offset) % alignment, 0);
                    let grown_extent = source_api::usable_size(grown.as_ptr());
                    assert!(grown_extent >= extent + 23);
                    assert!(core::slice::from_raw_parts(grown.as_ptr(), extent)
                        .iter().all(|byte| *byte == 0x6b));
                    assert!(core::slice::from_raw_parts(grown.as_ptr().add(extent), grown_extent - extent)
                        .iter().all(|byte| *byte == 0));
                    let shrunk = source_api::rezalloc_aligned_at(
                        grown.as_ptr(), 1, alignment, offset).value.unwrap();
                    assert_ne!(shrunk, grown);
                    assert_eq!(shrunk.as_ptr().addr().wrapping_add(offset) % alignment, 0);
                    let shrunk_extent = source_api::usable_size(shrunk.as_ptr());
                    assert!(shrunk_extent >= 1);
                    assert_eq!(shrunk.as_ptr().read(), 0x6b);
                    assert!(core::slice::from_raw_parts(shrunk.as_ptr().add(1), shrunk_extent - 1)
                        .iter().all(|byte| *byte == 0));
                    let (freed, canonical_size) = source_api::ufree(shrunk.as_ptr());
                    assert_eq!(freed, FreeOutcome::Freed);
                    assert!(canonical_size >= shrunk_extent);
                    assert_eq!(canonical_size % word, 0);

                    // Following requests remain valid after canonical free,
                    // even when their returned byte pointers do not have
                    // the word alignment required by canonical free links.
                    let next = source_api::malloc_aligned_at(request, alignment, offset)
                        .value.unwrap();
                    let next_extent = source_api::usable_size(next.as_ptr());
                    assert!(next_extent >= request);
                    next.as_ptr().write_bytes(0x39, next_extent);
                    assert_eq!(source_api::free(next.as_ptr()), FreeOutcome::Freed);
                }
            }
        }
    }
}
