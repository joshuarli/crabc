// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The scalar audit stays private to the feature and does
// not expose an owner, raw PageMap capability, or allocation identity.
#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;



use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors,
    native_allocate_aligned, native_free, native_runtime_lifecycle_test_audit,
    prepare_native_later_thread_arena,
};

const LOCAL_CYCLES: usize = 4;
const REQUEST: usize = 64;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_local() -> core::ptr::NonNull<u8> {
    match native_allocate_aligned(REQUEST, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial persistent owner creates its exact local client")
        }
    }
}

/// Pinned `mi_free` returns an all-free local page to its retained Theap; it
/// does not turn every ordinary client free into a heap-collection boundary.
/// This direct C-shaped sequence samples the process PageMap only after each
/// completed operation: the first local page remains registered through every
/// all-free cycle, then the explicit later-worker handoff alone drains it.
#[test]
fn initial_local_all_free_cycles_keep_the_page_engine_until_explicit_handoff() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the direct initial-local audit"
    );

    let mut registered_page_entries = None;
    let mut direct_local_baseline = None;
    for cycle in 0..LOCAL_CYCLES {
        let block = allocate_local();
        let after_allocate = native_runtime_lifecycle_test_audit()
            .expect("each initial local allocation leaves a readable scalar audit");
        let entries = after_allocate.page_map_registered_entry_count;
        if let Some(expected_entries) = registered_page_entries {
            assert_eq!(
                entries, expected_entries,
                "cycle {cycle} reuses the persistent initial page engine without a fresh PageMap setup"
            );
        } else {
            assert!(
                entries > 0,
                "the first direct local allocation publishes its source page"
            );
            registered_page_entries = Some(entries);
            direct_local_baseline = Some(after_allocate);
        }

        // SAFETY: the direct initial owner returned this exact local block,
        // which has no aliases, remote producer, or prior free.
        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        let after_free = native_runtime_lifecycle_test_audit()
            .expect("each completed direct local free leaves a readable scalar audit");
        assert_eq!(
            after_free.page_map_registered_entry_count,
            registered_page_entries.expect("the first local cycle fixes the retained page count"),
            "cycle {cycle} keeps the all-free page in the persistent local engine instead of force-collecting it"
        );
        assert_eq!(
            after_free.native_scheduler_transition_count,
            direct_local_baseline
                .expect("the first local cycle fixes the direct-owner audit baseline")
                .native_scheduler_transition_count,
            "the direct local cycle never enters the retired scheduler"
        );
        assert_eq!(
            after_free.native_parked_compatibility_operation_count,
            direct_local_baseline
                .expect("the first local cycle fixes the direct-owner audit baseline")
                .native_parked_compatibility_operation_count,
            "the direct local cycle never enters the parked compatibility bridge"
        );
    }

    // Repeated batches exhaust the immediate list while keeping the same
    // owner and pages live, then consume locally freed blocks through queue
    // lookup. The three requests cover ordinary, overallocated aligned, and
    // medium queue-head selection without a full-page transition.
    for (request, batch) in [(8, 128), (REQUEST, 128), (10248, 8)] {
        let mut retained_entries = None;
        for round in 0..32 {
            let mut blocks = Vec::with_capacity(batch);
            for index in 0..batch {
                let block = match native_allocate_aligned(request, 16, true) {
                    NativePageAllocationResult::Allocated(block) => block,
                    _ => panic!("queue-head reuse supplies request {request}, round {round}"),
                };
                assert_eq!(block.as_ptr().addr() & 15, 0);
                // SAFETY: each successful allocation supplies `request` live
                // writable bytes, exclusively owned until the final free.
                let bytes = unsafe { core::slice::from_raw_parts_mut(block.as_ptr(), request) };
                assert!(bytes.iter().all(|byte| *byte == 0), "reused blocks are zeroed");
                bytes.fill((index + 1) as u8);
                blocks.push(block);
            }
            let entries = native_runtime_lifecycle_test_audit().unwrap().page_map_registered_entry_count;
            if let Some(expected) = retained_entries {
                assert_eq!(entries, expected, "request {request} reuses its retained page image");
            } else {
                retained_entries = Some(entries);
            }
            for (index, block) in blocks.into_iter().enumerate() {
                // SAFETY: this exact allocation remains live; no other block
                // aliases its requested bytes, including after local reuse.
                let bytes = unsafe { core::slice::from_raw_parts(block.as_ptr(), request) };
                assert!(bytes.iter().all(|byte| *byte == (index + 1) as u8));
                // SAFETY: consumes the exact live client once on its owner.
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
            }
            assert_eq!(native_runtime_lifecycle_test_audit().unwrap().page_map_registered_entry_count, entries);
        }
    }

    assert!(
        prepare_native_later_thread_arena(),
        "the explicit later-worker boundary force-collects the now-all-free initial engine"
    );
    let after_handoff = native_runtime_lifecycle_test_audit()
        .expect("the explicit handoff leaves a readable scalar lifecycle audit");
    assert_eq!(
        after_handoff.page_map_registered_entry_count,
        0,
        "only the explicit later-worker boundary retires the retained initial page"
    );

    let worker = std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let block = match native_allocate_aligned(REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the explicit handoff admits one independent persistent worker")
            }
        };
        // SAFETY: this attached worker keeps the returned client local until
        // this exact free, then follows its ordinary source teardown.
        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        finish_current_thread_native_after_user_destructors()
    });
    assert_eq!(
        worker
            .join()
            .expect("the independent later worker returns normally"),
        ThreadFinishResult::Finished,
        "the explicit initial handoff preserves normal later-worker teardown"
    );
}
