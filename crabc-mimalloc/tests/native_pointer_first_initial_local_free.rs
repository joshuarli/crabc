// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The scalar audit is deliberately default-off and exposes
// no owner, route, PageMap, scheduler token, or allocation identity.
#![cfg(feature = "native-runtime-test-audit")]

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_runtime_lifecycle_test_audit, native_usable_size,
    prepare_native_later_thread_arena,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Pinned `mi_free_nonnull` performs local free after pointer/page
/// classification. Once the initial thread has its own live page, that normal
/// local operation must not borrow the old process page-owner scheduler or
/// park bridge merely to reach its current source engine.
#[test]
fn native_free_keeps_initial_local_page_out_of_legacy_scheduler() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the initial local-free ratchet"
    );
    let anchor = match native_allocate_aligned(97, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial thread creates its persistent local anchor")
        }
    };
    let local = match native_allocate_aligned(53, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial thread creates its current local native client")
        }
    };
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the live initial source page has a readable scalar audit");

    // SAFETY: this exact initial-thread client remains live and locally
    // owned until its one pointer-first native free below.
    assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);

    let after_local = native_runtime_lifecycle_test_audit()
        .expect("the completed initial local free retains a readable scalar audit");
    assert_eq!(
        after_local
            .native_scheduler_transition_count
            .saturating_sub(baseline.native_scheduler_transition_count),
        0,
        "ordinary initial pointer-first local free never claims the legacy scheduler"
    );
    assert_eq!(
        after_local
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "ordinary initial pointer-first local free never enters the parked compatibility bridge"
    );

    // SAFETY: the anchor remains an exact current initial-thread client after
    // the sibling pointer free. A direct owner-local free must not disturb its
    // source page or make its pointer-derived extent unavailable.
    assert!(
        unsafe { native_usable_size(anchor) }.is_some_and(|usable_size| usable_size >= 97),
        "the still-live initial anchor retains its usable extent after the local free"
    );
    // SAFETY: the anchor remains current and locally owned until this one
    // final pointer-first free.
    assert_eq!(unsafe { native_free(anchor) }, NativePageFreeResult::Freed);

    assert!(
        prepare_native_later_thread_arena(),
        "a promoted but source-dormant initial owner still prepares an independent later worker"
    );
    let worker = std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let block = match native_allocate_aligned(41, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the prepared later worker owns an independent local source engine")
            }
        };
        // SAFETY: this current worker owns its exact local native block until
        // its one pointer-first free below.
        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        finish_current_thread_native_after_user_destructors()
    });
    assert_eq!(
        worker
            .join()
            .expect("the independent later worker completes its local lifecycle"),
        ThreadFinishResult::Finished,
        "dormant initial promotion does not permanently reject later workers"
    );
}
