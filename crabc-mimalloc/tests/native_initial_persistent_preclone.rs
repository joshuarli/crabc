// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The pre-clone witness remains default-off and exposes no
// owner, PageMap, scheduler, route, or client capability.
#![cfg(feature = "native-runtime-test-audit")]

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free,
    prepare_native_initial_owner_for_later_thread,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Pre-clone preparation from `COLD` moves the initial static owner into its
/// persistent TLS cell before a later worker can claim an admission. Once the
/// worker has attached and fully finished, the initial thread's first native
/// operation still reaches that exact direct owner rather than the vacated
/// static scheduler slot.
#[test]
fn preclone_promotes_cold_initial_owner_before_later_admission() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the cold pre-clone witness"
    );
    prepare_native_initial_owner_for_later_thread();

    let worker = std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let local = match native_allocate_aligned(41, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the prepared later worker creates an independent local block")
            }
        };
        // SAFETY: this exact worker-local block remains current until its
        // one pointer-first free below.
        assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);
        finish_current_thread_native_after_user_destructors()
    });
    assert_eq!(
        worker
            .join()
            .expect("the independently prepared later worker joins"),
        ThreadFinishResult::Finished,
        "the pre-clone initial promotion admits and releases the later worker"
    );

    let initial = match native_allocate_aligned(97, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the first initial native operation remains available after the worker finishes")
        }
    };
    // SAFETY: the persistent initial owner created this exact local block and
    // retains it until its one pointer-first free below.
    assert_eq!(unsafe { native_free(initial) }, NativePageFreeResult::Freed);
}
