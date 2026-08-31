// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The transition witness remains default-off with the
// existing scalar audit feature and exposes no owner or page capability.
#![cfg(feature = "native-runtime-test-audit")]

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, initialize_process, native_allocate_aligned,
    native_free, prepare_native_later_thread_arena, process_is_active,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// A promoted initial owner may prepare a later worker only after its source
/// engine is dormant. A live source is retained rather than being converted
/// into `ParkedActive` or reviving the now-vacated process-static owner.
#[test]
fn native_initial_persistent_live_transfer_retains_without_parking() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the initial-owner transfer witness"
    );
    let anchor = match native_allocate_aligned(97, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial thread promotes and keeps its live source anchor")
        }
    };

    assert!(
        !prepare_native_later_thread_arena(),
        "later-worker preparation rejects an attempted transfer of a live initial source"
    );
    assert!(
        !process_is_active(),
        "a live transfer is terminally retained instead of parking or reviving the static owner"
    );

    // SAFETY: the source process is terminally retained by the rejected live
    // transfer. This exact once-live native client must therefore report the
    // scalar retained result instead of falling back to a legacy owner path.
    assert_eq!(unsafe { native_free(anchor) }, NativePageFreeResult::Retained);
}
