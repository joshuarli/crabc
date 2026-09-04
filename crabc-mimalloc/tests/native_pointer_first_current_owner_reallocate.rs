// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The scalar audit remains default-off and exposes neither
// pointer, page, owner, nor scheduler authority.
#![cfg(feature = "native-runtime-test-audit")]

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_reallocate, native_runtime_lifecycle_test_audit,
    native_usable_size, prepare_native_later_thread_arena,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_aligned_current(request: usize, alignment: usize) -> core::ptr::NonNull<u8> {
    match native_allocate_aligned(request, alignment, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the current persistent owner creates its aligned source client")
        }
    }
}

/// `mi_theap_realloc_zero_ex` derives the source page and usable extent from
/// the supplied client before deciding that the current Theap may reuse it in
/// place. Both persistent owner forms must keep that pointer-derived local
/// route direct: it neither reopens initial-owner admission nor borrows the
/// legacy scheduler or parked compatibility bridge.
#[test]
fn native_current_owner_reallocate_keeps_aligned_initial_and_later_paths_direct() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the current-owner realloc witness"
    );

    let initial = allocate_aligned_current(79, 128);
    assert_eq!(
        initial.as_ptr().addr() & 127,
        0,
        "the initial source exercises aligned canonical-page dispatch"
    );
    // SAFETY: this exact aligned client remains current in the initial
    // persistent owner through its in-place source operation below.
    unsafe {
        initial.as_ptr().write(0x4a);
        initial.as_ptr().add(78).write(0x4b);
    }
    let initial_usable = unsafe { native_usable_size(initial) }
        .expect("the initial source exposes its pointer-derived usable extent");
    assert!(initial_usable >= 79);
    let initial_baseline = native_runtime_lifecycle_test_audit()
        .expect("the initial aligned source establishes an auditable baseline");
    let initial_before_realloc = initial;
    let initial = match unsafe { native_reallocate(Some(initial), initial_usable) } {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial persistent owner reuses its exact aligned source")
        }
    };
    assert_eq!(
        initial, initial_before_realloc,
        "the initial current owner reuses its aligned source in place"
    );
    // SAFETY: the returned in-place client is the same current initial source.
    unsafe {
        assert_eq!(initial.as_ptr().read(), 0x4a);
        assert_eq!(initial.as_ptr().add(78).read(), 0x4b);
    }
    let after_initial = native_runtime_lifecycle_test_audit()
        .expect("the completed initial source operation remains auditable");
    assert_eq!(
        after_initial
            .native_scheduler_transition_count
            .saturating_sub(initial_baseline.native_scheduler_transition_count),
        0,
        "an initial current-owner realloc never reopens the legacy scheduler"
    );
    assert_eq!(
        after_initial
            .native_parked_compatibility_operation_count
            .saturating_sub(initial_baseline.native_parked_compatibility_operation_count),
        0,
        "an initial current-owner realloc never enters the parked compatibility bridge"
    );
    // SAFETY: the in-place source remains current until this direct free.
    assert_eq!(unsafe { native_free(initial) }, NativePageFreeResult::Freed);

    assert!(
        prepare_native_later_thread_arena(),
        "the source-dormant initial owner prepares an independent later persistent owner"
    );
    let later_baseline = native_runtime_lifecycle_test_audit()
        .expect("the later-owner phase starts from a quiescent scalar baseline");
    let worker = std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let later = allocate_aligned_current(83, 256);
        assert_eq!(
            later.as_ptr().addr() & 255,
            0,
            "the later source exercises aligned canonical-page dispatch"
        );
        // SAFETY: this exact aligned client remains current in the later
        // persistent owner through its in-place source operation below.
        unsafe {
            later.as_ptr().write(0x5c);
            later.as_ptr().add(82).write(0x5d);
        }
        let later_usable = unsafe { native_usable_size(later) }
            .expect("the later source exposes its pointer-derived usable extent");
        assert!(later_usable >= 83);
        let later_before_realloc = later;
        let later = match unsafe { native_reallocate(Some(later), later_usable) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the later persistent owner reuses its exact aligned source")
            }
        };
        assert_eq!(
            later, later_before_realloc,
            "the later current owner reuses its aligned source in place"
        );
        // SAFETY: the returned in-place client is the same current later source.
        unsafe {
            assert_eq!(later.as_ptr().read(), 0x5c);
            assert_eq!(later.as_ptr().add(82).read(), 0x5d);
        }
        // SAFETY: the in-place source remains current until this direct free.
        assert_eq!(unsafe { native_free(later) }, NativePageFreeResult::Freed);
        finish_current_thread_native_after_user_destructors()
    });
    assert_eq!(
        worker
            .join()
            .expect("the later current-owner realloc worker joins"),
        ThreadFinishResult::Finished,
        "the later persistent owner completes its normal all-free lifecycle"
    );

    let after_later = native_runtime_lifecycle_test_audit()
        .expect("the joined later owner leaves a quiescent scalar audit");
    assert!(
        after_later
            .native_owner_local_operation_count
            .saturating_sub(later_baseline.native_owner_local_operation_count)
            >= 3,
        "the later allocation, realloc, and free all use its retained local owner"
    );
    assert_eq!(
        after_later
            .native_scheduler_transition_count
            .saturating_sub(later_baseline.native_scheduler_transition_count),
        0,
        "a later current-owner realloc never reopens the legacy scheduler"
    );
    assert_eq!(
        after_later
            .native_parked_compatibility_operation_count
            .saturating_sub(later_baseline.native_parked_compatibility_operation_count),
        0,
        "a later current-owner realloc never enters the parked compatibility bridge"
    );
}
