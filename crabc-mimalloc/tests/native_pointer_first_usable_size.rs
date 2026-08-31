// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The scalar audit is deliberately default-off and exposes
// no client, page, owner, route, or scheduler capability.
#![cfg(feature = "native-runtime-test-audit")]

use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_runtime_lifecycle_test_audit, native_usable_size,
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
            panic!("the current persistent owner creates its aligned native client")
        }
    }
}

/// Pinned `mi_usable_size` first validates the supplied pointer's page, then
/// returns that page's geometry. It neither selects the calling owner nor
/// reopens a scheduler. Both persistent owner forms therefore expose an
/// aligned live client to either the source owner or a foreign attached
/// observer while the exact client remains live.
#[test]
fn native_usable_size_observes_aligned_initial_and_later_clients_from_foreign_threads() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the pointer-observer witness"
    );

    let initial = allocate_aligned_current(79, 128);
    assert_eq!(
        initial.as_ptr().addr() & 127,
        0,
        "the initial source exercises aligned pointer geometry"
    );
    // SAFETY: `initial` is the initial owner's exact live aligned client
    // through the local and foreign pointer-only observations below.
    let initial_usable = unsafe { native_usable_size(initial) }
        .expect("the initial source exposes its PageMap-derived usable extent");
    assert!(initial_usable >= 79);

    let before_initial_repeat = native_runtime_lifecycle_test_audit()
        .expect("the initial live client establishes a quiescent scalar baseline");
    assert_eq!(
        unsafe { native_usable_size(initial) },
        Some(initial_usable),
        "a repeated initial query copies the same pointer-derived extent"
    );
    let after_initial_repeat = native_runtime_lifecycle_test_audit()
        .expect("a usable-size query leaves the scalar runtime auditable");
    assert_eq!(
        after_initial_repeat, before_initial_repeat,
        "a valid usable-size query is read-only and does not select an owner or scheduler"
    );

    let initial_address = initial.as_ptr().addr();
    let (later_sender, later_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let later = allocate_aligned_current(83, 256);
        assert_eq!(
            later.as_ptr().addr() & 255,
            0,
            "the later source exercises aligned pointer geometry"
        );
        // SAFETY: `later` remains the worker's exact live client until its
        // matching local free after the initial observer finishes.
        let later_usable = unsafe { native_usable_size(later) }
            .expect("the later source exposes its PageMap-derived usable extent");
        assert!(later_usable >= 83);

        // SAFETY: the initial thread keeps this exact client live and does
        // not access it concurrently while the worker only observes its
        // immutable PageMap-derived usable extent.
        let foreign_initial = unsafe {
            core::ptr::NonNull::new_unchecked(initial_address as *mut u8)
        };
        assert_eq!(
            unsafe { native_usable_size(foreign_initial) },
            Some(initial_usable),
            "a later observer reads the initial client's pointer-derived extent"
        );
        later_sender
            .send((later.as_ptr().addr(), later_usable))
            .expect("the initial observer receives the later live client");
        resume_receiver
            .recv()
            .expect("the worker resumes after the foreign observation");

        // SAFETY: `later` remains this worker's exact current native client
        // until this one matching local pointer-first free.
        assert_eq!(unsafe { native_free(later) }, NativePageFreeResult::Freed);
        finish_current_thread_native_after_user_destructors()
    });

    let (later_address, later_usable) = later_receiver
        .recv()
        .expect("the worker publishes its still-live aligned client");
    // SAFETY: the worker keeps this exact client live and paused while the
    // initial thread only reads its immutable PageMap-derived usable extent.
    let foreign_later = unsafe { core::ptr::NonNull::new_unchecked(later_address as *mut u8) };
    assert_eq!(
        unsafe { native_usable_size(foreign_later) },
        Some(later_usable),
        "the initial observer reads the later client's pointer-derived extent"
    );
    resume_sender
        .send(())
        .expect("the worker resumes to free its local source");
    assert_eq!(
        worker
            .join()
            .expect("the later observer joins after its local free"),
        ThreadFinishResult::Finished,
        "the later persistent owner completes its normal all-free lifecycle"
    );

    // SAFETY: the initial source remains its exact current live client until
    // this one matching local pointer-first free.
    assert_eq!(unsafe { native_free(initial) }, NativePageFreeResult::Freed);
    let after = native_runtime_lifecycle_test_audit()
        .expect("both released clients leave a quiescent scalar audit");
    assert_eq!(
        after.native_scheduler_transition_count,
        before_initial_repeat.native_scheduler_transition_count,
        "pointer-only usable-size observations do not reopen the legacy scheduler"
    );
    assert_eq!(
        after.native_parked_compatibility_operation_count,
        before_initial_repeat.native_parked_compatibility_operation_count,
        "pointer-only usable-size observations do not enter the parked compatibility bridge"
    );
    assert_eq!(
        after.page_map_registered_entry_count, 0,
        "both exact clients release their PageMap registrations after their observers finish"
    );
}
