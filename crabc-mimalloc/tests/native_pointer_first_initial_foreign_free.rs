use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// A foreign `free` derives the initial owner's page and canonical block from
/// the supplied aligned client. It publishes only to that page's remote head;
/// neither owner borrows the other's persistent allocator state.
#[test]
fn native_free_publishes_an_aligned_initial_client_from_a_foreign_owner() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the pointer-first foreign-free witness"
    );

    let remote = match native_allocate_aligned(79, 128, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner creates the aligned foreign source")
        }
    };
    assert_eq!(
        remote.as_ptr().addr() & 127,
        0,
        "the source client exercises canonical recovery from an aligned address"
    );
    let anchor = match native_allocate_aligned(43, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner retains one live local client during foreign publication")
        }
    };

    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    let (publish_sender, publish_receiver) = mpsc::sync_channel(0);
    let remote_address = remote.as_ptr().addr();
    let worker = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let local = match native_allocate_aligned(41, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the foreign worker keeps its own persistent local owner")
            }
        };
        ready_sender
            .send(())
            .expect("the initial owner waits until the foreign worker is live");
        publish_receiver
            .recv()
            .expect("the foreign worker publishes only after the initial source is ready");

        // SAFETY: the initial owner keeps this exact aligned client live until
        // this source publication has completed.
        let remote = unsafe { core::ptr::NonNull::new_unchecked(remote_address as *mut u8) };
        assert_eq!(
            unsafe { native_free(remote) },
            NativePageFreeResult::Freed,
            "the foreign worker publishes the initial owner's canonical source block"
        );
        // SAFETY: `local` remains the worker's exact current client; the
        // foreign publication neither borrows nor terminals this owner.
        assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);
        finish_current_thread_native_after_user_destructors()
    });

    ready_receiver
        .recv()
        .expect("the initial owner observes the foreign worker before publication");
    publish_sender
        .send(())
        .expect("the foreign worker may publish the live initial client");
    assert_eq!(
        worker
            .join()
            .expect("the foreign worker completes after its page-local publication"),
        ThreadFinishResult::Finished,
        "the foreign worker completes its independent lifecycle"
    );

    let probe = match native_allocate_aligned(61, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner remains usable after collecting a foreign publication")
        }
    };
    // SAFETY: both clients remain current in the initial owner. The probe
    // gives that owner an ordinary post-publication source operation before
    // both local clients leave their direct paths.
    assert_eq!(unsafe { native_free(probe) }, NativePageFreeResult::Freed);
    assert_eq!(unsafe { native_free(anchor) }, NativePageFreeResult::Freed);
}
