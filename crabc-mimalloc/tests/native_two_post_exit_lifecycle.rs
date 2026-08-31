use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, prepare_native_later_thread_arena,
};

const OWNER_EXIT_CLIENT_COUNT: usize = 6;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_owner_exit_aggregate() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let direct_small = match native_allocate_aligned(37, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its direct-small native client"),
    };
    let non_direct_small = match native_allocate_aligned(1025, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its non-direct-small native client"),
    };
    let medium = match native_allocate_aligned(64 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its medium native client"),
    };
    let large = match native_allocate_aligned(128 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its regular-large native client"),
    };
    let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its arena-singleton native client"),
    };
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its OS-singleton native client"),
    };

    [
        direct_small.as_ptr().addr(),
        non_direct_small.as_ptr().addr(),
        medium.as_ptr().addr(),
        large.as_ptr().addr(),
        arena_singleton.as_ptr().addr(),
        os_singleton.as_ptr().addr(),
    ]
}

fn free_exact_post_exit_client(address: usize) {
    // SAFETY: the caller received this exact live C-shaped address before its
    // source owner exited. `native_free` must recover its PageMap/page state
    // from the pointer before considering the fresh releaser's identity.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "each fresh releaser frees only its exact post-exit client"
    );
}

#[test]
fn two_owner_exit_aggregates_free_through_pointer_page_state() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the two-owner post-exit witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner publishes the pair later owners need"
    );

    let (first_sender, first_receiver) = mpsc::sync_channel(0);
    let first_owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        first_sender
            .send(allocate_owner_exit_aggregate())
            .expect("A1 publishes only its C-shaped detached client inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A1 completes source owner exit with its live pages process-visible"
        );
    });
    let first = first_receiver
        .recv()
        .expect("the coordinator receives A1's exact live addresses before exit");
    first_owner
        .join()
        .expect("A1 completes its source owner-exit traversal");

    let (second_sender, second_receiver) = mpsc::sync_channel(0);
    let second_owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        second_sender
            .send(allocate_owner_exit_aggregate())
            .expect("A2 publishes only its C-shaped detached client inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A2 completes source owner exit beside A1's abandoned pages"
        );
    });
    let second = second_receiver
        .recv()
        .expect("the coordinator receives A2's exact live addresses before exit");
    second_owner
        .join()
        .expect("A2 completes its source owner-exit traversal");

    let both_attached = Arc::new(Barrier::new(3));
    let first_attached = Arc::clone(&both_attached);
    let second_attached = Arc::clone(&both_attached);
    let (turn_first_sender, turn_first_receiver) = mpsc::sync_channel(0);
    let (turn_second_sender, turn_second_receiver) = mpsc::sync_channel(0);
    let turn_first_from_second = turn_first_sender.clone();

    let first_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        first_attached.wait();
        for address in first {
            turn_first_receiver
                .recv()
                .expect("the first fresh releaser receives its next alternating turn");
            free_exact_post_exit_client(address);
            turn_second_sender
                .send(())
                .expect("the first fresh releaser passes the next turn to the second");
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the first releaser completes its own ordinary lifecycle after pointer-first frees"
        );
    });

    let second_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        second_attached.wait();
        for (index, address) in second.into_iter().enumerate() {
            turn_second_receiver
                .recv()
                .expect("the second fresh releaser receives its next alternating turn");
            free_exact_post_exit_client(address);
            if index + 1 != OWNER_EXIT_CLIENT_COUNT {
                turn_first_from_second
                    .send(())
                    .expect("the second fresh releaser passes the next turn to the first");
            }
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the second releaser completes its own ordinary lifecycle after pointer-first frees"
        );
    });

    both_attached.wait();
    turn_first_sender
        .send(())
        .expect("the coordinator starts the alternating pointer-first frees");
    first_releaser
        .join()
        .expect("the first releaser completes its alternating post-exit frees");
    second_releaser
        .join()
        .expect("the second releaser completes its alternating post-exit frees");
}
