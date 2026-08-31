use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, native_runtime_test_fail_next_unmap,
    prepare_native_later_thread_arena, ticket_zero_allocate,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Allocates a source-shaped mixed exit image, but returns only its
/// OS-aligned client. The other live members make A follow normal
/// collect-abandon before B supplies the exact client to PageMap dispatch.
fn allocate_mixed_owner_exit_aggregate() -> usize {
    for (request, alignment, name) in [
        (37, 16, "direct-small"),
        (1025, 16, "non-direct-small"),
        (64 * 1024, 16, "medium"),
        (128 * 1024, 16, "large"),
        (1024 * 1024, 16, "arena singleton"),
    ] {
        assert!(
            matches!(
                native_allocate_aligned(request, alignment, false),
                NativePageAllocationResult::Allocated(_)
            ),
            "A allocates the mixed aggregate's {name} member"
        );
    }
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates the mixed aggregate's OS-aligned singleton"),
    };
    assert_eq!(
        os_singleton.as_ptr().addr() % (128 * 1024),
        0,
        "the exact source client reaches the OS-backed terminal-release path"
    );
    os_singleton.as_ptr().addr()
}

#[test]
fn native_post_exit_failed_os_release_is_terminal_without_retaining_worker_admission() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the failed-OS-release witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before A borrows the dormant pair"
    );

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        owner_sender
            .send(allocate_mixed_owner_exit_aggregate())
            .expect("A gives B only the exact OS client before owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A's persistent owner completes collect-abandon before B's pointer free"
        );
    });
    let os_singleton = owner_receiver
        .recv()
        .expect("the coordinator receives B's one exact source client");
    owner
        .join()
        .expect("A completes the source Theap/TLD teardown before B starts");
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A's persistent owner releases its worker admission at the owner-exit boundary"
    );

    let consumer = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "B owns the one current worker admission before its foreign pointer free"
        );
        // SAFETY: A supplied this exact still-live OS-aligned client before
        // its source owner exited. B has no owner or release capability for
        // this address; `native_free` must begin with the PageMap lookup.
        let os_singleton = unsafe { core::ptr::NonNull::new_unchecked(os_singleton as *mut u8) };
        let unmap_failure = native_runtime_test_fail_next_unmap();
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Retained,
            "the failed PageMap-derived source release stays fail-closed"
        );
        assert_eq!(
            unmap_failure.observed(),
            1,
            "B attempts exactly the one injected terminal source unmap"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "the retained source does not manufacture a second worker admission"
        );
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Retained,
            "the retained source cannot be reopened into a retry path"
        );
        let finish = finish_current_thread_native_after_user_destructors();
        (unmap_failure.observed(), finish)
    });
    let (unmap_attempts, consumer_finish) = consumer
        .join()
        .expect("B finishes independently of A's terminal retained source");
    assert_eq!(
        unmap_attempts,
        1,
        "neither the repeated pointer free nor B's teardown retries the failed terminal unmap"
    );
    assert_eq!(
        consumer_finish,
        ThreadFinishResult::Finished,
        "A's retained PageMap source does not retain B's independent owner"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's finish releases its own admission without reconstructing A's"
    );

    assert!(
        matches!(
            ticket_zero_allocate(73, false),
            TicketZeroPageAllocationResult::Retained
        ),
        "the failed PageMap source closes the process owner instead of reporting an old scheduler miss"
    );
}
