use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_post_exit_registry_test_audit, native_runtime_fork_admission_test_audit,
    native_runtime_test_fail_next_unmap, prepare_native_later_thread_arena, ticket_zero_allocate,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Allocates the existing mixed aggregate, but returns only its OS-aligned
/// client. The other live members ensure A uses the source-shaped aggregate
/// traversal rather than a singleton-specific owner-exit route; B receives no
/// address other than the exact client that reaches the injected release.
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
fn native_post_exit_failed_os_release_stays_terminal_and_keeps_a_admission() {
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
            "A detaches the mixed aggregate into one opaque native route"
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
        1,
        "A's detached route retains its one worker-admission claim after old-Theap teardown"
    );

    let consumer = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "B's ordinary attachment adds its own claim without consuming A's detached-route claim"
        );
        // SAFETY: A supplied this exact still-live OS-aligned client before
        // its typed aggregate route detached. The test never gains a route,
        // client ledger, PageMap, or scheduler capability from that address.
        let os_singleton = unsafe { core::ptr::NonNull::new_unchecked(os_singleton as *mut u8) };
        let unmap_failure = native_runtime_test_fail_next_unmap();
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Retained,
            "the failed source mapping release retains the opaque post-exit route"
        );
        assert_eq!(
            unmap_failure.observed(),
            1,
            "B attempts exactly the one injected source terminal unmap"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "a failed terminal release cannot consume either A's route claim or B's live attachment claim"
        );
        drop(unmap_failure);
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Retained,
            "clearing injection cannot turn a terminally retained route into a retry path"
        );
        let audit = native_post_exit_registry_test_audit();
        assert_eq!(
            audit.published_entry_count, 1,
            "the failed route remains represented by its one stable registry node"
        );
        assert_eq!(
            audit.live_entry_count, 0,
            "the failed route cannot masquerade as a live retryable entry"
        );
        assert_eq!(
            audit.retained_entry_count, 1,
            "the native registry keeps the failed OS release terminally visible"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B can complete only its own no-page lifecycle; A's retained route remains parked"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "B's ordinary finish releases only B while A's retained route keeps its worker admission"
        );
    });
    consumer
        .join()
        .expect("B completes without manufacturing a terminal route proof");

    let audit = native_post_exit_registry_test_audit();
    assert_eq!(audit.live_entry_count, 0);
    assert_eq!(audit.retained_entry_count, 1);
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "A's retained route keeps the dormant pair unavailable after B has finished"
    );
}
