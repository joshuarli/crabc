use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free,
};

const OWNER_EXIT_CLIENT_COUNT: usize = 6;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_owner_exit_aggregate() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let direct_small = match native_allocate_aligned(37, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its direct-small native client"),
    };
    let non_direct_small = match native_allocate_aligned(1025, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its non-direct-small native client"),
    };
    let medium = match native_allocate_aligned(64 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its medium native client"),
    };
    let large = match native_allocate_aligned(128 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its regular-large native client"),
    };
    let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its arena-singleton native client"),
    };
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its OS-singleton native client"),
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

fn publish_detached_owner() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only its exact detached-route clients");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A moves its aggregate into one private detached route"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives every detached A client before A exits");
    owner
        .join()
        .expect("A reaches its typed native owner-exit boundary");
    clients
}

fn free_exact_native_route_client(address: usize) {
    // SAFETY: A supplied this exact C-shaped address before its detached route
    // entered the private dispatcher. The dispatcher validates it again
    // against that route's private ledger.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "B releases only an exact detached-route client"
    );
}

#[test]
fn completed_post_exit_route_does_not_block_b_live_remote_publication() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the completed-route publication witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before the two independent A routes begin"
    );

    let detached = publish_detached_owner();
    let (remote_sender, remote_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let live_owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("C creates one live exact source client"),
        };
        let local = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("C keeps one local client while B publishes its remote free"),
        };
        // SAFETY: both blocks remain in C's private ledger until C's later
        // all-free source finish. B receives only `remote`'s raw C address.
        unsafe {
            remote.as_ptr().write(0x61);
            remote.as_ptr().add(36).write(0x62);
            local.as_ptr().write(0x63);
            local.as_ptr().add(72).write(0x64);
        }
        remote_sender
            .send(remote.as_ptr().addr())
            .expect("B receives only C's exact live client");
        resume_receiver
            .recv()
            .expect("C waits until B has finished its own source teardown");
        // SAFETY: C's local client was never offered to either route. C's
        // all-free drain below force-collects B's already-published remote
        // client before C releases its pages.
        unsafe {
            assert_eq!(local.as_ptr().read(), 0x63);
            assert_eq!(local.as_ptr().add(72).read(), 0x64);
        }
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "C releases only its own local client before source collection"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "C's all-free finish collects B's publication and releases C's admission"
        );
    });
    let live_remote = remote_receiver
        .recv()
        .expect("C parks its live source session before B terminally frees A");

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            3,
            "A's detached route, C's live route, and B's attachment are all admitted"
        );
        let local = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes its independently parked local session"),
        };
        for address in detached {
            free_exact_native_route_client(address);
        }
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            3,
            "A's terminal completion remains admitted beside C and B"
        );

        // SAFETY: C supplied this exact live client and remains parked until
        // B completes the source-shaped remote publication. A's completion
        // carries no C client and may not freeze this independent B session.
        let live_remote = unsafe { core::ptr::NonNull::new_unchecked(live_remote as *mut u8) };
        assert_eq!(
            unsafe { native_free(live_remote) },
            NativePageFreeResult::Freed,
            "B publishes C's exact live client after A's completion is recorded"
        );
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "B frees its own local client before its source teardown"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes its own attachment before it settles A's completion"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "only C's still-live source route remains admitted after B settles A"
        );
    });
    releaser
        .join()
        .expect("B completes the completed-route and live-owner boundaries");

    resume_sender
        .send(())
        .expect("C may resume after B restored both source scheduler paths");
    live_owner
        .join()
        .expect("C collects B's publication and completes its own lifecycle");
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "every typed route admission releases only after its matching owner finishes"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes after the completed and live routes both finish"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
