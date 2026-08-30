use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_post_exit_registry_test_audit,
    native_reallocate, native_runtime_fork_admission_test_audit, prepare_native_later_thread_arena,
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

fn publish_detached_owner() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only its exact C-shaped detached clients");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A moves its aggregate into one independently typed detached route"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives every exact route client before A exits");
    owner
        .join()
        .expect("the owner reaches its typed source-exit boundary");
    clients
}

fn free_exact_native_route_client(address: usize) {
    // SAFETY: the owner supplied this exact C-shaped address before its typed
    // detached route entered the private dispatcher. The dispatcher validates
    // it again against that route's private ledger.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "B releases only an exact detached-route client"
    );
}

#[test]
fn one_b_finishes_multiple_terminal_post_exit_routes_after_its_own_teardown() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the multiple-completion witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before detached owners begin"
    );

    let first = publish_detached_owner();
    let second = publish_detached_owner();
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        2,
        "both detached A routes retain their worker-admission claims"
    );

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            3,
            "B attaches beside both detached source routes"
        );

        let local = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes one independently parked local session"),
        };
        // SAFETY: `local` stays in B's private ledger until the local
        // replacement below. The sentinels prove that a completed A route
        // cannot redirect B's ordinary local `realloc`.
        unsafe {
            local.as_ptr().write(0x51);
            local.as_ptr().add(52).write(0x52);
        }

        for address in first {
            free_exact_native_route_client(address);
        }
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            3,
            "the first terminal A completion remains admitted until B finishes"
        );
        assert_eq!(
            native_post_exit_registry_test_audit().live_entry_count,
            2,
            "the completed first route remains represented beside the live second route"
        );
        let continued_after_first = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes its own parked session for an ordinary local allocation after the first completion"
            ),
        };
        assert_eq!(
            unsafe { native_free(continued_after_first) },
            NativePageFreeResult::Freed,
            "the continued first-completion allocation returns through B's private ledger"
        );
        let local = match unsafe { native_reallocate(Some(local), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes its own parked session for a local replacement after the first completion"
            ),
        };
        assert_eq!(
            unsafe { local.as_ptr().read() },
            0x51,
            "the first-completion local replacement preserves B's first sentinel"
        );
        assert_eq!(
            unsafe { local.as_ptr().add(52).read() },
            0x52,
            "the first-completion local replacement preserves B's second sentinel"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            3,
            "resuming B's local session leaves both A admission proofs pending"
        );

        for address in second {
            free_exact_native_route_client(address);
        }
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            3,
            "both terminal A completions remain admitted before B's teardown"
        );
        assert_eq!(
            native_post_exit_registry_test_audit().live_entry_count,
            2,
            "both completed routes stay private and non-reusable until B finishes"
        );
        assert!(
            matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
            "ticket zero cannot reopen while B still owes either typed route completion"
        );
        let continued_after_second = match native_allocate_aligned(97, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes its own parked session after the second completed route as well"
            ),
        };
        assert_eq!(
            unsafe { native_free(continued_after_second) },
            NativePageFreeResult::Freed,
            "the second-completion local allocation returns through B's private ledger"
        );
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "B may discharge its continued local replacement before its own source finish"
        );

        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B tears down its own attachment before releasing either A admission"
        );
    });
    releaser
        .join()
        .expect("B completes both terminal detached-route lifecycles");

    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's successful finish releases both A claims and its own admission"
    );
    let registry = native_post_exit_registry_test_audit();
    assert_eq!(
        registry.live_entry_count, 0,
        "no completed route remains live after B's ordinary finish"
    );
    assert_eq!(
        registry.retained_entry_count, 0,
        "the successful multi-completion path leaves no terminal entry"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates only after B finishes every typed completion"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
