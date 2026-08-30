use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
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
            .expect("A publishes only the exact C-shaped detached clients");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A publishes one independently typed detached owner-exit route"
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
        "each fresh B releases only its exact detached-route client"
    );
}

fn release_detached_owner(clients: [usize; OWNER_EXIT_CLIENT_COUNT]) {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        for address in clients {
            free_exact_native_route_client(address);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the fresh B settles only its own detached owner-exit completion"
        );
    })
    .join()
    .expect("the detached route consumer completes its no-page lifecycle");
}

#[test]
fn registry_reuses_terminal_route_storage_without_releasing_pending_b_admission() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its registry-reuse lifecycle witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before detached owners begin"
    );

    let first = publish_detached_owner();
    let second = publish_detached_owner();

    let (first_terminal_sender, first_terminal_receiver) = mpsc::sync_channel(0);
    let (finish_first_sender, finish_first_receiver) = mpsc::sync_channel(0);
    let first_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        for address in first {
            free_exact_native_route_client(address);
        }
        first_terminal_sender
            .send(())
            .expect("B1 reports its terminal route release before it finishes");
        finish_first_receiver
            .recv()
            .expect("the coordinator delays B1's no-page lifecycle completion");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B1 releases A1's admission only through its own normal finish"
        );
    });

    first_terminal_receiver
        .recv()
        .expect("B1 reaches its route-terminal, pre-finish state");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "A1's terminal route completion still keeps ticket zero unavailable in B1 TLS"
    );

    // B1's terminal free made only A1's registry entry empty. Its parked
    // scheduler token and A1 admission stay in B1 TLS, while A2 remains a
    // live sibling route. A3 must be able to publish beside A2 without using
    // B1's normal no-page finalizer or reopening ticket zero.
    let third = publish_detached_owner();
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "publishing A3 beside the pending B1 completion does not reopen ticket zero"
    );

    release_detached_owner(second);
    release_detached_owner(third);
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "B1's delayed completion remains the final parked token after A2 and A3 finish"
    );

    finish_first_sender
        .send(())
        .expect("the coordinator releases B1's required no-page finish");
    first_releaser
        .join()
        .expect("B1 completes the final delayed detached owner-exit lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates only after B1 finishes its held completion"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
