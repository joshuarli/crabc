use std::sync::{Arc, Barrier, mpsc};

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

fn free_exact_native_route_client(address: usize) {
    // SAFETY: the owner supplied this exact C-shaped address before its typed
    // detached route entered the private dispatcher. The dispatcher still
    // validates the address against the selected route's ledger.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "each fresh B releases only its exact detached-route client"
    );
}

fn publish_detached_owner() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only its C-shaped detached client inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "each A publishes one independently live detached owner-exit route"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives every exact route client before A exits");
    owner
        .join()
        .expect("the detached owner reaches its typed source-exit boundary");
    clients
}

#[test]
fn three_detached_native_routes_release_independently_in_non_fifo_order() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its three-owner lifecycle witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before the detached owners begin"
    );

    let first = publish_detached_owner();
    let second = publish_detached_owner();
    let third = publish_detached_owner();

    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "three independently parked detached-route tokens keep ticket zero unavailable"
    );

    let all_attached = Arc::new(Barrier::new(4));
    let first_attached = Arc::clone(&all_attached);
    let second_attached = Arc::clone(&all_attached);
    let third_attached = Arc::clone(&all_attached);
    let (first_turn_sender, first_turn_receiver) = mpsc::sync_channel(0);
    let (second_turn_sender, second_turn_receiver) = mpsc::sync_channel(0);
    let (third_turn_sender, third_turn_receiver) = mpsc::sync_channel(0);
    let second_turn_from_first = second_turn_sender.clone();
    let first_turn_from_third = first_turn_sender.clone();
    let (first_terminal_sender, first_terminal_receiver) = mpsc::sync_channel(0);
    let (second_terminal_sender, second_terminal_receiver) = mpsc::sync_channel(0);
    let (third_terminal_sender, third_terminal_receiver) = mpsc::sync_channel(0);
    let (release_first_sender, release_first_receiver) = mpsc::sync_channel(0);
    let (release_second_sender, release_second_receiver) = mpsc::sync_channel(0);
    let (release_third_sender, release_third_receiver) = mpsc::sync_channel(0);

    let first_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        first_attached.wait();
        for (index, address) in first.into_iter().enumerate() {
            first_turn_receiver
                .recv()
                .expect("A1's B receives its next non-FIFO release turn");
            free_exact_native_route_client(address);
            if index + 1 != OWNER_EXIT_CLIENT_COUNT {
                second_turn_from_first
                    .send(())
                    .expect("A1's B passes the next turn to A2's B");
            }
        }
        first_terminal_sender
            .send(())
            .expect("A1's B reports its terminal source release");
        release_first_receiver
            .recv()
            .expect("the coordinator releases A1's B after a distinct route finishes first");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A1's B settles only A1's own parked detached-route token"
        );
    });

    let second_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        second_attached.wait();
        for (index, address) in second.into_iter().enumerate() {
            second_turn_receiver
                .recv()
                .expect("A2's B receives its next non-FIFO release turn");
            free_exact_native_route_client(address);
            third_turn_sender
                .send(())
                .expect("A2's B passes the next turn to A3's B");
        }
        second_terminal_sender
            .send(())
            .expect("A2's B reports its terminal source release");
        release_second_receiver
            .recv()
            .expect("the coordinator releases A2's B last");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A2's B settles the final independently parked detached-route token"
        );
    });

    let third_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        third_attached.wait();
        for address in third {
            third_turn_receiver
                .recv()
                .expect("A3's B receives its next non-FIFO release turn");
            free_exact_native_route_client(address);
            first_turn_from_third
                .send(())
                .expect("A3's B passes the next turn back to A1's B");
        }
        third_terminal_sender
            .send(())
            .expect("A3's B reports its terminal source release");
        release_third_receiver
            .recv()
            .expect("the coordinator releases A3's B first");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A3's B settles only A3's own parked detached-route token"
        );
    });

    all_attached.wait();
    second_turn_sender
        .send(())
        .expect("the coordinator begins with A2 so release order is non-FIFO");
    first_terminal_receiver
        .recv()
        .expect("A1's B reaches its terminal route state");
    second_terminal_receiver
        .recv()
        .expect("A2's B reaches its terminal route state");
    third_terminal_receiver
        .recv()
        .expect("A3's B reaches its terminal route state");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "ticket zero remains unavailable while all three terminal B lifecycle proofs wait"
    );

    release_third_sender
        .send(())
        .expect("the coordinator finishes A3's B first");
    third_releaser
        .join()
        .expect("A3's B completes without settling the first two routes");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "two independently parked route tokens keep ticket zero unavailable after A3 finishes"
    );

    release_first_sender
        .send(())
        .expect("the coordinator finishes A1's B second");
    first_releaser
        .join()
        .expect("A1's B completes without settling A2's remaining route");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "A2's independently parked route keeps ticket zero unavailable after A1 finishes"
    );

    release_second_sender
        .send(())
        .expect("the coordinator finishes A2's B last");
    second_releaser
        .join()
        .expect("A2's B completes the final detached owner-exit lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates only after every detached route finishes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
