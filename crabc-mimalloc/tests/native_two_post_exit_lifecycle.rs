use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
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
    // SAFETY: the caller received this exact C-shaped address from the owner
    // that published the typed detached route. The runtime still validates it
    // against the route's private ledger before it reaches source page state.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "each fresh B releases only one exact detached-route client"
    );
}

#[test]
fn two_detached_native_routes_park_independently_until_their_own_b_finish() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its bounded two-route witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before the detached owners begin"
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
            "A1 detaches into the first bounded post-exit route"
        );
    });
    let first = first_receiver
        .recv()
        .expect("the coordinator receives A1's exact addresses before exit");
    first_owner
        .join()
        .expect("A1 reaches its typed detached owner-exit boundary");

    let (second_sender, second_receiver) = mpsc::sync_channel(0);
    let second_owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        second_sender
            .send(allocate_owner_exit_aggregate())
            .expect("A2 publishes only its C-shaped detached client inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A2 parks beside A1 instead of retaining the process route"
        );
    });
    let second = second_receiver
        .recv()
        .expect("the coordinator receives A2's exact addresses before exit");
    second_owner
        .join()
        .expect("A2 reaches its separate typed detached owner-exit boundary");

    // Both A routes are source-active, so ticket zero may complete a private
    // operation beside their independent scheduler tokens. It cannot release
    // either route's worker-admission claim.
    let bookkeeping = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero runs only its private operation beside live detached routes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(bookkeeping) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its private client without changing either detached route"
    );

    let both_attached = Arc::new(Barrier::new(3));
    let first_attached = Arc::clone(&both_attached);
    let second_attached = Arc::clone(&both_attached);
    let (turn_first_sender, turn_first_receiver) = mpsc::sync_channel(0);
    let (turn_second_sender, turn_second_receiver) = mpsc::sync_channel(0);
    let turn_first_from_second = turn_first_sender.clone();
    let (first_terminal_sender, first_terminal_receiver) = mpsc::sync_channel(0);
    let (second_terminal_sender, second_terminal_receiver) = mpsc::sync_channel(0);
    let (release_first_sender, release_first_receiver) = mpsc::sync_channel(0);
    let (release_second_sender, release_second_receiver) = mpsc::sync_channel(0);

    let first_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        first_attached.wait();
        for address in first {
            turn_first_receiver
                .recv()
                .expect("A1's fresh B receives its next alternating turn");
            free_exact_native_route_client(address);
            turn_second_sender
                .send(())
                .expect("A1's fresh B passes the next turn to A2's B");
        }
        first_terminal_sender
            .send(())
            .expect("A1's fresh B reports its terminal source release");
        release_first_receiver
            .recv()
            .expect("the coordinator releases only A1's B finish first");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A1's B settles only A1's parked detached-route token"
        );
    });

    let second_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        second_attached.wait();
        for (index, address) in second.into_iter().enumerate() {
            turn_second_receiver
                .recv()
                .expect("A2's fresh B receives its next alternating turn");
            free_exact_native_route_client(address);
            if index + 1 != OWNER_EXIT_CLIENT_COUNT {
                turn_first_from_second
                    .send(())
                    .expect("A2's fresh B passes the next turn to A1's B");
            }
        }
        second_terminal_sender
            .send(())
            .expect("A2's fresh B reports its terminal source release");
        release_second_receiver
            .recv()
            .expect("the coordinator releases A2's B only after A1 finishes");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A2's B settles the final parked detached-route token"
        );
    });

    both_attached.wait();
    turn_first_sender
        .send(())
        .expect("the coordinator starts the alternating detached frees");
    first_terminal_receiver
        .recv()
        .expect("A1's B reaches its terminal route state");
    second_terminal_receiver
        .recv()
        .expect("A2's B reaches its terminal route state");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "ticket zero remains unavailable while both terminal B lifecycle proofs wait"
    );

    release_first_sender
        .send(())
        .expect("the coordinator releases A1's B lifecycle");
    first_releaser
        .join()
        .expect("A1's B completes without settling A2's route token");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "A2's parked route keeps ticket zero unavailable after A1's B completes"
    );

    release_second_sender
        .send(())
        .expect("the coordinator releases A2's B lifecycle");
    second_releaser
        .join()
        .expect("A2's B completes its final detached owner-exit lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates only after both detached routes finish"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
