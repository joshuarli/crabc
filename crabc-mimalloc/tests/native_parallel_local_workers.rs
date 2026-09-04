use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, native_usable_size,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn native_shadow_keeps_a_second_parked_worker_local_while_a_live_route_is_occupied() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before independent local workers park"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before either native worker starts"
    );

    let (owner_ready_sender, owner_ready_receiver) = mpsc::sync_channel(0);
    let (owner_release_sender, owner_release_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let block = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the one parked live-owner publication"),
        };
        owner_ready_sender
            .send(())
            .expect("B begins only after A has parked its native route");
        owner_release_receiver
            .recv()
            .expect("A stays parked while B completes its local-only lifecycle");

        // SAFETY: this exact block remains local to A; B never receives its
        // address or a route capability in this local-only witness.
        let freed = unsafe { native_free(block) };
        let finished = finish_current_thread_native_after_user_destructors();
        (freed, finished)
    });

    owner_ready_receiver
        .recv()
        .expect("A publishes its one live route before B attaches");
    let (worker_sender, worker_receiver) = mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let result = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => {
                // SAFETY: B's pointer remains in B's private native ledger.
                unsafe {
                    block.as_ptr().write(0x71);
                    block.as_ptr().add(72).write(0x72);
                    assert_eq!(block.as_ptr().read(), 0x71);
                    assert_eq!(block.as_ptr().add(72).read(), 0x72);
                }
                assert!(
                    unsafe { native_usable_size(block) }.is_some_and(|size| size >= 73),
                    "B's local-only session still owns its exact usable-size query"
                );
                let freed = unsafe { native_free(block) };
                let finished = finish_current_thread_native_after_user_destructors();
                Some((freed, finished))
            }
            _ => None,
        };
        worker_sender
            .send(result)
            .expect("the coordinator observes whether B remained local-only");
    });

    let worker_result = worker_receiver
        .recv()
        .expect("B reports its local-only lifecycle result");
    owner_release_sender
        .send(())
        .expect("A resumes only after B has completed its local lifecycle");
    worker
        .join()
        .expect("B exits after its local-only native lifecycle");
    let owner_result = owner
        .join()
        .expect("A exits after B has released its independent parked engine");

    assert_eq!(
        worker_result,
        Some((NativePageFreeResult::Freed, ThreadFinishResult::Finished)),
        "a second parked worker remains local-only instead of retaining when A owns the one live route"
    );
    assert_eq!(
        owner_result,
        (NativePageFreeResult::Freed, ThreadFinishResult::Finished),
        "A's original live route remains valid after B's independent local lifecycle"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after both independently parked workers finish"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the dormant ticket-zero pair receives its local client after both workers leave"
    );
}
