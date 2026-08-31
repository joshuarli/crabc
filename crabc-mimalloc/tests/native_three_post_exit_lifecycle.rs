use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::{
    native_runtime_fork_admission_test_audit, native_runtime_lifecycle_test_audit,
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

fn free_exact_native_post_exit_client(address: usize) {
    // SAFETY: the exited owner supplied this exact C-shaped address while the
    // allocation was live. The generic pointer-first free recovers its PageMap
    // source state; no owner, registry, ledger, or release capability crosses to
    // this consumer.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "each fresh B frees its exact exited-owner client through page state"
    );
}

fn publish_exited_owner() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only its C-shaped post-exit client inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "each A completes generic collect-abandon before its clients are freed"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives every exact client before A exits");
    owner
        .join()
        .expect("the exited owner reaches its generic source-exit boundary");
    clients
}

fn assert_ticket_zero_roundtrip() {
    let block = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero's persistent initial owner remains independently usable")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(block) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its direct initial-owner client without affecting exited pages"
    );
}

#[test]
fn three_exited_native_owners_free_aggregates_through_page_state_in_non_fifo_order() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its three-owner page-state witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial owner prepares the immutable process pair before the exited owners begin"
    );

    #[cfg(feature = "native-runtime-test-audit")]
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared initial owner exposes a quiescent lifecycle audit");

    let first = publish_exited_owner();
    let second = publish_exited_owner();
    let third = publish_exited_owner();

    #[cfg(feature = "native-runtime-test-audit")]
    {
        let after_owner_exit = native_runtime_lifecycle_test_audit()
            .expect("exited owners leave a quiescent PageMap/abandonment audit");
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            0,
            "generic owner exit releases every A admission before any later free"
        );
        assert!(
            after_owner_exit.page_map_registered_entry_count > 0,
            "exited aggregates remain PageMap-visible for pointer-first free"
        );
        assert!(
            after_owner_exit.main_heap_abandoned_page_count > 0
                || after_owner_exit.main_heap_os_abandoned_pages_empty == 0,
            "exited aggregates remain owned by page/process abandonment state"
        );
        assert_eq!(
            after_owner_exit
                .native_scheduler_transition_count
                .saturating_sub(baseline.native_scheduler_transition_count),
            0,
            "generic owner exit does not enter the legacy page-owner scheduler"
        );
        assert_eq!(
            after_owner_exit
                .native_parked_compatibility_operation_count
                .saturating_sub(baseline.native_parked_compatibility_operation_count),
            0,
            "generic owner exit does not enter the parked compatibility bridge"
        );
    }

    assert_ticket_zero_roundtrip();

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
            free_exact_native_post_exit_client(address);
            if index + 1 != OWNER_EXIT_CLIENT_COUNT {
                second_turn_from_first
                    .send(())
                    .expect("A1's B passes the next turn to A2's B");
            }
        }
        first_terminal_sender
            .send(())
            .expect("A1's B reports that it consumed every post-exit client");
        release_first_receiver
            .recv()
            .expect("the coordinator releases A1's B after a distinct consumer finishes first");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A1's B finishes only its own independent attachment"
        );
    });

    let second_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        second_attached.wait();
        for address in second {
            second_turn_receiver
                .recv()
                .expect("A2's B receives its next non-FIFO release turn");
            free_exact_native_post_exit_client(address);
            third_turn_sender
                .send(())
                .expect("A2's B passes the next turn to A3's B");
        }
        second_terminal_sender
            .send(())
            .expect("A2's B reports that it consumed every post-exit client");
        release_second_receiver
            .recv()
            .expect("the coordinator releases A2's B last");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A2's B finishes its own independent attachment last"
        );
    });

    let third_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        third_attached.wait();
        for address in third {
            third_turn_receiver
                .recv()
                .expect("A3's B receives its next non-FIFO release turn");
            free_exact_native_post_exit_client(address);
            first_turn_from_third
                .send(())
                .expect("A3's B passes the next turn back to A1's B");
        }
        third_terminal_sender
            .send(())
            .expect("A3's B reports that it consumed every post-exit client");
        release_third_receiver
            .recv()
            .expect("the coordinator releases A3's B attachment first");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A3's B finishes only its own independent attachment"
        );
    });

    all_attached.wait();
    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        3,
        "only the three live B consumers hold later-thread admissions"
    );
    second_turn_sender
        .send(())
        .expect("the coordinator begins with A2 so release order is non-FIFO");
    first_terminal_receiver
        .recv()
        .expect("A1's B consumes its complete post-exit aggregate");
    second_terminal_receiver
        .recv()
        .expect("A2's B consumes its complete post-exit aggregate");
    third_terminal_receiver
        .recv()
        .expect("A3's B consumes its complete post-exit aggregate");
    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        3,
        "post-exit page frees do not keep any exited A admission pending on B"
    );
    assert_ticket_zero_roundtrip();

    release_third_sender
        .send(())
        .expect("the coordinator finishes A3's B first");
    third_releaser
        .join()
        .expect("A3's B completes independently of the first two consumers");
    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        2,
        "A3's B releases only its own later-thread admission"
    );
    assert_ticket_zero_roundtrip();

    release_first_sender
        .send(())
        .expect("the coordinator finishes A1's B second");
    first_releaser
        .join()
        .expect("A1's B completes independently of A2's remaining consumer");
    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        1,
        "A1's B releases only its own later-thread admission"
    );
    assert_ticket_zero_roundtrip();

    release_second_sender
        .send(())
        .expect("the coordinator finishes A2's B last");
    second_releaser
        .join()
        .expect("A2's B completes the final independent consumer lifecycle");

    #[cfg(feature = "native-runtime-test-audit")]
    {
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            0,
            "every B releases its own admission after its independent teardown"
        );
        let after = native_runtime_lifecycle_test_audit()
            .expect("all exited-owner clients leave a quiescent lifecycle audit");
        assert_eq!(after.process_active, 1);
        assert_eq!(
            after.page_map_registered_entry_count, 0,
            "every freed exited-owner client releases its PageMap registration"
        );
        assert_eq!(
            after.main_heap_abandoned_page_count, 0,
            "no regular abandoned page remains after every aggregate client is freed"
        );
        assert_eq!(
            after.main_heap_os_abandoned_pages_empty, 1,
            "no OS abandoned-page membership remains after every aggregate client is freed"
        );
        assert_eq!(
            after
                .native_scheduler_transition_count
                .saturating_sub(baseline.native_scheduler_transition_count),
            0,
            "page-state dispatch and independent B teardown never use the legacy scheduler"
        );
        assert_eq!(
            after
                .native_parked_compatibility_operation_count
                .saturating_sub(baseline.native_parked_compatibility_operation_count),
            0,
            "page-state dispatch and independent B teardown never use the parked compatibility bridge"
        );
    }
    assert_ticket_zero_roundtrip();
}
