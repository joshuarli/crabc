use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, TicketZeroRemoteFreeProducer,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_free, native_test_prepare_source_published_live_owner_exit,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn publish_from_joined_worker<'owner>(
    producer: TicketZeroRemoteFreeProducer<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducer<'owner>> {
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(move || producer.publish())
                .join()
                .expect("the source publisher stays scoped to A's live session")
                .is_ok(),
            "the direct-small client reaches A's source remote head before owner exit"
        );
        Ok(())
    })
}

#[test]
fn joined_source_publication_stays_with_a_when_live_native_client_exits() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the mixed source-publication exit"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before A owns its native session"
    );

    let (live_sender, live_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let live = match native_test_prepare_source_published_live_owner_exit(
            publish_from_joined_worker,
        ) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("A constructs the joined-source plus live-native owner image")
            }
        };
        live_sender
            .send(live.as_ptr().addr())
            .expect("B receives only the surviving C-shaped medium address");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A force-collects its joined source publication before it detaches the live sibling"
        );
    });
    let live = live_receiver
        .recv()
        .expect("the coordinator receives A's one surviving client before A exits");
    owner
        .join()
        .expect("A reaches the typed native post-exit route");

    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "A's detached live sibling keeps ticket zero unavailable after source collection"
    );

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: A supplied exactly its still-live medium client before the
        // typed route detached. The joined direct-small publication never
        // enters this route and was consumed by A's source collector.
        let live = unsafe { core::ptr::NonNull::new_unchecked(live as *mut u8) };
        assert_eq!(
            unsafe { native_free(live) },
            NativePageFreeResult::Freed,
            "B terminally releases only A's live typed-route client"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B's own finish releases A's worker admission after the route terminally completes"
        );
    });
    releaser
        .join()
        .expect("B completes the typed terminal lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero resumes only after B releases A's terminal admission")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
