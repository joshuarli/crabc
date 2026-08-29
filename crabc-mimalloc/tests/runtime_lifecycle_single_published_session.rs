use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroPageAllocationResult,
    TicketZeroPageFreeResult, TicketZeroRemoteFreeProducer, initialize_process,
    ticket_zero_allocate, ticket_zero_free,
    ticket_zero_later_thread_single_source_published_session_through_normal_finish,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn publish_from_joined_worker<'owner>(
    producer: TicketZeroRemoteFreeProducer<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducer<'owner>> {
    std::thread::scope(|scope| {
        let publisher = scope.spawn(move || producer.publish());
        assert!(
            publisher
                .join()
                .expect("the publisher remains scoped to A's live session")
                .is_ok(),
            "the one source-published client reaches A's remote head"
        );
        Ok(())
    })
}

#[test]
fn one_source_published_parked_session_completes_through_the_source_all_free_drain() {
    assert!(
        initialize_process(current_page_size()),
        "this isolated test process initializes the private runtime"
    );
    let ticket_zero_client = match ticket_zero_allocate(37, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero initializes its dormant page owner before the worker session")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(ticket_zero_client) },
        TicketZeroPageFreeResult::Freed,
        "the ticket-zero setup returns its page owner to the ready scheduler state"
    );

    assert_eq!(
        std::thread::spawn(|| {
            ticket_zero_later_thread_single_source_published_session_through_normal_finish(
                publish_from_joined_worker,
            )
        })
        .join()
        .expect("the one-client source-published session worker joins"),
        TicketZeroLaterThreadPageResult::Completed,
        "normal finish force-collects the joined source remote head before it tears down A"
    );
    let resumed = match ticket_zero_allocate(41, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("the completed source-published session returns ticket zero to ready")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero remains usable after source collection and A's attachment teardown"
    );
}
