use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroPageAllocationResult,
    TicketZeroPageFreeResult, TicketZeroRemoteFreeProducerPair, initialize_process,
    ticket_zero_allocate, ticket_zero_free,
    ticket_zero_later_thread_source_published_session_through_normal_finish,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn publish_from_joined_workers<'owner>(
    producers: TicketZeroRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>> {
    let (first, second) = producers.split();
    std::thread::scope(|scope| {
        let first = scope.spawn(move || first.publish());
        let second = scope.spawn(move || second.publish());
        assert!(
            first
                .join()
                .expect("the first publisher remains scoped to A's live session")
                .is_ok(),
            "the first source-published client reaches A's remote head"
        );
        assert!(
            second
                .join()
                .expect("the second publisher remains scoped to A's live session")
                .is_ok(),
            "the second source-published client reaches A's remote head"
        );
        Ok(())
    })
}

#[test]
fn source_published_parked_session_completes_through_the_source_all_free_drain() {
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
            ticket_zero_later_thread_source_published_session_through_normal_finish(
                publish_from_joined_workers,
            )
        })
        .join()
        .expect("the source-published session worker joins"),
        TicketZeroLaterThreadPageResult::Completed,
        "normal finish force-collects the joined source remote heads before it tears down A"
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
