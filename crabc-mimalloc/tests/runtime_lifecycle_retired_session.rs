use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroOwnerExitFreeOutcome,
    TicketZeroOwnerExitFreeRoute, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    initialize_process, ticket_zero_allocate, ticket_zero_free,
    ticket_zero_later_thread_retired_then_live_session_owner_exit_through_normal_finish,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn free_owner_exit_route_in_fresh_runtime_worker<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || route.free_remaining_in_fresh_runtime_worker())
            .join()
            .expect("the fresh post-exit consumer joins the retired-page source owner")
    })
}

#[test]
fn retired_page_prepass_precedes_live_session_route_and_terminal_admission_release() {
    assert!(
        initialize_process(current_page_size()),
        "this isolated test process initializes the private runtime"
    );
    let ticket_zero_client = match ticket_zero_allocate(37, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero establishes the ready scheduler state")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(ticket_zero_client) },
        TicketZeroPageFreeResult::Freed,
        "the ticket-zero setup returns its page owner to the ready scheduler state"
    );

    assert_eq!(
        std::thread::spawn(|| {
            ticket_zero_later_thread_retired_then_live_session_owner_exit_through_normal_finish(
                free_owner_exit_route_in_fresh_runtime_worker,
            )
        })
        .join()
        .expect("the retired-page source owner and fresh route consumer join"),
        TicketZeroLaterThreadPageResult::Completed,
        "normal finish releases the retired source page before B terminally frees the live route"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero reactivates after the retired-page owner exit")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the completed A/B lifecycle leaves the native process pair ready"
    );
}
