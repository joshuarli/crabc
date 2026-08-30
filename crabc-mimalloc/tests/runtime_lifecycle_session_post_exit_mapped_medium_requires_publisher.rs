use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroOwnerExitFreeOutcome,
    TicketZeroOwnerExitFreeRoute, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    TicketZeroRemoteFreeProducerPair, initialize_process,
    ticket_zero_later_thread_session_owner_exit_with_post_exit_mapped_medium_publisher_through_normal_finish,
    ticket_zero_allocate, ticket_zero_free,
};

fn publish_before_owner_exit<'owner>(
    producers: TicketZeroRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>> {
    let (medium, large) = producers.split();
    std::thread::scope(|scope| {
        let medium = scope.spawn(move || medium.publish());
        let large = scope.spawn(move || large.publish());
        assert!(
            medium
                .join()
                .expect("the pre-exit medium publisher joins the parked session")
                .is_ok(),
            "the session's full-medium client publishes before A detaches"
        );
        assert!(
            large
                .join()
                .expect("the pre-exit large publisher joins the parked session")
                .is_ok(),
            "the session's force-empty large client publishes before A detaches"
        );
    });
    Ok(())
}

fn reject_owner_exit_route_without_typed_publisher<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || route.free_remaining_in_fresh_runtime_worker())
            .join()
            .expect("the fresh ordinary consumer joins after refusing the bounded source group")
    })
}

#[test]
fn mapped_medium_post_exit_group_rejects_an_ordinary_no_publisher_finish() {
    assert!(
        initialize_process(4096),
        "the ticket-zero owner initializes before the parked session"
    );
    let warm = match ticket_zero_allocate(37, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero initializes its dormant page owner before the session")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(warm) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero is dormant before the A/B source route"
    );

    assert_eq!(
        std::thread::spawn(|| {
            ticket_zero_later_thread_session_owner_exit_with_post_exit_mapped_medium_publisher_through_normal_finish(
                publish_before_owner_exit,
                reject_owner_exit_route_without_typed_publisher,
            )
        })
        .join()
        .expect("the parked source owner and ordinary B consumer join"),
        TicketZeroLaterThreadPageResult::Retained,
        "a prepared mapped-medium B/C/D group cannot fall through to B's ordinary no-page finalizer"
    );
    assert!(
        matches!(
            ticket_zero_allocate(41, false),
            TicketZeroPageAllocationResult::Retained
        ),
        "the missing typed publisher keeps A's worker-admission claim retained instead of reopening ticket zero"
    );
}
