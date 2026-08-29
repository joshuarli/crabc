use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroOwnerExitFreeOutcome,
    TicketZeroOwnerExitFreeRoute, TicketZeroOwnerExitRemoteFreeProducer,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, TicketZeroRemoteFreeProducerPair,
    initialize_process,
    ticket_zero_later_thread_session_owner_exit_with_post_exit_publisher_through_normal_finish,
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

fn publish_after_owner_exit<'owner>(
    producer: TicketZeroOwnerExitRemoteFreeProducer<'owner>,
) -> Result<(), TicketZeroOwnerExitRemoteFreeProducer<'owner>> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || producer.publish())
            .join()
            .expect("the post-exit publisher remains scoped to B's direct source free")
    })
}

fn free_owner_exit_route_with_joined_post_exit_publisher<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                route.free_remaining_in_fresh_runtime_worker_with_post_exit_publisher(
                    publish_after_owner_exit,
                )
            })
            .join()
            .expect("the fresh post-exit consumer joins its scoped publisher")
    })
}

#[test]
fn parked_session_keeps_scoped_post_exit_publication_inside_the_typed_route() {
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
        "ticket zero is dormant before the A/B/C source route"
    );

    assert_eq!(
        std::thread::spawn(|| {
            ticket_zero_later_thread_session_owner_exit_with_post_exit_publisher_through_normal_finish(
                publish_before_owner_exit,
                free_owner_exit_route_with_joined_post_exit_publisher,
            )
        })
        .join()
        .expect("the parked source owner, fresh B, and scoped C publisher join"),
        TicketZeroLaterThreadPageResult::Completed,
        "B collects C's private source publication before terminally releasing A's session route"
    );

    let resumed = match ticket_zero_allocate(41, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("the terminal typed route returns ticket zero to ready")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the completed session A/B/C route leaves no admission or page-owner residue"
    );
}
