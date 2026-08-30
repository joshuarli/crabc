use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroOwnerExitFreeOutcome,
    TicketZeroOwnerExitFreeRoute, TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair,
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

fn mapped_medium_publisher_must_not_receive_direct_small_clients<'owner>(
    _: TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'owner>> {
    panic!("a mapped-medium publisher must not consume a direct-small source group")
}

fn reject_direct_small_route_with_mapped_medium_publisher<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                route.free_remaining_in_fresh_runtime_worker_with_post_exit_mapped_medium_publisher(
                    mapped_medium_publisher_must_not_receive_direct_small_clients,
                )
            })
            .join()
            .expect("the fresh B consumer rejects the mismatched publisher before invoking it")
    })
}

#[test]
fn direct_small_post_exit_group_rejects_a_mapped_medium_publisher() {
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
            ticket_zero_later_thread_session_owner_exit_with_post_exit_publisher_through_normal_finish(
                publish_before_owner_exit,
                reject_direct_small_route_with_mapped_medium_publisher,
            )
        })
        .join()
        .expect("the parked source owner and mismatched B consumer join"),
        TicketZeroLaterThreadPageResult::Retained,
        "a direct-small group cannot be consumed by the nominally distinct mapped-medium publisher"
    );
    assert!(
        matches!(
            ticket_zero_allocate(41, false),
            TicketZeroPageAllocationResult::Retained
        ),
        "the mismatched publisher leaves A's worker-admission claim retained instead of reopening ticket zero"
    );
}
