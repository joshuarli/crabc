use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroOwnerExitFreeOutcome,
    TicketZeroOwnerExitFreeRoute, TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, TicketZeroRemoteFreeProducerPair,
    initialize_process,
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

fn publish_after_owner_exit<'owner>(
    producers: TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair<'owner>> {
    let (first, second) = producers.split();
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(move || first.publish())
                .join()
                .expect("the first mapped-medium publisher remains scoped to B's direct source free")
                .is_ok(),
            "the first mapped-medium client publishes before B resumes collection"
        );
    });
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(move || second.publish())
                .join()
                .expect("the second mapped-medium publisher remains scoped to B's direct source free")
                .is_ok(),
            "the second mapped-medium client appends before B resumes collection"
        );
    });
    Ok(())
}

fn free_owner_exit_route_with_joined_mapped_medium_publisher<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                route.free_remaining_in_fresh_runtime_worker_with_post_exit_mapped_medium_publisher(
                    publish_after_owner_exit,
                )
            })
            .join()
            .expect("the fresh post-exit consumer joins its mapped-medium publisher")
    })
}

#[test]
fn parked_session_collects_post_exit_mapped_medium_publications_before_terminal_release() {
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
            ticket_zero_later_thread_session_owner_exit_with_post_exit_mapped_medium_publisher_through_normal_finish(
                publish_before_owner_exit,
                free_owner_exit_route_with_joined_mapped_medium_publisher,
            )
        })
        .join()
        .expect("the parked source owner, fresh B, and scoped C publisher join"),
        TicketZeroLaterThreadPageResult::Completed,
        "B collects C's mapped-medium source publication before terminally releasing A's session route"
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
        "the completed mapped-medium session route leaves no admission or page-owner residue"
    );
}
