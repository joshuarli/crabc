use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroOwnerExitFreeOutcome,
    TicketZeroOwnerExitFreeRoute, TicketZeroOwnerExitMappedMediumRemoteFreeProducerPair,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, TicketZeroRemoteFreeProducerPair,
    initialize_process,
    ticket_zero_later_thread_session_owner_exit_with_initial_mapped_medium_post_exit_publisher_through_normal_finish,
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
                .expect("the force-normalized medium publisher joins the parked session")
                .is_ok(),
            "the unrelated pre-exit medium source publication completes before A detaches"
        );
        assert!(
            large
                .join()
                .expect("the force-empty large publisher joins the parked session")
                .is_ok(),
            "the unrelated pre-exit large source publication completes before A detaches"
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
                .expect("the first initially-mapped medium publisher remains scoped to B's direct source free")
                .is_ok(),
            "the first initially-mapped medium client publishes before B resumes collection"
        );
    });
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(move || second.publish())
                .join()
                .expect("the second initially-mapped medium publisher remains scoped to B's direct source free")
                .is_ok(),
            "the second initially-mapped medium client appends before B resumes collection"
        );
    });
    Ok(())
}

fn free_owner_exit_route_with_joined_initial_mapped_medium_publisher<'owner>(
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
            .expect("the fresh post-exit consumer joins its initially-mapped medium publishers")
    })
}

#[test]
fn parked_session_collects_initially_mapped_medium_publications_before_terminal_release() {
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
            ticket_zero_later_thread_session_owner_exit_with_initial_mapped_medium_post_exit_publisher_through_normal_finish(
                publish_before_owner_exit,
                free_owner_exit_route_with_joined_initial_mapped_medium_publisher,
            )
        })
        .join()
        .expect("the parked source owner, fresh B, and scoped C/D publishers join"),
        TicketZeroLaterThreadPageResult::Completed,
        "B collects C/D's initially-mapped-medium source publications before terminally releasing A's session route"
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
        "the completed initially-mapped-medium session route leaves no admission or page-owner residue"
    );
}
