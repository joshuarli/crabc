use std::sync::{Arc, Barrier, OnceLock};

use crabc_mimalloc::__crabc_runtime::{
    ThreadAttachResult, ThreadFinishResult, TicketZeroLaterThreadPageResult,
    TicketZeroOwnerExitFreeOutcome, TicketZeroOwnerExitFreeRoute,
    TicketZeroOwnerExitReclaimOutcome, TicketZeroOwnerExitReclaimRoute,
    TicketZeroOwnerExitRemoteFreeProducerPair,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    TicketZeroRemoteFreeProducerPair, after_fork_child, after_fork_parent,
    attach_current_thread, before_fork, finish_current_thread_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, native_reallocate,
    native_usable_size, prepare_native_later_thread_arena, process_is_active, ticket_zero_allocate,
    ticket_zero_allocate_aligned, ticket_zero_free, ticket_zero_usable_size,
    ticket_zero_later_thread_active_session_rejects_normal_finish,
    ticket_zero_later_thread_all_free_session_through_normal_finish,
    ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish,
    ticket_zero_later_thread_mapped_regular_owner_exit_through_normal_finish,
    ticket_zero_later_thread_mapped_regular_owner_exit_reclaim_through_normal_finish,
    ticket_zero_later_thread_session_owner_exit_through_normal_finish,
    ticket_zero_later_thread_session_owner_exit_with_post_exit_publisher_through_normal_finish,
    ticket_zero_later_thread_persistent_local_workload,
    ticket_zero_later_thread_remote_free_roundtrip,
};

// Linux's raw wait4 ABI uses bit zero for WNOHANG. This direct regression
// owns the process-isolated timeout rather than depending on libc state in a
// child whose runtime behavior is the subject under test.
const WNOHANG: u32 = 1;

// The owner-exit callback is a higher-ranked function pointer so it cannot
// capture a test-local barrier. This one-shot integration-test rendezvous
// stops A after it has transferred the opaque post-exit route, but before B
// can terminally release it. It makes the admission lifetime observable
// without exposing one of the route's private client addresses.
static OWNER_EXIT_ROUTE_HOLD: OnceLock<(Arc<Barrier>, Arc<Barrier>)> = OnceLock::new();

// The direct-small route has a distinct A-side source drain, but it must obey
// the same post-exit admission rule as the aggregate route. Pause B after A
// has transferred that opaque route so the test can observe the shared
// terminal-proof boundary without exposing an A client address.
static DIRECT_SMALL_RECLAIM_ROUTE_HOLD: OnceLock<(Arc<Barrier>, Arc<Barrier>)> = OnceLock::new();

// This is an evidence schedule, not allocator randomness. It deliberately
// matches the fixed C fixture's LCG so a failing lifecycle order is stable and
// recorded in the test source. The schedule remains serial at its C/Rust
// caller boundary: each item owns one fresh worker A, while the existing
// pointer-private routes create only their scoped B/C participants.
const SEEDED_LIFECYCLE_STRESS_SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const SEEDED_LIFECYCLE_STRESS_EPOCHS: usize = 8;

#[derive(Clone, Copy, Debug)]
enum SeededLifecycleRoute {
    PersistentLocal,
    LiveOwnerRemoteFree,
    AllFreeParkedTlsSession,
    MixedOwnerExit,
    ParkedTlsSessionOwnerExit,
    ParkedTlsSessionOwnerExitWithPostExitPublisher,
    MediumReclaim,
    DirectSmallReclaim,
}

fn next_seeded_lifecycle_schedule(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn run_seeded_lifecycle_route(route: SeededLifecycleRoute) -> TicketZeroLaterThreadPageResult {
    std::thread::spawn(move || match route {
        SeededLifecycleRoute::PersistentLocal => ticket_zero_later_thread_persistent_local_workload(),
        SeededLifecycleRoute::LiveOwnerRemoteFree => {
            ticket_zero_later_thread_remote_free_roundtrip(publish_owner_exit_remote_frees)
        }
        SeededLifecycleRoute::AllFreeParkedTlsSession => {
            ticket_zero_later_thread_all_free_session_through_normal_finish()
        }
        SeededLifecycleRoute::MixedOwnerExit => {
            ticket_zero_later_thread_mapped_regular_owner_exit_through_normal_finish(
                publish_owner_exit_remote_frees,
                free_owner_exit_route_with_joined_post_exit_remote_free,
            )
        }
        SeededLifecycleRoute::ParkedTlsSessionOwnerExit => {
            ticket_zero_later_thread_session_owner_exit_through_normal_finish(
                publish_owner_exit_remote_frees,
                free_owner_exit_route_in_fresh_runtime_worker,
            )
        }
        SeededLifecycleRoute::ParkedTlsSessionOwnerExitWithPostExitPublisher => {
            ticket_zero_later_thread_session_owner_exit_with_post_exit_publisher_through_normal_finish(
                publish_owner_exit_remote_frees,
                free_owner_exit_route_with_joined_post_exit_remote_free,
            )
        }
        SeededLifecycleRoute::MediumReclaim => {
            ticket_zero_later_thread_mapped_regular_owner_exit_reclaim_through_normal_finish(
                reclaim_owner_exit_route_in_fresh_runtime_worker,
            )
        }
        SeededLifecycleRoute::DirectSmallReclaim => {
            ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish(
                reclaim_owner_exit_route_in_fresh_runtime_worker,
            )
        }
    })
    .join()
    .expect("each deterministic lifecycle worker joins")
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn wait_for_clean_child(pid: i32) {
    let mut status = 0;
    for _ in 0..500 {
        let waited = unsafe {
            crabc_core::process::wait4_raw(pid, &mut status, WNOHANG)
                .expect("the parent polls the fork-lifecycle child")
        };
        if waited == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        assert_eq!(waited, pid, "wait4 returns the exact child");
        assert_eq!(status, 0, "the child completes its private lifecycle proof");
        return;
    }
    let _ = crabc_core::process::kill(pid, 9);
    let _ = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 0) };
    panic!("the fork-lifecycle child exceeded its five-second deadline");
}

fn fork_quiescent_runtime_child() -> ! {
    after_fork_child(true);
    if !process_is_active() {
        crabc_core::process::exit_immediately(101);
    }

    let worker = std::thread::spawn(|| {
        attach_current_thread() == ThreadAttachResult::Attached
            && finish_current_thread_after_user_destructors() == ThreadFinishResult::Finished
    });
    if !matches!(worker.join(), Ok(true)) {
        crabc_core::process::exit_immediately(102);
    }
    crabc_core::process::exit_immediately(0);
}

fn fork_live_runtime_child() -> ! {
    after_fork_child(true);
    if process_is_active() || attach_current_thread() != ThreadAttachResult::Inactive {
        crabc_core::process::exit_immediately(103);
    }
    crabc_core::process::exit_immediately(0);
}

fn fork_unprepared_runtime_child() -> ! {
    after_fork_child(false);
    if process_is_active() || attach_current_thread() != ThreadAttachResult::Inactive {
        crabc_core::process::exit_immediately(104);
    }
    crabc_core::process::exit_immediately(0);
}

fn publish_owner_exit_remote_frees<'owner>(
    producers: TicketZeroRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>> {
    let (medium, large) = producers.split();
    std::thread::scope(|scope| {
        let medium = scope.spawn(move || medium.publish());
        let large = scope.spawn(move || large.publish());
        assert!(
            medium
                .join()
                .expect("the medium publisher joins the owner-exit source")
                .is_ok(),
            "the full-medium remote client publishes before A begins owner exit"
        );
        assert!(
            large
                .join()
                .expect("the large publisher joins the owner-exit source")
                .is_ok(),
            "the force-empty large remote client publishes before A begins owner exit"
        );
    });
    Ok(())
}

fn publish_owner_exit_remote_free_from_scoped_test_threads<'owner>(
    producers: TicketZeroOwnerExitRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroOwnerExitRemoteFreeProducerPair<'owner>> {
    let (first, second) = producers.split();
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(move || first.publish())
                .join()
                .expect("the first joined post-exit publisher remains scoped to B's route")
                .is_ok(),
            "the first post-exit publication reaches B's held source remote head"
        );
    });
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(move || second.publish())
                .join()
                .expect("the second joined post-exit publisher remains scoped to B's route")
                .is_ok(),
            "the second post-exit publication appends before B resumes collection"
        );
    });
    Ok(())
}

fn free_owner_exit_route_with_joined_post_exit_remote_free<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                route.free_remaining_in_fresh_runtime_worker_with_post_exit_publisher(
                    publish_owner_exit_remote_free_from_scoped_test_threads,
                )
            })
            .join()
            .expect("the fresh post-exit consumer joins its concurrent source publisher")
    })
}

fn free_owner_exit_route_in_fresh_runtime_worker<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || route.free_remaining_in_fresh_runtime_worker())
            .join()
            .expect("the fresh ordinary post-exit consumer joins its source owner")
    })
}

fn hold_owner_exit_route_then_free_in_fresh_runtime_worker<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    let (entered, release) = OWNER_EXIT_ROUTE_HOLD
        .get()
        .expect("the owner-exit test installs its route rendezvous before A starts");
    entered.wait();
    release.wait();
    free_owner_exit_route_with_joined_post_exit_remote_free(route)
}

fn reclaim_owner_exit_route_in_fresh_runtime_worker(
    route: TicketZeroOwnerExitReclaimRoute,
) -> TicketZeroOwnerExitReclaimOutcome {
    std::thread::scope(|scope| {
        scope
            .spawn(move || route.reclaim_and_finish())
            .join()
            .expect("the fresh reclaim consumer joins the detached source owner")
    })
}

fn hold_direct_small_reclaim_route_then_finish_in_fresh_runtime_worker(
    route: TicketZeroOwnerExitReclaimRoute,
) -> TicketZeroOwnerExitReclaimOutcome {
    let (entered, release) = DIRECT_SMALL_RECLAIM_ROUTE_HOLD
        .get()
        .expect("the direct-small test installs its route rendezvous before A starts");
    entered.wait();
    release.wait();
    reclaim_owner_exit_route_in_fresh_runtime_worker(route)
}

#[test]
fn runtime_lifecycle_preserves_quiescent_fork_child_and_disables_unprepared_or_live_owner_child() {
    assert!(
        initialize_process(current_page_size()),
        "the process-main owner initializes from the native page-size contract"
    );
    assert!(process_is_active());

    const OVERLAPPING_WORKERS: usize = 4;
    let attached = Arc::new(Barrier::new(OVERLAPPING_WORKERS + 1));
    let release = Arc::new(Barrier::new(OVERLAPPING_WORKERS + 1));
    let mut workers = Vec::new();
    for _ in 0..OVERLAPPING_WORKERS {
        let attached = Arc::clone(&attached);
        let release = Arc::clone(&release);
        workers.push(std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            attached.wait();
            release.wait();
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::Finished
            );
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::AlreadyFinished,
                "the private owner cannot complete `_mi_thread_done` twice"
            );
        }));
    }
    attached.wait();
    assert!(
        process_is_active(),
        "overlapping later owners retain the static ticket-zero root"
    );
    release.wait();
    for worker in workers {
        worker
            .join()
            .expect("every overlapping worker completes its no-page teardown");
    }

    for _ in 0..32 {
        std::thread::spawn(|| {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::Finished
            );
        })
        .join()
        .expect("a churn worker completes its lifecycle");
    }
    assert!(
        process_is_active(),
        "successful no-page worker churn leaves the retained main owner active"
    );

    for _ in 0..2 {
        before_fork();
        match crabc_core::process::fork_raw() {
            Ok(0) => fork_quiescent_runtime_child(),
            Ok(pid) => {
                after_fork_parent();
                wait_for_clean_child(pid);
            }
            Err(error) => {
                after_fork_parent();
                panic!("the quiescent runtime fork succeeds: {error:?}");
            }
        }
    }
    assert!(
        process_is_active(),
        "the parent remains active after repeated quiescent child preservation"
    );

    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => fork_unprepared_runtime_child(),
        Ok(pid) => {
            after_fork_parent();
            wait_for_clean_child(pid);
        }
        Err(error) => {
            after_fork_parent();
            panic!("the unprepared runtime fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent remains active after an unprepared child is conservatively disabled"
    );

    let attached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker = {
        let attached = Arc::clone(&attached);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            attached.wait();
            release.wait();
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::Finished
            );
        })
    };
    attached.wait();
    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => fork_live_runtime_child(),
        Ok(pid) => {
            after_fork_parent();
            wait_for_clean_child(pid);
        }
        Err(error) => {
            after_fork_parent();
            release.wait();
            worker.join().expect("the live worker completes after fork failure");
            panic!("the live-runtime fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent retains its active bridge when a live child is conservatively disabled"
    );
    release.wait();
    worker
        .join()
        .expect("the live worker completes after the conservative child branch");

    // Exercise the source owner through the real normal post-destructor
    // runtime finish, then consume its opaque route through a fresh B
    // attachment. A's detached route still owns its client identities and
    // admission; B may use the normal no-page finish only for its own new
    // attachment after every route member terminally releases. Pause A after
    // it has transferred that opaque route, then prove ticket zero cannot
    // reactivate until B returns the terminal proof.
    let route_entered = Arc::new(Barrier::new(2));
    let route_release = Arc::new(Barrier::new(2));
    assert!(
        OWNER_EXIT_ROUTE_HOLD
            .set((Arc::clone(&route_entered), Arc::clone(&route_release)))
            .is_ok(),
        "this integration binary installs one owner-exit route rendezvous"
    );
    let first = match ticket_zero_allocate(37, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero starts the persistent page owner"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(first) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its first page engine to the dormant process pair"
    );

    // The nondefault libc shadow can use this same dormant pair for one
    // attached worker's explicitly tracked local C-facing objects. This test
    // stays below the missing general pointer router: every block is queried,
    // reallocated, and freed by the exact worker that received it, after
    // which normal pthread finish must drive the all-free page drain before
    // ticket zero becomes available again.
    assert!(
        prepare_native_later_thread_arena(),
        "the initial thread leaves the native first arena dormant before a worker borrows it"
    );
    let native_local_worker = std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let first = match native_allocate_aligned(37, 16, true) {
            crabc_mimalloc::__crabc_runtime::NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("the attached worker receives one native local allocation"),
        };
        assert!(
            unsafe { core::slice::from_raw_parts(first.as_ptr(), 37) }
                .iter()
                .all(|byte| *byte == 0),
            "the native worker zeroed allocation clears its requested extent"
        );
        unsafe { first.as_ptr().write(0x41) };
        let replacement = match unsafe { native_reallocate(Some(first), 97) } {
            crabc_mimalloc::__crabc_runtime::NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("the tracked worker client reallocates through its same parked owner"),
        };
        assert_eq!(
            unsafe { replacement.as_ptr().read() },
            0x41,
            "worker realloc preserves the source prefix"
        );
        assert!(
            unsafe { native_usable_size(replacement) }
                .is_some_and(|usable| usable >= 97),
            "the current worker owner reports the native replacement extent"
        );
        let aligned = match native_allocate_aligned(65, 64, false) {
            crabc_mimalloc::__crabc_runtime::NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("the tracked worker client accepts one aligned allocation"),
        };
        assert_eq!(aligned.as_ptr().addr() % 64, 0);
        assert_eq!(
            unsafe { native_free(aligned) },
            crabc_mimalloc::__crabc_runtime::NativePageFreeResult::Freed,
            "the worker frees its exact aligned client locally"
        );
        assert_eq!(
            unsafe { native_free(replacement) },
            crabc_mimalloc::__crabc_runtime::NativePageFreeResult::Freed,
            "the worker frees its exact reallocated client locally"
        );
        assert_eq!(
            finish_current_thread_after_user_destructors(),
            ThreadFinishResult::Finished,
            "an all-free native worker releases its admission only after the page drain"
        );
    });
    native_local_worker
        .join()
        .expect("the native local worker joins after its all-free page finish");
    let after_native_local_worker = match ticket_zero_allocate(39, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after the native local worker finishes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(after_native_local_worker) },
        TicketZeroPageFreeResult::Freed,
        "the native local worker returns the dormant process pair to ticket zero"
    );

    let aligned = match ticket_zero_allocate_aligned(65, 64, true) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("the permanent native owner accepts one aligned zeroed ticket-zero allocation")
        }
    };
    assert_eq!(
        aligned.as_ptr().addr() % 64,
        0,
        "the runtime native owner preserves aligned allocation's address contract"
    );
    // SAFETY: `aligned` is the exact current ticket-zero allocation and the
    // test remains on the initial thread while its owner is active.
    let usable = unsafe { ticket_zero_usable_size(aligned) }
        .expect("the aligned allocation remains recognizable to its native owner");
    assert!(usable >= 65, "usable size covers the requested C-facing extent");
    // SAFETY: the zeroed allocation remains live for this exact byte range.
    assert!(
        unsafe { core::slice::from_raw_parts(aligned.as_ptr(), 65) }
            .iter()
            .all(|byte| *byte == 0),
        "the native aligned zero path clears the caller-visible request"
    );
    assert_eq!(
        unsafe { ticket_zero_free(aligned) },
        TicketZeroPageFreeResult::Freed,
        "the C-facing aligned allocation returns the permanent owner to dormant"
    );
    let owner_exit = std::thread::spawn(|| {
        ticket_zero_later_thread_mapped_regular_owner_exit_through_normal_finish(
            publish_owner_exit_remote_frees,
            hold_owner_exit_route_then_free_in_fresh_runtime_worker,
        )
    });
    route_entered.wait();
    assert!(
        matches!(
            ticket_zero_allocate(41, false),
            TicketZeroPageAllocationResult::Unavailable
        ),
        "A's worker admission remains held while B owns the opaque post-exit route"
    );
    route_release.wait();
    let owner_exit = owner_exit
        .join()
        .expect("the source owner and its fresh post-exit consumer both join");
    assert_eq!(
        owner_exit,
        TicketZeroLaterThreadPageResult::Completed,
        "B finishes its own fresh attachment before A's typed route proof completes"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after the completed owner exit"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the completed A/B lifecycle returns the dormant process pair to ticket zero"
    );

    // The same typed normal finish must also accept a source image assembled
    // through several ordinary parked-TLS session operations. Its local
    // allocation/free/reuse and joined source publication all occur before
    // the session privately transfers every remaining client into the
    // general exit ledger; B still has to finish its own attachment before A
    // can make ticket zero available again.
    assert_eq!(
        std::thread::spawn(|| {
            ticket_zero_later_thread_session_owner_exit_through_normal_finish(
                publish_owner_exit_remote_frees,
                free_owner_exit_route_in_fresh_runtime_worker,
            )
        })
        .join()
        .expect("the parked session source owner and fresh route consumer join"),
        TicketZeroLaterThreadPageResult::Completed,
        "the ordinary TLS session transfers only its typed terminal route into normal finish"
    );
    let after_session_owner_exit = match ticket_zero_allocate(89, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after the completed parked-session owner exit"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(after_session_owner_exit) },
        TicketZeroPageFreeResult::Freed,
        "the parked-session A/B lifecycle returns the dormant process pair"
    );

    // A session whose every client was locally freed still owns a parked page
    // engine at pthread exit. It must take the typed all-free page-drain path
    // rather than being rejected as live or falling through to the no-page
    // finalizer. This is the positive counterpart to the terminal live-session
    // rejection at the end of this process-wide regression.
    assert_eq!(
        std::thread::spawn(ticket_zero_later_thread_all_free_session_through_normal_finish)
            .join()
            .expect("the all-free parked-session worker joins"),
        TicketZeroLaterThreadPageResult::Completed,
        "an all-free active session completes through its dedicated page-bearing finish"
    );
    let after_all_free_session = match ticket_zero_allocate(91, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after the all-free parked session"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(after_all_free_session) },
        TicketZeroPageFreeResult::Freed,
        "the all-free parked-session finish returns the dormant process pair"
    );

    // The same ordinary finish dispatch must also carry the source-valid
    // sole-medium adoption route. B owns the route until it has reused and
    // drained the exact reclaimed page, so A's admission cannot become
    // quiescent through the no-page finalizer before that typed proof returns.
    let reclaim_owner_exit = std::thread::spawn(|| {
        ticket_zero_later_thread_mapped_regular_owner_exit_reclaim_through_normal_finish(
            reclaim_owner_exit_route_in_fresh_runtime_worker,
        )
    });
    assert_eq!(
        reclaim_owner_exit
            .join()
            .expect("the source owner and fresh reclamation consumer join"),
        TicketZeroLaterThreadPageResult::Completed,
        "normal finish waits for the reclaimed-page route to terminally release"
    );
    let after_reclaim = match ticket_zero_allocate(97, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after the completed reclamation route"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(after_reclaim) },
        TicketZeroPageFreeResult::Freed,
        "the sole-medium A/B lifecycle returns the dormant process pair to ticket zero"
    );

    // Direct-small reclamation has a distinct source drain because A must
    // prove its complete rounded direct-cache image before it can transfer a
    // regular post-exit route. It must still use the same page-bearing normal
    // finish and terminal proof boundary: B's opaque adoption/drain completes
    // before A's admission can make ticket zero available again.
    let direct_small_entered = Arc::new(Barrier::new(2));
    let direct_small_release = Arc::new(Barrier::new(2));
    assert!(
        DIRECT_SMALL_RECLAIM_ROUTE_HOLD
            .set((
                Arc::clone(&direct_small_entered),
                Arc::clone(&direct_small_release),
            ))
            .is_ok(),
        "this integration binary installs one direct-small route rendezvous"
    );
    let direct_small_reclaim = std::thread::spawn(|| {
        ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish(
            hold_direct_small_reclaim_route_then_finish_in_fresh_runtime_worker,
        )
    });
    direct_small_entered.wait();
    assert!(
        matches!(
            ticket_zero_allocate(109, false),
            TicketZeroPageAllocationResult::Unavailable
        ),
        "A's direct-small admission remains held while B owns the opaque adoption route"
    );
    direct_small_release.wait();
    assert_eq!(
        direct_small_reclaim
            .join()
            .expect("the direct-small source owner and fresh reclaim consumer join"),
        TicketZeroLaterThreadPageResult::Completed,
        "normal finish waits for the direct-small typed route to terminally release"
    );
    let after_direct_small_reclaim = match ticket_zero_allocate(113, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after the direct-small reclamation route"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(after_direct_small_reclaim) },
        TicketZeroPageFreeResult::Freed,
        "the direct-small A/B lifecycle returns the dormant process pair to ticket zero"
    );

    // The held route above proves the admission boundary. Repeat the same
    // ordinary finish/reclaim path without a second rendezvous so this
    // integration process also catches direct-small TLS or PageMap state that
    // would accumulate only across fresh A/B lifecycles. The distinct Rust
    // state auditor covers the detailed process baseline; this boundary test
    // proves ticket zero can reactivate between every real normal finish.
    for cycle in 2..=8 {
        assert_eq!(
            std::thread::spawn(|| {
                ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish(
                    reclaim_owner_exit_route_in_fresh_runtime_worker,
                )
            })
            .join()
            .expect("each repeated direct-small source owner and fresh reclaim consumer join"),
            TicketZeroLaterThreadPageResult::Completed,
            "direct-small normal finish waits for each typed route to terminally release"
        );
        let resumed = match ticket_zero_allocate(113 + cycle, false) {
            TicketZeroPageAllocationResult::Allocated(block) => block,
            _ => panic!("ticket zero reactivates after repeated direct-small reclamation"),
        };
        assert_eq!(
            unsafe { ticket_zero_free(resumed) },
            TicketZeroPageFreeResult::Freed,
            "every direct-small A/B reclamation cycle returns the dormant process pair"
        );
    }

    // Exercise the eight core pointer-private lifecycle routes in a
    // reproducible order. The isolated source-published and retired-session
    // regressions retain their narrower source assertions in separate test
    // binaries. This is deliberately bounded development evidence, not a
    // claim that arbitrary concurrent callers or upstream stress are
    // supported. Each completed route must leave ticket zero available before
    // the next route begins, which catches an admission, TLS, PageMap, or
    // terminal-proof leak across mixed A/B/C owner transitions.
    let mut seed = SEEDED_LIFECYCLE_STRESS_SEED;
    for epoch in 0..SEEDED_LIFECYCLE_STRESS_EPOCHS {
        let mut routes = [
            SeededLifecycleRoute::PersistentLocal,
            SeededLifecycleRoute::LiveOwnerRemoteFree,
            SeededLifecycleRoute::AllFreeParkedTlsSession,
            SeededLifecycleRoute::MixedOwnerExit,
            SeededLifecycleRoute::ParkedTlsSessionOwnerExit,
            SeededLifecycleRoute::ParkedTlsSessionOwnerExitWithPostExitPublisher,
            SeededLifecycleRoute::MediumReclaim,
            SeededLifecycleRoute::DirectSmallReclaim,
        ];
        for remaining in (2..=routes.len()).rev() {
            let other = (next_seeded_lifecycle_schedule(&mut seed) as usize) % remaining;
            routes.swap(remaining - 1, other);
        }

        for (route_index, route) in routes.into_iter().enumerate() {
            assert_eq!(
                run_seeded_lifecycle_route(route),
                TicketZeroLaterThreadPageResult::Completed,
                "seed {SEEDED_LIFECYCLE_STRESS_SEED:#018x}, epoch {epoch}, route {route:?} completes its bounded lifecycle"
            );
            let request = 131 + epoch * routes.len() + route_index;
            let resumed = match ticket_zero_allocate(request, false) {
                TicketZeroPageAllocationResult::Allocated(block) => block,
                _ => panic!(
                    "ticket zero reactivates after seed {SEEDED_LIFECYCLE_STRESS_SEED:#018x}, epoch {epoch}, route {route:?}"
                ),
            };
            assert_eq!(
                unsafe { ticket_zero_free(resumed) },
                TicketZeroPageFreeResult::Freed,
                "seed {SEEDED_LIFECYCLE_STRESS_SEED:#018x}, epoch {epoch}, route {route:?} returns ticket zero to the dormant pair"
            );
        }
    }

    // This must be the final operation in this process-wide runtime test.
    // An active session has not selected a typed post-exit route, so normal
    // finish must conservatively retain its admission and parked engine
    // rather than applying the no-page finalizer. The retained state is
    // intentionally terminal and therefore cannot participate in another
    // lifecycle route in this test process.
    assert_eq!(
        std::thread::spawn(|| ticket_zero_later_thread_active_session_rejects_normal_finish())
            .join()
            .expect("the active-session negative worker joins"),
        TicketZeroLaterThreadPageResult::Retained,
        "normal finish rejects an unprepared active TLS session"
    );
    assert!(
        matches!(
            ticket_zero_allocate(257, false),
            TicketZeroPageAllocationResult::Retained
        ),
        "the retained active session keeps ticket zero closed instead of releasing A through no-page finish"
    );
}
