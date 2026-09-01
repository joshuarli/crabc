// This regression is compiled only with the default-off audit feature. Its
// rendezvous can witness one source CAS boundary but cannot participate in an
// ordinary allocator build.
#![cfg(feature = "native-runtime-test-audit")]

use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, native_runtime_lifecycle_test_audit,
    native_runtime_test_arm_owner_exit_collection_rendezvous, native_usable_size,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

const REQUEST: usize = 37;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// This is deliberately a bounded wait rather than a timing race. The audit
/// hook can pause only after `ProductionOwnerExitCallbacks` has entered the
/// actual `MI_ABANDON` force collector, loaded a nonempty remote head, and is
/// immediately before the production detach CAS. Dropping the guard releases
/// the owner if this assertion fails, so the test cannot leave its source
/// thread spinning during unwinding.
fn wait_for_owner_exit_collection_pause(
    rendezvous: &crabc_mimalloc::__crabc_runtime::NativeRuntimeOwnerExitCollectionRendezvous,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !rendezvous.is_paused() {
        assert!(
            Instant::now() < deadline,
            "A's `MI_ABANDON` queue collector must observe the seeded nonempty remote head"
        );
        std::thread::yield_now();
    }
}

fn assert_exact_distinct_racing_clients(addresses: &[usize], producer_count: usize) {
    assert_eq!(
        addresses.len(),
        producer_count,
        "the {producer_count}-publisher row gives each B exactly one current racing client"
    );
    for (first_index, first_address) in addresses.iter().enumerate() {
        for second_address in &addresses[first_index + 1..] {
            assert_ne!(
                first_address, second_address,
                "the {producer_count}-publisher row gives different Bs distinct current racing clients"
            );
        }
    }
}

/// Exercises the source `mi_page_thread_free_collect` retry inside the real
/// persistent-owner `MI_ABANDON` traversal. A first, separately named raw
/// C-shaped seed client takes the ordinary PageMap-derived `native_free` path
/// so the collector must read a nonempty remote head. Exactly one distinct,
/// still-current raw C-shaped racing client then goes to each of 1/2/4/8 B
/// threads. A's ordinary finish reaches
/// `PageAllocatorEngine::collect_abandon_owner_exit` and its
/// `ProductionOwnerExitCallbacks::page_free_collect_force` callback. The Bs
/// all call the ordinary `native_free` only after that callback stopped
/// between the source head read and its first detach CAS. Their publications
/// make the captured head stale, so the unchanged production CAS loop must
/// retry, collect the seed and every racing client, release A's direct-small
/// page, and finish the persistent owner.
#[test]
fn native_owner_exit_collection_retries_live_page_map_publishers_at_one_two_four_and_eight() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the owner-exit collection race"
    );

    for producer_count in [1usize, 2, 4, 8] {
        assert!(
            prepare_native_later_thread_arena(),
            "ticket zero prepares the dormant process pair before the {producer_count}-publisher owner"
        );
        run_owner_exit_collection_race(producer_count);
    }
}

fn run_owner_exit_collection_race(producer_count: usize) {
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared process exposes a quiescent scalar lifecycle baseline");
    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let (publisher_ready_sender, publisher_ready_receiver) = mpsc::channel();
    let (begin_exit_sender, begin_exit_receiver) = mpsc::sync_channel(0);
    let (owner_finished_sender, owner_finished_receiver) = mpsc::sync_channel(0);
    let publish_racing_clients = Arc::new(Barrier::new(producer_count + 1));
    let (racing_done_sender, racing_done_receiver) = mpsc::channel();

    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

        let seed = match native_allocate_aligned(REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the one nonempty-head seed client"),
        };
        // SAFETY: A retains its exact seed until the initial persistent owner
        // performs the one foreign PageMap-derived free below.
        unsafe {
            seed.as_ptr().write(0x11);
            seed.as_ptr().add(REQUEST - 1).write(0x12);
        }

        let mut racing_clients = Vec::with_capacity(producer_count);
        for index in 0..producer_count {
            let client = match native_allocate_aligned(REQUEST, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!("A creates racing client {index} for the source remote list"),
            };
            // SAFETY: A retains each exact current client until the one B
            // assigned below makes its only foreign `native_free` call. The
            // payload checks prevent a stale or substituted raw pointer from
            // becoming a fixture-only queue operation.
            unsafe {
                client.as_ptr().write((0x20 + index) as u8);
                client.as_ptr().add(REQUEST - 1).write((0x60 + index) as u8);
            }
            racing_clients.push(client.as_ptr().addr());
        }
        clients_sender
            .send((seed.as_ptr().addr(), racing_clients))
            .expect("the coordinator receives only exact A-owned C-shaped addresses");

        begin_exit_receiver
            .recv()
            .expect("A begins source owner exit only after the rendezvous is armed");
        let result = finish_current_thread_native_after_user_destructors();
        owner_finished_sender
            .send(result)
            .expect("the coordinator observes the completed source owner exit");
        assert_eq!(
            result,
            ThreadFinishResult::Finished,
            "A releases its all-remotely-freed page only after collecting the seed and every racing client"
        );
    });

    let (seed_address, racing_clients) = clients_receiver
        .recv()
        .expect("A remains live while each B receives its one raw native address");
    assert_exact_distinct_racing_clients(&racing_clients, producer_count);
    for racing_address in &racing_clients {
        assert_ne!(
            *racing_address, seed_address,
            "the nonempty-head seed is not any B's distinct racing client"
        );
    }

    let mut publishers = Vec::with_capacity(producer_count);
    for (index, racing_address) in racing_clients.into_iter().enumerate() {
        let publisher_ready_sender = publisher_ready_sender.clone();
        let publish_racing_clients = Arc::clone(&publish_racing_clients);
        let racing_done_sender = racing_done_sender.clone();
        publishers.push(std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            // SAFETY: A supplied this exact still-current C-shaped client to
            // this one B. B receives neither A's page nor an owner capability.
            let racing_client = unsafe {
                core::ptr::NonNull::new_unchecked(racing_address as *mut u8)
            };
            // SAFETY: the client remains live through this immutable PageMap
            // observation and its one source remote-head publication.
            unsafe {
                assert_eq!(racing_client.as_ptr().read(), (0x20 + index) as u8);
                assert_eq!(
                    racing_client.as_ptr().add(REQUEST - 1).read(),
                    (0x60 + index) as u8
                );
            }
            assert!(
                unsafe { native_usable_size(racing_client) }.is_some_and(|size| size >= REQUEST),
                "B{index} resolves its current racing client through the live production PageMap"
            );
            publisher_ready_sender
                .send(index)
                .expect("the coordinator waits until every B is ready to publish once");

            // The coordinator reaches this barrier only after A's existing
            // source collector loaded the nonempty seed head and stopped
            // before its first detach CAS.
            publish_racing_clients.wait();
            assert_eq!(
                unsafe { native_free(racing_client) },
                NativePageFreeResult::Freed,
                "B{index} makes A's captured remote head stale with its one distinct racing client"
            );
            racing_done_sender
                .send(index)
                .expect("the coordinator waits until every racing PageMap publication completed");
            assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "B{index} finishes its independent no-page attachment after its one publication"
            );
        }));
    }
    drop(publisher_ready_sender);
    drop(racing_done_sender);

    let mut ready_publishers = vec![false; producer_count];
    for _ in 0..producer_count {
        let index = publisher_ready_receiver
            .recv()
            .expect("every B prepares its one PageMap-derived racing publication");
        assert!(index < producer_count);
        assert!(
            !core::mem::replace(&mut ready_publishers[index], true),
            "each B prepares exactly one racing publication"
        );
    }
    assert!(
        ready_publishers.into_iter().all(core::convert::identity),
        "all {producer_count} distinct B publishers are ready before A begins owner exit"
    );

    // SAFETY: A still owns this exact seed client and cannot exit until the
    // coordinator later signals it. The initial persistent owner has only its
    // ordinary pointer-first interface, so this is a real foreign PageMap
    // publication rather than a raw remote-free fixture operation.
    let seed = unsafe { core::ptr::NonNull::new_unchecked(seed_address as *mut u8) };
    unsafe {
        assert_eq!(seed.as_ptr().read(), 0x11);
        assert_eq!(seed.as_ptr().add(REQUEST - 1).read(), 0x12);
    }
    assert!(
        unsafe { native_usable_size(seed) }.is_some_and(|size| size >= REQUEST),
        "the initial owner resolves the nonempty-head seed through the live production PageMap"
    );
    assert_eq!(
        unsafe { native_free(seed) },
        NativePageFreeResult::Freed,
        "the initial owner publishes the one foreign seed before A enters `MI_ABANDON`"
    );

    let rendezvous = native_runtime_test_arm_owner_exit_collection_rendezvous()
        .expect("this isolated test owns the one direct owner-exit rendezvous");
    begin_exit_sender
        .send(())
        .expect("A begins its production `MI_ABANDON` queue traversal");
    wait_for_owner_exit_collection_pause(&rendezvous);

    publish_racing_clients.wait();
    let mut completed_publishers = vec![false; producer_count];
    for _ in 0..producer_count {
        let index = racing_done_receiver
            .recv()
            .expect("every distinct racing PageMap publication completes before A resumes");
        assert!(index < producer_count);
        assert!(
            !core::mem::replace(&mut completed_publishers[index], true),
            "each B frees its distinct current racing client exactly once"
        );
    }
    assert!(
        completed_publishers.into_iter().all(core::convert::identity),
        "the exact {producer_count} current racing clients are all freed once"
    );
    assert!(
        rendezvous.release(),
        "only the armed test guard releases A's paused owner-exit collector"
    );
    assert_eq!(
        owner_finished_receiver
            .recv()
            .expect("A completes after its source collector retries"),
        ThreadFinishResult::Finished,
        "the retried production collector accounts for every live foreign free before A exits"
    );
    assert!(
        rendezvous.observed_retry(),
        "the source head CAS retries after the exact {producer_count} late native frees make its captured head stale"
    );
    drop(rendezvous);
    let reset_rendezvous = native_runtime_test_arm_owner_exit_collection_rendezvous()
        .expect("the completed owner-exit hook restores its scalar state to idle");
    drop(reset_rendezvous);

    for publisher in publishers {
        publisher
            .join()
            .expect("every foreign native publisher finishes its complete pointer-first lifecycle");
    }
    owner
        .join()
        .expect("A finishes the actual persistent-owner `MI_ABANDON` queue traversal");

    let after = native_runtime_lifecycle_test_audit()
        .expect("every producer and A joined before the post-race lifecycle audit");
    assert_eq!(
        after.process_active, baseline.process_active,
        "the process remains in its prepared native runtime state"
    );
    assert_eq!(
        after.page_owner_ready, baseline.page_owner_ready,
        "the source owner-ready state returns to its prepared baseline"
    );
    assert_eq!(
        after.page_map_registered_entry_count, baseline.page_map_registered_entry_count,
        "the seed and exact {producer_count} racing clients release their PageMap registrations"
    );
    assert_eq!(
        after.arena_registry_count, baseline.arena_registry_count,
        "the race leaves no extra native process arena registration"
    );
    assert_eq!(
        after.main_heap_abandoned_page_count, baseline.main_heap_abandoned_page_count,
        "A's all-remotely-freed direct-small page leaves no abandoned-page residue"
    );
    assert_eq!(
        after.main_heap_os_abandoned_pages_empty, baseline.main_heap_os_abandoned_pages_empty,
        "the owner-exit race leaves the OS abandoned-page list at baseline"
    );
    assert_eq!(
        after.live_thread_count, baseline.live_thread_count,
        "A and every foreign publisher release their later-thread identities"
    );
    assert_eq!(
        after.shared_later_theap_count, baseline.shared_later_theap_count,
        "the race leaves no shared later-Theap residue"
    );
    assert_eq!(
        after.metadata_live_capability_count, baseline.metadata_live_capability_count,
        "the completed race retains no live metadata capability"
    );
    assert_eq!(
        after
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "the direct owner exit does not enter the parked compatibility bridge"
    );
    assert_eq!(
        after
            .native_scheduler_transition_count
            .saturating_sub(baseline.native_scheduler_transition_count),
        0,
        "the direct persistent owner exit does not enter the legacy scheduler"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A and every foreign publisher release their fork-admission claims"
    );

    let resumed = match ticket_zero_allocate(REQUEST, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!(
            "ticket zero resumes after the {producer_count}-publisher source owner-exit collection"
        ),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the completed owner-exit race leaves no retained native page owner"
    );
}
