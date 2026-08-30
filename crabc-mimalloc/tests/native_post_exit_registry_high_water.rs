use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_post_exit_registry_test_audit,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

const DETACHED_OWNER_COUNT: usize = 3;
const OWNER_EXIT_CLIENT_COUNT: usize = 6;
const OWNER_EXIT_EPOCHS: usize = 8;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_owner_exit_aggregate() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let direct_small = match native_allocate_aligned(37, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its direct-small native client"),
    };
    let non_direct_small = match native_allocate_aligned(1025, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its non-direct-small native client"),
    };
    let medium = match native_allocate_aligned(64 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its medium native client"),
    };
    let large = match native_allocate_aligned(128 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its regular-large native client"),
    };
    let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its arena-singleton native client"),
    };
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives its OS-singleton native client"),
    };

    [
        direct_small.as_ptr().addr(),
        non_direct_small.as_ptr().addr(),
        medium.as_ptr().addr(),
        large.as_ptr().addr(),
        arena_singleton.as_ptr().addr(),
        os_singleton.as_ptr().addr(),
    ]
}

fn publish_detached_owner() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only its exact native clients before exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A installs one typed detached owner-exit route"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives A's exact route clients before exit");
    owner
        .join()
        .expect("A completes its detached source lifecycle");
    clients
}

fn release_detached_owner(clients: [usize; OWNER_EXIT_CLIENT_COUNT]) {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        for address in clients {
            // SAFETY: A supplied this exact address before its private typed
            // route detached. The registry must validate the client again
            // without exposing a route, page, or client capability.
            let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            assert_eq!(
                unsafe { native_free(block) },
                NativePageFreeResult::Freed,
                "B releases only the exact native client recorded by A"
            );
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B releases A's admission only through its normal attachment finish"
        );
    })
    .join()
    .expect("the detached-route consumer completes its B lifecycle");
}

#[test]
fn native_post_exit_registry_reuses_its_warm_concurrent_high_water() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the registry high-water witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before detached owners begin"
    );
    assert_eq!(
        native_post_exit_registry_test_audit().published_entry_count,
        0,
        "this isolated test process begins without a detached-route registry entry"
    );

    let mut warm_entry_count = None;
    for epoch in 0..OWNER_EXIT_EPOCHS {
        let clients: [[usize; OWNER_EXIT_CLIENT_COUNT]; DETACHED_OWNER_COUNT] =
            core::array::from_fn(|_| publish_detached_owner());
        let live = native_post_exit_registry_test_audit();
        assert_eq!(
            live.live_entry_count,
            DETACHED_OWNER_COUNT,
            "epoch {epoch} parks one route entry for each independently detached A"
        );
        assert_eq!(
            live.retained_entry_count,
            0,
            "epoch {epoch} has no terminal registry entry while every route remains live"
        );
        match warm_entry_count {
            Some(warm) => assert_eq!(
                live.published_entry_count, warm,
                "epoch {epoch} reuses the warm registry high-water rather than allocating another metadata node"
            ),
            None => {
                assert_eq!(
                    live.published_entry_count, DETACHED_OWNER_COUNT,
                    "the first concurrent epoch publishes exactly one stable entry per live route"
                );
                warm_entry_count = Some(live.published_entry_count);
            }
        }

        for owner_clients in clients {
            release_detached_owner(owner_clients);
        }
        let quiescent = native_post_exit_registry_test_audit();
        assert_eq!(
            quiescent.published_entry_count,
            warm_entry_count.expect("the first epoch records the warm high-water"),
            "epoch {epoch} keeps the stable metadata nodes for reuse, not another route lifetime"
        );
        assert_eq!(
            quiescent.live_entry_count,
            0,
            "epoch {epoch} returns every registry entry to the reusable empty state"
        );
        assert_eq!(
            quiescent.retained_entry_count,
            0,
            "epoch {epoch} leaves no terminally retained route hidden behind the warm nodes"
        );

        let resumed = match ticket_zero_allocate(73 + epoch, false) {
            TicketZeroPageAllocationResult::Allocated(block) => block,
            _ => panic!("ticket zero reactivates after every complete epoch"),
        };
        assert_eq!(
            unsafe { ticket_zero_free(resumed) },
            TicketZeroPageFreeResult::Freed,
            "the resumed ticket-zero client returns to the dormant pair"
        );
    }
}
