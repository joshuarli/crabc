use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_reallocate, native_runtime_fork_admission_test_audit, native_usable_size,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

const OWNER_EXIT_CLIENT_COUNT: usize = 6;
const OWNER_EXIT_CLIENTS: [(&str, usize); OWNER_EXIT_CLIENT_COUNT] = [
    ("direct-small", 37),
    ("non-direct-small", 1025),
    ("medium", 64 * 1024),
    ("regular-large", 128 * 1024),
    ("arena-singleton", 1024 * 1024),
    ("OS-singleton", 7),
];

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

/// Returns the exact C-shaped clients from one finished owner. The consumer
/// receives no owner, route token, client ledger, scheduler token, PageMap
/// lease, or release capability; pointer-first operations must rediscover
/// source state from the process PageMap. Each source owner releases its own
/// admission at owner exit; PageMap/abandonment ownership is the complete
/// post-exit consumer contract.
fn publish_owner_exit_page_map_sources() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only its exact C-shaped clients before owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon before a later pointer operation"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives every exact source client before A exits");
    owner
        .join()
        .expect("A reaches the completed native owner-exit boundary");
    clients
}

fn consume_owner_exit_page_map_sources(
    clients: [usize; OWNER_EXIT_CLIENT_COUNT],
    source: &str,
) {
    for (address, (geometry, minimum_usable_size)) in
        clients.into_iter().zip(OWNER_EXIT_CLIENTS)
    {
        // SAFETY: this exact live native client was supplied before its owner
        // completed source collect-abandon. The pointer-first query and free
        // each obtain their own PageMap source observation; neither receives
        // a former owner nor an exact-client route capability.
        let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
        assert!(
            unsafe { native_usable_size(block) }
                .is_some_and(|usable_size| usable_size >= minimum_usable_size),
            "{source}'s {geometry} client remains PageMap-queryable after owner exit"
        );
        assert_eq!(
            unsafe { native_free(block) },
            NativePageFreeResult::Freed,
            "B consumes {source}'s {geometry} source through pointer-first PageMap dispatch"
        );
    }
}

#[test]
fn one_b_consumes_multiple_post_exit_page_map_sources_while_initial_owner_remains_independent() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the multiple-source witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the persistent initial owner leaves its source arena pair dormant before workers begin"
    );

    let first = publish_owner_exit_page_map_sources();
    let second = publish_owner_exit_page_map_sources();
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "both completed A owners release their admissions before B attaches"
    );

    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(0);
    let (finish_sender, finish_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "B owns the only worker-admission claim while it consumes both PageMap sources"
        );

        let local = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes an independent local native owner"),
        };
        // SAFETY: `local` remains B-local through its replacement below. The
        // sentinels prove that consuming one completed A source cannot route
        // B's ordinary local reallocation through a post-exit compatibility
        // path.
        unsafe {
            local.as_ptr().write(0x51);
            local.as_ptr().add(52).write(0x52);
        }

        consume_owner_exit_page_map_sources(first, "the first A");
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "the first source's PageMap consumption leaves B as the only admitted worker"
        );
        let local = match unsafe { native_reallocate(Some(local), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B keeps its local replacement available after the first source"),
        };
        assert_eq!(
            unsafe { local.as_ptr().read() },
            0x51,
            "the first source leaves B's first local sentinel intact"
        );
        assert_eq!(
            unsafe { local.as_ptr().add(52).read() },
            0x52,
            "the first source leaves B's second local sentinel intact"
        );

        consume_owner_exit_page_map_sources(second, "the second A");
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "the second source's PageMap consumption still leaves only B admitted"
        );
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "B may discharge its local replacement before its own source finish"
        );

        terminal_sender
            .send(())
            .expect("B completes both PageMap source consumptions before its normal finish");
        finish_receiver
            .recv()
            .expect(
                "the initial owner performs an independent ticket-zero operation while B remains attached"
            );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes only its own persistent owner after both foreign source consumptions"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            0,
            "B's own finish releases the remaining worker-admission claim"
        );
    });

    terminal_receiver
        .recv()
        .expect("B consumes both completed source images before the initial owner operates");
    let while_b_attached = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable => {
            panic!("the persistent initial owner remains available while B is attached")
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            panic!("the fixed ticket-zero request remains allocatable while B is attached")
        }
        TicketZeroPageAllocationResult::Retained => {
            panic!("healthy PageMap source consumption leaves the initial owner usable")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(while_b_attached) },
        TicketZeroPageFreeResult::Freed,
        "the initial persistent owner frees its independent ticket-zero client while B remains attached"
    );
    finish_sender
        .send(())
        .expect("B may complete its own normal source finish");
    releaser
        .join()
        .expect("B completes both independent PageMap source consumptions");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("the initial persistent owner remains usable after B finishes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the initial persistent owner returns its local client after B finishes"
    );
}
