#![cfg(feature = "native-runtime-test-audit")]

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_reallocate, native_runtime_lifecycle_test_audit, native_usable_size,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

const OWNER_LOCAL_CYCLES: usize = 6;
const ANCHOR_REQUEST: usize = 37;
const ANCHOR_REALLOC_REQUEST: usize = 193;
const CYCLE_REQUEST: usize = 53;
const LIVE_OWNER_EXIT_CHILD: &str = "CRABC_NATIVE_PERSISTENT_OWNER_LIVE_EXIT_CHILD";

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_local(request: usize) -> core::ptr::NonNull<u8> {
    match native_allocate_aligned(request, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the attached worker creates its owner-local regular client")
        }
    }
}

/// Once its first ordinary regular page exists, an attached worker keeps that
/// owner in compiler TLS and performs each later local allocation/free through
/// it.  The scalar audit is intentionally sampled only after the worker joins:
/// it proves the native C-shaped boundary did not silently fall back to the
/// parked compatibility bridge for each cycle.
#[test]
fn attached_worker_reuses_its_owner_for_repeated_local_allocate_free_cycles() {
    assert!(
        initialize_process(current_page_size()),
        "the private native runtime initializes before the owner-local lifecycle"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero leaves its first arena dormant before the worker attaches"
    );
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the initialized process has a quiescent lifecycle audit");

    std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

        // Keep one regular page-owned client live while the repeating client
        // cycles.  This prevents an all-free owner transition from masking
        // whether the next allocation reused the same retained local owner.
        let anchor = allocate_local(ANCHOR_REQUEST);
        // SAFETY: the anchor is this worker's exact current allocation and
        // remains exclusively accessible through both operations.
        assert!(
            unsafe { native_usable_size(anchor) }
                .is_some_and(|usable_size| usable_size >= ANCHOR_REQUEST)
        );
        let anchor = match unsafe { native_reallocate(Some(anchor), ANCHOR_REALLOC_REQUEST) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the retained owner performs its local anchor realloc")
            }
        };
        for cycle in 0..OWNER_LOCAL_CYCLES {
            let block = allocate_local(CYCLE_REQUEST);
            // SAFETY: this exact worker owns `block` until this matching
            // local free, and no remote producer or post-exit route exists.
            unsafe {
                assert_eq!(
                    native_free(block),
                    NativePageFreeResult::Freed,
                    "owner-local cycle {cycle} frees its exact current client"
                );
            }
        }
        // SAFETY: the retained owner still owns the anchor locally.
        unsafe {
            assert_eq!(native_free(anchor), NativePageFreeResult::Freed);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the all-free retained owner reaches normal source teardown"
        );
    })
    .join()
    .expect("the owner-local worker joins after every local cycle");

    let after = native_runtime_lifecycle_test_audit()
        .expect("the completed worker restores a quiescent lifecycle audit");
    assert!(
        after
            .native_owner_local_operation_count
            .saturating_sub(baseline.native_owner_local_operation_count)
            >= OWNER_LOCAL_CYCLES * 2 + 4,
        "allocate, usable-size, realloc, and every local free use the retained owner-local path"
    );
    assert_eq!(
        after
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "ordinary local C operations never enter the per-call parked compatibility bridge"
    );
    assert_eq!(after.page_owner_ready, 1);
    assert_eq!(after.page_map_registered_entry_count, 0);

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("worker teardown restores the ticket-zero baseline")
        }
    };
    // SAFETY: `resumed` is ticket zero's exact current private block.
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed
    );
}

/// A later persistent worker with a live page exits through the source
/// collect-abandon traversal. Its abandoned page remains process-owned, while
/// ticket zero stays the independent persistent owner; the worker must not
/// enter the legacy scheduler/park bridge to make that transition happen.
/// Run this retained-abandoned-state witness in a fresh process so no later
/// test inherits the intentionally live source page.
#[test]
fn live_persistent_owner_exits_without_scheduler_handoff() {
    if std::env::var_os(LIVE_OWNER_EXIT_CHILD).is_some() {
        assert!(initialize_process(current_page_size()));
        assert!(prepare_native_later_thread_arena());
        let ticket_zero = match ticket_zero_allocate(73, false) {
            TicketZeroPageAllocationResult::Allocated(block) => block,
            TicketZeroPageAllocationResult::Unavailable
            | TicketZeroPageAllocationResult::AllocationFailed
            | TicketZeroPageAllocationResult::Retained => {
                panic!("ticket zero stays independently live while the worker exits")
            }
        };
        let baseline = native_runtime_lifecycle_test_audit().expect(
            "the live ticket-zero owner establishes the audit baseline before its worker exits",
        );
        std::thread::spawn(|| {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            let _live = allocate_local(81);
            assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "a live persistent worker leaves through collect-abandon rather than fail-stopping"
            );
        })
        .join()
        .expect("the source-shaped persistent worker returns normally after its exit");

        let after = native_runtime_lifecycle_test_audit()
            .expect("the abandoned-worker result retains a readable process audit");
        assert_eq!(after.page_owner_ready, 1);
        assert!(
            after.main_heap_abandoned_page_count >= baseline.main_heap_abandoned_page_count + 1,
            "the live worker leaves its page in the source static-main abandoned image"
        );
        assert_eq!(
            after
                .native_scheduler_transition_count
                .saturating_sub(baseline.native_scheduler_transition_count),
            0,
            "the direct persistent worker exit never takes a scheduler transition"
        );
        assert_eq!(
            after
                .native_parked_compatibility_operation_count
                .saturating_sub(baseline.native_parked_compatibility_operation_count),
            0,
            "the direct persistent worker exit never enters the parked compatibility bridge"
        );

        // SAFETY: this exact ticket-zero client stayed live through the
        // independent worker's source collect-abandon transition.
        assert_eq!(unsafe { ticket_zero_free(ticket_zero) }, TicketZeroPageFreeResult::Freed);
        return;
    }

    let status = std::process::Command::new(
        std::env::current_exe().expect("the focused test executable has a current path"),
    )
    .arg("--exact")
    .arg("live_persistent_owner_exits_without_scheduler_handoff")
    .env(LIVE_OWNER_EXIT_CHILD, "1")
    .status()
    .expect("the live-owner child test starts");
    assert_eq!(
        status.code(),
        Some(0),
        "the source-shaped live owner exits without retaining compiler TLS"
    );
}
