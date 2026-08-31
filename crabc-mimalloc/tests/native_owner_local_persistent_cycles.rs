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
const RETAINED_EXIT_CHILD: &str = "CRABC_NATIVE_PERSISTENT_OWNER_RETAINED_EXIT_CHILD";

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

/// A live source allocation makes the consuming owner finish refuse. The
/// exact owner remains in the retained compiler-TLS payload at that point, so
/// the runtime must terminate the process before libc can reclaim that TLS
/// image. Run the destructive half in a fresh copy of this test executable.
#[test]
fn retained_persistent_owner_fail_stops_before_native_thread_return() {
    if std::env::var_os(RETAINED_EXIT_CHILD).is_some() {
        assert!(initialize_process(current_page_size()));
        assert!(prepare_native_later_thread_arena());
        std::thread::spawn(|| {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            let _live = allocate_local(81);
            let _ = finish_current_thread_native_after_user_destructors();
            unreachable!("a retained persistent owner cannot reach native thread return");
        })
        .join()
        .expect("the fail-stop worker terminates the complete child process");
        unreachable!("the retained-owner child cannot survive its worker exit");
    }

    let status = std::process::Command::new(
        std::env::current_exe().expect("the focused test executable has a current path"),
    )
    .arg("--exact")
    .arg("retained_persistent_owner_fail_stops_before_native_thread_return")
    .env(RETAINED_EXIT_CHILD, "1")
    .status()
    .expect("the retained-owner child test starts");
    assert_eq!(
        status.code(),
        Some(134),
        "unresolved persistent TLS ownership terminates before thread return"
    );
}
