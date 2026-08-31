use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::native_runtime_lifecycle_test_audit;

const MEDIUM_REQUEST: usize = 64 * 1024;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn native_aggregate_reclaims_its_final_mapped_regular_member_before_b_finishes() {
    // `RUNTIME_PROCESS` is a true process-lifetime source owner. Keep this
    // regression in its own integration-test executable rather than the
    // shared `--lib` unit-test process: a second initialization would test
    // the intentional one-shot rejection, not aggregate reclamation.
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its aggregate-reclaim witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero sets aside its first arena before A creates its PageMap-backed source"
    );

    let (blocks_sender, blocks_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let direct_small = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A receives the direct-small aggregate sibling"),
        };
        // The 16-byte C ABI alignment is natural rather than over-aligned, so
        // these remain normal medium requests in A's live native source. A third
        // local allocation/free supplies the source force-collectable head
        // while the two live medium clients keep their page nonempty.
        let first_medium = match native_allocate_aligned(MEDIUM_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A receives its first mapped medium client"),
        };
        let final_medium = match native_allocate_aligned(MEDIUM_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A receives its final mapped medium client"),
        };
        let spare_medium = match native_allocate_aligned(MEDIUM_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the source medium free-list witness"),
        };
        assert_eq!(
            // SAFETY: A still owns this exact spare locally, and its two
            // medium siblings remain live in the same source workload.
            unsafe { native_free(spare_medium) },
            NativePageFreeResult::Freed,
            "A returns the source spare before it begins owner exit"
        );
        blocks_sender
            .send((
                direct_small.as_ptr().addr(),
                first_medium.as_ptr().addr(),
                final_medium.as_ptr().addr(),
            ))
            .expect("B receives only the exact C-shaped free inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A abandons its mixed source image through the native owner-exit path"
        );
    });

    let (direct_small, first_medium, final_medium) = blocks_receiver
        .recv()
        .expect("A publishes its exact post-exit free inputs before exit");
    owner
        .join()
        .expect("A finishes only after PageMap retains its post-exit clients");
    #[cfg(feature = "native-runtime-test-audit")]
    let source_after_owner_exit = native_runtime_lifecycle_test_audit()
        .expect("A's completed owner exit leaves an auditable PageMap source");
    #[cfg(feature = "native-runtime-test-audit")]
    assert!(
        source_after_owner_exit.main_heap_abandoned_page_count > 0,
        "A's still-live aggregate members enter the mapped-abandoned PageMap state"
    );

    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(0);
    let (finish_sender, finish_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let direct_small = unsafe { core::ptr::NonNull::new_unchecked(direct_small as *mut u8) };
        let first_medium = unsafe { core::ptr::NonNull::new_unchecked(first_medium as *mut u8) };
        let final_medium = unsafe { core::ptr::NonNull::new_unchecked(final_medium as *mut u8) };
        assert_eq!(
            // SAFETY: this exact client remains PageMap-live after A's
            // owner-exit boundary, and B cannot name any other source client.
            unsafe { native_free(direct_small) },
            NativePageFreeResult::Freed,
            "B releases the aggregate sibling before the final member"
        );
        assert_eq!(
            // SAFETY: A's mapped-abandoned source retains one additional
            // medium client after this exact PageMap-derived free.
            unsafe { native_free(first_medium) },
            NativePageFreeResult::Freed,
            "B releases all but the eligible final mapped member"
        );
        assert_eq!(
            // SAFETY: this final exact address remains PageMap-live through
            // the source abandonment state; B receives no page or reclaim
            // capability beyond this exact C-shaped free.
            unsafe { native_free(final_medium) },
            NativePageFreeResult::Freed,
            "B releases the aggregate's final mapped member through PageMap"
        );
        let continued = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes only its independent local session after the PageMap source releases"
            ),
        };
        // SAFETY: this allocation is B-local and remains valid through the
        // exact free below; A's released PageMap source retains no capability
        // over it.
        unsafe {
            continued.as_ptr().write(0x57);
            continued.as_ptr().add(72).write(0x58);
            assert_eq!(continued.as_ptr().read(), 0x57);
            assert_eq!(continued.as_ptr().add(72).read(), 0x58);
        }
        assert_eq!(
            unsafe { native_free(continued) },
            NativePageFreeResult::Freed,
            "B frees its independent local client before the terminal finish"
        );
        terminal_sender
            .send(())
            .expect("B reports PageMap source release before its own finish");
        finish_receiver
            .recv()
            .expect("the coordinator authorizes B's normal finish");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes its independent persistent owner after source release"
        );
    });

    terminal_receiver
        .recv()
        .expect("B reaches the source-release pre-finish state");
    #[cfg(feature = "native-runtime-test-audit")]
    let source_after_terminal_free = native_runtime_lifecycle_test_audit()
        .expect("B's terminal source free leaves an auditable PageMap state");
    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        source_after_terminal_free.main_heap_abandoned_page_count,
        0,
        "the final source member releases every mapped-abandoned aggregate page"
    );
    #[cfg(feature = "native-runtime-test-audit")]
    assert!(
        source_after_terminal_free.page_map_registered_entry_count
            < source_after_owner_exit.page_map_registered_entry_count,
        "the aggregate final free releases PageMap registrations before B finishes"
    );
    let while_b_attached = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable => {
            panic!("the released PageMap source leaves ticket zero available while B remains attached")
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            panic!("the fixed ticket-zero request remains allocatable after source release")
        }
        TicketZeroPageAllocationResult::Retained => {
            panic!("the aggregate final free does not retain ticket zero's independent owner")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(while_b_attached) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its independent client while B remains attached"
    );
    finish_sender
        .send(())
        .expect("the coordinator permits B's normal lifecycle finish");
    releaser
        .join()
        .expect("B completes its independent post-exit lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable => {
            panic!("ticket zero remains available after B finishes")
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            panic!("the fixed ticket-zero request remains allocatable after B finishes")
        }
        TicketZeroPageAllocationResult::Retained => {
            panic!("B's independent finish does not retain ticket zero's owner")
        }
    };
    assert_eq!(
        // SAFETY: `resumed` is the exact ticket-zero allocation returned
        // after B's independent lifecycle finished.
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the reactivated ticket-zero client frees normally"
    );
}
