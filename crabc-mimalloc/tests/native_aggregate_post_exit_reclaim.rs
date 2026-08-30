use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

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
        "ticket zero parks the first arena before A creates its detached route"
    );

    let (blocks_sender, blocks_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let direct_small = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A receives the direct-small aggregate sibling"),
        };
        // The 16-byte C ABI alignment is natural rather than over-aligned, so
        // these remain normal medium requests in A's private ledger. A third
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
            "A transfers its mixed source image into the opaque aggregate route"
        );
    });

    let (direct_small, first_medium, final_medium) = blocks_receiver
        .recv()
        .expect("A publishes its exact route inputs before exit");
    owner
        .join()
        .expect("A finishes only after the detached route owns its clients");

    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(0);
    let (finish_sender, finish_receiver) = mpsc::sync_channel(0);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let direct_small = unsafe { core::ptr::NonNull::new_unchecked(direct_small as *mut u8) };
        let first_medium = unsafe { core::ptr::NonNull::new_unchecked(first_medium as *mut u8) };
        let final_medium = unsafe { core::ptr::NonNull::new_unchecked(final_medium as *mut u8) };
        assert_eq!(
            // SAFETY: this exact client is recorded in A's private detached
            // ledger and B cannot name any other route client.
            unsafe { native_free(direct_small) },
            NativePageFreeResult::Freed,
            "B releases the aggregate sibling before the final member"
        );
        assert_eq!(
            // SAFETY: the route keeps one additional medium client after
            // this exact free, so it remains on the ordinary opaque path.
            unsafe { native_free(first_medium) },
            NativePageFreeResult::Freed,
            "B releases all but the eligible final mapped member"
        );
        assert_eq!(
            // SAFETY: this final exact address can enter only the private
            // last-member adoption boundary; B never receives a page or a
            // reclaim capability.
            unsafe { native_free(final_medium) },
            NativePageFreeResult::Freed,
            "B terminally consumes the aggregate's final mapped member"
        );
        let continued = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes only its independent local session after the aggregate completion"
            ),
        };
        // SAFETY: this allocation is B-local and remains valid through the
        // exact free below; the opaque completed A route retains no client
        // capability over it.
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
            .expect("B reports terminal route release before its own finish");
        finish_receiver
            .recv()
            .expect("the coordinator authorizes B's normal finish");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "only B's finish settles the matching detached-route completion"
        );
    });

    terminal_receiver
        .recv()
        .expect("B reaches its route-terminal pre-finish state");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "ticket zero remains unavailable until B consumes the terminal proof"
    );
    finish_sender
        .send(())
        .expect("the coordinator permits B's normal lifecycle finish");
    releaser
        .join()
        .expect("B completes the detached aggregate lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates after B finishes"),
    };
    assert_eq!(
        // SAFETY: `resumed` is the exact ticket-zero allocation returned
        // after the detached aggregate completion settled.
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the reactivated ticket-zero client frees normally"
    );
}
