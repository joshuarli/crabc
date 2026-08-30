use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::native_runtime_fork_admission_test_audit;

const OWNER_EXIT_CLIENT_COUNT: usize = 6;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_owner_exit_aggregate() -> [usize; OWNER_EXIT_CLIENT_COUNT] {
    let direct_small = match native_allocate_aligned(37, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives the direct-small native client"),
    };
    let non_direct_small = match native_allocate_aligned(1025, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives the non-direct-small native client"),
    };
    let medium = match native_allocate_aligned(64 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives the medium native client"),
    };
    let large = match native_allocate_aligned(128 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives the regular-large native client"),
    };
    let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives the arena-singleton native client"),
    };
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the owner receives the OS-singleton native client"),
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

fn free_exact_native_route_client(address: usize) {
    // SAFETY: the test simulates one C `free` input after the source owner
    // detached. The registry must still validate this exact address against
    // its private ledger before the source page transition can run.
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "an attached releaser consumes only its exact detached-route client"
    );
}

#[test]
fn detached_route_releases_admission_only_after_its_terminal_releaser_finishes() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the split-releaser lifecycle regression"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before the detached owner begins"
    );

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        owner_sender
            .send(allocate_owner_exit_aggregate())
            .expect("A publishes only exact C-shaped detached-route inputs");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A transfers its mixed aggregate into the typed detached route"
        );
    });
    let clients = owner_receiver
        .recv()
        .expect("the coordinator receives A's exact inputs before owner exit");
    owner
        .join()
        .expect("A completes the source owner-exit boundary");

    #[cfg(feature = "native-runtime-test-audit")]
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        1,
        "A's detached route alone keeps its worker-admission claim live"
    );

    let first_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "the nonterminal releaser attaches beside A's retained route admission"
        );

        // Preserve the source aggregate's terminal order for the singleton
        // tails, but deliberately finish this whole worker before C releases
        // the remaining regular pages. The registry must retain A's parked
        // route token while B's own no-page attachment completes.
        free_exact_native_route_client(clients[5]);
        free_exact_native_route_client(clients[4]);
        free_exact_native_route_client(clients[3]);
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the nonterminal B lifecycle releases only B's own admission"
        );
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "A's still-live route remains the one worker-admission claim after B finishes"
        );
    });
    first_releaser
        .join()
        .expect("B completes its nonterminal detached-route frees");

    // A's route is still source-active after B's nonterminal frees. Ticket
    // zero may run its own private operation beside that route, but this
    // cannot consume A's scheduler token or worker-admission claim.
    let bookkeeping = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero runs only its private operation beside A's source-active route"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(bookkeeping) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its private client without settling A's live route"
    );

    let (terminal_ready_sender, terminal_ready_receiver) = mpsc::sync_channel(0);
    let (release_terminal_sender, release_terminal_receiver) = mpsc::sync_channel(0);
    let terminal_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "C attaches beside A's remaining route admission"
        );

        free_exact_native_route_client(clients[2]);
        free_exact_native_route_client(clients[1]);
        free_exact_native_route_client(clients[0]);
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            2,
            "the terminal source free leaves A's proof and C's attachment admitted until C finishes"
        );
        let continued = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "C resumes only its independent local session while it holds A's typed terminal proof"
            ),
        };
        // SAFETY: this is C's exact local client, distinct from every opaque
        // A-route client consumed above.
        unsafe {
            continued.as_ptr().write(0x59);
            continued.as_ptr().add(72).write(0x5a);
            assert_eq!(continued.as_ptr().read(), 0x59);
            assert_eq!(continued.as_ptr().add(72).read(), 0x5a);
        }
        assert_eq!(
            unsafe { native_free(continued) },
            NativePageFreeResult::Freed,
            "C can free its independent local client before normal finish settles A's proof"
        );
        terminal_ready_sender
            .send(())
            .expect("C reports its terminal source release before the ticket-zero probe");
        release_terminal_receiver
            .recv()
            .expect("the initial thread releases C only after its ticket-zero probe");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "only C's normal finish consumes A's terminal route proof"
        );
        #[cfg(feature = "native-runtime-test-audit")]
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            0,
            "C's terminal lifecycle releases both its own and A's exact admissions"
        );
    });

    terminal_ready_receiver
        .recv()
        .expect("the initial thread observes C's terminal source release before its finish");
    match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Unavailable => {}
        TicketZeroPageAllocationResult::Allocated(_) => {
            panic!("ticket zero allocated before C completed its normal finish")
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            panic!("ticket zero attempted allocation before C completed its normal finish")
        }
        TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero became terminal before C completed its normal finish")
        }
    }
    release_terminal_sender
        .send(())
        .expect("the initial thread releases C after proving ticket zero is unavailable");
    terminal_releaser
        .join()
        .expect("C completes the terminal detached-route lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero reactivates only after the terminal releaser finishes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
